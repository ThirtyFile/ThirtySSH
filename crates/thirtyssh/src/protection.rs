//! SSH binary packet protection using the negotiated wire layout.
use crate::crypto_backend::aead::{self, chacha20_poly1305_openssh as chacha};
use crate::{
    algorithms::{Cipher, Compression, Mac, Suite},
    clear_packet::{self, HEADER_SIZE, LENGTH_SIZE, Layout, invalid},
    compression::Codec,
    initial::{KEXINIT, NEWKEYS},
    kex::DirectionKeys,
    protocol_error::ProtocolError,
    runtime::Instant,
    transport::{Activity, liveness_only},
};
use bytes::BufMut;
use ctr::cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    StreamCipher,
};
use hmac::{Hmac, KeyInit, Mac as _};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    io,
    ops::{Deref, Range},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
};
use zeroize::{Zeroize, Zeroizing};

const AES_BLOCK: usize = 16;
const AEAD_TAG: usize = 16;
const MAX_CACHED_SEND_FRAME: usize = 33 * 1024;
pub(crate) const KEY_BYTE_LIMIT: usize = 1 << 30;

/// A verified payload and its original allocation. Delay compaction until the
/// consumer knows which bytes it needs to own.
pub(crate) struct ReceivedPacket {
    wire: Zeroizing<Vec<u8>>,
    payload: Range<usize>,
}

impl ReceivedPacket {
    pub(crate) fn from_payload(payload: Vec<u8>) -> Self {
        Self {
            payload: 0..payload.len(),
            wire: Zeroizing::new(payload),
        }
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        let len = self.payload.len();
        if self.payload.start != 0 {
            self.wire.copy_within(self.payload, 0);
        }
        self.wire[len..].zeroize();
        self.wire.truncate(len);
        std::mem::take(&mut *self.wire)
    }

    pub(crate) fn into_suffix(mut self, len: usize) -> Vec<u8> {
        let start = self.payload.len() - len;
        // Limit retained frame capacity relative to the bytes charged to the receive window.
        if self.wire.capacity() - len > len / 4 {
            return self[start..].to_vec();
        }
        self.payload.start += start;
        self.into_vec()
    }
}

impl Deref for ReceivedPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.wire[self.payload.clone()]
    }
}

#[cfg(feature = "_bench")]
pub mod benchmark;

#[derive(Clone, Copy)]
pub(crate) enum Side {
    Receive,
    Send,
}

trait PacketCipher: Send + Sync {
    fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()>;
}

impl<C> PacketCipher for ctr::Ctr128BE<C>
where
    C: BlockCipherEncrypt<BlockSize = ctr::cipher::consts::U16>,
    Self: StreamCipher + Send + Sync,
{
    fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.try_apply_keystream(bytes)
            .map_err(|_| io::Error::other("SSH cipher counter exhausted"))
    }
}

impl<C: BlockCipherEncrypt + Send + Sync> PacketCipher for cbc::Encryptor<C> {
    fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.encrypt_blocks(packet_blocks::<Self>(bytes)?);
        Ok(())
    }
}

impl<C: BlockCipherDecrypt + Send + Sync> PacketCipher for cbc::Decryptor<C> {
    fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.decrypt_blocks(packet_blocks::<Self>(bytes)?);
        Ok(())
    }
}

fn packet_blocks<C: ctr::cipher::BlockSizeUser>(bytes: &mut [u8]) -> io::Result<&mut [Block<C>]> {
    let (blocks, remainder) = Block::<C>::slice_as_chunks_mut(bytes);
    if !remainder.is_empty() {
        return Err(invalid("SSH cipher requires whole blocks"));
    }
    Ok(blocks)
}

fn packet_cipher<M: PacketCipher + KeyIvInit + 'static>(
    keys: &DirectionKeys,
) -> Box<dyn PacketCipher> {
    Box::new(
        M::new_from_slices(&keys.cipher[..M::key_size()], &keys.iv[..M::iv_size()])
            .expect("SSH cipher key and IV lengths"),
    )
}

fn cbc_cipher<C>(keys: &DirectionKeys, side: Side) -> Box<dyn PacketCipher>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + ctr::cipher::KeyInit + Send + Sync + 'static,
{
    match side {
        Side::Receive => packet_cipher::<cbc::Decryptor<C>>(keys),
        Side::Send => packet_cipher::<cbc::Encryptor<C>>(keys),
    }
}

enum Integrity {
    Sha1(Box<Hmac<Sha1>>),
    Sha256(Box<Hmac<Sha256>>),
    Sha512(Box<Hmac<Sha512>>),
}

impl Integrity {
    fn new(algorithm: Mac, key: &[u8]) -> Self {
        let key = &key[..algorithm.tag_len()];
        match algorithm {
            Mac::HmacSha1 | Mac::HmacSha1Etm => {
                Self::Sha1(Box::new(Hmac::new_from_slice(key).expect("HMAC-SHA1 key")))
            }
            Mac::HmacSha256 | Mac::HmacSha256Etm => Self::Sha256(Box::new(
                Hmac::new_from_slice(key).expect("HMAC-SHA2-256 key"),
            )),
            Mac::HmacSha512 | Mac::HmacSha512Etm => Self::Sha512(Box::new(
                Hmac::new_from_slice(key).expect("HMAC-SHA2-512 key"),
            )),
            Mac::None => unreachable!("a packet MAC requires integrity protection"),
        }
    }

    fn with_packet<M: hmac::Mac + Clone>(key: &M, sequence: u32, frame: &[u8]) -> M {
        let mut mac = key.clone();
        mac.update(&sequence.to_be_bytes());
        mac.update(frame);
        mac
    }

    fn sign(&self, sequence: u32, frame: &[u8], tag: &mut [u8]) {
        match self {
            Self::Sha1(key) => tag.copy_from_slice(
                &Self::with_packet(&**key, sequence, frame)
                    .finalize()
                    .into_bytes(),
            ),
            Self::Sha256(key) => tag.copy_from_slice(
                &Self::with_packet(&**key, sequence, frame)
                    .finalize()
                    .into_bytes(),
            ),
            Self::Sha512(key) => tag.copy_from_slice(
                &Self::with_packet(&**key, sequence, frame)
                    .finalize()
                    .into_bytes(),
            ),
        }
    }

    fn verify(&self, sequence: u32, frame: &[u8], tag: &[u8]) -> io::Result<()> {
        match self {
            Self::Sha1(key) => Self::with_packet(&**key, sequence, frame).verify_slice(tag),
            Self::Sha256(key) => Self::with_packet(&**key, sequence, frame).verify_slice(tag),
            Self::Sha512(key) => Self::with_packet(&**key, sequence, frame).verify_slice(tag),
        }
        .map_err(|_| ProtocolError::PacketMac.into())
    }
}

/// AES-GCM uses the fixed IV prefix and a dedicated 64-bit invocation
/// counter. Neither Strict KEX nor the SSH packet sequence drives this nonce.
struct Gcm {
    key: aead::LessSafeKey,
    next_iv: Option<[u8; 12]>,
}

impl Gcm {
    fn new(algorithm: &'static aead::Algorithm, keys: &DirectionKeys) -> Self {
        let key = aead::UnboundKey::new(algorithm, &keys.cipher[..algorithm.key_len()])
            .expect("AES-GCM key length");
        Self {
            key: aead::LessSafeKey::new(key),
            next_iv: Some(keys.iv[..12].try_into().expect("AES-GCM IV length")),
        }
    }

    fn nonce(&mut self) -> io::Result<aead::Nonce> {
        let iv = self
            .next_iv
            .ok_or_else(|| io::Error::other("SSH AES-GCM IV exhausted"))?;
        let counter = u64::from_be_bytes(iv[4..].try_into().expect("AES-GCM counter length"));
        self.next_iv = counter.checked_add(1).map(|value| {
            let mut next = iv;
            next[4..].copy_from_slice(&value.to_be_bytes());
            next
        });
        Ok(aead::Nonce::assume_unique_for_key(iv))
    }

    fn open(&mut self, frame: &mut [u8], tag: &[u8]) -> io::Result<()> {
        let nonce = self.nonce()?;
        let (length, body) = frame.split_at_mut(LENGTH_SIZE);
        let aad = aead::Aad::from(length);
        #[cfg(feature = "aws-lc-rs")]
        let result = self.key.open_in_place_separate_tag(nonce, aad, tag, body);
        #[cfg(not(feature = "aws-lc-rs"))]
        let result = {
            let tag =
                aead::Tag::try_from(tag).map_err(|_| invalid("invalid SSH AEAD tag length"))?;
            self.key
                .open_in_place_separate_tag(nonce, aad, tag, body, 0..)
        };
        result
            .map(|_| ())
            .map_err(|_| ProtocolError::Decryption.into())
    }

    fn seal(&mut self, frame: &mut [u8], tag: &mut [u8]) -> io::Result<()> {
        let nonce = self.nonce()?;
        let (length, body) = frame.split_at_mut(LENGTH_SIZE);
        let result = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(length), body)
            .map_err(|_| io::Error::other("could not seal SSH AEAD packet"))?;
        tag.copy_from_slice(result.as_ref());
        Ok(())
    }
}

enum Protection {
    Clear,
    Classic(Box<dyn PacketCipher>, Integrity),
    Etm(Box<dyn PacketCipher>, Integrity),
    Gcm(Box<Gcm>),
    ChaChaOpen(chacha::OpeningKey),
    ChaChaSeal(chacha::SealingKey),
}

#[derive(Default)]
struct IncomingFrame {
    prefix: Zeroizing<[u8; AES_BLOCK]>,
    wire: Option<(Zeroizing<Vec<u8>>, usize)>,
    filled: usize,
}

// Persist each successful short read before waiting for more bytes.
async fn fill<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mut [u8],
    filled: &mut usize,
) -> io::Result<()> {
    while *filled < output.len() {
        match reader.read(&mut output[*filled..]).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated SSH packet",
                ));
            }
            Ok(count) => *filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) struct Direction {
    protection: Protection,
    suite: Suite,
    side: Side,
    compression: Codec,
    incoming: IncomingFrame,
    outgoing: Vec<u8>,
    optional_newkeys_codec: Option<Codec>,
    previous_auth_codec: Option<Codec>,
    pub(crate) sequence: u32,
    pub(crate) bytes: usize,
    pub(crate) activity: Option<watch::Sender<Activity>>,
}

impl Direction {
    pub(crate) fn new(keys: DirectionKeys, suite: Suite, side: Side, sequence: u32) -> Self {
        let protection = match suite.cipher {
            Cipher::Clear | Cipher::None => Protection::Clear,
            Cipher::ChaCha20Poly1305 => match side {
                Side::Receive => Protection::ChaChaOpen(chacha::OpeningKey::new(&keys.cipher)),
                Side::Send => Protection::ChaChaSeal(chacha::SealingKey::new(&keys.cipher)),
            },
            Cipher::Aes128Gcm => Protection::Gcm(Box::new(Gcm::new(&aead::AES_128_GCM, &keys))),
            Cipher::Aes256Gcm => Protection::Gcm(Box::new(Gcm::new(&aead::AES_256_GCM, &keys))),
            cipher => {
                let algorithm = suite.mac.expect("negotiated block cipher has a MAC");
                let integrity = Integrity::new(algorithm, keys.integrity.as_ref());
                let stream = match cipher {
                    Cipher::Aes128Ctr => packet_cipher::<ctr::Ctr128BE<aes::Aes128>>(&keys),
                    Cipher::Aes192Ctr => packet_cipher::<ctr::Ctr128BE<aes::Aes192>>(&keys),
                    Cipher::Aes256Ctr => packet_cipher::<ctr::Ctr128BE<aes::Aes256>>(&keys),
                    Cipher::Aes128Cbc => cbc_cipher::<aes::Aes128>(&keys, side),
                    Cipher::Aes192Cbc => cbc_cipher::<aes::Aes192>(&keys, side),
                    Cipher::Aes256Cbc => cbc_cipher::<aes::Aes256>(&keys, side),
                    #[cfg(feature = "des")]
                    Cipher::TripleDesCbc => cbc_cipher::<des::TdesEde3>(&keys, side),
                    Cipher::Clear
                    | Cipher::None
                    | Cipher::ChaCha20Poly1305
                    | Cipher::Aes128Gcm
                    | Cipher::Aes256Gcm => {
                        unreachable!("cipher is initialized separately")
                    }
                };
                if algorithm.is_etm() {
                    Protection::Etm(stream, integrity)
                } else {
                    Protection::Classic(stream, integrity)
                }
            }
        };
        Self {
            protection,
            suite,
            side,
            compression: Codec::new(Compression::None, side, false),
            incoming: IncomingFrame::default(),
            outgoing: Vec::new(),
            optional_newkeys_codec: None,
            previous_auth_codec: None,
            sequence,
            bytes: 0,
            activity: None,
        }
    }

    fn check_limit(&self, length: usize) -> io::Result<()> {
        if self.bytes + length > KEY_BYTE_LIMIT {
            return Err(io::Error::other("SSH transport requires rekey"));
        }
        Ok(())
    }

    fn advance(&mut self, size: usize) {
        // Even the smallest packets exhaust the byte limit before 2^32
        // invocations. A wrapping sequence cannot repeat within a key epoch.
        self.sequence = self.sequence.wrapping_add(1);
        self.bytes += size;
    }

    /// Count one inbound packet. `regular` is false for traffic that proves
    /// the peer is alive without being use of the session.
    fn record_received(&mut self, size: usize, regular: bool) {
        self.advance(size);
        if let Some(traffic) = &self.activity {
            let now = Instant::now();
            traffic.send_modify(|activity| {
                activity.received = now;
                if regular {
                    activity.active = now;
                }
            });
        }
    }

    fn layout(&self) -> Layout {
        Layout {
            block: self.suite.cipher.block_size(),
            max_packet_size: clear_packet::MAX_TRANSPORT_PACKET_SIZE,
            separate_length: !matches!(
                self.protection,
                Protection::Clear | Protection::Classic(..)
            ),
        }
    }

    fn tag_len(&self) -> usize {
        if matches!(self.protection, Protection::Clear) {
            0
        } else {
            self.suite.mac.map_or(AEAD_TAG, Mac::tag_len)
        }
    }

    /// A pending read can be dropped and resumed with the same stream.
    /// After an error the key and frame state must be discarded.
    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Vec<u8>> {
        self.read_packet(reader).await.map(ReceivedPacket::into_vec)
    }

    pub(crate) async fn read_packet<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<ReceivedPacket> {
        loop {
            if let Some(packet) = self.read_frame(reader).await? {
                return Ok(packet);
            }
        }
    }

    async fn read_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<ReceivedPacket>> {
        let layout = self.layout();
        let prefix_len = if layout.separate_length {
            LENGTH_SIZE
        } else {
            layout.block
        };
        let tag_len = self.tag_len();
        if self.incoming.wire.is_none() {
            self.check_limit(prefix_len)?;
            let prefix = &mut self.incoming.prefix[..prefix_len];
            fill(reader, prefix, &mut self.incoming.filled).await?;
            if let Protection::Classic(cipher, _) = &mut self.protection {
                cipher.apply(prefix)?;
            }
            let mut length = *prefix
                .first_chunk::<LENGTH_SIZE>()
                .expect("SSH packet length");
            if let Protection::ChaChaOpen(key) = &self.protection {
                length = key.decrypt_packet_length(self.sequence, length);
            }
            let size = clear_packet::packet_size(u32::from_be_bytes(length), layout)?;
            self.check_limit(size)?;
            let wire_len = size + tag_len;
            let mut wire = Zeroizing::new(Vec::with_capacity(wire_len));
            wire.extend_from_slice(&self.incoming.prefix[..prefix_len]);
            self.incoming.wire = Some((wire, wire_len));
        }
        let (wire, wire_len) = self
            .incoming
            .wire
            .as_mut()
            .expect("SSH frame has a parsed length");
        while wire.len() < *wire_len {
            let remaining = *wire_len - wire.len();
            // Append only this frame's bytes, even if the allocator rounded up
            // capacity. Each successful read advances the Vec's initialized length.
            let mut limited = (&mut **wire).limit(remaining);
            match reader.read_buf(&mut limited).await {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated SSH packet",
                    ));
                }
                Ok(count) => self.incoming.filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let (mut wire, _) = std::mem::take(&mut self.incoming)
            .wire
            .expect("complete SSH frame");
        let size = wire.len() - tag_len;
        let (frame, tag) = wire.split_at_mut(size);
        match &mut self.protection {
            Protection::Clear => {}
            Protection::Classic(cipher, mac) => {
                cipher.apply(&mut frame[prefix_len..])?;
                mac.verify(self.sequence, frame, tag)?;
            }
            Protection::Etm(cipher, mac) => {
                mac.verify(self.sequence, frame, tag)?;
                cipher.apply(&mut frame[LENGTH_SIZE..])?;
            }
            Protection::Gcm(key) => key.open(frame, tag)?,
            Protection::ChaChaOpen(key) => {
                let tag: &[u8; AEAD_TAG] =
                    (&*tag).try_into().expect("ChaCha20-Poly1305 tag length");
                key.open_in_place(self.sequence, frame, tag)
                    .map_err(|_| io::Error::from(ProtocolError::Decryption))?;
            }
            Protection::ChaChaSeal(_) => unreachable!("send key used to receive an SSH packet"),
        }
        let payload_len = clear_packet::payload_len(size, usize::from(frame[LENGTH_SIZE]))?;
        let payload = &frame[HEADER_SIZE..HEADER_SIZE + payload_len];
        // A peer may send one final NEWKEYS using the old dictionary.
        // All application packets use the new epoch. Never deliver the result
        // of trying the old decoder or keep it past this first packet.
        if let Some(mut previous) = self.optional_newkeys_codec.take()
            && previous
                .decode(payload)
                .is_ok_and(|decoded| decoded.as_deref().map_or(payload, Vec::as_slice) == NEWKEYS)
        {
            self.record_received(size, false);
            return Ok(None);
        }
        let previous_auth = self.previous_auth_codec.take();
        let decompressed = match self.compression.decode(payload) {
            Ok(decoded) => decoded,
            Err(error) => {
                // Some servers reset their outgoing delayed dictionary on
                // the first application request. If a rekey arrives first,
                // their KEXINIT and optional NEWKEYS use the pre-login codec.
                let Some(mut previous) = previous_auth else {
                    return Err(error);
                };
                let decoded = previous.decode(payload).map_err(|_| error)?;
                if decoded.as_deref().map_or(payload, Vec::as_slice).first() != Some(&KEXINIT) {
                    return Err(invalid(
                        "expected SSH_MSG_KEXINIT using previous compression",
                    ));
                }
                self.compression = previous;
                decoded
            }
        };
        let regular = !liveness_only(decompressed.as_deref().map_or(payload, Vec::as_slice));
        let packet = if let Some(mut decoded) = decompressed {
            ReceivedPacket::from_payload(std::mem::take(&mut *decoded))
        } else {
            ReceivedPacket {
                wire,
                payload: HEADER_SIZE..HEADER_SIZE + payload_len,
            }
        };
        self.record_received(size, regular);
        Ok(Some(packet))
    }

    pub(crate) async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> io::Result<()> {
        let compressed = self.compression.encode(payload)?;
        let wire_payload = compressed
            .as_deref()
            .map_or(payload, |bytes| bytes.as_slice());
        let layout = self.layout();
        #[cfg(feature = "des")]
        let layout = if self.suite.cipher == Cipher::TripleDesCbc {
            // Some peers probe 16 bytes even for 3DES. Pad output to a
            // multiple of 16 so a short EtM body fits the peer's probe.
            Layout {
                block: AES_BLOCK,
                ..layout
            }
        } else {
            layout
        };
        // Reserve the tag's wire space when framing the payload so the
        // complete protected packet can use one write.
        let tag_len = self.tag_len();
        let mut packet = Zeroizing::new(std::mem::take(&mut self.outgoing));
        packet.clear();
        clear_packet::encode_into(wire_payload, layout, tag_len, &mut packet)?;
        let frame_len = packet.len() - tag_len;
        self.check_limit(frame_len)?;
        let (frame, tag) = packet.split_at_mut(frame_len);
        match &mut self.protection {
            Protection::Clear => {}
            Protection::Classic(cipher, mac) => {
                mac.sign(self.sequence, frame, tag);
                cipher.apply(frame)?;
            }
            Protection::Etm(cipher, mac) => {
                cipher.apply(&mut frame[LENGTH_SIZE..])?;
                mac.sign(self.sequence, frame, tag);
            }
            Protection::Gcm(key) => key.seal(frame, tag)?,
            Protection::ChaChaSeal(key) => {
                key.seal_in_place(
                    self.sequence,
                    frame,
                    tag.try_into().expect("ChaCha20-Poly1305 tag length"),
                );
            }
            Protection::ChaChaOpen(_) => unreachable!("receive key used to send an SSH packet"),
        }
        // Keep plaintext in the zeroizing buffer on the clear and error paths.
        // A successfully sealed frame contains only wire-visible bytes.
        let mut ciphertext = Vec::new();
        let wire = if matches!(self.protection, Protection::Clear) {
            packet.as_slice()
        } else {
            ciphertext = std::mem::take(&mut *packet);
            ciphertext.as_slice()
        };
        writer.write_all(wire).await?;
        writer.flush().await?;
        if ciphertext.capacity() <= MAX_CACHED_SEND_FRAME {
            self.outgoing = ciphertext;
        }
        self.advance(frame_len);
        Ok(())
    }

    pub(crate) fn install(&mut self, keys: DirectionKeys, suite: Suite, strict_kex: bool) {
        let activity = self.activity.take();
        *self = Self::new(
            keys,
            suite,
            self.side,
            if strict_kex { 0 } else { self.sequence },
        );
        self.activity = activity;
    }

    pub(crate) fn renew_unprotected(
        &mut self,
        suite: Suite,
        mode: Compression,
        activate_delayed: bool,
        strict_kex: bool,
    ) {
        debug_assert!(
            matches!(self.protection, Protection::Clear) && suite.cipher.is_unprotected()
        );
        debug_assert_eq!(self.incoming.filled, 0);
        self.suite = suite;
        self.bytes = 0;
        self.previous_auth_codec = None;
        if strict_kex {
            self.sequence = 0;
        }
        let previous = std::mem::replace(
            &mut self.compression,
            Codec::new(mode, self.side, activate_delayed),
        );
        self.optional_newkeys_codec = match self.side {
            Side::Receive => Some(previous),
            Side::Send => None,
        };
    }

    pub(crate) fn reset_compression(&mut self, mode: Compression, authenticated: bool) {
        self.compression = Codec::new(mode, self.side, authenticated);
    }

    pub(crate) fn finish_unprotected_userauth(&mut self, allow_previous_kex: bool) {
        debug_assert!(
            self.suite.cipher.is_unprotected()
                && (!allow_previous_kex || matches!(self.side, Side::Receive))
        );
        self.previous_auth_codec = self
            .compression
            .restart_delayed(self.side)
            .filter(|_| allow_previous_kex);
    }

    pub(crate) fn enable_delayed_compression(&mut self) {
        self.compression.enable_delayed(self.side);
    }
}

#[cfg(test)]
mod tests;
