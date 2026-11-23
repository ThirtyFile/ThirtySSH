#[cfg(not(feature = "aws-lc-rs"))]
use crate::crypto_backend::rand::SystemRandom;
use crate::crypto_backend::{
    agreement,
    signature::{self, KeyPair},
};
use crate::{
    algorithms::{Kex, KexDigest},
    clear_packet::invalid,
    initial::Transcript,
    keys::{self, Algorithm, Certificate, CertificateSignaturePolicy, Credential, PrivateKey},
    protocol_error::ProtocolError,
    wire::{Reader, Writer},
};
use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{io, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

mod dh;
pub(crate) mod gex;
mod hybrid;
pub mod modp;

pub(crate) const KEX_METHOD_INIT: u8 = 30;
pub(crate) const KEX_METHOD_REPLY: u8 = 31;
pub(crate) const ED25519: &[u8] = b"ssh-ed25519";

/// An Ed25519 host key used to authenticate the transport.
#[derive(Clone)]
pub struct HostKey(Arc<signature::Ed25519KeyPair>);

impl HostKey {
    pub fn generate() -> io::Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> io::Result<Self> {
        signature::Ed25519KeyPair::from_seed_unchecked(seed)
            .map(Arc::new)
            .map(Self)
            .map_err(|_| io::Error::other("could not construct SSH host key"))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key length")
    }

    pub(crate) fn public_blob(&self) -> io::Result<Vec<u8>> {
        fields(None, &[ED25519, &self.public_key()])
    }

    pub(crate) fn sign_blob(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        fields(None, &[ED25519, self.0.sign(message).as_ref()])
    }
}

/// Server identities retained across key exchanges. A raw RSA key can sign
/// using either SSH RSA SHA-2 algorithm.
#[derive(Clone)]
pub struct HostKeys(Arc<[HostSigner]>);

impl From<HostKey> for HostKeys {
    fn from(key: HostKey) -> Self {
        Self(Arc::new([HostSigner::Ed25519(key)]))
    }
}

impl From<PrivateKey> for HostKeys {
    fn from(key: PrivateKey) -> Self {
        Self::from(vec![key])
    }
}

impl From<Vec<PrivateKey>> for HostKeys {
    fn from(keys: Vec<PrivateKey>) -> Self {
        Self(
            keys.into_iter()
                .map(|key| HostSigner::PrivateKey(Arc::new(key)))
                .collect(),
        )
    }
}

impl HostKeys {
    /// Associate host certificates with their private keys. Raw identities
    /// remain available for peers configured to use the corresponding keys.
    pub fn with_certificates(
        keys: Vec<PrivateKey>,
        certificates: Vec<Certificate>,
    ) -> io::Result<Self> {
        Self::with_certificates_and_policy(
            keys,
            certificates,
            CertificateSignaturePolicy::default(),
        )
    }

    /// Install local certificates with an explicit issuer signature policy.
    pub fn with_certificates_and_policy(
        keys: Vec<PrivateKey>,
        certificates: Vec<Certificate>,
        policy: CertificateSignaturePolicy,
    ) -> io::Result<Self> {
        use keys::ssh_key::certificate::CertType;

        let keys = keys.into_iter().map(Arc::new).collect::<Vec<_>>();
        let mut signers = Vec::with_capacity(keys.len() + certificates.len());
        for certificate in certificates {
            let key = keys
                .iter()
                .find(|key| key.public_key().key_data() == certificate.public_key())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SSH host certificate has no matching private key",
                    )
                })?;
            if certificate.cert_type() != CertType::Host
                || !certificate.critical_options().is_empty()
                || !policy.verify_signature(&certificate)?
            {
                return Err(invalid("invalid SSH host certificate"));
            }
            // Every client would refuse it, so fail where the operator sees it.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            if certificate.valid_before() <= now {
                return Err(invalid("SSH host certificate has expired"));
            }
            signers.push(HostSigner::Certificate {
                key: key.clone(),
                certificate: Box::new(certificate),
            });
        }
        signers.extend(keys.into_iter().map(HostSigner::PrivateKey));
        Ok(Self(signers.into()))
    }

    pub(crate) fn select(&self, algorithm: &Algorithm) -> Option<&HostSigner> {
        let cert_algorithm = keys::certificate_signature_algorithm(algorithm);
        self.0
            .iter()
            .find(|key| match (key, cert_algorithm.as_ref()) {
                (HostSigner::Ed25519(_), None) => algorithm == &Algorithm::Ed25519,
                (HostSigner::PrivateKey(key), None) => {
                    keys::matches_key(key.public_key(), algorithm)
                }
                (HostSigner::Certificate { key, .. }, Some(signature)) => {
                    keys::matches_key(key.public_key(), signature)
                }
                _ => false,
            })
    }
}

pub(crate) enum HostSigner {
    Ed25519(HostKey),
    PrivateKey(Arc<PrivateKey>),
    Certificate {
        key: Arc<PrivateKey>,
        certificate: Box<Certificate>,
    },
}

impl HostSigner {
    fn public_blob(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Ed25519(key) => key.public_blob(),
            Self::PrivateKey(key) => key.public_key().to_bytes().map_err(io::Error::other),
            Self::Certificate { certificate, .. } => {
                certificate.to_bytes().map_err(io::Error::other)
            }
        }
    }

    fn sign_blob(&self, algorithm: &Algorithm, data: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Ed25519(key) => key.sign_blob(data),
            Self::PrivateKey(key) => keys::sign(key, algorithm, data),
            Self::Certificate { key, .. } => {
                let signature = keys::certificate_signature_algorithm(algorithm)
                    .ok_or_else(|| invalid("unsupported SSH host certificate algorithm"))?;
                keys::sign(key, &signature, data)
            }
        }
    }
}

pub(crate) struct DirectionKeys {
    pub(crate) iv: Zeroizing<[u8; 32]>,
    pub(crate) cipher: Zeroizing<[u8; 64]>,
    pub(crate) integrity: Zeroizing<[u8; 64]>,
}

impl DirectionKeys {
    pub(crate) fn unused() -> Self {
        Self {
            iv: Zeroizing::new([0; 32]),
            cipher: Zeroizing::new([0; 64]),
            integrity: Zeroizing::new([0; 64]),
        }
    }
}

pub(crate) struct ExchangeKeys {
    pub(crate) exchange_hash: Zeroizing<Vec<u8>>,
    pub(crate) client_to_server: DirectionKeys,
    pub(crate) server_to_client: DirectionKeys,
}

impl ExchangeKeys {
    pub(crate) fn unprotected() -> Self {
        Self {
            exchange_hash: Zeroizing::new(Vec::new()),
            client_to_server: DirectionKeys::unused(),
            server_to_client: DirectionKeys::unused(),
        }
    }
}

#[cfg(feature = "aws-lc-rs")]
type X25519PrivateKey = agreement::PrivateKey;
#[cfg(not(feature = "aws-lc-rs"))]
type X25519PrivateKey = agreement::EphemeralPrivateKey;

enum EphemeralKey {
    Hybrid(hybrid::Client),
    X25519(X25519PrivateKey),
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
    Dh(dh::Key),
}

impl EphemeralKey {
    fn generate(method: &str) -> io::Result<(Self, Vec<u8>)> {
        macro_rules! nist_key {
            ($curve:ident, $variant:ident) => {{
                let private =
                    $curve::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng)
                        .map_err(io::Error::other)?;
                let public = private.public_key().to_sec1_point(false);
                Ok((Self::$variant(private), public.as_bytes().to_vec()))
            }};
        }
        match method {
            hybrid::METHOD => {
                let (client, public) = hybrid::Client::generate()?;
                Ok((Self::Hybrid(client), public))
            }
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                let (private, public) = x25519_keypair()?;
                Ok((Self::X25519(private), public.as_ref().to_vec()))
            }
            "ecdh-sha2-nistp256" => nist_key!(p256, P256),
            "ecdh-sha2-nistp384" => nist_key!(p384, P384),
            "ecdh-sha2-nistp521" => nist_key!(p521, P521),
            _ => {
                let group = dh::Group::fixed(method)
                    .ok_or_else(|| invalid("unsupported SSH key exchange method"))?;
                let (private, public) = dh::Key::generate(group)?;
                Ok((Self::Dh(private), public))
            }
        }
    }

    fn agree(self, peer: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        macro_rules! nist_agreement {
            ($curve:ident, $private:ident) => {{
                let public = $curve::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| invalid("invalid SSH NIST ECDH peer public key"))?;
                let secret = $private.diffie_hellman(&public);
                Ok(Zeroizing::new(
                    secret.raw_secret_bytes().as_slice().to_vec(),
                ))
            }};
        }
        match self {
            Self::Hybrid(client) => client.agree(peer),
            Self::X25519(private) => {
                x25519_agree(private, peer, |secret| Zeroizing::new(secret.to_vec()))
            }
            Self::P256(private) => nist_agreement!(p256, private),
            Self::P384(private) => nist_agreement!(p384, private),
            Self::P521(private) => nist_agreement!(p521, private),
            Self::Dh(private) => private.agree(peer),
        }
    }
}

fn x25519_keypair() -> io::Result<(X25519PrivateKey, agreement::PublicKey)> {
    #[cfg(feature = "aws-lc-rs")]
    let private = {
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut()).map_err(io::Error::other)?;
        agreement::PrivateKey::from_private_key(&agreement::X25519, entropy.as_ref())
    };
    #[cfg(not(feature = "aws-lc-rs"))]
    let private =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new());
    let private = private.map_err(|_| io::Error::other("could not generate ephemeral SSH key"))?;
    let public = private
        .compute_public_key()
        .map_err(|_| io::Error::other("could not compute ephemeral SSH public key"))?;
    Ok((private, public))
}

fn x25519_agree<T>(
    private: X25519PrivateKey,
    peer: &[u8],
    export: impl FnOnce(&[u8]) -> T,
) -> io::Result<T> {
    if peer.len() != 32 {
        return Err(invalid("invalid X25519 public key length"));
    }
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
    #[cfg(feature = "aws-lc-rs")]
    let result = agreement::agree(&private, peer, (), |secret| Ok(export(secret)));
    #[cfg(not(feature = "aws-lc-rs"))]
    let result = agreement::agree_ephemeral(private, &peer, export);
    result.map_err(|_| invalid("invalid X25519 peer public key"))
}

fn positive_mpint(bytes: &[u8]) -> Vec<u8> {
    let unsigned = &bytes[bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len())..];
    let padding = usize::from(unsigned.first().is_some_and(|byte| byte & 0x80 != 0));
    let mut encoded = Vec::with_capacity(unsigned.len() + padding);
    encoded.resize(padding, 0);
    encoded.extend_from_slice(unsigned);
    encoded
}

fn ssh_string(hash: &mut impl Digest, value: &[u8]) {
    // IDs, KEXINIT packets and keys in this transcript are bounded well below u32::MAX.
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}

fn derive(
    secret: &[u8],
    transcript: &Transcript,
    host_blob: &[u8],
    client_public: &[u8],
    server_public: &[u8],
    session_id: Option<&[u8]>,
    group: Option<&gex::Exchange>,
) -> ExchangeKeys {
    let prelude = [
        transcript.client.identification.as_slice(),
        &transcript.server.identification,
        &transcript.client.kexinit,
        &transcript.server.kexinit,
        host_blob,
    ];
    let public_keys = [client_public, server_public];
    // RFC 10042 hashes the two component secrets and uses the entire digest
    // as an SSH string. Other methods use a positive mpint.
    let mpint;
    let secret = if transcript.kex_algorithm == hybrid::METHOD {
        secret
    } else {
        mpint = Zeroizing::new(positive_mpint(secret));
        mpint.as_slice()
    };
    // The transcript carries the name negotiation chose from our own list.
    let digest = Kex::method(transcript.kex_algorithm)
        .and_then(Kex::digest)
        .expect("negotiated SSH key exchange method");
    match digest {
        KexDigest::Sha1 => {
            derive_with::<Sha1>(secret, prelude, group, public_keys, transcript, session_id)
        }
        KexDigest::Sha256 => {
            derive_with::<Sha256>(secret, prelude, group, public_keys, transcript, session_id)
        }
        KexDigest::Sha384 => {
            derive_with::<Sha384>(secret, prelude, group, public_keys, transcript, session_id)
        }
        KexDigest::Sha512 => {
            derive_with::<Sha512>(secret, prelude, group, public_keys, transcript, session_id)
        }
    }
}

fn derive_with<D: Digest>(
    secret: &[u8],
    prelude: [&[u8]; 5],
    group: Option<&gex::Exchange>,
    public_keys: [&[u8]; 2],
    transcript: &Transcript,
    session_id: Option<&[u8]>,
) -> ExchangeKeys {
    let mut hash = D::new();
    for value in prelude {
        ssh_string(&mut hash, value);
    }
    if let Some(group) = group {
        group.hash(&mut hash);
    }
    for value in public_keys {
        ssh_string(&mut hash, value);
    }
    ssh_string(&mut hash, secret);
    let mut digest = hash.finalize();
    let exchange_hash = Zeroizing::new(digest.to_vec());
    digest.as_mut_slice().zeroize();
    let session_id = session_id.unwrap_or(&exchange_hash);
    let direction = |suite: crate::algorithms::Suite, iv, cipher, integrity| DirectionKeys {
        iv: expand::<D, 32>(secret, &exchange_hash, session_id, iv, 32),
        cipher: expand::<D, 64>(
            secret,
            &exchange_hash,
            session_id,
            cipher,
            if suite.cipher == crate::algorithms::Cipher::ChaCha20Poly1305 {
                64
            } else {
                32
            },
        ),
        integrity: expand::<D, 64>(
            secret,
            &exchange_hash,
            session_id,
            integrity,
            if suite.mac.is_some_and(|mac| mac.tag_len() == 64) {
                64
            } else {
                32
            },
        ),
    };
    let client_to_server = direction(
        transcript.packet_algorithms.client_to_server,
        b'A',
        b'C',
        b'E',
    );
    let server_to_client = direction(
        transcript.packet_algorithms.server_to_client,
        b'B',
        b'D',
        b'F',
    );
    ExchangeKeys {
        exchange_hash,
        client_to_server,
        server_to_client,
    }
}

fn expand<D: Digest, const N: usize>(
    secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    letter: u8,
    length: usize,
) -> Zeroizing<[u8; N]> {
    let mut keys = Zeroizing::new([0; N]);
    let mut used = 0;
    while used < length {
        let mut hash = D::new();
        ssh_string(&mut hash, secret);
        hash.update(exchange_hash);
        if used == 0 {
            hash.update([letter]);
            hash.update(session_id);
        } else {
            hash.update(&keys[..used]);
        }
        let mut block = hash.finalize();
        let count = block.len().min(length - used);
        keys[used..used + count].copy_from_slice(&block[..count]);
        block.as_mut_slice().zeroize();
        used += count;
    }
    keys
}

pub(crate) fn fields(message: Option<u8>, fields: &[&[u8]]) -> io::Result<Vec<u8>> {
    let mut packet = vec![
        0;
        usize::from(message.is_some())
            + fields.iter().map(|field| 4 + field.len()).sum::<usize>()
    ];
    let mut writer = Writer::new(&mut packet);
    if let Some(message) = message {
        writer.byte(message).map_err(io::Error::other)?;
    }
    for field in fields {
        writer.string(field).map_err(io::Error::other)?;
    }
    Ok(packet)
}

pub(crate) fn decode<const N: usize>(packet: &[u8], message: Option<u8>) -> io::Result<[&[u8]; N]> {
    let mut reader = Reader::new(packet);
    let wire_error = |error| io::Error::new(io::ErrorKind::InvalidData, error);
    if let Some(message) = message
        && reader.byte().map_err(wire_error)? != message
    {
        return Err(invalid("unexpected SSH key exchange message"));
    }
    let mut slices = [&[][..]; N];
    for slice in &mut slices {
        *slice = reader.string().map_err(wire_error)?;
    }
    reader.finish().map_err(wire_error)?;
    Ok(slices)
}

pub(crate) fn verify_signature(key: &[u8; 32], message: &[u8], blob: &[u8]) -> io::Result<bool> {
    let [algorithm, proof] = decode(blob, None)?;
    if algorithm != ED25519 || proof.len() != 64 {
        return Err(invalid("invalid Ed25519 signature encoding"));
    }
    Ok(signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(message, proof)
        .is_ok())
}

pub(crate) struct ClientExchange {
    private: EphemeralKey,
    public: Vec<u8>,
    group: Option<gex::Exchange>,
}

pub(crate) struct ClientExchangeResult {
    pub(crate) keys: ExchangeKeys,
    pub(crate) host: Credential,
}

impl ClientExchange {
    pub(crate) fn start(method: &str) -> io::Result<(Self, Vec<u8>)> {
        let (private, public) = EphemeralKey::generate(method)?;
        let packet = fields(Some(KEX_METHOD_INIT), &[&public])?;
        Ok((
            Self {
                private,
                public,
                group: None,
            },
            packet,
        ))
    }

    pub(crate) fn start_group(group: gex::Exchange) -> io::Result<(Self, Vec<u8>)> {
        let (private, public) = dh::Key::generate(group.group.clone())?;
        let packet = fields(Some(gex::INIT), &[&public])?;
        Ok((
            Self {
                private: EphemeralKey::Dh(private),
                public,
                group: Some(group),
            },
            packet,
        ))
    }

    pub(crate) fn finish(
        self,
        reply: &[u8],
        transcript: &Transcript,
        session_id: Option<&[u8]>,
        certificate_signatures: CertificateSignaturePolicy,
    ) -> io::Result<ClientExchangeResult> {
        let message = if self.group.is_some() {
            gex::REPLY
        } else {
            KEX_METHOD_REPLY
        };
        let [host_blob, server_public, signature_blob] = decode(reply, Some(message))?;
        let algorithm = &transcript.host_key_algorithm;
        let host_key = keys::decode_host_identity(algorithm, host_blob, certificate_signatures)?;
        let secret = self.private.agree(server_public)?;
        let keys = derive(
            &secret,
            transcript,
            host_blob,
            &self.public,
            server_public,
            session_id,
            self.group.as_ref(),
        );
        let certified_algorithm = keys::certificate_signature_algorithm(algorithm);
        let signature_algorithm = certified_algorithm.as_ref().unwrap_or(algorithm);
        if !keys::verify(
            host_key.key_data(),
            signature_algorithm,
            &keys.exchange_hash,
            signature_blob,
        )? {
            return Err(ProtocolError::HostSignature.into());
        }
        Ok(ClientExchangeResult {
            keys,
            host: host_key,
        })
    }
}

pub(crate) fn server_reply(
    init: &[u8],
    transcript: &Transcript,
    host_key: &HostSigner,
    session_id: Option<&[u8]>,
    group: Option<&gex::Exchange>,
) -> io::Result<(ExchangeKeys, Vec<u8>)> {
    let message = if group.is_some() {
        gex::INIT
    } else {
        KEX_METHOD_INIT
    };
    let [client_public] = decode(init, Some(message))?;
    let dh_group = group
        .map(|group| group.group.clone())
        .or_else(|| dh::Group::fixed(transcript.kex_algorithm));
    let (public, secret) = if transcript.kex_algorithm == hybrid::METHOD {
        hybrid::server_exchange(client_public)?
    } else if let Some(group) = dh_group {
        let peer = group.decode_peer(client_public)?;
        let (private, public) = dh::Key::generate(group)?;
        (public, private.agree_validated(peer)?)
    } else {
        let (private, public) = EphemeralKey::generate(transcript.kex_algorithm)?;
        (public, private.agree(client_public)?)
    };
    let host_blob = host_key.public_blob()?;
    let keys = derive(
        &secret,
        transcript,
        &host_blob,
        client_public,
        &public,
        session_id,
        group,
    );
    let signature = host_key.sign_blob(&transcript.host_key_algorithm, &keys.exchange_hash)?;
    let reply_message = if group.is_some() {
        gex::REPLY
    } else {
        KEX_METHOD_REPLY
    };
    let reply = fields(Some(reply_message), &[&host_blob, &public, &signature])?;
    Ok((keys, reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algorithms::{Cipher, Compression, CompressionAlgorithms, Mac, PacketAlgorithms, Suite},
        initial::PeerTranscript,
    };

    pub(super) fn transcript() -> Transcript {
        Transcript {
            client: PeerTranscript {
                identification: b"SSH-2.0-fixture_c".to_vec(),
                kexinit: b"\x14client proposal".to_vec(),
            },
            server: PeerTranscript {
                identification: b"SSH-2.0-fixture_s".to_vec(),
                kexinit: b"\x14server proposal".to_vec(),
            },
            kex_algorithm: "curve25519-sha256",
            host_key_algorithm: Algorithm::Ed25519,
            packet_algorithms: PacketAlgorithms {
                client_to_server: Suite {
                    cipher: Cipher::ChaCha20Poly1305,
                    mac: None,
                },
                server_to_client: Suite {
                    cipher: Cipher::Aes256Ctr,
                    mac: Some(Mac::HmacSha512Etm),
                },
            },
            compression: CompressionAlgorithms {
                client_to_server: Compression::None,
                server_to_client: Compression::None,
            },
            strict_kex: true,
            peer_accepts_ext_info: false,
            next_receive_sequence: 0,
        }
    }

    fn hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), 2 * N);
        std::array::from_fn(|index| {
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap()
        })
    }

    #[test]
    #[allow(deprecated)] // ring's deterministic RNG is used only with public test vectors.
    fn curve25519_matches_the_independent_exchange_hash_and_kdf_for_both_roles() {
        let transcript = transcript();
        // RFC 7748 §6.1 key pairs. The transcript and KDF results below were
        // independently computed with Python hashlib from the published shared secret.
        let client_private =
            hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let client_public =
            hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let server_private =
            hex::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let server_public =
            hex::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let host_blob = fields(None, &[ED25519, &[0x42; 32]]).unwrap();
        let original_session = [0x5d; 32];

        for (secret, local, peer) in [
            (&client_private, &client_public, &server_public),
            (&server_private, &server_public, &client_public),
        ] {
            for session_id in [None, Some(original_session.as_slice())] {
                #[cfg(not(feature = "aws-lc-rs"))]
                let private = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &crate::crypto_backend::test::rand::FixedSliceRandom { bytes: secret },
                )
                .unwrap();
                #[cfg(feature = "aws-lc-rs")]
                let private =
                    agreement::PrivateKey::from_private_key(&agreement::X25519, secret).unwrap();
                assert_eq!(private.compute_public_key().unwrap().as_ref(), local);
                let agreed = EphemeralKey::X25519(private).agree(peer).unwrap();
                let keys = derive(
                    &agreed,
                    &transcript,
                    &host_blob,
                    &client_public,
                    &server_public,
                    session_id,
                    None,
                );
                assert_eq!(
                    keys.exchange_hash.as_slice(),
                    hex::<32>("391ae4505bd846573667112c30eda76586eca3233d12695236681b188df4dcef")
                );
                let client = keys.client_to_server;
                let server = keys.server_to_client;
                if session_id.is_none() {
                    assert_eq!(
                        *client.iv,
                        hex("f40bbf5f5da2e25a7410a5d1b9d6bb127d2238ba5096e2ad767d4a82b1ada6e9")
                    );
                    assert_eq!(
                        *client.cipher,
                        hex(concat!(
                            "d2fd642113ce619da6f4f3d0b5d5b7064b861c759b0eeb76dc0e25bc732376849",
                            "15e340fc3195791873b9d549db9f183c2746d3fcb0be68cf229aa50da4d5541",
                        ))
                    );
                    assert_eq!(
                        client.integrity[..32],
                        hex::<32>(
                            "85157bbe32c6a51e1f5d78265cb108787fe515cc5a8ce1cc86a3d9f7c880b5d8"
                        )
                    );
                    assert_eq!(
                        *server.iv,
                        hex("99f87f9d91a164accacb776f4992ab0e0cd36c0a6061c641beed8637e0b4cdb6")
                    );
                    assert_eq!(
                        server.cipher[..32],
                        hex::<32>(
                            "98becd2ad5874310c865f5364fb1565d864e20ea6a6f2cad25d7ab44bb6f2690"
                        )
                    );
                    assert_eq!(
                        *server.integrity,
                        hex(concat!(
                            "af2fdcc8f5ffc86bf601fac277d1bc99226cffcfd1d56f7daac6b11d91409bc65",
                            "ef285af7af1376578f36c0a5a56286d67e2363588a2ac49d630177ba0387513",
                        ))
                    );
                } else {
                    assert_eq!(
                        *client.iv,
                        hex("ee539803debcacdf1662096ee067b8c3d2866b0e975b35a0fe2f24e35986b182")
                    );
                    assert_eq!(
                        *server.iv,
                        hex("f2ea080186cb5b0b14f266dba878df24b75ac80110f92e9a9ed042a0b0187bc6")
                    );
                }
            }
        }
    }

    #[test]
    fn curve25519_rejects_low_order_keys_in_both_handshake_roles() {
        let transcript = transcript();
        let host = HostSigner::Ed25519(HostKey::from_seed(&[1; 32]).unwrap());
        let blob = host.public_blob().unwrap();
        let mut one = [0; 32];
        one[0] = 1;
        for low_order in [[0; 32], one] {
            let init = fields(Some(KEX_METHOD_INIT), &[&low_order]).unwrap();
            let server_error = server_reply(&init, &transcript, &host, None, None)
                .err()
                .unwrap();
            assert_eq!(server_error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(server_error.to_string(), "invalid X25519 peer public key");

            let (client, _) = ClientExchange::start(transcript.kex_algorithm).unwrap();
            let reply = fields(
                Some(KEX_METHOD_REPLY),
                &[&blob, &low_order, b"unused proof"],
            )
            .unwrap();
            let client_error = client
                .finish(&reply, &transcript, None, Default::default())
                .err()
                .unwrap();
            assert_eq!(client_error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(client_error.to_string(), "invalid X25519 peer public key");
        }
    }

    #[test]
    fn nist_exchange_hash_and_key_expansion_match_independent_vectors() {
        // OpenSSL via Python cryptography generated the SEC1 points for scalars
        // 1 and 4 (P-256), or 1 and 2 (P-384/P-521). Independently encoded the
        // SSH transcript and RFC 4253 KDF using Python hashlib. P-256 needs a
        // sign padding byte, P-521 has a leading zero in the unsigned x coordinate.
        macro_rules! vector {
            ($curve:ident, $method:literal, $width:literal, $scalar:literal, $session:literal,
             $hash:literal, $client_key:literal, $server_integrity:literal) => {{
                let mut fixture = transcript();
                fixture.kex_algorithm = $method;
                let mut left = [0u8; $width];
                left[$width - 1] = 1;
                let mut right = [0u8; $width];
                right[$width - 1] = $scalar;
                let left = $curve::SecretKey::from_slice(&left).unwrap();
                let right = $curve::SecretKey::from_slice(&right).unwrap();
                let left_public = left.public_key();
                let right_public = right.public_key();
                let a = left_public.to_sec1_point(false);
                let b = right_public.to_sec1_point(false);
                let host = fields(None, &[ED25519, &[0x42; 32]]).unwrap();
                let shared = left.diffie_hellman(&right_public);
                let keys = derive(
                    shared.raw_secret_bytes(),
                    &fixture,
                    &host,
                    a.as_bytes(),
                    b.as_bytes(),
                    None,
                    None,
                );
                assert_eq!(
                    keys.exchange_hash.as_slice(),
                    data_encoding::HEXLOWER_PERMISSIVE
                        .decode($hash.as_bytes())
                        .unwrap()
                );
                assert_eq!(*keys.client_to_server.cipher, hex::<64>($client_key));
                let keys = derive(
                    shared.raw_secret_bytes(),
                    &fixture,
                    &host,
                    a.as_bytes(),
                    b.as_bytes(),
                    Some(&[0x5d; $session]),
                    None,
                );
                assert_eq!(
                    *keys.server_to_client.integrity,
                    hex::<64>($server_integrity)
                );
            }};
        }
        vector!(
            p256,
            "ecdh-sha2-nistp256",
            32,
            4,
            64,
            "9fcddf47681faaaae414c358b4d7f9509cd9fa0fd7475ba644e7133ccaabe15d",
            "130f661dce2ed9e1e167cbcf55c230cf4e9cc9103698f34d82e73cfe4adbffefd2f21ba3696f44dfa558bb860c55ef13c4dd1345cfb27aefa081b37d05d174b1",
            "3d58835aae6677fdba9457c6d92f144aef8065a4aa847fd989292babcc9651dcf2bbfeab6428ccf198e700854e542492f0b8f9b229d57959e9076e3a7d7c8f48"
        );
        vector!(
            p384,
            "ecdh-sha2-nistp384",
            48,
            2,
            32,
            "b9b17e1fffdbc6b6b980a037ca22dfc1319b71b3032a2f72c9e3cfd48dedb4785e3a2d46f6b5f20ac81cfa73f30ab3af",
            "7ed285fd342bfeff1ea56f646495245e1ed426b54de629ed351df601ce063d6db0e4f19ed63ae7dd9ff071212a7f816ba15a8f9905ec643c6de5817da6a06184",
            "04c3284779e30402a4f59272dde7823bcea354e576be79a4cbc01d7bf73f858edd1333c448f0748bc9c7dea8b87054a06797e863c55f40735ac151a7d1894a21"
        );
        vector!(
            p521,
            "ecdh-sha2-nistp521",
            66,
            2,
            48,
            "9aab5621c2887c663aa24bbf8b780753fe0a96010175334b04b2c649dc183fc48110199da3782434216b872f1917ddb1cd99dcb26c7714ca2d1e3b43b0b89812",
            "1c21e84ebf764dadfe288b4fe1f731af504ade25681103eefcf8d6094fa62d5f054159d81f4cd43a165630598b3f2771cf11ca0f7cf886ad47ec138ec01ba57f",
            "4eb392987bbecc9f28071f2934188ca2f4e26225279ed9a3a9ec8408a771c981592de0fca501bfd92d7b1f4a89b7049d32a23989599979888e7adcb8628231e7"
        );
    }

    #[test]
    fn nist_key_validation_rejects_bad_sec1_points_in_both_roles() {
        let host = HostSigner::Ed25519(HostKey::from_seed(&[1; 32]).unwrap());
        let blob = host.public_blob().unwrap();
        for (method, width) in [
            ("ecdh-sha2-nistp256", 32),
            ("ecdh-sha2-nistp384", 48),
            ("ecdh-sha2-nistp521", 66),
        ] {
            let mut fixture = transcript();
            fixture.kex_algorithm = method;
            let mut off_curve = vec![0; 1 + 2 * width];
            off_curve[0] = 4;
            let mut out_of_field = vec![255; 1 + width];
            out_of_field[0] = 2;
            for malformed in [&[0][..], &[4, 1, 2], &off_curve, &out_of_field] {
                let init = fields(Some(KEX_METHOD_INIT), &[malformed]).unwrap();
                let failure = server_reply(&init, &fixture, &host, None, None)
                    .err()
                    .unwrap();
                assert_eq!(failure.to_string(), "invalid SSH NIST ECDH peer public key");
                let (client, _) = ClientExchange::start(method).unwrap();
                let reply =
                    fields(Some(KEX_METHOD_REPLY), &[&blob, malformed, b"unused proof"]).unwrap();
                let failure = client
                    .finish(&reply, &fixture, None, Default::default())
                    .err()
                    .unwrap();
                assert_eq!(failure.to_string(), "invalid SSH NIST ECDH peer public key");
            }
        }
    }

    #[test]
    fn nist_exchange_accepts_sec1_compressed_points() {
        macro_rules! check {
            ($curve:ident, $method:literal) => {{
                let (a, public_a) = EphemeralKey::generate($method).unwrap();
                let (b, public_b) = EphemeralKey::generate($method).unwrap();
                let compressed = $curve::PublicKey::from_sec1_bytes(&public_b)
                    .unwrap()
                    .to_sec1_point(true);
                assert_eq!(
                    a.agree(compressed.as_bytes()).unwrap().as_slice(),
                    b.agree(&public_a).unwrap().as_slice()
                );
            }};
        }
        check!(p256, "ecdh-sha2-nistp256");
        check!(p384, "ecdh-sha2-nistp384");
        check!(p521, "ecdh-sha2-nistp521");
    }

    #[test]
    fn ed25519_rfc8032_vector_matches_ssh_key_and_signature_blobs() {
        // RFC 8032 §7.1, TEST 1, signs an empty message.
        let seed = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let public = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let public_blob = [&b"\0\0\0\x0bssh-ed25519\0\0\0\x20"[..], &public].concat();
        let proof = [&b"\0\0\0\x0bssh-ed25519\0\0\0\x40"[..], &signature].concat();
        let identity = HostKey::from_seed(&seed).unwrap();
        assert_eq!(identity.public_key(), public);
        assert_eq!(identity.public_blob().unwrap(), public_blob);
        let parsed = keys::decode_public_key(&Algorithm::Ed25519, &public_blob).unwrap();
        assert_eq!(parsed.key_data().ed25519().unwrap().0, public);
        assert_eq!(identity.sign_blob(b"").unwrap(), proof);
        assert!(verify_signature(&public, b"", &proof).unwrap());
        assert!(!verify_signature(&public, b"different message", &proof).unwrap());

        let mut tampered = proof;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!verify_signature(&public, b"", &tampered).unwrap());
    }

    #[test]
    fn ed25519_rejects_inexact_ssh_key_and_signature_fields() {
        let identity = HostKey::from_seed(&[1; 32]).unwrap();
        let public = identity.public_key();
        for blob in [
            fields(None, &[ED25519, &[0; 31]]).unwrap(),
            fields(None, &[ED25519, &[0; 33]]).unwrap(),
            fields(None, &[b"ssh-rsa", &public]).unwrap(),
            fields(None, &[ED25519, &public, b"trailing field"]).unwrap(),
        ] {
            assert_eq!(
                keys::decode_public_key(&Algorithm::Ed25519, &blob)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        for blob in [
            fields(None, &[ED25519, &[0; 63]]).unwrap(),
            fields(None, &[ED25519, &[0; 65]]).unwrap(),
            fields(None, &[b"rsa-sha2-256", &[0; 64]]).unwrap(),
            fields(None, &[ED25519, &[0; 64], b"trailing field"]).unwrap(),
        ] {
            assert_eq!(
                verify_signature(&public, b"", &blob).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
