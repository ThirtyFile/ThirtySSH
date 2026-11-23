use super::{encoding_error, invalid, key_is_encrypted, malformed, openssh_decryption_error};
use crate::wire::Reader;
use ssh_key::{
    Cipher, Kdf, PrivateKey,
    cipher::Tag,
    private::{EcdsaKeypair, EcdsaPrivateKey},
    public::EcdsaPublicKey,
};
use std::io;
use zeroize::Zeroizing;

// ssh-key rc.11 assumes a minimum 32-byte ECDSA scalar on the wire. OpenSSH
// stores a signed mpint, which can be shorter even on a 256-bit curve.
pub(super) fn decode(
    mut header: Reader<'_>,
    public_blob: &[u8],
    public: &EcdsaPublicKey,
    cipher: Cipher,
    kdf: &Kdf,
    password: Option<&str>,
) -> io::Result<PrivateKey> {
    let body = header.string().map_err(malformed)?;
    if body.is_empty() || !body.len().is_multiple_of(cipher.block_size()) {
        return Err(invalid("invalid OpenSSH private key block length"));
    }
    let tag = if cipher.has_tag() {
        Some(
            Tag::try_from(header.remaining())
                .map_err(|_| invalid("invalid OpenSSH key tag length"))?,
        )
    } else {
        header.finish().map_err(malformed)?;
        None
    };
    if cipher == Cipher::None {
        return decode_body(body, public_blob, public, cipher);
    }
    let (key, iv) = kdf
        .derive_key_and_iv(cipher, password.ok_or_else(key_is_encrypted)?)
        .map_err(|_| openssh_decryption_error())?;
    let mut clear = Zeroizing::new(body.to_vec());
    cipher
        .decrypt(&key, &iv, &mut clear, tag)
        .map_err(|_| openssh_decryption_error())?;
    decode_body(&clear, public_blob, public, cipher)
}

fn decode_body(
    body: &[u8],
    public_blob: &[u8],
    public: &EcdsaPublicKey,
    cipher: Cipher,
) -> io::Result<PrivateKey> {
    let mut fields = Reader::new(body);
    if fields.uint32().map_err(malformed)? != fields.uint32().map_err(malformed)? {
        return Err(if cipher == Cipher::None {
            invalid("OpenSSH private key check integers differ")
        } else {
            openssh_decryption_error()
        });
    }
    // The algorithm, curve and point precede the scalar in the private section.
    let tail = fields
        .remaining()
        .strip_prefix(public_blob)
        .ok_or_else(|| invalid("inconsistent OpenSSH ECDSA public key"))?;
    let mut fields = Reader::new(tail);
    let scalar = fields.string().map_err(malformed)?;
    let comment = fields.string().map_err(malformed)?;
    let padding = fields.remaining();
    // PuTTYgen permits up to 16 padding bytes on unencrypted OpenSSH keys.
    let max_padding = if cipher == Cipher::None {
        16
    } else {
        cipher.block_size() - 1
    };
    if padding.len() > max_padding || !padding.iter().copied().eq(1..=padding.len() as u8) {
        return Err(invalid("invalid OpenSSH private key padding"));
    }
    let key = match public {
        EcdsaPublicKey::NistP256(point) => EcdsaKeypair::NistP256 {
            public: *point,
            private: decode_scalar(scalar)?,
        },
        EcdsaPublicKey::NistP384(point) => EcdsaKeypair::NistP384 {
            public: *point,
            private: decode_scalar(scalar)?,
        },
        EcdsaPublicKey::NistP521(point) => EcdsaKeypair::NistP521 {
            public: *point,
            private: decode_scalar(scalar)?,
        },
    };
    PrivateKey::new(key.into(), comment).map_err(encoding_error)
}

fn decode_scalar<const N: usize>(encoded: &[u8]) -> io::Result<EcdsaPrivateKey<N>> {
    if encoded.first().is_none_or(|first| first & 0x80 != 0) {
        return Err(invalid("expected a positive OpenSSH ECDSA scalar"));
    }
    // Accept both OpenSSH's minimal mpint and ssh-key's fixed-width encoding.
    let magnitude = encoded.strip_prefix(&[0]).unwrap_or(encoded);
    if magnitude.iter().all(|&byte| byte == 0)
        || (encoded.len() != N && encoded[0] == 0 && magnitude[0] & 0x80 == 0)
    {
        return Err(invalid("invalid OpenSSH ECDSA scalar encoding"));
    }
    let offset = N
        .checked_sub(magnitude.len())
        .ok_or_else(|| invalid("oversized OpenSSH ECDSA scalar"))?;
    let mut scalar = Zeroizing::new([0; N]);
    scalar[offset..].copy_from_slice(magnitude);
    Ok((*scalar).into())
}
