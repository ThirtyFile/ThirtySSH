//! Public-key and certificate files, and the typed reasons a key is refused.
use super::{Algorithm, Certificate, PublicKey, decode_canonical_public_key};
use crate::clear_packet::{MAX_PACKET_SIZE, invalid};
use data_encoding::{BASE64, BASE64_MIME};
use ssh_key::rand_core::{CryptoRng, UnwrapErr};
use std::{
    fs::File,
    io::{self, ErrorKind, Read},
    path::Path,
};

use super::format::MAX_KEY_FILE;

/// Why a key could not be used, where the caller can act on the reason.
///
/// Key functions return [`io::Error`]. When the failure is one of these, the
/// value travels inside it and [`KeyError::of`] finds it again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The private key is encrypted and no passphrase was supplied.
    PassphraseRequired,
    /// The public and private parts of a key pair do not belong together.
    Mismatched(&'static str),
    /// The key uses an algorithm this build does not handle. The text is the
    /// SSH algorithm name, or the object identifier of a PKCS#8 key.
    Unsupported(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PassphraseRequired => f.write_str("the private key needs a passphrase"),
            Self::Mismatched(detail) => f.write_str(detail),
            Self::Unsupported(algorithm) => write!(f, "unsupported key algorithm {algorithm}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl KeyError {
    /// The typed reason carried by an error from a key function.
    pub fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

impl From<KeyError> for io::Error {
    fn from(error: KeyError) -> Self {
        let kind = match error {
            KeyError::PassphraseRequired => ErrorKind::PermissionDenied,
            KeyError::Mismatched(_) => ErrorKind::InvalidData,
            KeyError::Unsupported(_) => ErrorKind::Unsupported,
        };
        Self::new(kind, error)
    }
}

/// An Ed25519 public key from its 32 raw bytes, with an empty comment.
pub fn from_ed25519(key: &[u8; 32]) -> PublicKey {
    use ssh_key::public::{Ed25519PublicKey, KeyData};
    PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(*key)), "")
}

/// Decode a binary SSH public key blob. The whole input must be the key in
/// its canonical encoding.
pub fn from_blob(blob: &[u8]) -> io::Result<PublicKey> {
    check_blob_size(blob.len())?;
    decode_canonical_public_key(blob)
}

/// Decode the base64 form of a public key blob. Line wrapping is accepted.
pub fn from_base64(text: &str) -> io::Result<PublicKey> {
    if text.len() > MAX_KEY_FILE {
        return Err(invalid("SSH public key text exceeds size limit"));
    }
    let blob = BASE64_MIME
        .decode(text.as_bytes())
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    from_blob(&blob)
}

/// Read a public key file: an OpenSSH `algorithm base64 [comment]` line, or
/// bare base64 that may span several lines.
pub fn from_file(path: impl AsRef<Path>) -> io::Result<PublicKey> {
    let contents = read_key_file(path.as_ref())?;
    let mut fields = contents.split_ascii_whitespace();
    let first = fields
        .next()
        .ok_or_else(|| invalid("SSH public key file is empty"))?;
    // Base64 text is never an algorithm name, so anything else is bare
    // base64, which may be wrapped over several lines.
    let blob = match fields.next() {
        Some(blob) if Algorithm::new(first).is_ok() => blob,
        _ => return from_base64(contents.trim_ascii()),
    };
    let key = from_base64(blob)?;
    if key.algorithm().as_str() != first {
        return Err(invalid("SSH public key type does not match its encoding"));
    }
    Ok(key)
}

/// Read an OpenSSH certificate file. Whether the certificate is trusted and
/// currently valid is decided separately.
pub fn certificate_from_file(path: impl AsRef<Path>) -> io::Result<Certificate> {
    let malformed = |error| io::Error::new(ErrorKind::InvalidData, error);
    let contents = read_key_file(path.as_ref())?;
    let field = contents.split_ascii_whitespace().nth(1).unwrap_or_default();
    if field.len() > MAX_PACKET_SIZE.div_ceil(3) * 4 {
        return Err(invalid("SSH certificate exceeds size limit"));
    }
    let certificate = Certificate::from_openssh(&contents).map_err(malformed)?;
    let blob = BASE64
        .decode(field.as_bytes())
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    check_blob_size(blob.len())?;
    if certificate.to_bytes().map_err(malformed)? != blob {
        return Err(invalid("noncanonical SSH certificate encoding"));
    }
    Ok(certificate)
}

fn read_key_file(path: &Path) -> io::Result<String> {
    let mut contents = String::new();
    File::open(path)?
        .take((MAX_KEY_FILE + 1) as u64)
        .read_to_string(&mut contents)?;
    if contents.len() > MAX_KEY_FILE {
        return Err(invalid("SSH key file exceeds size limit"));
    }
    Ok(contents)
}

fn check_blob_size(size: usize) -> io::Result<()> {
    if size > MAX_PACKET_SIZE {
        return Err(invalid("SSH public key blob exceeds size limit"));
    }
    Ok(())
}

/// A cryptographic random number generator backed by the operating system,
/// for generating keys.
pub fn system_rng() -> impl CryptoRng {
    UnwrapErr(getrandom::SysRng)
}
