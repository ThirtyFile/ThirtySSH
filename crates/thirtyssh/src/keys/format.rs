//! Bounded loading of persisted private keys.
mod ec;
#[cfg(feature = "pre-rfc8410-ed25519")]
mod legacy_ed25519;
mod legacy_pem;
mod openssh_ec;
pub(super) mod pkcs;
mod ppk;
pub use pkcs::{Pkcs8Encryption, pkcs8_der, pkcs8_pem};

#[cfg(feature = "rsa")]
use super::rsa_private_key;
use super::{KeyError, MAX_RSA_BITS, PrivateKey, decode_canonical_public_key, ssh_key::Cipher};
use crate::{auth::malformed, clear_packet::invalid, wire::Reader};
use signature::{Signer, Verifier};
use ssh_encoding::{
    Uint,
    bigint::{
        Resize,
        modular::{BoxedMontyForm, BoxedMontyParams},
    },
};
use ssh_key::{private::DsaKeypair, public::DsaPublicKey};
use std::{
    error::Error,
    fs::File,
    io::{self, ErrorKind, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub(super) const MAX_KEY_FILE: usize = 1024 * 1024;
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Cost limits applied before deriving encryption keys from a passphrase.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PrivateKeyLimits {
    /// Maximum allowed bcrypt-PBKDF rounds for an OpenSSH private key.
    pub max_bcrypt_rounds: u32,
    /// Maximum PBKDF2 iterations for encrypted PKCS#8.
    pub max_pbkdf2_rounds: u32,
    /// Maximum estimated scrypt buffer bytes.
    pub max_scrypt_memory: u64,
    /// Maximum scrypt work factor (N times r times p).
    pub max_scrypt_work: u64,
    /// Maximum Argon2 memory in KiB for a PPK v3 key.
    pub max_argon2_memory_kib: u32,
    /// Maximum total PPK Argon2 work in KiB times passes.
    pub max_argon2_work: u64,
    /// Maximum Argon2 lanes for PPK v3.
    pub max_argon2_parallelism: u32,
}

impl Default for PrivateKeyLimits {
    fn default() -> Self {
        Self {
            max_bcrypt_rounds: 256,
            max_pbkdf2_rounds: 1_000_000,
            max_scrypt_memory: 128 * 1024 * 1024,
            max_scrypt_work: 4 * 1024 * 1024,
            max_argon2_memory_kib: 128 * 1024,
            max_argon2_work: 1024 * 1024,
            max_argon2_parallelism: 8,
        }
    }
}

/// Reads private keys in every supported format: OpenSSH, PKCS#8, PKCS#1,
/// SEC1 and PuTTY.
///
/// A reader holds the passphrase to try and the cost limits for
/// passphrase-based key derivation, and can be reused for any number of keys.
/// A key that turns out to be encrypted when no passphrase was set fails with
/// [`KeyError::PassphraseRequired`].
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivateKeyReader<'a> {
    passphrase: Option<&'a str>,
    limits: PrivateKeyLimits,
}

impl<'a> PrivateKeyReader<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The passphrase for encrypted keys. Unencrypted keys ignore it.
    pub fn passphrase(mut self, passphrase: impl Into<Option<&'a str>>) -> Self {
        self.passphrase = passphrase.into();
        self
    }

    /// Replace the default key-derivation cost limits.
    pub fn limits(mut self, limits: PrivateKeyLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Read a key file of at most 1 MiB.
    pub fn file(&self, path: impl AsRef<Path>) -> io::Result<PrivateKey> {
        let mut file = File::open(path)?;
        let expected = file.metadata()?.len().min(MAX_KEY_FILE as u64) as usize;
        let contents = read_secret(&mut file, expected)?;
        self.text(std::str::from_utf8(&contents).map_err(encoding_error)?)
    }

    /// Decode the text of a key file: a PEM document or a PuTTY key.
    pub fn text(&self, contents: &str) -> io::Result<PrivateKey> {
        parse_text(contents, self.passphrase, self.limits)
    }

    /// Decode the binary body of an `OPENSSH PRIVATE KEY` document.
    pub fn openssh(&self, bytes: &[u8]) -> io::Result<PrivateKey> {
        decode_openssh_with_limits(bytes, self.passphrase, self.limits)
    }

    /// Decode DER: PKCS#8, or a bare SEC1 elliptic-curve key. With a
    /// passphrase set, the input must be encrypted PKCS#8.
    pub fn der(&self, bytes: &[u8]) -> io::Result<PrivateKey> {
        pkcs::decode_pkcs8(bytes, self.passphrase.map(str::as_bytes), self.limits)
    }
}

/// Read a private key of about `expected` bytes into memory that is erased
/// on drop. The buffers never reallocate, so no copy of the key is left
/// behind when the input is longer than expected.
fn read_secret(input: &mut impl Read, expected: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut contents = Zeroizing::new(vec![0; expected.min(MAX_KEY_FILE) + 1]);
    let mut len = fill(input, &mut contents)?;
    if len == contents.len() && len <= MAX_KEY_FILE {
        // The input outgrew its reported size. Continue in a buffer that
        // holds the largest accepted key and one byte more.
        let mut larger = Zeroizing::new(vec![0; MAX_KEY_FILE + 1]);
        larger[..len].copy_from_slice(&contents);
        len += fill(input, &mut larger[len..])?;
        contents = larger;
    }
    check_size(len)?;
    contents.truncate(len);
    Ok(contents)
}

/// Read until the buffer is full or the input ends.
fn fill(input: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut len = 0;
    while len < buffer.len() {
        match input.read(&mut buffer[len..]) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(len)
}

fn parse_text(
    contents: &str,
    password: Option<&str>,
    limits: PrivateKeyLimits,
) -> io::Result<PrivateKey> {
    check_size(contents.len())?;
    let contents = contents.trim();
    if contents.starts_with(ppk::HEADER_PREFIX) {
        return ppk::decode_ppk(contents, password, limits);
    }
    if let Some(result) = legacy_pem::decode_legacy_pem(contents, password) {
        return result;
    }
    let mut pem =
        pem_rfc7468::Decoder::new_detect_wrap(contents.as_bytes()).map_err(encoding_error)?;
    let label = pem.type_label();
    #[cfg(not(feature = "rsa"))]
    if label == "RSA PRIVATE KEY" {
        return Err(pkcs::rsa_pkcs1_unavailable());
    }
    let mut binary = Zeroizing::new(vec![0; pem.remaining_len()]);
    pem.decode(&mut binary).map_err(encoding_error)?;
    match label {
        "OPENSSH PRIVATE KEY" => decode_openssh_with_limits(&binary, password, limits),
        #[cfg(feature = "rsa")]
        "RSA PRIVATE KEY" => pkcs::decode_pkcs1(&binary),
        "EC PRIVATE KEY" => pkcs::decode_sec1(&binary),
        "PRIVATE KEY" => pkcs::decode_pkcs8_plain(&binary),
        "ENCRYPTED PRIVATE KEY" => {
            pkcs::decode_pkcs8_encrypted(&binary, password.map(str::as_bytes), limits)
        }
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported private key format",
        )),
    }
}

fn decode_openssh_with_limits(
    contents: &[u8],
    password: Option<&str>,
    limits: PrivateKeyLimits,
) -> io::Result<PrivateKey> {
    check_size(contents.len())?;
    let binary = contents
        .strip_prefix(OPENSSH_MAGIC)
        .ok_or_else(|| invalid("invalid OpenSSH private key header"))?;
    let mut header = Reader::new(binary);
    let cipher = header.string().map_err(malformed)?;
    let cipher = std::str::from_utf8(cipher)
        .ok()
        .and_then(|cipher| Cipher::new(cipher).ok())
        .filter(|cipher| *cipher != Cipher::TdesCbc)
        .ok_or_else(|| io::Error::new(ErrorKind::Unsupported, "unsupported OpenSSH key cipher"))?;
    let kdf = header.string().map_err(malformed)?;
    let options = header.string().map_err(malformed)?;
    let kdf = match (cipher, kdf) {
        (Cipher::None, b"none") if options.is_empty() => ssh_key::Kdf::None,
        (Cipher::None, _) | (_, b"none") => {
            return Err(invalid("inconsistent OpenSSH private key cipher and KDF"));
        }
        (_, b"bcrypt") => {
            let mut options = Reader::new(options);
            let salt = options.string().map_err(malformed)?;
            let rounds = options.uint32().map_err(malformed)?;
            options.finish().map_err(malformed)?;
            if salt.is_empty() || salt.len() > 1024 || rounds == 0 {
                return Err(invalid("invalid OpenSSH bcrypt parameters"));
            }
            if rounds > limits.max_bcrypt_rounds {
                return Err(invalid("OpenSSH bcrypt rounds exceed the configured limit"));
            }
            ssh_key::Kdf::Bcrypt {
                salt: salt.to_vec(),
                rounds,
            }
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported OpenSSH key KDF",
            ));
        }
    };
    if header.uint32().map_err(malformed)? != 1 {
        return Err(invalid("expected one key in the OpenSSH private key file"));
    }
    let public_blob = header.string().map_err(malformed)?;
    let public = decode_canonical_public_key(public_blob)?;
    let key = if let Some(point) = public.key_data().ecdsa() {
        openssh_ec::decode(header, public_blob, point, cipher, &kdf, password)?
    } else {
        let key = PrivateKey::from_bytes(contents).map_err(encoding_error)?;
        if key.is_encrypted() {
            key.decrypt(password.ok_or_else(key_is_encrypted)?)
                .map_err(|_| openssh_decryption_error())?
        } else {
            key
        }
    };
    validate_keypair(&key)?;
    Ok(key)
}

/// Refuse keys beyond the supported sizes and keys whose private half does
/// not belong to their public half.
pub(super) fn validate_keypair(key: &PrivateKey) -> io::Result<()> {
    if let Some(rsa) = key.key_data().rsa() {
        let max = MAX_RSA_BITS / 8 + 1;
        let private = rsa.private();
        if rsa.public().key_size() as usize > MAX_RSA_BITS
            || rsa.public().e().as_bytes().len() > 5
            || [private.d(), private.p(), private.q(), private.iqmp()]
                .iter()
                .any(|component| component.as_bytes().len() > max)
        {
            return Err(invalid("SSH RSA private key exceeds supported limits"));
        }
        #[cfg(feature = "rsa")]
        rsa_private_key(rsa).map_err(|_| invalid("inconsistent SSH RSA keypair"))?;
    } else if let Some(dsa) = key.key_data().dsa() {
        validate_dsa_keypair(dsa)?;
    } else if key.key_data().ecdsa().is_some() {
        let challenge = b"ThirtySSH private key validation";
        let signature = key
            .try_sign(challenge)
            .map_err(|_| invalid("invalid SSH ECDSA private scalar"))?;
        Verifier::verify(key.public_key(), challenge, &signature)
            .map_err(|_| invalid("inconsistent SSH ECDSA keypair"))?;
    }
    Ok(())
}

pub(super) fn dsa_parameters(public: &DsaPublicKey) -> io::Result<[Uint; 4]> {
    // RFC 4253 DSS uses at most 1024-bit p and 160-bit q. Check dimensions
    // before doing modular arithmetic with values from the key file.
    if [public.p(), public.g(), public.y()]
        .iter()
        .any(|n| n.as_bytes().len() > 129)
        || public.q().as_bytes().len() > 21
    {
        return Err(invalid("SSH DSA key exceeds supported limits"));
    }
    let p = Uint::try_from(public.p()).map_err(encoding_error)?;
    let q = Uint::try_from(public.q()).map_err(encoding_error)?;
    let g = Uint::try_from(public.g()).map_err(encoding_error)?;
    let y = Uint::try_from(public.y()).map_err(encoding_error)?;
    let one = Uint::from(1u8);
    let p_bits = p.bit_width_vartime();
    if !(512..=1024).contains(&p_bits)
        || !p_bits.is_multiple_of(64)
        || q.bit_width_vartime() != 160
        || g <= one
        || g >= p
        || y <= one
        || y >= p
    {
        return Err(invalid("invalid SSH DSA key components"));
    }
    Ok([p, q, g, y])
}

pub(super) fn validate_dsa_keypair(key: &DsaKeypair) -> io::Result<()> {
    let [p, q, g, y] = dsa_parameters(key.public())?;
    if key.private().as_bytes().len() > 21 {
        return Err(invalid("SSH DSA key exceeds supported limits"));
    }
    let secret = key
        .private()
        .as_mpint()
        .as_positive_bytes()
        .ok_or_else(|| invalid("invalid SSH DSA exponent"))?;
    let x = Zeroizing::new(Uint::from_be_slice(secret, 192).map_err(encoding_error)?);
    if *x == Uint::from(0u8) || *x >= q {
        return Err(invalid("invalid SSH DSA exponent"));
    }
    let modulus = Option::from(p.to_odd()).ok_or_else(|| invalid("invalid SSH DSA modulus"))?;
    let params = BoxedMontyParams::new_vartime(modulus);
    let generator = BoxedMontyForm::new(g.resize(params.bits_precision()), &params);
    if generator.pow(&q).retrieve() != Uint::from(1u8)
        || generator.pow_bounded_exp(&x, 160).retrieve() != y
    {
        return Err(invalid("inconsistent SSH DSA keypair"));
    }
    Ok(())
}

fn encoding_error(error: impl Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error)
}

fn openssh_decryption_error() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "could not decrypt OpenSSH private key",
    )
}

fn key_is_encrypted() -> io::Error {
    KeyError::PassphraseRequired.into()
}

fn check_size(len: usize) -> io::Result<()> {
    if len > MAX_KEY_FILE {
        return Err(invalid("private key exceeds the file size limit"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reads_follow_the_input_and_keep_the_size_limit() {
        let key: Vec<u8> = (0..=250).cycle().take(3000).collect();
        // An exact size, a size that grew or was not reported, and a size
        // that shrank all return the bytes actually read.
        for expected in [key.len(), 0, 100, key.len() + 500, usize::MAX] {
            let contents = read_secret(&mut key.as_slice(), expected).unwrap();
            assert_eq!(*contents, key);
        }
        assert!(read_secret(&mut io::empty(), 0).unwrap().is_empty());

        let largest = vec![b'a'; MAX_KEY_FILE];
        for expected in [0, MAX_KEY_FILE] {
            assert_eq!(
                read_secret(&mut largest.as_slice(), expected)
                    .unwrap()
                    .len(),
                MAX_KEY_FILE
            );
            let error = read_secret(&mut io::repeat(b'a'), expected).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }
}
