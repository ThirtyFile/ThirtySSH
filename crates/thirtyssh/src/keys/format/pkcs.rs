use super::{PrivateKey, PrivateKeyLimits, check_size, encoding_error, invalid, key_is_encrypted};
use crate::keys::KeyError;
use ed25519::pkcs8::{ALGORITHM_OID as ED25519, KeypairBytes};
use pkcs5::pbes2::{Kdf, Parameters};
use pkcs8::{
    EncodePrivateKey, EncryptedPrivateKeyInfoRef, ObjectIdentifier, PrivateKeyInfoRef,
    SecretDocument, der::Decode,
};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData};
use std::io::{self, ErrorKind};
use zeroize::Zeroizing;
#[cfg(feature = "rsa")]
use {
    super::{MAX_RSA_BITS, rsa_private_key},
    pkcs8::der::{
        Tag, Tagged,
        asn1::{AnyRef, OctetStringRef, UintRef},
    },
    rsa::traits::PrivateKeyParts,
    ssh_key::{
        Mpint,
        private::{RsaKeypair, RsaPrivateKey},
        public::RsaPublicKey,
    },
};

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

#[cfg(not(feature = "rsa"))]
pub(super) fn rsa_pkcs1_unavailable() -> io::Error {
    KeyError::Unsupported("RSA".into()).into()
}

pub(super) fn decode_pkcs8(
    bytes: &[u8],
    password: Option<&[u8]>,
    limits: PrivateKeyLimits,
) -> io::Result<PrivateKey> {
    check_size(bytes.len())?;
    if password.is_some() {
        return decode_pkcs8_encrypted(bytes, password, limits);
    }
    decode_pkcs8_plain(bytes)
        .or_else(|error| decode_sec1(bytes).or(Err(error)))
        .map_err(|error| {
            if EncryptedPrivateKeyInfoRef::from_der(bytes).is_ok() {
                key_is_encrypted()
            } else {
                error
            }
        })
}

pub(super) fn decode_pkcs8_plain(bytes: &[u8]) -> io::Result<PrivateKey> {
    let key = PrivateKeyInfoRef::from_der(bytes)
        .map_err(encoding_error)
        .and_then(decode_key_info);
    #[cfg(feature = "pre-rfc8410-ed25519")]
    let key = key.or_else(|error| super::legacy_ed25519::decode(bytes).or(Err(error)));
    key
}

pub(super) fn decode_pkcs8_encrypted(
    bytes: &[u8],
    password: Option<&[u8]>,
    limits: PrivateKeyLimits,
) -> io::Result<PrivateKey> {
    let encrypted = EncryptedPrivateKeyInfoRef::from_der(bytes).map_err(encoding_error)?;
    let params = encrypted.encryption_algorithm.pbes2().ok_or_else(|| {
        io::Error::new(
            ErrorKind::Unsupported,
            "unsupported PKCS#8 encryption scheme",
        )
    })?;
    match &params.kdf {
        Kdf::Pbkdf2(kdf) => {
            if kdf.iteration_count == 0 || kdf.iteration_count > limits.max_pbkdf2_rounds {
                return Err(invalid(
                    "PKCS#8 PBKDF2 rounds exceed the configured limit or are zero",
                ));
            }
        }
        Kdf::Scrypt(kdf) => {
            let n = kdf.cost_parameter;
            let r = u64::from(kdf.block_size);
            let p = u64::from(kdf.parallelization);
            if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
                return Err(invalid("invalid PKCS#8 scrypt parameters"));
            }
            let memory = n
                .checked_add(p + 1)
                .and_then(|size| size.checked_mul(128 * r));
            let work = n.checked_mul(r * p);
            if memory.is_none_or(|memory| memory > limits.max_scrypt_memory)
                || work.is_none_or(|work| work > limits.max_scrypt_work)
            {
                return Err(invalid("PKCS#8 scrypt cost exceeds the configured limit"));
            }
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported PKCS#8 KDF",
            ));
        }
    }

    let password = password.ok_or_else(key_is_encrypted)?;
    // The backend decrypts in-place, so a failure still drops the zeroizing buffer.
    let mut plaintext = Zeroizing::new(encrypted.encrypted_data.as_bytes().to_vec());
    let plaintext =
        params
            .decrypt_in_place(password, &mut plaintext)
            .map_err(|error| match error {
                pkcs5::Error::UnsupportedAlgorithm { .. } => {
                    io::Error::new(ErrorKind::Unsupported, error)
                }
                pkcs5::Error::AlgorithmParametersInvalid { .. } => encoding_error(error),
                _ => decryption_failed(),
            })?;
    // CBC can yield valid padding with an incorrect passphrase. Treat
    // invalid decrypted key data the same as a padding or tag failure.
    decode_pkcs8_plain(plaintext).map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            decryption_failed()
        } else {
            error
        }
    })
}

fn decryption_failed() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "could not decrypt PKCS#8 private key",
    )
}

fn decode_key_info(key: PrivateKeyInfoRef<'_>) -> io::Result<PrivateKey> {
    let outer_public = key
        .public_key
        .map(|public| {
            public
                .as_bytes()
                .ok_or_else(|| invalid("unaligned PKCS#8 public key"))
        })
        .transpose()?;
    let private = key.private_key.as_bytes();
    let keypair = match key.algorithm.oid {
        ED25519 => {
            let components = KeypairBytes::try_from(key).map_err(encoding_error)?;
            let pair = Ed25519Keypair::from_seed(&components.secret_key);
            if components
                .public_key
                .is_some_and(|public| public.0 != pair.public.0)
            {
                return Err(KeyError::Mismatched("inconsistent PKCS#8 Ed25519 keypair").into());
            }
            pair.into()
        }
        #[cfg(feature = "rsa")]
        RSA => {
            if key.algorithm.parameters.is_some_and(|parameters| {
                parameters.tag() != Tag::Null || !parameters.value().is_empty()
            }) {
                return Err(invalid("unexpected RSA PKCS#8 parameters"));
            }
            let private = pkcs1::RsaPrivateKeyRef::from_der(private).map_err(encoding_error)?;
            if let Some(public) = outer_public {
                let public = pkcs1::RsaPublicKeyRef::from_der(public).map_err(encoding_error)?;
                if public != private.public_key() {
                    return Err(KeyError::Mismatched("inconsistent PKCS#8 RSA public key").into());
                }
            }
            rsa_keypair(private)?.into()
        }
        #[cfg(not(feature = "rsa"))]
        RSA => {
            return Err(KeyError::Unsupported(RSA.to_string()).into());
        }
        sec1::ALGORITHM_OID => {
            let parameters = key
                .algorithm
                .parameters
                .ok_or_else(|| invalid("missing PKCS#8 EC parameters"))?;
            super::ec::decode_keypair(private, Some(parameters), outer_public)?.into()
        }
        _ => {
            return Err(KeyError::Unsupported(key.algorithm.oid.to_string()).into());
        }
    };
    PrivateKey::new(keypair, "").map_err(encoding_error)
}

#[cfg(feature = "rsa")]
pub(super) fn decode_pkcs1(bytes: &[u8]) -> io::Result<PrivateKey> {
    let private = pkcs1::RsaPrivateKeyRef::from_der(bytes).map_err(encoding_error)?;
    PrivateKey::new(rsa_keypair(private)?.into(), "").map_err(encoding_error)
}

#[cfg(not(feature = "rsa"))]
pub(super) fn decode_pkcs1(_: &[u8]) -> io::Result<PrivateKey> {
    Err(rsa_pkcs1_unavailable())
}

#[cfg(feature = "rsa")]
fn rsa_keypair(key: pkcs1::RsaPrivateKeyRef<'_>) -> io::Result<RsaKeypair> {
    if key.other_prime_infos.is_some() {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "multiprime RSA is unsupported by SSH",
        ));
    }
    let max = MAX_RSA_BITS / 8;
    if key.public_exponent.as_bytes().len() > 5
        || [
            key.modulus,
            key.private_exponent,
            key.prime1,
            key.prime2,
            key.exponent1,
            key.exponent2,
            key.coefficient,
        ]
        .iter()
        .any(|component| component.as_bytes().len() > max)
    {
        return Err(invalid("SSH RSA private key exceeds supported limits"));
    }
    let mpint = |value: UintRef<'_>| Mpint::from_positive_bytes(value.as_bytes());
    let public = RsaPublicKey::new(mpint(key.public_exponent), mpint(key.modulus))
        .map_err(encoding_error)?;
    let private = RsaPrivateKey::new(
        mpint(key.private_exponent),
        mpint(key.coefficient),
        mpint(key.prime1),
        mpint(key.prime2),
    )
    .map_err(encoding_error)?;
    let pair = RsaKeypair::new(public, private).map_err(encoding_error)?;
    let derived = rsa_private_key(&pair).map_err(|_| invalid("inconsistent PKCS RSA keypair"))?;
    let (dp, dq, coefficient) = rsa_crt(&derived)?;
    if &**dp != key.exponent1.as_bytes()
        || &**dq != key.exponent2.as_bytes()
        || &**coefficient != key.coefficient.as_bytes()
    {
        return Err(invalid("inconsistent PKCS RSA CRT parameters"));
    }
    Ok(pair)
}

#[cfg(feature = "rsa")]
type SecretBytes = Zeroizing<Box<[u8]>>;

#[cfg(feature = "rsa")]
fn rsa_crt(key: &rsa::PrivateKey) -> io::Result<(SecretBytes, SecretBytes, SecretBytes)> {
    let dp = key
        .dp()
        .ok_or_else(|| invalid("missing RSA CRT exponent"))?;
    let dq = key
        .dq()
        .ok_or_else(|| invalid("missing RSA CRT exponent"))?;
    let coefficient = Zeroizing::new(
        key.crt_coefficient()
            .ok_or_else(|| invalid("missing RSA CRT coefficient"))?,
    );
    Ok((
        Zeroizing::new(dp.to_be_bytes_trimmed_vartime()),
        Zeroizing::new(dq.to_be_bytes_trimmed_vartime()),
        Zeroizing::new(coefficient.to_be_bytes_trimmed_vartime()),
    ))
}

pub(super) fn decode_sec1(bytes: &[u8]) -> io::Result<PrivateKey> {
    PrivateKey::new(super::ec::decode_keypair(bytes, None, None)?.into(), "")
        .map_err(encoding_error)
}

/// Passphrase protection for PKCS#8 output, using PBKDF2-HMAC-SHA256 and
/// AES-256-CBC.
#[derive(Clone, Copy, Debug)]
pub struct Pkcs8Encryption<'a> {
    pub passphrase: &'a [u8],
    /// PBKDF2 iterations.
    pub rounds: u32,
}

fn pkcs8_document(
    key: &PrivateKey,
    encryption: Option<Pkcs8Encryption<'_>>,
) -> io::Result<(SecretDocument, &'static str)> {
    Ok(match encryption {
        Some(encryption) => (
            encrypt_key_info(encryption.passphrase, encryption.rounds, key)?,
            "ENCRYPTED PRIVATE KEY",
        ),
        None => (encode_key_info(key)?, "PRIVATE KEY"),
    })
}

/// Encode a private key as PKCS#8 DER. Without encryption the result is the
/// plaintext key, and it is erased when dropped.
pub fn pkcs8_der(
    key: &PrivateKey,
    encryption: Option<Pkcs8Encryption<'_>>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let (document, _) = pkcs8_document(key, encryption)?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

/// Encode a private key as a PKCS#8 PEM document.
pub fn pkcs8_pem(
    key: &PrivateKey,
    encryption: Option<Pkcs8Encryption<'_>>,
) -> io::Result<Zeroizing<String>> {
    let (document, label) = pkcs8_document(key, encryption)?;
    document
        .to_pem(label, pem_rfc7468::LineEnding::LF)
        .map_err(encoding_error)
}

fn encrypt_key_info(pass: &[u8], rounds: u32, key: &PrivateKey) -> io::Result<SecretDocument> {
    if rounds == 0 || rounds > PrivateKeyLimits::default().max_pbkdf2_rounds {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid PKCS#8 PBKDF2 rounds",
        ));
    }
    let document = encode_key_info(key)?;
    let info = PrivateKeyInfoRef::from_der(document.as_bytes()).map_err(encoding_error)?;
    let (mut salt, mut iv) = ([0u8; 32], [0u8; 16]);
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    getrandom::fill(&mut iv).map_err(io::Error::other)?;
    let params =
        Parameters::generate_pbkdf2_sha256_aes256cbc(rounds, &salt, iv).map_err(encoding_error)?;
    info.encrypt_with_params(params, pass)
        .map_err(encoding_error)
}

fn encode_key_info(key: &PrivateKey) -> io::Result<SecretDocument> {
    match key.key_data() {
        KeypairData::Ed25519(pair) => {
            if Ed25519Keypair::from_seed(pair.private.as_ref()).public != pair.public {
                return Err(invalid("inconsistent SSH Ed25519 keypair"));
            }
            KeypairBytes {
                secret_key: *pair.private.as_ref(),
                public_key: None,
            }
            .to_pkcs8_der()
            .map_err(encoding_error)
        }
        #[cfg(feature = "rsa")]
        KeypairData::Rsa(pair) => encode_rsa(pair),
        #[cfg(not(feature = "rsa"))]
        KeypairData::Rsa(_) => Err(KeyError::Unsupported(key.algorithm().as_str().into()).into()),
        KeypairData::Ecdsa(pair) => {
            super::validate_keypair(key)?;
            let private = pair.private_key_bytes();
            match pair {
                EcdsaKeypair::NistP256 { .. } => p256::SecretKey::from_slice(private)
                    .map_err(encoding_error)?
                    .to_pkcs8_der()
                    .map_err(encoding_error),
                EcdsaKeypair::NistP384 { .. } => p384::SecretKey::from_slice(private)
                    .map_err(encoding_error)?
                    .to_pkcs8_der()
                    .map_err(encoding_error),
                EcdsaKeypair::NistP521 { .. } => p521::SecretKey::from_slice(private)
                    .map_err(encoding_error)?
                    .to_pkcs8_der()
                    .map_err(encoding_error),
            }
        }
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported PKCS#8 key algorithm",
        )),
    }
}

#[cfg(feature = "rsa")]
pub(in super::super) fn rsa_pkcs1_der(
    pair: &RsaKeypair,
    backend: &rsa::PrivateKey,
) -> io::Result<SecretDocument> {
    let (dp, dq, coefficient) = rsa_crt(backend)?;
    fn integer(value: &Mpint) -> io::Result<UintRef<'_>> {
        let positive = value
            .as_positive_bytes()
            .ok_or_else(|| invalid("invalid RSA integer"))?;
        UintRef::new(positive).map_err(encoding_error)
    }
    let public = pair.public();
    let private = pair.private();
    SecretDocument::try_from(pkcs1::RsaPrivateKeyRef {
        modulus: integer(public.n())?,
        public_exponent: integer(public.e())?,
        private_exponent: integer(private.d())?,
        prime1: integer(private.p())?,
        prime2: integer(private.q())?,
        exponent1: UintRef::new(&dp).map_err(encoding_error)?,
        exponent2: UintRef::new(&dq).map_err(encoding_error)?,
        coefficient: UintRef::new(&coefficient).map_err(encoding_error)?,
        other_prime_infos: None,
    })
    .map_err(encoding_error)
}

#[cfg(feature = "rsa")]
fn encode_rsa(pair: &RsaKeypair) -> io::Result<SecretDocument> {
    let backend = rsa_private_key(pair)?;
    let inner = rsa_pkcs1_der(pair, &backend)?;
    let info = PrivateKeyInfoRef::new(
        pkcs8::AlgorithmIdentifierRef {
            oid: RSA,
            parameters: Some(AnyRef::NULL),
        },
        OctetStringRef::new(inner.as_bytes()).map_err(encoding_error)?,
    );
    SecretDocument::try_from(info).map_err(encoding_error)
}
