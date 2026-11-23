//! SSH key and signature types shared with the protocol and application policies.
pub mod agent;
mod certificate;
mod format;
mod key;
#[cfg(test)]
mod vectors;

use crate::{clear_packet::invalid, kex, wire::Reader};
use signature::{Signer, Verifier};
use ssh_key::public::KeyData;
use std::io::{self, ErrorKind};
#[cfg(feature = "rsa")]
use {
    sha1::Sha1,
    sha2::{Sha256, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    ssh_encoding::Uint,
};

pub(crate) use certificate::{
    CertificatePermissions, CertificateRequest, certificate_signature_algorithm,
    decode_certificate, decode_host_identity,
};
pub use certificate::{
    CertificateRevocations, CertificateSignaturePolicy, Credential, validate_certificate_at,
    validate_user_certificate_at,
};
pub use format::{Pkcs8Encryption, PrivateKeyLimits, PrivateKeyReader, pkcs8_der, pkcs8_pem};
pub use key::{KeyError, system_rng};
pub use ssh_key::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey, Signature};
pub use {signature, ssh_encoding, ssh_key};

/// Public keys and certificates from their binary, base64 and file forms.
pub mod public {
    pub use super::key::{certificate_from_file, from_base64, from_blob, from_ed25519, from_file};
}

/// Implemented SSH signature algorithms in default preference order.
pub const SIGNATURE_ALGORITHMS: [Algorithm; 4 + 2 * cfg!(feature = "rsa") as usize] = [
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

pub(crate) fn server_host_algorithms() -> Vec<Algorithm> {
    SIGNATURE_ALGORITHMS
        .iter()
        .map(|algorithm| {
            Algorithm::new(&algorithm.to_certificate_type())
                .expect("supported host certificate name")
        })
        .chain(SIGNATURE_ALGORITHMS)
        .collect()
}

pub(crate) const RSA_SHA1: Algorithm = Algorithm::Rsa { hash: None };
#[cfg(feature = "rsa")]
const MAX_RSA_BITS: usize = rsa::PublicKey::MAX_SIZE;
#[cfg(not(feature = "rsa"))]
const MAX_RSA_BITS: usize = 8192;

/// Signature algorithms a server accepts for public-key user authentication.
#[derive(Clone)]
pub(crate) struct UserSignatures(Vec<Algorithm>);

impl Default for UserSignatures {
    fn default() -> Self {
        Self(SIGNATURE_ALGORITHMS.to_vec())
    }
}

impl UserSignatures {
    pub(crate) fn from_algorithms(algorithms: &[Algorithm]) -> Self {
        Self(
            algorithms
                .iter()
                .filter(|algorithm| supports_signature_algorithm(algorithm))
                .cloned()
                .collect(),
        )
    }

    pub(crate) fn permits(&self, algorithm: &Algorithm) -> bool {
        self.0.contains(algorithm)
    }
}

/// Whether the runtime can process this raw signature algorithm when configured.
pub fn supports_signature_algorithm(algorithm: &Algorithm) -> bool {
    SIGNATURE_ALGORITHMS.contains(algorithm)
        || (cfg!(feature = "rsa") && algorithm == &RSA_SHA1)
        || (cfg!(feature = "dsa") && algorithm == &Algorithm::Dsa)
}

fn key_format(algorithm: &Algorithm) -> &Algorithm {
    if matches!(algorithm, Algorithm::Rsa { .. }) {
        &RSA_SHA1
    } else {
        algorithm
    }
}

pub(crate) fn matches_key(key: &PublicKey, algorithm: &Algorithm) -> bool {
    key_format(algorithm) == &key.algorithm()
}

pub(crate) fn signature_algorithm(
    key: &PublicKey,
    requested: Option<Algorithm>,
    peer_algorithms: Option<&str>,
) -> io::Result<Algorithm> {
    select_signature_algorithm(key, requested, peer_algorithms, false)
}

pub(crate) fn user_certificate_signature_algorithm(
    key: &PublicKey,
    requested: Option<Algorithm>,
    peer_algorithms: Option<&str>,
) -> io::Result<Algorithm> {
    select_signature_algorithm(key, requested, peer_algorithms, true)
}

fn select_signature_algorithm(
    key: &PublicKey,
    requested: Option<Algorithm>,
    peer_algorithms: Option<&str>,
    certificate: bool,
) -> io::Result<Algorithm> {
    if let Some(algorithm) = requested {
        if supports_signature_algorithm(&algorithm) && matches_key(key, &algorithm) {
            return Ok(algorithm);
        }
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH signature algorithm does not match the key or is disabled",
        ));
    }
    // Favor SHA-256 for RSA when the peer does not advertise its algorithms.
    // An explicit request may override the announcement.
    SIGNATURE_ALGORITHMS
        .into_iter()
        .find(|algorithm| {
            matches_key(key, algorithm)
                && match peer_algorithms {
                    Some(peer) => {
                        let certificate_name = certificate.then(|| algorithm.to_certificate_type());
                        peer.split(',').any(|name| {
                            name == algorithm.as_str() || certificate_name.as_deref() == Some(name)
                        })
                    }
                    None => !matches!(
                        algorithm,
                        Algorithm::Rsa {
                            hash: Some(HashAlg::Sha512)
                        }
                    ),
                }
        })
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::Unsupported,
                "no common SSH signature algorithm for the key",
            )
        })
}

pub(crate) fn decode_public_key(algorithm: &Algorithm, blob: &[u8]) -> io::Result<PublicKey> {
    let format = Reader::new(blob).string().map_err(crate::auth::malformed)?;
    if format != key_format(algorithm).as_str().as_bytes() {
        return Err(invalid(
            "SSH public key format does not match the signature algorithm",
        ));
    }
    let key = decode_canonical_public_key(blob)?;
    if !matches_key(&key, algorithm) {
        return Err(invalid(
            "SSH public key does not match the signature algorithm",
        ));
    }
    // Keep proof verification within the backend's supported RSA limits.
    if key
        .key_data()
        .rsa()
        .is_some_and(|rsa| rsa.key_size() as usize > MAX_RSA_BITS || rsa.e().as_bytes().len() > 5)
    {
        return Err(invalid("SSH RSA public key exceeds supported limits"));
    }
    if let Some(dsa) = key.key_data().dsa() {
        validate_dsa_signature_key(dsa)?;
    }
    Ok(key)
}

fn validate_dsa_signature_key(public: &ssh_key::public::DsaPublicKey) -> io::Result<()> {
    if !cfg!(feature = "dsa") {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "SSH DSA signatures require the dsa feature",
        ));
    }
    let [p, _, _, _] = format::dsa_parameters(public)?;
    if p.bit_width_vartime() != 1024 {
        return Err(invalid("SSH DSA signatures require a 1024-bit modulus"));
    }
    Ok(())
}

pub(crate) fn decode_canonical_public_key(blob: &[u8]) -> io::Result<PublicKey> {
    let key = PublicKey::from_bytes(blob)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    if key.to_bytes().map_err(io::Error::other)? != blob {
        return Err(invalid("noncanonical SSH public key encoding"));
    }
    Ok(key)
}

pub(crate) fn sign(key: &PrivateKey, algorithm: &Algorithm, message: &[u8]) -> io::Result<Vec<u8>> {
    if !matches_key(key.public_key(), algorithm) {
        return Err(invalid("SSH signing algorithm does not match the key"));
    }
    if let Some(dsa) = key.key_data().dsa() {
        validate_dsa_signature_key(dsa.public())?;
        format::validate_dsa_keypair(dsa)?;
    }
    if matches!(algorithm, Algorithm::Rsa { .. }) {
        #[cfg(feature = "rsa")]
        if let Algorithm::Rsa { hash } = algorithm
            && let Some(rsa) = key.key_data().rsa()
        {
            let signature = sign_rsa(rsa, *hash, message)?;
            return kex::fields(None, &[algorithm.as_str().as_bytes(), &signature]);
        }
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            ssh_key::Error::AlgorithmUnsupported {
                algorithm: algorithm.clone(),
            },
        ));
    }
    let signature = key.try_sign(message).map_err(io::Error::other)?;
    if &signature.algorithm() != algorithm {
        return Err(invalid(
            "SSH signing algorithm did not match the requested algorithm",
        ));
    }
    signature.try_into().map_err(io::Error::other)
}

#[cfg(feature = "rsa")]
fn rsa_private_key(key: &ssh_key::private::RsaKeypair) -> io::Result<rsa::PrivateKey> {
    let public = key.public();
    let private = key.private();
    let uint = |value: &ssh_key::Mpint| Uint::try_from(value).map_err(io::Error::other);
    rsa::PrivateKey::from_components(
        uint(public.n())?,
        uint(public.e())?,
        uint(private.d())?,
        vec![uint(private.p())?, uint(private.q())?],
    )
    .map_err(io::Error::other)
}

#[cfg(feature = "rsa")]
fn sign_rsa(
    key: &ssh_key::private::RsaKeypair,
    hash: Option<HashAlg>,
    message: &[u8],
) -> io::Result<Vec<u8>> {
    let backend = rsa_private_key(key)?;
    #[cfg(feature = "aws-lc-rs")]
    {
        use aws_lc_rs::{rand::SystemRandom, signature};

        let encoding = match hash {
            Some(HashAlg::Sha256) => Some(&signature::RSA_PKCS1_SHA256),
            Some(HashAlg::Sha512) => Some(&signature::RSA_PKCS1_SHA512),
            _ => None,
        };
        if let Some(encoding) = encoding
            && let Ok(der) = format::pkcs::rsa_pkcs1_der(key, &backend)
            && let Ok(key) = signature::RsaKeyPair::from_der(der.as_bytes())
        {
            let mut signature = vec![0; key.public_modulus_len()];
            key.sign(encoding, &SystemRandom::new(), message, &mut signature)
                .map_err(io::Error::other)?;
            return Ok(signature);
        }
    }
    // Use the operating system RNG for RSA signing blinding.
    let mut rng = getrandom::SysRng;
    let signature =
        match hash {
            None => {
                rsa::pkcs1v15::SigningKey::<Sha1>::new(backend).try_sign_with_rng(&mut rng, message)
            }
            Some(HashAlg::Sha256) => rsa::pkcs1v15::SigningKey::<Sha256>::new(backend)
                .try_sign_with_rng(&mut rng, message),
            Some(HashAlg::Sha512) => rsa::pkcs1v15::SigningKey::<Sha512>::new(backend)
                .try_sign_with_rng(&mut rng, message),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::Unsupported,
                    "unsupported SSH RSA signature hash",
                ));
            }
        }
        .map_err(io::Error::other)?;
    Ok(signature.to_vec())
}

pub(crate) fn verify(
    key: &KeyData,
    algorithm: &Algorithm,
    message: &[u8],
    blob: &[u8],
) -> io::Result<bool> {
    if algorithm == &Algorithm::Ed25519
        && let Some(ed25519) = key.ed25519()
    {
        return kex::verify_signature(&ed25519.0, message, blob);
    }
    // Decode the complete SSH structure. Signature::try_from by itself
    // does not require consuming the whole slice.
    let [name, data] = kex::decode::<2>(blob, None)?;
    if name != algorithm.as_str().as_bytes() || key_format(algorithm) != &key.algorithm() {
        return Err(invalid(
            "SSH signature algorithm does not match the public-key request",
        ));
    }
    if let Some(dsa) = key.dsa() {
        validate_dsa_signature_key(dsa)?;
    }
    if matches!(algorithm, Algorithm::Rsa { .. }) {
        #[cfg(feature = "rsa")]
        if let Algorithm::Rsa { hash } = algorithm
            && let Some(rsa) = key.rsa()
        {
            return verify_rsa(rsa, *hash, message, data);
        }
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            ssh_key::Error::AlgorithmUnsupported {
                algorithm: algorithm.clone(),
            },
        ));
    }
    let signature = Signature::new(algorithm.clone(), data)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    Ok(Verifier::verify(key, message, &signature).is_ok())
}

#[cfg(feature = "rsa")]
fn verify_rsa(
    key: &ssh_key::public::RsaPublicKey,
    hash: Option<HashAlg>,
    message: &[u8],
    signature: &[u8],
) -> io::Result<bool> {
    let width = (key.key_size() as usize).div_ceil(8);
    if signature.is_empty() || signature.len() > width || width > MAX_RSA_BITS / 8 {
        return Err(invalid("invalid SSH RSA signature length"));
    }
    let uint = |value: &ssh_key::Mpint| {
        Uint::try_from(value).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
    };
    let key = rsa::PublicKey::new(uint(key.n())?, uint(key.e())?)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    // RFC 8332 permits a shorter encoding when leading zero octets were omitted.
    let mut padded = vec![0; width];
    padded[width - signature.len()..].copy_from_slice(signature);
    let signature = rsa::pkcs1v15::Signature::try_from(padded.as_slice())
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    let result = match hash {
        None => rsa::pkcs1v15::VerifyingKey::<Sha1>::new(key).verify(message, &signature),
        Some(HashAlg::Sha256) => {
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(message, &signature)
        }
        Some(HashAlg::Sha512) => {
            rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key).verify(message, &signature)
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported SSH RSA signature hash",
            ));
        }
    };
    Ok(result.is_ok())
}

#[cfg(all(test, feature = "rsa"))]
mod tests {
    use super::*;

    const SHA256: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    };
    const SHA512: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    };

    #[test]
    fn rsa_signature_selection_distinguishes_peer_hashes_from_key_encoding() {
        let mut modulus = [0; 257];
        modulus[1] = 0x80;
        modulus[256] = 1;
        let blob = kex::fields(None, &[b"ssh-rsa", &[1, 0, 1], &modulus]).unwrap();
        let key = decode_public_key(&SHA256, &blob).unwrap();
        assert_eq!(key.algorithm(), RSA_SHA1);
        assert_eq!(key.to_bytes().unwrap(), blob);
        assert_eq!(signature_algorithm(&key, None, None).unwrap(), SHA256);
        assert_eq!(
            signature_algorithm(&key, None, Some("ssh-ed25519,rsa-sha2-512")).unwrap(),
            SHA512
        );
        assert_eq!(
            signature_algorithm(&key, None, Some("rsa-sha2-256,rsa-sha2-512")).unwrap(),
            SHA512
        );
        assert_eq!(
            signature_algorithm(&key, None, Some("rsa-sha2-256")).unwrap(),
            SHA256
        );
        assert_eq!(
            signature_algorithm(&key, None, Some("ssh-rsa"))
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            signature_algorithm(&key, Some(SHA256), Some("rsa-sha2-512")).unwrap(),
            SHA256
        );
        assert_eq!(
            signature_algorithm(&key, Some(RSA_SHA1), Some("rsa-sha2-512")).unwrap(),
            RSA_SHA1
        );
        assert_eq!(
            signature_algorithm(&key, Some(Algorithm::Ed25519), None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );

        let wrong_format = kex::fields(None, &[b"rsa-sha2-256", &[1, 0, 1], &modulus]).unwrap();
        assert!(decode_public_key(&SHA256, &wrong_format).is_err());
        let wrong_signature = kex::fields(None, &[b"rsa-sha2-512", &[1; 256]]).unwrap();
        assert!(verify(key.key_data(), &SHA256, b"fixture", &wrong_signature).is_err());
    }
}

#[cfg(all(test, not(feature = "rsa")))]
mod no_rsa_tests {
    use super::*;
    use ssh_key::{
        LineEnding, Mpint,
        private::{RsaKeypair, RsaPrivateKey},
        public::RsaPublicKey,
    };

    #[test]
    fn rsa_wire_keys_parse_without_enabling_local_proofs() {
        // Small textbook RSA key used only for serialization and rejection checks.
        let mpint = |value: u16| Mpint::from_positive_bytes(&value.to_be_bytes());
        let public = RsaPublicKey::new(mpint(17), mpint(3233)).unwrap();
        let private = RsaPrivateKey::new(mpint(2753), mpint(38), mpint(61), mpint(53)).unwrap();
        let pair = RsaKeypair::new(public, private).unwrap();
        let key = PrivateKey::new(pair.into(), "fixture").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let key = PrivateKeyReader::new().text(&pem).unwrap();
        let wire = key.public_key().to_bytes().unwrap();
        assert_eq!(
            key::from_blob(&wire).unwrap().key_data(),
            key.public_key().key_data()
        );
        assert_eq!(
            signature_algorithm(key.public_key(), None, None)
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );

        for algorithm in [
            RSA_SHA1,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        ] {
            assert!(!supports_signature_algorithm(&algorithm));
            assert!(!SIGNATURE_ALGORITHMS.contains(&algorithm));
            assert!(
                !UserSignatures::from_algorithms(std::slice::from_ref(&algorithm))
                    .permits(&algorithm)
            );
            let certificate = Algorithm::new(&algorithm.to_certificate_type()).unwrap();
            assert!(certificate_signature_algorithm(&certificate).is_none());
            let signing_error = sign(&key, &algorithm, b"fixture").unwrap_err();
            assert_eq!(signing_error.kind(), ErrorKind::Unsupported);
            assert!(matches!(
                signing_error.downcast::<ssh_key::Error>().unwrap(),
                ssh_key::Error::AlgorithmUnsupported { algorithm: reported } if reported == algorithm
            ));
            let proof = kex::fields(None, &[algorithm.as_str().as_bytes(), &[1]]).unwrap();
            assert_eq!(
                verify(key.public_key().key_data(), &algorithm, b"fixture", &proof)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unsupported
            );
        }
        assert_eq!(
            KeyError::of(&pkcs8_der(&key, None).unwrap_err()),
            Some(&KeyError::Unsupported("ssh-rsa".into()))
        );
    }

    #[test]
    fn rsa_private_key_conversions_are_disabled() {
        use ::pkcs8::{
            ObjectIdentifier, PrivateKeyInfoRef,
            der::{Encode, asn1::OctetStringRef},
        };

        let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let der = PrivateKeyInfoRef::new(
            ::pkcs8::AlgorithmIdentifierRef {
                oid: rsa_oid,
                parameters: None,
            },
            OctetStringRef::new(&[0x30, 0x00]).unwrap(),
        )
        .to_der()
        .unwrap();
        assert_eq!(
            KeyError::of(&PrivateKeyReader::new().der(&der).unwrap_err()),
            Some(&KeyError::Unsupported(rsa_oid.to_string()))
        );
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            KeyError::of(&PrivateKeyReader::new().text(pem).unwrap_err()),
            Some(&KeyError::Unsupported("RSA".into()))
        );
        let ppk = "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\n";
        assert_eq!(
            PrivateKeyReader::new().text(ppk).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }
}
