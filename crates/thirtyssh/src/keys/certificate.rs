mod user;
pub use user::validate_user_certificate_at;
pub(crate) use user::{CertificatePermissions, CertificateRequest};

use super::{
    Algorithm, Certificate, PublicKey, RSA_SHA1, key_format, matches_key,
    supports_signature_algorithm, validate_dsa_signature_key, verify,
};
use crate::{
    clear_packet::invalid,
    runtime::{SystemTime, UNIX_EPOCH},
    wire::Reader,
};
use ssh_encoding::Encode;
use ssh_key::{certificate::CertType, public::KeyData};
use std::{
    collections::{HashMap, HashSet},
    io::{self, ErrorKind},
};

/// Application-managed certificate revocations. Serial numbers and key IDs
/// are scoped to the issuing CA. A revoked leaf key or CA rejects every
/// associated certificate.
#[derive(Default)]
pub struct CertificateRevocations {
    keys: HashSet<KeyData>,
    authorities: HashMap<KeyData, RevokedCertificates>,
}

#[derive(Default)]
struct RevokedCertificates {
    serials: HashSet<u64>,
    key_ids: HashSet<String>,
}

impl CertificateRevocations {
    pub fn revoke_key(&mut self, key: &PublicKey) {
        self.keys.insert(key.key_data().clone());
    }

    pub fn revoke_serial(&mut self, ca: &PublicKey, serial: u64) {
        self.authorities
            .entry(ca.key_data().clone())
            .or_default()
            .serials
            .insert(serial);
    }

    pub fn revoke_key_id(&mut self, ca: &PublicKey, id: impl Into<String>) {
        self.authorities
            .entry(ca.key_data().clone())
            .or_default()
            .key_ids
            .insert(id.into());
    }

    /// Check the revocation policy for a certificate before authorizing it.
    pub fn is_revoked(&self, certificate: &Certificate) -> bool {
        self.keys.contains(certificate.public_key())
            || self.keys.contains(certificate.signature_key())
            || self
                .authorities
                .get(certificate.signature_key())
                .is_some_and(|revoked| {
                    revoked.serials.contains(&certificate.serial())
                        || revoked.key_ids.contains(certificate.key_id())
                })
    }
}

/// What a peer or an agent proves possession of: a plain public key, or a
/// certificate issued for one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Credential {
    Key(PublicKey),
    Certificate(Box<Certificate>),
}

impl Credential {
    /// The key material, without a certificate's envelope.
    pub fn key_data(&self) -> &KeyData {
        match self {
            Self::Key(key) => key.key_data(),
            Self::Certificate(certificate) => certificate.public_key(),
        }
    }

    /// The raw key, when this is a plain Ed25519 public key. A certificate
    /// is never reduced to its key here, so a pin on a key cannot be met by a
    /// certificate nobody has authorized.
    pub fn ed25519(&self) -> Option<[u8; 32]> {
        match self {
            Self::Key(key) => key.key_data().ed25519().map(|key| key.0),
            Self::Certificate(_) => None,
        }
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Self::Key(_) => None,
            Self::Certificate(certificate) => Some(certificate),
        }
    }
}

impl From<PublicKey> for Credential {
    fn from(key: PublicKey) -> Self {
        Self::Key(key)
    }
}

impl From<Certificate> for Credential {
    fn from(certificate: Certificate) -> Self {
        Self::Certificate(Box::new(certificate))
    }
}

pub(crate) fn certificate_signature_algorithm(algorithm: &Algorithm) -> Option<Algorithm> {
    let name = algorithm.as_str();
    let signature = Algorithm::new_certificate(name).ok()?;
    (supports_signature_algorithm(&signature) && signature.to_certificate_type() == name)
        .then_some(signature)
}

pub(crate) fn decode_host_identity(
    algorithm: &Algorithm,
    blob: &[u8],
    policy: CertificateSignaturePolicy,
) -> io::Result<Credential> {
    let Some(signature) = certificate_signature_algorithm(algorithm) else {
        return Ok(Credential::Key(super::decode_public_key(algorithm, blob)?));
    };
    let certificate = decode_certificate(&signature, blob, CertType::Host, policy)?;
    Ok(Credential::Certificate(Box::new(certificate)))
}

pub(crate) fn decode_certificate(
    signature: &Algorithm,
    blob: &[u8],
    usage: CertType,
    policy: CertificateSignaturePolicy,
) -> io::Result<Certificate> {
    let format = Reader::new(blob).string().map_err(crate::auth::malformed)?;
    if format != key_format(signature).to_certificate_type().as_bytes() {
        return Err(invalid(
            "SSH certificate format does not match the requested algorithm",
        ));
    }
    let certificate = Certificate::from_bytes(blob).map_err(certificate_encoding)?;
    let key = PublicKey::new(certificate.public_key().clone(), "");
    if !matches_key(&key, signature) || certificate.cert_type() != usage {
        return Err(invalid("wrong SSH certificate type or proof key"));
    }
    if let Some(dsa) = key.key_data().dsa() {
        validate_dsa_signature_key(dsa)?;
    }
    if certificate.to_bytes().map_err(certificate_encoding)? != blob
        || !policy.verify_signature(&certificate)?
    {
        return Err(invalid("invalid SSH certificate signature"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if !valid_at(&certificate, now)
        || (usage == CertType::Host && !certificate.critical_options().is_empty())
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "expired, premature or restricted SSH certificate",
        ));
    }
    Ok(certificate)
}

/// Validate a certificate against an explicitly trusted CA and principal.
/// This policy requires an exact principal and declines certificates with
/// critical options. The timestamp is expressed as Unix seconds.
pub fn validate_certificate_at(
    certificate: &Certificate,
    authority: &PublicKey,
    principal: &str,
    usage: CertType,
    unix_time: u64,
) -> io::Result<bool> {
    CertificateSignaturePolicy::default().validate_certificate_at(
        certificate,
        authority,
        principal,
        usage,
        unix_time,
    )
}

/// Additional algorithms permitted for an issuer's certificate signature.
/// The default permits modern signatures. The policy does not authorize the
/// issuer or enable legacy signatures by the certificate's subject.
#[derive(Clone, Copy, Debug, Default)]
pub struct CertificateSignaturePolicy {
    pub allow_rsa_sha1: bool,
    pub allow_dsa: bool,
}

impl CertificateSignaturePolicy {
    /// Validate a certificate against a trusted CA and exact principal.
    /// This method declines certificates with critical options.
    pub fn validate_certificate_at(
        self,
        certificate: &Certificate,
        authority: &PublicKey,
        principal: &str,
        usage: CertType,
        unix_time: u64,
    ) -> io::Result<bool> {
        if !certificate.critical_options().is_empty() {
            return Ok(false);
        }
        self.validate_trust_at(certificate, authority, principal, usage, unix_time)
    }

    fn validate_trust_at(
        self,
        certificate: &Certificate,
        authority: &PublicKey,
        principal: &str,
        usage: CertType,
        unix_time: u64,
    ) -> io::Result<bool> {
        if certificate.cert_type() != usage
            || certificate.signature_key() != authority.key_data()
            || principal.is_empty()
            || !certificate
                .valid_principals()
                .iter()
                .any(|entry| entry == principal)
            || !valid_at(certificate, unix_time)
        {
            return Ok(false);
        }
        self.verify_signature(certificate)
    }

    // Check signature integrity before authorizing the CA and principal.
    pub(crate) fn verify_signature(self, certificate: &Certificate) -> io::Result<bool> {
        let signature = certificate.signature();
        let algorithm = signature.algorithm();
        if !supports_signature_algorithm(&algorithm)
            || (algorithm == RSA_SHA1 && !self.allow_rsa_sha1)
            || (algorithm == Algorithm::Dsa && !self.allow_dsa)
        {
            return Ok(false);
        }
        let certificate_bytes = certificate.to_bytes().map_err(certificate_encoding)?;
        let mut signature_field = Vec::new();
        signature
            .encode_prefixed(&mut signature_field)
            .map_err(certificate_encoding)?;
        let tbs = certificate_bytes
            .strip_suffix(signature_field.as_slice())
            .ok_or_else(|| invalid("invalid SSH certificate signature field"))?;
        let ca = PublicKey::new(certificate.signature_key().clone(), "");
        let signature_bytes = signature.encode_vec().map_err(certificate_encoding)?;
        verify(ca.key_data(), &algorithm, tbs, &signature_bytes)
    }
}

fn valid_at(certificate: &Certificate, unix_time: u64) -> bool {
    (certificate.valid_after()..certificate.valid_before()).contains(&unix_time)
}

fn certificate_encoding(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, certificate::Builder, private::Ed25519Keypair};

    #[test]
    fn a_valid_ca_signature_cannot_override_critical_options_or_host_policy() {
        let private_key =
            |seed| PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap();
        let ca = private_key(1);
        let unrelated = private_key(2);
        let host = private_key(3);
        let builder = || {
            let mut build =
                Builder::new(vec![1; 32], host.public_key().key_data().clone(), 100, 200).unwrap();
            build
                .cert_type(CertType::Host)
                .unwrap()
                .valid_principal("host.example")
                .unwrap();
            build
        };
        let simple = builder().sign(&ca).unwrap();
        assert!(
            validate_certificate_at(
                &simple,
                ca.public_key(),
                "host.example",
                CertType::Host,
                100
            )
            .unwrap()
        );
        assert!(
            !validate_certificate_at(
                &simple,
                unrelated.public_key(),
                "host.example",
                CertType::Host,
                100
            )
            .unwrap()
        );
        assert!(
            !validate_certificate_at(
                &simple,
                ca.public_key(),
                "other.example",
                CertType::Host,
                100
            )
            .unwrap()
        );
        assert!(
            !validate_certificate_at(&simple, ca.public_key(), "host.example", CertType::Host, 99)
                .unwrap()
        );
        assert!(
            !validate_certificate_at(
                &simple,
                ca.public_key(),
                "host.example",
                CertType::Host,
                200
            )
            .unwrap()
        );

        let mut restricted = builder();
        restricted
            .critical_option("unknown-critical@example.test", "fixture")
            .unwrap();
        let restricted = restricted.sign(&ca).unwrap();
        assert!(
            CertificateSignaturePolicy::default()
                .verify_signature(&restricted)
                .unwrap()
        );
        assert!(
            !validate_certificate_at(
                &restricted,
                ca.public_key(),
                "host.example",
                CertType::Host,
                100
            )
            .unwrap()
        );
        assert!(
            crate::transport::HostKeys::with_certificates(vec![host], vec![restricted]).is_err()
        );
    }

    #[test]
    fn revocation_identifiers_are_scoped_to_their_issuer() {
        let private =
            |byte| PrivateKey::new(Ed25519Keypair::from_seed(&[byte; 32]).into(), "").unwrap();
        let leaf = private(20);
        let ca = private(21);
        let other_ca = private(22);
        let issue = |issuer: &PrivateKey, serial, id| {
            let mut builder =
                Builder::new(vec![0; 32], leaf.public_key().key_data().clone(), 100, 200).unwrap();
            builder
                .cert_type(CertType::User)
                .unwrap()
                .valid_principal("fixture")
                .unwrap()
                .serial(serial)
                .unwrap()
                .key_id(id)
                .unwrap();
            builder.sign(issuer).unwrap()
        };
        let first = issue(&ca, 3, "release-key");
        let third_party = issue(&other_ca, 3, "release-key");
        let renewed = issue(&ca, 4, "release-key");
        let mut revoked = CertificateRevocations::default();
        revoked.revoke_serial(ca.public_key(), 3);
        assert!(revoked.is_revoked(&first));
        assert!(!revoked.is_revoked(&third_party));
        assert!(!revoked.is_revoked(&renewed));
        revoked.revoke_key_id(ca.public_key(), "release-key");
        assert!(revoked.is_revoked(&renewed));
        assert!(!revoked.is_revoked(&third_party));
        revoked.revoke_key(leaf.public_key());
        assert!(revoked.is_revoked(&third_party));
    }
}
