//! OpenSSH known_hosts lookup, including host certificate authorities and revocation.
#[cfg(any(unix, windows))]
mod update;

use crate::crypto_backend::hmac;
use crate::{
    clear_packet::{MAX_PACKET_SIZE, invalid},
    keys::{
        Certificate, CertificateSignaturePolicy, PublicKey, decode_canonical_public_key,
        ssh_key::certificate::CertType,
    },
    runtime::{SystemTime, UNIX_EPOCH},
    wire::Reader,
};
use data_encoding::BASE64;
use std::{
    fs::File,
    io::{self, ErrorKind, Read},
    path::{Path, PathBuf},
};

const MAX_FILE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Changed,
    Trusted,
    Revoked,
}

/// A read-only snapshot of one or more OpenSSH known_hosts files.
#[derive(Default)]
pub struct KnownHosts {
    files: Vec<Vec<u8>>,
    certificate_signatures: CertificateSignaturePolicy,
}

#[derive(Clone, Copy)]
enum Credential<'a> {
    Key(&'a PublicKey),
    Certificate(&'a Certificate, u64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Marker {
    Key,
    Authority,
    Revoked,
}

struct Entry<'a> {
    marker: Marker,
    hosts: &'a [u8],
    algorithm: &'a [u8],
    field: Option<&'a [u8]>,
}

/// Return the current user's `.ssh/known_hosts` path.
pub fn default_path() -> io::Result<PathBuf> {
    std::env::home_dir()
        .map(|home| home.join(".ssh").join("known_hosts"))
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no SSH home directory"))
}

/// One OpenSSH known_hosts file, looked up and updated in place.
///
/// Every call reads the file again, so a value can be kept for the lifetime of
/// a program. A missing file holds no entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsFile {
    path: PathBuf,
}

/// The outcome of looking a raw host key up in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lookup {
    pub status: Status,
    /// One-based line of the first pin for the same host and key algorithm
    /// that holds a different key.
    pub conflict: Option<usize>,
}

/// A raw public key pinned for a host, with its one-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub line: usize,
    pub key: PublicKey,
}

impl KnownHostsFile {
    /// The current user's `.ssh/known_hosts`.
    pub fn user() -> io::Result<Self> {
        default_path().map(Self::at)
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Match a raw public key against the pins and revocations for a host.
    pub fn lookup(&self, hostname: &str, port: u16, key: &PublicKey) -> io::Result<Lookup> {
        let snapshot = KnownHosts {
            files: read_optional_file(&self.path)?.into_iter().collect(),
            ..KnownHosts::default()
        };
        let (status, conflict) = snapshot.check_credential(hostname, port, Credential::Key(key))?;
        Ok(Lookup { status, conflict })
    }

    /// Every raw public key pinned for a host. Certificate authorities and
    /// revocations are not pins.
    pub fn pins(&self, hostname: &str, port: u16) -> io::Result<Vec<Pin>> {
        let (_, target) = host_endpoint(hostname, port)?;
        let Some(bytes) = read_optional_file(&self.path)? else {
            return Ok(Vec::new());
        };
        let mut pins = Vec::new();
        for (index, line) in bytes.split(|&byte| byte == b'\n').enumerate() {
            let Some(entry) = parse_entry(line)? else {
                continue;
            };
            if entry.marker == Marker::Key
                && !entry.algorithm.ends_with(b"-cert-v01@openssh.com")
                && matches_host(entry.hosts, target.as_bytes()).unwrap_or(false)
            {
                pins.push(Pin {
                    line: index + 1,
                    key: decode_canonical_public_key(&entry.decode_blob()?)?,
                });
            }
        }
        Ok(pins)
    }
}

fn read_file(file: &File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(invalid("known_hosts file exceeds size limit"));
    }
    Ok(bytes)
}

fn read_optional_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(file) => read_file(&file).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

impl KnownHosts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the accepted issuer algorithms for certificate lookups.
    pub fn set_certificate_signature_policy(&mut self, policy: CertificateSignaturePolicy) {
        self.certificate_signatures = policy;
    }

    /// Add one file. File errors, including a missing file, are returned.
    pub fn load(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        self.files.push(read_file(&File::open(path)?)?);
        Ok(())
    }

    /// Evaluate the key for the exact host and port used by the caller.
    /// A matching revocation takes precedence over all positive entries.
    pub fn check(&self, hostname: &str, port: u16, key: &[u8; 32]) -> io::Result<Status> {
        use crate::keys::ssh_key::public::{Ed25519PublicKey, KeyData};

        let key = PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(*key)), "");
        self.check_public_key(hostname, port, &key)
    }

    /// Match a raw public key against pins and revocation entries.
    pub fn check_public_key(
        &self,
        hostname: &str,
        port: u16,
        key: &PublicKey,
    ) -> io::Result<Status> {
        self.check_credential(hostname, port, Credential::Key(key))
            .map(|(status, _)| status)
    }

    /// Verify a host certificate against a matching certification authority
    /// and the system clock. Revoking the leaf or the issuer also revokes the certificate.
    pub fn check_certificate(
        &self,
        hostname: &str,
        port: u16,
        cert: &Certificate,
    ) -> io::Result<Status> {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        self.check_certificate_at(hostname, port, cert, time)
    }

    /// Certificate lookup using an explicitly supplied Unix timestamp.
    pub fn check_certificate_at(
        &self,
        hostname: &str,
        port: u16,
        cert: &Certificate,
        unix_time: u64,
    ) -> io::Result<Status> {
        self.check_credential(hostname, port, Credential::Certificate(cert, unix_time))
            .map(|(status, _)| status)
    }

    fn check_credential(
        &self,
        hostname: &str,
        port: u16,
        credential: Credential<'_>,
    ) -> io::Result<(Status, Option<usize>)> {
        let (host, target) = host_endpoint(hostname, port)?;
        let (leaf, certificate) = match credential {
            Credential::Key(key) => (key.key_data(), None),
            Credential::Certificate(cert, _) => (cert.public_key(), Some(cert)),
        };
        let leaf_algorithm = leaf.algorithm();
        let issuer_algorithm = certificate.map(|cert| cert.signature_key().algorithm());
        let issuer = issuer_algorithm
            .as_ref()
            .map(|algorithm| algorithm.as_str().as_bytes());
        let certificate_type = certificate.map(|cert| cert.algorithm().to_certificate_type());
        let mut status = Status::Unknown;
        let mut conflicting_line = None;
        let mut authority = None;
        for (index, line) in self
            .files
            .iter()
            .flat_map(|file| file.split(|&b| b == b'\n').enumerate())
        {
            let Some(entry) = parse_entry(line)? else {
                continue;
            };
            let algorithm = entry.algorithm;
            let is_leaf = algorithm == leaf_algorithm.as_str().as_bytes();
            let is_issuer = issuer == Some(algorithm);
            let is_certificate = certificate_type.as_deref().map(str::as_bytes) == Some(algorithm);
            let relevant = match entry.marker {
                Marker::Key => certificate.is_none() && is_leaf,
                Marker::Authority => is_issuer,
                Marker::Revoked => is_leaf || is_issuer || is_certificate,
            };
            if !relevant {
                continue;
            }
            // A host field that cannot be read names no host, so the line is
            // passed over like one for another host. A revocation is the
            // exception: ignoring it could re-admit the key it bans.
            match matches_host(entry.hosts, target.as_bytes()) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) if entry.marker == Marker::Revoked => return Err(error),
                Err(_) => continue,
            }
            let blob = entry.decode_blob()?;
            if is_certificate {
                let revoked = Certificate::from_bytes(&blob)
                    .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
                let Some(cert) = certificate else { continue };
                if revoked.to_bytes().map_err(io::Error::other)? != blob {
                    return Err(invalid("noncanonical SSH certificate revocation"));
                }
                if blob == cert.to_bytes().map_err(io::Error::other)? {
                    return Ok((Status::Revoked, conflicting_line));
                }
                continue;
            }
            let key = decode_canonical_public_key(&blob)?;
            let matches_leaf = key.key_data() == leaf;
            let matches_issuer =
                certificate.is_some_and(|cert| key.key_data() == cert.signature_key());
            match entry.marker {
                Marker::Revoked if matches_leaf || matches_issuer => {
                    return Ok((Status::Revoked, conflicting_line));
                }
                Marker::Authority if matches_issuer => authority = Some(key),
                Marker::Key if matches_leaf => status = Status::Trusted,
                Marker::Key => {
                    conflicting_line.get_or_insert(index + 1);
                    if status == Status::Unknown {
                        status = Status::Changed;
                    }
                }
                _ => {}
            }
        }
        if let (Credential::Certificate(cert, time), Some(authority)) = (credential, authority) {
            if !self.certificate_signatures.validate_certificate_at(
                cert,
                &authority,
                &host,
                CertType::Host,
                time,
            )? {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "SSH host certificate fails known_hosts trust policy",
                ));
            }
            return Ok((Status::Trusted, conflicting_line));
        }
        Ok((status, conflicting_line))
    }
}

fn host_endpoint(hostname: &str, port: u16) -> io::Result<(String, String)> {
    if hostname.is_empty()
        || hostname.len() > 1024
        || port == 0
        || hostname.starts_with('#')
        || hostname.starts_with('@')
        || !hostname.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b',' | b'[' | b']' | b'*' | b'?' | b'!' | b'|')
        })
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH host endpoint",
        ));
    }
    let host = hostname.to_ascii_lowercase();
    let target = if port == 22 {
        host.clone()
    } else {
        format!("[{host}]:{port}")
    };
    Ok((host, target))
}

fn parse_entry(line: &[u8]) -> io::Result<Option<Entry<'_>>> {
    let mut fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let Some(first) = fields.next() else {
        return Ok(None);
    };
    let marker = match first {
        b"@revoked" => Marker::Revoked,
        b"@cert-authority" => Marker::Authority,
        _ if first.starts_with(b"#") || first.starts_with(b"@") => return Ok(None),
        _ => Marker::Key,
    };
    let hosts = if marker == Marker::Key {
        first
    } else {
        fields
            .next()
            .ok_or_else(|| invalid("missing marked known_hosts pattern"))?
    };
    let Some(algorithm) = fields.next() else {
        return Ok(None);
    };
    Ok(Some(Entry {
        marker,
        hosts,
        algorithm,
        field: fields.next(),
    }))
}

impl Entry<'_> {
    fn decode_blob(&self) -> io::Result<Vec<u8>> {
        let field = self
            .field
            .ok_or_else(|| invalid("missing known_hosts key"))?;
        if field.len() > MAX_PACKET_SIZE.div_ceil(3) * 4 {
            return Err(invalid("known_hosts key exceeds size limit"));
        }
        let blob = BASE64
            .decode(field)
            .map_err(|_| invalid("invalid known_hosts key encoding"))?;
        if Reader::new(&blob)
            .string()
            .map_err(crate::auth::malformed)?
            != self.algorithm
        {
            return Err(invalid("known_hosts key type does not match its encoding"));
        }
        Ok(blob)
    }
}

fn matches_host(patterns: &[u8], host: &[u8]) -> io::Result<bool> {
    if let Some(hashed) = patterns.strip_prefix(b"|1|") {
        let mut fields = hashed.split(|&b| b == b'|');
        let salt = fields
            .next()
            .ok_or_else(|| invalid("missing hashed host salt"))?;
        let tag = fields
            .next()
            .ok_or_else(|| invalid("missing hashed host tag"))?;
        if fields.next().is_some() || salt.len() != 28 || tag.len() != 28 {
            return Err(invalid("invalid hashed known_hosts entry"));
        }
        let salt = BASE64
            .decode(salt)
            .map_err(|_| invalid("invalid hashed host salt"))?;
        let tag = BASE64
            .decode(tag)
            .map_err(|_| invalid("invalid hashed host tag"))?;
        if salt.len() != 20 || tag.len() != 20 {
            return Err(invalid("invalid hashed known_hosts entry"));
        }
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
        return Ok(hmac::verify(&key, host, &tag).is_ok());
    }
    let mut matched = false;
    for pattern in patterns.split(|&b| b == b',') {
        let negative = pattern.strip_prefix(b"!");
        if wildcard(negative.unwrap_or(pattern), host) {
            if negative.is_some() {
                return Ok(false);
            }
            matched = true;
        }
    }
    Ok(matched)
}

fn wildcard(pattern: &[u8], host: &[u8]) -> bool {
    let (mut pattern_index, mut host_index) = (0, 0);
    let mut retry = None;
    while host_index < host.len() {
        match pattern.get(pattern_index) {
            Some(b'*') => {
                pattern_index += 1;
                retry = Some((pattern_index, host_index));
            }
            Some(byte) if *byte == b'?' || byte.eq_ignore_ascii_case(&host[host_index]) => {
                pattern_index += 1;
                host_index += 1;
            }
            _ => match retry {
                Some((after_star, matched)) => {
                    pattern_index = after_star;
                    host_index = matched + 1;
                    retry = Some((after_star, host_index));
                }
                None => return false,
            },
        }
    }
    pattern[pattern_index..].iter().all(|&b| b == b'*')
}
