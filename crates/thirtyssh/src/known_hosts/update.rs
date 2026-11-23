use super::{
    KnownHosts, KnownHostsFile, MAX_FILE, Status, host_endpoint, read_file, read_optional_file,
};
use crate::crypto_backend::hmac;
use crate::{
    clear_packet::{MAX_PACKET_SIZE, invalid},
    keys::{PublicKey, decode_canonical_public_key},
};
use data_encoding::BASE64;
use std::{
    fs::{self, OpenOptions},
    io::{self, ErrorKind, Write},
    path::Path,
};

impl KnownHostsFile {
    /// Pin a key the caller has decided to trust. A key that is already
    /// pinned needs no write. A changed or revoked key is refused and left
    /// for manual review.
    pub fn record(&self, hostname: &str, port: u16, key: &PublicKey) -> io::Result<()> {
        learn(hostname, port, key, self.path(), false)
    }

    /// Pin a key under a freshly salted OpenSSH hashed host field.
    pub fn record_hashed(&self, hostname: &str, port: u16, key: &PublicKey) -> io::Result<()> {
        learn(hostname, port, key, self.path(), true)
    }
}

fn learn(hostname: &str, port: u16, key: &PublicKey, path: &Path, hash: bool) -> io::Result<()> {
    let (_, target) = host_endpoint(hostname, port)?;
    let blob = key.to_bytes().map_err(io::Error::other)?;
    if blob.len() > MAX_PACKET_SIZE {
        return Err(invalid("known_hosts key exceeds size limit"));
    }
    decode_canonical_public_key(&blob)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing known_hosts filename"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // A missing parent such as `~/.ssh` must not be created world-readable.
    let mut directories = fs::DirBuilder::new();
    directories.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directories.mode(0o700);
    }
    directories.create(parent)?;
    let parent = parent.canonicalize()?;
    let path = parent.join(file_name);

    // An entry that is already present needs no write access, so a read-only
    // file or directory still reports a trusted key as recorded.
    if existing_regular_file(&path)?.is_some() {
        let mut recorded = KnownHosts::new();
        recorded.files.push(read_file(&fs::File::open(&path)?)?);
        if settled(recorded.check_public_key(hostname, port, key)?)? {
            return Ok(());
        }
    }

    // The lock lives next to the destination and remains at the same path
    // across replacements. Removing a lock file can split waiting writers.
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".thirtyssh.lock");
    let lock_path = parent.join(lock_name);
    existing_regular_file(&lock_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.lock()?;

    let current = existing_regular_file(&path)?;
    let mut snapshot = KnownHosts::new();
    if current.is_some() {
        snapshot.files.push(read_file(
            &OpenOptions::new().read(true).write(true).open(&path)?,
        )?);
    }
    // Another writer may have changed the file before this one held the lock.
    if settled(snapshot.check_public_key(hostname, port, key)?)? {
        return Ok(());
    }
    let host_field = if hash { hash_target(&target)? } else { target };
    let line = format!(
        "{host_field} {} {}\n",
        key.algorithm(),
        BASE64.encode(&blob)
    );
    let original = snapshot.files.first().map(Vec::as_slice);
    let bytes = original.unwrap_or_default();
    let needs_newline = !bytes.is_empty() && !bytes.ends_with(b"\n");
    if bytes.len() + usize::from(needs_newline) + line.len() > MAX_FILE {
        return Err(invalid("known_hosts file exceeds size limit"));
    }

    let mut temp = tempfile::NamedTempFile::new_in(&parent)?;
    temp.write_all(bytes)?;
    if needs_newline {
        temp.write_all(b"\n")?;
    }
    temp.write_all(line.as_bytes())?;
    if let Some(metadata) = current {
        temp.as_file().set_permissions(metadata.permissions())?;
    }
    temp.as_file().sync_all()?;

    if original.is_some() {
        existing_regular_file(&path)?;
        if read_optional_file(&path)?.as_deref() != original {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "known_hosts changed during the update",
            ));
        }
        temp.persist(&path).map_err(|error| error.error)?;
    } else {
        temp.persist_noclobber(&path).map_err(|error| error.error)?;
    }
    Ok(())
}

/// Whether the file already records the key, so nothing is left to write.
fn settled(status: Status) -> io::Result<bool> {
    match status {
        Status::Trusted => Ok(true),
        Status::Changed | Status::Revoked => Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "host key changed or was revoked in known_hosts",
        )),
        Status::Unknown => Ok(false),
    }
}

fn existing_regular_file(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata)),
        // Replacing the link would detach it from its target, and writing
        // through it would follow a path someone else may control.
        Ok(metadata) if metadata.is_symlink() => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "known_hosts is a symbolic link; update the file it points to",
        )),
        Ok(_) => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "known_hosts updates require a regular file",
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn hash_target(target: &str) -> io::Result<String> {
    let mut salt = [0; 20];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    let mac = hmac::sign(&key, target.as_bytes());
    Ok(format!(
        "|1|{}|{}",
        BASE64.encode(&salt),
        BASE64.encode(mac.as_ref()),
    ))
}
