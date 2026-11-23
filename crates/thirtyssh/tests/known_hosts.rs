use data_encoding::BASE64;
use std::fs;
use thirtyssh::{
    keys::{
        Certificate, PrivateKey,
        ssh_key::{
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        },
    },
    known_hosts::{KnownHosts, Status},
    transport::HostKey,
    wire::Writer,
};

#[cfg(any(unix, windows))]
use thirtyssh::known_hosts::{KnownHostsFile, Lookup, Pin};

fn identity(seed: u8) -> PrivateKey {
    PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap()
}

fn certificate(host: &PrivateKey, ca: &PrivateKey, serial: u64) -> Certificate {
    let mut builder =
        Builder::new(vec![0; 32], host.public_key().key_data().clone(), 100, 200).unwrap();
    builder
        .cert_type(CertType::Host)
        .unwrap()
        .serial(serial)
        .unwrap()
        .valid_principal("node.example.test")
        .unwrap();
    builder.sign(ca).unwrap()
}

fn encoded_key(key: &[u8; 32]) -> String {
    let mut buffer = [0; 51];
    let mut writer = Writer::new(&mut buffer);
    writer.string(b"ssh-ed25519").unwrap();
    writer.string(key).unwrap();
    BASE64.encode(writer.written())
}

#[test]
fn plain_entries_classify_trust_and_revocation_across_files() {
    let host = HostKey::generate().unwrap().public_key();
    let other = HostKey::generate().unwrap().public_key();
    let temp = tempfile::tempdir().unwrap();
    let known = temp.path().join("known_hosts");
    let revoked = temp.path().join("revoked");
    fs::write(&known, format!("# comment\r\n*.example.test,!blocked.example.test ssh-ed25519 {} note\r\n[::1]:2222 ssh-ed25519 {}\n",
        encoded_key(&host), encoded_key(&host))).unwrap();
    fs::write(
        &revoked,
        format!("@revoked [::1]:2222 ssh-ed25519 {}\n", encoded_key(&host)),
    )
    .unwrap();
    let mut keys = KnownHosts::new();
    keys.load(known).unwrap();
    assert_eq!(
        keys.check("NODE.example.test", 22, &host).unwrap(),
        Status::Trusted
    );
    assert_eq!(
        keys.check("NODE.example.test", 22, &other).unwrap(),
        Status::Changed
    );
    assert_eq!(
        keys.check("blocked.example.test", 22, &host).unwrap(),
        Status::Unknown
    );
    assert_eq!(keys.check("::1", 2222, &host).unwrap(), Status::Trusted);
    assert_eq!(keys.check("::1", 22, &host).unwrap(), Status::Unknown);
    keys.load(revoked).unwrap();
    assert_eq!(keys.check("::1", 2222, &host).unwrap(), Status::Revoked);
}

#[cfg(any(unix, windows))]
#[test]
fn file_lookups_report_conflicting_lines_and_revocations() {
    let host = "target.example.test";
    let port = 2222;
    let pin = identity(70);
    let different = identity(71);
    let directory = tempfile::tempdir().unwrap();
    let file = KnownHostsFile::at(directory.path().join("hosts"));
    let lookup = |key: &PrivateKey| file.lookup(host, port, key.public_key()).unwrap();
    let found = |status| Lookup {
        status,
        conflict: None,
    };
    assert_eq!(lookup(&pin), found(Status::Unknown));
    file.record(host, port, pin.public_key()).unwrap();
    let recorded = fs::read(file.path()).unwrap();
    file.record(host, port, pin.public_key()).unwrap();
    assert_eq!(fs::read(file.path()).unwrap(), recorded);
    assert_eq!(lookup(&pin), found(Status::Trusted));
    assert_eq!(
        file.lookup(host, 22, pin.public_key()).unwrap(),
        found(Status::Unknown)
    );
    let pinned = |line, key: &PrivateKey| Pin {
        line,
        key: key.public_key().clone(),
    };
    assert_eq!(file.pins(host, port).unwrap(), [pinned(1, &pin)]);
    assert_eq!(
        lookup(&different),
        Lookup {
            status: Status::Changed,
            conflict: Some(1)
        }
    );

    let raw = pin.public_key().to_openssh().unwrap();
    let stale = different.public_key().to_openssh().unwrap();
    let content = format!("# previous pins\n\n[{host}]:{port}\t{stale}\r\n[{host}]:{port} {raw}\n");
    fs::write(file.path(), &content).unwrap();
    // The key is pinned, and the stale pin above it is still reported.
    assert_eq!(
        lookup(&pin),
        Lookup {
            status: Status::Trusted,
            conflict: Some(3)
        }
    );
    assert_eq!(
        file.pins(host, port).unwrap(),
        [pinned(3, &different), pinned(4, &pin)]
    );

    let revoked = format!("{content}@revoked [{host}]:{port} {raw}\n");
    fs::write(file.path(), &revoked).unwrap();
    assert_eq!(lookup(&pin).status, Status::Revoked);
    assert!(file.record(host, port, pin.public_key()).is_err());
    assert_eq!(fs::read(file.path()).unwrap(), revoked.as_bytes());
    assert!(
        KnownHostsFile::at(directory.path())
            .lookup(host, port, pin.public_key())
            .is_err()
    );
}
#[test]
fn certificate_authorities_and_malformed_keys_do_not_pin_raw_ed25519() {
    let host = HostKey::generate().unwrap().public_key();
    let file = tempfile::tempdir().unwrap();
    let path = file.path().join("known_hosts");
    fs::write(
        &path,
        format!(
            "@cert-authority host.test ssh-ed25519 {}\nbroken.test ssh-ed25519 broken\n",
            encoded_key(&host)
        ),
    )
    .unwrap();
    let mut keys = KnownHosts::new();
    keys.load(path).unwrap();
    assert_eq!(keys.check("host.test", 22, &host).unwrap(), Status::Unknown);
    assert!(keys.check("broken.test", 22, &host).is_err());
}

#[test]
fn host_certificates_require_a_matching_authority_endpoint_and_principal() {
    use ring::hmac;

    let host = identity(1);
    let ca = identity(2);
    let cert = certificate(&host, &ca, 17);
    let unknown = certificate(&host, &identity(3), 17);
    let file = tempfile::tempdir().unwrap();
    let path = file.path().join("known_hosts");
    let salt = [4; 20];
    let hash_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    let hashed = hmac::sign(&hash_key, b"[node.example.test]:2222");
    fs::write(&path, format!(
        "@cert-authority |1|{}|{} {}\n@cert-authority other.example.test {}\nnode.example.test {}\n",
        BASE64.encode(&salt), BASE64.encode(hashed.as_ref()), ca.public_key().to_openssh().unwrap(),
        ca.public_key().to_openssh().unwrap(), host.public_key().to_openssh().unwrap(),
    )).unwrap();
    let mut keys = KnownHosts::new();
    keys.load(path).unwrap();
    assert_eq!(
        keys.check_certificate_at("NODE.example.test", 2222, &cert, 100)
            .unwrap(),
        Status::Trusted
    );
    assert_eq!(
        keys.check_certificate_at("node.example.test", 22, &cert, 100)
            .unwrap(),
        Status::Unknown
    );
    assert_eq!(
        keys.check_certificate_at("node.example.test", 2222, &unknown, 100)
            .unwrap(),
        Status::Unknown
    );
    assert_eq!(
        keys.check_certificate_at("node.example.test", 2222, &cert, 200)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        keys.check_certificate_at("other.example.test", 22, &cert, 100)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        keys.check_public_key("node.example.test", 22, host.public_key())
            .unwrap(),
        Status::Trusted
    );
}

#[test]
fn host_certificate_revocations_override_trust_across_files() {
    let host = identity(5);
    let ca = identity(6);
    let cert = certificate(&host, &ca, 17);
    let renewed = certificate(&host, &ca, 18);
    let directory = tempfile::tempdir().unwrap();
    let trusted = directory.path().join("trusted");
    let revoke = directory.path().join("revoked");
    let ca_line = ca.public_key().to_openssh().unwrap();
    fs::write(
        &trusted,
        format!("@cert-authority *.example.test,!excluded.example.test {ca_line}\n"),
    )
    .unwrap();
    for entry in [
        cert.to_openssh().unwrap(),
        host.public_key().to_openssh().unwrap(),
        ca_line,
    ] {
        fs::write(&revoke, format!("@revoked node.example.test {entry}\n")).unwrap();
        let mut keys = KnownHosts::new();
        keys.load(&trusted).unwrap();
        keys.load(&revoke).unwrap();
        assert_eq!(
            keys.check_certificate_at("node.example.test", 22, &cert, 100)
                .unwrap(),
            Status::Revoked
        );
        let renewed_status = if entry.starts_with("ssh-ed25519-cert-v01@openssh.com ") {
            Status::Trusted
        } else {
            Status::Revoked
        };
        assert_eq!(
            keys.check_certificate_at("node.example.test", 22, &renewed, 100)
                .unwrap(),
            renewed_status
        );
        assert_eq!(
            keys.check_certificate_at("excluded.example.test", 22, &cert, 100)
                .unwrap(),
            Status::Unknown
        );
    }
}

#[cfg(any(unix, windows))]
#[test]
fn updates_preserve_existing_records_and_refuse_changed_or_revoked_keys() {
    use std::io::ErrorKind;

    let host = identity(7);
    let key = host.public_key();
    let changed = identity(8);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested").join("known_hosts");
    assert!(
        KnownHostsFile::at(&path)
            .pins("node.test", 22)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        KnownHostsFile::at(&path)
            .lookup("node.test", 22, key)
            .unwrap()
            .status,
        Status::Unknown
    );
    KnownHostsFile::at(&path)
        .record("node.test", 22, key)
        .unwrap();
    assert_eq!(
        KnownHostsFile::at(&path)
            .lookup("node.test", 22, key)
            .unwrap()
            .status,
        Status::Trusted
    );

    let line = key.to_openssh().unwrap();
    let original = format!(
        "# existing comment\r\n@revoked deny.test {line}\r\nnode.test {line} keep this comment"
    );
    fs::write(&path, original.as_bytes()).unwrap();
    for (host, key, expected_error) in [
        (
            "node.test",
            changed.public_key(),
            ErrorKind::PermissionDenied,
        ),
        ("deny.test", key, ErrorKind::PermissionDenied),
        ("wildcard.*", key, ErrorKind::InvalidInput),
        ("host.test\nother.test", key, ErrorKind::InvalidInput),
    ] {
        assert_eq!(
            KnownHostsFile::at(&path)
                .record(host, 22, key)
                .unwrap_err()
                .kind(),
            expected_error
        );
    }
    KnownHostsFile::at(&path)
        .record("NODE.test", 22, key)
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), original.as_bytes());

    KnownHostsFile::at(&path).record("::1", 2222, key).unwrap();
    let expected = format!("{original}\n[::1]:2222 {line}\n");
    assert_eq!(fs::read(&path).unwrap(), expected.as_bytes());
    assert_eq!(
        KnownHostsFile::at(&path).pins("node.test", 22).unwrap(),
        [Pin {
            line: 3,
            key: key.clone()
        }]
    );
    assert_eq!(
        KnownHostsFile::at(&path).pins("::1", 2222).unwrap(),
        [Pin {
            line: 4,
            key: key.clone()
        }]
    );
    assert!(
        KnownHostsFile::at(&path)
            .pins("deny.test", 22)
            .unwrap()
            .is_empty()
    );
    assert!(
        KnownHostsFile::at(temp.path())
            .lookup("node.test", 22, key)
            .is_err()
    );
    let malformed = format!("{expected}wrong.test ssh-ed25519 invalid\n");
    fs::write(&path, &malformed).unwrap();
    assert_eq!(
        KnownHostsFile::at(&path)
            .record("wrong.test", 22, key)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(fs::read(&path).unwrap(), malformed.as_bytes());
}

#[cfg(any(unix, windows))]
#[test]
fn hashed_updates_are_private_salted_and_port_specific() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    let identity = identity(11);
    let key = identity.public_key();
    for path in [&first, &second] {
        KnownHostsFile::at(path)
            .record_hashed("HIDDEN.test", 2222, key)
            .unwrap();
        let content = fs::read_to_string(path).unwrap();
        assert!(content.starts_with("|1|"));
        assert!(!content.contains("hidden.test"));
        assert_eq!(
            KnownHostsFile::at(path).pins("hidden.test", 2222).unwrap(),
            [Pin {
                line: 1,
                key: key.clone()
            }]
        );
        assert_eq!(
            KnownHostsFile::at(path)
                .lookup("hidden.test", 22, key)
                .unwrap()
                .status,
            Status::Unknown
        );
        KnownHostsFile::at(path)
            .record_hashed("hidden.test", 2222, key)
            .unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), content);
    }
    assert_ne!(fs::read(first).unwrap(), fs::read(second).unwrap());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn handshake_requires_explicit_learning_and_rejects_a_changed_host() {
    use std::{io::ErrorKind, time::Duration};
    use thirtyssh::{
        keys::{PublicKey, ssh_key::public::Ed25519PublicKey},
        transport::Transport,
    };
    use tokio::{io, time::timeout};

    let host = HostKey::generate().unwrap();
    let wrong = HostKey::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("known_hosts");
    fs::write(&path, b"").unwrap();

    for (server_key, expected) in [
        (&host, Status::Unknown),
        (&host, Status::Trusted),
        (&wrong, Status::Changed),
    ] {
        let mut snapshot = KnownHosts::new();
        snapshot.load(&path).unwrap();
        let (left, right) = io::duplex(128);
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                Transport::connect(left, |presented| {
                    let status = snapshot.check("node.test", 2222, presented).unwrap();
                    assert_eq!(status, expected);
                    status == Status::Trusted
                }),
                Transport::accept(right, server_key),
            )
        })
        .await
        .unwrap();
        if expected == Status::Trusted {
            assert!(client.is_ok() && server.is_ok());
        } else {
            assert_eq!(client.err().unwrap().kind(), ErrorKind::PermissionDenied);
            assert!(server.is_err());
        }
        if expected == Status::Unknown {
            assert!(fs::read(&path).unwrap().is_empty());
            // This key was obtained separately, before connecting.
            let key = PublicKey::new(Ed25519PublicKey(host.public_key()).into(), "");
            KnownHostsFile::at(&path)
                .record_hashed("node.test", 2222, &key)
                .unwrap();
        }
    }
}

#[cfg(any(unix, windows))]
#[test]
fn concurrent_updates_keep_all_distinct_hosts_and_only_one_pin_per_host() {
    use std::{io::ErrorKind, sync::Barrier, thread};

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("known_hosts");
    fs::write(&path, "# original\n").unwrap();
    let start = Barrier::new(8);
    thread::scope(|scope| {
        let mut writers = Vec::new();
        for index in 0..8 {
            let start = &start;
            let path = &path;
            writers.push(scope.spawn(move || {
                let identity = identity(index);
                let key = identity.public_key();
                start.wait();
                KnownHostsFile::at(path)
                    .record(&format!("host-{index}.test"), 22, key)
                    .unwrap();
                KnownHostsFile::at(path).record("shared.test", 22, key)
            }));
        }
        let mut added = 0;
        for writer in writers {
            match writer.join().unwrap() {
                Ok(()) => added += 1,
                Err(error) => assert_eq!(error.kind(), ErrorKind::PermissionDenied),
            }
        }
        assert_eq!(added, 1);
    });
    let contents = fs::read_to_string(&path).unwrap();
    assert!(contents.starts_with("# original\n"));
    assert_eq!(contents.lines().count(), 10);
    for index in 0..8 {
        assert_eq!(
            KnownHostsFile::at(&path)
                .lookup(
                    &format!("host-{index}.test"),
                    22,
                    identity(index).public_key()
                )
                .unwrap()
                .status,
            Status::Trusted,
        );
    }
}

#[test]
fn recorded_keys_are_confirmed_in_a_read_only_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("known_hosts");
    let host = identity(13);
    let key = host.public_key();
    KnownHostsFile::at(&path)
        .record("node.test", 22, key)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions.clone()).unwrap();

    KnownHostsFile::at(&path)
        .record("node.test", 22, key)
        .unwrap();
    KnownHostsFile::at(&path)
        .record_hashed("NODE.test", 22, key)
        .unwrap();
    let changed = identity(14);
    assert_eq!(
        KnownHostsFile::at(&path)
            .record("node.test", 22, changed.public_key())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read(&path).unwrap(), original);

    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions).unwrap();
    KnownHostsFile::at(&path)
        .record("other.test", 22, key)
        .unwrap();
    assert_ne!(fs::read(&path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn updates_preserve_unix_mode_and_reject_symlinks() {
    use std::{
        io::ErrorKind,
        os::unix::fs::{PermissionsExt, symlink},
    };

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("known_hosts");
    let link = temp.path().join("link");
    let identity = identity(12);
    let key = identity.public_key();
    KnownHostsFile::at(&path)
        .record("old.test", 22, key)
        .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    KnownHostsFile::at(&path)
        .record("new.test", 22, key)
        .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    symlink(&path, &link).unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        KnownHostsFile::at(&link)
            .record("third.test", 22, key)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
}

#[test]
fn an_unreadable_hashed_host_field_names_no_host_unless_it_revokes() {
    let host = HostKey::generate().unwrap().public_key();
    let key = encoded_key(&host);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("known_hosts");
    let check = |content: String| {
        fs::write(&path, content).unwrap();
        let mut keys = KnownHosts::new();
        keys.load(&path).unwrap();
        keys.check("host.test", 22, &host)
    };
    // A damaged line for some other host must not hide the entry that matches.
    let damaged = format!("|1|truncated|entry ssh-ed25519 {key}\n");
    assert_eq!(
        check(format!("{damaged}host.test ssh-ed25519 {key}\n")).unwrap(),
        Status::Trusted
    );
    assert_eq!(check(damaged.clone()).unwrap(), Status::Unknown);
    // A damaged revocation could be the one that bans this key.
    assert!(check(format!("@revoked {damaged}host.test ssh-ed25519 {key}\n")).is_err());
}
