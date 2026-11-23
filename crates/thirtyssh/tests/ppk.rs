#[path = "fixtures/putty.rs"]
mod putty;

use data_encoding::{BASE64, HEXLOWER};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{fs, io::ErrorKind, path::Path, process::Command};
use thirtyssh::{
    keys::{
        HashAlg, PrivateKey, PrivateKeyLimits, PrivateKeyReader, PublicKey,
        ssh_key::{Mpint, private::Ed25519Keypair},
    },
    wire::Writer,
};

use putty::PASSPHRASE;

fn clear_ppk(key: &PublicKey, private: &[u8], comment: &str) -> String {
    let public = key.to_bytes().unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"").unwrap();
    for field in [
        b"ssh-ed25519",
        b"none".as_slice(),
        comment.as_bytes(),
        &public,
        private,
    ] {
        mac.update(&(field.len() as u32).to_be_bytes());
        mac.update(field);
    }
    format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: {comment}\nPublic-Lines: 1\n{}\nPrivate-Lines: 1\n{}\nPrivate-MAC: {}\n",
        BASE64.encode(&public),
        BASE64.encode(private),
        HEXLOWER.encode(&mac.finalize().into_bytes()),
    )
}

#[test]
fn ppk_checks_mac_before_keypair_and_accepts_canonical_seed_edge_cases() {
    for seed in [[0; 32], [0x80; 32]] {
        let fixture = PrivateKey::new(Ed25519Keypair::from_seed(&seed).into(), "fixture").unwrap();
        let scalar = Mpint::from_positive_bytes(&seed);
        let mut buf = [0u8; 38];
        let mut writer = Writer::new(&mut buf);
        writer.string(scalar.as_bytes()).unwrap();
        let private = writer.written();
        let file = clear_ppk(fixture.public_key(), private, "fixture");
        for ending in ["\n", "\r\n", "\r"] {
            assert_eq!(
                PrivateKeyReader::new()
                    .text(&file.replace('\n', ending))
                    .unwrap(),
                fixture
            );
        }
        let tampered = file.replace("Comment: fixture", "Comment: changed");
        let error = PrivateKeyReader::new().text(&tampered).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("MAC"));

        let other = PrivateKey::new(Ed25519Keypair::from_seed(&[7; 32]).into(), "fixture").unwrap();
        let wrong_key = clear_ppk(other.public_key(), private, "fixture");
        assert!(
            PrivateKeyReader::new()
                .text(&wrong_key)
                .unwrap_err()
                .to_string()
                .contains("keypair")
        );
        let mut extra = private.to_vec();
        extra.push(0);
        assert!(
            PrivateKeyReader::new()
                .text(&clear_ppk(fixture.public_key(), &extra, "fixture"))
                .is_err()
        );
        let mut raw = Writer::new(&mut buf);
        raw.string(&seed).unwrap();
        let file = clear_ppk(fixture.public_key(), raw.written(), "fixture");
        assert_eq!(PrivateKeyReader::new().text(&file).unwrap(), fixture);
    }
}

#[test]
fn encrypted_ppk_v2_and_v3_pinned_puttygen_vectors() {
    let [v2, v3] = putty::encrypted_vectors();
    let key = PrivateKeyReader::new()
        .passphrase(PASSPHRASE)
        .text(&v2)
        .unwrap();
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&v3)
            .unwrap(),
        key
    );
    assert_eq!(
        key.fingerprint(HashAlg::Sha256).to_string(),
        putty::FINGERPRINT
    );
    for file in [v2, v3] {
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase("wrong")
                .text(&file)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let modified = file.replace("thirtyssh-disposable-ppk-test", "tampered");
        assert!(
            PrivateKeyReader::new()
                .passphrase(PASSPHRASE)
                .text(&modified)
                .is_err()
        );
    }
}

#[test]
fn ppk_rejects_argon2_resource_parameters_before_key_derivation() {
    let public = PrivateKey::new(Ed25519Keypair::from_seed(&[9; 32]).into(), "").unwrap();
    let public = BASE64.encode(&public.public_key().to_bytes().unwrap());
    let fake = |memory: u32, passes: u32, lanes: u32| {
        format!(
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: ppk\nPublic-Lines: 1\n{public}\nKey-Derivation: Argon2id\nArgon2-Memory: {memory}\nArgon2-Passes: {passes}\nArgon2-Parallelism: {lanes}\nArgon2-Salt: 0123456789abcdef\nPrivate-Lines: 1\nAAAAAAAAAAAAAAAAAAAAAA==\nPrivate-MAC: {}\n",
            "0".repeat(64),
        )
    };
    for file in [
        fake(u32::MAX, 1, 1),
        fake(8192, u32::MAX, 1),
        fake(8192, 1, 9),
    ] {
        let error = PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&file)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("configured limit"));
    }
    let defaults_invalid = fake(8, 0, 1);
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&defaults_invalid)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );

    let mut tight = PrivateKeyLimits::default();
    tight.max_argon2_memory_kib = 32;
    let otherwise_valid = fake(64, 2, 1);
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .limits(tight)
            .text(&otherwise_valid)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData,
    );
    let duplicate = otherwise_valid.replace(
        "Argon2-Memory: 64",
        "Argon2-Memory: 64\nArgon2-Memory: 4294967295",
    );
    assert!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&duplicate)
            .is_err()
    );
}

#[test]
#[ignore = "requires PuTTYgen and ssh-keygen"]
fn puttygen_ppk_v2_and_v3_match_openssh_keypairs() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let password = root.join("fixture-passphrase");
    fs::write(&password, format!("{PASSPHRASE}\n")).unwrap();
    fs::write(root.join("empty-passphrase"), b"\n").unwrap();
    let original = root.join("original");
    let file = root.join("converted.ppk");

    for (algorithm, bits) in [
        ("ed25519", "256"),
        #[cfg(feature = "rsa")]
        ("rsa", "2048"),
        ("dsa", "1024"),
        ("ecdsa", "256"),
        ("ecdsa", "384"),
        ("ecdsa", "521"),
    ] {
        let identity = if algorithm == "dsa" {
            run(putty_command(root).args([
                "-q",
                "-t",
                algorithm,
                "-b",
                bits,
                "-C",
                "fixture",
                "-o",
                "generated-dsa.ppk",
                "--new-passphrase",
                "empty-passphrase",
            ]));
            run(putty_command(root).args([
                "generated-dsa.ppk",
                "-O",
                "private-openssh-new",
                "-o",
                "original",
            ]));
            PrivateKeyReader::new().file(&original).unwrap()
        } else {
            run(Command::new("ssh-keygen")
                .args([
                    "-q", "-t", algorithm, "-b", bits, "-N", "", "-C", "fixture", "-f",
                ])
                .arg(&original));
            PrivateKeyReader::new().file(&original).unwrap()
        };
        for (settings, encrypted) in [
            ("version=2", false),
            ("version=2", true),
            ("version=3", false),
            (
                "version=3,kdf=argon2id,memory=64,passes=2,parallelism=2",
                true,
            ),
            (
                "version=3,kdf=argon2i,memory=64,passes=2,parallelism=2",
                true,
            ),
            (
                "version=3,kdf=argon2d,memory=64,passes=2,parallelism=2",
                true,
            ),
        ] {
            convert(root, settings, encrypted);
            let actual = PrivateKeyReader::new()
                .passphrase(encrypted.then_some(PASSPHRASE))
                .file(&file)
                .unwrap_or_else(|error| panic!("{algorithm}/{bits} {settings}: {error}"));
            assert_eq!(actual, identity, "{algorithm}/{bits} {settings}");
            if encrypted {
                assert_eq!(
                    PrivateKeyReader::new().file(&file).unwrap_err().kind(),
                    ErrorKind::PermissionDenied
                );
                assert_eq!(
                    PrivateKeyReader::new()
                        .passphrase("wrong")
                        .file(&file)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::PermissionDenied
                );
            }
            fs::remove_file(&file).unwrap();
        }
        fs::remove_file(&original).unwrap();
    }
}

fn convert(dir: &Path, settings: &str, encrypted: bool) {
    let mut command = putty_command(dir);
    command.args([
        "original",
        "-q",
        "-O",
        "private",
        "-o",
        "converted.ppk",
        "--ppk-param",
        settings,
    ]);
    if encrypted {
        command.args(["--new-passphrase", "fixture-passphrase"]);
    }
    run(&mut command);
}

fn putty_command(dir: &Path) -> Command {
    let exe = std::env::var_os("THIRTYSSH_TEST_PUTTYGEN").unwrap_or_else(|| "puttygen".into());
    let mut command = Command::new(exe);
    command.current_dir(dir);
    command
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
