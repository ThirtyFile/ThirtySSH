use std::{fs, io::ErrorKind};
use thirtyssh::{
    keys::{
        PrivateKey, PrivateKeyLimits, PrivateKeyReader, PublicKey,
        ssh_key::{Cipher, Kdf, LineEnding, private::Ed25519Keypair},
    },
    wire::Reader,
};

const PASSPHRASE: &str = "fixture-key-passphrase";
const SHORT_P256_PEM: &str = include_str!("fixtures/openssh_p256_short.pem");
const SHORT_P256_PASSWORD: &str = "isolated-sshd-key-fixture";
const MAGIC: &[u8] = b"openssh-key-v1\0";

fn fixture_key() -> PrivateKey {
    PrivateKey::new(
        Ed25519Keypair::from_seed(&[42; 32]).into(),
        "format fixture",
    )
    .unwrap()
}

// ssh-keygen encrypted this test-only scalar (31 bytes of 0x37) with AES-128-CBC.
// OpenSSH encodes it as a 31-byte mpint in a P-256 key.
#[test]
fn openssh_loads_encrypted_short_p256_scalar() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openssh_p256_short.pem");
    let expected = PublicKey::from_openssh(concat!(
        "ecdsa-sha2-nistp256 ",
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHp/UDEvcwV8ynC3",
        "lhaVeUG1415wu3E3ic6w/jOg3lUarMM0pib47z0aTxXuNthXwd6z4pDcIu832SAxjSLSNCE="
    ))
    .unwrap();
    let loaded = PrivateKeyReader::new()
        .passphrase(SHORT_P256_PASSWORD)
        .file(&path)
        .unwrap();
    assert_eq!(loaded.public_key().key_data(), expected.key_data());
    for rejected in [None, Some("wrong")] {
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(rejected)
                .file(&path)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }
}

#[cfg(unix)]
#[test]
fn openssh_file_permissions_and_key_decryption_are_independent() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    fs::write(&path, SHORT_P256_PEM).unwrap();
    let expected = PrivateKeyReader::new()
        .passphrase(SHORT_P256_PASSWORD)
        .text(SHORT_P256_PEM)
        .unwrap();
    for mode in [0o600, 0o400, 0o000] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let loaded = PrivateKeyReader::new()
            .passphrase(SHORT_P256_PASSWORD)
            .file(&path);
        // A privileged process may still read a mode-000 file.
        match fs::File::open(&path) {
            Ok(_) => assert_eq!(loaded.unwrap(), expected),
            Err(err) => {
                assert_eq!(mode, 0);
                assert_eq!(err.kind(), ErrorKind::PermissionDenied);
                assert_eq!(loaded.unwrap_err().raw_os_error(), err.raw_os_error());
            }
        }
    }
}

// Assemble a plaintext PROTOCOL.key envelope without using ssh-key's
// fixed-width ECDSA encoder, so the wire representation is under test.
fn openssh_ec_fixture(public: &[u8], scalar: &[u8]) -> Vec<u8> {
    use ssh_encoding::Encode;
    let mut body = vec![0; 8]; // matching check integers
    body.extend_from_slice(public);
    scalar.encode(&mut body).unwrap();
    b"fixture".as_slice().encode(&mut body).unwrap();
    let padding = (8 - body.len() % 8) % 8;
    body.extend(1..=padding as u8);

    let mut key = MAGIC.to_vec();
    b"none".as_slice().encode(&mut key).unwrap();
    b"none".as_slice().encode(&mut key).unwrap();
    b"".as_slice().encode(&mut key).unwrap();
    1u32.encode(&mut key).unwrap();
    public.encode(&mut key).unwrap();
    body.as_slice().encode(&mut key).unwrap();
    key
}

#[test]
fn openssh_ec_mpints_use_the_curve_width_only_after_decoding() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use thirtyssh::keys::ssh_key::public::EcdsaPublicKey;

    let mut full = [0u8; 66];
    full[65] = 0x80;
    for (width, sec1) in [
        (
            32,
            p256::SecretKey::from_slice(&full[34..])
                .unwrap()
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
        (
            48,
            p384::SecretKey::from_slice(&full[18..])
                .unwrap()
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
        (
            66,
            p521::SecretKey::from_slice(&full)
                .unwrap()
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
    ] {
        let point = EcdsaPublicKey::from_sec1_bytes(&sec1).unwrap();
        let expected = PublicKey::new(point.into(), "fixture");
        let public = expected.to_bytes().unwrap();
        for valid in [&[0, 0x80][..], &full[66 - width..]] {
            let key = openssh_ec_fixture(&public, valid);
            assert_eq!(
                PrivateKeyReader::new().openssh(&key).unwrap().public_key(),
                &expected
            );
        }
        for bad in [
            &[][..],
            &[0],
            &[0x80],
            &[0, 0, 0x80],
            &[0x7f],
            &vec![1; width + 1],
        ] {
            assert_eq!(
                PrivateKeyReader::new()
                    .openssh(&openssh_ec_fixture(&public, bad))
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }
    }
}

#[test]
fn openssh_ec_rejects_damaged_authenticated_ciphertext() {
    let key = PrivateKeyReader::new()
        .passphrase(SHORT_P256_PASSWORD)
        .text(SHORT_P256_PEM)
        .unwrap();
    for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
        let encrypted = key
            .encrypt_with(
                cipher,
                Kdf::Bcrypt {
                    salt: vec![17; 16],
                    rounds: 2,
                },
                42,
                PASSPHRASE,
            )
            .unwrap();
        let mut bytes = encrypted.to_bytes().unwrap().to_vec();
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(PASSPHRASE)
                .openssh(&bytes)
                .unwrap(),
            key
        );
        *bytes.last_mut().unwrap() ^= 1;
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(PASSPHRASE)
                .openssh(&bytes)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        bytes.pop();
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(PASSPHRASE)
                .openssh(&bytes)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
}

#[test]
fn openssh_private_key_loading_bounds_kdf_and_validates_envelopes() {
    let key = fixture_key();
    let encrypted = key
        .encrypt_with(
            Cipher::Aes256Gcm,
            Kdf::Bcrypt {
                salt: vec![23; 16],
                rounds: 2,
            },
            47,
            PASSPHRASE,
        )
        .unwrap();
    let bytes = encrypted.to_bytes().unwrap();
    let pem = encrypted.to_openssh(LineEnding::CRLF).unwrap();
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .openssh(&bytes)
            .unwrap(),
        key
    );
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&pem)
            .unwrap(),
        key
    );
    for password in [None, Some(""), Some("wrong")] {
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(password)
                .text(&pem)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }
    let mut limits = PrivateKeyLimits::default();
    limits.max_bcrypt_rounds = 1;
    let error = PrivateKeyReader::new()
        .passphrase(PASSPHRASE)
        .limits(limits)
        .text(&pem)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(error.to_string().contains("rounds"));

    // Change the rounds in the header without invoking the KDF to build the fixture.
    let mut header = Reader::new(&bytes[MAGIC.len()..]);
    header.string().unwrap();
    header.string().unwrap();
    let options = header.string().unwrap();
    let round_offset = bytes.len() - header.remaining().len() - size_of::<u32>();
    assert_eq!(options.last(), Some(&2));
    for rounds in [0, u32::MAX] {
        let mut bad = bytes.to_vec();
        bad[round_offset..round_offset + size_of::<u32>()].copy_from_slice(&rounds.to_be_bytes());
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(PASSPHRASE)
                .openssh(&bad)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    // Valid ciphertext with an invalid GCM tag must never yield a key.
    let mut bad_tag = bytes.to_vec();
    *bad_tag.last_mut().unwrap() ^= 1;
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .openssh(&bad_tag)
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .openssh(&bytes[..bytes.len() - 1])
            .is_err()
    );
    bad_tag.push(0);
    assert!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .openssh(&bad_tag)
            .is_err()
    );

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture");
    assert_eq!(
        PrivateKeyReader::new().file(&path).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    fs::write(&path, pem.as_bytes()).unwrap();
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .file(&path)
            .unwrap(),
        key
    );
    assert!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .limits(limits)
            .file(&path)
            .is_err()
    );
    limits.max_bcrypt_rounds = 2;
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .limits(limits)
            .file(&path)
            .unwrap(),
        key
    );
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(
        PrivateKeyReader::new()
            .file(&path)
            .unwrap_err()
            .to_string()
            .contains("file size")
    );
}

#[test]
fn openssh_unencrypted_round_trip_and_public_key_mismatch() {
    let key = fixture_key();
    let bytes = key.to_bytes().unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    assert_eq!(PrivateKeyReader::new().openssh(&bytes).unwrap(), key);
    assert_eq!(PrivateKeyReader::new().text(&pem).unwrap(), key);
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .text(&pem)
            .unwrap(),
        key
    );

    let mut header = Reader::new(&bytes[MAGIC.len()..]);
    assert_eq!(header.string().unwrap(), b"none");
    assert_eq!(header.string().unwrap(), b"none");
    assert!(header.string().unwrap().is_empty());
    assert_eq!(header.uint32().unwrap(), 1);
    let end = bytes.len() - {
        header.string().unwrap();
        header.remaining().len()
    };
    let mut bad_public_key = bytes.to_vec();
    bad_public_key[end - 1] ^= 1;
    assert_eq!(
        PrivateKeyReader::new()
            .openssh(&bad_public_key)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}

#[test]
#[ignore = "requires OpenSSH ssh-keygen in PATH"]
fn openssh_generated_encrypted_key_ciphers_and_key_types() {
    use std::process::Command;

    let directory = tempfile::tempdir().unwrap();
    // This covers the complete cipher set enabled by the pinned ssh-key
    // encryption feature and every key type implemented by ThirtySSH.
    for (cipher, kind, bits) in [
        ("aes128-cbc", "ed25519", "256"),
        ("aes192-cbc", "ecdsa", "256"),
        ("aes256-cbc", "ecdsa", "384"),
        ("aes128-ctr", "ecdsa", "521"),
        ("aes192-ctr", "rsa", "2048"),
        ("aes256-ctr", "ed25519", "256"),
        ("aes128-gcm@openssh.com", "ed25519", "256"),
        ("aes256-gcm@openssh.com", "ed25519", "256"),
        ("chacha20-poly1305@openssh.com", "ed25519", "256"),
    ] {
        let path = directory.path().join(cipher.replace('@', "-"));
        let output = Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                kind,
                "-b",
                bits,
                "-Z",
                cipher,
                "-a",
                "2",
                "-N",
                PASSPHRASE,
                "-C",
                "generated key fixture",
                "-f",
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{cipher}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let loaded = PrivateKeyReader::new()
            .passphrase(PASSPHRASE)
            .file(&path)
            .unwrap_or_else(|error| panic!("{cipher}: {error}"));
        let mut public_path = path.as_os_str().to_owned();
        public_path.push(".pub");
        let expected = PublicKey::read_openssh_file(public_path).unwrap();
        assert_eq!(loaded.public_key(), &expected, "{cipher}");
        assert!(!loaded.is_encrypted(), "{cipher}");
        assert!(PrivateKeyReader::new().file(&path).is_err(), "{cipher}");
        assert!(
            PrivateKeyReader::new()
                .passphrase("wrong")
                .file(&path)
                .is_err(),
            "{cipher}"
        );
    }
}
