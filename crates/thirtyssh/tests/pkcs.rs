use pkcs5::pbes2::{EncryptionScheme, Kdf, Parameters, Pbkdf2Params, Pbkdf2Prf, ScryptParams};
#[cfg(feature = "rsa")]
use pkcs8::der::asn1::UintRef;
use pkcs8::{
    EncodePrivateKey, EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef, SecretDocument,
    der::{
        Decode, Tag,
        asn1::{AnyRef, OctetStringRef},
    },
};
use std::{fs, io::ErrorKind, path::Path, process::Command};
use thirtyssh::keys::{
    KeyError, Pkcs8Encryption, PrivateKey, PrivateKeyLimits, PrivateKeyReader, pkcs8_der,
    pkcs8_pem, ssh_key::private::Ed25519Keypair,
};

const PASSWORD: &str = "pkcs-fixture-passphrase";

fn encrypted_pem(params: Parameters, ciphertext: &[u8]) -> String {
    let encrypted = EncryptedPrivateKeyInfoRef {
        encrypted_data: OctetStringRef::new(ciphertext).unwrap(),
        encryption_algorithm: params.into(),
    };
    SecretDocument::try_from(encrypted)
        .unwrap()
        .to_pem("ENCRYPTED PRIVATE KEY", pem_rfc7468::LineEnding::LF)
        .unwrap()
        .to_string()
}

#[test]
fn pkcs8_key_round_trip_wrong_passphrase_and_malformed_der() {
    let key = PrivateKey::new(Ed25519Keypair::from_seed(&[11; 32]).into(), "").unwrap();
    let der = pkcs8_der(&key, None).unwrap();
    assert_eq!(PrivateKeyReader::new().der(&der).unwrap(), key);
    assert!(PrivateKeyReader::new().der(&der[..der.len() - 1]).is_err());
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(PrivateKeyReader::new().der(&trailing).is_err());
    let wrong_public = ed25519::pkcs8::KeypairBytes {
        secret_key: [11; 32],
        public_key: Some(ed25519::pkcs8::PublicKeyBytes([1; 32])),
    }
    .to_pkcs8_der()
    .unwrap();
    let mismatch = PrivateKeyReader::new()
        .der(wrong_public.as_bytes())
        .unwrap_err();
    assert!(mismatch.to_string().contains("keypair"));
    assert!(matches!(
        KeyError::of(&mismatch),
        Some(KeyError::Mismatched(_))
    ));

    let encrypted = pkcs8_der(
        &key,
        Some(Pkcs8Encryption {
            passphrase: PASSWORD.as_bytes(),
            rounds: 2000,
        }),
    )
    .unwrap();
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSWORD)
            .der(&encrypted)
            .unwrap(),
        key
    );
    assert!(
        PrivateKeyReader::new()
            .passphrase("wrong")
            .der(&encrypted)
            .is_err()
    );
    assert!(
        pkcs8_der(
            &key,
            Some(Pkcs8Encryption {
                passphrase: PASSWORD.as_bytes(),
                rounds: u32::MAX
            })
        )
        .is_err()
    );
    let protection = Pkcs8Encryption {
        passphrase: PASSWORD.as_bytes(),
        rounds: 2000,
    };
    let pem = pkcs8_pem(&key, Some(protection)).unwrap();
    let pem = pem.as_str();
    assert_eq!(
        PrivateKeyReader::new()
            .passphrase(PASSWORD)
            .text(pem)
            .unwrap(),
        key
    );
    let missing = PrivateKeyReader::new().text(pem).unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::PermissionDenied);
    assert_eq!(KeyError::of(&missing), Some(&KeyError::PassphraseRequired));
    let wrong = PrivateKeyReader::new()
        .passphrase("wrong")
        .text(pem)
        .unwrap_err();
    assert_eq!(wrong.kind(), ErrorKind::PermissionDenied);
    let params = Parameters::generate_pbkdf2_sha256_aes256cbc(4, b"fixture salt", [7; 16]).unwrap();
    let ciphertext = params.encrypt(PASSWORD, b"not a DER private key").unwrap();
    let encrypted = encrypted_pem(params, &ciphertext);
    let invalid_plaintext = PrivateKeyReader::new()
        .passphrase(PASSWORD)
        .text(&encrypted)
        .unwrap_err();
    assert_eq!(invalid_plaintext.kind(), ErrorKind::PermissionDenied);
    assert_eq!(invalid_plaintext.to_string(), wrong.to_string());
    // A wrong passphrase and undecodable plaintext are indistinguishable.
    assert!(KeyError::of(&invalid_plaintext).is_none());
    assert!(KeyError::of(&wrong).is_none());
}

#[test]
fn pkcs8_rejects_excessive_and_zero_kdf_costs_before_decryption() {
    let scheme = EncryptionScheme::Aes256Cbc { iv: [0; 16] };
    let mut pbkdf = Pbkdf2Params::hmac_sha256(2, b"fixture salt").unwrap();
    for rounds in [0, u32::MAX] {
        pbkdf.iteration_count = rounds;
        let pem = encrypted_pem(
            Parameters {
                encryption: scheme,
                kdf: Kdf::Pbkdf2(pbkdf),
            },
            &[0u8; 16],
        );
        let error = PrivateKeyReader::new()
            .passphrase(PASSWORD)
            .text(&pem)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("PBKDF2 rounds"));
    }
    let scrypt = ScryptParams {
        key_length: None,
        cost_parameter: 1 << 63,
        block_size: 8,
        parallelization: 1,
        salt: b"fixture salt".as_slice().try_into().unwrap(),
    };
    let variants = [
        (scrypt, "scrypt cost"),
        (
            ScryptParams {
                cost_parameter: 100,
                ..scrypt
            },
            "scrypt parameters",
        ),
        (
            ScryptParams {
                cost_parameter: 1 << 14,
                parallelization: 100,
                ..scrypt
            },
            "scrypt cost",
        ),
    ];
    for (kdf, reason) in variants {
        let pem = encrypted_pem(
            Parameters {
                encryption: scheme,
                kdf: Kdf::Scrypt(kdf),
            },
            &[0u8; 16],
        );
        let error = PrivateKeyReader::new()
            .passphrase(PASSWORD)
            .text(&pem)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains(reason));
    }
}

#[test]
fn pkcs8_covers_default_pbes2_cipher_and_kdf_combinations() {
    let key = PrivateKey::new(Ed25519Keypair::from_seed(&[17; 32]).into(), "").unwrap();
    let document = pkcs8_der(&key, None).unwrap();
    let salt = b"PKCS8 fixture salt".as_slice().try_into().unwrap();
    let scrypt = Kdf::Scrypt(ScryptParams {
        salt,
        cost_parameter: 16,
        block_size: 8,
        parallelization: 2,
        key_length: None,
    });
    let mut kdfs = vec![scrypt];
    for prf in [
        Pbkdf2Prf::HmacWithSha224,
        Pbkdf2Prf::HmacWithSha256,
        Pbkdf2Prf::HmacWithSha384,
        Pbkdf2Prf::HmacWithSha512,
    ] {
        kdfs.push(Kdf::Pbkdf2(Pbkdf2Params {
            salt,
            iteration_count: 4,
            key_length: None,
            prf,
        }));
    }
    for encryption in [
        EncryptionScheme::Aes128Cbc { iv: [0x11; 16] },
        EncryptionScheme::Aes192Cbc { iv: [0x22; 16] },
        EncryptionScheme::Aes256Cbc { iv: [0x33; 16] },
        EncryptionScheme::Aes128Gcm { nonce: [0x44; 12] },
        EncryptionScheme::Aes256Gcm { nonce: [0x55; 12] },
    ] {
        for kdf in &kdfs {
            let params = Parameters {
                encryption,
                kdf: kdf.clone(),
            };
            let ciphertext = params.encrypt(PASSWORD, &document).unwrap();
            let pem = encrypted_pem(params, &ciphertext);
            assert_eq!(
                PrivateKeyReader::new()
                    .passphrase(PASSWORD)
                    .text(&pem)
                    .unwrap(),
                key,
                "{encryption:?} {kdf:?}"
            );
            assert!(
                PrivateKeyReader::new()
                    .passphrase("wrong")
                    .text(&pem)
                    .is_err()
            );
        }
    }
}

#[test]
fn legacy_ed25519_pkcs8_requires_opt_in_and_checks_both_public_fields() {
    // The old encoding: version 1, the seed and public key together in a
    // nested OCTET STRING, and the public key again in an EXPLICIT [1] BIT
    // STRING.
    let seed: [u8; 32] = std::array::from_fn(|index| index as u8 * 7 + 3);
    let public = Ed25519Keypair::from_seed(&seed).public.0;
    let fixture = [
        &[0x30, 0x73, 0x02, 0x01, 0x01][..],
        &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
        &[0x04, 0x42, 0x04, 0x40],
        &seed,
        &public,
        &[0xa1, 0x23, 0x03, 0x21, 0x00],
        &public,
    ]
    .concat();
    let pem =
        pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, &fixture).unwrap();
    let pem = pem.as_str();
    let params = Parameters::generate_pbkdf2_sha256_aes256cbc(4, b"fixture salt", [7; 16]).unwrap();
    let ciphertext = params.encrypt(PASSWORD, &fixture).unwrap();
    let encrypted = encrypted_pem(params, &ciphertext);
    let mut inconsistent = fixture.clone();
    *inconsistent.last_mut().unwrap() ^= 1;
    assert!(PrivateKeyReader::new().der(&inconsistent).is_err());
    let mut inconsistent = fixture.clone();
    inconsistent[16 + 32] ^= 1;
    assert!(PrivateKeyReader::new().der(&inconsistent).is_err());

    if cfg!(feature = "pre-rfc8410-ed25519") {
        let key = PrivateKeyReader::new().text(pem).unwrap();
        let blank_line = pem.replace("\n-----END", "\n\n-----END");
        assert_ne!(blank_line, pem);
        assert_eq!(PrivateKeyReader::new().text(&blank_line).unwrap(), key);
        let pair = key.key_data().ed25519().unwrap();
        assert_eq!(pair.private.as_ref(), seed.as_slice());
        assert_eq!(pair.public.0, public);
        assert_eq!(PrivateKeyReader::new().der(&fixture).unwrap(), key);
        assert_eq!(
            PrivateKeyReader::new()
                .passphrase(PASSWORD)
                .text(&encrypted)
                .unwrap(),
            key
        );
        assert!(
            PrivateKeyReader::new()
                .passphrase("wrong")
                .text(&encrypted)
                .is_err()
        );
    } else {
        assert!(PrivateKeyReader::new().der(&fixture).is_err());
        assert!(PrivateKeyReader::new().text(pem).is_err());
        assert!(
            PrivateKeyReader::new()
                .passphrase(PASSWORD)
                .text(&encrypted)
                .is_err()
        );
    }
}

#[test]
#[ignore = "requires the OpenSSL executable in PATH"]
fn openssl_pkcs_import_export_and_encryption_interoperate() {
    let directory = tempfile::tempdir().unwrap();
    let work = directory.path();
    for (algorithm, parameters) in [
        ("ED25519", None),
        #[cfg(feature = "rsa")]
        ("RSA", Some("rsa_keygen_bits:2048")),
        ("EC", Some("ec_paramgen_curve:P-256")),
        ("EC", Some("ec_paramgen_curve:P-384")),
        ("EC", Some("ec_paramgen_curve:P-521")),
    ] {
        let mut generate = vec!["genpkey", "-algorithm", algorithm, "-out", "original"];
        if let Some(parameters) = parameters {
            generate.extend(["-pkeyopt", parameters]);
        }
        openssl(work, &generate);
        let original_public = openssl(
            work,
            &["pkey", "-in", "original", "-pubout", "-outform", "DER"],
        );
        let baseline = PrivateKeyReader::new().file(work.join("original")).unwrap();
        if algorithm != "ED25519" {
            openssl(
                work,
                &[
                    "pkey",
                    "-in",
                    "original",
                    "-traditional",
                    "-out",
                    "traditional",
                ],
            );
            let traditional = PrivateKeyReader::new()
                .file(work.join("traditional"))
                .unwrap();
            assert_eq!(traditional, baseline, "{algorithm} {parameters:?}");

            for cipher in ["-aes-128-cbc", "-aes-256-cbc"] {
                openssl(
                    work,
                    &[
                        "pkey",
                        "-in",
                        "original",
                        "-traditional",
                        cipher,
                        "-passout",
                        &format!("pass:{PASSWORD}"),
                        "-out",
                        "legacy",
                    ],
                );
                let path = work.join("legacy");
                assert_eq!(
                    PrivateKeyReader::new()
                        .passphrase(PASSWORD)
                        .file(&path)
                        .unwrap(),
                    baseline
                );
                assert!(
                    PrivateKeyReader::new()
                        .passphrase("wrong")
                        .file(&path)
                        .is_err()
                );
                assert_eq!(
                    PrivateKeyReader::new().file(&path).unwrap_err().kind(),
                    ErrorKind::PermissionDenied
                );
            }
        }

        #[cfg(feature = "rsa")]
        if algorithm == "RSA" {
            let der = openssl(
                work,
                &["rsa", "-in", "original", "-traditional", "-outform", "DER"],
            );
            let mut key = pkcs1::RsaPrivateKey::from_der(&der).unwrap();
            key.exponent2 = UintRef::new(&[1]).unwrap();
            let bad = SecretDocument::try_from(key)
                .unwrap()
                .to_pem("RSA PRIVATE KEY", pem_rfc7468::LineEnding::LF)
                .unwrap();
            let error = PrivateKeyReader::new().text(&bad).unwrap_err();
            assert!(error.to_string().contains("CRT parameters"));
        }

        if let Some(curve) = parameters.and_then(|arg| arg.strip_prefix("ec_paramgen_curve:")) {
            for conversion in ["uncompressed", "compressed"] {
                openssl(
                    work,
                    &[
                        "ec",
                        "-in",
                        "original",
                        "-param_enc",
                        "explicit",
                        "-conv_form",
                        conversion,
                        "-out",
                        "explicit",
                    ],
                );
                assert_eq!(
                    PrivateKeyReader::new().file(work.join("explicit")).unwrap(),
                    baseline
                );
                openssl(
                    work,
                    &[
                        "pkcs8",
                        "-topk8",
                        "-nocrypt",
                        "-in",
                        "explicit",
                        "-out",
                        "explicit-pkcs8",
                    ],
                );
                assert_eq!(
                    PrivateKeyReader::new()
                        .file(work.join("explicit-pkcs8"))
                        .unwrap(),
                    baseline
                );
            }
            let mut domain = openssl(
                work,
                &[
                    "ecparam",
                    "-name",
                    curve,
                    "-param_enc",
                    "explicit",
                    "-outform",
                    "DER",
                ],
            );
            let normal = pkcs8_der(&baseline, None).unwrap();
            let mut key = PrivateKeyInfoRef::from_der(&normal).unwrap();
            let params = AnyRef::from_der(&domain).unwrap();
            assert!(params.value().starts_with(&[2, 1, 1]));
            key.algorithm.parameters =
                Some(AnyRef::new(Tag::Sequence, &params.value()[3..]).unwrap());
            let versionless = SecretDocument::try_from(key).unwrap();
            assert_eq!(
                PrivateKeyReader::new().der(versionless.as_bytes()).unwrap(),
                baseline
            );

            assert!(domain.ends_with(&[2, 1, 1]));
            let order_byte = domain.len() - 4;
            domain[order_byte] ^= 1;
            let mut key = PrivateKeyInfoRef::from_der(&normal).unwrap();
            key.algorithm.parameters = Some(AnyRef::from_der(&domain).unwrap());
            let mutated = SecretDocument::try_from(key).unwrap();
            let error = PrivateKeyReader::new().der(mutated.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("explicit EC domain"));
        }

        for encryption in [
            &["-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256"][..],
            &["-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA512"],
            &["-scrypt", "-scrypt_N", "1024"],
        ] {
            let pass = format!("pass:{PASSWORD}");
            let mut protect = vec![
                "pkcs8",
                "-topk8",
                "-in",
                "original",
                "-out",
                "encrypted",
                "-passout",
                &pass,
            ];
            protect.extend(encryption);
            openssl(work, &protect);
            let path = work.join("encrypted");
            assert_eq!(
                PrivateKeyReader::new()
                    .passphrase(PASSWORD)
                    .file(&path)
                    .unwrap(),
                baseline
            );
            assert_eq!(
                PrivateKeyReader::new()
                    .passphrase("wrong")
                    .file(&path)
                    .unwrap_err()
                    .kind(),
                ErrorKind::PermissionDenied
            );
            let contents = fs::read_to_string(path).unwrap();
            let mut limits = PrivateKeyLimits::default();
            limits.max_pbkdf2_rounds = 1;
            limits.max_scrypt_memory = 1024;
            assert_eq!(
                PrivateKeyReader::new()
                    .passphrase(PASSWORD)
                    .limits(limits)
                    .text(&contents)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData,
            );
        }

        fs::write(
            work.join("export"),
            pkcs8_pem(&baseline, None).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            openssl(
                work,
                &["pkey", "-in", "export", "-pubout", "-outform", "DER"]
            ),
            original_public,
        );
        let protection = Pkcs8Encryption {
            passphrase: PASSWORD.as_bytes(),
            rounds: 2048,
        };
        let export = pkcs8_pem(&baseline, Some(protection)).unwrap();
        fs::write(work.join("export"), export.as_bytes()).unwrap();
        assert_eq!(
            openssl(
                work,
                &[
                    "pkey",
                    "-in",
                    "export",
                    "-passin",
                    &format!("pass:{PASSWORD}"),
                    "-pubout",
                    "-outform",
                    "DER"
                ]
            ),
            original_public,
        );
    }
}

fn openssl(directory: &Path, args: &[&str]) -> Vec<u8> {
    let command = std::env::var_os("THIRTYSSH_TEST_OPENSSL").unwrap_or_else(|| "openssl".into());
    let output = Command::new(command)
        .current_dir(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
