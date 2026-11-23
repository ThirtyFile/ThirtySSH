use data_encoding::BASE64;
use std::{fs, io::ErrorKind};
use thirtyssh::keys::{
    Algorithm, Certificate, Credential, EcdsaCurve, PrivateKey, public,
    ssh_key::certificate::{Builder, CertType},
    system_rng, validate_certificate_at,
};

#[test]
fn public_key_loading_and_exact_binary_decoding() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("test.pub");
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
    ] {
        let private = PrivateKey::random(&mut system_rng(), algorithm.clone()).unwrap();
        let public = private.public_key();
        let blob = public.to_bytes().unwrap();
        let base64 = BASE64.encode(&blob);
        assert_eq!(public::from_blob(&blob).unwrap(), *public);
        assert_eq!(public::from_base64(&base64).unwrap(), *public);
        let wrapped = base64
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        assert_eq!(public::from_base64(&wrapped).unwrap(), *public);
        fs::write(&path, &base64).unwrap();
        assert_eq!(public::from_file(&path).unwrap(), *public);
        for file in [wrapped.clone(), wrapped.replace('\r', "") + "\n"] {
            fs::write(&path, file).unwrap();
            assert_eq!(public::from_file(&path).unwrap(), *public);
        }
        fs::write(&path, format!("{base64} test fixture\n")).unwrap();
        let commented = public::from_file(&path).unwrap_err();
        assert_eq!(commented.kind(), ErrorKind::InvalidData);
        fs::write(&path, format!("{algorithm}\t{base64} test fixture\r\n")).unwrap();
        assert_eq!(public::from_file(&path).unwrap(), *public);
        fs::write(&path, format!("ssh-rsa {base64}\n")).unwrap();
        let mismatched = public::from_file(&path).unwrap_err();
        assert_eq!(mismatched.kind(), ErrorKind::InvalidData);

        let mut malformed = blob;
        malformed.push(0);
        assert!(public::from_blob(&malformed).is_err());
        let invalid = public::from_base64("bad+@base64").unwrap_err();
        assert_eq!(invalid.kind(), ErrorKind::InvalidData);
    }
    fs::write(&path, b"\n\t").unwrap();
    let empty = public::from_file(&path).unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::InvalidData);
    fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
    let oversized = public::from_file(&path).unwrap_err();
    assert_eq!(oversized.kind(), ErrorKind::InvalidData);
    let missing = public::from_file(directory.path().join("missing")).unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::NotFound);
}

#[test]
fn certificate_file_loading_preserves_signed_encoding_and_leaves_trust_to_policy() {
    let authority = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    let private = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    let mut builder = Builder::new(
        vec![3; 32],
        private.public_key().key_data().clone(),
        100,
        200,
    )
    .unwrap();
    builder
        .cert_type(CertType::Host)
        .unwrap()
        .valid_principal("host.example.test")
        .unwrap();
    let signed = builder.sign(&authority).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key-cert.pub");
    fs::write(&path, format!("{}\r\n", signed.to_openssh().unwrap())).unwrap();
    let certificate: Certificate = public::certificate_from_file(&path).unwrap();
    assert_eq!(certificate, signed);
    assert!(
        validate_certificate_at(
            &certificate,
            authority.public_key(),
            "host.example.test",
            CertType::Host,
            100
        )
        .unwrap()
    );
    assert!(
        !validate_certificate_at(
            &certificate,
            authority.public_key(),
            "host.example.test",
            CertType::Host,
            200
        )
        .unwrap()
    );
    let identity = Credential::from(certificate);
    assert_eq!(identity.certificate(), Some(&signed));
    assert_eq!(identity.key_data(), private.public_key().key_data());
    let raw = Credential::from(private.public_key().clone());
    assert!(raw.certificate().is_none());
    fs::write(
        &path,
        signed
            .to_openssh()
            .unwrap()
            .replace("ssh-ed25519-cert-v01", "ssh-rsa-cert-v01"),
    )
    .unwrap();
    assert!(public::certificate_from_file(&path).is_err());

    let mut oversized = Builder::new(
        vec![0; 64 * 1024],
        private.public_key().key_data().clone(),
        100,
        200,
    )
    .unwrap();
    oversized.all_principals_valid().unwrap();
    let oversized = oversized.sign(&authority).unwrap().to_openssh().unwrap();
    assert!(Certificate::from_openssh(&oversized).is_ok());
    fs::write(&path, oversized).unwrap();
    let oversized = public::certificate_from_file(&path).unwrap_err();
    assert_eq!(oversized.kind(), ErrorKind::InvalidData);
}
