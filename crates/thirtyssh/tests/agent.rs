use std::{
    io::ErrorKind,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use thirtyssh::keys::PrivateKeyReader;
use thirtyssh::{
    keys::{
        Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, Signature,
        agent::{AgentIo, Client, Constraint, Credential, Error, Identity},
        signature::{Signer, Verifier},
        ssh_encoding::{Decode, Encode},
        ssh_key::{
            certificate::{Builder, CertType},
            private::KeypairData,
        },
        system_rng,
    },
    wire::Reader,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

const DATA: &[u8] = b"agent fixture signing data";
const TEST_TIMEOUT: Duration = Duration::from_secs(8);

async fn receive(stream: &mut (impl AgentIo + Unpin)) -> Vec<u8> {
    let size = stream.read_u32().await.unwrap();
    assert!((1..=256 * 1024).contains(&size));
    let mut data = vec![0; size as usize];
    stream.read_exact(&mut data).await.unwrap();
    data
}

async fn reply(stream: &mut (impl AgentIo + Unpin), message: &[u8]) {
    stream.write_u32(message.len() as u32).await.unwrap();
    stream.write_all(message).await.unwrap();
    stream.flush().await.unwrap();
}

fn field(packet: &mut Vec<u8>, bytes: &[u8]) {
    packet.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    packet.extend_from_slice(bytes);
}

fn fake_rsa_public() -> PublicKey {
    let mut packet = Vec::new();
    field(&mut packet, b"ssh-rsa");
    field(&mut packet, &[1, 0, 1]);
    field(&mut packet, &[0x7f; 256]);
    PublicKey::from_bytes(&packet).unwrap()
}

fn inspect_sign_request(packet: &[u8], key_blob: &[u8], flags: u32) {
    let mut reader = Reader::new(packet);
    assert_eq!(reader.byte().unwrap(), 13);
    assert_eq!(reader.string().unwrap(), key_blob);
    assert_eq!(reader.string().unwrap(), DATA);
    assert_eq!(reader.uint32().unwrap(), flags);
    reader.finish().unwrap();
}

fn user_certificate(key: &PrivateKey) -> Certificate {
    let ca = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder =
        Builder::new_with_random_nonce(&mut system_rng(), key.public_key(), now - 10, now + 60)
            .unwrap();
    builder
        .key_id("fixture")
        .unwrap()
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal("fixture")
        .unwrap();
    builder.sign(&ca).unwrap()
}

#[tokio::test]
async fn agent_management_encodes_keys_and_token_constraints_and_checks_replies() {
    timeout(TEST_TIMEOUT, async {
        let mut key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        key.set_comment("fixture comment");
        let constraints = [
            Constraint::Lifetime { seconds: 19 },
            Constraint::ConfirmEachUse,
            Constraint::Extension {
                name: b"fixture@example.test".to_vec(),
                data: b"policy".to_vec(),
            },
        ];
        let (mut peer, stream) = duplex(256);
        let serve = async {
            let mut suffix = vec![1, 0, 0, 0, 19, 2, 255];
            field(&mut suffix, b"fixture@example.test");
            field(&mut suffix, b"policy");
            for expected in [17, 25] {
                let packet = receive(&mut peer).await;
                let mut wire = &packet[1..];
                assert_eq!(packet[0], expected);
                assert!(KeypairData::decode(&mut wire).unwrap() == *key.key_data());
                let mut reader = Reader::new(wire);
                assert_eq!(reader.string().unwrap(), b"fixture comment");
                assert_eq!(
                    reader.remaining(),
                    if expected == 25 {
                        suffix.as_slice()
                    } else {
                        &[]
                    }
                );
                reply(&mut peer, &[6]).await;
            }
            for expected in [20, 26, 21] {
                let packet = receive(&mut peer).await;
                let mut reader = Reader::new(&packet);
                assert_eq!(reader.byte().unwrap(), expected);
                assert_eq!(reader.string().unwrap(), b"fixture token");
                assert_eq!(reader.string().unwrap(), b"fixture pin");
                assert_eq!(
                    reader.remaining(),
                    if expected == 26 {
                        suffix.as_slice()
                    } else {
                        &[]
                    }
                );
                reply(&mut peer, &[if expected == 20 { 6 } else { 5 }]).await;
            }
            for (command, response) in [(22, &[6][..]), (23, &[5]), (23, &[6])] {
                let packet = receive(&mut peer).await;
                let mut reader = Reader::new(&packet);
                assert_eq!(reader.byte().unwrap(), command);
                assert_eq!(reader.string().unwrap(), b"fixture passphrase");
                reader.finish().unwrap();
                reply(&mut peer, response).await;
            }
            let packet = receive(&mut peer).await;
            let mut reader = Reader::new(&packet);
            assert_eq!(reader.byte().unwrap(), 18);
            assert_eq!(
                reader.string().unwrap(),
                key.public_key().to_bytes().unwrap()
            );
            reader.finish().unwrap();
            reply(&mut peer, &[5]).await;
            assert_eq!(receive(&mut peer).await, [19]);
            reply(&mut peer, &[6, 0]).await;
            assert_eq!(receive(&mut peer).await, [19]);
            reply(&mut peer, &[6]).await;
        };
        let run = async {
            let mut client = Client::new(stream);
            client.add(&key, &[]).await.unwrap();
            client.add(&key, &constraints).await.unwrap();
            client
                .add_token("fixture token", b"fixture pin", &[])
                .await
                .unwrap();
            assert!(matches!(
                client
                    .add_token("fixture token", b"fixture pin", &constraints)
                    .await,
                Err(Error::Refused)
            ));
            assert!(matches!(
                client.remove_token("fixture token", b"fixture pin").await,
                Err(Error::Refused)
            ));
            client.lock(b"fixture passphrase").await.unwrap();
            assert!(matches!(
                client.unlock(b"fixture passphrase").await,
                Err(Error::Refused)
            ));
            client.unlock(b"fixture passphrase").await.unwrap();
            assert!(matches!(
                client.remove(key.public_key()).await,
                Err(Error::Refused)
            ));
            assert!(matches!(client.remove_all().await, Err(Error::Protocol)));
            client.remove_all().await.unwrap();
        };
        tokio::join!(serve, run);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn agent_extensions_distinguish_unsupported_failed_and_typed_responses() {
    timeout(TEST_TIMEOUT, async {
        const NAME: &[u8] = b"fixture@example.test";
        const DATA: &[u8] = b"\x00\x00\x00\x02\x00\xff";
        let (mut peer, stream) = duplex(256);
        let serve = async {
            for code in [6, 5, 28, 29] {
                let packet = receive(&mut peer).await;
                let mut reader = Reader::new(&packet);
                assert_eq!(reader.byte().unwrap(), 27);
                assert_eq!(reader.string().unwrap(), NAME);
                assert_eq!(reader.remaining(), DATA);
                let mut response = vec![code];
                if code == 29 {
                    field(&mut response, b"unexpected@example.test");
                }
                reply(&mut peer, &response).await;
            }
            for (name, response) in [
                (NAME, vec![6, 0, 0, 0, 1, 42]),
                (NAME, {
                    let mut response = vec![29];
                    field(&mut response, NAME);
                    response.extend([0, 255]);
                    response
                }),
                (NAME, vec![5]),
                (NAME, vec![6]),
                (b"query", vec![5]),
                (b"query", {
                    let mut packet = vec![29];
                    field(&mut packet, b"query");
                    field(&mut packet, NAME);
                    field(&mut packet, b"query");
                    packet
                }),
            ] {
                let packet = receive(&mut peer).await;
                let mut reader = Reader::new(&packet);
                assert_eq!(reader.byte().unwrap(), 27);
                assert_eq!(reader.string().unwrap(), name);
                reader.finish().unwrap();
                reply(&mut peer, &response).await;
            }
        };
        let run = async {
            let mut client = Client::new(stream);
            assert!(matches!(
                client.lock(&vec![1; 256 * 1024]).await,
                Err(Error::Protocol)
            ));
            assert!(client.extension(NAME, DATA).await.unwrap().is_empty());
            assert!(matches!(
                client.extension(NAME, DATA).await,
                Err(Error::ExtensionUnsupported)
            ));
            assert!(matches!(
                client.extension(NAME, DATA).await,
                Err(Error::ExtensionFailed)
            ));
            assert!(matches!(
                client.extension(NAME, DATA).await,
                Err(Error::Protocol)
            ));
            assert_eq!(&client.extension(NAME, &[]).await.unwrap()[..], &[42]);
            assert_eq!(&client.extension(NAME, &[]).await.unwrap()[..], &[0, 255]);
            assert!(matches!(
                client.extension(NAME, &[]).await,
                Err(Error::ExtensionUnsupported)
            ));
            assert!(client.extension(NAME, &[]).await.unwrap().is_empty());
            assert!(client.extensions().await.unwrap().is_none());
            assert_eq!(
                client.extensions().await.unwrap().unwrap(),
                ["fixture@example.test", "query"]
            );
        };
        tokio::join!(serve, run);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lists_keys_and_certificates_and_uses_the_exact_agent_identity_for_signing() {
    timeout(TEST_TIMEOUT, async {
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let certificate = user_certificate(&key);
        let rsa_key = fake_rsa_public();
        let rsa_blob = rsa_key.to_bytes().unwrap();
        let key_blob = key.public_key().to_bytes().unwrap();
        let cert_blob = certificate.to_bytes().unwrap();
        let (mut peer, stream) = duplex(384);
        let agent = async {
            assert_eq!(receive(&mut peer).await, [11]);
            let mut list = vec![12, 0, 0, 0, 3];
            for (blob, comment) in [
                (&key_blob, "local key"),
                (&cert_blob, "本機憑證"),
                (&rsa_blob, "rsa fixture"),
            ] {
                field(&mut list, blob);
                field(&mut list, comment.as_bytes());
            }
            reply(&mut peer, &list).await;
            for blob in [&key_blob, &cert_blob] {
                inspect_sign_request(&receive(&mut peer).await, blob, 0);
                let signature: Signature = key.try_sign(DATA).unwrap();
                let mut packet = vec![14];
                signature.encode_prefixed(&mut packet).unwrap();
                reply(&mut peer, &packet).await;
            }
            for (flags, hash) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
                inspect_sign_request(&receive(&mut peer).await, &rsa_blob, flags);
                let signature =
                    Signature::new(Algorithm::Rsa { hash: Some(hash) }, vec![0x5a; 256]).unwrap();
                let mut packet = vec![14];
                signature.encode_prefixed(&mut packet).unwrap();
                reply(&mut peer, &packet).await;
            }
        };
        let client = async {
            let mut client = Client::new(stream).boxed();
            let available = client.identities().await.unwrap();
            assert_eq!(available.len(), 3);
            assert_eq!(
                available[0],
                Identity::new(key.public_key().clone(), "local key")
            );
            assert_eq!(available[1], Identity::new(certificate.clone(), "本機憑證"));
            for identity in &available[..2] {
                let signature = client
                    .sign(identity.credential(), None, DATA)
                    .await
                    .unwrap();
                Verifier::verify(identity.key_data(), DATA, &signature).unwrap();
            }
            let rsa = Credential::from(rsa_key.clone());
            for hash in [HashAlg::Sha256, HashAlg::Sha512] {
                let signature = client.sign(&rsa, Some(hash), DATA).await.unwrap();
                assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            }
        };
        tokio::join!(agent, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_oversized_frames_at_the_length_prefix_and_refuses_to_reuse_the_stream() {
    timeout(TEST_TIMEOUT, async {
        let (mut peer, stream) = duplex(64);
        let mut client = Client::new(stream);
        let agent = async {
            assert_eq!(receive(&mut peer).await, [11]);
            peer.write_u32(256 * 1024 + 1).await.unwrap();
        };
        let request = async {
            assert!(matches!(client.identities().await, Err(Error::Protocol)));
            assert!(matches!(client.identities().await, Err(Error::Io(error)) if error.kind() == ErrorKind::BrokenPipe));
        };
        tokio::join!(agent, request);
    }).await.unwrap();
}

#[tokio::test]
async fn malformed_signatures_and_identity_counts_are_rejected_and_agent_refusal_is_typed() {
    timeout(TEST_TIMEOUT, async {
        let key = fake_rsa_public();
        let blob = key.to_bytes().unwrap();
        let (mut peer, stream) = duplex(128);
        let agent = async {
            assert_eq!(receive(&mut peer).await, [11]);
            reply(&mut peer, &[12, 0xff, 0xff, 0xff, 0xff]).await;
            for response in [[5].as_slice(), &[14, 0, 0, 0, 1, 0]] {
                inspect_sign_request(&receive(&mut peer).await, &blob, 2);
                reply(&mut peer, response).await;
            }
            inspect_sign_request(&receive(&mut peer).await, &blob, 2);
            let mut wrong = vec![14];
            Signature::new(
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                vec![0x5a; 256],
            )
            .unwrap()
            .encode_prefixed(&mut wrong)
            .unwrap();
            reply(&mut peer, &wrong).await;
            for response in [&[6][..], wrong.as_slice()] {
                inspect_sign_request(&receive(&mut peer).await, &blob, 2);
                reply(&mut peer, response).await;
            }
        };
        let exchange = async {
            let mut client = Client::new(stream);
            assert!(matches!(client.identities().await, Err(Error::Protocol)));
            let identity = Identity::new(key.clone(), "");
            assert!(matches!(
                client
                    .sign(identity.credential(), Some(HashAlg::Sha256), DATA)
                    .await,
                Err(Error::Refused)
            ));
            // An empty signature, the wrong RSA hash, a bare success and the
            // wrong hash again are all rejected as protocol errors.
            for _ in 0..4 {
                assert!(matches!(
                    client
                        .sign(identity.credential(), Some(HashAlg::Sha256), DATA)
                        .await,
                    Err(Error::Protocol)
                ));
            }
        };
        tokio::join!(agent, exchange);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_agent_io_never_reuses_an_old_reply_for_a_new_request() {
    timeout(TEST_TIMEOUT, async {
        let (mut peer, stream) = duplex(128);
        let mut client = Client::new(stream);
        {
            let request = client.identities();
            tokio::pin!(request);
            tokio::select! {
                result = &mut request => panic!("unexpected agent reply: {result:?}"),
                packet = receive(&mut peer) => assert_eq!(packet, [11]),
            }
        }
        reply(&mut peer, &[12, 0, 0, 0, 0]).await;
        assert!(matches!(client.identities().await, Err(Error::Io(error)) if error.kind() == ErrorKind::BrokenPipe));
    }).await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn agent_uses_a_private_windows_named_pipe() {
    use tokio::net::windows::named_pipe::ServerOptions;

    timeout(TEST_TIMEOUT, async {
        let fixture = tempfile::tempdir().unwrap();
        let pipe = format!(r"\\.\pipe\thirtyssh-agent-{}-{}", std::process::id(), fixture.path().file_name().unwrap().to_string_lossy());
        let mut peer = ServerOptions::new().first_pipe_instance(true).create(&pipe).unwrap();
        let mut client = Client::named_pipe(&pipe).await.unwrap();
        peer.connect().await.unwrap();
        let exchange = async {
            assert_eq!(receive(&mut peer).await, [11]);
            reply(&mut peer, &[12, 0, 0, 0, 0]).await;
            assert_eq!(receive(&mut peer).await, [11]);
            peer.disconnect().unwrap();
        };
        let result = async {
            assert!(client.identities().await.unwrap().is_empty());
            assert!(matches!(client.identities().await, Err(Error::Io(_))));
        };
        tokio::join!(exchange, result);
        drop(peer);
        assert!(matches!(Client::named_pipe(&pipe).await, Err(Error::Io(error)) if error.kind() == ErrorKind::NotFound));
        let _read_only = ServerOptions::new().access_outbound(false).create(&pipe).unwrap();
        assert!(matches!(Client::named_pipe(&pipe).await, Err(Error::Io(error)) if error.kind() == ErrorKind::PermissionDenied));
    }).await.unwrap();
}

#[cfg(windows)]
#[tokio::test(start_paused = true)]
async fn busy_windows_named_pipe_is_retried_until_a_deadline() {
    use tokio::{net::windows::named_pipe::ServerOptions, time::Instant};

    let fixture = tempfile::tempdir().unwrap();
    let pipe = format!(
        r"\\.\pipe\thirtyssh-agent-busy-{}-{}",
        std::process::id(),
        fixture.path().file_name().unwrap().to_string_lossy()
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .create(&pipe)
        .unwrap();
    let first = Client::named_pipe(&pipe).await.unwrap();
    server.connect().await.unwrap();

    let start = Instant::now();
    assert!(matches!(
        Client::named_pipe(&pipe).await,
        Err(Error::Io(error)) if error.kind() == ErrorKind::TimedOut
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(2));

    // The pipe becoming free within the deadline lets the connection through.
    let release = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(first);
        server.disconnect().unwrap();
        server.connect().await.unwrap();
    };
    let start = Instant::now();
    let (second, ()) = tokio::join!(Client::named_pipe(&pipe), release);
    second.unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh-agent, ssh-add, and ssh-keygen and an unprivileged user"]
async fn openssh_agent_lists_and_signs_with_temporary_identities() {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        process::Stdio,
    };
    use thirtyssh::keys::ssh_key::LineEnding;
    use tokio::{process::Command, time::sleep};

    const CHILD_MODE: &str = "THIRTYSSH_TEST_AGENT_ENV";
    const TEST_NAME: &str = "openssh_agent_lists_and_signs_with_temporary_identities";

    if let Ok(mode) = std::env::var(CHILD_MODE) {
        let result = Client::from_env().await;
        match mode.as_str() {
            "connect" => assert_eq!(result.unwrap().identities().await.unwrap().len(), 3),
            "missing-socket" => assert!(matches!(result, Err(Error::NotRunning))),
            "missing-variable" => assert!(matches!(result, Err(Error::NotRunning))),
            _ => panic!("invalid agent test mode"),
        }
        return;
    }

    timeout(TEST_TIMEOUT, async {
        let fixture = tempfile::tempdir().unwrap();
        let socket = fixture.path().join("agent.sock");
        let path = fixture.path().join("id_ed25519");
        let rsa_path = fixture.path().join("id_rsa");
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let certificate = user_certificate(&key);
        fs::write(fixture.path().join("id_ed25519-cert.pub"), certificate.to_openssh().unwrap()).unwrap();
        let contents = key.to_openssh(LineEnding::LF).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        let generated = Command::new("ssh-keygen").args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
            .arg(&rsa_path).kill_on_drop(true).output().await.unwrap();
        assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
        let rsa_public = PublicKey::from_openssh(&fs::read_to_string(rsa_path.with_extension("pub")).unwrap()).unwrap();
        let approve = fixture.path().join("agent-approve");
        let askpass = fixture.path().join("agent-askpass");
        fs::write(&askpass, b"#!/bin/sh\ntest -f \"$THIRTYSSH_AGENT_APPROVED_FILE\"\n").unwrap();
        fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).unwrap();
        let mut agent = Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("THIRTYSSH_AGENT_APPROVED_FILE", &approve)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut client = loop {
            match Client::unix(&socket).await {
                Ok(client) => break client,
                Err(Error::Io(error))
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) =>
                {
                    assert!(agent.try_wait().unwrap().is_none());
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("agent socket failed: {error}"),
            }
        };
        assert!(client.identities().await.unwrap().is_empty());
        let rsa_key = PrivateKeyReader::new().file(&rsa_path).unwrap();
        client.add(&rsa_key, &[]).await.unwrap();
        let added = Command::new("ssh-add")
            .arg(&path)
            .env("SSH_AUTH_SOCK", &socket)
            .output()
            .await
            .unwrap();
        assert!(
            added.status.success(),
            "{}",
            String::from_utf8_lossy(&added.stderr)
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(rsa_path).unwrap();
        let identities = client.identities().await.unwrap();
        assert_eq!(identities.len(), 3);
        assert!(
            identities
                .iter()
                .any(|id| id.certificate() == Some(&certificate))
        );
        for identity in &identities {
            let public = identity.key_data();
            if public.rsa().is_some() {
                assert_eq!(public, rsa_public.key_data());
                for hash in [HashAlg::Sha256, HashAlg::Sha512] {
                    let signature = client.sign(identity.credential(), Some(hash), DATA).await.unwrap();
                    assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
                    assert_eq!(signature.as_bytes().len(), 256);
                }
            } else {
                assert_eq!(public, key.public_key().key_data());
                let signature = client.sign(identity.credential(), None, DATA).await.unwrap();
                Verifier::verify(key.public_key(), DATA, &signature).unwrap();
            }
        }
        let missing = fixture.path().join("missing.sock");
        for (mode, path) in [("connect", Some(&socket)), ("missing-socket", Some(&missing)), ("missing-variable", None)] {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child.args(["--exact", TEST_NAME, "--ignored"]).env(CHILD_MODE, mode).env_remove("SSH_AUTH_SOCK");
            if let Some(path) = path {
                child.env("SSH_AUTH_SOCK", path);
            }
            let output = child.kill_on_drop(true).output().await.unwrap();
            assert!(output.status.success(), "{mode}: {}", String::from_utf8_lossy(&output.stdout));
        }
        exercise_openssh_management(&mut client, &rsa_public, &approve).await;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(Client::unix(&socket).await, Err(Error::Io(error)) if error.kind() == ErrorKind::PermissionDenied));
        agent.kill().await.unwrap();
        assert!(matches!(
            client.identities().await,
            Err(Error::Io(_))
        ));
    })
    .await
    .unwrap();
}

#[cfg(unix)]
async fn exercise_openssh_management(
    client: &mut Client<tokio::net::UnixStream>,
    rsa_key: &PublicKey,
    approve: &std::path::Path,
) {
    assert!(matches!(
        client.extension(b"unknown-fixture@example.test", b"").await,
        Err(Error::ExtensionUnsupported)
    ));
    let _ = client.extensions().await.unwrap();
    client.remove(rsa_key).await.unwrap();
    assert_eq!(client.identities().await.unwrap().len(), 2);
    assert!(matches!(client.remove(rsa_key).await, Err(Error::Refused)));
    client.lock(b"fixture passphrase").await.unwrap();
    assert!(client.identities().await.unwrap().is_empty());
    assert!(matches!(
        client.unlock(b"incorrect").await,
        Err(Error::Refused)
    ));
    client.unlock(b"fixture passphrase").await.unwrap();
    assert_eq!(client.identities().await.unwrap().len(), 2);

    let temporary = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    client
        .add(&temporary, &[Constraint::Lifetime { seconds: 1 }])
        .await
        .unwrap();
    assert_eq!(client.identities().await.unwrap().len(), 3);
    while client.identities().await.unwrap().len() == 3 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(client.identities().await.unwrap().len(), 2);

    let controlled = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    let identity = Identity::new(controlled.public_key().clone(), "");
    client
        .add(&controlled, &[Constraint::ConfirmEachUse])
        .await
        .unwrap();
    assert!(matches!(
        client.sign(identity.credential(), None, DATA).await,
        Err(Error::Refused)
    ));
    std::fs::write(approve, b"fixture").unwrap();
    let signature = client
        .sign(identity.credential(), None, DATA)
        .await
        .unwrap();
    Verifier::verify(controlled.public_key(), DATA, &signature).unwrap();
    client.remove_all().await.unwrap();
    assert!(client.identities().await.unwrap().is_empty());
}

#[tokio::test]
async fn identities_the_library_cannot_decode_are_left_out_of_the_list() {
    timeout(TEST_TIMEOUT, async {
        let key = fake_rsa_public();
        let (mut peer, stream) = duplex(1024);
        let agent = async {
            assert_eq!(receive(&mut peer).await, [11]);
            let mut damaged = Vec::new();
            field(&mut damaged, b"ssh-ed25519");
            field(&mut damaged, b"short");
            let mut answer = vec![12, 0, 0, 0, 2];
            field(&mut answer, &damaged);
            field(&mut answer, b"damaged key");
            field(&mut answer, &key.to_bytes().unwrap());
            // A comment in a legacy code page, as Pageant can hold.
            field(&mut answer, b"cl\xe9");
            reply(&mut peer, &answer).await;
        };
        let list = async {
            let identities = Client::new(stream).identities().await.unwrap();
            assert_eq!(identities.len(), 1);
            assert_eq!(identities[0].credential(), &key.clone().into());
            assert_eq!(identities[0].comment(), "cl\u{fffd}");
        };
        tokio::join!(agent, list);
    })
    .await
    .unwrap();
}
