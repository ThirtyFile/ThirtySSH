use std::{io, time::Duration};
use thirtyssh::keys::{
    Algorithm, PrivateKey, PublicKey,
    agent::{
        Client, Constraint, Error, Identity,
        server::{self, Operation, Policy},
    },
    signature::Verifier,
    system_rng,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const DATA: &[u8] = b"agent server fixture";
const DEADLINE: Duration = Duration::from_secs(8);

#[cfg(windows)]
#[tokio::test]
async fn agent_server_serves_a_private_windows_named_pipe() {
    use tokio::net::windows::named_pipe::ServerOptions;

    timeout(DEADLINE, async {
        let fixture = tempfile::tempdir().unwrap();
        let pipe = format!(
            r"\\.\pipe\thirtyssh-server-{}-{}",
            std::process::id(),
            fixture.path().file_name().unwrap().to_string_lossy()
        );
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe)
            .unwrap();
        let mut admin = Client::named_pipe(&pipe).await.unwrap();
        first.connect().await.unwrap();
        let second = ServerOptions::new().create(&pipe).unwrap();
        let mut signer = Client::named_pipe(&pipe).await.unwrap();
        second.connect().await.unwrap();
        let (input, mut listener) = mpsc::channel(2);
        let service = tokio::spawn(server::run(async move || listener.recv().await, ()));
        input.send(Ok(first)).await.unwrap();
        input.send(Ok(second)).await.unwrap();
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        admin.add(&key, &[]).await.unwrap();
        let identity = signer.identities().await.unwrap().pop().unwrap();
        let signature = signer
            .sign(identity.credential(), None, DATA)
            .await
            .unwrap();
        Verifier::verify(key.public_key(), DATA, &signature).unwrap();
        admin.remove(key.public_key()).await.unwrap();
        assert!(signer.identities().await.unwrap().is_empty());
        drop((admin, signer, input));
        service.await.unwrap();
    })
    .await
    .unwrap();
}

struct Fixture {
    input: mpsc::Sender<io::Result<DuplexStream>>,
    running: JoinHandle<()>,
}

impl Fixture {
    fn new(policy: impl Policy) -> Self {
        let (input, mut receiver) = mpsc::channel(4);
        let running = tokio::spawn(server::run(async move || receiver.recv().await, policy));
        Self { input, running }
    }

    async fn stream(&self) -> DuplexStream {
        let (peer, client) = duplex(256);
        self.input.send(Ok(peer)).await.unwrap();
        client
    }

    async fn client(&self) -> Client<DuplexStream> {
        Client::new(self.stream().await)
    }

    async fn finish(self) {
        drop(self.input);
        self.running.await.unwrap();
    }
}

struct Approval {
    identity: PublicKey,
    decide: oneshot::Sender<bool>,
}

#[derive(Clone)]
struct Approvals {
    approvals: mpsc::Sender<Approval>,
}

impl Policy for Approvals {
    async fn approve_signature(&mut self, key: &PublicKey) -> bool {
        let (decide, answer) = oneshot::channel();
        let request = Approval {
            identity: key.clone(),
            decide,
        };
        self.approvals.send(request).await.is_ok() && answer.await.unwrap_or(false)
    }

    async fn permits(&self, operation: Operation) -> bool {
        operation != Operation::RemoveAllIdentities
    }
}

#[tokio::test]
async fn agent_server_shares_keys_and_strictly_checks_management_packets() {
    timeout(DEADLINE, async {
        let fixture = Fixture::new(());
        let mut first = fixture.client().await;
        let mut second = fixture.client().await;
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        first.add(&key, &[]).await.unwrap();
        let listed = second.identities().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key_data(), key.public_key().key_data());
        let signature = second
            .sign(listed[0].credential(), None, DATA)
            .await
            .unwrap();
        Verifier::verify(key.public_key(), DATA, &signature).unwrap();
        first
            .add(&key, &[Constraint::ConfirmEachUse])
            .await
            .unwrap();
        assert!(matches!(
            second.sign(listed[0].credential(), None, DATA).await,
            Err(Error::Refused)
        ));
        first.add(&key, &[]).await.unwrap();
        assert_eq!(first.extensions().await.unwrap().unwrap(), ["query"]);

        let mut raw = fixture.stream().await;
        raw.write_all(&[0, 0, 0, 2, 19, 0]).await.unwrap();
        let mut reply = [0; 5];
        raw.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0, 0, 0, 1, 5]);
        assert_eq!(second.identities().await.unwrap().len(), 1);
        let mut oversized = fixture.stream().await;
        oversized.write_u32(256 * 1024 + 1).await.unwrap();
        assert_eq!(oversized.read(&mut reply).await.unwrap(), 0);
        let mut zero = fixture.stream().await;
        zero.write_u32(0).await.unwrap();
        assert_eq!(zero.read(&mut reply).await.unwrap(), 0);

        assert!(matches!(first.lock(b"").await, Err(Error::Refused)));
        first.lock(b"fixture password").await.unwrap();
        assert!(second.identities().await.unwrap().is_empty());
        assert!(matches!(
            second.sign(listed[0].credential(), None, DATA).await,
            Err(Error::Refused)
        ));
        let attempt = std::time::Instant::now();
        assert!(matches!(second.unlock(b"wrong").await, Err(Error::Refused)));
        assert!(
            attempt.elapsed() >= Duration::from_millis(100),
            "a failed unlock must be delayed"
        );
        second.unlock(b"fixture password").await.unwrap();
        assert_eq!(first.identities().await.unwrap().len(), 1);
        second.remove_all().await.unwrap();
        assert!(first.identities().await.unwrap().is_empty());
        drop((first, second, raw, oversized, zero));
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn input_half_close_drains_final_queued_replies_in_order() {
    timeout(DEADLINE, async {
        let fixture = Fixture::new(());
        let mut stream = fixture.stream().await;
        for code in [11, 19, 11] {
            stream.write_all(&[0, 0, 0, 1, code]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        for expected in [&[12, 0, 0, 0, 0][..], &[6], &[12, 0, 0, 0, 0]] {
            let size = stream.read_u32().await.unwrap() as usize;
            let mut response = vec![0; size];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, expected);
        }
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_pending_approval_can_be_denied_or_invalidated_by_replacement_lock_and_expiry() {
    timeout(DEADLINE, async {
        let (send, mut approvals) = mpsc::channel(1);
        let fixture = Fixture::new(Approvals { approvals: send });
        let mut signing = fixture.client().await;
        let mut management = fixture.client().await;
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let identity = Identity::new(key.public_key().clone(), "");
        let persistent = [Constraint::ConfirmEachUse];
        management.add(&key, &persistent).await.unwrap();

        for action in ["deny", "remove", "replace", "lock", "allow", "expire"] {
            if action == "expire" {
                management
                    .add(
                        &key,
                        &[
                            Constraint::ConfirmEachUse,
                            Constraint::Lifetime { seconds: 1 },
                        ],
                    )
                    .await
                    .unwrap();
            }
            let interfere = async {
                let approval = approvals.recv().await.unwrap();
                assert_eq!(approval.identity.key_data(), key.public_key().key_data());
                match action {
                    "remove" => management.remove(key.public_key()).await.unwrap(),
                    "replace" => management.add(&key, &persistent).await.unwrap(),
                    "lock" => {
                        management.lock(b"fixture password").await.unwrap();
                        management.unlock(b"fixture password").await.unwrap();
                    }
                    "expire" => tokio::time::advance(Duration::from_secs(2)).await,
                    _ => (),
                }
                approval.decide.send(action != "deny").unwrap();
            };
            let (result, ()) =
                tokio::join!(signing.sign(identity.credential(), None, DATA), interfere);
            if action == "allow" {
                Verifier::verify(key.public_key(), DATA, &result.unwrap()).unwrap();
                assert!(matches!(management.remove_all().await, Err(Error::Refused)));
                assert_eq!(signing.identities().await.unwrap().len(), 1);
            } else {
                assert!(matches!(result, Err(Error::Refused)), "{action}");
            }
            if action == "remove" {
                management.add(&key, &persistent).await.unwrap();
            }
        }
        assert!(management.identities().await.unwrap().is_empty());
        drop((signing, management));
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn agent_server_cancels_confirmations_on_disconnect_and_listener_shutdown() {
    timeout(DEADLINE, async {
        let (send, mut approvals) = mpsc::channel(1);
        let fixture = Fixture::new(Approvals { approvals: send });
        let mut management = fixture.client().await;
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        management
            .add(&key, &[Constraint::ConfirmEachUse])
            .await
            .unwrap();
        let identity = Identity::new(key.public_key().clone(), "");

        let mut signing = fixture.client().await;
        let signing_identity = identity.clone();
        let signer = tokio::spawn(async move {
            signing
                .sign(signing_identity.credential(), None, DATA)
                .await
        });
        let mut approval = approvals.recv().await.unwrap();
        signer.abort();
        assert!(signer.await.unwrap_err().is_cancelled());
        approval.decide.closed().await;
        assert_eq!(management.identities().await.unwrap().len(), 1);

        let mut signing = fixture.client().await;
        let signer =
            tokio::spawn(async move { signing.sign(identity.credential(), None, DATA).await });
        let mut approval = approvals.recv().await.unwrap();
        fixture.running.abort();
        assert!(fixture.running.await.unwrap_err().is_cancelled());
        approval.decide.closed().await;
        assert!(matches!(signer.await.unwrap(), Err(Error::Io(_))));
        assert!(matches!(management.identities().await, Err(Error::Io(_))));
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh-add and ssh-keygen in PATH"]
async fn openssh_tools_add_sign_and_remove_with_the_thirtyssh_agent() {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
    };
    use thirtyssh::keys::ssh_key::{LineEnding, SshSig};
    use tokio::{net::UnixListener, process::Command};

    timeout(DEADLINE, async {
        let fixture = tempfile::tempdir().unwrap();
        let socket = fixture.path().join("agent.sock");
        let key_path = fixture.path().join("id_ed25519");
        let public_path = key_path.with_extension("pub");
        let message_path = fixture.path().join("message");
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let contents = key.to_openssh(LineEnding::LF).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        fs::write(&public_path, key.public_key().to_openssh().unwrap()).unwrap();
        fs::write(&message_path, DATA).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let service = tokio::spawn(server::run(
            async move || Some(listener.accept().await.map(|(stream, _)| stream)),
            (),
        ));
        let result = Command::new("ssh-add")
            .arg(&key_path)
            .env("SSH_AUTH_SOCK", &socket)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::remove_file(key_path).unwrap();
        let result = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&public_path)
            .args(["-n", "fixture"])
            .arg(&message_path)
            .env("SSH_AUTH_SOCK", &socket)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let signature =
            SshSig::from_pem(fs::read(message_path.with_extension("sig")).unwrap()).unwrap();
        key.public_key()
            .verify("fixture", DATA, &signature)
            .unwrap();
        #[cfg(feature = "rsa")]
        check_rsa(&socket, fixture.path()).await;
        let result = Command::new("ssh-add")
            .arg("-D")
            .env("SSH_AUTH_SOCK", &socket)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            Client::unix(&socket)
                .await
                .unwrap()
                .identities()
                .await
                .unwrap()
                .is_empty()
        );
        service.abort();
        assert!(service.await.unwrap_err().is_cancelled());
    })
    .await
    .unwrap();
}

#[cfg(all(unix, feature = "rsa"))]
async fn check_rsa(socket: &std::path::Path, directory: &std::path::Path) {
    use sha2::{Sha256, Sha512};
    use thirtyssh::keys::{HashAlg, ssh_encoding::Uint};
    use tokio::process::Command;

    let rsa_path = directory.join("id_rsa");
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
        .arg(&rsa_path)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let added = Command::new("ssh-add")
        .arg(&rsa_path)
        .env("SSH_AUTH_SOCK", socket)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    std::fs::remove_file(rsa_path).unwrap();
    let mut client = Client::unix(socket).await.unwrap();
    let identity = client
        .identities()
        .await
        .unwrap()
        .into_iter()
        .find(|id| id.key_data().rsa().is_some())
        .unwrap();
    let key = identity.key_data().rsa().unwrap();
    let public = rsa::PublicKey::new(
        Uint::try_from(key.n()).unwrap(),
        Uint::try_from(key.e()).unwrap(),
    )
    .unwrap();
    for hash in [HashAlg::Sha256, HashAlg::Sha512] {
        let signature = client
            .sign(identity.credential(), Some(hash), DATA)
            .await
            .unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
        let signature = rsa::pkcs1v15::Signature::try_from(signature.as_bytes()).unwrap();
        match hash {
            HashAlg::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public.clone())
                .verify(DATA, &signature)
                .unwrap(),
            HashAlg::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public.clone())
                .verify(DATA, &signature)
                .unwrap(),
            _ => unreachable!(),
        }
    }
    assert!(matches!(
        client.sign(identity.credential(), None, DATA).await,
        Err(Error::Refused)
    ));
}
