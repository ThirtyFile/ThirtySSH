//! Optional interoperability against a separately started, loopback sshd.
use data_encoding::BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{env, fs, io, path::PathBuf, sync::Arc, time::Duration};
#[cfg(feature = "rsa")]
use thirtyssh::keys::HashAlg;
use thirtyssh::{
    Pty,
    algorithms::{Cipher, DirectionPreferences, Kex, Mac, PacketPreferences},
    auth::{SignRequest, Signer},
    channel::Message,
    client,
    exec::{self, Exit},
    keys::{Algorithm, Certificate, Credential, PrivateKeyReader, PublicKey, public::from_ed25519},
    known_hosts::{KnownHosts, Status},
    pty::TerminalSize,
    session::{self, PtyRequest, Request},
    transport::PeerDisconnect,
    wire::{Reader, Writer},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::timeout,
};

// RFC 8032 §7.1 public test vector. Use only on the disposable test daemon.
const IDENTITY_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

#[path = "fixtures/pinned.rs"]
mod pinned;
use pinned::Pinned;

struct External(Ed25519KeyPair);

impl Signer for External {
    async fn auth_sign(&mut self, request: SignRequest<'_>) -> io::Result<Vec<u8>> {
        assert_eq!(request.algorithm, "ssh-ed25519");
        let signature = self.0.sign(request.data);
        let mut blob = vec![0; 8 + request.algorithm.len() + signature.as_ref().len()];
        let mut writer = Writer::new(&mut blob);
        writer.string(request.algorithm.as_bytes()).unwrap();
        writer.string(signature.as_ref()).unwrap();
        Ok(blob)
    }
}

fn endpoint() -> (u16, String) {
    let port: u16 = env::var("THIRTYSSH_TEST_SSHD_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let user = env::var("THIRTYSSH_TEST_SSHD_USER").unwrap();
    (port, user)
}

async fn connect_unauthenticated() -> (client::Client<tokio::net::TcpStream, Pinned>, String) {
    connect_unauthenticated_with_config(client::Config::default()).await
}

async fn connect_unauthenticated_with_config(
    config: client::Config,
) -> (client::Client<tokio::net::TcpStream, Pinned>, String) {
    let (port, user) = endpoint();
    let encoded = env::var("THIRTYSSH_TEST_SSHD_HOST_KEY").unwrap();
    let blob = BASE64.decode(encoded.as_bytes()).unwrap();
    let mut key = Reader::new(&blob);
    assert_eq!(key.string().unwrap(), b"ssh-ed25519");
    let pinned = Pinned(key.string().unwrap().try_into().unwrap());
    key.finish().unwrap();

    let client = client::connect(Arc::new(config), ("127.0.0.1", port), pinned)
        .await
        .unwrap();
    (client, user)
}

async fn connect_fixture() -> session::Session {
    let (client, user) = connect_unauthenticated().await;
    authenticate_fixture(client, &user).await
}

async fn authenticate_fixture(
    mut client: client::Client<tokio::net::TcpStream, impl client::Handler>,
    user: &str,
) -> session::Session {
    let mut signer = External(Ed25519KeyPair::from_seed_unchecked(&IDENTITY_SEED).unwrap());
    let identity = signer.0.public_key().as_ref().try_into().unwrap();
    assert!(
        client
            .authenticate_with(user, &from_ed25519(&identity).into(), None, &mut signer)
            .await
            .unwrap()
            .is_accepted()
    );
    client.start().unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture keys"]
async fn thirtyssh_uses_all_nist_ecdh_curves_with_openssh_server() {
    authenticate_and_rekey(&[Kex::EcdhNistP256, Kex::EcdhNistP384, Kex::EcdhNistP521]).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture keys"]
async fn thirtyssh_uses_fixed_dh_with_openssh_server() {
    authenticate_and_rekey(&[
        Kex::DhGroup14Sha256,
        Kex::DhGroup16Sha512,
        Kex::DhGroup18Sha512,
    ])
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture keys"]
async fn thirtyssh_uses_dh_group_exchange_with_openssh_server() {
    authenticate_and_rekey(&[Kex::DhGexSha256]).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon configured for SHA-1 DH KEX"]
async fn thirtyssh_uses_sha1_dh_with_openssh_server() {
    authenticate_and_rekey(&[Kex::DhGroup1Sha1, Kex::DhGroup14Sha1, Kex::DhGexSha1]).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon with mlkem768x25519-sha256"]
async fn thirtyssh_uses_hybrid_mlkem_x25519_with_openssh_server() {
    // OpenSSH gained this exchange in 9.9. The fixture reports what its
    // daemon offers, so an older daemon skips the test.
    const NAME: &str = "mlkem768x25519-sha256";
    let offered = env::var("THIRTYSSH_TEST_SSHD_KEX").unwrap();
    if !offered.split(',').any(|name| name == NAME) {
        eprintln!("skipped: this sshd does not offer {NAME}");
        return;
    }
    authenticate_and_rekey(&[Kex::MlKem768X25519Sha256]).await;
}

#[tokio::test]
#[ignore = "requires the isolated loopback OpenSSH daemon configured for CBC and HMAC-SHA1"]
async fn thirtyssh_uses_explicit_legacy_packets_with_openssh_server() {
    timeout(Duration::from_secs(30), async {
        for cipher in [
            Cipher::Aes128Cbc,
            Cipher::Aes192Cbc,
            Cipher::Aes256Cbc,
            #[cfg(feature = "des")]
            Cipher::TripleDesCbc,
        ] {
            for mac in [Mac::HmacSha1, Mac::HmacSha1Etm] {
                let direction = DirectionPreferences {
                    ciphers: vec![cipher],
                    macs: vec![mac],
                };
                let mut config = client::Config::default();
                config.preferred.packet = PacketPreferences {
                    client_to_server: direction.clone(),
                    server_to_client: direction,
                };
                let (client, user) = connect_unauthenticated_with_config(config).await;
                let session = authenticate_fixture(client, &user).await;
                let handle = session.handle();
                handle.ping().await.unwrap();
                handle.rekey().await.unwrap();
                handle.ping().await.unwrap();
                session.disconnect().await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

async fn authenticate_and_rekey(methods: &[Kex]) {
    timeout(Duration::from_secs(30), async {
        for &method in methods {
            let mut config = client::Config::default();
            config.preferred.kex = vec![method, Kex::StrictClient, Kex::ExtInfoClient];
            let (client, user) = connect_unauthenticated_with_config(config).await;
            let session = authenticate_fixture(client, &user).await;
            let handle = session.handle();
            handle.ping().await.unwrap();
            handle.rekey().await.unwrap();
            handle.ping().await.unwrap();
            session.disconnect().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture keys"]
async fn thirtyssh_verifies_rsa_and_ecdsa_hosts_against_openssh_server() {
    struct PinnedHost(KnownHosts, u16);
    impl session::Handler for PinnedHost {}
    impl client::Handler for PinnedHost {
        async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
            let Credential::Key(key) = host else {
                return Ok(false);
            };
            Ok(self.0.check_public_key("thirtyssh-test", self.1, key)? == Status::Trusted)
        }
    }

    timeout(Duration::from_secs(20), async {
        let directory = PathBuf::from(env::var_os("THIRTYSSH_TEST_SSHD_HOST_KEYS").unwrap());
        let (port, user) = endpoint();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("known_hosts");
        for (file, name) in [
            #[cfg(feature = "rsa")]
            ("rsa_2048.pub", "rsa-sha2-256"),
            #[cfg(feature = "rsa")]
            ("rsa_2048.pub", "rsa-sha2-512"),
            #[cfg(feature = "rsa")]
            ("rsa_2048.pub", "ssh-rsa"),
            ("ecdsa_256.pub", "ecdsa-sha2-nistp256"),
            ("ecdsa_384.pub", "ecdsa-sha2-nistp384"),
            ("ecdsa_521.pub", "ecdsa-sha2-nistp521"),
        ] {
            let key = PublicKey::read_openssh_file(directory.join(file)).unwrap();
            fs::write(
                &path,
                format!("[thirtyssh-test]:{port} {}\n", key.to_openssh().unwrap()),
            )
            .unwrap();
            let mut keys = KnownHosts::new();
            keys.load(&path).unwrap();
            let pinned = PinnedHost(keys, port);
            let config = Arc::new(client::Config {
                host_key_algorithms: vec![Algorithm::new(name).unwrap()],
                ..Default::default()
            });
            let client = client::connect(config, ("127.0.0.1", port), pinned)
                .await
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let session = authenticate_fixture(client, &user).await;
            let handle = session.handle();
            handle.ping().await.unwrap();
            handle.rekey().await.unwrap();
            handle.ping().await.unwrap();
            session.disconnect().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture host CA"]
async fn thirtyssh_verifies_host_certificates_against_openssh_server() {
    struct TrustedCa {
        hosts: Arc<KnownHosts>,
        hostname: &'static str,
        port: u16,
    }
    impl session::Handler for TrustedCa {}
    impl client::Handler for TrustedCa {
        async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
            let Some(certificate) = host.certificate() else {
                return Ok(false);
            };
            Ok(self
                .hosts
                .check_certificate(self.hostname, self.port, certificate)?
                == Status::Trusted)
        }
    }

    timeout(Duration::from_secs(20), async {
        let ca = PublicKey::read_openssh_file(PathBuf::from(
            env::var_os("THIRTYSSH_TEST_SSHD_HOST_CA").unwrap(),
        ))
        .unwrap();
        let (port, user) = endpoint();
        let address = ("127.0.0.1", port);
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("known_hosts");
        let ca_key = ca.to_openssh().unwrap();
        fs::write(
            &path,
            format!("@cert-authority [thirtyssh-test]:{port},[other-host]:{port} {ca_key}\n"),
        )
        .unwrap();
        let mut known = KnownHosts::new();
        known.load(&path).unwrap();
        let known = Arc::new(known);
        let config = |name: &str| {
            Arc::new(client::Config {
                host_key_algorithms: vec![Algorithm::new(name).unwrap()],
                ..Default::default()
            })
        };
        let untrusted = client::connect(
            config("ssh-ed25519-cert-v01@openssh.com"),
            address,
            TrustedCa {
                hosts: known.clone(),
                hostname: "other-host",
                port,
            },
        )
        .await;
        assert_eq!(
            untrusted.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );

        for name in [
            "ssh-ed25519-cert-v01@openssh.com",
            #[cfg(feature = "rsa")]
            "rsa-sha2-256-cert-v01@openssh.com",
            #[cfg(feature = "rsa")]
            "rsa-sha2-512-cert-v01@openssh.com",
            #[cfg(feature = "rsa")]
            "ssh-rsa-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        ] {
            let client = client::connect(
                config(name),
                address,
                TrustedCa {
                    hosts: known.clone(),
                    hostname: "thirtyssh-test",
                    port,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            let session = authenticate_fixture(client, &user).await;
            let handle = session.handle();
            handle.ping().await.unwrap();
            handle.rekey().await.unwrap();
            handle.ping().await.unwrap();
            session.disconnect().await.unwrap();
        }

        let revocation = temporary.path().join("revoked_hosts");
        fs::write(
            &revocation,
            format!("@revoked [thirtyssh-test]:{port} {ca_key}\n"),
        )
        .unwrap();
        let mut hosts = KnownHosts::new();
        hosts.load(path).unwrap();
        hosts.load(revocation).unwrap();
        let revoked = client::connect(
            config("ssh-ed25519-cert-v01@openssh.com"),
            address,
            TrustedCa {
                hosts: Arc::new(hosts),
                hostname: "thirtyssh-test",
                port,
            },
        )
        .await;
        assert_eq!(
            revoked.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture keys"]
async fn thirtyssh_uses_rsa_and_all_ecdsa_curves_with_openssh_server() {
    timeout(Duration::from_secs(20), async {
        let directory = PathBuf::from(env::var_os("THIRTYSSH_TEST_SSHD_IDENTITIES").unwrap());
        let passphrase = env::var("THIRTYSSH_TEST_SSHD_KEY_PASSPHRASE").unwrap();
        #[cfg(feature = "rsa")]
        let rsa256 = Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        };
        #[cfg(feature = "rsa")]
        let rsa512 = Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        };
        for (file, algorithm) in [
            #[cfg(feature = "rsa")]
            ("rsa_2048", Some(rsa256)),
            #[cfg(feature = "rsa")]
            ("rsa_2048", Some(rsa512)),
            #[cfg(feature = "rsa")]
            ("rsa_2048", Some(Algorithm::Rsa { hash: None })),
            #[cfg(feature = "rsa")]
            ("rsa_2048", None),
            ("ecdsa_256", None),
            ("ecdsa_384", None),
            ("ecdsa_521", None),
        ] {
            let (mut client, user) = connect_unauthenticated().await;
            let identity = PrivateKeyReader::new()
                .passphrase(passphrase.as_str())
                .file(directory.join(file))
                .unwrap_or_else(|err| panic!("could not load {file}: {err}"));
            let result = client
                .authenticate(
                    &user,
                    client::Method::Key {
                        key: &identity,
                        algorithm: algorithm.clone(),
                    },
                )
                .await
                .unwrap();
            assert!(result.is_accepted(), "{file} {algorithm:?}: {result:?}");
            let client = client.start().unwrap();
            client.handle().ping().await.unwrap();
            client.disconnect().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture user CA"]
async fn thirtyssh_authenticates_user_certificates_with_openssh_server() {
    timeout(Duration::from_secs(20), async {
        let directory = PathBuf::from(env::var_os("THIRTYSSH_TEST_SSHD_IDENTITIES").unwrap());
        let passphrase = env::var("THIRTYSSH_TEST_SSHD_KEY_PASSPHRASE").unwrap();
        let certificate = Certificate::read_file(&directory.join("ed25519-cert.pub")).unwrap();
        let (mut client, user) = connect_unauthenticated().await;
        let mut signer = External(Ed25519KeyPair::from_seed_unchecked(&IDENTITY_SEED).unwrap());
        assert!(
            client
                .authenticate_with(
                    &user,
                    &Credential::from(certificate.clone()),
                    None,
                    &mut signer
                )
                .await
                .unwrap()
                .is_accepted()
        );
        client.start().unwrap().disconnect().await.unwrap();

        for (file, name) in [
            #[cfg(feature = "rsa")]
            ("rsa_2048", "rsa-sha2-256"),
            #[cfg(feature = "rsa")]
            ("rsa_2048", "rsa-sha2-512"),
            #[cfg(feature = "rsa")]
            ("rsa_2048", "ssh-rsa"),
            ("ecdsa_256", "ecdsa-sha2-nistp256"),
            ("ecdsa_384", "ecdsa-sha2-nistp384"),
            ("ecdsa_521", "ecdsa-sha2-nistp521"),
        ] {
            let key = PrivateKeyReader::new()
                .passphrase(passphrase.as_str())
                .file(directory.join(file))
                .unwrap_or_else(|err| panic!("could not load {file}: {err}"));
            let certificate =
                Certificate::read_file(&directory.join(format!("{file}-cert.pub"))).unwrap();
            let algorithm = Algorithm::new(name).unwrap();
            let (mut client, user) = connect_unauthenticated().await;
            let result = client
                .authenticate(
                    &user,
                    client::Method::Certificate {
                        certificate: &certificate,
                        key: &key,
                        algorithm: Some(algorithm),
                    },
                )
                .await
                .unwrap();
            assert!(result.is_accepted(), "{name}: {result:?}");
            let client = client.start().unwrap();
            client.handle().ping().await.unwrap();
            client.disconnect().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture settings"]
async fn thirtyssh_streams_to_openssh_server() {
    timeout(Duration::from_secs(15), async {
        let session = connect_fixture().await;
        let handle = session.handle();
        handle.keepalive(false).await.unwrap();
        handle.keepalive(true).await.unwrap();
        handle.ping().await.unwrap();
        let input = (0..192 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let output = exec::start(
            &session.handle(),
            b"cat; printf 'fixture stderr' >&2; exit 37",
        )
        .await
        .unwrap()
        .capture(input.as_slice(), input.len() + 14)
        .await
        .unwrap();
        assert_eq!(output.stdout, input);
        assert_eq!(output.stderr, b"fixture stderr");
        assert_eq!(output.exit, Some(Exit::Status(37)));

        let output = exec::start(&session.handle(), b"kill -TERM $$")
            .await
            .unwrap()
            .capture(tokio::io::empty(), 0)
            .await
            .unwrap();
        let Some(Exit::Signal(signal)) = output.exit else {
            panic!("expected OpenSSH exit-signal, got {:?}", output.exit);
        };
        assert_eq!(signal.name, "TERM");
        assert!(!signal.core_dumped);
        session.disconnect().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated loopback OpenSSH daemon and its fixture settings"]
async fn openssh_honors_no_more_sessions_and_keeps_an_existing_session() {
    timeout(Duration::from_secs(10), async {
        for want_reply in [false, true] {
            let session = connect_fixture().await;
            let handle = session.handle();
            let mut channel = handle.open_session().await.unwrap();
            handle.no_more_sessions(want_reply).await.unwrap();
            handle.ping().await.unwrap();
            channel
                .request(
                    Request::Exec(b"cat; printf 'fixture stderr' >&2; exit 37"),
                    true,
                )
                .await
                .unwrap();
            assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
            channel.send(b"fixture".as_slice()).await.unwrap();
            channel.eof().await.unwrap();
            let mut output = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut channel.reader(), &mut output)
                .await
                .unwrap();
            assert_eq!(output, b"fixture");

            let error = handle
                .open_session()
                .await
                .err()
                .expect("new session must fail");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            // sshd ends the connection with a protocol error, and the session
            // reports that instead of passing it off as an orderly close.
            let ended = session.await.unwrap_err();
            let disconnect = ended
                .get_ref()
                .and_then(|source| source.downcast_ref::<PeerDisconnect>())
                .expect("the server's disconnect");
            assert_eq!(disconnect.reason, 2);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires the Linux sshd fixture and its expected PTY owner, group and mode"]
async fn openssh_assigns_the_pty_to_the_login_user() {
    let expected = env::var("THIRTYSSH_TEST_SSHD_PTY_OWNER").unwrap();
    timeout(Duration::from_secs(10), async {
        let session = connect_fixture().await;
        let mut channel = session.handle().open_session().await.unwrap();
        channel
            .request(
                Request::Pty(
                    PtyRequest::from_modes(
                        "xterm",
                        TerminalSize {
                            columns: 80,
                            rows: 24,
                            pixel_width: 0,
                            pixel_height: 0,
                        },
                        &[],
                    )
                    .unwrap(),
                ),
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            channel.recv().await,
            Some(Message::Reply { success: true }),
            "sshd must allocate the PTY"
        );
        channel
            .request(Request::Exec(b"pty-owner"), true)
            .await
            .unwrap();
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
        assert_line(&mut BufReader::new(channel.reader()), &expected).await;
        session.disconnect().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires the interactive loopback OpenSSH fixture"]
async fn thirtyssh_resizes_and_interrupts_an_openssh_server_pty() {
    timeout(Duration::from_secs(15), async {
        let session = connect_fixture().await;
        let mut channel = session.handle().open_session().await.unwrap();
        let modes = [
            (Pty::VINTR, 3),
            (Pty::ICANON, 1),
            (Pty::ISIG, 1),
            (Pty::ECHO, 0),
            (Pty::OPOST, 1),
            (Pty::ONLCR, 1),
        ];
        channel
            .request(
                Request::Pty(
                    PtyRequest::from_modes(
                        "xterm-256color",
                        TerminalSize {
                            columns: 80,
                            rows: 24,
                            pixel_width: 640,
                            pixel_height: 480,
                        },
                        &modes,
                    )
                    .unwrap(),
                ),
                true,
            )
            .await
            .unwrap();
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
        channel
            .request(
                Request::Environment {
                    name: "THIRTYSSH_FIXTURE".as_bytes(),
                    value: "fixture".as_bytes(),
                },
                true,
            )
            .await
            .unwrap();
        channel
            .request(
                Request::Environment {
                    name: "THIRTYSSH_UNLISTED".as_bytes(),
                    value: "ignored".as_bytes(),
                },
                true,
            )
            .await
            .unwrap();
        channel.request(Request::Shell, true).await.unwrap();
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
        assert_eq!(
            channel.recv().await,
            Some(Message::Reply { success: false })
        );
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));

        let (mut reader, writer) = channel.split();
        {
            let mut lines = BufReader::new(reader.reader());
            assert_line(&mut lines, "xterm-256color/fixture").await;
            assert_line(&mut lines, "24 80").await;
            writer
                .request(
                    Request::WindowChange(TerminalSize {
                        columns: 101,
                        rows: 37,
                        pixel_width: 808,
                        pixel_height: 740,
                    }),
                    false,
                )
                .await
                .unwrap();
            let mut input = writer.writer();
            input.write_all(b"size\nping\ninterrupt\n").await.unwrap();
            input.flush().await.unwrap();
            assert_line(&mut lines, "37 101").await;
            assert_line(&mut lines, "pong").await;
            assert_line(&mut lines, "ready").await;
            input.write_all(b"\x03").await.unwrap();
            input.flush().await.unwrap();
            assert_line(&mut lines, "interrupted").await;
        }
        let mut exit = None;
        loop {
            let message = reader.recv().await.expect("OpenSSH channel must close");
            if let Some(request) = message.session_request().unwrap()
                && let Request::Exit(result) = request.request
            {
                exit = Some(result);
            }
            if message == Message::Closed {
                break;
            }
        }
        assert_eq!(exit, Some(Exit::Status(43)));
        session.disconnect().await.unwrap();
    })
    .await
    .unwrap();
}

async fn assert_line(reader: &mut (impl AsyncBufRead + Unpin), expected: &str) {
    let mut line = String::new();
    assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
    assert_eq!(line.trim_end_matches(['\r', '\n']), expected);
}
