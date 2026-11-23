#[path = "fixtures/forwarding.rs"]
mod forwarding;
#[cfg(unix)]
#[path = "fixtures/streamlocal.rs"]
mod streamlocal;

use data_encoding::BASE64;
use std::{fs, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
#[cfg(any(feature = "rsa", feature = "dsa"))]
use thirtyssh::keys::CertificateSignaturePolicy;
use thirtyssh::{
    algorithms::{
        Cipher, Compression, CompressionPreferences, DirectionPreferences, Kex, Mac,
        PacketPreferences, Suite, TransportPreferences,
    },
    auth::{self, Policy},
    channel::Channel,
    clear_packet,
    exec::{self, Captured, Exit},
    forward::TcpipKind,
    identification::Role,
    initial,
    keys::{
        Algorithm, Certificate, PrivateKeyReader, PublicKey, ssh_key::certificate::CertType,
        validate_certificate_at,
    },
    known_hosts::{KnownHosts, Status},
    server, session,
    transport::{HostKey, HostKeys, Transport},
    wire::{Reader, Writer},
};
#[cfg(unix)]
use thirtyssh::{
    auth::AuthMethod,
    forward::{AgentForwarding, X11Open},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
    time::timeout,
};

#[tokio::test]
#[ignore = "requires the OpenSSH ssh executable in PATH"]
async fn openssh_client_negotiates_curve25519() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let mut ssh = Command::new("ssh")
        .args([
            "-F",
            "none",
            "-oBatchMode=yes",
            "-oKexAlgorithms=curve25519-sha256",
            "-oConnectTimeout=5",
            "-p",
            &port,
            "fixture@127.0.0.1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = socket.split();
        let mut read = BufReader::new(read);
        let exchange = initial::negotiate(Role::Server, &mut read, &mut write)
            .await
            .unwrap();
        assert!(
            exchange
                .client
                .identification
                .starts_with(b"SSH-2.0-OpenSSH")
        );
        assert_eq!(exchange.kex_algorithm, "curve25519-sha256");
        let packet = clear_packet::read(&mut read).await.unwrap();
        let mut reader = Reader::new(&packet);
        assert_eq!(reader.byte().unwrap(), 30); // SSH_MSG_KEX_ECDH_INIT
        assert_eq!(reader.string().unwrap().len(), 32);
        reader.finish().unwrap();
    })
    .await
    .unwrap();
    timeout(Duration::from_secs(10), ssh.wait())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_client_authenticates_and_executes() {
    openssh_session(false, None, false, Operation::Buffered).await;
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH and a POSIX askpass script"]
async fn openssh_client_completes_public_key_then_password_authentication() {
    openssh_public_key_then(AuthMethod::Password).await;
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH and a POSIX askpass script"]
async fn openssh_client_completes_public_key_then_keyboard_interactive_authentication() {
    openssh_public_key_then(AuthMethod::KeyboardInteractive).await;
}

#[cfg(unix)]
async fn openssh_public_key_then(method: AuthMethod) {
    use std::{io, os::unix::fs::PermissionsExt};
    use thirtyssh::auth::{AuthDecision, AuthMethod, Challenge, InteractiveDecision, Prompt};

    struct MultiFactor([u8; 32], AuthMethod);

    impl server::AuthPolicy for MultiFactor {
        async fn public_key_probe(&mut self, user: &str, key: &PublicKey) -> io::Result<bool> {
            Ok(user == "fixture" && key.key_data().ed25519().is_some_and(|key| key.0 == self.0))
        }

        async fn public_key_decision(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> io::Result<AuthDecision> {
            Ok(if self.public_key_probe(user, key).await? {
                AuthDecision::Reject {
                    proceed_with_methods: Some(vec![self.1]),
                    partial_success: true,
                }
            } else {
                AuthDecision::reject()
            })
        }

        async fn password(&mut self, username: &str, password: &[u8]) -> io::Result<bool> {
            Ok(username == "fixture" && password == b"fixture password")
        }

        async fn keyboard_interactive(
            &mut self,
            username: &str,
            _: &str,
            answers: Option<&[&[u8]]>,
        ) -> io::Result<InteractiveDecision> {
            assert_eq!(username, "fixture");
            Ok(match answers {
                None => InteractiveDecision::Challenge(Challenge {
                    name: "Fixture verification".into(),
                    instructions: String::new(),
                    language: String::new(),
                    prompts: vec![Prompt {
                        prompt: "Second factor: ".into(),
                        echo: false,
                    }],
                }),
                Some(answers) => InteractiveDecision::Finished(AuthDecision::from(
                    answers == [b"fixture password"],
                )),
            })
        }
    }

    impl session::Handler for MultiFactor {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            _: &session::Context,
        ) -> io::Result<()> {
            serve_key_fixture(request).await
        }
    }

    timeout(Duration::from_secs(15), async {
        let fixture = OpenSshFixture::new().await;
        let askpass = fixture.directory.path().join("askpass");
        fs::write(&askpass, b"#!/bin/sh\nprintf '%s\\n' 'fixture password'\n").unwrap();
        fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let preference = format!("-oPreferredAuthentications=publickey,{}", method.name());
        let mut ssh = fixture.command_with_options(
            port,
            "none",
            &fixture.identity_file,
            &["-oBatchMode=no", &preference, "-oNumberOfPasswordPrompts=1"],
        );
        ssh.env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("LC_ALL", "C")
            .args(["-v", "fixture@127.0.0.1", "fixture-command"]);
        let mut config = server::Config::new(fixture.host);
        config.authentication.methods = vec![AuthMethod::PublicKey];
        config.authentication.rejection_delay = Duration::ZERO;
        let serve = async {
            let (socket, _) = listener.accept().await.unwrap();
            server::accept_over(
                Arc::new(config),
                socket,
                None,
                MultiFactor(fixture.identity, method),
            )
            .await?
            .await
        };
        let (result, output) = tokio::join!(serve, ssh.output());
        let output = output.unwrap();
        let log = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{log}");
        assert!(log.contains("with partial success"), "{log}");
        assert_eq!(output.stdout, b"verified public key");
        result.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_client_streams_input_to_thirtyssh() {
    let input = (0..128 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    openssh_session(false, None, false, Operation::Exec(&input)).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_client_requests_pty_and_shell_from_thirtyssh() {
    openssh_session(false, None, false, Operation::Shell(b"ping\n")).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_client_opens_direct_tcpip() {
    openssh_session(
        false,
        None,
        false,
        Operation::Forward(b"forwarded bytes\0\xff"),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_client_requests_an_allocated_remote_tcpip_port() {
    timeout(Duration::from_secs(20), async {
        let fixture = OpenSshFixture::new().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forward = format!("127.0.0.1:0:{}", target.local_addr().unwrap());
        let mut ssh = fixture
            .command(listener.local_addr().unwrap().port())
            .args([
                "-N",
                "-v",
                "-oExitOnForwardFailure=yes",
                "-R",
                &forward,
                "forward@127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut messages = BufReader::new(ssh.stderr.take().unwrap()).lines();
        let (socket, _) = listener.accept().await.unwrap();
        let session = server::accept_over(
            Arc::new(server::Config::new(fixture.host)),
            socket,
            None,
            forwarding::LoopbackForwarding::new(fixture.identity),
        )
        .await
        .unwrap();
        let mut log = String::new();
        let port: u16 = loop {
            let Some(line) = messages.next_line().await.unwrap() else {
                panic!("OpenSSH did not allocate a port\n{log}");
            };
            if let Some(rest) = line.trim_start().strip_prefix("Allocated port ") {
                break rest.split_whitespace().next().unwrap().parse().unwrap();
            }
            log.push_str(&line);
            log.push('\n');
        };
        let mut external = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut internal, _) = target.accept().await.unwrap();
        let external = async {
            external
                .write_all(b"request through OpenSSH\0\xff")
                .await
                .unwrap();
            external.shutdown().await.unwrap();
            let mut reply = Vec::new();
            external.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply through OpenSSH\0\xf0");
        };
        let internal = async {
            let mut request = Vec::new();
            internal.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request through OpenSSH\0\xff");
            internal
                .write_all(b"reply through OpenSSH\0\xf0")
                .await
                .unwrap();
            internal.shutdown().await.unwrap();
        };
        tokio::join!(external, internal);
        session.disconnect().await.unwrap();
        ssh.wait().await.unwrap();
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH and Unix domain sockets"]
async fn openssh_client_forwards_direct_and_remote_unix_sockets() {
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};

    async fn exchange(path: &Path, target: &UnixListener) {
        let mut outside = UnixStream::connect(path).await.unwrap();
        let (mut inside, _) = target.accept().await.unwrap();
        let send = async {
            outside
                .write_all(b"OpenSSH Unix request\0\xff")
                .await
                .unwrap();
            outside.shutdown().await.unwrap();
            let mut response = Vec::new();
            outside.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"OpenSSH Unix response\0\xfe");
        };
        let receive = async {
            let mut request = Vec::new();
            inside.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"OpenSSH Unix request\0\xff");
            inside
                .write_all(b"OpenSSH Unix response\0\xfe")
                .await
                .unwrap();
            inside.shutdown().await.unwrap();
        };
        tokio::join!(send, receive);
    }

    timeout(Duration::from_secs(20), async {
        let fixture = OpenSshFixture::new().await;
        let directory = fixture.directory.path();
        let direct_path = directory.join("direct.sock");
        let remote_path = directory.join("remote.sock");
        let local_path = directory.join("local.sock");
        let target_path = directory.join("target.sock");
        let direct = UnixListener::bind(&direct_path).unwrap();
        let target = UnixListener::bind(&target_path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = format!("{}:{}", local_path.display(), direct_path.display());
        let remote = format!("{}:{}", remote_path.display(), target_path.display());
        let mut ssh = fixture
            .command(listener.local_addr().unwrap().port())
            .args([
                "-N",
                "-v",
                "-oExitOnForwardFailure=yes",
                "-L",
                &local,
                "-R",
                &remote,
                "forward@127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut messages = BufReader::new(ssh.stderr.take().unwrap()).lines();
        let (socket, _) = listener.accept().await.unwrap();
        let session = server::accept_over(
            Arc::new(server::Config::new(fixture.host)),
            socket,
            None,
            streamlocal::LocalForwarding::new(fixture.identity, direct_path, remote_path.clone()),
        )
        .await
        .unwrap();
        let mut log = String::new();
        loop {
            let Some(line) = messages.next_line().await.unwrap() else {
                panic!("OpenSSH did not establish Unix socket forwarding\n{log}");
            };
            if line.contains("remote forward success for:") {
                break;
            }
            log.push_str(&line);
            log.push('\n');
        }
        exchange(&local_path, &direct).await;
        exchange(&remote_path, &target).await;
        session.disconnect().await.unwrap();
        assert_eq!(
            fs::symlink_metadata(&remote_path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        ssh.wait().await.unwrap();
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh, ssh-keygen, ssh-agent, and xauth in PATH"]
async fn openssh_client_relays_x11_and_agent_to_isolated_endpoints() {
    use thirtyssh::session::{Context, IncomingChannel, Request};
    use tokio::sync::oneshot;

    const XAUTH_PROTOCOL: &str = "MIT-MAGIC-COOKIE-1";
    const DISPLAY_COOKIE: [u8; 16] = [0x43; 16];

    fn setup(cookie: &[u8; 16]) -> Vec<u8> {
        let mut message = vec![
            b'l',
            0,
            11,
            0,
            0,
            0,
            XAUTH_PROTOCOL.len() as u8,
            0,
            16,
            0,
            0,
            0,
        ];
        message.extend_from_slice(XAUTH_PROTOCOL.as_bytes());
        message.resize(message.len().next_multiple_of(4), 0);
        message.extend_from_slice(cookie);
        message
    }

    struct Auxiliary {
        key: [u8; 32],
        ready: Option<oneshot::Sender<[u8; 16]>>,
        finished: Option<oneshot::Receiver<()>>,
    }

    impl server::AuthPolicy for Auxiliary {
        async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> std::io::Result<bool> {
            Ok(user == "fixture" && self.key == *key)
        }
    }

    impl session::Handler for Auxiliary {
        async fn channel_open(
            &mut self,
            incoming: IncomingChannel,
            _: &Context,
        ) -> std::io::Result<()> {
            if incoming.kind() != b"session" || self.ready.is_none() {
                return Ok(());
            }
            let mut channel = incoming.accept(8192, &[]).await?;
            let mut cookie = None;
            let mut agent = false;
            while let Some(message) = channel.recv().await {
                let Some(request) = message.session_request()? else {
                    continue;
                };
                let approved = match request.request {
                    Request::X11(parameters) => {
                        assert_eq!(parameters.authentication_protocol, XAUTH_PROTOCOL);
                        assert_eq!(parameters.screen_number, 0);
                        assert_eq!(parameters.authentication_cookie.len(), 32);
                        let mut fake = [0u8; 16];
                        for (index, byte) in fake.iter_mut().enumerate() {
                            *byte = u8::from_str_radix(
                                &parameters.authentication_cookie[2 * index..2 * index + 2],
                                16,
                            )
                            .unwrap();
                        }
                        assert_ne!(fake, DISPLAY_COOKIE);
                        cookie = Some(fake);
                        true
                    }
                    Request::AgentForward(_) => {
                        agent = true;
                        true
                    }
                    Request::Exec(b"auxiliary-fixture") => {
                        assert!(agent, "missing OpenSSH agent request");
                        let fake = cookie.expect("missing OpenSSH X11 request");
                        if request.want_reply {
                            channel.reply(true).await?;
                        }
                        self.ready.take().unwrap().send(fake).unwrap();
                        self.finished
                            .take()
                            .unwrap()
                            .await
                            .map_err(std::io::Error::other)?;
                        channel
                            .request(Request::Exit(exec::Exit::Status(0)), false)
                            .await?;
                        channel.eof().await?;
                        return channel.close().await;
                    }
                    _ => false,
                };
                if request.want_reply {
                    channel.reply(approved).await?;
                }
            }
            Ok(())
        }
    }

    timeout(Duration::from_secs(20), async {
        let fixture = OpenSshFixture::new().await;
        let auth_path = fixture.directory.path().join("Xauthority");
        let agent_path = fixture.directory.path().join("agent.sock");
        let display = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let number = display
            .local_addr()
            .unwrap()
            .port()
            .checked_sub(6000)
            .unwrap();
        let display_name = format!("127.0.0.1:{number}");
        let auth = Command::new("xauth")
            .arg("-f")
            .arg(&auth_path)
            .args([
                "add",
                &display_name,
                XAUTH_PROTOCOL,
                &"43".repeat(DISPLAY_COOKIE.len()),
            ])
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            auth.status.success(),
            "{}",
            String::from_utf8_lossy(&auth.stderr)
        );

        let mut agent = Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&agent_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        while !agent_path.exists() {
            assert!(
                agent.try_wait().unwrap().is_none(),
                "ssh-agent exited before binding"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut ssh = fixture
            .command_with_identity_agent(
                listener.local_addr().unwrap().port(),
                &agent_path.to_string_lossy(),
            )
            .env("DISPLAY", &display_name)
            .env("XAUTHORITY", &auth_path)
            .args(["-Y", "-A"])
            .args(["fixture@127.0.0.1", "auxiliary-fixture"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = ssh.stderr.take().unwrap();
        let diagnostics = async move {
            let mut stderr = stderr;
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (ready, cookie) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let (socket, _) = listener.accept().await.unwrap();
        let session = server::accept_over(
            Arc::new(server::Config::new(fixture.host)),
            socket,
            None,
            Auxiliary {
                key: fixture.identity,
                ready: Some(ready),
                finished: Some(finished),
            },
        )
        .await
        .unwrap();
        let cookie = cookie.await.unwrap();
        let handle = session.handle();
        let x11 = async {
            let mut channel = handle
                .open_as(X11Open {
                    originator_address: "127.0.0.1",
                    originator_port: 6000,
                })
                .await
                .unwrap()
                .into_io();
            channel.write_all(&setup(&cookie)).await.unwrap();
            let mut response = [0; 4];
            channel.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"x-ok");
        };
        let display = async {
            let (mut socket, _) = display.accept().await.unwrap();
            let expected = setup(&DISPLAY_COOKIE);
            let mut received = vec![0; expected.len()];
            socket.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            socket.write_all(b"x-ok").await.unwrap();
            socket.shutdown().await.unwrap();
        };
        let agent_io = async {
            let mut channel = handle
                .open_as(AgentForwarding::OpenSsh)
                .await
                .unwrap()
                .into_io();
            channel.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
            let mut list = [0; 9];
            channel.read_exact(&mut list).await.unwrap();
            assert_eq!(list, [0, 0, 0, 5, 12, 0, 0, 0, 0]);
        };
        tokio::join!(x11, display, agent_io);
        done.send(()).unwrap();
        let (status, log) = tokio::join!(ssh.wait(), diagnostics);
        assert!(
            status.unwrap().success(),
            "{}",
            String::from_utf8_lossy(&log)
        );
        session.await.unwrap();
        agent.kill().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_exec_across_multiple_rekeys() {
    openssh_session(true, None, false, Operation::Buffered).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh with explicit CBC and HMAC-SHA1 options"]
async fn openssh_client_uses_explicit_legacy_packet_algorithms_across_rekeys() {
    for cipher in [
        Cipher::Aes128Cbc,
        Cipher::Aes192Cbc,
        Cipher::Aes256Cbc,
        #[cfg(feature = "des")]
        Cipher::TripleDesCbc,
    ] {
        for mac in [Mac::HmacSha1, Mac::HmacSha1Etm] {
            let suite = Suite {
                cipher,
                mac: Some(mac),
            };
            openssh_session(true, Some(suite), false, Operation::Buffered).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires the OpenSSH ssh and ssh-keygen executables in PATH"]
async fn openssh_client_uses_all_nist_ecdh_curves() {
    for method in [Kex::EcdhNistP256, Kex::EcdhNistP384, Kex::EcdhNistP521] {
        openssh_session_with_kex(true, None, false, Operation::Buffered, Some(method)).await;
    }
}

#[tokio::test]
#[ignore = "requires the OpenSSH ssh and ssh-keygen executables in PATH"]
async fn openssh_client_uses_fixed_dh_groups() {
    for method in [
        Kex::DhGroup14Sha256,
        Kex::DhGroup16Sha512,
        Kex::DhGroup18Sha512,
    ] {
        openssh_session_with_kex(true, None, false, Operation::Buffered, Some(method)).await;
    }
}

#[tokio::test]
#[ignore = "requires the OpenSSH ssh and ssh-keygen executables in PATH"]
async fn openssh_client_uses_dh_group_exchange() {
    openssh_session_with_kex(
        true,
        None,
        false,
        Operation::Buffered,
        Some(Kex::DhGexSha256),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh with the explicitly configured SHA-1 DH KEX methods"]
async fn openssh_client_uses_sha1_dh_and_rekeys() {
    for method in [Kex::DhGroup1Sha1, Kex::DhGroup14Sha1, Kex::DhGexSha1] {
        openssh_session_with_kex(true, None, false, Operation::Buffered, Some(method)).await;
    }
}

#[tokio::test]
#[ignore = "requires an OpenSSH ssh that supports mlkem768x25519-sha256"]
async fn openssh_hybrid_mlkem_x25519_rekeys() {
    // OpenSSH gained this exchange in 9.9. An older client skips the test.
    const NAME: &str = "mlkem768x25519-sha256";
    let supported = std::process::Command::new("ssh")
        .args(["-Q", "kex"])
        .output()
        .unwrap();
    assert!(supported.status.success());
    let supported = String::from_utf8(supported.stdout).unwrap();
    if !supported.lines().any(|name| name == NAME) {
        eprintln!("skipped: this ssh does not support {NAME}");
        return;
    }
    openssh_session_with_kex(
        true,
        None,
        false,
        Operation::Buffered,
        Some(Kex::MlKem768X25519Sha256),
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "flate2")]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_exec_with_delayed_zlib_and_rekeys() {
    openssh_session(true, None, true, Operation::Buffered).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_exec_with_each_cipher_and_sha2_mac() {
    for cipher in [
        Cipher::ChaCha20Poly1305,
        Cipher::Aes128Gcm,
        Cipher::Aes256Gcm,
    ] {
        openssh_session(
            true,
            Some(Suite { cipher, mac: None }),
            false,
            Operation::Buffered,
        )
        .await;
    }
    for cipher in [Cipher::Aes128Ctr, Cipher::Aes192Ctr, Cipher::Aes256Ctr] {
        for mac in [
            Mac::HmacSha256,
            Mac::HmacSha512,
            Mac::HmacSha256Etm,
            Mac::HmacSha512Etm,
        ] {
            openssh_session(
                true,
                Some(Suite {
                    cipher,
                    mac: Some(mac),
                }),
                false,
                Operation::Buffered,
            )
            .await;
        }
    }
}

enum Operation<'a> {
    Buffered,
    Exec(&'a [u8]),
    Shell(&'a [u8]),
    Forward(&'a [u8]),
}

struct OpenSshFixture {
    directory: tempfile::TempDir,
    host: HostKey,
    identity: [u8; 32],
    identity_file: PathBuf,
    known_hosts: PathBuf,
}

impl OpenSshFixture {
    async fn new() -> Self {
        let host = HostKey::generate().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join("known_hosts");
        let identity_file = directory.path().join("fixture_key");
        let generated = timeout(
            Duration::from_secs(10),
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&identity_file)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let identity = fs::read_to_string(identity_file.with_extension("pub")).unwrap();
        let identity = BASE64
            .decode(identity.split_ascii_whitespace().nth(1).unwrap().as_bytes())
            .unwrap();
        let mut reader = Reader::new(&identity);
        assert_eq!(reader.string().unwrap(), b"ssh-ed25519");
        let identity: [u8; 32] = reader.string().unwrap().try_into().unwrap();
        reader.finish().unwrap();
        let mut blob = [0; 51];
        let mut writer = Writer::new(&mut blob);
        writer.string(b"ssh-ed25519").unwrap();
        writer.string(&host.public_key()).unwrap();
        fs::write(
            &known_hosts,
            format!(
                "thirtyssh-test ssh-ed25519 {}\n",
                BASE64.encode(writer.written())
            ),
        )
        .unwrap();
        let hashed = timeout(
            Duration::from_secs(10),
            Command::new("ssh-keygen")
                .args(["-q", "-H", "-f"])
                .arg(&known_hosts)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            hashed.status.success(),
            "{}",
            String::from_utf8_lossy(&hashed.stderr)
        );
        let mut trust = KnownHosts::new();
        trust.load(&known_hosts).unwrap();
        assert_eq!(
            trust
                .check("thirtyssh-test", 22, &host.public_key())
                .unwrap(),
            Status::Trusted
        );
        assert_eq!(
            trust
                .check("thirtyssh-test", 2222, &host.public_key())
                .unwrap(),
            Status::Unknown
        );
        Self {
            directory,
            host,
            identity,
            identity_file,
            known_hosts,
        }
    }

    fn command(&self, port: u16) -> Command {
        self.command_with_identity_agent(port, "none")
    }

    fn command_with_identity_agent(&self, port: u16, identity_agent: &str) -> Command {
        self.command_with_identity(port, identity_agent, &self.identity_file)
    }

    fn command_with_identity(
        &self,
        port: u16,
        identity_agent: &str,
        identity_file: &std::path::Path,
    ) -> Command {
        self.command_with_options(
            port,
            identity_agent,
            identity_file,
            &["-oBatchMode=yes", "-oPreferredAuthentications=publickey"],
        )
    }

    fn command_with_options(
        &self,
        port: u16,
        identity_agent: &str,
        identity_file: &std::path::Path,
        options: &[&str],
    ) -> Command {
        let known_hosts_arg = format!("-oUserKnownHostsFile=\"{}\"", self.known_hosts.display());
        let agent_arg = format!("-oIdentityAgent=\"{identity_agent}\"");
        let mut ssh = Command::new("ssh");
        ssh.args(options);
        ssh.args([
            "-F",
            "none",
            "-oStrictHostKeyChecking=yes",
            "-oHostKeyAlias=thirtyssh-test",
            &known_hosts_arg,
            "-oGlobalKnownHostsFile=none",
            &agent_arg,
            "-oIdentitiesOnly=yes",
            "-oConnectTimeout=5",
            "-p",
            &port.to_string(),
            "-i",
        ])
        .arg(identity_file)
        .stdin(Stdio::null())
        .kill_on_drop(true);
        ssh
    }
}

type KeyFixture = (&'static str, &'static str, &'static [&'static str]);

const SIGNING_KEYS: &[KeyFixture] = &[
    ("ed25519", "256", &["ssh-ed25519"]),
    #[cfg(feature = "rsa")]
    ("rsa", "2048", &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]),
    ("ecdsa", "256", &["ecdsa-sha2-nistp256"]),
    ("ecdsa", "384", &["ecdsa-sha2-nistp384"]),
    ("ecdsa", "521", &["ecdsa-sha2-nistp521"]),
];

#[cfg(feature = "dsa")]
const DSA_KEYS: &[KeyFixture] = &[("dsa", "1024", &["ssh-dss"])];

async fn generate_key(directory: &std::path::Path, kind: &str, bits: &str) -> PathBuf {
    let path = directory.join(format!("{kind}_{bits}"));
    let mut generate = Command::new("ssh-keygen");
    generate.args(["-q", "-t", kind]);
    if kind != "ed25519" {
        generate.args(["-b", bits]);
    }
    let generated = generate
        .args(["-N", "", "-f"])
        .arg(&path)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    path
}

async fn issue_certificate(
    ca: &std::path::Path,
    key: &std::path::Path,
    name: &str,
    usage: CertType,
    options: &[&str],
) -> Certificate {
    issue_certificate_with_algorithm(ca, key, name, usage, options, None).await
}

async fn issue_certificate_with_algorithm(
    ca: &std::path::Path,
    key: &std::path::Path,
    name: &str,
    usage: CertType,
    options: &[&str],
    issuer_algorithm: Option<&str>,
) -> Certificate {
    let mut sign = Command::new("ssh-keygen");
    sign.args(["-q", "-s"]).arg(ca);
    if let Some(name) = issuer_algorithm {
        sign.args(["-t", name]);
    }
    if usage == CertType::Host {
        sign.arg("-h");
    }
    for option in options {
        sign.arg("-O").arg(option);
    }
    let result = sign
        .args(["-I", "fixture", "-n", name, "-V", "-1m:+15m"])
        .arg(key.with_extension("pub"))
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut name = key.as_os_str().to_owned();
    name.push("-cert.pub");
    Certificate::read_file(&PathBuf::from(name)).unwrap()
}

#[tokio::test]
#[cfg(feature = "rsa")]
#[ignore = "requires OpenSSH ssh and ssh-keygen with the ssh-rsa CA signature option"]
async fn openssh_uses_rsa_sha1_ca_with_ed25519_certificates() {
    openssh_uses_legacy_ca(
        "rsa",
        "2048",
        Algorithm::Rsa { hash: None },
        CertificateSignaturePolicy {
            allow_rsa_sha1: true,
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "dsa")]
#[ignore = "requires OpenSSH ssh and ssh-keygen that support DSA certificate authorities"]
async fn openssh_uses_dsa_ca_with_ed25519_certificates() {
    openssh_uses_legacy_ca(
        "dsa",
        "1024",
        Algorithm::Dsa,
        CertificateSignaturePolicy {
            allow_dsa: true,
            ..Default::default()
        },
    )
    .await;
}

#[cfg(any(feature = "rsa", feature = "dsa"))]
async fn openssh_uses_legacy_ca(
    kind: &str,
    bits: &str,
    signature: Algorithm,
    policy: CertificateSignaturePolicy,
) {
    struct UserCertificate {
        authority: PublicKey,
        policy: CertificateSignaturePolicy,
    }
    impl server::AuthPolicy for UserCertificate {
        fn certificate_signature_policy(&self) -> CertificateSignaturePolicy {
            self.policy
        }

        async fn certificate_probe(
            &mut self,
            user: &str,
            certificate: &Certificate,
        ) -> std::io::Result<bool> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.policy
                .validate_user_certificate_at(certificate, &self.authority, user, now, None)
        }

        async fn certificate_verified(
            &mut self,
            user: &str,
            certificate: &Certificate,
        ) -> std::io::Result<bool> {
            self.certificate_probe(user, certificate).await
        }
    }
    impl session::Handler for UserCertificate {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            _: &session::Context,
        ) -> std::io::Result<()> {
            serve_key_fixture(request).await
        }
    }

    timeout(Duration::from_secs(15), async {
        let fixture = OpenSshFixture::new().await;
        let ca = generate_key(fixture.directory.path(), kind, bits).await;
        let host = generate_key(fixture.directory.path(), "ed25519", "256").await;
        let authority = PublicKey::read_openssh_file(ca.with_extension("pub")).unwrap();
        let host_cert = issue_certificate_with_algorithm(
            &ca,
            &host,
            "thirtyssh-test",
            CertType::Host,
            &[],
            Some(signature.as_str()),
        )
        .await;
        let user_cert = issue_certificate_with_algorithm(
            &ca,
            &fixture.identity_file,
            "fixture",
            CertType::User,
            &[],
            Some(signature.as_str()),
        )
        .await;
        assert_eq!(host_cert.signature().algorithm(), signature);
        assert_eq!(user_cert.signature().algorithm(), signature);
        fs::write(
            &fixture.known_hosts,
            format!(
                "@cert-authority thirtyssh-test {}\n",
                authority.to_openssh().unwrap()
            ),
        )
        .unwrap();
        let keys = HostKeys::with_certificates_and_policy(
            vec![PrivateKeyReader::new().file(host).unwrap()],
            vec![host_cert],
            policy,
        )
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mut ssh = fixture.command(listener.local_addr().unwrap().port());
        ssh.arg(format!("-oCASignatureAlgorithms={}", signature.as_str()));
        ssh.args([
            "-oHostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com",
            "-oPubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com",
            "fixture@127.0.0.1",
            "fixture-command",
        ]);
        let serve = async {
            let (stream, _) = listener.accept().await.unwrap();
            server::accept_over(
                Arc::new(server::Config::new(keys)),
                stream,
                None,
                UserCertificate { authority, policy },
            )
            .await
        };
        let (result, running) = tokio::join!(ssh.output(), serve);
        let result = result.unwrap();
        assert!(
            result.status.success(),
            "{signature:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"verified public key");
        if let Err(error) = running.unwrap().await {
            assert!(
                cfg!(windows)
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ),
                "{error}"
            );
        }
    })
    .await
    .unwrap();
}

async fn serve_key_fixture(request: session::IncomingChannel) -> std::io::Result<()> {
    assert_eq!(request.kind(), b"session");
    let channel = request.accept(8192, &[]).await?;
    let request = exec::receive(channel).await?.unwrap();
    assert_eq!(request.command(), b"fixture-command");
    let (_, _, mut output) = request.accept().await?.split();
    output.stdout().write_all(b"verified public key").await?;
    output.finish(Some(exec::Exit::Status(0))).await
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_user_certificate_constrains_tcp_source_and_effective_command() {
    use std::{
        io,
        net::SocketAddr,
        time::{SystemTime, UNIX_EPOCH},
    };
    use thirtyssh::keys::validate_user_certificate_at;

    struct Restricted {
        authority: PublicKey,
        peer: SocketAddr,
    }

    impl server::AuthPolicy for Restricted {
        async fn certificate_probe(&mut self, user: &str, cert: &Certificate) -> io::Result<bool> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            validate_user_certificate_at(cert, &self.authority, user, now, Some(self.peer.ip()))
        }

        async fn certificate_verified(
            &mut self,
            user: &str,
            cert: &Certificate,
        ) -> io::Result<bool> {
            self.certificate_probe(user, cert).await
        }
    }

    impl session::Handler for Restricted {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            context: &session::Context,
        ) -> io::Result<()> {
            assert_eq!(context.peer_addr(), Some(self.peer));
            serve_key_fixture(request).await
        }
    }

    timeout(Duration::from_secs(20), async {
        let fixture = OpenSshFixture::new().await;
        let ca_dir = fixture.directory.path().join("restricted_authority");
        fs::create_dir(&ca_dir).unwrap();
        let ca = generate_key(&ca_dir, "ed25519", "256").await;
        let key = generate_key(fixture.directory.path(), "ed25519", "256").await;
        let authority = PublicKey::read_openssh_file(ca.with_extension("pub")).unwrap();
        let server = server::listen(
            Arc::new(server::Config::new(fixture.host.clone())),
            ("127.0.0.1", 0),
            move |peer| Restricted {
                authority: authority.clone(),
                peer,
            },
        )
        .await
        .unwrap();
        for (source, allowed) in [
            ("source-address=192.0.2.0/24", false),
            ("source-address=127.0.0.0/8,::1/128", true),
        ] {
            issue_certificate(
                &ca,
                &key,
                "fixture",
                CertType::User,
                &["clear", source, "force-command=fixture-command"],
            )
            .await;
            let output = fixture
                .command_with_identity(server.local_addr().port(), "none", &key)
                .args([
                    "-oPubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com",
                    "fixture@127.0.0.1",
                    "untrusted-ssh-command",
                ])
                .output()
                .await
                .unwrap();
            assert_eq!(
                output.status.success(),
                allowed,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if allowed {
                assert_eq!(output.stdout, b"verified public key");
            } else {
                assert!(output.stdout.is_empty());
            }
        }
        server.shutdown_handle().shutdown();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_authenticates_with_rsa_and_all_ecdsa_curves() {
    openssh_authenticates_typed_identities(false, SIGNING_KEYS).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_authenticates_with_user_certificates() {
    openssh_authenticates_typed_identities(true, SIGNING_KEYS).await;
}

#[tokio::test]
#[cfg(feature = "dsa")]
#[ignore = "requires an OpenSSH ssh and ssh-keygen that support ssh-dss"]
async fn openssh_client_uses_explicit_dsa_host_and_user_proofs() {
    for certified in [false, true] {
        openssh_authenticates_typed_identities(certified, DSA_KEYS).await;
        openssh_verifies_host_identity(certified, DSA_KEYS).await;
    }
}

async fn openssh_authenticates_typed_identities(certified: bool, keys: &[KeyFixture]) {
    struct TypedPolicy {
        key: PublicKey,
        ca: Option<PublicKey>,
    }

    impl server::AuthPolicy for TypedPolicy {
        async fn public_key_probe(&mut self, user: &str, key: &PublicKey) -> std::io::Result<bool> {
            Ok(self.ca.is_none() && user == "fixture" && key.key_data() == self.key.key_data())
        }

        async fn public_key_verified(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> std::io::Result<bool> {
            self.public_key_probe(user, key).await
        }

        async fn certificate_probe(
            &mut self,
            user: &str,
            certificate: &Certificate,
        ) -> std::io::Result<bool> {
            use std::time::{SystemTime, UNIX_EPOCH};

            let Some(ca) = &self.ca else { return Ok(false) };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(certificate.public_key() == self.key.key_data()
                && validate_certificate_at(certificate, ca, user, CertType::User, now)?)
        }

        async fn certificate_verified(
            &mut self,
            user: &str,
            certificate: &Certificate,
        ) -> std::io::Result<bool> {
            self.certificate_probe(user, certificate).await
        }
    }

    impl session::Handler for TypedPolicy {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            _: &session::Context,
        ) -> std::io::Result<()> {
            serve_key_fixture(request).await
        }
    }

    timeout(Duration::from_secs(30), async {
        let fixture = OpenSshFixture::new().await;
        let authority = if certified {
            let directory = fixture.directory.path().join("user_authority");
            fs::create_dir(&directory).unwrap();
            let path = generate_key(&directory, "ed25519", "256").await;
            Some((
                path.clone(),
                PublicKey::read_openssh_file(path.with_extension("pub")).unwrap(),
            ))
        } else {
            None
        };
        for &(kind, bits, algorithms) in keys {
            let path = generate_key(fixture.directory.path(), kind, bits).await;
            let key = PublicKey::read_openssh_file(path.with_extension("pub")).unwrap();
            let ca = if let Some((path_to_ca, ca)) = &authority {
                issue_certificate(path_to_ca, &path, "fixture", CertType::User, &[]).await;
                Some(ca.clone())
            } else {
                None
            };
            for algorithm in algorithms {
                let suffix = if certified {
                    "-cert-v01@openssh.com"
                } else {
                    ""
                };
                let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let mut ssh = fixture.command_with_identity(
                    listener.local_addr().unwrap().port(),
                    "none",
                    &path,
                );
                ssh.args([
                    format!("-oPubkeyAcceptedAlgorithms={algorithm}{suffix}"),
                    "fixture@127.0.0.1".into(),
                    "fixture-command".into(),
                ]);
                let accept = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut config = server::Config::new(fixture.host.clone());
                    if matches!(*algorithm, "ssh-rsa" | "ssh-dss") {
                        config
                            .user_signature_algorithms
                            .push(Algorithm::new(algorithm).unwrap());
                    }
                    server::accept_over(
                        Arc::new(config),
                        stream,
                        None,
                        TypedPolicy {
                            key: key.clone(),
                            ca: ca.clone(),
                        },
                    )
                    .await
                };
                let (result, accepted) = tokio::join!(ssh.output(), accept);
                let result = result.unwrap();
                assert!(
                    result.status.success(),
                    "{algorithm}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(result.stdout, b"verified public key");
                let end = accepted.unwrap().await;
                // The Windows OpenSSH CLI can close TCP immediately after
                // consuming the exit status instead of sending DISCONNECT.
                if let Err(error) = end {
                    assert!(
                        cfg!(windows)
                            && matches!(
                                error.kind(),
                                std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::ConnectionReset
                            ),
                        "{algorithm}: {error}"
                    );
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_verifies_rsa_and_all_ecdsa_host_keys() {
    openssh_verifies_host_identity(false, SIGNING_KEYS).await;
}

#[tokio::test]
#[ignore = "requires OpenSSH ssh and ssh-keygen in PATH"]
async fn openssh_verifies_thirtyssh_host_certificates() {
    openssh_verifies_host_identity(true, SIGNING_KEYS).await;
}

async fn openssh_verifies_host_identity(certified: bool, keys: &[KeyFixture]) {
    struct HostFixture([u8; 32]);

    impl server::AuthPolicy for HostFixture {
        async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> std::io::Result<bool> {
            Ok(user == "fixture" && key == &self.0)
        }
    }

    impl session::Handler for HostFixture {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            _: &session::Context,
        ) -> std::io::Result<()> {
            serve_key_fixture(request).await
        }
    }

    timeout(Duration::from_secs(45), async {
        let fixture = OpenSshFixture::new().await;
        let authority = if certified {
            let directory = fixture.directory.path().join("authority");
            fs::create_dir(&directory).unwrap();
            let (kind, bits) = if cfg!(feature = "rsa") {
                ("rsa", "2048")
            } else {
                ("ed25519", "256")
            };
            let path = generate_key(&directory, kind, bits).await;
            let key = PublicKey::read_openssh_file(path.with_extension("pub")).unwrap();
            fs::write(
                &fixture.known_hosts,
                format!(
                    "@cert-authority thirtyssh-test {}\n",
                    key.to_openssh().unwrap()
                ),
            )
            .unwrap();
            Some((path, key))
        } else {
            None
        };
        for &(kind, bits, algorithms) in keys {
            let path = generate_key(fixture.directory.path(), kind, bits).await;
            let key = PrivateKeyReader::new().file(&path).unwrap();
            let keys = if let Some((ca, trusted)) = &authority {
                let certificate =
                    issue_certificate(ca, &path, "thirtyssh-test", CertType::Host, &[]).await;
                assert!(
                    validate_certificate_at(
                        &certificate,
                        trusted,
                        "thirtyssh-test",
                        CertType::Host,
                        certificate.valid_after()
                    )
                    .unwrap()
                );
                assert!(
                    !validate_certificate_at(
                        &certificate,
                        trusted,
                        "thirtyssh-test",
                        CertType::Host,
                        certificate.valid_before()
                    )
                    .unwrap()
                );
                assert!(
                    !validate_certificate_at(
                        &certificate,
                        trusted,
                        "thirtyssh-test",
                        CertType::User,
                        certificate.valid_after()
                    )
                    .unwrap()
                );
                let mut tampered = certificate.to_bytes().unwrap();
                *tampered.last_mut().unwrap() ^= 1;
                let tampered = Certificate::from_bytes(&tampered).unwrap();
                assert!(HostKeys::with_certificates(vec![key.clone()], vec![tampered]).is_err());
                assert!(
                    HostKeys::with_certificates(Vec::new(), vec![certificate.clone()]).is_err()
                );
                HostKeys::with_certificates(vec![key], vec![certificate]).unwrap()
            } else {
                fs::write(
                    &fixture.known_hosts,
                    format!(
                        "thirtyssh-test {}\n",
                        key.public_key().to_openssh().unwrap()
                    ),
                )
                .unwrap();
                HostKeys::from(key)
            };
            let mut config = server::Config::new(keys);
            if let Some(legacy) = algorithms
                .iter()
                .find(|&&name| matches!(name, "ssh-rsa" | "ssh-dss"))
            {
                let algorithm = Algorithm::new(legacy).unwrap();
                config.host_key_algorithms.push(if certified {
                    Algorithm::new(&algorithm.to_certificate_type()).unwrap()
                } else {
                    algorithm
                });
            }
            let config = Arc::new(config);
            for algorithm in algorithms {
                let suffix = if certified {
                    "-cert-v01@openssh.com"
                } else {
                    ""
                };
                let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let mut ssh = fixture.command(listener.local_addr().unwrap().port());
                ssh.args([
                    format!("-oHostKeyAlgorithms={algorithm}{suffix}"),
                    "fixture@127.0.0.1".into(),
                    "fixture-command".into(),
                ]);
                let accept = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    server::accept_over(config.clone(), stream, None, HostFixture(fixture.identity))
                        .await
                };
                let (result, accepted) = tokio::join!(ssh.output(), accept);
                let result = result.unwrap();
                assert!(
                    result.status.success(),
                    "{algorithm}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(result.stdout, b"verified public key");
                if let Err(error) = accepted.unwrap().await {
                    assert!(
                        cfg!(windows)
                            && matches!(
                                error.kind(),
                                std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::ConnectionReset
                            ),
                        "{algorithm}: {error}"
                    );
                }
            }
        }
    })
    .await
    .unwrap();
}

async fn openssh_session(
    rekey: bool,
    requested: Option<Suite>,
    compressed: bool,
    operation: Operation<'_>,
) {
    openssh_session_with_kex(rekey, requested, compressed, operation, None).await;
}

async fn openssh_session_with_kex(
    rekey: bool,
    requested: Option<Suite>,
    compressed: bool,
    operation: Operation<'_>,
    kex: Option<Kex>,
) {
    let shell = matches!(operation, Operation::Shell(_));
    let forward = matches!(operation, Operation::Forward(_));
    let input = match operation {
        Operation::Buffered => None,
        Operation::Exec(input) | Operation::Shell(input) | Operation::Forward(input) => Some(input),
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let fixture = OpenSshFixture::new().await;
    let ssh_log = fixture.directory.path().join("ssh.log");
    let mut ssh = fixture.command(listener.local_addr().unwrap().port());
    let OpenSshFixture { host, identity, .. } = fixture;
    if shell {
        // Quiet suppresses the interactive client's local disconnect notice.
        ssh.args(["-tt", "-q"]).env("TERM", "xterm-256color");
    }
    if forward {
        ssh.args(["-W", "forwarding-fixture.test:48080"]);
    }
    if compressed {
        ssh.arg("-C");
    }
    if let Some(suite) = requested {
        ssh.args(["-c", suite.cipher.name()]);
        if let Some(mac) = suite.mac {
            ssh.args(["-m", mac.name()]);
        }
    }
    if rekey {
        ssh.args(["-v", "-oRekeyLimit=32K"]);
    }
    if let Some(method) = kex {
        ssh.arg(format!("-oKexAlgorithms={}", method.name()));
    }
    // Keep OpenSSH's own diagnostics apart from the remote command's stderr.
    ssh.arg("-E").arg(&ssh_log);
    ssh.arg("fixture@127.0.0.1");
    if !shell && !forward {
        ssh.arg("fixture-command");
    }
    struct AllowedKey {
        identity: [u8; 32],
        shell: bool,
        forward: bool,
    }
    impl Policy for AllowedKey {
        fn public_key(&mut self, username: &str, key: &[u8; 32]) -> bool {
            username == "fixture" && *key == self.identity
        }
    }
    impl server::AuthPolicy for AllowedKey {
        async fn public_key(&mut self, username: &str, key: &[u8; 32]) -> std::io::Result<bool> {
            Ok(Policy::public_key(self, username, key))
        }
    }
    impl session::Handler for AllowedKey {
        async fn channel_open(
            &mut self,
            request: session::IncomingChannel,
            _: &session::Context,
        ) -> std::io::Result<()> {
            if self.forward {
                let open = request.tcpip()?.expect("expected a TCP forwarding channel");
                assert_eq!(open.kind, TcpipKind::Direct);
                assert_eq!(
                    (open.address, open.port),
                    ("forwarding-fixture.test", 48080)
                );
                let mut channel = request.accept(8192, &[]).await?.into_io();
                let mut received = Vec::new();
                channel.read_to_end(&mut received).await?;
                channel.write_all(&received).await?;
                return channel.shutdown().await;
            }
            assert_eq!(request.kind(), b"session");
            let channel = request.accept(8192, &[]).await?;
            if self.shell {
                return serve_shell(channel).await;
            }
            let request = exec::receive(channel)
                .await?
                .expect("fixture must request exec");
            assert_eq!(request.command(), b"fixture-command");
            let (_, mut input, mut output) = request.accept().await?.split();
            let mut received = Vec::new();
            input.reader().read_to_end(&mut received).await?;
            output.stdout().write_all(&received).await?;
            output.stderr().write_all(b"fixture stderr\n").await?;
            output.finish(Some(exec::Exit::Status(19))).await
        }
    }
    let expected = if let Some(input) = input {
        input.to_vec()
    } else if compressed {
        let mut data = vec![0; 192 * 1024];
        getrandom::fill(&mut data).unwrap();
        for (index, block) in data
            .as_chunks_mut::<1024>()
            .0
            .iter_mut()
            .enumerate()
            .step_by(2)
        {
            block.fill(b'A' + (index % 26) as u8);
        }
        data
    } else if rekey {
        (0..192 * 1024)
            .map(|index| b'A' + ((index / 1024) % 26) as u8)
            .collect()
    } else {
        b"fixture stdout\n".to_vec()
    };
    let server = async {
        let (socket, _) = listener.accept().await.unwrap();
        if input.is_some() {
            let running = server::accept_over(
                Arc::new(server::Config::new(host)),
                socket,
                None,
                AllowedKey {
                    identity,
                    shell,
                    forward,
                },
            )
            .await?;
            return running.await;
        }
        let compression = if compressed {
            Compression::DelayedZlib
        } else {
            Compression::None
        };
        let packet = requested.map_or_else(PacketPreferences::default, |suite| {
            let direction = DirectionPreferences {
                ciphers: vec![suite.cipher],
                macs: suite.mac.into_iter().collect(),
            };
            PacketPreferences {
                client_to_server: direction.clone(),
                server_to_client: direction,
            }
        });
        let mut preferences = TransportPreferences {
            packet,
            compression: CompressionPreferences {
                client_to_server: vec![compression],
                server_to_client: vec![compression],
            },
            ..Default::default()
        };
        if let Some(method) = kex {
            preferences.kex = vec![method, Kex::StrictServer, Kex::ExtInfoServer];
        }
        let mut transport = Transport::accept_with_preferences(socket, &host, preferences).await?;
        if let Some(method) = kex {
            assert_eq!(transport.key_exchange_algorithm(), method.name());
        }
        assert_eq!(
            transport.compression_algorithms().client_to_server,
            compression
        );
        assert_eq!(
            transport.compression_algorithms().server_to_client,
            compression
        );
        if let Some(suite) = requested {
            assert_eq!(transport.packet_algorithms().client_to_server, suite);
            assert_eq!(transport.packet_algorithms().server_to_client, suite);
        }
        if rekey {
            let write_limit = if compressed { 20 * 1024 } else { 72 * 1024 };
            let read_limit = if compressed { 256 } else { 72 * 1024 };
            transport.set_rekey_limits(write_limit, read_limit, Duration::from_secs(60))?;
        }
        let session = auth::accept(
            transport,
            AllowedKey {
                identity,
                shell,
                forward,
            },
        )
        .await?;
        exec::serve(session, async |user, command| {
            assert_eq!(user, "fixture");
            assert_eq!(command, b"fixture-command");
            Some(Captured {
                stdout: expected.clone(),
                stderr: b"fixture stderr\n".to_vec(),
                exit: Some(Exit::Status(19)),
            })
        })
        .await
    };
    let ssh = async {
        if let Some(input) = input {
            let mut child = ssh
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut stdin = child.stdin.take().expect("piped SSH input");
            let feed = async move {
                stdin.write_all(input).await?;
                stdin.shutdown().await
            };
            let ((), output) = tokio::try_join!(feed, child.wait_with_output())?;
            Ok(output)
        } else {
            ssh.output().await
        }
    };
    let (output, served) = timeout(Duration::from_secs(10), async { tokio::join!(ssh, server) })
        .await
        .unwrap();
    let output = output.unwrap();
    let log = fs::read_to_string(ssh_log).unwrap_or_default();
    assert_eq!(
        output.status.code(),
        Some(if forward { 0 } else { 19 }),
        "{requested:?}\n{served:?}\n{log}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected);
    assert_eq!(
        output.stderr,
        if shell || forward {
            &b""[..]
        } else {
            &b"fixture stderr\n"[..]
        }
    );
    if let Err(error) = served {
        // OpenSSH for Windows can end the TCP connection after the full
        // command result, before our server observes the channel close.
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "{requested:?}\n{log}\n{error}"
        );
    }
    if rekey {
        let signature_algorithms = log.lines().find_map(|line| {
            let (_, algorithms) = line.trim_end().split_once("server-sig-algs=<")?;
            algorithms.strip_suffix('>')
        });
        assert!(
            signature_algorithms
                .is_some_and(|names| names.split(',').any(|name| name == "ssh-ed25519")),
            "{log}"
        );
        assert!(
            log.matches("SSH2_MSG_NEWKEYS received").count() > 2,
            "{log}"
        );
    }
}

async fn serve_shell(mut channel: Channel) -> std::io::Result<()> {
    use thirtyssh::session::Request;
    let mut pty = false;
    loop {
        let message = channel.recv().await.expect("shell request expected");
        let request = message
            .session_request()?
            .expect("session request expected");
        let accepted = match request.request {
            Request::Pty(request) => {
                assert_eq!(request.term, "xterm-256color");
                pty = true;
                true
            }
            Request::Shell => {
                assert!(pty, "OpenSSH requested a shell before PTY");
                if request.want_reply {
                    channel.reply(true).await?;
                }
                break;
            }
            _ => false,
        };
        if request.want_reply {
            channel.reply(accepted).await?;
        }
    }
    let mut received = [0; 5];
    channel.reader().read_exact(&mut received).await?;
    assert_eq!(&received, b"ping\n");
    channel.send(received.to_vec()).await?;
    channel
        .request(Request::Exit(exec::Exit::Status(19)), false)
        .await?;
    channel.eof().await?;
    channel.close().await
}
