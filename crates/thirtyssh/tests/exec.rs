use std::{io::ErrorKind, time::Duration};
use thirtyssh::{
    auth::{self, Policy},
    client,
    exec::{self, Captured, Exit},
    keys::{Algorithm, Credential},
    server::AuthPolicy,
    session::{Context, Handler, IncomingChannel, Session},
    transport::{HostKey, Transport},
};
use tokio::{io, time::timeout};

struct Credentials {
    key: [u8; 32],
}

impl Policy for Credentials {
    fn password(&mut self, user: &str, password: &[u8]) -> bool {
        user == "fixture" && password == b"fixture-password"
    }

    fn public_key(&mut self, user: &str, key: &[u8; 32]) -> bool {
        user == "fixture" && key == &self.key
    }
}

struct StreamClient([u8; 32], bool);

impl Handler for StreamClient {
    fn observe_routed_channel_events(&self) -> bool {
        self.1
    }
}
impl client::Handler for StreamClient {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(key == self.0)
    }
}

struct StreamServer;

impl AuthPolicy for StreamServer {
    async fn password(&mut self, name: &str, password: &[u8]) -> io::Result<bool> {
        Ok(Credentials { key: [0; 32] }.password(name, password))
    }
}

const PREFIX_SIZE: usize = 2 * 1024 * 1024 + 1024;
const ERROR_TEXT: &[u8] = b"fixture stderr";

fn termination_signal() -> exec::Exit {
    exec::Exit::Signal(exec::ExitSignal {
        name: "TERM".into(),
        core_dumped: false,
        message: "fixture stopped".into(),
        language: "en".into(),
    })
}

impl Handler for StreamServer {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert_eq!(request.kind(), b"session");
        assert!(request.fields().is_empty());
        let channel = request.accept(4096, &[]).await?;
        let Some(request) = exec::receive(channel).await? else {
            return Ok(());
        };
        if request.command() == b"refused" {
            return request.refuse().await;
        }
        let (command, mut stdin, mut output) = request.accept().await?.split();
        match &command[..] {
            b"exchange" => {
                let prefix = vec![0x8a; PREFIX_SIZE];
                output.stdout().write_all(&prefix).await?;
                output.stderr().write_all(ERROR_TEXT).await?;
                let mut input = Vec::new();
                stdin.reader().read_to_end(&mut input).await?;
                output.stdout().write_all(&input).await?;
                output.finish(Some(exec::Exit::Status(21))).await
            }
            b"terminate" => output.finish(Some(termination_signal())).await,
            _ => panic!("unexpected fixture command"),
        }
    }
}

async fn streaming_pair(observe: bool) -> (Session, Session) {
    use std::sync::Arc;
    use thirtyssh::server;

    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let client = async {
        let mut client = client::connect_over(
            Arc::new(client::Config::default()),
            left,
            StreamClient(host.public_key(), observe),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate("fixture", client::Method::Password("fixture-password"))
                .await
                .unwrap()
                .is_accepted()
        );
        client
    };
    let server = server::accept_over(
        Arc::new(server::Config::new(host.clone())),
        right,
        None,
        StreamServer,
    );
    let (client, server) = tokio::join!(client, server);
    (client.start().unwrap(), server.unwrap())
}

#[tokio::test]
async fn streaming_exec_crosses_both_windows_and_preserves_stderr_and_status() {
    timeout(Duration::from_secs(10), async {
        for observe in [false, true] {
            let (client, server) = streaming_pair(observe).await;
            let input = (0..192 * 1024)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let output = exec::start(&client.handle(), b"exchange")
                .await
                .unwrap()
                .capture(
                    input.as_slice(),
                    PREFIX_SIZE + input.len() + ERROR_TEXT.len(),
                )
                .await
                .unwrap();
            assert_eq!(output.stdout.len(), PREFIX_SIZE + input.len());
            assert!(
                output.stdout[..PREFIX_SIZE]
                    .iter()
                    .all(|byte| *byte == 0x8a)
            );
            assert_eq!(output.stdout[PREFIX_SIZE..], input);
            assert_eq!(output.stderr, ERROR_TEXT);
            assert_eq!(output.exit, Some(exec::Exit::Status(21)));
            client.disconnect().await.unwrap();
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn streaming_exec_distinguishes_refusal_and_exit_signal_with_idle_input() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = streaming_pair(false).await;
        let refused = exec::start(&client.handle(), b"refused")
            .await
            .err()
            .unwrap();
        assert_eq!(refused.kind(), ErrorKind::PermissionDenied);
        let (input, _still_open) = io::duplex(64);
        let output = exec::start(&client.handle(), b"terminate")
            .await
            .unwrap()
            .capture(input, 0)
            .await
            .unwrap();
        assert_eq!(output.exit, Some(termination_signal()));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        client.disconnect().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn password_login_and_exec_transfers_more_than_one_channel_window() {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(16 * 1024);
    let client = async {
        let transport = Transport::connect(left, |key| *key == host.public_key())
            .await
            .unwrap();
        let session = auth::login(
            transport,
            "fixture",
            auth::Method::Password("fixture-password"),
        )
        .await
        .unwrap();
        assert!(
            session
                .server_signature_algorithms()
                .unwrap()
                .split(',')
                .any(|algorithm| algorithm == "ssh-ed25519")
        );
        exec::run(session, b"fixture-command", 4 * 1024 * 1024)
            .await
            .unwrap()
    };
    let server = async {
        let transport = Transport::accept(right, &host).await.unwrap();
        let session = auth::accept(transport, Credentials { key: [0; 32] })
            .await
            .unwrap();
        assert_eq!(session.username(), "fixture");
        exec::serve(session, async |user, command| {
            assert_eq!(user, "fixture");
            assert_eq!(command, b"fixture-command");
            Some(Captured {
                stdout: vec![0x6a; 3 * 1024 * 1024],
                stderr: b"fixture error".to_vec(),
                exit: Some(Exit::Status(17)),
            })
        })
        .await
        .unwrap();
    };
    let (output, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    assert_eq!(output.stdout, vec![0x6a; 3 * 1024 * 1024]);
    assert_eq!(output.stderr, b"fixture error");
    assert_eq!(output.exit, Some(Exit::Status(17)));
}

#[tokio::test]
async fn signed_login_and_rejected_exec() {
    let host = HostKey::generate().unwrap();
    let identity = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let client = async {
        let transport = Transport::connect(left, |key| *key == host.public_key())
            .await
            .unwrap();
        let session = auth::login(transport, "fixture", &identity).await.unwrap();
        assert!(exec::run(session, b"fixture-command", 1024).await.is_err());
    };
    let server = async {
        let transport = Transport::accept(right, &host).await.unwrap();
        let session = auth::accept(
            transport,
            Credentials {
                key: identity.public_key(),
            },
        )
        .await
        .unwrap();
        exec::serve(session, async |_, _| None).await.unwrap();
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bad_credentials_never_open_a_session() {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let client = async {
        let transport = Transport::connect(left, |key| *key == host.public_key())
            .await
            .unwrap();
        auth::login(transport, "fixture", auth::Method::Password("wrong"))
            .await
            .err()
            .unwrap()
            .kind()
    };
    let server = async {
        let transport = Transport::accept(right, &host).await.unwrap();
        assert!(
            auth::accept(transport, Credentials { key: [0; 32] })
                .await
                .is_err()
        );
    };
    let (error, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    assert_eq!(error, ErrorKind::PermissionDenied);
}
