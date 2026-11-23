use std::{
    future::pending,
    io::{self, ErrorKind},
    sync::{Arc, Mutex},
    time::Duration,
};
use thirtyssh::{
    auth::{AuthDecision, AuthMethod, Outcome},
    channel::{Bytes, Channel, DEFAULT_WINDOW, Event, Message, OpenFailure},
    client::{self, PreAuth},
    keys::{Algorithm, Credential},
    server,
    session::{self, Context, End, IncomingChannel, OpenType},
    transport::{HostKey, Transport},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::TcpStream,
    sync::{Notify, mpsc},
    time::timeout,
};

const USER: &str = "fixture";
const PASSWORD: &str = "fixture password";

const CUSTOM: &str = "fixture-stream@example.test";
const DECLINE: &str = "decline@example.test";
const DEFER: &str = "defer@example.test";
const OPEN_FIELDS: &[u8] = b"\0\xffpayload";
const OPEN_REPLY: &[u8] = b"\xff\0confirmed";

struct CustomChannels {
    pin: [u8; 32],
    deferred: mpsc::Sender<IncomingChannel>,
}

impl client::Handler for CustomChannels {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(key == self.pin)
    }
}

impl server::AuthPolicy for CustomChannels {
    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == PASSWORD.as_bytes())
    }
}

impl session::Handler for CustomChannels {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let OpenType::Custom { name, fields } = request.open_type()? else {
            return Ok(());
        };
        match name {
            name if name == CUSTOM.as_bytes() => {
                assert_eq!(fields, OPEN_FIELDS);
                let mut stream = request.accept(1024, OPEN_REPLY).await?.into_io();
                let mut input = Vec::new();
                stream.read_to_end(&mut input).await?;
                stream.write_all(&input).await?;
                stream.shutdown().await
            }
            name if name == DECLINE.as_bytes() => request.refuse_with(custom_failure()).await,
            name if name == DEFER.as_bytes() => {
                self.deferred.send(request).await.map_err(io::Error::other)
            }
            _ => request.refuse(3).await,
        }
    }
}

fn custom_failure() -> OpenFailure {
    OpenFailure {
        reason: 0xfe00_004d,
        description: Bytes::from_static("傳輸遭拒".as_bytes()),
        language: Bytes::from_static(b"zh-TW"),
    }
}

#[tokio::test]
async fn custom_channel_opens_and_failures_round_trip_for_both_initiators() {
    timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let (to_client, mut client_pending) = mpsc::channel(1);
        let (to_server, _server_pending) = mpsc::channel(1);
        let pin = host.public_key();
        let (a, b) = duplex(4096);
        let (client, server) = tokio::join!(
            async {
                let mut client = client::connect_over(
                    Arc::new(client::Config::default()),
                    a,
                    CustomChannels {
                        pin,
                        deferred: to_client,
                    },
                )
                .await
                .unwrap();
                assert!(
                    client
                        .authenticate(USER, client::Method::Password(PASSWORD))
                        .await
                        .unwrap()
                        .is_accepted()
                );
                client
            },
            server::accept_over(
                Arc::new(config(host)),
                b,
                None,
                CustomChannels {
                    pin,
                    deferred: to_server
                }
            ),
        );
        let client = client.start().unwrap();
        let server = server.unwrap();
        let client_handle = client.handle();
        let server_handle = server.handle();
        for handle in [&client_handle, &server_handle] {
            let error = handle.open_channel(DECLINE, 1024, &[]).await.err().unwrap();
            assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(
                error.get_ref().unwrap().downcast_ref::<OpenFailure>(),
                Some(&custom_failure())
            );
            let unknown = handle
                .open_channel("unregistered@example.test", 1024, &[])
                .await
                .err()
                .unwrap();
            assert_eq!(
                unknown.get_ref().unwrap().downcast_ref::<OpenFailure>(),
                Some(&OpenFailure::new(3))
            );
            for name in ["", "bad type", "bad\0type", "bad,type"] {
                let error = handle.open_channel(name, 1024, &[]).await.err().unwrap();
                assert_eq!(error.kind(), ErrorKind::InvalidInput);
            }
        }
        let waiter = tokio::spawn({
            let server = server_handle.clone();
            async move { server.open_channel(DEFER, 1024, b"late confirmation").await }
        });
        let deferred = client_pending.recv().await.unwrap();
        assert_eq!(deferred.fields(), b"late confirmation");
        waiter.abort();
        assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
        let mut late = deferred.accept(1024, OPEN_REPLY).await.unwrap();
        assert_eq!(late.recv().await, Some(Message::Closed));

        for handle in [&client_handle, &server_handle] {
            let channel = handle
                .open_channel(CUSTOM, 1024, OPEN_FIELDS)
                .await
                .unwrap();
            assert_eq!(channel.open_fields(), OPEN_REPLY);
            let mut stream = channel.into_io();
            stream.write_all(b"\0\xfeapplication bytes").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"\0\xfeapplication bytes");
        }
        client.disconnect().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[derive(Clone)]
struct EchoHandler {
    pending_open: Arc<Notify>,
    end: Arc<Mutex<Vec<&'static str>>>,
}

impl server::AuthPolicy for EchoHandler {
    async fn password(&mut self, name: &str, password: &[u8]) -> io::Result<bool> {
        tokio::task::yield_now().await;
        Ok(name == USER && password == PASSWORD.as_bytes())
    }
}

impl session::Handler for EchoHandler {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        context: &Context,
    ) -> io::Result<()> {
        assert_eq!(context.username(), USER);
        match request.kind() {
            b"echo" => {
                let mut stream = request.accept(8, b"accepted").await?.into_io();
                let mut input = Vec::new();
                stream.read_to_end(&mut input).await?;
                stream.write_all(&input).await?;
                stream.shutdown().await
            }
            b"fail" => Err(io::Error::new(
                ErrorKind::InvalidData,
                "fixture handler failure",
            )),
            b"pending" => {
                self.pending_open.notify_one();
                pending::<()>().await;
                drop(request);
                Ok(())
            }
            _ => Ok(()), // Drop an unclaimed request and let the driver refuse it.
        }
    }

    async fn disconnected(&mut self, end: End<'_>, _: &Context) {
        let name = match end {
            End::LocalShutdown => "local",
            End::PeerDisconnect(info) => {
                assert_eq!(info.reason, 11);
                "peer"
            }
            End::Error(_) => "error",
        };
        self.end.lock().unwrap().push(name);
    }
}

struct Trusted {
    key: [u8; 32],
    seen: Arc<Mutex<Vec<&'static str>>>,
}

impl session::Handler for Trusted {
    async fn disconnected(&mut self, end: End<'_>, _: &Context) {
        let name = match end {
            End::LocalShutdown => "local",
            End::PeerDisconnect(info) => {
                assert_eq!(info.reason, 11);
                "peer"
            }
            End::Error(_) => "error",
        };
        self.seen.lock().unwrap().push(name);
    }
}

impl client::Handler for Trusted {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        tokio::task::yield_now().await;
        self.seen.lock().unwrap().push("key");
        Ok(self.key == key)
    }

    async fn banner(&mut self, banner: &client::Banner, _: &mut PreAuth) -> io::Result<()> {
        assert_eq!(banner.message, "fixture banner");
        assert_eq!(banner.language, "en");
        self.seen.lock().unwrap().push("banner");
        Ok(())
    }
}

fn handler() -> EchoHandler {
    EchoHandler {
        pending_open: Arc::new(Notify::new()),
        end: Arc::new(Mutex::new(Vec::new())),
    }
}

fn trusted(key: [u8; 32]) -> Trusted {
    Trusted {
        key,
        seen: Arc::new(Mutex::new(Vec::new())),
    }
}

fn config(key: HostKey) -> server::Config {
    let mut config = server::Config::new(key);
    config.authentication.rejection_delay = Duration::ZERO;
    config
}

async fn connected(
    server_config: server::Config,
    policy: impl server::Handler,
    test: impl AsyncFnOnce(client::Client<tokio::io::DuplexStream, Trusted>),
) {
    let pin = server_config.host_key.public_key();
    let (left, right) = duplex(4096);
    let client = async {
        let client = client::connect_over(Arc::new(client::Config::default()), left, trusted(pin))
            .await
            .unwrap();
        test(client).await;
    };
    let (_, server) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            client,
            server::accept_over(Arc::new(server_config), right, None, policy)
        )
    })
    .await
    .unwrap();
    drop(server);
}

#[tokio::test]
async fn rejection_budget_disconnects_after_the_configured_failures() {
    let mut server_config = config(HostKey::generate().unwrap());
    server_config.authentication.max_rejections = std::num::NonZeroUsize::new(2);
    connected(server_config, handler(), async |mut client| {
        for _ in 0..2 {
            assert!(
                !client
                    .authenticate(USER, client::Method::Password("incorrect"))
                    .await
                    .unwrap()
                    .is_accepted()
            );
        }
        assert!(
            client
                .authenticate(USER, client::Method::Password(PASSWORD))
                .await
                .is_err()
        );
    })
    .await;
}

struct KeyPolicy {
    key: [u8; 32],
    asked: Arc<Mutex<usize>>,
}

impl session::Handler for KeyPolicy {}

impl server::AuthPolicy for KeyPolicy {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        *self.asked.lock().unwrap() += 1;
        Ok(user == USER && self.key == *key)
    }
}

#[tokio::test]
async fn server_refuses_user_signature_algorithms_removed_from_its_config() {
    let identity = HostKey::generate().unwrap();
    for allowed in [true, false] {
        let asked = Arc::new(Mutex::new(0));
        let policy = KeyPolicy {
            key: identity.public_key(),
            asked: Arc::clone(&asked),
        };
        let mut server_config = config(HostKey::generate().unwrap());
        if !allowed {
            server_config
                .user_signature_algorithms
                .retain(|algorithm| *algorithm != Algorithm::Ed25519);
        }
        connected(server_config, policy, async |mut client| {
            let result = client.authenticate(USER, &identity).await.unwrap();
            assert_eq!(result.is_accepted(), allowed);
        })
        .await;
        assert_eq!(*asked.lock().unwrap() != 0, allowed);
    }
}

#[tokio::test(start_paused = true)]
async fn pre_auth_disconnect_times_out_while_sending_the_packet() {
    let key = HostKey::generate().unwrap();
    let (left, right) = duplex(32);
    let limit = Duration::from_millis(40);
    let (client, server) = tokio::join!(
        client::connect_over(
            Arc::new(client::Config {
                shutdown_timeout: limit,
                ..Default::default()
            }),
            left,
            trusted(key.public_key())
        ),
        Transport::accept(right, &key)
    );
    let _peer = server.unwrap();
    let start = tokio::time::Instant::now();
    let error = timeout(
        Duration::from_secs(1),
        client.unwrap().disconnect_with(11, &"x".repeat(512), ""),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), limit);
}

#[tokio::test]
async fn custom_stream_runs_host_trust_probe_retry_and_independent_handler_io() {
    timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let client_handler = trusted(key.public_key());
        let client_events = Arc::clone(&client_handler.seen);
        let mut cfg = config(key);
        cfg.authentication.banner = Some(client::Banner {
            message: "fixture banner".into(),
            language: "en".into(),
        });
        let server_handler = handler();
        let server_events = Arc::clone(&server_handler.end);
        let (left, right) = duplex(13);
        let client = async {
            let mut client =
                client::connect_over(Arc::new(client::Config::default()), left, client_handler)
                    .await
                    .unwrap();
            assert_eq!(
                client
                    .authenticate(USER, client::Method::None)
                    .await
                    .unwrap(),
                Outcome::Rejected {
                    remaining_methods: vec!["publickey".into(), "password".into()],
                    partial_success: false,
                }
            );
            assert!(
                !client
                    .authenticate(USER, client::Method::Password("incorrect"))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            assert!(
                client
                    .authenticate(USER, client::Method::Password(PASSWORD))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        };
        let (client, server) = tokio::join!(
            client,
            server::accept_over(Arc::new(cfg), right, None, server_handler)
        );
        let server = server.unwrap();
        let client = client.start().unwrap();
        let refusal = server
            .handle()
            .open_channel("unsupported@example.test", 8, &[])
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.get_ref().unwrap().downcast_ref::<OpenFailure>(),
            Some(&OpenFailure::new(3))
        );
        assert_eq!(client.context().username(), USER);
        assert_eq!(server.context().peer_addr(), None);
        for _ in 0..130 {
            let refused = client.handle().open_channel("unknown", 8, &[]).await;
            assert_eq!(refused.err().unwrap().kind(), ErrorKind::ConnectionRefused);
        }

        let channel = client.handle().open_channel("echo", 8, b"").await.unwrap();
        assert_eq!(channel.open_fields(), b"accepted");
        let mut stream = channel.into_io();
        stream
            .write_all(b"more than one eight byte window")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"more than one eight byte window");
        client.disconnect().await.unwrap();
        server.await.unwrap();
        assert_eq!(*client_events.lock().unwrap(), ["key", "banner", "local"]);
        assert_eq!(*server_events.lock().unwrap(), ["peer"]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn untrusted_hosts_and_handler_errors_end_the_session() {
    timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let config = Arc::new(config(key.clone()));
        let (left, right) = duplex(13);
        let (untrusted, failed_server) = tokio::join!(
            client::connect_over(Arc::new(client::Config::default()), left, ()),
            server::accept_over(Arc::clone(&config), right, None, handler()),
        );
        assert_eq!(untrusted.err().unwrap().kind(), ErrorKind::PermissionDenied);
        assert!(failed_server.is_err());

        let (left, right) = duplex(64);
        let endpoint = handler();
        let outcomes = Arc::clone(&endpoint.end);
        let (client, server) = tokio::join!(
            async {
                let mut client = client::connect_over(
                    Arc::new(client::Config::default()),
                    left,
                    trusted(key.public_key()),
                )
                .await
                .unwrap();
                assert!(
                    client
                        .authenticate(USER, client::Method::Password(PASSWORD))
                        .await
                        .unwrap()
                        .is_accepted()
                );
                client
            },
            server::accept_over(config, right, None, endpoint),
        );
        let client = client.start().unwrap();
        assert!(client.handle().open_channel("fail", 8, &[]).await.is_err());
        let error = server.unwrap().await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "fixture handler failure");
        client.await.unwrap();
        assert_eq!(*outcomes.lock().unwrap(), ["error"]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn interrupted_authentication_cannot_be_reused_as_a_new_attempt() {
    struct WaitingPolicy;
    impl server::AuthPolicy for WaitingPolicy {
        async fn password(&mut self, _: &str, _: &[u8]) -> io::Result<bool> {
            pending().await
        }
    }
    impl session::Handler for WaitingPolicy {}

    timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let presented = key.public_key();
        let mut cfg = config(key);
        cfg.authentication_timeout = Duration::from_millis(250);
        let (left, right) = duplex(1024);
        let ((), server) = tokio::join!(
            async {
                let mut client = client::connect_over(
                    Arc::new(client::Config {
                        authentication_timeout: Duration::from_millis(25),
                        ..client::Config::default()
                    }),
                    left,
                    trusted(presented),
                )
                .await
                .unwrap();
                assert_eq!(
                    client
                        .authenticate(USER, client::Method::Password(PASSWORD))
                        .await
                        .unwrap_err()
                        .kind(),
                    ErrorKind::TimedOut,
                );
                assert_eq!(
                    client
                        .authenticate("other account", client::Method::None)
                        .await
                        .unwrap_err()
                        .kind(),
                    ErrorKind::BrokenPipe,
                );
                assert_eq!(
                    client.start().err().unwrap().kind(),
                    ErrorKind::PermissionDenied
                );
            },
            server::accept_over(Arc::new(cfg), right, None, WaitingPolicy),
        );
        assert_eq!(server.err().unwrap().kind(), ErrorKind::TimedOut);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_a_session_requests_graceful_disconnect() {
    timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let presented = key.public_key();
        let (left, right) = duplex(1024);
        let endpoint = handler();
        let outcomes = Arc::clone(&endpoint.end);
        let (client, server) = tokio::join!(
            async {
                let mut client = client::connect_over(
                    Arc::new(client::Config::default()),
                    left,
                    trusted(presented),
                )
                .await
                .unwrap();
                assert!(
                    client
                        .authenticate(USER, client::Method::Password(PASSWORD))
                        .await
                        .unwrap()
                        .is_accepted()
                );
                client
            },
            server::accept_over(Arc::new(config(key)), right, None, endpoint),
        );
        let client = client.start().unwrap();
        let commands = client.handle();
        drop(client);
        server.unwrap().await.unwrap();
        assert_eq!(*outcomes.lock().unwrap(), ["peer"]);
        assert_eq!(
            commands.rekey().await.unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    })
    .await
    .unwrap();
}

struct Factory {
    handler: EchoHandler,
    new_clients: tokio::sync::mpsc::UnboundedSender<std::net::SocketAddr>,
    errors: Arc<Mutex<Vec<io::ErrorKind>>>,
}

impl server::Connections for Factory {
    type Handler = EchoHandler;

    fn handler(&mut self, addr: std::net::SocketAddr) -> Self::Handler {
        let _ = self.new_clients.send(addr);
        self.handler.clone()
    }

    fn failed(&mut self, error: io::Error) {
        self.errors.lock().unwrap().push(error.kind());
    }
}

#[tokio::test]
async fn listener_reports_invalid_ssh_config_before_resolving_the_address() {
    let mut config = config(HostKey::generate().unwrap());
    config.maximum_packet_size = 0;
    let (new_clients, _) = mpsc::unbounded_channel();
    let result = server::listen(
        Arc::new(config),
        "127.0.0.1:invalid-port",
        Factory {
            handler: handler(),
            new_clients,
            errors: Arc::new(Mutex::new(Vec::new())),
        },
    )
    .await;
    let error = result.err().expect("invalid SSH configuration");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .starts_with("SSH channel maximum packet size")
    );
}

#[tokio::test]
async fn tcp_listener_accepts_queued_connection_after_releasing_capacity() {
    timeout(Duration::from_secs(10), async {
        let key = HostKey::generate().unwrap();
        let public_key = key.public_key();
        let (new_clients, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let mut server_config = config(key);
        server_config.nodelay = true;
        server_config.max_connections = std::num::NonZeroUsize::MIN;
        let server = server::listen(
            Arc::new(server_config),
            ("127.0.0.1", 0),
            Factory {
                handler: handler(),
                new_clients,
                errors: errors.clone(),
            },
        )
        .await
        .unwrap();
        let address = server.local_addr();
        let login = async |socket: TcpStream| {
            socket.set_nodelay(true).unwrap();
            let mut client = client::connect_over(
                Arc::new(client::Config::default()),
                socket,
                trusted(public_key),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate(USER, client::Method::Password(PASSWORD))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        };

        let first = TcpStream::connect(address).await.unwrap();
        let first_address = first.local_addr().unwrap();
        let first = login(first).await.start().unwrap();
        assert_eq!(accepted.recv().await, Some(first_address));

        let queued = TcpStream::connect(address).await.unwrap();
        let queued_address = queued.local_addr().unwrap();
        assert!(
            timeout(Duration::from_millis(100), accepted.recv())
                .await
                .is_err(),
            "listener accepted beyond its configured connection limit"
        );
        first.disconnect().await.unwrap();
        assert_eq!(accepted.recv().await, Some(queued_address));
        login(queued)
            .await
            .start()
            .unwrap()
            .disconnect()
            .await
            .unwrap();

        server.shutdown_handle().shutdown();
        server.await.unwrap();
        assert!(errors.lock().unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_listener_limits_unauthenticated_connections() {
    timeout(Duration::from_secs(10), async {
        let key = HostKey::generate().unwrap();
        let public_key = key.public_key();
        let (new_clients, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let mut server_config = config(key);
        server_config.nodelay = true;
        server_config.max_unauthenticated_connections = std::num::NonZeroUsize::new(2).unwrap();
        server_config.max_unauthenticated_per_source = Some(std::num::NonZeroUsize::MIN);
        let server = server::listen(
            Arc::new(server_config),
            ("127.0.0.1", 0),
            Factory {
                handler: handler(),
                new_clients,
                errors: errors.clone(),
            },
        )
        .await
        .unwrap();
        let address = server.local_addr();
        let login = async || {
            let mut client = client::connect(
                Arc::new(client::Config::default()),
                address,
                trusted(public_key),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate(USER, client::Method::Password(PASSWORD))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        };

        // Authenticated sessions hold neither limit.
        let first = login().await.start().unwrap();
        let second = login().await.start().unwrap();
        let third = login().await.start().unwrap();
        for _ in 0..3 {
            accepted.recv().await.unwrap();
        }

        // A stalled connection holds its source's only slot, so the next
        // connection from that source is closed without a handler.
        let stalled = TcpStream::connect(address).await.unwrap();
        accepted.recv().await.unwrap();
        let mut refused = TcpStream::connect(address).await.unwrap();
        let mut banner = Vec::new();
        let closed = refused.read_to_end(&mut banner).await;
        assert!(closed.is_ok() || closed.unwrap_err().kind() == ErrorKind::ConnectionReset);
        assert!(banner.is_empty());
        assert!(accepted.try_recv().is_err());

        // Closing the stalled connection frees the slot.
        drop(stalled);
        while errors.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let fourth = login().await.start().unwrap();

        for session in [first, second, third, fourth] {
            session.disconnect().await.unwrap();
        }
        server.shutdown_handle().shutdown();
        server.await.unwrap();
        assert_eq!(errors.lock().unwrap().len(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_listener_shuts_down_active_sessions_and_incomplete_handshakes() {
    timeout(Duration::from_secs(10), async {
        let key = HostKey::generate().unwrap();
        let public_key = key.public_key();
        let (new_clients, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let endpoint = handler();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let mut config = config(key);
        config.nodelay = true;
        let running = server::listen(
            Arc::new(config),
            ("127.0.0.1", 0),
            Factory {
                handler: endpoint.clone(),
                new_clients,
                errors: Arc::clone(&errors),
            },
        )
        .await
        .unwrap();
        let addr = running.local_addr();
        let connect = async || {
            let mut client = client::connect(
                Arc::new(client::Config {
                    nodelay: true,
                    ..client::Config::default()
                }),
                addr,
                trusted(public_key),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate(USER, client::Method::Password(PASSWORD))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        };
        let (first, second) = tokio::join!(connect(), connect());
        let (first, second) = (first.start().unwrap(), second.start().unwrap());
        assert_eq!(first.context().peer_addr(), Some(addr));
        assert_eq!(second.context().peer_addr(), Some(addr));
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        for _ in 0..3 {
            assert!(accepted.recv().await.unwrap().ip().is_loopback());
        }

        let first_handle = first.handle();
        let pending_channel =
            tokio::spawn(async move { first_handle.open_channel("pending", 8, &[]).await });
        endpoint.pending_open.notified().await;
        running.shutdown_handle().shutdown();
        running.await.unwrap();
        assert!(pending_channel.await.unwrap().is_err());
        first.await.unwrap();
        second.await.unwrap();
        let mut banner = Vec::new();
        let closed = stalled.read_to_end(&mut banner).await;
        assert!(closed.is_ok() || closed.unwrap_err().kind() == ErrorKind::ConnectionReset);
        assert!(TcpStream::connect(addr).await.is_err());
        assert_eq!(*endpoint.end.lock().unwrap(), ["local", "local"]);
        assert!(errors.lock().unwrap().is_empty());
    })
    .await
    .unwrap();
}

/// Records every unrouted event the session delivers to the handler.
struct EventRecorder {
    key: [u8; 32],
    data: Arc<Mutex<Vec<u8>>>,
}

impl client::Handler for EventRecorder {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(self.key == key)
    }
}

impl session::Handler for EventRecorder {
    async fn event(&mut self, event: Event, _: &Context) -> io::Result<()> {
        // A slow handler lets the driver finish reading the whole burst
        // (data then disconnect) before the callbacks catch up.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        if let Event::Data { data, .. } = event {
            self.data.lock().unwrap().extend_from_slice(&data);
        }
        Ok(())
    }
}

/// The server writes its last bytes and disconnects in one burst.
struct SendThenDisconnect;

impl server::AuthPolicy for SendThenDisconnect {
    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == PASSWORD.as_bytes())
    }
}

impl session::Handler for SendThenDisconnect {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        context: &Context,
    ) -> io::Result<()> {
        let mut stream = request.accept(1024, b"").await?.into_io();
        stream.write_all(b"final output").await?;
        stream.flush().await?;
        context.handle().disconnect().await
    }
}

#[tokio::test]
async fn events_queued_before_the_driver_stops_still_reach_the_handler() {
    timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let pin = host.public_key();
        let data = Arc::new(Mutex::new(Vec::new()));
        let (a, b) = duplex(4096);
        let (client, server) = tokio::join!(
            async {
                let mut client = client::connect_over(
                    Arc::new(client::Config::default()),
                    a,
                    EventRecorder {
                        key: pin,
                        data: Arc::clone(&data),
                    },
                )
                .await
                .unwrap();
                assert!(
                    client
                        .authenticate(USER, client::Method::Password(PASSWORD))
                        .await
                        .unwrap()
                        .is_accepted()
                );
                client
            },
            server::accept_over(Arc::new(config(host)), b, None, SendThenDisconnect),
        );
        let client = client.start().unwrap();
        // The unrouted open reports through `Handler::event`.
        client.handle().open("tail", 1024, &[]).await.unwrap();
        let _ = client.await;
        let _ = server;
        assert_eq!(data.lock().unwrap().as_slice(), b"final output");
    })
    .await
    .unwrap();
}

struct Holder {
    held: Vec<Channel>,
}

impl server::AuthPolicy for Holder {
    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == PASSWORD.as_bytes())
    }
}

impl session::Handler for Holder {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let channel = request.accept(DEFAULT_WINDOW, &[]).await?;
        self.held.push(channel);
        Ok(())
    }
}

async fn holding_sessions(client_config: client::Config) -> (session::Session, session::Session) {
    let key = HostKey::generate().unwrap();
    let client_handler = trusted(key.public_key());
    let (left, right) = duplex(64 * 1024);
    let client = async {
        let mut client = client::connect_over(Arc::new(client_config), left, client_handler)
            .await
            .unwrap();
        assert!(
            client
                .authenticate(USER, client::Method::Password(PASSWORD))
                .await
                .unwrap()
                .is_accepted()
        );
        client
    };
    let (client, server) = tokio::join!(
        client,
        server::accept_over(
            Arc::new(config(key)),
            right,
            None,
            Holder { held: Vec::new() }
        )
    );
    (client.start().unwrap(), server.unwrap())
}

#[tokio::test]
async fn default_window_budget_allows_many_concurrent_channels() {
    timeout(Duration::from_secs(10), async {
        let (client, server) = holding_sessions(client::Config::default()).await;
        let mut channels = Vec::new();
        for _ in 0..32 {
            channels.push(client.handle().open_session().await.unwrap());
        }
        let error = client.handle().open_session().await.err().unwrap();
        assert!(error.to_string().contains("receive window budget"));
        // A smaller window that still does not fit is refused the same way.
        assert!(
            client
                .handle()
                .open_channel("session", 1, &[])
                .await
                .is_err()
        );
        drop(channels);
        client.disconnect().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_window_budget_limits_concurrent_channels() {
    timeout(Duration::from_secs(10), async {
        let config = client::Config {
            channel_window_budget: DEFAULT_WINDOW,
            ..Default::default()
        };
        let (client, server) = holding_sessions(config).await;
        let first = client.handle().open_session().await.unwrap();
        let error = client.handle().open_session().await.err().unwrap();
        assert!(error.to_string().contains("receive window budget"));
        drop(first);
        client.disconnect().await.unwrap();
        server.await.unwrap();

        let config = client::Config {
            channel_window_budget: 0,
            ..Default::default()
        };
        let (left, _right) = duplex(64);
        let error = client::connect_over(Arc::new(config), left, ())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    })
    .await
    .unwrap();
}

struct TwoPasswords;

impl session::Handler for TwoPasswords {}

impl server::AuthPolicy for TwoPasswords {
    async fn password_decision(&mut self, user: &str, password: &[u8]) -> io::Result<AuthDecision> {
        Ok(match password {
            b"first factor" if user == USER => AuthDecision::Reject {
                proceed_with_methods: Some(vec![AuthMethod::Password]),
                partial_success: true,
            },
            b"second factor" if user == USER => AuthDecision::Accept,
            _ => AuthDecision::reject(),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_passed_factor_is_answered_at_once_and_spends_no_rejection() {
    let mut server_config = server::Config::new(HostKey::generate().unwrap());
    server_config.authentication.rejection_delay = Duration::from_secs(3);
    server_config.authentication.max_rejections = std::num::NonZeroUsize::new(1);
    connected(server_config, TwoPasswords, async |mut client| {
        let start = tokio::time::Instant::now();
        assert_eq!(
            client
                .authenticate(USER, client::Method::Password("first factor"))
                .await
                .unwrap(),
            Outcome::Rejected {
                remaining_methods: vec!["password".into()],
                partial_success: true,
            }
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(
            client
                .authenticate(USER, client::Method::Password("second factor"))
                .await
                .unwrap()
                .is_accepted()
        );
    })
    .await;
}
