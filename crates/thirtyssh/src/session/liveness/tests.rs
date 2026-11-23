use super::*;
use crate::{
    auth::{self, Method, Policy},
    channel::{Connection, Event},
    client,
    keys::{Algorithm, Credential},
    server,
    session::{self, Context, IncomingChannel, Session},
    transport::{HostKey, Input, Transport},
    wire::Reader,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{DuplexStream, duplex},
    sync::Notify,
    task::yield_now,
    time::advance,
};

const USER: &str = "test-user";
const SECRET: &str = "test-password";
const SECOND: Duration = Duration::from_secs(1);

struct Password;
impl Policy for Password {
    fn password(&mut self, user: &str, password: &[u8]) -> bool {
        user == USER && password == SECRET.as_bytes()
    }
}

struct Pinned([u8; 32]);
impl session::Handler for Pinned {}
impl client::Handler for Pinned {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(key == self.0)
    }
}

async fn raw_peer(config: client::Config) -> (Session, Transport<DuplexStream>) {
    let key = HostKey::generate().unwrap();
    let (left, right) = duplex(8192);
    let (auth, peer) = tokio::join!(
        async {
            let mut auth = client::connect_over(Arc::new(config), left, Pinned(key.public_key()))
                .await
                .unwrap();
            assert!(
                auth.authenticate(USER, Method::Password(SECRET))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            auth
        },
        async {
            let transport = Transport::accept(right, &key).await.unwrap();
            auth::accept(transport, Password).await.unwrap().transport
        },
    );
    let session = auth.start().unwrap();
    session
        .handle()
        .global_notification("fixture-started@example.test", &[])
        .await
        .unwrap();
    let mut peer = peer;
    assert_eq!(peer.receive().await.unwrap()[0], 80);
    (session, peer)
}

async fn read_probe(peer: &mut Transport<DuplexStream>) {
    let bytes = peer.receive().await.unwrap();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.byte().unwrap(), 80);
    assert_eq!(reader.string().unwrap(), b"keepalive@openssh.com");
    assert!(reader.boolean().unwrap());
    reader.finish().unwrap();
}

fn assert_timeout(error: io::Error, reason: Timeout) {
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(
        error.get_ref().unwrap().downcast_ref::<Timeout>(),
        Some(&reason)
    );
}

#[tokio::test(start_paused = true)]
async fn any_authenticated_input_resets_the_unanswered_keepalive_deadline() {
    let (session, mut peer) = raw_peer(client::Config {
        keepalive_interval: Some(2 * SECOND),
        keepalive_max: 2,
        ..Default::default()
    })
    .await;
    let start = Instant::now();
    for expected in [2, 4] {
        read_probe(&mut peer).await;
        assert_eq!(start.elapsed(), expected * SECOND);
    }
    advance(SECOND).await;
    peer.send(&[2, 0, 0, 0, 0]).await.unwrap(); // SSH_MSG_IGNORE is authenticated input.
    for expected in [7, 9] {
        read_probe(&mut peer).await;
        assert_eq!(start.elapsed(), expected * SECOND);
    }
    advance(SECOND).await;
    assert!(!session.task.is_finished());
    assert_timeout(session.await.unwrap_err(), Timeout::Keepalive);
    assert_eq!(start.elapsed(), 11 * SECOND);
}

#[tokio::test(start_paused = true)]
async fn answered_keepalives_do_not_restart_the_idle_timer() {
    let (session, mut peer) = raw_peer(client::Config {
        inactivity_timeout: Some(5 * SECOND),
        keepalive_interval: Some(2 * SECOND),
        keepalive_max: 3,
        ..Default::default()
    })
    .await;
    let start = Instant::now();
    for expected in [2, 4] {
        read_probe(&mut peer).await;
        assert_eq!(start.elapsed(), expected * SECOND);
        peer.send(&[82]).await.unwrap(); // SSH_MSG_REQUEST_FAILURE answers the probe.
    }
    assert_timeout(session.await.unwrap_err(), Timeout::Inactivity);
    assert_eq!(start.elapsed(), 5 * SECOND);
}

#[tokio::test(start_paused = true)]
async fn only_regular_outbound_activity_restarts_the_idle_timer() {
    let (session, mut peer) = raw_peer(client::Config {
        inactivity_timeout: Some(5 * SECOND),
        keepalive_interval: Some(2 * SECOND),
        keepalive_max: 0,
        ..Default::default()
    })
    .await;
    let start = Instant::now();
    advance(SECOND).await;
    session
        .handle()
        .global_notification("ordinary-traffic@example.test", b"data")
        .await
        .unwrap();
    assert_eq!(peer.receive().await.unwrap()[0], 80);
    for expected in [2, 4] {
        read_probe(&mut peer).await;
        assert_eq!(start.elapsed(), expected * SECOND);
    }
    advance(SECOND).await;
    assert!(!session.task.is_finished());
    assert_timeout(session.await.unwrap_err(), Timeout::Inactivity);
    assert_eq!(start.elapsed(), 6 * SECOND);
}

#[tokio::test(start_paused = true)]
async fn the_watchdog_ends_a_stalled_rekey_and_releases_waiters() {
    let (session, mut peer) = raw_peer(client::Config {
        keepalive_interval: Some(2 * SECOND),
        keepalive_max: 1,
        ..Default::default()
    })
    .await;
    let start = Instant::now();
    let handle = session.handle();
    let rekey = tokio::spawn({
        let handle = handle.clone();
        async move { handle.rekey().await }
    });
    assert!(matches!(peer.read_input().await.unwrap(), Input::Packet(packet) if packet[0] == 20));
    assert_timeout(session.await.unwrap_err(), Timeout::Keepalive);
    assert_eq!(start.elapsed(), 4 * SECOND);
    assert_eq!(
        rekey.await.unwrap().unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
    assert_eq!(
        handle.ping().await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[tokio::test(start_paused = true)]
async fn unlimited_probes_pause_at_the_wire_request_limit_and_resume_after_a_reply() {
    let (session, mut peer) = raw_peer(client::Config {
        keepalive_interval: Some(SECOND),
        keepalive_max: 0,
        ..Default::default()
    })
    .await;
    for _ in 0..128 {
        read_probe(&mut peer).await;
    }
    advance(SECOND).await;
    yield_now().await;
    assert!(!session.task.is_finished());
    assert_eq!(
        session.handle().keepalive(true).await.unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    peer.send(&[82]).await.unwrap();
    read_probe(&mut peer).await;
    assert!(!session.task.is_finished());
    session.disconnect().await.unwrap();
}

struct BlockedCallback {
    entered: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct CallbackGuard(Arc<AtomicBool>);
impl Drop for CallbackGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl server::AuthPolicy for BlockedCallback {
    async fn password(&mut self, user: &str, secret: &[u8]) -> io::Result<bool> {
        Ok(Password.password(user, secret))
    }
}
impl session::Handler for BlockedCallback {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let _channel = request.accept(1024, &[]).await?;
        let _guard = CallbackGuard(Arc::clone(&self.dropped));
        self.entered.notify_one();
        pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn server_default_idle_timeout_cancels_the_callback_and_closes_the_transport() {
    let key = HostKey::generate().unwrap();
    let pin = key.public_key();
    let (left, right) = duplex(8192);
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let (peer, server) = tokio::join!(
        async {
            let transport = Transport::connect(left, |key| *key == pin).await.unwrap();
            auth::login(transport, USER, auth::Method::Password(SECRET))
                .await
                .unwrap()
        },
        server::accept_over(
            Arc::new(server::Config::new(key)),
            right,
            None,
            BlockedCallback {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            }
        ),
    );
    let server = server.unwrap();
    let mut peer = Connection::new(peer);
    let channel = peer.open("session", 1024, &[]).await.unwrap();
    assert!(
        matches!(peer.next_event().await.unwrap(), Event::Opened { channel: opened, .. } if opened == channel)
    );
    entered.notified().await;
    let start = Instant::now();
    advance(599 * SECOND).await;
    assert!(!dropped.load(Ordering::Acquire));
    assert_timeout(server.await.unwrap_err(), Timeout::Inactivity);
    // The session first lets the stuck callback drain queued events for up to
    // `shutdown_timeout` (five seconds by default), then cancels it.
    assert_eq!(start.elapsed(), (600 + 5) * SECOND);
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(
        peer.next_event().await.unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
}

#[tokio::test(start_paused = true)]
async fn both_roles_keep_working_through_a_blocked_callback_and_rekey() {
    let key = HostKey::generate().unwrap();
    let pin = key.public_key();
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let (left, right) = duplex(8192);
    let mut config = server::Config::new(key);
    config.keepalive_interval = Some(SECOND);
    config.keepalive_max = 2;
    let (client, server) = tokio::join!(
        async {
            let mut client = client::connect_over(
                Arc::new(client::Config {
                    keepalive_interval: Some(SECOND),
                    keepalive_max: 2,
                    ..Default::default()
                }),
                left,
                Pinned(pin),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate(USER, Method::Password(SECRET))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        },
        server::accept_over(
            Arc::new(config),
            right,
            None,
            BlockedCallback {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped)
            }
        ),
    );
    let client = client.start().unwrap();
    let server = server.unwrap();
    let channel = client.handle().open_session().await.unwrap();
    entered.notified().await;
    client.handle().rekey().await.unwrap();
    for _ in 0..12 {
        advance(SECOND).await;
        yield_now().await;
        assert!(!client.task.is_finished() && !server.task.is_finished());
    }
    for handle in [client.handle(), server.handle()] {
        handle.ping().await.unwrap();
    }
    assert!(!dropped.load(Ordering::Acquire));
    client.disconnect().await.unwrap();
    server.await.unwrap();
    assert!(dropped.load(Ordering::Acquire));
    drop(channel);
}
