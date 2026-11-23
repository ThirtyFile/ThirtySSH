//! SSH server setup for caller-owned streams and TCP listeners.
use crate::{
    algorithms::TransportPreferences,
    auth::{self, Authenticated},
    identification::{self, Role},
    keys::{Algorithm, SIGNATURE_ALGORITHMS, server_host_algorithms},
    runtime::{Instant, timeout, timeout_at},
    session,
    transport::{DisconnectRequest, HostKey, HostKeys, Identified, Limits, Transport},
};
pub use crate::{
    auth::{AsyncPolicy as AuthPolicy, ServerOptions},
    kex::gex::{GexGroup, GexGroupLookup},
    kex::modp,
    session::Session as RunningSession,
};
use std::{
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(not(target_family = "wasm"))]
mod tcp;
#[cfg(not(target_family = "wasm"))]
pub use tcp::{Connections, Listening, ShutdownHandle, listen, listen_on, serve_until};

#[derive(Clone)]
pub struct Config<K = HostKey> {
    /// An Ed25519 key, a typed private key, or a shared collection of host keys.
    pub host_key: K,
    pub identification: identification::Settings,
    pub limits: Limits,
    /// Maximum channel payload, in bytes, advertised to the peer.
    pub maximum_packet_size: u32,
    /// Capacity of the channel mailbox. Additional packets already within the
    /// receive window are retained in order. `None` uses the receive window.
    pub channel_buffer_size: Option<usize>,
    /// Total receive window allowed across the channels of one connection
    /// that have their own reader. It bounds the unread data the peer can
    /// make this connection buffer. Opening or accepting a channel whose
    /// window does not fit fails.
    pub channel_window_budget: u32,
    /// Capacity of the authenticated session's command queue.
    pub command_buffer_size: usize,
    pub preferred: TransportPreferences,
    /// Resolve a GEX request before each initial or subsequent key exchange.
    pub gex_group_lookup: Option<GexGroupLookup>,
    /// Advertise the algorithms in this list that the configured keys support.
    pub host_key_algorithms: Vec<Algorithm>,
    /// Signature algorithms accepted for public-key user authentication and
    /// advertised to clients in `server-sig-algs`. A certificate is accepted
    /// when the algorithm of its key is listed. `ssh-rsa` and the
    /// feature-gated `ssh-dss` are accepted only when added here.
    pub user_signature_algorithms: Vec<Algorithm>,
    pub authentication: ServerOptions,
    /// Advertise the standard Agent forwarding names. The handler still
    /// decides which sessions may use forwarding.
    pub advertise_agent_forwarding: bool,
    pub handshake_timeout: Duration,
    pub authentication_timeout: Duration,
    pub shutdown_timeout: Duration,
    /// Close an authenticated session after this long without use. Keepalive
    /// requests, replies to requests and transport filler in either direction
    /// do not count as use.
    pub inactivity_timeout: Option<Duration>,
    /// Probe after this long without authenticated input from the peer.
    pub keepalive_interval: Option<Duration>,
    /// Unanswered keepalives allowed before timeout. Zero disables the limit.
    pub keepalive_max: usize,
    pub nodelay: bool,
    /// Connections a TCP listener serves at once, authenticated or not.
    /// Further connections wait in the listen backlog.
    pub max_connections: std::num::NonZeroUsize,
    /// Connections a TCP listener allows before authentication completes.
    /// Further connections wait in the listen backlog, so clients that never
    /// authenticate cannot use up `max_connections`.
    pub max_unauthenticated_connections: std::num::NonZeroUsize,
    /// Unauthenticated connections a TCP listener allows from one source: an
    /// IPv4 address or an IPv6 /64 network. Connections beyond the limit are
    /// closed at once. Use `None` when clients share an address, for example
    /// behind a proxy.
    pub max_unauthenticated_per_source: Option<std::num::NonZeroUsize>,
}

impl<K> Config<K> {
    pub fn new(host_key: K) -> Self {
        Self {
            host_key,
            identification: identification::Settings::default(),
            limits: Limits::default(),
            maximum_packet_size: crate::channel::MAX_DATA,
            channel_buffer_size: None,
            channel_window_budget: crate::channel::DEFAULT_WINDOW_BUDGET,
            command_buffer_size: crate::channel::DEFAULT_COMMAND_CAPACITY,
            preferred: TransportPreferences::default(),
            gex_group_lookup: None,
            host_key_algorithms: server_host_algorithms(),
            user_signature_algorithms: SIGNATURE_ALGORITHMS.to_vec(),
            authentication: ServerOptions::default(),
            advertise_agent_forwarding: false,
            handshake_timeout: Duration::from_secs(10),
            authentication_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: None,
            keepalive_max: 3,
            nodelay: false,
            max_connections: std::num::NonZeroUsize::new(128).expect("positive connection limit"),
            max_unauthenticated_connections: std::num::NonZeroUsize::new(64)
                .expect("positive connection limit"),
            max_unauthenticated_per_source: std::num::NonZeroUsize::new(16),
        }
    }

    fn session_options(&self) -> session::Options {
        session::Options {
            maximum_packet_size: self.maximum_packet_size,
            channel_buffer_size: self.channel_buffer_size,
            channel_window_budget: self.channel_window_budget,
            command_capacity: self.command_buffer_size,
            liveness: session::Liveness {
                inactivity_timeout: self.inactivity_timeout,
                keepalive_interval: self.keepalive_interval,
                keepalive_max: self.keepalive_max,
            },
            shutdown_timeout: self.shutdown_timeout,
        }
    }

    fn validated_session_options(&self) -> io::Result<session::Options> {
        let options = self.session_options();
        options.validate()?;
        self.limits.validate()?;
        Ok(options)
    }
}

/// A server handler combines authentication policy with active callbacks.
pub trait Handler: AuthPolicy + session::Handler {}
impl<H: AuthPolicy + session::Handler> Handler for H {}

/// A server stream whose identification strings have been exchanged.
pub struct PendingSession<S> {
    stream: Identified<S>,
    config: Arc<Config<HostKeys>>,
    handshake_deadline: Instant,
    peer_addr: Option<SocketAddr>,
}

/// Exchange identification strings and leave the buffered stream ready for
/// key exchange. Authentication and channel processing can run in a task.
pub async fn prepare_stream<S: AsyncRead + AsyncWrite + Unpin>(
    config: Arc<Config<HostKeys>>,
    stream: S,
) -> io::Result<PendingSession<S>> {
    config.validated_session_options()?;
    let handshake_deadline = Instant::now()
        .checked_add(config.handshake_timeout)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "SSH handshake timeout exceeds timer range",
            )
        })?;
    let stream = timeout_at(
        handshake_deadline,
        Identified::exchange(stream, Role::Server, &config.identification),
    )
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "SSH server identification timed out"))??;
    Ok(PendingSession {
        stream,
        config,
        handshake_deadline,
        peer_addr: None,
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> PendingSession<S> {
    /// State the address the caller vouches for as the peer's. It is used
    /// for certificate source-address checks and reported to the handler.
    /// Without it, certificates restricted to source addresses are refused.
    pub fn with_peer_addr(mut self, peer_addr: SocketAddr) -> Self {
        self.peer_addr = Some(peer_addr);
        self
    }

    /// Complete key exchange and serve authentication. An explicit shutdown
    /// sends a disconnect at the next protected packet boundary.
    pub async fn authenticate_until_disconnect(
        self,
        mut handler: impl Handler,
        disconnect: impl Future<Output = DisconnectRequest>,
    ) -> io::Result<Option<RunningSession>> {
        let Self {
            stream,
            config,
            handshake_deadline,
            peer_addr,
        } = self;
        let mut transport = timeout_at(
            handshake_deadline,
            Transport::accept_identified(
                stream,
                config.host_key.clone(),
                config.preferred.clone(),
                &config.host_key_algorithms,
                handler
                    .gex_group_lookup()
                    .or_else(|| config.gex_group_lookup.clone()),
            ),
        )
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "SSH server handshake timed out"))??;
        transport.apply_limits(&config.limits)?;
        transport.configure_server_extensions(
            config.advertise_agent_forwarding,
            &config.user_signature_algorithms,
        );
        let authenticated = timeout(
            config.authentication_timeout,
            auth::accept_until_disconnect(
                transport,
                &mut handler,
                &config.authentication,
                peer_addr.map(|address| address.ip()),
                disconnect,
            ),
        )
        .await
        .map_err(|_| {
            io::Error::new(ErrorKind::TimedOut, "SSH server authentication timed out")
        })??;
        authenticated
            .map(|authenticated| {
                session::start(authenticated, handler, peer_addr, config.session_options())
            })
            .transpose()
    }
}

/// Run the server handshake and user authentication over a stream the caller
/// accepted, then start the session. `peer_addr` is the address the caller
/// vouches for. It is used for certificate source-address checks and
/// reported to the handler through the session context.
pub async fn accept_over<S, H>(
    config: Arc<Config<impl Clone + Into<HostKeys>>>,
    stream: S,
    peer_addr: Option<SocketAddr>,
    handler: H,
) -> io::Result<RunningSession>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    start_stream(config, stream, peer_addr, handler).await
}

async fn start_stream<S, H>(
    config: Arc<Config<impl Clone + Into<HostKeys>>>,
    stream: S,
    address: Option<SocketAddr>,
    mut handler: H,
) -> io::Result<RunningSession>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    let options = config.validated_session_options()?;
    let authenticated = establish(&config, stream, address, &mut handler).await?;
    session::start(authenticated, handler, address, options)
}

async fn establish<S, H>(
    config: &Config<impl Clone + Into<HostKeys>>,
    stream: S,
    address: Option<SocketAddr>,
    handler: &mut H,
) -> io::Result<Authenticated<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let mut transport = timeout(
        config.handshake_timeout,
        Transport::accept_with_settings(
            stream,
            config.host_key.clone().into(),
            config.preferred.clone(),
            &config.host_key_algorithms,
            handler
                .gex_group_lookup()
                .or_else(|| config.gex_group_lookup.clone()),
            &config.identification,
        ),
    )
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "SSH server handshake timed out"))??;
    transport.apply_limits(&config.limits)?;
    transport.configure_server_extensions(
        config.advertise_agent_forwarding,
        &config.user_signature_algorithms,
    );
    timeout(
        config.authentication_timeout,
        auth::accept_with_peer_addr(
            transport,
            handler,
            &config.authentication,
            address.map(|address| address.ip()),
        ),
    )
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "SSH server authentication timed out"))?
}
