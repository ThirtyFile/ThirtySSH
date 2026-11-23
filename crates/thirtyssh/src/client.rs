//! SSH client setup and authentication.
use crate::{
    algorithms::TransportPreferences,
    auth::{self, BannerObserver, CallbackActions},
    identification,
    keys::{Algorithm, CertificateSignaturePolicy, Credential, SIGNATURE_ALGORITHMS},
    runtime::timeout,
    session,
    transport::{Activity, ClientHandshakeOptions, CompletedKeyExchange, Limits, Transport},
};
pub use crate::{
    auth::{
        AuthBannerDisconnect, Banner, InteractiveResponse, KeyExchangeDisconnect, Method, Outcome,
    },
    extensions::ServerSignatureAlgorithms,
    session::Session,
};
use std::{
    future::{Future, ready},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};

#[derive(Clone, Debug)]
pub struct Config {
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
    pub preferred: TransportPreferences,
    /// Host signature algorithms in client preference order.
    pub host_key_algorithms: Vec<Algorithm>,
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
    /// Begin the connection protocol after host verification, for peers that
    /// expect no SSH user authentication service.
    pub anonymous: bool,
    pub nodelay: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identification: identification::Settings::default(),
            limits: Limits::default(),
            maximum_packet_size: crate::channel::MAX_DATA,
            channel_buffer_size: None,
            channel_window_budget: crate::channel::DEFAULT_WINDOW_BUDGET,
            preferred: TransportPreferences::default(),
            host_key_algorithms: SIGNATURE_ALGORITHMS.to_vec(),
            handshake_timeout: Duration::from_secs(10),
            authentication_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            inactivity_timeout: None,
            keepalive_interval: None,
            keepalive_max: 3,
            anonymous: false,
            nodelay: false,
        }
    }
}

impl Config {
    fn session_options(&self) -> session::Options {
        session::Options {
            maximum_packet_size: self.maximum_packet_size,
            channel_buffer_size: self.channel_buffer_size,
            channel_window_budget: self.channel_window_budget,
            command_capacity: crate::channel::DEFAULT_COMMAND_CAPACITY,
            liveness: session::Liveness {
                inactivity_timeout: self.inactivity_timeout,
                keepalive_interval: self.keepalive_interval,
                keepalive_max: self.keepalive_max,
            },
            shutdown_timeout: self.shutdown_timeout,
        }
    }
}

/// What a client decides for itself: whether to trust the host, and what to
/// do with what the server says before login. Session callbacks come from
/// the [`session::Handler`] supertrait.
pub trait Handler: session::Handler {
    /// Choose the issuer signature policy for this connection. Host trust
    /// still requires `verify_host` to accept the certificate.
    fn certificate_signature_policy(&self) -> CertificateSignaturePolicy {
        CertificateSignaturePolicy::default()
    }

    /// Decide whether this is the host the application meant to reach. The
    /// key or certificate has already proved itself: its signature over the
    /// exchange, and a certificate's own signature, have been verified with
    /// the negotiated `algorithm`. The default trusts no host.
    fn verify_host(
        &mut self,
        _host: &Credential,
        _algorithm: &Algorithm,
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    /// A message the server sent before login completed.
    fn banner(
        &mut self,
        _banner: &Banner,
        _connection: &mut PreAuth,
    ) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }

    /// Report completed key exchanges: to `early_key_exchange` until the
    /// session starts, and to `session::Handler::key_exchange_done` afterwards.
    fn observe_key_exchanges(&self) -> bool {
        false
    }

    /// A key exchange completed before the session started. Called only when
    /// `observe_key_exchanges` is enabled.
    fn early_key_exchange(
        &mut self,
        _exchange: &CompletedKeyExchange,
        _connection: &mut PreAuth,
    ) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }
}

impl Handler for () {}

/// The connection as a client callback sees it before login: who the peer
/// says it is, and the transport actions the callback may ask for.
pub struct PreAuth {
    peer_identification: Arc<[u8]>,
    actions: CallbackActions,
}

impl PreAuth {
    fn new(peer_identification: &[u8]) -> Self {
        Self {
            peer_identification: Arc::from(peer_identification),
            actions: CallbackActions::default(),
        }
    }

    pub fn peer_identification(&self) -> Arc<[u8]> {
        Arc::clone(&self.peer_identification)
    }

    pub fn request_disconnect(&mut self, request: crate::transport::DisconnectRequest) {
        self.actions.disconnect.get_or_insert(request);
    }

    pub fn request_rekey(&mut self) {
        self.actions.rekey = true;
    }
}

struct HandlerObserver<'a, H> {
    handler: &'a mut H,
    authentication_timeout: Duration,
    handshake_timeout: Duration,
}

impl<H: Handler> BannerObserver for HandlerObserver<'_, H> {
    fn banner_timeout(&self) -> Option<Duration> {
        Some(self.authentication_timeout)
    }

    async fn received_banner(
        &mut self,
        banner: &Banner,
        peer_identification: &[u8],
    ) -> io::Result<CallbackActions> {
        let mut context = PreAuth::new(peer_identification);
        self.handler.banner(banner, &mut context).await?;
        Ok(context.actions)
    }

    fn key_exchange_timeout(&self) -> Option<Duration> {
        Some(self.handshake_timeout)
    }

    async fn key_exchange_done(
        &mut self,
        exchange: &CompletedKeyExchange,
        peer_identification: &[u8],
    ) -> io::Result<CallbackActions> {
        let mut context = PreAuth::new(peer_identification);
        self.handler
            .early_key_exchange(exchange, &mut context)
            .await?;
        if exchange.initial {
            // The initial callback precedes the application's first usable session.
            context.actions.rekey = false;
        }
        Ok(context.actions)
    }
}

/// A client that has completed host verification. Authentication requests
/// share the same stream and can be retried after a rejection.
pub struct Client<S, H> {
    authentication: auth::Client<S>,
    handler: H,
    config: Arc<Config>,
    peer_addr: Option<SocketAddr>,
    inactivity: Option<PreAuthInactivity>,
}

struct PreAuthInactivity {
    liveness: session::Liveness,
    traffic: watch::Receiver<Activity>,
    expired: bool,
}

struct AuthTimer<'a> {
    inactivity: Option<&'a mut PreAuthInactivity>,
    authentication_timeout: Duration,
}

impl AuthTimer<'_> {
    async fn watch<T>(self, operation: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        let Some(inactivity) = self.inactivity else {
            return operation.await;
        };
        tokio::pin!(operation);
        tokio::select! {
            biased;
            result = inactivity.liveness.watchdog(inactivity.traffic.clone()) => {
                inactivity.expired = true;
                result.map(|never| match never {})
            }
            result = &mut operation => result,
        }
    }

    fn authenticate<T>(
        self,
        operation: impl Future<Output = io::Result<T>>,
    ) -> impl Future<Output = io::Result<T>> {
        let timed = timeout(self.authentication_timeout, operation);
        self.watch(async move {
            timed
                .await
                .map_err(|_| timed_out("SSH authentication timed out"))?
        })
    }
}

#[cfg(not(target_family = "wasm"))]
pub async fn connect<H: Handler>(
    config: Arc<Config>,
    address: impl tokio::net::ToSocketAddrs,
    handler: H,
) -> io::Result<Client<tokio::net::TcpStream, H>> {
    config.session_options().validate()?;
    config.limits.validate()?;
    let stream = timeout(
        config.handshake_timeout,
        tokio::net::TcpStream::connect(address),
    )
    .await
    .map_err(|_| timed_out("SSH TCP connection timed out"))??;
    stream.set_nodelay(config.nodelay)?;
    let peer = stream.peer_addr()?;
    establish(config, stream, handler, Some(peer)).await
}

/// Run the client handshake over a stream the caller has already
/// established, and verify the host.
pub async fn connect_over<S, H>(
    config: Arc<Config>,
    stream: S,
    handler: H,
) -> io::Result<Client<S, H>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    config.session_options().validate()?;
    config.limits.validate()?;
    establish(config, stream, handler, None).await
}

async fn establish<S, H>(
    config: Arc<Config>,
    stream: S,
    mut handler: H,
    peer_addr: Option<SocketAddr>,
) -> io::Result<Client<S, H>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let certificate_signatures = handler.certificate_signature_policy();
    let observe_key_exchanges = handler.observe_key_exchanges();
    let verifier = &mut handler;
    let mut transport = timeout(
        config.handshake_timeout,
        Transport::connect_with_negotiated_host_verifier(
            stream,
            |identity, algorithm| async move { verifier.verify_host(&identity, &algorithm).await },
            config.preferred.clone(),
            &config.host_key_algorithms,
            certificate_signatures,
            ClientHandshakeOptions {
                identification: &config.identification,
                observe_key_exchanges,
                inactivity_timeout: config.inactivity_timeout,
            },
        ),
    )
    .await
    .map_err(|_| timed_out("SSH client handshake timed out"))??;
    transport.apply_limits(&config.limits)?;
    // Automatic keepalive requests begin after authentication. The inactivity
    // watchdog still observes traffic while the client is waiting to log in.
    let inactivity = config
        .inactivity_timeout
        .filter(|_| !config.anonymous)
        .map(|duration| PreAuthInactivity {
            liveness: session::Liveness {
                inactivity_timeout: Some(duration),
                keepalive_interval: None,
                keepalive_max: 0,
            },
            traffic: transport.monitor_activity(),
            expired: false,
        });
    let authentication = if config.anonymous {
        auth::Client::new_anonymous(transport)
    } else {
        auth::Client::new(transport)
    };
    let mut client = Client {
        authentication,
        handler,
        config,
        peer_addr,
        inactivity,
    };
    let (authentication, mut observer, timer) = client.auth_parts();
    timer
        .watch(authentication.dispatch_key_exchanges(&mut observer))
        .await?;
    Ok(client)
}

impl<S: AsyncRead + AsyncWrite + Unpin, H: Handler> Client<S, H> {
    /// Observe `server-sig-algs` while this connection handles traffic. The
    /// observer stays attached when the client starts its authenticated session.
    pub fn watch_server_signature_algorithms(&mut self) -> ServerSignatureAlgorithms {
        self.authentication.watch_server_signature_algorithms()
    }

    /// Select the standard Agent forwarding names if the peer has advertised
    /// them. Call after user authentication to observe its announcement.
    pub fn agent_forwarding(&self) -> crate::forward::AgentForwarding {
        use crate::forward::AgentForwarding;
        if self.authentication.supports_standard_agent_forwarding() {
            AgentForwarding::Standard
        } else {
            AgentForwarding::OpenSsh
        }
    }

    /// Wait for a local command while handling peer transport traffic between
    /// authentication attempts. The command future may be polled repeatedly.
    pub async fn wait_for_command<T>(&mut self, command: impl Future<Output = T>) -> io::Result<T> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        timer
            .watch(authentication.wait_for_command(command, &mut observer))
            .await
    }

    /// Complete a key exchange while the connection is waiting for user authentication.
    pub async fn rekey(&mut self) -> io::Result<()> {
        self.check()?;
        let limit = self.config.handshake_timeout;
        let (authentication, mut observer, timer) = self.auth_parts();
        timer
            .watch(async {
                timeout(limit, authentication.rekey(&mut observer))
                    .await
                    .map_err(|_| timed_out("SSH client rekey timed out"))?
            })
            .await
    }

    /// Send a disconnect before starting the authenticated session.
    pub async fn disconnect_with(
        self,
        reason: u32,
        description: &str,
        language: &str,
    ) -> io::Result<()> {
        let packet = crate::transport::disconnect_packet(reason, description, language)?;
        timeout(
            self.config.shutdown_timeout,
            self.authentication.disconnect_with_packet(&packet),
        )
        .await
        .map_err(|_| timed_out("SSH shutdown timed out"))?
    }

    /// Whether a timeout, an interrupted callback or a transport failure has
    /// made this connection unusable for further authentication.
    pub fn is_unusable(&self) -> bool {
        self.inactivity_expired() || self.authentication.is_unusable()
    }

    /// Make one authentication request with a secret held in memory: a
    /// password, a private key, or a private key with its certificate.
    pub async fn authenticate(
        &mut self,
        user: &str,
        method: impl Into<auth::Method<'_>>,
    ) -> io::Result<Outcome> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        let attempt = timer
            .authenticate(authentication.authenticate_observed(user, method.into(), &mut observer))
            .await?;
        Ok(attempt.result)
    }

    /// Authenticate with a key held by an agent, a hardware token or another
    /// external signer. The signer is consulted only after the server has
    /// said it would accept the credential.
    pub async fn authenticate_with(
        &mut self,
        user: &str,
        credential: &Credential,
        algorithm: Option<Algorithm>,
        signer: &mut impl auth::Signer,
    ) -> io::Result<Outcome> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        let attempt = timer
            .authenticate(authentication.authenticate_with_observed(
                user,
                credential,
                algorithm,
                signer,
                &mut observer,
            ))
            .await?;
        Ok(attempt.result)
    }

    /// Begin keyboard-interactive authentication, or abandon an open
    /// challenge and start over.
    pub async fn keyboard_interactive(
        &mut self,
        user: &str,
        submethods: &str,
    ) -> io::Result<InteractiveResponse> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        let attempt = timer
            .authenticate(authentication.keyboard_interactive_observed(
                user,
                submethods,
                &mut observer,
            ))
            .await?;
        Ok(attempt.response)
    }

    /// Answer the open challenge, one answer per prompt and in prompt order.
    pub async fn answer(&mut self, answers: &[String]) -> io::Result<InteractiveResponse> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        let attempt = timer
            .authenticate(authentication.answer_observed(answers, &mut observer))
            .await?;
        Ok(attempt.response)
    }

    /// Authenticate through a GSSAPI security context the application owns.
    pub async fn gssapi(
        &mut self,
        user: &str,
        mechanisms: &[Vec<u8>],
        context: &mut impl auth::GssContext,
    ) -> io::Result<Outcome> {
        self.check()?;
        let (authentication, mut observer, timer) = self.auth_parts();
        let attempt = timer
            .authenticate(authentication.gssapi_observed(user, mechanisms, context, &mut observer))
            .await?;
        Ok(attempt.result)
    }

    fn auth_parts(&mut self) -> (&mut auth::Client<S>, HandlerObserver<'_, H>, AuthTimer<'_>) {
        let limit = self.config.authentication_timeout;
        (
            &mut self.authentication,
            HandlerObserver {
                handler: &mut self.handler,
                authentication_timeout: limit,
                handshake_timeout: self.config.handshake_timeout,
            },
            AuthTimer {
                inactivity: self.inactivity.as_mut(),
                authentication_timeout: limit,
            },
        )
    }

    /// Start channel handling after successful authentication.
    pub fn start(self) -> io::Result<Session>
    where
        S: Send + 'static,
    {
        self.check()?;
        let connection = self.authentication.into_authenticated()?;
        session::start(
            connection,
            self.handler,
            self.peer_addr,
            self.config.session_options(),
        )
    }

    fn check(&self) -> io::Result<()> {
        if self.inactivity_expired() {
            Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "SSH client timed out before authentication completed",
            ))
        } else if self.authentication.interrupted_callback() {
            Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "SSH client callback was interrupted before authentication completed",
            ))
        } else {
            Ok(())
        }
    }

    fn inactivity_expired(&self) -> bool {
        self.inactivity.as_ref().is_some_and(|idle| idle.expired)
    }
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::TimedOut, message)
}
