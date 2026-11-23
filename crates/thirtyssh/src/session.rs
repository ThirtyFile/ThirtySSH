//! Application callbacks and lifecycle for an authenticated SSH connection.
mod liveness;
mod request;
use crate::{
    auth::Authenticated,
    channel::{
        Bytes, Channel, ChannelId, Connection, Event, GlobalReply, GlobalRequest, Inbox,
        OpenFailure,
        driver::{Handle, SessionEvent},
        validate_maximum_packet_size,
    },
    clear_packet::invalid,
    forward::{AgentForwarding, TcpipOpen, X11Open, streamlocal::StreamlocalOpen},
    runtime::timeout,
    transport::{CompletedKeyExchange, PeerDisconnect},
};
pub(crate) use liveness::Liveness;
pub use liveness::Timeout;
pub use request::{PtyRequest, Request, SessionRequest, X11Request};
use std::{
    future::{Future, ready},
    io::{self, ErrorKind},
    net::SocketAddr,
    ops::ControlFlow,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tokio::sync::oneshot::Receiver as JoinHandle;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tokio::task::JoinHandle;

/// Authenticated connection information and channel commands.
#[derive(Clone)]
pub struct Context {
    handle: Handle,
    username: Arc<str>,
    peer_addr: Option<SocketAddr>,
    peer_identification: Arc<[u8]>,
}

impl Context {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// The peer's identification line, without its line ending.
    pub fn peer_identification(&self) -> Arc<[u8]> {
        Arc::clone(&self.peer_identification)
    }

    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

/// A peer's channel-open request. Dropping an unanswered request refuses it.
pub struct IncomingChannel {
    id: ChannelId,
    kind: Bytes,
    fields: Bytes,
    owner: Arc<IncomingOpenOwner>,
}

struct IncomingOpenOwner {
    abandoned: Arc<AtomicBool>,
    claimed: AtomicBool,
    handle: Handle,
}

impl IncomingOpenOwner {
    fn try_claim(&self) -> bool {
        !self.claimed.swap(true, Ordering::AcqRel)
    }
}

impl Drop for IncomingOpenOwner {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::Release);
        self.handle.wake();
    }
}

/// The typed channel-open payload. Extension names retain their exact fields
/// so applications can implement additional channels with the same callback.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenType<'a> {
    Session,
    X11(X11Open<'a>),
    Agent(AgentForwarding),
    Tcpip(TcpipOpen<'a>),
    Streamlocal(StreamlocalOpen<'a>),
    Custom { name: &'a [u8], fields: &'a [u8] },
}

impl IncomingChannel {
    pub fn id(&self) -> ChannelId {
        self.id
    }

    fn claim(&self) -> io::Result<()> {
        if self.owner.try_claim() {
            Ok(())
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SSH channel open already answered",
            ))
        }
    }

    pub fn kind(&self) -> &[u8] {
        &self.kind
    }

    pub fn fields(&self) -> &[u8] {
        &self.fields
    }

    pub fn open_type(&self) -> io::Result<OpenType<'_>> {
        if self.kind() == b"session" {
            if !self.fields().is_empty() {
                return Err(invalid("unexpected SSH session open fields"));
            }
            return Ok(OpenType::Session);
        }
        if let Some(open) = self.tcpip()? {
            return Ok(OpenType::Tcpip(open));
        }
        if let Some(open) = self.streamlocal()? {
            return Ok(OpenType::Streamlocal(open));
        }
        if let Some(open) = self.x11()? {
            return Ok(OpenType::X11(open));
        }
        if let Some(protocol) = self.agent_forwarding()? {
            return Ok(OpenType::Agent(protocol));
        }
        Ok(OpenType::Custom {
            name: self.kind(),
            fields: self.fields(),
        })
    }

    pub async fn accept(self, window: u32, fields: &[u8]) -> io::Result<Channel> {
        self.claim()?;
        self.owner
            .handle
            .accept_channel(self.id, window, fields)
            .await
    }

    /// Create local endpoints while the peer's open request is pending.
    /// The reader is activated on acceptance or closed on refusal.
    pub fn prepare(self, window: u32) -> io::Result<(Channel, ChannelOpenReply)> {
        let (channel, inbox) = self.owner.handle.prepare_channel(self.id, window)?;
        Ok((
            channel,
            ChannelOpenReply {
                request: self,
                window,
                inbox,
            },
        ))
    }

    pub async fn refuse(self, reason: u32) -> io::Result<()> {
        self.refuse_with(OpenFailure::new(reason)).await
    }

    pub async fn refuse_with(self, failure: OpenFailure) -> io::Result<()> {
        self.claim()?;
        self.owner.handle.refuse_with(self.id, failure).await
    }
}

/// Decision for an incoming channel whose local endpoints were prepared.
/// Dropping it without accepting or refusing the request refuses the channel.
pub struct ChannelOpenReply {
    request: IncomingChannel,
    window: u32,
    inbox: Inbox,
}

impl ChannelOpenReply {
    pub async fn accept(self, fields: &[u8]) -> io::Result<()> {
        let Self {
            request,
            window,
            inbox,
        } = self;
        request.claim()?;
        request
            .owner
            .handle
            .accept_prepared(request.id, window, fields, inbox)
            .await
    }

    pub async fn refuse(self, failure: OpenFailure) -> io::Result<()> {
        self.request.refuse_with(failure).await
    }
}

#[derive(Debug)]
pub enum End<'a> {
    LocalShutdown,
    PeerDisconnect(&'a PeerDisconnect),
    Error(&'a io::Error),
}

/// An inbound global request being processed by a session handler.
pub struct IncomingGlobalRequest<'a> {
    request: GlobalRequest,
    context: &'a Context,
    answered: bool,
}

impl IncomingGlobalRequest<'_> {
    pub fn request(&self) -> &GlobalRequest {
        &self.request
    }

    /// Send the reply before performing follow-up operations such as opening
    /// channels from a newly approved listener. For a notification this is a no-op.
    pub async fn reply(&mut self, reply: GlobalReply) -> io::Result<()> {
        if let Some(id) = self.request.reply_id {
            if self.answered {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "SSH global request already answered",
                ));
            }
            self.context.handle.global_reply(id, reply).await?;
        }
        self.answered = true;
        Ok(())
    }
}

/// Session callbacks run in order, with transport I/O progressing independently.
///
/// The next callback starts only when the current one returns. Events wait
/// in a small queue meanwhile, and channel data, window adjustments and
/// replies keep flowing past them, so a callback may open a channel or wait
/// for a reply. Once the queue fills, the connection stops reading until a
/// callback returns. Work that lasts as long as a channel therefore belongs
/// in a spawned task.
pub trait Handler: Send + 'static {
    /// Called after authentication, before dispatching the first channel event.
    fn started(&mut self, _session: &Context) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }

    /// Called after each key exchange once the session is running, when the
    /// client handler enables `observe_key_exchanges`. A key exchange that
    /// completed before authentication is reported with `initial` set.
    fn key_exchange_done(
        &mut self,
        _exchange: CompletedKeyExchange,
        _session: &Context,
    ) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }

    /// Also deliver events from channels with their own receive queue. The
    /// channel reader still owns receive credit. Callbacks run through the
    /// same bounded event queue used by unrouted channels.
    fn observe_routed_channel_events(&self) -> bool {
        false
    }

    /// Dispatch channel requests through the ordered session callback, which
    /// owns the replies requested by those events.
    fn handle_routed_channel_requests(&self) -> bool {
        false
    }

    fn channel_open(
        &mut self,
        request: IncomingChannel,
        _session: &Context,
    ) -> impl Future<Output = io::Result<()>> + Send {
        let reason = if matches!(request.open_type(), Ok(OpenType::Custom { .. })) {
            3
        } else {
            1
        };
        request.refuse(reason)
    }

    /// Called with the exact packet and window values from the peer's
    /// confirmation. By default this delivers the usual `Opened` event.
    fn channel_opened(
        &mut self,
        channel: ChannelId,
        _max_packet_size: u32,
        _window_size: u32,
        fields: Vec<u8>,
        session: &Context,
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.event(Event::Opened { channel, fields }, session)
    }

    /// Handle a connection-wide request. If the callback leaves a request
    /// unanswered, the session refuses it when a reply was requested.
    fn global_request(
        &mut self,
        _request: &mut IncomingGlobalRequest<'_>,
        _session: &Context,
    ) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }

    fn event(
        &mut self,
        _event: Event,
        _session: &Context,
    ) -> impl Future<Output = io::Result<()>> + Send {
        ready(Ok(()))
    }

    fn disconnected(
        &mut self,
        _end: End<'_>,
        _session: &Context,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Observe the original session result and optionally adapt the result
    /// returned to the session's waiter. The default reports the end of the
    /// connection through `disconnected`.
    fn connection_finished(
        &mut self,
        result: &mut io::Result<()>,
        context: &Context,
    ) -> impl Future<Output = ()> + Send {
        let end = match result {
            Ok(()) => End::LocalShutdown,
            Err(error) => match error
                .get_ref()
                .and_then(|source| source.downcast_ref::<PeerDisconnect>())
            {
                Some(disconnect) => End::PeerDisconnect(disconnect),
                None => End::Error(error),
            },
        };
        self.disconnected(end, context)
    }
}

impl Handler for () {}

/// An active connection. Await it to observe termination, or drop it to
/// request shutdown. Channel commands are available from its context.
#[must_use = "hold the session while it runs or await its completion"]
pub struct Session {
    context: Context,
    stop: Option<oneshot::Sender<Shutdown>>,
    task: JoinHandle<io::Result<()>>,
}

enum Shutdown {
    Disconnect(Arc<str>),
}

impl Shutdown {
    fn disconnect() -> Self {
        Self::Disconnect(Arc::from(""))
    }
}

impl Session {
    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn handle(&self) -> Handle {
        self.context.handle()
    }

    pub fn request_shutdown(&mut self) {
        self.stop(Shutdown::disconnect());
    }

    fn stop(&mut self, shutdown: Shutdown) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(shutdown);
        }
    }

    pub async fn disconnect(mut self) -> io::Result<()> {
        self.request_shutdown();
        self.await
    }
}

impl Future for Session {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx).map(join_result)
    }
}

pub(crate) fn join_result(
    result: Result<io::Result<()>, impl std::error::Error + Send + Sync + 'static>,
) -> io::Result<()> {
    result.map_err(io::Error::other)?
}

struct Running<S> {
    driver: crate::channel::driver::Driver<S>,
    events: mpsc::Receiver<SessionEvent>,
    context: Context,
}

#[derive(Clone, Copy)]
pub(crate) struct Options {
    pub(crate) maximum_packet_size: u32,
    pub(crate) channel_buffer_size: Option<usize>,
    pub(crate) channel_window_budget: u32,
    pub(crate) command_capacity: usize,
    pub(crate) liveness: Liveness,
    pub(crate) shutdown_timeout: Duration,
}

impl Options {
    pub(crate) fn validate(&self) -> io::Result<()> {
        validate_maximum_packet_size(self.maximum_packet_size)?;
        let max = tokio::sync::Semaphore::MAX_PERMITS;
        if !(1..=max).contains(&self.command_capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSH command buffer size",
            ));
        }
        if self
            .channel_buffer_size
            .is_some_and(|size| !(1..=max).contains(&size))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSH channel buffer size",
            ));
        }
        if self.channel_window_budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSH channel window budget",
            ));
        }
        self.liveness.validate()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Running<S> {
    fn new(
        authenticated: Authenticated<S>,
        peer_addr: Option<SocketAddr>,
        handler: &impl Handler,
        options: Options,
    ) -> Self {
        let username = Arc::from(authenticated.username());
        let peer_identification = Arc::from(authenticated.transport.peer_identification());
        let mut connection =
            Connection::with_packet_size(authenticated, options.maximum_packet_size);
        connection.enable_global_requests();
        let (mut driver, handle, events) = connection.into_session_driver(
            options.command_capacity,
            options.channel_buffer_size,
            options.channel_window_budget,
        );
        driver.routed_callbacks(
            handler.observe_routed_channel_events(),
            handler.handle_routed_channel_requests(),
        );
        let context = Context {
            handle,
            username,
            peer_addr,
            peer_identification,
        };
        Self {
            driver,
            events,
            context,
        }
    }

    async fn run(
        self,
        mut handler: impl Handler,
        stop: impl Future<Output = Shutdown>,
        options: Options,
    ) -> io::Result<()> {
        let Self {
            mut driver,
            mut events,
            context,
        } = self;
        let shutdown_timeout = options.shutdown_timeout;
        let result = {
            // The driver is moved into its future so that finishing the
            // future drops the driver and, with it, the event sender. That
            // lets the callback loop below drain queued events and end.
            let probe_handle = context.handle();
            let driver = async move {
                if !options.liveness.enabled() {
                    return driver.run().await;
                }
                let traffic = driver.monitor_activity();
                tokio::select! {
                    biased;
                    result = driver.run() => result,
                    result = options.liveness.watchdog(traffic.clone()) => result.map(|never| match never {}),
                    result = options.liveness.probe(traffic, probe_handle) => result,
                }
            };
            tokio::pin!(driver);
            let interrupted = {
                let callbacks = dispatch(&mut events, &context, &mut handler);
                tokio::pin!(callbacks);
                tokio::select! {
                    biased;
                    result = &mut driver => {
                        // Events the driver queued before it stopped (final
                        // data, exit status, EOF) must still reach the
                        // handler. Bound the drain so a stuck callback cannot
                        // hold the session open forever.
                        let drained = timeout(shutdown_timeout, &mut callbacks)
                            .await
                            .unwrap_or(Ok(()));
                        // A callback that tried to answer one of those events
                        // found the driver gone. That is how an orderly stop
                        // looks from inside, not a failure of the session.
                        let stopped = |error: &io::Error| {
                            matches!(
                                error.kind(),
                                ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
                            )
                        };
                        ControlFlow::Break(match (result, drained) {
                            (Ok(()), Err(error)) if stopped(&error) => Ok(()),
                            (result, drained) => result.and(drained),
                        })
                    }
                    shutdown = stop => ControlFlow::Continue((Ok(()), shutdown)),
                    result = &mut callbacks => ControlFlow::Continue((result, Shutdown::disconnect())),
                }
            };
            match interrupted {
                ControlFlow::Break(result) => result,
                ControlFlow::Continue((result, shutdown)) => {
                    // The current callback is gone. Keep the event receiver
                    // alive while the driver attempts a clean disconnect.
                    let disconnected = timeout(shutdown_timeout, async {
                        let disconnect = async {
                            match shutdown {
                                Shutdown::Disconnect(reason) => {
                                    context.handle.disconnect_with(11, &reason, "").await?;
                                }
                            }
                            std::future::pending().await
                        };
                        tokio::select! {
                            biased;
                            result = &mut driver => result,
                            result = disconnect => result,
                        }
                    })
                    .await
                    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "SSH shutdown timed out"))
                    .and_then(|result| result);
                    result.and(disconnected)
                }
            }
        };
        finish(handler, result, &context, shutdown_timeout).await
    }
}

async fn dispatch(
    events: &mut mpsc::Receiver<SessionEvent>,
    context: &Context,
    handler: &mut impl Handler,
) -> io::Result<()> {
    handler.started(context).await?;
    while let Some(event) = events.recv().await {
        let (event, confirmation) = match event {
            SessionEvent::Wire {
                event,
                confirmation,
            } => (event, confirmation),
            SessionEvent::KeyExchange(exchange) => {
                handler.key_exchange_done(exchange, context).await?;
                continue;
            }
        };
        match (event, confirmation) {
            (
                Event::Incoming {
                    channel,
                    kind,
                    fields,
                },
                _,
            ) => {
                let request = IncomingChannel {
                    id: channel,
                    kind: kind.into(),
                    fields: fields.into(),
                    owner: Arc::new(IncomingOpenOwner {
                        abandoned: Arc::new(AtomicBool::new(false)),
                        claimed: AtomicBool::new(false),
                        handle: context.handle(),
                    }),
                };
                context
                    .handle
                    .track_incoming(channel, Arc::clone(&request.owner.abandoned))
                    .await?;
                handler.channel_open(request, context).await?;
            }
            (Event::GlobalRequest(request), _) => {
                let mut request = IncomingGlobalRequest {
                    request,
                    context,
                    answered: false,
                };
                handler.global_request(&mut request, context).await?;
                if !request.answered {
                    request.reply(GlobalReply::Failure).await?;
                }
            }
            (Event::Opened { channel, fields }, Some(confirmation)) => {
                handler
                    .channel_opened(
                        channel,
                        confirmation.max_packet_size,
                        confirmation.window_size,
                        fields,
                        context,
                    )
                    .await?;
            }
            (event, _) => handler.event(event, context).await?,
        }
    }
    Ok(())
}

const DISCONNECT_BY_APPLICATION: u32 = 11;

async fn finish(
    mut handler: impl Handler,
    mut result: io::Result<()>,
    context: &Context,
    grace: Duration,
) -> io::Result<()> {
    let _ = timeout(grace, handler.connection_finished(&mut result, context)).await;
    // Only "by application" is the peer ending the session on purpose. Any
    // other reason reports a fault, and the caller needs to see it.
    let orderly = result
        .as_ref()
        .err()
        .and_then(io::Error::get_ref)
        .and_then(|source| source.downcast_ref::<PeerDisconnect>())
        .is_some_and(|disconnect| disconnect.reason == DISCONNECT_BY_APPLICATION);
    if orderly { Ok(()) } else { result }
}

pub(crate) fn start<S>(
    authenticated: Authenticated<S>,
    handler: impl Handler,
    peer_addr: Option<SocketAddr>,
    options: Options,
) -> io::Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let running = Running::new(authenticated, peer_addr, &handler, options);
    let context = running.context.clone();
    let (stop, stopped) = oneshot::channel();
    let run = running.run(
        handler,
        async {
            // Dropping the session's sender also requests shutdown.
            stopped.await.unwrap_or_else(|_| Shutdown::disconnect())
        },
        options,
    );
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    let task = tokio::runtime::Handle::try_current()
        .map_err(io::Error::other)?
        .spawn(run);
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let task = crate::runtime::spawn(run);
    Ok(Session {
        context,
        stop: Some(stop),
        task,
    })
}

#[cfg(not(target_family = "wasm"))]
pub(crate) async fn serve<S>(
    authenticated: Authenticated<S>,
    handler: impl Handler,
    peer_addr: SocketAddr,
    stop: impl Future<Output = Arc<str>>,
    options: Options,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Running::new(authenticated, Some(peer_addr), &handler, options)
        .run(handler, async { Shutdown::Disconnect(stop.await) }, options)
        .await
}
