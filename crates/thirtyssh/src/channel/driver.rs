//! A background driver for the multiplexed channel connection.
use super::{
    Bytes, Channel, ChannelId, ChannelIds, Connection, Event, GlobalReply, GlobalRequestId,
    KEEPALIVE_REQUEST, MAX_DATA, MAX_OUTGOING_DATA, OpenFailure, OpenFrame, State, input,
    named_size,
    stream::{Delivery, Inbox, Message, Signals, inbox},
};
use crate::{
    runtime::{Instant, sleep_until},
    transport::{Activity, CompletedKeyExchange, DisconnectRequest},
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, Notify, OwnedMutexGuard, mpsc, oneshot, watch},
};

pub(crate) const DEFAULT_COMMAND_CAPACITY: usize = 32;
const EVENT_CAPACITY: usize = 32;
/// Events the driver holds for a full consumer queue before it stops reading.
/// Reading on keeps everything that is not an event moving meanwhile: data
/// for channel readers, window adjustments, replies and open confirmations.
/// A callback that waits for one of those is then not blocked by the events
/// queued behind it. The rest of the capacity is headroom for events that do
/// not come from reading, such as completed key exchanges.
const EVENT_READ_AHEAD: usize = EVENT_CAPACITY / 2;
const NO_MORE_SESSIONS_REQUEST: &str = "no-more-sessions@openssh.com";
pub const QUEUED_OUTPUT_BUDGET: usize = 8 * 1024 * 1024;
const OUTPUT_COMMAND_CHARGE: usize = 1024;
const OPEN_WAITING: u8 = 0;
const OPEN_CLAIMED: u8 = 1;
const OPEN_CANCELLED: u8 = 2;

type Reply<T> = oneshot::Sender<io::Result<T>>;

pub(crate) enum GlobalResponse {
    Event,
    Application(Reply<GlobalReply>),
    Signal(&'static str),
}

impl GlobalResponse {
    /// Whether a caller is blocked until this reply arrives. A keepalive is
    /// not: its reply is read like any other input, and a session too far
    /// behind to reach it is one the liveness check should end.
    fn wants_input(&self) -> bool {
        match self {
            Self::Event | Self::Signal(_) => false,
            Self::Application(reply) => !reply.is_closed(),
        }
    }
}

/// How the driver's loop ended without an error.
enum Stop {
    /// The application let go of the connection.
    Finished,
    /// The application asked for a disconnect with this packet.
    Shutdown(Vec<u8>, Reply<()>),
}

enum Command {
    Open {
        kind: String,
        window: u32,
        fields: Vec<u8>,
        claim: Arc<AtomicU8>,
        inbox: Option<Inbox>,
        reply: Reply<ChannelId>,
    },
    SubmitOpen {
        frame: OpenFrame,
        reply: Reply<()>,
    },
    Data {
        channel: ChannelId,
        extended: Option<u32>,
        data: Vec<u8>,
        reply: Reply<usize>,
    },
    Write(ChannelId, ScheduledOutput),
    QueueOutput {
        channel: ChannelId,
        output: ChannelOutput,
        reply: Reply<()>,
    },
    WritablePacketSize(ChannelId, Reply<usize>),
    GlobalRequest(String, Vec<u8>, Reply<GlobalReply>),
    Control(Control, Reply<()>),
    Shutdown(Vec<u8>, Reply<()>),
}

enum Control {
    TrackIncoming(ChannelId, Arc<AtomicBool>),
    Accept(ChannelId, u32, Vec<u8>, Option<Inbox>),
    Refuse(ChannelId, OpenFailure),
    CancelOpen(ChannelId),
    Consume(ChannelId, u32),
    ConsumeUnrouted(ChannelId, u32),
    Grant(ChannelId, u32),
    Request {
        channel: ChannelId,
        name: String,
        want_reply: bool,
        fields: Vec<u8>,
    },
    Reply(ChannelId, bool),
    GlobalNotification(String, Vec<u8>),
    GlobalSignal(&'static str, bool),
    GlobalReply(GlobalRequestId, GlobalReply),
    Eof(ChannelId),
    Close(ChannelId),
    Rekey,
}

/// Output accepted from a callback. Per-channel ordering is preserved even
/// if transmission must wait for a window adjustment.
pub enum ChannelOutput {
    Data { extended: Option<u32>, data: Bytes },
    ExitStatus(u32),
    Eof,
    Close,
}

impl ChannelOutput {
    fn queue_charge(&self) -> usize {
        OUTPUT_COMMAND_CHARGE.saturating_add(self.data_len())
    }

    fn data_len(&self) -> usize {
        match self {
            Self::Data { data, .. } => data.len(),
            _ => 0,
        }
    }
}

struct ScheduledOutput {
    output: ChannelOutput,
    completion: Option<OutputCompletion>,
    charge: usize,
}

struct OutputCompletion {
    reply: Reply<()>,
    cancel_on_drop: bool,
    _pending: Option<PendingWrite>,
    _serial: OwnedMutexGuard<()>,
}

impl ScheduledOutput {
    fn cancelled(&self) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|waiter| waiter.cancel_on_drop && waiter.reply.is_closed())
    }

    fn complete(self, result: io::Result<()>, terminal: bool) -> io::Result<()> {
        match self.completion {
            Some(waiter) => complete(waiter.reply, result, terminal),
            None => result,
        }
    }
}

#[derive(Default)]
struct OutputQueue {
    items: VecDeque<ScheduledOutput>,
    ready: bool,
    eof: bool,
    close: bool,
}

struct PendingWrite {
    signals: Arc<Signals>,
    wake: Arc<Notify>,
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        self.signals.output_pending.store(false, Ordering::Release);
        if self.signals.writer_dropped.load(Ordering::Acquire) {
            self.wake.notify_one();
        }
    }
}

pub(super) struct WritePermit {
    channel: ChannelId,
    slot: mpsc::OwnedPermit<Command>,
    serial: OwnedMutexGuard<()>,
    signals: Arc<Signals>,
    wake: Arc<Notify>,
}

impl WritePermit {
    pub(super) fn send(self, extended: Option<u32>, data: Bytes, committed: bool) -> WriteReceipt {
        let (reply, result) = oneshot::channel();
        let cancel_wake = (!committed).then(|| self.wake.clone());
        // Publish before queueing so dropping the last writer cannot overtake it with EOF.
        self.signals
            .output_pending
            .store(committed, Ordering::Release);
        self.slot.send(Command::Write(
            self.channel,
            ScheduledOutput {
                output: ChannelOutput::Data { extended, data },
                completion: Some(OutputCompletion {
                    reply,
                    cancel_on_drop: !committed,
                    _pending: Some(PendingWrite {
                        signals: self.signals,
                        wake: self.wake,
                    }),
                    _serial: self.serial,
                }),
                charge: 0,
            },
        ));
        WriteReceipt {
            result,
            cancel_wake,
        }
    }

    pub(super) fn eof(self) -> WriteReceipt {
        self.finish(ChannelOutput::Eof)
    }

    pub(super) fn close(self) -> WriteReceipt {
        self.finish(ChannelOutput::Close)
    }

    fn finish(self, output: ChannelOutput) -> WriteReceipt {
        let (reply, result) = oneshot::channel();
        self.slot.send(Command::Write(
            self.channel,
            ScheduledOutput {
                output,
                completion: Some(OutputCompletion {
                    reply,
                    cancel_on_drop: false,
                    _pending: None,
                    _serial: self.serial,
                }),
                charge: 0,
            },
        ));
        WriteReceipt {
            result,
            cancel_wake: None,
        }
    }
}

pub(super) struct WriteReceipt {
    result: oneshot::Receiver<io::Result<()>>,
    cancel_wake: Option<Arc<Notify>>,
}

impl Future for WriteReceipt {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.result).poll(cx));
        self.cancel_wake = None;
        Poll::Ready(result.map_err(|_| stopped())?)
    }
}

impl Drop for WriteReceipt {
    fn drop(&mut self) {
        if let Some(wake) = &self.cancel_wake {
            self.result.close();
            wake.notify_one();
        }
    }
}

struct Route {
    inbox: Inbox,
    aborted: bool,
    /// When the application let go of both halves while output it had
    /// committed was still waiting for the peer's window.
    orphaned: Option<Instant>,
}

impl Route {
    fn new(inbox: Inbox) -> Self {
        Self {
            inbox,
            aborted: false,
            orphaned: None,
        }
    }
}

/// How long committed output of a channel nobody holds any more may wait for
/// the peer's window. A peer that never opens it would otherwise keep the
/// channel, its slot and its window budget for the life of the connection.
const ORPHANED_OUTPUT_GRACE: Duration = Duration::from_secs(30);

struct OpenGuard {
    claim: Arc<AtomicU8>,
    wake: Arc<Notify>,
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if self
            .claim
            .compare_exchange(
                OPEN_WAITING,
                OPEN_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.wake.notify_one();
        }
    }
}

/// Cloneable channel operations for a running [Driver].
///
/// A command that has started may finish even if the caller drops its
/// future. A cancelled open whose ID was never returned closes automatically.
#[derive(Clone)]
pub struct Handle {
    commands: mpsc::Sender<Command>,
    ids: Arc<ChannelIds>,
    channel_buffer_size: Option<usize>,
    pub(super) wake: Arc<Notify>,
}

/// A connection-scoped channel ID and open request. Dropping it before
/// submission releases the channel slot without sending a packet.
pub struct PendingOpen {
    ids: Arc<ChannelIds>,
    frame: OpenFrame,
}

impl PendingOpen {
    pub fn id(&self) -> ChannelId {
        self.frame.id
    }
}

/// Drives one authenticated SSH connection from a dedicated task.
#[must_use = "run the driver to service its handle and event receiver"]
pub struct Driver<S> {
    connection: Connection<S>,
    commands: mpsc::Receiver<Command>,
    events: EventSender,
    wake: Arc<Notify>,
    unclaimed_opens: Vec<(ChannelId, Arc<AtomicU8>)>,
    incoming: Vec<(ChannelId, Arc<AtomicBool>)>,
    routes: HashMap<ChannelId, Route>,
    outputs: HashMap<ChannelId, OutputQueue>,
    queued_output_charge: usize,
    ready_writes: VecDeque<ChannelId>,
    observe_routed_events: bool,
    handle_routed_requests: bool,
    window_budget: u32,
    global_replies: VecDeque<GlobalResponse>,
}

// The session dispatcher receives confirmation parameters with the event so
// it can invoke a callback even if the peer has closed the channel meanwhile.
// The public low-level driver continues to expose Event on its own.
pub(crate) enum SessionEvent {
    Wire {
        event: Event,
        confirmation: Option<OpenConfirmation>,
    },
    KeyExchange(CompletedKeyExchange),
}

pub(crate) struct OpenConfirmation {
    pub(crate) max_packet_size: u32,
    pub(crate) window_size: u32,
}

#[derive(Clone)]
enum EventSender {
    Basic(mpsc::Sender<Event>),
    Session(mpsc::Sender<SessionEvent>),
}

enum EventPermit<'a> {
    Basic(mpsc::Permit<'a, Event>),
    Session(mpsc::Permit<'a, SessionEvent>),
}

impl EventSender {
    async fn closed(&self) {
        match self {
            Self::Basic(events) => events.closed().await,
            Self::Session(events) => events.closed().await,
        }
    }

    async fn reserve(&self) -> Result<EventPermit<'_>, ()> {
        match self {
            Self::Basic(events) => events
                .reserve()
                .await
                .map(EventPermit::Basic)
                .map_err(|_| ()),
            Self::Session(events) => events
                .reserve()
                .await
                .map(EventPermit::Session)
                .map_err(|_| ()),
        }
    }

    fn try_reserve(&self) -> Result<EventPermit<'_>, ()> {
        match self {
            Self::Basic(events) => events.try_reserve().map(EventPermit::Basic).map_err(|_| ()),
            Self::Session(events) => events
                .try_reserve()
                .map(EventPermit::Session)
                .map_err(|_| ()),
        }
    }
}

impl EventPermit<'_> {
    fn send(self, event: SessionEvent) {
        match self {
            Self::Basic(permit) => {
                if let SessionEvent::Wire { event, .. } = event {
                    permit.send(event);
                }
            }
            Self::Session(permit) => permit.send(event),
        }
    }
}

/// Queue an event behind the ones already waiting for the consumer.
///
/// The driver stops reading once `EVENT_READ_AHEAD` events wait here, which
/// is ordinary backpressure. The exception is a callback awaiting a global
/// reply: the consumer of `events` is that callback, so waiting for queue
/// space would deadlock. The driver then reads on up to the full capacity and
/// aborts the connection when a peer floods past it. That is deliberate flood
/// protection, not backpressure.
fn queue_event(
    events: &EventSender,
    pending: &mut VecDeque<SessionEvent>,
    event: SessionEvent,
) -> io::Result<()> {
    if pending.len() == EVENT_CAPACITY {
        let permit = events.try_reserve().map_err(|_| {
            io::Error::new(
                ErrorKind::ConnectionAborted,
                "SSH event read-ahead limit exceeded while awaiting a global reply",
            )
        })?;
        permit.send(pending.pop_front().expect("waiting event"));
    }
    pending.push_back(event);
    Ok(())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Split the connection into a driver, a cloneable command handle and a
    /// bounded event receiver. Run the driver while using the other halves.
    pub fn into_driver(self) -> (Driver<S>, Handle, mpsc::Receiver<Event>) {
        let (events, receiver) = mpsc::channel(EVENT_CAPACITY);
        let (driver, handle) = self.driver(
            EventSender::Basic(events),
            DEFAULT_COMMAND_CAPACITY,
            None,
            super::DEFAULT_WINDOW_BUDGET,
        );
        (driver, handle, receiver)
    }

    pub(crate) fn into_session_driver(
        self,
        command_capacity: usize,
        channel_buffer_size: Option<usize>,
        window_budget: u32,
    ) -> (Driver<S>, Handle, mpsc::Receiver<SessionEvent>) {
        let (events, receiver) = mpsc::channel(EVENT_CAPACITY);
        let (driver, handle) = self.driver(
            EventSender::Session(events),
            command_capacity,
            channel_buffer_size,
            window_budget,
        );
        (driver, handle, receiver)
    }

    fn driver(
        self,
        events: EventSender,
        command_capacity: usize,
        channel_buffer_size: Option<usize>,
        window_budget: u32,
    ) -> (Driver<S>, Handle) {
        let (commands, requests) = mpsc::channel(command_capacity);
        let wake = Arc::new(Notify::new());
        let handle = Handle {
            commands,
            ids: self.ids.clone(),
            channel_buffer_size,
            wake: Arc::clone(&wake),
        };
        let driver = Driver {
            global_replies: (0..self.global.outgoing)
                .map(|_| GlobalResponse::Event)
                .collect(),
            connection: self,
            commands: requests,
            events,
            wake,
            unclaimed_opens: Vec::new(),
            incoming: Vec::new(),
            routes: HashMap::new(),
            outputs: HashMap::new(),
            queued_output_charge: 0,
            ready_writes: VecDeque::new(),
            observe_routed_events: false,
            handle_routed_requests: false,
            window_budget,
        };
        (driver, handle)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Driver<S> {
    pub(crate) fn routed_callbacks(&mut self, observe: bool, requests: bool) {
        self.observe_routed_events = observe;
        self.handle_routed_requests = requests;
    }

    pub(crate) fn monitor_activity(&mut self) -> watch::Receiver<Activity> {
        self.connection.connection.transport.monitor_activity()
    }

    /// Process I/O until a disconnect, an I/O or protocol error, or until the
    /// application drops its event receiver or all handles.
    pub async fn run(mut self) -> io::Result<()> {
        match self.drive().await {
            Ok(Stop::Finished) => self.connection.disconnect().await,
            Ok(Stop::Shutdown(packet, reply)) => {
                let result = self.connection.disconnect_with_packet(&packet).await;
                complete(reply, result, true)
            }
            Err(error) => {
                self.deliver_undelivered();
                Err(error)
            }
        }
    }

    /// Hand channel readers what the peer sent before the connection failed.
    /// A write that could not finish may have read a command's last output
    /// and exit status first; dropping those would report a lost connection
    /// for work that in fact completed.
    fn deliver_undelivered(&mut self) {
        while let Some(event) = self.connection.salvage() {
            let (Event::Data { channel, .. }
            | Event::Eof(channel)
            | Event::Closed(channel)
            | Event::Request { channel, .. }) = &event
            else {
                continue;
            };
            if let Some(route) = self.routes.get(channel)
                && !route.aborted
                && !route.inbox.reader_dropped()
                && let Some(message) = Delivery::from_event(event)
            {
                route.inbox.push(message);
            }
        }
    }

    async fn drive(&mut self) -> io::Result<Stop> {
        let events = self.events.clone();
        let mut pending = VecDeque::new();
        loop {
            tokio::task::consume_budget().await;
            self.settle_opens().await?;
            self.queue_key_exchanges(&events, &mut pending)?;
            // Events wait for the consumer in order, but nothing else should
            // wait behind them, so read ahead within a fixed budget. A
            // callback blocked on a global reply extends that budget, because
            // only reading can release it.
            let orphan_deadline = self
                .routes
                .values()
                .filter_map(|route| route.orphaned)
                .min()
                .map(|since| since + ORPHANED_OUTPUT_GRACE);
            let read = pending.len() < EVENT_READ_AHEAD
                || self.global_replies.iter().any(GlobalResponse::wants_input);
            let command = tokio::select! {
                command = self.commands.recv() => command,
                () = events.closed() => break,
                permit = events.reserve(), if !pending.is_empty() => {
                    let Ok(permit) = permit else { break };
                    permit.send(pending.pop_front().expect("waiting event"));
                    continue;
                }
                () = self.wake.notified() => {
                    self.settle_incoming().await?;
                    self.settle_routes().await?;
                    continue;
                }
                () = sleep_until(orphan_deadline.unwrap_or_else(Instant::now)),
                    if orphan_deadline.is_some() =>
                {
                    self.settle_routes().await?;
                    continue;
                }
                () = std::future::ready(()), if !self.ready_writes.is_empty() => {
                    self.write_one().await?;
                    continue;
                }
                input = self.connection.wait_input(), if read => {
                    let event = self.connection.process_input(input?).await?;
                    self.queue_key_exchanges(&events, &mut pending)?;
                    if let Some(event) = event
                        && let Some(event) = self.route_session_event(event).await?
                    {
                        queue_event(&events, &mut pending, event)?;
                    }
                    // A cancelled open can be refused without producing an event.
                    self.routes.retain(|id, _| self.connection.channels.contains_key(id));
                    continue;
                }
            };
            let Some(command) = command else { break };
            match command {
                Command::Shutdown(packet, reply) => return Ok(Stop::Shutdown(packet, reply)),
                command => self.execute(command).await?,
            }
        }
        Ok(Stop::Finished)
    }

    fn queue_key_exchanges(
        &mut self,
        events: &EventSender,
        pending: &mut VecDeque<SessionEvent>,
    ) -> io::Result<()> {
        for exchange in self
            .connection
            .connection
            .transport
            .take_completed_key_exchanges()
        {
            queue_event(events, pending, SessionEvent::KeyExchange(exchange))?;
        }
        Ok(())
    }

    fn open_confirmation(&self, event: &Event) -> Option<OpenConfirmation> {
        let Event::Opened { channel, .. } = event else {
            return None;
        };
        let open = self.connection.active(*channel).ok()?;
        Some(OpenConfirmation {
            max_packet_size: open.remote.max_data,
            window_size: open.remote.window,
        })
    }

    async fn route_session_event(&mut self, event: Event) -> io::Result<Option<SessionEvent>> {
        let confirmation = self.open_confirmation(&event);
        let routed = self.route_event(event).await?;
        Ok(routed.map(|event| SessionEvent::Wire {
            event,
            confirmation,
        }))
    }

    async fn execute(&mut self, command: Command) -> io::Result<()> {
        match command {
            Command::Open {
                kind,
                window,
                fields,
                claim,
                inbox,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                let result = match self.check_route_budget(inbox.as_ref()) {
                    Ok(()) => self.connection.open(&kind, window, &fields).await,
                    Err(error) => Err(error),
                };
                if let Ok(channel) = result {
                    self.unclaimed_opens.push((channel, claim));
                    if let Some(inbox) = inbox {
                        self.routes.insert(channel, Route::new(inbox));
                    }
                }
                complete(reply, result, self.connection.is_failed())
            }
            Command::SubmitOpen { frame, reply } => {
                if reply.is_closed() {
                    return Ok(());
                }
                let result = self.connection.open_reserved(frame).await;
                complete(reply, result, self.connection.is_failed())
            }
            Command::Data {
                channel,
                extended,
                data,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                let result = match self.require_raw_channel(channel) {
                    Ok(()) => self.connection.send_data(channel, extended, &data).await,
                    Err(error) => Err(error),
                };
                complete(reply, result, self.connection.is_failed())
            }
            Command::Write(id, write) => {
                if write.cancelled() {
                    return Ok(());
                }
                if let Err(error) = self.validate_output(id, &write.output) {
                    let error = if error.kind() == ErrorKind::NotFound {
                        io::Error::new(ErrorKind::BrokenPipe, error)
                    } else {
                        error
                    };
                    return write.complete(Err(error), false);
                }
                self.enqueue_output(id, write);
                Ok(())
            }
            Command::QueueOutput {
                channel: id,
                output,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                let charge = output.queue_charge();
                if charge > QUEUED_OUTPUT_BUDGET {
                    return complete(
                        reply,
                        Err(input("SSH output exceeds the queue budget")),
                        false,
                    );
                }
                if self.outputs.get(&id).is_some_and(|queue| match output {
                    ChannelOutput::Eof => queue.eof || queue.close,
                    ChannelOutput::Close => queue.close,
                    _ => false,
                }) {
                    return complete(reply, Ok(()), false);
                }
                let result = self.validate_output(id, &output).and_then(|()| {
                    if charge > QUEUED_OUTPUT_BUDGET - self.queued_output_charge {
                        return Err(io::Error::new(
                            ErrorKind::WouldBlock,
                            "SSH output queue budget exhausted",
                        ));
                    }
                    self.enqueue_output(
                        id,
                        ScheduledOutput {
                            output,
                            completion: None,
                            charge,
                        },
                    );
                    Ok(())
                });
                complete(reply, result, false)
            }
            Command::WritablePacketSize(id, reply) => {
                let size = self
                    .connection
                    .active(id)
                    .ok()
                    .filter(|open| !open.sent_eof)
                    .filter(|_| {
                        self.outputs
                            .get(&id)
                            .is_none_or(|queue| !queue.eof && !queue.close)
                    })
                    .map_or(0, |open| open.writable_packet_size());
                let _ = reply.send(Ok(size));
                Ok(())
            }
            Command::GlobalRequest(name, fields, reply) => {
                if reply.is_closed() {
                    return Ok(());
                }
                match self.connection.global_request(&name, true, &fields).await {
                    Ok(()) => {
                        // Keep this FIFO entry until its wire reply arrives, even
                        // if the request's local waiter is cancelled meanwhile.
                        self.global_replies
                            .push_back(GlobalResponse::Application(reply));
                        Ok(())
                    }
                    Err(error) => complete(reply, Err(error), self.connection.is_failed()),
                }
            }
            Command::Control(control, reply) => {
                if reply.is_closed() {
                    return Ok(());
                }
                let result = self.control(control).await;
                complete(reply, result, self.connection.is_failed())
            }
            Command::Shutdown(..) => unreachable!("handled before executing channel operations"),
        }
    }

    async fn control(&mut self, control: Control) -> io::Result<()> {
        match control {
            Control::TrackIncoming(id, abandoned) => {
                self.connection.incoming(id)?;
                self.incoming.push((id, abandoned));
                Ok(())
            }
            Control::Accept(id, window, fields, inbox) => {
                self.check_route_budget(inbox.as_ref())?;
                self.connection.accept(id, window, &fields).await?;
                if let Some(inbox) = inbox {
                    if let Ok(open) = self.connection.active(id) {
                        inbox.signals.update_writable(open);
                    }
                    self.routes.insert(id, Route::new(inbox));
                    self.wake.notify_one();
                }
                Ok(())
            }
            Control::Refuse(id, failure) => self.connection.refuse_with(id, &failure).await,
            Control::CancelOpen(id) => self.connection.cancel_open(id),
            Control::Consume(id, bytes) => {
                self.require_raw_channel(id)?;
                self.connection.consume(id, bytes).await
            }
            Control::ConsumeUnrouted(id, bytes) => {
                if !self.routes.contains_key(&id)
                    && matches!(self.connection.state(id), Some(State::Open(_)))
                {
                    self.connection.consume(id, bytes).await?;
                }
                Ok(())
            }
            Control::Grant(id, bytes) => {
                self.require_raw_channel(id)?;
                self.connection.grant(id, bytes).await
            }
            Control::Request {
                channel,
                name,
                want_reply,
                fields,
            } => {
                self.connection
                    .request(channel, &name, want_reply, &fields)
                    .await
            }
            Control::Reply(id, success) => self.connection.reply(id, success).await,
            Control::GlobalNotification(name, fields) => {
                self.connection.global_request(&name, false, &fields).await
            }
            Control::GlobalSignal(name, want_reply) => {
                self.connection
                    .global_request(name, want_reply, &[])
                    .await?;
                if want_reply {
                    self.global_replies.push_back(GlobalResponse::Signal(name));
                }
                Ok(())
            }
            Control::GlobalReply(id, result) => self.connection.global_reply(id, result).await,
            Control::Eof(id) => {
                if self.outputs.contains_key(&id) {
                    return Err(io::Error::new(
                        ErrorKind::WouldBlock,
                        "SSH channel has a pending write",
                    ));
                }
                self.connection.eof(id).await?;
                if let Some(route) = self.routes.get(&id) {
                    route.inbox.signals.close_output();
                }
                Ok(())
            }
            Control::Close(id) => {
                self.connection.close(id).await?;
                if let Some(route) = self.routes.get(&id) {
                    route.inbox.signals.close_output();
                }
                self.abort_output(id);
                Ok(())
            }
            Control::Rekey => self.connection.rekey().await,
        }
    }

    fn require_raw_channel(&self, id: ChannelId) -> io::Result<()> {
        if self.routes.contains_key(&id) {
            return Err(input("use the routed SSH channel's read or write half"));
        }
        Ok(())
    }

    async fn replenish_receive_window(&mut self, id: ChannelId) -> io::Result<()> {
        let Ok(open) = self.connection.active(id) else {
            return Ok(());
        };
        // Callbacks can request credit ahead of the reader. Reuse it only
        // after the application has freed the corresponding storage.
        let available = open
            .receive_capacity
            .saturating_sub(open.window + open.unread);
        let bytes = open.requested_credit.min(available);
        // Return credit in worthwhile amounts. A reader that trails by more
        // than half the window would otherwise trigger one adjustment per
        // read, each inviting the peer to send an equally small packet.
        let worthwhile = bytes >= open.receive_capacity / 8 || open.unread == 0;
        if bytes != 0 && worthwhile {
            self.connection.grant(id, bytes).await?;
            let open = self.connection.open_mut(id)?;
            open.requested_credit -= bytes;
            if let Some(route) = self.routes.get(&id) {
                route
                    .inbox
                    .signals
                    .read_credit_due
                    .store(open.needs_receive_credit(), Ordering::SeqCst);
            }
        }
        Ok(())
    }

    async fn consume_routed(&mut self, id: ChannelId, bytes: u32) -> io::Result<()> {
        if !self.connection.release_received(id, bytes)? {
            return Ok(());
        }
        let open = self.connection.open_mut(id)?;
        open.requested_credit = open
            .requested_credit
            .checked_add(bytes)
            .ok_or_else(|| input("SSH routed receive credit overflow"))?;
        // Return credit in batches while the peer can still send.
        if !open.needs_receive_credit() {
            return Ok(());
        }
        self.replenish_receive_window(id).await
    }

    fn route_budget_left(&self) -> u32 {
        // Widen the sum: a route that kept its window after its reader went
        // away is not budget-limited, so the total can exceed the budget.
        let reserved = self
            .routes
            .values()
            .map(|route| u64::from(route.inbox.reserved_window()))
            .sum::<u64>();
        u32::try_from(u64::from(self.window_budget).saturating_sub(reserved)).unwrap_or(0)
    }

    fn check_route_budget(&self, inbox: Option<&Inbox>) -> io::Result<()> {
        if inbox.is_some_and(|inbox| inbox.reserved_window() > self.route_budget_left()) {
            return Err(io::Error::other(
                "SSH channel window exceeds the connection's remaining receive window budget",
            ));
        }
        Ok(())
    }

    fn validate_output(&self, id: ChannelId, output: &ChannelOutput) -> io::Result<()> {
        let open = match self.connection.state(id) {
            Some(State::Open(open)) if !open.closing => open,
            Some(State::Open(_)) | None => {
                return Err(io::Error::new(ErrorKind::NotFound, "SSH channel is closed"));
            }
            _ => return Err(input("SSH channel is not confirmed")),
        };
        let queued = self.outputs.get(&id);
        if queued.is_some_and(|queue| queue.close)
            || (matches!(output, ChannelOutput::Data { .. })
                && (open.sent_eof || queued.is_some_and(|queue| queue.eof)))
        {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "SSH channel output has finished",
            ));
        }
        Ok(())
    }

    fn enqueue_output(&mut self, id: ChannelId, item: ScheduledOutput) {
        self.queued_output_charge += item.charge;
        let queue = self.outputs.entry(id).or_default();
        queue.eof |= matches!(item.output, ChannelOutput::Eof);
        queue.close |= matches!(item.output, ChannelOutput::Close);
        if (queue.eof || queue.close)
            && let Some(route) = self.routes.get(&id)
        {
            route.inbox.signals.close_output();
        }
        queue.items.push_back(item);
        self.schedule_write(id);
    }

    fn abort_output(&mut self, id: ChannelId) {
        if let Some(queue) = self.outputs.remove(&id) {
            self.ready_writes.retain(|queued| *queued != id);
            for item in queue.items {
                self.queued_output_charge -= item.charge;
                let _ = item.complete(
                    Err(io::Error::new(ErrorKind::BrokenPipe, "SSH channel closed")),
                    false,
                );
            }
        }
    }

    fn schedule_write(&mut self, id: ChannelId) {
        if let Some(queue) = self.outputs.get_mut(&id)
            && !queue.ready
            && let Some(next) = queue.items.front()
            && match &next.output {
                ChannelOutput::Data { data, .. } if !data.is_empty() => self
                    .connection
                    .active(id)
                    .is_ok_and(|open| open.writable_packet_size() != 0),
                _ => true,
            }
        {
            queue.ready = true;
            self.ready_writes.push_back(id);
        }
    }

    async fn write_one(&mut self) -> io::Result<()> {
        let Some(id) = self.ready_writes.pop_front() else {
            return Ok(());
        };
        self.write_channel(id).await
    }

    async fn write_channel(&mut self, id: ChannelId) -> io::Result<()> {
        let queue = self.outputs.get_mut(&id).expect("scheduled output queue");
        queue.ready = false;
        let mut item = queue.items.pop_front().expect("scheduled output");
        let cancelled = item.cancelled();
        let result = match &mut item.output {
            ChannelOutput::Data { extended, data } if !cancelled => {
                match self.connection.send_data(id, *extended, data).await {
                    Ok(sent) => {
                        if let Some(route) = self.routes.get(&id)
                            && let Ok(open) = self.connection.active(id)
                        {
                            route.inbox.signals.update_writable(open);
                        }
                        if sent < data.len() {
                            *data = data.slice(sent..);
                            let queue = self.outputs.get_mut(&id).expect("active output queue");
                            queue.items.push_front(item);
                            self.schedule_write(id);
                            return Ok(());
                        }
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            ChannelOutput::Data { .. } => Ok(()),
            ChannelOutput::ExitStatus(status) => {
                self.connection
                    .request(id, "exit-status", false, &status.to_be_bytes())
                    .await
            }
            ChannelOutput::Eof => self.connection.eof(id).await,
            ChannelOutput::Close => self.connection.close(id).await,
        };
        self.queued_output_charge -= item.charge;
        if self.outputs[&id].items.is_empty() {
            self.outputs.remove(&id);
            if self
                .routes
                .get(&id)
                .is_some_and(|route| route.inbox.signals.writer_dropped.load(Ordering::Acquire))
            {
                self.wake.notify_one();
            }
        } else {
            self.schedule_write(id);
        }
        item.complete(result, self.connection.is_failed())
    }

    async fn route_event(&mut self, event: Event) -> io::Result<Option<Event>> {
        if let Event::GlobalReply(reply) = event {
            return match self
                .global_replies
                .pop_front()
                .expect("matched global request")
            {
                GlobalResponse::Application(waiter) => {
                    let _ = waiter.send(Ok(reply));
                    Ok(None)
                }
                GlobalResponse::Event => Ok(Some(Event::GlobalReply(reply))),
                GlobalResponse::Signal(name) => {
                    if name == NO_MORE_SESSIONS_REQUEST
                        && matches!(reply, GlobalReply::Success(fields) if !fields.is_empty())
                    {
                        return Err(crate::clear_packet::invalid(
                            "unexpected SSH no-more-sessions reply fields",
                        ));
                    }
                    Ok(None)
                }
            };
        }
        let Some(id) = event.channel() else {
            return Ok(Some(event));
        };
        if matches!(event, Event::Closed(_) | Event::Refused { .. }) {
            self.abort_output(id);
        } else if matches!(event, Event::WindowAdjusted { .. }) {
            self.schedule_write(id);
        }
        let Some(mut route) = self.routes.get_mut(&id) else {
            return Ok(Some(event));
        };
        if self.handle_routed_requests && matches!(event, Event::Request { .. }) {
            if self.observe_routed_events
                && !route.aborted
                && !route.inbox.reader_dropped()
                && let Some(message) = Delivery::from_event(event.clone())
            {
                // The handler owns the reply. Mirror the request for consumers of the channel.
                route.inbox.observe(message);
            }
            return Ok(Some(event));
        }
        if matches!(event, Event::Opened { .. } | Event::WindowAdjusted { .. })
            && let Ok(open) = self.connection.active(id)
        {
            route.inbox.signals.update_writable(open);
        }
        if matches!(event, Event::Data { .. })
            && let Ok(open) = self.connection.active(id)
        {
            let signals = &route.inbox.signals;
            let due = open.needs_receive_credit();
            if signals.read_credit_due.load(Ordering::Relaxed) != due {
                signals.read_credit_due.store(due, Ordering::SeqCst);
            }
            // At an exhausted window, release prior credit even if the
            // reader waits for the peer to send more before reading again.
            if open.window == 0 && !route.inbox.reader_dropped() {
                let consumed = signals.consumed.swap(0, Ordering::SeqCst);
                if consumed != 0 || open.requested_credit != 0 {
                    self.consume_routed(id, consumed).await?;
                    route = self.routes.get_mut(&id).expect("existing data route");
                }
            }
        }
        if matches!(event, Event::Data { .. }) && route.inbox.reader_dropped() {
            // Only the session callback can observe this payload.
            self.discard_received(id).await?;
            return Ok(self.observe_routed_events.then_some(event));
        }
        let observed = self.observe_routed_events.then(|| event.clone());
        if matches!(event, Event::Closed(_) | Event::Refused { .. }) {
            if matches!(event, Event::Closed(_)) {
                route
                    .inbox
                    .signals
                    .peer_closed
                    .store(true, Ordering::Release);
            }
            if let Some(message) = Delivery::from_event(event) {
                route.inbox.push(message);
            }
            self.routes.remove(&id);
        } else if matches!(event, Event::WindowAdjusted { .. }) {
            if self.observe_routed_events
                && !route.aborted
                && !route.inbox.reader_dropped()
                && let Some(message) = Delivery::from_event(event)
            {
                // Window notifications are advisory and must never delay writes.
                route.inbox.observe(message);
            }
        } else if route.inbox.reader_dropped() {
            self.discard_received(id).await?;
        } else if !route.aborted
            && let Some(message) = Delivery::from_event(event)
            && !route.inbox.push(message)
            && !route.inbox.reader_dropped()
        {
            route.aborted = true;
            route.inbox.signals.close_output();
            route.inbox.push(Message::Overrun.into());
            self.abort_output(id);
            self.connection.close(id).await?;
        }
        Ok(observed)
    }

    async fn discard_received(&mut self, id: ChannelId) -> io::Result<()> {
        if let Some(State::Open(open)) = self.connection.state(id) {
            let bytes = open.unread;
            self.consume_routed(id, bytes).await?;
            while !self.handle_routed_requests
                && self
                    .connection
                    .active(id)
                    .is_ok_and(|open| !open.incoming_requests.is_empty())
            {
                self.connection.reply(id, false).await?;
            }
        }
        Ok(())
    }

    async fn settle_routes(&mut self) -> io::Result<()> {
        let ids: Vec<_> = self.routes.keys().copied().collect();
        for id in ids {
            if let Some(queue) = self.outputs.get_mut(&id) {
                let before = queue.items.len();
                queue.items.retain(|item| !item.cancelled());
                if queue.items.is_empty() {
                    self.outputs.remove(&id);
                    self.ready_writes.retain(|queued| *queued != id);
                } else if queue.ready && queue.items.len() != before {
                    // Removing a cancelled head can expose a zero-window write.
                    queue.ready = false;
                    self.ready_writes.retain(|queued| *queued != id);
                    self.schedule_write(id);
                } else {
                    self.schedule_write(id);
                }
            }
            let route = self.routes.get_mut(&id).expect("existing route");
            if route.aborted {
                continue;
            }
            let readers_gone = route.inbox.reader_dropped();
            let writers_gone = route.inbox.signals.writer_dropped.load(Ordering::Acquire);
            let output_pending = route.inbox.signals.output_pending.load(Ordering::Acquire)
                || self.outputs.contains_key(&id);
            let credit = route.inbox.signals.consumed.swap(0, Ordering::SeqCst);
            let unanswered = route.inbox.signals.unanswered.swap(0, Ordering::SeqCst);
            let orphaned = readers_gone && writers_gone && output_pending;
            let waited = match (orphaned, route.orphaned) {
                (true, Some(since)) => since.elapsed() >= ORPHANED_OUTPUT_GRACE,
                (true, None) => {
                    route.orphaned = Some(Instant::now());
                    false
                }
                (false, _) => {
                    route.orphaned = None;
                    false
                }
            };
            let output_pending = output_pending && !waited;
            for _ in 0..unanswered {
                // Replies leave in request order, so this refuses the oldest
                // request still waiting, which is the one the reader dropped
                // unless the application left an earlier one unanswered.
                if self.handle_routed_requests
                    || !self.connection.active(id).is_ok_and(|open| {
                        matches!(
                            open.incoming_requests.front(),
                            Some(super::IncomingReply::Application)
                        )
                    })
                {
                    break;
                }
                self.connection.reply(id, false).await?;
            }
            let route = self.routes.get_mut(&id).expect("existing route");
            if readers_gone && writers_gone && !output_pending {
                route.aborted = true;
                self.abort_output(id);
                match self.connection.state_mut(id) {
                    Some(State::Opening { cancelled, .. }) => *cancelled = true,
                    Some(State::Open(open)) => {
                        open.abandoned = true;
                        self.connection.close(id).await?;
                    }
                    _ => {}
                }
            } else {
                if readers_gone {
                    self.discard_received(id).await?;
                } else if credit != 0 {
                    self.consume_routed(id, credit).await?;
                }
                if writers_gone
                    && !output_pending
                    && self.connection.active(id).is_ok_and(|open| !open.sent_eof)
                {
                    self.connection.eof(id).await?;
                }
            }
        }
        Ok(())
    }

    async fn settle_opens(&mut self) -> io::Result<()> {
        let mut index = 0;
        while let Some((channel, claim)) = self.unclaimed_opens.get(index) {
            let channel = *channel;
            let state = self.connection.state_mut(channel);
            match (claim.load(Ordering::Acquire), state) {
                (OPEN_WAITING, Some(_)) => {
                    index += 1;
                    continue;
                }
                (OPEN_CANCELLED, Some(State::Opening { cancelled, .. })) => *cancelled = true,
                (OPEN_CANCELLED, Some(State::Open(open))) => {
                    open.abandoned = true;
                    self.connection.close(channel).await?;
                }
                _ => {}
            }
            self.unclaimed_opens.swap_remove(index);
        }
        Ok(())
    }

    async fn settle_incoming(&mut self) -> io::Result<()> {
        let mut index = 0;
        while let Some((id, abandoned)) = self.incoming.get(index) {
            let id = *id;
            if matches!(self.connection.state(id), Some(State::Incoming(_))) {
                if !abandoned.load(Ordering::Acquire) {
                    index += 1;
                    continue;
                }
                self.connection.refuse(id, 1).await?;
            }
            self.incoming.swap_remove(index);
        }
        Ok(())
    }
}

fn complete<T>(reply: Reply<T>, result: io::Result<T>, terminal: bool) -> io::Result<()> {
    match result {
        Err(error) if terminal => {
            let _ = reply.send(Err(io::Error::new(error.kind(), error.to_string())));
            Err(error)
        }
        result => {
            let _ = reply.send(result);
            Ok(())
        }
    }
}

fn stopped() -> io::Error {
    io::Error::new(ErrorKind::BrokenPipe, "SSH connection driver stopped")
}

#[cfg(test)]
mod tests;

mod handle;
