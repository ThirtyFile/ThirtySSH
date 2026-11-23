//! Multiplexed SSH channels driven by an authenticated connection.
//!
//! Read events and perform operations from the same task. Let operations run
//! to completion, since they can send packets or drive a key exchange.
use crate::{
    auth::{Authenticated, malformed},
    clear_packet::{MAX_CHANNEL_DATA, invalid},
    keys::{CertificatePermissions, CertificateRequest},
    protection::ReceivedPacket,
    transport::{Input, peer_disconnected},
    wire::{Reader, Writer},
};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, ErrorKind},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub mod driver;
pub(crate) use driver::DEFAULT_COMMAND_CAPACITY;
pub(crate) mod global;
mod stream;
pub(crate) use stream::Inbox;

pub use bytes::Bytes;
pub use global::{GlobalReply, GlobalRequest, GlobalRequestId};
pub use stream::{
    Channel, ChannelIo, ChannelReceiver, ChannelSender, DataReader, DataWriter, Message,
};

const OPEN: u8 = 90;
const CONFIRM: u8 = 91;
const OPEN_FAILURE: u8 = 92;
const ADJUST: u8 = 93;
const DATA: u8 = 94;
const EXTENDED_DATA: u8 = 95;
const EOF: u8 = 96;
const CLOSE: u8 = 97;
const REQUEST: u8 = 98;
const SUCCESS: u8 = 99;
const FAILURE: u8 = 100;
pub(crate) const KEEPALIVE_REQUEST: &str = "keepalive@openssh.com";
const MAX_CHANNELS: usize = 128;
pub(crate) const MAX_REQUESTS: usize = 128;
pub(crate) const MAX_FIELDS: usize = 48 * 1024;

pub const MAX_DATA: u32 = 32 * 1024;
pub const DEFAULT_WINDOW: u32 = 2 * 1024 * 1024;
/// Default limit on the receive windows of all channels of one connection
/// that have their own reader. It bounds the unread data a peer can make
/// the connection buffer, and allows 32 channels with the default window.
pub const DEFAULT_WINDOW_BUDGET: u32 = 32 * DEFAULT_WINDOW;
// Leave room for zlib to expand incompressible data without exceeding the
// peer's transport limit. This ceiling also holds if a later rekey enables zlib.
const MAX_OUTGOING_DATA: u32 = MAX_CHANNEL_DATA - 1024;

pub(crate) fn validate_maximum_packet_size(size: u32) -> io::Result<()> {
    if !(1..=MAX_CHANNEL_DATA).contains(&size) {
        return Err(input(
            "SSH channel maximum packet size must be in 1..=262144",
        ));
    }
    Ok(())
}

/// Connection-local identifier. IDs are never reused within a connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(u32);

impl From<ChannelId> for u32 {
    fn from(id: ChannelId) -> Self {
        id.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A peer's channel-open refusal. The full payload is available from the
/// inner error of a `ConnectionRefused` returned by `open_channel`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenFailure {
    pub reason: u32,
    pub description: Bytes,
    pub language: Bytes,
}

impl OpenFailure {
    pub fn new(reason: u32) -> Self {
        Self {
            reason,
            description: Bytes::new(),
            language: Bytes::new(),
        }
    }

    fn field_size(description: &[u8], language: &[u8]) -> io::Result<usize> {
        let size = description.len().saturating_add(language.len());
        if size > MAX_FIELDS {
            return Err(input("SSH channel refusal fields exceed limit"));
        }
        Ok(size)
    }
}

impl fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SSH channel open refused ({})", self.reason)
    }
}

impl std::error::Error for OpenFailure {}

#[derive(Clone, Eq, PartialEq)]
pub enum Event {
    GlobalRequest(GlobalRequest),
    GlobalReply(GlobalReply),
    Incoming {
        channel: ChannelId,
        kind: Vec<u8>,
        fields: Vec<u8>,
    },
    Opened {
        channel: ChannelId,
        fields: Vec<u8>,
    },
    Refused {
        channel: ChannelId,
        reason: u32,
        description: Vec<u8>,
        language: Vec<u8>,
    },
    WindowAdjusted {
        channel: ChannelId,
        remaining: u32,
    },
    Data {
        channel: ChannelId,
        extended: Option<u32>,
        data: Vec<u8>,
    },
    Request {
        channel: ChannelId,
        name: Vec<u8>,
        want_reply: bool,
        fields: Vec<u8>,
    },
    Reply {
        channel: ChannelId,
        success: bool,
    },
    Eof(ChannelId),
    Closed(ChannelId),
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlobalRequest(value) => f.debug_tuple("GlobalRequest").field(value).finish(),
            Self::GlobalReply(value) => f.debug_tuple("GlobalReply").field(value).finish(),
            Self::Incoming {
                channel,
                kind,
                fields,
            } => f
                .debug_struct("Incoming")
                .field("channel", channel)
                .field("kind", kind)
                .field("fields", fields)
                .finish(),
            Self::Opened { channel, fields } => f
                .debug_struct("Opened")
                .field("channel", channel)
                .field("fields", fields)
                .finish(),
            Self::Refused {
                channel,
                reason,
                description,
                language,
            } => f
                .debug_struct("Refused")
                .field("channel", channel)
                .field("reason", reason)
                .field("description", description)
                .field("language", language)
                .finish(),
            Self::WindowAdjusted { channel, remaining } => f
                .debug_struct("WindowAdjusted")
                .field("channel", channel)
                .field("remaining", remaining)
                .finish(),
            Self::Data {
                channel,
                extended,
                data,
            } => f
                .debug_struct("Data")
                .field("channel", channel)
                .field("extended", extended)
                .field("data", data)
                .finish(),
            Self::Request {
                channel,
                name,
                want_reply,
                fields,
            } => {
                let mut request = f.debug_struct("Request");
                request
                    .field("channel", channel)
                    .field("name", name)
                    .field("want_reply", want_reply);
                if &name[..] == b"x11-req" {
                    request.finish_non_exhaustive()
                } else {
                    request.field("fields", fields).finish()
                }
            }
            Self::Reply { channel, success } => f
                .debug_struct("Reply")
                .field("channel", channel)
                .field("success", success)
                .finish(),
            Self::Eof(value) => f.debug_tuple("Eof").field(value).finish(),
            Self::Closed(value) => f.debug_tuple("Closed").field(value).finish(),
        }
    }
}

impl Event {
    fn channel(&self) -> Option<ChannelId> {
        Some(match *self {
            Self::GlobalRequest(_) | Self::GlobalReply(_) => return None,
            Self::Incoming { channel, .. }
            | Self::Opened { channel, .. }
            | Self::Refused { channel, .. }
            | Self::WindowAdjusted { channel, .. }
            | Self::Data { channel, .. }
            | Self::Request { channel, .. }
            | Self::Reply { channel, .. }
            | Self::Eof(channel)
            | Self::Closed(channel) => channel,
        })
    }
}

#[derive(Clone, Copy)]
struct Remote {
    id: u32,
    window: u32,
    max_data: u32,
}

impl Remote {
    fn read(fields: &mut Reader<'_>) -> io::Result<Self> {
        Ok(Self {
            id: fields.uint32().map_err(malformed)?,
            window: fields.uint32().map_err(malformed)?,
            max_data: fields.uint32().map_err(malformed)?,
        })
    }
}

/// Smallest peer `maximum packet size` we accept. A peer advertising one byte
/// would make every payload byte cost a separate encrypted packet.
const MIN_REMOTE_MAX_DATA: u32 = 128;

struct Open {
    remote: Remote,
    window: u32,
    unread: u32,
    receive_capacity: u32,
    requested_credit: u32,
    sent_eof: bool,
    got_eof: bool,
    closing: bool,
    abandoned: bool,
    incoming_requests: VecDeque<IncomingReply>,
    outgoing_requests: usize,
}

impl Open {
    fn writable_packet_size(&self) -> usize {
        self.remote.window.min(self.outgoing_packet_limit()) as usize
    }

    fn outgoing_packet_limit(&self) -> u32 {
        self.remote.max_data.min(MAX_OUTGOING_DATA)
    }

    fn needs_receive_credit(&self) -> bool {
        self.window == 0 || self.window < self.receive_capacity / 2
    }

    fn new(remote: Remote, window: u32) -> Self {
        Self {
            remote,
            window,
            unread: 0,
            receive_capacity: window,
            requested_credit: 0,
            sent_eof: false,
            got_eof: false,
            closing: false,
            abandoned: false,
            incoming_requests: VecDeque::new(),
            outgoing_requests: 0,
        }
    }
}

enum IncomingReply {
    Application,
    Automatic(bool),
}

enum State {
    Opening { window: u32, cancelled: bool },
    Incoming(Remote),
    Open(Open),
}

impl State {
    fn remote_id(&self) -> Option<u32> {
        match self {
            Self::Opening { .. } => None,
            Self::Incoming(remote) | Self::Open(Open { remote, .. }) => Some(remote.id),
        }
    }
}

struct ChannelIds {
    next: AtomicU64,
    slots: Arc<Semaphore>,
    permissions: Option<CertificatePermissions>,
    maximum_packet_size: u32,
}

impl ChannelIds {
    fn new(permissions: Option<CertificatePermissions>, maximum_packet_size: u32) -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(0),
            slots: Arc::new(Semaphore::new(MAX_CHANNELS)),
            permissions,
            maximum_packet_size,
        })
    }

    fn allocate(&self) -> Option<(ChannelId, OwnedSemaphorePermit)> {
        let slot = self.slots.clone().try_acquire_owned().ok()?;
        let mut next = self.next.load(Ordering::Relaxed);
        loop {
            let id = u32::try_from(next).ok()?;
            match self.next.compare_exchange_weak(
                next,
                next + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some((ChannelId(id), slot)),
                Err(actual) => next = actual,
            }
        }
    }

    fn prepare(&self, kind: &str, window: u32, fields: &[u8]) -> io::Result<OpenFrame> {
        if !valid_channel_name(kind.as_bytes()) {
            return Err(input("invalid SSH channel name"));
        }
        if self
            .permissions
            .as_ref()
            .is_some_and(|policy| !policy.allows_open(kind.as_bytes(), fields))
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "SSH certificate prohibits this channel",
            ));
        }
        let size = named_size(17, kind, fields)?;
        let (id, slot) = self
            .allocate()
            .ok_or_else(|| io::Error::other("SSH channel limit reached"))?;
        let payload = packet(size, |writer| {
            writer.byte(OPEN)?;
            writer.string(kind.as_bytes())?;
            writer.uint32(id.0)?;
            writer.uint32(window)?;
            writer.uint32(self.maximum_packet_size)?;
            writer.fixed(fields)
        })?;
        Ok(OpenFrame {
            id,
            slot,
            window,
            payload,
        })
    }
}

struct OpenFrame {
    id: ChannelId,
    slot: OwnedSemaphorePermit,
    window: u32,
    payload: Vec<u8>,
}

struct ChannelState {
    state: State,
    _slot: OwnedSemaphorePermit,
}

/// Owns an authenticated transport and its bounded set of channel states.
pub struct Connection<S> {
    connection: Authenticated<S>,
    channels: HashMap<ChannelId, ChannelState>,
    ids: Arc<ChannelIds>,
    repeated_refusals: VecDeque<ChannelId>,
    global: global::Requests,
    failed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(connection: Authenticated<S>) -> Self {
        Self::with_packet_size(connection, MAX_DATA)
    }

    pub(crate) fn with_packet_size(connection: Authenticated<S>, maximum_packet_size: u32) -> Self {
        debug_assert!(validate_maximum_packet_size(maximum_packet_size).is_ok());
        let ids = ChannelIds::new(connection.permissions.clone(), maximum_packet_size);
        Self {
            connection,
            channels: HashMap::new(),
            ids,
            repeated_refusals: VecDeque::new(),
            global: global::Requests::default(),
            failed: false,
        }
    }

    pub fn username(&self) -> &str {
        self.connection.username()
    }

    /// Start an open request. The result arrives later as an event.
    pub async fn open(&mut self, kind: &str, window: u32, fields: &[u8]) -> io::Result<ChannelId> {
        let frame = self.ids.prepare(kind, window, fields)?;
        let id = frame.id;
        self.open_reserved(frame).await?;
        Ok(id)
    }

    async fn open_reserved(&mut self, frame: OpenFrame) -> io::Result<()> {
        let OpenFrame {
            id,
            slot,
            window,
            payload,
        } = frame;
        self.send(&payload).await?;
        self.channels.insert(
            id,
            ChannelState {
                state: State::Opening {
                    window,
                    cancelled: false,
                },
                _slot: slot,
            },
        );
        Ok(())
    }

    /// Cancel a pending open. A late confirmation is closed automatically.
    pub fn cancel_open(&mut self, channel: ChannelId) -> io::Result<()> {
        match self.state_mut(channel) {
            Some(State::Opening { cancelled, .. }) => {
                *cancelled = true;
                Ok(())
            }
            _ => Err(input("SSH channel is not opening")),
        }
    }

    pub async fn accept(
        &mut self,
        channel: ChannelId,
        window: u32,
        fields: &[u8],
    ) -> io::Result<()> {
        if fields.len() > MAX_DATA as usize {
            return Err(input("SSH confirmation fields exceed limit"));
        }
        let remote = self.incoming(channel)?;
        let payload = packet(17 + fields.len(), |writer| {
            writer.byte(CONFIRM)?;
            writer.uint32(remote)?;
            writer.uint32(channel.0)?;
            writer.uint32(window)?;
            writer.uint32(self.ids.maximum_packet_size)?;
            writer.fixed(fields)
        })?;
        self.send(&payload).await?;
        let Some(entry) = self.channels.get_mut(&channel) else {
            unreachable!("checked before sending");
        };
        let State::Incoming(ref remote) = entry.state else {
            unreachable!("checked before sending");
        };
        entry.state = State::Open(Open::new(*remote, window));
        Ok(())
    }

    pub async fn refuse(&mut self, channel: ChannelId, reason: u32) -> io::Result<()> {
        self.refuse_with(channel, &OpenFailure::new(reason)).await
    }

    pub async fn refuse_with(
        &mut self,
        channel: ChannelId,
        failure: &OpenFailure,
    ) -> io::Result<()> {
        let remote = self.incoming(channel)?;
        self.send_refusal(remote, failure).await?;
        self.channels.remove(&channel);
        Ok(())
    }

    /// Send up to one packet. A short write leaves the remainder with the
    /// caller. Zero indicates an empty slice or a full peer receive window.
    pub async fn send_data(
        &mut self,
        channel: ChannelId,
        extended: Option<u32>,
        data: &[u8],
    ) -> io::Result<usize> {
        let open = self.active(channel)?;
        if open.sent_eof {
            return Err(input("SSH channel already sent EOF"));
        }
        let remote = open.remote.id;
        let len = data.len().min(open.writable_packet_size());
        if len == 0 {
            return Ok(0);
        }
        let payload = packet(13 + len, |writer| {
            writer.byte(if extended.is_some() {
                EXTENDED_DATA
            } else {
                DATA
            })?;
            writer.uint32(remote)?;
            if let Some(code) = extended {
                writer.uint32(code)?;
            }
            writer.string(&data[..len])
        })?;
        self.send(&payload).await?;
        self.open_mut(channel)?.remote.window -= len as u32;
        Ok(len)
    }

    /// Return receive credit after delivering or discarding data. Credit may
    /// be batched, and can never exceed the bytes delivered through events.
    pub async fn consume(&mut self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        if self.release_received(channel, bytes)? && bytes != 0 {
            self.adjust_receive_window(channel, bytes).await?;
        }
        Ok(())
    }

    fn release_received(&mut self, channel: ChannelId, bytes: u32) -> io::Result<bool> {
        let open = self.open_mut(channel)?;
        if bytes > open.unread {
            return Err(input("SSH channel credit exceeds unread bytes"));
        }
        open.unread -= bytes;
        Ok(!open.closing)
    }

    /// Increase receive capacity, for example to start a channel opened with
    /// a zero window. The caller is responsible for provisioning the capacity.
    pub async fn grant(&mut self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        let open = self.active(channel)?;
        if bytes > u32::MAX - open.window - open.unread {
            return Err(input("SSH channel receive capacity overflow"));
        }
        if bytes != 0 {
            self.adjust_receive_window(channel, bytes).await?;
        }
        Ok(())
    }

    async fn adjust_receive_window(&mut self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        let remote = self.active(channel)?.remote.id;
        let payload = packet(9, |writer| {
            writer.byte(ADJUST)?;
            writer.uint32(remote)?;
            writer.uint32(bytes)
        })?;
        self.send(&payload).await?;
        self.open_mut(channel)?.window += bytes;
        Ok(())
    }

    pub async fn request(
        &mut self,
        channel: ChannelId,
        name: &str,
        want_reply: bool,
        fields: &[u8],
    ) -> io::Result<()> {
        let size = named_size(10, name, fields)?;
        let open = self.active(channel)?;
        if want_reply && open.outgoing_requests == MAX_REQUESTS {
            return Err(input("SSH channel request limit reached"));
        }
        let remote = open.remote.id;
        let payload = packet(size, |writer| {
            writer.byte(REQUEST)?;
            writer.uint32(remote)?;
            writer.string(name.as_bytes())?;
            writer.boolean(want_reply)?;
            writer.fixed(fields)
        })?;
        self.send(&payload).await?;
        self.open_mut(channel)?.outgoing_requests += usize::from(want_reply);
        Ok(())
    }

    /// Reply in the order that reply-bearing requests arrived on this channel.
    pub async fn reply(&mut self, channel: ChannelId, success: bool) -> io::Result<()> {
        let open = self.active(channel)?;
        if !matches!(
            open.incoming_requests.front(),
            Some(IncomingReply::Application)
        ) {
            return Err(input("SSH channel has no request awaiting a reply"));
        }
        self.control(if success { SUCCESS } else { FAILURE }, open.remote.id)
            .await?;
        self.open_mut(channel)?.incoming_requests.pop_front();
        self.flush_channel_replies(channel).await
    }

    async fn flush_channel_replies(&mut self, channel: ChannelId) -> io::Result<()> {
        loop {
            let open = self.active(channel)?;
            let Some(IncomingReply::Automatic(success)) = open.incoming_requests.front() else {
                break;
            };
            self.control(if *success { SUCCESS } else { FAILURE }, open.remote.id)
                .await?;
            self.open_mut(channel)?.incoming_requests.pop_front();
        }
        Ok(())
    }

    pub async fn eof(&mut self, channel: ChannelId) -> io::Result<()> {
        let open = self.active(channel)?;
        if !open.sent_eof {
            self.control(EOF, open.remote.id).await?;
            self.open_mut(channel)?.sent_eof = true;
        }
        Ok(())
    }

    /// Initiate a close. The ID remains reserved until a Closed event.
    pub async fn close(&mut self, channel: ChannelId) -> io::Result<()> {
        let open = self.open_mut(channel)?;
        if !open.closing {
            let remote = open.remote.id;
            self.control(CLOSE, remote).await?;
            self.open_mut(channel)?.closing = true;
        }
        Ok(())
    }

    pub async fn disconnect(self) -> io::Result<()> {
        self.connection.transport.disconnect().await
    }

    async fn disconnect_with_packet(self, packet: &[u8]) -> io::Result<()> {
        self.connection
            .transport
            .disconnect_with_packet(packet)
            .await
    }

    /// Request a new key exchange while preserving open channels.
    pub async fn rekey(&mut self) -> io::Result<()> {
        self.check()?;
        self.connection.transport.rekey().await
    }

    /// Consume the next event from the connection or any open channel.
    pub async fn next_event(&mut self) -> io::Result<Event> {
        loop {
            let input = self.wait_input().await?;
            if let Some(event) = self.process_input(input).await? {
                return Ok(event);
            }
        }
    }

    async fn wait_input(&mut self) -> io::Result<Input> {
        self.check()?;
        self.connection
            .transport
            .read_input()
            .await
            .inspect_err(|_| self.failed = true)
    }

    async fn process_input(&mut self, input: Input) -> io::Result<Option<Event>> {
        let Some(packet) = self.connection.transport.handle_packet_input(input).await? else {
            return Ok(None);
        };
        self.dispatch(packet)
            .await
            .inspect_err(|_| self.failed = true)
    }

    async fn dispatch(&mut self, packet: ReceivedPacket) -> io::Result<Option<Event>> {
        let mut fields = Reader::new(&packet[1..]);
        match packet[0] {
            1 => Err(peer_disconnected(&packet)),
            2 | 4 => Ok(None),
            global::REQUEST => self.receive_global_request(fields).await,
            global::SUCCESS | global::FAILURE => self.receive_global_reply(packet[0], fields),
            OPEN => self.peer_open(fields).await,
            message @ CONFIRM..=FAILURE => {
                let channel = ChannelId(fields.uint32().map_err(malformed)?);
                match message {
                    CONFIRM | OPEN_FAILURE => self.open_reply(channel, message, fields).await,
                    DATA | EXTENDED_DATA => self.received_data(channel, message, packet),
                    _ => self.channel_event(channel, message, fields).await,
                }
            }
            _ => Err(invalid("unexpected SSH connection message")),
        }
    }

    fn is_failed(&self) -> bool {
        self.failed || self.connection.transport.is_failed()
    }

    /// After the connection is lost, the next thing the peer had already said
    /// on a channel: its data, end of file, close, and requests that expect
    /// no answer, such as an exit status. Nothing can be sent any more, so
    /// everything that would need a reply or a decision is left out.
    pub(crate) fn salvage(&mut self) -> Option<Event> {
        loop {
            let packet = self.connection.transport.take_undelivered()?;
            let mut fields = Reader::new(packet.get(1..)?);
            let message = *packet.first()?;
            if !matches!(message, DATA | EXTENDED_DATA | EOF | CLOSE | REQUEST) {
                continue;
            }
            let Ok(id) = fields.uint32() else { continue };
            let channel = ChannelId(id);
            let event = match message {
                // A packet that breaks the channel's limits ends the salvage:
                // what follows it cannot be trusted to be in sequence.
                DATA | EXTENDED_DATA => self.received_data(channel, message, packet).ok()?,
                EOF => {
                    let open = self.open_mut(channel).ok()?;
                    if std::mem::replace(&mut open.got_eof, true) {
                        return None;
                    }
                    (!open.abandoned).then_some(Event::Eof(channel))
                }
                CLOSE => {
                    self.open_mut(channel).ok()?;
                    self.channels.remove(&channel);
                    Some(Event::Closed(channel))
                }
                _ => {
                    let open = self.open_mut(channel).ok()?;
                    let unanswered = !open.closing && !open.abandoned;
                    match (fields.string(), fields.boolean()) {
                        // A certificate's restrictions are applied where
                        // requests are answered, so restricted sessions keep
                        // none of them.
                        (Ok(name), Ok(false))
                            if unanswered && self.connection.permissions.is_none() =>
                        {
                            Some(Event::Request {
                                channel,
                                name: name.to_vec(),
                                want_reply: false,
                                fields: fields.remaining().to_vec(),
                            })
                        }
                        _ => None,
                    }
                }
            };
            if event.is_some() {
                return event;
            }
        }
    }

    async fn peer_open(&mut self, mut fields: Reader<'_>) -> io::Result<Option<Event>> {
        let kind = fields.string().map_err(malformed)?;
        let remote = Remote::read(&mut fields)?;
        self.unique_remote(remote.id)?;
        if !valid_channel_name(kind) {
            self.send_refusal(remote.id, &OpenFailure::new(3)).await?;
            return Ok(None);
        }
        if remote.max_data < MIN_REMOTE_MAX_DATA {
            self.send_refusal(remote.id, &OpenFailure::new(1)).await?;
            return Ok(None);
        }
        if self
            .connection
            .permissions
            .as_ref()
            .is_some_and(|policy| !policy.allows_open(kind, fields.remaining()))
        {
            self.send_refusal(remote.id, &OpenFailure::new(1)).await?;
            return Ok(None);
        }
        let Some((channel, slot)) = self.ids.allocate() else {
            self.send_refusal(remote.id, &OpenFailure::new(4)).await?;
            return Ok(None);
        };
        self.channels.insert(
            channel,
            ChannelState {
                state: State::Incoming(remote),
                _slot: slot,
            },
        );
        Ok(Some(Event::Incoming {
            channel,
            kind: kind.to_vec(),
            fields: fields.remaining().to_vec(),
        }))
    }

    async fn open_reply(
        &mut self,
        channel: ChannelId,
        message: u8,
        mut fields: Reader<'_>,
    ) -> io::Result<Option<Event>> {
        if message == OPEN_FAILURE {
            let reason = fields.uint32().map_err(malformed)?;
            let description = fields.string().map_err(malformed)?;
            let language = fields.string().map_err(malformed)?;
            fields.finish().map_err(malformed)?;
            if reason == 1
                && description == b"Administratively prohibited"
                && language == b"en"
                && let Some(index) = self
                    .repeated_refusals
                    .iter()
                    .position(|old| *old == channel)
            {
                self.repeated_refusals.remove(index);
                return Ok(None);
            }
            let Some(ChannelState {
                state: State::Opening { cancelled, .. },
                ..
            }) = self.channels.remove(&channel)
            else {
                return Err(invalid("unexpected SSH channel open reply"));
            };
            // Some peers send two refusals for the same channel-open request.
            // IDs are never reused, so a single matching duplicate is unambiguous.
            if language == b"en"
                && matches!(
                    (reason, description),
                    (3, b"Unknown channel type") | (1, b"Unsupported channel type")
                )
            {
                if self.repeated_refusals.len() == MAX_CHANNELS {
                    self.repeated_refusals.pop_front();
                }
                self.repeated_refusals.push_back(channel);
            }
            return Ok((!cancelled).then_some(Event::Refused {
                channel,
                reason,
                description: description.to_vec(),
                language: language.to_vec(),
            }));
        }
        let Some(State::Opening { window, cancelled }) = self.state(channel) else {
            return Err(invalid("unexpected SSH channel open reply"));
        };
        let (window, cancelled) = (*window, *cancelled);
        let remote = Remote::read(&mut fields)?;
        self.unique_remote(remote.id)?;
        if remote.max_data < MIN_REMOTE_MAX_DATA {
            // The channel is unusable, but only this channel: close it and
            // report the open as refused, as a peer's own open with such a
            // limit is refused.
            let mut open = Open::new(remote, window);
            open.abandoned = true;
            *self.state_mut(channel).expect("opening channel") = State::Open(open);
            self.close(channel).await?;
            return Ok((!cancelled).then(|| Event::Refused {
                channel,
                reason: 2,
                description: b"peer's maximum packet size is too small".to_vec(),
                language: Vec::new(),
            }));
        }
        let mut open = Open::new(remote, window);
        open.abandoned = cancelled;
        *self.state_mut(channel).expect("opening channel") = State::Open(open);
        if cancelled {
            self.close(channel).await?;
            return Ok(None);
        }
        Ok(Some(Event::Opened {
            channel,
            fields: fields.remaining().to_vec(),
        }))
    }

    fn received_data(
        &mut self,
        channel: ChannelId,
        message: u8,
        packet: ReceivedPacket,
    ) -> io::Result<Option<Event>> {
        let maximum_packet_size = self.ids.maximum_packet_size;
        let open = self
            .open_mut(channel)
            .map_err(|_| invalid("unknown or unconfirmed SSH channel ID"))?;
        let mut fields = Reader::new(&packet[5..]);
        let extended = if message == EXTENDED_DATA {
            Some(fields.uint32().map_err(malformed)?)
        } else {
            None
        };
        let data = fields.string().map_err(malformed)?;
        let len = data.len() as u32;
        if open.got_eof || len > open.window || len > maximum_packet_size {
            return Err(invalid(
                "SSH channel data exceeds advertised limit or follows EOF",
            ));
        }
        fields.finish().map_err(malformed)?;
        open.window -= len;
        open.unread += len;
        if open.abandoned {
            return Ok(None);
        }

        let len = data.len();
        Ok(Some(Event::Data {
            channel,
            extended,
            data: packet.into_suffix(len),
        }))
    }

    async fn channel_event(
        &mut self,
        channel: ChannelId,
        message: u8,
        mut fields: Reader<'_>,
    ) -> io::Result<Option<Event>> {
        if message == REQUEST {
            return self.peer_request(channel, fields).await;
        }
        let open = self
            .open_mut(channel)
            .map_err(|_| invalid("unknown or unconfirmed SSH channel ID"))?;
        let event = match message {
            ADJUST => {
                let increment = fields.uint32().map_err(malformed)?;
                open.remote.window = open
                    .remote
                    .window
                    .checked_add(increment)
                    .ok_or_else(|| invalid("SSH channel window overflow"))?;
                Event::WindowAdjusted {
                    channel,
                    remaining: open.remote.window,
                }
            }
            SUCCESS | FAILURE => {
                if open.outgoing_requests == 0 {
                    return Err(invalid("unexpected SSH channel request reply"));
                }
                open.outgoing_requests -= 1;
                Event::Reply {
                    channel,
                    success: message == SUCCESS,
                }
            }
            EOF => {
                if open.got_eof {
                    return Err(invalid("repeated SSH channel EOF"));
                }
                open.got_eof = true;
                Event::Eof(channel)
            }
            CLOSE => {
                fields.finish().map_err(malformed)?;
                self.close(channel).await?;
                self.channels.remove(&channel);
                return Ok(Some(Event::Closed(channel)));
            }
            _ => unreachable!("only channel messages reach this dispatcher"),
        };
        fields.finish().map_err(malformed)?;
        Ok((!open.abandoned).then_some(event))
    }

    async fn peer_request(
        &mut self,
        channel: ChannelId,
        mut fields: Reader<'_>,
    ) -> io::Result<Option<Event>> {
        let name = fields.string().map_err(malformed)?;
        let want_reply = fields.boolean().map_err(malformed)?;
        if self
            .open_mut(channel)
            .map_err(|_| invalid("unknown or unconfirmed SSH channel ID"))?
            .closing
        {
            return Ok(None);
        }
        let (decision, event) = if name == KEEPALIVE_REQUEST.as_bytes() {
            fields.finish().map_err(malformed)?;
            (IncomingReply::Automatic(true), None)
        } else {
            let request = match &self.connection.permissions {
                Some(policy) => policy.request(name, fields.remaining())?,
                None => CertificateRequest::Allow,
            };
            let (name, data) = match request {
                CertificateRequest::Reject => {
                    self.record_peer_reply(channel, want_reply, IncomingReply::Automatic(false))
                        .await?;
                    return Ok(None);
                }
                CertificateRequest::ForcedExec(command) => (b"exec".as_slice(), command),
                CertificateRequest::Allow => (name, fields.remaining()),
            };
            (
                IncomingReply::Application,
                Some(Event::Request {
                    channel,
                    name: name.to_vec(),
                    want_reply,
                    fields: data.to_vec(),
                }),
            )
        };
        self.record_peer_reply(channel, want_reply, decision)
            .await?;
        Ok(event)
    }

    async fn record_peer_reply(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        decision: IncomingReply,
    ) -> io::Result<()> {
        if want_reply {
            let open = self.open_mut(channel)?;
            if open.incoming_requests.len() == MAX_REQUESTS {
                return Err(invalid("too many outstanding SSH channel requests"));
            }
            let automatic = matches!(decision, IncomingReply::Automatic(_));
            open.incoming_requests.push_back(decision);
            if automatic {
                self.flush_channel_replies(channel).await?;
            }
        }
        Ok(())
    }

    fn check(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "SSH channel connection failed",
            ));
        }
        Ok(())
    }

    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.check()?;
        self.connection.transport.send(payload).await
    }

    async fn control(&mut self, message: u8, remote: u32) -> io::Result<()> {
        let mut bytes = [message; 5];
        bytes[1..].copy_from_slice(&remote.to_be_bytes());
        self.send(&bytes).await
    }

    async fn send_refusal(&mut self, remote: u32, failure: &OpenFailure) -> io::Result<()> {
        let size = OpenFailure::field_size(&failure.description, &failure.language)?;
        self.send(&packet(17 + size, |writer| {
            writer.byte(OPEN_FAILURE)?;
            writer.uint32(remote)?;
            writer.uint32(failure.reason)?;
            writer.string(&failure.description)?;
            writer.string(&failure.language)
        })?)
        .await
    }

    fn incoming(&self, channel: ChannelId) -> io::Result<u32> {
        match self.state(channel) {
            Some(State::Incoming(remote)) => Ok(remote.id),
            _ => Err(input("SSH channel is not awaiting acceptance")),
        }
    }

    fn open_mut(&mut self, channel: ChannelId) -> io::Result<&mut Open> {
        match self.state_mut(channel) {
            Some(State::Open(open)) => Ok(open),
            _ => Err(input("SSH channel is not open")),
        }
    }

    fn active(&self, channel: ChannelId) -> io::Result<&Open> {
        match self.state(channel) {
            Some(State::Open(open)) if !open.closing => Ok(open),
            _ => Err(input("SSH channel is not active")),
        }
    }

    fn unique_remote(&self, id: u32) -> io::Result<()> {
        if self
            .channels
            .values()
            .any(|entry| entry.state.remote_id() == Some(id))
        {
            return Err(invalid("duplicate SSH peer channel ID"));
        }
        Ok(())
    }

    fn state(&self, channel: ChannelId) -> Option<&State> {
        self.channels.get(&channel).map(|entry| &entry.state)
    }

    fn state_mut(&mut self, channel: ChannelId) -> Option<&mut State> {
        self.channels
            .get_mut(&channel)
            .map(|entry| &mut entry.state)
    }
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn valid_channel_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b',')
}

fn named_size(overhead: usize, name: &str, fields: &[u8]) -> io::Result<usize> {
    if name.is_empty() || !name.is_ascii() || name.len().saturating_add(fields.len()) > MAX_FIELDS {
        return Err(input("invalid or oversized SSH channel message fields"));
    }
    Ok(overhead + name.len() + fields.len())
}

pub(crate) fn packet(
    size: usize,
    encode: impl FnOnce(&mut Writer<'_>) -> Result<(), crate::wire::Error>,
) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; size];
    let mut writer = Writer::new(&mut bytes);
    encode(&mut writer).map_err(io::Error::other)?;
    let written = writer.written().len();
    bytes.truncate(written);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn raw_x11_events_hide_fields_from_both_debug_formats() {
        let fields = b"private-cookie".to_vec();
        for name in [b"x11-req".as_slice(), b"custom"] {
            let event = super::Event::Request {
                channel: super::ChannelId(7),
                name: name.to_vec(),
                want_reply: true,
                fields: fields.clone(),
            };
            let debug_event = format!("{event:?}");
            let message = super::stream::Delivery::from_event(event).unwrap();
            let debug_message = format!("{message:#?}");
            for text in [debug_event, debug_message] {
                assert!(text.contains("want_reply"));
                assert_eq!(text.contains("fields"), name == b"custom");
                if name == b"x11-req" {
                    assert!(!text.contains("private-cookie") && !text.contains("112, 114"));
                }
            }
            assert!(
                matches!(message, super::stream::Delivery::Message(super::Message::Request { fields: bytes, .. }) if bytes[..] == fields)
            );
        }
    }

    use super::*;
    use crate::transport::{HostKey, Transport};
    use std::time::Duration;
    use tokio::{io, time::timeout};

    #[derive(Clone, Copy, Debug)]
    enum BadEvent {
        UnknownChannel,
        DuplicateConfirmation,
        WindowOverflow,
        DataBeyondWindow,
        DataBeyondPacketLimit,
        DataAfterEof,
        DataWithTrailingByte,
    }

    #[tokio::test]
    async fn tolerates_one_matching_upstream_duplicate_refusal() {
        timeout(Duration::from_secs(5), async {
            let host = HostKey::generate().unwrap();
            let (left, right) = io::duplex(4096);
            let (client, peer) = tokio::join!(
                Transport::connect(left, |key| *key == host.public_key()),
                Transport::accept(right, &host),
            );
            let mut client = Connection::new(Authenticated { transport: client.unwrap(), username: String::new(), permissions: None });
            let mut peer = peer.unwrap();
            let first = client.open("example@example.test", 1024, &[]).await.unwrap();
            let second = client.open("session", 1024, &[]).await.unwrap();
            for _ in 0..2 { assert_eq!(peer.receive().await.unwrap()[0], OPEN); }
            let failure = |reason, description: &[u8]| packet(19 + description.len(), |writer| {
                writer.byte(OPEN_FAILURE)?;
                writer.uint32(first.0)?;
                writer.uint32(reason)?;
                writer.string(description)?;
                writer.string(b"en")
            }).unwrap();
            peer.send(&failure(3, b"Unknown channel type")).await.unwrap();
            assert!(matches!(client.next_event().await.unwrap(), Event::Refused { channel, reason: 3, .. } if channel == first));
            let repeated = failure(1, b"Administratively prohibited");
            peer.send(&repeated).await.unwrap();
            let confirmation = packet(17, |writer| {
                writer.byte(CONFIRM)?;
                writer.uint32(second.0)?;
                writer.uint32(51)?;
                writer.uint32(1024)?;
                writer.uint32(MAX_DATA)
            }).unwrap();
            peer.send(&confirmation).await.unwrap();
            assert_eq!(client.next_event().await.unwrap(), Event::Opened { channel: second, fields: Vec::new() });
            peer.send(&repeated).await.unwrap();
            assert_eq!(client.next_event().await.unwrap_err().kind(), ErrorKind::InvalidData);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_channel_packets_fail_without_exposing_their_data() {
        for bad in [
            BadEvent::UnknownChannel,
            BadEvent::DuplicateConfirmation,
            BadEvent::WindowOverflow,
            BadEvent::DataBeyondWindow,
            BadEvent::DataBeyondPacketLimit,
            BadEvent::DataAfterEof,
            BadEvent::DataWithTrailingByte,
        ] {
            timeout(Duration::from_secs(5), async {
                let host = HostKey::generate().unwrap();
                let (left, right) = io::duplex(4096);
                let (client, peer) = tokio::join!(
                    Transport::connect(left, |key| *key == host.public_key()),
                    Transport::accept(right, &host),
                );
                let authenticated = Authenticated {
                    transport: client.unwrap(),
                    username: String::new(),
                    permissions: None,
                };
                let (mut client, window) = if matches!(bad, BadEvent::DataBeyondPacketLimit) {
                    (Connection::with_packet_size(authenticated, 2), 16)
                } else {
                    (Connection::new(authenticated), 1)
                };
                let mut peer = peer.unwrap();
                let channel = client.open("session", window, &[]).await.unwrap();
                assert_eq!(peer.receive().await.unwrap()[0], OPEN);
                let confirmation = packet(17, |writer| {
                    writer.byte(CONFIRM)?;
                    writer.uint32(channel.0)?;
                    writer.uint32(91)?;
                    writer.uint32(u32::MAX)?;
                    writer.uint32(MAX_DATA)
                })
                .unwrap();
                peer.send(&confirmation).await.unwrap();
                assert_eq!(
                    client.next_event().await.unwrap(),
                    Event::Opened {
                        channel,
                        fields: vec![]
                    }
                );

                let data = |data: &[u8]| {
                    packet(9 + data.len(), |writer| {
                        writer.byte(DATA)?;
                        writer.uint32(channel.0)?;
                        writer.string(data)
                    })
                    .unwrap()
                };
                let invalid = match bad {
                    BadEvent::UnknownChannel => vec![CLOSE, 0, 0, 0, 1],
                    BadEvent::DuplicateConfirmation => confirmation,
                    BadEvent::WindowOverflow => packet(9, |writer| {
                        writer.byte(ADJUST)?;
                        writer.uint32(channel.0)?;
                        writer.uint32(1)
                    })
                    .unwrap(),
                    BadEvent::DataBeyondWindow => data(b"ab"),
                    BadEvent::DataBeyondPacketLimit => {
                        peer.send(&data(b"ab")).await.unwrap();
                        assert_eq!(
                            client.next_event().await.unwrap(),
                            Event::Data {
                                channel,
                                extended: None,
                                data: b"ab".to_vec()
                            }
                        );
                        packet(16, |writer| {
                            writer.byte(EXTENDED_DATA)?;
                            writer.uint32(channel.0)?;
                            writer.uint32(1)?;
                            writer.string(b"abc")
                        })
                        .unwrap()
                    }
                    BadEvent::DataAfterEof => {
                        let mut eof = vec![EOF];
                        eof.extend_from_slice(&channel.0.to_be_bytes());
                        peer.send(&eof).await.unwrap();
                        assert_eq!(client.next_event().await.unwrap(), Event::Eof(channel));
                        data(b"a")
                    }
                    BadEvent::DataWithTrailingByte => {
                        let mut packet = data(b"a");
                        packet.push(0);
                        packet
                    }
                };
                peer.send(&invalid).await.unwrap();
                assert_eq!(
                    client.next_event().await.unwrap_err().kind(),
                    ErrorKind::InvalidData,
                    "{bad:?}"
                );
                assert_eq!(
                    client.next_event().await.unwrap_err().kind(),
                    ErrorKind::ConnectionAborted
                );
            })
            .await
            .unwrap();
        }
    }
}
