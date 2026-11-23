//! Channel handles, their message queue and the Tokio byte adapters.
use super::{
    Bytes, ChannelId, DEFAULT_WINDOW, Event, MAX_DATA, Open, OpenFailure,
    driver::{Handle, WritePermit, WriteReceipt},
    input,
};
use crate::session::Request;
use bytes::BytesMut;
use std::{
    collections::VecDeque,
    fmt,
    future::{Future, poll_fn},
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify, mpsc},
};

const CONTROL_LIMIT: u32 = 128 * 1024;
const CONTROL_OVERHEAD: u32 = 1024;
/// Messages a mailbox holds before later ones wait in the backlog, where
/// adjacent data of one stream is joined. The receive window bounds the bytes
/// a peer can queue but not how finely it slices them, so without joining, a
/// window filled one byte at a time would cost a queue entry per byte.
const MAILBOX_CAPACITY: usize = 1024;
/// Entries the backlog holds once joining no longer helps, which takes a peer
/// that alternates streams packet by packet. Past it the channel is overrun.
const BACKLOG_LIMIT: usize = 16 * 1024;

/// What a channel delivers to its receiver, in the order the peer sent it.
#[derive(Eq, PartialEq)]
#[non_exhaustive]
pub enum Message {
    /// Bytes on the channel's ordinary stream.
    Data(Bytes),
    /// Bytes on a numbered side stream. Code 1 is standard error.
    ExtendedData { code: u32, data: Bytes },
    /// A request from the peer. Answer it with `reply` when it asks for one.
    Request {
        name: Bytes,
        want_reply: bool,
        fields: Bytes,
    },
    /// The peer's answer to the oldest request that asked for one.
    Reply { success: bool },
    /// The peer granted more send window. Writers wait for the window by
    /// themselves, so this is reported only by a session whose handler asked
    /// to observe channel events.
    WindowAdjusted { remaining: u32 },
    /// The peer will send no more data.
    Eof,
    /// The channel is closed in both directions.
    Closed,
    /// The peer outran this channel's event budget, and the channel was closed.
    Overrun,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => f.debug_tuple("Data").field(data).finish(),
            Self::ExtendedData { code, data } => f
                .debug_struct("ExtendedData")
                .field("code", code)
                .field("data", data)
                .finish(),
            Self::Request {
                name,
                want_reply,
                fields,
            } => {
                let mut request = f.debug_struct("Request");
                request.field("name", name).field("want_reply", want_reply);
                // The X11 request carries the session's authentication cookie.
                if &name[..] == b"x11-req" {
                    request.finish_non_exhaustive()
                } else {
                    request.field("fields", fields).finish()
                }
            }
            Self::Reply { success } => f.debug_struct("Reply").field("success", success).finish(),
            Self::WindowAdjusted { remaining } => f
                .debug_struct("WindowAdjusted")
                .field("remaining", remaining)
                .finish(),
            Self::Eof => f.write_str("Eof"),
            Self::Closed => f.write_str("Closed"),
            Self::Overrun => f.write_str("Overrun"),
        }
    }
}

/// One mailbox entry: the answer to an open, or a message for the receiver.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Delivery {
    Opened(Bytes),
    Refused(OpenFailure),
    Message(Message),
}

impl From<Message> for Delivery {
    fn from(message: Message) -> Self {
        Self::Message(message)
    }
}

impl Delivery {
    /// Convert a channel event, excluding bookkeeping for the connection or writer.
    pub(super) fn from_event(event: Event) -> Option<Self> {
        let message = match event {
            Event::Opened { fields, .. } => return Some(Self::Opened(fields.into())),
            Event::Refused {
                reason,
                description,
                language,
                ..
            } => {
                return Some(Self::Refused(OpenFailure {
                    reason,
                    description: description.into(),
                    language: language.into(),
                }));
            }
            Event::Data { extended, data, .. } if !data.is_empty() => match extended {
                Some(code) => Message::ExtendedData {
                    code,
                    data: data.into(),
                },
                None => Message::Data(data.into()),
            },
            Event::Request {
                name,
                want_reply,
                fields,
                ..
            } => Message::Request {
                name: name.into(),
                want_reply,
                fields: fields.into(),
            },
            Event::Reply { success, .. } => Message::Reply { success },
            Event::Eof(_) => Message::Eof,
            Event::Closed(_) => Message::Closed,
            Event::WindowAdjusted { remaining, .. } => Message::WindowAdjusted { remaining },
            _ => return None,
        };
        Some(Self::Message(message))
    }

    /// Data is paid for by the receive window. Everything else that carries a
    /// payload or can be repeated at will draws on the control budget.
    fn charge(&self) -> u32 {
        let size = match self {
            Self::Opened(fields) => fields.len(),
            Self::Refused(failure) => failure.description.len() + failure.language.len(),
            Self::Message(Message::Request { name, fields, .. }) => name.len() + fields.len(),
            Self::Message(Message::Reply { .. } | Message::WindowAdjusted { .. }) => 0,
            Self::Message(_) => return 0,
        };
        CONTROL_OVERHEAD + size as u32
    }
}

struct Queued {
    message: Delivery,
    charge: u32,
    advisory: bool,
}

impl Queued {
    /// Append the bytes of `next` when both are data of the same stream and
    /// the result still fits one packet. Returns `next` when they stay apart.
    fn join(&mut self, next: Self) -> Option<Self> {
        let (into, from) = match (&mut self.message, &next.message) {
            (Delivery::Message(Message::Data(into)), Delivery::Message(Message::Data(from))) => {
                (into, from)
            }
            (
                Delivery::Message(Message::ExtendedData { code, data: into }),
                Delivery::Message(Message::ExtendedData {
                    code: other,
                    data: from,
                }),
            ) if code == other => (into, from),
            _ => return Some(next),
        };
        let length = into.len() + from.len();
        if length > MAX_DATA as usize {
            return Some(next);
        }
        let mut joined = std::mem::take(into)
            .try_into_mut()
            .unwrap_or_else(|shared| {
                let mut copy = BytesMut::with_capacity(length.next_power_of_two());
                copy.extend_from_slice(&shared);
                copy
            });
        joined.extend_from_slice(from);
        *into = joined.freeze();
        None
    }
}

#[derive(Default)]
pub(super) struct Signals {
    pub(super) consumed: AtomicU32,
    pub(super) read_credit_due: AtomicBool,
    pub(super) reader_dropped: AtomicBool,
    pub(super) writer_dropped: AtomicBool,
    pub(super) output_closed: AtomicBool,
    pub(super) output_pending: AtomicBool,
    /// The peer closed the channel, as opposed to the connection being lost.
    pub(super) peer_closed: AtomicBool,
    /// Requests awaiting a reply that a byte reader passed over.
    pub(super) unanswered: AtomicU32,
    writable: AtomicU32,
    packet_limit: AtomicU32,
    output_changed: Notify,
    control_charge: AtomicU32,
    advisory_charge: AtomicU32,
}

impl Signals {
    fn charge(&self, advisory: bool) -> &AtomicU32 {
        if advisory {
            &self.advisory_charge
        } else {
            &self.control_charge
        }
    }

    pub(super) fn update_writable(&self, open: &Open) {
        if open.remote.max_data == 0 || open.sent_eof {
            self.close_output();
            return;
        }
        let writable = open.writable_packet_size() as u32;
        let previous = self.writable.swap(writable, Ordering::AcqRel);
        self.packet_limit
            .store(open.outgoing_packet_limit(), Ordering::Release);
        if previous == 0 && writable != 0 {
            self.output_changed.notify_waiters();
        }
    }

    pub(super) fn close_output(&self) {
        self.output_closed.store(true, Ordering::Release);
        self.writable.store(0, Ordering::Release);
        self.output_changed.notify_waiters();
    }
}

pub(crate) struct Inbox {
    queue: mpsc::Sender<Queued>,
    spill: Option<Arc<Spill>>,
    pub(super) signals: Arc<Signals>,
    pub(super) window: u32,
}

impl Inbox {
    /// Data uses its advertised SSH window. Control events have a separate
    /// budget, and EOF, close and the limit notification have reserved slots.
    pub(super) fn push(&self, message: Delivery) -> bool {
        self.enqueue(message, false)
    }

    /// Observations of events delivered elsewhere use their own budget so a
    /// slow observer cannot crowd out data, responses, EOF or close.
    pub(super) fn observe(&self, message: Delivery) {
        self.enqueue(message, true);
    }

    fn enqueue(&self, message: Delivery, advisory: bool) -> bool {
        let charge = message.charge();
        let budget = self.signals.charge(advisory);
        if budget.load(Ordering::Relaxed) + charge > CONTROL_LIMIT {
            return false;
        }
        budget.fetch_add(charge, Ordering::Relaxed);
        let can_spill = !matches!(message, Delivery::Message(Message::WindowAdjusted { .. }));
        if self.send(
            Queued {
                message,
                charge,
                advisory,
            },
            can_spill,
        ) {
            return true;
        }
        budget.fetch_sub(charge, Ordering::Relaxed);
        false
    }

    fn send(&self, queued: Queued, can_spill: bool) -> bool {
        let Some(spill) = &self.spill else {
            return self.queue.try_send(queued).is_ok();
        };
        let mut backlog = spill.backlog.lock().unwrap();
        if self.reader_dropped() {
            return false;
        }
        let queued = if backlog.is_empty() {
            match self.queue.try_send(queued) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(queued)) => queued,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
            }
        } else {
            queued
        };
        if !can_spill {
            return false;
        }
        let queued = match backlog.back_mut() {
            Some(last) => last.join(queued),
            None => Some(queued),
        };
        match queued {
            Some(_) if backlog.len() == BACKLOG_LIMIT => false,
            Some(queued) => {
                backlog.push_back(queued);
                true
            }
            None => true,
        }
    }

    pub(super) fn reader_dropped(&self) -> bool {
        self.signals.reader_dropped.load(Ordering::Acquire)
    }

    pub(super) fn reserved_window(&self) -> u32 {
        self.window
    }
}

impl Drop for Inbox {
    fn drop(&mut self) {
        self.signals.close_output();
    }
}

pub(super) struct Mailbox {
    queue: mpsc::Receiver<Queued>,
    spill: Option<Arc<Spill>>,
    signals: Arc<Signals>,
}

impl Mailbox {
    fn poll_delivery(&mut self, cx: &mut Context<'_>) -> Poll<Option<Delivery>> {
        let mut queued = ready!(self.queue.poll_recv(cx));
        if let Some(spill) = &self.spill {
            if queued.is_some() {
                spill.refill();
            } else {
                // The peer may close the route while packets are still waiting.
                let mut backlog = spill.backlog.lock().unwrap();
                queued = backlog.pop_front();
                if backlog.is_empty() {
                    *backlog = VecDeque::new();
                }
            }
        }
        Poll::Ready(queued.map(|queued| {
            self.signals
                .charge(queued.advisory)
                .fetch_sub(queued.charge, Ordering::Relaxed);
            queued.message
        }))
    }
}

struct Spill {
    sender: mpsc::WeakSender<Queued>,
    backlog: SyncMutex<VecDeque<Queued>>,
}

impl Spill {
    fn refill(&self) {
        let Some(sender) = self.sender.upgrade() else {
            return;
        };
        let mut backlog = self.backlog.lock().unwrap();
        while !backlog.is_empty() {
            let Ok(permit) = sender.try_reserve() else {
                return;
            };
            permit.send(backlog.pop_front().unwrap());
        }
        // Retain no heap storage after a burst of queued packets drains.
        *backlog = VecDeque::new();
    }
}

pub(super) fn inbox(window: u32, capacity: Option<usize>) -> io::Result<(Inbox, Mailbox)> {
    if window > DEFAULT_WINDOW {
        return Err(input(
            "SSH channel receive window exceeds the routed channel limit",
        ));
    }
    let (send, receive) = mpsc::channel(capacity.unwrap_or(MAILBOX_CAPACITY));
    // Packets covered by SSH receive credit wait in the backlog for mailbox
    // space, without blocking the connection driver or returning that credit
    // early. Every queued data event uses one or more bytes of that credit, so
    // a mailbox this large can never fill.
    let maximum_capacity = (DEFAULT_WINDOW + 2 * CONTROL_LIMIT / CONTROL_OVERHEAD + 3) as usize;
    let spill = (send.max_capacity() < maximum_capacity).then(|| {
        Arc::new(Spill {
            sender: send.downgrade(),
            backlog: SyncMutex::new(VecDeque::new()),
        })
    });
    let signals = Arc::new(Signals::default());
    Ok((
        Inbox {
            queue: send,
            spill: spill.clone(),
            signals: Arc::clone(&signals),
            window,
        },
        Mailbox {
            queue: receive,
            spill,
            signals,
        },
    ))
}

/// An open channel: a receiver for what the peer sends and a sender for
/// everything this side sends. `split` separates the two.
pub struct Channel {
    receiver: ChannelReceiver,
    sender: ChannelSender,
    open_fields: Bytes,
}

impl Channel {
    pub(super) fn new(id: ChannelId, handle: Handle, mailbox: Mailbox) -> Self {
        let signals = Arc::clone(&mailbox.signals);
        let receiver = ChannelReceiver {
            id,
            mailbox,
            handle: handle.clone(),
            partial: None,
            ended: false,
        };
        let sender = ChannelSender {
            route: Arc::new(WriteRoute {
                id,
                handle,
                signals,
                serial: Arc::new(Mutex::new(())),
            }),
        };
        Self {
            receiver,
            sender,
            open_fields: Bytes::new(),
        }
    }

    /// Wait for the peer's answer to the open request.
    pub(super) async fn confirm(mut self) -> io::Result<Self> {
        let answer = poll_fn(|cx| self.receiver.mailbox.poll_delivery(cx)).await;
        match answer {
            Some(Delivery::Opened(fields)) => {
                self.open_fields = fields;
                Ok(self)
            }
            Some(Delivery::Refused(failure)) => {
                Err(io::Error::new(ErrorKind::ConnectionRefused, failure))
            }
            _ => Err(disconnected()),
        }
    }

    pub fn id(&self) -> ChannelId {
        self.sender.id()
    }

    /// The type-specific fields of the peer's open confirmation.
    pub fn open_fields(&self) -> &[u8] {
        &self.open_fields
    }

    pub fn split(self) -> (ChannelReceiver, ChannelSender) {
        (self.receiver, self.sender)
    }

    /// Another handle to the sending side, for a task of its own.
    pub fn sender(&self) -> ChannelSender {
        self.sender.clone()
    }

    /// Treat the channel's ordinary data as one duplex byte stream.
    pub fn into_io(self) -> ChannelIo {
        ChannelIo {
            writer: self.sender.writer(),
            receiver: self.receiver,
        }
    }

    /// See [`ChannelReceiver::recv`].
    pub async fn recv(&mut self) -> Option<Message> {
        self.receiver.recv().await
    }

    /// See [`ChannelReceiver::reader`].
    pub fn reader(&mut self) -> DataReader<'_> {
        self.receiver.reader()
    }

    /// See [`ChannelReceiver::extended_reader`].
    pub fn extended_reader(&mut self, code: u32) -> DataReader<'_> {
        self.receiver.extended_reader(code)
    }

    /// See [`ChannelSender::writer`].
    pub fn writer(&self) -> DataWriter {
        self.sender.writer()
    }

    /// See [`ChannelSender::extended_writer`].
    pub fn extended_writer(&self, code: u32) -> DataWriter {
        self.sender.extended_writer(code)
    }

    /// See [`ChannelSender::send`].
    pub async fn send(&self, data: impl Into<Bytes>) -> io::Result<()> {
        self.sender.send(data).await
    }

    /// See [`ChannelSender::send_extended`].
    pub async fn send_extended(&self, code: u32, data: impl Into<Bytes>) -> io::Result<()> {
        self.sender.send_extended(code, data).await
    }

    /// See [`ChannelSender::request`].
    pub async fn request(&self, request: Request<'_>, want_reply: bool) -> io::Result<()> {
        self.sender.request(request, want_reply).await
    }

    /// See [`ChannelSender::raw_request`].
    pub async fn raw_request(&self, name: &str, fields: &[u8], want_reply: bool) -> io::Result<()> {
        self.sender.raw_request(name, fields, want_reply).await
    }

    /// See [`ChannelSender::reply`].
    pub async fn reply(&self, success: bool) -> io::Result<()> {
        self.sender.reply(success).await
    }

    /// See [`ChannelSender::eof`].
    pub async fn eof(&self) -> io::Result<()> {
        self.sender.eof().await
    }

    /// See [`ChannelSender::close`].
    pub async fn close(&self) -> io::Result<()> {
        self.sender.close().await
    }
}

/// The receiving side of a channel. Dropping it discards whatever the peer
/// sends afterwards.
pub struct ChannelReceiver {
    id: ChannelId,
    mailbox: Mailbox,
    handle: Handle,
    /// The unread tail of a data message a reader could not take whole.
    partial: Option<(Option<u32>, Bytes)>,
    ended: bool,
}

impl ChannelReceiver {
    pub fn id(&self) -> ChannelId {
        self.id
    }

    /// The next message, or `None` once the channel is gone. Taking a data
    /// message returns its receive credit to the peer.
    pub async fn recv(&mut self) -> Option<Message> {
        poll_fn(|cx| {
            let message = match self.partial.take() {
                Some((None, data)) => Message::Data(data),
                Some((Some(code), data)) => Message::ExtendedData { code, data },
                None => loop {
                    match ready!(self.mailbox.poll_delivery(cx)) {
                        Some(Delivery::Message(message)) => break message,
                        // Answers to an open are consumed before a channel exists.
                        Some(_) => continue,
                        None => return Poll::Ready(None),
                    }
                },
            };
            match &message {
                Message::Data(data) | Message::ExtendedData { data, .. } => {
                    self.release(data.len())
                }
                Message::Eof | Message::Closed => self.ended = true,
                _ => {}
            }
            Poll::Ready(Some(message))
        })
        .await
    }

    /// Read the channel's ordinary data as bytes. Everything else that arrives
    /// while reading is dropped, and a request that asks for a reply is
    /// refused. Use `recv` to see those messages.
    pub fn reader(&mut self) -> DataReader<'_> {
        DataReader {
            receiver: self,
            stream: None,
        }
    }

    /// Read one numbered side stream as bytes, dropping everything else.
    pub fn extended_reader(&mut self, code: u32) -> DataReader<'_> {
        DataReader {
            receiver: self,
            stream: Some(code),
        }
    }

    fn release(&self, count: usize) {
        if count != 0 {
            let signals = &self.mailbox.signals;
            signals.consumed.fetch_add(count as u32, Ordering::SeqCst);
            if signals.read_credit_due.load(Ordering::SeqCst) {
                self.handle.wake.notify_one();
            }
        }
    }

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        stream: Option<u32>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.ended {
            return Poll::Ready(Ok(()));
        }
        loop {
            let (code, data) = match self.partial.take() {
                Some(partial) => partial,
                None => match ready!(self.mailbox.poll_delivery(cx)) {
                    Some(Delivery::Message(Message::Data(data))) => (None, data),
                    Some(Delivery::Message(Message::ExtendedData { code, data })) => {
                        (Some(code), data)
                    }
                    Some(Delivery::Message(Message::Eof | Message::Closed)) => {
                        self.ended = true;
                        return Poll::Ready(Ok(()));
                    }
                    Some(Delivery::Message(Message::Overrun)) => {
                        return Poll::Ready(Err(io::Error::other(
                            "SSH channel event budget exceeded",
                        )));
                    }
                    Some(Delivery::Message(Message::Request {
                        want_reply: true, ..
                    })) => {
                        // Nobody will see this request, so the driver answers
                        // it. Left alone it would stall the peer and block
                        // every later reply on this channel behind it.
                        let signals = &self.mailbox.signals;
                        signals.unanswered.fetch_add(1, Ordering::SeqCst);
                        self.handle.wake.notify_one();
                        continue;
                    }
                    Some(_) => continue,
                    None => return Poll::Ready(Err(disconnected())),
                },
            };
            if code != stream {
                self.release(data.len());
                continue;
            }
            let count = buf.remaining().min(data.len());
            buf.put_slice(&data[..count]);
            self.release(count);
            if count < data.len() {
                self.partial = Some((code, data.slice(count..)));
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl Drop for ChannelReceiver {
    fn drop(&mut self) {
        self.mailbox
            .signals
            .reader_dropped
            .store(true, Ordering::Release);
        if let Some(spill) = &self.mailbox.spill {
            *spill.backlog.lock().unwrap() = VecDeque::new();
        }
        self.handle.wake.notify_one();
    }
}

/// Reads one of a channel's byte streams. End of file is the peer's EOF or
/// the channel closing.
pub struct DataReader<'a> {
    receiver: &'a mut ChannelReceiver,
    stream: Option<u32>,
}

impl AsyncRead for DataReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let reader = self.get_mut();
        reader.receiver.poll_data(cx, buf, reader.stream)
    }
}

/// What every sender and writer of one channel shares. The channel's sending
/// side ends when the last of them is dropped.
struct WriteRoute {
    id: ChannelId,
    handle: Handle,
    signals: Arc<Signals>,
    serial: Arc<Mutex<()>>,
}

impl WriteRoute {
    /// Take the channel's turn to write. Turns are granted in request order.
    async fn reserve(&self) -> io::Result<WritePermit> {
        self.handle
            .reserve_write(self.id, self.serial.clone(), self.signals.clone())
            .await
    }

    async fn eof(&self) -> io::Result<()> {
        self.reserve().await?.eof().await
    }

    /// Wait until the peer's window admits data, then take the turn to write.
    /// Returns how many bytes may be sent in that turn.
    async fn reserve_writable(&self) -> io::Result<(WritePermit, usize)> {
        loop {
            let changed = self.signals.output_changed.notified();
            self.ensure_writable()?;
            if self.signals.writable.load(Ordering::Acquire) != 0 {
                let permit = self.reserve().await?;
                self.ensure_writable()?;
                let size = self.signals.writable.load(Ordering::Acquire) as usize;
                if size != 0 {
                    return Ok((permit, size));
                }
            }
            changed.await;
        }
    }

    fn ensure_writable(&self) -> io::Result<()> {
        if self.signals.output_closed.load(Ordering::Acquire) {
            return Err(shut_down());
        }
        Ok(())
    }

    fn packet_limit(&self) -> usize {
        match self.signals.packet_limit.load(Ordering::Acquire) {
            0 => MAX_DATA as usize,
            limit => limit as usize,
        }
    }
}

impl Drop for WriteRoute {
    fn drop(&mut self) {
        self.signals.writer_dropped.store(true, Ordering::Release);
        self.handle.wake.notify_one();
    }
}

/// The sending side of a channel. Clones share the channel's send window, and
/// what they send is written in the order the calls were made.
#[derive(Clone)]
pub struct ChannelSender {
    route: Arc<WriteRoute>,
}

impl ChannelSender {
    pub fn id(&self) -> ChannelId {
        self.route.id
    }

    /// How many bytes the peer would accept in a single packet right now.
    pub async fn capacity(&self) -> usize {
        self.route
            .handle
            .writable_packet_size(self.id())
            .await
            .unwrap_or(0)
    }

    /// Send ordinary data, waiting for the peer's window as needed. Dropping
    /// the future withdraws whatever part has not been written yet.
    pub async fn send(&self, data: impl Into<Bytes>) -> io::Result<()> {
        self.transmit(None, data.into()).await
    }

    /// Send data on a numbered side stream. Code 1 is standard error.
    pub async fn send_extended(&self, code: u32, data: impl Into<Bytes>) -> io::Result<()> {
        self.transmit(Some(code), data.into()).await
    }

    async fn transmit(&self, stream: Option<u32>, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            self.route.ensure_writable()?;
            let chunk = data.split_to(data.len().min(self.route.packet_limit()));
            self.route
                .reserve()
                .await?
                .send(stream, chunk, false)
                .await?;
        }
        Ok(())
    }

    /// A byte writer for ordinary data.
    pub fn writer(&self) -> DataWriter {
        self.stream_writer(None)
    }

    /// A byte writer for a numbered side stream.
    pub fn extended_writer(&self, code: u32) -> DataWriter {
        self.stream_writer(Some(code))
    }

    fn stream_writer(&self, stream: Option<u32>) -> DataWriter {
        DataWriter {
            route: self.route.clone(),
            stream,
            state: WriteState::Idle,
            reservation: None,
        }
    }

    /// Send a session request. When `want_reply` is set, the peer's answer
    /// arrives as [`Message::Reply`], in the order such requests were sent.
    pub async fn request(&self, request: Request<'_>, want_reply: bool) -> io::Result<()> {
        let (name, fields) = request.encode(want_reply)?;
        self.raw_request(name, &fields, want_reply).await
    }

    /// Send a request by name with fields the caller has already encoded.
    pub async fn raw_request(&self, name: &str, fields: &[u8], want_reply: bool) -> io::Result<()> {
        self.route
            .handle
            .request(self.id(), name, want_reply, fields)
            .await
    }

    /// Answer the oldest request from the peer that asked for a reply.
    pub async fn reply(&self, success: bool) -> io::Result<()> {
        self.route.handle.reply(self.id(), success).await
    }

    /// Announce the end of this side's data once everything already handed to
    /// the channel has been written. The peer can still send.
    pub async fn eof(&self) -> io::Result<()> {
        self.route.eof().await
    }

    /// Close the channel now. Data still waiting for the peer's window is
    /// abandoned.
    pub async fn close(&self) -> io::Result<()> {
        self.route.handle.close(self.id()).await
    }

    /// Close the channel after everything already handed to it has been
    /// written.
    pub async fn close_when_sent(&self) -> io::Result<()> {
        self.route.reserve().await?.close().await
    }
}

type Completion = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
type Reservation = Pin<Box<dyn Future<Output = io::Result<(WritePermit, usize)>> + Send + Sync>>;

enum WriteState {
    Idle,
    /// A chunk the peer's window already admitted is on its way out.
    Sending(WriteReceipt),
    Finishing(Completion),
    Finished,
}

impl WriteState {
    fn ensure_writable(&self) -> io::Result<()> {
        match self {
            Self::Finished | Self::Finishing(_) => Err(shut_down()),
            _ => Ok(()),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (result, after) = match self {
            Self::Sending(receipt) => (ready!(Pin::new(receipt).poll(cx)), Self::Idle),
            Self::Finishing(pending) => (ready!(pending.as_mut().poll(cx)), Self::Finished),
            _ => return Poll::Ready(Ok(())),
        };
        *self = if result.is_ok() {
            after
        } else {
            Self::Finished
        };
        Poll::Ready(result)
    }

    fn poll_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        route: &Arc<WriteRoute>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        if matches!(self, Self::Finished) {
            return Poll::Ready(Ok(()));
        }
        let route = route.clone();
        *self = Self::Finishing(Box::pin(async move {
            match route.eof().await {
                // The peer closed the channel first, so there is nobody left
                // to tell. An ordinary teardown must not look like a failure
                // to code that shuts down both directions.
                Err(_) if route.signals.peer_closed.load(Ordering::Acquire) => Ok(()),
                result => result,
            }
        }));
        self.poll_flush(cx)
    }
}

/// Writes one of a channel's byte streams. A write is accepted only once the
/// peer's window has room for it, so an accepted write is never withdrawn.
/// Shutting down sends EOF.
pub struct DataWriter {
    route: Arc<WriteRoute>,
    stream: Option<u32>,
    state: WriteState,
    reservation: Option<Reservation>,
}

impl AsyncWrite for DataWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let writer = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(writer.state.poll_flush(cx))?;
        writer.state.ensure_writable()?;
        let reservation = writer.reservation.get_or_insert_with(|| {
            let route = writer.route.clone();
            Box::pin(async move { route.reserve_writable().await })
        });
        let result = ready!(reservation.as_mut().poll(cx));
        writer.reservation = None;
        let (permit, writable) = result?;
        let count = data.len().min(writable);
        let receipt = permit.send(writer.stream, Bytes::copy_from_slice(&data[..count]), true);
        writer.state = WriteState::Sending(receipt);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reservation = None;
        self.state.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let writer = self.get_mut();
        writer.reservation = None;
        writer.state.poll_shutdown(cx, &writer.route)
    }
}

/// A channel's ordinary data as one duplex Tokio stream. Shutting it down
/// sends EOF and leaves the read direction open.
pub struct ChannelIo {
    receiver: ChannelReceiver,
    writer: DataWriter,
}

impl ChannelIo {
    pub fn id(&self) -> ChannelId {
        self.receiver.id
    }
}

impl AsyncRead for ChannelIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().receiver.poll_data(cx, buf, None)
    }
}

impl AsyncWrite for ChannelIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

fn disconnected() -> io::Error {
    io::Error::new(ErrorKind::ConnectionAborted, "SSH channel disconnected")
}

fn shut_down() -> io::Error {
    io::Error::new(ErrorKind::BrokenPipe, "SSH channel writer is shut down")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_mailbox_refills_in_order_and_drains_after_sender_drop() {
        let (inbox, mut mailbox) = inbox(16, Some(1)).unwrap();
        let data = |value| Delivery::from(Message::Data(Bytes::from_static(value)));
        assert_eq!(mailbox.queue.max_capacity(), 1);
        assert!(inbox.push(data(b"first")));
        inbox.observe(Message::WindowAdjusted { remaining: 7 }.into());
        assert!(inbox.push(data(b"second")));
        assert_eq!(mailbox.queue.len(), 1);

        let first = poll_fn(|cx| mailbox.poll_delivery(cx)).await;
        assert_eq!(first, Some(data(b"first")));
        assert_eq!(mailbox.queue.len(), 1);
        assert!(inbox.push(Message::Eof.into()));
        assert!(inbox.push(Message::Closed.into()));
        drop(inbox);

        for expected in [data(b"second"), Message::Eof.into(), Message::Closed.into()] {
            assert_eq!(
                poll_fn(|cx| mailbox.poll_delivery(cx)).await,
                Some(expected)
            );
        }
        assert_eq!(poll_fn(|cx| mailbox.poll_delivery(cx)).await, None);
    }
}
