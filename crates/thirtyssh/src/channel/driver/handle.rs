use super::*;

impl Handle {
    /// Reserve and validate an open without waiting for the I/O driver.
    pub fn prepare_open(&self, kind: &str, window: u32, fields: &[u8]) -> io::Result<PendingOpen> {
        if self.commands.is_closed() {
            return Err(stopped());
        }
        Ok(PendingOpen {
            frame: self.ids.prepare(kind, window, fields)?,
            ids: self.ids.clone(),
        })
    }

    /// Send a prepared request. The open result is delivered through events.
    pub async fn submit_open(&self, pending: PendingOpen) -> io::Result<()> {
        if !Arc::ptr_eq(&self.ids, &pending.ids) {
            return Err(input(
                "SSH open reservation belongs to a different connection",
            ));
        }
        self.call(|reply| Command::SubmitOpen {
            frame: pending.frame,
            reply,
        })
        .await
    }
    /// Queue a channel open and return its ID. Confirmation or refusal arrives
    /// through the connection's event receiver.
    pub async fn open(&self, kind: &str, window: u32, fields: &[u8]) -> io::Result<ChannelId> {
        self.begin_open(kind, window, fields, None).await
    }

    /// Open a channel by type name, with a chosen receive window, and wait for
    /// the peer's confirmation. Its fields are available from the channel.
    pub async fn open_channel(
        &self,
        kind: &str,
        window: u32,
        fields: &[u8],
    ) -> io::Result<Channel> {
        let (inbox, receiver) = inbox(window, self.channel_buffer_size)?;
        let id = self.begin_open(kind, window, fields, Some(inbox)).await?;
        Channel::new(id, self.clone(), receiver).confirm().await
    }

    async fn begin_open(
        &self,
        kind: &str,
        window: u32,
        fields: &[u8],
        inbox: Option<Inbox>,
    ) -> io::Result<ChannelId> {
        named_size(17, kind, fields)?;
        let guard = OpenGuard {
            claim: Arc::new(AtomicU8::new(OPEN_WAITING)),
            wake: Arc::clone(&self.wake),
        };
        let channel = self
            .call(|reply| Command::Open {
                kind: kind.to_owned(),
                window,
                fields: fields.to_vec(),
                claim: Arc::clone(&guard.claim),
                inbox,
                reply,
            })
            .await?;
        guard.claim.store(OPEN_CLAIMED, Ordering::Release);
        self.wake.notify_one();
        Ok(channel)
    }

    pub async fn accept(&self, channel: ChannelId, window: u32, fields: &[u8]) -> io::Result<()> {
        self.accept_inner(channel, window, fields, None).await
    }

    /// Confirm an incoming open and route its messages to a dedicated queue.
    pub async fn accept_channel(
        &self,
        channel: ChannelId,
        window: u32,
        fields: &[u8],
    ) -> io::Result<Channel> {
        let (channel, inbox) = self.prepare_channel(channel, window)?;
        self.accept_prepared(channel.id(), window, fields, inbox)
            .await?;
        Ok(channel)
    }

    pub(crate) fn prepare_channel(
        &self,
        id: ChannelId,
        window: u32,
    ) -> io::Result<(Channel, Inbox)> {
        let (inbox, receiver) = inbox(window, self.channel_buffer_size)?;
        Ok((Channel::new(id, self.clone(), receiver), inbox))
    }

    pub(crate) async fn accept_prepared(
        &self,
        id: ChannelId,
        window: u32,
        fields: &[u8],
        inbox: Inbox,
    ) -> io::Result<()> {
        self.accept_inner(id, window, fields, Some(inbox)).await
    }

    async fn accept_inner(
        &self,
        channel: ChannelId,
        window: u32,
        fields: &[u8],
        inbox: Option<Inbox>,
    ) -> io::Result<()> {
        if fields.len() > MAX_DATA as usize {
            return Err(input("SSH confirmation fields exceed limit"));
        }
        self.call(|reply| {
            Command::Control(
                Control::Accept(channel, window, fields.to_vec(), inbox),
                reply,
            )
        })
        .await
    }

    pub async fn refuse(&self, channel: ChannelId, reason: u32) -> io::Result<()> {
        self.refuse_with(channel, OpenFailure::new(reason)).await
    }

    pub async fn refuse_with(&self, channel: ChannelId, failure: OpenFailure) -> io::Result<()> {
        self.control(Control::Refuse(channel, failure)).await
    }

    pub async fn cancel_open(&self, channel: ChannelId) -> io::Result<()> {
        self.control(Control::CancelOpen(channel)).await
    }

    pub(crate) async fn track_incoming(
        &self,
        id: ChannelId,
        abandoned: Arc<AtomicBool>,
    ) -> io::Result<()> {
        self.control(Control::TrackIncoming(id, abandoned)).await
    }

    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    /// Write at most one packet. Zero for a nonempty slice means the peer's
    /// window is full. Wait for WindowAdjusted before retrying.
    pub async fn send_data(
        &self,
        channel: ChannelId,
        extended: Option<u32>,
        data: &[u8],
    ) -> io::Result<usize> {
        let data = &data[..data.len().min(MAX_OUTGOING_DATA as usize)];
        self.call(|reply| Command::Data {
            channel,
            extended,
            data: data.to_vec(),
            reply,
        })
        .await
    }

    pub(in crate::channel) async fn reserve_write(
        &self,
        channel: ChannelId,
        serial: Arc<Mutex<()>>,
        signals: Arc<Signals>,
    ) -> io::Result<WritePermit> {
        let (serial, slot) = loop {
            let guard = serial.clone().lock_owned().await;
            let sender = match self.commands.clone().try_reserve_owned() {
                Ok(slot) => break (guard, slot),
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(stopped()),
                Err(mpsc::error::TrySendError::Full(sender)) => sender,
            };
            // Do not hold one permit across a wait for the other. In
            // particular, a writer might stop being polled while waiting.
            drop(guard);
            let slot = sender.reserve_owned().await.map_err(|_| stopped())?;
            if let Ok(guard) = serial.clone().try_lock_owned() {
                break (guard, slot);
            }
        };
        Ok(WritePermit {
            channel,
            slot,
            serial,
            signals,
            wake: self.wake.clone(),
        })
    }

    pub(in crate::channel) async fn writable_packet_size(
        &self,
        channel: ChannelId,
    ) -> io::Result<usize> {
        self.call(|reply| Command::WritablePacketSize(channel, reply))
            .await
    }

    pub async fn consume(&self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        self.control(Control::Consume(channel, bytes)).await
    }

    /// Return credit for data delivered directly to a connection handler.
    /// Routed readers return their own credit.
    pub async fn consume_unrouted(&self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        self.control(Control::ConsumeUnrouted(channel, bytes)).await
    }

    /// Enqueue a callback's output without waiting for the peer's receive window.
    pub async fn queue_output(&self, channel: ChannelId, output: ChannelOutput) -> io::Result<()> {
        if output.queue_charge() > QUEUED_OUTPUT_BUDGET {
            return Err(input("SSH output exceeds the queue budget"));
        }
        self.call(|reply| Command::QueueOutput {
            channel,
            output,
            reply,
        })
        .await
    }

    pub async fn grant(&self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        self.control(Control::Grant(channel, bytes)).await
    }

    pub async fn request(
        &self,
        channel: ChannelId,
        name: &str,
        want_reply: bool,
        fields: &[u8],
    ) -> io::Result<()> {
        named_size(10, name, fields)?;
        self.call(|reply| {
            Command::Control(
                Control::Request {
                    channel,
                    name: name.to_owned(),
                    want_reply,
                    fields: fields.to_vec(),
                },
                reply,
            )
        })
        .await
    }

    pub async fn reply(&self, channel: ChannelId, success: bool) -> io::Result<()> {
        self.control(Control::Reply(channel, success)).await
    }

    /// Send a connection-wide request and wait for its FIFO reply. Dropping the
    /// future after transmission does not undo the request on the peer.
    pub async fn global_request(&self, name: &str, fields: &[u8]) -> io::Result<GlobalReply> {
        named_size(6, name, fields)?;
        self.call(|reply| Command::GlobalRequest(name.to_owned(), fields.to_vec(), reply))
            .await
    }

    /// Send an OpenSSH-compatible global keepalive. If a reply was requested,
    /// the driver consumes it when it arrives.
    pub async fn keepalive(&self, want_reply: bool) -> io::Result<()> {
        self.control(Control::GlobalSignal(KEEPALIVE_REQUEST, want_reply))
            .await
    }

    /// Ask the peer to refuse new session channels. The driver consumes any
    /// requested reply without making the caller wait for it.
    pub async fn no_more_sessions(&self, want_reply: bool) -> io::Result<()> {
        self.control(Control::GlobalSignal(NO_MORE_SESSIONS_REQUEST, want_reply))
            .await
    }

    /// Wait for a reply to a global keepalive. Either protocol reply proves
    /// the peer is responsive, including the failure reply sent by OpenSSH.
    pub async fn ping(&self) -> io::Result<()> {
        if let GlobalReply::Success(fields) = self.global_request(KEEPALIVE_REQUEST, &[]).await?
            && !fields.is_empty()
        {
            return Err(crate::clear_packet::invalid(
                "unexpected SSH keepalive reply fields",
            ));
        }
        Ok(())
    }

    /// Send a connection-wide request without asking for a reply.
    pub async fn global_notification(&self, name: &str, fields: &[u8]) -> io::Result<()> {
        named_size(6, name, fields)?;
        self.call(|reply| {
            Command::Control(
                Control::GlobalNotification(name.to_owned(), fields.to_vec()),
                reply,
            )
        })
        .await
    }

    /// Answer the oldest inbound global request. Session handlers normally
    /// return a reply from their callback instead of calling this directly.
    pub async fn global_reply(&self, id: GlobalRequestId, result: GlobalReply) -> io::Result<()> {
        self.control(Control::GlobalReply(id, result)).await
    }

    pub async fn eof(&self, channel: ChannelId) -> io::Result<()> {
        self.control(Control::Eof(channel)).await
    }

    pub async fn close(&self, channel: ChannelId) -> io::Result<()> {
        self.control(Control::Close(channel)).await
    }

    pub async fn rekey(&self) -> io::Result<()> {
        self.control(Control::Rekey).await
    }

    pub async fn disconnect(&self) -> io::Result<()> {
        self.disconnect_with(11, "", "").await
    }

    /// Send a disconnect with an explicit reason and peer-visible text.
    pub async fn disconnect_with(
        &self,
        reason: u32,
        description: &str,
        language: &str,
    ) -> io::Result<()> {
        self.submit_disconnect(DisconnectRequest::new(reason, description, language)?)
            .await
    }

    /// Send a previously validated disconnect request and stop the driver.
    pub async fn submit_disconnect(&self, request: DisconnectRequest) -> io::Result<()> {
        self.call(|reply| Command::Shutdown(request.into_packet(), reply))
            .await
    }

    async fn control(&self, control: Control) -> io::Result<()> {
        self.call(|reply| Command::Control(control, reply)).await
    }

    async fn call<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> io::Result<T> {
        // Reserve before allocating a packet so waiters cannot fill the heap
        // with command buffers outside the bounded queue.
        let permit = self.commands.reserve().await.map_err(|_| stopped())?;
        let (reply, result) = oneshot::channel();
        permit.send(command(reply));
        result.await.map_err(|_| stopped())?
    }
}
