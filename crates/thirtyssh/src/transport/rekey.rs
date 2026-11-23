//! Key re-exchange on a running transport.
use super::*;

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    pub(super) fn rekey_due(&self) -> bool {
        !self.authenticating
            && (self.send.bytes >= self.rekey_write_bytes
                || self.receive.bytes >= self.rekey_read_bytes
                || self.keys_started.elapsed() >= self.rekey_age)
    }

    pub(super) fn rekey_gate(&self) -> Option<&Arc<Mutex<()>>> {
        self.gex_group_lookup.as_ref()?.rekey_gate.as_ref()
    }

    pub(super) fn try_rekey_guard(&self) -> Option<Option<OwnedMutexGuard<()>>> {
        match self.rekey_gate() {
            Some(gate) => gate.clone().try_lock_owned().ok().map(Some),
            None => Some(None),
        }
    }

    pub(super) async fn exchange_keys(
        &mut self,
        _guard: Option<OwnedMutexGuard<()>>,
    ) -> io::Result<()> {
        let peer_proposal = self.pending_kexinit.take();
        let role = self.host.role();
        let unprotected = matches!(self.host, HostIdentity::Unverified(_));
        let local_proposal =
            initial::local_proposal(role, false, &self.preferences, &self.host_algorithms)?;
        let was_authenticated = self.authenticated;
        let peer = async {
            if let Some(packet) = peer_proposal {
                return Ok(packet);
            }
            loop {
                let payload = self.receive.read(&mut self.reader).await?;
                if self.extensions.observe(&payload)? {
                    continue;
                }
                if !self.authenticated && payload == [SUCCESS] && role == Role::Client {
                    self.authenticated = true;
                    self.authenticating = false;
                    if unprotected {
                        self.receive.finish_unprotected_userauth(true);
                    } else {
                        self.receive.enable_delayed_compression();
                    }
                }
                match payload[0] {
                    KEXINIT => return Ok(payload),
                    1 => return Err(peer_disconnected(&payload)),
                    21..=49 => {
                        return Err(invalid(
                            "unexpected SSH key exchange message before KEXINIT",
                        ));
                    }
                    _ => self.in_flight.push(payload)?,
                }
            }
        };
        let send_proposal = write_with_extensions(
            &mut self.send,
            &mut self.writer,
            &mut self.announce_extensions,
            Some(&local_proposal),
        );
        let ((), peer_proposal) = tokio::try_join!(send_proposal, peer)?;
        if self.authenticated {
            if !unprotected {
                self.send.enable_delayed_compression();
            } else if !was_authenticated {
                self.send.finish_unprotected_userauth(false);
            }
        }
        let choice = initial::choose(
            &peer_proposal,
            role,
            &self.preferences,
            &self.host_algorithms,
        )?;
        if choice.discard_guess {
            let guessed = self.receive.read(&mut self.reader).await?;
            if guessed[0] == 1 {
                return Err(peer_disconnected(&guessed));
            }
            if !(30..=49).contains(&guessed[0]) {
                return Err(invalid("unexpected guessed packet during SSH rekey"));
            }
        }
        let (client_proposal, server_proposal) = match role {
            Role::Client => (local_proposal, peer_proposal),
            Role::Server => (peer_proposal, local_proposal),
        };
        self.transcript.client.kexinit = client_proposal;
        self.transcript.server.kexinit = server_proposal;
        self.transcript.kex_algorithm = choice.algorithm;
        self.transcript.host_key_algorithm = choice.host_key_algorithm;
        self.transcript.packet_algorithms = choice.packet_algorithms;
        self.transcript.compression = choice.compression;
        let strict = self.strict_kex();
        let (send_suite, receive_suite) = ordered_suites(choice.packet_algorithms, role);
        let (send_mode, receive_mode) = ordered_compression(choice.compression, role);
        if choice.algorithm == Kex::None.name() {
            if !unprotected {
                return Err(invalid("SSH rekey cannot drop host authentication"));
            }
            // Some peers start either zlib mode on rekey, including before
            // user authentication. The initial KEX still honors the delay.
            self.send
                .renew_unprotected(send_suite, send_mode, true, strict);
            self.receive
                .renew_unprotected(receive_suite, receive_mode, true, strict);
            self.keys_started = Instant::now();
            self.report_rekey(choice.selected_macs, choice.discard_guess);
            return Ok(());
        }
        let session_id = Some(self.session_id.as_slice());
        let mut exchange = MethodIo::Protected {
            reader: &mut self.reader,
            writer: &mut self.writer,
            receive: &mut self.receive,
            send: &mut self.send,
        };
        let keys = match &self.host {
            HostIdentity::Client {
                pinned,
                certificate_signatures,
            } => {
                let result = exchange
                    .client(
                        &self.transcript,
                        session_id,
                        self.preferences.gex,
                        *certificate_signatures,
                    )
                    .await?;
                if pinned != &result.host {
                    return Err(rejected_host());
                }
                result.keys
            }
            HostIdentity::Server(host) => {
                let signer = host
                    .select(&self.transcript.host_key_algorithm)
                    .ok_or_else(|| invalid("negotiated SSH host key is unavailable"))?;
                exchange
                    .server(
                        &self.transcript,
                        session_id,
                        signer,
                        self.gex_group_lookup.as_ref(),
                    )
                    .await?
            }
            HostIdentity::Unverified(_) => {
                return Err(invalid("SSH rekey changed from KEX none"));
            }
        };
        let (send_keys, receive_keys) = match role {
            Role::Client => (keys.client_to_server, keys.server_to_client),
            Role::Server => (keys.server_to_client, keys.client_to_server),
        };
        let activate_send = async {
            self.send.write(&mut self.writer, NEWKEYS).await?;
            self.send.install(send_keys, send_suite, strict);
            self.send.reset_compression(send_mode, self.authenticated);
            Ok(())
        };
        let activate_receive = async {
            if read_rekey_packet(&mut self.receive, &mut self.reader, NEWKEYS[0]).await? != NEWKEYS
            {
                return Err(invalid("invalid SSH_MSG_NEWKEYS"));
            }
            self.receive.install(receive_keys, receive_suite, strict);
            self.receive
                .reset_compression(receive_mode, self.authenticated);
            Ok(())
        };
        tokio::try_join!(activate_send, activate_receive)?;
        self.keys_started = Instant::now();
        self.report_rekey(choice.selected_macs, choice.discard_guess);
        Ok(())
    }
}
