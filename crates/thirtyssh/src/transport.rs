//! SSH key exchange and protected packet I/O.
//!
//! Client connections require an explicit host trust decision unless the
//! caller selects the dedicated `Kex::None` compatibility mode.
use crate::{
    algorithms::{
        Cipher, Compression, CompressionAlgorithms, GexSizes, Kex, Mac, PacketAlgorithms,
        PacketPreferences, Suite, TransportPreferences,
    },
    auth::SUCCESS,
    clear_packet::{self, invalid},
    extensions::{self, EXT_INFO, Extensions, ServerSignatureAlgorithms},
    identification::{self, Role},
    initial::{self, KEXINIT, NEWKEYS, Transcript},
    kex::{
        self, ClientExchange, ClientExchangeResult, ExchangeKeys, HostSigner, KEX_METHOD_INIT,
        KEX_METHOD_REPLY, gex,
    },
    keys::{
        Algorithm, CertificateSignaturePolicy, Credential, PublicKey, SIGNATURE_ALGORITHMS,
        UserSignatures, certificate_signature_algorithm, supports_signature_algorithm,
    },
    protection::{Direction, KEY_BYTE_LIMIT, ReceivedPacket, Side},
    protocol_error::{ProtocolError, unexpected_initial_message},
    runtime::{Instant, timeout},
    wire::Reader,
};
use std::{
    collections::VecDeque,
    future::{Future, Ready, ready},
    io::{self, ErrorKind},
    pin::pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{self as stream, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, OwnedMutexGuard, watch},
};
use zeroize::Zeroizing;

pub use crate::kex::{HostKey, HostKeys};

mod disconnect;
mod handshake;
mod limits;
mod queue;
mod rekey;

pub use disconnect::{DisconnectRequest, PeerDisconnect};
pub(crate) use disconnect::{disconnect_packet, peer_disconnected};
pub use limits::Limits;
use queue::{InFlight, MAX_IN_FLIGHT_BYTES};

const KEY_EXCHANGE_FAILED: u32 = 3;
const DEFAULT_REKEY_AGE: Duration = Duration::from_secs(3600);
// Start rekeying early enough that everything the peer may still send under
// the old keys, plus the key exchange itself, fits under the hard limit.
const DEFAULT_REKEY_BYTES: usize = KEY_BYTE_LIMIT - MAX_IN_FLIGHT_BYTES - (8 << 20);
// How much inbound data is discarded while a disconnect drains.
const DISCONNECT_DRAIN_BYTES: u64 = 2 << 20;
const DISCONNECT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
/// How long a disconnect message may take to leave. A peer that has stopped
/// reading would otherwise hold the closing side until TCP gives up.
const DISCONNECT_SEND_TIMEOUT: Duration = Duration::from_secs(5);
// Fit the default 32 KiB channel data packet and its transport overhead.
const TRANSPORT_READ_CAPACITY: usize = 33 * 1024;

enum HostIdentity {
    Client {
        pinned: Credential,
        certificate_signatures: CertificateSignaturePolicy,
    },
    Server(HostKeys),
    Unverified(Role),
}

enum Handshake<V> {
    Client {
        verify_host: V,
        certificate_signatures: CertificateSignaturePolicy,
        observe_key_exchanges: bool,
        inactivity_timeout: Option<Duration>,
    },
    Server(HostKeys),
}

pub(crate) struct ClientHandshakeOptions<'a> {
    pub(crate) identification: &'a identification::Settings,
    pub(crate) observe_key_exchanges: bool,
    pub(crate) inactivity_timeout: Option<Duration>,
}

pub(crate) struct Identified<S> {
    reader: BufReader<stream::ReadHalf<S>>,
    writer: stream::WriteHalf<S>,
    ids: identification::Ids,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Identified<S> {
    pub(crate) async fn exchange(
        stream: S,
        role: Role,
        settings: &identification::Settings,
    ) -> io::Result<Self> {
        let (reader, mut writer) = stream::split(stream);
        let mut reader = BufReader::with_capacity(TRANSPORT_READ_CAPACITY, reader);
        let ids = identification::exchange_with(role, &mut reader, &mut writer, settings).await?;
        Ok(Self {
            reader,
            writer,
            ids,
        })
    }
}

impl HostIdentity {
    fn role(&self) -> Role {
        match self {
            Self::Client { .. } => Role::Client,
            Self::Server(_) => Role::Server,
            Self::Unverified(role) => *role,
        }
    }
}

pub(crate) enum Input {
    Deferred(Vec<u8>),
    Packet(ReceivedPacket),
    Rekey(Option<OwnedMutexGuard<()>>),
}

#[derive(Clone, Copy)]
pub(crate) struct Activity {
    /// The last authenticated packet from the peer, of any kind.
    pub(crate) received: Instant,
    /// The last packet in either direction that was not liveness traffic.
    pub(crate) active: Instant,
}

/// Whether a payload only shows that its sender is alive: transport filler,
/// a keepalive request, or the reply to any request. Such packets must not
/// restart the idle timer, or probing a quiet peer would keep an unused
/// session open for ever. A reply is never activity of its own; the request
/// it answers already was, unless that was a keepalive.
pub(crate) fn liveness_only(payload: &[u8]) -> bool {
    const KEEPALIVE: &[u8] = crate::channel::KEEPALIVE_REQUEST.as_bytes();
    let named_keepalive = |fields: &[u8]| {
        fields
            .split_first_chunk::<4>()
            .is_some_and(|(length, name)| {
                u32::from_be_bytes(*length) as usize == KEEPALIVE.len()
                    && name.starts_with(KEEPALIVE)
            })
    };
    match payload {
        // IGNORE, UNIMPLEMENTED, DEBUG; global and channel request replies.
        [2..=4 | 81 | 82 | 99 | 100, ..] => true,
        [80, fields @ ..] => named_keepalive(fields),
        [98, _, _, _, _, fields @ ..] => named_keepalive(fields),
        _ => false,
    }
}

/// A stream after mutual NEWKEYS. The first exchange hash identifies its session.
pub struct Transport<S> {
    reader: BufReader<stream::ReadHalf<S>>,
    writer: stream::WriteHalf<S>,
    receive: Direction,
    send: Direction,
    session_id: Zeroizing<Vec<u8>>,
    transcript: Transcript,
    completed_exchanges: Option<Vec<CompletedKeyExchange>>,
    preferences: TransportPreferences,
    gex_group_lookup: Option<gex::GexGroupLookup>,
    pending_kexinit: Option<Vec<u8>>,
    host_algorithms: Vec<Algorithm>,
    host: HostIdentity,
    authenticated: bool,
    authenticating: bool,
    in_flight: InFlight,
    extensions: Extensions,
    announce_extensions: Option<ServerAdvertisement>,
    user_signatures: UserSignatures,
    keys_started: Instant,
    rekey_read_bytes: usize,
    rekey_write_bytes: usize,
    rekey_age: Duration,
    failed: bool,
    activity: Option<watch::Sender<Activity>>,
}

/// The algorithms negotiated by a completed client key exchange, reported
/// to handlers that enable `client::Handler::observe_key_exchanges`.
#[non_exhaustive]
pub struct CompletedKeyExchange {
    pub kex_algorithm: &'static str,
    pub host_key_algorithm: Algorithm,
    pub cipher: Cipher,
    pub macs: [Mac; 2],
    pub compression: CompressionAlgorithms,
    pub ignore_guessed: bool,
    pub strict_kex: bool,
    /// Whether this was the connection's first key exchange.
    pub initial: bool,
}

impl CompletedKeyExchange {
    fn new(transcript: &Transcript, macs: [Mac; 2], ignore_guessed: bool, initial: bool) -> Self {
        Self {
            kex_algorithm: transcript.kex_algorithm,
            host_key_algorithm: certificate_signature_algorithm(&transcript.host_key_algorithm)
                .unwrap_or_else(|| transcript.host_key_algorithm.clone()),
            cipher: transcript.packet_algorithms.client_to_server.cipher,
            macs,
            compression: transcript.compression,
            ignore_guessed,
            strict_kex: transcript.strict_kex,
            initial,
        }
    }
}

struct ServerAdvertisement {
    agent_forwarding: bool,
    signature_algorithms: Vec<Algorithm>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    pub(crate) fn take_completed_key_exchanges(&mut self) -> Vec<CompletedKeyExchange> {
        self.completed_exchanges
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    fn report_rekey(&mut self, macs: [Mac; 2], ignore_guessed: bool) {
        if let Some(completed) = &mut self.completed_exchanges {
            completed.push(CompletedKeyExchange::new(
                &self.transcript,
                macs,
                ignore_guessed,
                false,
            ));
        }
    }

    /// Exchange hash from the first key exchange. Empty for `Kex::None`.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    pub(crate) fn monitor_activity(&mut self) -> watch::Receiver<Activity> {
        let now = Instant::now();
        let (traffic, activity) = watch::channel(Activity {
            received: now,
            active: now,
        });
        self.receive.activity = Some(traffic.clone());
        self.activity = Some(traffic);
        activity
    }

    pub fn strict_kex(&self) -> bool {
        self.transcript.strict_kex
    }

    /// Method selected in the most recent key exchange.
    pub fn key_exchange_algorithm(&self) -> &'static str {
        self.transcript.kex_algorithm
    }

    /// The host signature algorithm selected in KEXINIT. With `Kex::None`
    /// this is an advertised name only and no host proof is presented.
    pub fn host_key_algorithm(&self) -> &Algorithm {
        &self.transcript.host_key_algorithm
    }

    /// Current negotiated packet protection, ordered by protocol direction.
    pub fn packet_algorithms(&self) -> PacketAlgorithms {
        self.transcript.packet_algorithms
    }

    /// Compression selected during the current key exchange.
    pub fn compression_algorithms(&self) -> CompressionAlgorithms {
        self.transcript.compression
    }

    /// Algorithms the server announced for public-key user authentication.
    pub fn server_signature_algorithms(&self) -> Option<&str> {
        self.extensions.server_signature_algorithms()
    }

    pub(crate) fn watch_server_signature_algorithms(&mut self) -> ServerSignatureAlgorithms {
        self.extensions.watch_server_signature_algorithms()
    }

    pub(crate) fn supports_standard_agent_forwarding(&self) -> bool {
        self.extensions.supports_standard_agent_forwarding()
    }

    pub(crate) fn configure_server_extensions(
        &mut self,
        agent_forwarding: bool,
        signature_algorithms: &[Algorithm],
    ) {
        let signature_algorithms = if self.session_id.is_empty() {
            &[]
        } else {
            signature_algorithms
        };
        self.user_signatures = UserSignatures::from_algorithms(signature_algorithms);
        if let Some(announcement) = &mut self.announce_extensions {
            announcement.agent_forwarding = agent_forwarding;
            announcement.signature_algorithms.clear();
            for algorithm in signature_algorithms {
                if supports_signature_algorithm(algorithm)
                    && !announcement.signature_algorithms.contains(algorithm)
                {
                    announcement.signature_algorithms.push(algorithm.clone());
                }
            }
        }
    }

    pub(crate) fn user_signatures(&self) -> UserSignatures {
        self.user_signatures.clone()
    }

    pub(crate) async fn send_initial_server_extensions(&mut self) -> io::Result<()> {
        if self.announce_extensions.is_some() {
            self.begin_io()?;
            self.write_application(None).await?;
            self.failed = false;
        }
        Ok(())
    }

    /// Start rekey at the next packet boundary once either direction uses
    /// its own byte allowance or the keys reach `age`. An idle stream checks
    /// the threshold when the caller next drives I/O. The built-in userauth
    /// exchange defers local automatic rekey until authentication succeeds.
    ///
    /// The arguments follow [`Limits::new`]. Byte limits may be as large as
    /// one GiB; the transport starts earlier than a limit near that maximum.
    pub fn set_rekey_limits(
        &mut self,
        write_bytes: usize,
        read_bytes: usize,
        age: Duration,
    ) -> io::Result<()> {
        let valid = 1..=KEY_BYTE_LIMIT;
        if !valid.contains(&read_bytes) || !valid.contains(&write_bytes) || age.is_zero() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid SSH rekey limits",
            ));
        }
        self.rekey_read_bytes = read_bytes.min(DEFAULT_REKEY_BYTES);
        self.rekey_write_bytes = write_bytes.min(DEFAULT_REKEY_BYTES);
        self.rekey_age = age;
        Ok(())
    }

    pub(crate) fn apply_limits(&mut self, limits: &Limits) -> io::Result<()> {
        self.set_rekey_limits(
            limits.rekey_write_limit,
            limits.rekey_read_limit,
            limits.rekey_time_limit,
        )
    }

    /// Replace the active keys and preserve the connection's session ID.
    /// The peer must drive its input while this operation runs. Cancellation
    /// and I/O errors make the connection unusable.
    pub async fn rekey(&mut self) -> io::Result<()> {
        let guard = acquire_rekey(self.rekey_gate().cloned()).await;
        self.rekey_with_guard(guard).await
    }

    async fn rekey_with_guard(&mut self, guard: Option<OwnedMutexGuard<()>>) -> io::Result<()> {
        self.begin_io()?;
        self.exchange_keys(guard).await?;
        self.failed = false;
        Ok(())
    }

    /// Close the connection with SSH_MSG_DISCONNECT (by application).
    pub async fn disconnect(self) -> io::Result<()> {
        self.disconnect_with_packet(&disconnect_packet(11, "", "")?)
            .await
    }

    pub(crate) async fn disconnect_with_packet(mut self, packet: &[u8]) -> io::Result<()> {
        self.close_with_packet(packet).await
    }

    pub(crate) async fn close_with_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let sent = timeout(DISCONNECT_SEND_TIMEOUT, self.send(packet)).await;
        self.failed = true;
        sent.map_err(|_| {
            io::Error::new(
                ErrorKind::TimedOut,
                "SSH disconnect message could not be sent in time",
            )
        })??;
        // A caller-owned relay may still be forwarding the flushed packet.
        // Half-close the write side and give the peer time to close its side
        // before the stream (and any relay process it owns) is dropped.
        let _ = timeout(DISCONNECT_DRAIN_TIMEOUT, async {
            self.writer.shutdown().await?;
            let mut inbound = (&mut self.reader).take(DISCONNECT_DRAIN_BYTES);
            stream::copy(&mut inbound, &mut stream::sink()).await
        })
        .await;
        Ok(())
    }

    /// The peer's identification line, without the line ending or greeting.
    pub fn peer_identification(&self) -> &[u8] {
        match self.host.role() {
            Role::Client => &self.transcript.server.identification,
            Role::Server => &self.transcript.client.identification,
        }
    }

    /// Read an authenticated payload. A pending packet read can be resumed
    /// after cancellation. Cancellation during key exchange, or an I/O or
    /// protocol error, makes the connection unusable.
    pub async fn receive(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let input = self.read_input().await?;
            if let Some(payload) = self.handle_input(input).await? {
                return Ok(payload);
            }
        }
    }

    /// Wait for one input without writing or initiating key exchange.
    pub(crate) async fn read_input(&mut self) -> io::Result<Input> {
        self.ensure_usable()?;
        if let Some(payload) = self.in_flight.pop() {
            return Ok(Input::Deferred(payload));
        }
        if self.pending_kexinit.is_some() {
            // The next frame can belong to the deferred exchange. Leave it on
            // the wire while the channel driver continues servicing commands.
            return Ok(Input::Rekey(
                acquire_rekey(self.rekey_gate().cloned()).await,
            ));
        }
        let result = if self.rekey_due() {
            let gate = self.rekey_gate().cloned();
            tokio::select! {
                biased;
                guard = acquire_rekey(gate) => return Ok(Input::Rekey(guard)),
                result = self.receive.read_packet(&mut self.reader) => result,
            }
        } else {
            self.receive.read_packet(&mut self.reader).await
        };
        result
            .map(Input::Packet)
            .inspect_err(|_| self.failed = true)
    }

    /// Commit the result of read_input before starting the next operation.
    pub(crate) async fn handle_input(&mut self, input: Input) -> io::Result<Option<Vec<u8>>> {
        Ok(self
            .handle_packet_input(input)
            .await?
            .map(ReceivedPacket::into_vec))
    }

    pub(crate) async fn handle_packet_input(
        &mut self,
        input: Input,
    ) -> io::Result<Option<ReceivedPacket>> {
        self.ensure_usable()?;
        let payload = match input {
            Input::Deferred(payload) => return Ok(Some(ReceivedPacket::from_payload(payload))),
            Input::Packet(payload) => payload,
            Input::Rekey(guard) => {
                self.rekey_with_guard(guard).await?;
                return Ok(None);
            }
        };
        if self
            .extensions
            .observe(&payload)
            .inspect_err(|_| self.failed = true)?
        {
            return Ok(None);
        }
        if !self.authenticated && *payload == [SUCCESS] && self.host.role() == Role::Client {
            self.authentication_succeeded();
        }
        match payload[0] {
            KEXINIT => {
                self.pending_kexinit = Some(payload.into_vec());
                if let Some(guard) = self.try_rekey_guard() {
                    self.rekey_with_guard(guard).await?;
                }
                Ok(None)
            }
            21..=49 => {
                self.failed = true;
                Err(invalid("unexpected SSH key exchange message"))
            }
            _ => Ok(Some(payload)),
        }
    }

    /// Send one protected payload. After authentication, a blocked write can
    /// buffer incoming packets so both directions can make progress.
    /// I/O failure or cancellation makes the connection unusable because a
    /// frame may have been partially written.
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send_packet(payload, true).await
    }

    pub(crate) async fn send_probe(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send_packet(payload, false).await
    }

    async fn send_packet(&mut self, payload: &[u8], count_as_activity: bool) -> io::Result<()> {
        if payload
            .first()
            .is_some_and(|&message| message == EXT_INFO || (20..=49).contains(&message))
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SSH key exchange and extension messages belong to the transport",
            ));
        }
        if payload.is_empty() || payload.len() > clear_packet::MAX_TRANSPORT_PAYLOAD {
            // Reject a caller error before any I/O can make the transport unusable.
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid SSH payload length",
            ));
        }
        self.begin_io()?;
        if payload.first() != Some(&1)
            && (self.pending_kexinit.is_some() || self.rekey_due())
            && let Some(guard) = self.try_rekey_guard()
        {
            self.exchange_keys(guard).await?;
        }
        self.write_application(Some(payload)).await?;
        if payload == [SUCCESS] && self.host.role() == Role::Server {
            self.authentication_succeeded();
        }
        self.failed = false;
        if count_as_activity
            && !liveness_only(payload)
            && let Some(traffic) = &self.activity
        {
            traffic.send_modify(|activity| activity.active = Instant::now());
        }
        Ok(())
    }

    async fn write_application(&mut self, payload: Option<&[u8]>) -> io::Result<()> {
        let write = write_with_extensions(
            &mut self.send,
            &mut self.writer,
            &mut self.announce_extensions,
            payload,
        );
        // A normal pre-auth write cannot process an incoming success packet
        // until its own frame finishes. The server's initial EXT_INFO may
        // instead overlap a client's service request on a small buffer.
        if payload.is_some_and(|packet| !self.authenticated || packet.first() == Some(&1)) {
            return write.await;
        }
        // The block ends with the peer's KEXINIT, or with the write's result.
        let outcome = {
            let mut write = pin!(write);
            loop {
                let receive_enabled =
                    self.pending_kexinit.is_none() && self.in_flight.has_packet_space();
                let mut read = pin!(self.receive.read(&mut self.reader));
                let packet = if payload.is_none() {
                    // A peer may send a disconnect and close immediately after
                    // NEWKEYS. Observe it before an initial EXT_INFO write
                    // can fail against the closed stream.
                    tokio::select! {
                        biased;
                        result = &mut read, if receive_enabled => result?,
                        result = &mut write => break Err(result),
                    }
                } else {
                    tokio::select! {
                        biased;
                        result = &mut write => break Err(result),
                        result = &mut read, if receive_enabled => result?,
                    }
                };
                if self.extensions.observe(&packet)? {
                    continue;
                }
                match packet[0] {
                    KEXINIT => {
                        // Finish the frame already started under the old keys.
                        match write.await {
                            Ok(()) => break Ok(packet),
                            Err(error) => break Err(Err(error)),
                        }
                    }
                    1 => return Err(peer_disconnected(&packet)),
                    21..=49 => return Err(invalid("unexpected SSH key exchange message")),
                    _ => self.in_flight.push(packet)?,
                }
            }
        };
        let peer_proposal = match outcome {
            Ok(proposal) => proposal,
            Err(Ok(())) => return Ok(()),
            Err(Err(error)) => {
                self.queue_arrived_input().await;
                return Err(error);
            }
        };
        self.pending_kexinit = Some(peer_proposal);
        if let Some(guard) = self.try_rekey_guard() {
            self.exchange_keys(guard).await?;
        }
        Ok(())
    }

    /// After a failed write, keep the packets that had already arrived in
    /// full. A peer that sends its last output and then closes the stream
    /// breaks our write while that output is still unread; this is the only
    /// chance to read it. Nothing here waits for the peer.
    async fn queue_arrived_input(&mut self) {
        while self.pending_kexinit.is_none() && self.in_flight.has_packet_space() {
            let arrived = tokio::select! {
                biased;
                result = self.receive.read(&mut self.reader) => result.ok(),
                () = std::future::ready(()) => None,
            };
            let Some(packet) = arrived else { break };
            match self.extensions.observe(&packet) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => break,
            }
            // A disconnect or the start of a key exchange ends what can be
            // kept: nothing after either belongs to the channels.
            if matches!(packet[0], 1 | 20..=49) || self.in_flight.push(packet).is_err() {
                break;
            }
        }
    }

    fn begin_io(&mut self) -> io::Result<()> {
        self.ensure_usable()?;
        self.failed = true;
        Ok(())
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "SSH transport is unusable",
            ));
        }
        Ok(())
    }

    /// A packet the peer sent before this transport failed that nobody has
    /// seen yet. A write keeps reading while it waits for the peer, so input
    /// can be queued here when the connection is lost; it was authenticated
    /// on arrival and stays valid.
    pub(crate) fn take_undelivered(&mut self) -> Option<ReceivedPacket> {
        self.in_flight.pop().map(ReceivedPacket::from_payload)
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }

    fn authentication_succeeded(&mut self) {
        self.authenticated = true;
        self.authenticating = false;
        if let HostIdentity::Unverified(role) = self.host {
            self.send.finish_unprotected_userauth(false);
            self.receive
                .finish_unprotected_userauth(role == Role::Client);
        } else {
            self.send.enable_delayed_compression();
            self.receive.enable_delayed_compression();
        }
    }

    pub(crate) fn begin_userauth(&mut self) {
        self.authenticating = true;
    }

    pub(crate) fn begin_connection_without_userauth(&mut self) {
        // Without a USERAUTH_SUCCESS packet, delayed compression stays off
        // until the first rekey establishes the authenticated compression state.
        self.authenticated = true;
    }
}

async fn acquire_rekey(gate: Option<Arc<Mutex<()>>>) -> Option<OwnedMutexGuard<()>> {
    match gate {
        Some(gate) => Some(gate.lock_owned().await),
        None => None,
    }
}

fn handshake_algorithms<V>(
    handshake: &Handshake<V>,
    offered: &[Algorithm],
) -> io::Result<(Role, Vec<Algorithm>)> {
    if offered.is_empty()
        || offered.iter().enumerate().any(|(index, algorithm)| {
            (!supports_signature_algorithm(algorithm)
                && certificate_signature_algorithm(algorithm).is_none())
                || offered[..index].contains(algorithm)
        })
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH host key algorithms",
        ));
    }
    let (role, algorithms) = match handshake {
        Handshake::Client { .. } => (Role::Client, offered.to_vec()),
        Handshake::Server(keys) => (
            Role::Server,
            offered
                .iter()
                .filter(|algorithm| keys.select(algorithm).is_some())
                .cloned()
                .collect(),
        ),
    };
    if algorithms.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "no SSH host key for the configured algorithms",
        ));
    }
    Ok((role, algorithms))
}

fn ordered_suites(algorithms: PacketAlgorithms, role: Role) -> (Suite, Suite) {
    match role {
        Role::Client => (algorithms.client_to_server, algorithms.server_to_client),
        Role::Server => (algorithms.server_to_client, algorithms.client_to_server),
    }
}

fn ordered_compression(
    algorithms: CompressionAlgorithms,
    role: Role,
) -> (Compression, Compression) {
    match role {
        Role::Client => (algorithms.client_to_server, algorithms.server_to_client),
        Role::Server => (algorithms.server_to_client, algorithms.client_to_server),
    }
}

async fn write_with_extensions<W: AsyncWrite + Unpin>(
    direction: &mut Direction,
    writer: &mut W,
    announce: &mut Option<ServerAdvertisement>,
    packet: Option<&[u8]>,
) -> io::Result<()> {
    if !packet.is_some_and(|packet| packet.first() == Some(&1))
        && let Some(options) = announce.as_ref()
    {
        direction
            .write(
                writer,
                &extensions::server_announcement(
                    options.agent_forwarding,
                    &options.signature_algorithms,
                )?,
            )
            .await?;
        *announce = None;
    }
    if let Some(packet) = packet {
        direction.write(writer, packet).await?;
    }
    Ok(())
}

enum MethodIo<'a, S> {
    Clear {
        reader: &'a mut clear_packet::PacketReader<BufReader<stream::ReadHalf<S>>>,
        writer: &'a mut stream::WriteHalf<S>,
        strict: bool,
        next_receive_sequence: u32,
    },
    Protected {
        reader: &'a mut BufReader<stream::ReadHalf<S>>,
        writer: &'a mut stream::WriteHalf<S>,
        receive: &'a mut Direction,
        send: &'a mut Direction,
    },
}

impl<S: AsyncRead + AsyncWrite + Unpin> MethodIo<'_, S> {
    async fn write(&mut self, packet: &[u8]) -> io::Result<()> {
        match self {
            Self::Clear { writer, .. } => clear_packet::write(writer, packet).await,
            Self::Protected { writer, send, .. } => send.write(writer, packet).await,
        }
    }

    async fn read(&mut self, expected: u8) -> io::Result<Vec<u8>> {
        match self {
            Self::Clear {
                reader,
                strict,
                next_receive_sequence,
                ..
            } => {
                let packet = reader.read().await?;
                let sequence = *next_receive_sequence;
                *next_receive_sequence += 1;
                match packet[0] {
                    message if message == expected => Ok(packet),
                    1 => Err(peer_disconnected(&packet)),
                    message => Err(unexpected_initial_message(
                        message,
                        sequence,
                        *strict,
                        "unexpected SSH key exchange message",
                    )),
                }
            }
            Self::Protected {
                reader, receive, ..
            } => read_rekey_packet(receive, reader, expected).await,
        }
    }

    async fn client(
        &mut self,
        transcript: &Transcript,
        session_id: Option<&[u8]>,
        parameters: GexSizes,
        certificate_signatures: CertificateSignaturePolicy,
    ) -> io::Result<ClientExchangeResult> {
        let (client, init, reply_message) = if gex::is_method(transcript.kex_algorithm) {
            self.write(&parameters.request()).await?;
            let group = gex::Exchange::client(parameters, self.read(gex::GROUP).await?).await?;
            let (exchange, init) = ClientExchange::start_group(group)?;
            (exchange, init, gex::REPLY)
        } else {
            let (exchange, init) = ClientExchange::start(transcript.kex_algorithm)?;
            (exchange, init, KEX_METHOD_REPLY)
        };
        self.write(&init).await?;
        let reply = self.read(reply_message).await?;
        let result = client.finish(&reply, transcript, session_id, certificate_signatures);
        self.kex_result(transcript, result).await
    }

    async fn server(
        &mut self,
        transcript: &Transcript,
        session_id: Option<&[u8]>,
        signer: &HostSigner,
        group_lookup: Option<&gex::GexGroupLookup>,
    ) -> io::Result<ExchangeKeys> {
        let (group, init_message) = if gex::is_method(transcript.kex_algorithm) {
            let group =
                gex::Exchange::server(&self.read(gex::REQUEST).await?, group_lookup).await?;
            self.write(group.group_packet()).await?;
            (Some(group), gex::INIT)
        } else {
            (None, KEX_METHOD_INIT)
        };
        let init = self.read(init_message).await?;
        let result = kex::server_reply(&init, transcript, signer, session_id, group.as_ref());
        let (keys, reply) = self.kex_result(transcript, result).await?;
        self.write(&reply).await?;
        Ok(keys)
    }

    async fn kex_result<T>(
        &mut self,
        transcript: &Transcript,
        result: io::Result<T>,
    ) -> io::Result<T> {
        if transcript.kex_algorithm == Kex::MlKem768X25519Sha256.name()
            && result
                .as_ref()
                .is_err_and(|error| error.kind() == ErrorKind::InvalidData)
            && let Ok(packet) =
                disconnect_packet(KEY_EXCHANGE_FAILED, "SSH key exchange failed", "")
        {
            // Ignore a peer write failure so the local caller still sees the original proof error.
            let _ = self.write(&packet).await;
        }
        result
    }
}

async fn read_rekey_packet<R: AsyncRead + Unpin>(
    direction: &mut Direction,
    reader: &mut R,
    expected: u8,
) -> io::Result<Vec<u8>> {
    for _ in 0..32 {
        let packet = direction.read(reader).await?;
        match packet[0] {
            message if message == expected => return Ok(packet),
            1 => return Err(peer_disconnected(&packet)),
            2..=4 => {}
            _ => return Err(invalid("unexpected SSH rekey message")),
        }
    }
    Err(invalid("too many SSH transport messages during rekey"))
}

fn rejected_host() -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, "SSH host key rejected")
}

#[cfg(test)]
mod tests;
