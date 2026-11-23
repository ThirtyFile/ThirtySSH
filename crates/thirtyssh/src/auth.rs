//! Authentication for the SSH connection service.
mod gssapi;
mod interactive;

use crate::{
    channel::global,
    clear_packet::invalid,
    kex::{self, ED25519},
    keys::{
        self, Algorithm, Certificate, CertificatePermissions, CertificateSignaturePolicy,
        Credential, PrivateKey, PublicKey, UserSignatures, ssh_key::certificate::CertType,
    },
    protocol_error::ProtocolError,
    runtime::{Instant, sleep_until, timeout},
    transport::{
        CompletedKeyExchange, DisconnectRequest, HostKey, Transport, disconnect_packet,
        peer_disconnected,
    },
    wire::{self, Reader, Writer},
};
pub use gssapi::{GssContext, GssInput, GssProgress, GssRejection};
pub use interactive::{
    Challenge, InteractiveAttempt, InteractiveDecision, InteractiveResponse, Prompt,
};
use std::{
    future::{Future, pending, ready},
    io::{self, ErrorKind},
    net::IpAddr,
    num::NonZeroUsize,
    pin::Pin,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

const AUTH_SERVICE: &[u8] = b"ssh-userauth";
const CONNECTION: &[u8] = b"ssh-connection";
const REQUEST: u8 = 50;
const FAILURE: u8 = 51;
pub(crate) const SUCCESS: u8 = 52;
const BANNER: u8 = 53;
const PASSWORD_CHANGE_REQUEST: u8 = 60;
const PUBLIC_KEY_OK: u8 = 60;
const MAX_USERNAME: usize = 1024;
const MAX_PASSWORD: usize = 32768;
const MAX_ATTEMPTS: usize = 10;
// With a failure budget (`max_rejections`) probes and intermediate challenges
// are not counted as rejections. Cap them separately so an unauthenticated
// client cannot drive unlimited policy callbacks (key enumeration, PAM or
// database lookups) without ever failing a login.
const MAX_UNCOUNTED_REPLIES: usize = 256;

mod policy;
mod server;
pub use policy::*;
pub use server::*;

/// A connection whose peer has authenticated for the SSH connection service.
pub struct Authenticated<S> {
    pub(crate) transport: Transport<S>,
    pub(crate) username: String,
    pub(crate) permissions: Option<CertificatePermissions>,
}

impl<S> Authenticated<S> {
    pub fn username(&self) -> &str {
        &self.username
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Authenticated<S> {
    pub fn server_signature_algorithms(&self) -> Option<&str> {
        self.transport.server_signature_algorithms()
    }
}

pub(crate) fn malformed(error: wire::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error)
}

fn denied() -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, "SSH authentication rejected")
}

fn request(username: &str, method: &[u8]) -> io::Result<Vec<u8>> {
    if username.len() > MAX_USERNAME {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH username exceeds limit",
        ));
    }
    kex::fields(Some(REQUEST), &[username.as_bytes(), CONNECTION, method])
}

fn public_key_request(
    username: &str,
    signed: bool,
    algorithm: &[u8],
    key: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = request(username, b"publickey")?;
    packet.push(u8::from(signed));
    packet.extend_from_slice(&kex::fields(None, &[algorithm, key])?);
    Ok(packet)
}

fn require_session_binding(session_id: &[u8]) -> io::Result<()> {
    if session_id.is_empty() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "SSH authentication proof requires a session identifier",
        ));
    }
    Ok(())
}

fn signature_input(session_id: &[u8], packet: &[u8]) -> io::Result<Vec<u8>> {
    require_session_binding(session_id)?;
    let mut signed = kex::fields(None, &[session_id])?;
    signed.extend_from_slice(packet);
    Ok(signed)
}

/// The server's verdict on one authentication request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "a rejected request leaves the connection unauthenticated"]
pub enum Outcome {
    Accepted,
    Rejected {
        /// Methods the server would still consider.
        remaining_methods: Vec<String>,
        /// The request was valid, but the server requires another one as well.
        partial_success: bool,
    },
}

impl Outcome {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// A way to authenticate with a secret this process holds in memory. For a
/// key held elsewhere, such as an agent or a hardware token, see
/// [`Client::authenticate_with`].
#[derive(Clone)]
#[non_exhaustive]
pub enum Method<'a> {
    /// Ask for access without a credential. The rejection lists the methods
    /// the server offers.
    None,
    Password(&'a str),
    /// The transport's Ed25519 key pair, used as a user identity.
    Ed25519(&'a HostKey),
    /// A private key. Without an algorithm, the server's announcement decides
    /// which signature to make.
    Key {
        key: &'a PrivateKey,
        algorithm: Option<Algorithm>,
    },
    /// A user certificate together with the private key it certifies.
    Certificate {
        certificate: &'a Certificate,
        key: &'a PrivateKey,
        algorithm: Option<Algorithm>,
    },
}

impl<'a> From<&'a PrivateKey> for Method<'a> {
    fn from(key: &'a PrivateKey) -> Self {
        Self::Key {
            key,
            algorithm: None,
        }
    }
}

impl<'a> From<&'a HostKey> for Method<'a> {
    fn from(identity: &'a HostKey) -> Self {
        Self::Ed25519(identity)
    }
}

/// A message from the remote endpoint, typically displayed before login.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Banner {
    pub message: String,
    pub language: String,
}

#[derive(Default)]
pub(crate) struct CallbackActions {
    pub(crate) rekey: bool,
    pub(crate) disconnect: Option<DisconnectRequest>,
}

pub(crate) trait BannerObserver {
    fn banner_timeout(&self) -> Option<Duration> {
        None
    }

    fn received_banner(
        &mut self,
        banner: &Banner,
        peer_identification: &[u8],
    ) -> impl Future<Output = io::Result<CallbackActions>> + Send;

    fn key_exchange_timeout(&self) -> Option<Duration> {
        None
    }

    fn key_exchange_done(
        &mut self,
        _exchange: &CompletedKeyExchange,
        _peer_identification: &[u8],
    ) -> impl Future<Output = io::Result<CallbackActions>> + Send {
        ready(Ok(CallbackActions::default()))
    }
}

impl BannerObserver for () {
    fn received_banner(
        &mut self,
        _: &Banner,
        _: &[u8],
    ) -> impl Future<Output = io::Result<CallbackActions>> + Send {
        ready(Ok(CallbackActions::default()))
    }
}

/// Error source reported when the banner callback requested a local
/// disconnect and it was sent.
#[derive(Debug)]
pub struct AuthBannerDisconnect;

impl std::fmt::Display for AuthBannerDisconnect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SSH client disconnected from the authentication banner callback")
    }
}

impl std::error::Error for AuthBannerDisconnect {}

/// Error source reported when the key exchange callback requested a local
/// disconnect and it was sent.
#[derive(Debug)]
pub struct KeyExchangeDisconnect;

impl std::fmt::Display for KeyExchangeDisconnect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SSH client disconnected from the key exchange callback")
    }
}

impl std::error::Error for KeyExchangeDisconnect {}

/// A complete authentication response and the banners preceding it.
#[derive(Debug, Eq, PartialEq)]
pub struct Attempt {
    pub result: Outcome,
    pub banners: Vec<Banner>,
}

/// The credential and session-bound message passed to an external signer.
pub struct SignRequest<'a> {
    /// The algorithm of the requested proof signature.
    pub algorithm: &'a str,
    /// The public key or certificate in SSH wire format, including its type string.
    pub public_key: &'a [u8],
    /// The encoded session identifier followed by the unsigned portion of the
    /// signed `SSH_MSG_USERAUTH_REQUEST`.
    pub data: &'a [u8],
}

struct KeyOffer<'a> {
    public: &'a PublicKey,
    signature: &'a Algorithm,
    name: &'a str,
    blob: &'a [u8],
}

/// Sign a user authentication request using an agent, hardware key or other provider.
pub trait Signer {
    /// Return the SSH signature blob (algorithm string and signature string),
    /// without the enclosing packet field's length prefix.
    fn auth_sign(
        &mut self,
        request: SignRequest<'_>,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

enum ClientState {
    Unstarted,
    Ready,
    Exchanging,
    Interactive { username: String, prompts: usize },
    Authenticated(String),
}

/// A key-exchanged client connection that supports multiple authentication attempts.
pub struct Client<S> {
    transport: Transport<S>,
    state: ClientState,
    banners: Vec<Banner>,
    banner_bytes: usize,
    interrupted_callback: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub(crate) fn supports_standard_agent_forwarding(&self) -> bool {
        self.transport.supports_standard_agent_forwarding()
    }

    pub(crate) fn watch_server_signature_algorithms(
        &mut self,
    ) -> crate::extensions::ServerSignatureAlgorithms {
        self.transport.watch_server_signature_algorithms()
    }

    pub fn new(transport: Transport<S>) -> Self {
        Self {
            transport,
            state: ClientState::Unstarted,
            banners: Vec::new(),
            banner_bytes: 0,
            interrupted_callback: false,
        }
    }

    pub(crate) fn new_anonymous(mut transport: Transport<S>) -> Self {
        transport.begin_connection_without_userauth();
        let mut client = Self::new(transport);
        client.state = ClientState::Authenticated(String::new());
        client
    }

    pub fn into_authenticated(self) -> io::Result<Authenticated<S>> {
        match self.state {
            ClientState::Authenticated(username) => Ok(Authenticated {
                permissions: None,
                transport: self.transport,
                username,
            }),
            _ => Err(denied()),
        }
    }

    pub(crate) async fn wait_for_command<T>(
        &mut self,
        command: impl Future<Output = T>,
        observer: &mut impl BannerObserver,
    ) -> io::Result<T> {
        if matches!(
            self.state,
            ClientState::Exchanging | ClientState::Authenticated(_)
        ) {
            return Err(denied());
        }
        tokio::pin!(command);
        loop {
            self.dispatch_key_exchanges(observer).await?;
            let input = tokio::select! {
                biased;
                command = &mut command => return Ok(command),
                input = self.transport.read_input() => input?,
            };
            match self.transport.handle_input(input).await?.as_deref() {
                None | Some([2 | 4, ..]) => (),
                Some(packet @ [1, ..]) => return Err(peer_disconnected(packet)),
                Some([global::REQUEST | global::SUCCESS | global::FAILURE, ..]) => {
                    return Err(ProtocolError::GlobalMessageBeforeAuthentication.into());
                }
                Some(packet @ [BANNER, ..]) if !matches!(self.state, ClientState::Unstarted) => {
                    self.receive_banner(packet, observer).await?;
                }
                Some(_) => {
                    return Err(invalid(
                        "unexpected SSH packet between authentication attempts",
                    ));
                }
            }
        }
    }

    pub(crate) fn is_unusable(&self) -> bool {
        self.interrupted_callback
            || self.transport.is_failed()
            || matches!(self.state, ClientState::Exchanging)
    }

    pub(crate) fn interrupted_callback(&self) -> bool {
        self.interrupted_callback
    }

    pub(crate) async fn disconnect_with_packet(self, packet: &[u8]) -> io::Result<()> {
        self.transport.disconnect_with_packet(packet).await
    }

    pub(crate) async fn rekey(&mut self, observer: &mut impl BannerObserver) -> io::Result<()> {
        if matches!(
            self.state,
            ClientState::Exchanging | ClientState::Authenticated(_)
        ) {
            return Err(denied());
        }
        self.transport.rekey().await?;
        self.dispatch_key_exchanges(observer).await
    }

    /// Make one authentication request with a secret held in memory.
    pub async fn authenticate(
        &mut self,
        username: &str,
        method: impl Into<Method<'_>>,
    ) -> io::Result<Attempt> {
        self.authenticate_observed(username, method.into(), &mut ())
            .await
    }

    pub(crate) async fn authenticate_observed(
        &mut self,
        username: &str,
        method: Method<'_>,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Attempt> {
        let packet = match method {
            Method::None => Zeroizing::new(request(username, b"none")?),
            Method::Password(password) => password_request(username, password)?,
            Method::Ed25519(identity) => {
                let packet = public_key_request(username, true, ED25519, &identity.public_blob()?)?;
                let data = signature_input(self.transport.session_id(), &packet)?;
                signed(packet, &identity.sign_blob(&data)?)?
            }
            Method::Key { key, algorithm } => {
                require_session_binding(self.transport.session_id())?;
                self.ensure_service(observer).await?;
                let algorithm = keys::signature_algorithm(
                    key.public_key(),
                    algorithm,
                    self.transport.server_signature_algorithms(),
                )?;
                let blob = key.public_key().to_bytes().map_err(io::Error::other)?;
                let packet =
                    public_key_request(username, true, algorithm.as_str().as_bytes(), &blob)?;
                let data = signature_input(self.transport.session_id(), &packet)?;
                signed(packet, &keys::sign(key, &algorithm, &data)?)?
            }
            Method::Certificate {
                certificate,
                key,
                algorithm,
            } => {
                if certificate.public_key() != key.public_key().key_data() {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "SSH user certificate does not match its private key",
                    ));
                }
                let algorithm = self
                    .certificate_algorithm(certificate, key.public_key(), algorithm, observer)
                    .await?;
                let blob = certificate.to_bytes().map_err(io::Error::other)?;
                let name = algorithm.to_certificate_type();
                let packet = public_key_request(username, true, name.as_bytes(), &blob)?;
                let data = signature_input(self.transport.session_id(), &packet)?;
                signed(packet, &keys::sign(key, &algorithm, &data)?)?
            }
        };
        self.attempt(username, packet, observer).await
    }

    /// Authenticate with a key held by something else: an agent, a hardware
    /// token, a remote service. The server is first asked whether it would
    /// accept the credential, so the signer is not consulted for a key the
    /// server has no use for. A signer that fails or is cancelled leaves the
    /// connection ready for another attempt.
    pub async fn authenticate_with(
        &mut self,
        username: &str,
        credential: &Credential,
        algorithm: Option<Algorithm>,
        signer: &mut impl Signer,
    ) -> io::Result<Attempt> {
        self.authenticate_with_observed(username, credential, algorithm, signer, &mut ())
            .await
    }

    pub(crate) async fn authenticate_with_observed(
        &mut self,
        username: &str,
        credential: &Credential,
        algorithm: Option<Algorithm>,
        signer: &mut impl Signer,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Attempt> {
        let offer = |public, signature, name, blob| KeyOffer {
            public,
            signature,
            name,
            blob,
        };
        match credential {
            Credential::Key(key) => {
                require_session_binding(self.transport.session_id())?;
                self.ensure_service(observer).await?;
                let algorithm = keys::signature_algorithm(
                    key,
                    algorithm,
                    self.transport.server_signature_algorithms(),
                )?;
                let blob = key.to_bytes().map_err(io::Error::other)?;
                let offer = offer(key, &algorithm, algorithm.as_str(), &blob);
                self.probe_and_sign(username, offer, signer, observer).await
            }
            Credential::Certificate(certificate) => {
                let key = PublicKey::new(certificate.public_key().clone(), "");
                let algorithm = self
                    .certificate_algorithm(certificate, &key, algorithm, observer)
                    .await?;
                let name = algorithm.to_certificate_type();
                let blob = certificate.to_bytes().map_err(io::Error::other)?;
                let offer = offer(&key, &algorithm, &name, &blob);
                self.probe_and_sign(username, offer, signer, observer).await
            }
        }
    }

    /// Begin keyboard-interactive authentication, or abandon an open
    /// challenge and start over.
    pub async fn keyboard_interactive(
        &mut self,
        username: &str,
        submethods: &str,
    ) -> io::Result<InteractiveAttempt> {
        self.keyboard_interactive_observed(username, submethods, &mut ())
            .await
    }

    pub(crate) async fn keyboard_interactive_observed(
        &mut self,
        username: &str,
        submethods: &str,
        observer: &mut impl BannerObserver,
    ) -> io::Result<InteractiveAttempt> {
        let mut packet = request(username, interactive::NAME)?;
        packet.extend_from_slice(&interactive::request_fields(submethods)?);
        self.exchange_interactive(username.to_owned(), Zeroizing::new(packet), observer)
            .await
    }

    /// Answer the open challenge, one answer per prompt and in prompt order.
    pub async fn answer(&mut self, answers: &[String]) -> io::Result<InteractiveAttempt> {
        self.answer_observed(answers, &mut ()).await
    }

    pub(crate) async fn answer_observed(
        &mut self,
        answers: &[String],
        observer: &mut impl BannerObserver,
    ) -> io::Result<InteractiveAttempt> {
        let ClientState::Interactive { username, prompts } = &self.state else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "no SSH challenge is pending",
            ));
        };
        if answers.len() != *prompts {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SSH answer count does not match prompts",
            ));
        }
        let packet = interactive::encode_answers(answers)?;
        self.exchange_interactive(username.clone(), packet, observer)
            .await
    }

    async fn exchange_interactive(
        &mut self,
        username: String,
        packet: Zeroizing<Vec<u8>>,
        observer: &mut impl BannerObserver,
    ) -> io::Result<InteractiveAttempt> {
        self.begin_attempt(observer).await?;
        self.transport.send(&packet).await?;
        drop(packet);
        let reply = self.read_reply(observer).await?;
        if reply[0] == interactive::INFO_REQUEST {
            let challenge = Challenge::decode(&reply)?;
            self.state = ClientState::Interactive {
                username,
                prompts: challenge.prompts.len(),
            };
            // The banners of this round are handed over below, so the budget
            // starts again with the next one.
            self.banner_bytes = 0;
            return Ok(InteractiveAttempt {
                response: InteractiveResponse::Challenge(challenge),
                banners: std::mem::take(&mut self.banners),
            });
        }
        let attempt = self.finish_attempt(&username, &reply)?;
        Ok(InteractiveAttempt {
            response: InteractiveResponse::Finished(attempt.result),
            banners: attempt.banners,
        })
    }

    async fn certificate_algorithm(
        &mut self,
        certificate: &Certificate,
        key: &PublicKey,
        algorithm: Option<Algorithm>,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Algorithm> {
        require_session_binding(self.transport.session_id())?;
        if certificate.cert_type() != CertType::User {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SSH user authentication requires a user certificate",
            ));
        }
        self.ensure_service(observer).await?;
        keys::user_certificate_signature_algorithm(
            key,
            algorithm,
            self.transport.server_signature_algorithms(),
        )
    }

    async fn probe_and_sign(
        &mut self,
        username: &str,
        offer: KeyOffer<'_>,
        signer: &mut impl Signer,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Attempt> {
        require_session_binding(self.transport.session_id())?;
        let probe = public_key_request(username, false, offer.name.as_bytes(), offer.blob)?;
        self.begin_attempt(observer).await?;
        self.transport.send(&probe).await?;
        let reply = self.read_reply(observer).await?;
        if reply[0] == FAILURE {
            return self.finish_attempt(username, &reply);
        }
        if kex::decode::<2>(&reply, Some(PUBLIC_KEY_OK))? != [offer.name.as_bytes(), offer.blob] {
            return Err(invalid(
                "SSH public-key probe reply does not match the offered key",
            ));
        }

        // This is a complete exchange. Until we send the signed request,
        // there is no server reply to discard after a local signer error.
        self.state = ClientState::Ready;
        let packet = public_key_request(username, true, offer.name.as_bytes(), offer.blob)?;
        let data = signature_input(self.transport.session_id(), &packet)?;
        let proof = signer.auth_sign(SignRequest {
            algorithm: offer.signature.as_str(),
            public_key: offer.blob,
            data: &data,
        });
        let signature = self.wait_for_command(proof, observer).await??;
        if !keys::verify(offer.public.key_data(), offer.signature, &data, &signature)? {
            return Err(invalid(
                "SSH authentication signer returned an invalid signature",
            ));
        }
        self.attempt(username, signed(packet, &signature)?, observer)
            .await
    }

    async fn attempt(
        &mut self,
        username: &str,
        packet: Zeroizing<Vec<u8>>,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Attempt> {
        self.begin_attempt(observer).await?;
        self.transport.send(&packet).await?;
        drop(packet);
        let reply = self.read_reply(observer).await?;
        self.finish_attempt(username, &reply)
    }

    async fn begin_attempt(&mut self, observer: &mut impl BannerObserver) -> io::Result<()> {
        self.ensure_service(observer).await?;
        // A cancelled exchange may still receive a response for its old
        // username or credential. Require a fresh connection in that case.
        self.state = ClientState::Exchanging;
        Ok(())
    }

    async fn ensure_service(&mut self, observer: &mut impl BannerObserver) -> io::Result<()> {
        match self.state {
            ClientState::Unstarted => {}
            ClientState::Ready | ClientState::Interactive { .. } => return Ok(()),
            ClientState::Exchanging => {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "SSH authentication exchange was interrupted",
                ));
            }
            ClientState::Authenticated(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "SSH authentication already succeeded",
                ));
            }
        }
        self.state = ClientState::Exchanging;
        self.transport.begin_userauth();
        self.transport
            .send(&kex::fields(Some(5), &[AUTH_SERVICE])?)
            .await?;
        let service = self.read_auth_packet(observer).await?;
        if kex::decode::<1>(&service, Some(6))? != [AUTH_SERVICE] {
            return Err(invalid("wrong SSH authentication service"));
        }
        self.state = ClientState::Ready;
        Ok(())
    }

    async fn read_reply(&mut self, observer: &mut impl BannerObserver) -> io::Result<Vec<u8>> {
        loop {
            let reply = self.read_auth_packet(observer).await?;
            if reply[0] != BANNER {
                return Ok(reply);
            }
            self.receive_banner(&reply, observer).await?;
        }
    }

    async fn read_auth_packet(
        &mut self,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Vec<u8>> {
        loop {
            self.dispatch_key_exchanges(observer).await?;
            let input = self.transport.read_input().await?;
            match self.transport.handle_input(input).await? {
                Some(packet) if packet[0] == 1 => return Err(peer_disconnected(&packet)),
                Some(packet)
                    if matches!(
                        packet[0],
                        global::REQUEST | global::SUCCESS | global::FAILURE
                    ) =>
                {
                    return Err(ProtocolError::GlobalMessageBeforeAuthentication.into());
                }
                Some(packet) if !matches!(packet[0], 2 | 4) => return Ok(packet),
                _ => (),
            }
        }
    }

    pub(crate) async fn dispatch_key_exchanges(
        &mut self,
        observer: &mut impl BannerObserver,
    ) -> io::Result<()> {
        let mut completed = self.transport.take_completed_key_exchanges();
        if completed.is_empty() {
            return Ok(());
        }
        self.interrupted_callback = true;
        let limit = observer.key_exchange_timeout();
        let callbacks = async {
            while !completed.is_empty() {
                for exchange in completed {
                    let actions = observer
                        .key_exchange_done(&exchange, self.transport.peer_identification())
                        .await?;
                    drop(exchange);
                    self.apply_callback_actions(actions, KeyExchangeDisconnect)
                        .await?;
                }
                completed = self.transport.take_completed_key_exchanges();
            }
            Ok::<(), io::Error>(())
        };
        if let Some(limit) = limit {
            timeout(limit, callbacks).await.map_err(|_| {
                io::Error::new(ErrorKind::TimedOut, "SSH key exchange callback timed out")
            })??;
        } else {
            callbacks.await?;
        }
        self.interrupted_callback = false;
        Ok(())
    }

    async fn receive_banner(
        &mut self,
        packet: &[u8],
        observer: &mut impl BannerObserver,
    ) -> io::Result<()> {
        self.interrupted_callback = true;
        self.record_banner(packet)?;
        let limit = observer.banner_timeout();
        let callback = async {
            let banner = self.banners.last().expect("recorded banner");
            let actions = observer
                .received_banner(banner, self.transport.peer_identification())
                .await?;
            self.apply_callback_actions(actions, AuthBannerDisconnect)
                .await
        };
        if let Some(limit) = limit {
            timeout(limit, callback).await.map_err(|_| {
                io::Error::new(
                    ErrorKind::TimedOut,
                    "SSH authentication banner callback timed out",
                )
            })??;
        } else {
            callback.await?;
        }
        self.interrupted_callback = false;
        Ok(())
    }

    async fn apply_callback_actions(
        &mut self,
        actions: CallbackActions,
        disconnected: impl std::error::Error + Send + Sync + 'static,
    ) -> io::Result<()> {
        if actions.rekey && actions.disconnect.is_none() {
            self.transport.rekey().await?;
        }
        if let Some(request) = actions.disconnect {
            self.transport.close_with_packet(request.packet()).await?;
            return Err(io::Error::new(ErrorKind::ConnectionAborted, disconnected));
        }
        Ok(())
    }

    fn record_banner(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.banners.len() == 31 {
            return Err(invalid("too many SSH authentication banners"));
        }
        self.banner_bytes += packet.len();
        if self.banner_bytes > 256 * 1024 {
            return Err(invalid("SSH authentication banners exceed budget"));
        }
        let [message, language] = kex::decode::<2>(packet, Some(BANNER))?;
        let decode = |field: &[u8]| {
            String::from_utf8(field.to_vec())
                .map_err(|_| invalid("invalid UTF-8 in SSH authentication banner"))
        };
        // A banner comes from a server that has proved nothing yet, and it is
        // usually printed. Keep line structure and drop every other control
        // character, so it cannot drive the terminal (RFC 4252 section 5.4).
        let printable = |text: &str| -> String {
            text.chars()
                .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
                .collect()
        };
        self.banners.push(Banner {
            message: printable(&decode(message)?),
            language: decode(language)?,
        });
        Ok(())
    }

    fn finish_attempt(&mut self, username: &str, reply: &[u8]) -> io::Result<Attempt> {
        let result = match reply {
            [SUCCESS] => {
                self.state = ClientState::Authenticated(username.to_owned());
                Outcome::Accepted
            }
            [FAILURE, tail @ ..] => {
                let mut reader = Reader::new(tail);
                let methods = reader.name_list().map_err(malformed)?;
                let partial_success = reader.boolean().map_err(malformed)?;
                reader.finish().map_err(malformed)?;
                let remaining_methods = methods
                    .split(',')
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .collect();
                self.state = ClientState::Ready;
                Outcome::Rejected {
                    remaining_methods,
                    partial_success,
                }
            }
            // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: the password was not accepted
            // as it stands. This library does not change passwords, so the
            // attempt is a rejection, and the connection stays usable for
            // another method.
            [PASSWORD_CHANGE_REQUEST, ..] => {
                self.state = ClientState::Ready;
                Outcome::Rejected {
                    remaining_methods: Vec::new(),
                    partial_success: false,
                }
            }
            _ => return Err(invalid("unexpected SSH authentication response")),
        };
        self.banner_bytes = 0;
        Ok(Attempt {
            result,
            banners: std::mem::take(&mut self.banners),
        })
    }
}

/// Authenticate once and require the server to accept. A rejection is
/// reported as `PermissionDenied`.
pub async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    transport: Transport<S>,
    username: &str,
    method: impl Into<Method<'_>>,
) -> io::Result<Authenticated<S>> {
    let mut client = Client::new(transport);
    let _ = client.authenticate(username, method).await?;
    client.into_authenticated()
}

fn password_request(username: &str, password: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if password.len() > MAX_PASSWORD {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH password exceeds limit",
        ));
    }
    let header = request(username, b"password")?;
    let mut packet = Zeroizing::new(vec![0; header.len() + 5 + password.len()]);
    packet[..header.len()].copy_from_slice(&header);
    let mut writer = Writer::new(&mut packet[header.len()..]);
    writer.boolean(false).map_err(io::Error::other)?;
    writer
        .string(password.as_bytes())
        .map_err(io::Error::other)?;
    Ok(packet)
}

/// Complete a public-key request with its proof of possession.
fn signed(mut packet: Vec<u8>, signature: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    packet.extend_from_slice(&kex::fields(None, &[signature])?);
    Ok(Zeroizing::new(packet))
}
