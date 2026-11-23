use super::{policy::Synchronous, *};

enum Login {
    Decision(AuthDecision, Option<CertificatePermissions>),
    UnverifiedPartial(Option<Vec<AuthMethod>>),
    Probe {
        reply: Vec<u8>,
        key: PublicKeyProbe,
    },
    Challenge {
        reply: Vec<u8>,
        pending: PendingChallenge,
    },
    Rejected,
}

struct PublicKeyProbe {
    algorithm: Vec<u8>,
    key: Vec<u8>,
}

struct PendingChallenge {
    submethods: String,
    prompts: usize,
    rounds: usize,
}

fn interactive_outcome(
    decision: InteractiveDecision,
    submethods: &str,
    rounds: usize,
) -> io::Result<Login> {
    Ok(match decision {
        InteractiveDecision::Finished(decision) if rounds == 0 => unverified_decision(decision),
        InteractiveDecision::Finished(decision) => Login::Decision(decision, None),
        InteractiveDecision::Challenge(challenge) if rounds < interactive::MAX_ROUNDS => {
            Login::Challenge {
                reply: challenge.encode()?,
                pending: PendingChallenge {
                    submethods: submethods.to_owned(),
                    prompts: challenge.prompts.len(),
                    rounds: rounds + 1,
                },
            }
        }
        InteractiveDecision::Challenge(_) => Login::Rejected,
    })
}

struct ServerAuthState {
    username: Option<String>,
    methods: Vec<AuthMethod>,
    init_methods: Vec<AuthMethod>,
    partial: bool,
    password_hidden: bool,
    permissions: Option<CertificatePermissions>,
    probe: Option<PublicKeyProbe>,
    interactive: Option<PendingChallenge>,
    peer: Option<IpAddr>,
    signatures: UserSignatures,
    session_bound: bool,
}

impl ServerAuthState {
    fn new(
        methods: &[AuthMethod],
        peer: Option<IpAddr>,
        signatures: UserSignatures,
        session_bound: bool,
    ) -> Self {
        let mut state = Self {
            username: None,
            methods: Vec::new(),
            init_methods: Vec::new(),
            partial: false,
            password_hidden: false,
            permissions: None,
            probe: None,
            interactive: None,
            peer,
            signatures,
            session_bound,
        };
        state.replace_methods(methods);
        state.init_methods = state.methods.clone();
        state
    }

    fn replace_methods(&mut self, methods: &[AuthMethod]) {
        self.methods.clear();
        self.password_hidden = false;
        for &method in methods {
            if self.supports_method(method) && !self.methods.contains(&method) {
                self.methods.push(method);
            }
        }
    }

    fn supports_method(&self, method: AuthMethod) -> bool {
        method != AuthMethod::PublicKey || self.session_bound
    }

    fn bind(&mut self, username: Option<&str>) {
        if self.username.as_deref() != username || username.is_none() {
            self.username = username.map(str::to_owned);
            self.methods.clone_from(&self.init_methods);
            self.partial = false;
            self.password_hidden = false;
            self.permissions = None;
            self.probe = None;
        }
    }

    fn keep_permissions(&mut self, permissions: Option<CertificatePermissions>) -> io::Result<()> {
        if let Some(permissions) = permissions {
            let joined = match self.permissions.take() {
                Some(existing) => existing.intersect(permissions)?,
                None => permissions,
            };
            self.permissions = Some(joined);
        }
        Ok(())
    }

    fn failure(
        &self,
        partial_success: bool,
        advertised: Option<&[AuthMethod]>,
    ) -> io::Result<Vec<u8>> {
        let methods = advertised
            .unwrap_or(&self.methods)
            .iter()
            .filter(|&&method| {
                self.supports_method(method)
                    && (advertised.is_some()
                        || !self.password_hidden
                        || method != AuthMethod::Password)
            })
            .map(|method| method.name())
            .collect::<Vec<_>>()
            .join(",");
        let mut packet = kex::fields(Some(FAILURE), &[methods.as_bytes()])?;
        packet.push(u8::from(partial_success));
        Ok(packet)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthRequestKind {
    None,
    Password,
    Other,
}

async fn check_request(
    packet: &[u8],
    session_id: &[u8],
    policy: &mut impl AsyncPolicy,
    state: &mut ServerAuthState,
) -> io::Result<(String, Login, AuthRequestKind)> {
    let mut reader = Reader::new(packet);
    if reader.byte().map_err(malformed)? != REQUEST {
        return Err(invalid("expected SSH user authentication request"));
    }
    let username = reader.string().map_err(malformed)?;
    let service = reader.string().map_err(malformed)?;
    let method = reader.string().map_err(malformed)?;
    let username =
        str::from_utf8(username).map_err(|_| invalid("invalid SSH username encoding"))?;
    // NUL and other control characters in a username become injection
    // vectors when a policy later uses it in a path, a shell command or a log.
    if service != CONNECTION
        || username.len() > MAX_USERNAME
        || username.chars().any(char::is_control)
    {
        state.bind(None);
        return Ok((username.to_owned(), Login::Rejected, AuthRequestKind::Other));
    }
    state.bind(Some(username));
    let probe = state.probe.take();
    let login = match method {
        b"password" if state.methods.contains(&AuthMethod::Password) => {
            let change = reader.boolean().map_err(malformed)?;
            let password = reader.string().map_err(malformed)?;
            if change {
                reader.string().map_err(malformed)?;
            }
            reader.finish().map_err(malformed)?;
            let decision = if change || password.len() > MAX_PASSWORD {
                AuthDecision::reject()
            } else {
                policy.password_decision(username, password).await?
            };
            Login::Decision(decision, None)
        }
        b"publickey" if state.methods.contains(&AuthMethod::PublicKey) => {
            let login = check_key_request(
                packet,
                reader,
                session_id,
                username,
                policy,
                state,
                probe.as_ref(),
            )
            .await?;
            return Ok((username.to_owned(), login, AuthRequestKind::Other));
        }
        interactive::NAME if state.methods.contains(&AuthMethod::KeyboardInteractive) => {
            let submethods = interactive::read_initial(reader)?;
            let decision = policy
                .keyboard_interactive(username, submethods, None)
                .await?;
            interactive_outcome(decision, submethods, 0)?
        }
        b"none" if !state.partial => {
            reader.finish().map_err(malformed)?;
            unverified_decision(policy.none_decision(username).await?)
        }
        _ => Login::Rejected,
    };
    let kind = match method {
        b"none" => AuthRequestKind::None,
        b"password" => AuthRequestKind::Password,
        _ => AuthRequestKind::Other,
    };
    Ok((username.to_owned(), login, kind))
}

async fn check_interactive_response(
    packet: &[u8],
    policy: &mut impl AsyncPolicy,
    state: &mut ServerAuthState,
) -> io::Result<(String, Login, AuthRequestKind)> {
    let pending = state
        .interactive
        .take()
        .ok_or_else(|| invalid("unexpected SSH keyboard-interactive response"))?;
    let username = state
        .username
        .clone()
        .expect("challenge requires a principal");
    let Some(answers) = interactive::decode_answers(packet, pending.prompts)? else {
        return Ok((username, Login::Rejected, AuthRequestKind::Other));
    };
    let decision = policy
        .keyboard_interactive(&username, &pending.submethods, Some(&answers))
        .await?;
    let outcome = interactive_outcome(decision, &pending.submethods, pending.rounds)?;
    Ok((username, outcome, AuthRequestKind::Other))
}

fn unverified_decision(decision: AuthDecision) -> Login {
    match decision {
        AuthDecision::Reject {
            proceed_with_methods,
            partial_success: true,
        } => Login::UnverifiedPartial(proceed_with_methods),
        decision => Login::Decision(decision, None),
    }
}

async fn check_key_request(
    packet: &[u8],
    mut reader: Reader<'_>,
    session_id: &[u8],
    username: &str,
    policy: &mut impl AsyncPolicy,
    state: &ServerAuthState,
    probe: Option<&PublicKeyProbe>,
) -> io::Result<Login> {
    let signed = reader.boolean().map_err(malformed)?;
    let algorithm = reader.string().map_err(malformed)?;
    let key_blob = reader.string().map_err(malformed)?;
    let signed_len = packet.len() - reader.remaining().len();
    let proof = if signed {
        Some(reader.string().map_err(malformed)?)
    } else {
        None
    };
    reader.finish().map_err(malformed)?;
    let Some(name) = str::from_utf8(algorithm)
        .ok()
        .filter(|name| name.len() <= 64)
    else {
        return Ok(Login::Rejected);
    };
    let Ok(requested) = Algorithm::new(name) else {
        return Ok(Login::Rejected);
    };
    let certificate_signature = keys::certificate_signature_algorithm(&requested);
    let signature = certificate_signature.as_ref().unwrap_or(&requested);
    if !state.signatures.permits(signature) {
        return Ok(Login::Rejected);
    }
    let (identity, permissions) = if certificate_signature.is_some() {
        let cert = match keys::decode_certificate(
            signature,
            key_blob,
            CertType::User,
            policy.certificate_signature_policy(),
        ) {
            Ok(cert) => cert,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(Login::Rejected);
            }
            Err(error) => return Err(error),
        };
        let permissions = match CertificatePermissions::for_user(&cert, state.peer) {
            Ok(permissions) => permissions,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(Login::Rejected);
            }
            Err(error) => return Err(error),
        };
        (Credential::Certificate(Box::new(cert)), Some(permissions))
    } else {
        // A key this server cannot parse is refused like any other unacceptable
        // key, so the client can go on to offer its next one.
        let key = match keys::decode_public_key(signature, key_blob) {
            Ok(key) => key,
            Err(error) if error.kind() == ErrorKind::InvalidData => return Ok(Login::Rejected),
            Err(error) => return Err(error),
        };
        (Credential::Key(key), None)
    };
    let matching_probe =
        probe.is_some_and(|probe| probe.algorithm == algorithm && probe.key == key_blob);
    if !signed || (policy.check_signed_key_offer() && !matching_probe) {
        let decision = match &identity {
            Credential::Key(key) => policy.public_key_offer_decision(username, key).await?,
            Credential::Certificate(cert) => {
                policy.certificate_offer_decision(username, cert).await?
            }
        };
        if decision != AuthDecision::Accept {
            return Ok(unverified_decision(decision));
        }
    }
    if let Some(proof) = proof {
        let verified = keys::verify(
            identity.key_data(),
            signature,
            &signature_input(session_id, &packet[..signed_len])?,
            proof,
        );
        // A proof in the wrong format fails like one that does not verify, so
        // the client can go on to its next key or method.
        match verified {
            Ok(true) => {}
            Ok(false) => return Ok(Login::Rejected),
            Err(error) if error.kind() == ErrorKind::InvalidData => return Ok(Login::Rejected),
            Err(error) => return Err(error),
        }
        let decision = match identity {
            Credential::Key(key) => policy.public_key_decision(username, &key).await?,
            Credential::Certificate(cert) => policy.certificate_decision(username, &cert).await?,
        };
        return Ok(Login::Decision(decision, permissions));
    }
    Ok(Login::Probe {
        reply: kex::fields(Some(PUBLIC_KEY_OK), &[algorithm, key_blob])?,
        key: PublicKeyProbe {
            algorithm: algorithm.to_vec(),
            key: key_blob.to_vec(),
        },
    })
}

/// Settings for a server authentication exchange.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    /// Methods initially enabled for each principal.
    pub methods: Vec<AuthMethod>,
    /// Maximum number of initial authentication requests, including probes.
    pub max_attempts: NonZeroUsize,
    /// Disconnect after this many failure replies, in place of the
    /// `max_attempts` request budget. Probes and intermediate challenges are
    /// not counted.
    pub max_rejections: Option<NonZeroUsize>,
    pub rejection_delay: Duration,
    /// Override the delay only for an initial `none` authentication attempt.
    pub initial_none_rejection_delay: Option<Duration>,
    pub banner: Option<Banner>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            methods: vec![AuthMethod::PublicKey, AuthMethod::Password],
            max_attempts: NonZeroUsize::new(MAX_ATTEMPTS).expect("positive attempt limit"),
            max_rejections: None,
            rejection_delay: Duration::from_millis(250),
            initial_none_rejection_delay: None,
            banner: None,
        }
    }
}

/// Serve up to ten authentication requests, including probes.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    transport: Transport<S>,
    policy: impl Policy,
) -> io::Result<Authenticated<S>> {
    accept_with_options(
        transport,
        &mut Synchronous(policy),
        &ServerOptions::default(),
    )
    .await
}

/// Serve authentication requests before giving the application a connection.
pub async fn accept_with_options<S: AsyncRead + AsyncWrite + Unpin>(
    transport: Transport<S>,
    policy: &mut impl AsyncPolicy,
    options: &ServerOptions,
) -> io::Result<Authenticated<S>> {
    accept_with_peer_addr(transport, policy, options, None).await
}

/// Serve authentication using the trusted remote IP of the transport. Use
/// None when the stream has no reliable network identity.
pub async fn accept_with_peer_addr<S: AsyncRead + AsyncWrite + Unpin>(
    transport: Transport<S>,
    policy: &mut impl AsyncPolicy,
    options: &ServerOptions,
    peer: Option<IpAddr>,
) -> io::Result<Authenticated<S>> {
    accept_until_disconnect(transport, policy, options, peer, pending())
        .await?
        .ok_or_else(denied)
}

enum ServerAuthInput {
    Packet(Vec<u8>),
    Disconnect(DisconnectRequest),
}

async fn wait_server_auth<S: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut Transport<S>,
    mut disconnect: Pin<&mut impl Future<Output = DisconnectRequest>>,
) -> io::Result<ServerAuthInput> {
    loop {
        let input = tokio::select! {
            biased;
            request = &mut disconnect => return Ok(ServerAuthInput::Disconnect(request)),
            input = transport.read_input() => input?,
        };
        // Finish processing a packet before polling the command again. A
        // partial exchange or write cannot be resumed after cancellation.
        if let Some(packet) = transport.handle_input(input).await? {
            match packet[0] {
                1 => return Err(peer_disconnected(&packet)),
                2 | 4 => continue,
                _ => return Ok(ServerAuthInput::Packet(packet)),
            }
        }
    }
}

pub(crate) async fn accept_until_disconnect<S: AsyncRead + AsyncWrite + Unpin>(
    mut transport: Transport<S>,
    policy: &mut impl AsyncPolicy,
    options: &ServerOptions,
    peer: Option<IpAddr>,
    disconnect: impl Future<Output = DisconnectRequest>,
) -> io::Result<Option<Authenticated<S>>> {
    tokio::pin!(disconnect);
    // The configured banner goes out with the answer to the first request.
    // Sent any earlier it would cross the client's request on the wire, and
    // on a stream with little buffering each side would block on its write.
    let mut banner = options.banner.as_ref().map(banner_packet).transpose()?;
    transport.begin_userauth();
    transport.send_initial_server_extensions().await?;
    let service = match wait_server_auth(&mut transport, disconnect.as_mut()).await? {
        ServerAuthInput::Packet(packet) => packet,
        ServerAuthInput::Disconnect(request) => {
            transport.disconnect_with_packet(request.packet()).await?;
            return Ok(None);
        }
    };
    if kex::decode::<1>(&service, Some(5))? != [AUTH_SERVICE] {
        return Err(invalid("wrong SSH authentication service"));
    }
    // The policy's banner applies only when none is configured. It is
    // decided per connection, before any request arrives.
    if banner.is_none() {
        banner = policy
            .authentication_banner()
            .await?
            .as_ref()
            .map(banner_packet)
            .transpose()?;
    }
    transport
        .send(&kex::fields(Some(6), &[AUTH_SERVICE])?)
        .await?;
    let mut state = ServerAuthState::new(
        &options.methods,
        peer,
        transport.user_signatures(),
        !transport.session_id().is_empty(),
    );
    let mut attempts = 0usize;
    let mut rejections = 0usize;
    let mut uncounted_replies = 0usize;
    while options.max_rejections.is_some()
        || attempts < options.max_attempts.get()
        || state.interactive.is_some()
    {
        let attempt = match wait_server_auth(&mut transport, disconnect.as_mut()).await? {
            ServerAuthInput::Packet(packet) => Zeroizing::new(packet),
            ServerAuthInput::Disconnect(request) => {
                transport.disconnect_with_packet(request.packet()).await?;
                return Ok(None);
            }
        };
        if options
            .max_rejections
            .is_some_and(|limit| rejections >= limit.get())
            && matches!(attempt[0], REQUEST | interactive::INFO_RESPONSE)
        {
            drop(attempt);
            let packet = disconnect_packet(14, "Too many authentication attempts", "")?;
            transport.disconnect_with_packet(&packet).await?;
            return Ok(None);
        }
        let received = Instant::now();
        let (username, outcome, kind) = if attempt[0] == interactive::INFO_RESPONSE {
            check_interactive_response(&attempt, policy, &mut state).await?
        } else {
            if options.max_rejections.is_none() && attempts == options.max_attempts.get() {
                break;
            }
            attempts = attempts.saturating_add(1);
            state.interactive = None;
            check_request(&attempt, transport.session_id(), policy, &mut state).await?
        };
        if let Some(banner) = banner.take() {
            transport.send(&banner).await?;
        }
        let (partial_success, advertised) = match outcome {
            Login::Decision(AuthDecision::Accept, permissions) => {
                state.keep_permissions(permissions)?;
                transport.send(&[SUCCESS]).await?;
                return Ok(Some(Authenticated {
                    transport,
                    username,
                    permissions: state.permissions,
                }));
            }
            Login::Probe { reply, key } => {
                uncounted_replies += 1;
                if too_many_uncounted(options, uncounted_replies) {
                    drop(attempt);
                    return refuse_flood(transport).await;
                }
                state.probe = Some(key);
                transport.send(&reply).await?;
                continue;
            }
            Login::Challenge { reply, pending } => {
                drop(attempt);
                uncounted_replies += 1;
                if too_many_uncounted(options, uncounted_replies) {
                    return refuse_flood(transport).await;
                }
                state.interactive = Some(pending);
                transport.send(&reply).await?;
                continue;
            }
            Login::Decision(
                AuthDecision::Reject {
                    proceed_with_methods,
                    partial_success,
                },
                permissions,
            ) => {
                if let Some(methods) = proceed_with_methods {
                    state.replace_methods(&methods);
                } else if kind == AuthRequestKind::Password
                    && policy.hide_rejected_password_method()
                {
                    state.password_hidden = true;
                }
                if partial_success {
                    state.partial = true;
                    state.keep_permissions(permissions)?;
                }
                (partial_success, None)
            }
            // Keep a suggested list for this reply without granting access to
            // a later factor based on an unverified claim of partial success.
            Login::UnverifiedPartial(methods) => (false, methods),
            Login::Rejected => (false, None),
        };
        drop(attempt);
        if partial_success {
            // A factor that passed is not a failed guess: answer at once and
            // leave the rejection budget alone. The reply still counts toward
            // the flood guard so a peer cannot repeat it without bound.
            uncounted_replies += 1;
            if too_many_uncounted(options, uncounted_replies) {
                return refuse_flood(transport).await;
            }
            transport
                .send(&state.failure(true, advertised.as_deref())?)
                .await?;
            continue;
        }
        let delay = if attempts == 1 && kind == AuthRequestKind::None {
            options
                .initial_none_rejection_delay
                .unwrap_or(options.rejection_delay)
        } else {
            options.rejection_delay
        };
        let retry = received.checked_add(delay).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "SSH authentication rejection delay exceeds range",
            )
        })?;
        tokio::select! {
            biased;
            request = &mut disconnect => {
                transport.disconnect_with_packet(request.packet()).await?;
                return Ok(None);
            }
            () = sleep_until(retry) => (),
        }
        transport
            .send(&state.failure(partial_success, advertised.as_deref())?)
            .await?;
        rejections = rejections.saturating_add(1);
    }
    // Say why the connection ends, as the rejection budget does. The result
    // is the denial either way.
    let packet = disconnect_packet(14, "Too many authentication attempts", "")?;
    let _ = transport.disconnect_with_packet(&packet).await;
    Err(denied())
}

fn too_many_uncounted(options: &ServerOptions, replies: usize) -> bool {
    options.max_rejections.is_some() && replies > MAX_UNCOUNTED_REPLIES
}

async fn refuse_flood<S: AsyncRead + AsyncWrite + Unpin>(
    transport: Transport<S>,
) -> io::Result<Option<Authenticated<S>>> {
    let packet = disconnect_packet(14, "Too many authentication attempts", "")?;
    transport.disconnect_with_packet(&packet).await?;
    Ok(None)
}

fn banner_packet(banner: &Banner) -> io::Result<Vec<u8>> {
    if banner.message.len().saturating_add(banner.language.len()) > MAX_PASSWORD {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH authentication banner exceeds limit",
        ));
    }
    kex::fields(
        Some(BANNER),
        &[banner.message.as_bytes(), banner.language.as_bytes()],
    )
}
