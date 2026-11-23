//! Initial key exchange: the ways to open a transport as client or server.
use super::*;

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    /// Perform a client handshake. The verifier runs after signature validation.
    pub async fn connect(
        stream: S,
        verify_host: impl FnOnce(&[u8; 32]) -> bool,
    ) -> io::Result<Self> {
        Self::connect_with_packet_preferences(stream, verify_host, PacketPreferences::default())
            .await
    }

    /// Connect with explicit cipher and MAC preferences.
    pub async fn connect_with_packet_preferences(
        stream: S,
        verify_host: impl FnOnce(&[u8; 32]) -> bool,
        preferences: PacketPreferences,
    ) -> io::Result<Self> {
        Self::connect_with_preferences(
            stream,
            verify_host,
            TransportPreferences {
                packet: preferences,
                ..TransportPreferences::default()
            },
        )
        .await
    }

    /// Connect with explicit packet protection and compression preferences.
    pub async fn connect_with_preferences(
        stream: S,
        verify_host: impl FnOnce(&[u8; 32]) -> bool,
        preferences: TransportPreferences,
    ) -> io::Result<Self> {
        Self::connect_with_verifier(stream, |key| ready(Ok(verify_host(&key))), preferences).await
    }

    /// Perform a client handshake with an asynchronous host-key verifier.
    pub async fn connect_with_verifier<F: Future<Output = io::Result<bool>>>(
        stream: S,
        verify_host: impl FnOnce([u8; 32]) -> F,
        preferences: TransportPreferences,
    ) -> io::Result<Self> {
        Self::connect_with_host_key_verifier(
            stream,
            |key| {
                let verification = key.key_data().ed25519().map(|key| verify_host(key.0));
                async move {
                    match verification {
                        Some(verification) => verification.await,
                        None => Ok(false),
                    }
                }
            },
            preferences,
            &[Algorithm::Ed25519],
        )
        .await
    }

    /// Connect with a typed host-key verifier and an ordered list of allowed
    /// host signature algorithms. The verifier runs only after proof of possession.
    pub async fn connect_with_host_key_verifier<F: Future<Output = io::Result<bool>>>(
        stream: S,
        verify_host: impl FnOnce(PublicKey) -> F,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
    ) -> io::Result<Self> {
        if host_algorithms
            .iter()
            .any(|algorithm| !supports_signature_algorithm(algorithm))
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "raw SSH host key verifier requires raw host algorithms",
            ));
        }
        Self::connect_with_host_identity_verifier(
            stream,
            |identity| async move {
                match identity {
                    Credential::Key(key) => verify_host(key).await,
                    Credential::Certificate(_) => Ok(false),
                }
            },
            preferences,
            host_algorithms,
        )
        .await
    }

    /// Connect with a verifier for raw host keys and OpenSSH host certificates.
    /// The verifier must authorize the peer identity for the dialed host.
    pub async fn connect_with_host_identity_verifier<F: Future<Output = io::Result<bool>>>(
        stream: S,
        verify_host: impl FnOnce(Credential) -> F,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
    ) -> io::Result<Self> {
        Self::connect_with_certificate_policy(
            stream,
            verify_host,
            preferences,
            host_algorithms,
            CertificateSignaturePolicy::default(),
        )
        .await
    }

    /// Connect with an explicit policy for host certificate issuer signatures.
    /// The verifier still decides whether to trust the peer identity.
    pub async fn connect_with_certificate_policy<F: Future<Output = io::Result<bool>>>(
        stream: S,
        verify_host: impl FnOnce(Credential) -> F,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        certificate_signatures: CertificateSignaturePolicy,
    ) -> io::Result<Self> {
        Self::connect_with_negotiated_host_verifier(
            stream,
            |identity, _| verify_host(identity),
            preferences,
            host_algorithms,
            certificate_signatures,
            ClientHandshakeOptions {
                identification: &identification::Settings::default(),
                observe_key_exchanges: false,
                inactivity_timeout: None,
            },
        )
        .await
    }

    pub(crate) async fn connect_with_negotiated_host_verifier<
        F: Future<Output = io::Result<bool>>,
    >(
        stream: S,
        verify_host: impl FnOnce(Credential, Algorithm) -> F,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        certificate_signatures: CertificateSignaturePolicy,
        options: ClientHandshakeOptions<'_>,
    ) -> io::Result<Self> {
        Self::handshake(
            stream,
            Handshake::Client {
                verify_host,
                certificate_signatures,
                observe_key_exchanges: options.observe_key_exchanges,
                inactivity_timeout: options.inactivity_timeout,
            },
            preferences,
            host_algorithms,
            None,
            options.identification,
        )
        .await
    }

    /// Perform a server handshake with the configured Ed25519 host key.
    pub async fn accept(stream: S, host_key: &HostKey) -> io::Result<Self> {
        Self::accept_with_packet_preferences(stream, host_key, PacketPreferences::default()).await
    }

    /// Accept with explicit cipher and MAC preferences.
    pub async fn accept_with_packet_preferences(
        stream: S,
        host_key: &HostKey,
        preferences: PacketPreferences,
    ) -> io::Result<Self> {
        Self::accept_with_preferences(
            stream,
            host_key,
            TransportPreferences {
                packet: preferences,
                ..TransportPreferences::default()
            },
        )
        .await
    }

    /// Accept with explicit packet protection and compression preferences.
    pub async fn accept_with_preferences(
        stream: S,
        host_key: &HostKey,
        preferences: TransportPreferences,
    ) -> io::Result<Self> {
        Self::accept_with_host_keys(
            stream,
            host_key.clone().into(),
            preferences,
            &[Algorithm::Ed25519],
        )
        .await
    }

    /// Accept with one or more server identities. Advertise only requested
    /// algorithms that the configured keys can sign.
    pub async fn accept_with_host_keys(
        stream: S,
        host_keys: HostKeys,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
    ) -> io::Result<Self> {
        Self::accept_with_gex_lookup(stream, host_keys, preferences, host_algorithms, None).await
    }

    /// Accept with an optional per-exchange finite-field group lookup.
    pub async fn accept_with_gex_lookup(
        stream: S,
        host_keys: HostKeys,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        gex_group_lookup: Option<gex::GexGroupLookup>,
    ) -> io::Result<Self> {
        Self::accept_with_settings(
            stream,
            host_keys,
            preferences,
            host_algorithms,
            gex_group_lookup,
            &identification::Settings::default(),
        )
        .await
    }

    pub(crate) async fn accept_with_settings(
        stream: S,
        host_keys: HostKeys,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        gex_group_lookup: Option<gex::GexGroupLookup>,
        settings: &identification::Settings,
    ) -> io::Result<Self> {
        Self::handshake(
            stream,
            Handshake::<fn(Credential, Algorithm) -> Ready<io::Result<bool>>>::Server(host_keys),
            preferences,
            host_algorithms,
            gex_group_lookup,
            settings,
        )
        .await
    }

    pub(crate) async fn accept_identified(
        stream: Identified<S>,
        host_keys: HostKeys,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        gex_group_lookup: Option<gex::GexGroupLookup>,
    ) -> io::Result<Self> {
        let handshake =
            Handshake::<fn(Credential, Algorithm) -> Ready<io::Result<bool>>>::Server(host_keys);
        let (role, algorithms) = handshake_algorithms(&handshake, host_algorithms)?;
        let local_kexinit = initial::local_proposal(role, true, &preferences, &algorithms)?;
        Self::finish_handshake(
            stream,
            handshake,
            role,
            preferences,
            algorithms,
            local_kexinit,
            gex_group_lookup,
        )
        .await
    }

    async fn handshake<F: Future<Output = io::Result<bool>>>(
        stream: S,
        handshake: Handshake<impl FnOnce(Credential, Algorithm) -> F>,
        preferences: TransportPreferences,
        host_algorithms: &[Algorithm],
        gex_group_lookup: Option<gex::GexGroupLookup>,
        settings: &identification::Settings,
    ) -> io::Result<Self> {
        let (role, algorithms) = handshake_algorithms(&handshake, host_algorithms)?;
        let local_kexinit = initial::local_proposal(role, true, &preferences, &algorithms)?;
        let stream = Identified::exchange(stream, role, settings).await?;
        Self::finish_handshake(
            stream,
            handshake,
            role,
            preferences,
            algorithms,
            local_kexinit,
            gex_group_lookup,
        )
        .await
    }

    async fn finish_handshake<F: Future<Output = io::Result<bool>>>(
        stream: Identified<S>,
        handshake: Handshake<impl FnOnce(Credential, Algorithm) -> F>,
        role: Role,
        preferences: TransportPreferences,
        algorithms: Vec<Algorithm>,
        local_kexinit: Vec<u8>,
        gex_group_lookup: Option<gex::GexGroupLookup>,
    ) -> io::Result<Self> {
        let Identified {
            reader,
            mut writer,
            ids,
        } = stream;
        let inactivity_timeout = match &handshake {
            Handshake::Client {
                inactivity_timeout, ..
            } => *inactivity_timeout,
            Handshake::Server(_) => None,
        };
        let mut reader = clear_packet::PacketReader::new(reader, inactivity_timeout);
        let (transcript, macs) = initial::negotiate_identified(
            role,
            &mut reader,
            &mut writer,
            ids,
            local_kexinit,
            &preferences,
            &algorithms,
        )
        .await?;
        let observe = matches!(
            &handshake,
            Handshake::Client {
                observe_key_exchanges: true,
                ..
            }
        );
        let unprotected = transcript.kex_algorithm == Kex::None.name();
        let (keys, host, packets_after_kexinit) = if unprotected {
            (
                ExchangeKeys::unprotected(),
                HostIdentity::Unverified(role),
                0,
            )
        } else {
            let mut exchange = MethodIo::Clear {
                reader: &mut reader,
                writer: &mut writer,
                strict: transcript.strict_kex,
                next_receive_sequence: transcript.next_receive_sequence,
            };
            let (keys, host) = match handshake {
                Handshake::Client {
                    verify_host,
                    certificate_signatures,
                    ..
                } => {
                    let ClientExchangeResult {
                        keys,
                        host: presented,
                    } = exchange
                        .client(&transcript, None, preferences.gex, certificate_signatures)
                        .await?;
                    if !verify_host(presented.clone(), transcript.host_key_algorithm.clone())
                        .await?
                    {
                        return Err(rejected_host());
                    }
                    (
                        keys,
                        HostIdentity::Client {
                            pinned: presented,
                            certificate_signatures,
                        },
                    )
                }
                Handshake::Server(host) => {
                    let signer = host
                        .select(&transcript.host_key_algorithm)
                        .ok_or_else(|| invalid("negotiated SSH host key is unavailable"))?;
                    let keys = exchange
                        .server(&transcript, None, signer, gex_group_lookup.as_ref())
                        .await?;
                    (keys, HostIdentity::Server(host))
                }
            };
            // One method packet per direction (two for GEX), followed by NEWKEYS.
            let method_packets = if gex::is_method(transcript.kex_algorithm) {
                2
            } else {
                1
            };
            let receive_newkeys = async {
                let packet = reader.read().await?;
                if packet == NEWKEYS {
                    Ok(())
                } else if packet[0] == NEWKEYS[0] {
                    Err(ProtocolError::KeyExchangeInit("invalid SSH_MSG_NEWKEYS").into())
                } else if packet[0] == 1 {
                    // The peer gave up and said why; report that reason.
                    Err(peer_disconnected(&packet))
                } else {
                    Err(unexpected_initial_message(
                        packet[0],
                        transcript.next_receive_sequence + method_packets,
                        transcript.strict_kex,
                        "expected SSH_MSG_NEWKEYS",
                    ))
                }
            };
            tokio::try_join!(clear_packet::write(&mut writer, NEWKEYS), receive_newkeys)?;
            (keys, host, method_packets + 1)
        };
        let (send, receive) = match role {
            Role::Client => (keys.client_to_server, keys.server_to_client),
            Role::Server => (keys.server_to_client, keys.client_to_server),
        };
        let (send_seq, receive_seq) = if transcript.strict_kex {
            (0, 0)
        } else {
            (
                1 + packets_after_kexinit,
                transcript.next_receive_sequence + packets_after_kexinit,
            )
        };
        let (send_suite, receive_suite) = ordered_suites(transcript.packet_algorithms, role);
        let announce_extensions = role == Role::Server && transcript.peer_accepts_ext_info;
        let (send_mode, receive_mode) = ordered_compression(transcript.compression, role);
        let completed_exchanges = observe.then(|| {
            vec![CompletedKeyExchange::new(
                &transcript,
                macs,
                transcript.next_receive_sequence == 2,
                true,
            )]
        });
        let mut send = Direction::new(send, send_suite, Side::Send, send_seq);
        let mut receive = Direction::new(receive, receive_suite, Side::Receive, receive_seq);
        if unprotected {
            // Some peers send NEWKEYS without accepting a reciprocal marker.
            // With no keys to switch, omit ours and tolerate theirs.
            send.renew_unprotected(send_suite, send_mode, false, false);
            receive.renew_unprotected(receive_suite, receive_mode, false, false);
        } else {
            send.reset_compression(send_mode, false);
            receive.reset_compression(receive_mode, false);
        }
        Ok(Self {
            reader: reader.into_inner(),
            writer,
            send,
            receive,
            session_id: keys.exchange_hash,
            transcript,
            completed_exchanges,
            preferences,
            gex_group_lookup,
            pending_kexinit: None,
            host_algorithms: algorithms,
            host,
            authenticated: false,
            authenticating: false,
            in_flight: InFlight::default(),
            extensions: Extensions::new(role),
            announce_extensions: announce_extensions.then(|| ServerAdvertisement {
                agent_forwarding: false,
                signature_algorithms: if unprotected {
                    Vec::new()
                } else {
                    SIGNATURE_ALGORITHMS.to_vec()
                },
            }),
            user_signatures: UserSignatures::default(),
            keys_started: Instant::now(),
            rekey_read_bytes: DEFAULT_REKEY_BYTES,
            rekey_write_bytes: DEFAULT_REKEY_BYTES,
            rekey_age: DEFAULT_REKEY_AGE,
            failed: false,
            activity: None,
        })
    }
}
