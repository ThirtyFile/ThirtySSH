use super::*;
use crate::algorithms::Kex;

#[test]
fn rekey_queue_holds_the_default_window_budget() {
    // Every window the default budget allows, filled with full-size data
    // packets, must fit while the peer has not yet answered our KEXINIT.
    let mut queue = InFlight::default();
    let packet = vec![0u8; 32 * 1024];
    for _ in 0..crate::channel::DEFAULT_WINDOW_BUDGET as usize / packet.len() {
        assert!(queue.has_packet_space());
        queue.push(packet.clone()).unwrap();
    }
    // A peer that ignores every window still hits a hard bound.
    let mut queue = InFlight::default();
    let result =
        (0..=MAX_IN_FLIGHT_BYTES / packet.len()).try_for_each(|_| queue.push(packet.clone()));
    assert!(result.is_err());
    assert!(queue.bytes <= MAX_IN_FLIGHT_BYTES);
}

#[tokio::test]
async fn disconnect_half_closes_writes_before_dropping_the_read_side() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let (left, right) = stream::duplex(512);
        let (client, mut peer) = tokio::try_join!(
            Transport::connect(left, |key| *key == host.public_key()),
            Transport::accept(right, &host),
        )
        .unwrap();
        let mut closing = Box::pin(client.disconnect());
        for expected in [Ok(disconnect_packet(11, "", "").unwrap()), Err(ErrorKind::UnexpectedEof)] {
            let observed = tokio::select! {
                biased;
                _ = &mut closing => panic!("transport dropped before its peer could observe the half-close"),
                result = peer.receive() => result.map_err(|error| error.kind()),
            };
            assert_eq!(observed, expected);
        }
        drop(peer);
        closing.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_deferred_peer_rekey_allows_old_key_writes_until_the_callback_finishes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let pin = host.public_key();
        let gate = Arc::new(Mutex::new(()));
        let lookup = gex::GexGroupLookup::new(|request| ready(Ok(gex::GexGroup::builtin(request))))
            .serialize_rekey_with(gate.clone());
        let preferences = TransportPreferences {
            kex: vec![Kex::DhGexSha256, Kex::StrictClient, Kex::StrictServer],
            ..Default::default()
        };
        let (left, right) = stream::duplex(8192);
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect_with_preferences(left, |key| *key == pin, preferences.clone()),
            Transport::accept_with_gex_lookup(
                right,
                host.into(),
                preferences,
                &[Algorithm::Ed25519],
                Some(lookup)
            ),
        )
        .unwrap();
        client.begin_connection_without_userauth();
        server.begin_connection_without_userauth();
        let callback = gate.lock().await;
        let server = async {
            let input = server.read_input().await.unwrap();
            assert!(matches!(&input, Input::Packet(packet) if packet[0] == KEXINIT));
            assert!(server.handle_input(input).await.unwrap().is_none());
            assert!(server.pending_kexinit.is_some());
            server.send(b"\x5edata from the callback").await.unwrap();
            assert!(server.pending_kexinit.is_some());
            drop(callback);
            let input = server.read_input().await.unwrap();
            assert!(matches!(&input, Input::Rekey(Some(_))));
            assert!(server.handle_input(input).await.unwrap().is_none());
            assert!(server.pending_kexinit.is_none());
        };
        let client = async {
            client.rekey().await.unwrap();
            assert_eq!(
                client.receive().await.unwrap(),
                b"\x5edata from the callback"
            );
        };
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn changing_kex_hash_size_on_rekey_preserves_the_first_session_id() {
    let host = HostKey::generate().unwrap();
    let (left, right) = stream::duplex(512);
    tokio::time::timeout(Duration::from_secs(5), async {
        let preferences = TransportPreferences {
            kex: vec![Kex::EcdhNistP521, Kex::StrictClient, Kex::StrictServer],
            ..Default::default()
        };
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect_with_preferences(
                left,
                |key| *key == host.public_key(),
                preferences.clone(),
            ),
            Transport::accept_with_preferences(right, &host, preferences),
        )
        .unwrap();
        assert_eq!(client.key_exchange_algorithm(), Kex::EcdhNistP521.name());
        assert!(client.strict_kex() && server.strict_kex());
        let original_id = client.session_id().to_vec();
        assert_eq!(original_id.len(), 64);
        assert_eq!(server.session_id(), original_id);

        for method in [
            Kex::EcdhNistP384,
            Kex::MlKem768X25519Sha256,
            Kex::DhGexSha1,
            Kex::DhGroup1Sha1,
            Kex::DhGroup14Sha1,
            Kex::Curve25519,
        ] {
            client.preferences.kex = vec![method];
            server.preferences.kex = vec![method];
            tokio::try_join!(client.rekey(), server.rekey()).unwrap();
            assert_eq!(client.key_exchange_algorithm(), method.name());
            assert_eq!(server.key_exchange_algorithm(), method.name());
            assert_eq!(client.session_id(), original_id);
            assert_eq!(server.session_id(), original_id);
            client.send(b"\x5eafter rekey").await.unwrap();
            assert_eq!(server.receive().await.unwrap(), b"\x5eafter rekey");
            server.send(b"\x5eacknowledgment").await.unwrap();
            assert_eq!(client.receive().await.unwrap(), b"\x5eacknowledgment");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_authenticated_connection_cannot_rekey_into_kex_none() {
    use crate::algorithms::{Cipher, DirectionPreferences, Mac};

    tokio::time::timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let (left, right) = stream::duplex(256);
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |key_bytes| *key_bytes == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        let direction = DirectionPreferences {
            ciphers: vec![Cipher::Clear],
            macs: vec![Mac::None],
        };
        let rekey = TransportPreferences {
            kex: vec![Kex::None],
            packet: PacketPreferences {
                client_to_server: direction.clone(),
                server_to_client: direction,
            },
            ..Default::default()
        };
        client.preferences = rekey.clone();
        server.preferences = rekey;
        let (client_rekey, server_rekey) = tokio::join!(client.rekey(), server.rekey());
        for result in [client_rekey, server_rekey] {
            let error = result.unwrap_err();
            assert_eq!(
                error.to_string(),
                "SSH rekey cannot drop host authentication"
            );
        }
        assert!(client.is_failed() && server.is_failed());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn elapsed_time_triggers_rekey_before_reading_application_data() {
    let host = HostKey::generate().unwrap();
    let (left, right) = stream::duplex(512);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |key| *key == host.public_key()),
            Transport::accept(right, &host),
        )
        .unwrap();
        client
            .set_rekey_limits(
                DEFAULT_REKEY_BYTES,
                DEFAULT_REKEY_BYTES,
                Duration::from_secs(1),
            )
            .unwrap();
        client.keys_started -= Duration::from_secs(2);
        let expired = client.keys_started;
        let peer = async {
            server.send(b"\x5ebefore rekey").await.unwrap();
            assert_eq!(server.receive().await.unwrap(), b"\x5eafter rekey");
        };
        let local = async {
            assert_eq!(client.receive().await.unwrap(), b"\x5ebefore rekey");
            assert!(client.keys_started > expired);
            assert_eq!(client.receive.sequence, 0);
            client.send(b"\x5eafter rekey").await.unwrap();
        };
        tokio::join!(local, peer);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rekey_rejects_a_changed_host_key_and_invalidates_the_stream() {
    let host = HostKey::generate().unwrap();
    let (left, right) = stream::duplex(512);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |key| *key == host.public_key()),
            Transport::accept(right, &host),
        )
        .unwrap();
        server.host = HostIdentity::Server(HostKey::generate().unwrap().into());
        let error = tokio::try_join!(client.rekey(), server.rekey()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            client
                .send(b"\x5eapplication packet")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn typed_host_verifier_only_runs_after_valid_proof() {
    let host = HostKey::generate().unwrap();
    let (left, right) = stream::duplex(512);
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = async {
            let (read, mut write) = stream::split(right);
            let mut read = BufReader::new(read);
            let transcript = initial::negotiate(Role::Server, &mut read, &mut write)
                .await
                .unwrap();
            let init = clear_packet::read(&mut read).await.unwrap();
            let host = HostKeys::from(host);
            let signer = host.select(&Algorithm::Ed25519).unwrap();
            let (_, mut reply) = kex::server_reply(&init, &transcript, signer, None, None).unwrap();
            *reply.last_mut().unwrap() ^= 1;
            clear_packet::write(&mut write, &reply).await.unwrap();
        };
        let client = Transport::connect_with_host_key_verifier(
            left,
            |_| async { panic!("trust policy must not see an invalid host proof") },
            TransportPreferences::default(),
            &SIGNATURE_ALGORITHMS,
        );
        let (result, ()) = tokio::join!(client, peer);
        let error = result.err().expect("expected a host proof error");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid SSH host signature");
        assert!(matches!(
            error.downcast::<ProtocolError>(),
            Ok(ProtocolError::HostSignature)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_needs_an_available_signer_for_configured_algorithms() {
    let (stream, _peer) = stream::duplex(1);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        Transport::accept_with_host_keys(
            stream,
            HostKey::generate().unwrap().into(),
            TransportPreferences::default(),
            &[Algorithm::Rsa {
                hash: Some(crate::keys::HashAlg::Sha512),
            }],
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.err().unwrap().kind(), ErrorKind::InvalidInput);
}

fn assert_key_exchange_failed(packet: &[u8]) {
    assert_eq!(packet[0], 1);
    let error = peer_disconnected(packet);
    let disconnect = error
        .get_ref()
        .unwrap()
        .downcast_ref::<PeerDisconnect>()
        .unwrap();
    assert_eq!(disconnect.reason, KEY_EXCHANGE_FAILED);
}

fn change_hybrid_reply(reply: &[u8], change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let [host, field, signature] = kex::decode(reply, Some(KEX_METHOD_REPLY)).unwrap();
    assert_eq!(field.len(), 1120);
    let mut field = field.to_vec();
    change(&mut field);
    kex::fields(Some(KEX_METHOD_REPLY), &[host, &field, signature]).unwrap()
}

type InvalidHybridField = (fn(&mut Vec<u8>), &'static str);

#[tokio::test]
async fn rejected_hybrid_initial_replies_send_key_exchange_failed_before_host_trust() {
    let cases: [InvalidHybridField; 4] = [
        (
            |field| field.truncate(1119),
            "invalid SSH hybrid reply length",
        ),
        (|field| field.push(0), "invalid SSH hybrid reply length"),
        (|field| field[0] ^= 1, "invalid SSH host signature"),
        (
            |field| field[1088..].fill(0),
            "invalid X25519 peer public key",
        ),
    ];
    tokio::time::timeout(Duration::from_secs(5), async {
        for (tamper, expected) in cases {
            let host = HostKeys::from(HostKey::generate().unwrap());
            let signer = host.select(&Algorithm::Ed25519).unwrap();
            let (left, right) = stream::duplex(512);
            let peer = async {
                let (read, mut write) = stream::split(right);
                let mut read = BufReader::new(read);
                let transcript = initial::negotiate(Role::Server, &mut read, &mut write)
                    .await
                    .unwrap();
                assert_eq!(transcript.kex_algorithm, Kex::MlKem768X25519Sha256.name());
                let init = clear_packet::read(&mut read).await.unwrap();
                let (_, valid) = kex::server_reply(&init, &transcript, signer, None, None).unwrap();
                let wrong = change_hybrid_reply(&valid, tamper);
                clear_packet::write(&mut write, &wrong).await.unwrap();
                assert_key_exchange_failed(&clear_packet::read(&mut read).await.unwrap());
            };
            let client = Transport::connect(left, |_| panic!("unexpected host trust callback"));
            let (result, ()) = tokio::join!(client, peer);
            let error = result.err().unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(error.to_string(), expected);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_hybrid_initial_keys_send_key_exchange_failed() {
    let cases: [InvalidHybridField; 4] = [
        (
            |field| field.truncate(1215),
            "invalid SSH hybrid init length",
        ),
        (|field| field.push(0), "invalid SSH hybrid init length"),
        // The first encoded 12-bit polynomial coefficient is 4095 > 3328.
        (
            |field| {
                field[0] = 0xff;
                field[1] |= 0x0f;
            },
            "invalid SSH ML-KEM encapsulation key",
        ),
        (
            |field| field[1184..].fill(0),
            "invalid X25519 peer public key",
        ),
    ];
    let host = HostKey::generate().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        for (tamper, expected) in cases {
            let (left, right) = stream::duplex(512);
            let peer = async {
                let (read, mut write) = stream::split(left);
                let mut read = BufReader::new(read);
                let transcript = initial::negotiate(Role::Client, &mut read, &mut write)
                    .await
                    .unwrap();
                assert_eq!(transcript.kex_algorithm, Kex::MlKem768X25519Sha256.name());
                let (_, init) = ClientExchange::start(transcript.kex_algorithm).unwrap();
                let [field] = kex::decode(&init, Some(KEX_METHOD_INIT)).unwrap();
                let mut field = field.to_vec();
                tamper(&mut field);
                let invalid = kex::fields(Some(KEX_METHOD_INIT), &[&field]).unwrap();
                clear_packet::write(&mut write, &invalid).await.unwrap();
                assert_key_exchange_failed(&clear_packet::read(&mut read).await.unwrap());
            };
            let (result, ()) = tokio::join!(Transport::accept(right, &host), peer);
            let error = result.err().unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(error.to_string(), expected);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn corrupted_hybrid_ciphertext_during_rekey_invalidates_the_transport() {
    let key = HostKey::generate().unwrap();
    let preferences = TransportPreferences {
        kex: vec![
            Kex::MlKem768X25519Sha256,
            Kex::StrictClient,
            Kex::StrictServer,
        ],
        ..Default::default()
    };
    let (left, right) = stream::duplex(512);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect_with_preferences(
                left,
                |key_bytes| *key_bytes == key.public_key(),
                preferences.clone()
            ),
            Transport::accept_with_preferences(right, &key, preferences)
        )
        .unwrap();
        assert_eq!(
            client.key_exchange_algorithm(),
            Kex::MlKem768X25519Sha256.name()
        );
        let forged = async {
            let local = initial::local_proposal(
                Role::Server,
                false,
                &server.preferences,
                &server.host_algorithms,
            )
            .unwrap();
            let ((), remote) = tokio::try_join!(
                server.send.write(&mut server.writer, &local),
                server.receive.read(&mut server.reader),
            )
            .unwrap();
            assert_eq!(remote[0], KEXINIT);
            server.transcript.server.kexinit = local;
            server.transcript.client.kexinit = remote;
            let init = server.receive.read(&mut server.reader).await.unwrap();
            let host = HostKeys::from(key);
            let signer = host.select(&Algorithm::Ed25519).unwrap();
            let (_, reply) = kex::server_reply(
                &init,
                &server.transcript,
                signer,
                Some(server.session_id()),
                None,
            )
            .unwrap();
            let wrong = change_hybrid_reply(&reply, |field| field[0] ^= 1);
            server.send.write(&mut server.writer, &wrong).await.unwrap();
            assert_key_exchange_failed(&server.receive.read(&mut server.reader).await.unwrap());
        };
        let (result, ()) = tokio::join!(client.rekey(), forged);
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid SSH host signature"
        );
        assert_eq!(
            client
                .send(b"\x5eunusable transport")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    })
    .await
    .unwrap();
}
