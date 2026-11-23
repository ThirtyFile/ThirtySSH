use std::{future::ready, io::ErrorKind, pin::pin, time::Duration};
use thirtyssh::{
    algorithms::{Cipher, DirectionPreferences, Mac, PacketAlgorithms, PacketPreferences, Suite},
    transport::{HostKey, Transport},
};
use tokio::{io, time::timeout};

#[path = "fixtures/transport_io.rs"]
mod transport_io;

#[tokio::test]
async fn client_and_server_activate_matching_keys() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        assert_eq!(client.session_id(), server.session_id());
        assert!(client.strict_kex() && server.strict_kex());
        for value in [b"\x05ssh-userauth".as_slice(), b"\x32second packet"] {
            tokio::join!(
                async {
                    client.send(value).await.unwrap();
                },
                async {
                    assert_eq!(server.receive().await.unwrap(), value);
                },
            );
            tokio::join!(
                async {
                    server.send(value).await.unwrap();
                },
                async {
                    assert_eq!(client.receive().await.unwrap(), value);
                },
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_host_key_ends_the_handshake() {
    let expected = HostKey::generate().unwrap().public_key();
    let actual = HostKey::generate().unwrap();
    let (left, right) = io::duplex(128);
    let (client, server) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            Transport::connect(left, |presented| *presented == expected),
            Transport::accept(right, &actual)
        )
    })
    .await
    .unwrap();
    assert_eq!(client.err().unwrap().kind(), ErrorKind::PermissionDenied);
    assert!(server.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_paused_transport_read_times_out_and_can_resume_at_eof() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let (left, read) = transport_io::ControlledRead::new(left);
    let (mut client, server) = timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
    })
    .await
    .unwrap()
    .unwrap();

    read.pause();
    drop(server);
    assert!(
        timeout(Duration::from_secs(1), client.receive())
            .await
            .is_err()
    );
    read.resume();
    assert_eq!(
        client.receive().await.unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
}

#[tokio::test(start_paused = true)]
async fn a_paused_transport_read_resumes_or_reports_a_reset() {
    timeout(Duration::from_secs(5), async {
        let key = HostKey::generate().unwrap();
        let (left, right) = io::duplex(4096);
        let (left, read) = transport_io::ControlledRead::new(left);
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        let payload = b"^delayed data";

        read.pause();
        server.send(payload).await.unwrap();
        {
            let mut pending = pin!(client.receive());
            tokio::select! {
                biased;
                result = &mut pending => panic!("read completed while paused: {result:?}"),
                () = ready(()) => {}
            }
            read.resume();
            assert_eq!(pending.await.unwrap(), payload);
        }

        read.pause();
        {
            let mut pending = pin!(client.receive());
            tokio::select! {
                biased;
                result = &mut pending => panic!("read completed before reset: {result:?}"),
                () = ready(()) => {}
            }
            read.reset();
            assert_eq!(
                pending.await.unwrap_err().kind(),
                ErrorKind::ConnectionReset
            );
        }
        assert_eq!(
            client.receive().await.unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_read_can_resume_and_write_on_the_same_stream() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key)
        )
        .unwrap();
        let server_out = b"\x5eserver payload";
        let client_out = b"\x5eclient payload";
        {
            let mut send = pin!(server.send(server_out));
            // Force a partial write before polling and cancelling the client read.
            tokio::select! {
                biased;
                result = &mut send => panic!("unexpected write completion: {result:?}"),
                () = ready(()) => {}
            }
            tokio::select! {
                biased;
                result = client.receive() => panic!("unexpected read completion: {result:?}"),
                () = ready(()) => {}
            }
            let ((), received) = tokio::try_join!(&mut send, client.receive()).unwrap();
            assert_eq!(received, server_out);
        }
        let ((), received) = tokio::try_join!(client.send(client_out), server.receive()).unwrap();
        assert_eq!(received, client_out);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_rekey_prevents_reuse() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(512);
    let (mut client, _server) = timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key)
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        timeout(Duration::from_millis(10), client.rekey())
            .await
            .is_err()
    );
    assert_eq!(
        client.send(b"\x05").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn simultaneous_rekey_keeps_session_id_and_resumes_both_directions() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        let session_id = client.session_id().to_vec();
        for payload in [b"\x5eafter first".as_slice(), b"\x5eafter second"] {
            tokio::try_join!(client.rekey(), server.rekey()).unwrap();
            assert_eq!(client.session_id(), &session_id);
            assert_eq!(server.session_id(), &session_id);
            let ((), received) = tokio::try_join!(client.send(payload), server.receive()).unwrap();
            assert_eq!(received, payload);
            let (received, ()) = tokio::try_join!(client.receive(), server.send(payload)).unwrap();
            assert_eq!(received, payload);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn either_peer_can_rekey_with_data_in_flight() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        for reverse in [false, true] {
            let (initiator, responder) = if reverse {
                (&mut server, &mut client)
            } else {
                (&mut client, &mut server)
            };
            let initiator = async {
                initiator.rekey().await.unwrap();
                assert_eq!(initiator.receive().await.unwrap(), b"\x5eold keys one");
                assert_eq!(initiator.receive().await.unwrap(), b"\x5eold keys two");
                initiator.send(b"\x5enew keys").await.unwrap();
            };
            let responder = async {
                responder.send(b"\x5eold keys one").await.unwrap();
                responder.send(b"\x5eold keys two").await.unwrap();
                assert_eq!(responder.receive().await.unwrap(), b"\x5enew keys");
            };
            tokio::join!(initiator, responder);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn byte_limit_triggers_rekey_during_regular_io() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        assert!(
            client
                .set_rekey_limits(4096, 0, Duration::from_secs(10))
                .is_err()
        );
        client
            .set_rekey_limits(1, 4096, Duration::from_secs(10))
            .unwrap();
        for _ in 0..4 {
            let ((), sent) =
                tokio::try_join!(client.send(b"\x5eapplication packet"), server.receive()).unwrap();
            assert_eq!(sent, b"\x5eapplication packet");
        }
        client
            .set_rekey_limits(4096, 1, Duration::from_secs(10))
            .unwrap();
        let client = async {
            for _ in 0..4 {
                assert_eq!(client.receive().await.unwrap(), b"\x5eapplication packet");
                client.send(b"\x5eacknowledged").await.unwrap();
            }
        };
        let server = async {
            for _ in 0..4 {
                server.send(b"\x5eapplication packet").await.unwrap();
                assert_eq!(server.receive().await.unwrap(), b"\x5eacknowledged");
            }
        };
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn distinct_directional_suites_protect_data_across_rekey() {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    let preferences = PacketPreferences {
        client_to_server: DirectionPreferences {
            ciphers: vec![Cipher::Aes192Ctr],
            macs: vec![Mac::HmacSha512Etm],
        },
        server_to_client: DirectionPreferences {
            ciphers: vec![Cipher::Aes128Gcm],
            macs: vec![],
        },
    };
    let expected = PacketAlgorithms {
        client_to_server: Suite {
            cipher: Cipher::Aes192Ctr,
            mac: Some(Mac::HmacSha512Etm),
        },
        server_to_client: Suite {
            cipher: Cipher::Aes128Gcm,
            mac: None,
        },
    };
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect_with_packet_preferences(
                left,
                |key| *key == host.public_key(),
                preferences
            ),
            Transport::accept(right, &host),
        )
        .unwrap();
        for _ in 0..3 {
            assert_eq!(client.packet_algorithms(), expected);
            assert_eq!(server.packet_algorithms(), expected);
            let ((), packet) =
                tokio::try_join!(client.send(b"\x5eclient data"), server.receive()).unwrap();
            assert_eq!(packet, b"\x5eclient data");
            let (packet, ()) =
                tokio::try_join!(client.receive(), server.send(b"\x5eserver data")).unwrap();
            assert_eq!(packet, b"\x5eserver data");
            tokio::try_join!(client.rekey(), server.rekey()).unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsupported_direction_fails_before_host_verification() {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let mut client = PacketPreferences::default();
    let mut server = PacketPreferences::default();
    client.server_to_client.ciphers = vec![Cipher::Aes128Gcm];
    server.server_to_client.ciphers = vec![Cipher::Aes128Ctr];
    let (local, remote) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            Transport::connect_with_packet_preferences(
                left,
                |_| panic!("unexpected host verification"),
                client
            ),
            Transport::accept_with_packet_preferences(right, &host, server),
        )
    })
    .await
    .unwrap();
    assert_eq!(local.err().unwrap().kind(), ErrorKind::InvalidData);
    assert_eq!(remote.err().unwrap().kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn a_disconnect_in_place_of_kexinit_reports_the_peers_reason() {
    use thirtyssh::{clear_packet, transport::PeerDisconnect};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(Duration::from_secs(5), async {
        let (left, mut right) = io::duplex(4096);
        let peer = async {
            right.write_all(b"SSH-2.0-fixture\r\n").await.unwrap();
            // SSH_MSG_DISCONNECT, reason 2, "busy", no language tag.
            clear_packet::write(&mut right, b"\x01\0\0\0\x02\0\0\0\x04busy\0\0\0\0")
                .await
                .unwrap();
            let mut rest = Vec::new();
            let _ = right.read_to_end(&mut rest).await;
        };
        let (result, ()) = tokio::join!(Transport::connect(left, |_| true), peer);
        let error = result.err().unwrap();
        let disconnect = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<PeerDisconnect>())
            .expect("the peer's disconnect");
        assert_eq!(disconnect.reason, 2);
        assert_eq!(disconnect.description, b"busy");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_oversized_payload_is_refused_without_breaking_the_transport() {
    let key = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect(left, |presented| *presented == key.public_key()),
            Transport::accept(right, &key),
        )
        .unwrap();
        let oversized = vec![0x5e; 300 * 1024];
        assert_eq!(
            client.send(&oversized).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        let ((), received) =
            tokio::try_join!(client.send(b"\x5estill usable"), server.receive()).unwrap();
        assert_eq!(received, b"\x5estill usable");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_packet_injected_into_a_strict_key_exchange_ends_it() {
    use thirtyssh::{clear_packet, protocol_error::ProtocolError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = HostKey::generate().unwrap();
    timeout(Duration::from_secs(5), async {
        let (client_stream, relay_client) = io::duplex(4096);
        let (relay_server, server_stream) = io::duplex(4096);
        // Something on the path that cannot read the keys but can add a
        // packet of its own before they take effect, as the Terrapin attack
        // does to shift sequence numbers.
        let relay = async {
            let (mut from_client, mut to_client) = io::split(relay_client);
            let (mut from_server, mut to_server) = io::split(relay_server);
            let upstream = async {
                let mut byte = [0];
                while byte[0] != b'\n' {
                    from_client.read_exact(&mut byte).await?;
                    to_server.write_all(&byte).await?;
                }
                let kexinit = clear_packet::read(&mut from_client).await?;
                assert_eq!(kexinit[0], 20);
                clear_packet::write(&mut to_server, &kexinit).await?;
                // SSH_MSG_IGNORE with an empty string.
                clear_packet::write(&mut to_server, b"\x02\0\0\0\0").await?;
                io::copy(&mut from_client, &mut to_server).await
            };
            tokio::select! {
                _ = upstream => {}
                _ = io::copy(&mut from_server, &mut to_client) => {}
            }
        };
        let (client, server, ()) = tokio::join!(
            Transport::connect(client_stream, |presented| *presented == key.public_key()),
            Transport::accept(server_stream, &key),
            relay,
        );
        assert!(client.is_err());
        let error = server.err().unwrap();
        assert!(
            matches!(
                error.downcast::<ProtocolError>().unwrap(),
                ProtocolError::StrictKeyExchange {
                    message_type: 2,
                    ..
                }
            ),
            "the injected packet must be what ends the exchange"
        );
    })
    .await
    .unwrap();
}
