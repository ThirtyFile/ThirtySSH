use std::{io::ErrorKind, time::Duration};
use thirtyssh::{
    auth::{self, Authenticated, Policy},
    channel::{
        Bytes, Channel, ChannelId, Connection, Event, GlobalReply, GlobalRequest, MAX_DATA,
        driver::Handle,
    },
    transport::{HostKey, Transport},
};
use tokio::{
    io::{self, DuplexStream},
    time::timeout,
};

struct AllowPassword;
impl Policy for AllowPassword {
    fn password(&mut self, user: &str, password: &[u8]) -> bool {
        user == "fixture" && password == b"fixture-password"
    }
}

async fn pair() -> (Authenticated<DuplexStream>, Authenticated<DuplexStream>) {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(4096);
    let client = async {
        let transport = Transport::connect(left, |key| *key == host.public_key())
            .await
            .unwrap();
        auth::login(
            transport,
            "fixture",
            auth::Method::Password("fixture-password"),
        )
        .await
        .unwrap()
    };
    let server = async {
        let transport = Transport::accept(right, &host).await.unwrap();
        auth::accept(transport, AllowPassword).await.unwrap()
    };
    tokio::join!(client, server)
}

async fn incoming(connection: &mut Connection<DuplexStream>, kind: &[u8]) -> ChannelId {
    let Event::Incoming {
        channel,
        kind: actual,
        fields,
    } = connection.next_event().await.unwrap()
    else {
        panic!("expected incoming channel")
    };
    assert_eq!(actual, kind);
    assert_eq!(fields, b"open fields");
    channel
}

async fn global(
    connection: &mut Connection<DuplexStream>,
    name: &str,
    fields: &[u8],
) -> GlobalRequest {
    let Event::GlobalRequest(request) = connection.next_event().await.unwrap() else {
        panic!("expected global request {name}");
    };
    assert_eq!(request.name, name.as_bytes());
    assert_eq!(request.fields, fields);
    request
}

#[tokio::test]
async fn global_replies_stay_ordered_across_driver_start_and_cancelled_waiters() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let mut client = Connection::new(client);
        client.enable_global_requests();
        client
            .global_request("before-driver", true, b"first")
            .await
            .unwrap();
        let (driver, handle, mut events) = client.into_driver();
        let running = tokio::spawn(driver.run());
        let mut server = Connection::new(server);
        server.enable_global_requests();
        let first = global(&mut server, "before-driver", b"first")
            .await
            .reply_id
            .unwrap();
        let cancelled = tokio::spawn({
            let handle = handle.clone();
            async move { handle.global_request("cancel-waiter", b"second").await }
        });
        let second = global(&mut server, "cancel-waiter", b"second")
            .await
            .reply_id
            .unwrap();
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());

        handle
            .global_notification("notice", b"no reply")
            .await
            .unwrap();
        assert!(
            !global(&mut server, "notice", b"no reply")
                .await
                .wants_reply()
        );
        let waiting = tokio::spawn({
            let handle = handle.clone();
            async move { handle.global_request("keep-waiter", b"third").await }
        });
        let third = global(&mut server, "keep-waiter", b"third")
            .await
            .reply_id
            .unwrap();
        assert_eq!(
            server
                .global_reply(third, GlobalReply::Failure)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        server
            .global_reply(first, GlobalReply::Failure)
            .await
            .unwrap();
        server
            .global_reply(
                second,
                GlobalReply::Success(Bytes::from_static(b"abandoned")),
            )
            .await
            .unwrap();
        // Fill the event queue before sending a reply. The waiting application
        // doesn't resume consuming events until its request has completed.
        for index in 0..40 {
            server
                .global_request("before-reply", false, &[index])
                .await
                .unwrap();
        }
        let expected = GlobalReply::Success(Bytes::from_static(b"third response\0\xff"));
        server.global_reply(third, expected.clone()).await.unwrap();
        assert_eq!(waiting.await.unwrap().unwrap(), expected);
        assert_eq!(
            events.recv().await,
            Some(Event::GlobalReply(GlobalReply::Failure))
        );
        for index in 0..40 {
            let Some(Event::GlobalRequest(request)) = events.recv().await else {
                panic!("expected queued notification");
            };
            assert_eq!(request.name, b"before-reply".as_slice());
            assert_eq!(request.fields, &[index][..]);
            assert!(!request.wants_reply());
        }
        assert!(events.try_recv().is_err());
        handle.disconnect().await.unwrap();
        running.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn keepalive_replies_share_the_global_fifo_without_reaching_application_callbacks() {
    timeout(Duration::from_secs(5), async {
        let (left, right) = pair().await;
        let (driver, handle, mut events) = Connection::new(left).into_driver();
        let running = tokio::spawn(driver.run());
        let mut peer = Connection::new(right);
        peer.enable_global_requests();
        let ask_first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.global_request("first@example.test", b"first").await }
        });
        let first = global(&mut peer, "first@example.test", b"first").await.reply_id.unwrap();
        handle.keepalive(false).await.unwrap();
        handle.keepalive(true).await.unwrap();
        let ask_last = tokio::spawn({
            let handle = handle.clone();
            async move { handle.global_request("last@example.test", b"last").await }
        });
        let last = global(&mut peer, "last@example.test", b"last").await.reply_id.unwrap();
        peer.global_reply(first, GlobalReply::Failure).await.unwrap();
        let expected = GlobalReply::Success(Bytes::from_static(b"last response"));
        peer.global_reply(last, expected.clone()).await.unwrap();
        assert_eq!(ask_first.await.unwrap().unwrap(), GlobalReply::Failure);
        assert_eq!(ask_last.await.unwrap().unwrap(), expected);
        assert!(events.try_recv().is_err());
        tokio::select! {
            result = handle.ping() => result.unwrap(),
            event = peer.next_event() => panic!("keepalive should stay at the connection layer: {event:?}"),
        }
        handle.disconnect().await.unwrap();
        running.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn channel_keepalive_replies_follow_pending_application_replies() {
    timeout(Duration::from_secs(5), async {
        let (left, right) = pair().await;
        let mut left = Connection::new(left);
        let mut right = Connection::new(right);
        let channel = left.open("fixture", 1024, b"open fields").await.unwrap();
        let peer = incoming(&mut right, b"fixture").await;
        right.accept(peer, 1024, &[]).await.unwrap();
        assert!(matches!(left.next_event().await.unwrap(), Event::Opened { .. }));
        left.request(channel, "custom@example.test", true, b"choose first reply").await.unwrap();
        left.request(channel, "keepalive@openssh.com", false, &[]).await.unwrap();
        left.request(channel, "keepalive@openssh.com", true, &[]).await.unwrap();
        left.request(channel, "after@example.test", true, b"choose last reply").await.unwrap();
        for expected in [b"custom@example.test".as_slice(), b"after@example.test".as_slice()] {
            assert!(matches!(right.next_event().await.unwrap(), Event::Request { name, want_reply: true, .. } if name == expected));
        }
        assert!(timeout(Duration::from_millis(30), left.next_event()).await.is_err());
        right.reply(peer, false).await.unwrap();
        right.reply(peer, false).await.unwrap();
        for success in [false, true, false] {
            assert_eq!(left.next_event().await.unwrap(), Event::Reply { channel, success });
        }
        left.request(channel, "keepalive@openssh.com", true, &[]).await.unwrap();
        left.eof(channel).await.unwrap();
        assert_eq!(right.next_event().await.unwrap(), Event::Eof(peer));
        assert_eq!(left.next_event().await.unwrap(), Event::Reply { channel, success: true });
    }).await.unwrap();
}

#[tokio::test]
async fn independent_windows_requests_half_close_and_crossed_close() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let mut client = Connection::new(client);
        let mut server = Connection::new(server);
        let first = client.open("fixture", 3, b"open fields").await.unwrap();
        let second = client.open("fixture", 8, b"open fields").await.unwrap();
        let peer_first = incoming(&mut server, b"fixture").await;
        let peer_second = incoming(&mut server, b"fixture").await;
        server.accept(peer_second, 8, b"confirm").await.unwrap();
        server.accept(peer_first, 0, b"").await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Opened {
                channel: second,
                fields: b"confirm".to_vec()
            }
        );
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Opened {
                channel: first,
                fields: vec![]
            }
        );
        assert_eq!(client.send_data(first, None, b"stdin").await.unwrap(), 0);
        assert_eq!(client.send_data(second, None, b"other").await.unwrap(), 5);
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Data {
                channel: peer_second,
                extended: None,
                data: b"other".to_vec()
            }
        );
        assert_eq!(
            server.consume(peer_second, 6).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        client.request(first, "first", true, b"1").await.unwrap();
        client.request(second, "second", true, b"2").await.unwrap();
        for (channel, name, fields) in [
            (peer_first, b"first".as_slice(), b'1'),
            (peer_second, b"second".as_slice(), b'2'),
        ] {
            assert_eq!(
                server.next_event().await.unwrap(),
                Event::Request {
                    channel,
                    name: name.to_vec(),
                    want_reply: true,
                    fields: vec![fields]
                }
            );
        }
        server.reply(peer_second, false).await.unwrap();
        server.grant(peer_first, 2).await.unwrap();
        assert_eq!(
            server.grant(peer_first, u32::MAX).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        server.reply(peer_first, true).await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Reply {
                channel: second,
                success: false
            }
        );
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: first,
                remaining: 2
            }
        );
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Reply {
                channel: first,
                success: true
            }
        );

        assert_eq!(client.send_data(first, None, b"stdin").await.unwrap(), 2);
        assert_eq!(client.send_data(first, None, b"din").await.unwrap(), 0);
        client.eof(first).await.unwrap();
        assert_eq!(
            client.send_data(first, None, b"").await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Data {
                channel: peer_first,
                extended: None,
                data: b"st".to_vec()
            }
        );
        assert_eq!(server.next_event().await.unwrap(), Event::Eof(peer_first));
        assert_eq!(
            server
                .send_data(peer_first, Some(1), b"errmore")
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            server.send_data(peer_first, None, b"more").await.unwrap(),
            0
        );
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Data {
                channel: first,
                extended: Some(1),
                data: b"err".to_vec()
            }
        );
        client.consume(first, 3).await.unwrap();
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: peer_first,
                remaining: 3
            }
        );
        client.close(first).await.unwrap();
        server.close(peer_first).await.unwrap();
        assert_eq!(client.next_event().await.unwrap(), Event::Closed(first));
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Closed(peer_first)
        );
        assert_eq!(client.send_data(second, None, b"yes").await.unwrap(), 3);
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Data {
                channel: peer_second,
                extended: None,
                data: b"yes".to_vec()
            }
        );
        server.close(peer_second).await.unwrap();
        assert_eq!(client.next_event().await.unwrap(), Event::Closed(second));
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Closed(peer_second)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_drains_late_confirmation_and_releases_capacity() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let mut client = Connection::new(client);
        let mut server = Connection::new(server);
        let cancelled = client.open("fixture", 4, b"open fields").await.unwrap();
        let late_refusal = client.open("fixture", 0, b"open fields").await.unwrap();
        let survivor = client.open("fixture", 0, b"open fields").await.unwrap();
        client.cancel_open(cancelled).unwrap();
        client.cancel_open(late_refusal).unwrap();
        let late = incoming(&mut server, b"fixture").await;
        let refused = incoming(&mut server, b"fixture").await;
        let other = incoming(&mut server, b"fixture").await;
        server.accept(late, 0, &[]).await.unwrap();
        assert_eq!(server.send_data(late, None, b"late").await.unwrap(), 4);
        server.refuse(refused, 1).await.unwrap();
        server.accept(other, 0, &[]).await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap(),
            Event::Opened {
                channel: survivor,
                fields: vec![]
            }
        );
        assert_eq!(server.next_event().await.unwrap(), Event::Closed(late));
        assert_eq!(client.next_event().await.unwrap(), Event::Closed(cancelled));
        assert!(client.cancel_open(late_refusal).is_err());

        for _ in 0..127 {
            client.open("fixture", 0, b"open fields").await.unwrap();
            incoming(&mut server, b"fixture").await;
        }
        assert!(client.open("fixture", 0, &[]).await.is_err());
        client.close(survivor).await.unwrap();
        assert_eq!(server.next_event().await.unwrap(), Event::Closed(other));
        assert_eq!(client.next_event().await.unwrap(), Event::Closed(survivor));
        assert_ne!(client.open("fixture", 0, &[]).await.unwrap(), survivor);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn data_packets_are_bounded_even_when_window_is_larger() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let mut client = Connection::new(client);
        let mut server = Connection::new(server);
        let channel = client.open("fixture", 0, b"open fields").await.unwrap();
        let peer = incoming(&mut server, b"fixture").await;
        server.accept(peer, 2 * MAX_DATA, &[]).await.unwrap();
        assert!(matches!(
            client.next_event().await.unwrap(),
            Event::Opened { .. }
        ));
        let data = vec![1; MAX_DATA as usize + 1];
        let (written, received) = tokio::join!(
            client.send_data(channel, Some(1), &data),
            server.next_event()
        );
        assert_eq!(written.unwrap(), MAX_DATA as usize);
        assert_eq!(
            received.unwrap(),
            Event::Data {
                channel: peer,
                extended: Some(1),
                data: data[..MAX_DATA as usize].to_vec()
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn large_crossed_writes_and_rekey_keep_the_same_channel() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let mut client = Connection::new(client);
        let mut server = Connection::new(server);
        let channel = client
            .open("fixture", 3 * MAX_DATA, b"open fields")
            .await
            .unwrap();
        let peer = incoming(&mut server, b"fixture").await;
        server.accept(peer, 3 * MAX_DATA, &[]).await.unwrap();
        assert!(matches!(
            client.next_event().await.unwrap(),
            Event::Opened { .. }
        ));

        let left = vec![1; MAX_DATA as usize];
        let right = vec![2; MAX_DATA as usize];
        let left_task = async {
            assert_eq!(
                client.send_data(channel, None, &left).await.unwrap(),
                left.len()
            );
            client.next_event().await.unwrap()
        };
        let right_task = async {
            assert_eq!(
                server.send_data(peer, Some(1), &right).await.unwrap(),
                right.len()
            );
            server.next_event().await.unwrap()
        };
        let (client_event, server_event) = tokio::join!(left_task, right_task);
        assert_eq!(
            server_event,
            Event::Data {
                channel: peer,
                extended: None,
                data: left.clone()
            }
        );
        assert_eq!(
            client_event,
            Event::Data {
                channel,
                extended: Some(1),
                data: right
            }
        );

        let left_task = async {
            assert_eq!(
                client.send_data(channel, None, &left).await.unwrap(),
                left.len()
            );
            client.next_event().await.unwrap()
        };
        let right_task = async {
            server.rekey().await.unwrap();
            let Event::Data {
                channel,
                extended: None,
                data,
            } = server.next_event().await.unwrap()
            else {
                panic!("expected in-flight data")
            };
            assert_eq!(channel, peer);
            assert_eq!(data, left);
            assert_eq!(server.send_data(peer, None, b"new key").await.unwrap(), 7);
        };
        let (event, ()) = tokio::join!(left_task, right_task);
        assert_eq!(
            event,
            Event::Data {
                channel,
                extended: None,
                data: b"new key".to_vec()
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn background_driver_progresses_after_a_cancelled_event_wait_and_crossed_writes() {
    use std::future::ready;

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (client_driver, client, mut client_events) = Connection::new(client).into_driver();
        let (server_driver, server, mut server_events) = Connection::new(server).into_driver();
        let client_task = tokio::spawn(client_driver.run());
        let server_task = tokio::spawn(server_driver.run());
        tokio::select! {
            biased;
            event = client_events.recv() => panic!("unexpected early event: {event:?}"),
            () = ready(()) => {}
        }
        let channel = client
            .open("fixture", MAX_DATA, b"open fields")
            .await
            .unwrap();
        let Some(Event::Incoming { channel: peer, .. }) = server_events.recv().await else {
            panic!("expected incoming channel");
        };
        server.accept(peer, MAX_DATA, &[]).await.unwrap();
        assert_eq!(
            client_events.recv().await.unwrap(),
            Event::Opened {
                channel,
                fields: vec![]
            }
        );

        let left = vec![1; MAX_DATA as usize];
        let right = vec![2; MAX_DATA as usize];
        let writer = client.clone();
        let (written, written_reply) = tokio::try_join!(
            writer.send_data(channel, None, &left),
            server.send_data(peer, Some(1), &right),
        )
        .unwrap();
        assert_eq!(written, left.len());
        assert_eq!(written_reply, right.len());
        assert_eq!(
            server_events.recv().await.unwrap(),
            Event::Data {
                channel: peer,
                extended: None,
                data: left
            }
        );
        assert_eq!(
            client_events.recv().await.unwrap(),
            Event::Data {
                channel,
                extended: Some(1),
                data: right
            }
        );
        client.rekey().await.unwrap();
        drop(writer);
        drop(client);
        client_task.await.unwrap().unwrap();
        assert_eq!(
            server_task.await.unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            server.close(peer).await.unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn driver_reclaims_an_open_if_its_id_was_never_returned() {
    use std::{future::ready, pin::pin};

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, mut events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut server = Connection::new(server);
        let unclaimed = {
            let mut opening = pin!(client.open("fixture", 0, b"open fields"));
            tokio::select! {
                biased;
                result = &mut opening => panic!("unexpected early ID: {result:?}"),
                () = ready(()) => {}
            }
            // The open went out, but its future has never returned an ID.
            incoming(&mut server, b"fixture").await
        };
        server.accept(unclaimed, 0, &[]).await.unwrap();
        assert_eq!(server.next_event().await.unwrap(), Event::Closed(unclaimed));
        loop {
            match events.recv().await.unwrap() {
                Event::Opened { .. } => {}
                Event::Closed(_) => break,
                event => panic!("unexpected event: {event:?}"),
            }
        }
        drop(events);
        task.await.unwrap().unwrap();
        assert_eq!(
            server.next_event().await.unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reserved_opens_share_ids_and_capacity_with_incoming_channels() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, mut events) = Connection::new(client).into_driver();
        let (server_driver, server, mut peer_events) = Connection::new(server).into_driver();
        let client_task = tokio::spawn(driver.run());
        let server_task = tokio::spawn(server_driver.run());

        let dropped: Vec<_> = (0..128).map(|_| client.prepare_open("session", 8, &[]).unwrap()).collect();
        assert!(client.prepare_open("session", 8, &[]).is_err());
        let full_peer = server.open("session", 9, &[]).await.unwrap();
        assert!(matches!(peer_events.recv().await, Some(Event::Refused { channel, reason: 4, .. }) if channel == full_peer));
        let previous_id = dropped[127].id();
        drop(dropped);

        let other_connection = client.prepare_open("session", 5, &[]).unwrap();
        assert!(matches!(server.submit_open(other_connection).await, Err(error) if error.kind() == ErrorKind::InvalidInput));
        let pending = client.prepare_open("session", 8, &[]).unwrap();
        let reserved = pending.id();
        assert_ne!(reserved, previous_id);
        let peer = server.open("session", 9, &[]).await.unwrap();
        let Some(Event::Incoming { channel: inbound, .. }) = events.recv().await else { panic!("expected concurrent incoming open") };
        assert_ne!(inbound, reserved);
        client.refuse(inbound, 1).await.unwrap();
        assert!(matches!(peer_events.recv().await, Some(Event::Refused { channel, .. }) if channel == peer));

        client.submit_open(pending).await.unwrap();
        let Some(Event::Incoming { channel: remote, .. }) = peer_events.recv().await else { panic!("expected reserved open") };
        server.accept(remote, 13, &[]).await.unwrap();
        assert_eq!(events.recv().await, Some(Event::Opened { channel: reserved, fields: vec![] }));
        client.disconnect().await.unwrap();
        client_task.await.unwrap().unwrap();
        assert_eq!(server_task.await.unwrap().unwrap_err().kind(), ErrorKind::ConnectionAborted);
    }).await.unwrap();
}

#[tokio::test]
async fn callback_output_is_bounded_and_a_zero_window_does_not_stall_other_channels() {
    use thirtyssh::channel::{
        Bytes,
        driver::{ChannelOutput, QUEUED_OUTPUT_BUDGET},
    };

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, mut events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut peer = Connection::new(server);
        let slow = client.open("fixture", 8, b"open fields").await.unwrap();
        let slow_peer = incoming(&mut peer, b"fixture").await;
        peer.accept(slow_peer, 0, &[]).await.unwrap();
        assert!(matches!(events.recv().await, Some(Event::Opened { channel, .. }) if channel == slow));
        let fast = client.open("fixture", 8, b"open fields").await.unwrap();
        let fast_peer = incoming(&mut peer, b"fixture").await;
        peer.accept(fast_peer, 8, &[]).await.unwrap();
        assert!(matches!(events.recv().await, Some(Event::Opened { channel, .. }) if channel == fast));

        let block = 64 * 1024;
        client.queue_output(slow, ChannelOutput::Data { extended: None, data: Bytes::from(vec![0; QUEUED_OUTPUT_BUDGET - block]) }).await.unwrap();
        let more = || ChannelOutput::Data { extended: None, data: Bytes::from(vec![0; block]) };
        assert!(matches!(client.queue_output(slow, more()).await, Err(error) if error.kind() == ErrorKind::WouldBlock));
        client.queue_output(fast, ChannelOutput::Data { extended: Some(1), data: Bytes::from_static(b"fast") }).await.unwrap();
        client.queue_output(fast, ChannelOutput::ExitStatus(23)).await.unwrap();
        client.queue_output(fast, ChannelOutput::Eof).await.unwrap();
        assert_eq!(peer.next_event().await.unwrap(), Event::Data { channel: fast_peer, extended: Some(1), data: b"fast".to_vec() });
        assert!(matches!(peer.next_event().await.unwrap(), Event::Request { channel, name, fields, want_reply: false } if channel == fast_peer && name == b"exit-status" && fields == 23u32.to_be_bytes()));
        assert_eq!(peer.next_event().await.unwrap(), Event::Eof(fast_peer));

        client.close(slow).await.unwrap();
        assert_eq!(peer.next_event().await.unwrap(), Event::Closed(slow_peer));
        assert_eq!(events.recv().await, Some(Event::Closed(slow)));
        let replacement = client.open("fixture", 8, b"open fields").await.unwrap();
        let replacement_peer = incoming(&mut peer, b"fixture").await;
        peer.accept(replacement_peer, 0, &[]).await.unwrap();
        assert!(matches!(events.recv().await, Some(Event::Opened { channel, .. }) if channel == replacement));
        client.queue_output(replacement, more()).await.unwrap();
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn a_full_driver_event_queue_still_services_outbound_commands() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, mut events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut server = Connection::new(server);
        let first = client.open("fixture", 0, b"open fields").await.unwrap();
        let second = client.open("fixture", 0, b"open fields").await.unwrap();
        let peer_first = incoming(&mut server, b"fixture").await;
        let peer_second = incoming(&mut server, b"fixture").await;
        server.accept(peer_first, 0, &[]).await.unwrap();
        server.accept(peer_second, 0, &[]).await.unwrap();
        assert_eq!(
            events.recv().await.unwrap(),
            Event::Opened {
                channel: first,
                fields: vec![]
            }
        );
        assert_eq!(
            events.recv().await.unwrap(),
            Event::Opened {
                channel: second,
                fields: vec![]
            }
        );

        let count = events.max_capacity() + 1;
        for _ in 0..count {
            server
                .request(peer_first, "notice", false, &[])
                .await
                .unwrap();
        }
        while events.len() < events.max_capacity() {
            tokio::task::yield_now().await;
        }
        client.request(second, "control", true, &[]).await.unwrap();
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Request {
                channel: peer_second,
                name: b"control".to_vec(),
                want_reply: true,
                fields: vec![]
            }
        );
        server.reply(peer_second, true).await.unwrap();
        for _ in 0..count {
            assert_eq!(
                events.recv().await.unwrap(),
                Event::Request {
                    channel: first,
                    name: b"notice".to_vec(),
                    want_reply: false,
                    fields: vec![]
                }
            );
        }
        assert_eq!(
            events.recv().await.unwrap(),
            Event::Reply {
                channel: second,
                success: true
            }
        );
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

async fn routed_pair(
    client: &Handle,
    server: &Handle,
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    window: u32,
) -> (Channel, Channel) {
    let opened = client.open_channel("fixture", window, b"open fields");
    let accepted = async {
        let Some(Event::Incoming {
            channel,
            kind,
            fields,
        }) = events.recv().await
        else {
            panic!("expected an incoming channel");
        };
        assert_eq!(kind, b"fixture");
        assert_eq!(fields, b"open fields");
        server.accept_channel(channel, window, b"confirmed").await
    };
    let (left, right) = tokio::try_join!(opened, accepted).unwrap();
    assert_eq!(left.open_fields(), b"confirmed");
    (left, right)
}

#[tokio::test]
async fn routed_streams_isolate_a_stalled_reader_and_support_half_close() {
    use std::future::ready;
    use thirtyssh::channel::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (client_driver, client, _client_events) = Connection::new(client).into_driver();
        let (server_driver, server, mut server_events) = Connection::new(server).into_driver();
        let client_task = tokio::spawn(client_driver.run());
        let server_task = tokio::spawn(server_driver.run());
        let (mut slow_client, slow_server) =
            routed_pair(&client, &server, &mut server_events, 4).await;
        let (mut fast_client, mut fast_server) =
            routed_pair(&client, &server, &mut server_events, 7).await;

        // A write is accepted only as far as the peer's window reaches.
        let mut writer = slow_server.writer();
        assert_eq!(writer.write(b"stalled").await.unwrap(), 4);
        fast_client.raw_request("probe", &[], true).await.unwrap();
        assert!(matches!(
            fast_server.recv().await,
            Some(Message::Request {
                want_reply: true,
                ..
            })
        ));
        fast_server.reply(true).await.unwrap();
        assert_eq!(
            fast_client.recv().await,
            Some(Message::Reply { success: true })
        );
        let mut fast_client = fast_client.into_io();
        let mut fast_server = fast_server.into_io();
        let fast_output = vec![0x66; 90];
        let fast_input = vec![0x77; 70];
        let receive = async {
            let mut output = Vec::new();
            fast_client.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, fast_output);
            fast_client.write_all(&fast_input).await.unwrap();
            fast_client.shutdown().await.unwrap();
        };
        let send = async {
            fast_server.write_all(&fast_output).await.unwrap();
            fast_server.flush().await.unwrap();
            fast_server.shutdown().await.unwrap();
            let mut received = Vec::new();
            fast_server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, fast_input);
        };
        tokio::join!(send, receive);

        tokio::select! {
            biased;
            result = writer.write(b"led") => panic!("slow stream wrote past its window: {result:?}"),
            () = ready(()) => {}
        }
        let mut slow_data = Vec::new();
        let ((), ()) = tokio::join!(
            async {
                slow_client
                    .reader()
                    .read_to_end(&mut slow_data)
                    .await
                    .unwrap();
            },
            async {
                writer.write_all(b"led").await.unwrap();
                writer.shutdown().await.unwrap();
            },
        );
        assert_eq!(slow_data, b"stalled");
        client.disconnect().await.unwrap();
        client_task.await.unwrap().unwrap();
        assert_eq!(
            server_task.await.unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn routed_reads_batch_credit_and_refill_an_exhausted_window() {
    use tokio::io::AsyncReadExt;

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, _events) = Connection::new(client).into_driver();
        let driver = tokio::spawn(driver.run());
        let mut peer = Connection::new(server);
        let (channel, peer_id) =
            tokio::join!(client.open_channel("fixture", 8, b"open fields"), async {
                let id = incoming(&mut peer, b"fixture").await;
                peer.accept(id, 8, b"").await.unwrap();
                id
            });
        let mut channel = channel.unwrap();
        let mut reader = channel.reader();
        let mut data = [0; 3];

        assert_eq!(peer.send_data(peer_id, None, b"one").await.unwrap(), 3);
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"one");
        assert!(
            timeout(Duration::from_secs(1), peer.next_event())
                .await
                .is_err()
        );

        assert_eq!(peer.send_data(peer_id, None, b"two").await.unwrap(), 3);
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"two");
        assert_eq!(
            peer.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: peer_id,
                remaining: 8
            }
        );

        assert_eq!(peer.send_data(peer_id, None, b"12345678").await.unwrap(), 8);
        assert_eq!(reader.read_u8().await.unwrap(), b'1');
        assert_eq!(
            peer.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: peer_id,
                remaining: 1
            }
        );

        let mut rest = [0; 7];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"2345678");
        assert_eq!(
            peer.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: peer_id,
                remaining: 8
            }
        );
        assert_eq!(peer.send_data(peer_id, None, b"abc").await.unwrap(), 3);
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"abc");
        assert_eq!(peer.send_data(peer_id, None, b"defgh").await.unwrap(), 5);
        assert_eq!(
            peer.next_event().await.unwrap(),
            Event::WindowAdjusted {
                channel: peer_id,
                remaining: 3
            }
        );

        client.disconnect().await.unwrap();
        driver.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn routed_halves_preserve_extended_bytes_and_release_dropped_channels() {
    use thirtyssh::channel::{Bytes, Message};
    use tokio::io::AsyncReadExt;

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (client_driver, client, _client_events) = Connection::new(client).into_driver();
        let (server_driver, server, mut server_events) = Connection::new(server).into_driver();
        let client_task = tokio::spawn(client_driver.run());
        let server_task = tokio::spawn(server_driver.run());
        let (client_channel, server_channel) =
            routed_pair(&client, &server, &mut server_events, 3).await;
        let (mut client_read, client_write) = client_channel.split();
        let (mut server_read, server_write) = server_channel.split();
        let stderr = Bytes::from_static(b"errors");
        let stdout = Bytes::from_static(b"text");
        let process = async {
            server_write.send_extended(1, stderr.clone()).await.unwrap();
            server_write.send(stdout.clone()).await.unwrap();
            server_write.eof().await.unwrap();
        };
        let application = async {
            let mut prefix = [0; 2];
            client_read
                .extended_reader(1)
                .read_exact(&mut prefix)
                .await
                .unwrap();
            assert_eq!(&prefix, b"er");
            let mut remaining = prefix.to_vec();
            let mut output = Vec::new();
            loop {
                match client_read.recv().await.unwrap() {
                    Message::ExtendedData { data, code: 1 } => remaining.extend_from_slice(&data),
                    Message::Data(data) => output.extend_from_slice(&data),
                    Message::Eof => break,
                    message => panic!("unexpected message: {message:?}"),
                }
            }
            assert_eq!(remaining, stderr);
            assert_eq!(output, stdout);
        };
        tokio::join!(process, application);
        drop(client_read);
        drop(client_write);
        assert_eq!(server_read.recv().await, Some(Message::Closed));
        assert_eq!(server_read.recv().await, None);
        client.disconnect().await.unwrap();
        client_task.await.unwrap().unwrap();
        assert_eq!(
            server_task.await.unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn owned_writes_survive_writer_drop_and_cancel_unaccepted_bytes_at_zero_window() {
    use std::{future::ready, pin::pin};
    use thirtyssh::channel::{Bytes, Message};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (client_driver, client, _client_events) = Connection::new(client).into_driver();
        let (server_driver, server, mut server_events) = Connection::new(server).into_driver();
        let client_task = tokio::spawn(client_driver.run());
        let server_task = tokio::spawn(server_driver.run());
        let (client_channel, server_channel) = routed_pair(&client, &server, &mut server_events, 4).await;
        let (_client_read, output) = client_channel.split();
        let (mut server_read, _server_write) = server_channel.split();
        assert_eq!(output.capacity().await, 4);
        output.send(Bytes::from_static(b"1234")).await.unwrap();
        assert_eq!(output.capacity().await, 0);

        // A cancelled zero-window transfer must not send bytes when the peer
        // eventually restores receive credit.
        {
            let stalled = pin!(output.send(Bytes::from_static(b"cancelled")));
            tokio::select! {
                biased;
                result = stalled => panic!("zero-window write finished: {result:?}"),
                () = ready(()) => {},
            }
            assert_eq!(output.capacity().await, 0);
        }

        let mut writer = output.writer();
        tokio::select! {
            biased;
            result = writer.write(b"accepted") => panic!("write accepted bytes with no window: {result:?}"),
            () = ready(()) => {},
        }
        let mut prefix = [0; 4];
        server_read.reader().read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"1234");
        assert_eq!(writer.write(b"accepted").await.unwrap(), 4);
        let mut another = output.writer();
        tokio::select! {
            biased;
            result = another.write(b"unaccepted") => panic!("concurrent write bypassed backpressure: {result:?}"),
            () = ready(()) => {},
        }
        drop((another, writer, output));

        let mut data = Vec::new();
        server_read.reader().read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"acce");

        // Both explicit close and dropping both halves must follow an
        // already accepted packet.
        for explicit in [false, true] {
            let (closing, mut peer) = routed_pair(&client, &server, &mut server_events, 4).await;
            let mut writer = closing.sender().writer();
            assert_eq!(writer.write(b"last").await.unwrap(), 4);
            if explicit {
                closing.sender().close_when_sent().await.unwrap();
            }
            drop((writer, closing));
            assert_eq!(peer.recv().await, Some(Message::Data(Bytes::from_static(b"last"))));
            assert_eq!(peer.recv().await, Some(Message::Closed));
        }

        client.disconnect().await.unwrap();
        client_task.await.unwrap().unwrap();
        assert_eq!(server_task.await.unwrap().unwrap_err().kind(), ErrorKind::ConnectionAborted);
    }).await.unwrap();
}

#[tokio::test]
async fn typed_queue_keeps_one_byte_packets_and_limits_control_messages_per_channel() {
    use thirtyssh::channel::{Bytes, Message};

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, _client_events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut server = Connection::new(server);
        let (first, peer_first) =
            tokio::join!(client.open_channel("fixture", 256, b"open fields"), async {
                let id = incoming(&mut server, b"fixture").await;
                server.accept(id, 256, &[]).await.unwrap();
                id
            },);
        let mut first = first.unwrap();
        let (second, peer_second) =
            tokio::join!(client.open_channel("fixture", 256, b"open fields"), async {
                let id = incoming(&mut server, b"fixture").await;
                server.accept(id, 256, &[]).await.unwrap();
                id
            },);
        let mut second = second.unwrap();
        for byte in 0..=255u8 {
            assert_eq!(
                server
                    .send_data(peer_first, Some(u32::from(byte % 2)), &[byte])
                    .await
                    .unwrap(),
                1
            );
        }
        let fields = vec![0; 45 * 1024];
        for _ in 0..3 {
            server
                .request(peer_first, "notice", false, &fields)
                .await
                .unwrap();
        }
        assert_eq!(
            server.next_event().await.unwrap(),
            Event::Closed(peer_first)
        );
        for byte in 0..=255u8 {
            assert_eq!(
                first.recv().await.unwrap(),
                Message::ExtendedData {
                    data: Bytes::copy_from_slice(&[byte]),
                    code: u32::from(byte % 2)
                }
            );
        }
        for _ in 0..2 {
            assert!(matches!(
                first.recv().await.unwrap(),
                Message::Request { .. }
            ));
        }
        assert_eq!(first.recv().await, Some(Message::Overrun));
        assert_eq!(first.recv().await, Some(Message::Closed));
        server.send_data(peer_second, None, b"ok").await.unwrap();
        assert_eq!(
            second.recv().await,
            Some(Message::Data(Bytes::from_static(b"ok")))
        );
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn byte_readers_refuse_the_requests_they_pass_over() {
    use tokio::io::AsyncReadExt;

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, _events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut peer = Connection::new(server);
        let (channel, peer_id) = tokio::join!(
            client.open_channel("fixture", 1024, b"open fields"),
            async {
                let id = incoming(&mut peer, b"fixture").await;
                peer.accept(id, 1024, &[]).await.unwrap();
                id
            }
        );
        let mut channel = channel.unwrap();

        peer.request(peer_id, "shell", true, &[]).await.unwrap();
        peer.request(peer_id, "notice", false, &[]).await.unwrap();
        peer.request(peer_id, "keepalive@openssh.com", true, &[])
            .await
            .unwrap();
        peer.send_data(peer_id, None, b"data").await.unwrap();
        let mut data = [0; 4];
        channel.reader().read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"data");

        // The request nobody saw is refused, which also lets the keepalive
        // reply queued behind it leave.
        for success in [false, true] {
            assert_eq!(
                peer.next_event().await.unwrap(),
                Event::Reply {
                    channel: peer_id,
                    success
                }
            );
        }
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_window_filled_byte_by_byte_is_queued_in_joined_chunks() {
    use thirtyssh::channel::Message;

    timeout(Duration::from_secs(10), async {
        const WINDOW: usize = 8192;
        let (client, server) = pair().await;
        let (driver, client, _events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut peer = Connection::new(server);
        let (channel, peer_id) = tokio::join!(
            client.open_channel("fixture", WINDOW as u32, b"open fields"),
            async {
                let id = incoming(&mut peer, b"fixture").await;
                peer.accept(id, WINDOW as u32, &[]).await.unwrap();
                id
            }
        );
        let mut channel = channel.unwrap();
        for index in 0..WINDOW {
            assert_eq!(
                peer.send_data(peer_id, None, &[index as u8]).await.unwrap(),
                1
            );
        }
        // Replies leave in order, so this one shows every byte was queued.
        peer.request(peer_id, "keepalive@openssh.com", true, &[])
            .await
            .unwrap();
        assert_eq!(
            peer.next_event().await.unwrap(),
            Event::Reply {
                channel: peer_id,
                success: true
            }
        );

        let (mut received, mut messages) = (Vec::new(), 0);
        while received.len() < WINDOW {
            let Some(Message::Data(data)) = channel.recv().await else {
                panic!("expected channel data");
            };
            received.extend_from_slice(&data);
            messages += 1;
        }
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == index as u8)
        );
        // One queue entry per byte would be 8192 of them.
        assert!(messages < WINDOW / 4, "{messages} queued messages");
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_full_event_queue_does_not_hold_back_an_open_confirmation() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, mut events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut server = Connection::new(server);
        let first = client.open("fixture", 0, b"open fields").await.unwrap();
        let peer_first = incoming(&mut server, b"fixture").await;
        server.accept(peer_first, 0, &[]).await.unwrap();
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::Opened { channel, .. } if channel == first
        ));

        // More events than the consumer's queue holds, and nobody reading them.
        let count = events.max_capacity() + 8;
        for _ in 0..count {
            server
                .request(peer_first, "notice", false, &[])
                .await
                .unwrap();
        }
        while events.len() < events.max_capacity() {
            tokio::task::yield_now().await;
        }
        // The confirmation is behind those events on the wire. It still has
        // to arrive, or a consumer that opens a channel before reading its
        // next event would wait for ever.
        let (channel, peer_second) = tokio::join!(
            client.open_channel("fixture", 1024, b"open fields"),
            async {
                let id = incoming(&mut server, b"fixture").await;
                server.accept(id, 1024, b"confirmed").await.unwrap();
                id
            }
        );
        let mut channel = channel.unwrap();
        server.send_data(peer_second, None, b"data").await.unwrap();
        assert_eq!(
            channel.recv().await,
            Some(thirtyssh::channel::Message::Data(Bytes::from_static(
                b"data"
            )))
        );
        for _ in 0..count {
            assert!(matches!(
                events.recv().await.unwrap(),
                Event::Request { channel, .. } if channel == first
            ));
        }
        client.disconnect().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn what_the_peer_sent_before_the_connection_broke_a_write_still_arrives() {
    use thirtyssh::channel::Message;

    timeout(Duration::from_secs(5), async {
        let (client, server) = pair().await;
        let (driver, client, _events) = Connection::new(client).into_driver();
        let task = tokio::spawn(driver.run());
        let mut peer = Connection::new(server);
        let (channel, peer_id) = tokio::join!(
            client.open_channel("fixture", 1024, b"open fields"),
            async {
                let id = incoming(&mut peer, b"fixture").await;
                peer.accept(id, 1024 * 1024, &[]).await.unwrap();
                id
            }
        );
        let (mut receiver, sender) = channel.unwrap().split();
        // The peer never reads, so this write fills the stream and stays
        // blocked inside the transport.
        let writing = tokio::spawn(async move { sender.send(vec![0x5a; 256 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!writing.is_finished());

        // A command's last words, then the connection goes away.
        peer.send_data(peer_id, None, b"last output").await.unwrap();
        peer.request(peer_id, "exit-status", false, &[0, 0, 0, 7])
            .await
            .unwrap();
        peer.eof(peer_id).await.unwrap();
        peer.close(peer_id).await.unwrap();
        drop(peer);

        assert_eq!(
            receiver.recv().await,
            Some(Message::Data(Bytes::from_static(b"last output")))
        );
        assert!(matches!(
            receiver.recv().await,
            Some(Message::Request { name, want_reply: false, fields })
                if name == "exit-status" && fields[..] == [0, 0, 0, 7]
        ));
        assert_eq!(receiver.recv().await, Some(Message::Eof));
        assert_eq!(receiver.recv().await, Some(Message::Closed));
        assert_eq!(receiver.recv().await, None);
        assert!(writing.await.unwrap().is_err());
        assert!(task.await.unwrap().is_err());
    })
    .await
    .unwrap();
}
