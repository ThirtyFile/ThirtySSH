#![cfg(not(target_family = "wasm"))]

#[path = "fixtures/forwarding.rs"]
mod forwarding;

use forwarding::LoopbackForwarding;
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use thirtyssh::{
    channel::GlobalReply,
    client,
    forward::{RemoteListener, TcpipKind, TcpipOpen},
    keys::{Algorithm, Credential},
    server,
    session::{self, Context, IncomingChannel, OpenType},
    transport::HostKey,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex},
    net::{TcpListener, TcpStream},
    time::timeout,
};

#[path = "fixtures/pinned.rs"]
mod pinned;
use pinned::Pinned;

struct ForwardedTarget {
    host: [u8; 32],
    listening_port: Arc<AtomicU32>,
    target: SocketAddr,
}

impl client::Handler for ForwardedTarget {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(self.host == key)
    }
}

impl session::Handler for ForwardedTarget {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let Ok(OpenType::Tcpip(open)) = request.open_type() else {
            return Ok(());
        };
        if open.kind != TcpipKind::Forwarded
            || open.address != "127.0.0.1"
            || open.port != self.listening_port.load(Ordering::Acquire)
        {
            return request.refuse(1).await;
        }
        let mut socket = TcpStream::connect(self.target).await?;
        let mut channel = request.accept(32 * 1024, &[]).await?.into_io();
        copy_bidirectional(&mut socket, &mut channel).await?;
        Ok(())
    }
}

struct AllowOneDestination {
    target: SocketAddr,
    key: [u8; 32],
}

impl server::AuthPolicy for AllowOneDestination {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        Ok(user == "forward" && self.key == *key)
    }
}

impl session::Handler for AllowOneDestination {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let Ok(OpenType::Tcpip(open)) = request.open_type() else {
            return Ok(());
        };
        if open.kind != TcpipKind::Direct
            || open.address != "127.0.0.1"
            || open.port != u32::from(self.target.port())
        {
            return request.refuse(1).await;
        }
        assert_eq!(
            (open.originator_address, open.originator_port),
            ("127.0.0.2", 12345)
        );
        let Ok(mut socket) = TcpStream::connect(self.target).await else {
            return request.refuse(2).await;
        };
        let mut stream = request.accept(32 * 1024, &[]).await?.into_io();
        copy_bidirectional(&mut stream, &mut socket).await?;
        Ok(())
    }
}

#[tokio::test]
async fn direct_tcpip_relays_a_loopback_socket_and_preserves_both_half_closes() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let port = u32::from(target.port());
        let key = HostKey::generate().unwrap();
        let identity = HostKey::generate().unwrap();
        let trust = Pinned(key.public_key());
        let config = Arc::new(server::Config::new(key));
        let policy = AllowOneDestination {
            target,
            key: identity.public_key(),
        };
        let (a, b) = duplex(8192);
        let connect = async {
            let mut client = client::connect_over(Arc::new(client::Config::default()), b, trust)
                .await
                .unwrap();
            assert!(
                client
                    .authenticate("forward", &identity)
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client
        };
        let (server, client) = tokio::join!(server::accept_over(config, a, None, policy), connect);
        let server = server.unwrap();
        let client = client.start().unwrap();
        let handle = client.handle();
        let refused = handle
            .open_as(TcpipOpen {
                kind: TcpipKind::Direct,
                address: "127.0.0.2",
                port,
                originator_address: "127.0.0.2",
                originator_port: 12345,
            })
            .await;
        assert!(matches!(refused, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        let malformed = handle.open_channel("direct-tcpip", 16, b"bad").await;
        assert!(matches!(malformed, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        let unrequested = server
            .handle()
            .open_as(TcpipOpen {
                kind: TcpipKind::Forwarded,
                address: "127.0.0.1",
                port,
                originator_address: "127.0.0.2",
                originator_port: 12345,
            })
            .await;
        assert!(matches!(unrequested, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        let channel = handle
            .open_as(TcpipOpen {
                kind: TcpipKind::Direct,
                address: "127.0.0.1",
                port,
                originator_address: "127.0.0.2",
                originator_port: 12345,
            })
            .await
            .unwrap();
        let payload: Vec<u8> = (0..192 * 1024).map(|i| (i % 251) as u8).collect();
        let client_io = async {
            let mut stream = channel.into_io();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"after TCP EOF");
        };
        let target_io = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, payload);
            socket.write_all(b"after TCP EOF").await.unwrap();
            socket.shutdown().await.unwrap();
        };
        tokio::join!(client_io, target_io);
        drop(client);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn tcpip_fields_decode_exact_wire_layout_and_reject_invalid_values() {
    let fields = b"\0\0\0\x09localhost\0\0\x1f\x90\0\0\0\x09127.0.0.1\0\0\0\x50";
    let expected = TcpipOpen {
        kind: TcpipKind::Direct,
        address: "localhost",
        port: 8080,
        originator_address: "127.0.0.1",
        originator_port: 80,
    };
    assert_eq!(
        TcpipOpen::decode(b"direct-tcpip", fields).unwrap(),
        Some(expected)
    );
    assert_eq!(
        TcpipOpen::decode(b"forwarded-tcpip", fields).unwrap(),
        Some(TcpipOpen {
            kind: TcpipKind::Forwarded,
            ..expected
        })
    );
    assert_eq!(TcpipOpen::decode(b"session", fields).unwrap(), None);
    assert!(TcpipOpen::decode(b"direct-tcpip", &fields[..fields.len() - 1]).is_err());
    assert!(TcpipOpen::decode(b"direct-tcpip", &[fields.as_slice(), b"\0"].concat()).is_err());
    let mut bad = *fields;
    bad[14] = 1; // Port above the TCP maximum.
    assert!(TcpipOpen::decode(b"direct-tcpip", &bad).is_err());
    let mut bad = *fields;
    bad[4] = 0;
    assert!(TcpipOpen::decode(b"direct-tcpip", &bad).is_err());
}

#[tokio::test]
async fn remote_tcpip_allocates_and_cancels_listeners_while_existing_channels_drain() {
    timeout(Duration::from_secs(15), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let active_port = Arc::new(AtomicU32::new(0));
        let (a, b) = duplex(8192);
        let host = HostKey::generate().unwrap();
        let identity = HostKey::generate().unwrap();
        let handler = ForwardedTarget {
            host: host.public_key(),
            listening_port: Arc::clone(&active_port),
            target: target.local_addr().unwrap(),
        };
        let connect = async {
            let mut auth = client::connect_over(Arc::new(client::Config::default()), a, handler).await.unwrap();
            assert!(auth.authenticate("forward", &identity).await.unwrap().is_accepted());
            auth
        };
        let server = server::accept_over(Arc::new(server::Config::new(host)), b, None, LoopbackForwarding::new(identity.public_key()));
        let (client, server) = tokio::join!(connect, server);
        let client = client.start().unwrap();
        let server = server.unwrap();
        let handle = client.handle();

        assert_eq!(handle.global_request("unknown@example.test", b"unhandled").await.unwrap(), GlobalReply::Failure);
        for (address, port) in [("0.0.0.0", 0), ("127.0.0.1", 22)] {
            assert_eq!(handle.listen(RemoteListener::Tcp { bind_address: address, port }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        assert_eq!(handle.global_request("tcpip-forward", b"malformed").await.unwrap(), GlobalReply::Failure);
        assert!(handle.listen(RemoteListener::Tcp { bind_address: "127.0.0.1", port: u32::from(u16::MAX) + 1 }).await.is_err());
        let blocked = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blocked_port = u32::from(blocked.local_addr().unwrap().port());
        assert_eq!(handle.listen(RemoteListener::Tcp { bind_address: "127.0.0.1", port: blocked_port }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);

        let port = handle.listen(RemoteListener::Tcp { bind_address: "127.0.0.1", port: 0 }).await.unwrap().unwrap();
        assert!((1024..=u32::from(u16::MAX)).contains(&port));
        active_port.store(port, Ordering::Release);
        let endpoint = ("127.0.0.1", port as u16);
        let mut external = TcpStream::connect(endpoint).await.unwrap();
        let (mut internal, _) = target.accept().await.unwrap();
        handle.unlisten(RemoteListener::Tcp { bind_address: "127.0.0.1", port }).await.unwrap();
        assert!(TcpStream::connect(endpoint).await.is_err());
        assert_eq!(handle.unlisten(RemoteListener::Tcp { bind_address: "127.0.0.1", port }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);

        let send = async {
            external.write_all(b"accepted before cancellation").await.unwrap();
            external.shutdown().await.unwrap();
            let mut reply = Vec::new();
            external.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"still open after cancel");
        };
        let receive = async {
            let mut data = Vec::new();
            internal.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"accepted before cancellation");
            internal.write_all(b"still open after cancel").await.unwrap();
            internal.shutdown().await.unwrap();
        };
        tokio::join!(send, receive);

        assert_eq!(handle.listen(RemoteListener::Tcp { bind_address: "127.0.0.1", port }).await.unwrap(), None);
        let mut external = TcpStream::connect(endpoint).await.unwrap();
        let (mut internal, _) = target.accept().await.unwrap();
        drop(client);
        server.await.unwrap();
        assert!(TcpStream::connect(endpoint).await.is_err());
        for stream in [&mut external, &mut internal] {
            assert!(matches!(stream.read_u8().await, Err(err) if matches!(err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)));
        }
    }).await.unwrap();
}
