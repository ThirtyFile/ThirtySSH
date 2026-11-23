use std::{io, sync::Arc, time::Duration};
#[cfg(unix)]
use thirtyssh::forward::RemoteListener;
#[cfg(unix)]
use thirtyssh::keys::{Algorithm, Credential};
use thirtyssh::{
    client,
    forward::streamlocal::{
        StreamlocalForward, StreamlocalForwardKind, StreamlocalKind, StreamlocalOpen,
    },
    server,
    session::{self, Session},
    transport::HostKey,
};
use tokio::{io::duplex, time::timeout};

#[cfg(unix)]
#[path = "fixtures/streamlocal.rs"]
mod fixture;

#[path = "fixtures/pinned.rs"]
mod pinned;
use pinned::Pinned;

async fn sessions(
    host: HostKey,
    identity: HostKey,
    verifier: impl client::Handler,
    policy: impl server::Handler,
) -> (Session, Session) {
    let (a, b) = duplex(8192);
    let connect = async {
        let mut auth = client::connect_over(Arc::new(client::Config::default()), a, verifier)
            .await
            .unwrap();
        assert!(
            auth.authenticate("forward", &identity)
                .await
                .unwrap()
                .is_accepted()
        );
        auth
    };
    let accept = server::accept_over(Arc::new(server::Config::new(host)), b, None, policy);
    let (client, server) = tokio::join!(connect, accept);
    (client.start().unwrap(), server.unwrap())
}

#[test]
fn streamlocal_layouts_preserve_socket_bytes_and_consume_reserved_fields() {
    const PATH: &[u8] = b"/s\xffk";
    const DIRECT: &[u8] = b"direct-streamlocal@openssh.com";
    const FORWARDED: &[u8] = b"forwarded-streamlocal@openssh.com";
    const LISTEN: &[u8] = b"streamlocal-forward@openssh.com";
    const CANCEL: &[u8] = b"cancel-streamlocal-forward@openssh.com";
    let string = b"\0\0\0\x04/s\xffk";
    let forwarded = &[string.as_slice(), b"\0\0\0\x03xyz"].concat();
    let direct = &[forwarded.as_slice(), b"\0\0\0\x09"].concat();
    for (name, bytes, kind) in [
        (DIRECT, direct, StreamlocalKind::Direct),
        (FORWARDED, forwarded, StreamlocalKind::Forwarded),
    ] {
        assert_eq!(
            StreamlocalOpen::decode(name, bytes).unwrap(),
            Some(StreamlocalOpen {
                kind,
                socket_path: PATH
            })
        );
        assert!(StreamlocalOpen::decode(name, &bytes[..bytes.len() - 1]).is_err());
        assert!(StreamlocalOpen::decode(name, &[bytes.as_slice(), b"\0"].concat()).is_err());
    }
    for (name, kind) in [
        (LISTEN, StreamlocalForwardKind::Listen),
        (CANCEL, StreamlocalForwardKind::Cancel),
    ] {
        assert_eq!(
            StreamlocalForward::decode(name, string).unwrap(),
            Some(StreamlocalForward {
                kind,
                socket_path: PATH
            })
        );
        assert!(StreamlocalForward::decode(name, b"\0\0\0\0").is_err());
        assert!(StreamlocalForward::decode(name, b"\0\0\0\x02a\0").is_err());
        assert!(StreamlocalForward::decode(name, forwarded).is_err());
    }
    assert_eq!(StreamlocalOpen::decode(b"session", &[]).unwrap(), None);
    assert_eq!(
        StreamlocalForward::decode(b"tcpip-forward", &[]).unwrap(),
        None
    );
}

#[cfg(unix)]
mod unix {
    use super::*;

    // Socket paths are bytes, not text, and the names here prove that where
    // the file system allows it. Apple's file systems refuse names that are
    // not valid UTF-8, so there the names only leave ASCII.
    #[cfg(not(target_vendor = "apple"))]
    const DIRECT_NAME: &[u8] = b"direct-\xff.sock";
    #[cfg(not(target_vendor = "apple"))]
    const REMOTE_NAME: &[u8] = b"remote-\xfe.sock";
    #[cfg(target_vendor = "apple")]
    const DIRECT_NAME: &[u8] = "direct-\u{e9}.sock".as_bytes();
    #[cfg(target_vendor = "apple")]
    const REMOTE_NAME: &[u8] = "remote-\u{e8}.sock".as_bytes();
    use crate::fixture::LocalForwarding;
    use std::{
        ffi::OsStr,
        fs,
        os::unix::{ffi::OsStrExt, fs::FileTypeExt},
        path::PathBuf,
    };
    use thirtyssh::{
        channel::GlobalReply,
        forward::streamlocal::relay_to_socket,
        session::{Context, IncomingChannel},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };

    async fn round_trip(
        mut left: impl AsyncRead + AsyncWrite + Unpin,
        mut right: impl AsyncRead + AsyncWrite + Unpin,
    ) {
        let ask = async {
            left.write_all(b"streamlocal input\0\xff").await.unwrap();
            left.shutdown().await.unwrap();
            let mut reply = Vec::new();
            left.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"streamlocal response\0\xfe");
        };
        let answer = async {
            let mut input = Vec::new();
            right.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"streamlocal input\0\xff");
            right
                .write_all(b"streamlocal response\0\xfe")
                .await
                .unwrap();
            right.shutdown().await.unwrap();
        };
        tokio::join!(ask, answer);
    }

    #[tokio::test]
    async fn direct_streamlocal_uses_the_authorized_unix_socket() {
        timeout(Duration::from_secs(10), async {
            let directory = tempfile::tempdir().unwrap();
            let direct = directory.path().join(OsStr::from_bytes(DIRECT_NAME));
            let host = HostKey::generate().unwrap();
            let identity = HostKey::generate().unwrap();
            let client = Pinned(host.public_key());
            let policy = LocalForwarding::new(identity.public_key(), direct.clone(), directory.path().join("unused.sock"));
            let (client, server) = sessions(host, identity, client, policy).await;
            let handle = client.handle();
            let allowed = direct.as_os_str().as_bytes();
            for path in [b"outside-policy".as_slice(), allowed] {
                // The first path is forbidden and the authorized one does not exist yet.
                assert!(matches!(handle.open_as(StreamlocalOpen { kind: StreamlocalKind::Direct, socket_path: path }).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
            }
            assert!(matches!(handle.open_as(StreamlocalOpen { kind: StreamlocalKind::Direct, socket_path: (b"bad\0path").as_ref() }).await, Err(err) if err.kind() == io::ErrorKind::InvalidInput));
            let target = UnixListener::bind(&direct).unwrap();
            let channel = handle.open_as(StreamlocalOpen { kind: StreamlocalKind::Direct, socket_path: allowed }).await.unwrap();
            let (connection, _) = target.accept().await.unwrap();
            round_trip(channel.into_io(), connection).await;
            client.disconnect().await.unwrap();
            server.await.unwrap();
            assert!(fs::metadata(direct).unwrap().file_type().is_socket());
        }).await.unwrap();
    }

    struct LocalTarget {
        host: [u8; 32],
        remote: PathBuf,
        destination: PathBuf,
    }

    impl client::Handler for LocalTarget {
        async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
            let Some(key) = host.ed25519() else {
                return Ok(false);
            };
            Ok(self.host == key)
        }
    }

    impl session::Handler for LocalTarget {
        async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
            let Ok(Some(open)) = request.streamlocal() else {
                return Ok(());
            };
            if open.kind != StreamlocalKind::Forwarded
                || open.socket_path != self.remote.as_os_str().as_bytes()
            {
                return request.refuse(1).await;
            }
            relay_to_socket(request, &self.destination).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn remote_streamlocal_cancels_and_removes_its_path_while_a_channel_remains_open() {
        timeout(Duration::from_secs(10), async {
            let directory = tempfile::tempdir().unwrap();
            let remote = directory.path().join(OsStr::from_bytes(REMOTE_NAME));
            let destination = directory.path().join("destination.sock");
            let target = UnixListener::bind(&destination).unwrap();
            let host = HostKey::generate().unwrap();
            let identity = HostKey::generate().unwrap();
            let verifier = LocalTarget { host: host.public_key(), remote: remote.clone(), destination };
            let policy = LocalForwarding::new(identity.public_key(), directory.path().join("unused.sock"), remote.clone());
            let (client, server) = sessions(host, identity, verifier, policy).await;
            let handle = client.handle();
            let path = remote.as_os_str().as_bytes();
            let denied = handle.listen(RemoteListener::Unix { socket_path: (b"outside-policy").as_ref() }).await.unwrap_err();
            assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(handle.global_request("streamlocal-forward@openssh.com", b"malformed").await.unwrap(), GlobalReply::Failure);
            assert!(matches!(server.handle().open_as(StreamlocalOpen { kind: StreamlocalKind::Forwarded, socket_path: (b"unknown").as_ref() }).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
            fs::write(&remote, b"pre-existing regular file").unwrap();
            assert_eq!(handle.listen(RemoteListener::Unix { socket_path: path }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::read(&remote).unwrap(), b"pre-existing regular file");
            fs::remove_file(&remote).unwrap();

            handle.listen(RemoteListener::Unix { socket_path: path }).await.unwrap();
            assert!(fs::metadata(&remote).unwrap().file_type().is_socket());
            assert_eq!(handle.listen(RemoteListener::Unix { socket_path: path }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            let outside = UnixStream::connect(&remote).await.unwrap();
            let (inside, _) = target.accept().await.unwrap();
            handle.unlisten(RemoteListener::Unix { socket_path: path }).await.unwrap();
            assert_eq!(handle.unlisten(RemoteListener::Unix { socket_path: path }).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::symlink_metadata(&remote).unwrap_err().kind(), io::ErrorKind::NotFound);
            assert!(UnixStream::connect(&remote).await.is_err());
            round_trip(outside, inside).await;

            handle.listen(RemoteListener::Unix { socket_path: path }).await.unwrap();
            let mut outside = UnixStream::connect(&remote).await.unwrap();
            let (mut inside, _) = target.accept().await.unwrap();
            client.disconnect().await.unwrap();
            server.await.unwrap();
            assert_eq!(fs::symlink_metadata(&remote).unwrap_err().kind(), io::ErrorKind::NotFound);
            for stream in [&mut outside, &mut inside] {
                assert_eq!(stream.read_u8().await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
            }
        }).await.unwrap();
    }
}

#[cfg(not(unix))]
#[tokio::test]
async fn local_socket_relay_reports_unsupported_while_channel_requests_still_work() {
    use thirtyssh::{
        forward::streamlocal::relay_to_socket,
        session::{Context, IncomingChannel},
    };

    struct NoLocalSocket {
        key: [u8; 32],
        result: Option<tokio::sync::oneshot::Sender<io::ErrorKind>>,
    }
    impl server::AuthPolicy for NoLocalSocket {
        async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
            Ok(user == "forward" && *key == self.key)
        }
    }
    impl session::Handler for NoLocalSocket {
        async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
            let open = request
                .streamlocal()?
                .expect("expected a streamlocal request");
            assert_eq!(open.socket_path, b"/wire/only.sock");
            let error = relay_to_socket(request, "unused").await.unwrap_err();
            let _ = self.result.take().unwrap().send(error.kind());
            Ok(())
        }
    }
    timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let identity = HostKey::generate().unwrap();
        let verifier = Pinned(host.public_key());
        let (result, observation) = tokio::sync::oneshot::channel();
        let policy = NoLocalSocket {
            key: identity.public_key(),
            result: Some(result),
        };
        let (client, server) = sessions(host, identity, verifier, policy).await;
        let refused = client
            .handle()
            .open_as(StreamlocalOpen {
                kind: StreamlocalKind::Direct,
                socket_path: ("/wire/only.sock").as_ref(),
            })
            .await;
        assert!(matches!(refused, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        assert_eq!(observation.await.unwrap(), io::ErrorKind::Unsupported);
        client.disconnect().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}
