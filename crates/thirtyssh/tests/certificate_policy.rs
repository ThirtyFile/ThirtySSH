use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thirtyssh::{
    channel::{GlobalReply, Message},
    client,
    forward::AgentForwarding,
    keys::{
        Certificate, PrivateKey, PublicKey,
        ssh_key::{
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        },
        validate_user_certificate_at,
    },
    pty::TerminalSize,
    server,
    session::{self, PtyRequest, Request, X11Request},
    transport::HostKey,
};
use tokio::{io::duplex, sync::Notify, time::timeout};

const USER: &str = "fixture";
const FORCED: &str = "fixture-certificate-command";

#[path = "fixtures/pinned.rs"]
mod pinned;
use pinned::Pinned;

struct Policy {
    authority: PublicKey,
    address: Option<SocketAddr>,
    verified: Arc<AtomicUsize>,
    release: Arc<Notify>,
}

impl server::AuthPolicy for Policy {
    async fn certificate_verified(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> io::Result<bool> {
        self.verified.fetch_add(1, Ordering::Relaxed);
        // Address and command restrictions must be enforced by the runtime
        // even when an application independently authorizes this identity.
        Ok(user == USER && certificate.signature_key() == self.authority.key_data())
    }

    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == b"fixture password")
    }
}

impl session::Handler for Policy {
    async fn channel_open(
        &mut self,
        request: session::IncomingChannel,
        context: &session::Context,
    ) -> io::Result<()> {
        assert_eq!(context.peer_addr(), self.address);
        assert_eq!(request.open_type()?, session::OpenType::Session);
        let mut channel = request.accept(8192, &[]).await?;
        let release = self.release.clone();
        tokio::spawn(async move {
            while let Some(message) = channel.recv().await {
                let request = message.session_request().unwrap();
                if let Some(request) = request {
                    assert_eq!(request.request, Request::Exec(FORCED.as_bytes()));
                    release.notified().await;
                    if request.want_reply {
                        channel.reply(true).await.unwrap();
                    }
                    channel.send(FORCED.as_bytes()).await.unwrap();
                }
            }
        });
        Ok(())
    }

    async fn global_request(
        &mut self,
        _: &mut session::IncomingGlobalRequest<'_>,
        _: &session::Context,
    ) -> io::Result<()> {
        panic!("restricted global request reached the handler");
    }
}

fn key(seed: u8) -> PrivateKey {
    PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap()
}

fn issue(
    identity: &PrivateKey,
    authority: &PrivateKey,
    options: &[(&str, &str)],
    now: u64,
) -> Certificate {
    let mut builder = Builder::new(
        vec![0; 32],
        identity.public_key().key_data().clone(),
        now - 60,
        now + 60,
    )
    .unwrap();
    builder
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal(USER)
        .unwrap();
    for &(name, value) in options {
        builder.critical_option(name, value).unwrap();
    }
    builder.sign(authority).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn restricted_certificate_checks_peer_and_forces_exec_in_channel_order() {
    timeout(Duration::from_secs(10), async {
        let identity = key(21);
        let authority = key(22);
        let time = now();
        let peer: SocketAddr = "[2001:db8::4]:53212".parse().unwrap();
        let certificate = issue(
            &identity, &authority,
            &[("source-address", "192.0.2.0/24,2001:db8::/32"), ("force-command", FORCED)],
            time,
        );
        let rejected = [
            issue(&identity, &authority, &[("source-address", "192.0.2.0/24")], time),
            issue(&identity, &authority, &[("source-address", "::/0,192.0.2.1/24")], time),
            issue(&identity, &authority, &[("source-address", "::/0,broken")], time),
            issue(&identity, &authority, &[("force-command", "")], time),
            issue(&identity, &authority, &[("verify-required", "")], time),
        ];
        assert!(validate_user_certificate_at(&certificate, authority.public_key(), USER, time, Some(peer.ip())).unwrap());
        assert!(!validate_user_certificate_at(&certificate, authority.public_key(), USER, time, None).unwrap());
        let verified = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let host = HostKey::generate().unwrap();
        let pin = Pinned(host.public_key());
        let mut config = server::Config::new(host);
        config.authentication.rejection_delay = Duration::ZERO;
        let (left, right) = duplex(8192);
        let serve = server::accept_over(Arc::new(config), left, Some(peer), Policy {
            authority: authority.public_key().clone(),
            address: Some(peer),
            verified: verified.clone(),
            release: release.clone(),
        });
        let connect = async {
            let mut client = client::connect_over(Arc::new(client::Config::default()), right, pin).await.unwrap();
            for certificate in rejected {
                assert!(!client.authenticate(USER, client::Method::Certificate { certificate: &certificate, key: &identity, algorithm: None }).await.unwrap().is_accepted());
            }
            assert_eq!(verified.load(Ordering::Relaxed), 0);
            assert!(client.authenticate(USER, client::Method::Certificate { certificate: &certificate, key: &identity, algorithm: None }).await.unwrap().is_accepted());
            client
        };
        let (server, client) = tokio::join!(serve, connect);
        let server = server.unwrap();
        let client = client.start().unwrap();
        assert_eq!(verified.load(Ordering::Relaxed), 1);
        for kind in ["auth-agent@openssh.com", "agent-connect"] {
            assert!(matches!(server.handle().prepare_open(kind, 8192, &[]), Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        }
        let handle = client.handle();
        for kind in ["direct-tcpip", "direct-streamlocal@openssh.com", "custom-exec@example.test"] {
            assert!(handle.open_channel(kind, 8192, &[]).await.is_err());
        }
        assert!(handle.open_channel("session", 8192, b"unexpected").await.is_err());
        assert_eq!(handle.global_request("tcpip-forward", &[]).await.unwrap(), GlobalReply::Failure);
        assert_eq!(handle.global_request("custom-command@example.test", &[]).await.unwrap(), GlobalReply::Failure);
        let mut channel = handle.open_session().await.unwrap();
        channel.request(Request::Exec(b"untrusted command"), true).await.unwrap();
        channel.request(Request::Environment { name: "PATH".as_bytes(), value: "/fixture".as_bytes() }, true).await.unwrap();
        channel.request(Request::Pty(PtyRequest::from_modes("vt100", TerminalSize { columns: 80, rows: 24, pixel_width: 0, pixel_height: 0 }, &[]).unwrap()), true).await.unwrap();
        channel.request(Request::AgentForward(AgentForwarding::OpenSsh), true).await.unwrap();
        channel.request(Request::AgentForward(AgentForwarding::Standard), true).await.unwrap();
        channel.request(Request::X11(X11Request { single_connection: false, authentication_protocol: "MIT-MAGIC-COOKIE-1", authentication_cookie: "0123456789abcdef", screen_number: 0 }), true).await.unwrap();
        channel.raw_request("custom-command@example.test", &[], true).await.unwrap();
        channel.request(Request::Keepalive, true).await.unwrap();
        handle.ping().await.unwrap();
        release.notify_one();
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
        for _ in 0..6 {
            assert_eq!(channel.recv().await, Some(Message::Reply { success: false }));
        }
        assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
        assert!(matches!(channel.recv().await, Some(Message::Data(data)) if data == FORCED.as_bytes()));

        handle.rekey().await.unwrap();
        for request in [Request::Shell, Request::Subsystem("sftp")] {
            let mut channel = handle.open_session().await.unwrap();
            channel.request(request, true).await.unwrap();
            release.notify_one();
            assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
            assert!(matches!(channel.recv().await, Some(Message::Data(data)) if data == FORCED.as_bytes()));
        }
        client.disconnect().await.unwrap();
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn caller_owned_stream_with_no_source_rejects_cidr_and_allows_password_retry() {
    timeout(Duration::from_secs(5), async {
        let authority = key(24);
        let identity = key(25);
        let certificate = issue(
            &identity,
            &authority,
            &[("source-address", "::/0,0.0.0.0/0")],
            now(),
        );
        let verified = Arc::new(AtomicUsize::new(0));
        let host = HostKey::generate().unwrap();
        let pin = Pinned(host.public_key());
        let (left, right) = duplex(8192);
        let mut config = server::Config::new(host);
        config.authentication.rejection_delay = Duration::ZERO;
        let server = server::accept_over(
            Arc::new(config),
            left,
            None,
            Policy {
                authority: authority.public_key().clone(),
                address: None,
                verified: verified.clone(),
                release: Arc::new(Notify::new()),
            },
        );
        let client = async {
            let mut client = client::connect_over(Arc::new(client::Config::default()), right, pin)
                .await
                .unwrap();
            assert!(
                !client
                    .authenticate(
                        USER,
                        client::Method::Certificate {
                            certificate: &certificate,
                            key: &identity,
                            algorithm: None
                        }
                    )
                    .await
                    .unwrap()
                    .is_accepted()
            );
            assert!(
                client
                    .authenticate(USER, client::Method::Password("fixture password"))
                    .await
                    .unwrap()
                    .is_accepted()
            );
            client.start().unwrap().disconnect().await.unwrap();
        };
        let (server, ()) = tokio::join!(server, client);
        server.unwrap().await.unwrap();
        assert_eq!(verified.load(Ordering::Relaxed), 0);
    })
    .await
    .unwrap();
}
