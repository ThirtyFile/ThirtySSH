use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use thirtyssh::{
    channel::{Channel, Message},
    client,
    forward::{AgentForwarding, X11Open},
    keys::{Algorithm, Credential},
    server,
    session::{self, Context, IncomingChannel, OpenType, Request, X11Request},
    transport::HostKey,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    sync::mpsc,
    time::timeout,
};

const COOKIE: &str = "00112233445566778899aabbccddeeff"; // A fixture cookie only.
const X11_AUTH: &str = "MIT-MAGIC-COOKIE-1";
const PASSWORD: &str = "duplex fixture password";

#[derive(Default)]
struct Grants {
    x11: AtomicBool,
    agent: AtomicBool,
}

struct AuthorizedPeer {
    key: [u8; 32],
    grants: Arc<Grants>,
    channels: mpsc::Sender<Channel>,
}

impl client::Handler for AuthorizedPeer {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(self.key == key)
    }
}

impl session::Handler for AuthorizedPeer {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        let allowed = match request.open_type() {
            Ok(OpenType::X11(open)) => {
                assert_eq!(
                    (open.originator_address, open.originator_port),
                    ("::1", 6010)
                );
                self.grants.x11.swap(false, Ordering::AcqRel)
            }
            Ok(OpenType::Agent(_)) => self.grants.agent.load(Ordering::Acquire),
            _ => false,
        };
        if !allowed {
            return request.refuse(1).await;
        }
        let channel = request.accept(32 * 1024, &[]).await?;
        self.channels.send(channel).await.map_err(io::Error::other)
    }
}

struct SessionPolicy;
impl server::AuthPolicy for SessionPolicy {
    async fn password(&mut self, user: &str, secret: &[u8]) -> io::Result<bool> {
        Ok(user == "fixture" && secret == PASSWORD.as_bytes())
    }
}

impl session::Handler for SessionPolicy {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        if request.open_type()? != OpenType::Session {
            return Ok(());
        }
        let mut channel = request.accept(8192, &[]).await?;
        let mut refuse_first_agent = true;
        while let Some(message) = channel.recv().await {
            let Some(request) = message.session_request()? else {
                continue;
            };
            let approved = match request.request {
                Request::X11(parameters) => {
                    assert_eq!(
                        parameters,
                        X11Request {
                            single_connection: true,
                            authentication_protocol: X11_AUTH,
                            authentication_cookie: COOKIE,
                            screen_number: 7,
                        }
                    );
                    true
                }
                Request::AgentForward(_) => !std::mem::take(&mut refuse_first_agent),
                _ => false,
            };
            if request.want_reply {
                channel.reply(approved).await?;
            }
        }
        Ok(())
    }
}

async fn round_trip(opened: Channel, accepted: Channel, payload: &'static [u8]) {
    let mut remote = opened.into_io();
    let mut local = accepted.into_io();
    let send = async {
        remote.write_all(payload).await.unwrap();
        remote.shutdown().await.unwrap();
        let mut response = Vec::new();
        remote.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"after SSH EOF");
    };
    let receive = async {
        let mut data = Vec::new();
        local.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, payload);
        local.write_all(b"after SSH EOF").await.unwrap();
        local.shutdown().await.unwrap();
    };
    tokio::join!(send, receive);
}

#[tokio::test]
async fn x11_and_agent_channels_require_grants_and_survive_the_session_channel() {
    timeout(Duration::from_secs(10), async {
        let (a, b) = duplex(8192);
        let host = HostKey::generate().unwrap();
        let grants = Arc::new(Grants::default());
        let (channels, mut incoming) = mpsc::channel(3);
        let peer = AuthorizedPeer { key: host.public_key(), grants: Arc::clone(&grants), channels };
        let connect = async {
            let mut client = client::connect_over(Arc::new(client::Config::default()), b, peer).await.unwrap();
            assert!(client.authenticate("fixture", client::Method::Password(PASSWORD)).await.unwrap().is_accepted());
            client
        };
        let (server, client) = tokio::join!(server::accept_over(Arc::new(server::Config::new(host)), a, None, SessionPolicy), connect);
        let server = server.unwrap();
        let client = client.start().unwrap();
        let server_handle = server.handle();
        let mut control = client.handle().open_session().await.unwrap();
        assert!(matches!(server_handle.open_as(X11Open { originator_address: "::1", originator_port: 6010 }).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        assert!(matches!(server_handle.open_as(AgentForwarding::OpenSsh).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));

        control.request(Request::AgentForward(AgentForwarding::OpenSsh), true).await.unwrap();
        assert_eq!(control.recv().await, Some(Message::Reply { success: false }));
        assert_eq!(control.request(Request::X11(X11Request { single_connection: true, authentication_protocol: X11_AUTH, authentication_cookie: "bad!", screen_number: 7 }), true).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        control.request(Request::X11(X11Request { single_connection: true, authentication_protocol: X11_AUTH, authentication_cookie: COOKIE, screen_number: 7 }), true).await.unwrap();
        assert_eq!(control.recv().await, Some(Message::Reply { success: true }));
        grants.x11.store(true, Ordering::Release);
        control.request(Request::AgentForward(AgentForwarding::OpenSsh), true).await.unwrap();
        assert_eq!(control.recv().await, Some(Message::Reply { success: true }));
        grants.agent.store(true, Ordering::Release);

        let malformed = server_handle.open_channel("auth-agent@openssh.com", 8192, b"unexpected").await;
        assert!(matches!(malformed, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        let x11 = server_handle.open_as(X11Open { originator_address: "::1", originator_port: 6010 }).await.unwrap();
        let x11_peer = incoming.recv().await.unwrap();
        assert!(matches!(server_handle.open_as(X11Open { originator_address: "::1", originator_port: 6010 }).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        let agent = server_handle.open_as(AgentForwarding::OpenSsh).await.unwrap();
        let agent_peer = incoming.recv().await.unwrap();
        let other_agent = server_handle.open_as(AgentForwarding::OpenSsh).await.unwrap();
        let other_agent_peer = incoming.recv().await.unwrap();

        control.close().await.unwrap();
        assert_eq!(control.recv().await, Some(Message::Closed));
        grants.agent.store(false, Ordering::Release);
        assert!(matches!(server_handle.open_as(AgentForwarding::OpenSsh).await, Err(err) if err.kind() == io::ErrorKind::ConnectionRefused));
        tokio::join!(round_trip(x11, x11_peer, b"X bytes"), round_trip(agent, agent_peer, b"agent one"), round_trip(other_agent, other_agent_peer, b"agent two"));
        client.disconnect().await.unwrap();
        server.await.unwrap();
    }).await.unwrap();
}
