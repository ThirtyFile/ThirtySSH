use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thirtyssh::{
    channel::{ChannelIo, Message, driver::Handle},
    client,
    forward::AgentForwarding,
    keys::{
        Algorithm, Credential, PrivateKey, PublicKey, Signature,
        agent::{
            Client, Constraint, Error, Identity,
            server::{self as agent, Policy},
        },
        public::from_ed25519,
        signature::{Signer, Verifier},
        ssh_encoding::Encode,
        ssh_key::certificate::{Builder, CertType},
        system_rng,
    },
    server,
    session::{self, Context as SessionContext, IncomingChannel, OpenType, Request},
    transport::HostKey,
    wire::Reader,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const DATA: &[u8] = b"forwarded signer fixture";
const USER: &str = "fixture";
const PASSWORD: &str = "fixture password";

type RelayTask = JoinHandle<io::Result<(u64, u64)>>;

struct LocalPeer {
    pin: [u8; 32],
    protocol: AgentForwarding,
    granted: Arc<AtomicBool>,
    incoming: mpsc::Sender<io::Result<DuplexStream>>,
    relays: mpsc::Sender<RelayTask>,
}

impl client::Handler for LocalPeer {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(key == self.pin)
    }
}

impl session::Handler for LocalPeer {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        _: &SessionContext,
    ) -> io::Result<()> {
        if request.agent_forwarding().ok().flatten() != Some(self.protocol)
            || !self.granted.load(Ordering::Acquire)
        {
            return request.refuse(1).await;
        }
        let (relay, agent) = duplex(256);
        self.incoming
            .send(Ok(agent))
            .await
            .map_err(io::Error::other)?;
        self.relays
            .send(tokio::spawn(request.relay_agent(relay)))
            .await
            .map_err(io::Error::other)
    }
}

struct Forwarder(AgentForwarding);

impl server::AuthPolicy for Forwarder {
    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == PASSWORD.as_bytes())
    }
}

impl session::Handler for Forwarder {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        _: &SessionContext,
    ) -> io::Result<()> {
        if request.open_type()? != OpenType::Session {
            return request.refuse(1).await;
        }
        let mut control = request.accept(8192, &[]).await?;
        while let Some(message) = control.recv().await {
            if let Some(request) = message.session_request()?
                && request.want_reply
            {
                let authorized = request.request == Request::AgentForward(self.0);
                control.reply(authorized).await?;
            }
        }
        Ok(())
    }
}

async fn sessions(
    protocol: AgentForwarding,
    incoming: mpsc::Sender<io::Result<DuplexStream>>,
    relays: mpsc::Sender<RelayTask>,
) -> (client::Session, server::RunningSession) {
    let (left, right) = duplex(8192);
    let host = HostKey::generate().unwrap();
    let granted = Arc::new(AtomicBool::new(false));
    let peer = LocalPeer {
        pin: host.public_key(),
        protocol,
        granted: granted.clone(),
        incoming,
        relays,
    };
    let mut config = server::Config::new(host);
    config.advertise_agent_forwarding = protocol == AgentForwarding::Standard;
    let connect = async {
        let mut client = client::connect_over(Arc::default(), right, peer)
            .await
            .unwrap();
        assert!(
            client
                .authenticate(USER, client::Method::Password(PASSWORD))
                .await
                .unwrap()
                .is_accepted()
        );
        assert_eq!(client.agent_forwarding(), protocol);
        client
    };
    let (server, client) = tokio::join!(
        server::accept_over(Arc::new(config), left, None, Forwarder(protocol)),
        connect
    );
    let server = server.unwrap();
    let client = client.start().unwrap();
    let peer = server.handle();
    let other = match protocol {
        AgentForwarding::OpenSsh => AgentForwarding::Standard,
        AgentForwarding::Standard => AgentForwarding::OpenSsh,
    };
    expect_refusal(&peer, protocol).await;
    let mut control = client.handle().open_session().await.unwrap();
    control
        .request(Request::AgentForward(other), true)
        .await
        .unwrap();
    assert_eq!(
        control.recv().await,
        Some(Message::Reply { success: false })
    );
    control
        .request(Request::AgentForward(protocol), true)
        .await
        .unwrap();
    assert_eq!(control.recv().await, Some(Message::Reply { success: true }));
    granted.store(true, Ordering::Release);
    expect_refusal(&peer, other).await;
    (client, server)
}

async fn expect_refusal(peer: &Handle, protocol: AgentForwarding) {
    assert!(
        matches!(peer.open_as(protocol).await, Err(error) if error.kind() == io::ErrorKind::ConnectionRefused)
    );
}

#[derive(Clone)]
struct Confirmation(mpsc::Sender<oneshot::Sender<bool>>);

impl Policy for Confirmation {
    async fn approve_signature(&mut self, _: &PublicKey) -> bool {
        let (reply, decision) = oneshot::channel();
        self.0.send(reply).await.is_ok() && decision.await.unwrap_or(false)
    }
}

#[tokio::test]
async fn both_forwarding_protocols_relay_approval_and_cancel_work_after_disconnect() {
    for protocol in [AgentForwarding::OpenSsh, AgentForwarding::Standard] {
        timeout(Duration::from_secs(8), async {
            let (incoming, mut receiver) = mpsc::channel(4);
            let (relays, mut relay_tasks) = mpsc::channel(4);
            let (confirm, mut approvals) = mpsc::channel(2);
            let agent_service = tokio::spawn(agent::run(
                async move || receiver.recv().await,
                Confirmation(confirm),
            ));
            let (local, admin) = duplex(256);
            incoming.send(Ok(local)).await.unwrap();
            let mut admin = Client::new(admin);
            let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
            let protected = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
            admin.add(&key, &[]).await.unwrap();
            admin
                .add(&protected, &[Constraint::ConfirmEachUse])
                .await
                .unwrap();
            let (client, server) = sessions(protocol, incoming.clone(), relays).await;
            let peer = server.handle();
            let mut first = Client::new(peer.open_as(protocol).await.unwrap().into_io());
            let mut second = Client::new(peer.open_as(protocol).await.unwrap().into_io());
            let first_relay = relay_tasks.recv().await.unwrap();
            let second_relay = relay_tasks.recv().await.unwrap();
            let (ids, other) = tokio::join!(first.identities(), second.identities());
            assert_eq!(ids.unwrap().len(), 2);
            assert_eq!(other.unwrap().len(), 2);
            let identity = Identity::new(key.public_key().clone(), "");
            let signature = first.sign(identity.credential(), None, DATA).await.unwrap();
            Verifier::verify(key.public_key(), DATA, &signature).unwrap();
            authenticate_through_agent(
                &mut first,
                key.public_key().key_data().ed25519().unwrap().0,
            )
            .await;
            let restricted = Identity::new(protected.public_key().clone(), "");
            let deny = async {
                approvals.recv().await.unwrap().send(false).unwrap();
            };
            let (result, ()) = tokio::join!(second.sign(restricted.credential(), None, DATA), deny);
            assert!(matches!(result, Err(Error::Refused)));

            let sign =
                tokio::spawn(async move { second.sign(restricted.credential(), None, DATA).await });
            let mut pending = approvals.recv().await.unwrap();
            client.disconnect().await.unwrap();
            pending.closed().await;
            assert!(matches!(sign.await.unwrap(), Err(Error::Io(_))));
            let _ = first_relay.await.unwrap();
            let _ = second_relay.await.unwrap();
            server.await.unwrap();
            assert_eq!(admin.identities().await.unwrap().len(), 2);
            drop((admin, incoming));
            agent_service.await.unwrap();
        })
        .await
        .unwrap();
    }
}

async fn authenticate_through_agent(signer: &mut Client<ChannelIo>, user_key: [u8; 32]) {
    struct HostPin([u8; 32]);
    impl session::Handler for HostPin {}
    impl client::Handler for HostPin {
        async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
            let Some(key) = host.ed25519() else {
                return Ok(false);
            };
            Ok(key == self.0)
        }
    }
    struct KeyPolicy([u8; 32]);
    impl session::Handler for KeyPolicy {}
    impl server::AuthPolicy for KeyPolicy {
        async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
            Ok(user == USER && key == &self.0)
        }
    }
    let host = HostKey::generate().unwrap();
    let pin = HostPin(host.public_key());
    let (a, b) = duplex(8192);
    let use_signer = async {
        let mut client = client::connect_over(Arc::default(), b, pin).await.unwrap();
        assert!(
            client
                .authenticate_with(USER, &from_ed25519(&user_key).into(), None, signer)
                .await
                .unwrap()
                .is_accepted()
        );
        client.start().unwrap().disconnect().await.unwrap();
    };
    let serve = async {
        server::accept_over(
            Arc::new(server::Config::new(host)),
            a,
            None,
            KeyPolicy(user_key),
        )
        .await
        .unwrap()
        .await
        .unwrap();
    };
    tokio::join!(serve, use_signer);
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires an isolated, empty Pageant instance on the Windows desktop"]
async fn a_forwarded_pageant_key_authenticates_over_both_transports() {
    use pageant::{Pageant, Transport};

    timeout(Duration::from_secs(8), async {
        let preferred = Pageant::connect().await.unwrap();
        assert_eq!(preferred.transport(), Transport::NamedPipe);
        let mut admin = Client::new(preferred);
        assert!(admin.identities().await.unwrap().is_empty());
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        admin.add(&key, &[]).await.unwrap();
        let streams = [
            (
                AgentForwarding::Standard,
                Pageant::connect_over(Transport::NamedPipe).await.unwrap(),
            ),
            (
                AgentForwarding::OpenSsh,
                Pageant::connect_over(Transport::WindowMessage)
                    .await
                    .unwrap(),
            ),
        ];
        for (protocol, mut pageant) in streams {
            let (incoming, mut local) = mpsc::channel(1);
            let (relays, mut relay_tasks) = mpsc::channel(1);
            let (client, server) = sessions(protocol, incoming, relays).await;
            let proxy = async {
                let mut socket = local.recv().await.unwrap().unwrap();
                tokio::io::copy_bidirectional(&mut socket, &mut pageant).await
            };
            let verify = async {
                let remote = server.handle().open_as(protocol).await.unwrap();
                let mut forwarded = Client::new(remote.into_io());
                let identities = forwarded.identities().await.unwrap();
                assert_eq!(identities.len(), 1);
                let signature = forwarded.sign(identities[0].credential(), None, DATA).await.unwrap();
                Verifier::verify(key.public_key(), DATA, &signature).unwrap();
                authenticate_through_agent(&mut forwarded, key.public_key().key_data().ed25519().unwrap().0).await;
            };
            tokio::select! {
                () = verify => {},
                outcome = proxy => panic!("Pageant relay closed before authentication: {outcome:?}"),
            }
            client.disconnect().await.unwrap();
            let _ = relay_tasks.recv().await.unwrap().await.unwrap();
            server.await.unwrap();
        }
        admin.remove(key.public_key()).await.unwrap();
        assert!(admin.identities().await.unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_forwarded_certificate_keeps_the_exact_agent_signing_identity() {
    timeout(Duration::from_secs(8), async {
        let (incoming, mut agent_streams) = mpsc::channel(2);
        let (relays, mut relay_tasks) = mpsc::channel(2);
        let protocol = AgentForwarding::Standard;
        let (client, server) = sessions(protocol, incoming, relays).await;
        let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let ca = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut builder =
            Builder::new_with_random_nonce(&mut system_rng(), key.public_key(), now - 10, now + 60)
                .unwrap();
        builder
            .cert_type(CertType::User)
            .unwrap()
            .valid_principal(USER)
            .unwrap();
        let certificate = builder.sign(&ca).unwrap();
        let blob = certificate.to_bytes().unwrap();
        let remote = server.handle().open_as(protocol).await.unwrap();
        let mut local = agent_streams.recv().await.unwrap().unwrap();
        let relay = relay_tasks.recv().await.unwrap();
        let serve = async {
            assert_eq!(local.read_u32().await.unwrap(), 1);
            assert_eq!(local.read_u8().await.unwrap(), 11);
            let mut response = vec![12];
            1u32.encode(&mut response).unwrap();
            blob.encode(&mut response).unwrap();
            "certificate fixture".encode(&mut response).unwrap();
            local.write_u32(response.len() as u32).await.unwrap();
            local.write_all(&response).await.unwrap();
            let count = local.read_u32().await.unwrap() as usize;
            assert!(count <= 1024);
            let mut packet = vec![0; count];
            local.read_exact(&mut packet).await.unwrap();
            let mut reader = Reader::new(&packet);
            assert_eq!(reader.byte().unwrap(), 13);
            assert_eq!(reader.string().unwrap(), blob);
            assert_eq!(reader.string().unwrap(), DATA);
            assert_eq!(reader.uint32().unwrap(), 0);
            reader.finish().unwrap();
            let signature: Signature = key.try_sign(DATA).unwrap();
            let mut response = vec![14];
            signature.encode_prefixed(&mut response).unwrap();
            local.write_u32(response.len() as u32).await.unwrap();
            local.write_all(&response).await.unwrap();
        };
        let connect = async {
            let mut remote = Client::new(remote.into_io());
            let identity = remote.identities().await.unwrap().pop().unwrap();
            assert_eq!(
                identity,
                Identity::new(certificate.clone(), "certificate fixture")
            );
            let signature = remote
                .sign(identity.credential(), None, DATA)
                .await
                .unwrap();
            Verifier::verify(key.public_key(), DATA, &signature).unwrap();
        };
        tokio::join!(serve, connect);
        drop(local);
        client.disconnect().await.unwrap();
        let _ = relay.await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}
