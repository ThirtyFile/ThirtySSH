use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    future::pending,
    io::{self, ErrorKind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thirtyssh::{
    auth::{
        Banner, Client, GssContext, GssInput, GssProgress, GssRejection, Outcome, SignRequest,
        Signer,
    },
    client::{self, PreAuth},
    keys::{
        Algorithm, Certificate, CertificateRevocations, Credential, PrivateKey, PublicKey,
        public::from_ed25519,
        ssh_key::{
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        },
        validate_certificate_at,
    },
    server, session,
    transport::{HostKey, Transport},
    wire::Reader,
};
use tokio::{io::duplex, sync::oneshot, time::timeout};

const USER: &str = "fixture";
const KEY_TYPE: &[u8] = b"ssh-ed25519";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct Pinned {
    key: [u8; 32],
    banners: Arc<Mutex<Vec<Banner>>>,
}

impl session::Handler for Pinned {}
impl client::Handler for Pinned {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(self.key == key)
    }

    async fn banner(&mut self, banner: &Banner, _: &mut PreAuth) -> io::Result<()> {
        self.banners.lock().unwrap().push(banner.clone());
        Ok(())
    }
}

struct BannerNotification {
    key: [u8; 32],
    entered: Option<oneshot::Sender<()>>,
    block: bool,
}

impl session::Handler for BannerNotification {}

impl client::Handler for BannerNotification {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(key == self.key)
    }

    async fn banner(&mut self, _: &Banner, _: &mut PreAuth) -> io::Result<()> {
        self.entered.take().unwrap().send(()).unwrap();
        if self.block { pending().await } else { Ok(()) }
    }
}

#[tokio::test]
async fn an_interrupted_banner_between_attempts_cannot_resume_authentication() {
    timeout(TEST_TIMEOUT, async {
        for cancel in [false, true] {
            let host = HostKey::generate().unwrap();
            let (left, right) = duplex(4096);
            let (enter, entered) = oneshot::channel();
            let (reject, rejected) = oneshot::channel();
            let client = async {
                let config = Arc::new(client::Config {
                    authentication_timeout: Duration::from_millis(250),
                    ..Default::default()
                });
                let mut client = client::connect_over(config, left, BannerNotification {
                    key: host.public_key(), entered: Some(enter), block: true,
                }).await.unwrap();
                assert!(matches!(client.authenticate(USER, client::Method::None).await.unwrap(), Outcome::Rejected { .. }));
                reject.send(()).unwrap();

                if cancel {
                    tokio::select! {
                        result = client.wait_for_command(pending::<()>()) => panic!("unexpected completion: {result:?}"),
                        result = entered => result.unwrap(),
                    }
                } else {
                    let error = client.wait_for_command(pending::<()>()).await.unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::TimedOut);
                    entered.await.unwrap();
                }
                assert!(client.is_unusable());
                assert_eq!(client.authenticate(USER, client::Method::None).await.unwrap_err().kind(), ErrorKind::BrokenPipe);
            };
            let peer = async {
                let mut peer = Transport::accept(right, &host).await.unwrap();
                assert_eq!(peer.receive().await.unwrap(), b"\x05\0\0\0\x0cssh-userauth");
                peer.send(b"\x06\0\0\0\x0cssh-userauth").await.unwrap();
                assert_eq!(peer.receive().await.unwrap()[0], 50);
                let mut failure = vec![51];
                fields(&mut failure, &[b"password"]);
                failure.push(0);
                peer.send(&failure).await.unwrap();
                rejected.await.unwrap();
                let mut banner = vec![53];
                fields(&mut banner, &[b"fixture banner", b"en"]);
                peer.send(&banner).await.unwrap();
                assert_eq!(peer.receive().await.unwrap_err().kind(), ErrorKind::UnexpectedEof);
            };
            tokio::join!(client, peer);
        }
    }).await.unwrap();
}

struct DeferredSigner {
    signer: External,
    started: Option<oneshot::Sender<()>>,
    proceed: Option<oneshot::Receiver<()>>,
}

impl Signer for DeferredSigner {
    async fn auth_sign(&mut self, request: SignRequest<'_>) -> io::Result<Vec<u8>> {
        self.started.take().unwrap().send(()).unwrap();
        self.proceed.take().unwrap().await.unwrap();
        self.signer.auth_sign(request).await
    }
}

#[tokio::test]
async fn receives_banner_while_an_external_signer_is_waiting() {
    timeout(TEST_TIMEOUT, async {
        let host = HostKey::generate().unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public = key.public_key().as_ref().try_into().unwrap();
        let (left, right) = duplex(4096);
        let (send_banner, signer_started) = oneshot::channel();
        let (allow_signer, proceed) = oneshot::channel();
        let (notify, observed) = oneshot::channel();
        let handler = BannerNotification {
            key: host.public_key(),
            entered: Some(notify),
            block: false,
        };
        let client = async {
            let mut client = client::connect_over(Arc::default(), left, handler)
                .await
                .unwrap();
            let mut signer = DeferredSigner {
                signer: External {
                    key,
                    response: Response::Sign,
                    calls: 0,
                },
                started: Some(send_banner),
                proceed: Some(proceed),
            };
            assert_eq!(
                client
                    .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut signer)
                    .await
                    .unwrap(),
                Outcome::Accepted
            );
            assert_eq!(signer.signer.calls, 1);
            client.disconnect_with(11, "", "").await.unwrap();
        };
        let peer = async {
            let mut peer = Transport::accept(right, &host).await.unwrap();
            assert_eq!(peer.receive().await.unwrap(), b"\x05\0\0\0\x0cssh-userauth");
            peer.send(b"\x06\0\0\0\x0cssh-userauth").await.unwrap();
            let probe = peer.receive().await.unwrap();
            assert_eq!(probe[0], 50);
            let mut reader = Reader::new(&probe[1..]);
            for expected in [USER.as_bytes(), b"ssh-connection", b"publickey"] {
                assert_eq!(reader.string().unwrap(), expected);
            }
            assert!(!reader.boolean().unwrap());
            let algorithm = reader.string().unwrap();
            let key = reader.string().unwrap();
            reader.finish().unwrap();
            let mut accepted = vec![60];
            fields(&mut accepted, &[algorithm, key]);
            peer.send(&accepted).await.unwrap();

            signer_started.await.unwrap();
            let mut banner = vec![53];
            fields(&mut banner, &[b"fixture banner", b"en"]);
            peer.send(&banner).await.unwrap();
            observed.await.unwrap();
            allow_signer.send(()).unwrap();
            assert_eq!(peer.receive().await.unwrap()[0], 50);
            peer.send(&[52]).await.unwrap();
            assert_eq!(peer.receive().await.unwrap()[0], 1);
        };
        tokio::join!(client, peer);
    })
    .await
    .unwrap();
}

struct Policy {
    key: [u8; 32],
    offers: Arc<AtomicUsize>,
    verified: Arc<AtomicUsize>,
}

impl session::Handler for Policy {}
impl server::AuthPolicy for Policy {
    async fn public_key_offered(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        self.offers.fetch_add(1, Ordering::Relaxed);
        Ok(user == USER && key == &self.key)
    }

    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        self.verified.fetch_add(1, Ordering::Relaxed);
        Ok(user == USER && key == &self.key)
    }

    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == USER && password == b"fixture password")
    }
}

fn fields(packet: &mut Vec<u8>, fields: &[&[u8]]) {
    for field in fields {
        packet.extend_from_slice(&(field.len() as u32).to_be_bytes());
        packet.extend_from_slice(field);
    }
}

#[derive(Clone, Copy)]
enum Response {
    Sign,
    Refuse,
    WrongAlgorithm,
    Wait,
}

struct External {
    key: Ed25519KeyPair,
    response: Response,
    calls: usize,
}

impl Signer for External {
    async fn auth_sign(&mut self, request: SignRequest<'_>) -> io::Result<Vec<u8>> {
        self.calls += 1;
        assert_eq!(request.algorithm, "ssh-ed25519");
        let mut data = Reader::new(request.data);
        let session_id = data.string().unwrap();
        assert_eq!(session_id.len(), 32);
        assert_ne!(session_id, [0; 32]);
        assert_eq!(data.byte().unwrap(), 50);
        assert_eq!(data.string().unwrap(), USER.as_bytes());
        assert_eq!(data.string().unwrap(), b"ssh-connection");
        assert_eq!(data.string().unwrap(), b"publickey");
        assert!(data.boolean().unwrap());
        let name = data.string().unwrap();
        if Certificate::from_bytes(request.public_key).is_ok() {
            assert_eq!(name, b"ssh-ed25519-cert-v01@openssh.com");
        } else {
            assert_eq!(name, KEY_TYPE);
        }
        assert_eq!(data.string().unwrap(), request.public_key);
        data.finish().unwrap();

        let algorithm = match self.response {
            Response::Sign => KEY_TYPE,
            Response::Refuse => return Err(io::Error::from(ErrorKind::PermissionDenied)),
            Response::WrongAlgorithm => b"rsa-sha2-256",
            Response::Wait => return pending().await,
        };
        let mut signature = Vec::new();
        fields(
            &mut signature,
            &[algorithm, self.key.sign(request.data).as_ref()],
        );
        Ok(signature)
    }
}

struct CertificatePolicy {
    authority: PublicKey,
    revoked: CertificateRevocations,
    verified: Arc<AtomicUsize>,
    time: u64,
}

impl session::Handler for CertificatePolicy {}
impl server::AuthPolicy for CertificatePolicy {
    async fn certificate_probe(&mut self, user: &str, cert: &Certificate) -> io::Result<bool> {
        Ok(!self.revoked.is_revoked(cert)
            && validate_certificate_at(cert, &self.authority, user, CertType::User, self.time)?)
    }

    async fn certificate_verified(&mut self, user: &str, cert: &Certificate) -> io::Result<bool> {
        self.verified.fetch_add(1, Ordering::Relaxed);
        self.certificate_probe(user, cert).await
    }
}

#[tokio::test]
async fn certificate_authentication_rejects_untrusted_claims_before_requesting_a_signature() {
    timeout(TEST_TIMEOUT, async {
        let private =
            |seed| PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap();
        let identity = private(7);
        let ca = private(8);
        let other = private(9);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issue = |authority: &PrivateKey, serial, principal, usage, expiry, restricted| {
            let mut builder = Builder::new(
                vec![0; 32],
                identity.public_key().key_data().clone(),
                now - 60,
                expiry,
            )
            .unwrap();
            builder
                .serial(serial)
                .unwrap()
                .cert_type(usage)
                .unwrap()
                .valid_principal(principal)
                .unwrap();
            if restricted {
                builder
                    .critical_option("require-valid-test@example.test", "fixture")
                    .unwrap();
            }
            builder.sign(authority).unwrap()
        };
        let good = issue(&ca, 1, USER, CertType::User, now + 60, false);
        let host_cert = issue(&ca, 1, USER, CertType::Host, now + 60, false);
        let mut tampered = good.to_bytes().unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        let rejected = [
            issue(&other, 1, USER, CertType::User, now + 60, false),
            issue(&ca, 1, "different-user", CertType::User, now + 60, false),
            issue(&ca, 1, USER, CertType::User, now, false),
            issue(&ca, 1, USER, CertType::User, now + 60, true),
            issue(&ca, 2, USER, CertType::User, now + 60, false),
            Certificate::from_bytes(&tampered).unwrap(),
        ];
        let mut revoked = CertificateRevocations::default();
        revoked.revoke_serial(ca.public_key(), 2);
        let verified = Arc::new(AtomicUsize::new(0));
        let host = HostKey::generate().unwrap();
        let pin = host.public_key();
        let mut config = server::Config::new(host);
        config.authentication.rejection_delay = Duration::ZERO;
        let (a, b) = duplex(8192);
        let server = server::accept_over(
            Arc::new(config),
            a,
            None,
            CertificatePolicy {
                authority: ca.public_key().clone(),
                revoked,
                verified: verified.clone(),
                time: now,
            },
        );
        let client = async {
            let mut client = client::connect_over(
                Arc::new(client::Config::default()),
                b,
                Pinned {
                    key: pin,
                    banners: Arc::default(),
                },
            )
            .await
            .unwrap();
            let mut signer = External {
                key: Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap(),
                response: Response::Sign,
                calls: 0,
            };
            assert_eq!(
                client
                    .authenticate(
                        USER,
                        client::Method::Certificate {
                            certificate: &good,
                            key: &other,
                            algorithm: None
                        }
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                client
                    .authenticate_with(
                        USER,
                        &Credential::from(host_cert.clone()),
                        None,
                        &mut signer
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            for cert in rejected {
                assert!(
                    !client
                        .authenticate_with(USER, &Credential::from(cert.clone()), None, &mut signer)
                        .await
                        .unwrap()
                        .is_accepted()
                );
            }
            assert_eq!(signer.calls, 0);
            assert_eq!(
                client
                    .authenticate_with(USER, &Credential::from(good.clone()), None, &mut signer)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(verified.load(Ordering::Relaxed), 0);
            signer.key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
            assert!(
                client
                    .authenticate_with(USER, &Credential::from(good.clone()), None, &mut signer)
                    .await
                    .unwrap()
                    .is_accepted()
            );
            assert_eq!(signer.calls, 2);
            assert_eq!(verified.load(Ordering::Relaxed), 1);
            client.start().unwrap().disconnect().await.unwrap();
        };
        let (server, ()) = tokio::join!(server, client);
        server.unwrap().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn external_signer_handles_probe_rejection_local_errors_and_retry() {
    timeout(TEST_TIMEOUT, async {
        let identity = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public = identity.public_key().as_ref().try_into().unwrap();
        let mut signer = External {
            key: identity,
            response: Response::Refuse,
            calls: 0,
        };
        let host = HostKey::generate().unwrap();
        let offers = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));
        let banners = Arc::new(Mutex::new(Vec::new()));
        let banner = Banner {
            message: "fixture banner".into(),
            language: "en".into(),
        };
        let (a, b) = duplex(4096);
        let mut config = server::Config::new(host.clone());
        config.authentication.rejection_delay = Duration::ZERO;
        config.authentication.banner = Some(banner.clone());
        let server = server::accept_over(
            Arc::new(config),
            a,
            None,
            Policy {
                key: public,
                offers: offers.clone(),
                verified: verified.clone(),
            },
        );
        let client = async {
            let mut client = client::connect_over(
                Arc::new(client::Config {
                    authentication_timeout: Duration::from_millis(100),
                    ..Default::default()
                }),
                b,
                Pinned {
                    key: host.public_key(),
                    banners: banners.clone(),
                },
            )
            .await
            .unwrap();
            assert_eq!(
                client
                    .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut signer)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::PermissionDenied
            );
            assert_eq!(
                banners.lock().unwrap().as_slice(),
                std::slice::from_ref(&banner)
            );
            assert_eq!(signer.calls, 1);

            let unknown = HostKey::generate().unwrap().public_key();
            let rejected = client
                .authenticate_with(USER, &from_ed25519(&unknown).into(), None, &mut signer)
                .await
                .unwrap();
            assert!(matches!(
                rejected,
                Outcome::Rejected {
                    partial_success: false,
                    ..
                }
            ));
            assert_eq!(signer.calls, 1, "a rejected probe must not ask the signer");
            assert_eq!(*banners.lock().unwrap(), [banner]);

            for (response, kind) in [
                (Response::WrongAlgorithm, ErrorKind::InvalidData),
                (Response::Wait, ErrorKind::TimedOut),
            ] {
                signer.response = response;
                assert_eq!(
                    client
                        .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut signer)
                        .await
                        .unwrap_err()
                        .kind(),
                    kind
                );
            }
            let mut wrong_key = External {
                key: Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap(),
                response: Response::Sign,
                calls: 0,
            };
            assert_eq!(
                client
                    .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut wrong_key)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(verified.load(Ordering::Relaxed), 0);

            signer.response = Response::Sign;
            assert_eq!(
                client
                    .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut signer)
                    .await
                    .unwrap(),
                Outcome::Accepted
            );
            assert_eq!(offers.load(Ordering::Relaxed), 6);
            assert_eq!(verified.load(Ordering::Relaxed), 1);
            assert_eq!(signer.calls, 4);
            assert_eq!(wrong_key.calls, 1);
            assert_eq!(banners.lock().unwrap().len(), 1);
            client.start().unwrap().disconnect().await.unwrap();
        };
        let (server, ()) = tokio::join!(server, client);
        server.unwrap().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unexpected_probe_replies_leave_authentication_unusable() {
    timeout(TEST_TIMEOUT, async {
        let host = HostKey::generate().unwrap();
        let mut signer = External {
            key: Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap(),
            response: Response::Sign,
            calls: 0,
        };
        let public: [u8; 32] = signer.key.public_key().as_ref().try_into().unwrap();
        let mut wrong_algorithm = vec![60];
        let mut real_key_blob = Vec::new();
        fields(&mut real_key_blob, &[KEY_TYPE, &public]);
        fields(&mut wrong_algorithm, &[b"rsa-sha2-256", &real_key_blob]);
        let mut wrong_key = vec![60];
        let mut wrong_key_blob = Vec::new();
        fields(&mut wrong_key_blob, &[KEY_TYPE, &[8; 32]]);
        fields(&mut wrong_key, &[KEY_TYPE, &wrong_key_blob]);
        let mut trailing = vec![60];
        fields(&mut trailing, &[KEY_TYPE, &real_key_blob, b"unexpected"]);

        for reply in [vec![52], wrong_algorithm, wrong_key, trailing] {
            let (a, b) = duplex(4096);
            let server = async {
                let mut peer = Transport::accept(a, &host).await.unwrap();
                assert_eq!(peer.receive().await.unwrap(), b"\x05\0\0\0\x0cssh-userauth");
                peer.send(b"\x06\0\0\0\x0cssh-userauth").await.unwrap();
                let probe = peer.receive().await.unwrap();
                let mut expected = vec![50];
                fields(
                    &mut expected,
                    &[USER.as_bytes(), b"ssh-connection", b"publickey"],
                );
                expected.push(0);
                fields(&mut expected, &[KEY_TYPE, &real_key_blob]);
                assert_eq!(probe, expected);
                peer.send(&reply).await.unwrap();
            };
            let client = async {
                let transport = Transport::connect(b, |k| *k == host.public_key())
                    .await
                    .unwrap();
                let mut client = Client::new(transport);
                assert_eq!(
                    client
                        .authenticate_with(USER, &from_ed25519(&public).into(), None, &mut signer)
                        .await
                        .unwrap_err()
                        .kind(),
                    ErrorKind::InvalidData
                );
                assert_eq!(
                    client
                        .authenticate(USER, client::Method::None)
                        .await
                        .unwrap_err()
                        .kind(),
                    ErrorKind::BrokenPipe
                );
                assert!(client.into_authenticated().is_err());
            };
            tokio::join!(server, client);
        }
        assert_eq!(signer.calls, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_server_rejects_a_stale_session_signature_before_authorization() {
    timeout(TEST_TIMEOUT, async {
        let host = HostKey::generate().unwrap();
        let identity = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public = identity.public_key().as_ref().try_into().unwrap();
        let offers = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));
        let (a, b) = duplex(4096);
        let mut config = server::Config::new(host.clone());
        config.authentication.rejection_delay = Duration::ZERO;
        let server = server::accept_over(
            Arc::new(config),
            a,
            None,
            Policy {
                key: public,
                offers: offers.clone(),
                verified: verified.clone(),
            },
        );
        let client = async {
            let mut peer = Transport::connect(b, |k| *k == host.public_key())
                .await
                .unwrap();
            peer.send(b"\x05\0\0\0\x0cssh-userauth").await.unwrap();
            assert_eq!(peer.receive().await.unwrap(), b"\x06\0\0\0\x0cssh-userauth");

            let mut request = vec![50];
            fields(
                &mut request,
                &[USER.as_bytes(), b"ssh-connection", b"publickey"],
            );
            request.push(1);
            let mut blob = Vec::new();
            fields(&mut blob, &[KEY_TYPE, &public]);
            fields(&mut request, &[KEY_TYPE, &blob]);
            let mut signed = Vec::new();
            fields(&mut signed, &[&[0; 32]]);
            signed.extend_from_slice(&request);
            let mut signature = Vec::new();
            fields(&mut signature, &[KEY_TYPE, identity.sign(&signed).as_ref()]);
            fields(&mut request, &[&signature]);
            peer.send(&request).await.unwrap();
            assert_eq!(peer.receive().await.unwrap()[0], 51);
            assert_eq!(offers.load(Ordering::Relaxed), 0);
            assert_eq!(verified.load(Ordering::Relaxed), 0);

            let mut fallback = vec![50];
            fields(
                &mut fallback,
                &[USER.as_bytes(), b"ssh-connection", b"password"],
            );
            fallback.push(0);
            fields(&mut fallback, &[b"fixture password"]);
            peer.send(&fallback).await.unwrap();
            assert_eq!(peer.receive().await.unwrap(), [52]);
            peer.disconnect().await.unwrap();
        };
        let (server, ()) = tokio::join!(server, client);
        server.unwrap().await.unwrap();
    })
    .await
    .unwrap();
}

/// A scripted security context that records what the exchange gave it.
struct ScriptedContext {
    steps: Vec<GssProgress>,
    inputs: Vec<Vec<u8>>,
    mic: bool,
    mic_data: Option<Vec<u8>>,
    rejections: Vec<GssRejection>,
}

impl GssContext for ScriptedContext {
    async fn step(&mut self, input: GssInput<'_>) -> io::Result<GssProgress> {
        let (GssInput::Mechanism(bytes) | GssInput::Token(bytes)) = input;
        // The mechanism arrives first, and only once.
        assert_eq!(
            matches!(input, GssInput::Mechanism(_)),
            self.inputs.is_empty()
        );
        self.inputs.push(bytes.to_vec());
        Ok(self.steps.remove(0))
    }

    async fn mic(&mut self, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        assert!(self.steps.is_empty() && self.mic_data.is_none());
        self.mic_data = Some(data.to_vec());
        Ok(self.mic.then(|| b"fixture mic".to_vec()))
    }

    async fn rejected(&mut self, rejection: GssRejection) {
        self.rejections.push(rejection);
    }
}

#[tokio::test]
async fn gssapi_exchanges_tokens_binds_the_mic_to_the_session_and_reports_rejections() {
    const MECHANISM: &[u8] = &[0x06, 2, 0x2a, 3];
    for with_mic in [true, false] {
        timeout(TEST_TIMEOUT, async {
            let host = HostKey::generate().unwrap();
            let (left, right) = duplex(4096);
            let handler = Pinned {
                key: host.public_key(),
                banners: Arc::default(),
            };
            let mut context = ScriptedContext {
                steps: if with_mic {
                    vec![
                        GssProgress::Continue(b"first".to_vec()),
                        GssProgress::Established(Some(b"last".to_vec())),
                    ]
                } else {
                    vec![GssProgress::Established(None)]
                },
                inputs: Vec::new(),
                mic: with_mic,
                mic_data: None,
                rejections: Vec::new(),
            };
            let client = async {
                let mut client = client::connect_over(Arc::default(), left, handler)
                    .await
                    .unwrap();
                let result = client
                    .gssapi(USER, &[MECHANISM.to_vec()], &mut context)
                    .await
                    .unwrap();
                client.disconnect_with(11, "", "").await.unwrap();
                result
            };
            let peer = async {
                let mut peer = Transport::accept(right, &host).await.unwrap();
                assert_eq!(peer.receive().await.unwrap(), b"\x05\0\0\0\x0cssh-userauth");
                peer.send(b"\x06\0\0\0\x0cssh-userauth").await.unwrap();
                let mut bound = Vec::new();
                fields(&mut bound, &[peer.session_id()]);
                bound.push(50);
                fields(
                    &mut bound,
                    &[USER.as_bytes(), b"ssh-connection", b"gssapi-with-mic"],
                );
                let mut offer = bound[4 + peer.session_id().len()..].to_vec();
                offer.extend_from_slice(&1u32.to_be_bytes());
                fields(&mut offer, &[MECHANISM]);
                assert_eq!(peer.receive().await.unwrap(), offer);
                let token = |code: u8, value: &[u8]| {
                    let mut packet = vec![code];
                    fields(&mut packet, &[value]);
                    packet
                };
                peer.send(&token(60, MECHANISM)).await.unwrap();
                if with_mic {
                    assert_eq!(peer.receive().await.unwrap(), token(61, b"first"));
                    peer.send(&token(61, b"server token")).await.unwrap();
                    assert_eq!(peer.receive().await.unwrap(), token(61, b"last"));
                    assert_eq!(peer.receive().await.unwrap(), token(66, b"fixture mic"));
                    peer.send(&[52]).await.unwrap();
                } else {
                    // No token and no MIC: the exchange is only marked complete.
                    assert_eq!(peer.receive().await.unwrap(), [63]);
                    let mut status = vec![64, 0, 0, 0, 1, 0, 0, 0, 2];
                    fields(&mut status, &[b"denied", b"en"]);
                    peer.send(&status).await.unwrap();
                    peer.send(&token(65, b"error token")).await.unwrap();
                    let mut failure = token(51, b"password");
                    failure.push(0);
                    peer.send(&failure).await.unwrap();
                }
                assert_eq!(peer.receive().await.unwrap()[0], 1);
                bound
            };
            let (result, bound) = tokio::join!(client, peer);
            assert_eq!(context.mic_data, Some(bound));
            if with_mic {
                assert_eq!(result, Outcome::Accepted);
                assert_eq!(context.inputs, [MECHANISM, b"server token"]);
                assert!(context.rejections.is_empty());
            } else {
                assert_eq!(
                    result,
                    Outcome::Rejected {
                        remaining_methods: vec!["password".into()],
                        partial_success: false,
                    }
                );
                assert_eq!(context.inputs, [MECHANISM]);
                assert_eq!(
                    context.rejections,
                    [
                        GssRejection::Status {
                            major: 1,
                            minor: 2,
                            message: "denied".into(),
                        },
                        GssRejection::Token(b"error token".to_vec()),
                    ]
                );
            }
        })
        .await
        .unwrap();
    }
}
