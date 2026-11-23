use super::*;
use crate::{
    auth, server, session,
    transport::{HostKey, Transport},
};
use std::time::Duration;
use tokio::{io::duplex, time::timeout};

struct Password;

impl server::AuthPolicy for Password {
    async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
        Ok(user == "fixture" && password == b"fixture-password")
    }
}

impl session::Handler for Password {}

#[tokio::test]
async fn only_abandoned_cancellable_writes_wake_route_settlement() {
    fn was_notified(wake: &Notify) -> bool {
        let mut notified = std::pin::pin!(wake.notified());
        notified
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_ready()
    }

    let wake = Arc::new(Notify::new());
    let (reply, result) = oneshot::channel();
    reply.send(Ok(())).unwrap();
    WriteReceipt {
        result,
        cancel_wake: Some(wake.clone()),
    }
    .await
    .unwrap();
    assert!(!was_notified(&wake));

    let (reply, result) = oneshot::channel();
    drop(WriteReceipt {
        result,
        cancel_wake: Some(wake.clone()),
    });
    assert!(reply.is_closed());
    assert!(was_notified(&wake));

    let (reply, result) = oneshot::channel();
    drop(WriteReceipt {
        result,
        cancel_wake: None,
    });
    assert!(reply.is_closed());
    assert!(!was_notified(&wake));
}

#[tokio::test]
async fn configured_server_command_queue_backpressures_at_capacity() {
    timeout(Duration::from_secs(5), async {
        let host = HostKey::generate().unwrap();
        let public_key = host.public_key();
        let (client, server) = duplex(8192);
        let mut config = server::Config::new(host);
        config.command_buffer_size = 1;
        let (session, _peer) = tokio::join!(
            server::accept_over(Arc::new(config), server, None, Password),
            async {
                let transport = Transport::connect(client, |key| *key == public_key)
                    .await
                    .unwrap();
                auth::login(
                    transport,
                    "fixture",
                    auth::Method::Password("fixture-password"),
                )
                .await
                .unwrap()
            }
        );
        let session = session.unwrap();
        let handle = session.handle();
        let slot = handle.commands.try_reserve().unwrap();
        assert!(matches!(
            handle.commands.try_reserve(),
            Err(mpsc::error::TrySendError::Full(()))
        ));
        drop(slot);
        assert!(handle.commands.try_reserve().is_ok());
    })
    .await
    .unwrap();
}
