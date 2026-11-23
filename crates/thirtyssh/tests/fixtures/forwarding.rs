use std::{collections::HashMap, io, net::Ipv4Addr};
use thirtyssh::{
    channel::driver::Handle,
    forward::{TcpipForwardKind, TcpipKind, TcpipOpen},
    server,
    session::{self, Context, End, IncomingGlobalRequest},
};
use tokio::{io::copy_bidirectional, net::TcpListener, sync::oneshot, task::JoinSet};

/// A per-session policy restricted to IPv4 loopback and unprivileged ports.
pub struct LoopbackForwarding {
    key: [u8; 32],
    listeners: HashMap<u32, oneshot::Sender<oneshot::Sender<()>>>,
    tasks: JoinSet<()>,
}

impl LoopbackForwarding {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            listeners: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }
}

impl server::AuthPolicy for LoopbackForwarding {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        Ok(user == "forward" && self.key == *key)
    }
}

impl session::Handler for LoopbackForwarding {
    async fn global_request(
        &mut self,
        request: &mut IncomingGlobalRequest<'_>,
        context: &Context,
    ) -> io::Result<()> {
        while self.tasks.try_join_next().is_some() {}
        let Ok(Some(forward)) = request.request().tcpip_forward() else {
            return Ok(());
        };
        if forward.bind_address != "127.0.0.1" || (1..1024).contains(&forward.port) {
            return Ok(());
        }
        match forward.kind {
            TcpipForwardKind::Listen => {
                if self.tasks.len() >= 8
                    || self.listeners.contains_key(&forward.port)
                    || (forward.port == 0 && !request.request().wants_reply())
                {
                    return Ok(());
                }
                let Ok(listener) =
                    TcpListener::bind((Ipv4Addr::LOCALHOST, forward.port as u16)).await
                else {
                    return Ok(());
                };
                let port = u32::from(listener.local_addr()?.port());
                // Reply on the wire before opening channels for accepted sockets.
                request.reply(forward.success(port)?).await?;
                let (cancel, stopping) = oneshot::channel();
                self.listeners.insert(port, cancel);
                self.tasks
                    .spawn(accept(listener, port, context.handle(), stopping));
            }
            TcpipForwardKind::Cancel => {
                let Some(cancel) = self.listeners.remove(&forward.port) else {
                    return Ok(());
                };
                let (closed, closing) = oneshot::channel();
                if cancel.send(closed).is_err() || closing.await.is_err() {
                    return Ok(());
                }
                request.reply(forward.success(forward.port)?).await?;
            }
        }
        Ok(())
    }

    async fn disconnected(&mut self, _: End<'_>, _: &Context) {
        // Close the listeners before the session reports completion.
        self.tasks.shutdown().await;
    }
}

async fn accept(
    listener: TcpListener,
    port: u32,
    handle: Handle,
    mut stopping: oneshot::Receiver<oneshot::Sender<()>>,
) {
    let mut relays = JoinSet::new();
    let closed = loop {
        tokio::select! {
            biased;
            result = &mut stopping => break result.ok(),
            _ = relays.join_next(), if !relays.is_empty() => {},
            result = listener.accept(), if relays.len() < 8 => {
                let Ok((mut socket, origin)) = result else { break None; };
                let handle = handle.clone();
                relays.spawn(async move {
                    let channel = handle.open_as(TcpipOpen { kind: TcpipKind::Forwarded, address: "127.0.0.1", port, originator_address: &origin.ip().to_string(), originator_port: u32::from(origin.port()) }).await?;
                    copy_bidirectional(&mut socket, &mut channel.into_io()).await
                });
            }
        }
    };
    drop(listener);
    if let Some(closed) = closed {
        let _ = closed.send(());
    }
    while relays.join_next().await.is_some() {}
}
