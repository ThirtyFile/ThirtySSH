use std::{fs, io, os::unix::ffi::OsStrExt, path::PathBuf};
use thirtyssh::{
    channel::{Bytes, GlobalReply, driver::Handle},
    forward::streamlocal::{
        StreamlocalForwardKind, StreamlocalKind, StreamlocalOpen, relay_to_socket,
    },
    server,
    session::{self, Context, End, IncomingChannel, IncomingGlobalRequest, OpenType},
};
use tokio::{io::copy_bidirectional, net::UnixListener, sync::oneshot, task::JoinSet};

/// Only these exact socket paths are authorized. The caller provides a private
/// temporary directory for the server-created listener.
pub struct LocalForwarding {
    key: [u8; 32],
    destination: PathBuf,
    listen_path: PathBuf,
    stop_listener: Option<oneshot::Sender<oneshot::Sender<io::Result<()>>>>,
    tasks: JoinSet<()>,
}

impl LocalForwarding {
    pub fn new(key: [u8; 32], destination: PathBuf, listen_path: PathBuf) -> Self {
        Self {
            key,
            destination,
            listen_path,
            stop_listener: None,
            tasks: JoinSet::new(),
        }
    }
}

impl server::AuthPolicy for LocalForwarding {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        Ok(user == "forward" && self.key == *key)
    }
}

impl session::Handler for LocalForwarding {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        while self.tasks.try_join_next().is_some() {}
        let Ok(OpenType::Streamlocal(open)) = request.open_type() else {
            return Ok(());
        };
        if open.kind != StreamlocalKind::Direct
            || open.socket_path != self.destination.as_os_str().as_bytes()
        {
            return request.refuse(1).await;
        }
        if self.tasks.len() >= 8 {
            return request.refuse(4).await;
        }
        let destination = self.destination.clone();
        self.tasks.spawn(async move {
            let _ = relay_to_socket(request, destination).await;
        });
        Ok(())
    }

    async fn global_request(
        &mut self,
        request: &mut IncomingGlobalRequest<'_>,
        context: &Context,
    ) -> io::Result<()> {
        while self.tasks.try_join_next().is_some() {}
        let Ok(Some(operation)) = request.request().streamlocal_forward() else {
            return Ok(());
        };
        if operation.socket_path != self.listen_path.as_os_str().as_bytes() {
            return Ok(());
        }
        let success = GlobalReply::Success(Bytes::new());
        match operation.kind {
            StreamlocalForwardKind::Listen => {
                if self.stop_listener.is_some() || self.tasks.len() >= 8 {
                    return Ok(());
                }
                let Ok(listener) = UnixListener::bind(&self.listen_path) else {
                    return Ok(());
                };
                let socket = SocketPath {
                    path: self.listen_path.clone(),
                    linked: true,
                };
                request.reply(success).await?;
                let (stop, stopping) = oneshot::channel();
                self.stop_listener = Some(stop);
                self.tasks.spawn(forward_listener(
                    listener,
                    socket,
                    context.handle(),
                    stopping,
                ));
            }
            StreamlocalForwardKind::Cancel => {
                let Some(stop) = self.stop_listener.take() else {
                    return Ok(());
                };
                let (closed, closing) = oneshot::channel();
                if stop.send(closed).is_ok() && matches!(closing.await, Ok(Ok(()))) {
                    request.reply(success).await?;
                }
            }
        }
        Ok(())
    }

    async fn disconnected(&mut self, _: End<'_>, _: &Context) {
        self.tasks.shutdown().await;
    }
}

// Constructed only after a successful bind in the fixture's private directory.
struct SocketPath {
    path: PathBuf,
    linked: bool,
}

impl SocketPath {
    fn remove(&mut self) -> io::Result<()> {
        if self.linked {
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
            self.linked = false;
        }
        Ok(())
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

async fn forward_listener(
    listener: UnixListener,
    mut socket: SocketPath,
    handle: Handle,
    mut stopping: oneshot::Receiver<oneshot::Sender<io::Result<()>>>,
) {
    let mut relays = JoinSet::new();
    let closed = loop {
        tokio::select! {
            biased;
            result = &mut stopping => break result.ok(),
            _ = relays.join_next(), if !relays.is_empty() => {},
            result = listener.accept(), if relays.len() < 8 => {
                let Ok((mut stream, _)) = result else { break None; };
                let handle = handle.clone();
                let path = socket.path.clone();
                relays.spawn(async move {
                    let mut channel = handle.open_as(StreamlocalOpen { kind: StreamlocalKind::Forwarded, socket_path: path.as_os_str().as_bytes() }).await?.into_io();
                    copy_bidirectional(&mut stream, &mut channel).await
                });
            }
        }
    };
    drop(listener);
    let result = socket.remove();
    drop(socket);
    if let Some(closed) = closed {
        let _ = closed.send(result);
    }
    while relays.join_next().await.is_some() {}
}
