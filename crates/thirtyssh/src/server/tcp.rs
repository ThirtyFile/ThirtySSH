//! TCP accept loop and coordinated shutdown.
use super::{Config, Handler, establish};
use crate::{session, transport::HostKeys};
use std::{
    borrow::Borrow,
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinHandle, JoinSet},
};

/// Supplies a handler for each accepted connection. A closure taking the
/// peer address is enough when nothing else needs to be observed.
pub trait Connections: Send {
    type Handler: Handler;

    /// Create the handler for a connection from `peer`.
    fn handler(&mut self, peer: SocketAddr) -> Self::Handler;

    /// A connection ended with an error, or could not be accepted.
    fn failed(&mut self, _error: io::Error) {}
}

impl<F, H> Connections for F
where
    F: FnMut(SocketAddr) -> H + Send,
    H: Handler,
{
    type Handler = H;

    fn handler(&mut self, peer: SocketAddr) -> H {
        self(peer)
    }
}

/// Cloneable signal to stop a listener and close its connections.
#[derive(Clone)]
pub struct ShutdownHandle {
    stop: watch::Sender<Option<Arc<str>>>,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.shutdown_with("");
    }

    /// Stop the listener and tell every connected client why. The first
    /// call decides the reason.
    pub fn shutdown_with(&self, reason: impl Into<Arc<str>>) {
        let reason = reason.into();
        self.stop.send_if_modified(|stop| {
            if stop.is_some() {
                return false;
            }
            *stop = Some(reason);
            true
        });
    }
}

/// Running TCP listener and its connection tasks.
#[must_use = "hold the listener while it runs or await its completion"]
pub struct Listening {
    local_addr: SocketAddr,
    handle: ShutdownHandle,
    task: JoinHandle<io::Result<()>>,
}

impl Listening {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.handle.clone()
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

impl Future for Listening {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx).map(session::join_result)
    }
}

/// Start accepting connections on a listener the caller has bound.
pub fn listen_on(
    config: Arc<Config<impl Clone + Into<HostKeys> + Send + Sync + 'static>>,
    listener: TcpListener,
    connections: impl Connections + 'static,
) -> io::Result<Listening> {
    config.validated_session_options()?;
    spawn_listener(config, listener, connections)
}

fn spawn_listener(
    config: Arc<Config<impl Clone + Into<HostKeys> + Send + Sync + 'static>>,
    listener: TcpListener,
    connections: impl Connections + 'static,
) -> io::Result<Listening> {
    let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    let local_addr = listener.local_addr()?;
    let (stop, stopped) = watch::channel(None);
    let handle = ShutdownHandle { stop };
    let task = runtime.spawn(accept_loop(
        config,
        listener,
        connections,
        handle.clone(),
        stopped,
    ));
    Ok(Listening {
        local_addr,
        handle,
        task,
    })
}

/// Bind a TCP listener and start accepting connections.
pub async fn listen(
    config: Arc<Config<impl Clone + Into<HostKeys> + Send + Sync + 'static>>,
    address: impl ToSocketAddrs,
    connections: impl Connections + 'static,
) -> io::Result<Listening> {
    config.validated_session_options()?;
    let listener = TcpListener::bind(address).await?;
    spawn_listener(config, listener, connections)
}

/// Accept connections on a borrowed listener until `shutdown` completes,
/// then close the sessions that are still running.
pub async fn serve_until(
    config: Arc<Config<impl Clone + Into<HostKeys> + Send + Sync + 'static>>,
    listener: &TcpListener,
    connections: impl Connections,
    shutdown: impl Future<Output = Arc<str>> + Send,
) -> io::Result<()> {
    config.validated_session_options()?;
    let (stop, stopped) = watch::channel(None);
    let handle = ShutdownHandle { stop };
    let run = accept_loop(config, listener, connections, handle.clone(), stopped);
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => result,
        reason = shutdown => {
            handle.shutdown_with(reason);
            run.await
        }
    }
}

async fn accept_loop(
    config: Arc<Config<impl Clone + Into<HostKeys> + Send + Sync + 'static>>,
    listener: impl Borrow<TcpListener> + Send,
    mut connections: impl Connections,
    handle: ShutdownHandle,
    mut stop: watch::Receiver<Option<Arc<str>>>,
) -> io::Result<()> {
    let mut clients = JoinSet::new();
    let startups = Startups::new(
        config.max_unauthenticated_connections,
        config.max_unauthenticated_per_source,
    );
    let result = loop {
        tokio::select! {
            biased;
            _ = stopping(&mut stop) => break Ok(()),
            Some(closed) = clients.join_next() => {
                if let Err(error) = session::join_result(closed) {
                    connections.failed(error);
                }
            }
            accepted = startups.accept(listener.borrow()), if clients.len() < config.max_connections.get() => {
                let (stream, address, slot) = match accepted {
                    Ok(client) => client,
                    Err(error) => {
                        // Say so at once; the error itself is returned when
                        // the sessions that are still running have ended.
                        connections.failed(io::Error::new(error.kind(), error.to_string()));
                        break Err(error);
                    }
                };
                // Dropping the stream closes a connection over its source's limit.
                let Some(startup) = startups.admit(address.ip(), slot) else {
                    continue;
                };
                let handler = connections.handler(address);
                clients.spawn(serve(
                    Arc::clone(&config),
                    stream,
                    address,
                    handler,
                    startup,
                    stop.clone(),
                ));
            }
        }
    };
    drop(listener);
    // A listener that failed takes no one down with it: the clients already
    // connected are served until they leave or a shutdown is requested.
    if result.is_ok() {
        handle.shutdown();
    }
    while let Some(closed) = clients.join_next().await {
        if let Err(error) = session::join_result(closed) {
            connections.failed(error);
        }
    }
    result
}

/// The address unit that shares one unauthenticated connection limit.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Source {
    V4(u32),
    /// The /64 network: one host commonly controls all of its addresses.
    V6(u64),
}

impl From<IpAddr> for Source {
    fn from(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V4(address) => Self::V4(address.into()),
            IpAddr::V6(address) => Self::V6((u128::from(address) >> 64) as u64),
        }
    }
}

/// Limits on connections that have not completed authentication.
struct Startups {
    slots: Arc<Semaphore>,
    per_source: Option<NonZeroUsize>,
    sources: Arc<Mutex<HashMap<Source, usize>>>,
}

impl Startups {
    fn new(limit: NonZeroUsize, per_source: Option<NonZeroUsize>) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit.get().min(Semaphore::MAX_PERMITS))),
            per_source,
            sources: Arc::default(),
        }
    }

    /// Accept a connection once an unauthenticated slot is free.
    async fn accept(
        &self,
        listener: &TcpListener,
    ) -> io::Result<(TcpStream, SocketAddr, OwnedSemaphorePermit)> {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("startup slots stay open");
        let (stream, address) = accept_with_retry(|| listener.accept()).await?;
        Ok((stream, address, slot))
    }

    /// Count the connection against its source, unless the source is full.
    fn admit(&self, address: IpAddr, slot: OwnedSemaphorePermit) -> Option<Startup> {
        let source = Source::from(address);
        let mut sources = self.sources.lock().expect("startup sources");
        let count = sources.entry(source).or_insert(0);
        if self.per_source.is_some_and(|limit| *count >= limit.get()) {
            return None;
        }
        *count += 1;
        Some(Startup {
            _slot: slot,
            source,
            sources: Arc::clone(&self.sources),
        })
    }
}

/// One unauthenticated connection's share of the limits, released on drop.
struct Startup {
    _slot: OwnedSemaphorePermit,
    source: Source,
    sources: Arc<Mutex<HashMap<Source, usize>>>,
}

impl Drop for Startup {
    fn drop(&mut self) {
        let mut sources = self.sources.lock().expect("startup sources");
        if let Some(count) = sources.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                sources.remove(&self.source);
            }
        }
    }
}

// Keep transient accept errors local to the pending accept operation. The
// outer select can still reap sessions and react to shutdown during backoff.
async fn accept_with_retry<T, F: Future<Output = io::Result<T>>>(
    mut accept: impl FnMut() -> F,
) -> io::Result<T> {
    loop {
        match accept().await {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                tokio::task::yield_now().await;
            }
            Err(e) if retry_with_backoff(&e) => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            result => return result,
        }
    }
}

fn retry_with_backoff(error: &io::Error) -> bool {
    use io::ErrorKind::*;
    if matches!(
        error.kind(),
        WouldBlock | OutOfMemory | NetworkDown | NetworkUnreachable | HostUnreachable | TimedOut
    ) {
        return true;
    }
    match error.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS) => true,
        // Linux also reports pending network errors on the incoming socket from accept.
        #[cfg(target_os = "linux")]
        Some(
            libc::EPROTO | libc::ENOPROTOOPT | libc::ENONET | libc::EHOSTDOWN | libc::EOPNOTSUPP,
        ) => true,
        #[cfg(windows)]
        Some(10024 | 10055) => true, // WSAEMFILE, WSAENOBUFS
        _ => false,
    }
}

async fn serve(
    config: Arc<Config<impl Clone + Into<HostKeys>>>,
    stream: TcpStream,
    address: SocketAddr,
    mut handler: impl Handler,
    startup: Startup,
    mut stop: watch::Receiver<Option<Arc<str>>>,
) -> io::Result<()> {
    stream.set_nodelay(config.nodelay)?;
    let authenticated = tokio::select! {
        biased;
        _ = stopping(&mut stop) => return Ok(()),
        result = establish(&config, stream, Some(address), &mut handler) => result?,
    };
    drop(startup);
    session::serve(
        authenticated,
        handler,
        address,
        stopping(&mut stop),
        config.session_options(),
    )
    .await
}

async fn stopping(stop: &mut watch::Receiver<Option<Arc<str>>>) -> Arc<str> {
    stop.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|reason| reason.clone())
        .unwrap_or_else(|| Arc::from(""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;

    #[tokio::test]
    async fn startups_limit_each_source_and_release_on_drop() {
        let startups = Startups::new(NonZeroUsize::new(8).unwrap(), NonZeroUsize::new(2));
        let slot = || Arc::clone(&startups.slots).try_acquire_owned().unwrap();
        let admit = |address: &str| startups.admit(address.parse().unwrap(), slot());

        let first = admit("192.0.2.1").unwrap();
        let _second = admit("::ffff:192.0.2.1").unwrap();
        assert!(admit("192.0.2.1").is_none());
        assert!(admit("192.0.2.2").is_some());
        drop(first);
        assert!(admit("192.0.2.1").is_some());

        let _a = admit("2001:db8::1").unwrap();
        let _b = admit("2001:db8::ffff:2").unwrap();
        assert!(admit("2001:db8::3").is_none());
        assert!(admit("2001:db8:0:1::3").is_some());

        // Rejected and released connections leave no slot or entry behind.
        assert_eq!(startups.slots.available_permits(), 5);
        drop((_second, _a, _b));
        assert!(startups.sources.lock().unwrap().is_empty());
        assert_eq!(startups.slots.available_permits(), 8);

        let unlimited = Startups::new(NonZeroUsize::MIN, None);
        let slot = Arc::clone(&unlimited.slots).try_acquire_owned().unwrap();
        let held = unlimited.admit("192.0.2.1".parse().unwrap(), slot);
        assert!(held.is_some());
        assert!(Arc::clone(&unlimited.slots).try_acquire_owned().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn accept_recovers_from_peer_and_resource_errors_and_propagates_fatal_errors() {
        #[cfg(windows)]
        let exhausted = io::Error::from_raw_os_error(10024);
        #[cfg(unix)]
        let exhausted = io::Error::from_raw_os_error(libc::EMFILE);
        #[cfg(not(any(unix, windows)))]
        let exhausted = io::Error::from(io::ErrorKind::OutOfMemory);
        let mut results = [
            Err(io::ErrorKind::ConnectionAborted.into()),
            Err(exhausted),
            Ok(42),
            Err(io::ErrorKind::InvalidInput.into()),
        ]
        .into_iter();
        let mut accept = || ready(results.next().unwrap());
        let start = tokio::time::Instant::now();
        assert_eq!(accept_with_retry(&mut accept).await.unwrap(), 42);
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert_eq!(
            accept_with_retry(accept).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
