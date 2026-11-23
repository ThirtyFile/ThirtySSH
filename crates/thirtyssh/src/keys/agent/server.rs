//! A bounded agent service with a key store shared by its accepted streams.
mod request;

use super::{
    Error,
    protocol::{
        FAILURE, IDENTITIES_ANSWER, MAX_FRAME, SIGN_RESPONSE, SUCCESS, read_frame_size, write_frame,
    },
};
use crate::{
    SecretBuf,
    keys::{self, PublicKey, RSA_SHA1},
    runtime::{Instant, sleep_until},
};
use request::{Identity, PendingIdentity, Request};
use ssh_encoding::Encode;
use std::{
    future::{Future, ready},
    io,
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::{Mutex, Notify, Semaphore, mpsc},
    task::JoinSet,
};

const UNLOCK_DELAY: Duration = Duration::from_millis(100);
const MAX_UNLOCK_DELAY: Duration = Duration::from_secs(10);

/// The kind of request a client sent, as seen by a [`Policy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Operation {
    ListIdentities,
    AddIdentity,
    RemoveIdentity,
    RemoveAllIdentities,
    Sign,
    Lock,
    Unlock,
}

/// Decides what the clients of an agent service may do.
///
/// Each connection works with its own clone, so a decision that spans
/// connections needs shared state inside the policy. `()` is the policy that
/// keeps every default.
pub trait Policy: Clone + Send + Sync + 'static {
    /// Whether a request of this kind may proceed. Every kind is permitted
    /// by default.
    fn permits(&self, _operation: Operation) -> impl Future<Output = bool> + Send {
        ready(true)
    }

    /// Approve one signature with a key that was added under
    /// [`Constraint::ConfirmEachUse`](super::Constraint::ConfirmEachUse).
    /// Denied by default, because approval needs a way to ask the user.
    fn approve_signature(&mut self, _key: &PublicKey) -> impl Future<Output = bool> + Send {
        ready(false)
    }

    /// Permit a request without RSA hash flags to sign with SHA-1 using this
    /// key. The request still has to pass every other check.
    fn permits_rsa_sha1(&self, _key: &PublicKey) -> bool {
        false
    }
}

impl Policy for () {}

/// Serve the agent protocol to every stream the caller accepts, sharing one
/// key store between them. The caller decides who may connect.
///
/// The service runs until `connections` ends and the accepted streams have
/// finished. A stream that closes its sending side gets up to five seconds
/// for pending replies. Dropping the future closes the service, its streams
/// and its keys.
///
/// `connections` is called for each next stream and returns `None` when no
/// more will come, for example `async || Some(listener.accept().await.map(|(stream, _)| stream))`.
/// It must be safe to drop a call that has not finished, as accepting from a
/// Tokio listener or receiving from a channel is.
pub async fn run<S>(
    mut connections: impl AsyncFnMut() -> Option<io::Result<S>>,
    policy: impl Policy,
) where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let shared = Arc::new(Shared::default());
    let expire = shared.expire();
    tokio::pin!(expire);
    let mut clients = JoinSet::new();
    let mut accepting = true;
    while accepting || !clients.is_empty() {
        tokio::select! {
            _ = &mut expire => unreachable!("expiration loop returned"),
            _ = clients.join_next(), if !clients.is_empty() => (),
            incoming = connections(), if accepting && clients.len() < MAX_CLIENTS => {
                match incoming {
                    Some(Ok(stream)) => {
                        clients.spawn(serve_connection(stream, policy.clone(), shared.clone()));
                    }
                    // A failed accept (descriptor exhaustion, an aborted
                    // connection) must not drop every client and the loaded
                    // keys. Back off briefly and keep serving.
                    Some(Err(_)) => {
                        let _ = crate::runtime::timeout(
                            ACCEPT_ERROR_BACKOFF,
                            std::future::pending::<()>(),
                        )
                        .await;
                    }
                    None => accepting = false,
                }
            }
        }
    }
}

/// Upper bound on concurrent agent clients; further connections wait in the
/// listener's backlog instead of each holding request buffers.
const MAX_CLIENTS: usize = 256;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    policy: impl Policy,
    shared: Arc<Shared>,
) -> Result<(), Error> {
    let (input, output) = tokio::io::split(stream);
    let (sender, requests) = mpsc::channel(1);
    let replies = serve_requests(output, requests, policy, shared);
    tokio::pin!(replies);
    tokio::select! {
        result = read_requests(input, sender) => {
            result?;
            // EOF can be a write half-close. A fully disconnected peer looks
            // identical here, so an unanswered approval must eventually expire.
            crate::runtime::timeout(Duration::from_secs(5), replies)
                .await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
        }
        result = &mut replies => result,
    }
}

async fn read_requests(
    mut input: impl AsyncRead + Unpin,
    sender: mpsc::Sender<SecretBuf>,
) -> Result<(), Error> {
    while let Some(size) = read_frame_size(&mut input).await? {
        let mut frame = SecretBuf::zeroed(size);
        input.read_exact(&mut frame).await?;
        if sender.send(frame).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn serve_requests(
    mut output: impl AsyncWrite + Unpin,
    mut input: mpsc::Receiver<SecretBuf>,
    mut policy: impl Policy,
    shared: Arc<Shared>,
) -> Result<(), Error> {
    while let Some(frame) = input.recv().await {
        let reply = respond(&frame, &mut policy, &shared)
            .await
            .unwrap_or_else(|_| vec![FAILURE]);
        drop(frame);
        write_frame(&mut output, &reply).await?;
    }
    Ok(())
}

async fn respond(
    frame: &[u8],
    policy: &mut impl Policy,
    shared: &Shared,
) -> Result<Vec<u8>, Error> {
    let request = Request::parse(frame)?;
    let version = {
        let store = shared.store.lock().await;
        if !store.allows(&request) {
            return Err(Error::Refused);
        }
        store.lock_version
    };
    if let Some(operation) = request.operation()
        && !policy.permits(operation).await
    {
        return Err(Error::Refused);
    }

    if let Request::Sign { blob, data, flags } = request {
        return sign(shared, policy, version, SignOperation { blob, data, flags }).await;
    }
    // Unlock attempts run one at a time, and each failure is answered after a
    // growing delay, so a peer cannot guess the lock passphrase at socket speed.
    let mut failed_unlocks = match request {
        Request::Unlock(_) => Some(shared.failed_unlocks.lock().await),
        _ => None,
    };
    let mut store = shared.store.lock().await;
    if store.lock_version != version || !store.allows(&request) {
        return Err(Error::Refused);
    }
    store.purge();
    let reply = store.apply(request);
    drop(store);
    if let Some(failures) = failed_unlocks.as_deref_mut() {
        if reply.is_ok() {
            *failures = 0;
        } else {
            *failures = failures.saturating_add(1);
            sleep_until(Instant::now() + unlock_delay(*failures)).await;
        }
    }
    let reply = reply?;
    shared.changed.notify_one();
    Ok(reply)
}

/// Delay before reporting the `failures`-th consecutive failed unlock.
fn unlock_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    (UNLOCK_DELAY * (1 << doublings)).min(MAX_UNLOCK_DELAY)
}

struct SignOperation<'a> {
    blob: &'a [u8],
    data: &'a [u8],
    flags: u32,
}

async fn sign(
    shared: &Shared,
    policy: &mut impl Policy,
    version: u64,
    operation: SignOperation<'_>,
) -> Result<Vec<u8>, Error> {
    let SignOperation { blob, data, flags } = operation;
    let identity = {
        let mut store = shared.store.lock().await;
        store.purge();
        store.signing_identity(blob, version)?.clone()
    };
    let algorithm = identity.signature_algorithm(flags)?;
    if algorithm == RSA_SHA1 && !policy.permits_rsa_sha1(identity.key.public_key()) {
        return Err(Error::Refused);
    }
    if identity.confirm && !policy.approve_signature(identity.key.public_key()).await {
        return Err(Error::Refused);
    }

    let key = identity.key.clone();
    let data = zeroize::Zeroizing::new(data.to_vec());
    let signature = shared
        .sign_if_current(blob, version, &identity, move || {
            keys::sign(&key, &algorithm, &data)
        })
        .await?;
    let mut reply = vec![SIGN_RESPONSE];
    signature.encode(&mut reply)?;
    Ok(reply)
}

struct Shared {
    store: Mutex<Store>,
    failed_unlocks: Mutex<u32>,
    changed: Notify,
    signing_slots: Arc<Semaphore>,
}

impl Default for Shared {
    fn default() -> Self {
        let workers = std::thread::available_parallelism().map_or(1, usize::from);
        Self {
            store: Mutex::default(),
            failed_unlocks: Mutex::default(),
            changed: Notify::new(),
            signing_slots: Arc::new(Semaphore::new(workers)),
        }
    }
}

impl Shared {
    async fn validate_signer(
        &self,
        blob: &[u8],
        version: u64,
        identity: &Arc<Identity>,
    ) -> Result<(), Error> {
        let mut store = self.store.lock().await;
        store.purge();
        if !Arc::ptr_eq(store.signing_identity(blob, version)?, identity) {
            return Err(Error::Refused);
        }
        Ok(())
    }

    async fn sign_if_current(
        &self,
        blob: &[u8],
        version: u64,
        identity: &Arc<Identity>,
        sign: impl FnOnce() -> std::io::Result<Vec<u8>> + Send + 'static,
    ) -> Result<Vec<u8>, Error> {
        let permit = self
            .signing_slots
            .clone()
            .acquire_owned()
            .await
            .expect("signing semaphore stays open");
        self.validate_signer(blob, version, identity).await?;
        // A started blocking task can outlive its request. Keep its permit
        // until CPU work finishes even if that request is cancelled.
        let work = move || {
            let _permit = permit;
            sign()
        };
        #[cfg(not(target_family = "wasm"))]
        let signature = tokio::task::spawn_blocking(work)
            .await
            .map_err(std::io::Error::other)??;
        #[cfg(target_family = "wasm")]
        let signature = work()?;
        self.validate_signer(blob, version, identity).await?;
        Ok(signature)
    }

    async fn expire(&self) {
        loop {
            let next = {
                let mut store = self.store.lock().await;
                store.purge();
                store
                    .keys
                    .iter()
                    .filter_map(|(_, entry)| entry.expires)
                    .min()
            };
            if let Some(expires) = next {
                tokio::select! {
                    () = self.changed.notified() => (),
                    () = sleep_until(expires) => (),
                }
            } else {
                self.changed.notified().await;
            }
        }
    }
}

#[derive(Default)]
struct Store {
    /// Identities by public key blob, in the order they were added. Clients
    /// try keys in listed order, so the order must not change between runs.
    keys: Vec<(Vec<u8>, Arc<Identity>)>,
    password: Option<SecretBuf>,
    lock_version: u64,
}

impl Store {
    fn allows(&self, request: &Request<'_>) -> bool {
        self.password.is_some() == matches!(request, Request::Unlock(_))
    }

    fn signing_identity(&self, blob: &[u8], version: u64) -> Result<&Arc<Identity>, Error> {
        if self.password.is_some() || self.lock_version != version {
            return Err(Error::Refused);
        }
        self.keys
            .iter()
            .find(|(existing, _)| existing == blob)
            .map(|(_, entry)| entry)
            .ok_or(Error::Refused)
    }

    fn purge(&mut self) {
        let now = Instant::now();
        self.keys
            .retain(|(_, entry)| entry.expires.is_none_or(|deadline| deadline > now));
    }

    fn apply(&mut self, request: Request<'_>) -> Result<Vec<u8>, Error> {
        match request {
            Request::List => return self.identities(),
            Request::Add(identity) => self.insert(identity)?,
            Request::Remove(blob) => {
                let index = self
                    .keys
                    .iter()
                    .position(|(existing, _)| existing == blob)
                    .ok_or(Error::Refused)?;
                self.keys.remove(index);
            }
            Request::RemoveAll => self.keys.clear(),
            Request::Lock(password) => self.set_password(Some(SecretBuf::from(password))),
            Request::Unlock(candidate) => {
                let password = self.password.as_ref().ok_or(Error::Refused)?;
                if !bool::from(password.ct_eq(candidate)) {
                    return Err(Error::Refused);
                }
                self.set_password(None);
            }
            Request::Query => return request::query_reply(),
            Request::Sign { .. } => unreachable!("sign requests use the approval path"),
        }
        Ok(vec![SUCCESS])
    }

    fn set_password(&mut self, password: Option<SecretBuf>) {
        self.password = password;
        self.lock_version = self.lock_version.wrapping_add(1);
    }

    fn insert(&mut self, identity: PendingIdentity) -> Result<(), Error> {
        let (blob, entry) = identity.install()?;
        let total = self
            .keys
            .iter()
            .filter(|(existing, _)| **existing != blob)
            .map(|(blob, entry)| 8 + blob.len() + entry.key.comment().len())
            .sum::<usize>()
            + 5
            + 8
            + blob.len()
            + entry.key.comment().len();
        if total > MAX_FRAME {
            return Err(Error::Refused);
        }
        let entry = Arc::new(entry);
        // Adding a key again replaces it where it stands.
        match self.keys.iter_mut().find(|(existing, _)| *existing == blob) {
            Some((_, existing)) => *existing = entry,
            None => self.keys.push((blob, entry)),
        }
        Ok(())
    }

    fn identities(&self) -> Result<Vec<u8>, Error> {
        let mut reply = vec![IDENTITIES_ANSWER];
        (self.keys.len() as u32).encode(&mut reply)?;
        for (blob, entry) in &self.keys {
            blob.encode(&mut reply)?;
            entry.key.comment().encode(&mut reply)?;
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Algorithm, PrivateKey, system_rng};
    use std::time::Duration;

    #[cfg(not(target_family = "wasm"))]
    #[tokio::test]
    async fn revocation_can_finish_during_signing_and_prevents_delivery() {
        let shared = Arc::new(Shared::default());
        let key = Arc::new(PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap());
        let blob = key.public_key().to_bytes().unwrap();
        let identity = Arc::new(Identity {
            key,
            confirm: false,
            expires: None,
        });
        shared
            .store
            .lock()
            .await
            .keys
            .push((blob.clone(), identity.clone()));
        let (started, running) = tokio::sync::oneshot::channel();
        let (resume, release) = std::sync::mpsc::channel();
        let signing = tokio::spawn({
            let shared = shared.clone();
            let blob = blob.clone();
            async move {
                shared
                    .sign_if_current(&blob, 0, &identity, move || {
                        started.send(()).unwrap();
                        release
                            .recv_timeout(Duration::from_secs(3))
                            .map_err(std::io::Error::other)?;
                        Ok(vec![42])
                    })
                    .await
            }
        });
        running.await.unwrap();
        shared
            .store
            .try_lock()
            .expect("signing must release the store")
            .keys
            .retain(|(existing, _)| *existing != blob);
        resume.send(()).unwrap();
        assert!(matches!(signing.await.unwrap(), Err(Error::Refused)));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_releases_an_idle_identity_without_any_request() {
        let shared = Arc::new(Shared::default());
        let key = Arc::new(PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap());
        let blob = key.public_key().to_bytes().unwrap();
        let weak = Arc::downgrade(&key);
        shared.store.lock().await.keys.push((
            blob,
            Arc::new(Identity {
                key,
                confirm: false,
                expires: Some(Instant::now() + Duration::from_secs(1)),
            }),
        ));
        let timer = tokio::spawn({
            let shared = shared.clone();
            async move { shared.expire().await }
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(weak.upgrade().is_none());
        assert!(shared.store.lock().await.keys.is_empty());
        timer.abort();
        assert!(timer.await.unwrap_err().is_cancelled());
    }
}
