//! Bounded, sequential SSH agent requests over a caller-supplied stream.
mod management;
use super::{
    Credential, Error, Identity,
    protocol::{
        self, FAILURE, IDENTITIES_ANSWER, REQUEST_IDENTITIES, RSA_SHA256, RSA_SHA512, SIGN_REQUEST,
        SIGN_RESPONSE, check_frame_size, protocol,
    },
};
use crate::{
    auth::{SignRequest, Signer},
    keys::{Algorithm, Certificate, HashAlg, Signature, key},
    wire::Reader,
};
use ssh_encoding::{Decode, Encode};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use zeroize::Zeroizing;

/// A byte stream that reaches an agent. Every Tokio stream is one.
pub trait AgentIo: AsyncRead + AsyncWrite {}
impl<S: AsyncRead + AsyncWrite> AgentIo for S {}

/// An agent stream whose concrete type has been erased.
pub type BoxedIo<'a> = Box<dyn AgentIo + Send + Unpin + 'a>;

/// One connection to an SSH agent.
///
/// The agent protocol answers requests in order and without identifiers, so
/// a client runs one request at a time. A request that is dropped after it
/// began leaves the stream at an unknown position, and every later request
/// fails with `BrokenPipe`.
pub struct Client<S> {
    stream: S,
    usable: bool,
}

impl<S> Client<S> {
    /// Speak the agent protocol over a connected stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            usable: true,
        }
    }

    /// Give the stream back, for example to shut it down.
    pub fn into_io(self) -> S {
        self.stream
    }
}

impl<S: AgentIo + Unpin + Send> Client<S> {
    /// Erase the stream type, so clients for different transports share one
    /// type.
    pub fn boxed<'a>(self) -> Client<BoxedIo<'a>>
    where
        S: 'a,
    {
        Client {
            stream: Box::new(self.stream),
            usable: self.usable,
        }
    }
}

#[cfg(unix)]
impl Client<tokio::net::UnixStream> {
    /// Connect to the agent socket at a path.
    pub async fn unix(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Ok(Self::new(tokio::net::UnixStream::connect(path).await?))
    }

    /// Connect to the agent named by `SSH_AUTH_SOCK`.
    pub async fn from_env() -> Result<Self, Error> {
        let path = std::env::var_os("SSH_AUTH_SOCK").ok_or(Error::NotRunning)?;
        match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => Ok(Self::new(stream)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(Error::NotRunning),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(windows)]
impl Client<pageant::Pageant> {
    /// Connect to the Pageant instance of the current Windows account.
    pub async fn pageant() -> Result<Self, Error> {
        Ok(Self::new(pageant::Pageant::connect().await?))
    }
}

#[cfg(windows)]
impl Client<tokio::net::windows::named_pipe::NamedPipeClient> {
    /// Connect to an agent's named pipe. A pipe whose instances are all in
    /// use is retried for two seconds and then reported as `TimedOut`. A
    /// pipe owned by another account is refused with `PermissionDenied`.
    pub async fn named_pipe(path: impl AsRef<std::ffi::OsStr>) -> Result<Self, Error> {
        use tokio::{
            net::windows::named_pipe::ClientOptions,
            time::{Duration, Instant, sleep_until},
        };

        const ERROR_PIPE_BUSY: i32 = 231;
        const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
        const RETRY_INTERVAL: Duration = Duration::from_millis(50);
        let deadline = Instant::now() + BUSY_TIMEOUT;
        loop {
            match ClientOptions::new().open(path.as_ref()) {
                Ok(stream) => {
                    // Anyone can create a pipe under a well-known name before
                    // the real agent starts. Talk only to one owned by this
                    // account or by the system.
                    pageant::check_agent_pipe_owner(&stream)?;
                    return Ok(Self::new(stream));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {}
                Err(error) => return Err(error.into()),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SSH agent named pipe stayed busy",
                )
                .into());
            }
            sleep_until((now + RETRY_INTERVAL).min(deadline)).await;
        }
    }
}

impl<S: AgentIo + Unpin> Client<S> {
    async fn exchange(&mut self, request: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        check_frame_size(request.len())?;
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SSH agent exchange was interrupted",
            )
            .into());
        }
        // The protocol has no request identifiers. Once any I/O starts, a
        // cancelled exchange cannot safely share its reply with a later call.
        self.usable = false;
        protocol::write_frame(&mut self.stream, request).await?;
        let size = protocol::read_frame_size(&mut self.stream)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SSH agent closed before its reply",
                )
            })?;
        let mut response = Zeroizing::new(vec![0; size]);
        self.stream.read_exact(&mut response).await?;
        self.usable = true;
        Ok(response)
    }

    /// List the keys and certificates the agent offers. An agent that
    /// declines to list them, such as a locked one, offers none. Identities
    /// whose key cannot be decoded are left out.
    pub async fn identities(&mut self) -> Result<Vec<Identity>, Error> {
        let response = self.exchange(&[REQUEST_IDENTITIES]).await?;
        let payload = match response.as_slice() {
            [FAILURE] => return Ok(Vec::new()),
            [IDENTITIES_ANSWER, payload @ ..] => payload,
            _ => return Err(Error::Protocol),
        };
        let mut reader = Reader::new(payload);
        let count = reader.uint32().map_err(protocol)? as usize;
        if count > reader.remaining().len() / 8 {
            return Err(Error::Protocol);
        }
        let mut identities = Vec::new();
        for _ in 0..count {
            let blob = reader.string().map_err(protocol)?;
            let comment = String::from_utf8_lossy(reader.string().map_err(protocol)?);
            // An agent may hold a key this library cannot represent. Leave it
            // out instead of hiding every other identity behind it.
            if let Ok(credential) = decode_credential(blob) {
                identities.push(Identity::new(credential, comment));
            }
        }
        reader.finish().map_err(protocol)?;
        Ok(identities)
    }

    /// Ask the agent to sign `data` with the private key behind a
    /// credential. `rsa_hash` selects the digest of an RSA signature and is
    /// ignored for other keys; `None` leaves the choice to the agent.
    ///
    /// The reply is checked against the request: a signature of another
    /// algorithm is [`Error::Protocol`].
    pub async fn sign(
        &mut self,
        credential: &Credential,
        rsa_hash: Option<HashAlg>,
        data: &[u8],
    ) -> Result<Signature, Error> {
        let (blob, algorithm) = match credential {
            Credential::Key(key) => (key.to_bytes()?, key.algorithm()),
            Credential::Certificate(certificate) => {
                (certificate.to_bytes()?, certificate.algorithm())
            }
        };
        check_frame_size(
            13usize
                .saturating_add(blob.len())
                .saturating_add(data.len()),
        )?;
        let flags = match (&algorithm, rsa_hash) {
            (Algorithm::Rsa { .. }, Some(HashAlg::Sha256)) => RSA_SHA256,
            (Algorithm::Rsa { .. }, Some(HashAlg::Sha512)) => RSA_SHA512,
            _ => 0,
        };
        let mut request = Zeroizing::new(crate::kex::fields(Some(SIGN_REQUEST), &[&blob, data])?);
        request.extend_from_slice(&flags.to_be_bytes());

        let response = self.exchange(&request).await?;
        let payload = match response.as_slice() {
            [FAILURE] => return Err(Error::Refused),
            [SIGN_RESPONSE, payload @ ..] => payload,
            _ => return Err(Error::Protocol),
        };
        let mut reader = Reader::new(payload);
        let mut blob = reader.string().map_err(protocol)?;
        reader.finish().map_err(protocol)?;
        let signature = Signature::decode(&mut blob).map_err(protocol)?;
        let expected = match (&algorithm, signature.algorithm()) {
            (Algorithm::Rsa { .. }, Algorithm::Rsa { hash }) => {
                rsa_hash.is_none() || rsa_hash == hash
            }
            (key, signed) => *key == signed,
        };
        if !blob.is_empty() || !expected {
            return Err(Error::Protocol);
        }
        Ok(signature)
    }
}

impl<S: AgentIo + Unpin + Send> Signer for Client<S> {
    async fn auth_sign(&mut self, request: SignRequest<'_>) -> io::Result<Vec<u8>> {
        let algorithm = Algorithm::new(request.algorithm).map_err(io::Error::other)?;
        let credential = decode_credential(request.public_key).map_err(io::Error::other)?;
        let hash = match algorithm {
            Algorithm::Rsa { hash } => hash,
            _ => None,
        };
        let signature = self
            .sign(&credential, hash, request.data)
            .await
            .map_err(io::Error::other)?;
        signature.encode_vec().map_err(io::Error::other)
    }
}

fn decode_credential(blob: &[u8]) -> Result<Credential, Error> {
    let algorithm = Reader::new(blob).string().map_err(protocol)?;
    if algorithm.ends_with(b"-cert-v01@openssh.com") {
        Ok(Certificate::from_bytes(blob)?.into())
    } else {
        Ok(key::from_blob(blob)?.into())
    }
}
