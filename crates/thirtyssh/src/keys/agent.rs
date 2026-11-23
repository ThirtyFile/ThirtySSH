//! Identity types used by external signers and SSH agents.
use super::Certificate;
pub use super::Credential;
use ssh_key::public::KeyData;

mod client;
mod protocol;
pub mod server;

pub use client::{AgentIo, BoxedIo, Client};

/// Why an agent request did not succeed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The agent answered with a failure. It does not say why: the key may be
    /// unknown, the agent locked, or the request declined.
    Refused,
    /// A message did not follow the agent protocol, or exceeds its size limit.
    Protocol,
    ExtensionUnsupported,
    ExtensionFailed,
    /// `SSH_AUTH_SOCK` is unset, or names a socket that does not exist.
    NotRunning,
    Io(std::io::Error),
    Key(ssh_key::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Refused => "the SSH agent refused the request",
            Self::Protocol => "malformed SSH agent message",
            Self::ExtensionUnsupported => "the SSH agent does not support the extension",
            Self::ExtensionFailed => "the SSH agent extension request failed",
            Self::NotRunning => "no SSH agent is reachable through SSH_AUTH_SOCK",
            Self::Io(error) => return error.fmt(f),
            Self::Key(error) => return write!(f, "SSH key encoding: {error}"),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // The I/O error speaks for itself above; its own cause follows.
            Self::Io(error) => error.source(),
            Self::Key(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ssh_key::Error> for Error {
    fn from(error: ssh_key::Error) -> Self {
        Self::Key(error)
    }
}

impl From<ssh_encoding::Error> for Error {
    fn from(error: ssh_encoding::Error) -> Self {
        Self::Key(error.into())
    }
}

/// A restriction the agent applies to a key it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// Forget the key after this many seconds.
    Lifetime { seconds: u32 },
    /// Ask for approval before every signature.
    ConfirmEachUse,
    /// A named constraint extension and its encoded fields.
    Extension { name: Vec<u8>, data: Vec<u8> },
}

/// A credential held by an agent, with the label the agent keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    credential: Credential,
    comment: String,
}

impl Identity {
    pub fn new(credential: impl Into<Credential>, comment: impl Into<String>) -> Self {
        Self {
            credential: credential.into(),
            comment: comment.into(),
        }
    }

    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The certificate, when the agent holds one for this identity.
    pub fn certificate(&self) -> Option<&Certificate> {
        self.credential.certificate()
    }

    pub fn key_data(&self) -> &KeyData {
        self.credential.key_data()
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }
}
