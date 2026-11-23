use std::io;
use thirtyssh::{
    client,
    keys::{Algorithm, Credential},
    session,
};

/// A client handler that trusts exactly one Ed25519 host key.
pub struct Pinned(pub [u8; 32]);

impl session::Handler for Pinned {}

impl client::Handler for Pinned {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        Ok(host.ed25519() == Some(self.0))
    }
}
