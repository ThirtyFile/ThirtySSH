//! ThirtySSH: an asynchronous SSH-2 client and server library built on Tokio.
//!
//! The crate offers layered building blocks, from the raw [`transport`] and
//! [`auth`] exchanges up to multiplexed [`session`]s with [`client`] and
//! [`server`] front ends, plus [`keys`] handling, [`known_hosts`] and agent
//! support.
//!
//! # Example
//!
//! Connect, check the host against `known_hosts`, log in with a key and run
//! a command:
//!
//! ```no_run
//! use std::{io, sync::Arc};
//! use thirtyssh::{
//!     client::{self, Method},
//!     exec,
//!     keys::{Algorithm, Credential, PrivateKeyReader},
//!     known_hosts::{KnownHosts, Status},
//!     session,
//! };
//!
//! struct Known(KnownHosts);
//!
//! impl session::Handler for Known {}
//!
//! impl client::Handler for Known {
//!     async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
//!         let status = match host {
//!             Credential::Key(key) => self.0.check_public_key("example.com", 22, key)?,
//!             Credential::Certificate(cert) => self.0.check_certificate("example.com", 22, cert)?,
//!         };
//!         Ok(status == Status::Trusted)
//!     }
//! }
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> io::Result<()> {
//!     let mut hosts = KnownHosts::new();
//!     hosts.load("/home/me/.ssh/known_hosts")?;
//!     let config = Arc::new(client::Config::default());
//!     let mut client = client::connect(config, ("example.com", 22), Known(hosts)).await?;
//!
//!     let key = PrivateKeyReader::new().file("/home/me/.ssh/id_ed25519")?;
//!     let method = Method::Key { key: &key, algorithm: None };
//!     if !client.authenticate("me", method).await?.is_accepted() {
//!         return Err(io::Error::new(io::ErrorKind::PermissionDenied, "login rejected"));
//!     }
//!
//!     let session = client.start()?;
//!     let output = exec::start(&session.handle(), b"uname -a")
//!         .await?
//!         .capture(tokio::io::empty(), 1024 * 1024)
//!         .await?;
//!     print!("{}", String::from_utf8_lossy(&output.stdout));
//!     session.disconnect().await
//! }
//! ```
//!
//! # Cargo features
//!
//! | Feature | Default | Purpose |
//! |---|---|---|
//! | `ring` | yes | Crypto backend (one of `ring` or `aws-lc-rs` is required) |
//! | `aws-lc-rs` | no | Alternative crypto backend, preferred when both are on |
//! | `rsa` | yes | RSA keys and signatures |
//! | `flate2` | yes | `zlib` and `zlib@openssh.com` compression |
//! | `dsa` | no | Legacy DSA keys |
//! | `des` | no | Legacy `3des-cbc` transport cipher and 3DES-encrypted key files |
//! | `serde` | no | `serde` support for key types |
//! | `pre-rfc8410-ed25519` | no | Parser for a pre-RFC 8410 PKCS#8 Ed25519 key encoding |
#![forbid(unsafe_code)]

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("ThirtySSH requires either the `aws-lc-rs` or `ring` feature as a crypto backend");

// Prefer AWS-LC when Cargo enables both crypto backend features.
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as crypto_backend;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as crypto_backend;
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
use ring as _;

pub use thirtyssh_secretbuf::SecretBuf;

pub mod algorithms;
pub mod auth;
pub mod channel;
pub mod clear_packet;
pub mod client;
pub(crate) mod compression;
pub mod exec;
pub(crate) mod extensions;
pub mod forward;
pub mod identification;
pub mod initial;
pub(crate) mod kex;
pub mod keys;
pub mod known_hosts;
pub(crate) mod protection;
pub mod protocol_error;
#[cfg(feature = "_bench")]
#[doc(hidden)]
pub use protection::benchmark;
pub mod pty;
pub use pty::Pty;
pub(crate) mod runtime;
pub mod server;
pub mod session;
pub mod transport;
pub mod wire;
