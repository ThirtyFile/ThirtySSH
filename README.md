# ThirtySSH

[![CI](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml/badge.svg)](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/thirtyssh.svg)](https://crates.io/crates/thirtyssh)
[![docs.rs](https://docs.rs/thirtyssh/badge.svg)](https://docs.rs/thirtyssh)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

An asynchronous SSH-2 client and server library for Rust, built on Tokio.
It is an independent implementation with a layered design: use the high-level
client and server, or build on the transport, authentication and channel
layers directly.

> **Status:** pre-1.0. The API may change between minor versions.
> Read [SECURITY.md](SECURITY.md) before using it in production.

## Features

- Client and server, multiplexed channels with flow control
- Key exchange: ML-KEM-768 + X25519 hybrid, Curve25519, NIST P-256/384/521,
  DH group exchange and fixed groups; strict key exchange (Terrapin mitigation)
- Ciphers: ChaCha20-Poly1305, AES-GCM, AES-CTR, and AES-CBC for older peers
- Public key, password and keyboard-interactive authentication, OpenSSH user
  and host certificates, GSSAPI hooks
- Key formats: OpenSSH, PKCS#1/#8 (encrypted too), PuTTY `.ppk`
- `known_hosts` parsing, matching and updating (hashed hosts, `@cert-authority`,
  `@revoked`)
- SSH agent client and server, agent forwarding, Windows Pageant
- Port forwarding, streamlocal (Unix socket) forwarding, PTY helpers, `exec`
- Keepalive and inactivity handling

## Installation

Add ThirtySSH from crates.io:

```toml
[dependencies]
thirtyssh = "0.2"
tokio = { version = "1", features = ["macros", "rt"] }
```

The minimum supported Rust version is 1.89. Linux, Windows and macOS are
tested in CI.

## Example

Connect, check the host against `known_hosts`, log in with a key and run a
command:

```rust
use std::{io, sync::Arc};
use thirtyssh::{
    client::{self, Method},
    exec,
    keys::{Algorithm, Credential, PrivateKeyReader},
    known_hosts::{KnownHosts, Status},
    session,
};

struct Known(KnownHosts);

impl session::Handler for Known {}

impl client::Handler for Known {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let status = match host {
            Credential::Key(key) => self.0.check_public_key("example.com", 22, key)?,
            Credential::Certificate(cert) => self.0.check_certificate("example.com", 22, cert)?,
        };
        Ok(status == Status::Trusted)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let mut hosts = KnownHosts::new();
    hosts.load("/home/me/.ssh/known_hosts")?;
    let config = Arc::new(client::Config::default());
    let mut client = client::connect(config, ("example.com", 22), Known(hosts)).await?;

    let key = PrivateKeyReader::new().file("/home/me/.ssh/id_ed25519")?;
    let method = Method::Key { key: &key, algorithm: None };
    if !client.authenticate("me", method).await?.is_accepted() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "login rejected"));
    }

    let session = client.start()?;
    let output = exec::start(&session.handle(), b"uname -a")
        .await?
        .capture(tokio::io::empty(), 1024 * 1024)
        .await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    session.disconnect().await
}
```

A host is trusted only when `verify_host` says so; the default refuses every
host. Complete programs, including a server with a pseudo-terminal, are in
[`crates/thirtyssh/examples`](crates/thirtyssh/examples):

```sh
cargo run -p thirtyssh --example openssh_exec -- \
  HOST 22 USER ~/.ssh/known_hosts ~/.ssh/id_ed25519 "uname -a"
```

The API documentation is on [docs.rs](https://docs.rs/thirtyssh).

## Cargo features

| Feature | Default | Purpose |
|---|---|---|
| `ring` | yes | Crypto backend (one of `ring` or `aws-lc-rs` is required) |
| `aws-lc-rs` | no | Alternative crypto backend, used when both are enabled |
| `rsa` | yes | RSA keys and signatures |
| `flate2` | yes | `zlib` and `zlib@openssh.com` compression |
| `dsa` | no | Legacy DSA keys |
| `des` | no | Legacy `3des-cbc` cipher and 3DES-encrypted key files |
| `serde` | no | `serde` support for key types |
| `pre-rfc8410-ed25519` | no | Parser for a pre-RFC 8410 PKCS#8 Ed25519 key encoding |

## Workspace layout

| Path | Crate | Purpose |
|---|---|---|
| `crates/thirtyssh` | `thirtyssh` | The SSH library |
| `crates/secretbuf` | `thirtyssh-secretbuf` | Page-locked byte buffer, erased when released |
| `crates/pageant` | `thirtyssh-pageant` | Pageant client (Windows only) |
| `tools/` | | Helper scripts for interoperability tests |
| `docs/` | | Architecture notes |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

Interoperability tests against real OpenSSH binaries are marked `#[ignore]`
and run in CI on Linux. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
