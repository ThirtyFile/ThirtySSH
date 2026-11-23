#[cfg(any(unix, windows))]
mod pty;

#[cfg(any(unix, windows))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use data_encoding::BASE64;
    use portable_pty::CommandBuilder;
    use std::{
        env, fs,
        io::{self, Write},
        sync::Arc,
    };
    use thirtyssh::{server, transport::HostKey};
    use tokio::net::TcpListener;

    const ED25519_PREFIX: &[u8] = b"\0\0\0\x0bssh-ed25519\0\0\0\x20";
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: pty_server CLIENT_ED25519_PUBLIC_KEY NEW_KNOWN_HOSTS PROGRAM [ARG ...]",
        )
    };
    let mut args = env::args_os().skip(1);
    let client_key = fs::read_to_string(args.next().ok_or_else(invalid)?)?;
    let known_hosts = args.next().ok_or_else(invalid)?;
    let mut command = CommandBuilder::new(args.next().ok_or_else(invalid)?);
    command.args(args);

    let mut fields = client_key.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an OpenSSH Ed25519 public key",
        ));
    }
    let blob = BASE64
        .decode(fields.next().ok_or_else(invalid)?.as_bytes())
        .map_err(io::Error::other)?;
    let key = blob
        .strip_prefix(ED25519_PREFIX)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid)?;

    struct Factory(pty::Shell);
    impl server::Connections for Factory {
        type Handler = pty::Shell;

        fn handler(&mut self, _: std::net::SocketAddr) -> Self::Handler {
            self.0.clone()
        }

        fn failed(&mut self, err: io::Error) {
            eprintln!("SSH session ended: {err}");
        }
    }

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let host_key = HostKey::generate()?;
    let host_blob = [ED25519_PREFIX, &host_key.public_key()].concat();
    let host_line = format!(
        "[127.0.0.1]:{port} ssh-ed25519 {}\n",
        BASE64.encode(&host_blob)
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(known_hosts)?
        .write_all(host_line.as_bytes())?;
    let server = server::listen_on(
        Arc::new(server::Config::new(host_key)),
        listener,
        Factory(pty::Shell { key, command }),
    )?;
    println!("Listening on 127.0.0.1:{port} as {}", pty::USER);
    server.await
}

#[cfg(not(any(unix, windows)))]
fn main() -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
