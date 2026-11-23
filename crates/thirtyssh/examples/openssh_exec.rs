#[cfg(not(target_family = "wasm"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<std::process::ExitCode> {
    use std::{
        env,
        io::{self, ErrorKind, Write},
        process::ExitCode,
        sync::Arc,
    };
    use thirtyssh::{
        client,
        exec::{self, Exit},
        keys::{Algorithm, Credential, PrivateKeyReader},
        known_hosts::{KnownHosts, Status},
        session,
    };

    const CAPTURE_LIMIT: usize = 8 * 1024 * 1024;

    struct VerifyHost {
        hostname: String,
        port: u16,
        hosts: KnownHosts,
    }

    impl session::Handler for VerifyHost {}

    impl client::Handler for VerifyHost {
        async fn verify_host(&mut self, identity: &Credential, _: &Algorithm) -> io::Result<bool> {
            let status = match identity {
                Credential::Key(key) => {
                    self.hosts
                        .check_public_key(&self.hostname, self.port, key)?
                }
                Credential::Certificate(cert) => {
                    self.hosts
                        .check_certificate(&self.hostname, self.port, cert)?
                }
            };
            if status != Status::Trusted {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("host verification failed: {status:?}"),
                ));
            }
            Ok(true)
        }
    }

    let args: Vec<_> = env::args().skip(1).collect();
    let [host, port, user, known_hosts, identity, command] = args.as_slice() else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: openssh_exec HOST PORT USER KNOWN_HOSTS PRIVATE_KEY COMMAND",
        ));
    };
    let port: u16 = port
        .parse()
        .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
    let mut hosts = KnownHosts::new();
    hosts.load(known_hosts)?;
    let verifier = VerifyHost {
        hostname: host.clone(),
        port,
        hosts,
    };
    let mut client = client::connect(
        Arc::new(client::Config::default()),
        (host.as_str(), port),
        verifier,
    )
    .await?;
    let identity = PrivateKeyReader::new().file(identity)?;
    if !client
        .authenticate(
            user,
            client::Method::Key {
                key: &identity,
                algorithm: None,
            },
        )
        .await?
        .is_accepted()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "login rejected",
        ));
    }
    drop(identity);

    let session = client.start()?;
    let output = exec::start(&session.handle(), command.as_bytes())
        .await?
        .capture(tokio::io::empty(), CAPTURE_LIMIT)
        .await?;
    io::stdout().lock().write_all(&output.stdout)?;
    io::stderr().lock().write_all(&output.stderr)?;
    session.disconnect().await?;
    match output.exit {
        Some(Exit::Status(status)) => Ok(ExitCode::from(u8::try_from(status).unwrap_or(255))),
        Some(Exit::Signal(signal)) => Err(io::Error::other(format!(
            "remote command terminated by signal {}",
            signal.name
        ))),
        None => Err(io::Error::other(
            "remote command did not report an exit status",
        )),
    }
}

#[cfg(target_family = "wasm")]
fn main() -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
