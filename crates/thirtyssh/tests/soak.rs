#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thirtyssh::{
    channel::Channel,
    client,
    forward::{TcpipKind, TcpipOpen},
    keys::{Algorithm, Credential},
    server,
    session::{self, Context, IncomingChannel, OpenType},
    transport::{CompletedKeyExchange, HostKey, Limits},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::{Barrier, oneshot},
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout},
};

const CLIENTS: usize = 8;
const CHANNELS: usize = 3;
const WINDOW: u32 = 32 * 1024;
const PACKET: u32 = 16 * 1024;
const CHUNK: usize = 8 * 1024;
const PAYLOAD: usize = 192 * 1024;
const REKEY_LIMIT: usize = 256 * 1024;
const WARMUP_WAVES: usize = 3;
const WAVE_PERIOD: Duration = Duration::from_secs(1);
const WAVE_TIMEOUT: Duration = Duration::from_secs(20);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_RSS_SLACK_KIB: usize = 16 * 1024;
const PEAK_RSS_LIMIT_KIB: usize = 96 * 1024;
const USER: &str = "soak";

type Failure = Arc<Mutex<Option<io::Error>>>;

struct Endpoint {
    key: [u8; 32],
    target: SocketAddr,
    failure: Failure,
}

impl server::Connections for Endpoint {
    type Handler = ServerSession;

    fn handler(&mut self, _: SocketAddr) -> ServerSession {
        ServerSession {
            key: self.key,
            target: self.target,
            tasks: JoinSet::new(),
        }
    }

    fn failed(&mut self, error: io::Error) {
        self.failure.lock().unwrap().get_or_insert(error);
    }
}

struct ServerSession {
    key: [u8; 32],
    target: SocketAddr,
    tasks: JoinSet<io::Result<()>>,
}

impl server::AuthPolicy for ServerSession {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        Ok(user == USER && self.key == *key)
    }
}

impl session::Handler for ServerSession {
    async fn channel_open(&mut self, request: IncomingChannel, _: &Context) -> io::Result<()> {
        match request.open_type()? {
            OpenType::Session => {
                let stream = request.accept(WINDOW, &[]).await?.into_io();
                self.tasks.spawn(echo(stream));
            }
            OpenType::Tcpip(open)
                if open.kind == TcpipKind::Direct
                    && open.address == "127.0.0.1"
                    && open.port == u32::from(self.target.port()) =>
            {
                let mut socket = TcpStream::connect(self.target).await?;
                socket.set_nodelay(true)?;
                let mut stream = request.accept(WINDOW, &[]).await?.into_io();
                self.tasks.spawn(async move {
                    let (sent, received) = copy_bidirectional(&mut stream, &mut socket).await?;
                    if sent != PAYLOAD as u64 || received != sent {
                        return Err(io::Error::other("TCP relay transferred an unexpected size"));
                    }
                    Ok(())
                });
            }
            _ => request.refuse(1).await?,
        }
        Ok(())
    }

    async fn connection_finished(&mut self, result: &mut io::Result<()>, _: &Context) {
        let drained = timeout(SETTLE_TIMEOUT, async {
            while let Some(task) = self.tasks.join_next().await {
                task.map_err(io::Error::other)??;
            }
            Ok::<(), io::Error>(())
        })
        .await
        .map_err(io::Error::other)
        .and_then(|result| result);
        if let Err(error) = drained {
            *result = Err(error);
        }
    }
}

async fn echo(stream: impl AsyncRead + AsyncWrite + Unpin) -> io::Result<()> {
    let (mut read, mut write) = tokio::io::split(stream);
    let bytes = tokio::io::copy(&mut read, &mut write).await?;
    if bytes != PAYLOAD as u64 {
        return Err(io::Error::other("echo received an unexpected size"));
    }
    write.shutdown().await
}

async fn tcp_echo(listener: TcpListener, mut stop: oneshot::Receiver<()>) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            Some(result) = tasks.join_next() => result.map_err(io::Error::other)??,
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                socket.set_nodelay(true)?;
                tasks.spawn(echo(socket));
            }
        }
    }
    while let Some(task) = tasks.join_next().await {
        task.map_err(io::Error::other)??;
    }
    Ok(())
}

struct Pinned {
    key: [u8; 32],
    rekeys: Arc<Mutex<usize>>,
}

impl client::Handler for Pinned {
    fn observe_key_exchanges(&self) -> bool {
        true
    }

    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let Some(key) = host.ed25519() else {
            return Ok(false);
        };
        Ok(self.key == key)
    }
}

impl session::Handler for Pinned {
    async fn key_exchange_done(
        &mut self,
        exchange: CompletedKeyExchange,
        _: &Context,
    ) -> io::Result<()> {
        if !exchange.initial {
            *self.rekeys.lock().unwrap() += 1;
        }
        Ok(())
    }
}

async fn verify_channel(channel: Channel, read_delay: Duration) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(channel.into_io());
    let (sent, received) = tokio::try_join!(
        async {
            let mut buffer = [0; CHUNK];
            getrandom::fill(&mut buffer).map_err(io::Error::other)?;
            let mut digest = Sha256::new();
            for index in 0..PAYLOAD / CHUNK {
                buffer[..8].copy_from_slice(&(index as u64).to_be_bytes());
                writer.write_all(&buffer).await?;
                digest.update(buffer);
            }
            writer.shutdown().await?;
            Ok::<_, io::Error>(digest.finalize())
        },
        async {
            if !read_delay.is_zero() {
                sleep(read_delay).await;
            }
            let mut digest = Sha256::new();
            let mut buffer = [0; CHUNK];
            for _ in 0..PAYLOAD / CHUNK {
                reader.read_exact(&mut buffer).await?;
                digest.update(buffer);
            }
            if reader.read(&mut buffer).await? != 0 {
                return Err(io::Error::other("echo sent extra channel data"));
            }
            Ok(digest.finalize())
        }
    )?;
    if sent != received {
        return Err(io::Error::other("echo payload SHA-256 mismatch"));
    }
    Ok(())
}

#[derive(Clone)]
struct ClientEndpoint {
    config: Arc<client::Config>,
    address: SocketAddr,
    host: [u8; 32],
    user_key: HostKey,
    destination: SocketAddr,
}

impl ClientEndpoint {
    async fn transfer(
        self,
        ready: Arc<Barrier>,
        observe: bool,
    ) -> io::Result<(usize, Option<Resources>)> {
        let rekeys = Arc::new(Mutex::new(0));
        let mut authenticating = client::connect(
            self.config,
            self.address,
            Pinned {
                key: self.host,
                rekeys: rekeys.clone(),
            },
        )
        .await?;
        if !authenticating
            .authenticate(USER, &self.user_key)
            .await?
            .is_accepted()
        {
            return Err(io::Error::other("soak login refused"));
        }
        let client = authenticating.start()?;
        let handle = client.handle();
        let (name, fields) = TcpipOpen {
            kind: TcpipKind::Direct,
            address: "127.0.0.1",
            port: u32::from(self.destination.port()),
            originator_address: "127.0.0.1",
            originator_port: 12345,
        }
        .encode_open()?;
        let (slow, normal, forward) = tokio::try_join!(
            handle.open_channel("session", WINDOW, &[]),
            handle.open_channel("session", WINDOW, &[]),
            handle.open_channel(name, WINDOW, &fields),
        )?;
        ready.wait().await;
        let active = observe.then(Resources::sample).transpose()?;
        tokio::try_join!(
            verify_channel(slow, Duration::from_millis(15)),
            verify_channel(normal, Duration::ZERO),
            verify_channel(forward, Duration::ZERO),
        )?;
        client.disconnect().await?;
        let rekeys = *rekeys.lock().unwrap();
        if rekeys == 0 {
            return Err(io::Error::other("no traffic-triggered rekey was observed"));
        }
        Ok((rekeys, active))
    }
}

#[derive(Debug, Clone, Copy)]
struct Resources {
    tasks: usize,
    fds: usize,
    threads: usize,
    rss_kib: usize,
    peak_kib: usize,
}

impl Resources {
    fn sample() -> io::Result<Self> {
        let status = fs::read_to_string("/proc/self/status")?;
        let field = |name| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| io::Error::other(format!("missing {name} in /proc/self/status")))
        };
        Ok(Self {
            tasks: Handle::current().metrics().num_alive_tasks(),
            fds: fs::read_dir("/proc/self/fd")?
                .try_fold(0, |count, entry| entry.map(|_| count + 1))?,
            threads: field("Threads:")?,
            rss_kib: field("VmRSS:")?,
            peak_kib: field("VmHWM:")?,
        })
    }

    async fn settle(self) -> io::Result<Self> {
        let start = Instant::now();
        loop {
            let now = Self::sample()?;
            if (now.tasks, now.fds, now.threads) == (self.tasks, self.fds, self.threads) {
                return Ok(now);
            }
            if start.elapsed() >= SETTLE_TIMEOUT {
                return Err(io::Error::other(format!(
                    "resources did not settle: baseline {self:?}, current {now:?}"
                )));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn wave(client: &ClientEndpoint) -> io::Result<(usize, Resources)> {
    timeout(WAVE_TIMEOUT, async {
        let ready = Arc::new(Barrier::new(CLIENTS));
        let mut workers = JoinSet::new();
        for index in 0..CLIENTS {
            workers.spawn(client.clone().transfer(ready.clone(), index == 0));
        }
        let mut rekeys = 0;
        let mut resources = None;
        while let Some(result) = workers.join_next().await {
            let (exchanges, sample) = result.map_err(io::Error::other)??;
            rekeys += exchanges;
            resources = resources.or(sample);
        }
        Ok((
            rekeys,
            resources.expect("one client observes the live wave"),
        ))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "concurrent SSH wave stalled"))?
}

fn check_server(failure: &Failure) -> io::Result<()> {
    match failure.lock().unwrap().take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[tokio::test]
#[ignore = "24-hour loopback soak, run explicitly with --ignored --nocapture"]
async fn tcp_sessions_rekey_and_release_resources() -> Result<(), Box<dyn std::error::Error>> {
    let seconds = match env::var("THIRTYSSH_SOAK_SECONDS") {
        Ok(value) => value.parse::<u64>()?,
        Err(env::VarError::NotPresent) => 24 * 60 * 60,
        Err(error) => return Err(error.into()),
    };
    if seconds == 0 {
        return Err(io::Error::other("soak duration must be positive").into());
    }
    let duration = Duration::from_secs(seconds);
    let mut totals = (0u64, 0u64);
    let failure = Failure::default();
    let before_listeners = Resources::sample()?;
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let destination = echo_listener.local_addr()?;
    let (stop_echo, stop) = oneshot::channel();
    let echo_task = tokio::spawn(tcp_echo(echo_listener, stop));
    let host_key = HostKey::generate()?;
    let host = host_key.public_key();
    let user_key = HostKey::generate()?;
    let mut config = server::Config::new(host_key);
    config.nodelay = true;
    config.maximum_packet_size = PACKET;
    config.channel_buffer_size = Some(2);
    config.max_connections = CLIENTS.try_into()?;
    config.limits = Limits::new(REKEY_LIMIT, REKEY_LIMIT, Duration::from_secs(3600));
    let server = server::listen(
        Arc::new(config),
        (Ipv4Addr::LOCALHOST, 0),
        Endpoint {
            key: user_key.public_key(),
            target: destination,
            failure: failure.clone(),
        },
    )
    .await?;
    let client = ClientEndpoint {
        config: Arc::new(client::Config {
            maximum_packet_size: PACKET,
            channel_buffer_size: Some(2),
            nodelay: true,
            ..client::Config::default()
        }),
        address: server.local_addr(),
        host,
        user_key,
        destination,
    };

    let listeners = Resources::sample()?;
    for _ in 0..WARMUP_WAVES {
        wave(&client).await?;
        listeners.settle().await?;
        check_server(&failure)?;
    }
    let baseline = Resources::sample()?;
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    eprintln!(
        "soak_start schema=1 epoch={epoch} seconds={seconds} clients={CLIENTS} channels_per_client={CHANNELS} payload_bytes={PAYLOAD} window_bytes={WINDOW} packet_bytes={PACKET} rekey_bytes={REKEY_LIMIT} warmup={WARMUP_WAVES} wave_ms={} idle_rss_slack_kib={IDLE_RSS_SLACK_KIB} peak_rss_limit_kib={PEAK_RSS_LIMIT_KIB} baseline={baseline:?}",
        WAVE_PERIOD.as_millis(),
    );
    let start = Instant::now();
    let mut next_report = Duration::ZERO;
    let mut max_active_fds = baseline.fds;
    let mut max_active_tasks = baseline.tasks;
    // A suspended host can advance elapsed time without exercising any connections.
    while start.elapsed() < duration || totals.0 < seconds {
        let next_wave = Instant::now() + WAVE_PERIOD;
        let (rekeys, active) = wave(&client).await?;
        let idle = baseline.settle().await?;
        check_server(&failure)?;
        if idle.rss_kib > baseline.rss_kib + IDLE_RSS_SLACK_KIB
            || idle.peak_kib > PEAK_RSS_LIMIT_KIB
        {
            return Err(io::Error::other(format!(
                "RSS ceiling exceeded: baseline {baseline:?}, idle {idle:?}"
            ))
            .into());
        }
        max_active_fds = max_active_fds.max(active.fds);
        max_active_tasks = max_active_tasks.max(active.tasks);
        totals.0 += 1;
        totals.1 += rekeys as u64;
        let elapsed = start.elapsed();
        if elapsed >= next_report || elapsed >= duration {
            eprintln!(
                "soak_progress elapsed_ms={} waves={} connections={} checked_channels={} checked_bytes={} rekeys={} max_active_fds={max_active_fds} max_active_tasks={max_active_tasks} idle={idle:?}",
                elapsed.as_millis(),
                totals.0,
                totals.0 * CLIENTS as u64,
                totals.0 * (CLIENTS * CHANNELS) as u64,
                totals.0 * (CLIENTS * CHANNELS * PAYLOAD) as u64,
                totals.1,
            );
            next_report = elapsed + Duration::from_secs(60);
        }
        sleep_until(next_wave).await;
    }
    server.shutdown_handle().shutdown();
    timeout(WAVE_TIMEOUT, server).await??;
    check_server(&failure)?;
    let _ = stop_echo.send(());
    timeout(WAVE_TIMEOUT, echo_task).await???;
    let final_resources = before_listeners.settle().await?;
    eprintln!(
        "soak_pass elapsed_ms={} waves={} connections={} checked_channels={} checked_bytes={} rekeys={} startup={before_listeners:?} final={final_resources:?}",
        start.elapsed().as_millis(),
        totals.0,
        totals.0 * CLIENTS as u64,
        totals.0 * (CLIENTS * CHANNELS) as u64,
        totals.0 * (CLIENTS * CHANNELS * PAYLOAD) as u64,
        totals.1,
    );
    Ok(())
}
