use portable_pty::{Child, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system};
use std::{
    io::{self, ErrorKind, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use thirtyssh::{channel::Bytes, pty::TerminalSize};
use tokio::sync::{mpsc, oneshot, watch};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const EOF_GRACE: Duration = Duration::from_secs(1);
const BUFFER_CHUNKS: usize = 8;

#[derive(Clone, Copy)]
pub(super) struct Terminal {
    size: PtySize,
    eof: bool,
}

impl Terminal {
    pub(super) fn new(size: TerminalSize) -> io::Result<Self> {
        let mut terminal = Self {
            size: PtySize::default(),
            eof: false,
        };
        terminal.resize(size)?;
        Ok(terminal)
    }

    pub(super) fn resize(&mut self, size: TerminalSize) -> io::Result<()> {
        self.size = PtySize {
            cols: dimension(size.columns, self.size.cols, 512)?,
            rows: dimension(size.rows, self.size.rows, 512)?,
            pixel_width: dimension(size.pixel_width, self.size.pixel_width, u16::MAX)?,
            pixel_height: dimension(size.pixel_height, self.size.pixel_height, u16::MAX)?,
        };
        Ok(())
    }

    pub(super) fn eof(&mut self) {
        self.eof = true;
    }
}

fn dimension(value: u32, previous: u16, maximum: u16) -> io::Result<u16> {
    match value {
        0 => Ok(previous),
        value if value <= u32::from(maximum) => Ok(value as u16),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "terminal dimension exceeds example limit",
        )),
    }
}

pub(super) struct Process {
    pub(super) input: mpsc::Sender<Bytes>,
    pub(super) output: mpsc::Receiver<io::Result<Vec<u8>>>,
    pub(super) terminal: watch::Sender<Terminal>,
    pub(super) exit: oneshot::Receiver<io::Result<ExitStatus>>,
}

impl Process {
    pub(super) async fn start(command: CommandBuilder, terminal: Terminal) -> io::Result<Self> {
        let (input, writer) = mpsc::channel(BUFFER_CHUNKS);
        let (reader, output) = mpsc::channel(BUFFER_CHUNKS);
        let (terminal, control) = watch::channel(terminal);
        let (started, ready) = oneshot::channel();
        let (finished, exit) = oneshot::channel();
        thread::Builder::new()
            .name("ssh-pty-child".into())
            .spawn(move || {
                let result = run(command, control, writer, reader, started);
                let _ = finished.send(result);
            })?;
        match ready.await {
            Ok(()) => Ok(Self {
                input,
                output,
                terminal,
                exit,
            }),
            Err(_) => Err(exit
                .await
                .map_err(io::Error::other)?
                .err()
                .unwrap_or_else(|| io::Error::other("terminal exited before startup"))),
        }
    }
}

fn run(
    command: CommandBuilder,
    mut control: watch::Receiver<Terminal>,
    input: mpsc::Receiver<Bytes>,
    output: mpsc::Sender<io::Result<Vec<u8>>>,
    started: oneshot::Sender<()>,
) -> io::Result<ExitStatus> {
    let initial_size = control.borrow_and_update().size;
    let pair = native_pty_system()
        .openpty(initial_size)
        .map_err(io::Error::other)?;
    #[cfg(unix)]
    set_nonblocking(&*pair.master)?;
    let reader = pair.master.try_clone_reader().map_err(io::Error::other)?;
    let writer = pair.master.take_writer().map_err(io::Error::other)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stopped);
    let stop_writer = Arc::clone(&stopped);
    // Start the reader before spawning so ConPTY can always flush its output during teardown.
    thread::Builder::new()
        .name("ssh-pty-output".into())
        .spawn(move || read_output(reader, output, &stop_reader))?;
    thread::Builder::new()
        .name("ssh-pty-input".into())
        .spawn(move || {
            let _ = write_input(writer, input, &stop_writer);
        })?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(io::Error::other)?;
    drop(pair.slave);
    let _ = started.send(());
    let result = match monitor(&mut *child, &*pair.master, &mut control, initial_size) {
        Ok(Some(status)) => Ok(status),
        outcome => {
            let killed = child.kill();
            // A process can exit between try_wait and kill. Collect that exit too.
            let status = match killed {
                Ok(()) => child.wait(),
                Err(err) => child.try_wait().and_then(|status| status.ok_or(err)),
            };
            outcome.and(status)
        }
    };
    stopped.store(true, Ordering::Release);
    drop(pair.master);
    result
}

fn monitor(
    child: &mut dyn Child,
    master: &dyn MasterPty,
    control: &mut watch::Receiver<Terminal>,
    mut size: PtySize,
) -> io::Result<Option<ExitStatus>> {
    let mut eof_deadline = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        match control.has_changed() {
            Err(_) => return Ok(None),
            Ok(true) => {
                let terminal = *control.borrow_and_update();
                if terminal.size != size {
                    master.resize(terminal.size).map_err(io::Error::other)?;
                    size = terminal.size;
                }
                if terminal.eof {
                    eof_deadline.get_or_insert_with(|| Instant::now() + EOF_GRACE);
                }
            }
            Ok(false) => {}
        }
        if eof_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn set_nonblocking(master: &dyn MasterPty) -> io::Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let fd = master
        .as_raw_fd()
        .ok_or_else(|| io::Error::other("missing Unix PTY descriptor"))?;
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

fn read_output(
    mut reader: impl Read,
    output: mpsc::Sender<io::Result<Vec<u8>>>,
    stopped: &AtomicBool,
) {
    let mut bytes = [0; 8192];
    let mut forward = true;
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => {
                if forward {
                    // ClosePseudoConsole can wait for output readers on older Windows.
                    forward = output.blocking_send(Ok(bytes[..n].to_vec())).is_ok();
                }
                #[cfg(unix)]
                if !forward && stopped.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(err) => {
                let _ = output.blocking_send(Err(err));
                break;
            }
        }
    }
}

fn write_input(
    mut writer: impl Write,
    mut input: mpsc::Receiver<Bytes>,
    stopped: &AtomicBool,
) -> io::Result<()> {
    while let Some(bytes) = input.blocking_recv() {
        let mut bytes = bytes.as_ref();
        while !bytes.is_empty() && !stopped.load(Ordering::Acquire) {
            match writer.write(bytes) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
                Err(err) => return Err(err),
            }
        }
    }
    Ok(())
}
