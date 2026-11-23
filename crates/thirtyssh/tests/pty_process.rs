#![cfg(any(unix, windows))]

#[path = "../examples/pty/mod.rs"]
mod pty;

use portable_pty::CommandBuilder;
use std::{ffi::OsString, io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use thirtyssh::{
    channel::{Channel, DEFAULT_WINDOW, Message},
    client,
    exec::{self, Exit},
    forward::{TcpipKind, TcpipOpen},
    pty::TerminalSize,
    server::{self, AuthPolicy},
    session::{self, Context, IncomingChannel, PtyRequest, Request, Session},
    transport::HostKey,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

#[path = "fixtures/pinned.rs"]
mod pinned;
use pinned::Pinned;

fn python() -> OsString {
    std::env::var_os("THIRTYSSH_TEST_PYTHON").unwrap_or_else(|| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    })
}

fn probe_command() -> CommandBuilder {
    let mut command = CommandBuilder::new(python());
    command.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/terminal_probe.py"));
    command
}

async fn pair<H: server::Handler>(handler: impl FnOnce([u8; 32]) -> H) -> (Session, Session) {
    let host = HostKey::generate().unwrap();
    let client_key = HostKey::generate().unwrap();
    let verifier = Pinned(host.public_key());
    let (a, b) = duplex(8192);
    let accept = server::accept_over(
        Arc::new(server::Config::new(host)),
        a,
        None,
        handler(client_key.public_key()),
    );
    let connect = async {
        let mut auth = client::connect_over(Arc::new(client::Config::default()), b, verifier)
            .await
            .unwrap();
        assert!(
            auth.authenticate(pty::USER, &client_key)
                .await
                .unwrap()
                .is_accepted()
        );
        auth
    };
    let (server, client) = tokio::join!(accept, connect);
    (server.unwrap(), client.start().unwrap())
}

async fn open() -> (Session, Session, Channel) {
    let (server, client) = pair(|key| pty::Shell {
        key,
        command: probe_command(),
    })
    .await;
    let channel = client.handle().open_session().await.unwrap();
    (server, client, channel)
}

async fn shell(channel: &mut Channel) {
    // The sample's default is a fixed local program admitted via PTY+shell.
    channel.request(Request::Shell, true).await.unwrap();
    assert_eq!(
        channel.recv().await,
        Some(Message::Reply { success: false })
    );
    channel
        .request(
            Request::Pty(
                PtyRequest::from_modes(
                    "xterm-256color",
                    TerminalSize {
                        columns: 65537,
                        rows: 24,
                        pixel_width: 0,
                        pixel_height: 0,
                    },
                    &[],
                )
                .unwrap(),
            ),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        channel.recv().await,
        Some(Message::Reply { success: false })
    );
    channel
        .request(
            Request::Pty(
                PtyRequest::from_modes(
                    "xterm-256color",
                    TerminalSize {
                        columns: 80,
                        rows: 24,
                        pixel_width: 0,
                        pixel_height: 0,
                    },
                    &[],
                )
                .unwrap(),
            ),
            true,
        )
        .await
        .unwrap();
    assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
    channel.request(Request::Shell, true).await.unwrap();
    assert_eq!(channel.recv().await, Some(Message::Reply { success: true }));
}

async fn read_until(channel: &mut Channel, bytes: &mut Vec<u8>, needle: &str) {
    let found = timeout(PROBE_TIMEOUT, async {
        while !bytes
            .windows(needle.len())
            .any(|span| span == needle.as_bytes())
        {
            match channel.recv().await {
                Some(Message::Data(data)) => bytes.extend_from_slice(&data),
                other => panic!(
                    "expected {needle:?}, read {other:?}; output={:?}",
                    String::from_utf8_lossy(bytes)
                ),
            }
            assert!(
                bytes.len() < 1024 * 1024,
                "terminal probe produced too much output"
            );
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "expected {needle:?}; output={:?}",
        String::from_utf8_lossy(bytes)
    );
}

async fn ready(channel: &mut Channel, bytes: &mut Vec<u8>) {
    // ConPTY asks the attached terminal for its cursor position at startup.
    #[cfg(windows)]
    {
        read_until(channel, bytes, "\x1b[6n").await;
        channel.send("\x1b[1;1R").await.unwrap();
    }
    read_until(channel, bytes, "-xterm-256color").await;
}

async fn exit(channel: &mut Channel, bytes: &mut Vec<u8>) -> Exit {
    let mut exit = None;
    let mut eof = false;
    loop {
        let message = channel
            .recv()
            .await
            .expect("channel closed without SSH CLOSE");
        match message {
            Message::Data(data) => {
                assert!(!eof);
                bytes.extend_from_slice(&data);
            }
            Message::Eof => eof = true,
            Message::Closed => {
                assert!(eof);
                return exit.expect("missing exit status");
            }
            other => {
                if let Some(Request::Exit(result)) =
                    other.session_request().unwrap().map(|r| r.request)
                {
                    assert!(!eof && exit.replace(result).is_none());
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires native PTY and Python 3"]
async fn native_pty_input_resize_alternate_screen_and_interrupt() {
    timeout(PROBE_TIMEOUT * 2, async {
        let (_server, _client, mut channel) = open().await;
        shell(&mut channel).await;
        let mut bytes = Vec::new();
        ready(&mut channel, &mut bytes).await;
        read_until(&mut channel, &mut bytes, "SIZE-80x24").await;
        channel
            .request(
                Request::WindowChange(TerminalSize {
                    columns: 101,
                    rows: 37,
                    pixel_width: 800,
                    pixel_height: 600,
                }),
                false,
            )
            .await
            .unwrap();
        read_until(&mut channel, &mut bytes, "SIZE-101x37").await;
        channel.send("hello terminal\r").await.unwrap();
        read_until(&mut channel, &mut bytes, "ECHO-hello terminal").await;
        channel.send(&b"\x03"[..]).await.unwrap();
        read_until(&mut channel, &mut bytes, "INTERRUPTED").await;
        assert_eq!(exit(&mut channel, &mut bytes).await, Exit::Status(43));
        let output = String::from_utf8_lossy(&bytes);
        assert!(
            output.contains("\x1b[?1049h") && output.contains("\x1b[?1049l"),
            "output={output:?}"
        );
    })
    .await
    .unwrap();
}

struct Multiplexed {
    shell: pty::Shell,
    destination: SocketAddr,
    slow: Option<(oneshot::Sender<()>, oneshot::Sender<io::ErrorKind>)>,
    tasks: JoinSet<io::Result<()>>,
}

impl AuthPolicy for Multiplexed {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        self.shell.public_key(user, key).await
    }
}

impl session::Handler for Multiplexed {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        context: &Context,
    ) -> io::Result<()> {
        while let Some(result) = self.tasks.try_join_next() {
            result.map_err(io::Error::other)??;
        }
        if request.kind() == b"session" && request.fields().is_empty() {
            let channel = request.accept(DEFAULT_WINDOW, &[]).await?;
            if let Some((filled, cancelled)) = self.slow.take() {
                self.tasks.spawn(async move {
                    let exec = exec::receive(channel).await?.expect("slow exec request");
                    assert_eq!(exec.command(), b"slow");
                    let (_, _stdin, mut output) = exec.accept().await?.split();
                    // The client leaves this channel unread. Its entire SSH receive
                    // window is now occupied, even while other channels are serviced.
                    let stdout = output.stdout();
                    stdout
                        .write_all(&vec![0x8a; DEFAULT_WINDOW as usize])
                        .await?;
                    stdout.flush().await?;
                    filled.send(()).expect("fixture still waiting for output");
                    let err = async {
                        stdout.write_all(b"blocked").await?;
                        stdout.flush().await
                    }
                    .await
                    .unwrap_err();
                    cancelled
                        .send(err.kind())
                        .expect("fixture still waiting for close");
                    Ok(())
                });
            } else {
                let handle = context.handle();
                let command = self.shell.command.clone();
                self.tasks
                    .spawn(async move { pty::serve(channel, handle, &command).await });
            }
        } else if let Some(open) = request.tcpip()?
            && open.kind == TcpipKind::Direct
            && open.address == "127.0.0.1"
            && open.port == u32::from(self.destination.port())
        {
            let mut socket = TcpStream::connect(self.destination).await?;
            let mut channel = request.accept(DEFAULT_WINDOW, &[]).await?.into_io();
            self.tasks.spawn(async move {
                copy_bidirectional(&mut channel, &mut socket).await?;
                Ok(())
            });
        } else {
            request.refuse(1).await?;
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires native PTY and Python 3"]
async fn slow_exec_keeps_native_pty_and_tcp_forward_live_across_rekey() {
    timeout(PROBE_TIMEOUT * 2, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let (filled, full) = oneshot::channel();
        let (cancelled, mut closed) = oneshot::channel();
        let (server, client) = pair(|key| Multiplexed {
            shell: pty::Shell {
                key,
                command: probe_command(),
            },
            destination,
            slow: Some((filled, cancelled)),
            tasks: JoinSet::new(),
        })
        .await;
        let handle = client.handle();
        let slow = exec::start(&handle, b"slow").await.unwrap();
        full.await.unwrap();

        let mut terminal = handle.open_session().await.unwrap();
        shell(&mut terminal).await;
        let mut bytes = Vec::new();
        ready(&mut terminal, &mut bytes).await;
        read_until(&mut terminal, &mut bytes, "SIZE-80x24").await;

        let mut forward = handle
            .open_as(TcpipOpen {
                kind: TcpipKind::Direct,
                address: "127.0.0.1",
                port: u32::from(destination.port()),
                originator_address: "127.0.0.1",
                originator_port: 12345,
            })
            .await
            .unwrap()
            .into_io();
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut payload = [0; 4];
        forward.write_all(b"one\0").await.unwrap();
        socket.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"one\0");

        let (rekey, keystroke, data) = tokio::join!(
            handle.rekey(),
            terminal.send("during rekey\r"),
            forward.write_all(b"two\xff"),
        );
        rekey.unwrap();
        keystroke.unwrap();
        data.unwrap();
        read_until(&mut terminal, &mut bytes, "ECHO-during rekey").await;
        socket.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"two\xff");
        assert_eq!(closed.try_recv(), Err(oneshot::error::TryRecvError::Empty));
        drop(slow);
        assert_eq!(closed.await.unwrap(), io::ErrorKind::BrokenPipe);

        terminal
            .request(
                Request::WindowChange(TerminalSize {
                    columns: 103,
                    rows: 39,
                    pixel_width: 800,
                    pixel_height: 600,
                }),
                false,
            )
            .await
            .unwrap();
        read_until(&mut terminal, &mut bytes, "SIZE-103x39").await;
        terminal.send(&b"\x03"[..]).await.unwrap();
        read_until(&mut terminal, &mut bytes, "INTERRUPTED").await;
        assert_eq!(exit(&mut terminal, &mut bytes).await, Exit::Status(43));
        forward.shutdown().await.unwrap();
        assert_eq!(socket.read(&mut payload).await.unwrap(), 0);
        socket.write_all(b"after EOF").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut tail = Vec::new();
        forward.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"after EOF");
        handle.ping().await.unwrap();
        client.disconnect().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires native PTY and Python 3"]
async fn native_pty_reaps_child_on_eof_close_and_disconnect() {
    timeout(PROBE_TIMEOUT * 4, async {
        for shutdown in ["eof", "close", "disconnect"] {
            let (server, client, mut channel) = open().await;
            shell(&mut channel).await;
            channel.request(Request::WindowChange(TerminalSize { columns: 92, rows: 30, pixel_width: 0, pixel_height: 0 }), false).await.unwrap();
            let mut bytes = Vec::new();
            ready(&mut channel, &mut bytes).await;
            read_until(&mut channel, &mut bytes, "SIZE-92x30").await;
            let output = String::from_utf8_lossy(&bytes);
            let pid: u32 = output.split_once("READY-").unwrap().1.split_once('-').unwrap().0.parse().unwrap();
            assert!(pid > 0);
            match shutdown {
                "eof" => {
                    channel.eof().await.unwrap();
                    assert!(matches!(exit(&mut channel, &mut bytes).await, Exit::Status(code) if code != 0));
                }
                "close" => channel.close().await.unwrap(),
                "disconnect" => {
                    drop(client);
                    server.await.unwrap();
                }
                _ => unreachable!(),
            }
            assert_reaped(pid, shutdown).await;
        }
    }).await.unwrap();
}

async fn assert_reaped(pid: u32, cause: &str) {
    let check = r#"
import os, sys, time
pid = int(sys.argv[1])
if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x100000, False, pid)
    if handle:
        result = kernel.WaitForSingleObject(handle, 5000)
        kernel.CloseHandle(handle)
        sys.exit(result != 0)
    sys.exit(ctypes.get_last_error() != 87)
else:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            sys.exit(0)
        time.sleep(0.025)
    sys.exit(1)
"#;
    let mut command = Command::new(python());
    command
        .args(["-c", check, &pid.to_string()])
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let result = timeout(PROBE_TIMEOUT, command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.status.success(),
        "process {pid} survived {cause}; stderr={:?}",
        String::from_utf8_lossy(&result.stderr)
    );
}
