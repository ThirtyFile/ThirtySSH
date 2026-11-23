mod bridge;

use self::bridge::{Process, Terminal};
use portable_pty::CommandBuilder;
use std::{io, time::Duration};
use thirtyssh::{
    channel::{Bytes, Channel, ChannelReceiver, Message, driver::Handle},
    exec::Exit,
    server,
    session::{self, Context, IncomingChannel, Request},
};

pub const USER: &str = "terminal";

#[derive(Clone)]
pub struct Shell {
    pub key: [u8; 32],
    pub command: CommandBuilder,
}

impl server::AuthPolicy for Shell {
    async fn public_key(&mut self, user: &str, key: &[u8; 32]) -> io::Result<bool> {
        Ok(user == USER && *key == self.key)
    }
}

impl session::Handler for Shell {
    async fn channel_open(
        &mut self,
        request: IncomingChannel,
        context: &Context,
    ) -> io::Result<()> {
        if request.kind() == b"session" && request.fields().is_empty() {
            let channel = request.accept(64 * 1024, b"").await?;
            // Callbacks run one at a time, so the shell gets a task of its
            // own. Running it here would hold up every later channel and
            // request of this connection until it exited.
            let (handle, command) = (context.handle(), self.command.clone());
            tokio::spawn(async move {
                if let Err(error) = serve(channel, handle, &command).await {
                    eprintln!("SSH terminal session ended: {error}");
                }
            });
        }
        Ok(())
    }
}

pub(crate) async fn serve(
    mut channel: Channel,
    handle: Handle,
    command: &CommandBuilder,
) -> io::Result<()> {
    let mut terminal = None;
    while let Some(message) = channel.recv().await {
        if matches!(message, Message::Closed | Message::Overrun) {
            return Ok(());
        }
        if message == Message::Eof {
            return channel.close().await;
        }
        let Some(request) = message.session_request()? else {
            continue;
        };
        let success = match request.request {
            Request::Pty(pty) if terminal.is_none() => {
                if pty.term.len() <= 128
                    && pty
                        .term
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+-_.".contains(&byte))
                    && let Ok(size) = Terminal::new(pty.size)
                {
                    let term = if pty.term.is_empty() {
                        "xterm"
                    } else {
                        pty.term
                    };
                    terminal = Some((size, term.to_owned()));
                    true
                } else {
                    false
                }
            }
            Request::WindowChange(size) if terminal.is_some() => {
                let (terminal, _) = terminal.as_mut().expect("PTY was requested");
                terminal.resize(size).is_ok()
            }
            Request::Shell if terminal.is_some() => {
                let (terminal_size, term) = terminal.as_ref().expect("PTY was requested");
                let mut command = command.clone();
                command.env("TERM", term);
                match Process::start(command, *terminal_size).await {
                    Ok(process) => {
                        if request.want_reply {
                            channel.reply(true).await?;
                        }
                        return exchange(channel, handle, process).await;
                    }
                    Err(err) => {
                        eprintln!("Cannot start terminal program: {err}");
                        false
                    }
                }
            }
            _ => false,
        };
        if request.want_reply {
            channel.reply(success).await?;
        }
    }
    Ok(())
}

async fn exchange(channel: Channel, handle: Handle, process: Process) -> io::Result<()> {
    let (mut rx, tx) = channel.split();
    let Process {
        input,
        mut output,
        terminal,
        exit,
    } = process;
    let drain = async {
        while let Some(result) = output.recv().await {
            tx.send(result?).await?;
        }
        let status = exit.await.map_err(io::Error::other)??;
        tx.request(Request::Exit(Exit::Status(status.exit_code())), false)
            .await?;
        tx.eof().await?;
        tx.close().await
    };
    tokio::select! {
        result = read_channel(&mut rx, handle, input, terminal) => result,
        result = drain => result,
    }
}

async fn read_channel(
    rx: &mut ChannelReceiver,
    handle: Handle,
    input: tokio::sync::mpsc::Sender<Bytes>,
    terminal: tokio::sync::watch::Sender<Terminal>,
) -> io::Result<()> {
    let mut input = Some(input);
    while let Some(message) = rx.recv().await {
        match message {
            Message::Data(data) => {
                if let Some(input) = &input {
                    // Cap a stalled terminal's queue wait so channel close is still observed.
                    match tokio::time::timeout(Duration::from_secs(5), input.send(data)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => { /* Program stopped accepting input; drain its output. */ }
                        Err(_) => {
                            drop(terminal);
                            return handle.close(rx.id()).await;
                        }
                    }
                }
            }
            Message::Eof => {
                input = None;
                terminal.send_modify(Terminal::eof);
            }
            Message::Closed | Message::Overrun => return Ok(()),
            Message::Request { .. } => {
                let Some(request) = message.session_request()? else {
                    continue;
                };
                let accepted = match request.request {
                    Request::WindowChange(size) => {
                        terminal.send_if_modified(|terminal| terminal.resize(size).is_ok())
                    }
                    _ => false,
                };
                if request.want_reply {
                    handle.reply(rx.id(), accepted).await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
