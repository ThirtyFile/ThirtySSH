use super::{MAX_COMMAND, decode_command};
use crate::{
    auth::malformed,
    channel::{
        Bytes, Channel, ChannelReceiver, ChannelSender, DataWriter, Message, driver::Handle, packet,
    },
    clear_packet::invalid,
    session::Request,
    wire::Reader,
};
use std::io::{self, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// How the peer reported that a command terminated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Exit {
    Status(u32),
    Signal(ExitSignal),
}

/// The SSH exit-signal fields. A signal name omits the SIG prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitSignal {
    pub name: String,
    pub core_dumped: bool,
    pub message: String,
    pub language: String,
}

impl Exit {
    pub(crate) fn decode(request: &[u8], fields: &[u8]) -> io::Result<Option<Self>> {
        let mut reader = Reader::new(fields);
        let exit = match request {
            b"exit-status" => Self::Status(reader.uint32().map_err(malformed)?),
            b"exit-signal" => {
                let name = text(&mut reader)?;
                if !valid_signal_name(&name) {
                    return Err(invalid("invalid SSH exit signal name"));
                }
                Self::Signal(ExitSignal {
                    name,
                    core_dumped: reader.boolean().map_err(malformed)?,
                    message: text(&mut reader)?,
                    language: text(&mut reader)?,
                })
            }
            _ => return Ok(None),
        };
        reader.finish().map_err(malformed)?;
        Ok(Some(exit))
    }

    pub(crate) fn encode(&self) -> io::Result<(&'static str, Vec<u8>)> {
        match self {
            Self::Status(status) => Ok(("exit-status", status.to_be_bytes().to_vec())),
            Self::Signal(signal) => {
                let bytes = signal
                    .name
                    .len()
                    .saturating_add(signal.message.len())
                    .saturating_add(signal.language.len());
                if bytes > MAX_COMMAND || !valid_signal_name(&signal.name) {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "invalid or oversized SSH exit signal",
                    ));
                }
                let fields = packet(13 + bytes, |writer| {
                    writer.string(signal.name.as_bytes())?;
                    writer.boolean(signal.core_dumped)?;
                    writer.string(signal.message.as_bytes())?;
                    writer.string(signal.language.as_bytes())
                })?;
                Ok(("exit-signal", fields))
            }
        }
    }
}

fn text(reader: &mut Reader<'_>) -> io::Result<String> {
    let bytes = reader.string().map_err(malformed)?;
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| invalid("invalid UTF-8 in SSH exit signal"))
}

fn valid_signal_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExecEvent {
    Stdout(Bytes),
    Stderr(Bytes),
    Exit(Exit),
    /// The peer sent no more data. Its exit report can arrive after EOF.
    Eof,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Captured {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<Exit>,
}

/// A command whose exec request succeeded.
pub struct Exec {
    stdin: ChannelSender,
    output: ExecOutput,
}

/// Open a session channel and wait for the server to accept the command.
pub async fn start(handle: &Handle, command: &[u8]) -> io::Result<Exec> {
    let mut channel = handle.open_session().await?;
    channel.request(Request::Exec(command), true).await?;
    loop {
        match channel.recv().await {
            Some(Message::Reply { success: true }) => break,
            Some(Message::Reply { success: false }) => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "SSH exec request refused",
                ));
            }
            Some(Message::Request {
                want_reply: true, ..
            }) => channel.reply(false).await?,
            Some(Message::Request { .. } | Message::WindowAdjusted { .. }) => {}
            Some(Message::Closed) | None => return Err(channel_closed()),
            _ => return Err(invalid("unexpected SSH exec response")),
        }
    }
    let (reader, stdin) = channel.split();
    let output = ExecOutput {
        reader,
        handle: handle.clone(),
        closed: false,
    };
    Ok(Exec { stdin, output })
}

impl Exec {
    /// Separate command input from ordered stdout, stderr and termination events.
    pub fn split(self) -> (ChannelSender, ExecOutput) {
        (self.stdin, self.output)
    }

    /// Pump input and output independently. An input EOF half-closes the
    /// channel. A remote close ends the command even if the input is idle.
    pub async fn capture(
        self,
        mut input: impl AsyncRead + Unpin,
        limit: usize,
    ) -> io::Result<Captured> {
        let (stdin, mut output) = self.split();
        let send = forward_input(&mut input, stdin.writer());
        let collect = output.collect(limit);
        tokio::pin!(send, collect);
        tokio::select! {
            biased;
            result = &mut collect => result,
            result = &mut send => {
                result?;
                collect.await
            }
        }
    }
}

async fn forward_input(
    input: &mut (impl AsyncRead + Unpin),
    mut stdin: DataWriter,
) -> io::Result<()> {
    let mut bytes = vec![0; 32 * 1024];
    loop {
        let count = input.read(&mut bytes).await?;
        if count == 0 {
            return stdin.shutdown().await.or_else(ignore_closed_channel);
        }
        if let Err(error) = stdin.write_all(&bytes[..count]).await {
            return ignore_closed_channel(error);
        }
    }
}

// The driver may have received CLOSE before it runs our next write or EOF.
// The output side still has to observe CLOSE before reporting success.
fn ignore_closed_channel(error: io::Error) -> io::Result<()> {
    match error.kind() {
        ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::InvalidInput => Ok(()),
        _ => Err(error),
    }
}

fn channel_closed() -> io::Error {
    io::Error::new(
        ErrorKind::ConnectionAborted,
        "SSH exec channel disconnected",
    )
}

/// Concurrent receiver of the command's stdout, stderr and termination.
pub struct ExecOutput {
    reader: ChannelReceiver,
    handle: Handle,
    closed: bool,
}

impl ExecOutput {
    /// Read an event. None indicates an orderly channel close.
    pub async fn next_event(&mut self) -> io::Result<Option<ExecEvent>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            let event = match self.reader.recv().await {
                Some(Message::Data(data)) => ExecEvent::Stdout(data),
                Some(Message::ExtendedData { code: 1, data }) => ExecEvent::Stderr(data),
                Some(Message::Eof) => ExecEvent::Eof,
                Some(Message::WindowAdjusted { .. }) => continue,
                Some(Message::Request {
                    name,
                    want_reply,
                    fields,
                }) => {
                    if want_reply {
                        self.handle
                            .reply(self.reader.id(), false)
                            .await
                            .or_else(ignore_closed_channel)?;
                    }
                    // An exit report this side cannot read counts as none
                    // given. Failing here would throw away the output that
                    // was received in full.
                    let Ok(Some(exit)) = Exit::decode(&name, &fields) else {
                        continue;
                    };
                    ExecEvent::Exit(exit)
                }
                Some(Message::Closed) => {
                    self.closed = true;
                    return Ok(None);
                }
                None => return Err(channel_closed()),
                _ => return Err(invalid("unexpected SSH exec output")),
            };
            return Ok(Some(event));
        }
    }

    async fn collect(&mut self, limit: usize) -> io::Result<Captured> {
        let mut output = Captured::default();
        let mut remaining = limit;
        while let Some(event) = self.next_event().await? {
            let (buffer, data) = match event {
                ExecEvent::Stdout(data) => (&mut output.stdout, data),
                ExecEvent::Stderr(data) => (&mut output.stderr, data),
                ExecEvent::Exit(exit) => {
                    output.exit = Some(exit);
                    continue;
                }
                ExecEvent::Eof => continue,
            };
            remaining = remaining
                .checked_sub(data.len())
                .ok_or_else(|| io::Error::other("SSH command output exceeds limit"))?;
            buffer.extend_from_slice(&data);
        }
        Ok(output)
    }
}

/// A pending command request received on a server's session channel.
pub struct IncomingExec {
    channel: Channel,
    command: Bytes,
    want_reply: bool,
}

/// Wait for an exec request on an accepted session channel. Unsupported
/// requests are refused when the peer asks for a reply.
pub async fn receive(mut channel: Channel) -> io::Result<Option<IncomingExec>> {
    while let Some(message) = channel.recv().await {
        match message {
            Message::Request {
                name,
                want_reply,
                fields,
            } if &name[..] == b"exec" => {
                let command = decode_command(&fields)?;
                if command.len() > MAX_COMMAND {
                    if want_reply {
                        channel.reply(false).await?;
                    }
                    channel.close().await?;
                    return Ok(None);
                }
                return Ok(Some(IncomingExec {
                    channel,
                    command: fields.slice(4..),
                    want_reply,
                }));
            }
            Message::Request {
                want_reply: true, ..
            } => channel.reply(false).await?,
            Message::Request { .. } | Message::Eof | Message::WindowAdjusted { .. } => {}
            Message::Closed => return Ok(None),
            _ => return Err(invalid("unexpected SSH message before exec")),
        }
    }
    Err(channel_closed())
}

impl IncomingExec {
    pub fn command(&self) -> &[u8] {
        &self.command
    }

    pub async fn accept(self) -> io::Result<ServerExec> {
        if self.want_reply {
            self.channel.reply(true).await?;
        }
        let (stdin, output) = self.channel.split();
        Ok(ServerExec {
            command: self.command,
            stdin,
            output: ServerOutput {
                stdout: output.writer(),
                stderr: output.extended_writer(1),
                channel: output,
            },
        })
    }

    pub async fn refuse(self) -> io::Result<()> {
        if self.want_reply {
            self.channel.reply(false).await?;
        }
        self.channel.close().await
    }
}

/// An accepted command. The application owns execution and can read input
/// and send output from separate tasks.
pub struct ServerExec {
    command: Bytes,
    stdin: ChannelReceiver,
    output: ServerOutput,
}

impl ServerExec {
    pub fn split(self) -> (Bytes, ChannelReceiver, ServerOutput) {
        (self.command, self.stdin, self.output)
    }
}

/// The server side of a command's standard output and standard error.
pub struct ServerOutput {
    stdout: DataWriter,
    stderr: DataWriter,
    channel: ChannelSender,
}

impl ServerOutput {
    pub fn stdout(&mut self) -> &mut DataWriter {
        &mut self.stdout
    }

    pub fn stderr(&mut self) -> &mut DataWriter {
        &mut self.stderr
    }

    /// Flush both output streams before sending the optional exit report,
    /// the output EOF and the channel close.
    pub async fn finish(mut self, exit: Option<Exit>) -> io::Result<()> {
        self.stdout.flush().await?;
        self.stderr.flush().await?;
        if let Some(exit) = exit {
            self.channel.request(Request::Exit(exit), false).await?;
        }
        self.channel.eof().await?;
        self.channel.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_report_rejects_invalid_names_and_inexact_fields() {
        let exit = Exit::Signal(ExitSignal {
            name: "VENDOR@example.test".into(),
            core_dumped: true,
            message: "fixture stopped".into(),
            language: "en".into(),
        });
        let (name, mut fields) = exit.encode().unwrap();
        assert_eq!(Exit::decode(name.as_bytes(), &fields).unwrap(), Some(exit));
        let truncated = &fields[..fields.len() - 1];
        assert_eq!(
            Exit::decode(name.as_bytes(), truncated).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        fields.push(0);
        assert_eq!(
            Exit::decode(name.as_bytes(), &fields).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let invalid = Exit::Signal(ExitSignal {
            name: "bad name".into(),
            core_dumped: false,
            message: String::new(),
            language: String::new(),
        });
        assert_eq!(
            invalid.encode().unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
}
