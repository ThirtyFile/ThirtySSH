//! Buffered and streaming command execution on SSH session channels.
use crate::{
    auth::{Authenticated, malformed},
    channel::{ChannelId, Connection, DEFAULT_WINDOW, Event, packet},
    clear_packet::invalid,
    wire::Reader,
};
use std::io::{self, ErrorKind};
use tokio::io::{AsyncRead, AsyncWrite};

mod streaming;
pub use streaming::{
    Captured, Exec, ExecEvent, ExecOutput, Exit, ExitSignal, IncomingExec, ServerExec,
    ServerOutput, receive, start,
};

const MAX_COMMAND: usize = 32768;

pub(crate) fn command_fields(command: &[u8]) -> io::Result<Vec<u8>> {
    if command.len() > MAX_COMMAND {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH command exceeds limit",
        ));
    }
    packet(4 + command.len(), |writer| writer.string(command))
}

pub(crate) fn decode_command(fields: &[u8]) -> io::Result<&[u8]> {
    let mut reader = Reader::new(fields);
    let command = reader.string().map_err(malformed)?;
    reader.finish().map_err(malformed)?;
    Ok(command)
}

/// Execute a command and capture its output, with a combined stdout/stderr limit.
/// The client closes stdin immediately and consumes the authenticated connection.
pub async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    connection: Authenticated<S>,
    command: &[u8],
    output_limit: usize,
) -> io::Result<Captured> {
    let command = command_fields(command)?;
    let mut connection = Connection::new(connection);
    let channel = connection.open("session", DEFAULT_WINDOW, &[]).await?;
    loop {
        match connection.next_event().await? {
            Event::Opened { fields, .. } if fields.is_empty() => break,
            Event::Refused { .. } => return Err(io::Error::other("SSH session channel refused")),
            Event::Incoming { channel, .. } => connection.refuse(channel, 1).await?,
            _ => return Err(invalid("expected SSH channel confirmation")),
        }
    }
    connection.request(channel, "exec", true, &command).await?;
    let mut output = Captured::default();
    let mut started = false;
    let mut credit = 0;
    loop {
        match connection.next_event().await? {
            Event::Reply { success: true, .. } => {
                started = true;
                connection.eof(channel).await?;
            }
            Event::Reply { success: false, .. } => {
                return Err(io::Error::other("SSH exec request refused"));
            }
            Event::Data { extended, data, .. } if started => {
                if data.len()
                    > output_limit.saturating_sub(output.stdout.len() + output.stderr.len())
                {
                    return Err(io::Error::other("SSH command output exceeds limit"));
                }
                match extended {
                    None => output.stdout.extend_from_slice(&data),
                    Some(1) => output.stderr.extend_from_slice(&data),
                    _ => return Err(invalid("unexpected SSH extended data type")),
                }
                credit += data.len() as u32;
                if credit >= DEFAULT_WINDOW / 2 {
                    connection.consume(channel, credit).await?;
                    credit = 0;
                }
            }
            Event::Request {
                name,
                want_reply,
                fields,
                ..
            } => {
                if want_reply {
                    connection.reply(channel, false).await?;
                }
                // The first readable report counts: a status, or the signal
                // that ended the command. Anything else is not an exit report.
                if started
                    && output.exit.is_none()
                    && let Ok(Some(exit)) = Exit::decode(&name, &fields)
                {
                    output.exit = Some(exit);
                }
            }
            Event::Closed(_) => {
                connection.disconnect().await?;
                return if started {
                    Ok(output)
                } else {
                    Err(io::Error::other("SSH channel closed before exec"))
                };
            }
            Event::Incoming { channel, .. } => connection.refuse(channel, 1).await?,
            Event::Eof(_) | Event::WindowAdjusted { .. } => {}
            _ => return Err(invalid("unexpected SSH exec channel event")),
        }
    }
}

async fn send_output<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    channel: ChannelId,
    mut data: &[u8],
    extended: Option<u32>,
) -> io::Result<()> {
    while !data.is_empty() {
        let sent = connection.send_data(channel, extended, data).await?;
        data = &data[sent..];
        if sent == 0 && !progress(connection, channel).await? {
            return Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "SSH exec channel closed",
            ));
        }
    }
    Ok(())
}

// Read control messages while output is blocked or the close handshake is pending.
async fn progress<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    channel: ChannelId,
) -> io::Result<bool> {
    match connection.next_event().await? {
        Event::WindowAdjusted { .. } | Event::Eof(_) => {}
        Event::Incoming { channel, .. } => connection.refuse(channel, 1).await?,
        Event::Closed(_) => return Ok(false),
        Event::Request { want_reply, .. } => {
            if want_reply {
                connection.reply(channel, false).await?;
            }
        }
        _ => return Err(invalid("unexpected SSH exec channel event")),
    }
    Ok(true)
}

/// Serve one exec request through an application callback, which is given
/// the user name and the command and supplies the result, or `None` to
/// refuse. This operation advertises a zero receive window for command stdin.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    connection: Authenticated<S>,
    execute: impl AsyncFnOnce(&str, &[u8]) -> Option<Captured>,
) -> io::Result<()> {
    let mut connection = Connection::new(connection);
    let Event::Incoming {
        channel,
        kind,
        fields,
    } = connection.next_event().await?
    else {
        return Err(invalid("expected SSH channel open"));
    };
    if kind != b"session" {
        connection.refuse(channel, 3).await?;
        return Err(io::Error::other("SSH session channel refused"));
    }
    Reader::new(&fields).finish().map_err(malformed)?;
    connection.accept(channel, 0, &[]).await?;
    let output = loop {
        match connection.next_event().await? {
            Event::Request {
                name,
                fields,
                want_reply,
                ..
            } if name == b"exec" => {
                let command = decode_command(&fields)?;
                let output = if command.len() <= MAX_COMMAND {
                    execute(connection.username(), command).await
                } else {
                    None
                };
                if want_reply {
                    connection.reply(channel, output.is_some()).await?;
                }
                let Some(output) = output else {
                    connection.close(channel).await?;
                    return Ok(());
                };
                break output;
            }
            Event::Request {
                want_reply: true, ..
            } => connection.reply(channel, false).await?,
            Event::Request { .. } | Event::WindowAdjusted { .. } | Event::Eof(_) => {}
            Event::Incoming { channel, .. } => connection.refuse(channel, 1).await?,
            Event::Closed(_) => return Ok(()),
            _ => return Err(invalid("unexpected SSH exec channel event")),
        }
    };
    send_output(&mut connection, channel, &output.stdout, None).await?;
    send_output(&mut connection, channel, &output.stderr, Some(1)).await?;
    if let Some(exit) = &output.exit {
        let (name, fields) = exit.encode()?;
        connection.request(channel, name, false, &fields).await?;
    }
    connection.eof(channel).await?;
    connection.close(channel).await?;
    while progress(&mut connection, channel).await? {}
    Ok(())
}
