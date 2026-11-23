//! SSH-2 identification exchange ([RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)).
use crate::protocol_error::ProtocolError;
use std::{
    borrow::Cow,
    io::{self, ErrorKind},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Local identification bytes covered by a future key exchange hash (without CRLF).
pub const LOCAL_ID: &[u8] = DEFAULT_ID.as_bytes();
const DEFAULT_ID: &str = concat!("SSH-2.0-ThirtySSH_", env!("CARGO_PKG_VERSION"));
const MAX_ID_LINE: usize = 255;
// Local resource policy for server greetings, including their line endings.
const MAX_GREETING_BYTES: usize = 8192;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

/// SSH identification sent before key exchange.
#[derive(Clone, Debug)]
pub enum IdLine {
    /// The identification text. The CRLF terminator is appended.
    Terminated(Cow<'static, str>),
    /// A complete line, sent exactly as given, terminator included.
    Verbatim(Cow<'static, str>),
}

impl Default for IdLine {
    fn default() -> Self {
        Self::Terminated(Cow::Borrowed(DEFAULT_ID))
    }
}

/// Identification settings for a client or server connection.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub local: IdLine,
    /// Accept older peers that send an LF-terminated SSH-2.0 ID.
    pub accept_bare_lf: bool,
}

pub(crate) struct Ids {
    pub(crate) local: Vec<u8>,
    pub(crate) peer: Vec<u8>,
}

fn invalid(message: &'static str) -> io::Error {
    ProtocolError::Identification(message).into()
}

fn validate_line(
    line: &[u8],
    role: Role,
    saw_greeting: bool,
    accept_bare_lf: bool,
) -> io::Result<&[u8]> {
    if line.len() > MAX_ID_LINE {
        return Err(invalid("SSH identification exceeds 255 bytes"));
    }
    let legacy_server = role == Role::Client && line.starts_with(b"SSH-1.99-");
    if legacy_server && saw_greeting {
        return Err(invalid(
            "unexpected greeting before SSH-1.99 identification",
        ));
    }
    let identifier = match line.strip_suffix(b"\r\n") {
        Some(id) => id,
        None if legacy_server || accept_bare_lf => line
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid("missing newline"))?,
        None => return Err(invalid("SSH-2.0 identification requires CRLF")),
    };
    let prefix: &[u8] = if legacy_server {
        b"SSH-1.99-"
    } else {
        b"SSH-2.0-"
    };
    let tail = identifier
        .strip_prefix(prefix)
        .ok_or_else(|| invalid("unsupported SSH version"))?;
    let software = tail.split(|byte| *byte == b' ').next().unwrap_or_default();
    if software.is_empty()
        || !software.iter().all(|b| b.is_ascii_graphic() && *b != b'-')
        || tail.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
    {
        return Err(invalid("invalid SSH identification"));
    }
    Ok(identifier)
}

async fn read_peer<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    role: Role,
    accept_bare_lf: bool,
) -> io::Result<Vec<u8>> {
    let mut greeting_left = if role == Role::Client {
        MAX_GREETING_BYTES
    } else {
        0
    };
    let mut line = Vec::new();
    loop {
        line.clear();
        // Select the correct budget as soon as we can distinguish the two
        // line types. read_until leaves any pipelined packet in the caller's reader.
        (&mut *reader).take(4).read_until(b'\n', &mut line).await?;
        if line.is_empty() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "missing SSH identification",
            ));
        }
        let is_id = line.starts_with(b"SSH-");
        let limit = if is_id { MAX_ID_LINE } else { greeting_left };
        let available = limit
            .checked_sub(line.len())
            .ok_or_else(|| invalid("unexpected or oversized SSH greeting"))?;
        if line.last() != Some(&b'\n') {
            (&mut *reader)
                .take(available as u64)
                .read_until(b'\n', &mut line)
                .await?;
            if line.last() != Some(&b'\n') {
                return Err(if line.len() == limit {
                    invalid("SSH greeting or identification exceeds limit")
                } else {
                    io::Error::new(ErrorKind::UnexpectedEof, "incomplete SSH identification")
                });
            }
        }
        if is_id {
            let id = validate_line(
                &line,
                role,
                role == Role::Client && greeting_left < MAX_GREETING_BYTES,
                accept_bare_lf,
            )?;
            return Ok(id.to_vec());
        }
        greeting_left -= line.len();
    }
}

/// Exchange IDs over the two halves of a stream. Returns the peer's exact ID
/// without its line ending. Reuse `reader` for subsequent packets. On error
/// or cancellation, discard the connection as either half may have advanced.
/// Callers can wrap the exchange in a deadline appropriate for their transport.
pub async fn exchange<R, W>(role: Role, reader: &mut R, writer: &mut W) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    Ok(exchange_with(role, reader, writer, &Settings::default())
        .await?
        .peer)
}

pub(crate) async fn exchange_with<R, W>(
    role: Role,
    reader: &mut R,
    writer: &mut W,
    settings: &Settings,
) -> io::Result<Ids>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let peer_role = match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    };
    let wire: Cow<'_, str> = match &settings.local {
        IdLine::Terminated(id) => {
            // Bound the allocation before appending the terminator.
            if id.len() > MAX_ID_LINE - 2 {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "SSH identification exceeds 255 bytes",
                ));
            }
            Cow::Owned(format!("{id}\r\n"))
        }
        IdLine::Verbatim(line) => Cow::Borrowed(line),
    };
    let valid = validate_line(wire.as_bytes(), peer_role, false, true)
        .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
    let send = async {
        writer.write_all(wire.as_bytes()).await?;
        writer.flush().await
    };
    let ((), peer) = tokio::try_join!(send, read_peer(reader, role, settings.accept_bare_lf))?;
    Ok(Ids {
        local: valid.to_vec(),
        peer,
    })
}
