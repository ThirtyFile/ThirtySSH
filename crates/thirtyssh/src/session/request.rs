//! Typed requests on an open SSH session channel.
use crate::{
    auth::malformed,
    channel::{KEEPALIVE_REQUEST, MAX_FIELDS, Message, packet},
    clear_packet::invalid,
    exec::{self, Exit},
    forward::AgentForwarding,
    pty::{TerminalMode, TerminalSize, decode_modes, encode_modes},
    wire::{self, Reader, Writer},
};
use std::{
    borrow::Cow,
    fmt,
    io::{self, ErrorKind},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtyRequest<'a> {
    pub term: &'a str,
    pub size: TerminalSize,
    pub modes: Cow<'a, [TerminalMode]>,
}

impl<'a> PtyRequest<'a> {
    /// Build a PTY request from application modes. The encoder adds TTY_OP_END.
    pub fn from_modes(
        term: &'a str,
        size: TerminalSize,
        terminal_modes: &[(crate::Pty, u32)],
    ) -> io::Result<Self> {
        // The same budget the encoder checks: the fixed fields, the terminal
        // name and the end marker come out of it before the modes do.
        let max_modes = MAX_FIELDS.saturating_sub(25 + term.len()) / 5;
        let modes: Vec<_> = terminal_modes
            .iter()
            .copied()
            .filter(|(mode, _)| *mode != crate::Pty::TTY_OP_END)
            .take(max_modes + 1)
            .map(Into::into)
            .collect();
        if modes.len() > max_modes {
            return Err(input("SSH terminal modes exceed the packet limit"));
        }
        Ok(Self {
            term,
            size,
            modes: Cow::Owned(modes),
        })
    }
}

/// X11 forwarding parameters. Supply a per-session fake cookie and validate
/// it before connecting a forwarded stream to the real X server.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct X11Request<'a> {
    pub single_connection: bool,
    pub authentication_protocol: &'a str,
    pub authentication_cookie: &'a str,
    pub screen_number: u32,
}

impl fmt::Debug for X11Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X11Request")
            .field("single_connection", &self.single_connection)
            .field("authentication_protocol", &self.authentication_protocol)
            .field("screen_number", &self.screen_number)
            .finish_non_exhaustive()
    }
}

impl X11Request<'_> {
    fn valid(self) -> bool {
        !self.authentication_protocol.contains('\0')
            && self.authentication_cookie.len().is_multiple_of(2)
            && self
                .authentication_cookie
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }
}

/// A session request and its SSH reply flag. Replies for requests on the
/// same channel are sent in the order the requests arrived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRequest<'a> {
    pub want_reply: bool,
    pub request: Request<'a>,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    Pty(PtyRequest<'a>),
    X11(X11Request<'a>),
    /// Ask for agent forwarding under the given protocol's request name.
    AgentForward(AgentForwarding),
    Keepalive,
    Shell,
    Environment {
        name: &'a [u8],
        value: &'a [u8],
    },
    Exec(&'a [u8]),
    Subsystem(&'a str),
    WindowChange(TerminalSize),
    Signal(&'a str),
    XonXoff(bool),
    Exit(Exit),
    Unknown {
        name: &'a [u8],
        fields: &'a [u8],
    },
}

impl<'a> Request<'a> {
    /// Decode a request from the channel's request name and payload.
    /// Unrecognized extensions retain their fields verbatim.
    pub fn decode(name: &'a [u8], fields: &'a [u8]) -> io::Result<Self> {
        let mut reader = Reader::new(fields);
        let request = match name {
            b"pty-req" => {
                let term = text(&mut reader)?;
                let size = TerminalSize::decode(&mut reader).map_err(malformed)?;
                let modes = decode_modes(reader.string().map_err(malformed)?)?;
                Self::Pty(PtyRequest {
                    term,
                    size,
                    modes: Cow::Owned(modes),
                })
            }
            b"shell" => Self::Shell,
            b"x11-req" => {
                let x11 = X11Request {
                    single_connection: reader.boolean().map_err(malformed)?,
                    authentication_protocol: text(&mut reader)?,
                    authentication_cookie: text(&mut reader)?,
                    screen_number: reader.uint32().map_err(malformed)?,
                };
                if !x11.valid() {
                    return Err(invalid("invalid X11 forwarding authentication fields"));
                }
                Self::X11(x11)
            }
            b"auth-agent-req@openssh.com" => Self::AgentForward(AgentForwarding::OpenSsh),
            b"agent-req" => Self::AgentForward(AgentForwarding::Standard),
            name if name == KEEPALIVE_REQUEST.as_bytes() => Self::Keepalive,
            b"env" => Self::Environment {
                name: reader.string().map_err(malformed)?,
                value: reader.string().map_err(malformed)?,
            },
            b"exec" => return exec::decode_command(fields).map(Self::Exec),
            b"subsystem" => Self::Subsystem(text(&mut reader)?),
            b"window-change" => {
                Self::WindowChange(TerminalSize::decode(&mut reader).map_err(malformed)?)
            }
            b"signal" => {
                let signal = text(&mut reader)?;
                if !valid_name(signal.as_bytes()) {
                    return Err(invalid("invalid SSH signal name"));
                }
                Self::Signal(signal)
            }
            b"xon-xoff" => Self::XonXoff(reader.boolean().map_err(malformed)?),
            b"exit-status" | b"exit-signal" => {
                return Exit::decode(name, fields)?
                    .map(Self::Exit)
                    .ok_or_else(|| invalid("invalid SSH exit report"));
            }
            _ => return Ok(Self::Unknown { name, fields }),
        };
        reader.finish().map_err(malformed)?;
        Ok(request)
    }

    /// Encode the request name and request-specific fields for the given reply flag.
    pub fn encode(&self, want_reply: bool) -> io::Result<(&str, Cow<'_, [u8]>)> {
        if want_reply
            && matches!(
                self,
                Self::WindowChange(_) | Self::Signal(_) | Self::XonXoff(_) | Self::Exit(_)
            )
        {
            return Err(input(
                "this SSH session notification cannot request a reply",
            ));
        }
        let (name, fields) = match self {
            Self::Pty(request) => {
                let modes = encode_modes(&request.modes)?;
                encode(
                    "pty-req",
                    24usize
                        .saturating_add(request.term.len())
                        .saturating_add(modes.len()),
                    |writer| {
                        writer.string(request.term.as_bytes())?;
                        request.size.encode(writer)?;
                        writer.string(&modes)
                    },
                )?
            }
            Self::Shell => return Ok(("shell", Cow::Borrowed(&[]))),
            Self::X11(request) => {
                if !request.valid() {
                    return Err(input("invalid X11 forwarding authentication fields"));
                }
                encode(
                    "x11-req",
                    13usize
                        .saturating_add(request.authentication_protocol.len())
                        .saturating_add(request.authentication_cookie.len()),
                    |writer| {
                        writer.boolean(request.single_connection)?;
                        writer.string(request.authentication_protocol.as_bytes())?;
                        writer.string(request.authentication_cookie.as_bytes())?;
                        writer.uint32(request.screen_number)
                    },
                )?
            }
            Self::AgentForward(protocol) => {
                return Ok((protocol.request_name(), Cow::Borrowed(&[])));
            }
            Self::Keepalive => return Ok((KEEPALIVE_REQUEST, Cow::Borrowed(&[]))),
            Self::Environment { name, value } => encode(
                "env",
                8usize
                    .saturating_add(name.len())
                    .saturating_add(value.len()),
                |writer| {
                    writer.string(name)?;
                    writer.string(value)
                },
            )?,
            Self::Exec(command) => ("exec", exec::command_fields(command)?),
            Self::Subsystem(subsystem) => single_string("subsystem", subsystem)?,
            Self::WindowChange(size) => encode("window-change", 16, |writer| size.encode(writer))?,
            Self::Signal(signal) => {
                if !valid_name(signal.as_bytes()) {
                    return Err(input("invalid SSH signal name"));
                }
                single_string("signal", signal)?
            }
            Self::XonXoff(client_can_do) => {
                encode("xon-xoff", 1, |writer| writer.boolean(*client_can_do))?
            }
            Self::Exit(exit) => exit.encode()?,
            Self::Unknown { name, fields } => {
                if !valid_name(name) {
                    return Err(input("invalid SSH session request name"));
                }
                let name =
                    str::from_utf8(name).map_err(|_| input("invalid SSH session request name"))?;
                return Ok((name, Cow::Borrowed(fields)));
            }
        };
        Ok((name, Cow::Owned(fields)))
    }
}

impl Message {
    /// Inspect the typed form of a channel request while retaining the
    /// original message and reply flag.
    pub fn session_request(&self) -> io::Result<Option<SessionRequest<'_>>> {
        if let Self::Request {
            name,
            want_reply,
            fields,
        } = self
        {
            Ok(Some(SessionRequest {
                want_reply: *want_reply,
                request: Request::decode(name, fields)?,
            }))
        } else {
            Ok(None)
        }
    }
}

fn encode(
    name: &'static str,
    size: usize,
    fields: impl FnOnce(&mut Writer<'_>) -> Result<(), wire::Error>,
) -> io::Result<(&'static str, Vec<u8>)> {
    if size.saturating_add(name.len()) > MAX_FIELDS {
        return Err(input("SSH session request exceeds the packet limit"));
    }
    Ok((name, packet(size, fields)?))
}

fn single_string(name: &'static str, field: &str) -> io::Result<(&'static str, Vec<u8>)> {
    encode(name, 4usize.saturating_add(field.len()), |writer| {
        writer.string(field.as_bytes())
    })
}

fn text<'a>(reader: &mut Reader<'a>) -> io::Result<&'a str> {
    let bytes = reader.string().map_err(malformed)?;
    str::from_utf8(bytes).map_err(|_| invalid("invalid UTF-8 in SSH session request"))
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(u8::is_ascii_graphic)
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pty, exec::ExitSignal};

    #[test]
    fn typed_requests_preserve_payloads_and_reply_policy() {
        let modes = [(Pty::ECHO, 0).into(), (Pty::IUTF8, 1).into()];
        let cases = [
            (
                Request::Pty(PtyRequest {
                    term: "xterm-256color",
                    size: TerminalSize {
                        columns: 0,
                        rows: 24,
                        pixel_width: 640,
                        pixel_height: 480,
                    },
                    modes: (&modes[..]).into(),
                }),
                true,
            ),
            (
                Request::X11(X11Request {
                    single_connection: true,
                    authentication_protocol: "MIT-MAGIC-COOKIE-1",
                    authentication_cookie: "00112233445566778899aAbBcCdDeEfF",
                    screen_number: 3,
                }),
                true,
            ),
            (Request::AgentForward(AgentForwarding::OpenSsh), true),
            (Request::AgentForward(AgentForwarding::Standard), true),
            (Request::Keepalive, true),
            (Request::Shell, true),
            (
                Request::Environment {
                    name: b"TERM",
                    value: &[0xde, 0xad],
                },
                true,
            ),
            (Request::Exec(b"fixture"), true),
            (Request::Subsystem("sftp"), true),
            (
                Request::WindowChange(TerminalSize {
                    columns: 132,
                    rows: 40,
                    pixel_width: 0,
                    pixel_height: 0,
                }),
                false,
            ),
            (Request::Signal("TERM"), false),
            (Request::XonXoff(true), false),
            (Request::Exit(Exit::Status(42)), false),
            (
                Request::Exit(Exit::Signal(ExitSignal {
                    name: "INT".into(),
                    core_dumped: false,
                    message: "fixture interrupted".into(),
                    language: "en".into(),
                })),
                false,
            ),
            (
                Request::Unknown {
                    name: b"future@example.test",
                    fields: &[0x00, 0xff],
                },
                true,
            ),
        ];
        for (request, want_reply) in cases {
            let (name, fields) = request.encode(want_reply).unwrap();
            let message = Message::Request {
                name: name.as_bytes().to_vec().into(),
                want_reply,
                fields: fields.into_owned().into(),
            };
            let decoded = message.session_request().unwrap().unwrap();
            assert_eq!(decoded.want_reply, want_reply);
            assert_eq!(decoded.request, request);
            if !want_reply {
                assert_eq!(
                    request.encode(true).unwrap_err().kind(),
                    ErrorKind::InvalidInput
                );
            }
        }
        assert!(Message::Eof.session_request().unwrap().is_none());
    }

    #[test]
    fn known_request_fields_must_be_exact() {
        for name in [
            "pty-req",
            "x11-req",
            "env",
            "subsystem",
            "window-change",
            "signal",
            "xon-xoff",
        ] {
            assert_eq!(
                Request::decode(name.as_bytes(), &[]).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
        for name in ["shell", "pty-req", "window-change", "xon-xoff"] {
            let valid = match name {
                "shell" => Request::Shell,
                "pty-req" => Request::Pty(PtyRequest {
                    term: "vt100",
                    size: TerminalSize::default(),
                    modes: Cow::Borrowed(&[]),
                }),
                "window-change" => Request::WindowChange(TerminalSize::default()),
                _ => Request::XonXoff(false),
            };
            let (_, fields) = valid.encode(false).unwrap();
            let mut fields = fields.into_owned();
            fields.push(0);
            assert_eq!(
                Request::decode(name.as_bytes(), &fields)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }
        assert_eq!(
            Request::Environment {
                name: b"TERM",
                value: &vec![0; MAX_FIELDS]
            }
            .encode(true)
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidInput
        );
        assert!(Request::decode(b"auth-agent-req@openssh.com", b"trailing").is_err());
        assert!(Request::decode(b"agent-req", b"trailing").is_err());
    }

    #[test]
    fn x11_cookie_is_hex_and_omitted_from_typed_debug() {
        let request = X11Request {
            single_connection: false,
            authentication_protocol: "MIT-MAGIC-COOKIE-1",
            authentication_cookie: "decafbad",
            screen_number: 1,
        };
        assert!(!format!("{:?}", Request::X11(request)).contains(request.authentication_cookie));
        let encoded = Request::X11(request);
        let (name, fields) = encoded.encode(true).unwrap();
        let mut fields = fields.into_owned();
        let cookie = fields
            .windows(8)
            .position(|value| value == b"decafbad")
            .unwrap();
        fields[cookie] = b'?';
        assert_eq!(
            Request::decode(name.as_bytes(), &fields)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        let odd = X11Request {
            authentication_cookie: "123",
            ..request
        };
        assert_eq!(
            Request::X11(odd).encode(true).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
}
