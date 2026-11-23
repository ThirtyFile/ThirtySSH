//! Forwarding requests and channel open operations.
//!
//! The receiver decides whether to accept a direct connection. Accept a
//! forwarded connection only when it matches an established remote forward.
//! The originator fields are supplied by the peer and are not credentials.

use crate::{
    auth::malformed,
    channel::{
        Bytes, Channel, DEFAULT_WINDOW, GlobalReply, GlobalRequest, MAX_FIELDS, driver::Handle,
        packet,
    },
    clear_packet::invalid,
    session::{IncomingChannel, OpenType},
    wire::Reader,
};
use std::{
    borrow::Cow,
    io::{self, ErrorKind},
};
use streamlocal::{StreamlocalForward, StreamlocalForwardKind, StreamlocalOpen};

pub mod streamlocal;

/// The wire names used by an agent forwarding request and its channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentForwarding {
    OpenSsh,
    Standard,
}

impl AgentForwarding {
    pub(crate) fn request_name(self) -> &'static str {
        match self {
            Self::OpenSsh => "auth-agent-req@openssh.com",
            Self::Standard => "agent-req",
        }
    }

    pub(crate) fn channel_name(self) -> &'static str {
        match self {
            Self::OpenSsh => "auth-agent@openssh.com",
            Self::Standard => "agent-connect",
        }
    }
}

/// Peer-provided source address for a forwarded X11 connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X11Open<'a> {
    pub originator_address: &'a str,
    pub originator_port: u32,
}

impl<'a> X11Open<'a> {
    pub fn encode_open(self) -> io::Result<(&'static str, Vec<u8>)> {
        let size = 8usize.saturating_add(self.originator_address.len());
        if !self.valid() || size.saturating_add(3) > MAX_FIELDS {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid or oversized X11 forwarding source",
            ));
        }
        let fields = packet(size, |writer| {
            writer.string(self.originator_address.as_bytes())?;
            writer.uint32(self.originator_port)
        })?;
        Ok(("x11", fields))
    }

    pub fn decode(name: &[u8], fields: &'a [u8]) -> io::Result<Option<Self>> {
        if name != b"x11" {
            return Ok(None);
        }
        let mut reader = Reader::new(fields);
        let originator_address = address(&mut reader)?;
        let originator_port = reader.uint32().map_err(malformed)?;
        reader.finish().map_err(malformed)?;
        let open = Self {
            originator_address,
            originator_port,
        };
        if !open.valid() {
            return Err(invalid("invalid X11 forwarding source"));
        }
        Ok(Some(open))
    }

    fn valid(self) -> bool {
        !self.originator_address.is_empty()
            && !self.originator_address.contains('\0')
            && self.originator_port <= u32::from(u16::MAX)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpipForwardKind {
    Listen,
    Cancel,
}

impl TcpipForwardKind {
    fn name(self) -> &'static str {
        match self {
            Self::Listen => "tcpip-forward",
            Self::Cancel => "cancel-tcpip-forward",
        }
    }
}

/// Request to listen for remote TCP connections or cancel that listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpipForward<'a> {
    pub kind: TcpipForwardKind,
    pub bind_address: &'a str,
    /// A listen request can use 0 to ask for an automatically allocated port.
    pub port: u32,
}

impl<'a> TcpipForward<'a> {
    pub fn decode(name: &[u8], fields: &'a [u8]) -> io::Result<Option<Self>> {
        let kind = match name {
            b"tcpip-forward" => TcpipForwardKind::Listen,
            b"cancel-tcpip-forward" => TcpipForwardKind::Cancel,
            _ => return Ok(None),
        };
        let mut reader = Reader::new(fields);
        let request = Self {
            kind,
            bind_address: address(&mut reader)?,
            port: reader.uint32().map_err(malformed)?,
        };
        reader.finish().map_err(malformed)?;
        if !request.valid() {
            return Err(invalid("invalid TCP forwarding listener fields"));
        }
        Ok(Some(request))
    }

    /// Encode success after binding or cancelling `port` on the requested address.
    pub fn success(self, port: u32) -> io::Result<GlobalReply> {
        if !self.valid()
            || port == 0
            || port > u32::from(u16::MAX)
            || (self.port != 0 && port != self.port)
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid bound TCP forwarding port",
            ));
        }
        Ok(GlobalReply::Success(if self.port == 0 {
            Bytes::copy_from_slice(&port.to_be_bytes())
        } else {
            Bytes::new()
        }))
    }

    fn valid(self) -> bool {
        self.port <= u32::from(u16::MAX)
            && (self.kind == TcpipForwardKind::Listen || self.port != 0)
            && !self.bind_address.contains('\0')
    }

    /// Encode the SSH global request name and listener fields.
    pub fn encode_request(self) -> io::Result<(&'static str, Vec<u8>)> {
        let name = self.kind.name();
        let size = 8usize.saturating_add(self.bind_address.len());
        if !self.valid() || size.saturating_add(name.len()) > MAX_FIELDS {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid TCP forwarding listener fields",
            ));
        }
        let fields = packet(size, |writer| {
            writer.string(self.bind_address.as_bytes())?;
            writer.uint32(self.port)
        })?;
        Ok((name, fields))
    }
}

impl GlobalRequest {
    pub fn tcpip_forward(&self) -> io::Result<Option<TcpipForward<'_>>> {
        TcpipForward::decode(&self.name, &self.fields)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpipKind {
    Direct,
    Forwarded,
}

impl TcpipKind {
    fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct-tcpip",
            Self::Forwarded => "forwarded-tcpip",
        }
    }
}

/// The destination and originator in a TCP forwarding channel open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpipOpen<'a> {
    pub kind: TcpipKind,
    pub address: &'a str,
    pub port: u32,
    pub originator_address: &'a str,
    pub originator_port: u32,
}

impl<'a> TcpipOpen<'a> {
    pub fn encode_open(self) -> io::Result<(&'static str, Vec<u8>)> {
        Ok((self.kind.name(), self.encode()?))
    }

    /// Decode the open fields. Other channel types return `Ok(None)`.
    pub fn decode(kind: &[u8], fields: &'a [u8]) -> io::Result<Option<Self>> {
        let kind = match kind {
            b"direct-tcpip" => TcpipKind::Direct,
            b"forwarded-tcpip" => TcpipKind::Forwarded,
            _ => return Ok(None),
        };
        let mut reader = Reader::new(fields);
        let open = Self {
            kind,
            address: address(&mut reader)?,
            port: reader.uint32().map_err(malformed)?,
            originator_address: address(&mut reader)?,
            originator_port: reader.uint32().map_err(malformed)?,
        };
        reader.finish().map_err(malformed)?;
        if !open.valid() {
            return Err(invalid("invalid TCP forwarding channel address or port"));
        }
        Ok(Some(open))
    }

    fn valid(self) -> bool {
        self.port <= u32::from(u16::MAX)
            && self.port != 0
            && self.originator_port <= u32::from(u16::MAX)
            && (self.kind != TcpipKind::Direct || !self.address.is_empty())
            && !self.address.contains('\0')
            && !self.originator_address.contains('\0')
    }

    fn encode(self) -> io::Result<Vec<u8>> {
        let size = 16usize
            .saturating_add(self.address.len())
            .saturating_add(self.originator_address.len());
        if !self.valid() || size.saturating_add(self.kind.name().len()) > MAX_FIELDS {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid TCP forwarding channel fields",
            ));
        }
        packet(size, |writer| {
            writer.string(self.address.as_bytes())?;
            writer.uint32(self.port)?;
            writer.string(self.originator_address.as_bytes())?;
            writer.uint32(self.originator_port)
        })
    }
}

fn address<'a>(reader: &mut Reader<'a>) -> io::Result<&'a str> {
    str::from_utf8(reader.string().map_err(malformed)?)
        .map_err(|_| invalid("invalid UTF-8 in SSH forwarding address"))
}

impl IncomingChannel {
    pub fn tcpip(&self) -> io::Result<Option<TcpipOpen<'_>>> {
        TcpipOpen::decode(self.kind(), self.fields())
    }

    pub fn x11(&self) -> io::Result<Option<X11Open<'_>>> {
        X11Open::decode(self.kind(), self.fields())
    }

    /// Recognize the forwarding name and verify its empty open payload.
    pub fn agent_forwarding(&self) -> io::Result<Option<AgentForwarding>> {
        let protocol = match self.kind() {
            b"auth-agent@openssh.com" => AgentForwarding::OpenSsh,
            b"agent-connect" => AgentForwarding::Standard,
            _ => return Ok(None),
        };
        Reader::new(self.fields()).finish().map_err(malformed)?;
        Ok(Some(protocol))
    }

    /// Relay an authorized incoming Agent channel to an application-supplied
    /// stream. The application decides which peer may use the agent.
    pub async fn relay_agent(
        self,
        mut agent: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    ) -> io::Result<(u64, u64)> {
        if self.agent_forwarding()?.is_none() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "expected an SSH agent channel",
            ));
        }
        let mut channel = self.accept(DEFAULT_WINDOW, &[]).await?.into_io();
        tokio::io::copy_bidirectional(&mut channel, &mut agent).await
    }
}

impl<'a> From<TcpipOpen<'a>> for OpenType<'a> {
    fn from(open: TcpipOpen<'a>) -> Self {
        Self::Tcpip(open)
    }
}

impl<'a> From<StreamlocalOpen<'a>> for OpenType<'a> {
    fn from(open: StreamlocalOpen<'a>) -> Self {
        Self::Streamlocal(open)
    }
}

impl<'a> From<X11Open<'a>> for OpenType<'a> {
    fn from(open: X11Open<'a>) -> Self {
        Self::X11(open)
    }
}

impl From<AgentForwarding> for OpenType<'_> {
    fn from(protocol: AgentForwarding) -> Self {
        Self::Agent(protocol)
    }
}

impl<'a> OpenType<'a> {
    /// The channel type name and its type-specific open fields.
    fn encode(self) -> io::Result<(Cow<'a, str>, Vec<u8>)> {
        let (name, fields) = match self {
            Self::Session => ("session", Vec::new()),
            Self::X11(open) => open.encode_open()?,
            Self::Agent(protocol) => (protocol.channel_name(), Vec::new()),
            Self::Tcpip(open) => open.encode_open()?,
            Self::Streamlocal(open) => open.encode_open()?,
            Self::Custom { name, fields } => {
                let name = std::str::from_utf8(name).map_err(|_| {
                    io::Error::new(ErrorKind::InvalidInput, "SSH channel type is not UTF-8")
                })?;
                return Ok((Cow::Borrowed(name), fields.to_vec()));
            }
        };
        Ok((Cow::Borrowed(name), fields))
    }
}

/// A listener the peer runs for this side. Each connection it accepts comes
/// back as a forwarded channel open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteListener<'a> {
    /// A TCP address on the peer. Port zero lets the peer choose the port.
    Tcp { bind_address: &'a str, port: u32 },
    /// A Unix domain socket on the peer.
    Unix { socket_path: &'a [u8] },
}

impl RemoteListener<'_> {
    fn request(self, listen: bool) -> io::Result<(&'static str, Vec<u8>)> {
        match self {
            Self::Tcp { bind_address, port } => TcpipForward {
                kind: if listen {
                    TcpipForwardKind::Listen
                } else {
                    TcpipForwardKind::Cancel
                },
                bind_address,
                port,
            }
            .encode_request(),
            Self::Unix { socket_path } => StreamlocalForward {
                kind: if listen {
                    StreamlocalForwardKind::Listen
                } else {
                    StreamlocalForwardKind::Cancel
                },
                socket_path,
            }
            .encode_request(),
        }
    }
}

impl Handle {
    /// Open a session channel.
    pub async fn open_session(&self) -> io::Result<Channel> {
        self.open_as(OpenType::Session).await
    }

    /// Open a channel of a described type with the default window. The peer's
    /// confirmation must carry no type-specific fields. Use `open_channel`
    /// for a type whose confirmation does.
    pub async fn open_as<'a>(&self, open: impl Into<OpenType<'a>>) -> io::Result<Channel> {
        let (name, fields) = open.into().encode()?;
        let channel = self.open_channel(&name, DEFAULT_WINDOW, &fields).await?;
        if !channel.open_fields().is_empty() {
            return Err(invalid("unexpected SSH channel confirmation fields"));
        }
        Ok(channel)
    }

    /// Ask the peer to start a listener. Returns the port the peer chose when
    /// a TCP request left the choice to it.
    pub async fn listen(&self, listener: RemoteListener<'_>) -> io::Result<Option<u32>> {
        let reply = self.listener_request(listener, true).await?;
        let requested = match listener {
            RemoteListener::Tcp { port, .. } => port,
            RemoteListener::Unix { .. } => {
                Reader::new(&reply).finish().map_err(malformed)?;
                return Ok(None);
            }
        };
        if requested != 0 && reply.is_empty() {
            return Ok(None);
        }
        let mut reader = Reader::new(&reply);
        let actual = reader.uint32().map_err(malformed)?;
        reader.finish().map_err(malformed)?;
        if actual == 0 || actual > u32::from(u16::MAX) || (requested != 0 && actual != requested) {
            return Err(invalid("invalid allocated TCP forwarding port"));
        }
        Ok((requested == 0).then_some(actual))
    }

    /// Ask the peer to stop a listener. Channels it already opened have their
    /// own lifetime.
    pub async fn unlisten(&self, listener: RemoteListener<'_>) -> io::Result<()> {
        let reply = self.listener_request(listener, false).await?;
        Reader::new(&reply).finish().map_err(malformed)
    }

    async fn listener_request(
        &self,
        listener: RemoteListener<'_>,
        listen: bool,
    ) -> io::Result<Bytes> {
        let (name, fields) = listener.request(listen)?;
        match self.global_request(name, &fields).await? {
            GlobalReply::Success(fields) => Ok(fields),
            GlobalReply::Failure => Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "peer refused the forwarding request",
            )),
        }
    }
}
