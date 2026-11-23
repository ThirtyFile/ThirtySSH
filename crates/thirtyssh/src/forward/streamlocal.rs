//! OpenSSH Unix domain socket forwarding. Wire paths are byte strings because
//! Unix filesystem paths can contain non-UTF-8 bytes. Applications authorize
//! each path before accepting a channel or binding a local listener.

use crate::{
    auth::malformed,
    channel::{GlobalRequest, MAX_FIELDS, packet},
    clear_packet::invalid,
    session::IncomingChannel,
    wire::Reader,
};
use std::{
    io::{self, ErrorKind},
    path::Path,
};

const DIRECT: &str = "direct-streamlocal@openssh.com";
const FORWARDED: &str = "forwarded-streamlocal@openssh.com";
const LISTEN: &str = "streamlocal-forward@openssh.com";
const CANCEL: &str = "cancel-streamlocal-forward@openssh.com";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamlocalKind {
    Direct,
    Forwarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamlocalOpen<'a> {
    pub kind: StreamlocalKind,
    pub socket_path: &'a [u8],
}

impl<'a> StreamlocalOpen<'a> {
    pub fn encode_open(self) -> io::Result<(&'static str, Vec<u8>)> {
        let (name, reserved) = match self.kind {
            StreamlocalKind::Direct => (DIRECT, &[0; 8][..]),
            StreamlocalKind::Forwarded => (FORWARDED, &[0; 4][..]),
        };
        Ok((name, encode_path(name, self.socket_path, reserved)?))
    }

    /// Decode a streamlocal channel open. The reserved fields are consumed
    /// and ignored. Other channel types return `Ok(None)`.
    pub fn decode(kind: &[u8], fields: &'a [u8]) -> io::Result<Option<Self>> {
        let kind = match kind {
            name if name == DIRECT.as_bytes() => StreamlocalKind::Direct,
            name if name == FORWARDED.as_bytes() => StreamlocalKind::Forwarded,
            _ => return Ok(None),
        };
        let mut reader = Reader::new(fields);
        let socket_path = read_path(&mut reader)?;
        reader.string().map_err(malformed)?;
        if kind == StreamlocalKind::Direct {
            reader.uint32().map_err(malformed)?;
        }
        reader.finish().map_err(malformed)?;
        Ok(Some(Self { kind, socket_path }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamlocalForwardKind {
    Listen,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamlocalForward<'a> {
    pub kind: StreamlocalForwardKind,
    pub socket_path: &'a [u8],
}

impl<'a> StreamlocalForward<'a> {
    /// Encode the SSH global request name and socket path.
    pub fn encode_request(self) -> io::Result<(&'static str, Vec<u8>)> {
        let name = match self.kind {
            StreamlocalForwardKind::Listen => LISTEN,
            StreamlocalForwardKind::Cancel => CANCEL,
        };
        Ok((name, encode_path(name, self.socket_path, &[])?))
    }

    /// Decode a remote listener request or cancellation.
    pub fn decode(name: &[u8], fields: &'a [u8]) -> io::Result<Option<Self>> {
        let kind = match name {
            name if name == LISTEN.as_bytes() => StreamlocalForwardKind::Listen,
            name if name == CANCEL.as_bytes() => StreamlocalForwardKind::Cancel,
            _ => return Ok(None),
        };
        let mut reader = Reader::new(fields);
        let socket_path = read_path(&mut reader)?;
        reader.finish().map_err(malformed)?;
        Ok(Some(Self { kind, socket_path }))
    }
}

impl IncomingChannel {
    pub fn streamlocal(&self) -> io::Result<Option<StreamlocalOpen<'_>>> {
        StreamlocalOpen::decode(self.kind(), self.fields())
    }
}

impl GlobalRequest {
    pub fn streamlocal_forward(&self) -> io::Result<Option<StreamlocalForward<'_>>> {
        StreamlocalForward::decode(&self.name, &self.fields)
    }
}

/// After authorizing the request, connect to the caller's chosen local socket
/// before confirming the channel. On a non-Unix platform this returns
/// `Unsupported`. Protocol operations targeting a remote host work separately.
pub async fn relay_to_socket(
    request: IncomingChannel,
    local_path: impl AsRef<Path>,
) -> io::Result<(u64, u64)> {
    #[cfg(unix)]
    {
        let mut socket = match tokio::net::UnixStream::connect(local_path).await {
            Ok(socket) => socket,
            Err(error) => {
                request.refuse(2).await?;
                return Err(error);
            }
        };
        let mut channel = request
            .accept(crate::channel::DEFAULT_WINDOW, &[])
            .await?
            .into_io();
        tokio::io::copy_bidirectional(&mut channel, &mut socket).await
    }
    #[cfg(not(unix))]
    {
        let _ = local_path;
        request.refuse(1).await?;
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "local Unix domain socket forwarding is unavailable",
        ))
    }
}

fn read_path<'a>(reader: &mut Reader<'a>) -> io::Result<&'a [u8]> {
    let path = reader.string().map_err(malformed)?;
    if !valid_path(path) {
        return Err(invalid("invalid streamlocal socket path"));
    }
    Ok(path)
}

fn encode_path(name: &str, path: &[u8], trailing: &[u8]) -> io::Result<Vec<u8>> {
    let size = 4usize
        .saturating_add(path.len())
        .saturating_add(trailing.len());
    if !valid_path(path) || size.saturating_add(name.len()) > MAX_FIELDS {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid or oversized streamlocal socket path",
        ));
    }
    packet(size, |writer| {
        writer.string(path)?;
        writer.fixed(trailing)
    })
}

fn valid_path(path: &[u8]) -> bool {
    !path.is_empty() && !path.contains(&0)
}
