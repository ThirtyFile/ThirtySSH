//! Packet framing during the initial key exchange, before key activation.
//!
//! After a read or write error or cancellation, discard the stream. The operation
//! can stop after consuming or writing part of a frame.
use crate::{protocol_error::ProtocolError, runtime::timeout, session::Timeout};
use std::{
    io::{self, ErrorKind},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const LENGTH_SIZE: usize = size_of::<u32>();
pub(crate) const HEADER_SIZE: usize = LENGTH_SIZE + 1;
const MIN_PACKET: usize = 16;
const MIN_PADDING: usize = 4;

/// Limit on a binary packet during the initial key exchange.
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

pub(crate) const MAX_CHANNEL_DATA: u32 = 256 * 1024;
// Full channel extended data plus its message fields and up to 19 bytes of
// padding for 16-byte ciphers. The authentication tag is separate.
pub(crate) const MAX_TRANSPORT_PACKET_SIZE: usize =
    MAX_CHANNEL_DATA as usize + HEADER_SIZE + 13 + 19;
/// The largest payload one transport packet can carry.
pub(crate) const MAX_TRANSPORT_PAYLOAD: usize =
    MAX_TRANSPORT_PACKET_SIZE - HEADER_SIZE - MIN_PADDING;

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) block: usize,
    pub(crate) separate_length: bool,
    pub(crate) max_packet_size: usize,
}

const CLEAR: Layout = Layout {
    block: 8,
    separate_length: false,
    max_packet_size: MAX_PACKET_SIZE,
};

impl Layout {
    fn prefix(self) -> usize {
        if self.separate_length { LENGTH_SIZE } else { 0 }
    }

    fn minimum(self) -> usize {
        if self.separate_length {
            HEADER_SIZE + MIN_PADDING + 1
        } else {
            MIN_PACKET
        }
    }
}

/// Read one SSH payload. The padding and framing bytes are consumed separately.
pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let total = packet_size(reader.read_u32().await?, CLEAR)?;
    let padding_length = usize::from(reader.read_u8().await?);
    let mut payload = vec![0; payload_len(total, padding_length)?];
    reader.read_exact(&mut payload).await?;
    let mut padding = [0; u8::MAX as usize];
    reader.read_exact(&mut padding[..padding_length]).await?;
    Ok(payload)
}

/// Applies the inactivity interval to each whole frame. Partial input does
/// not extend it. A failed read invalidates the initial exchange.
pub(crate) struct PacketReader<R> {
    reader: R,
    inactivity_timeout: Option<Duration>,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub(crate) fn new(reader: R, inactivity_timeout: Option<Duration>) -> Self {
        Self {
            reader,
            inactivity_timeout,
        }
    }

    pub(crate) async fn read(&mut self) -> io::Result<Vec<u8>> {
        let packet = read(&mut self.reader);
        match self.inactivity_timeout {
            Some(limit) => timeout(limit, packet)
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, Timeout::Inactivity))?,
            None => packet.await,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.reader
    }
}

/// Write and flush one SSH payload with OS-generated random padding.
pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let packet = encode(payload, CLEAR, 0)?;
    writer.write_all(&packet).await?;
    writer.flush().await
}

pub(crate) fn packet_size(length: u32, layout: Layout) -> io::Result<usize> {
    let length = usize::try_from(length).map_err(|_| invalid("invalid SSH packet length"))?;
    if !(layout.minimum() - LENGTH_SIZE..=layout.max_packet_size - LENGTH_SIZE).contains(&length)
        || !(length + LENGTH_SIZE - layout.prefix()).is_multiple_of(layout.block)
    {
        return Err(ProtocolError::PacketSize {
            size: length,
            detail: "invalid SSH packet length",
        }
        .into());
    }
    Ok(length + LENGTH_SIZE)
}

pub(crate) fn payload_len(total: usize, padding: usize) -> io::Result<usize> {
    if padding < MIN_PADDING || padding >= total - HEADER_SIZE {
        return Err(invalid("invalid SSH padding length"));
    }
    Ok(total - HEADER_SIZE - padding)
}

pub(crate) fn encode(payload: &[u8], layout: Layout, tag_len: usize) -> io::Result<Vec<u8>> {
    let mut packet = Vec::new();
    encode_into(payload, layout, tag_len, &mut packet)?;
    Ok(packet)
}

pub(crate) fn encode_into(
    payload: &[u8],
    layout: Layout,
    tag_len: usize,
    packet: &mut Vec<u8>,
) -> io::Result<()> {
    debug_assert!(packet.is_empty());
    if payload.is_empty() || payload.len() > layout.max_packet_size - HEADER_SIZE - MIN_PADDING {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH payload length",
        ));
    }
    let unpadded = HEADER_SIZE + payload.len();
    let total = ((unpadded + MIN_PADDING - layout.prefix()).next_multiple_of(layout.block)
        + layout.prefix())
    .max(layout.minimum());
    if total > layout.max_packet_size {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH payload leaves no room for padding",
        ));
    }
    let padding_length = total - unpadded;
    let length = (total - LENGTH_SIZE) as u32;
    let mut padding = [0; u8::MAX as usize];
    let padding = &mut padding[..padding_length];
    getrandom::fill(padding).map_err(io::Error::other)?;
    packet.reserve_exact(total + tag_len);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.push(padding_length as u8);
    packet.extend_from_slice(payload);
    packet.extend_from_slice(padding);
    packet.resize(total + tag_len, 0);
    Ok(())
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
