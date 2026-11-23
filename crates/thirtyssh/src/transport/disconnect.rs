//! Disconnect messages, sent and received.
use super::*;

pub(crate) fn disconnect_packet(
    reason: u32,
    description: &str,
    language: &str,
) -> io::Result<Vec<u8>> {
    let size = 13usize
        .saturating_add(description.len())
        .saturating_add(language.len());
    if size > clear_packet::MAX_PACKET_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH disconnect exceeds size limit",
        ));
    }
    crate::channel::packet(size, |writer| {
        writer.byte(1)?;
        writer.uint32(reason)?;
        writer.string(description.as_bytes())?;
        writer.string(language.as_bytes())
    })
}

/// A local SSH disconnect that can be queued before authentication completes.
pub struct DisconnectRequest(Vec<u8>);

impl DisconnectRequest {
    pub fn new(reason: u32, description: &str, language: &str) -> io::Result<Self> {
        Ok(Self(disconnect_packet(reason, description, language)?))
    }

    pub(crate) fn packet(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_packet(self) -> Vec<u8> {
        self.0
    }
}

/// The peer's explicit SSH disconnect message, available as an I/O error cause.
#[derive(Debug, Eq, PartialEq)]
pub struct PeerDisconnect {
    pub reason: u32,
    pub description: Vec<u8>,
    pub language: Vec<u8>,
}

impl std::fmt::Display for PeerDisconnect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SSH peer disconnected (reason {})", self.reason)
    }
}

impl std::error::Error for PeerDisconnect {}

pub(crate) fn peer_disconnected(packet: &[u8]) -> io::Error {
    fn decode(packet: &[u8]) -> Result<PeerDisconnect, crate::wire::Error> {
        let mut fields = Reader::new(&packet[1..]);
        let reason = fields.uint32()?;
        let description = fields.string()?.to_vec();
        let language = fields.string()?.to_vec();
        fields.finish()?;
        Ok(PeerDisconnect {
            reason,
            description,
            language,
        })
    }
    match decode(packet) {
        Ok(disconnect) => io::Error::new(ErrorKind::ConnectionAborted, disconnect),
        Err(error) => crate::auth::malformed(error),
    }
}
