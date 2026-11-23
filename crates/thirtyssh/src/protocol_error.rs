//! Typed protocol errors that callers can recover from an `io::Error`.

use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ProtocolError {
    Identification(&'static str),
    KeyExchangeInit(&'static str),
    HostSignature,
    PacketMac,
    Decryption,
    GlobalMessageBeforeAuthentication,
    PacketSize {
        size: usize,
        detail: &'static str,
    },
    #[cfg(feature = "flate2")]
    Compression(flate2::CompressError),
    #[cfg(feature = "flate2")]
    Decompression(flate2::DecompressError),
    StrictKeyExchange {
        message_type: u8,
        sequence_number: usize,
        detail: &'static str,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identification(detail)
            | Self::KeyExchangeInit(detail)
            | Self::PacketSize { detail, .. }
            | Self::StrictKeyExchange { detail, .. } => detail,
            Self::HostSignature => "invalid SSH host signature",
            Self::PacketMac => "invalid SSH packet MAC",
            Self::Decryption => "invalid SSH AEAD packet",
            Self::GlobalMessageBeforeAuthentication => {
                "SSH global message received before authentication"
            }
            #[cfg(feature = "flate2")]
            Self::Compression(_) => "SSH zlib compression failed",
            #[cfg(feature = "flate2")]
            Self::Decompression(_) => "invalid SSH zlib stream",
        })
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "flate2")]
            Self::Compression(source) => Some(source),
            #[cfg(feature = "flate2")]
            Self::Decompression(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ProtocolError> for io::Error {
    fn from(error: ProtocolError) -> Self {
        Self::new(io::ErrorKind::InvalidData, error)
    }
}

pub(crate) fn unexpected_initial_message(
    message_type: u8,
    sequence_number: u32,
    strict: bool,
    detail: &'static str,
) -> io::Error {
    if strict {
        ProtocolError::StrictKeyExchange {
            message_type,
            sequence_number: sequence_number as usize,
            detail,
        }
        .into()
    } else {
        ProtocolError::KeyExchangeInit(detail).into()
    }
}
