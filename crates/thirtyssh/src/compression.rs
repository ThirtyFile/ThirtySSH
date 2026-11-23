//! Bounded, stateful SSH payload compression.
use crate::{algorithms::Compression, protection::Side};
use std::io;
use zeroize::Zeroizing;

#[cfg(feature = "flate2")]
use crate::{
    clear_packet::{LENGTH_SIZE, MAX_TRANSPORT_PACKET_SIZE, invalid},
    protocol_error::ProtocolError,
};
#[cfg(feature = "flate2")]
use flate2::{Compress, Decompress, FlushCompress, FlushDecompress, Status};
#[cfg(feature = "flate2")]
use zeroize::Zeroize;

#[cfg(feature = "flate2")]
const MAX_PAYLOAD: usize = MAX_TRANSPORT_PACKET_SIZE - LENGTH_SIZE;

#[cfg(feature = "flate2")]
enum Stream {
    Inactive,
    Encode(Compress),
    Decode(Decompress),
}

pub(crate) struct Codec {
    #[cfg(feature = "flate2")]
    selected: Compression,
    #[cfg(feature = "flate2")]
    stream: Stream,
}

impl Codec {
    pub(crate) fn new(selected: Compression, side: Side, authenticated: bool) -> Self {
        #[cfg(feature = "flate2")]
        {
            let stream = if selected == Compression::Zlib
                || (selected == Compression::DelayedZlib && authenticated)
            {
                start(side)
            } else {
                Stream::Inactive
            };
            Self { selected, stream }
        }
        #[cfg(not(feature = "flate2"))]
        {
            debug_assert_eq!(selected, Compression::None);
            let _ = (side, authenticated);
            Self {}
        }
    }

    pub(crate) fn enable_delayed(&mut self, side: Side) {
        #[cfg(feature = "flate2")]
        if self.selected == Compression::DelayedZlib && matches!(self.stream, Stream::Inactive) {
            self.stream = start(side);
        }
        #[cfg(not(feature = "flate2"))]
        let _ = side;
    }

    pub(crate) fn restart_delayed(&mut self, side: Side) -> Option<Self> {
        #[cfg(feature = "flate2")]
        if self.selected == Compression::DelayedZlib {
            return Some(std::mem::replace(
                self,
                Self::new(Compression::DelayedZlib, side, true),
            ));
        }
        #[cfg(not(feature = "flate2"))]
        let _ = side;
        None
    }

    pub(crate) fn encode(&mut self, input: &[u8]) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(feature = "flate2")]
        if let Stream::Encode(encoder) = &mut self.stream {
            if input.is_empty() || input.len() > MAX_PAYLOAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid SSH payload size for compression",
                ));
            }
            let before_in = encoder.total_in();
            let before_out = encoder.total_out();
            // Allow compression overhead without allocating the full limit
            // for each small packet.
            let capacity = (input.len() + 1024).min(MAX_PAYLOAD + 1);
            let mut output = Zeroizing::new(vec![0; capacity]);
            let status = encoder
                .compress(input, &mut output, FlushCompress::Partial)
                .map_err(|error| io::Error::other(ProtocolError::Compression(error)))?;
            let written = (encoder.total_out() - before_out) as usize;
            // A full buffer means zlib may be holding output back, which
            // would then leak into the next packet.
            if status != Status::Ok
                || encoder.total_in() - before_in != input.len() as u64
                || !(1..=MAX_PAYLOAD).contains(&written)
                || written == output.len()
            {
                return Err(io::Error::other("SSH zlib packet exceeds its wire limit"));
            }
            output.truncate(written);
            return Ok(Some(output));
        }
        let _ = input;
        Ok(None)
    }

    pub(crate) fn decode(&mut self, input: &[u8]) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(feature = "flate2")]
        if let Stream::Decode(decoder) = &mut self.stream {
            let mut output = Zeroizing::new(Vec::new());
            let result =
                inflate(decoder, input, &mut output, input.len().max(4096)).map_err(|error| {
                    io::Error::from(match error {
                        InflateError::Stream(error) => ProtocolError::Decompression(error),
                        InflateError::Limit(size) => ProtocolError::PacketSize {
                            size,
                            detail: "decompressed SSH payload exceeds limit",
                        },
                    })
                })?;
            if result.stream_end {
                return Err(invalid("SSH zlib stream ended before NEWKEYS"));
            }
            if result.consumed != input.len() || result.written == 0 {
                return Err(invalid("incomplete SSH zlib payload"));
            }
            output.truncate(result.written);
            return Ok(Some(output));
        }
        let _ = input;
        Ok(None)
    }
}

#[cfg(feature = "flate2")]
pub enum InflateError {
    Stream(flate2::DecompressError),
    Limit(usize),
}

#[cfg(feature = "flate2")]
pub struct Inflated {
    pub consumed: usize,
    pub written: usize,
    pub stream_end: bool,
}

/// Inflate one bounded chunk, preserving the dictionary across calls.
/// The caller determines whether a completed zlib stream is valid here.
#[cfg(feature = "flate2")]
pub fn inflate(
    decoder: &mut Decompress,
    input: &[u8],
    output: &mut Vec<u8>,
    initial_capacity: usize,
) -> Result<Inflated, InflateError> {
    let before_in = decoder.total_in();
    let before_out = decoder.total_out();
    let limit = MAX_PAYLOAD + 1;
    output.clear();
    output.resize(initial_capacity.clamp(1, limit), 0);
    let (mut consumed, mut written) = (0, 0);
    loop {
        let status = decoder
            .decompress(
                &input[consumed..],
                &mut output[written..],
                FlushDecompress::None,
            )
            .map_err(InflateError::Stream)?;
        let next_in = (decoder.total_in() - before_in) as usize;
        let next_out = (decoder.total_out() - before_out) as usize;
        if next_out > MAX_PAYLOAD {
            return Err(InflateError::Limit(next_out));
        }
        let stream_end = status == Status::StreamEnd;
        if stream_end || (next_in == consumed && next_out == written) {
            return Ok(Inflated {
                consumed: next_in,
                written: next_out,
                stream_end,
            });
        }
        (consumed, written) = (next_in, next_out);
        if written == output.len() {
            let mut next = vec![0; (written * 2).min(limit)];
            next[..written].copy_from_slice(output);
            let mut previous = std::mem::replace(output, next);
            previous.zeroize();
        }
    }
}

#[cfg(feature = "flate2")]
fn start(side: Side) -> Stream {
    match side {
        Side::Send => Stream::Encode(Compress::new(flate2::Compression::fast(), true)),
        Side::Receive => Stream::Decode(Decompress::new(true)),
    }
}

#[cfg(all(test, feature = "flate2"))]
mod tests {
    use super::*;

    #[test]
    fn delayed_compression_is_inactive_then_preserves_the_dictionary() {
        let mut encoder = Codec::new(Compression::DelayedZlib, Side::Send, false);
        let mut decoder = Codec::new(Compression::DelayedZlib, Side::Receive, false);
        assert!(encoder.encode(&[52]).unwrap().is_none());
        assert!(decoder.decode(&[52]).unwrap().is_none());
        encoder.enable_delayed(Side::Send);
        decoder.enable_delayed(Side::Receive);
        let mut previous = Vec::new();
        for fill in *b"aba" {
            let original = vec![fill; 4096];
            let wire = encoder.encode(&original).unwrap().unwrap();
            assert!(wire.len() < original.len());
            assert_eq!(&**decoder.decode(&wire).unwrap().unwrap(), &original);
            previous.extend_from_slice(&wire);
        }
        // A new epoch starts with an independent zlib header and history.
        let mut next_encoder = Codec::new(Compression::DelayedZlib, Side::Send, true);
        let mut next_decoder = Codec::new(Compression::DelayedZlib, Side::Receive, true);
        let original = vec![b'a'; 4096];
        let wire = next_encoder.encode(&original).unwrap().unwrap();
        assert_eq!(&*wire, &previous[..wire.len()]);
        assert_eq!(&**next_decoder.decode(&wire).unwrap().unwrap(), &original);
    }

    #[test]
    fn rejects_invalid_stream_and_enforces_exact_inflate_limit() {
        let mut decoder = Codec::new(Compression::Zlib, Side::Receive, false);
        assert!(decoder.decode(b"invalid input").is_err());
        let at_limit = vec![b'x'; MAX_PAYLOAD];
        let mut encoder = Codec::new(Compression::Zlib, Side::Send, false);
        let wire = encoder.encode(&at_limit).unwrap().unwrap();
        let mut truncated = Codec::new(Compression::Zlib, Side::Receive, false);
        assert!(truncated.decode(&wire[..1]).is_err());
        let mut decoder = Codec::new(Compression::Zlib, Side::Receive, false);
        assert_eq!(decoder.decode(&wire).unwrap().unwrap().len(), MAX_PAYLOAD);

        let mut stream = Compress::new(flate2::Compression::fast(), true);
        let mut wire = Vec::with_capacity(4096);
        stream
            .compress_vec(
                &vec![b'x'; MAX_PAYLOAD + 1],
                &mut wire,
                FlushCompress::Partial,
            )
            .unwrap();
        let mut decoder = Codec::new(Compression::Zlib, Side::Receive, false);
        assert_eq!(
            decoder.decode(&wire).unwrap_err().to_string(),
            "decompressed SSH payload exceeds limit"
        );
    }

    #[test]
    fn transport_rejects_a_zlib_stream_ending_inside_an_epoch() {
        use std::io::Write;
        let mut stream = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        stream.write_all(b"payload").unwrap();
        let wire = stream.finish().unwrap();
        let mut decoder = Codec::new(Compression::Zlib, Side::Receive, false);
        assert_eq!(
            decoder.decode(&wire).unwrap_err().to_string(),
            "SSH zlib stream ended before NEWKEYS"
        );
    }
}
