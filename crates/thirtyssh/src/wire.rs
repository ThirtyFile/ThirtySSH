//! SSH binary fields from [RFC 4251 §5](https://www.rfc-editor.org/rfc/rfc4251#section-5).
//! Both cursors borrow caller-supplied buffers. A failed operation leaves its cursor unchanged.
//!
//! ```
//! use thirtyssh::wire::{Reader, Writer};
//!
//! let mut output = [0; 32];
//! let mut writer = Writer::new(&mut output);
//! writer.string(b"ssh-userauth")?;
//! let mut reader = Reader::new(writer.written());
//! assert_eq!(reader.string()?, b"ssh-userauth");
//! reader.finish()?;
//! # Ok::<(), thirtyssh::wire::Error>(())
//! ```
use std::{error, fmt, str};

/// Errors contain no field contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    OutputTooSmall,
    LengthOverflow,
    InvalidMpint,
    InvalidNameList,
    TrailingBytes,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated SSH field",
            Self::OutputTooSmall => "SSH output buffer too small",
            Self::LengthOverflow => "SSH field length exceeds representable range",
            Self::InvalidMpint => "noncanonical SSH mpint",
            Self::InvalidNameList => "invalid SSH name-list",
            Self::TrailingBytes => "unexpected trailing SSH data",
        })
    }
}

impl error::Error for Error {}

// RFC 4251 encodes zero as an empty string. A sign byte is necessary
// only when removing it would change the sign of the following byte.
pub(crate) fn validate_mpint(bytes: &[u8]) -> Result<&[u8], Error> {
    match bytes {
        [0] => Err(Error::InvalidMpint),
        [0, next, ..] if next & 0x80 == 0 => Err(Error::InvalidMpint),
        [0xff, next, ..] if next & 0x80 != 0 => Err(Error::InvalidMpint),
        _ => Ok(bytes),
    }
}

fn validate_names(bytes: &[u8]) -> Result<&str, Error> {
    if !bytes.is_ascii()
        || bytes.contains(&0)
        || (!bytes.is_empty() && bytes.split(|b| *b == b',').any(|name| name.is_empty()))
    {
        return Err(Error::InvalidNameList);
    }
    str::from_utf8(bytes).map_err(|_| Error::InvalidNameList)
}

/// Zero-copy reader over one bounded SSH payload.
pub struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { remaining: payload }
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (bytes, rest) = self.remaining.split_first_chunk().ok_or(Error::Truncated)?;
        self.remaining = rest;
        Ok(*bytes)
    }

    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }
    pub fn boolean(&mut self) -> Result<bool, Error> {
        Ok(self.byte()? != 0)
    }
    pub fn uint32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub fn uint64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn field<T>(&mut self, parse: impl FnOnce(&'a [u8]) -> Result<T, Error>) -> Result<T, Error> {
        let (prefix, contents) = self.remaining.split_first_chunk().ok_or(Error::Truncated)?;
        let len =
            usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| Error::LengthOverflow)?;
        let (bytes, rest) = contents.split_at_checked(len).ok_or(Error::Truncated)?;
        let value = parse(bytes)?;
        self.remaining = rest;
        Ok(value)
    }

    /// SSH strings may contain arbitrary octets.
    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        self.field(Ok)
    }
    /// Canonical signed two's-complement bytes, most significant first.
    pub fn mpint(&mut self) -> Result<&'a [u8], Error> {
        self.field(validate_mpint)
    }
    /// Comma-separated ASCII names. Algorithm-specific rules belong to negotiation.
    pub fn name_list(&mut self) -> Result<&'a str, Error> {
        self.field(validate_names)
    }
}

/// Encoder into a fixed-size destination. Only the written prefix is part of the payload.
pub struct Writer<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    pub fn written(&self) -> &[u8] {
        &self.buffer[..self.position]
    }

    fn reserve(&mut self, len: usize) -> Result<&mut [u8], Error> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::LengthOverflow)?;
        let space = self
            .buffer
            .get_mut(self.position..end)
            .ok_or(Error::OutputTooSmall)?;
        self.position = end;
        Ok(space)
    }

    pub(crate) fn fixed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.reserve(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    pub fn byte(&mut self, value: u8) -> Result<(), Error> {
        self.fixed(&[value])
    }
    pub fn boolean(&mut self, value: bool) -> Result<(), Error> {
        self.byte(u8::from(value))
    }
    pub fn uint32(&mut self, value: u32) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    pub fn uint64(&mut self, value: u64) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }

    pub fn string(&mut self, value: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(value.len()).map_err(|_| Error::LengthOverflow)?;
        let size = value.len().checked_add(4).ok_or(Error::LengthOverflow)?;
        let (prefix, contents) = self.reserve(size)?.split_at_mut(4);
        prefix.copy_from_slice(&len.to_be_bytes());
        contents.copy_from_slice(value);
        Ok(())
    }

    /// Takes the canonical two's-complement representation of a signed integer.
    pub fn mpint(&mut self, value: &[u8]) -> Result<(), Error> {
        self.string(validate_mpint(value)?)
    }

    pub fn name_list(&mut self, value: &str) -> Result<(), Error> {
        self.string(validate_names(value.as_bytes())?.as_bytes())
    }
}
