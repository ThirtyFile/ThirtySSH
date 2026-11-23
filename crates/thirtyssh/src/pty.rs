//! Portable terminal modes for SSH pseudo-terminal requests.
use crate::{
    auth::malformed,
    channel::{MAX_FIELDS, packet},
    clear_packet::invalid,
    wire::{self, Reader, Writer},
};
use std::io::{self, ErrorKind};

// The names and discriminants follow the SSH terminal mode registry.
macro_rules! pty_modes {
    ($($name:ident = $opcode:expr),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        pub enum Pty {
            TTY_OP_END = 0,
            $($name = $opcode),+
        }

        impl Pty {
            pub const fn from_u8(opcode: u8) -> Option<Self> {
                match opcode {
                    $($opcode => Some(Self::$name),)+
                    _ => None,
                }
            }
        }
    };
}

pty_modes! {
    VINTR = 1, VQUIT = 2, VERASE = 3, VKILL = 4, VEOF = 5,
    VEOL = 6, VEOL2 = 7, VSTART = 8, VSTOP = 9, VSUSP = 10,
    VDSUSP = 11, VREPRINT = 12, VWERASE = 13, VLNEXT = 14,
    VFLUSH = 15, VSWTCH = 16, VSTATUS = 17, VDISCARD = 18,
    IGNPAR = 30, PARMRK = 31, INPCK = 32, ISTRIP = 33, INLCR = 34,
    IGNCR = 35, ICRNL = 36, IUCLC = 37, IXON = 38, IXANY = 39,
    IXOFF = 40, IMAXBEL = 41, IUTF8 = 42,
    ISIG = 50, ICANON = 51, XCASE = 52, ECHO = 53, ECHOE = 54,
    ECHOK = 55, ECHONL = 56, NOFLSH = 57, TOSTOP = 58, IEXTEN = 59,
    ECHOCTL = 60, ECHOKE = 61, PENDIN = 62,
    OPOST = 70, OLCUC = 71, ONLCR = 72, OCRNL = 73, ONOCR = 74, ONLRET = 75,
    CS7 = 90, CS8 = 91, PARENB = 92, PARODD = 93,
    TTY_OP_ISPEED = 128, TTY_OP_OSPEED = 129,
}

/// A terminal mode and its RFC 4254 argument. Unknown opcodes below 160
/// are retained so the caller can ignore or forward them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalMode {
    pub opcode: u8,
    pub value: u32,
}

impl TerminalMode {
    pub const fn known(self) -> Option<Pty> {
        Pty::from_u8(self.opcode)
    }
}

impl From<(Pty, u32)> for TerminalMode {
    fn from((mode, value): (Pty, u32)) -> Self {
        Self {
            opcode: mode as u8,
            value,
        }
    }
}

/// Character and pixel dimensions as carried on the wire. Zero means
/// unspecified. An application applies character dimensions in preference
/// to pixel dimensions when both are supplied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl TerminalSize {
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, wire::Error> {
        Ok(Self {
            columns: reader.uint32()?,
            rows: reader.uint32()?,
            pixel_width: reader.uint32()?,
            pixel_height: reader.uint32()?,
        })
    }

    pub(crate) fn encode(self, writer: &mut Writer<'_>) -> Result<(), wire::Error> {
        writer.uint32(self.columns)?;
        writer.uint32(self.rows)?;
        writer.uint32(self.pixel_width)?;
        writer.uint32(self.pixel_height)
    }
}

/// Encode the mode list with its terminating TTY_OP_END.
pub fn encode_modes(modes: &[TerminalMode]) -> io::Result<Vec<u8>> {
    let size = modes.len().saturating_mul(5).saturating_add(1);
    if size > MAX_FIELDS || modes.iter().any(|mode| !(1..160).contains(&mode.opcode)) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH terminal modes",
        ));
    }
    packet(size, |writer| {
        for mode in modes {
            writer.byte(mode.opcode)?;
            writer.uint32(mode.value)?;
        }
        writer.byte(Pty::TTY_OP_END as u8)
    })
}

/// Decode a terminal mode list. A reserved opcode of 160 or higher ends
/// parsing. An empty string, as sent by OpenSSH without a local TTY,
/// leaves all modes at their defaults.
pub fn decode_modes(encoded: &[u8]) -> io::Result<Vec<TerminalMode>> {
    if encoded.len() > crate::clear_packet::MAX_PACKET_SIZE {
        return Err(invalid("SSH terminal modes exceed the packet limit"));
    }
    let mut reader = Reader::new(encoded);
    let mut modes = Vec::new();
    if encoded.is_empty() {
        return Ok(modes);
    }
    loop {
        let opcode = reader.byte().map_err(malformed)?;
        match opcode {
            0 => {
                reader.finish().map_err(malformed)?;
                return Ok(modes);
            }
            160..=255 => return Ok(modes),
            _ => modes.push(TerminalMode {
                opcode,
                value: reader.uint32().map_err(malformed)?,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_terminal_modes_have_the_standard_opcodes() {
        assert_eq!(Pty::TTY_OP_END as u8, 0);
        for opcode in 0..=255 {
            let known = matches!(
                opcode,
                1..=18 | 30..=42 | 50..=62 | 70..=75 | 90..=93 | 128..=129
            );
            assert_eq!(
                Pty::from_u8(opcode).map(|mode| mode as u8),
                known.then_some(opcode)
            );
        }
    }

    #[test]
    fn modes_preserve_u32_arguments_and_stop_at_reserved_opcodes() {
        let modes = [
            (Pty::VINTR, 3).into(),
            TerminalMode {
                opcode: 19,
                value: 0xfeed_beef,
            },
            (Pty::TTY_OP_OSPEED, 230_400).into(),
        ];
        let encoded = encode_modes(&modes).unwrap();
        assert_eq!(
            encoded,
            [
                1, 0, 0, 0, 3, 19, 0xfe, 0xed, 0xbe, 0xef, 129, 0, 3, 0x84, 0, 0
            ]
        );
        assert_eq!(decode_modes(&encoded).unwrap(), modes);
        assert_eq!(modes[1].known(), None);
        let mut reserved = encoded[..encoded.len() - 1].to_vec();
        reserved.extend_from_slice(&[160, 255, 0xde, 0xad]);
        assert_eq!(decode_modes(&reserved).unwrap(), modes);
        assert!(decode_modes(&[]).unwrap().is_empty());
    }

    #[test]
    fn terminal_modes_reject_truncation_and_invalid_outgoing_opcodes() {
        for malformed in [&[53, 0, 0, 0][..], &[53, 0, 0, 0, 1], &[0, 53]] {
            assert_eq!(
                decode_modes(malformed).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
        for opcode in [0, 160, 255] {
            let mode = TerminalMode { opcode, value: 1 };
            assert_eq!(
                encode_modes(&[mode]).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
    }
}
