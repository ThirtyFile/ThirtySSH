//! Packets read while this side could not yet process them.
use super::*;

// While a rekey is pending the peer may keep sending until it sees our
// KEXINIT, so the queue must hold everything the channel windows we granted
// allow: the whole default window budget, plus room for packets that carry
// no channel data. The bound still caps what a misbehaving peer can make us
// buffer.
pub(super) const MAX_IN_FLIGHT_BYTES: usize =
    crate::channel::DEFAULT_WINDOW_BUDGET as usize + (8 << 20);
// Interactive and forwarded traffic arrives in packets far smaller than the
// maximum, so the count allows an average of roughly half a kilobyte.
pub(super) const MAX_IN_FLIGHT_PACKETS: usize = 128 * 1024;

#[derive(Default)]
pub(super) struct InFlight {
    pub(super) packets: VecDeque<Zeroizing<Vec<u8>>>,
    pub(super) bytes: usize,
}

impl InFlight {
    pub(super) fn has_packet_space(&self) -> bool {
        self.packets.len() < MAX_IN_FLIGHT_PACKETS
            && self.bytes <= MAX_IN_FLIGHT_BYTES - clear_packet::MAX_TRANSPORT_PACKET_SIZE
    }

    pub(super) fn push(&mut self, packet: Vec<u8>) -> io::Result<()> {
        let packet = Zeroizing::new(packet);
        if self.packets.len() == MAX_IN_FLIGHT_PACKETS
            || self.bytes + packet.len() > MAX_IN_FLIGHT_BYTES
        {
            return Err(invalid(
                "SSH in-flight packet queue exceeds limit during rekey",
            ));
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        Ok(())
    }

    pub(super) fn pop(&mut self) -> Option<Vec<u8>> {
        let mut packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        Some(std::mem::take(&mut *packet))
    }
}
