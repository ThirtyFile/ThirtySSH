//! Thresholds for automatic key re-exchange.
use super::*;

/// Byte and key-age thresholds for automatic key exchange.
#[derive(Clone, Debug)]
pub struct Limits {
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit: Duration,
}

impl Limits {
    /// Construct thresholds with a maximum byte limit of one GiB per key.
    /// A transport rekeys somewhat earlier than a limit near that maximum,
    /// so that what the peer still sends under the old keys fits below it.
    pub fn new(write_limit: usize, read_limit: usize, time_limit: Duration) -> Self {
        assert!(write_limit <= KEY_BYTE_LIMIT && read_limit <= KEY_BYTE_LIMIT);
        Self {
            rekey_write_limit: write_limit,
            rekey_read_limit: read_limit,
            rekey_time_limit: time_limit,
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let valid = 1..=KEY_BYTE_LIMIT;
        if !valid.contains(&self.rekey_read_limit)
            || !valid.contains(&self.rekey_write_limit)
            || self.rekey_time_limit.is_zero()
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid SSH rekey limits",
            ));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(KEY_BYTE_LIMIT, KEY_BYTE_LIMIT, DEFAULT_REKEY_AGE)
    }
}
