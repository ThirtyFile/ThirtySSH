//! Connection timers. The watchdog stays runnable while the driver is
//! blocked on packet I/O or a key exchange.
#[cfg(test)]
mod tests;
use crate::{
    channel::driver::Handle,
    runtime::{Instant, sleep_until},
    transport::Activity,
};
use std::{
    convert::Infallible,
    fmt,
    future::pending,
    io::{self, ErrorKind},
    time::Duration,
};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Timeout {
    Inactivity,
    Keepalive,
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inactivity => "SSH session inactivity timed out",
            Self::Keepalive => "SSH peer did not respond to keepalives",
        })
    }
}

impl std::error::Error for Timeout {}

#[derive(Clone, Copy)]
pub(crate) struct Liveness {
    pub(crate) inactivity_timeout: Option<Duration>,
    pub(crate) keepalive_interval: Option<Duration>,
    pub(crate) keepalive_max: usize,
}

impl Liveness {
    pub(crate) fn enabled(self) -> bool {
        self.inactivity_timeout.is_some() || self.keepalive_interval.is_some()
    }

    pub(crate) fn validate(self) -> io::Result<()> {
        let now = Instant::now();
        for span in [
            self.inactivity_timeout,
            self.keepalive_interval,
            self.silence_period()?,
        ]
        .into_iter()
        .flatten()
        {
            if span.is_zero() || now.checked_add(span).is_none() {
                return Err(invalid_duration());
            }
        }
        Ok(())
    }

    fn silence_period(self) -> io::Result<Option<Duration>> {
        let Some(interval) = self.keepalive_interval.filter(|_| self.keepalive_max != 0) else {
            return Ok(None);
        };
        // After N unanswered probes, the next probe deadline expires the session.
        let nanos = interval
            .as_nanos()
            .checked_mul(self.keepalive_max as u128 + 1)
            .ok_or_else(invalid_duration)?;
        let seconds = u64::try_from(nanos / 1_000_000_000).map_err(|_| invalid_duration())?;
        Ok(Some(Duration::new(seconds, (nanos % 1_000_000_000) as u32)))
    }

    pub(crate) async fn watchdog(
        self,
        mut traffic: watch::Receiver<Activity>,
    ) -> io::Result<Infallible> {
        let silence = self.silence_period()?;
        loop {
            let activity = *traffic.borrow_and_update();
            let idle = deadline(activity.active, self.inactivity_timeout)?;
            let unresponsive = deadline(activity.received, silence)?;
            let (at, reason) = match (idle, unresponsive) {
                (Some(a), Some(b)) if b < a => (b, Timeout::Keepalive),
                (Some(a), _) => (a, Timeout::Inactivity),
                (None, Some(b)) => (b, Timeout::Keepalive),
                (None, None) => return pending().await,
            };
            if at <= Instant::now() {
                return Err(io::Error::new(ErrorKind::TimedOut, reason));
            }
            tokio::select! {
                changed = traffic.changed() => if changed.is_err() { return pending().await; },
                () = sleep_until(at) => {},
            }
        }
    }

    pub(crate) async fn probe(
        self,
        mut traffic: watch::Receiver<Activity>,
        handle: Handle,
    ) -> io::Result<()> {
        let Some(interval) = self.keepalive_interval else {
            return pending().await;
        };
        let mut last_probe = traffic.borrow().received;
        loop {
            let last = traffic.borrow_and_update().received.max(last_probe);
            let at = last.checked_add(interval).ok_or_else(invalid_duration)?;
            tokio::select! {
                biased;
                () = sleep_until(at) => {
                    if traffic.borrow().received > last { continue; }
                    match handle.keepalive(true).await {
                        Ok(()) => {},
                        // The wire cannot correlate more replies until its
                        // bounded FIFO drains. Retry after the next interval.
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {},
                        Err(error) => return Err(error),
                    }
                    let now = Instant::now();
                    last_probe = if at.checked_add(interval).is_some_and(|next| next > now) { at } else { now };
                }
                changed = traffic.changed() => if changed.is_err() { return pending().await; },
            }
        }
    }
}

fn deadline(start: Instant, span: Option<Duration>) -> io::Result<Option<Instant>> {
    span.map(|span| start.checked_add(span).ok_or_else(invalid_duration))
        .transpose()
}

fn invalid_duration() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidInput,
        "invalid SSH session timer duration",
    )
}
