//! Platform adapters for clocks, timers and background session tasks.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tokio::time::timeout;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use tokio::time::{Instant, sleep_until, timeout_at};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use web_time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod web {
    use super::Instant;
    use gloo_timers::future::TimeoutFuture;
    use std::{future::Future, time::Duration};
    use tokio::sync::oneshot;
    use wasm_bindgen_futures::spawn_local;

    // The host timer belongs to the JS event loop. The receiving future is
    // Send, and dropping it cancels the timer via the closed receiver.
    pub(crate) async fn sleep_until(deadline: Instant) {
        if deadline <= Instant::now() {
            return;
        }
        let (mut fired, wait) = oneshot::channel();
        spawn_local(async move {
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                if fired.is_closed() {
                    return;
                }
                if remaining.is_zero() {
                    break;
                }
                // setTimeout interprets the duration as a signed 32-bit value.
                // Round up to avoid waking repeatedly before the deadline.
                let delay = remaining
                    .as_nanos()
                    .div_ceil(1_000_000)
                    .min(i32::MAX as u128) as u32;
                tokio::select! {
                    biased;
                    () = fired.closed() => return,
                    () = TimeoutFuture::new(delay) => (),
                }
            }
            let _ = fired.send(());
        });
        let _ = wait.await;
    }

    #[derive(Debug)]
    pub struct Elapsed;

    pub fn timeout<F: Future>(
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output, Elapsed>> {
        // Construct the boxed operation before capturing it in the timer's
        // future. Moving nested I/O futures through each timer can exceed
        // the default JavaScript Wasm stack in unoptimized builds.
        let future = Box::pin(future);
        async move {
            match Instant::now().checked_add(duration) {
                Some(deadline) => timeout_at(deadline, future).await,
                None => Ok(future.await),
            }
        }
    }

    pub(crate) async fn timeout_at<F: Future>(
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, Elapsed> {
        tokio::pin!(future);
        tokio::select! {
            biased;
            result = &mut future => Ok(result),
            () = sleep_until(deadline) => Err(Elapsed),
        }
    }

    pub fn spawn<F>(future: F) -> oneshot::Receiver<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        spawn_local(async move {
            let _ = sender.send(future.await);
        });
        receiver
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use web::{sleep_until, timeout_at};
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web::{spawn, timeout};
