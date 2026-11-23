//! Client streams to the PuTTY Pageant SSH agent on Windows.
//!
//! `Pageant` is a byte stream that carries the SSH agent protocol to the
//! Pageant instance of the current Windows account.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(windows, feature = "window-message"))]
mod message;
#[cfg(all(windows, feature = "named-pipe"))]
mod pipe;
#[cfg(windows)]
mod stream;
#[cfg(all(windows, any(feature = "named-pipe", feature = "window-message")))]
mod windows_account;

#[cfg(windows)]
pub use stream::{Pageant, Transport};

/// Check that a connected named pipe belongs to an SSH agent the current
/// account can trust: one owned by this account, or by the system, as the
/// pipe of an agent running as a Windows service is. Call it before sending
/// anything, so that a pipe another account created under a well-known name
/// receives no keys or signing requests.
#[cfg(all(windows, feature = "named-pipe"))]
pub fn check_agent_pipe_owner(
    pipe: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<()> {
    windows_account::check_pipe_owner(
        windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()),
        windows_account::PipeOwner::CurrentUserOrSystem,
    )
}

/// No Pageant instance was found for the current account.
#[cfg(windows)]
pub(crate) fn not_running() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, "Pageant is not running")
}

#[cfg(all(windows, any(feature = "named-pipe", feature = "window-message")))]
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
