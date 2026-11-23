//! Local named pipe transport supported by Pageant since PuTTY 0.75.

use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    io::{self, IoSlice},
    os::windows::io::AsRawHandle,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time::{Duration, Instant, sleep_until},
};
use windows::Win32::{
    Foundation::{ERROR_PIPE_BUSY, HANDLE},
    Security::Cryptography::{
        CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_CROSS_PROCESS, CryptProtectMemory,
    },
    Storage::FileSystem::SECURITY_IDENTIFICATION,
};

use crate::windows_account;

const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Direct connection to a Pageant instance running under the current account.
pub(crate) struct PipeStream(NamedPipeClient);

impl PipeStream {
    pub(crate) async fn connect() -> io::Result<Self> {
        let mut path = OsString::from(r"\\.\pipe\pageant.");
        path.push(windows_account::name()?);
        path.push(".");
        path.push(pipe_suffix());
        let stream = open(path, BUSY_TIMEOUT).await?;
        windows_account::check_pipe_owner(
            HANDLE(stream.as_raw_handle()),
            windows_account::PipeOwner::CurrentUser,
        )?;
        Ok(Self(stream))
    }
}

fn pipe_suffix() -> String {
    // PuTTY hashes a length-prefixed, CAPI-obfuscated, null-padded label.
    const BLOCK_BYTES: usize = CRYPTPROTECTMEMORY_BLOCK_SIZE as usize;
    let mut plain = [0; BLOCK_BYTES];
    plain[..7].copy_from_slice(b"Pageant");
    let mut protected = plain;
    // SAFETY: The initialized writable buffer has one full CAPI block.
    let result = unsafe {
        CryptProtectMemory(
            protected.as_mut_ptr().cast(),
            CRYPTPROTECTMEMORY_BLOCK_SIZE,
            CRYPTPROTECTMEMORY_CROSS_PROCESS,
        )
    };
    let mut hash = Sha256::new();
    hash.update(CRYPTPROTECTMEMORY_BLOCK_SIZE.to_be_bytes());
    hash.update(if result.is_ok() { protected } else { plain });
    crate::encode_hex(&hash.finalize())
}

async fn open(path: OsString, busy_timeout: Duration) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + busy_timeout;
    let mut options = ClientOptions::new();
    options.security_qos_flags(SECURITY_IDENTIFICATION.0);
    loop {
        match options.open(&path) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(crate::not_running());
            }
            Err(error) => return Err(error),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Pageant named pipe stayed busy",
            ));
        }
        sleep_until((now + RETRY_INTERVAL).min(deadline)).await;
    }
}

impl AsyncRead for PipeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ServerOptions;

    #[tokio::test(start_paused = true)]
    async fn busy_pipe_is_bounded_and_missing_pipe_is_reported() {
        let path = OsString::from(format!(
            r"\\.\pipe\thirtyssh-pageant-test-{}",
            std::process::id()
        ));
        let wait = Duration::from_millis(130);
        let missing = open(path.clone(), wait).await.unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .create(&path)
            .unwrap();
        let stream = open(path.clone(), wait).await.unwrap();
        server.connect().await.unwrap();
        let start = Instant::now();
        let busy = open(path, wait).await.unwrap_err();
        assert_eq!(busy.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), wait);
        drop(stream);
    }
}
