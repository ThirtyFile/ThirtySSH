use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How a stream reaches Pageant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transport {
    /// The named pipe Pageant has offered since PuTTY 0.75.
    #[cfg(feature = "named-pipe")]
    NamedPipe,
    /// Window messages with shared memory, which every Pageant version
    /// understands.
    #[cfg(feature = "window-message")]
    WindowMessage,
}

impl Transport {
    /// The enabled transports, in the order [`Pageant::connect`] tries them.
    pub const ALL: &[Self] = &[
        #[cfg(feature = "named-pipe")]
        Self::NamedPipe,
        #[cfg(feature = "window-message")]
        Self::WindowMessage,
    ];
}

/// An SSH agent byte stream to the current account's Pageant.
pub struct Pageant(Inner);

enum Inner {
    #[cfg(feature = "named-pipe")]
    Pipe(crate::pipe::PipeStream),
    #[cfg(feature = "window-message")]
    Message(crate::message::MessageStream),
}

trait Io: AsyncRead + AsyncWrite + Unpin {}
impl<S: AsyncRead + AsyncWrite + Unpin> Io for S {}

impl Pageant {
    /// Connect over the first transport that reaches Pageant.
    ///
    /// The error is `NotFound` when Pageant is not running. When a transport
    /// found Pageant and then failed, that failure is returned instead.
    pub async fn connect() -> io::Result<Self> {
        let mut failure = None;
        for &transport in Transport::ALL {
            match Self::connect_over(transport).await {
                Ok(stream) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => failure = failure.or(Some(error)),
            }
        }
        Err(failure.unwrap_or_else(crate::not_running))
    }

    /// Connect over one chosen transport.
    pub async fn connect_over(transport: Transport) -> io::Result<Self> {
        Ok(Self(match transport {
            #[cfg(feature = "named-pipe")]
            Transport::NamedPipe => Inner::Pipe(crate::pipe::PipeStream::connect().await?),
            #[cfg(feature = "window-message")]
            Transport::WindowMessage => Inner::Message(crate::message::MessageStream::connect()?),
        }))
    }

    /// The transport this stream uses.
    pub fn transport(&self) -> Transport {
        match self.0 {
            #[cfg(feature = "named-pipe")]
            Inner::Pipe(_) => Transport::NamedPipe,
            #[cfg(feature = "window-message")]
            Inner::Message(_) => Transport::WindowMessage,
        }
    }

    fn io(&mut self) -> Pin<&mut dyn Io> {
        match self.0 {
            #[cfg(feature = "named-pipe")]
            Inner::Pipe(ref mut stream) => Pin::new(stream),
            #[cfg(feature = "window-message")]
            Inner::Message(ref mut stream) => Pin::new(stream),
        }
    }
}

impl AsyncRead for Pageant {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.io().poll_read(cx, buffer)
    }
}

impl AsyncWrite for Pageant {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io().poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_shutdown(cx)
    }
}
