//! The legacy Pageant transport, using a same-account window and shared memory.

mod window;

use std::{
    future::Future,
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::{JoinHandle, spawn_blocking},
};
use zeroize::Zeroizing;

use self::window::Target;

const HEADER: usize = size_of::<u32>();
/// Size of the shared-memory frame for one request or reply. Identity lists
/// with many keys or certificates exceed the historical 8 KiB limit.
const MAX_FRAME: usize = 64 * 1024;
type Frame = Zeroizing<Vec<u8>>;

fn frame_size(header: [u8; HEADER]) -> io::Result<usize> {
    match u32::from_be_bytes(header) as usize {
        0 => Err(no_answer()),
        length if length > MAX_FRAME - HEADER => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Pageant frame exceeds the transport limit",
        )),
        length => Ok(length + HEADER),
    }
}

fn no_answer() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Pageant did not answer")
}

/// Sequential asynchronous stream over the synchronous Windows message API.
pub(crate) struct MessageStream {
    target: Target,
    request: Frame,
    exchange: Option<JoinHandle<io::Result<Frame>>>,
    response: Option<(Frame, usize)>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
}

impl MessageStream {
    pub(crate) fn connect() -> io::Result<Self> {
        Ok(Self {
            target: Target::find()?,
            request: Zeroizing::new(Vec::with_capacity(MAX_FRAME)),
            exchange: None,
            response: None,
            reader: None,
            writer: None,
            closed: false,
        })
    }

    fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for MessageStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(exchange) = &mut self.exchange {
            let result = ready!(Pin::new(exchange).poll(cx));
            self.exchange = None;
            match result.map_err(io::Error::other).flatten() {
                Ok(response) => self.response = Some((response, 0)),
                Err(error) => {
                    self.closed = true;
                    if let Some(waker) = self.writer.take() {
                        waker.wake();
                    }
                    return Poll::Ready(Err(error));
                }
            }
        }
        if let Some((frame, offset)) = &mut self.response {
            let end = (*offset + output.remaining()).min(frame.len());
            output.put_slice(&frame[*offset..end]);
            *offset = end;
            if end == frame.len() {
                self.response = None;
                if let Some(waker) = self.writer.take() {
                    waker.wake();
                }
            }
            return Poll::Ready(Ok(()));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        self.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MessageStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.exchange.is_some() || self.response.is_some() {
            self.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let missing_header = HEADER.saturating_sub(self.request.len());
        let header_bytes = missing_header.min(data.len());
        self.request.extend_from_slice(&data[..header_bytes]);
        let Ok(header) = self.request[..self.request.len().min(HEADER)].try_into() else {
            return Poll::Ready(Ok(header_bytes));
        };
        let frame_size = match frame_size(header) {
            Ok(size) => size,
            Err(error) => {
                self.closed = true;
                self.wake_reader();
                return Poll::Ready(Err(error));
            }
        };
        let body_bytes = (frame_size - self.request.len()).min(data.len() - header_bytes);
        let total = header_bytes + body_bytes;
        self.request.extend_from_slice(&data[header_bytes..total]);
        if self.request.len() == frame_size {
            let request = mem::replace(
                &mut self.request,
                Zeroizing::new(Vec::with_capacity(MAX_FRAME)),
            );
            let target = self.target.clone();
            self.exchange = Some(spawn_blocking(move || target.query("", &request)));
            self.wake_reader();
        }
        Poll::Ready(Ok(total))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        self.wake_reader();
        if self.request.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete Pageant request",
            )))
        }
    }
}

impl Drop for MessageStream {
    fn drop(&mut self) {
        // A queued job can be cancelled. A started Windows dispatch has its own deadline.
        if let Some(exchange) = &self.exchange {
            exchange.abort();
        }
    }
}
