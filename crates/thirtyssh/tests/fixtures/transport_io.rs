use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum ReadState {
    Open,
    Paused(Option<Waker>),
    Reset,
}

#[derive(Clone)]
pub struct ReadControl(Arc<Mutex<ReadState>>);

impl ReadControl {
    pub fn pause(&self) {
        self.set(ReadState::Paused(None));
    }

    pub fn resume(&self) {
        self.set(ReadState::Open);
    }

    pub fn reset(&self) {
        self.set(ReadState::Reset);
    }

    fn set(&self, new: ReadState) {
        let previous = std::mem::replace(&mut *self.0.lock().unwrap(), new);
        if let ReadState::Paused(Some(waker)) = previous {
            waker.wake();
        }
    }
}

pub struct ControlledRead<S> {
    inner: S,
    control: ReadControl,
}

impl<S> ControlledRead<S> {
    pub fn new(inner: S) -> (Self, ReadControl) {
        let control = ReadControl(Arc::new(Mutex::new(ReadState::Open)));
        let stream = Self {
            inner,
            control: control.clone(),
        };
        (stream, control)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ControlledRead<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        match &mut *stream.control.0.lock().unwrap() {
            ReadState::Open => {}
            ReadState::Paused(waiter) => {
                *waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
            ReadState::Reset => {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
        }
        Pin::new(&mut stream.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ControlledRead<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
