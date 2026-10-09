//! Closing a connection from outside its SSH session loop.
//!
//! russh offers no way to force a connection shut: `Handle::disconnect`
//! goes through the same bounded queue as channel data, which the session
//! loop stops draining while a channel is window-blocked, and after a
//! DISCONNECT the loop waits for the client to close its side, which a
//! misbehaving client never does. So every TCP stream is wrapped in a
//! `Cuttable` before russh sees it, and whoever holds the matching `Cut`
//! can end the connection: the next read or write fails, the session loop
//! returns, and the stream is dropped with everything that depended on it.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Cuts the connection it was created with. Clones share the connection;
/// cutting is idempotent and harmless once the stream is gone.
#[derive(Clone, Debug, Default)]
pub struct Cut(Arc<State>);

#[derive(Debug, Default)]
struct State {
    cut: AtomicBool,
    /// Wakers of the pending read and write, so a loop parked in either
    /// notices the cut at once.
    wakers: Mutex<[Option<Waker>; 2]>,
}

const READ: usize = 0;
const WRITE: usize = 1;

impl Cut {
    /// A cut for nothing in particular; `cut` then has no effect.
    pub fn new() -> Cut {
        Cut::default()
    }

    /// Ends the connection now.
    pub fn cut(&self) {
        if self.0.cut.swap(true, Ordering::SeqCst) {
            return;
        }
        let wakers =
            std::mem::take(&mut *self.0.wakers.lock().unwrap_or_else(PoisonError::into_inner));
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    /// Ends the connection after `after` unless it is gone by then.
    pub fn cut_after(&self, after: Duration) {
        let cut = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            cut.cut();
        });
    }

    pub fn is_cut(&self) -> bool {
        self.0.cut.load(Ordering::SeqCst)
    }

    /// Remembers the poller, then reports whether the connection is cut.
    /// Registering first means a cut between the check and the park still
    /// wakes the poller.
    fn arm(&self, slot: usize, cx: &Context<'_>) -> bool {
        {
            let mut wakers = self.0.wakers.lock().unwrap_or_else(PoisonError::into_inner);
            match &mut wakers[slot] {
                Some(w) if w.will_wake(cx.waker()) => {}
                w => *w = Some(cx.waker().clone()),
            }
        }
        self.is_cut()
    }
}

fn cut_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection cut by the server",
    )
}

/// A stream that fails once its `Cut` is pulled.
pub struct Cuttable<S> {
    inner: S,
    cut: Cut,
}

impl<S> Cuttable<S> {
    pub fn new(inner: S) -> (Cuttable<S>, Cut) {
        let cut = Cut::new();
        (
            Cuttable {
                inner,
                cut: cut.clone(),
            },
            cut,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Cuttable<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cut.arm(READ, cx) {
            return Poll::Ready(Err(cut_error()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Cuttable<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.cut.arm(WRITE, cx) {
            return Poll::Ready(Err(cut_error()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cut.arm(WRITE, cx) {
            return Poll::Ready(Err(cut_error()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutting down is always allowed; it is where a cut connection
        // ends up anyway.
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_parked_read_fails_as_soon_as_the_connection_is_cut() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let (mut stream, cut) = Cuttable::new(ours);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            stream.read(&mut buf).await
        });
        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "nothing to read yet: the read waits");
        cut.cut();
        let result = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("the read was woken by the cut")
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert!(cut.is_cut());
    }

    #[tokio::test]
    async fn writes_fail_after_a_cut_and_cutting_twice_is_fine() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let (mut stream, cut) = Cuttable::new(ours);
        stream.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        theirs.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        cut.cut();
        cut.cut();
        assert!(stream.write_all(b"more").await.is_err());
        assert!(stream.flush().await.is_err());
        assert!(stream.shutdown().await.is_ok(), "shutdown still works");
    }

    #[tokio::test(start_paused = true)]
    async fn cut_after_waits_and_a_default_cut_is_harmless() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let (_stream, cut) = Cuttable::new(ours);
        cut.cut_after(Duration::from_secs(10));
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!cut.is_cut());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cut.is_cut());
        let lone = Cut::new();
        lone.cut();
        assert!(lone.is_cut());
    }
}
