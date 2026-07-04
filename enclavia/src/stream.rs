use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::error::Error;
use crate::message::StreamHalf;
use crate::transport::OutboundCommand;

/// A bidirectional byte pipe to an upgraded connection on the workload side
/// (e.g. a WebSocket post-`101 Switching Protocols`). Constructed via
/// [`crate::Client::upgrade`].
///
/// Reads block on `StreamData` frames arriving from the workload through the
/// background transport task; server-side EOF surfaces as a zero-length read.
/// Writes are wrapped in `ClientMessage::StreamData` frames and routed back
/// through the same transport task. `poll_shutdown` half-closes the write
/// side (the workload still sees its read EOF). Dropping the stream fires a
/// best-effort `StreamClose{Both}` so the in-enclave server can release the
/// per-stream TCP connection.
#[derive(Debug)]
pub struct UpgradedStream {
    id: u64,
    cmd_tx: mpsc::Sender<OutboundCommand>,
    rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    write_closed: bool,
    closed: bool,
}

impl UpgradedStream {
    pub(crate) fn new(
        id: u64,
        cmd_tx: mpsc::Sender<OutboundCommand>,
        rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
        initial: Vec<u8>,
    ) -> Self {
        Self {
            id,
            cmd_tx,
            rx,
            read_buf: initial,
            read_pos: 0,
            eof: false,
            write_closed: false,
            closed: false,
        }
    }

    /// Stream id assigned by the in-enclave server. The SDK uses this
    /// internally to send close frames; downstream callers shouldn't need
    /// to look at it, but it's `pub(crate)` so the HTTP upgrade path in
    /// `client.rs` can keep working without re-fetching the id off the
    /// `OpenStream` reply.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Pull the next decrypted `StreamData` chunk out of the background
    /// transport task. Used by `Client::upgrade` to parse the HTTP head
    /// before handing the stream to the caller; ordinary callers should
    /// drive the stream via `AsyncRead` instead.
    pub(crate) async fn recv_chunk(&mut self) -> Option<Result<Vec<u8>, Error>> {
        self.rx.recv().await
    }

    /// Push bytes back to the front of the read buffer so the next
    /// `AsyncRead::poll_read` returns them. `Client::upgrade` uses this to
    /// hand the leftover bytes (anything past the 101 head's double-CRLF in
    /// the same packet) back to the caller without losing them.
    pub(crate) fn prepend_read(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        // The internal read buffer is consumed front-to-back via `read_pos`.
        // Splice the leftover bytes ahead of whatever's still unread, then
        // reset the cursor so the next poll_read starts at the leftover.
        let mut joined = Vec::with_capacity(bytes.len() + (self.read_buf.len() - self.read_pos));
        joined.extend_from_slice(bytes);
        joined.extend_from_slice(&self.read_buf[self.read_pos..]);
        self.read_buf = joined;
        self.read_pos = 0;
    }
}

impl AsyncRead for UpgradedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let available = self.read_buf.len() - self.read_pos;
            if available > 0 {
                let n = available.min(buf.remaining());
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if self.eof {
                // EOF: keep returning Ready(Ok(())) with zero bytes, which is
                // the AsyncRead contract for end-of-stream.
                return Poll::Ready(Ok(()));
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        // Treat as a wakeup, not EOF.
                        continue;
                    }
                    self.read_buf = chunk;
                    self.read_pos = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for UpgradedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write half closed",
            )));
        }
        // try_send is non-blocking by design. If the transport task's command
        // queue is full we report WouldBlock so the runtime backs off and
        // retries; the channel becomes ready when the task drains a slot.
        match this.cmd_tx.try_send(OutboundCommand::StreamData {
            id: this.id,
            payload: buf.to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Park the task and let the next runtime cycle retry. tokio's
                // mpsc doesn't expose a poll_ready hook for permit acquisition
                // off the futures slow path here, so we wake immediately;
                // bounded channel drain will throttle naturally.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // We don't buffer past poll_write returning Ready: each write hands the
        // payload to the transport task immediately.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        // The close frame MUST reach the transport: it is what lets the
        // in-enclave server half-close the workload connection and release
        // the stream's in-flight permit. Silently dropping it when the
        // command queue is momentarily full leaks the server-side stream
        // for the life of the session (and a session with open streams
        // never idle-times-out), so back off and retry like poll_write.
        match this.cmd_tx.try_send(OutboundCommand::StreamClose {
            id: this.id,
            half: StreamHalf::Write,
        }) {
            Ok(()) => {
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Transport gone: the whole session (and every server-side
                // stream with it) is already being torn down.
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Drop for UpgradedStream {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.cmd_tx.try_send(OutboundCommand::StreamClose {
                id: self.id,
                half: StreamHalf::Both,
            });
        }
    }
}
