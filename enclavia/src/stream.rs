use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use enclavia_protocol::StreamHalf;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::error::Error;
use crate::transport::{OutboundCommand, TerminalErr};

/// Maximum payload bytes packed into a single `StreamData` frame from
/// [`UpgradedStream::poll_write`]. Matches the in-enclave server's 16 KiB
/// read chunk and stays well under the Noise transport plaintext ceiling
/// even with worst-case 2-byte-per-byte CBOR integer-array encoding.
const MAX_STREAM_WRITE_CHUNK: usize = 16 * 1024;

type ReserveFuture = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<OutboundCommand>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;

/// A bidirectional byte pipe to an upgraded connection on the workload side
/// (e.g. a WebSocket post-`101 Switching Protocols`). Constructed via
/// [`crate::Client::upgrade`].
///
/// Reads block on `StreamData` frames arriving from the workload through the
/// background transport task; server-side EOF surfaces as a zero-length read.
/// Writes are chunked to at most 16 KiB, wrapped in `ClientMessage::StreamData`
/// frames, and routed back through the same transport task using proper channel
/// permit reservation (no busy-spin). `poll_shutdown` half-closes the write
/// side (the workload still sees its read EOF). Dropping the stream fires a
/// best-effort `StreamClose{Both}` so the in-enclave server can release the
/// per-stream TCP connection.
pub struct UpgradedStream {
    id: u64,
    cmd_tx: mpsc::Sender<OutboundCommand>,
    write_reserve: Option<ReserveFuture>,
    rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
    terminal_err: TerminalErr,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    write_closed: bool,
    closed: bool,
}

impl fmt::Debug for UpgradedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradedStream")
            .field("id", &self.id)
            .field("eof", &self.eof)
            .field("write_closed", &self.write_closed)
            .field("closed", &self.closed)
            .finish()
    }
}

impl UpgradedStream {
    pub(crate) fn new(
        id: u64,
        cmd_tx: mpsc::Sender<OutboundCommand>,
        rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
        terminal_err: TerminalErr,
        initial: Vec<u8>,
    ) -> Self {
        Self {
            id,
            cmd_tx,
            write_reserve: None,
            rx,
            terminal_err,
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
        match self.rx.recv().await {
            Some(item) => Some(item),
            None => {
                if let Some(msg) = self.terminal_err.lock().unwrap().take() {
                    Some(Err(Error::ServerError {
                        id: self.id,
                        message: msg,
                    }))
                } else {
                    None
                }
            }
        }
    }

    /// Push bytes back to the front of the read buffer so the next
    /// `AsyncRead::poll_read` returns them. `Client::upgrade` uses this to
    /// hand the leftover bytes (anything past the 101 head's double-CRLF in
    /// the same packet) back to the caller without losing them.
    pub(crate) fn prepend_read(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut joined = Vec::with_capacity(bytes.len() + (self.read_buf.len() - self.read_pos));
        joined.extend_from_slice(bytes);
        joined.extend_from_slice(&self.read_buf[self.read_pos..]);
        self.read_buf = joined;
        self.read_pos = 0;
    }

    /// Poll for a send permit on `cmd_tx` without busy-spinning.
    fn poll_permit(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<mpsc::OwnedPermit<OutboundCommand>, ()>> {
        if self.write_reserve.is_none() {
            match self.cmd_tx.clone().try_reserve_owned() {
                Ok(permit) => return Poll::Ready(Ok(permit)),
                Err(mpsc::error::TrySendError::Closed(_)) => return Poll::Ready(Err(())),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.write_reserve = Some(Box::pin(self.cmd_tx.clone().reserve_owned()));
                }
            }
        }
        let fut = self.write_reserve.as_mut().expect("reserve future set");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                self.write_reserve = None;
                Poll::Ready(Ok(permit))
            }
            Poll::Ready(Err(_)) => {
                self.write_reserve = None;
                Poll::Ready(Err(()))
            }
        }
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
                    // Consume any duplicate terminal error recorded alongside
                    // this explicit error item.
                    let _ = self.terminal_err.lock().unwrap().take();
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => {
                    // Check the out-of-band terminal error slot: if the
                    // transport died while our 64-slot buffer was full, we
                    // must surface that error instead of silent EOF.
                    let term = self.terminal_err.lock().unwrap().take();
                    self.eof = true;
                    if let Some(msg) = term {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            msg,
                        )));
                    }
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(MAX_STREAM_WRITE_CHUNK);
        match this.poll_permit(cx) {
            Poll::Ready(Ok(permit)) => {
                permit.send(OutboundCommand::StreamData {
                    id: this.id,
                    payload: buf[..chunk_len].to_vec(),
                });
                Poll::Ready(Ok(chunk_len))
            }
            Poll::Ready(Err(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        match this.poll_permit(cx) {
            Poll::Ready(Ok(permit)) => {
                permit.send(OutboundCommand::StreamClose {
                    id: this.id,
                    half: StreamHalf::Write,
                });
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(())) => {
                // Transport gone: the whole session (and every server-side
                // stream with it) is already being torn down.
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn poll_write_chunks_large_buffers_to_16_kib() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let (_tx, rx) = mpsc::channel(4);
        let terminal_err = Arc::new(StdMutex::new(None));
        let mut stream = UpgradedStream::new(7, cmd_tx, rx, terminal_err, Vec::new());

        let big = vec![0xab; 40 * 1024];
        stream.write_all(&big).await.expect("write_all");

        let mut reassembled = Vec::new();
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                OutboundCommand::StreamData { id, payload } => {
                    assert_eq!(id, 7);
                    assert!(
                        payload.len() <= MAX_STREAM_WRITE_CHUNK,
                        "chunk len {} exceeded 16 KiB",
                        payload.len()
                    );
                    reassembled.extend_from_slice(&payload);
                }
                other => panic!("unexpected command: {other:?}"),
            }
        }
        assert_eq!(reassembled, big);
    }

    #[tokio::test]
    async fn full_receive_channel_on_transport_drop_surfaces_error_not_silent_eof() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let (tx, rx) = mpsc::channel(1);
        let terminal_err = Arc::new(StdMutex::new(None));
        let mut stream = UpgradedStream::new(9, cmd_tx, rx, Arc::clone(&terminal_err), Vec::new());

        // Fill the 1-slot buffer, then simulate transport teardown setting
        // `terminal_err` and dropping `tx` (try_send on the full channel fails).
        tx.try_send(Ok(b"partial".to_vec())).unwrap();
        *terminal_err.lock().unwrap() = Some(Error::ConnectionClosed.to_string());
        let _ = tx.try_send(Err(Error::ConnectionClosed)); // fails because full!
        drop(tx);

        // First read delivers the buffered bytes; next read MUST return an
        // error, NOT clean EOF!
        let mut first = [0u8; 16];
        let n = stream.read(&mut first).await.expect("buffered bytes");
        assert_eq!(&first[..n], b"partial");

        let err = stream
            .read(&mut first)
            .await
            .expect_err("must surface transport drop error, not silent EOF");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }
}
