//! Id-correlated request/response RPC over an attested mesh channel.
//!
//! Each directed connection is owned by its dialer (see [`super`]): on the
//! A->B connection, A is the RPC *client* (it issues requests and reads
//! responses) and B is the RPC *server* (it reads requests, dispatches them to
//! its handler, and writes responses). For B to call A, B dials A on its own
//! connection. So a node's outbound side ([`ClientChannel`]) drives
//! [`super::Mesh::call`], and its inbound side ([`serve`]) feeds the node's
//! request handler.
//!
//! ## Envelope + correlation
//!
//! Every RPC message is a length-prefixed CBOR [`Envelope`] carried inside a
//! [`super::handshake::MeshFrame::Rpc`]. A request carries a monotonically
//! increasing `id`; the matching response echoes it, so the client can have
//! many requests in flight on one connection and route each response back to
//! the right awaiting caller via the `id`. The `body` is an opaque
//! [`MeshPayload`] (CBOR bytes today; slice 3 defines the Raft message set on
//! top without changing this layer).
//!
//! ## One driver, one reader, many callers
//!
//! A client connection is split (see [`spawn_client`]) into a dedicated reader
//! task that only pulls whole ciphertext frames off the wire, and a driver
//! task that owns the single stateful Noise transport and `select!`s over
//! outbound envelopes (encrypt + write) and inbound ciphertext (decrypt +
//! demux). Concurrent [`super::Mesh::call`]s from different tasks enqueue onto
//! one mpsc queue the driver drains, so their frames serialise cleanly without
//! a write lock on the stream; responses are demultiplexed to per-id oneshot
//! channels held in a shared pending-map. Splitting the reader off the driver
//! keeps the driver's `select!` cancel-safe: it only ever awaits cancel-safe
//! channel `recv()`s, never a partially-read length-prefixed frame.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::mesh::handshake::{
    HandshakeError, MeshFrame, decrypt_frame, read_ciphertext_frame, read_frame, write_frame,
};

/// Opaque application payload carried in an [`Envelope`]. CBOR bytes for now;
/// the Raft layer (slice 3) defines the message set encoded inside without
/// touching this transport. Modelled as a newtype over `Vec<u8>` so the API
/// is self-documenting and slice 3 can swap the inner encoding freely.
pub type MeshPayload = Vec<u8>;

/// One RPC envelope on the wire: a request or its correlated response.
///
/// CBOR-encoded inside a [`MeshFrame::Rpc`]. The `id` correlates a response to
/// its request; it is unique per client connection (a monotonic counter).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Envelope {
    /// A request from the client side, awaiting a [`Envelope::Response`] with
    /// the same `id`.
    Request {
        /// Per-connection correlation id.
        id: u64,
        /// Opaque request payload.
        body: MeshPayload,
    },
    /// The response to the request with the matching `id`.
    Response {
        /// Correlation id echoed from the request.
        id: u64,
        /// Opaque response payload.
        body: MeshPayload,
    },
}

/// Errors surfaced by an RPC call on a [`ClientChannel`].
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// The connection's writer or reader task is gone (the connection
    /// dropped). The caller (the mesh, then Raft) retries on reconnect.
    #[error("rpc connection closed")]
    ConnectionClosed,
    /// CBOR encode of the request envelope failed (should not happen for
    /// well-formed payloads).
    #[error("cbor encode: {0}")]
    Encode(String),
}

/// Inbound-request handler hook. The node implements this to serve requests
/// that arrive on its accept side; the handler returns the response body.
///
/// Object-safe so the mesh can hold a `dyn RequestHandler`. The Raft layer
/// (slice 3) supplies one that decodes the `body` as a Raft message, drives
/// the consensus state machine, and encodes the reply.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle one request from `from` (the source peer's logical name) and
    /// return the response body.
    async fn handle(&self, from: &str, body: MeshPayload) -> MeshPayload;
}

/// A no-op handler that echoes the request body back. Used as the default
/// before slice 3 wires Raft in, and as the server side of the request/
/// response tests.
#[derive(Clone, Copy, Default)]
pub struct EchoHandler;

#[async_trait::async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(&self, _from: &str, body: MeshPayload) -> MeshPayload {
        body
    }
}

/// Shared map of in-flight request ids to the oneshot that delivers their
/// response.
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<MeshPayload>>>>;

/// The client face of one directed connection: issue requests and await
/// correlated responses.
///
/// Created by [`ClientChannel::spawn`], which starts the reader and writer
/// tasks over the connection's Noise transport. Clone-cheap (it is just the
/// shared queue + counter + pending-map), so multiple caller tasks can issue
/// concurrent [`ClientChannel::call`]s on the same connection.
#[derive(Clone)]
pub struct ClientChannel {
    next_id: Arc<AtomicU64>,
    outbound: mpsc::Sender<Envelope>,
    pending: Pending,
}

impl ClientChannel {
    /// Issue one request and await its correlated response.
    ///
    /// Allocates a fresh id, registers a oneshot for it, enqueues the request
    /// for the writer task, and awaits the reader task delivering the matching
    /// response. Returns [`RpcError::ConnectionClosed`] if the connection
    /// drops before the response arrives.
    pub async fn call(&self, body: MeshPayload) -> Result<MeshPayload, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        if self
            .outbound
            .send(Envelope::Request { id, body })
            .await
            .is_err()
        {
            self.pending.lock().await.remove(&id);
            return Err(RpcError::ConnectionClosed);
        }
        rx.await.map_err(|_| RpcError::ConnectionClosed)
    }
}

/// Run the client side of one directed connection until it drops.
///
/// ## Cancel-safety: dedicated reader task, never a `select!` over a read
///
/// The connection's byte stream is split with [`tokio::io::split`] into a read
/// half and a write half. A dedicated **reader task** owns the read half and
/// does nothing but pull complete length-prefixed CIPHERTEXT frames off the
/// wire ([`read_ciphertext_frame`]) and forward each over an mpsc channel.
/// Because it never `select!`s, it is never cancelled mid-frame, so a
/// partially-read length-prefixed body can never be lost.
///
/// The **driver task** owns the single stateful
/// [`NoiseTransport`](enclavia_protocol::NoiseTransport) and `select!`s over
/// two cancel-safe sources: outbound envelopes from the
/// [`ClientChannel`]'s queue (encrypt + write via the write half) and complete
/// inbound ciphertext frames from the reader's channel (decrypt via
/// [`decrypt_frame`], demux to the pending oneshots by id). Both `recv()`s are
/// cancel-safe (an mpsc/`recv` that loses the race simply has not consumed its
/// item), so the `select!` is sound. Encryption and decryption both need
/// `&mut transport`, which is fine because both happen on this one driver task;
/// the reader task never touches the transport.
///
/// This is the fix for the slice-2 cancel-safety bug: the previous single-task
/// loop recreated a `read_frame` future every iteration, and `read_frame`
/// reads a 4-byte prefix then the body, so it is not cancel-safe. When the
/// outbound branch won the race after the prefix had been read, the read future
/// was dropped mid-frame; the next iteration wrote a request and then resumed
/// reading from the middle of the stale body, Noise decrypt failed, and the
/// connection dropped. Under concurrent calls (exactly Raft's heartbeat +
/// append pattern) this caused spurious drops.
///
/// Returns the [`ClientChannel`] handle and a future that resolves when the
/// connection ends (peer closed, reader errored, or queue closed). The caller
/// (the mesh dial loop) drives the future and reconnects when it resolves; it
/// also aborts the reader task on the way out so a half-open stream does not
/// leak a task.
pub fn spawn_client<S>(
    stream: S,
    mut transport: enclavia_protocol::NoiseTransport,
) -> (
    ClientChannel,
    impl std::future::Future<Output = Result<(), HandshakeError>>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Envelope>(1024);
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let channel = ClientChannel {
        next_id: Arc::new(AtomicU64::new(0)),
        outbound: outbound_tx,
        pending: Arc::clone(&pending),
    };

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // Reader task: owns the read half exclusively, reads whole ciphertext
    // frames, forwards each over `inbound_tx`. No `select!`, so no cancellation
    // mid-frame. A bounded channel back-pressures the wire if the driver is
    // slow. Forwarding `Ok(None)` would need a sentinel; instead we just close
    // `inbound_tx` (drop) on EOF, which the driver reads as a clean close.
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let reader = tokio::spawn(async move {
        loop {
            match read_ciphertext_frame(&mut read_half).await {
                Ok(Some(ciphertext)) => {
                    if inbound_tx.send(ciphertext).await.is_err() {
                        return; // driver gone
                    }
                }
                // Clean EOF or read error: drop `inbound_tx` so the driver's
                // `recv()` returns `None` and the connection winds down.
                _ => return,
            }
        }
    });

    let driver = async move {
        // Abort the reader when the driver returns, so a peer that stops
        // sending but keeps the stream open does not leak the reader task.
        let _reader_guard = AbortOnDrop(reader);
        loop {
            tokio::select! {
                maybe_req = outbound_rx.recv() => {
                    match maybe_req {
                        Some(env) => {
                            let mut buf = Vec::new();
                            ciborium::into_writer(&env, &mut buf)
                                .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
                            write_frame(&mut write_half, &mut transport, &MeshFrame::Rpc { envelope: buf }).await?;
                        }
                        // All ClientChannel clones dropped: shut down.
                        None => return Ok(()),
                    }
                }
                maybe_ct = inbound_rx.recv() => {
                    match maybe_ct {
                        Some(ciphertext) => {
                            match decrypt_frame(&mut transport, &ciphertext)? {
                                MeshFrame::Rpc { envelope } => {
                                    let env: Envelope = ciborium::from_reader(&envelope[..])
                                        .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
                                    if let Envelope::Response { id, body } = env {
                                        if let Some(tx) = pending.lock().await.remove(&id) {
                                            let _ = tx.send(body);
                                        }
                                        // An unmatched response id is ignored (the
                                        // caller may have given up). A stray Request on
                                        // the client side is a protocol error we also
                                        // ignore: the client connection only serves
                                        // responses.
                                    }
                                }
                                // Non-Rpc frame post-handshake is a protocol violation;
                                // drop the connection so the dialer reconnects.
                                _ => return Err(HandshakeError::NotAuthenticate),
                            }
                        }
                        // Reader task ended (peer closed or read error).
                        None => return Ok(()),
                    }
                }
            }
        }
    };

    (channel, driver)
}

/// Aborts the wrapped task handle when dropped. Used to tear down
/// [`spawn_client`]'s reader task when its driver returns.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve the inbound (accept) side of one directed connection: read requests,
/// dispatch to `handler`, and write back correlated responses, until the peer
/// closes.
///
/// `from` is the source peer's logical name (learned from the dialer's
/// `Hello`), passed to the handler so it can attribute the request. Requests
/// are handled one at a time per connection (the synchronizer's throughput is
/// low and Raft is happy with in-order per-link delivery); concurrent load is
/// spread across the per-peer connections, not pipelined within one.
///
/// ## Cancel-safety
///
/// Unlike [`spawn_client`], this loop is strictly sequential: read one
/// request, handle it, write the response, repeat. There is no `select!`, so
/// the non-cancel-safe [`read_frame`] is used directly and is never dropped
/// mid-frame, the only `.await` between two reads is the handler + write, both
/// of which run to completion. The split-reader machinery is therefore
/// unnecessary here, so it is deliberately not applied.
pub async fn serve<S, H>(
    mut stream: S,
    mut transport: enclavia_protocol::NoiseTransport,
    from: &str,
    handler: &H,
) -> Result<(), HandshakeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    H: RequestHandler + ?Sized,
{
    loop {
        match read_frame(&mut stream, &mut transport).await? {
            Some(MeshFrame::Rpc { envelope }) => {
                let env: Envelope = ciborium::from_reader(&envelope[..])
                    .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
                match env {
                    Envelope::Request { id, body } => {
                        let resp_body = handler.handle(from, body).await;
                        let mut buf = Vec::new();
                        ciborium::into_writer(
                            &Envelope::Response {
                                id,
                                body: resp_body,
                            },
                            &mut buf,
                        )
                        .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
                        write_frame(
                            &mut stream,
                            &mut transport,
                            &MeshFrame::Rpc { envelope: buf },
                        )
                        .await?;
                    }
                    // The server side never receives a Response: a peer that
                    // sends one on its dialed connection is misbehaving. Drop.
                    Envelope::Response { .. } => return Err(HandshakeError::NotAuthenticate),
                }
            }
            Some(_) => return Err(HandshakeError::NotAuthenticate),
            None => return Ok(()), // peer closed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrips() {
        for env in [
            Envelope::Request {
                id: 7,
                body: b"req".to_vec(),
            },
            Envelope::Response {
                id: 7,
                body: b"resp".to_vec(),
            },
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&env, &mut buf).unwrap();
            let decoded: Envelope = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(env, decoded);
        }
    }

    // --- cancel-safety regression (A2) --------------------------------
    //
    // The old single-task `select!` recreated a non-cancel-safe `read_frame`
    // future every iteration; an outbound write winning the race after the
    // length prefix had been read dropped the read mid-frame and desynced the
    // Noise transport. The split reader fixes it. This test reproduces the
    // race deterministically by fragmenting every read AND write into 1-7
    // byte pieces with a yield between pieces, then firing many concurrent
    // `call`s; if the driver ever resumed a read from the middle of a stale
    // frame, Noise decrypt would fail and the calls would error / hang.

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// Wraps a byte stream and lets only 1-7 bytes through per read/write
    /// poll, returning `Poll::Pending` (after waking) on the polls in between
    /// so the runtime reschedules and the driver's `select!` arms interleave.
    /// This maximises the number of points at which an outbound write can race
    /// a partially-read inbound frame, which is exactly the condition that
    /// desynced the pre-fix loop.
    struct Fragmenting<S> {
        inner: S,
        /// Cycles 1..=7 to vary the fragment size deterministically.
        step: usize,
        /// When true, the next poll yields (Pending + wake) instead of doing
        /// I/O, forcing a reschedule.
        stall: bool,
    }

    impl<S> Fragmenting<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                step: 1,
                stall: false,
            }
        }

        /// Advance the fragment size and decide whether the next poll stalls.
        fn bump(&mut self) -> usize {
            let n = self.step;
            self.step = if self.step >= 7 { 1 } else { self.step + 1 };
            self.stall = !self.stall;
            n
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Fragmenting<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.stall {
                self.stall = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let cap = self.bump().min(buf.remaining()).max(1);
            // Read into a tiny scratch buffer so we never hand the inner
            // stream more than `cap` bytes of room.
            let mut scratch = [0u8; 7];
            let mut small = ReadBuf::new(&mut scratch[..cap]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut small) {
                Poll::Ready(Ok(())) => {
                    buf.put_slice(small.filled());
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmenting<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stall {
                self.stall = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let cap = self.bump().min(data.len()).max(1);
            Pin::new(&mut self.inner).poll_write(cx, &data[..cap])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Build a connected pair of Noise transports, then wrap each post-
    /// handshake stream half in [`Fragmenting`], returning the two halves'
    /// (stream, transport) so the test can run `spawn_client` on one and
    /// `serve` on the other.
    ///
    /// The handshake itself runs on the PLAIN duplex: `perform_handshake_as_*`
    /// read each raw (non-length-prefixed) Noise message with a single
    /// `read()` and assume the whole message arrives at once, so fragmenting
    /// the handshake would corrupt it. The strict ping-pong handshake leaves
    /// no buffered leftover, so wrapping only afterward is sound, and the
    /// length-prefixed transport framing (the code under test) is what gets
    /// fragmented.
    async fn fragmented_noise_pair() -> (
        (
            Fragmenting<tokio::io::DuplexStream>,
            enclavia_protocol::NoiseTransport,
        ),
        (
            Fragmenting<tokio::io::DuplexStream>,
            enclavia_protocol::NoiseTransport,
        ),
    ) {
        use enclavia_protocol::{perform_handshake_as_initiator, perform_handshake_as_responder};
        let (mut a, mut b) = tokio::io::duplex(256 * 1024);
        let ta = tokio::spawn(async move {
            let (t, _h) = perform_handshake_as_initiator(&mut a).await.unwrap();
            (Fragmenting::new(a), t)
        });
        let tb = tokio::spawn(async move {
            let (t, _h) = perform_handshake_as_responder(&mut b).await.unwrap();
            (Fragmenting::new(b), t)
        });
        (ta.await.unwrap(), tb.await.unwrap())
    }

    /// Many concurrent `call`s over a transport that fragments every read and
    /// write into 1-7 byte pieces with stalls between them. All calls must
    /// complete with their own correlated response and the connection must
    /// never desync. With the pre-fix single-task loop this hangs / errors
    /// once an outbound write interrupts a partially-read response frame.
    #[tokio::test]
    async fn concurrent_calls_over_fragmented_stream_never_desync() {
        let ((client_stream, client_transport), (server_stream, server_transport)) =
            fragmented_noise_pair().await;

        // Server side: echo every request body back, one at a time.
        let server = tokio::spawn(async move {
            let _ = serve(server_stream, server_transport, "peer", &EchoHandler).await;
        });

        let (channel, driver) = spawn_client(client_stream, client_transport);
        let driver = tokio::spawn(driver);

        // Many concurrent caller tasks, each doing a long run of sequential
        // calls, so thousands of frames cross the wire while the outbound
        // queue is continuously non-empty. The pre-fix loop's `select!`
        // randomises arm order, so a single round rarely hits the bad
        // ordering (outbound winning the race after the inbound prefix was
        // read); driving thousands of frames makes hitting it at least once
        // overwhelmingly likely, which is what discriminates the fix from the
        // bug. Bodies vary in size so frames span several 1-7 byte fragments
        // and the mid-frame cancellation window is wide.
        const TASKS: u32 = 16;
        const ROUNDS: u32 = 80;
        let mut handles = Vec::new();
        for t in 0..TASKS {
            let ch = channel.clone();
            handles.push(tokio::spawn(async move {
                for r in 0..ROUNDS {
                    let seed = t.wrapping_mul(7).wrapping_add(r);
                    let len = (seed as usize % 200) + 1;
                    let body = vec![(seed & 0xff) as u8; len];
                    let resp = ch.call(body.clone()).await.expect("call must complete");
                    assert_eq!(resp, body, "echoed body mismatch (task {t}, round {r})");
                }
            }));
        }
        // A generous timeout: if the connection desyncs, the affected calls
        // never resolve (Noise decrypt fails, the driver returns, every
        // pending oneshot drops, and `call` errors, or the response never
        // arrives at all).
        let all = async {
            for h in handles {
                h.await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), all)
            .await
            .expect("all concurrent calls completed before timeout");

        // Closing the channel ends the driver; the server then sees EOF.
        drop(channel);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), driver).await;
        server.abort();
    }
}
