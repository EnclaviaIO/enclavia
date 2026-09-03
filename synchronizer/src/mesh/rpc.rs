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
//! ## Channel-attributed handler identity ([`PeerContext`])
//!
//! [`serve`] passes the request handler a [`PeerContext`], not just the peer's
//! name: it carries the peer's attested per-boot instance pubkey and PCR digest
//! from the mutual-attestation handshake alongside its `Hello` routing name.
//! This is what fulfils the #209 membership SECURITY CONTRACT: the join handler
//! reads a candidate's instance pubkey from the ATTESTED CHANNEL here, never
//! from a request payload field (which the host could forge), so a clone cannot
//! claim another instance's voting identity. Earlier slices only handed the
//! handler the routing name; the pubkey + digest were verified during the
//! handshake and then discarded.
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
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::mesh::handshake::{
    HandshakeError, MeshFrame, decrypt_frame, read_ciphertext_frame, read_frame, with_deadline,
    write_frame,
};

/// How long an established client channel may sit with NO inbound frame before
/// the driver sends a [`MeshFrame::Ping`].
///
/// Only inbound traffic resets this: bytes we WRITE prove nothing about the
/// peer. On a healthy but idle mesh this costs one tiny frame per peer per
/// interval, which is nothing next to Raft's own heartbeat traffic.
pub const IDLE_BEFORE_PING: Duration = Duration::from_secs(5);

/// How long the driver waits for the [`MeshFrame::Pong`] (or any other inbound
/// frame) answering its ping before declaring the channel dead and returning,
/// which drops the [`ClientChannel`] and makes the dial loop reconnect.
///
/// This is the fix for a dead-but-OPEN connection: a half-open stream (peer
/// enclave gone, relay wedged) never yields EOF, so before this the reader task
/// simply blocked in `read_exact` forever and the dial loop never got its
/// connection back to re-dial (#b-2026-09-02, 21 h wedged).
pub const PONG_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the SERVE (accept) side tolerates a connection with no inbound
/// frame before dropping it.
///
/// Comfortably above [`IDLE_BEFORE_PING`] + [`PONG_TIMEOUT`]: a live client
/// pings whenever it has nothing else to say, so silence for this long means
/// the dialer is gone and the serve task would otherwise leak, parked in
/// `read_exact` on a half-open stream, still holding a peer slot.
pub const SERVE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
        /// Opaque request payload, carried as a CBOR byte string (see the
        /// rationale on [`MeshFrame::Rpc`]'s `envelope`).
        #[serde(with = "serde_bytes")]
        body: MeshPayload,
    },
    /// The response to the request with the matching `id`.
    Response {
        /// Correlation id echoed from the request.
        id: u64,
        /// Opaque response payload, carried as a CBOR byte string (see the
        /// rationale on [`MeshFrame::Rpc`]'s `envelope`).
        #[serde(with = "serde_bytes")]
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

/// The channel-attributed identity of the peer whose request is being served.
///
/// Built by the accept loop from the mutual-attestation handshake's
/// [`PeerIdentity`](crate::mesh::handshake::PeerIdentity) plus the dialer's
/// `Hello` name, and threaded to the [`RequestHandler`] on every inbound
/// request. This is what fulfils the #209 membership SECURITY CONTRACT: the
/// join handler reads the candidate's instance pubkey from
/// [`mesh_pubkey`](PeerContext::mesh_pubkey) here (the attested channel),
/// NEVER from a request payload, so a host cannot forge a peer's voting
/// identity.
#[derive(Clone, Debug)]
pub struct PeerContext {
    /// The source peer's logical name (from the dialer's `Hello`). A routing
    /// label only; it carries no authority.
    pub name: String,
    /// The peer's 65-byte SEC1 P-256 per-boot mesh instance pubkey, proven
    /// live on this channel by the handshake-hash signature. The
    /// clone-resistant Raft id derives from it.
    pub mesh_pubkey: [u8; enclavia_protocol::attestation::CONTROL_PUBKEY_LEN],
    /// SHA-256 of the peer's attested PCR0/1/2. In a same-image cluster this
    /// equals the node's own digest (the allowlist check already passed).
    pub pcr_digest: crate::PcrKey,
}

/// Inbound-request handler hook. The node implements this to serve requests
/// that arrive on its accept side; the handler returns the response body.
///
/// Object-safe so the mesh can hold a `dyn RequestHandler`. The Raft layer
/// supplies one that decodes the `body` as a Raft / forward / join message,
/// drives the consensus state machine, and encodes the reply.
///
/// `peer` is the channel-attributed [`PeerContext`] (attested instance pubkey
/// + PCR digest + routing name). The membership-join path reads the
/// candidate's pubkey from it, never from the request payload (#209).
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle one request from `peer` (its channel-attributed identity) and
    /// return the response body.
    async fn handle(&self, peer: &PeerContext, body: MeshPayload) -> MeshPayload;
}

/// A no-op handler that echoes the request body back. Used as the default
/// before the Raft handler is wired in, and as the server side of the request/
/// response tests.
#[derive(Clone, Copy, Default)]
pub struct EchoHandler;

#[async_trait::async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(&self, _peer: &PeerContext, body: MeshPayload) -> MeshPayload {
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
        // Liveness state. `deadline` is when we next act on silence: send a
        // ping (normally) or give up (once `awaiting_pong` is set). ANY inbound
        // frame clears both, because any frame proves the peer is reading and
        // writing this channel.
        let mut awaiting_pong = false;
        let mut deadline = tokio::time::Instant::now() + IDLE_BEFORE_PING;
        loop {
            let idle = tokio::time::sleep_until(deadline);
            tokio::pin!(idle);
            tokio::select! {
                // Silence deadline. `sleep_until` is cancel-safe and keyed on
                // an absolute instant, so recreating it each iteration does not
                // extend the deadline.
                _ = &mut idle => {
                    if awaiting_pong {
                        // We pinged, nothing came back: the channel is open but
                        // dead. Returning drops the ClientChannel and lets the
                        // dial loop rebuild a working connection.
                        return Err(HandshakeError::Timeout {
                            phase: "peer pong",
                            after: PONG_TIMEOUT,
                        });
                    }
                    write_frame(&mut write_half, &mut transport, &MeshFrame::Ping).await?;
                    awaiting_pong = true;
                    deadline = tokio::time::Instant::now() + PONG_TIMEOUT;
                }
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
                            // Any inbound frame is proof of life: clear the
                            // outstanding ping and restart the idle window.
                            awaiting_pong = false;
                            deadline = tokio::time::Instant::now() + IDLE_BEFORE_PING;
                            match decrypt_frame(&mut transport, &ciphertext)? {
                                // A Pong needs nothing beyond the liveness
                                // bookkeeping above. A Ping on the client side
                                // is not expected (the serve side never probes)
                                // but is answered anyway, so the liveness
                                // protocol stays symmetric if that changes.
                                MeshFrame::Pong => {}
                                MeshFrame::Ping => {
                                    write_frame(&mut write_half, &mut transport, &MeshFrame::Pong).await?;
                                }
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
/// [`spawn_client`]'s reader task when its driver returns, and by the mesh's
/// dial-loop supervisor so aborting the supervisor also stops the loop task it
/// is currently watching.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve the inbound (accept) side of one directed connection: read requests,
/// dispatch to `handler`, and write back correlated responses, until the peer
/// closes.
///
/// `peer` is the source peer's channel-attributed identity ([`PeerContext`]:
/// its `Hello` name plus the attested instance pubkey + PCR digest from the
/// mutual-attestation handshake), passed to the handler so it can attribute
/// the request AND, for the #209 join path, read the candidate's pubkey from
/// the attested channel rather than a forgeable payload. Requests are handled
/// one at a time per connection (the synchronizer's throughput is low and Raft
/// is happy with in-order per-link delivery); concurrent load is spread across
/// the per-peer connections, not pipelined within one.
///
/// ## Cancel-safety
///
/// Unlike [`spawn_client`], this loop is strictly sequential: read one
/// request, handle it, write the response, repeat. Nothing races the read
/// except its own [`SERVE_IDLE_TIMEOUT`], so the non-cancel-safe [`read_frame`]
/// is used directly and is never dropped mid-frame on any path that CONTINUES
/// the loop; the only `.await` between two reads is the handler + write, both
/// of which run to completion. The idle timeout is the single cancellation
/// point and it is terminal (it returns, ending the connection), so a
/// half-consumed frame can never be resumed. The split-reader machinery is
/// therefore still unnecessary here.
pub async fn serve<S, H>(
    mut stream: S,
    mut transport: enclavia_protocol::NoiseTransport,
    peer: &PeerContext,
    handler: &H,
) -> Result<(), HandshakeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    H: RequestHandler + ?Sized,
{
    loop {
        // Bounded read: a dialer that vanished without closing the stream (a
        // wedged relay, a hard-killed enclave) leaves a half-open connection
        // that never yields EOF, and this task would park in `read_exact`
        // forever. Cancelling the non-cancel-safe `read_frame` on timeout is
        // safe here because a timeout ENDS the connection: we return, the
        // stream is dropped, and the peer's dial loop rebuilds it.
        let frame = with_deadline(
            "inbound peer idle",
            SERVE_IDLE_TIMEOUT,
            read_frame(&mut stream, &mut transport),
        )
        .await?;
        match frame {
            // Liveness probe from the peer's client driver: answer at once,
            // without troubling the request handler.
            Some(MeshFrame::Ping) => {
                write_frame(&mut stream, &mut transport, &MeshFrame::Pong).await?;
            }
            // The serve side never pings, so a Pong is unsolicited. It still
            // counts as traffic (the read above succeeded), so just ignore it
            // rather than tearing down an otherwise healthy connection.
            Some(MeshFrame::Pong) => {}
            Some(MeshFrame::Rpc { envelope }) => {
                let env: Envelope = ciborium::from_reader(&envelope[..])
                    .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
                match env {
                    Envelope::Request { id, body } => {
                        let resp_body = handler.handle(peer, body).await;
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

    // --- channel liveness (B) -----------------------------------------
    //
    // A peer that stops answering but keeps its stream OPEN produces no EOF
    // and no error, so the driver's reader simply blocked in `read_exact`
    // forever and the dial loop never got its connection back to re-dial.
    // These two tests pin the ping/idle behaviour that recycles such a
    // channel, and prove a healthy idle channel is NOT recycled.

    /// Build a plain (unfragmented) connected Noise pair.
    async fn noise_pair() -> (
        (tokio::io::DuplexStream, enclavia_protocol::NoiseTransport),
        (tokio::io::DuplexStream, enclavia_protocol::NoiseTransport),
    ) {
        use enclavia_protocol::{perform_handshake_as_initiator, perform_handshake_as_responder};
        let (mut a, mut b) = tokio::io::duplex(256 * 1024);
        let ta = tokio::spawn(async move {
            let (t, _h) = perform_handshake_as_initiator(&mut a).await.unwrap();
            (a, t)
        });
        let tb = tokio::spawn(async move {
            let (t, _h) = perform_handshake_as_responder(&mut b).await.unwrap();
            (b, t)
        });
        (ta.await.unwrap(), tb.await.unwrap())
    }

    /// A channel whose peer holds the stream open but never writes another
    /// byte must be recycled: the driver pings after [`IDLE_BEFORE_PING`],
    /// gets no pong within [`PONG_TIMEOUT`], and RETURNS, which is what makes
    /// the dial loop rebuild the connection.
    ///
    /// The far end here consumes the ciphertext (so writes never block) and
    /// answers nothing at all — a wedged relay or a dead enclave, not a closed
    /// socket. Before the ping the driver would sit here forever.
    #[tokio::test(start_paused = true)]
    async fn silent_peer_channel_is_recycled_by_the_liveness_ping() {
        let ((client_stream, client_transport), (server_stream, _server_transport)) =
            noise_pair().await;

        // Black hole: drain every byte the client writes, reply to nothing.
        let black_hole = tokio::spawn(async move {
            let mut server_stream = server_stream;
            let mut sink = [0u8; 4096];
            loop {
                use tokio::io::AsyncReadExt;
                if server_stream.read(&mut sink).await.unwrap_or(0) == 0 {
                    return;
                }
            }
        });

        let (channel, driver) = spawn_client(client_stream, client_transport);
        let started = tokio::time::Instant::now();
        let err = driver
            .await
            .expect_err("a silent peer must end the driver, not park it");
        let elapsed = started.elapsed();

        match err {
            HandshakeError::Timeout { phase, .. } => assert_eq!(phase, "peer pong"),
            other => panic!("expected a pong timeout, got {other:?}"),
        }
        assert!(
            elapsed >= IDLE_BEFORE_PING + PONG_TIMEOUT
                && elapsed < (IDLE_BEFORE_PING + PONG_TIMEOUT) * 2,
            "recycle should happen at ~IDLE_BEFORE_PING + PONG_TIMEOUT, took {elapsed:?}"
        );

        // The driver returning drops the pending map, so in-flight and later
        // calls fail and the mesh reports the peer down.
        assert!(matches!(
            channel.call(b"x".to_vec()).await,
            Err(RpcError::ConnectionClosed)
        ));
        black_hole.abort();
    }

    /// The converse: a channel that is idle but ALIVE (the peer's `serve` loop
    /// answers pings) must survive well past the ping interval. This is what
    /// stops the liveness check from flapping healthy links, and it exercises
    /// the `Ping` -> `Pong` path through the real serve loop.
    #[tokio::test(start_paused = true)]
    async fn idle_but_live_channel_survives_and_still_serves() {
        let ((client_stream, client_transport), (server_stream, server_transport)) =
            noise_pair().await;

        let server = tokio::spawn(async move {
            let peer = PeerContext {
                name: "peer".to_string(),
                mesh_pubkey: [0u8; enclavia_protocol::attestation::CONTROL_PUBKEY_LEN],
                pcr_digest: crate::PcrKey([0u8; 32]),
            };
            serve(server_stream, server_transport, &peer, &EchoHandler).await
        });

        let (channel, driver) = spawn_client(client_stream, client_transport);
        let driver = tokio::spawn(driver);

        // Sit idle across many ping intervals; each one must be answered.
        tokio::time::sleep(IDLE_BEFORE_PING * 10).await;
        assert!(
            !driver.is_finished(),
            "a live idle channel must not recycle"
        );

        // ...and the channel still carries real RPC afterwards.
        let resp = channel
            .call(b"still here".to_vec())
            .await
            .expect("an idle-but-live channel must still serve calls");
        assert_eq!(resp, b"still here");

        drop(channel);
        let _ = driver.await;
        server.abort();
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
            let peer = PeerContext {
                name: "peer".to_string(),
                mesh_pubkey: [0u8; enclavia_protocol::attestation::CONTROL_PUBKEY_LEN],
                pcr_digest: crate::PcrKey([0u8; 32]),
            };
            let _ = serve(server_stream, server_transport, &peer, &EchoHandler).await;
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
