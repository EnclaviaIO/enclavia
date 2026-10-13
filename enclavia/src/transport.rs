use std::collections::HashMap;

use crate::message::{ClientMessage, ServerMessage, StreamHalf};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

use crate::error::Error;
use crate::noise::recv_binary;
use crate::ws::{Ws, WsEvent};

type StreamMap = HashMap<u64, mpsc::Sender<Result<Vec<u8>, Error>>>;
type PendingMap = HashMap<u64, PendingRequest>;

/// Largest Noise transport message plaintext: 65535 bytes of ciphertext
/// minus the 16-byte authentication tag.
const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

/// Upper bound on the CBOR bytes around a stream payload: the message map,
/// its `type` tag and `id`, and the payload's array header.
const STREAM_FRAME_OVERHEAD: usize = 64;

/// Largest slice of request bytes carried by one `OpenStream` / `StreamData`
/// frame. Every message must fit in a single Noise transport message, and a
/// payload byte costs up to two CBOR bytes (bytes are sent as an array of
/// integers), so a request of any size is split into frames of at most this
/// many bytes. A request small enough for a single frame goes out as one
/// `OpenStream`, which the server writes to the workload in one call.
pub(crate) const REQUEST_CHUNK: usize = (MAX_NOISE_PLAINTEXT - STREAM_FRAME_OVERHEAD) / 2;

/// A one-shot request carried over a workload stream: the response bytes
/// accumulate here until the response is complete.
struct PendingRequest {
    response: Vec<u8>,
    response_tx: oneshot::Sender<Result<Vec<u8>, Error>>,
}

/// What the transport loop must do after routing one inbound message.
enum Followup {
    None,
    /// A one-shot request's response is complete. The server keeps the
    /// stream (and one of its in-flight slots) alive until the client
    /// closes both halves, so the loop sends `StreamClose { Both }` for
    /// this id.
    CloseStream(u64),
}

/// Outbound command from a `Client` handle to the background transport task.
#[derive(Debug)]
pub(crate) enum OutboundCommand {
    /// One-shot HTTP request. Carried over a workload stream so neither the
    /// request nor the response is bounded by the size of one Noise message:
    /// the raw request goes out as `OpenStream` plus `StreamData` frames of
    /// at most [`REQUEST_CHUNK`] bytes, and the `StreamData` the server
    /// returns for that id is accumulated until the response is complete:
    /// as soon as it is provably whole (see
    /// [`crate::http::is_complete_response`]), otherwise at the stream's
    /// `StreamClose` (workload EOF). It is then delivered via `response_tx`.
    /// Not waiting for EOF when the length is known keeps a request from
    /// stalling on a close the workload or a network hop delays.
    Request {
        payload: Vec<u8>,
        response_tx: oneshot::Sender<Result<Vec<u8>, Error>>,
    },

    /// Open a bidirectional byte stream to the workload. The transport task
    /// allocates the next id, sends `ClientMessage::OpenStream`, and delivers
    /// the assigned id back through `id_tx`. Every `ServerMessage::StreamData`
    /// for that id is routed into `stream_tx` from then on; the receiver is
    /// owned by `Client::upgrade` while it parses the HTTP head and is then
    /// handed off to the `UpgradedStream` it returns.
    OpenStream {
        payload: Vec<u8>,
        id_tx: oneshot::Sender<Result<u64, Error>>,
        stream_tx: mpsc::Sender<Result<Vec<u8>, Error>>,
    },

    /// Bytes to write into an already-open stream.
    StreamData { id: u64, payload: Vec<u8> },

    /// Close one or both halves of an open stream.
    StreamClose { id: u64, half: StreamHalf },
}

/// Encrypt a CBOR message with the Noise transport, returning length-prefixed ciphertext.
fn encrypt_cbor<T: serde::Serialize>(
    transport: &mut snow::TransportState,
    msg: &T,
    write_buf: &mut [u8],
) -> Result<Vec<u8>, Error> {
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(msg, &mut cbor)?;

    let encrypted_len = transport.write_message(&cbor, write_buf)?;

    let mut out = Vec::with_capacity(4 + encrypted_len);
    out.extend_from_slice(&(encrypted_len as u32).to_be_bytes());
    out.extend_from_slice(&write_buf[..encrypted_len]);
    Ok(out)
}

/// Decrypt a length-prefixed encrypted message from accumulated bytes.
///
/// Returns `Some((message, consumed))` if a complete message was decoded,
/// or `None` if more data is needed.
fn try_decrypt<T: serde::de::DeserializeOwned>(
    transport: &mut snow::TransportState,
    accum: &[u8],
    read_buf: &mut [u8],
) -> Result<Option<(T, usize)>, Error> {
    if accum.len() < 4 {
        return Ok(None);
    }

    let encrypted_len = u32::from_be_bytes(accum[..4].try_into().unwrap()) as usize;
    if accum.len() < 4 + encrypted_len {
        return Ok(None);
    }

    let payload_len =
        transport.read_message(&accum[4..4 + encrypted_len], read_buf)?;

    let msg: T =
        ciborium::de::from_reader(&read_buf[..payload_len])
            .map_err(|e| Error::Cbor(e.to_string()))?;

    Ok(Some((msg, 4 + encrypted_len)))
}

/// Send an encrypted CBOR message and receive a response before the background task starts.
///
/// Used during the connection phase for the attestation exchange.
pub(crate) async fn send_and_receive<S: serde::Serialize, R: serde::de::DeserializeOwned>(
    ws: &mut Ws,
    transport: &mut snow::TransportState,
    msg: &S,
) -> Result<R, Error> {
    let mut write_buf = vec![0u8; 65535];
    let data = encrypt_cbor(transport, msg, &mut write_buf)?;
    ws.send(data).await?;

    let mut accum = Vec::new();
    let mut read_buf = vec![0u8; 65535];

    loop {
        if let Some((msg, _)) = try_decrypt::<R>(transport, &accum, &mut read_buf)? {
            return Ok(msg);
        }
        let frame = recv_binary(ws).await?;
        accum.extend_from_slice(&frame);
    }
}

/// Run the background multiplexing task.
///
/// Owns the WebSocket connection and Noise transport. Receives outbound
/// commands via `cmd_rx`, assigns request ids, encrypts and sends them; reads
/// incoming WS frames, decrypts each `ServerMessage`, and routes it to the
/// appropriate consumer:
///
/// - `pending`: one-shot `Request` consumers, keyed by stream id; their
///   response bytes accumulate until the response is complete.
/// - `streams`: long-lived `OpenStream` consumers, keyed by id, removed on
///   `StreamClose` or an error.
pub(crate) async fn run_transport(
    mut ws: Ws,
    mut transport: snow::TransportState,
    mut cmd_rx: mpsc::Receiver<OutboundCommand>,
) {
    let mut write_buf = vec![0u8; 65535];
    let mut read_buf = vec![0u8; 65535];
    let mut accum = Vec::new();
    let mut next_id: u64 = 1;
    let mut pending: PendingMap = HashMap::new();
    let mut streams: StreamMap = HashMap::new();

    'transport: loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    debug!("All client handles dropped, shutting down transport");
                    ws.close().await;
                    break;
                };

                match cmd {
                    OutboundCommand::Request { payload, response_tx } => {
                        let id = next_id;
                        next_id += 1;
                        match send_request_frames(&mut ws, &mut transport, &mut write_buf, id, &payload).await {
                            Ok(()) => {
                                pending.insert(id, PendingRequest { response: Vec::new(), response_tx });
                                trace!(id, size = payload.len(), "Sent request");
                            }
                            Err(e) => {
                                let _ = response_tx.send(Err(e));
                            }
                        }
                    }
                    OutboundCommand::OpenStream { payload, id_tx, stream_tx } => {
                        let id = next_id;
                        next_id += 1;
                        let msg = ClientMessage::OpenStream { id, payload };
                        match encrypt_cbor(&mut transport, &msg, &mut write_buf) {
                            Ok(data) => {
                                if let Err(e) = ws.send(data).await {
                                    let _ = id_tx.send(Err(e));
                                    continue;
                                }
                                streams.insert(id, stream_tx);
                                let _ = id_tx.send(Ok(id));
                                trace!(id, "Sent OpenStream");
                            }
                            Err(e) => {
                                let _ = id_tx.send(Err(e));
                            }
                        }
                    }
                    OutboundCommand::StreamData { id, payload } => {
                        let msg = ClientMessage::StreamData { id, payload };
                        match encrypt_cbor(&mut transport, &msg, &mut write_buf) {
                            Ok(data) => {
                                if let Err(e) = ws.send(data).await {
                                    warn!(id, error = %e, "Failed to send StreamData");
                                    fail_stream(&mut streams, id, e);
                                }
                            }
                            Err(e) => {
                                warn!(id, error = %e, "Failed to encode StreamData");
                                fail_stream(&mut streams, id, e);
                            }
                        }
                    }
                    OutboundCommand::StreamClose { id, half } => {
                        let msg = ClientMessage::StreamClose { id, half };
                        if let Ok(data) = encrypt_cbor(&mut transport, &msg, &mut write_buf) {
                            let _ = ws.send(data).await;
                        }
                        if matches!(half, StreamHalf::Both) {
                            streams.remove(&id);
                        }
                    }
                }
            }

            frame = ws.recv() => {
                match frame {
                    Ok(WsEvent::Frame(data)) => {
                        accum.extend_from_slice(&data);
                        loop {
                            match try_decrypt::<ServerMessage>(&mut transport, &accum, &mut read_buf) {
                                Ok(Some((msg, consumed))) => {
                                    accum.drain(..consumed);
                                    // May suspend on a full per-stream buffer
                                    // (see dispatch_response). While suspended
                                    // the cmd_rx arm is not polled either, but
                                    // that cannot deadlock: stream consumers
                                    // never block on issuing a command before
                                    // draining. UpgradedStream's poll_write /
                                    // poll_shutdown use try_send (WouldBlock
                                    // semantics, never a suspended await), its
                                    // Drop uses try_send, and poll_read only
                                    // polls the receiving side, so any task
                                    // that is polling the stream keeps
                                    // draining slots and eventually resumes us.
                                    let followup =
                                        dispatch_response(&mut pending, &mut streams, msg).await;
                                    if let Followup::CloseStream(id) = followup {
                                        close_request_stream(&mut ws, &mut transport, &mut write_buf, id).await;
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    // A frame that fails to decrypt means the Noise
                                    // transport is desynced (or the peer is corrupt);
                                    // no later frame on this session can ever decrypt
                                    // again. Leaving the connection up wedged the
                                    // client silently: in-flight requests never
                                    // resolved, and because the command channel stayed
                                    // open, auto-reconnect never engaged. Fail the
                                    // whole channel instead — pending requests get a
                                    // retryable ConnectionClosed, and the next request
                                    // reconnects and re-attests.
                                    error!("Failed to decrypt incoming message, closing channel: {e}");
                                    notify_all_closed(&mut pending, &mut streams);
                                    ws.close().await;
                                    break 'transport;
                                }
                            }
                        }
                    }
                    Ok(WsEvent::Closed) => {
                        debug!("WebSocket closed");
                        notify_all_closed(&mut pending, &mut streams);
                        break;
                    }
                    Err(e) => {
                        warn!("WebSocket error: {e}");
                        notify_all_closed(&mut pending, &mut streams);
                        break;
                    }
                }
            }
        }
    }
}

/// Send a one-shot request as `OpenStream` (the first [`REQUEST_CHUNK`]
/// bytes) followed by `StreamData` frames for the rest. The server writes
/// them to the workload socket in order and does not half-close it, so the
/// workload receives the same bytes as from a single write.
async fn send_request_frames(
    ws: &mut Ws,
    transport: &mut snow::TransportState,
    write_buf: &mut [u8],
    id: u64,
    payload: &[u8],
) -> Result<(), Error> {
    let mut chunks = payload.chunks(REQUEST_CHUNK);
    let first = chunks.next().unwrap_or_default().to_vec();
    let data = encrypt_cbor(transport, &ClientMessage::OpenStream { id, payload: first }, write_buf)?;
    ws.send(data).await?;
    for chunk in chunks {
        let msg = ClientMessage::StreamData { id, payload: chunk.to_vec() };
        let data = encrypt_cbor(transport, &msg, write_buf)?;
        ws.send(data).await?;
    }
    Ok(())
}

/// Release the server side of a finished one-shot request stream. A failure
/// here means the channel itself is going down, which the read side reports.
async fn close_request_stream(
    ws: &mut Ws,
    transport: &mut snow::TransportState,
    write_buf: &mut [u8],
    id: u64,
) {
    let msg = ClientMessage::StreamClose { id, half: StreamHalf::Both };
    match encrypt_cbor(transport, &msg, write_buf) {
        Ok(data) => {
            if let Err(e) = ws.send(data).await {
                warn!(id, error = %e, "Failed to close finished request stream");
            }
        }
        Err(e) => warn!(id, error = %e, "Failed to encode StreamClose"),
    }
}

fn fail_stream(streams: &mut StreamMap, id: u64, err: Error) {
    if let Some(tx) = streams.remove(&id) {
        // Best-effort: receiver may already have been dropped.
        let _ = tx.try_send(Err(err));
    }
}

fn notify_all_closed(pending: &mut PendingMap, streams: &mut StreamMap) {
    for (_, req) in pending.drain() {
        let _ = req.response_tx.send(Err(Error::ConnectionClosed));
    }
    for (_, tx) in streams.drain() {
        let _ = tx.try_send(Err(Error::ConnectionClosed));
    }
}

async fn dispatch_response(
    pending: &mut PendingMap,
    streams: &mut StreamMap,
    msg: ServerMessage,
) -> Followup {
    match msg {
        ServerMessage::StreamData { id, payload } => {
            if let Some(req) = pending.get_mut(&id) {
                req.response.extend_from_slice(&payload);
                if crate::http::is_complete_response(&req.response) {
                    if let Some(req) = pending.remove(&id) {
                        let _ = req.response_tx.send(Ok(req.response));
                        trace!(id, "Dispatched response");
                    }
                    return Followup::CloseStream(id);
                }
            } else if let Some(tx) = streams.get(&id) {
                // Backpressured on purpose: awaiting here suspends the whole
                // transport task, so we stop reading further WebSocket frames
                // until the stream's consumer drains a slot, and the pressure
                // propagates over TCP back to the in-enclave server (whose
                // own per-stream channels already block the same way). The
                // previous try_send silently DISCARDED the frame and tore the
                // stream down when the 64-slot buffer filled, which truncated
                // responses under load ("ConnectionClosed while reading
                // response headers, bytes already read: 0" on the proxy).
                // Accepted tradeoff, mirroring the server side: one slow
                // consumer head-of-line-blocks the other multiplexed streams
                // of this client for the duration of the stall.
                if tx.send(Ok(payload)).await.is_err() {
                    // Receiver dropped: the UpgradedStream was abandoned
                    // locally. Drop the stream entry; a follow-up StreamClose
                    // will land on `streams.get(None)`.
                    streams.remove(&id);
                }
            } else {
                warn!(id, "Received StreamData for unknown stream id");
            }
        }
        ServerMessage::StreamClose { id } => {
            if let Some(req) = pending.remove(&id) {
                // Workload EOF ends a response whose length was not known up
                // front. The caller may have stopped waiting; the stream is
                // closed either way.
                let _ = req.response_tx.send(Ok(req.response));
                trace!(id, "Dispatched response");
                return Followup::CloseStream(id);
            }
            // Removing the Sender closes the mpsc on the receiver side; that
            // is how UpgradedStream observes server-side EOF.
            streams.remove(&id);
        }
        ServerMessage::Error { id, message } => {
            if let Some(req) = pending.remove(&id) {
                // A workload may answer and close before reading the whole
                // request (an early 404 or 413), and the server then fails
                // writing the rest of the request. A response that already
                // arrived in full is still the workload's answer; anything
                // short of that is an error.
                let result = if crate::http::is_complete_response(&req.response) {
                    debug!(id, error = %message, "Workload answered before reading the whole request");
                    Ok(req.response)
                } else {
                    Err(Error::ServerError { id, message })
                };
                let _ = req.response_tx.send(result);
            } else if let Some(tx) = streams.remove(&id) {
                // Same backpressured send as StreamData: the error is the
                // stream's terminal event and must not be lost to a full
                // buffer (dropping the Sender right after delivers EOF).
                let _ = tx.send(Err(Error::ServerError { id, message })).await;
            } else {
                warn!(id, "Received error for unknown request id");
            }
        }
        ServerMessage::Attestation { .. } => {
            warn!("Received unexpected attestation message during transport");
        }
        ServerMessage::ControlResult { .. } => {
            warn!("Received unexpected control result during transport");
        }
    }
    Followup::None
}
