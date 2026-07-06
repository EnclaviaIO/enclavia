use std::collections::HashMap;

use crate::message::{ClientMessage, ServerMessage, StreamHalf};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

use crate::error::Error;
use crate::noise::recv_binary;
use crate::ws::{Ws, WsEvent};

type PendingMap = HashMap<u64, oneshot::Sender<Result<Vec<u8>, Error>>>;
type StreamMap = HashMap<u64, mpsc::Sender<Result<Vec<u8>, Error>>>;

/// Outbound command from a `Client` handle to the background transport task.
#[derive(Debug)]
pub(crate) enum OutboundCommand {
    /// One-shot HTTP request. Response arrives as a single `Data` frame and is
    /// delivered via `response_tx`.
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
/// - `pending`: one-shot `Request` consumers, keyed by id, removed on first
///   response.
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

    loop {
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
                        let msg = ClientMessage::Data { id, payload };
                        match encrypt_cbor(&mut transport, &msg, &mut write_buf) {
                            Ok(data) => {
                                if let Err(e) = ws.send(data).await {
                                    let _ = response_tx.send(Err(e));
                                    continue;
                                }
                                pending.insert(id, response_tx);
                                trace!(id, "Sent request");
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
                                    dispatch_response(&mut pending, &mut streams, msg).await;
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    error!("Failed to decrypt incoming message: {e}");
                                    break;
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

fn fail_stream(streams: &mut StreamMap, id: u64, err: Error) {
    if let Some(tx) = streams.remove(&id) {
        // Best-effort: receiver may already have been dropped.
        let _ = tx.try_send(Err(err));
    }
}

fn notify_all_closed(pending: &mut PendingMap, streams: &mut StreamMap) {
    for (_, tx) in pending.drain() {
        let _ = tx.send(Err(Error::ConnectionClosed));
    }
    for (_, tx) in streams.drain() {
        let _ = tx.try_send(Err(Error::ConnectionClosed));
    }
}

async fn dispatch_response(
    pending: &mut PendingMap,
    streams: &mut StreamMap,
    msg: ServerMessage,
) {
    match msg {
        ServerMessage::Data { id, payload } => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Ok(payload));
                trace!(id, "Dispatched response");
            } else {
                warn!(id, "Received Data for unknown request id");
            }
        }
        ServerMessage::StreamData { id, payload } => {
            if let Some(tx) = streams.get(&id) {
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
            // Removing the Sender closes the mpsc on the receiver side; that
            // is how UpgradedStream observes server-side EOF.
            streams.remove(&id);
        }
        ServerMessage::Error { id, message } => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Err(Error::ServerError { id, message }));
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
}
