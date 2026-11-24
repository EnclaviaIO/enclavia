use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use enclavia_protocol::{
    ClientMessage, MAX_NOISE_PLAINTEXT, NoiseTransport, ServerMessage, StreamHalf,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

use crate::error::Error;
use crate::noise::recv_binary;
use crate::ws::{Ws, WsEvent};

/// Shared slot carrying a terminal stream error from the transport task to
/// [`crate::UpgradedStream`]. Stored out-of-band from the bounded data channel
/// so a transport teardown or stream failure can NEVER be silently dropped
/// into clean EOF when the 64-slot receive buffer is full.
pub(crate) type TerminalErr = Arc<StdMutex<Option<String>>>;

struct StreamEntry {
    tx: mpsc::Sender<Result<Vec<u8>, Error>>,
    terminal_err: TerminalErr,
}

type StreamMap = HashMap<u64, StreamEntry>;
type PendingMap = HashMap<u64, PendingRequest>;

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
        terminal_err: TerminalErr,
    },

    /// Bytes to write into an already-open stream.
    StreamData { id: u64, payload: Vec<u8> },

    /// Close one or both halves of an open stream.
    StreamClose { id: u64, half: StreamHalf },
}

/// Outcome of encrypting and sending one outbound CBOR frame.
enum SendOutcome {
    /// CBOR serialization or plaintext-size validation failed BEFORE the Noise
    /// outbound nonce advanced: the transport session is still intact.
    PreEncrypt(Error),
    /// The Noise cipher state advanced or the WebSocket write failed: the
    /// transport session is now dead/desynced and MUST be torn down.
    TransportFatal(Error),
}

/// Encrypt a CBOR message with the Noise transport, returning length-prefixed ciphertext.
///
/// Validates `cbor.len() <= MAX_NOISE_PLAINTEXT` BEFORE touching `transport`
/// so an oversized message never advances the Noise nonce.
fn encrypt_cbor<T: serde::Serialize>(
    transport: &mut NoiseTransport,
    msg: &T,
    write_buf: &mut [u8],
) -> Result<Vec<u8>, SendOutcome> {
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(msg, &mut cbor)
        .map_err(|e| SendOutcome::PreEncrypt(Error::from(e)))?;

    if cbor.len() > MAX_NOISE_PLAINTEXT {
        return Err(SendOutcome::PreEncrypt(Error::Cbor(format!(
            "outbound CBOR frame is {} bytes, exceeding Noise limit {}",
            cbor.len(),
            MAX_NOISE_PLAINTEXT
        ))));
    }

    let encrypted_len = transport
        .write_message(&cbor, write_buf)
        .map_err(|e| SendOutcome::TransportFatal(Error::from(e)))?;

    let mut out = Vec::with_capacity(4 + encrypted_len);
    out.extend_from_slice(&(encrypted_len as u32).to_be_bytes());
    out.extend_from_slice(&write_buf[..encrypted_len]);
    Ok(out)
}

/// Encrypt and send one CBOR message over the WebSocket.
async fn send_cbor<T: serde::Serialize>(
    ws: &mut Ws,
    transport: &mut NoiseTransport,
    write_buf: &mut [u8],
    msg: &T,
) -> Result<(), SendOutcome> {
    let data = encrypt_cbor(transport, msg, write_buf)?;
    ws.send(data).await.map_err(SendOutcome::TransportFatal)
}

/// Decrypt a length-prefixed encrypted message from accumulated bytes.
///
/// Returns `Some((message, consumed))` if a complete message was decoded,
/// or `None` if more data is needed. Rejects zero-length or oversized frames
/// (> `read_buf.len()`) before waiting for more bytes so a hostile proxy
/// cannot trigger unbounded buffering or 32-bit `4 + encrypted_len` overflow.
fn try_decrypt<T: serde::de::DeserializeOwned>(
    transport: &mut NoiseTransport,
    accum: &[u8],
    read_buf: &mut [u8],
) -> Result<Option<(T, usize)>, Error> {
    if accum.len() < 4 {
        return Ok(None);
    }

    let encrypted_len = u32::from_be_bytes(accum[..4].try_into().unwrap()) as usize;
    if encrypted_len == 0 || encrypted_len > read_buf.len() {
        return Err(Error::Cbor(format!(
            "invalid Noise frame length {encrypted_len} (must be 1..={})",
            read_buf.len()
        )));
    }
    let total_len = 4usize
        .checked_add(encrypted_len)
        .ok_or_else(|| Error::Cbor("Noise frame length overflow".into()))?;
    if accum.len() < total_len {
        return Ok(None);
    }

    let payload_len = transport.read_message(&accum[4..total_len], read_buf)?;

    let msg: T = ciborium::de::from_reader(&read_buf[..payload_len])
        .map_err(|e| Error::Cbor(e.to_string()))?;

    Ok(Some((msg, total_len)))
}

/// Send an encrypted CBOR message and receive a response before the background task starts.
///
/// Used during the connection phase for the attestation exchange.
pub(crate) async fn send_and_receive<S: serde::Serialize, R: serde::de::DeserializeOwned>(
    ws: &mut Ws,
    transport: &mut NoiseTransport,
    msg: &S,
) -> Result<R, Error> {
    let mut write_buf = vec![0u8; 65535];
    send_cbor(ws, transport, &mut write_buf, msg)
        .await
        .map_err(|e| match e {
            SendOutcome::PreEncrypt(err) | SendOutcome::TransportFatal(err) => err,
        })?;

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
    mut transport: NoiseTransport,
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
                            Err(SendOutcome::PreEncrypt(e)) => {
                                let _ = response_tx.send(Err(e));
                            }
                            Err(SendOutcome::TransportFatal(e)) => {
                                warn!(id, error = %e, "Transport send failed on Request, tearing down channel");
                                let _ = response_tx.send(Err(e));
                                notify_all_closed(&mut pending, &mut streams);
                                ws.close().await;
                                break 'transport;
                            }
                        }
                    }
                    OutboundCommand::OpenStream { payload, id_tx, stream_tx, terminal_err } => {
                        let id = next_id;
                        next_id += 1;
                        match send_request_frames(&mut ws, &mut transport, &mut write_buf, id, &payload).await {
                            Ok(()) => {
                                streams.insert(id, StreamEntry { tx: stream_tx, terminal_err });
                                let _ = id_tx.send(Ok(id));
                                trace!(id, "Sent OpenStream");
                            }
                            Err(SendOutcome::PreEncrypt(e)) => {
                                let _ = id_tx.send(Err(e));
                            }
                            Err(SendOutcome::TransportFatal(e)) => {
                                warn!(id, error = %e, "Transport send failed on OpenStream, tearing down channel");
                                let _ = id_tx.send(Err(e));
                                notify_all_closed(&mut pending, &mut streams);
                                ws.close().await;
                                break 'transport;
                            }
                        }
                    }
                    OutboundCommand::StreamData { id, payload } => {
                        let msg = ClientMessage::StreamData { id, payload };
                        match send_cbor(&mut ws, &mut transport, &mut write_buf, &msg).await {
                            Ok(()) => {}
                            Err(SendOutcome::PreEncrypt(e)) => {
                                warn!(id, error = %e, "Failed to encode StreamData");
                                fail_stream(&mut streams, id, e);
                            }
                            Err(SendOutcome::TransportFatal(e)) => {
                                warn!(id, error = %e, "Transport send failed on StreamData, tearing down channel");
                                fail_stream(&mut streams, id, e);
                                notify_all_closed(&mut pending, &mut streams);
                                ws.close().await;
                                break 'transport;
                            }
                        }
                    }
                    OutboundCommand::StreamClose { id, half } => {
                        if matches!(half, StreamHalf::Both) {
                            streams.remove(&id);
                        }
                        let msg = ClientMessage::StreamClose { id, half };
                        match send_cbor(&mut ws, &mut transport, &mut write_buf, &msg).await {
                            Ok(()) => {}
                            Err(SendOutcome::PreEncrypt(e)) => {
                                warn!(id, error = %e, "Failed to encode StreamClose");
                            }
                            Err(SendOutcome::TransportFatal(e)) => {
                                warn!(id, error = %e, "Transport send failed on StreamClose, tearing down channel");
                                notify_all_closed(&mut pending, &mut streams);
                                ws.close().await;
                                break 'transport;
                            }
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
                                    let followup =
                                        dispatch_response(&mut pending, &mut streams, msg).await;
                                    if let Followup::CloseStream(id) = followup {
                                        let close = ClientMessage::StreamClose {
                                            id,
                                            half: StreamHalf::Both,
                                        };
                                        if let Err(SendOutcome::TransportFatal(e)) =
                                            send_cbor(&mut ws, &mut transport, &mut write_buf, &close).await
                                        {
                                            warn!(id, error = %e, "Transport send failed closing finished request stream, tearing down channel");
                                            notify_all_closed(&mut pending, &mut streams);
                                            ws.close().await;
                                            break 'transport;
                                        }
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    // A frame that fails to decrypt means the Noise
                                    // transport is desynced (or the peer is corrupt);
                                    // no later frame on this session can ever decrypt
                                    // again. Fail the whole channel so pending requests
                                    // get retryable ConnectionClosed and auto-reconnect
                                    // re-establishes and re-attests.
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

/// Send an initial stream payload as `OpenStream` (the first [`REQUEST_CHUNK`]
/// bytes) followed by `StreamData` frames for the rest. The server writes
/// them to the workload socket in order and does not half-close it, so the
/// workload receives the same bytes as from a single write.
async fn send_request_frames(
    ws: &mut Ws,
    transport: &mut NoiseTransport,
    write_buf: &mut [u8],
    id: u64,
    payload: &[u8],
) -> Result<(), SendOutcome> {
    let mut chunks = payload.chunks(REQUEST_CHUNK);
    let first = chunks.next().unwrap_or_default().to_vec();
    send_cbor(
        ws,
        transport,
        write_buf,
        &ClientMessage::OpenStream { id, payload: first },
    )
    .await?;
    for chunk in chunks {
        let msg = ClientMessage::StreamData {
            id,
            payload: chunk.to_vec(),
        };
        send_cbor(ws, transport, write_buf, &msg).await?;
    }
    Ok(())
}

fn record_terminal_error(entry: &StreamEntry, msg: String) {
    let mut slot = entry.terminal_err.lock().unwrap();
    if slot.is_none() {
        *slot = Some(msg);
    }
}

fn fail_stream(streams: &mut StreamMap, id: u64, err: Error) {
    if let Some(entry) = streams.remove(&id) {
        record_terminal_error(&entry, err.to_string());
        let _ = entry.tx.try_send(Err(err));
    }
}

fn notify_all_closed(pending: &mut PendingMap, streams: &mut StreamMap) {
    for (_, req) in pending.drain() {
        let _ = req.response_tx.send(Err(Error::ConnectionClosed));
    }
    for (_, entry) in streams.drain() {
        record_terminal_error(&entry, Error::ConnectionClosed.to_string());
        let _ = entry.tx.try_send(Err(Error::ConnectionClosed));
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
            } else if let Some(entry) = streams.get(&id) {
                if entry.tx.send(Ok(payload)).await.is_err() {
                    streams.remove(&id);
                }
            } else {
                warn!(id, "Received StreamData for unknown stream id");
            }
        }
        ServerMessage::StreamClose { id } => {
            if let Some(req) = pending.remove(&id) {
                let _ = req.response_tx.send(Ok(req.response));
                trace!(id, "Dispatched response");
                return Followup::CloseStream(id);
            }
            // Clean EOF: drop sender without setting `terminal_err`.
            streams.remove(&id);
        }
        ServerMessage::Error { id, message } => {
            if let Some(req) = pending.remove(&id) {
                let result = if crate::http::is_complete_response(&req.response) {
                    debug!(id, error = %message, "Workload answered before reading the whole request");
                    Ok(req.response)
                } else {
                    Err(Error::ServerError { id, message })
                };
                let _ = req.response_tx.send(result);
            } else if let Some(entry) = streams.remove(&id) {
                let err = Error::ServerError { id, message };
                record_terminal_error(&entry, err.to_string());
                let _ = entry.tx.send(Err(err)).await;
            } else {
                warn!(id, "Received error for unknown request id");
            }
        }
        ServerMessage::Data { id, .. } => {
            warn!(id, "Received unexpected one-shot Data message during transport");
        }
        ServerMessage::Attestation { .. } => {
            warn!("Received unexpected attestation message during transport");
        }
        ServerMessage::ControlNonce { .. } => {
            warn!("Received unexpected control nonce during transport");
        }
        ServerMessage::ControlResult { .. } => {
            warn!("Received unexpected control result during transport");
        }
    }
    Followup::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavia_protocol::NoiseHandshake;

    fn paired_transports() -> (NoiseTransport, NoiseTransport) {
        let mut init = NoiseHandshake::initiator().unwrap();
        let mut resp = NoiseHandshake::responder().unwrap();
        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];
        let mut scratch = [0u8; 128];
        let n1 = init.write_message(&[], &mut buf1).unwrap();
        resp.read_message(&buf1[..n1], &mut scratch).unwrap();
        let n2 = resp.write_message(&[], &mut buf2).unwrap();
        init.read_message(&buf2[..n2], &mut scratch).unwrap();
        (
            init.into_transport_mode().unwrap(),
            resp.into_transport_mode().unwrap(),
        )
    }

    #[test]
    fn try_decrypt_rejects_zero_oversized_and_u32_max_frame_lengths() {
        let (mut init, _resp) = paired_transports();
        let mut read_buf = vec![0u8; 65535];

        for bad_len in [0u32, 65536u32, u32::MAX - 3, u32::MAX] {
            let accum = bad_len.to_be_bytes();
            let err = try_decrypt::<ServerMessage>(&mut init, &accum, &mut read_buf)
                .expect_err("invalid frame length must fail immediately");
            assert!(
                matches!(err, Error::Cbor(_)),
                "expected Cbor error for len={bad_len}, got {err:?}"
            );
        }
    }

    #[test]
    fn oversized_encrypt_does_not_desync_noise_nonce() {
        let (mut init, mut resp) = paired_transports();
        let mut write_buf = vec![0u8; 65535];
        let mut read_buf = vec![0u8; 65535];

        // Oversized message fails BEFORE touching Noise transport state.
        let huge = ClientMessage::StreamData {
            id: 1,
            payload: vec![0xff; MAX_NOISE_PLAINTEXT],
        };
        let err = encrypt_cbor(&mut init, &huge, &mut write_buf).unwrap_err();
        assert!(matches!(err, SendOutcome::PreEncrypt(_)));

        // Subsequent small message still decrypts cleanly on responder (nonce intact).
        let ok_msg = ClientMessage::StreamClose {
            id: 1,
            half: StreamHalf::Both,
        };
        let wire = encrypt_cbor(&mut init, &ok_msg, &mut write_buf)
            .ok()
            .expect("small message encrypts");
        let (decoded, consumed) =
            try_decrypt::<ClientMessage>(&mut resp, &wire, &mut read_buf)
                .unwrap()
                .expect("complete frame");
        assert_eq!(consumed, wire.len());
        assert!(matches!(
            decoded,
            ClientMessage::StreamClose {
                id: 1,
                half: StreamHalf::Both
            }
        ));
    }
}
