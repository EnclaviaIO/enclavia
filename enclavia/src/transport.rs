use std::collections::HashMap;

use crate::message::{ClientMessage, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, trace, warn};

use crate::error::Error;
use crate::noise::recv_binary;

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// A pending request waiting for a response from the server.
pub(crate) struct PendingRequest {
    pub payload: Vec<u8>,
    pub response_tx: oneshot::Sender<Result<Vec<u8>, Error>>,
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
    ws: &mut WsStream,
    transport: &mut snow::TransportState,
    msg: &S,
) -> Result<R, Error> {
    let mut write_buf = vec![0u8; 65535];
    let data = encrypt_cbor(transport, msg, &mut write_buf)?;
    ws.send(Message::Binary(data.into())).await?;

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
/// This task owns the WebSocket connection and Noise transport state.
/// It receives outgoing requests via `request_rx`, assigns IDs, encrypts and sends them.
/// It reads incoming WS frames, decrypts responses, and routes them to the correct
/// oneshot sender by request ID.
pub(crate) async fn run_transport(
    mut ws: WsStream,
    mut transport: snow::TransportState,
    mut request_rx: mpsc::Receiver<PendingRequest>,
) {
    let mut write_buf = vec![0u8; 65535];
    let mut read_buf = vec![0u8; 65535];
    let mut accum = Vec::new();
    let mut next_id: u64 = 1;
    let mut pending: HashMap<u64, oneshot::Sender<Result<Vec<u8>, Error>>> =
        HashMap::new();

    loop {
        tokio::select! {
            req = request_rx.recv() => {
                let Some(req) = req else {
                    debug!("All client handles dropped, shutting down transport");
                    let _ = ws.close(None).await;
                    break;
                };

                let id = next_id;
                next_id += 1;

                let msg = ClientMessage::Data {
                    id,
                    payload: req.payload,
                };

                match encrypt_cbor(&mut transport, &msg, &mut write_buf) {
                    Ok(data) => {
                        if let Err(e) = ws.send(Message::Binary(data.into())).await {
                            let _ = req.response_tx.send(Err(Error::WebSocket(e)));
                            continue;
                        }
                        pending.insert(id, req.response_tx);
                        trace!(id, "Sent request");
                    }
                    Err(e) => {
                        let _ = req.response_tx.send(Err(e));
                    }
                }
            }

            frame = ws.next() => {
                match frame {
                    Some(Ok(Message::Binary(data))) => {
                        accum.extend_from_slice(&data);
                        // Try to drain all complete messages from the accumulator
                        loop {
                            match try_decrypt::<ServerMessage>(&mut transport, &accum, &mut read_buf) {
                                Ok(Some((msg, consumed))) => {
                                    accum.drain(..consumed);
                                    dispatch_response(&mut pending, msg);
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    error!("Failed to decrypt incoming message: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket closed");
                        // Notify all pending requests
                        for (_, tx) in pending.drain() {
                            let _ = tx.send(Err(Error::ConnectionClosed));
                        }
                        break;
                    }
                    Some(Ok(_)) => continue, // skip ping/pong/text
                    Some(Err(e)) => {
                        warn!("WebSocket error: {e}");
                        for (_, tx) in pending.drain() {
                            let _ = tx.send(Err(Error::ConnectionClosed));
                        }
                        break;
                    }
                }
            }
        }
    }
}

fn dispatch_response(
    pending: &mut HashMap<u64, oneshot::Sender<Result<Vec<u8>, Error>>>,
    msg: ServerMessage,
) {
    match msg {
        ServerMessage::Data { id, payload } => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Ok(payload));
                trace!(id, "Dispatched response");
            } else {
                warn!(id, "Received response for unknown request ID");
            }
        }
        ServerMessage::Error { id, message } => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Err(Error::ServerError { id, message }));
            } else {
                warn!(id, "Received error for unknown request ID");
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
