use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

use crate::error::Error;

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Receive the next binary WebSocket frame, skipping non-binary messages.
pub(crate) async fn recv_binary(ws: &mut WsStream) -> Result<Vec<u8>, Error> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(data))) => return Ok(data.into()),
            Some(Ok(Message::Close(_))) | None => return Err(Error::ConnectionClosed),
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(Error::WebSocket(e)),
        }
    }
}

/// Perform a Noise NN handshake over a WebSocket connection.
///
/// Returns the `TransportState` for encrypting/decrypting messages and the
/// handshake hash (used as the attestation nonce).
pub(crate) async fn perform_handshake(
    ws: &mut WsStream,
) -> Result<(snow::TransportState, Vec<u8>), Error> {
    let mut handshake = snow::Builder::new(
        crate::message::NOISE_PATTERN
            .parse()
            .expect("valid noise pattern"),
    )
    .build_initiator()?;

    let mut buf = vec![0u8; 65535];

    // -> e
    let len = handshake.write_message(&[], &mut buf)?;
    ws.send(Message::Binary(buf[..len].to_vec().into()))
        .await?;
    debug!("Sent handshake -> e");

    // <- e, ee
    let response = recv_binary(ws).await?;
    let mut payload = vec![0u8; 65535];
    handshake.read_message(&response, &mut payload)?;
    debug!("Received handshake <- e, ee");

    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let transport = handshake.into_transport_mode()?;
    info!("Noise handshake complete");

    Ok((transport, handshake_hash))
}
