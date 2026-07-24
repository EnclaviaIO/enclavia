//! Mock enclave for the wasm reconnect smoke test
//! (`enclavia-wasm/reconnect-smoke.mjs`).
//!
//! Mirrors the `channel_dropped_between_requests_reconnects` harness from
//! tests/reconnect.rs, but as a long-running process: accept a WS
//! connection, run the responder-side Noise handshake, answer the
//! attestation exchange with a FakeAttestation (seed 0x11 -> PCR0 =
//! "11"*48 etc.), answer exactly ONE Data request (body = "conn-<n>"),
//! then DROP the connection. Every further request therefore requires the
//! client to transparently reconnect + re-attest — which is exactly what
//! the smoke test asserts on.
//!
//! Usage: reconnect_mock_server [port]
//!
//! Port 0 (the default) binds an ephemeral port; the actual port is
//! printed as `listening on <port>` so a harness can parse it (this is
//! what lets parallel CI jobs on one runner coexist).

use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{ClientMessage, ServerMessage, perform_cbor_handshake_as_responder};
use tokio::net::TcpListener;

#[path = "../tests/ws_adapter.rs"]
mod ws_adapter;
use ws_adapter::wrap_ws;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .map(|a| a.parse().expect("port arg"))
        .unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    // Parsed by the smoke-test harness — keep the format stable.
    println!("listening on {}", listener.local_addr().unwrap().port());

    let mut n = 0u32;
    loop {
        let (tcp, _) = listener.accept().await.unwrap();
        n += 1;
        let ws = match tokio_tungstenite::accept_async(tcp).await {
            Ok(ws) => ws,
            Err(e) => {
                println!("conn {n}: ws accept failed: {e}");
                continue;
            }
        };
        let stream = wrap_ws(ws);
        let (mut transport, hash) = match perform_cbor_handshake_as_responder(stream).await {
            Ok(x) => x,
            Err(e) => {
                println!("conn {n}: noise handshake failed: {e}");
                continue;
            }
        };
        println!("conn {n}: noise up");

        // Attestation exchange (client sends RequestAttestation first).
        match transport.receive::<ClientMessage>().await {
            Ok(ClientMessage::RequestAttestation) => {}
            other => {
                println!("conn {n}: expected RequestAttestation, got {other:?}");
                continue;
            }
        }
        let doc = FakeAttestation::with_seed(0x11, hash).encode();
        transport
            .send(&ServerMessage::Attestation { data: doc, control_nonce: [0u8; 32] })
            .await
            .unwrap();
        println!("conn {n}: attested");

        // Answer exactly one request, then drop the connection.
        let id = match transport.receive::<ClientMessage>().await {
            Ok(ClientMessage::Data { id, .. }) => id,
            other => {
                println!("conn {n}: expected Data, got {other:?}");
                continue;
            }
        };
        let body = format!("conn-{n}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        transport
            .send(&ServerMessage::Data { id, payload: resp.into_bytes() })
            .await
            .unwrap();
        println!("conn {n}: answered one request, dropping");
        // transport dropped here -> socket closes -> client must reconnect.
    }
}
