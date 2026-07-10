//! Integration tests for `Client::upgrade`. Spin up an in-process WebSocket
//! endpoint that mimics enclavia-server: terminates the Noise channel,
//! receives `RequestAttestation` then `OpenStream { id, payload }`, replies
//! by streaming the HTTP response head + body bytes back as `StreamData`
//! frames, and echoes any `StreamData` the client sends. The HTTP head
//! detection (101 vs other status) is the SDK's responsibility, exercised
//! here end to end.

use std::time::Duration;

use enclavia::{Client, Method, Pcrs};
use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{
    perform_cbor_handshake_as_responder, ClientMessage, ServerMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[path = "ws_adapter.rs"]
mod ws_adapter;
use ws_adapter::{wrap_ws, WsByteStream};

type Transport = enclavia_protocol::CborTransport<WsByteStream>;

struct TestSrv {
    transport: Transport,
    hash: Vec<u8>,
}

impl TestSrv {
    fn handshake_hash(&self) -> &[u8] {
        &self.hash
    }

    async fn send(&mut self, msg: &ServerMessage) -> Result<(), Box<dyn std::error::Error>> {
        self.transport.send(msg).await
    }

    async fn receive<T>(&mut self) -> Result<T, Box<dyn std::error::Error>>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.transport.receive().await
    }
}

async fn spawn_test_server<F, Fut>(handler: F) -> String
where
    F: FnOnce(TestSrv) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let stream = wrap_ws(ws);
        let (transport, hash) = perform_cbor_handshake_as_responder(stream).await.unwrap();
        let srv = TestSrv { transport, hash };
        handler(srv).await;
    });
    format!("ws://127.0.0.1:{port}")
}

fn fake_attestation_for(hash: Vec<u8>) -> Vec<u8> {
    FakeAttestation::with_seed(0x11, hash).encode()
}

fn matching_pcrs() -> Pcrs {
    Pcrs {
        pcr0: vec![0x11; 48],
        pcr1: vec![0x12; 48],
        pcr2: vec![0x13; 48],
    }
}

#[tokio::test]
async fn upgrade_succeeds_and_streams_bytes_both_ways() {
    let url = spawn_test_server(|mut t| async move {
        // Attestation exchange in debug mode: server encodes a FakeAttestation
        // pinned to the handshake hash so the SDK's verify_against passes.
        match t.receive::<ClientMessage>().await.unwrap() {
            ClientMessage::RequestAttestation => {}
            other => panic!("expected RequestAttestation, got {other:?}"),
        }
        let hash = t.handshake_hash().to_vec();
        let doc = fake_attestation_for(hash);
        t.send(&ServerMessage::Attestation {
            data: doc,
            control_nonce: [0u8; 32],
        })
        .await
        .unwrap();

        let id = match t.receive::<ClientMessage>().await.unwrap() {
            ClientMessage::OpenStream { id, payload } => {
                assert!(
                    payload.starts_with(b"GET /ws HTTP/1.1"),
                    "request did not start with GET /ws: {:?}",
                    String::from_utf8_lossy(&payload)
                );
                id
            }
            other => panic!("expected OpenStream, got {other:?}"),
        };

        // Server sends the 101 head + a first server-pushed payload back as
        // StreamData (split across two frames to exercise the SDK's
        // accumulator).
        t.send(&ServerMessage::StreamData {
            id,
            payload: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n".to_vec(),
        })
        .await
        .unwrap();
        t.send(&ServerMessage::StreamData {
            id,
            payload: b"Connection: Upgrade\r\n\r\nserver-push".to_vec(),
        })
        .await
        .unwrap();

        loop {
            let msg: ClientMessage = match t.receive().await {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                ClientMessage::StreamData { id: rid, payload } => {
                    assert_eq!(rid, id);
                    t.send(&ServerMessage::StreamData { id, payload })
                        .await
                        .unwrap();
                }
                ClientMessage::StreamClose { id: _, .. } => {
                    let _ = t.send(&ServerMessage::StreamClose { id }).await;
                    break;
                }
                other => panic!("unexpected message during pump: {other:?}"),
            }
        }
    })
    .await;

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(matching_pcrs())
        .build()
        .await
        .expect("client connect");

    let mut stream = client
        .upgrade(
            Method::Get,
            "/ws",
            &[
                ("Upgrade".into(), "websocket".into()),
                ("Connection".into(), "Upgrade".into()),
            ],
        )
        .await
        .expect("upgrade ok");

    // Initial read drains the leftover bytes (the "server-push" payload that
    // was glued onto the 101 head's tail).
    let mut buf = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf[..n], b"server-push");

    stream.write_all(b"hello-back").await.unwrap();
    let mut received = Vec::new();
    while received.len() < b"hello-back".len() {
        let mut tmp = vec![0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(received, b"hello-back");

    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut tail)).await;
}

/// Round-trip raw bytes through `Client::open_stream`. The test responder
/// expects an arbitrary prologue (no HTTP shape) as the OpenStream payload,
/// then byte-echoes anything else it receives. This exercises the
/// no-HTTP-parsing primitive that `Client::upgrade` is built on, which
/// downstream proxies (e.g. `pingora-enclavia`) use directly.
#[tokio::test]
async fn open_stream_round_trips_raw_bytes() {
    let url = spawn_test_server(|mut t| async move {
        match t.receive::<ClientMessage>().await.unwrap() {
            ClientMessage::RequestAttestation => {}
            other => panic!("expected RequestAttestation, got {other:?}"),
        }
        let hash = t.handshake_hash().to_vec();
        let doc = fake_attestation_for(hash);
        t.send(&ServerMessage::Attestation {
            data: doc,
            control_nonce: [0u8; 32],
        })
        .await
        .unwrap();

        let id = match t.receive::<ClientMessage>().await.unwrap() {
            ClientMessage::OpenStream { id, payload } => {
                // Arbitrary opaque payload — no HTTP request line, no headers.
                assert_eq!(payload, b"HELLO-PROLOGUE");
                id
            }
            other => panic!("expected OpenStream, got {other:?}"),
        };

        t.send(&ServerMessage::StreamData {
            id,
            payload: b"prologue-ack".to_vec(),
        })
        .await
        .unwrap();

        loop {
            let msg: ClientMessage = match t.receive().await {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                ClientMessage::StreamData { id: rid, payload } => {
                    assert_eq!(rid, id);
                    t.send(&ServerMessage::StreamData { id, payload })
                        .await
                        .unwrap();
                }
                ClientMessage::StreamClose { id: _, .. } => {
                    let _ = t.send(&ServerMessage::StreamClose { id }).await;
                    break;
                }
                other => panic!("unexpected message during pump: {other:?}"),
            }
        }
    })
    .await;

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(matching_pcrs())
        .build()
        .await
        .expect("client connect");

    let mut stream = client
        .open_stream(b"HELLO-PROLOGUE".to_vec())
        .await
        .expect("open_stream ok");

    let mut buf = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf[..n], b"prologue-ack");

    stream.write_all(b"ping").await.unwrap();
    let mut received = Vec::new();
    while received.len() < b"ping".len() {
        let mut tmp = vec![0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(received, b"ping");

    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn upgrade_surfaces_non_101_as_error() {
    let url = spawn_test_server(|mut t| async move {
        let _ = t.receive::<ClientMessage>().await.unwrap();
        let hash = t.handshake_hash().to_vec();
        let doc = fake_attestation_for(hash);
        t.send(&ServerMessage::Attestation {
            data: doc,
            control_nonce: [0u8; 32],
        })
        .await
        .unwrap();
        let id = match t.receive::<ClientMessage>().await.unwrap() {
            ClientMessage::OpenStream { id, .. } => id,
            other => panic!("expected OpenStream, got {other:?}"),
        };
        t.send(&ServerMessage::StreamData {
            id,
            payload: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnah".to_vec(),
        })
        .await
        .unwrap();
    })
    .await;

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(matching_pcrs())
        .build()
        .await
        .unwrap();
    let err = client
        .upgrade(Method::Get, "/ws", &[])
        .await
        .expect_err("expected upgrade rejection");
    match err {
        enclavia::Error::UpgradeFailed { status, head } => {
            assert_eq!(status, 400);
            assert!(head.starts_with(b"HTTP/1.1 400 Bad Request"));
            assert!(head.ends_with(b"\r\n\r\n"), "head should stop at the double CRLF");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
