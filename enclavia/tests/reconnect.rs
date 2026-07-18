//! Integration tests for the SDK's transparent reconnect on the
//! request/response path.
//!
//! The enclave restarts on every deploy/upgrade, which kills the attested
//! WebSocket channel. The SDK re-establishes it, RE-RUNNING the full Noise
//! and attestation handshake against the originally-pinned expectations,
//! before the next request. These tests exercise the invariants:
//!
//! 1. A channel dropped BETWEEN requests is transparently re-established:
//!    the caller's next request reconnects, re-attests, and succeeds.
//! 2. A request whose channel drops WHILE IT IS IN FLIGHT is not silently
//!    re-sent (it may already have executed); it surfaces as a retryable
//!    error, and the caller's explicit retry succeeds on the fresh channel.
//! 3. If, after a restart, the enclave's attestation no longer matches the
//!    pinned PCRs, the reconnect FAILS CLOSED with a distinct attestation
//!    error rather than attaching to the wrong enclave.
//! 4. With auto-reconnect disabled, a dropped channel just surfaces.
//! 5. Opening a new upgraded stream after a drop reconnects and re-attests;
//!    an already-open stream is never silently recreated.
//! 6. Concurrent callers share one reconnect attempt instead of each
//!    performing its own WebSocket, Noise, and attestation handshakes.
//!
//! The harness stands up a small in-process Noise responder that mimics
//! enclavia-server (attestation reply + a single `Data` response per
//! request). Unlike `upgrade.rs` it accepts MULTIPLE TCP connections in
//! sequence, so the SDK can be observed reconnecting.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use enclavia::{Client, Method, Pcrs};
use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{perform_cbor_handshake_as_responder, ClientMessage, ServerMessage};
use tokio::net::TcpListener;
use tokio::sync::Barrier;

#[path = "ws_adapter.rs"]
mod ws_adapter;
use ws_adapter::wrap_ws;

type Transport = enclavia_protocol::CborTransport<ws_adapter::WsByteStream>;

/// A single accepted enclave connection: the Noise responder plus the
/// handshake hash it derived (used to bind the synthetic attestation).
struct Conn {
    transport: Transport,
    hash: Vec<u8>,
}

impl Conn {
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

/// Accept one TCP connection, run the responder-side Noise handshake, and
/// hand the caller a [`Conn`].
async fn accept_one(listener: &TcpListener) -> Conn {
    let (tcp, _) = listener.accept().await.unwrap();
    let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    let stream = wrap_ws(ws);
    let (transport, hash) = perform_cbor_handshake_as_responder(stream).await.unwrap();
    Conn { transport, hash }
}

/// Do the attestation exchange: expect `RequestAttestation`, reply with a
/// [`FakeAttestation`] seeded by `seed` and bound to the live handshake
/// hash. A different `seed` yields different PCRs, which is how the
/// "PCRs changed after restart" case is simulated.
async fn do_attestation(conn: &mut Conn, seed: u8) {
    match conn.receive::<ClientMessage>().await.unwrap() {
        ClientMessage::RequestAttestation => {}
        other => panic!("expected RequestAttestation, got {other:?}"),
    }
    let doc = FakeAttestation::with_seed(seed, conn.hash.clone()).encode();
    conn.send(&ServerMessage::Attestation {
        data: doc,
        control_nonce: [0u8; 32],
    })
    .await
    .unwrap();
}

/// Receive exactly one `Data` request WITHOUT answering it, to simulate
/// the enclave dropping while a request is in flight.
async fn receive_one_request(conn: &mut Conn) {
    match conn.receive::<ClientMessage>().await.unwrap() {
        ClientMessage::Data { .. } => {}
        other => panic!("expected Data, got {other:?}"),
    }
}

/// Answer exactly one `Data` request, echoing back `body` in the response.
async fn answer_one_request(conn: &mut Conn, body: &[u8]) {
    let id = match conn.receive::<ClientMessage>().await.unwrap() {
        ClientMessage::Data { id, .. } => id,
        other => panic!("expected Data, got {other:?}"),
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut payload = resp.into_bytes();
    payload.extend_from_slice(body);
    conn.send(&ServerMessage::Data { id, payload }).await.unwrap();
}

/// Accept one stream-opening request and complete its HTTP upgrade.
async fn answer_one_upgrade(conn: &mut Conn) {
    let id = match conn.receive::<ClientMessage>().await.unwrap() {
        ClientMessage::OpenStream { id, .. } => id,
        other => panic!("expected OpenStream, got {other:?}"),
    };
    conn.send(&ServerMessage::StreamData {
        id,
        payload: b"HTTP/1.1 101 Switching Protocols\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\r\n"
            .to_vec(),
    })
    .await
    .unwrap();
}

/// The PCRs a [`FakeAttestation::with_seed(0x11, _)`] doc carries.
fn pcrs_for_seed(seed: u8) -> Pcrs {
    Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    }
}

/// A channel dropped BETWEEN requests is transparently re-established: the
/// second request reconnects, re-attests (same PCRs), and succeeds.
#[tokio::test]
async fn channel_dropped_between_requests_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");
    let accepted = Arc::new(AtomicUsize::new(0));

    let server_accepted = accepted.clone();
    tokio::spawn(async move {
        // First connection: attest, answer one request, then DROP (simulate
        // an enclave restart mid-session by closing the socket).
        let mut c1 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c1, 0x11).await;
        answer_one_request(&mut c1, b"first").await;
        drop(c1); // close the WebSocket / TCP connection

        // Second connection: the SDK reconnects here, re-attests (same
        // seed = same PCRs, so verification passes), and the retried
        // request is answered.
        let mut c2 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c2, 0x11).await;
        answer_one_request(&mut c2, b"second").await;
        // Keep the task alive so the connection is not torn down early.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .build()
        .await
        .expect("initial connect");

    let r1 = client.get("/one").send().await.expect("first request");
    assert_eq!(r1.status(), 200);
    assert_eq!(r1.bytes(), b"first");

    // The server dropped the channel after the first response. The next
    // request must transparently reconnect (re-attest) and succeed once the
    // background reader has observed that drop.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r2 = client.get("/two").send().await.expect("second request after reconnect");
    assert_eq!(r2.status(), 200);
    assert_eq!(r2.bytes(), b"second");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "SDK should have opened a second connection (reconnect)"
    );
}

/// Opening a new stream after the previous attested channel dropped performs
/// the same reconnect and re-attestation preflight as a one-shot request.
#[tokio::test]
async fn channel_dropped_before_new_stream_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");
    let accepted = Arc::new(AtomicUsize::new(0));

    let server_accepted = accepted.clone();
    tokio::spawn(async move {
        let mut c1 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c1, 0x11).await;
        drop(c1);

        let mut c2 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c2, 0x11).await;
        answer_one_upgrade(&mut c2).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .build()
        .await
        .expect("initial connect");

    // Give the transport reader time to observe the server-side close. A
    // replacement stream must then use a fresh, fully-attested connection.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        client.upgrade(
            Method::Get,
            "/v1/ws",
            &[
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
            ],
        ),
    )
    .await
    .expect("stream reconnect must not hang")
    .expect("stream should open after reconnect");
    drop(stream);

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "opening a replacement stream should reconnect exactly once"
    );
}

/// All clones that discover the same dropped channel share one reconnect
/// attempt and use the sender installed by its winner.
#[tokio::test]
async fn concurrent_requests_share_one_reconnect() {
    const CALLERS: usize = 8;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");
    let accepted = Arc::new(AtomicUsize::new(0));

    let server_accepted = accepted.clone();
    tokio::spawn(async move {
        let mut c1 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c1, 0x11).await;
        answer_one_request(&mut c1, b"first").await;
        drop(c1);

        let mut c2 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c2, 0x11).await;
        for _ in 0..CALLERS {
            answer_one_request(&mut c2, b"shared").await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .build()
        .await
        .expect("initial connect");

    let first = client.get("/first").send().await.expect("first request");
    assert_eq!(first.bytes(), b"first");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let barrier = Arc::new(Barrier::new(CALLERS + 1));
    let mut requests = Vec::with_capacity(CALLERS);
    for index in 0..CALLERS {
        let client = client.clone();
        let barrier = barrier.clone();
        requests.push(tokio::spawn(async move {
            barrier.wait().await;
            client.get(&format!("/concurrent/{index}")).send().await
        }));
    }
    barrier.wait().await;

    tokio::time::timeout(Duration::from_secs(5), async move {
        for request in requests {
            let response = request
                .await
                .expect("request task should not panic")
                .expect("request should succeed after the shared reconnect");
            assert_eq!(response.bytes(), b"shared");
        }
    })
    .await
    .expect("concurrent reconnect should not hang");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "concurrent callers should establish only one replacement session"
    );
}

/// A request whose channel drops WHILE IT IS IN FLIGHT is not silently
/// re-sent (it may already have executed). It surfaces as a retryable
/// error; the caller's explicit retry then succeeds on a freshly
/// re-established, re-attested channel.
#[tokio::test]
async fn inflight_drop_surfaces_retryable_then_retry_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");
    let accepted = Arc::new(AtomicUsize::new(0));

    let server_accepted = accepted.clone();
    tokio::spawn(async move {
        // First connection: attest, RECEIVE the request, then drop WITHOUT
        // answering (the enclave died mid-request).
        let mut c1 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c1, 0x11).await;
        receive_one_request(&mut c1).await;
        drop(c1);

        // Second connection: only the caller's explicit retry reaches here.
        // Re-attest (same PCRs) and answer. The SDK sends a request on this
        // connection ONLY because the caller called send() again; it never
        // re-sent the in-flight one itself (reconnect does attestation, not
        // request replay).
        let mut c2 = accept_one(&listener).await;
        server_accepted.fetch_add(1, Ordering::SeqCst);
        do_attestation(&mut c2, 0x11).await;
        answer_one_request(&mut c2, b"second").await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .build()
        .await
        .expect("initial connect");

    // In-flight drop: a retryable error, not a hang and not a silent resend.
    let err = client
        .get("/one")
        .send()
        .await
        .expect_err("in-flight drop should surface an error, not resend");
    assert!(err.is_retryable(), "expected a retryable drop, got {err:?}");

    // The caller retries; the SDK reconnects + re-attests under the hood and
    // this fresh request succeeds.
    let r2 = client
        .get("/two")
        .send()
        .await
        .expect("retry after reconnect");
    assert_eq!(r2.bytes(), b"second");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "SDK should have reconnected exactly once"
    );
}

/// If the enclave's attestation no longer matches the pinned PCRs after a
/// restart, the reconnect FAILS CLOSED with an attestation error and does
/// NOT attach to the (differently-measured) enclave.
#[tokio::test]
async fn reconnect_fails_closed_on_pcr_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");

    tokio::spawn(async move {
        // First connection: attest with the PINNED seed, answer one
        // request, then drop.
        let mut c1 = accept_one(&listener).await;
        do_attestation(&mut c1, 0x11).await;
        answer_one_request(&mut c1, b"first").await;
        drop(c1);

        // Every subsequent reconnect attempt presents a DIFFERENT
        // measurement (seed 0x22 => different PCRs), as if the enclave was
        // upgraded to an unpinned image. The SDK must refuse each one.
        loop {
            let mut c = match tokio::time::timeout(Duration::from_secs(5), accept_one(&listener))
                .await
            {
                Ok(c) => c,
                Err(_) => break,
            };
            // The client's re-attestation runs verify_against with the
            // pinned PCRs; seed 0x22 does not match, so verify fails and
            // the client tears the connection down. We just need to serve
            // the wrong doc; the request is never answered.
            do_attestation(&mut c, 0x22).await;
        }
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .build()
        .await
        .expect("initial connect");

    let r1 = client.get("/one").send().await.expect("first request");
    assert_eq!(r1.bytes(), b"first");

    // The channel dropped; the next request reconnects, re-attests against a
    // mismatched measurement, and must fail closed with a distinct
    // attestation error rather than silently connecting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = client
        .get("/two")
        .send()
        .await
        .expect_err("reconnect must fail closed on PCR mismatch");
    match err {
        enclavia::Error::Attestation(_) => {}
        other => panic!("expected fail-closed Error::Attestation, got {other:?}"),
    }
}

/// With reconnect disabled, a dropped channel surfaces as an error (the
/// pre-reconnect behavior), never a silent retry.
#[tokio::test]
async fn reconnect_disabled_surfaces_the_drop() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");

    tokio::spawn(async move {
        let mut c1 = accept_one(&listener).await;
        do_attestation(&mut c1, 0x11).await;
        answer_one_request(&mut c1, b"first").await;
        drop(c1);
        // No further connections are accepted; if the SDK tried to
        // reconnect it would hang, but with reconnect disabled it must
        // surface the drop immediately.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let client = Client::builder(&url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .auto_reconnect(false)
        .build()
        .await
        .expect("initial connect");

    let r1 = client.get("/one").send().await.expect("first request");
    assert_eq!(r1.bytes(), b"first");

    let err = tokio::time::timeout(
        Duration::from_secs(3),
        client.get("/two").send(),
    )
    .await
    .expect("must not hang when reconnect is disabled")
    .expect_err("dropped channel must surface an error");
    match err {
        enclavia::Error::ConnectionClosed | enclavia::Error::WebSocket(_) => {}
        other => panic!("expected a transport-drop error, got {other:?}"),
    }

    let stream_result = tokio::time::timeout(
        Duration::from_secs(3),
        client.open_stream(Vec::new()),
    )
    .await
    .expect("opening a stream must not hang when reconnect is disabled");
    assert!(matches!(
        stream_result,
        Err(enclavia::Error::ConnectionClosed | enclavia::Error::WebSocket(_))
    ));
}
