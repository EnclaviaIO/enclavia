//! Integration tests for one-shot requests whose request or response does
//! not fit in a single Noise transport message (65535 bytes of ciphertext).
//!
//! The harness mimics enclavia-server's stream handling: a request arrives
//! as `OpenStream` plus `StreamData` frames, the workload's response goes
//! back as `StreamData` frames of at most 16 KiB followed by `StreamClose`
//! at workload EOF, and the server keeps each stream (and one of its 64
//! in-flight slots) until the client sends `StreamClose { Both }`. The
//! harness enforces that slot limit, so a client that never releases its
//! finished request streams fails here as it would against a real enclave.
//! Payloads are encoded the way enclavia-server encodes them.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use enclavia::{Client, Pcrs};
use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{
    perform_cbor_handshake_as_responder, ClientMessage, ServerMessage, StreamHalf,
};
use tokio::net::TcpListener;

#[path = "ws_adapter.rs"]
mod ws_adapter;
use ws_adapter::wrap_ws;

/// Workload read chunk used by enclavia-server's stream pump.
const SERVER_CHUNK: usize = 16 * 1024;
/// enclavia-server's per-session in-flight stream limit.
const MAX_IN_FLIGHT: usize = 64;
/// The server's error when writing the rest of a request to a workload
/// that already closed its connection.
const BROKEN_PIPE: &str = "Broken pipe (os error 32)";

/// Body of `GET /big`: every byte value, so the CBOR encoding of the
/// payload cannot shrink below one byte per body byte.
fn big_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut resp = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    resp
}

/// What the workload does with the request bytes received so far.
enum Reply {
    /// Needs more request bytes.
    Pending,
    /// Read the whole request and answered; closed its connection after
    /// the response if `eof`.
    Answer { response: Vec<u8>, eof: bool },
    /// Answered from the head alone and closed without reading the body:
    /// the server relays these bytes, then fails writing the rest of the
    /// request.
    Early(Vec<u8>),
}

/// The workload.
fn workload(buf: &[u8]) -> Reply {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf).expect("valid HTTP request") {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Reply::Pending,
    };
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| std::str::from_utf8(h.value).unwrap())
    };
    assert_eq!(header("host"), Some("127.0.0.1"), "SDK must set the Host header");
    assert_eq!(header("connection"), Some("close"), "SDK must ask the workload to close");
    let content_length = header("content-length").map_or(0, |v| v.parse::<usize>().unwrap());
    let (method, path) = (req.method.unwrap(), req.path.unwrap());

    match (method, path) {
        ("POST", "/early") => return Reply::Early(http_response("413 Payload Too Large", b"no")),
        // Closes after a partial response: nothing provably complete.
        ("POST", "/early-truncated") => {
            return Reply::Early(http_response("413 Payload Too Large", b"no")[..20].to_vec())
        }
        _ => {}
    }

    if buf.len() < head_len + content_length {
        return Reply::Pending;
    }
    assert_eq!(buf.len(), head_len + content_length, "no bytes past the body");
    let body = &buf[head_len..];
    let (response, eof) = match (method, path) {
        ("GET", "/big") => (http_response("200 OK", &big_body(200 * 1024)), true),
        ("POST", "/echo") => (http_response("200 OK", body), true),
        ("GET", "/small") => (http_response("200 OK", b"ok"), true),
        // Keeps the connection open after a complete response.
        ("GET", "/no-eof") => (http_response("200 OK", &big_body(40 * 1024)), false),
        // No Content-Length: the body ends at connection close.
        ("GET", "/close-delimited") => {
            let mut resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
            resp.extend_from_slice(&big_body(40 * 1024));
            (resp, true)
        }
        _ => (http_response("404 Not Found", b"not found"), true),
    };
    Reply::Answer { response, eof }
}

/// What the mock enclave observed over the session.
#[derive(Default)]
struct Stats {
    connections: AtomicUsize,
    answered: AtomicUsize,
    closed: AtomicUsize,
    /// Largest request frame, in payload bytes.
    max_frame: AtomicUsize,
}

/// Serve one attested session per accepted connection, enclavia-server
/// style, until the client goes away.
async fn spawn_mock_enclave(stats: Arc<Stats>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            // enclavia-server writes to vsock, which has no Nagle delay.
            tcp.set_nodelay(true).unwrap();
            stats.connections.fetch_add(1, Ordering::SeqCst);
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (mut transport, hash) = perform_cbor_handshake_as_responder(wrap_ws(ws))
                .await
                .unwrap();

            match transport.receive::<ClientMessage>().await.unwrap() {
                ClientMessage::RequestAttestation => {}
                other => panic!("expected RequestAttestation, got {other:?}"),
            }
            let doc = FakeAttestation::with_seed(0x11, hash).encode();
            transport
                .send(&ServerMessage::Attestation { data: doc, control_nonce: [0u8; 32] })
                .await
                .unwrap();

            // Request bytes received so far, per stream not yet answered.
            let mut receiving: HashMap<u64, Vec<u8>> = HashMap::new();
            // Streams holding an in-flight slot (opened, not yet closed by
            // the client).
            let mut open: HashSet<u64> = HashSet::new();

            loop {
                // A receive error means the client went away.
                let Some(msg) = transport.receive::<ClientMessage>().await.ok() else {
                    break;
                };
                let id = match msg {
                    ClientMessage::OpenStream { id, payload } => {
                        assert!(
                            open.len() < MAX_IN_FLIGHT,
                            "client exhausted the server's in-flight streams"
                        );
                        stats.max_frame.fetch_max(payload.len(), Ordering::SeqCst);
                        open.insert(id);
                        receiving.insert(id, payload);
                        id
                    }
                    ClientMessage::StreamData { id, payload } => {
                        stats.max_frame.fetch_max(payload.len(), Ordering::SeqCst);
                        match receiving.get_mut(&id) {
                            Some(buf) => buf.extend_from_slice(&payload),
                            None => {
                                // The stream's pump is gone; this is what
                                // enclavia-server answers.
                                transport
                                    .send(&ServerMessage::Error {
                                        id,
                                        message: "unknown stream id".into(),
                                    })
                                    .await
                                    .unwrap();
                                continue;
                            }
                        }
                        id
                    }
                    ClientMessage::StreamClose { id, half: StreamHalf::Both } => {
                        assert!(
                            !receiving.contains_key(&id),
                            "client closed stream {id} before its response"
                        );
                        if open.remove(&id) {
                            stats.closed.fetch_add(1, Ordering::SeqCst);
                        }
                        continue;
                    }
                    other => panic!("unexpected client message {other:?}"),
                };

                match workload(&receiving[&id]) {
                    Reply::Pending => {}
                    Reply::Answer { response, eof } => {
                        receiving.remove(&id);
                        for chunk in response.chunks(SERVER_CHUNK) {
                            transport
                                .send(&ServerMessage::StreamData { id, payload: chunk.to_vec() })
                                .await
                                .unwrap();
                        }
                        if eof {
                            transport.send(&ServerMessage::StreamClose { id }).await.unwrap();
                        }
                        stats.answered.fetch_add(1, Ordering::SeqCst);
                    }
                    Reply::Early(bytes) => {
                        receiving.remove(&id);
                        // The pump exits on the write error and frees its
                        // slot without waiting for the client's close.
                        open.remove(&id);
                        transport
                            .send(&ServerMessage::StreamData { id, payload: bytes })
                            .await
                            .unwrap();
                        transport
                            .send(&ServerMessage::Error { id, message: BROKEN_PIPE.into() })
                            .await
                            .unwrap();
                    }
                }
            }
        }
    });
    format!("ws://127.0.0.1:{port}")
}

fn pcrs_for_seed(seed: u8) -> Pcrs {
    Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    }
}

async fn connect(url: &str) -> Client {
    // Reconnect off: every request below must succeed on the ONE channel.
    Client::builder(url)
        .debug_mode(true)
        .pcrs(pcrs_for_seed(0x11))
        .auto_reconnect(false)
        .build()
        .await
        .expect("connect")
}

/// A response far larger than one Noise message arrives intact, a request
/// body far larger than one Noise message reaches the workload intact, and
/// the channel keeps serving requests afterwards.
#[tokio::test]
async fn large_response_and_large_request_body_on_one_channel() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    let big = tokio::time::timeout(Duration::from_secs(10), client.get("/big").send())
        .await
        .expect("large response must not hang")
        .expect("large response");
    assert_eq!(big.status(), 200);
    assert_eq!(big.bytes().len(), 200 * 1024);
    assert!(big.bytes() == big_body(200 * 1024).as_slice(), "large body corrupted");

    let small = client.get("/small").send().await.expect("request after large response");
    assert_eq!(small.bytes(), b"ok");

    // 0xff costs two CBOR bytes per byte: the largest encoding a request
    // frame can have.
    let upload = vec![0xffu8; 100 * 1024];
    let echoed = tokio::time::timeout(
        Duration::from_secs(10),
        client.post("/echo").body(upload.clone()).send(),
    )
    .await
    .expect("large request body must not hang")
    .expect("large request body");
    assert_eq!(echoed.status(), 200);
    assert!(echoed.bytes() == upload.as_slice(), "echoed body corrupted");
    assert!(stats.max_frame.load(Ordering::SeqCst) < upload.len(), "body split into frames");

    let small = client.get("/small").send().await.expect("request after large body");
    assert_eq!(small.bytes(), b"ok");

    assert_eq!(stats.connections.load(Ordering::SeqCst), 1, "one channel throughout");
    assert_eq!(stats.answered.load(Ordering::SeqCst), 4);
}

/// A request that fits in one Noise message goes out as a single frame, so
/// the workload receives it in one write.
#[tokio::test]
async fn request_that_fits_one_message_is_one_frame() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    let upload = vec![0xffu8; 30 * 1024];
    let echoed = client.post("/echo").body(upload.clone()).send().await.expect("echo");
    assert!(echoed.bytes() == upload.as_slice());
    assert!(stats.max_frame.load(Ordering::SeqCst) > upload.len(), "whole request in one frame");
}

/// Every finished request releases its server-side stream. Sequential
/// requests well past the server's in-flight limit keep working on one
/// channel, and the server sees one `StreamClose { Both }` per request.
#[tokio::test]
async fn finished_requests_release_their_server_streams() {
    const REQUESTS: usize = 3 * MAX_IN_FLIGHT;

    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    for i in 0..REQUESTS {
        let resp = tokio::time::timeout(Duration::from_secs(5), client.get("/small").send())
            .await
            .unwrap_or_else(|_| panic!("request {i} hung"))
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        assert_eq!(resp.bytes(), b"ok");
    }

    // The close for the last request is sent right after its response is
    // delivered; give it a moment to reach the server.
    tokio::time::timeout(Duration::from_secs(5), async {
        while stats.closed.load(Ordering::SeqCst) < REQUESTS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every finished request stream must be closed");
    assert_eq!(stats.connections.load(Ordering::SeqCst), 1);
}

/// A response with a Content-Length is returned once its body is in, without
/// waiting for the workload to close, and its stream is still released.
#[tokio::test]
async fn response_with_known_length_does_not_wait_for_eof() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    let resp = tokio::time::timeout(Duration::from_secs(5), client.get("/no-eof").send())
        .await
        .expect("must not wait for workload EOF")
        .expect("response");
    assert!(resp.bytes() == big_body(40 * 1024).as_slice());

    tokio::time::timeout(Duration::from_secs(5), async {
        while stats.closed.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stream released");
}

/// A response without a Content-Length ends at workload EOF, intact.
#[tokio::test]
async fn close_delimited_response_ends_at_eof() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    let resp = client.get("/close-delimited").send().await.expect("response");
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes() == big_body(40 * 1024).as_slice());
}

/// A non-2xx workload status is returned as a response, not an error.
#[tokio::test]
async fn non_success_status_is_returned_as_a_response() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;

    let resp = client.get("/missing").send().await.expect("404 response");
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.bytes(), b"not found");
}

/// A workload that answers before reading a large body: its complete
/// response is returned; a response cut short is an error. Either way the
/// channel keeps working.
#[tokio::test]
async fn workload_answering_before_reading_the_body() {
    let stats = Arc::new(Stats::default());
    let url = spawn_mock_enclave(stats.clone()).await;
    let client = connect(&url).await;
    let upload = vec![b'x'; 200 * 1024];

    let resp = client
        .post("/early")
        .body(upload.clone())
        .send()
        .await
        .expect("complete early response is the answer");
    assert_eq!(resp.status(), 413);
    assert_eq!(resp.bytes(), b"no");

    let err = client
        .post("/early-truncated")
        .body(upload)
        .send()
        .await
        .expect_err("truncated response is an error");
    match err {
        enclavia::Error::ServerError { message, .. } => assert_eq!(message, BROKEN_PIPE),
        other => panic!("expected ServerError, got {other:?}"),
    }

    let small = client.get("/small").send().await.expect("channel still alive");
    assert_eq!(small.bytes(), b"ok");
    assert_eq!(stats.connections.load(Ordering::SeqCst), 1);
}
