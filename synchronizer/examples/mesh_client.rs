//! Synchronizer customer-RPC smoke client (QEMU debug harness).
//!
//! Adapted from `enclavia-router/examples/smoke_test.rs`: that one speaks
//! the enclavia-server Noise+CBOR `ClientMessage`/`ServerMessage` shape
//! over a router WebSocket; this one speaks the synchronizer's
//! `wire::Request`/`Response` over a `vhost-device-vsock` proxy UDS.
//!
//! Flow against one node:
//!   1. Connect the node's `vhost-device-vsock` proxy UDS and send
//!      `connect <port>\n`; expect `OK <port>\n`. The socket is then a
//!      byte stream to the guest's customer vsock port (5010).
//!   2. `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake (initiator).
//!   3. Send `Frame::Authenticate { nsm_doc }`, a synthetic
//!      `FakeAttestation` whose nonce binds to the handshake hash and
//!      whose `user_data` carries a real 65-byte SEC1 P-256 control
//!      pubkey. The node runs in skip-cert-chain (debug) mode, so the
//!      synthetic COSE_Sign1 is accepted; the session binds to
//!      `PcrKey = SHA-256(PCR0||PCR1||PCR2)` derived from the seed.
//!   4. Send one `Frame::Rpc { request }` (Pin or Get) and print the
//!      decoded `Response`.
//!
//! The PCR seed is fixed (`--seed`, default 0x42) so a Pin on one node
//! and a Get on another reference the SAME key, exercising the cluster's
//! cross-node forwarding + linearizable read.
//!
//! Usage:
//!   mesh_client <proxy-uds> pin <commitment-hex-byte> [--port P] [--seed S]
//!   mesh_client <proxy-uds> get [--port P] [--seed S]

use std::time::Duration;

use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{NoiseTransport, perform_handshake_as_initiator};
use p256::ecdsa::SigningKey;
use synchronizer::listener::Frame;
use synchronizer::wire::{Request, Response};
use synchronizer::{Commitment, PcrKey};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const MAX_FRAME_SIZE: usize = 65535;

#[derive(Debug)]
struct Args {
    proxy: String,
    cmd: String,
    commitment_byte: u8,
    port: u32,
    seed: u8,
}

fn parse_args() -> Args {
    let mut a = std::env::args().skip(1);
    let proxy = a
        .next()
        .expect("usage: mesh_client <proxy-uds> <pin|get> [commitment-hex] [--port P] [--seed S]");
    let cmd = a.next().expect("missing command (pin|get)");
    let mut commitment_byte = 0xc0u8;
    let mut port = 5010u32;
    let mut seed = 0x42u8;
    let rest: Vec<String> = a.collect();
    let mut i = 0;
    // Positional commitment byte for `pin`.
    if cmd == "pin" && i < rest.len() && !rest[i].starts_with("--") {
        commitment_byte = parse_hex_byte(&rest[i]);
        i += 1;
    }
    while i < rest.len() {
        match rest[i].as_str() {
            "--port" => {
                let v = rest.get(i + 1).expect("--port requires a value");
                port = v.parse().expect("bad --port");
                i += 2;
            }
            "--seed" => {
                let v = rest.get(i + 1).expect("--seed requires a value");
                seed = parse_hex_byte(v);
                i += 2;
            }
            other => panic!("unexpected arg {other}"),
        }
    }
    Args {
        proxy,
        cmd,
        commitment_byte,
        port,
        seed,
    }
}

fn parse_hex_byte(s: &str) -> u8 {
    let s = s.trim_start_matches("0x");
    u8::from_str_radix(s, 16).unwrap_or_else(|_| s.parse().expect("bad byte value"))
}

/// `key_from_seed`, matching `FakeAttestation::with_seed`'s PCRs and the
/// listener's `PcrKey(identity.pcrs.digest())` derivation.
fn key_from_seed(seed: u8) -> PcrKey {
    use enclavia_protocol::attestation::Pcrs;
    let raw = Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    };
    PcrKey(raw.digest())
}

async fn proxy_connect(proxy: &str, port: u32) -> UnixStream {
    let mut stream = UnixStream::connect(proxy)
        .await
        .unwrap_or_else(|e| panic!("connect proxy {proxy}: {e}"));
    stream
        .write_all(format!("connect {port}\n").as_bytes())
        .await
        .expect("write connect cmd");
    // Read the single `OK <port>\n` line. Use a small BufReader on a
    // borrowed handle so we don't consume buffered post-OK bytes (there
    // are none before our handshake write, so this is safe).
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read OK line");
    assert!(
        line.trim_start().starts_with("OK"),
        "vhost rejected connect: {line:?}"
    );
    eprintln!(
        "[client] proxy connected to vsock port {port}: {}",
        line.trim()
    );
    stream
}

async fn write_frame<S>(stream: &mut S, t: &mut NoiseTransport, frame: &Frame)
where
    S: AsyncWriteExt + Unpin,
{
    let mut plaintext = Vec::new();
    ciborium::into_writer(frame, &mut plaintext).expect("cbor encode frame");
    let mut ct = vec![0u8; MAX_FRAME_SIZE];
    let n = t.write_message(&plaintext, &mut ct).expect("noise encrypt");
    stream
        .write_all(&(n as u32).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&ct[..n]).await.expect("write ct");
    stream.flush().await.expect("flush");
}

async fn read_response<S>(stream: &mut S, t: &mut NoiseTransport) -> Response
where
    S: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.expect("read len");
    let len = u32::from_be_bytes(len_bytes) as usize;
    assert!(len <= MAX_FRAME_SIZE, "response frame too large: {len}");
    let mut ct = vec![0u8; len];
    stream.read_exact(&mut ct).await.expect("read ct");
    let mut pt = vec![0u8; MAX_FRAME_SIZE];
    let n = t.read_message(&ct, &mut pt).expect("noise decrypt");
    ciborium::from_reader(&pt[..n]).expect("cbor decode response")
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    eprintln!(
        "[client] proxy={} cmd={} port={} seed=0x{:02x}",
        args.proxy, args.cmd, args.port, args.seed
    );

    let mut stream = proxy_connect(&args.proxy, args.port).await;

    let (mut transport, handshake_hash) = perform_handshake_as_initiator(&mut stream)
        .await
        .expect("noise handshake");
    eprintln!("[client] Noise handshake complete");

    // Authenticate: synthetic NSM doc bound to this handshake, real
    // P-256 control pubkey so a (hypothetical) Transition could verify
    // and so Register freezes a decodable pubkey.
    let mut scalar = [0u8; 32];
    scalar[0] = 0x01;
    scalar[1] = args.seed;
    let sk = SigningKey::from_slice(&scalar).expect("p256 key");
    let pk_pt = sk.verifying_key().to_encoded_point(false);
    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(pk_pt.as_bytes());

    let fake = FakeAttestation::with_seed_and_pubkey(args.seed, handshake_hash.clone(), pubkey);
    let session_key = key_from_seed(args.seed);
    write_frame(
        &mut stream,
        &mut transport,
        &Frame::Authenticate {
            nsm_doc: fake.encode(),
        },
    )
    .await;
    eprintln!(
        "[client] authenticated; session key = {}",
        hex(&session_key.0)
    );

    let request = match args.cmd.as_str() {
        "pin" => Request::Pin {
            key: session_key,
            commitment: Commitment([args.commitment_byte; 32]),
        },
        "get" => Request::Get { key: session_key },
        other => panic!("unknown command {other}"),
    };

    write_frame(&mut stream, &mut transport, &Frame::Rpc { request }).await;

    let resp = tokio::time::timeout(
        Duration::from_secs(20),
        read_response(&mut stream, &mut transport),
    )
    .await
    .expect("timed out waiting for response");

    match &resp {
        Response::PinOk { version } => {
            println!("RESULT pin ok version={}", version.0);
        }
        Response::GetOk {
            commitment,
            version,
        } => {
            println!(
                "RESULT get ok commitment_byte=0x{:02x} version={}",
                commitment.0[0], version.0
            );
        }
        Response::Err { error } => {
            println!("RESULT error {error:?}");
            std::process::exit(3);
        }
        other => {
            println!("RESULT unexpected {other:?}");
            std::process::exit(3);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
