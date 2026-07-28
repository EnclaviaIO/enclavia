//! Synchronizer customer-RPC stress bench (QEMU debug harness).
//!
//! Same session setup as `mesh_client` (proxy UDS -> `connect 5010\n` ->
//! Noise -> synthetic client attestation -> #208 server attestation
//! verify), then hammers the cluster: M concurrent sessions, each with a
//! DISTINCT seed (distinct PcrKey), issuing N sequential RPCs and
//! recording per-op latency.
//!
//! Modes:
//!   pin  - each op is a `Pin` with a varying commitment. Op 0 of each
//!          session is the Register (first pin); it is reported in a
//!          separate bucket so registration cost never pollutes the
//!          steady-state numbers.
//!   get  - each op is a linearizable `Get` (the key must exist, so the
//!          session issues ONE untimed Pin first). This isolates the
//!          ReadIndex quorum round from the write path: on the current
//!          serve path a Pin is roughly Get + commit + full-replication
//!          wait, so (pin - get) attributes the write-side cost.
//!
//! Usage:
//!   pin_bench <proxy-uds> --server-pcrs <pcr.json> \
//!       [--sessions M] [--ops N] [--mode pin|get] [--port P] \
//!       [--seed-base S] [--csv <path>]
//!
//! `--csv` appends one line per op: `mode,session,op,micros,ok` so runs
//! can be diffed across code revisions.

use std::time::{Duration, Instant};

use enclavia_protocol::attestation::Pcrs;
use enclavia_protocol::attestation::test_utils::FakeAttestation;
use enclavia_protocol::{NoiseTransport, perform_handshake_as_initiator};
use p256::ecdsa::SigningKey;
use synchronizer::listener::Frame;
use synchronizer::wire::{Request, Response};
use synchronizer::{Commitment, PcrKey};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const MAX_FRAME_SIZE: usize = 65535;

/// Per-RPC ceiling. Generous: the serve path's replication_wait is 2s
/// and a retryable client would reconnect, but the bench treats any op
/// this slow as a failure worth counting, not retrying.
const OP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct Args {
    proxy: String,
    server_pcrs: String,
    sessions: usize,
    ops: usize,
    mode: String,
    port: u32,
    seed_base: u8,
    csv: Option<String>,
}

fn parse_args() -> Args {
    let usage = "usage: pin_bench <proxy-uds> --server-pcrs <pcr.json> [--sessions M] [--ops N] [--mode pin|get] [--port P] [--seed-base S] [--csv path]";
    let mut a = std::env::args().skip(1);
    let proxy = a.next().expect(usage);
    let mut sessions = 1usize;
    let mut ops = 100usize;
    let mut mode = "pin".to_string();
    let mut port = 5010u32;
    let mut seed_base = 0x60u8;
    let mut server_pcrs: Option<String> = None;
    let mut csv: Option<String> = None;
    let rest: Vec<String> = a.collect();
    let mut i = 0;
    while i < rest.len() {
        let val = |i: usize| rest.get(i + 1).unwrap_or_else(|| panic!("{usage}")).clone();
        match rest[i].as_str() {
            "--sessions" => sessions = val(i).parse().expect("bad --sessions"),
            "--ops" => ops = val(i).parse().expect("bad --ops"),
            "--mode" => mode = val(i),
            "--port" => port = val(i).parse().expect("bad --port"),
            "--seed-base" => {
                let v = val(i);
                let v = v.trim_start_matches("0x");
                seed_base = u8::from_str_radix(v, 16).expect("bad --seed-base");
            }
            "--server-pcrs" => server_pcrs = Some(val(i)),
            "--csv" => csv = Some(val(i)),
            other => panic!("unexpected arg {other}; {usage}"),
        }
        i += 2;
    }
    assert!(mode == "pin" || mode == "get", "bad --mode (pin|get)");
    assert!(sessions >= 1 && sessions <= 150, "--sessions must be 1..=150 (u8 seed space)");
    Args {
        proxy,
        server_pcrs: server_pcrs.expect("--server-pcrs <pcr.json> is required"),
        sessions,
        ops,
        mode,
        port,
        seed_base,
        csv,
    }
}

fn load_expected_pcrs(path: &str) -> Pcrs {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read server pcrs {path}: {e}"));
    let extract = |name: &str| -> Vec<u8> {
        let key = format!("\"{name}\"");
        let start = text
            .find(&key)
            .unwrap_or_else(|| panic!("{name} not found in {path}"));
        let after = &text[start + key.len()..];
        let colon = after.find(':').expect("malformed pcr.json (no colon)");
        let rest = &after[colon + 1..];
        let open = rest.find('"').expect("malformed pcr.json (no open quote)");
        let tail = &rest[open + 1..];
        let close = tail.find('"').expect("malformed pcr.json (no close quote)");
        hex::decode(&tail[..close]).unwrap_or_else(|e| panic!("{name} is not hex: {e}"))
    };
    Pcrs {
        pcr0: extract("PCR0"),
        pcr1: extract("PCR1"),
        pcr2: extract("PCR2"),
    }
}

fn key_from_seed(seed: u8) -> PcrKey {
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
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read OK line");
    assert!(
        line.trim_start().starts_with("OK"),
        "vhost rejected connect: {line:?}"
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

async fn read_plaintext<S>(stream: &mut S, t: &mut NoiseTransport) -> Vec<u8>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.expect("read len");
    let len = u32::from_be_bytes(len_bytes) as usize;
    assert!(len <= MAX_FRAME_SIZE, "inbound frame too large: {len}");
    let mut ct = vec![0u8; len];
    stream.read_exact(&mut ct).await.expect("read ct");
    let mut pt = vec![0u8; MAX_FRAME_SIZE];
    let n = t.read_message(&ct, &mut pt).expect("noise decrypt");
    pt.truncate(n);
    pt
}

async fn read_response<S>(stream: &mut S, t: &mut NoiseTransport) -> Response
where
    S: AsyncReadExt + Unpin,
{
    let pt = read_plaintext(stream, t).await;
    ciborium::from_reader(pt.as_slice()).expect("cbor decode response")
}

struct Session {
    stream: UnixStream,
    transport: NoiseTransport,
    key: PcrKey,
}

async fn open_session(args: &Args, expected: &Pcrs, seed: u8) -> Session {
    use synchronizer::wire::{ServerPcrPolicy, verify_server_attestation};

    let mut stream = proxy_connect(&args.proxy, args.port).await;
    let (mut transport, handshake_hash) = perform_handshake_as_initiator(&mut stream)
        .await
        .expect("noise handshake");

    let mut scalar = [0u8; 32];
    scalar[0] = 0x01;
    scalar[1] = seed;
    let sk = SigningKey::from_slice(&scalar).expect("p256 key");
    let pk_pt = sk.verifying_key().to_encoded_point(false);
    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(pk_pt.as_bytes());

    let fake = FakeAttestation::with_seed_and_pubkey(seed, handshake_hash.clone(), pubkey);
    let key = key_from_seed(seed);
    write_frame(
        &mut stream,
        &mut transport,
        &Frame::Authenticate {
            nsm_doc: fake.encode(),
        },
    )
    .await;

    let pt = read_plaintext(&mut stream, &mut transport).await;
    let frame: Frame = ciborium::from_reader(pt.as_slice()).expect("cbor decode server frame");
    let nsm_doc = match frame {
        Frame::Authenticate { nsm_doc } => nsm_doc,
        other => panic!("expected the node's Authenticate frame, got {other:?}"),
    };
    verify_server_attestation(
        &nsm_doc,
        &handshake_hash,
        &ServerPcrPolicy::Expected(vec![expected.clone()]),
        /* debug_mode */ true,
    )
    .expect("server attestation must verify");

    Session {
        stream,
        transport,
        key,
    }
}

/// One timed RPC. Returns (micros, ok).
async fn timed_op(sess: &mut Session, req: Request) -> (u64, bool) {
    let start = Instant::now();
    write_frame(&mut sess.stream, &mut sess.transport, &Frame::Rpc { request: req }).await;
    let resp = tokio::time::timeout(OP_TIMEOUT, read_response(&mut sess.stream, &mut sess.transport))
        .await;
    let micros = start.elapsed().as_micros() as u64;
    let ok = matches!(
        resp,
        Ok(Response::PinOk { .. }) | Ok(Response::GetOk { .. })
    );
    if !ok {
        eprintln!("[bench] op failed: {resp:?}");
    }
    (micros, ok)
}

#[derive(Default)]
struct SessionResult {
    /// (op index, micros, ok) per timed op.
    ops: Vec<(usize, u64, bool)>,
    /// Micros for the session's Register (first pin), pin mode only.
    register_micros: Option<u64>,
    setup_micros: u64,
}

fn commitment_for(seed: u8, op: usize) -> Commitment {
    let mut c = [0u8; 32];
    c[0] = seed;
    c[1] = (op & 0xff) as u8;
    c[2] = ((op >> 8) & 0xff) as u8;
    c[3] = 0xbe;
    Commitment(c)
}

async fn run_session(args: Args, expected: Pcrs, idx: usize) -> SessionResult {
    let seed = args.seed_base.wrapping_add(idx as u8);
    let setup_start = Instant::now();
    let mut sess = open_session(&args, &expected, seed).await;
    let mut result = SessionResult {
        setup_micros: setup_start.elapsed().as_micros() as u64,
        ..Default::default()
    };

    let key = sess.key;
    if args.mode == "pin" {
        // Op 0 is the Register: time it into its own bucket.
        let (us, ok) = timed_op(
            &mut sess,
            Request::Pin {
                key,
                commitment: commitment_for(seed, 0),
            },
        )
        .await;
        result.register_micros = Some(us);
        if !ok {
            return result;
        }
        for op in 1..=args.ops {
            let (us, ok) = timed_op(
                &mut sess,
                Request::Pin {
                    key,
                    commitment: commitment_for(seed, op),
                },
            )
            .await;
            result.ops.push((op, us, ok));
            if !ok {
                break;
            }
        }
    } else {
        // get mode: one untimed Pin so the key exists, then timed Gets.
        let (_, ok) = timed_op(
            &mut sess,
            Request::Pin {
                key,
                commitment: commitment_for(seed, 0),
            },
        )
        .await;
        if !ok {
            return result;
        }
        for op in 1..=args.ops {
            let (us, ok) = timed_op(&mut sess, Request::Get { key }).await;
            result.ops.push((op, us, ok));
            if !ok {
                break;
            }
        }
    }
    result
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn summarize(label: &str, micros: &mut Vec<u64>) {
    micros.sort_unstable();
    let n = micros.len();
    if n == 0 {
        println!("{label}: no samples");
        return;
    }
    let sum: u64 = micros.iter().sum();
    println!(
        "{label}: n={n} mean={:.1}ms p50={:.1}ms p90={:.1}ms p99={:.1}ms p999={:.1}ms max={:.1}ms",
        sum as f64 / n as f64 / 1000.0,
        percentile(micros, 0.50) as f64 / 1000.0,
        percentile(micros, 0.90) as f64 / 1000.0,
        percentile(micros, 0.99) as f64 / 1000.0,
        percentile(micros, 0.999) as f64 / 1000.0,
        micros[n - 1] as f64 / 1000.0,
    );
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    eprintln!(
        "[bench] proxy={} mode={} sessions={} ops={} port={} seed-base=0x{:02x}",
        args.proxy, args.mode, args.sessions, args.ops, args.port, args.seed_base
    );
    let expected = load_expected_pcrs(&args.server_pcrs);

    let wall = Instant::now();
    let mut handles = Vec::new();
    for idx in 0..args.sessions {
        let args = args.clone();
        let expected = expected.clone();
        handles.push(tokio::spawn(run_session(args, expected, idx)));
    }
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.expect("session task panicked"));
    }
    let wall = wall.elapsed();

    let mut steady: Vec<u64> = Vec::new();
    let mut registers: Vec<u64> = Vec::new();
    let mut setups: Vec<u64> = Vec::new();
    let mut ok_ops = 0usize;
    let mut failed_ops = 0usize;
    let mut csv_lines = String::new();
    for (sidx, r) in results.iter().enumerate() {
        setups.push(r.setup_micros);
        if let Some(us) = r.register_micros {
            registers.push(us);
        }
        for (op, us, ok) in &r.ops {
            if *ok {
                ok_ops += 1;
                steady.push(*us);
            } else {
                failed_ops += 1;
            }
            csv_lines.push_str(&format!(
                "{},{},{},{},{}\n",
                args.mode, sidx, op, us, *ok as u8
            ));
        }
    }

    println!(
        "== pin_bench mode={} sessions={} ops/session={} wall={:.2}s ok={} failed={} throughput={:.1} op/s ==",
        args.mode,
        args.sessions,
        args.ops,
        wall.as_secs_f64(),
        ok_ops,
        failed_ops,
        ok_ops as f64 / wall.as_secs_f64(),
    );
    summarize("steady   ", &mut steady);
    summarize("register ", &mut registers);
    summarize("setup    ", &mut setups);

    if let Some(path) = &args.csv {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open csv");
        f.write_all(csv_lines.as_bytes()).expect("write csv");
        eprintln!("[bench] appended {} lines to {path}", ok_ops + failed_ops);
    }

    if failed_ops > 0 {
        std::process::exit(4);
    }
}
