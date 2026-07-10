//! End-to-end test of the in-enclave egress daemon's outward path
//! WITHOUT the TUN+smoltcp piece: the test spins up the same
//! `egress-host` relay the production binary talks to, dials it over
//! UDS (via the `test-utils` UdsTransport), pushes bytes through one
//! [`forward_flow`] invocation, and asserts the round-trip against a
//! tokio TCP echo server.
//!
//! Why no real TUN: a real TUN device requires `CAP_NET_ADMIN` (or
//! root) and a network namespace, which makes this test fragile on
//! shared CI runners. The TUN-to-smoltcp path is exercised by the
//! `parse_new_tcp_syn_*` unit tests, and the splice path is exercised
//! here. Real-TUN coverage is planned once the CI environment is
//! reliably namespace-capable.

#![cfg(feature = "test-utils")]

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use std::sync::Arc;

use enclavia_egress::{
    forward_flow, AllowAll, AllowlistConfig, ForwardError, MockResolver, StaticAllowlistPolicy,
    UdsTransport,
};
use enclavia_protocol::egress::{read_open_frame, Open};

/// Test-local stand-in for the host-side `egress-host` relay. Reads one
/// `Open` frame, dials the requested IPv4 destination, splices bytes. The
/// production relay (the host-side `egress-host` crate, which lives
/// outside this repository) has the same shape; we re-implement it
/// here so this workspace has no dependency on it.
async fn handle_connection<S>(mut stream: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let open = read_open_frame(&mut stream)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    match open {
        Open::Tcp { host, port } => {
            let addr = SocketAddr::from((host, port));
            let mut upstream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(_) => return Ok(()), // mirror egress-host: drop the stream on connect failure
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            Ok(())
        }
    }
}

/// Spin up a fake egress-host UDS relay on `path`, mirroring the production
/// vsock listener but addressable from the test process.
async fn spawn_egress_host(path: PathBuf) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind egress-host UDS");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = handle_connection(stream).await;
            });
        }
    })
}

async fn spawn_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (port, handle)
}

#[tokio::test]
async fn forward_flow_round_trips_through_egress_host() {
    let tmp = TempDir::new().expect("tempdir");
    let uds = tmp.path().join("egress.sock");
    let _host = spawn_egress_host(uds.clone()).await;
    let (echo_port, _echo) = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // The forwarder takes a generic AsyncRead+Write as the "local"
    // side; in production that is the smoltcp FlowStream, here it is
    // a Unix socket pair that the test drives.
    let (mut workload, daemon_side) = UnixStream::pair().expect("pair");
    let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_port);

    let transport = UdsTransport { path: uds };
    let policy = AllowAll;
    let forwarder = tokio::spawn(async move {
        forward_flow(SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 40000), dst, daemon_side, &transport, &policy).await
    });

    let payload = b"hello enclavia egress";
    workload.write_all(payload).await.expect("write");
    workload.flush().await.expect("flush");

    let mut received = vec![0u8; payload.len()];
    workload
        .read_exact(&mut received)
        .await
        .expect("read echo");
    assert_eq!(&received[..], payload);

    drop(workload);
    let _ = tokio::time::timeout(Duration::from_secs(2), forwarder)
        .await
        .expect("forwarder returns");
}

#[tokio::test]
async fn forward_flow_surfaces_destination_unreachable() {
    // egress-host running, but the destination port is closed.
    // egress-host's connect fails, closes the UDS stream, the
    // forwarder's bidirectional copy finishes cleanly. The "workload"
    // side sees EOF, which is what smoltcp would translate to a TCP
    // RST surfaced as ECONNREFUSED to the actual workload.
    let tmp = TempDir::new().expect("tempdir");
    let uds = tmp.path().join("egress.sock");
    let _host = spawn_egress_host(uds.clone()).await;

    let dead_port = {
        let lst = TcpListener::bind("127.0.0.1:0").await.unwrap();
        lst.local_addr().unwrap().port()
    };

    tokio::time::sleep(Duration::from_millis(20)).await;

    let (mut workload, daemon_side) = UnixStream::pair().expect("pair");
    let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, dead_port);

    let transport = UdsTransport { path: uds };
    let policy = AllowAll;
    let forwarder = tokio::spawn(async move {
        forward_flow(SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 40000), dst, daemon_side, &transport, &policy).await
    });

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), workload.read(&mut buf))
        .await
        .expect("read returns within timeout")
        .expect("read");
    assert_eq!(n, 0, "expected EOF after egress-host close");

    // copy_bidirectional only returns once both halves EOF; drop the
    // workload end so the daemon-side read of the splice surfaces EOF
    // and the forwarder finishes.
    drop(workload);
    let _ = tokio::time::timeout(Duration::from_secs(2), forwarder)
        .await
        .expect("forwarder returns");
}

#[tokio::test]
async fn forward_flow_denies_when_policy_rejects() {
    // The transport is never dialed when the policy denies the flow.
    // Point at a non-existent UDS so the test fails loudly if the
    // policy gets bypassed and the daemon falls through to a transport
    // dial.
    let tmp = TempDir::new().expect("tempdir");
    let uds = tmp.path().join("never-dialed.sock");

    let (_workload, daemon_side) = UnixStream::pair().expect("pair");
    let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

    let transport = UdsTransport { path: uds };
    // Allowlist exists but doesn't cover `dst`: expect Denied.
    let cfg = AllowlistConfig::from_bytes(
        br#"{ "version": 1, "egress": [
            {"host":"1.2.3.4","port":443,"protocol":"tcp"}
        ] }"#,
    )
    .expect("parse allowlist");
    let policy = StaticAllowlistPolicy::new(cfg, Arc::new(MockResolver::new()), Ipv4Addr::new(10, 99, 0, 1));
    let result = forward_flow(SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 40000), dst, daemon_side, &transport, &policy).await;
    assert!(matches!(result, Err(ForwardError::Denied(_))));
}

#[tokio::test]
async fn forward_flow_surfaces_transport_failure() {
    // Point the transport at a non-existent UDS path; the dial fails
    // before any frame goes out.
    let tmp = TempDir::new().expect("tempdir");
    let uds = tmp.path().join("missing.sock");

    let (_workload, daemon_side) = UnixStream::pair().expect("pair");
    let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);

    let transport = UdsTransport { path: uds };
    let policy = AllowAll;
    let result = forward_flow(SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 40000), dst, daemon_side, &transport, &policy).await;
    assert!(matches!(
        result,
        Err(enclavia_egress::ForwardError::Transport(_))
    ));
}
