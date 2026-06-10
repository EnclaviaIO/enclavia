//! Synchronizer single-node listener.
//!
//! Accepts CBOR-framed RPC connections, dispatches each to a shared
//! [`Node`], and writes responses back. Transport is selected at compile
//! time via the `debug` and `enclave` features (mutually exclusive in
//! practice; the rest of the workspace follows the same pattern):
//!
//! - `debug` listens on a Unix domain socket (env: `LISTEN_PATH`). The
//!   attestation verifier uses the `decode_attestation_document` debug
//!   path (skip cert chain), matching what QEMU's self-signing NSM emits.
//! - `enclave` listens on vsock (env: `VSOCK_PORT`, default
//!   [`SYNCHRONIZER_CLIENT_PORT`] = 5010). The verifier requires a full
//!   Nitro CA-chain-signed attestation document.

use std::sync::Arc;

#[cfg(feature = "enclave")]
use enclavia_protocol::mesh::SYNCHRONIZER_CLIENT_PORT;
use synchronizer::Node;
use synchronizer::listener::handle_connection;
use tracing::{error, info, warn};

#[cfg(all(feature = "debug", feature = "enclave"))]
compile_error!("synchronizer: enable exactly one of the `debug` and `enclave` features");

#[cfg(not(any(feature = "debug", feature = "enclave")))]
compile_error!("synchronizer: enable one of the `debug` or `enclave` features");

/// Default vsock port the in-enclave listener serves customer RPC on.
/// Settled in the #16 design pass (the interim 5004 collided with
/// `secrets-host`); see [`enclavia_protocol::mesh::SYNCHRONIZER_CLIENT_PORT`].
#[cfg(feature = "enclave")]
const DEFAULT_VSOCK_PORT: u32 = SYNCHRONIZER_CLIENT_PORT;

/// Picked at compile time from the `debug`/`enclave` feature pair. Passed
/// to [`handle_connection`] so the listener picks the matching
/// attestation-validation path (skip-cert-chain vs full chain).
#[cfg(feature = "debug")]
const DEBUG_MODE: bool = true;
#[cfg(feature = "enclave")]
const DEBUG_MODE: bool = false;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    // The Node carries the same `debug_mode` the listener passes to
    // `handle_connection`: it selects the skip-cert-chain vs full-Nitro-CA
    // path used when verifying a `Transition`'s chain-link attestation.
    let node = Arc::new(Node::with_debug_mode(DEBUG_MODE));

    #[cfg(feature = "debug")]
    {
        let path = std::env::var("LISTEN_PATH").unwrap_or_else(|_| {
            // Sensible-ish default for local dev; the launcher sets it
            // explicitly in the test harness.
            "/tmp/enclavia-synchronizer.sock".into()
        });
        // Remove a leftover socket from a previous run; ignore failure
        // (it might genuinely not exist).
        let _ = std::fs::remove_file(&path);
        let listener = match tokio::net::UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                error!(path = %path, error = %e, "failed to bind UDS");
                std::process::exit(1);
            }
        };
        info!(path = %path, "synchronizer listening on UDS");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let node = Arc::clone(&node);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(&node, stream, DEBUG_MODE).await {
                            warn!(error = %e, "connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept failed");
                }
            }
        }
    }

    #[cfg(feature = "enclave")]
    {
        let port: u32 = std::env::var("VSOCK_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_VSOCK_PORT);
        // VMADDR_CID_ANY — accept connections on any CID.
        let cid: u32 = u32::MAX;
        let mut listener = match tokio_vsock::VsockListener::bind(cid, port) {
            Ok(l) => l,
            Err(e) => {
                error!(port, error = %e, "failed to bind vsock");
                std::process::exit(1);
            }
        };
        info!(port, "synchronizer listening on vsock");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let node = Arc::clone(&node);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(&node, stream, DEBUG_MODE).await {
                            warn!(error = %e, "connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept failed");
                }
            }
        }
    }
}
