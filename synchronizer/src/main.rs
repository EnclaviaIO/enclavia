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

/// Host CID the in-enclave node dials to reach `mesh-host`. Always 2 (the
/// parent under real Nitro; the vhost-device-vsock bridge under QEMU debug),
/// so the mesh transport is vsock in both binary variants, regardless of the
/// `debug`/`enclave` split (which only governs the customer-facing listener).
const VSOCK_HOST_CID: u32 = 2;

/// Start the mutually-attested peer mesh (#118) from the environment, if
/// configured. Returns the running [`synchronizer::mesh::Mesh`] so `main`
/// keeps it (and its dial / accept tasks) alive for the process lifetime;
/// returns `None` when no peer set is configured (single-node deployments).
///
/// Env (all required together to enable the mesh):
/// * `MESH_SELF_NAME`  - this node's logical name (matches what `mesh-host`
///   resolves).
/// * `MESH_PEERS`      - comma-separated logical names of the other nodes.
/// * `MESH_SELF_PCR0`, `MESH_SELF_PCR1`, `MESH_SELF_PCR2` - hex-encoded PCR
///   measurements of THIS node's own EIF (the build output). The self-PCR
///   allowlist admits a peer only if its attested PCR digest equals
///   `sha256(PCR0||PCR1||PCR2)` of these. Configured at launch because a
///   debug enclave cannot trust its own fake attestation as a reference.
///
/// The node generates a fresh per-boot P-256 mesh identity, reaches
/// `mesh-host` over vsock ([`enclavia_protocol::mesh::MESH_VSOCK_PORT`]) and
/// listens for relayed-in peer connections on
/// [`enclavia_protocol::mesh::SYNCHRONIZER_BOOTSTRAP_PORT`]. Inbound requests
/// are served by an echo handler until slice 3 (openraft) supplies the real
/// one.
fn start_mesh_from_env() -> Option<synchronizer::mesh::Mesh> {
    use enclavia_protocol::attestation::Pcrs;
    use enclavia_protocol::mesh::{MESH_VSOCK_PORT, SYNCHRONIZER_BOOTSTRAP_PORT};
    use synchronizer::PcrKey;
    use synchronizer::mesh::Mesh;
    use synchronizer::mesh::attestation::NsmAttestor;
    use synchronizer::mesh::config::MeshConfig;
    use synchronizer::mesh::identity::MeshIdentity;
    use synchronizer::mesh::rpc::EchoHandler;
    use synchronizer::mesh::transport::{VsockMeshAcceptor, VsockMeshDialer};

    let self_name = std::env::var("MESH_SELF_NAME").ok()?;
    let peers_raw = std::env::var("MESH_PEERS").ok()?;
    let peers: Vec<String> = peers_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if peers.is_empty() {
        warn!("MESH_PEERS was empty, not starting the peer mesh");
        return None;
    }

    let decode_pcr = |name: &str| -> Option<Vec<u8>> {
        let hexed = std::env::var(name).ok()?;
        match hex::decode(hexed.trim()) {
            Ok(b) => Some(b),
            Err(e) => {
                error!(var = name, error = %e, "MESH_SELF_PCR* is not valid hex");
                None
            }
        }
    };
    let self_pcrs = Pcrs {
        pcr0: decode_pcr("MESH_SELF_PCR0")?,
        pcr1: decode_pcr("MESH_SELF_PCR1")?,
        pcr2: decode_pcr("MESH_SELF_PCR2")?,
    };
    let self_digest = PcrKey(self_pcrs.digest());

    let config = MeshConfig::new(self_name.clone(), peers.clone(), self_digest);
    let identity = MeshIdentity::generate();
    let attestor = NsmAttestor::new(&identity);
    let dialer = VsockMeshDialer {
        cid: VSOCK_HOST_CID,
        port: MESH_VSOCK_PORT,
    };
    let acceptor = match VsockMeshAcceptor::bind(SYNCHRONIZER_BOOTSTRAP_PORT) {
        Ok(a) => a,
        Err(e) => {
            error!(port = SYNCHRONIZER_BOOTSTRAP_PORT, error = %e, "failed to bind mesh bootstrap vsock listener");
            return None;
        }
    };

    info!(
        self_name = %self_name,
        peers = ?config.peers,
        bootstrap_port = SYNCHRONIZER_BOOTSTRAP_PORT,
        mesh_port = MESH_VSOCK_PORT,
        "starting mutually-attested peer mesh"
    );
    Some(Mesh::start(
        config,
        dialer,
        acceptor,
        attestor,
        identity,
        EchoHandler,
        DEBUG_MODE,
    ))
}

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

    // Start the mutually-attested peer mesh (#118) if configured. Held in
    // `_mesh` for the process lifetime: dropping it would abort the dial /
    // accept tasks. Slice 2 only stands the mesh up (boot-time attestation,
    // reconnect, the call/serve RPC surface); the Raft layer that drives it
    // lands in slice 3, so nothing reads `_mesh` here yet.
    let _mesh = start_mesh_from_env();

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
