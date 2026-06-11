//! Synchronizer node listener.
//!
//! Accepts CBOR-framed customer RPC connections, dispatches each through a
//! [`SessionDispatch`](synchronizer::listener::SessionDispatch), and writes
//! responses back. Transport is selected at compile time via the `debug` and
//! `enclave` features (mutually exclusive in practice; the rest of the workspace
//! follows the same pattern):
//!
//! - `debug` listens on a Unix domain socket (env: `LISTEN_PATH`). The
//!   attestation verifier uses the `decode_attestation_document` debug
//!   path (skip cert chain), matching what QEMU's self-signing NSM emits.
//! - `enclave` listens on vsock (env: `VSOCK_PORT`, default
//!   [`SYNCHRONIZER_CLIENT_PORT`] = 5010). The verifier requires a full
//!   Nitro CA-chain-signed attestation document.
//!
//! ## Single-node vs replicated (#120 / #121, slice 4)
//!
//! Without the `raft` feature (or when the mesh env is not configured) the node
//! is a single-node [`Node`](synchronizer::Node): it verifies + applies every
//! request against one local state machine. With the `raft` feature AND a
//! configured peer mesh, the node joins the 3-node replicated cluster: a
//! [`ReplicatedDispatch`](synchronizer::raft::ReplicatedDispatch) routes each
//! request to the cluster leader (forwarding over the mesh when this node is a
//! follower) and serves reads linearizably. The exactly-one-node bootstrap and
//! the hydrate-on-restart precondition are documented on
//! [`start_replicated_from_env`].

use std::sync::Arc;

#[cfg(feature = "enclave")]
use enclavia_protocol::mesh::SYNCHRONIZER_CLIENT_PORT;
use synchronizer::Node;
use synchronizer::listener::{SessionDispatch, handle_connection};
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
/// attestation-validation path (skip-cert-chain vs full chain), and to the
/// Node / replicated dispatcher for the `Transition` chain-link check.
#[cfg(feature = "debug")]
const DEBUG_MODE: bool = true;
#[cfg(feature = "enclave")]
const DEBUG_MODE: bool = false;

/// Host CID the in-enclave node dials to reach `mesh-host`. Always 2 (the
/// parent under real Nitro; the vhost-device-vsock bridge under QEMU debug),
/// so the mesh transport is vsock in both binary variants, regardless of the
/// `debug`/`enclave` split (which only governs the customer-facing listener).
#[cfg(any(feature = "mesh", feature = "raft"))]
const VSOCK_HOST_CID: u32 = 2;

/// The pieces read from the mesh environment, shared by the single-node
/// (echo-handler) and replicated (raft-handler) wiring paths.
///
/// Env (all required together to enable the mesh):
/// * `MESH_SELF_NAME`  - this node's logical name (matches what `mesh-host`
///   resolves).
/// * `MESH_PEERS`      - comma-separated logical names of the other nodes.
///
/// The self-PCR digest that gates the allowlist is NOT read from the
/// environment: it is derived at startup from a fresh attestation document this
/// node requests from its OWN `/dev/nsm` (see [`read_mesh_env`]). The host is
/// the adversary, so a host-supplied digest would let it admit a rogue image
/// into the mesh and Raft; the local NSM device is inside the TCB and measures
/// this exact VM, identically on real Nitro and under QEMU's nitro-enclave
/// machine.
#[cfg(any(feature = "mesh", feature = "raft"))]
struct MeshEnv {
    self_name: String,
    config: synchronizer::mesh::config::MeshConfig,
    identity: synchronizer::mesh::identity::MeshIdentity,
    dialer: synchronizer::mesh::transport::VsockMeshDialer,
    acceptor: synchronizer::mesh::transport::VsockMeshAcceptor,
}

/// Read the mesh environment, build the config + identity + transports. Returns
/// `None` when no peer set is configured (single-node deployments), a required
/// value is missing, or the startup self-attestation fails.
///
/// ## Self-PCR digest: derived from `/dev/nsm`, never from the host
///
/// The self-PCR allowlist admits a peer only when the peer's attested PCR
/// digest equals THIS node's own image measurements. Those measurements are
/// obtained here by requesting a fresh attestation document from the node's own
/// `/dev/nsm` (with an arbitrary nonce / user_data, since there is no session or
/// peer to bind to) and reading back PCR0/1/2 with
/// [`extract_own_pcrs`](enclavia_protocol::attestation::extract_own_pcrs). The
/// host is the adversary: a host-supplied digest (the old `MESH_SELF_PCR*` env
/// vars) would let it choose an allowlist that admits a rogue image into the
/// mesh and Raft. The local NSM device is inside the node's TCB and measures
/// this exact VM identically on real Nitro and under QEMU's nitro-enclave
/// machine, so no cert-chain trust is needed (the node is reading its own
/// hardware, not authenticating a remote party). If the NSM request or parse
/// fails there is NO env fallback (that would reopen the hole): the mesh stays
/// disabled and the node runs single-node, with a loud error log.
#[cfg(any(feature = "mesh", feature = "raft"))]
fn read_mesh_env() -> Option<MeshEnv> {
    use enclavia_protocol::attestation::extract_own_pcrs;
    use enclavia_protocol::mesh::{MESH_VSOCK_PORT, SYNCHRONIZER_BOOTSTRAP_PORT};
    use synchronizer::PcrKey;
    use synchronizer::mesh::attestation::request_own_attestation;
    use synchronizer::mesh::config::MeshConfig;
    use synchronizer::mesh::identity::MeshIdentity;
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

    // Self-attestation: request a document from our own /dev/nsm and read back
    // our hardware-measured PCRs. nonce/user_data are irrelevant here (no
    // session, no peer to bind to), so we pass placeholders. No env fallback on
    // failure: the host must not be able to pick this digest.
    let self_doc = match request_own_attestation(None, None) {
        Ok(doc) => doc,
        Err(e) => {
            error!(error = %e, "self-attestation from /dev/nsm failed; mesh disabled (single-node mode)");
            return None;
        }
    };
    let self_pcrs = match extract_own_pcrs(&self_doc) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "failed to parse own /dev/nsm attestation document; mesh disabled (single-node mode)");
            return None;
        }
    };
    let self_digest = PcrKey(self_pcrs.digest());
    info!("derived self-PCR digest from /dev/nsm for the mesh allowlist");

    let config = MeshConfig::new(self_name.clone(), peers, self_digest);
    let identity = MeshIdentity::generate();
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

    Some(MeshEnv {
        self_name,
        config,
        identity,
        dialer,
        acceptor,
    })
}

/// Start the mutually-attested peer mesh (#118) with the no-op echo handler,
/// used in the non-`raft` build (the mesh stands up but nothing drives it).
/// Returns the running [`Mesh`](synchronizer::mesh::Mesh) so `main` keeps it
/// alive; `None` when no peer set is configured.
#[cfg(all(feature = "mesh", not(feature = "raft")))]
fn start_mesh_from_env() -> Option<synchronizer::mesh::Mesh> {
    use enclavia_protocol::mesh::{MESH_VSOCK_PORT, SYNCHRONIZER_BOOTSTRAP_PORT};
    use synchronizer::mesh::Mesh;
    use synchronizer::mesh::attestation::NsmAttestor;
    use synchronizer::mesh::rpc::EchoHandler;

    let env = read_mesh_env()?;
    let attestor = NsmAttestor::new(&env.identity);
    info!(
        self_name = %env.self_name,
        peers = ?env.config.peers,
        bootstrap_port = SYNCHRONIZER_BOOTSTRAP_PORT,
        mesh_port = MESH_VSOCK_PORT,
        "starting mutually-attested peer mesh (single-node binary, echo handler)"
    );
    Some(Mesh::start(
        env.config,
        env.dialer,
        env.acceptor,
        attestor,
        env.identity,
        EchoHandler,
        DEBUG_MODE,
    ))
}

/// Start the replicated cluster (#119 mesh + Raft + #209 membership): build the
/// mesh with a deferred [`RaftRequestHandler`], stand up the [`RaftHandle`] over
/// it (whose id is the per-boot instance key, #209), enable serving forwarded
/// client requests AND inbound membership joins, then drive the discovery/join
/// state machine in the background.
///
/// Returns the running mesh (held for the process lifetime), the handle, and a
/// [`ReplicatedDispatch`](synchronizer::raft::ReplicatedDispatch) the listener
/// uses for every customer connection. `None` when no peer set is configured.
///
/// ## Discovery, join, and exactly-once initialize (#209)
///
/// There is no fixed bootstrap node any more. Each node runs
/// [`discover_and_join`](synchronizer::raft::discover_and_join): it probes peers
/// for a live cluster (a Join doubles as the probe) and is admitted for its
/// configured slot; ONLY when no peer reports a cluster within a discovery
/// window AND this node holds the lexicographically-smallest configured name
/// does it initialize a FRESH cluster from the peers' channel-attested pubkeys.
/// That probe-first window plus the "only initialize when no peer knows a
/// cluster" rule is the safety property that stops a restarted smallest-name
/// node from re-initializing a SECOND cluster over a live one (split brain).
/// The candidate pubkey the leader admits always comes from the join's attested
/// mesh channel, never a payload (the #209 SECURITY CONTRACT). Once a voter, the
/// node watches for eviction by a same-slot replacement
/// ([`watch_for_eviction`](synchronizer::raft::watch_for_eviction)) and shuts
/// its Raft down if it is replaced.
///
/// ## Hydrate-on-restart (#121) + cold-start precondition (#122)
///
/// A node restarted with EMPTY in-memory state and a FRESH instance key JOINs
/// (evicting its dead old id for the slot) and hydrates the full view from the
/// survivors over the mesh (log replay, or an InstallSnapshot transfer once the
/// leader's log has purged past what the node is missing). openraft's
/// `loosen-follower-log-revert` mode (enabled in `Cargo.toml`) is what lets an
/// empty-log node rejoin without the leader panicking on its log reversion.
/// Operational precondition: durability is purely N-replica in-memory, so NEVER
/// lose all three nodes simultaneously. TWO simultaneous losses leave the old
/// config without quorum and the cluster halts (a fresh joiner is not admitted),
/// the deliberate #209 availability trade and the #122 recovery boundary.
#[cfg(feature = "raft")]
async fn start_replicated_from_env() -> Option<(
    Arc<synchronizer::mesh::Mesh>,
    synchronizer::raft::RaftHandle,
    synchronizer::raft::ReplicatedDispatch,
)> {
    use enclavia_protocol::mesh::{MESH_VSOCK_PORT, SYNCHRONIZER_BOOTSTRAP_PORT};
    use synchronizer::mesh::Mesh;
    use synchronizer::mesh::attestation::NsmAttestor;
    use synchronizer::raft::{RaftHandle, RaftRequestHandler, ReplicatedDispatch};

    let env = read_mesh_env()?;
    let attestor = NsmAttestor::new(&env.identity);
    // The deduped peer set (== Raft membership minus self), captured before the
    // config is moved into the mesh. The per-boot instance pubkey is captured
    // too: it is this node's clone-resistant Raft id (#209).
    let self_name = env.self_name.clone();
    let self_pubkey = env.identity.pubkey();
    let peers = env.config.peers.clone();

    info!(
        self_name = %self_name,
        peers = ?peers,
        bootstrap_port = SYNCHRONIZER_BOOTSTRAP_PORT,
        mesh_port = MESH_VSOCK_PORT,
        "starting replicated cluster (mesh + raft)"
    );

    // 1. Deferred Raft handler, installed as the mesh's inbound handler so peer
    //    RPCs (forwarded client requests + membership joins) reach this node
    //    once the Raft is wired in.
    let handler = RaftRequestHandler::deferred();
    let mesh = Arc::new(Mesh::start(
        env.config,
        env.dialer,
        env.acceptor,
        attestor,
        env.identity,
        handler.clone(),
        DEBUG_MODE,
    ));

    // 2. Stand up the local Raft over the mesh, installing the live Raft into
    //    the deferred handler. The Raft id is instance_node_id(self_pubkey).
    let raft = match RaftHandle::new(
        Arc::clone(&mesh),
        &self_name,
        self_pubkey,
        &peers,
        handler.clone(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "failed to construct RaftHandle");
            return None;
        }
    };

    // 3. Enable serving forwarded client requests AND inbound membership joins
    //    on this node (any node may become the leader and admit a joiner).
    raft.enable_serving(&handler, DEBUG_MODE);

    // 4. Discovery + join (#209): probe peers for a live cluster and be
    //    admitted for our slot; or, when this node holds the smallest
    //    configured name and NO peer reports a cluster within the discovery
    //    window, initialize a fresh one from the peers' channel-attested
    //    pubkeys. A restart with a fresh key takes the join path, NEVER a
    //    re-initialize, even on the bootstrap-name node (see
    //    [`synchronizer::raft::join`]). Runs in the background so the listener
    //    can come up immediately; the dispatcher returns `Unavailable` until
    //    this node is a voter.
    {
        let raft_for_join = raft.clone();
        let mesh_for_join = Arc::clone(&mesh);
        tokio::spawn(async move {
            synchronizer::raft::discover_and_join(&raft_for_join, &mesh_for_join).await;
            // Once a voter, watch for eviction by a same-slot replacement and
            // stop serving if it happens.
            synchronizer::raft::watch_for_eviction(raft_for_join).await;
        });
    }

    let dispatch = ReplicatedDispatch::new(raft.clone(), Arc::clone(&mesh), DEBUG_MODE);
    Some((mesh, raft, dispatch))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    // Build the request dispatcher. With the `raft` feature AND a configured
    // mesh, this is the replicated cluster; otherwise the single-node Node. The
    // mesh / raft handle are held for the process lifetime (dropping them aborts
    // the dial / accept / openraft tasks).
    #[cfg(feature = "raft")]
    let (dispatch, _mesh, _raft): (Arc<dyn SessionDispatch>, _, _) =
        match start_replicated_from_env().await {
            Some((mesh, raft, replicated)) => {
                info!("serving customer RPC through the replicated cluster");
                (Arc::new(replicated), Some(mesh), Some(raft))
            }
            None => {
                info!("no mesh configured, serving customer RPC as a single node");
                (
                    Arc::new(Node::with_debug_mode(DEBUG_MODE)),
                    None::<Arc<synchronizer::mesh::Mesh>>,
                    None::<synchronizer::raft::RaftHandle>,
                )
            }
        };

    // Non-raft build: single-node Node, plus (if `mesh` is on) the echo-handler
    // mesh stood up but not driven.
    #[cfg(not(feature = "raft"))]
    let dispatch: Arc<dyn SessionDispatch> = Arc::new(Node::with_debug_mode(DEBUG_MODE));
    #[cfg(all(feature = "mesh", not(feature = "raft")))]
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
                    let dispatch = Arc::clone(&dispatch);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(dispatch.as_ref(), stream, DEBUG_MODE).await
                        {
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
        // VMADDR_CID_ANY: accept connections on any CID.
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
                    let dispatch = Arc::clone(&dispatch);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(dispatch.as_ref(), stream, DEBUG_MODE).await
                        {
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
