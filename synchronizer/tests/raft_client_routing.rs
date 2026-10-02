//! End-to-end client routing tests (#120 / #121, slice 4).
//!
//! Stands up an in-process 3-node replicated synchronizer over the test-utils
//! mesh transports (UDS + `MeshHostStub`, no QEMU / vsock) and, on top of each
//! node, runs the REAL customer listener (`handle_connection`) on its own UDS
//! backed by a [`ReplicatedDispatch`]. A test client speaks the genuine
//! customer wire protocol against any node's listener: Noise handshake, an
//! `Authenticate` frame carrying a `FakeAttestation`, then RPC frames.
//!
//! Exercises the slice-4 surface end to end:
//!
//! * (a) Pin then Get against the SAME node, in both the leader and non-leader
//!   cases (a follower forwards to the leader for both the write and the
//!   linearizable read). Each Pin ACK is immediately checked against the
//!   nodes' logs: under majority ACK the ACK itself guarantees the entry is on
//!   a quorum (no settle loop), and all three state machines then converge;
//! * Pin against one node, Get against ANOTHER (forwarding + linearizable
//!   read see the committed write regardless of which node the client dialed);
//! * (c) the full Transition flow with a real p256-signed #47 upgrade chain
//!   link: register the old key, then a new-enclave session submits the
//!   Transition; the old key retires and the carried version survives;
//! * (d) restart one node with EMPTY state, wait for it to hydrate from the
//!   survivors, then serve a Get from it (forwarded to the leader) and verify
//!   the three nodes' views are identical;
//! * (e) partition the LEADER: the survivors re-elect and keep ACKing writes
//!   (a quorum of two), reads keep working; after healing, the old leader
//!   catches up and all three agree;
//! * (b) partition a NON-leader and submit a Pin to the leader: it is ACKed on
//!   the remaining quorum. Then lose the LEADER and bring the partitioned node
//!   back: the only survivor holding the ACKed pin must win the election, so
//!   the pin is still served (an ACKed write survives the loss of any single
//!   node).
//!
//! Gated on `raft` + `test-utils` + `node` (the UDS transport + `FakeAttestor`
//! are never compiled into the production binary; `node` brings in the customer
//! listener these tests drive end to end). `raft` and `test-utils` both imply
//! `mesh` but not `node`, so the gate names `node` explicitly: run these with a
//! feature set that includes it, e.g. `--features raft,test-utils,debug`.
#![cfg(all(feature = "raft", feature = "test-utils", feature = "node"))]

use std::sync::Arc;
use std::time::Duration;

use enclavia_protocol::attestation::test_utils::{
    FakeAttestation, FakeChainAttestation, identity_from_seed,
};
use enclavia_protocol::attestation::{CONTROL_PUBKEY_LEN, Pcrs};
use enclavia_protocol::chain::{
    ChainLink, ChainLinkKind, RevocationPayload, UpgradePayload, upgrade_link_hash,
};
use enclavia_protocol::{NoiseTransport, perform_handshake_as_initiator};
use enclavia_protocol::signing::{SignedDomain, sign_control};
use p256::ecdsa::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use synchronizer::listener::{FakeSessionAttestor, Frame, MAX_FRAME_SIZE, handle_connection};
use synchronizer::mesh::Mesh;
use synchronizer::mesh::attestation::FakeAttestor;
use synchronizer::mesh::config::MeshConfig;
use synchronizer::mesh::identity::MeshIdentity;
use synchronizer::mesh::transport::{MeshHostStub, UdsMeshAcceptor};
use synchronizer::raft::forward::ROUTE_DEADLINE;
use synchronizer::raft::{COMMIT_TIMEOUT, RaftHandle, RaftRequestHandler, ReplicatedDispatch};
use synchronizer::wire::{Request, Response, RpcError};
use synchronizer::{Commitment, PcrKey, Version};

const IMAGE_SEED: u8 = 0x42;
const NODE_NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

// --- fixtures -------------------------------------------------------------

/// Deterministic P-256 keypair: the signing key + 65-byte SEC1 verifying-key
/// bytes the attestation document carries (and a transition link is signed by).
fn keypair(seed: u8) -> (SigningKey, [u8; CONTROL_PUBKEY_LEN]) {
    let mut scalar = [0u8; 32];
    scalar[0] = 0x01;
    scalar[1] = seed;
    let sk = SigningKey::from_slice(&scalar).unwrap();
    let pk_vec = sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let mut pk = [0u8; CONTROL_PUBKEY_LEN];
    pk.copy_from_slice(&pk_vec);
    (sk, pk)
}

fn c(b: u8) -> Commitment {
    Commitment([b; 32])
}

/// The PcrKey of a customer seed's identity. Matches both
/// `FakeAttestation::with_seed` (no user PCRs) and the transition-link
/// derivation.
fn key_from_seed(seed: u8) -> PcrKey {
    PcrKey(identity_from_seed(seed).key())
}

/// Build a #47 upgrade chain link `from_seed -> to_seed`, signed by the OLD
/// enclave's control key and attested for the OLD measurements.
fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
    let payload = UpgradePayload {
        enclave_id: uuid::Uuid::new_v4(),
        from: identity_from_seed(from_seed),
        to: identity_from_seed(to_seed),
        image_digest: "sha256:to".into(),
        valid_from: chrono::Utc::now(),
        valid_until: chrono::Utc::now() + chrono::Duration::days(7),
        issued_at: chrono::Utc::now(),
        nonce: vec![0x5a; 32],
    };
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
    let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
    let sig = sign_control(signing, SignedDomain::UpgradePayload, &payload_bytes);
    ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Upgrade,
        payload: payload_bytes,
        attestation,
        signature: Some(sig.to_vec()),
    }
}

// --- node harness ---------------------------------------------------------

/// One node: its mesh, Raft handle, replicated dispatcher, and a client
/// listener on its own UDS. Dropping it (mesh + listener task abort) is the
/// "kill the node" operation.
struct Node {
    name: String,
    /// Held for the node's lifetime so its dial/accept loops keep running;
    /// dropped (with the node) when the node is killed.
    _mesh: Arc<Mesh>,
    raft: RaftHandle,
    /// The UDS path the customer listener accepts on.
    client_sock: std::path::PathBuf,
    /// The customer-listener accept loop. ABORTED on drop: a leaked listener
    /// task would keep `Arc` clones of this node's mesh + raft alive past the
    /// "kill the node" drop, so the old mesh's dial/accept loops would never
    /// stop and the dead node would keep talking to its peers.
    listener_task: tokio::task::JoinHandle<()>,
    /// The background #209 discovery/join + eviction-watch task. Aborted on
    /// drop alongside the listener so a killed node fully stops.
    bootstrap_task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.listener_task.abort();
        self.bootstrap_task.abort();
    }
}

async fn spawn_node(name: &str, host: &MeshHostStub) -> Node {
    spawn_node_full(name, host, RaftHandle::default_config()).await
}

/// Like [`spawn_node`] but with a caller-chosen openraft config, so the
/// hydration test can force aggressive snapshotting + log purging (the
/// InstallSnapshot path proven in slice 3).
async fn spawn_node_with_config(
    name: &str,
    host: &MeshHostStub,
    raft_config: synchronizer::raft::Config,
) -> Node {
    spawn_node_full(name, host, raft_config).await
}

/// Full spawn: mesh, Raft, customer listener, and the #209 discovery task.
async fn spawn_node_full(
    name: &str,
    host: &MeshHostStub,
    raft_config: synchronizer::raft::Config,
) -> Node {
    let peers: Vec<String> = NODE_NAMES
        .iter()
        .copied()
        .filter(|n| *n != name)
        .map(|s| s.to_string())
        .collect();

    let dir = tempfile::tempdir().unwrap();
    let mesh_sock = dir.path().join(format!("{name}.mesh.sock"));
    let acceptor = UdsMeshAcceptor::bind(&mesh_sock).unwrap();
    host.register(name, &mesh_sock);

    let identity = MeshIdentity::generate();
    let self_pubkey = identity.pubkey();
    let attestor = FakeAttestor::new(IMAGE_SEED, &identity);
    let config = MeshConfig::new(
        name.to_string(),
        peers.clone(),
        FakeAttestor::pcr_digest(IMAGE_SEED),
    );

    let handler = RaftRequestHandler::deferred();
    let mesh = Arc::new(Mesh::start(
        config,
        host.dialer_for(name),
        acceptor,
        attestor,
        identity,
        handler.clone(),
        /* debug_mode */ true,
    ));

    let raft = RaftHandle::with_config(
        Arc::clone(&mesh),
        name,
        self_pubkey,
        &peers,
        handler.clone(),
        raft_config,
    )
    .await
    .expect("RaftHandle::with_config");
    raft.enable_serving(&handler, true);
    // Drive #209 discovery/join in the background: the smallest-name node
    // initializes the fresh cluster from peers' attested pubkeys, the others
    // join. Replaces the old single-node initialize_cluster the cluster helpers
    // used to call.
    let bootstrap_task = {
        let raft = raft.clone();
        let mesh = Arc::clone(&mesh);
        tokio::spawn(async move {
            synchronizer::raft::discover_and_join(&raft, &mesh).await;
            synchronizer::raft::watch_for_eviction(raft).await;
        })
    };

    // Stand up the real customer listener on its own UDS backed by the
    // replicated dispatcher.
    let dispatch: Arc<ReplicatedDispatch> = Arc::new(ReplicatedDispatch::new(
        raft.clone(),
        Arc::clone(&mesh),
        true,
    ));
    let client_sock = dir.path().join(format!("{name}.client.sock"));
    let _ = std::fs::remove_file(&client_sock);
    let client_listener = UnixListener::bind(&client_sock).unwrap();
    let listener_task = tokio::spawn(async move {
        loop {
            match client_listener.accept().await {
                Ok((stream, _)) => {
                    let dispatch = Arc::clone(&dispatch);
                    tokio::spawn(async move {
                        // The node attests its own sessions (#208) with the
                        // shared image seed, like every cluster member.
                        let attestor = FakeSessionAttestor { seed: IMAGE_SEED };
                        let _ = handle_connection(&*dispatch, &attestor, stream, true).await;
                    });
                }
                Err(_) => return,
            }
        }
    });

    Node {
        name: name.to_string(),
        _mesh: mesh,
        raft,
        client_sock,
        listener_task,
        bootstrap_task,
        _dir: dir,
    }
}

async fn current_leader(nodes: &[Node]) -> Option<&Node> {
    for n in nodes {
        if n.raft.is_leader().await {
            return Some(n);
        }
    }
    None
}

async fn await_leader(nodes: &[Node], timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if current_leader(nodes).await.is_some() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

// --- customer client over the listener's UDS ------------------------------

/// A customer session: a Noise transport over a UDS to one node's listener,
/// already authenticated as `session_key`.
struct Client {
    stream: UnixStream,
    transport: NoiseTransport,
    /// The capabilities the node advertised in its `Authenticate`.
    server_capabilities: std::collections::BTreeSet<String>,
}

impl Client {
    /// Connect to `node`'s customer listener, do the Noise handshake, and send
    /// the `Authenticate` frame for a session attested as `seed` with the
    /// supplied control pubkey.
    async fn connect(node: &Node, seed: u8, pubkey: [u8; CONTROL_PUBKEY_LEN]) -> Client {
        let mut stream = UnixStream::connect(&node.client_sock).await.unwrap();
        let (mut transport, hash) = perform_handshake_as_initiator(&mut stream).await.unwrap();
        let fake = FakeAttestation::with_seed_and_pubkey(seed, hash.clone(), pubkey);
        let auth = Frame::authenticate(fake.encode());
        write_frame(&mut stream, &mut transport, &auth).await;
        // Mutual auth (#208): the node answers with its own session-bound
        // attestation. Verify it against the cluster's shared image PCRs
        // before issuing RPCs, exactly as a real customer would.
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let mut ciphertext = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
        stream.read_exact(&mut ciphertext).await.unwrap();
        let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
        let pt_len = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        let frame: Frame = ciborium::from_reader(&plaintext[..pt_len]).unwrap();
        let (server_doc, server_capabilities) = match frame {
            Frame::Authenticate {
                nsm_doc,
                capabilities,
                ..
            } => (nsm_doc, capabilities),
            other => panic!("expected the node's Authenticate, got {other:?}"),
        };
        let expected = Pcrs {
            pcr0: vec![IMAGE_SEED; 48],
            pcr1: vec![IMAGE_SEED.wrapping_add(1); 48],
            pcr2: vec![IMAGE_SEED.wrapping_add(2); 48],
        };
        let policy = synchronizer::wire::ServerPcrPolicy::Expected(vec![expected]);
        synchronizer::wire::verify_server_attestation(&server_doc, &hash, &policy, true)
            .expect("node's server attestation must verify");
        Client {
            stream,
            transport,
            server_capabilities,
        }
    }

    /// Send one RPC and read the response.
    async fn rpc(&mut self, request: Request) -> Response {
        write_frame(
            &mut self.stream,
            &mut self.transport,
            &Frame::Rpc { request },
        )
        .await;
        read_response(&mut self.stream, &mut self.transport).await
    }

    /// CAS-aware Pin mirroring the nbd-client's recovery: issue the pin
    /// with `expected`; on `VersionConflict`, disambiguate with a Get —
    /// if the current commitment is ours, an earlier attempt of the SAME
    /// pin committed before its ack was lost (benign); anything else is
    /// a genuine fork and surfaces as-is. Returns the version the pin
    /// landed at, or the non-success response.
    async fn pin_cas(
        &mut self,
        key: PcrKey,
        expected: Version,
        commitment: Commitment,
    ) -> Result<Version, Response> {
        match self
            .rpc(Request::Pin {
                key,
                expected_version: expected,
                commitment,
            })
            .await
        {
            Response::PinOk { version } => Ok(version),
            Response::Err {
                error: RpcError::VersionConflict,
            } => match self.rpc(Request::Get { key }).await {
                Response::GetOk {
                    commitment: current,
                    version,
                } if current == commitment => Ok(version),
                other => Err(other),
            },
            other => Err(other),
        }
    }
}

async fn write_frame(stream: &mut UnixStream, transport: &mut NoiseTransport, frame: &Frame) {
    let mut plaintext = Vec::new();
    ciborium::into_writer(frame, &mut plaintext).unwrap();
    let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .unwrap();
    let len = ct_len as u32;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&ciphertext[..ct_len]).await.unwrap();
    stream.flush().await.unwrap();
}

async fn read_response(stream: &mut UnixStream, transport: &mut NoiseTransport) -> Response {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.unwrap();
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut ciphertext = vec![0u8; len];
    stream.read_exact(&mut ciphertext).await.unwrap();
    let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
    let pt_len = transport.read_message(&ciphertext, &mut plaintext).unwrap();
    ciborium::from_reader(&plaintext[..pt_len]).unwrap()
}

/// Bring up a fresh initialized 3-node cluster with a leader.
async fn cluster(host: &MeshHostStub) -> Vec<Node> {
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node(name, host).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node_full).
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader elected at startup"
    );
    nodes
}

/// Like [`cluster`] but every node runs `raft_config`.
async fn cluster_with_config(
    host: &MeshHostStub,
    raft_config: synchronizer::raft::Config,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node_with_config(name, host, raft_config.clone()).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node_full).
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader elected at startup"
    );
    nodes
}

fn find<'a>(nodes: &'a [Node], name: &str) -> &'a Node {
    nodes.iter().find(|n| n.name == name).unwrap()
}

/// The IMMEDIATE, no-settle-loop proof of the majority ACK: the moment a write
/// is ACKed, a QUORUM of the given nodes already holds the committed entry in
/// its LOG. This is the durability guarantee the design rests on (see the
/// `raft` module docs' "Majority ACK"): with the entry on a quorum, the loss of
/// any single node leaves a holder that no election can bypass.
///
/// Concretely: the leader applied the entry before ACKing, so the target is the
/// highest `last_applied` index among `nodes`; assert that more than half of
/// `cluster_size` nodes have `last_log_index >= target`. `nodes` may be a subset
/// of the cluster (e.g. only the reachable nodes during a partition), but the
/// quorum is always counted against the full `cluster_size`. NO loop: if this
/// is not true the instant the ACK returns, the majority ACK is broken.
fn assert_quorum_logged_committed(nodes: &[&Node], cluster_size: usize) {
    let target = nodes
        .iter()
        .filter_map(|n| {
            n.raft
                .raft()
                .metrics()
                .borrow()
                .last_applied
                .map(|l| l.index)
        })
        .max()
        .expect("at least one node has applied something");
    let holders: Vec<&str> = nodes
        .iter()
        .filter(|n| n.raft.raft().metrics().borrow().last_log_index.unwrap_or(0) >= target)
        .map(|n| n.name.as_str())
        .collect();
    assert!(
        holders.len() * 2 > cluster_size,
        "only {holders:?} hold committed index {target} right after the ACK; a quorum of \
         {cluster_size} must (majority ACK violated)"
    );
}

/// [`assert_quorum_logged_committed`] over a whole, healthy cluster.
fn assert_all_nodes_logged_committed(nodes: &[Node]) {
    let all: Vec<&Node> = nodes.iter().collect();
    assert_quorum_logged_committed(&all, nodes.len());
}

/// Assert EVERY node's state machine holds `key` at `version`. The majority
/// ACK guarantees the entry is in a quorum's LOG immediately (proven
/// separately, no loop, by [`assert_all_nodes_logged_committed`]); in a
/// healthy cluster the remaining follower receives it within a heartbeat, and
/// applying a committed entry into a follower's STATE MACHINE trails log
/// replication by at most one more heartbeat. So observing the applied
/// projection uses a short bounded convergence: this is NOT what makes the
/// write durable (the quorum already did at ACK), only a wait for the
/// downstream deterministic apply to land everywhere.
async fn assert_all_nodes_have(nodes: &[Node], key: PcrKey, version: Version) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let mut all_ok = true;
        for n in nodes {
            match n.raft.state_machine().get(&key).await {
                Some(state) if state.version == version => {}
                _ => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            return;
        }
        if std::time::Instant::now() >= deadline {
            // Re-run once more for a precise panic message.
            for n in nodes {
                let state =
                    n.raft.state_machine().get(&key).await.unwrap_or_else(|| {
                        panic!("node {} never applied the committed key", n.name)
                    });
                assert_eq!(
                    state.version, version,
                    "node {} applied the key at the wrong version",
                    n.name
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Assert EVERY node holds `key` and they all agree on the SAME version,
/// returning that version. Used after a heal where the exact version is not
/// pinned down: while a node was partitioned the dispatcher's at-least-once
/// retry can commit several duplicate Pins (each benignly bumps the version),
/// so the final version is `>= the ACKed value` but not a fixed number. What
/// MUST hold after the heal is convergence: every node applies the same
/// committed history, so all three agree on one version (a short bounded
/// apply-convergence, as in [`assert_all_nodes_have`]).
async fn assert_all_nodes_agree(nodes: &[Node], key: PcrKey) -> Version {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let mut versions = Vec::new();
        for n in nodes {
            versions.push(n.raft.state_machine().get(&key).await.map(|s| s.version));
        }
        if let Some(Some(first)) = versions.first().copied() {
            if versions.iter().all(|v| *v == Some(first)) {
                return first;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "nodes never converged on a single version for the key: {versions:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// --- tests ----------------------------------------------------------------

/// (a) Pin then Get against the SAME node, leader case: a session whose
/// listener happens to be the leader writes a commitment and reads it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_then_get_same_node_leader() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let seed = 0x11;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let leader = current_leader(&nodes).await.unwrap();

    let mut client = Client::connect(leader, seed, pk).await;
    let resp = client
        .rpc(Request::Register {
            key,
            commitment: c(0xaa),
        })
        .await;
    assert_eq!(
        resp,
        Response::RegisterOk
    );

    // Majority ACK: the moment the Pin is ACKed, a quorum's LOG already holds
    // the committed entry. NO settle loop, the ACK is the guarantee.
    assert_all_nodes_logged_committed(&nodes);
    // And the entry applies into every node's state machine (bounded
    // convergence, not what makes it durable).
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    let resp = client.rpc(Request::Get { key }).await;
    assert_eq!(
        resp,
        Response::GetOk {
            commitment: c(0xaa),
            version: Version(0),
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (a) Pin then Get against the SAME node, non-leader case: the listener the
/// client dials is a follower, so BOTH the write and the linearizable read are
/// forwarded to the leader over the mesh, transparently to the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_then_get_same_node_follower() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let follower = nodes.iter().find(|n| n.name != leader_name).unwrap();

    let seed = 0x12;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);

    let mut client = Client::connect(follower, seed, pk).await;
    let resp = client
        .rpc(Request::Register {
            key,
            commitment: c(0xbb),
        })
        .await;
    assert_eq!(
        resp,
        Response::RegisterOk
    );

    // Majority ACK holds regardless of which node the client dialed: the
    // forwarded write was ACKed only once a quorum's log had it (no loop), and
    // applies into every state machine (bounded convergence).
    assert_all_nodes_logged_committed(&nodes);
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    let resp = client.rpc(Request::Get { key }).await;
    assert_eq!(
        resp,
        Response::GetOk {
            commitment: c(0xbb),
            version: Version(0),
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// A Pin never registers, on the leader or forwarded from a follower: a key
/// the replicated state does not hold is `NotFound` and stays unknown. Only
/// `Register` creates it, once; a second `Register` is `AlreadyRegistered`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_on_unknown_key_is_not_found_and_only_register_creates_it() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let follower = nodes.iter().find(|n| n.name != leader_name).unwrap();
    let seed = 0x13;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let pin = |expected_version, byte| Request::Pin {
        key,
        expected_version,
        commitment: c(byte),
    };

    for node in [find(&nodes, &leader_name), follower] {
        let mut client = Client::connect(node, seed, pk).await;
        assert_eq!(
            client.rpc(pin(Version(0), 0xc1)).await,
            Response::Err {
                error: RpcError::NotFound
            }
        );
        assert_eq!(
            client.rpc(Request::Get { key }).await,
            Response::Err {
                error: RpcError::NotFound
            }
        );
    }

    let mut client = Client::connect(follower, seed, pk).await;
    let register = |byte| Request::Register {
        key,
        commitment: c(byte),
    };
    assert_eq!(client.rpc(register(0xc2)).await, Response::RegisterOk);
    assert_eq!(
        client.rpc(register(0xc3)).await,
        Response::Err {
            error: RpcError::AlreadyRegistered
        }
    );
    assert_eq!(
        client.rpc(pin(Version(0), 0xc4)).await,
        Response::PinOk {
            version: Version(1)
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (b) Pin against ONE node, Get against ANOTHER: the write commits to the
/// cluster (forwarded if the first node is a follower), and a linearizable read
/// on a different node sees it (forwarded if that node is a follower). Proves
/// the freshness oracle returns the committed value regardless of entry node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_on_one_node_get_on_another() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let seed = 0x13;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);

    // Pin against node-a, Get against node-c. Whichever is/are the follower
    // forwards to the leader; the committed value is visible either way.
    let mut writer = Client::connect(find(&nodes, "node-a"), seed, pk).await;
    let resp = writer
        .rpc(Request::Register {
            key,
            commitment: c(0xcd),
        })
        .await;
    assert_eq!(
        resp,
        Response::RegisterOk
    );

    let mut reader = Client::connect(find(&nodes, "node-c"), seed, pk).await;
    let resp = reader.rpc(Request::Get { key }).await;
    assert_eq!(
        resp,
        Response::GetOk {
            commitment: c(0xcd),
            version: Version(0),
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (c) Full Transition flow: the OLD enclave registers (and pins) its key, then
/// a NEW enclave session submits a real p256-signed #47 upgrade link. The
/// transition retires the old key and carries the version forward to the new
/// key, and a Get for the new key returns the carried state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_flow_carries_version_and_retires_old() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let old_seed = 0x20;
    let new_seed = 0x30;
    let (sk_old, pk_old) = keypair(old_seed);
    let (_, pk_new) = keypair(new_seed);
    let old_key = key_from_seed(old_seed);
    let new_key = key_from_seed(new_seed);

    // The OLD enclave session: register, then pin (commitment 0xbb, version 1).
    {
        let mut old = Client::connect(find(&nodes, "node-a"), old_seed, pk_old).await;
        let r = old
            .rpc(Request::Register {
                key: old_key,
                commitment: c(0xaa),
            })
            .await;
        assert_eq!(
            r,
            Response::RegisterOk
        );
        let r = old
            .rpc(Request::Pin {
                key: old_key,
                expected_version: Version(0),
                commitment: c(0xbb),
            })
            .await;
        assert_eq!(
            r,
            Response::PinOk {
                version: Version(1)
            }
        );
    }

    // The NEW enclave session submits the Transition (against a possibly-
    // different node, exercising forwarding of a Transition too).
    let link = upgrade_link(old_seed, new_seed, &sk_old);
    let mut new_enclave = Client::connect(find(&nodes, "node-b"), new_seed, pk_new).await;
    let r = new_enclave.rpc(Request::Transition { link }).await;
    assert_eq!(
        r,
        Response::TransitionOk {
            version: Version(1)
        }
    );

    // The new key now owns the carried commitment + version.
    let r = new_enclave.rpc(Request::Get { key: new_key }).await;
    assert_eq!(
        r,
        Response::GetOk {
            commitment: c(0xbb),
            version: Version(1),
        }
    );

    // The old key is gone: a session bound to it reads NotFound.
    let mut old = Client::connect(find(&nodes, "node-c"), old_seed, pk_old).await;
    let r = old.rpc(Request::Get { key: old_key }).await;
    assert_eq!(
        r,
        Response::Err {
            error: RpcError::NotFound,
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (d) Restart one node with EMPTY state, wait for it to hydrate from the
/// survivors, then serve a Get from it (forwarded to the leader) and assert the
/// three nodes' replicated views are identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_node_hydrates_and_serves_get() {
    // Aggressive snapshot policy (mirrors slice 3's hydration test): snapshot
    // after a few logs and keep none, so the leader's log purges and a node that
    // lost everything catches up via an InstallSnapshot transfer over the mesh,
    // the `loosen-follower-log-revert` hydration path.
    let aggressive = synchronizer::raft::Config {
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: synchronizer::raft::SnapshotPolicy::LogsSinceLast(4),
        max_in_snapshot_log_to_keep: 0,
        ..Default::default()
    };

    let host = MeshHostStub::new();
    let mut nodes = cluster_with_config(&host, aggressive.clone()).await;

    // Commit a batch of keys through client sessions so the log grows past the
    // snapshot threshold and the leader builds + purges to a snapshot. Each
    // session connects to whichever node is the CURRENT leader (so the write is
    // served locally), keeping the setup fast and avoiding piling forwards
    // through one follower while the log is churning.
    let mut seeds = Vec::new();
    for i in 0..12u8 {
        let seed = 0x40 + i;
        seeds.push(seed);
        let (_, pk) = keypair(seed);
        let key = key_from_seed(seed);
        let ld = current_leader(&nodes).await.expect("leader for setup");
        let mut client = Client::connect(ld, seed, pk).await;
        let r = client
            .rpc(Request::Register {
                key,
                commitment: c(0x10 + i),
            })
            .await;
        assert_eq!(
            r,
            Response::RegisterOk
        );
    }
    // Let snapshots build + log purge settle.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Restart a NON-leader with empty state.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let victim_idx = nodes.iter().position(|n| n.name != leader_name).unwrap();
    let victim_name = nodes[victim_idx].name.clone();
    let old = nodes.remove(victim_idx);
    old.raft.shutdown().await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    nodes.insert(
        victim_idx,
        spawn_node_with_config(&victim_name, &host, aggressive.clone()).await,
    );

    // Wait until the restarted node's replicated view has all 12 keys (hydrated
    // via snapshot install, since the log was purged).
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let view = nodes[victim_idx].raft.state_machine().head_view().await;
        if view.len() == 12 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restarted node never hydrated (have {} of 12)",
            view.len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Serve a Get THROUGH the restarted node's listener: it forwards to the
    // leader (a freshly-restarted node is a follower) and returns the committed
    // value.
    let seed = seeds[0];
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let mut client = Client::connect(&nodes[victim_idx], seed, pk).await;
    let r = client.rpc(Request::Get { key }).await;
    assert_eq!(
        r,
        Response::GetOk {
            commitment: c(0x10),
            version: Version(0),
        }
    );

    // The three nodes' replicated head views are identical.
    let mut views = Vec::new();
    for n in &nodes {
        views.push((n.name.clone(), n.raft.state_machine().head_view().await));
    }
    let (ref_name, ref_view) = &views[0];
    for (name, view) in &views[1..] {
        assert_eq!(view, ref_view, "view diverged: {name} vs {ref_name}");
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Register `key` through `node` until it is ACKed, riding out the
/// `Unavailable` answers of a leader election. A retry that finds the key
/// already registered checks with a Get that it holds this registration.
async fn register_until_acked(
    node: &Node,
    seed: u8,
    pk: [u8; CONTROL_PUBKEY_LEN],
    key: PcrKey,
    commitment: Commitment,
) {
    let mut client = Client::connect(node, seed, pk).await;
    for _ in 0..40 {
        match client.rpc(Request::Register { key, commitment }).await {
            Response::RegisterOk => return,
            Response::Err {
                error: RpcError::Unavailable,
            } => tokio::time::sleep(Duration::from_millis(200)).await,
            Response::Err {
                error: RpcError::AlreadyRegistered,
            } => {
                assert_eq!(
                    client.rpc(Request::Get { key }).await,
                    Response::GetOk {
                        commitment,
                        version: Version(0),
                    },
                    "an AlreadyRegistered retry must find its own registration"
                );
                return;
            }
            other => panic!("unexpected response to register via {}: {other:?}", node.name),
        }
    }
    panic!("register via {} was never ACKed", node.name);
}

/// Pin through `node` until it is ACKed, riding out the `Unavailable` answers
/// of a leader election. Uses the CAS-aware [`Client::pin_cas`], so an attempt
/// that committed before its ACK was lost is recognised on the retry. Returns
/// the ACKed version.
async fn pin_until_acked(
    node: &Node,
    seed: u8,
    pk: [u8; CONTROL_PUBKEY_LEN],
    key: PcrKey,
    expected: Version,
    commitment: Commitment,
) -> Version {
    let mut client = Client::connect(node, seed, pk).await;
    for _ in 0..40 {
        match client.pin_cas(key, expected, commitment).await {
            Ok(version) => return version,
            Err(Response::Err {
                error: RpcError::Unavailable,
            }) => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(other) => panic!("unexpected response to pin via {}: {other:?}", node.name),
        }
    }
    panic!("pin via {} was never ACKed", node.name);
}

/// Wait until one of `candidates` is leader and return its name.
async fn await_leader_among(candidates: &[&Node], timeout: Duration) -> Option<String> {
    let start = std::time::Instant::now();
    loop {
        for n in candidates {
            if n.raft.is_leader().await {
                return Some(n.name.clone());
            }
        }
        if start.elapsed() > timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// (e) Partition the LEADER. The two survivors re-elect and keep ACKing writes
/// (they are a quorum), linearizable reads keep working, and after the
/// partition heals the old leader catches up so all three nodes agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_continue_through_leader_outage_then_heal() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    // Commit one key while the cluster is whole.
    let seed = 0x55;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    register_until_acked(find(&nodes, "node-a"), seed, pk, key, c(0x01)).await;
    assert_all_nodes_logged_committed(&nodes);
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    // Partition the current leader: the other two must elect a new one.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    host.block(leader_name.clone());
    let survivors: Vec<&Node> = nodes.iter().filter(|n| n.name != leader_name).collect();
    assert!(
        await_leader_among(&survivors, Duration::from_secs(10))
            .await
            .is_some(),
        "survivors never re-elected a leader after the leader partition"
    );

    // A write through a survivor is ACKed on the 2-node quorum.
    let v1 = pin_until_acked(survivors[0], seed, pk, key, Version(0), c(0x02)).await;
    assert_eq!(v1, Version(1));
    assert_quorum_logged_committed(&survivors, nodes.len());

    // Linearizable read through a survivor sees the ACKed write.
    let mut client = Client::connect(survivors[1], seed, pk).await;
    assert_eq!(
        client.rpc(Request::Get { key }).await,
        Response::GetOk {
            commitment: c(0x02),
            version: Version(1),
        }
    );

    // Heal: the old leader rejoins as a follower and catches up.
    host.unblock(&leader_name);
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader after healing"
    );
    assert_all_nodes_have(&nodes, key, Version(1)).await;
    assert_eq!(assert_all_nodes_agree(&nodes, key).await, Version(1));

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (b) An ACKed pin survives the loss of any single node, including the worst
/// case for a majority ACK: the pin is ACKed while one follower is partitioned
/// (so only the leader and the other follower hold it), then the LEADER is
/// lost and the node that never saw the pin comes back. The only surviving
/// holder must win the election (Raft's election restriction), so the pin is
/// still served, never rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acked_pin_survives_loss_of_any_single_node() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let seed = 0x66;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);

    // Commit a first version while the cluster is whole.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    register_until_acked(
        find(&nodes, &leader_name),
        seed,
        pk,
        key,
        c(0x01)
    )
    .await;
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    // Partition a follower (the victim). The leader keeps a 2-node quorum with
    // the other follower (the holder).
    let victim_name = nodes
        .iter()
        .find(|n| n.name != leader_name)
        .unwrap()
        .name
        .clone();
    let holder_name = nodes
        .iter()
        .find(|n| n.name != leader_name && n.name != victim_name)
        .unwrap()
        .name
        .clone();
    host.block(victim_name.clone());

    // With one node down the pin is still ACKed (it used to be refused).
    let v1 = pin_until_acked(
        find(&nodes, &leader_name),
        seed,
        pk,
        key,
        Version(0),
        c(0x02),
    )
    .await;
    assert_eq!(v1, Version(1));
    let quorum = [find(&nodes, &leader_name), find(&nodes, &holder_name)];
    assert_quorum_logged_committed(&quorum, nodes.len());
    // The victim really does not have it: the rest of the test depends on the
    // holder being the only survivor with the ACKed entry.
    let acked_index = find(&nodes, &leader_name)
        .raft
        .raft()
        .metrics()
        .borrow()
        .last_applied
        .map(|l| l.index)
        .unwrap();
    let victim_last_log = find(&nodes, &victim_name)
        .raft
        .raft()
        .metrics()
        .borrow()
        .last_log_index
        .unwrap_or(0);
    assert!(
        victim_last_log < acked_index,
        "the partitioned node already holds the ACKed entry ({victim_last_log} >= \
         {acked_index}); the scenario would prove nothing"
    );

    // Lose the leader, THEN let the victim back in. Survivors: the holder (has
    // the pin) and the victim (does not).
    host.block(leader_name.clone());
    host.unblock(&victim_name);

    let survivors = [find(&nodes, &holder_name), find(&nodes, &victim_name)];
    let new_leader = await_leader_among(&survivors, Duration::from_secs(15))
        .await
        .expect("the two survivors never elected a leader");
    assert_eq!(
        new_leader, holder_name,
        "a node missing an ACKed entry won the election"
    );

    // Read through the victim (forwarded to the new leader): the ACKed pin is
    // there, at the ACKed version.
    let mut client = Client::connect(find(&nodes, &victim_name), seed, pk).await;
    let mut resp = client.rpc(Request::Get { key }).await;
    for _ in 0..20 {
        if resp
            != (Response::Err {
                error: RpcError::Unavailable,
            })
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        resp = client.rpc(Request::Get { key }).await;
    }
    assert_eq!(
        resp,
        Response::GetOk {
            commitment: c(0x02),
            version: Version(1),
        },
        "the ACKed pin was lost after a single-node failure"
    );
    // And the victim catches up from the new leader.
    let victim = find(&nodes, &victim_name);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if victim
            .raft
            .state_machine()
            .get(&key)
            .await
            .map(|s| s.version)
            == Some(Version(1))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the returning node never caught up to the ACKed pin"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

// --- #209 clone-resistant membership tests --------------------------------

/// The slot name a committed voter id holds, read from the leader's committed
/// membership records, or `None` if the id is not a committed voter.
async fn slot_holders(nodes: &[Node]) -> std::collections::BTreeMap<String, u64> {
    // No leader right now (e.g. a re-election in progress after the leader was
    // restarted): report an empty membership so polling callers keep waiting
    // rather than panicking. When a leader exists this is unchanged.
    let Some(leader) = current_leader(nodes).await else {
        return std::collections::BTreeMap::new();
    };
    leader
        .raft
        .committed_voters()
        .await
        .into_values()
        .map(|rec| {
            (
                rec.name.clone(),
                synchronizer::raft::instance_node_id(&rec.pubkey),
            )
        })
        .collect()
}

/// Wait until the leader's committed membership reports `slot` held by `id`.
async fn await_slot_holder(nodes: &[Node], slot: &str, id: u64, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if slot_holders(nodes).await.get(slot) == Some(&id) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Restart the SMALLEST-configured-name node (the fresh-cluster bootstrap
/// initializer, here `node-a`) with a fresh identity against a LIVE cluster
/// (#209 bootstrap-race regression). This is the dangerous path: a restarted
/// bootstrap-name node boots with empty state and is NOT in the live
/// membership (its instance id is new), so it gets no passive signal that the
/// cluster exists, only its Join probes do. It must JOIN, and must NEVER
/// initialize a competing cluster. A competitor would reuse the same member
/// ids and could, via a higher-term election, roll the real log back (the
/// `loosen-follower-log-revert` mode removes the panic that would otherwise
/// catch it). The fix: a peer that has itself seen no cluster answers
/// `NoCluster`; a live peer answers `NotLeader`/`Admitted`, so the restarted
/// node observes a cluster and never initializes.
///
/// Assertions: the survivors' leader term is preserved across the restart (no
/// competing election bumped it via a parallel cluster), the restarted node is
/// admitted for its slot evicting its old id, exactly three slot holders, and
/// all three views converge, including the pre-restart pin (proving no
/// rollback).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_of_bootstrap_name_node_joins_never_initializes_competitor() {
    let host = MeshHostStub::new();
    let mut nodes = cluster(&host).await;

    // Commit a pin so a rollback (which a competing cluster could cause) would
    // be observable as a lost/regressed version.
    let seed = 0x73;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    {
        let ld = current_leader(&nodes).await.unwrap();
        let mut client = Client::connect(ld, seed, pk).await;
        assert_eq!(
            client
                .rpc(Request::Register {
                    key,
                    commitment: c(0xb2),
                })
                .await,
            Response::RegisterOk
        );
    }

    // The smallest configured name is the bootstrap initializer. Restarting it
    // is the case that, before the NoCluster discriminator, could race into
    // initializing a second cluster.
    let victim_name = NODE_NAMES.iter().copied().min().unwrap().to_string();
    let victim_idx = nodes.iter().position(|n| n.name == victim_name).unwrap();
    let old_id = nodes[victim_idx].raft.self_id();

    let old = nodes.remove(victim_idx);
    old.raft.shutdown().await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Re-spawn node-a with a brand-new identity (empty state, new instance id).
    let replacement = spawn_node(&victim_name, &host).await;
    let new_id = replacement.raft.self_id();
    assert_ne!(old_id, new_id, "replacement must have a fresh instance id");
    nodes.insert(victim_idx, replacement);

    // The two survivors retain quorum (2 of 3) and re-elect among themselves if
    // node-a was the leader. If this ever fails, restarting the bootstrap-name
    // node deadlocked the cluster, a real product bug, not test fragility.
    assert!(
        await_leader(&nodes, Duration::from_secs(15)).await,
        "the surviving nodes did not keep/elect a leader after the bootstrap-name restart"
    );

    // The restarted bootstrap-name node must JOIN (be admitted for its slot
    // with the new id), not stand up a competitor.
    assert!(
        await_slot_holder(&nodes, &victim_name, new_id, Duration::from_secs(15)).await,
        "the restarted bootstrap-name node was not admitted via join (it may have \
         initialized a competing cluster instead)"
    );

    // Exactly three slots, each held by a live node's current id, and the old
    // id is gone: one cluster, no duplicate/competitor membership.
    let holders = slot_holders(&nodes).await;
    assert_eq!(holders.len(), 3, "not exactly three slots after restart");
    assert_eq!(holders.get(&victim_name), Some(&new_id));
    assert!(
        !holders.values().any(|id| *id == old_id),
        "the evicted old bootstrap-name id is still a committed voter"
    );
    for n in &nodes {
        assert_eq!(
            holders.get(&n.name),
            Some(&n.raft.self_id()),
            "slot {} held by an id that matches no live node (competing membership)",
            n.name
        );
    }

    // No rollback: the pre-restart pin survives, served through the restarted
    // node (forwarded to the leader). A competing cluster that won would have
    // wiped this.
    let mut client = Client::connect(&nodes[victim_idx], seed, pk).await;
    assert_eq!(
        client.rpc(Request::Get { key }).await,
        Response::GetOk {
            commitment: c(0xb2),
            version: Version(0)
        }
    );

    // All three live nodes converge on the identical view.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut views = Vec::new();
        for n in &nodes {
            views.push(n.raft.state_machine().head_view().await);
        }
        if views.iter().all(|v| *v == views[0]) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "views never converged after bootstrap-name restart"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Restart a node with the SAME slot name but a NEW per-boot identity (#209):
/// it must be ADMITTED via join (evicting the old instance id for the slot),
/// hydrate the committed view, and the cluster keeps serving clients. The
/// three live nodes converge on the identical view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_with_new_identity_is_admitted_via_join() {
    let host = MeshHostStub::new();
    let mut nodes = cluster(&host).await;

    // Pin a key so there is committed state the restarted node must hydrate.
    let seed = 0x71;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    {
        let ld = current_leader(&nodes).await.unwrap();
        let mut client = Client::connect(ld, seed, pk).await;
        assert_eq!(
            client
                .rpc(Request::Register {
                    key,
                    commitment: c(0xa1),
                })
                .await,
            Response::RegisterOk
        );
    }

    // Restart a NON-leader with a fresh identity (spawn_node generates a new
    // MeshIdentity, so the replacement has a brand-new instance id).
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let victim_idx = nodes.iter().position(|n| n.name != leader_name).unwrap();
    let victim_name = nodes[victim_idx].name.clone();
    let old_id = nodes[victim_idx].raft.self_id();
    let old = nodes.remove(victim_idx);
    old.raft.shutdown().await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replacement = spawn_node(&victim_name, &host).await;
    let new_id = replacement.raft.self_id();
    assert_ne!(
        old_id, new_id,
        "the replacement must have a fresh instance id"
    );
    nodes.insert(victim_idx, replacement);

    // The replacement joins for its slot, evicting the old id: the committed
    // membership for the slot is now the NEW id, never the old one.
    assert!(
        await_slot_holder(&nodes, &victim_name, new_id, Duration::from_secs(15)).await,
        "the restarted node was not admitted for its slot via join"
    );
    let holders = slot_holders(&nodes).await;
    assert_eq!(holders.get(&victim_name), Some(&new_id));
    assert!(
        !holders.values().any(|id| *id == old_id),
        "the evicted old instance id is still a committed voter"
    );

    // The replacement hydrates the committed view and the cluster serves a Get
    // through it (forwarded to the leader).
    let mut client = Client::connect(&nodes[victim_idx], seed, pk).await;
    assert_eq!(
        client.rpc(Request::Get { key }).await,
        Response::GetOk {
            commitment: c(0xa1),
            version: Version(0)
        }
    );

    // The three live nodes converge on the identical view.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut views = Vec::new();
        for n in &nodes {
            views.push(n.raft.state_machine().head_view().await);
        }
        if views.iter().all(|v| *v == views[0]) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "views never converged after restart"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Clone race (#209): while a node is alive, a SECOND instance with the same
/// slot name and a fresh identity joins. The host points routing at the clone
/// (modelled by re-registering the slot's mesh socket, then severing the
/// original's connections so the cluster re-dials the clone). The clone is
/// admitted, EVICTING the original's id: exactly one instance holds the slot at
/// the end, and the original is no longer a committed voter (its participation
/// ceases). Then flap back: a third fresh instance for the slot is admitted,
/// again evicting the clone, still exactly one holder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clone_race_evicts_original_exactly_one_holder() {
    let host = MeshHostStub::new();
    let mut nodes = cluster(&host).await;

    // Pick a NON-leader slot to clone (so the leader stays put and admits).
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let slot = nodes
        .iter()
        .find(|n| n.name != leader_name)
        .unwrap()
        .name
        .clone();
    let original_idx = nodes.iter().position(|n| n.name == slot).unwrap();
    let original_id = nodes[original_idx].raft.self_id();

    // Exactly one holder of the slot before the clone: the original.
    assert_eq!(slot_holders(&nodes).await.get(&slot), Some(&original_id));

    // Bring up the clone: a fresh instance for the SAME slot. spawn_node
    // re-registers the slot's mesh socket (the host now routes the slot to the
    // clone) and generates a fresh identity. To make the cluster actually route
    // to the clone (rather than keep its live splice to the original), block the
    // slot briefly (severs the original's live connections AND the clone's,
    // which has none yet), then unblock so the cluster re-dials the slot name
    // and reaches the clone's freshly-registered socket.
    host.block(slot.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let clone = spawn_node(&slot, &host).await;
    let clone_id = clone.raft.self_id();
    assert_ne!(original_id, clone_id);
    host.unblock(&slot);

    // The clone is admitted for the slot, evicting the original id. At the end
    // exactly ONE instance holds the slot (the clone), and the original id is
    // gone from the committed membership.
    assert!(
        await_slot_holder(&nodes, &slot, clone_id, Duration::from_secs(20)).await,
        "the clone was not admitted (evicting the original) for its slot"
    );
    {
        let holders = slot_holders(&nodes).await;
        assert_eq!(
            holders.get(&slot),
            Some(&clone_id),
            "slot not held by the clone"
        );
        assert!(
            !holders.values().any(|id| *id == original_id),
            "the evicted original id is still a committed voter (two holders)"
        );
        // Exactly one voter per name: no duplicate slot.
        let names: Vec<&String> = holders.keys().collect();
        let unique: std::collections::BTreeSet<&String> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "a slot has two committed voters");
    }

    // The original instance's participation ceased: it is not the leader and a
    // direct write on it fails (it is no longer a voter that can commit). Its
    // eviction watch shuts its Raft down on observing itself gone.
    assert!(
        !nodes[original_idx].raft.is_leader().await,
        "the evicted original still believes it is the leader"
    );

    // The cluster (leader + other + clone) still serves clients with a
    // consistent view.
    let seed = 0x72;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let ld = current_leader(&nodes).await.unwrap();
    let mut client = Client::connect(ld, seed, pk).await;
    assert_eq!(
        client
            .rpc(Request::Register {
                key,
                commitment: c(0xb2),
            })
            .await,
        Response::RegisterOk
    );

    // Drop the now-orphaned original so it stops contending for the slot route,
    // and replace the slot once more (flap back): a third fresh instance is
    // admitted, evicting the clone. Still exactly one holder.
    let original = nodes.remove(original_idx);
    original.raft.shutdown().await;
    drop(original);
    host.block(slot.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let flapped = spawn_node(&slot, &host).await;
    let flapped_id = flapped.raft.self_id();
    assert_ne!(clone_id, flapped_id);
    nodes.insert(original_idx, flapped);
    host.unblock(&slot);

    assert!(
        await_slot_holder(&nodes, &slot, flapped_id, Duration::from_secs(20)).await,
        "the flapped-back instance was not admitted (evicting the clone)"
    );
    {
        let holders = slot_holders(&nodes).await;
        assert_eq!(holders.get(&slot), Some(&flapped_id));
        assert!(!holders.values().any(|id| *id == clone_id));
        let names: Vec<&String> = holders.keys().collect();
        let unique: std::collections::BTreeSet<&String> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "a slot has two committed voters after flap"
        );
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
    // The clone node we replaced is still in scope; shut it down.
    clone.raft.shutdown().await;
}

/// A joiner whose slot name is NOT in the configured set is refused by the
/// kernel and NEVER becomes a committed voter (#209): the cluster never grows
/// past its configured slots no matter how many attested same-image instances
/// ask. We exercise the leader's join handler directly via the public `admit`
/// API (the join path runs it with the channel-attested pubkey); the wire Join
/// would return `Refused`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_slot_name_is_refused_and_never_a_voter() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let leader = current_leader(&nodes).await.unwrap();
    // A pubkey for an unconfigured slot.
    let bogus_pk = keypair(0x99).1;
    let err = leader
        .raft
        .admit("node-evil", &bogus_pk)
        .await
        .expect_err("an unconfigured slot must be refused");
    assert!(
        matches!(err, synchronizer::raft::RaftHandleError::JoinRefused(_)),
        "expected JoinRefused for an unconfigured slot, got {err:?}"
    );

    // The cluster membership is unchanged: still exactly the three configured
    // slots, and the bogus id is not a voter.
    let bogus_id = synchronizer::raft::instance_node_id(&bogus_pk);
    assert!(
        !leader.raft.is_committed_voter(bogus_id).await,
        "an unconfigured-slot joiner became a voter"
    );
    let holders = slot_holders(&nodes).await;
    assert_eq!(
        holders.len(),
        3,
        "the cluster grew past its configured slots"
    );
    assert!(holders.keys().all(|n| NODE_NAMES.contains(&n.as_str())));

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Double-loss (#209, the #122 recovery boundary): kill TWO of three nodes.
/// The old config has no quorum, so the cluster HALTS, no leader, and a new
/// joiner with a fresh key is NOT admitted (the surviving node cannot commit a
/// membership change without quorum). The joiner halts rather than misbehaves;
/// it never becomes a voter. This is the deliberate availability trade documented
/// in #209: clone resistance costs double-restart recovery, which is operator-
/// gated (#122).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn double_loss_halts_and_refuses_a_fresh_joiner() {
    let host = MeshHostStub::new();
    let mut nodes = cluster(&host).await;

    // Kill two nodes (keep the third). The survivor loses quorum: it can no
    // longer COMMIT anything (no client writes, no membership changes), which is
    // the halt the design intends. A lone survivor may still briefly *believe*
    // it is leader (openraft only relinquishes the belief on a higher term it
    // never sees, or an explicit linearizability check), but belief without
    // quorum commits nothing, which is what the assertions below pin down.
    for _ in 0..2 {
        let victim = nodes.pop().unwrap();
        victim.raft.shutdown().await;
        drop(victim);
    }
    let survivor = &nodes[0];

    // The survivor cannot serve client writes (no quorum to commit them): a
    // client Pin through its listener fails with Unavailable rather than ACKing.
    // This is the "halts" half.
    {
        let seed = 0x5a;
        let (_, pk) = keypair(seed);
        let key = key_from_seed(seed);
        let mut client = Client::connect(survivor, seed, pk).await;
        // The answer is a structured Unavailable inside the routing deadline,
        // never a hang up to the customer's own RPC timeout.
        let r = tokio::time::timeout(
            ROUTE_DEADLINE + Duration::from_secs(2),
            client.rpc(Request::Pin {
                key,
                expected_version: Version(0),
                commitment: c(0x5a),
            }),
        )
        .await;
        assert_eq!(
            r.ok(),
            Some(Response::Err {
                error: RpcError::Unavailable
            }),
            "a write without quorum must be answered Unavailable within the routing deadline"
        );
    }

    // A fresh-key joiner for a dead slot asks the survivor to admit it. Without
    // quorum the survivor cannot commit the membership change, so the join is
    // NOT admitted within a bounded window (it would hang on the blocking
    // add_learner): it halts, never a voter. Bound it with a timeout so a hung
    // membership change surfaces as the (correct) "not admitted" outcome.
    let dead_slot = NODE_NAMES
        .iter()
        .find(|n| **n != survivor.name)
        .unwrap()
        .to_string();
    let fresh_pk = keypair(0x55).1;
    let fresh_id = synchronizer::raft::instance_node_id(&fresh_pk);
    let admitted = tokio::time::timeout(
        Duration::from_secs(5),
        survivor.raft.admit(&dead_slot, &fresh_pk),
    )
    .await;
    // Either the admit returned an error (NotLeader / Raft), or it hung and
    // timed out: in NO case did it report Ok(true) (a successful admission).
    let was_admitted = matches!(admitted, Ok(Ok(true)));
    assert!(
        !was_admitted,
        "without quorum a join must NOT be admitted; got {admitted:?}"
    );
    assert!(
        !survivor.raft.is_committed_voter(fresh_id).await,
        "a fresh joiner became a committed voter without quorum (must halt instead)"
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Bootstrap (#209): a fresh 3-node cluster initializes EXACTLY ONCE via the
/// discovery window. After bootstrap the committed membership has exactly the
/// three configured slots, each held by the running instance's id, so no slot
/// was filled twice and no extra initialize happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_cluster_initializes_exactly_once() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    // Exactly the three configured slots, each held by the corresponding live
    // node's instance id. A double-initialize or duplicate fill would show up
    // as a wrong count or a slot id that matches no live node.
    let holders = slot_holders(&nodes).await;
    assert_eq!(
        holders.len(),
        3,
        "bootstrap did not yield exactly three slots"
    );
    for n in &nodes {
        assert_eq!(
            holders.get(&n.name),
            Some(&n.raft.self_id()),
            "slot {} not held by its live instance id (double-init or wrong fill)",
            n.name
        );
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

// --- bounded client writes (no quorum) -------------------------------------

/// Two nodes lost: the leader keeps believing it leads but cannot commit. A
/// Pin through it is answered `Unavailable` once the commit timeout elapses,
/// well inside the routing deadline, instead of hanging until the customer's
/// own RPC timeout. The node stays up and answers the next request too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_without_quorum_is_unavailable_within_the_bound() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let seed = 0x71;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    register_until_acked(
        find(&nodes, &leader_name),
        seed,
        pk,
        key,
        c(0x01)
    )
    .await;

    // Cut the leader off from both followers.
    for n in &nodes {
        if n.name != leader_name {
            host.block(n.name.clone());
        }
    }

    let mut client = Client::connect(find(&nodes, &leader_name), seed, pk).await;
    for commitment in [c(0x02), c(0x03)] {
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            ROUTE_DEADLINE + Duration::from_secs(2),
            client.rpc(Request::Pin {
                key,
                expected_version: Version(0),
                commitment,
            }),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(
            r.ok(),
            Some(Response::Err {
                error: RpcError::Unavailable
            }),
            "a write without quorum must be answered Unavailable"
        );
        assert!(
            elapsed <= ROUTE_DEADLINE + Duration::from_secs(1),
            "Unavailable took {elapsed:?}, over the {ROUTE_DEADLINE:?} routing deadline"
        );
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// "Timed out but committed": the leader's commit wait times out (forced here
/// with a near-zero commit timeout on a clone of the leader's handle), so the
/// customer is told `Unavailable`, and the entry commits anyway a moment
/// later. The customer's recovery (the nbd-client's: retry with the same CAS
/// version, and on `VersionConflict` a `Get`) must see its own commitment and
/// continue, and its NEXT compare-and-swap must succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_write_that_commits_does_not_break_the_next_cas() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let seed = 0x72;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let leader = find(&nodes, &leader_name);
    register_until_acked(leader, seed, pk, key, c(0x01)).await;
    assert_eq!(leader.raft.commit_timeout(), COMMIT_TIMEOUT);

    // The write is submitted and the wait gives up almost at once, so the
    // answer is the timed-out Unavailable. A commit that completes within the
    // first poll still ACKs; then pin again from the new version until one
    // attempt does time out.
    let impatient = leader
        .raft
        .clone()
        .with_commit_timeout(Duration::from_micros(1));
    let mut expected = Version(0);
    let mut commitment = 0x02u8;
    loop {
        let answered = synchronizer::raft::serve::handle_on_leader(
            &impatient,
            key,
            pk,
            Request::Pin {
                key,
                expected_version: expected,
                commitment: c(commitment),
            },
            true,
        )
        .await;
        match answered.response {
            Response::PinOk { version } if !answered.timed_out => {
                assert_eq!(version.0, expected.0 + 1);
                expected = version;
                commitment += 1;
                assert!(commitment < 0x40, "no attempt ever timed out");
            }
            Response::Err {
                error: RpcError::Unavailable,
            } if answered.timed_out => break,
            other => panic!("unexpected answer: {other:?} (timed_out {})", answered.timed_out),
        }
    }
    let landed = Version(expected.0 + 1);

    // It commits anyway, on every node.
    assert_all_nodes_have(&nodes, key, landed).await;

    // The customer retries the same pin (same CAS version): VersionConflict,
    // then a Get that shows its own commitment, so the pin counts as landed.
    let mut client = Client::connect(leader, seed, pk).await;
    assert_eq!(
        client.pin_cas(key, expected, c(commitment)).await,
        Ok(landed)
    );
    // The next CAS, from the committed version, succeeds.
    let next = Version(landed.0 + 1);
    assert_eq!(client.pin_cas(key, landed, c(0x7f)).await, Ok(next));
    assert_all_nodes_have(&nodes, key, next).await;
    assert_eq!(assert_all_nodes_agree(&nodes, key).await, next);

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

// --- upgrade-link revocation ------------------------------------------------

/// An upgrade link `from_seed -> to_seed` stamped `issued_at` and already
/// valid. Every call builds a distinct link (fresh enclave id in the payload).
fn upgrade_link_issued_at(
    from_seed: u8,
    to_seed: u8,
    signing: &SigningKey,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> ChainLink {
    let payload = UpgradePayload {
        enclave_id: uuid::Uuid::new_v4(),
        from: identity_from_seed(from_seed),
        to: identity_from_seed(to_seed),
        image_digest: "sha256:to".into(),
        valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
        valid_until: (chrono::Utc::now() - chrono::Duration::hours(1)) + chrono::Duration::days(7),
        issued_at,
        nonce: vec![0x5a; 32],
    };
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
    let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
    let sig = sign_control(signing, SignedDomain::UpgradePayload, &payload_bytes);
    ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Upgrade,
        payload: payload_bytes,
        attestation,
        signature: Some(sig.to_vec()),
    }
}

/// A revocation link signed by `signing`, naming `revokes_link`.
fn revocation_link(signing: &SigningKey, revokes_link: [u8; 32]) -> ChainLink {
    let payload = RevocationPayload {
        enclave_id: uuid::Uuid::new_v4(),
        revokes: uuid::Uuid::new_v4(),
        issued_at: chrono::Utc::now() - chrono::Duration::days(365),
        nonce: vec![0x6b; 32],
        revokes_link,
    };
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
    let attestation = FakeChainAttestation::for_payload(0, &payload_bytes).encode();
    let sig = sign_control(signing, SignedDomain::RevocationPayload, &payload_bytes);
    ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Revocation,
        payload: payload_bytes,
        attestation,
        signature: Some(sig.to_vec()),
    }
}

/// A v2 revocation of exactly `target`.
fn revocation_of(signing: &SigningKey, target: &ChainLink) -> ChainLink {
    revocation_link(signing, upgrade_link_hash(&target.payload))
}

/// Send `request` through `node` until the answer is not `Unavailable`
/// (an election may be in progress right after a partition).
async fn rpc_until_available(
    node: &Node,
    seed: u8,
    pk: [u8; CONTROL_PUBKEY_LEN],
    request: Request,
) -> Response {
    let mut client = Client::connect(node, seed, pk).await;
    for _ in 0..40 {
        let resp = client.rpc(request.clone()).await;
        if resp
            != (Response::Err {
                error: RpcError::Unavailable,
            })
        {
            return resp;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{request:?} via {} stayed Unavailable", node.name);
}

/// Wait until every node in `nodes` holds exactly `expected` as `key`'s
/// revoked links.
async fn assert_all_nodes_revoked(nodes: &[&Node], key: PcrKey, expected: &[[u8; 32]]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut sets = Vec::new();
        for n in nodes {
            sets.push(n.raft.state_machine().revoked_links(&key).await);
        }
        if sets.iter().all(|s| s.as_slice() == expected) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "revocation not applied everywhere: {sets:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The attack this closes: the host kept a signed upgrade link, the customer
/// revoked it during the delay, and after `valid_from` the host boots the new
/// image and submits the Transition anyway. The link carries a far-future
/// `issued_at` (a hostile backend's stamp), which does not matter: the
/// revocation names the link's payload hash. With the revocation committed
/// (through a follower, so on the forwarded path), the Transition is refused
/// on the leader-local path and the forwarded path, and still after the
/// leader is lost. Replaying the revocation changes nothing. A
/// re-approved (different) link to the same target then goes through, and
/// revoking after that is refused as too late.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_link_is_refused_everywhere_and_survives_a_leader_change() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let old_seed = 0x81;
    let new_seed = 0x82;
    let (sk_old, pk_old) = keypair(old_seed);
    let (_, pk_new) = keypair(new_seed);
    let old_key = key_from_seed(old_seed);
    let far_future = chrono::Utc::now() + chrono::Duration::days(3650);
    let revoked = upgrade_link_issued_at(old_seed, new_seed, &sk_old, far_future);

    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let leader = find(&nodes, &leader_name);
    let followers: Vec<&Node> = nodes.iter().filter(|n| n.name != leader_name).collect();

    register_until_acked(leader, old_seed, pk_old, old_key, c(0x81)).await;

    // The node advertises the capability.
    let mut old_session = Client::connect(followers[0], old_seed, pk_old).await;
    assert!(
        old_session
            .server_capabilities
            .contains(synchronizer::wire::CAPABILITY_REVOCATION),
        "node does not advertise revocation: {:?}",
        old_session.server_capabilities
    );

    // The old enclave revokes, through a follower (forwarded to the leader),
    // twice: the replay is idempotent.
    for _ in 0..2 {
        assert_eq!(
            old_session
                .rpc(Request::Revoke {
                    link: revocation_of(&sk_old, &revoked),
                })
                .await,
            Response::RevokeOk
        );
    }
    let all: Vec<&Node> = nodes.iter().collect();
    assert_all_nodes_revoked(&all, old_key, &[upgrade_link_hash(&revoked.payload)]).await;

    // The host submits the revoked link from the new image: refused on the
    // leader-local path and on the forwarded path.
    let revoked_err = Response::Err {
        error: RpcError::TransitionRevoked,
    };
    let mut via_leader = Client::connect(leader, new_seed, pk_new).await;
    assert_eq!(
        via_leader
            .rpc(Request::Transition {
                link: revoked.clone()
            })
            .await,
        revoked_err
    );
    let mut via_follower = Client::connect(followers[1], new_seed, pk_new).await;
    assert_eq!(
        via_follower
            .rpc(Request::Transition {
                link: revoked.clone()
            })
            .await,
        revoked_err
    );
    // Lose the leader. The survivors elect a new one, which still refuses.
    host.block(leader_name.clone());
    assert!(
        await_leader_among(&followers, Duration::from_secs(10))
            .await
            .is_some(),
        "survivors never elected a leader"
    );
    assert_eq!(
        rpc_until_available(
            followers[0],
            new_seed,
            pk_new,
            Request::Transition {
                link: revoked.clone()
            }
        )
        .await,
        revoked_err
    );
    // The pin never moved.
    assert_eq!(
        rpc_until_available(followers[0], old_seed, pk_old, Request::Get { key: old_key }).await,
        Response::GetOk {
            commitment: c(0x81),
            version: Version(0),
        }
    );

    // Re-approval: a NEW link to the same target (another payload, even one
    // stamped earlier than the revoked link) goes through.
    let reapproved = upgrade_link_issued_at(
        old_seed,
        new_seed,
        &sk_old,
        chrono::Utc::now() - chrono::Duration::hours(1),
    );
    assert_eq!(
        rpc_until_available(
            followers[1],
            new_seed,
            pk_new,
            Request::Transition { link: reapproved }
        )
        .await,
        Response::TransitionOk {
            version: Version(0)
        }
    );

    // Revoking once the pin has moved is too late, and says so.
    assert_eq!(
        rpc_until_available(
            followers[0],
            old_seed,
            pk_old,
            Request::Revoke {
                link: revocation_of(&sk_old, &revoked),
            }
        )
        .await,
        Response::Err {
            error: RpcError::RevocationRejected
        }
    );

    host.unblock(&leader_name);
    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Who may revoke, and what: only the enclave that holds the pin, only with
/// the control key's signature, and only by naming a link. A revocation
/// signed by any other key (the host holds no control key), one from a
/// session of another image (anything the host can boot), and an upgrade
/// link sent as a revocation are all refused and record nothing. A validly
/// signed revocation of ANOTHER link (what a hostile backend would get
/// signed if the signer did not check) commits but does not block the real
/// link. So the genuine link still works at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_or_mistargeted_revocations_do_not_block_the_link() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    let old_seed = 0x83;
    let new_seed = 0x84;
    let stranger_seed = 0x85;
    let (sk_old, pk_old) = keypair(old_seed);
    let (host_sk, _) = keypair(0x86);
    let (_, pk_new) = keypair(new_seed);
    let old_key = key_from_seed(old_seed);
    let issued = chrono::Utc::now() - chrono::Duration::hours(3);
    let target = upgrade_link_issued_at(old_seed, new_seed, &sk_old, issued);

    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let leader = find(&nodes, &leader_name);
    register_until_acked(leader, old_seed, pk_old, old_key, c(0x83)).await;

    let rejected = Response::Err {
        error: RpcError::RevocationRejected,
    };
    let mut old_session = Client::connect(leader, old_seed, pk_old).await;
    // The pin holder's session, but a signature by a key other than the
    // frozen control key.
    assert_eq!(
        old_session
            .rpc(Request::Revoke {
                link: revocation_of(&host_sk, &target),
            })
            .await,
        rejected
    );
    // A validly signed revocation, but from a session of another image (whose
    // key holds no pin), announcing the old control key as its own.
    let mut stranger = Client::connect(leader, stranger_seed, pk_old).await;
    assert_eq!(
        stranger
            .rpc(Request::Revoke {
                link: revocation_of(&sk_old, &target),
            })
            .await,
        rejected
    );
    // An upgrade link is not a revocation, even from the right session.
    assert_eq!(
        old_session
            .rpc(Request::Revoke {
                link: target.clone(),
            })
            .await,
        rejected
    );
    for n in &nodes {
        assert!(n.raft.state_machine().revoked_links(&old_key).await.is_empty());
    }

    // A genuine revocation of a DIFFERENT link to the same target.
    let decoy = upgrade_link_issued_at(old_seed, new_seed, &sk_old, issued);
    assert_eq!(
        old_session
            .rpc(Request::Revoke {
                link: revocation_of(&sk_old, &decoy),
            })
            .await,
        Response::RevokeOk
    );

    let mut new_session = Client::connect(leader, new_seed, pk_new).await;
    assert_eq!(
        new_session
            .rpc(Request::Transition { link: target })
            .await,
        Response::TransitionOk {
            version: Version(0)
        }
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// A node that lost everything hydrates from a snapshot (the log is purged
/// past the revocation) and holds the revocation, and a Transition routed
/// through it once the old leader is gone is still refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_survives_snapshot_install() {
    let aggressive = synchronizer::raft::Config {
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: synchronizer::raft::SnapshotPolicy::LogsSinceLast(4),
        max_in_snapshot_log_to_keep: 0,
        ..Default::default()
    };
    let host = MeshHostStub::new();
    let mut nodes = cluster_with_config(&host, aggressive.clone()).await;

    let old_seed = 0x87;
    let new_seed = 0x88;
    let (sk_old, pk_old) = keypair(old_seed);
    let (_, pk_new) = keypair(new_seed);
    let old_key = key_from_seed(old_seed);
    let revoked = upgrade_link_issued_at(
        old_seed,
        new_seed,
        &sk_old,
        chrono::Utc::now() - chrono::Duration::hours(3),
    );

    let ld = current_leader(&nodes).await.unwrap();
    register_until_acked(ld, old_seed, pk_old, old_key, c(0x87)).await;
    let mut old_session = Client::connect(ld, old_seed, pk_old).await;
    assert_eq!(
        old_session
            .rpc(Request::Revoke {
                link: revocation_of(&sk_old, &revoked),
            })
            .await,
        Response::RevokeOk
    );

    // Push the log well past the snapshot threshold so it is purged.
    for i in 0..12u8 {
        let seed = 0x90 + i;
        let (_, pk) = keypair(seed);
        let ld = current_leader(&nodes).await.expect("leader for setup");
        let mut client = Client::connect(ld, seed, pk).await;
        assert_eq!(
            client
                .rpc(Request::Register {
                    key: key_from_seed(seed),
                    commitment: c(i),
                })
                .await,
            Response::RegisterOk
        );
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Restart a non-leader with empty state; it can only catch up through an
    // InstallSnapshot.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    let victim_idx = nodes.iter().position(|n| n.name != leader_name).unwrap();
    let victim_name = nodes[victim_idx].name.clone();
    let old = nodes.remove(victim_idx);
    old.raft.shutdown().await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    nodes.insert(
        victim_idx,
        spawn_node_with_config(&victim_name, &host, aggressive.clone()).await,
    );
    let victim = &nodes[victim_idx];
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while victim.raft.state_machine().head_view().await.len() < 13 {
        assert!(
            std::time::Instant::now() < deadline,
            "restarted node never hydrated"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        victim.raft.raft().metrics().borrow().snapshot.is_some(),
        "the restarted node caught up without a snapshot; the test proves nothing"
    );
    assert_eq!(
        victim.raft.state_machine().revoked_links(&old_key).await,
        vec![upgrade_link_hash(&revoked.payload)],
        "the snapshot did not carry the revocation"
    );

    // Lose the old leader: the new leader is the hydrated node or the other
    // survivor, and the Transition routed through the hydrated node is
    // refused either way.
    host.block(leader_name.clone());
    let survivors: Vec<&Node> = nodes.iter().filter(|n| n.name != leader_name).collect();
    assert!(
        await_leader_among(&survivors, Duration::from_secs(10))
            .await
            .is_some()
    );
    assert_eq!(
        rpc_until_available(
            victim,
            new_seed,
            pk_new,
            Request::Transition { link: revoked }
        )
        .await,
        Response::Err {
            error: RpcError::TransitionRevoked
        }
    );

    host.unblock(&leader_name);
    for n in &nodes {
        n.raft.shutdown().await;
    }
}
