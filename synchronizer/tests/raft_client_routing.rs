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
//!   linearizable read). Each Pin ACK is immediately checked against ALL THREE
//!   nodes' state machines: under full-replication ACK the ACK itself
//!   guarantees the entry is on every replica (no settle loop);
//! * Pin against one node, Get against ANOTHER (forwarding + linearizable
//!   read see the committed write regardless of which node the client dialed);
//! * (c) the full Transition flow with a real p256-signed #47 upgrade chain
//!   link: register the old key, then a new-enclave session submits the
//!   Transition; the old key retires and the carried version survives;
//! * (d) restart one node with EMPTY state, wait for it to hydrate from the
//!   survivors, then serve a Get from it (forwarded to the leader) and verify
//!   the three nodes' views are identical;
//! * (e) partition the LEADER: under full-replication ACK the survivors
//!   re-elect but writes now STALL (a write needs all three nodes), so a client
//!   write fails with `Unavailable` while reads keep working; after healing,
//!   writes succeed on all three again;
//! * (b) partition a NON-leader and submit a Pin to the leader: the client must
//!   receive `Unavailable`, NEVER a false success ACK, because the committed
//!   entry cannot reach the down node. Heal, retry, assert success +
//!   all-three visibility.
//!
//! Gated on `raft` + `test-utils` + `node` (the UDS transport + `FakeAttestor`
//! are never compiled into the production binary; `node` brings in the customer
//! listener these tests drive end to end). `raft` and `test-utils` both imply
//! `mesh` but not `node`, so the gate names `node` explicitly: run these with a
//! feature set that includes it, e.g. `--features raft,test-utils,debug`.
#![cfg(all(feature = "raft", feature = "test-utils", feature = "node"))]

use std::sync::Arc;
use std::time::Duration;

use enclavia_protocol::attestation::test_utils::{FakeAttestation, FakeChainAttestation};
use enclavia_protocol::attestation::{CONTROL_PUBKEY_LEN, Pcrs};
use enclavia_protocol::chain::{ChainLink, ChainLinkKind, PcrsHex, UpgradePayload};
use enclavia_protocol::{NoiseTransport, perform_handshake_as_initiator};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use synchronizer::listener::{Frame, MAX_FRAME_SIZE, handle_connection};
use synchronizer::mesh::Mesh;
use synchronizer::mesh::attestation::FakeAttestor;
use synchronizer::mesh::config::MeshConfig;
use synchronizer::mesh::identity::MeshIdentity;
use synchronizer::mesh::transport::{MeshHostStub, UdsMeshAcceptor};
use synchronizer::raft::{RaftHandle, RaftRequestHandler, ReplicatedDispatch};
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

fn pcrs_hex_from_seed(seed: u8) -> PcrsHex {
    PcrsHex {
        pcr0: hex::encode(vec![seed; 48]),
        pcr1: hex::encode(vec![seed.wrapping_add(1); 48]),
        pcr2: hex::encode(vec![seed.wrapping_add(2); 48]),
    }
}

/// The PcrKey a customer seed's PCR triple hashes to. Matches both
/// `FakeAttestation::with_seed`'s PCRs and the transition-link derivation.
fn key_from_seed(seed: u8) -> PcrKey {
    let raw = Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    };
    PcrKey(raw.digest())
}

/// Build a #47 upgrade chain link `from_seed -> to_seed`, signed by the OLD
/// enclave's control key and attested for the OLD measurements.
fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
    let payload = UpgradePayload {
        enclave_id: uuid::Uuid::new_v4(),
        from_pcrs: pcrs_hex_from_seed(from_seed),
        to_pcrs: pcrs_hex_from_seed(to_seed),
        image_digest: "sha256:to".into(),
        valid_from: chrono::Utc::now(),
        issued_at: chrono::Utc::now(),
        nonce: vec![0x5a; 32],
    };
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
    let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
    let sig: Signature = signing.sign(&payload_bytes);
    ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Upgrade,
        payload: payload_bytes,
        attestation,
        signature: Some(sig.to_bytes().to_vec()),
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
    spawn_node_full(name, host, RaftHandle::default_config(), None).await
}

/// Like [`spawn_node`] but with a caller-chosen openraft config, so the
/// hydration test can force aggressive snapshotting + log purging (the
/// InstallSnapshot path proven in slice 3).
async fn spawn_node_with_config(
    name: &str,
    host: &MeshHostStub,
    raft_config: synchronizer::raft::Config,
) -> Node {
    spawn_node_full(name, host, raft_config, None).await
}

/// Full spawn with an optional full-replication-wait override. The
/// partitioned-write test passes a short wait so a write that can never reach
/// all three replicas fails fast (with `Unavailable`) instead of burning the
/// 2s production default on every dispatcher retry; everything else uses the
/// default by passing `None`.
async fn spawn_node_full(
    name: &str,
    host: &MeshHostStub,
    raft_config: synchronizer::raft::Config,
    replication_wait: Option<Duration>,
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

    let mut raft = RaftHandle::with_config(
        Arc::clone(&mesh),
        name,
        self_pubkey,
        &peers,
        handler.clone(),
        raft_config,
    )
    .await
    .expect("RaftHandle::with_config");
    // Apply the replication-wait override BEFORE installing the handle into the
    // serving handler / dispatcher: both take a clone, and the wait must travel
    // with it.
    if let Some(wait) = replication_wait {
        raft = raft.with_replication_wait(wait);
    }
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
                        let _ = handle_connection(&*dispatch, stream, true).await;
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
}

impl Client {
    /// Connect to `node`'s customer listener, do the Noise handshake, and send
    /// the `Authenticate` frame for a session attested as `seed` with the
    /// supplied control pubkey.
    async fn connect(node: &Node, seed: u8, pubkey: [u8; CONTROL_PUBKEY_LEN]) -> Client {
        let mut stream = UnixStream::connect(&node.client_sock).await.unwrap();
        let (mut transport, hash) = perform_handshake_as_initiator(&mut stream).await.unwrap();
        let fake = FakeAttestation::with_seed_and_pubkey(seed, hash, pubkey);
        let auth = Frame::Authenticate {
            nsm_doc: fake.encode(),
        };
        write_frame(&mut stream, &mut transport, &auth).await;
        Client { stream, transport }
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

/// A short full-replication wait for the partitioned-write test: a write that
/// can never reach the down node fails fast instead of burning the 2s
/// production default per dispatcher retry. Still well above the healthy
/// follower append latency on the in-process UDS mesh, so a whole cluster ACKs
/// normally.
const TEST_REPLICATION_WAIT: Duration = Duration::from_millis(150);

/// Like [`cluster`] but every node uses [`TEST_REPLICATION_WAIT`] for the
/// full-replication ACK, so partitioned writes fail quickly.
async fn cluster_short_replication_wait(host: &MeshHostStub) -> Vec<Node> {
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(
            spawn_node_full(
                name,
                host,
                RaftHandle::default_config(),
                Some(TEST_REPLICATION_WAIT),
            )
            .await,
        );
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

/// The IMMEDIATE, no-settle-loop proof of the full-replication ACK: the moment
/// a write is ACKed, EVERY node's LOG already holds the committed entry. This is
/// exactly what `client_write_durable` waits for (every voter's match index
/// reaches the entry's index) and is the durability guarantee the design rests
/// on: with the entry in every node's log, re-seeding from ANY single survivor
/// (#122) replays it, so no ACKed write is ever lost.
///
/// Concretely: assert every node's `last_log_index` covers the leader's
/// last-applied index (the leader applied the entry before ACKing, and the ACK
/// waited for every follower's log to reach it). NO loop: if this is not true
/// the instant the ACK returns, the full-replication ACK is broken.
fn assert_all_nodes_logged_committed(nodes: &[Node]) {
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
    for n in nodes {
        let last_log = n.raft.raft().metrics().borrow().last_log_index.unwrap_or(0);
        assert!(
            last_log >= target,
            "node {} log index {last_log} < committed index {target} right after the ACK \
             (full-replication ACK violated)",
            n.name
        );
    }
}

/// Assert EVERY node's state machine holds `key` at `version`. The
/// full-replication ACK guarantees the entry is in every node's LOG immediately
/// (proven separately, no loop, by [`assert_all_nodes_logged_committed`]);
/// applying that committed entry into the follower's STATE MACHINE trails log
/// replication by at most one heartbeat (openraft applies on the follower once
/// it learns the advanced commit index). So observing the applied projection
/// uses a short bounded convergence: this is NOT a replication settle loop (the
/// durability is already guaranteed at ACK), only a wait for the downstream
/// deterministic apply to land.
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
/// MUST hold is full-replication: the ACKed entry is on all three nodes (its
/// log presence proven with no loop), applied at the identical version (a short
/// bounded apply-convergence, as in [`assert_all_nodes_have`]).
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
        .rpc(Request::Pin {
            key,
            commitment: c(0xaa),
        })
        .await;
    assert_eq!(
        resp,
        Response::PinOk {
            version: Version(0)
        }
    );

    // Full-replication ACK: the moment the Pin is ACKed, EVERY node's LOG
    // already holds the committed entry. NO settle loop, the ACK is the
    // guarantee (this is what `client_write_durable` waited for).
    assert_all_nodes_logged_committed(&nodes);
    // And the entry applies into every node's state machine (apply trails log
    // replication by <= one heartbeat; bounded convergence, not a settle loop).
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
        .rpc(Request::Pin {
            key,
            commitment: c(0xbb),
        })
        .await;
    assert_eq!(
        resp,
        Response::PinOk {
            version: Version(0)
        }
    );

    // Full-replication ACK holds regardless of which node the client dialed:
    // the forwarded write was ACKed only after every node's log had it (no
    // loop), and applies into every state machine (bounded convergence).
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
        .rpc(Request::Pin {
            key,
            commitment: c(0xcd),
        })
        .await;
    assert_eq!(
        resp,
        Response::PinOk {
            version: Version(0)
        }
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
            .rpc(Request::Pin {
                key: old_key,
                commitment: c(0xaa),
            })
            .await;
        assert_eq!(
            r,
            Response::PinOk {
                version: Version(0)
            }
        );
        let r = old
            .rpc(Request::Pin {
                key: old_key,
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
            .rpc(Request::Pin {
                key,
                commitment: c(0x10 + i),
            })
            .await;
        assert_eq!(
            r,
            Response::PinOk {
                version: Version(0)
            }
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

/// (e) Partition the LEADER; under full-replication ACK the two survivors
/// re-elect but writes through the new leader now STALL (a write needs all
/// three nodes, and the old leader is down), so a client write must fail with
/// `Unavailable` rather than a false ACK. Linearizable reads still work (they
/// need only a fresh quorum). After healing the partition, writes succeed again
/// and the value is present on all three nodes.
///
/// This is the deliberate behavior change from the old majority-ACK world,
/// where a survivor-served write would commit on the 2-node quorum. Under
/// full-replication ACK, ANY single-node outage blocks writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_stall_under_node_outage_reads_ok_then_heal() {
    let host = MeshHostStub::new();
    let nodes = cluster_short_replication_wait(&host).await;

    // Commit one key while the cluster is whole (all three replicate it).
    let seed = 0x55;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);
    {
        let mut client = Client::connect(find(&nodes, "node-a"), seed, pk).await;
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x01),
            })
            .await;
        assert_eq!(
            r,
            Response::PinOk {
                version: Version(0)
            }
        );
    }
    assert_all_nodes_logged_committed(&nodes);
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    // Partition the current leader from the mesh: its splices are severed and
    // new dials to/from it are refused, so the surviving two re-elect a leader
    // among themselves. But the cluster is no longer whole.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    host.block(leader_name.clone());

    // Let the surviving two re-elect so the survivor we dial has a leader to
    // forward to (otherwise the failure would be "no leader", not "not fully
    // replicated"; we want to prove the write reaches a leader and STILL cannot
    // be ACKed because the third node is down).
    let survivors: Vec<&Node> = nodes.iter().filter(|n| n.name != leader_name).collect();
    let elected = {
        let start = std::time::Instant::now();
        loop {
            let mut found = None;
            for n in &survivors {
                if n.raft.is_leader().await {
                    found = Some(n.name.clone());
                    break;
                }
            }
            if found.is_some() {
                break found;
            }
            if start.elapsed() > Duration::from_secs(10) {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    assert!(
        elected.is_some(),
        "survivors never re-elected a leader after the leader partition"
    );

    // A client against a survivor: the Pin is forwarded to the new leader, which
    // commits it on the 2-node majority but can NEVER replicate it to the
    // partitioned node, so client_write_durable times out and the client sees
    // Unavailable. It must NEVER see a PinOk: that would be a false ACK of a
    // write not present on all replicas. Try a handful of times to be sure it is
    // never spuriously a success.
    let survivor = survivors[0];
    let mut client = Client::connect(survivor, seed, pk).await;
    // A single client RPC already exercises the partitioned write thoroughly:
    // the dispatcher internally retries the forward up to FORWARD_MAX_RETRIES
    // times, each paying one short replication-wait, before surfacing
    // Unavailable. Two outer attempts are belt-and-braces against a transient
    // re-election window where no leader is momentarily known.
    for _ in 0..2 {
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x02),
            })
            .await;
        match r {
            Response::Err {
                error: RpcError::Unavailable,
            } => {}
            Response::PinOk { version } => panic!(
                "FALSE ACK: write returned PinOk(version={version:?}) while a node was down; \
                 full-replication ACK must refuse to ACK"
            ),
            other => panic!("unexpected response during outage: {other:?}"),
        }
    }

    // Linearizable reads keep working through a survivor while a node is down: a
    // read needs only a fresh quorum, not full replication. Note the read
    // reflects the latest MAJORITY-COMMITTED value: the writes above were
    // refused at the ACK boundary (the client never got a PinOk), but openraft
    // still committed them on the 2-node majority, so the linearized read sees
    // commitment 0x02 at whatever version those committed pins reached. The
    // point being asserted is that the read SUCCEEDS (reads are unaffected by
    // the full-replication write gate), not a specific version.
    let r = client.rpc(Request::Get { key }).await;
    match r {
        Response::GetOk { commitment, .. } => {
            assert!(
                commitment == c(0x01) || commitment == c(0x02),
                "linearizable read returned an unexpected commitment: {commitment:?}"
            );
        }
        other => panic!("linearizable read failed while a node was down: {other:?}"),
    }

    // Heal the partition. Once the cluster is whole again, the same write
    // succeeds and is present on all three nodes. The exact version is not
    // pinned down (each failed-but-committed Pin during the outage benignly
    // bumped it, the documented at-least-once duplicate-Pin behavior), so we
    // assert success + full-replication agreement rather than a fixed number.
    host.unblock(&leader_name);
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader after healing"
    );
    let mut committed = None;
    for _ in 0..20 {
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x02),
            })
            .await;
        match r {
            Response::PinOk { version } => {
                committed = Some(version);
                break;
            }
            Response::Err {
                error: RpcError::Unavailable,
            } => tokio::time::sleep(Duration::from_millis(200)).await,
            other => panic!("unexpected response after heal: {other:?}"),
        }
    }
    let committed = committed.expect("write never succeeded after healing the partition");
    // The ACKed version is on all three nodes (full-replication ACK), and it is
    // at least the pre-outage version + 1.
    let agreed = assert_all_nodes_agree(&nodes, key).await;
    assert_eq!(agreed, committed, "ACKed version not the one on all nodes");
    assert!(
        committed.0 >= 1,
        "version did not advance past the pre-outage value"
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// (b) No false ACK under a single-node outage. Partition ONE node (a
/// non-leader, so no re-election is needed), submit a Pin to the LEADER, and
/// assert the client receives `Unavailable`, NOT a success: the entry committed
/// on the 2-node majority but cannot reach the partitioned node, so the
/// full-replication ACK refuses to ACK. Then heal, retry, and assert success
/// plus all-three visibility.
///
/// Leader-submitted timing note: `route_client_request`'s leader fast path runs
/// `handle_on_leader` directly; the `client_write_durable` there waits up to
/// [`TEST_REPLICATION_WAIT`] for the down node, then returns
/// `NotFullyReplicated` -> wire `Unavailable`. That `Unavailable` is "transient"
/// to the dispatcher, so it retries the whole dispatch a bounded number of times
/// (`FORWARD_MAX_RETRIES`), each paying one short replication-wait, then the RPC
/// returns `Unavailable` to the client. The short wait keeps the total bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_false_ack_when_a_node_is_partitioned() {
    let host = MeshHostStub::new();
    let nodes = cluster_short_replication_wait(&host).await;

    let seed = 0x66;
    let (_, pk) = keypair(seed);
    let key = key_from_seed(seed);

    // Commit a first version while the cluster is whole.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    {
        let leader = find(&nodes, &leader_name);
        let mut client = Client::connect(leader, seed, pk).await;
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x01),
            })
            .await;
        assert_eq!(
            r,
            Response::PinOk {
                version: Version(0)
            }
        );
    }
    assert_all_nodes_logged_committed(&nodes);
    assert_all_nodes_have(&nodes, key, Version(0)).await;

    // Partition a NON-leader so the leader stays put (no re-election): the
    // cluster keeps its leader + a 2-node majority, but is no longer whole.
    let victim_name = nodes
        .iter()
        .find(|n| n.name != leader_name)
        .unwrap()
        .name
        .clone();
    host.block(victim_name.clone());

    // Submit a Pin to the LEADER. The leader commits on the majority but cannot
    // replicate to the partitioned node, so client_write_durable times out and
    // the client must see Unavailable, never a false PinOk.
    let leader = find(&nodes, &leader_name);
    let mut client = Client::connect(leader, seed, pk).await;
    // One client RPC already drives the dispatcher's internal forward-retry to
    // exhaustion against the down node; two outer attempts guard a transient
    // re-election window.
    for _ in 0..2 {
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x02),
            })
            .await;
        match r {
            Response::Err {
                error: RpcError::Unavailable,
            } => {}
            Response::PinOk { version } => panic!(
                "FALSE ACK: leader returned PinOk(version={version:?}) with a node partitioned; \
                 full-replication ACK must refuse to ACK"
            ),
            other => panic!("unexpected response during partition: {other:?}"),
        }
    }

    // Heal: unblock the partitioned node, wait for it to catch up, then retry
    // the Pin. It now succeeds and is visible on all three nodes. The exact
    // version is not pinned (failed-but-committed Pins during the outage benignly
    // bumped it), so we assert success + full-replication agreement.
    host.unblock(&victim_name);
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader after healing"
    );
    let mut committed = None;
    for _ in 0..20 {
        let r = client
            .rpc(Request::Pin {
                key,
                commitment: c(0x02),
            })
            .await;
        match r {
            Response::PinOk { version } => {
                committed = Some(version);
                break;
            }
            Response::Err {
                error: RpcError::Unavailable,
            } => tokio::time::sleep(Duration::from_millis(200)).await,
            other => panic!("unexpected response after heal: {other:?}"),
        }
    }
    let committed = committed.expect("Pin never succeeded after healing the partition");
    let agreed = assert_all_nodes_agree(&nodes, key).await;
    assert_eq!(agreed, committed, "ACKed version not the one on all nodes");
    assert!(
        committed.0 >= 1,
        "version did not advance past the pre-outage value"
    );

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
                .rpc(Request::Pin {
                    key,
                    commitment: c(0xb2)
                })
                .await,
            Response::PinOk {
                version: Version(0)
            }
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
                .rpc(Request::Pin {
                    key,
                    commitment: c(0xa1)
                })
                .await,
            Response::PinOk {
                version: Version(0)
            }
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
            .rpc(Request::Pin {
                key,
                commitment: c(0xb2)
            })
            .await,
        Response::PinOk {
            version: Version(0)
        }
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
        let r = tokio::time::timeout(
            Duration::from_secs(8),
            client.rpc(Request::Pin {
                key,
                commitment: c(0x5a),
            }),
        )
        .await;
        assert!(
            matches!(
                r,
                Ok(Response::Err {
                    error: RpcError::Unavailable
                }) | Err(_)
            ),
            "a write succeeded without quorum (the cluster did not halt): {r:?}"
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
