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
//!   linearizable read);
//! * (b) Pin against one node, Get against ANOTHER (forwarding + linearizable
//!   read see the committed write regardless of which node the client dialed);
//! * (c) the full Transition flow with a real p256-signed #47 upgrade chain
//!   link: register the old key, then a new-enclave session submits the
//!   Transition; the old key retires and the carried version survives;
//! * (d) restart one node with EMPTY state, wait for it to hydrate from the
//!   survivors, then serve a Get from it (forwarded to the leader) and verify
//!   the three nodes' views are identical;
//! * (e) partition the leader mid-traffic; clients against the remaining two
//!   nodes still complete after the survivors re-elect (the dispatcher's
//!   bounded forward-retry rides through the election).
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
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.listener_task.abort();
    }
}

async fn spawn_node(name: &str, host: &MeshHostStub) -> Node {
    spawn_node_with_config(name, host, RaftHandle::default_config()).await
}

/// Like [`spawn_node`] but with a caller-chosen openraft config, so the
/// hydration test can force aggressive snapshotting + log purging (the
/// InstallSnapshot path proven in slice 3).
async fn spawn_node_with_config(
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
        &peers,
        handler.clone(),
        raft_config,
    )
    .await
    .expect("RaftHandle::with_config");
    raft.enable_serving(&handler, true);

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
    nodes[0].raft.initialize_cluster().await.unwrap();
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
    nodes[0].raft.initialize_cluster().await.unwrap();
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader elected at startup"
    );
    nodes
}

fn find<'a>(nodes: &'a [Node], name: &str) -> &'a Node {
    nodes.iter().find(|n| n.name == name).unwrap()
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

/// (e) Partition the leader mid-traffic; clients against the surviving two
/// nodes still complete after the survivors re-elect. The dispatcher's bounded
/// forward-retry rides through the election window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_complete_after_leader_partition() {
    let host = MeshHostStub::new();
    let nodes = cluster(&host).await;

    // Commit one key before the partition.
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

    // Partition the current leader from the mesh: its splices are severed and
    // new dials to/from it are refused, so the surviving two re-elect.
    let leader_name = current_leader(&nodes).await.unwrap().name.clone();
    host.block(leader_name.clone());

    // A client against one of the two survivors keeps working: the Pin is
    // forwarded to the freshly-elected leader (the dispatcher retries across the
    // election). Pick a survivor that is NOT the old leader.
    let survivor = nodes.iter().find(|n| n.name != leader_name).unwrap();
    let mut client = Client::connect(survivor, seed, pk).await;

    // The write must eventually commit (a fresh re-pin bumps to version 1). The
    // dispatcher's internal retry handles the re-election; if it ever surfaced
    // Unavailable we retry the whole RPC a few times to ride a longer election.
    let mut committed = None;
    for _ in 0..10 {
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
            } => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => panic!("unexpected response during partition: {other:?}"),
        }
    }
    assert_eq!(
        committed,
        Some(Version(1)),
        "client never committed against the surviving nodes after the leader partition"
    );

    // A linearizable Get through a survivor returns the latest committed value.
    let r = client.rpc(Request::Get { key }).await;
    assert_eq!(
        r,
        Response::GetOk {
            commitment: c(0x02),
            version: Version(1),
        }
    );

    host.unblock(&leader_name);
    for n in &nodes {
        n.raft.shutdown().await;
    }
}
