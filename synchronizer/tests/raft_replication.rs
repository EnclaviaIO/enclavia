//! Focused 3-node Raft replication tests (#119): leader election, single-op
//! replication to all followers, the leader-hint / `is_leader` API, and the
//! linearizable read path. The randomized fault-injection invariant lives in
//! `raft_node_view_consistent.rs`; this file is the happy-path acceptance check
//! and exercises the [`RaftHandle`] read / leader-hint surface slice 4 drives.
//!
//! Gated on `raft` + `test-utils`.
#![cfg(all(feature = "raft", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;

use synchronizer::mesh::Mesh;
use synchronizer::mesh::attestation::FakeAttestor;
use synchronizer::mesh::config::MeshConfig;
use synchronizer::mesh::identity::MeshIdentity;
use synchronizer::mesh::transport::{MeshHostStub, UdsMeshAcceptor};
use synchronizer::raft::{RaftHandle, RaftRequestHandler, ReplicatedOp};
use synchronizer::{Commitment, Op, PcrKey, StateMachine, Version};

const IMAGE_SEED: u8 = 0x42;
const NODE_NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

fn pubkey(seed: u64) -> [u8; 65] {
    use p256::ecdsa::SigningKey;
    let mut scalar = [0u8; 32];
    scalar[0] = 0x01;
    scalar[1..9].copy_from_slice(&seed.to_be_bytes());
    let sk = SigningKey::from_slice(&scalar).unwrap();
    let pk = sk.verifying_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(pk.as_bytes());
    out
}
fn key(idx: u64) -> PcrKey {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&idx.to_be_bytes());
    b[31] = 0xab;
    PcrKey(b)
}
/// A cheap, distinct 65-byte SEC1-shaped control pubkey for `idx`. The
/// replicated `Register` path only STORES the pubkey (it is the leader, not the
/// follower, that already verified attestation), so the bytes need not be a
/// valid P-256 point: distinctness is all the snapshot-size test needs, and it
/// avoids 600+ real key derivations on the hot path.
fn fake_pubkey(idx: u64) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04; // uncompressed SEC1 tag, for shape only
    out[1..9].copy_from_slice(&idx.to_be_bytes());
    out[64] = 0xcd;
    out
}
fn commitment(n: u64) -> Commitment {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    Commitment(b)
}

struct Node {
    name: String,
    _mesh: Arc<Mesh>,
    raft: RaftHandle,
    /// The background #209 discovery/join + eviction-watch task. Aborted on
    /// drop so a killed node's discovery does not linger.
    _bootstrap: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        self._bootstrap.abort();
    }
}

async fn spawn_node(name: &str, host: &MeshHostStub) -> Node {
    spawn_node_with_config(name, host, RaftHandle::default_config()).await
}

/// Like [`spawn_node`] but with a caller-chosen openraft config, so the
/// hydration test can force aggressive snapshotting + log purging and thereby
/// exercise the InstallSnapshot path on a restarted empty node.
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
    let sock = dir.path().join(format!("{name}.sock"));
    let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
    host.register(name, &sock);
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
        true,
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
    .unwrap();
    // Enable serving (so inbound joins are admitted) and drive #209 discovery:
    // the smallest-name node initializes a fresh cluster from peers' attested
    // pubkeys, the others join. Replaces the old single-node initialize_cluster.
    raft.enable_serving(&handler, true);
    let bootstrap = {
        let raft = raft.clone();
        let mesh = Arc::clone(&mesh);
        tokio::spawn(async move {
            synchronizer::raft::discover_and_join(&raft, &mesh).await;
            synchronizer::raft::watch_for_eviction(raft).await;
        })
    };
    Node {
        name: name.to_string(),
        _mesh: mesh,
        raft,
        _bootstrap: bootstrap,
        _dir: dir,
    }
}

async fn leader(nodes: &[Node]) -> Option<&Node> {
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
        if leader(nodes).await.is_some() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

/// Acceptance: a 3-node cluster elects a leader quickly; an op submitted to the
/// leader replicates to all three state machines; every node's linearizable /
/// local view agrees; and the non-leaders report the leader as their hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_elect_and_replicate() {
    let host = MeshHostStub::new();
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node(name, &host).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node).

    // A leader is elected within a short window.
    assert!(
        await_leader(&nodes, Duration::from_secs(5)).await,
        "no leader elected"
    );

    // Submit a Register on the leader; it must replicate to all three.
    let ld = leader(&nodes).await.unwrap();
    let st = ld
        .raft
        .client_write(ReplicatedOp::Register {
            key: key(1),
            commitment: commitment(7),
            control_pubkey: pubkey(1),
        })
        .await
        .expect("register applied on leader");
    assert_eq!(st.version, Version(0));

    // Every node converges to the same committed state for key(1).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_have = true;
        for n in &nodes {
            match n.raft.state_machine().get(&key(1)).await {
                Some(s) if s.commitment == commitment(7) && s.version == Version(0) => {}
                _ => all_have = false,
            }
        }
        if all_have {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "op did not replicate to all nodes in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Leader-hint API: every non-leader names the actual leader.
    let leader_name = leader(&nodes).await.unwrap().name.clone();
    for n in &nodes {
        if n.name != leader_name {
            assert_eq!(
                n.raft.leader_name().await.as_deref(),
                Some(leader_name.as_str()),
                "{} should redirect to {leader_name}",
                n.name
            );
        }
    }

    // Linearizable read on the leader returns the committed value; on a
    // follower it is refused (a follower cannot guarantee freshness, and a
    // freshness oracle must not serve stale data).
    let ld = leader(&nodes).await.unwrap();
    let got = ld
        .raft
        .linearizable_get(&key(1))
        .await
        .expect("leader linearizable read");
    assert_eq!(got.map(|s| s.commitment), Some(commitment(7)));

    let follower = nodes.iter().find(|n| n.name != leader_name).unwrap();
    assert!(
        follower.raft.linearizable_get(&key(1)).await.is_err(),
        "a follower must refuse a linearizable read"
    );

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// Killing the leader triggers a re-election and the cluster keeps committing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_failure_reelects_and_keeps_committing() {
    let host = MeshHostStub::new();
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node(name, &host).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node).
    assert!(await_leader(&nodes, Duration::from_secs(5)).await);

    // Commit one op, then KILL the current leader. We drop it (rather than
    // partition it) so its mesh tasks and per-connection serve tasks abort,
    // definitively severing the survivors' connections to it: a partition that
    // only blocks new dials would leave the old leader's existing heartbeat
    // splices alive and the survivors would never time out and re-elect.
    let first_leader = leader(&nodes).await.unwrap().name.clone();
    leader(&nodes)
        .await
        .unwrap()
        .raft
        .client_write(ReplicatedOp::Register {
            key: key(1),
            commitment: commitment(1),
            control_pubkey: pubkey(1),
        })
        .await
        .unwrap();

    let dead_idx = nodes.iter().position(|n| n.name == first_leader).unwrap();
    let dead = nodes.remove(dead_idx);
    dead.raft.shutdown().await;
    drop(dead);

    // The two survivors re-elect within a window and keep committing. Submit to
    // whichever survivor becomes leader, retrying: a freshly-elected leader
    // must commit its initial blank entry before it serves writes.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let committed = match leader(&nodes).await {
            Some(n) => n
                .raft
                .client_write(ReplicatedOp::Register {
                    key: key(2),
                    commitment: commitment(2),
                    control_pubkey: pubkey(2),
                })
                .await
                .is_ok(),
            None => false,
        };
        if committed {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "survivors never re-elected + committed after the leader was killed"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// #121 hydration path: a node restarted with EMPTY state rejoins a quiet
/// cluster and catches its full view up from the survivors. The cluster runs
/// with an aggressive snapshot policy that purges the log, so the empty node's
/// catch-up MUST go through an InstallSnapshot transfer over the mesh, not log
/// replay.
///
/// This is the dedicated, deterministic home for the empty-state-restart fault
/// (kept out of the randomized NodeViewConsistent fuzzer, where stacking it on
/// concurrent partition churn hits openraft 0.9's `loosen-follower-log-revert`
/// debug-assert; see that harness's module docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_empty_node_hydrates_from_peers() {
    // Snapshot after only a few logs and keep none in the log, so the leader's
    // log is purged and a node that lost everything can only catch up via a
    // snapshot install.
    let aggressive = synchronizer::raft::Config {
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: synchronizer::raft::SnapshotPolicy::LogsSinceLast(4),
        max_in_snapshot_log_to_keep: 0,
        ..Default::default()
    };

    let host = MeshHostStub::new();
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node_with_config(name, &host, aggressive.clone()).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node).
    assert!(await_leader(&nodes, Duration::from_secs(5)).await);

    // Commit a batch of ops so the log grows past the snapshot threshold and
    // the leader builds + purges to a snapshot.
    for i in 0..12u64 {
        let ld = leader(&nodes).await.unwrap();
        let _ = ld
            .raft
            .client_write(ReplicatedOp::Register {
                key: key(i),
                commitment: commitment(i),
                control_pubkey: pubkey(i),
            })
            .await;
    }
    // Let snapshots build + log purge settle.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Restart a non-leader with EMPTY state.
    let leader_name = leader(&nodes).await.unwrap().name.clone();
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

    // The fresh empty node must hydrate the FULL set of 12 keys from the
    // survivors (via snapshot install, since the log was purged).
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let view = nodes[victim_idx].raft.state_machine().head_view().await;
        if view.len() == 12 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restarted empty node never hydrated (have {} of 12 keys)",
            view.len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}

/// How many distinct keys to register before the restart. A `Register` snapshot
/// entry costs ~230 raw bytes of CBOR (a `state` entry: 32-byte key + 32-byte
/// commitment + 8-byte version + 65-byte pubkey, plus an `attested` entry:
/// 32-byte key + 65-byte pubkey), so 600 keys take the snapshot blob well past
/// the 65535-byte single-Noise-message ceiling. We assert the actual blob size
/// below so the test stays honest if the snapshot layout ever changes.
const BIG_SNAPSHOT_KEYS: u64 = 600;

/// #121 hydration under a >64 KiB snapshot: the same restarted-empty-node path
/// as [`restarted_empty_node_hydrates_from_peers`], but with enough committed
/// keys that the state-machine snapshot CBOR exceeds the mesh's single-Noise-
/// message ceiling (65535 bytes).
///
/// A mesh RPC is ONE Noise message (`mesh::handshake::write_frame` /
/// `write_message`), and `Noise_NN_25519_ChaChaPoly_BLAKE2s` caps a single
/// message at 65535 bytes. openraft fragments an `InstallSnapshot` into chunks
/// of `Config::snapshot_max_chunk_size` and ships each chunk as one such RPC.
/// With openraft's 3 MiB default chunk size the whole >64 KiB snapshot rides a
/// SINGLE chunk that overflows the frame, so `write_frame` errors and hydration
/// never completes. `RaftHandle::default_config` bounds the chunk to 16 KiB
/// (see `raft::mod`, which explains why the usable budget is well under 64 KiB:
/// the chunk is wrapped in three `Vec<u8>` layers that ciborium encodes as
/// int arrays, inflating it ~3x), and the aggressive config here mirrors that
/// bound, so the snapshot is fragmented into frame-sized chunks and the empty
/// node hydrates.
///
/// Verified to FAIL (hydration times out) when `snapshot_max_chunk_size` is
/// left at openraft's default; passes with the 16 KiB bound. See the commit
/// message.
///
/// The snapshot + purge are triggered EXPLICITLY (once, after the bulk load has
/// gone quiescent) rather than via an aggressive `LogsSinceLast` policy: at 600
/// commits, continuous mid-load snapshot/purge churn races openraft 0.9's
/// `loosen-follower-log-revert` debug-assert (the same hazard the randomized
/// fuzzer's module docs call out). A single deterministic snapshot+purge on a
/// quiet cluster isolates the one thing under test: whether an oversized
/// snapshot survives the mesh frame ceiling on its way to an empty node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_empty_node_hydrates_from_oversized_snapshot() {
    // First, prove the test is meaningful: a state machine carrying
    // `BIG_SNAPSHOT_KEYS` registrations produces a snapshot blob larger than a
    // single Noise message. This mirrors exactly what `build_snapshot` does in
    // the Raft store (snapshot the pure core, CBOR-encode it).
    let mut probe = StateMachine::new();
    for i in 0..BIG_SNAPSHOT_KEYS {
        probe.observe_attestation(key(i), fake_pubkey(i));
        probe
            .apply(Op::Register {
                key: key(i),
                commitment: commitment(i),
            })
            .expect("register applies");
    }
    let mut snapshot_blob = Vec::new();
    ciborium::into_writer(&probe.snapshot(), &mut snapshot_blob).unwrap();
    assert!(
        snapshot_blob.len() > 65535,
        "test is not meaningful: snapshot blob is only {} bytes, not over the \
         65535-byte single-Noise-message ceiling (raise BIG_SNAPSHOT_KEYS)",
        snapshot_blob.len()
    );

    // Aggressive snapshotting + log purge (mirroring
    // `restarted_empty_node_hydrates_from_peers`) so the restarted empty node
    // can ONLY catch up via an InstallSnapshot transfer, plus the 16 KiB chunk
    // bound from `default_config` so the oversized snapshot is fragmented into
    // frame-sized chunks instead of one frame-overflowing chunk.
    let cfg = synchronizer::raft::Config {
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: synchronizer::raft::SnapshotPolicy::LogsSinceLast(4),
        max_in_snapshot_log_to_keep: 0,
        snapshot_max_chunk_size: 16 * 1024,
        max_payload_entries: 64,
        ..Default::default()
    };

    let host = MeshHostStub::new();
    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node_with_config(name, &host, cfg.clone()).await);
    }
    // Cluster bootstraps itself via #209 discovery (driven in spawn_node).
    assert!(await_leader(&nodes, Duration::from_secs(5)).await);

    // Commit all the Registers so the committed state (and thus its snapshot)
    // exceeds 64 KiB.
    for i in 0..BIG_SNAPSHOT_KEYS {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let ld = leader(&nodes).await.expect("a leader is present");
            let ok = ld
                .raft
                .client_write(ReplicatedOp::Register {
                    key: key(i),
                    commitment: commitment(i),
                    control_pubkey: fake_pubkey(i),
                })
                .await
                .is_ok();
            if ok {
                break;
            }
            // A transient leader change mid-batch: retry on the new leader.
            assert!(
                std::time::Instant::now() < deadline,
                "could not commit register {i} of {BIG_SNAPSHOT_KEYS}"
            );
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    // Let the auto snapshot policy build a snapshot and purge the log on the
    // survivors, exactly as `restarted_empty_node_hydrates_from_peers` does, so
    // the restarted empty node can only catch up via an InstallSnapshot transfer.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Restart a non-leader with EMPTY state.
    let leader_name = leader(&nodes).await.unwrap().name.clone();
    let victim_idx = nodes.iter().position(|n| n.name != leader_name).unwrap();
    let victim_name = nodes[victim_idx].name.clone();
    let old = nodes.remove(victim_idx);
    old.raft.shutdown().await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    nodes.insert(
        victim_idx,
        spawn_node_with_config(&victim_name, &host, cfg.clone()).await,
    );

    // The fresh empty node must hydrate the FULL set of keys from the survivors.
    // This can only happen via an InstallSnapshot transfer (the log was purged),
    // and that transfer can only succeed if the oversized snapshot is chunked
    // under the 65535-byte frame ceiling.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let view = nodes[victim_idx].raft.state_machine().head_view().await;
        if view.len() as u64 == BIG_SNAPSHOT_KEYS {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restarted empty node never hydrated from the oversized snapshot \
             (have {} of {BIG_SNAPSHOT_KEYS} keys)",
            view.len()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    for n in &nodes {
        n.raft.shutdown().await;
    }
}
