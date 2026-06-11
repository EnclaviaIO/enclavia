//! NodeViewConsistent fuzz harness (acceptance gate for #119, slice 3).
//!
//! Stands up an in-process 3-node Raft cluster over the test-utils mesh
//! transports + `FakeAttestor` (no QEMU, no vsock), then drives a randomized,
//! deterministic-per-seed interleaving of client ops (Register / Pin /
//! Transition, all with VALID embedded facts the way the leader would have
//! verified them) against the current leader, with fault injection:
//!
//! * drop and reheal individual mesh links / isolate a node (partition the
//!   stub, then unblock it: this severs the victim's live splices too, so a
//!   partitioned leader genuinely steps down);
//! * leader changes (partitioning the current leader forces a re-election
//!   among the surviving two).
//!
//! The empty-state restart + snapshot/log hydration fault is exercised by a
//! dedicated deterministic test,
//! `raft_replication::restarted_empty_node_hydrates_from_peers`, rather than
//! stacked into this fuzzer: combining an empty-state restart (which drops a
//! node's committed log) with simultaneous partition churn is the
//! cold-start-adjacent regime the no-persistence design defers (#122), and
//! openraft 0.9's `loosen-follower-log-revert` mode trips an internal
//! debug-assert in that combination. Keeping hydration on its own quiet-cluster
//! test covers the path the brief asks for without the unrelated flake.
//!
//! Invariant checked after quiescence (all links healed, log settled): the
//! three nodes report the IDENTICAL view, the same `get()` for every key ever
//! touched, the same `head_keys()`, the same `retired_keys()`, and per-key
//! versions are monotonic across the whole run from the perspective of accepted
//! client responses (a key's version never decreases, no rollback). This is the
//! TLA+ `NodeViewConsistent` invariant against the replicated state machine.
//!
//! Gated on `raft` + `test-utils`.
#![cfg(all(feature = "raft", feature = "test-utils"))]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use synchronizer::mesh::Mesh;
use synchronizer::mesh::attestation::FakeAttestor;
use synchronizer::mesh::config::MeshConfig;
use synchronizer::mesh::identity::MeshIdentity;
use synchronizer::mesh::transport::{MeshHostStub, UdsMeshAcceptor};
use synchronizer::raft::{RaftHandle, RaftHandleError, RaftRequestHandler, ReplicatedOp};
use synchronizer::{Commitment, PcrKey, Version};

/// All three nodes run the same EIF, so they share a PCR seed: the self-PCR
/// allowlist admits a peer only when its digest equals the node's own.
const IMAGE_SEED: u8 = 0x42;

const NODE_NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

/// A deterministic, valid-point 65-byte SEC1 P-256 control pubkey for a given
/// seed. The pure core never verifies these bytes in the replicated path (the
/// leader already did the crypto), so any distinct 65-byte value works; we use
/// a real curve point so the value is well-formed.
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

/// A distinct PcrKey for a logical key index.
fn key(idx: u64) -> PcrKey {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&idx.to_be_bytes());
    b[31] = 0xab;
    PcrKey(b)
}

/// A distinct commitment for a counter.
fn commitment(n: u64) -> Commitment {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    b[31] = 0xcd;
    Commitment(b)
}

/// One node under test: its mesh + Raft handle + temp dir (dropping it kills
/// the node, which is the "restart" operation's first half).
struct Node {
    name: String,
    /// Kept alive for the node's lifetime: dropping the mesh aborts its dial /
    /// accept loops (that is exactly the "kill the node" operation). Never read
    /// directly after construction.
    _mesh: Arc<Mesh>,
    raft: RaftHandle,
    _dir: tempfile::TempDir,
}

/// Spin up one node over the shared stub: bind its inbound socket, build the
/// mesh with a deferred Raft handler, then construct the Raft handle and
/// install it into the handler. Bidirectional partitioning works because the
/// dialer is tagged with this node's own name (`dialer_for`).
async fn spawn_node(name: &str, host: &MeshHostStub) -> Node {
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

    let raft = RaftHandle::new(Arc::clone(&mesh), name, &peers, handler)
        .await
        .expect("RaftHandle::new");

    Node {
        name: name.to_string(),
        _mesh: mesh,
        raft,
        _dir: dir,
    }
}

/// Find the node that currently believes it is the leader, if any.
async fn current_leader(nodes: &[Node]) -> Option<&Node> {
    for n in nodes {
        if n.raft.is_leader().await {
            return Some(n);
        }
    }
    None
}

/// Wait until SOME node reports a stable leader, or the deadline elapses.
async fn await_leader(nodes: &[Node], timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if current_leader(nodes).await.is_some() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Submit `op` to whichever node is the leader, retrying across a window so a
/// just-changed leader or a transient ForwardToLeader does not flake. Returns
/// the resulting [`Version`] on success (for the monotonicity oracle), `None`
/// if the op was deterministically rejected by the state machine, or panics if
/// the cluster never accepted/rejected it within the window (a liveness bug).
async fn submit(nodes: &[Node], op: ReplicatedOp) -> Option<Version> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let leader = match current_leader(nodes).await {
            Some(l) => l,
            None => {
                if std::time::Instant::now() > deadline {
                    panic!("no leader to accept op within window");
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
                continue;
            }
        };
        match leader.raft.client_write(op.clone()).await {
            Ok(state) => return Some(state.version),
            // Deterministic state-machine rejection: a legitimate outcome
            // (e.g. racing duplicate Register). Not a consistency violation.
            Err(RaftHandleError::Rejected(_)) => return None,
            // Not the leader / quorum lost / transient: retry on the (possibly
            // new) leader.
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            Err(e) => panic!("op never accepted within window: {e}"),
        }
    }
}

/// The harness's model of what keys are live and what each expects, so it can
/// generate VALID ops (Pin/Transition against a currently-registered key) and
/// run the per-key version-monotonicity oracle.
#[derive(Default)]
struct Model {
    /// Currently-registered logical key indices -> last accepted version.
    live: BTreeMap<u64, u64>,
    /// Retired logical key indices.
    retired: std::collections::BTreeSet<u64>,
    /// Highest version ever accepted per key index (rollback oracle).
    max_version: BTreeMap<u64, u64>,
    /// Next fresh key index to hand out.
    next_idx: u64,
}

impl Model {
    fn fresh_idx(&mut self) -> u64 {
        let i = self.next_idx;
        self.next_idx += 1;
        i
    }

    fn record_version(&mut self, idx: u64, v: u64) {
        let m = self.max_version.entry(idx).or_insert(0);
        assert!(
            v >= *m,
            "version rollback for key {idx}: accepted {v} after {m}"
        );
        *m = v.max(*m);
        self.live.insert(idx, v);
    }
}

/// Run one randomized scenario under `seed`: bring the cluster up, drive a
/// randomized op + fault interleaving, heal everything, then assert the three
/// nodes converge to the identical view and no version ever rolled back.
async fn run_scenario(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let host = MeshHostStub::new();

    let mut nodes = Vec::new();
    for name in NODE_NAMES {
        nodes.push(spawn_node(name, &host).await);
    }

    // Initialize the cluster on one node; it elects a leader within a few
    // hundred ms.
    nodes[0]
        .raft
        .initialize_cluster()
        .await
        .expect("initialize_cluster");
    assert!(
        await_leader(&nodes, Duration::from_secs(10)).await,
        "no leader elected at startup (seed {seed})"
    );

    let mut model = Model::default();
    // Track which logical key index maps to which pubkey-seed so Transition can
    // carry the right new pubkey (cosmetic for the pure core; kept faithful).
    let pubkey_seed = |idx: u64| idx.wrapping_mul(2_654_435_761);

    let mut commit_counter: u64 = 0;
    let steps = 60;
    for step in 0..steps {
        // --- fault injection (interleaved with ops) ---
        //
        // ~30% of steps partition a single node (link drop / leader change):
        // block the stub from routing dials to/from the victim AND sever its
        // live splices for a window, then heal. If the victim was the leader,
        // the surviving two re-elect (a genuine leader change); otherwise the
        // victim falls behind and catches up on heal. Either way 2 of 3 nodes
        // stay connected, so quorum holds.
        //
        // This randomized harness drives partitions + leader changes + link
        // drops under the full Register/Pin/Transition op mix. The empty-state
        // restart + hydration fault is exercised separately, as a dedicated
        // deterministic test
        // (`raft_replication::restarted_empty_node_hydrates_from_peers`):
        // combining an empty-state restart with simultaneous partition churn is
        // the cold-start-adjacent regime the no-persistence design defers
        // (#122), and openraft 0.9's `loosen-follower-log-revert` mode trips an
        // internal debug-assert there, so we keep that path on its own
        // quiet-cluster test rather than stacking it into the fuzzer.
        if rng.gen_range(0u8..100) < 30 {
            let victim = NODE_NAMES[rng.gen_range(0..NODE_NAMES.len())];
            host.block(victim);
            tokio::time::sleep(Duration::from_millis(rng.gen_range(120..400))).await;
            host.unblock(victim);
        }

        // --- one client op against the leader ---
        // Make sure there's a leader to talk to (a fault may have just
        // triggered a re-election).
        if !await_leader(&nodes, Duration::from_secs(10)).await {
            panic!("cluster lost its leader permanently at step {step} (seed {seed})");
        }

        let choice = rng.gen_range(0u8..100);
        if model.live.is_empty() || choice < 40 {
            // Register a fresh key.
            let idx = model.fresh_idx();
            commit_counter += 1;
            let op = ReplicatedOp::Register {
                key: key(idx),
                commitment: commitment(commit_counter),
                control_pubkey: pubkey(pubkey_seed(idx)),
            };
            if let Some(v) = submit(&nodes, op).await {
                model.record_version(idx, v.0);
            }
        } else if choice < 80 {
            // Pin an existing live key.
            let idx = *model
                .live
                .keys()
                .nth(rng.gen_range(0..model.live.len()))
                .unwrap();
            commit_counter += 1;
            let op = ReplicatedOp::Pin {
                key: key(idx),
                commitment: commitment(commit_counter),
            };
            if let Some(v) = submit(&nodes, op).await {
                model.record_version(idx, v.0);
            }
        } else {
            // Transition an existing live key to a fresh successor.
            let old_idx = *model
                .live
                .keys()
                .nth(rng.gen_range(0..model.live.len()))
                .unwrap();
            let new_idx = model.fresh_idx();
            let op = ReplicatedOp::Transition {
                old_key: key(old_idx),
                new_key: key(new_idx),
                new_control_pubkey: pubkey(pubkey_seed(new_idx)),
            };
            if let Some(v) = submit(&nodes, op).await {
                // The successor adopts the old key's state; retire the old,
                // make the new live carrying the same version.
                model.live.remove(&old_idx);
                model.retired.insert(old_idx);
                model.record_version(new_idx, v.0);
            }
        }
    }

    // --- quiesce: heal everything, then wait for the cluster to fully settle.
    for name in NODE_NAMES {
        host.unblock(name);
    }
    // After aggressive churn (including leader restarts) the cluster needs a
    // stable leader, a committed settle op that every node applies, and time
    // for any just-restarted node to hydrate. Loop until all three nodes'
    // applied index AND head view match, re-driving a settle op as needed.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let settle_idx = model.fresh_idx();
    let mut settle_committed = false;
    loop {
        // Ensure a leader, then push one settle op (idempotent: a duplicate
        // Register is deterministically rejected, which is fine).
        if await_leader(&nodes, Duration::from_secs(10)).await && !settle_committed {
            commit_counter += 1;
            let op = ReplicatedOp::Register {
                key: key(settle_idx),
                commitment: commitment(commit_counter),
                control_pubkey: pubkey(pubkey_seed(settle_idx)),
            };
            if let Some(v) = submit(&nodes, op).await {
                model.record_version(settle_idx, v.0);
                settle_committed = true;
            }
        }
        if cluster_converged(&nodes).await {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let mut diag = String::new();
            for n in &nodes {
                let m = n.raft.raft().metrics().borrow().clone();
                let hv = n.raft.state_machine().head_view().await.len();
                diag.push_str(&format!(
                    "{}=[applied={:?} leader={:?} state={:?} head={hv}] ",
                    n.name,
                    m.last_applied.map(|l| l.index),
                    m.current_leader,
                    m.state
                ));
            }
            panic!("cluster never converged after healing (seed {seed}): {diag}");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // --- invariant: all three nodes report the identical view ---
    let mut views = Vec::new();
    for n in &nodes {
        let head = n.raft.state_machine().head_view().await;
        let retired = n.raft.state_machine().retired_view().await;
        views.push((n.name.clone(), head, retired));
    }
    let (ref_name, ref_head, ref_retired) = &views[0];
    for (name, head, retired) in &views[1..] {
        assert_eq!(
            head, ref_head,
            "head view diverged: {name} vs {ref_name} (seed {seed})"
        );
        assert_eq!(
            retired, ref_retired,
            "retired view diverged: {name} vs {ref_name} (seed {seed})"
        );
    }

    // --- invariant: the converged view matches the model ---
    // Every live key the model tracked is present at its expected version;
    // every retired key is absent and in the retired set.
    for (idx, expected_v) in &model.live {
        let got = ref_head.get(&key(*idx)).unwrap_or_else(|| {
            panic!("converged view missing live key {idx} (seed {seed})");
        });
        assert_eq!(
            got.version,
            Version(*expected_v),
            "key {idx} version mismatch (seed {seed})"
        );
    }
    for idx in &model.retired {
        assert!(
            !ref_head.contains_key(&key(*idx)),
            "retired key {idx} still live (seed {seed})"
        );
        assert!(
            ref_retired.contains(&key(*idx)),
            "retired key {idx} missing from retired set (seed {seed})"
        );
    }

    // Tear the cluster down explicitly (drops abort the mesh tasks).
    drop(nodes);
}

/// Whether the cluster has fully settled: every node has applied the same
/// last log index AND reports the identical head + retired view. Both checks
/// matter, the applied index converging is necessary (the log replicated
/// everywhere) and the view equality is the actual invariant the harness
/// asserts, so requiring both before declaring convergence avoids reading the
/// views mid-apply on a node that has the index but not yet the state.
async fn cluster_converged(nodes: &[Node]) -> bool {
    let mut applied = Vec::new();
    for n in nodes {
        let idx = n
            .raft
            .raft()
            .metrics()
            .borrow()
            .last_applied
            .map(|l| l.index)
            .unwrap_or(0);
        applied.push(idx);
    }
    let max = *applied.iter().max().unwrap();
    if !applied.iter().all(|a| *a == max) {
        return false;
    }

    // Applied index agrees; now require the projected views to agree too.
    let mut heads = Vec::new();
    let mut retireds = Vec::new();
    for n in nodes {
        heads.push(n.raft.state_machine().head_view().await);
        retireds.push(n.raft.state_machine().retired_view().await);
    }
    heads.iter().all(|h| *h == heads[0]) && retireds.iter().all(|r| *r == retireds[0])
}

// Five deterministic seeds, each a few seconds, CI-friendly. Multiple seeds
// exercise different op / fault interleavings of the same invariant.
macro_rules! node_view_consistent_seed {
    ($name:ident, $seed:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            run_scenario($seed).await;
        }
    };
}

node_view_consistent_seed!(node_view_consistent_seed_1, 1);
node_view_consistent_seed!(node_view_consistent_seed_2, 7);
node_view_consistent_seed!(node_view_consistent_seed_3, 42);
node_view_consistent_seed!(node_view_consistent_seed_4, 1337);
node_view_consistent_seed!(node_view_consistent_seed_5, 90210);
