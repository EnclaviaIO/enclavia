//! Startup discovery + join, and the eviction watch (#209).
//!
//! Clone-resistant membership (see [`crate::raft::membership`]) makes a node's
//! Raft identity its per-boot instance key, so a (re)started node is a NEW
//! member that must be ADMITTED into the cluster for its configured slot rather
//! than re-using a name-derived id. This module is the node-lifecycle glue that
//! drives that on boot, on top of the leader-side primitives on
//! [`RaftHandle`](crate::raft::RaftHandle):
//!
//! * [`discover_and_join`]: the boot state machine. Probe peers for a live
//!   cluster (a Join attempt doubles as the probe); if a leader admits us (or
//!   we are already a voter via an `initialize` that included our id), we are
//!   done. Initialize a FRESH cluster (from the peers' channel-attested
//!   pubkeys) ONLY when this node holds the lexicographically-smallest
//!   configured name AND every configured peer POSITIVELY reports it has no
//!   cluster (a [`JoinReply::NoCluster`] reply).
//! * [`watch_for_eviction`]: a background watch that detects this node's id
//!   leaving the committed membership (it was replaced by a same-slot
//!   instance) and stops it serving.
//!
//! ## The discriminator that makes the two startup races safe
//!
//! The whole bootstrap rests on telling "no cluster exists anywhere" apart from
//! "a cluster exists but this peer is not its leader / is mid-election". Both
//! used to look identical (a non-leader reply), so the initialize-vs-join
//! decision came down to channel timing, and first-provision liveness and
//! restart safety needed that timing to break in OPPOSITE directions. A peer
//! now answers [`JoinReply::NoCluster`] only when its OWN committed membership
//! is empty; a peer in a live cluster answers `Admitted` / `NotLeader` /
//! `Unavailable`. The smallest-name node initializes only on POSITIVE
//! confirmation: every peer answered `NoCluster` this pass. The mere ABSENCE of
//! a reply (an unreachable peer) is never read as "no cluster".
//!
//! **First provision (all three boot fresh, empty).** Every node probes. The
//! two larger-name nodes answer `NoCluster` once their channels are up; the
//! smallest-name node, seeing `NoCluster` from BOTH (so it also has both
//! attested pubkeys), initializes the complete three-node membership. The other
//! two are voters from that single `initialize` (their ids were in it), so they
//! discover the cluster via replication and never Join. Exactly one
//! `initialize` runs because "smallest name" is a pure function of the static
//! configured set, identical on every node; the larger names NEVER initialize.
//!
//! **Restart with a fresh key while the cluster lives (the whole point).** A
//! node (even the smallest-name bootstrap node) restarts with empty state and a
//! NEW instance key. It is not in the live membership (new id), so it gets no
//! passive signal; it probes by sending Join. The surviving peers are in a live
//! cluster, so they answer `Admitted` / `NotLeader`, never `NoCluster`. The
//! restarted node therefore observes a cluster and joins (replace-on-rejoin
//! atomically evicts the dead old instance for the slot), and CANNOT take the
//! initialize path even if it is the bootstrap name: that path requires every
//! peer to answer `NoCluster`, which a live cluster never does. This closes the
//! split-brain a timing-based window would have left open (a competing
//! `initialize` reusing the same member ids could, via a higher-term election,
//! roll the real log back, which `loosen-follower-log-revert` would not catch).
//!
//! ## Eviction
//!
//! A replaced instance that is still alive (e.g. a clone that lost the slot to
//! the genuine node coming back, or an old instance whose slot a fresh-key
//! restart took) detects that its id is no longer a committed voter and stops
//! serving. We choose the SIMPLEST safe behavior: shut the local Raft down
//! (`raft.shutdown()`), which makes every subsequent client write / linearizable
//! read fail (the dispatcher surfaces `Unavailable`) and stops the node
//! answering peers. We log loudly. This is safe because the eviction was
//! linearized through the committed membership change, so by the time we see
//! ourselves gone, a DIFFERENT instance already holds the slot's vote; the
//! evicted process holds no vote and must not act as if it does.

use std::time::Duration;

use std::collections::BTreeMap;
use tracing::{error, info, warn};

use crate::mesh::Mesh;
use crate::raft::network::{JoinReply, JoinRequest, MeshMessage};
use crate::raft::{MemberRecord, RaftHandle, RaftNodeId, instance_node_id};

/// Backoff between Join retries while waiting to be admitted (or to observe the
/// cluster another way). Bounded per-attempt; the overall loop retries
/// indefinitely (joins may retry forever, per the brief).
pub const JOIN_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Upper bound on ONE `Join` round-trip to a peer.
///
/// [`Mesh::call`] itself has no deadline: it hands the request to the peer's
/// client channel and awaits the correlated response, so a leader that accepts
/// the Join and then stalls (on 2026-09-03 the leader parked ~10 minutes inside
/// its own unbounded `add_learner` wait, with a snapshot install stuck at
/// ~4.5 MB) blocks this probe for as long as it stalls. The whole discovery
/// loop is sequential over the peer set, so one stalled peer also starves the
/// probes to the others.
///
/// Deliberately set ABOVE the leader's own bounded admission
/// ([`ADD_LEARNER_TIMEOUT`](crate::raft::ADD_LEARNER_TIMEOUT)), so in the
/// stalled-admission case the joiner still receives the leader's
/// [`JoinReply::Unavailable`] instead of walking away. That ordering matters
/// because the leader's serve loop is SEQUENTIAL per connection: abandoning
/// early would queue the retry behind the request we gave up on, and every
/// subsequent Join would inherit the same head-of-line block. This deadline is
/// therefore the backstop for a peer that answers nothing at all (a dead
/// channel whose liveness ping has not yet recycled it), not the normal path.
pub const JOIN_CALL_TIMEOUT: Duration = Duration::from_secs(150);

/// The minimum membership a FRESH `initialize` may carry: the designed
/// 3-node shape (this node plus the two peers `MIN_MESH_PEERS` in the
/// binary requires). Defence in depth against an undersized configured
/// set slipping past the env reader: a 1- or 2-voter `initialize` would
/// silently collapse the freshness oracle (a 1-voter cluster commits on
/// itself alone, and its restart wipes every pinned state, the exact
/// rollback the cluster exists to prevent). See [`do_initialize`].
const MIN_INITIAL_CLUSTER_MEMBERS: usize = crate::MIN_CLUSTER_NODES;

/// Drive the boot discovery + join state machine to completion: return once
/// this node is a committed voter (admitted via Join, or included in the fresh
/// `initialize`). Retries indefinitely with backoff; the only terminal states
/// are "I am a voter" and a kernel `Refused` (an unconfigured slot name, which
/// is a misconfiguration this node can never recover from, so it logs and
/// keeps probing in case the operator fixes the config, but never becomes a
/// voter).
///
/// `mesh` is the running peer mesh; `raft` is this node's handle. Call once on
/// boot, after the mesh + Raft are wired and `enable_serving` has run (so an
/// inbound Join we receive while probing can be admitted).
pub async fn discover_and_join(raft: &RaftHandle, mesh: &Mesh) {
    let self_name = raft.self_record().name.clone();

    loop {
        // Already a voter? (We initialized, were admitted, or an initialize that
        // included our id replicated to us, or we hydrated a membership naming
        // us.) Done.
        if raft.self_is_committed_voter().await {
            info!(node = %self_name, "this node is a committed voter; discovery complete");
            return;
        }

        // Probe: send a Join to each peer. The reply is the discriminator the
        // whole bootstrap hinges on:
        //
        // * Admitted / NotLeader / Unavailable: a live cluster exists (or is
        //   electing). We must NOT initialize; keep probing until admitted or
        //   until the membership replicates to us.
        // * Refused: a deterministic kernel rejection (unconfigured slot name).
        //   This node can never be a voter; log and keep probing in case the
        //   operator fixes the config, but never initialize.
        // * NoCluster: this peer has itself never seen a cluster. The DEFINITIVE
        //   "no cluster exists" signal: only this lets us initialize.
        // * None (unreachable): NOT a signal. Absence of a reply must never be
        //   read as "no cluster", or a node restarted with a fresh identity
        //   whose Join channel is briefly down would initialize a competitor
        //   against the live cluster it simply has not reached yet.
        //
        // So the smallest-name node initializes only on POSITIVE confirmation:
        // every configured peer answered NoCluster this pass (so we have all
        // their attested pubkeys AND know none holds a cluster). Any other
        // outcome (a live-cluster reply, OR a single unreachable peer) keeps us
        // off the initialize path.
        let mut observed_cluster = false;
        let peers = peer_names(raft, &self_name);
        let mut peers_reporting_no_cluster = 0usize;
        for peer in &peers {
            match send_join(mesh, peer, &self_name).await {
                Some(JoinReply::Admitted)
                | Some(JoinReply::NotLeader(_))
                | Some(JoinReply::Unavailable(_)) => {
                    observed_cluster = true;
                }
                Some(JoinReply::Refused(why)) => {
                    error!(
                        node = %self_name, peer = %peer, reason = %why,
                        "join refused by the admission kernel (likely an unconfigured slot \
                         name): this node can never become a voter until the config is fixed"
                    );
                    observed_cluster = true;
                }
                Some(JoinReply::NoCluster) => {
                    peers_reporting_no_cluster += 1;
                }
                None => { /* peer not reachable yet: NOT a no-cluster signal */ }
            }
        }

        // We may also have learned the cluster passively (a peer's AppendEntries
        // reached us and installed a membership naming us, or we hydrated).
        if raft.cluster_is_initialized().await {
            observed_cluster = true;
        }

        if observed_cluster {
            // A cluster exists (or is forming). Keep probing / waiting to be
            // admitted; do NOT initialize.
            tokio::time::sleep(JOIN_RETRY_DELAY).await;
            continue;
        }

        // Initialize a fresh cluster only on positive confirmation: this is the
        // smallest-name node (exactly-once by construction) AND every configured
        // peer answered NoCluster this pass.
        let all_peers_report_no_cluster = peers_reporting_no_cluster == peers.len();
        if raft.is_smallest_name()
            && all_peers_report_no_cluster
            && try_initialize_fresh(raft, mesh, &self_name).await
        {
            continue; // re-check voter status at the top
        }
        tokio::time::sleep(JOIN_RETRY_DELAY).await;
    }
}

/// The smallest-name node's fresh-cluster initialize, called ONLY after every
/// configured peer answered `NoCluster` this pass (see the caller). That gate
/// guarantees two things: no live cluster exists, and every peer's channel is
/// up, so its attested instance pubkey is recorded. Build the COMPLETE initial
/// membership (self plus all peers) from those pubkeys and initialize.
///
/// Deliberately all-or-nothing: it never initializes a SUBSET of the configured
/// nodes. A partial-membership initialize (e.g. a 2-node cluster while the
/// third is briefly unreachable) is itself a split-brain risk on a restart, so
/// if any peer pubkey is somehow not yet recorded we simply retry rather than
/// shrink the cluster. Returns `true` if it initialized (or the cluster became
/// initialized concurrently), `false` to retry.
async fn try_initialize_fresh(raft: &RaftHandle, mesh: &Mesh, self_name: &str) -> bool {
    if raft.cluster_is_initialized().await {
        return true; // someone (or we) initialized; stop trying to init
    }
    let peers = peer_names(raft, self_name);
    let mut records = vec![own_record(raft)];
    for peer in &peers {
        match mesh.observed_peer_pubkey(peer).await {
            Some(pk) => records.push(MemberRecord {
                name: peer.clone(),
                pubkey: pk,
            }),
            // A peer answered NoCluster this pass but its pubkey is not recorded
            // yet (should not happen: the dial that carried the reply records it
            // during attestation). Do NOT initialize a subset; retry.
            None => {
                warn!(
                    node = %self_name, peer = %peer,
                    "peer reported NoCluster but its attested pubkey is not yet recorded; \
                     retrying rather than initializing an incomplete membership"
                );
                return false;
            }
        }
    }
    do_initialize(raft, self_name, records).await
}

/// Initialize the cluster from `records` (keyed by their derived ids) and log
/// the outcome. Returns `true` on success or benign already-initialized.
///
/// REFUSES to initialize when the records dedup to fewer than
/// [`MIN_INITIAL_CLUSTER_MEMBERS`] distinct instance ids (loud error, `false`
/// so the caller retries). The count is taken AFTER keying by
/// [`instance_node_id`]: the host routes peer names, so several configured
/// names can resolve to one node (attestation cannot distinguish same-image
/// instances), and a pre-dedup count would pass 3 records that are really 2
/// voters. Defence in depth: the production env reader already refuses a
/// peer set below the 3-node minimum, but that check lives in the binary and
/// ran against host-supplied env vars; this is the last stop before an
/// irreversible `initialize`. A smaller fresh cluster is never legitimate:
/// a 1-voter cluster commits on itself alone and its restart wipes all
/// pinned state (no persistence, #122), which is the rollback hazard the
/// 3-node oracle exists to prevent. Retrying (rather than initializing
/// anyway) is the fail-closed behaviour: the node simply never forms a
/// cluster until the configuration is fixed.
async fn do_initialize(raft: &RaftHandle, self_name: &str, records: Vec<MemberRecord>) -> bool {
    let members: BTreeMap<RaftNodeId, MemberRecord> = records
        .into_iter()
        .map(|r| (instance_node_id(&r.pubkey), r))
        .collect();
    // The size gate runs on the DEDUPED, id-keyed map, not the record list:
    // two records carrying the SAME instance pubkey collapse to one voter
    // (the host routes peer names, so az-b and az-c can both resolve to one
    // node — attestation cannot distinguish same-image instances). A pre-
    // dedup count would pass 3 records that are really 2 voters, silently
    // collapsing the freshness oracle below its designed shape — the same
    // pre-dedup mistake the env reader's post-dedup `MIN_MESH_PEERS` check
    // was hardened against.
    if members.len() < MIN_INITIAL_CLUSTER_MEMBERS {
        error!(
            node = %self_name,
            distinct = members.len(),
            required = MIN_INITIAL_CLUSTER_MEMBERS,
            "refusing to initialize a fresh cluster below the designed 3-node shape \
             (after de-duplicating instance ids — duplicate peer pubkeys mean the host \
             routed several names to one node); will retry (never collapse the \
             freshness oracle to fewer voters)"
        );
        return false;
    }
    match raft.initialize_cluster(members).await {
        Ok(()) => {
            info!(node = %self_name, "initialized a fresh cluster (discovery window elapsed with no live peer cluster)");
            true
        }
        Err(e) => {
            warn!(node = %self_name, error = %e, "initialize_cluster failed; will retry");
            false
        }
    }
}

/// Encode + send a [`MeshMessage::Join`] to `peer`, decode the [`JoinReply`].
/// Returns `None` on any transport / decode failure OR on exceeding
/// [`JOIN_CALL_TIMEOUT`] (the peer is not reachable or is wedged; the caller
/// treats `None` as "no signal from this peer" and retries after
/// [`JOIN_RETRY_DELAY`]).
///
/// `None` is the correct outcome for a timeout, not an error: the discovery
/// loop already documents that the ABSENCE of a reply is never read as "no
/// cluster", so an abandoned probe can only cause a retry, never a spurious
/// `initialize` against a live cluster.
async fn send_join(mesh: &Mesh, peer: &str, self_name: &str) -> Option<JoinReply> {
    let msg = MeshMessage::Join(JoinRequest {
        slot_name: self_name.to_string(),
    });
    let mut buf = Vec::new();
    if ciborium::into_writer(&msg, &mut buf).is_err() {
        return None;
    }
    let reply = match tokio::time::timeout(JOIN_CALL_TIMEOUT, mesh.call(peer, buf)).await {
        Ok(result) => result.ok()?,
        Err(_) => {
            warn!(
                peer = %peer, timeout = ?JOIN_CALL_TIMEOUT,
                "join round-trip timed out; treating the peer as unreachable this pass"
            );
            return None;
        }
    };
    ciborium::from_reader(reply.as_slice()).ok()
}

/// This node's own [`MemberRecord`].
fn own_record(raft: &RaftHandle) -> MemberRecord {
    raft.self_record().clone()
}

/// The configured peer names (everything in the configured set except this
/// node).
fn peer_names(raft: &RaftHandle, self_name: &str) -> Vec<String> {
    raft.configured_names()
        .iter()
        .filter(|n| n.as_str() != self_name)
        .cloned()
        .collect()
}

/// Background eviction watch: shut this node's Raft down the moment its id
/// leaves the committed membership (it was replaced by a same-slot instance).
///
/// Spawn this once, AFTER discovery has made the node a voter. It watches the
/// Raft metrics and, on observing that this node's id is no longer a committed
/// voter (while the cluster IS still initialized, so this is a genuine
/// eviction, not a pre-membership boot), logs loudly and shuts the local Raft
/// down. After shutdown the node answers no writes / reads (the dispatcher
/// returns `Unavailable`) and stops participating in consensus, which is the
/// simplest safe behavior for a replaced instance (see the module docs).
pub async fn watch_for_eviction(raft: RaftHandle) {
    let self_id = raft.self_id();
    let self_name = raft.self_record().name.clone();
    let mut rx = raft.raft().metrics();
    loop {
        {
            let metrics = rx.borrow_and_update().clone();
            let initialized = metrics.membership_config.voter_ids().next().is_some();
            let still_voter = metrics.membership_config.voter_ids().any(|v| v == self_id)
                || metrics
                    .membership_config
                    .membership()
                    .get_node(&self_id)
                    .is_some();
            if initialized && !still_voter {
                error!(
                    node = %self_name, id = self_id,
                    "EVICTED: this instance's id is no longer in the committed membership \
                     (a same-slot instance replaced it). Shutting down the local Raft; this \
                     node will serve no further writes or reads."
                );
                raft.shutdown().await;
                return;
            }
        }
        if rx.changed().await.is_err() {
            // Metrics sender dropped (Raft already shutting down): nothing to do.
            return;
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::CONTROL_PUBKEY_LEN;
    use crate::mesh::attestation::FakeAttestor;
    use crate::mesh::config::MeshConfig;
    use crate::mesh::identity::MeshIdentity;
    use crate::mesh::transport::{MeshHostStub, UdsMeshAcceptor};
    use crate::raft::RaftRequestHandler;
    use std::sync::Arc;

    /// A cheap, distinct 65-byte SEC1-shaped pubkey for records OTHER than
    /// this node's own (whose real per-boot key comes from its `MeshIdentity`).
    /// `do_initialize` only hashes the bytes via [`instance_node_id`], so
    /// distinctness is all the gate needs.
    fn pk(b: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        let mut out = [b.wrapping_add(0x80); CONTROL_PUBKEY_LEN];
        out[0] = 0x04;
        out
    }

    /// Stand up a lone node's mesh + Raft handle over the in-process test
    /// transport (same scaffold as the multi-node integration harnesses in
    /// tests/), with its peers configured but NEVER reachable (nothing
    /// registers their routes). The initialize-size gate must hold before any
    /// peer is contacted, which is exactly what these tests drive.
    async fn lone_handle(
        name: &str,
        peers: &[&str],
        dir: &std::path::Path,
    ) -> (RaftHandle, Arc<Mesh>) {
        lone_handle_with_config(name, peers, dir, RaftHandle::default_config()).await
    }

    /// [`lone_handle`] with a caller-supplied openraft config, for the tests
    /// that need to tune replication behaviour (see the bounded-admission
    /// test's `replication_lag_threshold`).
    async fn lone_handle_with_config(
        name: &str,
        peers: &[&str],
        dir: &std::path::Path,
        raft_config: openraft::Config,
    ) -> (RaftHandle, Arc<Mesh>) {
        const IMAGE_SEED: u8 = 0x42;
        let host = MeshHostStub::new();
        let sock = dir.join(format!("{name}.sock"));
        let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
        host.register(name, &sock);
        let identity = MeshIdentity::generate();
        let self_pubkey = identity.pubkey();
        let attestor = FakeAttestor::new(IMAGE_SEED, &identity);
        let peer_names: Vec<String> = peers.iter().map(|s| s.to_string()).collect();
        let config = MeshConfig::new(
            name.to_string(),
            peer_names.clone(),
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
            &peer_names,
            handler,
            raft_config,
        )
        .await
        .unwrap();
        (raft, mesh)
    }

    /// Regression test for the undersized-cluster hole: a fresh `initialize`
    /// carrying fewer than the designed 3 members (here: just this node, the
    /// MESH_PEERS="az-a,az-a" self-padding scenario the env reader now also
    /// rejects) must be REFUSED, and no cluster may form. A 1-voter cluster
    /// would commit on itself alone and lose every pinned state on restart.
    #[tokio::test]
    async fn initialize_refuses_an_undersized_membership() {
        let dir = tempfile::tempdir().unwrap();
        let (raft, _mesh) = lone_handle("node-a", &["node-b", "node-c"], dir.path()).await;
        let records = vec![raft.self_record().clone()];
        assert!(
            !do_initialize(&raft, "node-a", records).await,
            "a 1-record initialize must be refused"
        );
        assert!(
            !raft.cluster_is_initialized().await,
            "no cluster may form from the refused initialize"
        );
        raft.shutdown().await;
    }

    /// The designed shape still initializes: self plus both peers, exactly
    /// what [`try_initialize_fresh`] builds from the channel-attested pubkeys
    /// on a genuine first provision.
    #[tokio::test]
    async fn initialize_accepts_the_three_node_membership() {
        let dir = tempfile::tempdir().unwrap();
        let (raft, _mesh) = lone_handle("node-a", &["node-b", "node-c"], dir.path()).await;
        let records = vec![
            raft.self_record().clone(),
            MemberRecord {
                name: "node-b".to_string(),
                pubkey: pk(2),
            },
            MemberRecord {
                name: "node-c".to_string(),
                pubkey: pk(3),
            },
        ];
        assert!(
            do_initialize(&raft, "node-a", records).await,
            "the designed 3-node initialize must be accepted"
        );
        assert!(
            raft.cluster_is_initialized().await,
            "the fresh cluster is initialized after the accepted initialize"
        );
        assert!(
            raft.self_is_committed_voter().await,
            "the initializing node is a committed voter of the fresh cluster"
        );
        raft.shutdown().await;
    }

    /// A leader-side admission whose learner can NEVER catch up (the candidate
    /// name resolves to no reachable node, so replication to it never
    /// progresses) must return within the bounded `add_learner` wait instead of
    /// parking the leader.
    ///
    /// This is the 2026-09-03 stall: openraft's blocking `add_learner` ends in
    /// `self.wait(None)`, a wait with NO deadline of its own, and because the
    /// mesh serve loop is sequential per connection the parked leader stopped
    /// answering the joiner entirely for ~10 minutes. The bound is shortened
    /// here (production is two minutes) purely to keep the test fast; what is
    /// asserted is that `admit` HONOURS it.
    ///
    /// Two setup details make the blocking path real rather than incidental:
    ///
    /// * `replication_lag_threshold = 0`. openraft's wait is satisfied once the
    ///   learner is within `replication_lag_threshold` entries of the leader,
    ///   and the default is 1000 — so on a short log an UNREACHABLE learner is
    ///   still deemed "up to date" and the wait returns at once. Zero makes any
    ///   un-replicated learner genuinely not caught up, which is the state a
    ///   real node stuck mid-`InstallSnapshot` is in.
    /// * The single-voter `initialize_cluster` makes this node leader on its
    ///   own, so the admission actually reaches `add_learner`. It goes through
    ///   the handle directly, bypassing `do_initialize`'s 3-node gate — which
    ///   is exactly what that gate exists to stop in production.
    ///
    /// node-b is configured but has no route in the mesh stub, so replication
    /// to it can never progress.
    #[tokio::test]
    async fn admit_returns_when_the_learner_never_catches_up() {
        const BOUND: Duration = Duration::from_millis(500);
        let dir = tempfile::tempdir().unwrap();
        let mut raft_config = RaftHandle::default_config();
        raft_config.replication_lag_threshold = 0;
        let (raft, _mesh) =
            lone_handle_with_config("node-a", &["node-b", "node-c"], dir.path(), raft_config).await;

        let mut solo = BTreeMap::new();
        solo.insert(raft.self_id(), raft.self_record().clone());
        raft.initialize_cluster(solo).await.unwrap();
        raft.wait_for_leader(Duration::from_secs(10))
            .await
            .expect("the solo node must elect itself leader");

        let bounded = raft.clone().with_add_learner_timeout(BOUND);
        let started = std::time::Instant::now();
        let result = bounded.admit("node-b", &pk(2)).await;
        let elapsed = started.elapsed();

        let err = result.expect_err("an admission whose learner never catches up must fail");
        assert!(
            matches!(err, crate::raft::RaftHandleError::Raft(ref m) if m.contains("did not catch up")),
            "expected a bounded-wait failure, got: {err}"
        );
        // Returning at ~the bound is the whole point: the leader's serve loop
        // for this connection is freed instead of parking on the wait.
        assert!(
            elapsed < BOUND * 20,
            "admit must return at ~the bound, took {elapsed:?}"
        );
        // The join handler maps a bare `Raft` error to wire `Unavailable`, so
        // the joiner retries; `plan_admission` is pure, so the retry recomputes
        // the same plan (or reports `already_member`). The abandoned candidate
        // must NOT have been made a voter along the way.
        assert!(
            !raft
                .committed_voters()
                .await
                .contains_key(&super::instance_node_id(&pk(2))),
            "the abandoned candidate must not have become a voter"
        );
        raft.shutdown().await;
    }

    /// Regression for the pre-dedup count: three records that are really TWO
    /// instances (the host routed two peer names to one node, so both carry
    /// the same attested pubkey) must be REFUSED — the id-keyed map
    /// collapses them to 2 voters, below the designed 3-node shape.
    #[tokio::test]
    async fn initialize_refuses_duplicate_instance_pubkeys() {
        let dir = tempfile::tempdir().unwrap();
        let (raft, _mesh) = lone_handle("node-a", &["node-b", "node-c"], dir.path()).await;
        let records = vec![
            raft.self_record().clone(),
            MemberRecord {
                name: "node-b".to_string(),
                pubkey: pk(2),
            },
            MemberRecord {
                name: "node-c".to_string(),
                pubkey: pk(2), // same instance as "node-b": host-routed names
            },
        ];
        assert!(
            !do_initialize(&raft, "node-a", records).await,
            "records that dedup below the 3-node minimum must be refused"
        );
        assert!(
            !raft.cluster_is_initialized().await,
            "no cluster may form from the refused initialize"
        );
        raft.shutdown().await;
    }
}
