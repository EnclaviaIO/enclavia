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

use tracing::{error, info, warn};

use crate::mesh::Mesh;
use crate::raft::network::{JoinReply, JoinRequest, MeshMessage};
use crate::raft::{MemberRecord, RaftHandle, instance_node_id};

/// Backoff between Join retries while waiting to be admitted (or to observe the
/// cluster another way). Bounded per-attempt; the overall loop retries
/// indefinitely (joins may retry forever, per the brief).
pub const JOIN_RETRY_DELAY: Duration = Duration::from_millis(200);

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
async fn do_initialize(raft: &RaftHandle, self_name: &str, records: Vec<MemberRecord>) -> bool {
    let members = records
        .into_iter()
        .map(|r| (instance_node_id(&r.pubkey), r))
        .collect();
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
/// Returns `None` on any transport / decode failure (the peer is not reachable
/// yet; the caller retries).
async fn send_join(mesh: &Mesh, peer: &str, self_name: &str) -> Option<JoinReply> {
    let msg = MeshMessage::Join(JoinRequest {
        slot_name: self_name.to_string(),
    });
    let mut buf = Vec::new();
    if ciborium::into_writer(&msg, &mut buf).is_err() {
        return None;
    }
    let reply = mesh.call(peer, buf).await.ok()?;
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
