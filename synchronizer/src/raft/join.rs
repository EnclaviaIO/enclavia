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
//!   done. If NO peer reports an initialized cluster within a bounded discovery
//!   window AND this node holds the lexicographically-smallest configured name,
//!   initialize a FRESH cluster from the peers' channel-attested pubkeys.
//! * [`watch_for_eviction`]: a background watch that detects this node's id
//!   leaving the committed membership (it was replaced by a same-slot
//!   instance) and stops it serving.
//!
//! ## The two startup races, and why they are safe
//!
//! **First provision (all three boot fresh, empty).** Every node probes; no
//! peer reports a cluster (none is initialized yet), so the window elapses on
//! all three. Only the lexicographically-smallest-name node initializes, and
//! it does so with the records of itself plus every peer whose mesh channel is
//! up (it waits until both peers' channels are up so the initial membership is
//! complete). The other two are voters from that single `initialize` (their
//! ids were in it), so they discover the cluster via replication and never
//! Join. Exactly one `initialize` runs because "smallest name" is a pure
//! function of the static configured set, identical on every node; the larger
//! names NEVER initialize.
//!
//! **Restart with a fresh key while the cluster lives (the whole point).** A
//! node (even the smallest-name bootstrap node) restarts with empty state and a
//! NEW instance key. It probes FIRST: it sends Join to its peers. A surviving
//! leader admits it (replace-on-rejoin evicts the dead old instance for the
//! slot, atomically), it hydrates from the survivors, done. Crucially, the
//! restarted bootstrap-name node MUST NOT re-initialize: the probe-first window
//! plus the "only initialize when NO peer reports a cluster" rule guarantee it
//! observes the live cluster (its peers answer the Join, or it sees their
//! AppendEntries) and joins instead of initializing a SECOND cluster over the
//! live one. A fresh `initialize` on a live cluster would be a split brain;
//! this is the safety rule the discovery window enforces.
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

/// How long each boot probe waits to observe a live cluster before the
/// smallest-name node falls back to initializing a fresh one. Comfortably
/// longer than a healthy election (300-600ms) and the mesh dial backoff, so a
/// genuine live cluster is always observed first on a restart.
pub const DISCOVERY_WINDOW: Duration = Duration::from_secs(3);

/// Backoff between Join retries while waiting to be admitted (or to observe the
/// cluster another way). Bounded per-attempt; the overall loop retries
/// indefinitely (joins may retry forever, per the brief).
pub const JOIN_RETRY_DELAY: Duration = Duration::from_millis(200);

/// How long to wait for ALL peer channels to come up before the smallest-name
/// node initializes a fresh cluster, so the initial membership is complete
/// (every configured slot filled). If a peer never appears within this window
/// the node initializes with whatever peers ARE up plus itself; the missing
/// peer then Joins when it arrives (replace-on-rejoin / first-fill).
pub const INITIAL_MEMBERSHIP_WAIT: Duration = Duration::from_secs(5);

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

        // Probe: send a Join to each peer. A leader admits us (or reports we are
        // already a member); a follower hints the leader; an election-in-progress
        // peer is Unavailable. Any successful Admitted (or observing ourselves as
        // a voter) ends discovery.
        let mut observed_cluster = false;
        for peer in peer_names(raft, &self_name) {
            match send_join(mesh, &peer, &self_name).await {
                Some(JoinReply::Admitted) => {
                    observed_cluster = true;
                    // The membership change is linearized; wait briefly for it to
                    // replicate to us so the voter check above sees it next loop.
                }
                Some(JoinReply::NotLeader(_)) => {
                    // The peer is up and in a cluster (it knows there is/should be
                    // a leader): a live cluster exists, so we must NOT initialize.
                    observed_cluster = true;
                }
                Some(JoinReply::Unavailable(_)) => {
                    // Peer is up but mid-election / serve-not-ready: a cluster is
                    // forming. Treat as "cluster observed" to stay off the
                    // initialize path (the restart-race safety rule).
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
                None => { /* peer not reachable yet */ }
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

        // No peer reports a cluster. Only the lexicographically-smallest-name
        // node initializes a fresh one (exactly-once by construction). The
        // larger-name nodes keep probing until the smallest one initializes and
        // names them, or until they are admitted.
        if raft.is_smallest_name() && try_initialize_fresh(raft, mesh, &self_name).await {
            continue; // re-check voter status at the top
        }
        tokio::time::sleep(JOIN_RETRY_DELAY).await;
    }
}

/// The smallest-name node's fresh-cluster initialize: wait for the peer
/// channels to come up (so the initial membership is complete), build the
/// member records from the peers' CHANNEL-attested pubkeys plus our own, and
/// initialize. Returns `true` if it initialized (or the cluster became
/// initialized while waiting), `false` to retry.
async fn try_initialize_fresh(raft: &RaftHandle, mesh: &Mesh, self_name: &str) -> bool {
    let peers = peer_names(raft, self_name);

    // Wait until every peer channel is up so the initial membership is complete.
    // Re-check for a cluster on each tick: a peer may initialize / a Join may be
    // admitted while we wait, in which case we abandon the initialize.
    let deadline = tokio::time::Instant::now() + INITIAL_MEMBERSHIP_WAIT;
    loop {
        if raft.cluster_is_initialized().await {
            return true; // someone (or we) initialized; stop trying to init
        }
        let mut records = vec![own_record(raft)];
        let mut missing = Vec::new();
        for peer in &peers {
            match mesh.observed_peer_pubkey(peer).await {
                Some(pk) => records.push(MemberRecord {
                    name: peer.clone(),
                    pubkey: pk,
                }),
                None => missing.push(peer.clone()),
            }
        }
        if missing.is_empty() {
            return do_initialize(raft, self_name, records).await;
        }
        if tokio::time::Instant::now() >= deadline {
            // A peer never appeared. Initialize with whoever IS up plus self;
            // the missing peer Joins when it arrives (first-fill admits it).
            warn!(
                node = %self_name, ?missing,
                "initializing the fresh cluster without all peers' channels up; \
                 missing peers will join when they appear"
            );
            return do_initialize(raft, self_name, records).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
