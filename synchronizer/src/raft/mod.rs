//! Raft replication of the freshness state machine (#119, slice 3).
//!
//! Replicates the pure [`StateMachine`](crate::StateMachine) across the 3-node
//! mesh from slice 2 using [`openraft`]. In-memory log + state, NO persistence
//! (the #16 design pass froze cold-start out of scope; see the precondition
//! below). This is the LIBRARY layer only: it stands up the [`RaftHandle`] and
//! its storage / network plumbing and exposes them for slice 4 to drive. It
//! deliberately does NOT rewire `main.rs` / the customer-facing listener onto
//! Raft.
//!
//! ## Leader-verified conclusions, follower-trusted replication
//!
//! The pure core's [`apply`](crate::StateMachine::apply) checks per-session
//! observations (`NotAttested`, `NoTransitionAuthorization`, ...), but those
//! observations are LEADER-LOCAL knowledge: only the node holding the client's
//! attested Noise session can verify a Nitro attestation document or a #47
//! upgrade chain link. So the leader does ALL cryptographic verification
//! (session attestation at Register, [`verify_transition_link`] at Transition),
//! exactly as the single-node [`Node`](crate::Node) does today, and the
//! replicated log entry carries only the verified CONCLUSIONS as a
//! self-contained [`ReplicatedOp`]: the facts a follower needs to reproduce the
//! leader's `apply` deterministically, with no crypto.
//!
//! Every replica (the leader included, when it applies its own committed entry)
//! feeds those facts into the pure core in a fixed order:
//!
//! * [`ReplicatedOp::Register`]: `observe_attestation(key, control_pubkey)`
//!   then `apply(Op::Register { key, commitment })`.
//! * [`ReplicatedOp::Pin`]: `apply(Op::Pin { key, commitment })`.
//! * [`ReplicatedOp::Transition`]: the new key must be attested for the pure
//!   core's `Transition` to pass (`NewKeyNotAttested`), and the leader observed
//!   the new key's attestation from the submitting session, so the entry
//!   carries `new_control_pubkey`. A follower replays
//!   `observe_attestation(new_key, new_control_pubkey)` then
//!   `observe_transition(old_key, new_key)` then
//!   `apply(Op::Transition { old_key, new_key })`. (The old key was attested by
//!   an earlier `Register`/`Pin` entry, already replicated, so its observation
//!   is already present on every replica.)
//!
//! Followers never re-verify crypto. The trust argument is the same one Raft
//! itself rests on: openraft assumes non-Byzantine members, and mesh membership
//! is gated by mutual attestation against the self-PCR allowlist (slice 2), so
//! a peer that reached the replication channel is provably running our exact
//! image. Leader-verified conclusions are therefore trusted by followers
//! exactly as far as the cluster trusts its own members, which the PCR
//! allowlist already pins to "bit-for-bit us".
//!
//! ## Snapshot / hydration semantics
//!
//! The state-machine snapshot serializes the ENTIRE pure-core state, the
//! committed `(PcrKey -> KeyState)` projection AND the observation sets
//! (`attested`, `transition_authorizations`), via
//! [`StateMachine::snapshot`](crate::StateMachine::snapshot). A node hydrated
//! from a snapshot then applies subsequent `Transition` entries identically to
//! one that replayed the whole log, because the observation a post-snapshot
//! `Transition` checks is already in the restored state. openraft's library
//! snapshot mechanism transfers the blob over the same mesh channel
//! (`InstallSnapshot` RPC), which is what slice 4 leans on for #121 hydration
//! of a restarted node.
//!
//! ## Cold-start precondition (#122, out of scope)
//!
//! There is no on-disk persistence: durability is purely N-replica in-memory.
//! **Do not lose all three nodes simultaneously.** Simultaneous loss of every
//! node wipes the freshness map; recovering from that is a custody-mode-
//! dependent design tracked separately (#122) and explicitly out of this
//! slice. A single node restarting with empty state is fine: it rejoins as a
//! follower and hydrates from the survivors' snapshot before serving.
//!
//! ## Full-replication ACK (client writes wait for ALL nodes)
//!
//! Raft commit is a MAJORITY (2 of 3): openraft applies and would return an
//! entry as soon as a quorum has it, while the third node may never have seen
//! it. With no persistence, recovery from a catastrophic loss is "re-seed from
//! a surviving node" (#122). If the two nodes holding a
//! majority-committed-but-not-fully-replicated entry die, re-seeding from the
//! single survivor silently loses the most recent pins: a bounded rollback
//! window, the one thing a freshness oracle must not have.
//!
//! So the CLIENT-facing write path
//! ([`client_write_durable`](RaftHandle::client_write_durable)) does NOT ACK on
//! the majority commit; it waits until EVERY current voter has replicated the
//! written entry's log index before returning success. Every ACKed write is
//! then present on every node, so re-seeding from ANY single survivor is
//! lossless. The cost: while a node is down, writes (Pin / Transition) stall
//! and fail with `Unavailable` until the cluster is whole again. Linearizable
//! reads are unaffected (they still only need a fresh quorum). This is
//! acceptable for a freshness oracle whose writes are boot-time events.
//!
//! [`client_write`](RaftHandle::client_write) keeps the plain majority-ACK
//! semantics and is retained for internal use and the multi-node test harnesses
//! (which submit ops directly, not through the serve path).

pub mod forward;
pub(crate) mod network;
pub mod serve;
mod store;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use openraft::error::{ClientWriteError, RaftError};
use serde::{Deserialize, Serialize};

use crate::mesh::Mesh;
use crate::mesh::config::PeerName;
use crate::{CONTROL_PUBKEY_LEN, Commitment, KeyState, PcrKey, ValidationError};

#[cfg(feature = "node")]
pub use forward::ReplicatedDispatch;
pub use forward::{ForwardedClientRequest, ForwardedClientResponse, route_client_request};
pub use network::{MeshRaftNetworkFactory, RaftRequestHandler};
pub use store::{LogStore, StateMachineStore, control_pubkey_bytes};

/// Re-export of openraft's tuning [`Config`](openraft::Config) +
/// [`SnapshotPolicy`](openraft::SnapshotPolicy), so callers (slice 4, tests)
/// can build a custom config to pass to [`RaftHandle::with_config`] without
/// depending on `openraft` directly.
pub use openraft::{Config, SnapshotPolicy};

/// openraft node id: a small integer derived from the logical peer's position
/// in the cluster's sorted name list. The mesh keys connections by name; this
/// id is purely openraft's internal handle. See [`NodeIdMap`].
pub type RaftNodeId = u64;

/// The replicated log entry: the verified CONCLUSIONS the leader reached after
/// doing all cryptographic verification, self-contained so every follower can
/// re-derive the same `apply` deterministically without any crypto.
///
/// See the module docs for the trust argument and the per-variant replay order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicatedOp {
    /// First-time registration of an attested key. The leader verified the
    /// submitting session's attestation; the entry carries the key, its
    /// initial commitment, and the 65-byte SEC1 P-256 control pubkey the
    /// attestation announced (frozen into `KeyState` on apply).
    Register {
        /// The attested PCR key being registered.
        key: PcrKey,
        /// Initial storage commitment (version 0).
        commitment: Commitment,
        /// 65-byte SEC1 P-256 control pubkey from the session's attestation.
        #[serde(with = "control_pubkey_bytes")]
        control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    },
    /// Pin a fresh commitment under an already-registered key. No crypto facts
    /// to carry: the key is already attested + registered on every replica.
    Pin {
        /// The registered key whose commitment is updated.
        key: PcrKey,
        /// New commitment; bumps the per-key version.
        commitment: Commitment,
    },
    /// Authorized upgrade transition. The leader verified the #47 upgrade chain
    /// link (signature against `old_key`'s frozen pubkey, chain attestation,
    /// `new_key == submitting session`). The entry carries the derived key pair
    /// plus the new key's control pubkey (the leader observed it from the
    /// submitting session), so a follower can record the new key's attestation
    /// before applying. The old key's attestation is already present on every
    /// replica from its earlier Register entry.
    Transition {
        /// Key being retired. `sha256(payload.from_pcrs)`.
        old_key: PcrKey,
        /// Successor key adopting the retired key's state.
        /// `sha256(payload.to_pcrs)`.
        new_key: PcrKey,
        /// 65-byte SEC1 P-256 control pubkey of the new key, as the leader
        /// observed it from the submitting (new-enclave) session.
        #[serde(with = "control_pubkey_bytes")]
        new_control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    },
}

/// The response a replicated [`ReplicatedOp`] produces once applied, mirroring
/// the pure core's `apply` result. Carried back to the [`RaftHandle::client_write`]
/// caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicatedOpResult {
    /// The op applied; carries the resulting [`KeyState`] for the touched key
    /// (the `new_key` for a `Transition`).
    Applied(KeyState),
    /// The pure core rejected the op. Deterministic across replicas (the same
    /// committed entry rejects identically everywhere), so it is safe to
    /// replicate the rejection rather than reject at submit time.
    Rejected(ValidationError),
}

openraft::declare_raft_types!(
    /// Type configuration for the synchronizer Raft cluster: a [`ReplicatedOp`]
    /// log entry, a [`ReplicatedOpResult`] response, [`RaftNodeId`] node ids,
    /// [`openraft::BasicNode`] node metadata (the logical peer name lives in
    /// its `addr`), and a `Cursor<Vec<u8>>` snapshot blob (the CBOR-then-JSON
    /// serialized pure-core snapshot).
    pub TypeConfig:
        D = ReplicatedOp,
        R = ReplicatedOpResult,
        NodeId = RaftNodeId,
        Node = openraft::BasicNode,
        SnapshotData = std::io::Cursor<Vec<u8>>,
);

/// openraft `Raft` specialized for this cluster's [`TypeConfig`].
pub type Raft = openraft::Raft<TypeConfig>;

/// Convenience alias for openraft errors surfaced by [`RaftHandle`] methods.
pub type RaftClientWriteError =
    RaftError<RaftNodeId, ClientWriteError<RaftNodeId, openraft::BasicNode>>;

/// Static map between logical peer names and openraft node ids.
///
/// Node ids are assigned by sorting `self_name` plus the peer set and taking
/// each name's index, so every node in a same-config cluster computes the
/// identical name <-> id mapping (the cluster membership is static 3-node from
/// [`MeshConfig`](crate::mesh::config::MeshConfig)).
#[derive(Clone, Debug)]
pub struct NodeIdMap {
    name_to_id: BTreeMap<PeerName, RaftNodeId>,
    id_to_name: BTreeMap<RaftNodeId, PeerName>,
}

impl NodeIdMap {
    /// Build the mapping from this node's own name and its peer set. The full
    /// membership is `self_name` + `peers`, sorted, indexed.
    pub fn new(self_name: &str, peers: &[PeerName]) -> Self {
        let mut all: Vec<PeerName> = peers.to_vec();
        all.push(self_name.to_string());
        all.sort();
        all.dedup();
        let mut name_to_id = BTreeMap::new();
        let mut id_to_name = BTreeMap::new();
        for (i, name) in all.into_iter().enumerate() {
            let id = i as RaftNodeId;
            name_to_id.insert(name.clone(), id);
            id_to_name.insert(id, name);
        }
        Self {
            name_to_id,
            id_to_name,
        }
    }

    /// openraft node id for a logical peer name.
    pub fn id_of(&self, name: &str) -> Option<RaftNodeId> {
        self.name_to_id.get(name).copied()
    }

    /// Logical peer name for an openraft node id.
    pub fn name_of(&self, id: RaftNodeId) -> Option<&str> {
        self.id_to_name.get(&id).map(|s| s.as_str())
    }

    /// All `(id, name)` pairs, sorted by id. Used to build the initial cluster
    /// membership for `Raft::initialize`.
    pub fn members(&self) -> impl Iterator<Item = (RaftNodeId, &PeerName)> {
        self.id_to_name.iter().map(|(id, name)| (*id, name))
    }
}

/// Errors surfaced by [`RaftHandle`] writes / reads.
#[derive(Debug, thiserror::Error)]
pub enum RaftHandleError {
    /// The pure core rejected the op (replicated deterministically). Carries
    /// the underlying [`ValidationError`].
    #[error("operation rejected by state machine: {0}")]
    Rejected(#[from] ValidationError),
    /// openraft refused the write: not the leader (carries a leader hint, if
    /// known), quorum lost, or an internal Raft error. The caller should
    /// redirect to the hinted leader or retry.
    #[error("raft write failed: {0}")]
    Raft(String),
    /// A linearizable read could not be guaranteed (not the leader / quorum
    /// lost). A freshness oracle must not serve stale data, so the caller
    /// surfaces this rather than returning a possibly-stale value.
    #[error("linearizable read unavailable: {0}")]
    NotLinearizable(String),
    /// The write committed and applied locally (a Raft majority has it) but at
    /// least one peer had not replicated it to its log within the bounded wait.
    /// Returned ONLY by [`client_write_durable`](RaftHandle::client_write_durable),
    /// which refuses to ACK a client write until EVERY node holds the entry (see
    /// the module docs' full-replication ACK section). The caller maps this to
    /// wire `Unavailable`: the at-least-once retry semantics apply (a duplicate
    /// Pin is benign; a duplicate Transition surfaces `TransitionRejected` and
    /// the client confirms via `Get`).
    #[error("write committed but not yet replicated to all nodes: {0}")]
    NotFullyReplicated(String),
}

/// Handle the listener / slice-4 drives to submit ops and read state.
///
/// Wraps the local [`Raft`] instance plus the shared [`StateMachineStore`] (for
/// leader-local linearizable reads). Construct with [`RaftHandle::new`], then
/// [`RaftHandle::initialize_cluster`] exactly once on bootstrap.
#[derive(Clone)]
pub struct RaftHandle {
    raft: Raft,
    sm: Arc<StateMachineStore>,
    ids: NodeIdMap,
    self_id: RaftNodeId,
    /// Bounded wait used by
    /// [`client_write_durable`](Self::client_write_durable) for EVERY voter to
    /// replicate a just-committed entry before the client write is ACKed.
    /// Defaults to [`DEFAULT_REPLICATION_WAIT`]; tests that intentionally write
    /// under a partition shorten it with [`with_replication_wait`](Self::with_replication_wait)
    /// to keep CI fast without changing the production behavior.
    replication_wait: Duration,
}

/// Bounded wait for full replication on the client write path
/// ([`RaftHandle::client_write_durable`]). The entry IS already committed and
/// applied on a Raft majority once `client_write` returns; this is only the
/// extra window we give the LAST node to catch up before we tell the client the
/// write is durable on every replica. Two seconds comfortably covers a healthy
/// follower's append latency on the low-latency mesh; exceeding it means a node
/// is genuinely down or partitioned, and the write fails with
/// [`RaftHandleError::NotFullyReplicated`] (mapped to wire `Unavailable`).
pub const DEFAULT_REPLICATION_WAIT: Duration = Duration::from_secs(2);

impl RaftHandle {
    /// Stand up the local Raft node over `mesh`, installing its `Raft` into
    /// the already-constructed `handler`.
    ///
    /// `mesh` is the running slice-2 peer mesh; its `Mesh::call` carries the
    /// AppendEntries / Vote / InstallSnapshot RPCs. `self_name` + `peers`
    /// define the static membership and the name <-> id mapping. `handler` is
    /// the [`RaftRequestHandler::deferred`] the caller ALREADY passed to
    /// `Mesh::start` as the mesh's inbound
    /// [`RequestHandler`](crate::mesh::rpc::RequestHandler); this call installs
    /// the freshly-created `Raft` into it so peers' inbound RPCs start
    /// dispatching into the local instance.
    ///
    /// Bootstrap order:
    /// 1. `let handler = RaftRequestHandler::deferred();`
    /// 2. `let mesh = Mesh::start(.., handler.clone(), ..);`
    /// 3. `let raft = RaftHandle::new(mesh, self_name, peers, handler).await?;`
    /// 4. on EXACTLY ONE node, `raft.initialize_cluster().await?`.
    pub async fn new(
        mesh: Arc<Mesh>,
        self_name: &str,
        peers: &[PeerName],
        handler: RaftRequestHandler,
    ) -> Result<Self, RaftHandleError> {
        Self::with_config(mesh, self_name, peers, handler, Self::default_config()).await
    }

    /// The default openraft tuning for the synchronizer cluster.
    ///
    /// Small heartbeat / election timeouts: the cluster is 3 nodes on a
    /// low-latency mesh, and we want leader election in a few hundred ms. These
    /// mirror the openraft kv example's tuned values.
    ///
    /// Snapshotting: build a snapshot every so often so a freshly-restarted
    /// EMPTY node can hydrate from a blob (the #121 path), but retain a
    /// generous in-memory log tail after each snapshot
    /// (`max_in_snapshot_log_to_keep`). The dataset is tiny, so keeping a long
    /// tail is cheap, and it means a node that merely fell BEHIND (partitioned
    /// for a while, then healed) catches up by ordinary log replay rather than
    /// a mid-flight log revert. Keeping recovery on the replay path keeps the
    /// no-persistence + `loosen-follower-log-revert` combination on openraft's
    /// well-trodden code; a node that lost EVERYTHING still hydrates via the
    /// snapshot once the log eventually purges past what it is missing.
    ///
    /// Payload bounds: both `snapshot_max_chunk_size` and `max_payload_entries`
    /// are pinned well under the mesh's single-Noise-message ceiling, because
    /// every replication RPC rides exactly one such message. See the field
    /// comments below for the full argument.
    pub fn default_config() -> openraft::Config {
        openraft::Config {
            heartbeat_interval: 150,
            election_timeout_min: 300,
            election_timeout_max: 600,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(100),
            max_in_snapshot_log_to_keep: 1000,
            // Bound every replication payload to the mesh's single-Noise-message
            // ceiling. A mesh RPC is ONE Noise message
            // (`mesh::handshake::write_message`), and
            // `Noise_NN_25519_ChaChaPoly_BLAKE2s` caps a single message at 65535
            // bytes. openraft fragments an `InstallSnapshot` into chunks of
            // `snapshot_max_chunk_size` and ships each chunk as one such RPC, and
            // batches up to `max_payload_entries` log entries per AppendEntries
            // RPC, so both default ceilings (3 MiB chunk / 300 entries) blow past
            // the frame the moment the snapshot CBOR or a log batch exceeds
            // ~64 KiB, and hydration / replication wedges permanently.
            //
            // The usable budget is well under a literal 64 KiB because the
            // payload is wrapped in THREE layers of `Vec<u8>` on its way to the
            // wire (`InstallSnapshotRequest.data` -> `MeshRaftRpc` -> mesh
            // `Envelope.body` -> `MeshFrame::Rpc.envelope`), and ciborium encodes
            // a `Vec<u8>` as a CBOR array of integers (~1.6x per layer), so the
            // chunk's raw bytes are inflated ~3x before encryption. A 16 KiB chunk
            // therefore reaches the Noise layer at ~48 KiB, comfortably under the
            // 65535-byte cap with room for the 16-byte ChaChaPoly AEAD tag; a
            // 64-entry log batch (each `ReplicatedOp` entry is a couple hundred
            // bytes) stays far smaller still.
            snapshot_max_chunk_size: 16 * 1024,
            max_payload_entries: 64,
            ..Default::default()
        }
    }

    /// Like [`new`](Self::new) but with a caller-supplied openraft [`Config`]
    /// (e.g. tests that force aggressive snapshotting to exercise the
    /// InstallSnapshot hydration path). Production uses [`new`](Self::new).
    pub async fn with_config(
        mesh: Arc<Mesh>,
        self_name: &str,
        peers: &[PeerName],
        handler: RaftRequestHandler,
        config: openraft::Config,
    ) -> Result<Self, RaftHandleError> {
        let ids = NodeIdMap::new(self_name, peers);
        let self_id = ids
            .id_of(self_name)
            .expect("self_name is always in the membership");

        let config = Arc::new(
            config
                .validate()
                .map_err(|e| RaftHandleError::Raft(format!("invalid raft config: {e}")))?,
        );

        let log_store = LogStore::default();
        let sm = Arc::new(StateMachineStore::default());
        let network = MeshRaftNetworkFactory::new(Arc::clone(&mesh), ids.clone());

        let raft = openraft::Raft::new(self_id, config, network, log_store, Arc::clone(&sm))
            .await
            .map_err(|e| RaftHandleError::Raft(format!("Raft::new failed: {e}")))?;

        // Install the live Raft into the deferred handler the mesh already
        // serves, so inbound peer RPCs now reach this instance.
        handler.set_raft(raft.clone());

        Ok(Self {
            raft,
            sm,
            ids,
            self_id,
            replication_wait: DEFAULT_REPLICATION_WAIT,
        })
    }

    /// Override the full-replication wait used by
    /// [`client_write_durable`](Self::client_write_durable). Consumes and
    /// returns the handle (builder style) so a test can shorten the wait, e.g.
    /// to assert that a write under a partition fails fast with
    /// [`RaftHandleError::NotFullyReplicated`] rather than burning the full
    /// production [`DEFAULT_REPLICATION_WAIT`]. Production never calls this; the
    /// default is correct for real use.
    pub fn with_replication_wait(mut self, wait: Duration) -> Self {
        self.replication_wait = wait;
        self
    }

    /// Enable serving FORWARDED client requests on this node.
    ///
    /// A non-leader relays a customer request to the leader over the mesh (see
    /// [`forward`]); the leader's inbound [`RaftRequestHandler`] runs it through
    /// the replicated client path, which needs this `RaftHandle` (the state
    /// machine plus the linearizable read) and the node's `debug_mode` (for
    /// `Transition` chain-link verification). Install them into the SAME
    /// `handler` that was passed to [`new`](Self::new) /
    /// [`with_config`](Self::with_config).
    ///
    /// Call exactly once, right after the handle is constructed, on EVERY node
    /// (any node may end up the leader and receive a forward). Idempotent.
    pub fn enable_serving(&self, handler: &RaftRequestHandler, debug_mode: bool) {
        handler.set_serve(self.clone(), debug_mode);
    }

    /// Whether THIS node is the designated bootstrap node, the one that calls
    /// [`initialize_cluster`](Self::initialize_cluster).
    ///
    /// Every node computes the identical [`NodeIdMap`] (sorted membership), so
    /// the node with id 0 (lexicographically-smallest name) is the same on every
    /// node and is the natural single initializer. This makes the
    /// "exactly one node initializes" rule a pure function of the static config,
    /// no coordination, no env flag. A non-bootstrap node simply waits for the
    /// initial membership to replicate to it.
    pub fn is_bootstrap_node(&self) -> bool {
        self.self_id == 0
    }

    /// Initialize the static 3-node cluster. Call on EXACTLY ONE node (the
    /// [`is_bootstrap_node`](Self::is_bootstrap_node) one) after every node's
    /// `RaftRequestHandler` is wired into its mesh. The other nodes learn the
    /// membership through the initial replication. Idempotent failure
    /// (`NotAllowed` if already initialized) is mapped to `Ok(())`, so a
    /// restarted bootstrap node that re-attempts it on a live cluster is benign.
    pub async fn initialize_cluster(&self) -> Result<(), RaftHandleError> {
        let members: BTreeMap<RaftNodeId, openraft::BasicNode> = self
            .ids
            .members()
            .map(|(id, name)| (id, openraft::BasicNode::new(name.clone())))
            .collect();
        match self.raft.initialize(members).await {
            Ok(()) => Ok(()),
            // Already-initialized is benign on a retry.
            Err(RaftError::APIError(openraft::error::InitializeError::NotAllowed(_))) => Ok(()),
            Err(e) => Err(RaftHandleError::Raft(format!("initialize failed: {e}"))),
        }
    }

    /// Submit a verified [`ReplicatedOp`] for replication and application,
    /// returning as soon as a Raft MAJORITY has committed it.
    ///
    /// Must be called on the leader. Returns the applied [`KeyState`] on
    /// success, [`RaftHandleError::Rejected`] if the pure core deterministically
    /// rejected the op, or [`RaftHandleError::Raft`] (carrying a leader hint
    /// when openraft knows one) if this node is not the leader / quorum is lost.
    ///
    /// This is the MAJORITY-ACK primitive. The CUSTOMER-facing serve path must
    /// NOT use it directly: a majority commit can ACK an entry to a client while
    /// the third node has never seen it, which is the bounded rollback window a
    /// freshness oracle must not have (see the module docs). Use it only
    /// internally, and from the multi-node test harnesses that drive ops
    /// directly. The serve path uses
    /// [`client_write_durable`](Self::client_write_durable) instead.
    pub async fn client_write(&self, op: ReplicatedOp) -> Result<KeyState, RaftHandleError> {
        match self.raft.client_write(op).await {
            Ok(resp) => match resp.data {
                ReplicatedOpResult::Applied(state) => Ok(state),
                ReplicatedOpResult::Rejected(e) => Err(RaftHandleError::Rejected(e)),
            },
            Err(e) => Err(RaftHandleError::Raft(format!("client_write failed: {e}"))),
        }
    }

    /// Submit a verified [`ReplicatedOp`] and ACK only after EVERY current voter
    /// has replicated it. This is the CLIENT write primitive; the serve path
    /// ([`super::serve`]) uses it for `Pin` / `Register` / `Transition`.
    ///
    /// Must be called on the leader. Replicates exactly like
    /// [`client_write`](Self::client_write) (same `Rejected` / `Raft` behavior on
    /// a rejection or a non-leader / quorum-lost error), but on a successful
    /// majority commit it does NOT return yet: it takes the written entry's log
    /// index from openraft's `ClientWriteResponse::log_id` and waits, by watching
    /// [`Raft::metrics`](openraft::Raft::metrics) (a `watch` channel of
    /// `RaftMetrics`), until every voter has caught up to at least that index.
    /// The leader itself is treated as matched (it wrote and applied the entry);
    /// the per-follower match index lives in `metrics.replication`
    /// (`Some(BTreeMap<NodeId, Option<LogId>>)` on a leader). The voter set is
    /// read live from `metrics.membership_config` each poll, so it tracks the
    /// CURRENT membership rather than assuming a hardcoded 3.
    ///
    /// On a [`replication_wait`](Self::replication_wait) timeout (default
    /// [`DEFAULT_REPLICATION_WAIT`], 2s) it returns
    /// [`RaftHandleError::NotFullyReplicated`]: the entry IS committed and
    /// applied locally, but at least one peer has not caught up (a node is down /
    /// partitioned). The caller maps that to wire `Unavailable`; the
    /// at-least-once retry semantics already documented apply (duplicate Pin
    /// benign, duplicate Transition surfaces `TransitionRejected` and the client
    /// confirms via `Get`).
    pub async fn client_write_durable(
        &self,
        op: ReplicatedOp,
    ) -> Result<KeyState, RaftHandleError> {
        let resp = match self.raft.client_write(op).await {
            Ok(resp) => resp,
            Err(e) => return Err(RaftHandleError::Raft(format!("client_write failed: {e}"))),
        };
        let state = match resp.data {
            ReplicatedOpResult::Applied(state) => state,
            ReplicatedOpResult::Rejected(e) => return Err(RaftHandleError::Rejected(e)),
        };

        // The entry is committed + applied on a majority. Wait for the LAST node
        // to catch up to its index before ACKing, so every replica holds it and
        // re-seeding from any single survivor is lossless.
        let target = resp.log_id.index;
        let mut rx = self.raft.metrics();
        let deadline = tokio::time::Instant::now() + self.replication_wait;
        loop {
            if Self::all_voters_replicated(&rx.borrow(), self.self_id, target) {
                return Ok(state);
            }
            // Wait for the next metrics tick or the deadline, whichever first.
            // `changed()` resolves on every metrics update (replication progress
            // included); the timeout bounds a genuinely-down peer.
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(RaftHandleError::NotFullyReplicated(format!(
                    "entry at index {target} committed + applied locally, but not every node \
                     replicated it within {:?}",
                    self.replication_wait
                )));
            }
            match tokio::time::timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => continue,
                // The metrics sender dropped (the Raft core is shutting down):
                // treat as not-fully-replicated rather than hanging.
                Ok(Err(_)) => {
                    return Err(RaftHandleError::NotFullyReplicated(
                        "raft metrics channel closed before full replication".to_string(),
                    ));
                }
                // Timed out waiting for the next tick: re-check the deadline at
                // the top of the loop (it will return NotFullyReplicated).
                Err(_) => continue,
            }
        }
    }

    /// Whether every voter in the current membership has replicated the log
    /// entry at `target` (its match index is `>= target`). The leader
    /// (`self_id`) is always treated as matched: it wrote and applied the entry
    /// before any follower could replicate it. Returns `false` (not fully
    /// replicated) if `metrics.replication` is absent, which happens when this
    /// node is not (or no longer) the leader, so the caller keeps waiting until
    /// the deadline rather than falsely ACKing.
    fn all_voters_replicated(
        metrics: &openraft::RaftMetrics<RaftNodeId, openraft::BasicNode>,
        self_id: RaftNodeId,
        target: u64,
    ) -> bool {
        let Some(replication) = metrics.replication.as_ref() else {
            return false;
        };
        metrics.membership_config.voter_ids().all(|voter| {
            if voter == self_id {
                return true;
            }
            matches!(replication.get(&voter), Some(Some(log_id)) if log_id.index >= target)
        })
    }

    /// Whether this node currently believes it is the leader. A best-effort
    /// hint for write routing; the authoritative check happens inside
    /// [`client_write`](Self::client_write) (a stale `true` simply yields a
    /// `ForwardToLeader` error there).
    pub async fn is_leader(&self) -> bool {
        self.raft.current_leader().await == Some(self.self_id)
    }

    /// The logical name of the node this node currently believes is the
    /// leader, if any. The write-routing redirect hint for slice 4.
    pub async fn leader_name(&self) -> Option<String> {
        let id = self.raft.current_leader().await?;
        self.ids.name_of(id).map(|s| s.to_string())
    }

    /// Linearizable read: look up the current [`KeyState`] for `key`, only
    /// after openraft confirms this node is still a leader with a fresh quorum
    /// (`ensure_linearizable`). A freshness oracle MUST NOT serve stale data,
    /// so a non-leader / quorum-lost node returns
    /// [`RaftHandleError::NotLinearizable`] instead of a possibly-stale local
    /// read. `Ok(None)` means the key is not currently registered.
    pub async fn linearizable_get(
        &self,
        key: &PcrKey,
    ) -> Result<Option<KeyState>, RaftHandleError> {
        self.raft
            .ensure_linearizable()
            .await
            .map_err(|e| RaftHandleError::NotLinearizable(format!("{e}")))?;
        Ok(self.sm.get(key).await)
    }

    /// Shared state-machine store, for tests / slice-4 inspection (e.g. the
    /// NodeViewConsistent harness comparing views across nodes). Reads through
    /// this are leader-local and NOT linearized; use
    /// [`linearizable_get`](Self::linearizable_get) on the serving path.
    pub fn state_machine(&self) -> &Arc<StateMachineStore> {
        &self.sm
    }

    /// The underlying openraft handle, for metrics / advanced control in
    /// slice 4 (leader-change waits, membership, etc.).
    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Wait up to `timeout` for this node to observe SOME leader (itself or a
    /// peer). Convenience for bootstrap / tests; returns the leader's node id.
    pub async fn wait_for_leader(&self, timeout: Duration) -> Option<RaftNodeId> {
        self.raft
            .wait(Some(timeout))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .ok()
            .and_then(|m| m.current_leader)
    }

    /// Cleanly stop the local openraft core task. Slice 4 / tests call this on
    /// node teardown so the openraft background task (which holds a clone of
    /// the mesh through its network) actually exits, rather than lingering and
    /// continuing to answer peers from a node that is supposed to be gone.
    /// After this, drop the mesh to tear down its dial / accept loops.
    pub async fn shutdown(&self) {
        let _ = self.raft.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }
    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }
    fn pk(b: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        let mut out = [b.wrapping_add(0x80); CONTROL_PUBKEY_LEN];
        out[0] = 0x04;
        out
    }

    /// Every node in a same-config cluster computes the identical name <-> id
    /// mapping (sorted membership = self + peers), so the static 3-node cluster
    /// agrees on ids without coordination.
    #[test]
    fn node_id_map_is_deterministic_across_nodes() {
        let a = NodeIdMap::new("node-a", &["node-b".into(), "node-c".into()]);
        let b = NodeIdMap::new("node-b", &["node-a".into(), "node-c".into()]);
        let c = NodeIdMap::new("node-c", &["node-a".into(), "node-b".into()]);
        for name in ["node-a", "node-b", "node-c"] {
            assert_eq!(a.id_of(name), b.id_of(name));
            assert_eq!(b.id_of(name), c.id_of(name));
        }
        // Sorted order assigns 0/1/2 to a/b/c.
        assert_eq!(a.id_of("node-a"), Some(0));
        assert_eq!(a.id_of("node-b"), Some(1));
        assert_eq!(a.id_of("node-c"), Some(2));
        assert_eq!(a.name_of(2), Some("node-c"));
        assert_eq!(a.members().count(), 3);
    }

    /// Each [`ReplicatedOp`] variant CBOR-round-trips, including the 65-byte
    /// control pubkey carried through the custom byte adapter, so the log
    /// entries the leader replicates decode identically on every follower.
    #[test]
    fn replicated_op_cbor_round_trips() {
        for op in [
            ReplicatedOp::Register {
                key: k(1),
                commitment: c(0xaa),
                control_pubkey: pk(1),
            },
            ReplicatedOp::Pin {
                key: k(2),
                commitment: c(0xbb),
            },
            ReplicatedOp::Transition {
                old_key: k(3),
                new_key: k(4),
                new_control_pubkey: pk(4),
            },
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&op, &mut buf).unwrap();
            let back: ReplicatedOp = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(op, back);
        }
    }
}
