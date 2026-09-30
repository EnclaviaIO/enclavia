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
//!   `apply(Op::Transition { old_key, new_key, link_hash })`. (The old
//!   key was attested by an earlier `Register`/`Pin` entry, already
//!   replicated, so its observation is already present on every replica.)
//! * [`ReplicatedOp::Revoke`]: `apply(Op::Revoke { key, link_hash })`. The
//!   leader verified the revocation link's control signature against `key`'s
//!   frozen pubkey and that the submitting session IS `key`.
//!
//! The revocation check sits in the pure core's `apply` of the Transition, not
//! in a leader pre-check, so it is decided at the entry's position in the
//! committed log: a `Revoke` committed before a `Transition` refuses it on
//! every replica, including one hydrated from a snapshot (the revoked hashes are
//! part of it).
//!
//! Followers never re-verify crypto. The trust argument is the same one Raft
//! itself rests on: openraft assumes non-Byzantine members, and mesh membership
//! is gated by mutual attestation against the self-PCR allowlist (slice 2), so
//! a peer that reached the replication channel is provably running our exact
//! image. Leader-verified conclusions are therefore trusted by followers
//! exactly as far as the cluster trusts its own members, which the PCR
//! allowlist already pins to "bit-for-bit us".
//!
//! ## Identity and membership: clone-resistant, per-boot instance keys (#209)
//!
//! A node's Raft member identity ([`RaftNodeId`]) is [`instance_node_id`] of
//! its per-boot P-256 mesh instance pubkey, NOT a name-derived index. The
//! openraft node payload is a [`MemberRecord`] (`{ name, pubkey }`) carried in
//! the committed membership, so every replica re-derives ids and re-checks the
//! one-instance-per-slot invariant from committed state alone, and id->name
//! routing reads the leader's / target's record out of the membership rather
//! than a static table. Logical names are pure routing labels that only bound
//! the cluster shape (one member slot per configured name).
//!
//! Why: attestation proves WHAT runs, never WHICH instance, so a host can boot
//! a second copy of the same measured image. A name-derived id would let two
//! honest processes hold one vote (split-brain / rollback). A per-boot instance
//! key cannot be impersonated (a clone has no copy of it), so the worst a clone
//! can do is REQUEST a replacement through the same join path a genuine restart
//! uses: membership churn (a DoS the host can already inflict), never two
//! simultaneous holders of a slot's vote. The decision kernel
//! ([`membership::plan_admission`]) is pure and frozen; its SECURITY CONTRACT
//! is that the candidate pubkey comes from the candidate's mutually-attested
//! mesh channel ([`crate::mesh::rpc::PeerContext::mesh_pubkey`]), never a
//! request payload. The leader-side execution (`add_learner` then one atomic
//! `change_membership`, [`RaftHandle::admit`]) linearizes replace-on-rejoin
//! through the log. Boot discovery, the join state machine, and the eviction
//! watch live in [`join`]; the threat model and invariant are in
//! [`membership`].
//!
//! ## Snapshot / hydration semantics
//!
//! The state-machine snapshot serializes the ENTIRE pure-core state, the
//! committed `(PcrKey -> KeyState)` projection AND the observation sets
//! (`attested`, `transition_authorizations`) and the revoked link hashes, via
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
//! ## Majority ACK (client writes are durable on a quorum of voters)
//!
//! A client write ([`client_write`](RaftHandle::client_write), used by the
//! serve path for every `Pin` / `Register` / `Transition`) is ACKed when
//! openraft returns it: the entry has been COMMITTED, i.e. appended to the log
//! of a quorum of the effective membership (both halves of a joint config
//! during a membership change), and applied on the leader. With three voters
//! that is the leader plus at least one follower. Applied-on-the-leader alone
//! is never an ACK: openraft only applies committed entries.
//!
//! Safety invariant: **an ACKed write survives the loss of any single node.**
//!
//! * The leader dies: at least one surviving follower holds the entry. Any new
//!   leader needs votes from a quorum of the voters, which among two survivors
//!   means both, and Raft's election restriction makes the holder refuse a
//!   candidate whose log is behind its own. So the new leader holds the entry
//!   and the committed history is never rolled back.
//! * A follower dies: the leader still holds the entry, and so does every
//!   other quorum member it counted.
//! * The node that died comes back with an empty log. It cannot vote the
//!   entry away because its identity is per boot (#209): it is a new id, not a
//!   voter, until the leader admits it (`add_learner` catches it up first,
//!   then `change_membership` commits under the current quorum). This part of
//!   the argument depends on per-boot identity; a restarted node that kept its
//!   old voter id with an empty in-memory log would break it.
//!
//! What this does NOT cover: losing two nodes at once. With no persistence
//! (#122) an entry that reached only two nodes is gone if both die, and the
//! remaining node cannot commit anything (no quorum), so the cluster halts
//! rather than serving; recovery from that is the cold-start design, out of
//! scope here. The alternative (ACK only once EVERY voter holds the entry)
//! made re-seeding from any single survivor lossless, but it meant one dead
//! node turned every client write into `Unavailable`, which is the far more
//! common failure. Linearizable reads need a fresh quorum either way.

pub mod forward;
pub mod join;
pub mod membership;
pub(crate) mod network;
pub mod serve;
mod store;

use std::collections::{BTreeMap, BTreeSet};
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
pub use join::{discover_and_join, watch_for_eviction};
pub use membership::{
    AdmissionError, AdmissionPlan, MemberRecord, instance_node_id, plan_admission,
};
pub use network::{MeshRaftNetworkFactory, RaftRequestHandler};
pub use store::{LogStore, StateMachineStore, StoreStats, control_pubkey_bytes};

/// Re-export of openraft's tuning [`Config`](openraft::Config) +
/// [`SnapshotPolicy`](openraft::SnapshotPolicy), so callers (slice 4, tests)
/// can build a custom config to pass to [`RaftHandle::with_config`] without
/// depending on `openraft` directly.
pub use openraft::{Config, SnapshotPolicy};

/// openraft node id: the clone-resistant per-boot member identity, derived
/// from the node's mesh instance pubkey by [`instance_node_id`] (truncated
/// SHA-256). NOT derived from the logical name (that was the host-replayable
/// identity #209 kills); the name is a pure routing label that lives in the
/// node's [`MemberRecord`] payload. See [`membership`] for the threat model.
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
    /// Pin a fresh commitment under an already-registered key. Carries the
    /// compare-and-swap `expected_version` the leader accepted at submit
    /// time; the pure core re-checks it deterministically on every replica
    /// at apply (identically everywhere), so a stale fork's pin rejects on
    /// ALL nodes, never just on the leader that first saw it.
    Pin {
        /// The registered key whose commitment is updated.
        key: PcrKey,
        /// CAS guard: applies only when the key's current version equals
        /// this at apply time.
        expected_version: crate::Version,
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
        /// Payload hash of the presented link (`upgrade_link_hash`), checked
        /// against `old_key`'s revoked links at apply.
        link_hash: [u8; 32],
    },
    /// Revocation of one upgrade link out of `key`. The leader verified the
    /// revocation link's control signature against `key`'s frozen pubkey, and
    /// that the submitting session is authenticated as `key`.
    Revoke {
        /// The key whose outgoing upgrade links are revoked.
        key: PcrKey,
        /// The revocation's signed `RevocationPayload.revokes_link`.
        link_hash: [u8; 32],
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
    /// log entry, a [`ReplicatedOpResult`] response, [`RaftNodeId`] node ids
    /// (clone-resistant instance ids, #209), [`MemberRecord`] node metadata
    /// (the routing name + the instance pubkey the id derives from), and a
    /// `Cursor<Vec<u8>>` snapshot blob (the CBOR-serialized pure-core
    /// snapshot).
    ///
    /// The node payload moved from `openraft::BasicNode` (a bare `addr`
    /// string) to [`MemberRecord`] so the committed membership carries each
    /// voter's instance pubkey: every replica can re-derive the id from the
    /// pubkey and re-check the one-instance-per-slot invariant from committed
    /// state alone, and the join handler reads the leader / target name out of
    /// the replicated records rather than a static name->id table.
    pub TypeConfig:
        D = ReplicatedOp,
        R = ReplicatedOpResult,
        NodeId = RaftNodeId,
        Node = MemberRecord,
        SnapshotData = std::io::Cursor<Vec<u8>>,
);

/// openraft `Raft` specialized for this cluster's [`TypeConfig`].
pub type Raft = openraft::Raft<TypeConfig>;

/// Convenience alias for openraft errors surfaced by [`RaftHandle`] methods.
pub type RaftClientWriteError = RaftError<RaftNodeId, ClientWriteError<RaftNodeId, MemberRecord>>;

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
    /// The kernel ([`plan_admission`](membership::plan_admission)) refused a
    /// join request: an unknown slot name, an id collision with a live voter
    /// of a different slot, or corrupt committed membership. Deterministic on
    /// the leader; the joiner must NOT retry (the answer will not change), so
    /// it is surfaced distinctly from a transient not-leader / quorum error.
    #[error("join refused by admission kernel: {0}")]
    JoinRefused(#[from] membership::AdmissionError),
    /// This node is not currently the leader, so it cannot execute a join /
    /// membership change. Carries the leader's routing name as a redirect hint
    /// when one is known (the joiner retries against it). A `None` hint means
    /// no leader is currently known (an election is in progress).
    #[error("not the leader; redirect to {0:?}")]
    NotLeader(Option<String>),
    /// No quorum confirmed the operation within the bound (see
    /// [`COMMIT_TIMEOUT`]). For a write the outcome is UNKNOWN: the entry may
    /// still commit later.
    #[error("no quorum within {0:?}; a write may still commit")]
    CommitTimeout(Duration),
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
    /// This node's own committed-membership record: its routing name plus its
    /// per-boot instance pubkey. The id is [`instance_node_id`] of the pubkey
    /// (no name-derived id any more, #209).
    self_record: MemberRecord,
    /// The configured cluster shape: one member slot per name. Bounds
    /// admission ([`plan_admission`] refuses any name outside this set) and
    /// the discovery bootstrap (the lexicographically-smallest name is the
    /// fresh-cluster initializer).
    configured_names: BTreeSet<String>,
    self_id: RaftNodeId,
    /// Bounded wait for the blocking `add_learner` in [`Self::admit`]. Defaults
    /// to [`ADD_LEARNER_TIMEOUT`]; shortened by tests via
    /// [`with_add_learner_timeout`](Self::with_add_learner_timeout).
    add_learner_timeout: Duration,
    /// Bounded wait for a quorum on the client path: a commit in
    /// [`Self::client_write`], a ReadIndex round in
    /// [`Self::linearizable_get`]. Defaults to [`COMMIT_TIMEOUT`]; changed by
    /// tests via [`with_commit_timeout`](Self::with_commit_timeout).
    commit_timeout: Duration,
}

/// How long the client path waits for a quorum before answering
/// `Unavailable`: for a write, until the entry is committed and applied on the
/// leader; for a linearizable read, until the leader has confirmed that it
/// still leads a quorum.
///
/// openraft's `client_write` has no deadline of its own. Without a quorum it
/// waits until one comes back, so the customer's request would hang until its
/// own RPC timeout (30 s in nbd-client), and a forwarded request would also
/// hold the forwarding peer's mesh channel, whose serve loop is sequential.
///
/// Five seconds, against the numbers this cluster runs at: a healthy commit
/// takes about a millisecond, a snapshot build stalls writes for 50-100 ms,
/// and an election takes 300-600 ms. So 5 s only elapses when no quorum is
/// reachable. It is also well below the customer's 30 s RPC timeout, so the
/// customer gets the structured `Unavailable` (and retries on the same session
/// under its own budget) instead of an RPC timeout, which it treats as a dead
/// session.
///
/// A write that times out is NOT abandoned: the entry stays in the leader's
/// log and may still commit later. `Unavailable` therefore means "outcome
/// unknown" for a write, never "not applied". This is safe because the
/// deterministic `apply` checks every op again when it commits (the pin's
/// compare-and-swap, `AlreadyRegistered`, the transition and revocation
/// rules), and because a pending entry either commits before any entry
/// appended after it, or never.
pub const COMMIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded wait for the blocking `add_learner` step of a leader-side admission
/// ([`RaftHandle::admit`]).
///
/// openraft's `add_learner(.., blocking = true)` waits with NO deadline of its
/// own (`wait(None)`) for the new learner to catch up by log replay or
/// `InstallSnapshot`. A learner that stops making progress therefore parks the
/// leader in that wait, and because the mesh serve loop is SEQUENTIAL per
/// connection it takes the joiner's whole channel with it: no further request
/// from that peer is answered until the wait ends.
///
/// Two minutes is far beyond a healthy catch-up (the state machine is small and
/// the mesh is low-latency); exceeding it means the learner is not making
/// progress, and the leader is better off failing the admission — freeing its
/// serve loop — and letting the joiner's retry start a fresh attempt.
///
/// Timing out is SAFE to retry: the admission kernel
/// ([`plan_admission`](membership::plan_admission)) is a pure function of the
/// committed voter set, and a learner that was added but never caught up is not
/// a voter, so a retry recomputes the identical plan. If the earlier attempt
/// did complete, rule 3 of the kernel reports `already_member` and the retry is
/// a no-op.
pub const ADD_LEARNER_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// `self_pubkey` is this node's 65-byte SEC1 per-boot mesh instance pubkey
    /// (`MeshIdentity::pubkey`); its [`instance_node_id`] is this node's
    /// clone-resistant Raft id (#209). `self_name` + `peers` define the
    /// configured cluster shape (one slot per name), used to bound admission
    /// and to pick the discovery bootstrap node.
    ///
    /// Bootstrap order:
    /// 1. `let handler = RaftRequestHandler::deferred();`
    /// 2. `let mesh = Mesh::start(.., handler.clone(), ..);`
    /// 3. `let raft = RaftHandle::new(mesh, self_name, self_pubkey, peers, handler).await?;`
    /// 4. drive [`discover_and_join`](Self::discover_and_join) (which probes
    ///    for a live cluster, joins it, or initializes a fresh one when this
    ///    node holds the smallest configured name and no peer knows a cluster).
    pub async fn new(
        mesh: Arc<Mesh>,
        self_name: &str,
        self_pubkey: [u8; CONTROL_PUBKEY_LEN],
        peers: &[PeerName],
        handler: RaftRequestHandler,
    ) -> Result<Self, RaftHandleError> {
        Self::with_config(
            mesh,
            self_name,
            self_pubkey,
            peers,
            handler,
            Self::default_config(),
        )
        .await
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
            // 50000, not 100: every snapshot build stalls the cluster's write
            // path for ~50-100ms (measured on the QEMU bench cluster; the
            // stall survives quieted logging and disabled purge, so it is
            // openraft's snapshot-completion machinery itself, not our
            // storage callbacks, which all measure <7ms). At LogsSinceLast(100)
            // that stall recurred every ~100 Pins and dominated the
            // customer-visible p99 under load (bench: p99 47-65ms with the
            // stall vs ~1ms without). At 50000 it is amortized to noise at
            // any realistic pin rate, while memory stays bounded (a
            // ReplicatedOp entry is a couple hundred bytes, so the retained
            // tail is ~15 MiB worst case in a 768M guest) and a restarting
            // node still hydrates exactly as before: by log replay when it
            // merely fell behind, by snapshot once the log purges past what
            // it is missing.
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(50000),
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
        self_pubkey: [u8; CONTROL_PUBKEY_LEN],
        peers: &[PeerName],
        handler: RaftRequestHandler,
        config: openraft::Config,
    ) -> Result<Self, RaftHandleError> {
        let self_record = MemberRecord {
            name: self_name.to_string(),
            pubkey: self_pubkey,
        };
        let self_id = instance_node_id(&self_pubkey);

        // Configured cluster shape: one slot per name (self + peers).
        let mut configured_names: BTreeSet<String> = peers.iter().map(|p| p.to_string()).collect();
        configured_names.insert(self_name.to_string());

        let config = Arc::new(
            config
                .validate()
                .map_err(|e| RaftHandleError::Raft(format!("invalid raft config: {e}")))?,
        );

        let log_store = LogStore::default();
        let sm = Arc::new(StateMachineStore::default());
        let network = MeshRaftNetworkFactory::new(Arc::clone(&mesh));

        let raft = openraft::Raft::new(self_id, config, network, log_store, Arc::clone(&sm))
            .await
            .map_err(|e| RaftHandleError::Raft(format!("Raft::new failed: {e}")))?;

        // Install the live Raft into the deferred handler the mesh already
        // serves, so inbound peer RPCs now reach this instance.
        handler.set_raft(raft.clone());

        Ok(Self {
            raft,
            sm,
            self_record,
            configured_names,
            self_id,
            add_learner_timeout: ADD_LEARNER_TIMEOUT,
            commit_timeout: COMMIT_TIMEOUT,
        })
    }

    /// Override the bounded `add_learner` wait used by [`admit`](Self::admit).
    /// Consumes and returns the handle (builder style) so a test can
    /// assert that an admission whose learner never catches up returns within
    /// the bound without burning the full production [`ADD_LEARNER_TIMEOUT`].
    /// Production never calls this.
    pub fn with_add_learner_timeout(mut self, timeout: Duration) -> Self {
        self.add_learner_timeout = timeout;
        self
    }

    /// Override the bounded quorum wait used by
    /// [`client_write`](Self::client_write) and
    /// [`linearizable_get`](Self::linearizable_get) (default
    /// [`COMMIT_TIMEOUT`]). Consumes and returns the handle (builder style).
    /// Tests use a near-zero value on a clone to get a write that times out
    /// and still commits. Production never calls this.
    pub fn with_commit_timeout(mut self, timeout: Duration) -> Self {
        self.commit_timeout = timeout;
        self
    }

    /// The bounded quorum wait of the client path (see [`COMMIT_TIMEOUT`]).
    pub fn commit_timeout(&self) -> Duration {
        self.commit_timeout
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

    /// This node's own committed-membership record (routing name + instance
    /// pubkey). Its id is [`Self::self_id`].
    pub fn self_record(&self) -> &MemberRecord {
        &self.self_record
    }

    /// This node's clone-resistant Raft id ([`instance_node_id`] of its mesh
    /// instance pubkey).
    pub fn self_id(&self) -> RaftNodeId {
        self.self_id
    }

    /// The configured cluster shape (one slot per name). Bounds admission and
    /// picks the discovery bootstrap node.
    pub fn configured_names(&self) -> &BTreeSet<String> {
        &self.configured_names
    }

    /// Whether THIS node holds the lexicographically-smallest configured name.
    ///
    /// Names are pure routing labels (#209), so the smallest one is identical
    /// on every node and is the natural single initializer of a FRESH cluster.
    /// Note this is NOT "the node that always initializes": [`discover_and_join`]
    /// only initializes when NO peer reports an existing cluster within the
    /// discovery window. A restarted smallest-name node on a LIVE cluster
    /// discovers the cluster (its Join is admitted, or it is already a member)
    /// and never re-initializes. See [`discover_and_join`].
    pub fn is_smallest_name(&self) -> bool {
        self.configured_names
            .iter()
            .next()
            .map(|n| n.as_str() == self.self_record.name)
            .unwrap_or(false)
    }

    /// Initialize a fresh cluster with the given member records, keyed by their
    /// derived ids. Call on EXACTLY ONE node (the discovery bootstrap), with
    /// `members` containing this node plus every peer whose mesh channel is up
    /// (so their instance pubkeys are known). The other nodes learn the
    /// membership through the initial replication and so become voters WITHOUT
    /// a join. Idempotent failure (`NotAllowed` if already initialized) is
    /// mapped to `Ok(())`, so a re-attempt on a live cluster is benign.
    ///
    /// SECURITY: each record's pubkey MUST be the peer's attested
    /// `PeerIdentity::mesh_pubkey` (the caller obtains it from the mesh
    /// channel, never from a request payload), the same contract
    /// [`plan_admission`] documents.
    pub async fn initialize_cluster(
        &self,
        members: BTreeMap<RaftNodeId, MemberRecord>,
    ) -> Result<(), RaftHandleError> {
        match self.raft.initialize(members).await {
            Ok(()) => Ok(()),
            // Already-initialized is benign on a retry.
            Err(RaftError::APIError(openraft::error::InitializeError::NotAllowed(_))) => Ok(()),
            Err(e) => Err(RaftHandleError::Raft(format!("initialize failed: {e}"))),
        }
    }

    /// Submit a verified [`ReplicatedOp`] for replication and application.
    /// This is the client write primitive: the serve path ([`super::serve`])
    /// uses it for every `Pin` / `Register` / `Transition`.
    ///
    /// Must be called on the leader. Returns the applied [`KeyState`] on
    /// success, [`RaftHandleError::Rejected`] if the pure core deterministically
    /// rejected the op, or [`RaftHandleError::Raft`] (carrying a leader hint
    /// when openraft knows one) if this node is not the leader / quorum is lost.
    ///
    /// Success means the entry is durable on a quorum of voters: openraft
    /// resolves a client write only after the entry is committed (in the log of
    /// a quorum of the effective membership, joint configs included) and then
    /// applied on the leader. Both outcomes, `Applied` and `Rejected`, are
    /// committed facts that every replica reproduces. See the module docs'
    /// "Majority ACK" section for why a quorum-durable ACK survives the loss of
    /// any single node.
    ///
    /// The wait is bounded by [`COMMIT_TIMEOUT`]. When it elapses this returns
    /// [`RaftHandleError::CommitTimeout`] and the entry may STILL commit later:
    /// the caller must report "outcome unknown", never "not applied".
    pub async fn client_write(&self, op: ReplicatedOp) -> Result<KeyState, RaftHandleError> {
        match tokio::time::timeout(self.commit_timeout, self.raft.client_write(op)).await {
            Ok(Ok(resp)) => match resp.data {
                ReplicatedOpResult::Applied(state) => Ok(state),
                ReplicatedOpResult::Rejected(e) => Err(RaftHandleError::Rejected(e)),
            },
            Ok(Err(e)) => Err(RaftHandleError::Raft(format!("client_write failed: {e}"))),
            Err(_) => Err(RaftHandleError::CommitTimeout(self.commit_timeout)),
        }
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
    ///
    /// The id->name mapping now comes from the COMMITTED membership records
    /// (the leader's [`MemberRecord`] in `metrics.membership_config`), not a
    /// static name<->id table: an id is the leader's instance id, and its
    /// routing name is whatever record the cluster committed for it.
    pub async fn leader_name(&self) -> Option<String> {
        let id = self.raft.current_leader().await?;
        self.name_of_committed(id).await
    }

    /// The routing name committed for `id` in the current membership, if `id`
    /// is a member. Reads the replicated [`MemberRecord`]s out of
    /// `metrics.membership_config`; returns `None` for a non-member id.
    pub async fn name_of_committed(&self, id: RaftNodeId) -> Option<String> {
        let metrics = self.raft.metrics().borrow().clone();
        metrics
            .membership_config
            .membership()
            .get_node(&id)
            .map(|rec| rec.name.clone())
    }

    /// The committed voter records, keyed by id, read live from
    /// `metrics.membership_config`. This is the map the join handler feeds to
    /// [`plan_admission`] (committed voters only, not learners): each entry's
    /// id equals [`instance_node_id`] of its recorded pubkey, which the kernel
    /// re-checks as defence in depth.
    pub async fn committed_voters(&self) -> BTreeMap<RaftNodeId, MemberRecord> {
        let metrics = self.raft.metrics().borrow().clone();
        let cfg = metrics.membership_config.membership();
        let voters: BTreeSet<RaftNodeId> = cfg.voter_ids().collect();
        cfg.nodes()
            .filter(|(id, _)| voters.contains(id))
            .map(|(id, rec)| (*id, rec.clone()))
            .collect()
    }

    /// Whether `id` is a committed VOTER in the current membership. Used by a
    /// joiner to detect "I am already a voter" (it was admitted, or an
    /// initialize included its id) and stop retrying its Join.
    pub async fn is_committed_voter(&self, id: RaftNodeId) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        metrics.membership_config.voter_ids().any(|v| v == id)
    }

    /// Whether THIS node is a committed voter in the current membership. The
    /// eviction watch ([`watch_for_eviction`](Self::watch_for_eviction)) and
    /// the joiner's "already a member" detection both rest on it.
    pub async fn self_is_committed_voter(&self) -> bool {
        self.is_committed_voter(self.self_id).await
    }

    /// Whether the local node has observed an INITIALIZED cluster: it has a
    /// committed membership with at least one voter (either it initialized,
    /// joined, or learned the membership via replication / a snapshot). A
    /// brand-new node that has not yet discovered the cluster reports `false`.
    pub async fn cluster_is_initialized(&self) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        metrics.membership_config.voter_ids().next().is_some()
    }

    /// Linearizable read: look up the current [`KeyState`] for `key`, only
    /// after openraft confirms this node is still a leader with a fresh quorum
    /// (`ensure_linearizable`). A freshness oracle MUST NOT serve stale data,
    /// so a non-leader / quorum-lost node returns
    /// [`RaftHandleError::NotLinearizable`] instead of a possibly-stale local
    /// read. `Ok(None)` means the key is not currently registered.
    ///
    /// The quorum confirmation is bounded by [`COMMIT_TIMEOUT`]
    /// ([`RaftHandleError::CommitTimeout`] when it elapses).
    pub async fn linearizable_get(
        &self,
        key: &PcrKey,
    ) -> Result<Option<KeyState>, RaftHandleError> {
        match tokio::time::timeout(self.commit_timeout, self.raft.ensure_linearizable()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(RaftHandleError::NotLinearizable(format!("{e}"))),
            Err(_) => return Err(RaftHandleError::CommitTimeout(self.commit_timeout)),
        }
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

    /// LEADER-SIDE admission: run the frozen kernel
    /// ([`plan_admission`](membership::plan_admission)) against the current
    /// committed voters, then execute its plan through openraft (a blocking
    /// `add_learner` followed by one `change_membership`), linearizing the
    /// replace-on-rejoin atomically.
    ///
    /// SECURITY CONTRACT: `candidate_pubkey` MUST be the candidate's attested
    /// `PeerIdentity::mesh_pubkey`, taken from its mutually-attested mesh
    /// channel by the caller (the inbound join handler), NEVER from a request
    /// payload. This method does no attestation itself; it trusts its caller to
    /// have sourced the key from the channel, exactly as the kernel docs
    /// require.
    ///
    /// Returns:
    /// * `Ok(true)`: the candidate is now (or was already) the slot's voter;
    /// * `Err(JoinRefused)`: the kernel refused (unknown slot / id collision /
    ///   corrupt membership), deterministic, the joiner must not retry;
    /// * `Err(NotLeader(hint))`: this node is not the leader (the membership
    ///   change was rejected by openraft); the joiner retries against `hint`;
    /// * `Err(Raft(..))`: a transient openraft error executing the plan.
    pub async fn admit(
        &self,
        candidate_name: &str,
        candidate_pubkey: &[u8; CONTROL_PUBKEY_LEN],
    ) -> Result<bool, RaftHandleError> {
        // Only the leader can change membership. Fail fast with a hint so the
        // joiner redirects rather than running the kernel against a possibly
        // stale follower view.
        if !self.is_leader().await {
            return Err(RaftHandleError::NotLeader(self.leader_name().await));
        }

        let voters = self.committed_voters().await;
        let plan = plan_admission(
            &self.configured_names,
            &voters,
            candidate_name,
            candidate_pubkey,
        )?;

        // Idempotent re-join (a retry after a lost reply): the candidate is
        // already the slot's live voter. Nothing to commit.
        if plan.already_member {
            return Ok(true);
        }

        // Execute the plan: add the candidate as a learner (block until it has
        // caught up via log replay / InstallSnapshot), then one atomic
        // change_membership to the kernel's exact voter set (joint consensus).
        // `retain: false` DROPS the evicted previous holder entirely (not kept
        // as a learner): a replaced instance must leave the cluster.
        //
        // The blocking add_learner is bounded (see ADD_LEARNER_TIMEOUT): a
        // learner that never catches up must not park the leader's serve loop
        // for this connection, which would block every later request from the
        // joiner behind it. On timeout we return a transient `Raft` error,
        // which the join handler maps to wire `Unavailable`, so the joiner
        // retries and the (idempotent) plan is recomputed from scratch.
        match tokio::time::timeout(
            self.add_learner_timeout,
            self.raft
                .add_learner(plan.added_id, plan.added.clone(), true),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(Self::membership_change_err(e, self).await),
            Err(_) => {
                tracing::warn!(
                    candidate = %candidate_name,
                    learner_id = plan.added_id,
                    timeout = ?self.add_learner_timeout,
                    "add_learner did not catch the candidate up within the bound; \
                     abandoning this admission so the joiner can retry"
                );
                return Err(RaftHandleError::Raft(format!(
                    "learner {candidate_name} did not catch up within {:?}; retry the join",
                    self.add_learner_timeout
                )));
            }
        }
        // NOT bounded, deliberately. `change_membership` needs a quorum of the
        // committed voter set to commit, so in the designed 3-node shape it
        // succeeds whenever the two SURVIVING nodes are up — which is exactly
        // the replace-on-rejoin case. Cancelling it midway could leave the
        // cluster in the joint configuration openraft transitions through, so
        // the deadline goes on the step that can stall on an unresponsive
        // learner (`add_learner`, above) and not on this one. A cluster that
        // has already lost quorum cannot admit anyone regardless.
        if let Err(e) = self
            .raft
            .change_membership(plan.new_voter_ids.clone(), false)
            .await
        {
            return Err(Self::membership_change_err(e, self).await);
        }
        let join = &crate::metrics::global().join;
        join.admissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if plan.evicted_id.is_some() {
            join.evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(true)
    }

    /// Map an openraft membership-change error to a [`RaftHandleError`]: a
    /// `ForwardToLeader` (this node stepped down mid-change) becomes
    /// [`RaftHandleError::NotLeader`] carrying the current leader hint so the
    /// joiner redirects; everything else is a transient `Raft` error.
    async fn membership_change_err(
        e: RaftClientWriteError,
        handle: &RaftHandle,
    ) -> RaftHandleError {
        let msg = format!("{e}");
        if msg.contains("ForwardToLeader") || msg.contains("forward") {
            RaftHandleError::NotLeader(handle.leader_name().await)
        } else {
            RaftHandleError::Raft(format!("membership change failed: {e}"))
        }
    }

    /// Wait up to `window` for THIS node to observe an initialized cluster
    /// (a committed membership with voters). Returns `true` if a cluster was
    /// observed, `false` if the window elapsed with none. The discovery
    /// bootstrap uses it: only when NO peer reports a cluster within the
    /// window does the smallest-name node initialize a fresh one.
    pub async fn await_cluster_observed(&self, window: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + window;
        loop {
            if self.cluster_is_initialized().await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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

    /// The clone-resistant id is a function of the per-boot instance PUBKEY,
    /// not the routing name (#209): two nodes sharing a name but holding
    /// different keys get different ids, and the same key always yields the
    /// same id. The full id-derivation rules are the kernel's; this only
    /// confirms the wiring re-exports and uses [`instance_node_id`] for ids.
    #[test]
    fn id_derives_from_pubkey_not_name() {
        // Same name, different keys -> different ids (the restart / clone case).
        assert_ne!(instance_node_id(&pk(1)), instance_node_id(&pk(2)));
        // Same key -> same id, regardless of which node computes it.
        assert_eq!(instance_node_id(&pk(1)), instance_node_id(&pk(1)));
    }

    /// The [`MemberRecord`] node payload CBOR-round-trips (its 65-byte pubkey
    /// rides the shared byte adapter), so committed membership decodes
    /// identically on every replica.
    #[test]
    fn member_record_cbor_round_trips() {
        let rec = MemberRecord {
            name: "node-b".to_string(),
            pubkey: pk(7),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&rec, &mut buf).unwrap();
        let back: MemberRecord = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(rec, back);
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
                expected_version: crate::Version(0),
                commitment: c(0xbb),
            },
            ReplicatedOp::Transition {
                old_key: k(3),
                new_key: k(4),
                new_control_pubkey: pk(4),
                link_hash: [0x4c; 32],
            },
            ReplicatedOp::Revoke {
                key: k(3),
                link_hash: [0x4d; 32],
            },
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&op, &mut buf).unwrap();
            let back: ReplicatedOp = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(op, back);
        }
    }
}
