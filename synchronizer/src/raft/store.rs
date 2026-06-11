//! In-memory Raft storage for the synchronizer cluster.
//!
//! Two pieces, per openraft's storage-v2 split:
//!
//! * [`LogStore`]: an in-memory [`RaftLogStorage`] (vote, committed marker, log
//!   entries, purge/truncate). Vendored from openraft's `memstore` example
//!   (in-memory, demonstration-grade), which is exactly what the #16 design
//!   asks for: no persistence, durability is purely N-replica in memory.
//! * [`StateMachineStore`]: a [`RaftStateMachine`] that wraps the pure
//!   [`StateMachine`](crate::StateMachine). `apply` feeds each committed
//!   [`ReplicatedOp`]'s embedded facts into the pure core deterministically
//!   (see the module docs' trust argument); snapshots serialize the ENTIRE
//!   pure-core state so a hydrated node behaves identically.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, LogState, RaftLogId, RaftLogReader, RaftSnapshotBuilder,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use tokio::sync::{Mutex, RwLock};

use crate::raft::{RaftNodeId, ReplicatedOp, ReplicatedOpResult, TypeConfig};
use crate::{KeyState, Op, PcrKey, StateMachine, StateMachineSnapshot};

// ---------------------------------------------------------------------------
// Log store: in-memory, vendored from openraft's `memstore` example.
// ---------------------------------------------------------------------------

/// In-memory [`RaftLogStorage`]. No persistence: the #16 design makes the
/// synchronizer's durability purely N-replica in memory (a restarting node
/// hydrates from peers; do not lose all three at once). Cloneable; the shared
/// inner is behind a `Mutex`.
#[derive(Clone, Debug, Default)]
pub struct LogStore {
    inner: Arc<Mutex<LogStoreInner>>,
}

#[derive(Debug, Default)]
struct LogStoreInner {
    last_purged_log_id: Option<LogId<RaftNodeId>>,
    log: BTreeMap<u64, Entry<TypeConfig>>,
    committed: Option<LogId<RaftNodeId>>,
    vote: Option<Vote<RaftNodeId>>,
}

impl LogStoreInner {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<RaftNodeId>> {
        Ok(self.log.range(range).map(|(_, v)| v.clone()).collect())
    }

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<RaftNodeId>> {
        let last = self.log.iter().next_back().map(|(_, e)| *e.get_log_id());
        let last_purged = self.last_purged_log_id;
        let last = match last {
            None => last_purged,
            Some(x) => Some(x),
        };
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<RaftNodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>>,
    {
        for entry in entries {
            self.log.insert(entry.get_log_id().index, entry);
        }
        // Flush-before-return: the in-memory write is immediately durable
        // (within the process), so signal completion synchronously.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(
        &mut self,
        log_id: LogId<RaftNodeId>,
    ) -> Result<(), StorageError<RaftNodeId>> {
        let keys: Vec<u64> = self.log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys {
            self.log.remove(&k);
        }
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<RaftNodeId>) -> Result<(), StorageError<RaftNodeId>> {
        assert!(self.last_purged_log_id.as_ref() <= Some(&log_id));
        self.last_purged_log_id = Some(log_id);
        let keys: Vec<u64> = self.log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys {
            self.log.remove(&k);
        }
        Ok(())
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<RaftNodeId>> {
        self.inner.lock().await.try_get_log_entries(range).await
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<RaftNodeId>> {
        self.inner.lock().await.get_log_state().await
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<RaftNodeId>>,
    ) -> Result<(), StorageError<RaftNodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<RaftNodeId>>, StorageError<RaftNodeId>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn save_vote(&mut self, vote: &Vote<RaftNodeId>) -> Result<(), StorageError<RaftNodeId>> {
        self.inner.lock().await.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<RaftNodeId>>, StorageError<RaftNodeId>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<RaftNodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        self.inner.lock().await.append(entries, callback).await
    }

    async fn truncate(
        &mut self,
        log_id: LogId<RaftNodeId>,
    ) -> Result<(), StorageError<RaftNodeId>> {
        self.inner.lock().await.truncate(log_id).await
    }

    async fn purge(&mut self, log_id: LogId<RaftNodeId>) -> Result<(), StorageError<RaftNodeId>> {
        self.inner.lock().await.purge(log_id).await
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}

// ---------------------------------------------------------------------------
// State machine store: wraps the pure StateMachine.
// ---------------------------------------------------------------------------

/// A stored snapshot blob plus its metadata.
#[derive(Debug, Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<RaftNodeId, BasicNode>,
    /// CBOR-encoded [`StateMachineSnapshot`].
    data: Vec<u8>,
}

/// The applied bookkeeping openraft needs alongside the pure core.
#[derive(Debug, Default)]
struct AppliedState {
    last_applied_log: Option<LogId<RaftNodeId>>,
    last_membership: StoredMembership<RaftNodeId, BasicNode>,
}

/// [`RaftStateMachine`] wrapping the pure [`StateMachine`].
///
/// Each committed [`ReplicatedOp`] is replayed into the pure core in the fixed
/// order documented on [`crate::raft`] (observe the embedded facts, then
/// `apply`). Because every replica applies the identical committed log in the
/// identical order, all three converge to the identical view, which is exactly
/// the TLA+ `NodeViewConsistent` invariant.
#[derive(Debug, Default)]
pub struct StateMachineStore {
    /// The pure synchronizer state machine plus openraft's applied bookkeeping.
    state: RwLock<(StateMachine, AppliedState)>,
    snapshot_idx: AtomicU64,
    current_snapshot: RwLock<Option<StoredSnapshot>>,
}

impl StateMachineStore {
    /// Leader-local (NOT linearized) lookup of `key`'s current state. The
    /// serving read path uses [`RaftHandle::linearizable_get`](crate::raft::RaftHandle::linearizable_get);
    /// this is for tests / the NodeViewConsistent harness comparing views.
    pub async fn get(&self, key: &PcrKey) -> Option<KeyState> {
        self.state.read().await.0.get(key).copied()
    }

    /// Snapshot of the head projection `(key -> KeyState)` for every
    /// currently-registered key. Used by the NodeViewConsistent harness.
    pub async fn head_view(&self) -> BTreeMap<PcrKey, KeyState> {
        let sm = &self.state.read().await.0;
        sm.head_keys().map(|k| (*k, *sm.get(k).unwrap())).collect()
    }

    /// The set of retired keys. Used by the NodeViewConsistent harness.
    pub async fn retired_view(&self) -> std::collections::BTreeSet<PcrKey> {
        self.state.read().await.0.retired_keys().copied().collect()
    }

    /// Apply one committed [`ReplicatedOp`] to the pure core, recording the
    /// embedded facts first. Returns the deterministic result. Shared by
    /// `apply` (kept out of the trait method so the locking stays tight).
    fn apply_one(sm: &mut StateMachine, op: &ReplicatedOp) -> ReplicatedOpResult {
        let result = match op {
            ReplicatedOp::Register {
                key,
                commitment,
                control_pubkey,
            } => {
                sm.observe_attestation(*key, *control_pubkey);
                sm.apply(Op::Register {
                    key: *key,
                    commitment: *commitment,
                })
            }
            ReplicatedOp::Pin { key, commitment } => sm.apply(Op::Pin {
                key: *key,
                commitment: *commitment,
            }),
            ReplicatedOp::Transition {
                old_key,
                new_key,
                new_control_pubkey,
            } => {
                // The new key's attestation was observed by the leader from the
                // submitting session; record it so the pure core's
                // NewKeyNotAttested check passes. The old key's attestation is
                // already present from its earlier Register entry. Then record
                // the (verified) transition authorization and apply.
                sm.observe_attestation(*new_key, *new_control_pubkey);
                sm.observe_transition(*old_key, *new_key);
                sm.apply(Op::Transition {
                    old_key: *old_key,
                    new_key: *new_key,
                })
            }
        };
        match result {
            Ok(state) => ReplicatedOpResult::Applied(state),
            Err(e) => ReplicatedOpResult::Rejected(e),
        }
    }
}

impl RaftSnapshotBuilder<TypeConfig> for Arc<StateMachineStore> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<RaftNodeId>> {
        let (data, last_applied, last_membership) = {
            let guard = self.state.read().await;
            let snap = guard.0.snapshot();
            let mut buf = Vec::new();
            ciborium::into_writer(&snap, &mut buf)
                .map_err(|e| StorageIOError::read_state_machine(&e))?;
            (
                buf,
                guard.1.last_applied_log,
                guard.1.last_membership.clone(),
            )
        };

        let snapshot_idx = self.snapshot_idx.fetch_add(1, Ordering::Relaxed) + 1;
        let snapshot_id = match last_applied {
            Some(last) => format!("{}-{}-{}", last.leader_id, last.index, snapshot_idx),
            None => format!("--{snapshot_idx}"),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        *self.current_snapshot.write().await = Some(StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        });
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for Arc<StateMachineStore> {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<RaftNodeId>>,
            StoredMembership<RaftNodeId, BasicNode>,
        ),
        StorageError<RaftNodeId>,
    > {
        let guard = self.state.read().await;
        Ok((guard.1.last_applied_log, guard.1.last_membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<ReplicatedOpResult>, StorageError<RaftNodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        let mut guard = self.state.write().await;
        let (sm, applied) = &mut *guard;
        let mut results = Vec::new();
        for entry in entries {
            applied.last_applied_log = Some(entry.log_id);
            match &entry.payload {
                // Blank (no-op, e.g. leader's initial entry) and Membership
                // entries do not touch the freshness state machine; they still
                // return a result so openraft's per-entry response vector lines
                // up.
                EntryPayload::Blank => results.push(ReplicatedOpResult::Applied(KeyState {
                    commitment: crate::Commitment([0u8; 32]),
                    version: crate::Version(0),
                    control_pubkey: [0u8; crate::CONTROL_PUBKEY_LEN],
                })),
                EntryPayload::Normal(op) => results.push(StateMachineStore::apply_one(sm, op)),
                EntryPayload::Membership(mem) => {
                    applied.last_membership =
                        StoredMembership::new(Some(entry.log_id), mem.clone());
                    results.push(ReplicatedOpResult::Applied(KeyState {
                        commitment: crate::Commitment([0u8; 32]),
                        version: crate::Version(0),
                        control_pubkey: [0u8; crate::CONTROL_PUBKEY_LEN],
                    }));
                }
            }
        }
        Ok(results)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<RaftNodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<RaftNodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<RaftNodeId>> {
        let data = snapshot.into_inner();
        let restored: StateMachineSnapshot = ciborium::from_reader(data.as_slice())
            .map_err(|e| StorageIOError::read_snapshot(Some(meta.signature()), &e))?;
        {
            let mut guard = self.state.write().await;
            guard.0.restore_from_snapshot(restored);
            guard.1.last_applied_log = meta.last_log_id;
            guard.1.last_membership = meta.last_membership.clone();
        }
        *self.current_snapshot.write().await = Some(StoredSnapshot {
            meta: meta.clone(),
            data,
        });
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<RaftNodeId>> {
        Ok(self
            .current_snapshot
            .read()
            .await
            .as_ref()
            .map(|s| Snapshot {
                meta: s.meta.clone(),
                snapshot: Box::new(Cursor::new(s.data.clone())),
            }))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }
}

/// serde adapter for the 65-byte SEC1 control pubkey carried inside
/// [`ReplicatedOp`] variants (serde's derive only covers fixed arrays up to
/// length 32, same constraint `KeyState` works around).
pub mod control_pubkey_bytes {
    use crate::CONTROL_PUBKEY_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize the pubkey as a CBOR byte string.
    pub fn serialize<S: Serializer>(
        v: &[u8; CONTROL_PUBKEY_LEN],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(ser)
    }

    /// Deserialize a length-checked 65-byte pubkey from a CBOR byte string.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<[u8; CONTROL_PUBKEY_LEN], D::Error> {
        let buf = serde_bytes::ByteBuf::deserialize(de)?;
        buf.as_slice().try_into().map_err(|_| {
            serde::de::Error::invalid_length(buf.len(), &"65-byte SEC1 P-256 control pubkey")
        })
    }
}
