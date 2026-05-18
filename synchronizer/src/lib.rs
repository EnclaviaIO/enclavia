#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Synchronizer protocol state machine.
//!
//! Pure, deterministic Rust translation of the TLA+ specification at
//! `synchronizer-spec/Synchronizer.tla` (see the sibling repository). Given
//! the same sequence of inputs (attestation observations, transition
//! signature observations, and operations), this module produces the same
//! `(state, retired)` projection that the spec's global committed log folds
//! to.
//!
//! Scope is deliberately narrow:
//!
//! * No networking, no CBOR/Noise wire format, no Raft.
//! * No signature verification — the caller is responsible for verifying
//!   Nitro attestation documents and Ed25519 transition signatures and then
//!   calling [`StateMachine::observe_attestation`] /
//!   [`StateMachine::observe_transition_sig`].
//!
//! See issue [#16](https://github.com/EnclaviaIO/enclavia-crates/issues/16)
//! for the broader design.

#[cfg(feature = "wire")]
pub mod wire;

#[cfg(feature = "node")]
pub mod node;
#[cfg(feature = "node")]
pub use node::Node;

#[cfg(feature = "node")]
pub mod listener;

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SHA-256 hash of `PCR0 || PCR1 || PCR2` from a Nitro attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PcrKey(pub [u8; 32]);

/// Storage commitment — opaque hash a customer enclave pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment(pub [u8; 32]);

/// Per-key version counter. Strictly monotonic per [`PcrKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(pub u64);

/// Operations the synchronizer accepts and commits to its log.
///
/// Mirrors the `Operation` set in the TLA+ spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Op {
    /// First-time registration of a hardware-attested PCR key.
    Register {
        /// Attested PCR key being registered.
        key: PcrKey,
        /// Initial storage commitment (version 0).
        commitment: Commitment,
    },
    /// Pin a fresh storage commitment under an already-registered key.
    Pin {
        /// Currently-registered key whose commitment is being updated.
        key: PcrKey,
        /// New commitment; bumps the per-key version by one.
        commitment: Commitment,
    },
    /// Authorized upgrade: retire `old_key` and adopt `new_key`, carrying
    /// the existing commitment forward.
    Transition {
        /// Current key being retired.
        old_key: PcrKey,
        /// Successor key adopting the retired key's state.
        new_key: PcrKey,
    },
}

/// Per-key state held in [`StateMachine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyState {
    /// Latest pinned commitment for this key.
    pub commitment: Commitment,
    /// Per-key version. `0` immediately after `Register`; `+1` on each
    /// `Pin`; carried unchanged across `Transition`.
    pub version: Version,
    /// Raw 32-byte Ed25519 verifying key that authorizes `Transition`
    /// from this key. Frozen at the moment the key was committed
    /// (`Register` or `Transition`-target): the caller takes whatever
    /// pubkey was in `attested` at that point and copies it here, so
    /// later re-attestations from the same `PcrKey` cannot rotate the
    /// authorizing pubkey out from under a pending Transition.
    pub control_pubkey: [u8; 32],
}

/// Reasons [`StateMachine::apply`] may reject an operation.
///
/// These are the negations of the `ValidOp` clauses in the TLA+ spec, named
/// individually so callers can surface meaningful errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// `Register` or `Transition` named a key without a recorded
    /// hardware attestation.
    #[error("PCR key has not produced a hardware attestation")]
    NotAttested,
    /// `Register` named a key that is already current (live in the
    /// committed state).
    #[error("PCR key is already registered")]
    AlreadyRegistered,
    /// Operation referenced a key that has been retired by a prior
    /// `Transition`. Retired keys are permanently dead.
    #[error("PCR key has been retired")]
    KeyRetired,
    /// `Pin` or `Transition` named an `old_key` that is not currently
    /// registered (never registered, or already retired).
    #[error("PCR key is not currently registered")]
    KeyNotCurrent,
    /// `Transition` named a `new_key` that is already registered.
    #[error("transition target key is already registered")]
    NewKeyAlreadyExists,
    /// `Transition` named a `new_key` that has not produced a hardware
    /// attestation.
    #[error("transition target key has not produced an attestation")]
    NewKeyNotAttested,
    /// `Transition` was not preceded by an observation of an Ed25519
    /// signature from `old_key` authorizing `new_key`.
    #[error("no transition signature observed for (old_key, new_key)")]
    NoTransitionSignature,
    /// `Transition` named the same key for `old_key` and `new_key`.
    #[error("transition old_key equals new_key")]
    OldKeyEqualsNew,
}

/// Synchronizer state machine.
///
/// Maintains the projection of the committed log onto a `(PcrKey ->
/// KeyState)` map plus the retirement set. Inputs:
///
/// 1. [`observe_attestation`](Self::observe_attestation) — record that a
///    PCR key produced a valid Nitro attestation.
/// 2. [`observe_transition_sig`](Self::observe_transition_sig) — record
///    that the enclave currently running under `old_key` signed an
///    authorization for `new_key`.
/// 3. [`apply`](Self::apply) — try to apply an operation. Either commits
///    the operation (mutating internal state) or returns a
///    [`ValidationError`].
///
/// All inputs are monotonically additive. Once a key is attested it stays
/// attested; signatures and retirements are forever. The TLA+ spec has the
/// same shape: `attestedKeys` and `transitionSigs` only grow, and
/// `RetirementIsFinal` is one of the verified invariants.
#[derive(Clone, Debug, Default)]
pub struct StateMachine {
    state: BTreeMap<PcrKey, KeyState>,
    /// Keys that have produced a valid hardware attestation in this
    /// run, along with the Ed25519 control pubkey their attestation
    /// document carried. `Register` and `Transition` consume the
    /// recorded pubkey by copying it into `KeyState.control_pubkey`,
    /// freezing it. Late re-attestations are allowed to overwrite this
    /// map (e.g. the same enclave re-handshakes), but they cannot
    /// retroactively change an already-committed `KeyState.control_pubkey`.
    attested: BTreeMap<PcrKey, [u8; 32]>,
    transition_sigs: BTreeSet<(PcrKey, PcrKey)>,
    retired: BTreeSet<PcrKey>,
}

impl StateMachine {
    /// Create a fresh synchronizer state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `key` has produced a valid Nitro attestation and
    /// announced `control_pubkey` as its Ed25519 verifying key.
    ///
    /// Caller is responsible for verifying the attestation document
    /// (PCRs, signature chain in production, nonce binding to the
    /// Noise handshake hash) and for confirming the pubkey lives in
    /// the doc's `user_data`. This method only updates the internal
    /// `attested` map. Repeat calls overwrite the recorded pubkey for
    /// `key` — but they have no effect on an already-committed
    /// `KeyState.control_pubkey`, which was frozen at `Register` /
    /// `Transition` time.
    pub fn observe_attestation(&mut self, key: PcrKey, control_pubkey: [u8; 32]) {
        self.attested.insert(key, control_pubkey);
    }

    /// Record an Ed25519 control-key signature from the enclave running
    /// under `old_key` authorizing `new_key` as its successor.
    ///
    /// Caller is responsible for verifying the signature against
    /// `old_key`'s control public key. Repeat calls are idempotent.
    pub fn observe_transition_sig(&mut self, old_key: PcrKey, new_key: PcrKey) {
        self.transition_sigs.insert((old_key, new_key));
    }

    /// Apply `op` to the state machine.
    ///
    /// Mirrors the `ValidOp` predicate and `ApplyOp` operator in the TLA+
    /// spec. On success, returns the post-state for the key the operation
    /// touches (the `new_key` for `Transition`).
    pub fn apply(&mut self, op: Op) -> Result<KeyState, ValidationError> {
        match op {
            Op::Register { key, commitment } => self.apply_register(key, commitment),
            Op::Pin { key, commitment } => self.apply_pin(key, commitment),
            Op::Transition { old_key, new_key } => self.apply_transition(old_key, new_key),
        }
    }

    fn apply_register(
        &mut self,
        key: PcrKey,
        commitment: Commitment,
    ) -> Result<KeyState, ValidationError> {
        let control_pubkey = match self.attested.get(&key) {
            Some(pk) => *pk,
            None => return Err(ValidationError::NotAttested),
        };
        if self.state.contains_key(&key) {
            return Err(ValidationError::AlreadyRegistered);
        }
        if self.retired.contains(&key) {
            return Err(ValidationError::KeyRetired);
        }
        let entry = KeyState {
            commitment,
            version: Version(0),
            control_pubkey,
        };
        self.state.insert(key, entry);
        Ok(entry)
    }

    fn apply_pin(
        &mut self,
        key: PcrKey,
        commitment: Commitment,
    ) -> Result<KeyState, ValidationError> {
        let entry = self
            .state
            .get_mut(&key)
            .ok_or(ValidationError::KeyNotCurrent)?;
        entry.commitment = commitment;
        entry.version = Version(entry.version.0 + 1);
        Ok(*entry)
    }

    fn apply_transition(
        &mut self,
        old_key: PcrKey,
        new_key: PcrKey,
    ) -> Result<KeyState, ValidationError> {
        if old_key == new_key {
            return Err(ValidationError::OldKeyEqualsNew);
        }
        if !self.state.contains_key(&old_key) {
            return Err(ValidationError::KeyNotCurrent);
        }
        if self.state.contains_key(&new_key) {
            return Err(ValidationError::NewKeyAlreadyExists);
        }
        if self.retired.contains(&new_key) {
            return Err(ValidationError::KeyRetired);
        }
        let new_pubkey = match self.attested.get(&new_key) {
            Some(pk) => *pk,
            None => return Err(ValidationError::NewKeyNotAttested),
        };
        if !self.transition_sigs.contains(&(old_key, new_key)) {
            return Err(ValidationError::NoTransitionSignature);
        }
        let mut carried = self.state.remove(&old_key).expect("checked above");
        // Rotate the registered pubkey to `new_key`'s — future
        // Transition requests from `new_key` will be verified against
        // it, not against the old key's pubkey.
        carried.control_pubkey = new_pubkey;
        self.retired.insert(old_key);
        self.state.insert(new_key, carried);
        Ok(carried)
    }

    /// Lookup the current state of `key`. Returns `None` if `key` is not
    /// currently registered (never registered, or retired).
    pub fn get(&self, key: &PcrKey) -> Option<&KeyState> {
        self.state.get(key)
    }

    /// Iterator over all currently-registered (non-retired) keys.
    pub fn head_keys(&self) -> impl Iterator<Item = &PcrKey> {
        self.state.keys()
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

    /// Synthetic Ed25519 pubkey for tests that just need *some* pubkey
    /// in `observe_attestation`. The pure state machine doesn't verify
    /// the bytes — it only stores them — so any 32-byte seed works.
    fn pk(b: u8) -> [u8; 32] {
        [b.wrapping_add(0x80); 32]
    }

    /// Spec invariant: `RegisterAuthenticity` — every committed Register
    /// names a hardware-attested key.
    #[test]
    fn register_authenticity_rejects_unattested_key() {
        let mut sm = StateMachine::new();
        let err = sm
            .apply(Op::Register {
                key: k(1),
                commitment: c(0xaa),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::NotAttested);
        assert!(sm.get(&k(1)).is_none());
    }

    #[test]
    fn register_succeeds_for_attested_key() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        let state = sm
            .apply(Op::Register {
                key: k(1),
                commitment: c(0xaa),
            })
            .unwrap();
        assert_eq!(state.version, Version(0));
        assert_eq!(state.commitment, c(0xaa));
    }

    #[test]
    fn register_rejects_already_registered_key() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        let err = sm
            .apply(Op::Register {
                key: k(1),
                commitment: c(0xbb),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::AlreadyRegistered);
        assert_eq!(sm.get(&k(1)).unwrap().commitment, c(0xaa));
    }

    /// Spec invariant: `TransitionAuthenticity` — every committed
    /// Transition has a valid signature, and the new key is itself
    /// hardware-attested.
    #[test]
    fn transition_authenticity_requires_signature() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::NoTransitionSignature);
    }

    #[test]
    fn transition_authenticity_requires_new_key_attested() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::NewKeyNotAttested);
    }

    #[test]
    fn transition_succeeds_with_sig_and_attestation() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.apply(Op::Pin {
            key: k(1),
            commitment: c(0xbb),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        let state = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap();
        assert_eq!(state.commitment, c(0xbb));
        assert_eq!(state.version, Version(1));
        assert!(sm.get(&k(1)).is_none());
        assert_eq!(sm.get(&k(2)).unwrap().commitment, c(0xbb));
    }

    #[test]
    fn transition_rejects_old_equals_new() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(1));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(1),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::OldKeyEqualsNew);
    }

    #[test]
    fn transition_rejects_unregistered_old_key() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(2), pk(2));
        sm.observe_transition_sig(k(1), k(2));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyNotCurrent);
    }

    #[test]
    fn transition_rejects_already_registered_new_key() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.apply(Op::Register {
            key: k(2),
            commitment: c(0xbb),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::NewKeyAlreadyExists);
    }

    /// Spec invariant: `NoPhantomKey` — every key currently in
    /// HeadState was attested at some point.
    #[test]
    fn no_phantom_key_after_arbitrary_sequence() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.observe_attestation(k(3), pk(3));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.apply(Op::Register {
            key: k(2),
            commitment: c(0xbb),
        })
        .unwrap();
        sm.observe_transition_sig(k(2), k(3));
        sm.apply(Op::Transition {
            old_key: k(2),
            new_key: k(3),
        })
        .unwrap();
        for key in sm.head_keys() {
            assert!(sm.attested.contains_key(key), "{key:?} live but never attested");
        }
    }

    /// Spec invariant: `PinTraceability` — every committed Pin has a
    /// prior, still-live Register/Transition for the same key.
    #[test]
    fn pin_traceability_rejects_pin_without_register() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        let err = sm
            .apply(Op::Pin {
                key: k(1),
                commitment: c(0xaa),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyNotCurrent);
    }

    #[test]
    fn pin_succeeds_after_register_and_bumps_version() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        let s1 = sm
            .apply(Op::Pin {
                key: k(1),
                commitment: c(0xbb),
            })
            .unwrap();
        assert_eq!(s1.version, Version(1));
        assert_eq!(s1.commitment, c(0xbb));
        let s2 = sm
            .apply(Op::Pin {
                key: k(1),
                commitment: c(0xcc),
            })
            .unwrap();
        assert_eq!(s2.version, Version(2));
        assert_eq!(s2.commitment, c(0xcc));
    }

    /// Spec invariant: `RetirementIsFinal` — once a key is retired by a
    /// Transition, no further op may reference it.
    #[test]
    fn retirement_is_final_for_register() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        sm.apply(Op::Transition {
            old_key: k(1),
            new_key: k(2),
        })
        .unwrap();
        let err = sm
            .apply(Op::Register {
                key: k(1),
                commitment: c(0xff),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyRetired);
    }

    #[test]
    fn retirement_is_final_for_pin() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        sm.apply(Op::Transition {
            old_key: k(1),
            new_key: k(2),
        })
        .unwrap();
        let err = sm
            .apply(Op::Pin {
                key: k(1),
                commitment: c(0xff),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyNotCurrent);
    }

    #[test]
    fn retirement_is_final_for_transition_old_key() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.observe_attestation(k(3), pk(3));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(2));
        sm.apply(Op::Transition {
            old_key: k(1),
            new_key: k(2),
        })
        .unwrap();
        sm.observe_transition_sig(k(1), k(3));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(3),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyNotCurrent);
    }

    /// Spec property: `MonotonicHeadVersion` — for any key that remains
    /// in HeadState across a step, its version cannot decrease.
    #[test]
    fn monotonic_head_version_across_pins() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        let mut prev = sm.get(&k(1)).unwrap().version;
        for i in 0u8..16 {
            sm.apply(Op::Pin {
                key: k(1),
                commitment: c(i),
            })
            .unwrap();
            let now = sm.get(&k(1)).unwrap().version;
            assert!(now >= prev, "version went backwards: {prev:?} -> {now:?}");
            prev = now;
        }
    }

    #[test]
    fn transition_carries_version_and_commitment_unchanged() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.observe_attestation(k(2), pk(2));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        sm.apply(Op::Pin {
            key: k(1),
            commitment: c(0xbb),
        })
        .unwrap();
        sm.apply(Op::Pin {
            key: k(1),
            commitment: c(0xcc),
        })
        .unwrap();
        let pre = *sm.get(&k(1)).unwrap();
        sm.observe_transition_sig(k(1), k(2));
        sm.apply(Op::Transition {
            old_key: k(1),
            new_key: k(2),
        })
        .unwrap();
        let post = *sm.get(&k(2)).unwrap();
        // Commitment + version carry across the transition; control
        // pubkey rotates to the successor's so subsequent Transitions
        // from `new_key` are authorized by `new_key`'s own keypair.
        assert_eq!(post.commitment, pre.commitment);
        assert_eq!(post.version, pre.version);
        assert_eq!(post.control_pubkey, pk(2));
        assert_ne!(post.control_pubkey, pre.control_pubkey);
    }

    /// `KeyState.control_pubkey` is frozen at Register time — a later
    /// re-attestation of the same `PcrKey` with a different pubkey
    /// does NOT rotate the registered authorizer. This is what makes
    /// "control pubkey substitution" hard: an attacker who can steer
    /// the `attested` map after first registration cannot retroactively
    /// gain authority to sign a Transition.
    #[test]
    fn register_freezes_control_pubkey() {
        let mut sm = StateMachine::new();
        sm.observe_attestation(k(1), pk(1));
        sm.apply(Op::Register {
            key: k(1),
            commitment: c(0xaa),
        })
        .unwrap();
        // Re-attest with a different pubkey (simulates the same
        // PcrKey hash being observed in a fresh session that
        // announced a different pubkey).
        let other_pubkey = [0x55u8; 32];
        sm.observe_attestation(k(1), other_pubkey);
        let state = sm.get(&k(1)).unwrap();
        assert_eq!(state.control_pubkey, pk(1));
        assert_ne!(state.control_pubkey, other_pubkey);
    }
}
