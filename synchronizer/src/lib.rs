#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Synchronizer protocol state machine.
//!
//! Pure, deterministic Rust translation of the TLA+ specification at
//! `synchronizer-spec/Synchronizer.tla` (see the sibling repository). Given
//! the same sequence of inputs (attestation observations, transition
//! authorization observations, and operations), this module produces the same
//! `(state, retired)` projection that the spec's global committed log folds
//! to.
//!
//! Scope is deliberately narrow:
//!
//! * No networking, no CBOR/Noise wire format, no Raft.
//! * No signature verification, the caller is responsible for verifying
//!   Nitro attestation documents and the #47 upgrade chain link that
//!   authorizes a transition, then calling
//!   [`StateMachine::observe_attestation`] /
//!   [`StateMachine::observe_transition`].
//!
//! ## Control key is ECDSA P-256, not Ed25519
//!
//! Earlier revisions of this crate (and issue #16's original body)
//! described an Ed25519 control key. That is stale: the protocol swapped
//! to ECDSA P-256 in enclavia#21, and the per-enclave control key carried
//! in `AttestationDoc::user_data` is a 65-byte uncompressed SEC1 P-256
//! verifying key (see [`enclavia_protocol::attestation::CONTROL_PUBKEY_LEN`]
//! and `AttestedIdentity::control_pubkey`). Signatures over chain payloads
//! are 64-byte raw `r || s` P-256. This module stores the 65-byte pubkey
//! verbatim; verification of the raw r||s signature against it lives in
//! [`wire::verify_transition_link`] (a pure helper) and is wired into the
//! node/listener layer, never into this pure core.
//!
//! See issue [#16](https://github.com/EnclaviaIO/enclavia-crates/issues/16)
//! for the broader design, and the 2026-06-10 design pass that supersedes
//! the transition-credential and key-algorithm parts of that body.

#[cfg(feature = "wire")]
pub mod wire;

#[cfg(feature = "node")]
pub mod node;
#[cfg(feature = "node")]
pub use node::Node;

#[cfg(feature = "node")]
pub mod listener;

#[cfg(feature = "mesh")]
pub mod mesh;

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Length of the control public key this module stores per registered
/// key: a 65-byte uncompressed SEC1 ECDSA P-256 verifying key
/// (`0x04 || X(32) || Y(32)`). MUST equal
/// `enclavia_protocol::attestation::CONTROL_PUBKEY_LEN`; the pure core
/// cannot depend on that crate (it is only pulled in by the `node`
/// feature), so the value is repeated here and pinned by a `node`-gated
/// assertion in [`wire`].
pub const CONTROL_PUBKEY_LEN: usize = 65;

/// SHA-256 hash of `PCR0 || PCR1 || PCR2` from a Nitro attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PcrKey(pub [u8; 32]);

/// Storage commitment, opaque hash a customer enclave pins.
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
    ///
    /// The credential that authorizes this op is a #47 upgrade chain link
    /// whose `UpgradePayload` binds `from_pcrs -> to_pcrs`, signed under
    /// the OLD key's control private key and carrying the new enclave's
    /// hardware attestation. The pure state machine does NOT see or verify
    /// that link: the caller verifies it with
    /// [`wire::verify_transition_link`], records the result via
    /// [`StateMachine::observe_transition`], and only then applies this op.
    /// The op itself names only the derived `(old_key, new_key)` pair so
    /// the replicated log stays compact and verification-free on replay.
    Transition {
        /// Current key being retired. Equals
        /// `sha256(payload.from_pcrs.PCR0||PCR1||PCR2)`.
        old_key: PcrKey,
        /// Successor key adopting the retired key's state. Equals
        /// `sha256(payload.to_pcrs.PCR0||PCR1||PCR2)`.
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
    /// 65-byte uncompressed SEC1 ECDSA P-256 verifying key
    /// (`0x04 || X || Y`) that authorizes `Transition` from this key.
    /// This is `AttestedIdentity::control_pubkey` (#21/#47), learned from
    /// the key's attestation at Register time. Frozen at the moment the
    /// key was committed (`Register` or `Transition`-target): the caller
    /// takes whatever pubkey was in `attested` at that point and copies it
    /// here, so later re-attestations from the same `PcrKey` cannot rotate
    /// the authorizing pubkey out from under a pending Transition.
    ///
    /// A transition link's `UpgradePayload` is signed under the OLD key's
    /// control private key; the node verifies the 64-byte raw r||s P-256
    /// signature against THIS frozen pubkey before applying the op.
    #[cfg_attr(feature = "serde", serde(with = "control_pubkey_serde"))]
    pub control_pubkey: [u8; CONTROL_PUBKEY_LEN],
}

/// serde adapter for the 65-byte `control_pubkey` field. `serde`'s
/// derive only covers fixed arrays up to length 32; the SEC1 P-256 key
/// is 65 bytes, so we (de)serialize it through a `[u8; CONTROL_PUBKEY_LEN]`
/// round-trip over a length-checked byte sequence. This keeps `KeyState`
/// CBOR-encodable for the future Raft snapshot / log path without pulling
/// in a big-array helper crate.
#[cfg(feature = "serde")]
mod control_pubkey_serde {
    use super::CONTROL_PUBKEY_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        v: &[u8; CONTROL_PUBKEY_LEN],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<[u8; CONTROL_PUBKEY_LEN], D::Error> {
        let buf = serde_bytes::ByteBuf::deserialize(de)?;
        buf.as_slice().try_into().map_err(|_| {
            serde::de::Error::invalid_length(buf.len(), &"65-byte SEC1 P-256 control pubkey")
        })
    }
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
    /// `Transition` was not preceded by an observation of a verified
    /// upgrade chain link from `old_key` authorizing `new_key`.
    #[error("no verified transition authorization observed for (old_key, new_key)")]
    NoTransitionAuthorization,
    /// `Transition` named the same key for `old_key` and `new_key`.
    #[error("transition old_key equals new_key")]
    OldKeyEqualsNew,
}

/// Synchronizer state machine.
///
/// Maintains the projection of the committed log onto a `(PcrKey ->
/// KeyState)` map plus the retirement set. Inputs:
///
/// 1. [`observe_attestation`](Self::observe_attestation), record that a
///    PCR key produced a valid Nitro attestation, carrying its 65-byte
///    SEC1 P-256 control pubkey.
/// 2. [`observe_transition`](Self::observe_transition), record that the
///    caller has verified an upgrade chain link from `old_key`
///    authorizing `new_key`.
/// 3. [`apply`](Self::apply), try to apply an operation. Either commits
///    the operation (mutating internal state) or returns a
///    [`ValidationError`].
///
/// All inputs are monotonically additive. Once a key is attested it stays
/// attested; authorizations and retirements are forever. The TLA+ spec has
/// the same shape: `attestedKeys` and the transition-authorization set only
/// grow, and `RetirementIsFinal` is one of the verified invariants.
#[derive(Clone, Debug, Default)]
pub struct StateMachine {
    state: BTreeMap<PcrKey, KeyState>,
    /// Keys that have produced a valid hardware attestation in this
    /// run, along with the 65-byte SEC1 P-256 control pubkey their
    /// attestation document carried. `Register` and `Transition` consume
    /// the recorded pubkey by copying it into `KeyState.control_pubkey`,
    /// freezing it. Late re-attestations are allowed to overwrite this
    /// map (e.g. the same enclave re-handshakes), but they cannot
    /// retroactively change an already-committed `KeyState.control_pubkey`.
    attested: BTreeMap<PcrKey, [u8; CONTROL_PUBKEY_LEN]>,
    /// `(old_key, new_key)` pairs for which the caller has verified an
    /// upgrade chain link authorizing the transition. Append-only.
    transition_authorizations: BTreeSet<(PcrKey, PcrKey)>,
    retired: BTreeSet<PcrKey>,
}

impl StateMachine {
    /// Create a fresh synchronizer state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `key` has produced a valid Nitro attestation and
    /// announced `control_pubkey` as its 65-byte SEC1 P-256 verifying
    /// key (`AttestedIdentity::control_pubkey`).
    ///
    /// Caller is responsible for verifying the attestation document
    /// (PCRs, signature chain in production, nonce binding to the
    /// Noise handshake hash) and for confirming the pubkey lives in
    /// the doc's `user_data`. This method only updates the internal
    /// `attested` map. Repeat calls overwrite the recorded pubkey for
    /// `key`, but they have no effect on an already-committed
    /// `KeyState.control_pubkey`, which was frozen at `Register` /
    /// `Transition` time.
    pub fn observe_attestation(&mut self, key: PcrKey, control_pubkey: [u8; CONTROL_PUBKEY_LEN]) {
        self.attested.insert(key, control_pubkey);
    }

    /// Record that the caller has verified an upgrade chain link from the
    /// enclave running under `old_key` authorizing `new_key` as its
    /// successor.
    ///
    /// Caller is responsible for the full verification contract before
    /// calling this (see [`wire::verify_transition_link`]): the link's
    /// P-256 control signature verifies against `old_key`'s registered
    /// pubkey, the chain attestation validates with `user_data ==
    /// sha256(payload)`, and the payload's `from_pcrs`/`to_pcrs` hash to
    /// `old_key`/`new_key`. Repeat calls are idempotent.
    pub fn observe_transition(&mut self, old_key: PcrKey, new_key: PcrKey) {
        self.transition_authorizations.insert((old_key, new_key));
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
        if !self.transition_authorizations.contains(&(old_key, new_key)) {
            return Err(ValidationError::NoTransitionAuthorization);
        }
        let mut carried = self.state.remove(&old_key).expect("checked above");
        // Rotate the registered pubkey to `new_key`'s, future
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

    /// Iterator over all retired keys, in sorted order. Retirement is
    /// final, so this set only grows. Exposed for the future replicated
    /// layer's snapshot / state-equality checks (e.g. the TLA+
    /// `NodeViewConsistent` harness compares this projection across
    /// nodes).
    pub fn retired_keys(&self) -> impl Iterator<Item = &PcrKey> {
        self.retired.iter()
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

    /// Synthetic 65-byte SEC1-shaped pubkey for tests that just need
    /// *some* control pubkey in `observe_attestation`. The pure state
    /// machine doesn't verify the bytes, it only stores them, so any
    /// 65-byte seed works (the `0x04` prefix mirrors a real uncompressed
    /// SEC1 point, but is not load-bearing in the pure core).
    fn pk(b: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        let mut out = [b.wrapping_add(0x80); CONTROL_PUBKEY_LEN];
        out[0] = 0x04;
        out
    }

    /// Spec invariant: `RegisterAuthenticity`, every committed Register
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

    /// Spec invariant: `TransitionAuthenticity`, every committed
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
        assert_eq!(err, ValidationError::NoTransitionAuthorization);
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
        sm.observe_transition(k(1), k(2));
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
        sm.observe_transition(k(1), k(2));
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
        sm.observe_transition(k(1), k(1));
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
        sm.observe_transition(k(1), k(2));
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
        sm.observe_transition(k(1), k(2));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(2),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::NewKeyAlreadyExists);
    }

    /// Spec invariant: `NoPhantomKey`, every key currently in
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
        sm.observe_transition(k(2), k(3));
        sm.apply(Op::Transition {
            old_key: k(2),
            new_key: k(3),
        })
        .unwrap();
        for key in sm.head_keys() {
            assert!(
                sm.attested.contains_key(key),
                "{key:?} live but never attested"
            );
        }
    }

    /// Spec invariant: `PinTraceability`, every committed Pin has a
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

    /// Spec invariant: `RetirementIsFinal`, once a key is retired by a
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
        sm.observe_transition(k(1), k(2));
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
        sm.observe_transition(k(1), k(2));
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
        sm.observe_transition(k(1), k(2));
        sm.apply(Op::Transition {
            old_key: k(1),
            new_key: k(2),
        })
        .unwrap();
        sm.observe_transition(k(1), k(3));
        let err = sm
            .apply(Op::Transition {
                old_key: k(1),
                new_key: k(3),
            })
            .unwrap_err();
        assert_eq!(err, ValidationError::KeyNotCurrent);
    }

    /// Spec property: `MonotonicHeadVersion`, for any key that remains
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
        sm.observe_transition(k(1), k(2));
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

    /// `KeyState.control_pubkey` is frozen at Register time, a later
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
        let mut other_pubkey = [0x55u8; CONTROL_PUBKEY_LEN];
        other_pubkey[0] = 0x04;
        sm.observe_attestation(k(1), other_pubkey);
        let state = sm.get(&k(1)).unwrap();
        assert_eq!(state.control_pubkey, pk(1));
        assert_ne!(state.control_pubkey, other_pubkey);
    }

    /// Determinism contract: replaying the SAME ordered sequence of
    /// observations + ops on two fresh state machines yields the SAME
    /// `(state, retired)` projection. This is the property the Raft layer
    /// relies on, every node applies the committed log in the same order
    /// and must converge to the same view. Exercises the full new op set
    /// {Register, Pin, Transition} with the post-redesign shapes.
    #[test]
    fn replaying_same_sequence_yields_same_projection() {
        // Observations the caller would record after verifying
        // attestations / transition links.
        let observations: &[(&str, PcrKey, PcrKey, [u8; CONTROL_PUBKEY_LEN])] = &[
            ("attest", k(1), k(1), pk(1)),
            ("attest", k(2), k(2), pk(2)),
            ("attest", k(3), k(3), pk(3)),
            // (old, new) transition authorizations.
            ("transition", k(2), k(3), pk(0)),
        ];
        let ops = [
            Op::Register {
                key: k(1),
                commitment: c(0xaa),
            },
            Op::Pin {
                key: k(1),
                commitment: c(0xab),
            },
            Op::Register {
                key: k(2),
                commitment: c(0xbb),
            },
            Op::Pin {
                key: k(2),
                commitment: c(0xbc),
            },
            Op::Transition {
                old_key: k(2),
                new_key: k(3),
            },
            Op::Pin {
                key: k(3),
                commitment: c(0xcc),
            },
        ];

        let run = || {
            let mut sm = StateMachine::new();
            for (kind, a, b, pubkey) in observations {
                match *kind {
                    "attest" => sm.observe_attestation(*a, *pubkey),
                    "transition" => sm.observe_transition(*a, *b),
                    other => panic!("unknown observation kind {other}"),
                }
            }
            let results: Vec<_> = ops.iter().map(|op| sm.apply(*op)).collect();
            // Project to the comparable (state, retired) view.
            let state: BTreeMap<PcrKey, KeyState> =
                sm.head_keys().map(|k| (*k, *sm.get(k).unwrap())).collect();
            let retired: BTreeSet<PcrKey> = sm.retired_keys().copied().collect();
            (results, state, retired)
        };

        let (results_a, state_a, retired_a) = run();
        let (results_b, state_b, retired_b) = run();

        assert_eq!(results_a, results_b, "per-op results diverged");
        assert_eq!(state_a, state_b, "head state diverged");
        assert_eq!(retired_a, retired_b, "retired set diverged");

        // Sanity on the actual projection the sequence produces: k(1)
        // pinned, k(2) retired in favour of k(3), k(3) carrying state.
        assert!(state_a.contains_key(&k(1)));
        assert!(!state_a.contains_key(&k(2)));
        assert!(state_a.contains_key(&k(3)));
        assert!(retired_a.contains(&k(2)));
        assert_eq!(state_a[&k(3)].commitment, c(0xcc));
    }
}
