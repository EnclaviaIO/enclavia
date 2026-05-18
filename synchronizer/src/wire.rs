//! Wire-format request/response types for the synchronizer RPC surface.
//!
//! CBOR-encoded, transport-agnostic. The synchronizer service binds these to
//! a vsock+Noise channel; the customer-side client encodes/decodes them with
//! `ciborium` over its existing Noise transport (the same one
//! `enclavia-server` already runs).
//!
//! Each request maps onto one [`crate::Op`] (with some shaping — `Pin`
//! distinguishes "first pin" from "subsequent pin" only at the state-machine
//! level via the [`crate::Op::Register`] / [`crate::Op::Pin`] split, but on
//! the wire we expose a single `Pin` RPC and let the server decide which
//! state-machine op to apply based on whether the key is already
//! registered).
//!
//! Errors are flattened into a small `RpcError` enum that the client can
//! match against without depending on the state machine's
//! [`crate::ValidationError`] type — the synchronizer is allowed to evolve
//! the internal validation surface without breaking wire compatibility.

use serde::{Deserialize, Serialize};

use crate::{Commitment, PcrKey, ValidationError, Version};

/// Request frame sent by a customer enclave to a synchronizer node.
///
/// The synchronizer is responsible for verifying that the calling session is
/// bound (via Noise + Nitro attestation) to a PCR set whose SHA-256 equals
/// [`PcrKey`] before honouring any of these RPCs. The wire format
/// deliberately does *not* repeat the PCR key inside every request: the
/// caller's authenticated session identity is the authority.
///
/// Including the PCR key in the request bodies anyway (rather than relying
/// purely on session state) is a deliberate redundancy: it lets the server
/// double-check the caller is talking about *its own* state, which catches
/// client bugs and makes the wire trace easier to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Read the latest pinned commitment for `key`.
    ///
    /// Returns [`Response::GetOk`] with the current commitment + version,
    /// or [`Response::Err`] with [`RpcError::NotFound`] if the key is not
    /// currently registered.
    Get {
        /// PCR set whose latest commitment is being read.
        key: PcrKey,
    },

    /// Write a new freshness commitment for `key`.
    ///
    /// On the wire this is a single RPC — internally the synchronizer maps
    /// it to [`crate::Op::Register`] (first pin for an unseen key) or
    /// [`crate::Op::Pin`] (subsequent pin) depending on the committed
    /// state. The result includes the resulting version so the caller can
    /// distinguish them: `Version(0)` means this was the registration.
    Pin {
        /// PCR set whose commitment is being updated.
        key: PcrKey,
        /// New commitment to associate with `key`.
        commitment: Commitment,
    },

    /// Authorize and execute a PCR transition for an enclave upgrade.
    ///
    /// `signature` is the Ed25519 control-key signature of the bytes
    /// `b"transition:" || old_key || new_key`, produced by the enclave
    /// currently running under `old_key`. The synchronizer verifies the
    /// signature against `old_key`'s registered Ed25519 control public
    /// key and, on success, retires `old_key`, registers `new_key` (which
    /// must itself have produced an attestation in this session), and
    /// carries the existing commitment + version forward.
    Transition {
        /// Current key being retired.
        old_key: PcrKey,
        /// Successor key adopting the retired key's state.
        new_key: PcrKey,
        /// Ed25519 signature over `b"transition:" || old_key || new_key`
        /// from `old_key`'s registered control private key.
        signature: Vec<u8>,
    },
}

/// Response frame sent by the synchronizer to a customer enclave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Successful [`Request::Get`].
    GetOk {
        /// Latest pinned commitment.
        commitment: Commitment,
        /// Per-key monotonic version.
        version: Version,
    },

    /// Successful [`Request::Pin`].
    ///
    /// `version` is `Version(0)` if this Pin registered the key for the
    /// first time, `Version(n+1)` if it bumped an existing pin from
    /// version `n`.
    PinOk {
        /// Per-key monotonic version after this pin.
        version: Version,
    },

    /// Successful [`Request::Transition`].
    ///
    /// `version` is the carried-over per-key version of the old key, now
    /// associated with `new_key`. The synchronizer guarantees the
    /// commitment is preserved across the transition.
    TransitionOk {
        /// Per-key monotonic version (unchanged across transition).
        version: Version,
    },

    /// Failure response. Carries a structured [`RpcError`] so the client
    /// can branch on the failure category without parsing strings.
    Err {
        /// Failure category.
        error: RpcError,
    },
}

/// Failure categories returned to clients over the wire.
///
/// Intentionally coarser than [`ValidationError`]: we want wire stability
/// even if the state-machine validation surface grows. Each variant maps
/// from one or more `ValidationError`s and carries no payload that could
/// leak per-key state to an unauthenticated caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code")]
pub enum RpcError {
    /// The session is not bound to a hardware-attested PCR set, or the key
    /// referenced in the request does not match the session's bound key.
    #[error("session is not authorized for this key")]
    Unauthorized,

    /// The requested key is not currently registered (never pinned, or
    /// retired by a prior `Transition`).
    #[error("key not found")]
    NotFound,

    /// `Transition` was rejected: signature did not verify, target key
    /// hasn't attested in this session, or target key is already
    /// registered / retired.
    #[error("transition rejected")]
    TransitionRejected,

    /// Generic request was well-formed but rejected by the state machine
    /// for a reason the wire surface deliberately does not enumerate
    /// (e.g. retired key, duplicate registration). Clients should treat
    /// this as fatal for the affected key.
    #[error("operation rejected")]
    OperationRejected,

    /// The server is currently unable to commit writes (e.g. quorum lost).
    /// Reads may still succeed; clients should back off and retry.
    #[error("synchronizer cluster unavailable")]
    Unavailable,
}

impl From<ValidationError> for RpcError {
    fn from(err: ValidationError) -> Self {
        match err {
            // Attestation failures only happen at Register/Transition.
            // The state machine doesn't model the per-session
            // authentication binding — that's the server's job before it
            // ever calls into the state machine — so a `NotAttested`
            // surfacing here means the *target* key of a transition
            // hasn't been attested in this session, which is a transition
            // rejection from the caller's point of view.
            ValidationError::NotAttested => RpcError::TransitionRejected,
            ValidationError::NewKeyNotAttested => RpcError::TransitionRejected,
            ValidationError::NoTransitionSignature => RpcError::TransitionRejected,
            ValidationError::NewKeyAlreadyExists => RpcError::TransitionRejected,
            ValidationError::OldKeyEqualsNew => RpcError::TransitionRejected,

            // KeyNotCurrent surfaces from Pin/Get on an unregistered key
            // (NotFound for the caller) AND from Transition on an
            // unregistered old_key (rejection). The server distinguishes
            // by knowing which RPC it was handling; here we default to
            // NotFound and let the server override for transitions.
            ValidationError::KeyNotCurrent => RpcError::NotFound,

            ValidationError::AlreadyRegistered => RpcError::OperationRejected,
            ValidationError::KeyRetired => RpcError::OperationRejected,
        }
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

    fn roundtrip<T>(value: &T)
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("encode");
        let decoded: T = ciborium::from_reader(&buf[..]).expect("decode");
        assert_eq!(*value, decoded, "round-trip mismatch");
    }

    #[test]
    fn request_get_roundtrip() {
        roundtrip(&Request::Get { key: k(1) });
    }

    #[test]
    fn request_pin_roundtrip() {
        roundtrip(&Request::Pin {
            key: k(7),
            commitment: c(0xab),
        });
    }

    #[test]
    fn request_transition_roundtrip() {
        roundtrip(&Request::Transition {
            old_key: k(1),
            new_key: k(2),
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        });
    }

    #[test]
    fn response_get_ok_roundtrip() {
        roundtrip(&Response::GetOk {
            commitment: c(0x5a),
            version: Version(42),
        });
    }

    #[test]
    fn response_pin_ok_roundtrip() {
        roundtrip(&Response::PinOk { version: Version(0) });
        roundtrip(&Response::PinOk {
            version: Version(u64::MAX),
        });
    }

    #[test]
    fn response_transition_ok_roundtrip() {
        roundtrip(&Response::TransitionOk { version: Version(7) });
    }

    #[test]
    fn response_err_roundtrip() {
        for code in [
            RpcError::Unauthorized,
            RpcError::NotFound,
            RpcError::TransitionRejected,
            RpcError::OperationRejected,
            RpcError::Unavailable,
        ] {
            roundtrip(&Response::Err { error: code });
        }
    }

    /// Sanity check: every `ValidationError` variant maps to a wire error.
    /// If a new variant is added to the state machine, this test forces a
    /// conscious decision about how to surface it on the wire.
    #[test]
    fn validation_error_to_rpc_error_total() {
        let cases = [
            (ValidationError::NotAttested, RpcError::TransitionRejected),
            (ValidationError::AlreadyRegistered, RpcError::OperationRejected),
            (ValidationError::KeyRetired, RpcError::OperationRejected),
            (ValidationError::KeyNotCurrent, RpcError::NotFound),
            (ValidationError::NewKeyAlreadyExists, RpcError::TransitionRejected),
            (ValidationError::NewKeyNotAttested, RpcError::TransitionRejected),
            (ValidationError::NoTransitionSignature, RpcError::TransitionRejected),
            (ValidationError::OldKeyEqualsNew, RpcError::TransitionRejected),
        ];
        for (input, expected) in cases {
            assert_eq!(RpcError::from(input), expected, "for {input:?}");
        }
    }

    /// Wire frames serialize as CBOR maps with a `"type"` (or `"code"`)
    /// discriminator. Lock this in so external clients (e.g. a future Go
    /// implementation) can rely on the wire shape.
    #[test]
    fn discriminator_tag_is_stable() {
        let req = Request::Get { key: k(0) };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        // Decode as a generic CBOR Value and assert the "type" key is
        // present with the expected discriminator.
        let val: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let map = val.as_map().expect("CBOR map");
        let ty = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("type") {
                    v.as_text()
                } else {
                    None
                }
            })
            .expect("type discriminator present");
        assert_eq!(ty, "Get");
    }
}
