//! Async wrapper that pairs the [`StateMachine`](crate::StateMachine) with
//! the [`wire`](crate::wire) RPC surface.
//!
//! This is the "single-node, no-Raft, no-mesh" version of the synchronizer.
//! It handles the request/response dispatch, the session-binding check,
//! and the Ed25519 `Transition`-signature verification — the actual
//! transport (Noise over vsock) and the NSM attestation pipeline live in
//! the binary (part 4).
//!
//! ## Contract with the listener
//!
//! The Node assumes the listener has already:
//!
//! 1. Performed the Noise handshake with the caller.
//! 2. Verified the caller's Nitro attestation document, derived a
//!    [`PcrKey`] from its PCRs, and extracted the raw 32-byte Ed25519
//!    control pubkey from `user_data`.
//! 3. Called [`Node::observe_attestation`] for the caller's key + pubkey.
//!    For `Transition` requests, the *new* key also has to have called
//!    `observe_attestation` in its own session beforehand.
//!
//! In other words: the Node trusts that the [`PcrKey`] it sees as
//! `session_key` is genuinely the caller's attested identity, and that
//! the pubkey passed to `observe_attestation` was sourced from a
//! cryptographically verified NSM document. The Node itself owns
//! verifying `Transition` signatures against the registered pubkey — the
//! listener no longer needs to do that step (and importantly, no longer
//! observes Transition signatures unconditionally, which was the #111
//! pre-fix insecurity).

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tokio::sync::Mutex;

use crate::wire::{Request, Response, RpcError};
use crate::{Op, PcrKey, StateMachine, ValidationError};

/// Domain-separation prefix mixed into every `Transition` signature
/// payload. The signed bytes are `TRANSITION_SIG_PREFIX || old_key.0 ||
/// new_key.0` — 11 + 32 + 32 = 75 bytes. The wire docs in
/// `crate::wire::Request::Transition` are the single source of truth for
/// the format; `enclavia-crypto`'s `prepare-upgrade` flow must build
/// exactly the same bytes.
const TRANSITION_SIG_PREFIX: &[u8] = b"transition:";

/// Build the canonical bytes a `Transition` signature must cover.
fn transition_signing_payload(old_key: PcrKey, new_key: PcrKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TRANSITION_SIG_PREFIX.len() + 32 + 32);
    buf.extend_from_slice(TRANSITION_SIG_PREFIX);
    buf.extend_from_slice(&old_key.0);
    buf.extend_from_slice(&new_key.0);
    buf
}

/// Single-node synchronizer.
///
/// Wraps a [`StateMachine`] behind a [`tokio::sync::Mutex`] so that
/// concurrent client sessions can serialize their requests through one
/// in-memory log. The Mutex is intentionally coarse: at the throughputs
/// this service runs at (btrfs commits at most once every 30 s per
/// customer enclave), serializing is fine and keeps the state machine
/// `&mut`-only API honest.
#[derive(Default)]
pub struct Node {
    inner: Arc<Mutex<StateMachine>>,
}

impl Node {
    /// Create a fresh, empty single-node synchronizer.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateMachine::new())),
        }
    }

    /// Record that `key` has produced a valid Nitro attestation and
    /// announced `control_pubkey` as its Ed25519 verifying key. The
    /// listener calls this once per session, immediately after the
    /// attestation document is verified.
    ///
    /// The pubkey is what `Transition` signatures from `key` will be
    /// checked against. If `key` is already committed in the state
    /// machine, its frozen `KeyState.control_pubkey` wins — this method
    /// only updates the pending-attestation map.
    pub async fn observe_attestation(&self, key: PcrKey, control_pubkey: [u8; 32]) {
        self.inner
            .lock()
            .await
            .observe_attestation(key, control_pubkey);
    }

    /// Record that the enclave running under `old_key` has produced a
    /// valid Ed25519 signature authorizing `new_key` as its successor.
    ///
    /// In production this is called internally by
    /// [`Node::handle_request`] after it verifies the signature in a
    /// `Transition` RPC. It's exposed at the Node API for tests and for
    /// the future replicated-state-machine driver, which will need to
    /// replay observations across Raft followers without re-running the
    /// signature verification on every node.
    pub async fn observe_transition_sig(&self, old_key: PcrKey, new_key: PcrKey) {
        self.inner
            .lock()
            .await
            .observe_transition_sig(old_key, new_key);
    }

    /// Handle one [`Request`] from a session authenticated as
    /// `session_key`.
    ///
    /// Every request body carries a redundant `key` (or `old_key`); we
    /// reject the request with [`RpcError::Unauthorized`] when that
    /// doesn't match `session_key`. This is a belt-and-braces check —
    /// the session binding already establishes the authorized key — but
    /// it catches client bugs and makes wire traces self-explanatory.
    pub async fn handle_request(&self, session_key: PcrKey, req: Request) -> Response {
        match req {
            Request::Get { key } => self.handle_get(session_key, key).await,
            Request::Pin { key, commitment } => {
                self.handle_pin(session_key, key, commitment).await
            }
            Request::Transition {
                old_key,
                new_key,
                signature,
            } => {
                self.handle_transition(session_key, old_key, new_key, &signature)
                    .await
            }
        }
    }

    async fn handle_get(&self, session_key: PcrKey, key: PcrKey) -> Response {
        if key != session_key {
            return err(RpcError::Unauthorized);
        }
        let inner = self.inner.lock().await;
        match inner.get(&key) {
            Some(state) => Response::GetOk {
                commitment: state.commitment,
                version: state.version,
            },
            None => err(RpcError::NotFound),
        }
    }

    async fn handle_pin(
        &self,
        session_key: PcrKey,
        key: PcrKey,
        commitment: crate::Commitment,
    ) -> Response {
        if key != session_key {
            return err(RpcError::Unauthorized);
        }
        let mut inner = self.inner.lock().await;
        // Pin is a single wire RPC; map to Register (first pin) or Pin
        // (subsequent) based on what's already committed. The caller
        // distinguishes the two by inspecting the returned version:
        // Version(0) means this was the registration.
        let op = if inner.get(&key).is_some() {
            Op::Pin { key, commitment }
        } else {
            Op::Register { key, commitment }
        };
        match inner.apply(op) {
            Ok(state) => Response::PinOk {
                version: state.version,
            },
            Err(e) => err(RpcError::from(e)),
        }
    }

    async fn handle_transition(
        &self,
        session_key: PcrKey,
        old_key: PcrKey,
        new_key: PcrKey,
        signature: &[u8],
    ) -> Response {
        // The session must be the *old* enclave — only it can sign and
        // authorize the transition into its successor.
        if old_key != session_key {
            return err(RpcError::Unauthorized);
        }
        let mut inner = self.inner.lock().await;

        // Look up `old_key`'s registered control pubkey. If `old_key`
        // isn't currently registered (never registered, or retired by
        // a prior Transition) we report the wire-level transition
        // rejection rather than NotFound — Transition isn't a query.
        let pubkey_bytes = match inner.get(&old_key) {
            Some(state) => state.control_pubkey,
            None => return err(RpcError::TransitionRejected),
        };

        // Verify the Ed25519 signature over `b"transition:" || old_key
        // || new_key` against the registered pubkey. Any failure path
        // (malformed pubkey, malformed signature bytes, invalid
        // signature) folds into a single TransitionRejected — we don't
        // tell the caller *which* check failed.
        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(k) => k,
            Err(_) => return err(RpcError::TransitionRejected),
        };
        let parsed_sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return err(RpcError::TransitionRejected),
        };
        let payload = transition_signing_payload(old_key, new_key);
        if verifying_key.verify(&payload, &parsed_sig).is_err() {
            return err(RpcError::TransitionRejected);
        }

        // Signature verified — record the observation and apply the op
        // through the pure state machine, which still enforces the
        // remaining structural checks (new_key attested, not retired,
        // not already registered, etc.).
        inner.observe_transition_sig(old_key, new_key);
        match inner.apply(Op::Transition { old_key, new_key }) {
            Ok(state) => Response::TransitionOk {
                version: state.version,
            },
            // `KeyNotCurrent` from a Transition means the old key isn't
            // registered — that's a transition rejection, not a Get-style
            // NotFound. The default `From<ValidationError>` impl maps to
            // NotFound (the Pin/Get sense), so we override here.
            Err(ValidationError::KeyNotCurrent) => err(RpcError::TransitionRejected),
            Err(e) => err(RpcError::from(e)),
        }
    }
}

fn err(error: RpcError) -> Response {
    Response::Err { error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commitment, Version};
    use ed25519_dalek::{Signer, SigningKey};

    fn k(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }

    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    /// Deterministic Ed25519 keypair derived from `seed`. Returns the
    /// signing key plus the raw 32-byte verifying-key bytes that should
    /// be passed to `observe_attestation`.
    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Sign the canonical Transition payload for `(old_key, new_key)`
    /// using `sk`, mirroring what `enclavia-crypto` produces on the
    /// retiring enclave.
    fn sign_transition(sk: &SigningKey, old: PcrKey, new: PcrKey) -> Vec<u8> {
        sk.sign(&transition_signing_payload(old, new))
            .to_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn get_unknown_key_returns_not_found() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        node.observe_attestation(k(1), pk1).await;
        let resp = node
            .handle_request(k(1), Request::Get { key: k(1) })
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    #[tokio::test]
    async fn pin_registers_unseen_key_at_version_zero() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        node.observe_attestation(k(1), pk1).await;
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await;
        assert_eq!(resp, Response::PinOk { version: Version(0) });
    }

    #[tokio::test]
    async fn pin_bumps_version_on_repeat() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        node.observe_attestation(k(1), pk1).await;
        // First pin: registers.
        let _ = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await;
        // Second pin: bumps.
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xbb),
                },
            )
            .await;
        assert_eq!(resp, Response::PinOk { version: Version(1) });
        // Third pin: bumps again.
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xcc),
                },
            )
            .await;
        assert_eq!(resp, Response::PinOk { version: Version(2) });
    }

    #[tokio::test]
    async fn get_after_pin_returns_latest() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        node.observe_attestation(k(1), pk1).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xab),
            },
        )
        .await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xcd),
            },
        )
        .await;
        let resp = node
            .handle_request(k(1), Request::Get { key: k(1) })
            .await;
        assert_eq!(
            resp,
            Response::GetOk {
                commitment: c(0xcd),
                version: Version(1),
            }
        );
    }

    /// Session-binding check: a session authenticated as key A cannot
    /// read or write key B's state even if it tries.
    #[tokio::test]
    async fn session_binding_rejects_cross_key_get() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        let resp = node
            .handle_request(k(1), Request::Get { key: k(2) })
            .await;
        assert_eq!(resp, err(RpcError::Unauthorized));
    }

    #[tokio::test]
    async fn session_binding_rejects_cross_key_pin() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(2),
                    commitment: c(0xff),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::Unauthorized));
        // And no side effect on k(2).
        let resp = node
            .handle_request(k(2), Request::Get { key: k(2) })
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    /// Session-binding fires before crypto verification: even with a
    /// valid signature for `(k1, k3)`, a session authenticated as k(2)
    /// can't retire k(1).
    #[tokio::test]
    async fn session_binding_rejects_transition_signed_for_someone_else() {
        let node = Node::new();
        let (sk1, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        let (_, pk3) = keypair(3);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.observe_attestation(k(3), pk3).await;
        // k(1) registers.
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        // Session for k(2) tries to perform k(1) -> k(3) with a
        // *valid* sig from k(1). Still disallowed: only k(1)'s own
        // session can authorize its retirement.
        let sig = sign_transition(&sk1, k(1), k(3));
        let resp = node
            .handle_request(
                k(2),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(3),
                    signature: sig,
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::Unauthorized));
    }

    /// A Transition with the wrong-length / unparseable signature bytes
    /// is rejected before any state machine call.
    #[tokio::test]
    async fn transition_with_malformed_signature_is_rejected() {
        let node = Node::new();
        let (_, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        let resp = node
            .handle_request(
                k(1),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(2),
                    signature: vec![0xde, 0xad],
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A 64-byte signature that simply doesn't verify against `old_key`'s
    /// registered control pubkey is rejected.
    #[tokio::test]
    async fn transition_with_invalid_signature_is_rejected() {
        let node = Node::new();
        let (sk_wrong, _) = keypair(99); // attacker's keypair
        let (_, pk1) = keypair(1); // k(1) registers pk1, not pk_wrong
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        let sig = sign_transition(&sk_wrong, k(1), k(2));
        let resp = node
            .handle_request(
                k(1),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(2),
                    signature: sig,
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A signature that is well-formed and from the right key but
    /// covers a *different* `new_key` than the one in the request is
    /// rejected. Guards against an attacker capturing a sig the enclave
    /// produced for one upgrade target and replaying it for another.
    #[tokio::test]
    async fn transition_with_signature_over_wrong_payload_is_rejected() {
        let node = Node::new();
        let (sk1, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        let (_, pk3) = keypair(3);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.observe_attestation(k(3), pk3).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        // Signed over (k(1) -> k(3)) but request asks for (k(1) -> k(2)).
        let sig = sign_transition(&sk1, k(1), k(3));
        let resp = node
            .handle_request(
                k(1),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(2),
                    signature: sig,
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A Transition with a valid signature, an attested target, and a
    /// registered old_key succeeds and rotates state to new_key.
    #[tokio::test]
    async fn transition_succeeds_with_valid_signature() {
        let node = Node::new();
        let (sk1, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xbb),
            },
        )
        .await;
        let sig = sign_transition(&sk1, k(1), k(2));
        let resp = node
            .handle_request(
                k(1),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(2),
                    signature: sig,
                },
            )
            .await;
        assert_eq!(resp, Response::TransitionOk { version: Version(1) });
        // The new key now owns the commitment + version.
        let resp = node
            .handle_request(k(2), Request::Get { key: k(2) })
            .await;
        assert_eq!(
            resp,
            Response::GetOk {
                commitment: c(0xbb),
                version: Version(1),
            }
        );
        // The old key is gone.
        let resp = node
            .handle_request(k(1), Request::Get { key: k(1) })
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    /// "Control pubkey substitution": after k(1) is Registered with
    /// pubkey pk1, the attacker re-attests k(1) with their own pubkey
    /// and signs a Transition with the matching signing key. The
    /// pubkey registered in `KeyState` is frozen, so verification
    /// against pk1 fails and the Transition is rejected.
    #[tokio::test]
    async fn transition_rejects_control_pubkey_substitution() {
        let node = Node::new();
        let (_sk1_genuine, pk1) = keypair(1);
        let (sk_attacker, pk_attacker) = keypair(0xff);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        // Now the attacker re-attests k(1) (somehow) with their own
        // pubkey. observe_attestation overwrites the pending map but
        // not KeyState — k(1)'s registered authorizer is still pk1.
        node.observe_attestation(k(1), pk_attacker).await;
        let sig = sign_transition(&sk_attacker, k(1), k(2));
        let resp = node
            .handle_request(
                k(1),
                Request::Transition {
                    old_key: k(1),
                    new_key: k(2),
                    signature: sig,
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// Once a key transitions, any further session bound to it is dead.
    #[tokio::test]
    async fn retired_key_cannot_pin() {
        let node = Node::new();
        let (sk1, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                commitment: c(0xaa),
            },
        )
        .await;
        let sig = sign_transition(&sk1, k(1), k(2));
        node.handle_request(
            k(1),
            Request::Transition {
                old_key: k(1),
                new_key: k(2),
                signature: sig,
            },
        )
        .await;
        // After retirement, k(1) tries to Pin. Should not bring it back.
        // Mapped to Register (since k(1) is not registered), which the
        // state machine refuses because the key is retired.
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xee),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::OperationRejected));
    }

    /// Two sessions pinning their own keys concurrently both succeed —
    /// the Mutex serializes them in some order without losing writes.
    #[tokio::test]
    async fn concurrent_pins_on_disjoint_keys_serialize() {
        let node = Arc::new(Node::new());
        let (_, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        node.observe_attestation(k(1), pk1).await;
        node.observe_attestation(k(2), pk2).await;

        let n1 = Arc::clone(&node);
        let n2 = Arc::clone(&node);
        let t1 = tokio::spawn(async move {
            n1.handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await
        });
        let t2 = tokio::spawn(async move {
            n2.handle_request(
                k(2),
                Request::Pin {
                    key: k(2),
                    commitment: c(0xbb),
                },
            )
            .await
        });
        let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());
        assert_eq!(r1, Response::PinOk { version: Version(0) });
        assert_eq!(r2, Response::PinOk { version: Version(0) });

        // Both keys are now registered with their own commitments.
        let g1 = node
            .handle_request(k(1), Request::Get { key: k(1) })
            .await;
        let g2 = node
            .handle_request(k(2), Request::Get { key: k(2) })
            .await;
        assert_eq!(
            g1,
            Response::GetOk {
                commitment: c(0xaa),
                version: Version(0),
            }
        );
        assert_eq!(
            g2,
            Response::GetOk {
                commitment: c(0xbb),
                version: Version(0),
            }
        );
    }
}
