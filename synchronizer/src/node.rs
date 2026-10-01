//! Async wrapper that pairs the [`StateMachine`](crate::StateMachine) with
//! the [`wire`](crate::wire) RPC surface.
//!
//! This is the "single-node, no-Raft, no-mesh" version of the synchronizer.
//! It handles the request/response dispatch, the session-binding check,
//! and `Transition`-link verification (the #47 upgrade chain link), the
//! actual transport (Noise over vsock) and the NSM attestation pipeline
//! live in the binary (part 4).
//!
//! ## Contract with the listener
//!
//! The Node assumes the listener has already:
//!
//! 1. Performed the Noise handshake with the caller.
//! 2. Verified the caller's Nitro attestation document, derived a
//!    [`PcrKey`] from its PCRs, and extracted the 65-byte SEC1 P-256
//!    control pubkey from `user_data` (`ValidatedAttestation::control_pubkey`).
//! 3. Called [`Node::observe_attestation`] for the caller's key + pubkey.
//!
//! For a `Transition` the SUBMITTING session is the NEW enclave: it
//! authenticates as `new_key`, and that is the session whose
//! `observe_attestation` the listener calls. The OLD enclave does NOT
//! hold a session at cutover (it has stopped); instead it earlier
//! registered `old_key` (`Pin`), which froze its control pubkey, and it
//! emitted the upgrade link the new enclave now presents. So the only
//! attestation observed for a Transition is the new enclave's own.
//!
//! In other words: the Node trusts that the [`PcrKey`] it sees as
//! `session_key` is genuinely the caller's attested identity, and that
//! the pubkey passed to `observe_attestation` was sourced from a
//! cryptographically verified NSM document. The Node itself owns
//! verifying a `Transition`'s chain link, deriving `old_key`/`new_key`
//! from the link payload, requiring `new_key == session_key`, and
//! checking the link's signature against the pubkey frozen for the
//! derived `old_key`, via [`crate::wire::decode_transition_link`] +
//! [`crate::wire::verify_transition_link`]. The listener no longer needs
//! to do that step (and importantly, no longer observes Transition
//! authorizations unconditionally, which was the #111 pre-fix insecurity).

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::wire::{
    ChainLink, Request, Response, RpcError, decode_transition_link, verify_revocation_link,
    verify_transition_link,
};
use crate::{CONTROL_PUBKEY_LEN, Op, PcrKey, StateMachine, ValidationError};

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
    /// Selects the debug (skip-cert-chain, QEMU/test NSM) vs production
    /// (full Nitro CA chain) attestation-validation path used when
    /// verifying a `Transition`'s chain link. The binary derives it from
    /// its `debug`/`enclave` Cargo feature; `Default`/`new()` use `false`
    /// (production) so a caller has to opt into the debug path explicitly.
    debug_mode: bool,
}

impl Node {
    /// Create a fresh, empty single-node synchronizer in production
    /// (full-chain) attestation mode.
    pub fn new() -> Self {
        Self::with_debug_mode(false)
    }

    /// Create a fresh, empty single-node synchronizer, selecting the
    /// attestation-validation path. `debug_mode = true` skips the Nitro
    /// CA-chain check (QEMU / test NSM docs); `false` requires the full
    /// chain.
    pub fn with_debug_mode(debug_mode: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateMachine::new())),
            debug_mode,
        }
    }

    /// Record that `key` has produced a valid Nitro attestation and
    /// announced `control_pubkey` as its 65-byte SEC1 P-256 verifying key
    /// (`ValidatedAttestation::control_pubkey`). The listener calls this once
    /// per session, immediately after the attestation document is
    /// verified.
    ///
    /// When `key` later registers (`Pin` of an unseen key), this pubkey is
    /// frozen into its `KeyState.control_pubkey`. A `Transition` link that
    /// names this `key` as its `old_key` (via `from`) is checked
    /// against that frozen pubkey, even though the submitting session is a
    /// different (new) enclave. If `key` is already committed in the state
    /// machine, its frozen `KeyState.control_pubkey` wins, this method only
    /// updates the pending-attestation map.
    pub async fn observe_attestation(&self, key: PcrKey, control_pubkey: [u8; CONTROL_PUBKEY_LEN]) {
        self.inner
            .lock()
            .await
            .observe_attestation(key, control_pubkey);
    }

    /// Record that the caller has verified an upgrade chain link from the
    /// enclave running under `old_key` authorizing `new_key` as its
    /// successor.
    ///
    /// In production this is called internally by
    /// [`Node::handle_request`] after it verifies the chain link in a
    /// `Transition` RPC. It's exposed at the Node API for tests and for
    /// the future replicated-state-machine driver, which will need to
    /// replay observations across Raft followers without re-running the
    /// link verification on every node.
    pub async fn observe_transition(&self, old_key: PcrKey, new_key: PcrKey) {
        self.inner.lock().await.observe_transition(old_key, new_key);
    }

    /// Handle one [`Request`] from a session authenticated as
    /// `session_key`.
    ///
    /// `Get` / `Pin` carry a redundant `key`; we reject the request with
    /// [`RpcError::Unauthorized`] when it doesn't match `session_key`.
    /// This is a belt-and-braces check, the session binding already
    /// establishes the authorized key, but it catches client bugs and
    /// makes wire traces self-explanatory. `Transition` carries no
    /// redundant key (only the upgrade link); its session binding is the
    /// `new_key == session_key` check inside the verifier, since the NEW
    /// enclave is the submitter.
    pub async fn handle_request(&self, session_key: PcrKey, req: Request) -> Response {
        match req {
            Request::Get { key } => self.handle_get(session_key, key).await,
            Request::Register { key, commitment } => {
                self.handle_register(session_key, key, commitment).await
            }
            Request::Pin {
                key,
                expected_version,
                commitment,
            } => {
                self.handle_pin(session_key, key, expected_version, commitment)
                    .await
            }
            Request::Transition { link } => self.handle_transition(session_key, link).await,
            Request::Revoke { link } => self.handle_revoke(session_key, link).await,
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

    /// Register the session's own key (its control pubkey was recorded by
    /// `observe_attestation`). An already registered key is
    /// `AlreadyRegistered`, a retired one `OperationRejected`.
    async fn handle_register(
        &self,
        session_key: PcrKey,
        key: PcrKey,
        commitment: crate::Commitment,
    ) -> Response {
        if key != session_key {
            return err(RpcError::Unauthorized);
        }
        let mut inner = self.inner.lock().await;
        match inner.apply(Op::Register { key, commitment }) {
            Ok(_) => Response::RegisterOk,
            Err(e) => err(RpcError::from(e)),
        }
    }

    /// Compare-and-swap pin of a registered key. An unknown key is
    /// `NotFound`: a Pin never registers.
    async fn handle_pin(
        &self,
        session_key: PcrKey,
        key: PcrKey,
        expected_version: crate::Version,
        commitment: crate::Commitment,
    ) -> Response {
        if key != session_key {
            return err(RpcError::Unauthorized);
        }
        let mut inner = self.inner.lock().await;
        match inner.apply(Op::Pin {
            key,
            expected_version,
            commitment,
        }) {
            Ok(state) => Response::PinOk {
                version: state.version,
            },
            Err(e) => err(RpcError::from(e)),
        }
    }

    async fn handle_transition(&self, session_key: PcrKey, link: ChainLink) -> Response {
        // Trusted time for the link's `valid_from` gate, read before taking
        // the state-machine lock. No trusted time means the gate cannot be
        // evaluated, so the transition is refused (retryable).
        let now_ms = match crate::trusted_time::now_ms().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "transition refused: trusted time unavailable");
                return err(RpcError::Unavailable);
            }
        };

        let mut inner = self.inner.lock().await;

        // Phase one: structurally decode the (still-untrusted) link to
        // learn the derived old_key / new_key. The NEW enclave submits a
        // Transition, so the session is bound to new_key; the OLD key is
        // the key of the payload's `from` identity, and is the key whose
        // FROZEN control pubkey must have authorized the link. Any
        // structural failure (wrong kind, missing signature, undecodable
        // payload, malformed identity) folds to TransitionRejected.
        let decoded = match decode_transition_link(&link) {
            Ok(d) => d,
            Err(_) => return err(RpcError::TransitionRejected),
        };

        // Look up the control pubkey frozen for the DERIVED old_key. That
        // enclave must already be registered: only a live key can be
        // transitioned away from. If it isn't (never registered, or
        // retired by a prior Transition) we report the wire-level
        // transition rejection rather than NotFound; a Transition isn't a
        // query.
        let old_control_pubkey = match inner.get(&decoded.old_key) {
            Some(state) => state.control_pubkey,
            None => return err(RpcError::TransitionRejected),
        };

        // Phase two: cryptographically verify the link. This enforces the
        // full contract: new_key (the key of `to`) equals the
        // submitting session, it is not a self-transition, the link's
        // control signature verifies under old_key's frozen pubkey, and
        // the chain attestation binds `user_data == sha256(payload)` and
        // the OLD enclave's full identity (`from`). Both keys are re-derived
        // from the signed payload, never from an untrusted wire field, and
        // the payload's `valid_from` has been reached. Any failure folds to
        // a single TransitionRejected.
        let verified = match verify_transition_link(
            &link,
            decoded,
            session_key,
            &old_control_pubkey,
            self.debug_mode,
            now_ms,
        ) {
            Ok(v) => v,
            Err(e) => {
                if let Some(reason) = e.attestation_reason() {
                    crate::metrics::record_rejection(
                        crate::metrics::RejectionSource::TransitionLink,
                        reason,
                    );
                }
                tracing::warn!(
                    reason = e.attestation_reason().map(|r| r.as_str()),
                    error = %e,
                    "transition link rejected"
                );
                return err(RpcError::TransitionRejected);
            }
        };

        // Link verified, record the observation and apply the op through
        // the pure state machine, which still enforces the remaining
        // structural checks (new_key attested, not retired, not already
        // registered, etc.).
        inner.observe_transition(verified.old_key, verified.new_key);
        match inner.apply(Op::Transition {
            old_key: verified.old_key,
            new_key: verified.new_key,
            link_hash: verified.link_hash,
        }) {
            Ok(state) => Response::TransitionOk {
                version: state.version,
            },
            // `KeyNotCurrent` from a Transition means the old key isn't
            // registered, that's a transition rejection, not a Get-style
            // NotFound. The default `From<ValidationError>` impl maps to
            // NotFound (the Pin/Get sense), so we override here.
            Err(ValidationError::KeyNotCurrent) => err(RpcError::TransitionRejected),
            Err(e) => err(RpcError::from(e)),
        }
    }

    /// Revoke the upgrade links out of the session's own key. The session
    /// must hold the pin (its key registered); the link must carry the
    /// control signature of that key's FROZEN pubkey
    /// ([`verify_revocation_link`]). Any failure is `RevocationRejected`,
    /// meaning the revocation did NOT take effect.
    async fn handle_revoke(&self, session_key: PcrKey, link: ChainLink) -> Response {
        let mut inner = self.inner.lock().await;
        let control_pubkey = match inner.get(&session_key) {
            Some(state) => state.control_pubkey,
            None => return err(RpcError::RevocationRejected),
        };
        let verified = match verify_revocation_link(&link, &control_pubkey) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "revocation link rejected");
                return err(RpcError::RevocationRejected);
            }
        };
        match inner.apply(Op::Revoke {
            key: session_key,
            link_hash: verified.link_hash,
        }) {
            Ok(_) => Response::RevokeOk,
            Err(_) => err(RpcError::RevocationRejected),
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
    use enclavia_protocol::attestation::test_utils::{FakeChainAttestation, identity_from_seed};
    use enclavia_protocol::chain::{ChainLinkKind, UpgradePayload};
    use enclavia_protocol::signing::{SignedDomain, sign_control};
    use p256::ecdsa::SigningKey;

    /// Arbitrary PcrKey for the Pin/Get/session-binding tests that never
    /// go through transition-link verification. These never have to match
    /// a PCR-hash, so a flat byte pattern is fine.
    fn k(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }

    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    /// The PcrKey of a seed's identity (no user PCRs), matching
    /// `verify_transition_link`'s key derivation.
    fn key_from_seed(seed: u8) -> PcrKey {
        PcrKey(identity_from_seed(seed).key())
    }

    /// Deterministic P-256 keypair; returns the signing key and the
    /// 65-byte uncompressed SEC1 verifying-key bytes that should be passed
    /// to `observe_attestation`.
    fn keypair(seed: u8) -> (SigningKey, [u8; CONTROL_PUBKEY_LEN]) {
        // A reliably-valid, nonzero P-256 scalar: a small big-endian
        // integer (0x01, seed, 0, ...) is always below the curve order.
        let mut scalar = [0u8; 32];
        scalar[0] = 0x01;
        scalar[1] = seed;
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let pk_vec = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut pk = [0u8; CONTROL_PUBKEY_LEN];
        pk.copy_from_slice(&pk_vec);
        (sk, pk)
    }

    /// A throwaway 65-byte SEC1 pubkey for tests that only Pin/Get and
    /// never verify a transition signature. Derived from a real keypair so
    /// it is a valid point, but the signing half is discarded.
    fn dummy_pubkey(seed: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        keypair(seed).1
    }

    /// Build a #47 upgrade chain link `from_seed -> to_seed`, signed by
    /// `signing` (the OLD enclave's control key) and attested for the OLD
    /// measurements (`from_seed`): the old enclave emits the link during
    /// its PrepareUpgrade flow, so it attests its own PCRs. Mirrors what
    /// `enclavia-server::run_prepare_upgrade` / `chain-host` produce.
    fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
        upgrade_link_valid_from(from_seed, to_seed, signing, chrono::Utc::now())
    }

    /// [`upgrade_link`] with an explicit `valid_from`.
    fn upgrade_link_valid_from(
        from_seed: u8,
        to_seed: u8,
        signing: &SigningKey,
        valid_from: chrono::DateTime<chrono::Utc>,
    ) -> ChainLink {
        let payload = UpgradePayload {
            enclave_id: uuid::Uuid::new_v4(),
            from: identity_from_seed(from_seed),
            to: identity_from_seed(to_seed),
            image_digest: "sha256:to".into(),
            valid_from,
            valid_until: valid_from + chrono::Duration::days(7),
            issued_at: chrono::Utc::now(),
            nonce: vec![0x5a; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
        let sig = sign_control(signing, SignedDomain::UpgradePayload, &payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Upgrade,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_vec()),
        }
    }

    /// Register an OLD key (attest + Register) so it is live with a frozen
    /// control pubkey, ready to be a transition's `from`. The submitting
    /// session in the corrected flow is the NEW enclave, so the old key is
    /// set up by a separate (earlier) session, modelled here by driving
    /// the node directly as `key_old`.
    async fn register_old(
        node: &Node,
        seed: u8,
        signing_pubkey: [u8; CONTROL_PUBKEY_LEN],
    ) -> PcrKey {
        let key_old = key_from_seed(seed);
        node.observe_attestation(key_old, signing_pubkey).await;
        node.handle_request(
            key_old,
            Request::Register {
                key: key_old,
                commitment: c(0xaa),
            },
        )
        .await;
        key_old
    }

    /// Debug-mode node so the chain-link validation accepts the synthetic
    /// `FakeChainAttestation` docs (no real Nitro CA chain).
    fn debug_node() -> Node {
        Node::with_debug_mode(true)
    }

    #[tokio::test]
    async fn get_unknown_key_returns_not_found() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        let resp = node.handle_request(k(1), Request::Get { key: k(1) }).await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    #[tokio::test]
    async fn register_creates_unseen_key_at_version_zero() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        let resp = node
            .handle_request(
                k(1),
                Request::Register {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await;
        assert_eq!(resp, Response::RegisterOk);
        let resp = node.handle_request(k(1), Request::Get { key: k(1) }).await;
        assert_eq!(
            resp,
            Response::GetOk {
                commitment: c(0xaa),
                version: Version(0),
            }
        );
    }

    /// A Pin never registers: an unknown key is `NotFound`, and stays
    /// unknown.
    #[tokio::test]
    async fn pin_on_unknown_key_is_not_found() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    expected_version: Version(0),
                    commitment: c(0xaa),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
        let resp = node.handle_request(k(1), Request::Get { key: k(1) }).await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    /// A second Register of a live key is `AlreadyRegistered` and leaves the
    /// pinned state alone; a Register for another session's key is refused.
    #[tokio::test]
    async fn register_is_once_and_own_key_only() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        node.observe_attestation(k(2), dummy_pubkey(2)).await;
        let register = |key, byte| Request::Register {
            key,
            commitment: c(byte),
        };
        assert_eq!(
            node.handle_request(k(1), register(k(1), 0xaa)).await,
            Response::RegisterOk
        );
        assert_eq!(
            node.handle_request(k(1), register(k(1), 0xbb)).await,
            err(RpcError::AlreadyRegistered)
        );
        assert_eq!(
            node.handle_request(k(1), register(k(2), 0xcc)).await,
            err(RpcError::Unauthorized)
        );
        assert_eq!(
            node.handle_request(k(1), Request::Get { key: k(1) }).await,
            Response::GetOk {
                commitment: c(0xaa),
                version: Version(0),
            }
        );
    }

    #[tokio::test]
    async fn pin_bumps_version_on_repeat() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        let _ = node
            .handle_request(
                k(1),
                Request::Register {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await;
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    expected_version: Version(0),
                    commitment: c(0xbb),
                },
            )
            .await;
        assert_eq!(
            resp,
            Response::PinOk {
                version: Version(1)
            }
        );
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(1),
                    expected_version: Version(1),
                    commitment: c(0xcc),
                },
            )
            .await;
        assert_eq!(
            resp,
            Response::PinOk {
                version: Version(2)
            }
        );
    }

    #[tokio::test]
    async fn get_after_pin_returns_latest() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        node.handle_request(
            k(1),
            Request::Register {
                key: k(1),
                commitment: c(0xab),
            },
        )
        .await;
        node.handle_request(
            k(1),
            Request::Pin {
                key: k(1),
                expected_version: Version(0),
                commitment: c(0xcd),
            },
        )
        .await;
        let resp = node.handle_request(k(1), Request::Get { key: k(1) }).await;
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
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        node.observe_attestation(k(2), dummy_pubkey(2)).await;
        let resp = node.handle_request(k(1), Request::Get { key: k(2) }).await;
        assert_eq!(resp, err(RpcError::Unauthorized));
    }

    #[tokio::test]
    async fn session_binding_rejects_cross_key_pin() {
        let node = Node::new();
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        node.observe_attestation(k(2), dummy_pubkey(2)).await;
        let resp = node
            .handle_request(
                k(1),
                Request::Pin {
                    key: k(2),
                    expected_version: Version(0),
                    commitment: c(0xff),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::Unauthorized));
        let resp = node.handle_request(k(2), Request::Get { key: k(2) }).await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    /// Session-binding fires inside the link verifier: even with a valid
    /// link for (from=A -> to=C), a session authenticated as B (not the
    /// link's to=C) can't drive it. The link's `to` has key C, not B,
    /// so the SessionKeyMismatch path rejects it as TransitionRejected.
    #[tokio::test]
    async fn session_binding_rejects_transition_for_someone_else() {
        let node = debug_node();
        let (sk_a, pk_a) = keypair(0x10);
        let (_, pk_b) = keypair(0x20);
        // A (the old enclave) is registered and live.
        register_old(&node, 0x10, pk_a).await;
        // B is some unrelated registered session.
        let key_b = key_from_seed(0x20);
        node.observe_attestation(key_b, pk_b).await;
        node.handle_request(
            key_b,
            Request::Register {
                key: key_b,
                commitment: c(0xbb),
            },
        )
        .await;
        // Pre-attest the genuine target C (the new enclave).
        node.observe_attestation(key_from_seed(0x30), dummy_pubkey(0x30))
            .await;
        // A genuine link for A -> C, but presented by B's session (B is
        // neither the old key A nor the new key C).
        let link = upgrade_link(0x10, 0x30, &sk_a);
        let resp = node
            .handle_request(key_b, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A transition link with a malformed (wrong-length) signature is
    /// rejected. The NEW key (0x21) is the submitting session; old key
    /// (0x11) is registered separately.
    #[tokio::test]
    async fn transition_with_malformed_signature_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x11);
        register_old(&node, 0x11, pk).await;
        let key_new = key_from_seed(0x21);
        node.observe_attestation(key_new, dummy_pubkey(0x21)).await;
        let mut link = upgrade_link(0x11, 0x21, &sk);
        link.signature = Some(vec![0xde, 0xad]); // not 64 bytes
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A 64-byte signature that doesn't verify against old_key's frozen
    /// control pubkey is rejected.
    #[tokio::test]
    async fn transition_with_invalid_signature_is_rejected() {
        let node = debug_node();
        let (_sk_real, pk_real) = keypair(0x12);
        let (sk_attacker, _) = keypair(0xab);
        register_old(&node, 0x12, pk_real).await;
        let key_new = key_from_seed(0x22);
        node.observe_attestation(key_new, dummy_pubkey(0x22)).await;
        // Link signed by the attacker, not old_key's registered key.
        let link = upgrade_link(0x12, 0x22, &sk_attacker);
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A transition whose derived old_key isn't registered is rejected
    /// (you cannot retire a key that was never pinned), even though the
    /// new enclave's session is perfectly valid.
    #[tokio::test]
    async fn transition_against_unregistered_old_key_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x13);
        let key_old = key_from_seed(0x13);
        // Attest old_key but never Pin/Register it.
        node.observe_attestation(key_old, pk).await;
        let key_new = key_from_seed(0x23);
        node.observe_attestation(key_new, dummy_pubkey(0x23)).await;
        let link = upgrade_link(0x13, 0x23, &sk);
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A transition whose target (the submitting session) hasn't attested
    /// in this run is rejected (the pure state machine refuses
    /// NewKeyNotAttested). We force this by driving handle_transition with
    /// a session_key that was never observed.
    #[tokio::test]
    async fn transition_with_unattested_new_key_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x14);
        register_old(&node, 0x14, pk).await;
        let key_new = key_from_seed(0x24);
        // Deliberately do NOT attest the new key (0x24), but still submit
        // as that session.
        let link = upgrade_link(0x14, 0x24, &sk);
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A valid link, attested submitting (new) session, and registered old
    /// key succeeds and rotates state to new_key, carrying commitment +
    /// version.
    #[tokio::test]
    async fn transition_succeeds_with_valid_link() {
        let node = debug_node();
        let (sk, pk) = keypair(0x15);
        let key_old = key_from_seed(0x15);
        let key_new = key_from_seed(0x25);
        // Old enclave registers and pins twice (commitment 0xbb, version 1).
        node.observe_attestation(key_old, pk).await;
        node.handle_request(
            key_old,
            Request::Register {
                key: key_old,
                commitment: c(0xaa),
            },
        )
        .await;
        node.handle_request(
            key_old,
            Request::Pin {
                key: key_old,
                expected_version: Version(0),
                commitment: c(0xbb),
            },
        )
        .await;
        // New enclave attests in its own session and submits.
        node.observe_attestation(key_new, dummy_pubkey(0x25)).await;
        let link = upgrade_link(0x15, 0x25, &sk);
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(
            resp,
            Response::TransitionOk {
                version: Version(1)
            }
        );
        // The new key now owns the commitment + version.
        let resp = node
            .handle_request(key_new, Request::Get { key: key_new })
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
            .handle_request(key_old, Request::Get { key: key_old })
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
    }

    /// "Control pubkey substitution": after old_key registers with pk_real,
    /// the attacker re-attests old_key with their own pubkey and signs a
    /// link with the matching key, submitting from the new enclave's
    /// session. The pubkey in old_key's KeyState is frozen, so
    /// verification against pk_real fails and the link is rejected.
    #[tokio::test]
    async fn transition_rejects_control_pubkey_substitution() {
        let node = debug_node();
        let (_sk_genuine, pk_real) = keypair(0x16);
        let (sk_attacker, pk_attacker) = keypair(0xfe);
        let key_old = register_old(&node, 0x16, pk_real).await;
        let key_new = key_from_seed(0x26);
        node.observe_attestation(key_new, dummy_pubkey(0x26)).await;
        // Attacker re-attests old_key with their own pubkey. This updates
        // the pending map but NOT old_key's frozen KeyState pubkey.
        node.observe_attestation(key_old, pk_attacker).await;
        let link = upgrade_link(0x16, 0x26, &sk_attacker);
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
    }

    /// A link scheduled an hour from now is refused (the `valid_from` gate),
    /// and the old key keeps its state: the early attempt changes nothing.
    #[tokio::test]
    async fn transition_before_valid_from_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x18);
        let key_old = register_old(&node, 0x18, pk).await;
        let key_new = key_from_seed(0x28);
        node.observe_attestation(key_new, dummy_pubkey(0x28)).await;
        let link = upgrade_link_valid_from(
            0x18,
            0x28,
            &sk,
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRejected));
        let resp = node
            .handle_request(key_old, Request::Get { key: key_old })
            .await;
        assert_eq!(
            resp,
            Response::GetOk {
                commitment: c(0xaa),
                version: Version(0),
            }
        );
    }

    /// Once a key transitions, any further session bound to it is dead.
    #[tokio::test]
    async fn retired_key_cannot_pin() {
        let node = debug_node();
        let (sk, pk) = keypair(0x17);
        let key_old = register_old(&node, 0x17, pk).await;
        let key_new = key_from_seed(0x27);
        node.observe_attestation(key_new, dummy_pubkey(0x27)).await;
        let link = upgrade_link(0x17, 0x27, &sk);
        node.handle_request(key_new, Request::Transition { link })
            .await;
        // After retirement old_key is unknown to Pin, and the state machine
        // refuses to register it again.
        let resp = node
            .handle_request(
                key_old,
                Request::Pin {
                    key: key_old,
                    expected_version: Version(0),
                    commitment: c(0xee),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::NotFound));
        let resp = node
            .handle_request(
                key_old,
                Request::Register {
                    key: key_old,
                    commitment: c(0xee),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::OperationRejected));
    }

    /// Two sessions registering their own keys concurrently both succeed:
    /// the Mutex serializes them in some order without losing writes.
    #[tokio::test]
    async fn concurrent_pins_on_disjoint_keys_serialize() {
        let node = Arc::new(Node::new());
        node.observe_attestation(k(1), dummy_pubkey(1)).await;
        node.observe_attestation(k(2), dummy_pubkey(2)).await;

        let n1 = Arc::clone(&node);
        let n2 = Arc::clone(&node);
        let t1 = tokio::spawn(async move {
            n1.handle_request(
                k(1),
                Request::Register {
                    key: k(1),
                    commitment: c(0xaa),
                },
            )
            .await
        });
        let t2 = tokio::spawn(async move {
            n2.handle_request(
                k(2),
                Request::Register {
                    key: k(2),
                    commitment: c(0xbb),
                },
            )
            .await
        });
        let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());
        assert_eq!(r1, Response::RegisterOk);
        assert_eq!(r2, Response::RegisterOk);

        let g1 = node.handle_request(k(1), Request::Get { key: k(1) }).await;
        let g2 = node.handle_request(k(2), Request::Get { key: k(2) }).await;
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

    // --- revocation --------------------------------------------------------

    /// An upgrade link with an explicit `issued_at` (and `valid_from` in the
    /// past, so only a revocation can stop it).
    fn upgrade_link_issued_at(
        from_seed: u8,
        to_seed: u8,
        signing: &SigningKey,
        issued_at: chrono::DateTime<chrono::Utc>,
    ) -> ChainLink {
        let payload = UpgradePayload {
            enclave_id: uuid::Uuid::new_v4(),
            from: identity_from_seed(from_seed),
            to: identity_from_seed(to_seed),
            image_digest: "sha256:to".into(),
            valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
            valid_until: (chrono::Utc::now() - chrono::Duration::hours(1)) + chrono::Duration::days(7),
            issued_at,
            nonce: vec![0x5a; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
        let sig = sign_control(signing, SignedDomain::UpgradePayload, &payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Upgrade,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_vec()),
        }
    }

    /// A revocation of `target` signed by `signing`, stamped `issued_at`.
    fn revocation_of(
        signing: &SigningKey,
        target: &ChainLink,
        issued_at: chrono::DateTime<chrono::Utc>,
    ) -> ChainLink {
        let payload = enclavia_protocol::chain::RevocationPayload {
            enclave_id: uuid::Uuid::new_v4(),
            revokes: uuid::Uuid::new_v4(),
            issued_at,
            nonce: vec![0x6b; 32],
            revokes_link: crate::wire::upgrade_link_hash(&target.payload),
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let sig = sign_control(signing, SignedDomain::RevocationPayload, &payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Revocation,
            payload: payload_bytes,
            attestation: vec![],
            signature: Some(sig.to_vec()),
        }
    }

    fn hours_ago(h: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() - chrono::Duration::hours(h)
    }

    /// The old enclave revokes a link; that exact link can never move the
    /// pin, even when a hostile backend stamped it with a far-future
    /// `issued_at` and the revocation with an old one. A different
    /// (re-approved) link to the same target still works.
    #[tokio::test]
    async fn revoked_link_is_refused_whatever_its_timestamps() {
        let node = debug_node();
        let (sk, pk) = keypair(0x51);
        let key_old = register_old(&node, 0x51, pk).await;
        let key_new = key_from_seed(0x52);
        node.observe_attestation(key_new, dummy_pubkey(0x52)).await;

        let far_future = chrono::Utc::now() + chrono::Duration::days(3650);
        let revoked = upgrade_link_issued_at(0x51, 0x52, &sk, far_future);
        let resp = node
            .handle_request(
                key_old,
                Request::Revoke {
                    link: revocation_of(&sk, &revoked, hours_ago(1000)),
                },
            )
            .await;
        assert_eq!(resp, Response::RevokeOk);

        let resp = node
            .handle_request(key_new, Request::Transition { link: revoked })
            .await;
        assert_eq!(resp, err(RpcError::TransitionRevoked));
        let resp = node
            .handle_request(key_old, Request::Get { key: key_old })
            .await;
        assert!(matches!(resp, Response::GetOk { .. }), "{resp:?}");

        let reapproved = upgrade_link_issued_at(0x51, 0x52, &sk, hours_ago(1));
        let resp = node
            .handle_request(key_new, Request::Transition { link: reapproved })
            .await;
        assert!(matches!(resp, Response::TransitionOk { .. }), "{resp:?}");
    }

    /// A revocation naming ANOTHER link (what a hostile backend would hand
    /// the signer) does not block the real one: only the named link is
    /// revoked, which is why the signer must check the name.
    #[tokio::test]
    async fn revocation_of_another_link_does_not_block_the_target() {
        let node = debug_node();
        let (sk, pk) = keypair(0x58);
        let key_old = register_old(&node, 0x58, pk).await;
        let key_new = key_from_seed(0x59);
        node.observe_attestation(key_new, dummy_pubkey(0x59)).await;
        let target = upgrade_link_issued_at(0x58, 0x59, &sk, hours_ago(2));
        let decoy = upgrade_link_issued_at(0x58, 0x59, &sk, hours_ago(3));
        let resp = node
            .handle_request(
                key_old,
                Request::Revoke {
                    link: revocation_of(&sk, &decoy, hours_ago(1)),
                },
            )
            .await;
        assert_eq!(resp, Response::RevokeOk);
        let resp = node
            .handle_request(key_new, Request::Transition { link: target })
            .await;
        assert!(matches!(resp, Response::TransitionOk { .. }), "{resp:?}");
    }

    /// A revocation signed by anything but the key's frozen control key is
    /// refused and records nothing: the link still works afterwards.
    #[tokio::test]
    async fn revocation_signed_by_another_key_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x53);
        let (host_sk, _) = keypair(0x54);
        let key_old = register_old(&node, 0x53, pk).await;
        let link = upgrade_link_issued_at(0x53, 0x55, &sk, hours_ago(2));
        let resp = node
            .handle_request(
                key_old,
                Request::Revoke {
                    link: revocation_of(&host_sk, &link, hours_ago(1)),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::RevocationRejected));

        let key_new = key_from_seed(0x55);
        node.observe_attestation(key_new, dummy_pubkey(0x55)).await;
        let resp = node
            .handle_request(key_new, Request::Transition { link })
            .await;
        assert!(matches!(resp, Response::TransitionOk { .. }), "{resp:?}");
    }

    /// Only the enclave holding the pin can revoke: a session whose key is
    /// not registered (any other image the host can boot) is refused, even
    /// with a validly signed revocation.
    #[tokio::test]
    async fn revocation_from_a_session_without_a_pin_is_rejected() {
        let node = debug_node();
        let (sk, pk) = keypair(0x56);
        register_old(&node, 0x56, pk).await;
        let stranger = key_from_seed(0x57);
        node.observe_attestation(stranger, pk).await;
        let link = upgrade_link_issued_at(0x56, 0x57, &sk, hours_ago(2));
        let resp = node
            .handle_request(
                stranger,
                Request::Revoke {
                    link: revocation_of(&sk, &link, hours_ago(1)),
                },
            )
            .await;
        assert_eq!(resp, err(RpcError::RevocationRejected));
    }
}
