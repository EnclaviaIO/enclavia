//! Replicated client-request handling (#120, slice 4).
//!
//! Maps a customer enclave's [`wire::Request`] onto the Raft layer. This is the
//! replicated successor to the single-node [`Node`](crate::Node): instead of
//! mutating one in-memory [`StateMachine`](crate::StateMachine) behind a Mutex,
//! it submits verified [`ReplicatedOp`]s through [`RaftHandle::client_write`]
//! (which ACKs once the entry is committed on a quorum of voters, see
//! "Majority ACK" below) and serves reads through
//! [`RaftHandle::linearizable_get`] (which refuses to answer off a stale
//! follower).
//!
//! ## Session facts, leader-verified
//!
//! A customer session arrives on the client listener with an attested identity:
//! its [`PcrKey`] (derived from the verified NSM document's PCRs) plus the
//! 65-byte SEC1 P-256 control pubkey pulled from the document's `user_data`.
//! The listener has already done that attestation (exactly as the single-node
//! path does), so by the time a request reaches here the `(session_key,
//! control_pubkey)` pair is trusted facts.
//!
//! All cryptographic verification of a `Transition`'s #47 upgrade chain link
//! happens HERE, on the node holding the session, against the REPLICATED state
//! (the leader-local [`StateMachineStore`](crate::raft::StateMachineStore)
//! view): exactly the [`Node::handle_transition`](crate::Node) contract,
//! lifted onto the Raft state machine. Only the verified conclusions are
//! submitted as a [`ReplicatedOp`]; followers re-apply them without re-doing
//! crypto (see the [`crate::raft`] module docs' trust argument).
//!
//! ## Leader-only writes + linearizable reads
//!
//! Both `client_write` and `linearizable_get` are leader-only by
//! construction: openraft rejects a write on a follower (`ForwardToLeader`) and
//! refuses to confirm linearizability off a non-leader. So [`handle_on_leader`]
//! only ever succeeds when this node is the leader; a non-leader's caller must
//! FORWARD the request to the leader over the mesh first (see
//! [`super::forward`]). The freshness-oracle rule, never serve a stale read,
//! falls out of using `linearizable_get` for every `Get`.
//!
//! ## Majority ACK
//!
//! Writes (`Pin` / `Register` / `Transition`) are ACKed once
//! [`RaftHandle::client_write`] returns, i.e. once the entry is committed on a
//! quorum of voters (2 of 3) and applied on the leader. That ACK survives the
//! loss of any single node; the argument is in the [`crate::raft`] module docs'
//! "Majority ACK" section. One node down therefore does not stop writes. Losing
//! quorum does: openraft cannot commit, and after
//! [`COMMIT_TIMEOUT`](crate::raft::COMMIT_TIMEOUT) the client gets
//! [`RpcError::Unavailable`] rather than an ACK.
//!
//! ## `Unavailable` after a write means "outcome unknown"
//!
//! A write that timed out stays in the leader's log and may still commit. The
//! answer is therefore never "not applied", and the client must treat it as
//! "maybe applied". It does: a retried Pin names the same `expected_version`,
//! so if the first attempt committed the retry fails the compare-and-swap with
//! `VersionConflict`, and the client's `Get` finds its own commitment; a
//! retried Transition or Revoke is rejected or idempotent in the same way, and
//! the client confirms with `Get`. Timed-out writes are not retried on the
//! server side (see [`super::forward`]), so a lost quorum does not pile up
//! duplicate entries.

use crate::metrics::Answered;
use crate::raft::{RaftHandle, RaftHandleError, ReplicatedOp};
use crate::wire::{
    Request, Response, RpcError, decode_transition_link, verify_revocation_link,
    verify_transition_link,
};
use crate::{CONTROL_PUBKEY_LEN, PcrKey, ValidationError};

/// Run one client [`Request`] from a session authenticated as `session_key`
/// (with `control_pubkey` its announced 65-byte SEC1 P-256 control key) against
/// the LOCAL Raft, which must be the leader.
///
/// `debug_mode` selects the skip-cert-chain (QEMU / test NSM) vs full-Nitro-CA
/// attestation path used when verifying a `Transition`'s chain link, mirroring
/// the single-node [`Node`](crate::Node).
///
/// Returns the [`wire::Response`] to send back to the client. A write that
/// fails because this node is not the leader / quorum is lost surfaces as
/// [`RpcError::Unavailable`]; the caller (the listener on a node that thought it
/// was leader but raced a step-down) should not normally see it because it only
/// calls this after `is_leader`, but it is mapped defensively. When no quorum
/// answers within the commit timeout the response is also `Unavailable`, with
/// [`Answered::timed_out`] set: the write's outcome is unknown and the caller
/// must not resubmit it. The non-leader-forwarding path lives in
/// [`super::forward`].
pub async fn handle_on_leader(
    raft: &RaftHandle,
    session_key: PcrKey,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    req: Request,
    debug_mode: bool,
) -> Answered {
    match req {
        Request::Get { key } => handle_get(raft, session_key, key).await,
        Request::Pin {
            key,
            expected_version,
            commitment,
        } => {
            handle_pin(
                raft,
                session_key,
                key,
                expected_version,
                commitment,
                control_pubkey,
            )
            .await
        }
        Request::Transition { link } => {
            handle_transition(raft, session_key, control_pubkey, link, debug_mode).await
        }
        Request::Revoke { link } => handle_revoke(raft, session_key, link).await,
    }
}

/// Verify a `Revoke`'s revocation chain link and submit a
/// [`ReplicatedOp::Revoke`] for the session's own key.
///
/// The session must hold the pin: its key must be registered in the replicated
/// state, and the link must carry the control signature of that key's FROZEN
/// pubkey ([`verify_revocation_link`]). The lookup reads the leader-local state
/// for the pubkey only; the committed `apply` checks again that the key is
/// still current. Anything but `RevokeOk` means the revocation did not take
/// effect, except a timed-out `Unavailable`, whose outcome is unknown (a
/// revocation is idempotent, so the client simply retries).
async fn handle_revoke(
    raft: &RaftHandle,
    session_key: PcrKey,
    link: crate::wire::ChainLink,
) -> Answered {
    let control_pubkey = match raft.state_machine().get(&session_key).await {
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
    match raft
        .client_write(ReplicatedOp::Revoke {
            key: session_key,
            link_hash: verified.link_hash,
        })
        .await
    {
        Ok(_) => {
            tracing::info!(
                link_hash = %hex_of(&verified.link_hash),
                "upgrade link out of the session key revoked"
            );
            Answered::new(Response::RevokeOk)
        }
        Err(RaftHandleError::Rejected(_)) => err(RpcError::RevocationRejected),
        Err(RaftHandleError::CommitTimeout(_)) => timed_out("revoke"),
        Err(_) => err(RpcError::Unavailable),
    }
}

/// Linearizable read of `key`. A freshness oracle must never serve stale data,
/// so this uses [`RaftHandle::linearizable_get`] (leader + fresh quorum) and
/// NEVER a follower-local read. The redundant `key` must match the session's
/// bound key (belt-and-braces, same as the single-node path).
async fn handle_get(raft: &RaftHandle, session_key: PcrKey, key: PcrKey) -> Answered {
    if key != session_key {
        return err(RpcError::Unauthorized);
    }
    match raft.linearizable_get(&key).await {
        Ok(Some(state)) => Answered::new(Response::GetOk {
            commitment: state.commitment,
            version: state.version,
        }),
        Ok(None) => err(RpcError::NotFound),
        // Not the leader / quorum lost: cannot guarantee freshness. The caller
        // forwards to the leader before reaching here, so on the leader this is
        // a transient quorum loss the client retries.
        Err(RaftHandleError::CommitTimeout(_)) => timed_out("get"),
        Err(_) => err(RpcError::Unavailable),
    }
}

/// Map the single wire `Pin` RPC onto a replicated `Register` (first pin) or
/// `Pin` (re-pin), deciding from the CURRENT leader state (the replicated state
/// machine), then submit it.
///
/// The `expected_version` compare-and-swap guard is enforced by the pure
/// core's deterministic `apply` on the committed entry (identically on every
/// replica), never by this pre-check: it is what stops two live writers for
/// one key (a host-booted clone pair shares the image's PCRs) from forking
/// the pinned history — the loser's first divergent pin is rejected with
/// `VersionConflict` instead of silently last-write-winning. For a first
/// pin the op maps to `Register`, which is inherently a CAS on
/// non-existence, so the guard is ignored there.
///
/// ## The concurrent-first-pin race
///
/// Two enclaves cannot share a `PcrKey` (it is the SHA-256 of their PCR triple),
/// so a key is only ever pinned by one identity. But the SAME enclave can hold
/// two sessions (e.g. a client retry that overlaps the original), and both can
/// observe the key as unregistered and submit `Register`. Only one such
/// `Register` commits; the other is applied as a committed entry that the pure
/// core deterministically rejects with [`ValidationError::AlreadyRegistered`]
/// (the rejection replicates identically on every node). That losing `Register`
/// is a benign race, not a client error: the key IS now registered, so we retry
/// it ONCE as a `Pin`, which is exactly what the client wanted (write a fresh
/// commitment). A second `AlreadyRegistered` cannot happen (the key is live and
/// `Pin` does not check registration that way), so one retry is sufficient and
/// bounded.
async fn handle_pin(
    raft: &RaftHandle,
    session_key: PcrKey,
    key: PcrKey,
    expected_version: crate::Version,
    commitment: crate::Commitment,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
) -> Answered {
    if key != session_key {
        return err(RpcError::Unauthorized);
    }

    // Decide Register vs Pin from the leader's LOCAL applied state. This used
    // to be a `linearizable_get`, which costs a full ReadIndex quorum round on
    // the mesh per Pin; that made the pre-check the most expensive part of the
    // steady-state Pin path. The local read is safe because the decision is
    // only a HINT: the authoritative check is the deterministic pure-core
    // `apply` on the committed entry, and both stale directions are handled:
    //
    // * Local "unregistered" but actually registered (another session's
    //   Register raced us): the committed `Register` is rejected
    //   `AlreadyRegistered` and retried ONCE as a `Pin` below (pre-existing
    //   path).
    // * Local "registered" is always a committed fact (applied state is a
    //   prefix of committed history), and a live key only leaves via that same
    //   enclave's `Transition`; a Pin racing its own retirement surfaces the
    //   core's rejection, exactly as it would have with the linearized read.
    let is_registered = raft.state_machine().get(&key).await.is_some();

    let first_op = if is_registered {
        ReplicatedOp::Pin {
            key,
            expected_version,
            commitment,
        }
    } else {
        ReplicatedOp::Register {
            key,
            commitment,
            control_pubkey,
        }
    };

    match raft.client_write(first_op).await {
        Ok(state) => Answered::new(Response::PinOk {
            version: state.version,
        }),
        // Concurrent first-pin race: our Register lost to another session's
        // Register for the same key. The key is now registered, so retry ONCE
        // as a Pin (bounded, deterministic: a live key's Pin cannot itself hit
        // AlreadyRegistered).
        //
        // The retried Pin carries the caller's `expected_version`, which the
        // CAS then enforces against the just-registered key. This is only
        // reachable in the concurrent-first-pin race (the wire has one Pin
        // RPC for both Register and re-pin), and it is contained: both
        // racers booted from the same snapshot, so their commitments are
        // identical in practice; even in the divergent case the fallback
        // pin wins the CAS (v0 matches) but the loser's client sees
        // `version != 0` and fail-stops, and the "winner"'s next pin hits
        // VersionConflict with a foreign commitment and fail-stops too —
        // conservative stop on both sides, never a silent rollback.
        Err(RaftHandleError::Rejected(ValidationError::AlreadyRegistered)) => {
            match raft
                .client_write(ReplicatedOp::Pin {
                    key,
                    expected_version,
                    commitment,
                })
                .await
            {
                Ok(state) => Answered::new(Response::PinOk {
                    version: state.version,
                }),
                Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
                Err(RaftHandleError::CommitTimeout(_)) => timed_out("pin"),
                // Not the leader any more, or quorum lost: the write is not
                // known to be committed, so never ACK it.
                Err(_) => err(RpcError::Unavailable),
            }
        }
        Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
        // No quorum within the bound: the entry may still commit, so the
        // answer is "outcome unknown", never an ACK.
        Err(RaftHandleError::CommitTimeout(_)) => timed_out("pin"),
        // Raft errors (not the leader any more / quorum lost): the write is not
        // known to be committed on a quorum, so the oracle must not ACK it.
        Err(_) => err(RpcError::Unavailable),
    }
}

/// Verify a `Transition`'s #47 upgrade chain link against the REPLICATED state,
/// then submit a [`ReplicatedOp::Transition`].
///
/// This is exactly the single-node [`Node::handle_transition`](crate::Node)
/// contract, lifted onto Raft:
///
/// 1. `decode_transition_link` to derive `(old_key, new_key)` from the payload.
/// 2. Look up `old_key`'s FROZEN control pubkey in the replicated state machine
///    (`state_machine().get(old_key)`); a transition can only retire a live key.
/// 3. `verify_transition_link` against that frozen pubkey + the session key
///    (the NEW enclave submits, so `new_key == session_key`), with the
///    leader's own NSM time as `now` for the payload's `valid_from` gate.
/// 4. Submit `ReplicatedOp::Transition { old_key, new_key, new_control_pubkey:
///    control_pubkey }`, where `control_pubkey` is the submitting (new-enclave)
///    session's announced key. The verifier requires `new_key == session_key`,
///    so the session's `control_pubkey` IS the new key's attested pubkey;
///    followers record it before applying so the pure core's `NewKeyNotAttested`
///    check passes.
///
/// The `old_key` lookup reads the leader-local state machine directly rather
/// than through `linearizable_get`: a Transition is a write, and `client_write`
/// re-applies the op against the committed log on a quorum, so the authoritative
/// decision is the replicated `apply`, not this pre-check. The pre-check only
/// fetches the frozen pubkey the verifier needs; a stale read here can at worst
/// cause a spurious `TransitionRejected` (old key not yet visible), never an
/// incorrect accept (the committed `apply` still enforces every structural
/// rule, and the signature was verified against whatever pubkey we read).
async fn handle_transition(
    raft: &RaftHandle,
    session_key: PcrKey,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    link: crate::wire::ChainLink,
    debug_mode: bool,
) -> Answered {
    // Phase one: structurally decode the (still-untrusted) link.
    let decoded = match decode_transition_link(&link) {
        Ok(d) => d,
        Err(_) => return err(RpcError::TransitionRejected),
    };

    // Look up the control pubkey frozen for the DERIVED old_key in the
    // replicated state. The old enclave must already be registered: only a live
    // key can be transitioned away from.
    let old_control_pubkey = match raft.state_machine().get(&decoded.old_key).await {
        Some(state) => state.control_pubkey,
        None => return err(RpcError::TransitionRejected),
    };

    // Trusted time for the link's `valid_from` gate: the leader's own NSM
    // timestamp, never its system clock. Without it the gate cannot be
    // evaluated, so the transition is refused (retryable).
    let now_ms = match crate::trusted_time::now_ms().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "transition refused: trusted time unavailable");
            return err(RpcError::Unavailable);
        }
    };

    // Phase two: cryptographically verify the link against old_key's frozen
    // pubkey and the submitting session key, and check that its `valid_from`
    // has been reached.
    let verified = match verify_transition_link(
        &link,
        decoded,
        session_key,
        &old_control_pubkey,
        debug_mode,
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

    // The submitting (NEW enclave) session's announced control pubkey: the
    // verifier already required `verified.new_key == session_key`, so the
    // session's own `control_pubkey` IS the new key's attested pubkey. Followers
    // record it (observe_attestation) before applying the Transition so the pure
    // core's NewKeyNotAttested check passes.
    match raft
        .client_write(ReplicatedOp::Transition {
            old_key: verified.old_key,
            new_key: verified.new_key,
            new_control_pubkey: control_pubkey,
            link_hash: verified.link_hash,
        })
        .await
    {
        Ok(state) => Answered::new(Response::TransitionOk {
            version: state.version,
        }),
        // KeyNotCurrent from a Transition means the old key isn't registered:
        // a transition rejection, not a Get-style NotFound.
        Err(RaftHandleError::Rejected(ValidationError::KeyNotCurrent)) => {
            err(RpcError::TransitionRejected)
        }
        Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
        // No quorum within the bound: the transition may still commit.
        Err(RaftHandleError::CommitTimeout(_)) => timed_out("transition"),
        // Raft error (not the leader any more / quorum lost): the transition is
        // not known to be committed on a quorum, so do not ACK it.
        Err(_) => err(RpcError::Unavailable),
    }
}

fn err(error: RpcError) -> Answered {
    Answered::new(Response::Err { error })
}

/// `Unavailable` after the commit timeout. For a write the outcome is
/// unknown, which is what the flag records.
fn timed_out(op: &'static str) -> Answered {
    tracing::warn!(
        op,
        "no quorum within the commit timeout; answering Unavailable (a write may still commit)"
    );
    Answered::deadline_elapsed()
}

/// Lowercase hex, for logging a link hash.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
