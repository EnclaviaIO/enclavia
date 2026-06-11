//! Replicated client-request handling (#120, slice 4).
//!
//! Maps a customer enclave's [`wire::Request`] onto the Raft layer. This is the
//! replicated successor to the single-node [`Node`](crate::Node): instead of
//! mutating one in-memory [`StateMachine`](crate::StateMachine) behind a Mutex,
//! it submits verified [`ReplicatedOp`]s through [`RaftHandle::client_write`]
//! (which replicates them to a quorum before applying) and serves reads through
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
//! Both `client_write` and `linearizable_get` are leader-only by construction:
//! openraft rejects a write on a follower (`ForwardToLeader`) and refuses to
//! confirm linearizability off a non-leader. So [`handle_on_leader`] only ever
//! succeeds when this node is the leader; a non-leader's caller must FORWARD the
//! request to the leader over the mesh first (see [`super::forward`]). The
//! freshness-oracle rule, never serve a stale read, falls out of using
//! `linearizable_get` for every `Get`.

use crate::raft::{RaftHandle, RaftHandleError, ReplicatedOp};
use crate::wire::{Request, Response, RpcError, decode_transition_link, verify_transition_link};
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
/// calls this after `is_leader`, but it is mapped defensively. The
/// non-leader-forwarding path lives in [`super::forward`].
pub async fn handle_on_leader(
    raft: &RaftHandle,
    session_key: PcrKey,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    req: Request,
    debug_mode: bool,
) -> Response {
    match req {
        Request::Get { key } => handle_get(raft, session_key, key).await,
        Request::Pin { key, commitment } => {
            handle_pin(raft, session_key, key, commitment, control_pubkey).await
        }
        Request::Transition { link } => {
            handle_transition(raft, session_key, control_pubkey, link, debug_mode).await
        }
    }
}

/// Linearizable read of `key`. A freshness oracle must never serve stale data,
/// so this uses [`RaftHandle::linearizable_get`] (leader + fresh quorum) and
/// NEVER a follower-local read. The redundant `key` must match the session's
/// bound key (belt-and-braces, same as the single-node path).
async fn handle_get(raft: &RaftHandle, session_key: PcrKey, key: PcrKey) -> Response {
    if key != session_key {
        return err(RpcError::Unauthorized);
    }
    match raft.linearizable_get(&key).await {
        Ok(Some(state)) => Response::GetOk {
            commitment: state.commitment,
            version: state.version,
        },
        Ok(None) => err(RpcError::NotFound),
        // Not the leader / quorum lost: cannot guarantee freshness. The caller
        // forwards to the leader before reaching here, so on the leader this is
        // a transient quorum loss the client retries.
        Err(RaftHandleError::NotLinearizable(_)) => err(RpcError::Unavailable),
        Err(_) => err(RpcError::Unavailable),
    }
}

/// Map the single wire `Pin` RPC onto a replicated `Register` (first pin) or
/// `Pin` (re-pin), deciding from the CURRENT leader state (the replicated state
/// machine), then submit it.
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
    commitment: crate::Commitment,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
) -> Response {
    if key != session_key {
        return err(RpcError::Unauthorized);
    }

    // Decide Register vs Pin from the leader's linearized view. A `None`
    // (unregistered) means first-pin -> Register; a present key means re-pin ->
    // Pin. Reading through `linearizable_get` keeps the decision honest on the
    // leader (a stale follower would mis-decide, but only the leader gets here).
    let is_registered = match raft.linearizable_get(&key).await {
        Ok(state) => state.is_some(),
        Err(_) => return err(RpcError::Unavailable),
    };

    let first_op = if is_registered {
        ReplicatedOp::Pin { key, commitment }
    } else {
        ReplicatedOp::Register {
            key,
            commitment,
            control_pubkey,
        }
    };

    match raft.client_write(first_op).await {
        Ok(state) => Response::PinOk {
            version: state.version,
        },
        // Concurrent first-pin race: our Register lost to another session's
        // Register for the same key. The key is now registered, so retry ONCE
        // as a Pin (bounded, deterministic: a live key's Pin cannot itself hit
        // AlreadyRegistered).
        Err(RaftHandleError::Rejected(ValidationError::AlreadyRegistered)) => {
            match raft
                .client_write(ReplicatedOp::Pin { key, commitment })
                .await
            {
                Ok(state) => Response::PinOk {
                    version: state.version,
                },
                Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
                Err(_) => err(RpcError::Unavailable),
            }
        }
        Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
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
///    (the NEW enclave submits, so `new_key == session_key`).
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
) -> Response {
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

    // Phase two: cryptographically verify the link against old_key's frozen
    // pubkey and the submitting session key.
    let verified = match verify_transition_link(
        &link,
        decoded,
        session_key,
        &old_control_pubkey,
        debug_mode,
    ) {
        Ok(v) => v,
        Err(_) => return err(RpcError::TransitionRejected),
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
        })
        .await
    {
        Ok(state) => Response::TransitionOk {
            version: state.version,
        },
        // KeyNotCurrent from a Transition means the old key isn't registered:
        // a transition rejection, not a Get-style NotFound.
        Err(RaftHandleError::Rejected(ValidationError::KeyNotCurrent)) => {
            err(RpcError::TransitionRejected)
        }
        Err(RaftHandleError::Rejected(e)) => err(RpcError::from(e)),
        Err(_) => err(RpcError::Unavailable),
    }
}

fn err(error: RpcError) -> Response {
    Response::Err { error }
}
