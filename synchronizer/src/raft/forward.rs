//! Non-leader client-request forwarding over the mesh (#120, slice 4).
//!
//! A customer enclave may dial ANY synchronizer node. Writes (and linearizable
//! reads) only succeed on the leader, so a non-leader must transparently FORWARD
//! the request to the current leader over the existing attested mesh and relay
//! the response back. The client stays dumb: there is no redirect variant on the
//! customer wire protocol, the follower does the redirect internally.
//!
//! ## The forwarded message carries the session FACTS
//!
//! The leader never saw the client's Noise handshake or attestation: the session
//! terminates on the FORWARDING node. So the forwarded message carries the facts
//! the leader needs to act as if it had: the session's [`PcrKey`], its 65-byte
//! SEC1 P-256 control pubkey, and the original [`wire::Request`]. The forwarding
//! node already verified the session's attestation (the listener did, exactly as
//! the single-node path does) before forwarding, and mesh peers are mutually
//! attested same-image nodes (the self-PCR allowlist pins membership to
//! bit-for-bit-identical peers, slice 2). So the leader trusts the forwarded
//! facts for the SAME reason a follower trusts a [`ReplicatedOp`]'s embedded
//! conclusions: the cluster trusts its own members as far as attestation pins
//! them, which is "provably us". The leader then runs the full replicated
//! handler ([`super::serve::handle_on_leader`]) on those facts, including the
//! `Transition` chain-link verification, so the credential check is not skipped,
//! only the session attestation (already done by the forwarder) is.
//!
//! ## Wire multiplexing
//!
//! The forwarded message rides the SAME mesh RPC payload namespace the Raft RPCs
//! use. The mesh's inbound [`RequestHandler`](crate::mesh::rpc::RequestHandler)
//! is a [`RaftRequestHandler`](super::RaftRequestHandler); slice 3 had it decode
//! the body as a Raft RPC. Slice 4 wraps that in an outer
//! [`MeshMessage`](super::network::MeshMessage) enum so the same handler
//! dispatches both Raft RPCs and forwarded client requests cleanly.

use serde::{Deserialize, Serialize};

use crate::raft::RaftHandle;
use crate::wire::{Request, Response, RpcError};
use crate::{CONTROL_PUBKEY_LEN, PcrKey};

/// A bounded number of retries when no leader is currently known (election in
/// progress). Each retry waits [`FORWARD_RETRY_DELAY`] before re-checking the
/// leader hint, so a brief election does not surface as a client error.
pub(crate) const FORWARD_MAX_RETRIES: usize = 20;

/// Delay between leader-hint re-checks while forwarding. 20 * 50ms = 1s total,
/// comfortably longer than the cluster's election timeout (300-600ms) so a
/// normal re-election completes inside the window.
pub(crate) const FORWARD_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// A client request forwarded from a non-leader to the leader, carrying the
/// verified session facts the leader needs (the leader did not see the client's
/// attestation; the forwarding node did and vouches for it, see the module
/// docs' trust argument).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedClientRequest {
    /// The session's attested [`PcrKey`] (SHA-256 of its verified PCR triple).
    pub session_key: PcrKey,
    /// The session's 65-byte SEC1 P-256 control pubkey (from the attestation
    /// document's `user_data`). Needed for a `Register` (frozen into `KeyState`)
    /// and a `Transition` (recorded as the new key's attestation).
    #[serde(with = "crate::raft::control_pubkey_bytes")]
    pub control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    /// The original customer RPC to run on the leader.
    pub request: Request,
}

/// The leader's response to a [`ForwardedClientRequest`], relayed verbatim back
/// to the customer by the forwarding node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedClientResponse(pub Response);

/// Route one client request to the leader and return the response.
///
/// If this node IS the leader, run it locally ([`super::serve::handle_on_leader`]).
/// Otherwise forward it over the mesh to the current leader and relay the reply.
/// Handles a missing leader (election in progress) with a bounded retry, then
/// gives up with [`RpcError::Unavailable`].
///
/// `debug_mode` is only consulted on the LEADER (it verifies the `Transition`
/// chain link); a forwarding follower passes the request through untouched, the
/// leader uses its OWN `debug_mode`.
pub async fn route_client_request(
    raft: &RaftHandle,
    mesh: &crate::mesh::Mesh,
    session_key: PcrKey,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    request: Request,
    debug_mode: bool,
) -> Response {
    for _ in 0..FORWARD_MAX_RETRIES {
        // Leader fast path: serve locally.
        if raft.is_leader().await {
            let resp = super::serve::handle_on_leader(
                raft,
                session_key,
                control_pubkey,
                request.clone(),
                debug_mode,
            )
            .await;
            // A transient Unavailable means we raced a step-down between the
            // is_leader check and the write/read; retry (we may now know a new
            // leader to forward to).
            if !is_transient(&resp) {
                return resp;
            }
            tokio::time::sleep(FORWARD_RETRY_DELAY).await;
            continue;
        }

        // Non-leader: forward to whoever we currently believe is the leader. A
        // `None` leader hint means an election is in progress, wait and
        // re-check. A forwarded reply that is itself transient (the leader
        // stepped down / lost quorum mid-call) or a failed mesh call (the leader
        // is unreachable / mid-reconnect) also falls through to a retry, where
        // the hint may have changed.
        if let Some(leader) = raft.leader_name().await {
            if let Ok(resp) =
                forward_to(mesh, &leader, session_key, control_pubkey, request.clone()).await
            {
                if !is_transient(&resp) {
                    return resp;
                }
            }
        }
        tokio::time::sleep(FORWARD_RETRY_DELAY).await;
    }
    Response::Err {
        error: RpcError::Unavailable,
    }
}

/// Whether a response is a transient failure worth retrying (re-resolve the
/// leader and try again) rather than a definitive answer to relay to the client.
fn is_transient(resp: &Response) -> bool {
    matches!(
        resp,
        Response::Err {
            error: RpcError::Unavailable
        }
    )
}

/// CBOR-encode a [`ForwardedClientRequest`] into the outer [`MeshMessage`],
/// send it to `leader` over the mesh, decode the [`ForwardedClientResponse`].
/// Returns `Err(())` on any transport / decode failure (the caller retries).
async fn forward_to(
    mesh: &crate::mesh::Mesh,
    leader: &str,
    session_key: PcrKey,
    control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    request: Request,
) -> Result<Response, ()> {
    use crate::raft::network::MeshMessage;

    let msg = MeshMessage::ForwardClient(ForwardedClientRequest {
        session_key,
        control_pubkey,
        request,
    });
    let mut buf = Vec::new();
    if ciborium::into_writer(&msg, &mut buf).is_err() {
        return Err(());
    }
    let reply = mesh.call(leader, buf).await.map_err(|_| ())?;
    // The leader answers a forwarded client request with a bare
    // ForwardedClientResponse (NOT wrapped in MeshMessage): the reply channel is
    // unambiguous, the request kind already told the handler what to produce.
    let resp: ForwardedClientResponse = ciborium::from_reader(reply.as_slice()).map_err(|_| ())?;
    Ok(resp.0)
}

/// The replicated [`SessionDispatch`](crate::listener::SessionDispatch): backs
/// the client listener with the Raft cluster instead of a single local
/// [`Node`](crate::Node).
///
/// Holds the node's [`RaftHandle`], a clone of the running [`Mesh`](crate::mesh::Mesh)
/// (to forward to the leader when this node is a follower), and the node's
/// `debug_mode` (for `Transition` chain-link verification on the leader). Each
/// request runs through [`route_client_request`], which serves locally if this
/// node is the leader and forwards over the mesh otherwise.
///
/// Gated on `node` (the same feature the listener it serves is gated on): the
/// `raft` feature alone is the library consensus layer with no listener.
#[cfg(feature = "node")]
#[derive(Clone)]
pub struct ReplicatedDispatch {
    raft: RaftHandle,
    mesh: std::sync::Arc<crate::mesh::Mesh>,
    debug_mode: bool,
}

#[cfg(feature = "node")]
impl ReplicatedDispatch {
    /// Build the dispatcher over a node's Raft handle + its running mesh.
    /// `debug_mode` selects the attestation-verification path for `Transition`
    /// chain links (skip-cert-chain in QEMU / tests, full Nitro CA in prod).
    pub fn new(
        raft: RaftHandle,
        mesh: std::sync::Arc<crate::mesh::Mesh>,
        debug_mode: bool,
    ) -> Self {
        Self {
            raft,
            mesh,
            debug_mode,
        }
    }
}

#[cfg(feature = "node")]
#[async_trait::async_trait]
impl crate::listener::SessionDispatch for ReplicatedDispatch {
    async fn dispatch(
        &self,
        session_key: PcrKey,
        control_pubkey: [u8; CONTROL_PUBKEY_LEN],
        request: Request,
    ) -> Response {
        route_client_request(
            &self.raft,
            &self.mesh,
            session_key,
            control_pubkey,
            request,
            self.debug_mode,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Commitment;

    fn k(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }
    fn pk(b: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        let mut out = [b.wrapping_add(0x80); CONTROL_PUBKEY_LEN];
        out[0] = 0x04;
        out
    }

    /// The forwarded request CBOR-round-trips, including the 65-byte control
    /// pubkey through the byte adapter, so a follower's forward decodes
    /// identically on the leader.
    #[test]
    fn forwarded_request_cbor_round_trips() {
        for request in [
            Request::Get { key: k(1) },
            Request::Pin {
                key: k(2),
                commitment: Commitment([0xab; 32]),
            },
        ] {
            let fwd = ForwardedClientRequest {
                session_key: k(3),
                control_pubkey: pk(3),
                request,
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&fwd, &mut buf).unwrap();
            let back: ForwardedClientRequest = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(fwd, back);
        }
    }

    /// The forwarded response CBOR-round-trips.
    #[test]
    fn forwarded_response_cbor_round_trips() {
        let resp = ForwardedClientResponse(Response::PinOk {
            version: crate::Version(3),
        });
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let back: ForwardedClientResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(resp, back);
    }
}
