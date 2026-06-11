//! Raft network over the slice-2 mesh.
//!
//! openraft's [`RaftNetwork`] / [`RaftNetworkFactory`] are implemented on top
//! of [`Mesh::call`]: each AppendEntries / Vote / InstallSnapshot RPC is
//! CBOR-encoded into a [`MeshRaftRpc`] envelope and sent to the target peer's
//! logical name; the response is the CBOR-encoded openraft reply. On the
//! receiving side, [`RaftRequestHandler`] (installed as the mesh's inbound
//! [`RequestHandler`]) decodes the envelope and dispatches it into the local
//! [`Raft`] instance.
//!
//! Snapshot transfer uses openraft's default `full_snapshot` implementation
//! (the `generic-snapshot-data` feature is OFF), which fragments the snapshot
//! into `InstallSnapshot` RPCs that ride this exact channel. That is what
//! slice 4 leans on for #121 hydration of a restarted node.

use std::sync::Arc;

use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::{Deserialize, Serialize};

use crate::mesh::Mesh;
use crate::mesh::rpc::{MeshPayload, PeerContext, RequestHandler};
use crate::raft::forward::{ForwardedClientRequest, ForwardedClientResponse};
use crate::raft::{MemberRecord, Raft, RaftHandle, RaftHandleError, RaftNodeId, TypeConfig};

/// The outer envelope multiplexed over the mesh's RPC payload namespace.
///
/// Slice 3 sent a bare Raft RPC ([`MeshRaftRpc`]) as the `Mesh::call` body.
/// Slice 4 added a [`ForwardedClientRequest`] class. The #209 membership slice
/// adds a third: a [`Join`](MeshMessage::Join) a (re)started node sends to the
/// leader to be admitted for its configured slot. The same inbound
/// [`RaftRequestHandler`] dispatches all three. The reply shape differs per
/// class: a Raft RPC is answered with a CBOR [`MeshRaftReply`]; a forwarded
/// client request with a CBOR [`ForwardedClientResponse`]; a Join with a CBOR
/// [`JoinReply`].
#[derive(Serialize, Deserialize)]
pub enum MeshMessage {
    /// A Raft consensus RPC (AppendEntries / Vote / InstallSnapshot).
    Raft(MeshRaftRpc),
    /// A customer request a non-leader forwarded to the leader.
    ForwardClient(ForwardedClientRequest),
    /// A membership-join request from a (re)started node for its configured
    /// slot. See [`JoinRequest`].
    Join(JoinRequest),
}

/// A node's request to be admitted into the cluster for its configured slot
/// (#209). Carries ONLY the slot name: there is deliberately NO pubkey field.
///
/// SECURITY CONTRACT (the whole point of #209): the leader takes the
/// candidate's instance pubkey from the JOIN's mutually-attested mesh channel
/// ([`PeerIdentity::mesh_pubkey`](crate::mesh::handshake::PeerIdentity),
/// surfaced to the handler as [`PeerContext`]), NEVER from this payload. A
/// payload pubkey would be host-forgeable, which is exactly the hole the
/// clone-resistant scheme closes, so it is simply not carried. The handler
/// IGNORES anything but the channel identity for its admission decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The configured slot name the candidate wants to occupy. A routing
    /// label, bounded by the cluster's configured names; it confers no
    /// authority (the kernel refuses any name outside the configured set).
    pub slot_name: String,
}

/// The leader's reply to a [`JoinRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinReply {
    /// The candidate is now (or was already) the slot's committed voter.
    Admitted,
    /// The kernel deterministically refused the join (unknown slot / id
    /// collision / corrupt membership). The joiner must NOT retry; the answer
    /// will not change. Carries the kernel's error string for logging.
    Refused(String),
    /// This node is not the leader. Carries the leader's routing name as a
    /// redirect hint when known (`None` = election in progress). The joiner
    /// retries against the hint (or any peer) with backoff.
    NotLeader(Option<String>),
    /// A transient failure executing the membership change (quorum lost, the
    /// leader stepped down mid-change, an internal Raft error). The joiner
    /// retries with backoff.
    Unavailable(String),
}

/// One Raft RPC envelope on the mesh wire. CBOR-encoded inside a
/// [`MeshMessage::Raft`]; the mesh layer treats it as opaque bytes.
#[derive(Serialize, Deserialize)]
pub enum MeshRaftRpc {
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<RaftNodeId>),
    InstallSnapshot(InstallSnapshotRequest<TypeConfig>),
}

/// The CBOR-encoded reply to a [`MeshRaftRpc`]. Each variant carries the
/// openraft response for the matching request; the `Raft::*` call on the
/// receiver cannot fail in a way the caller needs to distinguish here (a Raft
/// error is serialized inside the response types), so a successful mesh
/// round-trip always yields one of these.
#[derive(Serialize, Deserialize)]
enum MeshRaftReply {
    AppendEntries(AppendEntriesResponse<RaftNodeId>),
    Vote(VoteResponse<RaftNodeId>),
    InstallSnapshot(InstallSnapshotResponse<RaftNodeId>),
    /// The receiver could not handle the RPC (decode error, or its local Raft
    /// instance returned a fatal error). Mapped to a network error on the
    /// caller so openraft retries.
    Error(String),
}

/// Builds a [`MeshRaftNetwork`] per target peer. Holds the shared mesh; the
/// target's routing name comes from its [`MemberRecord`] node payload (which
/// openraft hands to [`new_client`](RaftNetworkFactory::new_client)), not a
/// static name<->id table (#209 killed that).
pub struct MeshRaftNetworkFactory {
    mesh: Arc<Mesh>,
}

impl MeshRaftNetworkFactory {
    /// Build the factory over a running mesh.
    pub fn new(mesh: Arc<Mesh>) -> Self {
        Self { mesh }
    }
}

impl RaftNetworkFactory<TypeConfig> for MeshRaftNetworkFactory {
    type Network = MeshRaftNetwork;

    async fn new_client(&mut self, target: RaftNodeId, node: &MemberRecord) -> Self::Network {
        // The target's routing name comes from its committed membership record:
        // `Mesh::call` routes by name, and the record is what the cluster
        // committed for this instance id.
        MeshRaftNetwork {
            mesh: Arc::clone(&self.mesh),
            target,
            target_name: node.name.clone(),
        }
    }
}

/// One directed Raft network connection to a single target peer.
pub struct MeshRaftNetwork {
    mesh: Arc<Mesh>,
    target: RaftNodeId,
    target_name: String,
}

impl MeshRaftNetwork {
    /// CBOR-encode `rpc`, send it to the target over the mesh, decode the
    /// reply. Maps mesh `CallError`s onto openraft `RPCError`s: a
    /// not-connected / dropped channel becomes [`Unreachable`] (so openraft
    /// backs off rather than hammering), anything else a [`NetworkError`].
    async fn call(
        &self,
        rpc: MeshRaftRpc,
    ) -> Result<MeshRaftReply, RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId>>> {
        let mut buf = Vec::new();
        ciborium::into_writer(&MeshMessage::Raft(rpc), &mut buf)
            .map_err(|e| RPCError::Network(NetworkError::new(&CborErr(e.to_string()))))?;

        let resp: MeshPayload = self.mesh.call(&self.target_name, buf).await.map_err(|e| {
            use crate::mesh::CallError;
            match e {
                CallError::NotConnected(_) | CallError::Rpc { .. } => {
                    RPCError::Unreachable(Unreachable::new(&MeshErr(e.to_string())))
                }
                other => RPCError::Network(NetworkError::new(&MeshErr(other.to_string()))),
            }
        })?;

        let reply: MeshRaftReply = ciborium::from_reader(resp.as_slice())
            .map_err(|e| RPCError::Network(NetworkError::new(&CborErr(e.to_string()))))?;
        if let MeshRaftReply::Error(msg) = &reply {
            return Err(RPCError::Network(NetworkError::new(&MeshErr(msg.clone()))));
        }
        Ok(reply)
    }
}

impl RaftNetwork<TypeConfig> for MeshRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<RaftNodeId>,
        RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId>>,
    > {
        match self.call(MeshRaftRpc::AppendEntries(rpc)).await? {
            MeshRaftReply::AppendEntries(r) => Ok(r),
            other => Err(reply_mismatch(self.target, "append_entries", other)),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<RaftNodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<RaftNodeId>, RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId>>>
    {
        match self.call(MeshRaftRpc::Vote(rpc)).await? {
            MeshRaftReply::Vote(r) => Ok(r),
            other => Err(reply_mismatch(self.target, "vote", other)),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<RaftNodeId>,
        RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId, InstallSnapshotError>>,
    > {
        // The shared `call` returns the generic RaftError; remap onto the
        // InstallSnapshot-specialized error type openraft wants here.
        let reply = self
            .call(MeshRaftRpc::InstallSnapshot(rpc))
            .await
            .map_err(remap_rpc_error)?;
        match reply {
            MeshRaftReply::InstallSnapshot(r) => Ok(r),
            other => Err(remap_rpc_error(reply_mismatch(
                self.target,
                "install_snapshot",
                other,
            ))),
        }
    }
}

/// A reply variant that did not match the request kind is a protocol bug;
/// surface it as a network error so openraft retries / logs it.
fn reply_mismatch(
    _target: RaftNodeId,
    rpc: &str,
    got: MeshRaftReply,
) -> RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId>> {
    let kind = match got {
        MeshRaftReply::AppendEntries(_) => "AppendEntries",
        MeshRaftReply::Vote(_) => "Vote",
        MeshRaftReply::InstallSnapshot(_) => "InstallSnapshot",
        MeshRaftReply::Error(_) => "Error",
    };
    RPCError::Network(NetworkError::new(&MeshErr(format!(
        "raft rpc {rpc} got mismatched reply {kind}"
    ))))
}

/// Remap the generic-error `RPCError` the shared `call` produces onto the
/// `InstallSnapshotError`-specialized one openraft's `install_snapshot`
/// signature requires. Only the `Network`/`Unreachable` arms can occur here
/// (the receiver never returns a `RemoteError` over this channel), so the
/// other arms are unreachable in practice but mapped conservatively.
fn remap_rpc_error(
    e: RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId>>,
) -> RPCError<RaftNodeId, MemberRecord, RaftError<RaftNodeId, InstallSnapshotError>> {
    match e {
        RPCError::Unreachable(u) => RPCError::Unreachable(u),
        RPCError::Network(n) => RPCError::Network(n),
        RPCError::Timeout(t) => RPCError::Timeout(t),
        RPCError::PayloadTooLarge(p) => RPCError::PayloadTooLarge(p),
        RPCError::RemoteError(re) => {
            RPCError::Network(NetworkError::new(&MeshErr(format!("remote: {re}"))))
        }
    }
}

/// The mesh's inbound [`RequestHandler`]: decode a [`MeshMessage`] and dispatch
/// it, either a Raft consensus RPC into the local [`Raft`] instance, or a
/// [`ForwardedClientRequest`] (relayed by a non-leader) into the replicated
/// client-request handler. Encodes the matching reply.
///
/// Install this as the mesh's handler (slice 4 wires it in `main.rs`; the
/// NodeViewConsistent harness wires it directly). Holds the local `Raft`
/// handle behind a [`OnceCell`](tokio::sync::OnceCell), because the mesh must
/// be constructed (it owns the inbound handler) BEFORE the `Raft` instance,
/// which needs the mesh for its outbound network. Build the handler with
/// [`deferred`](Self::deferred), pass it to `Mesh::start`, then once
/// [`RaftHandle::new`](crate::raft::RaftHandle::new) has produced the `Raft`,
/// install it with [`set_raft`](Self::set_raft). RPCs that arrive before the
/// `Raft` is installed are answered with a transient error (the peer retries),
/// which is harmless during the brief bootstrap window.
///
/// The forwarded-client path additionally needs the full
/// [`RaftHandle`](crate::raft::RaftHandle) (state machine + linearizable read)
/// and the node's `debug_mode`; those are installed alongside the `Raft` by
/// [`set_serve`](Self::set_serve). A forwarded request arriving before
/// `set_serve` (or addressed to a node that is no longer the leader) is answered
/// with [`RpcError::Unavailable`](crate::wire::RpcError::Unavailable) so the
/// forwarding follower re-resolves the leader and retries.
#[derive(Clone)]
pub struct RaftRequestHandler {
    raft: Arc<tokio::sync::OnceCell<Raft>>,
    /// The full handle + debug-mode flag for serving forwarded client requests.
    /// Installed by [`set_serve`](Self::set_serve) after the `RaftHandle` is
    /// constructed (it cannot exist when the handler is first built, the mesh
    /// owns the handler and is constructed first).
    serve: Arc<tokio::sync::OnceCell<(RaftHandle, bool)>>,
}

impl RaftRequestHandler {
    /// Build a handler with no `Raft` installed yet. Install it later with
    /// [`set_raft`](Self::set_raft). Use this when the mesh is constructed
    /// before the Raft instance.
    pub fn deferred() -> Self {
        Self {
            raft: Arc::new(tokio::sync::OnceCell::new()),
            serve: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Build a handler already bound to a `Raft` instance (for the rare case
    /// the Raft exists first).
    pub fn new(raft: Raft) -> Self {
        let cell = tokio::sync::OnceCell::new();
        let _ = cell.set(raft);
        Self {
            raft: Arc::new(cell),
            serve: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Install the local `Raft` instance. Idempotent: a second call is a
    /// no-op. Returns whether this call set it.
    pub fn set_raft(&self, raft: Raft) -> bool {
        self.raft.set(raft).is_ok()
    }

    /// Install the [`RaftHandle`](crate::raft::RaftHandle) + `debug_mode` used to
    /// serve forwarded client requests on the leader. Idempotent; returns
    /// whether this call set it. Called by [`RaftHandle::enable_serving`]
    /// once the handle exists, so the deferred handler can run the replicated
    /// client-request path for forwards that land here.
    pub fn set_serve(&self, handle: RaftHandle, debug_mode: bool) -> bool {
        self.serve.set((handle, debug_mode)).is_ok()
    }

    async fn dispatch_raft(&self, rpc: MeshRaftRpc) -> MeshRaftReply {
        let Some(raft) = self.raft.get() else {
            return MeshRaftReply::Error("raft not yet installed (bootstrap window)".to_string());
        };
        match rpc {
            MeshRaftRpc::AppendEntries(req) => match raft.append_entries(req).await {
                Ok(r) => MeshRaftReply::AppendEntries(r),
                Err(e) => MeshRaftReply::Error(format!("append_entries: {e}")),
            },
            MeshRaftRpc::Vote(req) => match raft.vote(req).await {
                Ok(r) => MeshRaftReply::Vote(r),
                Err(e) => MeshRaftReply::Error(format!("vote: {e}")),
            },
            MeshRaftRpc::InstallSnapshot(req) => match raft.install_snapshot(req).await {
                Ok(r) => MeshRaftReply::InstallSnapshot(r),
                Err(e) => MeshRaftReply::Error(format!("install_snapshot: {e}")),
            },
        }
    }

    /// Run a forwarded client request on this (leader) node. The forwarding
    /// follower already verified the session attestation and vouches for the
    /// carried facts (see [`crate::raft::forward`]); the leader still runs the
    /// full replicated handler, including the `Transition` chain-link check.
    async fn serve_forwarded(&self, fwd: ForwardedClientRequest) -> ForwardedClientResponse {
        use crate::wire::{Response, RpcError};
        let Some((handle, debug_mode)) = self.serve.get() else {
            // Serve path not yet installed (bootstrap window): tell the
            // forwarder to retry.
            return ForwardedClientResponse(Response::Err {
                error: RpcError::Unavailable,
            });
        };
        let resp = crate::raft::serve::handle_on_leader(
            handle,
            fwd.session_key,
            fwd.control_pubkey,
            fwd.request,
            *debug_mode,
        )
        .await;
        ForwardedClientResponse(resp)
    }

    /// Handle a membership [`JoinRequest`] on this node (#209). The candidate's
    /// instance pubkey is taken from `peer` (its mutually-attested mesh
    /// channel), NEVER from the request payload, which is the whole security
    /// contract. Runs [`RaftHandle::admit`], which runs the frozen kernel and,
    /// on the leader, executes the membership change.
    ///
    /// The handler uses the serve-installed [`RaftHandle`] (the same one the
    /// forward path uses). A join arriving before `set_serve` (bootstrap
    /// window) is answered `Unavailable` so the joiner retries.
    async fn serve_join(&self, peer: &PeerContext, req: JoinRequest) -> JoinReply {
        let Some((handle, _debug_mode)) = self.serve.get() else {
            return JoinReply::Unavailable("raft serve path not yet installed".to_string());
        };
        // SECURITY: candidate pubkey from the attested channel, not the payload.
        match handle.admit(&req.slot_name, &peer.mesh_pubkey).await {
            Ok(_admitted) => JoinReply::Admitted,
            Err(RaftHandleError::JoinRefused(e)) => JoinReply::Refused(e.to_string()),
            Err(RaftHandleError::NotLeader(hint)) => JoinReply::NotLeader(hint),
            Err(e) => JoinReply::Unavailable(format!("{e}")),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for RaftRequestHandler {
    async fn handle(&self, peer: &PeerContext, body: MeshPayload) -> MeshPayload {
        let msg: MeshMessage = match ciborium::from_reader(body.as_slice()) {
            Ok(m) => m,
            Err(e) => {
                // Undecodable body: answer with a Raft error envelope (the most
                // common caller is the Raft network, which treats it as a
                // network error and retries).
                let reply = MeshRaftReply::Error(format!("decode mesh message: {e}"));
                return encode_or_empty(&reply);
            }
        };
        match msg {
            MeshMessage::Raft(rpc) => {
                let reply = self.dispatch_raft(rpc).await;
                encode_or_empty(&reply)
            }
            MeshMessage::ForwardClient(fwd) => {
                let reply = self.serve_forwarded(fwd).await;
                encode_or_empty(&reply)
            }
            MeshMessage::Join(req) => {
                let reply = self.serve_join(peer, req).await;
                encode_or_empty(&reply)
            }
        }
    }
}

/// CBOR-encode a reply, falling back to an empty body on the (unrealistic)
/// encode failure. The caller decodes an empty body as a transport error and
/// retries.
fn encode_or_empty<T: Serialize>(reply: &T) -> MeshPayload {
    let mut buf = Vec::new();
    if ciborium::into_writer(reply, &mut buf).is_err() {
        buf.clear();
    }
    buf
}

/// Minimal `std::error::Error` wrappers so mesh / CBOR failure strings can be
/// fed into openraft's `NetworkError::new` / `Unreachable::new`, which take a
/// `&(impl Error)`.
#[derive(Debug)]
struct MeshErr(String);
impl std::fmt::Display for MeshErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MeshErr {}

#[derive(Debug)]
struct CborErr(String);
impl std::fmt::Display for CborErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CborErr {}
