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

use openraft::BasicNode;
use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::{Deserialize, Serialize};

use crate::mesh::Mesh;
use crate::mesh::rpc::{MeshPayload, RequestHandler};
use crate::raft::{NodeIdMap, Raft, RaftNodeId, TypeConfig};

/// One Raft RPC envelope on the mesh wire. CBOR-encoded into a
/// [`MeshPayload`]; the mesh layer treats it as opaque bytes.
#[derive(Serialize, Deserialize)]
enum MeshRaftRpc {
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

/// Builds a [`MeshRaftNetwork`] per target peer. Holds the shared mesh and the
/// name <-> id mapping so it can translate openraft's [`RaftNodeId`] target
/// back to the logical peer name [`Mesh::call`] routes by.
pub struct MeshRaftNetworkFactory {
    mesh: Arc<Mesh>,
    ids: NodeIdMap,
}

impl MeshRaftNetworkFactory {
    /// Build the factory over a running mesh and the cluster's id mapping.
    pub fn new(mesh: Arc<Mesh>, ids: NodeIdMap) -> Self {
        Self { mesh, ids }
    }
}

impl RaftNetworkFactory<TypeConfig> for MeshRaftNetworkFactory {
    type Network = MeshRaftNetwork;

    async fn new_client(&mut self, target: RaftNodeId, _node: &BasicNode) -> Self::Network {
        let target_name = self
            .ids
            .name_of(target)
            .map(|s| s.to_string())
            .unwrap_or_default();
        MeshRaftNetwork {
            mesh: Arc::clone(&self.mesh),
            target,
            target_name,
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
    ) -> Result<MeshRaftReply, RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>> {
        let mut buf = Vec::new();
        ciborium::into_writer(&rpc, &mut buf)
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
        RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>,
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
    ) -> Result<VoteResponse<RaftNodeId>, RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>>
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
        RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId, InstallSnapshotError>>,
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
) -> RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>> {
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
    e: RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>,
) -> RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId, InstallSnapshotError>> {
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

/// The mesh's inbound [`RequestHandler`]: decode a [`MeshRaftRpc`] and dispatch
/// it into the local [`Raft`] instance, encoding the reply.
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
#[derive(Clone)]
pub struct RaftRequestHandler {
    raft: Arc<tokio::sync::OnceCell<Raft>>,
}

impl RaftRequestHandler {
    /// Build a handler with no `Raft` installed yet. Install it later with
    /// [`set_raft`](Self::set_raft). Use this when the mesh is constructed
    /// before the Raft instance.
    pub fn deferred() -> Self {
        Self {
            raft: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Build a handler already bound to a `Raft` instance (for the rare case
    /// the Raft exists first).
    pub fn new(raft: Raft) -> Self {
        let cell = tokio::sync::OnceCell::new();
        let _ = cell.set(raft);
        Self {
            raft: Arc::new(cell),
        }
    }

    /// Install the local `Raft` instance. Idempotent: a second call is a
    /// no-op. Returns whether this call set it.
    pub fn set_raft(&self, raft: Raft) -> bool {
        self.raft.set(raft).is_ok()
    }

    async fn dispatch(&self, body: MeshPayload) -> MeshRaftReply {
        let Some(raft) = self.raft.get() else {
            return MeshRaftReply::Error("raft not yet installed (bootstrap window)".to_string());
        };
        let rpc: MeshRaftRpc = match ciborium::from_reader(body.as_slice()) {
            Ok(r) => r,
            Err(e) => return MeshRaftReply::Error(format!("decode raft rpc: {e}")),
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
}

#[async_trait::async_trait]
impl RequestHandler for RaftRequestHandler {
    async fn handle(&self, _from: &str, body: MeshPayload) -> MeshPayload {
        let reply = self.dispatch(body).await;
        let mut buf = Vec::new();
        // Encoding our own reply enum cannot realistically fail; if it
        // somehow does, fall back to an empty body (the caller decodes it as a
        // network error and retries).
        if ciborium::into_writer(&reply, &mut buf).is_err() {
            buf.clear();
        }
        buf
    }
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
