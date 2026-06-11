//! Mutually-attested peer mesh (#118).
//!
//! Each synchronizer node keeps a long-lived, attested channel to every other
//! node in its configured peer set. This module is the orchestrator: it spawns
//! the per-peer dial loops and the inbound accept loop, performs the boot-time
//! mutual attestation, enforces the self-PCR allowlist, and reconnects with
//! backoff when a peer blips. It exposes an id-correlated request/response API,
//! [`Mesh::call`], that the Raft layer (slice 3) consumes, plus an inbound
//! [`rpc::RequestHandler`] hook the node serves; nothing here is Raft-aware.
//!
//! ## Connection model: one directed connection per ordered peer pair
//!
//! A node *dials* each of its peers and *accepts* their dials. On the A->B
//! dialed connection, A is the RPC client (issues requests, reads responses)
//! and B is the RPC server (reads requests, dispatches to its handler, writes
//! responses). For B to call A, B dials A on its own B->A connection. So
//! [`Mesh::call("B", ..)`](Mesh::call) on node A drives the A->B connection,
//! and node B serves A's requests on its accept side through its
//! [`rpc::RequestHandler`]. This keeps reconnect semantics simple (a dropped
//! connection only affects the dialer's outbound calls) while still giving
//! every ordered pair a full request/response path.
//!
//! Because a same-image cluster's nodes are indistinguishable by attestation
//! (identical PCRs), both ends exchange a [`handshake::MeshFrame::Hello`] frame
//! naming themselves right after attestation: the dialer sends first then
//! reads the responder's, the responder reads then sends (the same strict
//! ping-pong the `Authenticate` exchange uses). The acceptor uses the dialer's
//! `Hello` to attribute the inbound stream and rejects a name outside its peer
//! set; the dialer uses the responder's `Hello` to confirm the relay spliced
//! it to the peer it asked for, and drops the channel on a mismatch (a
//! misrouted or reflected dial), so the dial loop backs off and retries. See
//! that frame's docs for why a routing label among already-attested identical
//! peers is safe.
//!
//! ## Reconnect + backoff
//!
//! A dial loop that loses its connection (peer restart, AZ blip, mesh-host
//! hiccup) re-dials after an exponential backoff with jitter, capped at
//! [`MAX_BACKOFF`]. A restarted peer re-attests on its next successful dial
//! and rejoins transparently. In-flight [`Mesh::call`]s on a dropped
//! connection fail with [`rpc::RpcError::ConnectionClosed`]; the caller (Raft)
//! retries, and the retry lands on the freshly re-established channel.

pub mod attestation;
pub mod config;
pub mod handshake;
pub mod identity;
pub mod rpc;
pub mod transport;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::mesh::attestation::AttestationProvider;
use crate::mesh::config::{MeshConfig, PeerName};
use crate::mesh::handshake::{MeshFrame, Role, mutual_authenticate, read_frame, write_frame};
use crate::mesh::identity::MeshIdentity;
use crate::mesh::rpc::{ClientChannel, MeshPayload, RequestHandler, RpcError, serve, spawn_client};
use crate::mesh::transport::{BoxedStream, MeshAcceptor, MeshDialer};

/// Initial reconnect backoff after a dropped peer connection.
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
/// Cap on the exponential reconnect backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Errors surfaced by [`Mesh::call`].
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// No such peer in the configured peer set.
    #[error("unknown peer: {0}")]
    UnknownPeer(PeerName),
    /// The peer's attested channel is not currently up (never connected yet,
    /// or mid-reconnect). The caller should retry after a backoff.
    #[error("peer {0} is not currently connected")]
    NotConnected(PeerName),
    /// The request was issued but the connection dropped before a response
    /// arrived. The caller should retry; the retry lands on the reconnected
    /// channel.
    #[error("rpc to peer {peer} failed: {source}")]
    Rpc {
        /// The peer the call targeted.
        peer: PeerName,
        /// The underlying RPC failure.
        #[source]
        source: RpcError,
    },
}

/// The currently-live client channel for one peer, swapped by its dial loop on
/// each (re)connect. `None` while the peer is down or mid-handshake.
type PeerSlot = Arc<Mutex<Option<ClientChannel>>>;

/// A running peer mesh.
///
/// Construct with [`Mesh::start`]. Drop it (or call [`Mesh::shutdown`]) to tear
/// down every dial loop and the accept loop.
pub struct Mesh {
    /// Per-peer live client channel, kept current by the dial loops.
    peers: HashMap<PeerName, PeerSlot>,
    /// Spawned tasks (dial loops + accept loop). Aborted on shutdown/drop.
    tasks: Vec<JoinHandle<()>>,
}

impl Mesh {
    /// Start the mesh.
    ///
    /// Spawns one dial loop per configured peer (outbound, this node is the
    /// Noise initiator and RPC client) plus one accept loop draining
    /// `acceptor` (inbound, this node is the Noise responder and RPC server,
    /// dispatching to `handler`). `attestor` produces this node's own
    /// attestation document and `identity` signs each connection's handshake
    /// hash; the self-PCR allowlist in `config` gates which peers are admitted.
    /// `debug_mode` selects the attestation-verification path for *peers'*
    /// documents (skip-cert-chain in QEMU / tests, full Nitro CA chain in
    /// production).
    ///
    /// `dialer` and `acceptor` are the transport: in production the vsock
    /// implementations; in tests, the UDS/in-memory ones behind `test-utils`.
    pub fn start<D, R, A, H>(
        config: MeshConfig,
        dialer: D,
        acceptor: R,
        attestor: A,
        identity: MeshIdentity,
        handler: H,
        debug_mode: bool,
    ) -> Self
    where
        D: MeshDialer + 'static,
        R: MeshAcceptor + 'static,
        A: AttestationProvider + 'static,
        H: RequestHandler + 'static,
    {
        let dialer = Arc::new(dialer);
        let attestor = Arc::new(attestor);
        let handler = Arc::new(handler);
        let config = Arc::new(config);

        let mut peers = HashMap::new();
        let mut tasks = Vec::new();

        // One dial loop per peer (outbound, initiator + RPC client).
        for peer in &config.peers {
            let slot: PeerSlot = Arc::new(Mutex::new(None));
            peers.insert(peer.clone(), Arc::clone(&slot));
            let handle = tokio::spawn(dial_loop(
                Arc::clone(&config),
                peer.clone(),
                Arc::clone(&dialer),
                Arc::clone(&attestor),
                identity.clone(),
                debug_mode,
                slot,
            ));
            tasks.push(handle);
        }

        // One accept loop (inbound, responder + RPC server).
        let accept_handle = tokio::spawn(accept_loop(
            Arc::clone(&config),
            acceptor,
            attestor,
            identity,
            handler,
            debug_mode,
        ));
        tasks.push(accept_handle);

        Mesh { peers, tasks }
    }

    /// Issue an id-correlated request to `peer` over its attested channel and
    /// await the response.
    ///
    /// Returns [`CallError::UnknownPeer`] for a name not in the peer set,
    /// [`CallError::NotConnected`] if the channel is not currently up (the
    /// caller retries after a backoff), or [`CallError::Rpc`] if the
    /// connection dropped mid-call. Many concurrent `call`s to the same peer
    /// are correlated independently by id.
    pub async fn call(&self, peer: &str, payload: MeshPayload) -> Result<MeshPayload, CallError> {
        let slot = self
            .peers
            .get(peer)
            .ok_or_else(|| CallError::UnknownPeer(peer.to_string()))?;
        // Clone the current channel out from under the lock so the call does
        // not hold it across the await (and so a reconnect can swap the slot
        // while a call is in flight on the old channel).
        let channel = {
            let guard = slot.lock().await;
            guard.clone()
        };
        let channel = channel.ok_or_else(|| CallError::NotConnected(peer.to_string()))?;
        channel
            .call(payload)
            .await
            .map_err(|source| CallError::Rpc {
                peer: peer.to_string(),
                source,
            })
    }

    /// The logical names of the configured peers.
    pub fn peers(&self) -> impl Iterator<Item = &PeerName> {
        self.peers.keys()
    }

    /// Whether `peer`'s attested channel is currently up.
    pub async fn is_connected(&self, peer: &str) -> bool {
        match self.peers.get(peer) {
            Some(slot) => slot.lock().await.is_some(),
            None => false,
        }
    }

    /// Tear down all dial loops and the accept loop.
    pub fn shutdown(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Outbound dial loop for one peer. Re-dials with backoff forever; each
/// successful dial attests, sends the `Hello`, publishes a live
/// [`ClientChannel`] into `slot`, and drives the connection until it drops.
#[allow(clippy::too_many_arguments)]
async fn dial_loop<D, A>(
    config: Arc<MeshConfig>,
    peer: PeerName,
    dialer: Arc<D>,
    attestor: Arc<A>,
    identity: MeshIdentity,
    debug_mode: bool,
    slot: PeerSlot,
) where
    D: MeshDialer + ?Sized,
    A: AttestationProvider + ?Sized,
{
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match dial_once(
            &config,
            &peer,
            dialer.as_ref(),
            attestor.as_ref(),
            &identity,
            debug_mode,
            &slot,
        )
        .await
        {
            Ok(()) => {
                // Connection ran and then ended cleanly (peer closed). Clear
                // the slot, reset backoff, and reconnect after a short pause so
                // a flapping peer does not spin us.
                *slot.lock().await = None;
                info!(peer = %peer, "peer connection ended, will reconnect");
                backoff = INITIAL_BACKOFF;
                sleep_with_jitter(INITIAL_BACKOFF).await;
            }
            Err(e) => {
                *slot.lock().await = None;
                warn!(peer = %peer, error = %e, backoff_ms = backoff.as_millis(), "dial/handshake failed, backing off");
                sleep_with_jitter(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// One dial attempt: connect, attest as initiator, send `Hello`, publish the
/// client channel into `slot`, and drive it. Returns `Ok(())` when the
/// connection ends cleanly, or an error if the dial / handshake failed (caller
/// backs off).
#[allow(clippy::too_many_arguments)]
async fn dial_once<D, A>(
    config: &MeshConfig,
    peer: &str,
    dialer: &D,
    attestor: &A,
    identity: &MeshIdentity,
    debug_mode: bool,
    slot: &PeerSlot,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    D: MeshDialer + ?Sized,
    A: AttestationProvider + ?Sized,
{
    let mut stream = dialer.dial(peer).await?;
    let (mut transport, peer_id) = mutual_authenticate(
        &mut stream,
        Role::Initiator,
        attestor,
        identity,
        &config.allowlist,
        debug_mode,
    )
    .await?;
    info!(peer = %peer, digest = ?peer_id.pcr_digest, "outbound peer attested, channel up");

    // Mutual Hello: send ours first (so the acceptor can attribute our
    // stream), then read the responder's and confirm the relay spliced us to
    // the peer we asked for. All nodes have identical PCRs, so attestation
    // cannot distinguish them; the honest self-claimed name is what proves a
    // dial intended for B was not misrouted into C (or reflected back to us).
    // A mismatch drops the connection; the dial loop backs off and retries.
    write_frame(
        &mut stream,
        &mut transport,
        &MeshFrame::Hello {
            from: config.self_name.clone(),
        },
    )
    .await?;
    let announced = match read_frame(&mut stream, &mut transport).await? {
        Some(MeshFrame::Hello { from }) => from,
        Some(_) => return Err("responder's first frame was not Hello".into()),
        None => return Err("responder closed before sending Hello".into()),
    };
    if announced != *peer {
        return Err(format!(
            "responder announced name {announced:?} but we dialed {peer:?} (misrouted or reflected dial)"
        )
        .into());
    }

    // Stand up the RPC client over the established transport. Publish the live
    // channel so `Mesh::call` can use it, then drive the connection until it
    // ends.
    let (channel, driver) = spawn_client(stream, transport);
    *slot.lock().await = Some(channel);
    driver.await?;
    Ok(())
}

/// Inbound accept loop. Accepts peer connections forever; each one attests as
/// responder, reads the dialer's `Hello` to learn the source name, then serves
/// RPC requests through the shared handler. Each accepted connection runs in
/// its own task (tracked in a [`JoinSet`](tokio::task::JoinSet)) so a slow or
/// stuck peer cannot block the others.
///
/// The per-connection serve tasks are tracked in a `JoinSet` OWNED by this
/// loop, so when the loop's task is aborted on [`Mesh::shutdown`] / drop, the
/// `JoinSet` is dropped and every in-flight serve task is aborted too. Without
/// this, a node that restarts would leave its old accept-side serve tasks
/// running, still answering peers from a node that is supposed to be gone (the
/// peer would never notice the connection should have dropped and would keep
/// talking to the dead instance). Finished tasks are reaped opportunistically
/// so the set does not grow without bound.
async fn accept_loop<R, A, H>(
    config: Arc<MeshConfig>,
    mut acceptor: R,
    attestor: Arc<A>,
    identity: MeshIdentity,
    handler: Arc<H>,
    debug_mode: bool,
) where
    R: MeshAcceptor,
    A: AttestationProvider + ?Sized + 'static,
    H: RequestHandler + ?Sized + 'static,
{
    let mut conns = tokio::task::JoinSet::new();
    loop {
        // Reap any finished serve tasks without blocking the accept path.
        while conns.try_join_next().is_some() {}

        let stream = match acceptor.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "mesh accept failed");
                sleep_with_jitter(INITIAL_BACKOFF).await;
                continue;
            }
        };
        let config = Arc::clone(&config);
        let attestor = Arc::clone(&attestor);
        let handler = Arc::clone(&handler);
        let identity = identity.clone();
        conns.spawn(async move {
            if let Err(e) = handle_inbound(
                &config,
                stream,
                attestor.as_ref(),
                &identity,
                handler.as_ref(),
                debug_mode,
            )
            .await
            {
                warn!(error = %e, "inbound peer connection ended with error");
            }
        });
    }
}

/// Drive one accepted connection: attest as responder, read `Hello`, serve RPC
/// requests until the peer closes.
async fn handle_inbound<A, H>(
    config: &MeshConfig,
    mut stream: BoxedStream,
    attestor: &A,
    identity: &MeshIdentity,
    handler: &H,
    debug_mode: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    A: AttestationProvider + ?Sized,
    H: RequestHandler + ?Sized,
{
    let (mut transport, peer_id) = mutual_authenticate(
        &mut stream,
        Role::Responder,
        attestor,
        identity,
        &config.allowlist,
        debug_mode,
    )
    .await?;

    // Mutual Hello, mirroring the Authenticate ping-pong: the responder reads
    // the dialer's Hello first, then sends its own. We accept the dialer's
    // name only if it is in our configured peer set (an attested same-image
    // peer should never announce a name we do not know, but we refuse to
    // attribute traffic to an unconfigured name; self-name is never in the
    // peer set, which also rejects a reflected dial).
    let from = match read_frame(&mut stream, &mut transport).await? {
        Some(MeshFrame::Hello { from }) => from,
        Some(_) => return Err("inbound peer's first frame was not Hello".into()),
        None => return Ok(()),
    };
    if !config.peers.contains(&from) {
        return Err(format!("inbound peer announced unconfigured name {from:?}").into());
    }
    // Announce our own name so the dialer can confirm it reached the peer it
    // dialed (and was not misrouted into a different node by the relay).
    write_frame(
        &mut stream,
        &mut transport,
        &MeshFrame::Hello {
            from: config.self_name.clone(),
        },
    )
    .await?;
    info!(peer = %from, digest = ?peer_id.pcr_digest, "inbound peer attested, serving RPC");

    serve(stream, transport, &from, handler).await?;
    debug!(peer = %from, "inbound peer closed");
    Ok(())
}

/// Sleep `base` plus up to 50% jitter, so a fleet of peers reconnecting after
/// the same blip does not synchronise their retries.
async fn sleep_with_jitter(base: Duration) {
    use rand::Rng;
    let jitter_ms = rand::thread_rng().gen_range(0..=(base.as_millis() as u64 / 2 + 1));
    tokio::time::sleep(base + Duration::from_millis(jitter_ms)).await;
}
