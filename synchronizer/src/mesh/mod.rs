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

/// serde adapter for the mesh's nested opaque byte payloads
/// ([`handshake::MeshFrame::Rpc`]'s `envelope`, [`rpc::Envelope`]'s `body`).
///
/// Plain `Vec<u8>` is CBOR-encoded by ciborium as an ARRAY of integers
/// (~1.6-2x the raw size per nesting layer, plus per-element encode/decode
/// work); with two such layers wrapping every replication RPC the payload
/// reached the Noise layer ~3x inflated, which both burned leader CPU and
/// forced the tight `max_payload_entries` / `snapshot_max_chunk_size`
/// ceilings in `raft::default_config`. This adapter emits a CBOR BYTE STRING
/// instead (1x + 5 bytes header), and on decode accepts BOTH encodings so a
/// mixed-version cluster keeps talking during a rolling restart: a new node
/// decodes an old peer's array frames, while old nodes cannot decode the new
/// byte-string frames, so a rollout must roll ALL nodes (one at a time is
/// fine: the rolled node rejoins once a quorum of upgraded peers exists;
/// see the rollout note in the PR).
pub mod cbor_bytes {
    use serde::{Deserializer, Serializer};

    /// Serialize as a CBOR byte string.
    pub fn serialize<S: Serializer>(v: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(v)
    }

    /// Serialize in the LEGACY integer-array encoding (what a plain `Vec<u8>`
    /// field emits). Kept as the emit-side default until every deployed
    /// cluster node runs an accept-both build: a byte-string frame is
    /// undecodable by pre-adapter nodes, which would wedge a one-node-at-a-
    /// time rolling restart (the rolled node's frames get rejected by its
    /// still-old peers and it can never rejoin). Once the fleet is on
    /// accept-both, a follow-up flips emission to [`serialize`].
    pub fn serialize_legacy<S: Serializer>(v: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        use serde::Serialize;
        v.serialize(ser)
    }

    struct BytesOrSeq;

    impl<'de> serde::de::Visitor<'de> for BytesOrSeq {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a byte string or a sequence of bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }

        // The legacy array-of-integers encoding.
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    /// Deserialize from a byte string OR the legacy integer array.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        de.deserialize_any(BytesOrSeq)
    }
}

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
use crate::mesh::rpc::{
    ClientChannel, MeshPayload, PeerContext, RequestHandler, RpcError, serve, spawn_client,
};
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

/// The instance pubkeys of peers this node has attested over INBOUND
/// connections, keyed by the peer's `Hello` name. Populated by the accept loop
/// after a successful mutual attestation; read by the #209 discovery bootstrap
/// so the smallest-name node can build the initial membership from the peers'
/// CHANNEL-attested pubkeys (never a payload).
type ObservedPeers =
    Arc<Mutex<HashMap<PeerName, [u8; enclavia_protocol::attestation::CONTROL_PUBKEY_LEN]>>>;

/// A running peer mesh.
///
/// Construct with [`Mesh::start`]. Drop it (or call [`Mesh::shutdown`]) to tear
/// down every dial loop and the accept loop.
pub struct Mesh {
    /// Per-peer live client channel, kept current by the dial loops.
    peers: HashMap<PeerName, PeerSlot>,
    /// Instance pubkeys observed over inbound (accept-side) attested channels,
    /// keyed by the peer's `Hello` name. See [`ObservedPeers`].
    observed: ObservedPeers,
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

        // Instance pubkeys observed over ANY attested channel (inbound accept
        // OR outbound dial). Created before the dial loops so they can record
        // the peer pubkey they attested, which the #209 bootstrap needs to
        // build a peer's MemberRecord after a successful Join round-trip.
        let observed: ObservedPeers = Arc::new(Mutex::new(HashMap::new()));

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
                Arc::clone(&observed),
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
            Arc::clone(&observed),
        ));
        tasks.push(accept_handle);

        Mesh {
            peers,
            observed,
            tasks,
        }
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

    /// The instance pubkey this node has attested for `peer` over an INBOUND
    /// channel, if it has seen one. Used by the #209 discovery bootstrap to
    /// build the initial membership from the peers' channel-attested pubkeys.
    /// `None` until the peer has dialed in and mutually attested at least once.
    pub async fn observed_peer_pubkey(
        &self,
        peer: &str,
    ) -> Option<[u8; enclavia_protocol::attestation::CONTROL_PUBKEY_LEN]> {
        self.observed.lock().await.get(peer).copied()
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
    observed: ObservedPeers,
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
            &observed,
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
    observed: &ObservedPeers,
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

    // Record the peer's attested instance pubkey under the name we dialed (the
    // mutual Hello below confirms the responder IS that name). The #209
    // bootstrap reads this to build a peer's MemberRecord after a successful
    // Join, so it must be available on the OUTBOUND path too, not only the
    // accept side. The pubkey comes from the attestation handshake, never a
    // payload.
    observed
        .lock()
        .await
        .insert(peer.to_string(), peer_id.mesh_pubkey);

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
            byte_wire: true,
        },
    )
    .await?;
    let (announced, peer_byte_wire) = match read_frame(&mut stream, &mut transport).await? {
        Some(MeshFrame::Hello { from, byte_wire }) => (from, byte_wire),
        Some(_) => return Err("responder's first frame was not Hello".into()),
        None => return Err("responder closed before sending Hello".into()),
    };
    if announced != *peer {
        return Err(format!(
            "responder announced name {announced:?} but we dialed {peer:?} (misrouted or reflected dial)"
        )
        .into());
    }

    // Stand up the RPC client over the established transport, emitting the
    // compact byte-string payload encoding only if the peer announced it can
    // decode it (a pre-adapter peer's Hello carries no flag -> legacy).
    // Publish the live channel so `Mesh::call` can use it, then drive the
    // connection until it ends.
    let (channel, driver) = spawn_client(stream, transport, peer_byte_wire);
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
#[allow(clippy::too_many_arguments)]
async fn accept_loop<R, A, H>(
    config: Arc<MeshConfig>,
    mut acceptor: R,
    attestor: Arc<A>,
    identity: MeshIdentity,
    handler: Arc<H>,
    debug_mode: bool,
    observed: ObservedPeers,
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
        let observed = Arc::clone(&observed);
        conns.spawn(async move {
            if let Err(e) = handle_inbound(
                &config,
                stream,
                attestor.as_ref(),
                &identity,
                handler.as_ref(),
                debug_mode,
                &observed,
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
#[allow(clippy::too_many_arguments)]
async fn handle_inbound<A, H>(
    config: &MeshConfig,
    mut stream: BoxedStream,
    attestor: &A,
    identity: &MeshIdentity,
    handler: &H,
    debug_mode: bool,
    observed: &ObservedPeers,
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
    let (from, peer_byte_wire) = match read_frame(&mut stream, &mut transport).await? {
        Some(MeshFrame::Hello { from, byte_wire }) => (from, byte_wire),
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
            byte_wire: true,
        },
    )
    .await?;
    info!(peer = %from, digest = ?peer_id.pcr_digest, "inbound peer attested, serving RPC");

    // Channel-attributed identity for the handler: the dialer's `Hello` name
    // plus the attested instance pubkey + PCR digest from the handshake. The
    // #209 join handler reads the candidate's pubkey from HERE (the attested
    // channel), never from a request payload.
    let peer = PeerContext {
        name: from.clone(),
        mesh_pubkey: peer_id.mesh_pubkey,
        pcr_digest: peer_id.pcr_digest,
    };
    // Record the channel-attested instance pubkey so the discovery bootstrap
    // (#209) can build the initial membership from peers' attested pubkeys.
    observed
        .lock()
        .await
        .insert(from.clone(), peer_id.mesh_pubkey);
    serve(stream, transport, &peer, handler, peer_byte_wire).await?;
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

#[cfg(test)]
mod cbor_bytes_tests {
    use super::handshake::MeshFrame;

    /// Emission stays on the LEGACY integer-array encoding for now (rolling
    /// compatibility with pre-adapter nodes, see `cbor_bytes::serialize_legacy`),
    /// and legacy frames roundtrip through the accept-both deserializer.
    #[test]
    fn emits_legacy_and_roundtrips() {
        let frame = MeshFrame::Rpc {
            envelope: vec![0xAA; 300],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&frame, &mut buf).unwrap();
        // The legacy encoding writes each 0xAA byte as a 2-byte CBOR integer
        // (0x18 0xAA), so the raw run must NOT appear verbatim.
        assert!(
            !buf.windows(300).any(|w| w.iter().all(|b| *b == 0xAA)),
            "emission switched to byte strings; pre-adapter peers cannot decode this"
        );
        let decoded: MeshFrame = ciborium::from_reader(buf.as_slice()).unwrap();
        match decoded {
            MeshFrame::Rpc { envelope } => assert_eq!(envelope, vec![0xAA; 300]),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// A PRE-ADAPTER decoder (the deployed cluster's current build) must
    /// tolerate our new Hello's `byte_wire` field: serde ignores unknown
    /// fields on internally-tagged enums by default, and the whole rolling
    /// upgrade rests on that. Simulated here with an enum matching the old
    /// wire shape exactly.
    #[test]
    fn old_decoder_ignores_byte_wire_field() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(tag = "frame")]
        enum OldMeshFrame {
            Hello { from: String },
        }
        let mut buf = Vec::new();
        ciborium::into_writer(
            &MeshFrame::Hello {
                from: "node-b".to_string(),
                byte_wire: true,
            },
            &mut buf,
        )
        .unwrap();
        let decoded: OldMeshFrame = ciborium::from_reader(buf.as_slice())
            .expect("old decoder must ignore the unknown byte_wire field");
        match decoded {
            OldMeshFrame::Hello { from } => assert_eq!(from, "node-b"),
        }
    }

    /// And the reverse: an OLD peer's Hello (no `byte_wire` field) decodes on
    /// a new node as `byte_wire: false`, so we emit legacy frames to it.
    #[test]
    fn old_hello_decodes_as_legacy_wire() {
        #[derive(serde::Serialize)]
        #[serde(tag = "frame")]
        enum OldMeshFrame {
            Hello { from: String },
        }
        let mut buf = Vec::new();
        ciborium::into_writer(
            &OldMeshFrame::Hello {
                from: "node-c".to_string(),
            },
            &mut buf,
        )
        .unwrap();
        let decoded: MeshFrame = ciborium::from_reader(buf.as_slice()).unwrap();
        match decoded {
            MeshFrame::Hello { from, byte_wire } => {
                assert_eq!(from, "node-c");
                assert!(!byte_wire, "missing field must default to legacy wire");
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// The FUTURE emit format (a real CBOR byte string) already decodes, so
    /// flipping emission later needs no decode-side change.
    #[test]
    fn decodes_future_byte_string() {
        // Hand-build a byte-string-encoded frame via the adapter's serialize.
        #[derive(serde::Serialize)]
        #[serde(tag = "frame")]
        enum FutureFrame {
            Rpc {
                #[serde(serialize_with = "crate::mesh::cbor_bytes::serialize")]
                envelope: Vec<u8>,
            },
        }
        let mut buf = Vec::new();
        ciborium::into_writer(
            &FutureFrame::Rpc {
                envelope: vec![0xAA; 300],
            },
            &mut buf,
        )
        .unwrap();
        let decoded: MeshFrame = ciborium::from_reader(buf.as_slice()).unwrap();
        match decoded {
            MeshFrame::Rpc { envelope } => assert_eq!(envelope, vec![0xAA; 300]),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// A legacy peer's array-of-integers encoding still decodes (rolling
    /// restart compatibility).
    #[test]
    fn decodes_legacy_integer_array() {
        // Hand-build the legacy encoding: {"frame": "Rpc", "envelope": [1,2,3]}
        // exactly as a pre-byte-string node would emit it (plain Vec<u8>).
        #[derive(serde::Serialize)]
        #[serde(tag = "frame")]
        enum LegacyFrame {
            Rpc { envelope: Vec<u8> },
        }
        let mut buf = Vec::new();
        ciborium::into_writer(
            &LegacyFrame::Rpc {
                envelope: vec![1, 2, 3, 200, 255],
            },
            &mut buf,
        )
        .unwrap();
        let decoded: MeshFrame = ciborium::from_reader(buf.as_slice()).unwrap();
        match decoded {
            MeshFrame::Rpc { envelope } => assert_eq!(envelope, vec![1, 2, 3, 200, 255]),
            other => panic!("wrong frame: {other:?}"),
        }
    }
}
