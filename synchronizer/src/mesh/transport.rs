//! Transport abstraction for the peer mesh.
//!
//! Two directions, two traits:
//!
//! * [`MeshDialer`] - outbound. The node dials `mesh-host` over vsock
//!   ([`enclavia_protocol::mesh::MESH_VSOCK_PORT`] = 5009), writes the
//!   [`enclavia_protocol::mesh::Open`] frame naming the peer it wants, then
//!   reads exactly one ack byte. [`enclavia_protocol::mesh::OPEN_ACK_OK`]
//!   means the far relay reached the target's bootstrap listener and the
//!   end-to-end guest-to-guest stream is up; anything else (including EOF)
//!   is a dial failure the orchestrator retries with backoff.
//! * [`MeshAcceptor`] - inbound. The node listens on
//!   [`enclavia_protocol::mesh::SYNCHRONIZER_BOOTSTRAP_PORT`] = 5008 for peer
//!   connections that `mesh-host` relays in. The accepting node never sees
//!   the ack byte: it is consumed between the relays and the dialer.
//!
//! Production is always vsock (this is an in-enclave crate; the production
//! binary unconditionally uses `tokio-vsock`). The `test-utils` feature adds
//! a UDS-backed dialer/acceptor plus an in-process [`MeshHostStub`] that
//! splices dialer-to-target the way the real `mesh-host` does, including
//! writing the ack byte, so the multi-node mesh test can wire three nodes
//! together on a dev machine without booting QEMU.
//!
//! Both directions return a boxed `AsyncRead + AsyncWrite + Send + Unpin` so
//! the handshake and per-peer-pump code stay transport-agnostic.

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// One open byte stream to a peer (through `mesh-host`). Boxed because the
/// vsock and UDS concrete types differ and the mesh layer does not care
/// which.
pub type BoxedStream = Box<dyn AsyncReadWrite + Send + Unpin>;

/// Convenience supertrait: anything `AsyncRead + AsyncWrite + Send + Unpin`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

/// Dials `mesh-host` to reach a named peer (outbound side).
///
/// The dialer opens the raw byte stream, writes the
/// [`enclavia_protocol::mesh::Open`] frame, and reads the single ack byte. It
/// returns the open stream (positioned just past the ack) only on
/// [`enclavia_protocol::mesh::OpenAck::Ok`]; an unsuccessful ack or EOF is
/// returned as an `io::Error` so the orchestrator backs off. The Noise
/// handshake and attestation exchange happen on top, in [`super::handshake`].
#[async_trait]
pub trait MeshDialer: Send + Sync {
    /// Dial the relay, request a splice to `target_peer`, and consume the
    /// ack byte. Returns the open stream ready for the Noise handshake on a
    /// successful ack, or an error (which the orchestrator treats as a
    /// transient dial failure) on a failed/EOF ack or any I/O error.
    async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream>;
}

/// Accepts inbound peer connections relayed in by `mesh-host`.
#[async_trait]
pub trait MeshAcceptor: Send {
    /// Block until a peer connection arrives, then return the raw byte
    /// stream. The Noise handshake (responder side) and attestation
    /// verification happen on top, in [`super::handshake`].
    async fn accept(&mut self) -> io::Result<BoxedStream>;
}

/// Helper shared by every dialer: write the [`Open`] frame, then read the
/// single ack byte, mapping a non-OK ack or EOF to an `io::Error`.
async fn open_and_await_ack<S>(stream: &mut S, target_peer: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use enclavia_protocol::mesh::{Open, OpenAck, read_open_ack, write_open_frame};
    let open = Open {
        target_peer: target_peer.to_string(),
    };
    write_open_frame(stream, &open).await?;
    match read_open_ack(stream).await? {
        OpenAck::Ok => Ok(()),
        OpenAck::Failed(byte) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("mesh relay refused open to {target_peer} (ack byte {byte:#04x})"),
        )),
        OpenAck::Eof => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("mesh relay closed before acking open to {target_peer}"),
        )),
    }
}

/// Production outbound transport: AF_VSOCK to `mesh-host`.
///
/// `cid` is the host CID (2 under both real Nitro and the QEMU /
/// vhost-device-vsock bridge); `port` is
/// [`enclavia_protocol::mesh::MESH_VSOCK_PORT`].
///
/// Always compiled (the production binary needs it). The UDS dialer below is
/// an additive `test-utils` alternative, it does not replace this.
#[derive(Clone, Copy, Debug)]
pub struct VsockMeshDialer {
    /// Host CID to dial (2).
    pub cid: u32,
    /// Mesh relay port on the host (5009).
    pub port: u32,
}

#[async_trait]
impl MeshDialer for VsockMeshDialer {
    async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
        let mut stream = tokio_vsock::VsockStream::connect(self.cid, self.port)
            .await
            .map_err(io::Error::other)?;
        open_and_await_ack(&mut stream, target_peer).await?;
        Ok(Box::new(stream))
    }
}

/// Production inbound transport: AF_VSOCK listener on the bootstrap port.
///
/// Binds `VMADDR_CID_ANY` so it accepts whichever CID `mesh-host` relays the
/// peer connection from. Always compiled; the UDS acceptor below is an
/// additive `test-utils` alternative.
pub struct VsockMeshAcceptor {
    listener: tokio_vsock::VsockListener,
}

impl VsockMeshAcceptor {
    /// Bind the inbound mesh listener on `port`
    /// ([`enclavia_protocol::mesh::SYNCHRONIZER_BOOTSTRAP_PORT`]).
    pub fn bind(port: u32) -> io::Result<Self> {
        // VMADDR_CID_ANY: accept on any CID.
        let listener =
            tokio_vsock::VsockListener::bind(u32::MAX, port).map_err(io::Error::other)?;
        Ok(Self { listener })
    }
}

#[async_trait]
impl MeshAcceptor for VsockMeshAcceptor {
    async fn accept(&mut self) -> io::Result<BoxedStream> {
        let (stream, _addr) = self.listener.accept().await.map_err(io::Error::other)?;
        Ok(Box::new(stream))
    }
}

// ---------------------------------------------------------------------------
// test-utils: UDS-backed dialer/acceptor + an in-process mesh-host stub.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-utils")]
mod test_transport {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use enclavia_protocol::mesh::{read_open_frame, write_open_ack};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    /// In-process stand-in for `mesh-host`, used by the multi-node mesh test.
    ///
    /// Each node registers an inbound UDS path (where its [`UdsMeshAcceptor`]
    /// listens) under its logical name. A [`UdsMeshDialer`] dialing
    /// `target_peer` reaches a per-node relay endpoint owned by this stub;
    /// the relay reads the `Open` frame, resolves the name, dials that node's
    /// inbound socket, writes the ack toward the dialer, and splices, exactly
    /// the resolve-dial-ack-splice the real `mesh-host` does, minus the
    /// inter-host TCP hop.
    #[derive(Clone, Default)]
    pub struct MeshHostStub {
        routes: Arc<Mutex<HashMap<String, PathBuf>>>,
        /// Peer names the stub currently refuses to route to OR from. Used by
        /// fault-injection tests (e.g. the Raft NodeViewConsistent harness) to
        /// partition a node: a dial whose source or target is blocked is acked
        /// FAILED, AND any already-established splice touching the peer is torn
        /// down, exactly as if `mesh-host` (or the network) dropped the peer.
        /// Empty in the steady state.
        blocked: Arc<Mutex<std::collections::HashSet<String>>>,
        /// Notified whenever the blocked set changes, so in-flight relay
        /// splices can re-check and abort if their source/target just became
        /// blocked (a real partition severs live connections, not just new
        /// dials).
        block_changed: Arc<tokio::sync::Notify>,
    }

    impl MeshHostStub {
        /// Fresh, empty routing table.
        pub fn new() -> Self {
            Self::default()
        }

        /// Register `peer` as reachable at the UDS `path` (that node's inbound
        /// [`UdsMeshAcceptor`] socket).
        pub fn register(&self, peer: impl Into<String>, path: impl Into<PathBuf>) {
            self.routes.lock().unwrap().insert(peer.into(), path.into());
        }

        /// Resolve a peer name to its inbound socket path, if registered.
        fn resolve(&self, peer: &str) -> Option<PathBuf> {
            self.routes.lock().unwrap().get(peer).cloned()
        }

        /// Partition `peer`: every dial to OR from it is refused (acked FAILED)
        /// and every already-established splice touching it is torn down, until
        /// [`unblock`](Self::unblock). Bidirectional, so it models a node whose
        /// network is paused (it can neither receive nor send) the way a real
        /// partition would, which is how the harness forces a leader change.
        pub fn block(&self, peer: impl Into<String>) {
            self.blocked.lock().unwrap().insert(peer.into());
            self.block_changed.notify_waiters();
        }

        /// Heal a previously [`block`](Self::block)ed peer's partition.
        pub fn unblock(&self, peer: &str) {
            self.blocked.lock().unwrap().remove(peer);
            self.block_changed.notify_waiters();
        }

        /// Whether `peer` is currently partitioned.
        fn is_blocked(&self, peer: &str) -> bool {
            self.blocked.lock().unwrap().contains(peer)
        }

        /// A dialer that resolves through this stub, with no source name (so
        /// only the target's block state is consulted). Kept for the existing
        /// mesh tests; the Raft harness uses [`dialer_for`](Self::dialer_for).
        pub fn dialer(&self) -> UdsMeshDialer {
            UdsMeshDialer {
                host: self.clone(),
                source: None,
            }
        }

        /// A dialer tagged with its owning node's name `source`, so the relay
        /// can drop a dial when EITHER end is partitioned (bidirectional
        /// isolation). This is what the Raft fault-injection harness uses.
        pub fn dialer_for(&self, source: impl Into<String>) -> UdsMeshDialer {
            UdsMeshDialer {
                host: self.clone(),
                source: Some(source.into()),
            }
        }
    }

    /// Test outbound transport: connects to the [`MeshHostStub`] relay via an
    /// in-memory duplex pair, writes the `Open` frame, and reads the ack. The
    /// relay half runs as a spawned task that resolves the name and splices.
    #[derive(Clone)]
    pub struct UdsMeshDialer {
        host: MeshHostStub,
        /// The dialing node's own name, if known, so the relay can refuse a
        /// dial when the SOURCE is partitioned (not just the target).
        source: Option<String>,
    }

    #[async_trait]
    impl MeshDialer for UdsMeshDialer {
        async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
            // Model the dialer<->relay link as an in-memory duplex pair: the
            // dialer keeps `client`, the relay task drives `relay`. This lets
            // the relay inject the ack byte and splice to the resolved target
            // exactly as `mesh-host` would, while exercising the real
            // write_open_frame / read_open_ack wire path on the dialer side.
            let (client, relay) = tokio::io::duplex(64 * 1024);
            let host = self.host.clone();
            let target = target_peer.to_string();
            let source = self.source.clone();
            tokio::spawn(async move {
                relay_one(host, relay, source).await;
            });

            let mut client = client;
            open_and_await_ack(&mut client, &target).await?;
            Ok(Box::new(client))
        }
    }

    /// One relay session: read the `Open` frame from the dialer side, resolve
    /// the target, dial its inbound UDS socket, ack accordingly, and splice.
    /// `source` is the dialing node's name (if tagged), so the relay can refuse
    /// a dial whose source is partitioned, not just one whose target is.
    async fn relay_one(host: MeshHostStub, relay: tokio::io::DuplexStream, source: Option<String>) {
        relay_one_to(host, relay, None, source).await
    }

    /// Like [`relay_one`] but, if `override_target` is `Some`, splices the
    /// dialer to THAT peer's inbound socket instead of the one the dialer
    /// named in its `Open` frame. Models a malicious `mesh-host` that
    /// misroutes (or, when the override is the dialer's own node, reflects) a
    /// dial. The dialer's `Open` frame is still read off the wire so the
    /// ack/splice path is identical; only the resolution target differs.
    async fn relay_one_to(
        host: MeshHostStub,
        mut relay: tokio::io::DuplexStream,
        override_target: Option<String>,
        source: Option<String>,
    ) {
        let open = match read_open_frame(&mut relay).await {
            Ok(o) => o,
            Err(_) => return,
        };
        let resolve_name = override_target.as_deref().unwrap_or(&open.target_peer);
        // Partition check: if either the dialing node (source) or the target
        // is currently blocked, refuse the open exactly as if `mesh-host`
        // could not reach the peer. This is how the fault-injection harness
        // drops a link / isolates a node.
        if source.as_deref().is_some_and(|s| host.is_blocked(s)) || host.is_blocked(resolve_name) {
            let _ = write_open_ack(&mut relay, false).await;
            return;
        }
        let path = match host.resolve(resolve_name) {
            Some(p) => p,
            None => {
                // No route: tell the dialer the open failed and close.
                let _ = write_open_ack(&mut relay, false).await;
                return;
            }
        };
        let mut target = match UnixStream::connect(&path).await {
            Ok(s) => s,
            Err(_) => {
                // Target down (e.g. killed node): ack failure.
                let _ = write_open_ack(&mut relay, false).await;
                return;
            }
        };
        // The far relay (modelled here, co-located) reached the target's
        // bootstrap listener: ack OK toward the dialer, then splice the two
        // legs. The OK byte transits back over the same `relay` stream the
        // dialer reads from.
        if write_open_ack(&mut relay, true).await.is_err() {
            return;
        }
        // Splice, but abort the moment either end of this connection becomes
        // partitioned: a real partition severs live connections, not just new
        // dials. We race the byte pump against a watcher that wakes on every
        // block-set change and re-checks. Dropping `relay`/`target` on abort
        // closes both legs, so the peers see EOF and reconnect/re-elect.
        let notify = Arc::clone(&host.block_changed);
        let src = source.clone();
        let tgt = resolve_name.to_string();
        let host2 = host.clone();
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut relay, &mut target) => {}
            _ = async move {
                loop {
                    let notified = notify.notified();
                    if src.as_deref().is_some_and(|s| host2.is_blocked(s))
                        || host2.is_blocked(&tgt)
                    {
                        return;
                    }
                    notified.await;
                }
            } => {}
        }
    }

    /// Test inbound transport: a UDS listener. The stub's relay connects
    /// straight to this socket (it already stripped the dialer's `Open`
    /// frame and emitted the ack), so this acceptor hands the spliced stream
    /// straight up: the first byte it reads is the start of the peer's Noise
    /// handshake.
    pub struct UdsMeshAcceptor {
        listener: UnixListener,
    }

    impl UdsMeshAcceptor {
        /// Bind a UDS listener at `path` (removing any stale socket first).
        pub fn bind(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
            let path = path.as_ref();
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)?;
            Ok(Self { listener })
        }
    }

    #[async_trait]
    impl MeshAcceptor for UdsMeshAcceptor {
        async fn accept(&mut self) -> io::Result<BoxedStream> {
            let (stream, _addr) = self.listener.accept().await?;
            Ok(Box::new(stream))
        }
    }

    /// A dialer whose relay always refuses the open with
    /// [`enclavia_protocol::mesh::OPEN_ACK_FAILED`], for the ack-failure test.
    #[derive(Clone, Copy, Default)]
    pub struct FailingAckDialer;

    #[async_trait]
    impl MeshDialer for FailingAckDialer {
        async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
            let (client, mut relay) = tokio::io::duplex(4096);
            let target = target_peer.to_string();
            tokio::spawn(async move {
                // Drain the Open frame, then ack failure.
                let _ = read_open_frame(&mut relay).await;
                let _ = write_open_ack(&mut relay, false).await;
            });
            let mut client = client;
            open_and_await_ack(&mut client, &target).await?;
            Ok(Box::new(client))
        }
    }

    /// A dialer whose relay drops the connection right after the `Open`
    /// frame, before writing any ack, for the EOF-ack test.
    #[derive(Clone, Copy, Default)]
    pub struct EofAckDialer;

    #[async_trait]
    impl MeshDialer for EofAckDialer {
        async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
            let (client, mut relay) = tokio::io::duplex(4096);
            let target = target_peer.to_string();
            tokio::spawn(async move {
                let _ = read_open_frame(&mut relay).await;
                // Drop `relay` without acking: the dialer sees EOF.
                drop(relay);
            });
            let mut client = client;
            open_and_await_ack(&mut client, &target).await?;
            Ok(Box::new(client))
        }
    }

    /// A garbage-emitting dialer: after a successful-looking ack it sends a
    /// 4-byte length prefix far over the mesh frame cap, so the responder's
    /// handshake/first-frame read rejects it. Used to prove oversized/garbage
    /// inbound frames are refused without wedging the node. The relay splices
    /// to a real target inbound socket.
    pub struct GarbageDialer {
        /// The stub that resolves and splices to the target's inbound socket.
        pub host: MeshHostStub,
    }

    #[async_trait]
    impl MeshDialer for GarbageDialer {
        async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
            let (client, relay) = tokio::io::duplex(64 * 1024);
            let host = self.host.clone();
            let target = target_peer.to_string();
            tokio::spawn(async move {
                relay_one(host, relay, None).await;
            });
            let mut client = client;
            open_and_await_ack(&mut client, &target).await?;
            // Skip the Noise handshake entirely; emit a giant length prefix
            // followed by junk. The responder's mesh frame reader caps frame
            // size, and the Noise responder handshake will fail on the junk.
            let bogus_len: u32 = enclavia_protocol::mesh::MAX_OPEN_FRAME_SIZE; // any nonsense
            client.write_all(&bogus_len.to_be_bytes()).await?;
            client.write_all(&[0xde, 0xad, 0xbe, 0xef]).await?;
            client.flush().await?;
            // Park so the stream stays open while the responder rejects it.
            let mut sink = [0u8; 16];
            let _ = client.read(&mut sink).await;
            Ok(Box::new(client))
        }
    }

    /// A malicious dialer/relay that ignores the dialed peer name and always
    /// splices the dialer to `actual_target`'s inbound socket. With
    /// `actual_target` set to a different (but still valid, same-image) peer it
    /// models a misrouted dial; set to the dialer's OWN node it models a
    /// reflection. The dialer's mutual-`Hello` check must reject the resulting
    /// channel because the responder honestly announces `actual_target`, not
    /// the name the dialer asked for.
    #[derive(Clone)]
    pub struct MisroutingDialer {
        /// The stub that resolves and splices to inbound sockets.
        pub host: MeshHostStub,
        /// The peer whose inbound socket every dial is spliced to, regardless
        /// of the name in the `Open` frame.
        pub actual_target: String,
    }

    #[async_trait]
    impl MeshDialer for MisroutingDialer {
        async fn dial(&self, target_peer: &str) -> io::Result<BoxedStream> {
            let (client, relay) = tokio::io::duplex(64 * 1024);
            let host = self.host.clone();
            let actual = self.actual_target.clone();
            tokio::spawn(async move {
                relay_one_to(host, relay, Some(actual), None).await;
            });
            let mut client = client;
            open_and_await_ack(&mut client, target_peer).await?;
            Ok(Box::new(client))
        }
    }
}

#[cfg(feature = "test-utils")]
pub use test_transport::{
    EofAckDialer, FailingAckDialer, GarbageDialer, MeshHostStub, MisroutingDialer, UdsMeshAcceptor,
    UdsMeshDialer,
};
