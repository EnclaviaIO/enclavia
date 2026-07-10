//! In-enclave egress daemon. Owns a TUN device, runs a userspace TCP/IP
//! stack on it, and for every accepted outbound TCP connection dials
//! `egress-host` over vsock to splice bytes to the destination.
//!
//! Allowlist enforcement is wired through the [`ConnectPolicy`]
//! trait: [`StaticAllowlistPolicy`] reads `/etc/enclavia/egress.json`
//! at boot, classifies entries into IP literals, CIDR blocks, and
//! hostname entries, and denies anything not on the list. Hostname
//! entries are enforced by calling out to a separate `unbound`
//! process running inside the EIF (listening on `127.0.0.1:53`): the
//! policy issues an A query for every hostname entry whose port + proto
//! matches the connect, and admits the connect iff its IP appears in
//! any returned answer set. `unbound` owns DNSSEC validation, caching,
//! upstream forwarding (DNS-over-TCP) and retries. [`AllowAll`] is kept
//! around for tests that want to bypass enforcement.

pub mod config;
pub mod policy;
pub mod resolver;
pub mod stack;
pub mod transport;

pub use config::{
    assemble_from_cli, parse_cli_entry, parse_cli_resolver, validate_json, AllowlistConfig,
    AllowlistEntry, AllowlistFlagError, AllowlistLoadError, Config, DnsMode, HostMatcher,
    HostnameEntry, PortMatcher, Protocol, RawAllowlist, RawEgressEntry, RawPort, SCHEMA_VERSION,
};
pub use policy::{AllowAll, ConnectPolicy, PolicyDecision, StaticAllowlistPolicy};
pub use resolver::{Resolver, UnboundClient};
#[cfg(any(test, feature = "test-utils"))]
pub use resolver::MockResolver;
pub use transport::{EgressTransport, VsockTransport};
#[cfg(feature = "test-utils")]
pub use transport::UdsTransport;

/// Mirror every `resolvers[i]:53/tcp` entry into the allowlist's IP
/// literal list.
///
/// The chicken-and-egg: `unbound` runs inside the enclave and forwards
/// to the operator-supplied resolvers (e.g. `1.1.1.1`) over DNS-over-TCP.
/// Those forwarder connections flow through the same `tun0 → smoltcp →
/// enclavia-egress → vsock → egress-host` path as workload traffic, so
/// the egress policy MUST allow them. Rather than make the operator
/// spell out the resolver IP+port in `egress.json` (and risk drift if
/// the JSON only has hostname-based resolvers later), we synthesize
/// `resolvers[i]:53/tcp` literal entries at boot. The auto-injected
/// entries are returned for logging.
///
/// The injected entries are flagged `trusted_source_only`: they exist
/// for `unbound`, not for the workload, so the policy only honours
/// them for connections sourced from the daemon's trusted address
/// (the init netns, where `unbound` lives). Without the flag a
/// workload could sidestep the in-enclave resolver entirely by
/// dialing the upstream resolvers on TCP/53 itself (the
/// resolver-bypass hardening). Under the pre-netns-split
/// topology workload traffic also sources from the trusted address,
/// so the flag is a no-op there; it bites once the builder moves the
/// workload behind its own netns/veth.
pub fn inject_resolver_entries(cfg: &mut AllowlistConfig) -> Vec<std::net::SocketAddrV4> {
    let mut injected = Vec::with_capacity(cfg.resolvers.len());
    for resolver in cfg.resolvers.clone() {
        cfg.push_entry(AllowlistEntry {
            host: HostMatcher::Literal(resolver),
            port: PortMatcher::Single(53),
            protocol: Protocol::Tcp,
            trusted_source_only: true,
        });
        injected.push(std::net::SocketAddrV4::new(resolver, 53));
    }
    injected
}

use std::net::SocketAddrV4;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use enclavia_protocol::egress::{write_open_frame, Open};

/// Forward one accepted TCP flow to `egress-host`.
///
/// Runs the `(src, dst)` pair through `policy`, dials the transport,
/// sends the `Open` frame, and splices bytes between the in-stack TCP
/// socket and the transport. The function returns once either half
/// closes or the transport errors.
pub async fn forward_flow<S, T, P>(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    mut local: S,
    transport: &T,
    policy: &P,
) -> Result<(), ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: EgressTransport,
    P: ConnectPolicy,
{
    match policy.allow_tcp(*src.ip(), dst).await {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            warn!(%src, %dst, "Egress policy denied TCP connection");
            return Err(ForwardError::Denied(dst));
        }
    }

    let mut remote = transport.connect().await.map_err(ForwardError::Transport)?;
    write_open_frame(
        &mut remote,
        &Open::Tcp {
            host: *dst.ip(),
            port: dst.port(),
        },
    )
    .await
    .map_err(ForwardError::Frame)?;

    info!(%dst, "Egress relay established");
    // vsock cannot carry single writes larger than ~32 KiB (empirical). Cap
    // both directions so neither side issues a write that exceeds the limit.
    match tokio::io::copy_bidirectional_with_sizes(
        &mut local,
        &mut remote,
        VSOCK_CHUNK_BYTES,
        VSOCK_CHUNK_BYTES,
    )
    .await
    {
        Ok((sent, received)) => {
            info!(%dst, sent, received, "Egress relay closed");
            Ok(())
        }
        Err(e) => Err(ForwardError::Splice(e)),
    }
}

const VSOCK_CHUNK_BYTES: usize = 32 * 1024;

/// Errors that can terminate one flow.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("policy denied connection to {0}")]
    Denied(SocketAddrV4),
    #[error("transport dial failed: {0}")]
    Transport(std::io::Error),
    #[error("Open frame write failed: {0}")]
    Frame(std::io::Error),
    #[error("splice error: {0}")]
    Splice(std::io::Error),
}

/// One accepted outbound TCP flow surfaced by the in-stack accept loop:
/// a destination address plus a bidirectional byte stream that bridges
/// the smoltcp socket.
///
/// The stack hands these out via an [`mpsc::Receiver`]; the caller spawns
/// a forwarding task per flow and lets it run through to completion.
pub struct AcceptedFlow {
    /// Source endpoint from the SYN. Under the netns-split topology
    /// this distinguishes workload traffic (veth subnet) from
    /// init-netns infra traffic (`unbound`, sourced from the tun
    /// address); the policy uses it to gate `trusted_source_only`
    /// entries.
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub stream: stack::FlowStream,
}

/// Spawn one per-flow forwarder per accepted connection.
///
/// The supervisor consumes `flows`, runs each flow through `forward_flow`
/// using the shared `transport` and `policy`, and returns once the
/// channel is closed (which happens when the stack task ends).
pub async fn run_supervisor<T, P>(
    mut flows: mpsc::Receiver<AcceptedFlow>,
    transport: Arc<T>,
    policy: Arc<P>,
) where
    T: EgressTransport + Send + Sync + 'static,
    P: ConnectPolicy + Send + Sync + 'static,
{
    while let Some(flow) = flows.recv().await {
        let transport = transport.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_flow(
                flow.src,
                flow.dst,
                flow.stream,
                transport.as_ref(),
                policy.as_ref(),
            )
            .await
            {
                error!(src = %flow.src, dst = %flow.dst, "Flow forwarding failed: {e}");
            }
        });
    }
}
