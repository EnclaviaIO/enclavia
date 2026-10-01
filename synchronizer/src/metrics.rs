//! Operational metrics and the one-way exporter that ships them to the host.
//!
//! Every counter here is an atomic. The code paths being measured (the
//! customer listener, the mesh, Raft serving, join) only ever bump one; none
//! of them awaits, locks, or allocates for metrics. A separate task
//! ([`run_exporter`]) reads the atomics plus openraft's metrics watch every
//! [`EXPORT_INTERVAL`], builds a
//! [`SynchronizerSample`](enclavia_protocol::synchronizer_metrics::SynchronizerSample)
//! and delivers it to the parent instance.
//!
//! ## One-way delivery
//!
//! The host is untrusted, so the exporter must not give it a way in:
//!
//! * The exporter dials out ([`MetricsSink`]); it never listens.
//! * [`send_frame`] is generic over `AsyncWrite` only. There is no read
//!   bound, so no code on the send path can read the socket. On vsock and
//!   UDS the read side is also shut down right after connect, so bytes the
//!   host sends are discarded by the kernel.
//! * One frame per connection, bounded by
//!   [`MAX_SAMPLE_FRAME_SIZE`](enclavia_protocol::synchronizer_metrics::MAX_SAMPLE_FRAME_SIZE),
//!   then the write side is shut down and the socket dropped.
//! * Connect plus write run under [`SEND_TIMEOUT`]. A failed or timed-out
//!   send drops that sample and counts it; nothing is queued or retried.
//!
//! The host can still fake, drop or replay samples. Nothing may trust the
//! values; they are for dashboards and alerts only.
//!
//! ## What is not measured
//!
//! * Ping round-trip time is only observed when a channel was idle long
//!   enough to be pinged ([`crate::mesh::rpc::IDLE_BEFORE_PING`]). Raft
//!   heartbeats keep the leader's outbound channels busy, so in practice
//!   the value comes from followers' channels to the leader.
//! * The age of the last nitro-timesync clock step is not visible to this
//!   process; the clock offset against a fresh NSM timestamp is exported
//!   instead.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use enclavia_protocol::attestation::RejectionReason;
use enclavia_protocol::synchronizer_metrics as sample;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::wire::{Request, Response, RpcError};

/// How often a sample is exported.
pub const EXPORT_INTERVAL: Duration = Duration::from_secs(15);

/// Upper bound on one delivery: connect, write the frame, shut down the
/// write side.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on building one sample.
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on the clock probe (one own NSM attestation).
pub const CLOCK_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bounds of the RPC latency buckets, in milliseconds. A final
/// `+Inf` bucket follows.
pub const RPC_LATENCY_BOUNDS_MS: [u32; 12] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

const N_BUCKETS: usize = RPC_LATENCY_BOUNDS_MS.len() + 1;

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// Customer RPC kind, one per request variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcKind {
    /// `Request::Get`.
    Get,
    /// `Request::Pin`.
    Pin,
    /// `Request::Register`.
    Register,
    /// `Request::Transition`.
    Transition,
    /// `Request::Revoke`.
    Revoke,
}

impl RpcKind {
    /// Every kind, in label order.
    pub const ALL: [RpcKind; 5] = [
        RpcKind::Get,
        RpcKind::Pin,
        RpcKind::Register,
        RpcKind::Transition,
        RpcKind::Revoke,
    ];

    /// Metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            RpcKind::Get => "get",
            RpcKind::Pin => "pin",
            RpcKind::Register => "register",
            RpcKind::Transition => "transition",
            RpcKind::Revoke => "revoke",
        }
    }

    /// The kind `request` is counted under.
    pub fn of_request(request: &Request) -> Self {
        match request {
            Request::Get { .. } => RpcKind::Get,
            Request::Pin { .. } => RpcKind::Pin,
            Request::Register { .. } => RpcKind::Register,
            Request::Transition { .. } => RpcKind::Transition,
            Request::Revoke { .. } => RpcKind::Revoke,
        }
    }
}

/// How a customer RPC ended: `ok`, or the [`RpcError`] it returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcOutcome {
    /// A successful response.
    Ok,
    /// [`RpcError::Unauthorized`].
    Unauthorized,
    /// [`RpcError::NotFound`].
    NotFound,
    /// [`RpcError::AlreadyRegistered`].
    AlreadyRegistered,
    /// [`RpcError::TransitionRejected`].
    TransitionRejected,
    /// [`RpcError::OperationRejected`].
    OperationRejected,
    /// [`RpcError::VersionConflict`].
    VersionConflict,
    /// [`RpcError::Unavailable`].
    Unavailable,
    /// [`RpcError::Unavailable`] because a deadline elapsed while waiting for
    /// a quorum (see [`Answered::timed_out`]). For a write the outcome is
    /// unknown: the entry may still commit.
    Timeout,
    /// [`RpcError::TransitionRevoked`].
    TransitionRevoked,
    /// [`RpcError::RevocationRejected`].
    RevocationRejected,
}

impl RpcOutcome {
    /// Every outcome, in label order.
    pub const ALL: [RpcOutcome; 11] = [
        RpcOutcome::Ok,
        RpcOutcome::Unauthorized,
        RpcOutcome::NotFound,
        RpcOutcome::AlreadyRegistered,
        RpcOutcome::TransitionRejected,
        RpcOutcome::OperationRejected,
        RpcOutcome::VersionConflict,
        RpcOutcome::Unavailable,
        RpcOutcome::Timeout,
        RpcOutcome::TransitionRevoked,
        RpcOutcome::RevocationRejected,
    ];

    /// Metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            RpcOutcome::Ok => "ok",
            RpcOutcome::Unauthorized => "unauthorized",
            RpcOutcome::NotFound => "not_found",
            RpcOutcome::AlreadyRegistered => "already_registered",
            RpcOutcome::TransitionRejected => "transition_rejected",
            RpcOutcome::OperationRejected => "operation_rejected",
            RpcOutcome::VersionConflict => "version_conflict",
            RpcOutcome::Unavailable => "unavailable",
            RpcOutcome::Timeout => "timeout",
            RpcOutcome::TransitionRevoked => "transition_revoked",
            RpcOutcome::RevocationRejected => "revocation_rejected",
        }
    }

    /// The outcome of `answered`: [`RpcOutcome::Timeout`] for an
    /// `Unavailable` produced by an elapsed deadline, otherwise the outcome
    /// of its response.
    pub fn of_answered(answered: &Answered) -> Self {
        match Self::of_response(&answered.response) {
            RpcOutcome::Unavailable if answered.timed_out => RpcOutcome::Timeout,
            other => other,
        }
    }

    /// The outcome of `response`.
    pub fn of_response(response: &Response) -> Self {
        match response {
            Response::Err { error } => match error {
                RpcError::Unauthorized => RpcOutcome::Unauthorized,
                RpcError::NotFound => RpcOutcome::NotFound,
                RpcError::AlreadyRegistered => RpcOutcome::AlreadyRegistered,
                RpcError::TransitionRejected => RpcOutcome::TransitionRejected,
                RpcError::OperationRejected => RpcOutcome::OperationRejected,
                RpcError::VersionConflict => RpcOutcome::VersionConflict,
                RpcError::Unavailable => RpcOutcome::Unavailable,
                RpcError::TransitionRevoked => RpcOutcome::TransitionRevoked,
                RpcError::RevocationRejected => RpcOutcome::RevocationRejected,
            },
            _ => RpcOutcome::Ok,
        }
    }
}

/// A customer response plus how it was produced, for the metrics.
///
/// The wire has one `Unavailable` for "no quorum right now", whether the node
/// found that out at once (not the leader, no leader known) or only after a
/// deadline elapsed. The two differ for a write: after a deadline the write
/// may still commit. `timed_out` keeps them apart in the RPC outcome label
/// without changing the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    /// The response sent to the customer.
    pub response: Response,
    /// The node answered `Unavailable` because a deadline elapsed while it
    /// waited for a quorum.
    pub timed_out: bool,
}

impl Answered {
    /// An answer that did not come from an elapsed deadline.
    pub fn new(response: Response) -> Self {
        Self {
            response,
            timed_out: false,
        }
    }

    /// `Unavailable` because a deadline elapsed.
    pub fn deadline_elapsed() -> Self {
        Self {
            response: Response::Err {
                error: RpcError::Unavailable,
            },
            timed_out: true,
        }
    }
}

impl From<Response> for Answered {
    fn from(response: Response) -> Self {
        Self::new(response)
    }
}

/// Where a rejected attestation document came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionSource {
    /// A customer session's `Authenticate` document.
    Client,
    /// A mesh peer's handshake (document, PCR allowlist, identity signature).
    Peer,
    /// The old enclave's document inside a `Transition` chain link.
    TransitionLink,
}

impl RejectionSource {
    /// Every source, in label order.
    pub const ALL: [RejectionSource; 3] = [
        RejectionSource::Client,
        RejectionSource::Peer,
        RejectionSource::TransitionLink,
    ];

    /// Metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            RejectionSource::Client => "client",
            RejectionSource::Peer => "peer",
            RejectionSource::TransitionLink => "transition_link",
        }
    }
}

/// Label for a [`RejectionReason`] this build does not know yet
/// (`RejectionReason` is `#[non_exhaustive]`).
pub const OTHER_REASON: &str = "other";

const N_REASONS: usize = RejectionReason::ALL.len() + 1;

/// Where this node is in the cluster join state machine
/// ([`crate::raft::join`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum JoinPhase {
    /// Discovery has not started.
    Starting = 0,
    /// Probing peers for a live cluster, waiting to be admitted.
    Discovering = 1,
    /// Initializing a fresh cluster (smallest-name node, no peer knows one).
    Initializing = 2,
    /// A committed voter.
    Voter = 3,
    /// Removed from the membership by a same-slot replacement; Raft is shut
    /// down.
    Evicted = 4,
}

impl JoinPhase {
    /// Every phase, in label order.
    pub const ALL: [JoinPhase; 5] = [
        JoinPhase::Starting,
        JoinPhase::Discovering,
        JoinPhase::Initializing,
        JoinPhase::Voter,
        JoinPhase::Evicted,
    ];

    /// Metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            JoinPhase::Starting => "starting",
            JoinPhase::Discovering => "discovering",
            JoinPhase::Initializing => "initializing",
            JoinPhase::Voter => "voter",
            JoinPhase::Evicted => "evicted",
        }
    }

    fn from_u8(v: u8) -> Self {
        Self::ALL
            .into_iter()
            .find(|p| *p as u8 == v)
            .unwrap_or(JoinPhase::Starting)
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Customer RPC counts by kind and outcome, plus a latency histogram per
/// kind.
#[derive(Debug)]
pub struct RpcStats {
    counts: [[AtomicU64; RpcOutcome::ALL.len()]; RpcKind::ALL.len()],
    buckets: [[AtomicU64; N_BUCKETS]; RpcKind::ALL.len()],
    sum_us: [AtomicU64; RpcKind::ALL.len()],
}

impl RpcStats {
    /// All counters at zero.
    pub const fn new() -> Self {
        Self {
            counts: [const { [const { AtomicU64::new(0) }; RpcOutcome::ALL.len()] };
                RpcKind::ALL.len()],
            buckets: [const { [const { AtomicU64::new(0) }; N_BUCKETS] }; RpcKind::ALL.len()],
            sum_us: [const { AtomicU64::new(0) }; RpcKind::ALL.len()],
        }
    }

    /// Count one completed request.
    pub fn record(&self, kind: RpcKind, outcome: RpcOutcome, elapsed: Duration) {
        let k = kind as usize;
        self.counts[k][outcome as usize].fetch_add(1, Ordering::Relaxed);
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.buckets[k][bucket_index(us)].fetch_add(1, Ordering::Relaxed);
        self.sum_us[k].fetch_add(us, Ordering::Relaxed);
    }

    /// Count one completed request, classified from its response.
    pub fn record_response(&self, kind: RpcKind, response: &Response, elapsed: Duration) {
        self.record(
            kind,
            RpcOutcome::of_response(response),
            elapsed,
        );
    }

    /// Count one completed request, classified from its [`Answered`].
    pub fn record_answered(&self, kind: RpcKind, answered: &Answered, elapsed: Duration) {
        self.record(
            kind,
            RpcOutcome::of_answered(answered),
            elapsed,
        );
    }

    fn sample(&self) -> Vec<sample::RpcKindSample> {
        RpcKind::ALL
            .into_iter()
            .map(|kind| {
                let k = kind as usize;
                sample::RpcKindSample {
                    kind: kind.as_str().to_string(),
                    outcomes: RpcOutcome::ALL
                        .into_iter()
                        .map(|o| sample::OutcomeCount {
                            outcome: o.as_str().to_string(),
                            count: self.counts[k][o as usize].load(Ordering::Relaxed),
                        })
                        .collect(),
                    latency_buckets: self.buckets[k]
                        .iter()
                        .map(|b| b.load(Ordering::Relaxed))
                        .collect(),
                    latency_sum_us: self.sum_us[k].load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}

impl Default for RpcStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Index of the bucket a latency of `us` microseconds falls in.
fn bucket_index(us: u64) -> usize {
    RPC_LATENCY_BOUNDS_MS
        .iter()
        .position(|bound_ms| us <= u64::from(*bound_ms) * 1000)
        .unwrap_or(RPC_LATENCY_BOUNDS_MS.len())
}

/// Attestation rejections by source and reason.
#[derive(Debug)]
pub struct RejectionStats {
    counts: [[AtomicU64; N_REASONS]; RejectionSource::ALL.len()],
}

impl RejectionStats {
    /// All counters at zero.
    pub const fn new() -> Self {
        Self {
            counts: [const { [const { AtomicU64::new(0) }; N_REASONS] };
                RejectionSource::ALL.len()],
        }
    }

    /// Count one rejection.
    pub fn record(&self, source: RejectionSource, reason: RejectionReason) {
        let r = RejectionReason::ALL
            .iter()
            .position(|known| *known == reason)
            .unwrap_or(N_REASONS - 1);
        self.counts[source as usize][r].fetch_add(1, Ordering::Relaxed);
    }

    fn sample(&self) -> Vec<sample::RejectionCount> {
        let labels = RejectionReason::ALL
            .iter()
            .map(|r| r.as_str())
            .chain(std::iter::once(OTHER_REASON));
        let mut out = Vec::with_capacity(RejectionSource::ALL.len() * N_REASONS);
        for source in RejectionSource::ALL {
            for (i, reason) in labels.clone().enumerate() {
                out.push(sample::RejectionCount {
                    source: source.as_str().to_string(),
                    reason: reason.to_string(),
                    count: self.counts[source as usize][i].load(Ordering::Relaxed),
                });
            }
        }
        out
    }
}

impl Default for RejectionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Where customer requests were served (replicated builds).
#[derive(Debug, Default)]
pub struct RouteStats {
    /// Served on this node as leader.
    pub local: AtomicU64,
    /// Forwarded to the leader over the mesh.
    pub forwarded: AtomicU64,
    /// No leader answered within the retry budget.
    pub unavailable: AtomicU64,
    /// Served on this node as leader on behalf of a forwarding peer.
    pub forwarded_served: AtomicU64,
}

impl RouteStats {
    /// All counters at zero.
    pub const fn new() -> Self {
        Self {
            local: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            forwarded_served: AtomicU64::new(0),
        }
    }
}

/// Join state machine phase and leader-side membership changes.
#[derive(Debug, Default)]
pub struct JoinStats {
    phase: AtomicU8,
    /// Join probes sent to peers.
    pub probes: AtomicU64,
    /// Candidates admitted by this node as leader.
    pub admissions: AtomicU64,
    /// Previous slot holders removed by this node as leader.
    pub evictions: AtomicU64,
}

impl JoinStats {
    /// Phase [`JoinPhase::Starting`], counters at zero.
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(JoinPhase::Starting as u8),
            probes: AtomicU64::new(0),
            admissions: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Record the current phase.
    pub fn set_phase(&self, phase: JoinPhase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    /// The current phase.
    pub fn phase(&self) -> JoinPhase {
        JoinPhase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    /// The join part of a sample.
    pub fn sample(&self) -> sample::JoinSample {
        sample::JoinSample {
            phase: self.phase().as_str().to_string(),
            probes: self.probes.load(Ordering::Relaxed),
            admissions: self.admissions.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

/// The process-wide counters. One synchronizer process is one node.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Customer RPCs, counted by the node that holds the session.
    pub rpc: RpcStats,
    /// Attestation rejections.
    pub rejections: RejectionStats,
    /// Request routing (replicated builds).
    pub routes: RouteStats,
    /// Join state (replicated builds).
    pub join: JoinStats,
    /// Samples that could not be built or delivered.
    pub export_failures: AtomicU64,
}

impl Metrics {
    /// All counters at zero.
    pub const fn new() -> Self {
        Self {
            rpc: RpcStats::new(),
            rejections: RejectionStats::new(),
            routes: RouteStats::new(),
            join: JoinStats::new(),
            export_failures: AtomicU64::new(0),
        }
    }

    fn rpc_sample(&self) -> sample::RpcSample {
        sample::RpcSample {
            latency_bounds_ms: RPC_LATENCY_BOUNDS_MS.to_vec(),
            kinds: self.rpc.sample(),
            routed_local: self.routes.local.load(Ordering::Relaxed),
            routed_forwarded: self.routes.forwarded.load(Ordering::Relaxed),
            routed_unavailable: self.routes.unavailable.load(Ordering::Relaxed),
            forwarded_served: self.routes.forwarded_served.load(Ordering::Relaxed),
        }
    }
}

static METRICS: Metrics = Metrics::new();

/// The process-wide counters.
pub fn global() -> &'static Metrics {
    &METRICS
}

/// Count one attestation rejection in the process-wide counters.
pub fn record_rejection(source: RejectionSource, reason: RejectionReason) {
    METRICS.rejections.record(source, reason);
}

/// Counters for one configured peer's outbound mesh channel. Owned by the
/// [`Mesh`](crate::mesh::Mesh); the dial loop and the channel driver update
/// it.
#[derive(Debug, Default)]
pub struct PeerLinkStats {
    connected: AtomicBool,
    channels_established: AtomicU64,
    dial_failures: AtomicU64,
    pings: AtomicU64,
    pong_timeouts: AtomicU64,
    /// Microseconds; 0 means no ping has been answered yet.
    last_ping_rtt_us: AtomicU64,
}

impl PeerLinkStats {
    /// An attested channel came up.
    pub fn channel_up(&self) {
        self.channels_established.fetch_add(1, Ordering::Relaxed);
        self.connected.store(true, Ordering::Relaxed);
    }

    /// The channel went down.
    pub fn channel_down(&self) {
        self.connected.store(false, Ordering::Relaxed);
    }

    /// A dial or handshake attempt failed.
    pub fn dial_failed(&self) {
        self.dial_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A liveness ping was sent.
    pub fn ping_sent(&self) {
        self.pings.fetch_add(1, Ordering::Relaxed);
    }

    /// A liveness ping went unanswered.
    pub fn pong_timed_out(&self) {
        self.pong_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// A liveness ping was answered after `rtt`.
    pub fn ping_answered(&self, rtt: Duration) {
        let us = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX).max(1);
        self.last_ping_rtt_us.store(us, Ordering::Relaxed);
    }

    /// Whether the channel is up.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn sample(&self, peer: &str) -> sample::PeerSample {
        let rtt = self.last_ping_rtt_us.load(Ordering::Relaxed);
        sample::PeerSample {
            peer: peer.to_string(),
            connected: self.connected.load(Ordering::Relaxed),
            channels_established: self.channels_established.load(Ordering::Relaxed),
            dial_failures: self.dial_failures.load(Ordering::Relaxed),
            pings: self.pings.load(Ordering::Relaxed),
            pong_timeouts: self.pong_timeouts.load(Ordering::Relaxed),
            last_ping_rtt_us: (rtt != 0).then_some(rtt),
        }
    }
}

// ---------------------------------------------------------------------------
// Sample assembly
// ---------------------------------------------------------------------------

/// Build the parts of a sample that come from process-wide state: the
/// counters, the mesh peers, and process memory. `raft` / `join` /
/// `clock` / state-size fields are left for the caller.
pub fn base_sample(
    node: &str,
    seq: u64,
    uptime: Duration,
    peers: &[(String, std::sync::Arc<PeerLinkStats>)],
) -> sample::SynchronizerSample {
    let m = global();
    sample::SynchronizerSample {
        version: sample::SAMPLE_VERSION,
        node: node.to_string(),
        seq,
        uptime_s: uptime.as_secs(),
        export_failures: m.export_failures.load(Ordering::Relaxed),
        raft: None,
        join: None,
        peers: peers
            .iter()
            .filter(|(name, _)| sample::is_valid_name(name))
            .take(sample::MAX_PEERS)
            .map(|(name, stats)| stats.sample(name))
            .collect(),
        rpc: m.rpc_sample(),
        rejections: m.rejections.sample(),
        clock: sample::ClockSample::default(),
        resources: sample::ResourceSample {
            rss_bytes: rss_bytes(),
            ..Default::default()
        },
    }
}

/// Resident set size of this process, from `/proc/self/status`.
pub fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_vm_rss(&status)
}

fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let mut parts = line["VmRSS:".len()..].split_whitespace();
    let value: u64 = parts.next()?.parse().ok()?;
    match parts.next() {
        Some("kB") => value.checked_mul(1024),
        _ => None,
    }
}

/// Set while a clock probe's blocking NSM call is running, so a wedged
/// `/dev/nsm` costs at most one parked blocking thread, not one per tick.
#[cfg(feature = "enclave")]
static CLOCK_PROBE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Enclave wall clock minus the NSM attestation timestamp, in milliseconds,
/// from one fresh own attestation. `None` if the probe fails, times out, or
/// a previous probe is still running.
#[cfg(feature = "enclave")]
pub async fn clock_offset_ms() -> Option<i64> {
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            CLOCK_PROBE_IN_FLIGHT.store(false, Ordering::Release);
        }
    }
    if CLOCK_PROBE_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        return None;
    }
    let probe = tokio::task::spawn_blocking(|| {
        let _release = Release;
        let before = std::time::SystemTime::now();
        let doc = crate::mesh::attestation::request_own_attestation(None, None).ok()?;
        let after = std::time::SystemTime::now();
        let nsm_ms = enclavia_protocol::attestation::extract_own_timestamp_ms(&doc).ok()?;
        let wall = |t: std::time::SystemTime| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_millis()).ok())
        };
        let (before, after) = (wall(before)?, wall(after)?);
        let midpoint = before + (after - before) / 2;
        Some(midpoint - i64::try_from(nsm_ms).ok()?)
    });
    tokio::time::timeout(CLOCK_PROBE_TIMEOUT, probe)
        .await
        .ok()?
        .ok()?
}

/// Builds full samples for a replicated (Raft) node.
#[cfg(feature = "raft")]
pub struct ReplicatedCollector {
    node: String,
    raft: crate::raft::RaftHandle,
    mesh: std::sync::Arc<crate::mesh::Mesh>,
    started: std::time::Instant,
}

#[cfg(feature = "raft")]
impl ReplicatedCollector {
    /// Collect from `raft` and `mesh`; uptime counts from `started`.
    pub fn new(
        raft: crate::raft::RaftHandle,
        mesh: std::sync::Arc<crate::mesh::Mesh>,
        started: std::time::Instant,
    ) -> Self {
        Self {
            node: raft.self_record().name.clone(),
            raft,
            mesh,
            started,
        }
    }

    /// Build one sample. Reads atomics and openraft's metrics watch; takes
    /// no lock the Raft apply path uses.
    pub async fn collect(&self, seq: u64) -> sample::SynchronizerSample {
        let mut s = base_sample(
            &self.node,
            seq,
            self.started.elapsed(),
            &self.mesh.peer_link_stats(),
        );
        let metrics = self.raft.raft().metrics().borrow().clone();
        s.raft = Some(raft_sample(&metrics));
        s.join = Some(global().join.sample());
        let store = self.raft.state_machine().stats();
        s.resources.live_keys = Some(store.live_keys);
        s.resources.retired_keys = Some(store.retired_keys);
        s.resources.snapshot_bytes = store.snapshot_bytes;
        #[cfg(feature = "enclave")]
        {
            s.clock.offset_ms = clock_offset_ms().await;
        }
        s
    }
}

/// Map openraft's metrics onto the sample, replacing every node id with the
/// slot name committed for it (ids derive from instance keys and are not
/// exported).
#[cfg(feature = "raft")]
pub fn raft_sample(
    m: &openraft::RaftMetrics<crate::raft::RaftNodeId, crate::raft::MemberRecord>,
) -> sample::RaftSample {
    use openraft::ServerState;
    let membership = m.membership_config.membership();
    let role = match m.state {
        ServerState::Leader => "leader",
        ServerState::Follower => "follower",
        ServerState::Candidate => "candidate",
        ServerState::Learner => "learner",
        ServerState::Shutdown => "shutdown",
    };
    let peer_matched_index = m
        .replication
        .as_ref()
        .map(|replication| {
            replication
                .iter()
                .filter(|(id, _)| **id != m.id)
                .filter_map(|(id, matched)| {
                    let name = &membership.get_node(id)?.name;
                    sample::is_valid_name(name).then(|| sample::PeerMatchedIndex {
                        peer: name.clone(),
                        matched_index: matched.map(|l| l.index),
                    })
                })
                .take(sample::MAX_PEERS)
                .collect()
        })
        .unwrap_or_default();
    sample::RaftSample {
        role: role.to_string(),
        term: m.current_term,
        last_log_index: m.last_log_index,
        last_applied_index: m.last_applied.map(|l| l.index),
        snapshot_index: m.snapshot.map(|l| l.index),
        voters: u32::try_from(membership.voter_ids().count()).unwrap_or(u32::MAX),
        learners: u32::try_from(membership.learner_ids().count()).unwrap_or(u32::MAX),
        has_leader: m.current_leader.is_some(),
        millis_since_quorum_ack: m.millis_since_quorum_ack,
        peer_matched_index,
    }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// Why one delivery failed. The sample is dropped either way.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Connect or write did not finish within the bound.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    /// Connect or write failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Deliver one encoded frame over a fresh connection from `connect`: write
/// it, shut down the write side, drop the connection. The whole exchange is
/// bounded by `timeout`.
///
/// `W` is only `AsyncWrite`: this function cannot read what the host sends.
pub async fn send_frame<F, Fut, W>(connect: F, frame: &[u8], timeout: Duration) -> Result<(), SendError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<W>>,
    W: AsyncWrite + Unpin,
{
    let exchange = async move {
        let mut sink = connect().await?;
        sink.write_all(frame).await?;
        sink.shutdown().await?;
        Ok::<(), io::Error>(())
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result.map_err(SendError::Io),
        Err(_) => Err(SendError::Timeout(timeout)),
    }
}

/// Where samples go.
#[derive(Clone, Debug)]
pub enum MetricsSink {
    /// vsock to the parent (`cid` is the detected host CID).
    Vsock {
        /// Host CID.
        cid: u32,
        /// Receiver port, normally
        /// [`SYNCHRONIZER_METRICS_PORT`](enclavia_protocol::synchronizer_metrics::SYNCHRONIZER_METRICS_PORT).
        port: u32,
    },
    /// A Unix socket, for the dev listener and tests.
    #[cfg(any(feature = "debug", feature = "test-utils"))]
    Uds(std::path::PathBuf),
}

/// A connected, write-only sink.
pub type SinkStream = Box<dyn AsyncWrite + Unpin + Send>;

impl MetricsSink {
    /// Connect, and shut the read side down so the kernel discards anything
    /// the host sends.
    pub async fn open(&self) -> io::Result<SinkStream> {
        match self {
            MetricsSink::Vsock { cid, port } => {
                let stream =
                    tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(*cid, *port))
                        .await?;
                stream.shutdown(std::net::Shutdown::Read)?;
                Ok(Box::new(stream))
            }
            #[cfg(any(feature = "debug", feature = "test-utils"))]
            MetricsSink::Uds(path) => {
                let stream = tokio::net::UnixStream::connect(path).await?.into_std()?;
                stream.shutdown(std::net::Shutdown::Read)?;
                Ok(Box::new(tokio::net::UnixStream::from_std(stream)?))
            }
        }
    }
}

/// Export forever: every `interval`, build a sample with `collect` (bounded
/// by [`COLLECT_TIMEOUT`]), encode it, and deliver it over a fresh
/// connection from `connect` (bounded by [`SEND_TIMEOUT`]). A failure drops
/// that sample and bumps the `export_failures` counter; nothing is retried.
///
/// Runs on its own task. Nothing in the measured code paths awaits it.
pub async fn run_exporter<C, CFut, W, S, SFut>(interval: Duration, connect: C, mut collect: S)
where
    C: Fn() -> CFut,
    CFut: Future<Output = io::Result<W>>,
    W: AsyncWrite + Unpin,
    S: FnMut(u64) -> SFut,
    SFut: Future<Output = sample::SynchronizerSample>,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seq: u64 = 0;
    let mut failing = false;
    loop {
        ticker.tick().await;
        let this_seq = seq;
        seq = seq.wrapping_add(1);
        let result = export_once(&connect, &mut collect, this_seq).await;
        match result {
            Ok(()) => {
                if failing {
                    tracing::info!(seq = this_seq, "metrics export recovered");
                    failing = false;
                }
            }
            Err(e) => {
                global().export_failures.fetch_add(1, Ordering::Relaxed);
                // One warning per failure streak: a missing receiver would
                // otherwise log every tick on the serial console.
                if !failing {
                    tracing::warn!(seq = this_seq, error = %e, "metrics export failed; dropping samples until it recovers");
                    failing = true;
                } else {
                    tracing::debug!(seq = this_seq, error = %e, "metrics export failed");
                }
            }
        }
    }
}

/// Why one export tick produced no delivered sample.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Building the sample took longer than [`COLLECT_TIMEOUT`].
    #[error("collecting the sample timed out")]
    CollectTimeout,
    /// The sample did not encode within the frame bound.
    #[error("encode: {0}")]
    Encode(#[from] sample::SampleFrameError),
    /// Delivery failed.
    #[error("send: {0}")]
    Send(#[from] SendError),
}

async fn export_once<C, CFut, W, S, SFut>(
    connect: &C,
    collect: &mut S,
    seq: u64,
) -> Result<(), ExportError>
where
    C: Fn() -> CFut,
    CFut: Future<Output = io::Result<W>>,
    W: AsyncWrite + Unpin,
    S: FnMut(u64) -> SFut,
    SFut: Future<Output = sample::SynchronizerSample>,
{
    let sample = tokio::time::timeout(COLLECT_TIMEOUT, collect(seq))
        .await
        .map_err(|_| ExportError::CollectTimeout)?;
    let frame = sample::encode_sample_frame(&sample)?;
    send_frame(connect, &frame, SEND_TIMEOUT).await?;
    Ok(())
}

/// Spawn the exporter for a replicated node, delivering to `sink`.
#[cfg(feature = "raft")]
pub fn spawn_replicated_exporter(
    collector: ReplicatedCollector,
    sink: MetricsSink,
) -> tokio::task::JoinHandle<()> {
    let sink = std::sync::Arc::new(sink);
    let collector = std::sync::Arc::new(collector);
    tokio::spawn(run_exporter(
        EXPORT_INTERVAL,
        move || {
            let sink = std::sync::Arc::clone(&sink);
            async move { sink.open().await }
        },
        move |seq| {
            let collector = std::sync::Arc::clone(&collector);
            async move { collector.collect(seq).await }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commitment, PcrKey, Version};
    use std::sync::Arc;

    fn get() -> Request {
        Request::Get { key: PcrKey([1; 32]) }
    }
    fn pin() -> Request {
        Request::Pin {
            key: PcrKey([1; 32]),
            expected_version: Version(0),
            commitment: Commitment([2; 32]),
        }
    }

    #[test]
    fn rpc_kind_and_outcome_classification() {
        assert_eq!(RpcKind::of_request(&get()), RpcKind::Get);
        assert_eq!(RpcKind::of_request(&pin()), RpcKind::Pin);
        assert_eq!(
            RpcKind::of_request(&Request::Register {
                key: PcrKey([1; 32]),
                commitment: Commitment([2; 32]),
            }),
            RpcKind::Register
        );
        assert_eq!(
            RpcOutcome::of_response(&Response::Err {
                error: RpcError::AlreadyRegistered,
            }),
            RpcOutcome::AlreadyRegistered
        );
        let conflict = Response::Err {
            error: RpcError::VersionConflict,
        };
        assert_eq!(
            RpcOutcome::of_response(&conflict),
            RpcOutcome::VersionConflict
        );
        assert_eq!(
            RpcOutcome::of_response(&Response::GetOk {
                commitment: Commitment([0; 32]),
                version: Version(1)
            }),
            RpcOutcome::Ok
        );
    }

    /// An `Unavailable` produced by an elapsed deadline is counted as
    /// `timeout`; the same response without the flag stays `unavailable`,
    /// and the flag never relabels any other response.
    #[test]
    fn timed_out_unavailable_is_labelled_timeout() {
        assert_eq!(
            RpcOutcome::of_answered(&Answered::deadline_elapsed()),
            RpcOutcome::Timeout
        );
        assert_eq!(RpcOutcome::Timeout.as_str(), "timeout");
        let unavailable = Response::Err {
            error: RpcError::Unavailable,
        };
        assert_eq!(
            RpcOutcome::of_answered(&Answered::new(unavailable)),
            RpcOutcome::Unavailable
        );
        let ok = Answered {
            response: Response::PinOk {
                version: Version(3),
            },
            timed_out: true,
        };
        assert_eq!(RpcOutcome::of_answered(&ok), RpcOutcome::Ok);

        let stats = RpcStats::new();
        stats.record_answered(
            RpcKind::Pin,
            &Answered::deadline_elapsed(),
            Duration::from_secs(5),
        );
        let pin = stats
            .sample()
            .into_iter()
            .find(|k| k.kind == "pin")
            .unwrap();
        let count = |label: &str| {
            pin.outcomes
                .iter()
                .find(|o| o.outcome == label)
                .unwrap()
                .count
        };
        assert_eq!(count("timeout"), 1);
        assert_eq!(count("unavailable"), 0);
    }

    #[test]
    fn latency_buckets_are_upper_inclusive() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1_000), 0);
        assert_eq!(bucket_index(1_001), 1);
        assert_eq!(bucket_index(5_000_000), RPC_LATENCY_BOUNDS_MS.len() - 1);
        assert_eq!(bucket_index(5_000_001), RPC_LATENCY_BOUNDS_MS.len());
        assert_eq!(bucket_index(u64::MAX), RPC_LATENCY_BOUNDS_MS.len());
    }

    #[test]
    fn rpc_stats_record_every_dimension() {
        let stats = RpcStats::new();
        stats.record_response(
            RpcKind::Register,
            &Response::RegisterOk,
            Duration::from_micros(1500),
        );
        stats.record_response(
            RpcKind::Get,
            &Response::Err {
                error: RpcError::Unavailable,
            },
            Duration::from_secs(60),
        );
        let kinds = stats.sample();
        assert_eq!(kinds.len(), RpcKind::ALL.len());
        let register = kinds.iter().find(|k| k.kind == "register").unwrap();
        assert_eq!(
            register
                .outcomes
                .iter()
                .find(|o| o.outcome == "ok")
                .unwrap()
                .count,
            1
        );
        assert_eq!(register.latency_buckets[1], 1);
        assert_eq!(register.latency_sum_us, 1500);
        let get = kinds.iter().find(|k| k.kind == "get").unwrap();
        assert_eq!(get.latency_buckets.len(), RPC_LATENCY_BOUNDS_MS.len() + 1);
        assert_eq!(*get.latency_buckets.last().unwrap(), 1);
        assert_eq!(
            get.outcomes
                .iter()
                .find(|o| o.outcome == "unavailable")
                .unwrap()
                .count,
            1
        );
        // Every cell is present from the start, at zero if unused.
        for k in &kinds {
            assert_eq!(k.outcomes.len(), RpcOutcome::ALL.len());
        }
    }

    #[test]
    fn rejection_stats_cover_every_source_and_reason() {
        let stats = RejectionStats::new();
        stats.record(RejectionSource::Peer, RejectionReason::PcrMismatch);
        stats.record(RejectionSource::Peer, RejectionReason::PcrMismatch);
        stats.record(RejectionSource::TransitionLink, RejectionReason::Expired);
        let cells = stats.sample();
        assert_eq!(cells.len(), RejectionSource::ALL.len() * N_REASONS);
        let count = |s: &str, r: &str| {
            cells
                .iter()
                .find(|c| c.source == s && c.reason == r)
                .unwrap()
                .count
        };
        assert_eq!(count("peer", "pcr_mismatch"), 2);
        assert_eq!(count("transition_link", "expired"), 1);
        assert_eq!(count("client", "pcr_mismatch"), 0);
        assert_eq!(count("client", OTHER_REASON), 0);
    }

    /// Every label this build can put in a sample is a fixed, well-formed
    /// enum label, and the reason labels are exactly `RejectionReason`'s
    /// plus `other`.
    #[test]
    fn every_label_is_a_fixed_valid_label() {
        let mut labels: Vec<&str> = Vec::new();
        labels.extend(RpcKind::ALL.iter().map(|k| k.as_str()));
        labels.extend(RpcOutcome::ALL.iter().map(|o| o.as_str()));
        labels.extend(RejectionSource::ALL.iter().map(|s| s.as_str()));
        labels.extend(JoinPhase::ALL.iter().map(|p| p.as_str()));
        labels.extend(RejectionReason::ALL.iter().map(|r| r.as_str()));
        labels.push(OTHER_REASON);
        labels.extend(["leader", "follower", "candidate", "learner", "shutdown"]);
        for l in labels {
            assert!(sample::is_valid_label(l), "bad label {l:?}");
        }

        let s = base_sample("az-a", 0, Duration::ZERO, &[]);
        for k in &s.rpc.kinds {
            assert!(RpcKind::ALL.iter().any(|x| x.as_str() == k.kind));
            for o in &k.outcomes {
                assert!(RpcOutcome::ALL.iter().any(|x| x.as_str() == o.outcome));
            }
        }
        for r in &s.rejections {
            assert!(RejectionSource::ALL.iter().any(|x| x.as_str() == r.source));
            assert!(
                RejectionReason::ALL.iter().any(|x| x.as_str() == r.reason)
                    || r.reason == OTHER_REASON
            );
        }
    }

    #[test]
    fn join_phase_round_trips() {
        let join = JoinStats::new();
        assert_eq!(join.phase(), JoinPhase::Starting);
        for p in JoinPhase::ALL {
            join.set_phase(p);
            assert_eq!(join.phase(), p);
        }
    }

    #[test]
    fn peer_link_stats_sample() {
        let stats = PeerLinkStats::default();
        assert_eq!(stats.sample("az-b").last_ping_rtt_us, None);
        stats.channel_up();
        stats.ping_sent();
        stats.ping_answered(Duration::from_micros(850));
        stats.channel_down();
        stats.dial_failed();
        stats.channel_up();
        let s = stats.sample("az-b");
        assert_eq!(s.peer, "az-b");
        assert!(s.connected);
        assert_eq!(s.channels_established, 2);
        assert_eq!(s.dial_failures, 1);
        assert_eq!(s.pings, 1);
        assert_eq!(s.last_ping_rtt_us, Some(850));
    }

    /// Peers with names that are not valid slot names are left out, and the
    /// list is capped.
    #[test]
    fn base_sample_filters_and_caps_peers() {
        let mut peers: Vec<(String, Arc<PeerLinkStats>)> = (0..sample::MAX_PEERS + 5)
            .map(|i| (format!("p{i}"), Arc::new(PeerLinkStats::default())))
            .collect();
        peers.insert(0, ("bad name".to_string(), Arc::new(PeerLinkStats::default())));
        let s = base_sample("az-a", 3, Duration::from_secs(7), &peers);
        assert_eq!(s.peers.len(), sample::MAX_PEERS);
        assert!(s.peers.iter().all(|p| sample::is_valid_name(&p.peer)));
        assert_eq!((s.seq, s.uptime_s), (3, 7));
        assert!(sample::encode_sample_frame(&s).is_ok());
    }

    /// The largest sample this node can build (every peer slot filled with
    /// a maximum-length name, every optional value present, every counter
    /// at `u64::MAX`) uses at most three quarters of the frame bound. The
    /// designed three-node cluster fills 2 of the 16 peer slots.
    #[test]
    fn largest_real_sample_has_headroom() {
        let peer_name = |i: usize| format!("{i:02}{}", "n".repeat(sample::MAX_NAME_LEN - 2));
        let peers: Vec<(String, Arc<PeerLinkStats>)> = (0..sample::MAX_PEERS)
            .map(|i| {
                let stats = PeerLinkStats::default();
                stats.channels_established.store(u64::MAX, Ordering::Relaxed);
                stats.dial_failures.store(u64::MAX, Ordering::Relaxed);
                stats.pings.store(u64::MAX, Ordering::Relaxed);
                stats.pong_timeouts.store(u64::MAX, Ordering::Relaxed);
                stats.last_ping_rtt_us.store(u64::MAX, Ordering::Relaxed);
                (peer_name(i), Arc::new(stats))
            })
            .collect();
        let mut s = base_sample(&peer_name(99), u64::MAX, Duration::MAX, &peers);
        for k in &mut s.rpc.kinds {
            k.outcomes.iter_mut().for_each(|o| o.count = u64::MAX);
            k.latency_buckets.iter_mut().for_each(|b| *b = u64::MAX);
            k.latency_sum_us = u64::MAX;
        }
        s.rejections.iter_mut().for_each(|r| r.count = u64::MAX);
        s.raft = Some(sample::RaftSample {
            role: "candidate".into(),
            term: u64::MAX,
            last_log_index: Some(u64::MAX),
            last_applied_index: Some(u64::MAX),
            snapshot_index: Some(u64::MAX),
            voters: u32::MAX,
            learners: u32::MAX,
            has_leader: true,
            millis_since_quorum_ack: Some(u64::MAX),
            peer_matched_index: (0..sample::MAX_PEERS)
                .map(|i| sample::PeerMatchedIndex {
                    peer: peer_name(i),
                    matched_index: Some(u64::MAX),
                })
                .collect(),
        });
        s.join = Some(sample::JoinSample {
            phase: "initializing".into(),
            probes: u64::MAX,
            admissions: u64::MAX,
            evictions: u64::MAX,
        });
        s.clock.offset_ms = Some(i64::MIN);
        s.resources = sample::ResourceSample {
            live_keys: Some(u64::MAX),
            retired_keys: Some(u64::MAX),
            snapshot_bytes: Some(u64::MAX),
            rss_bytes: Some(u64::MAX),
        };
        let body = sample::encode_sample_frame(&s).unwrap().len() - 4;
        assert!(
            body <= sample::MAX_SAMPLE_FRAME_SIZE as usize * 3 / 4,
            "largest real sample is {body} bytes"
        );
        assert!(s.rpc.kinds.len() <= sample::MAX_RPC_CELLS);
        assert!(s.rpc.kinds.iter().all(|k| k.outcomes.len() <= sample::MAX_RPC_CELLS));
        assert!(s.rejections.len() <= sample::MAX_REJECTION_CELLS);
        assert!(RPC_LATENCY_BOUNDS_MS.len() < sample::MAX_LATENCY_BUCKETS);
    }

    #[test]
    fn vm_rss_parsing() {
        assert_eq!(
            parse_vm_rss("Name:\tx\nVmRSS:\t   1234 kB\nVmSwap: 0 kB\n"),
            Some(1234 * 1024)
        );
        assert_eq!(parse_vm_rss("Name:\tx\n"), None);
        assert_eq!(parse_vm_rss("VmRSS:\t12 MB\n"), None);
    }

    fn tiny_sample() -> sample::SynchronizerSample {
        base_sample("az-a", 1, Duration::from_secs(1), &[])
    }

    /// A connect that never completes (host accepts nothing, or a wedged
    /// relay) costs the exporter exactly the send bound, then the sample is
    /// dropped.
    #[tokio::test(start_paused = true)]
    async fn hung_connect_is_bounded() {
        let frame = sample::encode_sample_frame(&tiny_sample()).unwrap();
        let started = tokio::time::Instant::now();
        let result = send_frame(
            std::future::pending::<io::Result<tokio::io::DuplexStream>>,
            &frame,
            SEND_TIMEOUT,
        )
        .await;
        assert!(matches!(result, Err(SendError::Timeout(_))));
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    /// A receiver that accepts but never reads cannot hold the exporter past
    /// the send bound either, even with a frame larger than the buffer.
    #[tokio::test(start_paused = true)]
    async fn stalled_reader_is_bounded() {
        let (mut ours, _theirs) = tokio::io::duplex(16);
        let frame = vec![0u8; 4096];
        let started = tokio::time::Instant::now();
        let result = send_frame(|| async { Ok(&mut ours) }, &frame, SEND_TIMEOUT).await;
        assert!(matches!(result, Err(SendError::Timeout(_))));
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test]
    async fn refused_connect_fails_fast() {
        let frame = sample::encode_sample_frame(&tiny_sample()).unwrap();
        let result = send_frame(
            || async {
                Err::<tokio::io::DuplexStream, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
            },
            &frame,
            SEND_TIMEOUT,
        )
        .await;
        assert!(matches!(result, Err(SendError::Io(_))));
    }

    /// The exporter loop keeps ticking while the host is absent, counts each
    /// dropped sample, and never queues: once the host appears, the next
    /// delivered sample is the current one, not a backlog.
    #[tokio::test(start_paused = true)]
    async fn exporter_drops_while_host_absent_and_recovers() {
        use tokio::io::AsyncReadExt;
        let host_up = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let connect = {
            let host_up = Arc::clone(&host_up);
            move || {
                let host_up = Arc::clone(&host_up);
                let tx = tx.clone();
                async move {
                    if !host_up.load(Ordering::SeqCst) {
                        return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                    }
                    let (ours, theirs) = tokio::io::duplex(64 * 1024);
                    tx.send(theirs).unwrap();
                    Ok(ours)
                }
            }
        };
        let before = global().export_failures.load(Ordering::Relaxed);
        let exporter = tokio::spawn(run_exporter(
            Duration::from_secs(15),
            connect,
            |seq| async move { base_sample("az-a", seq, Duration::ZERO, &[]) },
        ));
        // Three ticks with no host: t = 0, 15, 30.
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(global().export_failures.load(Ordering::Relaxed) >= before + 3);
        assert!(rx.try_recv().is_err());

        host_up.store(true, Ordering::SeqCst);
        let mut theirs = rx.recv().await.unwrap();
        let mut buf = Vec::new();
        theirs.read_to_end(&mut buf).await.unwrap();
        let got = sample::decode_sample_frame(&buf).unwrap();
        assert_eq!(got.seq, 3, "the first delivered sample is the current tick");
        exporter.abort();
    }

    /// Over a real socket: the host writes junk back and never reads past
    /// the frame; the exporter neither reads it nor stalls, and the frame
    /// arrives intact followed by EOF.
    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn uds_sink_is_one_way() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let host = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            // Anything written this way must be ignored by the node. The
            // write itself may fail once the node has shut its read side.
            let _ = conn.write_all(&[0xAA; 8192]).await;
            // Read until EOF. Closing a Unix socket with unread data makes
            // the peer's next read fail with ECONNRESET once the queued
            // bytes are consumed, so an error after the frame also ends it.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = conn.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            buf
        });
        let sink = MetricsSink::Uds(path.clone());
        let s = tiny_sample();
        let frame = sample::encode_sample_frame(&s).unwrap();
        send_frame(|| sink.open(), &frame, SEND_TIMEOUT)
            .await
            .unwrap();
        let received = host.await.unwrap();
        assert_eq!(sample::decode_sample_frame(&received).unwrap(), s);
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn uds_sink_absent_host_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MetricsSink::Uds(dir.path().join("nobody-listens.sock"));
        let frame = sample::encode_sample_frame(&tiny_sample()).unwrap();
        let started = std::time::Instant::now();
        let result = send_frame(|| sink.open(), &frame, SEND_TIMEOUT).await;
        assert!(matches!(result, Err(SendError::Io(_))));
        assert!(started.elapsed() < SEND_TIMEOUT);
    }
}
