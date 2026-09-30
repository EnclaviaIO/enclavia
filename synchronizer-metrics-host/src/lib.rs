//! Reference host-side receiver for the synchronizer's metrics frames.
//!
//! A synchronizer node dials its parent on vsock port
//! [`SYNCHRONIZER_METRICS_PORT`](enclavia_protocol::synchronizer_metrics::SYNCHRONIZER_METRICS_PORT)
//! every 15 s and writes one length-prefixed CBOR
//! [`SynchronizerSample`]. This crate reads that frame ([`receive`]), and
//! renders the latest sample as Prometheus text ([`render`]) for
//! node_exporter's textfile collector ([`write_atomic`]).
//!
//! Receiver contract:
//!
//! * Never write to the connection. The node never reads it.
//! * Read at most one frame, with a length prefix in
//!   `1..=MAX_SAMPLE_FRAME_SIZE`, within [`RECEIVE_TIMEOUT`]. Anything
//!   else (oversized or zero prefix, truncated body, non-CBOR, wrong shape,
//!   unknown version, invalid node name) is dropped and the connection
//!   closed; the previous output stays in place.
//! * Validate every label before rendering it, and drop a series whose
//!   label is not a valid slot name / enum label, or whose label set was
//!   already emitted (node_exporter rejects a file with duplicate series).
//!
//! The values come from an enclave, via a host the enclave does not trust;
//! they are for dashboards and alerts only.

use std::collections::HashSet;
use std::fmt::{Display, Write as _};
use std::io;
use std::path::Path;
use std::time::Duration;

use enclavia_protocol::synchronizer_metrics::{
    MAX_LATENCY_BUCKETS, SampleFrameError, SynchronizerSample, is_valid_label, is_valid_name,
    read_sample_frame,
};
use tokio::io::AsyncRead;

/// Upper bound on reading one frame from an accepted connection.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Prefix of every metric name.
pub const PREFIX: &str = "enclavia_synchronizer_";

/// Why a connection produced no sample.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    /// No complete frame within the bound.
    #[error("no frame within {0:?}")]
    Timeout(Duration),
    /// The frame was malformed, oversized, or of an unknown version.
    #[error("{0}")]
    Frame(#[from] SampleFrameError),
    /// The sample's node name is not a valid slot name.
    #[error("invalid node name")]
    InvalidNode,
}

/// Read and validate one sample from `stream` within `timeout`. Reads
/// nothing past the frame and never writes.
pub async fn receive<R>(stream: &mut R, timeout: Duration) -> Result<SynchronizerSample, ReceiveError>
where
    R: AsyncRead + Unpin,
{
    let sample = tokio::time::timeout(timeout, read_sample_frame(stream))
        .await
        .map_err(|_| ReceiveError::Timeout(timeout))??;
    if !is_valid_name(&sample.node) {
        return Err(ReceiveError::InvalidNode);
    }
    Ok(sample)
}

/// Replace `path` with `contents` atomically: write a hidden temporary file
/// in the same directory (not ending in `.prom`, so the textfile collector
/// never reads it half-written), then rename over the target.
pub fn write_atomic(path: &Path, contents: &str) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

/// Prometheus text writer: groups series by family, adds the `node` label,
/// validates labels and skips duplicate series.
struct Out<'a> {
    text: String,
    node: &'a str,
    seen: HashSet<String>,
    current: Option<String>,
}

impl<'a> Out<'a> {
    fn new(node: &'a str) -> Self {
        Self {
            text: String::new(),
            node,
            seen: HashSet::new(),
            current: None,
        }
    }

    /// Start a family. Series written until the next call belong to it.
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.text, "# HELP {PREFIX}{name} {help}");
        let _ = writeln!(self.text, "# TYPE {PREFIX}{name} {kind}");
        self.current = Some(name.to_string());
    }

    /// One series. `suffix` extends the family name (`_bucket`, `_sum`,
    /// `_count`). Labels whose key is `peer` must be valid slot names; all
    /// others valid enum labels, except `le`, which the renderer formats.
    fn series(&mut self, suffix: &str, labels: &[(&str, &str)], value: impl Display) {
        let valid = labels.iter().all(|(k, v)| match *k {
            "peer" => is_valid_name(v),
            "le" => true,
            _ => is_valid_label(v),
        });
        if !valid {
            return;
        }
        let family = self.current.as_deref().unwrap_or_default();
        let mut line = format!("{PREFIX}{family}{suffix}{{node=\"{}\"", self.node);
        for (k, v) in labels {
            let _ = write!(line, ",{k}=\"{v}\"");
        }
        line.push('}');
        if !self.seen.insert(line.clone()) {
            return;
        }
        let _ = writeln!(self.text, "{line} {value}");
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl Display) {
        self.family(name, "gauge", help);
        self.series("", &[], value);
    }

    fn counter(&mut self, name: &str, help: &str, value: impl Display) {
        self.family(name, "counter", help);
        self.series("", &[], value);
    }

    /// A one-hot state set over `known`, plus the reported state if it is a
    /// valid label outside `known`.
    fn state_set(&mut self, name: &str, label: &str, help: &str, known: &[&str], current: &str) {
        self.family(name, "gauge", help);
        for s in known {
            self.series("", &[(label, s)], u8::from(*s == current));
        }
        if !known.contains(&current) {
            self.series("", &[(label, current)], 1);
        }
    }
}

/// Milliseconds as seconds, for Prometheus base units.
fn ms_to_s(ms: f64) -> f64 {
    ms / 1000.0
}

/// Render `sample` (received at `received_unix_ms`, host clock) as
/// Prometheus text exposition format.
pub fn render(sample: &SynchronizerSample, received_unix_ms: u64) -> String {
    let mut o = Out::new(&sample.node);

    o.gauge(
        "sample_received_timestamp_seconds",
        "Host time the latest sample arrived (Unix seconds). Alert on staleness.",
        ms_to_s(received_unix_ms as f64),
    );
    o.gauge("sample_version", "Schema version of the latest sample.", sample.version);
    o.gauge("sample_seq", "Per-boot sequence number of the latest sample.", sample.seq);
    o.gauge("uptime_seconds", "Seconds since the synchronizer process started.", sample.uptime_s);
    o.counter(
        "export_failures_total",
        "Samples the node failed to deliver (dropped, never retried).",
        sample.export_failures,
    );

    if let Some(raft) = &sample.raft {
        o.state_set(
            "raft_role",
            "role",
            "Raft role of this node (1 for the current role).",
            &["leader", "follower", "candidate", "learner", "shutdown"],
            &raft.role,
        );
        o.gauge("raft_term", "Current Raft term.", raft.term);
        if let Some(v) = raft.last_log_index {
            o.gauge("raft_last_log_index", "Index of the last entry in this node's log.", v);
        }
        if let Some(v) = raft.last_applied_index {
            o.gauge(
                "raft_last_applied_index",
                "Index of the last entry applied to this node's state machine.",
                v,
            );
        }
        if let Some(v) = raft.snapshot_index {
            o.gauge(
                "raft_snapshot_index",
                "Index of the last entry covered by this node's snapshot.",
                v,
            );
        }
        o.gauge("raft_voters", "Voters in the effective membership.", raft.voters);
        o.gauge("raft_learners", "Learners in the effective membership.", raft.learners);
        o.gauge(
            "raft_has_leader",
            "1 if this node currently knows a leader.",
            u8::from(raft.has_leader),
        );
        if let Some(ms) = raft.millis_since_quorum_ack {
            o.gauge(
                "raft_quorum_ack_age_seconds",
                "Leader only: time since a quorum last acknowledged this leader.",
                ms_to_s(ms as f64),
            );
        }
        o.family(
            "raft_peer_matched_index",
            "gauge",
            "Leader only: highest log index known replicated to each peer.",
        );
        for p in &raft.peer_matched_index {
            if let Some(i) = p.matched_index {
                o.series("", &[("peer", &p.peer)], i);
            }
        }
    }

    if let Some(join) = &sample.join {
        o.state_set(
            "join_phase",
            "phase",
            "Cluster join phase of this node (1 for the current phase).",
            &["starting", "discovering", "initializing", "voter", "evicted"],
            &join.phase,
        );
        o.counter("join_probes_total", "Join probes this node sent to peers.", join.probes);
        o.counter(
            "join_admissions_total",
            "Nodes this node admitted as leader.",
            join.admissions,
        );
        o.counter(
            "join_evictions_total",
            "Previous slot holders this node removed as leader while admitting a replacement.",
            join.evictions,
        );
    }

    type PeerField = fn(&enclavia_protocol::synchronizer_metrics::PeerSample) -> Option<f64>;
    let peer_families: [(&str, &str, &str, PeerField); 6] = [
        (
            "mesh_peer_connected",
            "gauge",
            "1 if the outbound attested channel to the peer is up.",
            |p| Some(f64::from(u8::from(p.connected))),
        ),
        (
            "mesh_peer_channels_established_total",
            "counter",
            "Attested channels established to the peer (first connect plus reconnects).",
            |p| Some(p.channels_established as f64),
        ),
        (
            "mesh_peer_dial_failures_total",
            "counter",
            "Dial or handshake attempts to the peer that failed.",
            |p| Some(p.dial_failures as f64),
        ),
        (
            "mesh_peer_pings_total",
            "counter",
            "Liveness pings sent to the peer (only on an idle channel).",
            |p| Some(p.pings as f64),
        ),
        (
            "mesh_peer_pong_timeouts_total",
            "counter",
            "Liveness pings to the peer that went unanswered.",
            |p| Some(p.pong_timeouts as f64),
        ),
        (
            "mesh_peer_last_ping_rtt_seconds",
            "gauge",
            "Round-trip time of the most recent answered liveness ping.",
            |p| p.last_ping_rtt_us.map(|us| us as f64 / 1e6),
        ),
    ];
    for (name, kind, help, field) in peer_families {
        o.family(name, kind, help);
        for p in &sample.peers {
            if let Some(v) = field(p) {
                o.series("", &[("peer", &p.peer)], v);
            }
        }
    }

    let rpc = &sample.rpc;
    o.family(
        "rpc_requests_total",
        "counter",
        "Customer RPCs completed on sessions this node holds, by kind and outcome.",
    );
    for k in &rpc.kinds {
        for oc in &k.outcomes {
            o.series("", &[("kind", &k.kind), ("outcome", &oc.outcome)], oc.count);
        }
    }
    let bounds_ok = !rpc.latency_bounds_ms.is_empty()
        && rpc.latency_bounds_ms.len() < MAX_LATENCY_BUCKETS
        && rpc.latency_bounds_ms.windows(2).all(|w| w[0] < w[1]);
    o.family(
        "rpc_duration_seconds",
        "histogram",
        "Customer RPC latency on the node that holds the session, by kind.",
    );
    if bounds_ok {
        for k in &rpc.kinds {
            if k.latency_buckets.len() != rpc.latency_bounds_ms.len() + 1 || !is_valid_label(&k.kind) {
                continue;
            }
            let mut cumulative: u64 = 0;
            for (i, count) in k.latency_buckets.iter().enumerate() {
                cumulative = cumulative.saturating_add(*count);
                let le = match rpc.latency_bounds_ms.get(i) {
                    Some(ms) => ms_to_s(f64::from(*ms)).to_string(),
                    None => "+Inf".to_string(),
                };
                o.series("_bucket", &[("kind", &k.kind), ("le", &le)], cumulative);
            }
            o.series("_sum", &[("kind", &k.kind)], k.latency_sum_us as f64 / 1e6);
            o.series("_count", &[("kind", &k.kind)], cumulative);
        }
    }
    o.family(
        "rpc_routed_total",
        "counter",
        "Customer RPCs by where they were served: local (this node is leader), forwarded to the leader, or unavailable (no leader within the retry budget).",
    );
    o.series("", &[("route", "local")], rpc.routed_local);
    o.series("", &[("route", "forwarded")], rpc.routed_forwarded);
    o.series("", &[("route", "unavailable")], rpc.routed_unavailable);
    o.counter(
        "rpc_forwarded_served_total",
        "Customer RPCs other nodes forwarded to this node, served as leader.",
        rpc.forwarded_served,
    );

    o.family(
        "attestation_rejections_total",
        "counter",
        "Attestation rejections by source (client, peer, transition_link) and reason.",
    );
    for r in &sample.rejections {
        o.series("", &[("source", &r.source), ("reason", &r.reason)], r.count);
    }

    if let Some(ms) = sample.clock.offset_ms {
        o.gauge(
            "clock_offset_seconds",
            "Enclave wall clock minus the NSM attestation timestamp.",
            ms_to_s(ms as f64),
        );
    }

    let res = &sample.resources;
    o.family("state_keys", "gauge", "Keys in the replicated state machine, by state.");
    if let Some(v) = res.live_keys {
        o.series("", &[("state", "live")], v);
    }
    if let Some(v) = res.retired_keys {
        o.series("", &[("state", "retired")], v);
    }
    if let Some(v) = res.snapshot_bytes {
        o.gauge("snapshot_bytes", "Size of the latest Raft snapshot.", v);
    }
    if let Some(v) = res.rss_bytes {
        o.gauge(
            "process_resident_memory_bytes",
            "Resident set size of the synchronizer process.",
            v,
        );
    }

    o.text
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavia_protocol::synchronizer_metrics::{
        ClockSample, JoinSample, MAX_SAMPLE_FRAME_SIZE, OutcomeCount, PeerMatchedIndex,
        PeerSample, RaftSample, RejectionCount, ResourceSample, RpcKindSample, RpcSample,
        SAMPLE_VERSION, encode_sample_frame,
    };
    use tokio::io::AsyncWriteExt;

    fn sample() -> SynchronizerSample {
        SynchronizerSample {
            version: SAMPLE_VERSION,
            node: "az-a".into(),
            seq: 12,
            uptime_s: 180,
            export_failures: 1,
            raft: Some(RaftSample {
                role: "leader".into(),
                term: 4,
                last_log_index: Some(900),
                last_applied_index: Some(899),
                snapshot_index: None,
                voters: 3,
                learners: 0,
                has_leader: true,
                millis_since_quorum_ack: Some(120),
                peer_matched_index: vec![
                    PeerMatchedIndex {
                        peer: "az-b".into(),
                        matched_index: Some(899),
                    },
                    PeerMatchedIndex {
                        peer: "az-c".into(),
                        matched_index: None,
                    },
                ],
            }),
            join: Some(JoinSample {
                phase: "voter".into(),
                probes: 3,
                admissions: 1,
                evictions: 1,
            }),
            peers: vec![PeerSample {
                peer: "az-b".into(),
                connected: true,
                channels_established: 2,
                dial_failures: 5,
                pings: 1,
                pong_timeouts: 0,
                last_ping_rtt_us: Some(1500),
            }],
            rpc: RpcSample {
                latency_bounds_ms: vec![1, 10],
                kinds: vec![RpcKindSample {
                    kind: "pin".into(),
                    outcomes: vec![
                        OutcomeCount {
                            outcome: "ok".into(),
                            count: 7,
                        },
                        OutcomeCount {
                            outcome: "version_conflict".into(),
                            count: 1,
                        },
                    ],
                    latency_buckets: vec![5, 2, 1],
                    latency_sum_us: 42_000,
                }],
                routed_local: 6,
                routed_forwarded: 2,
                routed_unavailable: 0,
                forwarded_served: 3,
            },
            rejections: vec![RejectionCount {
                source: "peer".into(),
                reason: "pcr_mismatch".into(),
                count: 2,
            }],
            clock: ClockSample {
                offset_ms: Some(-250),
            },
            resources: ResourceSample {
                live_keys: Some(10),
                retired_keys: Some(1),
                snapshot_bytes: None,
                rss_bytes: Some(4096),
            },
        }
    }

    fn value(text: &str, series: &str) -> Option<String> {
        text.lines()
            .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
            .map(|l| l[series.len() + 1..].to_string())
    }

    #[test]
    fn renders_expected_series() {
        let text = render(&sample(), 1_700_000_000_500);
        let p = PREFIX;
        assert_eq!(
            value(&text, &format!("{p}raft_role{{node=\"az-a\",role=\"leader\"}}")).as_deref(),
            Some("1")
        );
        assert_eq!(
            value(&text, &format!("{p}raft_role{{node=\"az-a\",role=\"follower\"}}")).as_deref(),
            Some("0")
        );
        assert_eq!(
            value(&text, &format!("{p}raft_peer_matched_index{{node=\"az-a\",peer=\"az-b\"}}"))
                .as_deref(),
            Some("899")
        );
        assert!(!text.contains("peer=\"az-c\"}"), "unknown matched index is omitted");
        assert_eq!(
            value(&text, &format!("{p}raft_quorum_ack_age_seconds{{node=\"az-a\"}}")).as_deref(),
            Some("0.12")
        );
        assert_eq!(
            value(
                &text,
                &format!("{p}rpc_duration_seconds_bucket{{node=\"az-a\",kind=\"pin\",le=\"0.01\"}}")
            )
            .as_deref(),
            Some("7")
        );
        assert_eq!(
            value(
                &text,
                &format!("{p}rpc_duration_seconds_bucket{{node=\"az-a\",kind=\"pin\",le=\"+Inf\"}}")
            )
            .as_deref(),
            Some("8")
        );
        assert_eq!(
            value(&text, &format!("{p}rpc_duration_seconds_count{{node=\"az-a\",kind=\"pin\"}}"))
                .as_deref(),
            Some("8")
        );
        assert_eq!(
            value(&text, &format!("{p}clock_offset_seconds{{node=\"az-a\"}}")).as_deref(),
            Some("-0.25")
        );
        assert_eq!(
            value(
                &text,
                &format!("{p}attestation_rejections_total{{node=\"az-a\",source=\"peer\",reason=\"pcr_mismatch\"}}")
            )
            .as_deref(),
            Some("2")
        );
        assert_eq!(
            value(&text, &format!("{p}sample_received_timestamp_seconds{{node=\"az-a\"}}"))
                .as_deref(),
            Some("1700000000.5")
        );
        assert!(!text.contains("snapshot_bytes"), "absent values are not rendered");
    }

    /// Every metric line is `name{labels} value`, every family has HELP and
    /// TYPE, and no series appears twice.
    #[test]
    fn output_is_well_formed() {
        let text = render(&sample(), 0);
        let mut seen = HashSet::new();
        for line in text.lines() {
            if line.starts_with('#') {
                assert!(line.starts_with("# HELP ") || line.starts_with("# TYPE "));
                continue;
            }
            let (series, value) = line.rsplit_once(' ').unwrap();
            assert!(series.starts_with(PREFIX));
            assert!(series.ends_with('}'));
            assert!(value.parse::<f64>().is_ok() || value == "+Inf", "{line}");
            assert!(seen.insert(series.to_string()), "duplicate {series}");
        }
    }

    /// Hostile label values (quote, brace, newline, uppercase, overlong)
    /// never reach the output, and duplicate label sets are emitted once.
    #[test]
    fn invalid_and_duplicate_labels_are_dropped() {
        let mut s = sample();
        s.peers.push(PeerSample {
            peer: "x\"} 1\nevil_metric{a=\"".into(),
            ..Default::default()
        });
        s.peers.push(s.peers[0].clone());
        s.rejections.push(RejectionCount {
            source: "peer".into(),
            reason: "Bad-Reason".into(),
            count: 1,
        });
        s.rpc.kinds[0].outcomes.push(OutcomeCount {
            outcome: "x".repeat(100),
            count: 1,
        });
        if let Some(r) = s.raft.as_mut() {
            r.role = "LEADER\n".into();
        }
        let text = render(&s, 0);
        assert!(!text.contains("evil_metric"));
        assert!(!text.contains("Bad-Reason"));
        assert!(!text.contains("LEADER"));
        assert!(!text.contains(&"x".repeat(100)));
        let connected = format!("{PREFIX}mesh_peer_connected{{node=\"az-a\",peer=\"az-b\"}}");
        assert_eq!(text.matches(&connected).count(), 1);
    }

    /// A histogram whose shape does not match its bounds is dropped rather
    /// than rendered wrong.
    #[test]
    fn malformed_histogram_is_dropped() {
        let mut s = sample();
        s.rpc.kinds[0].latency_buckets.pop();
        assert!(!render(&s, 0).contains("rpc_duration_seconds_bucket"));
        let mut s = sample();
        s.rpc.latency_bounds_ms = vec![10, 1];
        assert!(!render(&s, 0).contains("rpc_duration_seconds_bucket"));
    }

    #[tokio::test]
    async fn receives_a_valid_frame() {
        let (mut node, mut host) = tokio::io::duplex(64 * 1024);
        node.write_all(&encode_sample_frame(&sample()).unwrap())
            .await
            .unwrap();
        drop(node);
        assert_eq!(receive(&mut host, RECEIVE_TIMEOUT).await.unwrap(), sample());
    }

    #[tokio::test]
    async fn rejects_oversized_prefix() {
        let (mut node, mut host) = tokio::io::duplex(64);
        node.write_all(&(MAX_SAMPLE_FRAME_SIZE + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            receive(&mut host, RECEIVE_TIMEOUT).await,
            Err(ReceiveError::Frame(SampleFrameError::TooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn rejects_garbage() {
        let (mut node, mut host) = tokio::io::duplex(1024);
        node.write_all(&8u32.to_be_bytes()).await.unwrap();
        node.write_all(b"\xff\xfe\xfd\xfc garbage").await.unwrap();
        assert!(matches!(
            receive(&mut host, RECEIVE_TIMEOUT).await,
            Err(ReceiveError::Frame(SampleFrameError::Decode(_)))
        ));

        let (mut node, mut host) = tokio::io::duplex(1024);
        node.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(receive(&mut host, RECEIVE_TIMEOUT).await.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_node_name() {
        let mut s = sample();
        s.node = "az-a\"}".into();
        let (mut node, mut host) = tokio::io::duplex(64 * 1024);
        node.write_all(&encode_sample_frame(&s).unwrap()).await.unwrap();
        assert!(matches!(
            receive(&mut host, RECEIVE_TIMEOUT).await,
            Err(ReceiveError::InvalidNode)
        ));
    }

    /// A sender that announces a frame and then stalls is cut off at the
    /// bound.
    #[tokio::test(start_paused = true)]
    async fn slow_sender_times_out() {
        let (mut node, mut host) = tokio::io::duplex(1024);
        node.write_all(&100u32.to_be_bytes()).await.unwrap();
        node.write_all(&[0u8; 10]).await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            receive(&mut host, RECEIVE_TIMEOUT).await,
            Err(ReceiveError::Timeout(_))
        ));
        assert_eq!(started.elapsed(), RECEIVE_TIMEOUT);
        drop(node);
    }

    #[test]
    fn atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enclavia_synchronizer.prom");
        write_atomic(&path, "a 1\n").unwrap();
        write_atomic(&path, "a 2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a 2\n");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "no temporary file is left behind");
    }
}
