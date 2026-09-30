//! Wire format for the synchronizer's operational metrics (guest -> host).
//!
//! A synchronizer node periodically dials its parent instance on vsock port
//! [`SYNCHRONIZER_METRICS_PORT`], writes exactly one length-prefixed CBOR
//! [`SynchronizerSample`] frame, shuts down its write side and closes. It
//! never reads from that connection. A host-side receiver turns the latest
//! sample into Prometheus text.
//!
//! ## Trust
//!
//! The host is untrusted and can fabricate, drop or replay samples, so
//! nothing may trust these values: they are for dashboards and alerts only.
//! In the other direction the sample only carries aggregate counters,
//! gauges, histograms and states. Label values are the node's own slot name,
//! peer slot names, and fixed enum labels (role, RPC kind, outcome,
//! rejection source and reason). No volume or enclave identifiers, keys,
//! commitments, PCRs, Raft node ids (they are derived from instance keys) or
//! addresses. `tests::sample_carries_only_allowed_fields` pins the field set.
//!
//! ## Frame
//!
//! A 4-byte big-endian length, then that many bytes of CBOR. The length
//! must be in `1..=`[`MAX_SAMPLE_FRAME_SIZE`]; a receiver rejects anything
//! else before allocating. The whole frame is a single write well under the
//! 32 KiB vsock per-write ceiling.
//!
//! ## Versioning
//!
//! [`SynchronizerSample::version`] is [`SAMPLE_VERSION`]. Adding a field is
//! not a version change: new fields carry `#[serde(default)]` and receivers
//! ignore fields they do not know. The version is bumped only when the
//! meaning of an existing field changes, and a receiver rejects any version
//! it does not implement. Label values travel as strings so a new enum value
//! (for example a new rejection reason) does not break older receivers; a
//! receiver must still validate every label with [`is_valid_label`] /
//! [`is_valid_name`] before rendering it.

use serde::{Deserialize, Serialize};

/// vsock port a synchronizer node dials on its parent (guest -> host) to
/// deliver one [`SynchronizerSample`] per export tick.
///
/// 5014 is unused by the synchronizer image (it uses 5008 bootstrap, 5009
/// mesh-host, 5010 customer RPC and 5011 names). The customer-enclave
/// monitor daemon's draft assigns 5014 to its own sample frame on customer
/// parents; the two never share a parent instance, and a receiver rejects a
/// frame of the other kind (it does not decode as this type).
pub const SYNCHRONIZER_METRICS_PORT: u32 = 5014;

/// Upper bound on the CBOR body of one frame, in bytes. A fully populated
/// sample at the [`MAX_PEERS`] / name-length limits stays well below it (see
/// `tests::worst_case_sample_fits`).
pub const MAX_SAMPLE_FRAME_SIZE: u32 = 16 * 1024;

/// Current [`SynchronizerSample::version`].
pub const SAMPLE_VERSION: u16 = 1;

/// Most per-peer entries a sample carries (in [`SynchronizerSample::peers`]
/// and [`RaftSample::peer_matched_index`]). The designed cluster has three
/// nodes; the bound only keeps the frame size fixed.
pub const MAX_PEERS: usize = 16;

/// Most attestation-rejection cells a sample carries.
pub const MAX_REJECTION_CELLS: usize = 48;

/// Most RPC kinds, and outcomes per kind, a sample carries.
pub const MAX_RPC_CELLS: usize = 8;

/// Longest node / peer slot name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Longest enum label accepted, in bytes.
pub const MAX_LABEL_LEN: usize = 32;

/// Most latency histogram buckets (including the `+Inf` bucket).
pub const MAX_LATENCY_BUCKETS: usize = 16;

/// One export tick's worth of aggregate metrics from one synchronizer node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizerSample {
    /// Schema version, [`SAMPLE_VERSION`].
    pub version: u16,
    /// This node's slot name (its `MESH_SELF_NAME`). Must satisfy
    /// [`is_valid_name`].
    pub node: String,
    /// Per-boot sample counter, starting at 0. Gaps are dropped samples.
    pub seq: u64,
    /// Seconds since the synchronizer process started.
    pub uptime_s: u64,
    /// Samples this node failed to deliver since it started (connect,
    /// write or timeout failure; each is dropped, never retried).
    #[serde(default)]
    pub export_failures: u64,
    /// openraft state. `None` in a build without Raft.
    #[serde(default)]
    pub raft: Option<RaftSample>,
    /// Cluster join state. `None` in a build without Raft.
    #[serde(default)]
    pub join: Option<JoinSample>,
    /// One entry per configured peer's outbound mesh channel.
    #[serde(default)]
    pub peers: Vec<PeerSample>,
    /// Customer RPC counters and latency.
    #[serde(default)]
    pub rpc: RpcSample,
    /// Attestation rejections by source and reason.
    #[serde(default)]
    pub rejections: Vec<RejectionCount>,
    /// Clock health.
    #[serde(default)]
    pub clock: ClockSample,
    /// State size and process memory.
    #[serde(default)]
    pub resources: ResourceSample,
}

/// openraft metrics, with every node id replaced by its slot name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftSample {
    /// `leader`, `follower`, `candidate`, `learner` or `shutdown`.
    pub role: String,
    /// Current Raft term.
    pub term: u64,
    /// Index of the last entry appended to this node's log.
    #[serde(default)]
    pub last_log_index: Option<u64>,
    /// Index of the last entry applied to this node's state machine.
    #[serde(default)]
    pub last_applied_index: Option<u64>,
    /// Index of the last entry covered by this node's snapshot.
    #[serde(default)]
    pub snapshot_index: Option<u64>,
    /// Voters in the effective membership.
    pub voters: u32,
    /// Learners in the effective membership.
    pub learners: u32,
    /// Whether this node currently knows a leader.
    pub has_leader: bool,
    /// Leader only: milliseconds since a quorum last acknowledged it.
    #[serde(default)]
    pub millis_since_quorum_ack: Option<u64>,
    /// Leader only: the highest log index each peer is known to hold.
    #[serde(default)]
    pub peer_matched_index: Vec<PeerMatchedIndex>,
}

/// One peer's replication progress, as seen by the leader.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMatchedIndex {
    /// The peer's slot name.
    pub peer: String,
    /// Highest log index known replicated to it; `None` before the first
    /// successful replication.
    #[serde(default)]
    pub matched_index: Option<u64>,
}

/// Cluster join state machine and leader-side membership changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinSample {
    /// `starting`, `discovering`, `initializing`, `voter` or `evicted`.
    pub phase: String,
    /// Join probes this node sent to peers.
    pub probes: u64,
    /// Nodes this node admitted as leader (new voters committed).
    pub admissions: u64,
    /// Previous slot holders this node removed as leader while admitting a
    /// replacement.
    pub evictions: u64,
}

/// One configured peer's outbound mesh channel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSample {
    /// The peer's slot name.
    pub peer: String,
    /// Whether an attested channel is up right now.
    pub connected: bool,
    /// Attested channels established since start (the first one plus every
    /// reconnect).
    pub channels_established: u64,
    /// Dial or handshake attempts that failed.
    pub dial_failures: u64,
    /// Liveness pings sent (only after the channel is idle).
    pub pings: u64,
    /// Pings that got no answer in time (the channel was then dropped).
    pub pong_timeouts: u64,
    /// Round-trip time of the most recent answered ping, in microseconds.
    #[serde(default)]
    pub last_ping_rtt_us: Option<u64>,
}

/// Customer RPC counters, as seen by the node that holds the session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcSample {
    /// Upper bounds of the latency buckets, in milliseconds, ascending. The
    /// last bucket in [`RpcKindSample::latency_buckets`] is `+Inf`.
    pub latency_bounds_ms: Vec<u32>,
    /// One entry per RPC kind.
    pub kinds: Vec<RpcKindSample>,
    /// Requests this node served as leader for its own sessions.
    pub routed_local: u64,
    /// Requests this node forwarded to the leader.
    pub routed_forwarded: u64,
    /// Requests that found no leader within the retry budget.
    pub routed_unavailable: u64,
    /// Requests other nodes forwarded to this node, served as leader.
    pub forwarded_served: u64,
}

/// Counters for one RPC kind.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcKindSample {
    /// `get`, `pin`, `register` or `transition`.
    pub kind: String,
    /// Completed requests by outcome (`ok` or an RPC error label).
    pub outcomes: Vec<OutcomeCount>,
    /// Non-cumulative bucket counts, one per bound plus `+Inf`.
    pub latency_buckets: Vec<u64>,
    /// Sum of all observed latencies, in microseconds.
    pub latency_sum_us: u64,
}

/// A counter for one outcome label.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeCount {
    /// The outcome label.
    pub outcome: String,
    /// How many requests ended with it.
    pub count: u64,
}

/// Attestation rejections for one (source, reason) pair.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionCount {
    /// `client`, `peer` or `transition_link`.
    pub source: String,
    /// The `RejectionReason` label, or `other`.
    pub reason: String,
    /// How many rejections.
    pub count: u64,
}

/// Clock health.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockSample {
    /// Enclave wall clock minus the NSM attestation timestamp, in
    /// milliseconds, from a fresh own attestation. `None` when not measured
    /// (no `/dev/nsm`, or the probe failed).
    #[serde(default)]
    pub offset_ms: Option<i64>,
}

/// State size and process memory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSample {
    /// Keys currently registered in the state machine.
    #[serde(default)]
    pub live_keys: Option<u64>,
    /// Keys retired by a transition.
    #[serde(default)]
    pub retired_keys: Option<u64>,
    /// Size of the latest Raft snapshot blob, in bytes.
    #[serde(default)]
    pub snapshot_bytes: Option<u64>,
    /// Resident set size of the process, in bytes.
    #[serde(default)]
    pub rss_bytes: Option<u64>,
}

/// Whether `s` is acceptable as a node or peer slot name:
/// `[A-Za-z0-9._-]{1,`[`MAX_NAME_LEN`]`}`.
pub fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `s` is acceptable as an enum label: `[a-z0-9_]{1,`[`MAX_LABEL_LEN`]`}`.
pub fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LABEL_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Errors building or reading a sample frame.
#[derive(Debug, thiserror::Error)]
pub enum SampleFrameError {
    /// Transport failure while reading.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The length prefix was zero.
    #[error("empty sample frame")]
    Empty,
    /// The length prefix (or an encoded body) exceeds [`MAX_SAMPLE_FRAME_SIZE`].
    #[error("sample frame too large: {0} > {MAX_SAMPLE_FRAME_SIZE}")]
    TooLarge(usize),
    /// The bytes after the prefix do not match the declared length.
    #[error("sample frame length mismatch: prefix {declared}, body {actual}")]
    LengthMismatch {
        /// Length the prefix announced.
        declared: usize,
        /// Bytes actually present.
        actual: usize,
    },
    /// The body is not a CBOR [`SynchronizerSample`].
    #[error("failed to decode sample frame: {0}")]
    Decode(String),
    /// CBOR encoding failed.
    #[error("failed to encode sample frame: {0}")]
    Encode(String),
    /// The sample's schema version is not one this code implements.
    #[error("unsupported sample version {0} (supported: {SAMPLE_VERSION})")]
    UnsupportedVersion(u16),
}

/// Encode `sample` as one frame: 4-byte big-endian length, then CBOR.
/// Fails without producing bytes when the body would exceed
/// [`MAX_SAMPLE_FRAME_SIZE`].
pub fn encode_sample_frame(sample: &SynchronizerSample) -> Result<Vec<u8>, SampleFrameError> {
    let mut frame = vec![0u8; 4];
    ciborium::into_writer(sample, &mut frame)
        .map_err(|e| SampleFrameError::Encode(e.to_string()))?;
    let body_len = frame.len() - 4;
    if body_len > MAX_SAMPLE_FRAME_SIZE as usize {
        return Err(SampleFrameError::TooLarge(body_len));
    }
    let len = u32::try_from(body_len).map_err(|_| SampleFrameError::TooLarge(body_len))?;
    frame[..4].copy_from_slice(&len.to_be_bytes());
    Ok(frame)
}

/// Check a length prefix before anything is allocated for the body.
pub fn check_frame_len(len: u32) -> Result<usize, SampleFrameError> {
    if len == 0 {
        return Err(SampleFrameError::Empty);
    }
    if len > MAX_SAMPLE_FRAME_SIZE {
        return Err(SampleFrameError::TooLarge(len as usize));
    }
    Ok(len as usize)
}

/// Decode a frame body (the bytes after the length prefix) and check its
/// version.
pub fn decode_sample_body(body: &[u8]) -> Result<SynchronizerSample, SampleFrameError> {
    if body.len() > MAX_SAMPLE_FRAME_SIZE as usize {
        return Err(SampleFrameError::TooLarge(body.len()));
    }
    let sample: SynchronizerSample =
        ciborium::from_reader(body).map_err(|e| SampleFrameError::Decode(e.to_string()))?;
    if sample.version != SAMPLE_VERSION {
        return Err(SampleFrameError::UnsupportedVersion(sample.version));
    }
    Ok(sample)
}

/// Decode one complete frame (prefix plus body, nothing after it).
pub fn decode_sample_frame(frame: &[u8]) -> Result<SynchronizerSample, SampleFrameError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .and_then(|p| p.try_into().ok())
        .ok_or(SampleFrameError::LengthMismatch {
            declared: 4,
            actual: frame.len(),
        })?;
    let declared = check_frame_len(u32::from_be_bytes(prefix))?;
    let body = &frame[4..];
    if body.len() != declared {
        return Err(SampleFrameError::LengthMismatch {
            declared,
            actual: body.len(),
        });
    }
    decode_sample_body(body)
}

/// Read one frame from `stream`: the length prefix, a bounds check, then
/// exactly that many bytes. Reads nothing past the frame. The caller bounds
/// the total time (a peer that stops sending would otherwise hold this
/// forever).
#[cfg(feature = "async-transport")]
pub async fn read_sample_frame<S>(stream: &mut S) -> Result<SynchronizerSample, SampleFrameError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = check_frame_len(stream.read_u32().await?)?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    decode_sample_body(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(len: usize) -> String {
        "n".repeat(len)
    }

    /// A sample with every field populated, at the size limits.
    fn worst_case() -> SynchronizerSample {
        let bounds: Vec<u32> = (1..MAX_LATENCY_BUCKETS as u32).collect();
        let kind = |k: &str| RpcKindSample {
            kind: k.to_string(),
            outcomes: (0..MAX_RPC_CELLS)
                .map(|i| OutcomeCount {
                    outcome: format!("{}{i:02}", "o".repeat(MAX_LABEL_LEN - 2)),
                    count: u64::MAX,
                })
                .collect(),
            latency_buckets: vec![u64::MAX; bounds.len() + 1],
            latency_sum_us: u64::MAX,
        };
        SynchronizerSample {
            version: SAMPLE_VERSION,
            node: name(MAX_NAME_LEN),
            seq: u64::MAX,
            uptime_s: u64::MAX,
            export_failures: u64::MAX,
            raft: Some(RaftSample {
                role: "candidate".into(),
                term: u64::MAX,
                last_log_index: Some(u64::MAX),
                last_applied_index: Some(u64::MAX),
                snapshot_index: Some(u64::MAX),
                voters: u32::MAX,
                learners: u32::MAX,
                has_leader: true,
                millis_since_quorum_ack: Some(u64::MAX),
                peer_matched_index: (0..MAX_PEERS)
                    .map(|_| PeerMatchedIndex {
                        peer: name(MAX_NAME_LEN),
                        matched_index: Some(u64::MAX),
                    })
                    .collect(),
            }),
            join: Some(JoinSample {
                phase: "initializing".into(),
                probes: u64::MAX,
                admissions: u64::MAX,
                evictions: u64::MAX,
            }),
            peers: (0..MAX_PEERS)
                .map(|_| PeerSample {
                    peer: name(MAX_NAME_LEN),
                    connected: true,
                    channels_established: u64::MAX,
                    dial_failures: u64::MAX,
                    pings: u64::MAX,
                    pong_timeouts: u64::MAX,
                    last_ping_rtt_us: Some(u64::MAX),
                })
                .collect(),
            rpc: RpcSample {
                latency_bounds_ms: bounds.clone(),
                kinds: ["get", "pin", "register", "transition"]
                    .into_iter()
                    .map(kind)
                    .collect(),
                routed_local: u64::MAX,
                routed_forwarded: u64::MAX,
                routed_unavailable: u64::MAX,
                forwarded_served: u64::MAX,
            },
            rejections: (0..MAX_REJECTION_CELLS)
                .map(|_| RejectionCount {
                    source: "transition_link".into(),
                    reason: "l".repeat(MAX_LABEL_LEN),
                    count: u64::MAX,
                })
                .collect(),
            clock: ClockSample {
                offset_ms: Some(i64::MIN),
            },
            resources: ResourceSample {
                live_keys: Some(u64::MAX),
                retired_keys: Some(u64::MAX),
                snapshot_bytes: Some(u64::MAX),
                rss_bytes: Some(u64::MAX),
            },
        }
    }

    #[test]
    fn frame_round_trips() {
        let s = worst_case();
        let frame = encode_sample_frame(&s).unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        assert_eq!(decode_sample_frame(&frame).unwrap(), s);
    }

    /// A sample with every list at its documented cap, every name and label
    /// at its maximum length and every counter at `u64::MAX` still fits the
    /// frame bound. (What the synchronizer actually produces is far smaller;
    /// its own test checks that with headroom.)
    #[test]
    fn worst_case_sample_fits() {
        let frame = encode_sample_frame(&worst_case()).unwrap();
        let body = frame.len() - 4;
        assert!(
            body <= MAX_SAMPLE_FRAME_SIZE as usize,
            "worst-case body is {body} bytes, over the {MAX_SAMPLE_FRAME_SIZE} cap"
        );
    }

    #[test]
    fn oversized_sample_is_not_encoded() {
        let mut s = worst_case();
        s.peers = (0..1000)
            .map(|_| PeerSample {
                peer: name(MAX_NAME_LEN),
                ..Default::default()
            })
            .collect();
        assert!(matches!(
            encode_sample_frame(&s),
            Err(SampleFrameError::TooLarge(_))
        ));
    }

    #[test]
    fn bad_prefixes_are_rejected() {
        assert!(matches!(check_frame_len(0), Err(SampleFrameError::Empty)));
        assert!(matches!(
            check_frame_len(MAX_SAMPLE_FRAME_SIZE + 1),
            Err(SampleFrameError::TooLarge(_))
        ));
        assert!(matches!(
            check_frame_len(u32::MAX),
            Err(SampleFrameError::TooLarge(_))
        ));
        assert_eq!(check_frame_len(MAX_SAMPLE_FRAME_SIZE).unwrap(), 16 * 1024);
    }

    #[test]
    fn garbage_and_truncation_are_rejected() {
        // Not CBOR.
        let mut frame = 4u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(
            decode_sample_frame(&frame),
            Err(SampleFrameError::Decode(_))
        ));
        // Valid CBOR of the wrong shape.
        let mut body = Vec::new();
        ciborium::into_writer(&vec![1u8, 2, 3], &mut body).unwrap();
        assert!(matches!(
            decode_sample_body(&body),
            Err(SampleFrameError::Decode(_))
        ));
        // Truncated and over-long frames.
        let good = encode_sample_frame(&worst_case()).unwrap();
        assert!(matches!(
            decode_sample_frame(&good[..good.len() - 1]),
            Err(SampleFrameError::LengthMismatch { .. })
        ));
        let mut long = good.clone();
        long.push(0);
        assert!(matches!(
            decode_sample_frame(&long),
            Err(SampleFrameError::LengthMismatch { .. })
        ));
        assert!(matches!(
            decode_sample_frame(&good[..3]),
            Err(SampleFrameError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let s = SynchronizerSample {
            version: SAMPLE_VERSION + 1,
            node: "az-a".into(),
            ..Default::default()
        };
        let frame = encode_sample_frame(&s).unwrap();
        assert!(matches!(
            decode_sample_frame(&frame),
            Err(SampleFrameError::UnsupportedVersion(v)) if v == SAMPLE_VERSION + 1
        ));
    }

    /// A receiver built from this version accepts a sample that carries a
    /// field it does not know, and one that omits every defaulted field.
    #[test]
    fn additive_fields_are_compatible() {
        #[derive(Serialize)]
        struct Newer {
            version: u16,
            node: String,
            seq: u64,
            uptime_s: u64,
            some_future_gauge: u64,
        }
        let mut body = Vec::new();
        ciborium::into_writer(
            &Newer {
                version: SAMPLE_VERSION,
                node: "az-b".into(),
                seq: 7,
                uptime_s: 9,
                some_future_gauge: 42,
            },
            &mut body,
        )
        .unwrap();
        let s = decode_sample_body(&body).unwrap();
        assert_eq!(s.node, "az-b");
        assert_eq!(s.seq, 7);
        assert!(s.raft.is_none());
        assert!(s.peers.is_empty());
    }

    /// Collect every map key in a serialized value, as dotted paths with
    /// list elements collapsed to `[]`.
    fn field_paths(v: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let path = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    out.push(path.clone());
                    field_paths(v, &path, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    field_paths(item, &format!("{prefix}[]"), out);
                }
            }
            _ => {}
        }
    }

    /// The sample carries exactly these fields. Adding one is a deliberate
    /// review point: it must be an aggregate (counter, gauge, histogram or
    /// state) and must not identify a customer, volume, enclave, key,
    /// commitment, PCR set, Raft node id or address. Update this list only
    /// after that check.
    #[test]
    fn sample_carries_only_allowed_fields() {
        const ALLOWED: &[&str] = &[
            "version",
            "node",
            "seq",
            "uptime_s",
            "export_failures",
            "raft",
            "raft.role",
            "raft.term",
            "raft.last_log_index",
            "raft.last_applied_index",
            "raft.snapshot_index",
            "raft.voters",
            "raft.learners",
            "raft.has_leader",
            "raft.millis_since_quorum_ack",
            "raft.peer_matched_index",
            "raft.peer_matched_index[].peer",
            "raft.peer_matched_index[].matched_index",
            "join",
            "join.phase",
            "join.probes",
            "join.admissions",
            "join.evictions",
            "peers",
            "peers[].peer",
            "peers[].connected",
            "peers[].channels_established",
            "peers[].dial_failures",
            "peers[].pings",
            "peers[].pong_timeouts",
            "peers[].last_ping_rtt_us",
            "rpc",
            "rpc.latency_bounds_ms",
            "rpc.kinds",
            "rpc.kinds[].kind",
            "rpc.kinds[].outcomes",
            "rpc.kinds[].outcomes[].outcome",
            "rpc.kinds[].outcomes[].count",
            "rpc.kinds[].latency_buckets",
            "rpc.kinds[].latency_sum_us",
            "rpc.routed_local",
            "rpc.routed_forwarded",
            "rpc.routed_unavailable",
            "rpc.forwarded_served",
            "rejections",
            "rejections[].source",
            "rejections[].reason",
            "rejections[].count",
            "clock",
            "clock.offset_ms",
            "resources",
            "resources.live_keys",
            "resources.retired_keys",
            "resources.snapshot_bytes",
            "resources.rss_bytes",
        ];
        let value = serde_json::to_value(worst_case()).unwrap();
        let mut paths = Vec::new();
        field_paths(&value, "", &mut paths);
        paths.sort();
        paths.dedup();
        let mut allowed: Vec<String> = ALLOWED.iter().map(|s| s.to_string()).collect();
        allowed.sort();
        assert_eq!(paths, allowed);
    }

    /// Nothing in the sample has room for raw bytes (a key, a digest, a
    /// document): the only arrays of scalars are the two histogram shapes.
    #[test]
    fn only_histograms_are_scalar_arrays() {
        fn walk(v: &serde_json::Value, path: &str, found: &mut Vec<String>) {
            match v {
                serde_json::Value::Array(items) => {
                    if items.iter().any(|i| !i.is_object()) {
                        found.push(path.to_string());
                    }
                    for item in items {
                        walk(item, &format!("{path}[]"), found);
                    }
                }
                serde_json::Value::Object(map) => {
                    for (k, v) in map {
                        let p = if path.is_empty() {
                            k.clone()
                        } else {
                            format!("{path}.{k}")
                        };
                        walk(v, &p, found);
                    }
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        walk(&serde_json::to_value(worst_case()).unwrap(), "", &mut found);
        found.sort();
        found.dedup();
        assert_eq!(
            found,
            vec![
                "rpc.kinds[].latency_buckets".to_string(),
                "rpc.latency_bounds_ms".to_string()
            ]
        );
    }

    #[test]
    fn name_and_label_validation() {
        assert!(is_valid_name("az-a"));
        assert!(is_valid_name("sync.eu-west-1_b"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name(&"x".repeat(MAX_NAME_LEN + 1)));
        assert!(!is_valid_name("a\"b"));
        assert!(!is_valid_name("a b"));
        assert!(!is_valid_name("a\nb"));
        assert!(!is_valid_name("a}b"));
        assert!(is_valid_label("pcr_mismatch"));
        assert!(is_valid_label("p99"));
        assert!(!is_valid_label("Leader"));
        assert!(!is_valid_label("a-b"));
        assert!(!is_valid_label(""));
        assert!(!is_valid_label(&"x".repeat(MAX_LABEL_LEN + 1)));
    }

    #[cfg(feature = "async-transport")]
    #[tokio::test]
    async fn stream_read_round_trips_and_stops_at_frame_end() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let s = worst_case();
        let frame = encode_sample_frame(&s).unwrap();
        a.write_all(&frame).await.unwrap();
        a.write_all(b"trailing bytes the reader must not consume")
            .await
            .unwrap();
        assert_eq!(read_sample_frame(&mut b).await.unwrap(), s);
    }

    #[cfg(feature = "async-transport")]
    #[tokio::test]
    async fn stream_read_rejects_oversized_prefix_before_body() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        // Only the prefix is sent; the reader must fail on it rather than
        // wait for (or allocate) a 4 GiB body.
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_sample_frame(&mut b).await,
            Err(SampleFrameError::TooLarge(_))
        ));
    }

    #[cfg(feature = "async-transport")]
    #[tokio::test]
    async fn stream_read_rejects_truncated_body() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(&[0u8; 10]).await.unwrap();
        drop(a);
        assert!(matches!(
            read_sample_frame(&mut b).await,
            Err(SampleFrameError::Io(_))
        ));
    }
}
