//! Wire format for the in-enclave monitor daemon (`enclavia-monitor`).
//!
//! The monitor daemon runs inside the enclave next to the workload and
//! has two duties, each with its own vsock port and frame type:
//!
//! * **Telemetry** (guest -> host, [`MONITOR_SAMPLE_PORT`]): every tick
//!   the daemon dials the host and writes exactly one length-prefixed
//!   CBOR [`MonitorSample`] frame, then closes. Connect-per-sample
//!   (single-shot, like the secrets pull) keeps the host-side relay
//!   trivial: accept, read one frame, forward, done. The host-side
//!   relay lives outside this repository and forwards each sample to
//!   the backend.
//!
//! * **Graceful shutdown** (host -> guest, [`MONITOR_SHUTDOWN_PORT`]):
//!   before tearing an enclave down, the host dials the guest's
//!   shutdown listener, writes one [`ShutdownRequest`] frame, and waits
//!   for the [`ShutdownAck`] frame. In between, the daemon flushes the
//!   data mount (`syncfs` forces the filesystem commit, which also
//!   drives the storage client's superblock pin) so a subsequent kill
//!   never loses acknowledged writes. The host proceeds with the kill
//!   after the ack, or after a timeout for images that predate the
//!   monitor.
//!
//! Framing mirrors `enclavia_protocol::egress` / `mesh` exactly: a
//! 4-byte big-endian length prefix, then the CBOR-encoded frame. Frames
//! here are tiny (well under the 32 KiB single-vsock-write ceiling).
//! Transport (vsock from inside the enclave, AF_VSOCK or
//! `vhost-device-vsock` UDS on the host depending on the runtime) is
//! external to this module: callers hand in any `AsyncRead + AsyncWrite`
//! and the helpers read or write one frame.

use std::io;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// vsock port the in-enclave monitor daemon dials on its host (guest ->
/// host) to deliver one [`MonitorSample`] frame per telemetry tick.
/// 5000-5013 are already allocated (server, storage, meta, kms,
/// secrets, chain, egress, control, synchronizer bootstrap/mesh/client/
/// names, customer relay, aws-creds); 5014 is the first free slot.
pub const MONITOR_SAMPLE_PORT: u32 = 5014;

/// vsock port the in-enclave monitor daemon LISTENS on (host -> guest)
/// for the graceful-shutdown exchange: one [`ShutdownRequest`] in, one
/// [`ShutdownAck`] out. Next free slot after [`MONITOR_SAMPLE_PORT`].
pub const MONITOR_SHUTDOWN_PORT: u32 = 5015;

/// Maximum size (in bytes) of any monitor CBOR frame. Plenty of room
/// for the small structs we serialize today, but tight enough to reject
/// obvious junk before allocating. Mirrors `egress::MAX_OPEN_FRAME_SIZE`.
pub const MAX_MONITOR_FRAME_SIZE: u32 = 4096;

/// One telemetry sample, sent guest -> host per tick.
///
/// Optional fields are `None` when the underlying signal is not
/// available in this enclave (no health path configured, no data mount)
/// rather than overloading a sentinel value; the backend treats absent
/// fields as "not applicable", not "failing".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorSample {
    /// Monotonic per-boot sample counter, starting at 0. Lets the
    /// receiving side spot gaps (dropped samples) and reordering.
    pub seq: u64,
    /// Seconds since the monitor daemon started (approximates enclave
    /// uptime: init launches the daemon alongside the workload).
    pub uptime_s: u64,
    /// Whether a TCP connect to the workload's loopback port succeeded
    /// this tick. `false` when the workload refused the connection OR
    /// when no workload port was configured (the daemon logs the
    /// distinction once at startup).
    pub workload_alive: bool,
    /// 2xx-ness of an HTTP GET against the configured health path.
    /// `None` when no health path is configured or the workload port is
    /// unknown; `Some(false)` covers both non-2xx responses and
    /// connect/parse failures.
    pub http_health: Option<bool>,
    /// Used bytes on the data mount. `None` when the data mount is
    /// absent (non-storage enclave).
    pub disk_used_bytes: Option<u64>,
    /// Total bytes on the data mount. `None` when the data mount is
    /// absent (non-storage enclave).
    pub disk_total_bytes: Option<u64>,
}

/// Graceful-shutdown request, sent host -> guest.
///
/// Deliberately empty for v1 (the frame's arrival IS the request), but
/// a struct rather than a bare signal byte so future fields (a deadline
/// hint, a reason) can land without a wire break: CBOR maps tolerate
/// unknown/absent fields under serde defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownRequest {}

/// Graceful-shutdown acknowledgement, sent guest -> host after the
/// flush. The host kills the VM after reading this (or after its own
/// timeout).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownAck {
    /// Whether the data-mount `syncfs` (the actual durability barrier)
    /// succeeded. `false` means the host should treat buffered writes
    /// as potentially lost; it still proceeds with the shutdown.
    pub synced: bool,
}

/// Errors surfaced while reading a monitor frame from a stream.
#[derive(Debug, thiserror::Error)]
pub enum ReadFrameError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("monitor frame too large: {0} > {MAX_MONITOR_FRAME_SIZE}")]
    FrameTooLarge(u32),
    #[error("failed to decode monitor frame: {0}")]
    Decode(#[from] ciborium::de::Error<io::Error>),
}

/// Read one length-prefixed CBOR monitor frame from `stream`.
///
/// Generic over the frame type: the same helper reads a
/// [`MonitorSample`] on the host side, a [`ShutdownRequest`] on the
/// guest side, and a [`ShutdownAck`] back on the host side.
pub async fn read_frame<S, T>(stream: &mut S) -> Result<T, ReadFrameError>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let len = stream.read_u32().await?;
    if len > MAX_MONITOR_FRAME_SIZE {
        return Err(ReadFrameError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    let frame: T = ciborium::from_reader(&buf[..])?;
    Ok(frame)
}

/// Write one length-prefixed CBOR monitor frame to `stream`.
pub async fn write_frame<S, T>(stream: &mut S, frame: &T) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(frame, &mut buf).expect("ciborium encode monitor frame");
    let len: u32 = buf
        .len()
        .try_into()
        .expect("monitor frame fits in u32 (CBOR encoding is small)");
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MonitorSample {
        MonitorSample {
            seq: 42,
            uptime_s: 1260,
            workload_alive: true,
            http_health: Some(true),
            disk_used_bytes: Some(123_456_789),
            disk_total_bytes: Some(10_737_418_240),
        }
    }

    #[test]
    fn sample_roundtrip_cbor() {
        let s = sample();
        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf).unwrap();
        let decoded: MonitorSample = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn sample_roundtrip_cbor_absent_optionals() {
        let s = MonitorSample {
            seq: 0,
            uptime_s: 0,
            workload_alive: false,
            http_health: None,
            disk_used_bytes: None,
            disk_total_bytes: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf).unwrap();
        let decoded: MonitorSample = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn shutdown_types_roundtrip_cbor() {
        let mut buf = Vec::new();
        ciborium::into_writer(&ShutdownRequest {}, &mut buf).unwrap();
        let _req: ShutdownRequest = ciborium::from_reader(&buf[..]).unwrap();

        let ack = ShutdownAck { synced: true };
        let mut buf = Vec::new();
        ciborium::into_writer(&ack, &mut buf).unwrap();
        let decoded: ShutdownAck = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(ack, decoded);
    }

    #[tokio::test]
    async fn framed_roundtrip_over_stream() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let s = sample();
        write_frame(&mut a, &s).await.unwrap();
        let decoded: MonitorSample = read_frame(&mut b).await.unwrap();
        assert_eq!(s, decoded);
    }

    #[tokio::test]
    async fn framed_shutdown_exchange() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        write_frame(&mut host, &ShutdownRequest {}).await.unwrap();
        let _req: ShutdownRequest = read_frame(&mut guest).await.unwrap();
        write_frame(&mut guest, &ShutdownAck { synced: true })
            .await
            .unwrap();
        let ack: ShutdownAck = read_frame(&mut host).await.unwrap();
        assert!(ack.synced);
    }

    #[tokio::test]
    async fn oversized_length_prefix_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // A length prefix over the cap must be rejected before any
        // allocation, even though no payload bytes follow.
        let bogus = (MAX_MONITOR_FRAME_SIZE + 1).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut a, &bogus)
            .await
            .unwrap();
        let err = read_frame::<_, MonitorSample>(&mut b).await.unwrap_err();
        assert!(matches!(
            err,
            ReadFrameError::FrameTooLarge(n) if n == MAX_MONITOR_FRAME_SIZE + 1
        ));
    }

    #[tokio::test]
    async fn empty_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // Zero-length frame: the prefix passes the size check but there
        // is no CBOR item to decode, so it must surface as Decode.
        tokio::io::AsyncWriteExt::write_all(&mut a, &0u32.to_be_bytes())
            .await
            .unwrap();
        let err = read_frame::<_, MonitorSample>(&mut b).await.unwrap_err();
        assert!(matches!(err, ReadFrameError::Decode(_)));
    }

    #[tokio::test]
    async fn truncated_stream_surfaces_io_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // Announce 16 bytes, deliver 4, then hang up.
        tokio::io::AsyncWriteExt::write_all(&mut a, &16u32.to_be_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8; 4])
            .await
            .unwrap();
        drop(a);
        let err = read_frame::<_, MonitorSample>(&mut b).await.unwrap_err();
        assert!(matches!(err, ReadFrameError::Io(_)));
    }
}
