//! Runtime detection of the host vsock CID for in-enclave binaries.
//!
//! A single EIF boots on both QEMU and real AWS Nitro, but the CID the
//! enclave dials to reach the host differs:
//!
//! * **Real AWS Nitro:** the parent EC2 instance is `VMADDR_CID_PARENT` == 3
//!   (AWS' upstream `init.c` dials CID 3; AWS docs fix the parent at 3).
//! * **QEMU + `vhost-device-vsock`:** only `VMADDR_CID_HOST` == 2 is
//!   routable to the host bridge; CID 3 goes nowhere.
//!
//! The in-enclave init (the patched Go init shared by every EIF) heartbeats
//! BOTH CIDs at boot and so learns definitively which one the host answers
//! on. It records that CID in [`HOST_CID_PATH`] before launching any
//! workload, and [`host_cid`] just reads the file.
//!
//! Reading the init-recorded value is strictly more robust than a post-boot
//! reachability probe: on real Nitro the parent's readiness listener on
//! CID 3:9000 may already be gone by the time a binary runs, so a probe
//! could wrongly conclude QEMU. The init, by contrast, observed the answer
//! at the one moment the listener is guaranteed up (the readiness handshake).
//!
//! If the file is missing (e.g. a binary run outside a patched-init EIF), we
//! fall back to the legacy reachability probe and log a warning. The probe is
//! reliable on QEMU (CID 3 is genuinely unreachable there) and only
//! unreliable in exactly the Nitro case the file was meant to cover.
//!
//! This is NOT a security decision. A wrong guess only fails closed (the
//! enclave cannot reach the host either way), and a hostile host can deny
//! service regardless, so detection only has to be correct in the honest
//! case. That is also why a simple recorded/probed signal is enough and no
//! attested/trusted signal is required.

use std::sync::OnceLock;
use std::time::Duration;

/// Real AWS Nitro parent (`VMADDR_CID_PARENT`).
pub const NITRO_PARENT_CID: u32 = 3;
/// QEMU / `vhost-device-vsock` host (`VMADDR_CID_HOST`).
pub const QEMU_HOST_CID: u32 = 2;

/// File the in-enclave init writes with the host CID its boot-time heartbeat
/// answered on (one of [`NITRO_PARENT_CID`] / [`QEMU_HOST_CID`], as ASCII
/// decimal). Lives on the init-mounted `/run` tmpfs; the Go init writes the
/// same path (`HOST_CID_PATH` in `init.go`).
pub const HOST_CID_PATH: &str = "/run/enclavia-host-cid";

/// Port the fallback probe dials on the parent CID. The in-enclave init
/// heartbeats here, so a listener exists on the real host during boot in
/// both environments.
const PROBE_PORT: u32 = 9000;

/// How long to wait for the CID-3 fallback probe before concluding QEMU.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

static CACHE: OnceLock<u32> = OnceLock::new();

/// The host vsock CID this enclave should dial, detected once and cached.
///
/// Prefers the init-recorded value in [`HOST_CID_PATH`]; falls back to a
/// reachability probe (CID 3 reachable => Nitro, else QEMU) only when that
/// file is absent or invalid. See the module docs.
pub async fn host_cid() -> u32 {
    if let Some(c) = CACHE.get() {
        return *c;
    }
    let cid = match read_host_cid_file() {
        Some(cid) => {
            tracing::info!(
                selected_cid = cid,
                path = HOST_CID_PATH,
                "host vsock CID read from init-recorded file"
            );
            cid
        }
        None => {
            let cid = if probe_reachable(NITRO_PARENT_CID).await {
                NITRO_PARENT_CID
            } else {
                QEMU_HOST_CID
            };
            tracing::warn!(
                selected_cid = cid,
                path = HOST_CID_PATH,
                "init-recorded host CID file absent/invalid; fell back to reachability probe \
                 (unreliable on Nitro)"
            );
            cid
        }
    };
    *CACHE.get_or_init(|| cid)
}

/// Read and validate the init-recorded host CID file. Returns `Some(cid)`
/// only when the file exists and holds exactly one of the two known CIDs.
fn read_host_cid_file() -> Option<u32> {
    let raw = std::fs::read_to_string(HOST_CID_PATH).ok()?;
    parse_host_cid(&raw)
}

/// Parse the host CID file contents: a single ASCII-decimal CID, optionally
/// surrounded by whitespace, that must be one of the two known CIDs.
fn parse_host_cid(raw: &str) -> Option<u32> {
    let cid: u32 = raw.trim().parse().ok()?;
    (cid == NITRO_PARENT_CID || cid == QEMU_HOST_CID).then_some(cid)
}

/// True if a vsock connection to `(cid, PROBE_PORT)` completes within the
/// timeout. Any error or timeout is treated as unreachable.
async fn probe_reachable(cid: u32) -> bool {
    matches!(
        tokio::time::timeout(
            PROBE_TIMEOUT,
            tokio_vsock::VsockStream::connect(cid, PROBE_PORT),
        )
        .await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_cids() {
        assert_eq!(parse_host_cid("3\n"), Some(NITRO_PARENT_CID));
        assert_eq!(parse_host_cid("2"), Some(QEMU_HOST_CID));
        assert_eq!(parse_host_cid("  3  \n"), Some(NITRO_PARENT_CID));
    }

    #[test]
    fn rejects_unknown_or_garbage() {
        assert_eq!(parse_host_cid("4"), None);
        assert_eq!(parse_host_cid("0"), None);
        assert_eq!(parse_host_cid(""), None);
        assert_eq!(parse_host_cid("nope"), None);
        assert_eq!(parse_host_cid("3 2"), None);
    }
}
