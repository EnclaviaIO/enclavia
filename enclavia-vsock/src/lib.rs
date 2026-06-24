//! Runtime detection of the host vsock CID for in-enclave binaries.
//!
//! A single EIF should boot on both QEMU and real AWS Nitro, but the CID
//! the enclave dials to reach the host differs:
//!
//! * **Real AWS Nitro:** the parent EC2 instance is `VMADDR_CID_PARENT` == 3
//!   (AWS' upstream `init.c` dials CID 3; AWS docs fix the parent at 3).
//! * **QEMU + `vhost-device-vsock`:** only `VMADDR_CID_HOST` == 2 is
//!   routable to the host bridge; CID 3 goes nowhere.
//!
//! [`host_cid`] probes for this once: it tries to reach CID 3 on the
//! heartbeat port (where a host listener exists in both environments, set
//! up by the in-enclave init's heartbeat). If CID 3 answers we are on
//! Nitro, otherwise QEMU. The result is cached for the process lifetime.
//!
//! This is NOT a security decision. A wrong guess only fails closed (the
//! enclave cannot reach the host either way), and a hostile host can deny
//! service regardless, so the probe only has to be correct in the honest
//! case. That is also why a simple reachability probe is enough and no
//! attested/trusted signal is required.

use std::sync::OnceLock;
use std::time::Duration;

/// Real AWS Nitro parent (`VMADDR_CID_PARENT`).
pub const NITRO_PARENT_CID: u32 = 3;
/// QEMU / `vhost-device-vsock` host (`VMADDR_CID_HOST`).
pub const QEMU_HOST_CID: u32 = 2;

/// Port the probe dials on the parent CID. The in-enclave init heartbeats
/// here, so a listener exists on the real host in BOTH environments (a
/// `vhost-device-vsock` bridge to `heartbeat.py` under QEMU, the parent's
/// heartbeat handler under Nitro).
const PROBE_PORT: u32 = 9000;

/// How long to wait for the CID-3 probe before concluding QEMU.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

static CACHE: OnceLock<u32> = OnceLock::new();

/// The host vsock CID this enclave should dial, detected once and cached.
///
/// Returns [`NITRO_PARENT_CID`] (3) when the parent answers the probe,
/// otherwise [`QEMU_HOST_CID`] (2). See the module docs.
pub async fn host_cid() -> u32 {
    if let Some(c) = CACHE.get() {
        return *c;
    }
    let cid = if probe_reachable(NITRO_PARENT_CID).await {
        NITRO_PARENT_CID
    } else {
        QEMU_HOST_CID
    };
    tracing::info!(
        selected_cid = cid,
        probe_port = PROBE_PORT,
        "host vsock CID detected by probe (CID 3 reachable => Nitro, else QEMU)"
    );
    *CACHE.get_or_init(|| cid)
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
