//! `enclavia-chain-init` (#47, phase 3b): in-enclave boot-attestation
//! submitter.
//!
//! Pipeline at boot, called from the in-enclave `init.sh` between
//! "filesystems mounted + secrets injected" and "crun start":
//!
//! ```text
//!   read /etc/enclavia/config.json -> { enclave_id, image_digest, pcrs ... }
//!     v
//!   build BootPayload { enclave_id, image_digest, pcrs, booted_at, nonce }
//!     v
//!   CBOR-encode payload
//!     v
//!   NSM Attestation { user_data = sha256(payload), nonce = 32 random bytes }
//!     v
//!   wrap into enclavia_protocol::chain::ChainLink { kind: Boot, ... }
//!     v
//!   CBOR-encode link
//!     v
//!   open vsock CID 2 (host), port 5005 with a tolerant timeout
//!     v
//!   write [u32 BE length prefix | CBOR ChainLink bytes]
//!     v
//!   shutdown(WRITE), drain to EOF (5s ceiling), exit 0
//! ```
//!
//! Failure modes: any error (missing config, bad config, NSM init,
//! vsock connect, write) is fatal. The host-side `chain-host` daemon is
//! long-lived (it serves upgrade + revocation links later in the
//! enclave's life), so a connect refused here means something is
//! genuinely wrong on the parent and we'd rather fail the boot loudly
//! than launch the workload without an attested chain entry.
//!
//! Wire format mirrors what `chain-host` re-encodes for the backend's
//! `POST /internal/enclaves/{id}/chain-links` JSON endpoint: opaque
//! `payload` / `attestation` / `signature` bytes that the backend
//! re-decodes with `enclavia_protocol::chain::validate_chain_link`. The
//! `id` and `sequence` fields are absent in the on-wire link (boot
//! genesis carries no signature either).

use std::path::{Path, PathBuf};

use enclavia_protocol::chain::{BootPayload, ChainLink, ChainLinkKind, PcrsHex};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

mod attestation;
mod config;

/// VMADDR_CID_HOST per the Linux vsock contract. Same value in real
/// Nitro and QEMU debug mode (the latter routes the connection through
/// `vhost-device-vsock` -> `<proxy>_5005` UDS).
const VSOCK_HOST_CID: u32 = 2;

/// Port the host-side `chain-host` daemon listens on (#47, phase 3b).
const CHAIN_HOST_PORT: u32 = 5005;

/// Vsock connect ceiling. The host-side daemon is launched by the
/// parent's systemd unit before the QEMU boot starts and stays up for
/// the enclave's life, so a healthy parent responds in milliseconds.
/// 30s matches the secrets-init tolerance for shared-host load (CI
/// matrix runs multiple QEMUs concurrently and virtio-vsock latency
/// grows under contention).
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Half-close drain ceiling: how long we wait for the host to ack and
/// EOF after we shutdown(WRITE). The host writes back at most a tiny
/// JSON response from the backend; 5s is generous.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Default path for the enclavia in-enclave config. Same path the
/// secrets-init and enclavia-server read.
const CONFIG_PATH: &str = "/etc/enclavia/config.json";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    if let Err(e) = run(Path::new(CONFIG_PATH)).await {
        error!("chain-init failed: {e}");
        std::process::exit(1);
    }
}

async fn run(config_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = config::load(config_path)?;
    info!(
        enclave_id = %cfg.enclave_id,
        image_digest = %cfg.image_digest,
        "loaded chain-init config"
    );

    // Build the BootPayload. PCRs come from the NSM `DescribePCR` calls
    // below so the payload's PCRs and the attestation's PCRs are read
    // from the same source (the alternative is reading them off a file
    // the launcher writes, but then the launcher and NSM could disagree
    // and we'd have to reconcile two sources of truth).
    let nsm = attestation::Nsm::open()?;
    let pcrs = nsm.read_pcrs()?;
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let payload = BootPayload {
        enclave_id: cfg.enclave_id,
        image_digest: cfg.image_digest,
        pcrs: PcrsHex {
            pcr0: hex::encode(&pcrs.pcr0),
            pcr1: hex::encode(&pcrs.pcr1),
            pcr2: hex::encode(&pcrs.pcr2),
        },
        booted_at: chrono::Utc::now(),
        nonce: nonce_bytes.to_vec(),
    };

    let mut payload_bytes = Vec::with_capacity(512);
    ciborium::ser::into_writer(&payload, &mut payload_bytes)?;

    // user_data binds the attestation to the payload bytes verbatim.
    // The backend's `verify_chain_attestation` recomputes sha256(payload)
    // and rejects on mismatch.
    let mut hasher = Sha256::new();
    hasher.update(&payload_bytes);
    let user_data: [u8; 32] = hasher.finalize().into();

    let attestation = nsm.attest(&user_data, &nonce_bytes)?;
    info!(
        payload_bytes = payload_bytes.len(),
        attestation_bytes = attestation.len(),
        "produced boot attestation"
    );

    let link = ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Boot,
        payload: payload_bytes,
        attestation,
        signature: None,
    };

    let mut link_bytes = Vec::with_capacity(1024);
    ciborium::ser::into_writer(&link, &mut link_bytes)?;

    submit(&link_bytes).await?;
    info!(
        link_bytes = link_bytes.len(),
        "boot chain link submitted; exiting"
    );
    Ok(())
}

/// Connect to the host-side `chain-host` daemon, write the
/// length-prefixed CBOR link, and drain the response to EOF.
///
/// The host always answers, even when ingest is disabled (it just
/// writes nothing and closes), so a successful drain means the bytes
/// landed on the parent's TCP buffer to the backend. Failures here
/// surface verbatim because every step is unrecoverable: a connect
/// refused means the launcher mis-wired the daemon, a write error
/// means the parent dropped us mid-stream, etc.
async fn submit(
    link_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(VSOCK_HOST_CID, CHAIN_HOST_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err(format!(
                "vsock {VSOCK_HOST_CID}:{CHAIN_HOST_PORT} connect timed out after {CONNECT_TIMEOUT:?}"
            )
            .into());
        }
    };

    let len: u32 = link_bytes
        .len()
        .try_into()
        .map_err(|_| "chain link too large to encode as u32-prefixed frame".to_string())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(link_bytes).await?;
    // Half-close the write side so the host's read loop sees EOF on the
    // frame and can return the response. AsyncWriteExt::shutdown is the
    // tokio analogue of shutdown(2, SHUT_WR); tokio-vsock implements
    // it via the underlying socket call.
    tokio::io::AsyncWriteExt::shutdown(&mut stream).await?;

    // Drain to EOF so the host can finish its end-of-message ack
    // sequence. A bounded read here avoids hanging if the host
    // misbehaves; 5s is generous given the host's response is at most
    // a tiny acknowledgement.
    let mut sink = [0u8; 64];
    loop {
        match tokio::time::timeout(DRAIN_TIMEOUT, stream.read(&mut sink)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) => {
                // Drain timed out. The frame already went out and the
                // host has no further obligation, so this is best-effort
                // cleanup; promote to a warning instead of a hard fail.
                tracing::warn!(
                    timeout = ?DRAIN_TIMEOUT,
                    "draining chain-host response timed out; continuing"
                );
                break;
            }
        }
    }
    Ok(())
}

/// Tiny helper for unit tests in submodules to call into without
/// needing a full `PathBuf` round-trip.
#[allow(dead_code)]
pub(crate) fn config_path_default() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}
