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
use enclavia_protocol::{CHAIN_LINK_ACK, submit_chain_link};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

mod attestation;
mod config;


/// Port the host-side `chain-host` daemon listens on (#47, phase 3b).
const CHAIN_HOST_PORT: u32 = 5005;

/// Vsock connect ceiling. The host-side daemon is launched by the
/// parent's systemd unit before the QEMU boot starts and stays up for
/// the enclave's life, so a healthy parent responds in milliseconds.
/// 30s matches the secrets-init tolerance for shared-host load (CI
/// matrix runs multiple QEMUs concurrently and virtio-vsock latency
/// grows under contention).
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long we wait for the host's 1-byte ACK after we shutdown(WRITE).
/// The ack is the host telling us the backend POST completed; a healthy
/// path is single-digit milliseconds. 5s is generous slack.
const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Default path for the enclavia in-enclave config. Same path the
/// secrets-init and enclavia-server read.
const CONFIG_PATH: &str = "/etc/enclavia/config.json";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // Output lands on the serial console; ANSI escapes turn into
        // literal garbage there. Same setting as every other in-enclave
        // daemon.
        .with_ansi(false)
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

    submit(&link).await?;
    info!("boot chain link submitted; exiting");
    Ok(())
}

/// Connect to the host-side `chain-host` daemon, write the
/// length-prefixed CBOR link, and wait for the ACK byte.
///
/// Uses the shared `enclavia_protocol::submit_chain_link` helper so the
/// wire format is guaranteed to match what `chain-host` (and
/// `enclavia-server`) expect. Failures here are fatal: a connect refused
/// means the launcher mis-wired the daemon; a write error means the parent
/// dropped us mid-stream.
async fn submit(link: &ChainLink) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cid = enclavia_vsock::host_cid().await;
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, CHAIN_HOST_PORT)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err(format!(
                "vsock {cid}:{CHAIN_HOST_PORT} connect timed out after {CONNECT_TIMEOUT:?}"
            )
            .into());
        }
    };

    // The shared helper serialises, writes the length-prefix+body in chunks
    // safe for AF_VSOCK, calls shutdown(WRITE), and reads the ACK byte.
    match submit_chain_link(&mut stream, link, ACK_TIMEOUT).await {
        Ok(ack) if ack != CHAIN_LINK_ACK => {
            warn!(
                byte = ack,
                "chain-host sent unexpected ack byte; continuing"
            );
        }
        Ok(_) => {}
        Err(e) => {
            // ACK errors are warn-not-fail: the link bytes already went out and
            // an absent ACK doesn't tell us whether the backend accepted them.
            warn!("chain-host ack failed: {e}; continuing");
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
