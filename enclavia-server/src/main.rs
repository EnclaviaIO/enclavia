use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use enclavia_protocol::chain::{ChainLink, ChainLinkKind};
use enclavia_protocol::{
    CHAIN_LINK_ACK, ClientMessage, ControlCommand, RekeyParams, ServerMessage, StreamHalf,
    perform_cbor_handshake_as_responder,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tracing::{error, info, instrument, trace, warn};

mod attestation;
mod config;

use tokio_vsock::VsockListener;
use tokio_vsock::VsockStream;

const VSOCK_PORT: u32 = 5000;

/// Control-channel vsock port. Same Noise responder as the public port,
/// but only `GetControlNonce` / `Control` (plus `RequestAttestation`)
/// are accepted here, and the public port rejects them in turn. The
/// router only ever bridges port 5000, so this port is reachable
/// exclusively from the host side (the backend's control dispatch).
/// Isolating the control surface means an anonymous internet client can
/// no longer churn the single-use control nonce (each `Control` attempt
/// rotates it before the signature check, so public reachability allowed
/// a trivial unauthenticated DoS of confirm/revoke) and never reaches
/// the control parser/verifier at all. 5001-5006 are taken by storage,
/// meta, kms, secrets, chain, and egress; 5007 is the first free slot.
const CONTROL_VSOCK_PORT: u32 = 5007;

const VSOCK_CID: u32 = u32::MAX; // VMADDR_CID_ANY — accept connections on any CID

/// Which listener a connection arrived on. Decides which message
/// variants `handle_client` accepts: the public channel proxies data and
/// serves attestations; the control channel additionally accepts signed
/// control commands but refuses to proxy anything to the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelKind {
    /// Router-bridged port 5000: anyone who can reach the enclave's
    /// public hostname terminates a Noise session here.
    Public,
    /// Host-only port 5007: only the backend (via the vsock proxy
    /// socket) can reach it.
    Control,
}

/// Port the host-side `chain-host` daemon listens on (#47).
const CHAIN_HOST_PORT: u32 = 5005;

/// How long we wait for the chain-host ACK byte after sending a link.
const CHAIN_HOST_ACK_TIMEOUT: Duration = Duration::from_secs(30);

const DEFAULT_CONTAINER_ADDR: &str = "127.0.0.1:8080";

/// Maximum allowed size for a single Data payload (4 MiB).
const MAX_PAYLOAD_SIZE: usize = 4 * 1024 * 1024;

/// Maximum number of in-flight requests per connection.
const MAX_IN_FLIGHT: usize = 64;

/// Maximum number of concurrent control-channel connections. The
/// backend dials one connection per control dispatch; 4 leaves room for
/// a retry racing a half-closed predecessor. Deliberately separate from
/// the public admission semaphore (see `main`).
const MAX_CONTROL_CLIENTS: usize = 4;

/// Maximum number of concurrent client connections (default: 2 per CPU core).
fn max_concurrent_clients() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() * 2)
        .unwrap_or(8)
}

/// Maximum time to wait for a client message before considering the connection idle.
const CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-boot single-use nonce for signed control commands. Initialized to a
/// random 32 bytes at startup; rotated each time a `Control` message is
/// processed (success OR failure) to prevent replay.
type ControlNonce = Arc<Mutex<[u8; 32]>>;

fn fresh_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Connect to the host-side `chain-host` daemon (vsock CID 2 port 5005),
/// write the chain link, and wait for the ACK.
///
/// Returns `Ok(())` on success, `Err(message)` if the link could not be
/// submitted. An error here means the backend has NOT yet ingested the link;
/// callers should reply error to the client so the operation can be retried.
///
/// The vsock write is chunked at 32 KiB per the per-write limit documented
/// in the repository conventions (single writes over AF_VSOCK fail above
/// ~32 KiB). The shared `submit_chain_link` helper in enclavia-protocol
/// handles chunking automatically.
async fn submit_chain_link_to_host(link: &ChainLink) -> Result<(), String> {
    let cid = enclavia_vsock::host_cid().await;
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(30),
        VsockStream::connect(cid, CHAIN_HOST_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(format!(
                "vsock {cid}:{CHAIN_HOST_PORT} connect failed: {e}"
            ));
        }
        Err(_) => {
            return Err(format!(
                "vsock {cid}:{CHAIN_HOST_PORT} connect timed out"
            ));
        }
    };

    let ack = enclavia_protocol::submit_chain_link(&mut stream, link, CHAIN_HOST_ACK_TIMEOUT)
        .await
        .map_err(|e| format!("chain-host submit failed: {e}"))?;

    if ack != CHAIN_LINK_ACK {
        warn!(ack_byte = ack, "chain-host sent unexpected ACK byte");
    }
    Ok(())
}

/// Build a chain attestation for the given payload bytes.
/// `user_data = sha256(payload)`. Talks to `/dev/nsm` in both
/// environments: real hardware on Nitro, QEMU's emulated NSM device in
/// debug (same wire shape, self-signed instead of AWS-CA-signed).
fn build_chain_attestation(payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let user_data: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(payload);
        h.finalize().into()
    };
    // Random nonce: the chain ingest verifier does not check the document's
    // nonce field (there is no Noise session at this point), but we populate
    // it with random bytes to avoid a deterministic value.
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    attestation::get_chain_attestation(&user_data, &nonce)
}

/// Verify and dispatch a signed control command. Returns the user-visible
/// result message; rotates the nonce regardless of outcome.
async fn handle_control(
    payload: &[u8],
    signature: &[u8],
    control_pubkey: Option<&VerifyingKey>,
    nonce: &ControlNonce,
    crypto_bin: &str,
    min_upgrade_delay_secs: u64,
) -> (bool, String) {
    // Rotate the nonce after this call, regardless of outcome — a leaked
    // nonce is single-use whether or not the command verified.
    let mut current = nonce.lock().await;
    let expected = *current;
    *current = fresh_nonce();
    drop(current);

    let pubkey = match control_pubkey {
        Some(k) => k,
        None => {
            return (
                false,
                "control channel disabled (no control_public_key configured)".into(),
            );
        }
    };

    // Locked-in wire format (#47): 64-byte raw `r || s`, each 32 B
    // big-endian zero-padded. DER signatures from PIV/OpenSSL must be
    // re-encoded to this shape by the signer before being shipped.
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return (false, "signature must be 64 bytes raw r||s".into()),
    };

    if pubkey.verify(payload, &sig).is_err() {
        return (false, "signature verification failed".into());
    }

    let cmd: ControlCommand = match ciborium::from_reader(payload) {
        Ok(c) => c,
        Err(e) => return (false, format!("malformed payload: {e}")),
    };

    match cmd {
        ControlCommand::PrepareUpgrade {
            payload: chain_payload,
            payload_signature,
            rekey,
            nonce: cmd_nonce,
        } => {
            if cmd_nonce != expected {
                return (false, "stale nonce, fetch a fresh attestation".into());
            }
            run_prepare_upgrade(
                pubkey,
                &chain_payload,
                &payload_signature,
                rekey.as_ref(),
                crypto_bin,
                min_upgrade_delay_secs,
            )
            .await
        }
        ControlCommand::RevokeUpgrade {
            payload: chain_payload,
            payload_signature,
            rollback,
            nonce: cmd_nonce,
        } => {
            if cmd_nonce != expected {
                return (false, "stale nonce, fetch a fresh attestation".into());
            }
            run_revoke_upgrade(
                pubkey,
                &chain_payload,
                &payload_signature,
                rollback,
                crypto_bin,
            )
            .await
        }
    }
}

/// Tolerance subtracted from the minimum-upgrade-delay floor to absorb
/// host/backend clock skew: the backend stamps `valid_from = its_now +
/// min_delay` moments before we check against our own clock, so a floor
/// with zero slack would reject every legitimate confirm whose backend
/// clock runs slightly behind ours. 60s is negligible against delays
/// measured in hours.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

/// Does `valid_from` land before this enclave's measured minimum upgrade
/// delay floor (`now + min_delay_secs - CLOCK_SKEW_TOLERANCE_SECS`)?
///
/// `min_delay_secs == 0` means no floor was configured (pre-existing
/// behavior) and never rejects. Pure so the comparison is unit-testable
/// without the chain-host machinery.
fn violates_min_upgrade_delay(
    valid_from: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    min_delay_secs: u64,
) -> bool {
    if min_delay_secs == 0 {
        return false;
    }
    let floor = now + chrono::Duration::seconds(min_delay_secs as i64)
        - chrono::Duration::seconds(CLOCK_SKEW_TOLERANCE_SECS);
    valid_from < floor
}

/// Execute the `PrepareUpgrade` flow:
/// 1. Defence-in-depth: verify `payload_signature` against the control pubkey.
/// 2. Validate the CBOR payload decodes as `UpgradePayload`.
/// 3. Enforce the measured minimum upgrade delay on `valid_from`.
/// 4. Optionally run `enclavia-crypto prepare-upgrade` (storage enclaves).
/// 5. Get a chain attestation binding `sha256(payload)`.
/// 6. Submit the `Upgrade` chain link to `chain-host`; wait for ACK.
///
/// The chain link is submitted BEFORE returning success so the backend sees
/// the link already ingested when the reply arrives on the Noise channel.
///
/// If the LUKS re-key fails, NO chain link is emitted and an error is returned.
/// If chain-host submission fails, an error is returned; the backend should
/// retry. For storage enclaves, `prepare-upgrade` will reject a repeat call
/// if a rollback stash already exists (see `enclavia-crypto`); the backend
/// enforces at most one in-flight upgrade.
async fn run_prepare_upgrade(
    pubkey: &VerifyingKey,
    chain_payload: &[u8],
    payload_signature: &[u8],
    rekey: Option<&RekeyParams>,
    bin: &str,
    min_upgrade_delay_secs: u64,
) -> (bool, String) {
    // Defence-in-depth: verify payload_signature against the control pubkey.
    let sig = match Signature::from_slice(payload_signature) {
        Ok(s) => s,
        Err(_) => return (false, "payload_signature must be 64 bytes raw r||s".into()),
    };
    if pubkey.verify(chain_payload, &sig).is_err() {
        return (
            false,
            "payload_signature does not verify under the control pubkey".into(),
        );
    }

    // Validate the chain payload shape. Fail before touching storage.
    let payload =
        match ciborium::from_reader::<enclavia_protocol::chain::UpgradePayload, _>(chain_payload) {
            Ok(p) => p,
            Err(e) => {
                return (
                    false,
                    format!("chain payload is not a valid UpgradePayload: {e}"),
                );
            }
        };

    // The measured minimum upgrade delay. `valid_from` is checked
    // against this enclave's OWN clock, not the signer-supplied
    // `issued_at`, so a compromised control key cannot fast-track an
    // activation past watching verifiers by backdating the payload.
    // CLOCK_SKEW_TOLERANCE_SECS absorbs host/backend clock skew (the
    // backend stamps `valid_from = its_now + min_delay` moments before
    // we check); it is negligible against delays measured in hours.
    // Enforced BEFORE the storage re-key and chain submission so a
    // rejected activation leaves no trace. Caveat (documented in the
    // issue): the guest clock is host-influenced, so a host that warps
    // the clock forward can shrink the effective delay.
    if min_upgrade_delay_secs > 0 {
        let now = chrono::Utc::now();
        if violates_min_upgrade_delay(payload.valid_from, now, min_upgrade_delay_secs) {
            let earliest = now + chrono::Duration::seconds(min_upgrade_delay_secs as i64)
                - chrono::Duration::seconds(CLOCK_SKEW_TOLERANCE_SECS);
            return (
                false,
                format!(
                    "valid_from {} violates the measured minimum upgrade delay: this enclave \
                     requires activation at least {}s after now ({}); earliest acceptable is {}",
                    payload.valid_from, min_upgrade_delay_secs, now, earliest,
                ),
            );
        }
    }

    // Storage re-key (only for storage enclaves).
    if let Some(rk) = rekey {
        let (ok, msg) =
            run_enclavia_crypto_prepare_upgrade(&rk.new_public_key, &rk.new_key_id, bin).await;
        if !ok {
            // Do NOT emit a chain link if the LUKS step failed.
            return (false, format!("storage re-key failed: {msg}"));
        }
        info!("storage re-key succeeded");
    }

    // Get chain attestation.
    let attestation = match build_chain_attestation(chain_payload) {
        Ok(a) => a,
        Err(e) => return (false, format!("chain attestation failed: {e}")),
    };

    let link = ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Upgrade,
        payload: chain_payload.to_vec(),
        attestation,
        signature: Some(payload_signature.to_vec()),
    };

    // Submit to chain-host and wait for ACK BEFORE replying to the client.
    if let Err(e) = submit_chain_link_to_host(&link).await {
        return (false, format!("chain-host submission failed: {e}"));
    }

    (
        true,
        "prepare-upgrade completed: chain link submitted".into(),
    )
}

/// Execute the `RevokeUpgrade` flow:
/// 1. Defence-in-depth: verify `payload_signature` against the control pubkey.
/// 2. Validate the CBOR payload decodes as `RevocationPayload`.
/// 3. Optionally run `enclavia-crypto revoke-upgrade` (storage enclaves).
/// 4. Get a chain attestation.
/// 5. Submit the `Revocation` chain link to `chain-host`; wait for ACK.
async fn run_revoke_upgrade(
    pubkey: &VerifyingKey,
    chain_payload: &[u8],
    payload_signature: &[u8],
    rollback: bool,
    bin: &str,
) -> (bool, String) {
    let sig = match Signature::from_slice(payload_signature) {
        Ok(s) => s,
        Err(_) => return (false, "payload_signature must be 64 bytes raw r||s".into()),
    };
    if pubkey.verify(chain_payload, &sig).is_err() {
        return (
            false,
            "payload_signature does not verify under the control pubkey".into(),
        );
    }

    if let Err(e) =
        ciborium::from_reader::<enclavia_protocol::chain::RevocationPayload, _>(chain_payload)
    {
        return (
            false,
            format!("chain payload is not a valid RevocationPayload: {e}"),
        );
    }

    if rollback {
        let (ok, msg) = run_enclavia_crypto_revoke_upgrade(bin).await;
        if !ok {
            return (false, format!("storage rollback failed: {msg}"));
        }
        info!("storage rollback succeeded");
    }

    let attestation = match build_chain_attestation(chain_payload) {
        Ok(a) => a,
        Err(e) => return (false, format!("chain attestation failed: {e}")),
    };

    let link = ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Revocation,
        payload: chain_payload.to_vec(),
        attestation,
        signature: Some(payload_signature.to_vec()),
    };

    if let Err(e) = submit_chain_link_to_host(&link).await {
        return (false, format!("chain-host submission failed: {e}"));
    }

    (
        true,
        "revoke-upgrade completed: chain link submitted".into(),
    )
}

/// Pull a fresh CBOR creds map from the on-demand IMDS relay the backend
/// re-armed on the parent for this upgrade (a single-shot `secrets-host
/// --source imds` on vsock `AWS_CREDS_VSOCK_PORT`). Same length-prefixed
/// framing as the boot-time `enclavia-secrets-init` pull. In-memory only: the
/// `kms:Decrypt`-capable creds never touch the enclave's disk.
async fn pull_upgrade_kms_creds() -> Result<BTreeMap<String, Vec<u8>>, String> {
    // Matches `enclavia-secrets-init`'s `AWS_CREDS_HOST_PORT` and the
    // launcher's AWS-creds `secrets-host` port.
    const AWS_CREDS_VSOCK_PORT: u32 = 5013;
    const ACK_BYTE: u8 = 0x00;
    const MAX_PAYLOAD_BYTES: usize = 1 << 20;

    let cid = enclavia_vsock::host_cid().await;
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        VsockStream::connect(cid, AWS_CREDS_VSOCK_PORT),
    )
    .await
    .map_err(|_| format!("vsock {cid}:{AWS_CREDS_VSOCK_PORT} connect timed out"))?
    .map_err(|e| format!("vsock {cid}:{AWS_CREDS_VSOCK_PORT} connect: {e}"))?;

    // 4-byte BE length prefix, then exactly N bytes of CBOR (the host stays
    // blocked on our ack below rather than shutting down the write half).
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("reading creds length prefix: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PAYLOAD_BYTES {
        return Err(format!("creds payload length {len} out of range"));
    }
    let mut bytes = vec![0u8; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| format!("reading creds payload: {e}"))?;
    // Ack so the single-shot relay can serve-once and exit.
    let _ = stream.write_all(&[ACK_BYTE]).await;

    ciborium::de::from_reader(&bytes[..]).map_err(|e| format!("decoding creds CBOR: {e}"))
}

/// Spawn `enclavia-crypto prepare-upgrade` and translate its exit status into
/// a user-visible result. The new public key is base64-encoded for the CLI;
/// the key id is passed through unchanged.
async fn run_enclavia_crypto_prepare_upgrade(
    new_public_key: &[u8],
    new_key_id: &str,
    bin: &str,
) -> (bool, String) {
    use base64::Engine as _;
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(new_public_key);

    let mut command = tokio::process::Command::new(bin);
    command.args([
        "prepare-upgrade",
        "--new-public-key",
        &pubkey_b64,
        "--new-key-id",
        new_key_id,
    ]);

    // The re-key re-derives the CURRENT LUKS passphrase via `kms:Decrypt`
    // (`enclavia-crypto prepare-upgrade` step 2). On real Nitro that needs live
    // AWS creds, but `init.sh` scrubs the boot creds before this server even
    // starts (the workload must never see `kms:Decrypt`-capable creds). So pull
    // a FRESH set from the on-demand relay the backend re-armed on the parent
    // and inject them into the subprocess env ONLY. Host CID 3 == real Nitro;
    // under QEMU (CID 2) the enclave talks to mock-kms and needs no creds.
    if enclavia_vsock::host_cid().await == 3 {
        match pull_upgrade_kms_creds().await {
            Ok(creds) => {
                let mut region: Option<String> = None;
                for (k, v) in &creds {
                    let value = String::from_utf8_lossy(v);
                    if k == "AWS_REGION" {
                        region = Some(value.to_string());
                    }
                    command.env(k, value.as_ref());
                }
                // `enclavia-crypto` selects its real-KMS transport off
                // KMS_AWS_REGION; the creds feed delivers the region under the
                // standard name AWS_REGION. Bridge it, mirroring init.sh's
                // boot path (which only does so on the real-Nitro CID 3).
                if let Some(r) = region {
                    command.env("KMS_AWS_REGION", r);
                }
            }
            Err(e) => {
                return (
                    false,
                    format!("failed to pull fresh KMS creds for re-key: {e}"),
                );
            }
        }
    }

    let output = match command.output().await {
        Ok(o) => o,
        Err(e) => return (false, format!("failed to spawn {bin}: {e}")),
    };

    if output.status.success() {
        (true, "prepare-upgrade completed".into())
    } else {
        // `enclavia-crypto` logs its fatal error via tracing to STDOUT (the
        // subscriber default), so capturing only stderr would drop the cause
        // and leave just the bare exit code. Surface the last non-empty line
        // of either stream.
        let last_line = |buf: &[u8]| -> String {
            String::from_utf8_lossy(buf)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .next_back()
                .unwrap_or("")
                .to_string()
        };
        let detail: Vec<String> = [last_line(&output.stdout), last_line(&output.stderr)]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        let suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(": {}", detail.join(" | "))
        };
        (
            false,
            format!("enclavia-crypto exited with {}{}", output.status, suffix),
        )
    }
}

/// Spawn `enclavia-crypto revoke-upgrade` and translate its exit status.
async fn run_enclavia_crypto_revoke_upgrade(bin: &str) -> (bool, String) {
    let output = match tokio::process::Command::new(bin)
        .arg("revoke-upgrade")
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => return (false, format!("failed to spawn {bin}: {e}")),
    };

    if output.status.success() {
        (true, "revoke-upgrade completed".into())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trimmed = stderr.trim();
        let suffix = if trimmed.is_empty() {
            String::new()
        } else {
            format!(": {trimmed}")
        };
        (
            false,
            format!(
                "enclavia-crypto revoke-upgrade exited with {}{}",
                output.status, suffix
            ),
        )
    }
}

/// How long we wait for the workload's HTTP response before giving up on a
/// one-shot `Data` request. The connection stays open until the workload sends
/// FIN (driven by the `Connection: close` header that the SDK inserts on every
/// `Data` request, see `enclavia/src/request.rs`).
const FORWARD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Read chunk size for the byte pump on an open stream.
const STREAM_READ_CHUNK: usize = 16 * 1024;

/// How long a dial to the workload may keep retrying `ConnectionRefused`
/// while the workload is still booting.
///
/// The enclave starts serving the control/data channels (and the launcher
/// publishes the proxy target) as soon as `enclavia-server` is up, but the
/// customer container may take much longer to bind its port: on a customer's
/// slow-booting Lightning node we measured ~20 seconds between the
/// proxy-target being published and the workload's own "Listening on
/// 0.0.0.0:3001" log line. During that window every proxied request used to
/// fail instantly with "Connection refused (os error 111)", which the proxy
/// surfaced to end users as a 502.
const WORKLOAD_STARTUP_GRACE: Duration = Duration::from_secs(60);

/// Sleep between dial attempts inside the startup grace window.
const WORKLOAD_DIAL_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Set once the first dial to the workload succeeds. After that, a refused
/// dial means the workload crashed or closed its listener, and we fail fast
/// instead of stalling clients for up to [`WORKLOAD_STARTUP_GRACE`].
static WORKLOAD_SEEN_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Dial the workload, absorbing `ConnectionRefused` during startup.
///
/// While `seen_up` is still false (the workload has never been observed
/// listening), a refused dial is retried every `retry_interval` until
/// `grace` has elapsed. The first successful connect sets `seen_up`, after
/// which refused dials (and any other error kind, always) fail immediately
/// with the original error, preserving the caller's error reporting.
async fn connect_with_startup_grace(
    addr: &str,
    seen_up: &std::sync::atomic::AtomicBool,
    retry_interval: Duration,
    grace: Duration,
) -> std::io::Result<TcpStream> {
    use std::sync::atomic::Ordering;

    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                seen_up.store(true, Ordering::Relaxed);
                return Ok(stream);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    && !seen_up.load(Ordering::Relaxed)
                    && tokio::time::Instant::now() + retry_interval <= deadline =>
            {
                trace!(addr, "workload not listening yet, retrying dial");
                tokio::time::sleep(retry_interval).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// [`connect_with_startup_grace`] with the production constants and the
/// process-wide [`WORKLOAD_SEEN_UP`] flag.
async fn connect_to_workload(addr: &str) -> std::io::Result<TcpStream> {
    connect_with_startup_grace(
        addr,
        &WORKLOAD_SEEN_UP,
        WORKLOAD_DIAL_RETRY_INTERVAL,
        WORKLOAD_STARTUP_GRACE,
    )
    .await
}

/// Commands handed from the per-connection handler to a per-stream pump after
/// the initial `OpenStream` request: extra bytes to write into the TCP, or a
/// close signal.
enum StreamCommand {
    Data(Vec<u8>),
    Close(StreamHalf),
}

/// One-shot forward of a `Data` request: write the payload, read until EOF (or
/// timeout), and return the full response as a single buffer.
///
/// We deliberately do NOT half-close the write side after sending the request,
/// even though it's the textbook "I'm done sending" signal. Uvicorn's
/// asyncio-based HTTP/1.1 protocol handler interprets the FIN arriving on its
/// read side as "peer gone, abort" and closes the connection without
/// dispatching the request, even when the request was fully buffered and
/// `Connection: close` was set (confirmed against a customer enclave running
/// nutshell-mint and against a minimal FastAPI/uvicorn reproduction). We rely
/// instead on the client-supplied `Connection: close` header to make the
/// workload close after responding; `read_to_end` returns once the workload
/// sends its FIN.
async fn forward_to_container(container_addr: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = connect_to_workload(container_addr)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(payload).await.map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    tokio::time::timeout(FORWARD_RESPONSE_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .map_err(|_| {
            format!(
                "workload did not respond within {}s; if it is an HTTP/1.1 keep-alive server, ensure clients send `Connection: close`",
                FORWARD_RESPONSE_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| e.to_string())?;
    Ok(response)
}

/// Open a bidirectional byte pipe to the workload for an `OpenStream` request.
/// Write the initial payload, then pump bytes both ways until either side
/// closes. Every workload->client read becomes `ServerMessage::StreamData`;
/// every `ClientMessage::StreamData` is written to the TCP. `StreamClose` is
/// emitted on workload-side EOF; client-side `StreamClose{Write}` is mapped
/// to TCP `shutdown(WRITE)`.
///
/// The server treats the payload and the response as opaque bytes — no HTTP
/// parsing — so a future non-Rust frontend (an nginx C module, a WASM SDK)
/// can implement the client side without dragging in `httparse`. Any
/// `101 Switching Protocols` detection lives entirely in the SDK.
///
/// Same no-write-half-close behavior as `forward_to_container`: WebSocket
/// upgrades don't send `Connection: close`, but uvicorn's reaction to a FIN
/// arriving on the request side is severe enough that we don't risk it.
async fn pump_bidirectional(
    id: u64,
    container_addr: &str,
    initial_payload: Vec<u8>,
    response_tx: mpsc::Sender<ServerMessage>,
    mut cmd_rx: mpsc::Receiver<StreamCommand>,
) {
    let tcp = match connect_to_workload(container_addr).await {
        Ok(s) => s,
        Err(e) => {
            let _ = response_tx
                .send(ServerMessage::Error {
                    id,
                    message: e.to_string(),
                })
                .await;
            return;
        }
    };
    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);

    if let Err(e) = tcp_w.write_all(&initial_payload).await {
        let _ = response_tx
            .send(ServerMessage::Error {
                id,
                message: e.to_string(),
            })
            .await;
        return;
    }

    let mut buf = vec![0u8; STREAM_READ_CHUNK];
    let mut workload_eof = false;
    loop {
        tokio::select! {
            read = tcp_r.read(&mut buf), if !workload_eof => {
                match read {
                    Ok(0) => {
                        let _ = response_tx
                            .send(ServerMessage::StreamClose { id })
                            .await;
                        workload_eof = true;
                    }
                    Ok(n) => {
                        if response_tx
                            .send(ServerMessage::StreamData { id, payload: buf[..n].to_vec() })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = response_tx
                            .send(ServerMessage::Error { id, message: e.to_string() })
                            .await;
                        return;
                    }
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(StreamCommand::Data(bytes)) => {
                        if let Err(e) = tcp_w.write_all(&bytes).await {
                            let _ = response_tx
                                .send(ServerMessage::Error { id, message: e.to_string() })
                                .await;
                            return;
                        }
                    }
                    Some(StreamCommand::Close(StreamHalf::Write)) => {
                        let _ = tcp_w.shutdown().await;
                    }
                    Some(StreamCommand::Close(StreamHalf::Both)) | None => {
                        return;
                    }
                }
            }
        }
    }
}

#[instrument(skip(stream, container_addr, control_pubkey, nonce))]
async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    kind: ChannelKind,
    container_addr: String,
    control_pubkey: Option<Arc<VerifyingKey>>,
    nonce: ControlNonce,
    crypto_bin: Arc<String>,
    min_upgrade_delay_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(?kind, "Client connected, performing handshake");

    let (mut transport, handshake_hash) = perform_cbor_handshake_as_responder(&mut stream).await?;
    info!("Handshake completed successfully");

    let (response_tx, mut response_rx) = mpsc::channel::<ServerMessage>(MAX_IN_FLIGHT);
    let (stream_done_tx, mut stream_done_rx) = mpsc::channel::<u64>(MAX_IN_FLIGHT);
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut streams: HashMap<u64, mpsc::Sender<StreamCommand>> = HashMap::new();

    loop {
        tokio::select! {
            // Read the next client message. We disable the idle timeout while
            // any open stream is in flight: a WS client may legitimately sit
            // silent for hours waiting on server-pushed frames.
            result = async {
                if streams.is_empty() {
                    match tokio::time::timeout(
                        CLIENT_IDLE_TIMEOUT,
                        transport.receive::<ClientMessage>(),
                    ).await {
                        Ok(inner) => inner.map_err(|e| e.to_string()),
                        Err(_elapsed) => Err("idle timeout".to_string()),
                    }
                } else {
                    transport.receive::<ClientMessage>().await.map_err(|e| e.to_string())
                }
            } => {
                let msg = match result {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Error receiving message, closing connection: {}", e);
                        break;
                    }
                };

                trace!(?msg, "Received message from client");

                // Channel gating (#47 hardening). Control messages are
                // only accepted on the host-only control listener: a
                // `Control` attempt rotates the single-use nonce before
                // the signature is checked, so accepting them from the
                // router-bridged public port let any internet client
                // starve legitimate confirm/revoke dispatches (and, in
                // the revoke case, run out the clock to `valid_from`).
                // Conversely the control listener never proxies bytes to
                // the container. Either violation closes the connection
                // without touching the nonce or the container.
                let allowed = !matches!(
                    (&msg, kind),
                    (
                        ClientMessage::GetControlNonce | ClientMessage::Control { .. },
                        ChannelKind::Public,
                    ) | (
                        ClientMessage::Data { .. }
                            | ClientMessage::OpenStream { .. }
                            | ClientMessage::StreamData { .. }
                            | ClientMessage::StreamClose { .. },
                        ChannelKind::Control,
                    )
                );
                if !allowed {
                    warn!(?kind, "message variant not allowed on this channel, closing");
                    let _ = transport
                        .send(&ServerMessage::ControlResult {
                            success: false,
                            message: format!(
                                "message not accepted on the {} channel",
                                match kind {
                                    ChannelKind::Public => "public",
                                    ChannelKind::Control => "control",
                                }
                            ),
                        })
                        .await;
                    break;
                }

                match msg {
                    ClientMessage::RequestAttestation => {
                        let control_nonce = *nonce.lock().await;
                        let attestation_data = attestation::get_attestation_with_data(
                            &handshake_hash,
                            &control_nonce,
                        )?;
                        let response = ServerMessage::Attestation {
                            data: attestation_data,
                            control_nonce,
                        };
                        if let Err(e) = transport.send(&response).await {
                            warn!(error = %e, "Failed to send attestation response");
                        }
                    }
                    ClientMessage::GetControlNonce => {
                        // Return the current nonce without consuming it. The
                        // nonce is only consumed when a Control message is
                        // processed. This lets the backend learn the nonce
                        // before signing without needing a full attestation
                        // round-trip.
                        let control_nonce = *nonce.lock().await;
                        let response = ServerMessage::ControlNonce { nonce: control_nonce };
                        if let Err(e) = transport.send(&response).await {
                            warn!(error = %e, "Failed to send ControlNonce response");
                        }
                    }
                    ClientMessage::Control { payload, signature } => {
                        let (success, message) = handle_control(
                            &payload,
                            &signature,
                            control_pubkey.as_deref(),
                            &nonce,
                            crypto_bin.as_str(),
                            min_upgrade_delay_secs,
                        ).await;
                        if !success {
                            warn!(message = %message, "Control command rejected");
                        }
                        let response = ServerMessage::ControlResult { success, message };
                        if let Err(e) = transport.send(&response).await {
                            warn!(error = %e, "Failed to send control result");
                            break;
                        }
                    }
                    ClientMessage::Data { id, payload } => {
                        if payload.len() > MAX_PAYLOAD_SIZE {
                            warn!(id, size = payload.len(), max = MAX_PAYLOAD_SIZE, "Payload exceeds size limit");
                            let _ = response_tx.send(ServerMessage::Error {
                                id,
                                message: "payload too large".into(),
                            }).await;
                            continue;
                        }

                        let permit = match in_flight.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let tx = response_tx.clone();
                        let addr = container_addr.clone();

                        tokio::spawn(async move {
                            let response = match forward_to_container(&addr, &payload).await {
                                Ok(response_bytes) => ServerMessage::Data {
                                    id,
                                    payload: response_bytes,
                                },
                                Err(e) => {
                                    error!(id, error = %e, "Failed to forward to container");
                                    ServerMessage::Error { id, message: e }
                                }
                            };
                            let _ = tx.send(response).await;
                            drop(permit);
                        });
                    }
                    ClientMessage::OpenStream { id, payload } => {
                        if payload.len() > MAX_PAYLOAD_SIZE {
                            warn!(id, size = payload.len(), max = MAX_PAYLOAD_SIZE, "OpenStream payload exceeds size limit");
                            let _ = response_tx.send(ServerMessage::Error {
                                id,
                                message: "payload too large".into(),
                            }).await;
                            continue;
                        }

                        let permit = match in_flight.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let tx = response_tx.clone();
                        let addr = container_addr.clone();

                        let (cmd_tx, cmd_rx) = mpsc::channel::<StreamCommand>(MAX_IN_FLIGHT);
                        streams.insert(id, cmd_tx);
                        let done = stream_done_tx.clone();

                        tokio::spawn(async move {
                            pump_bidirectional(id, &addr, payload, tx, cmd_rx).await;
                            let _ = done.send(id).await;
                            drop(permit);
                        });
                    }
                    ClientMessage::StreamData { id, payload } => {
                        match streams.get(&id) {
                            Some(tx) => {
                                if payload.len() > MAX_PAYLOAD_SIZE {
                                    warn!(id, size = payload.len(), max = MAX_PAYLOAD_SIZE, "StreamData payload exceeds size limit");
                                    let _ = response_tx.send(ServerMessage::Error {
                                        id,
                                        message: "payload too large".into(),
                                    }).await;
                                    continue;
                                }
                                if tx.send(StreamCommand::Data(payload)).await.is_err() {
                                    // Pump task already exited; drop the stream entry so a
                                    // follow-up StreamClose doesn't keep dispatching.
                                    streams.remove(&id);
                                }
                            }
                            None => {
                                warn!(id, "Received StreamData for unknown stream id");
                                let _ = response_tx.send(ServerMessage::Error {
                                    id,
                                    message: "unknown stream id".into(),
                                }).await;
                            }
                        }
                    }
                    ClientMessage::StreamClose { id, half } => {
                        if let Some(tx) = streams.get(&id) {
                            if tx.send(StreamCommand::Close(half)).await.is_err() {
                                streams.remove(&id);
                            }
                        }
                        if matches!(half, StreamHalf::Both) {
                            streams.remove(&id);
                        }
                    }
                }
            }

            // Send completed responses back to the client
            Some(response) = response_rx.recv() => {
                if let Err(e) = transport.send(&response).await {
                    warn!(error = %e, "Failed to send response");
                    break;
                }
            }

            // Reap finished stream pumps so the streams map stays bounded and
            // idle-timeout re-arms once the last open stream goes away.
            Some(id) = stream_done_rx.recv() => {
                streams.remove(&id);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let container_addr = {
        let mut addr = DEFAULT_CONTAINER_ADDR.to_string();
        let mut iter = args.iter().skip(1);
        while let Some(arg) = iter.next() {
            if arg == "--container-addr" {
                if let Some(val) = iter.next() {
                    addr = val.clone();
                }
            }
        }
        addr
    };

    let max_clients = max_concurrent_clients();
    let semaphore = Arc::new(Semaphore::new(max_clients));

    let server_config = config::load(Path::new(config::CONFIG_PATH)).unwrap_or_else(|e| {
        warn!(error = %e, "Failed to load enclavia config, control channel will be disabled");
        config::ServerConfig::default()
    });
    let control_pubkey = server_config.control_public_key.map(Arc::new);
    let min_upgrade_delay_secs = server_config.min_upgrade_delay_secs;
    let nonce: ControlNonce = Arc::new(Mutex::new(fresh_nonce()));
    let crypto_bin = Arc::new(
        std::env::var("ENCLAVIA_CRYPTO_BIN").unwrap_or_else(|_| "/bin/enclavia-crypto".into()),
    );

    info!(
        container = %container_addr,
        max_clients,
        control_enabled = control_pubkey.is_some(),
        min_upgrade_delay_secs,
        crypto_bin = %crypto_bin,
        "Starting enclavia server",
    );

    let public_listener = VsockListener::bind(VSOCK_CID, VSOCK_PORT)?;
    info!(
        "Server listening on vsock port: {} (CID: {})",
        VSOCK_PORT, VSOCK_CID
    );
    let control_listener = VsockListener::bind(VSOCK_CID, CONTROL_VSOCK_PORT)?;
    info!(
        "Control channel listening on vsock port: {} (CID: {})",
        CONTROL_VSOCK_PORT, VSOCK_CID
    );

    // The control channel gets its own small admission semaphore: a
    // public connection flood must not be able to starve the backend's
    // control dispatch out of a permit.
    let control_semaphore = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));

    let public_task = tokio::spawn(accept_loop(
        public_listener,
        ChannelKind::Public,
        container_addr.clone(),
        semaphore,
        control_pubkey.clone(),
        Arc::clone(&nonce),
        Arc::clone(&crypto_bin),
        min_upgrade_delay_secs,
    ));
    let control_task = tokio::spawn(accept_loop(
        control_listener,
        ChannelKind::Control,
        container_addr,
        control_semaphore,
        control_pubkey,
        nonce,
        crypto_bin,
        min_upgrade_delay_secs,
    ));

    // Both loops run forever; if either task exits the server is in an
    // unrecoverable state and should die loudly so init restarts it.
    let (a, b) = tokio::join!(public_task, control_task);
    a?;
    b?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    mut listener: VsockListener,
    kind: ChannelKind,
    container_addr: String,
    semaphore: Arc<Semaphore>,
    control_pubkey: Option<Arc<VerifyingKey>>,
    nonce: ControlNonce,
    crypto_bin: Arc<String>,
    min_upgrade_delay_secs: u64,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let addr = container_addr.clone();
                let sem = Arc::clone(&semaphore);
                let pubkey = control_pubkey.clone();
                let nonce = Arc::clone(&nonce);
                let crypto = Arc::clone(&crypto_bin);
                tokio::spawn(async move {
                    let _permit = match sem.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            error!("Semaphore closed, dropping client");
                            return;
                        }
                    };
                    info!(?kind, "Client admitted (permit acquired)");
                    if let Err(e) = handle_client(
                        stream,
                        kind,
                        addr,
                        pubkey,
                        nonce,
                        crypto,
                        min_upgrade_delay_secs,
                    )
                    .await
                    {
                        error!(error = %e, "Error handling client");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Error accepting connection");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the signed Control channel: signature verification,
    //! single-use nonce semantics, malformed input handling, and dispatch
    //! to an enclavia-crypto subprocess (stubbed with `true`/`false`).
    //!
    //! Chain-host submission will fail in these tests (no daemon running);
    //! tests that check the full happy-path would need an in-process mock
    //! chain-host. The nonce rotation and rejection paths don't need it.
    use super::*;
    use enclavia_protocol::ControlCommand;
    use p256::ecdsa::{SigningKey, signature::Signer};

    pub(super) fn fixed_pair() -> (SigningKey, VerifyingKey) {
        // Deterministic 32-byte scalar in (0, n). Seeds with `i+1` so
        // the first byte is 1 — guarantees a non-zero scalar that is
        // also far below the P-256 group order (n is just under 2^256;
        // any value with high byte < 0xff is safely below).
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let sk = SigningKey::from_slice(&seed).expect("non-zero seed yields a valid scalar");
        let pk = *sk.verifying_key();
        (sk, pk)
    }

    /// Type-annotated wrapper around `sk.sign(...)`. `p256::ecdsa::SigningKey`
    /// implements `Signer<Signature>` and `Signer<DerSignature>`; without
    /// annotating the return type the compiler can't pick one. Tests
    /// uniformly want the 64-byte raw r||s form we've locked in (#47).
    fn sign_raw(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        sig.to_bytes().to_vec()
    }

    fn cbor_encode<T: serde::Serialize>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn sample_upgrade_payload(nonce_seed: u8) -> Vec<u8> {
        use enclavia_protocol::chain::{PcrsHex, UpgradePayload};
        let pcrs = PcrsHex {
            pcr0: "aa".repeat(24),
            pcr1: "bb".repeat(24),
            pcr2: "cc".repeat(24),
        };
        let payload = UpgradePayload {
            enclave_id: uuid::Uuid::new_v4(),
            from_pcrs: pcrs.clone(),
            to_pcrs: pcrs,
            image_digest: "sha256:test".into(),
            valid_from: chrono::Utc::now() + chrono::Duration::days(1),
            issued_at: chrono::Utc::now(),
            nonce: vec![nonce_seed; 32],
        };
        let mut out = Vec::new();
        ciborium::into_writer(&payload, &mut out).unwrap();
        out
    }

    fn sample_revocation_payload(nonce_seed: u8) -> Vec<u8> {
        use enclavia_protocol::chain::RevocationPayload;
        let payload = RevocationPayload {
            enclave_id: uuid::Uuid::new_v4(),
            revokes: uuid::Uuid::new_v4(),
            issued_at: chrono::Utc::now(),
            nonce: vec![nonce_seed; 32],
        };
        let mut out = Vec::new();
        ciborium::into_writer(&payload, &mut out).unwrap();
        out
    }

    fn make_prepare_upgrade_command(
        nonce: [u8; 32],
        sk: &SigningKey,
        chain_payload: Vec<u8>,
        rekey: Option<RekeyParams>,
    ) -> Vec<u8> {
        let payload_signature = sign_raw(sk, &chain_payload);
        cbor_encode(&ControlCommand::PrepareUpgrade {
            payload: chain_payload,
            payload_signature,
            rekey,
            nonce,
        })
    }

    fn make_revoke_upgrade_command(
        nonce: [u8; 32],
        sk: &SigningKey,
        chain_payload: Vec<u8>,
        rollback: bool,
    ) -> Vec<u8> {
        let payload_signature = sign_raw(sk, &chain_payload);
        cbor_encode(&ControlCommand::RevokeUpgrade {
            payload: chain_payload,
            payload_signature,
            rollback,
            nonce,
        })
    }

    #[tokio::test]
    async fn rejects_when_no_control_key_configured() {
        let nonce_value = [42u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (sk, _) = fixed_pair();
        let chain_payload = sample_upgrade_payload(0x01);
        let payload = make_prepare_upgrade_command(nonce_value, &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);

        let (ok, msg) = handle_control(&payload, &signature, None, &nonce, "true", 0).await;
        assert!(!ok, "msg = {msg}");
        assert!(msg.contains("control channel disabled"), "msg = {msg}");
        // Nonce is still rotated even without a configured key — leakage of
        // the failure path must not let an attacker pin the nonce.
        assert_ne!(*nonce.lock().await, nonce_value);
    }

    #[tokio::test]
    async fn rejects_bad_signature_length() {
        let nonce_value = [1u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (sk, pk) = fixed_pair();
        let chain_payload = sample_upgrade_payload(0x02);
        let payload = make_prepare_upgrade_command(nonce_value, &sk, chain_payload, None);

        let (ok, msg) = handle_control(&payload, &[0u8; 5], Some(&pk), &nonce, "true", 0).await;
        assert!(!ok);
        assert!(msg.contains("64 bytes"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_invalid_signature() {
        let nonce_value = [1u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (_, pk) = fixed_pair();
        // Sign the payload with a DIFFERENT key.
        let mut wrong_seed = [0u8; 32];
        for (i, b) in wrong_seed.iter_mut().enumerate() {
            *b = (i + 2) as u8;
        }
        let wrong_sk = SigningKey::from_slice(&wrong_seed).unwrap();
        let chain_payload = sample_upgrade_payload(0x03);
        let payload = make_prepare_upgrade_command(nonce_value, &wrong_sk, chain_payload, None);
        let signature = sign_raw(&wrong_sk, &payload);

        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok);
        assert!(msg.contains("signature verification"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_malformed_payload() {
        let nonce_value = [7u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (sk, pk) = fixed_pair();
        let bogus = b"\xff\xff\xff not cbor".to_vec();
        let signature = sign_raw(&sk, &bogus);

        let (ok, msg) = handle_control(&bogus, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok);
        assert!(msg.contains("malformed payload"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_stale_nonce() {
        let server_nonce = [9u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        // Sign a payload bearing the *wrong* nonce — server must reject it.
        let chain_payload = sample_upgrade_payload(0x04);
        let payload = make_prepare_upgrade_command([0u8; 32], &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);

        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok);
        assert!(msg.contains("stale nonce"), "msg = {msg}");
    }

    #[tokio::test]
    async fn nonce_rotates_after_each_call() {
        let initial = [0xAAu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(initial));
        let (sk, pk) = fixed_pair();

        // First call: sign with the initial nonce. enclavia-crypto is stubbed
        // to `true` but chain-host connect will fail (no daemon in tests).
        // Nonce rotation does not depend on downstream success.
        let chain_payload = sample_upgrade_payload(0x05);
        let payload = make_prepare_upgrade_command(initial, &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);
        let _ = handle_control(&payload, &signature, Some(&pk), &nonce, "true", 0).await;

        // Server nonce should have rotated to something new.
        let after = *nonce.lock().await;
        assert_ne!(after, initial);

        // Replaying the same payload (still bearing the old nonce) must fail.
        let (ok2, msg2) = handle_control(&payload, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok2);
        assert!(msg2.contains("stale nonce"), "msg = {msg2}");
    }

    #[tokio::test]
    async fn dispatch_failure_surfaces_in_message() {
        let initial = [0xBBu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(initial));
        let (sk, pk) = fixed_pair();

        let chain_payload = sample_upgrade_payload(0x06);
        let payload = make_prepare_upgrade_command(initial, &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);
        // `false` exits 1 — verifies that enclavia-crypto failure is
        // reported back rather than silently masked.
        // Chain attestation (NSM) also fails in unit-test context (no /dev/nsm),
        // so any of those error strings is a valid signal that failures surface.
        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "false", 0).await;
        assert!(!ok);
        assert!(
            msg.contains("enclavia-crypto exited")
                || msg.contains("chain-host")
                || msg.contains("chain attestation"),
            "msg = {msg}"
        );
    }

    #[tokio::test]
    async fn revoke_upgrade_rejects_stale_nonce() {
        let server_nonce = [0xCCu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        let chain_payload = sample_revocation_payload(0x07);
        let payload = make_revoke_upgrade_command([0u8; 32], &sk, chain_payload, false);
        let signature = sign_raw(&sk, &payload);

        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok);
        assert!(msg.contains("stale nonce"), "msg = {msg}");
    }

    #[tokio::test]
    async fn revoke_upgrade_rejects_wrong_payload_shape() {
        let server_nonce = [0xDDu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        // Use an UpgradePayload as the chain payload for a RevokeUpgrade command.
        let wrong_payload = sample_upgrade_payload(0x08);
        let payload_signature = sign_raw(&sk, &wrong_payload);
        let cmd = cbor_encode(&ControlCommand::RevokeUpgrade {
            payload: wrong_payload,
            payload_signature,
            rollback: false,
            nonce: server_nonce,
        });
        let signature = sign_raw(&sk, &cmd);

        let (ok, msg) = handle_control(&cmd, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok, "msg = {msg}");
        assert!(msg.contains("RevocationPayload"), "msg = {msg}");
    }

    #[tokio::test]
    async fn prepare_upgrade_bad_chain_payload_signature() {
        let server_nonce = [0xEEu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();
        let mut wrong_seed = [0u8; 32];
        for (i, b) in wrong_seed.iter_mut().enumerate() {
            *b = (i + 50) as u8;
        }
        let sk2 = SigningKey::from_slice(&wrong_seed).unwrap();

        let chain_payload = sample_upgrade_payload(0x09);
        let wrong_payload_sig = sign_raw(&sk2, &chain_payload);
        let cmd = cbor_encode(&ControlCommand::PrepareUpgrade {
            payload: chain_payload,
            payload_signature: wrong_payload_sig,
            rekey: None,
            nonce: server_nonce,
        });
        let signature = sign_raw(&sk, &cmd);

        let (ok, msg) = handle_control(&cmd, &signature, Some(&pk), &nonce, "true", 0).await;
        assert!(!ok, "msg = {msg}");
        assert!(msg.contains("payload_signature"), "msg = {msg}");
    }

    #[test]
    fn min_delay_floor_comparison() {
        use chrono::{Duration, Utc};
        let now = Utc::now();
        let day: u64 = 86_400;

        // Zero configured delay never rejects, however early valid_from is.
        assert!(!violates_min_upgrade_delay(
            now - Duration::days(365),
            now,
            0
        ));

        // Exactly at the floor (now + delay - tolerance) passes.
        let floor =
            now + Duration::seconds(day as i64) - Duration::seconds(CLOCK_SKEW_TOLERANCE_SECS);
        assert!(!violates_min_upgrade_delay(floor, now, day));

        // One second under the floor is rejected: the tolerance is the
        // only slack, anything below it violates the measured delay.
        assert!(violates_min_upgrade_delay(
            floor - Duration::seconds(1),
            now,
            day
        ));

        // Exactly now + delay (no skew slack needed) passes comfortably.
        assert!(!violates_min_upgrade_delay(
            now + Duration::seconds(day as i64),
            now,
            day
        ));

        // "Immediate" activation (valid_from = now) is rejected.
        assert!(violates_min_upgrade_delay(now, now, day));
    }

    #[tokio::test]
    async fn prepare_upgrade_rejects_valid_from_under_min_delay() {
        let server_nonce = [0x11u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        // sample_upgrade_payload stamps valid_from = now + 1 day; a
        // configured 2-day floor must reject it with the delay message,
        // BEFORE any enclavia-crypto / chain-host dispatch is attempted.
        let chain_payload = sample_upgrade_payload(0x0A);
        let payload = make_prepare_upgrade_command(server_nonce, &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);

        let (ok, msg) =
            handle_control(&payload, &signature, Some(&pk), &nonce, "true", 2 * 86_400).await;
        assert!(!ok, "msg = {msg}");
        assert!(
            msg.contains("measured minimum upgrade delay"),
            "msg = {msg}"
        );
    }

    #[tokio::test]
    async fn prepare_upgrade_min_delay_satisfied_proceeds_past_the_check() {
        let server_nonce = [0x22u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        // valid_from = now + 1 day satisfies a 1-hour floor; the command
        // proceeds past the delay check and fails later at chain
        // attestation / chain-host (no NSM or daemon in unit tests).
        let chain_payload = sample_upgrade_payload(0x0B);
        let payload = make_prepare_upgrade_command(server_nonce, &sk, chain_payload, None);
        let signature = sign_raw(&sk, &payload);

        let (ok, msg) =
            handle_control(&payload, &signature, Some(&pk), &nonce, "true", 3_600).await;
        assert!(!ok, "unit tests cannot reach the happy path (no NSM)");
        assert!(
            !msg.contains("measured minimum upgrade delay"),
            "msg = {msg}"
        );
    }
}

#[cfg(test)]
mod stream_tests {
    //! In-process loopback tests for the bidirectional pump. Drives the same
    //! channel API the per-connection handler uses, so we exercise the byte
    //! pump without needing the full Noise/CBOR layer or QEMU.
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn bind_local() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        (listener, addr)
    }

    #[tokio::test]
    async fn data_request_returns_full_response_as_single_frame() {
        let (listener, addr) = bind_local().await;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
            // Drop closes the socket -> EOF on the reader side.
        });

        let request = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec();
        let resp = forward_to_container(&addr, &request)
            .await
            .expect("forward");
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"), "got: {s}");
        assert!(s.ends_with("hello"), "got: {s}");
    }

    #[tokio::test]
    async fn open_stream_pumps_bytes_both_ways() {
        let (listener, addr) = bind_local().await;

        // Workload: read the initial payload, send a "head-like" prefix, then
        // echo whatever arrives until the client half-closes. The server
        // doesn't parse the payload — to it, both the head and the echoed
        // frames are opaque bytes.
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut peek = vec![0u8; 4096];
            let _ = socket.read(&mut peek).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nFIRST-PUSH")
                .await
                .unwrap();

            let mut buf = vec![0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let (resp_tx, mut resp_rx) = mpsc::channel::<ServerMessage>(16);
        let (cmd_tx, cmd_rx) = mpsc::channel::<StreamCommand>(16);
        let request =
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .to_vec();
        let stream = tokio::spawn({
            let addr = addr.clone();
            async move { pump_bidirectional(7, &addr, request, resp_tx, cmd_rx).await }
        });

        // The first frame arrives as StreamData carrying whatever the workload
        // wrote, head and any pushed bytes alike. No special-casing in the
        // server: the SDK is responsible for splitting head from body.
        let mut accumulated: Vec<u8> = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), resp_rx.recv()).await {
                Ok(Some(ServerMessage::StreamData { id, payload })) => {
                    assert_eq!(id, 7);
                    accumulated.extend_from_slice(&payload);
                    if accumulated
                        .windows(b"FIRST-PUSH".len())
                        .any(|w| w == b"FIRST-PUSH")
                    {
                        break;
                    }
                }
                other => panic!("expected StreamData with head + push, got {other:?}"),
            }
        }
        assert!(accumulated.starts_with(b"HTTP/1.1 101 "));
        assert!(
            accumulated
                .windows(b"\r\n\r\n".len())
                .any(|w| w == b"\r\n\r\n")
        );

        // Send a few stream payloads, expect each to come back as StreamData.
        let payloads = [b"hello".to_vec(), b"world".to_vec(), b"ws-tunnel".to_vec()];
        for chunk in &payloads {
            cmd_tx
                .send(StreamCommand::Data(chunk.clone()))
                .await
                .unwrap();
        }

        let expected: Vec<u8> = payloads.iter().flatten().copied().collect();
        let mut received: Vec<u8> = Vec::new();
        while received.len() < expected.len() {
            match tokio::time::timeout(Duration::from_secs(5), resp_rx.recv()).await {
                Ok(Some(ServerMessage::StreamData { id, payload })) => {
                    assert_eq!(id, 7);
                    received.extend_from_slice(&payload);
                }
                Ok(Some(other)) => panic!("unexpected message during pump: {other:?}"),
                Ok(None) => panic!("response channel closed early"),
                Err(_) => panic!("timed out waiting for echoed bytes"),
            }
        }
        assert_eq!(received, expected);

        // Half-close the write side from the client; the loopback server reads
        // EOF and closes its socket, which closes the workload->client half too.
        cmd_tx
            .send(StreamCommand::Close(StreamHalf::Write))
            .await
            .unwrap();

        // Expect a StreamClose for the workload-side EOF.
        loop {
            match tokio::time::timeout(Duration::from_secs(5), resp_rx.recv()).await {
                Ok(Some(ServerMessage::StreamClose { id })) => {
                    assert_eq!(id, 7);
                    break;
                }
                Ok(Some(ServerMessage::StreamData { .. })) => continue, // benign trailing bytes
                Ok(Some(other)) => panic!("unexpected message after close: {other:?}"),
                Ok(None) => panic!("response channel closed without StreamClose"),
                Err(_) => panic!("timed out waiting for StreamClose"),
            }
        }

        // After workload EOF we tear down the stream from our side too.
        drop(cmd_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), stream)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod channel_gating_tests {
    //! Channel-split tests (#47 hardening): control variants are only
    //! accepted on the host-only control listener, data variants only on
    //! the public listener, and a public `Control` attempt must not spin
    //! the single-use nonce.
    use super::tests::fixed_pair;
    use super::*;

    /// Spawn `handle_client` over an in-memory duplex on the given
    /// channel kind and return an initiator-side CBOR transport into it.
    /// `container_addr` points nowhere; channel-gating tests never reach
    /// the proxy path.
    async fn connect_to_channel(
        kind: ChannelKind,
        pk: VerifyingKey,
        nonce: ControlNonce,
    ) -> enclavia_protocol::CborTransport<tokio::io::DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = handle_client(
                server,
                kind,
                "127.0.0.1:1".into(),
                Some(Arc::new(pk)),
                nonce,
                Arc::new("true".to_string()),
                0,
            )
            .await;
        });
        let (cbor, _hh) = enclavia_protocol::perform_cbor_handshake_as_initiator(client)
            .await
            .expect("initiator handshake");
        cbor
    }

    #[tokio::test]
    async fn public_channel_rejects_control_without_rotating_nonce() {
        let nonce_value = [7u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (_sk, pk) = fixed_pair();

        let mut cbor = connect_to_channel(ChannelKind::Public, pk, Arc::clone(&nonce)).await;
        cbor.send(&ClientMessage::Control {
            payload: vec![1, 2, 3],
            signature: vec![0u8; 64],
        })
        .await
        .expect("send");

        match cbor.receive::<ServerMessage>().await.expect("receive") {
            ServerMessage::ControlResult { success, message } => {
                assert!(!success);
                assert!(message.contains("public channel"), "message = {message}");
            }
            other => panic!("expected ControlResult, got {other:?}"),
        }

        // The defining regression: a public Control attempt must NOT spin
        // the nonce. Before the channel split, any internet client could
        // rotate it out from under a legitimate dispatch.
        assert_eq!(*nonce.lock().await, nonce_value);

        // And the connection is closed.
        assert!(cbor.receive::<ServerMessage>().await.is_err());
    }

    #[tokio::test]
    async fn public_channel_rejects_get_control_nonce() {
        let nonce: ControlNonce = Arc::new(Mutex::new([9u8; 32]));
        let (_sk, pk) = fixed_pair();

        let mut cbor = connect_to_channel(ChannelKind::Public, pk, nonce).await;
        cbor.send(&ClientMessage::GetControlNonce)
            .await
            .expect("send");

        match cbor.receive::<ServerMessage>().await.expect("receive") {
            ServerMessage::ControlResult { success, message } => {
                assert!(!success);
                assert!(message.contains("public channel"), "message = {message}");
            }
            other => panic!("expected ControlResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_channel_serves_nonce_and_consumes_it_on_attempt() {
        let nonce_value = [3u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (_sk, pk) = fixed_pair();

        let mut cbor = connect_to_channel(ChannelKind::Control, pk, Arc::clone(&nonce)).await;

        cbor.send(&ClientMessage::GetControlNonce)
            .await
            .expect("send");
        match cbor.receive::<ServerMessage>().await.expect("receive") {
            ServerMessage::ControlNonce { nonce: got } => assert_eq!(got, nonce_value),
            other => panic!("expected ControlNonce, got {other:?}"),
        }

        // A (garbage) Control attempt on the control channel still
        // rotates the nonce: single-use semantics are unchanged where
        // control messages are actually allowed.
        cbor.send(&ClientMessage::Control {
            payload: vec![1, 2, 3],
            signature: vec![0u8; 10],
        })
        .await
        .expect("send");
        match cbor.receive::<ServerMessage>().await.expect("receive") {
            ServerMessage::ControlResult { success, message } => {
                assert!(!success);
                assert!(message.contains("64 bytes"), "message = {message}");
            }
            other => panic!("expected ControlResult, got {other:?}"),
        }
        assert_ne!(*nonce.lock().await, nonce_value);
    }

    #[tokio::test]
    async fn control_channel_rejects_data_proxying() {
        let nonce: ControlNonce = Arc::new(Mutex::new([5u8; 32]));
        let (_sk, pk) = fixed_pair();

        let mut cbor = connect_to_channel(ChannelKind::Control, pk, nonce).await;
        cbor.send(&ClientMessage::Data {
            id: 1,
            payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        })
        .await
        .expect("send");

        match cbor.receive::<ServerMessage>().await.expect("receive") {
            ServerMessage::ControlResult { success, message } => {
                assert!(!success);
                assert!(message.contains("control channel"), "message = {message}");
            }
            other => panic!("expected ControlResult, got {other:?}"),
        }
        assert!(cbor.receive::<ServerMessage>().await.is_err());
    }
}

#[cfg(test)]
mod workload_dial_grace_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::connect_with_startup_grace;

    /// Test-scale timings: real code uses 250ms/60s, tests shrink both.
    const RETRY: Duration = Duration::from_millis(20);
    const GRACE: Duration = Duration::from_secs(5);

    /// Grab a loopback port that currently has no listener.
    async fn free_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn refused_then_listening_within_grace_succeeds_and_sets_flag() {
        let addr = free_addr().await;
        let seen_up = AtomicBool::new(false);

        // Workload "boots" 100ms in: nothing is listening at first, then a
        // listener appears on the same port.
        let bind_addr = addr.clone();
        let binder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let listener = TcpListener::bind(&bind_addr).await.unwrap();
            // Hold the listener long enough for the dial to land.
            let _ = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        });

        let result = connect_with_startup_grace(&addr, &seen_up, RETRY, GRACE).await;
        assert!(result.is_ok(), "dial should succeed once the workload binds");
        assert!(seen_up.load(Ordering::Relaxed), "first success must set the flag");
        binder.await.unwrap();
    }

    #[tokio::test]
    async fn refused_after_seen_up_fails_immediately() {
        let addr = free_addr().await;
        let seen_up = AtomicBool::new(true);

        let start = tokio::time::Instant::now();
        let err = connect_with_startup_grace(&addr, &seen_up, RETRY, GRACE)
            .await
            .expect_err("nothing is listening");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        // No retry loop: the failure must come back well before even one
        // retry interval elapses.
        assert!(
            start.elapsed() < GRACE / 2,
            "post-startup refused dial must fail fast, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn non_refused_errors_fail_immediately() {
        // An unresolvable hostname yields a non-ConnectionRefused error.
        let seen_up = AtomicBool::new(false);

        let start = tokio::time::Instant::now();
        let err = connect_with_startup_grace(
            "this-host-does-not-exist.invalid:1",
            &seen_up,
            RETRY,
            GRACE,
        )
        .await
        .expect_err("resolution must fail");
        assert_ne!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(!seen_up.load(Ordering::Relaxed));
        assert!(
            start.elapsed() < GRACE / 2,
            "non-refused errors must not be retried, took {:?}",
            start.elapsed()
        );
    }
}
