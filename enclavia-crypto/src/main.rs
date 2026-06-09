//! Enclave-side key management binary.
//!
//! Talks to:
//! - storage-host meta port (key blob GET/PUT) — vsock 5002
//! - KMS proxy (HTTP) — vsock 5003
//!
//! Subcommands:
//! - `init`: bootstrap or recover the LUKS passphrase, write 32 raw bytes
//!   to `LUKS_KEY_FILE` (suitable for `cryptsetup --key-file`).
//! - `prepare-upgrade`: rotate the LUKS wrapping key to a new KMS key. Issued
//!   by enclavia-server in response to a verified Control command from the
//!   backend during an enclave version upgrade.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

const BLOB_VERSION: u32 = 1;
const PASSPHRASE_BYTES: usize = 32;

/// Path where `prepare-upgrade` writes rollback state so `revoke-upgrade`
/// can undo the LUKS change. Lives in tmpfs so it is automatically cleaned up
/// on reboot. Override via `UPGRADE_ROLLBACK_STASH` env var.
const DEFAULT_ROLLBACK_STASH_PATH: &str = "/run/enclavia/upgrade-rollback.json";

/// Stash written by `prepare-upgrade` before touching LUKS.
/// `revoke-upgrade` reads this to find the keyslot to kill and the blob to
/// restore.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpgradeRollbackStash {
    /// The key blob as it was BEFORE the prepare-upgrade change.
    /// `revoke-upgrade` writes this back verbatim.
    pub pre_prepare_blob: String,
    /// The LUKS keyslot number that was added for the new passphrase.
    /// `revoke-upgrade` runs `cryptsetup luksKillSlot` on this slot.
    pub new_keyslot: u32,
}

/// Load the rollback stash path from the environment (with default).
fn rollback_stash_path() -> std::path::PathBuf {
    PathBuf::from(
        std::env::var("UPGRADE_ROLLBACK_STASH")
            .unwrap_or_else(|_| DEFAULT_ROLLBACK_STASH_PATH.into()),
    )
}

/// Write the rollback stash. Ensures the parent directory exists.
pub fn write_rollback_stash(
    stash: &UpgradeRollbackStash,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = rollback_stash_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(stash)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Read the rollback stash. Returns `None` if it does not exist.
pub fn read_rollback_stash() -> Result<Option<UpgradeRollbackStash>, Box<dyn std::error::Error>> {
    let path = rollback_stash_path();
    match std::fs::read_to_string(&path) {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Box::new(e)),
    }
}

/// Remove the rollback stash (called by `revoke-upgrade` on success).
fn remove_rollback_stash() -> Result<(), Box<dyn std::error::Error>> {
    let path = rollback_stash_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

/// Identify the keyslot number that `cryptsetup` will use for `luksAddKey`.
/// Returns the first free keyslot index (the slot `luksAddKey` would claim).
/// On LUKS2 the output of `cryptsetup luksDump` includes `Keyslots:` with
/// numbered entries; the simplest portable check is `luksAddKey --dry-run`,
/// but we cannot rely on that option being present everywhere. Instead we ask
/// `cryptsetup luksDump --dump-json` and count occupied slots; the next free
/// slot is the return value.
///
/// This is a best-effort heuristic. If it fails (e.g. json output unavailable)
/// we fall back to slot 1 since a freshly-provisioned volume has only slot 0
/// occupied (the `init` passphrase) and `luksChangeKey` in `prepare-upgrade`
/// changes slot 0 in place, leaving the volume still with just one slot
/// before `prepare-upgrade` adds the second.
///
/// The caller MUST call this BEFORE `luksAddKey` so the slot number in the
/// stash is the one actually added.
fn next_free_keyslot(device: &str, cryptsetup: &str) -> u32 {
    // Try `cryptsetup luksDump --dump-json`; if it fails, fall back.
    let output = std::process::Command::new(cryptsetup)
        .args(["luksDump", "--dump-json", device])
        .output();
    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            // Count occupied keyslot indices in the JSON dump.
            // Format: "keyslots":{"0":{...},"1":{...}}
            // We just count digit keys at the top level of "keyslots".
            let mut max_slot: i64 = -1;
            for line in text.lines() {
                let trimmed = line.trim();
                // Lines like `"0" : {` or `"1" : {`
                if let Some(rest) = trimmed.strip_prefix('"') {
                    if let Some(idx_end) = rest.find('"') {
                        if let Ok(n) = rest[..idx_end].parse::<i64>() {
                            if n > max_slot {
                                max_slot = n;
                            }
                        }
                    }
                }
            }
            if max_slot >= 0 {
                return (max_slot + 1) as u32;
            }
        }
    }
    // Fallback: assume slot 0 is the only occupied slot (standard first-boot).
    1
}

#[derive(Parser)]
#[command(name = "enclavia-crypto")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap or recover the LUKS passphrase and write it to LUKS_KEY_FILE.
    Init,
    /// Rotate the LUKS wrapping key to a new KMS key. Generates a fresh raw
    /// passphrase, runs `cryptsetup luksChangeKey`, encrypts the new
    /// passphrase to the supplied public key, and updates the on-disk key
    /// blob (recording the previous key ID for deletion at the new enclave's
    /// first boot).
    ///
    /// A rollback stash is written to `UPGRADE_ROLLBACK_STASH` (default
    /// `/run/enclavia/upgrade-rollback.json`) before any LUKS changes so
    /// `revoke-upgrade` can undo them.
    ///
    /// If a stash already exists (previous prepare not yet revoked), the
    /// command rejects with an error. The backend enforces at most one
    /// in-flight upgrade per enclave so this path should not be reachable in
    /// normal operation.
    PrepareUpgrade {
        /// Base64-encoded SubjectPublicKeyInfo (DER) of the new RSA-OAEP key,
        /// as returned by KMS::GetPublicKey for the new key.
        #[arg(long)]
        new_public_key: String,
        /// Identifier (e.g. KMS ARN, or mock-kms key id) of the new key.
        #[arg(long)]
        new_key_id: String,
    },
    /// Roll back a pending upgrade. Kills the LUKS keyslot added at
    /// `prepare-upgrade` time and restores the key blob to its pre-prepare
    /// state by reading the rollback stash written by `prepare-upgrade`.
    ///
    /// Errors if no stash exists (nothing to revoke).
    RevokeUpgrade,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init => init().await,
        Command::PrepareUpgrade {
            new_public_key,
            new_key_id,
        } => prepare_upgrade(&new_public_key, &new_key_id).await,
        Command::RevokeUpgrade => revoke_upgrade().await,
    };

    if let Err(e) = result {
        error!("fatal: {e}");
        std::process::exit(1);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyBlob {
    version: u32,
    kms_key_id: String,
    /// Base64-encoded RSA-OAEP ciphertext of the passphrase. `None` on first boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    /// If set, the previous KMS key ID — call `ScheduleKeyDeletion` on it after boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prev_key_id: Option<String>,
}

async fn init() -> Result<(), Box<dyn std::error::Error>> {
    let key_file =
        PathBuf::from(std::env::var("LUKS_KEY_FILE").unwrap_or_else(|_| "/tmp/luks.key".into()));

    let raw = meta_get().await?;

    let (passphrase, mut blob) = if raw.is_empty() {
        return Err("bootstrap key blob missing — backend must write it before launch".into());
    } else {
        let mut blob: KeyBlob = serde_json::from_slice(&raw)?;
        if blob.version != BLOB_VERSION {
            return Err(format!("unsupported blob version: {}", blob.version).into());
        }

        match blob.ciphertext.clone() {
            None => {
                info!(key_id = %blob.kms_key_id, "first boot — generating passphrase");
                let passphrase = random_passphrase();
                let pubkey_der = kms_get_public_key(&blob.kms_key_id).await?;
                let ciphertext = rsa_oaep_encrypt(&pubkey_der, &passphrase)?;
                blob.ciphertext = Some(B64.encode(&ciphertext));
                meta_put(&serde_json::to_vec(&blob)?).await?;
                (passphrase, blob)
            }
            Some(ct) => {
                info!(key_id = %blob.kms_key_id, "recovering passphrase via KMS");
                let ciphertext = B64.decode(ct.as_bytes())?;
                let plaintext = kms_decrypt(&blob.kms_key_id, &ciphertext).await?;
                if plaintext.len() != PASSPHRASE_BYTES {
                    return Err(format!(
                        "decrypted passphrase has wrong length: {} (expected {PASSPHRASE_BYTES})",
                        plaintext.len()
                    )
                    .into());
                }
                (plaintext, blob)
            }
        }
    };

    write_keyfile(&key_file, &passphrase).await?;
    info!(file = %key_file.display(), bytes = passphrase.len(), "wrote LUKS keyfile");

    if let Some(prev_key_id) = blob.prev_key_id.take() {
        info!(key_id = %prev_key_id, "scheduling deletion of previous KMS key");
        match kms_schedule_deletion(&prev_key_id).await {
            Ok(()) => {
                meta_put(&serde_json::to_vec(&blob)?).await?;
                info!("previous key scheduled for deletion, blob updated");
            }
            Err(e) => {
                // Don't fail boot — the deletion can be retried by the next boot. Log loudly.
                warn!(error = %e, "failed to schedule previous key for deletion");
            }
        }
    }

    Ok(())
}

async fn prepare_upgrade(
    new_pubkey_b64: &str,
    new_key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if new_key_id.is_empty() {
        return Err("new_key_id must not be empty".into());
    }

    // Reject if a rollback stash already exists: a previous prepare-upgrade
    // has not yet been revoked or committed. The backend enforces at most one
    // in-flight upgrade per enclave, so this is a safety guard.
    if read_rollback_stash()?.is_some() {
        return Err("upgrade rollback stash already exists: a previous prepare-upgrade is still pending; revoke it first".into());
    }

    // 1. Read the current blob — this is what the new enclave version will
    //    boot from after the swap.
    let raw = meta_get().await?;
    if raw.is_empty() {
        return Err("key blob missing — volume is not provisioned".into());
    }
    let mut blob: KeyBlob = serde_json::from_slice(&raw)?;
    if blob.version != BLOB_VERSION {
        return Err(format!("unsupported blob version: {}", blob.version).into());
    }
    if new_key_id == blob.kms_key_id {
        return Err("new_key_id must differ from the current key id".into());
    }
    let current_ct_b64 = blob
        .ciphertext
        .as_ref()
        .ok_or("blob has no ciphertext — volume hasn't been provisioned yet")?
        .clone();

    // 2. Re-derive the *current* passphrase via KMS. init wipes /tmp/luks.key
    //    after mount, so cryptsetup needs a fresh copy to authenticate the
    //    luksAddKey call. One extra Decrypt per upgrade is negligible.
    let current_ct = B64.decode(current_ct_b64.as_bytes())?;
    let current_passphrase = kms_decrypt(&blob.kms_key_id, &current_ct).await?;
    if current_passphrase.len() != PASSPHRASE_BYTES {
        return Err(format!(
            "decrypted current passphrase has wrong length: {} (expected {PASSPHRASE_BYTES})",
            current_passphrase.len()
        )
        .into());
    }

    // 3. Generate the new passphrase and wrap it under the new pubkey
    //    *before* touching LUKS — if either of these fails we haven't
    //    perturbed the running volume.
    let new_pubkey_der = B64.decode(new_pubkey_b64.as_bytes())?;
    let new_passphrase = random_passphrase();
    let new_ct = rsa_oaep_encrypt(&new_pubkey_der, &new_passphrase)?;

    // 4. Stage both passphrases in tmpfs files. luksAddKey wants
    //    --key-file (current) and a positional path (new).
    let current_key_path =
        std::env::var("LUKS_CURRENT_KEY_FILE").unwrap_or_else(|_| "/tmp/luks.current.key".into());
    let new_key_path =
        std::env::var("LUKS_NEW_KEY_FILE").unwrap_or_else(|_| "/tmp/luks.new.key".into());
    let current_pb = PathBuf::from(&current_key_path);
    let new_pb = PathBuf::from(&new_key_path);
    write_keyfile(&current_pb, &current_passphrase).await?;
    write_keyfile(&new_pb, &new_passphrase).await?;

    // Best-effort cleanup on every exit path so plaintext keys never linger
    // in tmpfs after we return.
    struct KeyFileGuard(PathBuf);
    impl Drop for KeyFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _current_guard = KeyFileGuard(current_pb.clone());
    let _new_guard = KeyFileGuard(new_pb.clone());

    let device = std::env::var("NBD_DEVICE").unwrap_or_else(|_| "/dev/nbd0".into());
    let cryptsetup = std::env::var("CRYPTSETUP_BIN").unwrap_or_else(|_| "cryptsetup".into());

    // 4b. Save rollback stash BEFORE touching LUKS. We record the pre-prepare
    //     blob and the keyslot we are about to add, so `revoke-upgrade` can
    //     kill that slot and restore the blob.
    let new_keyslot = next_free_keyslot(&device, &cryptsetup);
    let stash = UpgradeRollbackStash {
        pre_prepare_blob: String::from_utf8_lossy(&raw).into_owned(),
        new_keyslot,
    };
    write_rollback_stash(&stash)?;
    info!(new_keyslot, "rollback stash written");

    // 5. Add the new passphrase as an additional LUKS keyslot (luksAddKey)
    //    rather than replacing the current slot. This is important: at revoke
    //    time we can kill only the new slot; the old slot (carrying the
    //    current running passphrase) is untouched throughout the prepare
    //    phase. The new enclave version will use the new slot; on confirmed
    //    upgrade (next boot) it can remove the old one.
    let status = std::process::Command::new(&cryptsetup)
        .args([
            "luksAddKey",
            "--batch-mode",
            "--key-file",
            &current_key_path,
            &device,
            &new_key_path,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksAddKey: {e}"))?;
    if !status.success() {
        // Remove stash on failure so a retry is possible.
        let _ = remove_rollback_stash();
        return Err(format!("cryptsetup luksAddKey exited with {status}").into());
    }

    // 6. Volume is now unlockable with both the old and new passphrase,
    //    finalise the on-disk blob to point at the new KMS key.
    //    `prev_key_id` carries the old KMS key forward so the post-upgrade
    //    boot of the new enclave can call ScheduleKeyDeletion.
    let prev_key_id = std::mem::replace(&mut blob.kms_key_id, new_key_id.to_string());
    blob.ciphertext = Some(B64.encode(&new_ct));
    blob.prev_key_id = Some(prev_key_id);
    meta_put(&serde_json::to_vec(&blob)?).await?;

    info!(
        new_key_id = %new_key_id,
        new_keyslot,
        "prepare-upgrade complete: new keyslot added, blob updated, rollback stash written",
    );
    Ok(())
}

/// Roll back a pending upgrade:
/// 1. Read the rollback stash.
/// 2. Kill the LUKS keyslot added at `prepare-upgrade` time.
/// 3. Restore the pre-prepare key blob.
/// 4. Remove the stash.
async fn revoke_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let stash = read_rollback_stash()?
        .ok_or("no upgrade rollback stash found at UPGRADE_ROLLBACK_STASH, nothing to revoke")?;

    let device = std::env::var("NBD_DEVICE").unwrap_or_else(|_| "/dev/nbd0".into());
    let cryptsetup = std::env::var("CRYPTSETUP_BIN").unwrap_or_else(|_| "cryptsetup".into());

    // We need the current passphrase to authenticate luksKillSlot. The
    // pre-prepare blob still has the original KMS key id and ciphertext.
    let pre_blob: KeyBlob = serde_json::from_str(&stash.pre_prepare_blob)?;
    let ct_b64 = pre_blob
        .ciphertext
        .as_ref()
        .ok_or("pre-prepare blob has no ciphertext, unexpected state")?;
    let ct = B64.decode(ct_b64.as_bytes())?;
    let passphrase = kms_decrypt(&pre_blob.kms_key_id, &ct).await?;

    // Stage the passphrase for cryptsetup.
    let key_path =
        std::env::var("LUKS_CURRENT_KEY_FILE").unwrap_or_else(|_| "/tmp/luks.current.key".into());
    let key_pb = PathBuf::from(&key_path);
    write_keyfile(&key_pb, &passphrase).await?;
    struct KeyFileGuard(PathBuf);
    impl Drop for KeyFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = KeyFileGuard(key_pb);

    // Kill the new keyslot.
    let slot_str = stash.new_keyslot.to_string();
    let status = std::process::Command::new(&cryptsetup)
        .args([
            "luksKillSlot",
            "--batch-mode",
            "--key-file",
            &key_path,
            &device,
            &slot_str,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksKillSlot: {e}"))?;
    if !status.success() {
        return Err(format!(
            "cryptsetup luksKillSlot (slot {}) exited with {status}",
            stash.new_keyslot
        )
        .into());
    }
    info!(slot = stash.new_keyslot, "new keyslot killed");

    // Restore the pre-prepare blob.
    meta_put(stash.pre_prepare_blob.as_bytes()).await?;
    info!("pre-prepare key blob restored");

    // Remove stash so a fresh prepare-upgrade can run.
    remove_rollback_stash()?;
    info!("rollback stash removed; revoke-upgrade complete");
    Ok(())
}

fn random_passphrase() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; PASSPHRASE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn rsa_oaep_encrypt(
    pubkey_der: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pubkey = RsaPublicKey::from_public_key_der(pubkey_der)?;
    let mut rng = rand::rngs::OsRng;
    let padding = Oaep::new::<sha2::Sha256>();
    Ok(pubkey.encrypt(&mut rng, padding, plaintext)?)
}

async fn write_keyfile(path: &PathBuf, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(contents).await?;
    file.flush().await?;
    Ok(())
}

// === Meta protocol (storage-host port 5002) ===

const META_GET: u8 = 0x01;
const META_PUT: u8 = 0x02;
const META_OK: u8 = 0x00;

async fn meta_get() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = meta_connect().await?;
    stream.write_all(&[META_GET]).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn meta_put(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = meta_connect().await?;
    stream.write_all(&[META_PUT]).await?;
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;

    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    if status[0] != META_OK {
        return Err(format!("meta PUT rejected (status {:#x})", status[0]).into());
    }
    Ok(())
}

async fn meta_connect() -> Result<tokio_vsock::VsockStream, Box<dyn std::error::Error>> {
    let port: u32 = std::env::var("META_VSOCK_PORT")
        .unwrap_or_else(|_| "5002".into())
        .parse()?;
    Ok(tokio_vsock::VsockStream::connect(2, port).await?)
}

// === KMS HTTP client ===

#[derive(Debug, Serialize)]
struct GetPublicKeyReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct GetPublicKeyResp {
    #[serde(rename = "PublicKey")]
    public_key: String,
}

#[derive(Debug, Serialize)]
struct DecryptReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String,
    #[serde(rename = "EncryptionAlgorithm")]
    encryption_algorithm: &'static str,
}

#[derive(Debug, Deserialize)]
struct DecryptResp {
    #[serde(rename = "Plaintext")]
    plaintext: String,
}

#[derive(Debug, Serialize)]
struct ScheduleDeletionReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
    #[serde(rename = "PendingWindowInDays")]
    pending_window_in_days: u32,
}

async fn kms_get_public_key(key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&GetPublicKeyReq { key_id })?;
    let resp = kms_call("TrentService.GetPublicKey", body).await?;
    let parsed: GetPublicKeyResp = serde_json::from_slice(&resp)?;
    Ok(B64.decode(parsed.public_key.as_bytes())?)
}

async fn kms_decrypt(
    key_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let req = DecryptReq {
        key_id,
        ciphertext_blob: B64.encode(ciphertext),
        encryption_algorithm: "RSAES_OAEP_SHA_256",
    };
    let body = serde_json::to_vec(&req)?;
    let resp = kms_call("TrentService.Decrypt", body).await?;
    let parsed: DecryptResp = serde_json::from_slice(&resp)?;
    Ok(B64.decode(parsed.plaintext.as_bytes())?)
}

async fn kms_schedule_deletion(key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let req = ScheduleDeletionReq {
        key_id,
        pending_window_in_days: 7,
    };
    let body = serde_json::to_vec(&req)?;
    let _ = kms_call("TrentService.ScheduleKeyDeletion", body).await?;
    Ok(())
}

async fn kms_call(target: &str, body: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let stream = kms_connect().await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!(error = %e, "kms connection task failed");
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "kms.local")
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", target)
        .body(Full::new(Bytes::from(body)))?;

    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    if !status.is_success() {
        let msg = String::from_utf8_lossy(&body);
        return Err(format!("KMS {target} returned {status}: {msg}").into());
    }
    Ok(body)
}

async fn kms_connect() -> Result<tokio_vsock::VsockStream, Box<dyn std::error::Error>> {
    let port: u32 = std::env::var("KMS_VSOCK_PORT")
        .unwrap_or_else(|_| "5003".into())
        .parse()?;
    Ok(tokio_vsock::VsockStream::connect(2, port).await?)
}
