//! Enclave-side key management binary.
//!
//! Talks to:
//! - storage-host meta port (key blob GET/PUT) — vsock 5002
//! - KMS over vsock 5003. Two transports, picked from the environment:
//!   * **mock** (default, dev/QEMU): plaintext HTTP straight to `mock-kms`.
//!   * **AWS** (set `KMS_AWS_REGION`): the vsock peer is a raw TCP relay
//!     (`vsock-proxy`) to `kms.<region>.amazonaws.com:443`; the enclave
//!     terminates TLS itself (validating the Amazon cert chain compiled
//!     into this binary, so it is PCR-measured) and SigV4-signs each call
//!     with credentials from the environment. The host therefore sees only
//!     TLS ciphertext and cannot forge KMS responses — which is what makes
//!     the boot-time key-policy / Origin checks load-bearing.
//!
//! Subcommands:
//! - `init`: bootstrap or recover the LUKS passphrase, write 32 raw bytes
//!   to `LUKS_KEY_FILE` (suitable for `cryptsetup --key-file`).
//! - `prepare-upgrade`: rotate the LUKS wrapping key to a new KMS key. Issued
//!   by enclavia-server in response to a verified Control command from the
//!   backend during an enclave version upgrade.

use std::path::PathBuf;
use std::sync::Arc;

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

use enclavia_crypto::{kms_tls_config, sigv4};

const BLOB_VERSION: u32 = 1;
const PASSPHRASE_BYTES: usize = 32;
const KMS_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

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

/// Parse the `Keyslots:` section of a plain `cryptsetup luksDump` (LUKS2)
/// and return the occupied keyslot indices. Returns `None` when the dump
/// has no `Keyslots:` section at all (not a LUKS2 dump).
///
/// Section-aware on purpose: other sections (`Data segments:`, `Digests:`)
/// also contain numbered `  0: <type>` entries, so we only collect entries
/// between the `Keyslots:` header and the next unindented section header.
fn parse_occupied_keyslots(dump: &str) -> Option<Vec<u32>> {
    let mut in_keyslots = false;
    let mut seen_section = false;
    let mut slots = Vec::new();
    for line in dump.lines() {
        if !line.is_empty() && !line.starts_with([' ', '\t']) {
            // Unindented non-empty line: a section header or preamble field.
            in_keyslots = line.trim_end() == "Keyslots:";
            if in_keyslots {
                seen_section = true;
            }
            continue;
        }
        if !in_keyslots {
            continue;
        }
        // Slot entries look like `  0: luks2`; attribute lines under a slot
        // are tab-indented key/value pairs whose key is not an integer.
        if let Some((idx, _)) = line.trim_start().split_once(':') {
            if let Ok(n) = idx.parse::<u32>() {
                slots.push(n);
            }
        }
    }
    seen_section.then_some(slots)
}

/// Smallest keyslot index not present in `occupied`.
fn first_free_from_occupied(occupied: &[u32]) -> u32 {
    let mut n = 0u32;
    while occupied.contains(&n) {
        n += 1;
    }
    n
}

/// Determine the keyslot `prepare-upgrade` will assign to the new
/// passphrase. The caller passes this number to `luksAddKey --new-key-slot`
/// AND records it in the rollback stash, so the slot `revoke-upgrade` kills
/// is the slot that actually holds the new passphrase, by construction.
///
/// Errors instead of guessing: an earlier version of this function fell
/// back to "slot 1" when its dump parsing failed (it passed `--dump-json`,
/// which is not a cryptsetup option, so it ALWAYS fell back). That guess is
/// only right for the first upgrade on a fresh volume; on the second
/// upgrade the stash pointed at the RUNNING version's slot, which both
/// broke revoke ("No key available with this passphrase": cryptsetup wants
/// a surviving slot's passphrase to authorize the kill) and, had the kill
/// gone through, would have removed the running passphrase instead of the
/// staged one.
fn first_free_keyslot(device: &str, cryptsetup: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let out = std::process::Command::new(cryptsetup)
        .args(["luksDump", device])
        .output()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksDump: {e}"))?;
    if !out.status.success() {
        return Err(format!("cryptsetup luksDump exited with {}", out.status).into());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let occupied = parse_occupied_keyslots(&text)
        .ok_or("luksDump output has no Keyslots section: not a LUKS2 volume?")?;
    if occupied.is_empty() {
        return Err(
            "luksDump reports no occupied keyslots, but the volume is open: refusing to guess"
                .into(),
        );
    }
    Ok(first_free_from_occupied(&occupied))
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
    /// passphrase, adds it to the first free LUKS keyslot (`cryptsetup
    /// luksAddKey --new-key-slot`; the current slot is left untouched so a
    /// revoke can roll back), encrypts the new passphrase to the supplied
    /// public key, and updates the on-disk key blob (recording the previous
    /// key ID for deletion at the new enclave's first boot).
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

        // Before we either seal the passphrase under this key (first boot)
        // or rely on it to recover the passphrase (every later boot), prove
        // the key's policy gates Decrypt to OUR attestation and grants no
        // one a way to loosen that gate. A buggy or hostile backend must
        // not be able to mint a key whose plaintext the account can read.
        // Fail-closed: a bad (or unreadable) policy refuses the boot.
        verify_key_policy(&blob.kms_key_id).await?;

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
    //     blob and the keyslot luksAddKey is about to be TOLD to use (via
    //     --new-key-slot), so the slot `revoke-upgrade` kills is the slot
    //     that actually holds the new passphrase, by construction rather
    //     than by guesswork.
    let new_keyslot = first_free_keyslot(&device, &cryptsetup)?;
    let slot_str = new_keyslot.to_string();
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
    //    phase. The slot index is pinned with --new-key-slot so it is the
    //    slot recorded in the stash, not whatever cryptsetup picks. The new
    //    enclave version will unlock via the new slot; the old slot is left
    //    in place and becomes undecryptable garbage once the old KMS key is
    //    deleted after the post-upgrade boot.
    let status = std::process::Command::new(&cryptsetup)
        .args([
            "luksAddKey",
            "--batch-mode",
            "--new-key-slot",
            &slot_str,
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

    // 5b. Verify the new passphrase actually opens the slot recorded in the
    //     stash (`--test-passphrase` checks without creating a mapping). If
    //     this fails the stash points at the wrong slot and a later revoke
    //     would kill an innocent one: undo the add and bail out now, while
    //     the volume is still in its pre-prepare state.
    let verify = std::process::Command::new(&cryptsetup)
        .args([
            "luksOpen",
            "--test-passphrase",
            "--batch-mode",
            "--key-slot",
            &slot_str,
            "--key-file",
            &new_key_path,
            &device,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksOpen --test-passphrase: {e}"))?;
    if !verify.success() {
        // Best-effort cleanup: kill the slot we just added (authorized by
        // the still-valid current passphrase) and drop the stash so a retry
        // is possible.
        let _ = std::process::Command::new(&cryptsetup)
            .args([
                "luksKillSlot",
                "--batch-mode",
                "--key-file",
                &current_key_path,
                &device,
                &slot_str,
            ])
            .status();
        let _ = remove_rollback_stash();
        return Err(format!(
            "new keyslot verification failed: passphrase does not open slot {new_keyslot}"
        )
        .into());
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

    // Guard: the stash slot must NOT open with the current (pre-upgrade)
    // passphrase. If it does, the stash points at the live slot (the
    // historical failure mode of the old slot-guessing code) and killing it
    // would lock the running version out of its own volume. Refuse loudly
    // instead; the staged slot then needs manual cleanup, which beats an
    // unbootable enclave.
    let slot_str = stash.new_keyslot.to_string();
    let stash_slot_is_live = std::process::Command::new(&cryptsetup)
        .args([
            "luksOpen",
            "--test-passphrase",
            "--batch-mode",
            "--key-slot",
            &slot_str,
            "--key-file",
            &key_path,
            &device,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksOpen --test-passphrase: {e}"))?
        .success();
    if stash_slot_is_live {
        return Err(format!(
            "refusing to kill keyslot {}: the current passphrase opens it (stash points at the live slot)",
            stash.new_keyslot
        )
        .into());
    }

    // Kill the new keyslot. cryptsetup authorizes the kill with a passphrase
    // from a REMAINING slot, which the guard above just proved the current
    // passphrase is.
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

    // Sanity: the volume must still open with the pre-upgrade passphrase
    // (any slot). The guard above makes a failure here unreachable in
    // theory; if it fires anyway, do NOT restore the pre-prepare blob and
    // do NOT remove the stash, so the volume can still be opened via the
    // staged key at next boot and the state is preserved for inspection.
    let still_opens = std::process::Command::new(&cryptsetup)
        .args([
            "luksOpen",
            "--test-passphrase",
            "--batch-mode",
            "--key-file",
            &key_path,
            &device,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksOpen --test-passphrase: {e}"))?
        .success();
    if !still_opens {
        return Err(format!(
            "volume no longer opens with the pre-upgrade passphrase after killing slot {}: \
             leaving blob and stash untouched, manual recovery required",
            stash.new_keyslot
        )
        .into());
    }

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
    Ok(
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(host_cid().await, port))
            .await?,
    )
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
    // KMS phase 2 (#198): ask KMS to return the plaintext encrypted to the
    // ephemeral key we attest, instead of in the clear.
    #[serde(rename = "Recipient")]
    recipient: Recipient,
}

/// The `Recipient` parameter of a Nitro `kms:Decrypt` call: our attestation
/// document (base64) carrying the ephemeral public key, and the algorithm
/// KMS must use to wrap the content key to it.
#[derive(Debug, Serialize)]
struct Recipient {
    #[serde(rename = "AttestationDocument")]
    attestation_document: String,
    #[serde(rename = "KeyEncryptionAlgorithm")]
    key_encryption_algorithm: &'static str,
}

#[derive(Debug, Deserialize)]
struct DecryptResp {
    // With a Recipient, KMS returns the plaintext as a CMS envelope here
    // (base64) instead of `Plaintext`.
    #[serde(rename = "CiphertextForRecipient")]
    ciphertext_for_recipient: String,
}

#[derive(Debug, Serialize)]
struct ScheduleDeletionReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
    #[serde(rename = "PendingWindowInDays")]
    pending_window_in_days: u32,
}

#[derive(Debug, Serialize)]
struct GetKeyPolicyReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
    // KMS keys created by us have the single default policy. Naming it
    // explicitly keeps the request unambiguous across KMS versions.
    #[serde(rename = "PolicyName")]
    policy_name: &'static str,
}

#[derive(Debug, Deserialize)]
struct GetKeyPolicyResp {
    // The policy is returned as a stringified JSON document.
    #[serde(rename = "Policy")]
    policy: String,
}

#[derive(Debug, Serialize)]
struct DescribeKeyReq<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct DescribeKeyResp {
    #[serde(rename = "KeyMetadata")]
    key_metadata: KeyMetadata,
}

#[derive(Debug, Deserialize)]
struct KeyMetadata {
    // "AWS_KMS" for KMS-generated keys, "EXTERNAL" for imported (BYOK)
    // material, "AWS_CLOUDHSM" / "EXTERNAL_KEY_STORE" for custom stores.
    #[serde(rename = "Origin")]
    origin: String,
}

async fn kms_get_public_key(key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&GetPublicKeyReq { key_id })?;
    let resp = kms_call("TrentService.GetPublicKey", body).await?;
    let parsed: GetPublicKeyResp = serde_json::from_slice(&resp)?;
    Ok(B64.decode(parsed.public_key.as_bytes())?)
}

/// Fetch the stringified key policy via `kms:GetKeyPolicy`.
async fn kms_get_key_policy(key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&GetKeyPolicyReq {
        key_id,
        policy_name: "default",
    })?;
    let resp = kms_call("TrentService.GetKeyPolicy", body).await?;
    let parsed: GetKeyPolicyResp = serde_json::from_slice(&resp)?;
    Ok(parsed.policy)
}

/// Fetch the key's `Origin` via `kms:DescribeKey`.
async fn kms_key_origin(key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&DescribeKeyReq { key_id })?;
    let resp = kms_call("TrentService.DescribeKey", body).await?;
    let parsed: DescribeKeyResp = serde_json::from_slice(&resp)?;
    Ok(parsed.key_metadata.origin)
}

/// Verify the KMS key is safe to trust before we seal under it / rely on
/// it (see the call site in `init`). Two checks, both fatal (refuse to
/// boot on failure):
///
/// 1. **Origin must be `AWS_KMS`** (`kms:DescribeKey`). A key with imported
///    material (`EXTERNAL`) or a custom key store means someone holds the
///    private key out-of-band and could decrypt our sealed passphrase
///    offline, regardless of how tight the policy looks. So even a hostile
///    host that swaps the bootstrap blob's `key_id` to a key it created
///    cannot point us at a BYOK key.
/// 2. **Policy gates Decrypt to our own PCR0/1/2** (`kms:GetKeyPolicy` +
///    `enclavia_protocol::kms_policy::verify_decrypt_policy`), and grants no
///    principal a way to loosen that gate.
///
/// Both checks are only as trustworthy as the channel to KMS: see the
/// authenticated-transport note on `kms_call`.
async fn verify_key_policy(key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let origin = kms_key_origin(key_id).await?;
    if origin != "AWS_KMS" {
        return Err(format!(
            "KMS key {key_id} has Origin={origin}, refusing to boot: only KMS-generated \
             (non-exportable) keys are trusted; imported/external material could be held \
             out-of-band and decrypt our sealed passphrase."
        )
        .into());
    }

    let policy = kms_get_key_policy(key_id).await?;
    let own = own_pcrs()?;
    enclavia_protocol::kms_policy::verify_decrypt_policy(&policy, &own).map_err(|e| {
        format!(
            "KMS key {key_id} policy rejected, refusing to boot: {e}. \
             The key's Decrypt must be gated to this enclave's PCR0/1/2 and \
             grant no principal a way to loosen it."
        )
    })?;
    info!(key_id, "KMS key origin and policy verified against own attestation");
    Ok(())
}

/// This enclave's own PCR0/1/2, read from a fresh NSM attestation document
/// (no recipient public key needed — we only want the measurements). Works
/// identically under QEMU (emulated NSM) and real Nitro.
fn own_pcrs() -> Result<enclavia_protocol::attestation::Pcrs, Box<dyn std::error::Error>> {
    let attestation = nsm_attestation(&[])?;
    Ok(enclavia_protocol::attestation::extract_own_pcrs(&attestation)?)
}

/// Recover a plaintext via KMS using the attestation-bound recipient flow
/// (#198). We generate an ephemeral RSA key, embed its public half in an
/// NSM attestation document, and ask KMS to return the decrypted plaintext
/// as a `CiphertextForRecipient` CMS envelope encrypted to that key — so
/// the parent that proxies the KMS call sees only ciphertext. The key
/// policy's `kms:RecipientAttestation:PCRn` conditions gate the call on
/// this document's PCRs.
async fn kms_decrypt(
    key_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rsa::pkcs8::EncodePublicKey;

    // Ephemeral keypair: lives only for this call, never leaves the enclave.
    let ephemeral = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
    let public_der = rsa::RsaPublicKey::from(&ephemeral)
        .to_public_key_der()?
        .into_vec();

    // Attest the ephemeral public key. KMS reads `public_key` from the doc
    // and wraps the content key to it.
    let attestation = nsm_attestation(&public_der)?;

    let req = DecryptReq {
        key_id,
        ciphertext_blob: B64.encode(ciphertext),
        encryption_algorithm: "RSAES_OAEP_SHA_256",
        recipient: Recipient {
            attestation_document: B64.encode(&attestation),
            key_encryption_algorithm: "RSAES_OAEP_SHA_256",
        },
    };
    let body = serde_json::to_vec(&req)?;
    let resp = kms_call("TrentService.Decrypt", body).await?;
    let parsed: DecryptResp = serde_json::from_slice(&resp)?;
    let envelope = B64.decode(parsed.ciphertext_for_recipient.as_bytes())?;
    Ok(enclavia_protocol::kms_recipient::decode(&ephemeral, &envelope)?)
}

/// Request an NSM attestation document carrying `public_key` (our ephemeral
/// RSA public key, DER SPKI). Mirrors `enclavia-server::attestation`. Works
/// identically under QEMU (emulated NSM, self-signed doc) and real Nitro.
fn nsm_attestation(public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd == -1 {
        return Err("nsm_init failed (is /dev/nsm present?)".into());
    }
    let request = Request::Attestation {
        user_data: None,
        nonce: None,
        // Empty slice -> no recipient key (we only want the PCRs); a
        // non-empty key is embedded for the KMS Recipient flow.
        public_key: if public_key.is_empty() {
            None
        } else {
            Some(From::from(public_key.to_vec()))
        },
    };
    let result = match nsm_process_request(fd, request) {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(format!("NSM attestation error: {e:?}").into()),
        _ => Err("unexpected NSM response".into()),
    };
    nsm_exit(fd);
    result
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

/// Any tokio duplex stream, boxed so the plaintext (`VsockStream`) and TLS
/// (`TlsStream<VsockStream>`) transports share one `kms_call` body.
trait TokioIoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TokioIoStream for T {}

/// How the enclave reaches KMS, decided once from the environment.
enum KmsTransport {
    /// Dev/QEMU: plaintext HTTP straight to `mock-kms` over vsock.
    Mock,
    /// Production: TLS + SigV4 to real AWS KMS. The vsock peer is a raw TCP
    /// relay (`vsock-proxy`) to `kms.<region>.amazonaws.com:443`; the enclave
    /// terminates TLS itself, so the host cannot read or forge the exchange.
    Aws {
        region: String,
        host: String,
        creds: sigv4::Credentials,
    },
}

/// Select the KMS transport from the environment. `KMS_AWS_REGION` set (and
/// non-empty) selects real AWS KMS (TLS + SigV4), and then the standard
/// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ optional
/// `AWS_SESSION_TOKEN`) credentials are required; otherwise the dev/QEMU
/// plaintext-to-mock path is used.
fn kms_transport() -> Result<KmsTransport, Box<dyn std::error::Error>> {
    match std::env::var("KMS_AWS_REGION") {
        Ok(region) if !region.trim().is_empty() => {
            let region = region.trim().to_string();
            let host = format!("kms.{region}.amazonaws.com");
            let creds = sigv4::Credentials {
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID")
                    .map_err(|_| "AWS_ACCESS_KEY_ID required when KMS_AWS_REGION is set")?,
                secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY")
                    .map_err(|_| "AWS_SECRET_ACCESS_KEY required when KMS_AWS_REGION is set")?,
                session_token: std::env::var("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty()),
            };
            Ok(KmsTransport::Aws { region, host, creds })
        }
        _ => Ok(KmsTransport::Mock),
    }
}

fn kms_vsock_port() -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::env::var("KMS_VSOCK_PORT")
        .unwrap_or_else(|_| "5003".into())
        .parse()?)
}

use enclavia_vsock::host_cid;

/// Current UTC time as the SigV4 `(amz_date, date_stamp)` pair.
fn amz_timestamps() -> (String, String) {
    let now = chrono::Utc::now();
    (
        now.format("%Y%m%dT%H%M%SZ").to_string(),
        now.format("%Y%m%d").to_string(),
    )
}

async fn kms_call(target: &str, body: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let transport = kms_transport()?;
    let stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
        host_cid().await,
        kms_vsock_port()?,
    ))
    .await?;

    // TLS-wrap (AWS) or pass through (mock), and compute the signing headers.
    let (io, host_header, signed): (Box<dyn TokioIoStream>, String, Option<sigv4::SignedHeaders>) =
        match &transport {
            KmsTransport::Mock => (Box::new(stream), "kms.local".to_string(), None),
            KmsTransport::Aws {
                region,
                host,
                creds,
            } => {
                let tls = tls_connect(stream, host).await?;
                let (amz_date, date_stamp) = amz_timestamps();
                let headers = [
                    sigv4::Header {
                        name: "content-type",
                        value: KMS_CONTENT_TYPE,
                    },
                    sigv4::Header {
                        name: "x-amz-target",
                        value: target,
                    },
                ];
                let s =
                    sigv4::sign_post(creds, region, "kms", host, &amz_date, &date_stamp, &headers, &body);
                (Box::new(tls), host.clone(), Some(s))
            }
        };

    let io = TokioIo::new(io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!(error = %e, "kms connection task failed");
        }
    });

    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", host_header)
        .header("content-type", KMS_CONTENT_TYPE)
        .header("x-amz-target", target);
    if let Some(s) = signed {
        builder = builder
            .header("x-amz-date", s.amz_date)
            .header("authorization", s.authorization);
        if let Some(tok) = s.security_token {
            builder = builder.header("x-amz-security-token", tok);
        }
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;

    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let resp_body = resp.into_body().collect().await?.to_bytes().to_vec();
    if !status.is_success() {
        let msg = String::from_utf8_lossy(&resp_body);
        return Err(format!("KMS {target} returned {status}: {msg}").into());
    }
    Ok(resp_body)
}

/// TLS-wrap a raw stream to AWS KMS, validating the server certificate
/// against the Amazon (Mozilla `webpki-roots`) trust anchors compiled into
/// this binary (hence PCR-measured). Pinned to the `ring` provider so the
/// EIF builds without a C toolchain.
async fn tls_connect(
    stream: tokio_vsock::VsockStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio_vsock::VsockStream>, Box<dyn std::error::Error>> {
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(Arc::new(kms_tls_config()));
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())?;
    Ok(connector.connect(server_name, stream).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Handcrafted from a real `cryptsetup luksDump` of a LUKS2 volume with
    /// three occupied keyslots. The `Data segments:` and `Digests:` sections
    /// contain numbered `  0: <type>` entries on purpose: the parser must
    /// only count entries under `Keyslots:`.
    const LUKS2_DUMP_THREE_SLOTS: &str = "\
LUKS header information
Version:       \t2
Epoch:         \t5
Metadata area: \t16384 [bytes]
Keyslots area: \t16744448 [bytes]
UUID:          \t11111111-2222-3333-4444-555555555555
Label:         \t(no label)
Subsystem:     \t(no subsystem)
Flags:         \t(no flags)

Data segments:
  0: crypt
\toffset: 16777216 [bytes]
\tlength: (whole device)
\tcipher: aes-xts-plain64
\tsector: 512 [bytes]

Keyslots:
  0: luks2
\tKey:        512 bits
\tPriority:   normal
\tCipher:     aes-xts-plain64
\tCipher key: 512 bits
\tPBKDF:      argon2id
  1: luks2
\tKey:        512 bits
\tPriority:   normal
\tCipher:     aes-xts-plain64
  2: luks2
\tKey:        512 bits
\tPriority:   normal
Tokens:
Digests:
  0: pbkdf2
\tHash:       sha256
\tIterations: 129747
";

    #[test]
    fn parses_only_the_keyslots_section() {
        assert_eq!(
            parse_occupied_keyslots(LUKS2_DUMP_THREE_SLOTS),
            Some(vec![0, 1, 2])
        );
    }

    #[test]
    fn dump_without_keyslots_section_is_none() {
        let dump = "LUKS header information\nVersion:       \t2\n";
        assert_eq!(parse_occupied_keyslots(dump), None);
    }

    #[test]
    fn empty_keyslots_section_is_some_empty() {
        let dump = "Keyslots:\nTokens:\nDigests:\n  0: pbkdf2\n";
        assert_eq!(parse_occupied_keyslots(dump), Some(vec![]));
    }

    #[test]
    fn first_free_slot_selection() {
        assert_eq!(first_free_from_occupied(&[0, 1, 2]), 3);
        assert_eq!(first_free_from_occupied(&[0, 2]), 1);
        assert_eq!(first_free_from_occupied(&[1, 2]), 0);
        assert_eq!(first_free_from_occupied(&[]), 0);
    }
}
