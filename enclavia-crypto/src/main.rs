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
    PrepareUpgrade {
        /// Base64-encoded SubjectPublicKeyInfo (DER) of the new RSA-OAEP key,
        /// as returned by KMS::GetPublicKey for the new key.
        #[arg(long)]
        new_public_key: String,
        /// Identifier (e.g. KMS ARN, or mock-kms key id) of the new key.
        #[arg(long)]
        new_key_id: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init => init().await,
        Command::PrepareUpgrade { new_public_key, new_key_id } => {
            prepare_upgrade(&new_public_key, &new_key_id).await
        }
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
    let key_file = PathBuf::from(
        std::env::var("LUKS_KEY_FILE").unwrap_or_else(|_| "/tmp/luks.key".into()),
    );

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
    //    luksChangeKey call. One extra Decrypt per upgrade is negligible.
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

    // 4. Stage both passphrases in tmpfs files. luksChangeKey wants
    //    --key-file (current) and a positional path (new).
    let current_key_path = std::env::var("LUKS_CURRENT_KEY_FILE")
        .unwrap_or_else(|_| "/tmp/luks.current.key".into());
    let new_key_path = std::env::var("LUKS_NEW_KEY_FILE")
        .unwrap_or_else(|_| "/tmp/luks.new.key".into());
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
    // luksChangeKey atomically replaces the current keyslot's contents with
    // the new keyfile. From the host's perspective the change is durable as
    // soon as cryptsetup returns 0.
    let status = std::process::Command::new(&cryptsetup)
        .args([
            "luksChangeKey",
            "--batch-mode",
            "--key-file",
            &current_key_path,
            &device,
            &new_key_path,
        ])
        .status()
        .map_err(|e| format!("failed to spawn {cryptsetup} luksChangeKey: {e}"))?;
    if !status.success() {
        return Err(format!("cryptsetup luksChangeKey exited with {status}").into());
    }

    // 5. Volume is now wrapped with the new passphrase — finalise the
    //    on-disk blob. `prev_key_id` carries the old KMS key forward so the
    //    post-upgrade boot of the new enclave can call ScheduleKeyDeletion.
    let prev_key_id = std::mem::replace(&mut blob.kms_key_id, new_key_id.to_string());
    blob.ciphertext = Some(B64.encode(&new_ct));
    blob.prev_key_id = Some(prev_key_id);
    meta_put(&serde_json::to_vec(&blob)?).await?;

    info!(
        new_key_id = %new_key_id,
        "rotation complete: volume rewrapped, blob updated, prev key marked for deletion",
    );
    Ok(())
}

fn random_passphrase() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; PASSPHRASE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn rsa_oaep_encrypt(pubkey_der: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

async fn kms_decrypt(key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    let req = ScheduleDeletionReq { key_id, pending_window_in_days: 7 };
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
