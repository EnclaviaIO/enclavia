//! Lightweight mock of AWS KMS for local testing.
//!
//! Implements four operations matching the real KMS JSON-RPC API:
//! - `TrentService.CreateKey`
//! - `TrentService.GetPublicKey`
//! - `TrentService.Decrypt`
//! - `TrentService.ScheduleKeyDeletion`
//!
//! Keys are RSA-2048 (OAEP-SHA256) and are persisted as JSON files in
//! `KEY_DIR`. CreateKey accepts a stringified policy and, if it carries any
//! `kms:RecipientAttestation:PCR{n}` conditions, the PCR values are stored
//! alongside the key as a `<key_id>.pcrs.json` sidecar. Decrypt does not
//! enforce the policy — this is a *mock* and exists to exercise the
//! lifecycle, not to gate access.
//!
//! Listens on a Unix domain socket only — never used in production.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::net::UnixListener;
use tracing::{error, info, warn};

const RSA_BITS: usize = 2048;

/// On-disk representation of a KMS key.
#[derive(Debug, Serialize, Deserialize)]
struct StoredKey {
    key_id: String,
    /// PKCS#8 PEM private key.
    private_key_pem: String,
    /// If set, the key is scheduled for deletion (future-dated, but we treat as immediately disabled).
    deletion_date: Option<String>,
}

/// Sidecar file written next to a key whose creation policy bound it to
/// specific Nitro PCRs. We don't enforce these on Decrypt — the mock exists
/// to exercise the create-then-bind lifecycle, not to verify attestation.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct KeyPcrs {
    /// Map of PCR index (as string, matching the policy condition key suffix
    /// — e.g. "0", "1", "2") to the bound hex value.
    pcrs: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct Config {
    listen_path: PathBuf,
    key_dir: PathBuf,
    /// When true (default), `GetPublicKey` and `Decrypt` will mint a fresh
    /// keypair the first time they see a key id — preserving the legacy
    /// behaviour the storage E2E test relies on. When false, only an
    /// explicit `CreateKey` provisions a key. The backend lifecycle work
    /// (#72) flips this to `false`; `test-storage-vm` keeps the default.
    auto_create_keys: bool,
}

impl Config {
    fn from_env() -> Self {
        let listen_path =
            PathBuf::from(std::env::var("LISTEN_PATH").expect("LISTEN_PATH env var required"));
        let key_dir = PathBuf::from(
            std::env::var("KEY_DIR").unwrap_or_else(|_| "/tmp/mock-kms-keys".into()),
        );
        // Accept either the env var or a CLI flag. The flag is the
        // user-facing knob (matches the issue spec); the env var is what
        // process-compose / systemd units typically set.
        let auto_create_keys = match std::env::var("AUTO_CREATE_KEYS").ok().as_deref() {
            Some("0") | Some("false") | Some("no") => false,
            _ => true,
        };
        Self { listen_path, key_dir, auto_create_keys }
    }
}

#[derive(Clone)]
struct AppState {
    key_dir: Arc<PathBuf>,
    auto_create_keys: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut config = Config::from_env();
    // Tiny CLI surface — we only have one real flag, and adding clap just
    // to parse it would be overkill.
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--auto-create-keys" => config.auto_create_keys = true,
            "--no-auto-create-keys" => config.auto_create_keys = false,
            "--help" | "-h" => {
                eprintln!(
                    "enclavia-mock-kms\n\n\
                     Env:\n  \
                       LISTEN_PATH=<uds>           required\n  \
                       KEY_DIR=<dir>               default /tmp/mock-kms-keys\n  \
                       AUTO_CREATE_KEYS=0|1        default 1\n\n\
                     Flags:\n  \
                       --auto-create-keys / --no-auto-create-keys\n",
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    if let Err(e) = fs::create_dir_all(&config.key_dir).await {
        error!(error = %e, dir = %config.key_dir.display(), "failed to create key dir");
        std::process::exit(1);
    }

    if config.listen_path.exists() {
        let _ = fs::remove_file(&config.listen_path).await;
    }

    let listener = match UnixListener::bind(&config.listen_path) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, path = %config.listen_path.display(), "failed to bind UDS");
            std::process::exit(1);
        }
    };

    info!(
        path = %config.listen_path.display(),
        key_dir = %config.key_dir.display(),
        auto_create_keys = config.auto_create_keys,
        "mock-kms listening"
    );

    let state = AppState {
        key_dir: Arc::new(config.key_dir),
        auto_create_keys: config.auto_create_keys,
    };

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!(error = %e, "accept failed");
                        continue;
                    }
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        async move { handle(state, req).await }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        warn!(error = %e, "connection error");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown");
                return;
            }
        }
    }
}

async fn handle(
    state: AppState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != Method::POST {
        return Ok(error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""));
    }

    let target = req
        .headers()
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &format!("body read error: {e}"),
            ));
        }
    };

    let result = match target.as_str() {
        "TrentService.CreateKey" => handle_create_key(&state, &body).await,
        "TrentService.GetPublicKey" => handle_get_public_key(&state, &body).await,
        "TrentService.Decrypt" => handle_decrypt(&state, &body).await,
        "TrentService.ScheduleKeyDeletion" => handle_schedule_deletion(&state, &body).await,
        other => Err(KmsError::UnsupportedOperation(other.to_string())),
    };

    Ok(match result {
        Ok(json) => json_response(StatusCode::OK, &json),
        Err(e) => {
            warn!(target = %target, error = %e, "request failed");
            let (status, code) = e.status_and_code();
            error_response(status, code, &e.to_string())
        }
    })
}

#[derive(Debug, Default, Deserialize)]
struct CreateKeyReq {
    /// AWS uses `ENCRYPT_DECRYPT`; we accept anything but only support that.
    #[serde(rename = "KeyUsage", default)]
    _key_usage: Option<String>,
    /// AWS uses `RSA_2048`; same story — accepted but only RSA-2048 is wired up.
    #[serde(rename = "CustomerMasterKeySpec", default)]
    _customer_master_key_spec: Option<String>,
    /// AWS uses `RSA_2048` for the same field under a different name in v3 APIs.
    #[serde(rename = "KeySpec", default)]
    _key_spec: Option<String>,
    /// Stringified JSON. AWS treats this as opaque; we parse it permissively
    /// to extract `kms:RecipientAttestation:PCR{n}` bindings.
    #[serde(rename = "Policy", default)]
    policy: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateKeyResp {
    #[serde(rename = "KeyMetadata")]
    key_metadata: KeyMetadata,
}

#[derive(Debug, Serialize)]
struct KeyMetadata {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "KeyUsage")]
    key_usage: &'static str,
    #[serde(rename = "CustomerMasterKeySpec")]
    customer_master_key_spec: &'static str,
    #[serde(rename = "KeySpec")]
    key_spec: &'static str,
    #[serde(rename = "Enabled")]
    enabled: bool,
}

async fn handle_create_key(state: &AppState, body: &[u8]) -> Result<serde_json::Value, KmsError> {
    let req: CreateKeyReq = if body.is_empty() {
        CreateKeyReq::default()
    } else {
        serde_json::from_slice(body).map_err(KmsError::Invalid)?
    };

    // PCR extraction is best-effort: a malformed policy isn't a hard error
    // (we want CreateKey to succeed even if the caller passes a partial doc),
    // but missing PCRs are logged so misconfiguration surfaces in dev.
    let pcrs = match req.policy.as_deref() {
        Some(p) if !p.is_empty() => parse_policy_pcrs(p).unwrap_or_default(),
        _ => KeyPcrs::default(),
    };

    let key_id = uuid::Uuid::new_v4().to_string();

    let pem = {
        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, RSA_BITS)
            .map_err(|e| KmsError::Internal(format!("rsa keygen: {e}")))?;
        private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| KmsError::Internal(format!("pem encode: {e}")))?
            .to_string()
    };
    let stored = StoredKey {
        key_id: key_id.clone(),
        private_key_pem: pem,
        deletion_date: None,
    };
    save_key(&state.key_dir, &stored).await?;
    save_pcrs(&state.key_dir, &key_id, &pcrs).await?;

    if pcrs.pcrs.is_empty() {
        info!(key_id, "CreateKey (no PCR bindings)");
    } else {
        info!(
            key_id,
            pcrs = ?pcrs.pcrs,
            "CreateKey bound to attestation PCRs"
        );
    }

    let resp = CreateKeyResp {
        key_metadata: KeyMetadata {
            key_id: key_id.clone(),
            // Mock ARN — same shape as AWS's so callers that store/log it
            // don't choke. The trailing key id is the source of truth.
            arn: format!("arn:aws:kms:us-east-1:000000000000:key/{key_id}"),
            key_usage: "ENCRYPT_DECRYPT",
            customer_master_key_spec: "RSA_2048",
            key_spec: "RSA_2048",
            enabled: true,
        },
    };
    Ok(serde_json::to_value(resp).unwrap())
}

/// Parse a stringified KMS key policy permissively and pull out any
/// `kms:RecipientAttestation:PCR{n}` keys from any `Condition` block.
///
/// The shape we expect is the AWS-documented one (Statement[].Condition.<op>.<key>),
/// but we walk all condition operator entries and accept either a single
/// hex string or an array of hex strings as the value (AWS allows both).
/// Anything we don't recognise is silently ignored — the mock cares about
/// the PCR bindings, not the rest of the policy structure.
fn parse_policy_pcrs(policy: &str) -> Result<KeyPcrs, serde_json::Error> {
    let v: serde_json::Value = serde_json::from_str(policy)?;
    let mut out = KeyPcrs::default();

    // Statements may be a single object or an array. Normalise to a slice.
    let statements = match v.get("Statement") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(other) => vec![other.clone()],
        None => return Ok(out),
    };

    for stmt in &statements {
        let Some(cond) = stmt.get("Condition") else { continue };
        let Some(cond_map) = cond.as_object() else { continue };
        for (_op, kv) in cond_map {
            let Some(kv_map) = kv.as_object() else { continue };
            for (k, val) in kv_map {
                // `kms:RecipientAttestation:PCR0` etc. Match
                // case-insensitively on the prefix; AWS uses the canonical
                // form but our policy could be hand-rolled.
                let suffix = k
                    .strip_prefix("kms:RecipientAttestation:PCR")
                    .or_else(|| k.strip_prefix("kms:RecipientAttestation:pcr"));
                let Some(suffix) = suffix else { continue };
                let value = match val {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Array(arr) => {
                        // Take the first string; bound-on-set semantics in AWS
                        // require all to match, but a mock that just records the
                        // first entry is sufficient for the test we want to write.
                        match arr.iter().find_map(|v| v.as_str()) {
                            Some(s) => s.to_string(),
                            None => continue,
                        }
                    }
                    _ => continue,
                };
                out.pcrs.insert(suffix.to_string(), value);
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Deserialize)]
struct GetPublicKeyReq {
    #[serde(rename = "KeyId")]
    key_id: String,
}

#[derive(Debug, Serialize)]
struct GetPublicKeyResp {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "KeyUsage")]
    key_usage: &'static str,
    #[serde(rename = "KeySpec")]
    key_spec: &'static str,
    #[serde(rename = "EncryptionAlgorithms")]
    encryption_algorithms: Vec<&'static str>,
}

async fn handle_get_public_key(state: &AppState, body: &[u8]) -> Result<serde_json::Value, KmsError> {
    let req: GetPublicKeyReq = serde_json::from_slice(body).map_err(KmsError::Invalid)?;

    let stored = if state.auto_create_keys {
        load_or_create_key(&state.key_dir, &req.key_id).await?
    } else {
        load_key(&state.key_dir, &req.key_id).await?
    };
    if stored.deletion_date.is_some() {
        return Err(KmsError::KeyDisabled(req.key_id));
    }

    let private = RsaPrivateKey::from_pkcs8_pem(&stored.private_key_pem)
        .map_err(|e| KmsError::Internal(format!("decode private key: {e}")))?;
    let public = RsaPublicKey::from(&private);
    let der = public
        .to_public_key_der()
        .map_err(|e| KmsError::Internal(format!("encode public key: {e}")))?;

    let resp = GetPublicKeyResp {
        key_id: stored.key_id,
        public_key: B64.encode(der.as_bytes()),
        key_usage: "ENCRYPT_DECRYPT",
        key_spec: "RSA_2048",
        encryption_algorithms: vec!["RSAES_OAEP_SHA_256"],
    };
    Ok(serde_json::to_value(resp).unwrap())
}

#[derive(Debug, Deserialize)]
struct DecryptReq {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String,
    #[serde(rename = "EncryptionAlgorithm", default)]
    _encryption_algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
struct DecryptResp {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "Plaintext")]
    plaintext: String,
    #[serde(rename = "EncryptionAlgorithm")]
    encryption_algorithm: &'static str,
}

async fn handle_decrypt(state: &AppState, body: &[u8]) -> Result<serde_json::Value, KmsError> {
    let req: DecryptReq = serde_json::from_slice(body).map_err(KmsError::Invalid)?;

    // Decrypt never auto-creates: a missing key here means the caller is
    // confused about which key id to use, and silently minting a fresh
    // keypair would just produce a confusing "decryption failed" later.
    let stored = load_key(&state.key_dir, &req.key_id).await?;
    if stored.deletion_date.is_some() {
        return Err(KmsError::KeyDisabled(req.key_id));
    }

    let private = RsaPrivateKey::from_pkcs8_pem(&stored.private_key_pem)
        .map_err(|e| KmsError::Internal(format!("decode private key: {e}")))?;

    let ciphertext = B64
        .decode(req.ciphertext_blob.as_bytes())
        .map_err(|e| KmsError::Invalid(serde::de::Error::custom(format!("base64: {e}"))))?;

    let padding = Oaep::new::<sha2::Sha256>();
    let plaintext = private
        .decrypt(padding, &ciphertext)
        .map_err(|e| KmsError::DecryptFailed(e.to_string()))?;

    let resp = DecryptResp {
        key_id: stored.key_id,
        plaintext: B64.encode(&plaintext),
        encryption_algorithm: "RSAES_OAEP_SHA_256",
    };
    Ok(serde_json::to_value(resp).unwrap())
}

#[derive(Debug, Deserialize)]
struct ScheduleDeletionReq {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "PendingWindowInDays", default)]
    _window: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ScheduleDeletionResp {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "DeletionDate")]
    deletion_date: String,
    #[serde(rename = "KeyState")]
    key_state: &'static str,
}

async fn handle_schedule_deletion(
    state: &AppState,
    body: &[u8],
) -> Result<serde_json::Value, KmsError> {
    let req: ScheduleDeletionReq = serde_json::from_slice(body).map_err(KmsError::Invalid)?;

    let mut stored = load_key(&state.key_dir, &req.key_id).await?;
    let deletion_date = chrono_now_iso();
    stored.deletion_date = Some(deletion_date.clone());
    save_key(&state.key_dir, &stored).await?;

    let resp = ScheduleDeletionResp {
        key_id: stored.key_id,
        deletion_date,
        key_state: "PendingDeletion",
    };
    Ok(serde_json::to_value(resp).unwrap())
}

fn key_path(key_dir: &Path, key_id: &str) -> PathBuf {
    let safe: String = key_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    key_dir.join(format!("{safe}.json"))
}

fn pcrs_path(key_dir: &Path, key_id: &str) -> PathBuf {
    let safe: String = key_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    key_dir.join(format!("{safe}.pcrs.json"))
}

async fn load_key(key_dir: &Path, key_id: &str) -> Result<StoredKey, KmsError> {
    let path = key_path(key_dir, key_id);
    let raw = fs::read(&path).await.map_err(|_| KmsError::NotFound(key_id.into()))?;
    serde_json::from_slice(&raw).map_err(|e| KmsError::Internal(format!("parse stored key: {e}")))
}

async fn save_key(key_dir: &Path, stored: &StoredKey) -> Result<(), KmsError> {
    let path = key_path(key_dir, &stored.key_id);
    let json = serde_json::to_vec_pretty(stored)
        .map_err(|e| KmsError::Internal(format!("serialize: {e}")))?;
    fs::write(&path, json).await.map_err(|e| KmsError::Internal(format!("write: {e}")))?;
    Ok(())
}

async fn save_pcrs(key_dir: &Path, key_id: &str, pcrs: &KeyPcrs) -> Result<(), KmsError> {
    let path = pcrs_path(key_dir, key_id);
    let json = serde_json::to_vec_pretty(pcrs)
        .map_err(|e| KmsError::Internal(format!("serialize pcrs: {e}")))?;
    fs::write(&path, json).await.map_err(|e| KmsError::Internal(format!("write pcrs: {e}")))?;
    Ok(())
}

async fn load_or_create_key(key_dir: &Path, key_id: &str) -> Result<StoredKey, KmsError> {
    match load_key(key_dir, key_id).await {
        Ok(k) => Ok(k),
        Err(KmsError::NotFound(_)) => {
            info!(key_id, "auto-creating key");
            let pem = {
                let mut rng = rand::rngs::OsRng;
                let private = RsaPrivateKey::new(&mut rng, RSA_BITS)
                    .map_err(|e| KmsError::Internal(format!("rsa keygen: {e}")))?;
                private
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| KmsError::Internal(format!("pem encode: {e}")))?
                    .to_string()
            };
            let stored = StoredKey {
                key_id: key_id.to_string(),
                private_key_pem: pem,
                deletion_date: None,
            };
            save_key(key_dir, &stored).await?;
            Ok(stored)
        }
        Err(e) => Err(e),
    }
}

fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[derive(Debug)]
enum KmsError {
    NotFound(String),
    KeyDisabled(String),
    DecryptFailed(String),
    UnsupportedOperation(String),
    Invalid(serde_json::Error),
    Internal(String),
}

impl KmsError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            KmsError::NotFound(_) => (StatusCode::BAD_REQUEST, "NotFoundException"),
            KmsError::KeyDisabled(_) => (StatusCode::BAD_REQUEST, "KMSInvalidStateException"),
            KmsError::DecryptFailed(_) => (StatusCode::BAD_REQUEST, "InvalidCiphertextException"),
            KmsError::UnsupportedOperation(_) => {
                (StatusCode::BAD_REQUEST, "UnsupportedOperationException")
            }
            KmsError::Invalid(_) => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            KmsError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalFailure"),
        }
    }
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::NotFound(k) => write!(f, "key not found: {k}"),
            KmsError::KeyDisabled(k) => write!(f, "key is pending deletion: {k}"),
            KmsError::DecryptFailed(m) => write!(f, "decryption failed: {m}"),
            KmsError::UnsupportedOperation(t) => write!(f, "unsupported operation: {t}"),
            KmsError::Invalid(e) => write!(f, "invalid request: {e}"),
            KmsError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/x-amz-json-1.1")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let value = serde_json::json!({
        "__type": code,
        "message": message,
    });
    json_response(status, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};

    /// Spin up the mock-kms HTTP service over a fresh UDS in the supplied
    /// temp dir and return both the socket path and the key directory so
    /// tests can assert on the on-disk artefacts (key + pcrs sidecar).
    async fn spawn_mock_kms(dir: &Path) -> (PathBuf, Arc<PathBuf>) {
        let listen_path = dir.join("kms.sock");
        let key_dir = Arc::new(dir.join("keys"));
        tokio::fs::create_dir_all(&*key_dir).await.unwrap();

        let listener = UnixListener::bind(&listen_path).expect("bind kms uds");
        let state = AppState {
            key_dir: key_dir.clone(),
            // The lifecycle test exercises the strict mode: we want
            // GetPublicKey on a non-existent key to fail unless CreateKey
            // ran first, mirroring the backend-driven flow.
            auto_create_keys: false,
        };

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        async move { handle(state, req).await }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        (listen_path, key_dir)
    }

    /// Send a single TrentService request to the mock and return the parsed
    /// JSON response (or the error body, if any).
    async fn rpc(
        socket: &Path,
        target: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let stream = UnixStream::connect(socket).await.expect("connect kms");
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let body_bytes = serde_json::to_vec(&body).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "kms.local")
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", target)
            .body(Full::new(Bytes::from(body_bytes)))
            .unwrap();

        let resp = sender.send_request(req).await.expect("send");
        let status = resp.status();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = if body_bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn create_get_decrypt_round_trip_with_pcrs() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, key_dir) = spawn_mock_kms(dir.path()).await;

        // Build a policy that mirrors the AWS-documented condition shape.
        let policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": "aaaa",
                        "kms:RecipientAttestation:PCR1": "bbbb",
                        "kms:RecipientAttestation:PCR2": "cccc"
                    }
                }
            }]
        })
        .to_string();

        // CreateKey
        let (status, resp) = rpc(
            &socket,
            "TrentService.CreateKey",
            serde_json::json!({
                "KeyUsage": "ENCRYPT_DECRYPT",
                "CustomerMasterKeySpec": "RSA_2048",
                "Policy": policy,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "CreateKey body: {resp}");
        let key_id = resp["KeyMetadata"]["KeyId"].as_str().unwrap().to_string();
        assert!(!key_id.is_empty());
        assert_eq!(resp["KeyMetadata"]["KeyUsage"], "ENCRYPT_DECRYPT");
        assert_eq!(resp["KeyMetadata"]["CustomerMasterKeySpec"], "RSA_2048");

        // PCR sidecar must exist on disk.
        let sidecar = pcrs_path(&key_dir, &key_id);
        assert!(sidecar.exists(), "expected pcrs sidecar at {}", sidecar.display());
        let saved: KeyPcrs =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(saved.pcrs.get("0"), Some(&"aaaa".to_string()));
        assert_eq!(saved.pcrs.get("1"), Some(&"bbbb".to_string()));
        assert_eq!(saved.pcrs.get("2"), Some(&"cccc".to_string()));

        // GetPublicKey on the freshly-created key must succeed *without*
        // auto-create (we disabled it in spawn_mock_kms).
        let (status, resp) = rpc(
            &socket,
            "TrentService.GetPublicKey",
            serde_json::json!({ "KeyId": key_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GetPublicKey body: {resp}");
        let pubkey_b64 = resp["PublicKey"].as_str().unwrap().to_string();
        let pubkey_der = B64.decode(&pubkey_b64).unwrap();

        // RSA-OAEP encrypt 32 random bytes to that public key.
        let plaintext = b"this-is-a-mock-passphrase-32by!!";
        assert_eq!(plaintext.len(), 32);
        let pubkey = RsaPublicKey::from_public_key_der(&pubkey_der).unwrap();
        let mut rng = rand::rngs::OsRng;
        let padding = Oaep::new::<sha2::Sha256>();
        let ciphertext = pubkey.encrypt(&mut rng, padding, plaintext).unwrap();

        // Decrypt round-trip.
        let (status, resp) = rpc(
            &socket,
            "TrentService.Decrypt",
            serde_json::json!({
                "KeyId": key_id,
                "CiphertextBlob": B64.encode(&ciphertext),
                "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "Decrypt body: {resp}");
        let recovered = B64.decode(resp["Plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn get_public_key_on_unknown_id_with_auto_create_disabled_returns_404() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _key_dir) = spawn_mock_kms(dir.path()).await;

        let (status, resp) = rpc(
            &socket,
            "TrentService.GetPublicKey",
            serde_json::json!({ "KeyId": "no-such-key" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp["__type"], "NotFoundException");
    }

    #[tokio::test]
    async fn create_key_without_policy_succeeds_with_empty_pcrs() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, key_dir) = spawn_mock_kms(dir.path()).await;

        let (status, resp) = rpc(
            &socket,
            "TrentService.CreateKey",
            serde_json::json!({
                "KeyUsage": "ENCRYPT_DECRYPT",
                "CustomerMasterKeySpec": "RSA_2048"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "CreateKey body: {resp}");
        let key_id = resp["KeyMetadata"]["KeyId"].as_str().unwrap().to_string();

        let sidecar = pcrs_path(&key_dir, &key_id);
        assert!(sidecar.exists());
        let saved: KeyPcrs =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert!(saved.pcrs.is_empty());
    }

    #[test]
    fn parse_policy_extracts_pcrs_from_well_formed_doc() {
        let policy = r#"
        {
          "Statement": [{
            "Effect": "Allow",
            "Condition": {
              "StringEqualsIgnoreCase": {
                "kms:RecipientAttestation:PCR0": "aa",
                "kms:RecipientAttestation:PCR2": "cc",
                "aws:SourceArn": "arn:..."
              }
            }
          }]
        }"#;
        let pcrs = parse_policy_pcrs(policy).unwrap();
        assert_eq!(pcrs.pcrs.get("0"), Some(&"aa".to_string()));
        assert_eq!(pcrs.pcrs.get("2"), Some(&"cc".to_string()));
        assert!(pcrs.pcrs.get("1").is_none());
        assert_eq!(pcrs.pcrs.len(), 2);
    }

    #[test]
    fn parse_policy_handles_single_statement_object() {
        // Statement is sometimes serialised as a single object rather than
        // an array. We must accept both shapes.
        let policy = r#"
        {
          "Statement": {
            "Effect": "Allow",
            "Condition": {
              "StringEquals": {
                "kms:RecipientAttestation:PCR0": "deadbeef"
              }
            }
          }
        }"#;
        let pcrs = parse_policy_pcrs(policy).unwrap();
        assert_eq!(pcrs.pcrs.get("0"), Some(&"deadbeef".to_string()));
    }

    #[test]
    fn parse_policy_with_no_condition_yields_empty() {
        let policy = r#"{"Statement":[{"Effect":"Allow"}]}"#;
        let pcrs = parse_policy_pcrs(policy).unwrap();
        assert!(pcrs.pcrs.is_empty());
    }
}
