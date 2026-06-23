//! `enclavia-secrets-init` (#169): in-enclave secrets injector.
//!
//! Pipeline at boot, called from the in-enclave `init.sh` between
//! "filesystems mounted" and "crun start":
//!
//! ```text
//!   argv[1] = bundle path
//!     │
//!     ▼
//!   open vsock CID 2 (host), port 5004 with a ~2s timeout
//!     │
//!     ▼
//!   read CBOR BTreeMap<String, Vec<u8>> to EOF
//!     │
//!     ▼
//!   open <bundle>/config.json, walk process.env, splice each
//!   secret in as `NAME=value` (values are UTF-8, enforced by the
//!   backend validator); replace existing entries with the same NAME
//!     │
//!     ▼
//!   write the file back, exit 0
//! ```
//!
//! Failure modes: any error (connect, timeout, CBOR parse, file I/O,
//! malformed config.json) is fatal so the enclave fails to launch
//! loudly rather than silently dropping secrets. A silent skip on
//! connect failure would leave the workload running with missing env
//! vars; that path is unrecoverable, since the workload (e.g. the
//! notifier sample) may then re-bootstrap or otherwise overwrite
//! persistent state. The "no secrets configured" case is handled by
//! the host: the launcher always spawns `secrets-host`, which serves
//! an empty CBOR map when no secrets are defined. We then walk the
//! map and write nothing, which is a clean no-op.
//!
//! Wire format: matches the CBOR map `enclavia-secrets-host` writes
//! (see `secrets-host/src/main.rs` in `enclavia-crates`). Values are
//! `Vec<u8>` so a future binary-secret mode can land without a schema
//! change; for v1 the backend rejects non-UTF8 values so the bytes are
//! always a valid environment value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

/// Vsock CID of the host this enclave talks to.
///
/// On real AWS Nitro the parent EC2 instance is always
/// `VMADDR_CID_PARENT` == 3; under QEMU + vhost-device-vsock the host
/// bridge answers on `VMADDR_CID_HOST` == 2 (`<proxy>_5004`), where the
/// EIF init exports `VSOCK_HOST_CID=2`. Default 3 keeps production
/// correct with a single binary, no debug/enclave split (see the
/// in-enclave crate convention in CLAUDE.md).
fn host_cid() -> u32 {
    std::env::var("VSOCK_HOST_CID")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(3)
}

/// Port the host-side `enclavia-secrets-host` daemon listens on (#169).
const SECRETS_HOST_PORT: u32 = 5004;

/// One-byte ACK we send back to `secrets-host` after we have read the
/// payload. The host blocks on this byte before exiting; without it
/// the host's close (FIN) can race the receiver's reads at the
/// vhost-device-vsock UDS↔virtio bridge and surface as ENOTCONN.
/// Value `0x06` matches the constant in `secrets-host/src/main.rs`.
/// Don't change one without the other.
const ACK_BYTE: u8 = 0x06;

/// Upper bound on the secrets payload size we'll accept off the wire.
/// 1 MiB is several orders of magnitude beyond any realistic CBOR map
/// the backend would emit (a few hundred bytes per secret with the
/// per-secret value cap), and prevents a misbehaving or hostile host
/// from pinning the whole 4 GiB-CID address space.
const MAX_PAYLOAD_BYTES: usize = 1 << 20;

/// How long we wait for the host-side daemon's `accept`. The host
/// always spawns `secrets-host` (even for enclaves with no secrets,
/// in which case it serves an empty map), so a timeout here is a
/// hard failure: a missing or hung host daemon means the enclave
/// would start without env vars it was supposed to have, which is
/// unrecoverable for the workload.
///
/// 30s is a long ceiling chosen for tolerance under shared-host load:
/// the CI matrix runs multiple QEMUs concurrently on one box, and
/// virtio-vsock packet forwarding latency grows under that contention.
/// A healthy production enclave connects in single-digit milliseconds,
/// so this only ever matters as an upper bound for runaway hosts.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        // Output lands on the serial console; ANSI escapes turn into
        // literal garbage there. Same setting as every other in-enclave
        // daemon.
        .with_ansi(false)
        .init();

    let bundle = match parse_argv() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let secrets = match fetch_secrets().await {
        Ok(s) => s,
        Err(e) => {
            error!("fetching secrets from host: {e}");
            std::process::exit(1);
        }
    };

    if secrets.is_empty() {
        info!("host returned empty secrets map; nothing to inject");
        return;
    }

    if let Err(e) = inject_into_bundle(&bundle, &secrets).await {
        error!(bundle = %bundle.display(), "injecting secrets into config.json: {e}");
        std::process::exit(1);
    }

    info!(count = secrets.len(), "secrets injected into OCI bundle env");
}

fn parse_argv() -> Result<PathBuf, String> {
    let mut args = std::env::args_os();
    let _exe = args.next();
    let bundle = args
        .next()
        .ok_or_else(|| "usage: enclavia-secrets-init <bundle-dir>".to_string())?;
    if args.next().is_some() {
        return Err("usage: enclavia-secrets-init <bundle-dir> (extra args)".into());
    }
    Ok(PathBuf::from(bundle))
}

/// Connect to the host-side daemon and pull the CBOR map. Any failure
/// (connect refused, timeout, partial read, malformed CBOR) is fatal:
/// the host's launcher always spawns `secrets-host`, so an absence
/// here means something is wrong on the host side and we'd rather
/// fail the boot than start the workload with missing env vars. A
/// legitimately-empty secret set arrives as an empty CBOR map, not
/// as a missing daemon.
async fn fetch_secrets()
-> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let cid = host_cid();
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(cid, SECRETS_HOST_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err(format!(
                "vsock {cid}:{SECRETS_HOST_PORT} connect timed out after {CONNECT_TIMEOUT:?}"
            )
            .into());
        }
    };

    // Length-prefixed framing on the host→init direction: 4-byte BE
    // length, then exactly N bytes of CBOR. Replaces the older
    // `read_to_end` + `shutdown(WRITE)` shape, which relied on EOF
    // for end-of-payload and raced the host's FIN against our first
    // read at the vhost-device-vsock bridge — for a 1-byte empty
    // CBOR map (`0xa0`) the data and FIN coalesce into a single
    // virtio frame and the read surfaces as ENOTCONN. With length
    // framing the host doesn't shutdown(WRITE) at all; it stays in
    // its `await_ack` blocked on our ack byte below, so by the time
    // the kernel-level close happens we've already read the payload.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "secrets payload length {len} exceeds max {MAX_PAYLOAD_BYTES}"
        )
        .into());
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;

    // ACK as soon as we have the bytes in our address space. The host
    // is waiting on this byte; parsing + bundle write are local to
    // our process. Best-effort: if the ack write fails the host will
    // time out and log, but we already have the data so boot can
    // proceed.
    if let Err(e) = stream.write_all(&[ACK_BYTE]).await {
        warn!("sending ack to secrets-host: {e}");
    }
    // No explicit shutdown: the host's `read_exact(1)` returns as
    // soon as the ack byte arrives, regardless of whether we have
    // sent a FIN. Dropping `stream` at the end of this function
    // closes the socket; the kernel-level FIN is what cleans things
    // up on the host side too.

    if len == 0 {
        // CBOR empty map is `0xa0`, not zero bytes. Zero-length is a
        // malformed host response, not a "no secrets" case.
        return Err("host sent zero-length payload (expected at least an empty CBOR map)".into());
    }
    let map: BTreeMap<String, Vec<u8>> = ciborium::de::from_reader(&bytes[..])?;
    info!(count = map.len(), bytes = bytes.len(), "received secrets payload from host");
    Ok(map)
}

/// Read the bundle's `config.json`, merge the secrets into
/// `process.env`, and write the file back. Errors are surfaced
/// verbatim so the caller's exit logs name the failing step.
async fn inject_into_bundle(
    bundle: &Path,
    secrets: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = bundle.join("config.json");
    let raw = tokio::fs::read(&config_path).await.map_err(|e| {
        format!("reading {}: {e}", config_path.display())
    })?;
    let mut config: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("parsing {} as JSON: {e}", config_path.display()))?;

    merge_env_into_config(&mut config, secrets)?;

    let serialized = serde_json::to_vec_pretty(&config)
        .map_err(|e| format!("re-serialising config.json: {e}"))?;
    tokio::fs::write(&config_path, &serialized)
        .await
        .map_err(|e| format!("writing {}: {e}", config_path.display()))?;
    Ok(())
}

/// Pure helper for the merge step so it's exercised by unit tests.
///
/// Walks `process.env` (creating the array if absent), replaces any
/// existing `NAME=...` entry with the new value, and appends entries
/// that weren't already present. Secret values are interpreted as
/// UTF-8; the backend's validator already rejects non-UTF8 inserts so
/// the conversion is total in practice. A non-UTF8 byte sequence
/// arriving here is treated as a hard error rather than silently
/// lossy-decoded.
fn merge_env_into_config(
    config: &mut serde_json::Value,
    secrets: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let obj = config
        .as_object_mut()
        .ok_or_else(|| "config.json root is not an object".to_string())?;
    // `process` is required by the OCI runtime spec for any bundle that
    // exec's a command (which we always do); refuse to invent one.
    let process = obj
        .get_mut("process")
        .ok_or_else(|| "config.json: missing `process` object".to_string())?
        .as_object_mut()
        .ok_or_else(|| "config.json: `process` is not an object".to_string())?;

    let env = process
        .entry("env".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let env = env
        .as_array_mut()
        .ok_or_else(|| "config.json: `process.env` is not an array".to_string())?;

    for (name, value_bytes) in secrets {
        let value = std::str::from_utf8(value_bytes).map_err(|_| {
            format!("secret `{name}` value is not valid UTF-8; refusing to inject")
        })?;
        let new_entry = format!("{name}={value}");
        let prefix = format!("{name}=");
        let mut replaced = false;
        for slot in env.iter_mut() {
            if let Some(s) = slot.as_str() {
                if s.starts_with(&prefix) {
                    *slot = serde_json::Value::String(new_entry.clone());
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            env.push(serde_json::Value::String(new_entry));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(env: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "process": {
                "env": env,
                "args": ["/bin/true"],
            },
            "ociVersion": "1.0.2",
        })
    }

    fn secrets_from(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn merges_into_empty_env() {
        let mut cfg = make_config(&[]);
        let s = secrets_from(&[("FOO", "bar"), ("BAZ", "qux")]);
        merge_env_into_config(&mut cfg, &s).unwrap();
        let env = cfg["process"]["env"].as_array().unwrap();
        let strs: Vec<&str> = env.iter().filter_map(|v| v.as_str()).collect();
        assert!(strs.contains(&"FOO=bar"));
        assert!(strs.contains(&"BAZ=qux"));
        assert_eq!(strs.len(), 2);
    }

    #[test]
    fn replaces_existing_entry_in_place() {
        let mut cfg = make_config(&["PATH=/usr/bin", "FOO=old", "OTHER=keep"]);
        let s = secrets_from(&[("FOO", "new")]);
        merge_env_into_config(&mut cfg, &s).unwrap();
        let strs: Vec<&str> = cfg["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strs, vec!["PATH=/usr/bin", "FOO=new", "OTHER=keep"]);
    }

    #[test]
    fn appends_when_no_existing_entry() {
        let mut cfg = make_config(&["PATH=/usr/bin"]);
        let s = secrets_from(&[("NEW", "1")]);
        merge_env_into_config(&mut cfg, &s).unwrap();
        let strs: Vec<&str> = cfg["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strs, vec!["PATH=/usr/bin", "NEW=1"]);
    }

    #[test]
    fn creates_env_array_if_missing() {
        let mut cfg = serde_json::json!({
            "process": { "args": ["/bin/true"] },
            "ociVersion": "1.0.2",
        });
        let s = secrets_from(&[("FOO", "bar")]);
        merge_env_into_config(&mut cfg, &s).unwrap();
        let strs: Vec<&str> = cfg["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strs, vec!["FOO=bar"]);
    }

    #[test]
    fn rejects_non_utf8_value() {
        let mut cfg = make_config(&[]);
        let mut s = BTreeMap::new();
        s.insert("BAD".to_string(), vec![0xff, 0xfe, 0xfd]);
        let err = merge_env_into_config(&mut cfg, &s).unwrap_err();
        assert!(err.contains("BAD"));
        assert!(err.contains("UTF-8"));
    }

    #[test]
    fn errors_when_process_missing() {
        let mut cfg = serde_json::json!({ "ociVersion": "1.0.2" });
        let s = secrets_from(&[("FOO", "bar")]);
        assert!(merge_env_into_config(&mut cfg, &s).is_err());
    }

    #[test]
    fn errors_when_env_is_wrong_shape() {
        let mut cfg = serde_json::json!({
            "process": { "env": "not-an-array", "args": ["/bin/true"] },
        });
        let s = secrets_from(&[("FOO", "bar")]);
        assert!(merge_env_into_config(&mut cfg, &s).is_err());
    }

    #[test]
    fn empty_secret_map_is_noop() {
        let mut cfg = make_config(&["PATH=/usr/bin", "EXISTING=ok"]);
        let s = BTreeMap::new();
        merge_env_into_config(&mut cfg, &s).unwrap();
        let strs: Vec<&str> = cfg["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strs, vec!["PATH=/usr/bin", "EXISTING=ok"]);
    }

    #[test]
    fn replacement_handles_value_with_equals() {
        let mut cfg = make_config(&["DATABASE_URL=postgres://old"]);
        let s = secrets_from(&[("DATABASE_URL", "postgres://user:pass=word@host/db")]);
        merge_env_into_config(&mut cfg, &s).unwrap();
        let strs: Vec<&str> = cfg["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strs, vec!["DATABASE_URL=postgres://user:pass=word@host/db"]);
    }
}
