//! `enclavia-secrets-init` (#169): in-enclave host->enclave injector.
//!
//! Two modes share ONE transport (a single-shot CBOR-over-vsock pull
//! from a host-side `enclavia-secrets-host` instance) but write to TWO
//! different sinks. The mode is selected by `--mode`:
//!
//! * `workload-secrets` (default): the original #169 path. Pulls the
//!   per-enclave secrets snapshot from vsock 5004 and splices each
//!   entry into the OCI bundle's `process.env`, right before `crun`
//!   reads the config. Sink = the OCI bundle's `config.json`.
//!
//! * `aws-creds` (#199 / #198): the real-Nitro KMS boot path. Pulls a
//!   CBOR map of `AWS_*` credentials from a SEPARATE vsock port (5013)
//!   BEFORE the storage/crypto step, and writes them as `KEY=VALUE`
//!   lines to a tmpfs env file (default `/run/aws-creds.env`) that
//!   `init.sh` then `source`s + `export`s. Sink = the env file. This
//!   makes the creds visible in `init.sh`'s OWN environment so the
//!   `enclavia-crypto init` it runs (in-enclave TLS + hand-rolled
//!   SigV4 against KMS) can authenticate. It does NOT patch the OCI
//!   bundle, and init.sh `unset`s + `rm -f`s the creds before `crun
//!   start` so the customer workload never sees `kms:Decrypt`-capable
//!   credentials.
//!
//! ```text
//!   --mode workload-secrets [bundle-dir]      (default bundle = /var/lib/oci/bundle)
//!     │
//!     ▼  dial vsock <host-cid> : 5004
//!   read CBOR BTreeMap<String, Vec<u8>>, splice into <bundle>/config.json env
//!
//!   --mode aws-creds [env-file]               (default env-file = /run/aws-creds.env)
//!     │
//!     ▼  dial vsock <host-cid> : 5013
//!   read CBOR BTreeMap<String, Vec<u8>>, write KEY=value lines to <env-file>
//! ```
//!
//! The host CID is resolved at runtime (`enclavia-vsock::host_cid`: CID
//! 3 on real Nitro, CID 2 under QEMU), so one EIF runs in both worlds.
//!
//! Backward compatibility: when invoked with a single positional
//! argument and no `--mode`, that argument is the bundle dir and the
//! mode is `workload-secrets` (the historic `enclavia-secrets-init
//! /var/lib/oci/bundle` invocation in init.sh). New init.sh wiring
//! should pass `--mode` explicitly.
//!
//! Failure modes (both sinks): any error (connect, timeout, CBOR parse,
//! file I/O, malformed config.json) is fatal so the enclave fails to
//! launch loudly rather than silently dropping the payload. A silent
//! skip on connect failure would leave the workload running with
//! missing env vars, or `enclavia-crypto init` running without AWS
//! creds; both are unrecoverable. The "no payload configured" case is
//! handled by the host: the launcher always spawns the relevant
//! `secrets-host` instance, which serves an empty CBOR map when nothing
//! is defined. We then write nothing, a clean no-op.
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

/// Port the host-side `enclavia-secrets-host` daemon listens on for the
/// workload-secrets pass (#169).
const SECRETS_HOST_PORT: u32 = 5004;

/// Port the host-side creds-serving `enclavia-secrets-host` instance
/// listens on for the AWS-creds pass (#199 / #198). A SEPARATE port
/// from 5004 on purpose: `secrets-host` is single-shot (exits after the
/// first accepted connection), so running the same transport twice
/// against one port would race the two passes. 5000-5012 are already
/// allocated (server, storage, meta, kms, secrets, chain, egress,
/// control, synchronizer bootstrap/mesh/client/names, customer relay);
/// 5013 is the first free slot. Keep this in sync with the launcher's
/// `AWS_CREDS_DEFAULT_VSOCK_PORT` and the `--port` the host instance is
/// started on.
const AWS_CREDS_HOST_PORT: u32 = 5013;

/// Default OCI bundle path for the workload-secrets pass when no
/// positional bundle argument is supplied. Matches the historic init.sh
/// invocation.
const DEFAULT_BUNDLE_DIR: &str = "/var/lib/oci/bundle";

/// Default tmpfs env-file path for the aws-creds pass when no positional
/// argument is supplied. `/run` is tmpfs in the enclave, so the file
/// never touches durable storage; init.sh `source`s it then `rm -f`s it
/// before `crun start`.
const DEFAULT_AWS_CREDS_ENV_FILE: &str = "/run/aws-creds.env";

/// One-byte ACK we send back to `secrets-host` after we have read the
/// payload. The host blocks on this byte before exiting; without it
/// the host's close (FIN) can race the receiver's reads at the
/// vhost-device-vsock UDS<->virtio bridge and surface as ENOTCONN.
/// Value `0x06` matches the constant in `secrets-host/src/main.rs`.
/// Don't change one without the other.
const ACK_BYTE: u8 = 0x06;

/// Upper bound on the payload size we'll accept off the wire. 1 MiB is
/// several orders of magnitude beyond any realistic CBOR map the
/// backend would emit (a few hundred bytes per secret with the
/// per-secret value cap), and prevents a misbehaving or hostile host
/// from pinning the whole 4 GiB-CID address space.
const MAX_PAYLOAD_BYTES: usize = 1 << 20;

/// How long we wait for the host-side daemon's `accept`. The host
/// always spawns the relevant `secrets-host` instance (even when the
/// payload is empty, in which case it serves an empty map), so a
/// timeout here is a hard failure: a missing or hung host daemon means
/// the enclave would start without env vars it was supposed to have
/// (or `enclavia-crypto init` would run without AWS creds), which is
/// unrecoverable.
///
/// 30s is a long ceiling chosen for tolerance under shared-host load:
/// the CI matrix runs multiple QEMUs concurrently on one box, and
/// virtio-vsock packet forwarding latency grows under that contention.
/// A healthy production enclave connects in single-digit milliseconds,
/// so this only ever matters as an upper bound for runaway hosts.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Which sink the pulled payload lands in. The transport (single-shot
/// CBOR-over-vsock pull) is identical for both; only the destination
/// and the dial port differ.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// #169: splice each entry into the OCI bundle's `process.env`.
    WorkloadSecrets { bundle: PathBuf },
    /// #199 / #198: write each entry as a `KEY=value` line to a tmpfs
    /// env file that init.sh sources before `enclavia-crypto init`.
    AwsCreds { env_file: PathBuf },
}

impl Mode {
    /// Vsock port the host-side daemon for this mode listens on.
    fn host_port(&self) -> u32 {
        match self {
            Mode::WorkloadSecrets { .. } => SECRETS_HOST_PORT,
            Mode::AwsCreds { .. } => AWS_CREDS_HOST_PORT,
        }
    }
}

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

    let mode = match parse_argv(std::env::args_os().skip(1)) {
        Ok(m) => m,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let payload = match fetch_payload(mode.host_port()).await {
        Ok(s) => s,
        Err(e) => {
            error!("fetching payload from host: {e}");
            std::process::exit(1);
        }
    };

    match &mode {
        Mode::WorkloadSecrets { bundle } => {
            if payload.is_empty() {
                info!("host returned empty secrets map; nothing to inject");
                return;
            }
            if let Err(e) = inject_into_bundle(bundle, &payload).await {
                error!(bundle = %bundle.display(), "injecting secrets into config.json: {e}");
                std::process::exit(1);
            }
            info!(count = payload.len(), "secrets injected into OCI bundle env");
        }
        Mode::AwsCreds { env_file } => {
            // Always write the file, even for an empty map: init.sh
            // unconditionally `source`s it (a `[ -f ]` guard would be
            // brittle), so an empty file is the right no-op. On a real
            // EC2 parent the launcher forwards the instance-role creds
            // and the map is non-empty; the empty case only happens in
            // dev paths that opt out of creds.
            if let Err(e) = write_env_file(env_file, &payload).await {
                error!(env_file = %env_file.display(), "writing aws-creds env file: {e}");
                std::process::exit(1);
            }
            info!(
                count = payload.len(),
                env_file = %env_file.display(),
                "aws creds written to tmpfs env file"
            );
        }
    }
}

/// Parse argv (already stripped of argv[0]) into a [`Mode`].
///
/// Accepted forms:
/// * `--mode workload-secrets [bundle-dir]`
/// * `--mode aws-creds [env-file]`
/// * `[bundle-dir]` (no `--mode`): legacy default, workload-secrets.
fn parse_argv<I>(args: I) -> Result<Mode, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    let mut mode_str: Option<String> = None;
    let mut positional: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        let s = arg.to_string_lossy();
        match s.as_ref() {
            "--mode" => {
                let val = args.next().ok_or_else(|| {
                    "usage: enclavia-secrets-init --mode <workload-secrets|aws-creds> [path]"
                        .to_string()
                })?;
                mode_str = Some(val.to_string_lossy().into_owned());
            }
            other if other.starts_with("--mode=") => {
                mode_str = Some(other["--mode=".len()..].to_string());
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag `{other}`"));
            }
            _ => {
                if positional.is_some() {
                    return Err("usage: enclavia-secrets-init [--mode <mode>] [path] (extra positional arg)".into());
                }
                positional = Some(PathBuf::from(arg));
            }
        }
    }

    match mode_str.as_deref() {
        // Default mode preserves the historic single-arg invocation.
        None | Some("workload-secrets") => {
            let bundle = positional.unwrap_or_else(|| PathBuf::from(DEFAULT_BUNDLE_DIR));
            Ok(Mode::WorkloadSecrets { bundle })
        }
        Some("aws-creds") => {
            let env_file =
                positional.unwrap_or_else(|| PathBuf::from(DEFAULT_AWS_CREDS_ENV_FILE));
            Ok(Mode::AwsCreds { env_file })
        }
        Some(other) => Err(format!(
            "unknown --mode `{other}` (expected `workload-secrets` or `aws-creds`)"
        )),
    }
}

/// Connect to the host-side daemon on `host_port` and pull the CBOR map.
/// Any failure (connect refused, timeout, partial read, malformed CBOR)
/// is fatal: the host's launcher always spawns the matching
/// `secrets-host` instance, so an absence here means something is wrong
/// on the host side and we'd rather fail the boot than proceed. A
/// legitimately-empty payload arrives as an empty CBOR map, not as a
/// missing daemon.
async fn fetch_payload(
    host_port: u32,
) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    // Resolve the host CID at runtime: CID 3 on real Nitro (the parent
    // EC2 instance), CID 2 under QEMU (`vhost-device-vsock` maps host
    // connections to its UDS at `<proxy>_<port>`). Same probe every
    // other in-enclave binary uses, so one EIF runs in both worlds with
    // no per-build CID baking. See `enclavia-vsock::host_cid`.
    let cid = enclavia_vsock::host_cid().await;
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(cid, host_port),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err(format!(
                "vsock {cid}:{host_port} connect timed out after {CONNECT_TIMEOUT:?}"
            )
            .into());
        }
    };

    // Length-prefixed framing on the host->init direction: 4-byte BE
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
            "payload length {len} exceeds max {MAX_PAYLOAD_BYTES}"
        )
        .into());
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;

    // ACK as soon as we have the bytes in our address space. The host
    // is waiting on this byte; parsing + sink write are local to our
    // process. Best-effort: if the ack write fails the host will time
    // out and log, but we already have the data so boot can proceed.
    if let Err(e) = stream.write_all(&[ACK_BYTE]).await {
        warn!("sending ack to secrets-host: {e}");
    }
    // No explicit shutdown: the host's `read_exact(1)` returns as soon
    // as the ack byte arrives, regardless of whether we have sent a
    // FIN. Dropping `stream` at the end of this function closes the
    // socket; the kernel-level FIN cleans things up on the host side.

    if len == 0 {
        // CBOR empty map is `0xa0`, not zero bytes. Zero-length is a
        // malformed host response, not a "no payload" case.
        return Err("host sent zero-length payload (expected at least an empty CBOR map)".into());
    }
    let map: BTreeMap<String, Vec<u8>> = ciborium::de::from_reader(&bytes[..])?;
    info!(count = map.len(), bytes = bytes.len(), "received payload from host");
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

/// Render the aws-creds map to `KEY=value\n` lines and write them to the
/// tmpfs env file (0600, truncating any prior contents). The file is
/// consumed by init.sh via `set -a; . <file>; set +a` (or an explicit
/// `export` loop), so we deliberately emit plain `KEY=value` lines with
/// no quoting. AWS credential values are base64/hex tokens and an ARN
/// region string; none contain shell metacharacters, whitespace, or
/// newlines, so unquoted assignment is safe. We still reject the few
/// shapes that WOULD break a `source` (newlines in a value, a key that
/// isn't a valid shell identifier) rather than emit a file that init.sh
/// would mis-parse.
async fn write_env_file(
    env_file: &Path,
    creds: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = render_env_file(creds)?;

    // Best-effort: create the parent dir (e.g. /run) if it somehow
    // doesn't exist. /run is tmpfs and always present in the enclave,
    // but a test path may point elsewhere.
    if let Some(parent) = env_file.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                format!("creating parent dir {}: {e}", parent.display())
            })?;
        }
    }

    tokio::fs::write(env_file, body.as_bytes())
        .await
        .map_err(|e| format!("writing {}: {e}", env_file.display()))?;

    // 0600: the file holds kms:Decrypt-capable credentials for the few
    // milliseconds between this write and init.sh's `rm -f`. init.sh
    // runs as root and is the only reader; lock it down regardless.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(env_file, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| format!("chmod 0600 {}: {e}", env_file.display()))?;
    }
    Ok(())
}

/// Pure helper: render the creds map to the env-file body. Exercised by
/// unit tests. Rejects keys that aren't valid POSIX shell identifiers
/// and values that contain a newline (either would corrupt a `source`).
fn render_env_file(creds: &BTreeMap<String, Vec<u8>>) -> Result<String, String> {
    let mut body = String::new();
    for (name, value_bytes) in creds {
        if !is_valid_env_name(name) {
            return Err(format!(
                "credential name `{name}` is not a valid shell identifier; refusing to write"
            ));
        }
        let value = std::str::from_utf8(value_bytes).map_err(|_| {
            format!("credential `{name}` value is not valid UTF-8; refusing to write")
        })?;
        if value.contains('\n') || value.contains('\r') {
            return Err(format!(
                "credential `{name}` value contains a newline; refusing to write (would corrupt the sourced env file)"
            ));
        }
        body.push_str(name);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    Ok(body)
}

/// A POSIX-ish environment variable name: first char `[A-Za-z_]`, rest
/// `[A-Za-z0-9_]`. The AWS keys we forward (`AWS_ACCESS_KEY_ID`,
/// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`) all match.
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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
    use std::ffi::OsString;

    fn osv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

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

    // ---- argv parsing -------------------------------------------------

    #[test]
    fn legacy_single_arg_is_workload_secrets() {
        let m = parse_argv(osv(&["/var/lib/oci/bundle"])).unwrap();
        assert_eq!(
            m,
            Mode::WorkloadSecrets {
                bundle: PathBuf::from("/var/lib/oci/bundle")
            }
        );
        assert_eq!(m.host_port(), SECRETS_HOST_PORT);
    }

    #[test]
    fn no_args_defaults_to_workload_secrets_default_bundle() {
        let m = parse_argv(osv(&[])).unwrap();
        assert_eq!(
            m,
            Mode::WorkloadSecrets {
                bundle: PathBuf::from(DEFAULT_BUNDLE_DIR)
            }
        );
    }

    #[test]
    fn explicit_workload_secrets_mode_with_bundle() {
        let m = parse_argv(osv(&["--mode", "workload-secrets", "/b"])).unwrap();
        assert_eq!(m, Mode::WorkloadSecrets { bundle: PathBuf::from("/b") });
    }

    #[test]
    fn aws_creds_mode_default_env_file() {
        let m = parse_argv(osv(&["--mode", "aws-creds"])).unwrap();
        assert_eq!(
            m,
            Mode::AwsCreds {
                env_file: PathBuf::from(DEFAULT_AWS_CREDS_ENV_FILE)
            }
        );
        assert_eq!(m.host_port(), AWS_CREDS_HOST_PORT);
    }

    #[test]
    fn aws_creds_mode_explicit_env_file() {
        let m = parse_argv(osv(&["--mode", "aws-creds", "/run/x.env"])).unwrap();
        assert_eq!(m, Mode::AwsCreds { env_file: PathBuf::from("/run/x.env") });
    }

    #[test]
    fn mode_equals_form_is_accepted() {
        let m = parse_argv(osv(&["--mode=aws-creds", "/e"])).unwrap();
        assert_eq!(m, Mode::AwsCreds { env_file: PathBuf::from("/e") });
    }

    #[test]
    fn ports_differ_between_modes() {
        // Load-bearing: the two passes MUST NOT share a port (the host
        // daemon is single-shot).
        assert_ne!(SECRETS_HOST_PORT, AWS_CREDS_HOST_PORT);
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let err = parse_argv(osv(&["--mode", "bogus"])).unwrap_err();
        assert!(err.contains("bogus"));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        assert!(parse_argv(osv(&["--frobnicate"])).is_err());
    }

    #[test]
    fn extra_positional_is_rejected() {
        assert!(parse_argv(osv(&["a", "b"])).is_err());
    }

    #[test]
    fn missing_mode_value_is_rejected() {
        assert!(parse_argv(osv(&["--mode"])).is_err());
    }

    // ---- aws-creds env-file sink -------------------------------------

    #[test]
    fn renders_aws_creds_as_keqv_lines() {
        let creds = secrets_from(&[
            ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "abc/def+ghi"),
            ("AWS_SESSION_TOKEN", "FwoGZ..."),
            ("AWS_REGION", "eu-central-1"),
        ]);
        let body = render_env_file(&creds).unwrap();
        // BTreeMap orders keys lexicographically.
        assert_eq!(
            body,
            "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n\
             AWS_REGION=eu-central-1\n\
             AWS_SECRET_ACCESS_KEY=abc/def+ghi\n\
             AWS_SESSION_TOKEN=FwoGZ...\n"
        );
    }

    #[test]
    fn empty_creds_map_renders_empty_body() {
        let body = render_env_file(&BTreeMap::new()).unwrap();
        assert_eq!(body, "");
    }

    #[test]
    fn rejects_value_with_newline() {
        let mut creds = BTreeMap::new();
        creds.insert("AWS_REGION".to_string(), b"eu-central-1\nrm -rf /".to_vec());
        let err = render_env_file(&creds).unwrap_err();
        assert!(err.contains("newline"));
    }

    #[test]
    fn rejects_value_with_carriage_return() {
        let mut creds = BTreeMap::new();
        creds.insert("AWS_REGION".to_string(), b"eu-central-1\rx".to_vec());
        assert!(render_env_file(&creds).is_err());
    }

    #[test]
    fn rejects_non_utf8_creds_value() {
        let mut creds = BTreeMap::new();
        creds.insert("AWS_REGION".to_string(), vec![0xff, 0xfe]);
        let err = render_env_file(&creds).unwrap_err();
        assert!(err.contains("UTF-8"));
    }

    #[test]
    fn rejects_invalid_env_name() {
        let mut creds = BTreeMap::new();
        creds.insert("9BAD".to_string(), b"x".to_vec());
        assert!(render_env_file(&creds).is_err());

        let mut creds2 = BTreeMap::new();
        creds2.insert("BAD-NAME".to_string(), b"x".to_vec());
        assert!(render_env_file(&creds2).is_err());

        let mut creds3 = BTreeMap::new();
        creds3.insert("HAS SPACE".to_string(), b"x".to_vec());
        assert!(render_env_file(&creds3).is_err());
    }

    #[test]
    fn accepts_underscore_leading_env_name() {
        let mut creds = BTreeMap::new();
        creds.insert("_PRIVATE".to_string(), b"x".to_vec());
        assert_eq!(render_env_file(&creds).unwrap(), "_PRIVATE=x\n");
    }

    #[tokio::test]
    async fn write_env_file_writes_0600_and_content() {
        let dir = tempdir();
        let path = dir.join("aws-creds.env");
        let creds = secrets_from(&[("AWS_REGION", "us-east-1")]);
        write_env_file(&path, &creds).await.unwrap();

        let read_back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_back, "AWS_REGION=us-east-1\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn write_env_file_truncates_prior_contents() {
        let dir = tempdir();
        let path = dir.join("aws-creds.env");
        std::fs::write(&path, "STALE=leftover\nMORE=junk\n").unwrap();
        let creds = secrets_from(&[("AWS_REGION", "eu-west-1")]);
        write_env_file(&path, &creds).await.unwrap();
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_back, "AWS_REGION=eu-west-1\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Minimal tempdir helper so the crate doesn't need a dev-dependency
    /// on `tempfile`. Uses a pid+nanos suffix under the system temp dir.
    fn tempdir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "enclavia-secrets-init-test-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ---- existing workload-secrets merge behaviour -------------------

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
