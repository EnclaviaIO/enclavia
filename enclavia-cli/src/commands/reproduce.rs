//! `enclavia reproduce <enclave-id>` — rebuild an enclave's EIF locally and
//! verify its PCRs match what the backend recorded for the original build.
//!
//! Trust model: a public enclave's PCR set is the public proof that a given
//! image was built into the running enclave. Any third party can pull the
//! pinned image, run the same builder, and demand byte-for-byte PCR equality.
//! For private enclaves only the owner can pull the image (the registry
//! enforces this); the comparison is otherwise identical.
//!
//! The CLI does not re-implement the build — it shells out to the same
//! `builder` binary the backend uses, which is published as part of the
//! product. Path discovery falls back to `BUILDER_PATH` env var, then to
//! `builder` on `$PATH`.

use std::path::PathBuf;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::api::{ApiClient, EnclaveSummary};
use crate::error::CliError;

/// Result of `enclavia reproduce`. The CLI binary turns this into a
/// human-readable success/diff; downstream callers (MCP) can format it
/// however they like.
#[derive(Debug, Clone, Serialize)]
pub struct ReproduceResult {
    pub enclave_id: String,
    pub image_digest: String,
    /// PCRs the backend recorded when it originally built this enclave.
    pub expected: PcrTriple,
    /// PCRs the local builder produced just now.
    pub actual: PcrTriple,
    /// Empty when the build is reproducible. Each entry names a PCR slot
    /// (`PCR0`/`PCR1`/`PCR2`) that diverged.
    pub mismatches: Vec<PcrMismatch>,
    /// Git rev of the `builder` flake input the backend used when it
    /// originally built this enclave. Surfaced as a hint so the user can
    /// re-run their local builder against the matching source. `None` on
    /// rows from a backend without `FLAKE_LOCK_PATH` (or built before
    /// the column existed).
    pub recorded_builder_rev: Option<String>,
    /// Git rev of the `enclavia-crates` flake input. Same null
    /// semantics as `recorded_builder_rev`.
    pub recorded_crates_rev: Option<String>,
    /// Egress allowlist that the backend recorded for this enclave
    /// (verbatim from the JSONB column). `null` means the user didn't
    /// supply one; the local build is handed the empty document so
    /// PCRs match the backend's empty-doc bake.
    pub recorded_egress_allowlist: serde_json::Value,
}

impl ReproduceResult {
    pub fn is_reproducible(&self) -> bool {
        self.mismatches.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcrTriple {
    #[serde(rename = "PCR0")]
    pub pcr0: String,
    #[serde(rename = "PCR1")]
    pub pcr1: String,
    #[serde(rename = "PCR2")]
    pub pcr2: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcrMismatch {
    pub slot: &'static str,
    pub expected: String,
    pub actual: String,
}

/// The version-specific inputs that drive a single reproduce run. These
/// pair a docker image + digest with the PCRs the backend recorded and
/// the flake revs it built from. They come from one of two places:
///
/// - The `enclaves` row (the CURRENT running version), via the default
///   `enclavia reproduce <id>` path.
/// - A `staged_upgrades` row (a SUPERSEDED or pending version), via the
///   `enclavia reproduce <id> --upgrade <upgrade-id>` path.
///
/// Everything else the builder needs (container_port, mode, storage,
/// control pubkey, egress allowlist) is an enclave-level property that
/// does not change across upgrades, so it is always read from the
/// enclave row in [`run_builder`]. This struct carries only the bits
/// that differ between versions.
#[derive(Debug)]
struct ReproduceInputs {
    image_digest: String,
    expected: PcrTriple,
    docker_image: String,
    builder_rev: Option<String>,
    crates_rev: Option<String>,
}

impl ReproduceInputs {
    /// Build inputs from the `enclaves` row (the current version). Errors
    /// when the row has no recorded digest/PCRs (build never started).
    fn from_enclave_row(enclave: &serde_json::Value, enclave_id: &str) -> Result<Self, CliError> {
        let image_digest = enclave
            .get("image_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Other(format!(
                "enclave {enclave_id} has no recorded image_digest (only enclaves whose build has started can be reproduced)"
            )))?
            .to_string();

        let expected = expected_pcrs(enclave)?;

        let docker_image = enclave
            .get("docker_image")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Other("enclave is missing docker_image".into()))?
            .to_string();

        Ok(Self {
            image_digest,
            expected,
            docker_image,
            builder_rev: opt_str(enclave, "builder_rev"),
            crates_rev: opt_str(enclave, "crates_rev"),
        })
    }

    /// Build inputs from a `staged_upgrades` row (a historical or pending
    /// version). The DTO is `StagedUpgradeJson`, so the typed fields are
    /// already parsed.
    ///
    /// Two distinct failure modes get distinct, clear errors:
    /// - No digest/PCRs: the build never completed (still `building`, or
    ///   `failed`). There is nothing to reproduce.
    /// - Digest + PCRs present but NULL revs: the upgrade was staged
    ///   before per-version provenance was recorded, so the local rebuild
    ///   can't be pinned to the exact sources.
    fn from_staged_upgrade(
        upgrade: &enclavia_protocol::staging::StagedUpgradeJson,
    ) -> Result<Self, CliError> {
        let image_digest = upgrade.image_digest.clone().ok_or_else(|| {
            CliError::Other(format!(
                "upgrade {} has no recorded image_digest: its build never completed (status {:?}), so there is nothing to reproduce",
                upgrade.id, upgrade.status
            ))
        })?;

        let pcrs = upgrade.pcrs.as_ref().ok_or_else(|| {
            CliError::Other(format!(
                "upgrade {} has no recorded PCRs: its build never completed (status {:?}), so there is nothing to reproduce",
                upgrade.id, upgrade.status
            ))
        })?;
        let expected = PcrTriple {
            pcr0: pcrs.pcr0.clone(),
            pcr1: pcrs.pcr1.clone(),
            pcr2: pcrs.pcr2.clone(),
        };

        if upgrade.builder_rev.is_none() || upgrade.crates_rev.is_none() {
            return Err(CliError::Other(format!(
                "upgrade {} was staged before per-version provenance was recorded; cannot pin sources for a deterministic rebuild",
                upgrade.id
            )));
        }

        Ok(Self {
            image_digest,
            expected,
            docker_image: upgrade.docker_image.clone(),
            builder_rev: upgrade.builder_rev.clone(),
            crates_rev: upgrade.crates_rev.clone(),
        })
    }
}

/// Pull an optional string field off a JSON object as an owned `String`.
fn opt_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Resolve `<id-or-prefix>`, fetch the enclave row, run the local builder,
/// and compare PCRs. Returns Ok even when the comparison fails — the
/// caller decides how to surface a non-reproducible build (the binary
/// exits non-zero; MCP returns the struct as-is).
pub async fn reproduce(
    client: &ApiClient,
    id_or_prefix: &str,
) -> Result<ReproduceResult, CliError> {
    let summary = resolve_enclave(client, id_or_prefix).await?;
    let enclave = client.get_enclave(&summary.id).await?;
    let inputs = ReproduceInputs::from_enclave_row(&enclave, &summary.id)?;
    run_reproduce(&summary.id, &enclave, inputs).await
}

/// Reproduce a SUPERSEDED or pending version of an enclave from its
/// `staged_upgrades` row instead of the current `enclaves` row. The
/// enclave row is still fetched for the version-invariant build
/// parameters (container_port, mode, storage, control pubkey, egress
/// allowlist); only the digest/PCRs/revs come from the staged row.
pub async fn reproduce_upgrade(
    client: &ApiClient,
    id_or_prefix: &str,
    upgrade_id: &str,
) -> Result<ReproduceResult, CliError> {
    let summary = resolve_enclave(client, id_or_prefix).await?;
    let enclave = client.get_enclave(&summary.id).await?;
    let upgrade = client.get_upgrade(&summary.id, upgrade_id).await?;
    let inputs = ReproduceInputs::from_staged_upgrade(&upgrade)?;
    run_reproduce(&summary.id, &enclave, inputs).await
}

/// Shared tail of both reproduce paths: pin the image, run the local
/// builder against the version-invariant enclave parameters plus the
/// version-specific [`ReproduceInputs`], and diff the PCRs.
async fn run_reproduce(
    enclave_id: &str,
    enclave: &serde_json::Value,
    inputs: ReproduceInputs,
) -> Result<ReproduceResult, CliError> {
    let pinned_image = pin_to_digest(&inputs.docker_image, &inputs.image_digest);

    let recorded_egress_allowlist = enclave
        .get("egress_allowlist")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let actual = run_builder(
        enclave_id,
        &pinned_image,
        enclave,
        &inputs.image_digest,
        &recorded_egress_allowlist,
        inputs.builder_rev.as_deref(),
        inputs.crates_rev.as_deref(),
    )
    .await?;

    let mismatches = diff_pcrs(&inputs.expected, &actual);

    Ok(ReproduceResult {
        enclave_id: enclave_id.to_string(),
        image_digest: inputs.image_digest,
        expected: inputs.expected,
        actual,
        mismatches,
        recorded_builder_rev: inputs.builder_rev,
        recorded_crates_rev: inputs.crates_rev,
        recorded_egress_allowlist,
    })
}

/// Pull the typed PCR triple out of the GET /enclaves/:id response.
fn expected_pcrs(enclave: &serde_json::Value) -> Result<PcrTriple, CliError> {
    let pcrs = enclave
        .get("pcrs")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CliError::Other(
            "enclave has no recorded PCRs — only enclaves that have been built can be reproduced".into(),
        ))?;

    let take = |key: &str| -> Result<String, CliError> {
        pcrs.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::Other(format!("PCRs object is missing {key}")))
    };

    Ok(PcrTriple {
        pcr0: take("PCR0")?,
        pcr1: take("PCR1")?,
        pcr2: take("PCR2")?,
    })
}

/// Public-repo URLs used to fetch the `builder` and `enclavia` flake
/// sources at the revs the backend recorded. `github:` is unauthenticated
/// HTTPS now that both repos are public — anyone running
/// `enclavia reproduce` can fetch the recorded sources without an
/// SSH key on file with GitHub.
const BUILDER_FLAKE_URL: &str = "github:EnclaviaIO/builder";
const ENCLAVIA_FLAKE_URL: &str = "github:EnclaviaIO/enclavia";

/// Spawn the local builder with flags that mirror the backend's invocation
/// for this enclave. PCR equality is sensitive to every flag that touches
/// the kernel, initramfs, or rootfs — `--debug`, `--storage`, `--enclave-id`,
/// and `--control-pubkey` all change the measurements, so each is forwarded
/// based on what's recorded on the row.
///
/// When the backend recorded `builder_rev` / `crates_rev`, we fetch the
/// matching sources via `nix flake metadata` and pass them as
/// `BUILDER_FLAKE` / `ENCLAVIA_FLAKE` env vars. The builder picks these
/// up and passes them to its own `nix build` as `--override-input`, so
/// the EIF is reconstructed from the exact sources the backend used.
/// Without recorded revs we fall through to the caller's environment —
/// reproduce won't reliably match in that case, but it still runs.
#[allow(clippy::too_many_arguments)]
async fn run_builder(
    enclave_id: &str,
    pinned_image: &str,
    enclave: &serde_json::Value,
    image_digest: &str,
    egress_allowlist: &serde_json::Value,
    recorded_builder_rev: Option<&str>,
    recorded_crates_rev: Option<&str>,
) -> Result<PcrTriple, CliError> {
    let builder_path = std::env::var("BUILDER_PATH").unwrap_or_else(|_| "builder".to_string());
    let output_dir = std::env::temp_dir().join(format!("enclavia-reproduce-{enclave_id}"));
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", output_dir.display())))?;

    // Materialise the recorded allowlist as a file the builder can copy
    // into the bundle. NULL on the row means the original build went
    // through the empty-doc path, so we mirror that here for PCR
    // equality.
    let egress_doc = if egress_allowlist.is_null() {
        serde_json::json!({"version": 1, "resolvers": [], "egress": []})
    } else {
        egress_allowlist.clone()
    };
    let egress_path = output_dir.join("egress.json");
    let serialized = serde_json::to_vec_pretty(&egress_doc)
        .map_err(|e| CliError::Other(format!("serialising allowlist: {e}")))?;
    std::fs::write(&egress_path, serialized)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", egress_path.display())))?;

    let mut cmd = Command::new(&builder_path);
    cmd.arg("build")
        .arg("--image")
        .arg(pinned_image)
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--enclave-id")
        .arg(enclave_id)
        .arg("--egress-allowlist")
        .arg(&egress_path);

    // Match the backend's `--image-digest` invocation so the rebuilt
    // `enclavia-config.json` is byte-identical to the original.
    // Without this the chain-init path bakes a different config into
    // the initramfs, which moves PCR0 and PCR2 and makes the
    // reproducibility check fail. The digest is passed in explicitly:
    // for the default path it is the enclave row's digest, for the
    // `--upgrade` path it is the staged row's digest (which differs
    // from the enclave row's once a later version has been promoted).
    cmd.arg("--image-digest").arg(image_digest);

    if let Some(port) = enclave.get("container_port").and_then(|v| v.as_u64()) {
        cmd.arg("--container-port").arg(port.to_string());
    }

    let mode = enclave.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    if mode == "debug" {
        cmd.arg("--debug");
    }

    let storage_size = enclave
        .get("storage_size_bytes")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            enclave
                .get("storage")
                .and_then(|s| s.get("size_bytes"))
                .and_then(|v| v.as_u64())
        });
    if storage_size.is_some() {
        cmd.arg("--storage");
    }

    if let Some(pubkey_field) = enclave.get("control_public_key") {
        if let Some(b64) = pubkey_field.as_str() {
            // `serde_json` serialises `Vec<u8>` as a JSON array of bytes,
            // not a base64 string — so a string here means an upstream
            // formatter has already encoded it. Pass it straight through.
            cmd.arg("--control-pubkey").arg(b64);
        } else if let Some(arr) = pubkey_field.as_array() {
            // Array-of-bytes form: re-encode as base64 since the builder
            // expects a 32-byte key as base64 on the command line.
            use base64::Engine;
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            if !bytes.is_empty() {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                cmd.arg("--control-pubkey").arg(b64);
            }
        }
    }

    // If the backend recorded the source revs, materialise both as
    // /nix/store paths and hand them to the builder via the env vars
    // its `nix build` invocation honours as `--override-input`.
    if let Some(rev) = recorded_builder_rev {
        let path = fetch_flake_source("builder", BUILDER_FLAKE_URL, rev).await?;
        cmd.env("BUILDER_FLAKE", path);
    } else {
        eprintln!("No recorded builder_rev on this enclave; reproduce will use the BUILDER_FLAKE in your environment (or the builder's own default), which may differ from what the backend used and produce diverging PCRs.");
    }
    if let Some(rev) = recorded_crates_rev {
        let path = fetch_flake_source("enclavia", ENCLAVIA_FLAKE_URL, rev).await?;
        cmd.env("ENCLAVIA_FLAKE", path);
    } else {
        eprintln!("No recorded crates_rev on this enclave; reproduce will use the ENCLAVIA_FLAKE in your environment (or the builder's flake.lock pin), which may differ from what the backend used and produce diverging PCRs.");
    }

    eprintln!("Running local builder: {builder_path:?}");
    eprintln!("  output: {}", output_dir.display());

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| CliError::Other(format!("failed to spawn builder ({builder_path:?}): {e}. Set BUILDER_PATH to point at a `builder` binary.")))?
        .wait_with_output()
        .await
        .map_err(|e| CliError::Other(format!("builder I/O error: {e}")))?;

    if !output.status.success() {
        return Err(CliError::Other(format!(
            "builder exited with {}: rerun with `RUST_LOG=debug` for details",
            output.status,
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_builder_output(stdout.trim()).map_err(|e| {
        CliError::Other(format!(
            "couldn't parse builder output: {e}\n--- builder stdout ---\n{stdout}\n--- end ---"
        ))
    })
}

/// The builder writes a JSON line on stdout with `eif_path` and `pcrs`.
/// Some builders also emit logs on stdout; tolerate that by scanning for
/// the last line that parses as the expected JSON object.
fn parse_builder_output(stdout: &str) -> Result<PcrTriple, String> {
    #[derive(Deserialize)]
    struct BuildResult {
        pcrs: PcrTriple,
        #[serde(default)]
        #[allow(dead_code)]
        eif_path: Option<PathBuf>,
    }

    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("builder produced no stdout".into());
    }

    // Fast path: stdout is a single JSON object.
    if let Ok(parsed) = serde_json::from_str::<BuildResult>(trimmed) {
        return Ok(parsed.pcrs);
    }

    // Fallback: parse each line, keep the last successful parse.
    let mut last: Option<PcrTriple> = None;
    for line in trimmed.lines().rev() {
        if let Ok(parsed) = serde_json::from_str::<BuildResult>(line.trim()) {
            last = Some(parsed.pcrs);
            break;
        }
    }
    last.ok_or_else(|| {
        "no JSON line in builder stdout matched `{ pcrs: { PCR0, PCR1, PCR2 } }`".to_string()
    })
}

/// Fetch a flake source at a given git rev and return its /nix/store path.
/// Used to pin the builder + enclavia sources to whatever the backend
/// recorded for an enclave at build time. Shells out to `nix flake
/// metadata --json <url>?rev=<rev>` and parses the `path` field.
///
/// The user must have `nix` on PATH (a CLI prerequisite). Fetching uses
/// whatever auth `nix` is configured with — for `git+ssh://` URLs that
/// means the user's GitHub SSH key; for `github:` URLs (post public
/// flip) it's unauthenticated HTTPS.
async fn fetch_flake_source(label: &str, url: &str, rev: &str) -> Result<PathBuf, CliError> {
    let flake_ref = format!("{url}?rev={rev}");
    eprintln!("Fetching {label} source at {rev} from {url} …");

    // --no-write-lock-file: the remote URL is read-only, so don't let
    // nix try to rewrite the fetched flake's lock when it spots stale
    // transitive inputs. We only want the source store path; nothing
    // else cares about transitive lock freshness here.
    let output = Command::new("nix")
        .args([
            "flake",
            "metadata",
            "--json",
            "--no-write-lock-file",
            &flake_ref,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            CliError::Other(format!(
                "failed to spawn `nix flake metadata` (is `nix` on PATH?): {e}"
            ))
        })?
        .wait_with_output()
        .await
        .map_err(|e| CliError::Other(format!("`nix flake metadata` I/O error: {e}")))?;

    if !output.status.success() {
        return Err(CliError::Other(format!(
            "`nix flake metadata {flake_ref}` failed ({}). The recorded {label} rev is {rev}; verify your nix has access to the source URL (SSH key for the private repos pre-flip).",
            output.status,
        )));
    }

    #[derive(Deserialize)]
    struct FlakeMetadata {
        path: String,
    }
    let parsed: FlakeMetadata = serde_json::from_slice(&output.stdout).map_err(|e| {
        CliError::Other(format!(
            "couldn't parse `nix flake metadata` output for {label}: {e}"
        ))
    })?;
    Ok(PathBuf::from(parsed.path))
}

/// Replace a `<host>/<owner>/<repo>:<tag>` reference with its digest-pinned
/// form `<host>/<owner>/<repo>@sha256:<digest>`. Mirrors the backend's
/// `pin_image_to_digest` so the CLI pulls exactly the bytes the original
/// build pulled, even if the tag has since been overwritten by a newer push.
fn pin_to_digest(canonical: &str, digest: &str) -> String {
    if canonical.contains('@') {
        // Already digest-pinned. Trust the caller — re-pinning would just
        // produce the same string.
        return canonical.to_string();
    }
    match canonical.rsplit_once(':') {
        Some((stem, _tag)) => format!("{stem}@{digest}"),
        None => format!("{canonical}@{digest}"),
    }
}

/// Slot-by-slot comparison. Three independent PCRs means up to three
/// entries in the diff, each labelled with its slot.
pub fn diff_pcrs(expected: &PcrTriple, actual: &PcrTriple) -> Vec<PcrMismatch> {
    let mut diffs = Vec::new();
    if expected.pcr0 != actual.pcr0 {
        diffs.push(PcrMismatch {
            slot: "PCR0",
            expected: expected.pcr0.clone(),
            actual: actual.pcr0.clone(),
        });
    }
    if expected.pcr1 != actual.pcr1 {
        diffs.push(PcrMismatch {
            slot: "PCR1",
            expected: expected.pcr1.clone(),
            actual: actual.pcr1.clone(),
        });
    }
    if expected.pcr2 != actual.pcr2 {
        diffs.push(PcrMismatch {
            slot: "PCR2",
            expected: expected.pcr2.clone(),
            actual: actual.pcr2.clone(),
        });
    }
    diffs
}

/// Same prefix-matching the `push` command uses. Returns the `EnclaveSummary`
/// for the unique match; errors with a candidate list when the prefix is
/// ambiguous, and with a "no match" when nothing hits.
///
/// A full UUID short-circuits the listing — we don't need
/// `list_enclaves` to disambiguate, and skipping it lets the anonymous
/// reproduce path (no credentials, querying a public enclave) work
/// without ever hitting the authenticated list endpoint.
async fn resolve_enclave(
    client: &ApiClient,
    id_or_prefix: &str,
) -> Result<EnclaveSummary, CliError> {
    if id_or_prefix.is_empty() {
        return Err("enclave id cannot be empty".into());
    }

    if uuid::Uuid::parse_str(id_or_prefix).is_ok() {
        return Ok(EnclaveSummary {
            id: id_or_prefix.to_string(),
            ..Default::default()
        });
    }

    let all = client.list_enclaves(true).await?;
    let matches: Vec<EnclaveSummary> = all
        .into_iter()
        .filter(|e| e.id.starts_with(id_or_prefix))
        .collect();

    match matches.as_slice() {
        [] => Err(CliError::Other(format!(
            "no enclave matches `{id_or_prefix}`. List your enclaves with `enclavia enclave list`."
        ))),
        [one] => Ok(one.clone()),
        many => {
            let mut msg = format!(
                "prefix `{id_or_prefix}` matches {} enclaves; pass a longer prefix:\n",
                many.len()
            );
            for e in many {
                let name = e.name.as_deref().unwrap_or("-");
                msg.push_str(&format!("  {} ({name})\n", e.id));
            }
            Err(CliError::Other(msg.trim_end().to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn triple(p0: &str, p1: &str, p2: &str) -> PcrTriple {
        PcrTriple {
            pcr0: p0.into(),
            pcr1: p1.into(),
            pcr2: p2.into(),
        }
    }

    #[test]
    fn diff_returns_empty_when_all_match() {
        let t = triple("aa", "bb", "cc");
        assert!(diff_pcrs(&t, &t).is_empty());
    }

    #[test]
    fn diff_flags_single_mismatch() {
        let expected = triple("aa", "bb", "cc");
        let actual = triple("aa", "BB", "cc");
        let diffs = diff_pcrs(&expected, &actual);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].slot, "PCR1");
        assert_eq!(diffs[0].expected, "bb");
        assert_eq!(diffs[0].actual, "BB");
    }

    #[test]
    fn diff_flags_all_three_when_all_differ() {
        let expected = triple("aa", "bb", "cc");
        let actual = triple("AA", "BB", "CC");
        let diffs = diff_pcrs(&expected, &actual);
        assert_eq!(diffs.len(), 3);
        let slots: Vec<_> = diffs.iter().map(|m| m.slot).collect();
        assert_eq!(slots, vec!["PCR0", "PCR1", "PCR2"]);
    }

    #[test]
    fn pin_replaces_tag_with_digest() {
        let pinned = pin_to_digest("registry.local:5000/alice/foo:bar", "sha256:deadbeef");
        assert_eq!(pinned, "registry.local:5000/alice/foo@sha256:deadbeef");
    }

    #[test]
    fn pin_is_idempotent_when_already_digest_pinned() {
        let already = "registry.local:5000/alice/foo@sha256:deadbeef";
        assert_eq!(pin_to_digest(already, "sha256:other"), already);
    }

    #[test]
    fn parse_builder_output_handles_single_json_line() {
        let stdout = r#"{"pcrs":{"PCR0":"a","PCR1":"b","PCR2":"c"},"eif_path":"/tmp/x"}"#;
        let pcrs = parse_builder_output(stdout).expect("parse");
        assert_eq!(pcrs, triple("a", "b", "c"));
    }

    #[test]
    fn parse_builder_output_picks_last_json_when_logs_present() {
        let stdout = "loading…\nstep 1\n{\"pcrs\":{\"PCR0\":\"x\",\"PCR1\":\"y\",\"PCR2\":\"z\"}}";
        let pcrs = parse_builder_output(stdout).expect("parse");
        assert_eq!(pcrs, triple("x", "y", "z"));
    }

    #[test]
    fn parse_builder_output_errors_when_no_json() {
        assert!(parse_builder_output("nothing here\n").is_err());
    }

    #[test]
    fn is_reproducible_reflects_diff() {
        let r = ReproduceResult {
            enclave_id: "id".into(),
            image_digest: "sha256:x".into(),
            expected: triple("a", "b", "c"),
            actual: triple("a", "b", "c"),
            mismatches: vec![],
            recorded_builder_rev: None,
            recorded_crates_rev: None,
            recorded_egress_allowlist: serde_json::Value::Null,
        };
        assert!(r.is_reproducible());

        let r = ReproduceResult {
            mismatches: vec![PcrMismatch {
                slot: "PCR0",
                expected: "a".into(),
                actual: "z".into(),
            }],
            ..r
        };
        assert!(!r.is_reproducible());
    }

    // -- ReproduceInputs::from_enclave_row -----------------------------------

    #[test]
    fn from_enclave_row_extracts_all_fields() {
        let enclave = serde_json::json!({
            "image_digest": "sha256:abc",
            "docker_image": "registry.local/alice/foo:v1",
            "pcrs": { "PCR0": "00", "PCR1": "11", "PCR2": "22" },
            "builder_rev": "bbb",
            "crates_rev": "ccc",
        });
        let inputs = ReproduceInputs::from_enclave_row(&enclave, "eid").unwrap();
        assert_eq!(inputs.image_digest, "sha256:abc");
        assert_eq!(inputs.docker_image, "registry.local/alice/foo:v1");
        assert_eq!(inputs.expected, triple("00", "11", "22"));
        assert_eq!(inputs.builder_rev.as_deref(), Some("bbb"));
        assert_eq!(inputs.crates_rev.as_deref(), Some("ccc"));
    }

    #[test]
    fn from_enclave_row_errors_without_digest() {
        let enclave = serde_json::json!({
            "docker_image": "registry.local/alice/foo:v1",
            "pcrs": { "PCR0": "00", "PCR1": "11", "PCR2": "22" },
        });
        let err = ReproduceInputs::from_enclave_row(&enclave, "eid").unwrap_err();
        assert!(err.to_string().contains("image_digest"), "got: {err}");
    }

    // -- ReproduceInputs::from_staged_upgrade --------------------------------

    fn staged(
        status: enclavia_protocol::staging::StagedUpgradeStatus,
        digest: Option<&str>,
        pcrs: Option<enclavia_protocol::chain::PcrsHex>,
        builder_rev: Option<&str>,
        crates_rev: Option<&str>,
    ) -> enclavia_protocol::staging::StagedUpgradeJson {
        enclavia_protocol::staging::StagedUpgradeJson {
            id: uuid::Uuid::nil(),
            enclave_id: uuid::Uuid::nil(),
            status,
            docker_image: "registry.local/alice/foo:v2".into(),
            image_digest: digest.map(|s| s.to_string()),
            pcrs,
            valid_from: None,
            upgrade_link_id: None,
            revocation_link_id: None,
            error_message: None,
            builder_rev: builder_rev.map(|s| s.to_string()),
            crates_rev: crates_rev.map(|s| s.to_string()),
            created_at: chrono::Utc::now(),
        }
    }

    fn pcrs_hex(p0: &str, p1: &str, p2: &str) -> enclavia_protocol::chain::PcrsHex {
        enclavia_protocol::chain::PcrsHex {
            pcr0: p0.into(),
            pcr1: p1.into(),
            pcr2: p2.into(),
        }
    }

    #[test]
    fn from_staged_upgrade_happy_path() {
        use enclavia_protocol::staging::StagedUpgradeStatus;
        let up = staged(
            StagedUpgradeStatus::Promoted,
            Some("sha256:def"),
            Some(pcrs_hex("aa", "bb", "cc")),
            Some("bbb"),
            Some("ccc"),
        );
        let inputs = ReproduceInputs::from_staged_upgrade(&up).unwrap();
        assert_eq!(inputs.image_digest, "sha256:def");
        assert_eq!(inputs.docker_image, "registry.local/alice/foo:v2");
        assert_eq!(inputs.expected, triple("aa", "bb", "cc"));
        assert_eq!(inputs.builder_rev.as_deref(), Some("bbb"));
        assert_eq!(inputs.crates_rev.as_deref(), Some("ccc"));
    }

    #[test]
    fn from_staged_upgrade_errors_when_build_incomplete() {
        use enclavia_protocol::staging::StagedUpgradeStatus;
        // No digest, no pcrs: build never finished.
        let up = staged(StagedUpgradeStatus::Building, None, None, None, None);
        let err = ReproduceInputs::from_staged_upgrade(&up).unwrap_err();
        assert!(err.to_string().contains("never completed"), "got: {err}");
    }

    #[test]
    fn from_staged_upgrade_errors_when_revs_missing() {
        use enclavia_protocol::staging::StagedUpgradeStatus;
        // Digest + PCRs present (build completed) but the revs are NULL:
        // this row predates per-version provenance.
        let up = staged(
            StagedUpgradeStatus::Staged,
            Some("sha256:def"),
            Some(pcrs_hex("aa", "bb", "cc")),
            None,
            None,
        );
        let err = ReproduceInputs::from_staged_upgrade(&up).unwrap_err();
        assert!(
            err.to_string().contains("per-version provenance"),
            "got: {err}"
        );

        // One of the two missing also fails.
        let up = staged(
            StagedUpgradeStatus::Staged,
            Some("sha256:def"),
            Some(pcrs_hex("aa", "bb", "cc")),
            Some("bbb"),
            None,
        );
        assert!(ReproduceInputs::from_staged_upgrade(&up).is_err());
    }
}
