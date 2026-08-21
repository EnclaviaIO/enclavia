//! `enclavia build <image>` — build a Docker image into an enclave EIF
//! locally, without touching the backend. The intended home for this is a
//! customer's CI pipeline (hence the `ci` alias): after `docker build`,
//! run `enclavia build myapp:candidate` and fail the pipeline if the
//! image can't be turned into an EIF, before anything is pushed or
//! deployed.
//!
//! Like `reproduce`, this does not re-implement the build: it shells out
//! to the same `builder` binary the backend uses (BUILDER_PATH env var,
//! falling back to `builder` on `$PATH`). Unlike `reproduce` there is no
//! recorded row to mirror, so the flags are the user's own (port,
//! storage, debug, egress policy) and no PCR comparison happens — the
//! deliverable is "the build succeeds" plus the EIF and its PCRs.
//!
//! The image is read from the local Docker daemon by default
//! (`docker-daemon:` skopeo transport), which is what a CI job has right
//! after `docker build`. Pass `--pull` to fetch a registry reference
//! instead, or give an explicit skopeo transport (`docker-archive:...`,
//! `oci:...`) to build from a tarball / OCI layout without a daemon.

use std::path::PathBuf;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::commands::reproduce::PcrTriple;
use crate::error::CliError;

/// Skopeo transports we forward verbatim when the user names one
/// explicitly. Everything else is treated as a plain image reference and
/// resolved via the daemon (default) or a registry (`--pull`).
const EXPLICIT_TRANSPORTS: &[&str] = &[
    "docker://",
    "docker-daemon:",
    "docker-archive:",
    "oci:",
    "oci-archive:",
    "containers-storage:",
];

/// Inputs for one local build, resolved from the CLI flags.
#[derive(Debug)]
pub struct BuildArgs {
    /// Image reference as the user typed it.
    pub image: String,
    /// Treat `image` as a registry reference and pull it, instead of
    /// reading it from the local Docker daemon.
    pub pull: bool,
    /// Directory the builder writes `image.eif` + `pcr.json` into.
    pub output_dir: PathBuf,
    /// Port the container listens on inside the enclave.
    pub container_port: u16,
    /// Build the debug-mode EIF (QEMU-bootable, attestation marked debug).
    pub debug: bool,
    /// Build the storage-capable variant (LUKS+btrfs over NBD).
    pub storage: bool,
    /// Egress allowlist document, already assembled/validated by
    /// [`crate::commands::enclave::build_egress_allowlist`]. `None`
    /// mirrors the backend's default: the empty deny-all document is
    /// baked in, exactly as a create with no egress flags would.
    pub egress_allowlist: Option<serde_json::Value>,
}

/// Result of `enclavia build`. The binary prints it; MCP or other lib
/// callers can consume the struct directly.
#[derive(Debug, Clone, Serialize)]
pub struct BuildOutput {
    /// The skopeo source reference the builder was handed (after
    /// daemon/registry/transport resolution) — useful in CI logs to see
    /// exactly what got built.
    pub source: String,
    /// Path of the EIF the builder wrote.
    pub eif_path: PathBuf,
    /// Build-time PCR measurements of the EIF.
    pub pcrs: PcrTriple,
}

/// Resolve the user's image reference into the skopeo source reference
/// the builder should pull from.
fn source_reference(image: &str, pull: bool) -> String {
    if EXPLICIT_TRANSPORTS.iter().any(|t| image.starts_with(t)) {
        return image.to_string();
    }
    if pull {
        return format!("docker://{image}");
    }
    // The docker-daemon transport requires an explicit tag (or digest);
    // mirror docker's own `:latest` default for a bare name.
    let name_and_tag = image.split_once('@').map_or(image, |(name, _)| name);
    let has_tag = match (name_and_tag.rfind(':'), name_and_tag.rfind('/')) {
        (Some(colon), Some(slash)) => colon > slash,
        (Some(_), None) => true,
        _ => false,
    };
    if image.contains('@') || has_tag {
        format!("docker-daemon:{image}")
    } else {
        format!("docker-daemon:{image}:latest")
    }
}

/// Run the local builder and parse its result. Errors carry enough
/// context to act on in a CI log (missing builder binary, non-zero exit,
/// unparseable output).
pub async fn build(args: BuildArgs) -> Result<BuildOutput, CliError> {
    let builder_path = std::env::var("BUILDER_PATH").unwrap_or_else(|_| "builder".to_string());
    let source = source_reference(&args.image, args.pull);

    std::fs::create_dir_all(&args.output_dir)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", args.output_dir.display())))?;

    // Always bake an egress document, like the backend does: an enclave
    // created with no egress flags gets the empty deny-all doc, not an
    // EIF with the egress stack omitted. Local builds mirror that so the
    // artifact matches what a deploy of the same image would produce.
    let egress_doc = args.egress_allowlist.unwrap_or_else(|| {
        serde_json::json!({"version": 1, "resolvers": [], "egress": []})
    });
    let egress_path = args.output_dir.join("egress.json");
    let serialized = serde_json::to_vec_pretty(&egress_doc)
        .map_err(|e| CliError::Other(format!("serialising allowlist: {e}")))?;
    std::fs::write(&egress_path, serialized)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", egress_path.display())))?;

    let mut cmd = Command::new(&builder_path);
    cmd.arg("build")
        .arg("--image")
        .arg(&source)
        .arg("--output-dir")
        .arg(&args.output_dir)
        .arg("--container-port")
        .arg(args.container_port.to_string())
        .arg("--egress-allowlist")
        .arg(&egress_path);
    if args.debug {
        cmd.arg("--debug");
    }
    if args.storage {
        cmd.arg("--storage");
    }

    eprintln!("Building {source} into an EIF …");
    eprintln!("  output: {}", args.output_dir.display());

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| CliError::Other(format!(
            "failed to spawn builder ({builder_path:?}): {e}. Install it (e.g. `nix profile install github:EnclaviaIO/builder`) or set BUILDER_PATH to point at a `builder` binary."
        )))?
        .wait_with_output()
        .await
        .map_err(|e| CliError::Other(format!("builder I/O error: {e}")))?;

    if !output.status.success() {
        return Err(CliError::Other(format!(
            "builder exited with {}: the image could not be built into an EIF (see the log above)",
            output.status,
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (eif_path, pcrs) = parse_builder_output(stdout.trim()).map_err(|e| {
        CliError::Other(format!(
            "couldn't parse builder output: {e}\n--- builder stdout ---\n{stdout}\n--- end ---"
        ))
    })?;

    Ok(BuildOutput { source, eif_path, pcrs })
}

/// The builder writes a JSON line on stdout with `eif_path` and `pcrs`.
/// Tolerate stray log lines by scanning for the last line that parses.
fn parse_builder_output(stdout: &str) -> Result<(PathBuf, PcrTriple), String> {
    #[derive(Deserialize)]
    struct BuildResult {
        eif_path: PathBuf,
        pcrs: PcrTriple,
    }

    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("builder produced no stdout".into());
    }

    if let Ok(parsed) = serde_json::from_str::<BuildResult>(trimmed) {
        return Ok((parsed.eif_path, parsed.pcrs));
    }

    for line in trimmed.lines().rev() {
        if let Ok(parsed) = serde_json::from_str::<BuildResult>(line.trim()) {
            return Ok((parsed.eif_path, parsed.pcrs));
        }
    }
    Err("no JSON line in builder stdout matched `{ eif_path, pcrs: { PCR0, PCR1, PCR2 } }`".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_ref_gets_latest_tag_when_bare() {
        assert_eq!(source_reference("myapp", false), "docker-daemon:myapp:latest");
        assert_eq!(
            source_reference("ghcr.io/acme/myapp", false),
            "docker-daemon:ghcr.io/acme/myapp:latest"
        );
    }

    #[test]
    fn daemon_ref_keeps_existing_tag_or_digest() {
        assert_eq!(source_reference("myapp:dev", false), "docker-daemon:myapp:dev");
        assert_eq!(
            source_reference("localhost:5000/myapp", false),
            // Port colon is not a tag: `:latest` is still appended.
            "docker-daemon:localhost:5000/myapp:latest"
        );
        assert_eq!(
            source_reference("myapp@sha256:abcd", false),
            "docker-daemon:myapp@sha256:abcd"
        );
    }

    #[test]
    fn pull_flag_selects_registry_transport() {
        assert_eq!(source_reference("myapp:dev", true), "docker://myapp:dev");
    }

    #[test]
    fn explicit_transport_passes_through() {
        assert_eq!(
            source_reference("docker-archive:/tmp/img.tar", false),
            "docker-archive:/tmp/img.tar"
        );
        assert_eq!(
            source_reference("oci:/tmp/layout:latest", true),
            "oci:/tmp/layout:latest"
        );
    }

    #[test]
    fn parses_builder_stdout_with_noise() {
        let out = "some log line\n{\"eif_path\":\"/out/image.eif\",\"pcrs\":{\"PCR0\":\"a\",\"PCR1\":\"b\",\"PCR2\":\"c\"}}";
        let (path, pcrs) = parse_builder_output(out).unwrap();
        assert_eq!(path, PathBuf::from("/out/image.eif"));
        assert_eq!(pcrs.pcr0, "a");
    }
}
