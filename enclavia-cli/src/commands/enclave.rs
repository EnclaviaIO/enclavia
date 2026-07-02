//! Enclave-management commands.
//!
//! Each function returns a typed result. The CLI binary wraps these in
//! human-readable output; the MCP server hands the same structs straight
//! back to the model as JSON.

use serde::Serialize;

use crate::api::{ApiClient, EnclaveSummary};
use crate::error::CliError;

/// Result of `enclave create`. `next_step` carries the same hint the CLI
/// used to print after creation, so MCP clients can surface it too.
#[derive(Debug, Clone, Serialize)]
pub struct EnclaveCreated {
    pub id: String,
    pub status: String,
    /// Human-readable hint describing what to do next ("push the image"
    /// vs "wait for the build").
    pub next_step: String,
    /// Full backend response, for callers that want fields we don't model.
    pub raw: serde_json::Value,
}

/// Egress allowlist inputs collected from the CLI flags. The three
/// shapes are mutually exclusive — see [`build_egress_allowlist`].
#[derive(Debug, Default, Clone)]
pub struct EgressInputs {
    /// `--egress-allow HOST:PORT[/PROTO]`, repeatable.
    pub allows: Vec<String>,
    /// `--egress-resolver IP`, repeatable.
    pub resolvers: Vec<String>,
    /// `--egress-config <path>` to a pre-written JSON file.
    pub config_path: Option<std::path::PathBuf>,
}

impl EgressInputs {
    fn is_empty(&self) -> bool {
        self.allows.is_empty() && self.resolvers.is_empty() && self.config_path.is_none()
    }

    fn has_flags(&self) -> bool {
        !self.allows.is_empty() || !self.resolvers.is_empty()
    }
}

/// Resolve the three CLI shapes into a single JSON document, or `None`
/// when the user passed no egress flags at all. Flag-form and file-form
/// are mutually exclusive — combining them would just be confusing,
/// and the wire format is the same either way.
pub fn build_egress_allowlist(
    inputs: &EgressInputs,
) -> Result<Option<serde_json::Value>, CliError> {
    if inputs.is_empty() {
        return Ok(None);
    }
    if inputs.config_path.is_some() && inputs.has_flags() {
        return Err(CliError::Other(
            "--egress-config is mutually exclusive with --egress-allow / --egress-resolver"
                .into(),
        ));
    }
    if let Some(path) = &inputs.config_path {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::Other(format!("reading {}: {e}", path.display())))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::Other(format!("parsing {} as JSON: {e}", path.display()))
        })?;
        enclavia_egress::validate_json(&value)
            .map_err(|e| CliError::Other(format!("invalid egress allowlist: {e}")))?;
        return Ok(Some(value));
    }
    let allow_refs: Vec<&str> = inputs.allows.iter().map(String::as_str).collect();
    let resolver_refs: Vec<&str> = inputs.resolvers.iter().map(String::as_str).collect();
    let raw = enclavia_egress::assemble_from_cli(&allow_refs, &resolver_refs)
        .map_err(|e| CliError::Other(format!("invalid egress flags: {e}")))?;
    let value = serde_json::to_value(&raw)
        .map_err(|e| CliError::Other(format!("serialising allowlist: {e}")))?;
    Ok(Some(value))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &ApiClient,
    instance_type: crate::InstanceTypeArg,
    container_port: Option<u16>,
    storage_size_bytes: Option<u64>,
    name: Option<&str>,
    visibility: Option<&str>,
    egress_allowlist: Option<serde_json::Value>,
    upgradable: bool,
    production: bool,
    anti_rollback: bool,
) -> Result<EnclaveCreated, CliError> {
    let enclave = client
        .create_enclave(
            instance_type,
            container_port,
            storage_size_bytes,
            name,
            visibility,
            egress_allowlist.as_ref(),
            upgradable,
            production,
            anti_rollback,
        )
        .await?;

    let id = enclave["id"].as_str().unwrap_or("unknown").to_string();
    let status = enclave["status"].as_str().unwrap_or("unknown").to_string();
    // Every successful create lands the enclave in `waiting_for_image`. The
    // build is gated on a fresh push to this enclave's repo (#82.4 / #97),
    // so the next step is always "push to start". Under per-enclave repos
    // (#46 phase 2) the destination is the enclave id itself — we surface
    // an id-prefix that's unambiguous in the user's namespace today.
    let prefix = id.get(..8).unwrap_or(&id);
    let next_step = format!(
        "Push your image to start the build:\n  enclavia push <local-image> {prefix}\n\n\
         Check status with `enclavia enclave status {id}`."
    );

    Ok(EnclaveCreated { id, status, next_step, raw: enclave })
}

pub async fn list(
    client: &ApiClient,
    include_archived: bool,
) -> Result<Vec<EnclaveSummary>, CliError> {
    client.list_enclaves(include_archived).await
}

pub async fn status(client: &ApiClient, id: &str) -> Result<serde_json::Value, CliError> {
    client.get_enclave(id).await
}

pub async fn logs(client: &ApiClient, id: &str) -> Result<serde_json::Value, CliError> {
    client.get_enclave_logs(id).await
}

pub async fn stop(client: &ApiClient, id: &str) -> Result<(), CliError> {
    client.stop_enclave(id).await
}

pub async fn start(client: &ApiClient, id: &str) -> Result<(), CliError> {
    client.start_enclave(id).await
}

pub async fn destroy(client: &ApiClient, id: &str) -> Result<(), CliError> {
    client.destroy_enclave(id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_egress_allowlist_returns_none_when_empty() {
        let out = build_egress_allowlist(&EgressInputs::default()).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn build_egress_allowlist_assembles_from_flags() {
        let inputs = EgressInputs {
            allows: vec!["1.2.3.4:443".into(), "api.example.com:443/tcp".into()],
            resolvers: vec!["1.1.1.1".into()],
            config_path: None,
        };
        let out = build_egress_allowlist(&inputs).unwrap().expect("present");
        assert_eq!(out["version"], 1);
        assert_eq!(out["resolvers"][0], "1.1.1.1");
        assert_eq!(out["egress"][0]["host"], "1.2.3.4");
        assert_eq!(out["egress"][1]["host"], "api.example.com");
    }

    #[test]
    fn build_egress_allowlist_rejects_mixed_flag_and_config() {
        let inputs = EgressInputs {
            allows: vec!["1.2.3.4:443".into()],
            resolvers: vec![],
            config_path: Some(std::path::PathBuf::from("/dev/null")),
        };
        assert!(build_egress_allowlist(&inputs).is_err());
    }

    #[test]
    fn build_egress_allowlist_surfaces_parse_error() {
        let inputs = EgressInputs {
            allows: vec!["bogus".into()],
            resolvers: vec![],
            config_path: None,
        };
        assert!(build_egress_allowlist(&inputs).is_err());
    }
}
