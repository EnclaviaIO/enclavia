//! `enclavia secret` subcommands.
//!
//! Per-enclave environment-variable secrets. Encryption + storage lives
//! in the backend; the CLI is a thin REST client plus client-side input
//! parsing and a name-validation pre-check so users get a fast,
//! consistent error message before the request hits the wire.
//!
//! The validation rules mirror `enclavia-backend`'s
//! `services::secrets::validate_name` exactly. The backend re-runs the
//! same checks so this is a UX optimisation, never the security boundary.

use serde::{Deserialize, Serialize};

use crate::api::ApiClient;
use crate::error::CliError;

/// Hard cap on a secret name's length. Mirrors the backend constant in
/// `enclavia-backend/src/services/secrets.rs`.
pub const NAME_MAX_LEN: usize = 64;

/// Names blocked because they collide with the runtime-injected
/// environment inside the OCI bundle. Mirrors `RESERVED_NAMES` in the
/// backend; keep in sync.
pub const RESERVED_NAMES: &[&str] = &[
    "PATH", "HOME", "HOSTNAME", "PWD", "OLDPWD", "TERM", "SHLVL", "_",
];

/// Validate a candidate secret name. Same rules as the backend
/// (`^[A-Z_][A-Z0-9_]*$`, max 64 chars, no `__` prefix, no reserved
/// runtime names). Returned errors are surfaced verbatim to the user.
pub fn validate_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(CliError::Other("secret name must not be empty".into()));
    }
    if name.len() > NAME_MAX_LEN {
        return Err(CliError::Other(format!(
            "secret name must be at most {NAME_MAX_LEN} characters"
        )));
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_ascii_uppercase() || first == '_') {
        return Err(CliError::Other(
            "secret name must start with A-Z or '_'".into(),
        ));
    }
    for c in chars {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(CliError::Other(format!(
                "secret name must match ^[A-Z_][A-Z0-9_]*$ (offending char: {c:?})"
            )));
        }
    }
    if name.starts_with("__") {
        return Err(CliError::Other(
            "secret names starting with '__' are reserved".into(),
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(CliError::Other(format!(
            "secret name '{name}' is reserved (runtime-set)"
        )));
    }
    Ok(())
}

/// Parse a `NAME=VALUE` pair. The first `=` is the separator so values
/// may contain `=` themselves. Empty values are accepted (`NAME=`).
pub fn parse_name_value(input: &str) -> Result<(String, String), CliError> {
    let (name, value) = input.split_once('=').ok_or_else(|| {
        CliError::Other(format!("expected NAME=VALUE, got {input:?}"))
    })?;
    validate_name(name)?;
    Ok((name.to_string(), value.to_string()))
}

/// Backend `SecretSummary` row, mirrored for `secret list`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    /// `true` when the value was written/rotated after the most recent
    /// successful enclave start. Surfaces in the `list` view as a hint
    /// that the running enclave is still seeing the previous value.
    pub pending: bool,
}

/// `enclavia secret set`: create-or-rotate. The backend's REST surface
/// splits these into POST (create) and PUT (rotate); we figure out
/// which by listing first and matching by name. Repeated names in a
/// single invocation just rotate to the last-passed value.
pub async fn set(
    client: &ApiClient,
    enclave_id: &str,
    pairs: Vec<(String, String)>,
) -> Result<usize, CliError> {
    // Snapshot existing names so we can choose POST vs PUT per entry.
    let existing = client.list_secrets(enclave_id).await?;
    let mut existing_names: std::collections::HashSet<String> =
        existing.into_iter().map(|s| s.name).collect();

    let mut updated = 0usize;
    for (name, value) in pairs {
        if existing_names.contains(&name) {
            client.update_secret(enclave_id, &name, &value).await?;
        } else {
            client.create_secret(enclave_id, &name, &value).await?;
            existing_names.insert(name.clone());
        }
        updated += 1;
    }
    Ok(updated)
}

/// `enclavia secret list`.
pub async fn list(
    client: &ApiClient,
    enclave_id: &str,
) -> Result<Vec<SecretSummary>, CliError> {
    client.list_secrets(enclave_id).await
}

/// `enclavia secret delete`: removes each named secret. Returns the
/// number of successful deletes; callers decide what to do with that
/// count (the binary prints the "N change(s) pending" hint).
pub async fn delete(
    client: &ApiClient,
    enclave_id: &str,
    names: &[String],
) -> Result<usize, CliError> {
    let mut removed = 0usize;
    for n in names {
        validate_name(n)?;
        client.delete_secret(enclave_id, n).await?;
        removed += 1;
    }
    Ok(removed)
}

/// `enclavia enclave restart`: server-side stop + start.
pub async fn restart(client: &ApiClient, enclave_id: &str) -> Result<(), CliError> {
    client.restart_enclave(enclave_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_uppercase() {
        validate_name("FOO").unwrap();
        validate_name("API_KEY_2").unwrap();
        validate_name("_LEADING_UNDERSCORE").unwrap();
    }

    #[test]
    fn validate_name_rejects_lowercase() {
        assert!(validate_name("foo").is_err());
        assert!(validate_name("FoO").is_err());
    }

    #[test]
    fn validate_name_rejects_double_underscore_prefix() {
        assert!(validate_name("__SECRET").is_err());
    }

    #[test]
    fn validate_name_rejects_reserved() {
        assert!(validate_name("PATH").is_err());
        assert!(validate_name("HOME").is_err());
        assert!(validate_name("_").is_err());
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn validate_name_rejects_too_long() {
        let n = "A".repeat(NAME_MAX_LEN + 1);
        assert!(validate_name(&n).is_err());
    }

    #[test]
    fn parse_name_value_simple() {
        let (n, v) = parse_name_value("FOO=bar").unwrap();
        assert_eq!(n, "FOO");
        assert_eq!(v, "bar");
    }

    #[test]
    fn parse_name_value_allows_equals_in_value() {
        let (n, v) = parse_name_value("FOO=a=b=c").unwrap();
        assert_eq!(n, "FOO");
        assert_eq!(v, "a=b=c");
    }

    #[test]
    fn parse_name_value_allows_empty_value() {
        let (n, v) = parse_name_value("FOO=").unwrap();
        assert_eq!(n, "FOO");
        assert_eq!(v, "");
    }

    #[test]
    fn parse_name_value_rejects_missing_equals() {
        assert!(parse_name_value("FOO").is_err());
    }

    #[test]
    fn parse_name_value_validates_name() {
        assert!(parse_name_value("foo=bar").is_err());
        assert!(parse_name_value("PATH=bar").is_err());
    }
}
