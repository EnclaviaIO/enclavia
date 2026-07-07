//! Shared enclave-id resolution. Every command that takes an enclave id
//! accepts either a full UUID or a unique prefix of one, so users can
//! paste the short id printed by `enclave create` without looking up the
//! full UUID. This used to live as private copies in `push` and
//! `reproduce`; the other commands passed the raw string through to
//! backend routes that only parse full UUIDs.

use crate::api::{ApiClient, EnclaveSummary};
use crate::error::CliError;

/// Resolve a user-supplied id or unique prefix to exactly one enclave.
///
/// A full UUID short-circuits the listing — there is nothing to
/// disambiguate, and skipping `list_enclaves` keeps unauthenticated paths
/// (anonymous `reproduce` of a public enclave, `upgrade chain`) off the
/// authenticated list endpoint. The returned summary then carries only
/// the id; callers that need other row fields must fetch them.
///
/// Prefixes resolve against the caller's own enclaves, archived included,
/// so operating on a just-destroyed enclave yields the backend's clear
/// "destroyed" error rather than a confusing "no match" here. Two
/// terminal failures are distinguished: no match, and an ambiguous prefix
/// (the candidates are listed so the user can disambiguate without
/// re-running `enclave list`).
pub async fn resolve_enclave(
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
    match_prefix(all, id_or_prefix)
}

/// Convenience wrapper for the (many) callers that only need the id.
pub async fn resolve_enclave_id(
    client: &ApiClient,
    id_or_prefix: &str,
) -> Result<String, CliError> {
    Ok(resolve_enclave(client, id_or_prefix).await?.id)
}

/// The pure matching step, split out so it can be unit-tested without an
/// `ApiClient`.
fn match_prefix(
    all: Vec<EnclaveSummary>,
    id_or_prefix: &str,
) -> Result<EnclaveSummary, CliError> {
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

    fn summary(id: &str, name: Option<&str>) -> EnclaveSummary {
        EnclaveSummary {
            id: id.to_string(),
            name: name.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn unique_prefix_resolves() {
        let all = vec![
            summary("1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d", Some("api")),
            summary("9f8e7d6c-5b4a-3210-fedc-ba9876543210", None),
        ];
        let hit = match_prefix(all, "1d2c").unwrap();
        assert_eq!(hit.id, "1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d");
    }

    #[test]
    fn no_match_is_a_clear_error() {
        let all = vec![summary("1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d", None)];
        let err = match_prefix(all, "ffff").unwrap_err().to_string();
        assert!(err.contains("no enclave matches"), "{err}");
    }

    #[test]
    fn ambiguous_prefix_lists_candidates() {
        let all = vec![
            summary("1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d", Some("api")),
            summary("1d2cffff-0000-1111-2222-333344445555", None),
        ];
        let err = match_prefix(all, "1d2c").unwrap_err().to_string();
        assert!(err.contains("matches 2 enclaves"), "{err}");
        assert!(err.contains("1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d (api)"), "{err}");
        assert!(err.contains("1d2cffff-0000-1111-2222-333344445555 (-)"), "{err}");
    }
}
