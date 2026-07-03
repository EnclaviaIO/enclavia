//! Library-facing error type. The CLI binary still flattens these to a
//! single line via `Display`, so we keep `From<String>` ergonomic for the
//! `?` operator inside command modules — but downstream callers (the MCP
//! server) can match on the variant if they want richer surfacing.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    /// User isn't logged in / their token is missing.
    #[error("not logged in — run `enclavia auth login` first")]
    NotLoggedIn,

    /// Backend rejected our credentials.
    #[error("unauthorized — run `enclavia auth login` to re-authenticate")]
    Unauthorized,

    /// Backend returned 409 Conflict. Surfaced as its own variant so
    /// the self-hosted two-phase confirm/revoke flow (#48) can detect a
    /// stale-nonce dispatch failure and re-run prepare once.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Anything else, formatted as a string. Most call sites still use
    /// `String` errors today; this keeps the migration small.
    #[error("{0}")]
    Other(String),
}

impl CliError {
    /// Stable machine-readable discriminant for the `--json` error shape.
    /// Mirrors the variant; `Other` collapses to a generic `error` since it
    /// carries no further structure today.
    pub fn kind(&self) -> &'static str {
        match self {
            CliError::NotLoggedIn => "not_logged_in",
            CliError::Unauthorized => "unauthorized",
            CliError::Conflict(_) => "conflict",
            CliError::Other(_) => "error",
        }
    }

    /// Render this error as the single JSON object the CLI prints to stdout
    /// in `--json` mode: `{"error": <message>, "kind": <kind>}`. The
    /// `message` is the same `Display` string the human path prints to
    /// stderr, so the two surfaces never drift.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.to_string(),
            "kind": self.kind(),
        })
    }
}

impl From<String> for CliError {
    fn from(s: String) -> Self {
        CliError::Other(s)
    }
}

impl From<&str> for CliError {
    fn from(s: &str) -> Self {
        CliError::Other(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_carries_message_and_kind() {
        let v = CliError::NotLoggedIn.to_json();
        assert_eq!(v["kind"], "not_logged_in");
        assert!(v["error"].as_str().unwrap().contains("not logged in"));

        let v = CliError::Unauthorized.to_json();
        assert_eq!(v["kind"], "unauthorized");

        let v = CliError::Other("boom".into()).to_json();
        assert_eq!(v["kind"], "error");
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn to_json_is_a_single_object_with_exactly_two_keys() {
        let v = CliError::Other("x".into()).to_json();
        let obj = v.as_object().expect("error json is an object");
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("error"));
        assert!(obj.contains_key("kind"));
    }
}
