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

    /// Anything else, formatted as a string. Most call sites still use
    /// `String` errors today; this keeps the migration small.
    #[error("{0}")]
    Other(String),
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
