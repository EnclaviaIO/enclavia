//! Library face of the `enclavia` CLI.
//!
//! Splitting the CLI into a lib + thin binary lets other Rust components
//! (currently `enclavia-mcp`) reuse the typed REST client and command
//! orchestration without taking a dependency on clap or the on-disk
//! credentials cache.
//!
//! Modules:
//! - [`api`] — typed `reqwest` client over the backend REST surface.
//! - [`config`] — credentials cache and `ENCLAVIA_BACKEND_URL` resolution
//!   (only the binary should call into the on-disk parts).
//! - [`commands`] — high-level orchestrators that combine `api` calls and
//!   return typed results. Presentation lives in `bin/enclavia/main.rs`.
//! - [`error`] — shared error type used by the lib surface.

pub mod api;
pub mod commands;
pub mod config;
pub mod error;

pub use api::ApiClient;
pub use error::CliError;

/// Instance type selector. Mirrors the backend's `InstanceType` enum and
/// is reused by the MCP server's tool schema. The CLI binary keeps its
/// own clap-aware mirror so the lib doesn't have to depend on clap.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceTypeArg {
    Small,
    Medium,
    Large,
}
