//! On-disk credentials for the CLI (#88).
//!
//! When the CLI migrated from the bespoke `/auth/cli/*` device flow to
//! OAuth 2.1 + PKCE (#88), the credential schema gained `refresh_token`,
//! `expires_at`, and the backend URL the credentials were minted against.
//! Old single-`token` files from the device-flow era no longer carry
//! enough information to refresh, so we treat them as logged-out — the
//! user runs `enclavia auth login` and we overwrite with the new shape.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Credentials stored at `~/.config/enclavia/credentials.json` (or the
/// platform equivalent).
///
/// Persisted across CLI invocations so the user only logs in once. The
/// access token is short-lived (1h, mirroring the backend's JWT TTL) and
/// the refresh token is rotated on every use, so a leak of the
/// credentials file is mitigated to a 30-day window in the worst case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// Backend `/oauth/token` JWT. Sent as `Authorization: Bearer …` on
    /// every API call.
    pub access_token: String,
    /// OAuth refresh token. Used to mint a new `(access, refresh)` pair
    /// when the access token 401s.
    pub refresh_token: String,
    /// When the access token expires. Used by the API client to refresh
    /// proactively rather than only on 401.
    pub expires_at: DateTime<Utc>,
    /// Backend the tokens were minted against (e.g. `http://localhost:3000`
    /// in dev, `https://api.beta.enclavia.io` in prod). Persisted so we
    /// don't accidentally send a token to a different backend after the
    /// user changes `ENCLAVIA_BACKEND_URL` between commands.
    pub backend_url: String,
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .expect("could not determine config directory")
        .join("enclavia")
}

pub fn credentials_path() -> PathBuf {
    config_dir().join("credentials.json")
}

pub fn save_credentials(creds: &Credentials) -> std::io::Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(creds).expect("serialize credentials");
    std::fs::write(credentials_path(), json)?;
    Ok(())
}

/// Load credentials, ignoring older single-token shapes from the
/// pre-#88 device-flow era — those files don't have a refresh token, so
/// we'd just 401 silently after the access token expires. Treating them
/// as logged-out forces an explicit `enclavia auth login`.
pub fn load_credentials() -> Option<Credentials> {
    let path = credentials_path();
    let data = std::fs::read_to_string(path).ok()?;
    // Strict parse: missing fields → returns None → CLI prompts to login.
    serde_json::from_str(&data).ok()
}

pub fn backend_url() -> String {
    std::env::var("ENCLAVIA_BACKEND_URL")
        .unwrap_or_else(|_| "https://api.beta.enclavia.io".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Old credentials (single `token` field) must NOT deserialize into the
    /// new shape — the user gets logged-out and re-runs `auth login` to
    /// pick up a refresh token.
    #[test]
    fn legacy_credentials_are_treated_as_logged_out() {
        let legacy = serde_json::json!({"token": "abc"}).to_string();
        let parsed: Result<Credentials, _> = serde_json::from_str(&legacy);
        assert!(parsed.is_err(), "legacy schema must not deserialize");
    }

    #[test]
    fn round_trip_preserves_fields() {
        let creds = Credentials {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            expires_at: Utc::now(),
            backend_url: "http://localhost:3000".into(),
        };
        let s = serde_json::to_string(&creds).unwrap();
        let back: Credentials = serde_json::from_str(&s).unwrap();
        assert_eq!(back.access_token, "at");
        assert_eq!(back.refresh_token, "rt");
        assert_eq!(back.backend_url, "http://localhost:3000");
    }
}
