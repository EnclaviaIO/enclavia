//! On-disk credentials for the CLI.
//!
//! When the CLI migrated from the bespoke `/auth/cli/*` device flow to
//! OAuth 2.1 + PKCE, the credential schema gained `refresh_token`,
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
    save_credentials_at(&config_dir(), &credentials_path(), creds)
}

/// [`save_credentials`] with explicit paths, so tests don't touch the
/// real config directory.
///
/// The file holds a live bearer token plus a ~30-day refresh token, so it
/// gets the same treatment as the YubiKey key index in `keys.rs`: created
/// `0600` via `OpenOptions::mode` (no chmod-after-write window) and
/// re-clamped to `0600` on every rewrite, since an existing file keeps
/// its creation-time mode. The containing directory is clamped to `0700`.
fn save_credentials_at(
    dir: &std::path::Path,
    path: &std::path::Path,
    creds: &Credentials,
) -> std::io::Result<()> {
    use std::io::Write as _;

    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let json = serde_json::to_string_pretty(creds).expect("serialize credentials");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(json.as_bytes())?;
    Ok(())
}

/// Load credentials, ignoring older single-token shapes from the
/// pre-OAuth device-flow era — those files don't have a refresh token, so
/// we'd just 401 silently after the access token expires. Treating them
/// as logged-out forces an explicit `enclavia auth login`.
pub fn load_credentials() -> Option<Credentials> {
    let path = credentials_path();
    // Files written before permission hardening may still be
    // world/group-readable from their default-umask creation; clamp them
    // on first touch. Best-effort: a failed chmod must not lock the user
    // out of credentials they can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
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

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn test_creds() -> Credentials {
        Credentials {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            expires_at: Utc::now(),
            backend_url: "http://localhost:3000".into(),
        }
    }

    /// The credentials file holds a bearer + refresh token: it must be
    /// created `0600` (and the directory `0700`) regardless of umask.
    #[cfg(unix)]
    #[test]
    fn credentials_are_written_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("enclavia");
        let path = dir.join("credentials.json");
        save_credentials_at(&dir, &path, &test_creds()).unwrap();
        assert_eq!(mode_of(&path), 0o600, "credentials file must be 0600");
        assert_eq!(mode_of(&dir), 0o700, "config dir must be 0700");
    }

    /// Rewriting an existing world-readable file (pre-hardening layout)
    /// must clamp it back to `0600`: `OpenOptions::mode` only applies at
    /// creation, so the writer re-applies permissions explicitly.
    #[cfg(unix)]
    #[test]
    fn rewrite_clamps_existing_permissive_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("enclavia");
        let path = dir.join("credentials.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_credentials_at(&dir, &path, &test_creds()).unwrap();
        assert_eq!(mode_of(&path), 0o600, "rewrite must clamp to 0600");
        // And the content actually round-trips.
        let back: Credentials =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back.access_token, "at");
    }
}
