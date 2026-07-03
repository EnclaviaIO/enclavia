//! CLI OAuth 2.1 + PKCE login.
//!
//! `enclavia auth login` runs the standard OAuth code-grant flow against
//! the backend's `/oauth/authorize` + `/oauth/token` endpoints, with three
//! native-app conventions on top:
//!
//!   * The CLI binds an ephemeral loopback HTTP listener (RFC 8252 §7.3)
//!     and uses `http://127.0.0.1:<port>/cb` as its redirect URI. The
//!     backend treats the `enclavia-cli` client's registered URIs as
//!     port-agnostic, so we don't have to pre-register every possible
//!     port.
//!   * PKCE S256 verifier/challenge generated locally — no client secret.
//!   * `client_id=enclavia-cli` is seeded by migration 0006 with
//!     `trusted=true`, so the consent screen is bypassed (the user is
//!     already on their own machine — they've consented).
//!
//! The flow:
//!   1. Generate verifier + challenge, bind a TcpListener on 127.0.0.1:0.
//!   2. Open a browser to `/oauth/authorize?…&redirect_uri=…`.
//!   3. The user authenticates on the backend (cookie skip when present),
//!      backend 302s to our loopback URL with `?code=…`.
//!   4. We POST `/oauth/token` with the code + verifier, get an
//!      `(access_token, refresh_token)` pair, persist both to the
//!      credentials cache.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::{self, Credentials};
use crate::error::CliError;

/// First-party OAuth client_id, seeded into `oauth_clients` by migration
/// 0006. Marked `trusted=true` so the consent screen is bypassed.
const CLIENT_ID: &str = "enclavia-cli";

/// Hard timeout on the whole login flow. Generous because the user might
/// switch tabs, sign in to GitHub, hunt down a TOTP, etc.
const LOGIN_TIMEOUT: StdDuration = StdDuration::from_secs(5 * 60);

/// Outcome of `start_login` — used by the CLI binary to print the URL and
/// kick off the wait. Library callers can also drive the flow by calling
/// `wait_for_token` themselves.
pub struct PendingLogin {
    pub approval_url: String,
    /// State + verifier + listener live on the pending struct so the
    /// caller can `.wait_for_token().await` once they've shown the URL to
    /// the user.
    state_token: String,
    pkce_verifier: String,
    redirect_uri: String,
    backend: String,
    listener: TcpListener,
}

/// Initiate a CLI OAuth login. Binds a loopback listener, computes a
/// fresh PKCE verifier/challenge pair, and returns the URL to point the
/// user's browser at.
pub async fn start_login() -> Result<PendingLogin, CliError> {
    let backend = config::backend_url();

    // Bind ephemeral port. RFC 8252 §7.3 explicitly recommends this for
    // native CLI apps; the backend's redirect_uri matcher is
    // port-agnostic for loopback URIs.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| CliError::Other(format!("failed to bind loopback listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| CliError::Other(format!("failed to read listener addr: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/cb");

    let pkce_verifier = generate_verifier();
    let pkce_challenge = challenge_for(&pkce_verifier);
    // Opaque state — protects against the rare case of two concurrent
    // CLI logins on the same machine racing for the loopback port.
    let state_token = generate_token();

    let approval_url = format!(
        "{backend}/oauth/authorize?response_type=code&client_id={cid}&redirect_uri={r}&code_challenge={c}&code_challenge_method=S256&state={s}",
        backend = backend.trim_end_matches('/'),
        cid = urlencoding_encode(CLIENT_ID),
        r = urlencoding_encode(&redirect_uri),
        c = pkce_challenge,
        s = state_token,
    );

    Ok(PendingLogin {
        approval_url,
        state_token,
        pkce_verifier,
        redirect_uri,
        backend,
        listener,
    })
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

impl PendingLogin {
    /// Wait for the browser to hit our loopback callback, then exchange
    /// the code for an access token. Persists credentials on success.
    pub async fn wait_for_token(self) -> Result<String, CliError> {
        let PendingLogin {
            state_token,
            pkce_verifier,
            redirect_uri,
            backend,
            listener,
            ..
        } = self;

        // The callback handler shoves the parsed query into a oneshot.
        // The handler can't return its result up the call stack because
        // axum owns it — the channel is the bridge.
        let (tx, rx) = oneshot::channel::<CallbackQuery>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let app: Router = Router::new()
            .route("/cb", get(handle_callback))
            .with_state(tx);

        // Run the loopback server until either:
        //   - the callback fires and we have a code (or error), OR
        //   - the overall timeout trips.
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });

        let cb = tokio::time::timeout(LOGIN_TIMEOUT, rx)
            .await
            .map_err(|_| {
                CliError::Other(
                    "timed out waiting for browser. Run `enclavia auth login` to try again."
                        .into(),
                )
            })?
            .map_err(|_| CliError::Other("loopback callback channel dropped".into()))?;

        // Tear down the server now that we've got the data.
        server.abort();

        if let Some(error) = cb.error.as_deref() {
            let desc = cb.error_description.as_deref().unwrap_or("");
            return Err(CliError::Other(format!(
                "authorization failed: {error}{}",
                if desc.is_empty() {
                    String::new()
                } else {
                    format!(" — {desc}")
                }
            )));
        }
        if cb.state.as_deref() != Some(state_token.as_str()) {
            return Err(CliError::Other(
                "authorization failed: state parameter mismatch".into(),
            ));
        }
        let code = cb.code.ok_or_else(|| {
            CliError::Other("authorization failed: no code in callback".into())
        })?;

        let token = exchange_code(&backend, &code, &redirect_uri, &pkce_verifier).await?;

        let creds = Credentials {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token,
            expires_at: Utc::now() + Duration::seconds(token.expires_in),
            backend_url: backend.clone(),
        };
        config::save_credentials(&creds)
            .map_err(|e| CliError::Other(format!("failed to save credentials: {e}")))?;

        Ok(token.access_token)
    }
}

async fn handle_callback(
    State(tx): State<Arc<tokio::sync::Mutex<Option<oneshot::Sender<CallbackQuery>>>>>,
    Query(q): Query<CallbackQuery>,
) -> Html<&'static str> {
    let mut guard = tx.lock().await;
    if let Some(sender) = guard.take() {
        let _ = sender.send(q);
    }
    Html(SUCCESS_PAGE)
}

const SUCCESS_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorized</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; color: #111;">
<h1>You're signed in.</h1>
<p>You can close this tab and return to the terminal.</p>
</body>
</html>"#;

/// POST `/oauth/token` to exchange the auth code for an access + refresh
/// token. Public function so the API client can also call it on
/// `refresh_token` rotation.
async fn exchange_code(
    backend: &str,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<TokenResponse, CliError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/oauth/token", backend.trim_end_matches('/')))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", pkce_verifier),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|e| CliError::Other(format!("token request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::Other(format!(
            "token request failed ({status}): {body}"
        )));
    }
    resp.json::<TokenResponse>()
        .await
        .map_err(|e| CliError::Other(format!("invalid token response: {e}")))
}

/// Public refresh helper used by the api client when a 401 hits.
pub async fn refresh_credentials(creds: &Credentials) -> Result<Credentials, CliError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/oauth/token",
            creds.backend_url.trim_end_matches('/')
        ))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &creds.refresh_token),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|e| CliError::Other(format!("refresh request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(CliError::Unauthorized);
    }

    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| CliError::Other(format!("invalid refresh response: {e}")))?;

    let new_creds = Credentials {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: Utc::now() + Duration::seconds(token.expires_in),
        backend_url: creds.backend_url.clone(),
    };
    config::save_credentials(&new_creds)
        .map_err(|e| CliError::Other(format!("failed to save credentials: {e}")))?;

    Ok(new_creds)
}

// --- helpers ---------------------------------------------------------

fn generate_verifier() -> String {
    // RFC 7636 §4.1 — verifier is 43–128 chars from `[A-Z][a-z][0-9]-._~`.
    // 32 random bytes → 43 base64url-no-pad chars, the minimum length.
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge_for(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Tiny URL encoder — we only encode bits we put into a query string. The
/// `url` crate's `query_pairs_mut` would be cleaner but the URL we're
/// building is half-templated; doing the escaping inline keeps the code
/// straight-line readable.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// Re-exported so `main.rs` doesn't need to depend on tokio just to
// surface the listener address in error messages.
#[allow(dead_code)]
pub fn loopback_addr_unused() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_matches_rfc7636_known_answer() {
        // RFC 7636 §A.1 worked example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(challenge_for(verifier), expected);
    }

    #[test]
    fn verifier_is_within_rfc7636_length_bounds() {
        let v = generate_verifier();
        assert!(v.len() >= 43);
        assert!(v.len() <= 128);
        assert!(v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)));
    }

    #[test]
    fn url_encoding_escapes_reserved_chars() {
        assert_eq!(urlencoding_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(urlencoding_encode("abcXYZ-._~"), "abcXYZ-._~");
    }
}
