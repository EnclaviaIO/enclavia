//! Typed REST client over the backend.
//!
//! `ApiClient::new()` defaults to using the on-disk credentials (the
//! original CLI behaviour) and transparently refreshes the access token
//! on a 401 (#88). `ApiClient::with_token()` takes an explicit bearer —
//! used by the MCP server, which is multi-tenant and never touches
//! `~/.config/enclavia`. The MCP path explicitly does NOT participate in
//! refresh-token rotation; that's the caller's job.

use std::sync::Mutex;

use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::commands::auth as auth_cmd;
use crate::config::{self, Credentials};
use crate::error::CliError;

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    /// `Some` when constructed via `ApiClient::new()` — refresh-on-401 is
    /// enabled. `None` when constructed via `ApiClient::with_token()` —
    /// the caller (MCP server) supplied a token they manage themselves.
    creds: Option<Mutex<Credentials>>,
    /// Static token for the `with_token` path. Mutually exclusive with
    /// `creds`; one is always set.
    static_token: Option<String>,
}

/// Backend response for `GET /me/registry`.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryInfo {
    pub registry_url: String,
    pub namespace: String,
}

/// Backend response for `POST /me/registry/push-notify`. `triggered`
/// carries the enclave UUIDs whose build the call kicked off; `matched`
/// is the count of caller-owned enclaves that were waiting on this exact
/// reference (whether or not we ended up starting a build for them).
#[derive(Debug, Clone, Deserialize)]
pub struct NotifyPushResponse {
    pub matched: usize,
    pub triggered: Vec<String>,
}

/// Per-link record on the public upgrade chain (#47 phase 3a).
///
/// Mirrors `enclavia_backend::routes::chain::ChainLinkJson` and the
/// matching shape `enclavia_crates::chain-host` POSTs to the backend.
/// We don't import the backend type because the CLI has no business
/// depending on `enclavia-backend`; the canonical wire spec lives in
/// `enclavia-protocol::chain` and a follow-up will move this type
/// there so backend, chain-host, and the CLI share one definition.
///
/// `payload`, `attestation`, and `signature` are standard base64 with
/// padding. The CLI decodes them before handing the bytes to
/// `enclavia_protocol::chain::validate_chain_link` for local
/// re-verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainLinkJson {
    /// Assigned by the backend on insert; absent on the wire shape
    /// `chain-host` sends to the ingest route.
    #[serde(default)]
    pub id: Option<uuid::Uuid>,
    pub kind: enclavia_protocol::chain::ChainLinkKind,
    /// Monotonic per-enclave, starts at 0 for the boot link.
    #[serde(default)]
    pub sequence: Option<i64>,
    /// Base64 of the CBOR-encoded kind-specific payload.
    pub payload: String,
    /// Base64 of the COSE_Sign1 NSM attestation document. `user_data`
    /// is bound to `sha256(payload_bytes)`.
    pub attestation: String,
    /// Base64 of the raw 64-byte ECDSA P-256 r||s signature. Absent on
    /// boot links (they're authenticated by the attestation alone),
    /// required on upgrade/revocation links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Wall-clock time the backend appended this link. `None` on the
    /// chain-host ingest direction.
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Lightweight projection of a backend enclave row. We keep the raw JSON
/// alongside the typed fields so callers that need a backend-only field
/// (status detail, mode, PCRs, etc.) can dig into it without us having
/// to track the full schema in this crate.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EnclaveSummary {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub docker_image: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub instance_type: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub archived: bool,
    /// Git rev of the `builder` flake input the EIF was built with.
    /// `None` on rows from a pre-provenance backend or when
    /// `FLAKE_LOCK_PATH` was unset on that deployment.
    #[serde(default)]
    pub builder_rev: Option<String>,
    /// Git rev of the `enclavia-crates` flake input the EIF was built
    /// with. Same null semantics as `builder_rev`.
    #[serde(default)]
    pub crates_rev: Option<String>,
    #[serde(flatten)]
    pub raw: serde_json::Value,
}

impl ApiClient {
    /// Build a client using the user's stored credentials. Errors with
    /// `NotLoggedIn` if no credentials are on disk. Refreshes the access
    /// token on 401 using the stored refresh token; if refresh fails the
    /// caller surfaces `CliError::Unauthorized`.
    pub fn new() -> Result<Self, CliError> {
        let creds = config::load_credentials().ok_or(CliError::NotLoggedIn)?;
        let base_url = creds.backend_url.clone();
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
            creds: Some(Mutex::new(creds)),
            static_token: None,
        })
    }

    /// Build a client with an explicit bearer token. `base_url` should be
    /// the backend root (e.g. `https://api.beta.enclavia.io`), without a
    /// trailing slash — the same shape `config::backend_url()` returns.
    /// No refresh-on-401 — the caller manages token lifecycle.
    pub fn with_token(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            creds: None,
            static_token: Some(token.into()),
        }
    }

    /// Build a client that sends no `Authorization` header. Suitable only
    /// for endpoints the backend serves anonymously — currently
    /// `GET /enclaves/{id}` for public-visibility enclaves, used by
    /// `enclavia reproduce` when the caller has no credentials.
    pub fn anonymous() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config::backend_url(),
            creds: None,
            static_token: None,
        }
    }

    /// Caller's API token — used by `enclavia push` as the password for
    /// `docker login` against the registry's bearer-token endpoint. The
    /// realm endpoint accepts the API JWT directly as the Basic password,
    /// so callers don't need a separate registry credential. Reflects the
    /// most-recently-rotated value when refresh-on-401 is enabled.
    pub fn token(&self) -> String {
        self.current_token()
            .expect("ApiClient::token called on an anonymous client")
    }

    /// Returns the bearer string we'd send right now, peeking at the
    /// refreshed token without rotating. `None` when this is an anonymous
    /// client (`ApiClient::anonymous`) — request paths skip the
    /// `Authorization` header in that case.
    fn current_token(&self) -> Option<String> {
        if let Some(t) = &self.static_token {
            return Some(t.clone());
        }
        self.creds.as_ref().map(|c| {
            c.lock().expect("poisoned creds mutex").access_token.clone()
        })
    }

    /// Refresh the access token using the stored refresh token (if any).
    /// On success, the in-memory credentials are updated and the new
    /// pair is persisted to disk. On failure, returns `Unauthorized` —
    /// the user has to `enclavia auth login` again.
    async fn refresh_if_possible(&self) -> Result<(), CliError> {
        let Some(creds_lock) = &self.creds else {
            // `with_token` clients can't refresh — bubble up.
            return Err(CliError::Unauthorized);
        };
        let snapshot = creds_lock
            .lock()
            .expect("poisoned creds mutex")
            .clone();
        let new_creds = auth_cmd::refresh_credentials(&snapshot).await?;
        *creds_lock.lock().expect("poisoned creds mutex") = new_creds;
        Ok(())
    }

    /// Build a request, attaching the current bearer token when one is
    /// available. Anonymous clients (`ApiClient::anonymous`) send no
    /// `Authorization` header — used by `enclavia reproduce` against the
    /// public-visibility path on `GET /enclaves/{id}`.
    fn build(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let req = self
            .client
            .request(method, format!("{}{}", self.base_url, path));
        match self.current_token() {
            Some(t) => req.header("Authorization", format!("Bearer {t}")),
            None => req,
        }
    }

    /// Send a request, refresh-on-401 once, and parse the response.
    async fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<T, CliError> {
        let resp = self
            .build(method.clone(), path)
            .send()
            .await
            .map_err(|e| CliError::Other(format!("request failed: {e}")))?;

        if resp.status() == StatusCode::UNAUTHORIZED && self.creds.is_some() {
            self.refresh_if_possible().await?;
            let resp = self
                .build(method, path)
                .send()
                .await
                .map_err(|e| CliError::Other(format!("request failed: {e}")))?;
            return handle_response(resp).await;
        }

        handle_response(resp).await
    }

    async fn request_with_body<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &impl serde::Serialize,
    ) -> Result<T, CliError> {
        let body_json = serde_json::to_value(body)
            .map_err(|e| CliError::Other(format!("serialize body: {e}")))?;
        let resp = self
            .build(method.clone(), path)
            .json(&body_json)
            .send()
            .await
            .map_err(|e| CliError::Other(format!("request failed: {e}")))?;

        if resp.status() == StatusCode::UNAUTHORIZED && self.creds.is_some() {
            self.refresh_if_possible().await?;
            let resp = self
                .build(method, path)
                .json(&body_json)
                .send()
                .await
                .map_err(|e| CliError::Other(format!("request failed: {e}")))?;
            return handle_response(resp).await;
        }

        handle_response(resp).await
    }

    pub async fn list_enclaves(
        &self,
        include_archived: bool,
    ) -> Result<Vec<EnclaveSummary>, CliError> {
        // `?archived=all` mirrors the backend's filter: default behaviour is
        // to hide rows destroyed >30 minutes ago, the flag flips it to
        // returning everything (#67).
        let path = if include_archived { "/enclaves?archived=all" } else { "/enclaves" };
        self.request(reqwest::Method::GET, path).await
    }

    pub async fn get_registry(&self) -> Result<RegistryInfo, CliError> {
        self.request(reqwest::Method::GET, "/me/registry").await
    }

    /// Tell the backend that a push just landed for the given enclave so
    /// it can kick off the build immediately instead of waiting for the
    /// next registry poll. Under the per-enclave repo model (#46 phase 2)
    /// each enclave owns its own repo (`<owner>/<enclave-uuid>`), so a
    /// push only ever maps to one enclave — the id is the natural scope.
    /// The push itself succeeds independently of this — callers should
    /// treat a notify failure as best-effort.
    pub async fn notify_push(
        &self,
        enclave_id: &str,
    ) -> Result<NotifyPushResponse, CliError> {
        let body = serde_json::json!({ "enclave_id": enclave_id });
        self.request_with_body(reqwest::Method::POST, "/me/registry/push-notify", &body)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_enclave(
        &self,
        instance_type: crate::InstanceTypeArg,
        container_port: Option<u16>,
        storage_size_bytes: Option<u64>,
        name: Option<&str>,
        visibility: Option<&str>,
        egress_allowlist: Option<&serde_json::Value>,
        upgradable: bool,
    ) -> Result<serde_json::Value, CliError> {
        let mut body = serde_json::json!({
            "instance_type": instance_type,
        });
        if let Some(port) = container_port {
            body["container_port"] = serde_json::json!(port);
        }
        if let Some(size) = storage_size_bytes {
            body["storage_size_bytes"] = serde_json::json!(size);
        }
        if let Some(n) = name {
            body["name"] = serde_json::json!(n);
        }
        if let Some(v) = visibility {
            body["visibility"] = serde_json::json!(v);
        }
        if let Some(allow) = egress_allowlist {
            body["egress_allowlist"] = allow.clone();
        }
        // Only send `upgradable` when set, so the backend default
        // (currently `false`) governs the omitted case and we don't
        // commit the CLI to mirroring the server-side default.
        if upgradable {
            body["upgradable"] = serde_json::json!(true);
        }
        self.request_with_body(reqwest::Method::POST, "/enclaves", &body)
            .await
    }

    pub async fn get_enclave(&self, id: &str) -> Result<serde_json::Value, CliError> {
        self.request(reqwest::Method::GET, &format!("/enclaves/{id}"))
            .await
    }

    /// Fetch the public upgrade chain for an enclave (#47 phase 3a). The
    /// backend route is unauthenticated (chain visibility is by design
    /// public), but we still go through `request` so refresh-on-401
    /// remains consistent if the route ever gains auth.
    pub async fn get_enclave_chain(
        &self,
        id: &str,
    ) -> Result<Vec<ChainLinkJson>, CliError> {
        self.request(reqwest::Method::GET, &format!("/enclaves/{id}/upgrade-chain"))
            .await
    }

    pub async fn get_enclave_logs(&self, id: &str) -> Result<serde_json::Value, CliError> {
        self.request(reqwest::Method::GET, &format!("/enclaves/{id}/logs"))
            .await
    }

    pub async fn stop_enclave(&self, id: &str) -> Result<(), CliError> {
        self.request_no_response(
            reqwest::Method::POST,
            &format!("/enclaves/{id}/stop"),
            "stop",
        )
        .await
    }

    pub async fn start_enclave(&self, id: &str) -> Result<(), CliError> {
        self.request_no_response(
            reqwest::Method::POST,
            &format!("/enclaves/{id}/start"),
            "start",
        )
        .await
    }

    pub async fn destroy_enclave(&self, id: &str) -> Result<(), CliError> {
        self.request_no_response(
            reqwest::Method::DELETE,
            &format!("/enclaves/{id}"),
            "destroy",
        )
        .await
    }

    /// Server-side stop + start. Used by `enclavia enclave restart` to
    /// apply pending secret rotations / deletions (#169 / #175).
    pub async fn restart_enclave(&self, id: &str) -> Result<(), CliError> {
        self.request_no_response(
            reqwest::Method::POST,
            &format!("/enclaves/{id}/restart"),
            "restart",
        )
        .await
    }

    // --- Per-enclave secrets (#169) --------------------------------------

    pub async fn list_secrets(
        &self,
        enclave_id: &str,
    ) -> Result<Vec<crate::commands::secrets::SecretSummary>, CliError> {
        self.request(reqwest::Method::GET, &format!("/enclaves/{enclave_id}/secrets"))
            .await
    }

    pub async fn create_secret(
        &self,
        enclave_id: &str,
        name: &str,
        value: &str,
    ) -> Result<crate::commands::secrets::SecretSummary, CliError> {
        let body = serde_json::json!({ "name": name, "value": value });
        self.request_with_body(
            reqwest::Method::POST,
            &format!("/enclaves/{enclave_id}/secrets"),
            &body,
        )
        .await
    }

    pub async fn update_secret(
        &self,
        enclave_id: &str,
        name: &str,
        value: &str,
    ) -> Result<crate::commands::secrets::SecretSummary, CliError> {
        let body = serde_json::json!({ "value": value });
        self.request_with_body(
            reqwest::Method::PUT,
            &format!("/enclaves/{enclave_id}/secrets/{name}"),
            &body,
        )
        .await
    }

    pub async fn delete_secret(
        &self,
        enclave_id: &str,
        name: &str,
    ) -> Result<(), CliError> {
        self.request_no_response(
            reqwest::Method::DELETE,
            &format!("/enclaves/{enclave_id}/secrets/{name}"),
            "delete secret",
        )
        .await
    }

    /// Helper for endpoints that don't return a typed body. Mirrors
    /// `request`'s refresh-on-401 behaviour.
    async fn request_no_response(
        &self,
        method: reqwest::Method,
        path: &str,
        verb: &str,
    ) -> Result<(), CliError> {
        let resp = self
            .build(method.clone(), path)
            .send()
            .await
            .map_err(|e| CliError::Other(format!("request failed: {e}")))?;

        let resp = if resp.status() == StatusCode::UNAUTHORIZED && self.creds.is_some() {
            self.refresh_if_possible().await?;
            self.build(method, path)
                .send()
                .await
                .map_err(|e| CliError::Other(format!("request failed: {e}")))?
        } else {
            resp
        };

        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == StatusCode::UNAUTHORIZED {
            Err(CliError::Unauthorized)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(CliError::Other(format!("{verb} failed: {body}")))
        }
    }
}

async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, CliError> {
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(CliError::Unauthorized);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::Other(format!("request failed ({status}): {body}")));
    }
    resp.json()
        .await
        .map_err(|e| CliError::Other(format!("invalid response: {e}")))
}
