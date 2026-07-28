//! UniFFI bindings for the `enclavia` client SDK.
//!
//! Mirrors `enclavia-wasm`'s surface (`connect` + `Client::fetch`) but for
//! native mobile/desktop targets via UniFFI instead of wasm-bindgen. This is
//! the shared interface crate: per-language packages (`enclavia-dart` today,
//! `enclavia-swift` / `enclavia-kotlin` later) each carry a thin wrapper
//! crate that just re-exports this one and bundles that language's
//! `uniffi-bindgen` codegen, same as `bdk-ffi` vs. `bdk-dart`/`bdk-swift`.
//!
//! `enclavia::Client` is built on tokio's I/O (WebSocket + TLS), which needs
//! an active reactor on the polling thread at every await point — not just
//! at the start of the call. UniFFI's async support only guarantees that
//! much for `async_runtime = "tokio"` if the *ambient* runtime is already
//! driving the call, which isn't true when Dart/Swift/Kotlin call in from
//! outside any Rust runtime. So every exported async method spawns its body
//! onto an owned background `Runtime` and awaits the `JoinHandle`, rather
//! than relying on an ambient one.

use std::sync::Arc;

use once_cell::sync::Lazy;
use uuid::Uuid;

static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Runtime::new().expect("failed to start enclavia-ffi tokio runtime")
});

uniffi::setup_scaffolding!();

/// PCR (Platform Configuration Register) measurements identifying the
/// enclave image a connection is pinned to, as hex-decoded bytes. Copy the
/// hex strings from `enclavia enclave status` / `enclavia reproduce` and
/// decode them on the caller's side (each language's standard library has a
/// hex decoder), or decode them yourself before constructing this record.
#[derive(uniffi::Record, Clone)]
pub struct Pcrs {
    pub pcr0: Vec<u8>,
    pub pcr1: Vec<u8>,
    pub pcr2: Vec<u8>,
}

impl From<Pcrs> for enclavia_protocol::attestation::Pcrs {
    fn from(p: Pcrs) -> Self {
        enclavia_protocol::attestation::Pcrs {
            pcr0: p.pcr0,
            pcr1: p.pcr1,
            pcr2: p.pcr2,
        }
    }
}

/// Follow the enclave's signed upgrade chain instead of pinning one
/// immutable version. See `ClientBuilder::trust_upgrades` in the native SDK.
#[derive(uniffi::Record, Clone)]
pub struct TrustUpgrades {
    pub backend_url: String,
    pub enclave_id: String,
}

#[derive(uniffi::Record, Clone, Default)]
pub struct ConnectOptions {
    /// Accept the beta/QEMU debug attestation (nonce binding + PCR
    /// equality, no signature). Defaults to `false`, matching the native
    /// SDK. Leave unset on production Nitro.
    pub debug_mode: Option<bool>,
    pub trust_upgrades: Option<TrustUpgrades>,
}

#[derive(uniffi::Record, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Record, Clone, Default)]
pub struct FetchOptions {
    pub headers: Option<Vec<Header>>,
    pub body: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum EnclaviaError {
    /// Any error from the underlying `enclavia::Error` (transport, Noise,
    /// attestation, server-side, ...); message is `Display`-formatted since
    /// UniFFI records/enums can't carry the native SDK's error type
    /// directly. `retryable` mirrors `enclavia::Error::is_retryable`.
    #[error("{message}")]
    Client { message: String, retryable: bool },
    #[error("unsupported HTTP method: {0}")]
    InvalidMethod(String),
    #[error("invalid enclave id: {0}")]
    InvalidEnclaveId(String),
}

impl From<enclavia::Error> for EnclaviaError {
    fn from(e: enclavia::Error) -> Self {
        EnclaviaError::Client {
            retryable: e.is_retryable(),
            message: e.to_string(),
        }
    }
}

fn parse_method(m: &str) -> Result<enclavia::Method, EnclaviaError> {
    use enclavia::Method;
    Ok(match m.to_ascii_uppercase().as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        "HEAD" => Method::Head,
        "OPTIONS" => Method::Options,
        other => return Err(EnclaviaError::InvalidMethod(other.to_string())),
    })
}

/// An attested, end-to-end-encrypted connection to one enclave.
#[derive(uniffi::Object)]
pub struct Client {
    inner: enclavia::Client,
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Connect to an enclave and verify its attestation.
    ///
    /// - `url`: the enclave endpoint, `wss://<id>.enclaves.<env>.enclavia.io`.
    /// - `pcrs`: refused unless the live attestation matches.
    #[uniffi::constructor]
    pub async fn connect(
        url: String,
        pcrs: Pcrs,
        options: Option<ConnectOptions>,
    ) -> Result<Arc<Self>, EnclaviaError> {
        RUNTIME
            .spawn(async move {
                let mut builder = enclavia::Client::builder(&url).pcrs(pcrs.into());
                if let Some(opts) = options {
                    if let Some(debug) = opts.debug_mode {
                        builder = builder.debug_mode(debug);
                    }
                    if let Some(tu) = opts.trust_upgrades {
                        let enclave_id = Uuid::parse_str(&tu.enclave_id)
                            .map_err(|e| EnclaviaError::InvalidEnclaveId(e.to_string()))?;
                        builder = builder.trust_upgrades(tu.backend_url, enclave_id);
                    }
                }
                let inner = builder.build().await?;
                Ok(Arc::new(Self { inner }))
            })
            .await
            .expect("enclavia-ffi runtime task panicked")
    }

    /// Send one HTTP request through the encrypted channel.
    pub async fn fetch(
        &self,
        method: String,
        path: String,
        options: Option<FetchOptions>,
    ) -> Result<FetchResponse, EnclaviaError> {
        let client = self.inner.clone();
        RUNTIME
            .spawn(async move {
                let method = parse_method(&method)?;
                let mut req = client.request(method, &path);
                if let Some(opts) = options {
                    if let Some(headers) = opts.headers {
                        for h in headers {
                            req = req.header(h.name, h.value);
                        }
                    }
                    if let Some(body) = opts.body {
                        req = req.body(body);
                    }
                }
                let resp = req.send().await?;
                let status = resp.status();
                let headers = resp
                    .headers()
                    .iter()
                    .map(|(name, value)| Header {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect();
                Ok(FetchResponse {
                    status,
                    headers,
                    body: resp.into_bytes(),
                })
            })
            .await
            .expect("enclavia-ffi runtime task panicked")
    }
}
