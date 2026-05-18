use std::sync::Arc;

use crate::message::{ClientMessage, ServerMessage};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tracing::info;
use url::Url;

use crate::error::Error;
use enclavia_protocol::attestation::{self, Pcrs};
use crate::http::Method;
use crate::noise;
use crate::request::RequestBuilder;
use crate::transport::{self, PendingRequest};

struct ClientInner {
    request_tx: mpsc::Sender<PendingRequest>,
    host: String,
}

/// An encrypted HTTP client that communicates through an enclavia proxy.
///
/// All requests are encrypted end-to-end using the Noise protocol and forwarded
/// through a WebSocket proxy to the enclave backend. The client verifies the
/// enclave's attestation document during connection.
///
/// `Client` is cheaply cloneable and can be shared across tasks.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Connect to an enclavia proxy and verify the enclave attestation.
    ///
    /// This performs the full connection sequence:
    /// 1. WebSocket connection to the proxy
    /// 2. Noise NN handshake
    /// 3. Attestation request and verification
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), enclavia::Error> {
    /// let pcrs = enclavia::Pcrs {
    ///     pcr0: vec![/* ... */],
    ///     pcr1: vec![/* ... */],
    ///     pcr2: vec![/* ... */],
    /// };
    /// let client = enclavia::Client::connect("wss://proxy.example.com", pcrs).await?;
    /// let resp = client.get("/api/data").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(url: &str, pcrs: Pcrs) -> Result<Self, Error> {
        ClientBuilder::new(url).pcrs(pcrs).build().await
    }

    /// Create a builder for more advanced configuration.
    pub fn builder(url: &str) -> ClientBuilder {
        ClientBuilder::new(url)
    }

    /// Start building a GET request.
    pub fn get(&self, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Get, path.to_string())
    }

    /// Start building a POST request.
    pub fn post(&self, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Post, path.to_string())
    }

    /// Start building a PUT request.
    pub fn put(&self, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Put, path.to_string())
    }

    /// Start building a DELETE request.
    pub fn delete(&self, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Delete, path.to_string())
    }

    /// Start building a PATCH request.
    pub fn patch(&self, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Patch, path.to_string())
    }

    /// Start building a request with an arbitrary method.
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, path.to_string())
    }

    /// The host portion of the proxy URL (used for the HTTP Host header).
    pub(crate) fn host(&self) -> &str {
        &self.inner.host
    }

    /// Send a raw pending request to the background transport task.
    pub(crate) async fn send_raw(&self, req: PendingRequest) -> Result<(), Error> {
        self.inner
            .request_tx
            .send(req)
            .await
            .map_err(|_| Error::ConnectionClosed)
    }
}

/// Builder for configuring and establishing a [`Client`] connection.
pub struct ClientBuilder {
    url: String,
    pcrs: Option<Pcrs>,
    debug_mode: bool,
}

impl ClientBuilder {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            pcrs: None,
            debug_mode: false,
        }
    }

    /// Set the expected PCR values for attestation verification.
    pub fn pcrs(mut self, pcrs: Pcrs) -> Self {
        self.pcrs = Some(pcrs);
        self
    }

    /// Enable debug mode: skip attestation signature verification.
    ///
    /// In debug mode, the server echoes the handshake nonce instead of returning
    /// a real COSE_Sign1 attestation document. Only the nonce match is verified.
    pub fn debug_mode(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }

    /// Build the client: connect, handshake, verify attestation, and start the
    /// background transport task.
    pub async fn build(self) -> Result<Client, Error> {
        let pcrs = self.pcrs.unwrap_or(Pcrs {
            pcr0: Vec::new(),
            pcr1: Vec::new(),
            pcr2: Vec::new(),
        });

        let parsed_url =
            Url::parse(&self.url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("Missing host".into()))?
            .to_string();

        info!(url = %self.url, "Connecting to enclavia proxy");

        // rustls 0.23 requires a CryptoProvider to be installed in the
        // process before the first TLS handshake; otherwise tokio-tungstenite
        // panics. install_default() is process-global and idempotent — the
        // Err case ("already installed") is benign and ignored, so it's
        // safe to call on every build().
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. WebSocket connect
        let (mut ws, _) = connect_async(&self.url).await?;
        info!("WebSocket connected");

        // 2. Noise handshake
        let (mut transport, handshake_hash) =
            noise::perform_handshake(&mut ws).await?;

        // 3. Request and verify attestation
        let attestation_response: ServerMessage =
            transport::send_and_receive(
                &mut ws,
                &mut transport,
                &ClientMessage::RequestAttestation,
            )
            .await?;

        let attestation_data = match attestation_response {
            ServerMessage::Attestation { data, .. } => data,
            _ => return Err(Error::UnexpectedMessage),
        };

        attestation::verify_against(
            &attestation_data,
            &handshake_hash,
            &pcrs,
            self.debug_mode,
        )
        .map_err(|e| Error::Attestation(e.to_string()))?;
        info!("Attestation verified");

        // 4. Spawn background transport task
        let (request_tx, request_rx) = mpsc::channel(64);
        tokio::spawn(transport::run_transport(ws, transport, request_rx));

        Ok(Client {
            inner: Arc::new(ClientInner { request_tx, host }),
        })
    }
}
