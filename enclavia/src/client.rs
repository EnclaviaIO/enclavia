use std::sync::Arc;

use crate::message::{ClientMessage, ServerMessage, StreamHalf};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::connect_async;
use tracing::info;
use url::Url;

use crate::error::Error;
use enclavia_protocol::attestation::{self, Pcrs};
use crate::http::{self, Method};
use crate::noise;
use crate::request::RequestBuilder;
use crate::stream::UpgradedStream;
use crate::transport::{self, OutboundCommand};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

/// Maximum HTTP response head we'll buffer while waiting for the double-CRLF.
/// Anything past this means the workload is misbehaving (or attacking the
/// client) and we bail rather than grow unboundedly.
const MAX_UPGRADE_HEAD: usize = 64 * 1024;

struct ClientInner {
    cmd_tx: mpsc::Sender<OutboundCommand>,
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

    /// Open an upgraded stream (e.g. WebSocket) through the encrypted channel.
    ///
    /// Builds an HTTP/1.1 request with the supplied method, path, and headers,
    /// sends it as a `ClientMessage::OpenStream` through the Noise tunnel, and
    /// accumulates the workload's reply bytes (delivered as
    /// `ServerMessage::StreamData`) until a complete HTTP/1.1 response head is
    /// parsed.
    ///
    /// On `101 Switching Protocols` the returned [`UpgradedStream`] is a raw
    /// bidirectional byte pipe carrying the post-upgrade payload (e.g.
    /// WebSocket frames). On any other status the call returns
    /// [`Error::UpgradeFailed`] with the observed status code and the response
    /// head bytes, so the caller can surface the failure verbatim.
    ///
    /// The 101 detection lives entirely on the SDK side: the in-enclave server
    /// treats `OpenStream` as an opaque byte pipe, which keeps the server-side
    /// protocol small enough that a future non-Rust frontend can implement it
    /// without an HTTP parser.
    ///
    /// The returned stream implements [`tokio::io::AsyncRead`] +
    /// [`tokio::io::AsyncWrite`] and can be wrapped with
    /// [`tokio_tungstenite::WebSocketStream::from_raw_socket`] to get a
    /// client-side WebSocket endpoint that talks to the workload.
    pub async fn upgrade(
        &self,
        method: Method,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<UpgradedStream, Error> {
        // The caller's headers are forwarded verbatim: WebSocket handshakes are
        // header-sensitive (Upgrade, Sec-WebSocket-Key, etc.) and we don't want
        // to second-guess them. We only insert a Host header if missing so the
        // workload's vhost routing keeps working without each caller having to
        // remember it.
        let mut hdrs: Vec<(String, String)> = headers.to_vec();
        if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            hdrs.insert(0, ("Host".into(), self.host().to_string()));
        }

        let raw = http::serialize_request(method, path, &hdrs, None);

        let (id_tx, id_rx) = oneshot::channel();
        let (stream_tx, mut stream_rx) = mpsc::channel::<Result<Vec<u8>, Error>>(32);

        self.inner
            .cmd_tx
            .send(OutboundCommand::OpenStream {
                payload: raw,
                id_tx,
                stream_tx,
            })
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        let id = id_rx.await.map_err(|_| Error::ConnectionClosed)??;

        // Accumulate StreamData chunks until we can parse the response head.
        // The server treats the stream as opaque bytes — any HTTP awareness
        // lives here.
        let mut head_buf: Vec<u8> = Vec::new();
        let (status, head_len) = loop {
            match http::try_parse_response_head(&head_buf)? {
                Some(pair) => break pair,
                None => {
                    if head_buf.len() >= MAX_UPGRADE_HEAD {
                        let _ = self
                            .inner
                            .cmd_tx
                            .try_send(OutboundCommand::StreamClose { id, half: StreamHalf::Both });
                        return Err(Error::HttpParse(format!(
                            "response head exceeded {MAX_UPGRADE_HEAD} bytes before \\r\\n\\r\\n"
                        )));
                    }
                    match stream_rx.recv().await {
                        Some(Ok(chunk)) => head_buf.extend_from_slice(&chunk),
                        Some(Err(e)) => return Err(e),
                        None => {
                            return Err(Error::ConnectionClosed);
                        }
                    }
                }
            }
        };

        if status != 101 {
            // Tell the server to tear down the stream, then surface the head
            // verbatim so the caller can decide what to do.
            let _ = self
                .inner
                .cmd_tx
                .try_send(OutboundCommand::StreamClose { id, half: StreamHalf::Both });
            // Truncate the buffer to the head so callers only see what the
            // workload produced as its HTTP response, not any trailing body.
            head_buf.truncate(head_len);
            return Err(Error::UpgradeFailed {
                status,
                head: head_buf,
            });
        }

        // 101 path. Anything past the double-CRLF in our accumulator is the
        // first byte(s) of the upgraded stream the workload pushed in the same
        // packet as the head; surface them as the initial read buffer so we
        // don't lose them.
        let leftover = if head_len < head_buf.len() {
            head_buf[head_len..].to_vec()
        } else {
            Vec::new()
        };

        Ok(UpgradedStream::new(
            id,
            self.inner.cmd_tx.clone(),
            stream_rx,
            leftover,
        ))
    }

    /// The host portion of the proxy URL (used for the HTTP Host header).
    pub(crate) fn host(&self) -> &str {
        &self.inner.host
    }

    /// Send a one-shot request to the background transport task.
    pub(crate) async fn send_request(
        &self,
        payload: Vec<u8>,
        response_tx: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) -> Result<(), Error> {
        self.inner
            .cmd_tx
            .send(OutboundCommand::Request { payload, response_tx })
            .await
            .map_err(|_| Error::ConnectionClosed)
    }
}

/// Builder for configuring and establishing a [`Client`] connection.
pub struct ClientBuilder {
    url: String,
    pcrs: Option<Pcrs>,
    debug_mode: bool,
    extra_headers: Vec<(String, String)>,
}

impl ClientBuilder {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            pcrs: None,
            debug_mode: false,
            extra_headers: Vec::new(),
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

    /// Append a header to the initial WebSocket upgrade request.
    ///
    /// The production deployment selects the right backend by hostname (nginx
    /// reads the wildcard subdomain and stamps `X-Enclave-Host` before
    /// forwarding to the router), so most callers don't need this. The
    /// localhost end-to-end test harness, which bypasses nginx and points the
    /// SDK directly at the router, uses it to inject `X-Enclave-Host` itself.
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.extra_headers.push((name.into(), value.into()));
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

        // 1. WebSocket connect. Build the upgrade request explicitly so we
        // can stamp caller-supplied extra headers (the e2e harness uses this
        // for `X-Enclave-Host`).
        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        for (name, value) in &self.extra_headers {
            let header_name: tokio_tungstenite::tungstenite::http::HeaderName =
                name.parse().map_err(|e: tokio_tungstenite::tungstenite::http::header::InvalidHeaderName| {
                    Error::InvalidUrl(format!("invalid header name {name:?}: {e}"))
                })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                Error::InvalidUrl(format!("invalid header value for {name:?}: {e}"))
            })?;
            request.headers_mut().insert(header_name, header_value);
        }
        let (mut ws, _) = connect_async(request).await?;
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
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        tokio::spawn(transport::run_transport(ws, transport, cmd_rx));

        Ok(Client {
            inner: Arc::new(ClientInner { cmd_tx, host }),
        })
    }
}
