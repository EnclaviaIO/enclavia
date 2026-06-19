use std::sync::Arc;

use crate::message::{ClientMessage, ServerMessage, StreamHalf};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::connect_async;
use tracing::info;
use url::Url;

use crate::error::Error;
use enclavia_protocol::attestation::{self, Pcrs};
use enclavia_protocol::chain::{ChainLinkJson, EnclaveChainRow, RecordedLink};
use uuid::Uuid;
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
        let mut stream = self.open_stream(raw).await?;
        // The stream's id and the cmd_tx are private. We grab them via the
        // accessors we need: the byte-pump's accumulator + recv loop is
        // sufficient for HTTP head parsing, since the SDK pushes the leftover
        // bytes back into the same UpgradedStream's read buffer.
        let id = stream.id();

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
                    match stream.recv_chunk().await {
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
            // verbatim so the caller can decide what to do. Dropping `stream`
            // here is incidental: its Drop fires a StreamClose{Both} too, but
            // we send one eagerly so the close races the head into the wire.
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
        if head_len < head_buf.len() {
            stream.prepend_read(&head_buf[head_len..]);
        }

        Ok(stream)
    }

    /// Opens a raw bidirectional byte stream to the workload.
    ///
    /// The workload's loopback TCP receives `payload` first, then bytes flow
    /// bidirectionally over the returned [`UpgradedStream`]. No HTTP
    /// semantics: this is the low-level primitive
    /// [`Client::upgrade`] is built on top of. Useful for non-HTTP
    /// protocols (raw TCP forwarding, custom wire formats) or for proxies
    /// that handle HTTP parsing themselves (`pingora-enclavia` hands the
    /// resulting stream to Pingora as a custom L4 transport).
    ///
    /// `payload` is delivered as the first chunk of the in-enclave socket's
    /// receive buffer; if you don't have any prologue to ship, pass an empty
    /// `Vec<u8>` and the channel becomes a plain TCP-shaped pipe from the
    /// first byte.
    pub async fn open_stream(&self, payload: Vec<u8>) -> Result<UpgradedStream, Error> {
        let (id_tx, id_rx) = oneshot::channel();
        let (stream_tx, stream_rx) = mpsc::channel::<Result<Vec<u8>, Error>>(32);

        self.inner
            .cmd_tx
            .send(OutboundCommand::OpenStream {
                payload,
                id_tx,
                stream_tx,
            })
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        let id = id_rx.await.map_err(|_| Error::ConnectionClosed)??;

        Ok(UpgradedStream::new(
            id,
            self.inner.cmd_tx.clone(),
            stream_rx,
            Vec::new(),
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

/// Inputs the SDK needs to follow an enclave's upgrade chain when the
/// live PCRs no longer match the pinned ones. See
/// [`ClientBuilder::trust_upgrades`].
#[derive(Clone)]
struct TrustUpgrades {
    /// Backend API base, e.g. `https://api.beta.enclavia.io`.
    backend_url: String,
    /// The enclave whose chain to walk.
    enclave_id: Uuid,
}

/// Builder for configuring and establishing a [`Client`] connection.
pub struct ClientBuilder {
    url: String,
    pcrs: Option<Pcrs>,
    debug_mode: bool,
    extra_headers: Vec<(String, String)>,
    trust_upgrades: Option<TrustUpgrades>,
}

impl ClientBuilder {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            pcrs: None,
            debug_mode: false,
            extra_headers: Vec::new(),
            trust_upgrades: None,
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

    /// Follow enclave upgrades instead of pinning a single immutable
    /// version.
    ///
    /// By default the client trusts ONLY the exact PCRs passed to
    /// [`ClientBuilder::pcrs`]: once the enclave is rebuilt or upgraded
    /// to a new measured image, attestation no longer matches the pin
    /// and the connection is refused. That is the right default for a
    /// caller that wants to bind to one audited build.
    ///
    /// With `trust_upgrades` set, when the live attestation's PCRs differ
    /// from the pinned ones the client fetches the enclave's public
    /// upgrade chain from `backend_url` (`GET /enclaves/{id}` plus
    /// `GET /enclaves/{id}/upgrade-chain`) and verifies that the running
    /// version DESCENDS from the pinned version through a chain of
    /// hardware-attested, control-key-signed upgrade links. Only if that
    /// holds, and the live attestation matches the chain's verified tip,
    /// is the connection allowed.
    ///
    /// The pinned PCRs remain the trust root. Soundness rests on each
    /// link's AWS Nitro attestation, so a dishonest backend can at most
    /// cause the connection to be refused, never make the client trust
    /// an image that does not genuinely descend from the pinned one.
    /// Enabling this without also calling [`ClientBuilder::pcrs`] is a
    /// configuration error and fails the build.
    ///
    /// `backend_url` is the API base (e.g.
    /// `https://api.beta.enclavia.io`); `enclave_id` is the enclave the
    /// `wss://` endpoint routes to.
    pub fn trust_upgrades(
        mut self,
        backend_url: impl Into<String>,
        enclave_id: Uuid,
    ) -> Self {
        self.trust_upgrades = Some(TrustUpgrades {
            backend_url: backend_url.into(),
            enclave_id,
        });
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

        match attestation::verify_against(
            &attestation_data,
            &handshake_hash,
            &pcrs,
            self.debug_mode,
        ) {
            Ok(()) => info!("Attestation verified (pinned PCRs match)"),
            Err(pinned_err) => match &self.trust_upgrades {
                // Pinned PCRs did not match, but the caller opted into
                // following upgrades: try to verify the running enclave
                // as a descendant of the pinned version.
                Some(tu) => {
                    if pcrs.pcr0.is_empty() && pcrs.pcr1.is_empty() && pcrs.pcr2.is_empty() {
                        return Err(Error::TrustUpgrades(
                            "trust_upgrades requires pinned PCRs (call .pcrs(..))".into(),
                        ));
                    }
                    verify_via_upgrade_chain(
                        &attestation_data,
                        &handshake_hash,
                        &pcrs,
                        self.debug_mode,
                        tu,
                    )
                    .await?;
                    info!("Attestation verified (descends from pinned PCRs via upgrade chain)");
                }
                None => return Err(Error::Attestation(pinned_err.to_string())),
            },
        }

        // 4. Spawn background transport task
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        tokio::spawn(transport::run_transport(ws, transport, cmd_rx));

        Ok(Client {
            inner: Arc::new(ClientInner { cmd_tx, host }),
        })
    }
}

/// Verify a running enclave whose live PCRs differ from the pinned ones
/// by walking its public upgrade chain (the SDK side of
/// [`ClientBuilder::trust_upgrades`]).
///
/// Steps, in order, with the trust each one carries:
///
/// 1. Fetch the enclave row + chain from the backend over HTTPS. These
///    bytes are UNTRUSTED: the row's `control_public_key` / image digest
///    / PCRs and the chain links are corroborated below, never taken on
///    faith.
/// 2. [`enclavia_protocol::chain::verify_pcr_descent`] validates every
///    link's Nitro attestation (load-bearing) and proves the pinned PCRs
///    appear as an in-force state on the chain, returning the chain's
///    verified TIP measurements.
/// 3. Re-verify the LIVE attestation against exactly that tip. This is
///    the step that binds the verified descendant version to THIS Noise
///    session: without it the chain could belong to a different live
///    enclave. It reuses the same pinned-identity verifier
///    ([`attestation::verify_against`]) used for the original pin, so
///    the session-nonce and (in production) the Nitro CA chain are
///    checked on the live document too.
async fn verify_via_upgrade_chain(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    pinned: &Pcrs,
    debug_mode: bool,
    tu: &TrustUpgrades,
) -> Result<(), Error> {
    let base = tu.backend_url.trim_end_matches('/');
    let http = reqwest::Client::new();

    let fetch_err = |what: &str, e: reqwest::Error| {
        Error::TrustUpgrades(format!("fetching {what}: {e}"))
    };

    // The enclave row + chain are UNTRUSTED bytes: the row's
    // control_public_key / digest / PCRs and the chain links are all
    // corroborated below, never taken on faith (a wrong value can only
    // make a genuine chain fail to verify). The typed row deserialize
    // and the link decode are the shared protocol-crate parsers.
    let row: EnclaveChainRow = http
        .get(format!("{base}/enclaves/{}", tu.enclave_id))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| fetch_err("enclave row", e))?
        .json()
        .await
        .map_err(|e| fetch_err("enclave row", e))?;

    let wire: Vec<ChainLinkJson> = http
        .get(format!("{base}/enclaves/{}/upgrade-chain", tu.enclave_id))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| fetch_err("upgrade chain", e))?
        .json()
        .await
        .map_err(|e| fetch_err("upgrade chain", e))?;

    let mut links: Vec<RecordedLink> = Vec::with_capacity(wire.len());
    for w in &wire {
        links.push(
            w.into_recorded_link()
                .map_err(|e| Error::TrustUpgrades(format!("decoding chain link: {e}")))?,
        );
    }

    // Walk the chain rooted at the pinned PCRs; on success this is the
    // measured version the live enclave must be running.
    let tip = enclavia_protocol::chain::verify_pcr_descent(
        pinned,
        &links,
        row.control_public_key.as_deref(),
        &row.pcrs,
        &row.image_digest,
        row.upgradable,
        chrono::Utc::now(),
        debug_mode,
    )
    .map_err(|e| Error::TrustUpgrades(e.to_string()))?;

    // Bind the verified descendant version to this live session.
    attestation::verify_against(attestation_data, handshake_hash, &tip, debug_mode).map_err(|e| {
        Error::TrustUpgrades(format!(
            "running enclave does not match the verified chain tip: {e}"
        ))
    })?;

    Ok(())
}
