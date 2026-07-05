//! WebSocket transport: one internal API, two backends.
//!
//! - **Native** (`not(target_arch = "wasm32")`): tokio-tungstenite over
//!   rustls, exactly the pre-existing behaviour (including caller-supplied
//!   upgrade headers, used by the e2e harness for `X-Enclave-Host`).
//! - **wasm32**: the host's `WebSocket` (browser / wasm runtime) via web-sys.
//!   TLS and the HTTP upgrade are owned by the host, which also means custom
//!   upgrade headers are impossible on this backend — `connect` refuses them
//!   rather than silently dropping them. Production routing selects the
//!   enclave by hostname, so real deployments never need them.
//!
//! Everything security-relevant (Noise, attestation) happens above this
//! layer, so the two backends only have to agree on one thing: binary frames
//! in, binary frames out.

/// One incoming event from the socket.
pub(crate) enum WsEvent {
    /// A binary frame (the only kind the enclavia protocol uses).
    Frame(Vec<u8>),
    /// The peer closed the connection (or it dropped).
    Closed,
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message;

    use super::WsEvent;
    use crate::error::Error;

    type WsStream = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    pub(crate) struct Ws {
        inner: WsStream,
    }

    impl Ws {
        pub(crate) async fn connect(
            url: &str,
            extra_headers: &[(String, String)],
        ) -> Result<Self, Error> {
            // rustls 0.23 requires a CryptoProvider to be installed in the
            // process before the first TLS handshake; otherwise
            // tokio-tungstenite panics. install_default() is process-global
            // and idempotent — the Err case ("already installed") is benign
            // and ignored, so it's safe to call on every connect.
            let _ = rustls::crypto::ring::default_provider().install_default();

            // Build the upgrade request explicitly so we can stamp
            // caller-supplied extra headers (the e2e harness uses this for
            // `X-Enclave-Host`).
            let mut request = url
                .into_client_request()
                .map_err(|e| Error::InvalidUrl(e.to_string()))?;
            for (name, value) in extra_headers {
                let header_name: tokio_tungstenite::tungstenite::http::HeaderName =
                    name.parse().map_err(
                        |e: tokio_tungstenite::tungstenite::http::header::InvalidHeaderName| {
                            Error::InvalidUrl(format!("invalid header name {name:?}: {e}"))
                        },
                    )?;
                let header_value = HeaderValue::from_str(value).map_err(|e| {
                    Error::InvalidUrl(format!("invalid header value for {name:?}: {e}"))
                })?;
                request.headers_mut().insert(header_name, header_value);
            }
            let (ws, _) = tokio_tungstenite::connect_async(request).await?;
            Ok(Self { inner: ws })
        }

        pub(crate) async fn send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
            self.inner
                .send(Message::Binary(bytes.into()))
                .await
                .map_err(Error::from)
        }

        /// Next event. Non-binary frames (pings are answered by tungstenite
        /// internally; text frames are not part of the protocol) are skipped.
        pub(crate) async fn recv(&mut self) -> Result<WsEvent, Error> {
            loop {
                match self.inner.next().await {
                    Some(Ok(Message::Binary(data))) => return Ok(WsEvent::Frame(data.into())),
                    Some(Ok(Message::Close(_))) | None => return Ok(WsEvent::Closed),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(Error::from(e)),
                }
            }
        }

        pub(crate) async fn close(&mut self) {
            let _ = self.inner.close(None).await;
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use tokio::sync::mpsc;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

    use super::WsEvent;
    use crate::error::Error;

    /// What the JS event callbacks push into the channel.
    enum RawEvent {
        Open,
        Frame(Vec<u8>),
        Error(String),
        Closed,
    }

    pub(crate) struct Ws {
        ws: web_sys::WebSocket,
        rx: mpsc::UnboundedReceiver<RawEvent>,
        // Keep the JS closures alive for the socket's lifetime; dropping a
        // Closure invalidates the callback on the JS side.
        _callbacks: Vec<Closure<dyn FnMut(web_sys::Event)>>,
    }

    impl Ws {
        pub(crate) async fn connect(
            url: &str,
            extra_headers: &[(String, String)],
        ) -> Result<Self, Error> {
            if !extra_headers.is_empty() {
                // The browser WebSocket API cannot attach headers to the
                // upgrade request. Refuse loudly instead of silently dropping
                // them — a missing X-Enclave-Host would otherwise surface as
                // a confusing routing error.
                return Err(Error::InvalidUrl(
                    "custom WebSocket upgrade headers are not supported on wasm \
                     (the host WebSocket API cannot set them); rely on \
                     hostname-based routing instead"
                        .into(),
                ));
            }

            let ws = web_sys::WebSocket::new(url)
                .map_err(|e| Error::WebSocket(format!("WebSocket::new({url}): {e:?}")))?;
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

            let (tx, rx) = mpsc::unbounded_channel::<RawEvent>();
            let mut callbacks: Vec<Closure<dyn FnMut(web_sys::Event)>> = Vec::with_capacity(4);

            {
                let tx = tx.clone();
                let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                    let _ = tx.send(RawEvent::Open);
                });
                ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
                callbacks.push(cb);
            }
            {
                let tx = tx.clone();
                let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |e: web_sys::Event| {
                    let e: web_sys::MessageEvent = e.unchecked_into();
                    if let Ok(buf) = e.data().dyn_into::<js_sys::ArrayBuffer>() {
                        let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                        let _ = tx.send(RawEvent::Frame(bytes));
                    }
                    // Text frames are not part of the protocol; ignore.
                });
                ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
                callbacks.push(cb);
            }
            {
                let tx = tx.clone();
                let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                    // The browser deliberately hides error details (they can
                    // leak cross-origin information); the close event that
                    // follows carries what little is shareable.
                    let _ = tx.send(RawEvent::Error("WebSocket error".into()));
                });
                ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
                callbacks.push(cb);
            }
            {
                let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                    let _ = tx.send(RawEvent::Closed);
                });
                ws.set_onclose(Some(cb.as_ref().unchecked_ref()));
                callbacks.push(cb);
            }

            let mut this = Self {
                ws,
                rx,
                _callbacks: callbacks,
            };

            // Wait for the open event (or an early error/close).
            match this.rx.recv().await {
                Some(RawEvent::Open) => Ok(this),
                Some(RawEvent::Error(e)) => Err(Error::WebSocket(e)),
                Some(RawEvent::Closed) | None => Err(Error::ConnectionClosed),
                Some(RawEvent::Frame(_)) => Err(Error::UnexpectedMessage),
            }
        }

        pub(crate) async fn send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
            self.ws
                .send_with_u8_array(&bytes)
                .map_err(|e| Error::WebSocket(format!("send: {e:?}")))
        }

        pub(crate) async fn recv(&mut self) -> Result<WsEvent, Error> {
            match self.rx.recv().await {
                Some(RawEvent::Frame(bytes)) => Ok(WsEvent::Frame(bytes)),
                Some(RawEvent::Error(e)) => Err(Error::WebSocket(e)),
                Some(RawEvent::Closed) | None => Ok(WsEvent::Closed),
                // `Open` only fires once, before connect() returns.
                Some(RawEvent::Open) => Ok(WsEvent::Closed),
            }
        }

        pub(crate) async fn close(&mut self) {
            let _ = self.ws.close();
        }
    }

    impl Drop for Ws {
        fn drop(&mut self) {
            // Detach the event handlers BEFORE the Closures are dropped: the
            // socket can still fire events after we go away (at minimum the
            // close event that follows our own `close()`), and a JS callback
            // hitting a dropped Closure aborts with "closure invoked
            // recursively or after being dropped" — poisoning the whole wasm
            // instance for every other connection sharing it.
            self.ws.set_onopen(None);
            self.ws.set_onmessage(None);
            self.ws.set_onerror(None);
            self.ws.set_onclose(None);
            let _ = self.ws.close();
        }
    }
}

pub(crate) use imp::Ws;

/// Spawn the background transport future on the right executor for the
/// target: tokio natively, the JS microtask queue on wasm (where the future
/// is `!Send` — web-sys handles are thread-bound — and no tokio runtime
/// exists).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn_transport<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(fut);
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn_transport<F>(fut: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(fut);
}
