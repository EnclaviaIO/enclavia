use crate::client::Client;
use crate::error::Error;
use crate::http::{self, Method};
use crate::response::Response;

/// Builder for an HTTP request to be sent through the encrypted channel.
pub struct RequestBuilder {
    client: Client,
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl RequestBuilder {
    pub(crate) fn new(client: Client, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a header to the request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body from a byte slice.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the request body as JSON, automatically setting the Content-Type header.
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, Error> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| Error::HttpParse(format!("JSON serialize error: {e}")))?;
        self.body = Some(bytes);
        self.headers
            .push(("Content-Type".into(), "application/json".into()));
        Ok(self)
    }

    /// Send the request and await the response.
    pub async fn send(mut self) -> Result<Response, Error> {
        // Add Host header if not already set
        if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            self.headers
                .insert(0, ("Host".into(), self.client.host().to_string()));
        }

        // Add Connection: close for HTTP/1.1 (the server-side closes the TCP
        // connection after reading the response, matching HTTP/1.0 behaviour)
        if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
            self.headers.push(("Connection".into(), "close".into()));
        }

        let raw_request =
            http::serialize_request(self.method, &self.path, &self.headers, self.body.as_deref());

        // send_request re-establishes and RE-VERIFIES the attested channel
        // if it is down, but never silently re-sends an in-flight request:
        // a mid-flight drop returns a retryable `Error` (see its doc comment
        // and `Error::is_retryable`). The caller owns the retry decision.
        let raw_response = self.client.send_request(raw_request).await?;

        http::parse_response(&raw_response)
    }
}
