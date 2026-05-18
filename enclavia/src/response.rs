use crate::error::Error;

/// An HTTP response received through the encrypted channel.
#[derive(Debug)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    pub(crate) fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// HTTP status code (e.g. 200, 404).
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Response headers as `(name, value)` pairs.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Get the first value of a header by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Raw response body bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response and return the body bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    /// Response body as a UTF-8 string.
    pub fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.body)
            .map_err(|e| Error::HttpParse(format!("Response body is not valid UTF-8: {e}")))
    }

    /// Deserialize the response body from JSON.
    #[cfg(feature = "json")]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::HttpParse(format!("JSON parse error: {e}")))
    }
}
