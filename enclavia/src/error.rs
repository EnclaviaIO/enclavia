#[cfg(not(target_arch = "wasm32"))]
use tokio_tungstenite::tungstenite;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(not(target_arch = "wasm32"))]
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),

    /// On wasm the host WebSocket API doesn't expose a typed error (browsers
    /// deliberately hide details), so the variant carries a message instead.
    #[cfg(target_arch = "wasm32")]
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("Attestation verification failed: {0}")]
    Attestation(String),

    /// `trust_upgrades` was enabled, the live PCRs did not match the
    /// pinned ones, and verifying the running enclave as a descendant of
    /// the pinned version through its public upgrade chain failed.
    /// Carries the underlying reason: a chain-fetch error, a chain
    /// validation failure, the pin not appearing in the chain's lineage,
    /// or the live enclave not matching the verified chain tip.
    #[error("trust_upgrades verification failed: {0}")]
    TrustUpgrades(String),

    #[error("Attestation nonce mismatch")]
    AttestationNonceMismatch,

    #[error("PCR mismatch at index {index}")]
    PcrMismatch { index: usize },

    #[error("Server error for request {id}: {message}")]
    ServerError { id: u64, message: String },

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("HTTP parse error: {0}")]
    HttpParse(String),

    #[error("CBOR error: {0}")]
    Cbor(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Unexpected server message")]
    UnexpectedMessage,

    /// `Client::upgrade` received a complete HTTP response head, but the
    /// status was not `101 Switching Protocols`. The raw response head is
    /// preserved so the caller can surface it without losing information.
    #[error("upgrade rejected: server returned status {status}")]
    UpgradeFailed { status: u16, head: Vec<u8> },
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Cbor(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for Error {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Error::Cbor(e.to_string())
    }
}
