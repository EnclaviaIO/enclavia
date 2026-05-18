use tokio_tungstenite::tungstenite;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),

    #[error("Noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("Attestation verification failed: {0}")]
    Attestation(String),

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
