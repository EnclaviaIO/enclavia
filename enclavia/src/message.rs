use serde::{Deserialize, Serialize};

pub(crate) const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// Messages sent from the client to the enclave server. Wire-compatible with
/// `enclavia::ClientMessage` in the enclavia-server workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum ClientMessage {
    RequestAttestation,
    Data { id: u64, payload: Vec<u8> },
    Control { payload: Vec<u8>, signature: Vec<u8> },
}

/// Messages sent from the enclave server to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum ServerMessage {
    Attestation { data: Vec<u8>, control_nonce: [u8; 32] },
    Data { id: u64, payload: Vec<u8> },
    Error { id: u64, message: String },
    ControlResult { success: bool, message: String },
}
