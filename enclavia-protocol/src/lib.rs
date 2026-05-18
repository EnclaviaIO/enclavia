pub mod attestation;
#[cfg(feature = "async-transport")]
pub mod egress;
mod noise;

pub use noise::*;

use serde::{Deserialize, Serialize};

/// Messages sent from the client to the enclave server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Request an attestation document. The server includes the handshake hash
    /// as the attestation nonce and the current control nonce as user_data.
    RequestAttestation,

    /// Raw bytes to forward to the inner container (typically an HTTP request).
    /// The `id` is echoed back in the response so the client can match them.
    Data { id: u64, payload: Vec<u8> },

    /// Authenticated management command. `payload` is a CBOR-encoded
    /// `ControlCommand`; `signature` is an Ed25519 signature over `payload`
    /// produced with the project's control private key. The server verifies
    /// the signature against the control public key baked into the EIF and
    /// the embedded nonce against its current single-use nonce.
    Control {
        payload: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// Messages sent from the enclave server to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Attestation document (COSE_Sign1 in enclave mode, raw nonce in debug
    /// mode). `control_nonce` is the current per-boot single-use nonce that
    /// must be embedded in the next signed `ControlCommand`.
    Attestation {
        data: Vec<u8>,
        control_nonce: [u8; 32],
    },

    /// Raw bytes received from the inner container (typically an HTTP response).
    /// The `id` matches the corresponding `ClientMessage::Data` request.
    Data { id: u64, payload: Vec<u8> },

    /// Error forwarding to the inner container.
    Error { id: u64, message: String },

    /// Result of a `Control` command. The control nonce was rotated whether
    /// or not the command succeeded — the next signed command must use the
    /// new nonce, fetched via a fresh `RequestAttestation`.
    ControlResult { success: bool, message: String },
}

/// Inner payload of a signed control command. Serialized as CBOR before
/// signing — the wire-level signature covers the exact bytes the verifier
/// then deserializes, so re-encoding skew can't break verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum ControlCommand {
    /// Rotate the storage wrapping key onto a new KMS key. The old enclave
    /// runs `zfs change-key`, encrypts the new wrapping key with
    /// `new_public_key` (an RSA pubkey from the new KMS key), and updates
    /// the on-disk key blob. After a clean restart with a new EIF bound to
    /// `new_key_id`, the next boot schedules deletion of the old KMS key.
    PrepareUpgrade {
        /// RSA public key (DER-encoded SubjectPublicKeyInfo) from the new
        /// KMS key — used by the running enclave to wrap the next
        /// generation's wrapping key.
        new_public_key: Vec<u8>,
        /// ARN/identifier of the new KMS key. Stored in the key blob so
        /// the next boot decrypts via the right KMS key.
        new_key_id: String,
        /// Single-use per-boot nonce, must equal the server's current
        /// nonce. Prevents replay across boots without relying on clocks.
        nonce: [u8; 32],
    },
}
