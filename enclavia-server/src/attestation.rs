//! This enclave's own attestation documents. Every one comes from
//! `/dev/nsm` through [`ValidatedAttestation::request_local`], the only
//! way to wrap NSM output.

use enclavia_protocol::attestation::{LocalAttestationError, ValidatedAttestation};

/// A document bound to a Noise session (`nonce = handshake_hash`) carrying
/// `user_data`: the current control nonce in a `RequestAttestation` reply,
/// the control pubkey on a synchronizer session. Returns the bytes to send.
pub fn session_attestation(
    handshake_hash: &[u8],
    user_data: &[u8],
) -> Result<Vec<u8>, LocalAttestationError> {
    ValidatedAttestation::request_local(Some(handshake_hash), Some(user_data), None)
        .map(ValidatedAttestation::into_bytes)
}

/// Produce a chain-link attestation document.
///
/// `user_data` must be 32-byte `sha256(payload)`: chain-link validation
/// (`UnvalidatedAttestation::validate_chain_link`) checks this binding.
/// `nonce` populates the document's nonce slot; chain-link validation does
/// not check it (there is no Noise session at chain-link emission time), but
/// we pass a random value to avoid a deterministic placeholder.
pub fn chain_attestation(
    user_data: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<ValidatedAttestation, LocalAttestationError> {
    ValidatedAttestation::request_local(Some(nonce), Some(user_data), None)
}
