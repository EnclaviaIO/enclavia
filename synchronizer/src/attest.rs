//! Validation of the attestation documents the synchronizer receives.
//!
//! Every document that reaches the synchronizer from outside (a customer's
//! or a peer's `Authenticate`, the server's answer on the client side, an
//! upgrade link's attestation) goes through one of the two functions here,
//! which pick the context-specific method on
//! [`UnvalidatedAttestation`]. `debug_mode` (a compile-time constant in the
//! node binary, a measured-config flag in the customer client) selects the
//! skip-chain variant for QEMU's self-signing NSM. The skip-chain variants
//! exist only with the `dangerous-skip-chain` feature; a build without it
//! refuses every document validated with `debug_mode = true`.

use enclavia_protocol::attestation::{
    AttestationError, UnvalidatedAttestation, ValidatedAttestation,
};

/// Validate a document presented on a Noise session with handshake hash
/// `handshake_hash`.
pub fn validate_session(
    nsm_doc: &[u8],
    handshake_hash: &[u8],
    debug_mode: bool,
) -> Result<ValidatedAttestation, AttestationError> {
    let doc = UnvalidatedAttestation::from_bytes(nsm_doc.to_vec());
    if debug_mode {
        return skip_chain::session(&doc, handshake_hash);
    }
    doc.validate_session(handshake_hash)
}

/// Validate a chain link's document against the link's `payload`.
pub fn validate_chain_link(
    attestation: &[u8],
    payload: &[u8],
    debug_mode: bool,
) -> Result<ValidatedAttestation, AttestationError> {
    let doc = UnvalidatedAttestation::from_bytes(attestation.to_vec());
    if debug_mode {
        return skip_chain::chain_link(&doc, payload);
    }
    doc.validate_chain_link(payload)
}

#[cfg(feature = "dangerous-skip-chain")]
mod skip_chain {
    use super::*;

    pub(super) fn session(
        doc: &UnvalidatedAttestation,
        handshake_hash: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        doc.validate_session_skip_chain(handshake_hash)
    }

    pub(super) fn chain_link(
        doc: &UnvalidatedAttestation,
        payload: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        doc.validate_chain_link_skip_chain(payload)
    }
}

#[cfg(not(feature = "dangerous-skip-chain"))]
mod skip_chain {
    use super::*;

    pub(super) fn session(
        _doc: &UnvalidatedAttestation,
        _handshake_hash: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        Err(AttestationError::SkipChainNotCompiled)
    }

    pub(super) fn chain_link(
        _doc: &UnvalidatedAttestation,
        _payload: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        Err(AttestationError::SkipChainNotCompiled)
    }
}
