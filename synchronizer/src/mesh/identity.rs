//! Per-boot P-256 mesh identity keypair.
//!
//! Each node generates a fresh P-256 keypair at startup. Enclaves have no
//! disk, so the keypair lives only in memory and never leaves the enclave.
//! The public half is what the node stamps into its attestation document's
//! `user_data` (the [`enclavia_protocol::attestation::AttestedIdentity::control_pubkey`]
//! contract, 65-byte uncompressed SEC1); the private half signs the live
//! Noise handshake hash on every connection so the peer can bind the attested
//! identity to *this* channel (see
//! [`enclavia_protocol::mesh::verify_mesh_identity`]).
//!
//! P-256 (not Ed25519) is mandated by the #16 design pass so the 65-byte
//! `user_data` contract holds unmodified across the attestation, control, and
//! mesh layers.

use std::sync::Arc;

use enclavia_protocol::attestation::CONTROL_PUBKEY_LEN;
use p256::ecdsa::SigningKey;

/// A node's per-boot mesh identity: a P-256 signing key plus its 65-byte
/// SEC1 public encoding.
///
/// Cloneable (the inner key is `Arc`-shared) so each per-peer task can hold a
/// handle and sign its own connection's handshake hash. The private key is
/// never serialized or logged.
#[derive(Clone)]
pub struct MeshIdentity {
    signing_key: Arc<SigningKey>,
    pubkey: [u8; CONTROL_PUBKEY_LEN],
}

impl MeshIdentity {
    /// Generate a fresh per-boot identity from the system RNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        Self::from_signing_key(signing_key)
    }

    /// Build an identity from an existing signing key (used by tests with a
    /// deterministic key; production calls [`Self::generate`]).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let mut pubkey = [0u8; CONTROL_PUBKEY_LEN];
        pubkey.copy_from_slice(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        Self {
            signing_key: Arc::new(signing_key),
            pubkey,
        }
    }

    /// The 65-byte uncompressed SEC1 public key to stamp into the node's
    /// attestation document `user_data`.
    pub fn pubkey(&self) -> [u8; CONTROL_PUBKEY_LEN] {
        self.pubkey
    }

    /// Sign `handshake_hash` with this identity, producing the 64-byte raw
    /// r||s ECDSA P-256 signature the peer verifies against [`Self::pubkey`].
    pub fn sign_handshake(&self, handshake_hash: &[u8]) -> Vec<u8> {
        enclavia_protocol::mesh::sign_mesh_identity(&self.signing_key, handshake_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavia_protocol::mesh::verify_mesh_identity;

    #[test]
    fn generated_identity_signs_verifiably() {
        let id = MeshIdentity::generate();
        let hh = [0x5a; 32];
        let sig = id.sign_handshake(&hh);
        verify_mesh_identity(&id.pubkey(), &sig, &hh).expect("self-verify");
    }

    #[test]
    fn distinct_identities_have_distinct_pubkeys() {
        let a = MeshIdentity::generate();
        let b = MeshIdentity::generate();
        assert_ne!(a.pubkey(), b.pubkey());
    }
}
