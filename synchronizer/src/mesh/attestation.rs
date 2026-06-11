//! Attestation source for the mesh handshake.
//!
//! On every peer connection a node produces a fresh Nitro NSM attestation
//! document whose `nonce` is the live Noise handshake hash (channel binding)
//! and whose `user_data` carries the node's 65-byte uncompressed SEC1 P-256
//! mesh pubkey (the public half of its per-boot [`super::identity::MeshIdentity`]).
//! The peer verifies it with
//! [`enclavia_protocol::attestation::verify_and_extract`], which enforces the
//! handshake-hash binding and the 65-byte SEC1 contract, then checks the
//! derived PCR digest against its self-PCR allowlist AND verifies the peer's
//! identity-key signature over the handshake hash (see
//! [`super::handshake`]).
//!
//! Two providers implement the trait:
//!
//! * [`NsmAttestor`] (production): drives `/dev/nsm` to sign the document.
//! * `FakeAttestor` (test-utils only): wraps `enclavia-protocol`'s
//!   `FakeAttestation` so the multi-node mesh test runs on a dev machine
//!   without booting QEMU. Never compiled into the production binary.
//!
//! The pubkey the document carries always matches the
//! [`super::identity::MeshIdentity`] the same node signs handshake hashes
//! with: the attestor borrows the identity's public half, so the attestation
//! and the channel-binding signature are anchored to one keypair.

use async_trait::async_trait;
use enclavia_protocol::attestation::CONTROL_PUBKEY_LEN;

use crate::mesh::identity::MeshIdentity;

/// Produces this node's attestation document, bound to a Noise handshake
/// hash, for presentation to a peer.
///
/// Object-safe so the mesh layer can hold a `dyn AttestationProvider` and
/// swap the real NSM driver for a fake in tests.
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Produce an NSM attestation document whose `nonce` equals
    /// `handshake_hash` and whose `user_data` is this node's 65-byte SEC1
    /// P-256 mesh pubkey. The bytes are exactly what the peer feeds to
    /// [`enclavia_protocol::attestation::verify_and_extract`].
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, AttestationProviderError>;

    /// This node's own 65-byte SEC1 P-256 mesh pubkey (the value stamped
    /// into the documents produced by [`Self::attest`]). MUST equal the
    /// public half of the [`MeshIdentity`] the node signs handshake hashes
    /// with.
    fn mesh_pubkey(&self) -> [u8; CONTROL_PUBKEY_LEN];
}

/// Errors producing a local attestation document.
#[derive(Debug, thiserror::Error)]
pub enum AttestationProviderError {
    /// The `/dev/nsm` driver failed to initialise or returned an error
    /// response.
    #[error("nsm driver error: {0}")]
    Nsm(String),
}

/// Production attestation provider: drives the in-enclave `/dev/nsm` device.
///
/// Holds a handle to the node's per-boot [`MeshIdentity`] so the document's
/// `user_data` always carries the same pubkey the node signs handshake hashes
/// with. Each [`AttestationProvider::attest`] call opens the NSM device,
/// requests a document with `nonce = handshake_hash` and `user_data =
/// mesh_pubkey`, and closes the device.
///
/// Always compiled (the production binary needs it); `FakeAttestor` is an
/// additive `test-utils` alternative for dev-machine tests, it does not
/// replace this.
pub struct NsmAttestor {
    mesh_pubkey: [u8; CONTROL_PUBKEY_LEN],
}

impl NsmAttestor {
    /// Build the production attestor for a node's per-boot mesh identity.
    pub fn new(identity: &MeshIdentity) -> Self {
        Self {
            mesh_pubkey: identity.pubkey(),
        }
    }
}

#[async_trait]
impl AttestationProvider for NsmAttestor {
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, AttestationProviderError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let handshake_hash = handshake_hash.to_vec();
        let user_data = self.mesh_pubkey.to_vec();

        // The NSM driver is a blocking syscall; run it off the async
        // runtime's worker so the per-peer task does not stall the reactor.
        tokio::task::spawn_blocking(move || {
            let fd = nsm_init();
            if fd == -1 {
                return Err(AttestationProviderError::Nsm("nsm_init failed".into()));
            }
            let request = Request::Attestation {
                user_data: Some(user_data.into()),
                nonce: Some(handshake_hash.into()),
                public_key: None,
            };
            let result = match nsm_process_request(fd, request) {
                Response::Attestation { document } => Ok(document),
                Response::Error(e) => Err(AttestationProviderError::Nsm(format!("{e:?}"))),
                _ => Err(AttestationProviderError::Nsm(
                    "unexpected NSM response".into(),
                )),
            };
            // Close the device on every exit path.
            nsm_exit(fd);
            result
        })
        .await
        .map_err(|e| AttestationProviderError::Nsm(format!("join error: {e}")))?
    }

    fn mesh_pubkey(&self) -> [u8; CONTROL_PUBKEY_LEN] {
        self.mesh_pubkey
    }
}

/// Test-only attestation provider: produces synthetic `FakeAttestation`
/// documents whose PCRs are derived from a fixed seed, so a dev-machine
/// multi-node test can mutually attest without `/dev/nsm`.
///
/// Gated on `test-utils`; never compiled into the production binary. The
/// seed selects the PCR triple (so a test can make two nodes share a seed to
/// exercise the "admitted" path, or differ to exercise rejection). The
/// node's self-PCR digest for the allowlist is [`Self::pcr_digest`]. The
/// document carries the real per-boot [`MeshIdentity`] pubkey, so the
/// channel-binding signature the node sends verifies against it.
#[cfg(feature = "test-utils")]
pub struct FakeAttestor {
    seed: u8,
    mesh_pubkey: [u8; CONTROL_PUBKEY_LEN],
}

#[cfg(feature = "test-utils")]
impl FakeAttestor {
    /// Build a fake attestor whose attestation documents carry the PCR
    /// triple derived from `seed` and the real SEC1 pubkey of `identity`.
    /// Tests sharing a seed exercise the "admitted" path; differing seeds
    /// exercise allowlist rejection.
    pub fn new(seed: u8, identity: &MeshIdentity) -> Self {
        Self {
            seed,
            mesh_pubkey: identity.pubkey(),
        }
    }

    /// The SHA-256 of this attestor's PCR0/1/2 triple: the [`crate::PcrKey`]
    /// a peer derives when it verifies a document from this attestor, and the
    /// value a node configures into its own self-PCR allowlist.
    pub fn pcr_digest(seed: u8) -> crate::PcrKey {
        use enclavia_protocol::attestation::Pcrs;
        let raw = Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        };
        crate::PcrKey(raw.digest())
    }
}

#[cfg(feature = "test-utils")]
#[async_trait]
impl AttestationProvider for FakeAttestor {
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, AttestationProviderError> {
        use enclavia_protocol::attestation::test_utils::FakeAttestation;
        let fake = FakeAttestation::with_seed_and_pubkey(
            self.seed,
            handshake_hash.to_vec(),
            self.mesh_pubkey,
        );
        Ok(fake.encode())
    }

    fn mesh_pubkey(&self) -> [u8; CONTROL_PUBKEY_LEN] {
        self.mesh_pubkey
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use enclavia_protocol::attestation::verify_and_extract;

    #[tokio::test]
    async fn fake_attestor_doc_verifies_and_yields_seed_digest() {
        let identity = MeshIdentity::generate();
        let attestor = FakeAttestor::new(0x42, &identity);
        let hh = vec![0xabu8; 32];
        let doc = attestor.attest(&hh).await.unwrap();
        // The peer side: verify with the same handshake hash, in debug mode.
        let extracted = verify_and_extract(&doc, &hh, true).expect("verify");
        let digest = crate::PcrKey(extracted.pcrs.digest());
        assert_eq!(digest, FakeAttestor::pcr_digest(0x42));
        assert_eq!(extracted.control_pubkey, identity.pubkey());
    }

    #[tokio::test]
    async fn fake_attestor_doc_rejected_under_wrong_handshake_hash() {
        let identity = MeshIdentity::generate();
        let attestor = FakeAttestor::new(0x10, &identity);
        let doc = attestor.attest(&[0x01u8; 32]).await.unwrap();
        let err = verify_and_extract(&doc, &[0x02u8; 32], true).unwrap_err();
        assert!(format!("{err:?}").contains("Validation"));
    }
}
