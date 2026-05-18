//! Nitro NSM attestation verification.
//!
//! Two entry points share the same parse-and-verify core:
//!
//! - [`verify_against`] — "is this document from the enclave I expected?"
//!   The SDK's call path: a client knows what PCRs the target enclave is
//!   supposed to have and wants the document to confirm it.
//!
//! - [`verify_and_extract`] — "what enclave produced this document?" The
//!   synchronizer's call path: it does not pre-commit to a specific
//!   identity; the document's verified PCRs *are* the identity, and the
//!   caller hashes them into its own key. The doc must also carry the
//!   enclave's raw 32-byte Ed25519 control pubkey in `user_data` — the
//!   synchronizer registers it alongside the key and uses it to verify
//!   `Transition` signatures later.
//!
//! Both check that the doc's nonce equals `base64(handshake_hash)`,
//! binding the document to the live Noise session. In `debug_mode` the
//! COSE_Sign1 certificate chain is skipped (the in-enclave NSM
//! self-signs when run under QEMU) — production validates the full
//! chain.

use attestation_doc_validation::{
    PCRProvider, attestation_doc::decode_attestation_document,
    attestation_doc::get_pcrs as att_get_pcrs, validate_and_parse_attestation_doc,
    validate_expected_nonce, validate_expected_pcrs,
};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use sha2::{Digest, Sha256};

/// PCR (Platform Configuration Register) measurements that identify a
/// specific enclave image and configuration:
///
/// - `pcr0` — Enclave Image File (EIF) measurement.
/// - `pcr1` — Enclave OS measurement.
/// - `pcr2` — Application configuration measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcrs {
    /// EIF measurement.
    pub pcr0: Vec<u8>,
    /// Enclave OS measurement.
    pub pcr1: Vec<u8>,
    /// Application configuration measurement.
    pub pcr2: Vec<u8>,
}

impl Pcrs {
    /// SHA-256 over `PCR0 || PCR1 || PCR2`. The synchronizer uses this
    /// 32-byte digest as the per-enclave session key.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.pcr0);
        hasher.update(&self.pcr1);
        hasher.update(&self.pcr2);
        hasher.finalize().into()
    }
}

/// Errors from attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Parse/structure/signature/PCR/nonce validation failed in the
    /// upstream `attestation-doc-validation` crate. Carries the original
    /// error rendered to a string — the upstream type is non-exhaustive
    /// and not worth re-exporting.
    #[error("attestation document validation failed: {0}")]
    Validation(String),
    /// A PCR value coming out of the validated document hex-decoded to
    /// something other than 32/48/64 bytes, which would break PcrKey
    /// derivation. Should be unreachable for real Nitro docs.
    #[error("attestation document PCR {idx} has unexpected length {len}")]
    InvalidPcrLength {
        /// The PCR index (0, 1, or 2).
        idx: usize,
        /// The decoded length in bytes.
        len: usize,
    },
    /// A PCR slot was not hex-encoded. Should be unreachable: the
    /// upstream crate is the one that hex-encodes them on the way out.
    #[error("attestation document PCR {0} is not valid hex")]
    InvalidPcrHex(usize),
    /// The doc's `user_data` field is missing or not a 32-byte raw
    /// Ed25519 verifying key. Required by [`verify_and_extract`] — the
    /// synchronizer needs the control pubkey to verify `Transition`
    /// signatures later in the session.
    #[error("attestation document user_data is missing or not a 32-byte Ed25519 pubkey")]
    InvalidControlPubkey,
}

/// Verified enclave identity extracted from an NSM attestation document.
///
/// Returned by [`verify_and_extract`] when the document validates and the
/// caller wants both the PCRs (for deriving a session key) and the
/// enclave's Ed25519 control pubkey (for verifying future `Transition`
/// signatures from this key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIdentity {
    /// PCR0/1/2 from the validated document.
    pub pcrs: Pcrs,
    /// Raw 32-byte Ed25519 verifying key extracted from the doc's
    /// `user_data` field. The synchronizer registers this alongside
    /// the [`Pcrs::digest`]-derived key on first attestation, and uses
    /// it to verify Ed25519 signatures on subsequent `Transition` RPCs.
    pub control_pubkey: [u8; 32],
}

/// Verify an attestation document against expected PCRs.
///
/// SDK entry point. The caller has pinned the enclave's identity at
/// configure-time and wants `Ok(())` on a match or an error otherwise.
///
/// Checks performed (in order, in both `debug_mode` and production):
///
/// 1. Parse + structural validation of the COSE_Sign1 wrapper.
/// 2. Nonce equals `base64(handshake_hash)`.
/// 3. PCR0/1/2 in the doc equal the caller-supplied `expected_pcrs`.
///
/// Additionally, in production mode (`debug_mode = false`), the AWS
/// Nitro CA chain is validated and the COSE signature is verified.
pub fn verify_against(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    expected_pcrs: &Pcrs,
    debug_mode: bool,
) -> Result<(), AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = parse_and_validate(attestation_data, debug_mode)?;

    check_nonce(&doc, handshake_hash)?;

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    Ok(())
}

/// Verify an attestation document and return the enclave identity it
/// embeds.
///
/// Synchronizer entry point. The caller does not know in advance which
/// enclave is connecting — the verified document's PCRs *are* the
/// identity, and the doc's `user_data` carries the enclave's Ed25519
/// control pubkey. The caller typically passes the returned
/// [`AttestedIdentity::pcrs`] through [`Pcrs::digest`] to derive a stable
/// session key, and registers
/// [`AttestedIdentity::control_pubkey`] for verifying future
/// `Transition` RPCs from this key.
///
/// Verification is identical to [`verify_against`] minus the
/// `expected_pcrs` equality check (there are no expected PCRs at this
/// layer — the doc's nonce binding to the handshake hash is what
/// authenticates the document's origin to the live session), plus a
/// requirement that `user_data` is exactly 32 bytes — the raw Ed25519
/// verifying key.
pub fn verify_and_extract(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    debug_mode: bool,
) -> Result<AttestedIdentity, AttestationError> {
    let doc = parse_and_validate(attestation_data, debug_mode)?;

    check_nonce(&doc, handshake_hash)?;

    let hex_pcrs =
        att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;

    let pcrs = Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    };

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::InvalidControlPubkey)?;
    let control_pubkey: [u8; 32] = user_data
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidControlPubkey)?;

    Ok(AttestedIdentity {
        pcrs,
        control_pubkey,
    })
}

fn parse_and_validate(
    attestation_data: &[u8],
    debug_mode: bool,
) -> Result<AttestationDoc, AttestationError> {
    if debug_mode {
        let (_, doc) = decode_attestation_document(attestation_data)
            .map_err(|e| AttestationError::Validation(e.to_string()))?;
        Ok(doc)
    } else {
        validate_and_parse_attestation_doc(attestation_data)
            .map_err(|e| AttestationError::Validation(e.to_string()))
    }
}

fn check_nonce(doc: &AttestationDoc, handshake_hash: &[u8]) -> Result<(), AttestationError> {
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(handshake_hash);
    validate_expected_nonce(doc, &nonce_b64)
        .map_err(|e| AttestationError::Validation(e.to_string()))
}

fn decode_pcr(hex_str: &str, idx: usize) -> Result<Vec<u8>, AttestationError> {
    let bytes = hex::decode(hex_str).map_err(|_| AttestationError::InvalidPcrHex(idx))?;
    if ![32usize, 48, 64].contains(&bytes.len()) {
        return Err(AttestationError::InvalidPcrLength {
            idx,
            len: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Internal hex-encoded view of a [`Pcrs`] for the `PCRProvider` trait.
/// The upstream crate compares PCRs by string equality on hex
/// representations, so we encode once at the entry point.
struct PcrsHex {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

impl PcrsHex {
    fn from_pcrs(pcrs: &Pcrs) -> Self {
        Self {
            pcr0: hex::encode(&pcrs.pcr0),
            pcr1: hex::encode(&pcrs.pcr1),
            pcr2: hex::encode(&pcrs.pcr2),
        }
    }
}

impl PCRProvider for PcrsHex {
    fn pcr_0(&self) -> Option<&str> {
        Some(&self.pcr0)
    }
    fn pcr_1(&self) -> Option<&str> {
        Some(&self.pcr1)
    }
    fn pcr_2(&self) -> Option<&str> {
        Some(&self.pcr2)
    }
    fn pcr_8(&self) -> Option<&str> {
        None
    }
}

/// Test-only helpers for constructing attestation documents with known
/// PCRs and nonces. Behind the `test-utils` feature so downstream test
/// suites can build doc fixtures without spinning up real Nitro
/// hardware. Production builds cannot reach this module.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use std::collections::BTreeMap;

    use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
    use ciborium::value::Value as CborValue;

    /// Builder for synthetic attestation documents accepted by
    /// [`verify_against`](super::verify_against) /
    /// [`verify_and_extract`](super::verify_and_extract) in debug mode.
    ///
    /// In debug mode the COSE signature is not validated, so any
    /// well-formed COSE_Sign1 envelope around a well-formed
    /// [`AttestationDoc`] is accepted. PCR0/1/2 are 48-byte SHA-384
    /// values (matches what real Nitro hardware emits).
    pub struct FakeAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// Raw Noise handshake hash. The encoded doc's `nonce` field is
        /// set to these bytes verbatim — the verifier base64-encodes
        /// before comparing, so it works out.
        pub handshake_hash: Vec<u8>,
        /// Raw 32-byte Ed25519 verifying key. Encoded into the doc's
        /// `user_data` field — [`super::verify_and_extract`] requires
        /// this to be a 32-byte pubkey.
        pub control_pubkey: [u8; 32],
    }

    impl FakeAttestation {
        /// Build a fixture with all three PCRs and the control pubkey
        /// derived from `seed` so tests can assert against a known
        /// [`super::Pcrs::digest`] and a known pubkey. For tests that
        /// need a *real* Ed25519 keypair (to produce signatures), set
        /// `control_pubkey` directly after construction or use
        /// [`Self::with_seed_and_pubkey`].
        pub fn with_seed(seed: u8, handshake_hash: Vec<u8>) -> Self {
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                handshake_hash,
                control_pubkey: [seed.wrapping_add(0x80); 32],
            }
        }

        /// Like [`Self::with_seed`] but with a caller-supplied control
        /// pubkey (typically the verifying-key bytes from a real Ed25519
        /// keypair the test holds the signing key for).
        pub fn with_seed_and_pubkey(
            seed: u8,
            handshake_hash: Vec<u8>,
            control_pubkey: [u8; 32],
        ) -> Self {
            let mut fake = Self::with_seed(seed, handshake_hash);
            fake.control_pubkey = control_pubkey;
            fake
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// `debug_mode` verify path.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            // The upstream `get_pcrs` is hard-coded to require PCR8
            // (signing-cert measurement). Synchronizer doesn't use it,
            // but the doc has to include it to deserialize.
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                0,
                pcrs,
                // certificate / cabundle: not validated in debug mode,
                // but `validate_attestation_document_structure` does
                // require each cert byte slice to be 1..=1024 bytes.
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.control_pubkey.to_vec()),
                Some(self.handshake_hash.clone()),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            // COSE_Sign1, untagged: [protected: bstr, unprotected: map, payload: bstr, signature: bstr].
            // - protected is a *byte string* whose contents are a serialized HeaderMap.
            //   An empty CBOR map is one byte: 0xa0.
            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                // Signature: junk. The debug-mode verify path does not
                // touch it (and even production verify only fails if the
                // cert chain is wrong, which it always will be for
                // synthetic docs).
                CborValue::Bytes(vec![0u8; 96]),
            ]);

            let mut out = Vec::new();
            ciborium::into_writer(&cose, &mut out).expect("ciborium encode COSE_Sign1");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hh() -> Vec<u8> {
        // 32-byte BLAKE2s-shaped handshake hash for tests.
        (0u8..32).collect()
    }

    #[test]
    fn verify_and_extract_returns_doc_identity_in_debug_mode() {
        let fake = test_utils::FakeAttestation::with_seed(0x11, hh());
        let bytes = fake.encode();

        let identity = verify_and_extract(&bytes, &hh(), true).expect("verify");
        assert_eq!(identity.pcrs.pcr0, fake.pcr0);
        assert_eq!(identity.pcrs.pcr1, fake.pcr1);
        assert_eq!(identity.pcrs.pcr2, fake.pcr2);
        assert_eq!(identity.control_pubkey, fake.control_pubkey);
    }

    #[test]
    fn verify_and_extract_rejects_doc_without_user_data() {
        // Build a doc with `user_data: None` by constructing it directly,
        // since `FakeAttestation::encode` always populates user_data.
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0usize, vec![0x11u8; 48]);
        pcrs.insert(1usize, vec![0x12u8; 48]);
        pcrs.insert(2usize, vec![0x13u8; 48]);
        pcrs.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            0,
            pcrs,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            None, // user_data missing — the case under test.
            Some(hh()),
            None,
        );

        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_and_extract(&bytes, &hh(), true).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlPubkey),
            "expected InvalidControlPubkey, got {err:?}"
        );
    }

    #[test]
    fn verify_and_extract_rejects_doc_with_wrong_size_user_data() {
        let mut fake = test_utils::FakeAttestation::with_seed(0x22, hh());
        // Override user_data via the `control_pubkey` field by encoding
        // a longer payload — done by reaching directly into the struct
        // and re-encoding manually. Easier: build the doc inline with a
        // 16-byte user_data.
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;
        let _ = &mut fake;

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0usize, vec![0x22u8; 48]);
        pcrs.insert(1usize, vec![0x23u8; 48]);
        pcrs.insert(2usize, vec![0x24u8; 48]);
        pcrs.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            0,
            pcrs,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            Some(vec![0u8; 16]), // 16 bytes is the wrong size.
            Some(hh()),
            None,
        );

        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_and_extract(&bytes, &hh(), true).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlPubkey),
            "expected InvalidControlPubkey, got {err:?}"
        );
    }

    #[test]
    fn verify_against_accepts_matching_pcrs_in_debug_mode() {
        let fake = test_utils::FakeAttestation::with_seed(0x22, hh());
        let bytes = fake.encode();
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        verify_against(&bytes, &hh(), &expected, true).expect("verify");
    }

    #[test]
    fn verify_against_rejects_mismatched_pcrs() {
        let fake = test_utils::FakeAttestation::with_seed(0x33, hh());
        let bytes = fake.encode();
        let expected = Pcrs {
            pcr0: vec![0xff; 48],
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        let err = verify_against(&bytes, &hh(), &expected, true).unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_handshake_hash() {
        let fake = test_utils::FakeAttestation::with_seed(0x44, hh());
        let bytes = fake.encode();
        let wrong: Vec<u8> = vec![0xab; 32];
        let err = verify_and_extract(&bytes, &wrong, true).unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn digest_is_sha256_of_concatenated_pcrs() {
        let pcrs = Pcrs {
            pcr0: vec![0x01; 48],
            pcr1: vec![0x02; 48],
            pcr2: vec![0x03; 48],
        };
        let mut hasher = Sha256::new();
        hasher.update(&pcrs.pcr0);
        hasher.update(&pcrs.pcr1);
        hasher.update(&pcrs.pcr2);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(pcrs.digest(), expected);
    }
}
