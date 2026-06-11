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
    /// The doc's `user_data` field is missing or not a 65-byte
    /// uncompressed SEC1 ECDSA P-256 verifying key (#47). Required by
    /// [`verify_and_extract`] — the synchronizer needs the control
    /// pubkey to verify `Transition` signatures later in the session.
    #[error(
        "attestation document user_data is missing or not a 65-byte uncompressed SEC1 P-256 pubkey"
    )]
    InvalidControlPubkey,
    /// The doc's `user_data` field is missing or not the 32-byte
    /// SHA-256 hash of the chain link's `payload`. Required by
    /// [`verify_chain_attestation`] — every chain link binds its
    /// `attestation.user_data` to `sha256(payload)`, so any mismatch
    /// means either the payload or the attestation has been swapped.
    #[error("attestation document user_data does not match sha256(payload)")]
    PayloadBindingMismatch,
    /// The doc's `user_data` field is missing or not exactly 32 bytes
    /// where a control nonce was expected. Returned by
    /// [`verify_control_nonce_attestation`]: the in-enclave server's
    /// `RequestAttestation` reply always embeds the current 32-byte
    /// control nonce as `user_data`, so any other shape means the
    /// document was produced for a different purpose (or tampered with).
    #[error("attestation document user_data is not a 32-byte control nonce")]
    InvalidControlNonce,
}

/// Length of an ECDSA P-256 verifying key in uncompressed SEC1 form
/// (`0x04 || X(32) || Y(32)`). Locked at the protocol layer because
/// every caller — synchronizer node, in-enclave server, attestation
/// emitter — needs to agree on the shape carried in
/// `AttestationDoc::user_data`. See EnclaviaIO/enclavia-crates#47.
pub const CONTROL_PUBKEY_LEN: usize = 65;

/// Verified enclave identity extracted from an NSM attestation document.
///
/// Returned by [`verify_and_extract`] when the document validates and the
/// caller wants both the PCRs (for deriving a session key) and the
/// enclave's ECDSA P-256 control pubkey (for verifying future
/// `Transition` signatures from this key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIdentity {
    /// PCR0/1/2 from the validated document.
    pub pcrs: Pcrs,
    /// 65-byte uncompressed SEC1 ECDSA P-256 verifying key extracted
    /// from the doc's `user_data` field. The synchronizer registers
    /// this alongside the [`Pcrs::digest`]-derived key on first
    /// attestation, and uses it to verify raw r||s signatures on
    /// subsequent `Transition` RPCs.
    pub control_pubkey: [u8; CONTROL_PUBKEY_LEN],
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

/// Verify a control-nonce attestation and return the attested nonce.
///
/// Backend control-dispatch entry point (#47 hardening). Before signing
/// and sending a control command, the dispatcher requests an attestation
/// over the control channel; the in-enclave server's reply binds the
/// live Noise session (doc `nonce` = `base64(handshake_hash)`) and
/// carries the current 32-byte control nonce in `user_data`. Verifying
/// the document before dispatch gives the caller two guarantees a bare
/// `GetControlNonce` round-trip cannot:
///
/// 1. The Noise session terminates inside the enclave whose PCRs the
///    caller expected, with no host in the middle, so the eventual
///    `ControlResult` is authentic rather than the relay's word.
/// 2. The nonce embedded in the signed command was minted by that
///    enclave, not substituted on the way through the host.
///
/// Verification is [`verify_against`] (COSE chain in production mode,
/// session-nonce binding, PCR equality) plus a requirement that
/// `user_data` is exactly 32 bytes, returned as the attested control
/// nonce.
pub fn verify_control_nonce_attestation(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    expected_pcrs: &Pcrs,
    debug_mode: bool,
) -> Result<[u8; 32], AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = parse_and_validate(attestation_data, debug_mode)?;

    check_nonce(&doc, handshake_hash)?;

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::InvalidControlNonce)?;
    user_data
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidControlNonce)
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
/// requirement that `user_data` is exactly [`CONTROL_PUBKEY_LEN`]
/// bytes — the uncompressed SEC1 ECDSA P-256 verifying key.
pub fn verify_and_extract(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    debug_mode: bool,
) -> Result<AttestedIdentity, AttestationError> {
    let doc = parse_and_validate(attestation_data, debug_mode)?;

    check_nonce(&doc, handshake_hash)?;

    let hex_pcrs = att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;

    let pcrs = Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    };

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::InvalidControlPubkey)?;
    let control_pubkey: [u8; CONTROL_PUBKEY_LEN] = user_data
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidControlPubkey)?;
    // SEC1 uncompressed-form prefix must be 0x04. Anything else (0x02 /
    // 0x03 compressed, or random bytes that happen to fit) is rejected
    // here so the in-enclave verifier doesn't have to handle the
    // compressed-form decompression path.
    if control_pubkey[0] != 0x04 {
        return Err(AttestationError::InvalidControlPubkey);
    }

    Ok(AttestedIdentity {
        pcrs,
        control_pubkey,
    })
}

/// Extract PCR0/1/2 from an attestation document the caller JUST obtained from
/// its OWN `/dev/nsm`, WITHOUT verifying the certificate chain or the nonce.
///
/// # This is NOT a verification function. Read before using.
///
/// Every other entry point in this module (`verify_against`,
/// `verify_and_extract`, `verify_control_nonce_attestation`,
/// `verify_chain_attestation`) authenticates a document that came from SOMEONE
/// ELSE: in production it validates the AWS Nitro CA chain and the COSE
/// signature, and it binds the document to a live Noise session via the nonce.
/// This function does NONE of that. It only structurally decodes the COSE_Sign1
/// envelope and pulls out the PCRs. A document fed to it could be a forgery and
/// it would happily return whatever PCRs the forgery claims.
///
/// That is acceptable for, and ONLY for, one caller: a node deriving its OWN
/// self-PCR digest from a document it just requested from its OWN local
/// `/dev/nsm`. The local NSM device is inside the node's trusted computing base
/// (on real Nitro it is the hardware module measuring this very VM; under
/// QEMU's nitro-enclave machine it is the emulated module measuring the same),
/// so there is no cert chain to trust (the node is reading its own hardware
/// measurements, not authenticating a remote party) and there is no Noise
/// session to bind to (the node generated the request itself, with an arbitrary
/// nonce). This replaces a host-supplied PCR allowlist, which the host (the
/// adversary) could otherwise choose to admit a rogue image into the mesh.
///
/// Do NOT use this on a document received over the network, ever: use
/// [`verify_and_extract`] (peer attestation) or [`verify_against`] (pinned
/// identity) for that.
pub fn extract_own_pcrs(attestation_data: &[u8]) -> Result<Pcrs, AttestationError> {
    // Structural decode only: no cert chain, no signature, no nonce. The
    // `debug_mode = true` arm of `parse_and_validate` is exactly this
    // (decode_attestation_document), and it is correct here on BOTH QEMU and
    // real Nitro because the caller is reading its own local device, not
    // authenticating a remote party.
    let doc = parse_and_validate(attestation_data, true)?;
    let hex_pcrs = att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;
    Ok(Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    })
}

/// Verify a chain-link attestation document.
///
/// Used by the backend's `POST /enclaves/{id}/chain-links` ingest path
/// (#47): each chain link (`boot`, `upgrade`, `revocation`) carries a
/// hardware-signed `attestation` whose `user_data` field commits to the
/// link's `payload` via `sha256(payload)`. This function performs the
/// minimum-trust check required at ingest:
///
/// 1. Parse + structural validation of the COSE_Sign1 wrapper (same as
///    [`verify_against`] / [`verify_and_extract`]).
/// 2. `attestation.user_data == sha256(payload)` — the binding that
///    makes the chain entry tamper-evident.
/// 3. PCR0/1/2 in the doc equal `expected_pcrs` (the backend's recorded
///    PCRs for this enclave, post-build).
///
/// In production mode (`debug_mode = false`), the AWS Nitro CA chain is
/// validated and the COSE signature is verified by the upstream
/// `attestation-doc-validation` crate, same as the existing entry
/// points. In `debug_mode`, only structural validity is required —
/// matching QEMU's emulated NSM device, which signs documents with its
/// own key instead of the AWS CA (and the `test-utils` doc builders,
/// which carry placeholder signatures).
///
/// The doc's `nonce` field is **not** checked here. The chain-link
/// attestations are not produced in the context of a Noise session, so
/// there is no handshake hash to bind against; the binding lives in
/// `user_data` instead. Any value in `nonce` is accepted.
pub fn verify_chain_attestation(
    attestation_data: &[u8],
    payload: &[u8],
    expected_pcrs: &Pcrs,
    debug_mode: bool,
) -> Result<(), AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = parse_and_validate(attestation_data, debug_mode)?;

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::PayloadBindingMismatch)?;
    let expected: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.finalize().into()
    };
    if user_data.as_slice() != expected {
        return Err(AttestationError::PayloadBindingMismatch);
    }

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    Ok(())
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
        /// 65-byte uncompressed SEC1 ECDSA P-256 verifying key. Encoded
        /// into the doc's `user_data` field — [`super::verify_and_extract`]
        /// requires this to be a 65-byte pubkey with the SEC1 prefix
        /// `0x04` (#47).
        pub control_pubkey: [u8; super::CONTROL_PUBKEY_LEN],
    }

    impl FakeAttestation {
        /// Build a fixture with all three PCRs derived from `seed` and a
        /// synthetic but structurally-valid SEC1 control pubkey (prefix
        /// `0x04`, the remaining 64 bytes filled with `seed | 0x80`).
        /// The synthetic pubkey will NOT decode as a valid P-256 point,
        /// so tests that only need to exercise the verifier's
        /// length-and-prefix check can use this directly; tests that
        /// need a *real* P-256 keypair (to actually sign) should use
        /// [`Self::with_seed_and_pubkey`] with bytes from a
        /// `p256::ecdsa::SigningKey`.
        pub fn with_seed(seed: u8, handshake_hash: Vec<u8>) -> Self {
            let mut control_pubkey = [seed.wrapping_add(0x80); super::CONTROL_PUBKEY_LEN];
            control_pubkey[0] = 0x04;
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                handshake_hash,
                control_pubkey,
            }
        }

        /// Like [`Self::with_seed`] but with a caller-supplied control
        /// pubkey (typically `VerifyingKey::to_encoded_point(false)` from
        /// a real `p256::ecdsa::SigningKey` the test holds for signing).
        pub fn with_seed_and_pubkey(
            seed: u8,
            handshake_hash: Vec<u8>,
            control_pubkey: [u8; super::CONTROL_PUBKEY_LEN],
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

    /// Builder for synthetic control-nonce attestation documents
    /// accepted by
    /// [`verify_control_nonce_attestation`](super::verify_control_nonce_attestation)
    /// in debug mode. Mirrors the in-enclave server's
    /// `RequestAttestation` reply shape: `nonce` carries the Noise
    /// handshake hash, `user_data` carries the 32-byte control nonce.
    pub struct FakeControlNonceAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// Raw Noise handshake hash, encoded verbatim into the doc's
        /// `nonce` field (the verifier base64-encodes before comparing).
        pub handshake_hash: Vec<u8>,
        /// Encoded into the doc's `user_data` field. 32 bytes on the
        /// happy path; tests exercising the length check can override.
        pub control_nonce: Vec<u8>,
    }

    impl FakeControlNonceAttestation {
        /// Build a fixture with all three PCRs derived from `seed`.
        pub fn with_seed(seed: u8, handshake_hash: Vec<u8>, control_nonce: [u8; 32]) -> Self {
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                handshake_hash,
                control_nonce: control_nonce.to_vec(),
            }
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
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                0,
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.control_nonce.clone()),
                Some(self.handshake_hash.clone()),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                CborValue::Bytes(vec![0u8; 96]),
            ]);

            let mut out = Vec::new();
            ciborium::into_writer(&cose, &mut out).expect("ciborium encode COSE_Sign1");
            out
        }
    }

    /// Builder for synthetic chain-link attestation documents accepted
    /// by [`verify_chain_attestation`](super::verify_chain_attestation)
    /// in debug mode. Differs from [`FakeAttestation`] in two ways:
    ///   * `user_data` carries the SHA-256 of a caller-supplied
    ///     `payload` (not the control pubkey, which the chain ingest
    ///     path doesn't read).
    ///   * `nonce` is irrelevant to the chain ingest verifier and is
    ///     populated with a fixed zero-padded value so the doc still
    ///     serialises.
    pub struct FakeChainAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// 32-byte SHA-256 of the chain link's payload. Set by
        /// [`Self::for_payload`]; tests that want to exercise a
        /// `user_data` mismatch can override after construction.
        pub user_data: Vec<u8>,
    }

    impl FakeChainAttestation {
        /// Build a fixture with all three PCRs derived from `seed` and
        /// `user_data` set to `sha256(payload)`. Drop-in for the chain
        /// ingest verifier's happy path.
        pub fn for_payload(seed: u8, payload: &[u8]) -> Self {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(payload);
            let user_data: Vec<u8> = hasher.finalize().to_vec();
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                user_data,
            }
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// `debug_mode` chain-attestation verify path.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                0,
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.user_data.clone()),
                // Nonce is not consulted by `verify_chain_attestation`,
                // but the doc has to carry one to serialise. Zero-padded
                // to a length the structure-validator accepts.
                Some(vec![0u8; 32]),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
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
    fn extract_own_pcrs_returns_doc_pcrs_without_nonce_or_chain() {
        // A document the node "just got from its own /dev/nsm" (here a
        // FakeAttestation fixture). extract_own_pcrs must return its PCR0/1/2
        // verbatim with no nonce/cert-chain check, so the node can derive its
        // own self-PCR digest regardless of the throwaway/self-signed key.
        let fake = test_utils::FakeAttestation::with_seed(0x5a, hh());
        let bytes = fake.encode();

        let pcrs = extract_own_pcrs(&bytes).expect("extract own pcrs");
        assert_eq!(pcrs.pcr0, fake.pcr0);
        assert_eq!(pcrs.pcr1, fake.pcr1);
        assert_eq!(pcrs.pcr2, fake.pcr2);

        // The digest matches what verify_and_extract derives for the same doc,
        // i.e. it is the SAME identity a peer would compute, just without the
        // verification a peer document requires.
        let verified = verify_and_extract(&bytes, &hh(), true).expect("verify");
        assert_eq!(pcrs.digest(), verified.pcrs.digest());
    }

    #[test]
    fn extract_own_pcrs_ignores_the_nonce_entirely() {
        // Unlike verify_and_extract, extract_own_pcrs takes no handshake hash
        // and never inspects the nonce: a doc minted with one nonce still
        // yields its PCRs. (The node mints the request itself with an arbitrary
        // nonce; there is no session to bind to.)
        let fake = test_utils::FakeAttestation::with_seed(0x77, vec![0xde; 32]);
        let pcrs = extract_own_pcrs(&fake.encode()).expect("extract own pcrs");
        assert_eq!(pcrs.pcr0, fake.pcr0);
    }

    #[test]
    fn extract_own_pcrs_rejects_garbage_bytes() {
        let err = extract_own_pcrs(b"not a cose document").unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_control_nonce_attestation_returns_attested_nonce() {
        let nonce = [0xab; 32];
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), nonce);
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let got = verify_control_nonce_attestation(&fake.encode(), &hh(), &expected, true)
            .expect("verify");
        assert_eq!(got, nonce);
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_wrong_pcrs() {
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        let wrong = Pcrs {
            pcr0: vec![0xff; 48],
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let err =
            verify_control_nonce_attestation(&fake.encode(), &hh(), &wrong, true).unwrap_err();
        assert!(matches!(err, AttestationError::Validation(_)), "{err}");
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_wrong_handshake_hash() {
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        let other_hh: Vec<u8> = (100u8..132).collect();

        let err = verify_control_nonce_attestation(&fake.encode(), &other_hh, &expected, true)
            .unwrap_err();
        assert!(matches!(err, AttestationError::Validation(_)), "{err}");
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_non_32_byte_user_data() {
        let mut fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        fake.control_nonce = vec![0xab; 16]; // wrong length
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let err =
            verify_control_nonce_attestation(&fake.encode(), &hh(), &expected, true).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlNonce),
            "{err}"
        );
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

    fn pcrs_from_seed(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    #[test]
    fn verify_chain_attestation_accepts_well_formed_link_in_debug_mode() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x33, &payload);
        let bytes = fake.encode();
        let expected_pcrs = pcrs_from_seed(0x33);

        verify_chain_attestation(&bytes, &payload, &expected_pcrs, true)
            .expect("valid chain attestation must pass");
    }

    #[test]
    fn verify_chain_attestation_rejects_mismatched_payload_binding() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x44, &payload);
        let bytes = fake.encode();
        let expected_pcrs = pcrs_from_seed(0x44);

        // Same attestation, different payload — user_data binds to the
        // original, so the verifier must reject the substitution.
        let err = verify_chain_attestation(&bytes, b"DIFFERENT", &expected_pcrs, true)
            .expect_err("payload swap must fail the binding check");
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_attestation_rejects_pcr_mismatch() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x55, &payload);
        let bytes = fake.encode();
        // Wrong expected PCRs — the caller's recorded PCRs disagree with
        // what the doc carries. Verifier must reject.
        let mismatched_pcrs = pcrs_from_seed(0x99);

        let err = verify_chain_attestation(&bytes, &payload, &mismatched_pcrs, true)
            .expect_err("PCR mismatch must fail");
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_attestation_rejects_doc_without_user_data() {
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let payload = b"any-payload".to_vec();
        let pcrs = pcrs_from_seed(0x77);

        let mut pcr_map = BTreeMap::new();
        pcr_map.insert(0usize, pcrs.pcr0.clone());
        pcr_map.insert(1usize, pcrs.pcr1.clone());
        pcr_map.insert(2usize, pcrs.pcr2.clone());
        pcr_map.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            0,
            pcr_map,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            None, // user_data missing — the case under test.
            Some(vec![0u8; 32]),
            None,
        );

        let mut doc_bytes = Vec::new();
        ciborium::into_writer(&doc, &mut doc_bytes).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(doc_bytes),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_chain_attestation(&bytes, &payload, &pcrs, true)
            .expect_err("missing user_data must be rejected");
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
    }
}
