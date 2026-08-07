//! Self-hosted control-key custody helpers.
//!
//! In self-hosted custody the backend never holds the control private
//! key: the CLI signs upgrade confirmations and revocations with a key
//! it keeps locally (FIDO2 hardware token, YubiKey PIV, or a future
//! passphrase-protected keyfile). Both
//! sides must agree on the exact bytes the envelope signature covers,
//! which are the CBOR encoding of the [`ControlCommand`] the enclave
//! decodes. These helpers are that single encoding path: the backend's
//! managed flow and the CLI's self-hosted flow both call them, so the
//! bytes can never drift between the two.
//!
//! The module also carries the signing-request DTOs exchanged over the
//! two-phase confirm/revoke HTTP endpoints (`.../confirm/prepare` and
//! `.../confirm/submit`, plus the revoke pair), shared verbatim by the
//! CLI and the backend. Control proofs are either the original raw
//! P-256 signature (PIV/managed custody) or a versioned FIDO2 assertion
//! produced by a CTAP2 authenticator.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{ControlCommand, RekeyParams};

/// RP ID used for Enclavia control-key credentials.
///
/// This is deliberately protocol-wide and not supplied by the host or
/// backend: the authenticator binds every credential and assertion to
/// its SHA-256 hash, and the in-enclave verifier checks that hash.
pub const FIDO2_RP_ID: &str = "control.enclavia.io";

/// Web origin supplied to CTAP client implementations which model the
/// browser-side WebAuthn checks. Direct CTAP2 uses [`FIDO2_RP_ID`] for
/// the cryptographic RP binding.
pub const FIDO2_ORIGIN: &str = "https://control.enclavia.io";

/// Domain separator for the 32-byte CTAP2 `clientDataHash`.
const FIDO2_CLIENT_DATA_CONTEXT: &[u8] = b"enclavia-control-fido2-v1\0";

/// Prefix distinguishing a FIDO2 proof from the legacy 64-byte raw
/// ECDSA signature. The remainder is CBOR-encoded [`Fido2Assertion`].
const FIDO2_PROOF_PREFIX: &[u8] = b"enclavia-fido2-proof-v1\0";

/// Maximum accepted size of a versioned FIDO2 control proof.
///
/// A normal proof is only a few hundred bytes. Keeping a generous 4 KiB
/// ceiling bounds allocation and CBOR work before signature
/// verification on attacker-reachable enclave paths.
pub const MAX_FIDO2_PROOF_SIZE: usize = 4 * 1024;

/// CTAP2 assertion carried in either a control-command envelope
/// signature or an inner upgrade-chain payload signature.
///
/// The credential ID is included so callers can identify which
/// hardware credential produced the proof. Verification is ultimately
/// bound to the control public key baked into the enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fido2Assertion {
    /// Credential selected by the CTAP2 `getAssertion` operation.
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    /// Exact WebAuthn authenticator data (`rpIdHash || flags ||
    /// signCount || extensions`).
    #[serde(with = "serde_bytes")]
    pub authenticator_data: Vec<u8>,
    /// ASN.1 DER-encoded ES256 assertion signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl Fido2Assertion {
    /// Encode this assertion into the versioned opaque proof format
    /// carried by the existing `Vec<u8>` signature fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = FIDO2_PROOF_PREFIX.to_vec();
        ciborium::into_writer(self, &mut out)
            .expect("CBOR encoding a Fido2Assertion into a Vec cannot fail");
        out
    }

    /// Decode a versioned FIDO2 proof, rejecting unknown formats and
    /// trailing data.
    pub fn decode(proof: &[u8]) -> Result<Self, ControlProofError> {
        if proof.len() > MAX_FIDO2_PROOF_SIZE {
            return Err(ControlProofError::Fido2ProofTooLarge {
                actual: proof.len(),
                max: MAX_FIDO2_PROOF_SIZE,
            });
        }
        let body = proof
            .strip_prefix(FIDO2_PROOF_PREFIX)
            .ok_or(ControlProofError::UnsupportedFormat)?;
        let mut cursor = std::io::Cursor::new(body);
        let assertion: Self = ciborium::from_reader(&mut cursor)
            .map_err(|e| ControlProofError::MalformedFido2(e.to_string()))?;
        if cursor.position() != body.len() as u64 {
            return Err(ControlProofError::Fido2TrailingData);
        }
        Ok(assertion)
    }
}

/// Proof family accepted by the shared control-key verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlProofKind {
    /// Original 64-byte low-S P-256 `r || s` signature.
    P256Raw,
    /// CTAP2/WebAuthn ES256 assertion.
    Fido2,
}

/// Metadata returned after successful proof verification.
#[must_use = "FIDO2 verification metadata carries an authenticated signature counter"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedControlProof {
    pub kind: ControlProofKind,
    /// Authenticated FIDO2 signature counter. `None` for legacy raw
    /// signatures.
    ///
    /// This verifier authenticates the counter but cannot establish
    /// freshness without prior state. Call [`check_fido2_sign_count`]
    /// when a previous counter is available. FIDO2 authenticators that
    /// do not implement counters are allowed to return zero.
    pub sign_count: Option<u32>,
}

/// A FIDO2 signature counter failed the WebAuthn monotonicity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Fido2SignCountError {
    #[error(
        "FIDO2 signature counter did not advance (previous {previous}, current {current}); \
         the credential may have been cloned or reset"
    )]
    DidNotAdvance { previous: u32, current: u32 },
}

/// Check a newly authenticated FIDO2 signature counter against the
/// previously accepted value.
///
/// A pair of zero counters is accepted because CTAP2 permits
/// authenticators without counter support. If either value is nonzero,
/// the new value must be strictly greater than the previous value.
pub fn check_fido2_sign_count(previous: u32, current: u32) -> Result<(), Fido2SignCountError> {
    if previous == 0 && current == 0 {
        return Ok(());
    }
    if current <= previous {
        return Err(Fido2SignCountError::DidNotAdvance { previous, current });
    }
    Ok(())
}

/// A malformed or invalid control-key proof.
#[derive(Debug, thiserror::Error)]
pub enum ControlProofError {
    #[error(
        "unsupported proof format (expected 64 bytes raw P-256 or a versioned FIDO2 assertion)"
    )]
    UnsupportedFormat,
    #[error("invalid raw P-256 signature encoding")]
    InvalidRawSignature,
    #[error("raw P-256 signature verification failed")]
    InvalidRawSignatureValue,
    #[error("malformed FIDO2 proof: {0}")]
    MalformedFido2(String),
    #[error("FIDO2 proof is {actual} bytes; maximum accepted size is {max} bytes")]
    Fido2ProofTooLarge { actual: usize, max: usize },
    #[error("FIDO2 proof contains trailing data")]
    Fido2TrailingData,
    #[error("FIDO2 credential ID is empty or exceeds 1023 bytes")]
    InvalidCredentialId,
    #[error("FIDO2 authenticator data is shorter than 37 bytes")]
    AuthenticatorDataTooShort,
    #[error("FIDO2 assertion is scoped to a different RP ID")]
    RpIdHashMismatch,
    #[error("FIDO2 assertion does not prove user presence")]
    UserPresenceRequired,
    #[error("FIDO2 assertion does not prove user verification")]
    UserVerificationRequired,
    #[error("FIDO2 assertion contains attested credential data")]
    UnexpectedAttestedCredentialData,
    #[error("FIDO2 assertion contains extension data or trailing authenticator bytes")]
    UnexpectedAuthenticatorData,
    #[error("FIDO2 assertion sets reserved authenticator-data flags")]
    ReservedAuthenticatorFlags,
    #[error("FIDO2 assertion has an invalid backup-state flag combination")]
    InvalidBackupFlags,
    #[error(
        "backup-eligible FIDO2 credentials are not accepted; use a hardware-bound credential \
         that cannot be synced or exported"
    )]
    BackupEligibleCredential,
    #[error("FIDO2 assertion signature is not DER-encoded ES256")]
    InvalidFido2Signature,
    #[error("FIDO2 assertion signature verification failed")]
    InvalidFido2SignatureValue,
}

impl ControlProofError {
    /// Whether the error describes bytes that cannot represent a proof,
    /// rather than a well-shaped proof which failed verification.
    pub fn is_shape_error(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedFormat
                | Self::InvalidRawSignature
                | Self::MalformedFido2(_)
                | Self::Fido2ProofTooLarge { .. }
                | Self::Fido2TrailingData
                | Self::InvalidCredentialId
                | Self::AuthenticatorDataTooShort
                | Self::UnexpectedAttestedCredentialData
                | Self::UnexpectedAuthenticatorData
                | Self::ReservedAuthenticatorFlags
                | Self::InvalidBackupFlags
                | Self::InvalidFido2Signature
        )
    }
}

/// Compute the exact 32 bytes passed as CTAP2 `clientDataHash`.
///
/// Enclavia is a native client rather than a browser. Domain-separating
/// the hash prevents an assertion requested by another CTAP2 protocol
/// from authorizing an Enclavia control message with the same bytes. The
/// length-prefixed credential ID makes that otherwise-opaque proof field
/// part of what the authenticator signs.
pub fn fido2_client_data_hash(message: &[u8], credential_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FIDO2_CLIENT_DATA_CONTEXT);
    hasher.update((credential_id.len() as u32).to_be_bytes());
    hasher.update(credential_id);
    hasher.update(message);
    hasher.finalize().into()
}

/// Verify either a legacy raw P-256 signature or a CTAP2-only FIDO2
/// assertion against the enclave's registered control public key.
///
/// FIDO2 verification requires the fixed RP ID, UP and UV flags, a
/// hardware-bound (not backup-eligible) credential, a structurally
/// valid extension-free authenticator-data record, and an ES256
/// signature over `authenticatorData || clientDataHash`. Proofs are
/// size-limited before CBOR decoding.
///
/// The returned signature counter is authenticated here but must be
/// compared with prior state by the caller; see
/// [`check_fido2_sign_count`].
pub fn verify_control_proof(
    verifying_key: &p256::ecdsa::VerifyingKey,
    message: &[u8],
    proof: &[u8],
) -> Result<VerifiedControlProof, ControlProofError> {
    use p256::ecdsa::signature::Verifier as _;

    if proof.len() == 64 {
        let signature = p256::ecdsa::Signature::from_slice(proof)
            .map_err(|_| ControlProofError::InvalidRawSignature)?;
        verifying_key
            .verify(message, &signature)
            .map_err(|_| ControlProofError::InvalidRawSignatureValue)?;
        return Ok(VerifiedControlProof {
            kind: ControlProofKind::P256Raw,
            sign_count: None,
        });
    }

    let assertion = Fido2Assertion::decode(proof)?;
    if assertion.credential_id.is_empty() || assertion.credential_id.len() > 1023 {
        return Err(ControlProofError::InvalidCredentialId);
    }
    if assertion.authenticator_data.len() < 37 {
        return Err(ControlProofError::AuthenticatorDataTooShort);
    }

    let expected_rp_id_hash: [u8; 32] = Sha256::digest(FIDO2_RP_ID.as_bytes()).into();
    if assertion.authenticator_data[..32] != expected_rp_id_hash {
        return Err(ControlProofError::RpIdHashMismatch);
    }

    let flags = assertion.authenticator_data[32];
    const USER_PRESENT: u8 = 0x01;
    const USER_VERIFIED: u8 = 0x04;
    const BACKUP_ELIGIBLE: u8 = 0x08;
    const BACKUP_STATE: u8 = 0x10;
    const ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
    const EXTENSION_DATA: u8 = 0x80;
    const RESERVED_FLAGS: u8 = 0x02 | 0x20;
    if flags & USER_PRESENT == 0 {
        return Err(ControlProofError::UserPresenceRequired);
    }
    if flags & USER_VERIFIED == 0 {
        return Err(ControlProofError::UserVerificationRequired);
    }
    if flags & ATTESTED_CREDENTIAL_DATA != 0 {
        return Err(ControlProofError::UnexpectedAttestedCredentialData);
    }
    if flags & EXTENSION_DATA != 0 || assertion.authenticator_data.len() != 37 {
        return Err(ControlProofError::UnexpectedAuthenticatorData);
    }
    if flags & RESERVED_FLAGS != 0 {
        return Err(ControlProofError::ReservedAuthenticatorFlags);
    }
    if flags & BACKUP_STATE != 0 && flags & BACKUP_ELIGIBLE == 0 {
        return Err(ControlProofError::InvalidBackupFlags);
    }
    if flags & BACKUP_ELIGIBLE != 0 {
        return Err(ControlProofError::BackupEligibleCredential);
    }

    let sign_count = u32::from_be_bytes(
        assertion.authenticator_data[33..37]
            .try_into()
            .expect("length checked above"),
    );
    let signature = p256::ecdsa::Signature::from_der(&assertion.signature)
        .map_err(|_| ControlProofError::InvalidFido2Signature)?;
    let client_data_hash = fido2_client_data_hash(message, &assertion.credential_id);
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| ControlProofError::InvalidFido2SignatureValue)?;

    Ok(VerifiedControlProof {
        kind: ControlProofKind::Fido2,
        sign_count: Some(sign_count),
    })
}

/// CBOR-encode a [`ControlCommand::PrepareUpgrade`].
///
/// Returns the exact bytes the ENVELOPE signature must be computed
/// over (and that travel as `ClientMessage::Control.payload`). The
/// enclave verifies the envelope signature against these bytes and
/// then decodes them, so any re-encoding on the way breaks
/// verification.
///
/// `payload` is the CBOR-encoded [`crate::chain::UpgradePayload`] and
/// `payload_signature` is either the legacy 64-byte raw `r || s`
/// signature or a versioned FIDO2 assertion over it.
pub fn encode_prepare_upgrade(
    payload: &[u8],
    payload_signature: &[u8],
    rekey: Option<RekeyParams>,
    nonce: [u8; 32],
) -> Vec<u8> {
    let cmd = ControlCommand::PrepareUpgrade {
        payload: payload.to_vec(),
        payload_signature: payload_signature.to_vec(),
        rekey,
        nonce,
    };
    encode_command(&cmd)
}

/// CBOR-encode a [`ControlCommand::RevokeUpgrade`]. Same envelope
/// contract as [`encode_prepare_upgrade`]; `payload` is the
/// CBOR-encoded [`crate::chain::RevocationPayload`].
pub fn encode_revoke_upgrade(
    payload: &[u8],
    payload_signature: &[u8],
    rollback: bool,
    nonce: [u8; 32],
) -> Vec<u8> {
    let cmd = ControlCommand::RevokeUpgrade {
        payload: payload.to_vec(),
        payload_signature: payload_signature.to_vec(),
        rollback,
        nonce,
    };
    encode_command(&cmd)
}

/// Single serialization path for signed control commands. Writing into
/// a `Vec` cannot fail for these plain-data enums, so the panic is
/// unreachable in practice; panicking (vs. returning `Result`) keeps
/// the two encode helpers infallible for callers on both sides.
fn encode_command(cmd: &ControlCommand) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(cmd, &mut buf)
        .expect("CBOR encoding a ControlCommand into a Vec cannot fail");
    buf
}

/// Failure re-encoding a DER ECDSA signature to raw `r || s`.
#[derive(Debug, thiserror::Error)]
pub enum DerSignatureError {
    /// The bytes did not parse as a DER-encoded P-256 ECDSA signature.
    #[error("invalid DER ECDSA P-256 signature: {0}")]
    InvalidDer(#[source] p256::ecdsa::Error),
}

/// Re-encode a DER ECDSA P-256 signature to the locked-in 64-byte raw
/// `r || s` wire format: each scalar 32 bytes, big-endian,
/// zero-padded.
///
/// PIV hardware (YubiKey) and OpenSSL emit DER, and may emit a high-S
/// signature; the result is normalized to low-S so the enclave-side
/// verifier accepts it regardless of which form the hardware produced.
pub fn der_signature_to_raw(der: &[u8]) -> Result<[u8; 64], DerSignatureError> {
    let sig = p256::ecdsa::Signature::from_der(der).map_err(DerSignatureError::InvalidDer)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Ok(out)
}

/// Response body of `POST /enclaves/{id}/upgrades/{uid}/confirm/prepare`
/// (self-hosted custody): everything the CLI needs to assemble and
/// sign the `PrepareUpgrade` command offline.
///
/// The CLI signs `payload` (inner signature), calls
/// [`encode_prepare_upgrade`] with `payload`, that signature, `rekey`,
/// and `nonce`, then signs the returned bytes (envelope signature) and
/// submits both via [`ConfirmSubmitRequest`].
///
/// `rekey` is embedded as the [`RekeyParams`] struct itself: its byte
/// field serializes as a JSON number array (verbose but lossless), and
/// carrying the typed struct guarantees the CLI re-embeds the exact
/// value the backend prepared, so the CBOR command it assembles is
/// byte-identical to what the backend would have assembled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPrepareResponse {
    /// CBOR-encoded [`crate::chain::UpgradePayload`], base64.
    #[serde(with = "base64_vec")]
    pub payload: Vec<u8>,
    /// Current single-use control nonce fetched from the live enclave,
    /// base64. Stays valid across the offline signing round-trip (the
    /// enclave rotates it only when a `Control` message is processed).
    #[serde(with = "base64_array32")]
    pub nonce: [u8; 32],
    /// Storage re-key parameters, `None` for stateless enclaves.
    pub rekey: Option<RekeyParams>,
    /// Activation time baked into `payload`, RFC3339. Informational:
    /// the signed bytes are `payload`, this is for CLI display.
    pub valid_from: String,
}

/// Request body of `POST /enclaves/{id}/upgrades/{uid}/confirm/submit`
/// and `.../revoke/submit`: the fully-assembled command plus its
/// envelope signature. The backend checks the decoded command matches
/// what prepare issued (state-machine consistency only; the enclave is
/// the real verifier) and dispatches it over the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmSubmitRequest {
    /// CBOR-encoded [`ControlCommand`] as produced by
    /// [`encode_prepare_upgrade`] / [`encode_revoke_upgrade`], base64.
    #[serde(with = "base64_vec")]
    pub command: Vec<u8>,
    /// Legacy raw P-256 signature or versioned FIDO2 assertion over
    /// `command`, base64.
    #[serde(with = "base64_vec")]
    pub envelope_signature: Vec<u8>,
}

/// Revoke submissions carry the same shape as confirm submissions.
pub type RevokeSubmitRequest = ConfirmSubmitRequest;

/// Response body of `POST /enclaves/{id}/upgrades/{uid}/revoke/prepare`
/// (self-hosted custody). Mirrors [`ConfirmPrepareResponse`] with the `RevokeUpgrade`
/// command's field set: `rollback` instead of `rekey`, and no
/// `valid_from` (revocations take effect immediately).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokePrepareResponse {
    /// CBOR-encoded [`crate::chain::RevocationPayload`], base64.
    #[serde(with = "base64_vec")]
    pub payload: Vec<u8>,
    /// Current single-use control nonce, base64.
    #[serde(with = "base64_array32")]
    pub nonce: [u8; 32],
    /// Whether the enclave must roll back the LUKS keyslot added at
    /// prepare time. Set by the backend from the staged row (a re-key
    /// happened iff a new KMS key was minted).
    pub rollback: bool,
}

/// Serde adapter: `Vec<u8>` as a standard-base64 (padded) JSON string,
/// matching the chain endpoint's byte-field convention.
mod base64_vec {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Serde adapter: `[u8; 32]` as a standard-base64 (padded) JSON string.
/// Rejects any decoded length other than exactly 32 bytes.
mod base64_array32 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let v = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    fn sample_rekey() -> RekeyParams {
        RekeyParams {
            new_public_key: vec![0xAB; 70],
            new_key_id: "arn:aws:kms:us-east-1:123:key/abc".into(),
        }
    }

    /// Replicate the backend's current encoding sequence (build the enum,
    /// `ciborium::into_writer`) so a helper drift shows up as a byte
    /// mismatch here.
    fn backend_style_encode(cmd: &ControlCommand) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(cmd, &mut buf).unwrap();
        buf
    }

    #[test]
    fn encode_prepare_upgrade_round_trips_and_matches_backend_encoding() {
        let payload = vec![1u8, 2, 3, 4];
        let payload_sig = [0xDEu8; 64];
        let nonce = [0x42u8; 32];

        let bytes = encode_prepare_upgrade(&payload, &payload_sig, Some(sample_rekey()), nonce);

        // Byte-identical to the backend's encoding path.
        let expected = backend_style_encode(&ControlCommand::PrepareUpgrade {
            payload: payload.clone(),
            payload_signature: payload_sig.to_vec(),
            rekey: Some(sample_rekey()),
            nonce,
        });
        assert_eq!(bytes, expected);

        // Decodes as the command the enclave expects.
        let back: ControlCommand = ciborium::from_reader(bytes.as_slice()).unwrap();
        match back {
            ControlCommand::PrepareUpgrade {
                payload: p,
                payload_signature: ps,
                rekey,
                nonce: n,
            } => {
                assert_eq!(p, payload);
                assert_eq!(ps, payload_sig.to_vec());
                let rk = rekey.expect("rekey present");
                assert_eq!(rk.new_public_key, vec![0xAB; 70]);
                assert_eq!(rk.new_key_id, "arn:aws:kms:us-east-1:123:key/abc");
                assert_eq!(n, nonce);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn encode_prepare_upgrade_stateless_matches_backend_encoding() {
        let bytes = encode_prepare_upgrade(&[0xAA], &[0xBB; 64], None, [1u8; 32]);
        let expected = backend_style_encode(&ControlCommand::PrepareUpgrade {
            payload: vec![0xAA],
            payload_signature: vec![0xBB; 64],
            rekey: None,
            nonce: [1u8; 32],
        });
        assert_eq!(bytes, expected);
    }

    #[test]
    fn encode_revoke_upgrade_round_trips_and_matches_backend_encoding() {
        let payload = vec![0xCCu8; 8];
        let payload_sig = [0xDDu8; 64];
        let nonce = [0x99u8; 32];

        for rollback in [true, false] {
            let bytes = encode_revoke_upgrade(&payload, &payload_sig, rollback, nonce);
            let expected = backend_style_encode(&ControlCommand::RevokeUpgrade {
                payload: payload.clone(),
                payload_signature: payload_sig.to_vec(),
                rollback,
                nonce,
            });
            assert_eq!(bytes, expected);

            let back: ControlCommand = ciborium::from_reader(bytes.as_slice()).unwrap();
            match back {
                ControlCommand::RevokeUpgrade {
                    payload: p,
                    rollback: rb,
                    nonce: n,
                    ..
                } => {
                    assert_eq!(p, payload);
                    assert_eq!(rb, rollback);
                    assert_eq!(n, nonce);
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn der_signature_to_raw_matches_direct_raw_encoding() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let msg = b"custody der test vector";
        let sig: Signature = sk.sign(msg);
        // Reference: low-S normalized raw bytes.
        let low = sig.normalize_s().unwrap_or(sig);

        let raw = der_signature_to_raw(sig.to_der().as_bytes()).unwrap();
        assert_eq!(raw, <[u8; 64]>::try_from(&low.to_bytes()[..]).unwrap());

        // The wire form must verify exactly as the enclave does: parse the
        // 64 raw bytes with from_slice, then verify.
        let vk = VerifyingKey::from(&sk);
        let parsed = Signature::from_slice(&raw).unwrap();
        vk.verify(msg, &parsed).unwrap();
    }

    #[test]
    fn der_signature_to_raw_normalizes_high_s() {
        let sk = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let msg = b"high-s normalization vector";
        let sig: Signature = sk.sign(msg);
        let low = sig.normalize_s().unwrap_or(sig);

        // Synthesize the high-S twin: s' = n - s. PIV hardware can emit
        // either form; the helper must map both onto the same low-S bytes.
        let (r, s) = low.split_scalars();
        let high_s = -*s.as_ref();
        let high = Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();
        assert!(high.normalize_s().is_some(), "twin must be high-S");

        let raw = der_signature_to_raw(high.to_der().as_bytes()).unwrap();
        assert_eq!(raw, <[u8; 64]>::try_from(&low.to_bytes()[..]).unwrap());

        let vk = VerifyingKey::from(&sk);
        let parsed = Signature::from_slice(&raw).unwrap();
        vk.verify(msg, &parsed).unwrap();
    }

    #[test]
    fn der_signature_to_raw_rejects_garbage() {
        assert!(der_signature_to_raw(&[0u8; 64]).is_err());
        assert!(der_signature_to_raw(b"not der").is_err());
        assert!(der_signature_to_raw(&[]).is_err());
    }

    fn fido2_proof(sk: &SigningKey, msg: &[u8], flags: u8) -> Vec<u8> {
        let mut authenticator_data = Sha256::digest(FIDO2_RP_ID.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&42u32.to_be_bytes());

        let credential_id = vec![0xA5; 32];
        let client_data_hash = fido2_client_data_hash(msg, &credential_id);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let signature: Signature = sk.sign(&signed);
        Fido2Assertion {
            credential_id,
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
        }
        .encode()
    }

    #[test]
    fn fido2_control_proof_verifies_with_up_and_uv() {
        let sk = SigningKey::from_bytes(&[17u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let msg = b"fido2 control proof";
        let proof = fido2_proof(&sk, msg, 0x01 | 0x04);

        let verified = verify_control_proof(&vk, msg, &proof).unwrap();
        assert_eq!(verified.kind, ControlProofKind::Fido2);
        assert_eq!(verified.sign_count, Some(42));

        let decoded = Fido2Assertion::decode(&proof).unwrap();
        assert_eq!(decoded.credential_id, vec![0xA5; 32]);
    }

    #[test]
    fn fido2_control_proof_rejects_tampering_and_missing_uv() {
        let sk = SigningKey::from_bytes(&[18u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let msg = b"fido2 protected bytes";

        let proof = fido2_proof(&sk, msg, 0x01 | 0x04);
        assert!(matches!(
            verify_control_proof(&vk, b"different bytes", &proof),
            Err(ControlProofError::InvalidFido2SignatureValue)
        ));

        let mut wrong_credential = Fido2Assertion::decode(&proof).unwrap();
        wrong_credential.credential_id[0] ^= 0x01;
        assert!(matches!(
            verify_control_proof(&vk, msg, &wrong_credential.encode()),
            Err(ControlProofError::InvalidFido2SignatureValue)
        ));

        let no_uv = fido2_proof(&sk, msg, 0x01);
        assert!(matches!(
            verify_control_proof(&vk, msg, &no_uv),
            Err(ControlProofError::UserVerificationRequired)
        ));

        let no_up = fido2_proof(&sk, msg, 0x04);
        assert!(matches!(
            verify_control_proof(&vk, msg, &no_up),
            Err(ControlProofError::UserPresenceRequired)
        ));
    }

    #[test]
    fn fido2_control_proof_rejects_wrong_rp_and_trailing_data() {
        let sk = SigningKey::from_bytes(&[19u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let msg = b"rp-bound proof";
        let proof = fido2_proof(&sk, msg, 0x01 | 0x04);

        let mut wrong_rp = Fido2Assertion::decode(&proof).unwrap();
        wrong_rp.authenticator_data[0] ^= 0x01;
        assert!(matches!(
            verify_control_proof(&vk, msg, &wrong_rp.encode()),
            Err(ControlProofError::RpIdHashMismatch)
        ));

        let mut extra_authenticator_data = Fido2Assertion::decode(&proof).unwrap();
        extra_authenticator_data.authenticator_data.push(0);
        assert!(matches!(
            verify_control_proof(&vk, msg, &extra_authenticator_data.encode()),
            Err(ControlProofError::UnexpectedAuthenticatorData)
        ));

        let mut trailing = proof;
        trailing.push(0);
        assert!(matches!(
            Fido2Assertion::decode(&trailing),
            Err(ControlProofError::Fido2TrailingData)
        ));
    }

    #[test]
    fn fido2_control_proof_rejects_backup_eligible_credentials() {
        let sk = SigningKey::from_bytes(&[21u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let msg = b"hardware-bound credential required";

        let backup_eligible = fido2_proof(&sk, msg, 0x01 | 0x04 | 0x08);
        assert!(matches!(
            verify_control_proof(&vk, msg, &backup_eligible),
            Err(ControlProofError::BackupEligibleCredential)
        ));

        let invalid_backup_state = fido2_proof(&sk, msg, 0x01 | 0x04 | 0x10);
        assert!(matches!(
            verify_control_proof(&vk, msg, &invalid_backup_state),
            Err(ControlProofError::InvalidBackupFlags)
        ));
    }

    #[test]
    fn fido2_proof_size_is_bounded_before_decoding() {
        let oversized = vec![0u8; MAX_FIDO2_PROOF_SIZE + 1];
        assert!(matches!(
            Fido2Assertion::decode(&oversized),
            Err(ControlProofError::Fido2ProofTooLarge {
                actual,
                max: MAX_FIDO2_PROOF_SIZE,
            }) if actual == MAX_FIDO2_PROOF_SIZE + 1
        ));
    }

    #[test]
    fn fido2_signature_counter_must_advance_when_supported() {
        assert_eq!(check_fido2_sign_count(0, 0), Ok(()));
        assert_eq!(check_fido2_sign_count(0, 1), Ok(()));
        assert_eq!(check_fido2_sign_count(41, 42), Ok(()));
        assert_eq!(
            check_fido2_sign_count(42, 42),
            Err(Fido2SignCountError::DidNotAdvance {
                previous: 42,
                current: 42,
            })
        );
        assert_eq!(
            check_fido2_sign_count(42, 0),
            Err(Fido2SignCountError::DidNotAdvance {
                previous: 42,
                current: 0,
            })
        );
    }

    #[test]
    fn shared_verifier_preserves_legacy_raw_signatures() {
        let sk = SigningKey::from_bytes(&[20u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let msg = b"legacy control proof";
        let signature: Signature = sk.sign(msg);
        let raw = signature.normalize_s().unwrap_or(signature).to_bytes();

        let verified = verify_control_proof(&vk, msg, &raw).unwrap();
        assert_eq!(verified.kind, ControlProofKind::P256Raw);
        assert_eq!(verified.sign_count, None);
    }

    #[test]
    fn confirm_prepare_response_serde_round_trip() {
        let resp = ConfirmPrepareResponse {
            payload: vec![1, 2, 3],
            nonce: [0x11u8; 32],
            rekey: Some(sample_rekey()),
            valid_from: "2026-07-09T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ConfirmPrepareResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload, resp.payload);
        assert_eq!(back.nonce, resp.nonce);
        assert_eq!(back.valid_from, resp.valid_from);
        let rk = back.rekey.as_ref().unwrap();
        assert_eq!(rk.new_public_key, vec![0xAB; 70]);
        assert_eq!(rk.new_key_id, "arn:aws:kms:us-east-1:123:key/abc");

        // Byte fields are base64 strings on the wire, not number arrays.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["payload"].is_string());
        assert!(v["nonce"].is_string());
    }

    /// The load-bearing property: a command the CLI assembles from a
    /// JSON-round-tripped prepare response is byte-identical to the one the
    /// backend would have assembled from its in-memory values.
    #[test]
    fn rekey_survives_json_round_trip_byte_exactly() {
        let payload = vec![5u8; 16];
        let payload_sig = [0x77u8; 64];
        let nonce = [0x33u8; 32];

        let backend_cmd =
            encode_prepare_upgrade(&payload, &payload_sig, Some(sample_rekey()), nonce);

        let resp = ConfirmPrepareResponse {
            payload,
            nonce,
            rekey: Some(sample_rekey()),
            valid_from: "2026-07-09T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ConfirmPrepareResponse = serde_json::from_str(&json).unwrap();

        let cli_cmd = encode_prepare_upgrade(&back.payload, &payload_sig, back.rekey, back.nonce);
        assert_eq!(cli_cmd, backend_cmd);
    }

    #[test]
    fn confirm_submit_request_serde_round_trip() {
        let req = ConfirmSubmitRequest {
            command: vec![9, 8, 7],
            envelope_signature: vec![0x55; 64],
        };
        let json = serde_json::to_string(&req).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["command"].is_string());
        assert!(v["envelope_signature"].is_string());

        let back: ConfirmSubmitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command, req.command);
        assert_eq!(back.envelope_signature, req.envelope_signature);
    }

    #[test]
    fn revoke_prepare_response_serde_round_trip() {
        let resp = RevokePrepareResponse {
            payload: vec![4, 5, 6],
            nonce: [0x22u8; 32],
            rollback: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: RevokePrepareResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload, resp.payload);
        assert_eq!(back.nonce, resp.nonce);
        assert!(back.rollback);
    }

    #[test]
    fn nonce_deserialize_rejects_wrong_length() {
        // 31 bytes of base64 must not silently truncate or pad.
        let json = format!(
            r#"{{"payload":"AQID","nonce":"{}","rekey":null,"valid_from":"x"}}"#,
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 31])
            }
        );
        assert!(serde_json::from_str::<ConfirmPrepareResponse>(&json).is_err());
    }
}
