//! Self-hosted control-key custody helpers (#48).
//!
//! In self-hosted custody the backend never holds the control private
//! key: the CLI signs upgrade confirmations and revocations with a key
//! it keeps locally (passphrase-protected keyfile or YubiKey PIV). Both
//! sides must agree on the exact bytes the envelope signature covers,
//! which are the CBOR encoding of the [`ControlCommand`] the enclave
//! decodes. These helpers are that single encoding path: the backend's
//! managed flow and the CLI's self-hosted flow both call them, so the
//! bytes can never drift between the two.
//!
//! The module also carries the signing-request DTOs exchanged over the
//! two-phase confirm/revoke HTTP endpoints (`.../confirm/prepare` and
//! `.../confirm/submit`, plus the revoke pair), shared verbatim by the
//! CLI and the backend, and the DER to raw `r || s` re-encoding helper
//! for signatures produced by PIV hardware or OpenSSL.

use serde::{Deserialize, Serialize};

use crate::{ControlCommand, RekeyParams};

/// CBOR-encode a [`ControlCommand::PrepareUpgrade`].
///
/// Returns the exact bytes the ENVELOPE signature must be computed
/// over (and that travel as `ClientMessage::Control.payload`). The
/// enclave verifies the envelope signature against these bytes and
/// then decodes them, so any re-encoding on the way breaks
/// verification.
///
/// `payload` is the CBOR-encoded [`crate::chain::UpgradePayload`] and
/// `payload_signature` the 64-byte raw `r || s` inner signature over
/// it (see [`der_signature_to_raw`] for hardware signers that emit
/// DER).
pub fn encode_prepare_upgrade(
    payload: &[u8],
    payload_signature: &[u8; 64],
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
    payload_signature: &[u8; 64],
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
/// `r || s` wire format (#47): each scalar 32 bytes, big-endian,
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
/// (self-hosted custody, #48): everything the CLI needs to assemble and
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
/// and `.../revoke/submit` (#48): the fully-assembled command plus its
/// envelope signature. The backend checks the decoded command matches
/// what prepare issued (state-machine consistency only; the enclave is
/// the real verifier) and dispatches it over the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmSubmitRequest {
    /// CBOR-encoded [`ControlCommand`] as produced by
    /// [`encode_prepare_upgrade`] / [`encode_revoke_upgrade`], base64.
    #[serde(with = "base64_vec")]
    pub command: Vec<u8>,
    /// 64-byte raw `r || s` P-256 signature over `command`, base64.
    #[serde(with = "base64_vec")]
    pub envelope_signature: Vec<u8>,
}

/// Revoke submissions carry the same shape as confirm submissions.
pub type RevokeSubmitRequest = ConfirmSubmitRequest;

/// Response body of `POST /enclaves/{id}/upgrades/{uid}/revoke/prepare`
/// (#48). Mirrors [`ConfirmPrepareResponse`] with the `RevokeUpgrade`
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
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Serde adapter: `[u8; 32]` as a standard-base64 (padded) JSON string.
/// Rejects any decoded length other than exactly 32 bytes.
mod base64_array32 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let v = STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len())))
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

    /// The load-bearing property (#48): a command the CLI assembles from a
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

        let cli_cmd =
            encode_prepare_upgrade(&back.payload, &payload_sig, back.rekey, back.nonce);
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
