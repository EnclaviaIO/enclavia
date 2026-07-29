//! Control-key signers for self-hosted custody.
//!
//! [`ControlSigner`] is the seam between the two-phase confirm/revoke
//! flow and wherever the control private key actually lives. The
//! contract mirrors what `enclavia-server` verifies: `sign(msg)` must
//! return a 64-byte raw low-S `r || s` ECDSA P-256 signature such that
//! `p256::ecdsa::VerifyingKey::verify(msg, sig)` accepts it.
//! `VerifyingKey::verify` hashes the message with SHA-256 internally,
//! so hardware backends that sign a caller-provided digest (PIV) must
//! compute `SHA-256(msg)` themselves and sign that digest.
//!
//! Backends:
//! - [`YubiKeySigner`] (cargo feature `yubikey`, on by default): PIV
//!   ECDSA/P256 on a YubiKey. The key is generated on-device and never
//!   extractable; signing prompts for the PIN and (policy permitting) a
//!   touch.
//! - A passphrase-protected keyfile backend is planned as a follow-up
//!   and will implement the same trait.

use enclavia_protocol::custody::{
    ConfirmPrepareResponse, ConfirmSubmitRequest, RevokePrepareResponse, encode_prepare_upgrade,
    encode_revoke_upgrade,
};

use crate::error::CliError;
use crate::keys::{KeyBackend, KeyEntry};

/// A holder of the ECDSA P-256 control private key.
///
/// `Send`-bound so `Box<dyn ControlSigner>` can be held across an
/// `.await` point in an async, multi-threaded-executor caller (the MCP
/// server's confirm/revoke tools). Every impl already satisfies this:
/// `YubiKeySigner` wraps `pcsc::Card`, which is itself `unsafe impl
/// Send`.
pub trait ControlSigner: Send {
    /// The 65-byte uncompressed SEC1 public key (0x04 prefix), exactly
    /// as registered with the backend at enclave-create time.
    fn public_key(&self) -> [u8; 65];

    /// Sign `msg`: raw low-S `r || s` over `SHA-256(msg)`, i.e. exactly
    /// what `p256::ecdsa::VerifyingKey::verify(msg, sig)` accepts on
    /// the enclave side. Interactive backends may prompt (PIN, touch)
    /// on stderr.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], CliError>;
}

/// Build a signer for a key-index entry. When the CLI is built without
/// the `yubikey` feature (the library-face consumers do this to avoid
/// the pcsclite link dependency), YubiKey entries produce a clear
/// runtime error instead.
pub fn signer_for_entry(name: &str, entry: &KeyEntry) -> Result<Box<dyn ControlSigner>, CliError> {
    let public_key = entry.public_key_bytes()?;
    match &entry.backend {
        KeyBackend::Yubikey { serial, slot } => {
            #[cfg(feature = "yubikey")]
            {
                let signer = YubiKeySigner::open(Some(*serial), slot, public_key)?;
                let _ = name;
                Ok(Box::new(signer))
            }
            #[cfg(not(feature = "yubikey"))]
            {
                let _ = (serial, slot, public_key);
                Err(CliError::Other(format!(
                    "key {name:?} is a YubiKey key, but this enclavia build has no YubiKey \
                     support (rebuild enclavia-cli with the default `yubikey` feature)"
                )))
            }
        }
    }
}

/// Assemble and sign a `PrepareUpgrade` submission from a prepare
/// response: inner signature over the chain payload, canonical CBOR
/// command via the shared protocol encoder, envelope signature over the
/// command bytes. Two `sign` calls (two YubiKey touches).
pub fn sign_confirm_submission(
    signer: &dyn ControlSigner,
    prep: &ConfirmPrepareResponse,
) -> Result<ConfirmSubmitRequest, CliError> {
    let inner = signer.sign(&prep.payload)?;
    let command = encode_prepare_upgrade(&prep.payload, &inner, prep.rekey.clone(), prep.nonce);
    let envelope = signer.sign(&command)?;
    Ok(ConfirmSubmitRequest {
        command,
        envelope_signature: envelope.to_vec(),
    })
}

/// Assemble and sign a `RevokeUpgrade` submission. Same shape as
/// [`sign_confirm_submission`] with the revoke command's field set.
pub fn sign_revoke_submission(
    signer: &dyn ControlSigner,
    prep: &RevokePrepareResponse,
) -> Result<ConfirmSubmitRequest, CliError> {
    let inner = signer.sign(&prep.payload)?;
    let command = encode_revoke_upgrade(&prep.payload, &inner, prep.rollback, prep.nonce);
    let envelope = signer.sign(&command)?;
    Ok(ConfirmSubmitRequest {
        command,
        envelope_signature: envelope.to_vec(),
    })
}

#[cfg(feature = "yubikey")]
mod yubikey;
#[cfg(feature = "yubikey")]
pub use yubikey::{
    GenerateParams, RecoveredKey, YubiKeySigner, generate_on_device, parse_slot,
    read_public_key_on_device,
};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use enclavia_protocol::ControlCommand;
    use enclavia_protocol::RekeyParams;
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use p256::ecdsa::signature::{Signer as _, Verifier as _};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    /// Software test double: a plain p256 signing key implementing the
    /// same contract the YubiKey backend must satisfy.
    struct InMemorySigner(SigningKey);

    impl InMemorySigner {
        fn new(seed: u8) -> Self {
            Self(SigningKey::from_bytes(&[seed; 32].into()).unwrap())
        }
    }

    impl ControlSigner for InMemorySigner {
        fn public_key(&self) -> [u8; 65] {
            VerifyingKey::from(&self.0)
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn sign(&self, msg: &[u8]) -> Result<[u8; 64], CliError> {
            let sig: Signature = self.0.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(<[u8; 64]>::try_from(&sig.to_bytes()[..]).unwrap())
        }
    }

    fn prepare_fixture(rekey: Option<RekeyParams>) -> ConfirmPrepareResponse {
        ConfirmPrepareResponse {
            payload: vec![0xA1; 24],
            nonce: [0x42; 32],
            rekey,
            valid_from: "2026-07-09T00:00:00Z".into(),
        }
    }

    /// Verify exactly as `enclavia-server::handle_control` does: parse
    /// the 64 raw bytes with `Signature::from_slice`, then
    /// `VerifyingKey::verify` (which hashes the message internally).
    fn verify_like_enclave(pubkey: &[u8; 65], msg: &[u8], sig: &[u8]) {
        let vk = VerifyingKey::from_sec1_bytes(pubkey).unwrap();
        let sig = Signature::from_slice(sig).unwrap();
        vk.verify(msg, &sig).unwrap();
    }

    #[test]
    fn confirm_submission_verifies_like_the_enclave() {
        let signer = InMemorySigner::new(7);
        let rekey = RekeyParams {
            new_public_key: vec![0xAB; 70],
            new_key_id: "arn:aws:kms:eu-central-1:1:key/x".into(),
        };
        let prep = prepare_fixture(Some(rekey.clone()));

        let req = sign_confirm_submission(&signer, &prep).unwrap();

        // Envelope signature over the exact command bytes.
        verify_like_enclave(&signer.public_key(), &req.command, &req.envelope_signature);

        // The command decodes as PrepareUpgrade carrying the prepare
        // response's fields verbatim, and the inner signature verifies
        // over the chain payload (the enclave's defence-in-depth check).
        let cmd: ControlCommand = ciborium::from_reader(req.command.as_slice()).unwrap();
        match cmd {
            ControlCommand::PrepareUpgrade {
                payload,
                payload_signature,
                rekey: rk,
                nonce,
            } => {
                assert_eq!(payload, prep.payload);
                assert_eq!(nonce, prep.nonce);
                let rk = rk.expect("rekey present");
                assert_eq!(rk.new_public_key, rekey.new_public_key);
                assert_eq!(rk.new_key_id, rekey.new_key_id);
                verify_like_enclave(&signer.public_key(), &payload, &payload_signature);
            }
            other => panic!("wrong command variant: {other:?}"),
        }
    }

    #[test]
    fn revoke_submission_verifies_like_the_enclave() {
        let signer = InMemorySigner::new(9);
        for rollback in [false, true] {
            let prep = RevokePrepareResponse {
                payload: vec![0xB2; 18],
                nonce: [0x24; 32],
                rollback,
            };
            let req = sign_revoke_submission(&signer, &prep).unwrap();
            verify_like_enclave(&signer.public_key(), &req.command, &req.envelope_signature);

            let cmd: ControlCommand = ciborium::from_reader(req.command.as_slice()).unwrap();
            match cmd {
                ControlCommand::RevokeUpgrade {
                    payload,
                    payload_signature,
                    rollback: rb,
                    nonce,
                } => {
                    assert_eq!(payload, prep.payload);
                    assert_eq!(nonce, prep.nonce);
                    assert_eq!(rb, rollback);
                    verify_like_enclave(&signer.public_key(), &payload, &payload_signature);
                }
                other => panic!("wrong command variant: {other:?}"),
            }
        }
    }

    /// The digest-then-sign path a PIV device takes must produce a
    /// signature the enclave's message-level verify accepts. This pins
    /// the load-bearing assumption behind `YubiKeySigner::sign`
    /// (SHA-256 prehash == what `VerifyingKey::verify` hashes).
    #[test]
    fn prehash_signature_verifies_at_message_level() {
        use enclavia_protocol::custody::der_signature_to_raw;
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        use sha2::{Digest as _, Sha256};

        let sk = SigningKey::from_bytes(&[13u8; 32].into()).unwrap();
        let msg = b"control command bytes";
        let digest = Sha256::digest(msg);

        // Sign the prehash (what the YubiKey does), DER-encode (what the
        // wire from the device carries), then re-encode raw.
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        let raw = der_signature_to_raw(sig.to_der().as_bytes()).unwrap();

        let vk = VerifyingKey::from(&sk);
        let parsed = Signature::from_slice(&raw).unwrap();
        // Message-level verify, exactly like enclavia-server.
        vk.verify(msg, &parsed).unwrap();
        // And the prehash view agrees.
        vk.verify_prehash(&digest, &parsed).unwrap();
    }

    #[test]
    fn signer_for_entry_yubikey_without_hardware_errors_cleanly() {
        // With the yubikey feature ON but no device attached, opening
        // errors (rather than panicking); without the feature it errors
        // with the "built without yubikey support" message. Either way
        // the entry itself must be accepted (valid public key).
        let signer = InMemorySigner::new(5);
        let entry = crate::keys::KeyEntry {
            public_key: base64::engine::general_purpose::STANDARD.encode(signer.public_key()),
            backend: crate::keys::KeyBackend::Yubikey {
                serial: 1,
                slot: "9c".into(),
            },
        };
        // This must not panic; on a CI machine with no YubiKey (or no
        // feature) it returns an error. If a YubiKey with serial 1 is
        // somehow attached, opening could succeed, so only assert on
        // the error path's message shape.
        if let Err(e) = signer_for_entry("test", &entry) {
            let msg = e.to_string();
            assert!(
                msg.contains("YubiKey") || msg.contains("yubikey"),
                "unexpected error: {msg}"
            );
        }
    }

    #[test]
    fn signer_for_entry_rejects_bad_public_key() {
        let entry = crate::keys::KeyEntry {
            public_key: "AAAA".into(),
            backend: crate::keys::KeyBackend::Yubikey {
                serial: 1,
                slot: "9c".into(),
            },
        };
        assert!(signer_for_entry("test", &entry).is_err());
    }
}
