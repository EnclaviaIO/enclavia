//! Control-key signers for self-hosted custody (#48).
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
pub trait ControlSigner {
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
    Ok(ConfirmSubmitRequest { command, envelope_signature: envelope.to_vec() })
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
    Ok(ConfirmSubmitRequest { command, envelope_signature: envelope.to_vec() })
}

#[cfg(feature = "yubikey")]
pub use yubikey_backend::{GenerateParams, YubiKeySigner, generate_on_device, parse_slot};

#[cfg(feature = "yubikey")]
mod yubikey_backend {
    //! YubiKey PIV backend (#48).
    //!
    //! Manual hardware test plan (no CI coverage; needs a physical
    //! YubiKey 5 with the default PIN `123456` and the default PIV
    //! management key):
    //!
    //! 1. `enclavia key generate --yubikey --name hw-test`
    //!    prints a 65-byte base64 public key + fingerprint and adds an
    //!    entry to `~/.config/enclavia/keys/index.json` with the
    //!    device's serial and slot `9c`. `ykman piv info` shows a new
    //!    ECCP256 key in slot 9c with touch policy ALWAYS.
    //! 2. `enclavia key list` shows the entry; the fingerprint matches
    //!    step 1.
    //! 3. `enclavia enclave create --control-key hw-test --container-port 8080`
    //!    creates a self-hosted enclave (`control_key_mode:
    //!    "self_hosted"` in `enclave status`).
    //! 4. Push an image, wait for `staged`, then
    //!    `enclavia upgrade confirm <enclave> <upgrade> --immediate`:
    //!    the CLI prompts for the PIN once, asks for TWO touches
    //!    (inner + envelope signature), and the upgrade transitions to
    //!    `confirmed`; `enclavia upgrade chain` shows the new Upgrade
    //!    link as verified.
    //! 5. Stage another push and `enclavia upgrade revoke ...`: same
    //!    PIN + two-touch flow, upgrade ends `revoked`.
    //! 6. Negative: wrong PIN errors without consuming all retries
    //!    (message includes the wheel); unplugging the key mid-flow
    //!    surfaces a PC/SC error, and re-running recovers.
    //! 7. Stale nonce: run `confirm` up to the first touch prompt,
    //!    complete a control command from another terminal, then finish
    //!    the touches. The submit gets a 409 and the CLI re-prepares
    //!    and retries once, successfully.

    use std::io::Write as _;
    use std::sync::Mutex;

    use base64::Engine as _;
    use enclavia_protocol::custody::der_signature_to_raw;
    use sha2::{Digest as _, Sha256};
    use yubikey::piv::{AlgorithmId, SlotId};
    use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};

    use super::ControlSigner;
    use crate::error::CliError;

    /// Parse a PIV slot name in lowercase/uppercase hex. Only the four
    /// standard slots are supported; `9c` (Digital Signature) is the
    /// default and the natural home for a signing-only key.
    pub fn parse_slot(slot: &str) -> Result<SlotId, CliError> {
        match slot.to_ascii_lowercase().as_str() {
            "9a" => Ok(SlotId::Authentication),
            "9c" => Ok(SlotId::Signature),
            "9d" => Ok(SlotId::KeyManagement),
            "9e" => Ok(SlotId::CardAuthentication),
            other => Err(CliError::Other(format!(
                "unsupported PIV slot {other:?} (supported: 9a, 9c, 9d, 9e)"
            ))),
        }
    }

    fn open_device(serial: Option<u32>) -> Result<YubiKey, CliError> {
        let res = match serial {
            Some(s) => YubiKey::open_by_serial(Serial::from(s)),
            None => YubiKey::open(),
        };
        res.map_err(|e| match serial {
            Some(s) => CliError::Other(format!("opening YubiKey with serial {s}: {e}")),
            None => CliError::Other(format!(
                "opening YubiKey: {e} (is one plugged in and pcscd running? pass --serial if \
                 several are connected)"
            )),
        })
    }

    /// Prompt for the PIV PIN on stderr with hidden input. stderr keeps
    /// `--json` stdout parseable.
    fn prompt_pin(serial: u32) -> Result<String, CliError> {
        eprint!("PIN for YubiKey {serial}: ");
        std::io::stderr()
            .flush()
            .map_err(|e| CliError::Other(format!("flushing stderr: {e}")))?;
        let pin = rpassword::read_password()
            .map_err(|e| CliError::Other(format!("reading PIN: {e}")))?;
        if pin.is_empty() {
            return Err(CliError::Other("empty PIN".into()));
        }
        Ok(pin)
    }

    fn verify_pin(yk: &mut YubiKey, pin: &str) -> Result<(), CliError> {
        yk.verify_pin(pin.as_bytes()).map_err(|e| {
            let retries = match yk.get_pin_retries() {
                Ok(n) => format!(" ({n} PIN retries left)"),
                Err(_) => String::new(),
            };
            CliError::Other(format!("PIN verification failed: {e}{retries}"))
        })
    }

    /// A signing handle over one PIV slot. The PIN is verified at open
    /// time and re-verified before every signature, so keys generated
    /// with `--pin-policy always` work too; with the default `once`
    /// policy the extra verify is a no-op round-trip.
    pub struct YubiKeySigner {
        /// The pcsc handle is `&mut` for every operation; the trait
        /// takes `&self`, hence the mutex (never contended: the CLI is
        /// single-threaded through a signing flow).
        device: Mutex<YubiKey>,
        slot: SlotId,
        slot_name: String,
        serial: u32,
        pin: String,
        public_key: [u8; 65],
    }

    impl YubiKeySigner {
        /// Open the device (by serial when given), prompt for the PIN
        /// once, and verify it. `public_key` comes from the key index;
        /// PIV cannot read a raw public key back out of a slot without
        /// a certificate, so the index is the source of truth and the
        /// enclave-side verification is what catches a mismatch.
        pub fn open(
            serial: Option<u32>,
            slot: &str,
            public_key: [u8; 65],
        ) -> Result<Self, CliError> {
            let slot_id = parse_slot(slot)?;
            let mut device = open_device(serial)?;
            let serial = device.serial().0;
            let pin = prompt_pin(serial)?;
            verify_pin(&mut device, &pin)?;
            Ok(Self {
                device: Mutex::new(device),
                slot: slot_id,
                slot_name: slot.to_ascii_lowercase(),
                serial,
                pin,
                public_key,
            })
        }
    }

    impl ControlSigner for YubiKeySigner {
        fn public_key(&self) -> [u8; 65] {
            self.public_key
        }

        fn sign(&self, msg: &[u8]) -> Result<[u8; 64], CliError> {
            // PIV signs a caller-provided digest; the enclave verifies
            // with `VerifyingKey::verify(msg, sig)`, which SHA-256
            // hashes internally, so the digest we hand the device MUST
            // be SHA-256(msg).
            let digest = Sha256::digest(msg);
            let mut device = self.device.lock().expect("poisoned yubikey mutex");
            verify_pin(&mut device, &self.pin)?;
            eprintln!(
                "Touch your YubiKey {} to sign (slot {})...",
                self.serial, self.slot_name
            );
            let der = yubikey::piv::sign_data(&mut device, &digest, AlgorithmId::EccP256, self.slot)
                .map_err(|e| CliError::Other(format!("YubiKey signing failed: {e}")))?;
            // PIV emits DER (and possibly high-S); re-encode to the
            // locked-in 64-byte raw low-S r||s wire format.
            der_signature_to_raw(&der)
                .map_err(|e| CliError::Other(format!("re-encoding YubiKey signature: {e}")))
        }
    }

    /// Parameters for on-device key generation.
    pub struct GenerateParams<'a> {
        /// Pick a specific device when several are connected.
        pub serial: Option<u32>,
        /// PIV slot name, e.g. `"9c"`.
        pub slot: &'a str,
        /// `"always"`, `"cached"`, or `"never"`.
        pub touch_policy: &'a str,
        /// `"once"`, `"always"`, or `"never"`.
        pub pin_policy: &'a str,
    }

    fn parse_touch_policy(s: &str) -> Result<TouchPolicy, CliError> {
        match s {
            "always" => Ok(TouchPolicy::Always),
            "cached" => Ok(TouchPolicy::Cached),
            "never" => Ok(TouchPolicy::Never),
            other => Err(CliError::Other(format!(
                "invalid touch policy {other:?} (always, cached, never)"
            ))),
        }
    }

    fn parse_pin_policy(s: &str) -> Result<PinPolicy, CliError> {
        match s {
            "once" => Ok(PinPolicy::Once),
            "always" => Ok(PinPolicy::Always),
            "never" => Ok(PinPolicy::Never),
            other => Err(CliError::Other(format!(
                "invalid PIN policy {other:?} (once, always, never)"
            ))),
        }
    }

    /// Generate a P-256 key ON-DEVICE in the given slot (the private
    /// key never leaves the hardware, and is not extractable). Returns
    /// `(serial, sec1_public_key)`.
    ///
    /// Authenticates with the well-known default PIV management key;
    /// devices with a rotated management key must be prepared with
    /// external tooling (ykman) first. Generating into an occupied slot
    /// REPLACES the existing key; callers should warn.
    pub fn generate_on_device(params: &GenerateParams<'_>) -> Result<(u32, [u8; 65]), CliError> {
        let slot = parse_slot(params.slot)?;
        let touch = parse_touch_policy(params.touch_policy)?;
        let pin = parse_pin_policy(params.pin_policy)?;

        let mut device = open_device(params.serial)?;
        let serial = device.serial().0;
        device.authenticate(MgmKey::default()).map_err(|e| {
            CliError::Other(format!(
                "PIV management-key authentication failed on YubiKey {serial}: {e}. This CLI \
                 uses the default management key; if you rotated it, generate the key with \
                 `ykman piv keys generate` and import support will follow with the keyfile \
                 backend"
            ))
        })?;

        let spki =
            yubikey::piv::generate(&mut device, slot, AlgorithmId::EccP256, pin, touch)
                .map_err(|e| {
                    CliError::Other(format!("on-device key generation failed: {e}"))
                })?;
        let point = spki.subject_public_key.as_bytes().ok_or_else(|| {
            CliError::Other("device returned an unaligned public-key bit string".into())
        })?;
        let sec1: [u8; 65] = point.try_into().map_err(|_| {
            CliError::Other(format!(
                "device returned a {}-byte public key, expected 65 (uncompressed SEC1 P-256)",
                point.len()
            ))
        })?;
        if sec1[0] != 0x04 {
            return Err(CliError::Other(
                "device returned a non-uncompressed public key".into(),
            ));
        }
        // Sanity: parses as a valid P-256 point (this is what gets
        // registered with the backend and baked into the EIF).
        crate::keys::decode_public_key(
            &base64::engine::general_purpose::STANDARD.encode(sec1),
        )?;
        Ok((serial, sec1))
    }
}

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
            ControlCommand::PrepareUpgrade { payload, payload_signature, rekey: rk, nonce } => {
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
                ControlCommand::RevokeUpgrade { payload, payload_signature, rollback: rb, nonce } => {
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
            backend: crate::keys::KeyBackend::Yubikey { serial: 1, slot: "9c".into() },
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
            backend: crate::keys::KeyBackend::Yubikey { serial: 1, slot: "9c".into() },
        };
        assert!(signer_for_entry("test", &entry).is_err());
    }
}
