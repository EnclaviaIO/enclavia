//! `enclavia key` command orchestration (#48).
//!
//! Local control-key management for self-hosted custody. `generate`
//! creates the key (on a YubiKey, on-device) and records it in the
//! index at `~/.config/enclavia/keys/index.json`; `list` renders the
//! index. Presentation lives in the binary, as with every other
//! command module.

#[cfg(feature = "yubikey")]
use base64::Engine as _;
use serde::Serialize;

use crate::error::CliError;
#[cfg(feature = "yubikey")]
use crate::keys::KeyEntry;
use crate::keys::{self, KeyBackend, KeyIndex};

/// Result of `key generate`.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedKey {
    pub name: String,
    /// Backend discriminant, mirrors the index's `type` tag.
    #[serde(rename = "type")]
    pub backend: String,
    pub serial: u32,
    pub slot: String,
    /// Base64 65-byte uncompressed SEC1 P-256 public key.
    pub public_key: String,
    pub fingerprint: String,
}

/// One row of `key list`.
#[derive(Debug, Clone, Serialize)]
pub struct KeyListEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub backend: String,
    pub serial: Option<u32>,
    pub slot: Option<String>,
    pub public_key: String,
    pub fingerprint: String,
}

/// Flags for `key generate --yubikey`.
#[derive(Debug, Clone)]
pub struct YubiKeyGenerateArgs {
    pub name: String,
    /// PIV slot name (default `9c`, the Digital Signature slot).
    pub slot: String,
    /// `always` (default), `cached`, or `never`.
    pub touch_policy: String,
    /// `once` (default), `always`, or `never`.
    pub pin_policy: String,
    /// Disambiguates multiple connected devices.
    pub serial: Option<u32>,
}

/// Generate a P-256 control key on a YubiKey and record it in the
/// index. The private key is generated on-device and is never
/// extractable. Fails BEFORE touching the hardware if the name is
/// taken or invalid.
#[cfg(feature = "yubikey")]
pub fn generate_yubikey(args: &YubiKeyGenerateArgs) -> Result<GeneratedKey, CliError> {
    let mut index = keys::load_index()?;
    keys::validate_name(&args.name)?;
    if index.keys.contains_key(&args.name) {
        return Err(CliError::Other(format!(
            "a key named {:?} already exists; pick another --name",
            args.name
        )));
    }
    // Normalize + validate the slot before the device round-trip too.
    crate::signer::parse_slot(&args.slot)?;
    let slot = args.slot.to_ascii_lowercase();

    // Warn about slot replacement up front: PIV generation into an
    // occupied slot silently replaces whatever key was there.
    eprintln!(
        "Generating an ECDSA P-256 key on-device in PIV slot {slot} (touch policy: {}, \
         PIN policy: {}). Any existing key in that slot will be REPLACED.",
        args.touch_policy, args.pin_policy
    );

    let params = crate::signer::GenerateParams {
        serial: args.serial,
        slot: &slot,
        touch_policy: &args.touch_policy,
        pin_policy: &args.pin_policy,
    };
    let (serial, public_key) = crate::signer::generate_on_device(&params)?;

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    let entry = KeyEntry {
        public_key: public_key_b64.clone(),
        backend: KeyBackend::Yubikey { serial, slot: slot.clone() },
    };
    index.insert_new(&args.name, entry)?;
    keys::save_index(&index)?;

    Ok(GeneratedKey {
        name: args.name.clone(),
        backend: "yubikey".into(),
        serial,
        slot,
        public_key: public_key_b64,
        fingerprint: keys::fingerprint(&public_key),
    })
}

/// Feature-off stub: the clap surface still exposes `key generate
/// --yubikey`, but a build without the `yubikey` feature (library-face
/// consumers avoiding the pcsclite link dependency) cannot talk to the
/// hardware.
#[cfg(not(feature = "yubikey"))]
pub fn generate_yubikey(_args: &YubiKeyGenerateArgs) -> Result<GeneratedKey, CliError> {
    Err(CliError::Other(
        "this enclavia build was compiled without YubiKey support; rebuild enclavia-cli with \
         the default `yubikey` feature"
            .into(),
    ))
}

/// Read the index and render it as typed rows. Works regardless of the
/// `yubikey` feature (the index is plain JSON).
pub fn list() -> Result<Vec<KeyListEntry>, CliError> {
    let index = keys::load_index()?;
    rows_from_index(&index)
}

/// Pure projection used by [`list`]; split out for tests.
pub(crate) fn rows_from_index(index: &KeyIndex) -> Result<Vec<KeyListEntry>, CliError> {
    index
        .keys
        .iter()
        .map(|(name, entry)| {
            let (serial, slot) = match &entry.backend {
                KeyBackend::Yubikey { serial, slot } => (Some(*serial), Some(slot.clone())),
            };
            Ok(KeyListEntry {
                name: name.clone(),
                backend: entry.backend.kind().into(),
                serial,
                slot,
                public_key: entry.public_key.clone(),
                fingerprint: entry.fingerprint()?,
            })
        })
        .collect()
}

/// Look a key up by name and build the `control_key` JSON body the
/// backend expects on `POST /enclaves` for self-hosted custody.
pub fn control_key_body_for(name: &str) -> Result<serde_json::Value, CliError> {
    let index = keys::load_index()?;
    let entry = index.keys.get(name).ok_or_else(|| {
        CliError::Other(format!(
            "no key named {name:?} in {} (generate one with `enclavia key generate --yubikey \
             --name {name}`)",
            keys::index_path().display()
        ))
    })?;
    // Re-validate the stored key so a hand-edited index fails here with
    // a clear message rather than a backend 400.
    entry.public_key_bytes()?;
    Ok(serde_json::json!({
        "mode": "self_hosted",
        "public_key": entry.public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    fn entry(seed: u8) -> KeyEntry {
        let sk = p256::SecretKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = sk.public_key().to_encoded_point(false);
        KeyEntry {
            public_key: base64::engine::general_purpose::STANDARD.encode(point.as_bytes()),
            backend: KeyBackend::Yubikey { serial: seed as u32, slot: "9c".into() },
        }
    }

    #[test]
    fn rows_project_index_entries() {
        let mut index = KeyIndex::default();
        index.insert_new("alpha", entry(3)).unwrap();
        index.insert_new("beta", entry(4)).unwrap();
        let rows = rows_from_index(&index).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "alpha");
        assert_eq!(rows[0].backend, "yubikey");
        assert_eq!(rows[0].serial, Some(3));
        assert_eq!(rows[0].slot.as_deref(), Some("9c"));
        assert!(rows[0].fingerprint.starts_with("sha256:"));
        assert_eq!(rows[1].name, "beta");
    }
}
