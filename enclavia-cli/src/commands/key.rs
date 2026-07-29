//! `enclavia key` command orchestration.
//!
//! Local control-key management for self-hosted custody. `generate`
//! creates the key (on a YubiKey, on-device) and records it in the
//! platform configuration directory's key index; `import` recovers an
//! existing YubiKey PIV entry; `list` renders the index.
//! Presentation lives in the binary, as with every other command
//! module.

use serde::Serialize;

use crate::error::CliError;
use crate::keys::{self, KeyBackend, KeyIndex};

mod yubikey;

pub use yubikey::{
    GeneratedKey, ImportedKey, YubiKeyGenerateArgs, YubiKeyImportArgs, generate_yubikey,
    import_yubikey,
};

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
    use base64::Engine as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    use crate::keys::KeyEntry;

    fn entry(seed: u8) -> KeyEntry {
        let sk = p256::SecretKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = sk.public_key().to_encoded_point(false);
        KeyEntry {
            public_key: base64::engine::general_purpose::STANDARD.encode(point.as_bytes()),
            backend: KeyBackend::Yubikey {
                serial: seed as u32,
                slot: "9c".into(),
            },
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
