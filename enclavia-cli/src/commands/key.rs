//! `enclavia key` command orchestration.
//!
//! Local control-key management for self-hosted custody. `generate`
//! creates the key (on a YubiKey, on-device) and records it in the
//! index at `~/.config/enclavia/keys/index.json`; `import` recovers an
//! index entry for a key that already lives on a device (lost laptop:
//! the index is gone but the YubiKey still holds the private key);
//! `list` renders the index. Presentation lives in the binary, as with
//! every other command module.

use base64::Engine as _;
use serde::Serialize;

use crate::error::CliError;
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
    /// Skip the interactive slot-replacement confirmation (`--yes`).
    pub assume_yes: bool,
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
    // occupied slot silently replaces whatever key was there. Make the
    // user acknowledge it before the hardware is touched (--yes skips
    // the prompt for scripted use).
    eprintln!(
        "Generating an ECDSA P-256 key on-device in PIV slot {slot} (touch policy: {}, \
         PIN policy: {}). Any existing key in that slot will be REPLACED.",
        args.touch_policy, args.pin_policy
    );
    if !args.assume_yes {
        confirm_or_abort()?;
    }

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

/// Wait for the user to press Enter before proceeding (Ctrl-C aborts).
/// A closed stdin (EOF: piped input that ran out, or a non-interactive
/// caller that forgot `--yes`) aborts rather than proceeding.
#[cfg(feature = "yubikey")]
fn confirm_or_abort() -> Result<(), CliError> {
    use std::io::BufRead as _;
    eprint!("Press Enter to continue, or Ctrl-C to abort... ");
    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("failed to read confirmation from stdin: {e}")))?;
    if n == 0 {
        return Err(CliError::Other(
            "stdin closed before confirmation; pass --yes to skip the prompt in \
             non-interactive use"
                .into(),
        ));
    }
    Ok(())
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

/// Flags for `key import --yubikey`.
#[derive(Debug, Clone)]
pub struct YubiKeyImportArgs {
    pub name: String,
    /// PIV slot name (default `9c`, where `generate` puts keys).
    pub slot: String,
    /// Disambiguates multiple connected devices.
    pub serial: Option<u32>,
}

/// Result of `key import`. Same core fields as [`GeneratedKey`] (the
/// recovered entry is byte-identical to what `generate` would have
/// recorded), plus recovery provenance and index-overlap notes.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedKey {
    pub name: String,
    /// Backend discriminant, mirrors the index's `type` tag.
    #[serde(rename = "type")]
    pub backend: String,
    pub serial: u32,
    pub slot: String,
    /// Base64 65-byte uncompressed SEC1 P-256 public key.
    pub public_key: String,
    pub fingerprint: String,
    /// Name of an existing index entry with the SAME public key, if
    /// any (the import is then just a second name for the same key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_registered_as: Option<String>,
    /// Existing entries pointing at the same (serial, slot) under other
    /// names. Harmless, but worth a note.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub same_slot_names: Vec<String>,
}

/// Recover the index entry for a key that already exists on a YubiKey:
/// read the PUBLIC key back off the hardware (PIV GET METADATA,
/// firmware 5.2.3+) and record it exactly as
/// `generate` would have. Nothing is generated, no PIN is prompted,
/// nothing is written to the device. Fails BEFORE touching the
/// hardware if the name is taken or invalid.
#[cfg(feature = "yubikey")]
pub fn import_yubikey(args: &YubiKeyImportArgs) -> Result<ImportedKey, CliError> {
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

    let recovered = crate::signer::read_public_key_on_device(args.serial, &slot)?;

    let (already_registered_as, same_slot_names) = register_imported(
        &mut index,
        &args.name,
        recovered.serial,
        &slot,
        &recovered.public_key,
    )?;
    keys::save_index(&index)?;

    Ok(ImportedKey {
        name: args.name.clone(),
        backend: "yubikey".into(),
        serial: recovered.serial,
        slot,
        public_key: base64::engine::general_purpose::STANDARD.encode(recovered.public_key),
        fingerprint: keys::fingerprint(&recovered.public_key),
        already_registered_as,
        same_slot_names,
    })
}

/// Feature-off stub, mirroring [`generate_yubikey`]'s.
#[cfg(not(feature = "yubikey"))]
pub fn import_yubikey(_args: &YubiKeyImportArgs) -> Result<ImportedKey, CliError> {
    Err(CliError::Other(
        "this enclavia build was compiled without YubiKey support; rebuild enclavia-cli with \
         the default `yubikey` feature"
            .into(),
    ))
}

/// Pure index step of an import: detect overlaps with existing entries
/// and insert the recovered key under `name`. Returns the name of an
/// existing entry with the same public key (if any) and the names of
/// entries already pointing at the same (serial, slot). Split out from
/// [`import_yubikey`] so the collision behaviors are testable without
/// hardware.
#[cfg_attr(not(feature = "yubikey"), allow(dead_code))]
pub(crate) fn register_imported(
    index: &mut KeyIndex,
    name: &str,
    serial: u32,
    slot: &str,
    public_key: &[u8; 65],
) -> Result<(Option<String>, Vec<String>), CliError> {
    let already_registered_as =
        index.find_by_public_key(public_key).map(|(n, _)| n.to_string());
    let same_slot_names: Vec<String> = index
        .keys
        .iter()
        .filter(|(n, e)| {
            n.as_str() != name
                && matches!(&e.backend,
                    KeyBackend::Yubikey { serial: s, slot: sl } if *s == serial && sl == slot)
        })
        .map(|(n, _)| n.clone())
        .collect();
    let entry = KeyEntry {
        public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
        backend: KeyBackend::Yubikey { serial, slot: slot.to_string() },
    };
    index.insert_new(name, entry)?;
    Ok((already_registered_as, same_slot_names))
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

    fn point(seed: u8) -> [u8; 65] {
        let sk = p256::SecretKey::from_bytes(&[seed; 32].into()).unwrap();
        sk.public_key().to_encoded_point(false).as_bytes().try_into().unwrap()
    }

    #[test]
    fn import_into_fresh_index_has_no_notes() {
        let mut index = KeyIndex::default();
        let (already, same_slot) =
            register_imported(&mut index, "recovered", 42, "9c", &point(5)).unwrap();
        assert!(already.is_none());
        assert!(same_slot.is_empty());
        let entry = &index.keys["recovered"];
        assert_eq!(entry.public_key_bytes().unwrap(), point(5));
        match &entry.backend {
            KeyBackend::Yubikey { serial, slot } => {
                assert_eq!(*serial, 42);
                assert_eq!(slot, "9c");
            }
        }
    }

    #[test]
    fn import_notes_existing_entry_with_same_public_key() {
        let mut index = KeyIndex::default();
        register_imported(&mut index, "original", 42, "9c", &point(5)).unwrap();
        // Same device, same slot, same key under a second name: allowed,
        // both overlaps reported.
        let (already, same_slot) =
            register_imported(&mut index, "recovered", 42, "9c", &point(5)).unwrap();
        assert_eq!(already.as_deref(), Some("original"));
        assert_eq!(same_slot, vec!["original".to_string()]);
        assert_eq!(index.keys.len(), 2);
    }

    #[test]
    fn import_notes_same_slot_under_a_different_key() {
        let mut index = KeyIndex::default();
        // A stale entry: same (serial, slot) but an old public key (the
        // on-device key was regenerated since).
        register_imported(&mut index, "stale", 42, "9c", &point(6)).unwrap();
        let (already, same_slot) =
            register_imported(&mut index, "recovered", 42, "9c", &point(5)).unwrap();
        assert!(already.is_none());
        assert_eq!(same_slot, vec!["stale".to_string()]);
    }

    #[test]
    fn import_ignores_other_devices_and_slots() {
        let mut index = KeyIndex::default();
        register_imported(&mut index, "other-device", 7, "9c", &point(6)).unwrap();
        register_imported(&mut index, "other-slot", 42, "9a", &point(7)).unwrap();
        let (already, same_slot) =
            register_imported(&mut index, "recovered", 42, "9c", &point(5)).unwrap();
        assert!(already.is_none());
        assert!(same_slot.is_empty());
    }

    #[test]
    fn import_rejects_duplicate_names() {
        let mut index = KeyIndex::default();
        register_imported(&mut index, "recovered", 42, "9c", &point(5)).unwrap();
        assert!(register_imported(&mut index, "recovered", 42, "9c", &point(5)).is_err());
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
