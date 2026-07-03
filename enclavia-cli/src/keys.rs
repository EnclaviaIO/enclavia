//! Local control-key index for self-hosted custody.
//!
//! Self-hosted enclaves are created against a control public key the
//! user holds; the private half never reaches the backend. This module
//! is the on-disk registry of those keys: a single JSON index at
//! `~/.config/enclavia/keys/index.json` mapping a user-chosen name to a
//! backend descriptor plus the public key. Today the only backend is a
//! YubiKey PIV slot; the schema is a tagged enum so a future
//! passphrase-keyfile backend (`{"type": "file", "path": ...}`) slots
//! in without a migration.
//!
//! The index holds no secret material (a YubiKey key is not
//! extractable), but the directory is still created 0700 and the file
//! written 0600: the future keyfile backend stores its encrypted
//! keyfile under the same directory, and the index itself reveals which
//! enclaves the machine can control.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config;
use crate::error::CliError;

/// Current index schema version.
pub const INDEX_VERSION: u32 = 1;

/// Directory holding the index (and, for the future keyfile backend,
/// the key material itself). `~/.config/enclavia/keys` on Linux.
pub fn keys_dir() -> PathBuf {
    config::config_dir().join("keys")
}

/// Path of the JSON index inside [`keys_dir`].
pub fn index_path() -> PathBuf {
    keys_dir().join("index.json")
}

/// The whole on-disk index. Names are unique; `BTreeMap` keeps the
/// serialized order (and `key list`) stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIndex {
    pub version: u32,
    #[serde(default)]
    pub keys: BTreeMap<String, KeyEntry>,
}

impl Default for KeyIndex {
    fn default() -> Self {
        Self { version: INDEX_VERSION, keys: BTreeMap::new() }
    }
}

/// One named control key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Base64 (standard, padded) of the 65-byte uncompressed SEC1 P-256
    /// public key, exactly as sent to `POST /enclaves` at create time.
    pub public_key: String,
    /// Where the private half lives.
    #[serde(flatten)]
    pub backend: KeyBackend,
}

/// Backend descriptor. Tagged with `"type"` so future backends (the
/// passphrase keyfile: `{"type": "file", "path": "..."}`) extend the
/// enum without touching existing entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyBackend {
    /// A YubiKey PIV slot. The private key was generated on-device and
    /// is not extractable.
    Yubikey {
        /// YubiKey serial number, used to pick the right device when
        /// several are connected.
        serial: u32,
        /// PIV slot in lowercase hex, e.g. `"9c"`.
        slot: String,
    },
}

impl KeyBackend {
    /// Short human-readable backend label for `key list`.
    pub fn kind(&self) -> &'static str {
        match self {
            KeyBackend::Yubikey { .. } => "yubikey",
        }
    }
}

impl KeyEntry {
    /// Decode `public_key` into the 65-byte uncompressed SEC1 point,
    /// validating length and the `0x04` prefix (the same checks the
    /// backend and in-enclave verifier apply).
    pub fn public_key_bytes(&self) -> Result<[u8; 65], CliError> {
        decode_public_key(&self.public_key)
    }

    /// Short fingerprint of the public key for display.
    pub fn fingerprint(&self) -> Result<String, CliError> {
        Ok(fingerprint(&self.public_key_bytes()?))
    }
}

/// Decode a base64 SEC1 public key, enforcing the 65-byte uncompressed
/// (`0x04`-prefixed) shape and that the point is actually on P-256.
pub fn decode_public_key(b64: &str) -> Result<[u8; 65], CliError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CliError::Other(format!("invalid base64 public key: {e}")))?;
    let arr: [u8; 65] = bytes.as_slice().try_into().map_err(|_| {
        CliError::Other(format!(
            "public key must be 65 bytes (uncompressed SEC1), got {}",
            bytes.len()
        ))
    })?;
    if arr[0] != 0x04 {
        return Err(CliError::Other(
            "public key must be an uncompressed SEC1 point (0x04 prefix)".into(),
        ));
    }
    p256::PublicKey::from_sec1_bytes(&arr)
        .map_err(|e| CliError::Other(format!("public key is not a valid P-256 point: {e}")))?;
    Ok(arr)
}

/// Short fingerprint: first 8 bytes of SHA-256 over the 65 SEC1 bytes,
/// lowercase hex, `sha256:` prefixed. Display-only (collision
/// resistance is irrelevant at this length; the full key is what gets
/// registered).
pub fn fingerprint(public_key: &[u8; 65]) -> String {
    let digest = Sha256::digest(public_key);
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Load the index from its default location. A missing file is an
/// empty index (nothing generated yet), not an error.
pub fn load_index() -> Result<KeyIndex, CliError> {
    load_index_from(&index_path())
}

/// Load the index from an explicit path (tests).
pub fn load_index_from(path: &Path) -> Result<KeyIndex, CliError> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KeyIndex::default()),
        Err(e) => return Err(CliError::Other(format!("reading {}: {e}", path.display()))),
    };
    let index: KeyIndex = serde_json::from_str(&data)
        .map_err(|e| CliError::Other(format!("parsing {}: {e}", path.display())))?;
    if index.version != INDEX_VERSION {
        return Err(CliError::Other(format!(
            "unsupported key index version {} in {} (this CLI supports version {})",
            index.version,
            path.display(),
            INDEX_VERSION
        )));
    }
    Ok(index)
}

/// Persist the index to its default location, creating the keys
/// directory 0700 and writing the file 0600.
pub fn save_index(index: &KeyIndex) -> Result<(), CliError> {
    save_index_to(&index_path(), index)
}

/// Persist the index to an explicit path (tests). The parent directory
/// is created with mode 0700 and the file written with mode 0600 on
/// Unix.
pub fn save_index_to(path: &Path, index: &KeyIndex) -> Result<(), CliError> {
    let dir = path
        .parent()
        .ok_or_else(|| CliError::Other(format!("{} has no parent directory", path.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CliError::Other(format!("chmod {}: {e}", dir.display())))?;
    }
    let json = serde_json::to_string_pretty(index)
        .map_err(|e| CliError::Other(format!("serializing key index: {e}")))?;
    write_private(path, json.as_bytes())?;
    Ok(())
}

/// Write `data` to `path` with mode 0600 from the moment of creation
/// (no chmod-after-write window). Truncates an existing file.
fn write_private(path: &Path, data: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| CliError::Other(format!("opening {}: {e}", path.display())))?;
    // An existing file keeps its creation-time mode; enforce 0600 on
    // rewrite too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CliError::Other(format!("chmod {}: {e}", path.display())))?;
    }
    f.write_all(data)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", path.display())))?;
    Ok(())
}

/// Validate a user-supplied key name: 1..=64 chars from
/// `[A-Za-z0-9._-]`, no leading dot or dash. Keeps names shell- and
/// filesystem-safe (the future keyfile backend derives file names from
/// them).
pub fn validate_name(name: &str) -> Result<(), CliError> {
    let ok_len = !name.is_empty() && name.len() <= 64;
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    let ok_lead = !name.starts_with('.') && !name.starts_with('-');
    if ok_len && ok_chars && ok_lead {
        Ok(())
    } else {
        Err(CliError::Other(format!(
            "invalid key name {name:?}: 1-64 characters from [A-Za-z0-9._-], not starting with '.' or '-'"
        )))
    }
}

impl KeyIndex {
    /// Insert a new named key, rejecting duplicates by name.
    pub fn insert_new(&mut self, name: &str, entry: KeyEntry) -> Result<(), CliError> {
        validate_name(name)?;
        if self.keys.contains_key(name) {
            return Err(CliError::Other(format!(
                "a key named {name:?} already exists (pick another --name, or remove the entry from {})",
                index_path().display()
            )));
        }
        self.keys.insert(name.to_string(), entry);
        Ok(())
    }

    /// Find the entry whose public key equals `public_key` (65-byte
    /// SEC1 comparison, tolerant of base64 padding differences).
    pub fn find_by_public_key(&self, public_key: &[u8; 65]) -> Option<(&str, &KeyEntry)> {
        self.keys.iter().find_map(|(name, entry)| {
            match entry.public_key_bytes() {
                Ok(bytes) if &bytes == public_key => Some((name.as_str(), entry)),
                _ => None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid P-256 point (the generator) in SEC1 uncompressed form,
    /// so `decode_public_key`'s on-curve check passes.
    fn sample_pubkey() -> [u8; 65] {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let sk = p256::SecretKey::from_bytes(&[0x11u8; 32].into()).unwrap();
        let point = sk.public_key().to_encoded_point(false);
        point.as_bytes().try_into().unwrap()
    }

    fn sample_entry() -> KeyEntry {
        KeyEntry {
            public_key: base64::engine::general_purpose::STANDARD.encode(sample_pubkey()),
            backend: KeyBackend::Yubikey { serial: 12345678, slot: "9c".into() },
        }
    }

    #[test]
    fn index_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("index.json");

        let mut index = KeyIndex::default();
        index.insert_new("prod", sample_entry()).unwrap();
        save_index_to(&path, &index).unwrap();

        let back = load_index_from(&path).unwrap();
        assert_eq!(back.version, INDEX_VERSION);
        assert_eq!(back.keys.len(), 1);
        let entry = &back.keys["prod"];
        assert_eq!(entry.public_key_bytes().unwrap(), sample_pubkey());
        match &entry.backend {
            KeyBackend::Yubikey { serial, slot } => {
                assert_eq!(*serial, 12345678);
                assert_eq!(slot, "9c");
            }
        }
    }

    #[test]
    fn missing_index_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let index = load_index_from(&dir.path().join("nope.json")).unwrap();
        assert!(index.keys.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_private_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("index.json");
        save_index_to(&path, &KeyIndex::default()).unwrap();

        let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "keys dir must be 0700");
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "index file must be 0600");
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_restores_private_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        save_index_to(&path, &KeyIndex::default()).unwrap();
        // Loosen, then rewrite: the mode must come back to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_index_to(&path, &KeyIndex::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let mut index = KeyIndex::default();
        index.insert_new("k", sample_entry()).unwrap();
        assert!(index.insert_new("k", sample_entry()).is_err());
    }

    #[test]
    fn name_validation() {
        for good in ["a", "prod-key", "team.alpha_2", "X"] {
            assert!(validate_name(good).is_ok(), "{good:?} should be valid");
        }
        for bad in ["", ".hidden", "-flag", "has space", "a/b", &"x".repeat(65)] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn find_by_public_key_matches_bytes() {
        let mut index = KeyIndex::default();
        index.insert_new("k", sample_entry()).unwrap();
        let (name, _) = index.find_by_public_key(&sample_pubkey()).expect("found");
        assert_eq!(name, "k");

        // A different (valid) key does not match.
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let other_sk = p256::SecretKey::from_bytes(&[0x22u8; 32].into()).unwrap();
        let other: [u8; 65] =
            other_sk.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        assert!(index.find_by_public_key(&other).is_none());
    }

    #[test]
    fn wire_shape_uses_type_tag() {
        // The schema contract: the backend descriptor is flattened with a
        // "type" tag so a future {"type":"file","path":...} entry slots in.
        let json = serde_json::to_value(sample_entry()).unwrap();
        assert_eq!(json["type"], "yubikey");
        assert_eq!(json["serial"], 12345678);
        assert_eq!(json["slot"], "9c");
        assert!(json["public_key"].is_string());
    }

    #[test]
    fn decode_public_key_rejects_bad_shapes() {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        // Wrong length.
        assert!(decode_public_key(&b64(&[0x04; 64])).is_err());
        // Wrong prefix (compressed form).
        let mut compressed = [0x02u8; 65];
        compressed[0] = 0x02;
        assert!(decode_public_key(&b64(&compressed)).is_err());
        // Right shape but not on the curve.
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        assert!(decode_public_key(&b64(&off_curve)).is_err());
        // Not base64 at all.
        assert!(decode_public_key("!!!").is_err());
    }

    #[test]
    fn unknown_index_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        std::fs::write(&path, r#"{"version": 99, "keys": {}}"#).unwrap();
        assert!(load_index_from(&path).is_err());
    }
}
