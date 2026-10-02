//! Minimal `enclavia-config.json` reader for chain-init.
//!
//! We share the file with `enclavia-server` and `enclavia-secrets-init`.
//! chain-init reads `enclave_id`, `image_digest` and the anti-rollback
//! setting. The first two are required: without an enclave id the chain
//! link can't be POSTed to the right backend row; without an image digest
//! the boot payload would lie about what's running. The anti-rollback
//! setting comes from the `storage` and `synchronizer` sections, read the
//! way the image's init and nbd-client read them (absent fields are
//! `false` / empty).

use std::path::Path;

use enclavia_protocol::chain::{AntiRollbackSetting, PcrsHex};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct RawConfig {
    enclave_id: Option<String>,
    image_digest: Option<String>,
    #[serde(default)]
    storage: Option<RawStorage>,
    #[serde(default)]
    synchronizer: Option<RawSynchronizer>,
}

#[derive(Deserialize)]
struct RawStorage {
    #[serde(default)]
    enabled: bool,
}

/// The measured `synchronizer` section, with the defaults its other readers
/// (the image's init, nbd-client, enclavia-server) apply.
#[derive(Deserialize)]
struct RawSynchronizer {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    expected_pcrs: Vec<PcrsHex>,
    #[serde(default)]
    debug_attestation: bool,
    #[serde(default)]
    upgrade_target: bool,
}

#[derive(Debug)]
pub struct ChainInitConfig {
    pub enclave_id: Uuid,
    pub image_digest: String,
    pub anti_rollback: AntiRollbackSetting,
}

/// The anti-rollback setting the config describes. `enabled` mirrors the
/// init: it starts nbd-client with the synchronizer wiring only when storage
/// is on and `synchronizer.enabled` is true.
fn anti_rollback(storage: Option<RawStorage>, sync: Option<RawSynchronizer>) -> AntiRollbackSetting {
    let storage = storage.is_some_and(|s| s.enabled);
    match sync {
        None => AntiRollbackSetting::disabled(),
        Some(s) => AntiRollbackSetting {
            enabled: storage && s.enabled,
            upgrade_target: s.upgrade_target,
            debug_attestation: s.debug_attestation,
            synchronizer_pcrs: s.expected_pcrs,
        },
    }
}

pub fn load(path: &Path) -> Result<ChainInitConfig, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let raw: RawConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parsing {} as JSON: {e}", path.display()))?;

    let enclave_id_str = raw
        .enclave_id
        .ok_or("enclavia-config.json is missing required `enclave_id` field")?;
    let enclave_id = Uuid::parse_str(&enclave_id_str)
        .map_err(|e| format!("enclavia-config.json `enclave_id` is not a UUID: {e}"))?;

    let image_digest = raw
        .image_digest
        .ok_or("enclavia-config.json is missing required `image_digest` field")?;
    if !image_digest.starts_with("sha256:") || image_digest.len() != "sha256:".len() + 64 {
        return Err(format!(
            "enclavia-config.json `image_digest` not in canonical sha256:<64hex> form: {image_digest}"
        )
        .into());
    }

    Ok(ChainInitConfig {
        enclave_id,
        image_digest,
        anti_rollback: anti_rollback(raw.storage, raw.synchronizer),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Holder that cleans up its on-disk file when dropped. We roll
    /// our own instead of pulling in the `tempfile` dep just for one
    /// test module.
    struct TempJson(PathBuf);

    impl Drop for TempJson {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    impl TempJson {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    fn write_config(json: &str) -> TempJson {
        let path = std::env::temp_dir().join(format!(
            "chain-init-test-{}-{}.json",
            std::process::id(),
            // Distinguish concurrent tests in the same process.
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, json).unwrap();
        TempJson(path)
    }

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[test]
    fn rejects_missing_enclave_id() {
        let f = write_config(
            r#"{"image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#,
        );
        let err = load(f.path()).unwrap_err().to_string();
        assert!(err.contains("enclave_id"), "{err}");
    }

    #[test]
    fn rejects_missing_image_digest() {
        let f = write_config(r#"{"enclave_id":"00000000-0000-0000-0000-000000000000"}"#);
        let err = load(f.path()).unwrap_err().to_string();
        assert!(err.contains("image_digest"), "{err}");
    }

    #[test]
    fn rejects_malformed_image_digest() {
        let f = write_config(
            r#"{"enclave_id":"00000000-0000-0000-0000-000000000000","image_digest":"sha256:short"}"#,
        );
        let err = load(f.path()).unwrap_err().to_string();
        assert!(err.contains("canonical sha256"), "{err}");
    }

    #[test]
    fn accepts_minimal_config() {
        let f = write_config(
            r#"{"enclave_id":"11111111-1111-1111-1111-111111111111","image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(
            cfg.enclave_id.to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
        assert!(cfg.image_digest.starts_with("sha256:"));
    }

    #[test]
    fn ignores_unknown_fields() {
        let f = write_config(
            r#"{"enclave_id":"11111111-1111-1111-1111-111111111111","image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","control_public_key":"aaa","customer_app":{"port":8080}}"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(
            cfg.enclave_id.to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    const BASE: &str = r#""enclave_id":"11111111-1111-1111-1111-111111111111","image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000""#;

    fn setting(rest: &str) -> AntiRollbackSetting {
        let f = write_config(&format!("{{{BASE}{rest}}}"));
        load(f.path()).unwrap().anti_rollback
    }

    const PCRS: &str = r#"[{"PCR0":"aa","PCR1":"bb","PCR2":"cc"}]"#;

    /// The setting follows the config the way the image's init does: the
    /// wiring is on only with storage AND `synchronizer.enabled`.
    #[test]
    fn anti_rollback_setting_from_config() {
        assert_eq!(setting(""), AntiRollbackSetting::disabled());
        let on = setting(&format!(
            r#","storage":{{"enabled":true}},"synchronizer":{{"enabled":true,"expected_pcrs":{PCRS},"debug_attestation":true,"upgrade_target":true}}"#
        ));
        assert!(on.enabled && on.upgrade_target && on.debug_attestation);
        assert_eq!(on.synchronizer_pcrs.len(), 1);
        assert_eq!(on.synchronizer_pcrs[0].pcr0, "aa");
        // Anchors baked in but the wiring off: reported, not enabled.
        let baked = setting(&format!(
            r#","storage":{{"enabled":true}},"synchronizer":{{"enabled":false,"expected_pcrs":{PCRS}}}"#
        ));
        assert!(!baked.enabled && !baked.upgrade_target && !baked.debug_attestation);
        assert_eq!(baked.synchronizer_pcrs.len(), 1);
        // No storage: the init never starts nbd-client.
        let no_storage = setting(&format!(
            r#","synchronizer":{{"enabled":true,"expected_pcrs":{PCRS}}}"#
        ));
        assert!(!no_storage.enabled);
    }
}
