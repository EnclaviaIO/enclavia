//! Minimal `enclavia-config.json` reader for chain-init.
//!
//! We share the file with `enclavia-server` and `enclavia-secrets-init`
//! but only care about `enclave_id` and `image_digest` here. Both are
//! required: without an enclave id the chain link can't be POSTed to
//! the right backend row; without an image digest the boot payload
//! would lie about what's running.

use std::path::Path;

use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct RawConfig {
    enclave_id: Option<String>,
    image_digest: Option<String>,
}

#[derive(Debug)]
pub struct ChainInitConfig {
    pub enclave_id: Uuid,
    pub image_digest: String,
}

pub fn load(
    path: &Path,
) -> Result<ChainInitConfig, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    let raw: RawConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parsing {} as JSON: {e}", path.display()))?;

    let enclave_id_str = raw
        .enclave_id
        .ok_or("enclavia-config.json is missing required `enclave_id` field")?;
    let enclave_id = Uuid::parse_str(&enclave_id_str).map_err(|e| {
        format!("enclavia-config.json `enclave_id` is not a UUID: {e}")
    })?;

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

    static COUNTER: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    #[test]
    fn rejects_missing_enclave_id() {
        let f = write_config(r#"{"image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#);
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
}
