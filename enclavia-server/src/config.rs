use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p256::ecdsa::VerifyingKey;
use serde::Deserialize;

pub const CONFIG_PATH: &str = "/etc/enclavia/config.json";

/// Subset of `enclavia-config.json` that enclavia-server cares about. Other
/// fields (storage, customer_app, etc.) are read by init.sh and ignored here.
#[derive(Deserialize, Default)]
struct RawConfig {
    /// Base64-encoded ECDSA P-256 public key (#47). Wire format is
    /// 65-byte uncompressed SEC1 (`0x04 || X(32) || Y(32)`, big-endian)
    /// — what the backend's keypair-gen path produces via
    /// `VerifyingKey::to_encoded_point(false)`. Optional: when absent,
    /// the enclave is non-upgradable and signed `Control` commands are
    /// rejected unconditionally.
    control_public_key: Option<String>,
    /// Measured minimum upgrade delay in seconds. Create-time immutable:
    /// written by the builder into the rootfs config, so it is part of
    /// the measured image (PCR2) and cannot be changed without changing
    /// the enclave's identity. `PrepareUpgrade` rejects any `valid_from`
    /// earlier than this enclave's own now + delay. 0 (or absent, via
    /// the serde default) means no floor, matching the previous
    /// behavior.
    #[serde(default)]
    min_upgrade_delay_secs: u64,
}

#[derive(Default)]
pub struct ServerConfig {
    pub control_public_key: Option<VerifyingKey>,
    /// See `RawConfig::min_upgrade_delay_secs`. 0 = no floor.
    pub min_upgrade_delay_secs: u64,
}

pub fn load(path: &Path) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let raw: RawConfig = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ServerConfig::default()),
        Err(e) => return Err(Box::new(e)),
    };

    let control_public_key = match raw.control_public_key {
        Some(s) => {
            let bytes = B64.decode(s.as_bytes())?;
            // `from_sec1_bytes` accepts both compressed (33 B) and
            // uncompressed (65 B) SEC1 forms. We only ship uncompressed
            // from the backend (#47 spec lock), so anything else is a
            // shape error worth surfacing loudly rather than silently
            // accepting.
            if bytes.len() != 65 || bytes[0] != 0x04 {
                return Err("control_public_key must be 65-byte uncompressed SEC1 (0x04 || X || Y)".into());
            }
            Some(VerifyingKey::from_sec1_bytes(&bytes)?)
        }
        None => None,
    };

    Ok(ServerConfig {
        control_public_key,
        min_upgrade_delay_secs: raw.min_upgrade_delay_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_str(json: &str) -> ServerConfig {
        let dir = std::env::temp_dir().join(format!(
            "enclavia-server-config-test-{}-{json_len}",
            std::process::id(),
            json_len = json.len(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, json).unwrap();
        load(&path).unwrap()
    }

    #[test]
    fn config_without_min_upgrade_delay_defaults_to_zero() {
        // Pre-existing configs (and non-upgradable enclaves) carry no
        // `min_upgrade_delay_secs` field; they must keep parsing and
        // behave as "no floor".
        let cfg = load_str("{}");
        assert_eq!(cfg.min_upgrade_delay_secs, 0);
        assert!(cfg.control_public_key.is_none());
    }

    #[test]
    fn config_with_min_upgrade_delay_parses() {
        let cfg = load_str(r#"{"min_upgrade_delay_secs": 172800}"#);
        assert_eq!(cfg.min_upgrade_delay_secs, 172800);
    }

    #[test]
    fn missing_file_defaults_to_zero() {
        let cfg = load(Path::new("/nonexistent/enclavia-config.json")).unwrap();
        assert_eq!(cfg.min_upgrade_delay_secs, 0);
    }
}
