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
}

#[derive(Default)]
pub struct ServerConfig {
    pub control_public_key: Option<VerifyingKey>,
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

    Ok(ServerConfig { control_public_key })
}
