use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

pub const CONFIG_PATH: &str = "/etc/enclavia/config.json";

/// Subset of `enclavia-config.json` that enclavia-server cares about. Other
/// fields (storage, customer_app, etc.) are read by init.sh and ignored here.
#[derive(Deserialize, Default)]
struct RawConfig {
    /// Base64-encoded Ed25519 public key (32 raw bytes). Optional — when
    /// absent, signed `Control` commands are rejected.
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
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "control_public_key must decode to 32 bytes")?;
            Some(VerifyingKey::from_bytes(&arr)?)
        }
        None => None,
    };

    Ok(ServerConfig { control_public_key })
}
