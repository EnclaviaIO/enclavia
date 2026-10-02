use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use enclavia_protocol::attestation::Pcrs;
use enclavia_protocol::chain::PcrsHex;
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
    /// The synchronizer section the builder stamps into the measured
    /// config (`--synchronizer-enabled` / `--synchronizer-pcrs`), the same
    /// one nbd-client reads its oracle trust anchors from.
    #[serde(default)]
    synchronizer: Option<RawSynchronizerSection>,
}

#[derive(Deserialize)]
struct RawSynchronizerSection {
    /// Whether this enclave pins its storage to the synchronizer.
    #[serde(default)]
    enabled: bool,
    /// Hex PCR triples the synchronizer cluster may present.
    #[serde(default)]
    expected_pcrs: Vec<PcrsHex>,
    /// Skip-cert-chain verification of the synchronizer's document (QEMU).
    #[serde(default)]
    debug_attestation: bool,
}

/// Trust anchors for a session with the synchronizer, from the measured
/// config. Present only when the enclave pins its storage there.
pub struct SynchronizerTrust {
    /// Measurements the synchronizer must attest to. Never empty.
    pub expected_pcrs: Vec<Pcrs>,
    /// Skip-cert-chain verification of the synchronizer's document.
    pub debug_attestation: bool,
}

#[derive(Default)]
pub struct ServerConfig {
    pub control_public_key: Option<VerifyingKey>,
    /// See `RawConfig::min_upgrade_delay_secs`. 0 = no floor.
    pub min_upgrade_delay_secs: u64,
    /// `Some` exactly when the measured config says the synchronizer is
    /// enabled: the revoke flow must then commit the revocation there.
    pub synchronizer: Option<SynchronizerTrust>,
}

/// Whether this binary contains the path that checks the synchronizer's
/// attestation without the AWS Nitro certificate chain. Debug (QEMU) images
/// are built with it, production images without it.
pub const SKIPS_CERTIFICATE_CHAIN: bool = cfg!(feature = "dangerous-skip-chain");

/// The measured config's `synchronizer.debug_attestation` disagrees with
/// [`SKIPS_CERTIFICATE_CHAIN`]: the image carries the wrong build of this
/// binary. Fatal: the server must not start.
#[derive(Debug)]
pub struct BuildFlavourMismatch(pub String);

impl std::fmt::Display for BuildFlavourMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BuildFlavourMismatch {}

/// Load the measured config. A [`BuildFlavourMismatch`] error is fatal; any
/// other error leaves the control channel disabled.
pub fn load(path: &Path) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let raw: RawConfig = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ServerConfig::default()),
        Err(e) => return Err(Box::new(e)),
    };

    // How the synchronizer's attestation is checked is measured (the builder
    // writes `debug_attestation` from its `--debug`) and compiled: the
    // skip-chain path exists only in the debug build of this binary, which
    // only debug images carry. The two must agree, or the image was assembled
    // from the wrong build.
    if let Some(section) = &raw.synchronizer {
        if section.debug_attestation != SKIPS_CERTIFICATE_CHAIN {
            return Err(Box::new(BuildFlavourMismatch(format!(
                "measured config has synchronizer.debug_attestation = {}, but this \
                 enclavia-server is the {} build; the image carries the wrong build",
                section.debug_attestation,
                if SKIPS_CERTIFICATE_CHAIN { "debug (skip-chain)" } else { "production" },
            ))));
        }
    }

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

    // An enabled synchronizer without measurements to check it against is a
    // configuration error: failing the whole load disables the control
    // channel, so no revocation can be reported done without the
    // synchronizer committing it.
    let synchronizer = match raw.synchronizer {
        Some(section) if section.enabled => {
            if section.expected_pcrs.is_empty() {
                return Err(
                    "synchronizer.enabled is set but synchronizer.expected_pcrs is empty".into(),
                );
            }
            let mut expected_pcrs = Vec::with_capacity(section.expected_pcrs.len());
            for (i, hex_triple) in section.expected_pcrs.iter().enumerate() {
                expected_pcrs.push(hex_triple.to_pcrs().map_err(|e| {
                    format!("synchronizer.expected_pcrs[{i}] is malformed: {e}")
                })?);
            }
            Some(SynchronizerTrust {
                expected_pcrs,
                debug_attestation: section.debug_attestation,
            })
        }
        _ => None,
    };

    Ok(ServerConfig {
        control_public_key,
        min_upgrade_delay_secs: raw.min_upgrade_delay_secs,
        synchronizer,
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

    fn write_tmp(name: &str, json: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "enclavia-server-config-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    fn hex48(b: &str) -> String {
        b.repeat(48)
    }

    fn section(enabled: bool, debug_attestation: bool) -> String {
        format!(
            r#"{{"synchronizer": {{"enabled": {enabled}, "debug_attestation": {debug_attestation},
                "expected_pcrs": [{{"PCR0": "{}", "PCR1": "{}", "PCR2": "{}"}}]}}}}"#,
            hex48("aa"),
            hex48("bb"),
            hex48("cc")
        )
    }

    #[test]
    fn enabled_synchronizer_section_parses() {
        let json = section(true, SKIPS_CERTIFICATE_CHAIN);
        let cfg = load(&write_tmp("sync-on", &json)).unwrap();
        let trust = cfg.synchronizer.expect("enabled synchronizer");
        assert_eq!(trust.debug_attestation, SKIPS_CERTIFICATE_CHAIN);
        assert_eq!(trust.expected_pcrs.len(), 1);
        assert_eq!(trust.expected_pcrs[0].pcr0, vec![0xaa; 48]);
    }

    /// Present but not enabled (and absent): no synchronizer, so the revoke
    /// flow has nothing to commit there.
    #[test]
    fn disabled_or_absent_synchronizer_is_none() {
        let json = section(false, SKIPS_CERTIFICATE_CHAIN);
        assert!(load(&write_tmp("sync-off", &json)).unwrap().synchronizer.is_none());
        assert!(load_str("{}").synchronizer.is_none());
    }

    #[test]
    fn enabled_synchronizer_without_pcrs_is_an_error() {
        let path = write_tmp(
            "sync-empty",
            &format!(
                r#"{{"synchronizer": {{"enabled": true, "debug_attestation": {SKIPS_CERTIFICATE_CHAIN}}}}}"#
            ),
        );
        let err = load(&path).err().expect("an empty expected_pcrs is an error");
        assert!(!err.is::<BuildFlavourMismatch>(), "{err}");
    }

    /// A measured `debug_attestation` that disagrees with how this binary
    /// was built is the fatal BuildFlavourMismatch, whether or not the
    /// wiring is enabled.
    #[test]
    fn debug_attestation_must_match_the_build() {
        for enabled in [true, false] {
            let json = section(enabled, !SKIPS_CERTIFICATE_CHAIN);
            let err = load(&write_tmp(&format!("flavour-{enabled}"), &json))
                .err()
                .expect("a mismatched build is an error");
            assert!(err.is::<BuildFlavourMismatch>(), "{err}");
        }
    }
}
