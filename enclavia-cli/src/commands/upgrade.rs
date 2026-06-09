//! Public upgrade-chain CLI surface (#47 phase 3c) and staged-upgrade
//! management commands (#47 phase 4c).
//!
//! `enclavia upgrade chain <enclave-id>` fetches the chain from the
//! backend and re-validates each link locally using the same
//! `enclavia_protocol::chain::validate_chain_link` the backend's ingest
//! route applies. The CLI's per-link verification verdict reflects this
//! local re-check, not a server claim.
//!
//! `enclavia upgrade list <enclave-id>` lists all staged upgrades.
//! `enclavia upgrade confirm <enclave-id> <upgrade-id>` confirms a staged
//! upgrade, optionally scheduling it with `--at` or `--immediate`.
//! `enclavia upgrade revoke <enclave-id> <upgrade-id>` cancels a confirmed
//! upgrade before it fires.
//!
//! All three new functions return typed values; the binary is the only
//! place that prints to the terminal.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use enclavia_protocol::chain::{
    BootPayload, ChainContext, ChainLink, ChainLinkKind, PcrsHex, RevocationPayload,
    UpgradePayload, validate_chain_link,
};
pub use enclavia_protocol::staging::{StagedUpgradeJson, StagedUpgradeStatus};
use serde::Serialize;
use uuid::Uuid;

use crate::api::{ApiClient, ChainLinkJson};
use crate::error::CliError;

/// One chain link plus its decoded payload and local validation verdict.
#[derive(Debug, Serialize)]
pub struct VerifiedLink {
    pub id: Option<Uuid>,
    pub sequence: Option<i64>,
    pub kind: ChainLinkKind,
    pub created_at: Option<DateTime<Utc>>,
    /// CBOR-decoded payload union. `None` when the bytes don't decode
    /// (validator will also reject — see `validation` for the reason).
    pub payload: Option<DecodedPayload>,
    pub attestation_bytes: usize,
    pub signature_bytes: Option<usize>,
    /// Outcome of `validate_chain_link` for this link with the chain
    /// prefix that precedes it. `Ok(VerificationOk::Append { sequence })`
    /// is the happy path and `sequence` should match the link's
    /// `sequence`. Verbatim error message on failure.
    pub validation: Result<VerificationOk, String>,
}

/// CLI-local mirror of [`enclavia_protocol::chain::Outcome`] so the
/// summary can be serialised without needing the protocol enum to gain
/// `Serialize`. `Append.sequence` is the validator-assigned ordinal
/// (`u64` upstream, kept as-is here).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerificationOk {
    Append { sequence: u64 },
    Dedup,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecodedPayload {
    Boot(BootPayload),
    Upgrade(UpgradePayload),
    Revocation(RevocationPayload),
}

/// Full chain summary the binary renders and MCP returns as JSON.
#[derive(Debug, Serialize)]
pub struct ChainSummary {
    pub enclave_id: String,
    pub upgradable: bool,
    pub image_digest: String,
    pub pcrs: PcrsHex,
    /// Base64 of the 65-byte uncompressed SEC1 P-256 public key.
    /// `None` when the enclave is non-upgradable.
    pub control_public_key: Option<String>,
    pub links: Vec<VerifiedLink>,
}

/// Fetch the enclave + its chain and re-validate end-to-end.
///
/// Two backend round-trips: `GET /enclaves/{id}` for the validator
/// context (PCRs, image digest, control pubkey, upgradable flag) and
/// `GET /enclaves/{id}/upgrade-chain` for the link list. We walk the
/// chain in order, accumulating `prior_chain` so each link sees the
/// same context the backend ingest saw at insert time.
///
/// Per-link validation failures are recorded on the link and do not
/// abort the walk — the user wants to see the whole chain even when a
/// row is broken, so they can diagnose what went wrong.
pub async fn chain(client: &ApiClient, id: &str) -> Result<ChainSummary, CliError> {
    let enclave = client.get_enclave(id).await?;
    let wire_links = client.get_enclave_chain(id).await?;

    let upgradable = enclave
        .get("upgradable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let image_digest = enclave
        .get("image_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::Other("enclave row missing `image_digest`".to_string())
        })?
        .to_string();
    // The enclave row stores the builder's pcr.json verbatim, so the keys
    // arrive in nitro-cli casing (`PCR0`); the extractor tolerates both
    // casings rather than coupling to that detail.
    let pcrs = pcrs_from_enclave_row(&enclave)?;

    let control_public_key_bytes = control_key_bytes_from_enclave_row(&enclave)?;
    let control_public_key_b64 = control_public_key_bytes
        .as_deref()
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b));

    let now = Utc::now();
    let mut prior: Vec<ChainLink> = Vec::with_capacity(wire_links.len());
    let mut out: Vec<VerifiedLink> = Vec::with_capacity(wire_links.len());
    for wire in wire_links {
        let link = wire_to_chain_link(&wire)?;
        let payload = decode_payload(&link.kind, &link.payload);
        let ctx = ChainContext {
            enclave_pcrs: &pcrs,
            enclave_image_digest: &image_digest,
            control_public_key: control_public_key_bytes.as_deref(),
            upgradable,
            prior_chain: &prior,
        };
        let validation = validate_chain_link(&link, &ctx, now, false)
            .map(|o| match o {
                enclavia_protocol::chain::Outcome::Append { sequence } => {
                    VerificationOk::Append { sequence }
                }
                enclavia_protocol::chain::Outcome::Dedup => VerificationOk::Dedup,
            })
            .map_err(|e| e.to_string());
        let attestation_bytes = link.attestation.len();
        let signature_bytes = link.signature.as_ref().map(|s| s.len());
        prior.push(link);
        out.push(VerifiedLink {
            id: wire.id,
            sequence: wire.sequence,
            kind: wire.kind,
            created_at: wire.created_at,
            payload,
            attestation_bytes,
            signature_bytes,
            validation,
        });
    }

    Ok(ChainSummary {
        enclave_id: id.to_string(),
        upgradable,
        image_digest,
        pcrs,
        control_public_key: control_public_key_b64,
        links: out,
    })
}

fn pcrs_from_enclave_row(enclave: &serde_json::Value) -> Result<PcrsHex, CliError> {
    let pcrs_obj = enclave.get("pcrs").ok_or_else(|| {
        CliError::Other("enclave row missing `pcrs`".to_string())
    })?;
    // The backend persists the builder's pcr.json verbatim, which uses the
    // nitro-cli `PCR0`/`PCR1`/`PCR2` casing. Accept lowercase as well so a
    // future normalization on the row can't break the walker.
    let field = |upper: &str, lower: &str| -> Result<String, CliError> {
        pcrs_obj
            .get(upper)
            .or_else(|| pcrs_obj.get(lower))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::Other(format!("enclave.pcrs missing `{upper}`")))
    };
    Ok(PcrsHex {
        pcr0: field("PCR0", "pcr0")?,
        pcr1: field("PCR1", "pcr1")?,
        pcr2: field("PCR2", "pcr2")?,
    })
}

/// Extract the control public key bytes from the enclave row.
///
/// The column is a BYTEA, so the authenticated row serializes it as a JSON
/// array of numbers; tolerate a base64 string too in case the row shape is
/// ever normalized. `None`/`null` means the enclave is non-upgradable.
fn control_key_bytes_from_enclave_row(
    enclave: &serde_json::Value,
) -> Result<Option<Vec<u8>>, CliError> {
    match enclave.get("control_public_key") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(Some)
            .map_err(|e| CliError::Other(format!("control_public_key base64 decode: {e}"))),
        Some(serde_json::Value::Array(arr)) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for v in arr {
                let n = v.as_u64().filter(|n| *n <= 255).ok_or_else(|| {
                    CliError::Other(
                        "control_public_key array element is not a byte".to_string(),
                    )
                })?;
                bytes.push(n as u8);
            }
            Ok(Some(bytes))
        }
        Some(other) => Err(CliError::Other(format!(
            "control_public_key has unexpected JSON shape: {other}"
        ))),
    }
}

fn wire_to_chain_link(w: &ChainLinkJson) -> Result<ChainLink, CliError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64
        .decode(w.payload.as_bytes())
        .map_err(|e| CliError::Other(format!("payload base64: {e}")))?;
    let attestation = b64
        .decode(w.attestation.as_bytes())
        .map_err(|e| CliError::Other(format!("attestation base64: {e}")))?;
    let signature = match w.signature.as_deref() {
        Some(s) => Some(
            b64.decode(s.as_bytes())
                .map_err(|e| CliError::Other(format!("signature base64: {e}")))?,
        ),
        None => None,
    };
    Ok(ChainLink {
        id: w.id,
        // ChainLinkJson stores `sequence` as `i64` matching the
        // backend's serde shape; the validator-facing struct uses
        // `u64`. The backend never persists a negative value, but
        // surface a hard error instead of silently `as u64`-ing if a
        // misbehaving backend ever returns one.
        sequence: w
            .sequence
            .map(|s| {
                u64::try_from(s).map_err(|_| {
                    CliError::Other(format!("negative sequence {s} from backend"))
                })
            })
            .transpose()?,
        kind: w.kind,
        payload,
        attestation,
        signature,
    })
}

fn decode_payload(kind: &ChainLinkKind, bytes: &[u8]) -> Option<DecodedPayload> {
    match kind {
        ChainLinkKind::Boot => ciborium::de::from_reader::<BootPayload, _>(bytes)
            .ok()
            .map(DecodedPayload::Boot),
        ChainLinkKind::Upgrade => ciborium::de::from_reader::<UpgradePayload, _>(bytes)
            .ok()
            .map(DecodedPayload::Upgrade),
        ChainLinkKind::Revocation => {
            ciborium::de::from_reader::<RevocationPayload, _>(bytes)
                .ok()
                .map(DecodedPayload::Revocation)
        }
    }
}

// ---------------------------------------------------------------------------
// Staged-upgrade management (#47 phase 4c)
// ---------------------------------------------------------------------------

/// Fetch all staged upgrades for an enclave, newest first.
pub async fn list_upgrades(
    client: &ApiClient,
    enclave_id: &str,
) -> Result<Vec<StagedUpgradeJson>, CliError> {
    client.list_upgrades(enclave_id).await
}

/// Confirm a staged upgrade, optionally scheduling its `valid_from` time.
///
/// - `valid_from = None` lets the server default to `now + 7 days`.
/// - A past timestamp is clamped to `now` by the server.
pub async fn confirm_upgrade(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
) -> Result<StagedUpgradeJson, CliError> {
    client.confirm_upgrade(enclave_id, upgrade_id, valid_from).await
}

/// Revoke a confirmed upgrade before it fires. The running enclave keeps
/// its current version.
pub async fn revoke_upgrade(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
) -> Result<StagedUpgradeJson, CliError> {
    client.revoke_upgrade(enclave_id, upgrade_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn pcrs_fixture() -> PcrsHex {
        PcrsHex {
            pcr0: "00".repeat(48),
            pcr1: "11".repeat(48),
            pcr2: "22".repeat(48),
        }
    }

    fn boot_payload_fixture() -> BootPayload {
        BootPayload {
            enclave_id: Uuid::nil(),
            image_digest: "sha256:abc123".into(),
            pcrs: pcrs_fixture(),
            booted_at: Utc.with_ymd_and_hms(2026, 6, 9, 9, 54, 8).unwrap(),
            nonce: vec![0x42; 32],
        }
    }

    fn cbor(p: &BootPayload) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(p, &mut out).unwrap();
        out
    }

    #[test]
    fn wire_to_chain_link_round_trips_boot() {
        let payload = boot_payload_fixture();
        let payload_bytes = cbor(&payload);
        let b64 = base64::engine::general_purpose::STANDARD;
        let wire = ChainLinkJson {
            id: Some(Uuid::nil()),
            kind: ChainLinkKind::Boot,
            sequence: Some(0),
            payload: b64.encode(&payload_bytes),
            attestation: b64.encode(b"fake-att"),
            signature: None,
            created_at: None,
        };

        let link = wire_to_chain_link(&wire).unwrap();
        assert_eq!(link.id, Some(Uuid::nil()));
        assert_eq!(link.sequence, Some(0));
        assert_eq!(link.kind, ChainLinkKind::Boot);
        assert_eq!(link.payload, payload_bytes);
        assert_eq!(link.attestation, b"fake-att");
        assert!(link.signature.is_none());
    }

    #[test]
    fn wire_to_chain_link_decodes_signature_when_present() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let sig = vec![0xaa; 64];
        let wire = ChainLinkJson {
            id: None,
            kind: ChainLinkKind::Upgrade,
            sequence: Some(1),
            payload: b64.encode([0xa0]),
            attestation: b64.encode([0]),
            signature: Some(b64.encode(&sig)),
            created_at: None,
        };
        let link = wire_to_chain_link(&wire).unwrap();
        assert_eq!(link.signature.as_deref(), Some(sig.as_slice()));
    }

    #[test]
    fn wire_to_chain_link_rejects_negative_sequence() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let wire = ChainLinkJson {
            id: None,
            kind: ChainLinkKind::Boot,
            sequence: Some(-1),
            payload: b64.encode([0xa0]),
            attestation: b64.encode([0]),
            signature: None,
            created_at: None,
        };
        let err = wire_to_chain_link(&wire).unwrap_err().to_string();
        assert!(err.contains("negative sequence"), "{err}");
    }

    #[test]
    fn wire_to_chain_link_rejects_invalid_base64() {
        let wire = ChainLinkJson {
            id: None,
            kind: ChainLinkKind::Boot,
            sequence: Some(0),
            payload: "not!base64!!".to_string(),
            attestation: "AAAA".to_string(),
            signature: None,
            created_at: None,
        };
        let err = wire_to_chain_link(&wire).unwrap_err().to_string();
        assert!(err.contains("payload base64"), "{err}");
    }

    #[test]
    fn decode_payload_round_trips_boot() {
        let payload = boot_payload_fixture();
        let bytes = cbor(&payload);
        let decoded = decode_payload(&ChainLinkKind::Boot, &bytes).expect("decodes");
        match decoded {
            DecodedPayload::Boot(p) => {
                assert_eq!(p.image_digest, payload.image_digest);
                assert_eq!(p.pcrs.pcr0, payload.pcrs.pcr0);
                assert_eq!(p.nonce, payload.nonce);
            }
            other => panic!("unexpected payload kind: {other:?}"),
        }
    }

    #[test]
    fn decode_payload_round_trips_upgrade() {
        let payload = UpgradePayload {
            enclave_id: Uuid::nil(),
            from_pcrs: pcrs_fixture(),
            to_pcrs: pcrs_fixture(),
            image_digest: "sha256:next".into(),
            valid_from: Utc.with_ymd_and_hms(2026, 6, 9, 11, 0, 0).unwrap(),
            issued_at: Utc.with_ymd_and_hms(2026, 6, 9, 10, 15, 22).unwrap(),
            nonce: vec![0x43; 32],
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
        let decoded = decode_payload(&ChainLinkKind::Upgrade, &bytes).expect("decodes");
        match decoded {
            DecodedPayload::Upgrade(p) => {
                assert_eq!(p.image_digest, payload.image_digest);
                assert_eq!(p.valid_from, payload.valid_from);
            }
            other => panic!("unexpected payload kind: {other:?}"),
        }
    }

    #[test]
    fn decode_payload_round_trips_revocation() {
        let payload = RevocationPayload {
            enclave_id: Uuid::nil(),
            revokes: Uuid::from_u128(0x42),
            issued_at: Utc.with_ymd_and_hms(2026, 6, 9, 10, 18, 1).unwrap(),
            nonce: vec![0x44; 32],
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
        let decoded = decode_payload(&ChainLinkKind::Revocation, &bytes).expect("decodes");
        match decoded {
            DecodedPayload::Revocation(p) => {
                assert_eq!(p.revokes, Uuid::from_u128(0x42));
                assert_eq!(p.nonce, vec![0x44; 32]);
            }
            other => panic!("unexpected payload kind: {other:?}"),
        }
    }

    #[test]
    fn decode_payload_returns_none_on_garbage() {
        // A non-CBOR-decodable byte sequence shouldn't panic; the
        // pretty-printer special-cases `None` as `<undecodable>` and
        // continues, since the validator will surface the true cause.
        let decoded = decode_payload(&ChainLinkKind::Boot, &[0xff, 0xff, 0xff]);
        assert!(decoded.is_none());
    }

    #[test]
    fn pcrs_from_enclave_row_extracts_three() {
        let enclave = serde_json::json!({
            "pcrs": {
                "pcr0": "aa".repeat(48),
                "pcr1": "bb".repeat(48),
                "pcr2": "cc".repeat(48),
            }
        });
        let pcrs = pcrs_from_enclave_row(&enclave).unwrap();
        assert_eq!(pcrs.pcr0, "aa".repeat(48));
        assert_eq!(pcrs.pcr1, "bb".repeat(48));
        assert_eq!(pcrs.pcr2, "cc".repeat(48));
    }

    /// The shape the backend actually serves: the row stores the builder's
    /// pcr.json verbatim, so keys arrive in nitro-cli casing.
    #[test]
    fn pcrs_from_enclave_row_accepts_nitro_cli_casing() {
        let enclave = serde_json::json!({
            "pcrs": {
                "PCR0": "aa".repeat(48),
                "PCR1": "bb".repeat(48),
                "PCR2": "cc".repeat(48),
            }
        });
        let pcrs = pcrs_from_enclave_row(&enclave).unwrap();
        assert_eq!(pcrs.pcr0, "aa".repeat(48));
        assert_eq!(pcrs.pcr1, "bb".repeat(48));
        assert_eq!(pcrs.pcr2, "cc".repeat(48));
    }

    #[test]
    fn pcrs_from_enclave_row_errors_on_missing_field() {
        let enclave = serde_json::json!({
            "pcrs": {
                "pcr0": "aa",
                "pcr1": "bb",
            }
        });
        let err = pcrs_from_enclave_row(&enclave).unwrap_err().to_string();
        assert!(err.contains("PCR2"), "{err}");
    }

    #[test]
    fn pcrs_from_enclave_row_errors_when_pcrs_absent() {
        let enclave = serde_json::json!({});
        let err = pcrs_from_enclave_row(&enclave).unwrap_err().to_string();
        assert!(err.contains("pcrs"), "{err}");
    }

    /// `control_public_key` is a BYTEA on the row, so the authenticated
    /// endpoint serializes it as a JSON array of numbers.
    #[test]
    fn control_key_from_enclave_row_accepts_byte_array() {
        let enclave = serde_json::json!({ "control_public_key": [4, 100, 255, 0] });
        let bytes = control_key_bytes_from_enclave_row(&enclave).unwrap();
        assert_eq!(bytes, Some(vec![4u8, 100, 255, 0]));
    }

    #[test]
    fn control_key_from_enclave_row_accepts_base64_string() {
        let enclave = serde_json::json!({ "control_public_key": "BGT/AA==" });
        let bytes = control_key_bytes_from_enclave_row(&enclave).unwrap();
        assert_eq!(bytes, Some(vec![4u8, 100, 255, 0]));
    }

    #[test]
    fn control_key_from_enclave_row_none_when_null_or_absent() {
        let null_row = serde_json::json!({ "control_public_key": null });
        assert_eq!(control_key_bytes_from_enclave_row(&null_row).unwrap(), None);
        let absent_row = serde_json::json!({});
        assert_eq!(
            control_key_bytes_from_enclave_row(&absent_row).unwrap(),
            None
        );
    }

    #[test]
    fn control_key_from_enclave_row_rejects_out_of_range() {
        let enclave = serde_json::json!({ "control_public_key": [4, 256] });
        let err = control_key_bytes_from_enclave_row(&enclave)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a byte"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Staged-upgrade DTO parsing
    // -----------------------------------------------------------------------

    /// `StagedUpgradeJson` round-trips through JSON without loss.
    #[test]
    fn staged_upgrade_json_round_trips() {
        let json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "enclave_id": "00000000-0000-0000-0000-000000000002",
            "status": "staged",
            "docker_image": "registry.example.com/owner/app:v2",
            "created_at": "2026-06-09T10:00:00Z"
        });
        let v: StagedUpgradeJson = serde_json::from_value(json).unwrap();
        assert_eq!(v.status, StagedUpgradeStatus::Staged);
        assert!(v.valid_from.is_none());
        assert!(v.pcrs.is_none());
        assert!(v.image_digest.is_none());
    }

    /// Optional fields on `StagedUpgradeJson` deserialize when present.
    /// Note: `PcrsHex` uses `PCR0`/`PCR1`/`PCR2` as serde field names
    /// (uppercase, matching the backend wire shape).
    #[test]
    fn staged_upgrade_json_with_optional_fields() {
        let json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "enclave_id": "00000000-0000-0000-0000-000000000002",
            "status": "confirmed",
            "docker_image": "registry.example.com/owner/app:v2",
            "image_digest": "sha256:abcdef1234567890",
            "pcrs": {
                "PCR0": "aa".repeat(48),
                "PCR1": "bb".repeat(48),
                "PCR2": "cc".repeat(48)
            },
            "valid_from": "2026-06-16T10:00:00Z",
            "upgrade_link_id": "00000000-0000-0000-0000-000000000003",
            "created_at": "2026-06-09T10:00:00Z"
        });
        let v: StagedUpgradeJson = serde_json::from_value(json).unwrap();
        assert_eq!(v.status, StagedUpgradeStatus::Confirmed);
        assert!(v.valid_from.is_some());
        assert!(v.pcrs.is_some());
        assert_eq!(v.image_digest.as_deref(), Some("sha256:abcdef1234567890"));
    }

    /// `StagedUpgradeStatus` deserializes from all known lowercase strings.
    #[test]
    fn staged_upgrade_status_deserializes_all_variants() {
        let cases = [
            ("building", StagedUpgradeStatus::Building),
            ("staged", StagedUpgradeStatus::Staged),
            ("confirmed", StagedUpgradeStatus::Confirmed),
            ("promoted", StagedUpgradeStatus::Promoted),
            ("revoked", StagedUpgradeStatus::Revoked),
            ("failed", StagedUpgradeStatus::Failed),
            ("expired", StagedUpgradeStatus::Expired),
        ];
        for (s, expected) in &cases {
            let got: StagedUpgradeStatus =
                serde_json::from_str(&format!("\"{s}\"")).unwrap();
            assert_eq!(got, *expected, "variant {s}");
        }
    }
}
