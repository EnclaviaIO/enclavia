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
    BootPayload, ChainLinkKind, EnclaveChainRow, PcrsHex, RecordedLink, RevocationPayload,
    UpgradePayload, validate_chain,
};
pub use enclavia_protocol::staging::{StagedUpgradeJson, StagedUpgradeStatus};
use serde::Serialize;
use uuid::Uuid;

use crate::api::ApiClient;
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
    /// True when the enclave row reports `mode == "debug"`. Links are
    /// then re-validated with `debug_mode = true`, mirroring the
    /// backend's ingest: attestation documents are checked structurally
    /// but NOT against the AWS Nitro CA chain (QEMU enclaves can only
    /// produce fake, unsigned documents).
    pub debug_mode: bool,
    /// Whether the walk's final in-force state (genesis advanced by
    /// every verified promotion boot) equals the enclave row's current
    /// `pcrs` + `image_digest`. `false` means the chain does not
    /// explain what the row records: treat the chain as NOT verified
    /// even if every individual link validated.
    pub tip_matches_row: bool,
    pub links: Vec<VerifiedLink>,
}

/// Fetch the enclave + its chain and re-validate end-to-end.
///
/// Two backend round-trips: `GET /enclaves/{id}` for the validator
/// context (PCRs, image digest, control pubkey, upgradable flag) and
/// `GET /enclaves/{id}/upgrade-chain` for the link list. The links are
/// handed to `enclavia_protocol::chain::validate_chain`, which
/// reconstructs the historical context each link saw at ingest time
/// (the row state changes across upgrades, so validating history
/// against today's row would reject perfectly good links) and ties the
/// walk's final state back to the row (`tip_matches_row`).
///
/// Per-link validation failures are recorded on the link and do not
/// abort the walk — the user wants to see the whole chain even when a
/// row is broken, so they can diagnose what went wrong.
pub async fn chain(client: &ApiClient, id: &str) -> Result<ChainSummary, CliError> {
    let enclave = client.get_enclave(id).await?;
    let wire_links = client.get_enclave_chain(id).await?;

    // `mode` is CLI-specific (it picks the debug attestation path); the
    // rest of the validator context is the shared, tolerant
    // `EnclaveChainRow` parse used by every chain consumer.
    let debug_mode = debug_mode_from_enclave_row(&enclave);
    let row: EnclaveChainRow = serde_json::from_value(enclave)
        .map_err(|e| CliError::Other(format!("enclave row: {e}")))?;
    let control_public_key_b64 = row
        .control_public_key
        .as_deref()
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b));

    let now = Utc::now();
    let mut links: Vec<RecordedLink> = Vec::with_capacity(wire_links.len());
    for wire in &wire_links {
        // into_recorded_link carries `created_at` as the ingest
        // reference instant: time-dependent rules (revocations must
        // precede their target's valid_from) are judged against the
        // clock at ingest, not the walk's.
        links.push(
            wire.into_recorded_link()
                .map_err(|e| CliError::Other(format!("decoding chain link: {e}")))?,
        );
    }
    let walk = validate_chain(
        &links,
        &row.pcrs,
        &row.image_digest,
        row.control_public_key.as_deref(),
        row.upgradable,
        now,
        debug_mode,
    );

    let mut out: Vec<VerifiedLink> = Vec::with_capacity(wire_links.len());
    for ((wire, rl), outcome) in wire_links
        .iter()
        .zip(links.iter())
        .zip(walk.outcomes.into_iter())
    {
        let payload = decode_payload(&rl.link.kind, &rl.link.payload);
        let validation = outcome
            .map(|o| match o {
                enclavia_protocol::chain::Outcome::Append { sequence } => {
                    VerificationOk::Append { sequence }
                }
                enclavia_protocol::chain::Outcome::Dedup => VerificationOk::Dedup,
            })
            .map_err(|e| e.to_string());
        out.push(VerifiedLink {
            id: wire.id,
            sequence: wire.sequence,
            kind: wire.kind,
            created_at: wire.created_at,
            payload,
            attestation_bytes: rl.link.attestation.len(),
            signature_bytes: rl.link.signature.as_ref().map(|s| s.len()),
            validation,
        });
    }

    Ok(ChainSummary {
        enclave_id: id.to_string(),
        upgradable: row.upgradable,
        image_digest: row.image_digest,
        pcrs: row.pcrs,
        control_public_key: control_public_key_b64,
        debug_mode,
        tip_matches_row: walk.tip_matches_row,
        links: out,
    })
}

/// `mode` field off the enclave row. The backend stamps its
/// deployment-wide mode here (`"debug"` for the QEMU launcher) and uses
/// the same flag at chain-ingest time, so the local re-validation must
/// run with it too: debug enclaves can only produce fake attestation
/// documents, which the validator then checks structurally instead of
/// against the AWS Nitro CA chain.
fn debug_mode_from_enclave_row(enclave: &serde_json::Value) -> bool {
    enclave.get("mode").and_then(|v| v.as_str()) == Some("debug")
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

    /// The chain walker mirrors the backend's ingest-time `debug_mode`
    /// flag, read off the enclave row's `mode` field. (The rest of the
    /// row context is parsed by the shared `EnclaveChainRow`, tested in
    /// `enclavia-protocol`.)
    #[test]
    fn debug_mode_from_enclave_row_matches_mode_field() {
        let debug_row = serde_json::json!({ "mode": "debug" });
        assert!(debug_mode_from_enclave_row(&debug_row));
        let prod_row = serde_json::json!({ "mode": "production" });
        assert!(!debug_mode_from_enclave_row(&prod_row));
        let absent_row = serde_json::json!({});
        assert!(!debug_mode_from_enclave_row(&absent_row));
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
