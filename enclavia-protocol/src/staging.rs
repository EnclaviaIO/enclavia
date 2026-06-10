//! Wire DTOs for the staged-upgrade API surface (#47).
//!
//! These types are shared between:
//! - The backend's `POST /enclaves/{id}/upgrades` response and
//!   `GET /enclaves/{id}/upgrades/{upgrade_id}` response.
//! - The CLI's display and `--json` output.
//! - Future SDK consumers that want to poll upgrade status.
//!
//! Deliberately NO `eif_path`: that is a server-internal filesystem path
//! that must never appear in API responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chain::PcrsHex;

/// Lifecycle of a staged upgrade. Transitions are monotonic except that
/// `Staged` can transition to either `Confirmed` (happy path) or `Revoked`
/// (operator calls revoke before `valid_from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StagedUpgradeStatus {
    /// The new EIF is being built. `pcrs` and `image_digest` are not yet
    /// available.
    Building,
    /// Build finished; `pcrs` and `image_digest` are recorded. The upgrade
    /// is awaiting operator confirmation; nothing has been sent to the
    /// running enclave yet and no `valid_from` is set.
    Staged,
    /// The operator has called `POST /enclaves/{id}/upgrades/{uid}/confirm`:
    /// the backend fixed `valid_from`, signed the upgrade-auth payload, and
    /// dispatched it to the running enclave as a `PrepareUpgrade` control
    /// command; the enclave emitted an `Upgrade` chain link and
    /// acknowledged. The new version may launch once `valid_from` passes.
    Confirmed,
    /// The new enclave has started successfully with the new image. The
    /// upgrade is complete.
    Promoted,
    /// The operator revoked a confirmed upgrade before `valid_from`. The
    /// running enclave has rolled back its LUKS keyslot (if applicable) and
    /// emitted a `Revocation` chain link.
    Revoked,
    /// Build or chain-link submission failed. See `error_message`.
    Failed,
    /// Staged but never confirmed within the backend's staleness window;
    /// garbage-collected.
    Expired,
}

/// API-facing representation of a staged upgrade. Returned by the backend on
/// creation and on every subsequent status poll. Consumed by the CLI for
/// display and by SDK consumers for programmatic workflows.
///
/// ## Field notes
///
/// - `image_digest`: not available while `status == Building`; the backend
///   fills it in once the EIF build completes.
/// - `pcrs`: not available while `status == Building`.
/// - `valid_from`: chosen and signed into the upgrade-auth payload at
///   confirm time; `None` until `status == Confirmed`.
/// - `upgrade_link_id`: the chain entry UUID of the `Upgrade` link the
///   running enclave emitted. Set once `status == Confirmed`.
/// - `revocation_link_id`: set only when `status == Revoked`.
/// - `error_message`: non-empty only on `status == Failed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedUpgradeJson {
    /// Backend-assigned UUID for this upgrade record.
    pub id: Uuid,
    /// UUID of the enclave this upgrade targets.
    pub enclave_id: Uuid,
    /// Current lifecycle status.
    pub status: StagedUpgradeStatus,
    /// Docker image reference (as supplied at creation, e.g.
    /// `<registry>/<owner>/<repo>:<tag>`).
    pub docker_image: String,
    /// Manifest digest of the built image. `None` while `status ==
    /// Building`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    /// PCR0/1/2 for the new EIF. `None` while `status == Building`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcrs: Option<PcrsHex>,
    /// Wall-clock time after which the new enclave version may launch.
    /// `None` until the operator confirms (it is chosen at confirm time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// Chain entry UUID of the `Upgrade` link emitted by the running enclave.
    /// `None` until the enclave acknowledges the `PrepareUpgrade` dispatched
    /// at confirm time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_link_id: Option<Uuid>,
    /// Chain entry UUID of the `Revocation` link, set only when `status ==
    /// Revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_link_id: Option<Uuid>,
    /// Human-readable error details. Non-empty only on `status == Failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Wall-clock time this upgrade record was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> StagedUpgradeJson {
        StagedUpgradeJson {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            enclave_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            status: StagedUpgradeStatus::Confirmed,
            docker_image: "registry.example.com/owner/app:v2".into(),
            image_digest: Some("sha256:abcdef".into()),
            pcrs: Some(PcrsHex {
                pcr0: "aa".repeat(24),
                pcr1: "bb".repeat(24),
                pcr2: "cc".repeat(24),
            }),
            valid_from: Some(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()),
            upgrade_link_id: Some(Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap()),
            revocation_link_id: None,
            error_message: None,
            created_at: Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn staged_upgrade_json_round_trip() {
        let orig = sample();
        let json = serde_json::to_string(&orig).unwrap();
        let back: StagedUpgradeJson = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, orig.id);
        assert_eq!(back.enclave_id, orig.enclave_id);
        assert_eq!(back.status, orig.status);
        assert_eq!(back.docker_image, orig.docker_image);
        assert_eq!(back.image_digest, orig.image_digest);
        assert_eq!(back.upgrade_link_id, orig.upgrade_link_id);
        assert!(back.revocation_link_id.is_none());
        assert!(back.error_message.is_none());
    }

    /// Lock the exact JSON field names. Changing these is a wire break.
    #[test]
    fn staged_upgrade_json_field_names() {
        let v = serde_json::to_value(sample()).unwrap();
        // Required fields always present.
        assert!(v.get("id").is_some(), "missing id");
        assert!(v.get("enclave_id").is_some(), "missing enclave_id");
        assert!(v.get("status").is_some(), "missing status");
        assert!(v.get("docker_image").is_some(), "missing docker_image");
        assert!(v.get("created_at").is_some(), "missing created_at");
        // Optional fields present when Some.
        assert!(v.get("image_digest").is_some(), "missing image_digest");
        assert!(v.get("pcrs").is_some(), "missing pcrs");
        assert!(v.get("valid_from").is_some(), "missing valid_from");
        assert!(
            v.get("upgrade_link_id").is_some(),
            "missing upgrade_link_id"
        );
        // Absent when None (skip_serializing_if).
        assert!(
            v.get("revocation_link_id").is_none(),
            "revocation_link_id should be absent"
        );
        assert!(
            v.get("error_message").is_none(),
            "error_message should be absent"
        );
    }

    #[test]
    fn staged_upgrade_status_serde_lowercase() {
        let cases = [
            (StagedUpgradeStatus::Building, "building"),
            (StagedUpgradeStatus::Staged, "staged"),
            (StagedUpgradeStatus::Confirmed, "confirmed"),
            (StagedUpgradeStatus::Promoted, "promoted"),
            (StagedUpgradeStatus::Revoked, "revoked"),
            (StagedUpgradeStatus::Failed, "failed"),
            (StagedUpgradeStatus::Expired, "expired"),
        ];
        for (status, expected_json) in &cases {
            let got = serde_json::to_string(status).unwrap();
            assert_eq!(got, format!("\"{expected_json}\""), "status {status:?}");
            let back: StagedUpgradeStatus = serde_json::from_str(&got).unwrap();
            assert_eq!(back, *status);
        }
    }

    #[test]
    fn building_status_has_no_optional_fields() {
        let building = StagedUpgradeJson {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap(),
            enclave_id: Uuid::parse_str("00000000-0000-0000-0000-000000000011").unwrap(),
            status: StagedUpgradeStatus::Building,
            docker_image: "registry.example.com/owner/app:v3".into(),
            image_digest: None,
            pcrs: None,
            valid_from: None,
            upgrade_link_id: None,
            revocation_link_id: None,
            error_message: None,
            created_at: Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        };
        let v = serde_json::to_value(&building).unwrap();
        assert!(v.get("image_digest").is_none());
        assert!(v.get("pcrs").is_none());
        assert!(v.get("valid_from").is_none());
        assert!(v.get("upgrade_link_id").is_none());
    }
}
