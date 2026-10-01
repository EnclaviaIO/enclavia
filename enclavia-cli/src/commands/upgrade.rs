//! Public upgrade-chain CLI surface and staged-upgrade
//! management commands.
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
use enclavia_protocol::pin_identity::PinIdentity;
use enclavia_protocol::signing::{SignedDomain, decode_canonical, verify_control_signature};
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
    Upgrade(Box<UpgradePayload>),
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
/// against today's row would reject perfectly good links), checks every
/// payload binds the requested enclave id, and ties the walk's final
/// state back to the row (`tip_matches_row`).
///
/// Per-link validation failures are recorded on the link and do not
/// abort the walk — the user wants to see the whole chain even when a
/// row is broken, so they can diagnose what went wrong.
pub async fn chain(client: &ApiClient, id: &str) -> Result<ChainSummary, CliError> {
    let enclave = client.get_enclave(id).await?;
    let wire_links = client.get_enclave_chain(id).await?;

    // The expected enclave id for the walk is the (already resolved)
    // id the user asked about — the same id both GETs above were
    // addressed to — NOT anything read off the untrusted row, so a
    // transplanted chain cannot satisfy the validator's enclave_id
    // binding. `run_upgrade` resolves prefixes to full UUIDs before
    // calling here; the parse is a hard failure rather than a silent
    // skip in case a future caller forgets. Note the CLI's transplant
    // protection is inherently weaker than the SDK's: the resolved id
    // itself comes from the backend's list endpoint, so a malicious
    // backend controls both sides of this check. That's fine for an
    // inspection tool — the load-bearing enclave_id binding is the
    // SDK's caller-pinned id.
    let enclave_uuid = Uuid::parse_str(id)
        .map_err(|e| CliError::Other(format!("enclave id `{id}` is not a UUID: {e}")))?;

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
        &enclave_uuid,
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
        ChainLinkKind::Boot => decode_canonical::<BootPayload>(bytes)
            .ok()
            .map(DecodedPayload::Boot),
        ChainLinkKind::Upgrade => decode_canonical::<UpgradePayload>(bytes)
            .ok()
            .map(|p| DecodedPayload::Upgrade(Box::new(p))),
        ChainLinkKind::Revocation => decode_canonical::<RevocationPayload>(bytes)
            .ok()
            .map(DecodedPayload::Revocation),
    }
}

// ---------------------------------------------------------------------------
// Staged-upgrade management
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
///
/// Custody dispatch: the enclave row's `control_key_mode` decides
/// the path. Managed (or absent, pre-custody backends) keeps the
/// original single-shot call; self-hosted runs the two-phase
/// prepare/sign/submit flow against the locally-held control key.
pub async fn confirm_upgrade(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
) -> Result<StagedUpgradeJson, CliError> {
    let enclave = client.get_enclave(enclave_id).await?;
    match control_key_mode(&enclave) {
        ControlKeyMode::SelfHosted => {
            confirm_self_hosted(client, &enclave, enclave_id, upgrade_id, valid_from).await
        }
        ControlKeyMode::Managed => {
            client.confirm_upgrade(enclave_id, upgrade_id, valid_from).await
        }
    }
}

/// Revoke a confirmed upgrade before it fires. The running enclave keeps
/// its current version. Same custody dispatch as [`confirm_upgrade`].
pub async fn revoke_upgrade(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
) -> Result<StagedUpgradeJson, CliError> {
    let enclave = client.get_enclave(enclave_id).await?;
    match control_key_mode(&enclave) {
        ControlKeyMode::SelfHosted => {
            revoke_self_hosted(client, &enclave, enclave_id, upgrade_id).await
        }
        ControlKeyMode::Managed => client.revoke_upgrade(enclave_id, upgrade_id).await,
    }
}

// ---------------------------------------------------------------------------
// Self-hosted custody: two-phase confirm/revoke
// ---------------------------------------------------------------------------

/// Control-key custody mode read off the enclave row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKeyMode {
    /// Backend holds the control key (or the row predates custody
    /// modes): single-shot confirm/revoke.
    Managed,
    /// The user holds the control key: two-phase prepare/submit.
    SelfHosted,
}

/// Detect the custody mode from the enclave row. Anything other than an
/// explicit `"self_hosted"` (including a missing field on pre-custody
/// backends) is managed, preserving the existing single-shot behaviour.
pub fn control_key_mode(enclave: &serde_json::Value) -> ControlKeyMode {
    match enclave.get("control_key_mode").and_then(|v| v.as_str()) {
        Some("self_hosted") => ControlKeyMode::SelfHosted,
        _ => ControlKeyMode::Managed,
    }
}

/// Locate the enclave's control key in the local index and open a
/// signer for it. Interactive: the YubiKey backend prompts for its PIN
/// on stderr.
fn signer_for_enclave(
    enclave: &serde_json::Value,
) -> Result<Box<dyn crate::signer::ControlSigner>, CliError> {
    let pubkey_b64 = enclave
        .get("control_public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::Other(
                "enclave is self-hosted but has no control_public_key on its row (backend bug?)"
                    .into(),
            )
        })?;
    let pubkey = crate::keys::decode_public_key(pubkey_b64)?;
    let index = crate::keys::load_index()?;
    let (name, entry) = index.find_by_public_key(&pubkey).ok_or_else(|| {
        CliError::Other(format!(
            "this enclave uses self-hosted custody, but no local key matches its control \
             public key (fingerprint {}). Run this command from the machine holding the key, \
             or check `enclavia key list`.",
            crate::keys::fingerprint(&pubkey)
        ))
    })?;
    eprintln!(
        "Self-hosted custody: signing with control key {name:?} ({}).",
        crate::keys::fingerprint(&pubkey)
    );
    crate::signer::signer_for_entry(name, entry)
}

/// Two-phase confirm: prepare, sign locally (inner + envelope), submit.
/// On a stale-nonce 409 from submit, re-runs prepare and retries ONCE
/// (the enclave rotates its control nonce whenever a control command is
/// processed, so a concurrent command invalidates our signed bytes).
async fn confirm_self_hosted(
    client: &ApiClient,
    enclave: &serde_json::Value,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
) -> Result<StagedUpgradeJson, CliError> {
    let signer = signer_for_enclave(enclave)?;
    let prep = client.confirm_prepare(enclave_id, upgrade_id, valid_from).await?;
    eprintln!(
        "Upgrade will take effect at {} once confirmed. Two signatures are required.",
        prep.valid_from
    );
    let submission = crate::signer::sign_confirm_submission(signer.as_ref(), &prep)?;
    submitting("Confirming");
    match client.confirm_submit(enclave_id, upgrade_id, &submission).await {
        Err(CliError::Conflict(msg)) => {
            eprintln!(
                "Submit rejected (stale nonce): {msg}. Re-running prepare and retrying once."
            );
            let prep = client.confirm_prepare(enclave_id, upgrade_id, valid_from).await?;
            let submission = crate::signer::sign_confirm_submission(signer.as_ref(), &prep)?;
            submitting("Confirming");
            client.confirm_submit(enclave_id, upgrade_id, &submission).await
        }
        other => other,
    }
}

/// Signing is done; the submit round-trip through the backend to the
/// enclave takes a while, so tell the user what the silence is.
fn submitting(verb: &str) {
    eprintln!("Signatures complete. {verb} with the enclave, do not close this terminal...");
}

/// Two-phase revoke; same retry-once-on-409 contract as
/// [`confirm_self_hosted`].
///
/// The backend builds the `RevocationPayload`, and in self-hosted custody
/// the backend is not trusted. Before signing, every prepared payload goes
/// through [`check_revocation_target`], which verifies that it names (by
/// `revokes_link`) an upgrade link carrying OUR control key's signature and
/// matching the staged upgrade being revoked. Without that check the backend
/// could get a revocation of some other link signed, the synchronizer would
/// accept it, and the upgrade the user meant to cancel would still go
/// through.
async fn revoke_self_hosted(
    client: &ApiClient,
    enclave: &serde_json::Value,
    enclave_id: &str,
    upgrade_id: &str,
) -> Result<StagedUpgradeJson, CliError> {
    let signer = signer_for_enclave(enclave)?;
    // `signer_for_enclave` only succeeds when a LOCAL key has this public
    // key, so it is our own key, not merely what the backend's row says.
    let control_pubkey = enclave
        .get("control_public_key")
        .and_then(|v| v.as_str())
        .map(crate::keys::decode_public_key)
        .transpose()?
        .ok_or_else(|| CliError::Other("enclave has no control_public_key".into()))?;
    let enclave_uuid = Uuid::parse_str(enclave_id)
        .map_err(|e| CliError::Other(format!("invalid enclave id {enclave_id:?}: {e}")))?;

    let prep =
        prepare_checked_revocation(client, enclave_id, upgrade_id, enclave_uuid, &control_pubkey)
            .await?;
    eprintln!("Revoking upgrade {upgrade_id}. Two signatures are required.");
    let submission = crate::signer::sign_revoke_submission(signer.as_ref(), &prep)?;
    submitting("Revoking");
    match client.revoke_submit(enclave_id, upgrade_id, &submission).await {
        Err(CliError::Conflict(msg)) => {
            eprintln!(
                "Submit rejected (stale nonce): {msg}. Re-running prepare and retrying once."
            );
            let prep = prepare_checked_revocation(
                client,
                enclave_id,
                upgrade_id,
                enclave_uuid,
                &control_pubkey,
            )
            .await?;
            let submission = crate::signer::sign_revoke_submission(signer.as_ref(), &prep)?;
            submitting("Revoking");
            client.revoke_submit(enclave_id, upgrade_id, &submission).await
        }
        other => other,
    }
}

/// `revoke/prepare`, then [`check_revocation_target`] against the staged
/// upgrade and the enclave's chain, printing what will be cancelled. Only a
/// payload that passes is returned for signing.
async fn prepare_checked_revocation(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
    enclave_uuid: Uuid,
    control_pubkey: &[u8; 65],
) -> Result<enclavia_protocol::custody::RevokePrepareResponse, CliError> {
    let prep = client.revoke_prepare(enclave_id, upgrade_id).await?;
    let staged = client.get_upgrade(enclave_id, upgrade_id).await?;
    let chain = client
        .get_enclave_chain(enclave_id)
        .await?
        .iter()
        .map(|l| l.into_chain_link())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CliError::Other(format!("upgrade chain link does not decode: {e}")))?;
    let target = check_revocation_target(
        &prep.payload,
        enclave_uuid,
        control_pubkey,
        &staged,
        &chain,
        Utc::now(),
    )?;
    print_revocation_target(&target);
    Ok(prep)
}

/// The upgrade a self-hosted revocation cancels, as verified by
/// [`check_revocation_target`].
#[derive(Debug)]
pub struct RevocationTarget {
    /// `upgrade_link_hash` of the link, the value the revocation signs.
    pub link_hash: [u8; 32],
    /// The link's verified payload.
    pub upgrade: UpgradePayload,
}

/// Display lines for a pin identity: PCR0-2, then each nonzero user PCR, or
/// one line saying user PCRs 16-31 are all zero. `label` prefixes each
/// name (e.g. `to.`); names are padded to line values up in a column.
pub fn identity_lines(label: &str, identity: &PinIdentity) -> Vec<String> {
    let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let row = |name: String, value: String| format!("{:<13}{value}", name + ":");
    let mut lines: Vec<String> = identity
        .image()
        .iter()
        .enumerate()
        .map(|(i, v)| row(format!("{label}PCR{i}"), to_hex(v)))
        .collect();
    let mut any_user = false;
    for (index, value) in identity.nonzero_user_pcrs() {
        any_user = true;
        lines.push(row(format!("{label}PCR{index}"), to_hex(value)));
    }
    if !any_user {
        lines.push(row(format!("{label}PCR16-31"), "all zero".into()));
    }
    lines
}

fn print_revocation_target(t: &RevocationTarget) {
    let hash: String = t.link_hash.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("This revocation cancels the upgrade link signed by your control key:");
    eprintln!("  link hash:   {hash}");
    eprintln!("  target:      {}", t.upgrade.image_digest);
    for line in identity_lines("to.", &t.upgrade.to) {
        eprintln!("  {line}");
    }
    eprintln!(
        "  valid_from:  {}",
        t.upgrade.valid_from.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

/// Check a backend-built `RevocationPayload` before signing it (self-hosted
/// custody, where the backend is untrusted).
///
/// Accepts only when ALL of these hold:
/// 1. The payload is for this enclave.
/// 2. The chain entry its `revokes` id points at is an `Upgrade` link whose
///    signature verifies over its payload under OUR control key. The backend
///    cannot forge that signature, so this is an upgrade we approved.
/// 3. `revokes_link` equals `upgrade_link_hash` of that link's payload: the
///    signature we are about to make cancels exactly that link.
/// 4. The link matches the staged upgrade being revoked (its chain id,
///    target image and PCRs, `valid_from`), and it is still pending
///    (`valid_from` in the future).
///
/// The staged row and the chain both come from the backend. Within them
/// the backend can at most choose between upgrades we signed ourselves; the
/// returned target is printed so the user sees which one is cancelled.
pub fn check_revocation_target(
    revocation_payload: &[u8],
    enclave_id: Uuid,
    control_pubkey: &[u8; 65],
    staged: &StagedUpgradeJson,
    chain: &[enclavia_protocol::chain::ChainLink],
    now: DateTime<Utc>,
) -> Result<RevocationTarget, CliError> {
    use p256::ecdsa::VerifyingKey;
    let refuse = |why: &str| {
        Err(CliError::Other(format!(
            "refusing to sign the revocation the backend prepared: {why}"
        )))
    };

    let revocation: RevocationPayload = decode_canonical(revocation_payload)
        .map_err(|e| CliError::Other(format!("prepared payload is not a RevocationPayload: {e}")))?;
    if revocation.enclave_id != enclave_id {
        return refuse("it is for another enclave");
    }
    if staged.upgrade_link_id != Some(revocation.revokes) {
        return refuse("it references a different chain entry than the staged upgrade");
    }
    let Some(link) = chain.iter().find(|l| l.id == Some(revocation.revokes)) else {
        return refuse("the upgrade link it references is not on the enclave's chain");
    };
    if link.kind != ChainLinkKind::Upgrade {
        return refuse("the chain entry it references is not an upgrade link");
    }
    let verifying = VerifyingKey::from_sec1_bytes(control_pubkey)
        .map_err(|e| CliError::Other(format!("control public key does not decode: {e}")))?;
    let signature_ok = link.signature.as_deref().is_some_and(|sig| {
        verify_control_signature(&verifying, SignedDomain::UpgradePayload, &link.payload, sig)
            .is_ok()
    });
    if !signature_ok {
        return refuse("the upgrade link it references is not signed by your control key");
    }
    let link_hash = enclavia_protocol::chain::upgrade_link_hash(&link.payload);
    if link_hash != revocation.revokes_link {
        return refuse("its revokes_link names a different link than the upgrade it references");
    }
    let upgrade: UpgradePayload = decode_canonical(&link.payload)
        .map_err(|e| CliError::Other(format!("upgrade link payload does not decode: {e}")))?;
    if upgrade.enclave_id != enclave_id {
        return refuse("the upgrade link it references is for another enclave");
    }
    let staged_pcrs = staged.pcrs.as_ref();
    let to_image = upgrade.to.image_pcrs_hex();
    let pcrs_match = staged_pcrs.is_some_and(|p| {
        p.pcr0.eq_ignore_ascii_case(&to_image.pcr0)
            && p.pcr1.eq_ignore_ascii_case(&to_image.pcr1)
            && p.pcr2.eq_ignore_ascii_case(&to_image.pcr2)
    });
    if !pcrs_match
        || staged.image_digest.as_deref() != Some(upgrade.image_digest.as_str())
        || staged.valid_from != Some(upgrade.valid_from)
    {
        return refuse("the upgrade link it references does not match the staged upgrade");
    }
    if upgrade.valid_from <= now {
        return refuse("the upgrade link it references is already active; too late to revoke");
    }
    Ok(RevocationTarget { link_hash, upgrade })
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

    fn identity_fixture() -> PinIdentity {
        PinIdentity::new(
            [[0x00; 48], [0x11; 48], [0x22; 48]],
            enclavia_protocol::pin_identity::ZERO_USER_PCRS,
        )
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
    fn identity_lines_show_user_pcrs_only_when_set() {
        let plain = identity_fixture();
        let lines = identity_lines("to.", &plain);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], format!("to.PCR0:     {}", "00".repeat(48)));
        assert_eq!(lines[3], "to.PCR16-31: all zero");

        let mut user = enclavia_protocol::pin_identity::ZERO_USER_PCRS;
        user[1] = [0xab; 48];
        let lines = identity_lines("to.", &plain.with_user_pcrs(user));
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[3], format!("to.PCR17:    {}", "ab".repeat(48)));
    }

    #[test]
    fn decode_payload_round_trips_upgrade() {
        let payload = UpgradePayload {
            enclave_id: Uuid::nil(),
            from: identity_fixture(),
            to: identity_fixture(),
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
            revokes_link: [0x45; 32],
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
    // Custody detection
    // -----------------------------------------------------------------------

    /// Only an explicit `"self_hosted"` selects the two-phase flow;
    /// everything else (managed, unknown values, missing field on
    /// pre-custody backends, wrong type) stays on the single-shot path.
    #[test]
    fn control_key_mode_detection() {
        let self_hosted = serde_json::json!({ "control_key_mode": "self_hosted" });
        assert_eq!(control_key_mode(&self_hosted), ControlKeyMode::SelfHosted);

        for row in [
            serde_json::json!({ "control_key_mode": "managed" }),
            serde_json::json!({ "control_key_mode": null }),
            serde_json::json!({ "control_key_mode": 3 }),
            serde_json::json!({}),
        ] {
            assert_eq!(control_key_mode(&row), ControlKeyMode::Managed, "row: {row}");
        }
    }

    /// A self-hosted row without any matching local key must fail with
    /// the "no local key matches" guidance (and never fall back to the
    /// managed single-shot path).
    #[test]
    fn signer_for_enclave_errors_without_matching_key() {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        // A valid control pubkey that is certainly not in the (possibly
        // existing) index on the machine running the tests.
        let sk = p256::SecretKey::from_bytes(&[0xE7u8; 32].into()).unwrap();
        let pk = sk.public_key().to_encoded_point(false);
        let row = serde_json::json!({
            "control_key_mode": "self_hosted",
            "control_public_key": base64::engine::general_purpose::STANDARD.encode(pk.as_bytes()),
        });
        let err = match signer_for_enclave(&row) {
            Err(e) => e,
            Ok(_) => panic!("must not find a signer"),
        };
        assert!(err.to_string().contains("no local key matches"), "got: {err}");

        // Missing pubkey on a self-hosted row is a distinct, clear error.
        let row = serde_json::json!({ "control_key_mode": "self_hosted" });
        let err = match signer_for_enclave(&row) {
            Err(e) => e,
            Ok(_) => panic!("must fail"),
        };
        assert!(err.to_string().contains("control_public_key"), "got: {err}");
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

    // --- self-hosted revocation target check ------------------------------

    mod revocation_target {
        use super::*;
        use enclavia_protocol::chain::{ChainLink, upgrade_link_hash};
        use enclavia_protocol::signing::sign_control;
        use p256::ecdsa::SigningKey;

        fn key(seed: u8) -> (SigningKey, [u8; 65]) {
            let mut scalar = [0u8; 32];
            scalar[0] = 0x01;
            scalar[1] = seed;
            let sk = SigningKey::from_slice(&scalar).unwrap();
            let mut pk = [0u8; 65];
            pk.copy_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
            (sk, pk)
        }

        fn now() -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap()
        }

        fn enclave() -> Uuid {
            Uuid::from_u128(0xe1)
        }

        /// A signed upgrade link on the chain, with chain id `id`.
        fn upgrade(sk: &SigningKey, id: Uuid, issued_at: DateTime<Utc>) -> ChainLink {
            let payload = UpgradePayload {
                enclave_id: enclave(),
                from: identity_fixture(),
                to: identity_fixture(),
                image_digest: "sha256:next".into(),
                valid_from: now() + chrono::Duration::days(2),
                issued_at,
                nonce: id.as_bytes().to_vec(),
            };
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
            let sig = sign_control(sk, SignedDomain::UpgradePayload, &bytes);
            ChainLink {
                id: Some(id),
                sequence: Some(1),
                kind: ChainLinkKind::Upgrade,
                payload: bytes,
                attestation: vec![],
                signature: Some(sig.to_vec()),
            }
        }

        fn staged(link_id: Uuid) -> StagedUpgradeJson {
            StagedUpgradeJson {
                id: Uuid::from_u128(0x5a),
                enclave_id: enclave(),
                status: StagedUpgradeStatus::Confirmed,
                docker_image: "img".into(),
                image_digest: Some("sha256:next".into()),
                pcrs: Some(pcrs_fixture()),
                valid_from: Some(now() + chrono::Duration::days(2)),
                upgrade_link_id: Some(link_id),
                revocation_link_id: None,
                error_message: None,
                builder_rev: None,
                crates_rev: None,
                synchronizer_pcrs: None,
                synchronizer_enabled: true,
                upgrade_target: true,
                created_at: now(),
            }
        }

        fn revocation(revokes: Uuid, revokes_link: [u8; 32]) -> Vec<u8> {
            let payload = RevocationPayload {
                enclave_id: enclave(),
                revokes,
                issued_at: now(),
                nonce: vec![0x46; 32],
                revokes_link,
            };
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
            bytes
        }

        fn check(
            payload: &[u8],
            pk: &[u8; 65],
            staged: &StagedUpgradeJson,
            chain: &[ChainLink],
        ) -> Result<RevocationTarget, CliError> {
            check_revocation_target(payload, enclave(), pk, staged, chain, now())
        }

        #[test]
        fn names_the_verified_link() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x11);
            let link = upgrade(&sk, id, now());
            let hash = upgrade_link_hash(&link.payload);
            let t = check(&revocation(id, hash), &pk, &staged(id), &[link]).unwrap();
            assert_eq!(t.link_hash, hash);
        }

        /// Hostile backend: the link carries a far-future `issued_at`. That
        /// does not matter any more; the revocation names the link's hash.
        #[test]
        fn far_future_issued_at_is_still_the_named_link() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x12);
            let link = upgrade(&sk, id, now() + chrono::Duration::days(36500));
            let hash = upgrade_link_hash(&link.payload);
            assert!(check(&revocation(id, hash), &pk, &staged(id), &[link]).is_ok());
        }

        /// Hostile backend: the payload's `revokes_link` names another link
        /// (even another genuine one of ours) than the upgrade it references.
        #[test]
        fn mismatched_revokes_link_is_refused() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x13);
            let other = upgrade(&sk, Uuid::from_u128(0x14), now());
            let link = upgrade(&sk, id, now());
            let payload = revocation(id, upgrade_link_hash(&other.payload));
            let err = check(&payload, &pk, &staged(id), &[other, link]).unwrap_err();
            assert!(err.to_string().contains("different link"), "{err}");
        }

        /// A link the backend made up (not signed by our key) is not an
        /// upgrade we approved: refused.
        #[test]
        fn link_not_signed_by_our_key_is_refused() {
            let (_, pk) = key(1);
            let (backend_sk, _) = key(2);
            let id = Uuid::from_u128(0x16);
            let link = upgrade(&backend_sk, id, now());
            let hash = upgrade_link_hash(&link.payload);
            let err = check(&revocation(id, hash), &pk, &staged(id), &[link]).unwrap_err();
            assert!(err.to_string().contains("not signed by your control key"), "{err}");
        }

        /// A link carrying our key's signature in another domain (say, a
        /// revocation signature over bytes that also decode as an upgrade)
        /// is not an upgrade we approved.
        #[test]
        fn link_signed_in_another_domain_is_refused() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x1a);
            let mut link = upgrade(&sk, id, now());
            link.signature = Some(
                sign_control(&sk, SignedDomain::RevocationPayload, &link.payload).to_vec(),
            );
            let hash = upgrade_link_hash(&link.payload);
            let err = check(&revocation(id, hash), &pk, &staged(id), &[link]).unwrap_err();
            assert!(err.to_string().contains("not signed by your control key"), "{err}");
        }

        /// The revocation must reference the staged upgrade being revoked.
        #[test]
        fn revocation_of_another_chain_entry_is_refused() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x17);
            let other_id = Uuid::from_u128(0x18);
            let link = upgrade(&sk, id, now());
            let other = upgrade(&sk, other_id, now());
            let payload = revocation(other_id, upgrade_link_hash(&other.payload));
            let err = check(&payload, &pk, &staged(id), &[link, other]).unwrap_err();
            assert!(err.to_string().contains("different chain entry"), "{err}");
        }

        /// A link that does not match the staged row (another target) is
        /// refused, as is one that is already active.
        #[test]
        fn link_must_match_the_staged_upgrade_and_be_pending() {
            let (sk, pk) = key(1);
            let id = Uuid::from_u128(0x19);
            let link = upgrade(&sk, id, now());
            let hash = upgrade_link_hash(&link.payload);
            let mut other_target = staged(id);
            other_target.image_digest = Some("sha256:elsewhere".into());
            let err = check(&revocation(id, hash), &pk, &other_target, &[link.clone()])
                .unwrap_err();
            assert!(err.to_string().contains("does not match"), "{err}");

            let late = check_revocation_target(
                &revocation(id, hash),
                enclave(),
                &pk,
                &staged(id),
                &[link],
                now() + chrono::Duration::days(3),
            )
            .unwrap_err();
            assert!(late.to_string().contains("too late"), "{late}");
        }
    }
}
