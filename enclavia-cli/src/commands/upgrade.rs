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
    AntiRollbackSetting, BootPayload, ChainLinkKind, EnclaveChainRow, PcrsHex, RecordedLink, RevocationPayload,
    UpgradePayload, UPGRADE_DELAY_DEFAULT, UPGRADE_WINDOW_MAX, UPGRADE_WINDOW_MIN,
    upgrade_window_is_valid, validate_chain,
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
/// - `valid_from = None` lets the server default to `now + 7 days`
///   ([`UPGRADE_DELAY_DEFAULT`]).
/// - A past timestamp is clamped to `now` by the server.
///
/// Custody dispatch: the enclave row's `control_key_mode` decides
/// the path. Managed (or absent, pre-custody backends) keeps the
/// original single-shot call; self-hosted runs the two-phase
/// prepare/sign/submit flow against the locally-held control key, and
/// needs `target`: what the upgraded enclave must measure, from a source
/// the backend does not control (see [`UpgradeTarget`]).
pub async fn confirm_upgrade(
    client: &ApiClient,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
    target: Option<UpgradeTarget>,
) -> Result<StagedUpgradeJson, CliError> {
    let enclave = client.get_enclave(enclave_id).await?;
    match control_key_mode(&enclave) {
        ControlKeyMode::SelfHosted => {
            let target = target.ok_or_else(|| {
                CliError::Other(
                    "this enclave uses self-hosted custody: say what the upgraded enclave must \
                     measure before your key signs anything, with --reproduce (rebuild the \
                     staged image locally) or --expect-pcrs (PCRs you built or reproduced \
                     yourself)"
                        .into(),
                )
            })?;
            confirm_self_hosted(client, &enclave, enclave_id, upgrade_id, valid_from, target)
                .await
        }
        ControlKeyMode::Managed => {
            if target.is_some() {
                return Err(CliError::Other(
                    "--reproduce / --expect-pcrs / --expect-digest only apply to self-hosted \
                     custody: in managed custody the backend signs the upgrade itself"
                        .into(),
                ));
            }
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

/// What the owner expects a self-custody upgrade to install, from sources
/// the backend does not control. The backend builds the `UpgradePayload`
/// the owner's key signs; these are what the CLI checks it against first.
#[derive(Debug, Clone)]
pub struct UpgradeTarget {
    /// Where the target's PCR0-2 come from.
    pub pcrs: TargetPcrs,
    /// The image digest the owner pushed. `None` takes the staged row's
    /// digest; the PCRs are what binds the image either way.
    pub image_digest: Option<String>,
    /// Sign even though the target trusts another set of synchronizer
    /// measurements than the running version (a synchronizer rotation; see
    /// [`check_synchronizer_change`]).
    pub accept_synchronizer_change: bool,
}

/// Source of the PCR0-2 the upgraded enclave must measure.
#[derive(Debug, Clone)]
pub enum TargetPcrs {
    /// PCRs the owner obtained independently: their own build, or an
    /// earlier `enclavia reproduce <enclave> --upgrade <id>`.
    Expected(PcrsHex),
    /// Rebuild the staged upgrade now, from its image digest and recorded
    /// sources (`enclavia reproduce --upgrade`), and take the PCRs the local
    /// builder produces.
    Reproduce,
}

/// Parse `--expect-pcrs`: a path to a pcr.json, or inline JSON (detected by
/// a leading `{`), holding PCR0-2 as 96-character hex strings (`PCR0` or
/// `pcr0` keys; other keys, like pcr.json's `HashAlgorithm`, are ignored).
pub fn parse_expected_pcrs(arg: &str) -> Result<PcrsHex, CliError> {
    let trimmed = arg.trim();
    let json = if trimmed.starts_with('{') {
        trimmed.to_string()
    } else {
        std::fs::read_to_string(trimmed)
            .map_err(|e| CliError::Other(format!("cannot read --expect-pcrs file {trimmed:?}: {e}")))?
    };
    let pcrs: PcrsHex = serde_json::from_str(&json)
        .map_err(|e| CliError::Other(format!("--expect-pcrs is not a {{PCR0,PCR1,PCR2}} object: {e}")))?;
    for (name, value) in [("PCR0", &pcrs.pcr0), ("PCR1", &pcrs.pcr1), ("PCR2", &pcrs.pcr2)] {
        if value.len() != 96 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CliError::Other(format!(
                "--expect-pcrs {name} is not 96 hex characters (SHA-384)"
            )));
        }
    }
    Ok(pcrs)
}

/// Check the reproduced target's anti-rollback setting against the running
/// version's ([`AntiRollbackSetting::check_successor`]): anti-rollback is
/// fixed when the enclave is created, so the target keeps it on or off; with
/// it on, the target is built as an upgrade target (otherwise, booted on a
/// blank disk once this upgrade is signed, it would register a fresh volume
/// instead of taking over the enclave's pin, and the real Transition would
/// be refused for good), checks the synchronizer's attestation the same way
/// and trusts at least one synchronizer. A different trust list is checked
/// separately ([`check_synchronizer_change`]).
///
/// `running` comes from the running version's attested boot link, never
/// from the backend's enclave row: the backend sets the build flags and
/// records them, and a hostile one could claim anti-rollback is off and
/// build the target without it, which the reproduce check alone would
/// replay without noticing.
pub fn check_target_role(
    running: &AntiRollbackSetting,
    target: &AntiRollbackSetting,
) -> Result<(), CliError> {
    running.check_successor(target).map_err(|change| {
        CliError::Other(format!(
            "refusing to sign: {change} (running version: {}; staged image: {})",
            anti_rollback_summary(running),
            anti_rollback_summary(target)
        ))
    })
}

/// The synchronizer measurement sets in `running` and not in `target`
/// (removed), and in `target` and not in `running` (added), comparing PCR
/// hex case-insensitively.
pub fn synchronizer_diff(running: &[PcrsHex], target: &[PcrsHex]) -> (Vec<PcrsHex>, Vec<PcrsHex>) {
    let missing_from = |set: &[PcrsHex], p: &PcrsHex| !set.iter().any(|q| q.same_as(p));
    let removed = running.iter().filter(|p| missing_from(target, p)).cloned().collect();
    let added = target.iter().filter(|p| missing_from(running, p)).cloned().collect();
    (removed, added)
}

/// Check the target's trusted synchronizer measurements against the running
/// version's (from its attested boot link). A different set is a
/// synchronizer rotation: the chain allows it, because the owner's signature
/// over the target's PCRs (which cover the measured trust list) authorizes
/// it, so the CLI makes it explicit. It shows the sets removed and added and
/// refuses unless `accept` (`--accept-synchronizer-change`). Without the
/// wiring the list is not used, so it is not compared. `source` says where
/// the target's list comes from.
pub fn check_synchronizer_change(
    running: &AntiRollbackSetting,
    target_synchronizers: &[PcrsHex],
    source: &str,
    accept: bool,
) -> Result<(), CliError> {
    if !running.enabled {
        return Ok(());
    }
    let (removed, added) = synchronizer_diff(&running.synchronizer_pcrs, target_synchronizers);
    if removed.is_empty() && added.is_empty() {
        return Ok(());
    }
    eprintln!(
        "The upgraded image trusts other synchronizers than the running version (target list \
         from {source}):"
    );
    for (sign, set) in [("-", &removed), ("+", &added)] {
        for p in set.iter() {
            eprintln!("  {sign} PCR0 {}", p.pcr0);
            eprintln!("    PCR1 {}", p.pcr1);
            eprintln!("    PCR2 {}", p.pcr2);
        }
    }
    let consequence = "Until a migration protocol exists, the upgraded image works only if the \
                       cluster it trusts holds this enclave's pin: it is an upgrade target and \
                       never registers, so against a cluster without the pin it fail-stops at \
                       boot and the enclave stays down.";
    if !accept {
        return Err(CliError::Other(format!(
            "refusing to sign: this upgrade is a synchronizer rotation ({} measurement set(s) \
             removed, {} added). {consequence} Pass --accept-synchronizer-change to sign it \
             anyway.",
            removed.len(),
            added.len()
        )));
    }
    eprintln!("--accept-synchronizer-change given: signing the rotation. {consequence}");
    Ok(())
}

/// One-line form of [`anti_rollback_lines`] for error messages.
fn anti_rollback_summary(s: &AntiRollbackSetting) -> String {
    if !s.enabled {
        return "anti-rollback off".into();
    }
    format!(
        "anti-rollback on, {}, {} synchronizer attestation, {} trusted synchronizer build(s)",
        if s.upgrade_target { "upgrade target" } else { "first image" },
        if s.debug_attestation { "DEBUG" } else { "Nitro-verified" },
        s.synchronizer_pcrs.len()
    )
}

/// Slack for clock differences between this machine and the backend when
/// comparing `valid_from` with a requested or minimum activation time.
const VALID_FROM_SLACK: chrono::Duration = chrono::Duration::seconds(60);

/// Everything a backend-built upgrade payload is checked against before
/// the owner's key signs it ([`check_upgrade_payload`]).
#[derive(Debug, Clone)]
pub struct UpgradeExpectation {
    /// The enclave being upgraded.
    pub enclave_id: Uuid,
    /// PCR0-2 the enclave runs now: the tip of its chain, every link
    /// verified (Nitro-attested in production mode).
    pub current: PcrsHex,
    /// PCR0-2 the upgraded enclave must measure.
    pub target: PcrsHex,
    /// Image digest the target is built from.
    pub image_digest: String,
    /// The `valid_from` the owner asked for (`--at`, or now for
    /// `--immediate`); `None` for the default delay.
    pub requested_valid_from: Option<DateTime<Utc>>,
    /// The enclave's minimum upgrade delay, from its row. The enclave
    /// enforces its measured value itself (against its own clock); this is
    /// the signer's own check of the same floor.
    pub min_upgrade_delay_secs: u64,
    /// The signer's clock.
    pub now: DateTime<Utc>,
}

fn same_pcrs(a: &PcrsHex, b: &PcrsHex) -> bool {
    a.pcr0.eq_ignore_ascii_case(&b.pcr0)
        && a.pcr1.eq_ignore_ascii_case(&b.pcr1)
        && a.pcr2.eq_ignore_ascii_case(&b.pcr2)
}

/// Check a backend-built `UpgradePayload` before signing it (self-hosted
/// custody, where the backend is untrusted). The signature authorizes
/// moving the enclave's pin, with its data, to the `to` identity from
/// `valid_from` to `valid_until`, so the payload must say exactly what the
/// owner intends. Accepts only when ALL of these hold:
///
/// 1. The bytes are the canonical encoding of an `UpgradePayload` for this
///    enclave.
/// 2. `from` is the enclave's current identity: its PCR0-2 are the verified
///    chain tip, and `to` carries the same user PCRs 16-31 (they hold
///    per-enclave data, the same before and after an upgrade), so the pin
///    cannot be moved to another user-PCR identity of the target image.
/// 3. `to`'s PCR0-2 are the target's ([`UpgradeTarget`]) and `image_digest`
///    is the expected digest.
/// 4. `valid_from` is no earlier than the owner asked for (the default
///    delay when they named no time) and no earlier than the enclave's
///    minimum upgrade delay allows, each less [`VALID_FROM_SLACK`]. Later
///    only postpones the upgrade, and is shown.
/// 5. The window is sane ([`checked_upgrade_window`]).
///
/// `issued_at` and `nonce` are not checked: they name nothing the
/// signature authorizes.
pub fn check_upgrade_payload(
    payload: &[u8],
    expected: &UpgradeExpectation,
) -> Result<UpgradePayload, CliError> {
    let refuse = |why: String| {
        Err(CliError::Other(format!(
            "refusing to sign the upgrade the backend prepared: {why}"
        )))
    };
    let p = checked_upgrade_window(payload)?;
    if p.enclave_id != expected.enclave_id {
        return refuse("it is for another enclave".into());
    }
    if !same_pcrs(&p.from.image_pcrs_hex(), &expected.current) {
        return refuse(format!(
            "its `from` PCRs are not the ones this enclave runs (chain tip PCR0 {})",
            expected.current.pcr0
        ));
    }
    if !same_pcrs(&p.to.image_pcrs_hex(), &expected.target) {
        return refuse(format!(
            "its target PCRs are not the expected ones (expected PCR0 {}, payload PCR0 {})",
            expected.target.pcr0,
            p.to.image_pcrs_hex().pcr0
        ));
    }
    if p.to.user() != p.from.user() {
        return refuse(
            "its target carries other user PCRs 16-31 than the running enclave".into(),
        );
    }
    if p.image_digest != expected.image_digest {
        return refuse(format!(
            "its image digest {} is not the expected {}",
            p.image_digest, expected.image_digest
        ));
    }
    let asked = expected
        .requested_valid_from
        .unwrap_or(expected.now + UPGRADE_DELAY_DEFAULT);
    let floor = expected.now
        + chrono::Duration::seconds(i64::try_from(expected.min_upgrade_delay_secs).unwrap_or(i64::MAX / 2));
    let earliest = std::cmp::max(asked, floor) - VALID_FROM_SLACK;
    if p.valid_from < earliest {
        return refuse(format!(
            "its valid_from {} is earlier than you asked for (earliest acceptable {})",
            p.valid_from, earliest
        ));
    }
    Ok(p)
}

/// The version an enclave runs now, as its own chain attests it.
#[derive(Debug, Clone)]
pub struct RunningVersion {
    /// PCR0-2 of the chain tip.
    pub pcrs: PcrsHex,
    /// The anti-rollback setting the running image's boot link attests.
    pub anti_rollback: AntiRollbackSetting,
}

/// The version an enclave runs now: its chain, re-validated locally, must
/// account for the row's state with every link valid, and the running
/// image's setting is read from its own boot link.
async fn verified_running(client: &ApiClient, enclave_id: &str) -> Result<RunningVersion, CliError> {
    let summary = chain(client, enclave_id).await?;
    if let Some(bad) = summary.links.iter().find(|l| l.validation.is_err()) {
        return Err(CliError::Other(format!(
            "the enclave's upgrade chain does not verify (link {:?}: {}); refusing to sign an \
             upgrade out of an unverified state",
            bad.sequence,
            bad.validation.as_ref().err().map(String::as_str).unwrap_or_default()
        )));
    }
    if !summary.tip_matches_row {
        return Err(CliError::Other(
            "the enclave's upgrade chain does not account for the state the backend reports; \
             refusing to sign an upgrade out of an unverified state"
                .into(),
        ));
    }
    let anti_rollback = running_anti_rollback(&summary.links, &summary.pcrs)?;
    Ok(RunningVersion {
        pcrs: summary.pcrs,
        anti_rollback,
    })
}

/// The anti-rollback setting attested by the running image: the last
/// verified boot link whose PCRs are the chain tip's. Every stored boot is
/// a boot of a new image (reboots of the same image are not recorded), and
/// the setting lives in the measured config the PCRs cover, so any boot of
/// the tip's image carries the same setting.
pub fn running_anti_rollback(
    links: &[VerifiedLink],
    tip: &PcrsHex,
) -> Result<AntiRollbackSetting, CliError> {
    links
        .iter()
        .rev()
        .filter(|l| l.validation.is_ok())
        .find_map(|l| match &l.payload {
            Some(DecodedPayload::Boot(p)) if p.pcrs.same_as(tip) => Some(p.anti_rollback.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            CliError::Other(
                "the enclave's chain has no verified boot link of the running image, so its \
                 anti-rollback setting is unknown; refusing to sign"
                    .into(),
            )
        })
}

/// Gather an [`UpgradeExpectation`] for a self-hosted confirm: the target
/// (expected or locally reproduced), the verified current PCRs, the
/// enclave's minimum delay.
async fn upgrade_expectation(
    client: &ApiClient,
    enclave: &serde_json::Value,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
    target: &UpgradeTarget,
) -> Result<UpgradeExpectation, CliError> {
    let enclave_uuid = Uuid::parse_str(enclave_id)
        .map_err(|e| CliError::Other(format!("invalid enclave id {enclave_id:?}: {e}")))?;
    let staged = client.get_upgrade(enclave_id, upgrade_id).await?;
    let image_digest = match (&target.image_digest, &staged.image_digest) {
        (Some(want), Some(have)) if want != have => {
            return Err(CliError::Other(format!(
                "upgrade {upgrade_id} is built from image {have}, not the {want} you expect"
            )));
        }
        (Some(want), _) => want.clone(),
        (None, Some(have)) => have.clone(),
        (None, None) => {
            return Err(CliError::Other(format!(
                "upgrade {upgrade_id} has no image digest yet (its build has not completed)"
            )));
        }
    };
    let running = verified_running(client, enclave_id).await?;
    eprintln!("The running version's anti-rollback setting, from its attested boot link:");
    for line in anti_rollback_lines(&running.anti_rollback) {
        eprintln!("  {line}");
    }
    let target_pcrs = match &target.pcrs {
        TargetPcrs::Expected(pcrs) => {
            eprintln!(
                "The upgraded image must keep this setting. With --expect-pcrs the CLI cannot \
                 check that; the PCRs you give must be of an image built that way."
            );
            // The only record of the target's trust list here is the
            // backend's; the owner's PCRs are what bind the image to it.
            check_synchronizer_change(
                &running.anti_rollback,
                staged.synchronizer_pcrs.as_deref().unwrap_or_default(),
                "the backend's record of the staged build (your --expect-pcrs bind the image; \
                 build it with this list)",
                target.accept_synchronizer_change,
            )?;
            pcrs.clone()
        }
        TargetPcrs::Reproduce => {
            eprintln!("Rebuilding upgrade {upgrade_id} locally to learn its PCRs...");
            let r = crate::commands::reproduce::reproduce_upgrade(client, enclave_id, upgrade_id)
                .await?;
            if !r.is_reproducible() {
                return Err(CliError::Other(format!(
                    "the local rebuild of upgrade {upgrade_id} does not reproduce the PCRs the \
                     backend recorded (mismatched: {}); refusing to sign",
                    r.mismatches.iter().map(|m| m.slot).collect::<Vec<_>>().join(", ")
                )));
            }
            // The reproduced PCRs bind the build flags the rebuild used, so
            // this is the setting the target image really carries.
            let target_setting = r.anti_rollback_setting()?;
            check_target_role(&running.anti_rollback, &target_setting)?;
            check_synchronizer_change(
                &running.anti_rollback,
                &target_setting.synchronizer_pcrs,
                "your local rebuild",
                target.accept_synchronizer_change,
            )?;
            PcrsHex {
                pcr0: r.actual.pcr0,
                pcr1: r.actual.pcr1,
                pcr2: r.actual.pcr2,
            }
        }
    };
    Ok(UpgradeExpectation {
        enclave_id: enclave_uuid,
        current: running.pcrs,
        target: target_pcrs,
        image_digest,
        requested_valid_from: valid_from,
        min_upgrade_delay_secs: enclave
            .get("min_upgrade_delay_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        now: Utc::now(),
    })
}

fn print_upgrade_to_sign(p: &UpgradePayload, source: &TargetPcrs) {
    let source = match source {
        TargetPcrs::Expected(_) => "the PCRs you gave",
        TargetPcrs::Reproduce => "your local rebuild",
    };
    eprintln!("Your control key is about to authorize this upgrade (target matches {source}):");
    eprintln!("  image:       {}", p.image_digest);
    for line in identity_lines("from.", &p.from) {
        eprintln!("  {line}");
    }
    for line in identity_lines("to.", &p.to) {
        eprintln!("  {line}");
    }
    eprintln!(
        "  valid_from:  {}",
        p.valid_from.format("%Y-%m-%d %H:%M:%S UTC")
    );
    eprintln!(
        "  valid_until: {}",
        p.valid_until.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

/// Two-phase confirm: prepare, check the payload the backend built
/// ([`check_upgrade_payload`]), sign locally (inner + envelope), submit.
/// On a stale-nonce 409 from submit, re-runs prepare (and the check) and
/// retries ONCE (the enclave rotates its control nonce whenever a control
/// command is processed, so a concurrent command invalidates our signed
/// bytes).
async fn confirm_self_hosted(
    client: &ApiClient,
    enclave: &serde_json::Value,
    enclave_id: &str,
    upgrade_id: &str,
    valid_from: Option<DateTime<Utc>>,
    target: UpgradeTarget,
) -> Result<StagedUpgradeJson, CliError> {
    let expected =
        upgrade_expectation(client, enclave, enclave_id, upgrade_id, valid_from, &target).await?;
    let prep = client.confirm_prepare(enclave_id, upgrade_id, valid_from).await?;
    let payload = check_upgrade_payload(&prep.payload, &expected)?;
    print_upgrade_to_sign(&payload, &target.pcrs);
    let signer = signer_for_enclave(enclave)?;
    eprintln!("Two signatures are required.");
    let submission = crate::signer::sign_confirm_submission(signer.as_ref(), &prep)?;
    submitting("Confirming");
    match client.confirm_submit(enclave_id, upgrade_id, &submission).await {
        Err(CliError::Conflict(msg)) => {
            eprintln!(
                "Submit rejected (stale nonce): {msg}. Re-running prepare and retrying once."
            );
            let prep = client.confirm_prepare(enclave_id, upgrade_id, valid_from).await?;
            check_upgrade_payload(&prep.payload, &UpgradeExpectation {
                now: Utc::now(),
                ..expected
            })?;
            let submission = crate::signer::sign_confirm_submission(signer.as_ref(), &prep)?;
            submitting("Confirming");
            client.confirm_submit(enclave_id, upgrade_id, &submission).await
        }
        other => other,
    }
}

/// Decode a backend-built upgrade payload (canonically) and check its
/// activation window: `valid_until` after `valid_from` by at least
/// [`UPGRADE_WINDOW_MIN`] and at most [`UPGRADE_WINDOW_MAX`]. An upgrade not executed in its window can never
/// be, so a longer window keeps an abandoned upgrade usable for longer.
pub fn checked_upgrade_window(payload: &[u8]) -> Result<UpgradePayload, CliError> {
    let payload: UpgradePayload = decode_canonical(payload)
        .map_err(|e| CliError::Other(format!("prepared payload is not an UpgradePayload: {e}")))?;
    if !upgrade_window_is_valid(payload.valid_from, payload.valid_until) {
        return Err(CliError::Other(format!(
            "refusing to sign the upgrade the backend prepared: its window ({} to {}) is \
             shorter than {} minutes",
            payload.valid_from,
            payload.valid_until,
            UPGRADE_WINDOW_MIN.num_minutes()
        )));
    }
    if payload.valid_until - payload.valid_from > UPGRADE_WINDOW_MAX {
        return Err(CliError::Other(format!(
            "refusing to sign the upgrade the backend prepared: its window ({} to {}) is \
             longer than {} days",
            payload.valid_from,
            payload.valid_until,
            UPGRADE_WINDOW_MAX.num_days()
        )));
    }
    Ok(payload)
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

/// Display lines for an image's anti-rollback setting (see
/// [`AntiRollbackSetting`]): on or off, and with it on, whether the image is
/// an upgrade target, how it checks the synchronizer's attestation, and the
/// PCR0 of each synchronizer build it trusts.
pub fn anti_rollback_lines(setting: &AntiRollbackSetting) -> Vec<String> {
    let row = |name: &str, value: String| format!("{:<16}{value}", format!("{name}:"));
    if !setting.enabled {
        return vec![row("anti-rollback", "off".into())];
    }
    let role = if setting.upgrade_target {
        "on, upgrade target (takes over the pin, never registers)"
    } else {
        "on, first image (registers a blank volume)"
    };
    let check = if setting.debug_attestation {
        "DEBUG, no certificate chain (QEMU)"
    } else {
        "AWS Nitro certificate chain"
    };
    let mut lines = vec![row("anti-rollback", role.into()), row("synchronizer", check.into())];
    for p in &setting.synchronizer_pcrs {
        lines.push(row("  trusts PCR0", p.pcr0.clone()));
    }
    lines
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
    eprintln!(
        "  valid_until: {}",
        t.upgrade.valid_until.format("%Y-%m-%d %H:%M:%S UTC")
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
            anti_rollback: AntiRollbackSetting::disabled(),
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
            valid_until: (Utc.with_ymd_and_hms(2026, 6, 9, 11, 0, 0).unwrap()) + chrono::Duration::days(7),
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

    /// The CLI signs an upgrade only with a window of at least
    /// `UPGRADE_WINDOW_MIN` and at most `UPGRADE_WINDOW_MAX`.
    #[test]
    fn upgrade_window_edges() {
        let from = Utc.with_ymd_and_hms(2026, 10, 8, 12, 0, 0).unwrap();
        let payload = |until| {
            let p = UpgradePayload {
                enclave_id: Uuid::nil(),
                from: identity_fixture(),
                to: identity_fixture(),
                image_digest: "sha256:next".into(),
                valid_from: from,
                valid_until: until,
                issued_at: from - chrono::Duration::days(1),
                nonce: vec![0x47; 32],
            };
            enclavia_protocol::signing::encode(&p)
        };
        let one_s = chrono::Duration::seconds(1);
        let one_ms = chrono::Duration::milliseconds(1);
        assert!(checked_upgrade_window(&payload(from + UPGRADE_WINDOW_MIN)).is_ok());
        assert!(checked_upgrade_window(&payload(from + UPGRADE_WINDOW_MAX)).is_ok());
        for until in [
            from,
            from - one_s,
            from + UPGRADE_WINDOW_MIN - one_ms,
            from + UPGRADE_WINDOW_MAX + one_s,
        ] {
            let err = checked_upgrade_window(&payload(until)).unwrap_err();
            assert!(err.to_string().contains("refusing to sign"), "{err}");
        }
        let mut trailing = payload(from + UPGRADE_WINDOW_MIN);
        trailing.push(0);
        assert!(checked_upgrade_window(&trailing).is_err());
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
                valid_until: (now() + chrono::Duration::days(2)) + chrono::Duration::days(7),
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
    // --- self-hosted upgrade payload check (hostile backend) ------------

    mod upgrade_payload_check {
        use super::*;
        use enclavia_protocol::chain::UPGRADE_WINDOW_DEFAULT;
        use enclavia_protocol::pin_identity::ZERO_USER_PCRS;
        use enclavia_protocol::signing::encode;

        fn now() -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
        }

        fn enclave() -> Uuid {
            Uuid::from_u128(0xe2)
        }

        /// What the enclave runs (the verified chain tip).
        fn current() -> PinIdentity {
            PinIdentity::new([[0xa0; 48], [0xa1; 48], [0xa2; 48]], ZERO_USER_PCRS)
        }

        /// What the owner pushed and expects (reproduced or given).
        fn target() -> PinIdentity {
            PinIdentity::new([[0xc0; 48], [0xc1; 48], [0xc2; 48]], ZERO_USER_PCRS)
        }

        fn expectation(requested: Option<DateTime<Utc>>, min_delay: u64) -> UpgradeExpectation {
            UpgradeExpectation {
                enclave_id: enclave(),
                current: current().image_pcrs_hex(),
                target: target().image_pcrs_hex(),
                image_digest: "sha256:pushed".into(),
                requested_valid_from: requested,
                min_upgrade_delay_secs: min_delay,
                now: now(),
            }
        }

        /// What an honest backend builds for the default schedule.
        fn honest() -> UpgradePayload {
            let valid_from = now() + UPGRADE_DELAY_DEFAULT;
            UpgradePayload {
                enclave_id: enclave(),
                from: current(),
                to: target(),
                image_digest: "sha256:pushed".into(),
                valid_from,
                valid_until: valid_from + UPGRADE_WINDOW_DEFAULT,
                issued_at: now(),
                nonce: vec![0x48; 32],
            }
        }

        fn check(p: &UpgradePayload, e: &UpgradeExpectation) -> Result<UpgradePayload, CliError> {
            check_upgrade_payload(&encode(p), e)
        }

        fn refused(p: &UpgradePayload, e: &UpgradeExpectation, why: &str) {
            let err = check(p, e).unwrap_err().to_string();
            assert!(err.contains("refusing to sign"), "{err}");
            assert!(err.contains(why), "expected {why:?} in: {err}");
        }

        #[test]
        fn honest_payloads_pass() {
            check(&honest(), &expectation(None, 0)).unwrap();
            // An explicit time, and a later one than asked (only postpones).
            let at = now() + chrono::Duration::days(2);
            let mut p = honest();
            p.valid_from = at;
            p.valid_until = at + UPGRADE_WINDOW_DEFAULT;
            check(&p, &expectation(Some(at), 0)).unwrap();
            check(&honest(), &expectation(Some(at), 0)).unwrap();
        }

        /// Current_HostileBackend_Target: the backend builds the upgrade to
        /// another target than the owner approved.
        #[test]
        fn another_target_is_refused() {
            let mut p = honest();
            p.to = PinIdentity::new([[0xd0; 48], [0xd1; 48], [0xd2; 48]], ZERO_USER_PCRS);
            refused(&p, &expectation(None, 0), "target PCRs");
            // One PCR differing is enough.
            let mut p = honest();
            p.to = PinIdentity::new([[0xc0; 48], [0xc1; 48], [0xc3; 48]], ZERO_USER_PCRS);
            refused(&p, &expectation(None, 0), "target PCRs");
        }

        /// The pin must not move to another user-PCR identity of the target
        /// image, nor out of another identity than the enclave's own.
        #[test]
        fn other_identities_are_refused() {
            let mut user = ZERO_USER_PCRS;
            user[0] = [0x16; 48];
            let mut p = honest();
            p.to = target().with_user_pcrs(user);
            refused(&p, &expectation(None, 0), "user PCRs");

            let mut p = honest();
            p.from = PinIdentity::new([[0xb0; 48], [0xb1; 48], [0xb2; 48]], ZERO_USER_PCRS);
            refused(&p, &expectation(None, 0), "`from` PCRs");
        }

        /// Current_HostileBackend_ValidFrom: the backend signs an earlier
        /// valid_from than the owner approved, explicitly or by default, or
        /// one under the enclave's minimum delay.
        #[test]
        fn earlier_valid_from_is_refused() {
            let at = now() + chrono::Duration::days(2);
            let mut p = honest();
            p.valid_from = at - chrono::Duration::hours(1);
            p.valid_until = p.valid_from + UPGRADE_WINDOW_DEFAULT;
            refused(&p, &expectation(Some(at), 0), "earlier than you asked");

            // No time named: the default delay is what was approved.
            let mut p = honest();
            p.valid_from = now();
            p.valid_until = now() + UPGRADE_WINDOW_DEFAULT;
            refused(&p, &expectation(None, 0), "earlier than you asked");

            // --immediate on an enclave with a 2-day minimum delay.
            refused(&p, &expectation(Some(now()), 2 * 86_400), "earlier than you asked");
        }

        /// The valid_from edge: exactly the earliest acceptable time (less
        /// the slack) passes, one second earlier does not.
        #[test]
        fn valid_from_edge() {
            let e = expectation(None, 0);
            let earliest = now() + UPGRADE_DELAY_DEFAULT - VALID_FROM_SLACK;
            let mut p = honest();
            p.valid_from = earliest;
            p.valid_until = earliest + UPGRADE_WINDOW_DEFAULT;
            check(&p, &e).unwrap();
            p.valid_from = earliest - chrono::Duration::seconds(1);
            refused(&p, &e, "earlier than you asked");
        }

        #[test]
        fn other_enclave_digest_or_window_is_refused() {
            let e = expectation(None, 0);
            let mut p = honest();
            p.enclave_id = Uuid::from_u128(0xe3);
            refused(&p, &e, "another enclave");

            let mut p = honest();
            p.image_digest = "sha256:elsewhere".into();
            refused(&p, &e, "image digest");

            let mut p = honest();
            p.valid_until = p.valid_from + UPGRADE_WINDOW_MAX + chrono::Duration::seconds(1);
            refused(&p, &e, "longer than");
        }

        /// The F8 shape: bytes that also carry a revocation's fields (or any
        /// unknown field, or trailing bytes) are not an upgrade payload.
        #[test]
        fn polyglot_or_non_canonical_bytes_are_refused() {
            let e = expectation(None, 0);
            let mut map = match ciborium::Value::serialized(&honest()).unwrap() {
                ciborium::Value::Map(m) => m,
                other => panic!("{other:?}"),
            };
            map.push((
                ciborium::Value::Text("revokes_link".into()),
                ciborium::Value::Bytes(vec![0x45; 32]),
            ));
            let mut polyglot = Vec::new();
            ciborium::into_writer(&ciborium::Value::Map(map), &mut polyglot).unwrap();
            assert!(check_upgrade_payload(&polyglot, &e).is_err());

            let mut trailing = encode(&honest());
            trailing.push(0);
            assert!(check_upgrade_payload(&trailing, &e).is_err());
        }

        fn setting(enabled: bool, upgrade_target: bool, debug: bool, sync: &[&str]) -> AntiRollbackSetting {
            AntiRollbackSetting {
                enabled,
                upgrade_target,
                debug_attestation: debug,
                synchronizer_pcrs: sync
                    .iter()
                    .map(|s| PcrsHex {
                        pcr0: s.repeat(96),
                        pcr1: s.repeat(96),
                        pcr2: s.repeat(96),
                    })
                    .collect(),
            }
        }

        /// A hostile backend could build the successor without
        /// `--upgrade-target`, with the wiring turned on or off, with debug
        /// attestation or trusting no synchronizer, and record that: the
        /// reproduced flags then say so, and the CLI refuses against the
        /// running version's attested setting. Another trust list is a
        /// rotation, checked by `check_synchronizer_change`.
        #[test]
        fn target_role_check() {
            let genesis = setting(true, false, false, &["a"]);
            check_target_role(&genesis, &setting(true, true, false, &["a"])).unwrap();
            let off = AntiRollbackSetting::disabled();
            check_target_role(&off, &off).unwrap();
            // Without the wiring the image does not use the other fields.
            check_target_role(&off, &setting(false, true, true, &["c"])).unwrap();
            for (target, why) in [
                (setting(true, false, false, &["a"]), "not built as an upgrade target"),
                (off.clone(), "turns anti-rollback off"),
                (setting(false, true, false, &["a"]), "turns anti-rollback off"),
                (setting(true, true, true, &["a"]), "debug_attestation"),
                (setting(true, true, false, &[]), "trusts no synchronizer"),
            ] {
                let err = check_target_role(&genesis, &target).unwrap_err().to_string();
                assert!(err.contains(why), "{target:?}: {err}");
            }
            let err = check_target_role(&off, &setting(true, true, false, &["a"]))
                .unwrap_err()
                .to_string();
            assert!(err.contains("turns anti-rollback on"), "{err}");
            // Another trust list is not a role error.
            check_target_role(&genesis, &setting(true, true, false, &["c"])).unwrap();
        }

        /// A target trusting other synchronizers than the running version is
        /// a rotation: refused without the flag, signed with it. The same
        /// list (in any order or hex case) passes, and without the wiring the
        /// list is not compared.
        #[test]
        fn synchronizer_change_needs_the_flag() {
            let running = setting(true, false, false, &["a", "b"]);
            let list = |seeds: &[&str]| setting(true, true, false, seeds).synchronizer_pcrs;
            let mut same = list(&["b", "a"]);
            same[0].pcr0 = same[0].pcr0.to_uppercase();
            for accept in [false, true] {
                check_synchronizer_change(&running, &same, "test", accept).unwrap();
            }
            for changed in [list(&["a"]), list(&["a", "b", "c"]), list(&["c"]), list(&[])] {
                let err = check_synchronizer_change(&running, &changed, "test", false)
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("--accept-synchronizer-change"), "{err}");
                assert!(err.contains("fail-stops at boot"), "{err}");
                check_synchronizer_change(&running, &changed, "test", true).unwrap();
            }
            let (removed, added) = synchronizer_diff(&running.synchronizer_pcrs, &list(&["b", "c"]));
            assert_eq!(removed, list(&["a"]));
            assert_eq!(added, list(&["c"]));
            let off = AntiRollbackSetting::disabled();
            check_synchronizer_change(&off, &list(&["c"]), "test", false).unwrap();
        }

        /// The running setting is the one the tip image's own verified boot
        /// link attests; without such a link the CLI refuses.
        #[test]
        fn running_setting_comes_from_the_tip_boot_link() {
            let boot = |pcr: &str, s: AntiRollbackSetting, ok: bool| VerifiedLink {
                id: None,
                sequence: None,
                kind: ChainLinkKind::Boot,
                created_at: None,
                payload: Some(DecodedPayload::Boot(BootPayload {
                    enclave_id: Uuid::nil(),
                    image_digest: "sha256:x".into(),
                    pcrs: PcrsHex {
                        pcr0: pcr.repeat(96),
                        pcr1: pcr.repeat(96),
                        pcr2: pcr.repeat(96),
                    },
                    booted_at: Utc::now(),
                    nonce: vec![0; 32],
                    anti_rollback: s,
                })),
                attestation_bytes: 0,
                signature_bytes: None,
                validation: if ok {
                    Ok(VerificationOk::Append { sequence: 0 })
                } else {
                    Err("bad".into())
                },
            };
            let tip = PcrsHex {
                pcr0: "b".repeat(96),
                pcr1: "b".repeat(96),
                pcr2: "b".repeat(96),
            };
            let v1 = setting(true, false, false, &["a"]);
            let v2 = setting(true, true, false, &["a"]);
            let links = vec![boot("a", v1.clone(), true), boot("b", v2.clone(), true)];
            assert_eq!(running_anti_rollback(&links, &tip).unwrap(), v2);
            // Only a verified link of the tip image counts.
            let links = vec![boot("a", v1.clone(), true), boot("b", v2, false)];
            assert!(running_anti_rollback(&links, &tip).is_err());
            assert!(running_anti_rollback(&[boot("a", v1, true)], &tip).is_err());
        }

        #[test]
        fn expected_pcrs_parse() {
            let hex = |b: &str| b.repeat(96);
            let inline = format!(
                r#"{{"HashAlgorithm":"Sha384 {{ ... }}","PCR0":"{}","PCR1":"{}","PCR2":"{}"}}"#,
                hex("a"),
                hex("b"),
                hex("c")
            );
            let pcrs = parse_expected_pcrs(&inline).unwrap();
            assert_eq!(pcrs.pcr0, hex("a"));
            assert!(parse_expected_pcrs(r#"{"PCR0":"aa","PCR1":"bb","PCR2":"cc"}"#).is_err());
            assert!(parse_expected_pcrs("/nonexistent/pcr.json").is_err());
        }
    }
}
