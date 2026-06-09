//! Per-enclave public upgrade chain: shared types + pure validation.
//!
//! The chain is the user-facing audit trail of every transition an
//! enclave has been through, exposed by the backend as
//! `GET /enclaves/{id}/upgrade-chain` (unauthenticated). The same
//! validation that gates ingest server-side is what an SDK consumer
//! needs to walk the chain and convince themselves it is consistent;
//! both surfaces share this module so behaviour cannot drift.
//!
//! Three link kinds in v1:
//!
//! * [`ChainLinkKind::Boot`] — one per successful boot of a new image
//!   digest. Payload binds `pcrs / image_digest / enclave_id /
//!   booted_at / nonce`. The attestation's `user_data` is
//!   `sha256(payload)` (checked by [`super::attestation::verify_chain_attestation`]).
//! * [`ChainLinkKind::Upgrade`] — emitted by the OLD enclave after the
//!   backend signs and ships a `PrepareUpgrade` control command.
//!   Payload binds `from_pcrs / to_pcrs / image_digest / valid_from /
//!   issued_at / nonce`. The link's `signature` is the backend's
//!   ECDSA P-256 sig over the payload, verifiable against the enclave's
//!   baked-in control pubkey.
//! * [`ChainLinkKind::Revocation`] — emitted by the OLD enclave on a
//!   pre-activation revoke. Payload binds the chain entry id being
//!   cancelled + `issued_at / nonce`. Same signature treatment as
//!   upgrade.
//!
//! Non-upgradable enclaves can only ever produce a single Boot entry
//! (the genesis). [`validate_chain_link`] rejects upgrade / revocation
//! outright on those (no control pubkey to verify against, no upgrade
//! flow), and rejects a second boot that would change `image_digest`.
//!
//! The wire shape diverges slightly from the original issue body, which
//! described the chain as carrying no signature. We include one on
//! upgrade / revocation as defence-in-depth: a forged link injected by
//! a tampered host-side daemon would carry no valid signature.

use chrono::{DateTime, Utc};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::attestation::{AttestationError, Pcrs, verify_chain_attestation};

/// Kind of a chain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainLinkKind {
    Boot,
    Upgrade,
    Revocation,
}

/// One entry in an enclave's public chain. The opaque byte fields are
/// the same shape on the wire (base64 in the API JSON) and at rest
/// (raw bytes in the backend DB) — this struct is the canonical
/// representation either way.
///
/// `id` and `sequence` are assigned by the backend at insert time;
/// in-flight links being validated for the FIRST time will not have
/// them populated. Use [`ChainLink::with_assignment`] to attach them
/// after validation returns [`Outcome::Append`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    /// Backend-assigned UUID. Absent on inbound (pre-ingest) links;
    /// populated on every link returned by the public read endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Per-enclave monotonic ordering, starts at 0. Absent on inbound
    /// links — the backend computes it at validation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub kind: ChainLinkKind,
    /// CBOR-encoded payload. Decode against the kind-specific struct:
    /// [`BootPayload`] / [`UpgradePayload`] / [`RevocationPayload`].
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// COSE_Sign1 attestation document. `user_data == sha256(payload)`.
    #[serde(with = "serde_bytes")]
    pub attestation: Vec<u8>,
    /// 64-byte raw `r || s` ECDSA P-256 signature over `payload` under
    /// the enclave's control private key. Required for upgrade /
    /// revocation, absent on boot.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub signature: Option<Vec<u8>>,
}

/// `serde_bytes`-like adapter that handles `Option<Vec<u8>>` cleanly.
/// (`serde_bytes` requires Vec<u8> directly; without this, an Option
/// would round-trip through serde's default sequence representation
/// and break interop with the backend's DB-side BYTEA column.)
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, ser: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => serde_bytes::Bytes::new(bytes).serialize(ser),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<serde_bytes::ByteBuf>::deserialize(de).map(|o| o.map(|b| b.into_vec()))
    }
}

/// JSON wire shape of a chain link on the public `GET
/// /enclaves/{id}/upgrade-chain` route. The opaque byte fields are
/// carried as base64 strings here (vs. the raw-bytes [`ChainLink`] used
/// at rest and inside the validator). Consumed by the CLI today and, after
/// the enclavia-crates follow-up, by the backend + chain-host so all three
/// surfaces share one definition.
///
/// `payload`, `attestation`, and `signature` are standard base64 with
/// padding. Decode them before handing the bytes to [`validate_chain_link`]
/// for re-verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainLinkJson {
    /// Assigned by the backend on insert; absent on the wire shape
    /// `chain-host` sends to the ingest route.
    #[serde(default)]
    pub id: Option<uuid::Uuid>,
    pub kind: ChainLinkKind,
    /// Monotonic per-enclave, starts at 0 for the boot link.
    #[serde(default)]
    pub sequence: Option<i64>,
    /// Base64 of the CBOR-encoded kind-specific payload.
    pub payload: String,
    /// Base64 of the COSE_Sign1 NSM attestation document. `user_data`
    /// is bound to `sha256(payload_bytes)`.
    pub attestation: String,
    /// Base64 of the raw 64-byte ECDSA P-256 r||s signature. Absent on
    /// boot links (they're authenticated by the attestation alone),
    /// required on upgrade/revocation links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Wall-clock time the backend appended this link. `None` on the
    /// chain-host ingest direction.
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Payload shape for a [`ChainLinkKind::Boot`] link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootPayload {
    /// Enclave identifier. Must match the URL path on ingest.
    pub enclave_id: Uuid,
    /// Manifest digest of the Docker image this boot is bound to.
    pub image_digest: String,
    /// PCR0 / PCR1 / PCR2 in raw byte form (48 B each on Nitro).
    pub pcrs: PcrsHex,
    /// Wall-clock time the in-enclave boot path produced this
    /// attestation.
    pub booted_at: DateTime<Utc>,
    /// 32-byte freshly-generated nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

/// Payload shape for a [`ChainLinkKind::Upgrade`] link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePayload {
    pub enclave_id: Uuid,
    pub from_pcrs: PcrsHex,
    pub to_pcrs: PcrsHex,
    pub image_digest: String,
    pub valid_from: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

/// Payload shape for a [`ChainLinkKind::Revocation`] link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPayload {
    pub enclave_id: Uuid,
    /// Chain entry id of the upgrade link this revocation cancels.
    pub revokes: Uuid,
    pub issued_at: DateTime<Utc>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

/// PCRs in hex-string form. Chosen over raw bytes for the wire/CBOR
/// shape because hex strings interop trivially with the existing
/// hex-PCR format the backend already stores; clients walking the
/// chain don't have to deal with byte-vs-string conversion to match
/// what the attestation document carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrsHex {
    #[serde(rename = "PCR0")]
    pub pcr0: String,
    #[serde(rename = "PCR1")]
    pub pcr1: String,
    #[serde(rename = "PCR2")]
    pub pcr2: String,
}

impl PcrsHex {
    /// Decode to raw bytes for the attestation verifier.
    pub fn to_pcrs(&self) -> Result<Pcrs, ChainValidationError> {
        let pcr0 =
            hex::decode(&self.pcr0).map_err(|_| ChainValidationError::CorruptStoredPcrHex(0))?;
        let pcr1 =
            hex::decode(&self.pcr1).map_err(|_| ChainValidationError::CorruptStoredPcrHex(1))?;
        let pcr2 =
            hex::decode(&self.pcr2).map_err(|_| ChainValidationError::CorruptStoredPcrHex(2))?;
        Ok(Pcrs { pcr0, pcr1, pcr2 })
    }
}

/// Context the validator needs that lives outside the link itself: the
/// enclave's recorded metadata + the chain so far.
///
/// Backend usage: load from DB at ingest. SDK usage: fetch via
/// `GET /enclaves/{id}` and iterate the chain returned from
/// `GET /enclaves/{id}/upgrade-chain`, passing successively longer
/// prefixes as `prior_chain`.
pub struct ChainContext<'a> {
    /// PCR0/1/2 recorded for this enclave at build time. Every link's
    /// attestation document must carry these PCRs.
    pub enclave_pcrs: &'a PcrsHex,
    /// Manifest digest of the Docker image currently pinned to this
    /// enclave row. Boot payloads must reference this digest.
    pub enclave_image_digest: &'a str,
    /// Enclave's 65-byte uncompressed SEC1 ECDSA P-256 control public
    /// key, or None when the enclave was created non-upgradable.
    pub control_public_key: Option<&'a [u8]>,
    /// Whether the enclave was created with the upgradable flag.
    /// Upgrade / revocation links are rejected outright when false.
    pub upgradable: bool,
    /// Existing chain entries, in `sequence` order. May be empty (the
    /// link about to be validated would be genesis).
    pub prior_chain: &'a [ChainLink],
}

/// Validator outcome on a successful check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The link is well-formed and consistent with the chain. Caller
    /// should append it with this `sequence` number.
    Append {
        /// Sequence number to assign to the new link. The first
        /// genesis boot is 0; subsequent links increment by 1.
        sequence: u64,
    },
    /// The link is a duplicate of an already-active boot (same
    /// `image_digest` as the chain's most recent boot). Caller should
    /// NOT insert it; the existing matching link is still authoritative.
    Dedup,
}

/// All ways a chain link can fail validation.
#[derive(Debug, thiserror::Error)]
pub enum ChainValidationError {
    /// Bottom-line attestation verification (see
    /// [`super::attestation::verify_chain_attestation`]).
    #[error("{0}")]
    Attestation(#[from] AttestationError),
    /// `attestation` byte vec is empty.
    #[error("attestation must be present")]
    EmptyAttestation,
    /// CBOR-decode of `payload` failed against the kind's struct.
    #[error("{kind:?} payload not CBOR-decodable: {msg}")]
    PayloadDecode { kind: ChainLinkKind, msg: String },
    /// `payload.enclave_id` does not match the validator's context.
    #[error("payload enclave_id does not match the URL")]
    EnclaveIdMismatch,
    /// Boot link claims PCRs that disagree with what the backend
    /// recorded post-build.
    #[error("boot payload PCRs do not match the enclave's recorded PCRs")]
    PcrMismatch,
    /// Boot link's `image_digest` disagrees with `enclaves.image_digest`.
    #[error("boot payload image_digest does not match the enclave's pinned digest")]
    ImageDigestMismatch,
    /// Boot link presented a `signature`. Boot links carry no
    /// signature.
    #[error("boot link must not carry a signature")]
    BootHasSignature,
    /// Upgrade / revocation link is missing the `signature` field.
    #[error("{0:?} link must carry a signature")]
    SignatureMissing(ChainLinkKind),
    /// The control_public_key on `enclaves` did not decode as
    /// uncompressed SEC1 P-256. Indicates DB-side drift; user-facing
    /// error class should map to 500.
    #[error("stored control_public_key does not decode as SEC1 P-256: {0}")]
    BadControlPubkey(String),
    /// `signature` is not 64 bytes raw r||s.
    #[error("signature is not 64 bytes raw r||s ECDSA P-256")]
    SignatureShape,
    /// `signature` does not verify against the enclave's control
    /// pubkey.
    #[error("signature does not verify under the enclave's control_public_key")]
    SignatureInvalid,
    /// Upgrade / revocation submitted on a non-upgradable enclave.
    #[error("non-upgradable enclaves cannot record {0:?} links")]
    NonUpgradableSigned(ChainLinkKind),
    /// Boot of a fresh image digest on a non-upgradable enclave.
    #[error("non-upgradable enclaves cannot record a second boot")]
    NonUpgradableSecondBoot,
    /// Upgrade or revocation submitted before any genesis boot exists.
    #[error("first chain entry must be a boot — no upgrade or revocation can precede the genesis")]
    NoGenesisYet,
    /// Revocation's `revokes` does not resolve to any entry on the
    /// chain context.
    #[error("revocation `revokes` does not reference any chain entry on this enclave")]
    RevokeTargetMissing,
    /// Revocation's `revokes` points at a non-upgrade link.
    #[error("revocation can only target an upgrade entry, not a {0:?}")]
    RevokeTargetWrongKind(ChainLinkKind),
    /// Revoked upgrade is past `valid_from`. Pre-activation revoke only.
    #[error("revocation is past the upgrade's valid_from; pre-activation revoke only")]
    RevokePastActivation,
    /// Another revocation on this chain already targets the same
    /// upgrade.
    #[error("upgrade has already been revoked")]
    AlreadyRevoked,
    /// A stored chain entry's payload no longer CBOR-decodes (DB-side
    /// drift). Maps to 500.
    #[error("stored {0:?} payload corrupt: {1}")]
    CorruptStoredPayload(ChainLinkKind, String),
    /// A stored PCR string is not hex (DB-side drift). Maps to 500.
    #[error("stored PCR {0} is not valid hex")]
    CorruptStoredPcrHex(usize),
}

/// Pure validator. No DB access, no clock skew (uses the supplied
/// `now`), no I/O. Backend ingest calls this with `now = Utc::now()`;
/// SDK chain-walkers can pass any reference instant they want for
/// consistency (e.g. the chain GET's response time).
///
/// On `Ok(Outcome::Append { sequence })` the caller should INSERT the
/// link assigning that sequence number. On `Ok(Outcome::Dedup)` the
/// caller should not insert. On `Err(_)` the caller should reject.
pub fn validate_chain_link(
    link: &ChainLink,
    ctx: &ChainContext<'_>,
    now: DateTime<Utc>,
    debug_mode: bool,
) -> Result<Outcome, ChainValidationError> {
    if link.attestation.is_empty() {
        return Err(ChainValidationError::EmptyAttestation);
    }
    let recorded_pcrs = ctx.enclave_pcrs.to_pcrs()?;
    verify_chain_attestation(&link.attestation, &link.payload, &recorded_pcrs, debug_mode)?;

    match link.kind {
        ChainLinkKind::Boot => validate_boot(link, ctx),
        ChainLinkKind::Upgrade | ChainLinkKind::Revocation => validate_signed(link, ctx, now),
    }
}

fn validate_boot(
    link: &ChainLink,
    ctx: &ChainContext<'_>,
) -> Result<Outcome, ChainValidationError> {
    if link.signature.is_some() {
        return Err(ChainValidationError::BootHasSignature);
    }
    let parsed: BootPayload = ciborium::from_reader(link.payload.as_slice()).map_err(|e| {
        ChainValidationError::PayloadDecode {
            kind: ChainLinkKind::Boot,
            msg: e.to_string(),
        }
    })?;
    if parsed.pcrs != *ctx.enclave_pcrs {
        return Err(ChainValidationError::PcrMismatch);
    }
    if parsed.image_digest != ctx.enclave_image_digest {
        return Err(ChainValidationError::ImageDigestMismatch);
    }
    // Cross-link semantics: dedup against the most recent boot
    // anywhere in the chain (not just the tail). The reboot-during-
    // pending-upgrade case lands here with `upgrade` as the tail; the
    // running image hasn't actually changed.
    let last_boot = ctx
        .prior_chain
        .iter()
        .rev()
        .find(|l| l.kind == ChainLinkKind::Boot);
    match last_boot {
        None => {
            // Genesis. Sequence is `prior_chain.len()` so we pick up
            // from whatever's at the tail even if (somehow) a non-boot
            // entry preceded the genesis.
            Ok(Outcome::Append {
                sequence: ctx.prior_chain.len() as u64,
            })
        }
        Some(prev) => {
            let prev_payload: BootPayload = ciborium::from_reader(prev.payload.as_slice())
                .map_err(|e| {
                    ChainValidationError::CorruptStoredPayload(ChainLinkKind::Boot, e.to_string())
                })?;
            if prev_payload.image_digest == parsed.image_digest {
                return Ok(Outcome::Dedup);
            }
            if !ctx.upgradable {
                return Err(ChainValidationError::NonUpgradableSecondBoot);
            }
            Ok(Outcome::Append {
                sequence: ctx.prior_chain.len() as u64,
            })
        }
    }
}

fn validate_signed(
    link: &ChainLink,
    ctx: &ChainContext<'_>,
    now: DateTime<Utc>,
) -> Result<Outcome, ChainValidationError> {
    if !ctx.upgradable {
        return Err(ChainValidationError::NonUpgradableSigned(link.kind));
    }
    let sig_bytes = link
        .signature
        .as_deref()
        .ok_or(ChainValidationError::SignatureMissing(link.kind))?;
    let pubkey_bytes = ctx.control_public_key.ok_or_else(|| {
        ChainValidationError::BadControlPubkey(
            "upgradable enclave is missing control_public_key in context".into(),
        )
    })?;
    let verifying = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| ChainValidationError::BadControlPubkey(e.to_string()))?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| ChainValidationError::SignatureShape)?;
    verifying
        .verify(&link.payload, &sig)
        .map_err(|_| ChainValidationError::SignatureInvalid)?;

    // Payload-shape sanity + per-kind cross-link checks.
    match link.kind {
        ChainLinkKind::Upgrade => {
            let _: UpgradePayload =
                ciborium::from_reader(link.payload.as_slice()).map_err(|e| {
                    ChainValidationError::PayloadDecode {
                        kind: ChainLinkKind::Upgrade,
                        msg: e.to_string(),
                    }
                })?;
        }
        ChainLinkKind::Revocation => {
            let revoke: RevocationPayload = ciborium::from_reader(link.payload.as_slice())
                .map_err(|e| ChainValidationError::PayloadDecode {
                    kind: ChainLinkKind::Revocation,
                    msg: e.to_string(),
                })?;
            // Target lookup, kind check, activation check, double-revoke.
            let target = ctx
                .prior_chain
                .iter()
                .find(|l| l.id == Some(revoke.revokes))
                .ok_or(ChainValidationError::RevokeTargetMissing)?;
            if target.kind != ChainLinkKind::Upgrade {
                return Err(ChainValidationError::RevokeTargetWrongKind(target.kind));
            }
            let target_upgrade: UpgradePayload = ciborium::from_reader(target.payload.as_slice())
                .map_err(|e| {
                ChainValidationError::CorruptStoredPayload(ChainLinkKind::Upgrade, e.to_string())
            })?;
            if target_upgrade.valid_from <= now {
                return Err(ChainValidationError::RevokePastActivation);
            }
            for existing in ctx.prior_chain {
                if existing.kind != ChainLinkKind::Revocation {
                    continue;
                }
                let existing_payload: RevocationPayload =
                    ciborium::from_reader(existing.payload.as_slice()).map_err(|e| {
                        ChainValidationError::CorruptStoredPayload(
                            ChainLinkKind::Revocation,
                            e.to_string(),
                        )
                    })?;
                if existing_payload.revokes == revoke.revokes {
                    return Err(ChainValidationError::AlreadyRevoked);
                }
            }
        }
        ChainLinkKind::Boot => unreachable!("validate_signed not called for boot"),
    };

    // First chain entry must be a boot.
    if ctx.prior_chain.is_empty() {
        return Err(ChainValidationError::NoGenesisYet);
    }
    Ok(Outcome::Append {
        sequence: ctx.prior_chain.len() as u64,
    })
}

// ---------------------------------------------------------------------------
// Full-chain walker
// ---------------------------------------------------------------------------

/// One stored chain link plus its server-assigned ingest time: the
/// input unit for [`validate_chain`].
#[derive(Debug, Clone)]
pub struct RecordedLink {
    pub link: ChainLink,
    /// `created_at` on the stored row. Used as the reference instant
    /// for time-dependent rules: a revocation is judged against the
    /// clock at its ingest, not the verifier's clock: by the time
    /// anyone re-walks the chain, the revoked upgrade's `valid_from`
    /// has usually passed, and judging it "now" would reject a link
    /// that was perfectly valid when the backend recorded it. `None`
    /// falls back to the walk's `now`.
    pub recorded_at: Option<DateTime<Utc>>,
}

/// Result of [`validate_chain`].
#[derive(Debug)]
pub struct ChainWalk {
    /// Per-link outcome, same order as the input links.
    pub outcomes: Vec<Result<Outcome, ChainValidationError>>,
    /// PCRs in force after the walk: the genesis boot's values,
    /// advanced by every verified promotion boot. `None` when the
    /// chain has no usable genesis.
    pub final_pcrs: Option<PcrsHex>,
    /// Image digest in force after the walk (same advancement rule).
    pub final_image_digest: Option<String>,
    /// Whether the walk's final in-force state equals the enclave row
    /// state supplied to [`validate_chain`]. `false` means the chain
    /// does not explain what the row currently records (stale chain,
    /// missing links, or row drift): treat the chain as NOT verified
    /// even if every individual link validated.
    pub tip_matches_row: bool,
}

/// Re-validate a stored chain end-to-end, reconstructing the context
/// each link saw at ingest time.
///
/// The backend validates links incrementally: each arrives while the
/// enclave row still holds the state in force at that moment: the
/// genesis build's PCRs for the genesis boot, the old version's PCRs
/// for upgrade / revocation links (the running enclave attests them),
/// and the new version's PCRs for a promotion boot (the cutover sweep
/// promotes the row before the new enclave boots). A later verifier
/// only has the FINAL row state, so validating every link against it
/// rejects perfectly good history. This walker rebuilds the historical
/// context from the chain itself:
///
/// - The genesis boot anchors the walk on its own attested payload.
///   [`validate_chain_link`] then enforces payload <-> attestation
///   agreement, and in production the AWS Nitro CA signature roots
///   that payload in hardware.
/// - Upgrade / revocation links validate against the in-force state:
///   they are attested by the enclave version running at the time.
/// - A boot whose PCRs match the `to_pcrs` of a prior unrevoked
///   upgrade link (with the same target image digest) is a promotion:
///   it validates against that upgrade's target state, and on success
///   the in-force state advances to it.
/// - Any other boot validates against the in-force state: a
///   same-version reboot dedups, anything else fails the attestation
///   PCR check. A transition no signed upgrade link explains is
///   exactly what this rejects.
///
/// Callers MUST check [`ChainWalk::tip_matches_row`] in addition to
/// the per-link outcomes: it ties the walk's final state to the row,
/// proving the chain accounts for what is currently running.
///
/// `now` is the fallback reference instant for links with no
/// `recorded_at` (e.g. not-yet-ingested candidates).
pub fn validate_chain(
    links: &[RecordedLink],
    row_pcrs: &PcrsHex,
    row_image_digest: &str,
    control_public_key: Option<&[u8]>,
    upgradable: bool,
    now: DateTime<Utc>,
    debug_mode: bool,
) -> ChainWalk {
    let mut outcomes = Vec::with_capacity(links.len());
    let mut prior: Vec<ChainLink> = Vec::with_capacity(links.len());
    // (pcrs, image_digest) in force at the current walk position. Set
    // by the genesis boot, advanced by each verified promotion boot.
    // `None` until a genesis validates; the row state then stands in
    // so later links still get individually validated and reported.
    let mut in_force: Option<(PcrsHex, String)> = None;

    for recorded in links {
        let link = &recorded.link;
        let reference = recorded.recorded_at.unwrap_or(now);

        // Reconstruct the row state this link saw at ingest. `promotes`
        // marks the contexts that advance the in-force state when the
        // link validates (genesis anchor, promotion boot).
        let (ctx_pcrs, ctx_digest, promotes): (PcrsHex, String, bool) = match link.kind {
            ChainLinkKind::Boot if prior.is_empty() => {
                match ciborium::from_reader::<BootPayload, _>(link.payload.as_slice()) {
                    Ok(p) => (p.pcrs, p.image_digest, true),
                    // Undecodable genesis: hand the row state to the
                    // validator so it reports the decode error.
                    Err(_) => (row_pcrs.clone(), row_image_digest.to_owned(), false),
                }
            }
            ChainLinkKind::Boot => {
                match (
                    ciborium::from_reader::<BootPayload, _>(link.payload.as_slice()),
                    in_force.as_ref(),
                ) {
                    (Ok(p), Some((pcrs, digest))) => {
                        if p.pcrs == *pcrs {
                            // Same-version reboot.
                            (pcrs.clone(), digest.clone(), false)
                        } else if let Some(target) =
                            promotion_target(&prior, &p.pcrs, &p.image_digest)
                        {
                            // Promotion boot: ingest saw the row
                            // already promoted to the upgrade target.
                            (target.to_pcrs, target.image_digest, true)
                        } else {
                            // No signed upgrade explains these PCRs;
                            // validate against the in-force state and
                            // fail loudly.
                            (pcrs.clone(), digest.clone(), false)
                        }
                    }
                    (_, Some((pcrs, digest))) => (pcrs.clone(), digest.clone(), false),
                    (_, None) => (row_pcrs.clone(), row_image_digest.to_owned(), false),
                }
            }
            ChainLinkKind::Upgrade | ChainLinkKind::Revocation => match in_force.as_ref() {
                Some((pcrs, digest)) => (pcrs.clone(), digest.clone(), false),
                None => (row_pcrs.clone(), row_image_digest.to_owned(), false),
            },
        };

        let ctx = ChainContext {
            enclave_pcrs: &ctx_pcrs,
            enclave_image_digest: &ctx_digest,
            control_public_key,
            upgradable,
            prior_chain: &prior,
        };
        let outcome = validate_chain_link(link, &ctx, reference, debug_mode);
        if promotes && matches!(outcome, Ok(Outcome::Append { .. })) {
            in_force = Some((ctx_pcrs, ctx_digest));
        }
        outcomes.push(outcome);
        prior.push(link.clone());
    }

    let tip_matches_row = in_force
        .as_ref()
        .is_some_and(|(p, d)| p == row_pcrs && d == row_image_digest);
    let (final_pcrs, final_image_digest) = match in_force {
        Some((p, d)) => (Some(p), Some(d)),
        None => (None, None),
    };
    ChainWalk {
        outcomes,
        final_pcrs,
        final_image_digest,
        tip_matches_row,
    }
}

/// Most recent prior unrevoked upgrade link whose `to_pcrs` and target
/// image digest match the boot being explained. `None` when no signed
/// upgrade accounts for a boot with these measurements.
fn promotion_target(
    prior: &[ChainLink],
    boot_pcrs: &PcrsHex,
    boot_image_digest: &str,
) -> Option<UpgradePayload> {
    let revoked: Vec<Uuid> = prior
        .iter()
        .filter(|l| l.kind == ChainLinkKind::Revocation)
        .filter_map(|l| {
            ciborium::from_reader::<RevocationPayload, _>(l.payload.as_slice()).ok()
        })
        .map(|p| p.revokes)
        .collect();
    prior
        .iter()
        .rev()
        .filter(|l| l.kind == ChainLinkKind::Upgrade)
        .filter(|l| l.id.is_none_or(|id| !revoked.contains(&id)))
        .filter_map(|l| ciborium::from_reader::<UpgradePayload, _>(l.payload.as_slice()).ok())
        .find(|p| p.to_pcrs == *boot_pcrs && p.image_digest == boot_image_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::test_utils::FakeChainAttestation;
    use chrono::Duration;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn pcrs_hex_from_seed(seed: u8) -> PcrsHex {
        PcrsHex {
            pcr0: hex::encode(vec![seed; 48]),
            pcr1: hex::encode(vec![seed.wrapping_add(1); 48]),
            pcr2: hex::encode(vec![seed.wrapping_add(2); 48]),
        }
    }

    fn keypair() -> (SigningKey, Vec<u8>) {
        let seed: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let sk = SigningKey::from_slice(&seed).unwrap();
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (sk, pk)
    }

    fn boot_link(enclave_id: Uuid, image_digest: &str, pcr_seed: u8) -> ChainLink {
        let payload = BootPayload {
            enclave_id,
            image_digest: image_digest.into(),
            pcrs: pcrs_hex_from_seed(pcr_seed),
            booted_at: chrono::Utc::now(),
            nonce: vec![0x42; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(pcr_seed, &payload_bytes).encode();
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Boot,
            payload: payload_bytes,
            attestation,
            signature: None,
        }
    }

    fn upgrade_link(
        enclave_id: Uuid,
        image_digest: &str,
        pcr_seed: u8,
        signing: &SigningKey,
        valid_from: DateTime<Utc>,
    ) -> ChainLink {
        let pcrs = pcrs_hex_from_seed(pcr_seed);
        let payload = UpgradePayload {
            enclave_id,
            from_pcrs: pcrs.clone(),
            to_pcrs: pcrs,
            image_digest: image_digest.into(),
            valid_from,
            issued_at: chrono::Utc::now(),
            nonce: vec![0x43; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(pcr_seed, &payload_bytes).encode();
        let sig: Signature = signing.sign(&payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Upgrade,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_bytes().to_vec()),
        }
    }

    fn revocation_link(
        enclave_id: Uuid,
        revokes: Uuid,
        pcr_seed: u8,
        signing: &SigningKey,
    ) -> ChainLink {
        let payload = RevocationPayload {
            enclave_id,
            revokes,
            issued_at: chrono::Utc::now(),
            nonce: vec![0x44; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(pcr_seed, &payload_bytes).encode();
        let sig: Signature = signing.sign(&payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Revocation,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_bytes().to_vec()),
        }
    }

    fn ctx<'a>(
        pcrs: &'a PcrsHex,
        digest: &'a str,
        pubkey: Option<&'a [u8]>,
        upgradable: bool,
        chain: &'a [ChainLink],
    ) -> ChainContext<'a> {
        ChainContext {
            enclave_pcrs: pcrs,
            enclave_image_digest: digest,
            control_public_key: pubkey,
            upgradable,
            prior_chain: chain,
        }
    }

    #[test]
    fn boot_genesis_appends_at_zero() {
        let pcrs = pcrs_hex_from_seed(0x10);
        let id = Uuid::new_v4();
        let link = boot_link(id, "sha256:aaa", 0x10);
        let outcome = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:aaa", None, false, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Append { sequence: 0 });
    }

    #[test]
    fn boot_rejects_pcr_mismatch() {
        let pcrs = pcrs_hex_from_seed(0x11);
        let id = Uuid::new_v4();
        let link = boot_link(id, "sha256:aaa", 0x99);
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:aaa", None, false, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::Attestation(_)));
    }

    #[test]
    fn boot_rejects_image_digest_mismatch() {
        let pcrs = pcrs_hex_from_seed(0x12);
        let id = Uuid::new_v4();
        let link = boot_link(id, "sha256:DIFFERENT", 0x12);
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:aaa", None, false, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::ImageDigestMismatch));
    }

    #[test]
    fn boot_dedups_on_same_image_digest() {
        let pcrs = pcrs_hex_from_seed(0x13);
        let id = Uuid::new_v4();
        let first = boot_link(id, "sha256:bbb", 0x13);
        let outcome = validate_chain_link(
            &first,
            &ctx(
                &pcrs,
                "sha256:bbb",
                None,
                false,
                std::slice::from_ref(&first),
            ),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Dedup);
    }

    #[test]
    fn boot_after_pending_upgrade_dedups_against_last_boot() {
        // boot(v1) -> upgrade(v1->v2) -> reboot(v1): dedup.
        let pcrs = pcrs_hex_from_seed(0x14);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut chain = vec![boot_link(id, "sha256:v1", 0x14)];
        chain[0].id = Some(Uuid::new_v4());
        chain[0].sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x14,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        chain.push(upgrade);

        let reboot = boot_link(id, "sha256:v1", 0x14);
        let outcome = validate_chain_link(
            &reboot,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Dedup);
    }

    #[test]
    fn non_upgradable_rejects_second_boot_with_new_digest() {
        let pcrs = pcrs_hex_from_seed(0x15);
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:old", 0x15);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);

        let reboot = boot_link(id, "sha256:new", 0x15);
        let err = validate_chain_link(
            &reboot,
            &ctx(
                &pcrs,
                "sha256:new",
                None,
                false,
                std::slice::from_ref(&genesis),
            ),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::NonUpgradableSecondBoot));
    }

    #[test]
    fn upgrade_rejects_on_non_upgradable() {
        let pcrs = pcrs_hex_from_seed(0x16);
        let (sk, _) = keypair();
        let id = Uuid::new_v4();
        let link = upgrade_link(
            id,
            "sha256:v2",
            0x16,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", None, false, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ChainValidationError::NonUpgradableSigned(ChainLinkKind::Upgrade)
        ));
    }

    #[test]
    fn upgrade_rejects_bad_signature() {
        let pcrs = pcrs_hex_from_seed(0x17);
        let (_sk, pk) = keypair();
        // Sign with a different key.
        let other_seed: [u8; 32] = core::array::from_fn(|i| (i + 99) as u8);
        let other_sk = SigningKey::from_slice(&other_seed).unwrap();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x17);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);

        let link = upgrade_link(
            id,
            "sha256:v2",
            0x17,
            &other_sk,
            chrono::Utc::now() + Duration::days(7),
        );
        let err = validate_chain_link(
            &link,
            &ctx(
                &pcrs,
                "sha256:v1",
                Some(&pk),
                true,
                std::slice::from_ref(&genesis),
            ),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::SignatureInvalid));
    }

    #[test]
    fn upgrade_rejects_without_genesis() {
        let pcrs = pcrs_hex_from_seed(0x18);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let link = upgrade_link(
            id,
            "sha256:v2",
            0x18,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::NoGenesisYet));
    }

    #[test]
    fn upgrade_appends_after_genesis() {
        let pcrs = pcrs_hex_from_seed(0x19);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x19);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);

        let link = upgrade_link(
            id,
            "sha256:v2",
            0x19,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        let outcome = validate_chain_link(
            &link,
            &ctx(
                &pcrs,
                "sha256:v1",
                Some(&pk),
                true,
                std::slice::from_ref(&genesis),
            ),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Append { sequence: 1 });
    }

    #[test]
    fn revocation_succeeds_against_pending_upgrade() {
        let pcrs = pcrs_hex_from_seed(0x1a);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x1a);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x1a,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let chain = vec![genesis, upgrade.clone()];

        let link = revocation_link(id, upgrade.id.unwrap(), 0x1a, &sk);
        let outcome = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Append { sequence: 2 });
    }

    #[test]
    fn revocation_rejects_unknown_target() {
        let pcrs = pcrs_hex_from_seed(0x1b);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x1b);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let chain = vec![genesis];

        let link = revocation_link(id, Uuid::new_v4(), 0x1b, &sk);
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::RevokeTargetMissing));
    }

    #[test]
    fn revocation_rejects_past_activation() {
        let pcrs = pcrs_hex_from_seed(0x1c);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x1c);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x1c,
            &sk,
            chrono::Utc::now() - Duration::seconds(1),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let chain = vec![genesis, upgrade.clone()];

        let link = revocation_link(id, upgrade.id.unwrap(), 0x1c, &sk);
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::RevokePastActivation));
    }

    #[test]
    fn revocation_rejects_double_revoke() {
        let pcrs = pcrs_hex_from_seed(0x1d);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x1d);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x1d,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut prior_revoke = revocation_link(id, upgrade.id.unwrap(), 0x1d, &sk);
        prior_revoke.id = Some(Uuid::new_v4());
        prior_revoke.sequence = Some(2);
        let chain = vec![genesis, upgrade.clone(), prior_revoke];

        let link = revocation_link(id, upgrade.id.unwrap(), 0x1d, &sk);
        let err = validate_chain_link(
            &link,
            &ctx(&pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::AlreadyRevoked));
    }

    // -----------------------------------------------------------------------
    // Full-chain walker
    // -----------------------------------------------------------------------

    /// Upgrade link describing a real version transition: attested by
    /// the OLD enclave (`from_seed`, the version running at confirm
    /// time) and targeting the NEW measurements (`to_seed`). The
    /// single-seed [`upgrade_link`] fixture above keeps from == to,
    /// which never promotes anything.
    fn transition_upgrade_link(
        enclave_id: Uuid,
        target_digest: &str,
        from_seed: u8,
        to_seed: u8,
        signing: &SigningKey,
        valid_from: DateTime<Utc>,
    ) -> ChainLink {
        let payload = UpgradePayload {
            enclave_id,
            from_pcrs: pcrs_hex_from_seed(from_seed),
            to_pcrs: pcrs_hex_from_seed(to_seed),
            image_digest: target_digest.into(),
            valid_from,
            issued_at: chrono::Utc::now(),
            nonce: vec![0x45; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
        let sig: Signature = signing.sign(&payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Upgrade,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_bytes().to_vec()),
        }
    }

    fn recorded(link: ChainLink, at: DateTime<Utc>) -> RecordedLink {
        RecordedLink {
            link,
            recorded_at: Some(at),
        }
    }

    /// The promoted-history shape a real upgrade leaves behind:
    /// boot(v1) -> upgrade(v1->v2) -> boot(v2), walked AFTER promotion
    /// with the row already holding the v2 state. Validating each link
    /// against the final row state would reject the first two; the
    /// walker must reconstruct the per-link historical context.
    #[test]
    fn walk_validates_promoted_history() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x20);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = transition_upgrade_link(
            id,
            "sha256:v2",
            0x20,
            0x30,
            &sk,
            now - Duration::minutes(10),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut promo = boot_link(id, "sha256:v2", 0x30);
        promo.id = Some(Uuid::new_v4());
        promo.sequence = Some(2);

        let links = vec![
            recorded(genesis, now - Duration::hours(2)),
            recorded(upgrade, now - Duration::minutes(11)),
            recorded(promo, now - Duration::minutes(9)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x30);
        let walk = validate_chain(&links, &row_pcrs, "sha256:v2", Some(&pk), true, now, true);

        for (i, outcome) in walk.outcomes.iter().enumerate() {
            assert!(
                matches!(outcome, Ok(Outcome::Append { sequence }) if *sequence == i as u64),
                "link {i}: {outcome:?}"
            );
        }
        assert!(walk.tip_matches_row);
        assert_eq!(walk.final_pcrs, Some(row_pcrs));
        assert_eq!(walk.final_image_digest, Some("sha256:v2".into()));
    }

    /// A boot whose measurements no prior upgrade link explains must
    /// reject, and the in-force tip must NOT advance to it, even when
    /// the enclave row already claims the new state.
    #[test]
    fn walk_rejects_unexplained_transition_boot() {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x21);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut rogue = boot_link(id, "sha256:v2", 0x31);
        rogue.id = Some(Uuid::new_v4());
        rogue.sequence = Some(1);

        let links = vec![
            recorded(genesis, now - Duration::hours(1)),
            recorded(rogue, now - Duration::minutes(5)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x31);
        let walk = validate_chain(&links, &row_pcrs, "sha256:v2", Some(&[4u8; 65]), true, now, true);

        assert!(matches!(walk.outcomes[0], Ok(Outcome::Append { sequence: 0 })));
        assert!(walk.outcomes[1].is_err(), "{:?}", walk.outcomes[1]);
        // Tip stays at genesis, which the row no longer matches.
        assert!(!walk.tip_matches_row);
        assert_eq!(walk.final_pcrs, Some(pcrs_hex_from_seed(0x21)));
    }

    /// A boot of a REVOKED upgrade's target must reject: the revocation
    /// strips the upgrade link of its power to explain the transition.
    #[test]
    fn walk_rejects_boot_of_revoked_upgrade() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x22);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        // Confirmed for the future, then revoked before activation.
        let mut upgrade = transition_upgrade_link(
            id,
            "sha256:v2",
            0x22,
            0x32,
            &sk,
            now + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut revoke = revocation_link(id, upgrade.id.unwrap(), 0x22, &sk);
        revoke.id = Some(Uuid::new_v4());
        revoke.sequence = Some(2);
        let mut rogue = boot_link(id, "sha256:v2", 0x32);
        rogue.id = Some(Uuid::new_v4());
        rogue.sequence = Some(3);

        let links = vec![
            recorded(genesis, now - Duration::hours(1)),
            recorded(upgrade, now - Duration::minutes(30)),
            recorded(revoke, now - Duration::minutes(20)),
            recorded(rogue, now - Duration::minutes(5)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x22);
        let walk = validate_chain(&links, &row_pcrs, "sha256:v1", Some(&pk), true, now, true);

        assert!(walk.outcomes[0].is_ok());
        assert!(walk.outcomes[1].is_ok());
        assert!(walk.outcomes[2].is_ok());
        assert!(walk.outcomes[3].is_err(), "{:?}", walk.outcomes[3]);
        // Still on v1, which the row agrees with.
        assert!(walk.tip_matches_row);
    }

    /// Historical revocations validate against their INGEST clock, not
    /// the verifier's: by walk time the revoked upgrade's `valid_from`
    /// has passed, and judging the revocation "now" would reject a
    /// link the backend legitimately recorded.
    #[test]
    fn walk_accepts_historical_revocation_after_target_activation() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x23);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        // valid_from is an hour in the PAST relative to the walk...
        let mut upgrade = transition_upgrade_link(
            id,
            "sha256:v2",
            0x23,
            0x33,
            &sk,
            now - Duration::hours(1),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        // ...but the revocation was recorded 30 minutes BEFORE that.
        let mut revoke = revocation_link(id, upgrade.id.unwrap(), 0x23, &sk);
        revoke.id = Some(Uuid::new_v4());
        revoke.sequence = Some(2);

        let links = vec![
            recorded(genesis, now - Duration::hours(3)),
            recorded(upgrade, now - Duration::hours(2)),
            recorded(revoke, now - Duration::minutes(90)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x23);
        let walk = validate_chain(&links, &row_pcrs, "sha256:v1", Some(&pk), true, now, true);

        assert!(
            walk.outcomes.iter().all(Result::is_ok),
            "{:?}",
            walk.outcomes
        );
        assert!(walk.tip_matches_row);

        // Sanity: the same chain judged entirely at `now` (no recorded
        // ingest times) rejects the revocation as past activation.
        let unstamped: Vec<RecordedLink> = links
            .iter()
            .map(|r| RecordedLink {
                link: r.link.clone(),
                recorded_at: None,
            })
            .collect();
        let walk_now =
            validate_chain(&unstamped, &row_pcrs, "sha256:v1", Some(&pk), true, now, true);
        assert!(matches!(
            walk_now.outcomes[2],
            Err(ChainValidationError::RevokePastActivation)
        ));
    }
}
