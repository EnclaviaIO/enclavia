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
//!
//! ## Identity and clock trust
//!
//! Every payload carries an `enclave_id`, and the validator enforces it
//! against the expected id threaded through [`ChainContext`] (the URL
//! path id on backend ingest; the caller-pinned id on SDK walks).
//! Without that binding a link attested by one enclave would transplant
//! onto any other enclave sharing the same PCRs (i.e. booting the same
//! EIF), letting one enclave's chain stand in for another's.
//!
//! `BootPayload.booted_at` is the ENCLAVE's self-reported wall clock,
//! which the host can influence. The walker's refusal to accept a
//! promotion boot that predates its explaining upgrade's `valid_from`
//! (see [`ChainValidationError::UpgradeNotYetActive`]) is therefore an
//! auditability / defence-in-depth gate, not the load-bearing
//! activation enforcement: the real timelock lives enclave-side in the
//! min-upgrade-delay check that gates `PrepareUpgrade` processing.

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
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
/// at rest and inside the validator). Consumed by the CLI today and,
/// eventually, by the backend + chain-host so all three surfaces share
/// one definition.
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
    /// Enclave identifier. Must equal the expected id in the
    /// validator's context (the URL path id on ingest, the
    /// caller-pinned id on SDK walks); enforced by [`validate_boot`].
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

/// Failure decoding a [`ChainLinkJson`] wire link into a [`ChainLink`].
#[derive(Debug, thiserror::Error)]
pub enum ChainLinkDecodeError {
    /// One of the base64 byte fields did not decode.
    #[error("chain link `{field}` is not valid base64: {source}")]
    Base64 {
        field: &'static str,
        #[source]
        source: base64::DecodeError,
    },
    /// `sequence` was negative. The backend never persists a negative
    /// value; surface it instead of silently coercing, so a misbehaving
    /// source is visible rather than papered over.
    #[error("chain link has a negative sequence {0}")]
    NegativeSequence(i64),
}

impl ChainLinkJson {
    /// Decode the base64 wire fields into the raw-bytes [`ChainLink`] the
    /// validator consumes. `id` carries through; `sequence` narrows
    /// `i64 -> u64` and errors on a negative value rather than coercing.
    ///
    /// This is the single decode path for every consumer of the public
    /// `GET /enclaves/{id}/upgrade-chain` endpoint (the SDK's
    /// trust-upgrades walk and the CLI's `upgrade chain`), so the
    /// base64 handling is defined once in the audited crate rather than
    /// re-implemented per caller.
    pub fn into_chain_link(&self) -> Result<ChainLink, ChainLinkDecodeError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode = |field: &'static str, s: &str| {
            b64.decode(s.as_bytes())
                .map_err(|source| ChainLinkDecodeError::Base64 { field, source })
        };
        let payload = decode("payload", &self.payload)?;
        let attestation = decode("attestation", &self.attestation)?;
        let signature = match self.signature.as_deref() {
            Some(s) => Some(decode("signature", s)?),
            None => None,
        };
        let sequence = match self.sequence {
            Some(s) => {
                Some(u64::try_from(s).map_err(|_| ChainLinkDecodeError::NegativeSequence(s))?)
            }
            None => None,
        };
        Ok(ChainLink {
            id: self.id,
            sequence,
            kind: self.kind,
            payload,
            attestation,
            signature,
        })
    }

    /// Decode into a [`RecordedLink`], carrying `created_at` as the
    /// ingest reference instant for time-dependent rules (revocation
    /// `valid_from`).
    pub fn into_recorded_link(&self) -> Result<RecordedLink, ChainLinkDecodeError> {
        Ok(RecordedLink {
            link: self.into_chain_link()?,
            recorded_at: self.created_at,
        })
    }
}

/// PCRs in hex-string form. Chosen over raw bytes for the wire/CBOR
/// shape because hex strings interop trivially with the existing
/// hex-PCR format the backend already stores; clients walking the
/// chain don't have to deal with byte-vs-string conversion to match
/// what the attestation document carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrsHex {
    // `alias` accepts the lowercase form too: the backend persists the
    // builder's pcr.json verbatim (nitro-cli `PCR0` casing), but a
    // future normalization on the row should not break a consumer
    // deserializing it. Serialization is unchanged (always `PCR0`).
    #[serde(rename = "PCR0", alias = "pcr0")]
    pub pcr0: String,
    #[serde(rename = "PCR1", alias = "pcr1")]
    pub pcr1: String,
    #[serde(rename = "PCR2", alias = "pcr2")]
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

/// The `validate_chain` context fields carried on the public
/// `GET /enclaves/{id}` response. Deserialized by every consumer that
/// re-walks a chain (the SDK's `trust_upgrades`, the CLI's `upgrade
/// chain`) so the tolerant parsing lives once here instead of being
/// re-implemented per caller.
///
/// Tolerances, matching what the backend actually emits:
/// - `pcrs`: nitro-cli `PCR0` casing or lowercase (see [`PcrsHex`]).
/// - `control_public_key`: the BYTEA column serializes as a JSON array
///   of byte values; a base64 string and `null` (a non-upgradable
///   enclave) are also accepted.
/// - `upgradable`: defaults to `false` when absent.
///
/// The enclave id is deliberately NOT read from this row: callers pass
/// the id they asked about (the SDK's pinned id, the CLI's resolved
/// id — both also name the URL this row was fetched from) straight to
/// [`validate_chain`] / [`verify_pcr_descent`], so a backend serving a
/// transplanted row cannot redirect the identity check.
///
/// These values are corroborating, not load-bearing, in the
/// `trust_upgrades` trust model (a wrong value can only make a genuine
/// chain fail to verify); see [`verify_pcr_descent`].
#[derive(Debug, Clone, Deserialize)]
pub struct EnclaveChainRow {
    pub pcrs: PcrsHex,
    pub image_digest: String,
    #[serde(default, deserialize_with = "deserialize_control_key")]
    pub control_public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub upgradable: bool,
}

/// Accept the `control_public_key` BYTEA in any of the shapes the row
/// can carry: a JSON array of byte values, a base64 string, or
/// null/absent (non-upgradable enclave).
fn deserialize_control_key<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bytes(Vec<u8>),
        Base64(String),
    }
    match Option::<Raw>::deserialize(de)? {
        None => Ok(None),
        Some(Raw::Bytes(bytes)) => Ok(Some(bytes)),
        Some(Raw::Base64(s)) => base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
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
    /// The enclave this chain is expected to belong to. Every payload's
    /// `enclave_id` must equal it; a link attested by a DIFFERENT
    /// enclave that happens to share the same PCRs (same EIF) is
    /// rejected as transplanted. Backend: the URL path id. SDK: the
    /// caller-pinned enclave id.
    pub enclave_id: &'a Uuid,
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
    /// The link is a duplicate of an already-active entry: a boot with
    /// the same `image_digest` as the chain's most recent boot, or a
    /// signed (upgrade / revocation) link whose exact payload bytes
    /// already appear on the chain (a replayed copy — the payload's
    /// random nonce makes legitimate duplicates impossible). Caller
    /// should NOT insert it; the existing matching link is still
    /// authoritative.
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
    /// `payload.enclave_id` does not match the expected enclave id in
    /// the validator's context. The link was attested by (or forged
    /// for) a different enclave that happens to share this one's PCRs.
    #[error("payload enclave_id does not match the expected enclave id")]
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
    /// Walker-level rule: a signed (upgrade / revocation) link whose
    /// payload is byte-identical to an earlier signed link's payload.
    /// Ingest dedups such replays ([`Outcome::Dedup`]), so a chain a
    /// backend SERVES must never contain the same signed payload twice;
    /// one that does is carrying a resurrected copy of a (possibly
    /// revoked) link under a fresh row id. Distinct from
    /// [`ChainValidationError::AlreadyRevoked`], which is about a FRESH
    /// revocation payload re-targeting an already-revoked upgrade.
    #[error("{0:?} link duplicates the payload bytes of an earlier chain link")]
    DuplicatePayload(ChainLinkKind),
    /// Walker-level rule: a promotion boot whose self-reported
    /// `booted_at` predates the explaining upgrade's `valid_from`
    /// (minus the clock-skew tolerance). The timelock that was supposed
    /// to leave a pre-activation revoke window had not elapsed when the
    /// new image claims to have booted. See the module-level "Identity
    /// and clock trust" note for why this is defence-in-depth on top of
    /// the enclave-side min-upgrade-delay check.
    #[error("promotion boot predates the explaining upgrade's valid_from (minus clock skew)")]
    UpgradeNotYetActive,
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
    // Identity before anything else: a boot attested by a different
    // enclave (same EIF, same PCRs) must not land on this chain.
    if parsed.enclave_id != *ctx.enclave_id {
        return Err(ChainValidationError::EnclaveIdMismatch);
    }
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

    // Payload-shape sanity, the enclave_id binding, replay dedup, and
    // per-kind cross-link checks.
    match link.kind {
        ChainLinkKind::Upgrade => {
            let parsed: UpgradePayload =
                ciborium::from_reader(link.payload.as_slice()).map_err(|e| {
                    ChainValidationError::PayloadDecode {
                        kind: ChainLinkKind::Upgrade,
                        msg: e.to_string(),
                    }
                })?;
            if parsed.enclave_id != *ctx.enclave_id {
                return Err(ChainValidationError::EnclaveIdMismatch);
            }
            // Replayed-upgrade guard: a byte-identical payload already
            // on the chain is a captured re-submission (e.g. of a
            // since-revoked upgrade). Payload bytes are canonical — the
            // signature covers them and the attestation binds
            // sha256(payload) — and the payload's random nonce makes
            // legitimate duplicates impossible, so a second copy can
            // only be a replay. Dedup instead of appending: appending
            // would assign a fresh row id the prior revocation (keyed
            // to the original's id) does not cover, resurrecting the
            // revoked transition.
            if signed_payload_seen(link, ctx.prior_chain) {
                return Ok(Outcome::Dedup);
            }
        }
        ChainLinkKind::Revocation => {
            let revoke: RevocationPayload = ciborium::from_reader(link.payload.as_slice())
                .map_err(|e| ChainValidationError::PayloadDecode {
                    kind: ChainLinkKind::Revocation,
                    msg: e.to_string(),
                })?;
            if revoke.enclave_id != *ctx.enclave_id {
                return Err(ChainValidationError::EnclaveIdMismatch);
            }
            // Same replay guard as for upgrades. Runs BEFORE the
            // double-revoke scan: a byte-identical re-submission dedups,
            // while a FRESH revocation payload targeting an
            // already-revoked upgrade still fails `AlreadyRevoked`
            // below.
            if signed_payload_seen(link, ctx.prior_chain) {
                return Ok(Outcome::Dedup);
            }
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

/// True when an already-chained link has the same kind and
/// byte-identical payload as `link`. Shared by the ingest path (replay
/// dedup in [`validate_signed`]) and the walker (where a duplicate is a
/// hard [`ChainValidationError::DuplicatePayload`], since a served
/// chain should never have passed one through ingest).
fn signed_payload_seen(link: &ChainLink, prior: &[ChainLink]) -> bool {
    prior
        .iter()
        .any(|l| l.kind == link.kind && l.payload == link.payload)
}

// ---------------------------------------------------------------------------
// Full-chain walker
// ---------------------------------------------------------------------------

/// Clock-skew tolerance applied when judging a promotion boot's
/// `booted_at` against the explaining upgrade's `valid_from`. Mirrors
/// `CLOCK_SKEW_TOLERANCE_SECS` in `enclavia-server` (which uses the same
/// 60s slack on the enclave-side min-upgrade-delay check): the enclave's
/// clock is host-influenced, so a small allowance keeps a genuinely
/// valid history from failing on second-level disagreement while still
/// rejecting promotions claimed long before activation. NOTE: the two
/// constants are coupled by convention only — if the server value ever
/// changes, change this one to match.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

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
/// Two walker-only rules have no per-link counterpart at ingest (they
/// relate a link to the rebuilt history, not to a fixed context):
///
/// - A signed link whose payload byte-duplicates an earlier signed
///   link's payload fails with
///   [`ChainValidationError::DuplicatePayload`]: ingest dedups such
///   replays, so a served chain containing one is a backend attempt to
///   resurrect a (possibly revoked) link under a fresh row id.
/// - A promotion boot whose `booted_at` predates the explaining
///   upgrade's `valid_from` (minus a clock-skew tolerance) fails with
///   [`ChainValidationError::UpgradeNotYetActive`], so the recorded
///   history cannot claim an activation inside what was supposed to be
///   the pre-activation revoke window. `booted_at` is the enclave's
///   self-reported (host-influenced) clock, so this is defence-in-depth
///   only; see the module-level "Identity and clock trust" note.
///
/// Callers MUST check [`ChainWalk::tip_matches_row`] in addition to
/// the per-link outcomes: it ties the walk's final state to the row,
/// proving the chain accounts for what is currently running.
///
/// `enclave_id` is the enclave the caller asked about (SDK: the pinned
/// id; CLI: the resolved id; both also name the URL the row and chain
/// were fetched from). Every link's payload must carry it.
///
/// `now` is the fallback reference instant for links with no
/// `recorded_at` (e.g. not-yet-ingested candidates).
#[allow(clippy::too_many_arguments)]
pub fn validate_chain(
    links: &[RecordedLink],
    enclave_id: &Uuid,
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

        // Resurrected-replay guard: a served chain must never contain
        // the same signed payload twice (ingest dedups replays), so a
        // duplicate here means the backend is feeding us a copy of a
        // (possibly revoked) link under a fresh row id. Fail the link;
        // `verify_pcr_descent` rejects the whole chain on any per-link
        // error, so this is fail-closed.
        if matches!(
            link.kind,
            ChainLinkKind::Upgrade | ChainLinkKind::Revocation
        ) && signed_payload_seen(link, &prior)
        {
            outcomes.push(Err(ChainValidationError::DuplicatePayload(link.kind)));
            prior.push(link.clone());
            continue;
        }

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
                            // The boot must not PREDATE the upgrade's
                            // `valid_from` (minus skew slack): the
                            // timelock exists to leave a pre-activation
                            // revoke window, and a history that shows
                            // the new image running inside that window
                            // is one where the window never existed.
                            // `booted_at` is the enclave's self-reported
                            // (host-influenced) clock, so this is
                            // auditability / defence-in-depth; real
                            // activation enforcement is enclave-side.
                            if p.booted_at
                                < target.valid_from - Duration::seconds(CLOCK_SKEW_TOLERANCE_SECS)
                            {
                                outcomes.push(Err(ChainValidationError::UpgradeNotYetActive));
                                prior.push(link.clone());
                                continue;
                            }
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
            enclave_id,
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
///
/// An upgrade whose payload byte-duplicates an EARLIER upgrade link's
/// payload never explains a boot: the walker rejects such a duplicate
/// with [`ChainValidationError::DuplicatePayload`] (ingest dedups
/// replays, so a served chain containing one is already a backend
/// integrity failure), but `prior` also holds links that FAILED
/// validation, and the revoked-id filter alone would let the resurrected
/// copy (fresh row id the revocation doesn't cover) explain a promotion
/// boot in the display path. Skipping duplicates here keeps the reported
/// walk honest even though `verify_pcr_descent` already fails closed on
/// the duplicate's error.
fn promotion_target(
    prior: &[ChainLink],
    boot_pcrs: &PcrsHex,
    boot_image_digest: &str,
) -> Option<UpgradePayload> {
    let revoked: Vec<Uuid> = prior
        .iter()
        .filter(|l| l.kind == ChainLinkKind::Revocation)
        .filter_map(|l| ciborium::from_reader::<RevocationPayload, _>(l.payload.as_slice()).ok())
        .map(|p| p.revokes)
        .collect();
    for (i, l) in prior.iter().enumerate().rev() {
        if l.kind != ChainLinkKind::Upgrade {
            continue;
        }
        if l.id.is_some_and(|id| revoked.contains(&id)) {
            continue;
        }
        // A byte-duplicated upgrade payload is a resurrected replay
        // (possibly of a revoked upgrade); it never explains a boot.
        if signed_payload_seen(l, &prior[..i]) {
            continue;
        }
        let Ok(p) = ciborium::from_reader::<UpgradePayload, _>(l.payload.as_slice()) else {
            continue;
        };
        if p.to_pcrs == *boot_pcrs && p.image_digest == boot_image_digest {
            return Some(p);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Pinned-PCR upgrade-descent check (SDK `trust_upgrades`)
// ---------------------------------------------------------------------------

/// Why a live enclave's PCRs could not be shown to descend from the
/// caller's pinned PCRs.
#[derive(Debug, thiserror::Error)]
pub enum PcrDescentError {
    /// The chain produced no usable genesis, so no in-force state could
    /// be established and nothing descends from anything.
    #[error("chain has no valid genesis boot")]
    NoGenesis,
    /// A chain link failed validation (attestation, signature, or
    /// cross-link consistency). The whole chain is rejected: a single
    /// unverifiable link means the history is not a trustworthy account
    /// of how the enclave reached its current measurements.
    #[error("chain link at position {position} failed validation: {source}")]
    LinkInvalid {
        position: usize,
        #[source]
        source: ChainValidationError,
    },
    /// Every link validated, but the pinned PCRs never appear as an
    /// in-force boot state on this chain. The chain may be a perfectly
    /// valid history of a DIFFERENT enclave; it does not start from (or
    /// pass through) the version the caller pinned, so the live
    /// measurements cannot be said to descend from the pinned ones.
    #[error("pinned PCRs are not an in-force state anywhere on this chain")]
    PinnedNotInLineage,
    /// A boot link the walker accepted carries a payload that no longer
    /// CBOR-decodes, or PCR hex that no longer parses. Indicates the
    /// link bytes were mutated between validation and this read; treated
    /// as fatal.
    #[error("validated boot link at position {0} has an unreadable payload")]
    BootPayloadUnreadable(usize),
}

/// Verify that an enclave currently measuring some live PCRs descends,
/// through this enclave's signed upgrade chain, from the PCRs the caller
/// pinned, and return the chain's final (tip) measurements.
///
/// This backs the SDK's `trust_upgrades` mode. When a client pinned a
/// version's PCRs and the enclave has since upgraded, the live
/// attestation no longer matches the pin; this function decides whether
/// to extend trust to the new image by proving the new image is a
/// descendant of the pinned one.
///
/// The caller passes the pinned PCRs, the id of the enclave it believes
/// it is talking to (`enclave_id` — every link's payload must carry it,
/// so a chain transplanted from a same-EIF enclave fails), plus the
/// enclave's public chain (from `GET /enclaves/{id}/upgrade-chain`) and
/// the validator context (`row_*`, `control_public_key`, `upgradable`)
/// from `GET /enclaves/{id}`. On success it returns the chain's TIP
/// PCRs; the caller MUST then verify the LIVE attestation against
/// exactly those PCRs (e.g. [`crate::attestation::verify_against`]) to
/// bind the verified descendant version to the running Noise session.
/// This function does not see the live attestation and so cannot make
/// that binding itself.
///
/// ## Trust model
///
/// Soundness rests entirely on the per-link AWS Nitro attestations,
/// which `validate_chain` verifies (in production mode); the
/// control-key signatures and the `row_*` / `control_public_key` /
/// `upgradable` context are corroborating, never load-bearing. A
/// dishonest source of any of those can only make a genuine chain FAIL
/// here (a denial), never make a forged transition pass: forging an
/// upgrade link would require a real Nitro document from an enclave
/// measuring the `from` PCRs that voluntarily authorized the `to` PCRs,
/// which is exactly the trust delegation `trust_upgrades` opts into.
///
/// Two independent gates make the result meaningful:
///
/// 1. EVERY link validates. One bad link rejects the whole chain.
/// 2. The pinned PCRs appear as an in-force boot state on the chain.
///    Without this a valid chain belonging to some OTHER enclave would
///    pass; with it, the pinned version is provably part of THIS
///    enclave's measured history. Per-enclave PCRs are unique (the
///    enclave UUID is measured into them), so a single matching
///    in-force state on a fully-validated linear chain places the tip
///    downstream of the pin.
///
/// `debug_mode` must be the SDK's own mode: in production mode a chain
/// of debug (non-CA-signed) links fails attestation and is rejected, so
/// a production client never extends trust through unverifiable history.
// Two args over the lint's threshold: this mirrors `validate_chain`'s
// context (itself one over, from the expected enclave id) plus the
// pinned anchor. Bundling them into a struct would just move the same
// fields around.
#[allow(clippy::too_many_arguments)]
pub fn verify_pcr_descent(
    pinned: &Pcrs,
    links: &[RecordedLink],
    enclave_id: &Uuid,
    control_public_key: Option<&[u8]>,
    row_pcrs: &PcrsHex,
    row_image_digest: &str,
    upgradable: bool,
    now: DateTime<Utc>,
    debug_mode: bool,
) -> Result<Pcrs, PcrDescentError> {
    let ChainWalk {
        outcomes,
        final_pcrs,
        ..
    } = validate_chain(
        links,
        enclave_id,
        row_pcrs,
        row_image_digest,
        control_public_key,
        upgradable,
        now,
        debug_mode,
    );

    // Gate 1: every link must validate. Reject on the first failure so a
    // tampered or unexplained transition can never be papered over by a
    // later good link.
    for (position, outcome) in outcomes.into_iter().enumerate() {
        outcome.map_err(|source| PcrDescentError::LinkInvalid { position, source })?;
    }

    let tip = final_pcrs
        .ok_or(PcrDescentError::NoGenesis)?
        .to_pcrs()
        .map_err(|_| PcrDescentError::BootPayloadUnreadable(0))?;

    // Gate 2: the pinned PCRs must be one of the chain's in-force boot
    // states. Every boot link here was accepted by the walk above (we
    // returned on any failure), so its PCRs are a measured state the
    // enclave genuinely ran; the genesis and each promotion boot are the
    // points where the in-force version changed.
    let mut pinned_in_lineage = false;
    for (position, recorded) in links.iter().enumerate() {
        if recorded.link.kind != ChainLinkKind::Boot {
            continue;
        }
        let payload: BootPayload = ciborium::from_reader(recorded.link.payload.as_slice())
            .map_err(|_| PcrDescentError::BootPayloadUnreadable(position))?;
        let state = payload
            .pcrs
            .to_pcrs()
            .map_err(|_| PcrDescentError::BootPayloadUnreadable(position))?;
        if &state == pinned {
            pinned_in_lineage = true;
        }
    }
    if !pinned_in_lineage {
        return Err(PcrDescentError::PinnedNotInLineage);
    }

    Ok(tip)
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
        boot_link_at(enclave_id, image_digest, pcr_seed, chrono::Utc::now())
    }

    /// [`boot_link`] with an explicit `booted_at`, for tests that
    /// exercise the walker's `valid_from`-vs-`booted_at` rule.
    fn boot_link_at(
        enclave_id: Uuid,
        image_digest: &str,
        pcr_seed: u8,
        booted_at: DateTime<Utc>,
    ) -> ChainLink {
        let payload = BootPayload {
            enclave_id,
            image_digest: image_digest.into(),
            pcrs: pcrs_hex_from_seed(pcr_seed),
            booted_at,
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
        enclave_id: &'a Uuid,
        pcrs: &'a PcrsHex,
        digest: &'a str,
        pubkey: Option<&'a [u8]>,
        upgradable: bool,
        chain: &'a [ChainLink],
    ) -> ChainContext<'a> {
        ChainContext {
            enclave_id,
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
            &ctx(&id, &pcrs, "sha256:aaa", None, false, &[]),
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
            &ctx(&id, &pcrs, "sha256:aaa", None, false, &[]),
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
            &ctx(&id, &pcrs, "sha256:aaa", None, false, &[]),
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
                &id,
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
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
                &id,
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
            &ctx(&id, &pcrs, "sha256:v1", None, false, &[]),
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
                &id,
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &[]),
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
                &id,
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
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
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::AlreadyRevoked));
    }

    // -----------------------------------------------------------------------
    // enclave_id binding (transplant resistance)
    // -----------------------------------------------------------------------

    /// A boot payload carrying a DIFFERENT enclave id (a transplant
    /// from another enclave booting the same EIF, hence the same PCRs)
    /// must fail even though PCRs and image digest match.
    #[test]
    fn boot_rejects_enclave_id_mismatch() {
        let pcrs = pcrs_hex_from_seed(0x1e);
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let link = boot_link(other, "sha256:aaa", 0x1e);
        let err = validate_chain_link(
            &link,
            &ctx(&id, &pcrs, "sha256:aaa", None, false, &[]),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::EnclaveIdMismatch));
    }

    /// Same transplant for an upgrade link: valid signature, valid
    /// attestation, wrong enclave id.
    #[test]
    fn upgrade_rejects_enclave_id_mismatch() {
        let pcrs = pcrs_hex_from_seed(0x1f);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x1f);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);

        let link = upgrade_link(
            other,
            "sha256:v2",
            0x1f,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        let err = validate_chain_link(
            &link,
            &ctx(
                &id,
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
        assert!(matches!(err, ChainValidationError::EnclaveIdMismatch));
    }

    /// And for a revocation link.
    #[test]
    fn revocation_rejects_enclave_id_mismatch() {
        let pcrs = pcrs_hex_from_seed(0x24);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x24);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x24,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let chain = vec![genesis, upgrade.clone()];

        let link = revocation_link(other, upgrade.id.unwrap(), 0x24, &sk);
        let err = validate_chain_link(
            &link,
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChainValidationError::EnclaveIdMismatch));
    }

    // -----------------------------------------------------------------------
    // Signed-link replay dedup (ingest path)
    // -----------------------------------------------------------------------

    /// THE revoked-upgrade replay: a captured, valid upgrade link is
    /// re-submitted AFTER being revoked. The payload bytes (and thus
    /// the signature and attestation binding) are identical to the
    /// original's; ingest must dedup rather than append a copy the old
    /// revocation doesn't cover.
    #[test]
    fn upgrade_replay_after_revocation_dedups() {
        let pcrs = pcrs_hex_from_seed(0x25);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x25);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x25,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut revoke = revocation_link(id, upgrade.id.unwrap(), 0x25, &sk);
        revoke.id = Some(Uuid::new_v4());
        revoke.sequence = Some(2);
        let chain = vec![genesis, upgrade.clone(), revoke];

        // The replay is the captured link resubmitted: same payload,
        // attestation, and signature bytes; no backend-assigned fields.
        let mut replay = upgrade;
        replay.id = None;
        replay.sequence = None;
        let outcome = validate_chain_link(
            &replay,
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Dedup);
    }

    /// A byte-identical revocation replay dedups too — DISTINCT from a
    /// fresh revocation payload re-targeting the same upgrade, which
    /// still fails `AlreadyRevoked` (see `revocation_rejects_double_revoke`).
    #[test]
    fn revocation_replay_dedups() {
        let pcrs = pcrs_hex_from_seed(0x26);
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let mut genesis = boot_link(id, "sha256:v1", 0x26);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade = upgrade_link(
            id,
            "sha256:v2",
            0x26,
            &sk,
            chrono::Utc::now() + Duration::days(7),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut revoke = revocation_link(id, upgrade.id.unwrap(), 0x26, &sk);
        revoke.id = Some(Uuid::new_v4());
        revoke.sequence = Some(2);
        let chain = vec![genesis, upgrade, revoke.clone()];

        let mut replay = revoke;
        replay.id = None;
        replay.sequence = None;
        let outcome = validate_chain_link(
            &replay,
            &ctx(&id, &pcrs, "sha256:v1", Some(&pk), true, &chain),
            chrono::Utc::now(),
            true,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Dedup);
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
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v2",
            Some(&pk),
            true,
            now,
            true,
        );

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
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v2",
            Some(&[4u8; 65]),
            true,
            now,
            true,
        );

        assert!(matches!(
            walk.outcomes[0],
            Ok(Outcome::Append { sequence: 0 })
        ));
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
        let mut upgrade =
            transition_upgrade_link(id, "sha256:v2", 0x22, 0x32, &sk, now + Duration::days(7));
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
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v1",
            Some(&pk),
            true,
            now,
            true,
        );

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
        let mut upgrade =
            transition_upgrade_link(id, "sha256:v2", 0x23, 0x33, &sk, now - Duration::hours(1));
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
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v1",
            Some(&pk),
            true,
            now,
            true,
        );

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
        let walk_now = validate_chain(
            &unstamped,
            &id,
            &row_pcrs,
            "sha256:v1",
            Some(&pk),
            true,
            now,
            true,
        );
        assert!(matches!(
            walk_now.outcomes[2],
            Err(ChainValidationError::RevokePastActivation)
        ));
    }

    /// A served chain containing the same signed upgrade payload twice
    /// is carrying a resurrected copy: ingest would have deduped the
    /// replay, so its presence means the backend is feeding us a link
    /// the prior revocation no longer covers. The duplicate must fail
    /// per-link validation (and thus the whole descent check).
    #[test]
    fn walk_rejects_resurrected_upgrade_payload() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x40);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        // Confirmed for a week out, then revoked inside the window.
        let mut upgrade =
            transition_upgrade_link(id, "sha256:v2", 0x40, 0x50, &sk, now + Duration::days(7));
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut revoke = revocation_link(id, upgrade.id.unwrap(), 0x40, &sk);
        revoke.id = Some(Uuid::new_v4());
        revoke.sequence = Some(2);
        // The replayed copy: identical payload/attestation/signature,
        // freshly assigned row fields (as ingest would have assigned on
        // the vulnerable path).
        let mut replay = upgrade.clone();
        replay.id = Some(Uuid::new_v4());
        replay.sequence = Some(3);
        // A boot of the resurrected target, after valid_from.
        let mut promo = boot_link_at(
            id,
            "sha256:v2",
            0x50,
            now + Duration::days(7) + Duration::minutes(5),
        );
        promo.id = Some(Uuid::new_v4());
        promo.sequence = Some(4);

        let links = vec![
            recorded(genesis, now - Duration::hours(2)),
            recorded(upgrade, now - Duration::minutes(30)),
            recorded(revoke, now - Duration::minutes(20)),
            recorded(replay, now - Duration::minutes(15)),
            recorded(promo, now + Duration::days(7) + Duration::minutes(6)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x50);
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v2",
            Some(&pk),
            true,
            now,
            true,
        );

        assert!(walk.outcomes[0].is_ok());
        assert!(walk.outcomes[1].is_ok());
        assert!(walk.outcomes[2].is_ok());
        assert!(
            matches!(
                walk.outcomes[3],
                Err(ChainValidationError::DuplicatePayload(
                    ChainLinkKind::Upgrade
                ))
            ),
            "{:?}",
            walk.outcomes[3]
        );
        // The resurrected copy must NOT explain the promotion boot either:
        // `prior` includes failed links, and the revoked-id filter alone
        // would let the fresh-row-id copy through `promotion_target`. With
        // no legitimate upgrade explaining the v2 boot, the boot itself
        // fails and the walk no longer claims to account for the row.
        assert!(
            walk.outcomes[4].is_err(),
            "promotion boot explained by a resurrected upgrade: {:?}",
            walk.outcomes[4]
        );
        assert!(
            !walk.tip_matches_row,
            "a chain whose only explanation is a resurrected revoked upgrade must not match the row"
        );

        // Fail-closed end to end: the descent check rejects the whole
        // chain at the resurrected link, so a `trust_upgrades` client
        // never extends trust through it.
        let pinned = pcrs_hex_from_seed(0x40).to_pcrs().unwrap();
        let err = verify_pcr_descent(
            &pinned,
            &links,
            &id,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PcrDescentError::LinkInvalid {
                    position: 3,
                    source: ChainValidationError::DuplicatePayload(ChainLinkKind::Upgrade)
                }
            ),
            "{err:?}"
        );
    }

    /// A promotion boot that claims to have happened BEFORE the
    /// explaining upgrade's `valid_from` (minus clock skew) must fail:
    /// the timelock's pre-activation revoke window never existed for
    /// this transition.
    #[test]
    fn walk_rejects_pre_activation_promotion() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x60);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        // Active a week from now — the revoke window is still open.
        let mut upgrade =
            transition_upgrade_link(id, "sha256:v2", 0x60, 0x70, &sk, now + Duration::days(7));
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        // ...yet the new image claims to have booted already.
        let mut promo = boot_link_at(id, "sha256:v2", 0x70, now);
        promo.id = Some(Uuid::new_v4());
        promo.sequence = Some(2);

        let links = vec![
            recorded(genesis, now - Duration::hours(2)),
            recorded(upgrade, now - Duration::minutes(30)),
            recorded(promo, now - Duration::minutes(5)),
        ];
        // The row already shows the promoted state (the cutover sweep
        // promotes it before the new enclave boots).
        let row_pcrs = pcrs_hex_from_seed(0x70);
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v2",
            Some(&pk),
            true,
            now,
            true,
        );

        assert!(walk.outcomes[0].is_ok());
        assert!(walk.outcomes[1].is_ok());
        assert!(
            matches!(
                walk.outcomes[2],
                Err(ChainValidationError::UpgradeNotYetActive)
            ),
            "{:?}",
            walk.outcomes[2]
        );
        // The rejected boot must NOT advance the in-force tip.
        assert_eq!(walk.final_pcrs, Some(pcrs_hex_from_seed(0x60)));
        assert!(!walk.tip_matches_row);
    }

    /// The skew tolerance keeps a boot that happened seconds before
    /// `valid_from` (host/enclave clock disagreement) valid: only a
    /// boot EARLIER than `valid_from - 60s` is rejected.
    #[test]
    fn walk_accepts_promotion_within_clock_skew() {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut genesis = boot_link(id, "sha256:v1", 0x61);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        // valid_from is 30s in the future; the boot's self-reported
        // clock says "now" — inside the 60s tolerance.
        let mut upgrade = transition_upgrade_link(
            id,
            "sha256:v2",
            0x61,
            0x71,
            &sk,
            now + Duration::seconds(30),
        );
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut promo = boot_link_at(id, "sha256:v2", 0x71, now);
        promo.id = Some(Uuid::new_v4());
        promo.sequence = Some(2);

        let links = vec![
            recorded(genesis, now - Duration::hours(2)),
            recorded(upgrade, now - Duration::minutes(30)),
            recorded(promo, now - Duration::minutes(5)),
        ];
        let row_pcrs = pcrs_hex_from_seed(0x71);
        let walk = validate_chain(
            &links,
            &id,
            &row_pcrs,
            "sha256:v2",
            Some(&pk),
            true,
            now,
            true,
        );

        assert!(
            walk.outcomes.iter().all(Result::is_ok),
            "{:?}",
            walk.outcomes
        );
        assert!(walk.tip_matches_row);
        assert_eq!(walk.final_pcrs, Some(row_pcrs));
    }

    // -----------------------------------------------------------------------
    // verify_pcr_descent (SDK trust_upgrades)
    // -----------------------------------------------------------------------

    /// boot(v1) -> upgrade(v1->v2) -> boot(v2) walked AFTER promotion.
    /// Returns the links, the enclave id, the control pubkey, and the
    /// v1/v2 seeds.
    fn two_version_chain(now: DateTime<Utc>) -> (Vec<RecordedLink>, Uuid, Vec<u8>, u8, u8) {
        let (sk, pk) = keypair();
        let id = Uuid::new_v4();
        let (v1, v2) = (0x20u8, 0x30u8);

        let mut genesis = boot_link(id, "sha256:v1", v1);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut upgrade =
            transition_upgrade_link(id, "sha256:v2", v1, v2, &sk, now - Duration::minutes(10));
        upgrade.id = Some(Uuid::new_v4());
        upgrade.sequence = Some(1);
        let mut promo = boot_link(id, "sha256:v2", v2);
        promo.id = Some(Uuid::new_v4());
        promo.sequence = Some(2);

        let links = vec![
            recorded(genesis, now - Duration::hours(2)),
            recorded(upgrade, now - Duration::minutes(11)),
            recorded(promo, now - Duration::minutes(9)),
        ];
        (links, id, pk, v1, v2)
    }

    #[test]
    fn descent_pinned_genesis_returns_tip() {
        let now = chrono::Utc::now();
        let (links, id, pk, v1, v2) = two_version_chain(now);
        let row_pcrs = pcrs_hex_from_seed(v2);
        let pinned = pcrs_hex_from_seed(v1).to_pcrs().unwrap();

        let tip = verify_pcr_descent(
            &pinned,
            &links,
            &id,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap();
        // The tip is the v2 measurements the running enclave should show.
        assert_eq!(tip, pcrs_hex_from_seed(v2).to_pcrs().unwrap());
    }

    #[test]
    fn descent_pinned_current_tip_returns_tip() {
        // Pinning the CURRENT (post-upgrade) version is also "in lineage":
        // the tip itself is an in-force boot state.
        let now = chrono::Utc::now();
        let (links, id, pk, _v1, v2) = two_version_chain(now);
        let row_pcrs = pcrs_hex_from_seed(v2);
        let pinned = pcrs_hex_from_seed(v2).to_pcrs().unwrap();

        let tip = verify_pcr_descent(
            &pinned,
            &links,
            &id,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap();
        assert_eq!(tip, pinned);
    }

    #[test]
    fn descent_rejects_pin_not_in_chain() {
        // A fully-valid chain, but the pinned PCRs belong to neither the
        // genesis nor any promotion: this could be a real chain for a
        // different enclave. Must not extend trust.
        let now = chrono::Utc::now();
        let (links, id, pk, _v1, v2) = two_version_chain(now);
        let row_pcrs = pcrs_hex_from_seed(v2);
        let stranger = pcrs_hex_from_seed(0x77).to_pcrs().unwrap();

        let err = verify_pcr_descent(
            &stranger,
            &links,
            &id,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, PcrDescentError::PinnedNotInLineage));
    }

    #[test]
    fn descent_rejects_tampered_link() {
        // Flip a byte in the upgrade payload: its attestation binding
        // (user_data == sha256(payload)) breaks, so the link fails and
        // the whole chain is rejected even though the pin matches genesis.
        let now = chrono::Utc::now();
        let (mut links, id, pk, v1, v2) = two_version_chain(now);
        links[1].link.payload[0] ^= 0xff;
        let row_pcrs = pcrs_hex_from_seed(v2);
        let pinned = pcrs_hex_from_seed(v1).to_pcrs().unwrap();

        let err = verify_pcr_descent(
            &pinned,
            &links,
            &id,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PcrDescentError::LinkInvalid { position: 1, .. }
        ));
    }

    #[test]
    fn descent_rejects_unsigned_promotion() {
        // boot(v1) then a promotion boot(v2) with NO upgrade link
        // explaining the transition: the v2 boot fails the attestation
        // PCR check against the in-force v1 state. An attacker cannot
        // jump the measured version without a signed, attested upgrade.
        let now = chrono::Utc::now();
        let (_sk, pk) = keypair();
        let id = Uuid::new_v4();
        let (v1, v2) = (0x20u8, 0x30u8);

        let mut genesis = boot_link(id, "sha256:v1", v1);
        genesis.id = Some(Uuid::new_v4());
        genesis.sequence = Some(0);
        let mut rogue = boot_link(id, "sha256:v2", v2);
        rogue.id = Some(Uuid::new_v4());
        rogue.sequence = Some(1);
        let links = vec![
            recorded(genesis, now - Duration::hours(1)),
            recorded(rogue, now - Duration::minutes(1)),
        ];
        let pinned = pcrs_hex_from_seed(v1).to_pcrs().unwrap();

        let err = verify_pcr_descent(
            &pinned,
            &links,
            &id,
            Some(&pk),
            &pcrs_hex_from_seed(v1),
            "sha256:v1",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PcrDescentError::LinkInvalid { position: 1, .. }
        ));
    }

    /// A fully-valid chain walked against the WRONG expected enclave id
    /// (a transplant onto a same-EIF enclave, which shares the PCRs)
    /// fails at the genesis link: every payload binds the originating
    /// enclave's id.
    #[test]
    fn descent_rejects_transplanted_chain() {
        let now = chrono::Utc::now();
        let (links, id, pk, v1, v2) = two_version_chain(now);
        let row_pcrs = pcrs_hex_from_seed(v2);
        let pinned = pcrs_hex_from_seed(v1).to_pcrs().unwrap();
        let other = Uuid::new_v4();
        assert_ne!(other, id);

        let err = verify_pcr_descent(
            &pinned,
            &links,
            &other,
            Some(&pk),
            &row_pcrs,
            "sha256:v2",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PcrDescentError::LinkInvalid {
                    position: 0,
                    source: ChainValidationError::EnclaveIdMismatch
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn descent_empty_chain_has_no_genesis() {
        let now = chrono::Utc::now();
        let id = Uuid::new_v4();
        let pinned = pcrs_hex_from_seed(0x20).to_pcrs().unwrap();
        let err = verify_pcr_descent(
            &pinned,
            &[],
            &id,
            None,
            &pcrs_hex_from_seed(0x20),
            "sha256:v1",
            true,
            now,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, PcrDescentError::NoGenesis));
    }

    #[test]
    fn chain_link_json_round_trips_through_decode() {
        // into_chain_link is the SDK/CLI decode path: base64 wire fields
        // back to raw bytes, id/sequence carried, negative sequence
        // dropped.
        let id = Uuid::new_v4();
        let raw = boot_link(id, "sha256:v1", 0x20);
        let b64 = base64::engine::general_purpose::STANDARD;
        let wire = ChainLinkJson {
            id: Some(Uuid::new_v4()),
            kind: ChainLinkKind::Boot,
            sequence: Some(3),
            payload: b64.encode(&raw.payload),
            attestation: b64.encode(&raw.attestation),
            signature: None,
            created_at: None,
        };
        let decoded = wire.into_chain_link().unwrap();
        assert_eq!(decoded.payload, raw.payload);
        assert_eq!(decoded.attestation, raw.attestation);
        assert_eq!(decoded.sequence, Some(3));

        let bad = ChainLinkJson {
            payload: "not base64!!!".into(),
            ..wire.clone()
        };
        assert!(matches!(
            bad.into_chain_link(),
            Err(ChainLinkDecodeError::Base64 {
                field: "payload",
                ..
            })
        ));

        let neg = ChainLinkJson {
            sequence: Some(-1),
            ..wire
        };
        assert!(matches!(
            neg.into_chain_link(),
            Err(ChainLinkDecodeError::NegativeSequence(-1))
        ));
    }

    #[test]
    fn enclave_row_parses_array_control_key_and_pcr_casing() {
        let row = serde_json::json!({
            "upgradable": true,
            "image_digest": "sha256:abc",
            "pcrs": { "PCR0": "00", "PCR1": "11", "PCR2": "22" },
            "control_public_key": [4, 255, 0, 7],
        });
        let parsed: EnclaveChainRow = serde_json::from_value(row).unwrap();
        assert!(parsed.upgradable);
        assert_eq!(parsed.image_digest, "sha256:abc");
        assert_eq!(parsed.pcrs.pcr0, "00");
        assert_eq!(parsed.control_public_key, Some(vec![4u8, 255, 0, 7]));
    }

    #[test]
    fn enclave_row_accepts_base64_control_key_and_lowercase_pcrs() {
        let key = vec![4u8, 1, 2, 3];
        let row = serde_json::json!({
            "upgradable": true,
            "image_digest": "sha256:abc",
            "pcrs": { "pcr0": "aa", "pcr1": "bb", "pcr2": "cc" },
            "control_public_key": base64::engine::general_purpose::STANDARD.encode(&key),
        });
        let parsed: EnclaveChainRow = serde_json::from_value(row).unwrap();
        assert_eq!(parsed.pcrs.pcr1, "bb");
        assert_eq!(parsed.control_public_key, Some(key));
    }

    #[test]
    fn enclave_row_null_control_key_is_non_upgradable_and_upgradable_defaults_false() {
        let row = serde_json::json!({
            "image_digest": "sha256:abc",
            "pcrs": { "PCR0": "00", "PCR1": "11", "PCR2": "22" },
            "control_public_key": null,
        });
        let parsed: EnclaveChainRow = serde_json::from_value(row).unwrap();
        assert_eq!(parsed.control_public_key, None);
        assert!(!parsed.upgradable);
    }

    #[test]
    fn enclave_row_missing_image_digest_errors() {
        let row = serde_json::json!({
            "upgradable": true,
            "pcrs": { "PCR0": "00", "PCR1": "11", "PCR2": "22" },
        });
        assert!(serde_json::from_value::<EnclaveChainRow>(row).is_err());
    }
}
