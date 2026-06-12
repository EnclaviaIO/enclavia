//! Wire-format request/response types for the synchronizer RPC surface,
//! plus the pure verifier for a [`Request::Transition`] credential.
//!
//! CBOR-encoded, transport-agnostic. The synchronizer service binds these to
//! a vsock+Noise channel; the customer-side client encodes/decodes them with
//! `ciborium` over its existing Noise transport (the same one
//! `enclavia-server` already runs).
//!
//! Each request maps onto one [`crate::Op`] (with some shaping, `Pin`
//! distinguishes "first pin" from "subsequent pin" only at the state-machine
//! level via the [`crate::Op::Register`] / [`crate::Op::Pin`] split, but on
//! the wire we expose a single `Pin` RPC and let the server decide which
//! state-machine op to apply based on whether the key is already
//! registered).
//!
//! ## Transition credential = #47 upgrade chain link
//!
//! `Transition` no longer carries an "old enclave signs old->new"
//! signature. That shape (a control-key signature minted inside the old
//! enclave over `old_key || new_key`) was impossible as built: enclaves
//! verify control signatures but never hold the private key. The credential
//! is now a #47 upgrade [`ChainLink`] (kind [`ChainLinkKind::Upgrade`])
//! whose CBOR [`UpgradePayload`] already binds `from_pcrs -> to_pcrs` under
//! the OLD enclave's control-key signature and carries the OLD enclave's
//! own hardware attestation. See [`verify_transition_link`] for the exact
//! verification contract.
//!
//! ## Who submits a Transition, and whose attestation is on the link
//!
//! The NEW enclave submits the `Transition`. In a staged upgrade the old
//! enclave stops before the new one boots, so the old enclave can never
//! hold a live synchronizer session at cutover. The new enclave boots,
//! attests itself as `new_key` (`observe_attestation`), reads the upgrade
//! link out of its own chain, and presents it as the credential that lets
//! it adopt the old key's pinned state. This matches the pure state
//! machine, whose [`crate::Op::Transition`] requires `new_key` (the
//! submitting session) to have attested in-session.
//!
//! The link itself, however, is emitted by the OLD enclave during its
//! `PrepareUpgrade` flow (enclavia#30, `enclavia-server::run_prepare_upgrade`
//! calling `build_chain_attestation`): its `signature` is the OLD control
//! key's signature over the payload, and its `attestation` is the OLD
//! enclave's NSM document, so the link's PCRs equal `from_pcrs`. This
//! mirrors `enclavia_protocol::chain`'s rule that upgrade / revocation
//! links validate against the in-force state, attested by the enclave
//! version running at the time.
//!
//! **Wire-compatibility note.** This breaks the previous `Transition`
//! shape (`{ old_key, new_key, signature }`). The single-node binary has
//! no deployed users, so the break is free; this mirrors enclavia#30, which
//! did the same for `PrepareUpgrade`. There is no migration path because
//! there is nothing to migrate.
//!
//! Errors are flattened into a small `RpcError` enum that the client can
//! match against without depending on the state machine's
//! [`crate::ValidationError`] type, the synchronizer is allowed to evolve
//! the internal validation surface without breaking wire compatibility.

use serde::{Deserialize, Serialize};

use crate::{Commitment, PcrKey, ValidationError, Version};

// Re-exported so callers of `verify_transition_link` have one import site.
pub use enclavia_protocol::chain::{ChainLink, ChainLinkKind, UpgradePayload};

/// Maximum size (bytes) of an ENCRYPTED frame on the wire, in either
/// direction.
///
/// `Noise_NN_25519_ChaChaPoly_BLAKE2s` has a 65535-byte hard cap per
/// message, so we use that as the outer bound. Anything larger is a
/// protocol error, a malicious peer can't OOM the node by claiming a
/// giant length. A typical Nitro attestation document is ~5 KiB, well
/// within budget.
///
/// Shared by the listener (responder side) and the customer client
/// (`client` feature, initiator side); it lives here, next to the frame
/// type, so the two stay in lockstep.
pub const MAX_FRAME_SIZE: u32 = 65535;

/// One frame over the Noise-encrypted session stream. Tagged so we can
/// extend with control frames (ping, etc.) without breaking the format.
///
/// The session protocol: 4-byte big-endian length prefix, then that many
/// bytes of Noise ciphertext whose plaintext is one CBOR-encoded `Frame`.
/// Authentication is MUTUAL and strictly ordered (#208): the first
/// client-to-server frame MUST be [`Frame::Authenticate`] (the customer's
/// document), and the first server-to-client frame is the server's own
/// [`Frame::Authenticate`] (the oracle's document, sent only after the
/// client's verified). Every subsequent client frame is [`Frame::Rpc`],
/// answered with one CBOR [`Response`]. See `crate::listener` for the
/// responder side and `crate::client` for the initiator side.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame")]
pub enum Frame {
    /// Mutual-authentication frame, sent by BOTH ends (#208). Carries the
    /// raw CBOR/COSE_Sign1 bytes of a Nitro NSM attestation document
    /// whose `nonce` field MUST equal `base64(handshake_hash)` from the
    /// just-completed Noise handshake (channel binding: a document
    /// captured from any other session carries the wrong nonce and is
    /// rejected).
    ///
    /// Client→server (first client frame): the listener verifies the doc,
    /// extracts PCR0/1/2, and binds the session to
    /// `PcrKey = SHA-256(PCR0||PCR1||PCR2)`.
    ///
    /// Server→client (first server frame, sent only after the client's
    /// `Authenticate` verified): the client verifies the doc and checks
    /// its PCRs against the synchronizer measurements it trusts (a
    /// [`ServerPcrPolicy`] sourced from the customer enclave's MEASURED
    /// image/config). This is what stops a malicious host from
    /// terminating the customer's session itself and answering Get/Pin
    /// as a fake oracle: `Noise_NN` is unauthenticated DH, so without
    /// the server attesting back the customer would have no idea who is
    /// on the other end.
    Authenticate {
        /// Raw NSM attestation document bytes.
        nsm_doc: Vec<u8>,
    },

    /// Subsequent frame: an RPC [`Request`] to dispatch against the
    /// session's bound key.
    Rpc {
        /// RPC payload to dispatch against the session's bound key.
        request: Request,
    },
}

/// Compile-time check that the pure core's [`crate::CONTROL_PUBKEY_LEN`]
/// equals the protocol layer's contract for the SEC1 P-256 control key.
/// If enclavia-protocol ever changes the width, this fails the build here
/// rather than silently desyncing the frozen-pubkey storage.
const _: () =
    assert!(crate::CONTROL_PUBKEY_LEN == enclavia_protocol::attestation::CONTROL_PUBKEY_LEN);

/// Request frame sent by a customer enclave to a synchronizer node.
///
/// The synchronizer is responsible for verifying that the calling session is
/// bound (via Noise + Nitro attestation) to a PCR set whose SHA-256 equals
/// [`PcrKey`] before honouring any of these RPCs. The wire format
/// deliberately does *not* repeat the PCR key inside every request: the
/// caller's authenticated session identity is the authority.
///
/// Including the PCR key in the request bodies anyway (rather than relying
/// purely on session state) is a deliberate redundancy: it lets the server
/// double-check the caller is talking about *its own* state, which catches
/// client bugs and makes the wire trace easier to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Read the latest pinned commitment for `key`.
    ///
    /// Returns [`Response::GetOk`] with the current commitment + version,
    /// or [`Response::Err`] with [`RpcError::NotFound`] if the key is not
    /// currently registered.
    Get {
        /// PCR set whose latest commitment is being read.
        key: PcrKey,
    },

    /// Write a new freshness commitment for `key`.
    ///
    /// On the wire this is a single RPC, internally the synchronizer maps
    /// it to [`crate::Op::Register`] (first pin for an unseen key) or
    /// [`crate::Op::Pin`] (subsequent pin) depending on the committed
    /// state. The result includes the resulting version so the caller can
    /// distinguish them: `Version(0)` means this was the registration.
    Pin {
        /// PCR set whose commitment is being updated.
        key: PcrKey,
        /// New commitment to associate with `key`.
        commitment: Commitment,
    },

    /// Authorize and execute a PCR transition for an enclave upgrade.
    ///
    /// Submitted by the NEW enclave: the session that sends this RPC is
    /// authenticated as `new_key` (`sha256(payload.to_pcrs)`), the
    /// successor adopting the old key's pinned state. The old enclave is
    /// gone by cutover and could never submit it itself.
    ///
    /// `link` is a #47 upgrade [`ChainLink`] (kind
    /// [`ChainLinkKind::Upgrade`]) the new enclave read out of its own
    /// chain. Its CBOR-decoded [`UpgradePayload`] names `from_pcrs ->
    /// to_pcrs`; the link's `signature` is the OLD enclave's 64-byte raw
    /// r||s ECDSA P-256 control signature over the payload, and its
    /// `attestation` is the OLD enclave's NSM document bound to
    /// `sha256(payload)` (so its PCRs equal `from_pcrs`). The synchronizer
    /// derives `old_key`/`new_key` from the payload, verifies the link via
    /// [`verify_transition_link`] against the control pubkey frozen for the
    /// derived `old_key` at its registration, then retires `old_key`,
    /// registers `new_key` (which must itself have produced an attestation
    /// in this session, the submitting session does), and carries the
    /// existing commitment + version forward.
    Transition {
        /// The #47 upgrade chain link authorizing the transition.
        link: ChainLink,
    },
}

/// Response frame sent by the synchronizer to a customer enclave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Successful [`Request::Get`].
    GetOk {
        /// Latest pinned commitment.
        commitment: Commitment,
        /// Per-key monotonic version.
        version: Version,
    },

    /// Successful [`Request::Pin`].
    ///
    /// `version` is `Version(0)` if this Pin registered the key for the
    /// first time, `Version(n+1)` if it bumped an existing pin from
    /// version `n`.
    PinOk {
        /// Per-key monotonic version after this pin.
        version: Version,
    },

    /// Successful [`Request::Transition`].
    ///
    /// `version` is the carried-over per-key version of the old key, now
    /// associated with `new_key`. The synchronizer guarantees the
    /// commitment is preserved across the transition.
    TransitionOk {
        /// Per-key monotonic version (unchanged across transition).
        version: Version,
    },

    /// Failure response. Carries a structured [`RpcError`] so the client
    /// can branch on the failure category without parsing strings.
    Err {
        /// Failure category.
        error: RpcError,
    },
}

/// Failure categories returned to clients over the wire.
///
/// Intentionally coarser than [`ValidationError`]: we want wire stability
/// even if the state-machine validation surface grows. Each variant maps
/// from one or more `ValidationError`s and carries no payload that could
/// leak per-key state to an unauthenticated caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code")]
pub enum RpcError {
    /// The session is not bound to a hardware-attested PCR set, or the key
    /// referenced in the request does not match the session's bound key.
    #[error("session is not authorized for this key")]
    Unauthorized,

    /// The requested key is not currently registered (never pinned, or
    /// retired by a prior `Transition`).
    #[error("key not found")]
    NotFound,

    /// `Transition` was rejected: the chain link failed verification
    /// (bad control signature, attestation/payload binding mismatch,
    /// PCR-hash mismatch), the target key hasn't attested in this session,
    /// or the target key is already registered / retired.
    #[error("transition rejected")]
    TransitionRejected,

    /// Generic request was well-formed but rejected by the state machine
    /// for a reason the wire surface deliberately does not enumerate
    /// (e.g. retired key, duplicate registration). Clients should treat
    /// this as fatal for the affected key.
    #[error("operation rejected")]
    OperationRejected,

    /// The server is currently unable to commit writes (e.g. quorum lost).
    /// Reads may still succeed; clients should back off and retry.
    #[error("synchronizer cluster unavailable")]
    Unavailable,
}

impl From<ValidationError> for RpcError {
    fn from(err: ValidationError) -> Self {
        match err {
            // Attestation failures only happen at Register/Transition.
            // The state machine doesn't model the per-session
            // authentication binding, that's the server's job before it
            // ever calls into the state machine, so a `NotAttested`
            // surfacing here means the `new_key` of a transition (the
            // submitting session) hasn't been attested, which is a
            // transition rejection from the caller's point of view.
            ValidationError::NotAttested => RpcError::TransitionRejected,
            ValidationError::NewKeyNotAttested => RpcError::TransitionRejected,
            ValidationError::NoTransitionAuthorization => RpcError::TransitionRejected,
            ValidationError::NewKeyAlreadyExists => RpcError::TransitionRejected,
            ValidationError::OldKeyEqualsNew => RpcError::TransitionRejected,

            // KeyNotCurrent surfaces from Pin/Get on an unregistered key
            // (NotFound for the caller) AND from Transition on an
            // unregistered old_key (rejection). The server distinguishes
            // by knowing which RPC it was handling; here we default to
            // NotFound and let the server override for transitions.
            ValidationError::KeyNotCurrent => RpcError::NotFound,

            ValidationError::AlreadyRegistered => RpcError::OperationRejected,
            ValidationError::KeyRetired => RpcError::OperationRejected,
        }
    }
}

// ---------------------------------------------------------------------------
// Server-attestation verifier (#208; pure, called by the customer client)
// ---------------------------------------------------------------------------

// Re-exported so policy construction has one import site alongside the
// verifier that consumes it.
pub use enclavia_protocol::attestation::Pcrs;

/// Which synchronizer measurements a customer accepts when the oracle
/// attests back to it (#208).
///
/// # SECURITY CONTRACT: where the expected PCRs MUST come from
///
/// The whole point of the server attestation is to stop a malicious HOST
/// from impersonating the oracle, so the expected PCRs MUST come from
/// data the host cannot influence: the customer enclave's MEASURED
/// image or config (e.g. `/etc/enclavia/config.json`, which is baked
/// into the EIF and therefore part of the enclave's own PCRs). Sourcing
/// them from a host-controlled channel (environment variables, a vsock
/// side-channel, command-line arguments) makes the check WORTHLESS: the
/// host would simply supply the PCRs of whatever it wants to
/// impersonate the oracle with.
///
/// An empty [`ServerPcrPolicy::Expected`] list admits nothing
/// (fail-stop), never everything.
///
/// There is deliberately NO "accept any PCRs" variant. The oracle's
/// identity MUST always be checked against a known measurement set, so
/// every caller (production and tests alike) supplies the PCRs it
/// expects: production reads them from the customer enclave's MEASURED
/// config (hardcoded by the builder, injected into the EIF), and the
/// smoke client reads the freshly built EIF's `pcr.json`. Kept an enum
/// (rather than a bare `Vec<Pcrs>`) so future policy kinds, e.g. a
/// PCR0-only match, can be added without churning call sites.
#[derive(Clone, Debug)]
pub enum ServerPcrPolicy {
    /// Accept only a server whose verified PCR0/1/2 equal one of these
    /// triples exactly. The list normally has one entry (the deployed
    /// synchronizer cluster runs a single image) and only changes when a
    /// new cluster is stood up. An EMPTY list admits nothing.
    Expected(Vec<Pcrs>),
}

impl ServerPcrPolicy {
    /// Whether `pcrs` (a server's VERIFIED measurements) satisfy this
    /// policy.
    pub fn admits(&self, pcrs: &Pcrs) -> bool {
        match self {
            ServerPcrPolicy::Expected(expected) => expected.iter().any(|e| e == pcrs),
        }
    }
}

/// Why a server's `Authenticate` document was rejected by
/// [`verify_server_attestation`].
#[derive(Debug, thiserror::Error)]
pub enum ServerAuthError {
    /// The document failed validation: malformed COSE/CBOR, a failed
    /// AWS Nitro CA-chain / COSE-signature check (production mode), or a
    /// `nonce` that does not bind this session's handshake hash (a
    /// replayed capture from another session).
    #[error("server attestation document invalid: {0}")]
    Attestation(String),
    /// The document verified, but its PCRs are not admitted by the
    /// caller's [`ServerPcrPolicy`]: whatever is on the other end of
    /// this session, it is not the synchronizer the caller trusts.
    #[error("server attestation PCRs are not the expected synchronizer measurements")]
    PcrRejected,
}

/// Verify the server's `Authenticate` document for one customer session
/// (#208): full document validation (AWS Nitro CA chain + COSE signature
/// when `debug_mode = false`; structural-only for QEMU's self-signing
/// NSM when `true`), nonce binding to THIS session's `handshake_hash`,
/// then the PCR check against `policy`.
///
/// `debug_mode` MUST come from the same measured source as the policy
/// (it is part of the trust decision: a host that could flip it to
/// `true` could forge the document outright). Returns the server's
/// verified PCRs on success so the caller can log/record them.
pub fn verify_server_attestation(
    nsm_doc: &[u8],
    handshake_hash: &[u8],
    policy: &ServerPcrPolicy,
    debug_mode: bool,
) -> Result<Pcrs, ServerAuthError> {
    use enclavia_protocol::attestation::AttestationError;
    let ServerPcrPolicy::Expected(expected) = policy;
    // The PCR comparison happens INSIDE the protocol verifier (its
    // `expected` parameter is mandatory), so no code path can verify a
    // server document without committing to an identity.
    match enclavia_protocol::attestation::verify_and_extract_pcrs(
        nsm_doc,
        handshake_hash,
        expected,
        debug_mode,
    ) {
        Ok(pcrs) => Ok(pcrs),
        Err(AttestationError::PcrsNotExpected) => Err(ServerAuthError::PcrRejected),
        Err(e) => Err(ServerAuthError::Attestation(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Transition-link verifier (pure; called by the node before observe/apply)
// ---------------------------------------------------------------------------

/// Why a [`Request::Transition`]'s chain link failed verification.
///
/// Every variant deliberately folds to [`RpcError::TransitionRejected`] on
/// the wire (see [`From<TransitionLinkError>`]): clients learn the
/// transition was refused, not *which* internal check tripped. The variants
/// exist for server-side logging and tests.
#[derive(Debug, thiserror::Error)]
pub enum TransitionLinkError {
    /// The link's `kind` is not [`ChainLinkKind::Upgrade`].
    #[error("transition link is not an upgrade link (kind = {0:?})")]
    NotAnUpgradeLink(ChainLinkKind),
    /// The link carried no `signature` (upgrade links must).
    #[error("transition link is missing the control-key signature")]
    MissingSignature,
    /// `signature` is not 64 bytes raw r||s ECDSA P-256.
    #[error("transition link signature is not 64 bytes raw r||s P-256")]
    SignatureShape,
    /// The frozen control pubkey for the derived `old_key` did not decode
    /// as uncompressed SEC1 P-256. Indicates the stored pubkey is corrupt;
    /// should be unreachable for a key registered from a real
    /// `AttestedIdentity`.
    #[error("frozen control pubkey for old_key does not decode as SEC1 P-256")]
    BadControlPubkey,
    /// `signature` does not verify against the frozen control pubkey for
    /// the derived `old_key`.
    #[error("transition link signature does not verify under old_key's frozen control pubkey")]
    SignatureInvalid,
    /// The link's `payload` did not CBOR-decode as an [`UpgradePayload`].
    #[error("transition link payload is not a decodable UpgradePayload: {0}")]
    PayloadDecode(String),
    /// `verify_chain_attestation` rejected the link (attestation invalid,
    /// or `user_data != sha256(payload)`, or PCRs disagree with
    /// `from_pcrs`).
    #[error("transition link attestation failed: {0}")]
    Attestation(String),
    /// A PCR string inside `from_pcrs` / `to_pcrs` was not valid hex / not
    /// a usable length.
    #[error("transition link payload carries a malformed PCR set: {0}")]
    BadPayloadPcrs(String),
    /// `sha256(payload.to_pcrs)` (the derived `new_key`) did not equal the
    /// submitting session's bound key. The NEW enclave submits the
    /// transition, so the session must authenticate as `new_key`.
    #[error("transition link to_pcrs does not hash to the submitting session key")]
    SessionKeyMismatch,
    /// The derived `new_key` equals the derived `old_key`
    /// (`from_pcrs == to_pcrs`): a self-transition is never legitimate.
    #[error("transition link to_pcrs equals from_pcrs (self-transition)")]
    SelfTransition,
}

impl From<TransitionLinkError> for RpcError {
    fn from(_: TransitionLinkError) -> Self {
        RpcError::TransitionRejected
    }
}

/// Keys derived from a (still-untrusted) decode of a transition link's
/// payload, returned by [`decode_transition_link`].
///
/// The node uses [`Self::old_key`] to look up the frozen control pubkey it
/// must verify the link's signature against, before calling
/// [`verify_transition_link`]. Both keys are re-derived from the payload's
/// own PCR triples (`sha256(PCR0||PCR1||PCR2)`), never taken from an
/// untrusted wire field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedTransition {
    /// `sha256(payload.from_pcrs)`, the retiring (OLD) enclave's key. The
    /// link's signature is verified against the control pubkey frozen for
    /// THIS key at its registration.
    pub old_key: PcrKey,
    /// `sha256(payload.to_pcrs)`, the successor (NEW) enclave's key. Must
    /// equal the submitting session's bound key.
    pub new_key: PcrKey,
}

/// Successful output of [`verify_transition_link`]: the `(old_key,
/// new_key)` pair the verified link authorizes.
///
/// The node records this via [`crate::StateMachine::observe_transition`]
/// and then applies [`crate::Op::Transition`] with the same pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedTransition {
    /// `sha256(payload.from_pcrs)`, the retiring (OLD) enclave's key.
    pub old_key: PcrKey,
    /// `sha256(payload.to_pcrs)`, the successor key adopted by the
    /// transition. Equals the submitting session's bound key.
    pub new_key: PcrKey,
}

/// Derive a [`PcrKey`] from a chain payload's hex-PCR triple, matching
/// `Pcrs::digest()` (SHA-256 over the raw `PCR0 || PCR1 || PCR2` bytes).
fn pcr_key_from_hex(
    pcrs: &enclavia_protocol::chain::PcrsHex,
) -> Result<PcrKey, TransitionLinkError> {
    let raw = pcrs
        .to_pcrs()
        .map_err(|e| TransitionLinkError::BadPayloadPcrs(e.to_string()))?;
    Ok(PcrKey(raw.digest()))
}

/// Phase one of transition-link verification: structural checks plus the
/// key derivation, with NO cryptographic verification yet.
///
/// Decodes the link's payload (so the node can learn the `old_key` it must
/// look up a frozen control pubkey for) after the cheap up-front gates:
///
/// 1. The link must be an [`ChainLinkKind::Upgrade`] link.
/// 2. It must carry a non-empty `signature` (verified later, in
///    [`verify_transition_link`]).
/// 3. Its `payload` must CBOR-decode as an [`UpgradePayload`].
///
/// Returns the derived `(old_key, new_key)`. The payload is decoded here
/// before its signature is verified, which is safe: the node uses the
/// derived `old_key` only to *look up* a frozen pubkey, and
/// [`verify_transition_link`] then verifies the 64-byte signature over the
/// exact payload bytes against that pubkey. A payload that lies about
/// `from_pcrs` would have to carry a signature valid under some OTHER key's
/// frozen pubkey, which it cannot.
pub fn decode_transition_link(link: &ChainLink) -> Result<DecodedTransition, TransitionLinkError> {
    if link.kind != ChainLinkKind::Upgrade {
        return Err(TransitionLinkError::NotAnUpgradeLink(link.kind));
    }
    // The signature must be present (its bytes are verified in phase two);
    // reject a missing one early so the node never bothers with a lookup.
    if link.signature.is_none() {
        return Err(TransitionLinkError::MissingSignature);
    }
    let payload: UpgradePayload = ciborium::from_reader(link.payload.as_slice())
        .map_err(|e| TransitionLinkError::PayloadDecode(e.to_string()))?;
    let old_key = pcr_key_from_hex(&payload.from_pcrs)?;
    let new_key = pcr_key_from_hex(&payload.to_pcrs)?;
    Ok(DecodedTransition { old_key, new_key })
}

/// Phase two: cryptographically verify a [`Request::Transition`]'s #47
/// upgrade chain link against the frozen control pubkey for its derived
/// `old_key` and the submitting session's key.
///
/// `decoded` must come from [`decode_transition_link`] on the SAME `link`
/// (the node looks up `old_control_pubkey = state.control_pubkey` for
/// `decoded.old_key` in between). `session_key` is the key the submitting
/// (NEW) enclave authenticated as. This enforces the corrected contract:
///
/// 1. **Submitter binding.** `decoded.new_key` must equal `session_key`.
///    The NEW enclave submits the transition, so its session authenticates
///    as `new_key`. (The OLD enclave is gone by cutover and cannot hold a
///    session, this is why the credential, not a live old-key session,
///    authorizes the move.)
/// 2. **Not a self-transition.** `decoded.new_key != decoded.old_key`
///    (`from_pcrs != to_pcrs`). The state machine also rejects this, but a
///    self-transition link is never legitimate.
/// 3. **Control signature.** The link's 64-byte raw r||s ECDSA P-256
///    `signature` must verify over the payload bytes against
///    `old_control_pubkey`, the 65-byte SEC1 P-256 key the synchronizer
///    froze for `decoded.old_key` at its Register time
///    (`AttestedIdentity::control_pubkey`). This proves the retiring
///    enclave authorized this exact `from -> to` pair; control-pubkey
///    substitution is defeated because the pubkey is frozen, and the
///    decode-before-verify ordering is safe because the signature covers
///    `from_pcrs`.
/// 4. **Chain attestation.** `verify_chain_attestation` must accept the
///    link's `attestation` against its `payload`, i.e. the attestation's
///    `user_data == sha256(payload)` and its PCRs equal `from_pcrs` (the
///    OLD enclave emitted the link, so it attested its OWN measurements,
///    matching `enclavia_protocol::chain`'s "attested by the enclave
///    version running at the time" rule). `debug_mode` selects the
///    skip-cert-chain (QEMU / test) vs full-Nitro-CA path.
///
/// On success returns the `(old_key, new_key)` the caller should observe
/// and apply. The state machine still enforces the remaining structural
/// rules (`new_key` attested + not retired + not already registered,
/// `old_key` current, etc.) when the op is applied.
pub fn verify_transition_link(
    link: &ChainLink,
    decoded: DecodedTransition,
    session_key: PcrKey,
    old_control_pubkey: &[u8; crate::CONTROL_PUBKEY_LEN],
    debug_mode: bool,
) -> Result<VerifiedTransition, TransitionLinkError> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    // 1. The NEW enclave submits; the session must be bound to new_key.
    if decoded.new_key != session_key {
        return Err(TransitionLinkError::SessionKeyMismatch);
    }
    // 2. Self-transition is never legitimate.
    if decoded.new_key == decoded.old_key {
        return Err(TransitionLinkError::SelfTransition);
    }

    // 3. Control signature over the payload, against the pubkey frozen for
    //    the derived old_key. (decode_transition_link already guaranteed
    //    kind == Upgrade and signature.is_some().)
    let sig_bytes = link
        .signature
        .as_deref()
        .ok_or(TransitionLinkError::MissingSignature)?;
    let verifying = VerifyingKey::from_sec1_bytes(old_control_pubkey)
        .map_err(|_| TransitionLinkError::BadControlPubkey)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| TransitionLinkError::SignatureShape)?;
    verifying
        .verify(&link.payload, &sig)
        .map_err(|_| TransitionLinkError::SignatureInvalid)?;

    // 4. Chain attestation binds the document to sha256(payload) and to
    //    the OLD enclave's measurements (from_pcrs): the old enclave
    //    emitted the link, so it attested its own PCRs.
    let payload: UpgradePayload = ciborium::from_reader(link.payload.as_slice())
        .map_err(|e| TransitionLinkError::PayloadDecode(e.to_string()))?;
    let expected_pcrs = payload
        .from_pcrs
        .to_pcrs()
        .map_err(|e| TransitionLinkError::BadPayloadPcrs(e.to_string()))?;
    enclavia_protocol::attestation::verify_chain_attestation(
        &link.attestation,
        &link.payload,
        &expected_pcrs,
        debug_mode,
    )
    .map_err(|e| TransitionLinkError::Attestation(e.to_string()))?;

    Ok(VerifiedTransition {
        old_key: decoded.old_key,
        new_key: decoded.new_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavia_protocol::attestation::Pcrs;
    use enclavia_protocol::attestation::test_utils::FakeChainAttestation;
    use enclavia_protocol::chain::PcrsHex;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    fn k(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }

    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    fn roundtrip<T>(value: &T)
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("encode");
        let decoded: T = ciborium::from_reader(&buf[..]).expect("decode");
        assert_eq!(*value, decoded, "round-trip mismatch");
    }

    // --- shared transition-link fixtures ------------------------------

    fn pcrs_hex_from_seed(seed: u8) -> PcrsHex {
        PcrsHex {
            pcr0: hex::encode(vec![seed; 48]),
            pcr1: hex::encode(vec![seed.wrapping_add(1); 48]),
            pcr2: hex::encode(vec![seed.wrapping_add(2); 48]),
        }
    }

    /// The PcrKey a seed's PcrsHex hashes to, matching `Pcrs::digest()`.
    fn key_from_seed(seed: u8) -> PcrKey {
        let raw = Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        };
        PcrKey(raw.digest())
    }

    /// Deterministic P-256 keypair; returns the signing key and the
    /// 65-byte uncompressed SEC1 verifying-key bytes.
    fn keypair(seed: u8) -> (SigningKey, [u8; crate::CONTROL_PUBKEY_LEN]) {
        // A reliably-valid, nonzero P-256 scalar: a small big-endian
        // integer (0x01, seed, 0, ...) is always below the curve order.
        let mut scalar = [0u8; 32];
        scalar[0] = 0x01;
        scalar[1] = seed;
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let pk_vec = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut pk = [0u8; crate::CONTROL_PUBKEY_LEN];
        pk.copy_from_slice(&pk_vec);
        (sk, pk)
    }

    /// Build a #47 upgrade chain link for `from_seed -> to_seed`, signed
    /// by `signing` (the OLD enclave's control key) and attested against
    /// the OLD measurements (`from_seed`): the old enclave emits the link
    /// during its PrepareUpgrade flow, so it attests its own PCRs.
    fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
        let payload = UpgradePayload {
            enclave_id: uuid::Uuid::new_v4(),
            from_pcrs: pcrs_hex_from_seed(from_seed),
            to_pcrs: pcrs_hex_from_seed(to_seed),
            image_digest: "sha256:to".into(),
            valid_from: chrono::Utc::now(),
            issued_at: chrono::Utc::now(),
            nonce: vec![0x5a; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        // Attestation is the OLD enclave's: PCRs = from_seed, user_data =
        // sha256(payload).
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

    /// Decode then verify a link in one shot, mirroring the node's
    /// two-phase call. `session_key` is the NEW enclave's key (the
    /// submitter); `old_control_pubkey` is what the node looked up for the
    /// derived `old_key`.
    fn decode_and_verify(
        link: &ChainLink,
        session_key: PcrKey,
        old_control_pubkey: &[u8; crate::CONTROL_PUBKEY_LEN],
        debug_mode: bool,
    ) -> Result<VerifiedTransition, TransitionLinkError> {
        let decoded = decode_transition_link(link)?;
        verify_transition_link(link, decoded, session_key, old_control_pubkey, debug_mode)
    }

    // --- wire round-trips ---------------------------------------------

    #[test]
    fn request_get_roundtrip() {
        roundtrip(&Request::Get { key: k(1) });
    }

    #[test]
    fn request_pin_roundtrip() {
        roundtrip(&Request::Pin {
            key: k(7),
            commitment: c(0xab),
        });
    }

    #[test]
    fn request_transition_roundtrip() {
        let (sk, _) = keypair(0x10);
        let link = upgrade_link(0x10, 0x20, &sk);
        roundtrip(&Request::Transition { link });
    }

    #[test]
    fn response_get_ok_roundtrip() {
        roundtrip(&Response::GetOk {
            commitment: c(0x5a),
            version: Version(42),
        });
    }

    #[test]
    fn response_pin_ok_roundtrip() {
        roundtrip(&Response::PinOk {
            version: Version(0),
        });
        roundtrip(&Response::PinOk {
            version: Version(u64::MAX),
        });
    }

    #[test]
    fn response_transition_ok_roundtrip() {
        roundtrip(&Response::TransitionOk {
            version: Version(7),
        });
    }

    #[test]
    fn response_err_roundtrip() {
        for code in [
            RpcError::Unauthorized,
            RpcError::NotFound,
            RpcError::TransitionRejected,
            RpcError::OperationRejected,
            RpcError::Unavailable,
        ] {
            roundtrip(&Response::Err { error: code });
        }
    }

    /// Sanity check: every `ValidationError` variant maps to a wire error.
    /// If a new variant is added to the state machine, this test forces a
    /// conscious decision about how to surface it on the wire.
    #[test]
    fn validation_error_to_rpc_error_total() {
        let cases = [
            (ValidationError::NotAttested, RpcError::TransitionRejected),
            (
                ValidationError::AlreadyRegistered,
                RpcError::OperationRejected,
            ),
            (ValidationError::KeyRetired, RpcError::OperationRejected),
            (ValidationError::KeyNotCurrent, RpcError::NotFound),
            (
                ValidationError::NewKeyAlreadyExists,
                RpcError::TransitionRejected,
            ),
            (
                ValidationError::NewKeyNotAttested,
                RpcError::TransitionRejected,
            ),
            (
                ValidationError::NoTransitionAuthorization,
                RpcError::TransitionRejected,
            ),
            (
                ValidationError::OldKeyEqualsNew,
                RpcError::TransitionRejected,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(RpcError::from(input), expected, "for {input:?}");
        }
    }

    /// Wire frames serialize as CBOR maps with a `"type"` (or `"code"`)
    /// discriminator. Lock this in so external clients (e.g. a future Go
    /// implementation) can rely on the wire shape.
    #[test]
    fn discriminator_tag_is_stable() {
        let req = Request::Get { key: k(0) };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let val: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let map = val.as_map().expect("CBOR map");
        let ty = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("type") {
                    v.as_text()
                } else {
                    None
                }
            })
            .expect("type discriminator present");
        assert_eq!(ty, "Get");
    }

    // --- verify_server_attestation (#208) ------------------------------

    use enclavia_protocol::attestation::test_utils::FakeAttestation;

    fn pcrs_from_seed(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    fn hh() -> Vec<u8> {
        (0u8..32).collect()
    }

    /// Happy path: the server's document binds this session's hash and
    /// its PCRs are in the expected set.
    #[test]
    fn server_attestation_expected_pcrs_admitted() {
        let doc = FakeAttestation::with_seed(0x51, hh()).encode();
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x51)]);
        let pcrs = verify_server_attestation(&doc, &hh(), &policy, true).expect("verify");
        assert_eq!(pcrs, pcrs_from_seed(0x51));
    }

    /// A multi-entry policy admits any listed triple.
    #[test]
    fn server_attestation_any_of_expected_set_admitted() {
        let doc = FakeAttestation::with_seed(0x52, hh()).encode();
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x99), pcrs_from_seed(0x52)]);
        verify_server_attestation(&doc, &hh(), &policy, true).expect("verify");
    }

    /// The impersonation case: a valid, session-bound document whose
    /// PCRs are NOT the expected synchronizer measurements is rejected.
    /// This is exactly what a host reflecting the customer's own
    /// document (or fronting a rogue image) produces.
    #[test]
    fn server_attestation_wrong_pcrs_rejected() {
        let doc = FakeAttestation::with_seed(0x53, hh()).encode();
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x54)]);
        let err = verify_server_attestation(&doc, &hh(), &policy, true).unwrap_err();
        assert!(matches!(err, ServerAuthError::PcrRejected), "{err:?}");
    }

    /// An EMPTY expected set admits nothing: fail-stop, never
    /// fail-open.
    #[test]
    fn server_attestation_empty_expected_set_rejects_everything() {
        let doc = FakeAttestation::with_seed(0x55, hh()).encode();
        let policy = ServerPcrPolicy::Expected(Vec::new());
        let err = verify_server_attestation(&doc, &hh(), &policy, true).unwrap_err();
        assert!(matches!(err, ServerAuthError::PcrRejected), "{err:?}");
    }

    /// Nonce binding: a document captured from ANOTHER session (replay)
    /// is rejected even when its PCRs are expected.
    #[test]
    fn server_attestation_replayed_doc_rejected() {
        let doc = FakeAttestation::with_seed(0x56, vec![0xab; 32]).encode();
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x56)]);
        let err = verify_server_attestation(&doc, &hh(), &policy, true).unwrap_err();
        assert!(matches!(err, ServerAuthError::Attestation(_)), "{err:?}");
    }

    /// Garbage bytes are rejected as a malformed document (before any
    /// PCR comparison, so the specific expected set is irrelevant).
    #[test]
    fn server_attestation_garbage_doc_rejected() {
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x57)]);
        let err =
            verify_server_attestation(&[0xde, 0xad, 0xbe, 0xef], &hh(), &policy, true).unwrap_err();
        assert!(matches!(err, ServerAuthError::Attestation(_)), "{err:?}");
    }

    /// A correctly-bound, expected-PCR document verifies, and the SAME
    /// document replayed under a different session hash is rejected by
    /// the nonce binding even though its PCRs still match the policy.
    #[test]
    fn server_attestation_matching_policy_still_checks_nonce() {
        let policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x57)]);
        let good = FakeAttestation::with_seed(0x57, hh()).encode();
        verify_server_attestation(&good, &hh(), &policy, true).expect("verify");

        let replayed = FakeAttestation::with_seed(0x57, vec![0xcd; 32]).encode();
        let err = verify_server_attestation(&replayed, &hh(), &policy, true).unwrap_err();
        assert!(matches!(err, ServerAuthError::Attestation(_)), "{err:?}");
    }

    // --- verify_transition_link ---------------------------------------
    //
    // The NEW enclave submits, so `session_key` is the NEW key
    // (`key_from_seed(to_seed)`) and the looked-up control pubkey belongs
    // to the OLD key (`keypair(from_seed)`).

    /// Happy path: a link signed by the OLD key, attested for the OLD
    /// measurements, presented by a session bound to the NEW key, verifies
    /// and yields the derived (old_key, new_key).
    #[test]
    fn transition_link_happy_path() {
        let (sk_old, pk_old) = keypair(0x30);
        let link = upgrade_link(0x30, 0x40, &sk_old);
        let session_key = key_from_seed(0x40); // new key submits
        let verified = decode_and_verify(&link, session_key, &pk_old, true).expect("verify");
        assert_eq!(verified.old_key, key_from_seed(0x30));
        assert_eq!(verified.new_key, session_key);
    }

    /// Signed by a different key than the one registered for old_key:
    /// the control-signature check rejects it.
    #[test]
    fn transition_link_wrong_signing_key_rejected() {
        let (_sk_registered, pk_registered) = keypair(0x31);
        let (sk_attacker, _) = keypair(0xff);
        // Link is signed by the attacker, but verified against the OLD
        // key's registered pubkey.
        let link = upgrade_link(0x31, 0x41, &sk_attacker);
        let session_key = key_from_seed(0x41);
        let err = decode_and_verify(&link, session_key, &pk_registered, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::SignatureInvalid),
            "{err:?}"
        );
    }

    /// A pubkey that doesn't decode as a SEC1 point (e.g. an unregistered
    /// old_key represented by zero bytes) is rejected at decode time.
    #[test]
    fn transition_link_unregistered_pubkey_rejected() {
        let (sk, _pk) = keypair(0x32);
        let link = upgrade_link(0x32, 0x42, &sk);
        let session_key = key_from_seed(0x42);
        // All-zero bytes: not a valid SEC1 P-256 encoding.
        let bogus = [0u8; crate::CONTROL_PUBKEY_LEN];
        let err = decode_and_verify(&link, session_key, &bogus, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::BadControlPubkey),
            "{err:?}"
        );
    }

    /// to_pcrs hashes to something other than the submitting session's
    /// key: the NEW enclave isn't the one presenting the link.
    #[test]
    fn transition_link_session_key_mismatch_rejected() {
        let (sk, pk) = keypair(0x33);
        let link = upgrade_link(0x33, 0x43, &sk);
        // Caller's session is bound to a key the payload's to_pcrs does
        // not hash to.
        let wrong_session = key_from_seed(0x99);
        let err = decode_and_verify(&link, wrong_session, &pk, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::SessionKeyMismatch),
            "{err:?}"
        );
    }

    /// to_pcrs equals from_pcrs (self-transition) is rejected.
    #[test]
    fn transition_link_to_equals_from_rejected() {
        let (sk, pk) = keypair(0x34);
        let link = upgrade_link(0x34, 0x34, &sk);
        // from == to, so the derived new_key equals the session key here.
        let session_key = key_from_seed(0x34);
        let err = decode_and_verify(&link, session_key, &pk, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::SelfTransition),
            "{err:?}"
        );
    }

    /// A non-upgrade link (boot) is rejected outright at decode time.
    #[test]
    fn transition_link_wrong_kind_rejected() {
        let (sk, _pk) = keypair(0x35);
        let mut link = upgrade_link(0x35, 0x45, &sk);
        link.kind = ChainLinkKind::Boot;
        let err = decode_transition_link(&link).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::NotAnUpgradeLink(_)),
            "{err:?}"
        );
    }

    /// A link with no signature is rejected at decode time.
    #[test]
    fn transition_link_missing_signature_rejected() {
        let (sk, _pk) = keypair(0x37);
        let mut link = upgrade_link(0x37, 0x47, &sk);
        link.signature = None;
        let err = decode_transition_link(&link).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::MissingSignature),
            "{err:?}"
        );
    }

    /// The OLD bug shape: the link is attested with the TARGET (to_pcrs)
    /// measurements instead of the source (from_pcrs). The corrected
    /// verifier checks the attestation against from_pcrs, so this is now
    /// rejected by `verify_chain_attestation`.
    #[test]
    fn transition_link_attested_with_to_pcrs_rejected() {
        let (sk, pk) = keypair(0x36);
        // upgrade_link attests with from_seed (correct); rebuild the
        // attestation with the to_seed (0x46) to reproduce the old bug.
        let mut link = upgrade_link(0x36, 0x46, &sk);
        let payload_bytes = link.payload.clone();
        link.attestation = FakeChainAttestation::for_payload(0x46, &payload_bytes).encode();
        let session_key = key_from_seed(0x46);
        let err = decode_and_verify(&link, session_key, &pk, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::Attestation(_)),
            "{err:?}"
        );
    }

    /// Tampering the attestation so its PCRs match neither from nor to is
    /// caught by `verify_chain_attestation`.
    #[test]
    fn transition_link_attestation_pcr_mismatch_rejected() {
        let (sk, pk) = keypair(0x38);
        let mut link = upgrade_link(0x38, 0x48, &sk);
        // Re-attest the same payload under PCRs (0x77) that match neither
        // from_pcrs (0x38) nor to_pcrs (0x48). user_data still binds the
        // payload, so this isolates the PCR-equality check.
        let payload_bytes = link.payload.clone();
        link.attestation = FakeChainAttestation::for_payload(0x77, &payload_bytes).encode();
        let session_key = key_from_seed(0x48);
        let err = decode_and_verify(&link, session_key, &pk, true).unwrap_err();
        assert!(
            matches!(err, TransitionLinkError::Attestation(_)),
            "{err:?}"
        );
    }
}
