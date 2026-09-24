//! Nitro NSM attestation verification.
//!
//! Two entry points share the same parse-and-verify core:
//!
//! - [`verify_against`] — "is this document from the enclave I expected?"
//!   The SDK's call path: a client knows what PCRs the target enclave is
//!   supposed to have and wants the document to confirm it.
//!
//! - [`verify_and_extract`] — "what enclave produced this document?" The
//!   synchronizer's call path: it does not pre-commit to a specific
//!   identity; the document's verified PCRs *are* the identity, and the
//!   caller hashes them into its own key. The doc must also carry the
//!   enclave's raw 32-byte Ed25519 control pubkey in `user_data` — the
//!   synchronizer registers it alongside the key and uses it to verify
//!   `Transition` signatures later.
//!
//! Both check that the doc's nonce equals `base64(handshake_hash)`,
//! binding the document to the live Noise session. Every entry point
//! takes a [`VerificationMode`]: [`VerificationMode::Production`]
//! validates the full AWS Nitro CA chain and COSE_Sign1 signature, while
//! [`VerificationMode::DangerousSkipChain`] skips both (the in-enclave
//! NSM self-signs when run under QEMU) and must never be reachable from
//! runtime state a host or peer can influence.
//!
//! ## Which clock the certificate chain is validated at
//!
//! Every session-bound entry point (the ones taking a `handshake_hash`)
//! validates the chain at the document's own signed `timestamp`, not at
//! the verifier's clock. The nonce proves the document is fresh for the
//! session; the verifier's clock would add only a failure mode: a Nitro
//! leaf certificate becomes valid seconds before the first document it
//! signs, so a verifier running even a few seconds slow would see it as
//! "not yet valid" and refuse a genuine peer. Enclaves have no clock
//! synchronisation, so that drift is the normal state, not an edge case.
//! The local clock is kept only as the coarse
//! [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] sanity bound.

use attestation_doc_validation::{
    PCRProvider, attestation_doc::decode_attestation_document,
    attestation_doc::get_pcrs as att_get_pcrs, validate_expected_nonce, validate_expected_pcrs,
};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use sha2::{Digest, Sha256};

/// PCR (Platform Configuration Register) measurements that identify a
/// specific enclave image and configuration:
///
/// - `pcr0` — Enclave Image File (EIF) measurement.
/// - `pcr1` — Enclave OS measurement.
/// - `pcr2` — Application configuration measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcrs {
    /// EIF measurement.
    pub pcr0: Vec<u8>,
    /// Enclave OS measurement.
    pub pcr1: Vec<u8>,
    /// Application configuration measurement.
    pub pcr2: Vec<u8>,
}

impl Pcrs {
    /// Build [`Pcrs`] from the three hex-encoded measurements, exactly as
    /// printed by `enclavia enclave status` / `enclavia reproduce` and
    /// shown on the dashboard, so they can be copy/pasted verbatim.
    /// Accepts upper- or lower-case hex and surrounding whitespace. Each
    /// value must decode to 32, 48, or 64 bytes (real Nitro PCRs are
    /// 48-byte SHA-384, 96 hex characters).
    ///
    /// ```
    /// let pcrs = enclavia_protocol::attestation::Pcrs::from_hex(
    ///     &"ab".repeat(48),
    ///     &"cd".repeat(48),
    ///     &"ef".repeat(48),
    /// )
    /// .unwrap();
    /// assert_eq!(pcrs.pcr0.len(), 48);
    /// ```
    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Self, AttestationError> {
        fn decode(idx: usize, s: &str) -> Result<Vec<u8>, AttestationError> {
            let bytes = hex::decode(s.trim()).map_err(|_| AttestationError::InvalidPcrHex(idx))?;
            if !matches!(bytes.len(), 32 | 48 | 64) {
                return Err(AttestationError::InvalidPcrLength {
                    idx,
                    len: bytes.len(),
                });
            }
            Ok(bytes)
        }
        Ok(Pcrs {
            pcr0: decode(0, pcr0)?,
            pcr1: decode(1, pcr1)?,
            pcr2: decode(2, pcr2)?,
        })
    }

    /// SHA-256 over `PCR0 || PCR1 || PCR2`. The synchronizer uses this
    /// 32-byte digest as the per-enclave session key.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.pcr0);
        hasher.update(&self.pcr1);
        hasher.update(&self.pcr2);
        hasher.finalize().into()
    }
}

/// Errors from attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Parse/structure/signature/PCR/nonce validation failed in the
    /// upstream `attestation-doc-validation` crate. Carries the original
    /// error rendered to a string — the upstream type is non-exhaustive
    /// and not worth re-exporting.
    #[error("attestation document validation failed: {0}")]
    Validation(String),
    /// A PCR value coming out of the validated document hex-decoded to
    /// something other than 32/48/64 bytes, which would break PcrKey
    /// derivation. Should be unreachable for real Nitro docs.
    #[error("attestation document PCR {idx} has unexpected length {len}")]
    InvalidPcrLength {
        /// The PCR index (0, 1, or 2).
        idx: usize,
        /// The decoded length in bytes.
        len: usize,
    },
    /// A PCR slot was not hex-encoded. Should be unreachable: the
    /// upstream crate is the one that hex-encodes them on the way out.
    #[error("attestation document PCR {0} is not valid hex")]
    InvalidPcrHex(usize),
    /// The doc's `user_data` field is missing or not a 65-byte
    /// uncompressed SEC1 ECDSA P-256 verifying key. Required by
    /// [`verify_and_extract`] — the synchronizer needs the control
    /// pubkey to verify `Transition` signatures later in the session.
    #[error(
        "attestation document user_data is missing or not a 65-byte uncompressed SEC1 P-256 pubkey"
    )]
    InvalidControlPubkey,
    /// The doc's `user_data` field is missing or not the 32-byte
    /// SHA-256 hash of the chain link's `payload`. Required by
    /// [`verify_chain_attestation`] — every chain link binds its
    /// `attestation.user_data` to `sha256(payload)`, so any mismatch
    /// means either the payload or the attestation has been swapped.
    #[error("attestation document user_data does not match sha256(payload)")]
    PayloadBindingMismatch,
    /// The doc's `user_data` field is missing or not exactly 32 bytes
    /// where a control nonce was expected. Returned by
    /// [`verify_control_nonce_attestation`]: the in-enclave server's
    /// `RequestAttestation` reply always embeds the current 32-byte
    /// control nonce as `user_data`, so any other shape means the
    /// document was produced for a different purpose (or tampered with).
    #[error("attestation document user_data is not a 32-byte control nonce")]
    InvalidControlNonce,
    /// The document verified (structure, signature, nonce binding) but
    /// its PCR0/1/2 equal NONE of the caller's expected triples.
    /// Returned by [`verify_and_extract_pcrs`]: the presenting enclave
    /// is genuine but is not the identity the caller trusts
    /// (server authentication).
    #[error("attestation document PCRs match none of the expected values")]
    PcrsNotExpected,
}

/// Length of an ECDSA P-256 verifying key in uncompressed SEC1 form
/// (`0x04 || X(32) || Y(32)`). Locked at the protocol layer because
/// every caller — synchronizer node, in-enclave server, attestation
/// emitter — needs to agree on the shape carried in
/// `AttestationDoc::user_data`.
pub const CONTROL_PUBKEY_LEN: usize = 65;

/// Domain-separation string the canonical non-upgradable control key is
/// derived from. Public and fixed: it is the audit anchor that lets
/// anyone reproduce [`NON_UPGRADABLE_CONTROL_KEY`] and confirm the
/// construction.
pub const NON_UPGRADABLE_CONTROL_KEY_DST: &[u8] =
    b"enclavia/synchronizer/non-upgradable-control-key/v1";

/// The canonical "provably un-signable" control key for enclaves that
/// have no upgrade path at all (non-upgradable enclaves).
///
/// ## What it is for
///
/// The synchronizer freezes a key's control pubkey at first pin and uses
/// it for exactly one thing: verifying the ECDSA signature on a future
/// `Transition` (the PCR re-key that an upgrade performs). An enclave
/// with no upgrade chain has no control key, so the storage-pinning
/// client registers with THIS value instead. Because no private key for
/// it is known to anyone, no `Transition` signature can ever verify, so
/// the pinned storage history is permanently bound to that one image,
/// which is exactly the correct semantic for a non-upgradable enclave.
/// It only disables `Transition`; `Pin`/`Get` are gated by the attested
/// PCR key, not by this pubkey, so storage pinning works normally.
///
/// ## Why it is provably un-signable (nothing-up-my-sleeve)
///
/// The point's x-coordinate is a SHA-256 hash output over the public
/// [`NON_UPGRADABLE_CONTROL_KEY_DST`] (try-and-increment to the first
/// valid curve point). Recovering a private key would mean solving the
/// discrete log for a point whose x nobody chose, so by construction no
/// party knows (or could have arranged to know) the scalar. This is
/// strictly safer than minting a throwaway real key and trusting that
/// its private half was destroyed: here no usable private half ever
/// existed.
///
/// Baked as a compile-time constant (uncompressed SEC1, `0x04 || X || Y`)
/// so it costs nothing at runtime and is usable in const contexts. The
/// bytes are the output of try-and-increment over
/// [`NON_UPGRADABLE_CONTROL_KEY_DST`] (hash the DST with a 1-byte
/// counter to a candidate x-coordinate, take the first that decompresses
/// to a valid P-256 point). `derive_non_upgradable_control_key` in the
/// tests re-runs that derivation and asserts it equals this constant, so
/// the literal can never silently drift from its construction.
pub const NON_UPGRADABLE_CONTROL_KEY: [u8; CONTROL_PUBKEY_LEN] = [
    0x04, 0x22, 0x18, 0xad, 0x29, 0x17, 0x7d, 0x9a, 0x5c, 0xb3, 0x52, 0xc4, 0x78, 0x64, 0x06, 0xfa,
    0x76, 0x57, 0xaa, 0xc1, 0x6c, 0xe4, 0xb2, 0xe8, 0x19, 0xcd, 0xbd, 0x7f, 0x6e, 0xbd, 0xfa, 0x5a,
    0x8e, 0xb1, 0x1a, 0xf7, 0x68, 0x69, 0x3a, 0xd6, 0x5f, 0xc5, 0xb2, 0x21, 0x10, 0x3f, 0x10, 0x8a,
    0xe9, 0x50, 0x87, 0xb3, 0x1d, 0x68, 0x54, 0xe8, 0x13, 0x51, 0x60, 0x6d, 0xc4, 0xe2, 0xd4, 0xf7,
    0xda,
];

/// Verified enclave identity extracted from an NSM attestation document.
///
/// Returned by [`verify_and_extract`] when the document validates and the
/// caller wants both the PCRs (for deriving a session key) and the
/// enclave's ECDSA P-256 control pubkey (for verifying future
/// `Transition` signatures from this key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIdentity {
    /// PCR0/1/2 from the validated document.
    pub pcrs: Pcrs,
    /// 65-byte uncompressed SEC1 ECDSA P-256 verifying key extracted
    /// from the doc's `user_data` field. The synchronizer registers
    /// this alongside the [`Pcrs::digest`]-derived key on first
    /// attestation, and uses it to verify raw r||s signatures on
    /// subsequent `Transition` RPCs.
    pub control_pubkey: [u8; CONTROL_PUBKEY_LEN],
}

/// How much of an attestation document's cryptographic envelope is
/// verified.
///
/// This used to be a bare `debug_mode: bool` on every verify entry
/// point, which made the skip-the-root-of-trust switch look like any
/// other flag (enclavia#101). The dedicated type makes the insecure
/// choice explicit and greppable at every call site: constructing
/// [`VerificationMode::DangerousSkipChain`] is a visible, reviewable
/// act, never an anonymous `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Full verification: the AWS Nitro CA chain is validated and the
    /// COSE_Sign1 signature is verified. The only mode in which a
    /// document proves anything about the hardware that produced it.
    Production,
    /// Structural decode ONLY: the CA chain and COSE signature are NOT
    /// checked, so ANY well-formed document passes — including one
    /// forged by the host. Exists solely for QEMU's self-signing
    /// emulated NSM and the `test-utils` document builders. Must never
    /// be selected by runtime state a host or peer can influence; every
    /// production caller derives its mode from a compile-time feature
    /// or an explicit developer opt-in.
    DangerousSkipChain,
}

impl VerificationMode {
    /// Bridge from the workspace's established `debug_mode: bool`
    /// plumbing (compile-time `cfg` constants in the synchronizer, the
    /// SDK's explicit `ClientBuilder::debug_mode` opt-in).
    ///
    /// The argument MUST be a compile-time constant or an explicit
    /// developer opt-in — never a value read from the environment, a
    /// request, or any other channel the host or peer influences: `true`
    /// disables the certificate chain that makes attestation mean
    /// anything.
    pub fn from_debug_flag(debug_mode: bool) -> Self {
        if debug_mode {
            Self::DangerousSkipChain
        } else {
            Self::Production
        }
    }

    fn skips_chain(self) -> bool {
        matches!(self, Self::DangerousSkipChain)
    }
}

/// Verify an attestation document against expected PCRs.
///
/// SDK entry point. The caller has pinned the enclave's identity at
/// configure-time and wants `Ok(())` on a match or an error otherwise.
///
/// Checks performed (in order, in both [`VerificationMode`]s):
///
/// 1. Parse + structural validation of the COSE_Sign1 wrapper.
/// 2. Nonce equals `base64(handshake_hash)`.
/// 3. PCR0/1/2 in the doc equal the caller-supplied `expected_pcrs`.
///
/// Additionally, in [`VerificationMode::Production`], the AWS Nitro CA
/// chain is validated and the COSE signature is verified.
pub fn verify_against(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    expected_pcrs: &Pcrs,
    mode: VerificationMode,
) -> Result<(), AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = verify_session_bound(attestation_data, handshake_hash, mode)?;

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    Ok(())
}

/// Verify a control-nonce attestation and return the attested nonce.
///
/// Backend control-dispatch entry point (upgrade-chain hardening). Before signing
/// and sending a control command, the dispatcher requests an attestation
/// over the control channel; the in-enclave server's reply binds the
/// live Noise session (doc `nonce` = `base64(handshake_hash)`) and
/// carries the current 32-byte control nonce in `user_data`. Verifying
/// the document before dispatch gives the caller two guarantees a bare
/// `GetControlNonce` round-trip cannot:
///
/// 1. The Noise session terminates inside the enclave whose PCRs the
///    caller expected, with no host in the middle, so the eventual
///    `ControlResult` is authentic rather than the relay's word.
/// 2. The nonce embedded in the signed command was minted by that
///    enclave, not substituted on the way through the host.
///
/// Verification is [`verify_against`] (COSE chain in production mode,
/// session-nonce binding, PCR equality) plus a requirement that
/// `user_data` is exactly 32 bytes, returned as the attested control
/// nonce.
pub fn verify_control_nonce_attestation(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    expected_pcrs: &Pcrs,
    mode: VerificationMode,
) -> Result<[u8; 32], AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = verify_session_bound(attestation_data, handshake_hash, mode)?;

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::InvalidControlNonce)?;
    user_data
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidControlNonce)
}

/// Verify an attestation document and return the enclave identity it
/// embeds.
///
/// Synchronizer entry point. The caller does not know in advance which
/// enclave is connecting — the verified document's PCRs *are* the
/// identity, and the doc's `user_data` carries the enclave's Ed25519
/// control pubkey. The caller typically passes the returned
/// [`AttestedIdentity::pcrs`] through [`Pcrs::digest`] to derive a stable
/// session key, and registers
/// [`AttestedIdentity::control_pubkey`] for verifying future
/// `Transition` RPCs from this key.
///
/// Verification is identical to [`verify_against`] minus the
/// `expected_pcrs` equality check (there are no expected PCRs at this
/// layer — the doc's nonce binding to the handshake hash is what
/// authenticates the document's origin to the live session), plus a
/// requirement that `user_data` is exactly [`CONTROL_PUBKEY_LEN`]
/// bytes — the uncompressed SEC1 ECDSA P-256 verifying key.
pub fn verify_and_extract(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    mode: VerificationMode,
) -> Result<AttestedIdentity, AttestationError> {
    let doc = verify_session_bound(attestation_data, handshake_hash, mode)?;

    let hex_pcrs = att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;

    let pcrs = Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    };

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::InvalidControlPubkey)?;
    let control_pubkey: [u8; CONTROL_PUBKEY_LEN] = user_data
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidControlPubkey)?;
    // SEC1 uncompressed-form prefix must be 0x04. Anything else (0x02 /
    // 0x03 compressed, or random bytes that happen to fit) is rejected
    // here so the in-enclave verifier doesn't have to handle the
    // compressed-form decompression path.
    if control_pubkey[0] != 0x04 {
        return Err(AttestationError::InvalidControlPubkey);
    }

    Ok(AttestedIdentity {
        pcrs,
        control_pubkey,
    })
}

/// Verify an attestation document's session binding AND that its PCRs
/// equal one of the caller's `expected` triples, with no `user_data`
/// requirement. Returns the verified PCRs (which of the expected set
/// matched).
///
/// Server-authentication entry point.
/// The synchronizer's CUSTOMER client uses this to authenticate the
/// ORACLE back to itself: the synchronizer sends its own NSM document
/// bound to the live Noise session and the client validates it here
/// against the synchronizer measurements it trusts.
///
/// Checks performed:
///
/// 1. Parse + structural validation of the COSE_Sign1 wrapper; in
///    [`VerificationMode::Production`] the AWS Nitro CA chain is
///    validated and the COSE signature verified, exactly like
///    [`verify_against`] / [`verify_and_extract`].
/// 2. Nonce equals `base64(handshake_hash)`: the document is bound to
///    *this* Noise session, so a document captured from any other
///    session (including the mesh and other customers' sessions) is
///    rejected.
/// 3. The document's PCR0/1/2 equal one of `expected` EXACTLY. An empty
///    `expected` admits nothing. The comparison is mandatory and lives
///    here (not at the caller) so no public API exists that verifies a
///    document without committing to an identity; a bare
///    verify-and-return-PCRs form would be passable by ANY enclave,
///    including a reflection of the caller's own document.
///
/// Differs from [`verify_against`] in accepting a SET of valid triples
/// (a deployment may roll between two cluster images), and from
/// [`verify_and_extract`] in not requiring (or reading) `user_data`:
/// the server side of the customer protocol carries no control pubkey,
/// so demanding one would force the server to stuff a meaningless value
/// into the document.
pub fn verify_and_extract_pcrs(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    expected: &[Pcrs],
    mode: VerificationMode,
) -> Result<Pcrs, AttestationError> {
    let doc = verify_session_bound(attestation_data, handshake_hash, mode)?;

    let hex_pcrs = att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;

    let pcrs = Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    };
    if !expected.iter().any(|e| e == &pcrs) {
        return Err(AttestationError::PcrsNotExpected);
    }
    Ok(pcrs)
}

/// Extract PCR0/1/2 from an attestation document the caller JUST obtained from
/// its OWN `/dev/nsm`, WITHOUT verifying the certificate chain or the nonce.
///
/// # This is NOT a verification function. Read before using.
///
/// Every other entry point in this module (`verify_against`,
/// `verify_and_extract`, `verify_control_nonce_attestation`,
/// `verify_chain_attestation`) authenticates a document that came from SOMEONE
/// ELSE: in production it validates the AWS Nitro CA chain and the COSE
/// signature, and it binds the document to a live Noise session via the nonce.
/// This function does NONE of that. It only structurally decodes the COSE_Sign1
/// envelope and pulls out the PCRs. A document fed to it could be a forgery and
/// it would happily return whatever PCRs the forgery claims.
///
/// That is acceptable for, and ONLY for, one caller: a node deriving its OWN
/// self-PCR digest from a document it just requested from its OWN local
/// `/dev/nsm`. The local NSM device is inside the node's trusted computing base
/// (on real Nitro it is the hardware module measuring this very VM; under
/// QEMU's nitro-enclave machine it is the emulated module measuring the same),
/// so there is no cert chain to trust (the node is reading its own hardware
/// measurements, not authenticating a remote party) and there is no Noise
/// session to bind to (the node generated the request itself, with an arbitrary
/// nonce). This replaces a host-supplied PCR allowlist, which the host (the
/// adversary) could otherwise choose to admit a rogue image into the mesh.
///
/// Do NOT use this on a document received over the network, ever: use
/// [`verify_and_extract`] (peer attestation) or [`verify_against`] (pinned
/// identity) for that.
pub fn extract_own_pcrs(attestation_data: &[u8]) -> Result<Pcrs, AttestationError> {
    // Structural decode only: no cert chain, no signature, no nonce. The
    // `DangerousSkipChain` arm of `parse_and_validate` is exactly this
    // (decode_attestation_document), and it is correct here on BOTH QEMU and
    // real Nitro because the caller is reading its own local device, not
    // authenticating a remote party.
    let doc = parse_and_validate(attestation_data, VerificationMode::DangerousSkipChain)?;
    let hex_pcrs = att_get_pcrs(&doc).map_err(|e| AttestationError::Validation(e.to_string()))?;
    Ok(Pcrs {
        pcr0: decode_pcr(&hex_pcrs.pcr_0, 0)?,
        pcr1: decode_pcr(&hex_pcrs.pcr_1, 1)?,
        pcr2: decode_pcr(&hex_pcrs.pcr_2, 2)?,
    })
}

/// Verify a chain-link attestation document.
///
/// Used by the backend's `POST /enclaves/{id}/chain-links` ingest
/// path: each chain link (`boot`, `upgrade`, `revocation`) carries a
/// hardware-signed `attestation` whose `user_data` field commits to the
/// link's `payload` via `sha256(payload)`. This function performs the
/// minimum-trust check required at ingest:
///
/// 1. Parse + structural validation of the COSE_Sign1 wrapper (same as
///    [`verify_against`] / [`verify_and_extract`]).
/// 2. `attestation.user_data == sha256(payload)` — the binding that
///    makes the chain entry tamper-evident.
/// 3. PCR0/1/2 in the doc equal `expected_pcrs` (the backend's recorded
///    PCRs for this enclave, post-build).
///
/// In [`VerificationMode::Production`], the AWS Nitro CA chain is
/// validated and the COSE signature is verified by the upstream
/// `attestation-doc-validation` crate, same as the existing entry
/// points. In [`VerificationMode::DangerousSkipChain`], only
/// structural validity is required —
/// matching QEMU's emulated NSM device, which signs documents with its
/// own key instead of the AWS CA (and the `test-utils` doc builders,
/// which carry placeholder signatures).
///
/// The doc's `nonce` field is **not** checked here. The chain-link
/// attestations are not produced in the context of a Noise session, so
/// there is no handshake hash to bind against; the binding lives in
/// `user_data` instead. Any value in `nonce` is accepted.
pub fn verify_chain_attestation(
    attestation_data: &[u8],
    payload: &[u8],
    expected_pcrs: &Pcrs,
    mode: VerificationMode,
) -> Result<(), AttestationError> {
    let pcrs_hex = PcrsHex::from_pcrs(expected_pcrs);
    let doc = parse_and_validate(attestation_data, mode)?;

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::PayloadBindingMismatch)?;
    let expected: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.finalize().into()
    };
    if user_data.as_slice() != expected {
        return Err(AttestationError::PayloadBindingMismatch);
    }

    validate_expected_pcrs(&doc, &pcrs_hex)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;

    Ok(())
}

/// Largest accepted distance between a session-bound document's signed
/// `timestamp` and the verifier's clock, in either direction.
///
/// Not a freshness check: the handshake-hash nonce already proves the
/// document was produced for this session. It bounds how long a leaked
/// Nitro leaf signing key could keep producing acceptable documents past
/// its certificate's `notAfter` (without it, a leaked key could sign a
/// timestamp inside its old window forever). It is deliberately far wider
/// than any realistic drift of an unsynchronised clock so that clock drift
/// is never the reason a genuine, fresh document is refused; a
/// verifier whose clock is off by more than this also fails the wall-clock
/// check this replaced (the leaf is only valid for a few hours).
pub const MAX_SESSION_DOC_CLOCK_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Verification context for a session-bound document: the trust anchor and
/// the verifier's clock. Production uses [`SessionCtx::system`]; the unit
/// tests substitute a test CA and a chosen "now".
struct SessionCtx<'a> {
    root_der: &'a [u8],
    now_ms: u64,
}

impl SessionCtx<'static> {
    fn system() -> Self {
        Self {
            root_der: crate::nitro_verify::AWS_NITRO_ROOT_CA_DER,
            // chrono reads the platform clock on native targets and
            // `Date.now()` on wasm (std's SystemTime panics there).
            now_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
        }
    }
}

/// Parse and verify a document bound to a live Noise session: the shared
/// core of every entry point that takes a `handshake_hash`.
///
/// In [`VerificationMode::Production`] the certificate chain is validated
/// at the document's own signed `timestamp`, not at the verifier's clock
/// (see `nitro_verify.rs` for why that instant is sound). The nonce check
/// below is what makes the document fresh for this session, so the
/// verifier's clock only enters as the coarse
/// [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] sanity bound. The bound applies in
/// [`VerificationMode::DangerousSkipChain`] too, which skips only the chain
/// and the signature: QEMU's emulated NSM stamps the host's wall clock
/// (whole seconds), so a genuine QEMU document is as close to the
/// verifier's clock as a Nitro one.
fn verify_session_bound(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    mode: VerificationMode,
) -> Result<AttestationDoc, AttestationError> {
    verify_session_bound_with(
        attestation_data,
        handshake_hash,
        mode,
        &SessionCtx::system(),
    )
}

fn verify_session_bound_with(
    attestation_data: &[u8],
    handshake_hash: &[u8],
    mode: VerificationMode,
    ctx: &SessionCtx<'_>,
) -> Result<AttestationDoc, AttestationError> {
    let doc = if mode.skips_chain() {
        decode_only(attestation_data)?
    } else {
        crate::nitro_verify::validate_at_doc_timestamp(attestation_data, ctx.root_der)
            .map_err(AttestationError::Validation)?
    };
    let skew = doc.timestamp.abs_diff(ctx.now_ms);
    if skew > MAX_SESSION_DOC_CLOCK_SKEW_MS {
        return Err(AttestationError::Validation(format!(
            "document timestamp {} ms is {skew} ms from the local clock {} ms \
             (limit {MAX_SESSION_DOC_CLOCK_SKEW_MS} ms)",
            doc.timestamp, ctx.now_ms
        )));
    }

    check_nonce(&doc, handshake_hash)?;
    Ok(doc)
}

/// Structural decode only (the [`VerificationMode::DangerousSkipChain`]
/// path).
fn decode_only(attestation_data: &[u8]) -> Result<AttestationDoc, AttestationError> {
    let (_, doc) = decode_attestation_document(attestation_data)
        .map_err(|e| AttestationError::Validation(e.to_string()))?;
    Ok(doc)
}

/// Parse without a session binding ([`verify_chain_attestation`],
/// [`extract_own_pcrs`]). In production the chain is checked at the
/// verifier's wall clock.
fn parse_and_validate(
    attestation_data: &[u8],
    mode: VerificationMode,
) -> Result<AttestationDoc, AttestationError> {
    if mode.skips_chain() {
        decode_only(attestation_data)
    } else {
        attestation_doc_validation::validate_and_parse_attestation_doc(attestation_data)
            .map_err(|e| AttestationError::Validation(e.to_string()))
    }
}

fn check_nonce(doc: &AttestationDoc, handshake_hash: &[u8]) -> Result<(), AttestationError> {
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(handshake_hash);
    validate_expected_nonce(doc, &nonce_b64)
        .map_err(|e| AttestationError::Validation(e.to_string()))
}

fn decode_pcr(hex_str: &str, idx: usize) -> Result<Vec<u8>, AttestationError> {
    let bytes = hex::decode(hex_str).map_err(|_| AttestationError::InvalidPcrHex(idx))?;
    if ![32usize, 48, 64].contains(&bytes.len()) {
        return Err(AttestationError::InvalidPcrLength {
            idx,
            len: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Internal hex-encoded view of a [`Pcrs`] for the `PCRProvider` trait.
/// The upstream crate compares PCRs by string equality on hex
/// representations, so we encode once at the entry point.
struct PcrsHex {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

impl PcrsHex {
    fn from_pcrs(pcrs: &Pcrs) -> Self {
        Self {
            pcr0: hex::encode(&pcrs.pcr0),
            pcr1: hex::encode(&pcrs.pcr1),
            pcr2: hex::encode(&pcrs.pcr2),
        }
    }
}

impl PCRProvider for PcrsHex {
    fn pcr_0(&self) -> Option<&str> {
        Some(&self.pcr0)
    }
    fn pcr_1(&self) -> Option<&str> {
        Some(&self.pcr1)
    }
    fn pcr_2(&self) -> Option<&str> {
        Some(&self.pcr2)
    }
    fn pcr_8(&self) -> Option<&str> {
        None
    }
}

/// Test-only helpers for constructing attestation documents with known
/// PCRs and nonces. Behind the `test-utils` feature so downstream test
/// suites can build doc fixtures without spinning up real Nitro
/// hardware. Production builds cannot reach this module.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use std::collections::BTreeMap;

    use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
    use ciborium::value::Value as CborValue;

    /// The `timestamp` the builders stamp: the current time, as a genuine
    /// NSM (real or QEMU's emulated one) does, so session documents pass the
    /// verifier's clock-skew bound.
    pub fn now_ms() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
    }

    /// Builder for synthetic attestation documents accepted by
    /// [`verify_against`](super::verify_against) /
    /// [`verify_and_extract`](super::verify_and_extract) in debug mode.
    ///
    /// In debug mode the COSE signature is not validated, so any
    /// well-formed COSE_Sign1 envelope around a well-formed
    /// [`AttestationDoc`] is accepted. PCR0/1/2 are 48-byte SHA-384
    /// values (matches what real Nitro hardware emits).
    pub struct FakeAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// Raw Noise handshake hash. The encoded doc's `nonce` field is
        /// set to these bytes verbatim — the verifier base64-encodes
        /// before comparing, so it works out.
        pub handshake_hash: Vec<u8>,
        /// 65-byte uncompressed SEC1 ECDSA P-256 verifying key. Encoded
        /// into the doc's `user_data` field — [`super::verify_and_extract`]
        /// requires this to be a 65-byte pubkey with the SEC1 prefix
        /// `0x04`.
        pub control_pubkey: [u8; super::CONTROL_PUBKEY_LEN],
    }

    impl FakeAttestation {
        /// Build a fixture with all three PCRs derived from `seed` and a
        /// synthetic but structurally-valid SEC1 control pubkey (prefix
        /// `0x04`, the remaining 64 bytes filled with `seed | 0x80`).
        /// The synthetic pubkey will NOT decode as a valid P-256 point,
        /// so tests that only need to exercise the verifier's
        /// length-and-prefix check can use this directly; tests that
        /// need a *real* P-256 keypair (to actually sign) should use
        /// [`Self::with_seed_and_pubkey`] with bytes from a
        /// `p256::ecdsa::SigningKey`.
        pub fn with_seed(seed: u8, handshake_hash: Vec<u8>) -> Self {
            let mut control_pubkey = [seed.wrapping_add(0x80); super::CONTROL_PUBKEY_LEN];
            control_pubkey[0] = 0x04;
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                handshake_hash,
                control_pubkey,
            }
        }

        /// Like [`Self::with_seed`] but with a caller-supplied control
        /// pubkey (typically `VerifyingKey::to_encoded_point(false)` from
        /// a real `p256::ecdsa::SigningKey` the test holds for signing).
        pub fn with_seed_and_pubkey(
            seed: u8,
            handshake_hash: Vec<u8>,
            control_pubkey: [u8; super::CONTROL_PUBKEY_LEN],
        ) -> Self {
            let mut fake = Self::with_seed(seed, handshake_hash);
            fake.control_pubkey = control_pubkey;
            fake
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// `debug_mode` verify path.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            // The upstream `get_pcrs` is hard-coded to require PCR8
            // (signing-cert measurement). Synchronizer doesn't use it,
            // but the doc has to include it to deserialize.
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                now_ms(),
                pcrs,
                // certificate / cabundle: not validated in debug mode,
                // but `validate_attestation_document_structure` does
                // require each cert byte slice to be 1..=1024 bytes.
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.control_pubkey.to_vec()),
                Some(self.handshake_hash.clone()),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            // COSE_Sign1, untagged: [protected: bstr, unprotected: map, payload: bstr, signature: bstr].
            // - protected is a *byte string* whose contents are a serialized HeaderMap.
            //   An empty CBOR map is one byte: 0xa0.
            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                // Signature: junk. The debug-mode verify path does not
                // touch it (and even production verify only fails if the
                // cert chain is wrong, which it always will be for
                // synthetic docs).
                CborValue::Bytes(vec![0u8; 96]),
            ]);

            let mut out = Vec::new();
            ciborium::into_writer(&cose, &mut out).expect("ciborium encode COSE_Sign1");
            out
        }
    }

    /// Builder for synthetic control-nonce attestation documents
    /// accepted by
    /// [`verify_control_nonce_attestation`](super::verify_control_nonce_attestation)
    /// in debug mode. Mirrors the in-enclave server's
    /// `RequestAttestation` reply shape: `nonce` carries the Noise
    /// handshake hash, `user_data` carries the 32-byte control nonce.
    pub struct FakeControlNonceAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// Raw Noise handshake hash, encoded verbatim into the doc's
        /// `nonce` field (the verifier base64-encodes before comparing).
        pub handshake_hash: Vec<u8>,
        /// Encoded into the doc's `user_data` field. 32 bytes on the
        /// happy path; tests exercising the length check can override.
        pub control_nonce: Vec<u8>,
    }

    impl FakeControlNonceAttestation {
        /// Build a fixture with all three PCRs derived from `seed`.
        pub fn with_seed(seed: u8, handshake_hash: Vec<u8>, control_nonce: [u8; 32]) -> Self {
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                handshake_hash,
                control_nonce: control_nonce.to_vec(),
            }
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// `debug_mode` verify path.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                now_ms(),
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.control_nonce.clone()),
                Some(self.handshake_hash.clone()),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                CborValue::Bytes(vec![0u8; 96]),
            ]);

            let mut out = Vec::new();
            ciborium::into_writer(&cose, &mut out).expect("ciborium encode COSE_Sign1");
            out
        }
    }

    /// Builder for synthetic chain-link attestation documents accepted
    /// by [`verify_chain_attestation`](super::verify_chain_attestation)
    /// in debug mode. Differs from [`FakeAttestation`] in two ways:
    ///   * `user_data` carries the SHA-256 of a caller-supplied
    ///     `payload` (not the control pubkey, which the chain ingest
    ///     path doesn't read).
    ///   * `nonce` is irrelevant to the chain ingest verifier and is
    ///     populated with a fixed zero-padded value so the doc still
    ///     serialises.
    pub struct FakeChainAttestation {
        pub pcr0: Vec<u8>,
        pub pcr1: Vec<u8>,
        pub pcr2: Vec<u8>,
        /// 32-byte SHA-256 of the chain link's payload. Set by
        /// [`Self::for_payload`]; tests that want to exercise a
        /// `user_data` mismatch can override after construction.
        pub user_data: Vec<u8>,
    }

    impl FakeChainAttestation {
        /// Build a fixture with all three PCRs derived from `seed` and
        /// `user_data` set to `sha256(payload)`. Drop-in for the chain
        /// ingest verifier's happy path.
        pub fn for_payload(seed: u8, payload: &[u8]) -> Self {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(payload);
            let user_data: Vec<u8> = hasher.finalize().to_vec();
            Self {
                pcr0: vec![seed; 48],
                pcr1: vec![seed.wrapping_add(1); 48],
                pcr2: vec![seed.wrapping_add(2); 48],
                user_data,
            }
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// `debug_mode` chain-attestation verify path.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            pcrs.insert(8usize, vec![0u8; 48]);

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                now_ms(),
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.user_data.clone()),
                // Nonce is not consulted by `verify_chain_attestation`,
                // but the doc has to carry one to serialise. Zero-padded
                // to a length the structure-validator accepts.
                Some(vec![0u8; 32]),
                None,
            );

            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).expect("ciborium encode AttestationDoc");

            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                CborValue::Bytes(vec![0u8; 96]),
            ]);

            let mut out = Vec::new();
            ciborium::into_writer(&cose, &mut out).expect("ciborium encode COSE_Sign1");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test document comes from the `test-utils` builders (or the
    /// QEMU-shaped self-signed path), so the chain-skipping mode is the
    /// only one that can accept them.
    const DM: VerificationMode = VerificationMode::DangerousSkipChain;

    fn hh() -> Vec<u8> {
        // 32-byte BLAKE2s-shaped handshake hash for tests.
        (0u8..32).collect()
    }

    #[test]
    fn verify_and_extract_returns_doc_identity_in_debug_mode() {
        let fake = test_utils::FakeAttestation::with_seed(0x11, hh());
        let bytes = fake.encode();

        let identity = verify_and_extract(&bytes, &hh(), DM).expect("verify");
        assert_eq!(identity.pcrs.pcr0, fake.pcr0);
        assert_eq!(identity.pcrs.pcr1, fake.pcr1);
        assert_eq!(identity.pcrs.pcr2, fake.pcr2);
        assert_eq!(identity.control_pubkey, fake.control_pubkey);
    }

    #[test]
    fn extract_own_pcrs_returns_doc_pcrs_without_nonce_or_chain() {
        // A document the node "just got from its own /dev/nsm" (here a
        // FakeAttestation fixture). extract_own_pcrs must return its PCR0/1/2
        // verbatim with no nonce/cert-chain check, so the node can derive its
        // own self-PCR digest regardless of the throwaway/self-signed key.
        let fake = test_utils::FakeAttestation::with_seed(0x5a, hh());
        let bytes = fake.encode();

        let pcrs = extract_own_pcrs(&bytes).expect("extract own pcrs");
        assert_eq!(pcrs.pcr0, fake.pcr0);
        assert_eq!(pcrs.pcr1, fake.pcr1);
        assert_eq!(pcrs.pcr2, fake.pcr2);

        // The digest matches what verify_and_extract derives for the same doc,
        // i.e. it is the SAME identity a peer would compute, just without the
        // verification a peer document requires.
        let verified = verify_and_extract(&bytes, &hh(), DM).expect("verify");
        assert_eq!(pcrs.digest(), verified.pcrs.digest());
    }

    #[test]
    fn extract_own_pcrs_ignores_the_nonce_entirely() {
        // Unlike verify_and_extract, extract_own_pcrs takes no handshake hash
        // and never inspects the nonce: a doc minted with one nonce still
        // yields its PCRs. (The node mints the request itself with an arbitrary
        // nonce; there is no session to bind to.)
        let fake = test_utils::FakeAttestation::with_seed(0x77, vec![0xde; 32]);
        let pcrs = extract_own_pcrs(&fake.encode()).expect("extract own pcrs");
        assert_eq!(pcrs.pcr0, fake.pcr0);
    }

    #[test]
    fn extract_own_pcrs_rejects_garbage_bytes() {
        let err = extract_own_pcrs(b"not a cose document").unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_control_nonce_attestation_returns_attested_nonce() {
        let nonce = [0xab; 32];
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), nonce);
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let got =
            verify_control_nonce_attestation(&fake.encode(), &hh(), &expected, DM).expect("verify");
        assert_eq!(got, nonce);
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_wrong_pcrs() {
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        let wrong = Pcrs {
            pcr0: vec![0xff; 48],
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let err = verify_control_nonce_attestation(&fake.encode(), &hh(), &wrong, DM).unwrap_err();
        assert!(matches!(err, AttestationError::Validation(_)), "{err}");
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_wrong_handshake_hash() {
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        let other_hh: Vec<u8> = (100u8..132).collect();

        let err =
            verify_control_nonce_attestation(&fake.encode(), &other_hh, &expected, DM).unwrap_err();
        assert!(matches!(err, AttestationError::Validation(_)), "{err}");
    }

    #[test]
    fn verify_control_nonce_attestation_rejects_non_32_byte_user_data() {
        let mut fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        fake.control_nonce = vec![0xab; 16]; // wrong length
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };

        let err =
            verify_control_nonce_attestation(&fake.encode(), &hh(), &expected, DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlNonce),
            "{err}"
        );
    }

    #[test]
    fn verify_and_extract_rejects_doc_without_user_data() {
        // Build a doc with `user_data: None` by constructing it directly,
        // since `FakeAttestation::encode` always populates user_data.
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0usize, vec![0x11u8; 48]);
        pcrs.insert(1usize, vec![0x12u8; 48]);
        pcrs.insert(2usize, vec![0x13u8; 48]);
        pcrs.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            test_utils::now_ms(),
            pcrs,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            None, // user_data missing — the case under test.
            Some(hh()),
            None,
        );

        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_and_extract(&bytes, &hh(), DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlPubkey),
            "expected InvalidControlPubkey, got {err:?}"
        );
    }

    #[test]
    fn verify_and_extract_rejects_doc_with_wrong_size_user_data() {
        let mut fake = test_utils::FakeAttestation::with_seed(0x22, hh());
        // Override user_data via the `control_pubkey` field by encoding
        // a longer payload — done by reaching directly into the struct
        // and re-encoding manually. Easier: build the doc inline with a
        // 16-byte user_data.
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;
        let _ = &mut fake;

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0usize, vec![0x22u8; 48]);
        pcrs.insert(1usize, vec![0x23u8; 48]);
        pcrs.insert(2usize, vec![0x24u8; 48]);
        pcrs.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            test_utils::now_ms(),
            pcrs,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            Some(vec![0u8; 16]), // 16 bytes is the wrong size.
            Some(hh()),
            None,
        );

        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_and_extract(&bytes, &hh(), DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidControlPubkey),
            "expected InvalidControlPubkey, got {err:?}"
        );
    }

    /// The expected-PCR triple matching `FakeAttestation::with_seed(seed)`.
    fn seed_pcrs(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    #[test]
    fn verify_and_extract_pcrs_returns_doc_pcrs_in_debug_mode() {
        let fake = test_utils::FakeAttestation::with_seed(0x66, hh());
        let pcrs =
            verify_and_extract_pcrs(&fake.encode(), &hh(), &[seed_pcrs(0x66)], DM).expect("verify");
        assert_eq!(pcrs.pcr0, fake.pcr0);
        assert_eq!(pcrs.pcr1, fake.pcr1);
        assert_eq!(pcrs.pcr2, fake.pcr2);
    }

    #[test]
    fn verify_and_extract_pcrs_rejects_unexpected_pcrs() {
        let fake = test_utils::FakeAttestation::with_seed(0x66, hh());
        let err =
            verify_and_extract_pcrs(&fake.encode(), &hh(), &[seed_pcrs(0x99)], DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::PcrsNotExpected),
            "expected PcrsNotExpected, got {err:?}"
        );
        // An empty expected set admits nothing.
        let err = verify_and_extract_pcrs(&fake.encode(), &hh(), &[], DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::PcrsNotExpected),
            "expected PcrsNotExpected, got {err:?}"
        );
    }

    #[test]
    fn verify_and_extract_pcrs_rejects_wrong_handshake_hash() {
        let fake = test_utils::FakeAttestation::with_seed(0x67, hh());
        let wrong: Vec<u8> = vec![0xab; 32];
        let err =
            verify_and_extract_pcrs(&fake.encode(), &wrong, &[seed_pcrs(0x67)], DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_and_extract_pcrs_rejects_garbage_bytes() {
        let err = verify_and_extract_pcrs(b"not a cose document", &hh(), &[seed_pcrs(0x66)], DM)
            .unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_and_extract_pcrs_accepts_doc_without_user_data() {
        // The server side of the customer protocol carries no control
        // pubkey, so the doc may legitimately omit user_data (a real
        // /dev/nsm request with user_data = None). Build one inline,
        // since FakeAttestation always populates user_data.
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0usize, vec![0x68u8; 48]);
        pcrs.insert(1usize, vec![0x69u8; 48]);
        pcrs.insert(2usize, vec![0x6au8; 48]);
        pcrs.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            test_utils::now_ms(),
            pcrs,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            None, // no user_data: must still verify.
            Some(hh()),
            None,
        );

        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let pcrs = verify_and_extract_pcrs(&bytes, &hh(), &[seed_pcrs(0x68)], DM).expect("verify");
        assert_eq!(pcrs.pcr0, vec![0x68u8; 48]);
    }

    #[test]
    fn verify_against_accepts_matching_pcrs_in_debug_mode() {
        let fake = test_utils::FakeAttestation::with_seed(0x22, hh());
        let bytes = fake.encode();
        let expected = Pcrs {
            pcr0: fake.pcr0.clone(),
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        verify_against(&bytes, &hh(), &expected, DM).expect("verify");
    }

    #[test]
    fn verify_against_rejects_mismatched_pcrs() {
        let fake = test_utils::FakeAttestation::with_seed(0x33, hh());
        let bytes = fake.encode();
        let expected = Pcrs {
            pcr0: vec![0xff; 48],
            pcr1: fake.pcr1.clone(),
            pcr2: fake.pcr2.clone(),
        };
        let err = verify_against(&bytes, &hh(), &expected, DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_handshake_hash() {
        let fake = test_utils::FakeAttestation::with_seed(0x44, hh());
        let bytes = fake.encode();
        let wrong: Vec<u8> = vec![0xab; 32];
        let err = verify_and_extract(&bytes, &wrong, DM).unwrap_err();
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    /// Skipping the chain does not skip the clock-skew bound: a session
    /// document stamped further than the bound from the verifier's clock is
    /// refused in both modes.
    #[test]
    fn skip_chain_still_bounds_clock_skew() {
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let encode = |timestamp: u64| {
            let mut pcrs = BTreeMap::new();
            for i in [0usize, 1, 2, 8] {
                pcrs.insert(i, vec![0x45u8; 48]);
            }
            let mut control_pubkey = vec![0x04u8];
            control_pubkey.extend_from_slice(&[0x55; 64]);
            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                timestamp,
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(control_pubkey),
                Some(hh()),
                None,
            );
            let mut payload = Vec::new();
            ciborium::into_writer(&doc, &mut payload).unwrap();
            let cose = CborValue::Array(vec![
                CborValue::Bytes(vec![0xa0]),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(payload),
                CborValue::Bytes(vec![0u8; 96]),
            ]);
            let mut bytes = Vec::new();
            ciborium::into_writer(&cose, &mut bytes).unwrap();
            bytes
        };

        let now = test_utils::now_ms();
        let margin = 60 * 60 * 1000;
        verify_and_extract(&encode(now), &hh(), DM).expect("current timestamp");
        for stale in [
            now - MAX_SESSION_DOC_CLOCK_SKEW_MS - margin,
            now + MAX_SESSION_DOC_CLOCK_SKEW_MS + margin,
        ] {
            let err = verify_and_extract(&encode(stale), &hh(), DM).unwrap_err();
            assert!(err.to_string().contains("from the local clock"), "{err}");
        }
    }

    #[test]
    fn digest_is_sha256_of_concatenated_pcrs() {
        let pcrs = Pcrs {
            pcr0: vec![0x01; 48],
            pcr1: vec![0x02; 48],
            pcr2: vec![0x03; 48],
        };
        let mut hasher = Sha256::new();
        hasher.update(&pcrs.pcr0);
        hasher.update(&pcrs.pcr1);
        hasher.update(&pcrs.pcr2);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(pcrs.digest(), expected);
    }

    fn pcrs_from_seed(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    #[test]
    fn verify_chain_attestation_accepts_well_formed_link_in_debug_mode() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x33, &payload);
        let bytes = fake.encode();
        let expected_pcrs = pcrs_from_seed(0x33);

        verify_chain_attestation(&bytes, &payload, &expected_pcrs, DM)
            .expect("valid chain attestation must pass");
    }

    #[test]
    fn verify_chain_attestation_rejects_mismatched_payload_binding() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x44, &payload);
        let bytes = fake.encode();
        let expected_pcrs = pcrs_from_seed(0x44);

        // Same attestation, different payload — user_data binds to the
        // original, so the verifier must reject the substitution.
        let err = verify_chain_attestation(&bytes, b"DIFFERENT", &expected_pcrs, DM)
            .expect_err("payload swap must fail the binding check");
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_attestation_rejects_pcr_mismatch() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x55, &payload);
        let bytes = fake.encode();
        // Wrong expected PCRs — the caller's recorded PCRs disagree with
        // what the doc carries. Verifier must reject.
        let mismatched_pcrs = pcrs_from_seed(0x99);

        let err = verify_chain_attestation(&bytes, &payload, &mismatched_pcrs, DM)
            .expect_err("PCR mismatch must fail");
        assert!(
            matches!(err, AttestationError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_attestation_rejects_doc_without_user_data() {
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let payload = b"any-payload".to_vec();
        let pcrs = pcrs_from_seed(0x77);

        let mut pcr_map = BTreeMap::new();
        pcr_map.insert(0usize, pcrs.pcr0.clone());
        pcr_map.insert(1usize, pcrs.pcr1.clone());
        pcr_map.insert(2usize, pcrs.pcr2.clone());
        pcr_map.insert(8usize, vec![0u8; 48]);

        let doc = AttestationDoc::new(
            "test-module".to_string(),
            Digest::SHA384,
            test_utils::now_ms(),
            pcr_map,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            None, // user_data missing — the case under test.
            Some(vec![0u8; 32]),
            None,
        );

        let mut doc_bytes = Vec::new();
        ciborium::into_writer(&doc, &mut doc_bytes).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(vec![0xa0]),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(doc_bytes),
            CborValue::Bytes(vec![0u8; 96]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cose, &mut bytes).unwrap();

        let err = verify_chain_attestation(&bytes, &payload, &pcrs, DM)
            .expect_err("missing user_data must be rejected");
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
    }
}

/// Production-mode (full chain + COSE signature) tests against a throwaway
/// test CA. The fixtures below are a P-384 root, intermediate and
/// leaf shaped like a Nitro chain; the leaf is valid only from
/// 2030-01-01T00:00:00Z to 2030-01-01T03:00:00Z. The verifier's "now" is
/// injected, so these tests do not depend on the machine's clock.
///
/// The fixtures were made with `openssl` (secp384r1 keys, `-sha384`): a
/// self-signed root, an intermediate with `basicConstraints=critical,CA:TRUE`,
/// and a leaf with `basicConstraints=critical,CA:FALSE`, issued with
/// `-not_before 20300101000000Z -not_after 20300101030000Z`.
#[cfg(test)]
mod production_chain_tests {
    use super::*;
    use crate::nitro_verify::Sha2;
    use aws_nitro_enclaves_cose::CoseSign1;
    use aws_nitro_enclaves_cose::crypto::{
        MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
    };
    use aws_nitro_enclaves_cose::error::CoseError;
    use aws_nitro_enclaves_cose::header_map::HeaderMap;
    use aws_nitro_enclaves_nsm_api::api::Digest as NsmDigest;
    use ciborium::value::Value as CborValue;
    use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
    use std::collections::BTreeMap;

    const ROOT_HEX: &str = concat!(
        "308201d83082015ea0030201020214268f4a41a5a174b37fda6b3755ce77c4e525c68a300a06082a",
        "8648ce3d040303301a3118301606035504030c0f746573742d6e6974726f2d726f6f743020170d32",
        "30303130313030303030305a180f32303630303130313030303030305a301a311830160603550403",
        "0c0f746573742d6e6974726f2d726f6f743076301006072a8648ce3d020106052b81040022036200",
        "040c7b73807020e7ec162fc6fe77952706963db218ac9bcfdb0c4aed5099ec5c98c8362d807b4834",
        "05444d206f8726c664ae9bb149db1d7c81d2b3774436b958bc33b854411d9d4c2f39382ba5695f11",
        "cb5c8358bb0ee54ccdfac7981d7f03015da3633061301d0603551d0e04160414579059f167083cfd",
        "ebff6548a408a4f62d26f8c7301f0603551d23041830168014579059f167083cfdebff6548a408a4",
        "f62d26f8c7300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a",
        "06082a8648ce3d040303036800306502306aa5233c9ced4fd63296a29e0bd6b5eb40f1765e53fa13",
        "3c2f58d3bb04e244c6fcbb7631f2f02361343ed2f4fba76581023100f9dada944d7b129cd7275410",
        "a983f890e884284e0c65f1b942a815c9f93899aa5a5070f34f34534d2a9055f355355400",
    );
    const INTERMEDIATE_HEX: &str = concat!(
        "308201cc30820153a003020102020102300a06082a8648ce3d040303301a3118301606035504030c",
        "0f746573742d6e6974726f2d726f6f743020170d3230303130313030303030305a180f3230363030",
        "3130313030303030305a30223120301e06035504030c17746573742d6e6974726f2d696e7465726d",
        "6564696174653076301006072a8648ce3d020106052b81040022036200042761a28416776946638a",
        "f62ace3d84e2bde552f33b041d17014b421606b51d87a0194906a8e365ab3be2185ab0722381308f",
        "47dedeb9ce89294d21a85cb1d2a88d9409b803d7bcae7bc246e84fb3512389ed243a366ef6877487",
        "77ee800e01faa3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403",
        "020106301d0603551d0e04160414d157e6f8067ad4cdf903630a0f95d15a4a5ad123301f0603551d",
        "23041830168014579059f167083cfdebff6548a408a4f62d26f8c7300a06082a8648ce3d04030303",
        "6700306402300fba9b4105da8ed2f6fc7ad17df29c0ea9559ff95f786f78184916d0bc882c068be3",
        "e3e9e9e8c58feeb7c6865b59841d02303a2f6e0d21e33bdf5752f4e2b8eaeab8b5e6f712fa807678",
        "0118184a0186b9d58dd97b8407d0b189b84a298896fd06bc",
    );
    const LEAF_HEX: &str = concat!(
        "308201c83082014ea003020102020103300a06082a8648ce3d04030330223120301e06035504030c",
        "17746573742d6e6974726f2d696e7465726d656469617465301e170d333030313031303030303030",
        "5a170d3330303130313033303030305a301a3118301606035504030c0f746573742d6e6974726f2d",
        "6c6561663076301006072a8648ce3d020106052b8104002203620004e583b8134fc2a53cf58fe6c3",
        "998ee6994f4a9458f8a2d2c79360ff2237a4c1b7d93f14848afbb796f0818051bc0c66905e756e25",
        "9289f232211c76e2ecaf3186396a6ebe448d22f41adb52a31dcab7dbd8fe8c868d85af4d5f45f367",
        "7487522aa360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d",
        "0603551d0e04160414ac4efc0af3d0f9468e75d56ab5aaebc1b4b7aa19301f0603551d2304183016",
        "8014d157e6f8067ad4cdf903630a0f95d15a4a5ad123300a06082a8648ce3d040303036800306502",
        "303dd4b7408cd86c1b4c106c79f86ffef93d96940c6cc66c06d3a598ba1398581fd7fd913a340ae3",
        "89d6763187470240cc023100894430e665ab17f37baa0fc7c99f9122c6918dda0e92fca35a095c37",
        "f2c38b95b277a731f0b6ecadcfd5d05467c1ee57",
    );
    /// Private scalar of `test_leaf.der` (test-only key, signs nothing real).
    const LEAF_KEY_HEX: &str = "fadfe43e9ac388cce57702cc987d24191779f155f0b7ed868d3f7dfce69c4dfe0deee3105519c2d0d0fd3dd282f3a4b6";

    fn der(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).unwrap()
    }

    /// 2030-01-01T00:00:00Z, the leaf's notBefore.
    const LEAF_NOT_BEFORE_MS: u64 = 1_893_456_000_000;
    /// 2030-01-01T03:00:00Z, the leaf's notAfter.
    const LEAF_NOT_AFTER_MS: u64 = LEAF_NOT_BEFORE_MS + 3 * 60 * 60 * 1000;

    struct TestSigner(p384::ecdsa::SigningKey);

    impl TestSigner {
        fn leaf() -> Self {
            let bytes = hex::decode(LEAF_KEY_HEX).unwrap();
            Self(p384::ecdsa::SigningKey::from_slice(&bytes).unwrap())
        }
        fn other() -> Self {
            Self(p384::ecdsa::SigningKey::from_slice(&[0x42; 48]).unwrap())
        }
    }

    impl SigningPublicKey for TestSigner {
        fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
            Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
        }
        fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
            let sig = p384::ecdsa::Signature::from_slice(signature).unwrap();
            Ok(self.0.verifying_key().verify_prehash(digest, &sig).is_ok())
        }
    }

    impl SigningPrivateKey for TestSigner {
        fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
            let sig: p384::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().to_vec())
        }
    }

    fn hh() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn seed_pcrs(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    /// CBOR payload of an NSM-shaped document from the test chain.
    fn doc_payload(timestamp_ms: u64, nonce: &[u8]) -> Vec<u8> {
        let pcrs = seed_pcrs(0x31);
        let mut map = BTreeMap::new();
        map.insert(0usize, pcrs.pcr0);
        map.insert(1usize, pcrs.pcr1);
        map.insert(2usize, pcrs.pcr2);
        map.insert(8usize, vec![0u8; 48]);
        let mut control_pubkey = vec![0x04u8];
        control_pubkey.extend_from_slice(&[0x55; 64]);
        let doc = AttestationDoc::new(
            "i-test-enc0123456789abcdef".to_string(),
            NsmDigest::SHA384,
            timestamp_ms,
            map,
            der(LEAF_HEX),
            // Nitro order: root first, then intermediates.
            vec![der(ROOT_HEX), der(INTERMEDIATE_HEX)],
            Some(control_pubkey),
            Some(nonce.to_vec()),
            None,
        );
        let mut payload = Vec::new();
        ciborium::into_writer(&doc, &mut payload).unwrap();
        payload
    }

    fn sign(payload: &[u8], signer: &TestSigner) -> Vec<u8> {
        CoseSign1::new::<Sha2>(payload, &HeaderMap::new(), signer)
            .unwrap()
            .as_bytes(false)
            .unwrap()
    }

    fn signed_doc(timestamp_ms: u64, nonce: &[u8]) -> Vec<u8> {
        sign(&doc_payload(timestamp_ms, nonce), &TestSigner::leaf())
    }

    fn verify(doc: &[u8], nonce: &[u8], now_ms: u64) -> Result<AttestationDoc, AttestationError> {
        let root = der(ROOT_HEX);
        let ctx = SessionCtx {
            root_der: &root,
            now_ms,
        };
        verify_session_bound_with(doc, nonce, VerificationMode::Production, &ctx)
    }

    #[test]
    fn leaf_not_yet_valid_at_verifier_clock_passes_at_doc_timestamp() {
        // The NSM minted the leaf 5 s before signing; the verifier's clock
        // runs 20 s slow, so by its clock the leaf is not valid yet.
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let verifier_now = doc_ts - 20_000;
        assert!(verifier_now < LEAF_NOT_BEFORE_MS);
        let doc = signed_doc(doc_ts, &hh());

        // Validating the chain at the verifier's clock refuses it: this is
        // the failure the doc-timestamp check removes.
        let err = validate_chain_at_for_test(&doc, verifier_now / 1000).unwrap_err();
        assert!(err.contains("CertNotValidYet"), "{err}");

        let got = verify(&doc, &hh(), verifier_now).expect("must verify at doc timestamp");
        assert_eq!(got.timestamp, doc_ts);
    }

    #[test]
    fn verifier_clock_fast_or_slow_within_bound_passes() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = signed_doc(doc_ts, &hh());
        for now in [
            doc_ts - MAX_SESSION_DOC_CLOCK_SKEW_MS,
            doc_ts - 60 * 60 * 1000,
            doc_ts,
            doc_ts + 60 * 60 * 1000,
            doc_ts + MAX_SESSION_DOC_CLOCK_SKEW_MS,
        ] {
            verify(&doc, &hh(), now).unwrap_or_else(|e| panic!("now={now}: {e}"));
        }
    }

    #[test]
    fn verifier_clock_beyond_sanity_bound_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = signed_doc(doc_ts, &hh());
        for now in [
            doc_ts - MAX_SESSION_DOC_CLOCK_SKEW_MS - 1,
            doc_ts + MAX_SESSION_DOC_CLOCK_SKEW_MS + 1,
        ] {
            let err = verify(&doc, &hh(), now).unwrap_err();
            assert!(err.to_string().contains("from the local clock"), "{err}");
        }
    }

    #[test]
    fn doc_timestamp_after_leaf_expiry_fails() {
        // Signed by the genuine leaf key, but at an instant the leaf is
        // expired: must fail even if the verifier's clock agrees.
        let doc_ts = LEAF_NOT_AFTER_MS + 1_000;
        let doc = signed_doc(doc_ts, &hh());
        let err = verify(&doc, &hh(), doc_ts).unwrap_err();
        assert!(err.to_string().contains("CertExpired"), "{err}");
    }

    #[test]
    fn doc_timestamp_before_leaf_validity_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS - 1_000;
        let doc = signed_doc(doc_ts, &hh());
        let err = verify(&doc, &hh(), doc_ts).unwrap_err();
        assert!(err.to_string().contains("CertNotValidYet"), "{err}");
    }

    #[test]
    fn tampered_timestamp_fails_signature() {
        // Take a genuine document whose leaf is expired at its timestamp and
        // move the timestamp back into the leaf's window without re-signing.
        // The chain check now passes, so the COSE signature is what must
        // catch it.
        let genuine = signed_doc(LEAF_NOT_AFTER_MS + 1_000, &hh());
        let moved_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let tampered = replace_payload(&genuine, doc_payload(moved_ts, &hh()));
        let err = verify(&tampered, &hh(), moved_ts).unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
    }

    #[test]
    fn tampered_nonce_fails_signature() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let other: Vec<u8> = vec![0xab; 32];
        let genuine = signed_doc(doc_ts, &hh());
        // Re-bind the document to a different session without re-signing.
        let tampered = replace_payload(&genuine, doc_payload(doc_ts, &other));
        let err = verify(&tampered, &other, doc_ts).unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
    }

    #[test]
    fn doc_signed_by_key_other_than_leaf_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = sign(&doc_payload(doc_ts, &hh()), &TestSigner::other());
        let err = verify(&doc, &hh(), doc_ts).unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
    }

    #[test]
    fn nonce_mismatch_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = signed_doc(doc_ts, &hh());
        let wrong: Vec<u8> = vec![0xab; 32];
        let err = verify(&doc, &wrong, doc_ts).unwrap_err();
        assert!(err.to_string().contains("Nonce"), "{err}");
    }

    #[test]
    fn chain_not_rooted_in_the_aws_nitro_root_fails() {
        // Production entry points use the embedded AWS root, which the test
        // chain does not lead to.
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = signed_doc(doc_ts, &hh());
        let err = verify_and_extract(&doc, &hh(), VerificationMode::Production).unwrap_err();
        assert!(
            err.to_string().contains("certificate chain invalid"),
            "{err}"
        );
    }

    /// Replace the payload of a COSE_Sign1, keeping its protected header and
    /// signature.
    fn replace_payload(cose: &[u8], payload: Vec<u8>) -> Vec<u8> {
        let value: CborValue = ciborium::from_reader(cose).unwrap();
        let CborValue::Array(mut parts) = value else {
            panic!("COSE_Sign1 is an array")
        };
        parts[2] = CborValue::Bytes(payload);
        let mut out = Vec::new();
        ciborium::into_writer(&CborValue::Array(parts), &mut out).unwrap();
        out
    }

    /// The chain check as the verifier's-clock path performed it: same
    /// anchor and algorithms, validated at `at_secs`.
    fn validate_chain_at_for_test(cose: &[u8], at_secs: u64) -> Result<(), String> {
        let (_, doc) = decode_attestation_document(cose).map_err(|e| e.to_string())?;
        let leaf = webpki::EndEntityCert::try_from(doc.certificate.as_slice())
            .map_err(|e| format!("{e:?}"))?;
        let root = der(ROOT_HEX);
        let anchor = [webpki::TrustAnchor::try_from_cert_der(&root).unwrap()];
        let intermediates: Vec<&[u8]> = doc.cabundle.iter().map(|c| c.as_slice()).collect();
        leaf.verify_is_valid_tls_server_cert(
            &[&webpki::ECDSA_P384_SHA384],
            &webpki::TlsServerTrustAnchors(&anchor),
            &intermediates,
            webpki::Time::from_seconds_since_unix_epoch(at_secs),
        )
        .map_err(|e| format!("{e:?}"))
    }
}

#[cfg(test)]
mod non_upgradable_control_key_tests {
    use super::{CONTROL_PUBKEY_LEN, NON_UPGRADABLE_CONTROL_KEY, NON_UPGRADABLE_CONTROL_KEY_DST};
    use sha2::{Digest, Sha256};

    /// Re-run the try-and-increment derivation the baked constant came
    /// from: hash the DST with a 1-byte counter to a candidate
    /// x-coordinate and take the first that decompresses to a valid
    /// P-256 point. Test-only; the production value is the
    /// [`NON_UPGRADABLE_CONTROL_KEY`] constant, this just proves the
    /// constant equals its construction so the literal cannot drift.
    fn derive_non_upgradable_control_key() -> [u8; CONTROL_PUBKEY_LEN] {
        use p256::EncodedPoint;
        use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

        for counter in 0u16..=255 {
            let mut hasher = Sha256::new();
            hasher.update(NON_UPGRADABLE_CONTROL_KEY_DST);
            hasher.update([counter as u8]);
            let x = hasher.finalize();
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02; // even-y compressed SEC1
            compressed[1..].copy_from_slice(&x);
            let Ok(encoded) = EncodedPoint::from_bytes(compressed) else {
                continue;
            };
            let maybe_point = p256::AffinePoint::from_encoded_point(&encoded);
            if maybe_point.is_some().into() {
                let uncompressed = maybe_point.unwrap().to_encoded_point(false);
                let mut out = [0u8; CONTROL_PUBKEY_LEN];
                out.copy_from_slice(uncompressed.as_bytes());
                return out;
            }
        }
        panic!("no valid P-256 point found deriving the non-upgradable control key");
    }

    /// The baked constant must equal the live derivation. This is the
    /// audit anchor: a change to the DST or the derivation that is not
    /// mirrored into the constant trips here, forcing a deliberate
    /// review (changing the value would orphan every already-pinned
    /// non-upgradable enclave).
    #[test]
    fn constant_matches_derivation() {
        assert_eq!(
            NON_UPGRADABLE_CONTROL_KEY,
            derive_non_upgradable_control_key(),
            "baked non-upgradable control key drifted from its DST derivation"
        );
    }

    #[test]
    fn is_uncompressed_sec1_shape() {
        assert_eq!(NON_UPGRADABLE_CONTROL_KEY.len(), CONTROL_PUBKEY_LEN);
        assert_eq!(NON_UPGRADABLE_CONTROL_KEY[0], 0x04);
    }

    /// It must parse as a real P-256 verifying key, so `Register` and the
    /// `verify_transition_link` decode step accept it (the un-signability
    /// bites at the signature check, not at decode: a Transition cannot
    /// be rejected merely because the key looks malformed, it must be a
    /// well-formed key that simply no signature verifies against).
    #[test]
    fn parses_as_a_valid_verifying_key() {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(NON_UPGRADABLE_CONTROL_KEY.as_slice())
            .expect("canonical non-upgradable control key must be a valid P-256 point");
    }
}
