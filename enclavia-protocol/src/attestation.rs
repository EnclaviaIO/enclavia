//! Nitro NSM attestation documents, as two types.
//!
//! - [`UnvalidatedAttestation`] holds bytes that came from outside this
//!   process: a peer's `Authenticate` frame, a stored chain link, a backend
//!   response. It exposes no contents at all (no PCRs, timestamp,
//!   `user_data`), only the bytes for storing or forwarding. The way to
//!   read a document is to validate it in a named context, so the binding
//!   that context needs cannot be forgotten:
//!   - [`UnvalidatedAttestation::validate_session`]: a document presented
//!     on a live Noise session. Its `nonce` must equal the session's
//!     handshake hash.
//!   - [`UnvalidatedAttestation::validate_chain_link`]: a chain link's
//!     document. Its `user_data` must equal `sha256(payload)`.
//! - [`ValidatedAttestation`] is the only type with accessors. It has no
//!   public constructor: it comes from one of the two methods above, or
//!   from [`ValidatedAttestation::request_local`] (feature `nsm`), which
//!   asks this process's OWN `/dev/nsm`. The local device is inside the
//!   caller's trusted computing base, so its output needs no chain check.
//!
//! Validation establishes authenticity. Which enclave to trust is policy,
//! a separate step on the validated document:
//! [`ValidatedAttestation::require_pcrs`],
//! [`ValidatedAttestation::require_pcrs_in`],
//! [`ValidatedAttestation::require_identity`], or the caller's own
//! allowlist over [`ValidatedAttestation::identity`].
//!
//! ## Skipping the certificate chain
//!
//! QEMU's emulated NSM signs documents with its own key, not under the AWS
//! Nitro CA. [`UnvalidatedAttestation::validate_session_skip_chain`] and
//! [`UnvalidatedAttestation::validate_chain_link_skip_chain`] check the
//! structure, the context binding and (for a session document) the
//! clock-skew bound, but NOT the certificate chain or the COSE signature,
//! so any well-formed document passes, including one forged by the host.
//! They exist only with the `dangerous-skip-chain` feature
//! (implied by `test-utils`); a build without it has no way to skip the
//! chain.
//!
//! ## Which clock the certificate chain is validated at
//!
//! Both contexts validate the chain at the document's own signed
//! `timestamp`, not at the verifier's clock (see `nitro_verify.rs` for why
//! that instant is sound).
//!
//! For a session document the nonce proves the document is fresh for the
//! session; the verifier's clock would add only a failure mode: a Nitro
//! leaf certificate becomes valid seconds before the first document it
//! signs, so a verifier running even a few seconds slow would see it as
//! "not yet valid" and refuse a genuine peer. Enclaves have no clock
//! synchronisation, so that drift is the normal state, not an edge case.
//! The local clock is kept only as the coarse
//! [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] sanity bound.
//!
//! A chain link is a stored record verified long after it was produced,
//! so no bound against the local clock applies to it.

use attestation_doc_validation::validate_expected_nonce;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::pin_identity::{PinIdentity, PinIdentityError};


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
}

/// Why an attestation document was rejected, as a small fixed set of
/// causes.
///
/// Every [`AttestationError`] maps to exactly one reason
/// ([`AttestationError::reason`]). The set is deliberately coarse and
/// stable so a verifier can log and count rejections by cause; the
/// human-readable detail stays in the error's `Display`. [`Self::as_str`]
/// gives a stable snake_case label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The bytes are not a well-formed NSM attestation document: CBOR /
    /// COSE decode or structure checks failed, a certificate or key in it
    /// does not decode, or a field the caller requires (PCRs, `user_data`)
    /// has the wrong shape.
    Malformed,
    /// The leaf certificate is not valid yet at the document's timestamp.
    NotYetValid,
    /// The leaf certificate has expired at the document's timestamp.
    Expired,
    /// The certificate chain does not lead to the trusted root (unknown
    /// issuer, or any other path-validation failure above the leaf).
    UntrustedChain,
    /// A signature does not verify: the COSE signature under the leaf key,
    /// or a certificate signature in the chain.
    Signature,
    /// The document's timestamp is further from the verifier's clock than
    /// [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] (session-bound documents only).
    ClockSkew,
    /// The document's `nonce` is not this session's handshake hash: it was
    /// produced for another session (replay, or a relay's substitution).
    NonceMismatch,
    /// A chain-link document's `user_data` is not `sha256(payload)`.
    PayloadBindingMismatch,
    /// The document is genuine but its PCRs are not the expected ones.
    PcrMismatch,
}

impl RejectionReason {
    /// Every reason, in declaration order (for pre-registering counters).
    pub const ALL: &'static [RejectionReason] = &[
        RejectionReason::Malformed,
        RejectionReason::NotYetValid,
        RejectionReason::Expired,
        RejectionReason::UntrustedChain,
        RejectionReason::Signature,
        RejectionReason::ClockSkew,
        RejectionReason::NonceMismatch,
        RejectionReason::PayloadBindingMismatch,
        RejectionReason::PcrMismatch,
    ];

    /// Stable snake_case label, suitable for a log field or a metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            RejectionReason::Malformed => "malformed",
            RejectionReason::NotYetValid => "not_yet_valid",
            RejectionReason::Expired => "expired",
            RejectionReason::UntrustedChain => "untrusted_chain",
            RejectionReason::Signature => "signature",
            RejectionReason::ClockSkew => "clock_skew",
            RejectionReason::NonceMismatch => "nonce_mismatch",
            RejectionReason::PayloadBindingMismatch => "payload_binding_mismatch",
            RejectionReason::PcrMismatch => "pcr_mismatch",
        }
    }
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A document validation failure: the classified [`RejectionReason`] plus
/// a human-readable detail (often the upstream crate's error text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    /// Classified cause.
    pub reason: RejectionReason,
    /// Human-readable detail, for logs only (not a stable format).
    pub detail: String,
}

impl ValidationFailure {
    pub(crate) fn new(reason: RejectionReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.reason)
    }
}

/// Errors from attestation validation and policy checks.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Decode / structure / certificate chain / signature / clock-skew /
    /// nonce / PCR validation failed. Carries the classified reason and the
    /// upstream detail (the upstream error types are non-exhaustive and not
    /// worth re-exporting).
    #[error("attestation document validation failed: {0}")]
    Validation(ValidationFailure),
    /// A PCR given to [`Pcrs::from_hex`] decoded to something other than
    /// 32/48/64 bytes.
    #[error("attestation document PCR {idx} has unexpected length {len}")]
    InvalidPcrLength {
        /// The PCR index (0, 1, or 2).
        idx: usize,
        /// The decoded length in bytes.
        len: usize,
    },
    /// A PCR given to [`Pcrs::from_hex`] is not hex.
    #[error("attestation document PCR {0} is not valid hex")]
    InvalidPcrHex(usize),
    /// The doc's `user_data` field is missing or not a 65-byte
    /// uncompressed SEC1 ECDSA P-256 verifying key. Returned by
    /// [`ValidatedAttestation::control_pubkey`]: the synchronizer needs the
    /// control pubkey to verify `Transition` signatures later.
    #[error(
        "attestation document user_data is missing or not a 65-byte uncompressed SEC1 P-256 pubkey"
    )]
    InvalidControlPubkey,
    /// The doc's `user_data` field is missing or not the 32-byte
    /// SHA-256 hash of the chain link's `payload`. Returned by
    /// [`UnvalidatedAttestation::validate_chain_link`]: every chain link
    /// binds its `attestation.user_data` to `sha256(payload)`, so any
    /// mismatch means either the payload or the attestation has been
    /// swapped.
    #[error("attestation document user_data does not match sha256(payload)")]
    PayloadBindingMismatch,
    /// The doc's `user_data` field is missing or not exactly 32 bytes
    /// where a control nonce was expected. Returned by
    /// [`ValidatedAttestation::control_nonce`]: the in-enclave server's
    /// `RequestAttestation` reply always embeds the current 32-byte
    /// control nonce as `user_data`, so any other shape means the
    /// document was produced for a different purpose (or tampered with).
    #[error("attestation document user_data is not a 32-byte control nonce")]
    InvalidControlNonce,
    /// The document is genuine but its PCR0/1/2 equal NONE of the caller's
    /// expected triples. Returned by [`ValidatedAttestation::require_pcrs_in`]:
    /// the presenting enclave is not the identity the caller trusts.
    #[error("attestation document PCRs match none of the expected values")]
    PcrsNotExpected,
    /// The document's PCR map is not a valid pin identity (a missing
    /// PCR0-2, a value that is not 48 bytes, or an index of 32 or more).
    /// See [`crate::pin_identity`].
    #[error("attestation document PCRs are not a valid pin identity: {0}")]
    InvalidIdentity(#[from] PinIdentityError),
    /// The caller asked to skip the certificate chain, but this build has no
    /// skip-chain validation (its `dangerous-skip-chain` feature is off).
    /// The document is refused, never validated some other way.
    #[error("skipping the attestation certificate chain is not compiled into this build")]
    SkipChainNotCompiled,
}

impl AttestationError {
    /// The classified cause of this rejection.
    pub fn reason(&self) -> RejectionReason {
        match self {
            AttestationError::Validation(f) => f.reason,
            AttestationError::InvalidPcrLength { .. }
            | AttestationError::InvalidPcrHex(_)
            | AttestationError::InvalidControlPubkey
            | AttestationError::InvalidControlNonce
            | AttestationError::InvalidIdentity(_) => RejectionReason::Malformed,
            AttestationError::PayloadBindingMismatch => RejectionReason::PayloadBindingMismatch,
            AttestationError::PcrsNotExpected => RejectionReason::PcrMismatch,
            AttestationError::SkipChainNotCompiled => RejectionReason::UntrustedChain,
        }
    }

    fn validation(reason: RejectionReason, detail: impl Into<String>) -> Self {
        AttestationError::Validation(ValidationFailure::new(reason, detail))
    }
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

/// An attestation document received from outside this process, not yet
/// validated. It exposes no contents; validate it in the context it was
/// received in to read anything.
///
/// ```compile_fail,E0599
/// // An unvalidated document has no accessors.
/// let doc = enclavia_protocol::attestation::UnvalidatedAttestation::from_bytes(vec![]);
/// let _ = doc.identity();
/// ```
#[cfg_attr(
    not(feature = "dangerous-skip-chain"),
    doc = "Without the `dangerous-skip-chain` feature the chain cannot be skipped:",
    doc = "",
    doc = "```compile_fail,E0599",
    doc = "let doc = enclavia_protocol::attestation::UnvalidatedAttestation::from_bytes(vec![]);",
    doc = "let _ = doc.validate_session_skip_chain(&[]);",
    doc = "```"
)]
#[derive(Clone)]
pub struct UnvalidatedAttestation {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for UnvalidatedAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnvalidatedAttestation")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl UnvalidatedAttestation {
    /// Wrap document bytes received from a peer, a stored chain link or any
    /// other channel. Nothing is decoded until a `validate_*` method runs.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The raw bytes, for storing or forwarding. Not a way to read the
    /// document: decoding them yourself skips every check this type exists
    /// to enforce.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The raw bytes, for storing or forwarding (see [`Self::as_bytes`]).
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Validate a document presented on a live Noise session.
    ///
    /// Checks, in order:
    ///
    /// 1. COSE_Sign1 decode and structure; the AWS Nitro CA chain at the
    ///    document's own `timestamp`; the COSE signature under the leaf.
    /// 2. The document's `timestamp` is within
    ///    [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] of the verifier's clock.
    /// 3. `nonce == handshake_hash`: the document was produced for THIS
    ///    session, so a capture from any other session is refused.
    /// 4. The PCR map is a valid pin identity (see
    ///    [`crate::pin_identity`]).
    pub fn validate_session(
        &self,
        handshake_hash: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        validate_session_with(
            &self.bytes,
            handshake_hash,
            Chain::Verify,
            &SessionCtx::system(),
        )
    }

    /// Validate a chain link's document against the link's `payload`.
    ///
    /// Checks, in order:
    ///
    /// 1. COSE_Sign1 decode and structure; the AWS Nitro CA chain at the
    ///    document's own `timestamp`; the COSE signature under the leaf.
    ///    A chain link is a stored record that is verified again long after
    ///    it was produced, while a Nitro leaf certificate is valid for only
    ///    a few hours, so the verifier's clock is not consulted. What this
    ///    establishes is "genuine Nitro hardware attested this payload at
    ///    `timestamp`", which is the claim a chain link makes.
    /// 2. `user_data == sha256(payload)`: the binding that makes a chain
    ///    entry tamper-evident.
    /// 3. The PCR map is a valid pin identity.
    ///
    /// The `nonce` is not checked: a chain link is not produced in a Noise
    /// session, so there is nothing to bind it to.
    pub fn validate_chain_link(
        &self,
        payload: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        validate_chain_link_with(
            &self.bytes,
            payload,
            Chain::Verify,
            crate::nitro_verify::AWS_NITRO_ROOT_CA_DER,
        )
    }

    /// [`Self::validate_session`] WITHOUT the certificate chain or the COSE
    /// signature: structure, clock-skew bound, nonce and pin identity only.
    /// Any well-formed document passes, including one forged by the host. For QEMU's self-signing NSM and test fixtures only.
    #[cfg(any(test, feature = "dangerous-skip-chain"))]
    pub fn validate_session_skip_chain(
        &self,
        handshake_hash: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        validate_session_with(
            &self.bytes,
            handshake_hash,
            Chain::Skip,
            &SessionCtx::system(),
        )
    }

    /// [`Self::validate_chain_link`] WITHOUT the certificate chain or the
    /// COSE signature: structure, payload binding and pin identity only.
    /// Any well-formed document passes. For QEMU's self-signing NSM and
    /// test fixtures only.
    #[cfg(any(test, feature = "dangerous-skip-chain"))]
    pub fn validate_chain_link_skip_chain(
        &self,
        payload: &[u8],
    ) -> Result<ValidatedAttestation, AttestationError> {
        validate_chain_link_with(
            &self.bytes,
            payload,
            Chain::Skip,
            crate::nitro_verify::AWS_NITRO_ROOT_CA_DER,
        )
    }
}

/// Where a [`ValidatedAttestation`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Requested from this process's own `/dev/nsm`
    /// ([`ValidatedAttestation::request_local`]).
    Local,
    /// Received on a Noise session
    /// ([`UnvalidatedAttestation::validate_session`]).
    Session {
        /// `false` when validated with the skip-chain method.
        chain_verified: bool,
    },
    /// A chain link's document
    /// ([`UnvalidatedAttestation::validate_chain_link`]).
    ChainLink {
        /// `false` when validated with the skip-chain method.
        chain_verified: bool,
    },
}

/// An attestation document whose authenticity has been established: it
/// passed validation in a named context, or it came from this process's own
/// `/dev/nsm`. The only type with accessors for a document's contents.
///
/// There is no public constructor, no conversion from bytes and no
/// deserialisation:
///
/// ```compile_fail,E0451
/// // The fields are private, so it cannot be assembled by hand.
/// let _ = enclavia_protocol::attestation::ValidatedAttestation { bytes: vec![] };
/// ```
///
/// ```compile_fail,E0277
/// // No conversion from bytes.
/// let _: enclavia_protocol::attestation::ValidatedAttestation = vec![0u8].into();
/// ```
///
/// ```compile_fail,E0277
/// // No deserialisation.
/// fn decode<T: serde::de::DeserializeOwned>() {}
/// decode::<enclavia_protocol::attestation::ValidatedAttestation>();
/// ```
///
/// ```compile_fail,E0599
/// // No default value.
/// let _ = enclavia_protocol::attestation::ValidatedAttestation::default();
/// ```
#[derive(Clone)]
pub struct ValidatedAttestation {
    bytes: Vec<u8>,
    identity: PinIdentity,
    timestamp_ms: u64,
    user_data: Option<Vec<u8>>,
    provenance: Provenance,
}

impl std::fmt::Debug for ValidatedAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedAttestation")
            .field("provenance", &self.provenance)
            .field("identity", &self.identity)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl ValidatedAttestation {
    /// Request a document from this process's OWN `/dev/nsm`. BLOCKING (the
    /// driver is a blocking ioctl): call it from a blocking context, or
    /// through `spawn_blocking` from async code.
    ///
    /// The result is trusted without a chain check: the local NSM device is
    /// the hardware module measuring this very enclave (or, under QEMU's
    /// nitro-enclave machine, the emulated module measuring the same), so
    /// the caller is reading its own measurements, not authenticating a
    /// remote party. This is the only way to wrap NSM output in a
    /// [`ValidatedAttestation`].
    #[cfg(feature = "nsm")]
    pub fn request_local(
        nonce: Option<&[u8]>,
        user_data: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Self, LocalAttestationError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let fd = nsm_init();
        if fd < 0 {
            return Err(LocalAttestationError::Device(
                "nsm_init failed (is /dev/nsm present?)".into(),
            ));
        }
        let request = Request::Attestation {
            user_data: user_data.map(|b| b.to_vec().into()),
            nonce: nonce.map(|b| b.to_vec().into()),
            public_key: public_key.map(|b| b.to_vec().into()),
        };
        let response = nsm_process_request(fd, request);
        nsm_exit(fd);
        let bytes = match response {
            Response::Attestation { document } => document,
            Response::Error(e) => {
                return Err(LocalAttestationError::Device(format!(
                    "NSM attestation error: {e:?}"
                )));
            }
            other => {
                return Err(LocalAttestationError::Device(format!(
                    "unexpected NSM response: {other:?}"
                )));
            }
        };
        let doc = decode_only(&bytes).map_err(LocalAttestationError::Document)?;
        Self::from_doc(bytes, doc, Provenance::Local).map_err(LocalAttestationError::Document)
    }

    fn from_doc(
        bytes: Vec<u8>,
        doc: AttestationDoc,
        provenance: Provenance,
    ) -> Result<Self, AttestationError> {
        let identity = PinIdentity::from_doc_pcrs(&doc.pcrs)?;
        Ok(Self {
            bytes,
            identity,
            timestamp_ms: doc.timestamp,
            user_data: doc.user_data.map(|b| b.into_vec()),
            provenance,
        })
    }

    /// Where this document came from.
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// The document's pin identity: PCR0-2 and user PCRs 16-31, read by the
    /// rules in [`crate::pin_identity`].
    pub fn identity(&self) -> &PinIdentity {
        &self.identity
    }

    /// The document's image PCRs (PCR0-2).
    pub fn pcrs(&self) -> Pcrs {
        self.identity.image_pcrs()
    }

    /// The NSM `timestamp`, in milliseconds since the Unix epoch. The Nitro
    /// hypervisor stamps it; on a [`Provenance::Local`] document neither the
    /// parent instance nor the enclave's own clock can move it, so it is a
    /// trusted "now". On a remote document it is the instant the chain was
    /// validated at, not a statement about the present.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The document's `user_data`, if any.
    pub fn user_data(&self) -> Option<&[u8]> {
        self.user_data.as_deref()
    }

    /// The raw document bytes, for sending or storing.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The raw document bytes, for sending or storing.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// `user_data` read as an ECDSA P-256 control pubkey: exactly
    /// [`CONTROL_PUBKEY_LEN`] bytes in uncompressed SEC1 form (`0x04`
    /// prefix). An enclave announces its control pubkey this way on a
    /// synchronizer session, and a mesh node its mesh pubkey.
    pub fn control_pubkey(&self) -> Result<[u8; CONTROL_PUBKEY_LEN], AttestationError> {
        let key: [u8; CONTROL_PUBKEY_LEN] = self
            .user_data()
            .ok_or(AttestationError::InvalidControlPubkey)?
            .try_into()
            .map_err(|_| AttestationError::InvalidControlPubkey)?;
        // The compressed forms (0x02 / 0x03) are refused so no verifier has
        // to handle point decompression.
        if key[0] != 0x04 {
            return Err(AttestationError::InvalidControlPubkey);
        }
        Ok(key)
    }

    /// `user_data` read as the in-enclave server's 32-byte control nonce,
    /// which its `RequestAttestation` reply carries. A backend that verifies
    /// the reply before dispatching a signed control command learns both
    /// that the session ends in the expected enclave and that the nonce it
    /// signs was minted there.
    pub fn control_nonce(&self) -> Result<[u8; 32], AttestationError> {
        self.user_data()
            .ok_or(AttestationError::InvalidControlNonce)?
            .try_into()
            .map_err(|_| AttestationError::InvalidControlNonce)
    }

    /// Policy: the document's PCR0-2 equal `expected`.
    pub fn require_pcrs(&self, expected: &Pcrs) -> Result<(), AttestationError> {
        if self.pcrs() != *expected {
            return Err(AttestationError::validation(
                RejectionReason::PcrMismatch,
                "attestation document PCR0-2 differ from the expected values",
            ));
        }
        Ok(())
    }

    /// Policy: the document's PCR0-2 equal one of `expected`; returns the
    /// matching triple. An empty `expected` admits nothing. User PCRs are
    /// not compared, for anchors that are PCR0-2 triples (the synchronizer's
    /// measured configs, `enclavia reproduce`).
    pub fn require_pcrs_in(&self, expected: &[Pcrs]) -> Result<Pcrs, AttestationError> {
        let pcrs = self.pcrs();
        if !expected.contains(&pcrs) {
            return Err(AttestationError::PcrsNotExpected);
        }
        Ok(pcrs)
    }

    /// Policy: the document carries exactly `expected`, user PCRs 16-31
    /// included (absent ones read as zero).
    pub fn require_identity(&self, expected: &PinIdentity) -> Result<(), AttestationError> {
        self.require_pcrs(&expected.image_pcrs())?;
        if self.identity != *expected {
            return Err(AttestationError::validation(
                RejectionReason::PcrMismatch,
                "attestation document user PCRs (16-31) differ from the expected identity",
            ));
        }
        Ok(())
    }
}

/// Errors from [`ValidatedAttestation::request_local`].
#[cfg(feature = "nsm")]
#[derive(Debug, thiserror::Error)]
pub enum LocalAttestationError {
    /// The `/dev/nsm` driver failed to initialise or answered with an
    /// error.
    #[error("/dev/nsm: {0}")]
    Device(String),
    /// The device returned a document that does not decode, or whose PCR
    /// map is not a valid pin identity.
    #[error("own NSM attestation document: {0}")]
    Document(AttestationError),
}

/// Largest accepted distance between a session document's signed
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

/// Whether a validation checks the certificate chain. `Skip` exists only in
/// builds that have the skip-chain methods.
#[derive(Clone, Copy)]
enum Chain {
    Verify,
    #[cfg(any(test, feature = "dangerous-skip-chain"))]
    Skip,
}

/// Verification context for a session document: the trust anchor and the
/// verifier's clock. Production uses [`SessionCtx::system`]; the unit tests
/// substitute a test CA and a chosen "now".
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

/// The session context. With [`Chain::Verify`] the chain is validated at
/// the document's own `timestamp`, and the verifier's clock enters only as
/// the [`MAX_SESSION_DOC_CLOCK_SKEW_MS`] bound. `Chain::Skip` skips only the
/// chain and the signature; the bound still applies, since QEMU's emulated
/// NSM stamps the host's wall clock (whole seconds).
fn validate_session_with(
    bytes: &[u8],
    handshake_hash: &[u8],
    chain: Chain,
    ctx: &SessionCtx<'_>,
) -> Result<ValidatedAttestation, AttestationError> {
    let (doc, chain_verified) = match chain {
        Chain::Verify => (
            crate::nitro_verify::validate_at_doc_timestamp(bytes, ctx.root_der)
                .map_err(AttestationError::Validation)?,
            true,
        ),
        #[cfg(any(test, feature = "dangerous-skip-chain"))]
        Chain::Skip => (decode_only(bytes)?, false),
    };
    let skew = doc.timestamp.abs_diff(ctx.now_ms);
    if skew > MAX_SESSION_DOC_CLOCK_SKEW_MS {
        return Err(AttestationError::validation(
            RejectionReason::ClockSkew,
            format!(
                "document timestamp {} ms is {skew} ms from the local clock {} ms \
                 (limit {MAX_SESSION_DOC_CLOCK_SKEW_MS} ms)",
                doc.timestamp, ctx.now_ms
            ),
        ));
    }

    check_nonce(&doc, handshake_hash)?;
    ValidatedAttestation::from_doc(bytes.to_vec(), doc, Provenance::Session { chain_verified })
}

/// The chain-link context. The chain is validated at the document's own
/// `timestamp`; the local clock is not consulted.
fn validate_chain_link_with(
    bytes: &[u8],
    payload: &[u8],
    chain: Chain,
    root_der: &[u8],
) -> Result<ValidatedAttestation, AttestationError> {
    let (doc, chain_verified) = match chain {
        Chain::Verify => (
            crate::nitro_verify::validate_at_doc_timestamp(bytes, root_der)
                .map_err(AttestationError::Validation)?,
            true,
        ),
        #[cfg(any(test, feature = "dangerous-skip-chain"))]
        Chain::Skip => (decode_only(bytes)?, false),
    };

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or(AttestationError::PayloadBindingMismatch)?;
    let expected: [u8; 32] = Sha256::digest(payload).into();
    if user_data.as_slice() != expected {
        return Err(AttestationError::PayloadBindingMismatch);
    }

    ValidatedAttestation::from_doc(
        bytes.to_vec(),
        doc,
        Provenance::ChainLink { chain_verified },
    )
}

/// Structural decode only: COSE_Sign1 and document structure, nothing
/// authenticated.
#[cfg(any(test, feature = "dangerous-skip-chain", feature = "nsm"))]
fn decode_only(bytes: &[u8]) -> Result<AttestationDoc, AttestationError> {
    let (_, doc) = attestation_doc_validation::attestation_doc::decode_attestation_document(bytes)
        .map_err(|e| AttestationError::validation(RejectionReason::Malformed, e.to_string()))?;
    Ok(doc)
}

fn check_nonce(doc: &AttestationDoc, handshake_hash: &[u8]) -> Result<(), AttestationError> {
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(handshake_hash);
    validate_expected_nonce(doc, &nonce_b64)
        .map_err(|e| AttestationError::validation(RejectionReason::NonceMismatch, e.to_string()))
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

    /// The pin identity a [`FakeAttestation::with_seed`] /
    /// [`FakeChainAttestation::for_payload`] document with no user PCRs
    /// carries: PCR0-2 = `seed`, `seed + 1`, `seed + 2`, user PCRs zero.
    pub fn identity_from_seed(seed: u8) -> crate::pin_identity::PinIdentity {
        crate::pin_identity::PinIdentity::new(
            [
                [seed; 48],
                [seed.wrapping_add(1); 48],
                [seed.wrapping_add(2); 48],
            ],
            crate::pin_identity::ZERO_USER_PCRS,
        )
    }

    /// Builder for synthetic attestation documents accepted by
    /// [`UnvalidatedAttestation::validate_session_skip_chain`](super::UnvalidatedAttestation::validate_session_skip_chain).
    ///
    /// Without the chain check the COSE signature is not validated, so any
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
        /// into the doc's `user_data` field — [`super::ValidatedAttestation::control_pubkey`]
        /// requires this to be a 65-byte pubkey with the SEC1 prefix
        /// `0x04`.
        pub control_pubkey: [u8; super::CONTROL_PUBKEY_LEN],
        /// Extra PCRs to put in the document, by index (normally user PCRs
        /// 16-31, see [`crate::pin_identity`]). Empty by default: an enclave
        /// that locked no user PCR, as the emulated NSM reports it.
        pub user_pcrs: BTreeMap<usize, Vec<u8>>,
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
                user_pcrs: BTreeMap::new(),
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

        /// Put `value` in PCR `index` of the document (a locked user PCR).
        pub fn with_user_pcr(mut self, index: usize, value: Vec<u8>) -> Self {
            self.user_pcrs.insert(index, value);
            self
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// skip-chain session validation.
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
            pcrs.extend(self.user_pcrs.clone());

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                now_ms(),
                pcrs,
                // certificate / cabundle: not validated without the chain check,
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
    /// [`UnvalidatedAttestation::validate_session_skip_chain`](super::UnvalidatedAttestation::validate_session_skip_chain)
    /// and read by [`ValidatedAttestation::control_nonce`](super::ValidatedAttestation::control_nonce). Mirrors the in-enclave server's
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
        /// skip-chain session validation.
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
    /// by [`UnvalidatedAttestation::validate_chain_link_skip_chain`](super::UnvalidatedAttestation::validate_chain_link_skip_chain).
    /// Differs from [`FakeAttestation`] in two ways:
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
        /// Extra PCRs to put in the document, by index (normally user PCRs
        /// 16-31). Empty by default: an enclave that locked no user PCR.
        pub user_pcrs: BTreeMap<usize, Vec<u8>>,
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
                user_pcrs: BTreeMap::new(),
            }
        }

        /// Put `value` in PCR `index` of the document (a locked user PCR).
        pub fn with_user_pcr(mut self, index: usize, value: Vec<u8>) -> Self {
            self.user_pcrs.insert(index, value);
            self
        }

        /// CBOR-encoded COSE_Sign1 bytes ready to pass through the
        /// skip-chain chain-link validation.
        pub fn encode(&self) -> Vec<u8> {
            assert_eq!(self.pcr0.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr1.len(), 48, "test PCRs must be 48 bytes (SHA-384)");
            assert_eq!(self.pcr2.len(), 48, "test PCRs must be 48 bytes (SHA-384)");

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, self.pcr0.clone());
            pcrs.insert(1usize, self.pcr1.clone());
            pcrs.insert(2usize, self.pcr2.clone());
            pcrs.insert(8usize, vec![0u8; 48]);
            pcrs.extend(self.user_pcrs.clone());

            let doc = AttestationDoc::new(
                "test-module".to_string(),
                Digest::SHA384,
                now_ms(),
                pcrs,
                vec![0u8; 64],
                vec![vec![0u8; 64]],
                Some(self.user_data.clone()),
                // Nonce is not consulted by `validate_chain_link`,
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

    fn hh() -> Vec<u8> {
        // 32-byte BLAKE2s-shaped handshake hash for tests.
        (0u8..32).collect()
    }

    /// Every test document comes from the `test-utils` builders, which carry
    /// placeholder signatures, so only the skip-chain methods accept them.
    fn session(bytes: Vec<u8>, hh: &[u8]) -> Result<ValidatedAttestation, AttestationError> {
        UnvalidatedAttestation::from_bytes(bytes).validate_session_skip_chain(hh)
    }

    fn chain_link(bytes: Vec<u8>, payload: &[u8]) -> Result<ValidatedAttestation, AttestationError> {
        UnvalidatedAttestation::from_bytes(bytes).validate_chain_link_skip_chain(payload)
    }

    /// The expected-PCR triple matching `FakeAttestation::with_seed(seed)`.
    fn seed_pcrs(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    /// A COSE_Sign1 around a document with PCR0-2 from `seed`, PCR8, and the
    /// given `user_data` / `nonce`, for shapes the builders do not produce.
    fn doc_with(seed: u8, user_data: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> Vec<u8> {
        doc_at(seed, test_utils::now_ms(), user_data, nonce)
    }

    fn doc_at(
        seed: u8,
        timestamp_ms: u64,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
    ) -> Vec<u8> {
        use aws_nitro_enclaves_nsm_api::api::Digest as NsmDigest;
        use ciborium::value::Value as CborValue;
        use std::collections::BTreeMap;

        let pcrs = seed_pcrs(seed);
        let mut map = BTreeMap::new();
        map.insert(0usize, pcrs.pcr0);
        map.insert(1usize, pcrs.pcr1);
        map.insert(2usize, pcrs.pcr2);
        map.insert(8usize, vec![0u8; 48]);
        let doc = AttestationDoc::new(
            "test-module".to_string(),
            NsmDigest::SHA384,
            timestamp_ms,
            map,
            vec![0u8; 64],
            vec![vec![0u8; 64]],
            user_data,
            nonce,
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
    }

    #[test]
    fn session_doc_yields_identity_and_control_pubkey() {
        let fake = test_utils::FakeAttestation::with_seed(0x11, hh());
        let bytes = fake.encode();
        let doc = session(bytes.clone(), &hh()).expect("validate");

        assert_eq!(doc.identity().image()[0].as_slice(), fake.pcr0.as_slice());
        assert_eq!(doc.identity().image()[1].as_slice(), fake.pcr1.as_slice());
        assert_eq!(doc.identity().image()[2].as_slice(), fake.pcr2.as_slice());
        assert_eq!(doc.pcrs(), seed_pcrs(0x11));
        assert_eq!(doc.control_pubkey().unwrap(), fake.control_pubkey);
        assert_eq!(doc.user_data(), Some(fake.control_pubkey.as_slice()));
        assert!(doc.timestamp_ms().abs_diff(test_utils::now_ms()) < 60_000);
        assert_eq!(doc.raw_bytes(), bytes.as_slice());
        assert_eq!(
            doc.provenance(),
            Provenance::Session {
                chain_verified: false
            }
        );
    }

    /// The session binding: a document produced for one handshake hash is
    /// refused on any other session.
    #[test]
    fn session_doc_with_wrong_handshake_hash_fails() {
        let doc = test_utils::FakeAttestation::with_seed(0x44, hh()).encode();
        let err = session(doc, &[0xab; 32]).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::NonceMismatch, "{err:?}");
    }

    /// Skipping the chain does not skip the clock-skew bound: a session
    /// document stamped further than the bound from the verifier's clock is
    /// refused. A chain link's document has no such bound (old links are
    /// legitimate).
    #[test]
    fn skip_chain_session_still_bounds_clock_skew() {
        let now = test_utils::now_ms();
        let margin = 60 * 60 * 1000;
        let pubkey = Some(test_utils::FakeAttestation::with_seed(0x45, hh()).control_pubkey.to_vec());
        session(doc_at(0x45, now, pubkey.clone(), Some(hh())), &hh()).expect("current timestamp");
        for stale in [
            now - MAX_SESSION_DOC_CLOCK_SKEW_MS - margin,
            now + MAX_SESSION_DOC_CLOCK_SKEW_MS + margin,
        ] {
            let err = session(doc_at(0x45, stale, pubkey.clone(), Some(hh())), &hh()).unwrap_err();
            assert_eq!(err.reason(), RejectionReason::ClockSkew, "{err:?}");
        }
        let payload = b"payload";
        let binding = Some(Sha256::digest(payload).to_vec());
        chain_link(doc_at(0x45, 0, binding, Some(vec![0; 32])), payload)
            .expect("a chain link is not bounded by the local clock");
    }

    /// A chain link's document is not a session document: its nonce is not
    /// the session's handshake hash.
    #[test]
    fn chain_link_doc_is_not_a_session_doc() {
        let link = test_utils::FakeChainAttestation::for_payload(0x12, b"payload").encode();
        let err = session(link, &hh()).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::NonceMismatch, "{err:?}");
    }

    /// And a session document is not a chain link's: its `user_data` is not
    /// the hash of any payload it is presented with.
    #[test]
    fn session_doc_is_not_a_chain_link_doc() {
        let doc = test_utils::FakeAttestation::with_seed(0x13, hh()).encode();
        let err = chain_link(doc, b"payload").unwrap_err();
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "{err:?}"
        );
    }

    #[test]
    fn control_nonce_reads_32_byte_user_data() {
        let nonce = [0xab; 32];
        let fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), nonce);
        let doc = session(fake.encode(), &hh()).expect("validate");
        doc.require_pcrs(&seed_pcrs(0x21)).expect("pcrs");
        assert_eq!(doc.control_nonce().unwrap(), nonce);
    }

    #[test]
    fn control_nonce_rejects_non_32_byte_user_data() {
        let mut fake = test_utils::FakeControlNonceAttestation::with_seed(0x21, hh(), [0xab; 32]);
        fake.control_nonce = vec![0xab; 16];
        let doc = session(fake.encode(), &hh()).expect("validate");
        assert!(matches!(
            doc.control_nonce(),
            Err(AttestationError::InvalidControlNonce)
        ));
    }

    #[test]
    fn control_pubkey_rejects_missing_or_wrong_size_user_data() {
        for user_data in [None, Some(vec![0u8; 16])] {
            let doc = session(doc_with(0x22, user_data.clone(), Some(hh())), &hh())
                .expect("validate");
            assert!(
                matches!(
                    doc.control_pubkey(),
                    Err(AttestationError::InvalidControlPubkey)
                ),
                "user_data = {user_data:?}"
            );
        }
    }

    #[test]
    fn control_pubkey_rejects_compressed_prefix() {
        let mut key = vec![0x02u8];
        key.extend_from_slice(&[0x55; 64]);
        let doc = session(doc_with(0x23, Some(key), Some(hh())), &hh()).expect("validate");
        assert!(matches!(
            doc.control_pubkey(),
            Err(AttestationError::InvalidControlPubkey)
        ));
    }

    /// The server side of the customer protocol carries no control pubkey,
    /// so a session document may omit `user_data`.
    #[test]
    fn session_doc_without_user_data_validates() {
        let doc = session(doc_with(0x68, None, Some(hh())), &hh()).expect("validate");
        assert_eq!(doc.user_data(), None);
        assert_eq!(
            doc.require_pcrs_in(&[seed_pcrs(0x68)]).unwrap(),
            seed_pcrs(0x68)
        );
    }

    #[test]
    fn require_pcrs_in_admits_any_listed_triple_and_nothing_else() {
        let doc = session(
            test_utils::FakeAttestation::with_seed(0x66, hh()).encode(),
            &hh(),
        )
        .expect("validate");
        assert_eq!(
            doc.require_pcrs_in(&[seed_pcrs(0x01), seed_pcrs(0x66)])
                .unwrap(),
            seed_pcrs(0x66)
        );
        assert!(matches!(
            doc.require_pcrs_in(&[seed_pcrs(0x99)]),
            Err(AttestationError::PcrsNotExpected)
        ));
        assert!(matches!(
            doc.require_pcrs_in(&[]),
            Err(AttestationError::PcrsNotExpected)
        ));
    }

    #[test]
    fn require_pcrs_checks_every_image_pcr() {
        let doc = session(
            test_utils::FakeAttestation::with_seed(0x33, hh()).encode(),
            &hh(),
        )
        .expect("validate");
        doc.require_pcrs(&seed_pcrs(0x33)).expect("match");
        for idx in 0..3 {
            let mut wrong = seed_pcrs(0x33);
            [&mut wrong.pcr0, &mut wrong.pcr1, &mut wrong.pcr2][idx][0] ^= 0xff;
            let err = doc.require_pcrs(&wrong).unwrap_err();
            assert_eq!(err.reason(), RejectionReason::PcrMismatch, "PCR{idx}");
        }
    }

    /// Two documents with the same PCR0-2 but a different locked PCR16 are
    /// two identities, so two synchronizer keys.
    #[test]
    fn identity_includes_user_pcrs() {
        let plain = test_utils::FakeAttestation::with_seed(0x21, hh());
        let a =
            test_utils::FakeAttestation::with_seed(0x21, hh()).with_user_pcr(16, vec![0xa1; 48]);
        let b =
            test_utils::FakeAttestation::with_seed(0x21, hh()).with_user_pcr(16, vec![0xb2; 48]);

        let plain = session(plain.encode(), &hh()).expect("plain").identity().clone();
        let a = session(a.encode(), &hh()).expect("a").identity().clone();
        let b = session(b.encode(), &hh()).expect("b").identity().clone();

        assert_eq!(a.image_pcrs(), b.image_pcrs());
        assert_eq!(a.pcr(16), Some(&[0xa1; 48]));
        assert_eq!(
            plain.pcr(16),
            Some(&[0u8; 48]),
            "absent user PCR reads as zero"
        );
        assert_ne!(a.key(), b.key());
        assert_ne!(a.key(), plain.key());
    }

    /// A user PCR of the wrong length makes the document malformed.
    #[test]
    fn short_user_pcr_is_malformed() {
        let fake =
            test_utils::FakeAttestation::with_seed(0x22, hh()).with_user_pcr(17, vec![1; 47]);
        let err = session(fake.encode(), &hh()).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::Malformed, "{err:?}");
    }

    /// `require_identity` compares the user PCRs too.
    #[test]
    fn require_identity_checks_user_pcrs() {
        let payload = b"payload";
        let bytes = test_utils::FakeChainAttestation::for_payload(0x30, payload)
            .with_user_pcr(16, vec![0x16; 48])
            .encode();
        let image = seed_pcrs(0x30);
        let mut user = crate::pin_identity::ZERO_USER_PCRS;
        user[0] = [0x16; 48];
        let right = PinIdentity::from_image_pcrs(&image, user).unwrap();
        let wrong = right.with_user_pcrs(crate::pin_identity::ZERO_USER_PCRS);

        let doc = chain_link(bytes, payload).expect("validate");
        doc.require_pcrs(&image).expect("image match");
        assert_eq!(*doc.identity(), right);
        doc.require_identity(&right).expect("full match");
        let err = doc.require_identity(&wrong).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::PcrMismatch);
    }

    #[test]
    fn chain_link_doc_validates_against_its_payload() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x33, &payload);
        let doc = chain_link(fake.encode(), &payload).expect("valid chain attestation");
        doc.require_pcrs(&seed_pcrs(0x33)).expect("pcrs");
        assert_eq!(
            doc.provenance(),
            Provenance::ChainLink {
                chain_verified: false
            }
        );
    }

    /// The payload binding: the same document presented with any other
    /// payload is refused.
    #[test]
    fn chain_link_doc_with_mismatched_payload_fails() {
        let payload = b"chain-link-payload-canary".to_vec();
        let fake = test_utils::FakeChainAttestation::for_payload(0x44, &payload);
        let err = chain_link(fake.encode(), b"DIFFERENT").unwrap_err();
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
        assert_eq!(err.reason(), RejectionReason::PayloadBindingMismatch);
    }

    #[test]
    fn chain_link_doc_without_user_data_fails() {
        let err = chain_link(doc_with(0x77, None, Some(vec![0u8; 32])), b"any-payload")
            .unwrap_err();
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "expected PayloadBindingMismatch, got {err:?}"
        );
    }

    #[test]
    fn garbage_is_malformed_in_both_contexts() {
        let err = session(b"not a cose document".to_vec(), &hh()).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::Malformed);
        let err = chain_link(b"not a cose document".to_vec(), b"p").unwrap_err();
        assert_eq!(err.reason(), RejectionReason::Malformed);
    }

    /// Without a chain check, every document is refused by the production
    /// methods: the fixtures' placeholder certificates do not parse, let
    /// alone chain to the AWS Nitro root.
    #[test]
    fn production_methods_refuse_unsigned_fixtures() {
        let doc = UnvalidatedAttestation::from_bytes(
            test_utils::FakeAttestation::with_seed(0x21, hh()).encode(),
        );
        assert!(doc.validate_session(&hh()).is_err());
        let payload = b"payload";
        let link = UnvalidatedAttestation::from_bytes(
            test_utils::FakeChainAttestation::for_payload(0x21, payload).encode(),
        );
        assert!(link.validate_chain_link(payload).is_err());
    }

    /// Labels are unique and `ALL` lists every reason once.
    #[test]
    fn rejection_reason_labels_are_unique() {
        let labels: std::collections::BTreeSet<&str> =
            RejectionReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), RejectionReason::ALL.len());
        assert_eq!(RejectionReason::NotYetValid.to_string(), "not_yet_valid");
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
    use attestation_doc_validation::attestation_doc::decode_attestation_document;
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
        let mut control_pubkey = vec![0x04u8];
        control_pubkey.extend_from_slice(&[0x55; 64]);
        doc_payload_with(timestamp_ms, nonce, control_pubkey)
    }

    fn doc_payload_with(timestamp_ms: u64, nonce: &[u8], user_data: Vec<u8>) -> Vec<u8> {
        let pcrs = seed_pcrs(0x31);
        let mut map = BTreeMap::new();
        map.insert(0usize, pcrs.pcr0);
        map.insert(1usize, pcrs.pcr1);
        map.insert(2usize, pcrs.pcr2);
        map.insert(8usize, vec![0u8; 48]);
        let doc = AttestationDoc::new(
            "i-test-enc0123456789abcdef".to_string(),
            NsmDigest::SHA384,
            timestamp_ms,
            map,
            der(LEAF_HEX),
            // Nitro order: root first, then intermediates.
            vec![der(ROOT_HEX), der(INTERMEDIATE_HEX)],
            Some(user_data),
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

    /// A chain link's document from the test chain: `user_data` is
    /// `sha256(payload)`.
    fn link_doc(timestamp_ms: u64, payload: &[u8]) -> Vec<u8> {
        let user_data = Sha256::digest(payload).to_vec();
        sign(
            &doc_payload_with(timestamp_ms, &[0u8; 32], user_data),
            &TestSigner::leaf(),
        )
    }

    /// `validate_session` against the test CA, with the verifier's clock at
    /// `now_ms`.
    fn verify(
        doc: &[u8],
        nonce: &[u8],
        now_ms: u64,
    ) -> Result<ValidatedAttestation, AttestationError> {
        let root = der(ROOT_HEX);
        let ctx = SessionCtx {
            root_der: &root,
            now_ms,
        };
        validate_session_with(doc, nonce, Chain::Verify, &ctx)
    }

    /// `validate_chain_link` against the test CA.
    fn verify_link(doc: &[u8], payload: &[u8]) -> Result<ValidatedAttestation, AttestationError> {
        validate_chain_link_with(doc, payload, Chain::Verify, &der(ROOT_HEX))
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
        assert_eq!(got.timestamp_ms(), doc_ts);
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
            assert_eq!(err.reason(), RejectionReason::ClockSkew);
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
        assert_eq!(err.reason(), RejectionReason::Expired);
    }

    #[test]
    fn doc_timestamp_before_leaf_validity_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS - 1_000;
        let doc = signed_doc(doc_ts, &hh());
        let err = verify(&doc, &hh(), doc_ts).unwrap_err();
        assert!(err.to_string().contains("CertNotValidYet"), "{err}");
        assert_eq!(err.reason(), RejectionReason::NotYetValid);
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
        assert_eq!(err.reason(), RejectionReason::Signature);
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
        assert_eq!(err.reason(), RejectionReason::Signature);
    }

    #[test]
    fn doc_signed_by_key_other_than_leaf_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = sign(&doc_payload(doc_ts, &hh()), &TestSigner::other());
        let err = verify(&doc, &hh(), doc_ts).unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
        assert_eq!(err.reason(), RejectionReason::Signature);
    }

    #[test]
    fn nonce_mismatch_fails() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = signed_doc(doc_ts, &hh());
        let wrong: Vec<u8> = vec![0xab; 32];
        let err = verify(&doc, &wrong, doc_ts).unwrap_err();
        assert!(err.to_string().contains("Nonce"), "{err}");
        assert_eq!(err.reason(), RejectionReason::NonceMismatch);
    }

    #[test]
    fn chain_not_rooted_in_the_aws_nitro_root_fails() {
        // The public methods use the embedded AWS root, which the test chain
        // does not lead to.
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let doc = UnvalidatedAttestation::from_bytes(signed_doc(doc_ts, &hh()));
        let err = doc.validate_session(&hh()).unwrap_err();
        assert!(
            err.to_string().contains("certificate chain invalid"),
            "{err}"
        );
        assert_eq!(err.reason(), RejectionReason::UntrustedChain);
        let link = UnvalidatedAttestation::from_bytes(link_doc(doc_ts, b"payload"));
        let err = link.validate_chain_link(b"payload").unwrap_err();
        assert_eq!(err.reason(), RejectionReason::UntrustedChain);
    }

    #[test]
    fn verified_session_doc_reports_its_contents() {
        let doc_ts = LEAF_NOT_BEFORE_MS + 5_000;
        let got = verify(&signed_doc(doc_ts, &hh()), &hh(), doc_ts).expect("verify");
        assert_eq!(got.timestamp_ms(), doc_ts);
        assert_eq!(got.pcrs(), seed_pcrs(0x31));
        assert_eq!(got.control_pubkey().unwrap()[1..], [0x55; 64]);
        assert_eq!(
            got.provenance(),
            Provenance::Session {
                chain_verified: true
            }
        );
    }

    #[test]
    fn stored_doc_validates_at_its_own_timestamp_regardless_of_local_clock() {
        // The chain-link context never reads the local clock: the test
        // leaf's validity window does not contain the real current time, yet
        // the document verifies at its own timestamp.
        let doc_ts = LEAF_NOT_BEFORE_MS + 60 * 60 * 1000;
        let got = verify_link(&link_doc(doc_ts, b"payload"), b"payload")
            .expect("stored doc must verify at its own timestamp");
        assert_eq!(got.timestamp_ms(), doc_ts);
        assert_eq!(
            got.provenance(),
            Provenance::ChainLink {
                chain_verified: true
            }
        );
    }

    #[test]
    fn stored_doc_with_other_payload_fails_binding() {
        let doc = link_doc(LEAF_NOT_BEFORE_MS + 5_000, b"payload");
        let err = verify_link(&doc, b"other payload").unwrap_err();
        assert!(
            matches!(err, AttestationError::PayloadBindingMismatch),
            "{err:?}"
        );
    }

    #[test]
    fn stored_doc_expired_at_its_own_timestamp_fails() {
        let doc = link_doc(LEAF_NOT_AFTER_MS + 1_000, b"payload");
        let err = verify_link(&doc, b"payload").unwrap_err();
        assert!(err.to_string().contains("CertExpired"), "{err}");
        assert_eq!(err.reason(), RejectionReason::Expired);
    }

    #[test]
    fn stored_doc_with_moved_timestamp_fails_signature() {
        let genuine = link_doc(LEAF_NOT_AFTER_MS + 1_000, b"payload");
        let user_data = Sha256::digest(b"payload").to_vec();
        let tampered = replace_payload(
            &genuine,
            doc_payload_with(LEAF_NOT_BEFORE_MS, &[0u8; 32], user_data),
        );
        let err = verify_link(&tampered, b"payload").unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
        assert_eq!(err.reason(), RejectionReason::Signature);
    }

    #[test]
    fn garbage_is_malformed_in_production_mode() {
        let err = verify_link(b"not cose", b"payload").unwrap_err();
        assert_eq!(err.reason(), RejectionReason::Malformed);
        let err = verify(b"not cose", &hh(), LEAF_NOT_BEFORE_MS).unwrap_err();
        assert_eq!(err.reason(), RejectionReason::Malformed);
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
