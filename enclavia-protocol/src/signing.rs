//! Control-key signatures: domain separation and canonical encoding.
//!
//! An upgradable enclave's control key (ECDSA P-256, held by the backend in
//! managed custody, by the owner's CLI in self-hosted custody) signs three
//! kinds of bytes:
//!
//! * [`SignedDomain::UpgradePayload`]: a CBOR [`crate::chain::UpgradePayload`],
//!   the authority for a PCR transition;
//! * [`SignedDomain::RevocationPayload`]: a CBOR
//!   [`crate::chain::RevocationPayload`], which cancels one upgrade;
//! * [`SignedDomain::ControlCommand`]: a CBOR [`crate::ControlCommand`], the
//!   envelope the enclave executes.
//!
//! ## Domain separation
//!
//! A signature never covers the bytes alone. It covers
//! `domain.context() || bytes`, where the context is a fixed,
//! NUL-terminated string per kind. A signature made for one kind therefore
//! never verifies as another, whatever the bytes would decode to, and the
//! unsigned `kind` label of a chain link cannot turn one into the other:
//! the verifier picks the context from the kind it is about to act on.
//!
//! The context is part of the signed message only. Payload bytes, their
//! hash ([`crate::chain::upgrade_link_hash`]) and the attestation binding
//! (`user_data = sha256(payload)`) are unchanged by it. Signers that hash
//! the message themselves (PIV hardware) hash the prefixed message.
//!
//! ## Canonical encoding
//!
//! Every signed or hashed CBOR value is decoded with [`decode_canonical`]:
//! the bytes must decode, and re-encoding the decoded value must give the
//! same bytes back. A value therefore has exactly one accepted encoding:
//! unknown fields, a different field order, non-minimal integers,
//! indefinite lengths, alternative spellings of a field and trailing bytes
//! are all refused. The signed payload types also reject unknown fields
//! while decoding.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::chain::ChainLinkKind;

/// What a control-key signature authorizes. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedDomain {
    /// A CBOR [`crate::chain::UpgradePayload`].
    UpgradePayload,
    /// A CBOR [`crate::chain::RevocationPayload`].
    RevocationPayload,
    /// A CBOR [`crate::ControlCommand`] envelope.
    ControlCommand,
}

impl SignedDomain {
    /// The context string prefixed to the signed bytes. Distinct per
    /// domain, none a prefix of another (each ends in NUL).
    pub const fn context(self) -> &'static [u8] {
        match self {
            SignedDomain::UpgradePayload => b"enclavia/upgrade-payload/v1\0",
            SignedDomain::RevocationPayload => b"enclavia/revocation-payload/v1\0",
            SignedDomain::ControlCommand => b"enclavia/control-command/v1\0",
        }
    }

    /// The domain of a signed chain link's payload: upgrade and revocation
    /// links carry control-key signatures, boot links carry none.
    pub const fn for_link(kind: ChainLinkKind) -> Option<Self> {
        match kind {
            ChainLinkKind::Upgrade => Some(SignedDomain::UpgradePayload),
            ChainLinkKind::Revocation => Some(SignedDomain::RevocationPayload),
            ChainLinkKind::Boot => None,
        }
    }
}

/// The message a control-key signature covers: `domain.context() || bytes`.
pub fn signed_message(domain: SignedDomain, bytes: &[u8]) -> Vec<u8> {
    let context = domain.context();
    let mut msg = Vec::with_capacity(context.len() + bytes.len());
    msg.extend_from_slice(context);
    msg.extend_from_slice(bytes);
    msg
}

/// Sign `bytes` in `domain` with a software key: the 64-byte raw low-S
/// `r || s` signature over [`signed_message`].
pub fn sign_control(signing_key: &SigningKey, domain: SignedDomain, bytes: &[u8]) -> [u8; 64] {
    let sig: Signature = signing_key.sign(&signed_message(domain, bytes));
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    out
}

/// Why a control-key signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlSignatureError {
    /// The signature is not 64 bytes of raw `r || s`.
    #[error("signature is not 64 bytes raw r||s P-256")]
    Shape,
    /// The signature does not verify over the domain-separated message.
    #[error("signature does not verify under the control key in this domain")]
    Invalid,
}

/// Verify a 64-byte raw `r || s` signature over `bytes` in `domain`.
pub fn verify_control_signature(
    verifying_key: &VerifyingKey,
    domain: SignedDomain,
    bytes: &[u8],
    signature: &[u8],
) -> Result<(), ControlSignatureError> {
    let sig = Signature::from_slice(signature).map_err(|_| ControlSignatureError::Shape)?;
    verifying_key
        .verify(&signed_message(domain, bytes), &sig)
        .map_err(|_| ControlSignatureError::Invalid)
}

/// Why bytes were refused by [`decode_canonical`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalDecodeError {
    /// The bytes do not decode as the type.
    #[error("not a valid encoding: {0}")]
    Decode(String),
    /// The bytes decode, but are not the type's own encoding of the
    /// decoded value (extra or reordered fields, non-minimal integers,
    /// trailing bytes, ...).
    #[error("not the canonical encoding of the decoded value")]
    NotCanonical,
}

/// Encode `value` as CBOR: the single encoding every signer and hasher
/// uses, and the one [`decode_canonical`] accepts.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// Decode CBOR `bytes` as `T`, accepting only the canonical encoding: the
/// bytes must equal [`encode`] of the decoded value.
pub fn decode_canonical<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, CanonicalDecodeError> {
    let value: T = ciborium::from_reader(bytes)
        .map_err(|e| CanonicalDecodeError::Decode(e.to_string()))?;
    if encode(&value) != bytes {
        return Err(CanonicalDecodeError::NotCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{RevocationPayload, UpgradePayload};
    use crate::pin_identity::{PinIdentity, ZERO_USER_PCRS};
    use chrono::{TimeZone, Utc};
    use ciborium::Value;
    use uuid::Uuid;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x17; 32].into()).unwrap()
    }

    fn revocation() -> RevocationPayload {
        RevocationPayload {
            enclave_id: Uuid::from_u128(0xe1),
            revokes: Uuid::from_u128(0x11),
            issued_at: Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap(),
            nonce: vec![0x42; 32],
            revokes_link: [0x45; 32],
        }
    }

    fn upgrade() -> UpgradePayload {
        UpgradePayload {
            enclave_id: Uuid::from_u128(0xe1),
            from: PinIdentity::new([[0xa0; 48], [0xa1; 48], [0xa2; 48]], ZERO_USER_PCRS),
            to: PinIdentity::new([[0xc0; 48], [0xc1; 48], [0xc2; 48]], ZERO_USER_PCRS),
            image_digest: "sha256:target".into(),
            valid_from: Utc.with_ymd_and_hms(2026, 10, 7, 12, 0, 0).unwrap(),
            valid_until: (Utc.with_ymd_and_hms(2026, 10, 7, 12, 0, 0).unwrap()) + chrono::Duration::days(7),
            issued_at: Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap(),
            nonce: vec![0x42; 32],
        }
    }

    fn map_of(v: &impl Serialize) -> Vec<(Value, Value)> {
        match Value::serialized(v).unwrap() {
            Value::Map(m) => m,
            other => panic!("not a map: {other:?}"),
        }
    }

    fn cbor(v: &impl Serialize) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    /// One CBOR map carrying the union of both payloads' fields (the shared
    /// ones agree). Before domain separation and strict decoding it decoded
    /// as both a `RevocationPayload` and an `UpgradePayload`, so one
    /// signature authorized both.
    fn polyglot() -> Vec<u8> {
        let mut map = map_of(&revocation());
        for (k, v) in map_of(&upgrade()) {
            if !map.iter().any(|(k2, _)| *k2 == k) {
                map.push((k, v));
            }
        }
        cbor(&Value::Map(map))
    }

    #[test]
    fn polyglot_map_decodes_as_neither_payload() {
        let bytes = polyglot();
        assert!(ciborium::from_reader::<RevocationPayload, _>(bytes.as_slice()).is_err());
        assert!(ciborium::from_reader::<UpgradePayload, _>(bytes.as_slice()).is_err());
        assert!(decode_canonical::<RevocationPayload>(&bytes).is_err());
        assert!(decode_canonical::<UpgradePayload>(&bytes).is_err());
    }

    #[test]
    fn a_signature_verifies_only_in_its_own_domain() {
        let sk = key();
        let vk = VerifyingKey::from(&sk);
        let bytes = encode(&revocation());
        let sig = sign_control(&sk, SignedDomain::RevocationPayload, &bytes);
        verify_control_signature(&vk, SignedDomain::RevocationPayload, &bytes, &sig).unwrap();
        for other in [SignedDomain::UpgradePayload, SignedDomain::ControlCommand] {
            assert_eq!(
                verify_control_signature(&vk, other, &bytes, &sig),
                Err(ControlSignatureError::Invalid)
            );
        }
        // A signature over the bare bytes (no context) verifies nowhere.
        let bare: Signature = sk.sign(&bytes);
        for domain in [
            SignedDomain::UpgradePayload,
            SignedDomain::RevocationPayload,
            SignedDomain::ControlCommand,
        ] {
            assert!(verify_control_signature(&vk, domain, &bytes, &bare.to_bytes()).is_err());
        }
        assert_eq!(
            verify_control_signature(&vk, SignedDomain::RevocationPayload, &bytes, &sig[..63]),
            Err(ControlSignatureError::Shape)
        );
    }

    #[test]
    fn contexts_are_distinct_and_prefix_free() {
        let all = [
            SignedDomain::UpgradePayload,
            SignedDomain::RevocationPayload,
            SignedDomain::ControlCommand,
        ];
        for a in all {
            assert_eq!(a.context().last(), Some(&0));
            assert_eq!(a.context().iter().filter(|b| **b == 0).count(), 1);
            for b in all {
                if a != b {
                    assert!(!a.context().starts_with(b.context()));
                }
            }
        }
        assert_eq!(
            SignedDomain::for_link(ChainLinkKind::Upgrade),
            Some(SignedDomain::UpgradePayload)
        );
        assert_eq!(
            SignedDomain::for_link(ChainLinkKind::Revocation),
            Some(SignedDomain::RevocationPayload)
        );
        assert_eq!(SignedDomain::for_link(ChainLinkKind::Boot), None);
    }

    #[test]
    fn canonical_round_trip() {
        let bytes = encode(&upgrade());
        let back: UpgradePayload = decode_canonical(&bytes).unwrap();
        assert_eq!(encode(&back), bytes);
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let canonical = encode(&revocation());

        // Trailing bytes.
        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert!(decode_canonical::<RevocationPayload>(&trailing).is_err());

        // Same fields, another order.
        let mut map = map_of(&revocation());
        map.reverse();
        let reordered = cbor(&Value::Map(map));
        assert_ne!(reordered, canonical);
        assert!(ciborium::from_reader::<RevocationPayload, _>(reordered.as_slice()).is_ok());
        assert_eq!(
            decode_canonical::<RevocationPayload>(&reordered).unwrap_err(),
            CanonicalDecodeError::NotCanonical
        );

        // An unknown field.
        let mut map = map_of(&revocation());
        map.push((Value::Text("extra".into()), Value::Bool(true)));
        assert!(decode_canonical::<RevocationPayload>(&cbor(&Value::Map(map))).is_err());

        // Another spelling of a timestamp that names the same instant.
        let mut map = map_of(&revocation());
        for (k, v) in map.iter_mut() {
            if *k == Value::Text("issued_at".into()) {
                *v = Value::Text("2026-09-30T12:00:00+00:00".into());
            }
        }
        let respelled = cbor(&Value::Map(map));
        let lenient: RevocationPayload = ciborium::from_reader(respelled.as_slice()).unwrap();
        assert_eq!(lenient.issued_at, revocation().issued_at);
        assert_eq!(
            decode_canonical::<RevocationPayload>(&respelled).unwrap_err(),
            CanonicalDecodeError::NotCanonical
        );
    }

    #[test]
    fn non_minimal_integer_is_refused() {
        #[derive(Serialize, serde::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        struct Small {
            n: u8,
        }
        let canonical = encode(&Small { n: 5 });
        assert_eq!(canonical, [0xa1, 0x61, b'n', 0x05]);
        // 5 encoded as a one-byte-argument integer (0x18 0x05).
        let long = [0xa1, 0x61, b'n', 0x18, 0x05];
        assert!(ciborium::from_reader::<Small, _>(&long[..]).is_ok());
        assert_eq!(
            decode_canonical::<Small>(&long).unwrap_err(),
            CanonicalDecodeError::NotCanonical
        );
    }
}
