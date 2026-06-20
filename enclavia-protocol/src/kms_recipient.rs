//! KMS phase 2 (#198): the `CiphertextForRecipient` envelope.
//!
//! When a Nitro enclave calls `kms:Decrypt` with a `Recipient` parameter,
//! KMS does NOT return the plaintext on the wire. Instead it returns
//! `CiphertextForRecipient`: a CMS (RFC 5652) `EnvelopedData` structure in
//! which the plaintext is encrypted under a fresh symmetric content key,
//! and that content key is RSA-OAEP-wrapped to the **ephemeral public key
//! the enclave embedded in its attestation document**. Only the enclave
//! (which holds the matching ephemeral private key inside the VM) can
//! unwrap it, so the parent that proxies the KMS call sees only ciphertext.
//!
//! AWS uses, for the Nitro recipient envelope:
//!   * key encryption: RSAES-OAEP with SHA-256 (algorithm
//!     `RSAES_OAEP_SHA_256`, the only `KeyEncryptionAlgorithm` Nitro
//!     accepts), and
//!   * content encryption: AES-256-CBC with PKCS#7 padding.
//!
//! This module is the matched pair:
//!   * [`decode`] — the ENCLAVE side (`enclavia-crypto`): parse the
//!     EnvelopedData KMS returned and recover the plaintext with the
//!     ephemeral private key. This is the production-critical path.
//!   * [`encode`] — the MOCK-KMS side: produce the same envelope for the
//!     QEMU end-to-end test, so the in-enclave Recipient code path is
//!     exercised exactly as it is against real KMS.
//!
//! The [`tests`] round-trip (`encode` then `decode`) is the deterministic
//! correctness gate for the OAEP + AES-CBC + DER layering, independent of
//! any enclave boot.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{
    EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
    RecipientInfos,
};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use spki::AlgorithmIdentifierOwned;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// OIDs (RFC 5652 / PKCS#1 / NIST).
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

/// Errors from building or opening a recipient envelope.
#[derive(Debug, thiserror::Error)]
pub enum RecipientError {
    #[error("DER encode/decode: {0}")]
    Der(String),
    #[error("RSA: {0}")]
    Rsa(String),
    #[error("AES-CBC: {0}")]
    Aes(String),
    #[error("malformed envelope: {0}")]
    Malformed(String),
}

/// Wrap `plaintext` as a `CiphertextForRecipient` CMS `EnvelopedData`
/// encrypted to `recipient` (the enclave's ephemeral RSA public key). Used
/// by mock-kms (and the round-trip test); real KMS produces the same shape.
pub fn encode(recipient: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, RecipientError> {
    let mut rng = rand::rngs::OsRng;

    // Fresh content-encryption key + IV.
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    {
        use rand::RngCore;
        rng.fill_bytes(&mut cek);
        rng.fill_bytes(&mut iv);
    }

    // AES-256-CBC encrypt the plaintext (PKCS#7 padding).
    let encrypted_content = Aes256CbcEnc::new(&cek.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // RSA-OAEP-SHA256 wrap the CEK to the recipient's ephemeral key.
    let encrypted_key = recipient
        .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), &cek)
        .map_err(|e| RecipientError::Rsa(e.to_string()))?;

    // KeyTransRecipientInfo. The recipient id is irrelevant to the enclave
    // (it holds exactly one ephemeral key), so use an empty
    // SubjectKeyIdentifier rather than a synthetic cert.
    let ktri = KeyTransRecipientInfo {
        version: cms::content_info::CmsVersion::V0,
        rid: RecipientIdentifier::SubjectKeyIdentifier(x509_cert::ext::pkix::SubjectKeyIdentifier(
            OctetString::new(Vec::new()).map_err(|e| RecipientError::Der(e.to_string()))?,
        )),
        key_enc_alg: AlgorithmIdentifierOwned {
            oid: RSAES_OAEP,
            // OAEP params are omitted; both ends fix SHA-256 (the only
            // algorithm Nitro's RSAES_OAEP_SHA_256 uses).
            parameters: None,
        },
        enc_key: OctetString::new(encrypted_key).map_err(|e| RecipientError::Der(e.to_string()))?,
    };

    let mut recip_infos = SetOfVec::new();
    recip_infos
        .insert(RecipientInfo::Ktri(ktri))
        .map_err(|e| RecipientError::Der(e.to_string()))?;

    let enc_content_info = EncryptedContentInfo {
        content_type: ID_DATA,
        content_enc_alg: AlgorithmIdentifierOwned {
            oid: AES_256_CBC,
            parameters: Some(
                Any::new(der::Tag::OctetString, iv.as_slice())
                    .map_err(|e| RecipientError::Der(e.to_string()))?,
            ),
        },
        encrypted_content: Some(
            OctetString::new(encrypted_content).map_err(|e| RecipientError::Der(e.to_string()))?,
        ),
    };

    let enveloped = EnvelopedData {
        version: cms::content_info::CmsVersion::V0,
        originator_info: None,
        recip_infos: RecipientInfos(recip_infos),
        encrypted_content: enc_content_info,
        unprotected_attrs: None,
    };

    let content_info = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::encode_from(&enveloped).map_err(|e| RecipientError::Der(e.to_string()))?,
    };
    content_info
        .to_der()
        .map_err(|e| RecipientError::Der(e.to_string()))
}

/// Open a `CiphertextForRecipient` CMS `EnvelopedData` with the enclave's
/// ephemeral private key and recover the plaintext. The ENCLAVE side.
pub fn decode(ephemeral: &RsaPrivateKey, cms_der: &[u8]) -> Result<Vec<u8>, RecipientError> {
    let content_info =
        ContentInfo::from_der(cms_der).map_err(|e| RecipientError::Der(e.to_string()))?;
    if content_info.content_type != ID_ENVELOPED_DATA {
        return Err(RecipientError::Malformed(format!(
            "content type {} is not id-envelopedData",
            content_info.content_type
        )));
    }
    let enveloped: EnvelopedData = content_info
        .content
        .decode_as()
        .map_err(|e| RecipientError::Der(e.to_string()))?;

    // Single recipient (the enclave's ephemeral key).
    let ktri = enveloped
        .recip_infos
        .0
        .as_slice()
        .iter()
        .find_map(|ri| match ri {
            RecipientInfo::Ktri(k) => Some(k),
            _ => None,
        })
        .ok_or_else(|| RecipientError::Malformed("no KeyTransRecipientInfo".into()))?;
    if ktri.key_enc_alg.oid != RSAES_OAEP {
        return Err(RecipientError::Malformed(format!(
            "key encryption alg {} is not RSAES-OAEP",
            ktri.key_enc_alg.oid
        )));
    }

    // Unwrap the content key with RSA-OAEP-SHA256.
    let cek = ephemeral
        .decrypt(Oaep::new::<sha2::Sha256>(), ktri.enc_key.as_bytes())
        .map_err(|e| RecipientError::Rsa(e.to_string()))?;
    if cek.len() != 32 {
        return Err(RecipientError::Malformed(format!(
            "content key is {} bytes, expected 32",
            cek.len()
        )));
    }

    let eci = &enveloped.encrypted_content;
    if eci.content_enc_alg.oid != AES_256_CBC {
        return Err(RecipientError::Malformed(format!(
            "content encryption alg {} is not AES-256-CBC",
            eci.content_enc_alg.oid
        )));
    }
    // IV is the algorithm parameter (OCTET STRING).
    let iv_any = eci
        .content_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(|| RecipientError::Malformed("AES-CBC algorithm has no IV parameter".into()))?;
    let iv = iv_any
        .decode_as::<OctetString>()
        .map_err(|e| RecipientError::Der(e.to_string()))?;
    let iv = iv.as_bytes();
    if iv.len() != 16 {
        return Err(RecipientError::Malformed(format!(
            "IV is {} bytes, expected 16",
            iv.len()
        )));
    }

    let ciphertext = eci
        .encrypted_content
        .as_ref()
        .ok_or_else(|| RecipientError::Malformed("no encrypted content".into()))?
        .as_bytes();

    let plaintext = Aes256CbcDec::new(cek.as_slice().into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| RecipientError::Aes(e.to_string()))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};

    fn ephemeral_key() -> RsaPrivateKey {
        // A fixed test key (generation is slow); any RSA-2048 key works.
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("keygen")
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let priv_key = ephemeral_key();
        let pub_key = RsaPublicKey::from(&priv_key);
        let secret = b"a 32-byte LUKS passphrase-here!!"; // 32 bytes
        assert_eq!(secret.len(), 32);

        let envelope = encode(&pub_key, secret).expect("encode");
        // It is a real DER CMS structure, not the bare plaintext.
        assert!(envelope.len() > secret.len() + 200);
        assert_ne!(&envelope, secret);

        let recovered = decode(&priv_key, &envelope).expect("decode");
        assert_eq!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let pub_key = RsaPublicKey::from(&ephemeral_key());
        let envelope = encode(&pub_key, b"0123456789abcdef0123456789abcdef").expect("encode");
        // A different private key cannot unwrap the content key.
        let other = ephemeral_key();
        assert!(decode(&other, &envelope).is_err());
    }

    #[test]
    fn key_serialisation_round_trips_through_pkcs8() {
        // The enclave generates the ephemeral key, ships its public half in
        // the attestation doc, and keeps the private half; make sure a
        // PKCS#8 round-trip (how it is carried) preserves decryptability.
        let priv_key = ephemeral_key();
        let der = priv_key.to_pkcs8_der().unwrap();
        let restored = RsaPrivateKey::from_pkcs8_der(der.as_bytes()).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let env = encode(&pub_key, b"0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            decode(&restored, &env).unwrap().as_slice(),
            b"0123456789abcdef0123456789abcdef".as_slice()
        );
    }
}
