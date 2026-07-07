//! Attestation-gated KMS decrypt: the `CiphertextForRecipient` envelope.
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

fn ber_err(m: impl std::fmt::Display) -> RecipientError {
    RecipientError::Malformed(format!("BER->DER transcode: {m}"))
}

/// Transcode a (possibly BER, indefinite-length) ASN.1 blob to strict DER.
///
/// AWS KMS encodes the `CiphertextForRecipient` CMS with indefinite-length
/// constructed encodings (BER), and may chunk OCTET STRINGs into constructed
/// form. RustCrypto's `der` only accepts definite-length DER. This rewrites
/// every TLV with a definite length and collapses constructed OCTET STRINGs
/// into primitive ones, yielding bytes `ContentInfo::from_der` accepts. It is
/// idempotent on input that is already strict DER. Fail-closed: any structural
/// surprise returns an error (worst case recovery just fails, as it does now).
fn ber_to_der(input: &[u8]) -> Result<Vec<u8>, RecipientError> {
    let (out, rest) = transcode_tlv(input)?;
    if !rest.is_empty() {
        return Err(ber_err(format!("{} trailing bytes", rest.len())));
    }
    Ok(out)
}

/// Transcode one TLV; returns (definite-length DER bytes, remaining input).
fn transcode_tlv(input: &[u8]) -> Result<(Vec<u8>, &[u8]), RecipientError> {
    let id = *input.first().ok_or_else(|| ber_err("unexpected end of input"))?;
    if id & 0x1f == 0x1f {
        return Err(ber_err("high-tag-number form unsupported"));
    }
    let constructed = id & 0x20 != 0;
    let (len, after_len) = read_len(&input[1..])?;

    if !constructed {
        let len = len.ok_or_else(|| ber_err("indefinite length on primitive"))?;
        if after_len.len() < len {
            return Err(ber_err("truncated primitive content"));
        }
        return Ok((emit_der(id, &after_len[..len]), &after_len[len..]));
    }

    // Constructed: transcode every child first, then decide how to re-emit
    // this node. Two cases collapse a chunked string into a single PRIMITIVE
    // OCTET STRING (strict DER rejects the constructed form with "not
    // canonically encoded as DER"):
    //   * a universal constructed OCTET STRING (tag 0x24), and
    //   * an IMPLICIT-tagged OCTET STRING carried under a context-specific
    //     constructed tag that KMS chunked, e.g. EncryptedContentInfo's
    //     `encryptedContent [0] IMPLICIT OCTET STRING` -> tag 0xA0 holding 0x04
    //     segments. We detect this by the children all being OCTET STRINGs and
    //     re-emit with the constructed bit cleared (0xA0 -> 0x80), preserving
    //     the tag number/class.
    // Any other constructed tag (SEQUENCE, SET, an EXPLICIT [0] wrapper, ...)
    // keeps its children's full TLVs unchanged.
    let mut children: Vec<Vec<u8>> = Vec::new();
    let after: &[u8];
    match len {
        Some(len) => {
            if after_len.len() < len {
                return Err(ber_err("truncated constructed content"));
            }
            let mut region = &after_len[..len];
            after = &after_len[len..];
            while !region.is_empty() {
                let (child, rest) = transcode_tlv(region)?;
                children.push(child);
                region = rest;
            }
        }
        None => {
            // Indefinite length: children run until the end-of-contents (00 00).
            let mut region = after_len;
            loop {
                if region.len() >= 2 && region[0] == 0x00 && region[1] == 0x00 {
                    region = &region[2..];
                    break;
                }
                let (child, rest) = transcode_tlv(region)?;
                children.push(child);
                region = rest;
            }
            after = region;
        }
    }

    let is_universal_octet = id == 0x24;
    let is_context = id & 0xc0 == 0x80; // context-specific class
    let context_octet = is_context
        && !children.is_empty()
        && children.iter().all(|c| c.first() == Some(&0x04));
    if is_universal_octet || context_octet {
        let mut body = Vec::new();
        for child in &children {
            body.extend_from_slice(&octet_value(child)?);
        }
        let out_id = if is_universal_octet { 0x04 } else { id & !0x20 };
        return Ok((emit_der(out_id, &body), after));
    }

    let mut body = Vec::new();
    for child in &children {
        body.extend_from_slice(child);
    }
    Ok((emit_der(id, &body), after))
}

/// Read an ASN.1 length. `None` = indefinite (0x80). Returns the content slice.
fn read_len(input: &[u8]) -> Result<(Option<usize>, &[u8]), RecipientError> {
    let b = *input.first().ok_or_else(|| ber_err("truncated length"))?;
    let rest = &input[1..];
    if b == 0x80 {
        return Ok((None, rest));
    }
    if b & 0x80 == 0 {
        return Ok((Some(b as usize), rest));
    }
    let n = (b & 0x7f) as usize;
    if n == 0 || n > 4 || rest.len() < n {
        return Err(ber_err("bad long-form length"));
    }
    let mut len = 0usize;
    for &x in &rest[..n] {
        len = (len << 8) | x as usize;
    }
    Ok((Some(len), &rest[n..]))
}

/// Emit a DER TLV with the definite-length encoding of `content`.
fn emit_der(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let lb = &be[start..];
        out.push(0x80 | lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.extend_from_slice(content);
    out
}

/// Extract the value bytes of a transcoded primitive OCTET STRING TLV.
fn octet_value(der: &[u8]) -> Result<Vec<u8>, RecipientError> {
    if der.first() != Some(&0x04) {
        return Err(ber_err("constructed OCTET STRING child is not an OCTET STRING"));
    }
    let (len, content) = read_len(&der[1..])?;
    let len = len.ok_or_else(|| ber_err("indefinite OCTET STRING child"))?;
    content
        .get(..len)
        .map(|s| s.to_vec())
        .ok_or_else(|| ber_err("truncated OCTET STRING child"))
}

/// Open a `CiphertextForRecipient` CMS `EnvelopedData` with the enclave's
/// ephemeral private key and recover the plaintext. The ENCLAVE side.
pub fn decode(ephemeral: &RsaPrivateKey, cms_der: &[u8]) -> Result<Vec<u8>, RecipientError> {
    // AWS KMS emits the CiphertextForRecipient CMS using indefinite-length
    // (BER) constructed encodings, which RustCrypto's `der` (strict DER) rejects
    // with "indefinite length disallowed". Transcode to definite-length DER
    // first. Idempotent for input that is already strict DER (e.g. our own
    // `encode` / mock-kms), so it is safe to apply unconditionally.
    let der = ber_to_der(cms_der)?;
    let content_info =
        ContentInfo::from_der(&der).map_err(|e| RecipientError::Der(e.to_string()))?;
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
    fn ber_to_der_normalises_indefinite_length_and_constructed_octet_strings() {
        // Strict DER passes through unchanged (idempotent) -- SEQUENCE { INTEGER 1 }.
        let der = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(ber_to_der(&der).unwrap(), der);

        // Indefinite-length SEQUENCE { INTEGER 1 } -> definite-length.
        let ber_indef = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber_indef).unwrap(), der);

        // Constructed OCTET STRING (0x24), indefinite, chunked "ab"+"cd"
        // collapses to one primitive OCTET STRING 04 04 61 62 63 64.
        let want = [0x04, 0x04, 0x61, 0x62, 0x63, 0x64];
        let ber_octet_indef = [
            0x24, 0x80, 0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64, 0x00, 0x00,
        ];
        assert_eq!(ber_to_der(&ber_octet_indef).unwrap(), want);

        // Same in definite-length constructed form.
        let ber_octet_def = [0x24, 0x08, 0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64];
        assert_eq!(ber_to_der(&ber_octet_def).unwrap(), want);

        // Nested indefinite SEQUENCE { SEQUENCE { INTEGER 1 } } -> definite.
        let ber_nested = [0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00];
        let der_nested = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(ber_to_der(&ber_nested).unwrap(), der_nested);

        // IMPLICIT-tagged, chunked OCTET STRING under a context-specific
        // constructed tag [0] (0xA0), indefinite, "ab"+"cd" -> a single
        // PRIMITIVE context [0] (0x80) 80 04 61 62 63 64. This is exactly how
        // KMS chunks EncryptedContentInfo.encryptedContent.
        let want_ctx = [0x80, 0x04, 0x61, 0x62, 0x63, 0x64];
        let ber_ctx_indef = [
            0xA0, 0x80, 0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64, 0x00, 0x00,
        ];
        assert_eq!(ber_to_der(&ber_ctx_indef).unwrap(), want_ctx);
        // Definite-length form of the same.
        let ber_ctx_def = [0xA0, 0x08, 0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64];
        assert_eq!(ber_to_der(&ber_ctx_def).unwrap(), want_ctx);

        // An EXPLICIT [0] wrapper (single SEQUENCE child, not an OCTET STRING)
        // must STAY constructed -- this is ContentInfo.content.
        let ber_explicit = [0xA0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00];
        let der_explicit = [0xA0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(ber_to_der(&ber_explicit).unwrap(), der_explicit);

        // And a real CMS envelope (already DER) survives the transcode intact.
        let priv_key = ephemeral_key();
        let pub_key = RsaPublicKey::from(&priv_key);
        let env = encode(&pub_key, b"a 32-byte LUKS passphrase-here!!").expect("encode");
        assert_eq!(ber_to_der(&env).unwrap(), env);
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn real_kms_envelope_transcodes_and_parses() {
        // A genuine `CiphertextForRecipient` captured from real AWS KMS
        // (kms:Decrypt with a Nitro Recipient) on the production storage path.
        // It is indefinite-length BER throughout (note the leading 30 80 and
        // the trailing run of 00 00 EOC pairs) AND chunks the encrypted content
        // into a constructed context-specific [0] OCTET STRING -- the exact
        // shape that made strict DER fail with first "indefinite length
        // disallowed" then "CONTEXT-SPECIFIC [0] (constructed) not canonically
        // encoded as DER". After the transcode it must parse cleanly.
        let envelope = hex(concat!(
            "308006092a864886f70d010703a08030800201023182016b30820167020102802000d8032ce4",
            "b06d81bf38c4fc3ff1200706deb6678591c9b7ad900825840fa7eb303c06092a864886f70d01",
            "0107302fa00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d",
            "06096086480165030402010500048201008c0955736cd2c8f2b5e39bd13c1d3d0b8d0b6c3b16",
            "d29ba3e02bd072d7a54ea43d1b736a609654e3642de874a54f75f78c4abc1f131d87a4e92f36",
            "c6b54c325371bbbd47ea1b3c141ca7c3c6f68d075469a23ee0e5e780783f858e8db11a019d25",
            "0c81a3ec03d9171e86e6ecf3189aaa653e22e09cab0869bd08e9d5c007069d38da2a73c3c481",
            "f19e9b33bcc3dee46fc8ccbbba297fc7a8fc1257875342ba9694173c43ae60602429fe81292b",
            "d9faf46a54c5cf0ba83a7dcfa71f218c27c088d913b9f709c039348e46ea669e33dc6f0d0224",
            "dcd52874774db1c0e8a5574f7a397500aaef0ac23395597b372c959f336297eb93734b3f951e",
            "5b062adba12320308006092a864886f70d010701301d060960864801650304012a04104df038",
            "d3456a8cba065420e8a0ef0278a0800430df06bc5b3e8ba95b06220d48057835b6bc42e1fa30",
            "8530422b618a9839f12a0e27f6b1a667f14c7255d6f84d88e2300e00000000000000000000",
        ));

        let der = ber_to_der(&envelope).expect("transcode real KMS envelope");
        // Idempotent on its own output (it is now strict DER).
        assert_eq!(ber_to_der(&der).unwrap(), der);

        let ci = ContentInfo::from_der(&der).expect("parse transcoded ContentInfo");
        assert_eq!(ci.content_type, ID_ENVELOPED_DATA);
        let ed: EnvelopedData = ci.content.decode_as().expect("decode EnvelopedData");

        let ktri = ed
            .recip_infos
            .0
            .as_slice()
            .iter()
            .find_map(|ri| match ri {
                RecipientInfo::Ktri(k) => Some(k),
                _ => None,
            })
            .expect("a KeyTransRecipientInfo");
        assert_eq!(ktri.key_enc_alg.oid, RSAES_OAEP);
        // RSA-2048 OAEP-wrapped CEK is 256 bytes.
        assert_eq!(ktri.enc_key.as_bytes().len(), 256);

        let eci = &ed.encrypted_content;
        assert_eq!(eci.content_enc_alg.oid, AES_256_CBC);
        let iv = eci
            .content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .decode_as::<OctetString>()
            .unwrap();
        assert_eq!(iv.as_bytes().len(), 16);
        // The chunked [0] OCTET STRING collapsed to a single primitive blob.
        assert!(eci.encrypted_content.as_ref().unwrap().as_bytes().len() >= 16);
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
