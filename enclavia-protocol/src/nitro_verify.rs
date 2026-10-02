//! Production verification of a Nitro attestation document, with the
//! certificate chain checked at the document's OWN signed timestamp.
//!
//! This is the same validation `attestation-doc-validation`'s
//! `validate_and_parse_attestation_doc` performs (COSE_Sign1 decode and
//! structure checks, AWS Nitro CA chain through webpki with the same
//! signature-algorithm set, COSE signature under the leaf key), except for
//! the instant the chain is validated at. Upstream always uses the
//! verifier's wall clock and exposes no way to supply a time, hence this
//! module.
//!
//! ## Why the document timestamp is a sound validation instant
//!
//! The NSM `timestamp` field (milliseconds since the Unix epoch) lives inside
//! the COSE_Sign1 payload, which the leaf key signs. The chain is validated
//! at that instant and then the COSE signature is verified with the leaf
//! key, so a document is accepted only if:
//!
//! 1. the leaf chains to the AWS Nitro root and every certificate in the
//!    path is within its validity window at `timestamp`, and
//! 2. the leaf key signed the payload that carries that `timestamp`.
//!
//! Moving `timestamp` breaks (2); picking a `timestamp` outside the leaf's
//! window breaks (1). What this instant does NOT prove is that the document
//! is recent: freshness must come from elsewhere (the Noise handshake-hash
//! nonce on session-bound paths, see `attestation.rs`). The verifier's clock
//! is therefore not an input to the chain check at all, and a verifier
//! whose clock drifts no longer rejects a certificate the NSM minted
//! seconds ago as "not yet valid".

use attestation_doc_validation::attestation_doc::{
    decode_attestation_document, validate_cose_signature,
};
use aws_nitro_enclaves_cose::crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPublicKey};
use aws_nitro_enclaves_cose::error::CoseError;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use der::Decode;
use p384::ecdsa::signature::hazmat::PrehashVerifier;

use crate::attestation::{RejectionReason, ValidationFailure};

/// The AWS Nitro Enclaves root certificate (`CN=aws.nitro-enclaves`), DER.
/// Byte-identical to the PEM embedded in `attestation-doc-validation`.
/// SHA-256 fingerprint, as published by AWS:
/// `641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B`
/// (asserted by a unit test below).
pub(crate) static AWS_NITRO_ROOT_CA_DER: &[u8] = &[
    0x30, 0x82, 0x02, 0x11, 0x30, 0x82, 0x01, 0x96, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00,
    0xf9, 0x31, 0x75, 0x68, 0x1b, 0x90, 0xaf, 0xe1, 0x1d, 0x46, 0xcc, 0xb4, 0xe4, 0xe7, 0xf8, 0x56,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x49, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x12, 0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74, 0x72, 0x6f, 0x2d, 0x65,
    0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x73, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32,
    0x38, 0x31, 0x33, 0x32, 0x38, 0x30, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x30, 0x32, 0x38,
    0x31, 0x34, 0x32, 0x38, 0x30, 0x35, 0x5a, 0x30, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
    0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74, 0x72, 0x6f, 0x2d, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76,
    0x65, 0x73, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xfc, 0x02, 0x54, 0xeb, 0xa6, 0x08,
    0xc1, 0xf3, 0x68, 0x70, 0xe2, 0x9a, 0xda, 0x90, 0xbe, 0x46, 0x38, 0x32, 0x92, 0x73, 0x6e, 0x89,
    0x4b, 0xff, 0xf6, 0x72, 0xd9, 0x89, 0x44, 0x4b, 0x50, 0x51, 0xe5, 0x34, 0xa4, 0xb1, 0xf6, 0xdb,
    0xe3, 0xc0, 0xbc, 0x58, 0x1a, 0x32, 0xb7, 0xb1, 0x76, 0x07, 0x0e, 0xde, 0x12, 0xd6, 0x9a, 0x3f,
    0xea, 0x21, 0x1b, 0x66, 0xe7, 0x52, 0xcf, 0x7d, 0xd1, 0xdd, 0x09, 0x5f, 0x6f, 0x13, 0x70, 0xf4,
    0x17, 0x08, 0x43, 0xd9, 0xdc, 0x10, 0x01, 0x21, 0xe4, 0xcf, 0x63, 0x01, 0x28, 0x09, 0x66, 0x44,
    0x87, 0xc9, 0x79, 0x62, 0x84, 0x30, 0x4d, 0xc5, 0x3f, 0xf4, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x90, 0x25, 0xb5, 0x0d, 0xd9, 0x05,
    0x47, 0xe7, 0x96, 0xc3, 0x96, 0xfa, 0x72, 0x9d, 0xcf, 0x99, 0xa9, 0xdf, 0x4b, 0x96, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02,
    0x31, 0x00, 0xa3, 0x7f, 0x2f, 0x91, 0xa1, 0xc9, 0xbd, 0x5e, 0xe7, 0xb8, 0x62, 0x7c, 0x16, 0x98,
    0xd2, 0x55, 0x03, 0x8e, 0x1f, 0x03, 0x43, 0xf9, 0x5b, 0x63, 0xa9, 0x62, 0x8c, 0x3d, 0x39, 0x80,
    0x95, 0x45, 0xa1, 0x1e, 0xbc, 0xbf, 0x2e, 0x3b, 0x55, 0xd8, 0xae, 0xee, 0x71, 0xb4, 0xc3, 0xd6,
    0xad, 0xf3, 0x02, 0x31, 0x00, 0xa2, 0xf3, 0x9b, 0x16, 0x05, 0xb2, 0x70, 0x28, 0xa5, 0xdd, 0x4b,
    0xa0, 0x69, 0xb5, 0x01, 0x6e, 0x65, 0xb4, 0xfb, 0xde, 0x8f, 0xe0, 0x06, 0x1d, 0x6a, 0x53, 0x19,
    0x7f, 0x9c, 0xda, 0xf5, 0xd9, 0x43, 0xbc, 0x61, 0xfc, 0x2b, 0xeb, 0x03, 0xcb, 0x6f, 0xee, 0x8d,
    0x23, 0x02, 0xf3, 0xdf, 0xf6,
];

/// Same set `attestation-doc-validation` passes to webpki, so the accepted
/// chains are unchanged apart from the validation instant.
static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// `id-ecPublicKey` (RFC 5480).
const OID_EC_PUBLIC_KEY: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp384r1` (RFC 5480).
const OID_SECP384R1: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Decode a COSE_Sign1 attestation document and verify it against
/// `root_der`, validating the certificate chain at the document's own
/// `timestamp`. Returns the decoded document on success. Production callers
/// pass [`AWS_NITRO_ROOT_CA_DER`]; only the unit tests pass a throwaway
/// test CA.
pub(crate) fn validate_at_doc_timestamp(
    attestation_data: &[u8],
    root_der: &[u8],
) -> Result<AttestationDoc, ValidationFailure> {
    // Decode + structure checks (module id, SHA384 digest, PCR/cabundle/
    // nonce/user_data bounds). No signature is checked yet, so nothing read
    // from `doc` is trusted until the COSE signature below verifies.
    let (cose, doc) = decode_attestation_document(attestation_data)
        .map_err(|e| ValidationFailure::new(RejectionReason::Malformed, e.to_string()))?;

    // Chain at the document's timestamp. Integer division floors to the
    // second, which never moves the instant after the true signing time.
    let at = webpki::Time::from_seconds_since_unix_epoch(doc.timestamp / 1000);
    let intermediates: Vec<&[u8]> = doc.cabundle.iter().map(|c| c.as_slice()).collect();
    let leaf = webpki::EndEntityCert::try_from(doc.certificate.as_slice()).map_err(|e| {
        ValidationFailure::new(
            RejectionReason::Malformed,
            format!("leaf certificate: {e:?}"),
        )
    })?;
    let anchor = [
        webpki::TrustAnchor::try_from_cert_der(root_der).map_err(|e| {
            ValidationFailure::new(
                RejectionReason::UntrustedChain,
                format!("trust anchor: {e:?}"),
            )
        })?,
    ];
    leaf.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &webpki::TlsServerTrustAnchors(&anchor),
        &intermediates,
        at,
    )
    .map_err(|e| {
        ValidationFailure::new(
            chain_rejection_reason(&e),
            format!(
                "certificate chain invalid at document timestamp {} ms: {e:?}",
                doc.timestamp
            ),
        )
    })?;

    // COSE signature under the (now chain-validated) leaf key. This is what
    // authenticates `timestamp`, and with it the instant used above.
    let key = LeafKey::from_cert_der(&doc.certificate)
        .map_err(|e| ValidationFailure::new(RejectionReason::Malformed, e))?;
    validate_cose_signature::<Sha2>(&key, &cose)
        .map_err(|e| ValidationFailure::new(RejectionReason::Signature, e.to_string()))?;

    Ok(doc)
}

/// Classify a webpki chain-validation error.
///
/// Only the leaf's own validity window surfaces as `CertNotValidYet` /
/// `CertExpired`: webpki tries each candidate issuer and reports a path that
/// fails further up (an expired intermediate included) as `UnknownIssuer`,
/// which lands in [`RejectionReason::UntrustedChain`].
fn chain_rejection_reason(e: &webpki::Error) -> RejectionReason {
    match e {
        webpki::Error::CertNotValidYet => RejectionReason::NotYetValid,
        webpki::Error::CertExpired => RejectionReason::Expired,
        webpki::Error::InvalidSignatureForPublicKey
        | webpki::Error::SignatureAlgorithmMismatch
        | webpki::Error::UnsupportedSignatureAlgorithm
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKey => RejectionReason::Signature,
        webpki::Error::BadDer | webpki::Error::BadDerTime => RejectionReason::Malformed,
        _ => RejectionReason::UntrustedChain,
    }
}

/// The leaf certificate's P-384 public key, as a COSE verifier. Nitro signs
/// attestation documents with ECDSA P-384 / SHA-384 (ES384) only, so any
/// other key type is rejected.
struct LeafKey(p384::ecdsa::VerifyingKey);

impl LeafKey {
    fn from_cert_der(cert_der: &[u8]) -> Result<Self, String> {
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|e| format!("leaf certificate decode: {e}"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
            return Err("leaf key is not an EC key".to_string());
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<spki::ObjectIdentifier>().ok());
        if curve != Some(OID_SECP384R1) {
            return Err("leaf key is not on P-384".to_string());
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| "leaf key bit string is not octet-aligned".to_string())?;
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| format!("leaf key: {e}"))?;
        Ok(Self(key))
    }
}

impl SigningPublicKey for LeafKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        // COSE ECDSA signatures are raw `r || s` (RFC 8152 section 8.1).
        let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
            return Ok(false);
        };
        Ok(self.0.verify_prehash(digest, &sig).is_ok())
    }
}

/// SHA-2 provider for the COSE `Sig_structure` digest.
pub(crate) struct Sha2;

impl Hash for Sha2 {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        use sha2::Digest as _;
        Ok(match digest {
            MessageDigest::Sha256 => sha2::Sha256::digest(data).to_vec(),
            MessageDigest::Sha384 => sha2::Sha384::digest(data).to_vec(),
            MessageDigest::Sha512 => sha2::Sha512::digest(data).to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_root_is_the_published_aws_nitro_root() {
        use sha2::Digest as _;
        let fp = hex::encode(sha2::Sha256::digest(AWS_NITRO_ROOT_CA_DER));
        assert_eq!(
            fp,
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
    }
}
