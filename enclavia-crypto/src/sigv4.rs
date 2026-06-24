//! Minimal AWS Signature Version 4 signing for the in-enclave KMS client.
//!
//! Hand-rolled on `sha2` + `hmac` to keep the measured EIF free of the
//! `aws-smithy` SDK stack: this covers exactly what the KMS `POST` calls
//! need (one region, the `kms` service, a fixed small header set, body
//! hashing) and nothing else. The format-sensitive pieces (the canonical
//! request and the string-to-sign) are exposed and unit-tested byte-for-byte,
//! since those are where SigV4 implementations go wrong; the HMAC/SHA-256
//! primitives are trusted to the `hmac`/`sha2` crates.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINATOR: &str = "aws4_request";

/// AWS credentials used to sign a request.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present for temporary (instance-role / STS) credentials; signed as
    /// `x-amz-security-token`.
    pub session_token: Option<String>,
}

/// Headers the caller must add to the outgoing request for the signature
/// to validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub authorization: String,
    /// `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
    pub amz_date: String,
    /// `x-amz-security-token`, when the credentials are temporary.
    pub security_token: Option<String>,
}

/// One header to include in the signature. `name` MUST be lowercase.
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Sign a `POST /` request to `service` in `region`. `headers` are the
/// headers to sign (names lowercase); `host`, `x-amz-date`, and (when the
/// creds are temporary) `x-amz-security-token` are added by this function,
/// so the caller passes only the request-specific ones (e.g. `content-type`,
/// `x-amz-target`). `amz_date`/`date_stamp` are passed in (not read from the
/// clock) so the signature is deterministic and testable.
// SigV4 signing inherently takes the credentials, region, service, host,
// timestamp pair, header list, and payload; bundling them into a struct
// would add ceremony without making the single call site clearer.
#[allow(clippy::too_many_arguments)]
pub fn sign_post(
    creds: &Credentials,
    region: &str,
    service: &str,
    host: &str,
    amz_date: &str,
    date_stamp: &str,
    extra_headers: &[Header<'_>],
    payload: &[u8],
) -> SignedHeaders {
    // Assemble the full signed header set: caller's headers plus host,
    // x-amz-date, and (if temporary creds) x-amz-security-token.
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|h| (h.name.to_ascii_lowercase(), h.value.trim().to_string()))
        .collect();
    headers.push(("host".to_string(), host.to_string()));
    headers.push(("x-amz-date".to_string(), amz_date.to_string()));
    if let Some(tok) = &creds.session_token {
        headers.push(("x-amz-security-token".to_string(), tok.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical = canonical_request(&headers, payload);
    let signed_header_names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers = signed_header_names.join(";");

    let scope = format!("{date_stamp}/{region}/{service}/{TERMINATOR}");
    let to_sign = string_to_sign(amz_date, &scope, &canonical);

    let key = signing_key(&creds.secret_access_key, date_stamp, region, service);
    let signature = hex(&hmac(&key, to_sign.as_bytes()));

    let authorization = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    SignedHeaders {
        authorization,
        amz_date: amz_date.to_string(),
        security_token: creds.session_token.clone(),
    }
}

/// Build the SigV4 canonical request for a `POST /` (no query string).
/// `headers` must already be lowercased, trimmed, and sorted by name.
fn canonical_request(headers: &[(String, String)], payload: &[u8]) -> String {
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let payload_hash = hex(&Sha256::digest(payload));
    // METHOD \n URI \n QUERY \n CANONICAL_HEADERS \n SIGNED_HEADERS \n HASH
    format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}")
}

/// Build the SigV4 string-to-sign from the canonical request.
fn string_to_sign(amz_date: &str, scope: &str, canonical: &str) -> String {
    let hashed = hex(&Sha256::digest(canonical.as_bytes()));
    format!("{ALGORITHM}\n{amz_date}\n{scope}\n{hashed}")
}

/// Derive the SigV4 signing key (the HMAC chain over the date, region,
/// service, and terminator).
fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, TERMINATOR.as_bytes())
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_hex_of_empty_is_the_known_constant() {
        // Pins the hashing + hex path against the universally-known value.
        assert_eq!(hex(&Sha256::digest(b"")), SHA256_EMPTY);
    }

    #[test]
    fn canonical_request_is_byte_exact() {
        // host + x-amz-date only, empty body — mirrors AWS's `post-vanilla`
        // canonical request from the SigV4 test suite, byte-for-byte. This
        // is the format-sensitive part (newlines, sorting, trailing hash).
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let cr = canonical_request(&headers, b"");
        let expected = format!(
            "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n{SHA256_EMPTY}"
        );
        assert_eq!(cr, expected);
    }

    #[test]
    fn string_to_sign_is_byte_exact() {
        let canonical = "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n".to_string() + SHA256_EMPTY;
        let scope = "20150830/us-east-1/service/aws4_request";
        let sts = string_to_sign("20150830T123600Z", scope, &canonical);
        let canonical_hash = hex(&Sha256::digest(canonical.as_bytes()));
        let expected = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{canonical_hash}"
        );
        assert_eq!(sts, expected);
    }

    fn creds() -> Credentials {
        Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    #[test]
    fn authorization_is_deterministic_and_well_formed() {
        let h = [Header { name: "content-type", value: "application/x-amz-json-1.1" }];
        let a = sign_post(&creds(), "us-east-1", "kms", "kms.us-east-1.amazonaws.com",
            "20150830T123600Z", "20150830", &h, b"{}");
        let b = sign_post(&creds(), "us-east-1", "kms", "kms.us-east-1.amazonaws.com",
            "20150830T123600Z", "20150830", &h, b"{}");
        assert_eq!(a, b, "same inputs must produce the same signature");
        assert!(a.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request, SignedHeaders="
        ));
        // content-type, host, x-amz-date are signed and sorted.
        assert!(a.authorization.contains("SignedHeaders=content-type;host;x-amz-date, Signature="));
        assert_eq!(a.amz_date, "20150830T123600Z");
        assert!(a.security_token.is_none());
    }

    #[test]
    fn body_change_changes_signature() {
        let h = [Header { name: "content-type", value: "application/x-amz-json-1.1" }];
        let a = sign_post(&creds(), "us-east-1", "kms", "h", "20150830T123600Z", "20150830", &h, b"{}");
        let b = sign_post(&creds(), "us-east-1", "kms", "h", "20150830T123600Z", "20150830", &h, b"{\"x\":1}");
        assert_ne!(a.authorization, b.authorization);
    }

    #[test]
    fn temporary_creds_sign_and_surface_the_session_token() {
        let mut c = creds();
        c.session_token = Some("FwoGZXIvSESSIONTOKEN".into());
        let a = sign_post(&c, "eu-central-1", "kms", "kms.eu-central-1.amazonaws.com",
            "20240101T000000Z", "20240101", &[], b"{}");
        // The token is signed (appears in SignedHeaders) and surfaced for
        // the caller to add as a header.
        assert!(a.authorization.contains("host;x-amz-date;x-amz-security-token"));
        assert_eq!(a.security_token.as_deref(), Some("FwoGZXIvSESSIONTOKEN"));
    }
}
