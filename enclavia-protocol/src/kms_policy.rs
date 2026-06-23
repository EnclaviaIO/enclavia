//! In-enclave verification of a KMS key's policy (#198 follow-up).
//!
//! The backend mints one asymmetric KMS key per storage enclave whose
//! policy is supposed to gate `kms:Decrypt` on the enclave's attestation
//! PCR0/1/2 and to grant no principal a way to loosen that gate. The
//! enclave must not *trust* the backend to have done this correctly: a
//! buggy or hostile backend could mint a key whose policy lets the account
//! decrypt directly, or whose policy can later be rewritten. So before the
//! enclave seals its LUKS passphrase under the key (first boot) or relies
//! on it to recover the passphrase (every subsequent boot), it fetches the
//! policy with `kms:GetKeyPolicy` and runs it through
//! [`verify_decrypt_policy`]. A failure refuses the boot.
//!
//! ## Trust caveat
//!
//! In the current architecture the enclave reaches KMS over a plaintext
//! channel that the parent proxies (no in-enclave TLS validation of the
//! KMS endpoint). So this check is load-bearing against a *buggy or
//! misconfigured backend* (the realistic threat: a policy-construction
//! bug like granting the account root `kms:*`), and is defense-in-depth
//! against a fully hostile parent, which could forge the `GetKeyPolicy`
//! response. Closing that last gap needs end-to-end TLS to KMS and is
//! out of scope here.
//!
//! ## What is enforced
//!
//! Over every `Effect: "Allow"` statement in the policy:
//!
//! 1. **No `NotAction`.** An `Allow` + `NotAction` grants everything
//!    *except* the listed actions, which is too broad to reason about and
//!    would include `kms:Decrypt`/`kms:PutKeyPolicy`. Rejected outright.
//! 2. **No wildcard actions.** Any action containing `*` (e.g. `kms:*`,
//!    `kms:Decrypt*`) is rejected: the legitimate policy uses explicit
//!    actions only, and a wildcard is impossible to bound.
//! 3. **No gate-loosening actions for anyone.** `kms:PutKeyPolicy` (rewrite
//!    the policy), `kms:CreateGrant` (delegate decrypt to an un-attested
//!    principal), `kms:ReplicateKey` (clone the key elsewhere), and any
//!    `kms:ReEncrypt*` (recover plaintext outside the attestation
//!    condition) are forbidden for every principal.
//! 4. **Every `kms:Decrypt` grant is pinned to our PCRs.** A statement that
//!    allows `kms:Decrypt` must carry a `StringEquals` /
//!    `StringEqualsIgnoreCase` condition binding
//!    `kms:RecipientAttestation:PCR0`, `:PCR1`, and `:PCR2` to *this*
//!    enclave's own PCR values (and to exactly those, not a set).
//!
//! A policy with no `Allow` statement that grants `kms:Decrypt` passes
//! vacuously: it grants nobody decrypt, which is not a confidentiality
//! hole (in real KMS the enclave simply could not recover the passphrase,
//! a liveness failure that surfaces at the `Decrypt` call, never silent
//! exposure). This is what lets the dev/QEMU `mock-kms` auto-create path
//! (policy-less keys) boot while production policies are enforced strictly.

use serde_json::Value;

use crate::attestation::Pcrs;

/// A condition operator we accept as a hard string-equality binding.
/// Anything else (`StringLike`, `StringNotEquals`, `*IfExists`, set
/// operators) does not count as gating the action to our PCRs.
const EQ_OPERATORS: [&str; 2] = ["StringEquals", "StringEqualsIgnoreCase"];

/// Actions that could loosen or sidestep the attestation gate, forbidden
/// for ANY principal (matched case-insensitively, exact).
const FORBIDDEN_ACTIONS: [&str; 3] = [
    "kms:putkeypolicy",
    "kms:creategrant",
    "kms:replicatekey",
];

/// Why a KMS key policy is unacceptable for an attestation-bound LUKS key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// The policy was not valid JSON.
    #[error("key policy is not valid JSON: {0}")]
    Json(String),
    /// The policy had no `Statement` element at all.
    #[error("key policy has no Statement element")]
    NoStatements,
    /// An `Allow` statement used `NotAction` (an allow-all-but grant).
    #[error("an Allow statement uses NotAction, which is too broad to bound")]
    NotAction,
    /// An action used a `*` wildcard.
    #[error("key policy grants wildcard action {0:?}; only explicit actions are allowed")]
    WildcardAction(String),
    /// A gate-loosening action was granted to some principal.
    #[error("key policy grants gate-loosening action {0:?} (could change or bypass the decrypt gate)")]
    ForbiddenAction(String),
    /// A statement allows `kms:Decrypt` without a complete PCR binding to
    /// this enclave.
    #[error("a statement allows kms:Decrypt without binding it to this enclave's PCR0/1/2")]
    UngatedDecrypt,
    /// A `kms:Decrypt` statement binds a PCR to the wrong value.
    #[error("kms:Decrypt is bound to PCR{index} {found:?}, not this enclave's {expected:?}")]
    PcrMismatch {
        /// PCR index (0, 1, or 2).
        index: u8,
        /// Value found in the policy condition.
        found: String,
        /// This enclave's own PCR value (hex).
        expected: String,
    },
}

/// Verify that `policy_json` (the stringified document returned by
/// `kms:GetKeyPolicy`) is safe for a LUKS-wrapping key whose `kms:Decrypt`
/// must be gated to `own` — this enclave's own PCR0/1/2. Fails closed; see
/// the module docs for the exact invariants.
pub fn verify_decrypt_policy(policy_json: &str, own: &Pcrs) -> Result<(), PolicyError> {
    let doc: Value =
        serde_json::from_str(policy_json).map_err(|e| PolicyError::Json(e.to_string()))?;

    let statements = match doc.get("Statement") {
        Some(Value::Array(arr)) => arr.clone(),
        Some(other) => vec![other.clone()],
        None => return Err(PolicyError::NoStatements),
    };

    let want = [
        ("0", 0u8, hex::encode(&own.pcr0)),
        ("1", 1u8, hex::encode(&own.pcr1)),
        ("2", 2u8, hex::encode(&own.pcr2)),
    ];

    for stmt in &statements {
        // Deny statements only restrict; they cannot grant anything, so
        // they are irrelevant to "what is allowed". Skip anything that is
        // not an explicit Allow.
        if stmt.get("Effect").and_then(Value::as_str) != Some("Allow") {
            continue;
        }

        // An Allow + NotAction grants everything except the listed actions
        // (including Decrypt / PutKeyPolicy) — unbounded, reject.
        if stmt.get("NotAction").is_some() {
            return Err(PolicyError::NotAction);
        }

        let actions = normalize_actions(stmt.get("Action"));

        for action in &actions {
            if action.contains('*') {
                return Err(PolicyError::WildcardAction(action.clone()));
            }
            if FORBIDDEN_ACTIONS.contains(&action.as_str())
                || action.starts_with("kms:reencrypt")
            {
                return Err(PolicyError::ForbiddenAction(action.clone()));
            }
        }

        // Any statement that allows Decrypt must pin all three PCRs to us.
        if actions.iter().any(|a| a == "kms:decrypt") {
            let bound = collect_pcr_bindings(stmt);
            for (suffix, index, expected) in &want {
                match bound.get(*suffix) {
                    None => return Err(PolicyError::UngatedDecrypt),
                    Some(found) => {
                        if !found.eq_ignore_ascii_case(expected) {
                            return Err(PolicyError::PcrMismatch {
                                index: *index,
                                found: found.clone(),
                                expected: expected.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Normalize a statement's `Action` (a string or an array of strings) to a
/// lowercased `Vec<String>`. A missing/!string `Action` yields an empty
/// list (such a statement grants no action we care about).
fn normalize_actions(action: Option<&Value>) -> Vec<String> {
    match action {
        Some(Value::String(s)) => vec![s.to_ascii_lowercase()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        _ => Vec::new(),
    }
}

/// Pull the `kms:RecipientAttestation:PCR{n}` bindings out of a statement's
/// `Condition`, keyed by the `{n}` suffix ("0"/"1"/"2"). Only hard
/// string-equality operators ([`EQ_OPERATORS`]) count, and only a single
/// scalar value per PCR is accepted: a multi-value set would mean "match
/// any of these images", a looser gate than we require, so it is dropped
/// (and the missing binding then trips [`PolicyError::UngatedDecrypt`]).
fn collect_pcr_bindings(stmt: &Value) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Some(cond) = stmt.get("Condition").and_then(Value::as_object) else {
        return out;
    };
    for (op, kv) in cond {
        if !EQ_OPERATORS.contains(&op.as_str()) {
            continue;
        }
        let Some(kv_map) = kv.as_object() else { continue };
        for (key, val) in kv_map {
            let suffix = key
                .strip_prefix("kms:RecipientAttestation:PCR")
                .or_else(|| key.strip_prefix("kms:RecipientAttestation:pcr"));
            let Some(suffix) = suffix else { continue };
            // Only a single scalar string binds; an array (set) is a looser
            // "any of" gate we deliberately do not honour.
            if let Value::String(s) = val {
                out.insert(suffix.to_string(), s.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcrs(a: &[u8], b: &[u8], c: &[u8]) -> Pcrs {
        Pcrs {
            pcr0: a.to_vec(),
            pcr1: b.to_vec(),
            pcr2: c.to_vec(),
        }
    }

    /// Own PCRs used across the tests: bytes whose hex is stable/known.
    fn own() -> Pcrs {
        pcrs(&[0xaa; 48], &[0xbb; 48], &[0xcc; 48])
    }

    fn hex_of(b: &[u8]) -> String {
        hex::encode(b)
    }

    /// A correct production-shaped policy: account lifecycle (no decrypt),
    /// enclave GetPublicKey, enclave attested Decrypt gated to `own`.
    fn good_policy(own: &Pcrs) -> String {
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AccountKeyLifecycle",
                    "Effect": "Allow",
                    "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
                    "Action": [
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:ScheduleKeyDeletion"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "EnclaveGetPublicKey",
                    "Effect": "Allow",
                    "Principal": { "AWS": "arn:aws:iam::111122223333:role/enc" },
                    "Action": "kms:GetPublicKey",
                    "Resource": "*"
                },
                {
                    "Sid": "EnclaveAttestedDecrypt",
                    "Effect": "Allow",
                    "Principal": { "AWS": "arn:aws:iam::111122223333:role/enc" },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0),
                            "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                            "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                        }
                    }
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn accepts_correct_policy() {
        let own = own();
        verify_decrypt_policy(&good_policy(&own), &own).expect("good policy accepted");
    }

    #[test]
    fn accepts_correct_policy_case_insensitive_pcr_hex() {
        // StringEqualsIgnoreCase semantics: upper-case policy hex must still
        // match our lower-case own PCRs.
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0).to_uppercase(),
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1).to_uppercase(),
                    "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2).to_uppercase(),
                }}
            }]
        })
        .to_string();
        verify_decrypt_policy(&doc, &own).expect("case-insensitive hex accepted");
    }

    #[test]
    fn empty_statements_pass_vacuously() {
        let doc = r#"{"Version":"2012-10-17","Statement":[]}"#;
        verify_decrypt_policy(doc, &own()).expect("empty policy is vacuously safe");
    }

    #[test]
    fn rejects_account_kms_star() {
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Sid": "AccountAdmin",
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
                "Action": "kms:*",
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own),
            Err(PolicyError::WildcardAction("kms:*".into()))
        );
    }

    #[test]
    fn rejects_put_key_policy() {
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
                "Action": ["kms:DescribeKey", "kms:PutKeyPolicy"],
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own()),
            Err(PolicyError::ForbiddenAction("kms:putkeypolicy".into()))
        );
    }

    #[test]
    fn rejects_create_grant() {
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:CreateGrant",
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own()),
            Err(PolicyError::ForbiddenAction("kms:creategrant".into()))
        );
    }

    #[test]
    fn rejects_reencrypt() {
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:ReEncryptFrom",
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own()),
            Err(PolicyError::ForbiddenAction("kms:reencryptfrom".into()))
        );
    }

    #[test]
    fn rejects_ungated_decrypt() {
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own()),
            Err(PolicyError::UngatedDecrypt)
        );
    }

    #[test]
    fn rejects_decrypt_gated_to_wrong_pcr() {
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": hex_of(&[0xde; 48]),
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                    "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                }}
            }]
        })
        .to_string();
        match verify_decrypt_policy(&doc, &own) {
            Err(PolicyError::PcrMismatch { index: 0, .. }) => {}
            other => panic!("expected PCR0 mismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_decrypt_missing_one_pcr() {
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0),
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                }}
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own),
            Err(PolicyError::UngatedDecrypt)
        );
    }

    #[test]
    fn rejects_decrypt_gated_by_set_of_pcrs() {
        // An array value means "match any of these images" — a looser gate
        // we refuse to honour, so the binding is dropped and Decrypt reads
        // as ungated.
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": [hex_of(&own.pcr0), hex_of(&[0xff; 48])],
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                    "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                }}
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own),
            Err(PolicyError::UngatedDecrypt)
        );
    }

    #[test]
    fn rejects_decrypt_gated_by_wrong_operator() {
        // StringLike is not a hard equality, so it does not count as a
        // binding; Decrypt reads as ungated.
        let own = own();
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringLike": {
                    "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0),
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                    "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                }}
            }]
        })
        .to_string();
        assert_eq!(
            verify_decrypt_policy(&doc, &own),
            Err(PolicyError::UngatedDecrypt)
        );
    }

    #[test]
    fn rejects_not_action_allow() {
        let doc = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
                "NotAction": "kms:CreateKey",
                "Resource": "*"
            }]
        })
        .to_string();
        assert_eq!(verify_decrypt_policy(&doc, &own()), Err(PolicyError::NotAction));
    }

    #[test]
    fn ignores_deny_statements() {
        // A Deny with kms:* must not trip the wildcard check (it restricts,
        // it does not grant), and the Allow Decrypt is correctly gated.
        let own = own();
        let doc = serde_json::json!({
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                    "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
                },
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Condition": { "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0),
                        "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                        "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                    }}
                }
            ]
        })
        .to_string();
        verify_decrypt_policy(&doc, &own).expect("deny statements are ignored");
    }

    #[test]
    fn rejects_non_json() {
        match verify_decrypt_policy("not json", &own()) {
            Err(PolicyError::Json(_)) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_statement() {
        assert_eq!(
            verify_decrypt_policy(r#"{"Version":"2012-10-17"}"#, &own()),
            Err(PolicyError::NoStatements)
        );
    }

    #[test]
    fn accepts_single_statement_object() {
        // AWS allows Statement to be a single object, not just an array.
        let own = own();
        let doc = serde_json::json!({
            "Statement": {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Condition": { "StringEquals": {
                    "kms:RecipientAttestation:PCR0": hex_of(&own.pcr0),
                    "kms:RecipientAttestation:PCR1": hex_of(&own.pcr1),
                    "kms:RecipientAttestation:PCR2": hex_of(&own.pcr2),
                }}
            }
        })
        .to_string();
        verify_decrypt_policy(&doc, &own).expect("single-object statement accepted");
    }
}
