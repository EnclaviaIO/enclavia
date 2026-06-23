//! Real-AWS end-to-end smoke test for the IN-ENCLAVE KMS client path.
//!
//! Exercises the exact hand-rolled SigV4 signer (`enclavia_crypto::sigv4`)
//! and TLS configuration (`enclavia_crypto::kms_tls_config`) the enclave
//! uses, against real AWS KMS. The only difference from running inside a
//! Nitro enclave is the socket: here we connect to
//! `kms.<region>.amazonaws.com:443` over TCP directly; in the enclave the
//! identical bytes flow over a vsock relay. The request signing, TLS cert
//! validation, request/response JSON shapes, and the boot-time policy /
//! Origin verification are all the same code.
//!
//! It mints a key with the production-shaped restrictive policy (account
//! lifecycle only + enclave read + attested Decrypt gated to fixed test
//! PCRs) and `BypassPolicyLockoutSafetyCheck`, reads the policy back via
//! `GetKeyPolicy` and runs the real enclave check on it, confirms
//! `DescribeKey` reports `Origin=AWS_KMS`, checks a deliberately-bad policy
//! is rejected, then schedules the key for deletion.
//!
//! ```bash
//! eval "$(grep -A2 '\[enclavia\]' ~/.aws/credentials | sed -n 's/aws_access_key_id *= *\(.*\)/export AWS_ACCESS_KEY_ID=\1/p; s/aws_secret_access_key *= *\(.*\)/export AWS_SECRET_ACCESS_KEY=\1/p')"
//! KMS_SMOKE_REGION=eu-central-1 cargo run -p enclavia-crypto --example kms_real_smoke
//! ```
//!
//! Not run by CI (needs real credentials + makes a billable key).

use std::sync::Arc;

use bytes::Bytes;
use enclavia_crypto::{kms_tls_config, sigv4};
use enclavia_protocol::attestation::Pcrs;
use enclavia_protocol::kms_policy::verify_decrypt_policy;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::Value;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const ACCOUNT: &str = "873014949385";

type Err = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), Err> {
    let region = std::env::var("KMS_SMOKE_REGION").unwrap_or_else(|_| "eu-central-1".into());
    let host = format!("kms.{region}.amazonaws.com");
    let role = std::env::var("KMS_ENCLAVE_ROLE_ARN")
        .unwrap_or_else(|_| format!("arn:aws:iam::{ACCOUNT}:role/enclavia-enclave-instance"));
    let creds = sigv4::Credentials {
        access_key_id: std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID"),
        secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY"),
        session_token: std::env::var("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty()),
    };

    // Fixed "this enclave's" PCRs. We bake these into the minted policy and
    // verify against them, mirroring how a real enclave verifies against the
    // PCRs in its own NSM attestation.
    let own = Pcrs {
        pcr0: vec![0xaa; 48],
        pcr1: vec![0xbb; 48],
        pcr2: vec![0xcc; 48],
    };

    println!("== CreateKey (restrictive policy + BypassPolicyLockoutSafetyCheck), signed by the enclave's SigV4 ==");
    let policy = good_policy(&role, &own);
    let create_body = serde_json::json!({
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeySpec": "RSA_2048",
        "Policy": policy,
        "BypassPolicyLockoutSafetyCheck": true,
        "Description": "enclavia kms_real_smoke (delete me)",
    });
    let resp = kms_post(&region, &host, &creds, "TrentService.CreateKey",
        serde_json::to_vec(&create_body)?).await?;
    let v: Value = serde_json::from_slice(&resp)?;
    let key_id = v["KeyMetadata"]["Arn"].as_str().ok_or("no Arn in CreateKey response")?.to_string();
    println!("   minted (TLS + SigV4 authenticated to real KMS): {key_id}");

    // Best-effort cleanup even if a later step fails.
    let result = run_checks(&region, &host, &creds, &key_id, &own).await;

    println!("== ScheduleKeyDeletion (cleanup, 7-day window) ==");
    let del = serde_json::json!({ "KeyId": key_id, "PendingWindowInDays": 7 });
    match kms_post(&region, &host, &creds, "TrentService.ScheduleKeyDeletion",
        serde_json::to_vec(&del)?).await {
        Ok(_) => println!("   scheduled deletion for {key_id}"),
        Err(e) => println!("   WARNING: cleanup failed, delete manually: {e}"),
    }

    result?;
    println!("\nIN-ENCLAVE KMS PATH SMOKE TEST PASSED against real AWS KMS.");
    Ok(())
}

async fn run_checks(
    region: &str,
    host: &str,
    creds: &sigv4::Credentials,
    key_id: &str,
    own: &Pcrs,
) -> Result<(), Err> {
    println!("== GetKeyPolicy + verify_decrypt_policy (the boot-time gate) ==");
    let body = serde_json::json!({ "KeyId": key_id, "PolicyName": "default" });
    let resp = kms_post(region, host, creds, "TrentService.GetKeyPolicy",
        serde_json::to_vec(&body)?).await?;
    let v: Value = serde_json::from_slice(&resp)?;
    let policy = v["Policy"].as_str().ok_or("no Policy in GetKeyPolicy response")?;
    println!("   policy fetched from real KMS ({} bytes)", policy.len());
    verify_decrypt_policy(policy, own).map_err(|e| format!("real policy REJECTED by enclave check: {e}"))?;
    println!("   verify_decrypt_policy: ACCEPTED (Decrypt gated to our PCR0/1/2, no loosening grants)");

    println!("== DescribeKey + Origin check ==");
    let body = serde_json::json!({ "KeyId": key_id });
    let resp = kms_post(region, host, creds, "TrentService.DescribeKey",
        serde_json::to_vec(&body)?).await?;
    let v: Value = serde_json::from_slice(&resp)?;
    let origin = v["KeyMetadata"]["Origin"].as_str().ok_or("no Origin in DescribeKey response")?;
    println!("   Origin = {origin}");
    if origin != "AWS_KMS" {
        return Err(format!("expected Origin=AWS_KMS, got {origin}").into());
    }

    println!("== negative control: a bad policy (account kms:*) must be rejected ==");
    let bad = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AccountAdmin", "Effect": "Allow",
            "Principal": { "AWS": format!("arn:aws:iam::{ACCOUNT}:root") },
            "Action": "kms:*", "Resource": "*"
        }]
    }).to_string();
    match verify_decrypt_policy(&bad, own) {
        Err(e) => println!("   correctly rejected: {e}"),
        Ok(()) => return Err("BUG: bad policy was accepted".into()),
    }
    Ok(())
}

/// The production-shaped restrictive policy (mirrors the backend's
/// `AwsKmsClient::key_policy`): account lifecycle only, enclave read, and
/// attested Decrypt gated to `own`.
fn good_policy(role_arn: &str, own: &Pcrs) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Id": "enclavia-enclave-luks-key",
        "Statement": [
            {
                "Sid": "AccountKeyLifecycle", "Effect": "Allow",
                "Principal": { "AWS": format!("arn:aws:iam::{ACCOUNT}:root") },
                "Action": [
                    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey",
                    "kms:ListResourceTags", "kms:TagResource", "kms:UntagResource",
                    "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "EnclaveRead", "Effect": "Allow",
                "Principal": { "AWS": role_arn },
                "Action": ["kms:GetPublicKey", "kms:GetKeyPolicy"],
                "Resource": "*"
            },
            {
                "Sid": "EnclaveAttestedDecrypt", "Effect": "Allow",
                "Principal": { "AWS": role_arn },
                "Action": "kms:Decrypt", "Resource": "*",
                "Condition": { "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": hex::encode(&own.pcr0),
                    "kms:RecipientAttestation:PCR1": hex::encode(&own.pcr1),
                    "kms:RecipientAttestation:PCR2": hex::encode(&own.pcr2),
                }}
            }
        ]
    }).to_string()
}

/// Sign a KMS POST with the enclave's SigV4 + send it over a fresh TLS-over-
/// TCP connection built with the enclave's `kms_tls_config`. Mirrors the
/// in-enclave `kms_call`, minus the vsock relay.
async fn kms_post(
    region: &str,
    host: &str,
    creds: &sigv4::Credentials,
    target: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, Err> {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let headers = [
        sigv4::Header { name: "content-type", value: CONTENT_TYPE },
        sigv4::Header { name: "x-amz-target", value: target },
    ];
    let signed = sigv4::sign_post(creds, region, "kms", host, &amz_date, &date_stamp, &headers, &body);

    let tcp = tokio::net::TcpStream::connect((host, 443)).await?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(kms_tls_config()));
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tls = connector.connect(server_name, tcp).await?;

    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", host)
        .header("content-type", CONTENT_TYPE)
        .header("x-amz-target", target)
        .header("x-amz-date", signed.amz_date)
        .header("authorization", signed.authorization);
    if let Some(tok) = signed.security_token {
        builder = builder.header("x-amz-security-token", tok);
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;

    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let resp_body = resp.into_body().collect().await?.to_bytes().to_vec();
    if !status.is_success() {
        return Err(format!("KMS {target} returned {status}: {}", String::from_utf8_lossy(&resp_body)).into());
    }
    Ok(resp_body)
}
