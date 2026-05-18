//! `enclavia push` — re-tag a local Docker image into a specific enclave's
//! registry repo and ship it to the registry. The CLI mediates so testers
//! don't need to know the registry hostname or run `docker login` themselves.
//!
//! Under the per-enclave namespace (#46 phase 2) every enclave owns its own
//! repo at `<owner>/<enclave-uuid>`, so the push target is derived from the
//! enclave id rather than a free-form name. Tags don't matter for binding
//! — the enclave's identity is pinned to the digest of the first push — so
//! we always push as `:latest`.
//!
//! This is a CLI-binary-only orchestrator: it shells out to `docker` and
//! streams output to the terminal. The MCP server doesn't expose it.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::api::{ApiClient, EnclaveSummary};
use crate::error::CliError;

const DEFAULT_TAG: &str = "latest";

pub async fn push(local_image: &str, enclave_id_or_prefix: &str) -> Result<(), CliError> {
    let client = ApiClient::new()?;
    let registry = client.get_registry().await?;
    let registry_host = &registry.registry_url;
    let namespace = &registry.namespace;

    // Resolve the user-supplied id or prefix to exactly one of the caller's
    // enclaves. We accept prefixes so users can paste the short id printed by
    // `enclave create` without having to look up the full UUID; an ambiguous
    // prefix is a hard error rather than picking arbitrarily.
    let enclave = resolve_enclave(&client, enclave_id_or_prefix).await?;
    let push_target = extract_push_target(&enclave)?;

    let canonical = format!("{registry_host}/{push_target}:{DEFAULT_TAG}");

    // Authenticate the local docker daemon to the registry. The realm
    // endpoint accepts the user's API JWT as the Basic password, so the
    // docker daemon itself never sees the password — it stays in the user's
    // own keyring (or `~/.docker/config.json` if no helper is configured).
    docker_login(registry_host, namespace, &client.token()).await?;

    println!("Tagging {local_image} -> {canonical}");
    run_docker(&["tag", local_image, &canonical]).await?;

    println!("Pushing {canonical}");
    let digest = stream_docker_push(&canonical).await?;

    println!();
    println!("Pushed to {canonical}");
    if let Some(d) = digest.as_deref() {
        // The manifest digest is the only content-addressed identifier here;
        // tags are mutable. Surfacing it lets the user (or scripts) confirm
        // the digest the backend will pin against, which is what shows up in
        // the dashboard once the build completes.
        println!("Digest: {d}");
    }

    // Tell the backend a push just landed for this enclave so it can kick
    // off the build immediately instead of waiting for the next registry
    // poll. Critically, a no-op re-push (same digest, layers already cached)
    // would never trigger digest-change polling — this notify is the push
    // *event* signal that bypasses that. Best-effort: the push itself
    // succeeded, so we still print a status hint on notify failure.
    match client.notify_push(&enclave.id).await {
        Ok(resp) if !resp.triggered.is_empty() => {
            let n = resp.triggered.len();
            let plural = if n == 1 { "build" } else { "builds" };
            println!("Notified backend; {n} {plural} now starting:");
            for id in &resp.triggered {
                println!("  enclavia enclave status {id}");
            }
        }
        Ok(_) => {
            println!("Notified backend; check build progress with:");
            println!("  enclavia enclave status {}", enclave.id);
        }
        Err(e) => {
            eprintln!("warning: failed to notify backend of push: {e}");
            eprintln!("  the backend's registry poll will still pick it up within ~15s");
            println!("Check build progress with:");
            println!("  enclavia enclave status {}", enclave.id);
        }
    }
    Ok(())
}

/// Resolve a user-supplied id or unique prefix to exactly one enclave.
///
/// We list the caller's enclaves (the backend already filters to ownership)
/// and match by id-prefix. Two terminal failures are distinguished:
///   * no match → the prefix didn't hit any of the caller's enclaves
///   * multiple matches → the prefix was ambiguous; we list the candidates
///     so the user can disambiguate without re-running `enclave list`.
async fn resolve_enclave(
    client: &ApiClient,
    id_or_prefix: &str,
) -> Result<EnclaveSummary, CliError> {
    if id_or_prefix.is_empty() {
        return Err("enclave id cannot be empty".into());
    }

    // Include archived enclaves so a user who pushes to a destroyed enclave
    // gets a clear "destroyed" error from the backend on `notify_push`,
    // rather than the more confusing "no such enclave" from prefix
    // resolution. The match list is small (per-user cap), so this is cheap.
    let all = client.list_enclaves(true).await?;
    let matches: Vec<EnclaveSummary> = all
        .into_iter()
        .filter(|e| e.id.starts_with(id_or_prefix))
        .collect();

    match matches.as_slice() {
        [] => Err(CliError::Other(format!(
            "no enclave matches `{id_or_prefix}`. List your enclaves with `enclavia enclave list`."
        ))),
        [one] => Ok(one.clone()),
        many => {
            let mut msg = format!(
                "prefix `{id_or_prefix}` matches {} enclaves; pass a longer prefix:\n",
                many.len()
            );
            for e in many {
                let name = e.name.as_deref().unwrap_or("-");
                msg.push_str(&format!("  {} ({name})\n", e.id));
            }
            Err(CliError::Other(msg.trim_end().to_string()))
        }
    }
}

/// Pull the `push_target` field out of the backend's enclave row. The
/// backend writes `<owner>/<enclave-uuid>` for every row created under the
/// per-enclave namespace; the `Option` is just defensive belt-and-braces
/// against malformed rows on older deployments.
fn extract_push_target(enclave: &EnclaveSummary) -> Result<String, CliError> {
    enclave
        .raw
        .get("push_target")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            CliError::Other(format!(
                "enclave {} is missing `push_target`; the backend may be older than the CLI",
                enclave.id
            ))
        })
}

/// `docker login <host> -u <user> --password-stdin` — the password is the
/// caller's enclavia API JWT, piped on stdin so it never appears in the
/// process table or the shell history. `--password-stdin` is the docker
/// CLI's documented secure entry point for scripted logins.
async fn docker_login(host: &str, username: &str, password: &str) -> Result<(), CliError> {
    let mut child = Command::new("docker")
        .args(["login", host, "-u", username, "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CliError::Other(format!("failed to spawn docker login: {e}")))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| CliError::Other("docker login: stdin not piped (impossible)".into()))?;
        stdin
            .write_all(password.as_bytes())
            .await
            .map_err(|e| CliError::Other(format!("docker login: write password: {e}")))?;
        // Dropping closes stdin and signals EOF to docker.
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| CliError::Other(format!("docker login io error: {e}")))?;
    if !output.status.success() {
        // Docker writes its real error to stderr; surfacing it is much more
        // useful than a bare "exit code 1" so users can tell apart "wrong
        // creds" from "registry unreachable" without re-running with -D.
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Other(format!(
            "docker login {host} failed: {}\n{}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

async fn run_docker(args: &[&str]) -> Result<(), CliError> {
    let status = Command::new("docker")
        .args(args)
        .status()
        .await
        .map_err(|e| {
            CliError::Other(format!("failed to run docker (is it installed and on $PATH?): {e}"))
        })?;
    if !status.success() {
        return Err(CliError::Other(format!("docker {} failed: {status}", args[0])));
    }
    Ok(())
}

/// Run `docker push` and stream both stdout and stderr to the user as they
/// arrive — docker's own per-layer progress is the friendly output the issue
/// asks for, we just don't buffer it.
///
/// Returns the manifest digest extracted from docker's final summary line
/// (`<tag>: digest: sha256:<hex> size: <n>`), or `None` if docker emitted no
/// such line (older docker versions, registries that don't return one). The
/// caller should treat absence as "couldn't capture", not "push failed" —
/// the exit status is the source of truth on success.
async fn stream_docker_push(reference: &str) -> Result<Option<String>, CliError> {
    let mut child = Command::new("docker")
        .args(["push", reference])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CliError::Other(format!("failed to spawn docker push: {e}")))?;

    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");

    let stdout_task = tokio::spawn(async move {
        let mut digest: Option<String> = None;
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(d) = parse_push_digest(&line) {
                digest = Some(d);
            }
            println!("{line}");
        }
        digest
    });
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("{line}");
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| CliError::Other(format!("docker push io error: {e}")))?;
    let digest = stdout_task.await.unwrap_or(None);
    let _ = stderr_task.await;

    if !status.success() {
        return Err(CliError::Other(format!("docker push failed: {status}")));
    }
    Ok(digest)
}

/// Pull the manifest digest out of docker's summary line, which looks like
/// `v1: digest: sha256:abc... size: 1234`. The tag in front varies, so we
/// scan for the `digest:` token and accept the very next whitespace-bounded
/// token if it has the expected `sha256:`/`sha512:` prefix.
fn parse_push_digest(line: &str) -> Option<String> {
    let needle = "digest:";
    let idx = line.find(needle)?;
    let after = &line[idx + needle.len()..];
    let token = after.split_whitespace().next()?;
    if token.starts_with("sha256:") || token.starts_with("sha512:") {
        Some(token.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_push_digest_pulls_sha256_from_summary() {
        // The line docker emits at the very end of a successful push.
        let d = super::parse_push_digest(
            "v1: digest: sha256:0123456789abcdef size: 5678",
        );
        assert_eq!(d.as_deref(), Some("sha256:0123456789abcdef"));
    }

    #[test]
    fn parse_push_digest_ignores_unrelated_lines() {
        assert!(super::parse_push_digest("Pushing layer abc").is_none());
        assert!(super::parse_push_digest("").is_none());
    }

    #[test]
    fn parse_push_digest_rejects_non_sha_prefix() {
        // Defensive: never surface a non-content-addressed token as the
        // digest, even if some future docker variant uses a different
        // separator.
        assert!(super::parse_push_digest("v1: digest: not-a-digest size: 10").is_none());
    }

    fn summary(id: &str, name: Option<&str>) -> EnclaveSummary {
        EnclaveSummary {
            id: id.to_string(),
            name: name.map(|s| s.to_string()),
            docker_image: None,
            status: None,
            instance_type: None,
            created_at: None,
            archived: false,
            builder_rev: None,
            crates_rev: None,
            raw: serde_json::json!({ "push_target": format!("alice/{id}") }),
        }
    }

    #[test]
    fn extract_push_target_pulls_from_raw() {
        let s = summary("11111111-aaaa-bbbb-cccc-222222222222", Some("api"));
        assert_eq!(
            extract_push_target(&s).unwrap(),
            "alice/11111111-aaaa-bbbb-cccc-222222222222"
        );
    }

    #[test]
    fn extract_push_target_errors_on_missing() {
        let mut s = summary("aaaa", None);
        s.raw = serde_json::json!({});
        assert!(extract_push_target(&s).is_err());
    }
}
