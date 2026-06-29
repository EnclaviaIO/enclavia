//! End-to-end `--json` contract tests for the `enclavia` binary.
//!
//! These spawn the actual compiled binary (`CARGO_BIN_EXE_enclavia`) plus a
//! local stub backend, so they exercise the real stdout / stderr / exit-code
//! wiring without touching the network or the user's on-disk credentials.
//!
//! Coverage:
//!   * success path: `--json` emits a single parseable JSON value with the
//!     expected keys, nothing else on stdout (`list_json_success_*`).
//!   * error path: `--json` emits `{"error", "kind"}` and exits non-zero
//!     (`list_json_error_*`).
//!   * default UX is unchanged: the human path prints the table to stdout and
//!     surfaces errors on stderr (`list_human_*`).
//!   * the `--json` flag is global (works before the subcommand too).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use axum::{routing::get, Json, Router};
use tokio::net::TcpListener;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh, process-unique config home so tests never see each other's (or
/// the developer's) credentials.
fn unique_config_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "enclavia-cli-json-test-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Write a valid credentials file pointing at `backend_url`, so `ApiClient`
/// authenticates against the stub instead of returning `NotLoggedIn`.
fn write_credentials(config_home: &Path, backend_url: &str) {
    // `config::config_dir()` is `$XDG_CONFIG_HOME/enclavia`.
    let dir = config_home.join("enclavia");
    std::fs::create_dir_all(&dir).unwrap();
    let creds = serde_json::json!({
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "expires_at": "2999-01-01T00:00:00Z",
        "backend_url": backend_url,
    });
    std::fs::write(dir.join("credentials.json"), creds.to_string()).unwrap();
}

/// Stand up a minimal stub backend serving `GET /enclaves`. Returns the bound
/// address; the server task lives for the rest of the test process.
async fn spawn_stub_backend() -> SocketAddr {
    async fn list_enclaves() -> Json<serde_json::Value> {
        Json(serde_json::json!([
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "demo",
                "docker_image": "registry.local/alice/demo:latest",
                "status": "running",
                "instance_type": "small",
                "created_at": "2026-06-20T10:00:00Z"
            }
        ]))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/enclaves", get(list_enclaves));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    addr
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_enclavia")
}

/// Run the binary with a controlled config home (no real credentials leak in)
/// and `ENCLAVIA_BACKEND_URL` cleared so only the written creds drive the URL.
async fn run(config_home: &Path, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(bin())
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("HOME", config_home)
        .env_remove("ENCLAVIA_BACKEND_URL")
        .output()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn list_json_success_emits_single_array_with_keys() {
    let addr = spawn_stub_backend().await;
    let cfg = unique_config_dir();
    write_credentials(&cfg, &format!("http://{addr}"));

    let out = run(&cfg, &["enclave", "list", "--json"]).await;

    assert!(
        out.status.success(),
        "exit: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    // stdout must be exactly one parseable JSON value.
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single JSON value");
    let arr = v.as_array().expect("list --json is a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "11111111-1111-1111-1111-111111111111");
    assert_eq!(arr[0]["status"], "running");
    assert_eq!(arr[0]["name"], "demo");
    assert_eq!(arr[0]["docker_image"], "registry.local/alice/demo:latest");

    cleanup(&cfg);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_human_success_prints_table_not_json() {
    let addr = spawn_stub_backend().await;
    let cfg = unique_config_dir();
    write_credentials(&cfg, &format!("http://{addr}"));

    let out = run(&cfg, &["enclave", "list"]).await;

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Unchanged human table: header + the enclave id.
    assert!(stdout.contains("ID"), "stdout: {stdout}");
    assert!(stdout.contains("NAME"), "stdout: {stdout}");
    assert!(stdout.contains("11111111-1111-1111-1111-111111111111"));
    // The human output is deliberately NOT a single JSON value.
    assert!(serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err());

    cleanup(&cfg);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_json_error_when_not_logged_in() {
    // No credentials written: the client short-circuits with NotLoggedIn
    // before any network call, so no stub backend is needed.
    let cfg = unique_config_dir();

    let out = run(&cfg, &["enclave", "list", "--json"]).await;

    assert!(!out.status.success(), "expected non-zero exit on error");
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("error path is a single JSON value");
    assert_eq!(v["kind"], "not_logged_in");
    assert!(
        v["error"].as_str().unwrap().contains("not logged in"),
        "error: {v}"
    );

    cleanup(&cfg);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_human_error_goes_to_stderr_not_stdout() {
    let cfg = unique_config_dir();

    let out = run(&cfg, &["enclave", "list"]).await;

    assert!(!out.status.success());
    // Human errors stay on stderr; stdout is empty (unchanged behaviour).
    assert!(out.stdout.is_empty(), "stdout should be empty on a human error");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Error:"), "stderr: {stderr}");
    assert!(stderr.contains("not logged in"), "stderr: {stderr}");

    cleanup(&cfg);
}

#[tokio::test(flavor = "multi_thread")]
async fn json_flag_is_global_before_subcommand() {
    // `enclavia --json enclave list` must behave like `... list --json`.
    let cfg = unique_config_dir();

    let out = run(&cfg, &["--json", "enclave", "list"]).await;

    assert!(!out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("error path is a single JSON value");
    assert_eq!(v["kind"], "not_logged_in");

    cleanup(&cfg);
}
