//! `enclavia deploy`: the watch half of the create, push, build,
//! running pipeline. After `main` has created the enclave and pushed the
//! image, [`watch_until_running`] follows the enclave's status, streams the
//! build log as it grows, and returns the final row once the enclave is
//! `running` (or fails with the backend's error and the log tail).
//!
//! This is a CLI-binary-only convenience for humans, like `push`: it prints
//! directly to the terminal and animates a spinner when one is attached.
//! Agents and the MCP server should keep using `create` + `push` +
//! `status` polling (the agent skill documents that flow); a spinner over
//! a long-lived connection is exactly what a machine caller doesn't want.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use crate::api::ApiClient;
use crate::error::CliError;

/// Overall watch ceiling. `waiting_for_image` alone may take up to 30
/// minutes server-side before the backend times it out to `error`, and a
/// large build adds more. Hitting this stops the WATCH, not the build: the
/// backend carries on, and `enclave status` picks up where we left off.
const WATCH_TIMEOUT: Duration = Duration::from_secs(45 * 60);
/// Status poll cadence.
const STATUS_EVERY: Duration = Duration::from_secs(2);
/// Build-log poll cadence (only while a build is in flight).
const LOGS_EVERY: Duration = Duration::from_secs(3);
/// Spinner redraw cadence.
const SPINNER_EVERY: Duration = Duration::from_millis(120);
/// How many consecutive failed status polls we tolerate before giving up
/// (transient network blips shouldn't kill a 10-minute watch).
const MAX_POLL_FAILURES: u32 = 5;

/// Follow enclave `id` until it reaches `running`, printing status
/// transitions and streaming the build log. Returns the final enclave row.
///
/// In `--json` mode all progress goes to stderr (stdout stays reserved for
/// the caller's single JSON value) and the spinner is disabled.
pub async fn watch_until_running(
    client: &ApiClient,
    id: &str,
    json: bool,
) -> Result<serde_json::Value, CliError> {
    let started = Instant::now();
    let mut spinner = Spinner::new(!json && std::io::stdout().is_terminal());
    let say = |msg: &str| {
        if json {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
    };

    let mut phase = String::new();
    let mut row = serde_json::Value::Null;
    let mut poll_failures = 0u32;
    let mut last_status_poll: Option<Instant> = None;
    let mut last_logs_poll: Option<Instant> = None;
    // Byte offset into `build_log` up to which we've already printed.
    let mut log_printed = 0usize;

    loop {
        if started.elapsed() > WATCH_TIMEOUT {
            spinner.clear();
            return Err(CliError::Other(format!(
                "gave up watching after {}; the build/launch continues server-side; check \
                 `enclavia enclave status {id}`",
                fmt_elapsed(WATCH_TIMEOUT)
            )));
        }

        if last_status_poll.is_none_or(|t| t.elapsed() >= STATUS_EVERY) {
            last_status_poll = Some(Instant::now());
            match client.get_enclave(id).await {
                Ok(r) => {
                    poll_failures = 0;
                    row = r;
                }
                Err(e) => {
                    poll_failures += 1;
                    if poll_failures >= MAX_POLL_FAILURES {
                        spinner.clear();
                        return Err(CliError::Other(format!(
                            "lost contact with the backend while watching ({e}); the \
                             build/launch continues server-side; check \
                             `enclavia enclave status {id}`"
                        )));
                    }
                }
            }
            let status = row["status"].as_str().unwrap_or("").to_string();
            if !status.is_empty() && status != phase {
                spinner.clear();
                match status.as_str() {
                    "waiting_for_image" => {
                        say("Waiting for the backend to pick up the pushed image...");
                    }
                    "building" => say("Build started; streaming the build log:"),
                    "deploying" => say("Build complete; launching the enclave..."),
                    _ => {}
                }
                phase = status.clone();
            }
            match status.as_str() {
                "running" => {
                    // Drain whatever build log we hadn't printed yet, so the
                    // transcript is complete even when the tail landed
                    // between our last logs poll and the flip to running.
                    stream_new_log(client, id, &mut log_printed, &mut spinner, json, true).await;
                    spinner.clear();
                    return Ok(row);
                }
                "error" => {
                    stream_new_log(client, id, &mut log_printed, &mut spinner, json, true).await;
                    spinner.clear();
                    let detail = row["error_message"]
                        .as_str()
                        .or_else(|| row["status_detail"].as_str())
                        .unwrap_or("no error detail recorded");
                    return Err(CliError::Other(format!(
                        "deploy failed: {detail}\n  full logs: enclavia enclave logs {id}"
                    )));
                }
                // A concurrent stop/destroy from another session. Not our
                // error to swallow silently, but not a build failure either.
                "stopped" | "destroyed" => {
                    spinner.clear();
                    return Err(CliError::Other(format!(
                        "enclave moved to `{status}` while deploying (stopped or destroyed \
                         from elsewhere?); check `enclavia enclave status {id}`"
                    )));
                }
                _ => {}
            }
        }

        // Stream build-log growth while a build is in flight (and just
        // after, while `deploying`, in case the flip beat our last poll).
        if matches!(phase.as_str(), "building" | "deploying")
            && last_logs_poll.is_none_or(|t| t.elapsed() >= LOGS_EVERY)
        {
            last_logs_poll = Some(Instant::now());
            stream_new_log(client, id, &mut log_printed, &mut spinner, json, false).await;
        }

        spinner.tick(&phase, started.elapsed());
        tokio::time::sleep(SPINNER_EVERY).await;
    }
}

/// Print the human epilogue for a successful deploy: endpoint, PCRs, and
/// elapsed time, mirroring the fields of `enclave status` a first-time user
/// needs next.
pub fn print_deployed(row: &serde_json::Value, elapsed: Duration) {
    println!();
    println!("✓ Deployed in {}", fmt_elapsed(elapsed));
    println!();
    println!("  ID:       {}", row["id"].as_str().unwrap_or("-"));
    if let Some(name) = row["name"].as_str() {
        println!("  Name:     {name}");
    }
    if let Some(endpoint) = row["endpoint"].as_str() {
        println!("  Endpoint: {endpoint}");
    }
    if let Some(pcrs) = row["pcrs"].as_object() {
        println!("  PCRs (pin these in your client):");
        for (k, v) in pcrs {
            println!("    {k}: {}", v.as_str().unwrap_or("-"));
        }
    }
}

/// Fetch the build log and print any complete lines we haven't shown yet.
/// Best-effort: a failed logs fetch never interrupts the watch. Holds back
/// a trailing partial line until it's newline-terminated, unless `drain`
/// (terminal state: print everything we have).
async fn stream_new_log(
    client: &ApiClient,
    id: &str,
    printed: &mut usize,
    spinner: &mut Spinner,
    json: bool,
    drain: bool,
) {
    let Ok(logs) = client.get_enclave_logs(id).await else {
        return;
    };
    let Some(build_log) = logs["build_log"].as_str() else {
        return;
    };
    // A shrinking log means the backend restarted the build (or the field
    // was rewritten); start over rather than slicing out of bounds.
    if build_log.len() < *printed {
        *printed = 0;
    }
    let new = &build_log[*printed..];
    let upto = if drain {
        new.len()
    } else {
        match new.rfind('\n') {
            Some(i) => i + 1,
            None => return,
        }
    };
    if upto == 0 {
        return;
    }
    spinner.clear();
    for line in new[..upto].lines() {
        if json {
            eprintln!("  {line}");
        } else {
            println!("  {line}");
        }
    }
    *printed += upto;
}

/// Single-line terminal spinner: `⠹ building (1m23s)`, redrawn in place on
/// stdout. Disabled (all methods no-op) when stdout isn't a terminal or the
/// caller is in `--json` mode, so piped output stays clean.
struct Spinner {
    enabled: bool,
    frame: usize,
    /// Whether the spinner line is currently on screen (needs clearing
    /// before any regular output).
    drawn: bool,
}

const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

impl Spinner {
    fn new(enabled: bool) -> Self {
        Spinner {
            enabled,
            frame: 0,
            drawn: false,
        }
    }

    fn tick(&mut self, phase: &str, elapsed: Duration) {
        if !self.enabled {
            return;
        }
        let c = FRAMES[self.frame % FRAMES.len()];
        self.frame += 1;
        let label = if phase.is_empty() { "starting" } else { phase };
        // \r + clear-to-end redraws in place without a full-line erase flash.
        print!("\r\x1b[2K{c} {label} ({})", fmt_elapsed(elapsed));
        let _ = std::io::stdout().flush();
        self.drawn = true;
    }

    /// Erase the spinner line so regular output starts at column 0.
    fn clear(&mut self) {
        if self.enabled && self.drawn {
            print!("\r\x1b[2K");
            let _ = std::io::stdout().flush();
            self.drawn = false;
        }
    }
}

/// `95s` → `1m35s`; sub-minute stays `42s`.
fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else {
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_elapsed_formats() {
        assert_eq!(fmt_elapsed(Duration::from_secs(42)), "42s");
        assert_eq!(fmt_elapsed(Duration::from_secs(95)), "1m35s");
        assert_eq!(fmt_elapsed(Duration::from_secs(600)), "10m00s");
    }
}
