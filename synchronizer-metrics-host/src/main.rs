//! `synchronizer-metrics-host`: reference receiver for synchronizer metrics.
//!
//! Runs on a synchronizer node's parent instance. Listens on vsock
//! (`VMADDR_CID_ANY`, port 5014 by default) or on a Unix socket (`--uds`,
//! for QEMU's `vhost-device-vsock` bridge, which exposes a guest's
//! connection to host port P as `<uds-path>_P`). Each connection carries
//! one frame; the receiver reads it within a bound, never writes back, and
//! renders the sample to a Prometheus textfile (default
//! `/var/lib/prometheus-node-exporter-text/enclavia_synchronizer.prom`). A
//! bad connection is logged and dropped; the previous file stays in place.
//! If no valid sample arrives for `--stale-after-secs` (default 60), the
//! file is removed, so a dead node shows up as absent series rather than
//! frozen values.
//!
//! ```text
//! synchronizer-metrics-host [--vsock-port N | --uds PATH] [--output FILE]
//!                           [--stale-after-secs N]
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use synchronizer_metrics_host::{RECEIVE_TIMEOUT, receive, render, write_atomic};
use tracing::{debug, error, info, warn};

const DEFAULT_OUTPUT: &str = "/var/lib/prometheus-node-exporter-text/enclavia_synchronizer.prom";
const VMADDR_CID_ANY: u32 = u32::MAX;

enum Listen {
    Vsock(u32),
    Uds(PathBuf),
}

struct Args {
    listen: Listen,
    output: PathBuf,
    stale_after: Duration,
}

fn usage() -> ! {
    eprintln!(
        "usage: synchronizer-metrics-host [--vsock-port N | --uds PATH] [--output FILE] \
         [--stale-after-secs N]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut listen = Listen::Vsock(enclavia_protocol::synchronizer_metrics::SYNCHRONIZER_METRICS_PORT);
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut stale_after = Duration::from_secs(60);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--vsock-port" => listen = Listen::Vsock(value().parse().unwrap_or_else(|_| usage())),
            "--uds" => listen = Listen::Uds(PathBuf::from(value())),
            "--output" => output = PathBuf::from(value()),
            "--stale-after-secs" => {
                stale_after = Duration::from_secs(value().parse().unwrap_or_else(|_| usage()))
            }
            _ => usage(),
        }
    }
    Args {
        listen,
        output,
        stale_after,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Read one sample from `stream` and publish it. Never writes to `stream`.
async fn handle<S>(mut stream: S, output: &Path) -> bool
where
    S: tokio::io::AsyncRead + Unpin,
{
    match receive(&mut stream, RECEIVE_TIMEOUT).await {
        Ok(sample) => {
            let text = render(&sample, now_unix_ms());
            match write_atomic(output, &text) {
                Ok(()) => {
                    debug!(node = %sample.node, seq = sample.seq, "sample written");
                    true
                }
                Err(e) => {
                    error!(path = %output.display(), error = %e, "writing the textfile failed");
                    false
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "dropping connection without a valid sample");
            false
        }
    }
}

fn remove_stale(output: &Path) {
    match std::fs::remove_file(output) {
        Ok(()) => warn!(path = %output.display(), "no valid sample recently; removed the textfile"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => error!(path = %output.display(), error = %e, "removing the stale textfile failed"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = parse_args();

    // Connections are handled one at a time, each bounded by
    // RECEIVE_TIMEOUT: the node sends one frame every 15 s.
    match args.listen {
        Listen::Vsock(port) => {
            let listener = match tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
                VMADDR_CID_ANY,
                port,
            )) {
                Ok(l) => l,
                Err(e) => {
                    error!(port, error = %e, "binding the vsock listener failed");
                    std::process::exit(1);
                }
            };
            info!(port, output = %args.output.display(), "listening on vsock");
            let mut last_valid = tokio::time::Instant::now();
            loop {
                match tokio::time::timeout(args.stale_after, listener.accept()).await {
                    Ok(Ok((stream, _))) => {
                        if handle(stream, &args.output).await {
                            last_valid = tokio::time::Instant::now();
                        }
                    }
                    Ok(Err(e)) => warn!(error = %e, "accept failed"),
                    Err(_) => {}
                }
                if last_valid.elapsed() >= args.stale_after {
                    remove_stale(&args.output);
                }
            }
        }
        Listen::Uds(path) => {
            let _ = std::fs::remove_file(&path);
            let listener = match tokio::net::UnixListener::bind(&path) {
                Ok(l) => l,
                Err(e) => {
                    error!(path = %path.display(), error = %e, "binding the Unix listener failed");
                    std::process::exit(1);
                }
            };
            info!(path = %path.display(), output = %args.output.display(), "listening on Unix socket");
            let mut last_valid = tokio::time::Instant::now();
            loop {
                match tokio::time::timeout(args.stale_after, listener.accept()).await {
                    Ok(Ok((stream, _))) => {
                        if handle(stream, &args.output).await {
                            last_valid = tokio::time::Instant::now();
                        }
                    }
                    Ok(Err(e)) => warn!(error = %e, "accept failed"),
                    Err(_) => {}
                }
                if last_valid.elapsed() >= args.stale_after {
                    remove_stale(&args.output);
                }
            }
        }
    }
}
