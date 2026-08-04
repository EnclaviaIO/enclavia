//! `enclavia-monitor`: in-enclave management daemon.
//!
//! Runs next to the workload (init launches it after `crun start`) and
//! has two duties:
//!
//! * **Telemetry loop** (guest -> host): every
//!   `$MONITOR_SAMPLE_INTERVAL_SECS` (default 30) it probes the
//!   workload (TCP connect to `127.0.0.1:$WORKLOAD_PORT`; optionally a
//!   hand-rolled HTTP GET of `$HEALTH_PATH` on the same port) and the
//!   data mount (`statvfs` on `$DATA_MOUNT`, default `/data`, only when
//!   it is an actual mountpoint), then dials the host on vsock port
//!   5014 (`enclavia_protocol::monitor::MONITOR_SAMPLE_PORT`) and
//!   writes exactly one length-prefixed CBOR `MonitorSample` frame.
//!   Connect-per-sample keeps the host-side relay trivial. Any failure
//!   to probe or deliver is logged and the loop keeps going: telemetry
//!   must never take the enclave down.
//!
//! * **Shutdown listener** (host -> guest, vsock port 5015,
//!   `MONITOR_SHUTDOWN_PORT`): accepts a connection, reads one
//!   `ShutdownRequest` frame, flushes the data mount (`syncfs` on
//!   `$DATA_MOUNT` is the durability barrier that forces the filesystem
//!   commit, which in turn drives the storage client's superblock pin),
//!   does a global `sync`, attempts a best-effort `umount` (expected to
//!   fail while the workload holds files open; syncfs is the real
//!   guarantee), then writes a `ShutdownAck { synced }` frame back and
//!   keeps running. The host kills the VM after the ack (or after its
//!   own timeout, so images without this daemon still stop cleanly).
//!
//! The host CID is resolved at runtime (`enclavia-vsock::host_cid`: CID
//! 3 on real Nitro, CID 2 under QEMU), so one EIF runs in both worlds.
//! No debug/enclave feature split, per the in-enclave transport
//! conventions.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use enclavia_protocol::monitor::{
    MONITOR_SAMPLE_PORT, MONITOR_SHUTDOWN_PORT, MonitorSample, ShutdownAck, ShutdownRequest,
    read_frame, write_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info, warn};

/// Ceiling on each per-tick probe (TCP connect / HTTP GET) so a wedged
/// workload cannot stall the telemetry loop past its own cadence.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on delivering one sample to the host (vsock connect + write).
/// A healthy host accepts in single-digit milliseconds; this only
/// bounds the damage of a hung host-side relay.
const DELIVER_TIMEOUT: Duration = Duration::from_secs(10);

/// vsock CID the shutdown listener binds (`VMADDR_CID_ANY`, same as
/// `enclavia-server`'s listeners).
const VSOCK_CID_ANY: u32 = u32::MAX;

/// Runtime configuration, read once from the environment at startup.
#[derive(Debug, Clone)]
struct Config {
    /// Loopback port the workload serves on. `None` disables both
    /// probes: `workload_alive` is reported `false` and `http_health`
    /// stays absent (logged once at startup, not per tick).
    workload_port: Option<u16>,
    /// HTTP path to GET for the 2xx health probe. Only meaningful when
    /// `workload_port` is set.
    health_path: Option<String>,
    /// Data mount to report disk usage for and to flush on shutdown.
    data_mount: PathBuf,
    /// Telemetry cadence.
    sample_interval: Duration,
}

impl Config {
    fn from_env() -> Self {
        // Telemetry must never take the enclave down, so a malformed
        // value degrades to "unset" with a warning instead of aborting
        // (unlike egress, where a bad config is a fatal misbuild).
        let workload_port = match std::env::var("WORKLOAD_PORT") {
            Ok(s) => match s.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => {
                    warn!(value = %s, "invalid WORKLOAD_PORT; liveness probes disabled");
                    None
                }
            },
            Err(_) => {
                warn!("WORKLOAD_PORT not set; reporting workload_alive=false and skipping probes");
                None
            }
        };
        let health_path = std::env::var("HEALTH_PATH").ok().filter(|p| !p.is_empty());
        let data_mount =
            PathBuf::from(std::env::var("DATA_MOUNT").unwrap_or_else(|_| "/data".into()));
        let sample_interval = std::env::var("MONITOR_SAMPLE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        Self {
            workload_port,
            health_path,
            data_mount,
            sample_interval,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // Output lands on the serial console; ANSI escapes turn into
        // literal garbage there. Same setting as every other in-enclave
        // daemon.
        .with_ansi(false)
        .init();

    let config = Config::from_env();
    info!(?config, "starting enclavia-monitor");

    let shutdown_mount = config.data_mount.clone();
    let shutdown_task = tokio::spawn(shutdown_listener(shutdown_mount));

    let telemetry_task = tokio::spawn(telemetry_loop(config));

    // Both tasks are loop-forever; either one returning means something
    // went unrecoverably wrong (e.g. the vsock listener could not bind).
    // Exit nonzero so the failure is visible on the console, but note
    // init does NOT restart us: a dead monitor never harms the workload.
    tokio::select! {
        r = shutdown_task => error!(?r, "shutdown listener task ended"),
        r = telemetry_task => error!(?r, "telemetry loop task ended"),
    }
    std::process::exit(1);
}

// ---------------------------------------------------------------------
// Telemetry loop
// ---------------------------------------------------------------------

async fn telemetry_loop(config: Config) {
    let start = tokio::time::Instant::now();
    let mut ticker = tokio::time::interval(config.sample_interval);
    // A tick that overruns (slow probe + slow delivery) should not be
    // "made up" with a burst afterwards; skip to the next cadence slot.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seq: u64 = 0;

    loop {
        ticker.tick().await;
        let sample = collect_sample(&config, seq, start.elapsed().as_secs()).await;
        seq = seq.wrapping_add(1);
        if let Err(e) = deliver_sample(&sample).await {
            // Never crash the enclave over telemetry: log and keep
            // looping (the host relay may simply not be up yet).
            warn!(seq = sample.seq, "delivering monitor sample: {e}");
        }
    }
}

/// Probe the workload and the data mount and assemble one sample.
async fn collect_sample(config: &Config, seq: u64, uptime_s: u64) -> MonitorSample {
    let (workload_alive, http_health) = match config.workload_port {
        Some(port) => {
            let alive = tcp_alive(port).await;
            let health = match (&config.health_path, alive) {
                // An unreachable workload cannot be healthy; skip the
                // GET rather than timing out a second time.
                (Some(path), true) => Some(http_health_probe(port, path).await),
                (Some(_), false) => Some(false),
                (None, _) => None,
            };
            (alive, health)
        }
        None => (false, None),
    };

    let (disk_used_bytes, disk_total_bytes) = match disk_usage(&config.data_mount) {
        Some((used, total)) => (Some(used), Some(total)),
        None => (None, None),
    };

    MonitorSample {
        seq,
        uptime_s,
        workload_alive,
        http_health,
        disk_used_bytes,
        disk_total_bytes,
    }
}

/// TCP connect to the workload's loopback port; accepting == alive.
async fn tcp_alive(port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            PROBE_TIMEOUT,
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await,
        Ok(Ok(_))
    )
}

/// GET `path` on the workload's loopback port and report 2xx-ness.
/// Any connect/write/read/parse failure is `false`.
async fn http_health_probe(port: u16, path: &str) -> bool {
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        http_health_over(&mut stream, path).await
    };
    match tokio::time::timeout(PROBE_TIMEOUT, fut).await {
        Ok(Ok(healthy)) => healthy,
        Ok(Err(e)) => {
            warn!(port, path, "http health probe failed: {e}");
            false
        }
        Err(_) => {
            warn!(port, path, "http health probe timed out");
            false
        }
    }
}

/// Hand-rolled HTTP/1.1 GET over an already-connected stream, returning
/// whether the status line reports a 2xx.
///
/// Deliberately minimal (no reqwest/hyper: the in-enclave binaries stay
/// small and this only needs the status line). `Connection: close` lets
/// us read to EOF without chunked-body parsing; we stop as soon as the
/// status line is complete anyway.
async fn http_health_over<S>(stream: &mut S, path: &str) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Read until the status line (first CRLF) is in the buffer. 1 KiB
    // is far beyond any legitimate status line.
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        if buf.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no status line within 1024 bytes",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before status line",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("loop above guarantees a CRLF");
    let line = String::from_utf8_lossy(&buf[..line_end]);
    Ok(parse_status_is_2xx(&line))
}

/// Parse an HTTP/1.x status line ("HTTP/1.1 200 OK") and report whether
/// the status code is 2xx. Malformed lines are not healthy.
fn parse_status_is_2xx(line: &str) -> bool {
    let mut parts = line.split_ascii_whitespace();
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.starts_with("HTTP/1.") {
        return false;
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

/// `(used_bytes, total_bytes)` for `path`, or `None` when `path` is not
/// a mountpoint (absent mount = no disk field in the sample).
fn disk_usage(path: &Path) -> Option<(u64, u64)> {
    if !is_mountpoint(path) {
        return None;
    }
    match statvfs_bytes(path) {
        Ok(pair) => Some(pair),
        Err(e) => {
            warn!(path = %path.display(), "statvfs failed: {e}");
            None
        }
    }
}

/// A path is a mountpoint when it sits on a different device than its
/// parent directory (the classic `mountpoint(1)` check). The enclave
/// root itself is never the data mount, so the root edge case (parent
/// == self) correctly reads as "not a mountpoint" here.
fn is_mountpoint(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(parent_meta) = std::fs::metadata(path.join("..")) else {
        return false;
    };
    meta.dev() != parent_meta.dev()
}

/// `statvfs` the path: total = `f_blocks * f_frsize`, used =
/// `(f_blocks - f_bfree) * f_frsize`. `f_bfree` (root-reserved
/// included) rather than `f_bavail`: we report the filesystem's own
/// occupancy, not a user-visible quota.
fn statvfs_bytes(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let frsize = st.f_frsize as u64;
    let total = (st.f_blocks as u64).saturating_mul(frsize);
    let used = (st.f_blocks as u64)
        .saturating_sub(st.f_bfree as u64)
        .saturating_mul(frsize);
    Ok((used, total))
}

/// Dial the host and deliver one sample frame (single-shot connection).
async fn deliver_sample(sample: &MonitorSample) -> io::Result<()> {
    let cid = enclavia_vsock::host_cid().await;
    let fut = async {
        let mut stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            cid,
            MONITOR_SAMPLE_PORT,
        ))
        .await?;
        write_frame(&mut stream, sample).await?;
        // Signal EOF to the host relay (single-shot exchange: one
        // frame, no response expected).
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok::<_, io::Error>(())
    };
    tokio::time::timeout(DELIVER_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sample delivery timed out"))?
}

// ---------------------------------------------------------------------
// Shutdown listener
// ---------------------------------------------------------------------

async fn shutdown_listener(data_mount: PathBuf) {
    let listener = match tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
        VSOCK_CID_ANY,
        MONITOR_SHUTDOWN_PORT,
    )) {
        Ok(l) => l,
        Err(e) => {
            error!("binding shutdown listener on vsock port {MONITOR_SHUTDOWN_PORT}: {e}");
            return;
        }
    };
    info!(
        port = MONITOR_SHUTDOWN_PORT,
        "shutdown listener on vsock (CID any)"
    );

    loop {
        let (mut stream, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accepting shutdown connection: {e}");
                continue;
            }
        };
        info!(?addr, "shutdown connection accepted");
        let mount = data_mount.clone();
        // Connections are handled inline (no spawn): shutdown is a
        // one-at-a-time affair and serializing the flushes is the
        // safer behavior if the host ever double-dials.
        if let Err(e) = handle_shutdown_conn(&mut stream, move || flush_data_mount(&mount)).await {
            warn!("shutdown exchange failed: {e}");
        }
    }
}

/// One shutdown exchange: read the request frame, run the flush, write
/// the ack. Generic over the stream and the flush action for testing.
async fn handle_shutdown_conn<S, F>(stream: &mut S, flush: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> bool + Send + 'static,
{
    let _req: ShutdownRequest = read_frame(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    info!("shutdown request received; flushing data mount");

    // syncfs/sync can legitimately block for a while (they wait for the
    // filesystem commit); keep the runtime responsive.
    let synced = tokio::task::spawn_blocking(flush)
        .await
        .unwrap_or_else(|e| {
            error!("flush task panicked: {e}");
            false
        });

    info!(synced, "flush finished; acking shutdown");
    write_frame(stream, &ShutdownAck { synced }).await?;
    stream.flush().await?;
    Ok(())
}

/// Flush the data mount for shutdown. Returns whether the durability
/// barrier (`syncfs` on the mount) succeeded; when the mount is absent
/// there is nothing to lose and the global `sync` alone counts as
/// success.
fn flush_data_mount(mount: &Path) -> bool {
    let synced = if is_mountpoint(mount) {
        match syncfs_path(mount) {
            Ok(()) => true,
            Err(e) => {
                error!(mount = %mount.display(), "syncfs failed: {e}");
                false
            }
        }
    } else {
        info!(mount = %mount.display(), "no data mount present; skipping syncfs");
        true
    };

    // Global sync as belt-and-braces for anything outside the data
    // mount. Cannot fail (void return).
    unsafe { libc::sync() };

    // Best-effort umount: expected to fail with EBUSY while the
    // workload holds files open; syncfs above is the real durability
    // guarantee, so the outcome does not affect the ack.
    if is_mountpoint(mount) {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c_path) = std::ffi::CString::new(mount.as_os_str().as_bytes()) {
            let rc = unsafe { libc::umount2(c_path.as_ptr(), 0) };
            if rc == 0 {
                info!(mount = %mount.display(), "data mount unmounted");
            } else {
                let e = io::Error::last_os_error();
                info!(mount = %mount.display(), "best-effort umount declined (expected while workload runs): {e}");
            }
        }
    }

    synced
}

/// `syncfs(2)` on the filesystem containing `path`.
fn syncfs_path(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(path)?;
    let rc = unsafe { libc::syncfs(dir.as_raw_fd()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_parsing() {
        assert!(parse_status_is_2xx("HTTP/1.1 200 OK"));
        assert!(parse_status_is_2xx("HTTP/1.0 204 No Content"));
        assert!(parse_status_is_2xx("HTTP/1.1 299"));
        assert!(!parse_status_is_2xx("HTTP/1.1 301 Moved Permanently"));
        assert!(!parse_status_is_2xx("HTTP/1.1 500 Internal Server Error"));
        assert!(!parse_status_is_2xx("HTTP/1.1 abc"));
        assert!(!parse_status_is_2xx("HTTP/1.1"));
        assert!(!parse_status_is_2xx("SIP/2.0 200 OK"));
        assert!(!parse_status_is_2xx(""));
    }

    #[tokio::test]
    async fn http_health_over_2xx() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let probe = tokio::spawn(async move { http_health_over(&mut client, "/healthz").await });

        // Read the request, assert its shape, answer 200.
        let mut req = vec![0u8; 1024];
        let n = server.read(&mut req).await.unwrap();
        let req = String::from_utf8_lossy(&req[..n]).into_owned();
        assert!(req.starts_with("GET /healthz HTTP/1.1\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        assert!(probe.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn http_health_over_5xx() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let probe = tokio::spawn(async move { http_health_over(&mut client, "/healthz").await });
        let mut req = vec![0u8; 1024];
        let _ = server.read(&mut req).await.unwrap();
        server
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            .await
            .unwrap();
        assert!(!probe.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn http_health_over_eof_is_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let probe = tokio::spawn(async move { http_health_over(&mut client, "/healthz").await });
        let mut req = vec![0u8; 1024];
        let _ = server.read(&mut req).await.unwrap();
        drop(server);
        assert!(probe.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn shutdown_exchange_acks_flush_result() {
        for flush_result in [true, false] {
            let (mut host, mut guest) = tokio::io::duplex(1024);
            let handler = tokio::spawn(async move {
                handle_shutdown_conn(&mut guest, move || flush_result).await
            });

            write_frame(&mut host, &ShutdownRequest {}).await.unwrap();
            let ack: ShutdownAck = read_frame(&mut host).await.unwrap();
            assert_eq!(ack.synced, flush_result);
            handler.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown_garbage_frame_is_error_and_no_flush() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        let handler = tokio::spawn(async move {
            handle_shutdown_conn(&mut guest, || panic!("flush must not run on a bad frame")).await
        });
        // An oversized length prefix must fail the exchange before the
        // flush action runs.
        host.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(handler.await.unwrap().is_err());
    }

    #[test]
    fn disk_usage_none_for_non_mountpoint() {
        // A temp dir sits on the same device as its parent, so it must
        // read as "no data mount" rather than reporting the host fs.
        let dir = std::env::temp_dir();
        assert_eq!(disk_usage(&dir), None);
    }

    #[test]
    fn statvfs_reports_sane_bytes() {
        // statvfs itself (below the mountpoint gate) must return a
        // consistent pair on any real filesystem.
        let (used, total) = statvfs_bytes(Path::new("/")).unwrap();
        assert!(total > 0);
        assert!(used <= total);
    }

    #[test]
    fn is_mountpoint_root_edge_case() {
        // "/" has itself as parent (same device), so the check reads it
        // as not-a-mountpoint; the data mount is never "/" so this is
        // the behavior we want.
        assert!(!is_mountpoint(Path::new("/")));
        assert!(!is_mountpoint(Path::new(
            "/nonexistent-enclavia-monitor-test"
        )));
    }
}
