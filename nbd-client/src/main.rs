#[allow(dead_code)]
mod nbd;
mod rollback;

use std::collections::HashMap;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/// Configuration parsed from environment variables.
struct Config {
    device: PathBuf,
    block_size: u32,
    /// Offset (in bytes) of the dm-crypt data area within the NBD export.
    /// Btrfs superblock offsets are relative to /dev/mapper/encdata, so we
    /// translate them by this amount before checking against NBD write offsets.
    /// LUKS2's default with cryptsetup ≥ 2.0 places data at 16 MiB.
    luks_data_offset: u64,
    vsock_port: u32,
    /// Opt-in anti-rollback wiring (#16): when true (SYNCHRONIZER_ENABLED=1),
    /// boot-time superblock verification against the synchronizer cluster is
    /// mandatory before serving, and every primary-superblock write gates its
    /// NBD reply on a durable Pin ack. When false, nothing about the legacy
    /// data path changes.
    synchronizer_enabled: bool,
}

impl Config {
    fn from_env() -> Self {
        let device =
            PathBuf::from(std::env::var("NBD_DEVICE").unwrap_or_else(|_| "/dev/nbd0".into()));
        let block_size: u32 = std::env::var("NBD_BLOCK_SIZE")
            .unwrap_or_else(|_| "4096".into())
            .parse()
            .expect("invalid NBD_BLOCK_SIZE");
        let luks_data_offset: u64 = std::env::var("LUKS_DATA_OFFSET")
            .unwrap_or_else(|_| "16777216".into())
            .parse()
            .expect("invalid LUKS_DATA_OFFSET");

        let vsock_port: u32 = std::env::var("VSOCK_PORT")
            .unwrap_or_else(|_| "5001".into())
            .parse()
            .expect("invalid VSOCK_PORT");

        Self {
            device,
            block_size,
            luks_data_offset,
            vsock_port,
            synchronizer_enabled: rollback::synchronizer_enabled(),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    let config = Config::from_env();

    if let Err(e) = run(config).await {
        error!("Fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Connect to the host storage daemon over vsock. The host CID is
    // resolved at runtime (CID 3 on real Nitro, CID 2 under QEMU) so one EIF
    // boots in both -- read from the value the init recorded at boot. See
    // enclavia_vsock::host_cid.
    let cid = enclavia_vsock::host_cid().await;
    info!(
        cid,
        port = config.vsock_port,
        "Connecting to storage host via vsock"
    );
    let mut stream = tokio_vsock::VsockStream::connect(cid, config.vsock_port).await?;

    // 2. Perform NBD newstyle negotiation.
    let export_info = negotiate(&mut stream).await?;
    info!(
        size = export_info.size,
        flags = export_info.flags,
        "NBD negotiation complete"
    );

    // 2b. Anti-rollback boot verification (#16, opt-in via
    //     SYNCHRONIZER_ENABLED). MUST complete before the kernel gets the
    //     device: connect + attest to the synchronizer, read the primary
    //     btrfs superblock region directly off the host stream, and run
    //     the decision table. Any failure aborts run() and the device is
    //     never served (fail-stop; see rollback.rs for the policy).
    let sync_session = if config.synchronizer_enabled {
        info!("Synchronizer anti-rollback wiring enabled; verifying superblock before serving");
        Some(
            rollback::boot(&mut stream, config.luks_data_offset)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { e })?,
        )
    } else {
        None
    };

    // 3. Create a Unix socketpair. One half goes to the kernel via NBD_SET_SOCK;
    //    the other half is held in userspace so we can sit between the kernel
    //    and the host, parsing the NBD wire format. The kernel doesn't care
    //    about the address family — it just does kernel_sendmsg / kernel_recvmsg.
    let (kernel_side_fd, proxy_side) = make_socketpair()?;

    // 4. Open the NBD device and configure it via ioctls.
    let nbd_fd = open_nbd_device(&config.device)?;

    info!(device = %config.device.display(), "Configuring NBD device");

    unsafe {
        nbd_ioctl(
            nbd_fd,
            nbd::NBD_SET_BLKSIZE,
            config.block_size as libc::c_ulong,
        )?;
        nbd_ioctl(nbd_fd, nbd::NBD_SET_SIZE, export_info.size as libc::c_ulong)?;
        nbd_ioctl(
            nbd_fd,
            nbd::NBD_SET_FLAGS,
            export_info.flags as libc::c_ulong,
        )?;
        // Kernel takes a refcount on the file via fget(); our fd can be closed.
        nbd_ioctl(nbd_fd, nbd::NBD_SET_SOCK, kernel_side_fd as libc::c_ulong)?;
        libc::close(kernel_side_fd);
    }

    info!(
        luks_data_offset = config.luks_data_offset,
        "NBD device configured, starting userspace proxy + kernel I/O"
    );

    // 5. Split the host stream and the proxy-side socket so the two directions
    //    of the NBD transmission phase can run as independent tasks. Inflight
    //    request lengths are shared so the host→kernel side knows how many
    //    payload bytes follow each read reply.
    let (host_read, host_write) = tokio::io::split(stream);
    let proxy_std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(proxy_side) };
    proxy_std.set_nonblocking(true)?;
    let proxy_async = tokio::net::UnixStream::from_std(proxy_std)?;
    let (proxy_read, proxy_write) = tokio::io::split(proxy_async);

    let inflight = Arc::new(Mutex::new(HashMap::<u64, u32>::new()));
    let data_offset = config.luks_data_offset;

    // With the synchronizer wiring enabled, the reply path runs the gated
    // pump plus a pin actor; without it, the legacy proxies run untouched.
    let (sync_hooks, rep_task, pin_task) = match sync_session {
        Some(session) => {
            let gate = Arc::new(rollback::PinGate::new());
            let (pin_tx, pin_rx) = tokio::sync::mpsc::channel::<rollback::PinJob>(64);
            let (nudge_tx, nudge_rx) = tokio::sync::mpsc::unbounded_channel();
            let hooks = rollback::SyncHooks {
                gate: gate.clone(),
                pin_tx,
            };
            let inflight_rep = inflight.clone();
            let rep_task = tokio::spawn(rollback::gated_reply_proxy(
                host_read,
                proxy_write,
                inflight_rep,
                gate.clone(),
                nudge_rx,
            ));
            let pinner = rollback::into_pinner(session);
            let pin_task = tokio::spawn(rollback::pin_actor(pinner, gate, pin_rx, nudge_tx));
            (Some(hooks), rep_task, Some(pin_task))
        }
        None => {
            let inflight_rep = inflight.clone();
            let rep_task = tokio::spawn(reply_proxy(host_read, proxy_write, inflight_rep));
            (None, rep_task, None)
        }
    };

    let inflight_req = inflight.clone();
    let req_task = tokio::spawn(request_proxy(
        proxy_read,
        host_write,
        inflight_req,
        data_offset,
        sync_hooks,
    ));

    // 6. NBD_DO_IT blocks until the device is disconnected.
    let nbd_fd_copy = nbd_fd;
    let do_it_handle = tokio::task::spawn_blocking(move || unsafe {
        // `as _`: glibc declares the ioctl request as c_ulong, musl as
        // c_int; let the cast follow whichever libc we're built against.
        let ret = libc::ioctl(nbd_fd_copy, nbd::NBD_DO_IT as _);
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // ENOTCONN is normal on disconnect.
            if err.raw_os_error() != Some(libc::ENOTCONN) {
                error!("NBD_DO_IT returned error: {err}");
            }
        }
        ret
    });

    // Wait for either NBD_DO_IT to return, a proxy task to fail, or SIGTERM/SIGINT.
    let mut proxy_error: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    tokio::select! {
        result = do_it_handle => {
            match result {
                Ok(_) => info!("NBD device disconnected"),
                Err(e) => error!("NBD task panicked: {e}"),
            }
        }
        result = async {
            match pin_task {
                Some(pin) => tokio::try_join!(flatten(req_task), flatten(rep_task), flatten(pin))
                    .map(|_| ()),
                None => tokio::try_join!(flatten(req_task), flatten(rep_task)).map(|_| ()),
            }
        } => {
            if let Err(e) = result {
                error!("Proxy task ended: {e}");
                proxy_error = Some(e);
            }
            unsafe {
                let _ = nbd_ioctl(nbd_fd, nbd::NBD_DISCONNECT, 0);
                let _ = nbd_ioctl(nbd_fd, nbd::NBD_CLEAR_SOCK, 0);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Signal received, disconnecting NBD device");
            unsafe {
                let _ = nbd_ioctl(nbd_fd, nbd::NBD_DISCONNECT, 0);
                let _ = nbd_ioctl(nbd_fd, nbd::NBD_CLEAR_SOCK, 0);
            }
        }
    }

    // Cleanup
    unsafe {
        let _ = nbd_ioctl(nbd_fd, nbd::NBD_CLEAR_QUE, 0);
        let _ = nbd_ioctl(nbd_fd, nbd::NBD_CLEAR_SOCK, 0);
        libc::close(nbd_fd);
    }

    // Fail-stop: with the synchronizer wiring enabled, a proxy / pin
    // failure must surface as a non-zero exit so the supervisor never
    // treats an unprotected teardown as a clean stop. Without the wiring,
    // keep the historical log-and-exit-clean behavior.
    if let Some(e) = proxy_error {
        if config.synchronizer_enabled {
            return Err(format!("fatal proxy/synchronizer failure: {e}").into());
        }
    }

    Ok(())
}

async fn flatten<T>(
    handle: tokio::task::JoinHandle<Result<T, Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    match handle.await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(Box::new(e)),
    }
}

/// Forward NBD requests from the kernel side to the host, parsing each header
/// and logging writes that touch a btrfs superblock offset.
///
/// When `sync_hooks` is set (synchronizer wiring enabled), a write that
/// covers the primary superblock region is additionally hashed on the way
/// through: its handle is gated BEFORE the request is forwarded (so the
/// reply pump holds the eventual reply), the region's new ciphertext is
/// extracted while streaming, and a PinJob is queued for the pin actor.
/// A write that only PARTIALLY covers the region is fatal: its post-write
/// content cannot be derived from the payload (legitimate btrfs
/// superblock writes are whole-block, so this never fires in practice).
///
/// Wire format (kernel → server):
///   magic:   u32  (NBD_REQUEST_MAGIC)
///   flags:   u16
///   type:    u16
///   handle:  u64
///   offset:  u64
///   length:  u32
///   payload: [u8; length]   // only present for NBD_CMD_WRITE
async fn request_proxy<R, W>(
    mut from_kernel: R,
    mut to_host: W,
    inflight: Arc<Mutex<HashMap<u64, u32>>>,
    data_offset: u64,
    sync_hooks: Option<rollback::SyncHooks>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 28];
    loop {
        if let Err(e) = from_kernel.read_exact(&mut header).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                debug!("request_proxy: kernel side EOF");
                return Ok(());
            }
            return Err(Box::new(e));
        }

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != nbd::NBD_REQUEST_MAGIC {
            return Err(format!("bad NBD request magic: {magic:#x}").into());
        }
        let cmd_type = u16::from_be_bytes(header[6..8].try_into().unwrap());
        let handle = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let offset = u64::from_be_bytes(header[16..24].try_into().unwrap());
        let length = u32::from_be_bytes(header[24..28].try_into().unwrap());

        debug!(cmd_type, handle, offset, length, "request");

        // Anti-rollback: classify the write against the primary superblock
        // region and gate its handle BEFORE the request is forwarded, so
        // the gate entry exists before the host can possibly reply.
        let mut sb_capture: Option<usize> = None;
        match cmd_type {
            nbd::NBD_CMD_READ => {
                inflight.lock().unwrap().insert(handle, length);
            }
            nbd::NBD_CMD_WRITE => {
                if let Some(label) = classify_superblock_write(offset, length, data_offset) {
                    debug!(
                        target: "synchronizer",
                        offset, length, %label,
                        "superblock write detected"
                    );
                }
                if let Some(hooks) = &sync_hooks {
                    match rollback::primary_sb_overlap(offset, length, data_offset) {
                        rollback::SbOverlap::None => {}
                        rollback::SbOverlap::Full { payload_offset } => {
                            hooks.gate.begin(handle);
                            sb_capture = Some(payload_offset);
                        }
                        rollback::SbOverlap::Partial => {
                            return Err(format!(
                                "write at offset {offset} (len {length}) partially covers \
                                 the primary btrfs superblock; cannot compute its \
                                 commitment (fail-stop)"
                            )
                            .into());
                        }
                    }
                }
            }
            _ => {}
        }

        to_host.write_all(&header).await?;

        if cmd_type == nbd::NBD_CMD_WRITE && length > 0 {
            match (sb_capture, &sync_hooks) {
                (Some(payload_offset), Some(hooks)) => {
                    // Forward the payload while extracting the superblock
                    // region's new ciphertext, then queue the durable pin.
                    // The NBD reply for `handle` stays parked in the reply
                    // pump until the pin actor reports the cluster's ack.
                    let region = rollback::forward_bytes_extract(
                        &mut from_kernel,
                        &mut to_host,
                        length as u64,
                        payload_offset,
                        rollback::SB_REGION_LEN,
                    )
                    .await?;
                    let commitment = rollback::commitment_of_region(&region);
                    debug!(
                        handle,
                        offset, "superblock write: reply gated on durable pin"
                    );
                    hooks
                        .pin_tx
                        .send(rollback::PinJob { handle, commitment })
                        .await
                        .map_err(|_| {
                            "pin actor is gone; cannot guarantee rollback protection \
                             (fail-stop)"
                        })?;
                }
                _ => {
                    // Forward the write payload. Use a bounded buffer to avoid
                    // a huge alloc on a single oversized request.
                    forward_bytes(&mut from_kernel, &mut to_host, length as u64).await?;
                }
            }
        }

        to_host.flush().await?;

        if cmd_type == nbd::NBD_CMD_DISC {
            return Ok(());
        }
    }
}

/// Forward NBD replies from the host back to the kernel. For READ replies,
/// the server appends `length` payload bytes — we look up the original length
/// keyed by handle to know how many to forward.
///
/// Wire format (server → kernel, simple reply):
///   magic:   u32  (NBD_SIMPLE_REPLY_MAGIC)
///   error:   u32
///   handle:  u64
///   payload: [u8; length]   // only for successful reads
async fn reply_proxy<R, W>(
    mut from_host: R,
    mut to_kernel: W,
    inflight: Arc<Mutex<HashMap<u64, u32>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 16];
    loop {
        if let Err(e) = from_host.read_exact(&mut header).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                debug!("reply_proxy: host side EOF");
                return Ok(());
            }
            return Err(Box::new(e));
        }

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != nbd::NBD_SIMPLE_REPLY_MAGIC {
            return Err(format!("bad NBD reply magic: {magic:#x}").into());
        }
        let error = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let handle = u64::from_be_bytes(header[8..16].try_into().unwrap());

        let read_len = inflight.lock().unwrap().remove(&handle);

        debug!(error, handle, ?read_len, "reply");

        to_kernel.write_all(&header).await?;

        // Successful reads carry a payload; errored reads don't.
        if error == 0 {
            if let Some(len) = read_len {
                forward_bytes(&mut from_host, &mut to_kernel, len as u64).await?;
            }
        } else if read_len.is_some() {
            warn!(error, handle, "NBD read reply errored");
        }

        to_kernel.flush().await?;
    }
}

/// Stream `n` bytes from `src` to `dst` through a fixed-size buffer.
///
/// The chunk size matters: in debug mode the host stream traverses
/// vhost-device-vsock's UDS bridge, which deadlocks on a single `write_all`
/// of ≥ 48 KiB (32 KiB works, 48 KiB hangs indefinitely). 32 KiB stays under
/// that limit and is large enough that per-syscall overhead is negligible
/// for NBD's typical 64–128 KiB writes.
async fn forward_bytes<R, W>(
    src: &mut R,
    dst: &mut W,
    mut n: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 32 * 1024];
    while n > 0 {
        let take = std::cmp::min(n as usize, buf.len());
        src.read_exact(&mut buf[..take]).await?;
        dst.write_all(&buf[..take]).await?;
        n -= take as u64;
    }
    Ok(())
}

/// Btrfs places its primary superblock at 64 KiB and replicates it at fixed
/// further offsets relative to the start of the filesystem.
const BTRFS_SUPERBLOCKS: &[(u64, &str)] = &[
    (0x10000, "btrfs sb#0 (64 KiB)"),
    (0x4000000, "btrfs sb#1 (64 MiB)"),
    (0x4000000000, "btrfs sb#2 (256 GiB)"),
];

/// If `offset..offset+length` (an NBD write) intersects any btrfs superblock
/// region (translated through the LUKS data offset), return its label.
fn classify_superblock_write(offset: u64, length: u32, data_offset: u64) -> Option<&'static str> {
    if offset < data_offset {
        return None;
    }
    let fs_offset = offset - data_offset;
    let fs_end = fs_offset.saturating_add(length as u64);
    const SB_LEN: u64 = 0x1000;
    for &(sb, label) in BTRFS_SUPERBLOCKS {
        if fs_offset < sb + SB_LEN && fs_end > sb {
            return Some(label);
        }
    }
    None
}

/// Create an AF_UNIX SOCK_STREAM socketpair. Returns (a, b) where `a` is the
/// fd handed to the kernel via NBD_SET_SOCK and `b` is the proxy-side fd we
/// keep in userspace.
fn make_socketpair() -> Result<(i32, i32), Box<dyn std::error::Error>> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!("socketpair failed: {}", std::io::Error::last_os_error()).into());
    }
    Ok((fds[0], fds[1]))
}

/// Perform NBD newstyle handshake with the server.
async fn negotiate<S>(stream: &mut S) -> Result<nbd::ExportInfo, Box<dyn std::error::Error>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Read server greeting: NBDMAGIC (8) + IHAVEOPT (8) + handshake flags (2)
    let magic = stream.read_u64().await?;
    if magic != nbd::NBD_MAGIC {
        return Err(format!("bad NBD magic: {magic:#x}").into());
    }

    let opt_magic = stream.read_u64().await?;
    if opt_magic != nbd::IHAVEOPT {
        return Err(format!("bad IHAVEOPT magic: {opt_magic:#x}").into());
    }

    let server_flags = stream.read_u16().await?;
    let no_zeroes = (server_flags & nbd::NBD_FLAG_NO_ZEROES) != 0;

    // Send client flags
    let client_flags: u32 = nbd::NBD_FLAG_C_FIXED_NEWSTYLE
        | if no_zeroes {
            nbd::NBD_FLAG_C_NO_ZEROES
        } else {
            0
        };
    stream.write_all(&client_flags.to_be_bytes()).await?;

    // Send OPT_EXPORT_NAME with empty name (default export)
    stream.write_all(&nbd::IHAVEOPT.to_be_bytes()).await?;
    stream
        .write_all(&nbd::NBD_OPT_EXPORT_NAME.to_be_bytes())
        .await?;
    stream.write_all(&0u32.to_be_bytes()).await?; // data length = 0 (empty export name)
    stream.flush().await?;

    // Server responds: size (8) + transmission flags (2) + [124 zero bytes unless no_zeroes]
    let size = stream.read_u64().await?;
    let flags = stream.read_u16().await?;

    if !no_zeroes {
        let mut zeroes = [0u8; 124];
        stream.read_exact(&mut zeroes).await?;
    }

    Ok(nbd::ExportInfo { size, flags })
}

/// Open the NBD device file, returning the raw fd.
fn open_nbd_device(path: &Path) -> Result<i32, Box<dyn std::error::Error>> {
    use std::ffi::CString;

    let c_path = CString::new(path.to_str().ok_or("invalid device path")?)?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "cannot open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(fd)
}

/// Perform an NBD ioctl, returning an error on failure.
unsafe fn nbd_ioctl(
    fd: i32,
    request: libc::c_ulong,
    arg: libc::c_ulong,
) -> Result<(), Box<dyn std::error::Error>> {
    // `as _`: glibc declares the ioctl request as c_ulong, musl as c_int.
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 {
        Err(format!(
            "ioctl {request:#x} failed: {}",
            std::io::Error::last_os_error()
        )
        .into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_primary_superblock() {
        assert_eq!(
            classify_superblock_write(0x1000000 + 0x10000, 4096, 0x1000000),
            Some("btrfs sb#0 (64 KiB)")
        );
    }

    #[test]
    fn classify_secondary_superblock() {
        assert_eq!(
            classify_superblock_write(0x1000000 + 0x4000000, 4096, 0x1000000),
            Some("btrfs sb#1 (64 MiB)")
        );
    }

    #[test]
    fn ignores_non_superblock_writes() {
        assert_eq!(
            classify_superblock_write(0x1000000 + 0x100000, 4096, 0x1000000),
            None
        );
    }

    #[test]
    fn ignores_writes_inside_luks_header() {
        assert_eq!(classify_superblock_write(0x10000, 4096, 0x1000000), None);
    }

    #[test]
    fn detects_overlapping_large_write() {
        // A 64 KiB write that straddles the 64 KiB superblock offset.
        assert_eq!(
            classify_superblock_write(0x1000000 + 0xF000, 0x10000, 0x1000000),
            Some("btrfs sb#0 (64 KiB)")
        );
    }
}
