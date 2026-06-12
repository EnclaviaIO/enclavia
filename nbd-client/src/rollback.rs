//! Anti-rollback wiring: pin btrfs superblock writes to the synchronizer
//! cluster (EnclaviaIO/enclavia-crates#16, final integration phase).
//!
//! The nbd-client sits between the in-enclave kernel and the host-side
//! storage relay, below dm-crypt: every byte it sees is LUKS ciphertext.
//! The btrfs PRIMARY superblock lives at filesystem offset 64 KiB
//! ([`SB_PRIMARY_FS_OFFSET`], translated through the LUKS data offset),
//! and btrfs commits it last in every transaction, so the (ciphertext)
//! content of that 4 KiB region is a freshness beacon for the whole
//! filesystem. We pin `SHA-256(region ciphertext)` to the synchronizer:
//!
//! * **Boot:** before the kernel is allowed to touch the device, read
//!   the region directly off the host stream and compare against the
//!   cluster's pinned commitment. Any mismatch is rollback evidence and
//!   the client REFUSES to serve (fail-stop). A blank (all-zero) region
//!   with no pinned key is a fresh device: register it and proceed.
//! * **Runtime:** every NBD write that covers the region is hashed on
//!   the way through, a `Pin` RPC is issued, and the corresponding NBD
//!   reply to the kernel is HELD until the cluster's durable `PinOk`
//!   arrives (the replicated server only ACKs a Pin after the entry is
//!   replicated to every voter, see `synchronizer::raft::serve`).
//!   Unrelated requests are never stalled: the reply pump parks only the
//!   gated reply and keeps forwarding everything else.
//!
//! ## Fail-stop policy
//!
//! There is NO degraded mode. The synchronizer being unreachable, slow
//! past the explicit timeouts, or answering anything unexpected is fatal:
//! the process exits non-zero and the device is never (or no longer)
//! served. Serving without freshness assurance would silently reopen the
//! rollback hole this module exists to close.
//!
//! ## Opt-in gate
//!
//! The wiring activates only when [`ENV_SYNCHRONIZER_ENABLED`] is set to
//! `1` or `true` in the environment. Without it, nbd-client behaves
//! byte-for-byte as before (no synchronizer connection, no gating), so
//! enclaves without storage rollback protection keep booting as today.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use synchronizer::client::{Client, ClientError, Handshake};
use synchronizer::wire::RpcError;
use synchronizer::{Commitment, PcrKey, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::nbd;

/// Boxed fatal error: any of these tears the whole nbd-client down.
pub type FatalError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Filesystem-relative byte offset of the PRIMARY btrfs superblock
/// (64 KiB). Mirror copies (64 MiB, 256 GiB) are deliberately NOT
/// pinned: btrfs mounts from the primary, and pinning one beacon keeps
/// boot verification a single read + compare. Translated to a device
/// offset by adding the LUKS data offset.
pub const SB_PRIMARY_FS_OFFSET: u64 = 0x10000;

/// Length in bytes of the pinned superblock region. `struct
/// btrfs_super_block` occupies one 4 KiB block; kernel writes to it are
/// 4 KiB-aligned and at least 4 KiB long, so a legitimate superblock
/// write always covers the region entirely.
pub const SB_REGION_LEN: usize = 4096;

/// Time allowed for the vsock connect to the host-side synchronizer
/// relay (CID 2, port [`enclavia_protocol::mesh::SYNCHRONIZER_CUSTOMER_RELAY_PORT`]).
/// Expiry = the rollback oracle is unreachable = fail-stop; there is no
/// retry loop because serving without the oracle is never acceptable.
pub const SYNC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for one synchronizer interaction: the Noise handshake +
/// NSM attest + Authenticate at session setup, and each Get / Pin RPC
/// afterwards. Generous because a Pin in the replicated deployment only
/// ACKs after full replication (which may wait out a follower hiccup),
/// but finite: expiry is treated exactly like the oracle being
/// unreachable, i.e. fail-stop.
pub const SYNC_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variable that opts an enclave into the anti-rollback
/// wiring (`1` / `true`). Absent or any other value: nbd-client runs
/// exactly as before this module existed.
pub const ENV_SYNCHRONIZER_ENABLED: &str = "SYNCHRONIZER_ENABLED";

/// Environment variable overriding the path of the enclave config file
/// carrying the #47 `control_public_key` (defaults to
/// [`DEFAULT_CONFIG_PATH`], the same file enclavia-server reads).
pub const ENV_CONFIG_PATH: &str = "ENCLAVIA_CONFIG_PATH";

/// Default path of the enclave config JSON (mirrors
/// `enclavia-server::config::CONFIG_PATH`).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/enclavia/config.json";

/// True when the operator opted this enclave into synchronizer pinning.
pub fn synchronizer_enabled() -> bool {
    match std::env::var(ENV_SYNCHRONIZER_ENABLED) {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Pure pieces: region geometry, commitment, boot decision
// ---------------------------------------------------------------------------

/// How an NBD write relates to the pinned superblock region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbOverlap {
    /// The write does not touch the region at all.
    None,
    /// The write covers the ENTIRE region; the region's new content is
    /// `payload[payload_offset .. payload_offset + SB_REGION_LEN]`.
    Full {
        /// Byte offset of the region within the write payload.
        payload_offset: usize,
    },
    /// The write covers part of the region but not all of it. We cannot
    /// compute the region's full post-write content from the payload
    /// alone, so this is a fail-stop condition (it also never happens
    /// for legitimate btrfs superblock writes, which are whole-block).
    Partial,
}

/// Classify an NBD write (`offset`, `length` in device bytes) against
/// the primary superblock region, translated through the LUKS
/// `data_offset`.
pub fn primary_sb_overlap(offset: u64, length: u32, data_offset: u64) -> SbOverlap {
    let region_start = data_offset + SB_PRIMARY_FS_OFFSET;
    let region_end = region_start + SB_REGION_LEN as u64;
    let write_end = offset.saturating_add(length as u64);
    if write_end <= region_start || offset >= region_end {
        return SbOverlap::None;
    }
    if offset <= region_start && write_end >= region_end {
        return SbOverlap::Full {
            payload_offset: (region_start - offset) as usize,
        };
    }
    SbOverlap::Partial
}

/// The pinned commitment for a superblock region: SHA-256 over the raw
/// 4 KiB of (LUKS-ciphertext) region content.
pub fn commitment_of_region(region: &[u8]) -> [u8; 32] {
    Sha256::digest(region).into()
}

/// A region that has never been written: all zeroes. The host-side
/// storage daemon creates disk images zero-filled, and dm-crypt
/// ciphertext is never a 4 KiB run of zeroes in practice, so an all-zero
/// region means no btrfs superblock has ever been committed through
/// this device.
pub fn region_is_blank(region: &[u8]) -> bool {
    region.iter().all(|b| *b == 0)
}

/// What the synchronizer answered to the boot-time `Get`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetOutcome {
    /// The key is registered; this is its latest pinned commitment.
    Found {
        /// Latest pinned commitment bytes.
        commitment: [u8; 32],
    },
    /// The key has never been registered (or was retired).
    NotFound,
}

/// Boot-time verdict. Only `Serve` / `RegisterThenServe` let the device
/// reach the kernel; `FailStop` aborts the process before any I/O is
/// served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootDecision {
    /// Pinned commitment matches the device: serve.
    Serve,
    /// Fresh device, unregistered key: register (first Pin) the blank
    /// region's commitment, then serve.
    RegisterThenServe,
    /// Rollback evidence or inconsistency: refuse to serve. The carried
    /// string is the operator-facing reason.
    FailStop(String),
}

/// The boot-time decision table. Pure so it can be tested exhaustively;
/// this is the heart of the rollback-protection kernel.
///
/// | device region | synchronizer | verdict |
/// |---------------|--------------|---------|
/// | any           | Found, hash matches    | Serve |
/// | any           | Found, hash mismatches | FailStop (rollback or corruption) |
/// | blank         | NotFound               | RegisterThenServe (fresh device) |
/// | non-blank     | NotFound               | FailStop (data exists but no pin: rollback evidence) |
///
/// Note the blank + Found case falls out of the hash compare: a pinned
/// commitment over a blank region (registered at first boot, no write
/// yet) matches a still-blank device and serves; a pinned commitment
/// over real data against a blanked device mismatches and fail-stops
/// (a wiped/substituted disk is a rollback).
pub fn boot_decision(region: &[u8], outcome: &GetOutcome) -> BootDecision {
    match outcome {
        GetOutcome::Found { commitment } => {
            if commitment_of_region(region) == *commitment {
                BootDecision::Serve
            } else {
                BootDecision::FailStop(
                    "superblock commitment mismatch: device content does not match the \
                     synchronizer's pinned state (rollback or corruption); refusing to serve"
                        .to_string(),
                )
            }
        }
        GetOutcome::NotFound => {
            if region_is_blank(region) {
                BootDecision::RegisterThenServe
            } else {
                BootDecision::FailStop(
                    "device carries a written superblock region but the synchronizer has no \
                     pinned state for this enclave (rollback evidence: history was erased); \
                     refusing to serve"
                        .to_string(),
                )
            }
        }
    }
}

/// Map a `Client::get` result onto the decision table's [`GetOutcome`].
/// Only the structured `NotFound` is survivable; every other error (I/O,
/// crypto, Unavailable, Unauthorized, ...) is fatal, per the fail-stop
/// policy.
pub fn get_outcome(
    result: Result<(Commitment, Version), ClientError>,
) -> Result<GetOutcome, ClientError> {
    match result {
        Ok((commitment, _version)) => Ok(GetOutcome::Found {
            commitment: commitment.0,
        }),
        Err(ClientError::Rpc(RpcError::NotFound)) => Ok(GetOutcome::NotFound),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Streaming extraction (request path)
// ---------------------------------------------------------------------------

/// Stream `n` payload bytes from `src` to `dst` in 32 KiB chunks (the
/// proven-safe vsock write size, see `forward_bytes` in main.rs) while
/// copying out `payload[extract_off .. extract_off + extract_len]`.
///
/// Used on superblock writes: the payload is forwarded to the host
/// unmodified and the region's new content is captured for hashing,
/// without ever buffering the whole payload.
pub async fn forward_bytes_extract<R, W>(
    src: &mut R,
    dst: &mut W,
    n: u64,
    extract_off: usize,
    extract_len: usize,
) -> Result<Vec<u8>, FatalError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if (extract_off as u64).saturating_add(extract_len as u64) > n {
        return Err("extraction window exceeds payload length".into());
    }
    let mut out = vec![0u8; extract_len];
    let mut buf = [0u8; 32 * 1024];
    let mut pos: u64 = 0;
    let mut remaining = n;
    while remaining > 0 {
        let take = std::cmp::min(remaining as usize, buf.len());
        src.read_exact(&mut buf[..take]).await?;

        // Copy the intersection of [pos, pos+take) with the window.
        let lo = std::cmp::max(pos, extract_off as u64);
        let hi = std::cmp::min(pos + take as u64, (extract_off + extract_len) as u64);
        if lo < hi {
            let src_start = (lo - pos) as usize;
            let dst_start = (lo - extract_off as u64) as usize;
            let len = (hi - lo) as usize;
            out[dst_start..dst_start + len].copy_from_slice(&buf[src_start..src_start + len]);
        }

        dst.write_all(&buf[..take]).await?;
        pos += take as u64;
        remaining -= take as u64;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The pin gate (reply path)
// ---------------------------------------------------------------------------

/// Per-handle pin progress, shared between the request task (which gates
/// a handle), the pin actor (which resolves it), and the reply pump
/// (which holds / releases the NBD reply).
#[derive(Clone, Debug)]
enum PinStatus {
    /// Pin RPC in flight (or about to be); the reply must be held.
    Pending,
    /// Durable PinOk received; the reply may pass.
    Ok,
    /// Pin failed; carries the reason. Fail-stop.
    Failed(String),
}

/// What the reply pump should do with a reply (or a parked reply) for a
/// given handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateCheck {
    /// Handle was never gated: forward immediately.
    NotGated,
    /// Pin still in flight: hold the reply.
    Hold,
    /// Durable PinOk arrived: forward (the gate entry is consumed).
    Pass,
    /// Pin failed: fail-stop with this reason.
    Fail(String),
}

/// Shared gate state. Plain `std::sync::Mutex` (never held across an
/// await); wake-ups travel separately over the pump's nudge channel.
#[derive(Default)]
pub struct PinGate {
    inner: Mutex<HashMap<u64, PinStatus>>,
}

impl PinGate {
    /// Fresh gate with no gated handles.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gate `handle`: its NBD reply must be held until the pin resolves.
    /// MUST be called before the corresponding request is forwarded to
    /// the host (so the gate entry exists before the reply can arrive).
    pub fn begin(&self, handle: u64) {
        self.inner
            .lock()
            .unwrap()
            .insert(handle, PinStatus::Pending);
    }

    /// Resolve `handle`'s pin as durably acknowledged.
    pub fn finish_ok(&self, handle: u64) {
        self.inner.lock().unwrap().insert(handle, PinStatus::Ok);
    }

    /// Resolve `handle`'s pin as failed (fail-stop reason attached).
    pub fn finish_err(&self, handle: u64, reason: String) {
        self.inner
            .lock()
            .unwrap()
            .insert(handle, PinStatus::Failed(reason));
    }

    /// Consult (and on `Pass`, consume) the gate for `handle`.
    pub fn check(&self, handle: u64) -> GateCheck {
        let mut map = self.inner.lock().unwrap();
        match map.get(&handle) {
            None => GateCheck::NotGated,
            Some(PinStatus::Pending) => GateCheck::Hold,
            Some(PinStatus::Ok) => {
                map.remove(&handle);
                GateCheck::Pass
            }
            Some(PinStatus::Failed(reason)) => GateCheck::Fail(reason.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Pin actor
// ---------------------------------------------------------------------------

/// One queued superblock pin: the gated NBD handle and the commitment
/// hashed off the write payload.
#[derive(Clone, Copy, Debug)]
pub struct PinJob {
    /// NBD request handle whose reply is gated on this pin.
    pub handle: u64,
    /// `SHA-256(region ciphertext)` to pin.
    pub commitment: [u8; 32],
}

/// Hooks handed to the request proxy when the wiring is enabled.
pub struct SyncHooks {
    /// Shared gate; `begin` is called per superblock write.
    pub gate: Arc<PinGate>,
    /// Queue feeding the pin actor.
    pub pin_tx: mpsc::Sender<PinJob>,
}

/// Issues one Pin RPC. Abstracted from the network client so the actor's
/// gate/ordering semantics are testable without a Noise stack.
#[allow(async_fn_in_trait)]
pub trait Pinner {
    /// Pin `commitment`; resolve only once the ack is durable. An `Err`
    /// is fatal for the whole device.
    async fn pin(&mut self, commitment: [u8; 32]) -> Result<(), String>;
}

/// Production [`Pinner`]: the authenticated synchronizer session, with
/// [`SYNC_RPC_TIMEOUT`] applied per RPC.
pub struct SyncPinner<S> {
    client: Client<S>,
    key: PcrKey,
}

impl<S> Pinner for SyncPinner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn pin(&mut self, commitment: [u8; 32]) -> Result<(), String> {
        match tokio::time::timeout(
            SYNC_RPC_TIMEOUT,
            self.client.pin(self.key, Commitment(commitment)),
        )
        .await
        {
            Ok(Ok(version)) => {
                info!(version = version.0, "superblock pin durably acknowledged");
                Ok(())
            }
            Ok(Err(e)) => Err(format!("pin rpc failed: {e}")),
            Err(_) => Err(format!(
                "pin rpc timed out after {SYNC_RPC_TIMEOUT:?} (synchronizer unreachable)"
            )),
        }
    }
}

/// Drain [`PinJob`]s in order, resolving the gate after each durable
/// ack and nudging the reply pump. Any pin failure marks the gate and
/// returns an error, which tears the whole nbd-client down (fail-stop).
/// Returns `Ok(())` when the job queue closes (request proxy ended).
pub async fn pin_actor<P>(
    mut pinner: P,
    gate: Arc<PinGate>,
    mut rx: mpsc::Receiver<PinJob>,
    nudge: mpsc::UnboundedSender<()>,
) -> Result<(), FatalError>
where
    P: Pinner,
{
    while let Some(job) = rx.recv().await {
        match pinner.pin(job.commitment).await {
            Ok(()) => {
                gate.finish_ok(job.handle);
                let _ = nudge.send(());
            }
            Err(reason) => {
                gate.finish_err(job.handle, reason.clone());
                let _ = nudge.send(());
                return Err(
                    format!("synchronizer pin failed, refusing to keep serving: {reason}").into(),
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gated reply pump (replaces reply_proxy when the wiring is enabled)
// ---------------------------------------------------------------------------

/// Cancel-safe accumulation of up to `target` total bytes into `buf`.
/// Returns the number of bytes appended by this call (0 = EOF).
async fn read_into<R>(src: &mut R, buf: &mut Vec<u8>, target: usize) -> std::io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let remaining = target - buf.len();
    let mut limited = src.take(remaining as u64);
    limited.read_buf(buf).await
}

/// Forward NBD replies from the host to the kernel, holding the reply of
/// each gated (superblock-write) handle until its durable PinOk.
///
/// Identical wire behavior to `reply_proxy` for ungated traffic: read
/// replies stream their payload through a 32 KiB buffer, errored reads
/// are forwarded without payload. Gated write replies (16-byte header,
/// no payload) are parked in a side map and written out when the pin
/// actor nudges; everything else keeps flowing meanwhile, so unrelated
/// requests are never stalled. A failed or host-errored gated write is
/// fatal (fail-stop).
pub async fn gated_reply_proxy<R, W>(
    mut from_host: R,
    mut to_kernel: W,
    inflight: Arc<Mutex<HashMap<u64, u32>>>,
    gate: Arc<PinGate>,
    mut nudge_rx: mpsc::UnboundedReceiver<()>,
) -> Result<(), FatalError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stashed: HashMap<u64, [u8; 16]> = HashMap::new();
    let mut header: Vec<u8> = Vec::with_capacity(16);
    let mut nudge_open = true;

    loop {
        // Accumulate one 16-byte reply header, processing pin releases
        // while we wait. `read_into` is cancel-safe (partial progress
        // stays in `header`), so the select! cannot lose bytes.
        header.clear();
        while header.len() < 16 {
            tokio::select! {
                res = read_into(&mut from_host, &mut header, 16) => {
                    let n = res?;
                    if n == 0 {
                        if header.is_empty() && stashed.is_empty() {
                            tracing::debug!("gated_reply_proxy: host side EOF");
                            return Ok(());
                        }
                        return Err("host stream closed mid-reply or with gated superblock \
                                    replies still pending"
                            .into());
                    }
                }
                maybe = nudge_rx.recv(), if nudge_open => {
                    match maybe {
                        Some(()) => {
                            flush_stashed(&mut to_kernel, &mut stashed, &gate).await?;
                        }
                        None => nudge_open = false,
                    }
                }
            }
        }

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != nbd::NBD_SIMPLE_REPLY_MAGIC {
            return Err(format!("bad NBD reply magic: {magic:#x}").into());
        }
        let error = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let handle = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let read_len = inflight.lock().unwrap().remove(&handle);

        if let Some(len) = read_len {
            // Read replies are never gated (only writes are). Forward
            // header + payload (payload only on success).
            to_kernel.write_all(&header).await?;
            if error == 0 {
                crate::forward_bytes(&mut from_host, &mut to_kernel, len as u64).await?;
            } else {
                warn!(error, handle, "NBD read reply errored");
            }
            to_kernel.flush().await?;
            continue;
        }

        // Non-read reply: consult the gate.
        match gate.check(handle) {
            GateCheck::NotGated => {
                to_kernel.write_all(&header).await?;
                to_kernel.flush().await?;
            }
            GateCheck::Pass => {
                if error != 0 {
                    // The host failed the superblock write we already
                    // pinned (or are pinning): the device and the pinned
                    // state have diverged. Fail-stop; the next boot's
                    // verify would refuse this device anyway.
                    return Err(format!(
                        "host failed a gated superblock write (NBD error {error}); \
                         device no longer matches pinned state"
                    )
                    .into());
                }
                to_kernel.write_all(&header).await?;
                to_kernel.flush().await?;
            }
            GateCheck::Hold => {
                if error != 0 {
                    return Err(format!(
                        "host failed a gated superblock write (NBD error {error}) while \
                         its pin was in flight"
                    )
                    .into());
                }
                info!(handle, "holding superblock write reply until durable PinOk");
                stashed.insert(handle, header[..16].try_into().unwrap());
            }
            GateCheck::Fail(reason) => {
                return Err(format!("superblock pin failed: {reason}").into());
            }
        }
    }
}

/// Re-examine every parked reply after a pin-actor nudge, releasing the
/// ones whose pin completed. A `Fail` (or a gate entry that vanished,
/// which would be a bookkeeping bug) is fatal.
async fn flush_stashed<W>(
    to_kernel: &mut W,
    stashed: &mut HashMap<u64, [u8; 16]>,
    gate: &PinGate,
) -> Result<(), FatalError>
where
    W: AsyncWrite + Unpin,
{
    let handles: Vec<u64> = stashed.keys().copied().collect();
    for handle in handles {
        match gate.check(handle) {
            GateCheck::Hold => {}
            GateCheck::Pass => {
                let hdr = stashed.remove(&handle).expect("stashed handle present");
                info!(handle, "releasing superblock write reply (PinOk)");
                to_kernel.write_all(&hdr).await?;
                to_kernel.flush().await?;
            }
            GateCheck::Fail(reason) => {
                return Err(format!("superblock pin failed: {reason}").into());
            }
            GateCheck::NotGated => {
                return Err(format!(
                    "gate entry for stashed reply (handle {handle}) disappeared; \
                     refusing to serve with inconsistent gate state"
                )
                .into());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Boot-time verification
// ---------------------------------------------------------------------------

/// NBD handle used for the boot-time direct superblock read, issued
/// before the kernel ever attaches (so it cannot collide with kernel
/// handles). ASCII "SYNCBOOT".
const BOOT_READ_HANDLE: u64 = 0x53594e43_424f4f54;

/// Read the pinned superblock region directly off the host NBD stream
/// (transmission phase, before the kernel is wired up).
pub async fn nbd_read_region<S>(stream: &mut S, device_offset: u64) -> Result<Vec<u8>, FatalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 28];
    header[0..4].copy_from_slice(&nbd::NBD_REQUEST_MAGIC.to_be_bytes());
    // bytes 4..6: command flags (zero); 6..8: type.
    header[6..8].copy_from_slice(&nbd::NBD_CMD_READ.to_be_bytes());
    header[8..16].copy_from_slice(&BOOT_READ_HANDLE.to_be_bytes());
    header[16..24].copy_from_slice(&device_offset.to_be_bytes());
    header[24..28].copy_from_slice(&(SB_REGION_LEN as u32).to_be_bytes());
    stream.write_all(&header).await?;
    stream.flush().await?;

    let mut reply = [0u8; 16];
    stream.read_exact(&mut reply).await?;
    let magic = u32::from_be_bytes(reply[0..4].try_into().unwrap());
    if magic != nbd::NBD_SIMPLE_REPLY_MAGIC {
        return Err(format!("boot verify: bad NBD reply magic {magic:#x}").into());
    }
    let error = u32::from_be_bytes(reply[4..8].try_into().unwrap());
    let handle = u64::from_be_bytes(reply[8..16].try_into().unwrap());
    if handle != BOOT_READ_HANDLE {
        return Err(format!("boot verify: NBD reply for unexpected handle {handle:#x}").into());
    }
    if error != 0 {
        return Err(format!("boot verify: NBD read of superblock region failed ({error})").into());
    }
    let mut region = vec![0u8; SB_REGION_LEN];
    stream.read_exact(&mut region).await?;
    Ok(region)
}

/// Run the boot decision table against a live session: `Get`, compare,
/// and on a fresh device register the blank region. Any verdict other
/// than serve / register propagates as a fatal error.
pub async fn verify_or_register<S>(
    client: &mut Client<S>,
    key: PcrKey,
    region: &[u8],
) -> Result<(), FatalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get(key))
        .await
        .map_err(|_| {
            format!(
                "boot verify: Get timed out after {SYNC_RPC_TIMEOUT:?} (synchronizer unreachable)"
            )
        })?;
    let outcome =
        get_outcome(result).map_err(|e| format!("boot verify: synchronizer Get failed: {e}"))?;

    match boot_decision(region, &outcome) {
        BootDecision::Serve => {
            info!("boot verify: superblock matches pinned commitment; serving");
            Ok(())
        }
        BootDecision::RegisterThenServe => {
            info!("boot verify: fresh device, registering with the synchronizer");
            let commitment = Commitment(commitment_of_region(region));
            let version = tokio::time::timeout(SYNC_RPC_TIMEOUT, client.pin(key, commitment))
                .await
                .map_err(|_| {
                    format!(
                        "boot verify: registration Pin timed out after {SYNC_RPC_TIMEOUT:?} \
                         (synchronizer unreachable)"
                    )
                })?
                .map_err(|e| format!("boot verify: registration Pin failed: {e}"))?;
            if version != Version(0) {
                // Get said NotFound but the Pin did not register: another
                // session squeezed a registration in between. Two live
                // writers for one PcrKey can only corrupt each other;
                // refuse to serve.
                return Err(format!(
                    "boot verify: registration raced (PinOk version {} != 0); another \
                     session owns this key",
                    version.0
                )
                .into());
            }
            Ok(())
        }
        BootDecision::FailStop(reason) => Err(format!("boot verify: {reason}").into()),
    }
}

// ---------------------------------------------------------------------------
// Session setup (config, NSM, vsock dial)
// ---------------------------------------------------------------------------

/// Subset of `/etc/enclavia/config.json` we need: the #47 control
/// pubkey (the same field enclavia-server reads).
#[derive(serde::Deserialize, Default)]
struct RawConfig {
    control_public_key: Option<String>,
}

/// Load the 65-byte uncompressed SEC1 P-256 control pubkey from the
/// enclave config, the value the synchronizer freezes and later uses to
/// verify a PCR `Transition` for this key.
///
/// Two valid outcomes:
///
/// - `control_public_key` present: an upgradable enclave (#47 chain).
///   Decode it; a malformed value is fatal (a real key was intended, so
///   a broken one is a misconfiguration, not a non-upgradable signal).
/// - `control_public_key` absent: a non-upgradable enclave. Register
///   with the canonical provably-un-signable
///   [`NON_UPGRADABLE_CONTROL_KEY`] instead of failing. No private key
///   for it exists, so no `Transition` can ever be authorized and the
///   pinned storage history is permanently bound to this one image,
///   which is the correct semantic for an enclave with no upgrade path.
///   Storage pinning itself is unaffected (`Pin`/`Get` are gated by the
///   attested PCR key, not by this pubkey). The choice is logged so the
///   non-upgradable posture is observable; a chain-enabled enclave whose
///   key went missing therefore fails SAFE (it can never transition,
///   never an unauthorised one).
pub fn load_control_pubkey(path: &Path) -> Result<[u8; 65], FatalError> {
    use base64::Engine;
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read enclave config {}: {e}", path.display()))?;
    let raw: RawConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse enclave config {}: {e}", path.display()))?;
    let Some(b64) = raw.control_public_key else {
        warn!(
            "enclave config has no control_public_key: treating this enclave as NON-UPGRADABLE \
             and pinning storage under the canonical un-signable control key (no PCR Transition \
             will ever be possible for it)"
        );
        return Ok(enclavia_protocol::attestation::NON_UPGRADABLE_CONTROL_KEY);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("control_public_key is not valid base64: {e}"))?;
    if decoded.len() != 65 || decoded[0] != 0x04 {
        return Err("control_public_key must be 65-byte uncompressed SEC1 (0x04 || X || Y)".into());
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Request one attestation document from this enclave's own `/dev/nsm`
/// with `nonce = handshake_hash` (channel binding) and `user_data =
/// control_pubkey` (#47). BLOCKING: call through `spawn_blocking`.
/// Mirrors `synchronizer::mesh::attestation::request_own_attestation`,
/// re-implemented here so nbd-client does not pull the mesh feature in.
fn request_nsm_attestation(nonce: Vec<u8>, user_data: Vec<u8>) -> Result<Vec<u8>, FatalError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd == -1 {
        return Err("nsm_init failed (is /dev/nsm present?)".into());
    }
    let request = Request::Attestation {
        user_data: Some(user_data.into()),
        nonce: Some(nonce.into()),
        public_key: None,
    };
    let result = match nsm_process_request(fd, request) {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(format!("NSM attestation error: {e:?}").into()),
        _ => Err("unexpected NSM response".into()),
    };
    // Close the device on every exit path.
    nsm_exit(fd);
    result
}

/// An authenticated synchronizer session plus the PCR key it is bound
/// to (derived from our own attestation document, exactly as the server
/// derives it on its side).
pub struct SyncSession {
    /// RPC-ready client over the vsock relay.
    pub client: Client<tokio_vsock::VsockStream>,
    /// `SHA-256(PCR0||PCR1||PCR2)` of this enclave.
    pub key: PcrKey,
}

/// Dial the host-side relay (CID 2, vsock port
/// `SYNCHRONIZER_CUSTOMER_RELAY_PORT`), run the Noise handshake, mint a
/// real NSM document bound to it, and authenticate. Every step is under
/// an explicit timeout; any failure is fatal (fail-stop, no retries).
pub async fn connect_and_authenticate() -> Result<SyncSession, FatalError> {
    let config_path = std::env::var(ENV_CONFIG_PATH).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
    let control_pubkey = load_control_pubkey(Path::new(&config_path))?;

    let port = enclavia_protocol::mesh::SYNCHRONIZER_CUSTOMER_RELAY_PORT;
    info!(port, "connecting to the synchronizer relay over vsock");
    let stream = tokio::time::timeout(
        SYNC_CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(2, port),
    )
    .await
    .map_err(|_| {
        format!("synchronizer relay connect timed out after {SYNC_CONNECT_TIMEOUT:?} (fail-stop)")
    })??;

    tokio::time::timeout(SYNC_RPC_TIMEOUT, async move {
        let hs = Handshake::start(stream).await?;
        let nonce = hs.handshake_hash().to_vec();
        let user_data = control_pubkey.to_vec();
        let doc = tokio::task::spawn_blocking(move || request_nsm_attestation(nonce, user_data))
            .await
            .map_err(|e| format!("NSM attestation task panicked: {e}"))??;
        // Derive our own PcrKey from the document we just minted; the
        // listener derives the session key the same way on its side, so
        // RPC `key` fields match the session binding.
        let pcrs = enclavia_protocol::attestation::extract_own_pcrs(&doc)
            .map_err(|e| format!("cannot extract own PCRs from NSM document: {e}"))?;
        let key = PcrKey(pcrs.digest());
        let client = hs.authenticate(doc).await?;
        info!("synchronizer session authenticated");
        Ok::<_, FatalError>(SyncSession { client, key })
    })
    .await
    .map_err(|_| {
        format!("synchronizer session setup timed out after {SYNC_RPC_TIMEOUT:?} (fail-stop)")
    })?
}

/// Full boot sequence for the anti-rollback wiring: connect +
/// authenticate, read the device's current superblock region off the
/// host stream, and run the decision table. Returns the live session
/// (handed to the pin actor) only if the device may be served.
pub async fn boot<H>(host: &mut H, data_offset: u64) -> Result<SyncSession, FatalError>
where
    H: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = connect_and_authenticate().await?;
    let region = nbd_read_region(host, data_offset + SB_PRIMARY_FS_OFFSET).await?;
    verify_or_register(&mut session.client, session.key, &region).await?;
    Ok(session)
}

/// Turn a [`SyncSession`] into the production [`Pinner`] for the actor.
pub fn into_pinner(session: SyncSession) -> SyncPinner<tokio_vsock::VsockStream> {
    SyncPinner {
        client: session.client,
        key: session.key,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;
    use tokio::sync::mpsc::{channel, unbounded_channel};
    use tokio::time::timeout;

    const DATA_OFFSET: u64 = 16 * 1024 * 1024; // LUKS2 default (16 MiB)
    const REGION_START: u64 = DATA_OFFSET + SB_PRIMARY_FS_OFFSET;

    // --- primary_sb_overlap -------------------------------------------

    #[test]
    fn overlap_none_before_region() {
        assert_eq!(
            primary_sb_overlap(REGION_START - 8192, 8192, DATA_OFFSET),
            SbOverlap::None
        );
    }

    #[test]
    fn overlap_none_after_region() {
        assert_eq!(
            primary_sb_overlap(REGION_START + SB_REGION_LEN as u64, 4096, DATA_OFFSET),
            SbOverlap::None
        );
    }

    #[test]
    fn overlap_none_inside_luks_header() {
        // A write below the data offset can never reach the region.
        assert_eq!(primary_sb_overlap(0, 4096, DATA_OFFSET), SbOverlap::None);
    }

    #[test]
    fn overlap_full_exact() {
        assert_eq!(
            primary_sb_overlap(REGION_START, SB_REGION_LEN as u32, DATA_OFFSET),
            SbOverlap::Full { payload_offset: 0 }
        );
    }

    #[test]
    fn overlap_full_straddling_write() {
        // A 64 KiB write starting 4 KiB before the region covers it
        // entirely; the region sits 4 KiB into the payload.
        assert_eq!(
            primary_sb_overlap(REGION_START - 4096, 64 * 1024, DATA_OFFSET),
            SbOverlap::Full {
                payload_offset: 4096
            }
        );
    }

    #[test]
    fn overlap_partial_front() {
        // Write covers only the first half of the region.
        assert_eq!(
            primary_sb_overlap(REGION_START - 2048, 4096, DATA_OFFSET),
            SbOverlap::Partial
        );
    }

    #[test]
    fn overlap_partial_back() {
        // Write starts mid-region.
        assert_eq!(
            primary_sb_overlap(REGION_START + 2048, 4096, DATA_OFFSET),
            SbOverlap::Partial
        );
    }

    #[test]
    fn overlap_partial_sub_block_write_inside_region() {
        // A 512-byte write inside the region does not cover all of it.
        assert_eq!(
            primary_sb_overlap(REGION_START + 512, 512, DATA_OFFSET),
            SbOverlap::Partial
        );
    }

    #[test]
    fn overlap_edges_are_exclusive() {
        // Write ending exactly at region start, and starting exactly at
        // region end: neither overlaps.
        assert_eq!(
            primary_sb_overlap(REGION_START - 4096, 4096, DATA_OFFSET),
            SbOverlap::None
        );
        assert_eq!(
            primary_sb_overlap(REGION_START + SB_REGION_LEN as u64, 4096, DATA_OFFSET),
            SbOverlap::None
        );
    }

    // --- commitment + blankness ---------------------------------------

    #[test]
    fn commitment_is_sha256_of_region() {
        let region = vec![0xabu8; SB_REGION_LEN];
        let expected: [u8; 32] = Sha256::digest(&region).into();
        assert_eq!(commitment_of_region(&region), expected);
    }

    #[test]
    fn blankness_detection() {
        assert!(region_is_blank(&vec![0u8; SB_REGION_LEN]));
        let mut region = vec![0u8; SB_REGION_LEN];
        region[SB_REGION_LEN - 1] = 1;
        assert!(!region_is_blank(&region));
    }

    // --- boot decision table (exhaustive) ------------------------------

    fn region_with_data() -> Vec<u8> {
        let mut r = vec![0u8; SB_REGION_LEN];
        r[64] = 0x5f; // arbitrary non-zero content
        r[65] = 0x42;
        r
    }

    #[test]
    fn decision_found_matching_serves() {
        let region = region_with_data();
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&region),
        };
        assert_eq!(boot_decision(&region, &outcome), BootDecision::Serve);
    }

    #[test]
    fn decision_found_mismatching_fail_stops() {
        let region = region_with_data();
        let outcome = GetOutcome::Found {
            commitment: [0x11; 32],
        };
        assert!(matches!(
            boot_decision(&region, &outcome),
            BootDecision::FailStop(_)
        ));
    }

    #[test]
    fn decision_blank_not_found_registers() {
        let region = vec![0u8; SB_REGION_LEN];
        assert_eq!(
            boot_decision(&region, &GetOutcome::NotFound),
            BootDecision::RegisterThenServe
        );
    }

    #[test]
    fn decision_present_not_found_fail_stops() {
        // The rollback-evidence case: device has data, oracle has no pin.
        let region = region_with_data();
        assert!(matches!(
            boot_decision(&region, &GetOutcome::NotFound),
            BootDecision::FailStop(_)
        ));
    }

    #[test]
    fn decision_blank_found_blank_hash_serves() {
        // Registered at first boot, crashed before any write: pinned
        // commitment is the blank hash, device still blank.
        let region = vec![0u8; SB_REGION_LEN];
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&region),
        };
        assert_eq!(boot_decision(&region, &outcome), BootDecision::Serve);
    }

    #[test]
    fn decision_blank_found_data_hash_fail_stops() {
        // Oracle pinned real data; device was wiped: rollback.
        let region = vec![0u8; SB_REGION_LEN];
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&region_with_data()),
        };
        assert!(matches!(
            boot_decision(&region, &outcome),
            BootDecision::FailStop(_)
        ));
    }

    #[test]
    fn decision_even_one_flipped_bit_fail_stops() {
        let region = region_with_data();
        let mut tampered = region.clone();
        tampered[64] ^= 0x01;
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&tampered),
        };
        assert!(matches!(
            boot_decision(&region, &outcome),
            BootDecision::FailStop(_)
        ));
    }

    // --- get_outcome mapping -------------------------------------------

    #[test]
    fn get_outcome_found() {
        let out = get_outcome(Ok((Commitment([0xaa; 32]), Version(3)))).unwrap();
        assert_eq!(
            out,
            GetOutcome::Found {
                commitment: [0xaa; 32]
            }
        );
    }

    #[test]
    fn get_outcome_not_found_is_survivable() {
        let out = get_outcome(Err(ClientError::Rpc(RpcError::NotFound))).unwrap();
        assert_eq!(out, GetOutcome::NotFound);
    }

    #[test]
    fn get_outcome_other_errors_are_fatal() {
        for err in [
            ClientError::Rpc(RpcError::Unavailable),
            ClientError::Rpc(RpcError::Unauthorized),
            ClientError::Rpc(RpcError::OperationRejected),
            ClientError::ConnectionClosed,
        ] {
            assert!(get_outcome(Err(err)).is_err());
        }
    }

    // --- forward_bytes_extract ------------------------------------------

    #[tokio::test]
    async fn extract_within_single_chunk() {
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut src = Cursor::new(payload.clone());
        let mut dst = Vec::new();
        let region = forward_bytes_extract(&mut src, &mut dst, 8192, 1024, 4096)
            .await
            .unwrap();
        assert_eq!(dst, payload, "payload must be forwarded unmodified");
        assert_eq!(region, payload[1024..1024 + 4096].to_vec());
    }

    #[tokio::test]
    async fn extract_across_chunk_boundary() {
        // Payload bigger than the 32 KiB streaming buffer, with the
        // window straddling the boundary.
        let payload: Vec<u8> = (0..(64 * 1024u32)).map(|i| (i % 241) as u8).collect();
        let off = 32 * 1024 - 2048;
        let mut src = Cursor::new(payload.clone());
        let mut dst = Vec::new();
        let region = forward_bytes_extract(&mut src, &mut dst, payload.len() as u64, off, 4096)
            .await
            .unwrap();
        assert_eq!(dst, payload);
        assert_eq!(region, payload[off..off + 4096].to_vec());
    }

    #[tokio::test]
    async fn extract_window_beyond_payload_is_rejected() {
        let payload = vec![0u8; 1024];
        let mut src = Cursor::new(payload);
        let mut dst = Vec::new();
        assert!(
            forward_bytes_extract(&mut src, &mut dst, 1024, 512, 4096)
                .await
                .is_err()
        );
    }

    // --- PinGate ----------------------------------------------------------

    #[test]
    fn gate_lifecycle() {
        let gate = PinGate::new();
        assert_eq!(gate.check(1), GateCheck::NotGated);
        gate.begin(1);
        assert_eq!(gate.check(1), GateCheck::Hold);
        gate.finish_ok(1);
        assert_eq!(gate.check(1), GateCheck::Pass);
        // Pass consumed the entry.
        assert_eq!(gate.check(1), GateCheck::NotGated);

        gate.begin(2);
        gate.finish_err(2, "boom".into());
        assert!(matches!(gate.check(2), GateCheck::Fail(r) if r == "boom"));
        // Failure is sticky (not consumed).
        assert!(matches!(gate.check(2), GateCheck::Fail(_)));
    }

    // --- gated reply pump ---------------------------------------------

    fn reply_header(error: u32, handle: u64) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&nbd::NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&error.to_be_bytes());
        h[8..16].copy_from_slice(&handle.to_be_bytes());
        h
    }

    struct PumpHarness {
        host: tokio::io::DuplexStream,
        kernel: tokio::io::DuplexStream,
        inflight: Arc<Mutex<HashMap<u64, u32>>>,
        gate: Arc<PinGate>,
        nudge_tx: mpsc::UnboundedSender<()>,
        task: tokio::task::JoinHandle<Result<(), FatalError>>,
    }

    fn spawn_pump() -> PumpHarness {
        let (host, host_side) = duplex(256 * 1024);
        let (kernel_side, kernel) = duplex(256 * 1024);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let gate = Arc::new(PinGate::new());
        let (nudge_tx, nudge_rx) = unbounded_channel();
        let task = tokio::spawn(gated_reply_proxy(
            host_side,
            kernel_side,
            inflight.clone(),
            gate.clone(),
            nudge_rx,
        ));
        PumpHarness {
            host,
            kernel,
            inflight,
            gate,
            nudge_tx,
            task,
        }
    }

    /// The core gating semantics: a gated write reply is HELD until the
    /// pin actor reports the durable PinOk, then released byte-for-byte.
    #[tokio::test]
    async fn gated_reply_held_until_pin_ok_then_released() {
        let mut h = spawn_pump();
        h.gate.begin(7);

        h.host.write_all(&reply_header(0, 7)).await.unwrap();
        h.host.flush().await.unwrap();

        // The reply must NOT reach the kernel while the pin is pending.
        let mut buf = [0u8; 16];
        assert!(
            timeout(Duration::from_millis(200), h.kernel.read_exact(&mut buf))
                .await
                .is_err(),
            "gated reply leaked to the kernel before PinOk"
        );

        // Durable ack arrives: the reply is released.
        h.gate.finish_ok(7);
        h.nudge_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut buf))
            .await
            .expect("released reply must reach the kernel")
            .unwrap();
        assert_eq!(buf, reply_header(0, 7));

        drop(h.host);
        h.task.await.unwrap().unwrap();
    }

    /// Unrelated replies keep flowing while a gated reply is parked:
    /// the gate stalls exactly one handle, nothing else.
    #[tokio::test]
    async fn unrelated_replies_flow_while_gated_reply_is_held() {
        let mut h = spawn_pump();
        h.gate.begin(7);
        // Handle 9 is a read with an 8-byte payload.
        h.inflight.lock().unwrap().insert(9, 8);

        // Gated write reply first, then an unrelated write reply, then a
        // read reply with payload.
        h.host.write_all(&reply_header(0, 7)).await.unwrap();
        h.host.write_all(&reply_header(0, 8)).await.unwrap();
        h.host.write_all(&reply_header(0, 9)).await.unwrap();
        h.host.write_all(&[0xee; 8]).await.unwrap();
        h.host.flush().await.unwrap();

        // The kernel sees handle 8 and handle 9 (+payload), NOT handle 7.
        let mut buf = [0u8; 16];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, reply_header(0, 8), "ungated write reply must pass");
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, reply_header(0, 9), "read reply must pass");
        let mut payload = [0u8; 8];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, [0xee; 8]);

        // Now release the gated one.
        h.gate.finish_ok(7);
        h.nudge_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, reply_header(0, 7));

        drop(h.host);
        h.task.await.unwrap().unwrap();
    }

    /// PinOk arriving BEFORE the host reply: the reply passes straight
    /// through when it shows up (no deadlock on ordering).
    #[tokio::test]
    async fn pin_ok_before_reply_passes_immediately() {
        let mut h = spawn_pump();
        h.gate.begin(7);
        h.gate.finish_ok(7);
        h.nudge_tx.send(()).unwrap();

        h.host.write_all(&reply_header(0, 7)).await.unwrap();
        h.host.flush().await.unwrap();

        let mut buf = [0u8; 16];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, reply_header(0, 7));

        drop(h.host);
        h.task.await.unwrap().unwrap();
    }

    /// A failed pin is fail-stop: the pump errors out instead of ever
    /// releasing the reply.
    #[tokio::test]
    async fn pin_failure_is_fatal() {
        let mut h = spawn_pump();
        h.gate.begin(7);

        h.host.write_all(&reply_header(0, 7)).await.unwrap();
        h.host.flush().await.unwrap();
        // Let the pump park the reply, then fail the pin.
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.gate.finish_err(7, "cluster unavailable".into());
        h.nudge_tx.send(()).unwrap();

        let result = timeout(Duration::from_secs(2), h.task).await.unwrap();
        let err = result.unwrap().unwrap_err();
        assert!(err.to_string().contains("cluster unavailable"), "{err}");
    }

    /// The host failing a gated superblock write (NBD error) is fatal:
    /// device and pinned state have diverged.
    #[tokio::test]
    async fn host_error_on_gated_write_is_fatal() {
        let mut h = spawn_pump();
        h.gate.begin(7);

        h.host.write_all(&reply_header(5, 7)).await.unwrap();
        h.host.flush().await.unwrap();

        let result = timeout(Duration::from_secs(2), h.task).await.unwrap();
        assert!(result.unwrap().is_err());
    }

    /// Host EOF with a gated reply still parked is an error, never a
    /// silent success.
    #[tokio::test]
    async fn eof_with_parked_reply_is_fatal() {
        let mut h = spawn_pump();
        h.gate.begin(7);
        h.host.write_all(&reply_header(0, 7)).await.unwrap();
        h.host.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(h.host);

        let result = timeout(Duration::from_secs(2), h.task).await.unwrap();
        assert!(result.unwrap().is_err());
    }

    /// Clean EOF with nothing parked mirrors reply_proxy: Ok.
    #[tokio::test]
    async fn clean_eof_is_ok() {
        let h = spawn_pump();
        drop(h.host);
        let result = timeout(Duration::from_secs(2), h.task).await.unwrap();
        result.unwrap().unwrap();
    }

    // --- pin actor ------------------------------------------------------

    /// Scripted pinner: pops pre-programmed results.
    struct ScriptedPinner {
        results: std::collections::VecDeque<Result<(), String>>,
        seen: Vec<[u8; 32]>,
    }

    impl Pinner for ScriptedPinner {
        async fn pin(&mut self, commitment: [u8; 32]) -> Result<(), String> {
            self.seen.push(commitment);
            self.results.pop_front().expect("unexpected pin call")
        }
    }

    #[tokio::test]
    async fn pin_actor_resolves_gate_and_nudges() {
        let gate = Arc::new(PinGate::new());
        let (pin_tx, pin_rx) = channel(8);
        let (nudge_tx, mut nudge_rx) = unbounded_channel();
        gate.begin(7);

        let pinner = ScriptedPinner {
            results: [Ok(())].into_iter().collect(),
            seen: Vec::new(),
        };
        let actor = tokio::spawn(pin_actor(pinner, gate.clone(), pin_rx, nudge_tx));

        pin_tx
            .send(PinJob {
                handle: 7,
                commitment: [0xaa; 32],
            })
            .await
            .unwrap();
        timeout(Duration::from_secs(2), nudge_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gate.check(7), GateCheck::Pass);

        drop(pin_tx);
        actor.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pin_actor_failure_marks_gate_and_returns_error() {
        let gate = Arc::new(PinGate::new());
        let (pin_tx, pin_rx) = channel(8);
        let (nudge_tx, mut nudge_rx) = unbounded_channel();
        gate.begin(9);

        let pinner = ScriptedPinner {
            results: [Err("no quorum".to_string())].into_iter().collect(),
            seen: Vec::new(),
        };
        let actor = tokio::spawn(pin_actor(pinner, gate.clone(), pin_rx, nudge_tx));

        pin_tx
            .send(PinJob {
                handle: 9,
                commitment: [0xbb; 32],
            })
            .await
            .unwrap();
        timeout(Duration::from_secs(2), nudge_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(gate.check(9), GateCheck::Fail(_)));
        let err = actor.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("no quorum"), "{err}");
    }

    // --- nbd_read_region -------------------------------------------------

    /// Mock host: answer the boot read with a canned region and assert
    /// the request shape.
    #[tokio::test]
    async fn boot_read_round_trip() {
        let (mut host, mut client_side) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 28];
            host.read_exact(&mut req).await.unwrap();
            assert_eq!(
                u32::from_be_bytes(req[0..4].try_into().unwrap()),
                nbd::NBD_REQUEST_MAGIC
            );
            assert_eq!(
                u16::from_be_bytes(req[6..8].try_into().unwrap()),
                nbd::NBD_CMD_READ
            );
            let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
            assert_eq!(
                u64::from_be_bytes(req[16..24].try_into().unwrap()),
                REGION_START
            );
            assert_eq!(
                u32::from_be_bytes(req[24..28].try_into().unwrap()),
                SB_REGION_LEN as u32
            );
            host.write_all(&reply_header(0, handle)).await.unwrap();
            host.write_all(&vec![0x5a; SB_REGION_LEN]).await.unwrap();
            host.flush().await.unwrap();
        });

        let region = nbd_read_region(&mut client_side, REGION_START)
            .await
            .unwrap();
        assert_eq!(region, vec![0x5a; SB_REGION_LEN]);
        server.await.unwrap();
    }

    /// An NBD error on the boot read is fatal (fail-stop).
    #[tokio::test]
    async fn boot_read_error_is_fatal() {
        let (mut host, mut client_side) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 28];
            host.read_exact(&mut req).await.unwrap();
            let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
            host.write_all(&reply_header(22, handle)).await.unwrap();
            host.flush().await.unwrap();
        });

        assert!(
            nbd_read_region(&mut client_side, REGION_START)
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    // --- load_control_pubkey -----------------------------------------

    /// Write `contents` to a unique temp config file; returns its path.
    fn temp_config(tag: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("nbd-cpk-{tag}.json"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn control_pubkey_absent_uses_non_upgradable_key() {
        // No control_public_key field: a non-upgradable enclave. The
        // loader must fall back to the canonical un-signable key, not
        // fail-stop.
        let path = temp_config("absent", r#"{"other_field": 1}"#);
        let got = load_control_pubkey(&path).expect("absent key must not be fatal");
        assert_eq!(
            got,
            enclavia_protocol::attestation::NON_UPGRADABLE_CONTROL_KEY
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn control_pubkey_present_valid_is_used_verbatim() {
        use base64::Engine;
        // A real (test) uncompressed SEC1 key round-trips unchanged.
        let mut key = [0u8; 65];
        key[0] = 0x04;
        key[1] = 0xAB;
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let path = temp_config("valid", &format!(r#"{{"control_public_key": "{b64}"}}"#));
        let got = load_control_pubkey(&path).expect("valid key must load");
        assert_eq!(got, key);
        // And it must NOT be the un-signable fallback.
        assert_ne!(
            got,
            enclavia_protocol::attestation::NON_UPGRADABLE_CONTROL_KEY
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn control_pubkey_present_but_malformed_is_fatal() {
        // A present-but-broken key is a misconfiguration of an
        // upgradable enclave, not a non-upgradable signal: stay fatal.
        let path = temp_config("malformed", r#"{"control_public_key": "not-base64!!!"}"#);
        assert!(load_control_pubkey(&path).is_err());
        let _ = std::fs::remove_file(&path);

        let path = temp_config("shortkey", r#"{"control_public_key": "BAAB"}"#);
        assert!(load_control_pubkey(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
