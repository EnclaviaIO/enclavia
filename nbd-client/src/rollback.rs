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
//!   A WRITTEN region with no pinned key under our PCR key is either a
//!   rollback or the first boot after a staged upgrade (#46): the pin
//!   then lives under the OLD image's key, and the disambiguator is the
//!   #47 upgrade `ChainLink`, fetched best-effort from `chain-host` and
//!   submitted as a `Transition` RPC the ORACLE verifies end to end.
//!   Without a link (or on rejection) the verdict stays fail-stop.
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
//! ## Mutual authentication: verifying the oracle (#208)
//!
//! The session protocol authenticates BOTH ways. This enclave attests to
//! the synchronizer (client `Authenticate`), and the synchronizer
//! attests back: its first frame is its own NSM document bound to the
//! same Noise handshake hash, which the client verifies and checks
//! against the expected synchronizer PCRs before issuing any RPC.
//! Without that check `Noise_NN` would leave the oracle's end of the
//! host-relayed channel unauthenticated: the host could terminate the
//! session itself and answer `Get`/`Pin` with arbitrarily stale state,
//! which is exactly the rollback this module exists to prevent.
//!
//! **Trust-anchor contract.** The expected synchronizer PCRs and the
//! `debug_attestation` flag are read from the enclave config
//! (`/etc/enclavia/config.json`), which is baked into the EIF and
//! therefore covered by THIS enclave's own measurements. They MUST NEVER
//! come from host-controlled input (environment variables, vsock
//! side-channels, kernel cmdline): a host that chooses the expected PCRs
//! or flips `debug_attestation` can impersonate the oracle and the whole
//! check is worthless. With [`ENV_SYNCHRONIZER_ENABLED`] set, a missing
//! or empty `synchronizer.expected_pcrs` config is fail-stop.
//!
//! ## Opt-in gate
//!
//! The wiring activates only when [`ENV_SYNCHRONIZER_ENABLED`] is set to
//! `1` or `true` in the environment. Without it, nbd-client behaves
//! byte-for-byte as before (no synchronizer connection, no gating), so
//! enclaves without storage rollback protection keep booting as today —
//! and log a prominent warning saying so (enclavia#99).
//!
//! On production images the variable is not host-controlled: the
//! measured EIF init exports it exactly when the builder-stamped config
//! (`synchronizer.enabled`, set via the builder's
//! `--synchronizer-enabled`) says so, which makes the on/off choice part
//! of PCR0/1/2 and therefore visible in the attestation the customer
//! verifies. An unrecognized value (anything other than `1`/`true` /
//! `0`/`false`/empty/unset) is fail-stop rather than silently "off":
//! see [`synchronizer_enabled`].

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclavia_protocol::chain::{ChainLink, ChainLinkKind};
use sha2::{Digest, Sha256};
use synchronizer::client::{Client, ClientError, Handshake, ServerPcrPolicy};
use synchronizer::wire::RpcError;
use synchronizer::{Commitment, PcrKey, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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

/// Vsock port of the host-side `chain-host` daemon (same constant as
/// `enclavia-chain-init`; the #46 fetch verb shares the submit socket).
pub const CHAIN_HOST_PORT: u32 = 5005;

/// Overall ceiling for the chain-host upgrade-link fetch (dial + frame
/// round trip). Deliberately short AND non-fatal: the fetch only runs
/// on the written-superblock-but-no-pin boot path, and any failure
/// collapses to "no link", which fail-stops exactly as before #46.
pub const CHAIN_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the chain-host fetch response frame. An upgrade link is a few
/// KiB (CBOR payload + ~5 KiB NSM document + 64-byte signature); 256 KiB
/// bounds a misbehaving host with generous slack.
pub const CHAIN_FETCH_MAX_FRAME: u32 = 256 * 1024;

/// Environment variable that opts an enclave into the anti-rollback
/// wiring (`1` / `true`). Absent or any other value: nbd-client runs
/// exactly as before this module existed.
pub const ENV_SYNCHRONIZER_ENABLED: &str = "SYNCHRONIZER_ENABLED";

/// Path of the enclave config JSON carrying the synchronizer trust
/// anchors (mirrors `enclavia-server::config::CONFIG_PATH` and the
/// hard-coded path `enclavia-chain-init` reads). This is a fixed,
/// compiled-in constant on purpose: the file is part of the measured EIF
/// rootfs, and its trust anchors (expected oracle PCRs, `debug_attestation`,
/// the #47 control public key) MUST NOT be locatable via host-controlled
/// input. Honouring an env-var override (as this module previously did via
/// `ENCLAVIA_CONFIG_PATH`) would let the parent VM redirect the path to an
/// unmeasured file of its choosing and substitute its own trust anchors, so
/// there is deliberately no override.
pub const CONFIG_PATH: &str = "/etc/enclavia/config.json";

/// True when the operator opted this enclave into synchronizer pinning.
///
/// Fail-stops (panics, which aborts the boot before the device is ever
/// served) on a value it does not recognize: the flag arms the
/// anti-rollback wiring, and a typo'd `SYNCHRONIZER_ENABLED=yes` that
/// silently mapped to "off" would boot an unprotected enclave that the
/// operator believes is protected (enclavia#99). Absent, `0`, `false`,
/// and empty remain "off": on production images the variable is
/// exported by the measured EIF init exactly when the builder-stamped
/// config says `synchronizer.enabled == true`, so absence is the
/// measured "this enclave has no rollback protection" choice, not a
/// host-droppable toggle.
pub fn synchronizer_enabled() -> bool {
    parse_synchronizer_flag(std::env::var(ENV_SYNCHRONIZER_ENABLED).ok().as_deref())
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Pure parser behind [`synchronizer_enabled`], split out for tests.
pub fn parse_synchronizer_flag(value: Option<&str>) -> Result<bool, String> {
    match value {
        None => Ok(false),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(v) => Err(format!(
            "unrecognized {ENV_SYNCHRONIZER_ENABLED}={v:?}: use 1/true to arm the anti-rollback \
             wiring or 0/false/unset to disable it; refusing to guess for a value that decides \
             whether the volume is rollback-protected"
        )),
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
        /// Its current per-key version (the CAS input for the next pin).
        version: Version,
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
    /// Written superblock, no pin under our key: either a rollback or
    /// the first boot after a staged upgrade (#46). Attempt a PCR
    /// `Transition` with a chain-host-fetched #47 upgrade link; without
    /// one, or on oracle rejection, fail-stop with the carried reason.
    /// NEVER falls back to Register: registering over a written region
    /// is exactly the history-erasure hole this module closes.
    TransitionOrFailStop(String),
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
/// | non-blank     | NotFound               | TransitionOrFailStop (staged upgrade, #46, or rollback evidence) |
///
/// Note the blank + Found case falls out of the hash compare: a pinned
/// commitment over a blank region (registered at first boot, no write
/// yet) matches a still-blank device and serves; a pinned commitment
/// over real data against a blanked device mismatches and fail-stops
/// (a wiped/substituted disk is a rollback).
pub fn boot_decision(region: &[u8], outcome: &GetOutcome) -> BootDecision {
    match outcome {
        GetOutcome::Found { commitment, .. } => {
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
                BootDecision::TransitionOrFailStop(
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
        Ok((commitment, version)) => Ok(GetOutcome::Found {
            commitment: commitment.0,
            version,
        }),
        Err(ClientError::Rpc(RpcError::NotFound)) => Ok(GetOutcome::NotFound),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Runtime region verification (closes the boot-verify TOCTOU)
// ---------------------------------------------------------------------------

/// What a region-covering READ must match at reply time.
#[derive(Clone, Copy, Debug)]
struct ReadWatch {
    /// Byte offset of the region within the read payload.
    payload_offset: usize,
    /// The watch seq of the newest pinned commitment when the read was
    /// issued: content at least this fresh is acceptable, anything older
    /// is rollback evidence.
    accept_from_seq: u64,
}

#[derive(Default)]
struct RegionWatchInner {
    /// (seq, commitment) in pin order, newest last. Seq 0 is the
    /// boot-verified commitment; each gated write takes the next seq.
    history: VecDeque<(u64, [u8; 32])>,
    /// (seq, commitment) of gated writes whose pins are still in flight,
    /// keyed by the NBD write handle.
    pending: HashMap<u64, (u64, [u8; 32])>,
    /// Region-covering reads in flight, keyed by the NBD read handle.
    reads: HashMap<u64, ReadWatch>,
    next_seq: u64,
}

/// Shared runtime view of the superblock region's acceptable contents.
///
/// The boot-time verify checks the device ONCE, before the kernel attaches,
/// via a single pre-attach read the host can trivially recognize (fixed
/// handle, fixed offset, fixed length) — and then serve a different,
/// rolled-back device for all subsequent traffic. This watch closes that
/// TOCTOU by verifying EVERY read reply that fully covers the region, at a
/// point the host cannot distinguish from btrfs's own superblock reads:
///
/// * the boot seeds `history` with the verified commitment;
/// * every gated (superblock) write registers its new commitment in
///   `pending` at gate time, and the pin actor moves it to `history` on
///   the durable PinOk;
/// * a read that fully covers the region records, at ISSUE time, the seq
///   of the newest pinned commitment (`accept_from_seq`); at REPLY time
///   its region bytes are hashed and must equal SOME known commitment
///   with seq >= `accept_from_seq` — content at least as fresh as when
///   the read was issued.
///
/// A legitimately concurrent read/write pair can yield either the pre- or
/// post-write content (both accepted, since a pending write's commitment
/// is known from its payload), so honest out-of-order NBD replies never
/// false-positive. Anything OLDER than the read's issue-time state is
/// rollback evidence and fatal. Reads can therefore never be answered
/// with state older than the moment they were issued — the guarantee the
/// single recognizable pre-attach read could not provide. (Reads that
/// only PARTIALLY cover the region are not verified: the full region is
/// never visible in one payload. btrfs reads the superblock as one 4 KiB
/// block, so the mount-time read — the critical one — is always covered.)
pub struct RegionWatch {
    inner: Mutex<RegionWatchInner>,
}

impl RegionWatch {
    /// Seed the watch with the boot-verified region commitment (seq 0).
    pub fn new(boot_commitment: [u8; 32]) -> Self {
        let mut inner = RegionWatchInner::default();
        inner.history.push_back((0, boot_commitment));
        inner.next_seq = 1;
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Issue-side (request proxy): register a read that fully covers the
    /// region. `payload_offset` locates the region inside the read payload.
    pub fn watch_read(&self, handle: u64, payload_offset: usize) {
        let mut i = self.inner.lock().unwrap();
        let accept_from = i.history.back().map(|(s, _)| *s).unwrap_or(0);
        i.reads.insert(
            handle,
            ReadWatch {
                payload_offset,
                accept_from_seq: accept_from,
            },
        );
    }

    /// Gate-side (request proxy): register a gated write's new commitment,
    /// in pin order (the pin actor drains jobs FIFO, so seqs assigned here
    /// match the order commitments land in `history`).
    pub fn begin_pending(&self, handle: u64, commitment: [u8; 32]) {
        let mut i = self.inner.lock().unwrap();
        let seq = i.next_seq;
        i.next_seq += 1;
        i.pending.insert(handle, (seq, commitment));
    }

    /// PinOk (pin actor): move the write's commitment from pending to
    /// history, then prune history entries too old to ever be an
    /// acceptable answer again: with reads in flight, the floor is the
    /// oldest in-flight read's `accept_from_seq` (its issue-time state);
    /// with none, the floor is the newest entry (older content can only
    /// ever be served to a read issued before it was superseded, and no
    /// such read exists). Keeps the per-read scan bounded instead of
    /// growing with every commit.
    pub fn commit(&self, handle: u64) {
        let mut i = self.inner.lock().unwrap();
        let Some((seq, c)) = i.pending.remove(&handle) else {
            warn!(
                handle,
                "pin completed for a handle with no pending watch entry (bookkeeping bug?)"
            );
            return;
        };
        i.history.push_back((seq, c));
        let floor = i
            .reads
            .values()
            .map(|w| w.accept_from_seq)
            .min()
            .unwrap_or(seq);
        while i.history.len() > 1 {
            if i.history[0].0 >= floor {
                break;
            }
            i.history.pop_front();
        }
    }

    /// Reply-side: the payload offset recorded for `handle`, if this read
    /// covers the region (and must be verified after extraction).
    pub fn read_payload_offset(&self, handle: u64) -> Option<usize> {
        self.inner
            .lock()
            .unwrap()
            .reads
            .get(&handle)
            .map(|w| w.payload_offset)
    }

    /// Reply-side: verify a read reply's captured region bytes against
    /// "content at least as fresh as when the read was issued". Unwatched
    /// handles pass through. A mismatch is rollback evidence; the returned
    /// string is the fatal reason.
    pub fn verify_read(&self, handle: u64, region: &[u8]) -> Result<(), String> {
        let mut i = self.inner.lock().unwrap();
        let Some(w) = i.reads.remove(&handle) else {
            return Ok(());
        };
        let hash = commitment_of_region(region);
        let fresh = i
            .history
            .iter()
            .any(|(s, c)| *s >= w.accept_from_seq && *c == hash)
            || i.pending
                .values()
                .any(|(s, c)| *s >= w.accept_from_seq && *c == hash);
        if fresh {
            Ok(())
        } else {
            Err(format!(
                "superblock region read (handle {handle}) does not match any pinned state at \
                 least as fresh as its issue time: the host is serving stale device content \
                 (rollback); refusing to serve"
            ))
        }
    }

    /// A read ended without verification (host error reply): drop the
    /// watch entry so it cannot linger.
    pub fn drop_read(&self, handle: u64) {
        self.inner.lock().unwrap().reads.remove(&handle);
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
///
/// `on_window_complete` fires the instant the extraction window is fully
/// captured, BEFORE the chunk carrying its last bytes is written to `dst`.
/// The host learns the region's new content only from what we forward, so
/// anything the callback registers (the pending pin commitment) is
/// registered before the host can possibly act on the new content — this
/// ordering is what lets a read racing the write accept the new content
/// without a false-positive rollback verdict.
pub async fn forward_bytes_extract<R, W, F>(
    src: &mut R,
    dst: &mut W,
    n: u64,
    extract_off: usize,
    extract_len: usize,
    on_window_complete: F,
) -> Result<Vec<u8>, FatalError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(&[u8]),
{
    if (extract_off as u64).saturating_add(extract_len as u64) > n {
        return Err("extraction window exceeds payload length".into());
    }
    let mut out = vec![0u8; extract_len];
    let mut buf = [0u8; 32 * 1024];
    let mut pos: u64 = 0;
    let mut remaining = n;
    let mut callback = Some(on_window_complete);
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
        pos += take as u64;
        remaining -= take as u64;

        // Fire the callback the moment the window closes, before this
        // chunk reaches `dst` (see the doc comment for the ordering
        // argument).
        if pos >= (extract_off + extract_len) as u64 {
            if let Some(cb) = callback.take() {
                cb(&out);
            }
        }

        dst.write_all(&buf[..take]).await?;
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
    /// Runtime region watch: superblock-covering reads are verified
    /// against pinned history, gated writes register their new
    /// commitment here before the PinJob is queued.
    pub watch: Arc<RegionWatch>,
}

/// Issues one Pin RPC. Abstracted from the network client so the actor's
/// gate/ordering semantics are testable without a Noise stack.
#[allow(async_fn_in_trait)]
pub trait Pinner {
    /// Pin `commitment`; resolve only once the ack is durable. An `Err`
    /// is fatal for the whole device.
    async fn pin(&mut self, commitment: [u8; 32]) -> Result<(), String>;
}

/// How many times a failed pin may trigger a session re-establishment
/// before the fail-stop policy takes over. Each attempt is a FULL new
/// session (fresh dial through the relay, which fails over to a healthy
/// cluster node, then a fresh Noise handshake and MUTUAL attestation),
/// so reconnection never weakens authentication. Bounded so a truly
/// unreachable oracle still fail-stops promptly.
pub const SYNC_RECONNECT_ATTEMPTS: u32 = 3;

/// Pause before each reconnect attempt: long enough for relay failover
/// to route around a restarting cluster node, short enough that a gated
/// superblock write does not stall the guest noticeably.
pub const SYNC_RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

/// Whether a pin failure is plausibly a dropped connection (a cluster
/// node restart severs the relay splice) rather than a protocol-level
/// answer. Only these trigger reconnection; a structured `Rpc` refusal,
/// a malformed frame, or a protocol mismatch stay immediately fatal,
/// because retrying them against another node would repeat the same
/// answer (or mask a real bug).
pub fn pin_error_is_retryable(e: &ClientError) -> bool {
    matches!(e, ClientError::Io(_) | ClientError::ConnectionClosed)
}

/// Re-establishes a full session after a dropped connection. Returns
/// the new client AND the key its attestation bound, which MUST equal
/// the old key (same enclave, same `/dev/nsm`, same PCRs): a mismatch
/// would mean our own attested identity changed mid-run, which is
/// fatal. Boxed so [`SyncPinner`] stays a nameable type.
pub type Reconnector<S> = Box<
    dyn FnMut() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(Client<S>, PcrKey), String>> + Send>,
        > + Send,
>;

/// Production [`Pinner`]: the authenticated synchronizer session, with
/// [`SYNC_RPC_TIMEOUT`] applied per RPC and bounded session
/// re-establishment on dropped connections.
///
/// The pinner tracks the key's current per-key `Version` and names it as
/// the compare-and-swap `expected_version` on every pin: two live writers
/// for one key (a host-booted clone pair shares the image's PCRs) can then
/// never both keep pinning — the loser's first divergent pin is rejected
/// with `VersionConflict` instead of silently last-write-winning, which is
/// what stops a forked volume's acknowledged writes from being rolled back
/// undetected. A `VersionConflict` is NOT immediately fatal: an earlier
/// attempt of the SAME pin may have committed before its ack was lost
/// (the at-least-once retry semantics), so we disambiguate with a `Get` —
/// current commitment == ours means our pin landed (idempotent success);
/// anything else is a genuine fork and fatal.
pub struct SyncPinner<S> {
    client: Client<S>,
    key: PcrKey,
    /// The version we currently believe the key is at (the next pin's CAS
    /// input). Seeded from the boot `Get`/registration and advanced by
    /// every successful pin.
    expected: Version,
    reconnect: Option<Reconnector<S>>,
}

impl<S> SyncPinner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// One pin attempt on the current session. `Err((retryable, msg))`.
    async fn pin_once(&mut self, commitment: [u8; 32]) -> Result<(), (bool, String)> {
        match tokio::time::timeout(
            SYNC_RPC_TIMEOUT,
            self.client
                .pin(self.key, self.expected, Commitment(commitment)),
        )
        .await
        {
            Ok(Ok(version)) => {
                debug!(version = version.0, "superblock pin durably acknowledged");
                self.expected = version;
                Ok(())
            }
            Ok(Err(ClientError::Rpc(RpcError::VersionConflict))) => {
                self.resolve_conflict(commitment).await
            }
            Ok(Err(e)) => Err((pin_error_is_retryable(&e), format!("pin rpc failed: {e}"))),
            // A timeout is indistinguishable from a dead node: retryable.
            Err(_) => Err((
                true,
                format!("pin rpc timed out after {SYNC_RPC_TIMEOUT:?} (synchronizer unreachable)"),
            )),
        }
    }

    /// Disambiguate a `VersionConflict`: did an earlier attempt of THIS
    /// pin commit before its ack was lost, or is a different writer
    /// ahead of us (a fork)?
    async fn resolve_conflict(&mut self, commitment: [u8; 32]) -> Result<(), (bool, String)> {
        match tokio::time::timeout(SYNC_RPC_TIMEOUT, self.client.get(self.key)).await {
            Ok(Ok((current, version))) if current == Commitment(commitment) => {
                info!(
                    version = version.0,
                    "pin version conflict resolved: our earlier attempt had already committed"
                );
                self.expected = version;
                Ok(())
            }
            Ok(Ok((_current, version))) => Err((
                false,
                format!(
                    "pin version conflict and the cluster holds a DIFFERENT commitment \
                     (version {}): a second live writer is pinning this key — volume fork \
                     detected, refusing to serve",
                    version.0
                ),
            )),
            // The conflict was real but we can't even read the cluster:
            // treat like any unreachable-oracle error (retryable).
            Ok(Err(e)) => Err((
                pin_error_is_retryable(&e),
                format!("conflict-disambiguation Get failed: {e}"),
            )),
            Err(_) => Err((
                true,
                "conflict-disambiguation Get timed out (synchronizer unreachable)".to_string(),
            )),
        }
    }
}

impl<S> Pinner for SyncPinner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn pin(&mut self, commitment: [u8; 32]) -> Result<(), String> {
        let mut last_err = match self.pin_once(commitment).await {
            Ok(()) => return Ok(()),
            Err((retryable, msg)) => {
                if !retryable || self.reconnect.is_none() {
                    return Err(msg);
                }
                msg
            }
        };
        for attempt in 1..=SYNC_RECONNECT_ATTEMPTS {
            warn!(
                attempt,
                last_err, "pin failed on a dropped session; re-establishing"
            );
            tokio::time::sleep(SYNC_RECONNECT_BACKOFF).await;
            let reconnect = self.reconnect.as_mut().expect("checked above");
            match reconnect().await {
                Ok((client, key)) => {
                    if key != self.key {
                        return Err(format!(
                            "reconnected session attested a DIFFERENT key ({key:?} != {:?}); \
                             our own identity cannot change mid-run, refusing",
                            self.key
                        ));
                    }
                    self.client = client;
                }
                Err(e) => {
                    last_err = format!("session re-establishment failed: {e}");
                    continue;
                }
            }
            match self.pin_once(commitment).await {
                Ok(()) => {
                    info!(attempt, "pin succeeded after session re-establishment");
                    return Ok(());
                }
                Err((retryable, msg)) => {
                    if !retryable {
                        return Err(msg);
                    }
                    last_err = msg;
                }
            }
        }
        Err(format!(
            "pin failed after {SYNC_RECONNECT_ATTEMPTS} session re-establishments: {last_err}"
        ))
    }
}

/// Drain [`PinJob`]s in order, resolving the gate after each durable
/// ack and nudging the reply pump. Any pin failure marks the gate and
/// returns an error, which tears the whole nbd-client down (fail-stop).
/// Returns `Ok(())` when the job queue closes (request proxy ended).
pub async fn pin_actor<P>(
    mut pinner: P,
    gate: Arc<PinGate>,
    watch: Arc<RegionWatch>,
    mut rx: mpsc::Receiver<PinJob>,
    nudge: mpsc::UnboundedSender<()>,
) -> Result<(), FatalError>
where
    P: Pinner,
{
    while let Some(job) = rx.recv().await {
        match pinner.pin(job.commitment).await {
            Ok(()) => {
                watch.commit(job.handle);
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
///
/// Additionally, every read reply that fully covers the superblock region
/// is captured en route and verified against the pinned history
/// ([`RegionWatch`]): the host cannot tell these verifications apart from
/// btrfs's own superblock reads, so it cannot serve a rolled-back device
/// after the (recognizable) pre-attach boot read — the boot-TOCTOU this
/// pump exists to close. A mismatch is fatal.
pub async fn gated_reply_proxy<R, W>(
    mut from_host: R,
    mut to_kernel: W,
    inflight: Arc<Mutex<HashMap<u64, u32>>>,
    gate: Arc<PinGate>,
    watch: Arc<RegionWatch>,
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
            // Read replies are never gated (only writes are), but a read
            // that fully covers the superblock region IS verified before
            // any of its bytes reach the kernel: buffer the (small) reply,
            // check the region against the pinned history, and only then
            // forward. Unwatched reads stream through as before. The
            // payload length comes from the kernel-issued request (bounded
            // by the kernel's own request-size caps), never the host.
            match watch.read_payload_offset(handle) {
                Some(payload_offset) => {
                    if error != 0 {
                        watch.drop_read(handle);
                        to_kernel.write_all(&header).await?;
                        to_kernel.flush().await?;
                        warn!(error, handle, "NBD read reply errored");
                        continue;
                    }
                    let mut payload = vec![0u8; len as usize];
                    from_host.read_exact(&mut payload).await?;
                    let region = &payload[payload_offset..payload_offset + SB_REGION_LEN];
                    watch
                        .verify_read(handle, region)
                        .map_err(|e| format!("fatal: {e}"))?;
                    debug!(
                        handle,
                        "superblock region read verified against pinned history"
                    );
                    to_kernel.write_all(&header).await?;
                    to_kernel.write_all(&payload).await?;
                    to_kernel.flush().await?;
                }
                None => {
                    to_kernel.write_all(&header).await?;
                    if error == 0 {
                        crate::forward_bytes(&mut from_host, &mut to_kernel, len as u64).await?;
                    } else {
                        warn!(error, handle, "NBD read reply errored");
                    }
                    to_kernel.flush().await?;
                }
            }
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
                debug!(handle, "holding superblock write reply until durable PinOk");
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
                debug!(handle, "releasing superblock write reply (PinOk)");
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
// Upgrade-link fetch (chain-host, #46)
// ---------------------------------------------------------------------------

/// Run chain-host's fetch verb on an established stream: write one
/// zero-length frame (`u32 BE 0`, exactly 4 zero bytes, where the
/// submit path puts a link), read back `[u32 BE len | CBOR ChainLink]`
/// carrying the enclave's LATEST upgrade link, or a zero length when
/// none exists.
///
/// Returns `None` for BOTH "no link" and every failure (truncated or
/// oversized frame, non-CBOR body): the fetch channel is host-relayed
/// and carries NO trust by design (the link is a bearer credential the
/// synchronizer verifies end to end), so a broken answer is
/// indistinguishable from a withheld one and must degrade to the same
/// fail-stop-as-before-#46 outcome, never a panic and never a weaker
/// verdict.
pub async fn fetch_link_over<S>(stream: &mut S) -> Option<ChainLink>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result: Result<Option<ChainLink>, FatalError> = async {
        stream.write_all(&0u32.to_be_bytes()).await?;
        stream.flush().await?;

        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes);
        if len == 0 {
            return Ok(None);
        }
        if len > CHAIN_FETCH_MAX_FRAME {
            return Err(
                format!("response frame claims {len} bytes (cap {CHAIN_FETCH_MAX_FRAME})").into(),
            );
        }
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let link: ChainLink = ciborium::from_reader(buf.as_slice())
            .map_err(|e| format!("response frame is not a CBOR ChainLink: {e}"))?;
        Ok(Some(link))
    }
    .await;

    match result {
        Ok(Some(link)) => {
            info!(
                sequence = ?link.sequence,
                "fetched latest upgrade link from chain-host"
            );
            Some(link)
        }
        Ok(None) => {
            debug!("chain-host has no upgrade link for this enclave");
            None
        }
        Err(e) => {
            warn!("chain-host upgrade-link fetch failed ({e}); treating as no link available");
            None
        }
    }
}

/// Dial chain-host (CID 2, port [`CHAIN_HOST_PORT`]) and fetch this
/// enclave's latest upgrade link. Best-effort by design: every failure
/// (connect refused, timeout, malformed frame) is logged at warn and
/// collapses to `None`, which the verify path treats exactly like "no
/// upgrade ever happened" (fail-stop on a written-but-unpinned device).
pub async fn fetch_latest_upgrade_link() -> Option<ChainLink> {
    let fetch = async {
        match tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            enclavia_vsock::host_cid().await,
            CHAIN_HOST_PORT,
        ))
        .await
        {
            Ok(mut stream) => fetch_link_over(&mut stream).await,
            Err(e) => {
                warn!("chain-host connect failed ({e}); treating as no upgrade link available");
                None
            }
        }
    };
    match tokio::time::timeout(CHAIN_FETCH_TIMEOUT, fetch).await {
        Ok(link) => link,
        Err(_) => {
            warn!(
                "chain-host upgrade-link fetch timed out after {CHAIN_FETCH_TIMEOUT:?}; \
                 treating as no upgrade link available"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Boot-time verification
// ---------------------------------------------------------------------------

/// NBD handle used for the boot-time direct superblock read, issued
/// before the kernel ever attaches (so it cannot collide with kernel
/// handles). ASCII "SYNCBOOT".
const BOOT_READ_HANDLE: u64 = 0x53594e43_424f4f54;

/// NBD handle for the boot-time LUKS2 header reads (ASCII "SYNCHDR!"),
/// same pre-attach window as [`BOOT_READ_HANDLE`].
const BOOT_HDR_READ_HANDLE: u64 = 0x53594e43_48445221;

/// Read `len` bytes at `offset` directly off the host NBD stream
/// (transmission phase, before the kernel is wired up), using `handle`.
async fn nbd_read_range<S>(
    stream: &mut S,
    handle: u64,
    offset: u64,
    len: u32,
) -> Result<Vec<u8>, FatalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 28];
    header[0..4].copy_from_slice(&nbd::NBD_REQUEST_MAGIC.to_be_bytes());
    // bytes 4..6: command flags (zero); 6..8: type.
    header[6..8].copy_from_slice(&nbd::NBD_CMD_READ.to_be_bytes());
    header[8..16].copy_from_slice(&handle.to_be_bytes());
    header[16..24].copy_from_slice(&offset.to_be_bytes());
    header[24..28].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.flush().await?;

    let mut reply = [0u8; 16];
    stream.read_exact(&mut reply).await?;
    let magic = u32::from_be_bytes(reply[0..4].try_into().unwrap());
    if magic != nbd::NBD_SIMPLE_REPLY_MAGIC {
        return Err(format!("boot verify: bad NBD reply magic {magic:#x}").into());
    }
    let error = u32::from_be_bytes(reply[4..8].try_into().unwrap());
    let got_handle = u64::from_be_bytes(reply[8..16].try_into().unwrap());
    if got_handle != handle {
        return Err(format!("boot verify: NBD reply for unexpected handle {got_handle:#x}").into());
    }
    if error != 0 {
        return Err(format!("boot verify: NBD read at offset {offset} failed ({error})").into());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read the pinned superblock region directly off the host NBD stream
/// (transmission phase, before the kernel is wired up).
pub async fn nbd_read_region<S>(stream: &mut S, device_offset: u64) -> Result<Vec<u8>, FatalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    nbd_read_range(
        stream,
        BOOT_READ_HANDLE,
        device_offset,
        SB_REGION_LEN as u32,
    )
    .await
}

/// The RPCs boot verification issues on the authenticated session.
/// Abstracted from the network client (mirroring [`Pinner`]) so the
/// verify / transition flow is testable without a Noise stack.
#[allow(async_fn_in_trait)]
pub trait BootOracle {
    /// `Client::get`.
    async fn get(&mut self, key: PcrKey) -> Result<(Commitment, Version), ClientError>;
    /// `Client::pin` (the CAS guard is ignored on a first-time Register).
    async fn pin(
        &mut self,
        key: PcrKey,
        expected_version: Version,
        commitment: Commitment,
    ) -> Result<Version, ClientError>;
    /// `Client::transition`.
    async fn transition(&mut self, link: ChainLink) -> Result<Version, ClientError>;
}

impl<S> BootOracle for Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn get(&mut self, key: PcrKey) -> Result<(Commitment, Version), ClientError> {
        Client::get(self, key).await
    }
    async fn pin(
        &mut self,
        key: PcrKey,
        expected_version: Version,
        commitment: Commitment,
    ) -> Result<Version, ClientError> {
        Client::pin(self, key, expected_version, commitment).await
    }
    async fn transition(&mut self, link: ChainLink) -> Result<Version, ClientError> {
        Client::transition(self, link).await
    }
}

/// Run the boot decision table against a live session: `Get`, compare,
/// and on a fresh device register the blank region. On the
/// written-but-unpinned verdict, attempt the #46 staged-upgrade
/// `Transition` (see [`transition_and_reverify`]); `upgrade_link` is the
/// LAZY chain-host fetch, awaited only on that branch. Any verdict other
/// than serve / register / successful transition propagates as a fatal
/// error.
///
/// Returns the key's current per-key version on success (the Found
/// version for a plain serve, `Version(0)` after a registration, the
/// carried-forward version after a transition): the CAS `expected_version`
/// the runtime pinner must name on its first pin.
pub async fn verify_or_register<O, F>(
    oracle: &mut O,
    key: PcrKey,
    region: &[u8],
    upgrade_link: F,
) -> Result<Version, FatalError>
where
    O: BootOracle,
    F: std::future::Future<Output = Option<ChainLink>>,
{
    let result = tokio::time::timeout(SYNC_RPC_TIMEOUT, oracle.get(key))
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
            let GetOutcome::Found { version, .. } = outcome else {
                unreachable!("Serve implies Found");
            };
            Ok(version)
        }
        BootDecision::RegisterThenServe => {
            info!("boot verify: fresh device, registering with the synchronizer");
            let commitment = Commitment(commitment_of_region(region));
            let version =
                tokio::time::timeout(SYNC_RPC_TIMEOUT, oracle.pin(key, Version(0), commitment))
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
            Ok(Version(0))
        }
        BootDecision::TransitionOrFailStop(reason) => {
            transition_and_reverify(oracle, key, region, upgrade_link, &reason).await
        }
        BootDecision::FailStop(reason) => Err(format!("boot verify: {reason}").into()),
    }
}

/// The #46 staged-upgrade branch of boot verification: the device
/// carries a written superblock but the oracle has no pin under our
/// (new) key, which is either a genuine rollback or the first boot
/// after a staged upgrade whose pin still lives under the OLD image's
/// PCR key. Disambiguate with the #47 upgrade link: if chain-host
/// serves one, submit `Transition { link }` on the already-established,
/// MUTUALLY-authenticated session (the only place this is ever called
/// from) and re-run the NORMAL verify against the migrated pin, whose
/// carried-forward commitment must match the disk. Anything short of
/// that full success (no link, non-upgrade link, oracle rejection,
/// post-transition mismatch) fail-stops exactly as before #46, with
/// the extra context appended to `fail_reason`.
///
/// SECURITY: the link is a bearer credential the ORACLE verifies end to
/// end (control signature against the pubkey frozen for the old key,
/// attestation/payload binding, new key == session key), so the
/// host-relayed fetch channel adds no trust: a forged or substituted
/// link can at worst be rejected. This path NEVER registers; Register
/// over a written region is the rollback hole this module closes.
///
/// Returns the carried-forward per-key version (the post-transition
/// `Get`'s), which the runtime pinner needs as its first CAS input.
async fn transition_and_reverify<O, F>(
    oracle: &mut O,
    key: PcrKey,
    region: &[u8],
    upgrade_link: F,
    fail_reason: &str,
) -> Result<Version, FatalError>
where
    O: BootOracle,
    F: std::future::Future<Output = Option<ChainLink>>,
{
    let Some(link) = upgrade_link.await else {
        return Err(format!(
            "boot verify: {fail_reason} (no upgrade link available from chain-host, so this \
             is not a recoverable staged upgrade)"
        )
        .into());
    };
    if link.kind != ChainLinkKind::Upgrade {
        warn!(kind = ?link.kind, "chain-host returned a non-upgrade link; treating as no link");
        return Err(format!(
            "boot verify: {fail_reason} (chain-host returned a {:?} link where only an \
             Upgrade link can authorize a transition)",
            link.kind
        )
        .into());
    }

    info!("submitting PCR transition: adopting the pre-upgrade pinned state under this image");
    let version = tokio::time::timeout(SYNC_RPC_TIMEOUT, oracle.transition(link))
        .await
        .map_err(|_| {
            format!(
                "boot verify: Transition timed out after {SYNC_RPC_TIMEOUT:?} \
                 (synchronizer unreachable)"
            )
        })?
        .map_err(|e| {
            format!(
                "boot verify: {fail_reason} (the synchronizer rejected the PCR transition: {e})"
            )
        })?;
    info!(
        version = version.0,
        "transition accepted; pinned state migrated to this image"
    );

    // Re-issue the Get and run the NORMAL verify path against the
    // migrated pin: same decision table, but transition and register are
    // no longer survivable answers (TransitionOk just told us the pin
    // exists under our key, so a second NotFound is oracle inconsistency,
    // and looping or registering would weaken the verdict).
    let result = tokio::time::timeout(SYNC_RPC_TIMEOUT, oracle.get(key))
        .await
        .map_err(|_| {
            format!(
                "boot verify: post-transition Get timed out after {SYNC_RPC_TIMEOUT:?} \
                 (synchronizer unreachable)"
            )
        })?;
    let outcome =
        get_outcome(result).map_err(|e| format!("boot verify: post-transition Get failed: {e}"))?;
    match boot_decision(region, &outcome) {
        BootDecision::Serve => {
            info!("boot verify: superblock matches the migrated pinned commitment; serving");
            let GetOutcome::Found { version, .. } = outcome else {
                unreachable!("Serve implies Found");
            };
            Ok(version)
        }
        BootDecision::FailStop(reason) => Err(format!("boot verify: {reason}").into()),
        BootDecision::RegisterThenServe | BootDecision::TransitionOrFailStop(_) => Err(
            "boot verify: the synchronizer reported no pin under our key immediately after \
             accepting the transition (inconsistent oracle state); refusing to serve"
                .into(),
        ),
    }
}

// ---------------------------------------------------------------------------
// LUKS2 data-offset cross-check (the watched region must be the REAL one)
// ---------------------------------------------------------------------------

/// LUKS2 fixed binary-header length; the JSON metadata area follows it.
const LUKS2_BINARY_HEADER_LEN: u64 = 4096;
/// LUKS2 magic at offset 0 ("LUKS" + 0xBA 0xBE).
const LUKS2_MAGIC: [u8; 6] = [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe];
/// Cap on the LUKS2 `hdr_size` we will read/parse (bounds a hostile
/// header's claimed size; real headers are 16 KiB).
const LUKS2_MAX_HDR_SIZE: u64 = 1 << 20;

/// Parse the data offset (bytes) of the first crypt segment out of a full
/// LUKS2 header (`[0, hdr_size)`). Returns `Ok(None)` when the blob does
/// not start with the LUKS2 magic (a fresh, never-formatted device).
/// Pure so it is unit-testable.
///
/// The JSON metadata area is zero-padded to `hdr_size` on disk (cryptsetup
/// pads with NULs), so the JSON string ends at the first NUL byte. Raw NUL
/// is impossible inside JSON, so truncating there is exactly what
/// cryptsetup itself does.
pub fn parse_luks2_data_offset(header: &[u8]) -> Result<Option<u64>, String> {
    if header.len() < LUKS2_BINARY_HEADER_LEN as usize || header[0..6] != LUKS2_MAGIC {
        return Ok(None);
    }
    let version = u16::from_be_bytes(header[6..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("LUKS header version {version} is not 2"));
    }
    let hdr_size = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if !(LUKS2_BINARY_HEADER_LEN..=LUKS2_MAX_HDR_SIZE).contains(&hdr_size) {
        return Err(format!("LUKS2 hdr_size {hdr_size} out of sane range"));
    }
    if (header.len() as u64) < hdr_size {
        return Err(format!(
            "LUKS2 header truncated: have {} bytes, hdr_size is {hdr_size}",
            header.len()
        ));
    }
    let json_area = &header[LUKS2_BINARY_HEADER_LEN as usize..hdr_size as usize];
    let json_end = json_area
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(json_area.len());
    let json: serde_json::Value = serde_json::from_slice(&json_area[..json_end])
        .map_err(|e| format!("LUKS2 JSON metadata does not parse: {e}"))?;
    let segments = json
        .get("segments")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "LUKS2 header has no `segments` object".to_string())?;
    // The crypt data segment is the one whose `type` is "crypt" (LUKS2
    // also lists no other segment types in practice).
    for (_id, seg) in segments {
        if seg.get("type").and_then(serde_json::Value::as_str) == Some("crypt") {
            let offset = seg
                .get("offset")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "LUKS2 crypt segment has no `offset`".to_string())?;
            return offset
                .parse::<u64>()
                .map(Some)
                .map_err(|e| format!("LUKS2 segment offset {offset:?} is not a number: {e}"));
        }
    }
    Err("LUKS2 header has no crypt segment".to_string())
}

/// Boot-time cross-check of the configured LUKS data offset against the
/// device's actual LUKS2 header. The watched superblock window is
/// `[data_offset + 64 KiB, +4 KiB)`; if `data_offset` is wrong, the watch
/// covers the wrong 4 KiB and anti-rollback is silently absent while
/// appearing enabled — so a disagreement is FATAL, never a warning.
///
/// A device with no LUKS2 header (a fresh, never-formatted volume) passes:
/// the first format happens inside this enclave with builder-controlled
/// parameters, and the resulting header is then checked by this same call
/// on every subsequent boot.
///
/// LIMITS (documented, see the module-level residual note): this check
/// reads the header over the same recognizable pre-attach channel the
/// region watch exists to distrust, so a host that serves the EXPECTED
/// header to these boot reads and a DIFFERENT header (different crypt
/// segment offset) to cryptsetup's runtime `luksOpen` reads can desync
/// the watched window — on every boot, not only the first. A zeroed
/// primary header plus a valid secondary (which cryptsetup falls back to)
/// is one concrete variant. The check therefore fully closes the
/// *accidental* config/device mismatch (a real hazard) but is only
/// defence-in-depth against the host; the load-bearing close is
/// builder-side: pin the offset (or a digest of the whole LUKS2 header,
/// which also covers keyslot tampering) in the measured enclave config.
pub async fn verify_luks_data_offset<S>(stream: &mut S, expected: u64) -> Result<(), FatalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let binary = nbd_read_range(
        stream,
        BOOT_HDR_READ_HANDLE,
        0,
        LUKS2_BINARY_HEADER_LEN as u32,
    )
    .await?;
    if binary[0..6] != LUKS2_MAGIC {
        info!(
            "boot verify: no LUKS2 header on device (fresh volume); offset check deferred to the first formatted boot"
        );
        return Ok(());
    }
    let hdr_size = u64::from_be_bytes(binary[8..16].try_into().unwrap());
    if !(LUKS2_BINARY_HEADER_LEN..=LUKS2_MAX_HDR_SIZE).contains(&hdr_size) {
        return Err(format!("boot verify: LUKS2 hdr_size {hdr_size} out of sane range").into());
    }
    let mut header = binary;
    if hdr_size > LUKS2_BINARY_HEADER_LEN {
        let json = nbd_read_range(
            stream,
            BOOT_HDR_READ_HANDLE,
            LUKS2_BINARY_HEADER_LEN,
            (hdr_size - LUKS2_BINARY_HEADER_LEN) as u32,
        )
        .await?;
        header.extend_from_slice(&json);
    }
    let actual = parse_luks2_data_offset(&header)?
        .ok_or("boot verify: device lost its LUKS2 header mid-read")?;
    if actual != expected {
        return Err(format!(
            "boot verify: LUKS2 header data offset {actual} does not match the configured \
             LUKS_DATA_OFFSET {expected}: the anti-rollback watch would cover the wrong \
             superblock region (silent rollback hole); refusing to serve"
        )
        .into());
    }
    info!(
        data_offset = expected,
        "boot verify: LUKS2 data offset matches the configured watch"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Session setup (config, NSM, vsock dial)
// ---------------------------------------------------------------------------

/// Subset of `/etc/enclavia/config.json` we need: the #47 control
/// pubkey (the same field enclavia-server reads) plus the synchronizer
/// trust anchors (#208).
#[derive(serde::Deserialize, Default)]
struct RawConfig {
    control_public_key: Option<String>,
    synchronizer: Option<RawSynchronizerSection>,
}

/// The `synchronizer` object inside the enclave config: the expected
/// oracle measurements and the attestation-verification mode. Baked
/// into the measured EIF, see the module docs' trust-anchor contract.
#[derive(serde::Deserialize)]
struct RawSynchronizerSection {
    /// Hex PCR triples (`{"PCR0": "...", "PCR1": "...", "PCR2": "..."}`,
    /// the same shape the chain endpoints use) the synchronizer cluster
    /// is allowed to present. Normally one entry; MUST be non-empty.
    expected_pcrs: Vec<enclavia_protocol::chain::PcrsHex>,
    /// `true` selects the skip-cert-chain verification path for the
    /// server's document (QEMU's self-signing NSM in dev clusters);
    /// `false` (the default, and the production value) requires the
    /// full AWS Nitro CA chain. Part of the trust decision, hence read
    /// from the measured config and never from the environment.
    #[serde(default)]
    debug_attestation: bool,
}

/// The synchronizer trust anchors loaded from the MEASURED enclave
/// config: everything the session setup needs that the host must not be
/// able to influence.
#[derive(Debug)]
pub struct SynchronizerTrust {
    /// 65-byte uncompressed SEC1 P-256 control pubkey (#47), sent as the
    /// attestation document's `user_data`.
    pub control_pubkey: [u8; 65],
    /// Expected synchronizer PCR policy the server's attestation is
    /// checked against (#208).
    pub server_policy: ServerPcrPolicy,
    /// Verification mode for the server's document (see
    /// [`RawSynchronizerSection::debug_attestation`]).
    pub debug_attestation: bool,
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

/// Load every synchronizer trust anchor from the enclave config: the
/// control pubkey, the expected oracle PCRs, and the verification mode.
///
/// Fail-stop on a missing `synchronizer` section, an EMPTY
/// `expected_pcrs` list, or any malformed PCR entry: with
/// `SYNCHRONIZER_ENABLED=1` the oracle MUST be verifiable, and serving
/// with an unauthenticated oracle would reopen the host-impersonation
/// rollback hole (#208). The config file is baked into the measured EIF,
/// so the host cannot supply or alter any of these values.
pub fn load_synchronizer_trust(path: &Path) -> Result<SynchronizerTrust, FatalError> {
    let control_pubkey = load_control_pubkey(path)?;

    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read enclave config {}: {e}", path.display()))?;
    let raw: RawConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse enclave config {}: {e}", path.display()))?;
    let section = raw.synchronizer.ok_or(
        "enclave config has no `synchronizer` section; the synchronizer wiring requires the \
         expected oracle PCRs (synchronizer.expected_pcrs) to authenticate the oracle (#208)",
    )?;
    if section.expected_pcrs.is_empty() {
        return Err(
            "enclave config `synchronizer.expected_pcrs` is empty; refusing to start with an \
             unverifiable oracle (fail-stop)"
                .into(),
        );
    }
    let mut expected = Vec::with_capacity(section.expected_pcrs.len());
    for (i, hex_triple) in section.expected_pcrs.iter().enumerate() {
        let pcrs = hex_triple.to_pcrs().map_err(|e| {
            format!("enclave config `synchronizer.expected_pcrs[{i}]` is malformed: {e}")
        })?;
        expected.push(pcrs);
    }

    Ok(SynchronizerTrust {
        control_pubkey,
        server_policy: ServerPcrPolicy::Expected(expected),
        debug_attestation: section.debug_attestation,
    })
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
/// real NSM document bound to it, and MUTUALLY authenticate: this
/// enclave attests to the oracle, and the oracle's answering attestation
/// is verified against the expected-PCR policy from the measured config
/// (#208). Every step is under an explicit timeout; any failure,
/// including the oracle failing to prove its identity, is fatal
/// (fail-stop, no retries).
pub async fn connect_and_authenticate() -> Result<SyncSession, FatalError> {
    // Trust anchors come only from the measured config at the fixed
    // CONFIG_PATH — never from a host-influenceable location (see the
    // CONFIG_PATH doc comment). No env-var override.
    let trust = load_synchronizer_trust(Path::new(CONFIG_PATH))?;

    let port = enclavia_protocol::mesh::SYNCHRONIZER_CUSTOMER_RELAY_PORT;
    info!(port, "connecting to the synchronizer relay over vsock");
    let cid = enclavia_vsock::host_cid().await;
    let stream = tokio::time::timeout(
        SYNC_CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)),
    )
    .await
    .map_err(|_| {
        format!("synchronizer relay connect timed out after {SYNC_CONNECT_TIMEOUT:?} (fail-stop)")
    })??;

    tokio::time::timeout(SYNC_RPC_TIMEOUT, async move {
        let hs = Handshake::start(stream).await?;
        let nonce = hs.handshake_hash().to_vec();
        let user_data = trust.control_pubkey.to_vec();
        let doc = tokio::task::spawn_blocking(move || request_nsm_attestation(nonce, user_data))
            .await
            .map_err(|e| format!("NSM attestation task panicked: {e}"))??;
        // Derive our own PcrKey from the document we just minted; the
        // listener derives the session key the same way on its side, so
        // RPC `key` fields match the session binding.
        let pcrs = enclavia_protocol::attestation::extract_own_pcrs(&doc)
            .map_err(|e| format!("cannot extract own PCRs from NSM document: {e}"))?;
        let key = PcrKey(pcrs.digest());
        // Mutual auth: send our document, then verify the oracle's
        // answering attestation (nonce-bound to this session) against
        // the measured-config policy. A server that cannot prove it is
        // the expected synchronizer is fail-stop.
        let client = hs
            .authenticate(doc, &trust.server_policy, trust.debug_attestation)
            .await?;
        info!("synchronizer session mutually authenticated (oracle PCRs verified)");
        Ok::<_, FatalError>(SyncSession { client, key })
    })
    .await
    .map_err(|_| {
        format!("synchronizer session setup timed out after {SYNC_RPC_TIMEOUT:?} (fail-stop)")
    })?
}

/// The result of a successful boot verification: the live session plus
/// the runtime-wiring seeds.
pub struct BootResult {
    /// RPC-ready, mutually-authenticated session (handed to the pinner).
    pub session: SyncSession,
    /// The boot-verified region commitment (seeds the [`RegionWatch`]).
    pub commitment: [u8; 32],
    /// The key's current per-key version (the runtime pinner's first CAS
    /// `expected_version`).
    pub version: Version,
}

/// Full boot sequence for the anti-rollback wiring: connect +
/// authenticate, cross-check the configured LUKS data offset against the
/// device's LUKS2 header, read the device's current superblock region off
/// the host stream, and run the decision table. Returns the
/// [`BootResult`] only if the device may be served.
pub async fn boot<H>(host: &mut H, data_offset: u64) -> Result<BootResult, FatalError>
where
    H: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = connect_and_authenticate().await?;
    // The watched region is derived from the configured data offset; prove
    // it matches the device's actual LUKS2 header before trusting any
    // classification derived from it (a wrong offset silently unwatches the
    // real superblock).
    verify_luks_data_offset(host, data_offset).await?;
    let region = nbd_read_region(host, data_offset + SB_PRIMARY_FS_OFFSET).await?;
    // The chain-host fetch future is lazy: it dials only if the verify
    // path reaches the transition branch (#46). The Transition itself
    // runs on `session.client`, i.e. strictly after the oracle's PCRs
    // were verified by `connect_and_authenticate`.
    let version = verify_or_register(
        &mut session.client,
        session.key,
        &region,
        fetch_latest_upgrade_link(),
    )
    .await?;
    // In every serve branch (Serve / RegisterThenServe / a successful
    // Transition re-verify) the pinned commitment equals the hash of the
    // region we just read, so that hash is the watch's seed.
    Ok(BootResult {
        session,
        commitment: commitment_of_region(&region),
        version,
    })
}

/// Turn a [`BootResult`] into the production [`Pinner`] for the actor,
/// with session re-establishment wired to a full
/// [`connect_and_authenticate`]: a fresh dial (the relay fails over to a
/// healthy cluster node), a fresh Noise handshake, and fresh MUTUAL
/// attestation. Boot verification is deliberately NOT re-run on
/// reconnect: the device has been live and gated the whole time, so the
/// pinned state cannot have moved under us; the key-continuity check in
/// [`SyncPinner`] guards the only thing that could change. The CAS
/// version likewise survives reconnects (same enclave, same state).
pub fn into_pinner(boot: BootResult) -> SyncPinner<tokio_vsock::VsockStream> {
    SyncPinner {
        client: boot.session.client,
        key: boot.session.key,
        expected: boot.version,
        reconnect: Some(Box::new(|| {
            Box::pin(async {
                let session = connect_and_authenticate()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok((session.client, session.key))
            })
        })),
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

    // --- SYNCHRONIZER_ENABLED parsing (enclavia#99) --------------------

    /// `1`/`true` arm the wiring; unset, empty, `0`, `false` leave it
    /// off (the measured "no rollback protection" choice).
    #[test]
    fn synchronizer_flag_recognized_values() {
        for (v, expect) in [
            (Some("1"), true),
            (Some("true"), true),
            (Some("TRUE"), true),
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("false"), false),
            (Some("False"), false),
        ] {
            assert_eq!(parse_synchronizer_flag(v).unwrap(), expect, "value {v:?}");
        }
    }

    /// Anything else is fail-stop, never silently "off": a typo like
    /// `yes` must not boot an unprotected enclave the operator believes
    /// is protected.
    #[test]
    fn synchronizer_flag_unrecognized_is_an_error() {
        for v in ["yes", "on", "enabled", "ture", "2"] {
            let err = parse_synchronizer_flag(Some(v)).unwrap_err();
            assert!(err.contains("unrecognized"), "value {v:?}: {err}");
        }
    }

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
            version: Version(0),
        };
        assert_eq!(boot_decision(&region, &outcome), BootDecision::Serve);
    }

    #[test]
    fn decision_found_mismatching_fail_stops() {
        let region = region_with_data();
        let outcome = GetOutcome::Found {
            commitment: [0x11; 32],
            version: Version(0),
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
    fn decision_present_not_found_transitions_or_fail_stops() {
        // The rollback-evidence case: device has data, oracle has no pin.
        // Since #46 this is the transition branch; WITHOUT a verified
        // upgrade link it still fail-stops (see the transition tests).
        let region = region_with_data();
        assert!(matches!(
            boot_decision(&region, &GetOutcome::NotFound),
            BootDecision::TransitionOrFailStop(_)
        ));
    }

    #[test]
    fn decision_blank_found_blank_hash_serves() {
        // Registered at first boot, crashed before any write: pinned
        // commitment is the blank hash, device still blank.
        let region = vec![0u8; SB_REGION_LEN];
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&region),
            version: Version(0),
        };
        assert_eq!(boot_decision(&region, &outcome), BootDecision::Serve);
    }

    #[test]
    fn decision_blank_found_data_hash_fail_stops() {
        // Oracle pinned real data; device was wiped: rollback.
        let region = vec![0u8; SB_REGION_LEN];
        let outcome = GetOutcome::Found {
            commitment: commitment_of_region(&region_with_data()),
            version: Version(0),
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
            version: Version(0),
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
                commitment: [0xaa; 32],
                version: Version(3),
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
            ClientError::Rpc(RpcError::VersionConflict),
            ClientError::ConnectionClosed,
        ] {
            assert!(get_outcome(Err(err)).is_err());
        }
    }

    // --- #46 transition path (verify_or_register) -----------------------

    /// Scripted [`BootOracle`]: pops pre-programmed RPC results in order
    /// and records every Transition link. `expect` panics double as the
    /// "this RPC must never be issued on this path" assertions (e.g. no
    /// Pin/Register on a written region).
    struct ScriptedOracle {
        gets: std::collections::VecDeque<Result<(Commitment, Version), ClientError>>,
        pins: std::collections::VecDeque<Result<Version, ClientError>>,
        transitions: std::collections::VecDeque<Result<Version, ClientError>>,
        seen_transitions: Vec<ChainLink>,
    }

    impl ScriptedOracle {
        fn new(
            gets: Vec<Result<(Commitment, Version), ClientError>>,
            pins: Vec<Result<Version, ClientError>>,
            transitions: Vec<Result<Version, ClientError>>,
        ) -> Self {
            Self {
                gets: gets.into_iter().collect(),
                pins: pins.into_iter().collect(),
                transitions: transitions.into_iter().collect(),
                seen_transitions: Vec::new(),
            }
        }
    }

    impl BootOracle for ScriptedOracle {
        async fn get(&mut self, _key: PcrKey) -> Result<(Commitment, Version), ClientError> {
            self.gets.pop_front().expect("unexpected Get")
        }
        async fn pin(
            &mut self,
            _key: PcrKey,
            _expected_version: Version,
            _commitment: Commitment,
        ) -> Result<Version, ClientError> {
            self.pins.pop_front().expect("unexpected Pin")
        }
        async fn transition(&mut self, link: ChainLink) -> Result<Version, ClientError> {
            self.seen_transitions.push(link);
            self.transitions.pop_front().expect("unexpected Transition")
        }
    }

    fn test_key() -> PcrKey {
        PcrKey([0x42; 32])
    }

    fn not_found() -> Result<(Commitment, Version), ClientError> {
        Err(ClientError::Rpc(RpcError::NotFound))
    }

    /// A structurally plausible #47 upgrade link. The contents are
    /// opaque to the client (the ORACLE verifies them), so dummy bytes
    /// are exactly as good as a real signed link here.
    fn test_upgrade_link(sequence: u64) -> ChainLink {
        ChainLink {
            id: None,
            sequence: Some(sequence),
            kind: ChainLinkKind::Upgrade,
            payload: vec![0x01, 0x02, 0x03],
            attestation: vec![0x04, 0x05],
            signature: Some(vec![0xab; 64]),
        }
    }

    /// The staged-upgrade happy path: written region, Get says NotFound,
    /// chain-host serves an upgrade link, the oracle accepts the
    /// Transition, and the re-issued Get returns the migrated pin whose
    /// commitment matches the disk. The device is served.
    #[tokio::test]
    async fn transition_success_serves() {
        let region = region_with_data();
        let migrated = Commitment(commitment_of_region(&region));
        let mut oracle = ScriptedOracle::new(
            vec![not_found(), Ok((migrated, Version(7)))],
            vec![],
            vec![Ok(Version(7))],
        );

        verify_or_register(&mut oracle, test_key(), &region, async {
            Some(test_upgrade_link(3))
        })
        .await
        .expect("transitioned device must be served");

        assert_eq!(oracle.seen_transitions.len(), 1);
        assert_eq!(oracle.seen_transitions[0].sequence, Some(3));
    }

    /// No upgrade link available: the written-but-unpinned device
    /// fail-stops exactly as before #46. No Transition, no Register.
    #[tokio::test]
    async fn transition_without_link_still_fail_stops() {
        let region = region_with_data();
        let mut oracle = ScriptedOracle::new(vec![not_found()], vec![], vec![]);

        let err = verify_or_register(&mut oracle, test_key(), &region, async { None })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rollback evidence"), "{err}");
        assert!(err.to_string().contains("no upgrade link"), "{err}");
        assert!(oracle.seen_transitions.is_empty());
    }

    /// The oracle rejecting the Transition is fail-stop, with the
    /// rejection reason in the fatal message.
    #[tokio::test]
    async fn transition_rejected_fail_stops() {
        let region = region_with_data();
        let mut oracle = ScriptedOracle::new(
            vec![not_found()],
            vec![],
            vec![Err(ClientError::Rpc(RpcError::TransitionRejected))],
        );

        let err = verify_or_register(&mut oracle, test_key(), &region, async {
            Some(test_upgrade_link(3))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("rollback evidence"), "{err}");
        assert!(err.to_string().contains("transition rejected"), "{err}");
    }

    /// A migrated pin whose commitment does NOT match the disk hits the
    /// existing mismatch fail-stop: the transition migrates state, it
    /// never weakens the compare.
    #[tokio::test]
    async fn transition_then_commitment_mismatch_fail_stops() {
        let region = region_with_data();
        let mut oracle = ScriptedOracle::new(
            vec![not_found(), Ok((Commitment([0x11; 32]), Version(7)))],
            vec![],
            vec![Ok(Version(7))],
        );

        let err = verify_or_register(&mut oracle, test_key(), &region, async {
            Some(test_upgrade_link(3))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("mismatch"), "{err}");
    }

    /// NotFound again right after TransitionOk is oracle inconsistency:
    /// fail-stop, never a second transition and never a Register (the
    /// scripted deques would panic on either).
    #[tokio::test]
    async fn transition_then_not_found_fail_stops() {
        let region = region_with_data();
        let mut oracle =
            ScriptedOracle::new(vec![not_found(), not_found()], vec![], vec![Ok(Version(7))]);

        let err = verify_or_register(&mut oracle, test_key(), &region, async {
            Some(test_upgrade_link(3))
        })
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("inconsistent oracle state"),
            "{err}"
        );
        assert_eq!(oracle.seen_transitions.len(), 1);
    }

    /// A link of the wrong kind (chain-host misbehaving) is treated as
    /// no link: fail-stop without ever submitting a Transition.
    #[tokio::test]
    async fn transition_with_non_upgrade_link_fail_stops() {
        let region = region_with_data();
        let mut oracle = ScriptedOracle::new(vec![not_found()], vec![], vec![]);

        let mut link = test_upgrade_link(3);
        link.kind = ChainLinkKind::Boot;
        let err = verify_or_register(&mut oracle, test_key(), &region, async { Some(link) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rollback evidence"), "{err}");
        assert!(oracle.seen_transitions.is_empty());
    }

    /// Untouched branches: a matching pin still serves, a fresh device
    /// still registers, and neither ever awaits the (lazy) link fetch:
    /// the fetch future panics if polled.
    #[tokio::test]
    async fn non_transition_branches_never_fetch_the_link() {
        let region = region_with_data();
        let mut oracle = ScriptedOracle::new(
            vec![Ok((Commitment(commitment_of_region(&region)), Version(1)))],
            vec![],
            vec![],
        );
        verify_or_register(&mut oracle, test_key(), &region, async {
            panic!("matching pin must not fetch the upgrade link")
        })
        .await
        .expect("matching pin must serve");

        let blank = vec![0u8; SB_REGION_LEN];
        let mut oracle = ScriptedOracle::new(vec![not_found()], vec![Ok(Version(0))], vec![]);
        verify_or_register(&mut oracle, test_key(), &blank, async {
            panic!("fresh device must not fetch the upgrade link")
        })
        .await
        .expect("fresh device must register and serve");
    }

    /// The boot outcome surfaces the per-key version for the runtime
    /// pinner's first CAS input: the Found version on a plain serve,
    /// `Version(0)` after a registration, the carried-forward version
    /// after a transition.
    #[tokio::test]
    async fn boot_returns_the_version_for_the_first_cas_pin() {
        let region = region_with_data();
        // Plain serve: the Found version (7) is returned.
        let mut oracle = ScriptedOracle::new(
            vec![Ok((Commitment(commitment_of_region(&region)), Version(7)))],
            vec![],
            vec![],
        );
        let v = verify_or_register(&mut oracle, test_key(), &region, async {
            panic!("matching pin must not fetch the upgrade link")
        })
        .await
        .unwrap();
        assert_eq!(v, Version(7));

        // Register: exactly Version(0).
        let blank = vec![0u8; SB_REGION_LEN];
        let mut oracle = ScriptedOracle::new(vec![not_found()], vec![Ok(Version(0))], vec![]);
        let v = verify_or_register(&mut oracle, test_key(), &blank, async { None })
            .await
            .unwrap();
        assert_eq!(v, Version(0));

        // Transition: the post-transition Get's version (the carried one).
        let mut oracle = ScriptedOracle::new(
            vec![
                not_found(),
                Ok((Commitment(commitment_of_region(&region)), Version(3))),
            ],
            vec![],
            vec![Ok(Version(3))],
        );
        let v = verify_or_register(&mut oracle, test_key(), &region, async {
            Some(test_upgrade_link(9))
        })
        .await
        .unwrap();
        assert_eq!(v, Version(3));
    }

    // --- #46 chain-host fetch framing -----------------------------------

    /// Round trip: the request is one zero-length frame, the response is
    /// a length-prefixed CBOR ChainLink, decoded intact.
    #[tokio::test]
    async fn fetch_round_trip_returns_link() {
        let (mut host, mut guest) = duplex(64 * 1024);
        let link = test_upgrade_link(5);
        let expected = link.clone();
        let server = tokio::spawn(async move {
            let mut req = [0xffu8; 4];
            host.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [0u8; 4], "fetch verb must be a zero-length frame");
            let mut body = Vec::new();
            ciborium::into_writer(&link, &mut body).unwrap();
            host.write_all(&(body.len() as u32).to_be_bytes())
                .await
                .unwrap();
            host.write_all(&body).await.unwrap();
            host.flush().await.unwrap();
        });

        let got = fetch_link_over(&mut guest).await.expect("link expected");
        assert_eq!(got, expected);
        server.await.unwrap();
    }

    /// A zero-length response frame means "no upgrade link exists".
    #[tokio::test]
    async fn fetch_zero_length_response_is_no_link() {
        let (mut host, mut guest) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 4];
            host.read_exact(&mut req).await.unwrap();
            host.write_all(&0u32.to_be_bytes()).await.unwrap();
            host.flush().await.unwrap();
        });

        assert_eq!(fetch_link_over(&mut guest).await, None);
        server.await.unwrap();
    }

    /// A response body that is not a CBOR ChainLink degrades to no-link
    /// (the fetch channel is untrusted; broken == withheld).
    #[tokio::test]
    async fn fetch_malformed_response_is_no_link() {
        let (mut host, mut guest) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 4];
            host.read_exact(&mut req).await.unwrap();
            host.write_all(&3u32.to_be_bytes()).await.unwrap();
            host.write_all(&[0xde, 0xad, 0xbe]).await.unwrap();
            host.flush().await.unwrap();
        });

        assert_eq!(fetch_link_over(&mut guest).await, None);
        server.await.unwrap();
    }

    /// A claimed frame length above the 256 KiB cap is rejected without
    /// reading the body: no-link.
    #[tokio::test]
    async fn fetch_oversized_frame_is_no_link() {
        let (mut host, mut guest) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 4];
            host.read_exact(&mut req).await.unwrap();
            host.write_all(&(CHAIN_FETCH_MAX_FRAME + 1).to_be_bytes())
                .await
                .unwrap();
            host.flush().await.unwrap();
        });

        assert_eq!(fetch_link_over(&mut guest).await, None);
        server.await.unwrap();
    }

    /// The daemon closing mid-frame (truncated length or body) is
    /// no-link, never a panic.
    #[tokio::test]
    async fn fetch_truncated_stream_is_no_link() {
        let (mut host, mut guest) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = [0u8; 4];
            host.read_exact(&mut req).await.unwrap();
            host.write_all(&64u32.to_be_bytes()).await.unwrap();
            host.write_all(&[0x01; 10]).await.unwrap();
            host.flush().await.unwrap();
            // Drop: only 10 of the claimed 64 body bytes ever arrive.
        });

        assert_eq!(fetch_link_over(&mut guest).await, None);
        server.await.unwrap();
    }

    // --- forward_bytes_extract ------------------------------------------

    #[tokio::test]
    async fn extract_within_single_chunk() {
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut src = Cursor::new(payload.clone());
        let mut dst = Vec::new();
        let region = forward_bytes_extract(&mut src, &mut dst, 8192, 1024, 4096, |_| {})
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
        let region =
            forward_bytes_extract(&mut src, &mut dst, payload.len() as u64, off, 4096, |_| {})
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
            forward_bytes_extract(&mut src, &mut dst, 1024, 512, 4096, |_| {})
                .await
                .is_err()
        );
    }

    /// The ordering contract the region watch relies on: the window
    /// callback fires the moment the window closes, BEFORE the chunk
    /// carrying its last bytes is written to `dst` — so anything the
    /// callback registers is registered before the host sees the content.
    #[tokio::test]
    async fn window_callback_fires_before_the_window_bytes_are_forwarded() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// A writer that reports how many bytes it has accepted so far.
        struct CountWriter {
            buf: Vec<u8>,
            count: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for CountWriter {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.buf.extend_from_slice(buf);
                self.count.store(self.buf.len(), Ordering::SeqCst);
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        // 96 KiB payload; window [32 KiB, 36 KiB) closes inside the second
        // 32 KiB chunk. At callback time only the first chunk (32 KiB) may
        // have been written to dst.
        let payload: Vec<u8> = (0..(96 * 1024u32)).map(|i| (i % 239) as u8).collect();
        let off = 32 * 1024;
        let mut src = Cursor::new(payload.clone());
        let written = Arc::new(AtomicUsize::new(0));
        let mut dst = CountWriter {
            buf: Vec::new(),
            count: written.clone(),
        };
        let dst_len_at_callback = std::cell::Cell::new(usize::MAX);
        let region_at_callback = std::cell::RefCell::new(Vec::new());
        let region = forward_bytes_extract(
            &mut src,
            &mut dst,
            payload.len() as u64,
            off,
            4096,
            |region| {
                dst_len_at_callback.set(written.load(Ordering::SeqCst));
                region_at_callback.replace(region.to_vec());
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dst_len_at_callback.get(),
            32 * 1024,
            "the callback must fire before the window's chunk is forwarded"
        );
        assert_eq!(region_at_callback.into_inner(), region);
        assert_eq!(dst.buf, payload);
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

    pub(crate) fn reply_header(error: u32, handle: u64) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&nbd::NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&error.to_be_bytes());
        h[8..16].copy_from_slice(&handle.to_be_bytes());
        h
    }

    pub(crate) struct PumpHarness {
        pub(crate) host: tokio::io::DuplexStream,
        pub(crate) kernel: tokio::io::DuplexStream,
        pub(crate) inflight: Arc<Mutex<HashMap<u64, u32>>>,
        #[allow(dead_code)]
        pub(crate) gate: Arc<PinGate>,
        pub(crate) watch: Arc<RegionWatch>,
        #[allow(dead_code)]
        pub(crate) nudge_tx: mpsc::UnboundedSender<()>,
        pub(crate) task: tokio::task::JoinHandle<Result<(), FatalError>>,
    }

    fn spawn_pump() -> PumpHarness {
        spawn_pump_with_watch(RegionWatch::new([0xbb; 32]))
    }

    pub(crate) fn spawn_pump_with_watch(watch: RegionWatch) -> PumpHarness {
        let (host, host_side) = duplex(256 * 1024);
        let (kernel_side, kernel) = duplex(256 * 1024);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let gate = Arc::new(PinGate::new());
        let watch = Arc::new(watch);
        let (nudge_tx, nudge_rx) = unbounded_channel();
        let task = tokio::spawn(gated_reply_proxy(
            host_side,
            kernel_side,
            inflight.clone(),
            gate.clone(),
            watch.clone(),
            nudge_rx,
        ));
        PumpHarness {
            host,
            kernel,
            inflight,
            gate,
            watch,
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
        let actor = tokio::spawn(pin_actor(
            pinner,
            gate.clone(),
            Arc::new(RegionWatch::new([0x00; 32])),
            pin_rx,
            nudge_tx,
        ));

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
        let actor = tokio::spawn(pin_actor(
            pinner,
            gate.clone(),
            Arc::new(RegionWatch::new([0x00; 32])),
            pin_rx,
            nudge_tx,
        ));

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

    // --- load_synchronizer_trust (#208 trust anchors) -------------------

    /// Write `contents` to a unique temp config file and return its path.
    fn write_config(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nbd-sync-trust-{}-{}.json",
            std::process::id(),
            name
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A valid 65-byte SEC1 control pubkey, base64-encoded, for config
    /// fixtures.
    fn control_pubkey_b64() -> String {
        use base64::Engine;
        let mut pk = [0x11u8; 65];
        pk[0] = 0x04;
        base64::engine::general_purpose::STANDARD.encode(pk)
    }

    fn hex48(byte: u8) -> String {
        hex_encode(&[byte; 48])
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Happy path: control pubkey + one expected PCR triple + explicit
    /// debug flag all load; the policy admits exactly the listed triple.
    #[test]
    fn trust_loads_with_expected_pcrs() {
        let config = format!(
            r#"{{
                "control_public_key": "{}",
                "synchronizer": {{
                    "expected_pcrs": [
                        {{"PCR0": "{}", "PCR1": "{}", "PCR2": "{}"}}
                    ],
                    "debug_attestation": true
                }}
            }}"#,
            control_pubkey_b64(),
            hex48(0xa5),
            hex48(0xa6),
            hex48(0xa7),
        );
        let path = write_config("happy", &config);
        let trust = load_synchronizer_trust(&path).expect("load");
        std::fs::remove_file(&path).ok();

        assert_eq!(trust.control_pubkey[0], 0x04);
        assert!(trust.debug_attestation);
        let listed = enclavia_protocol::attestation::Pcrs {
            pcr0: vec![0xa5; 48],
            pcr1: vec![0xa6; 48],
            pcr2: vec![0xa7; 48],
        };
        let other = enclavia_protocol::attestation::Pcrs {
            pcr0: vec![0x01; 48],
            pcr1: vec![0x02; 48],
            pcr2: vec![0x03; 48],
        };
        assert!(trust.server_policy.admits(&listed));
        assert!(!trust.server_policy.admits(&other));
    }

    /// `debug_attestation` defaults to FALSE (production full-chain
    /// verification) when omitted: forgetting the flag can only make
    /// verification stricter, never weaker.
    #[test]
    fn trust_debug_attestation_defaults_to_false() {
        let config = format!(
            r#"{{
                "control_public_key": "{}",
                "synchronizer": {{
                    "expected_pcrs": [
                        {{"PCR0": "{}", "PCR1": "{}", "PCR2": "{}"}}
                    ]
                }}
            }}"#,
            control_pubkey_b64(),
            hex48(0x10),
            hex48(0x11),
            hex48(0x12),
        );
        let path = write_config("default-debug", &config);
        let trust = load_synchronizer_trust(&path).expect("load");
        std::fs::remove_file(&path).ok();
        assert!(!trust.debug_attestation);
    }

    /// The decision the wiring hinges on: SYNCHRONIZER_ENABLED=1 with NO
    /// `synchronizer` section in the measured config is fail-stop, never
    /// an unauthenticated-oracle fallback.
    #[test]
    fn trust_missing_synchronizer_section_is_fatal() {
        let config = format!(r#"{{"control_public_key": "{}"}}"#, control_pubkey_b64());
        let path = write_config("no-section", &config);
        let err = load_synchronizer_trust(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        assert!(
            err.to_string().contains("expected_pcrs"),
            "error must name the missing trust anchor: {err}"
        );
    }

    /// An EMPTY expected_pcrs list is fail-stop: it would admit no oracle
    /// (the policy is fail-safe), so refuse at load time with a clear
    /// message instead of failing every connection cryptically.
    #[test]
    fn trust_empty_expected_pcrs_is_fatal() {
        let config = format!(
            r#"{{
                "control_public_key": "{}",
                "synchronizer": {{ "expected_pcrs": [] }}
            }}"#,
            control_pubkey_b64()
        );
        let path = write_config("empty-pcrs", &config);
        let err = load_synchronizer_trust(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    /// A malformed PCR entry (bad hex) is fail-stop.
    #[test]
    fn trust_malformed_pcr_hex_is_fatal() {
        let config = format!(
            r#"{{
                "control_public_key": "{}",
                "synchronizer": {{
                    "expected_pcrs": [
                        {{"PCR0": "not-hex", "PCR1": "{}", "PCR2": "{}"}}
                    ]
                }}
            }}"#,
            control_pubkey_b64(),
            hex48(0x21),
            hex48(0x22),
        );
        let path = write_config("bad-hex", &config);
        let err = load_synchronizer_trust(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("expected_pcrs[0]"), "{err}");
    }

    /// A missing control pubkey is NOT fatal through the trust loader: a
    /// non-upgradable enclave registers under the canonical un-signable
    /// control key (#41), so as long as the #208 oracle-authentication
    /// anchor (`expected_pcrs`) is present, the trust loads. Only a
    /// missing `synchronizer` section / empty `expected_pcrs` are fatal
    /// (covered by the tests below).
    #[test]
    fn trust_missing_control_pubkey_uses_non_upgradable_key() {
        let config = format!(
            r#"{{
                "synchronizer": {{
                    "expected_pcrs": [
                        {{"PCR0": "{}", "PCR1": "{}", "PCR2": "{}"}}
                    ]
                }}
            }}"#,
            hex48(0x31),
            hex48(0x32),
            hex48(0x33),
        );
        let path = write_config("no-control-key", &config);
        let trust = load_synchronizer_trust(&path).expect("missing control key must not be fatal");
        std::fs::remove_file(&path).ok();
        assert_eq!(
            trust.control_pubkey,
            enclavia_protocol::attestation::NON_UPGRADABLE_CONTROL_KEY,
            "a non-upgradable enclave must load the un-signable control key"
        );
    }

    /// A missing config file is fatal.
    #[test]
    fn trust_missing_config_file_is_fatal() {
        let path = std::env::temp_dir().join("nbd-sync-trust-does-not-exist.json");
        assert!(load_synchronizer_trust(&path).is_err());
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

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    /// Dropped-connection signatures trigger reconnection; protocol
    /// answers stay immediately fatal.
    #[test]
    fn retryable_classification() {
        use std::io::{Error, ErrorKind};
        assert!(pin_error_is_retryable(&ClientError::Io(Error::new(
            ErrorKind::BrokenPipe,
            "pipe"
        ))));
        assert!(pin_error_is_retryable(&ClientError::ConnectionClosed));
        assert!(!pin_error_is_retryable(&ClientError::Rpc(
            synchronizer::wire::RpcError::Unauthorized
        )));
        assert!(!pin_error_is_retryable(&ClientError::Cbor("x".into())));
        assert!(!pin_error_is_retryable(&ClientError::UnexpectedResponse(
            "x"
        )));
        assert!(!pin_error_is_retryable(&ClientError::Crypto("x".into())));
    }
}

#[cfg(test)]
mod region_watch_tests {
    use super::tests::{reply_header, spawn_pump_with_watch};
    use super::*;
    use tokio::time::timeout;

    fn region(b: u8) -> Vec<u8> {
        vec![b; SB_REGION_LEN]
    }

    // --- RegionWatch freshness semantics --------------------------------

    #[test]
    fn boot_commitment_is_accepted() {
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.watch_read(7, 0);
        assert_eq!(w.read_payload_offset(7), Some(0));
        w.verify_read(7, &region(0xaa)).unwrap();
    }

    #[test]
    fn rolled_back_content_is_rejected() {
        // The boot-TOCTOU scenario: the watch was seeded with the CURRENT
        // superblock, but the host serves an old snapshot's region to a
        // later read (e.g. the mount-time superblock read). Fatal.
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.watch_read(7, 0);
        let err = w.verify_read(7, &region(0x11)).unwrap_err();
        assert!(err.contains("rollback"), "{err}");
    }

    #[test]
    fn content_never_pinned_is_rejected() {
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.watch_read(7, 0);
        assert!(w.verify_read(7, &region(0xee)).is_err());
    }

    #[test]
    fn pending_write_content_is_accepted() {
        // A read racing a gated write can legitimately observe the new
        // content before the pin completes.
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.begin_pending(9, commitment_of_region(&region(0xbb)));
        w.watch_read(7, 0);
        w.verify_read(7, &region(0xbb)).unwrap();
        // And the pre-write content is still acceptable for this read.
        w.watch_read(8, 0);
        w.verify_read(8, &region(0xaa)).unwrap();
    }

    #[test]
    fn committed_write_becomes_the_fresh_floor() {
        // After the pin lands, a NEW read answered with the pre-pin
        // content is stale (rollback of one commit) and must fail.
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.begin_pending(9, commitment_of_region(&region(0xbb)));
        w.commit(9);
        w.watch_read(7, 0);
        assert!(w.verify_read(7, &region(0xaa)).is_err());
        w.watch_read(8, 0);
        w.verify_read(8, &region(0xbb)).unwrap();
    }

    #[test]
    fn read_issued_before_a_write_still_accepts_the_old_content() {
        // Out-of-order honesty: the read was issued while 0xaa was
        // current, so a delayed reply with 0xaa is fine even after a
        // newer pin landed.
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        w.watch_read(7, 0); // issued now, accept_from = seq of 0xaa
        w.begin_pending(9, commitment_of_region(&region(0xbb)));
        w.commit(9);
        w.verify_read(7, &region(0xaa)).unwrap();
        // ...and the newer content is fine for it too.
        w.watch_read(8, 0);
        w.verify_read(8, &region(0xbb)).unwrap();
    }

    #[test]
    fn unwatched_handles_pass_and_drop_works() {
        let w = RegionWatch::new(commitment_of_region(&region(0xaa)));
        // No watch_read: anything goes (not our business).
        w.verify_read(99, &region(0x00)).unwrap();
        w.watch_read(7, 0);
        w.drop_read(7);
        assert_eq!(w.read_payload_offset(7), None);
        w.verify_read(7, &region(0x00)).unwrap();
    }

    // --- reply-pump integration ------------------------------------------

    /// A region-covering read whose payload matches the pinned history
    /// streams through untouched.
    #[tokio::test]
    async fn pump_passes_a_verified_region_read() {
        let content = region(0x5a);
        let mut h = spawn_pump_with_watch(RegionWatch::new(commitment_of_region(&content)));
        h.watch.watch_read(9, 0);
        h.inflight.lock().unwrap().insert(9, SB_REGION_LEN as u32);

        h.host.write_all(&reply_header(0, 9)).await.unwrap();
        h.host.write_all(&content).await.unwrap();
        h.host.flush().await.unwrap();

        let mut hdr = [0u8; 16];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut hdr))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hdr, reply_header(0, 9));
        let mut payload = vec![0u8; SB_REGION_LEN];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, content);

        drop(h.host);
        h.task.await.unwrap().unwrap();
    }

    /// The boot-TOCTOU regression test: the host answered the pre-attach
    /// boot read with the current superblock (verify passed), then serves
    /// a rolled-back region to the mount-time read through the proxy.
    /// The pump must fail-stop.
    #[tokio::test]
    async fn pump_fail_stops_a_rolled_back_region_read() {
        let mut h = spawn_pump_with_watch(RegionWatch::new(commitment_of_region(&region(0x5a))));
        h.watch.watch_read(9, 0);
        h.inflight.lock().unwrap().insert(9, SB_REGION_LEN as u32);

        h.host.write_all(&reply_header(0, 9)).await.unwrap();
        h.host.write_all(&region(0x11)).await.unwrap(); // rolled-back content
        h.host.flush().await.unwrap();

        let result = timeout(Duration::from_secs(2), h.task).await.unwrap();
        let err = result.unwrap().unwrap_err();
        assert!(err.to_string().contains("rollback"), "{err}");
    }

    /// A read racing a gated write: the reply carrying the just-written
    /// content is accepted while the pin is still in flight.
    #[tokio::test]
    async fn pump_accepts_pending_write_content_for_a_racing_read() {
        let new_content = region(0x77);
        let mut h = spawn_pump_with_watch(RegionWatch::new(commitment_of_region(&region(0x5a))));
        h.watch
            .begin_pending(42, commitment_of_region(&new_content));
        h.watch.watch_read(9, 0);
        h.inflight.lock().unwrap().insert(9, SB_REGION_LEN as u32);

        h.host.write_all(&reply_header(0, 9)).await.unwrap();
        h.host.write_all(&new_content).await.unwrap();
        h.host.flush().await.unwrap();

        let mut payload = vec![0u8; SB_REGION_LEN + 16];
        timeout(Duration::from_secs(2), h.kernel.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        drop(h.host);
        h.task.await.unwrap().unwrap();
    }

    // --- LUKS2 header parsing --------------------------------------------

    /// Build a minimal LUKS2 header: 4 KiB binary header + JSON metadata.
    /// If `pad_to` is given, the JSON area is zero-padded so hdr_size
    /// reaches it — exactly what cryptsetup writes on disk (the default
    /// 16 KiB metadata area).
    fn luks2_header_padded(offset: u64, pad_to: Option<usize>) -> Vec<u8> {
        let json = format!(
            r#"{{"segments":{{"0":{{"type":"crypt","offset":"{offset}","size":"dynamic","iv_tweak":"0"}}}},"digests":{{}}}}"#
        );
        let hdr_size = pad_to
            .unwrap_or(LUKS2_BINARY_HEADER_LEN as usize + json.len())
            .max(LUKS2_BINARY_HEADER_LEN as usize + json.len());
        let mut h = vec![0u8; hdr_size];
        h[0..6].copy_from_slice(&LUKS2_MAGIC);
        h[6..8].copy_from_slice(&2u16.to_be_bytes());
        h[8..16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
        h[LUKS2_BINARY_HEADER_LEN as usize..LUKS2_BINARY_HEADER_LEN as usize + json.len()]
            .copy_from_slice(json.as_bytes());
        h
    }

    fn luks2_header(offset: u64) -> Vec<u8> {
        luks2_header_padded(offset, None)
    }

    #[test]
    fn parses_the_crypt_segment_offset() {
        let h = luks2_header(16 * 1024 * 1024);
        assert_eq!(parse_luks2_data_offset(&h).unwrap(), Some(16 * 1024 * 1024));
        let h = luks2_header(8 * 1024 * 1024);
        assert_eq!(parse_luks2_data_offset(&h).unwrap(), Some(8 * 1024 * 1024));
    }

    /// Regression: real cryptsetup headers zero-pad the JSON area to
    /// hdr_size (16 KiB by default); parsing must stop at the first NUL,
    /// or every existing formatted volume fails the boot check.
    #[test]
    fn parses_a_zero_padded_cryptsetup_header() {
        let h = luks2_header_padded(16 * 1024 * 1024, Some(16384));
        assert_eq!(h.len(), 16384);
        assert_eq!(parse_luks2_data_offset(&h).unwrap(), Some(16 * 1024 * 1024));
    }

    #[test]
    fn no_magic_is_none_not_an_error() {
        // A fresh (never-formatted) device: blank or garbage, never fatal.
        assert_eq!(parse_luks2_data_offset(&vec![0u8; 4096]).unwrap(), None);
        assert_eq!(parse_luks2_data_offset(&[1, 2, 3]).unwrap(), None);
    }

    #[test]
    fn truncated_or_malformed_header_is_an_error() {
        let mut h = luks2_header(16 * 1024 * 1024);
        h.truncate(4100); // JSON cut short
        assert!(parse_luks2_data_offset(&h).is_err());
        let mut h = luks2_header(16 * 1024 * 1024);
        h[7] = 3; // version 3
        assert!(parse_luks2_data_offset(&h).is_err());
    }

    #[test]
    fn missing_crypt_segment_is_an_error() {
        let json = r#"{"segments":{"0":{"type":"other","offset":"16777216"}}}"#;
        let hdr_size = LUKS2_BINARY_HEADER_LEN as usize + json.len();
        let mut h = vec![0u8; hdr_size];
        h[0..6].copy_from_slice(&LUKS2_MAGIC);
        h[6..8].copy_from_slice(&2u16.to_be_bytes());
        h[8..16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
        h[LUKS2_BINARY_HEADER_LEN as usize..].copy_from_slice(json.as_bytes());
        assert!(parse_luks2_data_offset(&h).is_err());
    }
}
