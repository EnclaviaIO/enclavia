//! `synchronizer-names-init`: in-enclave runtime identity fetcher.
//!
//! ## Why this exists
//!
//! The synchronizer's mesh allowlist admits a peer only when the peer's
//! attested PCR digest equals the node's OWN self-PCR digest (derived
//! from `/dev/nsm` at startup). For a three-node cluster to admit each
//! other, all three nodes must therefore run ONE identical EIF with
//! identical PCR0/1/2.
//!
//! That rules out baking each node's logical name (`MESH_SELF_NAME`) and
//! peer set (`MESH_PEERS`) into the measured image, or passing them on
//! the kernel command line: PCR1 measures the kernel + boot (including
//! the cmdline) and PCR2 the application ramdisk, so per-node identity
//! in either place would give each node a different PCR set and the
//! allowlist would reject every peer.
//!
//! Instead we inject identity at RUNTIME over an UNMEASURED vsock
//! side-channel, modelled on the existing per-enclave secrets path
//! (`enclavia-secrets-init` / `secrets-host`). Each guest has its own
//! `vhost-device-vsock` proxy socket, so the host stands up one tiny
//! "names responder" per guest that serves only that guest's identity;
//! no per-CID dispatch is needed.
//!
//! ## Pipeline at boot (called from the synchronizer EIF's `init.sh`)
//!
//! ```text
//!   open vsock CID 2 (host), port 5011 with a timeout
//!     │
//!     ▼
//!   read the length-prefixed identity payload (small UTF-8 text)
//!     │
//!     ▼
//!   write it verbatim to argv[1] (an env file the init sources)
//! ```
//!
//! ## Wire format
//!
//! 4-byte big-endian length prefix, then exactly that many bytes of
//! newline-terminated `KEY=value` text, e.g.:
//!
//! ```text
//!   MESH_SELF_NAME=node-a
//!   MESH_PEERS=node-b,node-c
//! ```
//!
//! Length-prefixed framing (not read-to-EOF) is REQUIRED, exactly like
//! `enclavia-secrets-init`: on the older AWS guest kernel a read-to-EOF
//! races the host's FIN at the `vhost-device-vsock` UDS↔virtio bridge
//! for a small payload, the bytes and FIN coalesce into one virtio
//! frame, and the guest read surfaces as ENOTCONN (os error 107). With
//! length framing the host does NOT shutdown(WRITE); it blocks on our
//! ACK byte instead, so by the time the socket closes we have already
//! read the payload. This is a one-shot, fail-closed step: any error
//! (connect, timeout, short read) is fatal and fails the boot. The
//! synchronizer itself also refuses to start without a valid mesh env
//! (at least two peers), so this just surfaces the failure earlier and
//! with a clearer error.
//!
//! Transport: one binary, one transport (`tokio-vsock` to host CID 2),
//! per the in-enclave crate convention. `vhost-device-vsock` translates
//! the host-side connection to its UDS at `<proxy>_5011` under QEMU; on
//! real Nitro CID 2 is the parent instance.

use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// The host vsock CID is detected at runtime via `enclavia_vsock::host_cid()`
// (NOT hardcoded 2): the parent is CID 3 under real Nitro but CID 2 under
// QEMU's vhost-device-vsock bridge. The old hardcoded 2 made this connect
// time out on real Nitro, and since a failed identity fetch is fatal (the
// init `set -e`-exits), it tore the enclave down seconds after boot.

/// Port the host-side names responder listens on. Picked to sit just
/// above the synchronizer's customer port (5010) and clear of the mesh
/// ports (5008 bootstrap, 5009 mesh-host) and the secrets port (5004).
const NAMES_HOST_PORT: u32 = 5011;

/// Upper bound on the identity payload. A few short lines; 64 KiB is
/// generous and bounds a misbehaving host.
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// How long we wait for the host responder's `accept`. The launcher
/// always stands the responder up before the guest boots, so a timeout
/// here means the host side is broken and we fail the boot loudly.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One-byte ACK we send after reading the payload, so the host's close
/// does not race our read at the vhost-device-vsock UDS↔virtio bridge
/// (same hazard `enclavia-secrets-init` documents). `0x06` = ASCII ACK.
const ACK_BYTE: u8 = 0x06;

#[tokio::main]
async fn main() {
    let out_path = match parse_argv() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("synchronizer-names-init: {msg}");
            std::process::exit(2);
        }
    };

    let payload = match fetch_names().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("synchronizer-names-init: fetching identity from host: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = std::fs::write(&out_path, &payload) {
        eprintln!(
            "synchronizer-names-init: writing identity to {}: {e}",
            out_path.display()
        );
        std::process::exit(1);
    }
    eprintln!(
        "synchronizer-names-init: wrote {} bytes of identity to {}",
        payload.len(),
        out_path.display()
    );
}

fn parse_argv() -> Result<PathBuf, String> {
    let mut args = std::env::args_os();
    let _exe = args.next();
    let out = args
        .next()
        .ok_or_else(|| "usage: synchronizer-names-init <out-env-file>".to_string())?;
    if args.next().is_some() {
        return Err("usage: synchronizer-names-init <out-env-file> (extra args)".into());
    }
    Ok(PathBuf::from(out))
}

/// Connect to the host names responder and read the length-prefixed
/// identity payload. Any failure is fatal (see module docs).
async fn fetch_names() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let host_cid = enclavia_vsock::host_cid().await;
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(host_cid, NAMES_HOST_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err(format!(
                "vsock {host_cid}:{NAMES_HOST_PORT} connect timed out after {CONNECT_TIMEOUT:?}"
            )
            .into());
        }
    };

    // Length-prefixed read: 4-byte BE length, then exactly N bytes.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err("host sent zero-length identity payload".into());
    }
    if len > MAX_PAYLOAD_BYTES {
        return Err(
            format!("identity payload length {len} exceeds max {MAX_PAYLOAD_BYTES}").into(),
        );
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;

    // ACK as soon as the bytes are in our address space. The host is
    // blocked on this byte (it never shutdown(WRITE)), so this is what
    // lets it close cleanly without the FIN racing our read.
    let _ = stream.write_all(&[ACK_BYTE]).await;

    Ok(bytes)
}
