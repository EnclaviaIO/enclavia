//! Wire format for the synchronizer mesh relay.
//!
//! The synchronizer cluster is a set of in-enclave nodes that need to
//! talk to one another. An in-enclave node cannot dial another enclave
//! directly: it can only reach its own host over vsock. The future
//! `mesh-host` daemon (shipped from `enclavia-crates`, following the
//! `chain-host` host-side conventions: `debug`/`enclave` feature split,
//! paired flake outputs, ACK framing, 32 KiB vsock write chunking) is
//! the host-side relay that bridges these vsock connections into
//! plain-TCP inter-host links between the parent EC2 instances. The
//! end-to-end Noise channel between the two enclaves is load-bearing for
//! confidentiality, so the relay never sees plaintext; in production
//! `mesh-host`'s inter-host TCP is itself wrapped in WireGuard.
//!
//! On every new outbound mesh connection the in-enclave node writes one
//! length-prefixed CBOR [`Open`] frame naming the peer it wants to reach,
//! then the bidirectional byte stream begins. `mesh-host` reads the
//! frame, resolves `target_peer` to that peer's host endpoint, dials it,
//! and splices. This mirrors `enclavia-protocol::egress`'s `Open` frame
//! style exactly (4-byte big-endian length prefix, then CBOR), so the
//! two relays share one framing idiom.
//!
//! Transport (vsock from inside the enclave, AF_VSOCK or
//! `vhost-device-vsock` UDS on the host) is external to this module:
//! callers hand in any `AsyncRead + AsyncWrite` and the helpers read or
//! write the opener frame.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// vsock port the in-enclave node dials to reach `mesh-host`, the
/// host-side relay that bridges the mesh into inter-host TCP. See
/// EnclaviaIO/enclavia-crates#125. Assignment settled in the #16 design
/// pass (5004/5007 from the earlier draft collided with `secrets-host`
/// and the control channel).
pub const MESH_VSOCK_PORT: u32 = 5009;

/// vsock port a synchronizer node listens on for cluster bootstrap /
/// peer-join traffic. Assignment settled in the #16 design pass.
pub const SYNCHRONIZER_BOOTSTRAP_PORT: u32 = 5008;

/// vsock port a synchronizer node listens on for customer-enclave RPC
/// (`Pin` / `Get` / `Transition`). Assignment settled in the #16 design
/// pass; supersedes the single-node binary's interim default of 5004.
pub const SYNCHRONIZER_CLIENT_PORT: u32 = 5010;

/// Maximum size (in bytes) of the opener CBOR frame. Plenty of room for
/// the small `Open` struct we serialize today (a peer name), but tight
/// enough to reject obvious junk before allocating. Mirrors
/// `egress::MAX_OPEN_FRAME_SIZE`.
pub const MAX_OPEN_FRAME_SIZE: u32 = 4096;

/// Opener frame the in-enclave node writes on every new mesh
/// connection to `mesh-host`.
///
/// Wire format: 4-byte big-endian length prefix, then CBOR-encoded
/// `Open`, then the bidirectional byte stream begins.
///
/// `target_peer` is an opaque, deployment-defined peer identifier (the
/// logical name of one of the other synchronizer nodes). `mesh-host`
/// owns the `target_peer -> host endpoint` mapping; this module deals
/// only in the name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
    /// Logical name of the synchronizer peer the node wants to reach.
    /// Resolved to a concrete host endpoint by `mesh-host`.
    pub target_peer: String,
}

/// Errors surfaced while reading the opener frame from a relay stream.
#[derive(Debug, thiserror::Error)]
pub enum ReadOpenError {
    /// Underlying transport I/O failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// The claimed frame length exceeds [`MAX_OPEN_FRAME_SIZE`].
    #[error("opener frame too large: {0} > {MAX_OPEN_FRAME_SIZE}")]
    FrameTooLarge(u32),
    /// CBOR decode of the opener frame failed.
    #[error("failed to decode opener frame: {0}")]
    Decode(#[from] ciborium::de::Error<io::Error>),
}

/// Read the length-prefixed CBOR [`Open`] frame from `stream`.
pub async fn read_open_frame<S>(stream: &mut S) -> Result<Open, ReadOpenError>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u32().await?;
    if len > MAX_OPEN_FRAME_SIZE {
        return Err(ReadOpenError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    let open: Open = ciborium::from_reader(&buf[..])?;
    Ok(open)
}

/// Write a length-prefixed CBOR [`Open`] frame to `stream`.
pub async fn write_open_frame<S>(stream: &mut S, open: &Open) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    ciborium::into_writer(open, &mut buf).expect("ciborium encode Open frame");
    let len: u32 = buf
        .len()
        .try_into()
        .expect("Open frame fits in u32 (CBOR encoding is small)");
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_roundtrip_cbor() {
        let open = Open {
            target_peer: "synchronizer-az-b".to_string(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&open, &mut buf).unwrap();
        let decoded: Open = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(open, decoded);
    }

    #[tokio::test]
    async fn open_frame_roundtrip_over_stream() {
        let open = Open {
            target_peer: "synchronizer-az-c".to_string(),
        };
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_open_frame(&mut a, &open).await.unwrap();
        let decoded = read_open_frame(&mut b).await.unwrap();
        assert_eq!(open, decoded);
    }

    #[tokio::test]
    async fn oversized_open_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // Claim a length past the cap; the reader must bail before
        // allocating or reading a body.
        a.write_u32(MAX_OPEN_FRAME_SIZE + 1).await.unwrap();
        a.flush().await.unwrap();
        let err = read_open_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, ReadOpenError::FrameTooLarge(_)), "{err:?}");
    }

    #[test]
    fn ports_are_distinct_and_match_design() {
        assert_eq!(SYNCHRONIZER_BOOTSTRAP_PORT, 5008);
        assert_eq!(MESH_VSOCK_PORT, 5009);
        assert_eq!(SYNCHRONIZER_CLIENT_PORT, 5010);
        // Sanity: no accidental collisions among the three.
        let ports = [
            SYNCHRONIZER_BOOTSTRAP_PORT,
            MESH_VSOCK_PORT,
            SYNCHRONIZER_CLIENT_PORT,
        ];
        for (i, p) in ports.iter().enumerate() {
            for q in &ports[i + 1..] {
                assert_ne!(p, q, "mesh ports must be distinct");
            }
        }
    }
}
