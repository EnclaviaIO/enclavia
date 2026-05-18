//! Wire format shared between the in-enclave egress daemon
//! (`enclavia-egress`) and the host-side relay (`egress-host`).
//!
//! Transport (vsock from inside the enclave, AF_VSOCK or
//! `vhost-device-vsock` UDS on the host depending on the runtime) is
//! external to this module: callers hand in any `AsyncRead + AsyncWrite`
//! and the helpers read or write the opener frame.
//!
//! On every new connection the in-enclave daemon writes one
//! length-prefixed CBOR [`Open`] frame, then the bidirectional byte
//! stream begins. The host-side relay reads the frame, dials the
//! requested destination, and splices.

use std::io;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size (in bytes) of the opener CBOR frame. Plenty of room for
/// the small `Open` enum we serialize today, but tight enough to reject
/// obvious junk before allocating.
pub const MAX_OPEN_FRAME_SIZE: u32 = 4096;

/// Opener frame sent by the in-enclave daemon on every new connection.
///
/// Wire format: 4-byte big-endian length prefix, then CBOR-encoded
/// `Open`, then the bidirectional byte stream begins.
///
/// IPv6 is intentionally not representable here. The epic punts IPv6
/// for v1; the in-enclave filter is expected to reject v6 destinations
/// before they ever reach the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Open {
    Tcp {
        #[serde(with = "ipv4_octets")]
        host: Ipv4Addr,
        port: u16,
    },
}

// Force `Ipv4Addr` onto a stable wire shape (4-byte array) regardless of
// serde's human-readable mode. CBOR's `is_human_readable()` is true, so
// the default Ipv4Addr impl would emit a string; we want the compact
// form and freedom to switch encoders later without a wire break.
pub(crate) mod ipv4_octets {
    use std::net::Ipv4Addr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(addr: &Ipv4Addr, s: S) -> Result<S::Ok, S::Error> {
        addr.octets().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Ipv4Addr, D::Error> {
        let bytes = <[u8; 4]>::deserialize(d)?;
        Ok(Ipv4Addr::from(bytes))
    }
}

/// Errors surfaced while reading the opener frame from a relay stream.
#[derive(Debug, thiserror::Error)]
pub enum ReadOpenError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("opener frame too large: {0} > {MAX_OPEN_FRAME_SIZE}")]
    FrameTooLarge(u32),
    #[error("failed to decode opener frame: {0}")]
    Decode(#[from] ciborium::de::Error<io::Error>),
}

/// Read the length-prefixed CBOR `Open` frame from `stream`.
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

/// Write a length-prefixed CBOR `Open` frame to `stream`.
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
        let open = Open::Tcp {
            host: Ipv4Addr::new(127, 0, 0, 1),
            port: 4242,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&open, &mut buf).unwrap();
        let decoded: Open = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(open, decoded);
    }
}
