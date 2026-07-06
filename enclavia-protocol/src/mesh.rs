//! Wire format for the synchronizer mesh relay.
//!
//! The synchronizer cluster is a set of in-enclave nodes that need to
//! talk to one another. An in-enclave node cannot dial another enclave
//! directly: it can only reach its own host over vsock. The future
//! `mesh-host` daemon (part of the host-side tooling, following the
//! `chain-host` conventions: ACK framing, 32 KiB vsock write chunking)
//! is the host-side relay that bridges these vsock connections into
//! plain-TCP inter-host links between the parent EC2 instances. The
//! end-to-end Noise channel between the two enclaves is load-bearing for
//! confidentiality, so the relay never sees plaintext; in production
//! `mesh-host`'s inter-host TCP is itself wrapped in WireGuard.
//!
//! On every new outbound mesh connection the in-enclave node writes one
//! length-prefixed CBOR [`Open`] frame naming the peer it wants to reach,
//! then reads exactly one ack byte, then the bidirectional byte stream
//! begins. `mesh-host` reads the frame, resolves `target_peer` to that
//! peer's host endpoint, dials it, and splices. This mirrors
//! `enclavia-protocol::egress`'s `Open` frame style exactly (4-byte
//! big-endian length prefix, then CBOR), so the two relays share one
//! framing idiom.
//!
//! ## The single-byte open ack (end-to-end, transits the relays)
//!
//! Right after the dialer writes its [`Open`] frame it reads exactly one
//! ack byte off the same stream:
//!
//! * [`OPEN_ACK_OK`] (`0x00`) means the end-to-end guest-to-guest path is
//!   established: the FAR side's relay successfully dialed its local
//!   guest's bootstrap port and the byte after it is the first byte of the
//!   remote enclave's Noise handshake.
//! * [`OPEN_ACK_FAILED`] (`0x01`), any other byte, or EOF means the path
//!   could not be set up (the target peer is down, the far relay could not
//!   reach its guest, etc). The dialer closes and retries with backoff.
//!
//! The ack **originates from the remote relay** (the one nearest the
//! target enclave) once it has a live connection to that enclave's
//! bootstrap listener, and it **transits the splice** back to the dialer.
//! The relays never inspect any byte after the [`Open`] frame: the ack is
//! the first byte the far relay forwards from its guest-side leg, so it is
//! the relay's only structured signal that the far leg came up before the
//! enclave-to-enclave Noise handshake takes over. (`mesh-host`
//! mirrors this contract: dial the named peer's bootstrap port, and on
//! success write [`OPEN_ACK_OK`] toward the originating side before
//! splicing; on failure write [`OPEN_ACK_FAILED`] and close.)
//!
//! Use [`read_open_ack`] on the dialer side and [`write_open_ack`] on the
//! relay side. The inbound (accepting) enclave never sees the ack byte: it
//! is consumed entirely between the two relays' splice and the dialer.
//!
//! Transport (vsock from inside the enclave, AF_VSOCK or
//! `vhost-device-vsock` UDS on the host) is external to this module:
//! callers hand in any `AsyncRead + AsyncWrite` and the helpers read or
//! write the opener frame.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::attestation::CONTROL_PUBKEY_LEN;

/// vsock port the in-enclave node dials to reach `mesh-host`, the
/// host-side relay that bridges the mesh into inter-host TCP.
/// Assignment settled in the synchronizer mesh design
/// pass (5004/5007 from the earlier draft collided with `secrets-host`
/// and the control channel).
pub const MESH_VSOCK_PORT: u32 = 5009;

/// vsock port a synchronizer node listens on for cluster bootstrap /
/// peer-join traffic. Assignment settled in the synchronizer mesh
/// design pass.
pub const SYNCHRONIZER_BOOTSTRAP_PORT: u32 = 5008;

/// vsock port a synchronizer node listens on for customer-enclave RPC
/// (`Pin` / `Get` / `Transition`). Assignment settled in the
/// synchronizer mesh design pass; supersedes the single-node binary's interim default of 5004.
pub const SYNCHRONIZER_CLIENT_PORT: u32 = 5010;

/// vsock port a CUSTOMER enclave's `nbd-client` dials on its OWN host
/// (CID 2) to reach the synchronizer cluster's customer RPC surface.
///
/// A customer enclave cannot dial the synchronizer enclaves directly (an
/// in-enclave binary only reaches its own parent over vsock), so a
/// host-side relay (same conventions as `egress-host` / `mesh-host`)
/// listens here and splices the
/// byte stream to a cluster node's [`SYNCHRONIZER_CLIENT_PORT`] (5010).
/// The relay never sees plaintext: the end-to-end Noise channel between
/// the customer enclave and the synchronizer node is load-bearing.
///
/// 5010 is the cluster's OWN customer listener (guest-side, inside the
/// synchronizer enclaves) and 5011 is the names side-channel
/// (`synchronizer-names-init`), so this had to be a fresh assignment.
pub const SYNCHRONIZER_CUSTOMER_RELAY_PORT: u32 = 5012;

/// Maximum size (in bytes) of the opener CBOR frame. Plenty of room for
/// the small `Open` struct we serialize today (a peer name), but tight
/// enough to reject obvious junk before allocating. Mirrors
/// `egress::MAX_OPEN_FRAME_SIZE`.
pub const MAX_OPEN_FRAME_SIZE: u32 = 4096;

/// Open ack byte the far relay writes back toward the dialer once it has a
/// live connection to the target peer's bootstrap listener. After this
/// byte the stream is end-to-end guest-to-guest and the Noise handshake
/// begins. See the module docs for the full contract.
pub const OPEN_ACK_OK: u8 = 0x00;

/// Open ack byte signalling the far relay could not establish the path to
/// the target peer (peer down, far relay could not reach its guest, etc).
/// Any byte that is not [`OPEN_ACK_OK`], plus EOF, is treated the same way
/// by [`read_open_ack`]: the dialer closes and retries with backoff.
pub const OPEN_ACK_FAILED: u8 = 0x01;

/// Outcome of reading the single open ack byte on the dialer side.
///
/// Returned by [`read_open_ack`]. Only [`OpenAck::Ok`] means the
/// end-to-end path is up; everything else is a failure the dialer must
/// retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAck {
    /// The far relay reported the end-to-end path is established
    /// ([`OPEN_ACK_OK`]). The next byte read belongs to the remote
    /// enclave's Noise handshake.
    Ok,
    /// The far relay reported failure: either [`OPEN_ACK_FAILED`] or some
    /// other unexpected byte. The carried byte is surfaced for logging.
    Failed(u8),
    /// The stream hit EOF before any ack byte arrived (the relay closed
    /// the connection). Treated as a failure.
    Eof,
}

/// Read exactly one open ack byte on the dialer side, after writing the
/// [`Open`] frame.
///
/// Maps [`OPEN_ACK_OK`] to [`OpenAck::Ok`], a clean EOF to [`OpenAck::Eof`],
/// and any other single byte (including [`OPEN_ACK_FAILED`]) to
/// [`OpenAck::Failed`]. Genuine transport read errors other than EOF
/// surface as `Err`.
pub async fn read_open_ack<S>(stream: &mut S) -> io::Result<OpenAck>
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    match stream.read_exact(&mut byte).await {
        Ok(_) => {
            if byte[0] == OPEN_ACK_OK {
                Ok(OpenAck::Ok)
            } else {
                Ok(OpenAck::Failed(byte[0]))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(OpenAck::Eof),
        Err(e) => Err(e),
    }
}

/// Write the single open ack byte. Used by the relay nearest the target
/// peer once it has dialed (or failed to dial) that peer's bootstrap
/// listener: pass `true` once the far leg is up, `false` on failure.
///
/// The relays never write any other byte before splicing, so this ack is
/// the first byte the far relay forwards from its guest-side leg.
pub async fn write_open_ack<S>(stream: &mut S, ok: bool) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let byte = if ok { OPEN_ACK_OK } else { OPEN_ACK_FAILED };
    stream.write_all(&[byte]).await?;
    stream.flush().await?;
    Ok(())
}

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

/// Why a mesh peer's identity-key signature over the Noise handshake hash
/// failed [`verify_mesh_identity`].
///
/// The mesh-identity signature is the channel-binding step the mutually
/// attested mesh layers on top of the attestation document: it proves the
/// enclave that produced the attestation (and announced
/// [`crate::attestation::AttestedIdentity::control_pubkey`] in the doc's
/// `user_data`) is the same party terminating *this* Noise channel, by
/// signing the channel's handshake hash with the matching private key.
#[derive(Debug, thiserror::Error)]
pub enum MeshIdentityError {
    /// The announced 65-byte SEC1 pubkey did not decode as a P-256 point.
    #[error("mesh identity pubkey does not decode as SEC1 P-256")]
    BadPubkey,
    /// The signature was not a 64-byte raw r||s ECDSA P-256 signature.
    #[error("mesh identity signature is not 64 bytes raw r||s P-256")]
    SignatureShape,
    /// The signature did not verify over the handshake hash under the
    /// announced pubkey.
    #[error("mesh identity signature does not verify over the handshake hash")]
    SignatureInvalid,
}

/// Sign `handshake_hash` with a per-boot P-256 mesh identity key, returning
/// the 64-byte raw r||s ECDSA signature.
///
/// This is the local half of the mesh channel binding: a node signs the
/// live Noise handshake hash with the same per-boot identity key whose
/// public half it stamped into its attestation document's `user_data`. The
/// peer verifies the result with [`verify_mesh_identity`] after extracting
/// that pubkey via [`crate::attestation::verify_and_extract`].
pub fn sign_mesh_identity(signing_key: &p256::ecdsa::SigningKey, handshake_hash: &[u8]) -> Vec<u8> {
    use p256::ecdsa::{Signature, signature::Signer};
    let sig: Signature = signing_key.sign(handshake_hash);
    sig.to_bytes().to_vec()
}

/// Verify a mesh peer's identity-key signature over the Noise handshake
/// hash.
///
/// `mesh_pubkey` is the 65-byte uncompressed SEC1 P-256 key extracted from
/// the peer's attestation document (`AttestedIdentity::control_pubkey`);
/// `signature` is the 64-byte raw r||s ECDSA signature the peer sent over
/// the channel; `handshake_hash` is this Noise session's hash (identical on
/// both ends). On success the caller knows the attested enclave is the same
/// party that terminates this channel, defeating a relay that splices a
/// captured attestation onto a channel it controls.
pub fn verify_mesh_identity(
    mesh_pubkey: &[u8; CONTROL_PUBKEY_LEN],
    signature: &[u8],
    handshake_hash: &[u8],
) -> Result<(), MeshIdentityError> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let verifying =
        VerifyingKey::from_sec1_bytes(mesh_pubkey).map_err(|_| MeshIdentityError::BadPubkey)?;
    let sig = Signature::from_slice(signature).map_err(|_| MeshIdentityError::SignatureShape)?;
    verifying
        .verify(handshake_hash, &sig)
        .map_err(|_| MeshIdentityError::SignatureInvalid)
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

    #[tokio::test]
    async fn open_ack_ok_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_open_ack(&mut a, true).await.unwrap();
        assert_eq!(read_open_ack(&mut b).await.unwrap(), OpenAck::Ok);
    }

    #[tokio::test]
    async fn open_ack_failed_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_open_ack(&mut a, false).await.unwrap();
        assert_eq!(
            read_open_ack(&mut b).await.unwrap(),
            OpenAck::Failed(OPEN_ACK_FAILED)
        );
    }

    #[tokio::test]
    async fn open_ack_unexpected_byte_is_failure() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x7f]).await.unwrap();
        a.flush().await.unwrap();
        assert_eq!(read_open_ack(&mut b).await.unwrap(), OpenAck::Failed(0x7f));
    }

    #[tokio::test]
    async fn open_ack_eof_is_failure() {
        let (a, mut b) = tokio::io::duplex(64);
        // Drop the writer without sending anything: the reader sees EOF.
        drop(a);
        assert_eq!(read_open_ack(&mut b).await.unwrap(), OpenAck::Eof);
    }

    #[test]
    fn ack_constants_are_distinct() {
        assert_eq!(OPEN_ACK_OK, 0x00);
        assert_eq!(OPEN_ACK_FAILED, 0x01);
        assert_ne!(OPEN_ACK_OK, OPEN_ACK_FAILED);
    }

    fn mesh_keypair() -> (p256::ecdsa::SigningKey, [u8; CONTROL_PUBKEY_LEN]) {
        use p256::ecdsa::SigningKey;
        let mut scalar = [0u8; 32];
        scalar[0] = 0x01;
        scalar[1] = 0x42;
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let mut pk = [0u8; CONTROL_PUBKEY_LEN];
        pk.copy_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
        (sk, pk)
    }

    #[test]
    fn mesh_identity_signature_roundtrips() {
        let (sk, pk) = mesh_keypair();
        let hh = [0xab; 32];
        let sig = sign_mesh_identity(&sk, &hh);
        verify_mesh_identity(&pk, &sig, &hh).expect("verify");
    }

    #[test]
    fn mesh_identity_rejects_wrong_handshake_hash() {
        let (sk, pk) = mesh_keypair();
        let sig = sign_mesh_identity(&sk, &[0x01; 32]);
        let err = verify_mesh_identity(&pk, &sig, &[0x02; 32]).unwrap_err();
        assert!(
            matches!(err, MeshIdentityError::SignatureInvalid),
            "{err:?}"
        );
    }

    #[test]
    fn mesh_identity_rejects_wrong_signer() {
        let (sk, _pk) = mesh_keypair();
        let hh = [0xcd; 32];
        let sig = sign_mesh_identity(&sk, &hh);
        // A different, structurally-valid SEC1 pubkey: the signature must
        // not verify under it.
        let mut other = [0u8; 32];
        other[0] = 0x01;
        other[1] = 0x99;
        let other_sk = p256::ecdsa::SigningKey::from_slice(&other).unwrap();
        let mut other_pk = [0u8; CONTROL_PUBKEY_LEN];
        other_pk.copy_from_slice(other_sk.verifying_key().to_encoded_point(false).as_bytes());
        let err = verify_mesh_identity(&other_pk, &sig, &hh).unwrap_err();
        assert!(
            matches!(err, MeshIdentityError::SignatureInvalid),
            "{err:?}"
        );
    }

    #[test]
    fn mesh_identity_rejects_malformed_signature() {
        let (_sk, pk) = mesh_keypair();
        let err = verify_mesh_identity(&pk, &[0xde, 0xad], &[0x00; 32]).unwrap_err();
        assert!(matches!(err, MeshIdentityError::SignatureShape), "{err:?}");
    }

    #[test]
    fn mesh_identity_rejects_bad_pubkey() {
        let (sk, _pk) = mesh_keypair();
        let hh = [0x11; 32];
        let sig = sign_mesh_identity(&sk, &hh);
        let bogus = [0u8; CONTROL_PUBKEY_LEN];
        let err = verify_mesh_identity(&bogus, &sig, &hh).unwrap_err();
        assert!(matches!(err, MeshIdentityError::BadPubkey), "{err:?}");
    }

    #[test]
    fn ports_are_distinct_and_match_design() {
        assert_eq!(SYNCHRONIZER_BOOTSTRAP_PORT, 5008);
        assert_eq!(MESH_VSOCK_PORT, 5009);
        assert_eq!(SYNCHRONIZER_CLIENT_PORT, 5010);
        // 5011 is the names side-channel (synchronizer-names-init); the
        // customer relay had to skip it.
        assert_eq!(SYNCHRONIZER_CUSTOMER_RELAY_PORT, 5012);
        // Sanity: no accidental collisions among the assignments.
        let ports = [
            SYNCHRONIZER_BOOTSTRAP_PORT,
            MESH_VSOCK_PORT,
            SYNCHRONIZER_CLIENT_PORT,
            SYNCHRONIZER_CUSTOMER_RELAY_PORT,
        ];
        for (i, p) in ports.iter().enumerate() {
            for q in &ports[i + 1..] {
                assert_ne!(p, q, "mesh ports must be distinct");
            }
        }
    }
}
