//! Mutual peer attestation over a Noise channel.
//!
//! Both peers attest and both verify. After the `Noise_NN` handshake
//! completes, each side:
//!
//! 1. Produces its own NSM attestation document bound to the handshake hash
//!    (`nonce = handshake_hash`, `user_data = mesh_pubkey`) and signs the
//!    handshake hash with its per-boot mesh identity key, then sends both as a
//!    [`MeshFrame::Authenticate`].
//! 2. Reads the peer's `Authenticate` and verifies, in order:
//!    * the attestation document with
//!      [`enclavia_protocol::attestation::verify_and_extract`] (which enforces
//!      the handshake-hash binding, so a captured document cannot be replayed,
//!      and yields the peer's PCRs + 65-byte SEC1 mesh pubkey);
//!    * the peer's PCR digest against the self-PCR allowlist (it must be
//!      running our image);
//!    * the peer's identity-key signature over the handshake hash with
//!      [`enclavia_protocol::mesh::verify_mesh_identity`], which proves the
//!      attested enclave is the same party terminating *this* channel (a relay
//!      that spliced a captured document onto a channel it controls cannot
//!      produce this signature).
//!
//! If either side rejects, the connection is dropped and no attested channel
//! is established. The handshake hash is identical on both ends of a Noise
//! session, so a document forged for a different session carries the wrong
//! nonce and fails verification: the same channel-binding trick the
//! single-node listener uses, applied symmetrically and reinforced by the
//! identity-key signature.
//!
//! ## Initiator/responder selection
//!
//! `Noise_NN` is asymmetric (one side writes the first message). A node always
//! *dials* its peers and *accepts* their dials, so the mapping is "dialer =
//! Noise initiator, acceptor = Noise responder". A given physical connection
//! has exactly one dialer, so this is unambiguous.
//!
//! ## Mutual `Hello` (both sides announce their name)
//!
//! After attestation BOTH ends exchange a [`MeshFrame::Hello`] naming
//! themselves, in a strict ping-pong keyed on the Noise role (dialer sends
//! first then reads, responder reads first then sends), exactly mirroring the
//! `Authenticate` ordering rationale above. The acceptor uses the dialer's
//! `Hello` to attribute the inbound stream and rejects a name outside its
//! configured peer set (self-name is never in that set, so a reflected dial
//! cannot be admitted). The dialer uses the responder's `Hello` to confirm it
//! reached the peer it asked the relay for: a malicious `mesh-host` could
//! splice an A->B dial into a connection to peer C, and since all nodes have
//! identical PCRs attestation cannot tell them apart, but each node honestly
//! self-claims its name, so the dialer rejects the channel when the announced
//! name is not the one it dialed. This is a routing check among
//! already-mutually-attested, identical, trusted peers; the PCR allowlist and
//! the identity signature remain the security boundary.

use enclavia_protocol::attestation::{self, CONTROL_PUBKEY_LEN};
use enclavia_protocol::{
    NoiseTransport, perform_handshake_as_initiator, perform_handshake_as_responder,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::PcrKey;
use crate::mesh::attestation::AttestationProvider;
use crate::mesh::config::PcrAllowlist;
use crate::mesh::identity::MeshIdentity;

/// Maximum size (bytes) of an inbound ENCRYPTED mesh frame on the wire.
/// `Noise_NN_25519_ChaChaPoly_BLAKE2s` caps a single message at 65535 bytes;
/// a Nitro attestation document is ~5 KiB, well within budget. Matches the
/// single-node listener's `MAX_FRAME_SIZE`.
pub const MAX_FRAME_SIZE: u32 = 65535;

/// Cap a single transport write at 32 KiB: AF_VSOCK rejects larger writes
/// (see CLAUDE.md). The handshake's attestation frame and all RPC payloads are
/// chunked at this boundary on the way out.
pub const VSOCK_WRITE_CHUNK: usize = 32 * 1024;

/// One frame over the Noise-encrypted mesh channel.
///
/// [`MeshFrame::Authenticate`] is the boot-time mutual attestation;
/// [`MeshFrame::Hello`] is the dialer's logical-name label (see below);
/// [`MeshFrame::Rpc`] carries the id-correlated RPC envelope the
/// [`super::rpc`] layer rides. The enum is tagged so future slices can add
/// frames without a wire break; the mesh layer never looks inside an `Rpc`
/// payload's `body` (it is opaque CBOR for now, Raft defines it in slice 3).
///
/// ## Why `Hello`
///
/// In a same-image cluster every node measures the *same* PCRs, so the
/// attestation digest cannot distinguish which peer is on the other end. Right
/// after mutual attestation BOTH ends send `Hello { from = self_name }`: the
/// dialer's lets the acceptor label the inbound stream with the source peer's
/// logical name, the responder's lets the dialer confirm it reached the peer
/// it asked the relay for (a misrouted or reflected dial announces the wrong
/// name and is dropped). This is a routing label among
/// already-mutually-attested, bit-for-bit-identical peers (the PCR allowlist
/// and the identity signature are the trust boundary, and both have already
/// passed): it confers no authority, it only names which of the
/// indistinguishable peers is on the other end.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame")]
pub enum MeshFrame {
    /// First frame each side sends after the Noise handshake: its NSM
    /// attestation document (`nonce`-bound to the handshake hash, carrying the
    /// sender's 65-byte SEC1 P-256 mesh pubkey in `user_data`) plus a 64-byte
    /// raw r||s P-256 signature over the handshake hash by that mesh key.
    Authenticate {
        /// Raw NSM attestation document bytes.
        nsm_doc: Vec<u8>,
        /// 64-byte raw r||s ECDSA P-256 signature over the Noise handshake
        /// hash, by the mesh key whose public half is in `nsm_doc`'s
        /// `user_data`.
        identity_sig: Vec<u8>,
    },
    /// Sent by BOTH ends immediately after mutual attestation: the sender's
    /// own logical peer name. The dialer's lets the acceptor attribute the
    /// inbound stream; the responder's lets the dialer confirm it reached the
    /// peer it dialed (defeating a relay that misroutes or reflects a dial).
    Hello {
        /// The sender's `self_name`.
        from: String,
    },
    /// An id-correlated RPC envelope (request or response). Opaque to the
    /// handshake layer; decoded by [`super::rpc`].
    Rpc {
        /// CBOR-encoded [`super::rpc::Envelope`].
        envelope: Vec<u8>,
    },
}

/// The verified identity of a peer admitted by the mutual-attestation
/// handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// SHA-256 of the peer's attested PCR0/1/2. In a same-image cluster this
    /// equals the node's own digest (that is the allowlist check).
    pub pcr_digest: PcrKey,
    /// The peer's 65-byte SEC1 P-256 per-boot mesh pubkey, from its
    /// attestation document's `user_data`, having verified its signature over
    /// the handshake hash.
    pub mesh_pubkey: [u8; CONTROL_PUBKEY_LEN],
}

/// Why a mutual-attestation handshake failed.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// Transport I/O failure during the handshake or frame exchange.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The `Noise_NN` handshake itself failed before any frame exchange.
    #[error("noise handshake: {0}")]
    Noise(String),
    /// Noise transport-mode encrypt/decrypt failed.
    #[error("noise crypto: {0}")]
    Crypto(String),
    /// Producing this node's own attestation document failed.
    #[error("local attestation: {0}")]
    LocalAttestation(String),
    /// An inbound frame's claimed length exceeded [`MAX_FRAME_SIZE`].
    #[error("frame too large: {0} > {MAX_FRAME_SIZE}")]
    FrameTooLarge(u32),
    /// CBOR decode of an inbound frame failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// The first frame from the peer was not [`MeshFrame::Authenticate`].
    #[error("peer's first frame was not Authenticate")]
    NotAuthenticate,
    /// The peer's attestation document failed verification (bad nonce
    /// binding, malformed document, or missing/short `user_data`).
    #[error("peer attestation: {0}")]
    PeerAttestation(String),
    /// The peer attested, but its PCR digest is not in the self-PCR
    /// allowlist: it is not running our image, so it is not a cluster peer.
    #[error("peer PCR digest not in allowlist (peer is not running our image)")]
    PcrNotAllowed,
    /// The peer's identity-key signature over the handshake hash did not
    /// verify against the pubkey in its attestation document. The attested
    /// enclave is not the party terminating this channel.
    #[error("peer mesh-identity signature failed: {0}")]
    IdentitySignature(String),
    /// The peer hung up before completing the attestation exchange.
    #[error("peer closed the connection during the handshake")]
    PeerClosed,
}

/// Which Noise role this side plays for a given physical connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The dialer: drives the first Noise handshake message.
    Initiator,
    /// The acceptor: responds to the first Noise handshake message.
    Responder,
}

/// Run the mutual-attestation handshake on `stream` and, on success, return
/// the established Noise transport plus the verified peer identity.
///
/// `role` selects the Noise side (dialer = [`Role::Initiator`], acceptor =
/// [`Role::Responder`]). `attestor` produces this node's own document;
/// `identity` signs the handshake hash; `allowlist` gates which peer PCR
/// digest is admitted. `debug_mode` selects the skip-cert-chain (QEMU / test)
/// vs full-Nitro-CA attestation path for verifying the *peer's* document,
/// mirroring the single-node listener.
pub async fn mutual_authenticate<S, A>(
    stream: &mut S,
    role: Role,
    attestor: &A,
    identity: &MeshIdentity,
    allowlist: &PcrAllowlist,
    debug_mode: bool,
) -> Result<(NoiseTransport, PeerIdentity), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: AttestationProvider + ?Sized,
{
    // 0. Noise handshake. Both ends derive the same `handshake_hash`, which is
    //    the channel-binding token we put in each attestation's nonce and sign
    //    with the mesh identity key.
    let (mut transport, handshake_hash) = match role {
        Role::Initiator => perform_handshake_as_initiator(stream).await,
        Role::Responder => perform_handshake_as_responder(stream).await,
    }
    .map_err(|e| HandshakeError::Noise(format!("{e}")))?;

    // 1. Produce our own attestation, bound to this session's hash, and sign
    //    the hash with our per-boot identity key.
    let nsm_doc = attestor
        .attest(&handshake_hash)
        .await
        .map_err(|e| HandshakeError::LocalAttestation(format!("{e}")))?;
    let identity_sig = identity.sign_handshake(&handshake_hash);
    let auth = MeshFrame::Authenticate {
        nsm_doc,
        identity_sig,
    };

    // 2. Exchange Authenticate frames in a strict order keyed on the Noise
    //    role: the initiator sends first then reads, the responder reads first
    //    then sends. This serialisation matters because the underlying
    //    `perform_handshake_as_*` helpers read raw (not length-prefixed) Noise
    //    messages: if both sides pipelined their encrypted Authenticate
    //    immediately after the handshake, a single `read()` on the far end
    //    could coalesce the trailing handshake message with the start of the
    //    Authenticate frame and corrupt the transport. Strict ping-pong
    //    guarantees the responder's first encrypted write happens only after
    //    the initiator has finished reading the last handshake message.
    let (peer_doc, peer_sig) = match role {
        Role::Initiator => {
            write_frame(stream, &mut transport, &auth).await?;
            read_peer_authenticate(stream, &mut transport).await?
        }
        Role::Responder => {
            let got = read_peer_authenticate(stream, &mut transport).await?;
            write_frame(stream, &mut transport, &auth).await?;
            got
        }
    };

    // 3. Verify the peer's attestation document (nonce binds it to this
    //    session, yields PCRs + mesh pubkey).
    let extracted = attestation::verify_and_extract(&peer_doc, &handshake_hash, debug_mode)
        .map_err(|e| HandshakeError::PeerAttestation(e.to_string()))?;
    let pcr_digest = PcrKey(extracted.pcrs.digest());

    // 4. Self-PCR allowlist: the peer must be running our image.
    if !allowlist.admits(&pcr_digest) {
        return Err(HandshakeError::PcrNotAllowed);
    }

    // 5. Channel binding: the peer's identity-key signature over the handshake
    //    hash must verify against the pubkey its attestation announced. This
    //    is what stops a relay from splicing a captured attestation onto a
    //    channel it terminates: it does not hold the private mesh key.
    enclavia_protocol::mesh::verify_mesh_identity(
        &extracted.control_pubkey,
        &peer_sig,
        &handshake_hash,
    )
    .map_err(|e| HandshakeError::IdentitySignature(e.to_string()))?;

    Ok((
        transport,
        PeerIdentity {
            pcr_digest,
            mesh_pubkey: extracted.control_pubkey,
        },
    ))
}

/// Read the peer's first post-handshake frame, requiring it to be a
/// [`MeshFrame::Authenticate`], and return `(nsm_doc, identity_sig)`.
async fn read_peer_authenticate<S>(
    stream: &mut S,
    transport: &mut NoiseTransport,
) -> Result<(Vec<u8>, Vec<u8>), HandshakeError>
where
    S: AsyncRead + Unpin,
{
    match read_frame(stream, transport).await? {
        Some(MeshFrame::Authenticate {
            nsm_doc,
            identity_sig,
        }) => Ok((nsm_doc, identity_sig)),
        Some(_) => Err(HandshakeError::NotAuthenticate),
        None => Err(HandshakeError::PeerClosed),
    }
}

/// Write a CBOR-encoded [`MeshFrame`] over the Noise transport: encrypt, then
/// `[u32 BE length][ciphertext]`, with the body chunked at 32 KiB so a single
/// AF_VSOCK write never exceeds the per-write limit.
pub async fn write_frame<S>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    frame: &MeshFrame,
) -> Result<(), HandshakeError>
where
    S: AsyncWrite + Unpin,
{
    let mut plaintext = Vec::new();
    ciborium::into_writer(frame, &mut plaintext)
        .map_err(|e| HandshakeError::Cbor(format!("{e}")))?;
    let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
    let len: u32 = ct_len
        .try_into()
        .map_err(|_| HandshakeError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    for chunk in ciphertext[..ct_len].chunks(VSOCK_WRITE_CHUNK) {
        stream.write_all(chunk).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Read one CBOR-encoded [`MeshFrame`] from the Noise transport. Returns
/// `Ok(None)` on a clean EOF before any bytes of a new frame (peer closed).
///
/// NOT cancel-safe: it reads the 4-byte length prefix and then the body to
/// completion, so dropping the returned future after the prefix has been read
/// loses the partially-read body and desyncs the stream. Callers that need to
/// `select!` over a read must use [`read_ciphertext_frame`] +
/// [`decrypt_frame`] on a dedicated reader task instead (see
/// [`super::rpc::spawn_client`]).
pub async fn read_frame<S>(
    stream: &mut S,
    transport: &mut NoiseTransport,
) -> Result<Option<MeshFrame>, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    match read_ciphertext_frame(stream).await? {
        Some(ciphertext) => Ok(Some(decrypt_frame(transport, &ciphertext)?)),
        None => Ok(None),
    }
}

/// Read one raw length-prefixed CIPHERTEXT frame off `stream` without
/// touching any Noise transport: `[u32 BE length][ciphertext]`. Returns
/// `Ok(None)` on a clean EOF before any bytes of a new frame (peer closed).
///
/// This is the read primitive a dedicated reader task uses so the
/// transport-owning driver can `select!` over decrypted frames delivered on a
/// channel (cancel-safe) rather than over [`read_frame`] (not cancel-safe).
/// The reader owns the read half exclusively and never decrypts; decryption
/// (which needs `&mut NoiseTransport`) happens on the driver via
/// [`decrypt_frame`], so the single stateful transport object is touched by
/// exactly one task.
pub async fn read_ciphertext_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>, HandshakeError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(HandshakeError::Io(e)),
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_SIZE {
        return Err(HandshakeError::FrameTooLarge(len));
    }
    let mut ciphertext = vec![0u8; len as usize];
    reader.read_exact(&mut ciphertext).await?;
    Ok(Some(ciphertext))
}

/// Decrypt one raw ciphertext frame (as produced by
/// [`read_ciphertext_frame`]) through the Noise transport and CBOR-decode it
/// into a [`MeshFrame`]. Advances the transport's read nonce, so frames MUST
/// be fed in the order they arrived on the wire.
pub fn decrypt_frame(
    transport: &mut NoiseTransport,
    ciphertext: &[u8],
) -> Result<MeshFrame, HandshakeError> {
    let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
    let pt_len = transport
        .read_message(ciphertext, &mut plaintext)
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
    ciborium::from_reader(&plaintext[..pt_len]).map_err(|e| HandshakeError::Cbor(format!("{e}")))
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::mesh::attestation::FakeAttestor;
    use tokio::io::duplex;

    /// Build the (attestor, identity, allowlist) triple for a node on `seed`.
    fn node(seed: u8) -> (FakeAttestor, MeshIdentity, PcrAllowlist) {
        let identity = MeshIdentity::generate();
        let attestor = FakeAttestor::new(seed, &identity);
        let allow = PcrAllowlist::self_only(FakeAttestor::pcr_digest(seed));
        (attestor, identity, allow)
    }

    /// Drive both ends of a duplex pair through the mutual handshake and
    /// assert they admit each other when they share an image (same seed).
    #[tokio::test]
    async fn same_image_peers_mutually_admit() {
        let (mut a, mut b) = duplex(64 * 1024);
        let (att_a, id_a, allow_a) = node(0x11);
        let (att_b, id_b, allow_b) = node(0x11);

        let ta = tokio::spawn(async move {
            mutual_authenticate(&mut a, Role::Initiator, &att_a, &id_a, &allow_a, true).await
        });
        let tb = tokio::spawn(async move {
            mutual_authenticate(&mut b, Role::Responder, &att_b, &id_b, &allow_b, true).await
        });
        let (ra, rb) = (ta.await.unwrap(), tb.await.unwrap());
        let (_, peer_seen_by_a) = ra.expect("initiator admits");
        let (_, peer_seen_by_b) = rb.expect("responder admits");
        // Same image => same digest on both ends.
        assert_eq!(peer_seen_by_a.pcr_digest, peer_seen_by_b.pcr_digest);
    }

    /// A peer running a different image (different seed => different PCR
    /// digest) is rejected by the allowlist on both ends.
    #[tokio::test]
    async fn different_image_peer_is_rejected() {
        let (mut a, mut b) = duplex(64 * 1024);
        let (att_a, id_a, allow_a) = node(0x11);
        let (att_b, id_b, allow_b) = node(0x22); // different image

        let ta = tokio::spawn(async move {
            mutual_authenticate(&mut a, Role::Initiator, &att_a, &id_a, &allow_a, true).await
        });
        let tb = tokio::spawn(async move {
            mutual_authenticate(&mut b, Role::Responder, &att_b, &id_b, &allow_b, true).await
        });
        let (ra, rb) = (ta.await.unwrap(), tb.await.unwrap());
        assert!(matches!(ra, Err(HandshakeError::PcrNotAllowed)));
        assert!(matches!(rb, Err(HandshakeError::PcrNotAllowed)));
    }

    /// A peer whose attestation announces a mesh pubkey it does NOT hold the
    /// private half of cannot produce a valid identity signature, so the
    /// handshake is rejected even though PCRs match. Models a relay that
    /// captured a victim's attestation document and tried to terminate the
    /// channel itself.
    #[tokio::test]
    async fn stolen_attestation_without_identity_key_is_rejected() {
        // The acceptor (b) presents a victim's attestation document (the
        // victim's real mesh pubkey) but signs with an unrelated key.
        let (mut a, mut b) = duplex(64 * 1024);
        let (att_a, id_a, allow_a) = node(0x33);
        let victim_identity = MeshIdentity::generate();
        let attacker_identity = MeshIdentity::generate();
        // b's attestor advertises the victim's pubkey...
        let att_b = FakeAttestor::new(0x33, &victim_identity);
        // ...but b signs the handshake hash with the attacker's key.
        let allow_b = PcrAllowlist::self_only(FakeAttestor::pcr_digest(0x33));

        let ta = tokio::spawn(async move {
            mutual_authenticate(&mut a, Role::Initiator, &att_a, &id_a, &allow_a, true).await
        });
        let tb = tokio::spawn(async move {
            mutual_authenticate(
                &mut b,
                Role::Responder,
                &att_b,
                &attacker_identity,
                &allow_b,
                true,
            )
            .await
        });
        let (ra, _rb) = (ta.await.unwrap(), tb.await.unwrap());
        // The initiator verifying b's frame must reject the signature.
        // `NoiseTransport` is not `Debug`, so match instead of formatting the
        // whole `Result`.
        match ra {
            Err(HandshakeError::IdentitySignature(_)) => {}
            Err(other) => panic!("expected IdentitySignature, got {other:?}"),
            Ok(_) => panic!("expected the stolen-attestation handshake to be rejected"),
        }
    }

    /// After a successful handshake the established transports carry frames
    /// both ways.
    #[tokio::test]
    async fn established_channel_carries_frames() {
        let (mut a, mut b) = duplex(64 * 1024);
        let (att_a, id_a, allow_a) = node(0x44);
        let (att_b, id_b, allow_b) = node(0x44);

        let ta = tokio::spawn(async move {
            let (mut t, _id) =
                mutual_authenticate(&mut a, Role::Initiator, &att_a, &id_a, &allow_a, true)
                    .await
                    .unwrap();
            write_frame(
                &mut a,
                &mut t,
                &MeshFrame::Rpc {
                    envelope: b"ping".to_vec(),
                },
            )
            .await
            .unwrap();
            match read_frame(&mut a, &mut t).await.unwrap() {
                Some(MeshFrame::Rpc { envelope }) => envelope,
                other => panic!("unexpected: {other:?}"),
            }
        });
        let tb = tokio::spawn(async move {
            let (mut t, _id) =
                mutual_authenticate(&mut b, Role::Responder, &att_b, &id_b, &allow_b, true)
                    .await
                    .unwrap();
            let got = match read_frame(&mut b, &mut t).await.unwrap() {
                Some(MeshFrame::Rpc { envelope }) => envelope,
                other => panic!("unexpected: {other:?}"),
            };
            assert_eq!(got, b"ping");
            write_frame(
                &mut b,
                &mut t,
                &MeshFrame::Rpc {
                    envelope: b"pong".to_vec(),
                },
            )
            .await
            .unwrap();
        });
        let echo = ta.await.unwrap();
        tb.await.unwrap();
        assert_eq!(echo, b"pong");
    }
}
