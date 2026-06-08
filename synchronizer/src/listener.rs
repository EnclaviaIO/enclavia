//! Connection handling for the synchronizer's vsock listener binary.
//!
//! Wire format on a connection:
//!
//! - `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake (responder side) before
//!   any framing — see `enclavia-protocol::perform_handshake_as_responder`.
//! - Then, repeatedly: 4-byte big-endian length prefix followed by that
//!   many bytes of Noise-encrypted ciphertext. The plaintext is a
//!   CBOR-encoded [`Frame`].
//! - First plaintext frame on the connection MUST be [`Frame::Authenticate`],
//!   which carries the raw bytes of a Nitro NSM attestation document.
//!   The listener calls
//!   [`enclavia_protocol::attestation::verify_and_extract`] with the
//!   Noise handshake hash as the expected nonce, derives
//!   `PcrKey = SHA-256(PCR0||PCR1||PCR2)` from the verified document,
//!   pulls the Ed25519 control pubkey out of the doc's `user_data`,
//!   and binds the session to that key for life.
//! - Subsequent frames are [`Frame::Rpc`] with a [`Request`] payload;
//!   the server replies with an encrypted CBOR [`Response`].
//!
//! The Noise handshake hash binds the attestation document to *this*
//! specific session — a document captured from a previous handshake
//! can't be replayed because it would carry the wrong hash in its
//! nonce field. No explicit server-side challenge frame is needed.
//!
//! `Transition` requests are dispatched straight to [`Node::handle_request`],
//! which performs the Ed25519 signature check against the pubkey
//! registered for `old_key` at first attestation — the listener no
//! longer pre-observes attestations or transition signatures on behalf
//! of the caller.

use enclavia_protocol::{attestation, perform_handshake_as_responder, NoiseTransport};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::node::Node;
use crate::wire::{Request, Response, RpcError};
use crate::PcrKey;

/// Maximum size (bytes) of an inbound ENCRYPTED frame on the wire.
///
/// `Noise_NN_25519_ChaChaPoly_BLAKE2s` has a 65535-byte hard cap per
/// message, so we use that as the outer bound. Anything larger is a
/// protocol error — a malicious peer can't OOM the node by claiming a
/// giant length. A typical Nitro attestation document is ~5 KiB, well
/// within budget.
pub const MAX_FRAME_SIZE: u32 = 65535;

/// One frame over the Noise-encrypted stream. Tagged so we can extend
/// with control frames (ping, etc.) without breaking the format.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame")]
pub enum Frame {
    /// First client→server frame on every connection. Carries the raw
    /// CBOR/COSE_Sign1 bytes of a Nitro NSM attestation document. The
    /// document's `nonce` field MUST equal `base64(handshake_hash)`
    /// from the just-completed Noise handshake; the listener verifies
    /// the doc, extracts PCR0/1/2, and binds the session to
    /// `PcrKey = SHA-256(PCR0||PCR1||PCR2)`.
    Authenticate {
        /// Raw NSM attestation document bytes.
        nsm_doc: Vec<u8>,
    },

    /// Subsequent frame: an RPC [`Request`] to dispatch through
    /// [`Node::handle_request`].
    Rpc {
        /// RPC payload to dispatch against the session's bound key.
        request: Request,
    },
}

/// Errors a single connection can hit. Propagated up to the top-level
/// `accept` loop; the loop logs and moves on.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// Underlying transport I/O failure (read or write on the stream).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Inbound frame's claimed length exceeds [`MAX_FRAME_SIZE`].
    #[error("frame too large: {0} bytes (max {max})", max = MAX_FRAME_SIZE)]
    FrameTooLarge(u32),
    /// CBOR decode of an inbound frame failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// CBOR encode of an outbound response failed.
    #[error("cbor encode: {0}")]
    CborEncode(String),
    /// Attestation document failed validation, or did not bind to the
    /// Noise handshake hash via its `nonce` field.
    #[error("attestation: {0}")]
    Attestation(String),
    /// Caller violated the framing contract (e.g. RPC before Authenticate,
    /// or re-authentication on an already-bound session).
    #[error("protocol: {0}")]
    Protocol(&'static str),
    /// Noise handshake failed before any frames were exchanged.
    #[error("noise handshake: {0}")]
    Handshake(String),
    /// Noise transport-mode encrypt or decrypt failed mid-session.
    #[error("noise crypto: {0}")]
    Crypto(String),
}

/// Drive one accepted connection to completion. Performs the Noise
/// handshake first, then reads encrypted frames until EOF: the first
/// frame must be `Authenticate` (verified against the handshake hash),
/// each subsequent frame an RPC.
///
/// `debug_mode` selects the debug (skip-cert-chain) vs production
/// (full chain) variant of the attestation validator. The binary
/// derives it from the crate's `debug`/`enclave` Cargo feature.
pub async fn handle_connection<S>(
    node: &Node,
    mut stream: S,
    debug_mode: bool,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // 0. Noise handshake. `handshake_hash` is the channel-binding token
    //    we feed to the attestation verifier as the expected nonce, so
    //    the attestation document is bound to *this* Noise session.
    let (mut transport, handshake_hash) = perform_handshake_as_responder(&mut stream)
        .await
        .map_err(|e| ConnError::Handshake(format!("{e}")))?;

    // 1. First frame must authenticate: a Nitro NSM document whose
    //    nonce binds it to the handshake hash. Derive the session key
    //    from the verified PCRs, pull the Ed25519 control pubkey out
    //    of `user_data`, and announce the (key, pubkey) pair to the
    //    Node so Register and (later, for *another* enclave's session)
    //    Transition-target checks pass.
    let session_key = match read_frame(&mut stream, &mut transport).await? {
        Some(Frame::Authenticate { nsm_doc }) => {
            let identity =
                attestation::verify_and_extract(&nsm_doc, &handshake_hash, debug_mode)
                    .map_err(|e| ConnError::Attestation(e.to_string()))?;
            let key = PcrKey(identity.pcrs.digest());
            // The protocol layer now extracts a 65-byte uncompressed
            // SEC1 ECDSA P-256 pubkey from `user_data` (#47), but the
            // synchronizer mesh's own control-key concept is a separate
            // (Ed25519, 32-byte) thing that has not been migrated yet.
            // Until that migration lands, hand `observe_attestation` a
            // 32-byte slice derived from the SEC1 bytes — specifically
            // the last 32 bytes (the Y coordinate) — so the synchronizer
            // continues to compile and the mesh-level identity stays
            // stable per attested enclave. This identity will not verify
            // any real signature in this state; production mesh use is
            // gated on a follow-up that aligns the algorithms.
            let mut mesh_pubkey = [0u8; 32];
            mesh_pubkey.copy_from_slice(&identity.control_pubkey[33..65]);
            node.observe_attestation(key, mesh_pubkey).await;
            key
        }
        Some(_) => return Err(ConnError::Protocol("first frame must be Authenticate")),
        None => return Ok(()),
    };

    // 2. Subsequent frames: RPC dispatch. Transition signature
    //    verification lives in `Node::handle_request` — the listener
    //    deliberately no longer pre-observes attestation or
    //    transition-sig events on behalf of the caller (that was the
    //    #111 pre-fix hole: any session could forge a Transition by
    //    relying on the listener's unconditional `observe_*` calls).
    while let Some(frame) = read_frame(&mut stream, &mut transport).await? {
        let request = match frame {
            Frame::Rpc { request } => request,
            Frame::Authenticate { .. } => {
                // Treat re-auth as a protocol error — the session is
                // bound to one key for life.
                let resp = Response::Err {
                    error: RpcError::Unauthorized,
                };
                write_response(&mut stream, &mut transport, &resp).await?;
                return Err(ConnError::Protocol("re-authentication is not supported"));
            }
        };

        let response = node.handle_request(session_key, request).await;
        write_response(&mut stream, &mut transport, &response).await?;
    }

    Ok(())
}

async fn read_frame<S>(
    stream: &mut S,
    transport: &mut NoiseTransport,
) -> Result<Option<Frame>, ConnError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ConnError::Io(e)),
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_SIZE {
        return Err(ConnError::FrameTooLarge(len));
    }
    let mut ciphertext = vec![0u8; len as usize];
    stream.read_exact(&mut ciphertext).await?;

    let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
    let pt_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(|e| ConnError::Crypto(format!("{e}")))?;

    let frame: Frame = ciborium::from_reader(&plaintext[..pt_len])
        .map_err(|e| ConnError::Cbor(format!("{e}")))?;
    Ok(Some(frame))
}

async fn write_response<S>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    resp: &Response,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let mut plaintext = Vec::new();
    ciborium::into_writer(resp, &mut plaintext)
        .map_err(|e| ConnError::CborEncode(format!("{e}")))?;
    let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(|e| ConnError::Crypto(format!("{e}")))?;
    let len: u32 = ct_len
        .try_into()
        .map_err(|_| ConnError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&ciphertext[..ct_len]).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commitment, Version};
    use ed25519_dalek::{Signer, SigningKey};
    use enclavia_protocol::attestation::test_utils::FakeAttestation;
    use enclavia_protocol::perform_handshake_as_initiator;
    use std::sync::Arc;
    use tokio::io::duplex;

    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    /// Deterministic Ed25519 keypair derived from `seed`. Tests sign
    /// transition payloads with the returned `SigningKey` and feed the
    /// matching pubkey bytes into the NSM doc's `user_data`.
    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build a [`Frame::Authenticate`] from a [`FakeAttestation`] whose
    /// nonce is set to the supplied handshake hash and whose `user_data`
    /// carries the seed-derived stub pubkey from
    /// [`FakeAttestation::with_seed`]. Use this for tests that don't
    /// care about Transition signing.
    fn auth_frame(seed: u8, handshake_hash: &[u8]) -> (Frame, PcrKey) {
        let fake = FakeAttestation::with_seed(seed, handshake_hash.to_vec());
        let key = PcrKey(
            attestation::Pcrs {
                pcr0: fake.pcr0.clone(),
                pcr1: fake.pcr1.clone(),
                pcr2: fake.pcr2.clone(),
            }
            .digest(),
        );
        (
            Frame::Authenticate {
                nsm_doc: fake.encode(),
            },
            key,
        )
    }

    /// Like [`auth_frame`] but embeds a specific Ed25519 verifying-key
    /// in `user_data`. Use this for Transition tests where the
    /// signature has to verify against the registered pubkey.
    ///
    /// The protocol layer (post-#47) extracts a 65-byte uncompressed
    /// SEC1 ECDSA P-256 pubkey from `user_data`, and the listener then
    /// slices bytes `[33..65]` (the Y coordinate position) before
    /// handing them to `observe_attestation`. Mirror that here: pack
    /// the 32-byte Ed25519 verifying key into the Y-coordinate slot of
    /// a synthetic SEC1 blob, so the listener slicing recovers the
    /// exact 32 bytes the test holds the signing key for. The blob
    /// will not decode as a valid P-256 point, but synchronizer's
    /// listener doesn't decode it — it just slices and stores.
    fn auth_frame_with_pubkey(
        seed: u8,
        handshake_hash: &[u8],
        control_pubkey: [u8; 32],
    ) -> (Frame, PcrKey) {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[33..65].copy_from_slice(&control_pubkey);
        let fake = FakeAttestation::with_seed_and_pubkey(
            seed,
            handshake_hash.to_vec(),
            sec1,
        );
        let key = PcrKey(
            attestation::Pcrs {
                pcr0: fake.pcr0.clone(),
                pcr1: fake.pcr1.clone(),
                pcr2: fake.pcr2.clone(),
            }
            .digest(),
        );
        (
            Frame::Authenticate {
                nsm_doc: fake.encode(),
            },
            key,
        )
    }

    /// Sign the canonical Transition payload (`b"transition:" ||
    /// old_key || new_key`) the same way `enclavia-crypto` does on the
    /// retiring enclave.
    fn sign_transition(sk: &SigningKey, old: PcrKey, new: PcrKey) -> Vec<u8> {
        let mut payload = Vec::with_capacity(11 + 32 + 32);
        payload.extend_from_slice(b"transition:");
        payload.extend_from_slice(&old.0);
        payload.extend_from_slice(&new.0);
        sk.sign(&payload).to_bytes().to_vec()
    }

    async fn write_frame<S>(stream: &mut S, transport: &mut NoiseTransport, frame: &Frame)
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let mut plaintext = Vec::new();
        ciborium::into_writer(frame, &mut plaintext).unwrap();
        let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
        let ct_len = transport
            .write_message(&plaintext, &mut ciphertext)
            .unwrap();
        let len = ct_len as u32;
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&ciphertext[..ct_len]).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_response<S>(stream: &mut S, transport: &mut NoiseTransport) -> Response
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut ciphertext = vec![0u8; len];
        stream.read_exact(&mut ciphertext).await.unwrap();
        let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
        let pt_len = transport
            .read_message(&ciphertext, &mut plaintext)
            .unwrap();
        ciborium::from_reader(&plaintext[..pt_len]).unwrap()
    }

    /// Spawn `handle_connection` against one half of a duplex pair and
    /// drive the initiator handshake on the other half. Returns the
    /// client stream + client-side `NoiseTransport` + handshake hash +
    /// server `JoinHandle`. Tests use the handshake hash to build a
    /// [`FakeAttestation`] whose nonce matches what the server will
    /// expect.
    async fn connect() -> (
        tokio::io::DuplexStream,
        NoiseTransport,
        Vec<u8>,
        tokio::task::JoinHandle<Result<(), ConnError>>,
    ) {
        connect_with_node(Arc::new(Node::new())).await
    }

    /// Like [`connect`] but uses a caller-supplied [`Node`], so a test
    /// can seed it with extra `observe_attestation` calls (mimicking
    /// another session attesting in parallel) before opening a
    /// connection.
    async fn connect_with_node(
        node: Arc<Node>,
    ) -> (
        tokio::io::DuplexStream,
        NoiseTransport,
        Vec<u8>,
        tokio::task::JoinHandle<Result<(), ConnError>>,
    ) {
        let (mut client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            handle_connection(node.as_ref(), server, true).await
        });
        let (transport, hash) = perform_handshake_as_initiator(&mut client).await.unwrap();
        (client, transport, hash, server_task)
    }

    #[tokio::test]
    async fn happy_path_authenticate_pin_get() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (auth, key) = auth_frame(0x11, &hash);
        write_frame(&mut client, &mut ct, &auth).await;
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Pin {
                    key,
                    commitment: c(0xaa),
                },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(resp, Response::PinOk { version: Version(0) });

        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Get { key },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::GetOk {
                commitment: c(0xaa),
                version: Version(0),
            }
        );

        drop(client);
        let result = server_task.await.unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn rpc_before_authenticate_is_rejected() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (_, key) = auth_frame(0x22, &hash);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Get { key },
            },
        )
        .await;
        drop(client);
        let result = server_task.await.unwrap();
        assert!(matches!(result, Err(ConnError::Protocol(_))));
    }

    #[tokio::test]
    async fn re_authentication_is_rejected() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (auth1, _) = auth_frame(0x33, &hash);
        let (auth2, _) = auth_frame(0x44, &hash);
        write_frame(&mut client, &mut ct, &auth1).await;
        write_frame(&mut client, &mut ct, &auth2).await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::Err {
                error: RpcError::Unauthorized
            }
        );
        drop(client);
        let result = server_task.await.unwrap();
        assert!(matches!(result, Err(ConnError::Protocol(_))));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        // Complete the handshake first, then lie about the length on
        // the next encrypted frame. The listener should reject the
        // length-prefix check before ever calling into the Noise
        // transport.
        let (mut client, _ct, _hash, server_task) = connect().await;

        let bogus_len = (MAX_FRAME_SIZE + 1).to_be_bytes();
        client.write_all(&bogus_len).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let result = server_task.await.unwrap();
        assert!(matches!(result, Err(ConnError::FrameTooLarge(_))));
    }

    /// Document bound to a *different* handshake hash than the one the
    /// current session produced is rejected — guards against replaying
    /// an attestation document captured from another session.
    #[tokio::test]
    async fn nsm_doc_with_wrong_handshake_hash_is_rejected() {
        let (mut client, mut ct, _real_hash, server_task) = connect().await;

        // Build the doc against a forged hash (what an attacker
        // replaying a stale doc would have).
        let forged = vec![0xab; 32];
        let (auth, _) = auth_frame(0x55, &forged);
        write_frame(&mut client, &mut ct, &auth).await;
        drop(client);

        let result = server_task.await.unwrap();
        assert!(
            matches!(result, Err(ConnError::Attestation(_))),
            "expected Attestation error, got {result:?}"
        );
    }

    /// A bag of random bytes that is not a valid NSM document is
    /// rejected — checks the parse path fails closed, rather than
    /// falling through to RPC dispatch under some zero-derived key.
    #[tokio::test]
    async fn nsm_doc_with_garbage_bytes_is_rejected() {
        let (mut client, mut ct, _hash, server_task) = connect().await;

        write_frame(
            &mut client,
            &mut ct,
            &Frame::Authenticate {
                nsm_doc: vec![0xde, 0xad, 0xbe, 0xef],
            },
        )
        .await;
        drop(client);

        let result = server_task.await.unwrap();
        assert!(
            matches!(result, Err(ConnError::Attestation(_))),
            "expected Attestation error, got {result:?}"
        );
    }

    /// After authentication the session is bound to the PCR-derived
    /// key, so RPC payloads must reference that same key. Belt-and-
    /// braces over `Node::handle_request`'s session check.
    #[tokio::test]
    async fn rpc_targeting_a_different_key_is_unauthorized() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (auth, _session_key) = auth_frame(0x66, &hash);
        write_frame(&mut client, &mut ct, &auth).await;

        let other_key = PcrKey([0u8; 32]);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Get { key: other_key },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::Err {
                error: RpcError::Unauthorized
            }
        );

        drop(client);
        let _ = server_task.await.unwrap();
    }

    /// End-to-end success: `old_key` attests through a Noise+NSM
    /// session, registers, then issues a `Transition` signed with the
    /// Ed25519 key embedded in its attestation doc's `user_data`.
    /// `new_key` had to attest in a parallel "session" first — we
    /// simulate that by seeding the shared [`Node`] up front.
    #[tokio::test]
    async fn transition_via_listener_with_valid_signature_succeeds() {
        // new_key would normally attest via its own connection; we
        // shortcut by calling Node::observe_attestation directly, which
        // matches what the listener would have done for that session.
        let node = Arc::new(Node::new());
        let (_, new_pubkey) = keypair(0xee);
        let new_key = PcrKey([0xee; 32]);
        node.observe_attestation(new_key, new_pubkey).await;

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        // old_key's attestation carries a real Ed25519 pubkey in
        // user_data so the listener registers it.
        let (sk_old, pk_old) = keypair(0x77);
        let (auth, old_key) = auth_frame_with_pubkey(0x77, &hash, pk_old);
        write_frame(&mut client, &mut ct, &auth).await;
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Pin {
                    key: old_key,
                    commitment: c(0xaa),
                },
            },
        )
        .await;
        let _ = read_response(&mut client, &mut ct).await;

        // Sign the canonical payload with old_key's private key.
        let sig = sign_transition(&sk_old, old_key, new_key);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition {
                    old_key,
                    new_key,
                    signature: sig,
                },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(resp, Response::TransitionOk { version: Version(0) });

        drop(client);
        let _ = server_task.await.unwrap();
    }

    /// An invalid Ed25519 signature (right length, but signed by the
    /// wrong key) is rejected — the listener-Node path enforces what
    /// pre-#111 it ignored.
    #[tokio::test]
    async fn transition_via_listener_with_invalid_signature_is_rejected() {
        let node = Arc::new(Node::new());
        let (_, new_pubkey) = keypair(0xee);
        let new_key = PcrKey([0xee; 32]);
        node.observe_attestation(new_key, new_pubkey).await;

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        // old_key registers with pk_real, but the test signs with a
        // *different* key the attacker controls.
        let (_sk_real, pk_real) = keypair(0x77);
        let (sk_attacker, _) = keypair(0xab);
        let (auth, old_key) = auth_frame_with_pubkey(0x77, &hash, pk_real);
        write_frame(&mut client, &mut ct, &auth).await;
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Pin {
                    key: old_key,
                    commitment: c(0xaa),
                },
            },
        )
        .await;
        let _ = read_response(&mut client, &mut ct).await;

        let sig = sign_transition(&sk_attacker, old_key, new_key);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition {
                    old_key,
                    new_key,
                    signature: sig,
                },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::Err {
                error: RpcError::TransitionRejected,
            }
        );

        drop(client);
        let _ = server_task.await.unwrap();
    }

    /// A Transition whose target hasn't attested yet is rejected with
    /// `TransitionRejected` — the listener used to paper over this by
    /// pre-observing the new_key attestation unconditionally, which
    /// was half of the #111 hole.
    #[tokio::test]
    async fn transition_via_listener_with_unattested_new_key_is_rejected() {
        let node = Arc::new(Node::new());
        // Deliberately do NOT pre-attest new_key.
        let new_key = PcrKey([0xee; 32]);

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        let (sk_old, pk_old) = keypair(0x77);
        let (auth, old_key) = auth_frame_with_pubkey(0x77, &hash, pk_old);
        write_frame(&mut client, &mut ct, &auth).await;
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Pin {
                    key: old_key,
                    commitment: c(0xaa),
                },
            },
        )
        .await;
        let _ = read_response(&mut client, &mut ct).await;

        let sig = sign_transition(&sk_old, old_key, new_key);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition {
                    old_key,
                    new_key,
                    signature: sig,
                },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::Err {
                error: RpcError::TransitionRejected,
            }
        );

        drop(client);
        let _ = server_task.await.unwrap();
    }
}
