//! Connection handling for the synchronizer's vsock listener binary.
//!
//! Wire format on a connection:
//!
//! - `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake (responder side) before
//!   any framing, see `enclavia-protocol::perform_handshake_as_responder`.
//! - Then, repeatedly: 4-byte big-endian length prefix followed by that
//!   many bytes of Noise-encrypted ciphertext. The plaintext is a
//!   CBOR-encoded [`Frame`].
//! - First plaintext frame on the connection MUST be [`Frame::Authenticate`],
//!   which carries the raw bytes of a Nitro NSM attestation document.
//!   The listener calls
//!   [`enclavia_protocol::attestation::verify_and_extract`] with the
//!   Noise handshake hash as the expected nonce, derives
//!   `PcrKey = SHA-256(PCR0||PCR1||PCR2)` from the verified document,
//!   pulls the 65-byte SEC1 P-256 control pubkey out of the doc's
//!   `user_data` (`AttestedIdentity::control_pubkey`), and binds the
//!   session to that key for life.
//! - The SERVER then authenticates back (#208): it requests a fresh NSM
//!   document from its own `/dev/nsm` with `nonce = handshake_hash`
//!   (per session, so the binding is per session, like the mesh) and
//!   sends it as the first server-to-client frame, also a
//!   [`Frame::Authenticate`]. The client verifies the document and
//!   checks its PCRs against the synchronizer measurements it trusts
//!   (see [`crate::wire::ServerPcrPolicy`]). This step is MANDATORY:
//!   `Noise_NN` is unauthenticated DH and the whole customer path is
//!   host-relayed, so without it a malicious host could terminate the
//!   customer's session itself and answer Get/Pin as a fake oracle,
//!   serving an arbitrarily stale commitment, the exact rollback the
//!   synchronizer exists to prevent.
//! - Subsequent frames are [`Frame::Rpc`] with a [`Request`] payload;
//!   the server replies with an encrypted CBOR [`Response`].
//!
//! The Noise handshake hash binds each attestation document to *this*
//! specific session, a document captured from a previous handshake
//! can't be replayed because it would carry the wrong hash in its
//! nonce field. No explicit challenge frames are needed in either
//! direction.
//!
//! ## Write ordering (frame-coalescing hazard)
//!
//! The mesh handshake (`crate::mesh::handshake`) documents why the
//! responder's first encrypted write must never be pipelined with the
//! Noise handshake messages: `perform_handshake_as_*` reads raw (not
//! length-prefixed) Noise messages, so an eager write could coalesce
//! with the trailing handshake message on the initiator and corrupt the
//! transport. The customer protocol is safe by construction: the
//! server's first encrypted write (its `Authenticate`) happens only
//! AFTER it has read and verified the client's `Authenticate` frame,
//! which the client can only have sent after finishing the handshake
//! reads. The client mirrors the strict ping-pong: write `Authenticate`,
//! then read the server's, then RPC.
//!
//! ## Why no identity signature (unlike the mesh)
//!
//! The mesh's mutual attestation adds an identity-key signature over the
//! handshake hash because mesh peers all run the SAME image: a malicious
//! relay holding a node's channel-bound document (nodes send theirs
//! first when dialing) could reflect it on the same channel and pass the
//! peer's self-PCR allowlist. On the customer path the only document an
//! attacker can hold for THIS session's hash is the customer's own
//! `Authenticate`, and the client's [`crate::wire::ServerPcrPolicy`]
//! rejects it (customer PCRs are not synchronizer PCRs). Every other
//! document fails the nonce binding, so the PCR policy alone closes the
//! reflection hole and no extra signature exchange is needed.
//!
//! Requests are dispatched through a [`SessionDispatch`]: the single-node
//! [`Node`](crate::Node) (no Raft) verifies + applies them against one local
//! state machine, while the replicated dispatcher (the `raft` feature) routes
//! each request to the cluster leader (forwarding over the mesh when this node
//! is a follower) and applies the verified conclusions through Raft. Either way
//! a `Transition` request's #47 upgrade chain link is decoded to derive
//! `old_key`/`new_key`, the submitting session is required to be bound to
//! `new_key` (the NEW enclave submits the transition), and the link's signature
//! is verified against the control pubkey frozen for the derived `old_key` at
//! its registration. The listener no longer pre-observes attestations or
//! transition authorizations on behalf of the caller.

use enclavia_protocol::{NoiseTransport, attestation, perform_handshake_as_responder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire::{Request, Response, RpcError};
use crate::{CONTROL_PUBKEY_LEN, PcrKey};

// Frame + MAX_FRAME_SIZE moved to `crate::wire` so the customer client
// (`client` feature) can share them without pulling in the responder
// stack; re-exported here for existing callers.
pub use crate::wire::{Frame, MAX_FRAME_SIZE};

/// Cap a single transport write at 32 KiB: AF_VSOCK (and the
/// vhost-device-vsock UDS bridge in QEMU debug mode) is unreliable on
/// single writes above that (see CLAUDE.md). Every outbound frame body
/// is chunked at this boundary; an NSM document (~5 KiB) plus Noise
/// overhead normally fits in one chunk, the cap keeps the listener safe
/// even at the 65535-byte Noise maximum.
const VSOCK_WRITE_CHUNK: usize = 32 * 1024;

/// Produces this node's own NSM attestation document for one customer
/// session (#208): `nonce = handshake_hash`, binding the document to
/// that session.
///
/// One document is requested PER SESSION (not cached per boot): the
/// nonce must bind the live session's handshake hash, exactly like the
/// mesh's per-peer documents, so there is nothing reusable to cache.
/// Object-safe so the binary can hold a `dyn SessionAttestor` across
/// the production / dev / test implementations.
#[async_trait::async_trait]
pub trait SessionAttestor: Send + Sync {
    /// Produce an NSM attestation document whose `nonce` equals
    /// `handshake_hash`. `user_data` is unconstrained (the customer
    /// client does not read it); the production implementation sends
    /// none.
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, String>;
}

/// Production [`SessionAttestor`]: drives the in-enclave `/dev/nsm`
/// device, one blocking request per session, off the async runtime via
/// `spawn_blocking`. Used by the `enclave` / `qemu` binaries (QEMU's
/// nitro-enclave machine emulates the device identically; its documents
/// are self-signed, which is exactly what the client's `debug_mode`
/// verification accepts).
pub struct NsmSessionAttestor;

#[async_trait::async_trait]
impl SessionAttestor for NsmSessionAttestor {
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = handshake_hash.to_vec();
        tokio::task::spawn_blocking(move || {
            crate::mesh::attestation::request_own_attestation(Some(nonce), None)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("nsm attestation task panicked: {e}"))?
    }
}

/// Synthetic [`SessionAttestor`] for the dev UDS listener (`debug`
/// feature) and in-process tests: there is no `/dev/nsm` on a dev
/// machine, so the mandatory server-authentication step serves a
/// `FakeAttestation` document with seed-derived PCRs instead. Only a
/// client verifying in `debug_mode` with a matching expected-PCR
/// policy accepts it; never compiled into the `enclave` / `qemu`
/// binaries.
#[cfg(any(test, feature = "test-utils", feature = "debug"))]
pub struct FakeSessionAttestor {
    /// Seed the document's PCR triple is derived from
    /// (`pcr0 = [seed; 48]`, `pcr1 = [seed+1; 48]`, `pcr2 = [seed+2; 48]`,
    /// matching `FakeAttestation::with_seed`).
    pub seed: u8,
}

#[cfg(any(test, feature = "test-utils", feature = "debug"))]
#[async_trait::async_trait]
impl SessionAttestor for FakeSessionAttestor {
    async fn attest(&self, handshake_hash: &[u8]) -> Result<Vec<u8>, String> {
        use enclavia_protocol::attestation::test_utils::FakeAttestation;
        Ok(FakeAttestation::with_seed(self.seed, handshake_hash.to_vec()).encode())
    }
}

/// Dispatch one attested-session request to whatever backs this node: the
/// single-node [`Node`](crate::Node), or (under the `raft` feature) the
/// replicated cluster.
///
/// The listener does ALL session-level work, the Noise handshake, the NSM
/// attestation verification, deriving the [`PcrKey`] and pulling the 65-byte
/// SEC1 P-256 control pubkey, then hands the verified `(session_key,
/// control_pubkey, request)` triple here. The implementor owns whatever happens
/// next (observe + apply locally, or route to the leader). The 65-byte
/// `control_pubkey` is the session's announced
/// `AttestedIdentity::control_pubkey`; the single-node path observes it before
/// applying, and the replicated path carries it into the `ReplicatedOp` so
/// followers can freeze / record it without re-attesting.
#[async_trait::async_trait]
pub trait SessionDispatch: Send + Sync {
    /// Handle one request from a session authenticated as `session_key` with
    /// `control_pubkey`. Returns the wire [`Response`] to send back.
    async fn dispatch(
        &self,
        session_key: PcrKey,
        control_pubkey: [u8; CONTROL_PUBKEY_LEN],
        request: Request,
    ) -> Response;
}

/// The single-node [`Node`](crate::Node) is a [`SessionDispatch`]: it observes
/// the session's attestation into its local state machine, then runs the request
/// through its own verifier + state machine. This keeps the no-Raft binary mode
/// (the currently-shipped one) on exactly its prior code path.
#[async_trait::async_trait]
impl SessionDispatch for crate::node::Node {
    async fn dispatch(
        &self,
        session_key: PcrKey,
        control_pubkey: [u8; CONTROL_PUBKEY_LEN],
        request: Request,
    ) -> Response {
        self.observe_attestation(session_key, control_pubkey).await;
        self.handle_request(session_key, request).await
    }
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
    /// Producing this node's OWN attestation document for the mandatory
    /// server-authentication step (#208) failed. The session cannot
    /// proceed unauthenticated, so the connection is torn down.
    #[error("local attestation: {0}")]
    LocalAttestation(String),
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
/// answered with this node's OWN session-bound `Authenticate` (#208),
/// each subsequent frame an RPC.
///
/// `debug_mode` selects the debug (skip-cert-chain) vs production
/// (full chain) variant of the attestation validator. The binary
/// derives it from the crate's `debug`/`enclave` Cargo feature.
///
/// `dispatch` backs the request handling: the single-node
/// [`Node`](crate::Node) or (under `raft`) the replicated cluster dispatcher.
/// `attestor` produces this node's own per-session attestation document
/// ([`NsmSessionAttestor`] in the enclave; [`FakeSessionAttestor`] in
/// the dev UDS listener and tests).
pub async fn handle_connection<S, D, A>(
    dispatch: &D,
    attestor: &A,
    mut stream: S,
    debug_mode: bool,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    D: SessionDispatch + ?Sized,
    A: SessionAttestor + ?Sized,
{
    // 0. Noise handshake. `handshake_hash` is the channel-binding token
    //    we feed to the attestation verifier as the expected nonce, so
    //    the attestation document is bound to *this* Noise session.
    let (mut transport, handshake_hash) = perform_handshake_as_responder(&mut stream)
        .await
        .map_err(|e| ConnError::Handshake(format!("{e}")))?;

    // 1. First frame must authenticate: a Nitro NSM document whose
    //    nonce binds it to the handshake hash. Derive the session key
    //    from the verified PCRs, pull the 65-byte SEC1 P-256 control
    //    pubkey out of `user_data`, and announce the (key, pubkey) pair
    //    to the Node so this session's Register passes and, when this
    //    session is a NEW enclave submitting a Transition, the
    //    `new_key == session_key` and NewKeyNotAttested checks pass.
    //
    //    The pubkey is `AttestedIdentity::control_pubkey` verbatim, the
    //    same 65-byte uncompressed SEC1 ECDSA P-256 key (#21/#47) the
    //    `Transition` chain-link verifier checks the upgrade payload's
    //    signature against (it checks it against the OLD key's frozen
    //    pubkey, registered when the old enclave first attested). No
    //    slicing / algorithm bridging: the synchronizer's transition
    //    credential IS the #47 upgrade link, so one P-256 key serves
    //    throughout.
    let (session_key, control_pubkey) = match read_frame(&mut stream, &mut transport).await? {
        Some(Frame::Authenticate { nsm_doc }) => {
            let identity = attestation::verify_and_extract(&nsm_doc, &handshake_hash, debug_mode)
                .map_err(|e| ConnError::Attestation(e.to_string()))?;
            let key = PcrKey(identity.pcrs.digest());
            (key, identity.control_pubkey)
        }
        Some(_) => return Err(ConnError::Protocol("first frame must be Authenticate")),
        None => return Ok(()),
    };

    // 1b. Server authentication (#208): answer with our OWN attestation
    //     document, freshly requested for THIS session (`nonce =
    //     handshake_hash`), as the first server-to-client frame. The
    //     client verifies it and checks our PCRs against the
    //     synchronizer measurements baked into its measured config;
    //     without this step `Noise_NN` would leave the oracle's end of
    //     the channel unauthenticated and a malicious host could answer
    //     Get/Pin itself. Ordering note: this is the server's first
    //     encrypted write and happens strictly after reading the
    //     client's first frame, so it can never coalesce with the Noise
    //     handshake messages (see the module docs).
    let own_doc = attestor
        .attest(&handshake_hash)
        .await
        .map_err(ConnError::LocalAttestation)?;
    write_cbor_frame(
        &mut stream,
        &mut transport,
        &Frame::Authenticate { nsm_doc: own_doc },
    )
    .await?;

    // 2. Subsequent frames: RPC dispatch. The dispatcher owns observing the
    //    attestation (single-node) / carrying the verified facts to the leader
    //    (replicated) and the `Transition` chain-link verification. The listener
    //    deliberately no longer pre-observes attestation or transition-sig events
    //    on behalf of the caller (that was the #111 pre-fix hole: any session
    //    could forge a Transition by relying on the listener's unconditional
    //    `observe_*` calls).
    while let Some(frame) = read_frame(&mut stream, &mut transport).await? {
        let request = match frame {
            Frame::Rpc { request } => request,
            Frame::Authenticate { .. } => {
                // Treat re-auth as a protocol error, the session is
                // bound to one key for life.
                let resp = Response::Err {
                    error: RpcError::Unauthorized,
                };
                write_response(&mut stream, &mut transport, &resp).await?;
                return Err(ConnError::Protocol("re-authentication is not supported"));
            }
        };

        let response = dispatch
            .dispatch(session_key, control_pubkey, request)
            .await;
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

    let frame: Frame =
        ciborium::from_reader(&plaintext[..pt_len]).map_err(|e| ConnError::Cbor(format!("{e}")))?;
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
    write_cbor_frame(stream, transport, resp).await
}

/// Encrypt one CBOR-serializable value through the Noise transport and
/// write it as `[u32 BE length][ciphertext]`, with the body chunked at
/// [`VSOCK_WRITE_CHUNK`] so a single vsock write never exceeds the
/// per-write limit. Shared by the RPC [`Response`] path and the server's
/// `Authenticate` frame (#208).
async fn write_cbor_frame<S, T>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    value: &T,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut plaintext = Vec::new();
    ciborium::into_writer(value, &mut plaintext)
        .map_err(|e| ConnError::CborEncode(format!("{e}")))?;
    let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(|e| ConnError::Crypto(format!("{e}")))?;
    let len: u32 = ct_len
        .try_into()
        .map_err(|_| ConnError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    for chunk in ciphertext[..ct_len].chunks(VSOCK_WRITE_CHUNK) {
        stream.write_all(chunk).await?;
    }
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::wire::{ChainLink, ChainLinkKind, UpgradePayload};
    use crate::{Commitment, Version};
    use enclavia_protocol::attestation::test_utils::{FakeAttestation, FakeChainAttestation};
    use enclavia_protocol::attestation::{CONTROL_PUBKEY_LEN, Pcrs};
    use enclavia_protocol::chain::PcrsHex;
    use enclavia_protocol::perform_handshake_as_initiator;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use std::sync::Arc;
    use tokio::io::duplex;

    fn c(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    /// Deterministic P-256 keypair; returns the signing key and the
    /// 65-byte uncompressed SEC1 verifying-key bytes that go in the NSM
    /// doc's `user_data`.
    fn keypair(seed: u8) -> (SigningKey, [u8; CONTROL_PUBKEY_LEN]) {
        // A reliably-valid, nonzero P-256 scalar: a small big-endian
        // integer (0x01, seed, 0, ...) is always below the curve order.
        let mut scalar = [0u8; 32];
        scalar[0] = 0x01;
        scalar[1] = seed;
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let pk_vec = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut pk = [0u8; CONTROL_PUBKEY_LEN];
        pk.copy_from_slice(&pk_vec);
        (sk, pk)
    }

    fn pcrs_hex_from_seed(seed: u8) -> PcrsHex {
        PcrsHex {
            pcr0: hex::encode(vec![seed; 48]),
            pcr1: hex::encode(vec![seed.wrapping_add(1); 48]),
            pcr2: hex::encode(vec![seed.wrapping_add(2); 48]),
        }
    }

    /// The PcrKey a seed's PcrsHex hashes to. Matches both `FakeAttestation::
    /// with_seed(seed)`'s PCRs and `verify_transition_link`'s derivation.
    fn key_from_seed(seed: u8) -> PcrKey {
        let raw = Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        };
        PcrKey(raw.digest())
    }

    /// Build a [`Frame::Authenticate`] from a [`FakeAttestation`] whose
    /// nonce is the supplied handshake hash and whose `user_data` carries a
    /// real 65-byte SEC1 P-256 pubkey, so a Transition link signed by the
    /// matching key verifies. The session key is `sha256` over the seed's
    /// PCR triple, equal to `key_from_seed(seed)`.
    fn auth_frame(
        seed: u8,
        handshake_hash: &[u8],
        pubkey: [u8; CONTROL_PUBKEY_LEN],
    ) -> (Frame, PcrKey) {
        let fake = FakeAttestation::with_seed_and_pubkey(seed, handshake_hash.to_vec(), pubkey);
        let key = key_from_seed(seed);
        (
            Frame::Authenticate {
                nsm_doc: fake.encode(),
            },
            key,
        )
    }

    /// Build a #47 upgrade chain link `from_seed -> to_seed`, signed by the
    /// OLD enclave's control key and attested for the OLD measurements
    /// (`from_seed`): the old enclave emits the link, so it attests its
    /// own PCRs.
    fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
        let payload = UpgradePayload {
            enclave_id: uuid::Uuid::new_v4(),
            from_pcrs: pcrs_hex_from_seed(from_seed),
            to_pcrs: pcrs_hex_from_seed(to_seed),
            image_digest: "sha256:to".into(),
            valid_from: chrono::Utc::now(),
            issued_at: chrono::Utc::now(),
            nonce: vec![0x5a; 32],
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
        let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
        let sig: Signature = signing.sign(&payload_bytes);
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Upgrade,
            payload: payload_bytes,
            attestation,
            signature: Some(sig.to_bytes().to_vec()),
        }
    }

    /// Register an OLD enclave's key into a shared node: attest it with the
    /// supplied control pubkey and Pin it so its `KeyState.control_pubkey`
    /// is frozen. Models the old enclave's earlier (now-stopped) session.
    async fn register_old(
        node: &Node,
        seed: u8,
        control_pubkey: [u8; CONTROL_PUBKEY_LEN],
    ) -> PcrKey {
        let key_old = key_from_seed(seed);
        node.observe_attestation(key_old, control_pubkey).await;
        node.handle_request(
            key_old,
            Request::Pin {
                key: key_old,
                commitment: c(0xaa),
            },
        )
        .await;
        key_old
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
        let pt_len = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        ciborium::from_reader(&plaintext[..pt_len]).unwrap()
    }

    /// The PCR seed [`connect`]'s server attests its own sessions with.
    const SERVER_SEED: u8 = 0xa5;

    /// Read the server's `Authenticate` frame (#208), verify it against
    /// this session's handshake hash and the [`SERVER_SEED`] PCR
    /// expectation, and return the raw document bytes.
    async fn read_and_verify_server_auth<S>(
        stream: &mut S,
        transport: &mut NoiseTransport,
        hash: &[u8],
    ) -> Vec<u8>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut ciphertext = vec![0u8; len];
        stream.read_exact(&mut ciphertext).await.unwrap();
        let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
        let pt_len = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        let frame: Frame = ciborium::from_reader(&plaintext[..pt_len]).unwrap();
        match frame {
            Frame::Authenticate { nsm_doc } => {
                let expected = Pcrs {
                    pcr0: vec![SERVER_SEED; 48],
                    pcr1: vec![SERVER_SEED.wrapping_add(1); 48],
                    pcr2: vec![SERVER_SEED.wrapping_add(2); 48],
                };
                let policy = crate::wire::ServerPcrPolicy::Expected(vec![expected]);
                crate::wire::verify_server_attestation(&nsm_doc, hash, &policy, true)
                    .expect("server attestation must verify and match the expected PCRs");
                nsm_doc
            }
            other => panic!("expected the server's Authenticate frame, got {other:?}"),
        }
    }

    /// Spawn `handle_connection` against one half of a duplex pair (debug
    /// mode) and drive the initiator handshake on the other half.
    async fn connect() -> (
        tokio::io::DuplexStream,
        NoiseTransport,
        Vec<u8>,
        tokio::task::JoinHandle<Result<(), ConnError>>,
    ) {
        connect_with_node(Arc::new(Node::with_debug_mode(true))).await
    }

    /// Like [`connect`] but uses a caller-supplied [`Node`], so a test can
    /// seed it with extra `observe_attestation` calls (mimicking another
    /// session attesting in parallel) before opening a connection.
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
            let attestor = FakeSessionAttestor { seed: SERVER_SEED };
            handle_connection(node.as_ref(), &attestor, server, true).await
        });
        let (transport, hash) = perform_handshake_as_initiator(&mut client).await.unwrap();
        (client, transport, hash, server_task)
    }

    #[tokio::test]
    async fn happy_path_authenticate_pin_get() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (_, pk) = keypair(0x11);
        let (auth, key) = auth_frame(0x11, &hash, pk);
        write_frame(&mut client, &mut ct, &auth).await;
        // Mutual auth (#208): the server answers a valid Authenticate
        // with its own session-bound document before any RPC response.
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;
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
        assert_eq!(
            resp,
            Response::PinOk {
                version: Version(0)
            }
        );

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
        let (mut client, mut ct, _hash, server_task) = connect().await;

        let key = key_from_seed(0x22);
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

        let (_, pk1) = keypair(0x33);
        let (_, pk2) = keypair(0x44);
        let (auth1, _) = auth_frame(0x33, &hash, pk1);
        let (auth2, _) = auth_frame(0x44, &hash, pk2);
        write_frame(&mut client, &mut ct, &auth1).await;
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;
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
        let (mut client, _ct, _hash, server_task) = connect().await;

        let bogus_len = (MAX_FRAME_SIZE + 1).to_be_bytes();
        client.write_all(&bogus_len).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let result = server_task.await.unwrap();
        assert!(matches!(result, Err(ConnError::FrameTooLarge(_))));
    }

    /// Document bound to a *different* handshake hash than the current
    /// session is rejected, guards against replaying a captured doc.
    #[tokio::test]
    async fn nsm_doc_with_wrong_handshake_hash_is_rejected() {
        let (mut client, mut ct, _real_hash, server_task) = connect().await;

        let forged = vec![0xab; 32];
        let (_, pk) = keypair(0x55);
        let (auth, _) = auth_frame(0x55, &forged, pk);
        write_frame(&mut client, &mut ct, &auth).await;
        drop(client);

        let result = server_task.await.unwrap();
        assert!(
            matches!(result, Err(ConnError::Attestation(_))),
            "expected Attestation error, got {result:?}"
        );
    }

    /// Random bytes that are not a valid NSM document are rejected.
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

    /// The server's own attestation (#208) is bound to THIS session: the
    /// same document fails verification under any other handshake hash,
    /// so a captured server doc cannot be replayed by a host fronting a
    /// different session.
    #[tokio::test]
    async fn server_attestation_is_bound_to_this_session() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (_, pk) = keypair(0x12);
        let (auth, _) = auth_frame(0x12, &hash, pk);
        write_frame(&mut client, &mut ct, &auth).await;
        let server_doc = read_and_verify_server_auth(&mut client, &mut ct, &hash).await;

        // Replay check: the SAME bytes under a different session hash
        // must be rejected by the nonce binding. The policy holds the
        // server's real (SERVER_SEED) PCRs, so the rejection is the
        // nonce binding alone, not a PCR mismatch.
        let other_hash = vec![0x77u8; 32];
        let policy = crate::wire::ServerPcrPolicy::Expected(vec![Pcrs {
            pcr0: vec![SERVER_SEED; 48],
            pcr1: vec![SERVER_SEED.wrapping_add(1); 48],
            pcr2: vec![SERVER_SEED.wrapping_add(2); 48],
        }]);
        let err = crate::wire::verify_server_attestation(&server_doc, &other_hash, &policy, true)
            .unwrap_err();
        assert!(
            matches!(err, crate::wire::ServerAuthError::Attestation(_)),
            "{err:?}"
        );

        drop(client);
        let _ = server_task.await.unwrap();
    }

    /// A failing local attestor is fatal for the connection (#208): the
    /// session must never proceed with the server unauthenticated, so
    /// the client sees the stream close instead of a missing/skipped
    /// server Authenticate.
    #[tokio::test]
    async fn failing_local_attestor_tears_the_connection_down() {
        struct FailingAttestor;
        #[async_trait::async_trait]
        impl SessionAttestor for FailingAttestor {
            async fn attest(&self, _handshake_hash: &[u8]) -> Result<Vec<u8>, String> {
                Err("nsm exploded".into())
            }
        }

        let node = Arc::new(Node::with_debug_mode(true));
        let (mut client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            handle_connection(node.as_ref(), &FailingAttestor, server, true).await
        });
        let (mut ct, hash) = perform_handshake_as_initiator(&mut client).await.unwrap();

        let (_, pk) = keypair(0x13);
        let (auth, _) = auth_frame(0x13, &hash, pk);
        write_frame(&mut client, &mut ct, &auth).await;

        // The connection is torn down with LocalAttestation; the client
        // reads EOF where the server Authenticate would have been.
        let result = server_task.await.unwrap();
        assert!(
            matches!(result, Err(ConnError::LocalAttestation(_))),
            "{result:?}"
        );
        let mut buf = [0u8; 4];
        let read = client.read_exact(&mut buf).await;
        assert!(read.is_err(), "expected EOF, got a frame header");
    }

    /// An invalid client never receives the server's attestation: the
    /// listener verifies the client FIRST and tears down on failure, so
    /// an unauthenticated probe cannot farm session-bound oracle
    /// documents.
    #[tokio::test]
    async fn invalid_client_gets_no_server_attestation() {
        let (mut client, mut ct, _hash, server_task) = connect().await;

        write_frame(
            &mut client,
            &mut ct,
            &Frame::Authenticate {
                nsm_doc: vec![0xde, 0xad, 0xbe, 0xef],
            },
        )
        .await;

        let result = server_task.await.unwrap();
        assert!(
            matches!(result, Err(ConnError::Attestation(_))),
            "{result:?}"
        );
        let mut buf = [0u8; 4];
        let read = client.read_exact(&mut buf).await;
        assert!(read.is_err(), "expected EOF, got a frame header");
    }

    /// After authentication the session is bound to the PCR-derived key,
    /// so RPC payloads must reference that same key.
    #[tokio::test]
    async fn rpc_targeting_a_different_key_is_unauthorized() {
        let (mut client, mut ct, hash, server_task) = connect().await;

        let (_, pk) = keypair(0x66);
        let (auth, _session_key) = auth_frame(0x66, &hash, pk);
        write_frame(&mut client, &mut ct, &auth).await;
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;

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

    /// End-to-end success: the OLD enclave (0x77) is already registered
    /// (seeded into the shared [`Node`], modelling its now-stopped
    /// session). The NEW enclave (0xee) attests through Noise+NSM in this
    /// connection, then issues a `Transition` carrying the #47 upgrade
    /// link the old enclave signed. The link is verified against the old
    /// key's frozen pubkey; the submitting session is bound to new_key.
    #[tokio::test]
    async fn transition_via_listener_with_valid_link_succeeds() {
        let node = Arc::new(Node::with_debug_mode(true));
        let (sk_old, pk_old) = keypair(0x77);
        register_old(&node, 0x77, pk_old).await;

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        // The NEW enclave authenticates as new_key (0xee) and submits.
        let (_, pk_new) = keypair(0xee);
        let (auth, _new_key) = auth_frame(0xee, &hash, pk_new);
        write_frame(&mut client, &mut ct, &auth).await;
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;

        let link = upgrade_link(0x77, 0xee, &sk_old);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition { link },
            },
        )
        .await;
        let resp = read_response(&mut client, &mut ct).await;
        assert_eq!(
            resp,
            Response::TransitionOk {
                version: Version(0)
            }
        );

        drop(client);
        let _ = server_task.await.unwrap();
    }

    /// An upgrade link signed by the wrong key (right length, attacker's
    /// key) is rejected, the listener-Node path enforces the control
    /// signature check against the OLD key's frozen pubkey.
    #[tokio::test]
    async fn transition_via_listener_with_invalid_signature_is_rejected() {
        let node = Arc::new(Node::with_debug_mode(true));
        // old_key (0x77) registers pk_real, but the link is signed with a
        // different key the attacker controls.
        let (_sk_real, pk_real) = keypair(0x77);
        let (sk_attacker, _) = keypair(0xab);
        register_old(&node, 0x77, pk_real).await;

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        let (_, pk_new) = keypair(0xee);
        let (auth, _new_key) = auth_frame(0xee, &hash, pk_new);
        write_frame(&mut client, &mut ct, &auth).await;
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;

        let link = upgrade_link(0x77, 0xee, &sk_attacker);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition { link },
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

    /// A Transition whose derived old_key was never registered is rejected,
    /// even though the new enclave's session is valid.
    #[tokio::test]
    async fn transition_via_listener_with_unregistered_old_key_is_rejected() {
        let node = Arc::new(Node::with_debug_mode(true));
        // Deliberately do NOT register old_key (0x77).
        let (sk_old, _pk_old) = keypair(0x77);

        let (mut client, mut ct, hash, server_task) = connect_with_node(Arc::clone(&node)).await;

        let (_, pk_new) = keypair(0xee);
        let (auth, _new_key) = auth_frame(0xee, &hash, pk_new);
        write_frame(&mut client, &mut ct, &auth).await;
        read_and_verify_server_auth(&mut client, &mut ct, &hash).await;

        let link = upgrade_link(0x77, 0xee, &sk_old);
        write_frame(
            &mut client,
            &mut ct,
            &Frame::Rpc {
                request: Request::Transition { link },
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
