//! Customer-side client for the synchronizer RPC surface (`client`
//! feature).
//!
//! Speaks exactly the session protocol `crate::listener` answers:
//!
//! 1. `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake (initiator side).
//! 2. First frame: [`Frame::Authenticate`] carrying a Nitro NSM
//!    attestation document whose `nonce` binds the just-completed Noise
//!    handshake hash and whose `user_data` carries the enclave's 65-byte
//!    SEC1 P-256 control pubkey (#47). A bad document tears the
//!    connection down.
//! 3. The SERVER authenticates back (#208): its first frame is its own
//!    [`Frame::Authenticate`], a document bound to the SAME handshake
//!    hash. [`Handshake::authenticate`] verifies it (full AWS Nitro CA
//!    chain when `debug_mode = false`) and checks its PCRs against the
//!    caller-supplied [`ServerPcrPolicy`] BEFORE returning an RPC-ready
//!    [`Client`]. This step is mandatory: `Noise_NN` is unauthenticated
//!    DH over a host-relayed transport, so without it ANY host could
//!    terminate the session and answer Get/Pin as a fake oracle, which
//!    is precisely the rollback the synchronizer exists to prevent.
//! 4. Subsequent frames: [`Frame::Rpc`] requests, each answered with one
//!    CBOR [`Response`].
//!
//! ## SECURITY: where the expected server PCRs MUST come from
//!
//! The [`ServerPcrPolicy`] is the trust anchor of the whole oracle
//! relationship. It MUST be sourced from the customer enclave's MEASURED
//! image or config (e.g. `/etc/enclavia/config.json`, baked into the
//! EIF and therefore covered by the enclave's own PCRs), NEVER from a
//! host-controlled channel (environment variables, command-line
//! arguments, any vsock side-channel). A host that can choose the
//! expected PCRs, or flip `debug_mode` to `true`, can impersonate the
//! oracle and the verification is worthless. See
//! [`crate::wire::ServerPcrPolicy`] for the full contract.
//!
//! The attestation document is produced by the CALLER (typically via
//! `/dev/nsm` from inside the customer enclave, or a `FakeAttestation`
//! in tests): the client only needs the raw bytes, so this module stays
//! free of any NSM driver dependency and is generic over any
//! `AsyncRead + AsyncWrite` transport (vsock in production, UDS or
//! `tokio::io::duplex` in tests).
//!
//! ## Wire shape note: there is no separate Register RPC
//!
//! On the wire a first-time registration IS a [`Request::Pin`]: the
//! server maps it to the state machine's `Register` op when the key is
//! unseen and reports it back as `PinOk { version: Version(0) }`. The
//! [`Client::pin`] return value carries that version so the caller can
//! distinguish registration from a subsequent pin.
//!
//! ## Durability
//!
//! In the replicated deployment the server answers `PinOk` only after
//! `client_write_durable` has replicated the entry to EVERY voter (see
//! `crate::raft::serve`). Awaiting [`Client::pin`]'s response therefore
//! IS the durable-replication ack the anti-rollback gate in `nbd-client`
//! relies on.
//!
//! ## vsock write sizing
//!
//! Single writes over AF_VSOCK (and the vhost-device-vsock UDS bridge in
//! debug mode) are unreliable above ~32 KiB, so every outbound buffer is
//! chunked to [`VSOCK_WRITE_CHUNK`]-byte writes. Frames here are small
//! (an NSM document is ~5 KiB) but the cap keeps the client safe even at
//! the 65535-byte Noise maximum.

use enclavia_protocol::{NoiseTransport, perform_handshake_as_initiator};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{Frame, MAX_FRAME_SIZE, Request, Response, RpcError};
use crate::{Commitment, PcrKey, Version};

// Re-exported so callers (nbd-client) construct the policy and match its
// rejection error from the module they already import the client from.
pub use crate::wire::{Pcrs, ServerAuthError, ServerPcrPolicy, verify_server_attestation};

/// Maximum bytes per single `write_all` on the underlying transport.
///
/// AF_VSOCK (and vhost-device-vsock's UDS bridge in QEMU debug mode)
/// deadlocks on single writes well above 32 KiB; 32 KiB is the proven
/// safe chunk size used across the workspace (see `nbd-client`'s
/// `forward_bytes`).
pub const VSOCK_WRITE_CHUNK: usize = 32 * 1024;

/// Errors the customer client can hit.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Underlying transport I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Noise handshake failed before any frames were exchanged.
    #[error("noise handshake: {0}")]
    Handshake(String),
    /// Noise transport-mode encrypt or decrypt failed mid-session.
    #[error("noise crypto: {0}")]
    Crypto(String),
    /// CBOR encode of an outbound frame failed.
    #[error("cbor encode: {0}")]
    CborEncode(String),
    /// CBOR decode of an inbound response failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// Inbound frame's claimed length exceeds [`MAX_FRAME_SIZE`].
    #[error("frame too large: {0} bytes (max {max})", max = MAX_FRAME_SIZE)]
    FrameTooLarge(u32),
    /// The server closed the stream where a response was expected.
    #[error("connection closed by server")]
    ConnectionClosed,
    /// The server answered with a structured RPC error.
    #[error("rpc error: {0}")]
    Rpc(RpcError),
    /// The server answered with a response of the wrong variant for the
    /// request that was sent (protocol bug on one side).
    #[error("unexpected response variant: {0}")]
    UnexpectedResponse(&'static str),
    /// The server's mandatory `Authenticate` frame (#208) failed
    /// verification: the document was malformed, failed the CA-chain /
    /// COSE checks (production mode), or did not bind this session's
    /// handshake hash (a replayed capture). Whoever is on the other end,
    /// it has not proven it is an enclave on THIS channel; fail-stop.
    #[error("server attestation invalid: {0}")]
    ServerAttestation(String),
    /// The server's attestation verified but its PCRs are not admitted
    /// by the caller's [`ServerPcrPolicy`]: the other end is a real,
    /// channel-bound enclave, but NOT the synchronizer the caller
    /// trusts (oracle impersonation). Fail-stop.
    #[error("server attestation PCRs are not the expected synchronizer measurements")]
    ServerPcrRejected,
    /// The server's first frame was not its `Authenticate` (#208): the
    /// far end does not speak the mutual-authentication protocol.
    #[error("server's first frame was not its Authenticate")]
    ServerAuthMissing,
}

/// A completed Noise handshake, waiting for the caller to produce the
/// attestation document that authenticates the session.
///
/// Split from [`Client`] because the NSM document must bind
/// [`Handshake::handshake_hash`] as its nonce, and only the caller can
/// drive `/dev/nsm` (or a test fake) to mint it.
pub struct Handshake<S> {
    stream: S,
    transport: NoiseTransport,
    handshake_hash: Vec<u8>,
}

impl<S> Handshake<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform the `Noise_NN` handshake (initiator side) on `stream`.
    pub async fn start(mut stream: S) -> Result<Self, ClientError> {
        let (transport, handshake_hash) = perform_handshake_as_initiator(&mut stream)
            .await
            .map_err(|e| ClientError::Handshake(e.to_string()))?;
        Ok(Self {
            stream,
            transport,
            handshake_hash,
        })
    }

    /// The Noise handshake hash for this session. The attestation
    /// document passed to [`Handshake::authenticate`] MUST carry exactly
    /// these bytes as its `nonce`, or the listener will reject it.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// Run the mutual authentication (#208): send [`Frame::Authenticate`]
    /// with the caller-produced NSM document, then read and verify the
    /// SERVER's `Authenticate` against this session's handshake hash and
    /// the caller's `server_policy`. Returns the RPC-ready [`Client`]
    /// only once the oracle has proven both that it is a genuine enclave
    /// terminating THIS channel (nonce binding; full AWS Nitro CA chain
    /// when `debug_mode = false`) and that it runs the expected
    /// synchronizer image (PCR policy).
    ///
    /// # SECURITY: `server_policy` and `debug_mode` are trust anchors
    ///
    /// Both MUST come from the customer enclave's MEASURED image/config
    /// (e.g. `/etc/enclavia/config.json`, baked into the EIF), NEVER
    /// from host-controlled input: a host that picks the expected PCRs,
    /// or sets `debug_mode = true`, can impersonate the oracle outright.
    /// See the module docs and [`ServerPcrPolicy`].
    ///
    /// An invalid CLIENT document still surfaces as
    /// [`ClientError::ConnectionClosed`] (the listener tears the
    /// connection down before attesting back).
    pub async fn authenticate(
        mut self,
        nsm_doc: Vec<u8>,
        server_policy: &ServerPcrPolicy,
        debug_mode: bool,
    ) -> Result<Client<S>, ClientError> {
        write_frame(
            &mut self.stream,
            &mut self.transport,
            &Frame::Authenticate { nsm_doc },
        )
        .await?;

        // Strict ping-pong (mirrors the listener): the server's first
        // frame after a valid client Authenticate is its own
        // Authenticate, bound to the same handshake hash.
        let plaintext = read_plaintext_frame(&mut self.stream, &mut self.transport).await?;
        let frame: Frame = ciborium::from_reader(plaintext.as_slice())
            .map_err(|e| ClientError::Cbor(e.to_string()))?;
        let server_doc = match frame {
            Frame::Authenticate { nsm_doc } => nsm_doc,
            _ => return Err(ClientError::ServerAuthMissing),
        };
        verify_server_attestation(&server_doc, &self.handshake_hash, server_policy, debug_mode)
            .map_err(|e| match e {
                ServerAuthError::Attestation(msg) => ClientError::ServerAttestation(msg),
                ServerAuthError::PcrRejected => ClientError::ServerPcrRejected,
            })?;

        Ok(Client {
            stream: self.stream,
            transport: self.transport,
        })
    }
}

/// An authenticated synchronizer session, ready to issue RPCs.
///
/// Requests are strictly serialized: one in flight at a time, matching
/// the listener's request/response loop.
pub struct Client<S> {
    stream: S,
    transport: NoiseTransport,
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Pin `commitment` under `key` (which must equal the session's
    /// attested key). Returns the resulting per-key version:
    /// `Version(0)` means this Pin REGISTERED the key (first pin for an
    /// unseen key); `Version(n+1)` bumped an existing pin.
    ///
    /// In the replicated deployment the response only arrives after the
    /// entry is replicated to every voter, so awaiting this is the
    /// durable ack.
    pub async fn pin(
        &mut self,
        key: PcrKey,
        commitment: Commitment,
    ) -> Result<Version, ClientError> {
        match self.rpc(Request::Pin { key, commitment }).await? {
            Response::PinOk { version } => Ok(version),
            Response::Err { error } => Err(ClientError::Rpc(error)),
            _ => Err(ClientError::UnexpectedResponse("expected PinOk")),
        }
    }

    /// Read the latest pinned commitment for `key` (which must equal the
    /// session's attested key). [`RpcError::NotFound`] (surfaced as
    /// [`ClientError::Rpc`]) means the key has never been registered, or
    /// was retired by a Transition.
    pub async fn get(&mut self, key: PcrKey) -> Result<(Commitment, Version), ClientError> {
        match self.rpc(Request::Get { key }).await? {
            Response::GetOk {
                commitment,
                version,
            } => Ok((commitment, version)),
            Response::Err { error } => Err(ClientError::Rpc(error)),
            _ => Err(ClientError::UnexpectedResponse("expected GetOk")),
        }
    }

    /// Issue one raw [`Request`] and read its [`Response`]. The typed
    /// helpers ([`Client::pin`], [`Client::get`]) are usually what you
    /// want; this exists for `Transition` and future RPCs.
    pub async fn rpc(&mut self, request: Request) -> Result<Response, ClientError> {
        write_frame(
            &mut self.stream,
            &mut self.transport,
            &Frame::Rpc { request },
        )
        .await?;
        read_response(&mut self.stream, &mut self.transport).await
    }
}

/// Write `buf` in [`VSOCK_WRITE_CHUNK`]-byte chunks. See the module docs
/// for why a single large `write_all` is unsafe over vsock.
async fn write_chunked<W>(stream: &mut W, buf: &[u8]) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    for chunk in buf.chunks(VSOCK_WRITE_CHUNK) {
        stream.write_all(chunk).await?;
    }
    Ok(())
}

async fn write_frame<W>(
    stream: &mut W,
    transport: &mut NoiseTransport,
    frame: &Frame,
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    let mut plaintext = Vec::new();
    ciborium::into_writer(frame, &mut plaintext)
        .map_err(|e| ClientError::CborEncode(e.to_string()))?;
    let mut ciphertext = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    let len: u32 = ct_len
        .try_into()
        .map_err(|_| ClientError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    write_chunked(stream, &ciphertext[..ct_len]).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one length-prefixed encrypted frame and return its decrypted
/// plaintext bytes. Shared by the server-`Authenticate` read (decoded as
/// a [`Frame`]) and the RPC path (decoded as a [`Response`]).
async fn read_plaintext_frame<R>(
    stream: &mut R,
    transport: &mut NoiseTransport,
) -> Result<Vec<u8>, ClientError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ClientError::ConnectionClosed);
        }
        Err(e) => return Err(ClientError::Io(e)),
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_SIZE {
        return Err(ClientError::FrameTooLarge(len));
    }
    let mut ciphertext = vec![0u8; len as usize];
    stream.read_exact(&mut ciphertext).await?;

    let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
    let pt_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    plaintext.truncate(pt_len);
    Ok(plaintext)
}

async fn read_response<R>(
    stream: &mut R,
    transport: &mut NoiseTransport,
) -> Result<Response, ClientError>
where
    R: AsyncRead + Unpin,
{
    let plaintext = read_plaintext_frame(stream, transport).await?;
    ciborium::from_reader(plaintext.as_slice()).map_err(|e| ClientError::Cbor(e.to_string()))
}
