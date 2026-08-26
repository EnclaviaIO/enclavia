use snow::{Builder, HandshakeState, TransportState};

#[cfg(feature = "async-transport")]
use ciborium::{de::from_reader, ser::into_writer};
#[cfg(feature = "async-transport")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "async-transport")]
use std::io::Cursor;
#[cfg(feature = "async-transport")]
use tracing::{debug, info, instrument, trace};

pub const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    pub fn initiator() -> Result<Self, snow::Error> {
        let builder: Builder<'_> = Builder::new(NOISE_PATTERN.parse()?);
        let state = builder.build_initiator()?;
        Ok(Self { state })
    }

    pub fn responder() -> Result<Self, snow::Error> {
        let builder: Builder<'_> = Builder::new(NOISE_PATTERN.parse()?);
        let state = builder.build_responder()?;
        Ok(Self { state })
    }

    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.state.write_message(payload, message)
    }

    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.state.read_message(message, payload)
    }

    pub fn into_transport_mode(self) -> Result<NoiseTransport, snow::Error> {
        let transport = self.state.into_transport_mode()?;
        Ok(NoiseTransport { state: transport })
    }

    pub fn get_handshake_hash(&self) -> &[u8] {
        self.state.get_handshake_hash()
    }
}

pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.state.write_message(payload, message)
    }

    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.state.read_message(message, payload)
    }
}

// --- Async transport layer (requires tokio) ---

/// Exact wire size of the first Noise handshake message ([`NOISE_PATTERN`]
/// with an empty handshake payload): the initiator's 32-byte X25519
/// ephemeral public key.
///
/// `Noise_NN` with empty payloads is fixed-size in both directions, which
/// is what lets the handshake reader use `read_exact` instead of trusting
/// a single `read()` to deliver exactly one whole message: a transport
/// that fragments (a short read hands `read_message` a truncated buffer)
/// or coalesces (a peer's pipelined first encrypted frame lands in the
/// same buffer as the handshake message) no longer corrupts the
/// handshake. The bytes on the wire are unchanged — this is purely a
/// reader-side robustness guarantee.
pub const NOISE_NN_MSG1_LEN: usize = 32;

/// Exact wire size of the second Noise handshake message: the responder's
/// 32-byte X25519 ephemeral plus the 16-byte ChaCha20-Poly1305 tag over
/// the empty payload. See [`NOISE_NN_MSG1_LEN`].
pub const NOISE_NN_MSG2_LEN: usize = 32 + 16;

/// Upper bound on waiting for the peer's handshake message. With
/// `read_exact` framing, a peer that opens a connection and then sends
/// fewer than the fixed message size (or nothing at all — which also
/// hung the previous single-`read()` reader) would otherwise park the
/// handshake task forever while holding the connection open. Generous
/// for any real link (the messages are 32/48 bytes); expiry means the
/// peer is not speaking the protocol, and the handshake fails.
pub const NOISE_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `read_exact` bounded by [`NOISE_HANDSHAKE_TIMEOUT`]: the handshake
/// must never wait indefinitely on a peer that sends too few bytes.
#[cfg(feature = "async-transport")]
async fn read_handshake_message(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    message: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    match tokio::time::timeout(
        NOISE_HANDSHAKE_TIMEOUT,
        tokio::io::AsyncReadExt::read_exact(stream, message),
    )
    .await
    {
        Ok(res) => {
            res?;
            Ok(())
        }
        Err(_) => Err(format!(
            "Noise handshake timed out after {NOISE_HANDSHAKE_TIMEOUT:?} waiting for the peer's \
             {}-byte handshake message",
            message.len()
        )
        .into()),
    }
}

/// Guard that a written handshake message has the exact size the reader
/// on the other side will `read_exact`. Cannot fail for [`NOISE_PATTERN`]
/// with empty payloads; a mismatch means the pattern or payload changed
/// without the framing constants being updated, and MUST fail loudly here
/// rather than desync the peer's reader.
#[cfg(feature = "async-transport")]
fn check_handshake_len(written: usize, expected: usize) -> Result<(), Box<dyn std::error::Error>> {
    if written != expected {
        return Err(format!(
            "Noise handshake message is {written} bytes, expected {expected}: \
             NOISE_PATTERN/payload changed without updating the fixed framing constants"
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "async-transport")]
#[instrument(skip(stream))]
pub async fn perform_handshake_as_initiator(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
) -> Result<(NoiseTransport, Vec<u8>), Box<dyn std::error::Error>> {
    info!("Starting Noise handshake as initiator");
    let mut handshake = NoiseHandshake::initiator()?;
    let mut buffer = vec![0u8; 65535];

    debug!("Sending first handshake message");
    let len = handshake.write_message(&[], &mut buffer)?;
    check_handshake_len(len, NOISE_NN_MSG1_LEN)?;
    tokio::io::AsyncWriteExt::write_all(stream, &buffer[..len]).await?;

    debug!("Waiting for handshake response");
    let mut message = [0u8; NOISE_NN_MSG2_LEN];
    read_handshake_message(stream, &mut message).await?;
    let mut payload = vec![0u8; 65535];
    handshake.read_message(&message, &mut payload)?;

    let handshake_hash = handshake.get_handshake_hash().to_vec();

    info!("Handshake completed successfully as initiator");
    Ok((handshake.into_transport_mode()?, handshake_hash))
}

#[cfg(feature = "async-transport")]
#[instrument(skip(stream))]
pub async fn perform_handshake_as_responder(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
) -> Result<(NoiseTransport, Vec<u8>), Box<dyn std::error::Error>> {
    info!("Starting Noise handshake as responder");
    let mut handshake = NoiseHandshake::responder()?;
    let mut buffer = vec![0u8; 65535];

    debug!("Waiting for first handshake message");
    let mut message = [0u8; NOISE_NN_MSG1_LEN];
    read_handshake_message(stream, &mut message).await?;
    let mut payload = vec![0u8; 65535];
    handshake.read_message(&message, &mut payload)?;

    debug!("Sending handshake response");
    let len = handshake.write_message(&[], &mut buffer)?;
    check_handshake_len(len, NOISE_NN_MSG2_LEN)?;
    tokio::io::AsyncWriteExt::write_all(stream, &buffer[..len]).await?;

    let handshake_hash = handshake.get_handshake_hash().to_vec();

    info!("Handshake completed successfully as responder");
    Ok((handshake.into_transport_mode()?, handshake_hash))
}

/// Perform handshake as initiator and return a CborTransport ready for CBOR messaging.
#[cfg(feature = "async-transport")]
#[instrument(skip(stream))]
pub async fn perform_cbor_handshake_as_initiator<S>(
    mut stream: S,
) -> Result<(CborTransport<S>, Vec<u8>), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let transport = perform_handshake_as_initiator(&mut stream).await?;
    Ok((CborTransport::new(transport.0, stream), transport.1))
}

/// Perform handshake as responder and return a CborTransport ready for CBOR messaging.
#[cfg(feature = "async-transport")]
#[instrument(skip(stream))]
pub async fn perform_cbor_handshake_as_responder<S>(
    mut stream: S,
) -> Result<(CborTransport<S>, Vec<u8>), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let transport = perform_handshake_as_responder(&mut stream).await?;
    Ok((CborTransport::new(transport.0, stream), transport.1))
}

/// Maximum bytes per write on a vsock-backed stream. A single AF_VSOCK
/// write larger than this is silently lost on the guest-to-host path (the
/// length prefix of a framed protocol arrives, the body never does, and the
/// connection wedges), so every vsock-facing writer must stay at or under
/// this size. Use [`write_all_vsock`] instead of `write_all` for any buffer
/// that is not statically known to fit.
pub const VSOCK_WRITE_CHUNK: usize = 32 * 1024;

/// `write_all`, segmented at [`VSOCK_WRITE_CHUNK`] per write so the buffer
/// survives a vsock hop. Identical semantics on any other stream type; use
/// this for every write whose bytes may cross AF_VSOCK and whose size is
/// not statically bounded below the limit.
///
/// Gated on the `tokio` dependency alone (not the full `async-transport`
/// feature) so consumers that skip the Noise transport machinery, like
/// enclavia-crypto, can still use it.
#[cfg(feature = "tokio")]
pub async fn write_all_vsock<S>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    for chunk in bytes.chunks(VSOCK_WRITE_CHUNK) {
        tokio::io::AsyncWriteExt::write_all(stream, chunk).await?;
    }
    Ok(())
}

/// A wrapper around NoiseTransport that provides CBOR message sending/receiving
/// with length-prefixed framing (4-byte big-endian length prefix + encrypted payload).
#[cfg(feature = "async-transport")]
pub struct CborTransport<S> {
    transport: NoiseTransport,
    stream: S,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

#[cfg(feature = "async-transport")]
impl<S> CborTransport<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    pub fn new(transport: NoiseTransport, stream: S) -> Self {
        Self {
            transport,
            stream,
            read_buffer: vec![0u8; 65535],
            write_buffer: vec![0u8; 65535],
        }
    }

    #[instrument(skip(self, message))]
    pub async fn send<T: Serialize>(
        &mut self,
        message: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut cbor_bytes = Vec::new();
        into_writer(message, &mut cbor_bytes)?;
        trace!(cbor_len = cbor_bytes.len(), "Serialized CBOR message");

        let encrypted_len = self
            .transport
            .write_message(&cbor_bytes, &mut self.write_buffer)?;
        trace!(encrypted_len = encrypted_len, "Encrypted message");

        let length_bytes = (encrypted_len as u32).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut self.stream, &length_bytes).await?;
        // Segmented write: a Noise frame can reach ~64 KiB ciphertext (CBOR
        // encodes Vec<u8> payloads as integer arrays, roughly doubling a
        // 16 KiB stream chunk), and an unsegmented write_all of that wedged
        // every stream whose per-message payload exceeded ~16 KiB. See
        // [`write_all_vsock`].
        write_all_vsock(&mut self.stream, &self.write_buffer[..encrypted_len]).await?;
        tokio::io::AsyncWriteExt::flush(&mut self.stream).await?;

        trace!("CBOR message sent successfully");
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn receive<T: for<'de> Deserialize<'de>>(
        &mut self,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut length_bytes = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut self.stream, &mut length_bytes).await?;
        let encrypted_len = u32::from_be_bytes(length_bytes) as usize;

        if encrypted_len > self.read_buffer.len() {
            return Err(format!(
                "Message too large: {} bytes (max: {})",
                encrypted_len,
                self.read_buffer.len()
            )
            .into());
        }

        trace!(encrypted_len = encrypted_len, "Reading encrypted message");

        tokio::io::AsyncReadExt::read_exact(
            &mut self.stream,
            &mut self.read_buffer[..encrypted_len],
        )
        .await?;

        let mut payload = vec![0u8; 65535];
        let payload_len = self
            .transport
            .read_message(&self.read_buffer[..encrypted_len], &mut payload)?;
        trace!(payload_len = payload_len, "Decrypted message");

        let mut cursor = Cursor::new(&payload[..payload_len]);
        let message: T = from_reader(&mut cursor)?;
        trace!("CBOR message received and deserialized successfully");
        Ok(message)
    }

    pub fn transport(&self) -> &NoiseTransport {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut NoiseTransport {
        &mut self.transport
    }
}

#[cfg(all(test, feature = "async-transport"))]
mod write_chunk_tests {
    use super::*;

    /// AsyncWrite sink that records the size of every poll_write call, so
    /// the test can assert `CborTransport::send` never exceeds the vsock
    /// single-write limit even for frames that encrypt to ~64 KiB.
    struct RecordingSink {
        writes: Vec<usize>,
        data: Vec<u8>,
    }

    impl tokio::io::AsyncWrite for RecordingSink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes.push(buf.len());
            self.data.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncRead for RecordingSink {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn send_never_writes_more_than_vsock_chunk() {
        // Hand-build a transport pair so we can drive `send` without a
        // network: initiator/responder over an in-memory handshake.
        let mut hs_i = NoiseHandshake::initiator().unwrap();
        let mut hs_r = NoiseHandshake::responder().unwrap();
        let mut buf_a = vec![0u8; 65535];
        let mut buf_b = vec![0u8; 65535];
        let len = hs_i.write_message(&[], &mut buf_a).unwrap();
        hs_r.read_message(&buf_a[..len], &mut buf_b).unwrap();
        let len = hs_r.write_message(&[], &mut buf_a).unwrap();
        hs_i.read_message(&buf_a[..len], &mut buf_b).unwrap();
        let transport = hs_i.into_transport_mode().unwrap();

        let sink = RecordingSink {
            writes: Vec::new(),
            data: Vec::new(),
        };
        let mut cbor = CborTransport::new(transport, sink);

        // A 30 KiB Vec<u8> payload CBOR-encodes to roughly double its size
        // (integer-array encoding), so the frame comfortably exceeds one
        // 32 KiB vsock write.
        #[derive(Serialize)]
        struct Big {
            payload: Vec<u8>,
        }
        let msg = Big {
            payload: vec![0xABu8; 30 * 1024],
        };
        cbor.send(&msg).await.unwrap();

        let sink = &cbor.stream;
        let total: usize = sink.writes.iter().sum();
        assert!(
            total > VSOCK_WRITE_CHUNK + 4,
            "frame should exceed one chunk"
        );
        assert!(
            sink.writes.iter().all(|w| *w <= VSOCK_WRITE_CHUNK),
            "single write exceeded the vsock limit: {:?}",
            sink.writes
        );
    }
}

#[cfg(all(test, feature = "async-transport"))]
mod handshake_framing_tests {
    use super::*;

    /// The framing constants ARE the wire format: `Noise_NN` with empty
    /// payloads produces exactly these message sizes. If this test fails,
    /// the pattern or handshake payload changed and every `read_exact` in
    /// `perform_handshake_as_*` would desync.
    #[test]
    fn nn_handshake_messages_have_the_pinned_sizes() {
        let mut hs_i = NoiseHandshake::initiator().unwrap();
        let mut hs_r = NoiseHandshake::responder().unwrap();
        let mut buf_a = vec![0u8; 65535];
        let mut buf_b = vec![0u8; 65535];
        let len1 = hs_i.write_message(&[], &mut buf_a).unwrap();
        assert_eq!(len1, NOISE_NN_MSG1_LEN, "message 1 size");
        hs_r.read_message(&buf_a[..len1], &mut buf_b).unwrap();
        let len2 = hs_r.write_message(&[], &mut buf_a).unwrap();
        assert_eq!(len2, NOISE_NN_MSG2_LEN, "message 2 size");
        hs_i.read_message(&buf_a[..len2], &mut buf_b).unwrap();
    }

    /// AsyncRead adapter that delivers at most one byte per poll_read:
    /// the worst-case fragmenting transport. The old single-`read()`
    /// handshake handed the first byte alone to `read_message` and failed;
    /// `read_exact` framing must complete the handshake regardless of how
    /// the stream fragments.
    struct OneBytePerRead<S>(S);

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for OneBytePerRead<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut one = [0u8; 1];
            let mut one_buf = tokio::io::ReadBuf::new(&mut one);
            match std::pin::Pin::new(&mut self.0).poll_read(cx, &mut one_buf) {
                std::task::Poll::Ready(Ok(())) => {
                    buf.put_slice(one_buf.filled());
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for OneBytePerRead<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Regression for the boundary in enclavia#102: a byte-stream
    /// transport that fragments the handshake messages (here: one byte
    /// per read on BOTH sides) must still complete the handshake and
    /// agree on the handshake hash.
    #[tokio::test]
    async fn handshake_survives_maximally_fragmented_stream() {
        let (a, b) = tokio::io::duplex(1024);
        let mut a = OneBytePerRead(a);
        let mut b = OneBytePerRead(b);
        let initiator = tokio::spawn(async move {
            let (_, hash) = perform_handshake_as_initiator(&mut a).await.unwrap();
            hash
        });
        let responder = tokio::spawn(async move {
            let (_, hash) = perform_handshake_as_responder(&mut b).await.unwrap();
            hash
        });
        let (hi, hr) = (initiator.await.unwrap(), responder.await.unwrap());
        assert_eq!(hi, hr, "both sides must derive the same handshake hash");
        assert!(!hi.is_empty());
    }

    /// A peer that opens a connection, sends fewer bytes than one
    /// handshake message, and then parks (the mesh `GarbageDialer`
    /// shape, and any slow-loris peer) must fail the handshake at
    /// [`NOISE_HANDSHAKE_TIMEOUT`] instead of holding the responder
    /// task forever. Paused tokio time makes the timeout fire
    /// immediately once both tasks are idle.
    #[tokio::test(start_paused = true)]
    async fn responder_times_out_on_a_peer_that_sends_too_few_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0xde, 0xad, 0xbe, 0xef])
            .await
            .unwrap();
        let err = perform_handshake_as_responder(&mut b)
            .await
            .err()
            .expect("a short handshake write must not hang");
        assert!(err.to_string().contains("timed out"), "{err}");
        drop(a);
    }

    /// A peer that pipelines its first length-prefixed encrypted frame in
    /// the same flush as its final handshake message must not corrupt the
    /// handshake: `read_exact` consumes exactly the handshake bytes and
    /// leaves the frame in the stream for the transport layer.
    #[tokio::test]
    async fn coalesced_post_handshake_frame_is_left_in_the_stream() {
        let (mut a, mut b) = tokio::io::duplex(4096);

        let responder = tokio::spawn(async move {
            // Hand-rolled responder that writes handshake message 2 and an
            // encrypted frame in ONE write (worst-case coalescing).
            let mut hs = NoiseHandshake::responder().unwrap();
            let mut msg1 = [0u8; NOISE_NN_MSG1_LEN];
            tokio::io::AsyncReadExt::read_exact(&mut b, &mut msg1)
                .await
                .unwrap();
            let mut payload = vec![0u8; 1024];
            hs.read_message(&msg1, &mut payload).unwrap();
            let mut msg2 = vec![0u8; 65535];
            let len2 = hs.write_message(&[], &mut msg2).unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let mut frame = vec![0u8; 65535];
            let flen = transport.write_message(b"pipelined", &mut frame).unwrap();
            let mut combined = msg2[..len2].to_vec();
            combined.extend_from_slice(&(flen as u32).to_be_bytes());
            combined.extend_from_slice(&frame[..flen]);
            tokio::io::AsyncWriteExt::write_all(&mut b, &combined)
                .await
                .unwrap();
        });

        let (mut transport, _) = perform_handshake_as_initiator(&mut a).await.unwrap();
        responder.await.unwrap();

        // The pipelined frame must still be intact in the stream.
        let mut len_bytes = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut a, &mut len_bytes)
            .await
            .unwrap();
        let flen = u32::from_be_bytes(len_bytes) as usize;
        let mut ciphertext = vec![0u8; flen];
        tokio::io::AsyncReadExt::read_exact(&mut a, &mut ciphertext)
            .await
            .unwrap();
        let mut plaintext = vec![0u8; 1024];
        let plen = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(&plaintext[..plen], b"pipelined");
    }
}
