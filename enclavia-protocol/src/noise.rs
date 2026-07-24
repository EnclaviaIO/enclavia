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
    tokio::io::AsyncWriteExt::write_all(stream, &buffer[..len]).await?;

    debug!("Waiting for handshake response");
    let len = tokio::io::AsyncReadExt::read(stream, &mut buffer).await?;
    let mut payload = vec![0u8; 65535];
    handshake.read_message(&buffer[..len], &mut payload)?;

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
    let len = tokio::io::AsyncReadExt::read(stream, &mut buffer).await?;
    let mut payload = vec![0u8; 65535];
    handshake.read_message(&buffer[..len], &mut payload)?;

    debug!("Sending handshake response");
    let len = handshake.write_message(&[], &mut buffer)?;
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

/// Maximum bytes per stream write in [`CborTransport::send`]. Single writes
/// over ~32 KiB on AF_VSOCK are silently lost (guest-to-host), so every
/// vsock-facing writer in this workspace stays at or under this size.
#[cfg(feature = "async-transport")]
const VSOCK_WRITE_CHUNK: usize = 32 * 1024;

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
        // Cap each write at 32 KiB: a single AF_VSOCK write larger than that
        // is silently lost between the guest driver and the host (the
        // repo-wide "cap vsock writes at 32 KiB" rule, see e.g. the chain
        // module's VSOCK_CHUNK). A Noise frame can reach ~64 KiB ciphertext
        // (CBOR encodes Vec<u8> payloads as integer arrays, roughly doubling
        // a 16 KiB stream chunk), so writing it in one call wedged every
        // stream whose per-message payload exceeded ~16 KiB.
        for chunk in self.write_buffer[..encrypted_len].chunks(VSOCK_WRITE_CHUNK) {
            tokio::io::AsyncWriteExt::write_all(&mut self.stream, chunk).await?;
        }
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

        let sink = RecordingSink { writes: Vec::new(), data: Vec::new() };
        let mut cbor = CborTransport::new(transport, sink);

        // A 30 KiB Vec<u8> payload CBOR-encodes to roughly double its size
        // (integer-array encoding), so the frame comfortably exceeds one
        // 32 KiB vsock write.
        #[derive(Serialize)]
        struct Big {
            payload: Vec<u8>,
        }
        let msg = Big { payload: vec![0xABu8; 30 * 1024] };
        cbor.send(&msg).await.unwrap();

        let sink = &cbor.stream;
        let total: usize = sink.writes.iter().sum();
        assert!(total > VSOCK_WRITE_CHUNK + 4, "frame should exceed one chunk");
        assert!(
            sink.writes.iter().all(|w| *w <= VSOCK_WRITE_CHUNK),
            "single write exceeded the vsock limit: {:?}",
            sink.writes
        );
    }
}
