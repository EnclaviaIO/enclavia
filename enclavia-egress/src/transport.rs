//! Transport abstraction the egress daemon uses to reach `egress-host`.
//!
//! Production is always vsock ([`VsockTransport`]). The `test-utils`
//! feature adds a [`UdsTransport`] so integration tests can stand the
//! daemon up on a dev machine without booting QEMU.
//!
//! The trait returns a boxed `AsyncRead + AsyncWrite + Send + Unpin` so
//! the rest of the crate stays transport-agnostic.

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// One open byte stream to `egress-host`. Boxed because vsock and UDS
/// streams are different concrete types and the rest of the crate
/// doesn't need to know which.
pub type BoxedStream = Box<dyn AsyncReadWrite + Send + Unpin>;

/// Convenience supertrait: anything that is both `AsyncRead` and
/// `AsyncWrite` (and `Send + Unpin`) qualifies as a transport stream.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

#[async_trait]
pub trait EgressTransport: Send + Sync {
    /// Dial `egress-host` and return the open byte stream. Each accepted
    /// in-stack flow gets its own dial; the relay protocol is one
    /// `Open` frame per stream.
    async fn connect(&self) -> io::Result<BoxedStream>;
}

/// Production transport: AF_VSOCK to a fixed (CID, port).
#[derive(Clone, Copy, Debug)]
pub struct VsockTransport {
    pub cid: u32,
    pub port: u32,
}

#[async_trait]
impl EgressTransport for VsockTransport {
    async fn connect(&self) -> io::Result<BoxedStream> {
        let stream = tokio_vsock::VsockStream::connect(self.cid, self.port)
            .await
            .map_err(io::Error::other)?;
        Ok(Box::new(stream))
    }
}

/// Test transport: Unix domain socket. Gated behind `test-utils` so it
/// is impossible to compile into the production binary.
#[cfg(feature = "test-utils")]
#[derive(Clone, Debug)]
pub struct UdsTransport {
    pub path: std::path::PathBuf,
}

#[cfg(feature = "test-utils")]
#[async_trait]
impl EgressTransport for UdsTransport {
    async fn connect(&self) -> io::Result<BoxedStream> {
        let stream = tokio::net::UnixStream::connect(&self.path).await?;
        Ok(Box::new(stream))
    }
}
