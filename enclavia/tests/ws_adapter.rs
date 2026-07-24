//! Shared test helper: bridge a `tokio_tungstenite::WebSocketStream`
//! (frame-level) to the AsyncRead/AsyncWrite API the
//! `perform_cbor_handshake_as_responder` helper expects. Each batch of
//! bytes written via AsyncWrite is shipped as a single binary WS frame;
//! incoming binary frames are concatenated into a byte stream on the read
//! side.
//!
//! Included via `#[path = "ws_adapter.rs"] mod ws_adapter;` from the
//! integration tests that stand up an in-process Noise responder.

#![allow(dead_code)]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;

pub struct WsBytes<S> {
    ws: S,
    buf: BytesMut,
}

pub fn wrap<S>(ws: S) -> WsBytes<S> {
    WsBytes {
        ws,
        buf: BytesMut::new(),
    }
}

pub type WsByteStream = WsBytes<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>;

pub fn wrap_ws(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> WsByteStream {
    wrap(ws)
}

impl<S> AsyncRead for WsBytes<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(buf.remaining());
                buf.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    self.buf.extend_from_slice(&data);
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsBytes<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Flush eagerly: noise handshake writes don't call flush, so any
        // buffering here would deadlock the responder.
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => return Poll::Pending,
        }
        if let Err(e) = Pin::new(&mut self.ws).start_send(Message::Binary(buf.to_vec().into())) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        let _ = Pin::new(&mut self.ws).poll_flush(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
