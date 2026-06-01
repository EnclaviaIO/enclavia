// The crate's `Error` enum has a `WebSocket(tungstenite::Error)` variant
// which trips `clippy::result_large_err` because `tungstenite::Error` itself
// is ~144 bytes. Boxing it would change the public matching shape of
// `Error::WebSocket(_)` for downstream callers; allow the lint at the
// crate level for now and revisit when we're ready for that minor break.
// Tracked in #9.
#![allow(clippy::result_large_err)]

mod client;
mod error;
mod http;
mod message;
mod noise;
mod request;
mod response;
mod stream;
mod transport;

pub use enclavia_protocol::attestation::Pcrs;
pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use http::Method;
pub use request::RequestBuilder;
pub use response::Response;
pub use stream::UpgradedStream;
