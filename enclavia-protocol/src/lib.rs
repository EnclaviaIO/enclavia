pub mod attestation;
#[cfg(feature = "async-transport")]
pub mod egress;
mod noise;

pub use noise::*;

use serde::{Deserialize, Serialize};

/// Messages sent from the client to the enclave server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Request an attestation document. The server includes the handshake hash
    /// as the attestation nonce and the current control nonce as user_data.
    RequestAttestation,

    /// Raw bytes to forward to the inner container (typically an HTTP request).
    /// The `id` is echoed back in the response so the client can match them.
    /// One-shot: the server writes the payload, drains the response to EOF,
    /// and replies with exactly one [`ServerMessage::Data`].
    Data { id: u64, payload: Vec<u8> },

    /// Authenticated management command. `payload` is a CBOR-encoded
    /// `ControlCommand`; `signature` is an Ed25519 signature over `payload`
    /// produced with the project's control private key. The server verifies
    /// the signature against the control public key baked into the EIF and
    /// the embedded nonce against its current single-use nonce.
    Control {
        payload: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Open a bidirectional byte stream to the inner container. The server
    /// writes `payload` (typically an HTTP/1.1 upgrade request) to the
    /// container's TCP socket, then pumps bytes both ways until either side
    /// closes: container reads come back as [`ServerMessage::StreamData`],
    /// client follow-ups arrive as [`ClientMessage::StreamData`]. The server
    /// does NOT inspect the payload — it is the caller's job (e.g. the SDK)
    /// to recognize `101 Switching Protocols` (or any other response shape)
    /// in the returned bytes. This keeps the in-enclave protocol small enough
    /// that a non-Rust frontend (a future nginx C module, a WASM SDK) can
    /// implement it without an HTTP parser.
    OpenStream { id: u64, payload: Vec<u8> },

    /// Additional bytes sent into an open stream (e.g. WebSocket payload
    /// frames). The `id` matches the original `OpenStream` request.
    StreamData { id: u64, payload: Vec<u8> },

    /// Close one or both halves of an open stream. `half = Write` signals
    /// that the client is done sending (the server should `shutdown(WRITE)` on
    /// the inner TCP), `half = Both` tears the stream down.
    StreamClose { id: u64, half: StreamHalf },
}

/// Which halves of an upgraded stream a [`ClientMessage::StreamClose`] tears
/// down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamHalf {
    /// Half-close: the client is done writing, but still expects to read.
    Write,
    /// Full close: both directions torn down.
    Both,
}

/// Messages sent from the enclave server to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Attestation document (COSE_Sign1 in enclave mode, raw nonce in debug
    /// mode). `control_nonce` is the current per-boot single-use nonce that
    /// must be embedded in the next signed `ControlCommand`.
    Attestation {
        data: Vec<u8>,
        control_nonce: [u8; 32],
    },

    /// Raw bytes received from the inner container (typically an HTTP response).
    /// The `id` matches the corresponding `ClientMessage::Data` request.
    Data { id: u64, payload: Vec<u8> },

    /// Error forwarding to the inner container.
    Error { id: u64, message: String },

    /// Result of a `Control` command. The control nonce was rotated whether
    /// or not the command succeeded — the next signed command must use the
    /// new nonce, fetched via a fresh `RequestAttestation`.
    ControlResult { success: bool, message: String },

    /// Bytes read out of an open inner-container connection. For an
    /// [`ClientMessage::OpenStream`] this carries everything the workload
    /// writes back, including the initial HTTP response head: the client is
    /// responsible for any parsing.
    StreamData { id: u64, payload: Vec<u8> },

    /// The open stream has been closed by the server side (workload EOF or
    /// error). After this, no further `StreamData` for this `id` will arrive.
    StreamClose { id: u64 },
}

/// Inner payload of a signed control command. Serialized as CBOR before
/// signing — the wire-level signature covers the exact bytes the verifier
/// then deserializes, so re-encoding skew can't break verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum ControlCommand {
    /// Rotate the storage wrapping key onto a new KMS key. The old enclave
    /// runs `zfs change-key`, encrypts the new wrapping key with
    /// `new_public_key` (an RSA pubkey from the new KMS key), and updates
    /// the on-disk key blob. After a clean restart with a new EIF bound to
    /// `new_key_id`, the next boot schedules deletion of the old KMS key.
    PrepareUpgrade {
        /// RSA public key (DER-encoded SubjectPublicKeyInfo) from the new
        /// KMS key — used by the running enclave to wrap the next
        /// generation's wrapping key.
        new_public_key: Vec<u8>,
        /// ARN/identifier of the new KMS key. Stored in the key blob so
        /// the next boot decrypts via the right KMS key.
        new_key_id: String,
        /// Single-use per-boot nonce, must equal the server's current
        /// nonce. Prevents replay across boots without relying on clocks.
        nonce: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("serialize");
        ciborium::from_reader(buf.as_slice()).expect("deserialize")
    }

    #[test]
    fn client_open_stream_round_trip() {
        let msg = ClientMessage::OpenStream {
            id: 11,
            payload: b"GET /ws HTTP/1.1\r\n\r\n".to_vec(),
        };
        let back = cbor_round_trip(&msg);
        match back {
            ClientMessage::OpenStream { id, payload } => {
                assert_eq!(id, 11);
                assert_eq!(payload, b"GET /ws HTTP/1.1\r\n\r\n".to_vec());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_stream_data_round_trip() {
        let msg = ClientMessage::StreamData { id: 42, payload: vec![1, 2, 3, 4, 5] };
        let back = cbor_round_trip(&msg);
        match back {
            ClientMessage::StreamData { id, payload } => {
                assert_eq!(id, 42);
                assert_eq!(payload, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_stream_close_round_trip() {
        for half in [StreamHalf::Write, StreamHalf::Both] {
            let msg = ClientMessage::StreamClose { id: 7, half };
            let back = cbor_round_trip(&msg);
            match back {
                ClientMessage::StreamClose { id, half: got } => {
                    assert_eq!(id, 7);
                    assert_eq!(got, half);
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn server_stream_data_round_trip() {
        let msg = ServerMessage::StreamData { id: 99, payload: vec![0xde, 0xad, 0xbe, 0xef] };
        let back = cbor_round_trip(&msg);
        match back {
            ServerMessage::StreamData { id, payload } => {
                assert_eq!(id, 99);
                assert_eq!(payload, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_stream_close_round_trip() {
        let msg = ServerMessage::StreamClose { id: 13 };
        let back = cbor_round_trip(&msg);
        match back {
            ServerMessage::StreamClose { id } => assert_eq!(id, 13),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn existing_data_variants_still_round_trip() {
        // Guard against accidental tag-shape changes affecting on-wire compat.
        let req = ClientMessage::Data { id: 1, payload: b"hello".to_vec() };
        let back = cbor_round_trip(&req);
        match back {
            ClientMessage::Data { id, payload } => {
                assert_eq!(id, 1);
                assert_eq!(payload, b"hello".to_vec());
            }
            _ => panic!("wrong variant"),
        }

        let resp = ServerMessage::Data { id: 1, payload: b"world".to_vec() };
        let back = cbor_round_trip(&resp);
        match back {
            ServerMessage::Data { id, payload } => {
                assert_eq!(id, 1);
                assert_eq!(payload, b"world".to_vec());
            }
            _ => panic!("wrong variant"),
        }
    }
}
