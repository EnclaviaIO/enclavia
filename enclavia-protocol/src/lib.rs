pub mod attestation;
pub mod chain;
#[cfg(feature = "async-transport")]
pub mod egress;
#[cfg(feature = "async-transport")]
pub mod mesh;
mod noise;
pub mod staging;

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
    /// `ControlCommand`; `signature` is a P-256 ECDSA raw r||s 64-byte
    /// signature over `payload` produced with the enclave's control private
    /// key. The server verifies the signature against the control public key
    /// baked into the EIF and the embedded nonce against its current
    /// single-use nonce.
    Control {
        payload: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Fetch the current single-use control nonce without consuming it.
    /// Answered by [`ServerMessage::ControlNonce`]. The nonce is only
    /// consumed when a full `Control` message is processed (success OR
    /// failure). Use this to learn the nonce before constructing a signed
    /// `ControlCommand` to embed in it.
    GetControlNonce,

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

    /// Response to [`ClientMessage::GetControlNonce`]. Returns the current
    /// single-use nonce. Unauthenticated: the nonce is not secret, only
    /// anti-replay. The nonce is NOT consumed by this fetch; it is only
    /// consumed when the server processes a full `Control` message (success
    /// or failure). The backend must fetch the nonce and then immediately
    /// send its signed `Control` without any intervening messages from
    /// another client that might rotate the nonce.
    ControlNonce { nonce: [u8; 32] },

    /// Raw bytes received from the inner container (typically an HTTP response).
    /// The `id` matches the corresponding `ClientMessage::Data` request.
    Data { id: u64, payload: Vec<u8> },

    /// Error forwarding to the inner container.
    Error { id: u64, message: String },

    /// Result of a `Control` command. The control nonce was rotated whether
    /// or not the command succeeded — the next signed command must use the
    /// new nonce, fetched via a fresh `GetControlNonce` or
    /// `RequestAttestation`.
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

/// Storage re-key parameters for a `PrepareUpgrade` control command. Only
/// provided for enclaves that have a persistent LUKS-backed storage volume;
/// `None` for stateless enclaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyParams {
    /// DER-encoded SubjectPublicKeyInfo of the new RSA-OAEP KMS key.
    /// The enclave wraps a freshly-generated passphrase under this key and
    /// stores the ciphertext in the key blob alongside `new_key_id`.
    pub new_public_key: Vec<u8>,
    /// Identifier of the new KMS key (ARN, mock-kms id, etc.). Recorded in
    /// the key blob so the post-upgrade enclave decrypts via the right key.
    pub new_key_id: String,
}

/// Inner payload of a signed control command. Serialized as CBOR before
/// signing — the wire-level signature covers the exact bytes the verifier
/// then deserializes, so re-encoding skew can't break verification.
///
/// # Wire-stability note
///
/// `PrepareUpgrade` was redesigned for issue #47. There were no live senders
/// of the previous shape (`new_public_key / new_key_id / nonce`), so the
/// wire change is safe. The new shape carries the chain artifact inline so
/// the enclave can emit the chain link as part of the same atomic operation
/// as the storage re-key, before replying to the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum ControlCommand {
    /// Staged-upgrade confirmation. The enclave verifies the envelope
    /// signature, optionally re-keys storage, emits a chain `Upgrade` link to
    /// `chain-host`, and replies success.
    PrepareUpgrade {
        /// CBOR-encoded [`chain::UpgradePayload`]. Becomes the `payload` field
        /// of the chain link verbatim; the enclave must not re-encode it.
        payload: Vec<u8>,
        /// 64-byte raw r||s ECDSA P-256 signature over `payload` under the
        /// enclave's control private key. Becomes the `signature` field of
        /// the chain link. The enclave MAY also verify this against its own
        /// control public key as defence-in-depth (same key signs both the
        /// envelope and the chain payload).
        payload_signature: Vec<u8>,
        /// Storage re-key parameters. `None` for stateless enclaves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rekey: Option<RekeyParams>,
        /// Single-use per-boot nonce, must equal the server's current nonce.
        /// Prevents replay across boots without relying on clocks.
        nonce: [u8; 32],
    },

    /// Pre-activation revocation. The enclave verifies the envelope
    /// signature, optionally rolls back the LUKS keyslot added at
    /// `PrepareUpgrade` time, emits a chain `Revocation` link to
    /// `chain-host`, and replies success.
    RevokeUpgrade {
        /// CBOR-encoded [`chain::RevocationPayload`]. Becomes the `payload`
        /// field of the chain link verbatim.
        payload: Vec<u8>,
        /// 64-byte raw r||s ECDSA P-256 signature over `payload`. Becomes the
        /// chain link signature.
        payload_signature: Vec<u8>,
        /// When `true`, the enclave runs `enclavia-crypto revoke-upgrade` to
        /// kill the LUKS keyslot added at prepare time and restore the key
        /// blob to its pre-prepare state. `false` for stateless enclaves.
        rollback: bool,
        /// Single-use per-boot nonce.
        nonce: [u8; 32],
    },
}

/// Shared helper: write a length-prefixed CBOR `ChainLink` to a generic
/// async stream and wait for the one-byte `0x06` ACK from `chain-host`.
///
/// Wire format (matches `chain-host/src/main.rs` and `enclavia-chain-init`):
/// ```text
///   [u32 BE length] [CBOR-encoded ChainLink bytes]
/// ```
/// After writing, the helper calls `shutdown(WRITE)` then reads exactly one
/// byte. The byte is expected to be `ACK_BYTE` (`0x06`); any other value is
/// logged (as a warning by the caller) but not treated as an error since the
/// link bytes already landed in chain-host's buffer.
///
/// Large links (rare; chain attestations are ~5 KiB) are safe because the
/// write is split into the 4-byte length header and then the body; both are
/// well under the ~32 KiB per-write vsock limit documented in CLAUDE.md.
///
/// Returns `Ok(ack_byte)` on success, `Err` on I/O failure or ACK timeout.
#[cfg(feature = "async-transport")]
pub async fn submit_chain_link<S>(
    stream: &mut S,
    link: &chain::ChainLink,
    ack_timeout: std::time::Duration,
) -> Result<u8, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut link_bytes = Vec::with_capacity(1024);
    ciborium::ser::into_writer(link, &mut link_bytes)?;

    let len: u32 = link_bytes
        .len()
        .try_into()
        .map_err(|_| "chain link too large to encode as u32-prefixed frame")?;

    // Write the 4-byte length header then the body in two separate calls.
    // Each call is well under the ~32 KiB vsock single-write limit.
    stream.write_all(&len.to_be_bytes()).await?;

    // Chunk body writes at 32 KiB to stay within the vsock per-write limit.
    const VSOCK_CHUNK: usize = 32 * 1024;
    for chunk in link_bytes.chunks(VSOCK_CHUNK) {
        stream.write_all(chunk).await?;
    }

    stream.shutdown().await?;

    // Wait for the explicit ACK byte from chain-host.
    let mut ack = [0u8; 1];
    tokio::time::timeout(ack_timeout, stream.read_exact(&mut ack)).await??;
    Ok(ack[0])
}

/// The ACK byte `chain-host` sends after accepting a chain link.
/// Value `0x06` (ASCII ACK). Must match `chain-host/src/main.rs` constant.
pub const CHAIN_LINK_ACK: u8 = 0x06;

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
        let msg = ClientMessage::StreamData {
            id: 42,
            payload: vec![1, 2, 3, 4, 5],
        };
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
        let msg = ServerMessage::StreamData {
            id: 99,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
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
        let req = ClientMessage::Data {
            id: 1,
            payload: b"hello".to_vec(),
        };
        let back = cbor_round_trip(&req);
        match back {
            ClientMessage::Data { id, payload } => {
                assert_eq!(id, 1);
                assert_eq!(payload, b"hello".to_vec());
            }
            _ => panic!("wrong variant"),
        }

        let resp = ServerMessage::Data {
            id: 1,
            payload: b"world".to_vec(),
        };
        let back = cbor_round_trip(&resp);
        match back {
            ServerMessage::Data { id, payload } => {
                assert_eq!(id, 1);
                assert_eq!(payload, b"world".to_vec());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn prepare_upgrade_round_trip() {
        let cmd = ControlCommand::PrepareUpgrade {
            payload: vec![1, 2, 3],
            payload_signature: vec![0xde; 64],
            rekey: Some(RekeyParams {
                new_public_key: vec![0xAB; 32],
                new_key_id: "arn:aws:kms:us-east-1:123:key/abc".into(),
            }),
            nonce: [0x42u8; 32],
        };
        let back: ControlCommand = cbor_round_trip(&cmd);
        match back {
            ControlCommand::PrepareUpgrade {
                payload,
                payload_signature,
                rekey,
                nonce,
            } => {
                assert_eq!(payload, vec![1, 2, 3]);
                assert_eq!(payload_signature, vec![0xde; 64]);
                let rk = rekey.expect("rekey should be Some");
                assert_eq!(rk.new_public_key, vec![0xAB; 32]);
                assert_eq!(rk.new_key_id, "arn:aws:kms:us-east-1:123:key/abc");
                assert_eq!(nonce, [0x42u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn prepare_upgrade_stateless_round_trip() {
        let cmd = ControlCommand::PrepareUpgrade {
            payload: vec![0xAA],
            payload_signature: vec![0xBB; 64],
            rekey: None,
            nonce: [0x01u8; 32],
        };
        let back: ControlCommand = cbor_round_trip(&cmd);
        match back {
            ControlCommand::PrepareUpgrade { rekey, .. } => {
                assert!(rekey.is_none(), "stateless: rekey should be None");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn revoke_upgrade_round_trip() {
        let cmd = ControlCommand::RevokeUpgrade {
            payload: vec![0xCC; 8],
            payload_signature: vec![0xDD; 64],
            rollback: true,
            nonce: [0x99u8; 32],
        };
        let back: ControlCommand = cbor_round_trip(&cmd);
        match back {
            ControlCommand::RevokeUpgrade {
                payload,
                payload_signature,
                rollback,
                nonce,
            } => {
                assert_eq!(payload, vec![0xCC; 8]);
                assert_eq!(payload_signature, vec![0xDD; 64]);
                assert!(rollback);
                assert_eq!(nonce, [0x99u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn get_control_nonce_round_trip() {
        let msg = ClientMessage::GetControlNonce;
        let back = cbor_round_trip(&msg);
        assert!(matches!(back, ClientMessage::GetControlNonce));
    }

    #[test]
    fn server_control_nonce_round_trip() {
        let nonce = [0x77u8; 32];
        let msg = ServerMessage::ControlNonce { nonce };
        let back = cbor_round_trip(&msg);
        match back {
            ServerMessage::ControlNonce { nonce: got } => assert_eq!(got, nonce),
            _ => panic!("wrong variant"),
        }
    }

    /// Exact JSON field-name shape lock for `ControlCommand::PrepareUpgrade`.
    /// Changing any of these names is a wire break; update the test AND add
    /// a migration note.
    #[test]
    fn prepare_upgrade_json_field_names() {
        let cmd = ControlCommand::PrepareUpgrade {
            payload: vec![1],
            payload_signature: vec![2; 64],
            rekey: Some(RekeyParams {
                new_public_key: vec![3],
                new_key_id: "k1".into(),
            }),
            nonce: [0u8; 32],
        };
        // Use JSON (not CBOR) for readable field-name assertions.
        let v = serde_json::to_value(&cmd).unwrap();
        assert_eq!(v["command"], "PrepareUpgrade");
        assert!(v.get("payload").is_some());
        assert!(v.get("payload_signature").is_some());
        assert!(v.get("rekey").is_some());
        assert_eq!(v["rekey"]["new_key_id"], "k1");
        assert!(v.get("nonce").is_some());
    }

    #[test]
    fn revoke_upgrade_json_field_names() {
        let cmd = ControlCommand::RevokeUpgrade {
            payload: vec![1],
            payload_signature: vec![2; 64],
            rollback: false,
            nonce: [0u8; 32],
        };
        let v = serde_json::to_value(&cmd).unwrap();
        assert_eq!(v["command"], "RevokeUpgrade");
        assert!(v.get("payload").is_some());
        assert!(v.get("payload_signature").is_some());
        assert_eq!(v["rollback"], false);
        assert!(v.get("nonce").is_some());
    }
}
