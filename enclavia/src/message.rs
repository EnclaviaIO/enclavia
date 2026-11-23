use serde::{Deserialize, Serialize};

pub(crate) const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// Which halves of an open stream to close. Wire-compatible with
/// `enclavia_protocol::StreamHalf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StreamHalf {
    Write,
    Both,
}

/// Messages sent from the client to the enclave server. Wire-compatible with
/// `enclavia_protocol::ClientMessage` in the enclavia-server workspace.
///
/// Byte fields are serialized as CBOR arrays of integers: the server decodes
/// these internally tagged enums through serde's buffered representation, in
/// which a plain `Vec<u8>` field only accepts an array, not a byte string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum ClientMessage {
    RequestAttestation,
    Control { payload: Vec<u8>, signature: Vec<u8> },
    OpenStream { id: u64, payload: Vec<u8> },
    StreamData { id: u64, payload: Vec<u8> },
    StreamClose { id: u64, half: StreamHalf },
}

/// Messages sent from the enclave server to the client. Byte fields accept
/// either a CBOR array of integers or a CBOR byte string, so the client
/// reads both encodings a server may use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum ServerMessage {
    Attestation {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        control_nonce: [u8; 32],
    },
    Error { id: u64, message: String },
    ControlResult { success: bool, message: String },
    StreamData {
        id: u64,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
    StreamClose { id: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    /// The server (`enclavia_protocol`) must be able to decode what the SDK
    /// sends.
    #[test]
    fn server_decodes_client_stream_messages() {
        let payload: Vec<u8> = (0..=255).collect();
        let bytes = to_cbor(&ClientMessage::OpenStream { id: 3, payload: payload.clone() });
        match ciborium::from_reader(bytes.as_slice()).unwrap() {
            enclavia_protocol::ClientMessage::OpenStream { id, payload: got } => {
                assert_eq!(id, 3);
                assert_eq!(got, payload);
            }
            other => panic!("wrong variant {other:?}"),
        }
    }

    /// The SDK reads stream payloads whether the server encodes bytes as an
    /// array of integers or as a byte string.
    #[test]
    fn client_decodes_both_byte_encodings() {
        let payload: Vec<u8> = (0..=255).collect();

        let as_array = to_cbor(&enclavia_protocol::ServerMessage::StreamData {
            id: 9,
            payload: payload.clone(),
        });
        let as_bstr = to_cbor(&ServerMessage::StreamData { id: 9, payload: payload.clone() });
        assert!(as_bstr.len() < as_array.len());

        for bytes in [as_array, as_bstr] {
            match ciborium::from_reader(bytes.as_slice()).unwrap() {
                ServerMessage::StreamData { id, payload: got } => {
                    assert_eq!(id, 9);
                    assert_eq!(got, payload);
                }
                other => panic!("wrong variant {other:?}"),
            }
        }
    }
}
