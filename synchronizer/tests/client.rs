//! Round-trip tests for the customer client (`client` feature) against
//! an in-process listener (`handle_connection` + single-node `Node`).
//!
//! This is the same responder stack the QEMU cluster runs (minus Raft);
//! the client side is what `nbd-client` ships. The attestation document
//! is a `FakeAttestation` (debug-mode verifier), standing in for the
//! real `/dev/nsm` document the production caller produces: both carry
//! `nonce = handshake_hash` and `user_data = control_pubkey`, which is
//! all the listener checks.

#![cfg(all(feature = "client", feature = "node"))]

use std::sync::Arc;

use enclavia_protocol::attestation::{CONTROL_PUBKEY_LEN, Pcrs, test_utils::FakeAttestation};
use p256::ecdsa::SigningKey;
use synchronizer::client::{ClientError, Handshake};
use synchronizer::listener::handle_connection;
use synchronizer::node::Node;
use synchronizer::wire::RpcError;
use synchronizer::{Commitment, PcrKey, Version};
use tokio::io::duplex;

fn c(b: u8) -> Commitment {
    Commitment([b; 32])
}

/// Deterministic 65-byte uncompressed SEC1 P-256 pubkey for the NSM
/// doc's `user_data` (the #47 control pubkey slot).
fn pubkey(seed: u8) -> [u8; CONTROL_PUBKEY_LEN] {
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
    pk
}

/// The PcrKey a seed's FakeAttestation binds the session to, matching
/// the listener's `PcrKey(identity.pcrs.digest())` derivation.
fn key_from_seed(seed: u8) -> PcrKey {
    let raw = Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    };
    PcrKey(raw.digest())
}

/// Spawn `handle_connection` (debug attestation mode) on one half of a
/// duplex pair and return the client half plus the server task handle.
fn spawn_server(
    node: Arc<Node>,
) -> (
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<Result<(), synchronizer::listener::ConnError>>,
) {
    let (client, server) = duplex(64 * 1024);
    let task = tokio::spawn(async move { handle_connection(node.as_ref(), server, true).await });
    (client, task)
}

/// Handshake + authenticate as `seed` against `node`, returning the
/// authenticated client and the session key.
async fn connect_as(
    node: Arc<Node>,
    seed: u8,
) -> (
    synchronizer::client::Client<tokio::io::DuplexStream>,
    PcrKey,
    tokio::task::JoinHandle<Result<(), synchronizer::listener::ConnError>>,
) {
    let (stream, task) = spawn_server(node);
    let hs = Handshake::start(stream).await.expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(seed, hs.handshake_hash().to_vec(), pubkey(seed))
            .encode();
    let client = hs.authenticate(doc).await.expect("authenticate");
    (client, key_from_seed(seed), task)
}

/// Happy path: first Pin registers (Version 0), second bumps to 1, Get
/// returns the latest commitment + version.
#[tokio::test]
async fn pin_register_then_bump_then_get() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (mut client, key, task) = connect_as(node, 0x42).await;

    let v0 = client.pin(key, c(0xaa)).await.expect("first pin");
    assert_eq!(v0, Version(0), "first pin must be the registration");

    let v1 = client.pin(key, c(0xbb)).await.expect("second pin");
    assert_eq!(v1, Version(1));

    let (commitment, version) = client.get(key).await.expect("get");
    assert_eq!(commitment, c(0xbb));
    assert_eq!(version, Version(1));

    drop(client);
    let result = task.await.unwrap();
    assert!(result.is_ok(), "{result:?}");
}

/// Get before any Pin surfaces the structured NotFound error, which the
/// nbd-client boot verifier branches on (fresh device vs rollback).
#[tokio::test]
async fn get_unregistered_key_is_not_found() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (mut client, key, _task) = connect_as(node, 0x43).await;

    let err = client.get(key).await.unwrap_err();
    assert!(
        matches!(err, ClientError::Rpc(RpcError::NotFound)),
        "{err:?}"
    );
}

/// A request naming a key other than the session's attested key is
/// rejected by the server's session binding.
#[tokio::test]
async fn cross_key_pin_is_unauthorized() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (mut client, _key, _task) = connect_as(node, 0x44).await;

    let other = PcrKey([0u8; 32]);
    let err = client.pin(other, c(0x01)).await.unwrap_err();
    assert!(
        matches!(err, ClientError::Rpc(RpcError::Unauthorized)),
        "{err:?}"
    );
}

/// State persists across sessions on the same node: a second connection
/// authenticated as the same PCR seed reads the first session's pin.
#[tokio::test]
async fn second_session_reads_first_sessions_pin() {
    let node = Arc::new(Node::with_debug_mode(true));

    let (mut client, key, _task) = connect_as(Arc::clone(&node), 0x45).await;
    client.pin(key, c(0xcd)).await.expect("pin");
    drop(client);

    let (mut client2, key2, _task2) = connect_as(node, 0x45).await;
    assert_eq!(key, key2);
    let (commitment, version) = client2.get(key2).await.expect("get");
    assert_eq!(commitment, c(0xcd));
    assert_eq!(version, Version(0));
}

/// An attestation document the server rejects (garbage bytes) tears the
/// connection down; the client surfaces it as ConnectionClosed on the
/// first RPC rather than hanging.
#[tokio::test]
async fn rejected_attestation_surfaces_as_connection_closed() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (stream, task) = spawn_server(node);
    let hs = Handshake::start(stream).await.expect("noise handshake");
    let mut client = hs
        .authenticate(vec![0xde, 0xad, 0xbe, 0xef])
        .await
        .expect("authenticate frame write");

    let err = client.get(key_from_seed(0x46)).await.unwrap_err();
    assert!(matches!(err, ClientError::ConnectionClosed), "{err:?}");

    let result = task.await.unwrap();
    assert!(result.is_err(), "server must reject the bogus doc");
}

/// A document bound to the WRONG handshake hash (a replayed capture) is
/// rejected by the listener's nonce binding.
#[tokio::test]
async fn replayed_attestation_is_rejected() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (stream, task) = spawn_server(node);
    let hs = Handshake::start(stream).await.expect("noise handshake");
    // Document minted for some OTHER session's handshake hash.
    let doc = FakeAttestation::with_seed_and_pubkey(0x47, vec![0xab; 32], pubkey(0x47)).encode();
    let mut client = hs
        .authenticate(doc)
        .await
        .expect("authenticate frame write");

    let err = client.get(key_from_seed(0x47)).await.unwrap_err();
    assert!(matches!(err, ClientError::ConnectionClosed), "{err:?}");

    let result = task.await.unwrap();
    assert!(result.is_err(), "server must reject the replayed doc");
}
