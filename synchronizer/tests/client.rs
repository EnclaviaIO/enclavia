//! Round-trip tests for the customer client (`client` feature) against
//! an in-process listener (`handle_connection` + single-node `Node`).
//!
//! This is the same responder stack the QEMU cluster runs (minus Raft);
//! the client side is what `nbd-client` ships. The attestation documents
//! are `FakeAttestation`s (debug-mode verifier) on BOTH sides (#208),
//! standing in for the real `/dev/nsm` documents the production parties
//! produce: the client's carries `nonce = handshake_hash` and
//! `user_data = control_pubkey`, the server's carries
//! `nonce = handshake_hash`, which is all each verifier checks.
//!
//! Gated on `test-utils` in addition to `client` + `node`: the server
//! half of the harness is `listener::FakeSessionAttestor`. Run with the
//! CI full-suite feature set (`raft,test-utils,debug,client`).

#![cfg(all(feature = "client", feature = "node", feature = "test-utils"))]

use std::sync::Arc;

use enclavia_protocol::attestation::test_utils::{FakeAttestation, FakeChainAttestation};
use enclavia_protocol::attestation::{CONTROL_PUBKEY_LEN, Pcrs};
use enclavia_protocol::chain::PcrsHex;
use enclavia_protocol::perform_handshake_as_responder;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use synchronizer::client::{ClientError, Handshake, ServerPcrPolicy};
use synchronizer::listener::{FakeSessionAttestor, handle_connection};
use synchronizer::node::Node;
use synchronizer::wire::{
    ChainLink, ChainLinkKind, Frame, MAX_FRAME_SIZE, Request, RpcError, UpgradePayload,
};
use synchronizer::{Commitment, PcrKey, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

/// The PCR seed the in-process listener attests its own sessions with.
const SERVER_SEED: u8 = 0xa5;

fn c(b: u8) -> Commitment {
    Commitment([b; 32])
}

/// Deterministic P-256 keypair; the 65-byte uncompressed SEC1 pubkey is
/// what goes in the NSM doc's `user_data` (the #47 control pubkey slot),
/// the signing key signs transition-link payloads.
fn keypair(seed: u8) -> (SigningKey, [u8; CONTROL_PUBKEY_LEN]) {
    // A reliably-valid, nonzero P-256 scalar: a small big-endian integer
    // (0x01, seed, 0, ...) is always below the curve order.
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
    (sk, pk)
}

/// Deterministic 65-byte uncompressed SEC1 P-256 pubkey for the NSM
/// doc's `user_data` (the #47 control pubkey slot).
fn pubkey(seed: u8) -> [u8; CONTROL_PUBKEY_LEN] {
    keypair(seed).1
}

/// The PcrKey a seed's FakeAttestation binds the session to, matching
/// the listener's `PcrKey(identity.pcrs.digest())` derivation.
fn key_from_seed(seed: u8) -> PcrKey {
    PcrKey(pcrs_from_seed(seed).digest())
}

/// The PCR triple `FakeAttestation::with_seed(seed)` (and
/// `FakeSessionAttestor { seed }`) embeds.
fn pcrs_from_seed(seed: u8) -> Pcrs {
    Pcrs {
        pcr0: vec![seed; 48],
        pcr1: vec![seed.wrapping_add(1); 48],
        pcr2: vec![seed.wrapping_add(2); 48],
    }
}

/// The policy a customer of the in-process listener bakes into its
/// measured config: exactly the listener's [`SERVER_SEED`] PCR triple.
fn server_policy() -> ServerPcrPolicy {
    ServerPcrPolicy::Expected(vec![pcrs_from_seed(SERVER_SEED)])
}

/// Spawn `handle_connection` (debug attestation mode, [`SERVER_SEED`]
/// server attestor) on one half of a duplex pair and return the client
/// half plus the server task handle.
fn spawn_server(
    node: Arc<Node>,
) -> (
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<Result<(), synchronizer::listener::ConnError>>,
) {
    let (client, server) = duplex(64 * 1024);
    let task = tokio::spawn(async move {
        let attestor = FakeSessionAttestor { seed: SERVER_SEED };
        handle_connection(node.as_ref(), &attestor, server, true).await
    });
    (client, task)
}

/// Handshake + mutually authenticate as `seed` against `node`, returning
/// the authenticated client and the session key.
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
    let client = hs
        .authenticate(doc, &server_policy(), true)
        .await
        .expect("mutual authenticate");
    (client, key_from_seed(seed), task)
}

/// Drive `authenticate` and require it to FAIL, returning the error.
/// (`Client` is not `Debug`, so `unwrap_err` cannot be used directly.)
async fn expect_auth_err<S>(hs: Handshake<S>, doc: Vec<u8>, policy: &ServerPcrPolicy) -> ClientError
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match hs.authenticate(doc, policy, true).await {
        Err(e) => e,
        Ok(_) => panic!("expected authentication to be rejected"),
    }
}

/// Happy path: mutual authentication succeeds, then first Pin registers
/// (Version 0), second bumps to 1, Get returns the latest commitment +
/// version.
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

/// The PcrsHex triple `FakeAttestation::with_seed(seed)` measures, in
/// the hex form transition-link payloads carry.
fn pcrs_hex_from_seed(seed: u8) -> PcrsHex {
    PcrsHex {
        pcr0: hex::encode(vec![seed; 48]),
        pcr1: hex::encode(vec![seed.wrapping_add(1); 48]),
        pcr2: hex::encode(vec![seed.wrapping_add(2); 48]),
    }
}

/// Build a #47 upgrade chain link `from_seed -> to_seed`, signed by the
/// OLD enclave's control key and attested for the OLD measurements
/// (mirrors the in-crate listener test fixture).
fn upgrade_link(from_seed: u8, to_seed: u8, signing: &SigningKey) -> ChainLink {
    let payload = UpgradePayload {
        enclave_id: uuid::Uuid::new_v4(),
        from_pcrs: pcrs_hex_from_seed(from_seed),
        to_pcrs: pcrs_hex_from_seed(to_seed),
        image_digest: "sha256:to".into(),
        valid_from: chrono::Utc::now(),
        issued_at: chrono::Utc::now(),
        nonce: vec![0x5a; 32],
    };
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut payload_bytes).unwrap();
    let attestation = FakeChainAttestation::for_payload(from_seed, &payload_bytes).encode();
    let sig: Signature = signing.sign(&payload_bytes);
    ChainLink {
        id: None,
        sequence: None,
        kind: ChainLinkKind::Upgrade,
        payload: payload_bytes,
        attestation,
        signature: Some(sig.to_bytes().to_vec()),
    }
}

/// Seed an OLD enclave's key into the node (attest + Pin), modelling its
/// earlier, now-stopped session, so its control pubkey is frozen.
async fn register_old(node: &Node, seed: u8, control_pubkey: [u8; CONTROL_PUBKEY_LEN]) -> PcrKey {
    let key_old = key_from_seed(seed);
    node.observe_attestation(key_old, control_pubkey).await;
    node.handle_request(
        key_old,
        Request::Pin {
            key: key_old,
            commitment: c(0xee),
        },
    )
    .await;
    key_old
}

/// `Client::transition` round trip (#46 client half): the NEW enclave's
/// authenticated session submits the old-key-signed upgrade link, the
/// oracle retires the old key and the migrated pin reads back under the
/// new key with commitment + version carried forward.
#[tokio::test]
async fn transition_migrates_pin_to_new_key() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (sk_old, pk_old) = keypair(0x50);
    register_old(&node, 0x50, pk_old).await;

    let (mut client, new_key, _task) = connect_as(Arc::clone(&node), 0x60).await;
    let link = upgrade_link(0x50, 0x60, &sk_old);
    let version = client.transition(link).await.expect("transition");
    assert_eq!(version, Version(0), "carried-over version");

    let (commitment, version) = client.get(new_key).await.expect("get after transition");
    assert_eq!(commitment, c(0xee));
    assert_eq!(version, Version(0));
}

/// A link the oracle cannot verify (signed by a key other than the one
/// frozen for old_key) surfaces as the structured TransitionRejected,
/// which the nbd-client boot verifier folds into its fail-stop message.
#[tokio::test]
async fn rejected_transition_surfaces_as_rpc_error() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (_sk_real, pk_real) = keypair(0x51);
    let (sk_attacker, _) = keypair(0x52);
    register_old(&node, 0x51, pk_real).await;

    let (mut client, _new_key, _task) = connect_as(Arc::clone(&node), 0x61).await;
    let link = upgrade_link(0x51, 0x61, &sk_attacker);
    let err = client.transition(link).await.unwrap_err();
    assert!(
        matches!(err, ClientError::Rpc(RpcError::TransitionRejected)),
        "{err:?}"
    );
}

/// An attestation document the server rejects (garbage bytes) tears the
/// connection down before the server ever attests back; the client
/// surfaces it as ConnectionClosed from `authenticate` rather than
/// hanging.
#[tokio::test]
async fn rejected_attestation_surfaces_as_connection_closed() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (stream, task) = spawn_server(node);
    let hs = Handshake::start(stream).await.expect("noise handshake");
    let err = expect_auth_err(hs, vec![0xde, 0xad, 0xbe, 0xef], &server_policy()).await;
    assert!(matches!(err, ClientError::ConnectionClosed), "{err:?}");

    let result = task.await.unwrap();
    assert!(result.is_err(), "server must reject the bogus doc");
}

/// A document bound to the WRONG handshake hash (a replayed capture) is
/// rejected by the listener's nonce binding, again before any server
/// attestation is sent.
#[tokio::test]
async fn replayed_attestation_is_rejected() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (stream, task) = spawn_server(node);
    let hs = Handshake::start(stream).await.expect("noise handshake");
    // Document minted for some OTHER session's handshake hash.
    let doc = FakeAttestation::with_seed_and_pubkey(0x47, vec![0xab; 32], pubkey(0x47)).encode();
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ConnectionClosed), "{err:?}");

    let result = task.await.unwrap();
    assert!(result.is_err(), "server must reject the replayed doc");
}

// ---------------------------------------------------------------------------
// Server-side attestation (#208): the client verifying the oracle.
// ---------------------------------------------------------------------------

/// A server whose verified PCRs are NOT the expected synchronizer
/// measurements is rejected by the client's policy. Models a malicious
/// host fronting a rogue image (or reflecting some other enclave's
/// channel-bound document) as the oracle.
#[tokio::test]
async fn wrong_server_pcrs_are_rejected() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (client_stream, _task) = spawn_server(node);
    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x48, hs.handshake_hash().to_vec(), pubkey(0x48))
            .encode();
    // Expect measurements the listener does NOT have.
    let wrong_policy = ServerPcrPolicy::Expected(vec![pcrs_from_seed(0x99)]);
    let err = expect_auth_err(hs, doc, &wrong_policy).await;
    assert!(matches!(err, ClientError::ServerPcrRejected), "{err:?}");
}

/// An EMPTY expected-PCR set admits no server at all: fail-stop, never
/// fail-open.
#[tokio::test]
async fn empty_server_policy_rejects_the_real_oracle() {
    let node = Arc::new(Node::with_debug_mode(true));
    let (client_stream, _task) = spawn_server(node);
    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x49, hs.handshake_hash().to_vec(), pubkey(0x49))
            .encode();
    let err = expect_auth_err(hs, doc, &ServerPcrPolicy::Expected(Vec::new())).await;
    assert!(matches!(err, ClientError::ServerPcrRejected), "{err:?}");
}

/// The reflection attack the PCR policy must close: a host that
/// terminated the customer's session holds exactly ONE document bound to
/// its handshake hash, the customer's own Authenticate. Reflecting it
/// back as the "server's" attestation passes the nonce binding but
/// carries the CUSTOMER's PCRs, so the policy rejects it.
#[tokio::test]
async fn reflected_client_document_is_rejected() {
    let (client_stream, server_stream) = duplex(64 * 1024);

    // The "malicious host": a raw responder that verifies nothing and
    // echoes the client's Authenticate frame straight back.
    let host = tokio::spawn(async move {
        let mut stream = server_stream;
        let (mut transport, _hash) = perform_handshake_as_responder(&mut stream).await.unwrap();
        // Read the client's Authenticate frame.
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let mut ciphertext = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
        stream.read_exact(&mut ciphertext).await.unwrap();
        let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
        let pt_len = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        // Reflect the identical frame back as the "server" Authenticate.
        let mut out_ct = vec![0u8; MAX_FRAME_SIZE as usize];
        let ct_len = transport
            .write_message(&plaintext[..pt_len], &mut out_ct)
            .unwrap();
        stream
            .write_all(&(ct_len as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&out_ct[..ct_len]).await.unwrap();
        stream.flush().await.unwrap();
    });

    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x4a, hs.handshake_hash().to_vec(), pubkey(0x4a))
            .encode();
    // The customer's own PCRs (0x4a) are NOT the synchronizer's
    // (SERVER_SEED), so the reflected doc must be rejected.
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ServerPcrRejected), "{err:?}");
    host.await.unwrap();
}

/// Helper: a scripted fake "server" that responds to the client's
/// Authenticate with arbitrary caller-chosen plaintext frame bytes.
async fn scripted_server(
    mut stream: tokio::io::DuplexStream,
    respond: impl FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
) {
    let (mut transport, hash) = perform_handshake_as_responder(&mut stream).await.unwrap();
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.unwrap();
    let mut ciphertext = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
    stream.read_exact(&mut ciphertext).await.unwrap();
    let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
    let _ = transport.read_message(&ciphertext, &mut plaintext).unwrap();

    let reply_plaintext = respond(&hash);
    let mut out_ct = vec![0u8; MAX_FRAME_SIZE as usize];
    let ct_len = transport
        .write_message(&reply_plaintext, &mut out_ct)
        .unwrap();
    stream
        .write_all(&(ct_len as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&out_ct[..ct_len]).await.unwrap();
    stream.flush().await.unwrap();
}

fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(frame, &mut buf).unwrap();
    buf
}

/// A "server" answering with garbled attestation bytes is rejected.
#[tokio::test]
async fn garbled_server_attestation_is_rejected() {
    let (client_stream, server_stream) = duplex(64 * 1024);
    let host = tokio::spawn(scripted_server(server_stream, |_hash| {
        encode_frame(&Frame::Authenticate {
            nsm_doc: vec![0xde, 0xad, 0xbe, 0xef],
        })
    }));

    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x4b, hs.handshake_hash().to_vec(), pubkey(0x4b))
            .encode();
    // Policy is irrelevant: garbage is rejected at the document parse
    // stage, before any PCR comparison.
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ServerAttestation(_)), "{err:?}");
    host.await.unwrap();
}

/// A "server" replaying a document bound to a DIFFERENT session's
/// handshake hash is rejected by the nonce binding, even when its PCRs
/// would satisfy the policy.
#[tokio::test]
async fn replayed_server_attestation_is_rejected() {
    let (client_stream, server_stream) = duplex(64 * 1024);
    let host = tokio::spawn(scripted_server(server_stream, |_hash| {
        // Bound to some other session, NOT the live hash.
        encode_frame(&Frame::Authenticate {
            nsm_doc: FakeAttestation::with_seed(SERVER_SEED, vec![0xab; 32]).encode(),
        })
    }));

    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x4c, hs.handshake_hash().to_vec(), pubkey(0x4c))
            .encode();
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ServerAttestation(_)), "{err:?}");
    host.await.unwrap();
}

/// A "server" whose first frame is not an Authenticate (it skips
/// straight to answering RPCs) is rejected: the mutual-auth step is
/// mandatory, not skippable by the far end.
#[tokio::test]
async fn server_skipping_its_attestation_is_rejected() {
    let (client_stream, server_stream) = duplex(64 * 1024);
    let host = tokio::spawn(scripted_server(server_stream, |_hash| {
        encode_frame(&Frame::Rpc {
            request: synchronizer::wire::Request::Get {
                key: PcrKey([0u8; 32]),
            },
        })
    }));

    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x4d, hs.handshake_hash().to_vec(), pubkey(0x4d))
            .encode();
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ServerAuthMissing), "{err:?}");
    host.await.unwrap();
}

/// A "server" that closes the stream instead of attesting back surfaces
/// as ConnectionClosed, never as an authenticated session.
#[tokio::test]
async fn server_closing_instead_of_attesting_is_rejected() {
    let (client_stream, server_stream) = duplex(64 * 1024);
    let host = tokio::spawn(async move {
        let mut stream = server_stream;
        let (mut transport, _hash) = perform_handshake_as_responder(&mut stream).await.unwrap();
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let mut ciphertext = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
        stream.read_exact(&mut ciphertext).await.unwrap();
        let mut plaintext = vec![0u8; MAX_FRAME_SIZE as usize];
        let _ = transport.read_message(&ciphertext, &mut plaintext).unwrap();
        // Hang up without attesting back.
        drop(stream);
    });

    let hs = Handshake::start(client_stream)
        .await
        .expect("noise handshake");
    let doc =
        FakeAttestation::with_seed_and_pubkey(0x4e, hs.handshake_hash().to_vec(), pubkey(0x4e))
            .encode();
    let err = expect_auth_err(hs, doc, &server_policy()).await;
    assert!(matches!(err, ClientError::ConnectionClosed), "{err:?}");
    host.await.unwrap();
}
