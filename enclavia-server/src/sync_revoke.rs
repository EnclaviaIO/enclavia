//! Commit an upgrade revocation to the synchronizer.
//!
//! An upgrade link is a bearer credential: whoever holds it can present it to
//! the synchronizer once its `valid_from` has passed and move this enclave's
//! pinned storage to the new image. Revoking the upgrade here (restoring the
//! LUKS keyslot, emitting the chain link) does not stop that on its own, since
//! the host keeps a copy of the link. So when this enclave pins its storage to
//! the synchronizer, the revocation is committed THERE first, and the revoke
//! command only succeeds once the synchronizer acknowledged it.
//!
//! The session is our own: this process dials the synchronizer relay, attests
//! as this enclave (so the session key is the key that holds the pin), and
//! verifies the synchronizer's attestation against the measured config, exactly
//! like nbd-client. A synchronizer that does not advertise the `revocation`
//! capability would accept nothing and enforce nothing, so that is an error,
//! never a silent skip.

use std::future::Future;
use std::time::Duration;

use enclavia_protocol::chain::ChainLink;
use synchronizer::client::{Client, ClientError, Handshake, ServerPcrPolicy};
use synchronizer::wire::{CAPABILITY_REVOCATION, RpcError};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use crate::config::SynchronizerTrust;

/// Bound on the vsock connect to the synchronizer relay.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the session setup (handshake and mutual attestation) and on each
/// RPC. The synchronizer answers a write within its own commit timeout (5 s)
/// or its routing deadline (10 s), so this only fires on a dead session.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the revocation keeps being re-submitted while the synchronizer
/// answers `Unavailable` (no quorum right now) or the session drops. The
/// revoke command is dispatched by the backend and retried by the operator on
/// failure, so this only rides out an election or a node restart; after it the
/// command fails and nothing is reported as revoked.
const RETRY_BUDGET: Duration = Duration::from_secs(60);

/// Pause between attempts.
const RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// How one attempt ended, when it did not commit the revocation.
#[derive(Debug)]
pub enum Failure {
    /// Trying again cannot change the answer.
    Fatal(String),
    /// The session dropped or the synchronizer had no quorum: try again.
    Retry(String),
}

/// Commit `link` (the revocation chain link this enclave is about to emit) to
/// the synchronizer over a fresh vsock session attested with this enclave's
/// NSM. `control_pubkey` goes into the attestation's `user_data`, as in every
/// synchronizer session this enclave opens.
///
/// Retries `Unavailable` and dropped sessions for [`RETRY_BUDGET`]: a
/// revocation is idempotent (it only adds a hash to a set), so resubmitting one
/// whose earlier attempt committed changes nothing.
pub async fn commit_revocation(
    trust: &SynchronizerTrust,
    control_pubkey: [u8; 65],
    link: &ChainLink,
) -> Result<(), String> {
    let policy = ServerPcrPolicy::Expected(trust.expected_pcrs.clone());
    let deadline = tokio::time::Instant::now() + RETRY_BUDGET;
    loop {
        let attempt = async {
            let stream = dial_relay().await.map_err(Failure::Retry)?;
            let mut client = open_session(stream, &policy, trust.debug_attestation, |hash| {
                nsm_attest(hash, control_pubkey)
            })
            .await?;
            revoke_on(&mut client, link).await
        };
        let err = match attempt.await {
            Ok(()) => {
                info!("revocation committed to the synchronizer");
                return Ok(());
            }
            Err(Failure::Fatal(msg)) => return Err(msg),
            Err(Failure::Retry(msg)) => msg,
        };
        if tokio::time::Instant::now() + RETRY_BACKOFF >= deadline {
            return Err(format!(
                "synchronizer did not commit the revocation within {RETRY_BUDGET:?}: {err}"
            ));
        }
        warn!(error = %err, "revocation not committed yet; retrying");
        tokio::time::sleep(RETRY_BACKOFF).await;
    }
}

/// Dial the host-side synchronizer relay, the same port nbd-client uses.
async fn dial_relay() -> Result<tokio_vsock::VsockStream, String> {
    let port = enclavia_protocol::mesh::SYNCHRONIZER_CUSTOMER_RELAY_PORT;
    let cid = enclavia_vsock::host_cid().await;
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("synchronizer relay vsock {cid}:{port}: {e}")),
        Err(_) => Err(format!("synchronizer relay vsock {cid}:{port}: connect timed out")),
    }
}

/// One NSM document bound to the session (`nonce = handshake hash`) with the
/// control pubkey as `user_data`.
async fn nsm_attest(handshake_hash: Vec<u8>, control_pubkey: [u8; 65]) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || {
        crate::attestation::session_attestation(&handshake_hash, &control_pubkey)
            .map_err(|e| format!("NSM attestation for the synchronizer session: {e}"))
    })
    .await
    .map_err(|e| format!("NSM attestation task failed: {e}"))?
}

/// Noise handshake plus mutual attestation over `stream`: `attest` produces
/// our document for the handshake hash, and the synchronizer's document must
/// match `policy`.
pub async fn open_session<S, F, Fut>(
    stream: S,
    policy: &ServerPcrPolicy,
    debug_attestation: bool,
    attest: F,
) -> Result<Client<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    let setup = async {
        let hs = Handshake::start(stream)
            .await
            .map_err(|e| Failure::Retry(format!("synchronizer handshake: {e}")))?;
        let doc = attest(hs.handshake_hash().to_vec())
            .await
            .map_err(Failure::Fatal)?;
        hs.authenticate(doc, policy, debug_attestation)
            .await
            .map_err(|e| match e {
                ClientError::Io(_) | ClientError::ConnectionClosed => {
                    Failure::Retry(format!("synchronizer session setup: {e}"))
                }
                other => Failure::Fatal(format!(
                    "synchronizer session authentication failed: {other}"
                )),
            })
    };
    tokio::time::timeout(RPC_TIMEOUT, setup)
        .await
        .map_err(|_| Failure::Retry("synchronizer session setup timed out".into()))?
}

/// Submit the revocation on an authenticated session.
pub async fn revoke_on<S>(client: &mut Client<S>, link: &ChainLink) -> Result<(), Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(RPC_TIMEOUT, client.revoke(link.clone())).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(ClientError::MissingCapability(_))) => Err(Failure::Fatal(format!(
            "the synchronizer does not advertise `{CAPABILITY_REVOCATION}`, so it would not \
             enforce this revocation; refusing to report the upgrade as revoked"
        ))),
        // No quorum right now. The outcome of a timed-out attempt is
        // unknown, which is fine: resubmitting a revocation is idempotent.
        Ok(Err(ClientError::Rpc(RpcError::Unavailable))) => Err(Failure::Retry(
            "the synchronizer has no quorum right now (Unavailable)".into(),
        )),
        Ok(Err(ClientError::Rpc(e))) => Err(Failure::Fatal(format!(
            "the synchronizer rejected the revocation: {e}"
        ))),
        Ok(Err(e @ (ClientError::Io(_) | ClientError::ConnectionClosed))) => {
            Err(Failure::Retry(format!("synchronizer session dropped: {e}")))
        }
        Ok(Err(e)) => Err(Failure::Fatal(format!("synchronizer revoke failed: {e}"))),
        Err(_) => Err(Failure::Retry(format!(
            "synchronizer revoke timed out after {RPC_TIMEOUT:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    //! `open_session` + `revoke_on` against a scripted synchronizer: a Noise
    //! responder that attests with a fake document, advertises a chosen
    //! capability set and answers the one RPC with a chosen response. The
    //! round trip against the real listener and state machine is covered by
    //! the synchronizer crate's own client tests.

    use super::*;

    use enclavia_protocol::attestation::Pcrs;
    use enclavia_protocol::attestation::test_utils::FakeAttestation;
    use enclavia_protocol::chain::ChainLinkKind;
    use enclavia_protocol::perform_handshake_as_responder;
    use synchronizer::wire::{Frame, MAX_FRAME_SIZE, Request, Response};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const SERVER_SEED: u8 = 0xa5;

    fn pcrs(seed: u8) -> Pcrs {
        Pcrs {
            pcr0: vec![seed; 48],
            pcr1: vec![seed.wrapping_add(1); 48],
            pcr2: vec![seed.wrapping_add(2); 48],
        }
    }

    fn link() -> ChainLink {
        ChainLink {
            id: None,
            sequence: None,
            kind: ChainLinkKind::Revocation,
            payload: vec![1, 2, 3],
            attestation: vec![],
            signature: Some(vec![0; 64]),
        }
    }

    async fn read_plaintext(
        stream: &mut DuplexStream,
        transport: &mut enclavia_protocol::NoiseTransport,
    ) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await.ok()?;
        let mut ct = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut ct).await.ok()?;
        let mut pt = vec![0u8; MAX_FRAME_SIZE as usize];
        let n = transport.read_message(&ct, &mut pt).ok()?;
        pt.truncate(n);
        Some(pt)
    }

    async fn write_plaintext<T: serde::Serialize>(
        stream: &mut DuplexStream,
        transport: &mut enclavia_protocol::NoiseTransport,
        value: &T,
    ) {
        let mut pt = Vec::new();
        ciborium::into_writer(value, &mut pt).unwrap();
        let mut ct = vec![0u8; MAX_FRAME_SIZE as usize];
        let n = transport.write_message(&pt, &mut ct).unwrap();
        stream.write_all(&(n as u32).to_be_bytes()).await.unwrap();
        stream.write_all(&ct[..n]).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// A synchronizer that authenticates, advertises `capabilities`, and
    /// answers the next RPC (if one comes) with `answer`. Returns the RPC it
    /// received.
    async fn scripted(
        mut stream: DuplexStream,
        capabilities: &[&str],
        answer: Response,
    ) -> Option<Request> {
        let (mut transport, hash) = perform_handshake_as_responder(&mut stream).await.unwrap();
        read_plaintext(&mut stream, &mut transport).await.unwrap();
        let auth = Frame::Authenticate {
            nsm_doc: FakeAttestation::with_seed(SERVER_SEED, hash).encode(),
            protocol_version: 1,
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        };
        write_plaintext(&mut stream, &mut transport, &auth).await;
        let rpc = read_plaintext(&mut stream, &mut transport).await?;
        let Frame::Rpc { request } = ciborium::from_reader(rpc.as_slice()).unwrap() else {
            panic!("expected an RPC frame");
        };
        write_plaintext(&mut stream, &mut transport, &answer).await;
        Some(request)
    }

    /// Open a session to a scripted synchronizer and revoke on it.
    async fn revoke_against(
        capabilities: &'static [&'static str],
        answer: Response,
    ) -> (Result<(), Failure>, Option<Request>) {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(scripted(server_stream, capabilities, answer));
        let policy = ServerPcrPolicy::Expected(vec![pcrs(SERVER_SEED)]);
        let mut client = match open_session(client_stream, &policy, true, |hash| async move {
            Ok(FakeAttestation::with_seed_and_pubkey(0x10, hash, [4; 65]).encode())
        })
        .await
        {
            Ok(c) => c,
            Err(e) => panic!("session: {e:?}"),
        };
        let result = revoke_on(&mut client, &link()).await;
        drop(client);
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn acknowledged_revocation_succeeds() {
        let (result, request) =
            revoke_against(&[CAPABILITY_REVOCATION], Response::RevokeOk).await;
        result.unwrap();
        assert_eq!(request, Some(Request::Revoke { link: link() }));
    }

    /// A synchronizer without the capability would not enforce the
    /// revocation: fail, without sending it.
    #[tokio::test]
    async fn synchronizer_without_the_capability_fails_loudly() {
        let (result, request) = revoke_against(&[], Response::RevokeOk).await;
        assert!(
            matches!(&result, Err(Failure::Fatal(msg)) if msg.contains(CAPABILITY_REVOCATION)),
            "{result:?}"
        );
        assert_eq!(request, None, "nothing may be sent to such a synchronizer");
    }

    #[tokio::test]
    async fn rejected_revocation_is_fatal() {
        let (result, _) = revoke_against(
            &[CAPABILITY_REVOCATION],
            Response::Err {
                error: RpcError::RevocationRejected,
            },
        )
        .await;
        assert!(
            matches!(&result, Err(Failure::Fatal(msg)) if msg.contains("rejected")),
            "{result:?}"
        );
    }

    /// No quorum: the outcome is unknown and a revocation is idempotent, so
    /// the caller retries.
    #[tokio::test]
    async fn unavailable_is_retried() {
        let (result, _) = revoke_against(
            &[CAPABILITY_REVOCATION],
            Response::Err {
                error: RpcError::Unavailable,
            },
        )
        .await;
        assert!(matches!(result, Err(Failure::Retry(_))), "{result:?}");
    }
}
