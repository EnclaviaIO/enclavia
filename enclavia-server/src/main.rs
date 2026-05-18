use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclavia_protocol::{perform_cbor_handshake_as_responder, ClientMessage, ControlCommand, ServerMessage};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tracing::{error, info, instrument, trace, warn};

mod attestation;
mod config;

use tokio_vsock::VsockListener;

const VSOCK_PORT: u32 = 5000;
const VSOCK_CID: u32 = u32::MAX; // VMADDR_CID_ANY — accept connections on any CID

const DEFAULT_CONTAINER_ADDR: &str = "127.0.0.1:8080";

/// Maximum allowed size for a single Data payload (4 MiB).
const MAX_PAYLOAD_SIZE: usize = 4 * 1024 * 1024;

/// Maximum number of in-flight requests per connection.
const MAX_IN_FLIGHT: usize = 64;

/// Maximum number of concurrent client connections (default: 2 per CPU core).
fn max_concurrent_clients() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() * 2)
        .unwrap_or(8)
}

/// Maximum time to wait for a client message before considering the connection idle.
const CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-boot single-use nonce for signed control commands. Initialized to a
/// random 32 bytes at startup; rotated each time a `Control` message is
/// processed (success OR failure) to prevent replay.
type ControlNonce = Arc<Mutex<[u8; 32]>>;

fn fresh_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Verify and dispatch a signed control command. Returns the user-visible
/// result message; rotates the nonce regardless of outcome.
async fn handle_control(
    payload: &[u8],
    signature: &[u8],
    control_pubkey: Option<&VerifyingKey>,
    nonce: &ControlNonce,
    crypto_bin: &str,
) -> (bool, String) {
    // Rotate the nonce after this call, regardless of outcome — a leaked
    // nonce is single-use whether or not the command verified.
    let mut current = nonce.lock().await;
    let expected = *current;
    *current = fresh_nonce();
    drop(current);

    let pubkey = match control_pubkey {
        Some(k) => k,
        None => return (false, "control channel disabled (no control_public_key configured)".into()),
    };

    let sig = match <[u8; 64]>::try_from(signature) {
        Ok(s) => Signature::from_bytes(&s),
        Err(_) => return (false, "signature must be 64 bytes".into()),
    };

    if pubkey.verify(payload, &sig).is_err() {
        return (false, "signature verification failed".into());
    }

    let cmd: ControlCommand = match ciborium::from_reader(payload) {
        Ok(c) => c,
        Err(e) => return (false, format!("malformed payload: {e}")),
    };

    match cmd {
        ControlCommand::PrepareUpgrade { new_public_key, new_key_id, nonce: cmd_nonce } => {
            if cmd_nonce != expected {
                return (false, "stale nonce — fetch a fresh attestation".into());
            }
            run_prepare_upgrade(&new_public_key, &new_key_id, crypto_bin).await
        }
    }
}

/// Spawn `enclavia-crypto prepare-upgrade` and translate its exit status into
/// a user-visible result. The new public key is base64-encoded for the CLI;
/// the key id is passed through unchanged.
async fn run_prepare_upgrade(
    new_public_key: &[u8],
    new_key_id: &str,
    bin: &str,
) -> (bool, String) {
    use base64::Engine as _;
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(new_public_key);

    let output = match tokio::process::Command::new(bin)
        .args([
            "prepare-upgrade",
            "--new-public-key",
            &pubkey_b64,
            "--new-key-id",
            new_key_id,
        ])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => return (false, format!("failed to spawn {bin}: {e}")),
    };

    if output.status.success() {
        (true, "prepare-upgrade completed".into())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trimmed = stderr.trim();
        let suffix = if trimmed.is_empty() { String::new() } else { format!(": {trimmed}") };
        (false, format!("enclavia-crypto exited with {}{}", output.status, suffix))
    }
}

/// Forward raw bytes to the inner container and return the response.
async fn forward_to_container(container_addr: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let connect = TcpStream::connect(container_addr).await.map_err(|e| e.to_string())?;
    let (mut read_half, mut write_half) = connect.into_split();

    write_half.write_all(payload).await.map_err(|e| e.to_string())?;
    write_half.shutdown().await.map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    read_half.read_to_end(&mut response).await.map_err(|e| e.to_string())?;
    Ok(response)
}

#[instrument(skip(stream, container_addr, control_pubkey, nonce))]
async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    container_addr: String,
    control_pubkey: Option<Arc<VerifyingKey>>,
    nonce: ControlNonce,
    crypto_bin: Arc<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Client connected, performing handshake");

    let (mut transport, handshake_hash) = perform_cbor_handshake_as_responder(&mut stream).await?;
    info!("Handshake completed successfully");

    let (response_tx, mut response_rx) = mpsc::channel::<ServerMessage>(MAX_IN_FLIGHT);
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));

    loop {
        tokio::select! {
            // Read the next client message
            result = async {
                match tokio::time::timeout(
                    CLIENT_IDLE_TIMEOUT,
                    transport.receive::<ClientMessage>(),
                ).await {
                    Ok(inner) => inner.map_err(|e| e.to_string()),
                    Err(_elapsed) => Err("idle timeout".to_string()),
                }
            } => {
                let msg = match result {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Error receiving message, closing connection: {}", e);
                        break;
                    }
                };

                trace!(?msg, "Received message from client");

                match msg {
                    ClientMessage::RequestAttestation => {
                        let control_nonce = *nonce.lock().await;
                        let attestation_data = attestation::get_attestation_with_data(
                            &handshake_hash,
                            &control_nonce,
                        )?;
                        let response = ServerMessage::Attestation {
                            data: attestation_data,
                            control_nonce,
                        };
                        if let Err(e) = transport.send(&response).await {
                            warn!(error = %e, "Failed to send attestation response");
                        }
                    }
                    ClientMessage::Control { payload, signature } => {
                        let (success, message) = handle_control(
                            &payload,
                            &signature,
                            control_pubkey.as_deref(),
                            &nonce,
                            crypto_bin.as_str(),
                        ).await;
                        if !success {
                            warn!(message = %message, "Control command rejected");
                        }
                        let response = ServerMessage::ControlResult { success, message };
                        if let Err(e) = transport.send(&response).await {
                            warn!(error = %e, "Failed to send control result");
                            break;
                        }
                    }
                    ClientMessage::Data { id, payload } => {
                        if payload.len() > MAX_PAYLOAD_SIZE {
                            warn!(id, size = payload.len(), max = MAX_PAYLOAD_SIZE, "Payload exceeds size limit");
                            let _ = response_tx.send(ServerMessage::Error {
                                id,
                                message: "payload too large".into(),
                            }).await;
                            continue;
                        }

                        let permit = match in_flight.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let tx = response_tx.clone();
                        let addr = container_addr.clone();

                        tokio::spawn(async move {
                            let response = match forward_to_container(&addr, &payload).await {
                                Ok(response_bytes) => ServerMessage::Data {
                                    id,
                                    payload: response_bytes,
                                },
                                Err(e) => {
                                    error!(id, error = %e, "Failed to forward to container");
                                    ServerMessage::Error {
                                        id,
                                        message: e,
                                    }
                                }
                            };
                            let _ = tx.send(response).await;
                            drop(permit);
                        });
                    }
                }
            }

            // Send completed responses back to the client
            Some(response) = response_rx.recv() => {
                if let Err(e) = transport.send(&response).await {
                    warn!(error = %e, "Failed to send response");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let container_addr = {
        let mut addr = DEFAULT_CONTAINER_ADDR.to_string();
        let mut iter = args.iter().skip(1);
        while let Some(arg) = iter.next() {
            if arg == "--container-addr" {
                if let Some(val) = iter.next() {
                    addr = val.clone();
                }
            }
        }
        addr
    };

    let max_clients = max_concurrent_clients();
    let semaphore = Arc::new(Semaphore::new(max_clients));

    let server_config = config::load(Path::new(config::CONFIG_PATH))
        .unwrap_or_else(|e| {
            warn!(error = %e, "Failed to load enclavia config, control channel will be disabled");
            config::ServerConfig::default()
        });
    let control_pubkey = server_config.control_public_key.map(Arc::new);
    let nonce: ControlNonce = Arc::new(Mutex::new(fresh_nonce()));
    let crypto_bin = Arc::new(
        std::env::var("ENCLAVIA_CRYPTO_BIN")
            .unwrap_or_else(|_| "/bin/enclavia-crypto".into()),
    );

    info!(
        container = %container_addr,
        max_clients,
        control_enabled = control_pubkey.is_some(),
        crypto_bin = %crypto_bin,
        "Starting enclavia server",
    );

    let mut listener = VsockListener::bind(VSOCK_CID, VSOCK_PORT)?;
    info!("Server listening on vsock port: {} (CID: {})", VSOCK_PORT, VSOCK_CID);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let addr = container_addr.clone();
                let sem = Arc::clone(&semaphore);
                let pubkey = control_pubkey.clone();
                let nonce = Arc::clone(&nonce);
                let crypto = Arc::clone(&crypto_bin);
                tokio::spawn(async move {
                    let _permit = match sem.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            error!("Semaphore closed, dropping client");
                            return;
                        }
                    };
                    info!("Client admitted (permit acquired)");
                    if let Err(e) = handle_client(stream, addr, pubkey, nonce, crypto).await {
                        error!(error = %e, "Error handling client");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Error accepting connection");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the signed Control channel: signature verification,
    //! single-use nonce semantics, malformed input handling, and dispatch
    //! to an enclavia-crypto subprocess (stubbed with `true`/`false`).
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use enclavia_protocol::ControlCommand;

    fn fixed_pair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    fn cbor_encode<T: serde::Serialize>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn make_command(nonce: [u8; 32]) -> Vec<u8> {
        cbor_encode(&ControlCommand::PrepareUpgrade {
            new_public_key: vec![0xAB; 16],
            new_key_id: "test-key".into(),
            nonce,
        })
    }

    #[tokio::test]
    async fn rejects_when_no_control_key_configured() {
        let nonce_value = [42u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (sk, _) = fixed_pair();
        let payload = make_command(nonce_value);
        let signature = sk.sign(&payload).to_bytes().to_vec();

        let (ok, msg) = handle_control(&payload, &signature, None, &nonce, "true").await;
        assert!(!ok, "msg = {msg}");
        assert!(msg.contains("control channel disabled"), "msg = {msg}");
        // Nonce is still rotated even without a configured key — leakage of
        // the failure path must not let an attacker pin the nonce.
        assert_ne!(*nonce.lock().await, nonce_value);
    }

    #[tokio::test]
    async fn rejects_bad_signature_length() {
        let nonce_value = [1u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (_, pk) = fixed_pair();
        let payload = make_command(nonce_value);

        let (ok, msg) = handle_control(&payload, &[0u8; 5], Some(&pk), &nonce, "true").await;
        assert!(!ok);
        assert!(msg.contains("64 bytes"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_invalid_signature() {
        let nonce_value = [1u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (_, pk) = fixed_pair();
        let payload = make_command(nonce_value);

        // 64 bytes of zero — well-formed length, but not a valid signature.
        let (ok, msg) = handle_control(&payload, &[0u8; 64], Some(&pk), &nonce, "true").await;
        assert!(!ok);
        assert!(msg.contains("signature verification"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_malformed_payload() {
        let nonce_value = [7u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(nonce_value));
        let (sk, pk) = fixed_pair();
        let bogus = b"\xff\xff\xff not cbor".to_vec();
        let signature = sk.sign(&bogus).to_bytes().to_vec();

        let (ok, msg) = handle_control(&bogus, &signature, Some(&pk), &nonce, "true").await;
        assert!(!ok);
        assert!(msg.contains("malformed payload"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_stale_nonce() {
        let server_nonce = [9u8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(server_nonce));
        let (sk, pk) = fixed_pair();

        // Sign a payload bearing the *wrong* nonce — server must reject it.
        let payload = make_command([0u8; 32]);
        let signature = sk.sign(&payload).to_bytes().to_vec();

        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "true").await;
        assert!(!ok);
        assert!(msg.contains("stale nonce"), "msg = {msg}");
    }

    #[tokio::test]
    async fn nonce_rotates_after_each_call() {
        let initial = [0xAAu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(initial));
        let (sk, pk) = fixed_pair();

        // First call: sign with the initial nonce. Underlying enclavia-crypto
        // is stubbed to `true` so dispatch reports success.
        let payload = make_command(initial);
        let signature = sk.sign(&payload).to_bytes().to_vec();
        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "true").await;
        assert!(ok, "expected success, got: {msg}");

        // Server nonce should have rotated to something new.
        let after = *nonce.lock().await;
        assert_ne!(after, initial);

        // Replaying the same payload (still bearing the old nonce) must fail.
        let (ok2, msg2) = handle_control(&payload, &signature, Some(&pk), &nonce, "true").await;
        assert!(!ok2);
        assert!(msg2.contains("stale nonce"), "msg = {msg2}");
    }

    #[tokio::test]
    async fn dispatch_failure_surfaces_in_message() {
        let initial = [0xBBu8; 32];
        let nonce: ControlNonce = Arc::new(Mutex::new(initial));
        let (sk, pk) = fixed_pair();

        let payload = make_command(initial);
        let signature = sk.sign(&payload).to_bytes().to_vec();
        // `false` exits 1 — verifies that enclavia-crypto failure is
        // reported back rather than silently masked.
        let (ok, msg) = handle_control(&payload, &signature, Some(&pk), &nonce, "false").await;
        assert!(!ok);
        assert!(msg.contains("enclavia-crypto exited"), "msg = {msg}");
    }
}
