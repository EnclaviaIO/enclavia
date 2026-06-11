//! Multi-node mesh integration test (acceptance bar for #118).
//!
//! Stands up synchronizer nodes in one process, wired together over UDS
//! through an in-process `mesh-host` stub (no QEMU, no vsock). Exercises the
//! full slice-2 surface:
//!
//! * 3 nodes mutually attest (P-256 identity signature over the handshake
//!   hash + self-PCR allowlist) and exchange id-correlated request/response
//!   RPCs in both directions;
//! * many concurrent correlated requests on one peer link resolve to the
//!   right responses;
//! * a peer running a different image (different PCRs) is refused and no
//!   channel is established;
//! * killing a node and restarting it lets the survivors reconnect and the
//!   restarted node rejoins;
//! * a relay that nacks the open (`OPEN_ACK_FAILED`) or drops before acking
//!   (EOF) never produces a usable channel;
//! * an oversized / garbage inbound frame is rejected without wedging the
//!   serving node.
//!
//! Gated on `test-utils`: the UDS transport and `FakeAttestor` it uses are
//! never compiled into the production binary.
#![cfg(feature = "test-utils")]

use std::sync::Arc;
use std::time::Duration;

use synchronizer::mesh::Mesh;
use synchronizer::mesh::attestation::FakeAttestor;
use synchronizer::mesh::config::MeshConfig;
use synchronizer::mesh::identity::MeshIdentity;
use synchronizer::mesh::rpc::{MeshPayload, PeerContext, RequestHandler};
use synchronizer::mesh::transport::{
    EofAckDialer, FailingAckDialer, GarbageDialer, MeshHostStub, MisroutingDialer, UdsMeshAcceptor,
};

/// All three nodes run the same EIF in a real deployment, so they share a PCR
/// seed here: the self-PCR allowlist admits a peer only if its digest equals
/// the node's own, and identical images means identical digests.
const IMAGE_SEED: u8 = 0x42;

/// A request handler that replies with `"<self_name>:<from>:<request>"`, so a
/// test can assert both the round-trip and the direction attribution (which
/// peer the serving node believes sent the request).
struct TaggingHandler {
    self_name: String,
}

#[async_trait::async_trait]
impl RequestHandler for TaggingHandler {
    async fn handle(&self, peer: &PeerContext, body: MeshPayload) -> MeshPayload {
        let req = String::from_utf8_lossy(&body);
        format!("{}:{}:{}", self.self_name, peer.name, req).into_bytes()
    }
}

/// Poll `f` until it returns true or the deadline elapses.
async fn eventually<F>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    loop {
        if f() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One node under test: its `Mesh` plus the temp dir holding its inbound UDS
/// socket. Dropping the node tears the mesh down (every task aborts) and
/// removes the socket, which is exactly the "kill a node" operation.
struct TestNode {
    name: String,
    mesh: Arc<Mesh>,
    _dir: tempfile::TempDir,
}

/// Spin up a node named `name` with peer set `peers`, registering its inbound
/// socket in `host` so the other nodes can dial it. Same image seed for all.
fn spawn_node(name: &str, peers: &[&str], host: &MeshHostStub) -> TestNode {
    spawn_node_seeded(name, peers, host, IMAGE_SEED)
}

fn spawn_node_seeded(name: &str, peers: &[&str], host: &MeshHostStub, seed: u8) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join(format!("{name}.sock"));
    let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
    host.register(name, &sock);

    let identity = MeshIdentity::generate();
    let attestor = FakeAttestor::new(seed, &identity);
    let config = MeshConfig::new(
        name.to_string(),
        peers.iter().map(|p| p.to_string()),
        FakeAttestor::pcr_digest(seed),
    );
    let handler = TaggingHandler {
        self_name: name.to_string(),
    };
    let mesh = Mesh::start(
        config,
        host.dialer(),
        acceptor,
        attestor,
        identity,
        handler,
        /* debug_mode */ true,
    );
    TestNode {
        name: name.to_string(),
        mesh: Arc::new(mesh),
        _dir: dir,
    }
}

/// Call `to` from `from` and assert the tagged response arrives within the
/// window. Retries across the window so a not-yet-established channel does not
/// flake the assertion. Returns the response bytes.
async fn assert_call(from: &TestNode, to: &TestNode, request: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match from.mesh.call(&to.name, request.as_bytes().to_vec()).await {
            Ok(resp) => {
                let expected = format!("{}:{}:{}", to.name, from.name, request);
                assert_eq!(
                    String::from_utf8_lossy(&resp),
                    expected,
                    "{} -> {} response mismatch",
                    from.name,
                    to.name
                );
                return resp;
            }
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            Err(e) => panic!("{} -> {} never succeeded: {e}", from.name, to.name),
        }
    }
}

#[tokio::test]
async fn three_nodes_attest_call_both_ways_kill_one_restart_rejoins() {
    let host = MeshHostStub::new();
    let all = ["node-a", "node-b", "node-c"];
    let peers_of = |me: &str| -> Vec<&str> { all.iter().copied().filter(|n| *n != me).collect() };

    let a = spawn_node("node-a", &peers_of("node-a"), &host);
    let b = spawn_node("node-b", &peers_of("node-b"), &host);
    let mut c = spawn_node("node-c", &peers_of("node-c"), &host);

    // 1. All-pairs request/response: every ordered pair can call. This is the
    //    "3 nodes mutually attest and report mesh up" acceptance check, proven
    //    by a real correlated round-trip over each attested channel.
    assert_call(&a, &b, "a->b").await;
    assert_call(&a, &c, "a->c").await;
    assert_call(&b, &a, "b->a").await;
    assert_call(&b, &c, "b->c").await;
    assert_call(&c, &a, "c->a").await;
    assert_call(&c, &b, "c->b").await;

    // 2. Kill node-c. Dropping it aborts its mesh tasks and drops its inbound
    //    socket. The surviving pair (a, b) must keep talking.
    let c_sock_dir = c._dir.path().to_path_buf();
    drop(c);
    assert_call(&a, &b, "a->b after c down").await;
    assert_call(&b, &a, "b->a after c down").await;
    assert!(
        !c_sock_dir.join("node-c.sock").exists(),
        "node-c socket should have been removed on drop"
    );

    // 3. Restart node-c. It re-attests and rejoins; the survivors' dial loops,
    //    retrying with backoff, re-establish, and the cluster is fully
    //    connected again.
    c = spawn_node("node-c", &peers_of("node-c"), &host);
    assert_call(&a, &c, "a->c rejoin").await;
    assert_call(&b, &c, "b->c rejoin").await;
    assert_call(&c, &a, "c->a rejoin").await;
    assert_call(&c, &b, "c->b rejoin").await;
    assert_call(&a, &b, "a->b final").await;
}

#[tokio::test]
async fn concurrent_correlated_requests_resolve_independently() {
    let host = MeshHostStub::new();
    let a = spawn_node("node-a", &["node-b"], &host);
    let b = spawn_node("node-b", &["node-a"], &host);

    // Bring the channel up first.
    assert_call(&a, &b, "warmup").await;

    // Fire many concurrent calls on the single a->b connection; each must get
    // back its OWN correlated response, proving id demultiplexing works under
    // concurrency on one link.
    let mut handles = Vec::new();
    for i in 0..64u32 {
        let mesh = Arc::clone(&a.mesh);
        handles.push(tokio::spawn(async move {
            let req = format!("req-{i}");
            let resp = mesh.call("node-b", req.as_bytes().to_vec()).await.unwrap();
            (i, String::from_utf8_lossy(&resp).into_owned())
        }));
    }
    for h in handles {
        let (i, resp) = h.await.unwrap();
        assert_eq!(resp, format!("node-b:node-a:req-{i}"));
    }
}

#[tokio::test]
async fn peer_running_a_different_image_is_not_admitted() {
    let host = MeshHostStub::new();

    // node-a runs IMAGE_SEED; node-evil runs a different image, so its PCR
    // digest is not in node-a's self-only allowlist (and vice versa).
    let a = spawn_node("node-a", &["node-evil"], &host);
    let evil = spawn_node_seeded("node-evil", &["node-a"], &host, 0x99);

    // Neither side ever establishes a channel: the mutual attestation fails
    // the PCR allowlist on both ends. `call` must keep returning
    // NotConnected (never a successful round-trip).
    let mut ever_connected = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if a.mesh.call("node-evil", b"nope".to_vec()).await.is_ok() {
            ever_connected = true;
            break;
        }
        if evil.mesh.call("node-a", b"nope".to_vec()).await.is_ok() {
            ever_connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !ever_connected,
        "a peer running a different image must never be admitted to the mesh"
    );
    assert!(!a.mesh.is_connected("node-evil").await);
    assert!(!evil.mesh.is_connected("node-a").await);
}

#[tokio::test]
async fn relay_nack_never_yields_a_channel() {
    // node-a dials through a relay that always answers OPEN_ACK_FAILED. The
    // dial fails before any handshake, so the channel never comes up.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("node-a.sock");
    let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
    let identity = MeshIdentity::generate();
    let attestor = FakeAttestor::new(IMAGE_SEED, &identity);
    let config = MeshConfig::new(
        "node-a".to_string(),
        ["node-b".to_string()],
        FakeAttestor::pcr_digest(IMAGE_SEED),
    );
    let mesh = Mesh::start(
        config,
        FailingAckDialer,
        acceptor,
        attestor,
        identity,
        TaggingHandler {
            self_name: "node-a".to_string(),
        },
        true,
    );

    // Give the dial loop plenty of attempts; it must never produce a channel.
    let stayed_down = eventually(Duration::from_secs(2), || false).await;
    assert!(!stayed_down); // eventually() returns false on timeout, as expected
    assert!(
        !mesh.is_connected("node-b").await,
        "a relay that nacks the open must never yield a connected channel"
    );
    assert!(matches!(
        mesh.call("node-b", b"x".to_vec()).await,
        Err(synchronizer::mesh::CallError::NotConnected(_))
    ));
}

#[tokio::test]
async fn relay_eof_before_ack_never_yields_a_channel() {
    // Same as above but the relay drops before writing any ack byte (EOF). The
    // dialer's read_open_ack maps EOF to a dial failure.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("node-a.sock");
    let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
    let identity = MeshIdentity::generate();
    let attestor = FakeAttestor::new(IMAGE_SEED, &identity);
    let config = MeshConfig::new(
        "node-a".to_string(),
        ["node-b".to_string()],
        FakeAttestor::pcr_digest(IMAGE_SEED),
    );
    let mesh = Mesh::start(
        config,
        EofAckDialer,
        acceptor,
        attestor,
        identity,
        TaggingHandler {
            self_name: "node-a".to_string(),
        },
        true,
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !mesh.is_connected("node-b").await,
        "a relay that EOFs before acking must never yield a connected channel"
    );
}

#[tokio::test]
async fn oversized_garbage_inbound_frame_is_rejected_without_wedging() {
    // node-b is a healthy serving node. node-a dials it through a relay that
    // (after a valid open ack) skips the Noise handshake and emits a giant
    // length prefix + junk. node-b's serving connection must reject it and
    // close, while node-b stays healthy enough to serve a legitimate peer.
    let host = MeshHostStub::new();
    let b = spawn_node("node-b", &["node-a", "node-c"], &host);
    let c = spawn_node("node-c", &["node-b"], &host);

    // A legitimate peer (c) can talk to b: proves b is up and serving.
    assert_call(&c, &b, "healthy-before").await;

    // Now fire the garbage dialer at b. It splices through the stub to b's
    // inbound socket. b's handle_inbound must error out on the bad frame and
    // drop that one connection without taking the node down.
    let garbage = GarbageDialer { host: host.clone() };
    {
        use synchronizer::mesh::transport::MeshDialer;
        // One garbage connection; ignore the result (the point is b survives).
        let _ = garbage.dial("node-b").await;
    }

    // b is still healthy: c can still round-trip after the garbage attempt.
    assert_call(&c, &b, "healthy-after").await;
}

/// Spawn a node whose outbound dials all go through `dialer` instead of the
/// stub's honest dialer. Used to inject a misrouting/reflecting relay on the
/// victim's dial side while the rest of the cluster runs normally.
fn spawn_node_with_dialer<D>(name: &str, peers: &[&str], host: &MeshHostStub, dialer: D) -> TestNode
where
    D: synchronizer::mesh::transport::MeshDialer + 'static,
{
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join(format!("{name}.sock"));
    let acceptor = UdsMeshAcceptor::bind(&sock).unwrap();
    host.register(name, &sock);

    let identity = MeshIdentity::generate();
    let attestor = FakeAttestor::new(IMAGE_SEED, &identity);
    let config = MeshConfig::new(
        name.to_string(),
        peers.iter().map(|p| p.to_string()),
        FakeAttestor::pcr_digest(IMAGE_SEED),
    );
    let handler = TaggingHandler {
        self_name: name.to_string(),
    };
    let mesh = Mesh::start(config, dialer, acceptor, attestor, identity, handler, true);
    TestNode {
        name: name.to_string(),
        mesh: Arc::new(mesh),
        _dir: dir,
    }
}

/// A1: misrouted dial. node-a dials "node-b" but a malicious relay always
/// splices it to node-c's inbound socket. node-c is a real, same-image
/// (identically attested) node, so mutual attestation succeeds, but node-c
/// honestly announces "node-c" in its Hello. node-a dialed "node-b", so the
/// announced name does not match and node-a drops the channel: it never marks
/// "node-b" connected and a call to it stays NotConnected.
#[tokio::test]
async fn misrouted_dial_is_rejected_by_dialer() {
    let host = MeshHostStub::new();
    // node-c is a genuine cluster node, fully up and serving.
    let c = spawn_node("node-c", &["node-a", "node-b"], &host);
    // node-a's dialer is malicious: every dial it makes is spliced to node-c.
    let misrouting = MisroutingDialer {
        host: host.clone(),
        actual_target: "node-c".to_string(),
    };
    let a = spawn_node_with_dialer("node-a", &["node-b"], &host, misrouting);

    // node-a's only configured peer is node-b, but its dials land on node-c,
    // which announces "node-c". node-a must never consider node-b connected.
    let start = std::time::Instant::now();
    let mut ever_connected = false;
    while start.elapsed() < Duration::from_secs(2) {
        if a.mesh.is_connected("node-b").await {
            ever_connected = true;
            break;
        }
        if a.mesh.call("node-b", b"x".to_vec()).await.is_ok() {
            ever_connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(
        !ever_connected,
        "a dial misrouted to a different (valid) peer must be rejected by the dialer's Hello check"
    );
    assert!(matches!(
        a.mesh.call("node-b", b"x".to_vec()).await,
        Err(synchronizer::mesh::CallError::NotConnected(_))
    ));
    drop(c);
}

/// A1: reflection. node-a dials "node-b" but the malicious relay reflects the
/// dial back to node-a's OWN inbound socket. node-a's accept side admits it
/// (same image) and announces "node-a"; the dialing side then sees its own
/// name where it expected "node-b" and drops the channel. (The responder side
/// also independently rejects it: self-name is never in the peer set.) Either
/// way node-a must never believe "node-b" is connected.
#[tokio::test]
async fn reflected_dial_is_rejected() {
    let host = MeshHostStub::new();
    let reflecting = MisroutingDialer {
        host: host.clone(),
        actual_target: "node-a".to_string(),
    };
    let a = spawn_node_with_dialer("node-a", &["node-b"], &host, reflecting);

    let start = std::time::Instant::now();
    let mut ever_connected = false;
    while start.elapsed() < Duration::from_secs(2) {
        if a.mesh.is_connected("node-b").await {
            ever_connected = true;
            break;
        }
        if a.mesh.call("node-b", b"x".to_vec()).await.is_ok() {
            ever_connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(
        !ever_connected,
        "a dial reflected back to the dialer's own node must be rejected"
    );
}
