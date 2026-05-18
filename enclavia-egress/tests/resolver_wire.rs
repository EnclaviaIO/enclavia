//! Wire-path integration test for the policy + UnboundClient pair.
//!
//! Stands up a tiny fake DNS-over-TCP server (no DNSSEC, no recursion,
//! no caching: it just answers whatever the test wires up) and points
//! `UnboundClient` at it. Confirms that the encode → write → read →
//! decode → match-against-connect-IP loop in the policy actually
//! works against a real socket. The production `unbound` is exercised
//! by the e2e in QEMU; this test catches wire-format regressions in
//! the unit-test loop.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use enclavia_egress::{
    AllowlistConfig, ConnectPolicy, PolicyDecision, StaticAllowlistPolicy, UnboundClient,
};

async fn spawn_fake_dns(answers: Vec<Ipv4Addr>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dns");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let answers = answers.clone();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut req = vec![0u8; n];
                if stream.read_exact(&mut req).await.is_err() {
                    return;
                }
                let msg = Message::from_bytes(&req).expect("decode req");
                let mut resp = Message::response(msg.metadata.id, OpCode::Query);
                resp.metadata.recursion_desired = true;
                resp.metadata.recursion_available = true;
                for q in &msg.queries {
                    resp.add_query(q.clone());
                    for ip in &answers {
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(hickory_proto::rr::rdata::A(*ip)),
                        ));
                    }
                }
                let bytes = resp.to_vec().unwrap();
                let mut out = Vec::with_capacity(2 + bytes.len());
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(&bytes);
                let _ = stream.write_all(&out).await;
            });
        }
    });
    // Tiny pause so the listener is definitely accepting before the
    // first resolve attempt.
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn policy_allows_when_real_resolver_returns_target_ip() {
    let dns_addr = spawn_fake_dns(vec![Ipv4Addr::new(1, 2, 3, 4)]).await;
    let resolver = Arc::new(UnboundClient::with_addr(dns_addr));

    let cfg = AllowlistConfig::from_bytes(
        br#"{ "version": 1, "egress": [
            {"host":"api.example.com","port":443,"protocol":"tcp"}
        ] }"#,
    )
    .expect("parse");
    let policy = StaticAllowlistPolicy::new(cfg, resolver);

    let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
    assert_eq!(policy.allow_tcp(dst).await, PolicyDecision::Allow);
}

#[tokio::test]
async fn policy_denies_when_real_resolver_does_not_return_target_ip() {
    let dns_addr = spawn_fake_dns(vec![Ipv4Addr::new(9, 9, 9, 9)]).await;
    let resolver = Arc::new(UnboundClient::with_addr(dns_addr));

    let cfg = AllowlistConfig::from_bytes(
        br#"{ "version": 1, "egress": [
            {"host":"api.example.com","port":443,"protocol":"tcp"}
        ] }"#,
    )
    .expect("parse");
    let policy = StaticAllowlistPolicy::new(cfg, resolver);

    let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
    assert_eq!(policy.allow_tcp(dst).await, PolicyDecision::Deny);
}
