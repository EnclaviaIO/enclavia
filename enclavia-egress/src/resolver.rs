//! DNS resolution stub used by hostname-allowlist enforcement.
//!
//! The in-enclave daemon does not implement its own recursive resolver:
//! a static `unbound` runs as a separate process inside the EIF, listens
//! on `127.0.0.1:53`, and owns DNSSEC validation, caching, retries and
//! upstream forwarding (over DNS-over-TCP, since `egress-host` is
//! TCP-only). This module is the thin async client we use to talk to
//! that local resolver.
//!
//! Wire format is encoded and decoded with `hickory-proto`; we only need
//! its low-level message types, not its recursive resolver machinery.
//!
//! Choice of transport: TCP. UDP would work too against a loopback
//! resolver, but the wider egress path is TCP-only and using TCP here
//! sidesteps the 512-byte UDP truncation rule entirely. The handful of
//! extra round-trip bytes are noise on `127.0.0.1`.
//!
//! Choice of caching: NONE in this module. `unbound` already caches with
//! authoritative TTLs; the in-enclave RTT is sub-millisecond; and adding
//! a cache here just creates a second source of truth for TTL accounting
//! we would then have to keep consistent with `unbound`'s view. If
//! connect throughput ever becomes a measurable concern we can add a
//! small (30 s) coalescing cache, but the default is "ask `unbound` on
//! every connect".

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Default address of the in-enclave `unbound` instance.
pub const DEFAULT_UNBOUND_ADDR: &str = "127.0.0.1:53";

/// Per-query timeout. `unbound` on loopback should answer in
/// milliseconds; this is a backstop against the resolver hanging.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum response size we will accept. 16 KiB is well above any
/// realistic A-record answer including DNSSEC RRSIGs, and keeps us safe
/// from a malicious local resolver trying to OOM us.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Resolve a hostname to its set of A records.
///
/// Returns an empty `Vec` when the name resolves but yields no A
/// records, or when the resolver returns a non-NOERROR rcode. Callers
/// treat empty as "deny": no possible IP can be matched against an
/// empty answer set.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<Ipv4Addr>>;
}

/// Stub-resolver client pointed at a local DNS server. In production
/// this is the in-enclave `unbound` listening on `127.0.0.1:53`.
#[derive(Clone, Debug)]
pub struct UnboundClient {
    addr: SocketAddr,
}

impl UnboundClient {
    /// Build a client pointed at `127.0.0.1:53`.
    pub fn loopback() -> Self {
        Self {
            addr: DEFAULT_UNBOUND_ADDR
                .parse()
                .expect("DEFAULT_UNBOUND_ADDR is a valid SocketAddr"),
        }
    }

    /// Build a client pointed at an arbitrary local resolver. Used by
    /// the wire-path integration test (fake DNS server on a random
    /// port).
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Issue a single A-record query over DNS-over-TCP and parse the
    /// answer. `unbound` owns retries, recursion, DNSSEC validation,
    /// caching: we just ferry one request/response pair.
    async fn query_a(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        let name = Name::from_ascii(host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let request_id: u16 = rand::random();
        let mut request = Message::new(request_id, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, RecordType::A));

        let request_bytes = request
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if request_bytes.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS request exceeds 64 KiB",
            ));
        }

        let mut stream = TcpStream::connect(self.addr).await?;
        // RFC 1035 4.2.2: DNS-over-TCP frames its messages with a 2-byte
        // big-endian length prefix.
        let mut framed = Vec::with_capacity(2 + request_bytes.len());
        framed.extend_from_slice(&(request_bytes.len() as u16).to_be_bytes());
        framed.extend_from_slice(&request_bytes);
        stream.write_all(&framed).await?;
        stream.flush().await?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response length is zero",
            ));
        }
        if resp_len > MAX_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "DNS response too large: {resp_len} > {MAX_RESPONSE_BYTES} bytes"
                ),
            ));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        let response = Message::from_bytes(&resp_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if response.metadata.id != request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response ID mismatch (potential cross-talk on loopback)",
            ));
        }

        // RCODE != NOERROR is not an error from the daemon's point of
        // view: it just means "no IPs to match against", which translates
        // to Deny upstream. Same with NXDOMAIN, SERVFAIL, etc.: surface
        // them as an empty vec, not an Err.
        if response.metadata.response_code != ResponseCode::NoError {
            debug!(
                host,
                rcode = ?response.metadata.response_code,
                "Resolver returned non-NoError rcode, treating as empty answer",
            );
            return Ok(Vec::new());
        }

        let mut ips = Vec::new();
        for record in &response.answers {
            if let RData::A(a) = &record.data {
                ips.push(a.0);
            }
        }
        Ok(ips)
    }
}

#[async_trait]
impl Resolver for UnboundClient {
    async fn resolve(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        match timeout(QUERY_TIMEOUT, self.query_a(host)).await {
            Ok(Ok(ips)) => {
                debug!(host, count = ips.len(), "Resolved hostname via unbound");
                Ok(ips)
            }
            Ok(Err(e)) => {
                warn!(host, error = %e, "DNS query failed");
                Err(e)
            }
            Err(_) => {
                warn!(host, "DNS query timed out");
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS query exceeded {QUERY_TIMEOUT:?}",
                ))
            }
        }
    }
}

/// Test resolver: returns the answer set the test wired in. Used by
/// every unit test that wants deterministic resolution without spinning
/// up a real DNS server.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Debug, Default)]
pub struct MockResolver {
    inner: std::sync::Arc<std::sync::Mutex<MockState>>,
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Default)]
struct MockState {
    /// Pre-canned answers. Lookup is exact-match on hostname.
    answers: std::collections::HashMap<String, Vec<Ipv4Addr>>,
    /// Hostnames that should surface an I/O error rather than an empty
    /// answer. Models the "DNS server unreachable" case.
    fail: std::collections::HashSet<String>,
    /// Counter incremented on every resolve call. Tests use it to
    /// assert that the policy queried (or didn't query) the resolver.
    pub calls: usize,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-canned A records for `host`.
    pub fn with_answer<I: IntoIterator<Item = Ipv4Addr>>(host: &str, ips: I) -> Self {
        let me = Self::new();
        me.set_answer(host, ips);
        me
    }

    pub fn set_answer<I: IntoIterator<Item = Ipv4Addr>>(&self, host: &str, ips: I) {
        let mut g = self.inner.lock().unwrap();
        g.answers
            .insert(host.to_ascii_lowercase(), ips.into_iter().collect());
    }

    pub fn fail_for(&self, host: &str) {
        let mut g = self.inner.lock().unwrap();
        g.fail.insert(host.to_ascii_lowercase());
    }

    pub fn calls(&self) -> usize {
        self.inner.lock().unwrap().calls
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[async_trait]
impl Resolver for MockResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        let mut g = self.inner.lock().unwrap();
        g.calls += 1;
        let key = host.to_ascii_lowercase();
        if g.fail.contains(&key) {
            return Err(io::Error::other("mock resolver: simulated failure"));
        }
        Ok(g.answers.get(&key).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Tiny DNS-over-TCP server: parses one A query, responds with the
    /// canned answer set, closes the connection. Enough surface to
    /// exercise the wire-format path end to end without depending on a
    /// real resolver.
    async fn spawn_fake_dns(answers: Vec<Ipv4Addr>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                            resp.add_answer(hickory_proto::rr::Record::from_rdata(
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
        addr
    }

    #[tokio::test]
    async fn unbound_client_round_trips_an_a_record_answer() {
        let want = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let addr = spawn_fake_dns(want.clone()).await;
        let client = UnboundClient::with_addr(addr);
        let got = client.resolve("api.example.com").await.expect("resolve");
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn unbound_client_returns_empty_on_no_answers() {
        let addr = spawn_fake_dns(Vec::new()).await;
        let client = UnboundClient::with_addr(addr);
        let got = client.resolve("api.example.com").await.expect("resolve");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn unbound_client_errors_on_unreachable_resolver() {
        // 127.0.0.1 + an obviously closed port.
        let client = UnboundClient::with_addr("127.0.0.1:1".parse().unwrap());
        let result = client.resolve("api.example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_resolver_returns_canned_answers() {
        let mock = MockResolver::with_answer(
            "api.openai.com",
            [Ipv4Addr::new(1, 2, 3, 4)],
        );
        let got = mock.resolve("api.openai.com").await.unwrap();
        assert_eq!(got, vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    #[tokio::test]
    async fn mock_resolver_simulates_failure() {
        let mock = MockResolver::new();
        mock.fail_for("api.openai.com");
        assert!(mock.resolve("api.openai.com").await.is_err());
    }
}
