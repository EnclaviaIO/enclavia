//! Connect-time policy hook.
//!
//! The on-disk allowlist is parsed by [`crate::config::AllowlistConfig`].
//! This module wires it into the [`ConnectPolicy`] trait that
//! [`crate::forward_flow`] calls between accept and transport dial.
//!
//! Hostname enforcement:
//! - IP literal / CIDR entries are tried first; a hit short-circuits to
//!   Allow without ever touching DNS. That keeps the hot path (workload
//!   talking to a fixed AWS endpoint, say) cache-free and resolver-free.
//! - On miss, the policy iterates `tcp_hostnames_for_port(dst.port())`
//!   and, for each entry, issues one query to the in-enclave `unbound`
//!   via the injected `Resolver`. If `dst.ip()` appears in any returned
//!   A-record set, the connection is allowed.
//! - We do NOT cache resolver answers here. `unbound` already caches
//!   them with the authoritative TTL; an in-daemon cache would just be
//!   a second source of truth to keep in sync. The default cost is one
//!   loopback DNS query per matching hostname per connect.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::AllowlistConfig;
use crate::resolver::Resolver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[async_trait]
pub trait ConnectPolicy: Send + Sync {
    /// Decide whether the daemon should forward a TCP connection from
    /// `src` to `dst`. `src` is the source address parsed from the SYN;
    /// under the netns-split topology it distinguishes workload traffic
    /// from init-netns infra traffic (see `trusted_source_only`).
    async fn allow_tcp(&self, src: Ipv4Addr, dst: SocketAddrV4) -> PolicyDecision;
}

/// Skeleton policy: everything is allowed. Kept for tests that want
/// to bypass enforcement, not used by the production binary.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

#[async_trait]
impl ConnectPolicy for AllowAll {
    async fn allow_tcp(&self, _src: Ipv4Addr, _dst: SocketAddrV4) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

/// Production policy: deny by default, allow iff the destination
/// matches one of the entries loaded from the JSON allowlist (either
/// an IP literal/CIDR, or a hostname that currently resolves to the
/// destination IP via the in-enclave `unbound`).
///
/// IPv6 destinations never reach this struct because [`forward_flow`]
/// already deals exclusively in [`SocketAddrV4`]; the in-stack smoltcp
/// build is IPv4-only. The IPv6 reject requirement is therefore
/// satisfied structurally (and reinforced parser-side, which drops IPv6
/// literals from the allowlist with a warning).
#[derive(Clone, Debug)]
pub struct StaticAllowlistPolicy<R: Resolver> {
    inner: Arc<AllowlistConfig>,
    resolver: Arc<R>,
    /// Source address of init-netns infra traffic: connections whose
    /// SYN sources from here (in practice: `unbound`'s upstream
    /// forwarder, which the kernel sources from the tun address) may
    /// match `trusted_source_only` entries. Workload traffic sources
    /// from the veth subnet under the netns-split topology and never
    /// matches them. Pre-split, ALL traffic sources from this address,
    /// so the gate is inert there by construction.
    trusted_src: Ipv4Addr,
}

impl<R: Resolver> StaticAllowlistPolicy<R> {
    pub fn new(config: AllowlistConfig, resolver: Arc<R>, trusted_src: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(config),
            resolver,
            trusted_src,
        }
    }

    /// Underlying allowlist, exposed for diagnostics and tests.
    pub fn config(&self) -> &AllowlistConfig {
        &self.inner
    }
}

#[async_trait]
impl<R: Resolver + 'static> ConnectPolicy for StaticAllowlistPolicy<R> {
    async fn allow_tcp(&self, src: Ipv4Addr, dst: SocketAddrV4) -> PolicyDecision {
        // Hot path: IP / CIDR hit, no DNS involvement.
        if self
            .inner
            .allows_tcp(*dst.ip(), dst.port(), src == self.trusted_src)
        {
            return PolicyDecision::Allow;
        }

        // Cold path: every hostname entry whose port matches the
        // destination port gets one resolver round-trip. We intentionally
        // do not stop on the first hostname whose query succeeds without
        // matching — the connect IP could match any one of them, so we
        // keep going until we find a match or exhaust the list.
        let target = *dst.ip();
        for entry in self.inner.tcp_hostnames_for_port(dst.port()) {
            match self.resolver.resolve(&entry.host).await {
                Ok(ips) => {
                    if ips.contains(&target) {
                        tracing::debug!(
                            host = %entry.host,
                            %dst,
                            "Egress policy: hostname match",
                        );
                        return PolicyDecision::Allow;
                    }
                }
                Err(e) => {
                    // Failed lookups deny by default. Logged at warn so
                    // operators can correlate denied connects with DNS
                    // outages.
                    tracing::warn!(
                        host = %entry.host,
                        %dst,
                        error = %e,
                        "Egress policy: hostname resolution failed",
                    );
                }
            }
        }

        PolicyDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::MockResolver;
    use std::net::Ipv4Addr;

    /// Trusted (init-netns) source address for tests: the tun address.
    const TRUSTED_SRC: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
    /// Workload source address for tests: the veth subnet under the
    /// netns-split topology.
    const WORKLOAD_SRC: Ipv4Addr = Ipv4Addr::new(10, 99, 1, 2);

    fn cfg_from_json(raw: &str) -> AllowlistConfig {
        AllowlistConfig::from_bytes(raw.as_bytes()).expect("parse")
    }

    fn allow_all_resolver() -> Arc<MockResolver> {
        Arc::new(MockResolver::new())
    }

    #[tokio::test]
    async fn literal_hit_allows() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"1.2.3.4","port":443,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn literal_miss_denies() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"1.2.3.4","port":443,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 5), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn cidr_hit_allows() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"10.0.0.0/8","port":443,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn cidr_miss_denies() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"10.0.0.0/8","port":443,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(11, 0, 0, 1), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn wrong_port_denies() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"1.2.3.4","port":443,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn empty_allowlist_denies_everything() {
        let policy =
            StaticAllowlistPolicy::new(AllowlistConfig::empty(), allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    // --- Trusted-source gating (resolver-bypass hardening) ---

    #[tokio::test]
    async fn injected_resolver_entry_denies_workload_source() {
        let mut cfg = cfg_from_json(r#"{ "version": 1, "resolvers": ["1.1.1.1"], "egress": [] }"#);
        crate::inject_resolver_entries(&mut cfg);
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn injected_resolver_entry_allows_trusted_source() {
        let mut cfg = cfg_from_json(r#"{ "version": 1, "resolvers": ["1.1.1.1"], "egress": [] }"#);
        crate::inject_resolver_entries(&mut cfg);
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        assert_eq!(policy.allow_tcp(TRUSTED_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn user_entry_on_port_53_still_allows_workload_source() {
        // An operator who EXPLICITLY allowlists a resolver IP on port 53
        // has opted the workload into direct DNS; only the auto-injected
        // entries are trusted-source gated.
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"9.9.9.9","port":53,"protocol":"tcp"} ] }"#,
        );
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn broad_cidr_does_not_unlock_injected_resolver_gating() {
        // 0.0.0.0/0:443 is a user entry on port 443; the injected
        // 1.1.1.1:53 entry stays trusted-source-only, so a workload
        // dialing the resolver port directly is still denied.
        let mut cfg = cfg_from_json(
            r#"{ "version": 1, "resolvers": ["1.1.1.1"],
                 "egress": [ {"host":"0.0.0.0/0","port":443,"protocol":"tcp"} ] }"#,
        );
        crate::inject_resolver_entries(&mut cfg);
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let https = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443);
        let dns = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, https).await, PolicyDecision::Allow);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dns).await, PolicyDecision::Deny);
    }

    // --- Hostname enforcement ---

    #[tokio::test]
    async fn hostname_match_allows_when_resolver_returns_target_ip() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"api.openai.com","port":443,"protocol":"tcp"} ] }"#,
        );
        let resolver = Arc::new(MockResolver::with_answer(
            "api.openai.com",
            [Ipv4Addr::new(1, 2, 3, 4)],
        ));
        let policy = StaticAllowlistPolicy::new(cfg, resolver, TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn hostname_mismatch_denies_even_when_resolver_succeeds() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"api.openai.com","port":443,"protocol":"tcp"} ] }"#,
        );
        let resolver = Arc::new(MockResolver::with_answer(
            "api.openai.com",
            [Ipv4Addr::new(1, 2, 3, 4)],
        ));
        let policy = StaticAllowlistPolicy::new(cfg, resolver, TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn hostname_resolver_failure_denies() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"api.openai.com","port":443,"protocol":"tcp"} ] }"#,
        );
        let mock = MockResolver::new();
        mock.fail_for("api.openai.com");
        let policy = StaticAllowlistPolicy::new(cfg, Arc::new(mock), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn hostname_empty_answer_denies() {
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"api.openai.com","port":443,"protocol":"tcp"} ] }"#,
        );
        // No answer registered: MockResolver returns an empty Vec.
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn hostname_wrong_port_denies_without_querying() {
        // Allowlist says port 443 for the hostname; workload tries
        // port 80. Even if the hostname WOULD resolve to the connect
        // IP, the entry's port does not match -> deny, and we should
        // not have issued a query.
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [ {"host":"api.openai.com","port":443,"protocol":"tcp"} ] }"#,
        );
        let resolver = Arc::new(MockResolver::with_answer(
            "api.openai.com",
            [Ipv4Addr::new(1, 2, 3, 4)],
        ));
        let policy = StaticAllowlistPolicy::new(cfg, resolver.clone(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Deny);
        assert_eq!(resolver.calls(), 0, "policy must short-circuit before DNS");
    }

    #[tokio::test]
    async fn ip_hit_short_circuits_dns() {
        // IP literal matches first -> resolver is never consulted, even
        // if there is a hostname entry on the same port that would also
        // need to be checked on an IP-miss path.
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [
                {"host":"1.2.3.4","port":443,"protocol":"tcp"},
                {"host":"api.openai.com","port":443,"protocol":"tcp"}
            ] }"#,
        );
        let resolver = Arc::new(MockResolver::new());
        let policy = StaticAllowlistPolicy::new(cfg, resolver.clone(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
        assert_eq!(
            resolver.calls(),
            0,
            "IP literal hit must not trigger any DNS",
        );
    }

    #[tokio::test]
    async fn second_hostname_match_is_found() {
        // First hostname does not include the connect IP; second does.
        // Policy must keep walking until it finds a match.
        let cfg = cfg_from_json(
            r#"{ "version": 1, "egress": [
                {"host":"a.example","port":443,"protocol":"tcp"},
                {"host":"b.example","port":443,"protocol":"tcp"}
            ] }"#,
        );
        let resolver = Arc::new(MockResolver::new());
        resolver.set_answer("a.example", [Ipv4Addr::new(9, 9, 9, 9)]);
        resolver.set_answer("b.example", [Ipv4Addr::new(1, 2, 3, 4)]);
        let policy = StaticAllowlistPolicy::new(cfg, resolver, TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(policy.allow_tcp(WORKLOAD_SRC, dst).await, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn auto_injected_resolver_entry_allows_tcp_to_resolver_port_53() {
        // Models main()'s startup behaviour: a config with one resolver
        // and no IP entries has `resolvers[i]:53/tcp` mirrored into
        // `entries`, so unbound's own outbound queries (sourced from the
        // trusted address) are permitted.
        let mut cfg = cfg_from_json(
            r#"{ "version": 1, "resolvers": ["1.1.1.1"], "egress": [] }"#,
        );
        assert!(cfg.entries.is_empty(), "test setup: no IP entries");
        crate::inject_resolver_entries(&mut cfg);
        let policy = StaticAllowlistPolicy::new(cfg, allow_all_resolver(), TRUSTED_SRC);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        assert_eq!(policy.allow_tcp(TRUSTED_SRC, dst).await, PolicyDecision::Allow);
        // And on a non-53 port the resolver entry must NOT inadvertently
        // allow general egress, trusted source or not.
        let other = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443);
        assert_eq!(policy.allow_tcp(TRUSTED_SRC, other).await, PolicyDecision::Deny);
    }
}
