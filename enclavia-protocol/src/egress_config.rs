//! The egress allowlist schema: the shared contract between everything
//! that AUTHORS a policy and the in-enclave daemon that ENFORCES it.
//!
//! The allowlist JSON (`/etc/enclavia/egress.json`, baked into the
//! measured EIF rootfs) is written by the CLI (`--egress-allow` /
//! `--egress-config`), validated by the backend on `POST /enclaves`,
//! and loaded by `enclavia-egress` at boot. All three run the SAME
//! pipeline in this module ([`AllowlistConfig::from_raw`]), so an entry
//! the CLI accepts is exactly an entry the daemon enforces; the
//! [`assemble_from_cli`] / [`validate_json`] entry points exist so
//! authoring tools never re-implement the grammar.
//!
//! Lives in `enclavia-protocol` (rather than the egress daemon crate)
//! so the CLI and backend can depend on the schema without dragging in
//! the TUN/smoltcp/vsock daemon stack. Gated behind the default-on
//! `egress-config` cargo feature (the wasm SDK build disables default
//! features and never needs it).

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Transport protocol for an allowlist entry.
///
/// TCP is the only one supported today. UDP is reserved at the type
/// level so the wire schema doesn't have to break when it lands, but
/// validation actively rejects UDP entries with a clear error rather
/// than silently dropping them at runtime. See
/// https://github.com/EnclaviaIO/enclavia/issues/1 for the tracking
/// issue.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Port half of an allowlist entry as it appears in the JSON file:
/// either a bare number (`443`) or the wildcard string `"*"` (any
/// port). Kept as a distinct raw type so serde deserialises both
/// JSON shapes; the number-vs-`"*"` validation happens in
/// [`RawPort::to_matcher`] alongside the rest of `from_raw`.
///
/// A numeric port serialises back to a JSON number and `"*"` back to
/// the string, so canonical JSON for pre-existing (all-numeric)
/// configs is byte-identical.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RawPort {
    Num(u16),
    Str(String),
}

impl std::fmt::Display for RawPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawPort::Num(n) => write!(f, "{n}"),
            RawPort::Str(s) => write!(f, "{s}"),
        }
    }
}

impl RawPort {
    /// The wildcard token accepted in the `port` field.
    pub const WILDCARD: &'static str = "*";

    /// Validate and canonicalise into a [`PortMatcher`]. A number must
    /// be `1..=65535`; the only accepted string is `"*"`.
    fn to_matcher(&self) -> Result<PortMatcher, AllowlistLoadError> {
        match self {
            RawPort::Num(0) => Err(AllowlistLoadError::BadPort("0".to_string())),
            RawPort::Num(n) => Ok(PortMatcher::Single(*n)),
            RawPort::Str(s) if s == RawPort::WILDCARD => Ok(PortMatcher::Any),
            RawPort::Str(s) => Err(AllowlistLoadError::BadPort(s.clone())),
        }
    }
}

/// Port-side matcher for a typed allowlist entry: a single port or the
/// wildcard that matches every destination port (`HOST:*`), which lets
/// a user allow all traffic to a given IP/CIDR/hostname.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMatcher {
    /// Match any destination port.
    Any,
    /// Match exactly this port.
    Single(u16),
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatcher::Any => true,
            PortMatcher::Single(p) => *p == port,
        }
    }
}

impl std::fmt::Display for PortMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortMatcher::Any => write!(f, "*"),
            PortMatcher::Single(p) => write!(f, "{p}"),
        }
    }
}

/// Raw entry as it appears in the JSON file. Host is `String` so we
/// can defer the IPv4 / IPv6 / hostname classification to load time;
/// `port` is a [`RawPort`] so `"*"` (any port) is accepted alongside
/// a bare number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RawEgressEntry {
    pub host: String,
    pub port: RawPort,
    pub protocol: Protocol,
}

/// How the in-enclave resolver (`unbound`) answers workload queries.
///
/// This knob only widens or narrows name *resolution*. Connect-time
/// enforcement (IP/CIDR entries plus hostname entries checked against
/// A records) is identical in both modes; a name the workload can
/// resolve is not a name it can connect to. The trade is the DNS
/// exfiltration surface: under `allowlist`, a workload cannot even ask
/// the resolver about names outside the allowlist, while under `open`
/// arbitrary queries reach the configured upstream resolvers.
///
/// Consumed by the builder's init script when it renders unbound.conf
/// (`local-zone: "." refuse` vs resolve-anything); the egress daemon
/// itself does not branch on it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    /// Default: refuse every name that is not an explicit
    /// hostname-shaped allowlist entry.
    #[default]
    Allowlist,
    /// Resolve any name the workload asks for.
    Open,
}

impl DnsMode {
    /// serde `skip_serializing_if` helper so canonical JSON emitted for
    /// pre-existing configs stays byte-identical (no `dns` key).
    pub fn is_default(&self) -> bool {
        matches!(self, DnsMode::Allowlist)
    }
}

impl std::str::FromStr for DnsMode {
    type Err = AllowlistFlagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allowlist" => Ok(DnsMode::Allowlist),
            "open" => Ok(DnsMode::Open),
            _ => Err(AllowlistFlagError::InvalidDnsMode(s.to_string())),
        }
    }
}

/// Schema version currently supported. Bump in lockstep with
/// `from_raw` when the on-disk shape changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Raw top-level JSON object.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RawAllowlist {
    /// Schema version. Only `SCHEMA_VERSION` is accepted today.
    pub version: u32,
    /// DNS resolvers the daemon is allowed to reach. Parsed here;
    /// enforcement belongs to the hostname-enforcement layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    /// The allow list itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<RawEgressEntry>,
    /// DNS resolution mode for the in-enclave resolver. Absent means
    /// [`DnsMode::Allowlist`], which is the pre-existing behaviour.
    #[serde(default, skip_serializing_if = "DnsMode::is_default")]
    pub dns: DnsMode,
}

impl RawAllowlist {
    /// Construct an empty schema-version-1 document. Useful for the
    /// CLI/backend assembly path that builds the allowlist from flags
    /// rather than reading a JSON file off disk.
    pub fn new_v1() -> Self {
        Self {
            version: SCHEMA_VERSION,
            resolvers: Vec::new(),
            egress: Vec::new(),
            dns: DnsMode::default(),
        }
    }
}

/// Address-side half of an allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostMatcher {
    /// Match exactly one IPv4 address.
    Literal(Ipv4Addr),
    /// Match any IPv4 address inside the CIDR block.
    Cidr(Ipv4Net),
}

impl HostMatcher {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        match self {
            HostMatcher::Literal(a) => *a == ip,
            HostMatcher::Cidr(net) => net.contains(&ip),
        }
    }
}

/// One canonical, typed IP-shaped allowlist entry.
#[derive(Clone, Debug)]
pub struct AllowlistEntry {
    pub host: HostMatcher,
    pub port: PortMatcher,
    pub protocol: Protocol,
    /// When true, the entry only matches connections originating from
    /// the daemon's trusted source address (the init-netns side, i.e.
    /// `unbound`), never from the workload. Set for the auto-injected
    /// `resolvers[i]:53/tcp` entries so a workload cannot sidestep the
    /// in-enclave resolver by dialing the upstream resolvers directly
    /// (the resolver-bypass hardening). Never true for user-supplied
    /// entries; there is no JSON surface for it.
    pub trusted_source_only: bool,
}

/// One canonical, typed hostname-shaped allowlist entry. Enforced via
/// a stub query to the in-enclave `unbound`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostnameEntry {
    /// Lowercased ASCII hostname. We do not preserve trailing dots; the
    /// resolver code re-adds them as part of building a `Name`.
    pub host: String,
    pub port: PortMatcher,
    pub protocol: Protocol,
}

/// Parsed, validated allowlist ready to hand to the policy matcher.
#[derive(Clone, Debug, Default)]
pub struct AllowlistConfig {
    /// IP- and CIDR-bound entries, evaluated in order on every
    /// connect. Order is not significant for correctness; the matcher
    /// short-circuits on the first hit.
    pub entries: Vec<AllowlistEntry>,
    /// Resolvers declared in the JSON file. The in-enclave daemon does
    /// not talk to these resolvers directly: `unbound` does (forwarder
    /// upstream, DNS-over-TCP). The daemon mirrors `resolvers[i]:53/tcp`
    /// into `entries` at boot so `unbound`'s own egress is permitted
    /// without the operator having to spell it out.
    pub resolvers: Vec<Ipv4Addr>,
    /// Hostname-shaped allow entries. Enforced by querying the
    /// in-enclave `unbound` at connect time and checking the
    /// destination IP against the returned A records.
    pub hostnames: Vec<HostnameEntry>,
    /// Resolution mode carried through from the raw document. The
    /// daemon's connect-time policy does not branch on this; it is
    /// here so consumers of the typed config see the same document
    /// the builder's init script renders unbound.conf from.
    pub dns: DnsMode,
}

/// Errors surfaced while loading the allowlist from disk.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistLoadError {
    #[error("I/O error reading {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("JSON parse error in {0}: {1}")]
    Json(PathBuf, serde_json::Error),
    #[error("unsupported allowlist schema version {0} (expected 1)")]
    UnsupportedVersion(u32),
    #[error("UDP egress is not supported yet (entry `{host}:{port}/udp`); see https://github.com/EnclaviaIO/enclavia/issues/1")]
    UdpNotSupported { host: String, port: String },
    #[error("invalid port `{0}` (expected 1..=65535 or \"*\" for any port)")]
    BadPort(String),
    #[error("`dns: open` requires at least one IPv4 entry in `resolvers` (the in-enclave resolver has no upstream to forward to)")]
    DnsOpenWithoutResolvers,
}

impl AllowlistConfig {
    /// Empty == deny everything. The supervisor's policy treats this
    /// the same way as a missing config file.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load + parse the allowlist from `path`. Missing file is not an
    /// error: it returns [`Self::empty`] (deny-all) so the daemon can
    /// boot before the operator has dropped a policy in.
    pub fn load_or_empty(path: &Path) -> Result<Self, AllowlistLoadError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(path = %path.display(), "Allowlist file missing, defaulting to deny-all");
                return Ok(Self::empty());
            }
            Err(e) => return Err(AllowlistLoadError::Io(path.to_path_buf(), e)),
        };
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            warn!(path = %path.display(), "Allowlist file is empty, defaulting to deny-all");
            return Ok(Self::empty());
        }
        Self::from_bytes(&bytes).map_err(|e| match e {
            AllowlistLoadError::Io(_, ioe) => AllowlistLoadError::Io(path.to_path_buf(), ioe),
            AllowlistLoadError::Json(_, je) => AllowlistLoadError::Json(path.to_path_buf(), je),
            other => other,
        })
    }

    /// Parse from raw JSON bytes. Public so unit tests can exercise the
    /// parser without touching the filesystem.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AllowlistLoadError> {
        let raw: RawAllowlist = serde_json::from_slice(bytes)
            .map_err(|e| AllowlistLoadError::Json(PathBuf::new(), e))?;
        Self::from_raw(raw)
    }

    /// Convert the JSON-shaped struct into the typed allowlist.
    ///
    /// Classification per entry:
    ///   - parses as `a.b.c.d/n`     -> `HostMatcher::Cidr`
    ///   - parses as `a.b.c.d`       -> `HostMatcher::Literal`
    ///   - parses as IPv6 literal    -> logged + dropped (always-deny)
    ///   - anything else (hostname)  -> `HostnameEntry`, enforced via the
    ///     in-enclave resolver
    ///
    /// Duplicates are not deduped; the matcher's short-circuit means
    /// they cost a little memory but cannot cause a logic bug.
    pub fn from_raw(raw: RawAllowlist) -> Result<Self, AllowlistLoadError> {
        if raw.version != 1 {
            return Err(AllowlistLoadError::UnsupportedVersion(raw.version));
        }

        let mut entries = Vec::new();
        let mut hostnames = Vec::new();
        for raw_entry in raw.egress {
            // UDP entries used to be accepted by the schema and silently
            // ignored at runtime (the daemon is TCP-only). That's footgun-y;
            // reject upfront with a clear error pointing at the tracking
            // issue. When the daemon learns UDP this check goes away.
            if matches!(raw_entry.protocol, Protocol::Udp) {
                return Err(AllowlistLoadError::UdpNotSupported {
                    host: raw_entry.host.trim().to_string(),
                    port: raw_entry.port.to_string(),
                });
            }
            // Validate `port` (number in 1..=65535 or "*") before host
            // classification so a bad port errors regardless of host shape.
            let port = raw_entry.port.to_matcher()?;
            let host = raw_entry.host.trim().to_string();
            if let Ok(net) = host.parse::<Ipv4Net>() {
                entries.push(AllowlistEntry {
                    host: HostMatcher::Cidr(net),
                    port,
                    protocol: raw_entry.protocol,
                    trusted_source_only: false,
                });
                continue;
            }
            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => entries.push(AllowlistEntry {
                    host: HostMatcher::Literal(v4),
                    port,
                    protocol: raw_entry.protocol,
                    trusted_source_only: false,
                }),
                Ok(IpAddr::V6(v6)) => {
                    warn!(
                        host = %v6,
                        port = %port,
                        protocol = ?raw_entry.protocol,
                        "Ignoring IPv6 allowlist entry: IPv6 egress is always denied",
                    );
                }
                Err(_) => {
                    hostnames.push(HostnameEntry {
                        host: host.to_ascii_lowercase(),
                        port,
                        protocol: raw_entry.protocol,
                    });
                }
            }
        }

        let mut resolvers = Vec::new();
        for r in raw.resolvers {
            match r.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => resolvers.push(v4),
                Ok(IpAddr::V6(v6)) => {
                    warn!(resolver = %v6, "Ignoring IPv6 resolver: IPv6 egress is always denied");
                }
                Err(_) => {
                    warn!(resolver = %r, "Ignoring non-IPv4 resolver entry");
                }
            }
        }

        // `dns: open` with no usable resolver is always a
        // misconfiguration: unbound would accept any query and then
        // SERVFAIL every one of them. Reject it here so the CLI and
        // the backend surface the error at submit time instead of the
        // enclave shipping a resolver that can never answer. The
        // equivalent hostname-entries-without-resolvers case stays a
        // boot-time warning for backward compatibility.
        if raw.dns == DnsMode::Open && resolvers.is_empty() {
            return Err(AllowlistLoadError::DnsOpenWithoutResolvers);
        }

        Ok(Self {
            entries,
            resolvers,
            hostnames,
            dns: raw.dns,
        })
    }

    /// True iff there is at least one TCP IP/CIDR entry that matches
    /// `(ip, port)`. Hostname entries are NOT consulted here; they are
    /// evaluated separately by the policy (which needs an async
    /// resolver call).
    ///
    /// `trusted_src` says whether the connection originated from the
    /// daemon's trusted source address (init-netns infra, i.e.
    /// `unbound`) rather than the workload. Entries flagged
    /// `trusted_source_only` (the auto-injected resolver entries) only
    /// match when it is true; user-supplied entries match either way.
    pub fn allows_tcp(&self, ip: Ipv4Addr, port: u16, trusted_src: bool) -> bool {
        self.entries.iter().any(|e| {
            matches!(e.protocol, Protocol::Tcp)
                && e.port.matches(port)
                && e.host.contains(ip)
                && (!e.trusted_source_only || trusted_src)
        })
    }

    /// Iterator over hostname TCP entries whose port matches `port`.
    /// The policy calls this when an IP/CIDR miss happens and needs to
    /// know which hostnames are worth resolving for the current connect.
    pub fn tcp_hostnames_for_port(&self, port: u16) -> impl Iterator<Item = &HostnameEntry> {
        self.hostnames
            .iter()
            .filter(move |h| matches!(h.protocol, Protocol::Tcp) && h.port.matches(port))
    }

    /// Append a fresh IP literal entry. Used at boot to auto-inject the
    /// resolvers from the JSON file (`resolvers[i]:53/tcp`) so the
    /// in-enclave `unbound` can reach them through the egress path.
    pub fn push_entry(&mut self, entry: AllowlistEntry) {
        self.entries.push(entry);
    }
}

/// Errors surfaced while parsing CLI / backend flag input.
///
/// These wrap [`AllowlistLoadError`] for the "assembled-then-validated"
/// path: callers build a [`RawAllowlist`] from flags, then run it
/// through the same `from_raw` pipeline the on-disk loader uses so the
/// CLI, the backend, and the in-enclave daemon all agree on what is
/// well-formed.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistFlagError {
    #[error("egress allow spec must be HOST:PORT[/PROTO] (got `{0}`)")]
    BadEntryShape(String),
    #[error("egress allow spec `{0}` is missing the :PORT segment")]
    MissingPort(String),
    #[error("egress allow spec `{0}` has an invalid port: {1}")]
    InvalidPort(String, std::num::ParseIntError),
    #[error("egress allow spec `{0}` has port 0 (must be 1..=65535)")]
    PortZero(String),
    #[error("egress allow spec `{0}` has an unsupported protocol `{1}` (expected tcp or udp)")]
    UnsupportedProtocol(String, String),
    #[error("egress allow spec `{0}` has an empty host")]
    EmptyHost(String),
    #[error("egress allow spec `{0}` uses an IPv6 host; IPv6 egress is always denied")]
    IpV6Host(String),
    #[error("egress allow spec `{spec}` has invalid hostname `{host}`: {reason}")]
    InvalidHostname { spec: String, host: String, reason: &'static str },
    #[error("resolver spec `{0}` must be an IPv4 address")]
    InvalidResolver(String),
    #[error("dns mode `{0}` is not recognised (expected `allowlist` or `open`)")]
    InvalidDnsMode(String),
    #[error("invalid allowlist: {0}")]
    Validation(#[from] AllowlistLoadError),
}

/// Parse one CLI / backend-flag entry like `HOST:PORT[/PROTO]` into a
/// canonical [`RawEgressEntry`]. Used by `--egress-allow HOST:PORT[/PROTO]`
/// on the CLI and by the backend's POST /enclaves validator so both gate
/// on the same grammar.
///
/// Forms accepted:
///   - `1.2.3.4:443`
///   - `10.0.0.0/8:443`
///   - `api.example.com:443`
///   - `1.2.3.4:*` (any-port wildcard: allow all ports to the host)
///   - any of the above with an explicit `/tcp` or `/udp` suffix
///
/// Defaults to `tcp` when the protocol suffix is omitted (tcp is the
/// only thing actually enforced today; udp entries parse but don't
/// fire).
pub fn parse_cli_entry(spec: &str) -> Result<RawEgressEntry, AllowlistFlagError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(AllowlistFlagError::BadEntryShape(spec.to_string()));
    }

    // Strip the optional `/tcp` / `/udp` suffix from the right so the
    // CIDR slash (e.g. `10.0.0.0/8`) doesn't get confused with the
    // protocol slash. The suffix is only recognised when it appears
    // *after* the port — a spec like `10.0.0.0/8:443` has a slash but
    // no proto tail, so we leave the whole string alone and let the
    // host:port split below pick up `10.0.0.0/8` as the host.
    let (head, protocol) = match trimmed.rsplit_once('/') {
        Some((head, tail)) if !tail.contains(':') => {
            match tail.to_ascii_lowercase().as_str() {
                "tcp" => (head, Protocol::Tcp),
                "udp" => (head, Protocol::Udp),
                _ => {
                    return Err(AllowlistFlagError::UnsupportedProtocol(
                        spec.to_string(),
                        tail.to_string(),
                    ));
                }
            }
        }
        _ => (trimmed, Protocol::Tcp),
    };

    // Now split the host:port on the *last* `:` so CIDR slashes in HOST
    // (which always sit left of the colon) are preserved verbatim.
    let (host, port_str) = head
        .rsplit_once(':')
        .ok_or_else(|| AllowlistFlagError::MissingPort(spec.to_string()))?;

    let host = host.trim();
    if host.is_empty() {
        return Err(AllowlistFlagError::EmptyHost(spec.to_string()));
    }

    // `*` is the any-port wildcard (`HOST:*`); otherwise a 1..=65535
    // number. Both round-trip through `from_raw`'s validation.
    let port = if port_str.trim() == RawPort::WILDCARD {
        RawPort::Str(RawPort::WILDCARD.to_string())
    } else {
        let n: u16 = port_str
            .trim()
            .parse()
            .map_err(|e| AllowlistFlagError::InvalidPort(spec.to_string(), e))?;
        if n == 0 {
            return Err(AllowlistFlagError::PortZero(spec.to_string()));
        }
        RawPort::Num(n)
    };

    // Up-front rejection of obviously-bad hosts. The `from_raw` pipeline
    // would otherwise silently demote them to hostname entries that
    // never resolve, so we'd lose the early error.
    if host.parse::<Ipv4Net>().is_err() && host.parse::<Ipv4Addr>().is_err() {
        // Not an IPv4 literal/CIDR — has to be a hostname. v6 lands here.
        if let Ok(IpAddr::V6(_)) = host.parse::<IpAddr>() {
            return Err(AllowlistFlagError::IpV6Host(spec.to_string()));
        }
        if let Err(reason) = validate_hostname(host) {
            return Err(AllowlistFlagError::InvalidHostname {
                spec: spec.to_string(),
                host: host.to_string(),
                reason,
            });
        }
    }

    Ok(RawEgressEntry {
        host: host.to_string(),
        port,
        protocol,
    })
}

/// Validate a resolver spec from `--egress-resolver`. IPv4 only —
/// `unbound` upstream resolvers must be IPv4 literals because IPv6
/// egress is denied across the whole policy.
pub fn parse_cli_resolver(spec: &str) -> Result<String, AllowlistFlagError> {
    let trimmed = spec.trim();
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok(trimmed.to_string()),
        _ => Err(AllowlistFlagError::InvalidResolver(spec.to_string())),
    }
}

/// Assemble a canonical [`RawAllowlist`] from CLI-style inputs and
/// validate it by running through the same `from_raw` pipeline the
/// in-enclave daemon uses. Returns the typed structure on success;
/// callers serialise it back to JSON with `serde_json::to_*`.
///
/// `allow_specs` are `HOST:PORT[/PROTO]` strings. `resolver_specs` are
/// IPv4 literals. Either list may be empty; an empty allowlist is
/// deny-all on the daemon side, which is the same behaviour as a
/// missing file. `dns` is the resolution mode; `None` means the
/// default ([`DnsMode::Allowlist`]).
pub fn assemble_from_cli(
    allow_specs: &[&str],
    resolver_specs: &[&str],
    dns: Option<DnsMode>,
) -> Result<RawAllowlist, AllowlistFlagError> {
    let mut raw = RawAllowlist::new_v1();
    for s in allow_specs {
        raw.egress.push(parse_cli_entry(s)?);
    }
    for r in resolver_specs {
        raw.resolvers.push(parse_cli_resolver(r)?);
    }
    if let Some(dns) = dns {
        raw.dns = dns;
    }
    // Run the typed-validation pipeline so CLI/backend/daemon agree on
    // what is well-formed. We discard the typed config here — the
    // caller wants the canonical JSON-shaped struct — but a failure
    // here means the daemon would reject the same input at boot.
    AllowlistConfig::from_raw(raw.clone()).map_err(AllowlistFlagError::Validation)?;
    Ok(raw)
}

/// Validate a JSON-shaped allowlist supplied by the frontend / API
/// without a CLI parse step. Backend uses this on POST /enclaves.
///
/// Accepts either a raw `serde_json::Value` (frontend POSTs a JSON
/// object) or anything that deserialises into [`RawAllowlist`]. On
/// success returns the canonical struct so the caller can re-serialise
/// it for storage; on failure returns the same `AllowlistFlagError`
/// the CLI path uses, so error messages stay consistent.
pub fn validate_json(value: &serde_json::Value) -> Result<RawAllowlist, AllowlistFlagError> {
    let raw: RawAllowlist = serde_json::from_value(value.clone()).map_err(|e| {
        AllowlistFlagError::Validation(AllowlistLoadError::Json(PathBuf::new(), e))
    })?;
    AllowlistConfig::from_raw(raw.clone()).map_err(AllowlistFlagError::Validation)?;
    Ok(raw)
}

/// Minimum-effort hostname validation: RFC 1035-ish syntax check that
/// catches obvious garbage (empty labels, leading/trailing dots,
/// invalid chars) without trying to be a full IDNA validator. We don't
/// resolve here — the in-enclave daemon's DNS query is the real test —
/// but rejecting `foo!bar` at the CLI is more useful than waiting for
/// the resolver to silently never match.
fn validate_hostname(host: &str) -> Result<(), &'static str> {
    if host.is_empty() {
        return Err("empty hostname");
    }
    if host.len() > 253 {
        return Err("hostname exceeds 253 characters");
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err("hostname must not start or end with a dot");
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("hostname contains an empty label (consecutive dots)");
        }
        if label.len() > 63 {
            return Err("hostname label exceeds 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("hostname label must not start or end with a hyphen");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("hostname label has invalid characters (allowed: a-z, 0-9, '-')");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_and_cidr_entries() {
        let raw = br#"{
            "version": 1,
            "resolvers": ["1.1.1.1"],
            "egress": [
                {"host": "10.0.0.0/8", "port": 443, "protocol": "tcp"},
                {"host": "1.2.3.4",   "port": 80,  "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.resolvers, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(matches!(cfg.entries[0].host, HostMatcher::Cidr(_)));
        assert!(matches!(cfg.entries[1].host, HostMatcher::Literal(_)));
    }

    #[test]
    fn hostnames_are_recognized_as_first_class() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "api.openai.com", "port": 443, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert!(cfg.entries.is_empty());
        assert_eq!(cfg.hostnames.len(), 1);
        assert_eq!(cfg.hostnames[0].host, "api.openai.com");
        assert_eq!(cfg.hostnames[0].port, PortMatcher::Single(443));
        assert!(matches!(cfg.hostnames[0].protocol, Protocol::Tcp));
    }

    #[test]
    fn hostnames_are_lowercased() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "API.Openai.COM", "port": 443, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.hostnames[0].host, "api.openai.com");
    }

    #[test]
    fn ipv6_literal_entries_are_dropped() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "::1", "port": 443, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert!(cfg.entries.is_empty());
        assert!(cfg.hostnames.is_empty());
    }

    #[test]
    fn hostnames_for_port_filters_by_port() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "a.example", "port": 443, "protocol": "tcp"},
                {"host": "b.example", "port": 80,  "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        let on_443: Vec<_> =
            cfg.tcp_hostnames_for_port(443).map(|h| h.host.as_str()).collect();
        assert_eq!(on_443, vec!["a.example"]);
    }

    #[test]
    fn udp_entry_in_json_is_rejected() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "1.1.1.1", "port": 53, "protocol": "udp"}
            ]
        }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must reject UDP");
        assert!(matches!(
            err,
            AllowlistLoadError::UdpNotSupported { ref host, ref port } if host == "1.1.1.1" && port == "53"
        ));
    }

    #[test]
    fn udp_entry_in_hostname_form_is_rejected() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "example.com", "port": 53, "protocol": "udp"}
            ]
        }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must reject UDP");
        assert!(matches!(err, AllowlistLoadError::UdpNotSupported { .. }));
    }

    #[test]
    fn udp_via_assemble_from_cli_is_rejected() {
        let err = assemble_from_cli(&["1.1.1.1:53/udp"], &[], None).expect_err("must reject UDP");
        assert!(matches!(
            err,
            AllowlistFlagError::Validation(AllowlistLoadError::UdpNotSupported { .. })
        ));
    }

    #[test]
    fn malformed_json_returns_error() {
        let raw = br#"{ "version": 1, "egress": [ ] "#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must fail");
        assert!(matches!(err, AllowlistLoadError::Json(_, _)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let raw = br#"{ "version": 2, "egress": [] }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must fail");
        assert!(matches!(err, AllowlistLoadError::UnsupportedVersion(2)));
    }

    #[test]
    fn missing_file_returns_empty() {
        let path = std::path::PathBuf::from("/tmp/this-path-does-not-exist-egress-XYZ.json");
        let cfg = AllowlistConfig::load_or_empty(&path).expect("missing file should not error");
        assert!(cfg.entries.is_empty());
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("egress.json");
        std::fs::write(&p, "\n\n  \n").unwrap();
        let cfg = AllowlistConfig::load_or_empty(&p).expect("load");
        assert!(cfg.entries.is_empty());
    }

    #[test]
    fn duplicate_entries_do_not_panic() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
                {"host": "1.2.3.4", "port": 80, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.entries.len(), 2);
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 80, false));
    }

    #[test]
    fn cli_entry_parses_literal_default_tcp() {
        let e = parse_cli_entry("1.2.3.4:443").unwrap();
        assert_eq!(e.host, "1.2.3.4");
        assert_eq!(e.port, RawPort::Num(443));
        assert_eq!(e.protocol, Protocol::Tcp);
    }

    #[test]
    fn cli_entry_parses_explicit_tcp() {
        let e = parse_cli_entry("1.2.3.4:443/tcp").unwrap();
        assert_eq!(e.protocol, Protocol::Tcp);
    }

    #[test]
    fn cli_entry_parses_explicit_udp() {
        let e = parse_cli_entry("1.2.3.4:53/udp").unwrap();
        assert_eq!(e.protocol, Protocol::Udp);
    }

    #[test]
    fn cli_entry_parses_cidr() {
        let e = parse_cli_entry("10.0.0.0/8:443").unwrap();
        assert_eq!(e.host, "10.0.0.0/8");
        assert_eq!(e.port, RawPort::Num(443));
    }

    #[test]
    fn cli_entry_parses_cidr_with_proto() {
        let e = parse_cli_entry("10.0.0.0/8:443/udp").unwrap();
        assert_eq!(e.host, "10.0.0.0/8");
        assert_eq!(e.protocol, Protocol::Udp);
    }

    #[test]
    fn cli_entry_parses_hostname() {
        let e = parse_cli_entry("api.example.com:443").unwrap();
        assert_eq!(e.host, "api.example.com");
        assert_eq!(e.port, RawPort::Num(443));
    }

    #[test]
    fn cli_entry_rejects_missing_port() {
        assert!(matches!(
            parse_cli_entry("api.example.com"),
            Err(AllowlistFlagError::MissingPort(_))
        ));
    }

    #[test]
    fn cli_entry_rejects_bad_port() {
        assert!(matches!(
            parse_cli_entry("api.example.com:abc"),
            Err(AllowlistFlagError::InvalidPort(_, _))
        ));
    }

    #[test]
    fn cli_entry_rejects_zero_port() {
        assert!(matches!(
            parse_cli_entry("1.2.3.4:0"),
            Err(AllowlistFlagError::PortZero(_))
        ));
    }

    #[test]
    fn cli_entry_rejects_unknown_protocol() {
        assert!(matches!(
            parse_cli_entry("1.2.3.4:443/sctp"),
            Err(AllowlistFlagError::UnsupportedProtocol(_, _))
        ));
    }

    #[test]
    fn cli_entry_rejects_bad_hostname() {
        assert!(matches!(
            parse_cli_entry("foo!bar.com:443"),
            Err(AllowlistFlagError::InvalidHostname { .. })
        ));
    }

    #[test]
    fn cli_entry_rejects_ipv6() {
        assert!(matches!(
            parse_cli_entry("::1:443"),
            Err(AllowlistFlagError::IpV6Host(_)) | Err(AllowlistFlagError::InvalidHostname { .. })
        ));
    }

    #[test]
    fn cli_resolver_accepts_ipv4() {
        assert_eq!(parse_cli_resolver("1.1.1.1").unwrap(), "1.1.1.1");
    }

    #[test]
    fn cli_resolver_rejects_hostname() {
        assert!(matches!(
            parse_cli_resolver("dns.example.com"),
            Err(AllowlistFlagError::InvalidResolver(_))
        ));
    }

    #[test]
    fn assemble_round_trips_through_from_raw() {
        let raw = assemble_from_cli(
            &["10.0.0.0/8:443", "api.example.com:443/tcp", "1.2.3.4:80"],
            &["1.1.1.1"],
            None,
        )
        .unwrap();
        assert_eq!(raw.version, SCHEMA_VERSION);
        assert_eq!(raw.egress.len(), 3);
        assert_eq!(raw.resolvers, vec!["1.1.1.1".to_string()]);

        // The typed config should accept this without complaint.
        let cfg = AllowlistConfig::from_raw(raw).unwrap();
        assert_eq!(cfg.entries.len(), 2); // CIDR + literal
        assert_eq!(cfg.hostnames.len(), 1);
        assert_eq!(cfg.resolvers.len(), 1);
    }

    #[test]
    fn validate_json_accepts_well_formed_doc() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"version": 1, "resolvers": ["1.1.1.1"], "egress": [{"host":"api.example.com","port":443,"protocol":"tcp"}]}"#,
        )
        .unwrap();
        let raw = validate_json(&v).unwrap();
        assert_eq!(raw.egress.len(), 1);
        assert_eq!(raw.resolvers.len(), 1);
    }

    #[test]
    fn validate_json_rejects_unknown_version() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"version": 2, "egress": []}"#).unwrap();
        assert!(matches!(
            validate_json(&v),
            Err(AllowlistFlagError::Validation(AllowlistLoadError::UnsupportedVersion(2)))
        ));
    }

    #[test]
    fn quad_zero_slash_zero_matches_everything() {
        let raw = br#"{
            "version": 1,
            "egress": [
                {"host": "0.0.0.0/0", "port": 19444, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 19444, false));
        assert!(cfg.allows_tcp(Ipv4Addr::new(192, 168, 1, 1), 19444, false));
        assert!(!cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 19445, false));
    }

    #[test]
    fn dns_mode_defaults_to_allowlist_when_absent() {
        let raw = br#"{ "version": 1, "egress": [] }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.dns, DnsMode::Allowlist);
    }

    #[test]
    fn dns_open_parses_with_resolvers() {
        let raw = br#"{
            "version": 1,
            "resolvers": ["1.1.1.1"],
            "dns": "open",
            "egress": [
                {"host": "0.0.0.0/0", "port": 443, "protocol": "tcp"}
            ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.dns, DnsMode::Open);
        assert_eq!(cfg.resolvers.len(), 1);
    }

    #[test]
    fn dns_open_without_resolvers_is_rejected() {
        let raw = br#"{ "version": 1, "dns": "open", "egress": [] }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must reject");
        assert!(matches!(err, AllowlistLoadError::DnsOpenWithoutResolvers));
    }

    #[test]
    fn dns_unknown_value_is_rejected_at_json_parse() {
        let raw = br#"{ "version": 1, "dns": "wide-open", "egress": [] }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must reject");
        assert!(matches!(err, AllowlistLoadError::Json(_, _)));
    }

    #[test]
    fn dns_default_is_not_serialised() {
        // Canonical JSON for pre-existing configs must stay
        // byte-identical: no `dns` key unless it is non-default.
        let raw = assemble_from_cli(&["1.2.3.4:80"], &[], None).unwrap();
        let v = serde_json::to_value(&raw).unwrap();
        assert!(v.get("dns").is_none());

        let raw = assemble_from_cli(&["1.2.3.4:80"], &["1.1.1.1"], Some(DnsMode::Open)).unwrap();
        let v = serde_json::to_value(&raw).unwrap();
        assert_eq!(v["dns"], "open");
    }

    #[test]
    fn dns_open_via_assemble_requires_resolver() {
        let err = assemble_from_cli(&["1.2.3.4:80"], &[], Some(DnsMode::Open))
            .expect_err("must reject open without resolvers");
        assert!(matches!(
            err,
            AllowlistFlagError::Validation(AllowlistLoadError::DnsOpenWithoutResolvers)
        ));
    }

    #[test]
    fn dns_mode_from_str_parses_and_rejects() {
        assert_eq!("open".parse::<DnsMode>().unwrap(), DnsMode::Open);
        assert_eq!("Allowlist".parse::<DnsMode>().unwrap(), DnsMode::Allowlist);
        assert!(matches!(
            "everything".parse::<DnsMode>(),
            Err(AllowlistFlagError::InvalidDnsMode(_))
        ));
    }

    #[test]
    fn validate_json_accepts_dns_open_doc() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"version": 1, "resolvers": ["1.1.1.1"], "dns": "open", "egress": [{"host":"0.0.0.0/0","port":443,"protocol":"tcp"}]}"#,
        )
        .unwrap();
        let raw = validate_json(&v).unwrap();
        assert_eq!(raw.dns, DnsMode::Open);
    }

    // --- Port wildcard (`HOST:*`) ---

    #[test]
    fn port_wildcard_literal_matches_every_port() {
        let raw = br#"{
            "version": 1,
            "egress": [ {"host": "1.2.3.4", "port": "*", "protocol": "tcp"} ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.entries[0].port, PortMatcher::Any);
        // Any port on the allowed IP passes; a different IP still fails.
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 443, false));
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 1, false));
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 65535, false));
        assert!(!cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 5), 443, false));
    }

    #[test]
    fn port_wildcard_cidr_matches_every_port() {
        let raw = br#"{
            "version": 1,
            "egress": [ {"host": "10.0.0.0/8", "port": "*", "protocol": "tcp"} ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert!(cfg.allows_tcp(Ipv4Addr::new(10, 1, 2, 3), 22, false));
        assert!(cfg.allows_tcp(Ipv4Addr::new(10, 9, 9, 9), 8080, false));
        assert!(!cfg.allows_tcp(Ipv4Addr::new(11, 0, 0, 1), 22, false));
    }

    #[test]
    fn port_wildcard_hostname_matches_every_port() {
        let raw = br#"{
            "version": 1,
            "egress": [ {"host": "api.example.com", "port": "*", "protocol": "tcp"} ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.hostnames[0].port, PortMatcher::Any);
        // The hostname entry is returned for any queried port.
        assert_eq!(cfg.tcp_hostnames_for_port(443).count(), 1);
        assert_eq!(cfg.tcp_hostnames_for_port(9000).count(), 1);
    }

    #[test]
    fn numeric_port_still_specific() {
        let raw = br#"{
            "version": 1,
            "egress": [ {"host": "1.2.3.4", "port": 443, "protocol": "tcp"} ]
        }"#;
        let cfg = AllowlistConfig::from_bytes(raw).expect("parse");
        assert_eq!(cfg.entries[0].port, PortMatcher::Single(443));
        assert!(cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 443, false));
        assert!(!cfg.allows_tcp(Ipv4Addr::new(1, 2, 3, 4), 444, false));
    }

    #[test]
    fn port_zero_rejected() {
        let raw = br#"{ "version": 1, "egress": [ {"host": "1.2.3.4", "port": 0, "protocol": "tcp"} ] }"#;
        let err = AllowlistConfig::from_bytes(raw).expect_err("must reject");
        assert!(matches!(err, AllowlistLoadError::BadPort(ref p) if p == "0"));
    }

    #[test]
    fn non_wildcard_port_string_rejected() {
        // A numeric string (not a bare number) and any non-`*` string
        // are rejected; the port must be a JSON number or exactly "*".
        for bad in [r#""443""#, r#""all""#, r#""8080-9090""#] {
            let raw = format!(
                r#"{{ "version": 1, "egress": [ {{"host": "1.2.3.4", "port": {bad}, "protocol": "tcp"}} ] }}"#
            );
            let err = AllowlistConfig::from_bytes(raw.as_bytes()).expect_err("must reject");
            assert!(matches!(err, AllowlistLoadError::BadPort(_)), "port {bad} should be rejected");
        }
    }

    #[test]
    fn port_wildcard_canonical_json_round_trips() {
        // `*` serialises back to the string; a numeric port to a number.
        let raw = assemble_from_cli(&["1.2.3.4:*", "5.6.7.8:443"], &[], None).unwrap();
        let v = serde_json::to_value(&raw).unwrap();
        assert_eq!(v["egress"][0]["port"], "*");
        assert_eq!(v["egress"][1]["port"], 443);
        // And it parses back to the same matchers.
        let cfg = AllowlistConfig::from_raw(raw).unwrap();
        assert_eq!(cfg.entries[0].port, PortMatcher::Any);
        assert_eq!(cfg.entries[1].port, PortMatcher::Single(443));
    }

    #[test]
    fn cli_entry_parses_wildcard_port() {
        let e = parse_cli_entry("1.2.3.4:*").unwrap();
        assert_eq!(e.host, "1.2.3.4");
        assert_eq!(e.port, RawPort::Str("*".to_string()));
        // With an explicit proto too.
        let e = parse_cli_entry("10.0.0.0/8:*/tcp").unwrap();
        assert_eq!(e.host, "10.0.0.0/8");
        assert_eq!(e.port, RawPort::Str("*".to_string()));
    }

    #[test]
    fn validate_json_accepts_wildcard_port() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"version": 1, "egress": [{"host":"1.2.3.4","port":"*","protocol":"tcp"}]}"#,
        )
        .unwrap();
        let raw = validate_json(&v).expect("valid");
        assert_eq!(raw.egress[0].port, RawPort::Str("*".to_string()));
    }
}
