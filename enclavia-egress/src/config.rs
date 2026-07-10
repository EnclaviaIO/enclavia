//! Daemon configuration parsed from environment variables, plus the
//! on-disk allowlist schema consumed at boot.
//!
//! The runtime knobs (TUN device, MTU, vsock peer) live in [`Config`]
//! and come from `EGRESS_*` env vars. The policy itself is loaded from
//! a JSON file (default `/etc/enclavia/egress.json`, override with
//! `EGRESS_CONFIG_PATH`) and exposed as [`AllowlistConfig`].

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Runtime configuration for the egress daemon.
#[derive(Clone, Debug)]
pub struct Config {
    /// TUN device name to open.
    pub tun_name: String,
    /// Local IPv4 address smoltcp owns inside the TUN subnet. The
    /// workload's default route points at this address.
    pub tun_local_ip: Ipv4Addr,
    /// Prefix length for `tun_local_ip` (the workload sits in the
    /// matching `/prefix` subnet).
    pub tun_prefix_len: u8,
    /// MTU advertised to smoltcp and the kernel.
    pub mtu: usize,
    /// Vsock port `egress-host` listens on.
    pub vsock_port: u32,
    /// Path to the JSON allowlist file. Missing or empty == deny-all.
    pub allowlist_path: PathBuf,
    /// Source address that in-enclave infrastructure (the isolated
    /// `unbound`) egresses from. Connections observed on `tun0` with
    /// this source may match the auto-injected `resolvers[i]:53/tcp`
    /// entries; workload connections (any other source) may not. See
    /// [`crate::inject_resolver_entries`] and the in-enclave
    /// resolver-bypass hardening.
    ///
    /// Defaults to `tun_local_ip`: pre-netns-split, ALL traffic
    /// (workload included) sources from the tun address, so the gate
    /// is inert and behaviour matches the shared-netns topology. The
    /// builder sets `EGRESS_TRUSTED_SRC` to the resolver netns'
    /// veth address once `unbound` is isolated, at which point the
    /// gate distinguishes resolver traffic from workload traffic.
    pub trusted_src: Ipv4Addr,
}

impl Config {
    pub fn from_env() -> Self {
        let tun_name = std::env::var("EGRESS_TUN_NAME").unwrap_or_else(|_| "tun0".into());
        let tun_local_ip: Ipv4Addr = std::env::var("EGRESS_TUN_LOCAL_IP")
            .unwrap_or_else(|_| "10.99.0.1".into())
            .parse()
            .expect("invalid EGRESS_TUN_LOCAL_IP");
        let tun_prefix_len: u8 = std::env::var("EGRESS_TUN_PREFIX_LEN")
            .unwrap_or_else(|_| "24".into())
            .parse()
            .expect("invalid EGRESS_TUN_PREFIX_LEN");
        let mtu: usize = std::env::var("EGRESS_MTU")
            .unwrap_or_else(|_| "1500".into())
            .parse()
            .expect("invalid EGRESS_MTU");
        let vsock_port: u32 = std::env::var("EGRESS_VSOCK_PORT")
            .unwrap_or_else(|_| "5006".into())
            .parse()
            .expect("invalid EGRESS_VSOCK_PORT");
        let allowlist_path = PathBuf::from(
            std::env::var("EGRESS_CONFIG_PATH")
                .unwrap_or_else(|_| "/etc/enclavia/egress.json".into()),
        );
        let trusted_src: Ipv4Addr = std::env::var("EGRESS_TRUSTED_SRC")
            .map(|s| s.parse().expect("invalid EGRESS_TRUSTED_SRC"))
            .unwrap_or(tun_local_ip);

        Self {
            tun_name,
            tun_local_ip,
            tun_prefix_len,
            mtu,
            vsock_port,
            allowlist_path,
            trusted_src,
        }
    }
}

// The allowlist schema itself (types, parsing, validation) moved to
// `enclavia_protocol::egress_config` so the CLI and backend can depend
// on it without dragging in the daemon stack. Re-exported here so
// `enclavia_egress::config::*` (and the crate-root re-exports below it)
// keep resolving for existing consumers.
pub use enclavia_protocol::egress_config::*;
