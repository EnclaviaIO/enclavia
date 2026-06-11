//! Mesh configuration: the node's own logical name, its peer set, and the
//! self-PCR allowlist that gates which peers it will admit.
//!
//! ## Self-PCR allowlist (the trust model)
//!
//! The synchronizer cluster is a closed set of *identical* EIFs: every node
//! runs the same image, so every node measures the same PCR0/1/2. A node
//! therefore admits a peer only when the peer's attested PCR digest equals
//! its OWN image measurements. There is no separate "trusted peer PCR list":
//! the allowlist is a singleton, `{ self_pcr_digest }`. It is deliberately
//! un-upgradable in v1 (the #16 design pass froze the mesh allowlist to
//! exactly the node's own PCR digest, no successor-PCR admission, no
//! config-driven list).
//!
//! The own-PCR digest is HARDWARE-derived at startup, not host-supplied. The
//! node requests a fresh attestation document from its OWN `/dev/nsm` and reads
//! back its PCR0/1/2 via
//! [`enclavia_protocol::attestation::extract_own_pcrs`] (see `read_mesh_env` in
//! the binary). This works identically in production and under QEMU: QEMU's
//! nitro-enclave machine emulates `/dev/nsm` and measures the real PCR0/1/2 of
//! the running VM (self-signed chain), and because the node is reading its OWN
//! local device, inside its trusted computing base, no cert-chain trust is
//! needed (the document authenticates nothing remote; it just reports this VM's
//! own measurements). The earlier design read the digest from host-supplied env
//! (`MESH_SELF_PCR*`), but the host is the adversary: a host-chosen digest could
//! admit a rogue image into the mesh and Raft, so the env path was removed
//! outright (an override would reopen the hole). Test-utils tests still pass an
//! explicit digest to [`MeshConfig::new`]; only the production launcher path is
//! hardware-derived.
//!
//! Logical peer names are opaque strings that match what `mesh-host` resolves
//! to a concrete host endpoint. This module never sees host endpoints: it
//! only names peers and hands the name to `mesh-host` in the
//! [`enclavia_protocol::mesh::Open`] frame. Names are routing labels only;
//! identity comes from attestation.

use std::collections::{BTreeMap, BTreeSet};

use crate::PcrKey;

/// Logical name of a synchronizer peer. Opaque to this crate; resolved to a
/// concrete host endpoint by `mesh-host`. Matches the `target_peer` field of
/// [`enclavia_protocol::mesh::Open`].
pub type PeerName = String;

/// The set of PCR digests a node will admit a peer under.
///
/// In v1 this is always a singleton equal to the node's own image
/// measurements (see the module docs): the cluster is its own peer set. The
/// type is a set rather than a single value only so the rejection path and
/// tests read naturally; [`PcrAllowlist::self_only`] is the sole constructor
/// the production launcher uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrAllowlist {
    allowed: BTreeSet<PcrKey>,
}

impl PcrAllowlist {
    /// Allowlist admitting exactly the node's own image measurements.
    pub fn self_only(self_pcr_digest: PcrKey) -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(self_pcr_digest);
        Self { allowed }
    }

    /// Whether a peer presenting `digest` (the SHA-256 of its attested
    /// PCR0/1/2) is admitted.
    pub fn admits(&self, digest: &PcrKey) -> bool {
        self.allowed.contains(digest)
    }
}

/// Static, launch-time mesh configuration for one node.
///
/// Cloned cheaply into each per-peer task. The peer set lists the *other*
/// nodes (a node never dials itself); `self_name` is this node's own logical
/// name, announced to peers so they can attribute its dialed connection.
#[derive(Clone, Debug)]
pub struct MeshConfig {
    /// This node's own logical name.
    pub self_name: PeerName,
    /// The other nodes in the cluster, by logical name. Each becomes one
    /// long-lived outbound dial task (plus this node's inbound accept loop
    /// receives their dials in turn).
    pub peers: Vec<PeerName>,
    /// PCR digests this node admits a peer under. Always
    /// [`PcrAllowlist::self_only`] in v1.
    pub allowlist: PcrAllowlist,
}

impl MeshConfig {
    /// Build a config for a node named `self_name` whose peer set is `peers`
    /// and whose admitted PCR digest is its own `self_pcr_digest`.
    ///
    /// `peers` must not contain `self_name` (a node never dials itself);
    /// `self_name` is dropped if present, and duplicate peer names are
    /// de-duplicated, preserving first-seen order.
    pub fn new(
        self_name: impl Into<PeerName>,
        peers: impl IntoIterator<Item = PeerName>,
        self_pcr_digest: PcrKey,
    ) -> Self {
        let self_name = self_name.into();
        let mut seen = BTreeMap::new();
        let mut ordered = Vec::new();
        for p in peers {
            if p == self_name {
                continue;
            }
            if seen.insert(p.clone(), ()).is_none() {
                ordered.push(p);
            }
        }
        Self {
            self_name,
            peers: ordered,
            allowlist: PcrAllowlist::self_only(self_pcr_digest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PcrKey {
        PcrKey([b; 32])
    }

    #[test]
    fn allowlist_admits_only_self() {
        let al = PcrAllowlist::self_only(key(1));
        assert!(al.admits(&key(1)));
        assert!(!al.admits(&key(2)));
    }

    #[test]
    fn config_drops_self_from_peer_set() {
        let cfg = MeshConfig::new(
            "node-a",
            [
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string(),
            ],
            key(7),
        );
        assert_eq!(cfg.self_name, "node-a");
        assert_eq!(cfg.peers, vec!["node-b".to_string(), "node-c".to_string()]);
    }

    #[test]
    fn config_dedups_peers_preserving_order() {
        let cfg = MeshConfig::new(
            "a",
            [
                "c".to_string(),
                "b".to_string(),
                "c".to_string(),
                "b".to_string(),
            ],
            key(0),
        );
        assert_eq!(cfg.peers, vec!["c".to_string(), "b".to_string()]);
    }
}
