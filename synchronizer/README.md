# synchronizer

In-enclave storage synchronization. Replicates the LUKS-encrypted volume's freshness state across a mutually-attested vsock mesh between enclaves, so storage-enabled enclaves can quiesce, fail over, and recover without losing data or accepting stale reads.

The mesh is **mutually attested**: each peer connects to the others over vsock via the host-side `mesh-proxy` daemon (out of repo scope), wraps the byte stream in Noise, and only accepts the peer's PCRs after verifying its Nitro attestation. From the storage layer's point of view, the synchronizer is a small Raft cluster that tracks the latest transaction id per superblock; from the security layer's point of view, it is a closed group of identical EIFs talking to themselves.

Current scope (incremental):
- Single-node listener binary and protocol skeleton (shipped).
- Multi-node mesh, Ed25519 transition-sig verification, PCR-bound peer authentication (in progress).
- Raft state machine for the freshness map, follower-redirect on writes, hydrate-from-peers on restart, cold-start recovery (tracked as separate sub-issues).

vsock-only.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
