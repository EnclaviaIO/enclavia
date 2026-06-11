# synchronizer

In-enclave storage synchronization. Replicates the LUKS-encrypted volume's freshness state across a mutually-attested vsock mesh between enclaves, so storage-enabled enclaves can quiesce, fail over, and recover without losing data or accepting stale reads.

The mesh is **mutually attested**: each peer connects to the others over vsock via the host-side `mesh-host` relay daemon (shipped from enclavia-crates, out of this repo's scope; wire format in `enclavia-protocol::mesh`), wraps the byte stream in end-to-end Noise, and only accepts the peer's PCRs after verifying its Nitro attestation. From the storage layer's point of view, the synchronizer is a small Raft cluster that tracks the latest transaction id per superblock; from the security layer's point of view, it is a closed group of identical EIFs talking to themselves.

Current scope (incremental):
- Single-node listener binary and protocol skeleton (shipped).
- Transition authorized by a #47 upgrade chain link. The NEW enclave submits it: at cutover the old enclave has stopped, so the new enclave boots, attests as `new_key`, and presents the link it read from its chain. The link is emitted by the OLD enclave during its prepare-upgrade flow, so it carries the old enclave's NSM attestation (PCRs = `from_pcrs`) and the old control key's 64-byte raw r||s ECDSA P-256 signature over the `UpgradePayload`. The synchronizer derives `old_key`/`new_key` from the payload (`from_pcrs`/`to_pcrs` hashes), requires `new_key` to equal the submitting session, and verifies the signature against the control pubkey frozen for `old_key` at its first registration (shipped). Control keys are P-256 throughout (no Ed25519).
- Multi-node mesh, PCR-bound peer authentication (in progress).
- Raft state machine for the freshness map, follower-redirect on writes, hydrate-from-peers on restart, cold-start recovery (tracked as separate sub-issues).

vsock-only.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
