# nbd-client

In-enclave NBD client. Connects to the host-side `storage-host` daemon over vsock (typically port `5001`), negotiates the NBD handshake, and exposes the result as `/dev/nbd0` inside the enclave. The unsealed LUKS device gets layered on top via [`enclavia-crypto`](../enclavia-crypto/) + `cryptsetup`, and the filesystem (btrfs) is mounted on the resulting `/dev/mapper/encdata`.

Also serves as a userspace filter point: writes to the well-known btrfs superblock offsets (`64 KiB`, `64 MiB`, `256 GiB`) are observed and forwarded to [`synchronizer`](../synchronizer/) so it can track the freshness of the volume across the mesh. The host-side relay sees only encrypted blocks; the synchronizer's view is post-LUKS but pre-FS-decryption-of-data (we read superblocks, not file contents).

vsock-only.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
