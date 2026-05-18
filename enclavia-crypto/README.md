# enclavia-crypto

In-enclave key management. Talks the AWS KMS `TrentService` protocol over vsock to either a production KMS proxy on the parent or the [`mock-kms`](../mock-kms/) dev daemon, and:

1. **First boot of a storage-enabled enclave**: generates a fresh LUKS passphrase, calls `GetPublicKey` against the per-enclave KMS key (whose policy is PCR-bound), locally RSA-OAEP encrypts the passphrase to that pubkey, and writes the ciphertext blob to the first 4 KiB of the backing file via the host-side key-blob protocol on vsock port `5002`.
2. **Subsequent boots**: reads the blob back, calls `Decrypt` with a Nitro attestation document attached as `Recipient`, KMS validates the PCRs server-side, returns the plaintext passphrase, and `enclavia-crypto` writes it to `/tmp/luks.key` for `cryptsetup luksOpen` to consume.
3. **Upgrade flow** (`prepare-upgrade` subcommand): triggered by a signed `Control` command relayed through `enclavia-server`. Adds a new LUKS keyslot encrypted under the new version's KMS key, kills the old slot, updates the on-disk blob, and stashes the old key id so the new enclave can call `ScheduleKeyDeletion` after boot.

Used by `init.sh` in the EIF rootfs. The unsealed device is then layered on top by `cryptsetup` and consumed by [`nbd-client`](../nbd-client/).

vsock-only.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
