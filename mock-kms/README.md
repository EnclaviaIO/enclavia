# mock-kms

A small HTTP server that speaks just enough of the AWS KMS `TrentService` JSON protocol to let [`enclavia-crypto`](../enclavia-crypto/) run end to end without an AWS account. Used by the [builder](https://github.com/EnclaviaIO/builder)'s `test-storage-vm` wrapper for the QEMU dev path, and by the `process-compose` dev stack as the backend-side KMS for `CreateKey` traffic.

Implements:

| `X-Amz-Target` | What it does |
|---|---|
| `TrentService.CreateKey` | Generates a fresh RSA-2048 keypair, persists it under `KEY_DIR/<key-id>.json`. Stores the supplied policy verbatim so PCR-bound policies can round-trip in test. |
| `TrentService.GetPublicKey` | Returns the DER-encoded public key. |
| `TrentService.Encrypt` / `Decrypt` | RSA-OAEP with SHA-256. The `Decrypt` path also surfaces the `Recipient` attestation document so test code can assert on it. |
| `TrentService.ScheduleKeyDeletion` | Marks the key for deletion; subsequent `Decrypt` calls return `KMSInvalidStateException`, matching real KMS behaviour. |

Two listener modes:
- **Unix domain socket** (default for debug / QEMU dev VMs).
- **vsock** (for in-enclave test fixtures that want a host-side KMS over the same transport real Nitro uses).

`--no-auto-create-keys` makes `GetPublicKey` on a missing key id return an error rather than fabricating one; the backend-side instance uses this so a stray query doesn't conjure an out-of-band key.

Not used in production.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
