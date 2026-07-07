# enclavia-server

In-enclave Noise responder. Runs inside the EIF and:

1. Listens on a vsock port (typically `5000`) for an inbound `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake from the host-side router.
2. Forwards plaintext bytes between the encrypted channel and the inner container over loopback TCP (defaults to `127.0.0.1:8080`, configurable per enclave).
3. Dispatches signed `Control` commands (e.g. `PrepareUpgrade`) to [`enclavia-crypto`](../enclavia-crypto/) after verifying their P-256 ECDSA signature (64-byte raw `r || s` over the command bytes) against the control public key baked into the measured EIF config. When the config carries a `min_upgrade_delay_secs`, a `PrepareUpgrade` whose activation time lands inside the delay window is rejected against the enclave's own clock.

This is the trust kernel's responder side: every byte between the SDK and the workload passes through here, and the attestation signed by `/dev/nsm` is what the client verifies before sending plaintext. QEMU's `nitro-enclave` machine type emulates the same NSM device with real PCR measurements; its documents are self-signed rather than AWS-CA-signed, which is exactly what the client's debug mode accepts.

The handshake and framing types live in [`enclavia-protocol`](../enclavia-protocol/). The host-side router is closed-source; the wire it speaks is defined here.

vsock-only: there is no host-direct mode. Run inside real Nitro hardware or QEMU debug mode (see the [builder](https://github.com/EnclaviaIO/builder) for the test wrappers).

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
