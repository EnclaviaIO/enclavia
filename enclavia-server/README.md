# enclavia-server

In-enclave Noise responder. Runs inside the EIF and:

1. Listens on a vsock port (typically `5000`) for an inbound `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake from the host-side router.
2. Forwards plaintext bytes between the encrypted channel and the inner container over loopback TCP (defaults to `127.0.0.1:8080`, configurable per enclave).
3. Dispatches signed `Control` commands (e.g. `PrepareUpgrade`) to [`enclavia-crypto`](../enclavia-crypto/) after verifying their Ed25519 signature against the control public key baked into the EIF.

This is the trust kernel's responder side: every byte between the SDK and the workload passes through here, and the attestation signed by `/dev/nsm` (or the deterministic `FakeAttestor` in QEMU debug mode) is what the client verifies before sending plaintext.

The handshake and framing types live in [`enclavia-protocol`](../enclavia-protocol/). The host-side router is closed-source; the wire it speaks is defined here.

vsock-only: there is no host-direct mode. Run inside real Nitro hardware or QEMU debug mode (see the [builder](https://github.com/EnclaviaIO/builder) for the test wrappers).

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
