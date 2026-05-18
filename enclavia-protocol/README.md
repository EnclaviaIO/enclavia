# enclavia-protocol

Shared wire types and Noise+CBOR responder helpers for the Enclavia trust kernel. Consumed by:

- [`enclavia-server`](../enclavia-server/) (the in-enclave responder)
- [`enclavia`](../enclavia/) (the client SDK)
- [`enclavia-egress`](../enclavia-egress/) (uses `egress::Open` for the host hand-off frame)
- `enclavia-router` and `enclavia-cli`'s smoke-test client (host-side, in a separate repo)

What's in here:

- **Wire types** (CBOR-serialized): `ClientMessage`, `ServerMessage`, `ControlCommand`, `egress::Open`.
- **Noise responder helpers**: the `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake machine + framed read/write.
- **Attestation**: a `Attestor` trait, a real `NsmAttestor` (signs via `/dev/nsm` inside a Nitro Enclave), and a deterministic `FakeAttestor` (gated on the `test-utils` cargo feature) for QEMU debug runs. The verifier side validates the COSE signature chain against the AWS Nitro root.

Wire format is forward-only via a `version` field on every frame; older clients keep working when new fields are added.

If you want to write your own client or your own host-side router, this is the crate to depend on.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
