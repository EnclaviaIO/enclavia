# enclavia-protocol

Shared wire types and Noise+CBOR responder helpers for the Enclavia trust kernel. Consumed by:

- [`enclavia-server`](../enclavia-server/) (the in-enclave responder)
- [`enclavia`](../enclavia/) (the client SDK, native and wasm)
- [`enclavia-egress`](../enclavia-egress/) (uses `egress::Open` for the host hand-off frame)
- [`synchronizer`](../synchronizer/) (uses `mesh` for the relay hand-off and `chain` for upgrade-link verification)
- `enclavia-router` and the host-side relays (in separate repos)

What's in here:

- **Wire types** (CBOR-serialized): `ClientMessage`, `ServerMessage`, `ControlCommand`, the `egress::Open` and `mesh` hand-off frames.
- **Noise responder helpers**: the `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake machine + framed read/write.
- **Attestation** (`attestation`): an `Attestor` trait with the real `NsmAttestor` (signs via `/dev/nsm`; QEMU's `nitro-enclave` machine type emulates the same device and measures real PCRs, so there is no separate fake attestor in the VM). The verifier side validates the COSE ES384 signature chain against the AWS Nitro root; a per-connection debug flag accepts QEMU's self-signed documents by skipping only the certificate-chain check. The `test-utils` cargo feature gates builders for synthetic attestation documents, used solely by host-side `cargo test` runs where no NSM device exists; it is never compiled into production binaries.
- **Upgrade chain** (`chain`): the signed boot/upgrade history link types (`UpgradePayload`, `RevocationPayload`, `ChainLink`) and their verification.
- **Custody** (`custody`): the single CBOR encoding path for signed control commands (`encode_prepare_upgrade` / `encode_revoke_upgrade`), the DER-to-raw low-S P-256 signature re-encoding for hardware signers, and the two-phase confirm/revoke signing DTOs shared by the CLI and the backend.
- **KMS helpers** (`kms_policy`, `kms_recipient`): PCR-bound key-policy verification and the Recipient attestation envelope used for KMS `Decrypt`.
- **Staging** (`staging`): staged-upgrade JSON shapes shared by the CLI and the backend.

Wire format is forward-only via a `version` field on every frame; older clients keep working when new fields are added.

If you want to write your own client or your own host-side router, this is the crate to depend on.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
