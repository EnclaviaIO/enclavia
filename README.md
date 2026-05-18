# Enclavia

Open-source crates that make up the Enclavia enclave runtime: the in-enclave services that run inside the EIF (Enclave Image File), the shared protocol types that describe the wire format between client and enclave, the client SDK, and the CLI.

Enclavia lets you run arbitrary Docker images inside an AWS Nitro Enclave (or a local QEMU debug enclave) and reach them through an end-to-end-encrypted channel that is anchored to a Nitro attestation. The hosted control plane (website, builder, router) lives in a separate, closed-source repository. The code that runs inside the enclave (which is PCR-measured and therefore part of the attestation contract) and the code that talks to it must be auditable, so it lives here.

See https://beta.enclavia.io for the hosted service.

## Crates

In-enclave binaries (run inside the EIF, reach the host over `tokio-vsock`):

- `enclavia-server`: Noise responder that terminates the encrypted channel from the router and forwards plaintext bytes to the inner container over loopback TCP.
- `enclavia-egress`: Outbound TCP daemon. Owns `tun0`, runs a `smoltcp` userspace TCP/IP stack, and dials `egress-host` over vsock for every accepted outbound flow. Enforces a deny-by-default allowlist of IP literals, CIDRs, and hostnames (resolved through an in-enclave `unbound`).
- `enclavia-crypto`: Key management. Talks to KMS over vsock and unseals the LUKS volume that backs persistent storage.
- `nbd-client`: NBD client that backs the encrypted filesystem on top of `storage-host`.
- `synchronizer`: Multi-node storage sync (mesh replication of the LUKS-encrypted volume).

Shared / client-side crates (build for any target):

- `enclavia-protocol`: Wire types and Noise+CBOR responder helpers. Shared between the in-enclave server, the host-side router, and the SDK. Includes attestation verification.
- `enclavia`: Client SDK. Opens a Noise tunnel through the router's WebSocket and exposes it as an `http`-compatible client to your application.
- `enclavia-cli`: The `enclavia` binary. Commands for auth, `push`, and enclave lifecycle. Also exposes a library face (`enclavia_cli::{api, commands, config}`) for tools that want to reuse the same API client.

Dev tools:

- `mock-kms`: A KMS Trent endpoint for QEMU dev wrappers and the local dev stack.

The host-side relays (`egress-host`, `storage-host`), the WebSocket-to-vsock router, the control-plane API, the frontend, and the EIF builder live in separate repositories.

## Build

This workspace is driven by Nix flakes and Cargo.

```sh
# One-shot Cargo build:
cargo build --workspace

# Or via the Nix dev shell (pins the Rust toolchain):
nix develop
cargo build --workspace
```

Individual flake packages:

```sh
nix build .#enclavia-server
nix build .#enclavia-egress
nix build .#enclavia-crypto
nix build .#nbd-client
nix build .#mock-kms
nix build .#enclavia
```

The in-enclave binaries only really run inside an enclave or QEMU. To exercise them end-to-end you also need the builder (which constructs the EIF). See https://github.com/EnclaviaIO/builder.

## Reproducibility

The whole point of this repo being open source is that anything PCR-measured inside the EIF must be buildable from sources you can audit. Every crate here is part of that perimeter (or is consumed by code that is, via `enclavia-protocol`).

The CLI's `enclavia reproduce` command pins to the same `flake.lock` the backend used when building an enclave, so you can verify that a given attestation came from the sources you expect.

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports go to `security@enclavia.io`.
