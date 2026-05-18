# Contributing to Enclavia

Thanks for considering a contribution. This document covers the basics; longer-form docs (architecture, transport conventions, debug-mode internals) live alongside the closed-source pieces at https://docs.enclavia.io.

## Building and testing

```sh
nix develop                  # drops you into the pinned toolchain
cargo build --workspace
cargo test --workspace
```

Most crates have unit tests that run without an enclave. End-to-end tests that require a QEMU enclave or a real Nitro instance are exercised through the builder repo (https://github.com/EnclaviaIO/builder) and the hosted CI; you do not need to run them locally.

## Submitting changes

1. Fork the repo and open a pull request against `main`.
2. Open PRs ready for review (not draft) unless the work is genuinely in-progress and you want a checkpoint review.
3. Keep commits focused. Squashing on merge is fine.
4. Run `cargo fmt --all` and `cargo clippy --workspace` before pushing.

## Security

Please do not file security issues on the public tracker. Email `security@enclavia.io` and we will respond before any public disclosure.

## License of contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
