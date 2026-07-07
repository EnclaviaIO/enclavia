# enclavia-vsock

Runtime host-CID detection for Enclavia's in-enclave binaries, so a single
EIF works under both real AWS Nitro (parent CID 3) and QEMU debug mode
(vhost-device-vsock, host CID 2) without a build-time feature split.

Used by [`enclavia-egress`](https://github.com/EnclaviaIO/enclavia/tree/master/enclavia-egress)
and the other in-enclave crates. You almost certainly want one of those
rather than this crate directly.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
