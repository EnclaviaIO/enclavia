# enclavia-egress

In-enclave outbound TCP daemon. Owns `/dev/net/tun`, creates `tun0` as the workload's default route, and runs a [`smoltcp`](https://github.com/smoltcp-rs/smoltcp) userspace TCP/IP stack on it. For every accepted outbound flow:

1. Checks the destination against `/etc/enclavia/egress.json` (deny-all by default).
2. For hostname entries: queries the in-enclave `unbound` resolver on `127.0.0.1:53` (DNSSEC-validating, configured at boot from `egress.json`'s `resolvers` array), and pins the resolved IP for the duration of the flow.
3. Dials the host-side `egress-host` relay over vsock and splices bytes.

The wire format for the host hand-off (length-prefixed CBOR `Open` frame) lives in [`enclavia-protocol::egress`](../enclavia-protocol/). The host-side relay lives outside this repository and runs alongside QEMU/Nitro on the parent.

Allowlist grammar:
- IPv4 literal or CIDR (e.g. `1.2.3.4` or `10.0.0.0/8`)
- RFC 1035 hostname (e.g. `api.openai.com`)
- IPv6 always rejected.
- TCP is enforced today; UDP entries parse but do not fire.

The allowlist is built into the EIF rootfs at builder time and is covered by the PCRs, so changing it changes the enclave's identity and is surfaced by `enclavia reproduce`.

vsock-only.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
