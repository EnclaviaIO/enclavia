# enclavia

Client SDK for the Enclavia enclave runtime. Opens an end-to-end-encrypted channel through the host-side router and exposes it as an `http`-compatible client to your application.

```rust
use enclavia::{Client, Pcrs};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
// Pin the enclave's expected measurements (e.g. from `enclavia reproduce`
// or your own build). The SDK verifies the Nitro attestation against these
// during connect and refuses to return a client if it does not match, so
// the channel is already attested before you send any plaintext.
let pcrs = Pcrs {
    pcr0: vec![/* 48 bytes */],
    pcr1: vec![/* 48 bytes */],
    pcr2: vec![/* 48 bytes */],
};
let client = Client::connect("wss://<enclave-id>.enclaves.beta.enclavia.io", pcrs).await?;

let resp = client.get("/health").send().await?;
println!("{}", resp.status());
# Ok(())
# }
```

For a debug/QEMU enclave (self-signed attestation), or to follow a signed upgrade chain, use the builder:

```rust
use enclavia::{Client, Pcrs};

# async fn run(pcrs: Pcrs) -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder("wss://<enclave-id>.enclaves.beta.enclavia.io")
    .pcrs(pcrs)
    .debug_mode(true) // accept the self-signed QEMU/debug attestation
    .build()
    .await?;
# Ok(())
# }
```

Under the hood the SDK does:

1. WebSocket connection to the host-side router (the router is what binds the public hostname; the SDK does not need to know the enclave's vsock CID).
2. `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake; the responder is `enclavia-server` inside the EIF.
3. Attestation: the SDK pulls the Nitro attestation document over the encrypted channel and **verifies it against the PCRs you pinned** (`Client::connect(.., pcrs)` / `ClientBuilder::pcrs`). On a mismatch, `connect` / `build` returns an error and no client is handed back, so you can never send plaintext to an unattested enclave. Production documents are validated against the AWS Nitro certificate chain; `debug_mode(true)` accepts the self-signed QEMU/debug document instead.
4. Plaintext HTTP request/response framed inside the Noise tunnel.

Use [`enclavia-protocol`](../enclavia-protocol/) directly if you need finer control or want to build a non-HTTP transport.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
