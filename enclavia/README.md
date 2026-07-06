# enclavia

Client SDK for the Enclavia enclave runtime. Opens an end-to-end-encrypted channel through the host-side router and exposes it as an `http`-compatible client to your application.

```rust
use enclavia::Client;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::connect("wss://<enclave-id>.enclaves.beta.enclavia.io").await?;

// Verify the attestation document BEFORE sending plaintext.
// The SDK exposes it; your code decides whether to trust it.
let attestation = client.attestation();
assert_pcrs_match(&attestation)?;  // your own policy

let resp = client.get("/health").send().await?;
println!("{}", resp.status());
# Ok(())
# }
# fn assert_pcrs_match(_a: &enclavia::Attestation) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
```

Under the hood the SDK does:

1. WebSocket connection to the host-side router (the router is what binds the public hostname; the SDK does not need to know the enclave's vsock CID).
2. `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake; the responder is `enclavia-server` inside the EIF.
3. Attestation: the SDK pulls the Nitro attestation document over the encrypted channel and exposes it. **Verification is the consumer's responsibility**, because what counts as a valid attestation is application-specific (expected PCRs, expected enclave identity, expiry tolerance).
4. Plaintext HTTP request/response framed inside the Noise tunnel.

Use [`enclavia-protocol`](../enclavia-protocol/) directly if you need finer control or want to build a non-HTTP transport.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
