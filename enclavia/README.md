# enclavia

Client SDK for the Enclavia enclave runtime. Opens an end-to-end-encrypted channel through the host-side router and exposes it as an `http`-compatible client to your application.

Published on crates.io as [`enclavia`](https://crates.io/crates/enclavia) (`cargo add enclavia`). For browsers and JS runtimes, the same core ships on npm as [`@enclavia/client-wasm`](https://www.npmjs.com/package/@enclavia/client-wasm) via [`enclavia-wasm`](../enclavia-wasm/).

```rust
use enclavia::{Client, Pcrs};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
// Pin the enclave's expected measurements: copy/paste the hex PCRs
// straight from `enclavia enclave status`, `enclavia reproduce`, or the
// dashboard. The SDK verifies the Nitro attestation against these during
// connect and refuses to return a client if it does not match, so the
// channel is already attested before you send any plaintext.
let pcrs = Pcrs::from_hex(
    "6be2...", // pcr0: the EIF measurement (96 hex chars)
    "4b4d...", // pcr1: the enclave OS measurement
    "21b9...", // pcr2: the application configuration measurement
)?;
let client = Client::connect("wss://<enclave-id>.enclaves.beta.enclavia.io", pcrs).await?;

// Requests are built fluently: method + path, then optional headers and
// body, then `.send()`. The response exposes status, headers, and body.
let resp = client
    .post("/api/echo")
    .header("Content-Type", "application/json")
    .body(br#"{"hello":"world"}"#.to_vec())
    .send()
    .await?;

println!("status: {}", resp.status());                 // u16, e.g. 200
if let Some(ct) = resp.header("Content-Type") {        // case-insensitive
    println!("content-type: {ct}");
}
println!("body: {}", resp.text()?);                    // or resp.bytes() / resp.into_bytes()
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

Every method has a shorthand (`get`, `post`, `put`, `delete`, `patch`) plus
`request(method, path)` for an arbitrary method; all return the same
[`RequestBuilder`](src/request.rs), so headers and a body work on any of
them. With the `json` feature enabled you can also call
`.json(&value)` (sets the body and `Content-Type: application/json`) and
`resp.json::<T>()`.

Under the hood the SDK does:

1. WebSocket connection to the host-side router (the router is what binds the public hostname; the SDK does not need to know the enclave's vsock CID).
2. `Noise_NN_25519_ChaChaPoly_BLAKE2s` handshake; the responder is `enclavia-server` inside the EIF.
3. Attestation: the SDK pulls the Nitro attestation document over the encrypted channel and **verifies it against the PCRs you pinned** (`Client::connect(.., pcrs)` / `ClientBuilder::pcrs`). On a mismatch, `connect` / `build` returns an error and no client is handed back, so you can never send plaintext to an unattested enclave. Production documents are validated against the AWS Nitro certificate chain; `debug_mode(true)` accepts the self-signed QEMU/debug document instead.
4. Plaintext HTTP request/response framed inside the Noise tunnel.

### Reconnection

The enclave restarts on every deploy/upgrade (and can drop at any time),
which kills the attested channel. By default the SDK re-establishes it for
you: when a `.send()` finds the channel down, it re-opens the WebSocket,
redoes the Noise handshake, and RE-VERIFIES the attestation against the
SAME PCRs you originally pinned before sending. If the enclave's
attestation no longer matches (for example it was upgraded to an image
whose PCRs are not the pinned ones), reconnection FAILS CLOSED with an
attestation error rather than attaching to a different enclave: it is held
to exactly the same trust bar as the initial connect.

What the SDK does NOT do is silently re-send a request that was in flight
when the channel dropped: it may already have reached the enclave, and
re-sending it would double-execute a non-idempotent call. Such a request
returns a retryable error (`Error::is_retryable()` is `true`), and you
decide whether to retry it. The retry runs on the already re-established,
re-verified channel, so you re-implement neither Noise nor attestation,
only the "is this request safe to retry" decision:

```rust
use enclavia::{Client, Pcrs};

# async fn run(pcrs: Pcrs) -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder("wss://<enclave-id>.enclaves.beta.enclavia.io")
    .pcrs(pcrs)
    .build()
    .await?;

// Retry an idempotent GET across a reconnect. A POST you would only retry
// if it is safe (or carries an idempotency key).
let response = loop {
    match client.get("/health").send().await {
        Ok(r) => break r,
        Err(e) if e.is_retryable() => continue, // channel re-established; try again
        Err(e) => return Err(e.into()),         // attestation / server error: give up
    }
};
# let _ = response;
# Ok(())
# }
```

Pass `.auto_reconnect(false)` to the builder to turn this off and own
recovery yourself. Streams opened with `open_stream` / `upgrade` are not
auto-reconnected (a live byte pipe carries workload socket state that
cannot be transparently rebuilt); re-open them on error.

Use [`enclavia-protocol`](../enclavia-protocol/) directly if you need finer control or want to build a non-HTTP transport.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
