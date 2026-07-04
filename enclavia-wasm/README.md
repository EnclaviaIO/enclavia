# enclavia-wasm

wasm-bindgen bindings for the [`enclavia`](../enclavia) client SDK: the
attested Noise tunnel to an enclave, from browsers and JS runtimes with a
global `WebSocket` (Node ≥ 22, Deno).

The security core is **the same Rust the native SDK runs** — Noise NN, the
shared attestation verifier from `enclavia-protocol` (including production
Nitro COSE ES384 + cert-chain validation), stream multiplexing. Only the
WebSocket is the host's.

## Usage

```js
import init, { connect } from "./pkg/enclavia_wasm.js";
await init();

const client = await connect(
  "wss://<id>.enclaves.beta.enclavia.io",
  { pcr0: "...", pcr1: "...", pcr2: "..." },   // hex, from `enclavia enclave status`
  { debugMode: true },                          // beta/QEMU only; omit on production Nitro
);

// HTTP through the encrypted channel:
const resp = await client.fetch("GET", "/health");
console.log(resp.status, new TextDecoder().decode(resp.body));

// Raw byte stream (non-HTTP protocols):
const stream = await client.openStream(firstBytes);
await stream.send(more);
const chunk = await stream.recv();   // Uint8Array | null on EOF
```

`connect` also accepts `trustUpgrades: { backendUrl, enclaveId }`, mirroring
the native `ClientBuilder::trust_upgrades`.

Differences from the native SDK, both inherent to the host WebSocket API:

- custom upgrade headers are refused (production routing is by hostname);
- TLS for the `wss://` hop is the host's (the security boundary is the Noise
  channel + attestation, which run in wasm regardless).

## Building

`ring`'s C sources must be compiled by a **wasm-capable clang** — without one,
cargo *silently* emits the EC math as unresolved `env` imports and the module
fails only at instantiation. Then run `wasm-bindgen` (CLI version must match
the pinned `wasm-bindgen` crate, currently 0.2.117):

```bash
export CC_wasm32_unknown_unknown=clang
# On Nix, clang-unwrapped also needs its builtin headers on the include path:
#   export CFLAGS_wasm32_unknown_unknown="-I$(dirname $(dirname $(command -v clang)))-lib/lib/clang/<ver>/include"

cargo build -p enclavia-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir enclavia-wasm/pkg \
  target/wasm32-unknown-unknown/release/enclavia_wasm.wasm
# optional: wasm-opt -Os pkg/enclavia_wasm_bg.wasm -o pkg/enclavia_wasm_bg.wasm
```

## Smoke test

With a deployed enclave (any workload answering `GET /health`):

```bash
ENCLAVE_URL=wss://<id>.enclaves.beta.enclavia.io PCR0=… PCR1=… PCR2=… \
  node enclavia-wasm/smoke.mjs
```

It asserts: wrong PCRs are refused; attested connect; `fetch("GET","/health")`
through the tunnel; and a raw `openStream` round-trip.
