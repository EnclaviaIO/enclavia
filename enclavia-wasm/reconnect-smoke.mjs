// Reconnect smoke test: the wasm SDK against a LOCAL mock enclave that
// drops the connection after every answered request, so every fetch past
// the first forces a transparent reconnect (full Noise + attestation
// re-verify). Unlike smoke.mjs this needs NO deployed enclave, so CI runs
// it against the nix-built publish artifact (`nix build .#enclavia-wasm-npm`).
//
// Start the mock first (it prints its port):
//   cargo run --example reconnect_mock_server -p enclavia
// Then: node reconnect-smoke.mjs <pkg-dir> <port>
// Node >= 22 (global WebSocket).
import { readFileSync } from "node:fs";
import { join } from "node:path";

const pkgDir = process.argv[2];
const port = process.argv[3];
if (!pkgDir || !port) {
  console.error("usage: node reconnect-smoke.mjs <wasm-pkg-dir> <mock-port>");
  process.exit(2);
}
const url = `ws://127.0.0.1:${port}`;

const mod = await import(join(pkgDir, "enclavia_wasm.js"));
const { default: init, connect } = mod;
await init({ module_or_path: readFileSync(join(pkgDir, "enclavia_wasm_bg.wasm")) });

// The mock attests with FakeAttestation::with_seed(0x11): pcrN is the
// byte (seed + N) repeated 48 times.
const rep = (b) => b.toString(16).padStart(2, "0").repeat(48);
const pcrs = { pcr0: rep(0x11), pcr1: rep(0x12), pcr2: rep(0x13) };

const dec = new TextDecoder();

// 1. Wrong PCRs must be refused: reconnect logic never weakens the
// attestation gate, including on the very first connect.
try {
  await connect(url, { ...pcrs, pcr0: "00".repeat(48) }, { debugMode: true });
  throw new Error("connect with wrong PCR0 should have failed!");
} catch (e) {
  if (!String(e.message ?? e).match(/PCR|attestation/i)) throw e;
  console.log("OK: wrong PCR0 refused:", String(e.message ?? e).slice(0, 70));
}

// 2. Connect with the right PCRs. NOTE: the failed connect above consumed
// one mock connection, and the mock drops after ONE answered request, so
// every fetch below lands on its own fresh connection.
const client = await connect(url, pcrs, { debugMode: true });
console.log("OK: connected, attestation verified");

// 3. First request on the live channel.
const r1 = await client.fetch("GET", "/one");
const b1 = dec.decode(r1.body);
if (r1.status !== 200) throw new Error(`fetch 1 -> ${r1.status}`);
console.log(`OK: fetch 1 -> ${r1.status} ${JSON.stringify(b1)}`);

// The server dropped the channel after answering. Give the client's
// background reader a beat to observe the close event.
await new Promise((r) => setTimeout(r, 300));

// 4. Second request MUST transparently reconnect + re-attest.
const r2 = await client.fetch("GET", "/two");
const b2 = dec.decode(r2.body);
if (r2.status !== 200) throw new Error(`fetch 2 (post-drop) -> ${r2.status}`);
console.log(`OK: fetch 2 after server drop -> ${r2.status} ${JSON.stringify(b2)} (transparent reconnect)`);

// 5. And again, to prove it is repeatable, not a one-shot.
await new Promise((r) => setTimeout(r, 300));
const r3 = await client.fetch("GET", "/three");
const b3 = dec.decode(r3.body);
if (r3.status !== 200) throw new Error(`fetch 3 -> ${r3.status}`);
console.log(`OK: fetch 3 after another drop -> ${r3.status} ${JSON.stringify(b3)}`);

// 6. The mock stamps each connection number into the body: the three
// fetches must have come over three DISTINCT connections (the reconnects
// really happened; the responses were not replays).
const conns = [b1, b2, b3].map((b) => {
  const m = b.match(/^conn-(\d+)$/);
  if (!m) throw new Error(`unexpected body ${JSON.stringify(b)}`);
  return Number(m[1]);
});
if (new Set(conns).size !== 3 || !(conns[0] < conns[1] && conns[1] < conns[2]))
  throw new Error(`expected 3 distinct increasing connections, got ${conns}`);
console.log(`OK: three requests served over three distinct connections: ${conns.join(", ")}`);

console.log("WASM RECONNECT SMOKE TEST PASSED");
process.exit(0);
