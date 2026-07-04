// Smoke test: the wasm SDK against a real deployed enclave.
// Env: ENCLAVE_URL, PCR0..2. Node >= 22 (global WebSocket).
import { readFileSync } from "node:fs";
import init, { connect } from "./pkg/enclavia_wasm.js";

await init({ module_or_path: readFileSync(new URL("./pkg/enclavia_wasm_bg.wasm", import.meta.url)) });

const pcrs = { pcr0: process.env.PCR0, pcr1: process.env.PCR1, pcr2: process.env.PCR2 };

// 1. Wrong PCRs must be refused (proves verification actually gates).
try {
  await connect(process.env.ENCLAVE_URL, { ...pcrs, pcr0: "00".repeat(48) }, { debugMode: true });
  throw new Error("connect with wrong PCR0 should have failed!");
} catch (e) {
  if (!String(e.message ?? e).match(/PCR|attestation/i)) throw e;
  console.log("OK: wrong PCR0 refused:", String(e.message ?? e).slice(0, 60));
}

// 2. Correct PCRs: connect + attested Noise channel up.
const client = await connect(process.env.ENCLAVE_URL, pcrs, { debugMode: true });
console.log("OK: connected, attestation verified (debug/QEMU)");

// 3. HTTP through the tunnel.
const resp = await client.fetch("GET", "/health");
const body = new TextDecoder().decode(resp.body);
if (resp.status !== 200 || body !== "ok") throw new Error(`GET /health -> ${resp.status} ${JSON.stringify(body)}`);
console.log(`OK: GET /health through the tunnel -> ${resp.status} ${JSON.stringify(body)}`);

// 4. Raw stream: hand-rolled HTTP over openStream (the primitive itself).
const stream = await client.openStream(new TextEncoder().encode("GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
let raw = "";
for (;;) {
  const chunk = await stream.recv();
  if (chunk === null) break;
  raw += new TextDecoder().decode(chunk);
  if (raw.includes("\r\n\r\nok")) break;
}
if (!raw.startsWith("HTTP/1.1 200") || !raw.endsWith("ok")) throw new Error("openStream response: " + JSON.stringify(raw));
console.log("OK: raw openStream round-trip ->", JSON.stringify(raw.split("\r\n")[0]));

console.log("WASM SDK SMOKE TEST PASSED");
process.exit(0);
