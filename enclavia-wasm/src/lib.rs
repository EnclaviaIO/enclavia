//! wasm-bindgen bindings for the `enclavia` client SDK.
//!
//! The whole security core — Noise NN, attestation verification (including
//! production Nitro cert-chain validation), stream multiplexing — is the SAME
//! Rust the native SDK runs; only the WebSocket is the host's. Works in
//! browsers and in JS runtimes with a global `WebSocket` (Node >= 22, Deno).
//!
//! ```js
//! import init, { connect } from "@enclavia/client-wasm";
//! await init();
//! const client = await connect("wss://<id>.enclaves.beta.enclavia.io", {
//!   pcr0: "...", pcr1: "...", pcr2: "...",   // hex, from `enclavia enclave status`
//! }, { debugMode: true });                    // omit on production Nitro
//! const resp = await client.fetch("GET", "/health");
//! console.log(resp.status, new TextDecoder().decode(resp.body));
//! ```
//!
//! Notes vs. the native SDK:
//! - custom WebSocket upgrade headers are impossible on wasm (the host API
//!   cannot set them); production routing is by hostname, so this only
//!   affects bespoke harnesses.
//! - `Client::upgrade` (HTTP 101) is not exposed; `openStream` gives the raw
//!   byte pipe it is built on, which is what non-HTTP protocols use.

use std::rc::Rc;

use js_sys::{Object, Promise, Reflect, Uint8Array};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use enclavia::{Method, Pcrs, UpgradedStream};

fn js_err(e: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}

fn opt_string(obj: &JsValue, key: &str) -> Option<String> {
    if obj.is_undefined() || obj.is_null() {
        return None;
    }
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
}

fn opt_bool(obj: &JsValue, key: &str) -> Option<bool> {
    if obj.is_undefined() || obj.is_null() {
        return None;
    }
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_bool())
}

fn pcr_from_hex(pcrs: &JsValue, key: &str) -> Result<Vec<u8>, JsValue> {
    let hex_str = opt_string(pcrs, key)
        .ok_or_else(|| js_err(format!("pcrs.{key} is required (hex string)")))?;
    hex::decode(hex_str.trim()).map_err(|e| js_err(format!("pcrs.{key}: invalid hex: {e}")))
}

fn parse_method(m: &str) -> Result<Method, JsValue> {
    Ok(match m.to_ascii_uppercase().as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        "HEAD" => Method::Head,
        "OPTIONS" => Method::Options,
        other => return Err(js_err(format!("unsupported HTTP method {other:?}"))),
    })
}

/// An attested, end-to-end-encrypted connection to one enclave.
#[wasm_bindgen]
pub struct Client {
    inner: enclavia::Client,
}

/// Connect to an enclave and verify its attestation.
///
/// - `url`: the enclave endpoint, `wss://<id>.enclaves.<env>.enclavia.io`.
/// - `pcrs`: `{ pcr0, pcr1, pcr2 }` as hex strings (from
///   `enclavia enclave status`). The connection is refused unless the live
///   attestation matches.
/// - `options` (optional):
///   - `debugMode` (default **false**, matching the native SDK): accept the
///     beta/QEMU debug attestation (nonce binding + PCR equality, no
///     signature). Leave unset on production Nitro, where the full COSE
///     ES384 + cert-chain validation runs — in wasm, same as natively.
///   - `trustUpgrades`: `{ backendUrl, enclaveId }` — follow the enclave's
///     signed upgrade chain instead of pinning one immutable version.
#[wasm_bindgen]
pub async fn connect(
    url: String,
    pcrs: JsValue,
    options: JsValue,
) -> Result<Client, JsValue> {
    let pcrs = Pcrs {
        pcr0: pcr_from_hex(&pcrs, "pcr0")?,
        pcr1: pcr_from_hex(&pcrs, "pcr1")?,
        pcr2: pcr_from_hex(&pcrs, "pcr2")?,
    };

    let mut builder = enclavia::Client::builder(&url).pcrs(pcrs);
    if let Some(debug) = opt_bool(&options, "debugMode") {
        builder = builder.debug_mode(debug);
    }
    if !options.is_undefined() && !options.is_null() {
        let tu = Reflect::get(&options, &JsValue::from_str("trustUpgrades"))
            .unwrap_or(JsValue::UNDEFINED);
        if !tu.is_undefined() && !tu.is_null() {
            let backend_url = opt_string(&tu, "backendUrl")
                .ok_or_else(|| js_err("trustUpgrades.backendUrl is required"))?;
            let enclave_id = opt_string(&tu, "enclaveId")
                .ok_or_else(|| js_err("trustUpgrades.enclaveId is required"))?;
            let enclave_id = uuid::Uuid::parse_str(&enclave_id)
                .map_err(|e| js_err(format!("trustUpgrades.enclaveId: {e}")))?;
            builder = builder.trust_upgrades(backend_url, enclave_id);
        }
    }

    let inner = builder.build().await.map_err(js_err)?;
    Ok(Client { inner })
}

#[wasm_bindgen]
impl Client {
    /// Send one HTTP request through the encrypted channel.
    ///
    /// `options` (optional): `{ headers?: [name, value][], body?: Uint8Array }`.
    /// Resolves to `{ status: number, headers: [name, value][], body: Uint8Array }`.
    pub fn fetch(&self, method: String, path: String, options: JsValue) -> Promise {
        let client = self.inner.clone();
        future_to_promise(async move {
            let method = parse_method(&method)?;
            let mut req = client.request(method, &path);

            if !options.is_undefined() && !options.is_null() {
                let headers =
                    Reflect::get(&options, &JsValue::from_str("headers")).unwrap_or(JsValue::UNDEFINED);
                if let Ok(arr) = headers.dyn_into::<js_sys::Array>() {
                    for pair in arr.iter() {
                        let pair: js_sys::Array = pair
                            .dyn_into()
                            .map_err(|_| js_err("headers must be [name, value] pairs"))?;
                        let name = pair.get(0).as_string().ok_or_else(|| js_err("header name"))?;
                        let value = pair.get(1).as_string().ok_or_else(|| js_err("header value"))?;
                        req = req.header(name, value);
                    }
                }
                let body =
                    Reflect::get(&options, &JsValue::from_str("body")).unwrap_or(JsValue::UNDEFINED);
                if let Ok(bytes) = body.dyn_into::<Uint8Array>() {
                    req = req.body(bytes.to_vec());
                }
            }

            let resp = req.send().await.map_err(js_err)?;

            let headers = js_sys::Array::new();
            for (k, v) in resp.headers() {
                let pair = js_sys::Array::new();
                pair.push(&JsValue::from_str(k));
                pair.push(&JsValue::from_str(v));
                headers.push(&pair);
            }
            let out = Object::new();
            Reflect::set(&out, &"status".into(), &JsValue::from_f64(resp.status() as f64))?;
            Reflect::set(&out, &"headers".into(), &headers)?;
            Reflect::set(&out, &"body".into(), &Uint8Array::from(resp.bytes()))?;
            Ok(out.into())
        })
    }

    /// Open a raw bidirectional byte stream to the workload (the primitive
    /// non-HTTP protocols use). `payload` is delivered as the first bytes of
    /// the in-enclave socket; pass an empty array for a plain pipe.
    /// Resolves to a [`Stream`].
    #[wasm_bindgen(js_name = openStream)]
    pub fn open_stream(&self, payload: Vec<u8>) -> Promise {
        let client = self.inner.clone();
        future_to_promise(async move {
            let stream = client.open_stream(payload).await.map_err(js_err)?;
            let (read, write) = tokio::io::split(stream);
            Ok(Stream {
                read: Rc::new(Mutex::new(read)),
                write: Rc::new(Mutex::new(write)),
            }
            .into())
        })
    }
}

/// A raw byte stream to the workload, from [`Client::open_stream`]. Reads and
/// writes are independently locked, so a pending `recv` never blocks `send`.
#[wasm_bindgen]
pub struct Stream {
    read: Rc<Mutex<ReadHalf<UpgradedStream>>>,
    write: Rc<Mutex<WriteHalf<UpgradedStream>>>,
}

#[wasm_bindgen]
impl Stream {
    /// Write bytes to the workload. Resolves when handed to the transport.
    pub fn send(&self, bytes: Vec<u8>) -> Promise {
        let write = self.write.clone();
        future_to_promise(async move {
            let mut w = write.lock().await;
            w.write_all(&bytes).await.map_err(js_err)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Read the next chunk of bytes from the workload. Resolves to a
    /// `Uint8Array`, or `null` on end-of-stream.
    pub fn recv(&self) -> Promise {
        let read = self.read.clone();
        future_to_promise(async move {
            let mut r = read.lock().await;
            let mut buf = vec![0u8; 64 * 1024];
            let n = r.read(&mut buf).await.map_err(js_err)?;
            if n == 0 {
                return Ok(JsValue::NULL);
            }
            Ok(Uint8Array::from(&buf[..n]).into())
        })
    }

    /// Half-close the write side (the workload sees read EOF; its responses
    /// still flow until it closes its side).
    #[wasm_bindgen(js_name = closeWrite)]
    pub fn close_write(&self) -> Promise {
        let write = self.write.clone();
        future_to_promise(async move {
            let mut w = write.lock().await;
            w.shutdown().await.map_err(js_err)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
