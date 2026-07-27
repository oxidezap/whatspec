//! The WebAssembly surface: which compiled binaries WA Web ships glue for, and the
//! bootloader resource handles (`bx` ids) the JS resolves their bytes through.
//!
//! This domain is deliberately **handles, not bytes**. A wasm URL never appears in the
//! JS: the emscripten glue asks the bootloader for a numeric id
//! (`r("bx").getURL(r("bx")("33861"))`) and the server maps that id to a content-hashed
//! URL in the page's `bxData` payload. So the durable, bundle-derived facts are the
//! build-time binary names and the id→consumer graph; the resolved URLs (and the bytes'
//! hashes) are network state and live in `wasm.lock.json` instead, next to
//! `bundles.lock.json`.
//!
//! Consumers use this to know *what* wasm the client runs (post-quantum `liboqs`, the
//! VoIP engine, media codecs, …) and which JS modules drive it, without needing the
//! multi-megabyte payloads.

use serde::{Deserialize, Serialize};

/// One emscripten-compiled binary the bundle carries glue for, named by its build-time
/// payload file (`crypto_utils_v2.wasm`) rather than its content-hashed URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WasmBinary {
    /// The `wasmBinaryFile` name the glue declares, e.g. `liboqs_wasm_wrapper.wasm`.
    pub name: String,
    /// The WA Web modules whose glue declares this payload, sorted.
    pub modules: Vec<String>,
}

/// One bootloader resource handle the JS resolves at runtime.
///
/// A `bx` id addresses any bootloader resource — most of them are images — so the id
/// alone doesn't prove a wasm payload. [`Self::wasm_hint`] carries the static evidence
/// that made this handle look wasm-related; an empty hint means the consuming modules
/// showed none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WasmResourceRef {
    /// The numeric `bx` id, as written in the JS (a string: it is a map key, not a
    /// number the client does arithmetic on).
    pub bx_id: String,
    /// The WA Web modules that request this id, sorted.
    pub consumers: Vec<String>,
    /// Why this handle is believed to address wasm, sorted. Exactly the values the
    /// extractor emits — this text ships inside the published JSON Schema, so a consumer
    /// matching on it must find the real names:
    ///
    /// - `wasmBinaryLiteral` — a consuming module names a `*.wasm` payload (emscripten glue)
    /// - `moduleName` — a consumer is named `…Wasm…`
    /// - `wasmModuleCacheDep` — a consumer depends on `WAWasmModuleCache`
    pub wasm_hint: Vec<String>,
}

/// The wasm-surface IR document: version stamp + the two catalogs, sorted for
/// determinism (`binaries` by name, `resources` by `bx` id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WasmIr {
    pub wa_version: String,
    /// Emscripten binaries the bundle ships glue for.
    pub binaries: Vec<WasmBinary>,
    /// Bootloader handles with wasm evidence — the ids `wa-fetch` resolves to URLs.
    pub resources: Vec<WasmResourceRef>,
}
