//! Browserless discovery + download of WhatsApp Web bundles, structured as
//! ports-and-adapters so the same logic can run native or in the browser.
//!
//! Mirrors the `sigilo` bundler's browserless approach (static HTML + `data-sjs`
//! JSON walk) instead of `wa-fetcher`'s headless browser.
//!
//! # Architecture
//!
//! - [`HttpClient`] is the *port*: a tiny blocking-GET abstraction. The
//!   discovery parser depends only on this trait, so it is backend-agnostic and
//!   WASM-safe. The download loop (`std::thread::scope`) and `save_bundles`
//!   (`std::fs`) are native-only and feature-gated.
//! - [`UreqClient`] is the native *adapter* (feature `native`, on by default):
//!   `ureq` over rustls with the pure-Rust OxiTLS/RustCrypto `CryptoProvider` — no
//!   `ring`, so the whole tree is C-free.
//! - A future web build can implement [`HttpClient`] over the browser `fetch`
//!   API as a second adapter, reusing the discovery parser unchanged, and
//!   download/persist by its own (async) means.
//!
//! The [`HttpClient`] port also carries one *optional* capability — a redirect probe
//! that stops at a 3xx instead of following it — defaulted to unsupported, because only
//! an adapter can decide who follows a redirect. The native adapter implements it; the
//! `btarchive` module (native-only, since Meta's build archive requires fetch-metadata
//! headers a browser will not let page JS set) is its only caller.
//!
//! `discover_bundle_urls_with` is the WASM-safe port-level entry point; the
//! thread-based download loop and the argument-free [`discover_bundle_urls`] /
//! [`download_bundles`] convenience wrappers live under the `native` feature.

mod bootloader;
mod discover;
mod download;
mod http;
mod util;

#[cfg(feature = "native")]
mod btarchive;
#[cfg(feature = "native")]
mod cache;
#[cfg(feature = "native")]
mod native;

#[cfg(all(test, feature = "native"))]
mod testutil;

pub use bootloader::{WasmResolution, WasmResolveOptions, is_cdn_payload, resolve_wasm_with};
pub use discover::{
    BootloaderParams, Discovered, Sources, WA_WEB_URL, build_wa_version, discover_bundle_urls_with,
    discover_from_html, is_wasm_url,
};
pub use download::{Bundle, DownloadFailure, DownloadOptions, DownloadOutcome, bundle_file_name};
pub use http::{FetchError, HttpClient, HttpResponse, RedirectResponse};

#[cfg(feature = "native")]
pub use bootloader::resolve_wasm;
#[cfg(feature = "native")]
pub use btarchive::{
    ArchiveApp, ArchiveLocation, ArchiveLookup, BTARCHIVE_ORIGIN, archive_url, lookup_archive,
    lookup_archive_with,
};
#[cfg(feature = "native")]
pub use cache::{BundleCache, BundleEntry, CacheManifest, CacheStatus};
#[cfg(feature = "native")]
pub use discover::discover_bundle_urls;
#[cfg(feature = "native")]
pub use download::{download_bundles, download_bundles_with, save_bundles};
#[cfg(feature = "native")]
pub use native::UreqClient;
