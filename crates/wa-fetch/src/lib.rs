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
//!   `ureq` over rustls with the pure-Rust RustCrypto `CryptoProvider` — no
//!   `ring`, so the whole tree is C-free.
//! - A future web build can implement [`HttpClient`] over the browser `fetch`
//!   API as a second adapter, reusing the discovery parser unchanged, and
//!   download/persist by its own (async) means.
//!
//! `discover_bundle_urls_with` is the WASM-safe port-level entry point; the
//! thread-based download loop and the argument-free [`discover_bundle_urls`] /
//! [`download_bundles`] convenience wrappers live under the `native` feature.

mod discover;
mod download;
mod http;
mod util;

#[cfg(feature = "native")]
mod cache;
#[cfg(feature = "native")]
mod native;

#[cfg(all(test, feature = "native"))]
mod testutil;

pub use discover::{
    Discovered, Sources, WA_WEB_URL, build_wa_version, discover_bundle_urls_with,
    discover_from_html,
};
pub use download::{Bundle, DownloadFailure, DownloadOptions, DownloadOutcome, bundle_file_name};
pub use http::{FetchError, HttpClient, HttpResponse};

#[cfg(feature = "native")]
pub use cache::{BundleCache, BundleEntry, CacheManifest, CacheStatus};
#[cfg(feature = "native")]
pub use discover::discover_bundle_urls;
#[cfg(feature = "native")]
pub use download::{download_bundles, download_bundles_with, save_bundles};
#[cfg(feature = "native")]
pub use native::UreqClient;
