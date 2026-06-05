//! The HTTP *port* (in the ports-and-adapters sense): a small abstraction over
//! a blocking GET, so the discovery/download logic depends only on this trait
//! and never on a concrete client.
//!
//! - Native builds supply [`crate::UreqClient`] (ureq + rustls + RustCrypto).
//! - A future WASM/web build can implement this same trait over the browser
//!   `fetch` API as an adapter, with no change to the discovery logic.
//!
//! This module is WASM-safe (no native-only deps), so it compiles into the
//! browser target alongside the pure discovery parser.

use std::error::Error;
use std::fmt;

/// A minimal HTTP response: the status code plus the raw body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A transport-level failure from an [`HttpClient`] — DNS, connect, TLS, I/O,
/// or a body that exceeded the byte cap.
///
/// A non-2xx HTTP status is **not** an error here: it is a successful response
/// and surfaces via [`HttpResponse::status`], leaving the status policy to the
/// caller (discovery wants the status for diagnostics; download treats non-2xx
/// as a per-URL failure).
#[derive(Debug, Clone)]
pub struct FetchError {
    message: String,
}

impl FetchError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for FetchError {}

/// A blocking HTTP GET. Implementors are the *adapters* (native `ureq` today,
/// browser `fetch` tomorrow); everything else in this crate is the *port* that
/// depends only on this trait.
///
/// `Sync` is required so a single client can be borrowed across the download
/// worker threads in [`crate::download_bundles`].
pub trait HttpClient: Sync {
    /// GET `url` with the given extra request `headers`, reading at most
    /// `max_bytes` of the response body.
    ///
    /// A non-2xx status must be returned in the [`HttpResponse`], not as an
    /// error; only transport-level problems return [`FetchError`].
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<HttpResponse, FetchError>;
}
