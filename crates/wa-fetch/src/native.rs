//! Native adapter for the [`HttpClient`] port: a blocking client backed by
//! `ureq` over rustls with the pure-Rust OxiTLS/RustCrypto `CryptoProvider` (no `ring`,
//! so the dependency tree stays free of any C build).
//!
//! Gated behind the `native` feature; a WASM build leaves this out and supplies
//! its own browser-`fetch` adapter instead.

use std::sync::Arc;

use ureq::tls::{TlsConfig, TlsProvider};

use crate::http::{FetchError, HttpClient, HttpResponse, RedirectResponse};

/// TLS config: rustls with the pure-Rust OxiTLS/RustCrypto `CryptoProvider` instead of
/// `ring`. ureq's `rustls-no-provider` feature drops ring and refuses to pick a
/// backend from feature flags alone, so we hand the provider in explicitly;
/// roots come from the bundled webpki set (`rustls-webpki-roots`).
fn tls_config() -> TlsConfig {
    TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
        .build()
}

/// The native [`HttpClient`]: two reusable `ureq::Agent`s.
///
/// Both are configured with `http_status_as_error(false)` so a non-2xx response
/// comes back as an [`HttpResponse`] with that status (not an error), keeping the
/// status policy in the calling discovery/download code. They differ only in
/// redirect handling: `agent` follows them (what discovery and download want),
/// `no_redirect` stops at the 3xx so [`HttpClient::get_redirect`] can report the
/// `Location` rather than fetching it. Redirect following is agent-level config in
/// ureq, so it takes a second agent, not a per-request flag.
#[derive(Clone)]
pub struct UreqClient {
    agent: ureq::Agent,
    no_redirect: ureq::Agent,
}

impl UreqClient {
    pub fn new() -> Self {
        let agent: ureq::Agent = ureq::config::Config::builder()
            .http_status_as_error(false)
            .tls_config(tls_config())
            .build()
            .into();
        let no_redirect: ureq::Agent = ureq::config::Config::builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .tls_config(tls_config())
            .build()
            .into();
        Self { agent, no_redirect }
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqClient {
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<HttpResponse, FetchError> {
        let mut req = self.agent.get(url);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req
            .call()
            .map_err(|e| FetchError::new(format!("GET {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .into_with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|e| FetchError::new(format!("read body of {url}: {e}")))?;
        Ok(HttpResponse { status, body })
    }

    fn get_redirect(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<RedirectResponse, FetchError> {
        let mut req = self.no_redirect.get(url);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req
            .call()
            .map_err(|e| FetchError::new(format!("GET {url}: {e}")))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // The body of a 3xx is a stub, but it is still remote input: read it under the
        // caller's cap and drop it, so a server that answers a redirect probe with a
        // large body cannot make this allocate without bound.
        let _ = resp
            .into_body()
            .into_with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|e| FetchError::new(format!("read body of {url}: {e}")))?;
        Ok(RedirectResponse { status, location })
    }
}
