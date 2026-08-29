//! Revision-addressed lookup of Meta's **build archive** (`btarchive`) — the one
//! endpoint that names a `www` build by revision instead of by whatever the site is
//! serving right now.
//!
//! # What the endpoint is
//!
//! `https://www.facebook.com/btarchive/<client_revision>/<app>` answers `302` with a
//! signed, short-lived `scontent-<pop>.<region>.fbcdn.net` URL whose body is a
//! `application/zip` of ~370 MB: ~74 k flat members, each named `<sha256 of its own
//! bytes>.js|.css`, no directories, no wasm, no manifest. A member is one *pre-package*
//! unit; the `rsrc.php` bundles discovery collects are those units joined by
//! `;/*FB_PKG_DELIM*/`, which is why an unlocalized bundle is byte-identical to a
//! member and a localized one (`/l/en_US-j/`) never is: translation is substituted when
//! the package is served, after the archive was written. So this is a second addressing
//! of the *same build*, not of the same bundle set — see the note on the lockfile below.
//!
//! A revision that was never published for that app answers `404`, including the
//! revision right next to a real one, which makes the endpoint a cheap existence oracle:
//! [`lookup_archive_with`] settles "was this revision published" in one request with no
//! body, before anything commits to hundreds of megabytes.
//!
//! # Why this is native-only
//!
//! The endpoint refuses (`400`) unless the request carries a `Sec-Fetch-Site` the browser
//! itself would have stamped (`none`/`same-origin`); `cross-site` and absent are rejected
//! the same way `web.whatsapp.com/sw.js` rejects them. `Sec-Fetch-*` is a forbidden header
//! name, so page JavaScript cannot set it and no `fetch` adapter can work around it: the
//! path is unreachable from a browser by construction, not by omission. Gating the module
//! on `native` keeps the WASM build honest about that instead of shipping a call that can
//! only ever 400.
//!
//! # What the archive is *not*
//!
//! It is not a reproducibility anchor for `generated/`. 163 of the 516 bundles in
//! `bundles.lock.json` — 45 MB of 77 MB — are localized packages the archive holds only
//! in pre-translation form, so the locked set cannot be rehydrated from it byte-for-byte.
//! The `bundle-store` release the lockfile points at stays the only thing that can. What
//! the archive adds is reach *backwards*: a revision no longer served anywhere still
//! resolves here.

use anyhow::{Result, bail};

use crate::http::HttpClient;
use crate::util::{UA, host_of};

/// Where the archive is addressed from. Constant, not derived from any server payload —
/// the only remote input in this module is the `Location` the endpoint answers with.
pub const BTARCHIVE_ORIGIN: &str = "https://www.facebook.com";

/// The redirect target is a signed CDN URL whose host carries a per-PoP prefix
/// (`scontent-ord5-1.xx.fbcdn.net`, `scontent-lhr8-2.xx.fbcdn.net`, …), so it cannot be
/// pinned the way [`crate::WA_WEB_URL`]'s payloads are pinned to `static.whatsapp.net`.
/// The policy is therefore a *domain suffix*, matched with the leading dot so
/// `notfbcdn.net` and `fbcdn.net.attacker.test` cannot satisfy it, applied to the
/// userinfo-stripped host (see [`host_of`]) and only to a `Location` handed back by the
/// constant origin above. That is the smallest widening that admits the redirect: the
/// value is still remote input, and everything it does not match is refused rather than
/// fetched.
const PAYLOAD_HOST_SUFFIX: &str = ".fbcdn.net";

/// Cap for the redirect probe's body. A `302` carries a stub or nothing; anything
/// larger means the response is not the redirect this asked for.
const REDIRECT_MAX_BYTES: u64 = 64 * 1024;

/// The fetch-metadata headers the endpoint demands. `Sec-Fetch-Site: none` is what a
/// browser stamps on a top-level navigation the user typed, which is the only shape of
/// request this endpoint answers.
const ARCHIVE_HEADERS: &[(&str, &str)] = &[
    ("User-Agent", UA),
    ("Accept", "*/*"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
];

/// The apps a `www` revision can be archived for. The revision numbers the same build
/// train across Meta's properties, so the second path segment is what selects whose
/// bundles come back; an unknown segment answers `404` exactly like an unpublished
/// revision, so the set is closed here rather than passed through as a free string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveApp {
    WhatsApp,
    Instagram,
    Messenger,
    Facebook,
}

impl ArchiveApp {
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveApp::WhatsApp => "whatsapp",
            ArchiveApp::Instagram => "instagram",
            ArchiveApp::Messenger => "messenger",
            ArchiveApp::Facebook => "facebook",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "whatsapp" => Some(ArchiveApp::WhatsApp),
            "instagram" => Some(ArchiveApp::Instagram),
            "messenger" => Some(ArchiveApp::Messenger),
            "facebook" => Some(ArchiveApp::Facebook),
            _ => None,
        }
    }
}

/// A resolved archive: where its bytes are, for as long as the signature holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLocation {
    pub revision: u64,
    pub app: ArchiveApp,
    /// The `btarchive` URL that was asked — stable, and the thing worth recording.
    pub request_url: String,
    /// The signed CDN URL the endpoint redirected to. Expires (`oe=`), so it is a
    /// handle to fetch with now, never an identifier to store.
    pub payload_url: String,
    /// Host of `payload_url`, already checked against the allowed suffix.
    pub payload_host: String,
}

/// Whether a revision was ever published for an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveLookup {
    Published(Box<ArchiveLocation>),
    /// The endpoint answered `404`: no such revision for this app.
    NotPublished {
        revision: u64,
        app: ArchiveApp,
    },
}

/// The archive URL for a revision + app. Pure; no request is made.
pub fn archive_url(revision: u64, app: ArchiveApp) -> String {
    format!("{BTARCHIVE_ORIGIN}/btarchive/{revision}/{}", app.as_str())
}

/// Ask whether `revision` was published for `app`, and where its archive is.
///
/// Reads the `302` and stops there: the payload is hundreds of megabytes and the
/// [`HttpClient::get`] contract is a capped `Vec<u8>`, so following the redirect through
/// the port is not a thing this can do. The caller gets the signed URL and streams it by
/// its own means — which is also why this returns no bytes and downloads nothing.
pub fn lookup_archive_with(
    client: &impl HttpClient,
    revision: u64,
    app: ArchiveApp,
) -> Result<ArchiveLookup> {
    let url = archive_url(revision, app);
    let resp = client.get_redirect(&url, ARCHIVE_HEADERS, REDIRECT_MAX_BYTES)?;
    match resp.status {
        301..=308 => {
            let Some(location) = resp.location else {
                bail!(
                    "GET {url} returned HTTP {} with no Location header",
                    resp.status
                );
            };
            let payload_url = accept_payload_location(&location)
                .map_err(|why| anyhow::anyhow!("GET {url}: {why}"))?;
            let payload_host = host_of(&payload_url).unwrap_or_default();
            Ok(ArchiveLookup::Published(Box::new(ArchiveLocation {
                revision,
                app,
                request_url: url,
                payload_url,
                payload_host,
            })))
        }
        404 => Ok(ArchiveLookup::NotPublished { revision, app }),
        400 => bail!(
            "GET {url} returned HTTP 400 — the endpoint rejects a request without the \
             fetch-metadata headers a browser navigation carries; this build sends them, \
             so a 400 means the check changed shape."
        ),
        status => bail!("GET {url} returned HTTP {status} (expected a 3xx or 404)"),
    }
}

/// Convenience over [`lookup_archive_with`] using the native
/// [`UreqClient`](crate::UreqClient).
pub fn lookup_archive(revision: u64, app: ArchiveApp) -> Result<ArchiveLookup> {
    lookup_archive_with(&crate::UreqClient::new(), revision, app)
}

/// Admit a `Location` only if it is an absolute `https` URL on the allowed CDN suffix,
/// with a bare authority.
///
/// Relative targets are refused rather than resolved: the endpoint answers with an
/// absolute signed URL, so a relative one is not the redirect this asked for, and
/// resolving it would silently turn `www.facebook.com` into a fetch target of its own
/// choosing. An authority carrying userinfo is refused for the same reason and one more:
/// [`host_of`] reads the host correctly, but the URL is handed back to whatever fetches
/// it, and `@`/`\` in an authority is exactly where URL parsers disagree about which
/// half is the host — a WHATWG parser reads `\` as a path separator, so
/// `attacker.test\host.fbcdn.net` connects somewhere this check would otherwise admit. A signed archive URL has no userinfo, so the safe reading is that
/// anything with one is not the redirect this asked for. Errors say which rule refused
/// it — a host that shifts PoP is expected, a host that leaves the suffix is not.
fn accept_payload_location(location: &str) -> Result<String, String> {
    let location = location.trim();
    let Some(rest) = location.strip_prefix("https://") else {
        return Err(format!(
            "redirect Location {location:?} is not an absolute https URL"
        ));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.contains('@') || authority.contains('\\') {
        return Err(format!(
            "redirect Location {location:?} carries userinfo in its authority"
        ));
    }
    let Some(host) = host_of(location) else {
        return Err(format!("redirect Location {location:?} has no host"));
    };
    if !host.ends_with(PAYLOAD_HOST_SUFFIX) {
        return Err(format!(
            "redirect Location host {host:?} is outside {PAYLOAD_HOST_SUFFIX}"
        ));
    }
    Ok(location.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{FetchError, HttpResponse, RedirectResponse};
    use std::sync::Mutex;

    /// Answers one canned redirect probe and records what it was asked, so the URL
    /// shape, the headers and the byte cap are all observable without a socket.
    struct CannedRedirect {
        status: u16,
        location: Option<String>,
        seen: Mutex<Vec<(String, u64)>>,
        headers: Mutex<Vec<(String, String)>>,
    }

    impl CannedRedirect {
        fn new(status: u16, location: Option<&str>) -> Self {
            Self {
                status,
                location: location.map(str::to_string),
                seen: Mutex::new(Vec::new()),
                headers: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpClient for CannedRedirect {
        fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _max_bytes: u64,
        ) -> Result<HttpResponse, FetchError> {
            unreachable!("the archive lookup must never fetch a body")
        }

        fn get_redirect(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            max_bytes: u64,
        ) -> Result<RedirectResponse, FetchError> {
            self.seen.lock().unwrap().push((url.to_string(), max_bytes));
            *self.headers.lock().unwrap() = headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Ok(RedirectResponse {
                status: self.status,
                location: self.location.clone(),
            })
        }
    }

    /// An adapter that never grew the optional capability — the browser-`fetch` case.
    struct NoRedirectSupport;

    impl HttpClient for NoRedirectSupport {
        fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _max_bytes: u64,
        ) -> Result<HttpResponse, FetchError> {
            unreachable!("the archive lookup must never fetch a body")
        }
    }

    const SIGNED: &str =
        "https://scontent-ord5-1.xx.fbcdn.net/m1/v/t0.50410-6/An9FE6?oh=00_AQ&oe=6AB9C6D9";

    #[test]
    fn url_is_revision_then_app() {
        assert_eq!(
            archive_url(1046341789, ArchiveApp::WhatsApp),
            "https://www.facebook.com/btarchive/1046341789/whatsapp"
        );
        assert_eq!(
            archive_url(1046341789, ArchiveApp::Instagram),
            "https://www.facebook.com/btarchive/1046341789/instagram"
        );
        assert_eq!(ArchiveApp::parse("messenger"), Some(ArchiveApp::Messenger));
        assert_eq!(ArchiveApp::parse("whatsapp-web"), None);
    }

    #[test]
    fn published_revision_yields_the_signed_url() {
        let client = CannedRedirect::new(302, Some(SIGNED));
        let out = lookup_archive_with(&client, 1046341789, ArchiveApp::WhatsApp).unwrap();
        let ArchiveLookup::Published(loc) = out else {
            panic!("expected a published archive");
        };
        assert_eq!(loc.payload_url, SIGNED);
        assert_eq!(loc.payload_host, "scontent-ord5-1.xx.fbcdn.net");
        assert_eq!(
            loc.request_url,
            "https://www.facebook.com/btarchive/1046341789/whatsapp"
        );

        // The probe is capped and carries the fetch-metadata headers the endpoint
        // demands — without them it answers 400, so their absence is a silent break.
        let seen = client.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "one request, no body fetch");
        assert_eq!(seen[0].1, REDIRECT_MAX_BYTES);
        let headers = client.headers.lock().unwrap();
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Sec-Fetch-Site" && v == "none")
        );
    }

    #[test]
    fn unpublished_revision_is_not_an_error() {
        let client = CannedRedirect::new(404, None);
        assert_eq!(
            lookup_archive_with(&client, 1046341790, ArchiveApp::WhatsApp).unwrap(),
            ArchiveLookup::NotPublished {
                revision: 1046341790,
                app: ArchiveApp::WhatsApp,
            }
        );
    }

    #[test]
    fn location_off_the_allowed_suffix_is_refused() {
        for bad in [
            "https://attacker.test/m1/v/t0.50410-6/x",
            // Suffix matched without the dot would admit this one.
            "https://notfbcdn.net/m1/v/x",
            // …and a suffix matched anywhere in the host would admit this one.
            "https://scontent.fbcdn.net.attacker.test/m1/v/x",
            // Userinfo must not be read as the host (see `host_of`)…
            "https://scontent-ord5-1.xx.fbcdn.net@attacker.test/m1/v/x",
            // …and even when the host after it *is* allowed, the URL is refused rather
            // than handed on with credentials a parser might split differently.
            "https://user:pass@scontent-ord5-1.xx.fbcdn.net/m1/v/x",
            "https://attacker.test\\@scontent-ord5-1.xx.fbcdn.net/m1/v/x",
            // A WHATWG parser reads `\` as a path separator and connects to
            // attacker.test, while a naive suffix check sees an allowed host.
            "https://attacker.test\\scontent-ord5-1.xx.fbcdn.net/m1/v/x",
            // Relative: refused, not resolved against www.facebook.com.
            "/m1/v/t0.50410-6/An9FE6",
            "//scontent-ord5-1.xx.fbcdn.net/m1/v/x",
            // Plaintext, even on an allowed host.
            "http://scontent-ord5-1.xx.fbcdn.net/m1/v/x",
        ] {
            let client = CannedRedirect::new(302, Some(bad));
            let Err(err) = lookup_archive_with(&client, 1046341789, ArchiveApp::WhatsApp) else {
                panic!("must refuse {bad}");
            };
            assert!(
                err.to_string().contains("Location"),
                "error should name the redirect target: {err}"
            );
        }
    }

    #[test]
    fn redirect_without_location_is_an_error() {
        let client = CannedRedirect::new(302, None);
        let err = lookup_archive_with(&client, 1046341789, ArchiveApp::WhatsApp)
            .expect_err("a 302 with no Location resolves to nothing")
            .to_string();
        assert!(err.contains("no Location header"), "{err}");
    }

    #[test]
    fn fetch_metadata_rejection_names_the_cause() {
        let client = CannedRedirect::new(400, None);
        let err = lookup_archive_with(&client, 1046341789, ArchiveApp::WhatsApp)
            .expect_err("400 is the endpoint refusing the request shape")
            .to_string();
        assert!(err.contains("fetch-metadata"), "{err}");
    }

    #[test]
    fn unexpected_status_is_an_error() {
        let client = CannedRedirect::new(200, None);
        let err = lookup_archive_with(&client, 1046341789, ArchiveApp::WhatsApp)
            .expect_err("a 200 is not this endpoint's answer")
            .to_string();
        assert!(err.contains("expected a 3xx or 404"), "{err}");
    }

    /// The cap is the caller's policy but the adapter's job; a probe that overruns it
    /// must fail rather than return a truncated answer.
    #[test]
    fn a_body_over_the_cap_fails_the_lookup() {
        struct Overrun;
        impl HttpClient for Overrun {
            fn get(
                &self,
                _url: &str,
                _headers: &[(&str, &str)],
                _max_bytes: u64,
            ) -> Result<HttpResponse, FetchError> {
                unreachable!("the archive lookup must never fetch a body")
            }
            fn get_redirect(
                &self,
                url: &str,
                _headers: &[(&str, &str)],
                max_bytes: u64,
            ) -> Result<RedirectResponse, FetchError> {
                Err(FetchError::new(format!(
                    "read body of {url}: response larger than {max_bytes} bytes"
                )))
            }
        }
        let err = lookup_archive_with(&Overrun, 1046341789, ArchiveApp::WhatsApp)
            .expect_err("an overrun body is a transport failure, not a lookup result")
            .to_string();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn adapter_without_redirect_support_says_so() {
        let err = lookup_archive_with(&NoRedirectSupport, 1046341789, ArchiveApp::WhatsApp)
            .expect_err("the default capability is unsupported")
            .to_string();
        assert!(err.contains("redirect inspection"), "{err}");
    }

    /// The canned tests fix the policy; these fix the *adapter*, which is the half that
    /// decides whether a redirect is followed at all. Against a local server: the probe
    /// must report the 3xx instead of chasing it, and must still honour the byte cap.
    mod adapter {
        use super::*;
        use crate::testutil::spawn_server_with_headers;
        use std::collections::HashMap;

        #[test]
        fn probe_reports_the_location_without_following_it() {
            let mut routes = HashMap::new();
            routes.insert(
                "/btarchive/1046341789/whatsapp".to_string(),
                (
                    302,
                    vec![("Location".to_string(), SIGNED.to_string())],
                    Vec::new(),
                ),
            );
            // Following the redirect would leave the local server; the assertion that it
            // did not is the reported status still being the 302.
            let base = spawn_server_with_headers(routes);
            let client = crate::UreqClient::new();
            let resp = client
                .get_redirect(
                    &format!("{base}/btarchive/1046341789/whatsapp"),
                    ARCHIVE_HEADERS,
                    REDIRECT_MAX_BYTES,
                )
                .expect("probe");
            assert_eq!(resp.status, 302);
            assert_eq!(resp.location.as_deref(), Some(SIGNED));
        }

        #[test]
        fn probe_enforces_the_byte_cap() {
            let mut routes = HashMap::new();
            routes.insert("/big".to_string(), (200, Vec::new(), vec![b'x'; 4096]));
            let base = spawn_server_with_headers(routes);
            let client = crate::UreqClient::new();
            let err = client
                .get_redirect(&format!("{base}/big"), ARCHIVE_HEADERS, 128)
                .expect_err("a body past the cap must fail, not truncate")
                .to_string();
            assert!(err.contains("read body of"), "{err}");
        }
    }
}
