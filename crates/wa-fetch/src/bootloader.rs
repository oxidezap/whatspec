//! Browserless resolution of `bx` resource handles through WA Web's **bootloader
//! endpoint** — the request a real browser makes when it needs a component the entry
//! page didn't inline.
//!
//! # Why this exists
//!
//! A wasm URL is never in the JS. The glue asks the bootloader for a numeric id
//! (`r("bx").getURL(r("bx")("33861"))`) and the id→URI map (`bxData`) is server state.
//! The entry page inlines only the handles the initial route needs — 3 of them in
//! practice — so the rest of the client's wasm (the VoIP engine, media codecs, the
//! post-quantum wrapper) is invisible to a page-only scrape. Asking
//! `/ajax/bootloader-endpoint/` for the components the page deferred returns their
//! `bxData` too, which is what makes full wasm discovery possible *without a browser*.
//!
//! # Non-determinism, handled
//!
//! The server answers the same request with **different subsets** of `bxData` (observed
//! 3, 6 and 9 wasm URIs for one unchanged `client_revision`), and the `modules` and
//! `nb_modules` request forms surface different entries. So a single call proves nothing:
//! [`resolve_wasm_with`] merges both forms over repeated rounds and stops when a whole
//! round adds nothing new. It reports what it did (rounds, requests, failures) rather
//! than pretending the result is a closed set — callers treat wasm as a best-effort
//! superset, never as a reproducibility anchor.
//!
//! WASM-safe: everything here goes through the [`HttpClient`] port.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::discover::{Discovered, collect_bx_data, is_wasm_url};
use crate::http::HttpClient;
use crate::util::{UA, host_of};

/// Only resources served from WA's static CDN are ever fetched, whatever the server
/// payload claims — a `bxData` URI is remote input, and the download step must not be
/// steerable to an arbitrary host.
const ALLOWED_HOST: &str = "static.whatsapp.net";

/// Domains the bootloader endpoint may live on. `endpointURI` is read out of the page,
/// i.e. it is remote input that decides where a request goes; restrict it the same way
/// the payload URLs are restricted rather than trusting whatever the page names.
const ENDPOINT_DOMAINS: [&str; 2] = [".whatsapp.com", ".whatsapp.net"];

/// Body cap for one bootloader-endpoint response (they run ~1 MB; this is slack).
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Anti-JSON-hijacking prefix Meta's `__a=1` endpoints prepend to their payloads.
const JSON_PREFIX: &str = "for (;;);";

/// The two module-parameter spellings the endpoint accepts. They return overlapping but
/// *unequal* payloads (`nb_modules` tends to carry more `rsrcMap`, `modules` more
/// `hsdp`/`bxData`), so both are asked.
const MODULE_PARAMS: [&str; 2] = ["nb_modules", "modules"];

/// Knobs for [`resolve_wasm_with`].
#[derive(Debug, Clone)]
pub struct WasmResolveOptions {
    /// Maximum passes over both request spellings. Each pass is 2 requests; a pass that adds
    /// no new `bxData` id ends the loop early.
    pub max_rounds: usize,
    /// Cap on components named in one request, keeping the query string sane. The
    /// deferred set is ~150 components in practice, well under this.
    pub max_components: usize,
}

impl Default for WasmResolveOptions {
    fn default() -> Self {
        Self {
            max_rounds: 3,
            max_components: 512,
        }
    }
}

/// What one resolution pass learned.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WasmResolution {
    /// `bx` id → wasm URL, for every wasm handle resolved (page + endpoint).
    pub by_id: BTreeMap<String, String>,
    /// Wasm URLs, deduped and sorted — what the downloader consumes. Includes any URL
    /// discovered by text scan that no `bx` id claimed.
    pub urls: Vec<String>,
    /// Handles the page already carried, before any request.
    pub from_page: usize,
    /// Rounds actually run (a round is one pass over both request spellings).
    pub rounds: usize,
    /// Requests actually sent.
    pub requests: usize,
    /// Requests that failed or returned a non-2xx / unparseable body, as diagnostics.
    /// Non-fatal: resolution degrades to whatever the other requests returned.
    pub failures: Vec<String>,
}

impl WasmResolution {
    /// The inverse index: wasm URL → the `bx` handle that resolved it. Where several
    /// handles point at one URL, the lowest id wins (`by_id` is sorted, so this is
    /// deterministic) — the pairing is provenance metadata, not identity.
    pub fn handle_by_url(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (id, url) in &self.by_id {
            out.entry(url.clone()).or_insert_with(|| id.clone());
        }
        out
    }
}

/// Resolve every wasm handle reachable without a browser: the page's own `bxData`, plus
/// what the bootloader endpoint reveals for the components the page deferred.
///
/// Never fails as a whole — a dead endpoint just yields the page-only set with the
/// reason recorded in [`WasmResolution::failures`], because wasm is auxiliary to the
/// spec extraction and must not be able to break an `update` run.
pub fn resolve_wasm_with(
    client: &impl HttpClient,
    discovered: &Discovered,
    opts: &WasmResolveOptions,
) -> WasmResolution {
    let mut bx: BTreeMap<String, String> = discovered.bx_data.clone();
    let mut out = WasmResolution {
        from_page: bx.values().filter(|u| is_wasm_url(u)).count(),
        ..Default::default()
    };

    let components: Vec<&str> = discovered
        .deferred_components
        .iter()
        .take(opts.max_components)
        .map(String::as_str)
        .collect();
    if discovered.deferred_components.len() > components.len() {
        // Never silently truncate: a capped request set means an incomplete answer.
        out.failures.push(format!(
            "component list capped at {} of {} deferred components — raise max_components \
             for full coverage",
            components.len(),
            discovered.deferred_components.len()
        ));
    }

    if let Some(params) = &discovered.bootloader
        && !endpoint_is_trusted(&params.endpoint_uri)
    {
        out.failures.push(format!(
            "refusing the bootloader endpoint {}: not an https WhatsApp host",
            params.endpoint_uri
        ));
    } else if let (Some(params), false) = (&discovered.bootloader, components.is_empty()) {
        let joined = components.join(",");
        for round in 0..opts.max_rounds {
            let before = bx.len();
            for param in MODULE_PARAMS {
                let url = endpoint_url(params, param, &joined);
                out.requests += 1;
                match fetch_payload(client, &url) {
                    Ok(payload) => collect_bx_data(&payload, &mut bx),
                    Err(why) => out.failures.push(format!("{param} round {round}: {why}")),
                }
            }
            out.rounds += 1;
            // The server varies its answer per request, so "nothing new this round" is
            // the only usable convergence signal.
            if bx.len() == before {
                break;
            }
        }
    } else if discovered.bootloader.is_none() {
        out.failures.push(
            "page did not ship the bootloader endpoint parameters (SiteData / \
             BootloaderEndpointConfig) — only page-inlined handles are resolvable"
                .to_string(),
        );
    } else {
        // Nothing deferred means nothing to ask about — but it is also what a change in
        // the page's `compMap`/`rsrcMap` shape would look like, silently collapsing
        // resolution to the ~3 page-inlined handles. Say so rather than return a small
        // set as if it were the whole one.
        out.failures.push(
            "page deferred no server-fetchable components — nothing to ask the bootloader \
             endpoint (expected ~150; suspect a page-payload shape change)"
                .to_string(),
        );
    }

    let mut urls: Vec<String> = Vec::new();
    for (id, uri) in bx {
        if is_wasm_url(&uri) && is_cdn_payload(&uri) {
            urls.push(uri.clone());
            out.by_id.insert(id, uri);
        }
    }
    // A wasm URL the text scan found but no handle claimed still belongs in the set.
    urls.extend(
        discovered
            .wasm
            .iter()
            .filter(|u| is_cdn_payload(u))
            .cloned(),
    );
    urls.sort();
    urls.dedup();
    out.urls = urls;
    out
}

/// Convenience over [`resolve_wasm_with`] using the native
/// [`UreqClient`](crate::UreqClient).
#[cfg(feature = "native")]
pub fn resolve_wasm(discovered: &Discovered, opts: &WasmResolveOptions) -> WasmResolution {
    resolve_wasm_with(&crate::UreqClient::new(), discovered, opts)
}

/// Whether a payload URL may be downloaded: HTTPS, served by WA's static CDN exactly.
///
/// Both halves matter. The URL comes from a server payload, so the host is checked against
/// the allowlist (see [`host_of`], which strips userinfo — a URL like
/// `https://static.whatsapp.net:443@attacker.example/x.wasm` names `attacker.example` as
/// the host a client would connect to, and must not pass as the CDN). Plaintext is refused
/// so a downgraded URL can't put a fetched payload on the wire unauthenticated.
fn is_cdn_payload(url: &str) -> bool {
    url.starts_with("https://") && host_of(url).as_deref() == Some(ALLOWED_HOST)
}

/// Whether the page-supplied endpoint may be requested: HTTPS, on a WhatsApp domain.
///
/// The request carries no credentials, so the risk isn't leakage — it is that a page
/// change (or a tampered response upstream of us) could point the run at an arbitrary
/// host. The allowlist keeps "where we fetch from" a property of this code, not of the
/// page. The trailing-dot form in [`ENDPOINT_DOMAINS`] is what makes
/// `evil-whatsapp.com` and `whatsapp.com.evil.test` fail.
fn endpoint_is_trusted(uri: &str) -> bool {
    if !uri.starts_with("https://") {
        return false;
    }
    match host_of(uri) {
        Some(host) => ENDPOINT_DOMAINS
            .iter()
            .any(|d| host.ends_with(d) || host == d[1..]),
        None => false,
    }
}

/// Build one bootloader-endpoint URL. Mirrors the query a browser sends; `__a=1` is what
/// makes the server answer with the JSON payload (prefixed — see [`JSON_PREFIX`]).
fn endpoint_url(
    params: &crate::discover::BootloaderParams,
    module_param: &str,
    components: &str,
) -> String {
    // Values come from the page and are echoed back verbatim; percent-encode so a value
    // carrying `&`/`=`/space can't reshape the query.
    let q = |v: &str| percent_encode(v);
    format!(
        "{endpoint}?{module_param}={components}&__user=0&__a=1&__req=1&__hs={hs}&dpr=1\
         &__ccg=UNKNOWN&__rev={rev}&__hsi={hsi}&__comet_req={comet}&__spin_r={spin_r}\
         &__spin_b={spin_b}&__spin_t={spin_t}",
        endpoint = params.endpoint_uri,
        components = q(components),
        hs = q(&params.haste_session),
        rev = q(&params.client_revision),
        hsi = q(&params.hsi),
        comet = q(&params.comet_env),
        spin_r = q(&params.spin_rev),
        spin_b = q(&params.spin_branch),
        spin_t = q(&params.spin_time),
    )
}

/// Percent-encode everything outside the unreserved set (plus `,`, which the endpoint
/// uses as the component separator and accepts literally).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b',' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// GET one endpoint response and parse its (prefix-stripped) JSON body.
fn fetch_payload(client: &impl HttpClient, url: &str) -> Result<Value, String> {
    let resp = client
        .get(
            url,
            &[
                ("User-Agent", UA),
                ("Accept", "*/*"),
                ("Referer", crate::WA_WEB_URL),
            ],
            MAX_RESPONSE_BYTES,
        )
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {}", resp.status));
    }
    let text = String::from_utf8_lossy(&resp.body);
    let json = text.strip_prefix(JSON_PREFIX).unwrap_or(&text);
    serde_json::from_str(json).map_err(|e| format!("unparseable payload: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::BootloaderParams;

    fn params() -> BootloaderParams {
        BootloaderParams {
            endpoint_uri: "https://web.whatsapp.com/ajax/bootloader-endpoint/".to_string(),
            client_revision: "1043893604".to_string(),
            haste_session: "20261.HYP:whatsapp_web_pkg.2.1..0.0".to_string(),
            hsi: "7551".to_string(),
            spin_rev: "1043".to_string(),
            spin_branch: "trunk".to_string(),
            spin_time: "1753600000".to_string(),
            comet_env: "17".to_string(),
        }
    }

    #[test]
    fn endpoint_url_carries_every_stamp_and_encodes_values() {
        let url = endpoint_url(&params(), "nb_modules", "CompA,CompB");
        assert!(url.starts_with("https://web.whatsapp.com/ajax/bootloader-endpoint/?nb_modules="));
        // The comma separator survives; the `:` in haste_session is encoded.
        assert!(url.contains("nb_modules=CompA,CompB"), "{url}");
        assert!(
            url.contains("__hs=20261.HYP%3Awhatsapp_web_pkg.2.1..0.0"),
            "{url}"
        );
        for stamp in [
            "__a=1",
            "__rev=1043893604",
            "__hsi=7551",
            "__comet_req=17",
            "__spin_r=1043",
            "__spin_b=trunk",
            "__spin_t=1753600000",
        ] {
            assert!(url.contains(stamp), "missing {stamp} in {url}");
        }
    }

    #[test]
    fn payload_urls_must_be_https_on_the_cdn_host() {
        assert!(is_cdn_payload(
            "https://static.whatsapp.net/rsrc.php/x.wasm"
        ));
        // Plaintext, another host, and the userinfo trick that names a different host.
        assert!(!is_cdn_payload("http://static.whatsapp.net/x.wasm"));
        assert!(!is_cdn_payload("https://web.whatsapp.com/x.wasm"));
        assert!(!is_cdn_payload(
            "https://static.whatsapp.net:443@attacker.example/x.wasm"
        ));
    }

    #[test]
    fn only_https_whatsapp_endpoints_are_requestable() {
        assert!(endpoint_is_trusted(
            "https://web.whatsapp.com/ajax/bootloader-endpoint/"
        ));
        assert!(endpoint_is_trusted("https://whatsapp.com/x"));
        assert!(endpoint_is_trusted("https://static.whatsapp.net/x"));
        // Plaintext, look-alike and suffix-appended hosts are all refused.
        assert!(!endpoint_is_trusted(
            "http://web.whatsapp.com/ajax/bootloader-endpoint/"
        ));
        assert!(!endpoint_is_trusted("https://evil-whatsapp.com/x"));
        assert!(!endpoint_is_trusted("https://whatsapp.com.evil.test/x"));
        assert!(!endpoint_is_trusted("https://evil.test/whatsapp.com"));
        assert!(!endpoint_is_trusted("/relative"));
    }

    #[test]
    fn percent_encoding_neutralizes_query_injection() {
        // A hostile/odd page value must not be able to add parameters.
        assert_eq!(percent_encode("a&__a=0 b"), "a%26__a%3D0%20b");
        assert_eq!(percent_encode("safe-._~,"), "safe-._~,");
    }

    /// Resolution exercised through the [`HttpClient`] port with a canned client: no
    /// sockets, and — unlike a local test server — the endpoint can be a real WhatsApp
    /// URL, which is what the host allowlist requires. This is the WASM-safe path too.
    mod resolution {
        use super::*;
        use crate::http::{FetchError, HttpResponse};
        use std::sync::Mutex;

        /// Serves queued responses in order, then repeats the last one forever, and records
        /// every requested URL.
        struct CannedClient {
            queued: Mutex<std::collections::VecDeque<(u16, Vec<u8>)>>,
            repeat: (u16, Vec<u8>),
            urls: Mutex<Vec<String>>,
        }

        impl CannedClient {
            fn always(status: u16, body: Vec<u8>) -> Self {
                Self {
                    queued: Mutex::new(Default::default()),
                    repeat: (status, body),
                    urls: Mutex::new(Vec::new()),
                }
            }

            fn calls(&self) -> Vec<String> {
                self.urls.lock().unwrap().clone()
            }
        }

        impl HttpClient for CannedClient {
            fn get(
                &self,
                url: &str,
                _headers: &[(&str, &str)],
                _max_bytes: u64,
            ) -> Result<HttpResponse, FetchError> {
                self.urls.lock().unwrap().push(url.to_string());
                let (status, body) = self
                    .queued
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| self.repeat.clone());
                Ok(HttpResponse { status, body })
            }
        }

        /// A bootloader payload carrying `bxData` under `hrp.hsrp.hsdp`, as the real one does.
        fn payload(entries: &[(&str, &str)]) -> Vec<u8> {
            let bx: Vec<String> = entries
                .iter()
                .map(|(id, uri)| format!("\"{id}\":{{\"uri\":\"{uri}\"}}"))
                .collect();
            format!(
                "for (;;);{{\"hrp\":{{\"hsrp\":{{\"hsdp\":{{\"bxData\":{{{}}}}}}}}}}}",
                bx.join(",")
            )
            .into_bytes()
        }

        fn discovered_with(endpoint: &str, page_bx: &[(&str, &str)]) -> Discovered {
            Discovered {
                bx_data: page_bx
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                bootloader: Some(BootloaderParams {
                    endpoint_uri: endpoint.to_string(),
                    ..params()
                }),
                deferred_components: vec!["WAWebVoipWebWasmLoader".to_string()],
                ..Default::default()
            }
        }

        const ENDPOINT: &str = "https://web.whatsapp.com/ajax/bootloader-endpoint/";

        #[test]
        fn merges_page_and_endpoint_handles_and_filters_non_wasm() {
            let client = CannedClient::always(
                200,
                payload(&[
                    (
                        "32180",
                        "https://static.whatsapp.net/rsrc.php/v4/y/voip.wasm",
                    ),
                    // Not wasm → excluded.
                    (
                        "9547",
                        "https://static.whatsapp.net/rsrc.php/v4/y/icon.webp",
                    ),
                    // Off-CDN → excluded even though it is wasm.
                    ("6666", "https://evil.example/pwn.wasm"),
                    // Userinfo naming another host → likewise excluded.
                    (
                        "6667",
                        "https://static.whatsapp.net:443@attacker.example/pwn.wasm",
                    ),
                    // Plaintext on the right host → still refused.
                    ("6668", "http://static.whatsapp.net/plain.wasm"),
                ]),
            );
            let d = discovered_with(
                ENDPOINT,
                &[(
                    "33861",
                    "https://static.whatsapp.net/rsrc.php/v4/y/kaleidoscope.wasm",
                )],
            );

            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert_eq!(res.from_page, 1);
            assert_eq!(
                res.by_id.keys().collect::<Vec<_>>(),
                ["32180", "33861"],
                "page + endpoint handles, wasm only"
            );
            assert_eq!(res.urls.len(), 2, "{:?}", res.urls);
            assert!(!res.urls.iter().any(|u| u.contains("evil.example")));
            assert!(!res.urls.iter().any(|u| u.contains("attacker.example")));
            assert!(!res.urls.iter().any(|u| u.starts_with("http://")));
            assert!(res.failures.is_empty(), "{:?}", res.failures);
            // Both request spellings were tried, against the endpoint the page named.
            let calls = client.calls();
            assert!(calls.iter().any(|u| u.contains("nb_modules=")), "{calls:?}");
            assert!(
                calls
                    .iter()
                    .any(|u| u.contains("?modules=") || u.contains("&modules=")),
                "{calls:?}"
            );
            assert!(calls.iter().all(|u| u.starts_with(ENDPOINT)), "{calls:?}");
        }

        #[test]
        fn stops_after_a_round_that_adds_nothing() {
            let client =
                CannedClient::always(200, payload(&[("1", "https://static.whatsapp.net/a.wasm")]));
            let d = discovered_with(ENDPOINT, &[]);
            let res = resolve_wasm_with(
                &client,
                &d,
                &WasmResolveOptions {
                    max_rounds: 5,
                    ..Default::default()
                },
            );
            // Round 1 adds id 1; round 2 adds nothing and ends the loop.
            assert_eq!((res.rounds, res.requests), (2, 4));
            assert_eq!(res.urls, ["https://static.whatsapp.net/a.wasm"]);
        }

        #[test]
        fn a_varying_server_keeps_going_until_a_round_is_dry() {
            // The real endpoint dribbles out different subsets; resolution must accumulate
            // across rounds instead of trusting any single answer.
            let client = CannedClient::always(200, payload(&[]));
            {
                let mut q = client.queued.lock().unwrap();
                q.push_back((200, payload(&[("1", "https://static.whatsapp.net/a.wasm")])));
                q.push_back((200, payload(&[])));
                q.push_back((200, payload(&[("2", "https://static.whatsapp.net/b.wasm")])));
                q.push_back((200, payload(&[])));
            }
            let d = discovered_with(ENDPOINT, &[]);
            let res = resolve_wasm_with(
                &client,
                &d,
                &WasmResolveOptions {
                    max_rounds: 5,
                    ..Default::default()
                },
            );
            assert_eq!(
                res.urls,
                [
                    "https://static.whatsapp.net/a.wasm",
                    "https://static.whatsapp.net/b.wasm"
                ],
                "both subsets merged"
            );
            assert_eq!(res.rounds, 3, "round 3 added nothing and ended the loop");
        }

        #[test]
        fn endpoint_failure_degrades_to_page_handles() {
            let client = CannedClient::always(500, b"nope".to_vec());
            let d = discovered_with(ENDPOINT, &[("33861", "https://static.whatsapp.net/k.wasm")]);
            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert_eq!(res.urls, ["https://static.whatsapp.net/k.wasm"]);
            assert_eq!(res.failures.len(), 2, "both param forms failed");
            assert!(res.failures[0].contains("500"), "{:?}", res.failures);
        }

        #[test]
        fn an_unparseable_body_is_a_failure_not_a_panic() {
            let client = CannedClient::always(200, b"for (;;);{not json".to_vec());
            let d = discovered_with(ENDPOINT, &[]);
            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert!(res.urls.is_empty());
            assert!(
                res.failures
                    .iter()
                    .all(|f| f.contains("unparseable payload")),
                "{:?}",
                res.failures
            );
        }

        #[test]
        fn an_untrusted_endpoint_is_refused_without_a_request() {
            // A page pointing the endpoint elsewhere must not steer the run there.
            let client =
                CannedClient::always(200, payload(&[("1", "https://static.whatsapp.net/a.wasm")]));
            let d = discovered_with("http://127.0.0.1:9/be", &[]);
            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert_eq!(res.requests, 0, "nothing was requested");
            assert!(client.calls().is_empty());
            assert!(res.urls.is_empty());
            assert!(
                res.failures
                    .iter()
                    .any(|f| f.contains("not an https WhatsApp host")),
                "{:?}",
                res.failures
            );
        }

        #[test]
        fn no_deferred_components_is_reported_not_silently_small() {
            // The page-shape regression this guards: params present, but the deferred set
            // came out empty, so resolution would quietly stop at the page handles.
            let client = CannedClient::always(200, payload(&[]));
            let d = Discovered {
                bx_data: [(
                    "1".to_string(),
                    "https://static.whatsapp.net/a.wasm".to_string(),
                )]
                .into_iter()
                .collect(),
                bootloader: Some(params()),
                deferred_components: Vec::new(),
                ..Default::default()
            };
            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert_eq!(res.requests, 0);
            assert_eq!(res.urls.len(), 1, "page handles still resolved");
            assert!(
                res.failures
                    .iter()
                    .any(|f| f.contains("deferred no server-fetchable")),
                "{:?}",
                res.failures
            );
        }

        #[test]
        fn no_bootloader_params_means_no_requests() {
            let client = CannedClient::always(200, payload(&[]));
            let d = Discovered {
                bx_data: [(
                    "1".to_string(),
                    "https://static.whatsapp.net/a.wasm".to_string(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            let res = resolve_wasm_with(&client, &d, &WasmResolveOptions::default());
            assert_eq!(res.requests, 0);
            assert_eq!(res.urls.len(), 1);
            assert!(res.failures[0].contains("bootloader endpoint parameters"));
        }

        #[test]
        fn a_capped_component_list_is_reported() {
            // Silent truncation would read as "asked about everything".
            let client = CannedClient::always(200, payload(&[]));
            let mut d = discovered_with(ENDPOINT, &[]);
            d.deferred_components = (0..10).map(|i| format!("Comp{i}")).collect();
            let res = resolve_wasm_with(
                &client,
                &d,
                &WasmResolveOptions {
                    max_components: 3,
                    ..Default::default()
                },
            );
            assert!(
                res.failures.iter().any(|f| f.contains("capped at 3 of 10")),
                "{:?}",
                res.failures
            );
        }
    }
}
