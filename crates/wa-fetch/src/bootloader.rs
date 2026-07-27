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
    /// Maximum passes over [`MODULE_PARAMS`]. Each pass is 2 requests; a pass that adds
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
    /// Rounds actually run (a round is one pass over [`MODULE_PARAMS`]).
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

    if let (Some(params), false) = (&discovered.bootloader, components.is_empty()) {
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
        if is_wasm_url(&uri) && host_of(&uri).as_deref() == Some(ALLOWED_HOST) {
            urls.push(uri.clone());
            out.by_id.insert(id, uri);
        }
    }
    // A wasm URL the text scan found but no handle claimed still belongs in the set.
    urls.extend(
        discovered
            .wasm
            .iter()
            .filter(|u| host_of(u).as_deref() == Some(ALLOWED_HOST))
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
    fn percent_encoding_neutralizes_query_injection() {
        // A hostile/odd page value must not be able to add parameters.
        assert_eq!(percent_encode("a&__a=0 b"), "a%26__a%3D0%20b");
        assert_eq!(percent_encode("safe-._~,"), "safe-._~,");
    }

    #[cfg(feature = "native")]
    mod live {
        use super::*;
        use crate::testutil::spawn_server;
        use std::collections::HashMap;

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

        #[test]
        fn merges_page_and_endpoint_handles_and_filters_non_wasm() {
            let mut routes = HashMap::new();
            routes.insert(
                "/be".to_string(),
                (
                    200u16,
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
                    ]),
                ),
            );
            let base = spawn_server(routes);
            let d = discovered_with(
                &format!("{base}/be"),
                &[(
                    "33861",
                    "https://static.whatsapp.net/rsrc.php/v4/y/kaleidoscope.wasm",
                )],
            );

            let res = resolve_wasm(&d, &WasmResolveOptions::default());
            assert_eq!(res.from_page, 1);
            assert_eq!(
                res.by_id.keys().collect::<Vec<_>>(),
                ["32180", "33861"],
                "page + endpoint handles, wasm only"
            );
            assert_eq!(res.urls.len(), 2, "{:?}", res.urls);
            assert!(!res.urls.iter().any(|u| u.contains("evil.example")));
            assert!(res.failures.is_empty(), "{:?}", res.failures);
        }

        #[test]
        fn stops_after_a_round_that_adds_nothing() {
            let mut routes = HashMap::new();
            routes.insert(
                "/be".to_string(),
                (
                    200u16,
                    payload(&[("1", "https://static.whatsapp.net/a.wasm")]),
                ),
            );
            let base = spawn_server(routes);
            let d = discovered_with(&format!("{base}/be"), &[]);
            let res = resolve_wasm(
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
        fn endpoint_failure_degrades_to_page_handles() {
            let mut routes = HashMap::new();
            routes.insert("/be".to_string(), (500u16, b"nope".to_vec()));
            let base = spawn_server(routes);
            let d = discovered_with(
                &format!("{base}/be"),
                &[("33861", "https://static.whatsapp.net/k.wasm")],
            );
            let res = resolve_wasm(&d, &WasmResolveOptions::default());
            assert_eq!(res.urls, ["https://static.whatsapp.net/k.wasm"]);
            assert_eq!(res.failures.len(), 2, "both param forms failed");
            assert!(res.failures[0].contains("500"), "{:?}", res.failures);
        }

        #[test]
        fn no_deferred_components_is_reported_not_silently_small() {
            // The page-shape regression this guards: params present, but the deferred set
            // came out empty, so resolution would quietly stop at the page handles.
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
            let res = resolve_wasm(&d, &WasmResolveOptions::default());
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
            let d = Discovered {
                bx_data: [(
                    "1".to_string(),
                    "https://static.whatsapp.net/a.wasm".to_string(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            let res = resolve_wasm(&d, &WasmResolveOptions::default());
            assert_eq!(res.requests, 0);
            assert_eq!(res.urls.len(), 1);
            assert!(res.failures[0].contains("bootloader endpoint parameters"));
        }
    }
}
