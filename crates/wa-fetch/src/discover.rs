//! Browserless discovery of WA Web bundle URLs + version, from the static HTML
//! and its `data-sjs` JSON payloads.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::http::HttpClient;
use crate::util::{UA, host_of, resolve, unescape_json_url};

pub const WA_WEB_URL: &str = "https://web.whatsapp.com/";
const ALLOWED_HOST: &str = "static.whatsapp.net";

/// Browser-like request headers sent when fetching the WA Web entry page.
const DISCOVERY_HEADERS: &[(&str, &str)] = &[
    ("User-Agent", UA),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
];

/// Body cap for the entry-page HTML.
const DISCOVERY_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Result of a discovery pass over the WA Web entry page.
#[derive(Debug, Default)]
pub struct Discovered {
    pub status: u16,
    /// `2.3000.<client_revision>` — see [`build_wa_version`].
    pub wa_version: Option<String>,
    /// `SiteData.client_revision` from the page payload.
    pub client_revision: Option<u64>,
    pub html_bytes: usize,
    /// JS bundle URLs on `static.whatsapp.net`.
    pub js: Vec<String>,
    /// WASM URLs referenced anywhere in the page JSON.
    pub wasm: Vec<String>,
    /// Per-source counts for diagnosing what the static page actually exposes.
    pub by_source: Sources,
}

#[derive(Debug, Default)]
pub struct Sources {
    pub script_tag: usize,
    pub rsrc_map: usize,
    pub scheduled_js: usize,
    pub wasm_ref: usize,
}

/// Fetch the WA Web HTML through any [`HttpClient`] and discover every JS/WASM
/// bundle URL it references. This is the port-level entry point: WASM-safe and
/// backend-agnostic.
pub fn discover_bundle_urls_with(client: &impl HttpClient, url: &str) -> Result<Discovered> {
    let resp = client
        .get(url, DISCOVERY_HEADERS, DISCOVERY_MAX_BYTES)
        .with_context(|| format!("GET {url}"))?;
    // A non-2xx response is an error/anti-bot page, not the entry document — fail
    // loud rather than scraping whatever stray `<script>` tags it happens to carry.
    if !(200..300).contains(&resp.status) {
        anyhow::bail!(
            "GET {url} returned HTTP {} (expected 2xx); {} bytes — likely an error or \
             anti-bot page, not the WhatsApp Web entry page.",
            resp.status,
            resp.body.len()
        );
    }
    let html = String::from_utf8_lossy(&resp.body);
    discover_from_html(resp.status, &html, url)
}

/// Convenience over [`discover_bundle_urls_with`] using the native
/// [`UreqClient`](crate::UreqClient).
#[cfg(feature = "native")]
pub fn discover_bundle_urls(url: &str) -> Result<Discovered> {
    discover_bundle_urls_with(&crate::UreqClient::new(), url)
}

/// Pure discovery over an already-fetched HTML body (network-free, WASM-safe,
/// testable). Useful for adapters that obtain the HTML by other means.
pub fn discover_from_html(status: u16, html: &str, base_url: &str) -> Result<Discovered> {
    let origin = crate::util::origin_of(base_url);
    let mut out = Discovered {
        status,
        html_bytes: html.len(),
        ..Default::default()
    };

    let mut js: BTreeSet<String> = BTreeSet::new();
    let mut wasm: BTreeSet<String> = BTreeSet::new();

    for script in extract_scripts(html) {
        // Phase 1: <script src="...">
        if let Some(src) = attr_value(script.attrs, "src") {
            let resolved = resolve(src, &origin);
            if host_of(&resolved).as_deref() == Some(ALLOWED_HOST) {
                if resolved.ends_with(".js") {
                    if js.insert(resolved.clone()) {
                        out.by_source.script_tag += 1;
                    }
                } else if resolved.ends_with(".wasm") {
                    wasm.insert(resolved);
                }
            }
        }

        // Phase 2: <script type="application/json" data-sjs> JSON payloads.
        if script.attrs.contains("data-sjs") {
            if let Ok(v) = serde_json::from_str::<Value>(script.body) {
                walk_require(&v, &mut js, &mut out.by_source);
                if out.client_revision.is_none() {
                    out.client_revision = find_client_revision(&v);
                }
            }
            scan_wasm_urls(script.body, &mut wasm, &mut out.by_source);
        }
    }

    out.wa_version = out.client_revision.map(build_wa_version);
    out.js = js.into_iter().collect();
    out.wasm = wasm.into_iter().collect();
    Ok(out)
}

/// Build the WA Web version string from `SiteData.client_revision`.
///
/// `WAWebBuildConstants` derives `Debug.VERSION` (which `wa-fetcher` reads via a
/// live browser) as `PRIMARY.SECONDARY.TERTIARY`. On the standard web build the
/// gatekeeper branch yields `PRIMARY="2"`, `SECONDARY="3000"`,
/// `TERTIARY=String(SiteData.client_revision)` — i.e. `2.3000.<client_revision>`.
/// The alternate branch (`3.0.0`) is not what web.whatsapp.com ships, so we take
/// the stable branch and recover the version fully browserless from the HTML.
pub fn build_wa_version(client_revision: u64) -> String {
    format!("2.3000.{client_revision}")
}

// ─── HTML script extraction (no HTML-parser dependency) ──────────────────────────

/// A `<script>` tag's opening-tag attribute string + body, borrowed from the HTML
/// (no per-tag allocation — the page has hundreds of scripts).
struct Script<'a> {
    attrs: &'a str,
    body: &'a str,
}

/// Extract `<script ...>...</script>` opening-tag attribute strings + bodies.
/// Quote-aware so `>` inside an attribute value doesn't end the tag early.
fn extract_scripts(html: &str) -> Vec<Script<'_>> {
    let bytes = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = html[i..].find("<script") {
        let start = i + rel;
        let after = start + "<script".len();
        // `<script` must be followed by a tag delimiter, not an identifier char —
        // otherwise `<scriptx>` (or a custom element) is mistaken for a script.
        if !matches!(
            bytes.get(after).copied(),
            None | Some(b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>')
        ) {
            i = after;
            continue;
        }
        let mut j = after;
        let mut quote = 0u8;
        let mut tag_end = None;
        while j < bytes.len() {
            let c = bytes[j];
            if quote != 0 {
                if c == quote {
                    quote = 0;
                }
            } else if c == b'"' || c == b'\'' {
                quote = c;
            } else if c == b'>' {
                tag_end = Some(j);
                break;
            }
            j += 1;
        }
        let Some(te) = tag_end else { break };
        let attrs = &html[after..te];
        let body_start = te + 1;
        let body = match html[body_start..].find("</script>") {
            Some(bp) => {
                let b = &html[body_start..body_start + bp];
                i = body_start + bp + "</script>".len();
                b
            }
            None => {
                i = html.len();
                &html[body_start..]
            }
        };
        out.push(Script { attrs, body });
    }
    out
}

/// Read `name="value"` / `name='value'` from an attribute string (borrowed).
fn attr_value<'a>(attrs: &'a str, name: &str) -> Option<&'a str> {
    for q in ['"', '\''] {
        let pat = format!("{name}={q}");
        if let Some(p) = attrs.find(&pat) {
            let rest = &attrs[p + pat.len()..];
            if let Some(end) = rest.find(q) {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

// ─── data-sjs `require` walk (Bootloader.rsrcMap + ScheduledServerJS.__d) ─────────

fn walk_require(v: &Value, js: &mut BTreeSet<String>, src: &mut Sources) {
    let Some(require) = v.get("require").and_then(Value::as_array) else {
        return;
    };
    for entry in require {
        let Some(arr) = entry.as_array() else {
            continue;
        };
        if arr.len() < 4 {
            continue;
        }
        let module = arr[0].as_str().unwrap_or("");
        let method = arr[1].as_str().unwrap_or("");
        let args = arr[3].as_array();

        if module == "Bootloader"
            && method == "handlePayload"
            && let Some(args) = args
        {
            for arg in args {
                if let Some(map) = arg.get("rsrcMap").and_then(Value::as_object) {
                    for val in map.values() {
                        if val.get("type").and_then(Value::as_str) == Some("js")
                            && let Some(s) = val.get("src").and_then(Value::as_str)
                        {
                            let u = unescape_json_url(s);
                            if host_of(&u).as_deref() == Some(ALLOWED_HOST) && js.insert(u) {
                                src.rsrc_map += 1;
                            }
                        }
                    }
                }
            }
        }

        if module == "ScheduledServerJS"
            && method == "handle"
            && let Some(args) = args
        {
            for arg in args {
                if let Some(defs) = arg.get("__d").and_then(Value::as_array) {
                    for def in defs {
                        let Some(da) = def.as_array() else { continue };
                        if da.len() < 3 {
                            continue;
                        }
                        if let Some(u) = da[2].get("url").and_then(Value::as_str) {
                            let u = unescape_json_url(u);
                            if u.ends_with(".js")
                                && host_of(&u).as_deref() == Some(ALLOWED_HOST)
                                && js.insert(u)
                            {
                                src.scheduled_js += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Scan raw JSON text for `.wasm` URLs (handles `\/` escaping).
fn scan_wasm_urls(text: &str, wasm: &mut BTreeSet<String>, src: &mut Sources) {
    let b = text.as_bytes();
    let mut search = 0;
    while let Some(rel) = text[search..].find(".wasm") {
        let dot = search + rel;
        let end = dot + ".wasm".len();
        let mut s = dot;
        while s > 0 {
            let c = b[s - 1];
            if matches!(
                c,
                b'"' | b'\'' | b',' | b' ' | b'\n' | b'\t' | b'(' | b'[' | b'>'
            ) {
                break;
            }
            s -= 1;
        }
        let tok = &text[s..end];
        if tok.contains("http") {
            let u = unescape_json_url(tok);
            if wasm.insert(u) {
                src.wasm_ref += 1;
            }
        }
        search = end;
    }
}

/// Recursively find the first `client_revision` integer in a JSON payload
/// (lives in the `SiteData` define entry).
fn find_client_revision(v: &Value) -> Option<u64> {
    match v {
        Value::Object(map) => {
            if let Some(r) = map.get("client_revision").and_then(Value::as_u64) {
                return Some(r);
            }
            map.values().find_map(find_client_revision)
        }
        Value::Array(arr) => arr.iter().find_map(find_client_revision),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    <html><head>
    <script src="https://static.whatsapp.net/rsrc.php/a.js"></script>
    <script src="//static.whatsapp.net/rsrc.php/b.js"></script>
    <script src="https://static.whatsapp.net/rsrc.php/icon.wasm"></script>
    <script src="https://other.cdn.net/skip.js"></script>
    <script src="https://static.whatsapp.net/style.css"></script>
    <script type="application/json" data-sjs>
    {"require":[
      ["Bootloader","handlePayload",null,[{"rsrcMap":{
        "x":{"type":"js","src":"https:\/\/static.whatsapp.net\/rsrc.php\/c.js"},
        "dup":{"type":"js","src":"https:\/\/static.whatsapp.net\/rsrc.php\/a.js"},
        "off":{"type":"js","src":"https:\/\/other.net\/d.js"},
        "y":{"type":"css","src":"https:\/\/static.whatsapp.net\/rsrc.php\/e.css"}
      }}]],
      ["ScheduledServerJS","handle",null,[{"__d":[
        ["m",[],{"url":"https:\/\/static.whatsapp.net\/rsrc.php\/f.js"}],
        ["n",[],{"url":"https:\/\/static.whatsapp.net\/rsrc.php\/g.css"}],
        ["short",[]]
      ]}]],
      ["Other","noop",null,[]],
      ["TooShort","x"]
    ],
    "define":[["SiteData",[],{"client_revision":1040225260,"server_revision":1040225260},270]]}
    </script>
    <script type="application/json" data-sjs>
    {"k":"voip https:\/\/static.whatsapp.net\/wasm\/audio.wasm and (https://static.whatsapp.net/wasm/b.wasm)"}
    </script>
    <script type="application/json" data-sjs>{ this is not json }</script>
    </head></html>
    "#;

    #[test]
    fn discovers_js_wasm_version_and_filters() {
        let d = discover_from_html(200, SAMPLE, "https://web.whatsapp.com/").unwrap();
        assert_eq!(d.status, 200);
        assert_eq!(d.wa_version.as_deref(), Some("2.3000.1040225260"));
        assert_eq!(d.client_revision, Some(1040225260));

        // a, b (script), c (rsrc), f (scheduled) — dedup a, drop css/off-host.
        assert!(d.js.contains(&"https://static.whatsapp.net/rsrc.php/a.js".to_string()));
        assert!(d.js.contains(&"https://static.whatsapp.net/rsrc.php/b.js".to_string()));
        assert!(d.js.contains(&"https://static.whatsapp.net/rsrc.php/c.js".to_string()));
        assert!(d.js.contains(&"https://static.whatsapp.net/rsrc.php/f.js".to_string()));
        assert_eq!(d.js.len(), 4);
        assert!(!d.js.iter().any(|u| u.contains("other")));
        assert!(!d.js.iter().any(|u| u.ends_with(".css")));

        // wasm: from script-tag + 2 in JSON text.
        assert!(
            d.wasm
                .contains(&"https://static.whatsapp.net/rsrc.php/icon.wasm".to_string())
        );
        assert!(
            d.wasm
                .contains(&"https://static.whatsapp.net/wasm/audio.wasm".to_string())
        );
        assert!(
            d.wasm
                .contains(&"https://static.whatsapp.net/wasm/b.wasm".to_string())
        );

        // source attribution.
        assert_eq!(d.by_source.script_tag, 2);
        assert_eq!(d.by_source.rsrc_map, 1); // only c (a is dup, off-host/css dropped)
        assert_eq!(d.by_source.scheduled_js, 1); // f
        assert!(d.by_source.wasm_ref >= 2);
    }

    #[test]
    fn version_none_when_no_sitedata() {
        let d =
            discover_from_html(200, "<html><body>no scripts</body></html>", WA_WEB_URL).unwrap();
        assert!(d.wa_version.is_none());
        assert!(d.client_revision.is_none());
        assert!(d.js.is_empty());
    }

    #[test]
    fn build_version_format() {
        assert_eq!(build_wa_version(1040208462), "2.3000.1040208462");
    }

    #[test]
    fn attr_value_quote_styles() {
        assert_eq!(attr_value(r#"src="x.js" id="a""#, "src"), Some("x.js"));
        assert_eq!(attr_value("src='y.js'", "src"), Some("y.js"));
        assert_eq!(attr_value("nosrc", "src"), None);
    }

    #[test]
    fn extract_scripts_handles_gt_in_attrs_and_unclosed() {
        // `>` inside an attribute value must not end the opening tag early.
        let html = r#"<script data-x="a>b" src="z.js"></script><script>tail"#;
        let scripts = extract_scripts(html);
        assert_eq!(scripts.len(), 2);
        assert_eq!(attr_value(scripts[0].attrs, "src"), Some("z.js"));
        assert_eq!(scripts[1].body, "tail"); // unclosed → rest-of-string body
    }

    #[cfg(feature = "native")]
    #[test]
    fn discover_bundle_urls_over_local_server() {
        use crate::testutil::spawn_server;
        use std::collections::HashMap;

        let mut routes = HashMap::new();
        routes.insert("/".to_string(), (200u16, SAMPLE.as_bytes().to_vec()));
        let base = spawn_server(routes);

        let d = discover_bundle_urls(&format!("{base}/")).unwrap();
        assert_eq!(d.status, 200);
        assert_eq!(d.wa_version.as_deref(), Some("2.3000.1040225260"));
        assert_eq!(d.js.len(), 4);
        assert!(d.html_bytes > 0);
    }

    #[test]
    fn find_client_revision_recurses() {
        let v: Value = serde_json::from_str(r#"{"a":[{"b":{"client_revision":7}}]}"#).unwrap();
        assert_eq!(find_client_revision(&v), Some(7));
        let none: Value = serde_json::from_str(r#"{"a":[1,2,"x"]}"#).unwrap();
        assert_eq!(find_client_revision(&none), None);
    }
}
