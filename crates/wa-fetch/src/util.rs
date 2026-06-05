//! Shared URL helpers + the browser-like User-Agent. Pure and WASM-safe — the
//! TLS/HTTP backend lives in the native adapter ([`crate::UreqClient`]).

pub(crate) const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Unescape JSON-escaped URLs (`\/` → `/`).
pub(crate) fn unescape_json_url(raw: &str) -> String {
    raw.replace("\\/", "/")
}

/// `scheme://host[:port]` from a full URL (no trailing path).
pub(crate) fn origin_of(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        format!("{}{}", &url[..scheme_end + 3], &rest[..host_end])
    } else {
        url.trim_end_matches('/').to_string()
    }
}

/// Lowercased host of a URL, or `None` if there's no `scheme://host`.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let host = after.split(['/', '?', '#', ':']).next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Resolve a possibly-relative URL against an origin.
pub(crate) fn resolve(raw: &str, origin: &str) -> String {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else if let Some(rest) = raw.strip_prefix("//") {
        format!("https://{rest}")
    } else if raw.starts_with('/') {
        format!("{origin}{raw}")
    } else {
        format!("{}/{}", origin.trim_end_matches('/'), raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_handles_json_slashes() {
        assert_eq!(
            unescape_json_url("https:\\/\\/a.net\\/x.js"),
            "https://a.net/x.js"
        );
        assert_eq!(unescape_json_url("no-escapes"), "no-escapes");
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(origin_of("https://h.net/a/b.js"), "https://h.net");
        assert_eq!(origin_of("https://h.net:8443/a"), "https://h.net:8443");
        assert_eq!(origin_of("https://h.net"), "https://h.net");
        // No scheme: trim trailing slash.
        assert_eq!(origin_of("h.net/path/"), "h.net/path");
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("https://Static.WhatsApp.net/x.js").as_deref(),
            Some("static.whatsapp.net")
        );
        assert_eq!(host_of("http://h.net:80/x?q=1").as_deref(), Some("h.net"));
        assert_eq!(host_of("https://h.net").as_deref(), Some("h.net"));
        assert_eq!(host_of("/relative/path"), None);
        assert_eq!(host_of("https://"), None);
    }

    #[test]
    fn resolve_variants() {
        let o = "https://web.whatsapp.com";
        assert_eq!(resolve("https://x.net/a.js", o), "https://x.net/a.js");
        assert_eq!(resolve("http://x.net/a.js", o), "http://x.net/a.js");
        assert_eq!(resolve("//cdn.net/a.js", o), "https://cdn.net/a.js");
        assert_eq!(
            resolve("/rsrc/a.js", o),
            "https://web.whatsapp.com/rsrc/a.js"
        );
        assert_eq!(resolve("a.js", o), "https://web.whatsapp.com/a.js");
        assert_eq!(
            resolve("a.js", "https://web.whatsapp.com/"),
            "https://web.whatsapp.com/a.js"
        );
    }
}
