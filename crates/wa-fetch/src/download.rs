//! Parallel bundle download using plain `std::thread` (no async runtime).

// The download loop (threads) + save (fs) are native-only; the WASM-safe surface
// of this module is the data types + `bundle_file_name`, which need none of these.
#[cfg(feature = "native")]
use std::path::Path;
#[cfg(feature = "native")]
use std::sync::Mutex;
#[cfg(feature = "native")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "native")]
use anyhow::{Context, Result};

#[cfg(feature = "native")]
use crate::http::HttpClient;
#[cfg(feature = "native")]
use crate::util::UA;

/// A downloaded bundle held in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub url: String,
    /// Stable on-disk filename derived from the URL (see [`bundle_file_name`]).
    pub file_name: String,
    pub bytes: Vec<u8>,
}

/// A URL that failed to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadFailure {
    pub url: String,
    pub error: String,
}

/// Outcome of a batch download: successes + per-URL failures (non-fatal).
#[derive(Debug, Default)]
pub struct DownloadOutcome {
    pub bundles: Vec<Bundle>,
    pub failures: Vec<DownloadFailure>,
}

/// Knobs for [`download_bundles`].
#[derive(Debug, Clone)]
pub struct DownloadOptions {
    /// Concurrent worker threads.
    pub workers: usize,
    /// Per-bundle body cap (bytes).
    pub max_bytes: u64,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            workers: 16,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Derive a stable filename from a bundle URL.
///
/// WA bundle URLs end in a content-hashed segment (`.../r/AaZPUusmHmF.js`), so
/// the last path segment is unique. Falls back to a sanitized full URL when the
/// path has no usable last segment.
pub fn bundle_file_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let seg = path.rsplit('/').next().unwrap_or("");
    if seg.is_empty() {
        sanitize(url)
    } else {
        seg.to_string()
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Download all URLs concurrently through any [`HttpClient`], collecting per-URL
/// failures instead of aborting. Native-only: it parallelizes with
/// `std::thread::scope`, which isn't supported on `wasm32` — a browser adapter
/// downloads via its own (async) path, reusing only the WASM-safe discovery + the
/// [`HttpClient`] port.
#[cfg(feature = "native")]
pub fn download_bundles_with(
    client: &impl HttpClient,
    urls: &[String],
    opts: &DownloadOptions,
) -> DownloadOutcome {
    let cursor = AtomicUsize::new(0);
    let results: Mutex<Vec<std::result::Result<Bundle, DownloadFailure>>> =
        Mutex::new(Vec::with_capacity(urls.len()));
    let workers = opts.workers.clamp(1, urls.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let cursor = &cursor;
            let results = &results;
            scope.spawn(move || {
                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    if i >= urls.len() {
                        break;
                    }
                    let url = &urls[i];
                    let item = match fetch_bytes(client, url, opts.max_bytes) {
                        Ok(bytes) => Ok(Bundle {
                            url: url.clone(),
                            file_name: bundle_file_name(url),
                            bytes,
                        }),
                        Err(e) => Err(DownloadFailure {
                            url: url.clone(),
                            error: e.to_string(),
                        }),
                    };
                    results.lock().unwrap().push(item);
                }
            });
        }
    });

    let mut outcome = DownloadOutcome::default();
    for r in results.into_inner().unwrap() {
        match r {
            Ok(b) => outcome.bundles.push(b),
            Err(f) => outcome.failures.push(f),
        }
    }
    // Deterministic ordering regardless of thread scheduling.
    outcome.bundles.sort_by(|a, b| a.url.cmp(&b.url));
    outcome.failures.sort_by(|a, b| a.url.cmp(&b.url));
    outcome
}

/// Convenience over [`download_bundles_with`] using the native
/// [`UreqClient`](crate::UreqClient).
#[cfg(feature = "native")]
pub fn download_bundles(urls: &[String], opts: &DownloadOptions) -> DownloadOutcome {
    download_bundles_with(&crate::UreqClient::new(), urls, opts)
}

/// GET `url` and return its body, enforcing the 2xx-only status policy here (the
/// client surfaces non-2xx as a normal response, not an error).
#[cfg(feature = "native")]
fn fetch_bytes(client: &impl HttpClient, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let resp = client
        .get(url, &[("User-Agent", UA)], max_bytes)
        .with_context(|| format!("GET {url}"))?;
    if !(200..300).contains(&resp.status) {
        anyhow::bail!("HTTP {} for {url}", resp.status);
    }
    Ok(resp.body)
}

/// Longest bundle filename we'll write to disk. WA usually serves short,
/// content-hashed last segments (`AaZPUusmHmF.js`), but a few URLs carry a very
/// long final segment that overflows the filesystem's `NAME_MAX` (255 bytes on
/// ext4, less on some encrypted mounts). The on-disk name is only a transport
/// label — `update --bundles` reads every `.js` regardless of name and is
/// order-invariant, keyed on content — so an overlong name is safely replaced by
/// a bounded, URL-derived one.
#[cfg(feature = "native")]
const MAX_BUNDLE_FILE_NAME: usize = 128;

/// Write bundles to `dir/<file_name>`, creating `dir` if needed. Native-only
/// (`std::fs`); a browser build persists by its own means.
#[cfg(feature = "native")]
pub fn save_bundles(bundles: &[Bundle], dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;
    // Distinct URLs can share a last path segment across CDN shards, and some WA
    // segments overflow NAME_MAX; a bounded, unique name derived from the URL keeps
    // saving from clobbering or erroring (the dump must round-trip through
    // `--bundles`, which reads every `.js` regardless of name).
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    for b in bundles {
        let name = disk_file_name(&b.file_name, &b.url, &mut used);
        let path = dir.join(&name);
        std::fs::write(&path, &b.bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

/// A filesystem-safe, collision-free `.js` name for a saved bundle. Prefers the
/// readable URL segment; falls back to `<sha256(url)>.js` when that name is already
/// taken (CDN-shard collision) or too long for the filesystem. Deterministic given
/// the (url-sorted) bundle order, so the dump — and the archive built from it — is
/// reproducible.
#[cfg(feature = "native")]
fn disk_file_name(
    file_name: &str,
    url: &str,
    used: &mut std::collections::HashSet<String>,
) -> String {
    if file_name.len() <= MAX_BUNDLE_FILE_NAME && used.insert(file_name.to_string()) {
        return file_name.to_string();
    }
    // `<sha256(url)>.js`: 67 bytes, unique per URL, always read back by `--bundles`.
    // The numeric suffix covers only the degenerate same-URL-twice case.
    let hash = wa_text::sha256_hex(url.as_bytes());
    let mut name = format!("{hash}.js");
    let mut n = 1;
    while !used.insert(name.clone()) {
        name = format!("{hash}-{n}.js");
        n += 1;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn file_name_derivation() {
        assert_eq!(
            bundle_file_name("https://static.whatsapp.net/rsrc.php/v4/y0/r/AaZPUusmHmF.js"),
            "AaZPUusmHmF.js"
        );
        assert_eq!(bundle_file_name("https://h.net/a/b.js?x=1#frag"), "b.js");
        // No last segment → sanitized fallback.
        let fb = bundle_file_name("https://h.net/dir/");
        assert_eq!(fb, "https___h.net_dir_");
        assert!(!fb.contains('/'));
    }

    #[test]
    fn options_defaults() {
        let o = DownloadOptions::default();
        assert_eq!(o.workers, 16);
        assert!(o.max_bytes > 0);
    }

    #[cfg(feature = "native")]
    #[test]
    fn downloads_successes_and_records_failures() {
        use crate::testutil::spawn_server;
        use std::collections::HashMap;
        let mut routes = HashMap::new();
        routes.insert(
            "/a.js".to_string(),
            (200u16, b"__d(\"A\",[],function(){});".to_vec()),
        );
        routes.insert("/b.js".to_string(), (200u16, b"bbbb".to_vec()));
        routes.insert("/boom.js".to_string(), (500u16, b"err".to_vec()));
        // /missing.js -> 404 (default route).
        let base = spawn_server(routes);

        let urls = vec![
            format!("{base}/a.js"),
            format!("{base}/b.js"),
            format!("{base}/boom.js"),
            format!("{base}/missing.js"),
        ];
        let out = download_bundles(
            &urls,
            &DownloadOptions {
                workers: 4,
                ..Default::default()
            },
        );

        assert_eq!(out.bundles.len(), 2, "a + b succeed");
        assert_eq!(out.failures.len(), 2, "boom(500) + missing(404) fail");

        let a = out
            .bundles
            .iter()
            .find(|b| b.url.ends_with("/a.js"))
            .unwrap();
        assert_eq!(a.file_name, "a.js");
        assert!(a.bytes.starts_with(b"__d("));

        assert!(
            out.failures
                .iter()
                .any(|f| f.url.ends_with("/boom.js") && f.error.contains("500"))
        );
        assert!(out.failures.iter().any(|f| f.url.ends_with("/missing.js")));
    }

    #[cfg(feature = "native")]
    #[test]
    fn single_worker_serial_download_works() {
        use crate::testutil::spawn_server;
        use std::collections::HashMap;
        let mut routes = HashMap::new();
        routes.insert("/x.js".to_string(), (200u16, b"x".to_vec()));
        let base = spawn_server(routes);
        let urls = vec![format!("{base}/x.js")];
        let out = download_bundles(
            &urls,
            &DownloadOptions {
                workers: 1,
                ..Default::default()
            },
        );
        assert_eq!(out.bundles.len(), 1);
        assert_eq!(out.bundles[0].bytes, b"x");
    }

    #[cfg(feature = "native")]
    #[test]
    fn empty_url_list_is_noop() {
        let out = download_bundles(&[], &DownloadOptions::default());
        assert!(out.bundles.is_empty());
        assert!(out.failures.is_empty());
    }

    #[cfg(feature = "native")]
    #[test]
    fn max_bytes_cap_rejects_oversized_body() {
        use crate::testutil::spawn_server;
        use std::collections::HashMap;
        let mut routes = HashMap::new();
        routes.insert("/big.js".to_string(), (200u16, vec![b'z'; 4096]));
        let base = spawn_server(routes);
        let urls = vec![format!("{base}/big.js")];
        let out = download_bundles(
            &urls,
            &DownloadOptions {
                workers: 1,
                max_bytes: 16,
            },
        );
        assert_eq!(out.bundles.len(), 0);
        assert_eq!(out.failures.len(), 1);
    }

    #[cfg(feature = "native")]
    #[test]
    fn save_bundles_writes_files() {
        let dir = std::env::temp_dir().join(format!(
            "whatspec-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bundles = vec![
            Bundle {
                url: "u1".into(),
                file_name: "one.js".into(),
                bytes: b"hello".to_vec(),
            },
            Bundle {
                url: "u2".into(),
                file_name: "two.js".into(),
                bytes: b"world".to_vec(),
            },
        ];
        save_bundles(&bundles, &dir).unwrap();
        assert_eq!(std::fs::read(dir.join("one.js")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dir.join("two.js")).unwrap(), b"world");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "native")]
    #[test]
    fn save_bundles_disambiguates_colliding_file_names() {
        let dir = std::env::temp_dir().join(format!(
            "whatspec-collide-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Distinct URLs, same last path segment → both must survive (no clobber).
        let bundles = vec![
            Bundle {
                url: "https://a.example/v1/x.js".into(),
                file_name: "x.js".into(),
                bytes: b"AAA".to_vec(),
            },
            Bundle {
                url: "https://b.example/v2/x.js".into(),
                file_name: "x.js".into(),
                bytes: b"BBB".to_vec(),
            },
        ];
        save_bundles(&bundles, &dir).unwrap();
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            files.len(),
            2,
            "both bundles must be written, not clobbered"
        );
        let total: usize = files
            .iter()
            .map(|f| f.metadata().unwrap().len() as usize)
            .sum();
        assert_eq!(total, 6, "AAA + BBB both present");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "native")]
    #[test]
    fn save_bundles_bounds_overlong_file_names() {
        // Regression: a WA URL whose last path segment overflows the filesystem's
        // NAME_MAX must still be saved (under a bounded URL-hash name) rather than
        // failing with "File name too long". The dump is name-invariant, so the
        // rename never affects what `--bundles` regenerates.
        let dir = std::env::temp_dir().join(format!(
            "whatspec-longname-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let long = format!("{}.js", "a".repeat(300));
        assert!(long.len() > MAX_BUNDLE_FILE_NAME);
        let bundles = vec![Bundle {
            url: "https://a.example/rsrc/verylong".into(),
            file_name: long,
            bytes: b"payload".to_vec(),
        }];
        save_bundles(&bundles, &dir).unwrap();
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "the bundle is written under a bounded name");
        let name = files[0].file_name().to_string_lossy().into_owned();
        assert!(name.len() <= MAX_BUNDLE_FILE_NAME, "bounded: {name}");
        assert!(name.ends_with(".js"), "read back by --bundles: {name}");
        assert_eq!(
            std::fs::read(files[0].path()).unwrap(),
            b"payload",
            "bytes intact under the bounded name"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "native")]
    #[test]
    fn disk_file_name_prefers_readable_then_falls_back() {
        let mut used = std::collections::HashSet::new();
        // Short + unclaimed → kept verbatim.
        assert_eq!(
            disk_file_name("short.js", "https://x/short.js", &mut used),
            "short.js"
        );
        // Same readable name, different URL → bounded URL-hash fallback (no clobber).
        let n2 = disk_file_name("short.js", "https://y/short.js", &mut used);
        assert_ne!(n2, "short.js");
        assert!(n2.ends_with(".js") && n2.len() <= MAX_BUNDLE_FILE_NAME);
        // Overlong readable name → bounded fallback.
        let n3 = disk_file_name(&"z".repeat(300), "https://z/blob", &mut used);
        assert!(n3.ends_with(".js") && n3.len() <= MAX_BUNDLE_FILE_NAME);
    }
}
