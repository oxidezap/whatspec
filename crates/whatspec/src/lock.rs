//! The bundle **lockfile** — the committed record of exactly which WhatsApp Web
//! JS bundles produced a given `generated/` snapshot.
//!
//! WhatsApp only serves the *current* version; old bundle URLs 404, so the inputs
//! that made a past `generated/` can't be re-fetched from source. The lock captures
//! their identity (content SHA-256 + size, plus the origin URL when known) so the
//! exact set can be restored from a durable store (a GitHub Release asset — see
//! [`crate`]'s `restore`) and the generation reproduced byte-for-byte.
//!
//! The set is **content-addressed and order-independent**: `generated/` is invariant
//! to bundle concatenation order (proven end-to-end), so the identity is the *multiset*
//! of bundle contents, not their filenames or order. [`set_hash`] fingerprints that
//! multiset in one line; [`BundleLock`] carries the full per-bundle detail.

use serde::{Deserialize, Serialize};

/// One bundle's identity, as collected during a generation run. The `url` is present
/// only in the fetch path (discovery knows it); the offline `--bundles` path leaves it
/// `None` — resolution never needs it (restore pulls the whole archive, not per-URL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleId {
    /// Lowercase hex SHA-256 of the bundle bytes.
    pub sha256: String,
    pub size: u64,
    pub url: Option<String>,
}

/// A committed bundle lockfile (`generated/bundles.lock.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleLock {
    /// The WhatsApp version these bundles belong to (keys the durable store asset).
    pub wa_version: String,
    /// One-line fingerprint of the whole input multiset — see [`set_hash`].
    pub set_hash: String,
    pub bundle_count: usize,
    /// Every bundle, sorted by `(sha256, url)` for a deterministic, diffable file.
    pub bundles: Vec<LockEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockEntry {
    pub sha256: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
}

/// One-line fingerprint of a bundle set: SHA-256 over the **sorted** `sha256:size`
/// lines. Order-independent (sorted) and count-sensitive (no dedup — a module served
/// from two URLs contributes its bytes twice, exactly as the generator concatenates
/// them), so two runs fingerprint equal **iff** they consumed the same input multiset.
pub fn set_hash(bundles: &[BundleId]) -> String {
    let mut lines: Vec<String> = bundles
        .iter()
        .map(|b| format!("{}:{}", b.sha256, b.size))
        .collect();
    lines.sort();
    wa_text::sha256_hex(lines.join("\n").as_bytes())
}

impl BundleLock {
    /// Build a lock from a generation run's collected bundle ids.
    pub fn new(wa_version: &str, mut bundles: Vec<BundleId>) -> Self {
        bundles.sort_by(|a, b| a.sha256.cmp(&b.sha256).then_with(|| a.url.cmp(&b.url)));
        let set_hash = set_hash(&bundles);
        let bundle_count = bundles.len();
        BundleLock {
            wa_version: wa_version.to_string(),
            set_hash,
            bundle_count,
            bundles: bundles
                .into_iter()
                .map(|b| LockEntry {
                    sha256: b.sha256,
                    size: b.size,
                    url: b.url,
                })
                .collect(),
        }
    }

    /// Serialize to the committed on-disk form: pretty JSON with a trailing newline
    /// (matching every other artifact `whatspec` writes).
    pub fn to_pretty_json(&self) -> String {
        // Infallible: the type is plain owned data with no non-string map keys.
        serde_json::to_string_pretty(self).expect("BundleLock serializes") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(sha: &str, size: u64, url: Option<&str>) -> BundleId {
        BundleId {
            sha256: sha.to_string(),
            size,
            url: url.map(str::to_string),
        }
    }

    #[test]
    fn set_hash_is_order_independent() {
        let a = [id("aa", 1, None), id("bb", 2, None), id("cc", 3, None)];
        let b = [id("cc", 3, None), id("aa", 1, None), id("bb", 2, None)];
        assert_eq!(set_hash(&a), set_hash(&b), "sorted set is order-invariant");
    }

    #[test]
    fn set_hash_ignores_url_but_tracks_content_and_size() {
        // URL is provenance metadata, not identity: same bytes/size → same fingerprint.
        let with_url = [id("aa", 1, Some("https://x/a.js"))];
        let no_url = [id("aa", 1, None)];
        assert_eq!(set_hash(&with_url), set_hash(&no_url));
        // A size change is a different input, even at the same (hypothetical) hash.
        assert_ne!(
            set_hash(&[id("aa", 1, None)]),
            set_hash(&[id("aa", 2, None)])
        );
    }

    #[test]
    fn set_hash_counts_duplicates() {
        // A module served from two URLs is concatenated twice → the multiset differs
        // from the same module appearing once.
        let once = [id("aa", 1, None)];
        let twice = [id("aa", 1, None), id("aa", 1, None)];
        assert_ne!(set_hash(&once), set_hash(&twice));
    }

    #[test]
    fn lock_is_sorted_and_round_trips() {
        let lock = BundleLock::new(
            "2.3000.1",
            vec![
                id("ff", 9, Some("https://x/z.js")),
                id("aa", 1, Some("https://x/a.js")),
            ],
        );
        // Sorted by sha256 regardless of input order.
        assert_eq!(lock.bundles[0].sha256, "aa");
        assert_eq!(lock.bundle_count, 2);
        assert_eq!(
            lock.set_hash,
            set_hash(&[id("aa", 1, None), id("ff", 9, None)])
        );

        let json = lock.to_pretty_json();
        assert!(json.ends_with('\n'));
        let back: BundleLock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lock);
    }

    #[test]
    fn url_absent_when_none() {
        let json = BundleLock::new("v", vec![id("aa", 1, None)]).to_pretty_json();
        assert!(
            !json.contains("url"),
            "None url is omitted from the file: {json}"
        );
    }
}
