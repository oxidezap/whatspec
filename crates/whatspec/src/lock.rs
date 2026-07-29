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

use std::collections::BTreeMap;

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

    /// Recompute the fingerprint from `bundles` and confirm the recorded `setHash` and
    /// `bundleCount` still agree — so a hand-edited or corrupted lockfile is rejected
    /// before it's trusted to select and verify an archive (the lock is the anchor of
    /// the whole reproducibility chain; it must be self-consistent). `Err` carries a
    /// human-readable reason.
    pub fn verify_self_consistent(&self) -> Result<(), String> {
        if self.bundle_count != self.bundles.len() {
            return Err(format!(
                "bundleCount {} != {} entries",
                self.bundle_count,
                self.bundles.len()
            ));
        }
        let ids: Vec<BundleId> = self
            .bundles
            .iter()
            .map(|e| BundleId {
                sha256: e.sha256.clone(),
                size: e.size,
                url: None,
            })
            .collect();
        let recomputed = set_hash(&ids);
        if self.set_hash != recomputed {
            return Err(format!(
                "setHash {} does not match the bundle list (recomputed {recomputed})",
                self.set_hash
            ));
        }
        Ok(())
    }
}

/// One resolved wasm payload's identity, as collected during a fetch run.
///
/// Unlike a JS bundle, a wasm payload is addressed by a **bootloader handle** (`bx` id)
/// rather than by a module name, so the id is carried alongside the URL: it is the join
/// key back to the `wasm` IR domain, which records (statically) which JS modules consume
/// that handle. A payload found only by text scan has no id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmLockEntry {
    /// The `bx` handle that resolved to this URL, when one did.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bx_id: Option<String>,
    /// The content-hashed last URL segment (`COs9e0Kj0ic.wasm`) — the payload's published
    /// identity, and the name `--wasm-out` and the archive use. (A pathological set whose
    /// segments collide is renamed on disk by `save_bundles`; publishing then fails loudly
    /// on the mismatch rather than shipping an archive the lock can't describe.)
    pub file_name: String,
    pub url: String,
    /// Lowercase hex SHA-256 of the payload bytes.
    pub sha256: String,
    pub size: u64,
}

/// The bootloader extraction, pinned.
///
/// The JS never carries a wasm URL: it asks the bootloader for a numeric `bx` id, and only
/// the page's resource map turns that id into something fetchable. Nothing recorded that
/// map, so a change in the bootloader's shape showed up only as a wasm count that quietly
/// stopped growing — and `wasmResources` is deliberately unguarded, because most handles
/// address theme images that come and go.
///
/// What is pinned is the EXTRACTION, not the page. The HTML carries nonces and timestamps
/// and is byte-unstable by construction; hashing it would fail the determinism gate for
/// reasons that have nothing to do with the protocol. The resolved id→URI map is stable
/// for a given release, so it can be diffed across releases and read on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootloaderPins {
    /// Handles the page inlined, before any request to the bootloader endpoint.
    pub handles_from_page: usize,
    /// Every `bx` id that resolved to a wasm URL, page and endpoint together.
    pub wasm_handles: BTreeMap<String, String>,
    /// Endpoint requests sent, and how many came back unusable. A run that suddenly
    /// needs more rounds, or starts failing, is the early signal that the endpoint
    /// contract moved.
    pub requests: usize,
    pub failed_requests: usize,
    /// How many ways resolution came up short, INCLUDING the ones that never reached a
    /// request — a component list capped by `max_components`, a page that deferred
    /// nothing, endpoint parameters the page did not ship. `failed_requests` counts only
    /// requests that failed, so a capped run whose requests all succeeded pinned zeroes
    /// across the board and, with the handle map accumulating, left no diff at all to say
    /// the extraction had been incomplete.
    #[serde(default)]
    pub degradations: usize,
}

/// The wasm lockfile (`generated/wasm.lock.json`) — what a fetch run resolved and stored.
///
/// Deliberately **separate** from [`BundleLock`]:
///
/// - wasm bytes are not an input to `generated/`, so they must not perturb the JS
///   `setHash` that the reproducibility gate and the published archive names are built on;
/// - the resolved wasm set is **not** closed. The bootloader endpoint answers the same
///   request with different subsets, so a run records a best-effort superset. Treating it
///   as an exact input fingerprint would make CI flap on server variance alone.
///
/// It is still content-addressed (`wasmSetHash`) so the durable store can name an
/// immutable asset per distinct set — and an unchanged wasm set across WhatsApp versions
/// resolves to the same asset instead of re-uploading megabytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmLock {
    pub wa_version: String,
    /// Order-invariant fingerprint of the payload multiset — see [`set_hash`].
    pub wasm_set_hash: String,
    pub wasm_count: usize,
    /// Every payload, sorted by `(sha256, url)` for a deterministic, diffable file.
    /// What the page's bootloader actually yielded this run — see [`BootloaderPins`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootloader: Option<BootloaderPins>,
    pub wasm: Vec<WasmLockEntry>,
}

impl WasmLock {
    /// Build a lock from a fetch run's resolved payloads and what the bootloader yielded.
    ///
    /// `bootloader` is `None` only for a path that never asked it anything; a local
    /// `--bundles` regen does not reach here at all, so a recorded map is never
    /// overwritten with nothing.
    pub fn with_bootloader(
        wa_version: &str,
        mut wasm: Vec<WasmLockEntry>,
        bootloader: Option<BootloaderPins>,
    ) -> Self {
        wasm.sort_by(|a, b| a.sha256.cmp(&b.sha256).then_with(|| a.url.cmp(&b.url)));
        let ids: Vec<BundleId> = wasm.iter().map(WasmLockEntry::as_bundle_id).collect();
        Self {
            wa_version: wa_version.to_string(),
            wasm_set_hash: set_hash(&ids),
            wasm_count: wasm.len(),
            bootloader,
            wasm,
        }
    }

    /// Serialize to the committed on-disk form: pretty JSON with a trailing newline.
    pub fn to_pretty_json(&self) -> String {
        // Infallible: plain owned data with no non-string map keys.
        serde_json::to_string_pretty(self).expect("WasmLock serializes") + "\n"
    }

    /// Same self-consistency contract as [`BundleLock::verify_self_consistent`]: a
    /// hand-edited or corrupted lock must be rejected before it is trusted to select and
    /// verify an archive.
    pub fn verify_self_consistent(&self) -> Result<(), String> {
        if self.wasm_count != self.wasm.len() {
            return Err(format!(
                "wasmCount {} != {} entries",
                self.wasm_count,
                self.wasm.len()
            ));
        }
        let ids: Vec<BundleId> = self.wasm.iter().map(WasmLockEntry::as_bundle_id).collect();
        let recomputed = set_hash(&ids);
        if self.wasm_set_hash != recomputed {
            return Err(format!(
                "wasmSetHash {} does not match the payload list (recomputed {recomputed})",
                self.wasm_set_hash
            ));
        }
        Ok(())
    }
}

impl WasmLockEntry {
    /// The content identity [`set_hash`] fingerprints (URL is provenance, not identity).
    fn as_bundle_id(&self) -> BundleId {
        BundleId {
            sha256: self.sha256.clone(),
            size: self.size,
            url: None,
        }
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

    #[test]
    fn self_consistency_catches_tampering() {
        let lock = BundleLock::new("v", vec![id("aa", 1, None), id("bb", 2, None)]);
        lock.verify_self_consistent()
            .expect("freshly built lock is consistent");

        // A tampered bundle list no longer matches the recorded setHash.
        let mut tampered = lock.clone();
        tampered.bundles[0].sha256 = "cc".to_string();
        assert!(
            tampered
                .verify_self_consistent()
                .unwrap_err()
                .contains("setHash")
        );

        // A stale count is caught too.
        let mut miscount = lock.clone();
        miscount.bundle_count = 5;
        assert!(
            miscount
                .verify_self_consistent()
                .unwrap_err()
                .contains("bundleCount")
        );
    }

    fn wasm_entry(sha: &str, size: u64, url: &str, bx: Option<&str>) -> WasmLockEntry {
        WasmLockEntry {
            bx_id: bx.map(str::to_string),
            file_name: url.rsplit('/').next().unwrap_or(url).to_string(),
            url: url.to_string(),
            sha256: sha.to_string(),
            size,
        }
    }

    #[test]
    fn wasm_lock_sorts_fingerprints_and_round_trips() {
        let lock = WasmLock::with_bootloader(
            "2.3000.1",
            vec![
                wasm_entry("ff", 9, "https://s/y/voip.wasm", Some("32180")),
                wasm_entry("aa", 1, "https://s/x/liboqs.wasm", None),
            ],
            None,
        );
        assert_eq!(lock.wasm[0].sha256, "aa", "sorted by content hash");
        assert_eq!(lock.wasm[0].file_name, "liboqs.wasm");
        assert_eq!(lock.wasm_count, 2);
        // Same fingerprint function as the JS lock, over the payload multiset.
        assert_eq!(
            lock.wasm_set_hash,
            set_hash(&[id("aa", 1, None), id("ff", 9, None)])
        );
        lock.verify_self_consistent().unwrap();

        let json = lock.to_pretty_json();
        assert!(json.ends_with('\n'));
        // A payload with no handle omits the key rather than emitting null.
        assert!(json.contains("\"bxId\": \"32180\""), "{json}");
        let back: WasmLock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lock);
    }

    #[test]
    fn wasm_lock_hash_is_independent_of_the_js_lock() {
        // The two locks fingerprint different sets; a wasm change must not move setHash
        // (the published JS archive name and the reproducibility gate depend on it).
        let bundles = vec![id("aa", 1, Some("https://s/a.js"))];
        let js = BundleLock::new("v", bundles.clone());
        let wasm = WasmLock::with_bootloader(
            "v",
            vec![wasm_entry("bb", 2, "https://s/w.wasm", None)],
            None,
        );
        assert_ne!(js.set_hash, wasm.wasm_set_hash);
        assert_eq!(js.set_hash, BundleLock::new("v", bundles).set_hash);
    }

    #[test]
    fn wasm_self_consistency_catches_tampering() {
        let lock = WasmLock::with_bootloader(
            "v",
            vec![
                wasm_entry("aa", 1, "https://s/a.wasm", None),
                wasm_entry("bb", 2, "https://s/b.wasm", None),
            ],
            None,
        );
        let mut tampered = lock.clone();
        tampered.wasm[0].sha256 = "cc".to_string();
        assert!(
            tampered
                .verify_self_consistent()
                .unwrap_err()
                .contains("wasmSetHash")
        );
        let mut miscount = lock.clone();
        miscount.wasm_count = 7;
        assert!(
            miscount
                .verify_self_consistent()
                .unwrap_err()
                .contains("wasmCount")
        );
    }
    #[test]
    fn the_bootloader_map_survives_a_lock_round_trip() {
        // The id→URI map is the only thing that turns the numeric handle the JS asks for
        // into something fetchable, and nothing recorded it — a change in the bootloader
        // showed up only as a wasm count that quietly stopped growing.
        let pins = BootloaderPins {
            handles_from_page: 12,
            wasm_handles: BTreeMap::from([("30933".into(), "https://s/a.wasm".into())]),
            requests: 4,
            failed_requests: 1,
            degradations: 2,
        };
        let lock = WasmLock::with_bootloader(
            "2.3000.TEST",
            vec![wasm_entry("aa", 1, "https://s/a.wasm", Some("30933"))],
            Some(pins.clone()),
        );
        let back: WasmLock = serde_json::from_str(&lock.to_pretty_json()).expect("round trip");
        assert_eq!(back.bootloader.as_ref(), Some(&pins));
        // And a run that never asked the bootloader writes no key at all, so an offline
        // regen cannot be mistaken for "the map is empty now".
        let bare = WasmLock::with_bootloader("2.3000.TEST", Vec::new(), None);
        assert!(!bare.to_pretty_json().contains("bootloader"));
    }
}
