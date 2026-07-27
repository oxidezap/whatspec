//! Version-keyed on-disk cache for fetched bundles, so an `update` run can skip
//! the (large) download when the remote WhatsApp version already sits in the
//! cache, fully and intact.
//!
//! # Layout (single version)
//!
//! ```text
//! <cache_dir>/
//!   manifest.json   { wa_version, complete, bundles: [ … ], wasm: [ … ] }
//!   bundles/
//!     AaZPUusmHmF.js
//!     …
//!   wasm/           (only when wasm was fetched)
//!     <sha256(url)>
//!     …
//! ```
//!
//! JS and wasm live in **separate subtrees and separate manifest lists** on purpose:
//! the JS set is concatenated into the source the extractors parse, so a wasm payload
//! that leaked into that list would put megabytes of binary into it. [`BundleCache::check`]
//! therefore only ever returns JS; wasm is read explicitly via
//! [`BundleCache::check_wasm`].
//!
//! The cache holds exactly one version at a time: storing a new version clears
//! the old one first (no unbounded growth).
//!
//! # Integrity & atomicity
//!
//! A [hit](CacheStatus::Hit) is returned only when *every* guard passes: the
//! manifest exists and is marked `complete`, its version equals the remote one,
//! its URL set matches what discovery just found, and every file is present with
//! the recorded size **and** SHA-256. A truncated or byte-corrupted file is a
//! [miss](CacheStatus::Miss), not a silent reuse.
//!
//! [`store`](BundleCache::store) writes the `manifest.json` *last* (after all
//! bundle files are on disk) and marks it `complete` only then. A crash partway
//! through leaves no valid manifest, so the next run re-downloads from scratch
//! instead of trusting a half-written cache. [`clear`](BundleCache::clear)
//! likewise removes the manifest first.
//!
//! Native-only (uses `std::fs`); not part of the WASM-safe port.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use wa_text::sha256_hex;

use crate::download::Bundle;

const MANIFEST_NAME: &str = "manifest.json";
const BUNDLES_DIR: &str = "bundles";
const WASM_DIR: &str = "wasm";

/// One cached bundle's identity + integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEntry {
    pub url: String,
    pub file_name: String,
    /// Lowercase hex SHA-256 of the bundle bytes.
    pub sha256: String,
    pub size: u64,
}

/// The cache manifest: which version is cached, whether the download finished,
/// and the per-bundle integrity records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheManifest {
    pub wa_version: String,
    /// `true` only once every bundle has been written and recorded.
    pub complete: bool,
    pub bundles: Vec<BundleEntry>,
    /// Wasm payloads cached for this version, if any were fetched. Defaulted so a cache
    /// written before wasm support (or by a run that skipped it) still loads, reporting
    /// simply "no wasm cached".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasm: Vec<BundleEntry>,
}

/// Result of probing the cache against the freshly-discovered remote state.
#[derive(Debug)]
pub enum CacheStatus {
    /// Cache is usable: the loaded, integrity-checked bundles (ready to use).
    Hit(Vec<Bundle>),
    /// Cache is not usable; the string explains why (for diagnostics/logging).
    Miss(String),
}

/// On-disk file name for a bundle in the cache: the SHA-256 of its URL.
///
/// Distinct URLs whose last path segment (the logical [`Bundle::file_name`])
/// happens to coincide — WA serves e.g. `.../v4/yl/r/X.js` and `.../v4/yh/r/X.js`
/// — must not clobber each other on disk, so the cache keys files by full URL.
fn cache_file_name(url: &str) -> String {
    sha256_hex(url.as_bytes())
}

/// A version-keyed bundle cache rooted at a directory.
pub struct BundleCache {
    dir: PathBuf,
}

impl BundleCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANIFEST_NAME)
    }

    fn bundles_dir(&self) -> PathBuf {
        self.dir.join(BUNDLES_DIR)
    }

    fn wasm_dir(&self) -> PathBuf {
        self.dir.join(WASM_DIR)
    }

    /// Path to where the bundle fetched from `url` is (or would be) cached.
    pub fn bundle_path(&self, url: &str) -> PathBuf {
        self.bundles_dir().join(cache_file_name(url))
    }

    /// Path to where the wasm payload fetched from `url` is (or would be) cached.
    pub fn wasm_path(&self, url: &str) -> PathBuf {
        self.wasm_dir().join(cache_file_name(url))
    }

    /// Read and parse the manifest, or `None` if it's absent or unparseable.
    pub fn read_manifest(&self) -> Option<CacheManifest> {
        let raw = fs::read_to_string(self.manifest_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Probe the cache for `remote_version`.
    ///
    /// Returns [`CacheStatus::Hit`] with the loaded bundles only when the cache
    /// is complete, its version matches `remote_version`, and every recorded
    /// file passes its size + SHA-256 check. Otherwise [`CacheStatus::Miss`] with
    /// a human-readable reason.
    ///
    /// The cache is keyed by **version alone**, not by the discovered URL set:
    /// WhatsApp serves a slightly different bundle set per request (CDN shards /
    /// rollout) even for the same version, so the complete cached download is the
    /// canonical artifact for that version. Bundle bytes are content-addressed
    /// (the filename is a content hash), so a complete, intact cache of a version
    /// is safe to reuse.
    pub fn check(&self, remote_version: &str) -> CacheStatus {
        match self.usable_manifest(remote_version) {
            Err(miss) => miss,
            Ok(manifest) => self.load_set(&manifest.bundles, &self.bundles_dir()),
        }
    }

    /// Probe the cache for `remote_version`'s **wasm** payloads.
    ///
    /// Same all-or-nothing integrity contract as [`Self::check`], against the separate
    /// `wasm/` subtree. A cache written without wasm (an older run, or one that didn't
    /// ask for it) is a miss, not an empty hit — the caller must be able to tell "none
    /// cached" from "there are none".
    pub fn check_wasm(&self, remote_version: &str) -> CacheStatus {
        match self.usable_manifest(remote_version) {
            Err(miss) => miss,
            Ok(manifest) if manifest.wasm.is_empty() => {
                CacheStatus::Miss("no wasm cached for this version".to_string())
            }
            Ok(manifest) => self.load_set(&manifest.wasm, &self.wasm_dir()),
        }
    }

    /// The manifest, if it is complete and for `remote_version`; otherwise the
    /// [`CacheStatus::Miss`] explaining why it can't be used.
    fn usable_manifest(&self, remote_version: &str) -> Result<CacheManifest, CacheStatus> {
        let Some(manifest) = self.read_manifest() else {
            return Err(CacheStatus::Miss("no cache manifest".to_string()));
        };
        if !manifest.complete {
            return Err(CacheStatus::Miss(
                "previous download was incomplete".to_string(),
            ));
        }
        if manifest.wa_version != remote_version {
            return Err(CacheStatus::Miss(format!(
                "version changed: cached {}, remote {remote_version}",
                manifest.wa_version
            )));
        }
        Ok(manifest)
    }

    /// Read every recorded file from `dir`, verifying size **and** SHA-256. Any missing
    /// or corrupt file makes the whole set a miss.
    fn load_set(&self, entries: &[BundleEntry], dir: &std::path::Path) -> CacheStatus {
        let mut bundles = Vec::with_capacity(entries.len());
        for entry in entries {
            let path = dir.join(cache_file_name(&entry.url));
            let Ok(bytes) = fs::read(&path) else {
                return CacheStatus::Miss(format!("missing cached file {}", entry.file_name));
            };
            if bytes.len() as u64 != entry.size {
                return CacheStatus::Miss(format!("size mismatch for {}", entry.file_name));
            }
            if sha256_hex(&bytes) != entry.sha256 {
                return CacheStatus::Miss(format!("checksum mismatch for {}", entry.file_name));
            }
            bundles.push(Bundle {
                url: entry.url.clone(),
                file_name: entry.file_name.clone(),
                bytes,
            });
        }
        CacheStatus::Hit(bundles)
    }

    /// Replace the cache contents with `bundles` for `wa_version`.
    ///
    /// Clears any prior version first (including its wasm), writes every bundle file,
    /// then writes the `complete` manifest *last* so the cache is only ever observed
    /// whole. Wasm is added afterwards by [`Self::store_wasm`], which is the only way it
    /// enters a cache — a fresh `store` never carries any.
    pub fn store(&self, wa_version: &str, bundles: &[Bundle]) -> Result<()> {
        self.clear()?;
        let entries = self.write_set(bundles, &self.bundles_dir())?;
        self.write_manifest(&CacheManifest {
            wa_version: wa_version.to_string(),
            complete: true,
            bundles: entries,
            wasm: Vec::new(),
        })
    }

    /// Add `wasm` payloads to the existing cache for `wa_version`.
    ///
    /// Additive on purpose: wasm is fetched *after* (and independently of) the JS set, and
    /// a full `store` would wipe the hundreds of megabytes of JS that are the expensive
    /// part. Requires a complete cache of the same version — storing wasm against a
    /// missing or stale JS cache would produce a manifest whose two halves came from
    /// different WhatsApp builds.
    pub fn store_wasm(&self, wa_version: &str, wasm: &[Bundle]) -> Result<()> {
        let mut manifest = self.read_manifest().with_context(|| {
            format!(
                "no cache manifest at {} — store the JS bundles before their wasm",
                self.dir.display()
            )
        })?;
        if !manifest.complete || manifest.wa_version != wa_version {
            anyhow::bail!(
                "cache holds {} (complete: {}), refusing to attach wasm for {wa_version}",
                manifest.wa_version,
                manifest.complete
            );
        }
        // Replace rather than merge: the resolved wasm set for a version is whatever this
        // run found, and a stale entry from an earlier run would claim coverage it can no
        // longer prove.
        let wasm_dir = self.wasm_dir();
        if wasm_dir.exists() {
            fs::remove_dir_all(&wasm_dir)
                .with_context(|| format!("remove {}", wasm_dir.display()))?;
        }
        manifest.wasm = self.write_set(wasm, &wasm_dir)?;
        self.write_manifest(&manifest)
    }

    /// Write every bundle into `dir` (created if needed), returning their integrity
    /// records in input order.
    fn write_set(&self, bundles: &[Bundle], dir: &std::path::Path) -> Result<Vec<BundleEntry>> {
        fs::create_dir_all(dir).with_context(|| format!("create cache dir {}", dir.display()))?;
        let mut entries = Vec::with_capacity(bundles.len());
        for b in bundles {
            let path = dir.join(cache_file_name(&b.url));
            fs::write(&path, &b.bytes)
                .with_context(|| format!("write cache file {}", path.display()))?;
            entries.push(BundleEntry {
                url: b.url.clone(),
                file_name: b.file_name.clone(),
                sha256: sha256_hex(&b.bytes),
                size: b.bytes.len() as u64,
            });
        }
        Ok(entries)
    }

    /// Commit point: the manifest is the last thing written, so a crash before here
    /// leaves no valid cache to trust.
    fn write_manifest(&self, manifest: &CacheManifest) -> Result<()> {
        let json = serde_json::to_string_pretty(manifest)? + "\n";
        fs::write(self.manifest_path(), json)
            .with_context(|| format!("write {}", self.manifest_path().display()))?;
        Ok(())
    }

    /// Remove the cache (manifest first, so a crash mid-clear can't leave a
    /// valid manifest pointing at deleted files). A no-op if nothing is cached.
    pub fn clear(&self) -> Result<()> {
        let manifest = self.manifest_path();
        if manifest.exists() {
            fs::remove_file(&manifest).with_context(|| format!("remove {}", manifest.display()))?;
        }
        for dir in [self.bundles_dir(), self.wasm_dir()] {
            if dir.exists() {
                fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("whatspec-cache-test-{tag}-{nanos}"))
    }

    fn bundle(url: &str, file_name: &str, bytes: &[u8]) -> Bundle {
        Bundle {
            url: url.to_string(),
            file_name: file_name.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256 of "abc".
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn store_then_check_is_hit() {
        let dir = tmp_dir("hit");
        let cache = BundleCache::new(&dir);
        let bundles = vec![
            bundle("https://h/a.js", "a.js", b"alpha"),
            bundle("https://h/b.js", "b.js", b"beta"),
        ];
        cache.store("2.3000.1", &bundles).unwrap();

        match cache.check("2.3000.1") {
            CacheStatus::Hit(loaded) => {
                assert_eq!(loaded.len(), 2);
                let a = loaded.iter().find(|b| b.file_name == "a.js").unwrap();
                assert_eq!(a.bytes, b"alpha");
            }
            CacheStatus::Miss(why) => panic!("expected hit, got miss: {why}"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn version_mismatch_is_miss() {
        let dir = tmp_dir("ver");
        let cache = BundleCache::new(&dir);
        cache
            .store("2.3000.1", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        assert!(matches!(cache.check("2.3000.2"), CacheStatus::Miss(_)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_miss() {
        let dir = tmp_dir("missing");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        fs::remove_file(cache.bundle_path("https://h/a.js")).unwrap();
        assert!(matches!(cache.check("v"), CacheStatus::Miss(_)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn size_mismatch_is_miss() {
        let dir = tmp_dir("size");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"hello")])
            .unwrap();
        // Truncate the cached file on disk.
        fs::write(cache.bundle_path("https://h/a.js"), b"hi").unwrap();
        match cache.check("v") {
            CacheStatus::Miss(why) => assert!(why.contains("size"), "reason: {why}"),
            CacheStatus::Hit(_) => panic!("expected miss"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checksum_mismatch_is_miss() {
        let dir = tmp_dir("sum");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"hello")])
            .unwrap();
        // Corrupt the bytes in place, keeping the same length so size still matches.
        fs::write(cache.bundle_path("https://h/a.js"), b"world").unwrap();
        match cache.check("v") {
            CacheStatus::Miss(why) => assert!(why.contains("checksum"), "reason: {why}"),
            CacheStatus::Hit(_) => panic!("expected miss"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn incomplete_manifest_is_miss() {
        let dir = tmp_dir("incomplete");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        // Flip the manifest to incomplete (simulating an interrupted write path).
        let mut m = cache.read_manifest().unwrap();
        m.complete = false;
        fs::write(
            cache.manifest_path(),
            serde_json::to_string_pretty(&m).unwrap(),
        )
        .unwrap();
        assert!(matches!(cache.check("v"), CacheStatus::Miss(_)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_replaces_previous_version() {
        let dir = tmp_dir("replace");
        let cache = BundleCache::new(&dir);
        cache
            .store("v1", &[bundle("https://h/old.js", "old.js", b"old")])
            .unwrap();
        cache
            .store("v2", &[bundle("https://h/new.js", "new.js", b"new")])
            .unwrap();
        // Old file is gone; new manifest reflects v2 only.
        assert!(!cache.bundle_path("https://h/old.js").exists());
        assert!(cache.bundle_path("https://h/new.js").exists());
        let m = cache.read_manifest().unwrap();
        assert_eq!(m.wa_version, "v2");
        assert_eq!(m.bundles.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wasm_is_a_separate_set_and_never_leaks_into_the_js_hit() {
        // The load-bearing invariant: wasm bytes must not reach the JS list, which the
        // caller concatenates into the source the extractors parse.
        let dir = tmp_dir("wasm-split");
        let cache = BundleCache::new(&dir);
        cache
            .store("v1", &[bundle("https://h/a.js", "a.js", b"alpha")])
            .unwrap();
        cache
            .store_wasm(
                "v1",
                &[bundle("https://h/e.wasm", "e.wasm", b"\0asm\x01\0\0\0")],
            )
            .unwrap();

        match cache.check("v1") {
            CacheStatus::Hit(js) => {
                assert_eq!(js.len(), 1, "only the JS bundle");
                assert_eq!(js[0].file_name, "a.js");
            }
            CacheStatus::Miss(why) => panic!("expected JS hit: {why}"),
        }
        match cache.check_wasm("v1") {
            CacheStatus::Hit(wasm) => {
                assert_eq!(wasm.len(), 1);
                assert_eq!(wasm[0].file_name, "e.wasm");
                assert!(wasm[0].bytes.starts_with(b"\0asm"));
            }
            CacheStatus::Miss(why) => panic!("expected wasm hit: {why}"),
        }
        // Distinct subtrees on disk.
        assert!(cache.bundle_path("https://h/a.js").exists());
        assert!(cache.wasm_path("https://h/e.wasm").exists());
        assert!(!cache.bundle_path("https://h/e.wasm").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_without_wasm_is_a_wasm_miss_not_an_empty_hit() {
        let dir = tmp_dir("wasm-absent");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        match cache.check_wasm("v") {
            CacheStatus::Miss(why) => assert!(why.contains("no wasm cached"), "reason: {why}"),
            CacheStatus::Hit(_) => panic!("expected miss"),
        }
        // The manifest omits the empty list entirely, so an old cache file still parses.
        let raw = fs::read_to_string(cache.manifest_path()).unwrap();
        assert!(!raw.contains("wasm"), "{raw}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_wasm_is_a_miss_and_leaves_the_js_hit_intact() {
        let dir = tmp_dir("wasm-corrupt");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"alpha")])
            .unwrap();
        cache
            .store_wasm("v", &[bundle("https://h/e.wasm", "e.wasm", b"hello")])
            .unwrap();
        // Same length, different bytes → checksum mismatch.
        fs::write(cache.wasm_path("https://h/e.wasm"), b"world").unwrap();
        match cache.check_wasm("v") {
            CacheStatus::Miss(why) => assert!(why.contains("checksum"), "reason: {why}"),
            CacheStatus::Hit(_) => panic!("expected miss"),
        }
        assert!(
            matches!(cache.check("v"), CacheStatus::Hit(_)),
            "JS unaffected"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_wasm_refuses_a_missing_or_stale_js_cache() {
        let dir = tmp_dir("wasm-stale");
        let cache = BundleCache::new(&dir);
        let w = [bundle("https://h/e.wasm", "e.wasm", b"x")];
        // No cache at all.
        let err = cache.store_wasm("v1", &w).unwrap_err().to_string();
        assert!(err.contains("no cache manifest"), "{err}");
        // Cache for a different version.
        cache
            .store("v1", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        let err = cache.store_wasm("v2", &w).unwrap_err().to_string();
        assert!(err.contains("refusing to attach wasm"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn storing_a_new_version_drops_the_previous_wasm() {
        let dir = tmp_dir("wasm-replace");
        let cache = BundleCache::new(&dir);
        cache
            .store("v1", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        cache
            .store_wasm("v1", &[bundle("https://h/old.wasm", "old.wasm", b"old")])
            .unwrap();
        cache
            .store("v2", &[bundle("https://h/b.js", "b.js", b"y")])
            .unwrap();
        assert!(!cache.wasm_path("https://h/old.wasm").exists());
        assert!(cache.read_manifest().unwrap().wasm.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_wasm_replaces_rather_than_merges() {
        let dir = tmp_dir("wasm-nomerge");
        let cache = BundleCache::new(&dir);
        cache
            .store("v", &[bundle("https://h/a.js", "a.js", b"x")])
            .unwrap();
        cache
            .store_wasm("v", &[bundle("https://h/one.wasm", "one.wasm", b"1")])
            .unwrap();
        cache
            .store_wasm("v", &[bundle("https://h/two.wasm", "two.wasm", b"2")])
            .unwrap();
        let m = cache.read_manifest().unwrap();
        assert_eq!(m.wasm.len(), 1);
        assert_eq!(m.wasm[0].file_name, "two.wasm");
        assert!(!cache.wasm_path("https://h/one.wasm").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_manifest_is_miss() {
        let dir = tmp_dir("empty");
        let cache = BundleCache::new(&dir);
        assert!(matches!(cache.check("v"), CacheStatus::Miss(_)));
    }
}
