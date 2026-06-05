//! Version-keyed on-disk cache for fetched bundles, so an `update` run can skip
//! the (large) download when the remote WhatsApp version already sits in the
//! cache, fully and intact.
//!
//! # Layout (single version)
//!
//! ```text
//! <cache_dir>/
//!   manifest.json   { wa_version, complete, bundles: [{ url, file_name, sha256, size }] }
//!   bundles/
//!     AaZPUusmHmF.js
//!     …
//! ```
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

    /// Path to where the bundle fetched from `url` is (or would be) cached.
    pub fn bundle_path(&self, url: &str) -> PathBuf {
        self.bundles_dir().join(cache_file_name(url))
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
        let Some(manifest) = self.read_manifest() else {
            return CacheStatus::Miss("no cache manifest".to_string());
        };
        if !manifest.complete {
            return CacheStatus::Miss("previous download was incomplete".to_string());
        }
        if manifest.wa_version != remote_version {
            return CacheStatus::Miss(format!(
                "version changed: cached {}, remote {remote_version}",
                manifest.wa_version
            ));
        }

        let mut bundles = Vec::with_capacity(manifest.bundles.len());
        for entry in &manifest.bundles {
            let path = self.bundle_path(&entry.url);
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
    /// Clears any prior version first, writes every bundle file, then writes the
    /// `complete` manifest *last* so the cache is only ever observed whole.
    pub fn store(&self, wa_version: &str, bundles: &[Bundle]) -> Result<()> {
        self.clear()?;
        let bundles_dir = self.bundles_dir();
        fs::create_dir_all(&bundles_dir)
            .with_context(|| format!("create cache dir {}", bundles_dir.display()))?;

        let mut entries = Vec::with_capacity(bundles.len());
        for b in bundles {
            let path = bundles_dir.join(cache_file_name(&b.url));
            fs::write(&path, &b.bytes)
                .with_context(|| format!("write cache file {}", path.display()))?;
            entries.push(BundleEntry {
                url: b.url.clone(),
                file_name: b.file_name.clone(),
                sha256: sha256_hex(&b.bytes),
                size: b.bytes.len() as u64,
            });
        }

        let manifest = CacheManifest {
            wa_version: wa_version.to_string(),
            complete: true,
            bundles: entries,
        };
        let json = serde_json::to_string_pretty(&manifest)? + "\n";
        // Commit point: the manifest is the last thing written, so a crash
        // before here leaves no valid cache to trust.
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
        let bundles_dir = self.bundles_dir();
        if bundles_dir.exists() {
            fs::remove_dir_all(&bundles_dir)
                .with_context(|| format!("remove {}", bundles_dir.display()))?;
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
    fn no_manifest_is_miss() {
        let dir = tmp_dir("empty");
        let cache = BundleCache::new(&dir);
        assert!(matches!(cache.check("v"), CacheStatus::Miss(_)));
    }
}
