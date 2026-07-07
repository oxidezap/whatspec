//! `whatspec restore` — materialize the exact bundle set a `generated/` snapshot was
//! built from, out of the durable store, and verify it byte-for-byte against the
//! committed [`BundleLock`](crate::lock::BundleLock).
//!
//! WhatsApp only serves the current version, so past inputs can't be re-fetched from
//! source. The durable store is a **GitHub Release asset** (`bundle-store` release,
//! one `bundles-<ver>.tar.gz` per version). Restore pulls that archive (or a
//! caller-supplied local/URL one), unpacks it, and asserts the content-SHA-256
//! *multiset* equals the lock's — a dropped or swapped bundle fails loudly instead of
//! silently producing a different spec. The recovered directory feeds straight into
//! `whatspec update --bundles` (which is order-invariant, so filenames don't matter).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use wa_fetch::{HttpClient, UreqClient};

use crate::lock::BundleLock;

/// The rolling GitHub Release that accumulates one bundle archive per WA version.
const STORE_TAG: &str = "bundle-store";
/// Default `owner/repo` the release URL is built against (overridable via `--repo`
/// so a fork restores from its own store).
const DEFAULT_REPO: &str = "oxidezap/whatspec";
/// Hard ceiling on the archive download (the tar.gz is ~15 MB; this is slack).
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

pub struct RestoreOptions {
    pub lock_path: PathBuf,
    pub out: PathBuf,
    /// Explicit archive location — a local file path or an `http(s)://` URL. When
    /// absent, the release URL is derived from the lock's version + `repo`.
    pub archive: Option<String>,
    pub repo: String,
}

impl RestoreOptions {
    pub fn new(lock_path: PathBuf, out: PathBuf) -> Self {
        Self {
            lock_path,
            out,
            archive: None,
            repo: DEFAULT_REPO.to_string(),
        }
    }
}

pub fn restore(opts: &RestoreOptions) -> Result<()> {
    let lock = read_lock(&opts.lock_path)?;
    eprintln!(
        "restoring {} bundle(s) for {} (setHash {})",
        lock.bundle_count,
        lock.wa_version,
        &lock.set_hash[..12.min(lock.set_hash.len())]
    );

    let archive = resolve_archive(opts, &lock)?;
    let files = unpack_tar_gz(&archive)?;
    verify_against_lock(&files, &lock)?;
    let written = write_bundles(&files, &opts.out)?;

    eprintln!(
        "restored {} bundle(s) to {} — verified against the lock",
        written,
        opts.out.display()
    );
    Ok(())
}

fn read_lock(path: &Path) -> Result<BundleLock> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read lockfile {}", path.display()))?;
    let lock: BundleLock =
        serde_json::from_str(&raw).with_context(|| format!("parse lockfile {}", path.display()))?;
    // The lock anchors the whole reproducibility chain — reject a hand-edited or
    // corrupted one (setHash/bundleCount out of sync with its bundle list) before
    // trusting it to select and verify an archive.
    lock.verify_self_consistent()
        .map_err(|why| anyhow::anyhow!("lockfile {} is inconsistent: {why}", path.display()))?;
    Ok(lock)
}

/// Fetch the archive bytes from the caller-supplied location, or the derived release
/// asset URL. A local path is read directly; anything `http(s)` is downloaded.
fn resolve_archive(opts: &RestoreOptions, lock: &BundleLock) -> Result<Vec<u8>> {
    if let Some(loc) = &opts.archive {
        if is_http_url(loc) {
            return download(loc);
        }
        let path = Path::new(loc);
        if path.is_file() {
            return std::fs::read(path).with_context(|| format!("read archive {loc}"));
        }
        bail!("--archive {loc} is neither an existing file nor an http(s) URL");
    }
    let url = release_asset_url(&opts.repo, &lock.wa_version, &lock.set_hash);
    download(&url)
}

fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// `…/releases/download/bundle-store/bundles-<ver>-<setHash>.tar.gz`.
///
/// The asset name is **content-addressed** (it carries the input `setHash`, not just
/// the version): a different bundle set produces a different name, so an archive can
/// never be overwritten with different bytes, and every past commit's lock always
/// resolves the exact archive it pins. The version prefix keeps the name browsable.
fn release_asset_url(repo: &str, wa_version: &str, set_hash: &str) -> String {
    format!(
        "https://github.com/{repo}/releases/download/{STORE_TAG}/bundles-{wa_version}-{set_hash}.tar.gz"
    )
}

fn download(url: &str) -> Result<Vec<u8>> {
    // A `GITHUB_TOKEN`, when present (CI), lifts the low unauthenticated rate limit;
    // the asset itself is public, so the token is a courtesy, not a requirement.
    let bearer = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![("User-Agent", "whatspec-restore")];
    if let Some(b) = &bearer {
        headers.push(("Authorization", b.as_str()));
    }

    eprintln!("downloading {url}");
    let resp = UreqClient::new()
        .get(url, &headers, MAX_ARCHIVE_BYTES)
        .with_context(|| format!("download {url}"))?;
    match resp.status {
        200 => Ok(resp.body),
        404 => bail!(
            "archive not found (HTTP 404): {url}\n\
             the bundle set for this version isn't published yet — run \
             scripts/publish-bundles.sh (or the update workflow) to upload it.",
        ),
        other => bail!("download {url} failed: HTTP {other}"),
    }
}

/// Unpack a gzip'd tar into `(file_name, bytes)` pairs (regular files only). The
/// file name is the entry's basename — a flat bundle directory, so unique.
fn unpack_tar_gz(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let mut out = Vec::new();
    for entry in tar.entries().context("read tar archive")? {
        let mut entry = entry.context("read tar entry")?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        let name = entry
            .path()
            .context("tar entry path")?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .context("tar entry has no file name")?;
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("read tar entry {name}"))?;
        out.push((name, bytes));
    }
    if out.is_empty() {
        bail!("archive contained no files");
    }
    Ok(out)
}

/// Assert the extracted content-SHA-256 multiset equals the lock's. Reports missing
/// (in lock, absent from archive) and extra (in archive, not in lock) so a mismatch
/// is actionable rather than a bare count.
fn verify_against_lock(files: &[(String, Vec<u8>)], lock: &BundleLock) -> Result<()> {
    let mut want: HashMap<&str, i64> = HashMap::new();
    for e in &lock.bundles {
        *want.entry(e.sha256.as_str()).or_default() += 1;
    }
    let got: Vec<String> = files
        .iter()
        .map(|(_, bytes)| wa_text::sha256_hex(bytes))
        .collect();
    let mut have: HashMap<&str, i64> = HashMap::new();
    for h in &got {
        *have.entry(h.as_str()).or_default() += 1;
    }
    if want == have {
        return Ok(());
    }
    let missing: Vec<&str> = want
        .keys()
        .filter(|h| have.get(*h).copied().unwrap_or(0) < want[*h])
        .copied()
        .collect();
    let extra: Vec<&str> = have
        .keys()
        .filter(|h| want.get(*h).copied().unwrap_or(0) < have[*h])
        .copied()
        .collect();
    bail!(
        "restored set does not match the lock: {} in archive vs {} locked; \
         {} missing, {} unexpected (e.g. missing {:?}, extra {:?})",
        files.len(),
        lock.bundle_count,
        missing.len(),
        extra.len(),
        missing.iter().take(3).collect::<Vec<_>>(),
        extra.iter().take(3).collect::<Vec<_>>(),
    );
}

/// Write the verified bundles into `out` (created if needed), first clearing any
/// stale `.js` so the directory holds *exactly* the restored set (a leftover bundle
/// would otherwise be concatenated by `update --bundles`).
fn write_bundles(files: &[(String, Vec<u8>)], out: &Path) -> Result<usize> {
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    for entry in std::fs::read_dir(out).with_context(|| format!("read {}", out.display()))? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("js") {
            std::fs::remove_file(&p).with_context(|| format!("remove stale {}", p.display()))?;
        }
    }
    let mut seen: HashMap<&str, ()> = HashMap::new();
    for (name, bytes) in files {
        if seen.insert(name.as_str(), ()).is_some() {
            bail!("archive has two entries named {name} — cannot restore flatly");
        }
        std::fs::write(out.join(name), bytes)
            .with_context(|| format!("write {}", out.join(name).display()))?;
    }
    Ok(files.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{BundleId, BundleLock};

    fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn lock_for(files: &[(&str, &[u8])]) -> BundleLock {
        BundleLock::new(
            "2.3000.TEST",
            files
                .iter()
                .map(|(_, b)| BundleId {
                    sha256: wa_text::sha256_hex(b),
                    size: b.len() as u64,
                    url: None,
                })
                .collect(),
        )
    }

    #[test]
    fn unpack_verify_write_roundtrip() {
        let files: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"beta")];
        let archive = tar_gz(files);
        let lock = lock_for(files);

        let unpacked = unpack_tar_gz(&archive).unwrap();
        verify_against_lock(&unpacked, &lock).unwrap();

        let dir = std::env::temp_dir().join(format!("wsr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A stale bundle must be swept so the restored dir is exactly the locked set.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale.js"), b"old").unwrap();
        let n = write_bundles(&unpacked, &dir).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dir.join("a.js")).unwrap(), b"alpha");
        assert!(!dir.join("stale.js").exists(), "stale .js swept");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_rejects_a_swapped_bundle() {
        let locked: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"beta")];
        let tampered: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"BETA-changed")];
        let unpacked = unpack_tar_gz(&tar_gz(tampered)).unwrap();
        let err = verify_against_lock(&unpacked, &lock_for(locked)).unwrap_err();
        assert!(err.to_string().contains("does not match the lock"), "{err}");
    }

    #[test]
    fn verify_rejects_a_dropped_bundle() {
        let locked: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"beta")];
        let short: &[(&str, &[u8])] = &[("a.js", b"alpha")];
        let unpacked = unpack_tar_gz(&tar_gz(short)).unwrap();
        let err = verify_against_lock(&unpacked, &lock_for(locked)).unwrap_err();
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn release_url_is_content_addressed() {
        assert_eq!(
            release_asset_url("oxidezap/whatspec", "2.3000.42", "abc123"),
            "https://github.com/oxidezap/whatspec/releases/download/bundle-store/bundles-2.3000.42-abc123.tar.gz"
        );
    }
}
