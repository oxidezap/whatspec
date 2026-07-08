//! `whatspec restore` — materialize the exact bundle set a `generated/` snapshot was
//! built from, out of the durable store, and verify it byte-for-byte against the
//! committed [`BundleLock`](crate::lock::BundleLock).
//!
//! WhatsApp only serves the current version, so past inputs can't be re-fetched from
//! source. The durable store is a **GitHub Release asset** (`bundle-store` release,
//! one `bundles-<ver>-<setHash>.tar.xz` per version — legacy `.tar.gz` assets are still
//! read). Restore pulls that archive (or a caller-supplied local/URL one), unpacks it,
//! and asserts the content-SHA-256 *multiset* equals the lock's — a dropped or swapped
//! bundle fails loudly instead of silently producing a different spec. The recovered
//! directory feeds straight into `whatspec update --bundles` (which is order-invariant,
//! so filenames don't matter).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use wa_fetch::{HttpClient, UreqClient};

use crate::lock::BundleLock;

/// The rolling GitHub Release that accumulates one bundle archive per WA version.
const STORE_TAG: &str = "bundle-store";
/// Default `owner/repo` the release URL is built against (overridable via `--repo`
/// so a fork restores from its own store).
const DEFAULT_REPO: &str = "oxidezap/whatspec";
/// Hard ceiling on the archive download (the compressed archive is ~9 MB xz / ~16 MB
/// gzip; this is slack).
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
/// Magic bytes identifying the two archive envelopes `restore` accepts, so the
/// decompressor is chosen by content (not a filename/extension a caller controls).
const XZ_MAGIC: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
/// Hard ceiling on the *decompressed* bundle set (the real set is ~71 MB; slack for
/// growth, but bounds a decompression bomb from a caller-supplied `--archive`).
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

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
    let files = unpack_archive(&archive, MAX_UNPACKED_BYTES, lock.bundle_count)?;
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
///
/// For the derived case the extension isn't known ahead of time — the store now holds
/// `.tar.xz`, but older versions were published as `.tar.gz` and every past commit's
/// lock must keep resolving. So we try the current `.tar.xz` first and fall back to the
/// legacy `.tar.gz`; the decompressor is then chosen by magic bytes, not the URL.
fn resolve_archive(opts: &RestoreOptions, lock: &BundleLock) -> Result<Vec<u8>> {
    if let Some(loc) = &opts.archive {
        if is_http_url(loc) {
            return download_opt(loc)?
                .ok_or_else(|| anyhow::anyhow!("archive not found (HTTP 404): {loc}"));
        }
        let path = Path::new(loc);
        if path.is_file() {
            return std::fs::read(path).with_context(|| format!("read archive {loc}"));
        }
        bail!("--archive {loc} is neither an existing file nor an http(s) URL");
    }
    let base = release_asset_base_url(&opts.repo, &lock.wa_version, &lock.set_hash);
    for ext in [".tar.xz", ".tar.gz"] {
        if let Some(bytes) = download_opt(&format!("{base}{ext}"))? {
            return Ok(bytes);
        }
    }
    bail!(
        "no archive found for this version at {base}.tar.xz or {base}.tar.gz — the bundle \
         set isn't published yet; run scripts/publish-bundles.sh (or the update workflow).",
    )
}

fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// `…/releases/download/bundle-store/bundles-<ver>-<setHash>` — the asset URL **without**
/// its `.tar.xz`/`.tar.gz` extension (chosen by [`resolve_archive`]).
///
/// The name is **content-addressed** (it carries the input `setHash`, not just the
/// version): a different bundle set produces a different name, so an archive can never be
/// overwritten with different bytes, and every past commit's lock always resolves the
/// exact archive it pins. The version prefix keeps the name browsable.
fn release_asset_base_url(repo: &str, wa_version: &str, set_hash: &str) -> String {
    format!(
        "https://github.com/{repo}/releases/download/{STORE_TAG}/bundles-{wa_version}-{set_hash}"
    )
}

/// The host `url` addresses, lowercased, ignoring scheme/userinfo/port/path — enough
/// to decide whether a bearer token may be attached. `userinfo@` is stripped (host is
/// after the last `@`), so `https://github.com@evil.com/…` correctly resolves to
/// `evil.com`.
fn url_host(url: &str) -> String {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
}

/// Whether `url`'s host is GitHub itself. Host-only — see [`may_send_github_token`]
/// for the full token-eligibility decision (which also requires HTTPS).
fn is_github_host(url: &str) -> bool {
    let host = url_host(url);
    host == "github.com" || host.ends_with(".github.com")
}

/// Whether a bearer `GITHUB_TOKEN` may be attached to `url`: GitHub **over HTTPS**
/// only. It exists solely to lift GitHub's unauthenticated rate limit, and it is a
/// `contents: write` credential — attaching it to an arbitrary `--archive` host would
/// leak it, and sending it over plaintext `http://` (even to `github.com`) would put
/// it on the wire in the clear. Both are refused.
fn may_send_github_token(url: &str) -> bool {
    url.starts_with("https://") && is_github_host(url)
}

/// Download `url`, returning `Ok(None)` on a 404 so callers can try a fallback name.
/// Any other non-200 (or transport failure) is a hard error.
fn download_opt(url: &str) -> Result<Option<Vec<u8>>> {
    // A `GITHUB_TOKEN`, when present (CI), lifts the low unauthenticated rate limit;
    // the asset itself is public, so the token is a courtesy, not a requirement. Only
    // send it to GitHub over HTTPS — never to a caller-supplied `--archive` host, and
    // never over plaintext http.
    let bearer = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|t| !t.is_empty() && may_send_github_token(url))
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
        200 => Ok(Some(resp.body)),
        404 => Ok(None),
        other => bail!("download {url} failed: HTTP {other}"),
    }
}

/// Unpack a compressed tar (xz or gzip, chosen by magic bytes) into `(file_name, bytes)`
/// pairs (regular files only). The file name is the entry's basename — a flat bundle
/// directory, so unique.
///
/// Two caps bound a hostile, caller-supplied `--archive` (untrusted) *before*
/// verification even runs:
/// - `max_unpacked` bounds the *total* decompressed payload — xz/gzip can inflate a
///   tiny archive into an enormous one (a decompression bomb), so decompression stops
///   the moment the running total would exceed it.
/// - `max_files` bounds the *number* of extracted entries — an archive of millions of
///   zero-byte entries carries no payload (so `max_unpacked` never trips) yet would
///   still allocate a `Vec` slot each. The lock pins an exact bundle count, so anything
///   beyond it is already invalid; bail instead of allocating unboundedly.
fn unpack_archive(
    archive: &[u8],
    max_unpacked: u64,
    max_files: usize,
) -> Result<Vec<(String, Vec<u8>)>> {
    let tar_bytes = decompress(archive, max_unpacked)?;
    read_tar(&tar_bytes, max_files)
}

/// Decompress a whole archive into memory, capped at `max_unpacked` (bounds a
/// decompression bomb before the tar is even parsed). The compressor is picked by magic
/// bytes so a caller can't mislabel the payload via a filename/extension.
fn decompress(archive: &[u8], max_unpacked: u64) -> Result<Vec<u8>> {
    if archive.starts_with(XZ_MAGIC) {
        let mut out = CapWriter::new(max_unpacked);
        let res = lzma_rs::xz_decompress(&mut std::io::Cursor::new(archive), &mut out);
        bomb_guard(out.overflowed, max_unpacked)?;
        res.context("decompress xz archive")?;
        Ok(out.buf)
    } else if archive.starts_with(GZIP_MAGIC) {
        let mut buf = Vec::new();
        // +1 so a stream that fills exactly to the cap and keeps going is caught.
        let read = flate2::read::GzDecoder::new(archive)
            .take(max_unpacked + 1)
            .read_to_end(&mut buf)
            .context("gunzip archive")? as u64;
        bomb_guard(read > max_unpacked, max_unpacked)?;
        Ok(buf)
    } else {
        bail!("archive is neither xz nor gzip (unrecognized magic bytes)")
    }
}

fn bomb_guard(overflowed: bool, max_unpacked: u64) -> Result<()> {
    if overflowed {
        bail!(
            "archive unpacks to more than {max_unpacked} bytes — refusing (possible decompression bomb)"
        );
    }
    Ok(())
}

/// A `Write` sink that buffers into a `Vec` but hard-stops once `cap` bytes are
/// exceeded, flagging `overflowed` and erroring so an eager decompressor (lzma-rs
/// writes the whole stream) can't allocate past the cap.
struct CapWriter {
    buf: Vec<u8>,
    cap: u64,
    overflowed: bool,
}

impl CapWriter {
    fn new(cap: u64) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            overflowed: false,
        }
    }
}

impl Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() as u64 + data.len() as u64 > self.cap {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "unpacked size cap exceeded",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Read regular-file entries from an (already decompressed) tar into `(name, bytes)`.
/// `max_files` bounds the entry count — see [`unpack_archive`].
fn read_tar(tar_bytes: &[u8], max_files: usize) -> Result<Vec<(String, Vec<u8>)>> {
    let mut tar = tar::Archive::new(tar_bytes);
    let mut out = Vec::new();
    for entry in tar.entries().context("read tar archive")? {
        let mut entry = entry.context("read tar entry")?;
        // Regular files only (the doc contract): skip directories *and* every other
        // entry type — symlinks, hardlinks, devices, FIFOs, GNU/pax metadata. A
        // non-file entry carries no bundle bytes; reading it as an empty "bundle" would
        // only surface later as a confusing verification mismatch.
        if !entry.header().entry_type().is_file() {
            continue;
        }
        // Bail before allocating this entry's name/bytes if the archive already holds
        // more files than the lock can describe (a zero-byte-entry allocation bomb).
        if out.len() >= max_files {
            bail!(
                "archive has more than {max_files} file entries (the lock pins exactly {max_files}) — refusing"
            );
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
    // Reject duplicate basenames *before* touching the filesystem. Two entries can share
    // a name even past hash-multiset verification (a crafted `--archive`), and writing
    // as we go would leave a half-populated `out` — and needlessly sweep an existing one
    // — when we bail on the collision. Check first, mutate second.
    let mut seen: HashMap<&str, ()> = HashMap::new();
    for (name, _) in files {
        if seen.insert(name.as_str(), ()).is_some() {
            bail!("archive has two entries named {name} — cannot restore flatly");
        }
    }

    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    for entry in std::fs::read_dir(out).with_context(|| format!("read {}", out.display()))? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("js") {
            std::fs::remove_file(&p).with_context(|| format!("remove stale {}", p.display()))?;
        }
    }
    for (name, bytes) in files {
        std::fs::write(out.join(name), bytes)
            .with_context(|| format!("write {}", out.join(name).display()))?;
    }
    Ok(files.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{BundleId, BundleLock};

    fn raw_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw_tar(files)).unwrap();
        enc.finish().unwrap()
    }

    fn tar_xz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(raw_tar(files)), &mut out).unwrap();
        out
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

        let unpacked = unpack_archive(&archive, 1 << 20, files.len()).unwrap();
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
        let unpacked = unpack_archive(&tar_gz(tampered), 1 << 20, tampered.len()).unwrap();
        let err = verify_against_lock(&unpacked, &lock_for(locked)).unwrap_err();
        assert!(err.to_string().contains("does not match the lock"), "{err}");
    }

    #[test]
    fn verify_rejects_a_dropped_bundle() {
        let locked: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"beta")];
        let short: &[(&str, &[u8])] = &[("a.js", b"alpha")];
        let unpacked = unpack_archive(&tar_gz(short), 1 << 20, locked.len()).unwrap();
        let err = verify_against_lock(&unpacked, &lock_for(locked)).unwrap_err();
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn release_url_is_content_addressed() {
        // The base carries version + setHash; resolve_archive appends .tar.xz / .tar.gz.
        assert_eq!(
            release_asset_base_url("oxidezap/whatspec", "2.3000.42", "abc123"),
            "https://github.com/oxidezap/whatspec/releases/download/bundle-store/bundles-2.3000.42-abc123"
        );
    }

    #[test]
    fn unpack_reads_both_xz_and_gzip() {
        // The same bundle set round-trips through either envelope, chosen by magic bytes.
        let files: &[(&str, &[u8])] = &[("a.js", b"alpha"), ("b.js", b"beta")];
        let lock = lock_for(files);
        for archive in [tar_xz(files), tar_gz(files)] {
            let unpacked = unpack_archive(&archive, 1 << 20, files.len()).unwrap();
            verify_against_lock(&unpacked, &lock).unwrap();
        }
    }

    #[test]
    fn unpack_rejects_unknown_magic() {
        let err = unpack_archive(b"not a compressed archive at all", 1 << 20, 8).unwrap_err();
        assert!(err.to_string().contains("neither xz nor gzip"), "{err}");
    }

    #[test]
    fn xz_decompression_bomb_is_capped() {
        // xz compresses long runs extremely well; two 64 KiB entries under a 5 KiB cap
        // must be refused during decompression, before the tar is parsed.
        let big = vec![b'x'; 65536];
        let files: &[(&str, &[u8])] = &[("a.js", &big), ("b.js", &big)];
        let err = unpack_archive(&tar_xz(files), 5000, 8).unwrap_err();
        assert!(err.to_string().contains("decompression bomb"), "{err}");
        assert_eq!(unpack_archive(&tar_xz(files), 1 << 20, 8).unwrap().len(), 2);
    }

    #[test]
    fn github_token_host_gate() {
        // The token may only go to GitHub — not to a `--archive` host or plain http.
        assert!(is_github_host(
            "https://github.com/oxidezap/whatspec/releases/download/x"
        ));
        assert!(is_github_host("https://api.github.com/…"));
        assert!(!is_github_host("https://attacker.example.com/x.tar.gz"));
        assert!(!is_github_host("http://github.com.evil.com/x")); // suffix trick
        assert!(!is_github_host("https://github.com@evil.com/x")); // userinfo trick
        assert!(!is_github_host("https://objects.githubusercontent.com/x")); // CDN, no token
    }

    #[test]
    fn write_bundles_rejects_duplicate_basenames_without_partial_writes() {
        // Duplicate basenames can slip past hash-multiset verification (a crafted
        // archive). The collision must be caught before any filesystem mutation, so a
        // failed restore never leaves a half-populated (or freshly swept) output dir.
        let dir = std::env::temp_dir().join(format!("wsr-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let files = vec![
            ("dup.js".to_string(), b"first".to_vec()),
            ("dup.js".to_string(), b"second".to_vec()),
        ];
        let err = write_bundles(&files, &dir).unwrap_err();
        assert!(err.to_string().contains("two entries named"), "{err}");
        assert!(
            !dir.exists(),
            "bailed before touching the filesystem — no partial output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unpack_skips_non_regular_entries() {
        // Only regular files are bundles. A symlink (or any non-file) entry must be
        // ignored outright — never read as a zero-byte "bundle" that later trips
        // verification with a confusing message — honoring the "regular files only"
        // contract and giving a hostile archive no non-file foothold.
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let data = b"alpha";
        let mut file = tar::Header::new_gnu();
        file.set_size(data.len() as u64);
        file.set_mode(0o644);
        file.set_cksum();
        builder.append_data(&mut file, "a.js", &data[..]).unwrap();

        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_link_name("elsewhere").unwrap();
        link.set_path("evil.js").unwrap();
        link.set_cksum();
        builder.append(&link, std::io::empty()).unwrap();

        let archive = builder.into_inner().unwrap().finish().unwrap();
        let unpacked = unpack_archive(&archive, 1 << 20, 8).unwrap();
        assert_eq!(unpacked.len(), 1, "only the regular file survives");
        assert_eq!(unpacked[0].0, "a.js");
        assert_eq!(unpacked[0].1, b"alpha");
    }

    #[test]
    fn decompression_bomb_is_capped() {
        // Two 4 KiB entries unpack to 8 KiB; a 5 KiB cap must stop extraction.
        let big = vec![b'x'; 4096];
        let files: &[(&str, &[u8])] = &[("a.js", &big), ("b.js", &big)];
        let err = unpack_archive(&tar_gz(files), 5000, 8).unwrap_err();
        assert!(err.to_string().contains("decompression bomb"), "{err}");
        // The same archive unpacks fine under a sufficient cap.
        assert_eq!(unpack_archive(&tar_gz(files), 1 << 20, 8).unwrap().len(), 2);
    }

    #[test]
    fn unpack_caps_file_count() {
        // An archive with more entries than the lock pins is refused *before* it can
        // allocate a slot per entry — the zero-byte-entry allocation-bomb vector that
        // the byte cap alone (which counts payload only) can't see.
        let files: &[(&str, &[u8])] = &[("a.js", b"a"), ("b.js", b"b"), ("c.js", b"c")];
        let err = unpack_archive(&tar_gz(files), 1 << 20, 2).unwrap_err();
        assert!(err.to_string().contains("file entries"), "{err}");
        // Exactly the pinned count unpacks fine.
        assert_eq!(unpack_archive(&tar_gz(files), 1 << 20, 3).unwrap().len(), 3);
    }

    #[test]
    fn github_token_requires_https_github() {
        // The token may go only to GitHub over HTTPS.
        assert!(may_send_github_token(
            "https://github.com/oxidezap/whatspec/releases/download/x"
        ));
        assert!(may_send_github_token("https://api.github.com/x"));
        // Plaintext http to github is refused — a token must never cross the wire in
        // the clear (the reported leak vector).
        assert!(!may_send_github_token("http://github.com/oxidezap/x"));
        // And of course non-GitHub hosts, suffix/userinfo tricks, and the CDN.
        assert!(!may_send_github_token("https://attacker.example.com/x"));
        assert!(!may_send_github_token("http://github.com.evil.com/x"));
        assert!(!may_send_github_token("https://github.com@evil.com/x"));
        assert!(!may_send_github_token(
            "https://objects.githubusercontent.com/x"
        ));
    }
}
