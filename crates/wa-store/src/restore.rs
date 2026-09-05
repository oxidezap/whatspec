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
//! files can be written either as a flat directory for `whatspec update --bundles` or
//! directly into the version-keyed cache consumed by `whatspec update --cache`.
//!
//! The **wasm** set (`--wasm`) rides the same machinery against its own lock
//! ([`WasmLock`](crate::lock::WasmLock)) and its own asset name
//! (`wasm-<wasmSetHash>.tar.xz`, content-addressed with no version). Keeping the two
//! assets separate is deliberate:
//! the JS asset name is content-addressed on the *input* `setHash` the reproducibility
//! gate depends on, so adding payloads to it would mutate an already-published archive.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use wa_fetch::{Bundle, BundleCache, HttpClient, UreqClient, bundle_file_name};

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
/// growth). It bounds the decompressed **output**, stopping a classic decompression bomb
/// (a tiny archive that inflates enormously) before the tar is even parsed.
///
/// Decompression is buffer-then-parse — xz's decoder isn't a streaming `Read`, so both
/// envelopes share one path that holds the whole tar in memory and then copies each entry
/// out, making peak *output* memory ~2× the decompressed size, which this cap bounds.
///
/// Caveat: this caps output only. lzma-rs's xz API exposes no `memlimit`, so the decoder
/// still allocates its LZMA2 dictionary (size read from the archive header) up front,
/// unbounded by this cap. That residual is accepted for the untrusted `--archive` path —
/// a deliberate, local action — since the release path restore normally uses is our own
/// published, content-addressed archive.
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreTarget {
    /// A flat directory of `.js` files, ready for `update --bundles`.
    Bundles(PathBuf),
    /// The version-keyed on-disk layout consumed by `update --cache`.
    Cache(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOptions {
    pub lock_path: PathBuf,
    pub target: RestoreTarget,
    /// Restore the **wasm** payload set from a `wasm.lock.json` instead of the JS bundle
    /// set from a `bundles.lock.json`.
    pub wasm: bool,
    /// Explicit archive location — a local file path or an `http(s)://` URL. When
    /// absent, the release URL is derived from the lock's version + `repo`.
    pub archive: Option<String>,
    pub repo: String,
}

impl RestoreOptions {
    pub fn new(lock_path: PathBuf, target: RestoreTarget) -> Self {
        Self {
            lock_path,
            target,
            wasm: false,
            archive: None,
            repo: DEFAULT_REPO.to_string(),
        }
    }
}

/// A cache is keyed by the original bundle URLs, so reject locks that cannot produce a
/// valid cache before paying for the release download and decompression. `write_cache`
/// repeats this cheap preflight because it is also exercised directly in tests and must
/// never clear an existing cache for an unusable lock.
fn preflight_cache_lock_urls(lock: &BundleLock) -> Result<()> {
    let mut seen_urls = HashSet::new();
    for entry in &lock.bundles {
        let url = entry
            .url
            .as_deref()
            .filter(|url| !url.is_empty())
            .context("cannot restore into a cache: every lock entry needs its origin URL")?;
        if !seen_urls.insert(url) {
            bail!("cannot restore into a cache: duplicate bundle URL {url}");
        }
    }
    Ok(())
}

pub fn restore(opts: &RestoreOptions) -> Result<()> {
    if opts.wasm {
        return restore_wasm(opts);
    }
    let lock = read_lock(&opts.lock_path)?;
    if matches!(&opts.target, RestoreTarget::Cache(_)) {
        preflight_cache_lock_urls(&lock)?;
    }
    eprintln!(
        "restoring {} bundle(s) for {} (setHash {})",
        lock.bundle_count,
        lock.wa_version,
        &lock.set_hash[..12.min(lock.set_hash.len())]
    );

    let archive = resolve_archive(opts, &js_asset_stem(&lock.wa_version, &lock.set_hash))?;
    let files = unpack_archive(&archive, MAX_UNPACKED_BYTES, lock.bundle_count)?;
    let verified_hashes = verify_against_lock(&files, &lock)?;
    match &opts.target {
        RestoreTarget::Bundles(out) => {
            let written = write_bundles(&files, out, "js")?;
            eprintln!(
                "restored {} bundle(s) to {} — verified against the lock",
                written,
                out.display()
            );
        }
        RestoreTarget::Cache(cache_dir) => {
            let written = write_cache(files, verified_hashes, &lock, cache_dir)?;
            eprintln!(
                "restored {} bundle(s) to cache {} — verified against the lock",
                written,
                cache_dir.display()
            );
        }
    }
    Ok(())
}

/// Restore the wasm payload set pinned by a `wasm.lock.json`.
///
/// Same contract as the JS path — pull the content-addressed asset, verify every payload's
/// SHA-256 against the lock, then materialize — with two differences that follow from wasm
/// being *auxiliary* rather than an input:
///
/// - the asset is `wasm-<wasmSetHash>.tar.xz` (never the `bundles-…` one);
/// - restoring into a cache **attaches** to that version's existing JS cache instead of
///   replacing it, because the JS set is what `update --cache` actually needs.
fn restore_wasm(opts: &RestoreOptions) -> Result<()> {
    let lock = read_wasm_lock(&opts.lock_path)?;
    eprintln!(
        "restoring {} wasm payload(s) for {} (wasmSetHash {})",
        lock.wasm_count,
        lock.wa_version,
        &lock.wasm_set_hash[..12.min(lock.wasm_set_hash.len())]
    );

    let archive = resolve_archive(opts, &wasm_asset_stem(&lock.wasm_set_hash))?;
    let files = unpack_archive(&archive, MAX_UNPACKED_BYTES, lock.wasm_count)?;
    let hashes = verify_multiset(
        &files,
        lock.wasm.iter().map(|e| e.sha256.as_str()),
        lock.wasm_count,
        "wasm payload",
    )?;

    match &opts.target {
        RestoreTarget::Bundles(out) => {
            // Deliberately NOT the archive's own names: hash-multiset verification proves
            // the *bytes* are the locked ones, not that each arrived under the right name.
            // Wasm consumers select a module by filename, so a crafted archive that swaps
            // two locked names would pass verification and then serve one payload in place
            // of another. Naming from the lock makes the association part of what is
            // verified. (The JS path is immune: `update --bundles` reads every `.js`
            // regardless of name.)
            let named = name_from_lock(files, &hashes, &lock)?;
            let written = write_bundles(&named, out, "wasm")?;
            eprintln!(
                "restored {} wasm payload(s) to {} — verified against the lock",
                written,
                out.display()
            );
        }
        RestoreTarget::Cache(cache_dir) => {
            let payloads = payloads_for_cache(files, hashes, &lock)?;
            let written = payloads.len();
            // The lock carries each payload's `bx` handle, so a restored cache is
            // indistinguishable from a live-resolved one (a later cache hit keeps the
            // join key back to the `wasm` IR domain).
            let handles: std::collections::BTreeMap<String, String> = lock
                .wasm
                .iter()
                .filter_map(|e| e.bx_id.clone().map(|id| (e.url.clone(), id)))
                .collect();
            BundleCache::new(cache_dir.to_path_buf())
                .store_wasm(&lock.wa_version, &payloads, &handles)
                .with_context(|| format!("attach wasm to the cache at {}", cache_dir.display()))?;
            eprintln!(
                "restored {} wasm payload(s) into cache {} — verified against the lock",
                written,
                cache_dir.display()
            );
        }
    }
    Ok(())
}

/// Re-label verified archive entries with the file name the lock records for their content
/// hash, so what lands on disk is the locked *(name, bytes)* pairing rather than whatever
/// the archive claimed. Duplicate hashes (one payload served from two URLs) are matched
/// one-for-one, so both locked names are produced.
fn name_from_lock(
    files: Vec<(String, Vec<u8>)>,
    hashes: &[String],
    lock: &crate::lock::WasmLock,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut names_by_hash: HashMap<&str, Vec<&str>> = HashMap::new();
    for entry in &lock.wasm {
        // The name is about to be joined onto the output directory, and `fileName` is not
        // covered by the lock's self-consistency check — a hand-edited or hostile lock
        // could name `../../x` and make a "verified" restore write outside the directory
        // the caller asked for. (The JS path is immune: it uses the archive entry's
        // basename.) Require a plain payload basename.
        safe_payload_name(&entry.file_name)?;
        names_by_hash
            .entry(entry.sha256.as_str())
            .or_default()
            .push(entry.file_name.as_str());
    }
    let mut out = Vec::with_capacity(files.len());
    for ((archive_name, bytes), sha256) in files.into_iter().zip(hashes) {
        let name = names_by_hash
            .get_mut(sha256.as_str())
            .and_then(Vec::pop)
            .with_context(|| {
                format!("archive entry {archive_name} ({sha256}) has no name in the lock")
            })?;
        out.push((name.to_string(), bytes));
    }
    Ok(out)
}

/// Re-pair verified archive bytes with the lock's URLs (the cache keys on URL, not on
/// archive file name) and assert the recorded sizes. Every check runs before the cache is
/// touched, so an inconsistent lock leaves the existing cache alone.
fn payloads_for_cache(
    files: Vec<(String, Vec<u8>)>,
    verified_hashes: Vec<String>,
    lock: &crate::lock::WasmLock,
) -> Result<Vec<Bundle>> {
    let mut seen_urls = HashSet::new();
    for e in &lock.wasm {
        if e.url.is_empty() {
            bail!(
                "cannot restore wasm into a cache: lock entry {} has no URL",
                e.sha256
            );
        }
        if !seen_urls.insert(e.url.as_str()) {
            bail!("cannot restore wasm into a cache: duplicate URL {}", e.url);
        }
    }
    if files.len() != verified_hashes.len() {
        bail!(
            "internal verified-hash count mismatch: {} files, {} hashes",
            files.len(),
            verified_hashes.len()
        );
    }

    let mut by_hash: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for ((_, bytes), sha256) in files.into_iter().zip(verified_hashes) {
        by_hash.entry(sha256).or_default().push(bytes);
    }
    let mut payloads = Vec::with_capacity(lock.wasm_count);
    for entry in &lock.wasm {
        let bytes = by_hash
            .get_mut(&entry.sha256)
            .and_then(Vec::pop)
            .with_context(|| format!("verified archive lost wasm payload {}", entry.sha256))?;
        if bytes.len() as u64 != entry.size {
            bail!(
                "locked size mismatch for {}: lock says {}, archive has {}",
                entry.sha256,
                entry.size,
                bytes.len()
            );
        }
        payloads.push(Bundle {
            url: entry.url.clone(),
            file_name: bundle_file_name(&entry.url),
            bytes,
        });
    }
    payloads.sort_by(|a, b| a.url.cmp(&b.url));
    Ok(payloads)
}

/// Accept only a single, unambiguous `*.wasm` file name: no separators, no traversal, no
/// drive/root prefix, nothing that could escape the output directory when joined to it.
fn safe_payload_name(name: &str) -> Result<()> {
    let rejected = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || Path::new(name)
            .file_name()
            .map(|n| n != name)
            .unwrap_or(true)
        || !name.ends_with(".wasm");
    if rejected {
        bail!(
            "lock entry names a payload {name:?} that is not a plain `*.wasm` file name — \
             refusing to write it"
        );
    }
    Ok(())
}

fn read_wasm_lock(path: &Path) -> Result<crate::lock::WasmLock> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read wasm lockfile {}", path.display()))?;
    let lock: crate::lock::WasmLock = serde_json::from_str(&raw)
        .with_context(|| format!("parse wasm lockfile {}", path.display()))?;
    lock.verify_self_consistent().map_err(|why| {
        anyhow::anyhow!("wasm lockfile {} is inconsistent: {why}", path.display())
    })?;
    Ok(lock)
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
fn resolve_archive(opts: &RestoreOptions, asset_stem: &str) -> Result<Vec<u8>> {
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
    let base = release_asset_base_url(&opts.repo, asset_stem);
    let exts = [".tar.xz", ".tar.gz"];
    for (i, ext) in exts.iter().enumerate() {
        if let Some(bytes) = download_opt(&format!("{base}{ext}"))? {
            return Ok(bytes);
        }
        if let Some(next) = exts.get(i + 1) {
            eprintln!("  not found ({ext}); trying legacy {next}");
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

/// The JS bundle set's asset name: `bundles-<ver>-<setHash>`. Content-addressed on the
/// input `setHash`, with the version kept as a browsable prefix — every WhatsApp version
/// has a different JS set anyway, so nothing would dedupe by dropping it.
fn js_asset_stem(wa_version: &str, set_hash: &str) -> String {
    format!("bundles-{wa_version}-{set_hash}")
}

/// The wasm set's asset name: `wasm-<wasmSetHash>` — **no version**.
///
/// Wasm payloads change far less often than the JS bundles (the same ~41 MB set survives
/// many rollouts), and the update workflow runs per version. A version-prefixed name would
/// re-upload the identical archive on every run; a purely content-addressed one is uploaded
/// once and every later version's lock resolves to it. The lock still records the version
/// the set was observed at.
fn wasm_asset_stem(wasm_set_hash: &str) -> String {
    format!("wasm-{wasm_set_hash}")
}

/// `…/releases/download/bundle-store/<asset_stem>` — the asset URL **without**
/// its `.tar.xz`/`.tar.gz` extension (chosen by [`resolve_archive`]).
///
/// The name is **content-addressed** (it carries the input `setHash`, not just the
/// version): a different bundle set produces a different name, so an archive can never be
/// overwritten with different bytes, and every past commit's lock always resolves the
/// exact archive it pins. The version prefix keeps the name browsable.
fn release_asset_base_url(repo: &str, asset_stem: &str) -> String {
    format!("https://github.com/{repo}/releases/download/{STORE_TAG}/{asset_stem}")
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
pub(crate) fn decompress(archive: &[u8], max_unpacked: u64) -> Result<Vec<u8>> {
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
            // A hard stop, not a "wrote zero / try again" condition — use `Other`.
            return Err(std::io::Error::other("unpacked size cap exceeded"));
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
/// is actionable rather than a bare count. Returns the verified hashes in file order so
/// the cache writer can index the bytes without hashing the full bundle set a second time.
fn verify_against_lock(files: &[(String, Vec<u8>)], lock: &BundleLock) -> Result<Vec<String>> {
    verify_multiset(
        files,
        lock.bundles.iter().map(|e| e.sha256.as_str()),
        lock.bundle_count,
        "bundle",
    )
}

/// The multiset comparison behind [`verify_against_lock`], shared with the wasm path.
/// `label` names the unit in the failure message ("bundle" / "wasm payload").
fn verify_multiset<'a>(
    files: &[(String, Vec<u8>)],
    locked: impl Iterator<Item = &'a str>,
    locked_count: usize,
    label: &str,
) -> Result<Vec<String>> {
    let mut want: HashMap<&str, i64> = HashMap::new();
    for sha in locked {
        *want.entry(sha).or_default() += 1;
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
        drop(have);
        return Ok(got);
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
        "restored {label} set does not match the lock: {} in archive vs {} locked; \
         {} missing, {} unexpected (e.g. missing {:?}, extra {:?})",
        files.len(),
        locked_count,
        missing.len(),
        extra.len(),
        missing.iter().take(3).collect::<Vec<_>>(),
        extra.iter().take(3).collect::<Vec<_>>(),
    );
}

/// Write the verified files into `out` (created if needed), first clearing any stale
/// file of the same extension so the directory holds *exactly* the restored set (a
/// leftover bundle would otherwise be concatenated by `update --bundles`; a leftover
/// payload would masquerade as part of a locked wasm set).
fn write_bundles(files: &[(String, Vec<u8>)], out: &Path, ext: &str) -> Result<usize> {
    // Reject duplicate basenames *before* touching the filesystem. Two entries can share
    // a name even past hash-multiset verification (a crafted `--archive`), and writing
    // as we go would leave a half-populated `out` — and needlessly sweep an existing one
    // — when we bail on the collision. Check first, mutate second.
    let mut seen = HashSet::new();
    for (name, _) in files {
        if !seen.insert(name.as_str()) {
            bail!("archive has two entries named {name} — cannot restore flatly");
        }
    }

    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    for entry in std::fs::read_dir(out).with_context(|| format!("read {}", out.display()))? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) == Some(ext) {
            std::fs::remove_file(&p).with_context(|| format!("remove stale {}", p.display()))?;
        }
    }
    for (name, bytes) in files {
        std::fs::write(out.join(name), bytes)
            .with_context(|| format!("write {}", out.join(name).display()))?;
    }
    Ok(files.len())
}

/// Convert the verified archive entries back into downloaded [`Bundle`] values and
/// delegate persistence to [`BundleCache`]. The lock supplies the original URLs that
/// the cache uses as stable keys; archive filenames are deliberately irrelevant.
///
/// All fallible conversion checks happen before `BundleCache::store` is called, so an
/// unusable lock (missing/duplicate URLs or inconsistent sizes) leaves an existing cache
/// untouched. `store` remains the single owner of the cache layout, integrity manifest,
/// stale-version cleanup, and manifest-last commit semantics.
fn write_cache(
    files: Vec<(String, Vec<u8>)>,
    verified_hashes: Vec<String>,
    lock: &BundleLock,
    cache_dir: &Path,
) -> Result<usize> {
    preflight_cache_lock_urls(lock)?;
    if files.len() != verified_hashes.len() {
        bail!(
            "internal verified-hash count mismatch: {} files, {} hashes",
            files.len(),
            verified_hashes.len()
        );
    }

    // Consume the archive bytes rather than cloning the whole (~70 MiB) bundle set.
    // A vector per hash preserves multiset semantics when identical bytes were served
    // from more than one URL.
    let mut files_by_hash: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for ((_, bytes), sha256) in files.into_iter().zip(verified_hashes) {
        files_by_hash.entry(sha256).or_default().push(bytes);
    }

    let mut bundles = Vec::with_capacity(lock.bundle_count);
    for entry in &lock.bundles {
        // Presence and uniqueness were checked above, before any cache mutation.
        let url = entry.url.as_deref().expect("URL preflight checked");
        let bytes = files_by_hash
            .get_mut(&entry.sha256)
            .and_then(Vec::pop)
            .with_context(|| format!("verified archive lost bundle {}", entry.sha256))?;
        if bytes.len() as u64 != entry.size {
            bail!(
                "locked size mismatch for {}: lock says {}, archive has {}",
                entry.sha256,
                entry.size,
                bytes.len()
            );
        }
        bundles.push(Bundle {
            url: url.to_string(),
            file_name: bundle_file_name(url),
            bytes,
        });
    }

    // Live downloads are URL-sorted before entering the cache. Preserve that canonical
    // ordering so a release-seeded hit behaves exactly like a live-seeded hit.
    bundles.sort_by(|a, b| a.url.cmp(&b.url));
    let written = bundles.len();
    BundleCache::new(cache_dir.to_path_buf())
        .store(&lock.wa_version, &bundles)
        .with_context(|| format!("write bundle cache at {}", cache_dir.display()))?;
    Ok(written)
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
        let _verified_hashes = verify_against_lock(&unpacked, &lock).unwrap();

        let dir = std::env::temp_dir().join(format!("wsr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A stale bundle must be swept so the restored dir is exactly the locked set.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale.js"), b"old").unwrap();
        let n = write_bundles(&unpacked, &dir, "js").unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dir.join("a.js")).unwrap(), b"alpha");
        assert!(!dir.join("stale.js").exists(), "stale .js swept");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_cache_roundtrip_uses_the_shared_bundle_cache_layout() {
        // Archive labels are transport-only and intentionally do not match the URL
        // basenames. Cache identity and readable names must come from the lock URLs.
        let archived: &[(&str, &[u8])] = &[("opaque-one.js", b"alpha"), ("opaque-two.js", b"beta")];
        let lock = BundleLock::new(
            "2.3000.CACHE",
            vec![
                BundleId {
                    sha256: wa_text::sha256_hex(b"alpha"),
                    size: 5,
                    url: Some("https://static.example.test/z-logical.js".to_string()),
                },
                BundleId {
                    sha256: wa_text::sha256_hex(b"beta"),
                    size: 4,
                    url: Some("https://static.example.test/a-logical.js".to_string()),
                },
            ],
        );
        let unpacked = unpack_archive(&tar_gz(archived), 1 << 20, archived.len()).unwrap();
        let verified_hashes = verify_against_lock(&unpacked, &lock).unwrap();

        let dir = std::env::temp_dir().join(format!("wsr-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let written = write_cache(unpacked, verified_hashes, &lock, &dir).unwrap();
        assert_eq!(written, 2);

        let cache = BundleCache::new(dir.clone());
        let manifest = cache.read_manifest().expect("cache manifest");
        assert_eq!(manifest.wa_version, "2.3000.CACHE");
        assert!(manifest.complete);
        assert_eq!(
            manifest
                .bundles
                .iter()
                .map(|entry| entry.file_name.as_str())
                .collect::<Vec<_>>(),
            vec!["a-logical.js", "z-logical.js"],
            "release-seeded cache keeps the live fetcher's URL ordering"
        );
        match cache.check("2.3000.CACHE") {
            wa_fetch::CacheStatus::Hit(bundles) => {
                assert_eq!(bundles.len(), 2);
                assert_eq!(bundles[0].bytes, b"beta");
                assert_eq!(bundles[1].bytes, b"alpha");
            }
            wa_fetch::CacheStatus::Miss(why) => panic!("expected cache hit, got miss: {why}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cache_restore_rejects_missing_urls_before_replacing_an_existing_cache() {
        let dir = std::env::temp_dir().join(format!("wsr-cache-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = BundleCache::new(dir.clone());
        cache
            .store(
                "old-version",
                &[Bundle {
                    url: "https://old.example.test/old.js".to_string(),
                    file_name: "old.js".to_string(),
                    bytes: b"old".to_vec(),
                }],
            )
            .unwrap();

        let files = vec![("new.js".to_string(), b"new".to_vec())];
        let lock = lock_for(&[("new.js", b"new")]);
        let verified_hashes = verify_against_lock(&files, &lock).unwrap();
        let err = write_cache(files, verified_hashes, &lock, &dir).unwrap_err();
        assert!(err.to_string().contains("origin URL"), "{err}");
        assert!(
            matches!(cache.check("old-version"), wa_fetch::CacheStatus::Hit(_)),
            "preflight failure must leave the prior cache intact"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cache_restore_rejects_missing_urls_before_reading_the_archive() {
        let dir = std::env::temp_dir().join(format!("wsr-cache-preflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let lock = lock_for(&[("new.js", b"new")]);
        let lock_path = dir.join("bundles.lock.json");
        std::fs::write(&lock_path, lock.to_pretty_json()).unwrap();
        let mut opts = RestoreOptions::new(lock_path, RestoreTarget::Cache(dir.join("cache")));
        opts.archive = Some(dir.join("missing.tar.xz").display().to_string());

        let err = restore(&opts).unwrap_err();
        assert!(err.to_string().contains("origin URL"), "{err}");
        assert!(
            !dir.join("cache").exists(),
            "URL preflight must fail before archive I/O or cache mutation"
        );
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
            release_asset_base_url("oxidezap/whatspec", &js_asset_stem("2.3000.42", "abc123")),
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
            let _verified_hashes = verify_against_lock(&unpacked, &lock).unwrap();
        }
    }

    #[test]
    fn unpack_reads_a_real_xz9_archive() {
        // Fixture produced by the actual `xz -9` CLI (the publisher's compressor), not
        // lzma-rs's own encoder — proof that lzma-rs decodes real xz output for our
        // single-stream tarballs, guarding the dependency choice against regressions.
        const FIXTURE: &[u8] = include_bytes!("testdata/sample.tar.xz");
        let mut got = unpack_archive(FIXTURE, 1 << 20, 8).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("a.js".to_string(), b"alpha".to_vec()),
                ("b.js".to_string(), b"beta".to_vec()),
            ]
        );
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
        let err = write_bundles(&files, &dir, "js").unwrap_err();
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

    // ── wasm restore ────────────────────────────────────────────────────────────────

    fn wasm_lock_for(entries: &[(&str, &str, &[u8])]) -> crate::lock::WasmLock {
        crate::lock::WasmLock::with_bootloader(
            "2.3000.TEST",
            entries
                .iter()
                .map(|(name, url, bytes)| crate::lock::WasmLockEntry {
                    bx_id: None,
                    file_name: (*name).to_string(),
                    url: (*url).to_string(),
                    sha256: wa_text::sha256_hex(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            None,
        )
    }

    #[test]
    fn wasm_asset_name_is_content_addressed_without_a_version() {
        // An unchanged payload set must resolve to the SAME asset across WA versions,
        // otherwise every update run re-uploads the identical megabytes.
        assert_eq!(wasm_asset_stem("deadbeef"), "wasm-deadbeef");
        assert_eq!(
            release_asset_base_url("oxidezap/whatspec", &wasm_asset_stem("deadbeef")),
            "https://github.com/oxidezap/whatspec/releases/download/bundle-store/wasm-deadbeef"
        );
        // And it is never the JS asset, whose name the reproducibility gate depends on.
        assert_ne!(
            wasm_asset_stem("deadbeef"),
            js_asset_stem("2.3000.1", "deadbeef")
        );
    }

    #[test]
    fn wasm_roundtrip_writes_a_flat_dir_and_sweeps_stale_payloads() {
        let payloads: &[(&str, &[u8])] = &[
            ("e.wasm", b"\0asm\x01\0\0\0one"),
            ("f.wasm", b"\0asm\x01\0\0\0two"),
        ];
        let archive = tar_xz(payloads);
        let lock = wasm_lock_for(&[
            (
                "e.wasm",
                "https://static.whatsapp.net/e.wasm",
                payloads[0].1,
            ),
            (
                "f.wasm",
                "https://static.whatsapp.net/f.wasm",
                payloads[1].1,
            ),
        ]);

        let unpacked = unpack_archive(&archive, 1 << 20, lock.wasm_count).unwrap();
        verify_multiset(
            &unpacked,
            lock.wasm.iter().map(|e| e.sha256.as_str()),
            lock.wasm_count,
            "wasm payload",
        )
        .unwrap();

        let dir = std::env::temp_dir().join(format!("wsr-wasm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale.wasm"), b"old").unwrap();
        // A `.js` in the same dir is none of this path's business and must survive.
        std::fs::write(dir.join("keep.js"), b"js").unwrap();
        let n = write_bundles(&unpacked, &dir, "wasm").unwrap();
        assert_eq!(n, 2);
        assert!(!dir.join("stale.wasm").exists(), "stale payload swept");
        assert!(
            dir.join("keep.js").exists(),
            "unrelated extension untouched"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wasm_verification_rejects_a_swapped_payload() {
        let lock = wasm_lock_for(&[("e.wasm", "https://s/e.wasm", b"real")]);
        let tampered = unpack_archive(&tar_xz(&[("e.wasm", b"fake")]), 1 << 20, 1).unwrap();
        let err = verify_multiset(
            &tampered,
            lock.wasm.iter().map(|e| e.sha256.as_str()),
            lock.wasm_count,
            "wasm payload",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("wasm payload set does not match the lock"),
            "{err}"
        );
    }

    #[test]
    fn wasm_cache_payloads_come_from_the_lock_urls_not_archive_names() {
        // Archive labels are transport-only; the cache keys on the locked URL.
        let bytes: &[u8] = b"payload";
        let lock = wasm_lock_for(&[(
            "opaque.wasm",
            "https://static.whatsapp.net/v/real.wasm",
            bytes,
        )]);
        let files = vec![("opaque.wasm".to_string(), bytes.to_vec())];
        let payloads = payloads_for_cache(files, vec![wa_text::sha256_hex(bytes)], &lock).unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].url, "https://static.whatsapp.net/v/real.wasm");
        assert_eq!(payloads[0].file_name, "real.wasm");
    }

    #[test]
    fn wasm_cache_refuses_a_size_mismatch_before_touching_the_cache() {
        let bytes: &[u8] = b"payload";
        let mut lock = wasm_lock_for(&[("e.wasm", "https://s/e.wasm", bytes)]);
        lock.wasm[0].size = 999;
        let files = vec![("e.wasm".to_string(), bytes.to_vec())];
        let err = payloads_for_cache(files, vec![wa_text::sha256_hex(bytes)], &lock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("locked size mismatch"), "{err}");
    }

    #[test]
    fn wasm_lock_reader_rejects_an_inconsistent_file() {
        let dir = std::env::temp_dir().join(format!("wsr-wlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wasm.lock.json");
        let mut lock = wasm_lock_for(&[("e.wasm", "https://s/e.wasm", b"x")]);
        lock.wasm_set_hash = "0".repeat(64);
        std::fs::write(&path, lock.to_pretty_json()).unwrap();
        let err = read_wasm_lock(&path).unwrap_err().to_string();
        assert!(err.contains("inconsistent"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_name_swapped_wasm_archive_is_relabelled_from_the_lock() {
        // The attack multiset verification alone cannot see: both locked payloads are
        // present, but the archive labels each with the other's name. Consumers select a
        // module by filename, so accepting the archive's labels would hand a runner the
        // wrong binary while reporting "verified against the lock".
        let voip: &[u8] = b"\0asm\x01\0\0\0voip-engine";
        let mp4: &[u8] = b"\0asm\x01\0\0\0mp4-utils";
        let lock = wasm_lock_for(&[
            ("voip.wasm", "https://static.whatsapp.net/voip.wasm", voip),
            ("mp4.wasm", "https://static.whatsapp.net/mp4.wasm", mp4),
        ]);
        // Swapped labels, correct bytes → passes the multiset check.
        let swapped = vec![
            ("mp4.wasm".to_string(), voip.to_vec()),
            ("voip.wasm".to_string(), mp4.to_vec()),
        ];
        let hashes = verify_multiset(
            &swapped,
            lock.wasm.iter().map(|e| e.sha256.as_str()),
            lock.wasm_count,
            "wasm payload",
        )
        .expect("bytes are the locked ones");

        let named = name_from_lock(swapped, &hashes, &lock).unwrap();
        let by_name: HashMap<&str, &[u8]> = named
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        assert_eq!(
            by_name["voip.wasm"], voip,
            "name follows the locked content"
        );
        assert_eq!(by_name["mp4.wasm"], mp4);
    }

    #[test]
    fn duplicate_content_keeps_both_locked_names() {
        // Two URLs serving identical bytes (WA does this for the VoIP engine): both locked
        // names must be produced, not one name twice.
        let same: &[u8] = b"identical";
        let lock = wasm_lock_for(&[
            ("a.wasm", "https://static.whatsapp.net/a.wasm", same),
            ("b.wasm", "https://static.whatsapp.net/b.wasm", same),
        ]);
        let files = vec![
            ("x.wasm".to_string(), same.to_vec()),
            ("y.wasm".to_string(), same.to_vec()),
        ];
        let hashes = vec![wa_text::sha256_hex(same), wa_text::sha256_hex(same)];
        let mut names: Vec<String> = name_from_lock(files, &hashes, &lock)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        names.sort();
        assert_eq!(names, ["a.wasm", "b.wasm"]);
    }

    #[test]
    fn an_entry_absent_from_the_lock_is_named_by_nothing() {
        let lock = wasm_lock_for(&[("a.wasm", "https://static.whatsapp.net/a.wasm", b"a")]);
        let files = vec![("x.wasm".to_string(), b"other".to_vec())];
        let err = name_from_lock(files, &[wa_text::sha256_hex(b"other")], &lock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no name in the lock"), "{err}");
    }

    #[test]
    fn lock_supplied_names_cannot_escape_the_output_directory() {
        // `fileName` is not covered by the lock's setHash, so a hand-edited lock could
        // otherwise make a "verified" restore write anywhere.
        for hostile in [
            "../../target/pwned.wasm",
            "/etc/pwned.wasm",
            "sub/dir.wasm",
            "back\\slash.wasm",
            "..",
            "",
            "plain.txt",
        ] {
            assert!(
                safe_payload_name(hostile).is_err(),
                "should reject {hostile:?}"
            );
        }
        assert!(safe_payload_name("COs9e0Kj0ic.wasm").is_ok());
        assert!(
            safe_payload_name("-5fSEd7-h_f.wasm").is_ok(),
            "a leading dash is a real WA name, not a flag"
        );
    }

    #[test]
    fn a_traversing_lock_is_rejected_before_anything_is_written() {
        let bytes: &[u8] = b"payload";
        let mut lock = wasm_lock_for(&[("ok.wasm", "https://static.whatsapp.net/ok.wasm", bytes)]);
        lock.wasm[0].file_name = "../escape.wasm".to_string();
        let files = vec![("archive.wasm".to_string(), bytes.to_vec())];
        let err = name_from_lock(files, &[wa_text::sha256_hex(bytes)], &lock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a plain `*.wasm` file name"), "{err}");
    }
}
