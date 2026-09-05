//! Verified restoration of selected historical wasm payloads.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use wa_fetch::{HttpClient, UreqClient, is_cdn_payload};

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 4096;
const MAX_WASM_BYTES: u64 = 64 * 1024 * 1024;

/// One immutable wasm payload required by a downstream tool.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WasmCapture {
    /// Basename used by the wasm consumer.
    pub file_name: String,
    /// Expected lowercase SHA-256.
    pub sha256: String,
    /// Expected byte length, when the source records it.
    #[serde(default)]
    pub size: Option<u64>,
    /// Original WhatsApp CDN URL, when retained.
    #[serde(default)]
    pub url: Option<String>,
}

/// A GitHub release whose wasm archives may contain historical payloads.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ReleaseSource {
    /// GitHub `owner/repository`.
    pub repo: String,
    /// Release tag.
    pub release: String,
}

#[derive(Debug, Deserialize)]
struct Release {
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    url: String,
    browser_download_url: String,
    created_at: String,
}

impl WasmCapture {
    fn validate(&self) -> Result<()> {
        ensure!(
            Path::new(&self.file_name)
                .file_name()
                .and_then(|v| v.to_str())
                == Some(self.file_name.as_str())
                && self.file_name.ends_with(".wasm"),
            "capture fileName must be a .wasm basename"
        );
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "capture {} has an invalid SHA-256",
            self.file_name
        );
        ensure!(
            self.size.is_none_or(|size| size <= MAX_WASM_BYTES),
            "capture {} exceeds the {} byte limit",
            self.file_name,
            MAX_WASM_BYTES
        );
        if let Some(url) = &self.url {
            ensure!(
                is_cdn_payload(url),
                "capture {} has a non-WhatsApp CDN URL",
                self.file_name
            );
        }
        Ok(())
    }

    fn matches(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"\0asm")
            && self.size.is_none_or(|size| size == bytes.len() as u64)
            && wa_text::sha256_hex(bytes) == self.sha256
    }
}

fn token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

fn github_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("User-Agent".to_owned(), "wa-store".to_owned()),
        (
            "Accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        ),
    ];
    if let Some(token) = token {
        headers.push(("Authorization".to_owned(), format!("Bearer {token}")));
    }
    headers
}

fn get(url: &str, headers: &[(String, String)], max: u64) -> Result<Vec<u8>> {
    let borrowed = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let response = UreqClient::new()
        .get(url, &borrowed, max)
        .with_context(|| format!("GET {url}"))?;
    ensure!(
        response.status == 200,
        "GET {url}: HTTP {}",
        response.status
    );
    Ok(response.body)
}

fn release(repo: &str, tag: &str, token: Option<&str>) -> Result<Release> {
    ensure!(
        repo.split_once('/').is_some_and(|(owner, name)| {
            !owner.is_empty()
                && !name.is_empty()
                && owner
                    .bytes()
                    .chain(name.bytes())
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }),
        "invalid GitHub repository {repo:?}"
    );
    ensure!(
        !tag.is_empty()
            && tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid GitHub release tag {tag:?}"
    );
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    serde_json::from_slice(&get(&url, &github_headers(token), 8 * 1024 * 1024)?)
        .context("decode GitHub release metadata")
}

fn asset_bytes(asset: &Asset, token: Option<&str>) -> Result<Vec<u8>> {
    if let Ok(bytes) = get(
        &asset.browser_download_url,
        &[("User-Agent".to_owned(), "wa-store".to_owned())],
        MAX_ARCHIVE_BYTES,
    ) {
        return Ok(bytes);
    }
    let Some(token) = token else {
        bail!("public asset download failed and no GitHub token is available");
    };
    ensure!(
        asset.url.starts_with("https://api.github.com/"),
        "refusing non-GitHub asset API URL"
    );
    let headers = [
        ("User-Agent".to_owned(), "wa-store".to_owned()),
        ("Accept".to_owned(), "application/octet-stream".to_owned()),
        ("Authorization".to_owned(), format!("Bearer {token}")),
    ];
    let borrowed = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let redirect = UreqClient::new()
        .get_redirect(&asset.url, &borrowed, 64 * 1024)
        .context("request private GitHub asset")?;
    ensure!(
        (300..400).contains(&redirect.status),
        "GitHub asset API returned HTTP {}",
        redirect.status
    );
    let location = redirect
        .location
        .context("GitHub asset redirect missing Location")?;
    ensure!(
        location.starts_with("https://")
            && [
                "github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ]
            .iter()
            .any(|host| url_host(&location) == *host),
        "refusing untrusted GitHub asset redirect"
    );
    get(
        &location,
        &[("User-Agent".to_owned(), "wa-store".to_owned())],
        MAX_ARCHIVE_BYTES,
    )
}

fn url_host(url: &str) -> &str {
    url.strip_prefix("https://")
        .unwrap_or_default()
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
}

fn take_archive(
    archive: &[u8],
    missing: &mut BTreeMap<String, WasmCapture>,
) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let tar = super::restore::decompress(archive, MAX_UNPACKED_BYTES)?;
    let mut selected = Vec::new();
    let mut count = 0usize;
    for entry in tar::Archive::new(tar.as_slice()).entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        count += 1;
        ensure!(
            count <= MAX_ARCHIVE_FILES,
            "archive contains too many files"
        );
        let name = entry
            .path()?
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        let Some(name) = name else { continue };
        let Some(capture) = missing.get(&name) else {
            continue;
        };
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if capture.matches(&bytes) {
            selected.push((PathBuf::from(&name), bytes));
            missing.remove(&name);
        }
    }
    Ok(selected)
}

fn persist(directory: &Path, selected: Vec<(PathBuf, Vec<u8>)>) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    for (name, bytes) in selected {
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&bytes)?;
        file.persist(directory.join(name))?;
    }
    Ok(())
}

fn apply_archive(
    archive: &[u8],
    missing: &mut BTreeMap<String, WasmCapture>,
    directory: &Path,
) -> Result<()> {
    let mut remaining = missing.clone();
    let selected = take_archive(archive, &mut remaining)?;
    persist(directory, selected)?;
    *missing = remaining;
    Ok(())
}

/// Restore every requested payload from its CDN URL or a configured release archive.
///
/// Existing files are accepted only after the same size/hash/magic checks. Release
/// archives may contain a superset; only matching locked basenames are materialized.
pub fn restore_captures(
    captures: &[WasmCapture],
    sources: &[ReleaseSource],
    directory: &Path,
) -> Result<()> {
    let mut missing = BTreeMap::new();
    for capture in captures {
        capture.validate()?;
        ensure!(
            missing
                .insert(capture.file_name.clone(), capture.clone())
                .is_none(),
            "duplicate capture {}",
            capture.file_name
        );
    }
    missing.retain(|name, capture| {
        !std::fs::read(directory.join(name)).is_ok_and(|bytes| capture.matches(&bytes))
    });
    for name in missing.keys().cloned().collect::<Vec<_>>() {
        let capture = &missing[&name];
        if let Some(url) = &capture.url
            && let Ok(bytes) = get(
                url,
                &[("User-Agent".to_owned(), "wa-store".to_owned())],
                capture.size.unwrap_or(MAX_WASM_BYTES) + 1,
            )
            && capture.matches(&bytes)
        {
            persist(directory, vec![(PathBuf::from(&name), bytes)])?;
            missing.remove(&name);
        }
    }
    let token = token();
    for source in sources {
        if missing.is_empty() {
            break;
        }
        let Ok(mut release) = release(&source.repo, &source.release, token.as_deref()) else {
            continue;
        };
        release.assets.retain(|asset| {
            asset.name.starts_with("wasm-")
                && (asset.name.ends_with(".tar.xz") || asset.name.ends_with(".tar.gz"))
        });
        release
            .assets
            .sort_by(|left, right| right.created_at.cmp(&left.created_at));
        for asset in release.assets {
            if missing.is_empty() {
                break;
            }
            let Ok(bytes) = asset_bytes(&asset, token.as_deref()) else {
                continue;
            };
            if apply_archive(&bytes, &mut missing, directory).is_err() {
                continue;
            }
        }
    }
    ensure!(
        missing.is_empty(),
        "pinned captures unavailable: {}",
        missing.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_boundary_rejects_paths_hashes_and_non_cdn_urls() {
        let capture = |file_name: &str, sha256: &str, url: Option<&str>| WasmCapture {
            file_name: file_name.to_owned(),
            sha256: sha256.to_owned(),
            size: Some(4),
            url: url.map(str::to_owned),
        };
        assert!(
            capture("../x.wasm", &"a".repeat(64), None)
                .validate()
                .is_err()
        );
        assert!(capture("x.wasm", "AA", None).validate().is_err());
        let mut oversized = capture("x.wasm", &"a".repeat(64), None);
        oversized.size = Some(MAX_WASM_BYTES + 1);
        assert!(oversized.validate().is_err());
        assert!(
            capture(
                "x.wasm",
                &"a".repeat(64),
                Some("https://example.invalid/x.wasm")
            )
            .validate()
            .is_err()
        );
    }

    #[test]
    fn archive_selection_requires_name_hash_size_and_wasm_magic() {
        let payload = b"\0asmgood";
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("wrong/x.wasm", b"\0asmbad".as_slice()),
            ("right/x.wasm", payload.as_slice()),
            ("other/y.wasm", b"\0asmother".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut tar.as_slice(), &mut compressed).unwrap();
        let pin = WasmCapture {
            file_name: "x.wasm".into(),
            sha256: wa_text::sha256_hex(payload),
            size: Some(payload.len() as u64),
            url: None,
        };
        let mut missing = BTreeMap::from([("x.wasm".into(), pin)]);
        let selected = take_archive(&compressed, &mut missing).unwrap();
        assert!(missing.is_empty());
        assert_eq!(selected, [(PathBuf::from("x.wasm"), payload.to_vec())]);
    }

    #[test]
    fn malformed_archive_does_not_consume_matches_from_later_archives() {
        let payload = b"\0asmgood";
        let pin = WasmCapture {
            file_name: "x.wasm".into(),
            sha256: wa_text::sha256_hex(payload),
            size: Some(payload.len() as u64),
            url: None,
        };
        let mut missing = BTreeMap::from([("x.wasm".into(), pin.clone())]);
        let directory = tempfile::tempdir().unwrap();
        assert!(apply_archive(b"not an archive", &mut missing, directory.path()).is_err());
        assert_eq!(missing, BTreeMap::from([("x.wasm".into(), pin)]));

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "x.wasm", payload.as_slice())
            .unwrap();
        let tar = builder.into_inner().unwrap();
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut tar.as_slice(), &mut compressed).unwrap();
        apply_archive(&compressed, &mut missing, directory.path()).unwrap();
        assert!(missing.is_empty());
        assert_eq!(
            std::fs::read(directory.path().join("x.wasm")).unwrap(),
            payload
        );
    }
}
