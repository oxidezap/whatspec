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
    assets_url: String,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    url: String,
    browser_download_url: String,
    created_at: String,
}

struct ArchiveSelection {
    remaining: BTreeMap<String, WasmCapture>,
    files: Vec<(PathBuf, Vec<u8>)>,
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
        bytes.len() as u64 <= MAX_WASM_BYTES
            && bytes.starts_with(b"\0asm")
            && self.size.is_none_or(|size| size == bytes.len() as u64)
            && wa_text::sha256_hex(bytes) == self.sha256
    }
}

fn token() -> Option<String> {
    ["GH_TOKEN", "GITHUB_TOKEN"]
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
    get_with(&UreqClient::new(), url, headers, max)
}

fn get_with(
    client: &impl HttpClient,
    url: &str,
    headers: &[(String, String)],
    max: u64,
) -> Result<Vec<u8>> {
    let borrowed = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let response = client
        .get(url, &borrowed, max)
        .with_context(|| format!("GET {url}"))?;
    ensure!(
        response.status == 200,
        "GET {url}: HTTP {}",
        response.status
    );
    Ok(response.body)
}

fn release_url(repo: &str, tag: &str) -> Result<url::Url> {
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
        !tag.is_empty() && !tag.chars().any(char::is_control),
        "invalid GitHub release tag {tag:?}"
    );
    let (owner, name) = repo.split_once('/').context("validated repository")?;
    let mut endpoint = url::Url::parse("https://api.github.com")?;
    endpoint
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("GitHub API URL cannot hold path segments"))?
        .extend(["repos", owner, name, "releases", "tags", tag]);
    Ok(endpoint)
}

fn release_with(
    client: &impl HttpClient,
    repo: &str,
    tag: &str,
    token: Option<&str>,
) -> Result<Release> {
    let endpoint = release_url(repo, tag)?;
    serde_json::from_slice(&get_with(
        client,
        endpoint.as_str(),
        &github_headers(token),
        8 * 1024 * 1024,
    )?)
    .context("decode GitHub release metadata")
}

fn release_assets(repo: &str, tag: &str, token: Option<&str>) -> Result<Vec<Asset>> {
    release_assets_with(&UreqClient::new(), repo, tag, token)
}

fn release_assets_with(
    client: &impl HttpClient,
    repo: &str,
    tag: &str,
    token: Option<&str>,
) -> Result<Vec<Asset>> {
    const MAX_ASSET_PAGES: u32 = 100;
    let release = release_with(client, repo, tag, token)?;
    let mut endpoint = url::Url::parse(&release.assets_url).context("parse GitHub assets URL")?;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.host_str() == Some("api.github.com")
            && endpoint.username().is_empty()
            && endpoint.password().is_none(),
        "refusing untrusted GitHub assets URL"
    );
    let mut assets = Vec::new();
    for page in 1..=MAX_ASSET_PAGES {
        endpoint
            .query_pairs_mut()
            .clear()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let batch: Vec<Asset> = serde_json::from_slice(&get_with(
            client,
            endpoint.as_str(),
            &github_headers(token),
            8 * 1024 * 1024,
        )?)
        .context("decode GitHub release assets")?;
        let complete = batch.len() < 100;
        assets.extend(batch);
        if complete {
            return Ok(assets);
        }
    }
    bail!(
        "GitHub release has more than {} assets",
        MAX_ASSET_PAGES * 100
    )
}

fn asset_bytes(asset: &Asset, token: Option<&str>) -> Result<Vec<u8>> {
    asset_bytes_with(&UreqClient::new(), asset, token)
}

fn asset_bytes_with(
    client: &impl HttpClient,
    asset: &Asset,
    token: Option<&str>,
) -> Result<Vec<u8>> {
    if let Ok(bytes) = get_with(
        client,
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
    let response = client
        .get_redirect(&asset.url, &borrowed, MAX_ARCHIVE_BYTES)
        .context("request private GitHub asset")?;
    if response.status == 200 {
        return Ok(response.body);
    }
    ensure!(
        (300..400).contains(&response.status),
        "GitHub asset API returned HTTP {}",
        response.status
    );
    let location = response
        .location
        .context("GitHub asset redirect missing Location")?;
    ensure!(
        trusted_asset_redirect(&location),
        "refusing untrusted GitHub asset redirect"
    );
    get_with(
        client,
        &location,
        &[("User-Agent".to_owned(), "wa-store".to_owned())],
        MAX_ARCHIVE_BYTES,
    )
}

fn trusted_asset_redirect(location: &str) -> bool {
    url::Url::parse(location).is_ok_and(|redirect| {
        redirect.scheme() == "https"
            && redirect.username().is_empty()
            && redirect.password().is_none()
            && [
                "github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ]
            .iter()
            .any(|host| redirect.host_str() == Some(*host))
    })
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

fn select_archive(
    archive: &[u8],
    missing: &BTreeMap<String, WasmCapture>,
) -> Result<ArchiveSelection> {
    let mut remaining = missing.clone();
    let files = take_archive(archive, &mut remaining)?;
    Ok(ArchiveSelection { remaining, files })
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
        let Ok(mut assets) = release_assets(&source.repo, &source.release, token.as_deref()) else {
            continue;
        };
        assets.retain(|asset| {
            asset.name.starts_with("wasm-")
                && (asset.name.ends_with(".tar.xz") || asset.name.ends_with(".tar.gz"))
        });
        assets.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        for asset in assets {
            if missing.is_empty() {
                break;
            }
            let Ok(bytes) = asset_bytes(&asset, token.as_deref()) else {
                continue;
            };
            let Ok(selection) = select_archive(&bytes, &missing) else {
                continue;
            };
            persist(directory, selection.files)?;
            missing = selection.remaining;
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
    use std::sync::Mutex;

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
    fn release_tags_are_encoded_as_one_api_path_segment() {
        let url = release_url("owner/repository", "releases/v1.2+build").unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.github.com/repos/owner/repository/releases/tags/releases%2Fv1.2+build"
        );
    }

    #[test]
    fn release_assets_are_paginated() {
        struct Pages(Mutex<Vec<String>>);
        impl HttpClient for Pages {
            fn get(
                &self,
                url: &str,
                _headers: &[(&str, &str)],
                _max_bytes: u64,
            ) -> std::result::Result<wa_fetch::HttpResponse, wa_fetch::FetchError> {
                self.0.lock().unwrap().push(url.to_owned());
                let body = if url.contains("/releases/tags/") {
                    br#"{"assets_url":"https://api.github.com/repos/owner/repository/releases/1/assets"}"#.to_vec()
                } else if url::Url::parse(url).is_ok_and(|url| {
                    url.query_pairs()
                        .any(|(name, value)| name == "page" && value == "1")
                }) {
                    serde_json::to_vec(
                        &(0..100)
                            .map(|index| serde_json::json!({
                                "name": format!("wasm-{index}.tar.xz"),
                                "url": format!("https://api.github.com/assets/{index}"),
                                "browser_download_url": format!("https://github.com/assets/{index}"),
                                "created_at": "2026-01-01T00:00:00Z"
                            }))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
                } else {
                    b"[]".to_vec()
                };
                Ok(wa_fetch::HttpResponse { status: 200, body })
            }
        }

        let client = Pages(Mutex::new(Vec::new()));
        assert_eq!(
            release_assets_with(&client, "owner/repository", "tag", None)
                .unwrap()
                .len(),
            100
        );
        let requested = client.0.into_inner().unwrap();
        assert!(requested.iter().any(|url| url.contains("page=1")));
        assert!(requested.iter().any(|url| url.contains("page=2")));
    }

    #[test]
    fn asset_redirect_rejects_credentials_and_untrusted_hosts() {
        assert!(trusted_asset_redirect(
            "https://release-assets.githubusercontent.com/file"
        ));
        assert!(!trusted_asset_redirect(
            "https://release-assets.githubusercontent.com@evil.example/file"
        ));
        assert!(!trusted_asset_redirect(
            "https://github.com:secret@evil.example/file"
        ));
    }

    #[test]
    fn authenticated_asset_api_may_stream_the_body_directly() {
        struct Direct;
        impl HttpClient for Direct {
            fn get(
                &self,
                _url: &str,
                _headers: &[(&str, &str)],
                _max_bytes: u64,
            ) -> std::result::Result<wa_fetch::HttpResponse, wa_fetch::FetchError> {
                Ok(wa_fetch::HttpResponse {
                    status: 404,
                    body: Vec::new(),
                })
            }

            fn get_redirect(
                &self,
                _url: &str,
                _headers: &[(&str, &str)],
                _max_bytes: u64,
            ) -> std::result::Result<wa_fetch::RedirectResponse, wa_fetch::FetchError> {
                Ok(wa_fetch::RedirectResponse {
                    status: 200,
                    location: None,
                    body: b"archive".to_vec(),
                })
            }
        }
        let asset = Asset {
            name: "wasm-test.tar.xz".into(),
            url: "https://api.github.com/repos/owner/repository/releases/assets/1".into(),
            browser_download_url: "https://github.com/owner/repository/releases/download/tag/asset"
                .into(),
            created_at: String::new(),
        };
        assert_eq!(
            asset_bytes_with(&Direct, &asset, Some("token")).unwrap(),
            b"archive"
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
        assert!(select_archive(b"not an archive", &missing).is_err());
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
        let selection = select_archive(&compressed, &missing).unwrap();
        persist(directory.path(), selection.files).unwrap();
        missing = selection.remaining;
        assert!(missing.is_empty());
        assert_eq!(
            std::fs::read(directory.path().join("x.wasm")).unwrap(),
            payload
        );
    }
}
