//! `whatspec` CLI. The `update` command runs the full pipeline and writes
//! versioned artifacts (IQ specs, WAProto.proto, mex operations, appstate
//! schemas) to disk, ready to be committed — locally or from CI.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const DEFAULT_OUT: &str = "generated";
const UNKNOWN_VERSION: &str = "unknown";
const BUNDLE_SEPARATOR: &str = "\n;\n";

const FLAG_OUT: &str = "--out";
const FLAG_BUNDLES: &str = "--bundles";
const FLAG_WA_VERSION: &str = "--wa-version";
const FLAG_SAVE_BUNDLES: &str = "--save-bundles";
const FLAG_CHECK: &str = "--check";
const FLAG_FILE: &str = "--file";
const FLAG_CACHE: &str = "--cache";
const FLAG_ALLOW_SHRINK: &str = "--allow-shrink";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("update") => update(&args[1..]),
        Some("mex-ids") => mex_ids(&args[1..]),
        Some("diff") => diff(&args[1..]),
        _ => {
            eprintln!("{}", usage());
            Ok(())
        }
    }
}

fn usage() -> String {
    format!(
        "whatspec — WhatsApp Web spec extractor\n\n\
         usage:\n  \
         whatspec update [{FLAG_OUT} <dir>] [{FLAG_BUNDLES} <dir>] [{FLAG_WA_VERSION} <ver>]\n                  \
         [{FLAG_SAVE_BUNDLES} <dir>] [{FLAG_CACHE} <dir>] [{FLAG_CHECK}] [{FLAG_ALLOW_SHRINK}]\n\n\
         Fetches web.whatsapp.com bundles (or reads {FLAG_BUNDLES} <dir> of .js files),\n\
         extracts IQ specs / WAProto.proto / mex operations / appstate schemas, and writes\n\
         them under <dir> (default `{DEFAULT_OUT}`), stamped with the WhatsApp version.\n\n\
         whatspec mex-ids {FLAG_FILE} <mex_ids.rs> [{FLAG_BUNDLES} <dir>] [{FLAG_WA_VERSION} <ver>] [{FLAG_CHECK}]\n\n\
         Refreshes the rotating `id` of each `MexDoc` in a hand-curated mex_ids.rs by matching\n\
         its stable `name` against the current bundle, preserving const names/grouping, and\n\
         reports stale entries whose `name` no longer exists upstream.\n\n\
         whatspec diff <old-dir> <new-dir>\n\n\
         Compares two generated output directories (by their `manifest.json` + `index.json`s)\n\
         and prints version/count deltas and the namespaces/operations/actions added or removed.\n\n\
         flags:\n  \
         {FLAG_OUT} <dir>           output directory (default `{DEFAULT_OUT}`)\n  \
         {FLAG_BUNDLES} <dir>       read local .js bundles instead of fetching\n  \
         {FLAG_WA_VERSION} <ver>    stamp this version instead of the discovered one\n  \
         {FLAG_SAVE_BUNDLES} <dir>  persist fetched bundles to <dir>\n  \
         {FLAG_CACHE} <dir>         cache bundles by version in <dir>; reuse if the remote\n                             \
         version is already cached complete & intact, else re-download\n  \
         {FLAG_FILE} <path>         (mex-ids) the mex_ids.rs to refresh in place\n  \
         {FLAG_CHECK}              generate in-memory and exit non-zero if it differs from disk\n  \
         {FLAG_ALLOW_SHRINK}       accept output that shrinks below the committed manifest counts"
    )
}

/// Parsed `update` options.
#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    out: PathBuf,
    bundles_dir: Option<PathBuf>,
    wa_version: Option<String>,
    // Only consumed by `fetch_source`; kept parseable in fetch-free builds so the
    // flags aren't a hard error, hence the conditional dead-code allowance.
    #[cfg_attr(not(feature = "fetch"), allow(dead_code))]
    save_bundles: Option<PathBuf>,
    /// When set, fetch goes through a version-keyed on-disk cache at this dir:
    /// a complete, intact cache of the discovered remote version skips the
    /// download; anything else re-downloads from scratch.
    #[cfg_attr(not(feature = "fetch"), allow(dead_code))]
    cache_dir: Option<PathBuf>,
    check: bool,
    /// Accept an output that shrinks below the committed `manifest.json` counts.
    /// Off by default: a drop trips the regression guard and aborts the write.
    allow_shrink: bool,
}

fn parse_update_args(args: &[String]) -> Result<Options> {
    let mut opts = Options {
        out: PathBuf::from(DEFAULT_OUT),
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            FLAG_OUT => {
                opts.out = PathBuf::from(arg_value(args, i, FLAG_OUT)?);
                i += 2;
            }
            FLAG_BUNDLES => {
                opts.bundles_dir = Some(PathBuf::from(arg_value(args, i, FLAG_BUNDLES)?));
                i += 2;
            }
            FLAG_WA_VERSION => {
                opts.wa_version = Some(arg_value(args, i, FLAG_WA_VERSION)?.to_string());
                i += 2;
            }
            FLAG_SAVE_BUNDLES => {
                opts.save_bundles = Some(PathBuf::from(arg_value(args, i, FLAG_SAVE_BUNDLES)?));
                i += 2;
            }
            FLAG_CACHE => {
                opts.cache_dir = Some(PathBuf::from(arg_value(args, i, FLAG_CACHE)?));
                i += 2;
            }
            FLAG_CHECK => {
                opts.check = true;
                i += 1;
            }
            FLAG_ALLOW_SHRINK => {
                opts.allow_shrink = true;
                i += 1;
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }
    Ok(opts)
}

fn update(args: &[String]) -> Result<()> {
    let opts = parse_update_args(args)?;

    let (wa_version, source) = load_source(&opts)?;
    eprintln!("WhatsApp version: {wa_version}");

    let (artifacts, counts) = build_artifacts(&wa_version, &source)?;

    if opts.check {
        let diffs = check_artifacts(&opts.out, &artifacts)?;
        if diffs.is_empty() {
            eprintln!("check: {} artifact(s) up to date", artifacts.len());
            return Ok(());
        }
        eprintln!("check: {} artifact(s) differ from disk:", diffs.len());
        for d in &diffs {
            eprintln!("  {d}");
        }
        std::process::exit(1);
    }

    // Regression guard (H1): refuse to overwrite committed artifacts with a
    // smaller set unless explicitly allowed. Catches an extractor silently
    // breaking (e.g. a bundle-format change halving the stanza count).
    let regressions = check_floor(&opts.out, &counts)?;
    if !regressions.is_empty() {
        eprintln!("regression guard: output counts dropped below the committed manifest:");
        for r in &regressions {
            eprintln!("  {r}");
        }
        if !opts.allow_shrink {
            anyhow::bail!(
                "refusing to overwrite ({} domain(s) shrank) — re-run with {FLAG_ALLOW_SHRINK} \
                 to accept the reduction",
                regressions.len()
            );
        }
        eprintln!("{FLAG_ALLOW_SHRINK}: accepting the reduction");
    }

    for art in &artifacts {
        let path = opts.out.join(&art.rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &art.content).with_context(|| format!("write {}", path.display()))?;
    }

    eprintln!(
        "wrote artifacts to {}: {} iq modules, {} proto entities, {} mex ops, {} appstate actions, \
         {} abprops, {} enums, {} wam events, {} notif types, {} stanzas, {}+{} tokens",
        opts.out.display(),
        counts.iq_modules,
        counts.proto_entities,
        counts.mex_ops,
        counts.appstate_actions,
        counts.abprops_configs,
        counts.enum_defs,
        counts.wam_events,
        counts.notif_types,
        counts.stanza_defs,
        counts.token_single_byte,
        counts.token_double_byte
    );
    Ok(())
}

fn arg_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str> {
    args.get(i + 1)
        .map(String::as_str)
        .with_context(|| format!("{flag} requires a value"))
}

/// `whatspec mex-ids` — refresh the rotating ids in a hand-curated mex_ids.rs.
fn mex_ids(args: &[String]) -> Result<()> {
    let mut file: Option<PathBuf> = None;
    let mut opts = Options::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            FLAG_FILE => {
                file = Some(PathBuf::from(arg_value(args, i, FLAG_FILE)?));
                i += 2;
            }
            FLAG_BUNDLES => {
                opts.bundles_dir = Some(PathBuf::from(arg_value(args, i, FLAG_BUNDLES)?));
                i += 2;
            }
            FLAG_WA_VERSION => {
                opts.wa_version = Some(arg_value(args, i, FLAG_WA_VERSION)?.to_string());
                i += 2;
            }
            FLAG_CHECK => {
                opts.check = true;
                i += 1;
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }
    let file = file.with_context(|| format!("mex-ids requires {FLAG_FILE} <path>"))?;

    let existing = fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    let (wa_version, source) = load_source(&opts)?;
    eprintln!("WhatsApp version: {wa_version}");

    let ir = wa_mex::extract_mex(&source, &wa_version);
    let refresh = wa_codegen::refresh_mex_ids(&existing, &ir);

    eprintln!(
        "mex-ids: {} unchanged, {} changed, {} stale, {} bundle ops unreferenced",
        refresh.unchanged.len(),
        refresh.changed.len(),
        refresh.stale.len(),
        refresh.available_unused
    );
    for (name, old, new) in &refresh.changed {
        eprintln!("  ~ {name}: {old} -> {new}");
    }
    for name in &refresh.stale {
        eprintln!("  ! stale (not in bundle, remap by hand): {name}");
    }

    if opts.check {
        if refresh.changed.is_empty() && refresh.stale.is_empty() {
            eprintln!("check: mex_ids.rs is up to date");
            return Ok(());
        }
        std::process::exit(1);
    }

    if refresh.updated_source != existing {
        fs::write(&file, &refresh.updated_source)
            .with_context(|| format!("write {}", file.display()))?;
        eprintln!("wrote {}", file.display());
    } else {
        eprintln!("no id changes — {} left untouched", file.display());
    }
    Ok(())
}

/// `whatspec diff <old-dir> <new-dir>` — report what changed between two
/// generated outputs (version/count deltas + per-domain name set add/remove).
fn diff(args: &[String]) -> Result<()> {
    let (old, new) = match (args.first(), args.get(1)) {
        (Some(a), Some(b)) => (Path::new(a), Path::new(b)),
        _ => anyhow::bail!("diff requires two paths: whatspec diff <old-dir> <new-dir>"),
    };
    let mo = read_json(&old.join("manifest.json"))?;
    let mn = read_json(&new.join("manifest.json"))?;

    println!("whatspec diff: {} -> {}", old.display(), new.display());

    // Version / contract fields.
    for key in ["schemaVersion", "generatorVersion", "waVersion"] {
        let (o, n) = (json_str(&mo, key), json_str(&mn, key));
        let mark = if o != n { "  *" } else { "" };
        println!("  {key}: {o} -> {n}{mark}");
    }

    // Per-domain counts.
    for key in [
        "iqModules",
        "protoEntities",
        "mexOperations",
        "appstateActions",
        "abPropsConfigs",
        "enumDefs",
        "wamEvents",
        "notifTypes",
        "stanzaDefs",
        "tokenSingleByte",
        "tokenDoubleByte",
    ] {
        print_count_delta(key, json_u64(&mo, key), json_u64(&mn, key));
    }

    // IQ extraction-quality diagnostics (present since the diagnostics manifest).
    let diag = |m: &serde_json::Value, k: &str| {
        m.get("diagnostics")
            .and_then(|d| d.get("iq"))
            .and_then(|i| i.get(k))
            .and_then(serde_json::Value::as_u64)
    };
    for key in ["typedResponses", "degradedResponses", "unparseable"] {
        if let (Some(o), Some(n)) = (diag(&mo, key), diag(&mn, key)) {
            print_count_delta(&format!("iq.{key}"), Some(o), Some(n));
        }
    }

    // Per-domain name sets added/removed.
    print_name_diff(
        "iq namespaces",
        old,
        new,
        "iq/index.json",
        "stanzas",
        "namespace",
    );
    print_name_diff(
        "mex operations",
        old,
        new,
        "mex/index.json",
        "operations",
        "name",
    );
    print_name_diff(
        "appstate actions",
        old,
        new,
        "appstate/index.json",
        "actions",
        "name",
    );
    print_name_diff(
        "abprops flags",
        old,
        new,
        "abprops/index.json",
        "configs",
        "name",
    );
    print_name_diff("enums", old, new, "enums/index.json", "enums", "name");
    print_name_diff(
        "notif types",
        old,
        new,
        "notif/index.json",
        "notifications",
        "type",
    );

    Ok(())
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn json_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("—")
}

fn json_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(serde_json::Value::as_u64)
}

/// Print `key: old -> new (±Δ)`, marking changes; `—` for an absent count.
fn print_count_delta(key: &str, old: Option<u64>, new: Option<u64>) {
    match (old, new) {
        (Some(o), Some(n)) if o != n => {
            let delta = n as i64 - o as i64;
            println!("  {key}: {o} -> {n} ({delta:+})");
        }
        (Some(o), Some(n)) => println!("  {key}: {n} (={o})"),
        (o, n) => println!(
            "  {key}: {} -> {}",
            o.map(|x| x.to_string()).unwrap_or_else(|| "—".into()),
            n.map(|x| x.to_string()).unwrap_or_else(|| "—".into()),
        ),
    }
}

/// Collect the distinct names of a domain collection for set-diffing. Handles
/// both shapes the IR emits: a JSON **array** of objects (iq/abprops/enums →
/// take `name_key` from each) and a JSON **object** keyed by name (mex/appstate
/// `BTreeMap`s → the keys are the names).
fn name_set(dir: &Path, rel: &str, array_key: &str, name_key: &str) -> Option<BTreeSet<String>> {
    let v = read_json(&dir.join(rel)).ok()?;
    match v.get(array_key)? {
        serde_json::Value::Array(arr) => Some(
            arr.iter()
                .filter_map(|e| e.get(name_key).and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect(),
        ),
        serde_json::Value::Object(map) => Some(map.keys().cloned().collect()),
        _ => None,
    }
}

/// Print the names added/removed for one domain (capped, with an overflow count).
fn print_name_diff(
    label: &str,
    old: &Path,
    new: &Path,
    rel: &str,
    array_key: &str,
    name_key: &str,
) {
    let (Some(o), Some(n)) = (
        name_set(old, rel, array_key, name_key),
        name_set(new, rel, array_key, name_key),
    ) else {
        return;
    };
    let added: Vec<&String> = n.difference(&o).collect();
    let removed: Vec<&String> = o.difference(&n).collect();
    if added.is_empty() && removed.is_empty() {
        println!("  {label}: unchanged ({} total)", n.len());
        return;
    }
    println!(
        "  {label}: +{} added, -{} removed",
        added.len(),
        removed.len()
    );
    const CAP: usize = 40;
    for name in added.iter().take(CAP) {
        println!("    + {name}");
    }
    if added.len() > CAP {
        println!("    + …and {} more", added.len() - CAP);
    }
    for name in removed.iter().take(CAP) {
        println!("    - {name}");
    }
    if removed.len() > CAP {
        println!("    - …and {} more", removed.len() - CAP);
    }
}

/// A generated file: path relative to the output dir + its full text.
struct Artifact {
    rel_path: PathBuf,
    content: String,
}

#[derive(Debug, Default)]
struct Counts {
    iq_modules: usize,
    proto_entities: usize,
    mex_ops: usize,
    appstate_actions: usize,
    abprops_configs: usize,
    enum_defs: usize,
    wam_events: usize,
    /// Number of `<notification type="…">` kinds in the dispatch catalog.
    notif_types: usize,
    /// Of those, how many recovered a typed content shape (the rest are degraded).
    notif_typed_content: usize,
    /// Top-level stanza tags in the dispatch catalog (a drop to 0 means the
    /// tag-switch stopped being recognized even if notif types survive).
    notif_stanza_tags: usize,
    /// Stanza-level IQ coverage (more sensitive than the namespace/module count)
    /// — carried so the floor guard can regress on a stanza-count drop, matching
    /// `manifest.diagnostics.iq.{stanzas,typedResponses}`.
    iq_stanzas: usize,
    iq_typed_responses: usize,
    /// Outgoing non-IQ stanzas (receipt/presence/chatstate/ack) the scanner recovers.
    stanza_defs: usize,
    /// Binary-protocol token tables: single-byte entries (incl. the leading empty
    /// token) and the total across all double-byte dictionaries.
    token_single_byte: usize,
    token_double_byte: usize,
}

/// Extraction-quality signals for the IQ domain, emitted under `diagnostics.iq`
/// in the manifest so a consumer (or CI) can see coverage and drops at a glance.
#[derive(Debug, Default)]
struct IqDiagnostics {
    candidate_modules: usize,
    stanzas: usize,
    typed_responses: usize,
    degraded_responses: usize,
    unparseable: usize,
    drops_by_reason: std::collections::BTreeMap<String, usize>,
    /// Cross-module (`mergeStanzas`, Phase 2) recovery counters: how many requests
    /// fold in mixin fragments, how many gain fields from them, and the total
    /// fields recovered. `requests_enriched`/`fields_recovered` going to 0 flags a
    /// regression in Phase-2 fragment merging.
    cross_module: wa_scan::CrossModuleStats,
}

/// Returns `(wa_version, concatenated_bundle_source)`. The `--wa-version`
/// override always wins; otherwise the version comes from discovery (fetch mode)
/// or defaults to `unknown` (local mode).
fn load_source(opts: &Options) -> Result<(String, String)> {
    match &opts.bundles_dir {
        Some(dir) => {
            let source = read_local_bundles(dir)?;
            let version = opts
                .wa_version
                .clone()
                .unwrap_or_else(|| UNKNOWN_VERSION.to_string());
            Ok((version, source))
        }
        #[cfg(feature = "fetch")]
        None => fetch_source(opts),
        #[cfg(not(feature = "fetch"))]
        None => anyhow::bail!(
            "network fetch is disabled in this build — pass {FLAG_BUNDLES} <dir> to process local \
             bundles, or rebuild with the `fetch` feature."
        ),
    }
}

fn read_local_bundles(dir: &Path) -> Result<String> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("js"))
        .collect();
    if paths.is_empty() {
        anyhow::bail!(
            "no .js bundles found in {} — pass a directory of WhatsApp Web .js bundles, \
             or omit {FLAG_BUNDLES} to fetch from the network",
            dir.display()
        );
    }
    // Deterministic order so concatenation (and thus output) is stable.
    paths.sort();

    let total: usize = paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| m.len() as usize)
        .sum();
    let mut source = String::with_capacity(total + paths.len() * BUNDLE_SEPARATOR.len());
    for path in &paths {
        source.push_str(&fs::read_to_string(path)?);
        source.push_str(BUNDLE_SEPARATOR);
    }
    eprintln!(
        "loaded {} local bundles from {}",
        paths.len(),
        dir.display()
    );
    Ok(source)
}

#[cfg(feature = "fetch")]
fn fetch_source(opts: &Options) -> Result<(String, String)> {
    let discovered = wa_fetch::discover_bundle_urls(wa_fetch::WA_WEB_URL)
        .context("discover WhatsApp Web bundles")?;
    eprintln!("discovered {} bundles", discovered.js.len());

    if discovered.js.is_empty() {
        anyhow::bail!(
            "discovered 0 JS bundles (HTTP {}, {} bytes of HTML; by source: script_tag={}, rsrc_map={}, scheduled_js={}). \
             Likely anti-bot interception or a page-structure change — inspect the response or run with --bundles <dir>.",
            discovered.status,
            discovered.html_bytes,
            discovered.by_source.script_tag,
            discovered.by_source.rsrc_map,
            discovered.by_source.scheduled_js
        );
    }

    // Stamp version: --wa-version override wins, else the discovered one, else bail.
    let version = match opts
        .wa_version
        .clone()
        .or_else(|| discovered.wa_version.clone())
    {
        Some(v) => v,
        None => anyhow::bail!(
            "could not determine the WhatsApp version (no SiteData.client_revision in the page). \
             Pass --wa-version <ver> to stamp it explicitly."
        ),
    };

    // Cache fast-path: discovery already gave us the remote version (one small
    // HTML request, no bundles). If that exact version is cached complete and
    // intact, reuse it and skip downloading hundreds of bundles. The cache is
    // keyed by the *discovered* version (the real remote identity), not by a
    // possibly-overridden stamp, nor by the URL set — WhatsApp serves a slightly
    // varying bundle set per request even for one version.
    if let (Some(cache_dir), Some(remote_version)) = (&opts.cache_dir, &discovered.wa_version) {
        let cache = wa_fetch::BundleCache::new(cache_dir.clone());
        match cache.check(remote_version) {
            wa_fetch::CacheStatus::Hit(bundles) => {
                eprintln!(
                    "cache hit for {remote_version} ({} bundles) — skipping download",
                    bundles.len()
                );
                maybe_save_bundles(opts, &bundles)?;
                return Ok((version, concat_bundles(&bundles)));
            }
            wa_fetch::CacheStatus::Miss(reason) => {
                eprintln!("cache miss ({reason}) — downloading from scratch");
            }
        }
    } else if opts.cache_dir.is_some() {
        eprintln!("cache disabled: remote version is undetectable, cannot key the cache");
    }

    let outcome = wa_fetch::download_bundles(&discovered.js, &wa_fetch::DownloadOptions::default());
    if !outcome.failures.is_empty() {
        eprintln!(
            "warning: {} bundle download(s) failed",
            outcome.failures.len()
        );
    }
    if outcome.bundles.is_empty() {
        anyhow::bail!(
            "downloaded 0 of {} discovered bundles (all {} failed) — network or anti-bot issue.",
            discovered.js.len(),
            outcome.failures.len()
        );
    }

    // Persist to the cache only on a fully-complete download (every discovered
    // bundle present, no failures) — never cache a half-downloaded set, so a
    // later run with the same version re-downloads instead of trusting a partial.
    if let (Some(cache_dir), Some(remote_version)) = (&opts.cache_dir, &discovered.wa_version) {
        let complete = outcome.failures.is_empty() && outcome.bundles.len() == discovered.js.len();
        if complete {
            let cache = wa_fetch::BundleCache::new(cache_dir.clone());
            cache
                .store(remote_version, &outcome.bundles)
                .with_context(|| format!("write bundle cache at {}", cache_dir.display()))?;
            eprintln!(
                "cached {} bundles for {remote_version} at {}",
                outcome.bundles.len(),
                cache_dir.display()
            );
        } else {
            eprintln!(
                "not caching: incomplete download ({} of {} bundles)",
                outcome.bundles.len(),
                discovered.js.len()
            );
        }
    }

    maybe_save_bundles(opts, &outcome.bundles)?;
    Ok((version, concat_bundles(&outcome.bundles)))
}

/// Concatenate bundle bytes into one source string (lossy UTF-8), with the
/// module separator between bundles. Shared by the cache-hit and download paths.
#[cfg(feature = "fetch")]
fn concat_bundles(bundles: &[wa_fetch::Bundle]) -> String {
    let total: usize = bundles.iter().map(|b| b.bytes.len()).sum();
    let mut source = String::with_capacity(total + bundles.len() * BUNDLE_SEPARATOR.len());
    for bundle in bundles {
        match std::str::from_utf8(&bundle.bytes) {
            Ok(s) => source.push_str(s),
            Err(_) => source.push_str(&String::from_utf8_lossy(&bundle.bytes)),
        }
        source.push_str(BUNDLE_SEPARATOR);
    }
    source
}

/// Honour `--save-bundles` if set (no-op otherwise).
#[cfg(feature = "fetch")]
fn maybe_save_bundles(opts: &Options, bundles: &[wa_fetch::Bundle]) -> Result<()> {
    if let Some(save_dir) = &opts.save_bundles {
        wa_fetch::save_bundles(bundles, save_dir)
            .with_context(|| format!("save bundles to {}", save_dir.display()))?;
        eprintln!("saved {} bundles to {}", bundles.len(), save_dir.display());
    }
    Ok(())
}

/// Run every extractor + codegen and collect the resulting files in memory.
fn build_artifacts(wa_version: &str, source: &str) -> Result<(Vec<Artifact>, Counts)> {
    // Split the ~71MB concatenation into Metro modules exactly once; every
    // AST-based extractor re-parses only the slices it cares about.
    let module_defs = wa_transform::extract_module_definitions(source);

    // The four extractors are independent and read-only over the shared inputs,
    // so run them concurrently on plain scoped threads (no async runtime).
    // The four extractors are independent and read-only over the shared inputs;
    // each returns `Result` so a failure surfaces with context instead of a
    // silent empty artifact or a bare panic.
    let (iq, proto, mex, appstate, abprops, enums, wam, notif, stanza, tokens) =
        std::thread::scope(|s| {
            let iq = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_iq(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let proto = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_proto(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let mex = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_mex(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let appstate = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_appstate(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let abprops = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_abprops(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let enums = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_enums(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let wam = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_wam(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let notif = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_notif(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let stanza = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_stanza(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            let tokens = s.spawn(|| -> Result<_> {
                let mut a = Vec::new();
                let c = push_tokens(&mut a, wa_version, source, &module_defs)?;
                Ok((a, c))
            });
            (
                iq.join().expect("iq extractor panicked"),
                proto.join().expect("proto extractor panicked"),
                mex.join().expect("mex extractor panicked"),
                appstate.join().expect("appstate extractor panicked"),
                abprops.join().expect("abprops extractor panicked"),
                enums.join().expect("enums extractor panicked"),
                wam.join().expect("wam extractor panicked"),
                notif.join().expect("notif extractor panicked"),
                stanza.join().expect("stanza extractor panicked"),
                tokens.join().expect("tokens extractor panicked"),
            )
        });
    let (iq_arts, (iq_count, iq_diag)) = iq.context("iq codegen")?;
    let (proto_arts, proto_count) = proto.context("proto extraction")?;
    let (mex_arts, mex_count) = mex.context("mex extraction")?;
    let (appstate_arts, appstate_count) = appstate.context("appstate extraction")?;
    let (abprops_arts, abprops_count) = abprops.context("abprops extraction")?;
    let (enums_arts, enums_count) = enums.context("enums extraction")?;
    let (wam_arts, wam_count) = wam.context("wam extraction")?;
    let (notif_arts, (notif_count, notif_typed, notif_tags)) = notif.context("notif extraction")?;
    let (stanza_arts, stanza_count) = stanza.context("stanza extraction")?;
    let (tokens_arts, (token_single, token_double)) = tokens.context("tokens extraction")?;

    // Fail loud if any domain extracted nothing — a real WA bundle always yields
    // all of these, so a zero means the bundle is incomplete or that extractor
    // broke (the IQ domain has its own 0-candidate bail inside `push_iq`).
    for (name, n) in [
        ("proto entities", proto_count),
        ("mex operations", mex_count),
        ("appstate actions", appstate_count),
        ("abprops configs", abprops_count),
        ("enum defs", enums_count),
        ("wam events", wam_count),
        ("notif types", notif_count),
        ("stanza defs", stanza_count),
        ("token single-byte entries", token_single),
    ] {
        if n == 0 {
            anyhow::bail!(
                "{name}: extracted 0 — the bundle is incomplete or the {name} extractor broke. \
                 Inspect the bundle or the extractor before overwriting committed artifacts."
            );
        }
    }

    // Concatenate in a fixed order so the artifact list is deterministic.
    let mut artifacts = Vec::new();
    artifacts.extend(iq_arts);
    artifacts.extend(proto_arts);
    artifacts.extend(mex_arts);
    artifacts.extend(appstate_arts);
    artifacts.extend(abprops_arts);
    artifacts.extend(enums_arts);
    artifacts.extend(wam_arts);
    artifacts.extend(notif_arts);
    artifacts.extend(stanza_arts);
    artifacts.extend(tokens_arts);

    // JSON Schema of the IR contract (one per domain), for cross-language
    // consumers to validate the `index.json` files and auto-generate IR types.
    for (rel, json) in wa_ir::schemas() {
        artifacts.push(Artifact {
            rel_path: PathBuf::from(rel),
            content: json,
        });
    }

    let counts = Counts {
        iq_modules: iq_count,
        proto_entities: proto_count,
        mex_ops: mex_count,
        appstate_actions: appstate_count,
        abprops_configs: abprops_count,
        enum_defs: enums_count,
        wam_events: wam_count,
        notif_types: notif_count,
        notif_typed_content: notif_typed,
        notif_stanza_tags: notif_tags,
        iq_stanzas: iq_diag.stanzas,
        iq_typed_responses: iq_diag.typed_responses,
        stanza_defs: stanza_count,
        token_single_byte: token_single,
        token_double_byte: token_double,
    };

    // The neutral, language-agnostic artifacts a consumer reads (one per domain).
    // Each manifest entry carries a content hash so consumers can cache/diff.
    let neutral = [
        ("iq", "iq/index.json", "schema/iq.schema.json"),
        ("proto", "proto/WAProto.proto", ""),
        ("mex", "mex/index.json", "schema/mex.schema.json"),
        (
            "appstate",
            "appstate/index.json",
            "schema/appstate.schema.json",
        ),
        (
            "abprops",
            "abprops/index.json",
            "schema/abprops.schema.json",
        ),
        ("enums", "enums/index.json", "schema/enums.schema.json"),
        ("wam", "wam/index.json", "schema/wam.schema.json"),
        ("notif", "notif/index.json", "schema/notif.schema.json"),
        ("stanza", "stanza/index.json", "schema/stanza.schema.json"),
        ("tokens", "tokens/index.json", "schema/tokens.schema.json"),
    ];
    let domains: serde_json::Map<String, serde_json::Value> =
        neutral
            .iter()
            .map(
                |(name, file, schema)| -> Result<(String, serde_json::Value)> {
                    // Bail instead of hashing an empty string if a domain's artifact name
                    // drifts out of sync with this table (which would record a bogus hash).
                    let content = artifacts
                .iter()
                .find(|a| a.rel_path.to_str() == Some(*file))
                .map(|a| a.content.as_str())
                .with_context(|| {
                    format!("manifest: domain artifact `{file}` is missing from the generated set")
                })?;
                    let mut entry = serde_json::json!({
                        "file": file,
                        "sha256": wa_text::sha256_hex(content.as_bytes()),
                    });
                    if !schema.is_empty() {
                        entry["schema"] = serde_json::Value::String((*schema).to_string());
                    }
                    Ok((name.to_string(), entry))
                },
            )
            .collect::<Result<_>>()?;

    let manifest = serde_json::json!({
        "schemaVersion": wa_ir::SCHEMA_VERSION,
        "generatorVersion": env!("CARGO_PKG_VERSION"),
        "waVersion": wa_version,
        "iqModules": counts.iq_modules,
        "protoEntities": counts.proto_entities,
        "mexOperations": counts.mex_ops,
        "appstateActions": counts.appstate_actions,
        "abPropsConfigs": counts.abprops_configs,
        "enumDefs": counts.enum_defs,
        "wamEvents": counts.wam_events,
        "notifTypes": counts.notif_types,
        "stanzaDefs": counts.stanza_defs,
        "tokenSingleByte": counts.token_single_byte,
        "tokenDoubleByte": counts.token_double_byte,
        "domains": domains,
        "diagnostics": {
            "iq": {
                "candidateModules": iq_diag.candidate_modules,
                "stanzas": iq_diag.stanzas,
                "typedResponses": iq_diag.typed_responses,
                "degradedResponses": iq_diag.degraded_responses,
                "unparseable": iq_diag.unparseable,
                "dropsByReason": iq_diag.drops_by_reason,
                "crossModule": {
                    "requestsWithMixins": iq_diag.cross_module.requests_with_mixins,
                    "requestsEnriched": iq_diag.cross_module.requests_enriched,
                    "fieldsRecovered": iq_diag.cross_module.fields_recovered,
                },
            },
            "notif": {
                "types": counts.notif_types,
                "typedContent": counts.notif_typed_content,
                "degraded": counts.notif_types - counts.notif_typed_content,
                "stanzaTags": counts.notif_stanza_tags,
            },
        },
    });
    artifacts.push(Artifact {
        rel_path: PathBuf::from("manifest.json"),
        content: serde_json::to_string_pretty(&manifest)? + "\n",
    });

    Ok((artifacts, counts))
}

/// Per-domain count drops vs the committed `manifest.json`, as human-readable
/// `"key: prev → new"` lines. Covers the top-level domain counts AND the
/// stanza-level IQ coverage (`diagnostics.iq.{stanzas,typedResponses}`) so a
/// silent extraction regression that keeps every namespace alive but drops most
/// stanzas is caught. Empty when there's no prior manifest (first run), when it
/// can't be parsed, or when nothing shrank — only a strict decrease regresses.
fn check_floor(out: &Path, counts: &Counts) -> Result<Vec<String>> {
    let Ok(prior_raw) = fs::read_to_string(out.join("manifest.json")) else {
        return Ok(Vec::new());
    };
    let Ok(prior) = serde_json::from_str::<serde_json::Value>(&prior_raw) else {
        // A corrupt prior manifest shouldn't block a fresh, correct generation.
        eprintln!("regression guard: prior manifest.json is unparseable — skipping floor check");
        return Ok(Vec::new());
    };
    let checks = [
        ("iqModules", counts.iq_modules),
        ("protoEntities", counts.proto_entities),
        ("mexOperations", counts.mex_ops),
        ("appstateActions", counts.appstate_actions),
        ("abPropsConfigs", counts.abprops_configs),
        ("enumDefs", counts.enum_defs),
        ("wamEvents", counts.wam_events),
        ("notifTypes", counts.notif_types),
        ("stanzaDefs", counts.stanza_defs),
        ("tokenSingleByte", counts.token_single_byte),
        ("tokenDoubleByte", counts.token_double_byte),
    ];
    let mut regressions = Vec::new();
    for (key, new) in checks {
        if let Some(prev) = prior.get(key).and_then(serde_json::Value::as_u64)
            && (new as u64) < prev
        {
            regressions.push(format!("{key}: {prev} → {new}"));
        }
    }
    // Stanza-level IQ coverage — the sensitive signal the guard's doc promises:
    // every one of the N namespaces can still yield ≥1 stanza while most of the
    // module's stanzas silently vanish, which the `iqModules` count alone misses.
    if let Some(iq) = prior.get("diagnostics").and_then(|d| d.get("iq")) {
        for (key, new) in [
            ("stanzas", counts.iq_stanzas),
            ("typedResponses", counts.iq_typed_responses),
        ] {
            if let Some(prev) = iq.get(key).and_then(serde_json::Value::as_u64)
                && (new as u64) < prev
            {
                regressions.push(format!("iq.{key}: {prev} → {new}"));
            }
        }
    }
    // Notification coverage below the catalog count: a drop in typed-content means a
    // handler's parser stopped resolving; a drop in stanzaTags means the tag-switch
    // stopped being recognized — either can regress silently while notif types survive.
    if let Some(notif) = prior.get("diagnostics").and_then(|d| d.get("notif")) {
        for (key, new) in [
            ("typedContent", counts.notif_typed_content),
            ("stanzaTags", counts.notif_stanza_tags),
        ] {
            if let Some(prev) = notif.get(key).and_then(serde_json::Value::as_u64)
                && (new as u64) < prev
            {
                regressions.push(format!("notif.{key}: {prev} → {new}"));
            }
        }
    }
    Ok(regressions)
}

/// Compare in-memory artifacts against what's on disk; returns human-readable diffs.
fn check_artifacts(out: &Path, artifacts: &[Artifact]) -> Result<Vec<String>> {
    let mut diffs = Vec::new();
    for art in artifacts {
        let path = out.join(&art.rel_path);
        match fs::read_to_string(&path) {
            Ok(existing) if existing == art.content => {}
            Ok(_) => diffs.push(format!("{} (content differs)", art.rel_path.display())),
            Err(_) => diffs.push(format!("{} (missing)", art.rel_path.display())),
        }
    }
    Ok(diffs)
}

/// Emit the outgoing non-IQ stanza catalog (`stanza/index.json`). Neutral IR only —
/// no reference codegen yet (that's a later phase); the committed contract is the
/// `index.json`.
fn push_stanza(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_ir::StanzaIr {
        wa_version: wa_version.to_string(),
        stanzas: wa_scan::scan_stanzas_from_modules(source, module_defs),
    };
    let count = ir.stanzas.len();
    artifacts.push(Artifact {
        rel_path: PathBuf::from("stanza/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    Ok(count)
}

fn push_iq(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, IqDiagnostics)> {
    let (ir, cross_module) =
        wa_scan::extract_iq_from_modules_with_diagnostics(source, module_defs, wa_version);

    // M8/M9 diagnostics. Every IQ candidate module yields ≥1 stanza or exactly one
    // `unparseable` entry, so the candidate count is the number of distinct
    // producing modules plus the unparseable count — logged so a silent drop in
    // extraction (candidates ≫ stanzas) is visible.
    let producing: std::collections::BTreeSet<&str> =
        ir.stanzas.iter().map(|s| s.module_name.as_str()).collect();
    let candidates = producing.len() + ir.unparseable.len();
    // M5: a stanza whose response fell back to the `unknown` parser is degraded
    // (request known, response shape unrecovered); the rest are fully typed.
    let degraded = ir
        .stanzas
        .iter()
        .filter(|s| s.response.parser_name == "unknown")
        .count();
    // Benign cross-module mixin fragments (folded into real requests) are recorded as
    // drops to honor the no-silent-vanish invariant, but they aren't genuine failures —
    // break them out so the headline reflects the real unresolved count.
    let fragment_reason = wa_scan::DropReason::MixinFragment.as_str();
    let fragments = ir
        .unparseable
        .iter()
        .filter(|u| u.reason == fragment_reason)
        .count();
    let genuine_unparseable = ir.unparseable.len() - fragments;
    eprintln!(
        "iq: {candidates} candidate module(s) -> {} stanza(s) from {} module(s), \
         {genuine_unparseable} unparseable (+ {fragments} benign mixin fragments), \
         {} typed / {degraded} degraded response(s)",
        ir.stanzas.len(),
        producing.len(),
        ir.stanzas.len() - degraded,
    );
    if candidates == 0 {
        anyhow::bail!(
            "iq extractor matched 0 candidate modules — the bundle is empty or the IQ builder \
             pattern changed (no `.wap(\"iq\"`/`.smax(\"iq\"` with its gating dep). Inspect the \
             bundle or the is_iq_module filter."
        );
    }

    // Aggregate the per-module drop reasons for the manifest (deterministic order
    // via BTreeMap on the stable reason strings).
    let mut drops_by_reason: std::collections::BTreeMap<String, usize> = Default::default();
    for u in &ir.unparseable {
        *drops_by_reason.entry(u.reason.clone()).or_default() += 1;
    }
    eprintln!(
        "iq: cross-module fragments -> {} request(s) reference mixins, {} enriched, \
         {} field(s) recovered",
        cross_module.requests_with_mixins,
        cross_module.requests_enriched,
        cross_module.fields_recovered,
    );
    let diag = IqDiagnostics {
        candidate_modules: candidates,
        stanzas: ir.stanzas.len(),
        typed_responses: ir.stanzas.len() - degraded,
        degraded_responses: degraded,
        unparseable: ir.unparseable.len(),
        drops_by_reason,
        cross_module,
    };

    // Neutral, language-agnostic IR (the cross-language contract): the same
    // `index.json` shape mex/appstate already emit. Any consumer can codegen
    // from this; the Rust modules below are the reference consumer.
    artifacts.push(Artifact {
        rel_path: PathBuf::from("iq/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });

    // Single reference Rust file (one `pub mod` per namespace), like every other
    // domain. The `.rs` is a gitignored reference consumer; the committed contract
    // is `iq/index.json` above.
    artifacts.push(Artifact {
        rel_path: PathBuf::from("iq/iq.rs"),
        content: wa_codegen::generate_iq(&ir),
    });
    // Count distinct namespaces (the `pub mod`s) for the manifest/floor guard.
    let namespaces: std::collections::BTreeSet<&str> =
        ir.stanzas.iter().map(|s| s.namespace.as_str()).collect();
    Ok((namespaces.len(), diag))
}

fn push_proto(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let file = wa_proto::extract_proto_from_modules(source, module_defs, wa_version);
    let count = file.entities.len();
    eprintln!("proto: {count} entities");
    artifacts.push(Artifact {
        rel_path: PathBuf::from("proto/WAProto.proto"),
        content: wa_proto::stringify(&file),
    });
    Ok(count)
}

fn push_mex(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_mex::extract_mex_from_modules(source, module_defs, wa_version);
    let count = ir.operations.len();
    eprintln!("mex: {count} operations");
    artifacts.push(Artifact {
        rel_path: PathBuf::from("mex/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Typed, self-contained Rust for every operation (decoupled from the lib).
    artifacts.push(Artifact {
        rel_path: PathBuf::from("mex/operations.rs"),
        content: wa_codegen::generate_mex_operations(&ir),
    });
    Ok(count)
}

fn push_appstate(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_appstate::extract_appstate_from_modules(source, module_defs, wa_version);
    let count = ir.actions.len();
    eprintln!("appstate: {count} actions");
    artifacts.push(Artifact {
        rel_path: PathBuf::from("appstate/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Typed, self-contained Rust registry of the action schemas.
    artifacts.push(Artifact {
        rel_path: PathBuf::from("appstate/schemas.rs"),
        content: wa_codegen::generate_appstate_schemas(&ir),
    });
    Ok(count)
}

fn push_abprops(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_abprops::extract_abprops_from_modules(source, module_defs, wa_version);
    let count = ir.configs.len();
    eprintln!("abprops: {count} configs");
    artifacts.push(Artifact {
        rel_path: PathBuf::from("abprops/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Reference Rust registry (name → code/type/default table).
    artifacts.push(Artifact {
        rel_path: PathBuf::from("abprops/abprops.rs"),
        content: wa_codegen::generate_abprops(&ir),
    });
    Ok(count)
}

fn push_enums(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_enums::extract_enums_from_modules(source, module_defs, wa_version);
    let count = ir.enums.len();
    eprintln!("enums: {count} definitions");
    artifacts.push(Artifact {
        rel_path: PathBuf::from("enums/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Reference Rust catalog (per-module `(variant, value)` const tables).
    artifacts.push(Artifact {
        rel_path: PathBuf::from("enums/enums.rs"),
        content: wa_codegen::generate_enums(&ir),
    });
    Ok(count)
}

/// `(notification types, types with a recovered typed content shape)`.
fn push_notif(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, usize, usize)> {
    let ir = wa_notif::extract_notif_from_modules(source, module_defs, wa_version);
    let count = ir.notifications.len();
    let stanza_tags = ir.stanza_tags.len();
    let typed = ir
        .notifications
        .iter()
        .filter(|n| n.content.is_some())
        .count();
    eprintln!(
        "notif: {count} notification types ({typed} with typed content, {} degraded), \
         {} stanza tags (dispatchers: {})",
        count - typed,
        stanza_tags,
        if ir.dispatcher_modules.is_empty() {
            "<none>".to_string()
        } else {
            ir.dispatcher_modules.join(", ")
        }
    );
    artifacts.push(Artifact {
        rel_path: PathBuf::from("notif/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Reference Rust catalog (NotificationType/StanzaTag enums, handler table,
    // typed content structs).
    artifacts.push(Artifact {
        rel_path: PathBuf::from("notif/notif.rs"),
        content: wa_codegen::generate_notif(&ir),
    });
    Ok((count, typed, stanza_tags))
}

fn push_wam(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_wam::extract_wam_from_modules(source, module_defs, wa_version);
    let count = ir.events.len();
    eprintln!("wam: {count} events, {} enums", ir.enums.len());
    artifacts.push(Artifact {
        rel_path: PathBuf::from("wam/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Reference Rust catalog: typed event emitters + enums + a stable WAM codec.
    artifacts.push(Artifact {
        rel_path: PathBuf::from("wam/wam.rs"),
        content: wa_codegen::generate_wam(&ir),
    });
    Ok(count)
}

/// `(single-byte entries, total double-byte entries)` for the binary-token tables.
fn push_tokens(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, usize)> {
    let ir = wa_tokens::extract_tokens_from_modules(source, module_defs, wa_version);
    let single = ir.single_byte.len();
    let double: usize = ir.double_byte.iter().map(Vec::len).sum();
    eprintln!(
        "tokens: {single} single-byte, {double} double-byte across {} dictionaries (dict v{})",
        ir.double_byte.len(),
        ir.dict_version
    );
    // Neutral, language-agnostic IR (the cross-language contract).
    artifacts.push(Artifact {
        rel_path: PathBuf::from("tokens/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    // Reference consumer artifact: the `tokens.json` whatsapp-rust's build.rs reads
    // (canonical whatsmeow/Baileys layout), byte-compatible across libs.
    artifacts.push(Artifact {
        rel_path: PathBuf::from("tokens/tokens.json"),
        content: wa_codegen::generate_tokens_json(&ir),
    });
    Ok((single, double))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_flags() {
        let args: Vec<String> = [
            FLAG_OUT,
            "out",
            FLAG_BUNDLES,
            "b",
            FLAG_WA_VERSION,
            "2.3000.1",
            FLAG_SAVE_BUNDLES,
            "s",
            FLAG_CACHE,
            "c",
            FLAG_CHECK,
            FLAG_ALLOW_SHRINK,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = parse_update_args(&args).unwrap();
        assert_eq!(opts.out, PathBuf::from("out"));
        assert_eq!(opts.bundles_dir, Some(PathBuf::from("b")));
        assert_eq!(opts.wa_version.as_deref(), Some("2.3000.1"));
        assert_eq!(opts.save_bundles, Some(PathBuf::from("s")));
        assert_eq!(opts.cache_dir, Some(PathBuf::from("c")));
        assert!(opts.check);
        assert!(opts.allow_shrink);
    }

    #[test]
    fn defaults_when_no_flags() {
        let opts = parse_update_args(&[]).unwrap();
        assert_eq!(opts.out, PathBuf::from(DEFAULT_OUT));
        assert_eq!(opts.bundles_dir, None);
        assert!(!opts.check);
    }

    #[test]
    fn missing_flag_value_errors() {
        let args = vec![FLAG_OUT.to_string()];
        assert!(parse_update_args(&args).is_err());
    }

    #[test]
    fn unknown_flag_errors() {
        let args = vec!["--nope".to_string()];
        assert!(parse_update_args(&args).is_err());
    }

    #[test]
    fn name_set_extracts_and_diffs() {
        let dir = std::env::temp_dir().join(format!("whatspec-nameset-{}", std::process::id()));
        fs::create_dir_all(dir.join("iq")).unwrap();
        let idx = serde_json::json!({
            "schemaVersion": "1.0.0",
            "waVersion": "x",
            "stanzas": [
                {"namespace": "w:foo"},
                {"namespace": "w:bar"},
                {"namespace": "w:foo"}, // duplicate collapses in the set
            ],
        });
        fs::write(dir.join("iq/index.json"), idx.to_string()).unwrap();
        let set = name_set(&dir, "iq/index.json", "stanzas", "namespace").unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("w:foo") && set.contains("w:bar"));

        // Object shape (mex/appstate BTreeMaps serialize as objects keyed by name).
        fs::create_dir_all(dir.join("mex")).unwrap();
        let mex = serde_json::json!({ "operations": { "OpA": {}, "OpB": {} } });
        fs::write(dir.join("mex/index.json"), mex.to_string()).unwrap();
        let ops = name_set(&dir, "mex/index.json", "operations", "name").unwrap();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains("OpA") && ops.contains("OpB"));

        // Missing file → None (callers skip the section).
        assert!(name_set(&dir, "appstate/index.json", "actions", "name").is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn json_helpers_read_fields() {
        let v = serde_json::json!({ "waVersion": "2.3", "iqModules": 33 });
        assert_eq!(json_str(&v, "waVersion"), "2.3");
        assert_eq!(json_str(&v, "missing"), "—");
        assert_eq!(json_u64(&v, "iqModules"), Some(33));
        assert_eq!(json_u64(&v, "waVersion"), None);
    }

    #[test]
    fn check_floor_flags_only_decreases() {
        let dir = std::env::temp_dir().join(format!("whatspec-floor-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let prior = serde_json::json!({
            "iqModules": 100,
            "protoEntities": 50,
            "mexOperations": 200,
            "appstateActions": 10,
        });
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&prior).unwrap(),
        )
        .unwrap();

        // iq shrank, proto shrank; mex grew, appstate equal → only the two drops.
        // abprops/enums absent from the prior manifest → not floor-checked.
        let counts = Counts {
            iq_modules: 99,
            proto_entities: 40,
            mex_ops: 201,
            appstate_actions: 10,
            abprops_configs: 0,
            enum_defs: 0,
            wam_events: 0,
            notif_types: 0,
            notif_typed_content: 0,
            notif_stanza_tags: 0,
            iq_stanzas: 0,
            iq_typed_responses: 0,
            stanza_defs: 0,
            token_single_byte: 0,
            token_double_byte: 0,
        };
        let regressions = check_floor(&dir, &counts).unwrap();
        assert_eq!(regressions.len(), 2);
        assert!(regressions.iter().any(|r| r.contains("iqModules")));
        assert!(regressions.iter().any(|r| r.contains("protoEntities")));

        // No prior manifest → no regressions.
        fs::remove_file(dir.join("manifest.json")).unwrap();
        assert!(check_floor(&dir, &counts).unwrap().is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn check_floor_catches_stanza_drop_with_steady_namespace_count() {
        let dir = std::env::temp_dir().join(format!("whatspec-floor-iq-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let prior = serde_json::json!({
            "iqModules": 33,
            "diagnostics": { "iq": { "stanzas": 186, "typedResponses": 85 } },
        });
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&prior).unwrap(),
        )
        .unwrap();
        // Namespace count unchanged (33) but stanzas halved → must regress on the
        // stanza-level signal, the gap the floor guard previously missed.
        let counts = Counts {
            iq_modules: 33,
            iq_stanzas: 90,
            iq_typed_responses: 40,
            ..Default::default()
        };
        let regressions = check_floor(&dir, &counts).unwrap();
        assert!(regressions.iter().any(|r| r.contains("iq.stanzas")));
        assert!(regressions.iter().any(|r| r.contains("iq.typedResponses")));
        assert!(!regressions.iter().any(|r| r.contains("iqModules")));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn check_artifacts_detects_missing_and_diff() {
        let dir = std::env::temp_dir().join(format!("whatspec-check-{}", std::process::id()));
        fs::create_dir_all(dir.join("iq")).unwrap();
        fs::write(dir.join("a.txt"), "same").unwrap();
        fs::write(dir.join("b.txt"), "old").unwrap();
        let artifacts = vec![
            Artifact {
                rel_path: PathBuf::from("a.txt"),
                content: "same".into(),
            },
            Artifact {
                rel_path: PathBuf::from("b.txt"),
                content: "new".into(),
            },
            Artifact {
                rel_path: PathBuf::from("c.txt"),
                content: "x".into(),
            },
        ];
        let diffs = check_artifacts(&dir, &artifacts).unwrap();
        assert_eq!(diffs.len(), 2);
        assert!(
            diffs
                .iter()
                .any(|d| d.contains("b.txt") && d.contains("differs"))
        );
        assert!(
            diffs
                .iter()
                .any(|d| d.contains("c.txt") && d.contains("missing"))
        );
        fs::remove_dir_all(&dir).ok();
    }
}
