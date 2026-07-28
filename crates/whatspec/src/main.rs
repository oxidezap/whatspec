//! `whatspec` CLI. The `update` command runs the full pipeline and writes
//! versioned artifacts (IQ specs, WAProto.proto, mex operations, appstate
//! schemas) to disk, ready to be committed — locally or from CI.

use std::collections::BTreeSet;
// Only the fetch path builds the bootloader pin map from it.
#[cfg(feature = "fetch")]
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

mod lock;
use lock::{BundleId, BundleLock, WasmLock, WasmLockEntry};

#[cfg(feature = "fetch")]
mod restore;

/// The committed bundle lockfile, written next to the domain artifacts.
const BUNDLE_LOCK_NAME: &str = "bundles.lock.json";
/// Every WebAssembly module starts with this header; a download that doesn't is an error
/// page, not a payload.
#[cfg(feature = "fetch")]
const WASM_MAGIC: &[u8] = b"\0asm";

/// The committed wasm lockfile — what a `--wasm` fetch resolved and stored. Separate
/// from [`BUNDLE_LOCK_NAME`] because wasm is not an input to `generated/`; see
/// [`lock::WasmLock`].
const WASM_LOCK_NAME: &str = "wasm.lock.json";

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
const FLAG_FROM_LOCK: &str = "--from-lock";
const FLAG_ARCHIVE: &str = "--archive";
const FLAG_REPO: &str = "--repo";
const FLAG_WASM: &str = "--wasm";
const FLAG_WASM_OUT: &str = "--wasm-out";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("update") => update(&args[1..]),
        Some("mex-ids") => mex_ids(&args[1..]),
        Some("diff") => diff(&args[1..]),
        Some("restore") => restore_cmd(&args[1..]),
        _ => {
            eprintln!("{}", usage());
            Ok(())
        }
    }
}

/// `whatspec restore` — rebuild a locked bundle set from the durable store and verify
/// it against `bundles.lock.json`, as either flat files or an `update --cache` cache.
#[cfg(feature = "fetch")]
fn parse_restore_args(args: &[String]) -> Result<restore::RestoreOptions> {
    let mut lock_path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut cache: Option<PathBuf> = None;
    let mut archive: Option<String> = None;
    let mut repo: Option<String> = None;
    let mut wasm = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            FLAG_FROM_LOCK => {
                lock_path = Some(PathBuf::from(arg_value(args, i, FLAG_FROM_LOCK)?));
                i += 2;
            }
            FLAG_OUT => {
                out = Some(PathBuf::from(arg_value(args, i, FLAG_OUT)?));
                i += 2;
            }
            FLAG_CACHE => {
                cache = Some(PathBuf::from(arg_value(args, i, FLAG_CACHE)?));
                i += 2;
            }
            FLAG_ARCHIVE => {
                archive = Some(arg_value(args, i, FLAG_ARCHIVE)?.to_string());
                i += 2;
            }
            FLAG_REPO => {
                repo = Some(arg_value(args, i, FLAG_REPO)?.to_string());
                i += 2;
            }
            FLAG_WASM => {
                wasm = true;
                i += 1;
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }
    let lock_path =
        lock_path.with_context(|| format!("restore requires {FLAG_FROM_LOCK} <path>"))?;
    let target = match (out, cache) {
        (Some(out), None) => restore::RestoreTarget::Bundles(out),
        (None, Some(cache)) => restore::RestoreTarget::Cache(cache),
        (None, None) => {
            anyhow::bail!("restore requires either {FLAG_OUT} <dir> or {FLAG_CACHE} <dir>")
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("restore accepts only one of {FLAG_OUT} <dir> or {FLAG_CACHE} <dir>")
        }
    };
    let mut opts = restore::RestoreOptions::new(lock_path, target);
    opts.wasm = wasm;
    opts.archive = archive;
    if let Some(repo) = repo {
        opts.repo = repo;
    }
    Ok(opts)
}

#[cfg(feature = "fetch")]
fn restore_cmd(args: &[String]) -> Result<()> {
    restore::restore(&parse_restore_args(args)?)
}

#[cfg(not(feature = "fetch"))]
fn restore_cmd(_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "`restore` pulls bundles over the network — this binary was built without the \
         `fetch` feature. Rebuild with it enabled."
    )
}

fn usage() -> String {
    format!(
        "whatspec — WhatsApp Web spec extractor\n\n\
         usage:\n  \
         whatspec update [{FLAG_OUT} <dir>] [{FLAG_BUNDLES} <dir>] [{FLAG_WA_VERSION} <ver>]\n                  \
         [{FLAG_SAVE_BUNDLES} <dir>] [{FLAG_CACHE} <dir>] [{FLAG_WASM}] [{FLAG_WASM_OUT} <dir>]\n                  \
         [{FLAG_CHECK}] [{FLAG_ALLOW_SHRINK}]\n\n\
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
         whatspec restore {FLAG_FROM_LOCK} <bundles.lock.json> ({FLAG_OUT} <dir> | {FLAG_CACHE} <dir>)\n                  \
         [{FLAG_WASM}] [{FLAG_ARCHIVE} <path|url>] [{FLAG_REPO} <owner/repo>]\n\n\
         Rebuilds the exact bundle set a `generated/` snapshot was built from — pulled from the\n\
         durable release store (or {FLAG_ARCHIVE}) and verified against the lock. {FLAG_OUT} writes\n\
         flat files for `update {FLAG_BUNDLES}`; {FLAG_CACHE} writes the reusable local-cache format.\n\n\
         flags:\n  \
         {FLAG_OUT} <dir>           output directory (default `{DEFAULT_OUT}`; restore: target dir)\n  \
         {FLAG_BUNDLES} <dir>       read local .js bundles instead of fetching\n  \
         {FLAG_WA_VERSION} <ver>    stamp this version instead of the discovered one\n  \
         {FLAG_SAVE_BUNDLES} <dir>  persist fetched bundles to <dir>\n  \
         {FLAG_CACHE} <dir>         update: reuse a complete version cache, else re-download;\n                             \
         restore: seed that cache directly from the verified release archive\n  \
         {FLAG_WASM}               update: also resolve/fetch/store the client wasm payloads;\n                             \
         restore: restore the wasm set from a wasm.lock.json\n  \
         {FLAG_WASM_OUT} <dir>      update: write fetched wasm here, named by URL hash (implies {FLAG_WASM})\n  \
         {FLAG_FILE} <path>         (mex-ids) the mex_ids.rs to refresh in place\n  \
         {FLAG_FROM_LOCK} <path>     (restore) the committed bundles.lock.json to restore\n  \
         {FLAG_ARCHIVE} <path|url>   (restore) explicit archive instead of the derived release URL\n  \
         {FLAG_REPO} <owner/repo>    (restore) repo hosting the bundle-store release\n  \
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
    /// Resolve, download and store the client's wasm payloads alongside the JS bundles.
    /// Off by default: it is ~40 MB of extra download that no `generated/` artifact
    /// depends on.
    #[cfg_attr(not(feature = "fetch"), allow(dead_code))]
    wasm: bool,
    /// Write the fetched wasm payloads into this directory, each named by its
    /// content-hashed URL segment (`COs9e0Kj0ic.wasm`) — the identity WhatsApp serves it
    /// under and the one a wasm runner keys on, *not* the `bx` handle that resolved it
    /// (the handle lives in `wasm.lock.json`, joined by `bxId`). Implies
    /// [`Options::wasm`].
    #[cfg_attr(not(feature = "fetch"), allow(dead_code))]
    wasm_out: Option<PathBuf>,
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
            FLAG_WASM => {
                opts.wasm = true;
                i += 1;
            }
            FLAG_WASM_OUT => {
                opts.wasm_out = Some(PathBuf::from(arg_value(args, i, FLAG_WASM_OUT)?));
                // Asking for the output is asking for the fetch.
                opts.wasm = true;
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
    // Wasm cannot be resolved from local bundles: the `bx` id → URL map is server state,
    // absent from the `.js` files. Refuse the combination rather than exit 0 having
    // silently produced no payloads (and no `--wasm-out` directory), which would let
    // automation believe collection succeeded.
    if opts.bundles_dir.is_some() && opts.wasm {
        anyhow::bail!(
            "{FLAG_WASM}/{FLAG_WASM_OUT} cannot be combined with {FLAG_BUNDLES}: wasm URLs \
             live in the live page's bootloader data, not in the .js bundles — drop \
             {FLAG_BUNDLES} to resolve them"
        );
    }
    Ok(opts)
}

fn update(args: &[String]) -> Result<()> {
    let opts = parse_update_args(args)?;

    let Loaded {
        wa_version,
        source,
        bundles,
        wasm,
        boot_pins,
        authoritative,
    } = load_source(&opts)?;
    eprintln!("WhatsApp version: {wa_version}");

    let (artifacts, counts) = build_artifacts(&wa_version, &source)?;

    if opts.check {
        let diffs = check_artifacts(&opts.out, &artifacts)?;
        if diffs.is_empty() {
            let checked = artifacts
                .iter()
                .filter(|a| !is_reference_only(&a.rel_path))
                .count();
            eprintln!("check: {checked} committed artifact(s) up to date");
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

    // Bundle lockfile: only the fetch path knows every bundle's origin URL, so it is
    // the sole authoritative writer. A local `--bundles` regen (e.g. from a restored
    // set) reproduces the same output but must not clobber the committed lock with a
    // URL-less one — its input fingerprint is still enforced by the determinism job,
    // which restores from this very lock and re-runs `--check`.
    if authoritative {
        let lock_path = opts.out.join(BUNDLE_LOCK_NAME);
        let lock = BundleLock::new(&wa_version, bundles);
        fs::write(&lock_path, lock.to_pretty_json())
            .with_context(|| format!("write {}", lock_path.display()))?;
        eprintln!(
            "wrote {} ({} bundles, setHash {})",
            lock_path.display(),
            lock.bundle_count,
            &lock.set_hash[..12]
        );
    }

    // The wasm lock is written only when this run actually resolved payloads. A plain
    // `update` (no `--wasm`) must leave a previously committed wasm lock alone rather
    // than truncate it to an empty set it never looked for.
    if authoritative && opts.wasm && wasm.is_empty() {
        let lock_path = opts.out.join(WASM_LOCK_NAME);
        warn_if_wasm_lock_is_now_stale(&lock_path, &wa_version);
        // A blocked or changed bootloader is EXACTLY the state the pins were added to
        // record, and it is also the state that yields no payloads — so dropping them
        // here would lose the diagnostic precisely when it matters. The recorded payload
        // set is preserved (that is what the emptiness guard protects); only the
        // bootloader section is rewritten.
        // Gated with the function it calls: without `fetch` there is no bootloader to
        // have asked, and `boot_pins` is always `None`. The call site was NOT gated when
        // the function was, so the no-default-features build stopped compiling — a
        // configuration `cargo test --workspace` never exercises.
        #[cfg(feature = "fetch")]
        if let Some(pins) = &boot_pins
            && let Err(e) = update_lock_bootloader(&lock_path, pins)
        {
            eprintln!("  wasm lock not updated with the bootloader map: {e:#}");
        }
    }
    if authoritative && !wasm.is_empty() {
        let lock_path = opts.out.join(WASM_LOCK_NAME);
        warn_if_wasm_shrank(&lock_path, &wasm);
        let lock = WasmLock::with_bootloader(&wa_version, wasm, boot_pins);
        fs::write(&lock_path, lock.to_pretty_json())
            .with_context(|| format!("write {}", lock_path.display()))?;
        eprintln!(
            "wrote {} ({} payloads, wasmSetHash {})",
            lock_path.display(),
            lock.wasm_count,
            &lock.wasm_set_hash[..12]
        );
    }

    eprintln!(
        "wrote artifacts to {}: {} iq modules, {} proto entities, {} mex ops, {} appstate actions, \
         {} abprops, {} enums, {} wam events, {} notif types, {} stanzas, {} incoming, {} srvreq, \
         {}+{} tokens, {} wasm binaries / {} wasm-evidenced of {} bx handles",
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
        counts.incoming_defs,
        counts.server_request_defs,
        counts.token_single_byte,
        counts.token_double_byte,
        counts.wasm_binaries,
        counts.wasm_wasm_handles,
        counts.wasm_resources
    );
    Ok(())
}

/// Warn when a requested wasm fetch came back empty and leaves behind a lock stamped with
/// a *different* version — the committed lock then describes payloads for an older tree.
///
/// The lock is not deleted: its archive is published and still restorable, and discarding a
/// valid pin because one run was unlucky would lose data. Both files carry their
/// `waVersion`, so the mismatch is visible rather than implied — but it must be said out
/// loud, since the run otherwise succeeds.
fn warn_if_wasm_lock_is_now_stale(lock_path: &Path, wa_version: &str) {
    let Ok(raw) = fs::read_to_string(lock_path) else {
        return;
    };
    let Ok(prior) = serde_json::from_str::<WasmLock>(&raw) else {
        return;
    };
    if prior.wa_version == wa_version {
        return;
    }
    eprintln!(
        "wasm lock: resolved nothing for {wa_version}, so {} still pins {} payload(s) for \
         {} — it no longer describes this tree (restoring it into this version's cache \
         will be refused). Re-run to refresh it.",
        lock_path.display(),
        prior.wasm_count,
        prior.wa_version
    );
}

/// Warn when this run resolved fewer payloads than the committed lock records.
///
/// Not a hard failure like the domain floor guard: the bootloader endpoint answers the
/// same request with varying subsets, so a smaller set is often server variance rather
/// than an upstream removal — and blocking a spec update on it would be wrong. But it must
/// never pass silently: the lock is about to be overwritten, and with it the set the
/// durable archive is published from.
fn warn_if_wasm_shrank(lock_path: &Path, resolved: &[WasmLockEntry]) {
    let Ok(raw) = fs::read_to_string(lock_path) else {
        return;
    };
    let Ok(prior) = serde_json::from_str::<WasmLock>(&raw) else {
        eprintln!(
            "wasm lock: prior {} is unparseable — overwriting",
            lock_path.display()
        );
        return;
    };
    if prior.wasm_count <= resolved.len() {
        return;
    }
    let now: BTreeSet<&str> = resolved.iter().map(|e| e.sha256.as_str()).collect();
    let dropped: Vec<&str> = prior
        .wasm
        .iter()
        .filter(|e| !now.contains(e.sha256.as_str()))
        .map(|e| e.file_name.as_str())
        .collect();
    eprintln!(
        "wasm lock: resolved {} payload(s), previously {} — {} no longer resolvable ({}). \
         Likely bootloader-endpoint variance; re-run to confirm before relying on the \
         published archive.",
        resolved.len(),
        prior.wasm_count,
        dropped.len(),
        dropped.join(", ")
    );
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
    let loaded = load_source(&opts)?;
    eprintln!("WhatsApp version: {}", loaded.wa_version);

    let ir = wa_mex::extract_mex(&loaded.source, &loaded.wa_version);
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
        "incomingDefs",
        "serverRequestDefs",
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
    for key in [
        "typedResponses",
        "degradedResponses",
        "unparseable",
        "excludedFragments",
    ] {
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
    /// Validation-constraint coverage, mirroring
    /// `manifest.diagnostics.iq.constraints` — see [`IqConstraintCounts`].
    iq_reference_constraints: usize,
    iq_field_literals: usize,
    iq_field_enum_refs: usize,
    iq_typed_error_variants: usize,
    iq_error_texts: usize,
    iq_error_arms: usize,
    /// Notification payload action-union arms recovered (`diagnostics.notif.actions`).
    notif_actions: usize,
    /// Shape-level coverage of those arms: resolved `actionType`s plus every field,
    /// constant and child field across them. The arm COUNT alone cannot regress while
    /// the child-tag switch is still recognized — each case still yields one arm even if
    /// its whole shape disappeared — so the layer could silently empty out inside a
    /// steady count. This is the number that actually moves when extraction breaks.
    notif_action_shapes: usize,
    /// Outgoing non-IQ stanzas (receipt/presence/chatstate/ack) the scanner recovers.
    stanza_defs: usize,
    /// Incoming content-stanza read-shapes (message/receipt/call/ack) recovered from
    /// their `WADeprecatedWapParser` bodies.
    incoming_defs: usize,
    /// Server-initiated request read-shapes (companion pairing / presence / client
    /// expiration / …) recovered from their `WASmaxIn*Request` parser modules.
    server_request_defs: usize,
    /// Binary-protocol token tables: single-byte entries (incl. the leading empty
    /// token) and the total across all double-byte dictionaries.
    token_single_byte: usize,
    token_double_byte: usize,
    wasm_binaries: usize,
    wasm_resources: usize,
    /// Handles carrying wasm evidence — the meaningful coverage number. The total
    /// `wasm_resources` counts every bootloader handle, most of which address images and
    /// churn with unrelated UI changes.
    wasm_wasm_handles: usize,
}

/// Extraction-quality signals for the IQ domain, emitted under `diagnostics.iq`
/// in the manifest so a consumer (or CI) can see coverage and drops at a glance.
#[derive(Debug, Default)]
struct IqDiagnostics {
    candidate_modules: usize,
    stanzas: usize,
    typed_responses: usize,
    degraded_responses: usize,
    /// Genuine parse failures only — modules that matched the IQ filter but produced no
    /// stanza for a real reason (unresolved namespace/type, no AST iq call). Excludes the
    /// benign mixin fragments, which are counted separately in `excluded_fragments` so this
    /// headline isn't inflated by intentional, folded-in fragments.
    unparseable: usize,
    /// Benign cross-module mixin fragments (folded into real requests, never standalone).
    /// Recorded so the no-silent-vanish invariant holds, but not a failure.
    excluded_fragments: usize,
    drops_by_reason: std::collections::BTreeMap<String, usize>,
    /// Cross-module (`mergeStanzas`, Phase 2) recovery counters: how many requests
    /// fold in mixin fragments, how many gain fields from them, and the total
    /// fields recovered. `requests_enriched`/`fields_recovered` going to 0 flags a
    /// regression in Phase-2 fragment merging.
    cross_module: wa_scan::CrossModuleStats,
    /// Validation-constraint coverage — see [`IqConstraintCounts`].
    constraints: IqConstraintCounts,
}

/// How many *validation constraints* the IQ IR carries, counted over the emitted
/// document. These are the numbers the floor guard watches for the constraint layer:
/// each one keys on a distinct JS construct, so a WA refactor that hides one fails
/// loudly instead of silently emptying a field that consumers depend on.
#[derive(Debug, Default, Clone, Copy)]
struct IqConstraintCounts {
    /// Echo rules — "this attribute must carry a value taken from the request" — in
    /// both forms: `reference` assertions (the required `from` == the request's `to`)
    /// and field-level `referencePath` pins (the optional ones).
    reference_constraints: usize,
    /// `ParsedField`s carrying a pinned `literalValue`.
    field_literals: usize,
    /// Response fields whose enum argument resolved to a real variant set.
    /// Response fields carrying a resolved wire-enum constraint, whether it arrived as a
    /// cross-module `enumRef` or an in-module `enumKeys` set.
    field_enum_refs: usize,
    /// Response variants classified as a client or server error.
    typed_error_variants: usize,
    /// Text-pinned error arms, keyed by `(module, variant, arm, text)`.
    ///
    /// NOT the count of distinct texts. A global set of strings cannot fall when one RPC
    /// loses its `bad-request` pin while another still carries it — and the arm survives
    /// too, so `errorArms` does not move either, and the floor passes while that RPC's
    /// accepted `(code, text)` pairing has silently degraded. Counting occurrences is what
    /// makes the guard able to see a per-RPC loss.
    error_texts: usize,
    /// Accepted `(code, text)` error shapes across every RPC — the paired form, which
    /// the flattened `errorTexts` count cannot regress on its own.
    error_arms: usize,
}

/// Count the validation constraints in an emitted IQ IR (see [`IqConstraintCounts`]).
fn iq_constraint_counts(ir: &wa_ir::IqIr) -> IqConstraintCounts {
    fn walk_fields(fields: &[wa_ir::ParsedField], c: &mut IqConstraintCounts) {
        for f in fields {
            if f.literal_value.is_some() {
                c.field_literals += 1;
            }
            if f.reference_path.is_some() {
                c.reference_constraints += 1;
            }
            // `enumKeys` is the SAME closed allowed-value constraint, just resolved
            // in-module instead of cross-module. Counting only `enumRef` meant losing an
            // `enumKeys` table left the floor unmoved — one such field is live today.
            if f.enum_ref.is_some() || f.enum_keys.as_ref().is_some_and(|k| !k.is_empty()) {
                c.field_enum_refs += 1;
            }
            if let Some(children) = &f.children {
                walk_fields(children, c);
            }
            for uv in f.union_variants.iter().flatten() {
                c.reference_constraints += count_references(&uv.assertions);
                walk_fields(&uv.fields, c);
            }
        }
    }
    fn count_references(assertions: &[wa_ir::ResponseAssertion]) -> usize {
        assertions
            .iter()
            .filter(|a| a.kind == wa_ir::AssertionKind::Reference)
            .count()
    }

    let mut c = IqConstraintCounts::default();
    let mut texts = std::collections::BTreeSet::new();
    for s in &ir.stanzas {
        c.reference_constraints += count_references(&s.response.assertions);
        // `response.fields` is a CLONE of the primary success variant's fields whenever
        // `variants` is non-empty (see `response_index::build_pass`), so walking both
        // would count that shape's constraints twice — and only for the 97 stanzas that
        // have variants, making the inflation non-uniform and the totals simply wrong.
        // Walk it directly only for the Pass-2 fallback shape, which has no variants.
        if s.response.variants.is_empty() {
            walk_fields(&s.response.fields, &mut c);
        }
        for v in &s.response.variants {
            c.reference_constraints += count_references(&v.assertions);
            if matches!(
                v.kind,
                wa_ir::ResponseVariantKind::ClientError | wa_ir::ResponseVariantKind::ServerError
            ) {
                c.typed_error_variants += 1;
            }
            // Keyed by the ARM this text pins, not by the text alone. A global set of
            // distinct strings cannot fall when one RPC loses its `bad-request` pin while
            // another still carries it — and the arm survives too, so `errorArms` does not
            // move either, and the floor passes while a specific RPC's accepted
            // `(code, text)` pairing silently degrades.
            texts.extend(
                v.error_arms
                    .iter()
                    .chain(v.error_envelope.as_ref())
                    .filter(|a| a.text.is_some())
                    .map(|a| {
                        format!(
                            "{}\u{1}{}\u{1}{}\u{1}{}",
                            s.module_name,
                            v.tag,
                            a.name.as_deref().unwrap_or_default(),
                            a.text.as_deref().unwrap_or_default()
                        )
                    }),
            );
            // Alternatives only. Folding the envelope in made the number disagree with
            // the artifact (646 reported against 645 present) and let an envelope
            // appearing offset an accepted shape disappearing in the floor check.
            c.error_arms += v.error_arms.len();
            walk_fields(&v.fields, &mut c);
        }
    }
    c.error_texts = texts.len();
    c
}

/// A loaded bundle set: the stamped version, the concatenated source the extractors
/// consume, and the per-bundle identities that fingerprint the inputs (for the lock).
struct Loaded {
    wa_version: String,
    source: String,
    bundles: Vec<BundleId>,
    /// Wasm payloads this run resolved and downloaded, empty unless `--wasm` was asked
    /// for on the fetch path. Never part of `source`: these are binaries, and the
    /// extractors parse `source` as JavaScript.
    wasm: Vec<WasmLockEntry>,
    /// What the bootloader yielded this run, when the fetch path ran — see
    /// [`lock::BootloaderPins`]. `None` for a local `--bundles` regen, which never
    /// asks the bootloader anything and must not clobber a recorded map with nothing.
    boot_pins: Option<lock::BootloaderPins>,
    /// `true` only for the fetch path, which knows every bundle's origin URL and is
    /// therefore the *authoritative* source of a full lockfile. The offline `--bundles`
    /// path fingerprints the same inputs (for `--check`) but never rewrites the lock,
    /// which would clobber the committed URLs it can't reconstruct.
    authoritative: bool,
}

/// Load the bundle set the `--wa-version` override always wins for; otherwise the
/// version comes from discovery (fetch mode) or defaults to `unknown` (local mode).
fn load_source(opts: &Options) -> Result<Loaded> {
    match &opts.bundles_dir {
        Some(dir) => {
            let (source, bundles) = read_local_bundles(dir)?;
            let wa_version = opts
                .wa_version
                .clone()
                .unwrap_or_else(|| UNKNOWN_VERSION.to_string());
            Ok(Loaded {
                wa_version,
                source,
                bundles,
                // The offline path has no network: wasm can't be resolved from a
                // directory of `.js` files, so it stays empty (and the committed wasm
                // lock is left untouched — see `authoritative`).
                wasm: Vec::new(),
                boot_pins: None,
                authoritative: false,
            })
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

/// Read every `.js` bundle in `dir`, returning the concatenated source and each
/// bundle's content identity (SHA-256 + size). Bytes are decoded with
/// [`String::from_utf8_lossy`] — matching the fetch path exactly, so the offline and
/// network routes concatenate identical source (and a non-UTF-8 bundle degrades the
/// same way instead of aborting only here).
fn read_local_bundles(dir: &Path) -> Result<(String, Vec<BundleId>)> {
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

    let mut source = String::new();
    let mut bundles = Vec::with_capacity(paths.len());
    for path in &paths {
        let bytes = fs::read(path).with_context(|| format!("read bundle {}", path.display()))?;
        bundles.push(BundleId {
            sha256: wa_text::sha256_hex(&bytes),
            size: bytes.len() as u64,
            url: None,
        });
        push_bundle(&mut source, &bytes);
    }
    eprintln!(
        "loaded {} local bundles from {}",
        paths.len(),
        dir.display()
    );
    Ok((source, bundles))
}

/// Content identity of each downloaded bundle, carrying its origin URL (the fetch
/// path is the only one that knows it) so the written lock records full provenance.
#[cfg(feature = "fetch")]
fn bundle_ids(bundles: &[wa_fetch::Bundle]) -> Vec<BundleId> {
    bundles
        .iter()
        .map(|b| BundleId {
            sha256: wa_text::sha256_hex(&b.bytes),
            size: b.bytes.len() as u64,
            url: Some(b.url.clone()),
        })
        .collect()
}

#[cfg(feature = "fetch")]
fn fetch_source(opts: &Options) -> Result<Loaded> {
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
                let (wasm, boot_pins) =
                    load_wasm(opts, &discovered, Some(remote_version.as_str()))?;
                return Ok(Loaded {
                    wa_version: version,
                    source: concat_bundles(&bundles),
                    bundles: bundle_ids(&bundles),
                    wasm,
                    boot_pins,
                    authoritative: true,
                });
            }
            wa_fetch::CacheStatus::Miss(reason) => {
                eprintln!("cache miss ({reason}) — downloading from scratch");
            }
        }
    } else if opts.cache_dir.is_some() {
        eprintln!("cache disabled: remote version is undetectable, cannot key the cache");
    }

    let outcome = wa_fetch::download_bundles(&discovered.js, &wa_fetch::DownloadOptions::default());
    // A partial download must not become authoritative: it would pin a lockfile and
    // publish a durable archive for an *incomplete* input set, silently dropping
    // whatever modules failed to fetch. Refuse it — the fetch is the sole writer of
    // the lock, and the run is retryable — rather than canonicalize a corrupt set.
    if !outcome.failures.is_empty() || outcome.bundles.len() != discovered.js.len() {
        anyhow::bail!(
            "incomplete download: {} of {} bundles present ({} failed) — refusing to build a \
             lockfile/spec from a partial set (transient network/anti-bot; retry).",
            outcome.bundles.len(),
            discovered.js.len(),
            outcome.failures.len()
        );
    }

    // A complete set: safe to cache for reuse by a later run of the same version.
    if let (Some(cache_dir), Some(remote_version)) = (&opts.cache_dir, &discovered.wa_version) {
        let cache = wa_fetch::BundleCache::new(cache_dir.clone());
        cache
            .store(remote_version, &outcome.bundles)
            .with_context(|| format!("write bundle cache at {}", cache_dir.display()))?;
        eprintln!(
            "cached {} bundles for {remote_version} at {}",
            outcome.bundles.len(),
            cache_dir.display()
        );
    }

    maybe_save_bundles(opts, &outcome.bundles)?;
    // Wasm is resolved after the JS set is complete and cached: it is auxiliary, so it
    // must never be able to cost the (expensive) JS download a retry.
    // The discovered version keys the cache; it does not gate the fetch. A run stamped
    // with `--wa-version` over an unreadable page still collects its payloads.
    let (wasm, boot_pins) = load_wasm(opts, &discovered, discovered.wa_version.as_deref())?;
    Ok(Loaded {
        wa_version: version,
        source: concat_bundles(&outcome.bundles),
        bundles: bundle_ids(&outcome.bundles),
        wasm,
        boot_pins,
        authoritative: true,
    })
}

/// Append one bundle's decoded bytes (+ the module separator) to `source`. Always
/// lossy — [`String::from_utf8_lossy`] borrows valid UTF-8 unchanged and only
/// allocates on invalid input — so the fetch and local bundle-loading paths
/// concatenate **byte-for-byte identically**. Both routes go through here so that
/// equivalence stays in one place and can't silently drift.
fn push_bundle(source: &mut String, bytes: &[u8]) {
    source.push_str(&String::from_utf8_lossy(bytes));
    source.push_str(BUNDLE_SEPARATOR);
}

/// Concatenate bundle bytes into one source string (lossy UTF-8), with the
/// module separator between bundles. Shared by the cache-hit and download paths.
#[cfg(feature = "fetch")]
fn concat_bundles(bundles: &[wa_fetch::Bundle]) -> String {
    let total: usize = bundles.iter().map(|b| b.bytes.len()).sum();
    let mut source = String::with_capacity(total + bundles.len() * BUNDLE_SEPARATOR.len());
    for bundle in bundles {
        push_bundle(&mut source, &bundle.bytes);
    }
    source
}

/// Resolve, fetch (or reuse from cache) and persist the client's wasm payloads.
///
/// A no-op unless `--wasm` was asked for. The payloads are auxiliary — no `generated/`
/// artifact depends on them — so **nothing here fails the run**: a dead bootloader
/// endpoint, a partial download or an unwritable cache degrades to fewer (or zero)
/// payloads with the reason on stderr, rather than aborting a spec update. Only
/// `--wasm-out`, an explicit user request for files on disk, is allowed to error.
///
/// # Why the cache never short-circuits resolution
///
/// The bootloader endpoint answers with varying subsets, so **no run can establish that
/// it saw the whole set** — not even one where nothing failed, since the resolver stops on
/// a round that merely added nothing new. Treating any live result as final would freeze
/// it: later runs would hit the cache and never ask again, so a payload that only appears
/// in some responses would be lost for that version forever.
///
/// So resolution runs every time (four small JSON requests), and the cache is a **byte
/// pool**: payloads already downloaded are reused instead of re-fetched, and the version's
/// set *accumulates* across runs rather than being replaced by the latest sample. That is
/// the honest model for a best-effort superset.
#[cfg(feature = "fetch")]
fn load_wasm(
    opts: &Options,
    discovered: &wa_fetch::Discovered,
    remote_version: Option<&str>,
) -> Result<(Vec<WasmLockEntry>, Option<lock::BootloaderPins>)> {
    if !opts.wasm {
        return Ok((Vec::new(), None));
    }

    // The cache is keyed by the *discovered* version. Without one it can't be used at all
    // — but resolution and download still can, so a `--wa-version`-stamped run with an
    // unreadable page still collects its payloads.
    let cache = opts
        .cache_dir
        .as_ref()
        .zip(remote_version)
        .map(|(dir, _)| wa_fetch::BundleCache::new(dir.clone()));
    if opts.cache_dir.is_some() && remote_version.is_none() {
        eprintln!("wasm cache disabled: remote version is undetectable, cannot key the cache");
    }

    let resolution = wa_fetch::resolve_wasm(discovered, &wa_fetch::WasmResolveOptions::default());
    // Pinned alongside the payloads: the id→URI map is the ONLY thing that turns the
    // numeric handle the JS asks for into something fetchable, and nothing recorded it.
    //
    // Built from the map ACCUMULATED for this version, not from this run's sample. The
    // endpoint answers the same request with different subsets, so pinning the latest
    // sample would let a later successful run DELETE ids a previous one resolved — while
    // their payloads stay in the set — and the supposedly diffable map would differ
    // between two runs of an unchanged release.
    let pin_from = |handles: &BTreeMap<String, String>| lock::BootloaderPins {
        handles_from_page: resolution.from_page,
        wasm_handles: handles
            .iter()
            .map(|(url, id)| (id.clone(), url.clone()))
            .collect(),
        requests: resolution.requests,
        failed_requests: resolution.failed_requests,
    };
    eprintln!(
        "resolved {} wasm payload(s): {} from the page, {} handle(s) after {} bootloader \
         round(s) ({} request(s))",
        resolution.urls.len(),
        resolution.from_page,
        resolution.by_id.len(),
        resolution.rounds,
        resolution.requests
    );
    for why in &resolution.failures {
        eprintln!("  wasm resolution: {why}");
    }

    // Bytes already paid for in an earlier run of this same version. Salvaged one by one:
    // a single corrupt file must not discard the rest, because the set that gets re-stored
    // below would then be permanently smaller.
    let mut cached: BTreeMap<String, wa_fetch::Bundle> = BTreeMap::new();
    if let Some((cache, version)) = cache.as_ref().zip(remote_version) {
        let (payloads, skipped) = cache.wasm_payloads(version);
        for why in &skipped {
            eprintln!("  wasm cache: {why}");
        }
        cached.extend(payloads.into_iter().map(|b| (b.url.clone(), b)));
    }

    let to_download: Vec<String> = resolution
        .urls
        .iter()
        .filter(|u| !cached.contains_key(*u))
        .cloned()
        .collect();
    let outcome = wa_fetch::download_bundles(
        &to_download,
        &wa_fetch::DownloadOptions {
            // Pinned for this path rather than inherited from the JS-tuned default. The
            // biggest payload observed is ~11 MB; the cap is a bound on a hostile or broken
            // response, and exceeding it is a hard download failure (never a truncated body
            // that would still carry a `\0asm` header past the check below).
            max_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    );
    for f in &outcome.failures {
        eprintln!("  wasm download failed: {} — {}", f.url, f.error);
    }

    // A 2xx anti-bot or error page is a "successful" download as far as the transport is
    // concerned. Hashing, locking and publishing one would propagate a body no runner can
    // instantiate, and restore would faithfully verify the corruption forever after. The
    // same check covers cached bytes: `wasm_payloads` proves they are the bytes recorded,
    // not that those bytes were ever a module (a lock-restored cache is hash-verified too).
    let mut discarded = 0usize;
    let mut keep = |b: &wa_fetch::Bundle| {
        let ok = b.bytes.starts_with(WASM_MAGIC);
        if !ok {
            discarded += 1;
            eprintln!(
                "  discarding {}: {} bytes that are not a wasm module (no \\0asm header)",
                b.url,
                b.bytes.len()
            );
        }
        ok
    };
    let downloaded: Vec<wa_fetch::Bundle> =
        outcome.bundles.into_iter().filter(|b| keep(b)).collect();
    let reused: Vec<wa_fetch::Bundle> = cached.into_values().filter(|b| keep(b)).collect();
    let (new_count, reused_count) = (downloaded.len(), reused.len());

    // The set for a version accumulates: a payload cached by an earlier run stays even if
    // this run's responses didn't mention it (the endpoint's subsets vary), and a newly
    // resolved one joins it. Fresh bytes win on a shared URL.
    let mut merged: BTreeMap<String, wa_fetch::Bundle> =
        reused.into_iter().map(|b| (b.url.clone(), b)).collect();
    merged.extend(downloaded.into_iter().map(|b| (b.url.clone(), b)));
    let payloads = with_lock_safe_file_names(merged.into_values().collect());

    eprintln!(
        "wasm set: {} payload(s), {:.1} MB ({new_count} newly downloaded, {reused_count} \
         reused from cache{})",
        payloads.len(),
        payloads.iter().map(|b| b.bytes.len()).sum::<usize>() as f64 / 1e6,
        if discarded > 0 {
            format!(", {discarded} discarded as non-wasm")
        } else {
            String::new()
        }
    );
    // Handles: what this run resolved, plus what the cache recorded for payloads it is
    // carrying over (their `bx` ids were learned in the run that downloaded them).
    // Built before the empty-payload exit so the pins describe the accumulated map even
    // when this particular run resolved nothing.
    let mut handles = invert(&discovered.bx_data);
    if let Some(cache) = &cache {
        handles.extend(cache.wasm_handles());
    }
    handles.extend(resolution.handle_by_url());
    let pins = pin_from(&handles);

    if payloads.is_empty() {
        // Still sweep: an explicit `--wasm-out` that produced nothing must not leave the
        // previous run's payloads behind, or a runner would consume a set no lock
        // describes. Not an error — a blocked resolution must not fail a spec update.
        maybe_save_wasm(opts, &payloads)?;
        return Ok((Vec::new(), Some(pins)));
    }

    // The wasm cache attaches to the JS cache for the same version; if that isn't there
    // (e.g. the JS came straight from a download with no `--cache`), skip caching rather
    // than fail — the payloads are already in hand for this run.
    if let Some((cache, version)) = cache.as_ref().zip(remote_version)
        && let Err(e) = cache.store_wasm(version, &payloads, &handles)
    {
        eprintln!("  wasm cache not updated: {e:#}");
    }

    let entries = wasm_entries(&payloads, &handles);
    maybe_save_wasm(opts, &payloads)?;
    Ok((entries, Some(pins)))
}

/// Give every payload a file name that is unique across the set and safe on disk, deriving
/// it from the URL rather than trusting the URL's last segment.
///
/// A payload's file name **is** its identity downstream: the lock records it, `--wasm-out`
/// writes it, `publish-wasm.sh` matches on it, the archive carries it and a runner selects
/// by it. WA serves content-hashed segments, so in practice the last segment is already
/// unique and short and is kept verbatim — but two URLs *could* share one, or carry a
/// segment past `NAME_MAX`, and then a writer would have to rename behind the lock's back.
///
/// Renaming here instead keeps all five in agreement **and** keeps the payload: the lock is
/// what defines the name, so a disambiguated one is just as valid. Dropping the payload
/// would publish an archive missing a module that could then never be restored.
///
/// Deterministic: names derive from the URL (not from a previous run's stored name), and
/// the input is URL-ordered, so the same set always produces the same names.
#[cfg(feature = "fetch")]
fn with_lock_safe_file_names(payloads: Vec<wa_fetch::Bundle>) -> Vec<wa_fetch::Bundle> {
    /// The bound `save_bundles` guards against, mirrored here because this path names the
    /// files itself. Leaves ample room for the disambiguating suffix.
    const MAX_NAME: usize = 128;

    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::with_capacity(payloads.len());
    for mut b in payloads {
        let preferred = wa_fetch::bundle_file_name(&b.url);
        let usable = !preferred.is_empty()
            && preferred.len() <= MAX_NAME
            && preferred.ends_with(".wasm")
            && Path::new(&preferred)
                .file_name()
                .is_some_and(|n| n == preferred.as_str());
        let digest = wa_text::sha256_hex(b.url.as_bytes());
        let base = if usable {
            preferred
        } else {
            // Unusable segment: a bounded, URL-derived name that is still a `.wasm` file.
            format!("{}.wasm", &digest[..16])
        };

        // Keep suffixing until the name is actually free. One pass is not enough: the
        // digest-suffixed fallback could itself equal a name already assigned, and two lock
        // entries sharing a file name is precisely what this function exists to prevent.
        // Terminates — each attempt adds a distinct counter — and is deterministic, since
        // the input is URL-ordered and every part derives from the URL.
        let mut name = base.clone();
        let mut attempt = 0u32;
        while taken.contains(&name) {
            attempt += 1;
            let stem = truncate_on_char_boundary(base.trim_end_matches(".wasm"), MAX_NAME - 32);
            name = format!("{stem}-{}-{attempt}.wasm", &digest[..8]);
        }
        if name != base {
            eprintln!(
                "  {} shares its file name with another payload — storing it as {name}",
                b.url
            );
        }
        taken.insert(name.clone());
        b.file_name = name;
        out.push(b);
    }
    out
}

/// Longest prefix of `s` that fits in `max_bytes` without splitting a character.
///
/// The input is a URL path segment, so it is *usually* ASCII — but slicing one that isn't
/// at a byte index would panic, and a payload name must never be able to crash a run.
#[cfg(feature = "fetch")]
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= max_bytes)
        .last()
        .unwrap_or(0);
    &s[..end]
}

/// `bx` id → URI inverted into URI → `bx` id, lowest id winning on a shared URI (the
/// input is sorted, so the choice is deterministic).
#[cfg(feature = "fetch")]
fn invert(by_id: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (id, uri) in by_id {
        out.entry(uri.clone()).or_insert_with(|| id.clone());
    }
    out
}

/// Pair each downloaded payload with the `bx` handle that resolved it (when one did),
/// producing the wasm lockfile's entries.
#[cfg(feature = "fetch")]
fn wasm_entries(
    payloads: &[wa_fetch::Bundle],
    handle_by_url: &BTreeMap<String, String>,
) -> Vec<WasmLockEntry> {
    payloads
        .iter()
        .map(|b| WasmLockEntry {
            bx_id: handle_by_url.get(&b.url).cloned(),
            file_name: b.file_name.clone(),
            url: b.url.clone(),
            sha256: wa_text::sha256_hex(&b.bytes),
            size: b.bytes.len() as u64,
        })
        .collect()
}

/// Honour `--wasm-out` if set (no-op otherwise). Files land under their content-hashed
/// URL segment (`COs9e0Kj0ic.wasm`) — the layout a wasm runner can be pointed straight
/// at. Deliberately not named by `bx` handle: the handle is provenance (recorded in the
/// lock), while the URL segment is the payload's published identity.
#[cfg(feature = "fetch")]
fn maybe_save_wasm(opts: &Options, payloads: &[wa_fetch::Bundle]) -> Result<()> {
    if let Some(dir) = &opts.wasm_out {
        // Sweep first, as the restore path does: a payload dropped from the set would
        // otherwise linger, so the directory would no longer be the lock's set — a runner
        // pointed at it could load an obsolete binary, and publishing aborts on the extra
        // name. Only `.wasm` is removed; anything else in the directory is not ours.
        let swept = sweep_wasm_dir(dir)?;
        // Written under exactly `Bundle::file_name`, which is what the lock records — not
        // through `save_bundles`, whose collision/length fallback renames on disk and would
        // leave the directory, the lock and the archive disagreeing about a payload's name.
        // `load_wasm` has already dropped anything whose name isn't unique and safe, so the
        // two can't diverge.
        for b in payloads {
            let path = dir.join(&b.file_name);
            fs::write(&path, &b.bytes).with_context(|| format!("write {}", path.display()))?;
        }
        eprintln!(
            "saved {} wasm payload(s) to {}{}",
            payloads.len(),
            dir.display(),
            if swept > 0 {
                format!(" ({swept} stale payload(s) removed)")
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

/// Remove every `.wasm` in `dir` (created if absent), returning how many were removed.
#[cfg(feature = "fetch")]
fn sweep_wasm_dir(dir: &Path) -> Result<usize> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut removed = 0;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
            fs::remove_file(&path).with_context(|| format!("remove stale {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
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

/// Join a domain extractor's scoped thread, turning a panic into a recoverable
/// diagnostic (naming the domain) instead of re-panicking the whole run. One broken
/// extractor then surfaces as a clear, named error — collected alongside the others by
/// the caller — so the run ends with one actionable message instead of unwinding the
/// whole scope on the first panic.
///
/// The panicking thread's own message (and a backtrace under `RUST_BACKTRACE`) still
/// prints to stderr via the default panic hook; that is deliberate — it points at where
/// the bug is — while the returned error drives the clean, aggregated exit. We don't
/// install a scoped panic hook to silence it: that's process-global state and the raw
/// stderr trace is worth keeping for the abnormal (real-bug) case this guards.
fn joined<T>(name: &str, handle: std::thread::ScopedJoinHandle<'_, Result<T>>) -> Result<T> {
    match handle.join() {
        Ok(result) => result.with_context(|| format!("{name} extraction")),
        Err(panic) => {
            // Recover the panic message (the common `&str`/`String` payloads) so the
            // diagnostic says *why*, not just *that*, the extractor panicked.
            let detail = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panicked".to_string());
            Err(anyhow::anyhow!("{name} extractor panicked: {detail}"))
        }
    }
}

/// Run every extractor + codegen and collect the resulting files in memory.
fn build_artifacts(wa_version: &str, source: &str) -> Result<(Vec<Artifact>, Counts)> {
    // Split the ~71MB concatenation into Metro modules exactly once; every
    // AST-based extractor re-parses only the slices it cares about.
    let module_defs = wa_transform::extract_module_definitions(source);

    // The four extractors are independent and read-only over the shared inputs,
    // so run them concurrently on plain scoped threads (no async runtime).
    // The extractors are independent and read-only over the shared inputs;
    // each returns `Result` so a failure surfaces with context instead of a
    // silent empty artifact or a bare panic.
    #[allow(clippy::type_complexity)]
    let (
        iq,
        proto,
        mex,
        appstate,
        abprops,
        enums,
        wam,
        notif,
        stanza,
        tokens,
        incoming,
        srvreq,
        wasm,
    ) = std::thread::scope(|s| {
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
        let incoming = s.spawn(|| -> Result<_> {
            let mut a = Vec::new();
            let c = push_incoming(&mut a, wa_version, source, &module_defs)?;
            Ok((a, c))
        });
        let srvreq = s.spawn(|| -> Result<_> {
            let mut a = Vec::new();
            let c = push_srvreq(&mut a, wa_version, source, &module_defs)?;
            Ok((a, c))
        });
        let wasm = s.spawn(|| -> Result<_> {
            let mut a = Vec::new();
            let c = push_wasm(&mut a, wa_version, source, &module_defs)?;
            Ok((a, c))
        });
        (
            joined("iq", iq),
            joined("proto", proto),
            joined("mex", mex),
            joined("appstate", appstate),
            joined("abprops", abprops),
            joined("enums", enums),
            joined("wam", wam),
            joined("notif", notif),
            joined("stanza", stanza),
            joined("tokens", tokens),
            joined("incoming", incoming),
            joined("srvreq", srvreq),
            joined("wasm", wasm),
        )
    });

    // Isolate per-domain failures: gather every extractor that errored or panicked so
    // one run reports all of them at once, then refuse to write a partial snapshot. A
    // panic in one domain no longer aborts the other eleven or crashes the process with
    // a raw backtrace — it degrades to a named diagnostic here.
    let failures: Vec<String> = [
        iq.as_ref().err(),
        proto.as_ref().err(),
        mex.as_ref().err(),
        appstate.as_ref().err(),
        abprops.as_ref().err(),
        enums.as_ref().err(),
        wam.as_ref().err(),
        notif.as_ref().err(),
        stanza.as_ref().err(),
        tokens.as_ref().err(),
        incoming.as_ref().err(),
        srvreq.as_ref().err(),
        wasm.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .map(|e| format!("{e:#}"))
    .collect();
    if !failures.is_empty() {
        anyhow::bail!(
            "{} domain extractor(s) failed — no artifacts written:\n  - {}",
            failures.len(),
            failures.join("\n  - ")
        );
    }

    // Every domain returned Ok (verified just above), so these unwraps can't fire.
    let checked = "domain result verified Ok above";
    let (iq_arts, (iq_count, iq_diag)) = iq.expect(checked);
    let (proto_arts, proto_count) = proto.expect(checked);
    let (mex_arts, mex_count) = mex.expect(checked);
    let (appstate_arts, appstate_count) = appstate.expect(checked);
    let (abprops_arts, abprops_count) = abprops.expect(checked);
    let (enums_arts, enums_count) = enums.expect(checked);
    let (wam_arts, wam_count) = wam.expect(checked);
    let (notif_arts, notif_counts) = notif.expect(checked);
    let NotifCounts {
        types: notif_count,
        typed_content: notif_typed,
        stanza_tags: notif_tags,
        actions: notif_actions,
        action_shapes: notif_action_shapes,
        drops: notif_drops,
    } = notif_counts;
    let (stanza_arts, stanza_count) = stanza.expect(checked);
    let (tokens_arts, (token_single, token_double)) = tokens.expect(checked);
    let (incoming_arts, (incoming_count, incoming_drops)) = incoming.expect(checked);
    let (srvreq_arts, srvreq_count) = srvreq.expect(checked);
    let (wasm_arts, (wasm_binaries, wasm_resources, wasm_wasm_handles)) = wasm.expect(checked);

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
        ("incoming defs", incoming_count),
        ("server request defs", srvreq_count),
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
    artifacts.extend(incoming_arts);
    artifacts.extend(srvreq_arts);
    artifacts.extend(wasm_arts);

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
        iq_reference_constraints: iq_diag.constraints.reference_constraints,
        iq_field_literals: iq_diag.constraints.field_literals,
        iq_field_enum_refs: iq_diag.constraints.field_enum_refs,
        iq_typed_error_variants: iq_diag.constraints.typed_error_variants,
        iq_error_texts: iq_diag.constraints.error_texts,
        iq_error_arms: iq_diag.constraints.error_arms,
        notif_actions,
        notif_action_shapes,
        stanza_defs: stanza_count,
        incoming_defs: incoming_count,
        server_request_defs: srvreq_count,
        token_single_byte: token_single,
        token_double_byte: token_double,
        wasm_binaries,
        wasm_resources,
        wasm_wasm_handles,
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
        (
            "incoming",
            "incoming/index.json",
            "schema/incoming.schema.json",
        ),
        ("srvreq", "srvreq/index.json", "schema/srvreq.schema.json"),
        ("wasm", "wasm/index.json", "schema/wasm.schema.json"),
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
        "incomingDefs": counts.incoming_defs,
        "serverRequestDefs": counts.server_request_defs,
        "tokenSingleByte": counts.token_single_byte,
        "tokenDoubleByte": counts.token_double_byte,
        "wasmBinaries": counts.wasm_binaries,
        "wasmResources": counts.wasm_resources,
        "wasmWasmHandles": counts.wasm_wasm_handles,
        "domains": domains,
        "diagnostics": {
            "iq": {
                "candidateModules": iq_diag.candidate_modules,
                "stanzas": iq_diag.stanzas,
                "typedResponses": iq_diag.typed_responses,
                "degradedResponses": iq_diag.degraded_responses,
                "unparseable": iq_diag.unparseable,
                "excludedFragments": iq_diag.excluded_fragments,
                "dropsByReason": iq_diag.drops_by_reason,
                "crossModule": {
                    "requestsWithMixins": iq_diag.cross_module.requests_with_mixins,
                    "requestsEnriched": iq_diag.cross_module.requests_enriched,
                    "fieldsRecovered": iq_diag.cross_module.fields_recovered,
                },
                "constraints": {
                    "referenceConstraints": iq_diag.constraints.reference_constraints,
                    "fieldLiterals": iq_diag.constraints.field_literals,
                    "fieldEnumRefs": iq_diag.constraints.field_enum_refs,
                    "typedErrorVariants": iq_diag.constraints.typed_error_variants,
                    "errorTexts": iq_diag.constraints.error_texts,
                    "errorArms": iq_diag.constraints.error_arms,
                },
            },
            "notif": {
                "types": counts.notif_types,
                "typedContent": counts.notif_typed_content,
                "degraded": counts.notif_types - counts.notif_typed_content,
                "stanzaTags": counts.notif_stanza_tags,
                "actions": counts.notif_actions,
                "actionShapes": counts.notif_action_shapes,
                "dropsByReason": notif_drops,
            },
            // These two domains run the same legacy parser as IQ and had no diagnostics
            // block at all, so a constraint they saw and could not recover was reported
            // nowhere — the one case the pending marker cannot distinguish on its own.
            "incoming": { "dropsByReason": incoming_drops },
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
        ("incomingDefs", counts.incoming_defs),
        ("wasmBinaries", counts.wasm_binaries),
        // Deliberately NOT `wasmResources`: it counts every bootloader handle, and most
        // address theme images/tones that come and go with UI work. Guarding it would
        // block an unrelated spec update behind `--allow-shrink`. The wasm-evidenced
        // subset is the number that actually regresses when extraction breaks.
        ("wasmWasmHandles", counts.wasm_wasm_handles),
        ("serverRequestDefs", counts.server_request_defs),
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
        // The validation-constraint layer. Each counter keys on a distinct JS construct
        // (`attrStringFromReference`, `literal`/`optionalLiteral`, the enum accessors,
        // the error mixins), so a WA refactor that hides one shows up here rather than
        // as a silently emptier field in every consumer's copy of the IR.
        if let Some(c) = iq.get("constraints") {
            for (key, new) in [
                ("referenceConstraints", counts.iq_reference_constraints),
                ("fieldLiterals", counts.iq_field_literals),
                ("fieldEnumRefs", counts.iq_field_enum_refs),
                ("typedErrorVariants", counts.iq_typed_error_variants),
                ("errorTexts", counts.iq_error_texts),
                ("errorArms", counts.iq_error_arms),
            ] {
                if let Some(prev) = c.get(key).and_then(serde_json::Value::as_u64)
                    && (new as u64) < prev
                {
                    regressions.push(format!("iq.constraints.{key}: {prev} → {new}"));
                }
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
            ("actions", counts.notif_actions),
            ("actionShapes", counts.notif_action_shapes),
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

/// A generated file that is *not* committed: the `.rs` reference consumers are gitignored
/// (`/generated/**/*.rs`) and regenerated on demand, so they sit outside the committed
/// reproducibility contract — the tracked IR (each `index.json` + `WAProto.proto`).
fn is_reference_only(rel_path: &Path) -> bool {
    rel_path.extension().and_then(|e| e.to_str()) == Some("rs")
}

/// Compare in-memory artifacts against what's on disk; returns human-readable diffs.
///
/// Only the **committed** artifacts are checked. The `.rs` reference consumers are
/// gitignored, so a fresh checkout (CI's determinism gate, a clean clone) has none on
/// disk — comparing them would report every one as "missing" and spuriously fail. They're
/// a deterministic function of the IR anyway, so verifying the IR reproduces is enough.
fn check_artifacts(out: &Path, artifacts: &[Artifact]) -> Result<Vec<String>> {
    let mut diffs = Vec::new();
    for art in artifacts {
        if is_reference_only(&art.rel_path) {
            continue;
        }
        let path = out.join(&art.rel_path);
        match fs::read_to_string(&path) {
            Ok(existing) if existing == art.content => {}
            Ok(_) => diffs.push(format!("{} (content differs)", art.rel_path.display())),
            Err(_) => diffs.push(format!("{} (missing)", art.rel_path.display())),
        }
    }
    Ok(diffs)
}

/// Emit the outgoing non-IQ stanza catalog (`stanza/index.json`) and its reference Rust
/// consumer (`stanza/stanza.rs`, gitignored like the other domains' `.rs`). The
/// committed contract is the `index.json`.
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
    artifacts.push(Artifact {
        rel_path: PathBuf::from("stanza/stanza.rs"),
        content: wa_codegen::generate_stanza(&ir),
    });
    Ok(count)
}

/// What the notification pass reports back: the counters the floor guard watches plus
/// the constraints it saw and could not resolve.
struct NotifCounts {
    types: usize,
    typed_content: usize,
    stanza_tags: usize,
    actions: usize,
    action_shapes: usize,
    drops: std::collections::BTreeMap<String, usize>,
}

/// Rewrite only the bootloader section of an existing wasm lock, leaving the payload set
/// it records untouched.
///
/// Used when a run resolved no payloads: the emptiness guard exists so an unproductive
/// run cannot truncate the committed set, but the bootloader outcome from that same run
/// is the diagnostic worth keeping. A missing or unreadable lock is left alone — there is
/// no payload set to preserve, and inventing one from an empty run is what the guard
/// forbids.
#[cfg(feature = "fetch")]
fn update_lock_bootloader(lock_path: &Path, pins: &lock::BootloaderPins) -> Result<()> {
    let raw = fs::read_to_string(lock_path)?;
    let mut lock: WasmLock = serde_json::from_str(&raw)?;
    if lock.bootloader.as_ref() == Some(pins) {
        return Ok(());
    }
    lock.bootloader = Some(pins.clone());
    fs::write(lock_path, lock.to_pretty_json())
        .with_context(|| format!("write {}", lock_path.display()))?;
    eprintln!(
        "updated {} bootloader map ({} wasm handle(s), {} request(s), {} failed)",
        lock_path.display(),
        pins.wasm_handles.len(),
        pins.requests,
        pins.failed_requests
    );
    Ok(())
}

/// Emit the incoming content-stanza read-shape catalog (`incoming/index.json`) — the
/// field trees WA Web parses out of received message/receipt/call/ack stanzas. Neutral
/// IR only; the codegen is a later phase.
fn push_incoming(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, std::collections::BTreeMap<String, usize>)> {
    let (incoming, drops) = wa_scan::scan_incoming_with_diagnostics(source, module_defs);
    let ir = wa_ir::IncomingIr {
        wa_version: wa_version.to_string(),
        incoming,
    };
    let count = ir.incoming.len();
    artifacts.push(Artifact {
        rel_path: PathBuf::from("incoming/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    Ok((count, drops))
}

/// Emit the server-initiated request read-shape catalog (`srvreq/index.json`) — the
/// field trees WA Web parses out of stanzas the server pushes (companion pairing,
/// presence server-update, client expiration, chatstate, newsletter delivery, …),
/// recovered from their `WASmaxIn*Request` smax parser modules. Neutral IR only.
fn push_srvreq(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<usize> {
    let ir = wa_ir::ServerRequestIr {
        wa_version: wa_version.to_string(),
        requests: wa_scan::scan_server_requests_from_modules(source, module_defs),
    };
    let count = ir.requests.len();
    artifacts.push(Artifact {
        rel_path: PathBuf::from("srvreq/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    Ok(count)
}

/// Emit the WebAssembly-surface catalog (`wasm/index.json`) — the emscripten payload
/// names the bundle ships glue for, and the bootloader (`bx`) handles it resolves their
/// bytes through, with the JS modules that consume each.
///
/// Purely static, so it reproduces offline like every other domain. The *resolved* URLs
/// and content hashes are network state and live in `wasm.lock.json` instead; the `bx` id
/// is the join key between the two.
fn push_wasm(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, usize, usize)> {
    let ir = wa_wasm::extract_wasm_from_modules(source, module_defs, wa_version);
    let counts = (
        ir.binaries.len(),
        ir.resources.len(),
        ir.resources
            .iter()
            .filter(|r| !r.wasm_hint.is_empty())
            .count(),
    );
    artifacts.push(Artifact {
        rel_path: PathBuf::from("wasm/index.json"),
        content: serde_json::to_string_pretty(&wa_ir::IrEnvelope::new(&ir))? + "\n",
    });
    Ok(counts)
}

fn push_iq(
    artifacts: &mut Vec<Artifact>,
    wa_version: &str,
    source: &str,
    module_defs: &[wa_transform::ModuleDefinition],
) -> Result<(usize, IqDiagnostics)> {
    let (ir, scan_stats) =
        wa_scan::extract_iq_from_modules_with_diagnostics(source, module_defs, wa_version);
    let cross_module = scan_stats.cross_module;

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
    // Constraints the response analysis saw but could not resolve structurally. Recorded
    // here rather than dropped silently: a consumer must be able to tell "this field has
    // no pinned value" from "this field has one and we failed to extract it".
    for (reason, n) in &scan_stats.constraint_drops {
        *drops_by_reason.entry(reason.clone()).or_default() += n;
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
        unparseable: genuine_unparseable,
        excluded_fragments: fragments,
        drops_by_reason,
        cross_module,
        constraints: iq_constraint_counts(&ir),
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
) -> Result<NotifCounts> {
    let (ir, notif_drops) =
        wa_notif::extract_notif_with_diagnostics(source, module_defs, wa_version);
    let count = ir.notifications.len();
    let stanza_tags = ir.stanza_tags.len();
    let typed = ir
        .notifications
        .iter()
        .filter(|n| n.content.is_some())
        .count();
    // Payload action-union arms (the `w:gp2` group actions and friends) — the layer
    // below the envelope, counted so it can't silently empty out.
    let actions: usize = ir.notifications.iter().map(|n| n.actions.len()).sum();
    let action_shapes: usize = ir
        .notifications
        .iter()
        .flat_map(|n| &n.actions)
        .map(|a| {
            usize::from(a.action_type.is_some())
                + a.fields.len()
                + a.constant_fields.len()
                + a.children.iter().map(|c| 1 + c.fields.len()).sum::<usize>()
        })
        .sum();
    eprintln!(
        "notif: {count} notification types ({typed} with typed content, {} degraded), \
         {actions} payload action(s) / {action_shapes} shape element(s), \
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
    Ok(NotifCounts {
        types: count,
        typed_content: typed,
        stanza_tags,
        actions,
        action_shapes,
        drops: notif_drops,
    })
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

    #[cfg(feature = "fetch")]
    #[test]
    fn restore_parses_cache_target_and_rejects_ambiguous_destinations() {
        let args: Vec<String> = [
            FLAG_FROM_LOCK,
            "generated/bundles.lock.json",
            FLAG_CACHE,
            ".wa-cache",
            FLAG_ARCHIVE,
            "bundle.tar.xz",
            FLAG_REPO,
            "owner/repo",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = parse_restore_args(&args).unwrap();
        assert_eq!(
            opts.target,
            restore::RestoreTarget::Cache(PathBuf::from(".wa-cache"))
        );
        assert_eq!(opts.lock_path, PathBuf::from("generated/bundles.lock.json"));
        assert_eq!(opts.archive.as_deref(), Some("bundle.tar.xz"));
        assert_eq!(opts.repo, "owner/repo");

        let both: Vec<String> = [
            FLAG_FROM_LOCK,
            "lock.json",
            FLAG_OUT,
            "bundles",
            FLAG_CACHE,
            "cache",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let err = parse_restore_args(&both).unwrap_err();
        assert!(err.to_string().contains("accepts only one"), "{err}");

        let neither: Vec<String> = [FLAG_FROM_LOCK, "lock.json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let err = parse_restore_args(&neither).unwrap_err();
        assert!(err.to_string().contains("requires either"), "{err}");
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn restore_keeps_flat_output_target_compatible() {
        let args: Vec<String> = [FLAG_FROM_LOCK, "lock.json", FLAG_OUT, "bundles"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = parse_restore_args(&args).unwrap();
        assert_eq!(
            opts.target,
            restore::RestoreTarget::Bundles(PathBuf::from("bundles"))
        );
    }

    #[test]
    fn iq_extraction_is_input_order_independent() {
        // The README's byte-identical-output guarantee: extraction is a pure function
        // of the module SET, not their order in the bundle. The iq domain is the most
        // order-sensitive (stanza ordering, dedup, the cross-module mixin/response
        // indices), so serialize its whole IR from two bundle orderings and require
        // byte-for-byte equality — an end-to-end guard against input-order-dependent
        // output. (The `byteLengthSource` first-wins tie-break that regressed once is
        // additionally pinned by a unit test in `content_length_index`.)
        let modules = [
            // Two same-namespace requests exercise the stanza sort tie-break
            // (namespace, then type, then exported fn, then module).
            r#"__d("WAWebReqA",["WAWap"],function(g,r,d,o,e,i){ e.a = function(){ return i.wap("iq", { xmlns: "w:a", type: "get" }); }; });"#,
            r#"__d("WAWebReqB",["WAWap"],function(g,r,d,o,e,i){ e.b = function(){ return i.wap("iq", { xmlns: "w:a", type: "set" }); }; });"#,
            // A legacy job whose typed response lives in a SIBLING parser module, linked
            // cross-module by the send-site parser index. This exercises the response-
            // enrichment path the two childless requests above do not: the job's `<iq>`
            // starts with an `unknown` parser and is only populated by resolving
            // `o("WAFooParser").fooParser` in the other module — so the enriched output
            // must be identical whether the job or its parser module is scanned first.
            r#"__d("WAWebQueryFooJob",["WAWap","WADeprecatedSendIq","WAFooParser"],function(g,r,d,o,e,i){ e.query = function(){ var m = o("WAWap").wap("iq", { xmlns: "w:foo", type: "get" }); return o("WADeprecatedSendIq").deprecatedSendIq(m, o("WAFooParser").fooParser); }; });"#,
            r#"__d("WAFooParser",["WADeprecatedWapParser"],function(g,r,d,o,e,i,l){ l.fooParser = new(r("WADeprecatedWapParser"))("fooParser", function(u){ u.assertTag("iq"); return { token: u.child("foo").attrString("token") }; }); },1);"#,
        ];
        let extract = |order: &[usize]| -> String {
            let src = order
                .iter()
                .map(|&i| modules[i])
                .collect::<Vec<_>>()
                .join("\n");
            let defs = wa_transform::extract_module_definitions(&src);
            let ir = wa_scan::extract_iq_from_modules(&src, &defs, "2.3000.test");
            serde_json::to_string_pretty(&ir).expect("serialize iq IR")
        };
        let forward = extract(&[0, 1, 2, 3]);
        assert_eq!(
            forward,
            extract(&[3, 2, 1, 0]),
            "iq extraction output depends on bundle module order"
        );
        // Guard that the cross-module enrichment actually ran (and thus that its
        // order-independence is genuinely under test) — the job's response is only
        // typed as `fooParser` if the send-site parser index resolved the sibling
        // module. Without this, the test could silently regress to exercising only
        // stanza ordering if the enrichment ever stopped matching.
        assert!(
            forward.contains("fooParser"),
            "determinism test did not exercise the cross-module response-enrichment path"
        );
    }

    #[test]
    fn joined_converts_a_thread_panic_into_a_named_diagnostic() {
        // A panicking extractor degrades to a recoverable, named error carrying the
        // panic message — not a re-panic that would crash the whole run. (The test
        // completing at all proves the panic was caught.)
        let result = std::thread::scope(|s| {
            let h = s.spawn(|| -> Result<()> { panic!("kaboom") });
            joined("widget", h)
        });
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("widget") && msg.contains("panicked") && msg.contains("kaboom"),
            "{msg}"
        );
    }

    #[test]
    fn joined_passes_through_ok_and_recoverable_errors() {
        std::thread::scope(|s| {
            let ok = s.spawn(|| -> Result<u32> { Ok(7) });
            assert_eq!(joined("d", ok).unwrap(), 7);
            let err = s.spawn(|| -> Result<u32> { anyhow::bail!("recoverable") });
            assert!(joined("d", err).is_err());
        });
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
            incoming_defs: 0,
            server_request_defs: 0,
            token_single_byte: 0,
            token_double_byte: 0,
            wasm_binaries: 0,
            wasm_resources: 0,
            wasm_wasm_handles: 0,
            ..Default::default()
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

    #[test]
    fn check_artifacts_skips_reference_only_rs() {
        // The gitignored `.rs` reference consumers are outside the committed contract, so
        // a fresh checkout has none on disk — check must skip them (not report "missing"),
        // while still catching a genuine drift in a committed (`.json`/`.proto`) artifact.
        let dir = std::env::temp_dir().join(format!("whatspec-check-rs-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("iq.json"), "same").unwrap(); // committed artifact, present + matching
        let artifacts = vec![
            Artifact {
                rel_path: PathBuf::from("iq.json"),
                content: "same".into(),
            },
            // Absent on disk AND different content — must be skipped, not flagged.
            Artifact {
                rel_path: PathBuf::from("iq/iq.rs"),
                content: "generated but not committed".into(),
            },
        ];
        let diffs = check_artifacts(&dir, &artifacts).unwrap();
        assert!(diffs.is_empty(), "reference-only .rs skipped: {diffs:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wasm_flags_are_rejected_with_local_bundles() {
        // Silently exiting 0 with no payloads (and no --wasm-out directory) would let
        // automation believe collection succeeded.
        for flags in [
            vec!["--bundles", "b", "--wasm"],
            vec!["--wasm-out", "w", "--bundles", "b"],
        ] {
            let args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
            let err = parse_update_args(&args).unwrap_err().to_string();
            assert!(err.contains("cannot be combined with --bundles"), "{err}");
        }
        // Either flag alone still parses.
        assert!(parse_update_args(&["--wasm".to_string()]).is_ok());
        assert!(parse_update_args(&["--bundles".to_string(), "b".to_string()]).is_ok());
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn wasm_out_sweeps_payloads_that_left_the_set() {
        let dir = std::env::temp_dir().join(format!("whatspec-wasm-out-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("gone.wasm"), b"old").unwrap();
        // Not ours: a neighbouring file of another kind must survive.
        fs::write(dir.join("notes.txt"), b"keep").unwrap();

        assert_eq!(sweep_wasm_dir(&dir).unwrap(), 1);
        assert!(!dir.join("gone.wasm").exists());
        assert!(dir.join("notes.txt").exists());
        // Creating a fresh directory is not an error and sweeps nothing.
        let fresh = dir.join("fresh");
        assert_eq!(sweep_wasm_dir(&fresh).unwrap(), 0);
        assert!(fresh.is_dir());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn colliding_or_overlong_payload_names_are_disambiguated_not_dropped() {
        let b = |url: &str| wa_fetch::Bundle {
            file_name: wa_fetch::bundle_file_name(url),
            url: url.to_string(),
            bytes: b"\0asm".to_vec(),
        };
        // Two CDN shards serving the same last segment, plus one segment past NAME_MAX.
        let long = format!("{}.wasm", "x".repeat(300));
        let payloads = vec![
            b("https://static.whatsapp.net/v4/ya/r/Same.wasm"),
            b("https://static.whatsapp.net/v4/yb/r/Same.wasm"),
            b(&format!("https://static.whatsapp.net/v4/yc/r/{long}")),
        ];
        let named = with_lock_safe_file_names(payloads.clone());

        assert_eq!(named.len(), 3, "no payload is dropped");
        let names: Vec<&str> = named.iter().map(|b| b.file_name.as_str()).collect();
        assert_eq!(names[0], "Same.wasm", "the first keeps the readable name");
        assert_ne!(names[1], names[0], "the second is disambiguated");
        assert!(names.iter().all(|n| n.ends_with(".wasm")));
        assert!(names.iter().all(|n| n.len() <= 128), "{names:?}");
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            3,
            "all distinct: {names:?}"
        );

        // Deriving from the URL (never from a stored name) keeps it reproducible.
        let again = with_lock_safe_file_names(payloads);
        assert_eq!(
            again
                .iter()
                .map(|b| b.file_name.clone())
                .collect::<Vec<_>>(),
            named
                .iter()
                .map(|b| b.file_name.clone())
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn ordinary_payload_names_are_left_alone() {
        // The real case: WA serves content-hashed segments, which must pass through
        // untouched so the lock keeps naming what the CDN does.
        let url = "https://static.whatsapp.net/rsrc.php/ye/r/COs9e0Kj0ic.wasm";
        let named = with_lock_safe_file_names(vec![wa_fetch::Bundle {
            url: url.to_string(),
            file_name: "COs9e0Kj0ic.wasm".to_string(),
            bytes: b"\0asm".to_vec(),
        }]);
        assert_eq!(named[0].file_name, "COs9e0Kj0ic.wasm");
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn a_fallback_name_that_is_itself_taken_keeps_disambiguating() {
        // The corner the single-pass version missed: the digest-suffixed fallback for one
        // payload happens to be another payload's preferred name. Two lock entries sharing
        // a file name is exactly what this function exists to prevent.
        let url_a = "https://static.whatsapp.net/v4/ya/r/Same.wasm";
        let url_b = "https://static.whatsapp.net/v4/yb/r/Same.wasm";
        let digest_b = &wa_text::sha256_hex(url_b.as_bytes())[..8];
        // A third payload whose *preferred* name is the fallback b would be given.
        let squatter = format!("https://static.whatsapp.net/v4/yc/r/Same-{digest_b}-1.wasm");

        let b = |url: &str| wa_fetch::Bundle {
            file_name: wa_fetch::bundle_file_name(url),
            url: url.to_string(),
            bytes: b"\0asm".to_vec(),
        };
        let named = with_lock_safe_file_names(vec![b(url_a), b(&squatter), b(url_b)]);

        let names: Vec<&str> = named.iter().map(|b| b.file_name.as_str()).collect();
        assert_eq!(names.len(), 3);
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            3,
            "all distinct even when the fallback was taken: {names:?}"
        );
        assert!(names.iter().all(|n| n.ends_with(".wasm") && n.len() <= 128));
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // A non-ASCII segment must not panic the run.
        assert_eq!(truncate_on_char_boundary("abcdef", 3), "abc");
        assert_eq!(truncate_on_char_boundary("abc", 10), "abc");
        let multi = "áéíóú";
        let cut = truncate_on_char_boundary(multi, 3);
        assert!(multi.starts_with(cut));
        assert!(cut.len() <= 3, "{cut:?}");
    }
}
