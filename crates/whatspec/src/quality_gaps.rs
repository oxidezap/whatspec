//! Optional WAM gap evidence tied to a verified bundle set.
use anyhow::{Result, ensure};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wa_store::lock::BundleLock;

pub fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 2,
        "usage: whatspec quality-gaps <lock> <bundle-dir>"
    );
    let lock: BundleLock = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    lock.verify_self_consistent().map_err(anyhow::Error::msg)?;
    // Verifies UTF-8 and parses every locked bundle without recovery before using byte spans.
    let index =
        super::source_index::index(Path::new(&args[0]), Path::new(&args[1]), &BTreeSet::new())?;
    let (source, identities) = super::read_local_bundles(Path::new(&args[1]))?;
    let observed = BundleLock::new(&lock.wa_version, identities);
    ensure!(
        observed.set_hash == lock.set_hash && observed.bundle_count == lock.bundle_count,
        "bundle set differs from lock"
    );
    let defs = wa_transform::extract_module_definitions_checked(&source)
        .map_err(|errors| anyhow::anyhow!("bundle set parse failed: {}", errors.join("; ")))?;
    let by_start: BTreeMap<_, _> = defs.iter().map(|d| (d.start, d)).collect();
    let (_, diag, gaps) = wa_wam::extract_wam_with_gap_sites(&source, &defs, &lock.wa_version);
    let mut sites = Vec::new();
    for gap in gaps {
        let definition = by_start[&gap.module_start];
        let module = &source[definition.start..definition.end];
        let module_hash = wa_text::sha256_hex(module.as_bytes());
        let sources: Vec<_> = index["modules"][&gap.module]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["moduleSha256"] == module_hash)
            .map(|v| json!({"bundleSha256":v["bundleSha256"],"start":v["start"],"end":v["end"]}))
            .collect();
        ensure!(
            !sources.is_empty(),
            "construction module is absent from verified source index"
        );
        sites.push(json!({"sources":sources,"module":gap.module,"moduleSha256":wa_text::sha256_hex(module.as_bytes()),
            "start":gap.start,"end":gap.end,"eventModule":gap.event_module,"eventExport":gap.event_export,"reason":gap.reason,
            "constructionSha256":wa_text::sha256_hex(&module.as_bytes()[gap.start as usize..gap.end as usize])}));
    }
    sites.sort_by_key(|v| serde_json::to_string(v).unwrap());
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"qualityReportVersion":1,"waVersion":lock.wa_version,"setHash":lock.set_hash,"dropsByReason":diag.drops_by_reason,"wamGapSites":sites})
        )?
    );
    Ok(())
}
