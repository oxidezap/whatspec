//! Optional WAM gap evidence tied to a verified bundle set.
use anyhow::{Context, Result, ensure};
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
    let defs = counted_definitions(&source)?;
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
            "start":gap.start,"end":gap.end,"eventModule":gap.event_module,"eventExport":gap.event_export,"reason":gap.reason,"field":gap.field,
            "constructionSha256":wa_text::sha256_hex(&module.as_bytes()[gap.start as usize..gap.end as usize])}));
    }
    let unlocated = unlocated_counts(&diag.drops_by_reason, &sites)?;
    sites.sort_by_key(|v| serde_json::to_string(v).unwrap());
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"qualityReportVersion":1,"waVersion":lock.wa_version,"setHash":lock.set_hash,"dropsByReason":diag.drops_by_reason,"unlocatedDropsByReason":unlocated,"wamGapSites":sites})
        )?
    );
    Ok(())
}

fn counted_definitions(source: &str) -> Result<Vec<wa_transform::ModuleDefinition>> {
    let mut defs = wa_transform::extract_module_definitions_checked(source)
        .map_err(|errors| anyhow::anyhow!("bundle set parse failed: {}", errors.join("; ")))?;
    // Match normal extraction's outer definitions: the WAM scanner already visits
    // nested bodies. Keep the full nested index separately for source lookup.
    let mut end = 0;
    defs.retain(|definition| {
        if definition.start < end {
            false
        } else {
            end = definition.end;
            true
        }
    });
    Ok(defs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_definitions_do_not_double_count_wam_gaps() {
        let source = r#"__d("Outer",["WAWebRawWamEvent"],function(){__d("Inner",["WAWebRawWamEvent"],function(){new(o("WAWebRawWamEvent")).RawWamEvent(unknown);});});"#;
        let normal = wa_transform::extract_module_definitions(source);
        let complete = wa_transform::extract_module_definitions_checked(source).unwrap();
        assert_eq!(complete.len(), 2);
        let counted = super::counted_definitions(source).unwrap();
        let (_, expected) = wa_wam::extract_wam_from_modules(source, &normal, "test");
        let (_, observed, gaps) = wa_wam::extract_wam_with_gap_sites(source, &counted, "test");
        assert_eq!(observed.drops_by_reason, expected.drops_by_reason);
        assert_eq!(gaps.len(), 2);
        assert_eq!(counted, normal);
    }
}

fn unlocated_counts(
    counts: &BTreeMap<String, usize>,
    sites: &[serde_json::Value],
) -> Result<BTreeMap<String, usize>> {
    let mut unlocated = counts.clone();
    for site in sites {
        let reason = site["reason"].as_str().context("gap site reason missing")?;
        let count = unlocated
            .get_mut(reason)
            .with_context(|| format!("uncounted gap site: {reason}"))?;
        ensure!(*count > 0, "more located sites than counted gaps: {reason}");
        *count -= 1;
    }
    unlocated.retain(|_, count| *count != 0);
    Ok(unlocated)
}

#[cfg(test)]
mod unlocated_tests {
    #[test]
    fn extracted_global_gap_is_not_presented_as_located() {
        let source = r#"__d("Globals",["WAWebWamCodegenUtils"],function(t,n,r,o,a,i,l){var e=o("WAWebWamCodegenUtils");l.Global=e.defineGlobal({computed:[3,e.TYPES.STRING,[CHANNEL]],empty:[4,e.TYPES.STRING,[]]});});"#;
        let defs = super::counted_definitions(source).unwrap();
        let (_, diag, sites) = wa_wam::extract_wam_with_gap_sites(source, &defs, "test");
        assert!(sites.is_empty());
        assert_eq!(
            diag.drops_by_reason["global with an unreadable channel list"],
            2
        );
        assert_eq!(
            super::unlocated_counts(&diag.drops_by_reason, &[]).unwrap(),
            diag.drops_by_reason
        );
    }

    #[test]
    fn overlocated_counts_are_rejected_instead_of_clamped() {
        let counts = std::collections::BTreeMap::from([("reason".to_string(), 1)]);
        let sites = vec![serde_json::json!({"reason":"reason"}); 2];
        assert!(super::unlocated_counts(&counts, &sites).is_err());
    }

    #[test]
    fn global_gaps_are_explicitly_unlocated() {
        let counts = std::collections::BTreeMap::from([
            ("global with an unreadable channel list".to_string(), 1),
            ("written key naming no field of the event".to_string(), 2),
        ]);
        let sites = vec![
            serde_json::json!({"reason":"written key naming no field of the event"}),
            serde_json::json!({"reason":"written key naming no field of the event"}),
        ];
        assert_eq!(
            super::unlocated_counts(&counts, &sites).unwrap(),
            std::collections::BTreeMap::from([(
                "global with an unreadable channel list".to_string(),
                1
            ),])
        );
    }
}
