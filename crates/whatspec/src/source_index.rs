//! Optional provenance sidecar. Never executes vendor code or changes the IR.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use wa_store::lock::{BundleId, BundleLock};

fn modules(source: &str, hash: &str, selected: &BTreeSet<&str>) -> Vec<(String, Value)> {
    wa_transform::extract_module_definitions(source).into_iter()
        .filter(|m| selected.is_empty() || selected.contains(m.name.as_str()))
        .map(|m| {
            let value = json!({"bundleSha256": hash, "start": m.start, "end": m.end,
                "moduleSha256": wa_text::sha256_hex(&source.as_bytes()[m.start..m.end]),
                "factorySha256": wa_text::sha256_hex(&source.as_bytes()[m.factory_start..m.factory_end]),
                "dependencies": m.deps});
            (m.name, value)
        }).collect()
}

pub fn index(lock_path: &Path, bundles: &Path, selected: &BTreeSet<&str>) -> Result<Value> {
    let lock: BundleLock = serde_json::from_slice(&std::fs::read(lock_path)?)?;
    lock.verify_self_consistent().map_err(anyhow::Error::msg)?;
    let mut files = std::fs::read_dir(bundles)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.retain(|p| p.extension().is_some_and(|s| s == "js"));
    files.sort();
    let mut identities = Vec::new();
    let mut definitions: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for path in files {
        let bytes = std::fs::read(&path)?;
        let hash = wa_text::sha256_hex(&bytes);
        let source = std::str::from_utf8(&bytes)
            .with_context(|| format!("{}: byte spans require valid UTF-8", path.display()))?;
        identities.push(BundleId {
            sha256: hash.clone(),
            size: bytes.len() as u64,
            url: None,
        });
        for (name, definition) in modules(source, &hash, selected) {
            definitions.entry(name).or_default().push(definition);
        }
    }
    let observed = BundleLock::new(&lock.wa_version, identities);
    ensure!(
        observed.set_hash == lock.set_hash && observed.bundle_count == lock.bundle_count,
        "bundle multiset differs from lock; source index not emitted"
    );
    for definitions in definitions.values_mut() {
        definitions.sort_by_key(|d| {
            (
                d["bundleSha256"].as_str().unwrap().to_owned(),
                d["start"].as_u64().unwrap(),
            )
        });
    }
    Ok(
        json!({"sourceIndexVersion":1,"waVersion":lock.wa_version,"setHash":lock.set_hash,
        "bundleCount":lock.bundle_count,"modules":definitions,
        "coverage":"recovered-definitions-only",
        "limits":["Offsets are UTF-8 byte offsets, end exclusive, in the bundle identified by SHA-256.",
            "The existing AST extractor does not expose parse diagnostics. Absence from this index is not proof of absence upstream.",
            "All recovered occurrences are retained. Equal module names with different hashes need review.",
            "Module provenance locates code; field-level semantics may require following dependencies."]}),
    )
}

pub fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() >= 2,
        "usage: whatspec source-index <lock> <bundle-dir> [module ...]"
    );
    let selected = args[2..].iter().map(String::as_str).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&index(Path::new(&args[0]), Path::new(&args[1]), &selected)?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_index_refuses_missing_or_tampered_bundle_sets() {
        let dir =
            std::env::temp_dir().join(format!("whatspec-source-index-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = b"__d(\"Real\",[],function(){});";
        let lock = BundleLock::new(
            "test",
            vec![BundleId {
                sha256: wa_text::sha256_hex(bytes),
                size: bytes.len() as u64,
                url: None,
            }],
        );
        let lock_path = dir.join("lock.json");
        std::fs::write(&lock_path, lock.to_pretty_json()).unwrap();
        assert!(index(&lock_path, &dir, &BTreeSet::new()).is_err());
        std::fs::write(dir.join("one.js"), bytes).unwrap();
        assert!(index(&lock_path, &dir, &BTreeSet::new()).is_ok());
        std::fs::write(dir.join("duplicate.js"), bytes).unwrap();
        assert!(index(&lock_path, &dir, &BTreeSet::new()).is_err());
        std::fs::remove_file(dir.join("duplicate.js")).unwrap();
        std::fs::write(dir.join("one.js"), b"tampered").unwrap();
        assert!(index(&lock_path, &dir, &BTreeSet::new()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ast_locations_ignore_strings_and_keep_duplicate_definitions() {
        let source = "// á UTF-8 prefix\nvar text = '__d(\"Fake\",[],function(){})'; __d(\"Real\",[\"Dep\"],function(){return 1;}); __d(\"Real\",[],function(){return 2;});";
        let result = modules(source, "bundle-hash", &BTreeSet::new());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "Real");
        let start = result[0].1["start"].as_u64().unwrap() as usize;
        let end = result[0].1["end"].as_u64().unwrap() as usize;
        assert_eq!(
            &source[start..end],
            "__d(\"Real\",[\"Dep\"],function(){return 1;})"
        );
        assert_ne!(result[0].1["factorySha256"], result[1].1["factorySha256"]);
    }
}
