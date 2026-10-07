//! Reviewable contract deltas. Neither a smaller catalog nor matching shapes prove
//! a rename, extraction improvement, or an upstream protocol removal.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

const FORMAT_VERSION: u32 = 1;

fn pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn local_file(root: &Path, rel: &str) -> Result<Vec<u8>> {
    ensure!(
        !rel.is_empty()
            && Path::new(rel)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "invalid snapshot-relative path: {rel}"
    );
    std::fs::read(root.join(rel)).with_context(|| format!("read {rel}"))
}

struct Snapshot {
    manifest: Value,
    lock: wa_store::lock::BundleLock,
    files: BTreeMap<String, (String, String, Value)>,
    schemas: BTreeMap<String, (String, String, Value)>,
}

impl Snapshot {
    fn read(root: &Path) -> Result<Self> {
        let manifest = super::read_json(&root.join("manifest.json"))?;
        let lock: wa_store::lock::BundleLock =
            serde_json::from_slice(&local_file(root, "bundles.lock.json")?)?;
        lock.verify_self_consistent().map_err(anyhow::Error::msg)?;
        ensure!(
            manifest["waVersion"].as_str() == Some(&lock.wa_version),
            "manifest/lock waVersion mismatch"
        );
        let domains = manifest["domains"]
            .as_object()
            .context("manifest.domains missing")?;
        ensure!(!domains.is_empty(), "manifest.domains empty");
        let mut files = BTreeMap::new();
        let mut schemas = BTreeMap::new();
        for (domain, entry) in domains {
            let rel = entry["file"].as_str().context("domain file missing")?;
            let bytes = local_file(root, rel)?;
            let hash = wa_text::sha256_hex(&bytes);
            ensure!(
                entry["sha256"].as_str() == Some(&hash),
                "{rel}: manifest hash mismatch"
            );
            let value = if rel.ends_with(".json") {
                let value: Value =
                    serde_json::from_slice(&bytes).with_context(|| format!("parse {rel}"))?;
                ensure!(
                    value["waVersion"] == manifest["waVersion"],
                    "{rel}: waVersion mismatch"
                );
                ensure!(
                    value["schemaVersion"] == manifest["schemaVersion"],
                    "{rel}: schemaVersion mismatch"
                );
                value
            } else {
                // Protobuf is reported as an opaque artifact, never a parsed contract.
                json!({"artifactSha256": hash})
            };
            files.insert(domain.clone(), (rel.to_string(), hash, value));
            if let Some(schema) = entry.get("schema") {
                let rel = schema
                    .as_str()
                    .context("declared schema path is not a string")?;
                let bytes = local_file(root, rel)?;
                let value: Value =
                    serde_json::from_slice(&bytes).with_context(|| format!("parse {rel}"))?;
                schemas.insert(
                    domain.clone(),
                    (rel.to_string(), wa_text::sha256_hex(&bytes), value),
                );
            }
        }
        Ok(Self {
            manifest,
            lock,
            files,
            schemas,
        })
    }

    fn metadata(&self) -> Value {
        json!({"waVersion": self.manifest["waVersion"], "schemaVersion": self.manifest["schemaVersion"],
            "generatorVersion": self.manifest["generatorVersion"], "setHash": self.lock.set_hash,
            "bundleCount": self.lock.bundle_count})
    }
}

/// Only explicit collection identities. All other arrays retain order and
/// multiplicity. In particular, parser variant order is part of the contract.
fn identity_keys(domain: &str, collection: &str) -> Option<&'static [&'static str]> {
    match (domain, collection) {
        ("enums", "enums") | ("wam", "enums") => Some(&["module", "name"]),
        ("abprops", "configs") => Some(&["module", "name"]),
        ("iq", "stanzas") | ("stanza", "stanzas") => Some(&["moduleName", "exportedFunction"]),
        ("incoming", "incoming") => Some(&["module", "tag"]),
        ("srvreq", "requests") => Some(&["module", "tag"]),
        ("notif", "notifications") => Some(&["type"]),
        ("notif", "stanzaTags") => Some(&["tag"]),
        ("wam", "events") => Some(&["module", "name"]),
        ("wam", "globals") | ("wam", "constants") => Some(&["name"]),
        ("wam", "privateStatsIds") => Some(&["key"]),
        ("wasm", "binaries") => Some(&["name"]),
        ("wasm", "resources") => Some(&["bxId"]),
        _ => None,
    }
}

type KeyedItems<'a> = BTreeMap<String, Vec<(usize, &'a Value)>>;

fn keyed<'a>(value: &'a Value, keys: &[&str]) -> Option<KeyedItems<'a>> {
    let mut map: KeyedItems<'a> = BTreeMap::new();
    for (index, item) in value.as_array()?.iter().enumerate() {
        let identity: Vec<&Value> = keys
            .iter()
            .map(|key| item.get(*key))
            .collect::<Option<_>>()?;
        let identity = serde_json::to_string(&identity).ok()?;
        map.entry(identity).or_default().push((index, item));
    }
    Some(map)
}

fn walk(
    old: Option<&Value>,
    new: Option<&Value>,
    old_path: &str,
    new_path: &str,
    changes: &mut Vec<Value>,
) {
    if old == new {
        return;
    }
    if let (Some(Value::Object(a)), Some(Value::Object(b))) = (old, new) {
        for key in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
            walk(
                a.get(key),
                b.get(key),
                &format!("{old_path}/{}", pointer(key)),
                &format!("{new_path}/{}", pointer(key)),
                changes,
            );
        }
    } else if let (Some(Value::Array(a)), Some(Value::Array(b))) = (old, new) {
        // Preserve an array as one change: a deletion must not be misrepresented
        // as a series of field edits on every later element.
        changes.push(json!({"oldPath": old_path, "newPath": new_path, "kind": "ordered-array-changed", "before": a, "after": b}));
    } else {
        changes.push(json!({"oldPath": old.map(|_| old_path), "newPath": new.map(|_| new_path),
            "kind": if old.is_none() { "added" } else if new.is_none() { "removed" } else { "changed" },
            "before": old, "after": new}));
    }
}

fn document_diff(domain: &str, old: &Value, new: &Value) -> Vec<Value> {
    let mut changes = Vec::new();
    let (Some(a), Some(b)) = (old.as_object(), new.as_object()) else {
        walk(Some(old), Some(new), "", "", &mut changes);
        return changes;
    };
    for collection in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
        if matches!(collection.as_str(), "schemaVersion" | "waVersion") {
            continue;
        }
        let path = format!("/{}", pointer(collection));
        let pair = identity_keys(domain, collection).and_then(|keys| {
            Some((
                keyed(a.get(collection)?, keys)?,
                keyed(b.get(collection)?, keys)?,
            ))
        });
        if let Some((old_items, new_items)) = pair {
            for identity in old_items
                .keys()
                .chain(new_items.keys())
                .collect::<BTreeSet<_>>()
            {
                let o = old_items
                    .get(identity)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let n = new_items
                    .get(identity)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let start = changes.len();
                if o.len() <= 1 && n.len() <= 1 {
                    walk(
                        o.first().map(|(_, v)| *v),
                        n.first().map(|(_, v)| *v),
                        &o.first()
                            .map(|(i, _)| format!("{path}/{i}"))
                            .unwrap_or_default(),
                        &n.first()
                            .map(|(i, _)| format!("{path}/{i}"))
                            .unwrap_or_default(),
                        &mut changes,
                    );
                } else {
                    let before: Vec<_> = o.iter().map(|(_, v)| *v).collect();
                    let after: Vec<_> = n.iter().map(|(_, v)| *v).collect();
                    if before != after {
                        changes.push(json!({"oldPath":path,"newPath":path,"kind":"ambiguous-identity-group-changed",
                            "before":before,"after":after,
                            "oldIndices":o.iter().map(|(i,_)| i).collect::<Vec<_>>(),
                            "newIndices":n.iter().map(|(i,_)| i).collect::<Vec<_>>(),
                            "identityDiagnostic":"non-unique identity; occurrences compared as an ordered group"}));
                    }
                }
                for change in &mut changes[start..] {
                    change["identity"] =
                        serde_json::from_str(identity).expect("serialized identity");
                }
            }
        } else {
            let start = changes.len();
            walk(
                a.get(collection),
                b.get(collection),
                &path,
                &path,
                &mut changes,
            );
            if identity_keys(domain, collection).is_some() {
                for change in &mut changes[start..] {
                    change["identityDiagnostic"] =
                        json!("missing or non-unique identity; collection compared in order");
                }
            }
        }
    }
    changes
}

fn reference(file: Option<&(String, String, Value)>, path: &Value) -> Value {
    let Some((rel, hash, document)) = file else {
        return Value::Null;
    };
    let Some(path) = path.as_str() else {
        return Value::Null;
    };
    // The nearest explicit source name is a locator, not proof that this module
    // supplies this specific field: composed shapes can come from dependencies.
    let mut at = path.to_string();
    let mut module = Value::Null;
    loop {
        if let Some(node) = document.pointer(&at) {
            for key in ["module", "moduleName", "handlerModule"] {
                if let Some(name) = node.get(key).and_then(Value::as_str) {
                    module = json!(name);
                    break;
                }
            }
        }
        if !module.is_null() || at.is_empty() {
            break;
        }
        at.truncate(at.rfind('/').unwrap_or(0));
    }
    json!({"file": rel, "sha256": hash, "pointer": path, "sourceModuleHint": module,
        "sourceStatus": "requires-source-review"})
}

pub fn report(old: &Path, new: &Path, evidence: Option<&Path>) -> Result<Value> {
    let old = Snapshot::read(old)?;
    let new = Snapshot::read(new)?;
    let mut changes = Vec::new();
    for (is_schema, old_files, new_files) in [
        (false, &old.files, &new.files),
        (true, &old.schemas, &new.schemas),
    ] {
        for domain in old_files
            .keys()
            .chain(new_files.keys())
            .collect::<BTreeSet<_>>()
        {
            let a = old_files.get(domain);
            let b = new_files.get(domain);
            let deltas = match (a, b) {
                (Some((_, _, av)), Some((_, _, bv))) if !is_schema => document_diff(domain, av, bv),
                _ => {
                    let mut d = Vec::new();
                    walk(a.map(|v| &v.2), b.map(|v| &v.2), "", "", &mut d);
                    d
                }
            };
            for mut change in deltas {
                change["domain"] = json!(domain);
                if is_schema {
                    change["artifactKind"] = json!("schema");
                }
                change["oldSource"] = reference(a, &change["oldPath"]);
                change["newSource"] = reference(b, &change["newPath"]);
                // A missing field still belongs to a concrete domain document. Bind
                // that document even though there is no field pointer to reference.
                change["oldArtifactSha256"] = json!(a.map(|(_, hash, _)| hash));
                change["newArtifactSha256"] = json!(b.map(|(_, hash, _)| hash));
                // Bind a review to exact artifact contents AND inputs, not just a name
                // that can survive an unrelated future snapshot.
                change["oldSetHash"] = json!(old.lock.set_hash);
                change["newSetHash"] = json!(new.lock.set_hash);
                change["id"] = json!(wa_text::sha256_hex(
                    serde_json::to_string(&change)?.as_bytes()
                ));
                change["assessment"] = json!({"classification": "indeterminate", "basis": "Contract delta only; inspect pinned sources and same-input regeneration."});
                changes.push(change);
            }
        }
    }
    if let Some(path) = evidence {
        apply_reviews(&mut changes, &super::read_json(path)?)?;
    }
    let mut classifications: BTreeMap<String, usize> = BTreeMap::new();
    for change in &changes {
        *classifications
            .entry(
                change["assessment"]["classification"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
            .or_default() += 1;
    }
    Ok(
        json!({"reportVersion": FORMAT_VERSION, "old": old.metadata(), "new": new.metadata(),
        "sameInputs": old.lock.set_hash == new.lock.set_hash, "classifications": classifications,
        "changes": changes, "oldDiagnostics": old.manifest["diagnostics"], "newDiagnostics": new.manifest["diagnostics"],
        "limits": ["No automatic rename matching or compatibility verdict.", "Reviews are supplied evidence assessments, not machine proofs.",
            "Source module hints may require following mixins or other dependencies.", "Unkeyed and ambiguous arrays retain order; protobuf is an opaque artifact delta."]}),
    )
}

fn apply_reviews(changes: &mut [Value], reviews: &Value) -> Result<()> {
    ensure!(
        reviews["reportVersion"] == FORMAT_VERSION,
        "unsupported review reportVersion"
    );
    let entries = reviews["reviews"]
        .as_array()
        .context("reviews must be an array")?;
    let mut seen = BTreeSet::new();
    for entry in entries {
        let id = entry["id"].as_str().context("review id missing")?;
        ensure!(seen.insert(id), "duplicate review id {id}");
        let change = changes
            .iter_mut()
            .find(|c| c["id"] == id)
            .with_context(|| format!("stale or unknown review {id}"))?;
        let label = entry["classification"]
            .as_str()
            .context("classification missing")?;
        ensure!(
            matches!(
                label,
                "upstream-change" | "extraction-improvement" | "extraction-loss" | "indeterminate"
            ),
            "unknown classification {label}"
        );
        ensure!(
            entry["basis"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
            "review basis missing"
        );
        let refs = entry["references"]
            .as_array()
            .context("review references missing")?;
        ensure!(
            !refs.is_empty()
                && refs
                    .iter()
                    .all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())),
            "review needs recoverable source references"
        );
        change["assessment"] = json!({"classification": label, "basis": entry["basis"], "references": refs, "origin": "reviewed-evidence"});
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 3 || args.len() == 5,
        "usage: whatspec diff <old> <new> --json [--evidence <file>]"
    );
    ensure!(args[2] == "--json", "expected --json");
    let evidence = if args.len() == 5 {
        if args[3] != "--evidence" {
            bail!("expected --evidence");
        }
        Some(Path::new(&args[4]))
    } else {
        None
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report(Path::new(&args[0]), Path::new(&args[1]), evidence)?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_and_removed_fields_bind_both_document_hashes() {
        let dir = std::env::temp_dir().join(format!("whatspec-absent-side-{}", std::process::id()));
        let old = dir.join("old");
        let new = dir.join("new");
        let write = |root: &Path, operations: Value| {
            std::fs::create_dir_all(root.join("mex")).unwrap();
            let lock = wa_store::lock::BundleLock::new("test", vec![]);
            std::fs::write(root.join("bundles.lock.json"), lock.to_pretty_json()).unwrap();
            let doc = json!({"waVersion":"test", "schemaVersion":"4.3.0", "operations":operations})
                .to_string();
            std::fs::write(root.join("mex/index.json"), &doc).unwrap();
            let manifest = json!({"waVersion":"test", "schemaVersion":"4.3.0", "domains":{"mex":{"file":"mex/index.json","sha256":wa_text::sha256_hex(doc.as_bytes())}}});
            std::fs::write(root.join("manifest.json"), manifest.to_string()).unwrap();
        };
        write(&old, json!({"A":{}}));
        write(&new, json!({"A":{"extra":true}}));
        let added = report(&old, &new, None).unwrap()["changes"][0]["id"].clone();
        let removed = report(&new, &old, None).unwrap()["changes"][0]["id"].clone();
        // The field is still absent in this side, and both input locks are unchanged.
        write(&old, json!({"A":{}, "Unrelated":{"docId":"9"}}));
        let updated_added = report(&old, &new, None).unwrap();
        let updated_removed = report(&new, &old, None).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        let added_change = updated_added["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["newPath"] == "/operations/A/extra")
            .unwrap();
        let removed_change = updated_removed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["oldPath"] == "/operations/A/extra")
            .unwrap();
        assert_ne!(added_change["id"], added);
        assert_ne!(removed_change["id"], removed);
    }

    #[test]
    fn snapshot_hashes_and_versions_are_checked_before_diffing() {
        let dir =
            std::env::temp_dir().join(format!("whatspec-contract-diff-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("mex")).unwrap();
        let lock = wa_store::lock::BundleLock::new("test", vec![]);
        std::fs::write(dir.join("bundles.lock.json"), lock.to_pretty_json()).unwrap();
        let doc =
            json!({"waVersion":"test", "schemaVersion":"4.3.0", "operations": {"A":{"docId":"1"}}})
                .to_string();
        std::fs::write(dir.join("mex/index.json"), &doc).unwrap();
        let mut manifest = json!({"waVersion":"test", "schemaVersion":"4.3.0", "domains":{"mex":{"file":"mex/index.json","sha256":wa_text::sha256_hex(doc.as_bytes())}}});
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        assert!(
            report(&dir, &dir, None).unwrap()["changes"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        std::fs::write(dir.join("mex/index.json"), "{}").unwrap();
        assert!(
            report(&dir, &dir, None)
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
        std::fs::write(dir.join("mex/index.json"), &doc).unwrap();
        manifest["waVersion"] = json!("other");
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        assert!(
            report(&dir, &dir, None)
                .unwrap_err()
                .to_string()
                .contains("waVersion mismatch")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn schema_only_changes_are_reported_and_missing_declared_schemas_fail() {
        let dir =
            std::env::temp_dir().join(format!("whatspec-schema-delta-{}", std::process::id()));
        let write = |name: &str, schema: Value| {
            let root = dir.join(name);
            std::fs::create_dir_all(&root).unwrap();
            let lock = wa_store::lock::BundleLock::new("test", vec![]);
            std::fs::write(root.join("bundles.lock.json"), lock.to_pretty_json()).unwrap();
            let doc = json!({"waVersion":"test", "schemaVersion":"4.3.0"}).to_string();
            std::fs::write(root.join("index.json"), &doc).unwrap();
            let manifest = json!({"waVersion":"test", "schemaVersion":"4.3.0", "domains":{"test":{"file":"index.json", "schema":"schema.json", "sha256":wa_text::sha256_hex(doc.as_bytes())}}});
            std::fs::write(root.join("manifest.json"), manifest.to_string()).unwrap();
            std::fs::write(root.join("schema.json"), schema.to_string()).unwrap();
            root
        };
        let old = write("old", json!({"type":"object", "required":[]}));
        let new = write("new", json!({"type":"object", "required":["added"]}));
        let report = report(&old, &new, None).unwrap();
        assert_eq!(report["changes"].as_array().unwrap().len(), 1);
        let delta = &report["changes"][0];
        assert_eq!(delta["oldSource"]["file"], "schema.json");
        assert_eq!(delta["oldPath"], "/required");
        assert_ne!(delta["oldArtifactSha256"], delta["newArtifactSha256"]);
        std::fs::remove_file(new.join("schema.json")).unwrap();
        assert!(Snapshot::read(&new).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reviewed_causes_are_explicit_and_cannot_be_renames() {
        let mut changes = [json!({"id":"current"})];
        let mut review = json!({"reportVersion":1,"reviews":[{"id":"current","classification":"extraction-loss","basis":"field remains in source","references":["bundle SHA-256 and byte span"]}]});
        apply_reviews(&mut changes, &review).unwrap();
        assert_eq!(changes[0]["assessment"]["origin"], "reviewed-evidence");
        review["reviews"][0]["classification"] = json!("rename");
        assert!(apply_reviews(&mut changes, &review).is_err());
        review["reviews"][0]["classification"] = json!("extraction-loss");
        review["reviews"][0]["references"] = json!([]);
        assert!(apply_reviews(&mut changes, &review).is_err());
    }

    #[test]
    fn same_name_enum_modules_do_not_collapse() {
        let a = json!({"enums": [{"module":"A","name":"X","variants":[1]}, {"module":"B","name":"X","variants":[2]}]});
        let b = json!({"enums": [{"module":"B","name":"X","variants":[3]}, {"module":"A","name":"X","variants":[1]}]});
        let changes = document_diff("enums", &a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0]["identity"], json!(["B", "X"]));
        assert_eq!(changes[0]["oldPath"], "/enums/1/variants");
        assert_eq!(changes[0]["newPath"], "/enums/0/variants");
    }

    #[test]
    fn duplicates_and_variant_order_are_not_erased() {
        let a = json!({"enums": [{"module":"A","name":"X"}, {"module":"A","name":"X"}]});
        let b = json!({"enums": [{"module":"A","name":"X"}]});
        let changes = document_diff("enums", &a, &b);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].get("identityDiagnostic").is_some());
        assert_eq!(
            document_diff("iq", &json!({"variants":[1,2]}), &json!({"variants":[2,1]})).len(),
            1
        );
    }

    #[test]
    fn absent_null_and_pointer_escapes_are_distinct() {
        let changes = document_diff(
            "mex",
            &json!({"operations":{"A/B~C":null}}),
            &json!({"operations":{}}),
        );
        assert_eq!(changes[0]["kind"], "removed");
        assert_eq!(changes[0]["oldPath"], "/operations/A~1B~0C");
        assert!(changes[0]["newPath"].is_null());
    }

    #[test]
    fn rename_is_add_remove_not_inferred_identity() {
        let changes = document_diff(
            "mex",
            &json!({"operations":{"Old":{"docId":"1"}}}),
            &json!({"operations":{"New":{"docId":"1"}}}),
        );
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .all(|v| v["kind"] == "added" || v["kind"] == "removed")
        );
    }

    #[test]
    fn stale_reviews_fail_instead_of_reclassifying_another_snapshot() {
        let review = json!({"reportVersion":1,"reviews":[{"id":"wrong","classification":"upstream-change","basis":"verified","references":["bundle:offset"]}]});
        assert!(
            apply_reviews(&mut [json!({"id":"current"})], &review)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }
}
