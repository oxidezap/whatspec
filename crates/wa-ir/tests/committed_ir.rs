//! Invariants checked against the **committed** `generated/`, not a fixture.
//!
//! A fixture proves the code does what the test wrote down. These questions are about
//! the document a consumer actually downloads: whether the key it is told to index by is
//! a key, and whether every reference in the IR lands somewhere. Both were false before,
//! and both were false in a way no unit test could have seen — the collisions and the
//! missing entries only exist at the scale of the whole bundle.
//!
//! Skips (rather than fails) when a document is absent, so a fresh checkout without
//! `generated/` still runs the rest of the suite.

use std::collections::{BTreeMap, BTreeSet};

/// The domains whose documents carry `enumRef` references.
const REFERENCING_DOMAINS: &[&str] = &["iq", "incoming", "notif", "srvreq", "stanza"];

fn read(domain: &str) -> Option<serde_json::Value> {
    let path = format!(
        "{}/../../generated/{domain}/index.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).ok()?;
    Some(serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}")))
}

/// Every `enumRef` object anywhere in `v`, as `(module, name)` → its variant values.
fn enum_refs(v: &serde_json::Value, out: &mut BTreeMap<(String, String), BTreeSet<String>>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                if k == "enumRef"
                    && let (Some(m), Some(n)) = (child.get("module"), child.get("name"))
                    && let (Some(m), Some(n)) = (m.as_str(), n.as_str())
                {
                    let values = child
                        .get("variants")
                        .and_then(|v| v.as_array())
                        .map(|vs| {
                            vs.iter()
                                .filter_map(|v| v.get("value").map(ToString::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    out.insert((m.to_string(), n.to_string()), values);
                }
                enum_refs(child, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| enum_refs(i, out)),
        _ => {}
    }
}

#[test]
fn the_enum_catalog_key_is_module_and_name_and_it_does_not_collide() {
    let Some(doc) = read("enums") else {
        eprintln!("skip: generated/enums/index.json not committed");
        return;
    };
    let enums: &Vec<serde_json::Value> = doc["enums"].as_array().expect("enums array");

    let mut by_key: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
    for e in enums {
        let (m, n) = (e["module"].as_str().unwrap(), e["name"].as_str().unwrap());
        *by_key.entry((m, n)).or_default() += 1;
        *by_name.entry(n).or_default() += 1;
    }

    let key_collisions: Vec<_> = by_key.iter().filter(|&(_, c)| *c > 1).collect();
    assert!(
        key_collisions.is_empty(),
        "(module, name) is the catalog key and must be unique: {key_collisions:?}",
    );

    // The other half, and the reason the key had to be spelled out: `name` alone is NOT
    // one. Asserted as a positive fact rather than left implicit, so a consumer — or a
    // future version of this repo — cannot quietly go back to indexing by name and have
    // the suite agree. `ENUM_FALSE_TRUE` is defined by eleven different modules, and
    // `EventType`'s two definitions disagree on `valueKind`.
    let name_collisions: BTreeSet<&str> = by_name
        .iter()
        .filter(|&(_, c)| *c > 1)
        .map(|(n, _)| *n)
        .collect();
    assert!(
        !name_collisions.is_empty(),
        "name is not a key, and this asserts the collisions are still there to prove it. \
         If a bundle ever makes `name` unique, that is a fact worth re-reading this \
         contract over — not a licence to index by it, since nothing keeps it unique.",
    );

    // The named examples are illustrations, not invariants: WhatsApp may rename or drop
    // either one without anything in this repository regressing. Checked when present,
    // noted when not, so an upstream rename does not read as a failure here.
    match enums.iter().filter(|e| e["name"] == "EventType").count() {
        0 => eprintln!("note: EventType is no longer in the catalog"),
        n => {
            assert!(n > 1, "EventType used to be defined twice");
            let kinds: BTreeSet<&str> = enums
                .iter()
                .filter(|e| e["name"] == "EventType")
                .filter_map(|e| e["valueKind"].as_str())
                .collect();
            assert_eq!(
                kinds.len(),
                2,
                "EventType's two definitions disagree on valueKind — indexing by name \
                 picks one and generates a type from the other's universe",
            );
        }
    }
}

#[test]
fn every_enum_reference_in_the_ir_resolves_against_the_catalog() {
    let Some(catalog) = read("enums") else {
        eprintln!("skip: generated/enums/index.json not committed");
        return;
    };
    let known: BTreeSet<(String, String)> = catalog["enums"]
        .as_array()
        .expect("enums array")
        .iter()
        .map(|e| {
            (
                e["module"].as_str().unwrap().to_string(),
                e["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    let mut refs = BTreeMap::new();
    let mut seen_a_domain = false;
    for d in REFERENCING_DOMAINS {
        if let Some(doc) = read(d) {
            seen_a_domain = true;
            enum_refs(&doc, &mut refs);
        }
    }
    assert!(seen_a_domain, "no referencing domain committed");
    assert!(!refs.is_empty(), "the IR references no enum at all");

    let unresolved: Vec<_> = refs.keys().filter(|k| !known.contains(k)).collect();
    assert!(
        unresolved.is_empty(),
        "{} enum reference(s) resolve against no catalog entry — a consumer reading the \
         catalog alone generates a fraction of the types the IR names: {unresolved:?}",
        unresolved.len(),
    );
}

#[test]
fn a_bit_position_enum_is_distinguishable_from_a_code_enum() {
    let Some(doc) = read("enums") else {
        eprintln!("skip: generated/enums/index.json not committed");
        return;
    };
    let enums = doc["enums"].as_array().expect("enums array");
    let bit: Vec<&serde_json::Value> = enums
        .iter()
        .filter(|e| e["bitPosition"] == serde_json::Value::Bool(true))
        .collect();
    assert!(
        !bit.is_empty(),
        "no enum is marked as bit positions — the shift evidence stopped being found",
    );
    for e in &bit {
        assert_eq!(
            e["valueKind"], "int",
            "a wire token has no bit to shift into"
        );
    }
    // The pair the finding is about: two int enums, same shape, different meaning.
    // `HID_FAILED_DECRYPT: 2` goes on the wire as `1 << 2 == 4`; a nack code of 2 goes
    // on the wire as 2. Nothing but this flag separates them.
    let receipt = bit
        .iter()
        .find(|e| e["name"] == "ReceiptModeBitPosition")
        .expect("ReceiptModeBitPosition is marked");
    assert_eq!(receipt["module"], "WAWebSendReceiptJobCommon");
    let code_enum = enums
        .iter()
        .find(|e| e["valueKind"] == "int" && e["bitPosition"] != serde_json::Value::Bool(true))
        .expect("a plain int enum to contrast with");
    assert_ne!(receipt["bitPosition"], code_enum["bitPosition"]);
}

#[test]
fn a_generated_enum_name_is_marked_as_one() {
    let Some(doc) = read("enums") else {
        eprintln!("skip: generated/enums/index.json not committed");
        return;
    };
    let enums = doc["enums"].as_array().expect("enums array");
    let synthetic: Vec<&str> = enums
        .iter()
        .filter(|e| e["syntheticName"] == serde_json::Value::Bool(true))
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(!synthetic.is_empty(), "no name is marked generated");
    // The invariant: the flag SEPARATES generated names from chosen ones, so a catalog
    // where everything is marked says nothing. That holds whatever WA spells them.
    assert!(
        synthetic.len() < enums.len(),
        "every name is marked generated — the flag distinguishes nothing",
    );
    // `ENUM_` is what WA's emitter happens to prefix today, not something the rule
    // requires: it reconstructs the name from the variants and compares. Noted rather
    // than asserted, since a future bundle spelling them differently would be news, not
    // a regression here.
    if let Some(other) = synthetic.iter().find(|n| !n.starts_with("ENUM_")) {
        eprintln!("note: a generated name no longer uses WA's `ENUM_` prefix: {other}");
    }
}
