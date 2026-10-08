//! Presence is a serialization property, separate from inferred type/nullability.
use std::{collections::BTreeMap, path::Path};
use wa_ir::{TypeNode, VariablePresence};

fn source(version: &str, module: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance")
            .join(version)
            .join(format!("{module}.js")),
    )
    .unwrap()
}

#[test]
fn verified_call_sites_keep_presence_separate_from_boolean_type() {
    for version in ["2.3000.1045368834", "2.3000.1047483476"] {
        let source = source(version, "WAWebMexFetchNewsletterJobQuery.graphql")
            + &source(version, "WAWebMexFetchNewsletterJob");
        let ir = wa_mex::extract_mex(&source, version);
        reviewed_catalog(&ir);
    }
}

fn reviewed_catalog(ir: &wa_ir::MexIr) {
    assert_eq!(
        ir.operations.keys().map(String::as_str).collect::<Vec<_>>(),
        ["FetchNewsletter"]
    );
    reviewed_presence(&ir.operations["FetchNewsletter"]);
}

fn reviewed_presence(op: &wa_ir::MexOperation) {
    // The source fixes object structure and argument names. Scalar tags remain
    // the documented name-based approximation, not GraphQL/server type proof.
    let boolean = || TypeNode::Leaf("boolean".into());
    let string = || TypeNode::Leaf("string".into());
    assert_eq!(
        op.variables_shape,
        BTreeMap::from([
            ("fetch_creation_time".into(), boolean()),
            ("fetch_full_image".into(), boolean()),
            ("fetch_status_metadata".into(), boolean()),
            ("fetch_wamo_sub".into(), boolean()),
            ("fetch_viewer_metadata".into(), boolean()),
            ("fetch_pinned_messages".into(), boolean()),
            (
                "input".into(),
                TypeNode::Object(BTreeMap::from([
                    ("key".into(), string()),
                    ("type".into(), string()),
                    ("view_role".into(), string()),
                ]))
            ),
        ])
    );
    let keys: std::collections::BTreeSet<_> =
        op.variables_presence.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "input",
            "fetch_creation_time",
            "fetch_full_image",
            "fetch_status_metadata",
            "fetch_wamo_sub",
            "fetch_viewer_metadata",
            "fetch_pinned_messages",
        ])
    );
    let input_keys: std::collections::BTreeSet<_> = op.variables_presence["input"]
        .fields
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        input_keys,
        std::collections::BTreeSet::from(["key", "type", "view_role"])
    );
    for (key, expected) in [
        ("fetch_creation_time", VariablePresence::Always),
        ("fetch_full_image", VariablePresence::Always),
        ("fetch_status_metadata", VariablePresence::Always),
        ("fetch_wamo_sub", VariablePresence::Always),
        ("fetch_viewer_metadata", VariablePresence::Conditional),
        ("fetch_pinned_messages", VariablePresence::Undetermined),
    ] {
        assert_eq!(op.variables_presence[key].presence, expected, "{key}");
        // The scalar-name heuristic types these fetch_* names as boolean.
        // That does not establish call-site nullability or key presence.
        assert_eq!(op.variables_shape[key], TypeNode::Leaf("boolean".into()));
    }
    assert_eq!(
        op.variables_presence["input"].presence,
        VariablePresence::Always
    );
    assert_eq!(
        op.variables_presence["input"].fields["key"].presence,
        VariablePresence::Conditional
    );
    assert_eq!(
        op.variables_presence["input"].fields["view_role"].presence,
        VariablePresence::Conditional
    );
    assert_eq!(
        op.variables_presence["input"].fields["type"].presence,
        VariablePresence::Always
    );
}

#[test]
fn presence_oracle_rejects_regressions_in_all_reviewed_keys() {
    let source = source(
        "2.3000.1047483476",
        "WAWebMexFetchNewsletterJobQuery.graphql",
    ) + &source("2.3000.1047483476", "WAWebMexFetchNewsletterJob");
    let ir = wa_mex::extract_mex(&source, "fixture");
    for key in ["fetch_status_metadata", "fetch_wamo_sub", "view_role"] {
        let mut op = ir.operations["FetchNewsletter"].clone();
        if key == "view_role" {
            op.variables_presence
                .get_mut("input")
                .unwrap()
                .fields
                .get_mut(key)
                .unwrap()
                .presence = VariablePresence::Always;
        } else {
            op.variables_presence.get_mut(key).unwrap().presence = VariablePresence::Undetermined;
        }
        assert!(
            std::panic::catch_unwind(|| reviewed_presence(&op)).is_err(),
            "accepted {key} regression"
        );
    }
}

#[test]
fn null_undefined_and_unresolved_calls_have_distinct_presence_verdicts() {
    // Hand-authored perturbations of a real operation, not extra claims about
    // which arguments the server accepts. Expectations follow JSON object-key
    // serialization: null survives, undefined disappears, calls are unresolved.
    let query = source(
        "2.3000.1047483476",
        "WAWebMexFetchNewsletterJobQuery.graphql",
    );
    for (expression, expected) in [
        ("null", VariablePresence::Always),
        ("false", VariablePresence::Always),
        ("void 0", VariablePresence::Conditional),
        ("t.flag", VariablePresence::Conditional),
        ("t.flag === true", VariablePresence::Always),
        ("o(\"External\").flag()", VariablePresence::Undetermined),
    ] {
        let caller = format!(
            r#"__d("ConformanceCaller",["WAWebMexClient","WAWebMexFetchNewsletterJobQuery.graphql","External"],(function(t,n,r,o,a,i,l){{function f(t){{return o("WAWebMexClient").fetchQuery(n("WAWebMexFetchNewsletterJobQuery.graphql"),{{fetch_viewer_metadata:{expression}}})}}l.run=f}}),98);"#
        );
        let ir = wa_mex::extract_mex(&(query.clone() + &caller), "fixture");
        let op = &ir.operations["FetchNewsletter"];
        assert_eq!(
            op.variables_presence["fetch_viewer_metadata"].presence, expected,
            "{expression}"
        );
        assert_eq!(
            op.variables_shape["fetch_viewer_metadata"],
            TypeNode::Leaf("boolean".into()),
            "presence does not establish nullability: {expression}"
        );
    }
}

#[test]
fn presence_oracle_rejects_unreviewed_keys() {
    let source = source(
        "2.3000.1047483476",
        "WAWebMexFetchNewsletterJobQuery.graphql",
    ) + &source("2.3000.1047483476", "WAWebMexFetchNewsletterJob");
    let ir = wa_mex::extract_mex(&source, "fixture");
    for nested in [false, true] {
        let mut op = ir.operations["FetchNewsletter"].clone();
        if nested {
            let input = op.variables_presence.get_mut("input").unwrap();
            input
                .fields
                .insert("unreviewed".into(), input.fields["key"].clone());
        } else {
            op.variables_presence
                .insert("unreviewed".into(), op.variables_presence["input"].clone());
        }
        assert!(
            std::panic::catch_unwind(|| reviewed_presence(&op)).is_err(),
            "accepted extra key, nested={nested}"
        );
    }
}

#[test]
fn source_catalog_rejects_spurious_mex_operations() {
    for version in ["2.3000.1045368834", "2.3000.1047483476"] {
        let source = source(version, "WAWebMexFetchNewsletterJobQuery.graphql")
            + &source(version, "WAWebMexFetchNewsletterJob");
        let mut ir = wa_mex::extract_mex(&source, version);
        ir.operations.insert(
            "Unreviewed".into(),
            ir.operations["FetchNewsletter"].clone(),
        );
        assert!(std::panic::catch_unwind(|| reviewed_catalog(&ir)).is_err());
    }
}

#[test]
fn variables_shape_oracle_rejects_missing_extra_and_changed_fields() {
    let source = source(
        "2.3000.1047483476",
        "WAWebMexFetchNewsletterJobQuery.graphql",
    ) + &source("2.3000.1047483476", "WAWebMexFetchNewsletterJob");
    let ir = wa_mex::extract_mex(&source, "fixture");
    let original = &ir.operations["FetchNewsletter"];
    for nested in [false, true] {
        let keys: Vec<_> = if nested {
            vec!["key", "type", "view_role"]
        } else {
            vec![
                "input",
                "fetch_creation_time",
                "fetch_full_image",
                "fetch_status_metadata",
                "fetch_wamo_sub",
                "fetch_viewer_metadata",
                "fetch_pinned_messages",
            ]
        };
        for key in keys.into_iter().chain(["unreviewed"]) {
            for remove in [false, true] {
                if key == "unreviewed" && remove {
                    continue;
                }
                let mut op = original.clone();
                let fields = if nested {
                    let TypeNode::Object(fields) = op.variables_shape.get_mut("input").unwrap()
                    else {
                        panic!("input must be an object")
                    };
                    fields
                } else {
                    &mut op.variables_shape
                };
                if remove {
                    fields.remove(key);
                } else {
                    fields.insert(key.into(), TypeNode::Leaf("wrong".into()));
                }
                assert!(
                    std::panic::catch_unwind(|| reviewed_presence(&op)).is_err(),
                    "accepted shape mutation {key}, nested={nested}, remove={remove}"
                );
            }
        }
    }
}
