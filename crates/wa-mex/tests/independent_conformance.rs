//! Presence is a serialization property, separate from inferred type/nullability.
use std::path::Path;
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
        let op = &ir.operations["FetchNewsletter"];
        for (key, expected) in [
            ("fetch_creation_time", VariablePresence::Always),
            ("fetch_full_image", VariablePresence::Always),
            ("fetch_viewer_metadata", VariablePresence::Conditional),
            ("fetch_pinned_messages", VariablePresence::Undetermined),
        ] {
            assert_eq!(
                op.variables_presence[key].presence, expected,
                "{version}: {key}"
            );
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
            op.variables_presence["input"].fields["type"].presence,
            VariablePresence::Always
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
