//! Guard: the committed IQ IR carries enough to **emit** a stanza, not only to read one.
//!
//! The IR has always described what fields a stanza has. That is enough to parse a
//! well-formed response and not enough to produce one — which is how a mock server can
//! answer a successful `promote` with `<participant type="200">` (a status code where
//! the role goes) and have a real client reject the whole thing, or answer an `<iq>`
//! addressed to `g.us` with `from="s.whatsapp.net"` and be unparseable.
//!
//! So this test closes the loop the way a consumer would: for every `<iq>` success
//! variant, build a stanza from **the IR alone** — nothing but the recorded assertions
//! and pinned field values — and check the recorded assertions accept it. A constraint
//! that the IR fails to carry shows up here as an emitted stanza that the same IR then
//! rejects.
//!
//! Both halves are deliberately naive: the emitter only knows how to satisfy
//! constraints, and the checker only knows how to verify them. Neither shares code with
//! the extractor, so a mis-extraction cannot cancel itself out.

use std::collections::BTreeMap;
use std::path::Path;

use wa_ir::{AssertionKind, IqIr, ParsedField, ResponseAssertion, ResponseVariantKind};

/// A minimal stanza: a tag, attributes, and text content. Everything the recorded
/// assertions can talk about.
#[derive(Debug, Default)]
struct Node {
    tag: String,
    attrs: BTreeMap<String, String>,
    content: Option<String>,
}

/// The request a response is answering, as far as the echo rules care: the attribute
/// values a `reference` assertion can point at. Keyed by the joined `referencePath`, so
/// a multi-hop path (`["account","action"]`) is addressable too.
fn sample_request() -> BTreeMap<String, String> {
    // A group-addressed request — the case that broke: `to` is NOT `s.whatsapp.net`, so
    // an emitter that hardcodes the server JID fails the `from` echo.
    BTreeMap::from([
        ("id".to_string(), "1234.5678-9".to_string()),
        ("to".to_string(), "120363000000000000@g.us".to_string()),
        ("account/action".to_string(), "sync".to_string()),
    ])
}

/// Build the response node a variant describes, using only the IR.
fn emit(assertions: &[ResponseAssertion], fields: &[ParsedField]) -> Node {
    let request = sample_request();
    let mut node = Node::default();
    for a in assertions {
        match a.kind {
            AssertionKind::Tag => node.tag = a.name.clone().unwrap_or_default(),
            AssertionKind::Attr => {
                if let (Some(name), Some(value)) = (&a.name, &a.value) {
                    node.attrs.insert(name.clone(), value.clone());
                }
            }
            AssertionKind::Content => node.content = a.value.clone(),
            // The whole point of the `reference` kind: the emitter reads the expected
            // value out of the REQUEST rather than inventing one.
            AssertionKind::Reference => {
                if let (Some(name), Some(path)) = (&a.name, &a.reference_path)
                    && let Some(value) = request.get(&path.join("/"))
                {
                    node.attrs.insert(name.clone(), value.clone());
                }
            }
            AssertionKind::FromServer => {}
        }
    }
    // Pinned field values (`type="admin"`, `matched="true"`) are constraints too: a
    // required one must be emitted, and an optional one must not be contradicted. A
    // field-level `referencePath` is the same rule with the value taken from the
    // request (the optional twin of a `reference` assertion).
    for f in fields {
        if f.source_path.is_some() || f.same_node {
            continue; // not read off this node
        }
        let wire = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
        if let Some(value) = pinned_value(f, &request)
            && f.required
        {
            node.attrs.entry(wire).or_insert(value);
        }
    }
    node
}

/// The value a field is pinned to, if any: a constant, or the request value it echoes.
fn pinned_value(f: &ParsedField, request: &BTreeMap<String, String>) -> Option<String> {
    if let Some(v) = &f.literal_value {
        return Some(v.clone());
    }
    let path = f.reference_path.as_ref()?;
    request.get(&path.join("/")).cloned()
}

/// Check the node against the same assertions, reporting each unsatisfied one.
fn violations(
    node: &Node,
    assertions: &[ResponseAssertion],
    fields: &[ParsedField],
) -> Vec<String> {
    let request = sample_request();
    let mut out = Vec::new();
    for a in assertions {
        match a.kind {
            AssertionKind::Tag => {
                if let Some(tag) = &a.name
                    && &node.tag != tag
                {
                    out.push(format!("tag: expected <{tag}>, got <{}>", node.tag));
                }
            }
            AssertionKind::Attr => {
                if let (Some(name), Some(value)) = (&a.name, &a.value)
                    && node.attrs.get(name) != Some(value)
                {
                    out.push(format!(
                        "attr {name}: expected {value:?}, got {:?}",
                        node.attrs.get(name)
                    ));
                }
            }
            AssertionKind::Content => {
                if node.content.as_ref() != a.value.as_ref() {
                    out.push(format!(
                        "content: expected {:?}, got {:?}",
                        a.value, node.content
                    ));
                }
            }
            AssertionKind::Reference => {
                let Some(name) = &a.name else { continue };
                let Some(path) = &a.reference_path else {
                    out.push(format!("reference {name}: no referencePath recorded"));
                    continue;
                };
                let Some(expected) = request.get(&path.join("/")) else {
                    // The path names a request field the sample doesn't model. Not a
                    // failure of the IR — but flag an unrecognised shape rather than
                    // passing silently.
                    out.push(format!(
                        "reference {name}: unmodelled request path {path:?}"
                    ));
                    continue;
                };
                if node.attrs.get(name) != Some(expected) {
                    out.push(format!(
                        "reference {name}: expected the request's {path:?} ({expected:?}), got {:?}",
                        node.attrs.get(name)
                    ));
                }
            }
            AssertionKind::FromServer => {}
        }
    }
    for f in fields {
        if f.source_path.is_some() || f.same_node {
            continue; // not read off this node
        }
        // A field pinned to a request path the sample doesn't model can't be checked,
        // but an unrecognised shape must still be visible rather than pass silently.
        if f.literal_value.is_none()
            && let Some(path) = &f.reference_path
            && !request.contains_key(&path.join("/"))
        {
            out.push(format!(
                "field {}: unmodelled request path {path:?}",
                f.name
            ));
            continue;
        }
        let Some(value) = pinned_value(f, &request) else {
            continue;
        };
        let wire = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
        match (node.attrs.get(&wire), f.required) {
            // A required pin must be present and exact.
            (None, true) => out.push(format!("pinned {wire}: required {value:?} not emitted")),
            (Some(got), _) if *got != value => out.push(format!(
                "pinned {wire}: expected {value:?}, emitted {got:?}"
            )),
            // An optional pin may be absent; it just must not contradict.
            _ => {}
        }
    }
    out
}

#[test]
fn every_iq_success_variant_round_trips_through_its_own_constraints() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../generated/iq/index.json");
    // Committed, so CI always has it: a missing file there means the guard is silently
    // not running. Locally (sparse checkout) skip instead of failing spuriously —
    // mirroring `wa-proto`'s committed-artifact guard.
    if !path.exists() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{} is absent under CI — the IQ round-trip guard would be silently skipped",
            path.display()
        );
        eprintln!("skipping: {} not present (local only)", path.display());
        return;
    }
    let raw = std::fs::read_to_string(&path).expect("read generated/iq/index.json");
    let ir: IqIr = serde_json::from_str(&raw).expect("parse the committed IQ IR");

    let mut checked = 0usize;
    let mut failures = Vec::new();
    for stanza in &ir.stanzas {
        // Both response shapes: a single-shape response's own assertions, and each
        // success variant of an outcome union.
        let shapes = std::iter::once((
            stanza.response.parser_name.clone(),
            &stanza.response.assertions,
            &stanza.response.fields,
        ))
        .chain(
            stanza
                .response
                .variants
                .iter()
                .filter(|v| v.kind == ResponseVariantKind::Success)
                .map(|v| (v.tag.clone(), &v.assertions, &v.fields)),
        );
        for (name, assertions, fields) in shapes {
            if assertions.is_empty() {
                continue; // nothing recorded to satisfy or to check
            }
            checked += 1;
            let node = emit(assertions, fields);
            for v in violations(&node, assertions, fields) {
                failures.push(format!("{} / {name}: {v}", stanza.module_name));
            }
        }
    }

    assert!(
        checked > 0,
        "no IQ response shape carried any assertion — the constraint layer is empty"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} IR-built response shape(s) fail their own recorded constraints:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("round-tripped {checked} IQ response shape(s) from the IR alone");
}

#[test]
fn a_hardcoded_from_fails_the_echo_rule() {
    // The negative control: without this the round-trip could pass by vacuously
    // ignoring `reference` assertions. Mirrors barback's real bug — answering a request
    // addressed to `g.us` with `from="s.whatsapp.net"`.
    let assertions = vec![
        ResponseAssertion {
            kind: AssertionKind::Tag,
            name: Some("iq".into()),
            value: None,
            reference_path: None,
        },
        ResponseAssertion {
            kind: AssertionKind::Reference,
            name: Some("from".into()),
            value: None,
            reference_path: Some(vec!["to".into()]),
        },
    ];
    let mut node = emit(&assertions, &[]);
    assert!(violations(&node, &assertions, &[]).is_empty());
    node.attrs
        .insert("from".into(), "s.whatsapp.net".to_string());
    let broken = violations(&node, &assertions, &[]);
    assert_eq!(broken.len(), 1, "{broken:?}");
    assert!(broken[0].contains("reference from"), "{broken:?}");
}
