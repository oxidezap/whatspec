//! Guard: the committed IQ IR carries enough to **emit** a stanza, not only to read one.
//!
//! The IR has always described what fields a stanza has. That is enough to parse a
//! well-formed response and not enough to produce one — which is how a mock server can
//! answer a successful `promote` with `<participant type="200">` (a status code where
//! the role goes) and have a real client reject the whole thing, or answer an `<iq>`
//! addressed to `g.us` with `from="s.whatsapp.net"` and be unparseable.
//!
//! So this test closes the loop the way a consumer would: for every `<iq>` success
//! shape, build a stanza from **the IR alone** — nothing but the recorded assertions and
//! pinned field values — and check the recorded constraints accept it. A constraint the
//! IR fails to carry shows up here as an emitted stanza that the same IR then rejects.
//!
//! The stanza is modelled as a **tree**, addressed by the path from the root, because
//! the constraints that motivated the change do not live on the root: `matched="true"`
//! sits on the `<list>` child (a `sourcePath`) and `type="admin"` on `<participant>` (a
//! nested `child` field). A root-only guard would accept exactly the malformed promote
//! response this file exists to reject.
//!
//! Both halves are deliberately naive: the emitter only knows how to satisfy
//! constraints, and the checker only knows how to verify them. Neither shares code with
//! the extractor, so a mis-extraction cannot cancel itself out.

use std::collections::BTreeMap;
use std::path::Path;

use wa_ir::{AssertionKind, IqIr, ParsedField, ResponseAssertion, ResponseVariantKind};

/// A stanza under construction: the root tag, its text content, and the attributes of
/// every node reachable in it, keyed by the path from the root (`[]` is the root itself,
/// `["list"]` its `<list>` child, `["participant"]` a `<participant>` child, …).
#[derive(Debug, Default)]
struct Stanza {
    tag: String,
    content: Option<String>,
    nodes: BTreeMap<Vec<String>, BTreeMap<String, String>>,
}

impl Stanza {
    fn attr(&self, path: &[String], name: &str) -> Option<&String> {
        self.nodes.get(path).and_then(|n| n.get(name))
    }
    fn set(&mut self, path: Vec<String>, name: String, value: String) {
        self.nodes
            .entry(path)
            .or_default()
            .entry(name)
            .or_insert(value);
    }
}

/// The request a response is answering, as far as the echo rules care: the attribute
/// values a `reference` constraint can point at. Keyed by the joined path, so a
/// multi-hop one (`["account","action"]`) is addressable too.
fn sample_request() -> BTreeMap<String, String> {
    // A group-addressed request — the case that broke: `to` is NOT `s.whatsapp.net`, so
    // an emitter that hardcodes the server JID fails the `from` echo.
    BTreeMap::from([
        ("id".to_string(), "1234.5678-9".to_string()),
        ("to".to_string(), "120363000000000000@g.us".to_string()),
        ("type".to_string(), "set".to_string()),
        ("account/action".to_string(), "sync".to_string()),
        ("item/dhash".to_string(), "2:abcdef==".to_string()),
        (
            "participant".to_string(),
            "5511999999999@s.whatsapp.net".to_string(),
        ),
        ("category".to_string(), "block".to_string()),
    ])
}

/// The value a field is pinned to, if any: a constant, or the request value it echoes.
/// `Err` marks a pin whose request path the sample doesn't model — not an IR failure,
/// but an unrecognised shape that must be reported rather than pass silently.
fn pinned_value(
    f: &ParsedField,
    request: &BTreeMap<String, String>,
) -> Option<Result<String, String>> {
    if let Some(v) = &f.literal_value {
        return Some(Ok(v.clone()));
    }
    let path = f.reference_path.as_ref()?;
    Some(
        request
            .get(&path.join("/"))
            .cloned()
            .ok_or_else(|| format!("unmodelled request path {path:?}")),
    )
}

/// Walk a field tree, invoking `visit` with each pinned field and the path of the node
/// it is read from.
///
/// Three shapes decide the path: `sourcePath` prepends wrapper tags to descend, a
/// `child` field descends into its own `tag`, and a `sameNode` mixin reads off the
/// parent without descending at all.
///
/// Only a **required** container is descended into. An optional one is a branch the
/// response need not take, and WA models mutually exclusive alternatives as several
/// optional same-node mixins rather than as one union: a newsletter `<status><meta>`
/// carries an `InteractionTypeQuestion` mixin pinning `interaction_type="question"` and
/// an `InteractionTypeQuestionReshare` mixin pinning `"question_reshare"` on the very
/// same attribute. Both pins are correct; only one applies at a time. Descending into
/// both would build a self-contradicting node and report the IR as broken when it is
/// the walk that is wrong. Unions are skipped for the same reason unless single-armed.
fn walk_pinned(
    fields: &[ParsedField],
    base: &[String],
    visit: &mut impl FnMut(&ParsedField, Vec<String>),
) {
    for f in fields {
        let mut path = base.to_vec();
        if !f.same_node {
            path.extend(f.source_path.iter().flatten().cloned());
            if let Some(tag) = &f.tag {
                path.push(tag.clone());
            }
        }
        if f.literal_value.is_some() || f.reference_path.is_some() {
            visit(f, path.clone());
        }
        if !f.required {
            continue; // a branch the response need not take — see above
        }
        if let Some(children) = &f.children {
            walk_pinned(children, &path, visit);
        }
        if let Some([only]) = f.union_variants.as_deref() {
            walk_pinned(&only.fields, &path, visit);
        }
    }
}

/// Build the response a shape describes, using only the IR.
fn emit(assertions: &[ResponseAssertion], fields: &[ParsedField]) -> Stanza {
    let request = sample_request();
    let mut s = Stanza::default();
    let root: Vec<String> = Vec::new();
    for a in assertions {
        match a.kind {
            AssertionKind::Tag => s.tag = a.name.clone().unwrap_or_default(),
            AssertionKind::Attr => {
                if let (Some(name), Some(value)) = (&a.name, &a.value) {
                    s.set(root.clone(), name.clone(), value.clone());
                }
            }
            AssertionKind::Content => s.content = a.value.clone(),
            // The whole point of the `reference` kind: the emitter reads the expected
            // value out of the REQUEST rather than inventing one.
            AssertionKind::Reference => {
                if let (Some(name), Some(path)) = (&a.name, &a.reference_path)
                    && let Some(value) = request.get(&path.join("/"))
                {
                    s.set(root.clone(), name.clone(), value.clone());
                }
            }
            AssertionKind::FromServer => {}
        }
    }
    // A required pin must be emitted; an optional one may be omitted (and this emitter
    // omits it, which the checker must accept).
    walk_pinned(fields, &root, &mut |f, path| {
        if !pin_is_required(f) {
            return;
        }
        if let Some(Ok(value)) = pinned_value(f, &request) {
            let wire = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
            s.set(path, wire, value);
        }
    });
    s
}

/// Check the stanza against the same constraints, reporting each unsatisfied one.
fn violations(s: &Stanza, assertions: &[ResponseAssertion], fields: &[ParsedField]) -> Vec<String> {
    let request = sample_request();
    let root: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for a in assertions {
        match a.kind {
            AssertionKind::Tag => {
                if let Some(tag) = &a.name
                    && &s.tag != tag
                {
                    out.push(format!("tag: expected <{tag}>, got <{}>", s.tag));
                }
            }
            AssertionKind::Attr => {
                if let (Some(name), Some(value)) = (&a.name, &a.value)
                    && s.attr(&root, name) != Some(value)
                {
                    out.push(format!(
                        "attr {name}: expected {value:?}, got {:?}",
                        s.attr(&root, name)
                    ));
                }
            }
            AssertionKind::Content => {
                if s.content.as_ref() != a.value.as_ref() {
                    out.push(format!(
                        "content: expected {:?}, got {:?}",
                        a.value, s.content
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
                    out.push(format!(
                        "reference {name}: unmodelled request path {path:?}"
                    ));
                    continue;
                };
                if s.attr(&root, name) != Some(expected) {
                    out.push(format!(
                        "reference {name}: expected the request's {path:?} ({expected:?}), got {:?}",
                        s.attr(&root, name)
                    ));
                }
            }
            AssertionKind::FromServer => {}
        }
    }
    walk_pinned(fields, &root, &mut |f, path| {
        let wire = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
        let at = if path.is_empty() {
            wire.clone()
        } else {
            format!("{}/@{wire}", path.join("/"))
        };
        match pinned_value(f, &request) {
            Some(Err(why)) => out.push(format!("pinned {at}: {why}")),
            Some(Ok(value)) => match (s.attr(&path, &wire), pin_is_required(f)) {
                // A required pin must be present and exact.
                (None, true) => out.push(format!("pinned {at}: required {value:?} not emitted")),
                (Some(got), _) if *got != value => {
                    out.push(format!("pinned {at}: expected {value:?}, emitted {got:?}"))
                }
                // An optional pin may be absent; it just must not contradict.
                _ => {}
            },
            None => {}
        }
    });
    out
}

/// Whether the pinned attribute must be present.
///
/// **Not** simply `f.required`. On a [`wa_ir::ParsedFieldType::Bool`] field the pin is
/// always conditional: such a field is a *presence flag* (`{hasListCDhash: m.value !=
/// null}`), so `required: true` describes the flag the parser always produces, never the
/// wire attribute it reports on — which may by construction be absent. Treating the flag
/// as the attribute would have this emitter demand an optional `c_dhash` and then compare
/// a request string against a boolean.
fn pin_is_required(f: &ParsedField) -> bool {
    f.required && f.field_type != wa_ir::ParsedFieldType::Bool
}

/// Whether a shape carries any of the constraint layer this guard exists to protect.
fn is_constrained(assertions: &[ResponseAssertion], fields: &[ParsedField]) -> bool {
    if assertions
        .iter()
        .any(|a| a.kind == AssertionKind::Reference)
    {
        return true;
    }
    let mut found = false;
    walk_pinned(fields, &[], &mut |_, _| found = true);
    found
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

    let (mut checked, mut constrained, mut pins) = (0usize, 0usize, 0usize);
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
            if is_constrained(assertions, fields) {
                constrained += 1;
            }
            walk_pinned(fields, &[], &mut |_, _| pins += 1);
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
    // `checked` alone would stay green on a regression that emptied every echo and pin:
    // thousands of `assertTag`-only shapes would still be counted. Floor the layer this
    // guard actually protects.
    assert!(
        constrained > 0 && pins > 0,
        "{checked} shape(s) carried assertions but only {constrained} carried an echo or a \
         pinned value ({pins} pins total) — the constraint layer degraded to tag-only"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} IR-built response shape(s) fail their own recorded constraints:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!(
        "round-tripped {checked} IQ response shape(s) from the IR alone \
         ({constrained} constrained, {pins} pinned field(s) exercised)"
    );
}

#[test]
fn a_hardcoded_from_fails_the_echo_rule() {
    // Negative control: without this the round-trip could pass by vacuously ignoring
    // `reference` assertions. Mirrors the real bug — answering a request addressed to
    // `g.us` with `from="s.whatsapp.net"`.
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
    let mut s = emit(&assertions, &[]);
    assert!(violations(&s, &assertions, &[]).is_empty());
    s.nodes
        .get_mut(&Vec::new())
        .expect("root")
        .insert("from".into(), "s.whatsapp.net".to_string());
    let broken = violations(&s, &assertions, &[]);
    assert_eq!(broken.len(), 1, "{broken:?}");
    assert!(broken[0].contains("reference from"), "{broken:?}");
}

#[test]
fn a_pin_on_a_nested_node_is_checked_where_it_lives() {
    // The promote bug in the file header: `type="admin"` sits on `<participant>`, not on
    // the root. A guard that only modelled the root would accept `<participant
    // type="200">` — so assert the nested pin is both emitted and verified at its own
    // path, and that a wrong value there is caught.
    let participant_type = ParsedField {
        method: "attrString".into(),
        name: "type".into(),
        wire_name: Some("type".into()),
        required: true,
        literal_value: Some("admin".into()),
        ..Default::default()
    };
    let fields = vec![
        // `<list matched="true">` — a pin reached through a `sourcePath` wrapper.
        ParsedField {
            method: "attrString".into(),
            name: "listMatched".into(),
            wire_name: Some("matched".into()),
            required: true,
            literal_value: Some("true".into()),
            source_path: Some(vec!["list".into()]),
            ..Default::default()
        },
        // `<participant type="admin">` — a pin inside a nested `child` field.
        ParsedField {
            method: "child".into(),
            name: "promoteParticipant".into(),
            tag: Some("participant".into()),
            required: true,
            children: Some(vec![participant_type]),
            ..Default::default()
        },
    ];
    let assertions = vec![ResponseAssertion {
        kind: AssertionKind::Tag,
        name: Some("iq".into()),
        value: None,
        reference_path: None,
    }];

    let mut s = emit(&assertions, &fields);
    assert!(
        violations(&s, &assertions, &fields).is_empty(),
        "the IR-built stanza must satisfy its own nested pins"
    );
    // Both pins really landed on their own nodes, not on the root.
    assert_eq!(
        s.attr(&["list".to_string()], "matched"),
        Some(&"true".to_string())
    );
    assert_eq!(
        s.attr(&["participant".to_string()], "type"),
        Some(&"admin".to_string())
    );
    assert!(s.attr(&[], "type").is_none(), "must not leak onto the root");

    // The status-code-where-the-role-goes bug is now caught.
    s.nodes
        .get_mut(&vec!["participant".to_string()])
        .expect("participant node")
        .insert("type".into(), "200".to_string());
    let broken = violations(&s, &assertions, &fields);
    assert_eq!(broken.len(), 1, "{broken:?}");
    assert!(broken[0].contains("participant/@type"), "{broken:?}");
}

#[test]
fn a_pin_on_a_presence_flag_is_never_required() {
    // `{hasListCDhash: m.value != null}` reports whether an OPTIONAL `c_dhash` attribute
    // was there; the flag itself is always produced. An emitter must be free to omit the
    // attribute — and must never be asked to compare the request's string against the
    // boolean.
    let flag = ParsedField {
        method: String::new(),
        name: "hasListCDhash".into(),
        wire_name: Some("c_dhash".into()),
        field_type: wa_ir::ParsedFieldType::Bool,
        required: true,
        reference_path: Some(vec!["item".into(), "dhash".into()]),
        ..Default::default()
    };
    let assertions = vec![ResponseAssertion {
        kind: AssertionKind::Tag,
        name: Some("iq".into()),
        value: None,
        reference_path: None,
    }];
    let fields = vec![flag];
    let s = emit(&assertions, &fields);
    assert!(
        s.attr(&[], "c_dhash").is_none(),
        "an optional attribute must not be forced onto the stanza"
    );
    assert!(
        violations(&s, &assertions, &fields).is_empty(),
        "omitting it is legal"
    );
    // Present but contradicting the request is still caught.
    let mut wrong = emit(&assertions, &fields);
    wrong
        .nodes
        .entry(Vec::new())
        .or_default()
        .insert("c_dhash".into(), "not-the-request-value".into());
    let broken = violations(&wrong, &assertions, &fields);
    assert_eq!(broken.len(), 1, "{broken:?}");
}
