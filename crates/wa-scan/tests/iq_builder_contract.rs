//! Guard: the committed IQ IR describes WA's **builder**, not only the wire.
//!
//! There are two shapes of consumer. One encodes the stanza itself and needs to know
//! that a group create carries a `<participant jid=…>`; the IR has always said that.
//! The other runs WA's own module and needs the other half — that the value goes in
//! `args.participantArgs[].participantJid` — which no amount of wire description
//! implies, because the argument key and the attribute name are chosen independently
//! (`subjectElementValue` becomes the text of `<subject>`).
//!
//! Everything here is checked against fixtures named by RPC rather than by count, so a
//! WA refactor that moves a construct fails on the construct instead of on an integer.
//! The aggregate coverage numbers live in `manifest.diagnostics.iq.builder` and are
//! floored by the update guard; the point of this file is the specific facts a consumer
//! would build a code generator on.

use std::path::Path;

use wa_ir::{IqIr, IqStanzaDef, ParsedField, WapArgSegment, WapChildNode, WapChildPresence};

/// Load the committed IR, or skip locally when it is absent (sparse checkout) while
/// still failing under CI, where its absence would silently disable every guard here.
/// Mirrors the committed-artifact gate in `iq_roundtrip.rs`.
fn committed_ir() -> Option<IqIr> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../generated/iq/index.json");
    if !path.exists() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{} is absent under CI — the builder-contract guard would be silently skipped",
            path.display()
        );
        eprintln!("skipping: {} not present (local only)", path.display());
        return None;
    }
    let raw = std::fs::read_to_string(&path).expect("read generated/iq/index.json");
    Some(serde_json::from_str(&raw).expect("parse the committed IQ IR"))
}

fn stanza<'a>(ir: &'a IqIr, module: &str) -> &'a IqStanzaDef {
    ir.stanzas
        .iter()
        .find(|s| s.module_name == module)
        .unwrap_or_else(|| panic!("{module} vanished from the IR"))
}

/// Depth-first over a request subtree, including variant-group children.
fn nodes(node: &WapChildNode) -> Vec<&WapChildNode> {
    let mut out = vec![node];
    for c in &node.children {
        out.extend(nodes(c));
    }
    for g in &node.variant_groups {
        for v in &g.variants {
            for c in &v.children {
                out.extend(nodes(c));
            }
        }
    }
    out
}

fn request_nodes(s: &IqStanzaDef) -> Vec<&WapChildNode> {
    s.request.children.iter().flat_map(nodes).collect()
}

fn find<'a>(s: &'a IqStanzaDef, tag: &str) -> &'a WapChildNode {
    request_nodes(s)
        .into_iter()
        .find(|n| n.tag == tag)
        .unwrap_or_else(|| panic!("<{tag}> vanished from {}", s.module_name))
}

fn path(segments: &[WapArgSegment]) -> Vec<(&str, bool)> {
    segments.iter().map(|s| (s.key.as_str(), s.list)).collect()
}

#[test]
fn a_group_rename_carries_the_name() {
    // The narrowest possible statement of the element-value gap: `SetSubject`'s entire
    // payload is the text of `<subject>`, and the builder reads it out of the argument
    // object before writing it. Without the content the IR describes a request that
    // renames a group to nothing.
    let Some(ir) = committed_ir() else { return };
    let s = stanza(&ir, "WASmaxOutGroupsSetSubjectRequest");
    let subject = find(s, "subject");
    let content = subject
        .content
        .as_ref()
        .expect("`<subject>` carries its element value");
    assert_eq!(
        path(content.arg_path.as_deref().unwrap_or_default()),
        vec![("subjectElementValue", false)],
        "and says which argument fills it"
    );
}

#[test]
fn a_repeated_child_is_indexed_and_an_optional_one_is_not() {
    // The two live side by side in one builder, which is why they are asserted
    // together: `REPEATED_CHILD` runs its template once per element, `OPTIONAL_CHILD`
    // hands the object over whole. Reading one as the other writes the value somewhere
    // the vendor builder never looks, and the stanza goes out missing it.
    let Some(ir) = committed_ir() else { return };
    let s = stanza(&ir, "WASmaxOutGroupsCreateRequest");

    let participant = find(s, "participant");
    assert!(participant.repeats);
    assert_eq!(
        path(participant.arg_path.as_deref().unwrap_or_default()),
        vec![("participantArgs", true)]
    );
    let jid = participant
        .attrs
        .iter()
        .find(|a| a.name == "jid")
        .expect("participant jid");
    assert_eq!(
        path(jid.arg_path.as_deref().unwrap_or_default()),
        vec![("participantArgs", true), ("participantJid", false)],
        "the list is indexed, the key read off an element is not"
    );

    let description = find(s, "description");
    assert_eq!(description.presence, WapChildPresence::Optional);
    let id = description
        .attrs
        .iter()
        .find(|a| a.name == "id")
        .expect("description id");
    assert_eq!(
        path(id.arg_path.as_deref().unwrap_or_default()),
        vec![("descriptionArgs", false), ("descriptionId", false)]
    );
    assert!(
        description
            .arg_path
            .iter()
            .flatten()
            .chain(id.arg_path.iter().flatten())
            .all(|seg| !seg.list),
        "nothing under an OPTIONAL_CHILD may be indexed"
    );
}

#[test]
fn the_three_cardinalities_are_distinguishable_on_a_real_request() {
    // `<locked/>`, `<description/>` and `<participant/>` are three children of one
    // `<create>`. On the wire the first is an empty element; in the IR it used to be
    // the same `{tag, [], []}` as a required empty one, so a consumer had no way to
    // learn it is the `bool` argument `hasLocked`.
    let Some(ir) = committed_ir() else { return };
    let s = stanza(&ir, "WASmaxOutGroupsCreateRequest");

    let locked = request_nodes(s)
        .into_iter()
        .find(|n| n.tag == "locked" && n.presence == WapChildPresence::PresenceFlag)
        .expect("<locked> is a presence marker");
    assert!(locked.attrs.is_empty() && locked.content.is_none());
    assert_eq!(
        path(locked.arg_path.as_deref().unwrap_or_default()),
        vec![("hasLocked", false)],
        "a marker addresses its boolean, not an argument object"
    );

    assert_eq!(find(s, "description").presence, WapChildPresence::Optional);
    assert_eq!(find(s, "participant").presence, WapChildPresence::Required);
}

#[test]
fn repeat_bounds_are_carried_where_the_builder_states_them() {
    // The server enforces these; a consumer that generates a plain `Vec<T>` finds the
    // ceiling by being rejected. Named RPCs rather than a count, so a WA change to one
    // limit is reported as that limit rather than as a smaller total.
    let Some(ir) = committed_ir() else { return };
    let bounded: Vec<_> = ir
        .stanzas
        .iter()
        .flat_map(request_nodes)
        .filter(|n| n.repeats)
        .filter_map(|n| Some((n.tag.as_str(), n.repeat_min?, n.repeat_max?)))
        .collect();
    for expected in [
        ("participant", 1u32, 1024u32),
        ("participant", 1, 19999),
        ("group", 1, 10000),
        ("media_list", 0, 10),
    ] {
        assert!(
            bounded.contains(&expected),
            "{expected:?} is no longer stated; have {bounded:?}"
        );
    }
    // An unbounded maximum (`1/0` in the bundle) keeps its minimum, which is what makes
    // "at least n, no ceiling" distinguishable from a child that states no bound at all.
    assert!(
        ir.stanzas
            .iter()
            .flat_map(request_nodes)
            .any(|n| n.repeats && n.repeat_min.is_some() && n.repeat_max.is_none()),
        "no explicitly unbounded repeated child left"
    );
}

#[test]
fn every_combinator_child_of_a_smax_builder_is_addressable() {
    // The coverage claim, stated where it is true rather than globally: every child a
    // `WASmaxOut*Request` builds through a `WASmaxChildren` combinator, and every
    // attribute and content under one, knows which argument fills it.
    //
    // The legacy `WAWeb*Job` builders are deliberately out: they take positional
    // parameters, so a bare key would name a property without naming which parameter it
    // hangs off. They are counted in `manifest.diagnostics.iq.builder`, not addressed.
    let Some(ir) = committed_ir() else { return };
    let mut missing = Vec::new();
    for s in ir
        .stanzas
        .iter()
        .filter(|s| s.module_name.starts_with("WASmaxOut") && s.module_name.ends_with("Request"))
    {
        for n in request_nodes(s) {
            if n.is_combinator_fed() && n.arg_path.is_none() {
                missing.push(format!("{}: <{}> node", s.module_name, n.tag));
            }
            // Variant-group attributes included. Walking only `n.attrs` made this pass
            // by not looking: the seven unaddressed attributes below all live inside a
            // disjunction, and the claim read as though it covered them.
            let variant_attrs = n
                .variant_groups
                .iter()
                .flat_map(|g| &g.variants)
                .flat_map(|v| &v.attrs);
            for a in n.attrs.iter().chain(variant_attrs) {
                // `reads_argument`/`is_combinator_fed` are the IR's own predicates, so
                // this test and the `diagnostics.iq.builder` counters cannot drift into
                // measuring different things — one rule written twice is the defect this
                // batch keeps finding.
                if a.reads_argument() && a.arg_path.is_none() {
                    missing.push(format!("{}: <{}> @{}", s.module_name, n.tag, a.name));
                }
            }
            if let Some(c) = &n.content
                && c.reads_argument()
                && c.arg_path.is_none()
            {
                missing.push(format!("{}: <{}> content", s.module_name, n.tag));
            }
        }
    }
    // No exemption. `PushConfigSet` used to be one — it hands its mixin a sub-object
    // rather than the whole argument object, and the by-module-name mixin closure had no
    // call site to rebase what that returned. The closure now carries each merge call's
    // argument, so those attributes are addressed like every other.
    assert!(missing.is_empty(), "unaddressable: {missing:?}");
}

#[test]
fn a_runtime_addressee_says_which_argument_supplies_it() {
    // `target` says this request goes to one group's own JID rather than to a server.
    // That is half an instruction: a consumer running the vendor builder still has to know
    // where the JID goes. Both are needed, and the second is recoverable — including
    // through a mixin group, where the path composes across the fold.
    let Some(ir) = committed_ir() else { return };
    let path_of = |name: &str| -> Option<Vec<String>> {
        ir.stanzas
            .iter()
            .find(|s| s.module_name == name)
            .and_then(|s| s.request.target_arg_path.as_ref())
            .map(|p| p.iter().map(|x| x.key.clone()).collect())
    };
    assert_eq!(
        path_of("WASmaxOutGroupsGetGroupInfoRequest").as_deref(),
        Some(["iqTo".to_string()].as_slice()),
        "a group request addresses the group it is about"
    );
    // And a request whose addressee comes from a runtime ROUTER names none. Its two arms
    // address a group's own JID and the group server; the union already reports `unknown`
    // for which, and one arm's key is not the request's answer. The composition works —
    // the path resolves to `baseGetGroupOrServerMixinGroupArgs → baseGetGroup → iqTo`
    // before the disagreement withdraws it — which is why the withdrawal is deliberate
    // rather than a gap.
    assert!(
        path_of("WASmaxOutGroupsGetGroupProfilePicturesRequest").is_none(),
        "a disagreement about which addressee is one about its address"
    );
    // A constant addressee has nothing to supply, so it names nothing.
    assert!(
        path_of("WASmaxOutGroupsCreateRequest").is_none(),
        "the group server is a constant, not an argument"
    );
}

#[test]
fn a_pinned_constant_payload_keeps_its_address() {
    // `<link_code_pairing_nonce>` is one byte of zero at every call site, which is how
    // `constBytes` got there. That does not make it builder-written: the payload is still
    // read from an argument, so it keeps the address a consumer has to write that byte
    // at. Dropping either fact leaves a caller unable to make the request — one without
    // knowing where, the other without knowing what.
    let Some(ir) = committed_ir() else { return };
    let s = ir
        .stanzas
        .iter()
        .find(|s| s.module_name == "WASmaxOutMdCompanionHelloRequest")
        .expect("the companion hello request");
    let nonce = request_nodes(s)
        .into_iter()
        .find(|n| n.tag == "link_code_pairing_nonce")
        .expect("the nonce element");
    let c = nonce.content.as_ref().expect("content");
    assert_eq!(c.const_bytes.as_deref(), Some("00"));
    assert_eq!(
        c.arg_path
            .as_ref()
            .map(|p| p.iter().map(|s| s.key.as_str()).collect::<Vec<_>>()),
        Some(vec![
            "linkCodePairingNonceArgs",
            "linkCodePairingNonceElementValue"
        ]),
        "pinned, not written: the argument is still there"
    );
    assert!(c.reads_argument(), "and the IR's own predicate says so");
}

#[test]
fn a_key_bundle_fetch_descends_into_its_union() {
    // `PreKeysFetchKeyBundles` is how every client gets the keys to send a first
    // message, and its whole payload sits inside a `…MixinGroup` disjunction. A field
    // that names a union and carries no alternatives is a leaf that looks like a
    // scalar: a consumer reads a string, gets nothing, and cannot tell what it missed.
    let Some(ir) = committed_ir() else { return };
    let s = stanza(&ir, "WASmaxOutPreKeysFetchKeyBundlesRequest");

    fn fields(f: &ParsedField) -> Vec<&ParsedField> {
        let mut out = vec![f];
        for c in f.children.iter().flatten() {
            out.extend(fields(c));
        }
        for v in f.union_variants.iter().flatten() {
            for inner in &v.fields {
                out.extend(fields(inner));
            }
        }
        out
    }
    let all: Vec<&ParsedField> = s
        .response
        .variants
        .iter()
        .flat_map(|v| v.fields.iter().flat_map(fields))
        .collect();

    let group = all
        .iter()
        .find(|f| f.name.ends_with("MixinGroup"))
        .expect("the key-bundle disjunction is still modelled");
    let arms = group
        .union_variants
        .as_ref()
        .expect("a union names its alternatives, rather than reading as a scalar");
    assert!(arms.len() >= 2, "a union with {} arm(s)", arms.len());
    // Discriminated, not flattened: each arm keeps its own name, so a consumer generates
    // a real sum type instead of a struct where every field is optional.
    assert!(
        arms.iter().any(|a| a.name.contains("Success"))
            && arms.iter().any(|a| !a.fields.is_empty()),
        "arms: {:?}",
        arms.iter().map(|a| &a.name).collect::<Vec<_>>()
    );

    // …and the invariant behind it, across every response in the IR.
    for f in ir
        .stanzas
        .iter()
        .flat_map(|s| &s.response.variants)
        .flat_map(|v| v.fields.iter().flat_map(fields))
    {
        assert!(
            !f.name.ends_with("MixinGroup")
                || f.union_variants.as_ref().is_some_and(|v| !v.is_empty())
                || f.children.as_ref().is_some_and(|c| !c.is_empty()),
            "{}: a mixin group with no alternatives and no children",
            f.name
        );
    }
}
