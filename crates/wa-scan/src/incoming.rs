//! Incoming stanza read-shape scanning: the field trees WA Web parses out of
//! *received* content stanzas (`message`/`receipt`/`call`/`ack`/…).
//!
//! Two mechanisms feed this catalog:
//! * **Legacy** — most received stanzas are read by a `new WADeprecatedWapParser("…", fn)`
//!   whose body (`assertTag`, `attrString`, `mapChildrenWithTag`, …) `response.rs`
//!   reconstructs into a [`ParsedResponse`]. We keep only the parsers that assert a
//!   *content* tag; `notification` (notif domain), `iq` (iq domain), and stream-control
//!   tags (`success`/`failure`/`error`/`ib`/…) are filtered out.
//! * **smax** — the `<ack>` a client publish/send receives back is parsed by the newer
//!   `WASmaxParseUtils` railway (`WASmaxInMessagePublish*Response{Success,Negative}`), not
//!   the legacy parser. We recover those roots with the shared [`analyze_module_exports`]
//!   machinery (the same the srvreq/iq domains use), folding the ack envelope + paid/edit
//!   /revoke sub-mixins and disjunctions in via the [`Resolver`].
//!
//! [`ParsedResponse`]: wa_ir::iq::ParsedResponse

use std::collections::{HashMap, HashSet};

use wa_ir::{AssertionKind, IncomingDef, IncomingTag};
use wa_transform::ModuleDefinition;

use crate::enum_link::ResponseEnumLinker;
use crate::response::parse_module_wap_parsers;
use crate::response_smax::{Resolver, analyze_module_exports};

/// The stanza tags whose incoming read-shape this domain catalogs — content stanzas
/// only. `None` for everything else (notification/iq/stream-control), which drops it.
/// Only tags an actual parser asserts are listed (no speculative entries).
fn incoming_tag(tag: &str) -> Option<IncomingTag> {
    Some(match tag {
        "message" => IncomingTag::Message,
        "receipt" => IncomingTag::Receipt,
        "call" => IncomingTag::Call,
        "ack" => IncomingTag::Ack,
        _ => return None,
    })
}

/// Scan every received-stanza read-shape a bundle defines: each
/// `new WADeprecatedWapParser("…", fn)` whose body asserts a content tag, with its
/// field tree recovered.
pub fn scan_incoming_from_modules(source: &str, defs: &[ModuleDefinition]) -> Vec<IncomingDef> {
    scan_incoming_with_diagnostics(source, defs).0
}

/// Like [`scan_incoming_from_modules`], but also returns the constraints the legacy
/// parsers carried and this domain could not resolve, by `dropsByReason` key.
///
/// The counts existed only for IQ, so an unresolvable enum table in a received-stanza
/// parser produced a field with no legal values and no signal anywhere that a constraint
/// had been lost — exactly the distinction the pending marker was introduced to keep.
pub fn scan_incoming_with_diagnostics(
    source: &str,
    defs: &[ModuleDefinition],
) -> (Vec<IncomingDef>, std::collections::BTreeMap<String, usize>) {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // The legacy parser records `o("Mod").ENUM` as a pending link because it reads one
    // module at a time; this domain has the whole bundle, so it runs the same
    // cross-module post-pass the IQ scan does. Without it the links were simply lost —
    // `message.type`'s `STANZA_MSG_TYPES` and `ALL_NONE` among them.
    let mut enums = ResponseEnumLinker::new(defs, source);
    for m in defs {
        let slice = &source[m.start..m.end];
        // Cheap pre-filter; the AST parse in `parse_module_wap_parsers` confirms the
        // real parser. `seen` skips a module re-declared later in the bundle.
        if !slice.contains("WADeprecatedWapParser") || !seen.insert(m.name.as_str()) {
            continue;
        }
        for mut shape in parse_module_wap_parsers(slice) {
            enums.resolve(&format!("{}::{}", m.name, shape.parser_name), &mut shape);
            // The parser's `assertTag("…")` is the received stanza's tag.
            // `assertTag("receipt")` stores the tag in the assertion's `name`.
            let tag = shape
                .assertions
                .iter()
                .find(|a| a.kind == AssertionKind::Tag)
                .and_then(|a| a.name.as_deref())
                .and_then(incoming_tag);
            if let Some(tag) = tag {
                out.push(IncomingDef {
                    tag,
                    module: m.name.clone(),
                    shape,
                });
            }
        }
    }
    // The smax-parsed `<ack>` read-shapes (a client publish's server ack) — a distinct
    // mechanism the legacy pass above never sees. Merged into the same catalog.
    out.extend(scan_incoming_smax_acks(source, defs));
    // Deterministic order, independent of bundle layout; then drop exact
    // (tag, parser, module) duplicates (a parser re-declared verbatim).
    out.sort_by(|a, b| {
        (a.tag as u8)
            .cmp(&(b.tag as u8))
            .then_with(|| a.shape.parser_name.cmp(&b.shape.parser_name))
            .then_with(|| a.module.cmp(&b.module))
    });
    out.dedup_by(|a, b| {
        a.tag == b.tag && a.module == b.module && a.shape.parser_name == b.shape.parser_name
    });
    (out, enums.into_drop_counts())
}

/// A `WASmaxIn*Response{Success,Negative}` module whose root reads a top-level `<ack>` —
/// the structured acknowledgement the server returns for a client publish/send (the
/// `WASmaxInMessagePublish*` family). iq responses live in `…Response*` modules too but
/// assert `iq`, so the `ack` tag gate in [`scan_incoming_smax_acks`] drops them; `…Mixin`
/// fragments are folded into a root, never catalogued standalone.
fn is_smax_ack_response_module(name: &str) -> bool {
    name.starts_with("WASmaxIn")
        && (name.ends_with("ResponseSuccess") || name.ends_with("ResponseNegative"))
        && !name.contains("Mixin")
}

/// Recover the smax `<ack>` read-shapes: each `WASmaxIn*Response{Success,Negative}` root
/// that asserts the top-level `ack`, with its field tree (ack envelope + edit/revoke/paid
/// sub-mixins and disjunctions) resolved through the shared [`Resolver`]. Mirrors the
/// srvreq root pass; only the tag gate (`ack`, not the server-request set) differs.
fn scan_incoming_smax_acks(source: &str, defs: &[ModuleDefinition]) -> Vec<IncomingDef> {
    // Every module name → slice (first occurrence wins; shard dedup) so the resolver can
    // chase the cross-module ack mixins these roots fold in.
    let mut slices: HashMap<&str, &str> = HashMap::new();
    for m in defs {
        slices
            .entry(m.name.as_str())
            .or_insert(&source[m.start..m.end]);
    }
    let resolver = Resolver::new(&slices);

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in defs {
        if !is_smax_ack_response_module(&m.name) || !seen.insert(m.name.as_str()) {
            continue;
        }
        let exports = analyze_module_exports(&source[m.start..m.end], &resolver);
        for (name, shape) in &exports {
            // Skip inner child parsers: their export name extends another export's at a
            // word boundary (`<root><ChildSuffix>`), and their fields already nest in the
            // root's tree (mirrors the srvreq root selection).
            let is_child = exports.iter().any(|(other, _)| {
                other != name
                    && name
                        .strip_prefix(other.as_str())
                        .is_some_and(|suffix| suffix.starts_with(char::is_uppercase))
            });
            if is_child {
                continue;
            }
            // Only a root asserting the top-level `<ack>`; anything else (an iq response,
            // a child-element tag) is dropped.
            let is_ack = shape
                .assertions
                .iter()
                .any(|a| a.kind == AssertionKind::Tag && a.name.as_deref() == Some("ack"));
            if !is_ack {
                continue;
            }
            let mut shape = shape.clone();
            // A same-node mixin can re-assert the `ack` tag its caller already checked;
            // collapse exact duplicates, keeping first (mirrors srvreq).
            let mut deduped = Vec::with_capacity(shape.assertions.len());
            for a in std::mem::take(&mut shape.assertions) {
                if !deduped.contains(&a) {
                    deduped.push(a);
                }
            }
            shape.assertions = deduped;
            out.push(IncomingDef {
                tag: IncomingTag::Ack,
                module: m.name.clone(),
                shape,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bundle: &str) -> Vec<IncomingDef> {
        let defs = wa_transform::extract_module_definitions(bundle);
        scan_incoming_from_modules(bundle, &defs)
    }

    #[test]
    fn captures_incoming_receipt_read_shape() {
        // The real bundle shape: `new(r("WADeprecatedWapParser"))("name", fn)`.
        let bundle = r#"
            __d("WAWebHandleMsgReceiptParser",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                var c=new(r("WADeprecatedWapParser"))("incomingMsgReceiptParser",function(e){
                    e.assertTag("receipt");
                    var t=e.attrString("type");
                    return {type:t};
                });
            }),1);
        "#;
        let got = scan(bundle);
        let r = got
            .iter()
            .find(|d| d.tag == IncomingTag::Receipt)
            .expect("receipt read-shape captured");
        assert_eq!(r.shape.parser_name, "incomingMsgReceiptParser");
        assert_eq!(r.module, "WAWebHandleMsgReceiptParser");
    }

    #[test]
    fn captures_smax_ack_response_shape() {
        // A `WASmaxIn*Publish*Response{Success,Negative}` root asserting `<ack>` is
        // catalogued (tag Ack) with its ack-envelope mixin folded in. An iq `…Response*`
        // (asserts `iq`) is dropped by the ack gate; a `…Mixin` is never standalone.
        let bundle = r#"
            __d("WASmaxInFooPublishAckMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
                function e(e){var t=o("WASmaxParseUtils").assertTag(e,"ack");if(!t.success)return t;var n=o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString,e,"class","message");if(!n.success)return n;var r=o("WASmaxParseUtils").attrIntRange(e,"t",0,void 0);return r.success?o("WAResultOrError").makeResult({class:n.value,t:r.value}):r;}
                l.parseAckMixin=e;
            }),1);
            __d("WASmaxInFooPublishFooResponseSuccess",["WASmaxParseUtils","WASmaxInFooPublishAckMixin","WAResultOrError"],(function(t,n,r,o,a,i,l){
                function e(e,t){var n=o("WASmaxParseUtils").assertTag(e,"ack");if(!n.success)return n;var r=o("WASmaxInFooPublishAckMixin").parseAckMixin(e);if(!r.success)return r;return o("WAResultOrError").makeResult(babelHelpers.extends({},r.value));}
                l.parseFooResponseSuccess=e;
            }),1);
            __d("WASmaxInBarGetBarResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
                function e(e){var t=o("WASmaxParseUtils").assertTag(e,"iq");if(!t.success)return t;return o("WAResultOrError").makeResult({});}
                l.parseBarResponseSuccess=e;
            }),1);
        "#;
        let got = scan(bundle);
        // Only the ack-asserting Publish response survives — not the iq response, not the mixin.
        assert_eq!(got.len(), 1, "{got:?}");
        let a = &got[0];
        assert_eq!(a.tag, IncomingTag::Ack);
        assert_eq!(a.module, "WASmaxInFooPublishFooResponseSuccess");
        assert_eq!(a.shape.parser_name, "parseFooResponseSuccess");
        // The ack envelope mixin is folded in: `class` + `t` fields, `class="message"` pinned.
        assert!(a.shape.fields.iter().any(|f| f.name == "class"));
        assert!(a.shape.fields.iter().any(|f| f.name == "t"));
        assert!(
            a.shape
                .assertions
                .iter()
                .any(|x| x.kind == AssertionKind::Attr
                    && x.name.as_deref() == Some("class")
                    && x.value.as_deref() == Some("message")),
            "required ack envelope discriminator bubbles: {:?}",
            a.shape.assertions
        );
    }

    #[test]
    fn excludes_notification_and_iq_parsers() {
        // `notification` (notif domain) and `iq` (iq domain) read-shapes are out of
        // scope; only content tags are catalogued.
        let bundle = r#"
            __d("WAWebHandleFooNotification",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                var c=new(r("WADeprecatedWapParser"))("incomingFooNotification",function(e){
                    e.assertTag("notification"); return {};
                });
            }),1);
            __d("WAWebSomeIqParser",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                var c=new(r("WADeprecatedWapParser"))("someIqParser",function(e){
                    e.assertTag("iq"); return {};
                });
            }),1);
            __d("WAWebHandleCall",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                var c=new(r("WADeprecatedWapParser"))("callParser",function(e){
                    e.assertTag("call"); return {};
                });
            }),1);
        "#;
        let got = scan(bundle);
        // Only the `call` content tag survives; notification and iq are dropped.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].tag, IncomingTag::Call);
        assert_eq!(got[0].shape.parser_name, "callParser");
    }
}
