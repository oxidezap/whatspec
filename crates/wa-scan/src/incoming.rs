//! Incoming stanza read-shape scanning: the field trees WA Web parses out of
//! *received* content stanzas (`message`/`receipt`/`call`/`ack`/…).
//!
//! Reuses the legacy response machinery wholesale — every received stanza is read by a
//! `new WADeprecatedWapParser("…", fn)` whose body (`assertTag`, `attrString`,
//! `mapChildrenWithTag`, …) `response.rs` already reconstructs into a [`ParsedResponse`].
//! We keep only the parsers that assert a *content* tag; `notification` (notif domain),
//! `iq` (iq domain), and stream-control tags (`success`/`failure`/`error`/`ib`/…) are
//! filtered out — the first two are catalogued elsewhere, the last carry no decodable
//! content shape.

use std::collections::HashSet;

use wa_ir::{AssertionKind, IncomingDef, IncomingTag};
use wa_transform::ModuleDefinition;

use crate::response::parse_module_wap_parsers;

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
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in defs {
        let slice = &source[m.start..m.end];
        // Cheap pre-filter; the AST parse in `parse_module_wap_parsers` confirms the
        // real parser. `seen` skips a module re-declared later in the bundle.
        if !slice.contains("WADeprecatedWapParser") || !seen.insert(m.name.as_str()) {
            continue;
        }
        for shape in parse_module_wap_parsers(slice) {
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
