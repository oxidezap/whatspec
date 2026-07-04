//! Outgoing non-IQ stanza scanning: `receipt`, `presence`, `chatstate`, `ack`.
//!
//! Reuses the IQ machinery — `parse_wap_call` for the builder shape, `attrs.rs` for
//! attribute classification (including the enum-linking), and `resolve_child_node` for
//! the child tree — but recognizes a stanza by its top-level tag instead of `<iq>`,
//! and emits the generic [`StanzaDef`] (outgoing, no response). `message` and the
//! incoming side are deliberately out of scope here.

use oxc_allocator::Allocator;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::{Visit, walk};
use wa_ir::{Direction, StanzaDef, StanzaTag, WapAttrKind};
use wa_oxc::{arg_expr, define_module_name, parse_cjs};
use wa_transform::ModuleDefinition;

use crate::alias::{AliasMap, build_alias_map};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::enum_link::EnumResolver;
use crate::helper_index::HelperIndex;
use crate::request::{VarScope, build_var_scope, resolve_child_node};

/// The outgoing fire-and-forget stanzas this scanner recognizes, by top-level tag.
/// IQ has its own path; `message` (and the incoming dispatch side) come later.
const STANZA_TAGS: &[(&str, StanzaTag)] = &[
    ("receipt", StanzaTag::Receipt),
    ("presence", StanzaTag::Presence),
    ("chatstate", StanzaTag::Chatstate),
    ("ack", StanzaTag::Ack),
];

fn stanza_tag(tag: &str) -> Option<StanzaTag> {
    STANZA_TAGS.iter().find(|(t, _)| *t == tag).map(|(_, k)| *k)
}

/// Cheap pre-filter: does this module build one of the recognized stanzas? The AST
/// re-check in the scan confirms the real tag, so a permissive substring only risks
/// re-parsing a few extra modules, never silently skipping one.
pub(crate) fn is_stanza_module(slice: &str) -> bool {
    STANZA_TAGS.iter().any(|(t, _)| {
        slice.contains(&format!(".wap(\"{t}\"")) || slice.contains(&format!(".smax(\"{t}\""))
    })
}

/// Scan every outgoing non-IQ stanza a bundle builds, with enum links resolved.
pub fn scan_stanzas_from_modules(source: &str, defs: &[ModuleDefinition]) -> Vec<StanzaDef> {
    let helpers = crate::helper_index::build_pass(defs, source);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in defs {
        let slice = &source[m.start..m.end];
        if !is_stanza_module(slice) || !seen.insert(m.name.as_str()) {
            continue;
        }
        out.extend(scan_module(slice, &helpers));
    }
    // Drop structureless stanzas (no attrs, no children, no subtype): a bare `<ack/>`
    // carries nothing a consumer can model, and these are mostly response-ack fragments
    // rather than genuine top-level builders.
    out.retain(|s| !s.attrs.is_empty() || !s.children.is_empty() || s.subtype.is_some());
    // Fill in the attribute enum links (`receipt.type` → `ENC_RETRY_RECEIPT_ATTRS`, …).
    let mut resolver = EnumResolver::new(defs, source);
    for s in &mut out {
        resolver.resolve_attrs(&mut s.attrs);
        resolver.resolve_tree(&mut s.children);
    }
    // Deterministic order independent of bundle layout.
    out.sort_by(|a, b| {
        (a.stanza_type as u8)
            .cmp(&(b.stanza_type as u8))
            .then_with(|| a.module_name.cmp(&b.module_name))
            .then_with(|| a.subtype.cmp(&b.subtype))
    });
    // A module often builds the same stanza in several code paths; emit each once.
    // Dedup by full equality rather than `dedup_by` (which only drops adjacent pairs,
    // so an interleaved `A, B, A` visit order would keep both `A`s). `n` is a few dozen
    // stanzas per bundle, so the O(n²) `contains` is negligible.
    let mut deduped: Vec<StanzaDef> = Vec::with_capacity(out.len());
    for s in out {
        if !deduped.contains(&s) {
            deduped.push(s);
        }
    }
    deduped
}

fn scan_module(source: &str, helpers: &HelperIndex) -> Vec<StanzaDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, source);
    if ret.panicked {
        return Vec::new();
    }
    let module_name = ret
        .program
        .body
        .iter()
        .find_map(define_module_name)
        .unwrap_or_default()
        .to_string();
    let scope = build_var_scope(&ret.program);
    let aliases = build_alias_map(&ret.program);
    let mut c = StanzaCollector {
        source,
        scope: &scope,
        aliases: &aliases,
        helpers,
        module_name,
        out: Vec::new(),
    };
    c.visit_program(&ret.program);
    c.out
}

struct StanzaCollector<'s> {
    source: &'s str,
    scope: &'s VarScope,
    aliases: &'s AliasMap,
    helpers: &'s HelperIndex,
    module_name: String,
    out: Vec<StanzaDef>,
}

impl<'a> Visit<'a> for StanzaCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(wap) = parse_wap_call(call, self.aliases)
            && let Some(stanza_type) = stanza_tag(wap.tag)
        {
            let attrs = wap
                .attrs_node
                .map(|n| extract_attrs_from_obj(n, self.source, self.aliases))
                .unwrap_or_default();
            // The `type` attr distinguishes stanza subtypes (`receipt type="read"`, …).
            let subtype = attrs
                .iter()
                .find(|a| a.name == "type" && a.kind == WapAttrKind::Const)
                .and_then(|a| a.value.clone());
            let mut children = Vec::new();
            for child_arg in wap.child_args {
                if let Some(ce) = arg_expr(child_arg) {
                    children.extend(resolve_child_node(
                        ce,
                        self.source,
                        self.scope,
                        self.source,
                        self.aliases,
                        None,
                        self.helpers,
                        0,
                    ));
                }
            }
            self.out.push(StanzaDef {
                stanza_type,
                direction: Direction::Outgoing,
                module_name: self.module_name.clone(),
                exported_function: None,
                all_exports: Vec::new(),
                namespace: None,
                subtype,
                target: None,
                attrs,
                children,
                response: None,
            });
            // The stanza's children are already recovered by `resolve_child_node`
            // above; don't descend into this call's args and re-capture a nested
            // builder as a second (duplicate/misparented) stanza.
            return;
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bundle: &str) -> Vec<StanzaDef> {
        let defs = wa_transform::extract_module_definitions(bundle);
        scan_stanzas_from_modules(bundle, &defs)
    }

    #[test]
    fn captures_outgoing_receipt_with_enum_linked_type() {
        // A receipt builder whose `type` attr is `CUSTOM_STRING(o("Mod").Enum.VARIANT)`,
        // plus the enum's (object-literal) definition in another module.
        let bundle = r#"
            __d("WAWebVoipSignalingEnums",[],(function(g,r,d,o,e,i,l){
                var s={SINGLE_PARTICIPANT:"enc",GROUP_CALL:"enc_rekey_retry"};
                i.ENC_RETRY_RECEIPT_ATTRS=s;
            }),98);
            __d("WAWebSendRetryReceipt",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(t){ return o("WAWap").wap("receipt",{to:o("WAWap").USER_JID(t),type:o("WAWap").CUSTOM_STRING(o("WAWebVoipSignalingEnums").ENC_RETRY_RECEIPT_ATTRS.GROUP_CALL)}); };
            }),98);
        "#;
        let stanzas = scan(bundle);
        let r = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Receipt)
            .expect("receipt captured");
        let type_attr = r
            .attrs
            .iter()
            .find(|a| a.name == "type")
            .expect("type attr");
        let er = type_attr.enum_ref.as_ref().expect("enum link resolved");
        assert_eq!(er.name, "ENC_RETRY_RECEIPT_ATTRS");
        assert_eq!(er.module, "WAWebVoipSignalingEnums");
        let vals: Vec<&str> = er.variants.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(vals, ["enc", "enc_rekey_retry"]);
    }

    #[test]
    fn captures_presence_with_children() {
        let bundle = r#"
            __d("WAWebSendPresence",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(t){ return o("WAWap").wap("presence",{type:"available"}); };
            }),98);
        "#;
        let stanzas = scan(bundle);
        let p = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Presence)
            .expect("presence captured");
        assert_eq!(p.subtype.as_deref(), Some("available"));
        assert_eq!(p.direction, Direction::Outgoing);
    }
}
