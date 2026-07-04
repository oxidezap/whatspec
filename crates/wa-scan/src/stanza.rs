//! Outgoing non-IQ stanza scanning: `message`, `receipt`, `presence`, `chatstate`,
//! `ack`.
//!
//! Reuses the IQ machinery — `parse_wap_call` for the builder shape, `attrs.rs` for
//! attribute classification (including the enum-linking), and `resolve_child_node` for
//! the child tree — but recognizes a stanza by its top-level tag instead of `<iq>`,
//! and emits the generic [`StanzaDef`] (outgoing, no response). Fragment `merge…Mixin`
//! modules are dropped (as in the IQ scan). The incoming side is out of scope here.

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

/// The outgoing stanzas this scanner recognizes, by top-level tag. IQ has its own
/// path; the incoming dispatch side comes later.
const STANZA_TAGS: &[(&str, StanzaTag)] = &[
    ("message", StanzaTag::Message),
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
    // Tolerate either quote style on the tag (`"receipt"` / `'receipt'`), matching the
    // IQ pre-filter — a single-quoted builder must not be silently skipped.
    STANZA_TAGS.iter().any(|(t, _)| {
        slice.contains(&format!(".wap(\"{t}\""))
            || slice.contains(&format!(".smax(\"{t}\""))
            || slice.contains(&format!(".wap('{t}'"))
            || slice.contains(&format!(".smax('{t}'"))
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
    // Drop structureless stanzas (no attrs, no children, no subtype) — a bare `<ack/>`
    // carries nothing a consumer can model. (Fragment `merge…Mixin` modules are already
    // dropped whole in `scan_module`.)
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
        current_export: None,
        exports: Vec::new(),
        out: Vec::new(),
    };
    c.visit_program(&ret.program);
    // A module whose function exports are all `merge…Mixin` is a fragment: its stanzas
    // are partials folded into real ones via `mergeStanzas`, not top-level builders (the
    // `smax` sits in an inner un-exported helper, so this is judged per-module, not per
    // call). The IQ scanner drops these the same way.
    if is_fragment_module(&c.exports) {
        return Vec::new();
    }
    c.out
}

/// Whether a module's exports are only `merge…Mixin` combinators — a stanza fragment.
/// Ignores constants (ALL_CAPS) and `default`, matching the IQ fragment heuristic.
fn is_fragment_module(exports: &[String]) -> bool {
    let functions: Vec<&str> = exports
        .iter()
        .map(String::as_str)
        .filter(|e| *e != "default" && !e.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .collect();
    !functions.is_empty()
        && functions
            .iter()
            .all(|e| e.starts_with("merge") && e.contains("Mixin"))
}

struct StanzaCollector<'s> {
    source: &'s str,
    scope: &'s VarScope,
    aliases: &'s AliasMap,
    helpers: &'s HelperIndex,
    module_name: String,
    /// The `l.<name> = …` export whose body the current call sits in, so an emitted
    /// stanza records the function that built it.
    current_export: Option<String>,
    /// Every `l.<name> = …` export name, to classify a whole module as a fragment.
    exports: Vec<String>,
    out: Vec<StanzaDef>,
}

impl<'a> Visit<'a> for StanzaCollector<'_> {
    fn visit_assignment_expression(&mut self, assign: &oxc_ast::ast::AssignmentExpression<'a>) {
        let export = assign
            .left
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            .filter(|p| *p != "__esModule" && *p != "prototype")
            .map(str::to_string);
        let prev = self.current_export.clone();
        if let Some(e) = &export {
            self.exports.push(e.clone());
            self.current_export = export.clone();
        }
        walk::walk_assignment_expression(self, assign);
        self.current_export = prev;
    }

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
                exported_function: self.current_export.clone(),
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

    #[test]
    fn captures_message_with_enc_child_enum_linked() {
        // A message with an `<enc type=CiphertextType.Skmsg>` child — the enc.type link
        // resolves through the child tree (FORM A), against the enum in another module.
        let bundle = r#"
            __d("WAWebBackendJobs.flow",["$InternalEnum"],(function(g,n,d,o,e,i,l){
                i.CiphertextType=n("$InternalEnum")({Skmsg:"skmsg",Pkmsg:"pkmsg"});
            }),1);
            __d("WAWebSendMsgJob",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(t){ return o("WAWap").wap("message",{id:o("WAWap").CUSTOM_STRING(t)}, o("WAWap").wap("enc",{type:o("WAWap").CUSTOM_STRING(o("WAWebBackendJobs.flow").CiphertextType.Skmsg)})); };
            }),1);
        "#;
        let stanzas = scan(bundle);
        let m = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Message)
            .expect("message captured");
        let enc = m
            .children
            .iter()
            .find(|c| c.tag == "enc")
            .expect("enc child");
        let er = enc.attrs[0].enum_ref.as_ref().expect("enc.type linked");
        assert_eq!(er.name, "CiphertextType");
        assert_eq!(
            er.variants
                .iter()
                .map(|v| v.value.as_str())
                .collect::<Vec<_>>(),
            ["skmsg", "pkmsg"]
        );
    }

    #[test]
    fn merge_mixin_fragment_module_is_dropped() {
        // A module whose only function export is a `merge…Mixin` combinator is a
        // fragment (its stanza is folded into a real one), so it emits nothing.
        let bundle = r#"
            __d("WASmaxOutFooMixin",["WASmaxJsx","WASmaxMixins"],(function(t,n,r,o,a,i,l){
                function e(){ return o("WASmaxJsx").smax("receipt",{type:"read"}); }
                function s(t){ return o("WASmaxMixins").mergeStanzas(t,e()); }
                l.mergeFooMixin=s;
            }),1);
        "#;
        assert!(
            scan(bundle).is_empty(),
            "fragment module must emit no stanza"
        );
        assert!(is_fragment_module(&["mergeFooMixin".into()]));
        assert!(!is_fragment_module(&["sendReceipt".into()]));
        // Constants alongside the mixin don't disqualify it.
        assert!(is_fragment_module(&[
            "mergeFooMixin".into(),
            "SOME_CONST".into()
        ]));
    }
}
