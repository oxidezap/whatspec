//! Outgoing non-IQ stanza scanning: `message`, `receipt`, `presence`, `chatstate`,
//! `ack`.
//!
//! Reuses the IQ machinery — `parse_wap_call` for the builder shape, `attrs.rs` for
//! attribute classification (including the enum-linking), and `resolve_child_node` for
//! the child tree — but recognizes a stanza by its top-level tag instead of `<iq>`,
//! and emits the generic [`StanzaDef`] (outgoing, no response). Fragment `merge…Mixin`
//! modules are dropped (as in the IQ scan). The incoming side is out of scope here.

use std::collections::HashSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentExpression, CallExpression, Function};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use wa_ir::{Direction, StanzaDef, StanzaTag, WapAttrKind};
use wa_oxc::{arg_expr, as_identifier, define_module_name, parse_cjs};
use wa_transform::ModuleDefinition;

use crate::alias::{AliasMap, build_alias_map};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::enum_link::EnumResolver;
use crate::helper_index::HelperIndex;
use crate::request::{
    VarScope, annotate_attr_arg_paths, build_var_scope, enforce_argument_boundary,
    resolve_child_node,
};

/// The outgoing stanzas this scanner recognizes, by top-level tag. IQ has its own
/// path; the incoming dispatch side comes later.
const STANZA_TAGS: &[(&str, StanzaTag)] = &[
    ("message", StanzaTag::Message),
    ("receipt", StanzaTag::Receipt),
    ("presence", StanzaTag::Presence),
    ("chatstate", StanzaTag::Chatstate),
    ("ack", StanzaTag::Ack),
    ("call", StanzaTag::Call),
    ("status", StanzaTag::Status),
    ("privacy", StanzaTag::Privacy),
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
    // carries nothing a consumer can model. Fragment `merge…Mixin` modules are kept and
    // marked via `StanzaDef::fragment` in `scan_module`, so they're only dropped here if
    // genuinely structureless.
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
    // Dedup on the STRUCTURAL fields (tag/module/subtype/attrs/children), not full
    // equality — the same shape can be built under two different exports, so comparing
    // `exported_function`/`all_exports` would leak duplicates. `dedup_by` won't do (it
    // only drops adjacent pairs); `n` is a few dozen per bundle so the O(n²) is fine.
    let mut deduped: Vec<StanzaDef> = Vec::with_capacity(out.len());
    for s in out {
        let dup = deduped.iter().any(|d| {
            d.stanza_type == s.stanza_type
                && d.module_name == s.module_name
                && d.subtype == s.subtype
                && d.attrs == s.attrs
                && d.children == s.children
        });
        if !dup {
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
        factory_params: HashSet::new(),
        out: Vec::new(),
    };
    c.visit_program(&ret.program);
    // A module whose function exports are all `merge…Mixin` is a fragment: its stanzas
    // are partials folded into real ones via `mergeStanzas`, not top-level builders (the
    // `smax` sits in an inner un-exported helper, so this is judged per-module, not per
    // call). We keep them, marked `fragment`, so the message/receipt content-type mixin
    // catalog (`{type:"reaction"}`, `{type:"media"}`, …) is captured rather than dropped;
    // a consumer building a sendable stanza filters them out.
    let fragment = is_fragment_module(&c.exports);
    // Record the module's exports on each emitted stanza (matches the IQ scanner).
    let all_exports = c.exports;
    for s in &mut c.out {
        s.all_exports = all_exports.clone();
        s.fragment = fragment;
    }
    c.out
}

/// Whether a module exports a `merge…Mixin` combinator — a stanza fragment. `any`, not
/// `all` (and matching the IQ scanner, `wa-scan::module`): a genuine mixin often exports
/// a `merge…Mixin` *alongside* a `make…` helper, so requiring every export to be a mixin
/// would misclassify it as a standalone sendable stanza. `merge…Mixin` is WA's exclusive
/// cross-module mixin-export convention, so a real standalone builder never carries one.
/// Ignores constants (ALL_CAPS) and `default`.
fn is_fragment_module(exports: &[String]) -> bool {
    exports
        .iter()
        .map(String::as_str)
        .filter(|e| *e != "default" && !e.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .any(|e| e.starts_with("merge") && e.contains("Mixin"))
}

struct StanzaCollector<'s> {
    source: &'s str,
    scope: &'s VarScope,
    aliases: &'s AliasMap,
    helpers: &'s HelperIndex,
    module_name: String,
    /// The `<exports>.<name> = …` export whose body the current call sits in, so an
    /// emitted stanza records the function that built it.
    current_export: Option<String>,
    /// Every export name (`<exports>.<name> = …`), to classify a module as a fragment.
    exports: Vec<String>,
    /// The module factory's parameter names (`function(g,r,d,o,e,i,l){…}`). An
    /// assignment is only an export when its object is one of these (`l.foo = …`), not
    /// a write to a local object (`cache.key = …`), which would otherwise pollute
    /// `exports` and misclassify a fragment.
    factory_params: HashSet<String>,
    out: Vec<StanzaDef>,
}

impl<'a> Visit<'a> for StanzaCollector<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        // The first function is the module factory; record its params so exports are
        // recognized by their binding.
        if self.factory_params.is_empty() {
            for p in &func.params.items {
                for id in p.pattern.get_binding_identifiers() {
                    self.factory_params.insert(id.name.to_string());
                }
            }
        }
        walk::walk_function(self, func, flags);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        // An export is `<factoryParam>.<name> = …` (e.g. `l.foo = …`) — not a write to a
        // local object.
        let export = assign
            .left
            .as_member_expression()
            .filter(|m| as_identifier(m.object()).is_some_and(|o| self.factory_params.contains(o)))
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
            let mut attrs = wap
                .attrs_node
                .map(|n| extract_attrs_from_obj(n, self.source, self.aliases))
                .unwrap_or_default();
            // The root's own attributes are argument-backed too — `<presence to=… name=…
            // context=…>` is most of what that builder writes — and unlike `<iq>`, whose
            // root attrs are consumed into `namespace`/`iqType`/`target`, they are
            // published as attributes. Without this they were the one place a consumer
            // could see a dynamic value and not where to supply it.
            if let Some(n) = wap.attrs_node {
                annotate_attr_arg_paths(
                    &mut attrs,
                    n,
                    self.aliases,
                    self.scope,
                    self.source,
                    Some(n.span().start as usize),
                );
            }
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
                        // `ce` is at a real module offset — anchors the function context
                        // for scoped-initializer (`owner_fn`) checks.
                        Some(ce.span().start as usize),
                    ));
                }
            }
            // See `try_iq_call`: a builder with no single options object publishes no
            // paths, inlined subtrees included. Once for the whole call — every child
            // shares the frame that built it.
            enforce_argument_boundary(&mut children, self.scope, call.span().start as usize);
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
                fragment: false,
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
    fn captures_call_status_privacy_tags() {
        // The three top-level outgoing tags added alongside message/receipt/ack.
        let bundle = r#"
            __d("WAWebSendCallStanza",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(t){ return o("WAWap").wap("call",{id:o("WAWap").STANZA_ID(),to:o("WAWap").USER_JID(t)}); };
            }),1);
            __d("WAWebSetPrivacyStanza",["WAWap"],(function(g,r,d,o,e,i,l){
                l.set=function(v){ return o("WAWap").wap("privacy",{category:o("WAWap").CUSTOM_STRING(v)}); };
            }),1);
            __d("WAWebPublishStatusStanza",["WAWap"],(function(g,r,d,o,e,i,l){
                l.pub=function(){ return o("WAWap").wap("status",{type:o("WAWap").CUSTOM_STRING("text")}); };
            }),1);
        "#;
        let stanzas = scan(bundle);
        let by = |t: StanzaTag| {
            stanzas
                .iter()
                .find(|s| s.stanza_type == t)
                .unwrap_or_else(|| panic!("expected a {t:?} stanza to be captured"))
        };
        let has = |s: &StanzaDef, n: &str| s.attrs.iter().any(|a| a.name == n);
        // Each tag is recognized AND its attributes are extracted (not just discovered).
        let call = by(StanzaTag::Call);
        assert!(has(call, "id") && has(call, "to"), "call attrs extracted");
        assert!(has(by(StanzaTag::Privacy), "category"), "privacy attr");
        assert!(has(by(StanzaTag::Status), "type"), "status attr");
    }

    #[test]
    fn reassigned_child_is_scoped_to_its_builder() {
        // Two builders in one module each seed a local `c=null` and conditionally
        // reassign it to a child (`t&&(c=wap(...))`) — the aggregate-builder shape.
        // Each stanza must recover ITS OWN reassigned child and no other: the
        // reassignment in `other` must not leak into `send`'s <message>, and vice
        // versa. A module-wide (unscoped) assignment scope crosses these wires.
        let bundle = r#"
            __d("WAWebSendTwo",["WAWap"],(function(g,r,d,o,e,i,l){
                l.other=function(t){ var c=null; t&&(c=o("WAWap").wap("leak",{x:"1"})); return o("WAWap").wap("call",{id:"1"},c); };
                l.send=function(t){ var c=null; t&&(c=o("WAWap").wap("device-identity",{})); return o("WAWap").wap("message",{id:"1"},c); };
            }),1);
        "#;
        let stanzas = scan(bundle);
        let m = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Message)
            .expect("message captured");
        let tags: Vec<&str> = m.children.iter().map(|c| c.tag.as_str()).collect();
        assert!(
            tags.contains(&"device-identity"),
            "message keeps its own reassigned child: {tags:?}"
        );
        assert!(
            !tags.contains(&"leak"),
            "sibling builder's reassigned child must not leak in: {tags:?}"
        );
        // And the sibling stanza correctly keeps ITS child.
        let call = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Call)
            .expect("call captured");
        assert!(
            call.children.iter().any(|c| c.tag == "leak"),
            "call keeps its own reassigned child"
        );
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
    fn merge_mixin_fragment_module_is_catalogued_as_fragment() {
        // A module whose only function export is a `merge…Mixin` combinator is a
        // fragment (its stanza is folded into a real one). It's kept — so the
        // message/receipt content-type mixin catalog is captured — but marked `fragment`
        // so a consumer building a sendable stanza can filter it out.
        let bundle = r#"
            __d("WASmaxOutFooMixin",["WASmaxJsx","WASmaxMixins"],(function(t,n,r,o,a,i,l){
                function e(){ return o("WASmaxJsx").smax("receipt",{type:"read"}); }
                function s(t){ return o("WASmaxMixins").mergeStanzas(t,e()); }
                l.mergeFooMixin=s;
            }),1);
        "#;
        let stanzas = scan(bundle);
        let frag = stanzas
            .iter()
            .find(|s| s.stanza_type == StanzaTag::Receipt)
            .expect("fragment receipt catalogued");
        assert!(frag.fragment, "must be marked as a fragment");
        assert_eq!(frag.subtype.as_deref(), Some("read"));
        assert!(is_fragment_module(&["mergeFooMixin".into()]));
        assert!(!is_fragment_module(&["sendReceipt".into()]));
        // Constants alongside the mixin don't disqualify it.
        assert!(is_fragment_module(&[
            "mergeFooMixin".into(),
            "SOME_CONST".into()
        ]));
        // A `make…` helper exported *alongside* the mixin must NOT reclassify it as a
        // standalone stanza (`any`, not `all` — matching the IQ scanner).
        assert!(is_fragment_module(&[
            "mergeFooMixin".into(),
            "makeFooRequest".into()
        ]));
        // A pure helper module (no mixin) is not a fragment.
        assert!(!is_fragment_module(&["makeFooRequest".into()]));
    }

    #[test]
    fn conditionally_built_child_is_recovered() {
        // The aggregate receipt/ack builder attaches its `<list>` child conditionally
        // (`a.length > 0 ? wap("list", …) : null`). The child must be recovered from the
        // ternary, not dropped.
        let bundle = r#"
            __d("WAWebSendAckJob",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(ids){
                    var extra = ids.length>0 ? o("WAWap").wap("list",null, o("WAWap").wap("item",{id:o("WAWap").CUSTOM_STRING(ids[0])})) : null;
                    return o("WAWap").wap("ack",{id:o("WAWap").CUSTOM_STRING(ids[0]),type:"text"}, extra);
                };
            }),1);
        "#;
        let ack = scan(bundle)
            .into_iter()
            .find(|s| s.stanza_type == StanzaTag::Ack)
            .expect("ack captured");
        let list = ack
            .children
            .iter()
            .find(|c| c.tag == "list")
            .expect("conditional <list> child recovered");
        assert!(
            list.children.iter().any(|c| c.tag == "item"),
            "nested <item> under the conditional list recovered"
        );
    }

    #[test]
    fn both_ternary_branches_children_are_captured() {
        // A genuinely divergent `cond ? wap("a") : wap("b")` child catalogs BOTH shapes,
        // not just the consequent — the static schema should reflect every possible child.
        let bundle = r#"
            __d("WAWebSendAckJob2",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(x){
                    var c = x ? o("WAWap").wap("a",{k:o("WAWap").CUSTOM_STRING(x)}) : o("WAWap").wap("b",{k:o("WAWap").CUSTOM_STRING(x)});
                    return o("WAWap").wap("ack",{id:o("WAWap").CUSTOM_STRING(x),type:"text"}, c);
                };
            }),1);
        "#;
        let ack = scan(bundle)
            .into_iter()
            .find(|s| s.stanza_type == StanzaTag::Ack)
            .expect("ack captured");
        let tags: Vec<&str> = ack.children.iter().map(|c| c.tag.as_str()).collect();
        assert!(
            tags.contains(&"a") && tags.contains(&"b"),
            "both ternary branches captured, got {tags:?}"
        );
    }

    #[test]
    fn standalone_stanza_is_not_marked_fragment() {
        // A real top-level builder (non-mixin export) stays `fragment: false`.
        let bundle = r#"
            __d("WAWebSendPresence",["WAWap"],(function(g,r,d,o,e,i,l){
                l.send=function(t){ return o("WAWap").wap("presence",{type:"available"}); };
            }),98);
        "#;
        let p = scan(bundle)
            .into_iter()
            .find(|s| s.stanza_type == StanzaTag::Presence)
            .expect("presence captured");
        assert!(!p.fragment);
    }

    #[test]
    fn internal_object_write_does_not_pollute_exports() {
        // A fragment module that also writes to a LOCAL object (`cache.key = …`) must
        // still be classified as a fragment: only `<factoryParam>.x = …` counts as an
        // export, so the internal write doesn't add a bogus non-mixin export that would
        // reclassify it as a standalone stanza.
        let bundle = r#"
            __d("WASmaxOutBarMixin",["WASmaxJsx","WASmaxMixins"],(function(t,n,r,o,a,i,l){
                var cache={}; cache.key="v";
                function e(){ return o("WASmaxJsx").smax("receipt",{type:"read"}); }
                l.mergeBarMixin=function(t){ return o("WASmaxMixins").mergeStanzas(t,e()); };
            }),1);
        "#;
        let frag = scan(bundle)
            .into_iter()
            .find(|s| s.stanza_type == StanzaTag::Receipt)
            .expect("fragment catalogued");
        assert!(
            frag.fragment,
            "internal `cache.key` write must not reclassify the fragment as standalone"
        );
    }
}
