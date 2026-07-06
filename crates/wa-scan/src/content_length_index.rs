//! Symmetric content-length cross-reference.
//!
//! A request builder writes a leaf value opaquely — `wap("signature", null,
//! e.signature)` states no length — so the byte length isn't in the builder. But
//! WA Web's own *parsers* read the same wire field with an explicit length:
//! `child("signature").contentBytes(64)`, `child("value").contentBytes(32)`. That
//! literal is the wire contract, written in the bundle.
//!
//! This index scans every parser for `child("PARENT")…child("TAG").contentBytes(N)`
//! / `contentUint(N)` and records `(parentTag, tag) → N`, requiring every occurrence
//! of a key to agree (a disagreement drops the key — we never guess). The request
//! resolver then cross-references it onto leaf nodes with a matching `(parent, tag)`
//! path, so `<skey><signature>` gains its real 64-byte length — sourced from the
//! parser, not from crypto domain knowledge.
//!
//! Keying is by `(parentTag, tag)`, never tag alone: `<id>` is a 3-byte key id under
//! `<skey>`/`<key>` but an opaque product id under `<product_list>`, so tag-only
//! matching would mislabel the latter.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, CallExpression, Expression, FormalParameters, Function,
    VariableDeclaration,
};
use oxc_ast_visit::{Visit, walk};
use oxc_syntax::scope::ScopeFlags;
use wa_ir::{WapChildNode, WapContentKind};
use wa_transform::ModuleDefinition;

use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_string_lit, callee_method, callee_object,
};

/// The content accessors that pin a byte length: `contentBytes(n)` / `contentUint(n)`.
const CONTENT_LEN_METHODS: [&str; 2] = ["contentBytes", "contentUint"];

/// `(parentTag, tag)` → the byte length WA Web's parsers read that field as, plus the
/// module the length was cross-referenced from. `by_tag` is the parent-agnostic view
/// (a `tag` whose length is the same under every parent) used as a guarded fallback
/// when the exact `(parent, tag)` path isn't present.
#[derive(Default)]
pub struct ContentLengthIndex {
    by_path: BTreeMap<(String, String), (u32, String)>,
    by_tag: BTreeMap<String, (u32, String)>,
}

impl ContentLengthIndex {
    /// The `(length, source module)` for a `(parentTag, tag)` wire field, if the
    /// bundle's parsers pin it unambiguously.
    pub(crate) fn get(&self, parent: &str, tag: &str) -> Option<(u32, &str)> {
        self.by_path
            .get(&(parent.to_string(), tag.to_string()))
            .map(|(len, src)| (*len, src.as_str()))
    }

    /// The `(length, source module)` for a `tag` regardless of parent, when every
    /// parse site of that tag agreed on the length. The caller must still gate this
    /// on the tag being unambiguous in its use (see [`enrich`]).
    pub(crate) fn get_by_tag(&self, tag: &str) -> Option<(u32, &str)> {
        self.by_tag.get(tag).map(|(len, src)| (*len, src.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.by_path.is_empty() && self.by_tag.is_empty()
    }
}

/// Build the index over every module whose slice reads sized content. Cheap: only
/// slices containing `contentBytes(`/`contentUint(` are re-parsed. A `(parentTag,
/// tag)` seen with two different lengths anywhere is dropped (ambiguous → no guess).
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> ContentLengthIndex {
    // (parentTag, tag) → lengths seen, and the first module each was seen in.
    let mut seen_lengths: BTreeMap<(String, String), BTreeSet<u32>> = BTreeMap::new();
    let mut source_module: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut scanned = HashSet::new();

    for m in defs {
        if !scanned.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        if !slice.contains("contentBytes(") && !slice.contains("contentUint(") {
            continue;
        }
        for (parent, tag, len) in collect_module(slice) {
            let key = (parent, tag);
            // Keep the lexicographically-smallest module name as the provenance, not
            // the first one *seen* — the scan order follows bundle file order, so a
            // first-wins tie-break makes `byteLengthSource` depend on input ordering
            // and breaks the byte-identical-output guarantee when two modules pin the
            // same (parent,tag,len).
            source_module
                .entry(key.clone())
                .and_modify(|existing| {
                    if m.name < *existing {
                        *existing = m.name.clone();
                    }
                })
                .or_insert_with(|| m.name.clone());
            seen_lengths.entry(key).or_default().insert(len);
        }
    }

    let mut index = ContentLengthIndex::default();
    // Per-tag ambiguity is computed from EVERY observed length (including lengths from
    // paths that are themselves ambiguous), so a tag read as different lengths anywhere
    // is excluded from the parent-agnostic fallback — even if one of its parents was
    // dropped by the per-path filter.
    let mut tag_lengths: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut tag_source: BTreeMap<String, String> = BTreeMap::new();
    for ((_parent, tag), lengths) in &seen_lengths {
        tag_lengths.entry(tag.clone()).or_default().extend(lengths);
    }
    for (key, lengths) in seen_lengths {
        // Only keep a path whose every occurrence agreed on the length.
        if let (1, Some(&len)) = (lengths.len(), lengths.iter().next()) {
            let src = source_module.get(&key).cloned().unwrap_or_default();
            tag_source.entry(key.1.clone()).or_insert(src.clone());
            index.by_path.insert(key, (len, src));
        }
    }
    for (tag, lengths) in tag_lengths {
        // A tag qualifies for the fallback only if it was read at exactly one length
        // everywhere AND at least one path pinned it (has a source).
        if let (1, Some(&len)) = (lengths.len(), lengths.iter().next())
            && let Some(src) = tag_source.remove(&tag)
        {
            index.by_tag.insert(tag, (len, src));
        }
    }
    index
}

/// Every `(parentTag, tag, byteLength)` a module's parsers read via a sized content
/// accessor.
fn collect_module(slice: &str) -> Vec<(String, String, u32)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    if ret.panicked {
        return Vec::new();
    }
    let mut collector = Collector {
        child_vars: HashMap::new(),
        out: Vec::new(),
    };
    collector.visit_program(&ret.program);
    collector.out
}

/// A resolved reference to a child node: its own `tag`, and its `parent` tag when
/// the parent chain is known.
#[derive(Clone)]
struct ChildRef {
    parent: Option<String>,
    tag: String,
}

struct Collector {
    /// local var name → the child node it was bound to (`var m = x.child("skey")`).
    child_vars: HashMap<String, ChildRef>,
    out: Vec<(String, String, u32)>,
}

impl<'a> Visit<'a> for Collector {
    // Scope child-var bindings to the function they're declared in: a nested function
    // starts from a copy of the outer bindings (so a closure can read them), with its
    // own PARAMETERS removed (they shadow any outer binding of the same name), and its
    // own additions discarded on exit. This keeps a `var m = child(...)` in one
    // function from being misattributed to a same-named local/param elsewhere.
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let outer = self.child_vars.clone();
        shadow_params(&mut self.child_vars, &func.params);
        walk::walk_function(self, func, flags);
        self.child_vars = outer;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let outer = self.child_vars.clone();
        shadow_params(&mut self.child_vars, &arrow.params);
        walk::walk_arrow_function_expression(self, arrow);
        self.child_vars = outer;
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let Some(name) = d.id.get_identifier_name() {
                match d
                    .init
                    .as_ref()
                    .and_then(|init| self.resolve_child_ref(init))
                {
                    // `var m = x.child("skey")` / `var v = m.child("value")` → track.
                    Some(cref) => {
                        self.child_vars.insert(name.as_str().to_string(), cref);
                    }
                    // `var m = <anything else>` → drop any stale binding for this name,
                    // so a reused local isn't read as its previous child.
                    None => {
                        self.child_vars.remove(name.as_str());
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(method) = callee_method(call)
            && CONTENT_LEN_METHODS.contains(&method)
            && let Some(len) = call.arguments.first().and_then(arg_expr).and_then(as_int)
            && let Ok(len) = u32::try_from(len)
            && let Some(receiver) = callee_object(call)
            && let Some(cref) = self.resolve_child_ref(receiver)
            && let Some(parent) = cref.parent
        {
            self.out.push((parent, cref.tag, len));
        }
        walk::walk_call_expression(self, call);
    }
}

impl Collector {
    /// The child node an expression refers to: a `Y.child("TAG")` call (parent from
    /// `Y`), or an identifier bound to a tracked child var. Handles the stored-leaf
    /// form `var v = m.child("value"); v.contentBytes(…)` by resolving `v`.
    fn resolve_child_ref(&self, e: &Expression) -> Option<ChildRef> {
        if let Some(id) = as_identifier(e) {
            return self.child_vars.get(id).cloned();
        }
        let tag = child_call_tag(e)?;
        let parent = as_call(e)
            .and_then(callee_object)
            .and_then(|y| self.tag_of(y));
        Some(ChildRef { parent, tag })
    }

    /// The tag a receiver expression resolves to (its own child tag): a `Z.child("P")`
    /// call, or an identifier bound to a child var.
    fn tag_of(&self, e: &Expression) -> Option<String> {
        child_call_tag(e).or_else(|| {
            as_identifier(e).and_then(|id| self.child_vars.get(id).map(|c| c.tag.clone()))
        })
    }
}

/// Remove a nested function's formal parameter names from the (copied) child-var
/// map, so a parameter shadows — never inherits — an outer binding of the same name.
/// Uses every bound identifier in each pattern, so a destructured param
/// (`function({ m })` / `function([m])`) shadows too, not just a simple `function(m)`.
fn shadow_params(child_vars: &mut HashMap<String, ChildRef>, params: &FormalParameters) {
    let mut remove_bound = |pattern: &oxc_ast::ast::BindingPattern| {
        for ident in pattern.get_binding_identifiers() {
            child_vars.remove(ident.name.as_str());
        }
    };
    for p in &params.items {
        remove_bound(&p.pattern);
    }
    if let Some(rest) = &params.rest {
        remove_bound(&rest.rest.argument);
    }
}

/// The tag of a `X.child("tag")` / `X.maybeChild("tag")` call, if `e` is one.
fn child_call_tag(e: &Expression) -> Option<String> {
    let call = as_call(e)?;
    if !matches!(callee_method(call), Some("child") | Some("maybeChild")) {
        return None;
    }
    as_string_lit(arg_expr(call.arguments.first()?)?).map(str::to_string)
}

/// Cross-reference the byte length WA Web's parsers read each leaf field as onto the
/// request tree: for a leaf node with content but no directly-written length, fill the
/// length + its parser provenance. Never overrides a builder-written length.
///
/// Resolution: the exact `(parentTag, tag)` path first; else — only for a tag in
/// `tag_fallback` — the parent-agnostic per-tag length. `tag_fallback` must be the set
/// of tags that are unambiguous in their use (e.g. appear in a single IQ namespace),
/// so a same-named field with a different meaning (a `<product_list><id>` vs a 3-byte
/// key `<id>`) is never mislabeled.
///
/// Recurses, threading each node's tag as the parent of its children (and into any
/// mutually-exclusive variant groups).
pub(crate) fn enrich(
    children: &mut [WapChildNode],
    parent_tag: &str,
    index: &ContentLengthIndex,
    tag_fallback: &HashSet<String>,
) {
    if index.is_empty() {
        return;
    }
    for node in children {
        // Exact `(parent, tag)` path wins; else the parent-agnostic per-tag fallback
        // (gated on `tag_fallback`), whose provenance is tagged `(by-tag)` so a
        // cross-context inference is distinguishable from an exact match.
        let resolved = index
            .get(parent_tag, &node.tag)
            .map(|(len, src)| (len, format!("parse:{src}")))
            .or_else(|| {
                tag_fallback
                    .contains(&node.tag)
                    .then(|| index.get_by_tag(&node.tag))
                    .flatten()
                    .map(|(len, src)| (len, format!("parse:{src} (by-tag)")))
            });
        if let Some(content) = node.content.as_mut()
            && content.byte_length.is_none()
            && let Some((len, source)) = resolved
        {
            content.byte_length = Some(len);
            content.byte_length_source = Some(source);
            if content.kind == WapContentKind::Dynamic {
                content.kind = WapContentKind::Bytes;
            }
        }
        let tag = node.tag.clone();
        enrich(&mut node.children, &tag, index, tag_fallback);
        // A node's children may instead live inside mutually-exclusive variant
        // groups; those leaves are children of this node too, so enrich them under
        // the same parent tag.
        for group in &mut node.variant_groups {
            for variant in &mut group.variants {
                enrich(&mut variant.children, &tag, index, tag_fallback);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(bundle: &str) -> ContentLengthIndex {
        let defs = wa_transform::extract_module_definitions(bundle);
        build_pass(&defs, bundle)
    }

    #[test]
    fn indexes_by_parent_and_tag() {
        // Both the tracked-child-var form (`m = u.child("skey"); m.child("value")…`)
        // and the chained form resolve the parent tag.
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u){ var m = u.child("skey"); return m.child("value").contentBytes(32); };
                l.b = function(u){ return u.child("skey").child("signature").contentBytes(64); };
            },1);
        "#;
        let idx = index(bundle);
        assert_eq!(idx.get("skey", "value"), Some((32, "P")));
        assert_eq!(idx.get("skey", "signature"), Some((64, "P")));
        // A field the parsers don't read is absent.
        assert_eq!(idx.get("skey", "nope"), None);
        // Tag-only would be wrong: the same tag under a different parent isn't shared.
        assert_eq!(idx.get("product_list", "value"), None);
    }

    #[test]
    fn byte_length_source_is_order_independent() {
        // Two modules pin the same (parent, tag, length); the recorded provenance must
        // be the lexicographically-smallest module name regardless of bundle order, so
        // the generated `byteLengthSource` is byte-identical across a reordering of the
        // input bundles (the byte-identical-output guarantee).
        let a = r#"__d("Aaa",[],function(g,r,d,o,e,i,l){ l.p = function(u){ return u.child("skey").child("value").contentBytes(32); };},1);"#;
        let z = r#"__d("Zzz",[],function(g,r,d,o,e,i,l){ l.p = function(u){ return u.child("skey").child("value").contentBytes(32); };},1);"#;
        let az = format!("{a}\n{z}");
        let za = format!("{z}\n{a}");
        assert_eq!(index(&az).get("skey", "value"), Some((32, "Aaa")));
        assert_eq!(index(&za).get("skey", "value"), Some((32, "Aaa")));
    }

    #[test]
    fn contentuint_length_is_indexed() {
        let bundle = r#"__d("P",[],function(g,r,d,o,e,i,l){
            l.a = function(u){ return u.child("skey").child("id").contentUint(3); };
        },1);"#;
        assert_eq!(index(bundle).get("skey", "id"), Some((3, "P")));
    }

    #[test]
    fn child_var_binding_is_scoped_to_its_function() {
        // Function `a` binds `m` to skey and reads value(32). Function `b` has a
        // parameter `m` (not a child binding) and reads value(48). Without
        // per-function scoping, `b`'s `m` would inherit `a`'s skey binding and record
        // a conflicting (skey, value) = 48, dropping the field as ambiguous.
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u){ var m = u.child("skey"); return m.child("value").contentBytes(32); };
                l.b = function(m){ return m.child("value").contentBytes(48); };
            },1);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), Some((32, "P")));
    }

    #[test]
    fn nested_param_shadows_outer_child_var() {
        // The outer function binds `m` to skey; a nested callback's PARAMETER `m`
        // shadows it, so the nested `m.child("value").contentBytes(48)` must not be
        // attributed to skey (which would conflict with the outer 32 and drop it).
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u){
                    var m = u.child("skey");
                    [1].forEach(function(m){ m.child("value").contentBytes(48); });
                    return m.child("value").contentBytes(32);
                };
            },1);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), Some((32, "P")));
    }

    #[test]
    fn destructured_nested_param_shadows_outer_child_var() {
        // A nested callback whose param is DESTRUCTURED (`function({ m })`) must still
        // shadow the outer `var m = u.child("skey")` — `get_binding_identifiers`
        // covers the bound name, not just a simple identifier param.
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u){
                    var m = u.child("skey");
                    [1].forEach(function({ m }){ m.child("value").contentBytes(48); });
                    return m.child("value").contentBytes(32);
                };
            },1);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), Some((32, "P")));
    }

    #[test]
    fn stored_leaf_identifier_receiver_is_resolved() {
        // `var v = m.child("value"); v.contentBytes(32)` — the leaf child is stored in
        // a var before being read; resolving `v` must recover (skey, value).
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u){ var m = u.child("skey"); var v = m.child("value"); return v.contentBytes(32); };
            },1);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), Some((32, "P")));
    }

    #[test]
    fn redeclaration_with_non_child_init_drops_stale_binding() {
        // `a` rebinds `m` to a non-child, so its later `m.child("value")` must not be
        // attributed to skey; only `b`'s legitimate read defines (skey, value).
        let bundle = r#"
            __d("P",[],function(g,r,d,o,e,i,l){
                l.a = function(u,x){ var m = u.child("skey"); var m = x.blob(); return m.child("value").contentBytes(48); };
                l.b = function(u){ var n = u.child("skey"); return n.child("value").contentBytes(32); };
            },1);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), Some((32, "P")));
    }

    #[test]
    fn enrich_descends_into_variant_groups() {
        let bundle = r#"__d("P",[],function(g,r,d,o,e,i,l){
            l.a = function(u){ var m = u.child("skey"); return m.child("signature").contentBytes(64); };
        },1);"#;
        let idx = index(bundle);
        // A `<skey>` whose `<signature>` leaf lives inside a variant, not `children`.
        let mut skey = WapChildNode {
            tag: "skey".into(),
            variant_groups: vec![wa_ir::WapVariantGroup {
                optional: false,
                variants: vec![wa_ir::WapVariant {
                    attrs: vec![],
                    children: vec![WapChildNode {
                        tag: "signature".into(),
                        content: Some(wa_ir::WapContent {
                            kind: WapContentKind::Dynamic,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                }],
            }],
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut skey), "iq", &idx, &HashSet::new());
        let sig = skey.variant_groups[0].variants[0].children[0]
            .content
            .as_ref()
            .unwrap();
        assert_eq!(sig.byte_length, Some(64));
        assert_eq!(sig.byte_length_source.as_deref(), Some("parse:P"));
    }

    #[test]
    fn tag_ambiguous_in_any_path_is_excluded_from_fallback() {
        // `value` is read as 16 under `foo` (ambiguous with 32 there too) and 32 under
        // `bar`. Even though `(bar, value)` is unambiguous, `value` is NOT globally
        // consistent, so it must not enter the per-tag fallback.
        let bundle = r#"
            __d("A",[],function(g,r,d,o,e,i,l){ l.a=function(u){ return u.child("foo").child("value").contentBytes(16); }; },1);
            __d("B",[],function(g,r,d,o,e,i,l){ l.b=function(u){ return u.child("foo").child("value").contentBytes(32); }; },2);
            __d("C",[],function(g,r,d,o,e,i,l){ l.c=function(u){ return u.child("bar").child("value").contentBytes(32); }; },3);
        "#;
        let idx = index(bundle);
        // (bar, value) is unambiguous → exact path still works.
        assert_eq!(idx.get("bar", "value"), Some((32, "C")));
        // (foo, value) is ambiguous → dropped from by_path.
        assert_eq!(idx.get("foo", "value"), None);
        // `value` is globally ambiguous (16 and 32) → NO by-tag fallback.
        assert_eq!(idx.get_by_tag("value"), None);
    }

    #[test]
    fn disagreeing_lengths_are_dropped() {
        // The same (parent, tag) read as two different lengths → ambiguous → no guess.
        let bundle = r#"
            __d("A",[],function(g,r,d,o,e,i,l){ l.a=function(u){ return u.child("skey").child("value").contentBytes(32); }; },1);
            __d("B",[],function(g,r,d,o,e,i,l){ l.b=function(u){ return u.child("skey").child("value").contentBytes(48); }; },2);
        "#;
        assert_eq!(index(bundle).get("skey", "value"), None);
    }

    #[test]
    fn enrich_fills_dynamic_length_and_keeps_builder_length() {
        let bundle = r#"__d("WAWebSigParser",[],function(g,r,d,o,e,i,l){
            l.a = function(u){ var m=u.child("skey"); return m.child("signature").contentBytes(64); };
        },1);"#;
        let idx = index(bundle);
        let mut skey = WapChildNode {
            tag: "skey".into(),
            children: vec![
                WapChildNode {
                    tag: "signature".into(),
                    content: Some(wa_ir::WapContent {
                        kind: WapContentKind::Dynamic,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                WapChildNode {
                    tag: "id".into(),
                    content: Some(wa_ir::WapContent {
                        kind: WapContentKind::Bytes,
                        byte_length: Some(3),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut skey), "iq", &idx, &HashSet::new());
        let sig = &skey.children[0].content.as_ref().unwrap();
        assert_eq!(sig.byte_length, Some(64));
        assert_eq!(
            sig.byte_length_source.as_deref(),
            Some("parse:WAWebSigParser")
        );
        assert_eq!(sig.kind, WapContentKind::Bytes);
        // The builder-written `id` length is untouched (no parse source).
        let id = &skey.children[1].content.as_ref().unwrap();
        assert_eq!(id.byte_length, Some(3));
        assert_eq!(id.byte_length_source, None);
    }
}
