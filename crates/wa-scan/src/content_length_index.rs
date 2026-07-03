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
use oxc_ast::ast::{CallExpression, Expression, FunctionBody, VariableDeclaration};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{WapChildNode, WapContentKind};
use wa_transform::ModuleDefinition;

use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_string_lit, callee_method, callee_object,
};

/// The content accessors that pin a byte length: `contentBytes(n)` / `contentUint(n)`.
const CONTENT_LEN_METHODS: [&str; 2] = ["contentBytes", "contentUint"];

/// `(parentTag, tag)` → the byte length WA Web's parsers read that field as, plus the
/// module the length was cross-referenced from.
#[derive(Default)]
pub struct ContentLengthIndex {
    by_path: BTreeMap<(String, String), (u32, String)>,
}

impl ContentLengthIndex {
    /// The `(length, source module)` for a `(parentTag, tag)` wire field, if the
    /// bundle's parsers pin it unambiguously.
    pub(crate) fn get(&self, parent: &str, tag: &str) -> Option<(u32, &str)> {
        self.by_path
            .get(&(parent.to_string(), tag.to_string()))
            .map(|(len, src)| (*len, src.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.by_path.is_empty()
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
            source_module
                .entry(key.clone())
                .or_insert_with(|| m.name.clone());
            seen_lengths.entry(key).or_default().insert(len);
        }
    }

    let mut index = ContentLengthIndex::default();
    for (key, lengths) in seen_lengths {
        // Only keep a key whose every occurrence agreed on the length.
        if let (1, Some(&len)) = (lengths.len(), lengths.iter().next()) {
            let src = source_module.remove(&key).unwrap_or_default();
            index.by_path.insert(key, (len, src));
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

struct Collector {
    /// local var name → the child tag it was bound to (`var m = x.child("skey")`).
    child_vars: HashMap<String, String>,
    out: Vec<(String, String, u32)>,
}

impl<'a> Visit<'a> for Collector {
    /// Scope child-var bindings to the function they're declared in: a nested body
    /// starts from a copy of the outer bindings (so a closure can read them) and its
    /// own additions are discarded on exit, so a `var m = child(...)` in one function
    /// can't be misattributed to a same-named local in a sibling function.
    fn visit_function_body(&mut self, body: &FunctionBody<'a>) {
        let outer = self.child_vars.clone();
        walk::walk_function_body(self, body);
        self.child_vars = outer;
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let Some(name) = d.id.get_identifier_name() {
                match d.init.as_ref().and_then(child_call_tag) {
                    // `var m = x.child("skey")` → track.
                    Some(tag) => {
                        self.child_vars.insert(name.as_str().to_string(), tag);
                    }
                    // `var m = <anything else>` → drop any stale binding for this name,
                    // so a reused local isn't read as its previous child tag.
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
            && let (Some(parent), Some(tag)) = self.parent_and_tag(receiver)
        {
            self.out.push((parent, tag, len));
        }
        walk::walk_call_expression(self, call);
    }
}

impl Collector {
    /// From the receiver of a `.contentBytes(n)` call, the `(parentTag, tag)` of the
    /// field being read — i.e. the receiver must be `Y.child("TAG")` and `Y` must
    /// resolve to a parent tag (a `Z.child("PARENT")` or a tracked child var).
    fn parent_and_tag(&self, receiver: &Expression) -> (Option<String>, Option<String>) {
        let Some(tag) = child_call_tag(receiver) else {
            return (None, None);
        };
        // `receiver` is `Y.child("TAG")`; find Y and its tag.
        let Some(inner) = as_call(receiver).and_then(callee_object) else {
            return (None, Some(tag));
        };
        let parent = child_call_tag(inner)
            .or_else(|| as_identifier(inner).and_then(|n| self.child_vars.get(n).cloned()));
        (parent, Some(tag))
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
/// request tree: for a leaf node with content but no directly-written length, whose
/// `(parentTag, tag)` the index pins, fill the length + its parser provenance. Never
/// overrides a builder-written length. Recurses, threading each node's tag as the
/// parent of its children.
pub(crate) fn enrich(children: &mut [WapChildNode], parent_tag: &str, index: &ContentLengthIndex) {
    if index.is_empty() {
        return;
    }
    for node in children {
        if let Some(content) = node.content.as_mut()
            && content.byte_length.is_none()
            && let Some((len, source)) = index.get(parent_tag, &node.tag)
        {
            content.byte_length = Some(len);
            content.byte_length_source = Some(format!("parse:{source}"));
            if content.kind == WapContentKind::Dynamic {
                content.kind = WapContentKind::Bytes;
            }
        }
        let tag = node.tag.clone();
        enrich(&mut node.children, &tag, index);
        // A node's children may instead live inside mutually-exclusive variant
        // groups; those leaves are children of this node too, so enrich them under
        // the same parent tag.
        for group in &mut node.variant_groups {
            for variant in &mut group.variants {
                enrich(&mut variant.children, &tag, index);
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
        enrich(std::slice::from_mut(&mut skey), "iq", &idx);
        let sig = skey.variant_groups[0].variants[0].children[0]
            .content
            .as_ref()
            .unwrap();
        assert_eq!(sig.byte_length, Some(64));
        assert_eq!(sig.byte_length_source.as_deref(), Some("parse:P"));
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
        enrich(std::slice::from_mut(&mut skey), "iq", &idx);
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
