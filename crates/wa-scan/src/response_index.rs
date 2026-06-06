//! Cross-module index of smax response parsers (Phase 3).
//!
//! Smax responses live in `WASmaxIn<X>ResponseSuccess` modules (separate from the
//! `WASmaxOut<X>Request` modules the scanner sees). This build pass parses every
//! `WASmaxIn*` module once, extracts each payload mixin's fields first, then each
//! `ResponseSuccess` parser (which may reference those mixins and recurse into
//! local child parsers), and exposes a lookup by operation name `X` so the scanner
//! can attach a response to a request.
//!
//! Mirrors [`crate::mixin_index`] in structure (build once before the scan loop,
//! `BTreeMap` for determinism, only the small `WASmaxIn*` slices re-parsed).

use std::collections::{BTreeMap, HashMap, HashSet};

use wa_ir::{ParsedField, ParsedFieldType, ParsedResponse, ResponseVariant, ResponseVariantKind};

use crate::response_smax::{Resolved, Resolver, analyze_module_exports, scan_cascade_variants};
use wa_transform::ModuleDefinition;

/// Index of smax response parsers, keyed for request→response linkage.
#[derive(Default)]
pub struct ResponseIndex {
    /// Operation name `X` (from `WASmaxIn<X>ResponseSuccess`) → its parsed response.
    by_x: BTreeMap<String, ParsedResponse>,
    /// Owned `WASmaxIn*` module name → slice, kept for the request-anchored fallback
    /// ([`Self::resolve_for_request_op`]) — Pass 1/2 only key the `RPC`/`ResponseSuccess`
    /// shapes, so an op whose response module ends differently (e.g. PingsClient's
    /// `…ResponseServerResponse`) needs a lookup that anchors on the known op name.
    in_slices: Vec<(String, String)>,
}

impl ResponseIndex {
    /// Look up the response for operation `x` (derived from a request module name).
    pub(crate) fn get_by_x(&self, x: &str) -> Option<&ParsedResponse> {
        self.by_x.get(x)
    }

    /// Fallback for an op with no `RPC`/`ResponseSuccess` module: find a
    /// `WASmaxIn<x>Response<V>` whose variant `V` is success-like (not an error/Mixin),
    /// anchored on the EXACT op name `x` (so the prefix match is unambiguous — never
    /// reverse-derived by stripping `Response`, which would mis-split `…ServerResponse`
    /// or an op ending in `Responses`). Parses it on demand; returns its typed fields.
    pub(crate) fn resolve_for_request_op(&self, x: &str) -> Option<ParsedResponse> {
        let slices: HashMap<&str, &str> = self
            .in_slices
            .iter()
            .map(|(n, s)| (n.as_str(), s.as_str()))
            .collect();
        let resolver = Resolver::new(&slices);
        let prefix = format!("WASmaxIn{x}Response");
        for (name, slice) in &self.in_slices {
            let Some(variant) = name.strip_prefix(&prefix) else {
                continue;
            };
            // Skip the bare `…Response`, error variants, and mixin payloads.
            if variant.is_empty()
                || variant.contains("Mixin")
                || variant_kind(variant) != ResponseVariantKind::Success
            {
                continue;
            }
            if let Some(pr) = analyze_module_exports(slice, &resolver)
                .into_iter()
                .find(|(_, pr)| !pr.fields.is_empty())
                .map(|(_, pr)| pr)
            {
                return Some(pr);
            }
        }
        None
    }
}

/// Build the response index over every `WASmaxIn*` module.
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> ResponseIndex {
    // First occurrence of each module name → its slice (shard dedup).
    let mut slices: HashMap<&str, &str> = HashMap::new();
    for m in defs {
        slices
            .entry(m.name.as_str())
            .or_insert(&source[m.start..m.end]);
    }
    // Lazily resolves cross-module parsers/mixins/unions on demand (memoized),
    // replacing the old eager mixin index.
    let resolver = Resolver::new(&slices);

    let mut by_x = BTreeMap::new();

    // Pass 1 (authoritative): each `WASmax<X>RPC` orchestrator defines the response
    // as an ordered discriminated union of `WASmaxIn<X>Response<Variant>` parsers
    // (first success wins). Parse the cascade → typed variants; the primary success
    // variant's fields fill `ParsedResponse.fields` for single-shape consumers.
    let mut seen_rpc = HashSet::new();
    for m in defs {
        if !(m.name.starts_with("WASmax") && m.name.ends_with("RPC")) {
            continue;
        }
        if !seen_rpc.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        let variant_refs = scan_cascade_variants(slice);
        if variant_refs.is_empty() {
            continue;
        }
        let mut variants = Vec::new();
        let mut primary: Vec<ParsedField> = Vec::new();
        for (tag, module, func) in variant_refs {
            // Resolve the exact parser the RPC calls (`o(module).<func>`); a
            // `ResponseSuccess` module exports several `parse…` fns, so match by name.
            let fields = match resolver.resolve(&module, &func) {
                Some(Resolved::Fields(f)) => f,
                Some(Resolved::Union(v)) if !v.is_empty() => vec![union_field("value", v)],
                _ => Vec::new(),
            };
            let kind = variant_kind(&tag);
            if kind == ResponseVariantKind::Success && primary.is_empty() {
                primary = fields.clone();
            }
            // The variant's same-node discriminators (e.g. `type:"result"` / `type:"error"`),
            // recovered separately since the JS keeps them as parser asserts, not fields.
            // These let codegen guard each arm so the outcome union doesn't misclassify.
            let assertions = resolver.assertions(&module, &func);
            variants.push(ResponseVariant {
                tag,
                module_name: module,
                kind,
                assertions,
                fields,
            });
        }
        by_x.entry(rpc_op_name(&m.name)).or_insert(ParsedResponse {
            parser_name: m.name.clone(),
            fields: primary,
            variants,
            ..Default::default()
        });
    }

    // Pass 2 (fallback): a plain `WASmaxIn<X>ResponseSuccess` for ops with no RPC
    // (e.g. PingsClient). Only fills gaps the RPC pass didn't cover.
    let mut seen = HashSet::new();
    for m in defs {
        if !(m.name.starts_with("WASmaxIn") && m.name.ends_with("ResponseSuccess")) {
            continue;
        }
        if !seen.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        let Some(pr) = analyze_module_exports(slice, &resolver)
            .into_iter()
            .find(|(n, pr)| n.ends_with("ResponseSuccess") && !pr.fields.is_empty())
            .map(|(_, pr)| pr)
        else {
            continue;
        };
        by_x.entry(response_op_name(&m.name)).or_insert(pr);
    }

    // Keep the `WASmaxIn*` slices (owned) for the request-anchored fallback.
    let in_slices: Vec<(String, String)> = slices
        .iter()
        .filter(|(n, _)| n.starts_with("WASmaxIn"))
        .map(|(n, s)| (n.to_string(), s.to_string()))
        .collect();

    ResponseIndex { by_x, in_slices }
}

/// A discriminated-union field carrying `variants`.
fn union_field(name: &str, variants: Vec<wa_ir::UnionVariant>) -> ParsedField {
    ParsedField {
        name: name.to_string(),
        field_type: ParsedFieldType::Union,
        union_variants: Some(variants),
        required: true,
        ..Default::default()
    }
}

/// `WASmax<X>RPC` → `X` (the op key shared with `WASmaxOut<X>Request`).
fn rpc_op_name(module: &str) -> String {
    module
        .strip_prefix("WASmax")
        .and_then(|s| s.strip_suffix("RPC"))
        .unwrap_or(module)
        .to_string()
}

/// Classify a response variant by its discriminator tag's tokens.
fn variant_kind(tag: &str) -> ResponseVariantKind {
    const ERROR_TOKENS: &[&str] = &[
        "Error",
        "InvalidRequest",
        "Nack",
        "Conflict",
        "Forbidden",
        "TooManyAttempts",
        "IncorrectNonce",
        "RecoveryRequired",
        "AlreadyExists",
        "Negative",
        "BadStanza",
        "NotAuthorized",
        "NotAcceptable",
        "NotExist",
        "ResourceLimit",
    ];
    if ERROR_TOKENS.iter().any(|t| tag.contains(t)) {
        ResponseVariantKind::Error
    } else {
        ResponseVariantKind::Success
    }
}

/// `WASmaxIn<X>ResponseSuccess` → `X` (operation name shared with the request).
fn response_op_name(module: &str) -> String {
    module
        .strip_prefix("WASmaxIn")
        .and_then(|s| s.strip_suffix("ResponseSuccess"))
        .unwrap_or(module)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_name_strips_prefix_suffix() {
        assert_eq!(
            response_op_name("WASmaxInNewslettersGetNewsletterStatusesResponseSuccess"),
            "NewslettersGetNewsletterStatuses"
        );
    }

    #[test]
    fn build_pass_indexes_a_response_module() {
        // Minimal module: assertTag + one attr field.
        let m = r#"__d("WASmaxInFooGetBarResponseSuccess",["WASmaxParseUtils"],function(g,r,d,o,e,i,l){
            function e(node, ref){
                var n = o("WASmaxParseUtils").assertTag(node, "iq"); if(!n.success) return n;
                var s = o("WASmaxParseUtils").attrString(node, "id"); if(!s.success) return s;
                return s.success ? o("WAResultOrError").makeResult({ id: s.value }) : s;
            }
            l.parseGetBarResponseSuccess = e;
        }, 1);"#;
        let defs = wa_transform::extract_module_definitions(m);
        let idx = build_pass(&defs, m);
        let pr = idx.get_by_x("FooGetBar").expect("indexed by X");
        assert_eq!(pr.fields.len(), 1);
        assert_eq!(pr.fields[0].name, "id");
    }

    #[test]
    fn build_pass_recovers_nested_child_response() {
        // A ResponseSuccess whose payload is a child parsed by a local fn — the
        // case the old per-fn analyzer dropped (empty fields → unindexed).
        let m = r#"__d("WASmaxInGroupsGetGroupInfoResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(g){
                var t = o("WASmaxParseUtils").assertTag(g, "group"); if(!t.success) return t;
                var s = o("WASmaxParseUtils").attrString(g, "subject"); if(!s.success) return s;
                return o("WAResultOrError").makeResult({ subject: s.value });
            }
            function s(t, n){
                var r = o("WASmaxParseUtils").assertTag(t, "iq"); if(!r.success) return r;
                var a = o("WASmaxParseUtils").optionalChildWithTag(t, "group", e); if(!a.success) return a;
                return o("WAResultOrError").makeResult({ group: a.value });
            }
            l.parseGetGroupInfoResponseSuccessGroup = e, l.parseGetGroupInfoResponseSuccess = s;
        }), 1);"#;
        let defs = wa_transform::extract_module_definitions(m);
        let idx = build_pass(&defs, m);
        let pr = idx.get_by_x("GroupsGetGroupInfo").expect("indexed by X");
        let group = pr
            .fields
            .iter()
            .find(|f| f.name == "group")
            .expect("group field");
        assert!(
            group
                .children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "subject")),
            "nested child fields recovered"
        );
    }
}
