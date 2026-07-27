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

use wa_ir::{
    ErrorClass, ParsedField, ParsedFieldType, ParsedResponse, ResponseVariant, ResponseVariantKind,
    UnionVariant,
};

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
    /// Constraints (literal values, reference paths, enum arguments) that were present
    /// in a parser but not structurally resolvable, by reason. Surfaced under
    /// `manifest.diagnostics.iq.dropsByReason` so "no constraint here" and "a constraint
    /// we failed to extract" never look alike to a consumer.
    drops: BTreeMap<String, usize>,
}

impl ResponseIndex {
    /// See [`ResponseIndex::drops`].
    pub(crate) fn drop_counts(&self) -> &BTreeMap<String, usize> {
        &self.drops
    }

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
            // The per-RPC error vocabulary: which `<error code/text>` pairs THIS RPC's
            // error arm accepts. It is a closed set and it differs per RPC, so it can
            // only be read off the arm's own error disjunction.
            let vocab = error_vocabulary(&fields);
            variants.push(ResponseVariant {
                tag,
                module_name: module,
                kind,
                error_class: (kind == ResponseVariantKind::Error)
                    .then(|| vocab.class())
                    .flatten(),
                error_codes: vocab.codes,
                error_texts: vocab.texts,
                error_code_min: vocab.code_min,
                error_code_max: vocab.code_max,
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

    ResponseIndex {
        by_x,
        in_slices,
        drops: resolver.drop_counts(),
    }
}

/// The `<error>` codes/texts one response variant accepts, gathered from its error
/// disjunction.
#[derive(Default)]
struct ErrorVocabulary {
    codes: Vec<i64>,
    texts: Vec<String>,
    code_min: Option<i64>,
    code_max: Option<i64>,
}

impl ErrorVocabulary {
    /// Which side the codes blame: 4xx is the client's fault, 5xx the server's. Derived
    /// from the evidence rather than the variant's name, since WA spells the two arms
    /// inconsistently (`…ResponseServerError` but also `…ResponseInternalServerError`).
    /// `None` when the arm pins no code at all, or mixes both families (never guessed).
    fn class(&self) -> Option<ErrorClass> {
        let of = |c: i64| match c {
            400..=499 => Some(ErrorClass::Client),
            500..=599 => Some(ErrorClass::Server),
            _ => None,
        };
        let mut seen: Option<ErrorClass> = None;
        for c in self
            .codes
            .iter()
            .copied()
            .chain(self.code_min)
            .chain(self.code_max)
        {
            match (of(c), seen) {
                (None, _) => return None,
                (Some(cur), None) => seen = Some(cur),
                (Some(cur), Some(prev)) if cur == prev => {}
                _ => return None,
            }
        }
        seen
    }
}

/// Collect the `<error>` vocabulary from a variant's resolved fields.
///
/// An error variant's payload is an `errorXxxErrors` union field whose alternatives are
/// the per-namespace error mixins; each mixin pins its own `text`/`code`
/// (`literal(attrString, e, "text", "rate-overlimit")` + `literal(attrInt, e, "code",
/// 429)`), except the fallback arms, which range-check the code instead
/// (`attrIntRange(e, "code", 500, 599)`). Both forms are already carried on the fields
/// (as `literal_value` / `int_min`+`int_max`), so this reads them back rather than
/// re-parsing the bundle.
fn error_vocabulary(fields: &[ParsedField]) -> ErrorVocabulary {
    let mut v = ErrorVocabulary::default();
    collect_error_vocabulary(fields, &mut v);
    v.codes.sort_unstable();
    v.codes.dedup();
    v.texts.sort();
    v.texts.dedup();
    v
}

fn collect_error_vocabulary(fields: &[ParsedField], out: &mut ErrorVocabulary) {
    for f in fields {
        if let Some(variants) = &f.union_variants {
            for uv in variants {
                collect_variant_vocabulary(uv, out);
            }
        }
        if let Some(children) = &f.children {
            collect_error_vocabulary(children, out);
        }
    }
}

fn collect_variant_vocabulary(uv: &UnionVariant, out: &mut ErrorVocabulary) {
    for f in &uv.fields {
        match (f.wire_name.as_deref().unwrap_or(&f.name), &f.literal_value) {
            ("code", Some(lit)) => {
                if let Ok(code) = lit.parse::<i64>() {
                    out.codes.push(code);
                }
            }
            ("text", Some(lit)) => out.texts.push(lit.clone()),
            // A fallback arm accepts any text within a code RANGE (400–499 / 500–599),
            // which no enumeration of exact codes can express.
            ("code", None) => {
                if let (Some(min), Some(max)) = (f.int_min, f.int_max) {
                    out.code_min = Some(out.code_min.map_or(min, |cur: i64| cur.min(min)));
                    out.code_max = Some(out.code_max.map_or(max, |cur: i64| cur.max(max)));
                }
            }
            _ => {}
        }
        // A variant that nests a further disjunction (union-of-unions).
        if let Some(nested) = &f.union_variants {
            for inner in nested {
                collect_variant_vocabulary(inner, out);
            }
        }
    }
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

    /// A minimal RPC with one client-error arm over two error mixins, plus the
    /// open-ended server fallback — the shape every namespace repeats.
    const ERROR_RPC: &str = r#"
    __d("WASmaxInFooIQErrorBadRequestMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxParseUtils").assertTag(e, "error"); if(!t.success) return t;
            var n = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, e, "text", "bad-request"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrInt, e, "code", 400);
            return r.success ? o("WAResultOrError").makeResult({text:n.value,code:r.value}) : r;
        }
        l.parseIQErrorBadRequestMixin = e;
    }), 98);
    __d("WASmaxInFooIQErrorFallbackServerMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxParseUtils").assertTag(e, "error"); if(!t.success) return t;
            var n = o("WASmaxParseUtils").attrString(e, "text"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").attrIntRange(e, "code", 500, 599);
            return r.success ? o("WAResultOrError").makeResult({text:n.value,code:r.value}) : r;
        }
        l.parseIQErrorFallbackServerMixin = e;
    }), 98);
    __d("WASmaxInFooClientErrors",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxInFooIQErrorBadRequestMixin").parseIQErrorBadRequestMixin(e);
            if(t.success) return o("WAResultOrError").makeResult({name:"IQErrorBadRequest",value:t.value});
            return o("WASmaxParseUtils").errorMixinDisjunction(e,["IQErrorBadRequest"],[t]);
        }
        l.parseClientErrors = e;
    }), 98);
    __d("WASmaxInFooServerErrors",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxInFooIQErrorFallbackServerMixin").parseIQErrorFallbackServerMixin(e);
            if(t.success) return o("WAResultOrError").makeResult({name:"IQErrorFallbackServer",value:t.value});
            return o("WASmaxParseUtils").errorMixinDisjunction(e,["IQErrorFallbackServer"],[t]);
        }
        l.parseServerErrors = e;
    }), 98);
    __d("WASmaxInFooGetBarResponseSuccess",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e,t){
            var n = o("WASmaxParseUtils").assertTag(e, "iq"); if(!n.success) return n;
            var s = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, e, "type", "result");
            return s.success ? o("WAResultOrError").makeResult({type:s.value}) : s;
        }
        l.parseGetBarResponseSuccess = e;
    }), 98);
    __d("WASmaxInFooGetBarResponseClientError",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e,t){
            var n = o("WASmaxParseUtils").assertTag(e, "iq"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").flattenedChildWithTag(e, "error"); if(!r.success) return r;
            var i = o("WASmaxInFooClientErrors").parseClientErrors(r.value);
            return i.success ? o("WAResultOrError").makeResult({errorClientErrors:i.value}) : i;
        }
        l.parseGetBarResponseClientError = e;
    }), 98);
    __d("WASmaxInFooGetBarResponseServerError",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e,t){
            var n = o("WASmaxParseUtils").assertTag(e, "iq"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").flattenedChildWithTag(e, "error"); if(!r.success) return r;
            var i = o("WASmaxInFooServerErrors").parseServerErrors(r.value);
            return i.success ? o("WAResultOrError").makeResult({errorServerErrors:i.value}) : i;
        }
        l.parseGetBarResponseServerError = e;
    }), 98);
    __d("WASmaxFooGetBarRPC",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e,t){
            var n = o("WASmaxInFooGetBarResponseSuccess").parseGetBarResponseSuccess(e,t);
            if(n.success) return o("WAResultOrError").makeResult({name:"GetBarResponseSuccess",value:n.value});
            var r = o("WASmaxInFooGetBarResponseClientError").parseGetBarResponseClientError(e,t);
            if(r.success) return o("WAResultOrError").makeResult({name:"GetBarResponseClientError",value:r.value});
            var a = o("WASmaxInFooGetBarResponseServerError").parseGetBarResponseServerError(e,t);
            return a.success ? o("WAResultOrError").makeResult({name:"GetBarResponseServerError",value:a.value}) : a;
        }
        l.default = e;
    }), 98);"#;

    #[test]
    fn variant_carries_its_closed_error_vocabulary() {
        let defs = wa_transform::extract_module_definitions(ERROR_RPC);
        let idx = build_pass(&defs, ERROR_RPC);
        let pr = idx.get_by_x("FooGetBar").expect("indexed by X");
        let v = |tag: &str| {
            pr.variants
                .iter()
                .find(|v| v.tag == tag)
                .unwrap_or_else(|| panic!("no variant {tag}"))
        };
        // A success variant carries no error vocabulary and no error class.
        let ok = v("GetBarResponseSuccess");
        assert_eq!(ok.kind, ResponseVariantKind::Success);
        assert!(ok.error_class.is_none());
        assert!(ok.error_codes.is_empty() && ok.error_texts.is_empty());
        // The client arm's vocabulary is CLOSED: exactly what its disjunction accepts.
        // Answering `404 item-not-found` here matches no branch — the bug this exists
        // to make visible — so 404 must not appear.
        let ce = v("GetBarResponseClientError");
        assert_eq!(ce.error_class, Some(ErrorClass::Client));
        assert_eq!(ce.error_codes, vec![400]);
        assert_eq!(ce.error_texts, vec!["bad-request".to_string()]);
        assert_eq!((ce.error_code_min, ce.error_code_max), (None, None));
        // The server arm is the open-ended fallback: any text, any code in 500..=599.
        let se = v("GetBarResponseServerError");
        assert_eq!(se.error_class, Some(ErrorClass::Server));
        assert!(se.error_codes.is_empty(), "a range is not an exact code");
        assert_eq!(
            (se.error_code_min, se.error_code_max),
            (Some(500), Some(599))
        );
    }

    #[test]
    fn error_class_is_derived_from_codes_not_from_the_variant_name() {
        // Codes decide, so `…ResponseInternalServerError` (which reads like a server
        // arm but is spelled inconsistently across namespaces) can't be misfiled.
        let v = ErrorVocabulary {
            codes: vec![400, 429],
            ..Default::default()
        };
        assert_eq!(v.class(), Some(ErrorClass::Client));
        let v = ErrorVocabulary {
            code_min: Some(500),
            code_max: Some(599),
            ..Default::default()
        };
        assert_eq!(v.class(), Some(ErrorClass::Server));
        // Mixed families, or a code outside both, is not classified — never guessed.
        let v = ErrorVocabulary {
            codes: vec![400, 500],
            ..Default::default()
        };
        assert_eq!(v.class(), None);
        let v = ErrorVocabulary {
            codes: vec![304],
            ..Default::default()
        };
        assert_eq!(v.class(), None);
        assert_eq!(ErrorVocabulary::default().class(), None);
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
