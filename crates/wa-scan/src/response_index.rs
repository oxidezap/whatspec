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
    ErrorArm, ParsedField, ParsedFieldType, ParsedResponse, ResponseVariant, ResponseVariantKind,
};

use crate::response_smax::{
    Drops, Resolved, Resolver, analyze_module_exports, scan_cascade_variants,
};
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
    ///
    /// Shared with the resolvers this index builds later, so the request-anchored
    /// fallback reports into it too — and therefore only meaningful once the whole scan
    /// has run. [`crate::scan_iq_with_diagnostics`] snapshots it at the end, not here.
    drops: Drops,
}

impl ResponseIndex {
    /// See [`ResponseIndex::drops`]. Call after the scan; the fallback path adds to it.
    pub(crate) fn drop_counts(&self) -> BTreeMap<String, usize> {
        self.drops
            .borrow()
            .iter()
            .map(|(reason, keys)| (reason.clone(), keys.len()))
            .collect()
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
        let resolver = Resolver::with_drops(&slices, self.drops.clone());
        let prefix = format!("WASmaxIn{x}Response");
        for (name, slice) in &self.in_slices {
            let Some(variant) = name.strip_prefix(&prefix) else {
                continue;
            };
            // Skip the bare `…Response`, error variants, and mixin payloads.
            if variant.is_empty()
                || variant.contains("Mixin")
                || variant_kind(variant, &[]) != ResponseVariantKind::Success
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
            let kind = variant_kind(&tag, &resolver.assertions(&module, &func));
            if kind == ResponseVariantKind::Success && primary.is_empty() {
                primary = fields.clone();
            }
            // The variant's same-node discriminators (e.g. `type:"result"` / `type:"error"`),
            // recovered separately since the JS keeps them as parser asserts, not fields.
            // These let codegen guard each arm so the outcome union doesn't misclassify.
            let assertions = resolver.assertions(&module, &func);
            // The per-RPC error vocabulary: which `<error code/text>` pairs THIS RPC's
            // error arm accepts. It is a closed set and it differs per RPC, so it can
            // only be read off the arm's own error arm.
            //
            // Gated on the variant kind, and not merely used to gate `error_class`: a
            // SUCCESS payload can legitimately nest a union whose variant pins a `code`
            // or `text` field for unrelated reasons (three PreKeys success variants do),
            // and reporting that as an accepted error vocabulary contradicts the
            // per-error-arm meaning documented on `ResponseVariant`.
            let vocab = if kind.is_error() {
                error_vocabulary(&fields)
            } else {
                ErrorVocabulary::default()
            };
            variants.push(ResponseVariant {
                tag,
                module_name: module,
                // The side at fault is a property of the codes, so it is settled only
                // once the vocabulary is read.
                kind: vocab.refine(kind),
                error_arms: vocab.arms,
                error_envelope: vocab.envelope,
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
        drops: resolver.drops(),
    }
}

/// The `<error>` codes/texts one response variant accepts, gathered from its error
/// disjunction.
#[derive(Default)]
struct ErrorVocabulary {
    /// The accepted `(code, text)` shapes, in parser order.
    arms: Vec<ErrorArm>,
    /// Pins on the `<error>` node enclosing the ones the arms discriminate, for a
    /// two-level error. Recorded once rather than duplicated into every arm.
    envelope: Option<ErrorArm>,
}

impl ErrorVocabulary {
    /// Refine `Error` into the side at fault: 4xx is the client's, 5xx the server's.
    /// Derived from every code the variant accepts — arms and envelope alike — so a
    /// variant that mixes families, or pins something outside both (the 207 partial
    /// failure), stays a plain `Error` rather than being guessed into a side.
    fn refine(&self, kind: ResponseVariantKind) -> ResponseVariantKind {
        if kind != ResponseVariantKind::Error {
            return kind;
        }
        let of = |c: i64| match c {
            400..=499 => Some(ResponseVariantKind::ClientError),
            500..=599 => Some(ResponseVariantKind::ServerError),
            _ => None,
        };
        let mut seen: Option<ResponseVariantKind> = None;
        for c in self
            .arms
            .iter()
            .chain(self.envelope.as_ref())
            .flat_map(|a| [a.code, a.code_min, a.code_max])
            .flatten()
        {
            match (of(c), seen) {
                (None, _) => return ResponseVariantKind::Error,
                (Some(cur), None) => seen = Some(cur),
                (Some(cur), Some(prev)) if cur == prev => {}
                _ => return ResponseVariantKind::Error,
            }
        }
        seen.unwrap_or(ResponseVariantKind::Error)
    }
}

/// Collect the `<error>` vocabulary from an error variant's resolved fields.
///
/// The usual shape is an `errorXxxErrors` union field whose alternatives are the
/// per-namespace error mixins, each pinning its own `text`/`code`
/// (`literal(attrString, e, "text", "rate-overlimit")` + `literal(attrInt, e, "code",
/// 429)`), except the fallback arms, which range-check the code instead
/// (`attrIntRange(e, "code", 500, 599)`).
///
/// But a good number of RPCs skip the disjunction and parse a single `<error>` child
/// directly — `SetResponseConflict` pins `409`/`conflict` as plain nested fields, and
/// `GetAccessTokenAndSessionCookiesResponseTooManyAttempts` pins `431` the same way. So
/// the `code`/`text` reading is applied to EVERY traversed field, not only to fields
/// inside a `UnionVariant`; restricting it to unions silently emptied the vocabulary of
/// 29 error variants. Both forms are already carried on the fields (as `literal_value` /
/// `int_min`+`int_max`), so this reads them back rather than re-parsing the bundle.
fn error_vocabulary(fields: &[ParsedField]) -> ErrorVocabulary {
    let mut v = ErrorVocabulary::default();
    let from_union = collect_error_arms(fields, &mut v.arms);
    // Partition the variant's own (non-alternative) pins by the NODE they are read from.
    // `SetResponsePreKeySuccessVnameFailure` pins `code=207` on `<error>` and
    // range-checks `code` 400..=599 on the `<error><error>` inside it: folding both into
    // one envelope tells a consumer that 207 must also fall in 400..=599, and leaves the
    // inner range attached to nothing. The deepest pins belong to the node the arms
    // discriminate and are merged into them; anything shallower is the envelope.
    let mut by_path: std::collections::BTreeMap<Vec<String>, ErrorArm> = Default::default();
    pins_by_path(fields, &[], &mut by_path);
    if from_union && !by_path.is_empty() {
        let deepest = by_path.keys().map(Vec::len).max().unwrap_or(0);
        let (inner, outer): (Vec<_>, Vec<_>) = by_path
            .into_iter()
            .partition(|(path, _)| path.len() == deepest && deepest > 0);
        // Shared constraints of the discriminating node: every arm is subject to them.
        for (_, shared) in &inner {
            for arm in &mut v.arms {
                arm.code = arm.code.or(shared.code);
                arm.text = arm.text.clone().or_else(|| shared.text.clone());
                arm.code_min = arm.code_min.or(shared.code_min);
                arm.code_max = arm.code_max.or(shared.code_max);
            }
        }
        let mut envelope = ErrorArm::default();
        for (_, outer_pins) in outer {
            envelope.code = envelope.code.or(outer_pins.code);
            envelope.text = envelope.text.or(outer_pins.text);
            envelope.code_min = envelope.code_min.or(outer_pins.code_min);
            envelope.code_max = envelope.code_max.or(outer_pins.code_max);
        }
        if envelope != ErrorArm::default() {
            v.envelope = Some(envelope);
        }
    }
    v
}

/// The `code`/`text` pins of the variant's own fields, grouped by the node path they are
/// read from. Disjunction alternatives are skipped — each of those is its own arm.
fn pins_by_path(
    fields: &[ParsedField],
    base: &[String],
    out: &mut std::collections::BTreeMap<Vec<String>, ErrorArm>,
) {
    for f in fields {
        let mut path = base.to_vec();
        path.extend(f.source_path.iter().flatten().cloned());
        match (f.wire_name.as_deref().unwrap_or(&f.name), &f.literal_value) {
            ("code", Some(lit)) => {
                if let Ok(code) = lit.parse::<i64>() {
                    out.entry(path.clone()).or_default().code = Some(code);
                }
            }
            ("text", Some(lit)) => {
                out.entry(path.clone()).or_default().text = Some(lit.clone());
            }
            ("code", None) => {
                if let (Some(min), Some(max)) = (f.int_min, f.int_max) {
                    let e = out.entry(path.clone()).or_default();
                    e.code_min = Some(min);
                    e.code_max = Some(max);
                }
            }
            _ => {}
        }
        if let Some(children) = &f.children {
            pins_by_path(children, &path, out);
        }
    }
}

/// One arm per accepted `<error>` shape, so the `(code, text)` pairing survives.
///
/// A `…Errors` disjunction contributes one arm per alternative; an RPC that parses a
/// single `<error>` child directly contributes exactly one unnamed arm. Flattening these
/// into two independent lists would let an emitter combine one arm's code with another's
/// text — `400 feature-not-implemented` matches no branch and is unparseable, which is
/// the whole failure class this domain exists to prevent.
fn collect_error_arms(fields: &[ParsedField], out: &mut Vec<ErrorArm>) -> bool {
    let mut found_union = false;
    collect_union_arms(fields, out, &mut found_union);
    if !found_union {
        // No disjunction: the variant parses one `<error>` shape, so its pins are one arm.
        // An arm with NO pins is still information when the parser reads `code`/`text` at
        // all — it says "one accepted shape, unconstrained", which is a different claim
        // from "no vocabulary extracted". `CreateCustomPaymentMethodResponseIQErrorWithCodeAndReason`
        // and `RemoveCustomPaymentMethodResponseError` are that shape, and dropping their
        // arm made an unrestricted error indistinguishable from a failed extraction.
        let arm = arm_pins(fields);
        if arm != ErrorArm::default() || reads_error_fields(fields) {
            out.push(arm);
        }
    }
    found_union
}

/// Walk the tree for disjunction alternatives, pushing one arm per leaf alternative.
fn collect_union_arms(fields: &[ParsedField], out: &mut Vec<ErrorArm>, found: &mut bool) {
    for f in fields {
        for uv in f.union_variants.iter().flatten() {
            *found = true;
            // What THIS alternative pins itself, before descending. An alternative can
            // both pin `429`/`rate-overlimit` and carry a further payload union of
            // reasons (`CreateOrAddGroupRateLimitError` does), and the nested reasons pin
            // nothing — so replacing the outer arm with them would publish two arms with
            // no usable pairing and drop the shape the server actually sends.
            let own = arm_pins(&uv.fields);
            let before = out.len();
            let mut nested = false;
            collect_union_arms(&uv.fields, out, &mut nested);
            if nested {
                for a in &mut out[before..] {
                    // Inner names are the specific ones; the outer pins are inherited
                    // wherever the inner arm has none of its own.
                    a.name.get_or_insert_with(|| uv.name.clone());
                    a.code = a.code.or(own.code);
                    a.text = a.text.clone().or_else(|| own.text.clone());
                    a.code_min = a.code_min.or(own.code_min);
                    a.code_max = a.code_max.or(own.code_max);
                }
            } else {
                let mut arm = own;
                arm.name = Some(uv.name.clone());
                out.push(arm);
            }
        }
        if let Some(children) = &f.children {
            collect_union_arms(children, out, found);
        }
    }
}

/// Whether the parser reads an `<error>` `code`/`text` at all, pinned or not.
fn reads_error_fields(fields: &[ParsedField]) -> bool {
    fields.iter().any(|f| {
        matches!(f.wire_name.as_deref().unwrap_or(&f.name), "code" | "text")
            || f.children.as_deref().is_some_and(reads_error_fields)
    })
}

/// The `code`/`text` pins of one error shape, scanning its whole field subtree but not
/// descending into disjunction alternatives (each of those is its own arm).
fn arm_pins(fields: &[ParsedField]) -> ErrorArm {
    let mut arm = ErrorArm::default();
    fn walk(fields: &[ParsedField], arm: &mut ErrorArm) {
        for f in fields {
            match (f.wire_name.as_deref().unwrap_or(&f.name), &f.literal_value) {
                ("code", Some(lit)) => arm.code = lit.parse::<i64>().ok().or(arm.code),
                ("text", Some(lit)) => arm.text = Some(lit.clone()),
                // A fallback arm accepts any text within a code RANGE (400–499 /
                // 500–599), which no enumeration of exact codes can express.
                ("code", None) => {
                    if let (Some(min), Some(max)) = (f.int_min, f.int_max) {
                        arm.code_min = Some(min);
                        arm.code_max = Some(max);
                    }
                }
                _ => {}
            }
            if let Some(children) = &f.children {
                walk(children, arm);
            }
        }
    }
    walk(fields, &mut arm);
    arm
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

/// Classify a response variant: by what its parser asserts on the wire first, then by
/// its discriminator tag's tokens.
///
/// The root discriminator wins because it is the protocol talking rather than a naming
/// convention. `SetResponsePreKeySuccessVnameFailure` reads as a success by every token
/// in its name, yet it asserts `type="error"` and parses an `<error code="207">` — the
/// prekeys landed, the vname did not, and the server said so with an error stanza.
/// Judging it by the tag alone classified a wire error as a success and, since the error
/// vocabulary is gated on the kind, silently dropped the codes and texts it accepts.
fn variant_kind(tag: &str, assertions: &[wa_ir::ResponseAssertion]) -> ResponseVariantKind {
    let asserts_error = assertions.iter().any(|a| {
        a.kind == wa_ir::AssertionKind::Attr
            && a.name.as_deref() == Some("type")
            && a.value.as_deref() == Some("error")
    });
    if asserts_error {
        return ResponseVariantKind::Error;
    }
    variant_kind_by_tag(tag)
}

/// The name-token fallback, for a variant whose parser pins no `type`.
fn variant_kind_by_tag(tag: &str) -> ResponseVariantKind {
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
        // A success variant carries no error vocabulary.
        let ok = v("GetBarResponseSuccess");
        assert_eq!(ok.kind, ResponseVariantKind::Success);
        assert!(ok.error_arms.is_empty() && ok.error_envelope.is_none());
        // The client arm's vocabulary is CLOSED: exactly what its disjunction accepts.
        // Answering `404 item-not-found` here matches no branch — the bug this exists
        // to make visible — so 404 must not appear.
        let ce = v("GetBarResponseClientError");
        assert_eq!(ce.kind, ResponseVariantKind::ClientError);
        assert_eq!(ce.error_arms.len(), 1);
        assert_eq!(
            (ce.error_arms[0].code, ce.error_arms[0].text.as_deref()),
            (Some(400), Some("bad-request"))
        );
        // The server arm is the open-ended fallback: any text, any code in 500..=599.
        let se = v("GetBarResponseServerError");
        assert_eq!(se.kind, ResponseVariantKind::ServerError);
        assert_eq!(se.error_arms.len(), 1);
        assert_eq!(se.error_arms[0].code, None, "a range is not an exact code");
        assert_eq!(
            (se.error_arms[0].code_min, se.error_arms[0].code_max),
            (Some(500), Some(599))
        );
    }

    #[test]
    fn error_arms_keep_code_and_text_paired() {
        // The flattened lists cannot say which code goes with which text: an arm taking
        // 400/bad-request and 429/rate-overlimit flattens to two codes and two texts,
        // and nothing then rules out `400 rate-overlimit` — a combination the parser
        // rejects. An emitter picking one value from each list would produce exactly the
        // unparseable stanza this domain exists to prevent, so the pairing is carried.
        let defs = wa_transform::extract_module_definitions(ERROR_RPC);
        let idx = build_pass(&defs, ERROR_RPC);
        let pr = idx.get_by_x("FooGetBar").expect("indexed by X");
        let v = |tag: &str| pr.variants.iter().find(|v| v.tag == tag).expect(tag);

        let ce = v("GetBarResponseClientError");
        assert_eq!(ce.error_arms.len(), 1);
        let arm = &ce.error_arms[0];
        assert_eq!(arm.name.as_deref(), Some("IQErrorBadRequest"));
        assert_eq!(
            (arm.code, arm.text.as_deref()),
            (Some(400), Some("bad-request"))
        );

        // A fallback arm pins a range and NO text: it accepts any text in 500..=599, so
        // a `text` of `None` there is the fact, not a gap.
        let se = v("GetBarResponseServerError");
        assert_eq!(se.error_arms.len(), 1);
        let fb = &se.error_arms[0];
        assert_eq!(fb.name.as_deref(), Some("IQErrorFallbackServer"));
        assert_eq!(fb.code, None);
        assert_eq!(fb.text, None);
        assert_eq!((fb.code_min, fb.code_max), (Some(500), Some(599)));

        // A success variant carries no arms at all.
        assert!(v("GetBarResponseSuccess").error_arms.is_empty());
    }

    #[test]
    fn a_nested_payload_union_inherits_the_outer_error_pins() {
        // An alternative can BOTH pin a code/text and carry a further payload union of
        // reasons that pin nothing (`CreateOrAddGroupRateLimitError` does). Replacing the
        // outer arm with the nested reasons publishes arms with no usable pairing and
        // drops the shape the server actually sends, so the outer pins are inherited.
        let bundle = ERROR_RPC.replace(
            r#"__d("WASmaxInFooClientErrors",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxInFooIQErrorBadRequestMixin").parseIQErrorBadRequestMixin(e);
            if(t.success) return o("WAResultOrError").makeResult({name:"IQErrorBadRequest",value:t.value});
            return o("WASmaxParseUtils").errorMixinDisjunction(e,["IQErrorBadRequest"],[t]);
        }
        l.parseClientErrors = e;
    }), 98);"#,
            r#"__d("WASmaxInFooTimeRateLimitMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxParseUtils").assertTag(e, "error"); if(!t.success) return t;
            var n = o("WASmaxParseUtils").attrString(e, "reason");
            return n.success ? o("WAResultOrError").makeResult({reason:n.value}) : n;
        }
        l.parseTimeRateLimitMixin = e;
    }), 98);
    __d("WASmaxInFooReasons",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxInFooTimeRateLimitMixin").parseTimeRateLimitMixin(e);
            if(t.success) return o("WAResultOrError").makeResult({name:"TimeRateLimit",value:t.value});
            return o("WASmaxParseUtils").errorMixinDisjunction(e,["TimeRateLimit"],[t]);
        }
        l.parseReasons = e;
    }), 98);
    __d("WASmaxInFooRateLimitMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxParseUtils").assertTag(e, "error"); if(!t.success) return t;
            var n = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, e, "text", "rate-overlimit"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrInt, e, "code", 429); if(!r.success) return r;
            var q = o("WASmaxInFooReasons").parseReasons(e);
            return q.success ? o("WAResultOrError").makeResult({text:n.value,code:r.value,reason:q.value}) : q;
        }
        l.parseRateLimitMixin = e;
    }), 98);
    __d("WASmaxInFooClientErrors",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
        function e(e){
            var t = o("WASmaxInFooRateLimitMixin").parseRateLimitMixin(e);
            if(t.success) return o("WAResultOrError").makeResult({name:"RateLimitError",value:t.value});
            return o("WASmaxParseUtils").errorMixinDisjunction(e,["RateLimitError"],[t]);
        }
        l.parseClientErrors = e;
    }), 98);"#,
        );
        let defs = wa_transform::extract_module_definitions(&bundle);
        let idx = build_pass(&defs, &bundle);
        let pr = idx.get_by_x("FooGetBar").expect("indexed by X");
        let ce = pr
            .variants
            .iter()
            .find(|v| v.tag == "GetBarResponseClientError")
            .expect("client error");
        assert!(
            !ce.error_arms.is_empty(),
            "the nested union must not erase the arm"
        );
        for arm in &ce.error_arms {
            assert_eq!(
                (arm.code, arm.text.as_deref()),
                (Some(429), Some("rate-overlimit")),
                "every nested reason keeps the outer pins: {arm:?}"
            );
        }
        // The specific inner name wins over the outer one.
        assert_eq!(ce.error_arms[0].name.as_deref(), Some("TimeRateLimit"));
    }

    #[test]
    fn the_error_side_is_derived_from_codes_not_from_the_variant_name() {
        // The codes decide, so `…ResponseInternalServerError` (which reads like a server
        // arm but is spelled inconsistently across namespaces) cannot be misfiled, and a
        // variant whose codes settle nothing stays a plain `Error` rather than a guess.
        let arm = |code: Option<i64>, min: Option<i64>, max: Option<i64>| ErrorArm {
            code,
            code_min: min,
            code_max: max,
            ..Default::default()
        };
        let vocab = |arms: Vec<ErrorArm>| ErrorVocabulary {
            arms,
            envelope: None,
        };
        let refine = |arms: Vec<ErrorArm>| vocab(arms).refine(ResponseVariantKind::Error);

        assert_eq!(
            refine(vec![arm(Some(400), None, None), arm(Some(429), None, None)]),
            ResponseVariantKind::ClientError
        );
        assert_eq!(
            refine(vec![arm(None, Some(500), Some(599))]),
            ResponseVariantKind::ServerError
        );
        // Mixed families, or a code outside both, is not classified — never guessed.
        assert_eq!(
            refine(vec![arm(Some(400), None, None), arm(Some(500), None, None)]),
            ResponseVariantKind::Error
        );
        assert_eq!(
            refine(vec![arm(Some(207), None, None)]),
            ResponseVariantKind::Error
        );
        assert_eq!(refine(vec![]), ResponseVariantKind::Error);
        // A success variant is never touched.
        assert_eq!(
            vocab(vec![arm(Some(400), None, None)]).refine(ResponseVariantKind::Success),
            ResponseVariantKind::Success
        );
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
