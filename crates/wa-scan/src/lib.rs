//! Native tooling: scan extracted WA Web modules into [`wa_ir`] types (AST-only,
//! via oxc). Port of `scan-iq-stanzas-ast.ts`.
//!
//! Pipeline: [`wa_transform::extract_module_definitions`] splits a bundle into
//! `__d()` modules; we keep only IQ-relevant ones (by dependency) and run
//! [`scan_module_source`] on each, producing [`wa_ir::IqScanResult`].
#![cfg(not(target_arch = "wasm32"))]

mod alias;
mod attrs;
mod content_length_index;
mod helper_index;
mod mixin_index;
mod module;
mod request;
mod response;
mod response_index;
mod response_smax;

pub use mixin_index::MixinIndex;
pub use module::{CrossModuleStat, DropReason, scan_module_outcome, scan_module_source};
pub use response::parse_module_wap_parsers;

use std::collections::{HashMap, HashSet};

use wa_ir::{IqIr, IqScanResult, IqStanzaDef, IqType, Unparseable, WapChildNode};
use wa_transform::ModuleDefinition;

/// Request leaf tags that carry content in exactly one IQ namespace — the tags safe
/// for the content-length parent-agnostic fallback. A tag used across namespaces
/// (`<id>`: a 3-byte key id in `encrypt`, a product id in `w:biz:catalog`) is
/// excluded so its per-namespace meaning is never conflated.
fn single_namespace_content_tags(stanzas: &[IqStanzaDef]) -> HashSet<String> {
    fn walk(nodes: &[WapChildNode], ns: &str, tag_ns: &mut HashMap<String, HashSet<String>>) {
        for n in nodes {
            if n.content.is_some() {
                tag_ns
                    .entry(n.tag.clone())
                    .or_default()
                    .insert(ns.to_string());
            }
            walk(&n.children, ns, tag_ns);
            for g in &n.variant_groups {
                for v in &g.variants {
                    walk(&v.children, ns, tag_ns);
                }
            }
        }
    }
    let mut tag_ns: HashMap<String, HashSet<String>> = HashMap::new();
    for s in stanzas {
        walk(&s.request.children, &s.namespace, &mut tag_ns);
    }
    tag_ns
        .into_iter()
        .filter(|(_, namespaces)| namespaces.len() == 1)
        .map(|(tag, _)| tag)
        .collect()
}

/// Cross-module (`mergeStanzas`, Phase 2) recovery counters for the IQ domain,
/// surfaced in `manifest.diagnostics.iq.crossModule`. They make the Phase-2 fix
/// visible and regressable: if a future bundle/codegen change silently broke
/// fragment merging, `requests_enriched`/`fields_recovered` would drop to 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossModuleStats {
    /// Request modules that fold in ≥1 cross-module `o("WASmaxOut…").merge…Mixin`
    /// fragment (whether or not it carried `<iq>` children).
    pub requests_with_mixins: usize,
    /// Of those, how many gained ≥1 field (tag/attr) ONLY via the fragment merge —
    /// i.e. requests whose IR would lose data without Phase 2.
    pub requests_enriched: usize,
    /// Total tag/attr fields recovered across all enriched requests.
    pub fields_recovered: usize,
}

/// A module is worth scanning only if it builds an IQ stanza. We detect that by
/// CONTENT of the module slice — both builders end up calling `("iq", …)` — gated
/// by the dependency that supplies each builder, so a stray substring inside a
/// string literal can't trigger a scan:
///
/// - legacy `.wap("iq", …)`  needs `WAWap` (the old builder), AND
/// - newer `.smax("iq", …)`  needs `WASmaxJsx` (the smax builder).
///
/// This is more precise than the old dep-only filter: the smax `Request` modules
/// are decoupled from the IQ transport (`WADeprecatedSendIq`/`WAComms`), so the
/// old `(transport && WAWap)` rule matched none of them.
fn is_iq_module(deps: &[String], slice: &str) -> bool {
    let has = |name: &str| deps.iter().any(|d| d == name);
    // Tolerate either quote style on the tag (`"iq"` / `'iq'`); the AST re-check
    // in `scan_module_outcome` confirms the real tag, so a permissive pre-filter
    // only risks parsing a few extra modules, never silently skipping one.
    let builds = |method: &str| {
        slice.contains(&format!("{method}(\"iq\"")) || slice.contains(&format!("{method}('iq'"))
    };
    (builds(".wap") && has("WAWap")) || (builds(".smax") && has("WASmaxJsx"))
}

/// Scan a whole bundle: split into modules, keep IQ-relevant ones, scan each.
pub fn scan_iq_stanzas(bundle_source: &str) -> IqScanResult {
    let module_defs = wa_transform::extract_module_definitions(bundle_source);
    scan_iq_stanzas_from_modules(bundle_source, &module_defs)
}

/// Scan IQ stanzas from an already-split module index (shares one whole-bundle
/// parse with the other extractors; only IQ-relevant module slices are re-parsed).
pub fn scan_iq_stanzas_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
) -> IqScanResult {
    scan_iq_with_diagnostics(source, module_defs).0
}

/// Like [`scan_iq_stanzas_from_modules`], but also returns the cross-module
/// (Phase 2) recovery counters for `manifest.diagnostics.iq.crossModule`.
pub fn scan_iq_with_diagnostics(
    source: &str,
    module_defs: &[ModuleDefinition],
) -> (IqScanResult, CrossModuleStats) {
    // Build the cross-module helper index first. It resolves wap-returning helpers
    // (`xmppSignedPreKey`, `xmppPreKey`, …) so a child built via `o("Module").fn(...)`
    // / `.map(o("Module").fn)` recovers its subtree instead of leaving a bare node
    // (e.g. `<rotate>` → `<skey><id/><value/><signature/></skey>`). Built before the
    // mixin index so mixin fragment children can expand helper calls too. Helpers
    // don't depend on mixins (they resolve with no contributions), so there's no cycle.
    let helper_index = helper_index::build_pass(module_defs, source);

    // Build the cross-module mixin index once (Phase 2), before scanning. It
    // records what each `WASmaxOut*` mixin contributes to the `<iq>` it folds,
    // so Requests that defer xmlns/type to mixins can be resolved.
    let mixin_index = mixin_index::build_pass(module_defs, source, &helper_index);

    // Build the cross-module response index once (Phase 3). It parses the smax
    // `WASmaxIn*ResponseSuccess` modules so a Request can attach its typed
    // response (the smax response lives in a separate module).
    let response_index = response_index::build_pass(module_defs, source);

    // Build the content-length cross-reference once. It reads the byte length WA
    // Web's parsers pin each wire field to (`child("signature").contentBytes(64)`),
    // to fill request leaf lengths the builder writes opaquely.
    let content_lengths = content_length_index::build_pass(module_defs, source);

    let mut stanzas = Vec::new();
    let mut unparseable = Vec::new();
    let mut cross = CrossModuleStats::default();
    // The same module is often defined in several bundle shards (FB_PKG_DELIM);
    // scan each module name once so identical stanzas aren't emitted per shard
    // (and we don't redo the work).
    let mut seen_modules = std::collections::HashSet::new();
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if !is_iq_module(&m.deps, slice) {
            continue;
        }
        if !seen_modules.insert(m.name.as_str()) {
            continue;
        }
        // Every IQ candidate either yields ≥1 stanza or records why it didn't, so
        // a silently-dropped module surfaces as an `unparseable` entry rather than
        // vanishing. Push order follows the deterministic module scan order.
        match scan_module_outcome(slice, &mixin_index, &response_index, &helper_index) {
            Ok((found, stat)) => {
                stanzas.extend(found);
                if stat.referenced_mixins {
                    cross.requests_with_mixins += 1;
                }
                if stat.fields_recovered > 0 {
                    cross.requests_enriched += 1;
                    cross.fields_recovered += stat.fields_recovered;
                }
            }
            Err(reason) => unparseable.push(Unparseable {
                module_name: m.name.clone(),
                reason: reason.as_str().to_string(),
            }),
        }
    }
    // Cross-reference each request's opaque leaf lengths from the symmetric parsers
    // (`<skey><signature>` gains its 64-byte length). The children of `<iq>` are the
    // tree roots, so their parent path is `iq`.
    //
    // Tags used with content in a single IQ namespace are safe for the parent-agnostic
    // fallback (e.g. `<identity>`/`<type>` live only in `encrypt`, so their length is
    // unambiguous even where the request nests them differently than the parser does).
    // A tag spanning namespaces (`<id>`: a key id in `encrypt`, a product id in
    // `w:biz:catalog`) is excluded, so it's never mislabeled.
    let tag_fallback = single_namespace_content_tags(&stanzas);
    for s in &mut stanzas {
        content_length_index::enrich(
            &mut s.request.children,
            "iq",
            &content_lengths,
            &tag_fallback,
        );
    }

    // Normalize ordering by an intrinsic key so the output (index.json + the
    // grouped codegen) is independent of bundle/source order, matching every
    // other domain (enums/abprops sort by name, mex/appstate use BTreeMaps).
    stanzas.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| iq_type_ord(a.iq_type).cmp(&iq_type_ord(b.iq_type)))
            .then_with(|| a.exported_function.cmp(&b.exported_function))
            .then_with(|| a.module_name.cmp(&b.module_name))
    });
    unparseable.sort_by(|a, b| {
        a.module_name
            .cmp(&b.module_name)
            .then_with(|| a.reason.cmp(&b.reason))
    });

    (
        IqScanResult {
            stanzas,
            unparseable,
        },
        cross,
    )
}

/// Stable ordinal for sorting (`IqType` isn't `Ord`).
fn iq_type_ord(t: IqType) -> u8 {
    match t {
        IqType::Get => 0,
        IqType::Set => 1,
    }
}

/// Uniform extractor entry: scan IQ stanzas and stamp them into the versioned
/// [`IqIr`], matching the `extract_<domain>_from_modules(source, modules, version)`
/// shape of the mex/proto/appstate extractors. [`scan_iq_stanzas_from_modules`]
/// stays the lower-level, version-agnostic scan primitive.
pub fn extract_iq_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> IqIr {
    extract_iq_from_modules_with_diagnostics(source, module_defs, wa_version).0
}

/// Like [`extract_iq_from_modules`], but also returns the cross-module (Phase 2)
/// recovery counters so the pipeline can record them under
/// `manifest.diagnostics.iq.crossModule`.
pub fn extract_iq_from_modules_with_diagnostics(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> (IqIr, CrossModuleStats) {
    let (scan, cross) = scan_iq_with_diagnostics(source, module_defs);
    (
        IqIr {
            wa_version: wa_version.to_string(),
            stanzas: scan.stanzas,
            unparseable: scan.unparseable,
        },
        cross,
    )
}

/// Convenience: split a whole bundle into modules, then extract the IQ IR.
/// Mirrors `extract_mex` / `extract_abprops` for a uniform per-domain surface;
/// the pipeline uses [`extract_iq_from_modules`] to share one split.
pub fn extract_iq(source: &str, wa_version: &str) -> IqIr {
    let module_defs = wa_transform::extract_module_definitions(source);
    extract_iq_from_modules(source, &module_defs, wa_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_filter() {
        // wap path: needs `.wap("iq"` in the slice AND the WAWap dep.
        assert!(is_iq_module(&["WAWap".into()], r#"i.wap("iq",{})"#));
        // smax path: needs `.smax("iq"` AND the WASmaxJsx dep.
        assert!(is_iq_module(
            &["WASmaxJsx".into(), "WAWap".into()],
            r#"o("WASmaxJsx").smax("iq",{})"#
        ));
        // Dep present but no builder call → skip.
        assert!(!is_iq_module(&["WAWap".into()], "var x = 1;"));
        assert!(!is_iq_module(&["WASmaxJsx".into()], "var x = 1;"));
        // Builder call but missing the gating dep → skip (substring safety).
        assert!(!is_iq_module(&[], r#"i.wap("iq",{})"#));
        assert!(!is_iq_module(&[], r#"o("WASmaxJsx").smax("iq",{})"#));
        // Single-quoted tag is tolerated (a minifier quote-style change must not
        // silently skip whole modules).
        assert!(is_iq_module(&["WAWap".into()], r#"i.wap('iq',{})"#));
        assert!(is_iq_module(
            &["WASmaxJsx".into()],
            r#"o("WASmaxJsx").smax('iq',{})"#
        ));
    }

    #[test]
    fn unresolved_smax_candidate_is_tracked_as_unparseable() {
        // An IQ candidate (`.smax("iq"` + WASmaxJsx dep) whose xmlns/type can't be
        // resolved (null attrs, no mixin) must surface in `unparseable`, not vanish.
        let bundle = r#"
            __d("WASmaxOutFooRequest", ["WASmaxJsx"], function(g,r,d,o,e,i,l){
                l.build = function(){ return o("WASmaxJsx").smax("iq", null); };
            }, 1);
        "#;
        let res = scan_iq_stanzas(bundle);
        assert!(res.stanzas.is_empty());
        assert_eq!(res.unparseable.len(), 1);
        assert_eq!(res.unparseable[0].module_name, "WASmaxOutFooRequest");
        assert!(res.unparseable[0].reason.contains("unresolved"));
    }

    #[test]
    fn cross_module_fragment_merges_into_request_and_is_counted() {
        // A Request builds `<iq>` inline with a local `spam_list{jid}` and folds in a
        // cross-module mixin that carries `xmlns`/`type` AND a `spam_list{spam_flow}`
        // fragment. Phase 2 must recover the namespace/type and union the child attrs,
        // and the diagnostic must count exactly that recovery.
        let bundle = r#"
            __d("WASmaxOutSpamBaseReportMixin",["WASmaxJsx","WAWap","WASmaxMixins"],function(g,r,d,o,e,i,l){
                function e(t){ return o("WASmaxJsx").smax("iq",{xmlns:"spam",type:"set"}, o("WASmaxJsx").smax("spam_list",{spam_flow:o("WAWap").CUSTOM_STRING(t.flow)})); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t, e(n)); }
                l.mergeBaseReportMixin = s;
            }, 1);
            __d("WASmaxOutSpamGroupReportRequest",["WASmaxJsx","WAWap","WASmaxOutSpamBaseReportMixin"],function(g,r,d,o,e,i,l){
                function e(n){ return o("WASmaxOutSpamBaseReportMixin").mergeBaseReportMixin(o("WASmaxJsx").smax("iq",null, o("WASmaxJsx").smax("spam_list",{jid:o("WAWap").CUSTOM_STRING(n.jid)})), n); }
                l.makeSpamGroupReportRequest = e;
            }, 1);
        "#;
        let defs = wa_transform::extract_module_definitions(bundle);
        let (scan, cross) = scan_iq_with_diagnostics(bundle, &defs);

        let req = scan
            .stanzas
            .iter()
            .find(|s| s.module_name == "WASmaxOutSpamGroupReportRequest")
            .expect("request stanza");
        // xmlns/type recovered from the mixin (absent in the Request module itself).
        assert_eq!(req.namespace, "spam");
        assert_eq!(req.iq_type, IqType::Set);
        // spam_list carries the local `jid` AND the cross-module `spam_flow`.
        let spam_list = req
            .request
            .children
            .iter()
            .find(|c| c.tag == "spam_list")
            .expect("spam_list child");
        let names: Vec<_> = spam_list.attrs.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"jid"), "local attr preserved");
        assert!(names.contains(&"spam_flow"), "cross-module attr merged in");

        // Diagnostics: exactly the Request folds in a mixin and is enriched by it;
        // only `spam_flow` is new (`jid` was already local), so one field recovered.
        assert_eq!(cross.requests_with_mixins, 1);
        assert_eq!(cross.requests_enriched, 1);
        assert_eq!(cross.fields_recovered, 1);
    }

    #[test]
    fn nested_sub_stanza_union_variants_recovered() {
        // Phase 4: a request whose `<iq>` child (`messages`) gets a base attr
        // (`count`) plus TWO MixinGroup disjunctions — query params (jid XOR invite,
        // via a direct merge + `smax$any` wildcard) and directions (before XOR after,
        // via optionalMerge). Each disjunction must surface as a discriminated
        // variant group on `messages`, not a flattened attr soup.
        let bundle = r#"
            __d("WASmaxOutNlBeforeMixinMixin",["WASmaxJsx","WASmaxMixins","WAWap"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxJsx").smax("messages",{before:o("WAWap").INT(a.b)}); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeBeforeMixinMixin=s;
            },1);
            __d("WASmaxOutNlAfterMixinMixin",["WASmaxJsx","WASmaxMixins","WAWap"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxJsx").smax("messages",{after:o("WAWap").INT(a.a)}); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeAfterMixinMixin=s;
            },1);
            __d("WASmaxOutNlDirections",["WASmaxMixinGroupExhaustiveError","WASmaxOutNlBeforeMixinMixin","WASmaxOutNlAfterMixinMixin"],function(g,r,d,o,e,i,l){
                function sel(t,n){ if(n.before) return o("WASmaxOutNlBeforeMixinMixin").mergeBeforeMixinMixin(t,n.before); if(n.after) return o("WASmaxOutNlAfterMixinMixin").mergeAfterMixinMixin(t,n.after); throw new(o("WASmaxMixinGroupExhaustiveError")).E; }
                l.mergeDirections=sel;
            },1);
            __d("WASmaxOutNlJidParamsMixin",["WASmaxJsx","WASmaxMixins","WAWap"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxJsx").smax("smax$any",{type:"jid",jid:o("WAWap").JID(a.j)}); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeJidParamsMixin=s;
            },1);
            __d("WASmaxOutNlInviteParamsMixin",["WASmaxJsx","WASmaxMixins","WAWap"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxJsx").smax("smax$any",{type:"invite",key:o("WAWap").CUSTOM_STRING(a.k)}); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeInviteParamsMixin=s;
            },1);
            __d("WASmaxOutNlQueryParams",["WASmaxMixinGroupExhaustiveError","WASmaxOutNlJidParamsMixin","WASmaxOutNlInviteParamsMixin"],function(g,r,d,o,e,i,l){
                function sel(t,n){ if(n.jid) return o("WASmaxOutNlJidParamsMixin").mergeJidParamsMixin(t,n.jid); if(n.invite) return o("WASmaxOutNlInviteParamsMixin").mergeInviteParamsMixin(t,n.invite); throw new(o("WASmaxMixinGroupExhaustiveError")).E; }
                l.mergeQueryParams=sel;
            },1);
            __d("WASmaxOutNlQueryParamsMixin",["WASmaxJsx","WASmaxMixins","WASmaxOutNlQueryParams"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxOutNlQueryParams").mergeQueryParams(o("WASmaxJsx").smax("smax$any",null), a.q); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeQueryParamsMixin=s;
            },1);
            __d("WASmaxOutNlPayloadMixin",["WASmaxJsx","WASmaxMixins","WASmaxOutNlDirections","WASmaxOutNlQueryParamsMixin","WAWap"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxOutNlQueryParamsMixin").mergeQueryParamsMixin(o("WASmaxMixins").optionalMerge(o("WASmaxOutNlDirections").mergeDirections, o("WASmaxJsx").smax("messages",{count:o("WAWap").INT(a.c)}), a.d), a.q); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergePayloadMixin=s;
            },1);
            __d("WASmaxOutNlIQPayloadMixin",["WASmaxJsx","WASmaxMixins","WASmaxOutNlPayloadMixin"],function(g,r,d,o,e,i,l){
                function b(a){ return o("WASmaxJsx").smax("iq",{xmlns:"newsletter",type:"get"}, o("WASmaxOutNlPayloadMixin").mergePayloadMixin(o("WASmaxJsx").smax("messages",null), a)); }
                function s(t,n){ return o("WASmaxMixins").mergeStanzas(t,b(n)); }
                l.mergeIQPayloadMixin=s;
            },1);
            __d("WASmaxOutNlGetMessagesRequest",["WASmaxJsx","WASmaxOutNlIQPayloadMixin"],function(g,r,d,o,e,i,l){
                function b(n){ return o("WASmaxOutNlIQPayloadMixin").mergeIQPayloadMixin(o("WASmaxJsx").smax("iq",null), n); }
                l.makeGetMessagesRequest=b;
            },1);
        "#;
        let defs = wa_transform::extract_module_definitions(bundle);
        let scan = scan_iq_stanzas_from_modules(bundle, &defs);
        let req = scan
            .stanzas
            .iter()
            .find(|s| s.module_name == "WASmaxOutNlGetMessagesRequest")
            .expect("request stanza");
        assert_eq!(req.namespace, "newsletter");
        assert_eq!(req.iq_type, IqType::Get);
        let messages = req
            .request
            .children
            .iter()
            .find(|c| c.tag == "messages")
            .expect("messages child recovered via the IQ-payload mixin");
        // Base attr only; the disjunctions are variant groups, not flattened attrs.
        let base: Vec<_> = messages.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(base, ["count"], "only the base attr stays flat: {base:?}");

        // Two variant groups: query params (required, jid/invite) + directions
        // (optional, before/after).
        assert_eq!(messages.variant_groups.len(), 2);
        let variant_attrs = |g: &wa_ir::WapVariantGroup| -> Vec<Vec<String>> {
            g.variants
                .iter()
                .map(|v| v.attrs.iter().map(|a| a.name.clone()).collect())
                .collect()
        };
        let query = messages
            .variant_groups
            .iter()
            .find(|g| !g.optional)
            .expect("required query-params group");
        let qv = variant_attrs(query);
        assert!(
            qv.contains(&vec!["type".into(), "jid".into()]),
            "jid variant: {qv:?}"
        );
        assert!(
            qv.contains(&vec!["type".into(), "key".into()]),
            "invite variant: {qv:?}"
        );

        let directions = messages
            .variant_groups
            .iter()
            .find(|g| g.optional)
            .expect("optional directions group");
        let dv = variant_attrs(directions);
        assert!(
            dv.contains(&vec!["before".into()]) && dv.contains(&vec!["after".into()]),
            "{dv:?}"
        );

        // The wildcard placeholder tag must never reach the IR.
        assert!(
            !req.request.children.iter().any(|c| c.tag == "smax$any"),
            "smax$any wildcard leaked into the request tree"
        );
    }

    #[test]
    fn scans_bundle_with_two_modules_one_iq() {
        let bundle = r#"
            __d("WAWebPlain", ["SomeDep"], function(g,r,d,o,e,i){ e.x = 1; }, 1);
            __d("WAWebDoIq", ["WADeprecatedSendIq","WAWap"], function(g,r,d,o,e,i){
                e.run = function(){ return i.wap("iq", { xmlns: "w:test", type: "get" }); };
            }, 2);
        "#;
        let res = scan_iq_stanzas(bundle);
        assert_eq!(res.stanzas.len(), 1);
        assert_eq!(res.stanzas[0].module_name, "WAWebDoIq");
        assert_eq!(res.stanzas[0].namespace, "w:test");
    }

    /// A prekey helper module + a rotate job that builds `<rotate>` via a
    /// cross-module `o("Helper").xmppSignedPreKey(t)` child (mirrors WAWebRotateKeyJob).
    const PREKEY_BUNDLE: &str = r#"
        __d("WAWebSignalUtilsApi", ["WAWap"], function(g,r,d,o,e,i,l){
            function sk(k){ var t; return (t=o("WAWap")).wap("skey", null,
                t.wap("id", null, t.BIG_ENDIAN_CONTENT(k.keyId, 3)),
                t.wap("value", null, k.pub),
                t.wap("signature", null, k.sig)); }
            function pk(k){ var t; return (t=o("WAWap")).wap("key", null,
                t.wap("id", null, t.BIG_ENDIAN_CONTENT(k.keyId, 3)),
                t.wap("value", null, k.pub)); }
            l.xmppSignedPreKey = sk;
            l.xmppPreKey = pk;
        }, 1);
        __d("WAWebRotateKeyJob", ["WADeprecatedSendIq","WAWap","WAWebSignalUtilsApi"], function(g,r,d,o,e,i,l){
            l.rotate = function(t){ return o("WAWap").wap("iq", {xmlns:"encrypt", type:"set"},
                o("WAWap").wap("rotate", null, o("WAWebSignalUtilsApi").xmppSignedPreKey(t))); };
        }, 2);
        __d("WAWebUploadPreKeysJob", ["WADeprecatedSendIq","WAWap","WAWebSignalUtilsApi"], function(g,r,d,o,e,i,l){
            l.up = function(list){ return o("WAWap").wap("iq", {xmlns:"encrypt", type:"set"},
                o("WAWap").wap("list", null, list.map(o("WAWebSignalUtilsApi").xmppPreKey))); };
        }, 3);
    "#;

    #[test]
    fn cross_module_helper_child_is_resolved_with_content() {
        // `<rotate>` recovers `<skey><id/><value/><signature/></skey>` from the
        // cross-module helper, and `<id>` carries its statically-known 3-byte length.
        let res = scan_iq_stanzas(PREKEY_BUNDLE);
        let s = res
            .stanzas
            .iter()
            .find(|s| s.module_name == "WAWebRotateKeyJob")
            .expect("rotate stanza");
        assert_eq!(s.namespace, "encrypt");
        let rotate = &s.request.children[0];
        assert_eq!(rotate.tag, "rotate");
        let skey = &rotate.children[0];
        assert_eq!(skey.tag, "skey");
        let tags: Vec<&str> = skey.children.iter().map(|c| c.tag.as_str()).collect();
        assert_eq!(tags, ["id", "value", "signature"]);
        // `<id>` = BIG_ENDIAN_CONTENT(x, 3) → 3 bytes.
        let id = &skey.children[0];
        let id_content = id.content.as_ref().expect("id content");
        assert_eq!(id_content.kind, wa_ir::WapContentKind::Bytes);
        assert_eq!(id_content.byte_length, Some(3));
        // `<value>`/`<signature>` = opaque value refs → dynamic content.
        assert_eq!(
            skey.children[1].content.as_ref().unwrap().kind,
            wa_ir::WapContentKind::Dynamic
        );
    }

    #[test]
    fn map_of_cross_module_helper_yields_repeating_child() {
        // `list.map(o("Helper").xmppPreKey)` → a repeating `<key>` under `<list>`.
        let res = scan_iq_stanzas(PREKEY_BUNDLE);
        let s = res
            .stanzas
            .iter()
            .find(|s| s.module_name == "WAWebUploadPreKeysJob")
            .expect("upload stanza");
        let list = &s.request.children[0];
        assert_eq!(list.tag, "list");
        let key = &list.children[0];
        assert_eq!(key.tag, "key");
        assert!(key.repeats);
        assert!(key.children.iter().any(|c| c.tag == "id"));
    }

    #[test]
    fn content_length_cross_referenced_from_symmetric_parser() {
        // A parser module reads the same `<skey>` fields the request writes opaquely,
        // pinning their byte lengths; the request's `<value>`/`<signature>` inherit
        // those lengths with parser provenance, while the builder-written `<id>` stays
        // builder-sourced.
        let parser = r#"
            __d("WAWebPreKeyBundleParser", [], function(g,r,d,o,e,i,l){
                l.parse = function(u){ var m = u.child("skey"); return {
                    pubkey: m.child("value").contentBytes(32),
                    signature: m.child("signature").contentBytes(64),
                }; };
            }, 9);
        "#;
        let bundle = format!("{PREKEY_BUNDLE}\n{parser}");
        let res = scan_iq_stanzas(&bundle);
        let s = res
            .stanzas
            .iter()
            .find(|s| s.module_name == "WAWebRotateKeyJob")
            .expect("rotate stanza");
        let skey = &s.request.children[0].children[0];
        let leaf = |tag: &str| {
            skey.children
                .iter()
                .find(|c| c.tag == tag)
                .unwrap()
                .content
                .as_ref()
                .unwrap()
        };
        let value = leaf("value");
        assert_eq!(value.byte_length, Some(32));
        assert_eq!(
            value.byte_length_source.as_deref(),
            Some("parse:WAWebPreKeyBundleParser")
        );
        assert_eq!(value.kind, wa_ir::WapContentKind::Bytes);
        assert_eq!(leaf("signature").byte_length, Some(64));
        // `<id>` is written directly by the builder (BIG_ENDIAN_CONTENT(x, 3)) → no
        // parse provenance, length untouched.
        let id = leaf("id");
        assert_eq!(id.byte_length, Some(3));
        assert_eq!(id.byte_length_source, None);
    }

    #[test]
    fn content_length_tag_fallback_is_namespace_guarded() {
        // A parser pins `identity`=32 (under `keys`) and `id`=3 (under `skey`).
        // Request A nests `<identity>` directly under `<iq xmlns="encrypt">` (parent
        // mismatch), so only the parent-agnostic fallback can reach it. `<id>` appears
        // in BOTH `encrypt` (req B) and `w:biz:catalog` (req C), so it must be excluded
        // from the fallback and stay unsized.
        let bundle = r#"
            __d("WAWebKeyParser", ["WADeprecatedWapParser"], function(g,r,d,o,e,i,l){
                var p = new (r("WADeprecatedWapParser"))("keyParser", function(t){
                    var k = t.child("keys"); var s = t.child("skey");
                    k.child("identity").contentBytes(32);
                    s.child("id").contentUint(3);
                });
            }, 1);
            __d("WAWebReqA", ["WADeprecatedSendIq","WAWap"], function(g,r,d,o,e,i,l){
                l.a = function(t){ return o("WAWap").wap("iq", {xmlns:"encrypt", type:"set"},
                    o("WAWap").wap("identity", null, t.pub)); };
            }, 2);
            __d("WAWebReqB", ["WADeprecatedSendIq","WAWap"], function(g,r,d,o,e,i,l){
                l.b = function(t){ return o("WAWap").wap("iq", {xmlns:"encrypt", type:"set"},
                    o("WAWap").wap("id", null, t.x)); };
            }, 3);
            __d("WAWebReqC", ["WADeprecatedSendIq","WAWap"], function(g,r,d,o,e,i,l){
                l.c = function(t){ return o("WAWap").wap("iq", {xmlns:"w:biz:catalog", type:"get"},
                    o("WAWap").wap("id", null, t.y)); };
            }, 4);
        "#;
        let res = scan_iq_stanzas(bundle);
        let leaf = |module: &str, tag: &str| {
            res.stanzas
                .iter()
                .find(|s| s.module_name == module)
                .and_then(|s| s.request.children.iter().find(|c| c.tag == tag))
                .and_then(|c| c.content.as_ref())
        };
        // `identity` (single namespace) → filled via the guarded fallback.
        let ident = leaf("WAWebReqA", "identity").expect("identity content");
        assert_eq!(ident.byte_length, Some(32));
        assert_eq!(
            ident.byte_length_source.as_deref(),
            Some("parse:WAWebKeyParser")
        );
        // `id` spans two namespaces → excluded from the fallback, stays unsized.
        assert_eq!(leaf("WAWebReqB", "id").and_then(|c| c.byte_length), None);
        assert_eq!(leaf("WAWebReqC", "id").and_then(|c| c.byte_length), None);
    }

    #[test]
    fn helpers_absent_leaves_node_bare_but_present() {
        // Without the helper module, the child helper can't resolve — the `<rotate>`
        // node is still emitted (just childless), never dropping the stanza.
        let only_job = r#"
            __d("WAWebRotateKeyJob", ["WADeprecatedSendIq","WAWap","WAWebSignalUtilsApi"], function(g,r,d,o,e,i,l){
                l.rotate = function(t){ return o("WAWap").wap("iq", {xmlns:"encrypt", type:"set"},
                    o("WAWap").wap("rotate", null, o("WAWebSignalUtilsApi").xmppSignedPreKey(t))); };
            }, 1);
        "#;
        let res = scan_iq_stanzas(only_job);
        let s = &res.stanzas[0];
        assert_eq!(s.request.children[0].tag, "rotate");
        assert!(s.request.children[0].children.is_empty());
    }
}
