//! Native tooling: scan extracted WA Web modules into [`wa_ir`] types (AST-only,
//! via oxc). Port of `scan-iq-stanzas-ast.ts`.
//!
//! Pipeline: [`wa_transform::extract_module_definitions`] splits a bundle into
//! `__d()` modules; we keep only IQ-relevant ones (by dependency) and run
//! [`scan_module_source`] on each, producing [`wa_ir::IqScanResult`].
#![cfg(not(target_arch = "wasm32"))]

mod alias;
mod attrs;
mod mixin_index;
mod module;
mod request;
mod response;
mod response_index;
mod response_smax;

pub use mixin_index::MixinIndex;
pub use module::{DropReason, scan_module_outcome, scan_module_source};

use wa_ir::{IqIr, IqScanResult, IqType, Unparseable};
use wa_transform::ModuleDefinition;

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
    // Build the cross-module mixin index once (Phase 2), before scanning. It
    // records what each `WASmaxOut*` mixin contributes to the `<iq>` it folds,
    // so Requests that defer xmlns/type to mixins can be resolved.
    let mixin_index = mixin_index::build_pass(module_defs, source);

    // Build the cross-module response index once (Phase 3). It parses the smax
    // `WASmaxIn*ResponseSuccess` modules so a Request can attach its typed
    // response (the smax response lives in a separate module).
    let response_index = response_index::build_pass(module_defs, source);

    let mut stanzas = Vec::new();
    let mut unparseable = Vec::new();
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
        match scan_module_outcome(slice, &mixin_index, &response_index) {
            Ok(found) => stanzas.extend(found),
            Err(reason) => unparseable.push(Unparseable {
                module_name: m.name.clone(),
                reason: reason.as_str().to_string(),
            }),
        }
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

    IqScanResult {
        stanzas,
        unparseable,
    }
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
    let scan = scan_iq_stanzas_from_modules(source, module_defs);
    IqIr {
        wa_version: wa_version.to_string(),
        stanzas: scan.stanzas,
        unparseable: scan.unparseable,
    }
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
}
