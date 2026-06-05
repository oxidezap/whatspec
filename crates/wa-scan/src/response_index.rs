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

use wa_ir::ParsedResponse;

use crate::response_smax::analyze_module_exports;
use wa_transform::ModuleDefinition;

/// Index of smax response parsers, keyed for request→response linkage.
#[derive(Default)]
pub struct ResponseIndex {
    /// Operation name `X` (from `WASmaxIn<X>ResponseSuccess`) → its parsed response.
    by_x: BTreeMap<String, ParsedResponse>,
}

impl ResponseIndex {
    /// Look up the response for operation `x` (derived from a request module name).
    pub(crate) fn get_by_x(&self, x: &str) -> Option<&ParsedResponse> {
        self.by_x.get(x)
    }
}

/// Build the response index over every `WASmaxIn*` module.
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> ResponseIndex {
    // Pass 1: every payload mixin's fields, keyed by its `parse…Mixin` fn name.
    // Mixins can reference other mixins; two widening rounds cover the shallow
    // mixin→mixin nesting seen in the bundle (a mixin built before its dependency
    // still picks it up on the second round).
    let mut mixins: HashMap<String, ParsedResponse> = HashMap::new();
    let mixin_mods: Vec<&str> = unique_modules(defs, source, |name| {
        name.starts_with("WASmaxIn") && name.ends_with("Mixin")
    });
    for _ in 0..2 {
        for slice in &mixin_mods {
            for (fn_name, pr) in analyze_module_exports(slice, &mixins) {
                if fn_name.ends_with("Mixin")
                    && !pr.fields.is_empty()
                    && !mixins.contains_key(&fn_name)
                {
                    mixins.insert(fn_name, pr);
                }
            }
        }
    }

    // Pass 2: each `ResponseSuccess` parser, resolving payload mixins from pass 1.
    let mut by_x = BTreeMap::new();
    let mut seen = HashSet::new();
    for m in defs {
        if !(m.name.starts_with("WASmaxIn") && m.name.ends_with("ResponseSuccess")) {
            continue;
        }
        if !seen.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        let Some(pr) = analyze_module_exports(slice, &mixins)
            .into_iter()
            .find(|(n, pr)| n.ends_with("ResponseSuccess") && !pr.fields.is_empty())
            .map(|(_, pr)| pr)
        else {
            continue;
        };
        by_x.entry(response_op_name(&m.name)).or_insert(pr);
    }

    ResponseIndex { by_x }
}

/// First slice of each distinct module name matching `pred` (shard dedup).
fn unique_modules<'s>(
    defs: &[ModuleDefinition],
    source: &'s str,
    pred: impl Fn(&str) -> bool,
) -> Vec<&'s str> {
    let mut seen = HashSet::new();
    defs.iter()
        .filter(|m| pred(&m.name) && seen.insert(m.name.as_str()))
        .map(|m| &source[m.start..m.end])
        .collect()
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
