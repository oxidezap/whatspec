//! Cross-module index of smax response parsers (Phase 3).
//!
//! Smax responses live in `WASmaxIn<X>ResponseSuccess` modules (separate from the
//! `WASmaxOut<X>Request` modules the scanner sees). This build pass parses every
//! `WASmaxIn*` module once, extracts each payload mixin's fields first, then each
//! `ResponseSuccess` parser (which may reference those mixins), and exposes a
//! lookup by operation name `X` so the scanner can attach a response to a request.
//!
//! Mirrors [`crate::mixin_index`] in structure (build once before the scan loop,
//! `BTreeMap` for determinism, only the small `WASmaxIn*` slices re-parsed).

use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Program, Statement};
use wa_ir::ParsedResponse;

use crate::response_smax::{analyze_module, parse_fn_body_by_name};
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
    // (Mixins can reference other mixins; we resolve in a couple of widening
    // rounds so a mixin built before its dependency still picks it up.)
    let mut mixins: HashMap<String, ParsedResponse> = HashMap::new();
    let mixin_mods: Vec<(&str, &str)> = defs
        .iter()
        .filter(|m| m.name.starts_with("WASmaxIn") && m.name.ends_with("Mixin"))
        .map(|m| (m.name.as_str(), &source[m.start..m.end]))
        .collect();
    // Two rounds cover the shallow mixin→mixin nesting seen in the bundle.
    for _ in 0..2 {
        for (_name, slice) in &mixin_mods {
            for (fn_name, body) in parse_fn_exports(slice) {
                if mixins.contains_key(&fn_name) {
                    continue;
                }
                if let Some(pr) = analyze_module_body(&body, &fn_name, &mixins)
                    && !pr.fields.is_empty()
                {
                    mixins.insert(fn_name, pr);
                }
            }
        }
    }

    // Pass 2: each `ResponseSuccess` parser, resolving payload mixins from pass 1.
    let mut by_x = BTreeMap::new();
    for m in defs {
        if !(m.name.starts_with("WASmaxIn") && m.name.ends_with("ResponseSuccess")) {
            continue;
        }
        let slice = &source[m.start..m.end];
        // The exported parse fn name (`parse…ResponseSuccess`); take the one that
        // ends in `ResponseSuccess`.
        let Some((fn_name, body)) = parse_fn_exports(slice)
            .into_iter()
            .find(|(n, _)| n.ends_with("ResponseSuccess"))
        else {
            continue;
        };
        let Some(pr) = analyze_module_body(&body, &fn_name, &mixins) else {
            continue;
        };
        if pr.fields.is_empty() {
            continue;
        }
        let x = response_op_name(&m.name);
        by_x.entry(x).or_insert(pr);
    }

    ResponseIndex { by_x }
}

/// `WASmaxIn<X>ResponseSuccess` → `X` (operation name shared with the request).
fn response_op_name(module: &str) -> String {
    module
        .strip_prefix("WASmaxIn")
        .and_then(|s| s.strip_suffix("ResponseSuccess"))
        .unwrap_or(module)
        .to_string()
}

/// All `l.<fn> = …` exported parse functions in a module slice, as
/// `(fn_name, fn_body_source)` so the analyzer can re-parse each body.
fn parse_fn_exports(slice: &str) -> Vec<(String, String)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let exports = collect_export_fn_names(&ret.program);
    exports
        .into_iter()
        .filter(|n| n.starts_with("parse"))
        .filter_map(|n| parse_fn_body_by_name(slice, &n).map(|body| (n, body)))
        .collect()
}

/// Names assigned as `l.<name> = <ident>` (the module's exports).
///
/// The module factory body holds `l.parseXxx = e`; collect every such property
/// name. The shared walker descends into the `__d(name, deps, factory)` body.
fn collect_export_fn_names(program: &Program) -> Vec<String> {
    let mut out = Vec::new();
    crate::response_smax::walk_factory_stmts::<(), _>(&program.body, &mut |s| {
        if let Statement::ExpressionStatement(es) = s
            && let oxc_ast::ast::Expression::AssignmentExpression(a) = &es.expression
            && let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            out.push(prop.to_string());
        }
        None
    });
    out
}

/// Analyze a parse-fn body source into a [`ParsedResponse`].
fn analyze_module_body(
    body: &str,
    fn_name: &str,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<ParsedResponse> {
    analyze_module(body, fn_name, mixins)
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
}
