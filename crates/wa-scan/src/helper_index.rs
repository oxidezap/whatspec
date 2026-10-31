//! Cross-module wap-returning-helper index.
//!
//! Some request builders don't build a child inline but call a helper that returns
//! the subtree — `o("WAWebSignalUtilsApi").xmppSignedPreKey(t)` builds
//! `<skey><id/><value/><signature/></skey>`, and `.map(o("…").xmppPreKey)` builds a
//! repeating `<key>`. Reading only inline `wap()`/`smax()` children (as the request
//! resolver did) silently drops those subtrees, leaving a bare `<rotate>`/`<list>`.
//!
//! This index resolves every module's exported wap-returning helpers once, keyed by
//! `"Module.fn"`, so [`crate::request::resolve_child_node`] can inline them
//! cross-module — mirroring the mixin index for legacy `wap()` helpers.

use std::collections::{BTreeMap, HashSet};

use wa_ir::WapChildNode;
use wa_transform::ModuleDefinition;

use crate::request::exported_wap_helpers;

/// `"Module.fn"` → the wap subtree that helper returns.
///
/// Built by [`build_pass`] and passed to the request resolver; an empty index
/// ([`HelperIndex::default`]) makes resolution purely local (no cross-module
/// helper expansion), matching the pre-index behavior.
#[derive(Default)]
pub struct HelperIndex {
    by_qualified_name: BTreeMap<String, Vec<WapChildNode>>,
}

impl HelperIndex {
    /// The subtree helper `module.func` returns, if indexed.
    pub(crate) fn get(&self, module: &str, func: &str) -> Option<&Vec<WapChildNode>> {
        self.by_qualified_name.get(&qualified(module, func))
    }
}

#[cfg(test)]
impl HelperIndex {
    /// Seed one entry, so a test can exercise the cross-module branch of
    /// [`crate::request::resolve_child_node`] without building a whole bundle.
    pub(crate) fn with(module: &str, func: &str, tree: Vec<WapChildNode>) -> Self {
        let mut index = HelperIndex::default();
        index
            .by_qualified_name
            .insert(qualified(module, func), tree);
        index
    }
}

fn qualified(module: &str, func: &str) -> String {
    format!("{module}.{func}")
}

/// Build the index over modules that construct stanza nodes. Cheap: only the slices
/// that actually contain a `.wap(`/`.smax(` builder are re-parsed (~100 of the
/// bundle's modules), and `<iq>`-builder returns are filtered out (those are whole
/// requests, never a child).
///
/// Runs **two passes** so the result is independent of module declaration order: the
/// first resolves each module's helpers against the index built so far (single-level
/// / earlier-declared helpers); the second re-resolves them all with that full index
/// available, so a helper that calls another module's helper resolves even when the
/// callee is declared later. First definition per module name wins (the same module
/// may appear in several bundle shards).
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> HelperIndex {
    let first = resolve_all(defs, source, &HelperIndex::default());
    resolve_all(defs, source, &first)
}

/// Resolve every module's exported wap helpers, expanding cross-module helper
/// references via `context` (a previous pass's index).
fn resolve_all(defs: &[ModuleDefinition], source: &str, context: &HelperIndex) -> HelperIndex {
    let mut index = HelperIndex::default();
    let mut seen = HashSet::new();
    for m in defs {
        if !seen.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        if !slice.contains(".wap(") && !slice.contains(".smax(") {
            continue;
        }
        for (func, tree) in exported_wap_helpers(slice, context) {
            index
                .by_qualified_name
                .entry(qualified(&m.name, &func))
                .or_insert(tree);
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_helper_does_not_resolve_a_sibling_functions_local() {
        let source = r#"
            __d("Helpers", ["WASmaxJsx"], function(g,r,d,o,e,i,l) {
                function sibling() {
                    var t = o("WASmaxJsx").smax("foreign", null);
                    return t;
                }
                function empty() {
                    var t = null;
                    return t;
                }
                function child() {
                    var t = o("WASmaxJsx").smax("child", null);
                    return t;
                }
                l.empty = empty;
                l.child = child;
            });
        "#;
        let defs = wa_transform::extract_module_definitions(source);
        let index = build_pass(&defs, source);
        assert!(index.get("Helpers", "empty").is_none());
        let child = index.get("Helpers", "child").unwrap();
        assert_eq!(child.len(), 1);
        assert_eq!(child[0].tag, "child");
    }
    #[test]
    fn reparsed_helper_body_does_not_inherit_nested_functions_initializer() {
        let source = r#"
            __d("NestedHelpers", ["WASmaxJsx"], function(g,r,d,o,e,i,l) {
                function child() {
                    function nested() {
                        var t = o("WASmaxJsx").smax("nested", null);
                        return t;
                    }
                    var t = o("WASmaxJsx").smax("outer", null);
                    return t;
                }
                l.child = child;
            });
        "#;
        let definitions = wa_transform::extract_module_definitions(source);
        let index = build_pass(&definitions, source);
        let child = index.get("NestedHelpers", "child").unwrap();
        assert_eq!(child.len(), 1);
        assert_eq!(child[0].tag, "outer");
    }
}
