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

fn qualified(module: &str, func: &str) -> String {
    format!("{module}.{func}")
}

/// Build the index over modules that construct `wap()` nodes. Cheap: only the slices
/// that actually contain a `.wap(` are re-parsed (~100 of the bundle's modules), and
/// `<iq>`-builder returns are filtered out (those are whole requests, never a child).
/// First definition per module name wins (the same module may appear in several
/// bundle shards).
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> HelperIndex {
    let mut index = HelperIndex::default();
    let mut seen = HashSet::new();
    for m in defs {
        if !seen.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        if !slice.contains(".wap(") {
            continue;
        }
        // Pass the index built so far so a helper that calls an already-indexed
        // helper (from an earlier module) still resolves.
        for (func, tree) in exported_wap_helpers(slice, &index) {
            index
                .by_qualified_name
                .entry(qualified(&m.name, &func))
                .or_insert(tree);
        }
    }
    index
}
