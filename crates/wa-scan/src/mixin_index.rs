//! Cross-module mixin resolution (Phase 2).
//!
//! Many newer IQ requests don't build the whole `<iq>` inline. A
//! `WASmaxOut<Domain><Op>Request` module starts from `smax("iq", null, …children)`
//! and composes the stanza by folding fragments from *other* modules via
//! `o("WASmaxOut…Mixin").merge<Name>Mixin(dst, …)`, fused by
//! `WASmaxMixins.mergeStanzas`. The `xmlns` comes from one mixin (e.g.
//! `…BaseReportMixin` → `xmlns:"spam"`) and the `type` from another
//! (`…BaseIQSetRequestMixin` → `type:"set"`), so neither is present in the
//! Request module itself — the per-module scanner discards it.
//!
//! This index, built once over every `WASmaxOut*` module, records what each
//! mixin contributes to the `<iq>` (its `xmlns`/`type`/`to`, plus the mixins it
//! itself folds in transitively). The scanner then unions the contributions of
//! the mixins a Request references to recover `xmlns`/`type`.
//!
//! Conservative by construction: a fragment is recorded only when the mixin's
//! helper actually builds a `smax("iq", …)` (mixins that fold `message`/`call`/…
//! sub-stanzas contribute nothing here), and resolution applies only when the
//! union is unambiguous (exactly one `xmlns`, one `type`).

use std::collections::{BTreeMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentExpression, CallExpression, Expression};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use wa_ir::{IqTarget, IqType, WapAttrKind, WapChildNode};

use crate::alias::{AliasMap, build_alias_map};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::helper_index::HelperIndex;
use crate::module::{iq_type_from_merge_name, require_module_name};
use crate::request::{
    MixinContributions, VarScope, build_var_scope, resolve_child_node, resolve_contribution,
};
use wa_oxc::{arg_expr, callee_method, callee_object};
use wa_transform::ModuleDefinition;

/// What one mixin contributes to the `<iq>` it helps build.
#[derive(Clone, Default, Debug)]
pub(crate) struct MixinIqFragment {
    /// Literal `xmlns:"…"` on the mixin's inner `smax("iq", …)`, if any.
    pub xmlns: Option<String>,
    /// `type`: inline `type:"get"/"set"`, else inferred from the Get/Set token in
    /// the merge-fn name. `None` if neither.
    pub iq_type: Option<IqType>,
    /// `to:"g.us"` → Group; otherwise (S_WHATSAPP_NET / absent) → Server.
    pub target: Option<IqTarget>,
    /// Other `WASmaxOut…` mixins this mixin folds in (by module name), in source
    /// order with duplicates removed — for transitive resolution (e.g. a Hack
    /// mixin whose `type` comes from a Base mixin it calls).
    pub merged_callees: Vec<String>,
    /// The children the mixin's inner `smax("iq", …, children)` fragment adds to
    /// the `<iq>` (e.g. `BaseReportMixin` → `spam_list{spam_flow}`). Merged by tag
    /// into a Request's children so cross-module attrs/children aren't lost.
    pub children: Vec<WapChildNode>,
}

/// Global index: mixin module name → its `<iq>` contribution.
///
/// Built by [`build_pass`] and passed to [`crate::scan_module_source`]; an empty
/// index ([`MixinIndex::default`]) makes the scan purely local.
#[derive(Default)]
pub struct MixinIndex {
    by_module: BTreeMap<String, MixinIqFragment>,
}

impl MixinIndex {
    pub(crate) fn get(&self, module: &str) -> Option<&MixinIqFragment> {
        self.by_module.get(module)
    }
}

/// Build the index over every `WASmaxOut*` module (mixins + requests). Cheap:
/// only those small slices are re-parsed, not the whole bundle.
///
/// Two stages: first resolve each mixin's *contribution* (the stanza tree it folds
/// into a destination) in dependency order, so a sub-stanza mixin's attrs are known
/// before any mixin that nests it (Phase 3). Then extract each `<iq>` fragment with
/// those contributions available, so a fragment's children (e.g. newsletter
/// `messages`) carry the cross-module attrs the nested mixins add.
pub(crate) fn build_pass(
    defs: &[ModuleDefinition],
    source: &str,
    helpers: &HelperIndex,
) -> MixinIndex {
    // First-occurrence slice per WASmaxOut* module (the same module may appear in
    // several bundle shards; the first definition is authoritative).
    let mut slices: BTreeMap<&str, &str> = BTreeMap::new();
    for m in defs {
        if m.name.starts_with("WASmaxOut") {
            slices.entry(&m.name).or_insert(&source[m.start..m.end]);
        }
    }

    // Dependency graph: which WASmaxOut* mixins each module references via `o("…")`.
    let deps: BTreeMap<&str, Vec<String>> = slices
        .iter()
        .map(|(name, slice)| (*name, collect_mixin_deps(slice, name)))
        .collect();

    // Resolve contributions in post-order (dependencies first), memoized.
    let mut contributions: MixinContributions = BTreeMap::new();
    let mut visiting: HashSet<String> = HashSet::new();
    for name in slices.keys() {
        resolve_contribution_rec(
            name,
            &slices,
            &deps,
            &mut contributions,
            &mut visiting,
            helpers,
        );
    }

    // Extract each module's `<iq>` fragment with the contributions available, so the
    // fragment's children pick up the nested mixins' attrs.
    let mut by_module = BTreeMap::new();
    for (name, slice) in &slices {
        if let Some(frag) = extract_fragment(slice, &contributions, helpers) {
            by_module.insert(name.to_string(), frag);
        }
    }
    MixinIndex { by_module }
}

/// WASmaxOut* module names a slice references via `o("…")` (excluding itself) —
/// the candidate dependency edges for contribution ordering. Over-inclusive is
/// safe: an extra edge only forces earlier resolution; cycles are bounded by the
/// `visiting` set in [`resolve_contribution_rec`].
fn collect_mixin_deps(slice: &str, self_name: &str) -> Vec<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let mut v = DepCollector {
        self_name,
        deps: Vec::new(),
    };
    v.visit_program(&ret.program);
    v.deps
}

struct DepCollector<'s> {
    self_name: &'s str,
    deps: Vec<String>,
}

impl<'a> Visit<'a> for DepCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // `o("WASmaxOut…")` — a require call: callee is a bare identifier (not a
        // member like `x.smax("messages")`, whose string arg is a tag, not a module).
        if matches!(&call.callee, Expression::Identifier(_))
            && let Some(arg) = wa_oxc::first_string_arg(call)
            && arg.starts_with("WASmaxOut")
            && arg != self.self_name
            && !self.deps.iter().any(|d| d == arg)
        {
            self.deps.push(arg.to_string());
        }
        walk::walk_call_expression(self, call);
    }
}

/// Resolve `name`'s contribution after all its dependencies', memoizing into
/// `contributions`. The `visiting` set bounds cycles (a mixin in-progress is
/// treated as contributing nothing until it completes).
fn resolve_contribution_rec(
    name: &str,
    slices: &BTreeMap<&str, &str>,
    deps: &BTreeMap<&str, Vec<String>>,
    contributions: &mut MixinContributions,
    visiting: &mut HashSet<String>,
    helpers: &HelperIndex,
) {
    if contributions.contains_key(name) || visiting.contains(name) {
        return;
    }
    visiting.insert(name.to_string());
    if let Some(ds) = deps.get(name) {
        for d in ds {
            resolve_contribution_rec(d, slices, deps, contributions, visiting, helpers);
        }
    }
    visiting.remove(name);
    if let Some(slice) = slices.get(name) {
        let contrib = resolve_contribution(slice, contributions, helpers);
        contributions.insert(name.to_string(), contrib);
    }
}

/// Parse a `WASmaxOut*` module slice and extract its `<iq>` fragment, if it
/// builds one. Returns `None` for modules that don't construct a `smax("iq", …)`.
/// `contributions` lets the fragment's children pick up cross-module sub-stanza
/// attrs (Phase 3); pass an empty map for purely structural extraction.
fn extract_fragment(
    slice: &str,
    contributions: &MixinContributions,
    helpers: &HelperIndex,
) -> Option<MixinIqFragment> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let aliases = build_alias_map(&ret.program);
    let scope = build_var_scope(&ret.program);
    let mut v = FragmentVisitor {
        source: slice,
        aliases: &aliases,
        scope: &scope,
        contributions,
        helpers,
        merge_fn: None,
        frag: MixinIqFragment::default(),
        found_iq: false,
    };
    v.visit_program(&ret.program);
    // A router-only MixinGroup (e.g. `mergeBaseGetGroupOrServerMixinGroup`: pure
    // `if (cond) return …BaseGetGroupMixin; …`) builds no direct `smax("iq", …)`, but
    // the branch mixins it folds DO carry `xmlns`/`type`. Keep it in the index when it
    // has callees so `resolve`'s BFS can bridge request → router → branch → base.
    if !v.found_iq && v.frag.merged_callees.is_empty() {
        return None;
    }
    // type: an inline `type:` on the iq wins; else infer from the export name.
    if v.frag.iq_type.is_none()
        && let Some(name) = &v.merge_fn
    {
        v.frag.iq_type = iq_type_from_merge_name(name);
    }
    Some(v.frag)
}

struct FragmentVisitor<'s> {
    source: &'s str,
    aliases: &'s AliasMap,
    scope: &'s VarScope,
    /// Resolved contributions of the mixins this one nests (Phase 3) — lets the iq's
    /// children pick up cross-module sub-stanza attrs.
    contributions: &'s MixinContributions,
    /// Cross-module wap-returning-helper index — so a fragment child built via a
    /// helper (`o("Module").fn(...)`) expands instead of dropping.
    helpers: &'s HelperIndex,
    /// The exported `l.merge<Name>Mixin = …` name, captured from the assignment.
    merge_fn: Option<String>,
    frag: MixinIqFragment,
    found_iq: bool,
}

impl<'a> Visit<'a> for FragmentVisitor<'_> {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        // `l.merge<Name>Mixin = s` / `…MixinGroup = e` → the export name.
        if self.merge_fn.is_none()
            && let Some(m) = assign.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
            && prop.starts_with("merge")
            && prop.contains("Mixin")
        {
            self.merge_fn = Some(prop.to_string());
        }
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // The first `smax("iq", {attrs}, …)` this module builds: read xmlns/type/to.
        if !self.found_iq
            && let Some(wap) = parse_wap_call(call, self.aliases)
            && wap.tag == "iq"
        {
            self.found_iq = true;
            if let Some(attrs_node) = wap.attrs_node {
                let attrs = extract_attrs_from_obj(attrs_node, self.source, self.aliases);
                if let Some(x) = attrs
                    .iter()
                    .find(|a| a.name == "xmlns" && a.kind == WapAttrKind::Const)
                    .and_then(|a| a.value.as_deref())
                {
                    self.frag.xmlns = Some(x.to_string());
                }
                match attrs
                    .iter()
                    .find(|a| a.name == "type" && a.kind == WapAttrKind::Const)
                    .and_then(|a| a.value.as_deref())
                {
                    Some("get") => self.frag.iq_type = Some(IqType::Get),
                    Some("set") => self.frag.iq_type = Some(IqType::Set),
                    _ => {}
                }
                let to_group = attrs.iter().any(|a| {
                    a.name == "to"
                        && a.kind == WapAttrKind::Const
                        && a.value.as_deref() == Some("g.us")
                });
                if to_group {
                    self.frag.target = Some(IqTarget::Group);
                } else if attrs.iter().any(|a| a.name == "to") {
                    self.frag.target = Some(IqTarget::Server);
                }
            }
            // The fragment's own children (e.g. `spam_list{spam_flow}`) — merged by
            // tag into a Request's children so cross-module attrs/children survive.
            for child_arg in wap.child_args {
                if let Some(ce) = arg_expr(child_arg) {
                    self.frag.children.extend(resolve_child_node(
                        ce,
                        self.source,
                        self.scope,
                        self.source,
                        self.aliases,
                        Some(self.contributions),
                        self.helpers,
                        0,
                        // `ce` is at a real module offset — anchors the function context
                        // for scoped-initializer (`owner_fn`) checks.
                        Some(ce.span().start as usize),
                    ));
                }
            }
        }

        // Mixins this module folds in: `o("WASmaxOut…").merge…(…)`. Collected for
        // transitive resolution (e.g. Hack→Base). Dedup, source order preserved.
        if let Some(method) = callee_method(call)
            && method.starts_with("merge")
            && method.contains("Mixin")
            && let Some(name) = callee_object(call).and_then(require_module_name)
            && name.starts_with("WASmaxOut")
            && !self.frag.merged_callees.contains(&name)
        {
            self.frag.merged_callees.push(name);
        }

        walk::walk_call_expression(self, call);
    }
}

/// Resolve `xmlns`/`type`/`target` for a Request by unioning the iq fragments of
/// the mixins it references (`mixin_modules`), following `merged_callees`
/// transitively. Returns `(xmlns, iq_type, target)`, each `Some` only when the
/// union is unambiguous (exactly one distinct value); a conflict yields `None`
/// for that field so the caller's guard discards the stanza rather than guess.
pub(crate) fn resolve(
    index: &MixinIndex,
    mixin_modules: &[String],
) -> (Option<String>, Option<IqType>, Option<IqTarget>) {
    // Transitive closure over merged_callees (BFS; visited set bounds cycles).
    let mut visited = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = mixin_modules.iter().cloned().collect();
    let mut xmlns: Option<String> = None;
    let mut xmlns_conflict = false;
    let mut iq_type: Option<IqType> = None;
    let mut type_conflict = false;
    let mut target: Option<IqTarget> = None;

    while let Some(name) = queue.pop_front() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(frag) = index.get(&name) else {
            continue;
        };
        if let Some(x) = &frag.xmlns {
            match &xmlns {
                None => xmlns = Some(x.clone()),
                Some(prev) if prev != x => xmlns_conflict = true,
                _ => {}
            }
        }
        if let Some(t) = frag.iq_type {
            match iq_type {
                None => iq_type = Some(t),
                Some(prev) if prev != t => type_conflict = true,
                _ => {}
            }
        }
        // First Group wins for target; Server is the default elsewhere.
        if target != Some(IqTarget::Group)
            && let Some(tg) = frag.target
        {
            target = Some(tg);
        }
        for c in &frag.merged_callees {
            if !visited.contains(c) {
                queue.push_back(c.clone());
            }
        }
    }

    (
        if xmlns_conflict { None } else { xmlns },
        if type_conflict { None } else { iq_type },
        target,
    )
}

/// The transitive union of the `<iq>` children every referenced mixin contributes
/// (following `merged_callees`), pre-merged by tag. The scanner merges this into a
/// Request's children to recover cross-module attrs/children (e.g. `spam_flow`).
pub(crate) fn resolve_fragment_children(
    index: &MixinIndex,
    mixin_modules: &[String],
) -> Vec<WapChildNode> {
    let mut visited = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = mixin_modules.iter().cloned().collect();
    let mut out: Vec<WapChildNode> = Vec::new();
    while let Some(name) = queue.pop_front() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(frag) = index.get(&name) else {
            continue;
        };
        merge_children(&mut out, &frag.children);
        for c in &frag.merged_callees {
            if !visited.contains(c) {
                queue.push_back(c.clone());
            }
        }
    }
    out
}

/// Count the tag/attr entries [`merge_children`] would ADD to `into` — fields the
/// cross-module fragment carries that are absent locally. Mirrors the same tag
/// matching so the diagnostic reports exactly what the merge recovers (0 when the
/// fragment only re-states fields already built locally). Used only for the
/// `diagnostics.iq.crossModule` manifest counters; it does not mutate anything.
pub(crate) fn count_recovered_fields(into: &[WapChildNode], from: &[WapChildNode]) -> usize {
    let mut n = 0;
    for fc in from {
        if let Some(existing) = into.iter().find(|c| c.tag == fc.tag) {
            n += fc
                .attrs
                .iter()
                .filter(|fa| !existing.attrs.iter().any(|a| a.name == fa.name))
                .count();
            n += count_recovered_fields(&existing.children, &fc.children);
            // Variant groups absent locally are recovered wholesale.
            for g in &fc.variant_groups {
                if !existing.variant_groups.contains(g) {
                    n += variant_group_field_count(g);
                }
            }
        } else {
            // Whole subtree is new: its tag + its attrs + every descendant tag/attr.
            n += 1 + subtree_field_count(fc);
        }
    }
    n
}

/// Tags + attrs contained in a subtree, excluding the node's own tag (the caller
/// counts that). The node's attrs plus its variant-group attrs plus, recursively,
/// each descendant's tag+attrs.
fn subtree_field_count(node: &WapChildNode) -> usize {
    let mut n = node.attrs.len();
    for g in &node.variant_groups {
        n += variant_group_field_count(g);
    }
    for c in &node.children {
        n += 1 + subtree_field_count(c);
    }
    n
}

/// Attrs (and nested subtree fields) across all variants of a group.
fn variant_group_field_count(g: &wa_ir::WapVariantGroup) -> usize {
    g.variants
        .iter()
        .map(|v| {
            v.attrs.len()
                + v.children
                    .iter()
                    .map(|c| 1 + subtree_field_count(c))
                    .sum::<usize>()
        })
        .sum()
}

/// Merge `from` children into `into` by tag (`mergeStanzas` semantics): a matching
/// tag has its attrs unioned (existing wins), variant groups unioned, and children
/// merged recursively; a non-matching child is appended. Locally-extracted fields
/// take precedence, so the merge only ever ADDS cross-module attrs/children.
pub(crate) fn merge_children(into: &mut Vec<WapChildNode>, from: &[WapChildNode]) {
    for fc in from {
        if let Some(existing) = into.iter_mut().find(|c| c.tag == fc.tag) {
            for fa in &fc.attrs {
                if !existing.attrs.iter().any(|a| a.name == fa.name) {
                    existing.attrs.push(fa.clone());
                }
            }
            // A fragment that marks the child repeated promotes it (the local build
            // may have seen a single template).
            existing.repeats = existing.repeats || fc.repeats;
            // Union variant groups (a node can carry several disjunctions); dedup so
            // a re-merge of the same fragment doesn't duplicate a group.
            for g in &fc.variant_groups {
                if !existing.variant_groups.contains(g) {
                    existing.variant_groups.push(g.clone());
                }
            }
            merge_children(&mut existing.children, &fc.children);
        } else {
            into.push(fc.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::WapAttrDef;

    fn attr(name: &str) -> WapAttrDef {
        WapAttrDef {
            name: name.to_string(),
            kind: WapAttrKind::Const,
            value: None,
            required: false,
            enum_ref: None,
        }
    }

    fn node(tag: &str, attrs: &[&str], children: Vec<WapChildNode>) -> WapChildNode {
        WapChildNode {
            tag: tag.to_string(),
            attrs: attrs.iter().map(|a| attr(a)).collect(),
            children,
            content: None,
            repeats: false,
            variant_groups: Vec::new(),
        }
    }

    fn frag(xmlns: Option<&str>, ty: Option<IqType>, callees: &[&str]) -> MixinIqFragment {
        MixinIqFragment {
            xmlns: xmlns.map(String::from),
            iq_type: ty,
            target: None,
            merged_callees: callees.iter().map(|s| s.to_string()).collect(),
            children: Vec::new(),
        }
    }

    fn index(entries: &[(&str, MixinIqFragment)]) -> MixinIndex {
        let mut by_module = BTreeMap::new();
        for (k, v) in entries {
            by_module.insert(k.to_string(), v.clone());
        }
        MixinIndex { by_module }
    }

    #[test]
    fn unions_xmlns_and_type_from_two_mixins() {
        // spam case: one mixin gives xmlns, another gives type.
        let idx = index(&[
            ("Xmlns", frag(Some("spam"), None, &[])),
            ("Type", frag(None, Some(IqType::Set), &[])),
        ]);
        let (x, t, _) = resolve(&idx, &["Xmlns".into(), "Type".into()]);
        assert_eq!(x.as_deref(), Some("spam"));
        assert_eq!(t, Some(IqType::Set));
    }

    #[test]
    fn resolves_type_transitively_via_merged_callees() {
        // Hack mixin has only `to`, but folds in Base which carries type:get.
        let idx = index(&[
            ("Hack", frag(Some("w:biz"), None, &["Base"])),
            ("Base", frag(None, Some(IqType::Get), &[])),
        ]);
        let (x, t, _) = resolve(&idx, &["Hack".into()]);
        assert_eq!(x.as_deref(), Some("w:biz"));
        assert_eq!(t, Some(IqType::Get), "type recovered transitively");
    }

    #[test]
    fn conflicting_xmlns_yields_none() {
        let idx = index(&[
            ("A", frag(Some("spam"), Some(IqType::Set), &[])),
            ("B", frag(Some("blocklist"), None, &[])),
        ]);
        let (x, t, _) = resolve(&idx, &["A".into(), "B".into()]);
        assert_eq!(x, None, "ambiguous xmlns → discard, never guess");
        assert_eq!(t, Some(IqType::Set));
    }

    #[test]
    fn cycle_terminates() {
        let idx = index(&[
            ("A", frag(Some("x"), None, &["B"])),
            ("B", frag(None, Some(IqType::Get), &["A"])),
        ]);
        let (x, t, _) = resolve(&idx, &["A".into()]);
        assert_eq!(x.as_deref(), Some("x"));
        assert_eq!(t, Some(IqType::Get));
    }

    #[test]
    fn extract_fragment_reads_xmlns_and_type() {
        let m = r#"__d("WASmaxOutSpamBaseIQSetRequestMixin",["WASmaxJsx","WAWap"],function(g,r,d,o,e,i,l){
            function e(){ return o("WASmaxJsx").smax("iq",{id:o("WAWap").generateId(),type:"set"}); }
            function s(t){ return o("WASmaxMixins").mergeStanzas(t, e()); }
            l.mergeBaseIQSetRequestMixin = s;
        }, 1);"#;
        let f = extract_fragment(m, &MixinContributions::new(), &HelperIndex::default())
            .expect("fragment");
        assert_eq!(f.iq_type, Some(IqType::Set));
        assert_eq!(f.xmlns, None);
    }

    #[test]
    fn extract_fragment_infers_type_from_name() {
        // No inline type, but the export name says Get.
        let m = r#"__d("WASmaxOutFooBaseIQGetRequestMixin",["WASmaxJsx","WAWap"],function(g,r,d,o,e,i,l){
            function e(){ return o("WASmaxJsx").smax("iq",{xmlns:"foo"}); }
            function s(t){ return o("WASmaxMixins").mergeStanzas(t, e()); }
            l.mergeBaseIQGetRequestMixin = s;
        }, 1);"#;
        let f = extract_fragment(m, &MixinContributions::new(), &HelperIndex::default())
            .expect("fragment");
        assert_eq!(f.xmlns.as_deref(), Some("foo"));
        assert_eq!(f.iq_type, Some(IqType::Get), "type from merge name");
    }

    #[test]
    fn non_iq_mixin_yields_no_fragment() {
        // Only folds a `message` sub-stanza — contributes nothing to the iq.
        let m = r#"__d("WASmaxOutSpamMessageMixin",["WASmaxJsx"],function(g,r,d,o,e,i,l){
            function e(x){ return o("WASmaxJsx").smax("message",{from:x}); }
            function s(t,n){ return o("WASmaxMixins").mergeStanzas(t, e(n)); }
            l.mergeMessageMixin = s;
        }, 1);"#;
        assert!(extract_fragment(m, &MixinContributions::new(), &HelperIndex::default()).is_none());
    }

    #[test]
    fn extract_fragment_captures_iq_children() {
        // The fragment's `<iq>` carries a `spam_list{spam_flow}` child — it must be
        // captured so the merge can fold it into a Request's tree (the Phase-2 win).
        let m = r#"__d("WASmaxOutSpamBaseReportMixin",["WASmaxJsx","WAWap","WASmaxMixins"],function(g,r,d,o,e,i,l){
            function e(t){ return o("WASmaxJsx").smax("iq",{xmlns:"spam"}, o("WASmaxJsx").smax("spam_list",{spam_flow:o("WAWap").CUSTOM_STRING(t.flow)})); }
            function s(t,n){ return o("WASmaxMixins").mergeStanzas(t, e(n)); }
            l.mergeBaseReportMixin = s;
        }, 1);"#;
        let f = extract_fragment(m, &MixinContributions::new(), &HelperIndex::default())
            .expect("fragment");
        assert_eq!(f.xmlns.as_deref(), Some("spam"));
        assert_eq!(f.children.len(), 1, "the iq's spam_list child is captured");
        assert_eq!(f.children[0].tag, "spam_list");
        assert!(
            f.children[0].attrs.iter().any(|a| a.name == "spam_flow"),
            "spam_flow attr captured on the fragment child"
        );
    }

    #[test]
    fn count_recovered_new_tag_counts_whole_subtree() {
        // local has nothing; the fragment adds spam_list{jid, spam_flow} > msg{from}.
        // Recovered = spam_list(tag) + jid + spam_flow + msg(tag) + from = 5.
        let local: Vec<WapChildNode> = vec![];
        let from = vec![node(
            "spam_list",
            &["jid", "spam_flow"],
            vec![node("msg", &["from"], vec![])],
        )];
        assert_eq!(count_recovered_fields(&local, &from), 5);
    }

    #[test]
    fn count_recovered_matching_tag_only_new_attrs() {
        // spam_list exists locally with `jid`; fragment adds spam_flow + subject.
        let local = vec![node("spam_list", &["jid"], vec![])];
        let from = vec![node("spam_list", &["jid", "spam_flow", "subject"], vec![])];
        assert_eq!(count_recovered_fields(&local, &from), 2);
    }

    #[test]
    fn count_recovered_zero_when_fragment_is_subset() {
        let local = vec![node("spam_list", &["jid", "spam_flow"], vec![])];
        let from = vec![node("spam_list", &["jid"], vec![])];
        assert_eq!(
            count_recovered_fields(&local, &from),
            0,
            "a fragment that only re-states local fields recovers nothing"
        );
    }

    #[test]
    fn merge_children_unions_attrs_existing_wins() {
        // spam_list{jid} + fragment spam_list{jid, spam_flow} → spam_list{jid, spam_flow}.
        let mut into = vec![node("spam_list", &["jid"], vec![])];
        merge_children(
            &mut into,
            &[node("spam_list", &["jid", "spam_flow"], vec![])],
        );
        assert_eq!(into.len(), 1, "same tag merges, not duplicates");
        let names: Vec<_> = into[0].attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["jid", "spam_flow"]);
    }

    #[test]
    fn merge_children_appends_non_matching_tag() {
        let mut into = vec![node("a", &[], vec![])];
        merge_children(&mut into, &[node("b", &["x"], vec![])]);
        let tags: Vec<_> = into.iter().map(|c| c.tag.as_str()).collect();
        assert_eq!(tags, vec!["a", "b"]);
    }

    #[test]
    fn merge_children_promotes_repeats_and_recurses() {
        let mut into = vec![node("links", &[], vec![node("link", &["a"], vec![])])];
        let mut frag_link = node("link", &["b"], vec![]);
        frag_link.repeats = true;
        merge_children(&mut into, &[node("links", &[], vec![frag_link])]);
        let link = &into[0].children[0];
        assert!(
            link.repeats,
            "a fragment that marks the child repeated promotes it"
        );
        let names: Vec<_> = link.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"], "nested attrs unioned recursively");
    }

    #[test]
    fn resolve_fragment_children_unions_transitively() {
        // Report folds in Base; spam_list's attrs come from BOTH (Report: spam_flow
        // directly, Base: subject via merged_callees).
        let mut base = frag(Some("spam"), Some(IqType::Set), &[]);
        base.children = vec![node("spam_list", &["subject"], vec![])];
        let mut report = frag(None, None, &["Base"]);
        report.children = vec![node("spam_list", &["spam_flow"], vec![])];
        let idx = index(&[("Base", base), ("Report", report)]);
        let kids = resolve_fragment_children(&idx, &["Report".into()]);
        assert_eq!(kids.len(), 1);
        let names: Vec<_> = kids[0].attrs.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"spam_flow"), "direct child attr");
        assert!(
            names.contains(&"subject"),
            "transitive child attr via callee"
        );
    }
}
