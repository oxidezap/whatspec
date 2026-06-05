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

use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentExpression, CallExpression};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{IqTarget, IqType, WapAttrKind};

use crate::alias::{AliasMap, build_alias_map};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::module::iq_type_from_merge_name;
use wa_oxc::{callee_method, callee_object};
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
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> MixinIndex {
    let mut by_module = BTreeMap::new();
    for m in defs {
        if !m.name.starts_with("WASmaxOut") {
            continue;
        }
        let slice = &source[m.start..m.end];
        if let Some(frag) = extract_fragment(slice) {
            by_module.insert(m.name.clone(), frag);
        }
    }
    MixinIndex { by_module }
}

/// Parse a `WASmaxOut*` module slice and extract its `<iq>` fragment, if it
/// builds one. Returns `None` for modules that don't construct a `smax("iq", …)`.
fn extract_fragment(slice: &str) -> Option<MixinIqFragment> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let aliases = build_alias_map(&ret.program);
    let mut v = FragmentVisitor {
        source: slice,
        aliases: &aliases,
        merge_fn: None,
        frag: MixinIqFragment::default(),
        found_iq: false,
    };
    v.visit_program(&ret.program);
    if !v.found_iq {
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

use crate::module::require_module_name;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(xmlns: Option<&str>, ty: Option<IqType>, callees: &[&str]) -> MixinIqFragment {
        MixinIqFragment {
            xmlns: xmlns.map(String::from),
            iq_type: ty,
            target: None,
            merged_callees: callees.iter().map(|s| s.to_string()).collect(),
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
        let f = extract_fragment(m).expect("fragment");
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
        let f = extract_fragment(m).expect("fragment");
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
        assert!(extract_fragment(m).is_none());
    }
}
