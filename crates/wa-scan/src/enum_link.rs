//! Cross-module resolution of attribute → wire-enum links.
//!
//! `attrs.rs` marks an attribute whose builder writes `o("Mod").EnumName.VARIANT` with
//! a *pending* [`AttrEnumRef`] (name + module, empty variants). The enum is defined in
//! another module, so it's resolved here after the scan: look the module up, read the
//! enum's variants via [`wa_enums::resolve_named_enum`] (which handles both the
//! `$InternalEnum` form and a plain object-literal enum), and fill them in. An enum
//! that doesn't resolve to a valid string-variant set drops the link entirely — never
//! a half-filled guess.
//!
//! Shared by the IQ scan and the generalized-stanza scan via [`EnumResolver`], so both
//! resolve links against one module index and cache.

use std::collections::HashMap;

use wa_ir::{AttrEnumRef, AttrEnumVariant, Scalar, WapAttrDef, WapChildNode};
use wa_transform::ModuleDefinition;

/// Resolves pending attribute enum links against the bundle's module slices, caching
/// each `(module, enum)` lookup so a shared enum resolves once.
pub(crate) struct EnumResolver<'a> {
    module_slice: HashMap<&'a str, &'a str>,
    cache: HashMap<(String, String), Option<Vec<AttrEnumVariant>>>,
}

impl<'a> EnumResolver<'a> {
    pub(crate) fn new(defs: &'a [ModuleDefinition], source: &'a str) -> Self {
        // First slice per module name (shards repeat definitions; any resolves the enum).
        let mut module_slice: HashMap<&str, &str> = HashMap::new();
        for m in defs {
            module_slice
                .entry(m.name.as_str())
                .or_insert(&source[m.start..m.end]);
        }
        Self {
            module_slice,
            cache: HashMap::new(),
        }
    }

    /// Fill in (or drop) a single attribute's pending enum link.
    fn resolve_attr(&mut self, attr: &mut WapAttrDef) {
        let (module, ename) = match &attr.enum_ref {
            Some(er) if er.variants.is_empty() => (er.module.clone(), er.name.clone()),
            _ => return, // no link, or already resolved
        };
        // FORM B carries a guard value in `value` that must be a member of the enum;
        // FORM A leaves it `None`. Either way it's transient scan state, so clear it.
        let guard = attr.value.take();
        let module_slice = &self.module_slice;
        let resolved = self
            .cache
            .entry((module.clone(), ename.clone()))
            .or_insert_with(|| {
                module_slice.get(module.as_str()).and_then(|slice| {
                    wa_enums::resolve_named_enum(slice, &module, &ename).and_then(variants_of)
                })
            });
        // Keep the link when the enum resolves AND — for a FORM B literal guard — the
        // guard value is one of its variants; otherwise drop it (never a guessed link).
        attr.enum_ref = match resolved.clone() {
            Some(variants)
                if guard
                    .as_ref()
                    .is_none_or(|gv| variants.iter().any(|v| &v.value == gv)) =>
            {
                Some(AttrEnumRef {
                    name: ename,
                    module,
                    variants,
                })
            }
            _ => None,
        };
    }

    /// Resolve every attribute directly on these nodes and throughout their subtrees.
    pub(crate) fn resolve_tree(&mut self, children: &mut [WapChildNode]) {
        for node in children {
            self.resolve_attrs(&mut node.attrs);
            self.resolve_tree(&mut node.children);
            for g in &mut node.variant_groups {
                for v in &mut g.variants {
                    self.resolve_attrs(&mut v.attrs);
                    self.resolve_tree(&mut v.children);
                }
            }
        }
    }

    /// Fill in (or drop) the pending enum links on a response field tree.
    ///
    /// Same contract as the request side: a link whose enum resolves to a string-variant
    /// set is kept, anything else is dropped rather than half-filled. The legacy scanner
    /// records the reference without variants because it reads one module at a time; this
    /// runs once the whole bundle index is available.
    /// Returns the constraints it had to drop, keyed `site\x01module.ENUM@attr`, for
    /// `dropsByReason` — an enum WA composes at runtime (`babelHelpers.extends({}, base,
    /// {error: "error"})`, as the privacy settings do) has no literal value set to
    /// recover, and that is worth reporting rather than leaving the field looking
    /// unconstrained.
    ///
    /// `site` identifies the parser the loss belongs to, so two parsers losing the same
    /// enum on the same attribute count as two — the smax counter learned this and this
    /// pass repeated the site-less key. It must stay stable across the mirrored
    /// `response.fields` / `response.variants` traversal of one parser, which is how the
    /// same loss seen twice still counts once.
    pub(crate) fn resolve_fields(
        &mut self,
        site: &str,
        fields: &mut [wa_ir::ParsedField],
        dropped: &mut std::collections::BTreeSet<String>,
    ) {
        self.resolve_fields_at(site, "", fields, dropped)
    }

    /// [`resolve_fields`], carrying the traversal `path` so two losses of the same table
    /// on the same attribute under different children count as two.
    ///
    /// [`resolve_fields`]: EnumResolver::resolve_fields
    fn resolve_fields_at(
        &mut self,
        site: &str,
        path: &str,
        fields: &mut [wa_ir::ParsedField],
        dropped: &mut std::collections::BTreeSet<String>,
    ) {
        for f in fields {
            // Taken, not read: the pending reference is consumed here whether or not it
            // resolves, so a second traversal of the same tree cannot count the same loss
            // twice and nothing is left half-promoted.
            if let Some(pending) = f.pending_enum_ref.take() {
                let attr = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
                // Both halves of the pending state are losses when they don't land: a
                // link whose module export won't resolve, and a table that was never a
                // resolvable reference at all. Counting only the first left the second
                // looking like an enum with no constraint.
                let lost = match pending {
                    wa_ir::PendingEnum::Link(er) => {
                        f.enum_ref = self.lookup(&er.module, &er.name);
                        f.enum_ref
                            .is_none()
                            .then(|| format!("{}.{}", er.module, er.name))
                    }
                    wa_ir::PendingEnum::Unresolvable => Some("<unresolvable table>".to_string()),
                };
                if let Some(what) = lost {
                    // The node PATH is part of the identity: one parser reading `state`
                    // off both `<current>` and `<previous>` loses two constraints, and
                    // `site + table + attr` collapsed them into one.
                    dropped.insert(format!("{site}\u{1}{path}/{what}@{attr}"));
                }
            }
            let here = format!("{path}/{}", f.tag.as_deref().unwrap_or(&f.name));
            if let Some(children) = &mut f.children {
                self.resolve_fields_at(site, &here, children, dropped);
            }
            for uv in f.union_variants.iter_mut().flatten() {
                self.resolve_fields_at(site, &here, &mut uv.fields, dropped);
            }
        }
    }

    /// The resolved variants of `module::name`, memoized. `None` when the module is
    /// absent, the export is not an enum, or a value is not a string.
    fn lookup(&mut self, module: &str, name: &str) -> Option<AttrEnumRef> {
        let module_slice = &self.module_slice;
        let variants = self
            .cache
            .entry((module.to_string(), name.to_string()))
            .or_insert_with(|| {
                module_slice.get(module).and_then(|slice| {
                    wa_enums::resolve_named_enum(slice, module, name).and_then(variants_of)
                })
            })
            .clone()?;
        Some(AttrEnumRef {
            name: name.to_string(),
            module: module.to_string(),
            variants,
        })
    }

    /// Resolve a flat list of attributes (a stanza root's own attrs).
    pub(crate) fn resolve_attrs(&mut self, attrs: &mut [WapAttrDef]) {
        for a in attrs {
            self.resolve_attr(a);
        }
    }
}

/// The string-valued variants of a resolved enum; `None` if any value isn't a string
/// (every stanza-attr enum is a wire-token enum — a non-string one isn't one of these,
/// so we drop rather than coerce) or if the result is empty. Returning `None` on empty
/// keeps the empty-`variants` "pending" sentinel unambiguous: a resolved link always
/// has ≥1 variant.
fn variants_of(def: wa_ir::InternalEnumDef) -> Option<Vec<AttrEnumVariant>> {
    let variants: Vec<AttrEnumVariant> = def
        .variants
        .into_iter()
        .map(|v| match v.value {
            Scalar::Str(s) => Some(AttrEnumVariant {
                name: v.name,
                value: s,
            }),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!variants.is_empty()).then_some(variants)
}

/// Cross-module resolution of the pending enum links a legacy parser leaves on a
/// response shape — the one public entry point for it.
///
/// A parser records `o("Mod").ENUM` without variants because it reads a single module;
/// only a caller holding the whole bundle can finish the job. Every domain that runs
/// [`crate::parse_module_wap_parsers`] needs this, and the traversal it needs (the
/// shape's own fields *and* each variant's, under one site key) is written here once
/// instead of at each call site — the IQ scan had it, incoming and notif did not, and
/// their artifacts shipped links that resolved to nothing.
pub struct ResponseEnumLinker<'a> {
    inner: EnumResolver<'a>,
    /// Enum-link losses keyed `site\x01module.ENUM@attr`; see
    /// [`EnumResolver::resolve_fields`].
    dropped: std::collections::BTreeSet<String>,
    /// Everything else the legacy scanner could not resolve, keyed the same way so two
    /// occurrences in one parser count twice and the same one seen twice counts once.
    other: std::collections::BTreeSet<String>,
}

impl<'a> ResponseEnumLinker<'a> {
    pub fn new(defs: &'a [ModuleDefinition], source: &'a str) -> Self {
        Self {
            inner: EnumResolver::new(defs, source),
            dropped: Default::default(),
            other: Default::default(),
        }
    }

    /// Resolve every pending link in `shape`, attributing losses to `site`.
    pub fn resolve(&mut self, site: &str, shape: &mut wa_ir::iq::ParsedResponse) {
        self.inner
            .resolve_fields(site, &mut shape.fields, &mut self.dropped);
        for v in &mut shape.variants {
            self.inner
                .resolve_fields(site, &mut v.fields, &mut self.dropped);
        }
        // The legacy scanner parks its other unresolved constraints (a byte pin, a
        // length band) on the shape because it has no diagnostics channel of its own.
        // This is the one pass every domain runs, so it is where they get collected.
        for d in shape.pending_drops.drain(..) {
            self.other.insert(format!("{site}\u{1}{d}"));
        }
    }

    /// The enum links seen but not resolvable, for `dropsByReason`.
    pub fn into_drops(self) -> std::collections::BTreeSet<String> {
        self.dropped
    }

    /// Every loss this pass collected, grouped by `dropsByReason` key: the enum links
    /// under [`crate::response_smax::ENUM_DROP`], plus whatever the legacy scanner
    /// parked on the shapes, each already de-duplicated per site.
    pub fn into_drop_counts(self) -> std::collections::BTreeMap<String, usize> {
        let mut out: std::collections::BTreeMap<String, usize> = Default::default();
        if !self.dropped.is_empty() {
            out.insert(
                crate::response_smax::ENUM_DROP.to_string(),
                self.dropped.len(),
            );
        }
        for key in self.other {
            // `site\x01reason@detail` → the reason is what a reader groups by.
            let reason = key
                .split_once('\u{1}')
                .map_or(key.as_str(), |(_, r)| r)
                .split('@')
                .next()
                .unwrap_or("")
                .to_string();
            *out.entry(reason).or_default() += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{WapAttrKind, WapChildNode};

    fn pending(module: &str, name: &str) -> WapAttrDef {
        pending_guard(module, name, None)
    }

    /// A pending link with an optional FORM B guard value (rides in `value`).
    fn pending_guard(module: &str, name: &str, guard: Option<&str>) -> WapAttrDef {
        WapAttrDef {
            name: "type".into(),
            kind: WapAttrKind::String,
            value: guard.map(str::to_string),
            required: true,
            enum_ref: Some(AttrEnumRef {
                name: name.into(),
                module: module.into(),
                variants: Vec::new(),
            }),
        }
    }

    fn resolve(bundle: &str, attrs: &mut [WapAttrDef]) {
        let defs = wa_transform::extract_module_definitions(bundle);
        let mut r = EnumResolver::new(&defs, bundle);
        r.resolve_attrs(attrs);
    }

    #[test]
    fn form_b_guard_value_membership_gates_the_link() {
        // SessionScope = {default, status, pq}.
        let bundle = r#"__d("M",["$InternalEnum"],(function(g,n,d,o,e,i,l){
            i.SessionScope=n("$InternalEnum")({DEFAULT:"default",STATUS:"status",PQ:"pq"});
        }),1);"#;
        // Guard value "status" IS a variant → link kept, and `value` is cleared.
        let mut ok = [pending_guard("M", "SessionScope", Some("status"))];
        resolve(bundle, &mut ok);
        assert!(ok[0].enum_ref.is_some(), "member guard keeps the link");
        assert_eq!(ok[0].value, None, "transient guard value is cleared");
        // Guard value "false" is NOT a variant (the `enc.state` case) → link dropped.
        let mut bad = [pending_guard("M", "SessionScope", Some("false"))];
        resolve(bundle, &mut bad);
        assert!(bad[0].enum_ref.is_none(), "non-member guard drops the link");
        assert_eq!(bad[0].value, None);
        // No guard (FORM A / structural FORM B) → link kept unconditionally.
        let mut structural = [pending_guard("M", "SessionScope", None)];
        resolve(bundle, &mut structural);
        assert!(structural[0].enum_ref.is_some());
    }

    #[test]
    fn resolvable_object_literal_enum_fills_variants() {
        let bundle = r#"__d("M",[],(function(g,r,d,o,e,i,l){
            var s={PN:"pn",LID:"lid"}; i.USYNC_ADDRESSING_MODE=s;
        }),1);"#;
        let mut attrs = [pending("M", "USYNC_ADDRESSING_MODE")];
        resolve(bundle, &mut attrs);
        let er = attrs[0].enum_ref.as_ref().expect("resolved");
        let vals: Vec<&str> = er.variants.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(vals, ["pn", "lid"]);
    }

    #[test]
    fn internal_enum_also_resolves() {
        let bundle = r#"__d("M",["$InternalEnum"],(function(g,r,d,n,e,i,l){
            i.SessionScope=n("$InternalEnum")({DEFAULT:"default",STATUS:"status"});
        }),1);"#;
        let mut attrs = [pending("M", "SessionScope")];
        resolve(bundle, &mut attrs);
        let er = attrs[0].enum_ref.as_ref().expect("resolved");
        assert_eq!(er.variants.len(), 2);
    }

    #[test]
    fn unresolvable_module_drops_the_link() {
        // The referenced module isn't in the bundle → link dropped, not left pending.
        let mut attrs = [pending("Missing", "Foo")];
        resolve("__d(\"Other\",[],(function(){}),1);", &mut attrs);
        assert!(attrs[0].enum_ref.is_none());
    }

    #[test]
    fn non_string_enum_drops_the_link() {
        // An int enum isn't a wire-token enum → dropped rather than coerced.
        let bundle = r#"__d("M",[],(function(g,r,d,o,e,i,l){
            var s={A:0,B:1}; i.Foo=s;
        }),1);"#;
        let mut attrs = [pending("M", "Foo")];
        resolve(bundle, &mut attrs);
        assert!(attrs[0].enum_ref.is_none());
    }

    #[test]
    fn resolve_tree_reaches_nested_and_variant_group_attrs() {
        let bundle = r#"__d("M",[],(function(g,r,d,o,e,i,l){
            var s={PN:"pn",LID:"lid"}; i.USYNC_ADDRESSING_MODE=s;
        }),1);"#;
        let defs = wa_transform::extract_module_definitions(bundle);
        let mut r = EnumResolver::new(&defs, bundle);
        let mut tree = vec![WapChildNode {
            tag: "outer".into(),
            children: vec![WapChildNode {
                tag: "inner".into(),
                attrs: vec![pending("M", "USYNC_ADDRESSING_MODE")],
                ..Default::default()
            }],
            variant_groups: vec![wa_ir::WapVariantGroup {
                optional: false,
                variants: vec![wa_ir::WapVariant {
                    attrs: vec![pending("M", "USYNC_ADDRESSING_MODE")],
                    children: Vec::new(),
                }],
            }],
            ..Default::default()
        }];
        r.resolve_tree(&mut tree);
        let resolved = |a: &WapAttrDef| a.enum_ref.as_ref().is_some_and(|e| !e.variants.is_empty());
        // Both a nested child attr and a variant-group attr get resolved.
        assert!(resolved(&tree[0].children[0].attrs[0]));
        assert!(resolved(&tree[0].variant_groups[0].variants[0].attrs[0]));
    }
}
