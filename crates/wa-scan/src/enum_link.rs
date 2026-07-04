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
        let module_slice = &self.module_slice;
        let resolved = self
            .cache
            .entry((module.clone(), ename.clone()))
            .or_insert_with(|| {
                module_slice.get(module.as_str()).and_then(|slice| {
                    wa_enums::resolve_named_enum(slice, &module, &ename).and_then(variants_of)
                })
            });
        // Some → fill the variants; None → drop the (unresolvable) link.
        attr.enum_ref = resolved.clone().map(|variants| AttrEnumRef {
            name: ename,
            module,
            variants,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{WapAttrKind, WapChildNode};

    fn pending(module: &str, name: &str) -> WapAttrDef {
        WapAttrDef {
            name: "type".into(),
            kind: WapAttrKind::String,
            value: None,
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
            ..Default::default()
        }];
        r.resolve_tree(&mut tree);
        let inner = &tree[0].children[0].attrs[0];
        assert!(
            inner
                .enum_ref
                .as_ref()
                .is_some_and(|e| !e.variants.is_empty())
        );
    }
}
