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
/// so we drop rather than coerce).
fn variants_of(def: wa_ir::InternalEnumDef) -> Option<Vec<AttrEnumVariant>> {
    def.variants
        .into_iter()
        .map(|v| match v.value {
            Scalar::Str(s) => Some(AttrEnumVariant {
                name: v.name,
                value: s,
            }),
            _ => None,
        })
        .collect()
}
