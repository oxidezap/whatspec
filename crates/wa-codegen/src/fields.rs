//! Response field-tree → Rust struct fields + nested item structs.

use std::collections::HashSet;

use wa_ir::wap;
use wa_ir::{ContentType, ParsedField, ParsedFieldType, WapAttrKind};

use crate::naming::{pascal_case, rust_ident};

/// A field on a generated response/item struct.
#[derive(Debug, Clone)]
pub(crate) struct RustField {
    pub name: String,
    pub rust_type: String,
    #[allow(dead_code)]
    pub is_vec: bool,
}

/// A generated `<Tag>Item` struct collected from repeating children.
#[derive(Debug, Clone)]
pub(crate) struct RustChildStruct {
    pub name: String,
    pub fields: Vec<RustField>,
}

/// A generated enum for a `type=union` response field (see [`crate::union`]).
#[derive(Debug, Clone)]
pub(crate) struct RustEnum {
    pub name: String,
    pub doc: String,
    pub variants: Vec<RustEnumVariant>,
}

/// One alternative of a [`RustEnum`]. Exactly one shape applies: a newtype variant
/// `Name(Type)` when `tuple_type` is set (a tag-discriminated arm wrapping a generated
/// per-variant struct); otherwise a unit variant (`fields` empty) or an inline struct
/// variant carrying `fields`.
#[derive(Debug, Clone)]
pub(crate) struct RustEnumVariant {
    pub name: String,
    pub fields: Vec<RustField>,
    pub tuple_type: Option<String>,
}

/// Emit a `pub enum` definition for a `type=union` response field — unit variants
/// (markers) or struct variants carrying inline leaf fields. Field types reference
/// the per-module imports (`Jid`, etc.), so the enum is emitted alongside the
/// module's shared child structs.
pub(crate) fn emit_enum_def(e: &RustEnum) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("/// {}", e.doc));
    lines.push("#[derive(Debug, Clone)]".to_string());
    lines.push(format!("pub enum {} {{", e.name));
    for v in &e.variants {
        if let Some(ty) = &v.tuple_type {
            lines.push(format!("    {}({}),", v.name, ty));
        } else if v.fields.is_empty() {
            lines.push(format!("    {},", v.name));
        } else {
            lines.push(format!("    {} {{", v.name));
            for f in &v.fields {
                lines.push(format!("        {}: {},", f.name, f.rust_type));
            }
            lines.push("    },".to_string());
        }
    }
    lines.push("}".to_string());
    lines.push(String::new());
    lines
}

/// `f.tag ?? f.name`.
fn tag_or_name(f: &ParsedField) -> &str {
    f.tag.as_deref().unwrap_or(&f.name)
}

/// Whether the range the IR declares for `f` admits a negative value.
///
/// Every integer materialized as `u64`, so a field the parser accepts down to `-10000` had
/// no representation at all. `samplingWeight` in `iq`'s `configs` and
/// `experimentOrSamplingConfigMixinGroup` is declared `intMin: -10000`, and both emit as a
/// tag cascade — each arm decoded inside a closure, an `Err` skipping to the next. A wire
/// value of `-500` therefore failed `parse()`, dropped the `SamplingConfig` arm, and fell
/// off the end of the cascade: the whole union field came back `None`, not just that leaf.
///
/// The width has to follow the declared range, and one predicate answers it for the type,
/// the decoder and a union arm's band alike. Spelling it separately at each is what let a
/// guard and the payload it admits disagree.
pub(crate) fn admits_negative(f: &ParsedField) -> bool {
    wap::method_field_type(&f.method) == ParsedFieldType::Integer
        && f.int_min.is_some_and(|n| n < 0)
}

/// The Rust integer width `f` materializes as.
pub(crate) fn integer_width(f: &ParsedField) -> &'static str {
    if admits_negative(f) { "i64" } else { "u64" }
}

/// The Rust type for a response field, derived from the method's canonical
/// [`wap::method_field_type`] + optionality — one mapping, no per-consumer drift.
pub(crate) fn rust_field_type(field: &ParsedField) -> &'static str {
    // Presence flags carry their type on the field, not the accessor method.
    if field.field_type == ParsedFieldType::Bool {
        return "bool";
    }
    let base = match wap::method_field_type(&field.method) {
        ParsedFieldType::Integer => integer_width(field),
        ParsedFieldType::Bytes => "Vec<u8>",
        // Every JID flavor materializes as one `Jid` today; the flavor lives in the IR.
        t if t.is_jid() => "Jid",
        // String / Enum / (Bool/Union handled elsewhere) materialize as String.
        _ => "String",
    };
    // Optionality has TWO sources. The accessor spelling is one; the IR's own `required`
    // is the other, and it is the only one that sees a smax tail conditional making a
    // field optional without changing its accessor. 108 JID fields in the committed
    // artifact are `attrUserJid` with `required: false`, and deriving from the name alone
    // declared them `Jid` and emitted `ok_or_else("missing …")` — rejecting responses the
    // IR explicitly says may omit them.
    if wap::is_optional_method(&field.method) || !field.required {
        match base {
            "u64" => "Option<u64>",
            "i64" => "Option<i64>",
            "Vec<u8>" => "Option<Vec<u8>>",
            "Jid" => "Option<Jid>",
            _ => "Option<String>",
        }
    } else {
        base
    }
}

pub(crate) fn rust_attr_type(kind: &WapAttrKind) -> &'static str {
    match kind {
        WapAttrKind::Const | WapAttrKind::String | WapAttrKind::Dynamic => "String",
        WapAttrKind::Integer => "u64",
        WapAttrKind::UserJid | WapAttrKind::DeviceJid | WapAttrKind::GroupJid => "Jid",
        WapAttrKind::Optional => "Option<String>",
        _ => "String",
    }
}

pub(crate) fn is_jid_kind(kind: &WapAttrKind) -> bool {
    matches!(
        kind,
        WapAttrKind::UserJid | WapAttrKind::DeviceJid | WapAttrKind::GroupJid
    )
}

pub(crate) fn is_child_field(f: &ParsedField) -> bool {
    wap::is_child_method(&f.method)
}

/// A field the codegen materializes as a top-level attr-style field: an attribute
/// accessor (via [`wap::is_attr_method`]), **any** content leaf (via
/// [`wap::is_content_method`]), or a `hasAttr` presence marker (the latter filtered out
/// by callers before emission).
///
/// The content half is derived, not enumerated. Naming three spellings here was the
/// fourth site of that mistake in this change, and the most misleading: the scanners
/// recovered live `contentUint` fields, the IR carried them, and the reference codegen
/// dropped them on the floor — so the generated Rust came out byte-identical and the
/// unchanged output read as "nothing broke" rather than "the new data is being ignored".
pub(crate) fn is_attr_field(f: &ParsedField) -> bool {
    wap::is_attr_method(&f.method) || wap::is_content_method(&f.method) || f.method == wap::HAS_ATTR
}

/// If `f` is a `child`/`maybeChild` whose body is just a content accessor
/// (`child("x").contentString()`), the content type it carries — so it can be
/// emitted as a single field named after the child tag (`x: String`) instead of
/// a stray `content` attr that collapses across sibling children.
pub(crate) fn child_content_type(f: &ParsedField) -> Option<ContentType> {
    if f.method != "child" && f.method != "maybeChild" {
        return None;
    }
    let kids = children_of(f);
    if kids.is_empty() || !kids.iter().all(is_content_method) {
        return None;
    }
    // Bytes wins a mixed group (the widest reading); otherwise the kids' own decoded
    // type decides. Collapsing everything that was not bytes onto `String` is what made
    // `<registration>`, `<type>` and `<id>` — three `contentUint` siblings — share a
    // single generated `content` field, two of the three silently dropped.
    //
    // Both branches ask the classifier. Using it for integers and an exact `contentBytes`
    // name test for bytes — in the same expression — would have typed a
    // `contentBytesRange` child as `String` and read it with `content_str()`.
    let decodes_to = |c: &ParsedField| wap::method_field_type(&c.method);
    Some(
        if kids.iter().any(|c| decodes_to(c) == ParsedFieldType::Bytes) {
            ContentType::Bytes
        } else if kids
            .iter()
            .all(|c| decodes_to(c) == ParsedFieldType::Integer)
        {
            ContentType::Integer
        } else {
            ContentType::String
        },
    )
}

fn is_content_method(f: &ParsedField) -> bool {
    wap::is_content_method(&f.method)
}

fn children_of(f: &ParsedField) -> &[ParsedField] {
    f.children.as_deref().unwrap_or(&[])
}

fn repeats(f: &ParsedField) -> bool {
    f.repeats == Some(true)
}

/// Hoist `same_node` fields (smax payload mixins nested under a key but read off
/// the PARENT node) so the codegen sees a flat attr/child list. The IR keeps them
/// nested for fidelity; the reference codegen flattens for a simple struct shape.
/// Recurses into real child fields' children (where nested same-node mixins live).
///
/// An *optional* same-node wrapper (`{key: m.success ? m.value : null}` →
/// `required:false`) makes every leaf it contributes optional: when hoisted the
/// wrapper itself disappears, so its absence can only be modeled by weakening the
/// hoisted attr leaves to their `maybe…` (optional) form.
pub(crate) fn flatten_same_node(fields: &[ParsedField]) -> Vec<ParsedField> {
    flatten_same_node_inner(fields, false)
}

fn flatten_same_node_inner(fields: &[ParsedField], force_optional: bool) -> Vec<ParsedField> {
    let mut out = Vec::new();
    for f in fields {
        if f.same_node {
            let child_optional = force_optional || !f.required;
            out.extend(flatten_same_node_inner(
                f.children.as_deref().unwrap_or(&[]),
                child_optional,
            ));
        } else {
            let mut f = f.clone();
            if force_optional {
                weaken_attr_to_optional(&mut f);
            }
            if let Some(kids) = &f.children {
                f.children = Some(flatten_same_node_inner(kids, force_optional));
            }
            out.push(f);
        }
    }
    out
}

/// Weaken an attribute leaf to its optional `maybe…` accessor (so an optional
/// same-node wrapper's children read as `Option<_>`). Content leaves already read
/// leniently (`unwrap_or_default`); child/JID accessors have no `maybe` form here,
/// so they are left unchanged (a rare over-strictness in the reference codegen).
fn weaken_attr_to_optional(f: &mut ParsedField) {
    let weakened = match f.method.as_str() {
        wap::ATTR_STRING => Some(wap::MAYBE_ATTR_STRING),
        wap::ATTR_INT => Some(wap::MAYBE_ATTR_INT),
        wap::ATTR_ENUM => Some(wap::MAYBE_ATTR_ENUM),
        _ => None,
    };
    if let Some(m) = weakened {
        f.method = m.to_string();
        f.required = false;
    }
}

/// Walk the response field tree, collecting top-level struct fields and any
/// `<Prefix><Tag>Item` child structs for repeating children. `prefix` (the owning
/// spec's base name) keeps child struct names unique across a namespace — two specs
/// can have a same-tagged child with incompatible shapes (e.g. `tos` `<notice>`).
pub(crate) fn collect_response_fields(
    fields: &[ParsedField],
    prefix: &str,
) -> (Vec<RustField>, Vec<RustChildStruct>, Vec<RustEnum>) {
    let flattened = &flatten_same_node(fields);
    let mut top_fields: Vec<RustField> = Vec::new();
    let mut child_structs: Vec<RustChildStruct> = Vec::new();
    let mut enums: Vec<RustEnum> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut add_field = |out: &mut Vec<RustField>, f: RustField| {
        if seen.insert(f.name.clone()) {
            out.push(f);
        }
    };

    for f in flattened {
        // `type=union` field → a discriminated enum (when codegen-able); an
        // unsupported union is skipped, exactly as `emit_response_parser` skips it.
        if f.field_type == ParsedFieldType::Union {
            if let Some((field, enum_defs, structs)) = crate::union::collect_union(f, prefix) {
                add_field(&mut top_fields, field);
                enums.extend(enum_defs);
                child_structs.extend(structs);
            }
            continue;
        }
        if is_child_field(f) {
            let kids = children_of(f);
            // `child("x").contentString()` → a single `x: String` field (named by
            // the child tag), not a stray `content` attr that collapses siblings.
            if let Some(ct) = f.content_type.or_else(|| child_content_type(f)) {
                let base = match ct {
                    ContentType::Bytes => "Vec<u8>",
                    ContentType::Integer => "u64",
                    _ => "String",
                };
                let wrapped = if f.method == "maybeChild" {
                    format!("Option<{base}>")
                } else {
                    base.to_string()
                };
                add_field(
                    &mut top_fields,
                    RustField {
                        name: rust_ident(tag_or_name(f)),
                        rust_type: wrapped,
                        is_vec: false,
                    },
                );
                continue;
            }
            if kids.is_empty() {
                continue;
            }

            let attr_children: Vec<&ParsedField> =
                kids.iter().filter(|c| is_attr_field(c)).collect();
            let nested_children: Vec<&ParsedField> =
                kids.iter().filter(|c| is_child_field(c)).collect();

            if repeats(f) {
                let struct_name = format!("{prefix}{}Item", pascal_case(tag_or_name(f)));
                let mut struct_fields: Vec<RustField> = Vec::new();

                for cf in &attr_children {
                    if cf.method == "hasAttr" {
                        continue;
                    }
                    struct_fields.push(RustField {
                        name: rust_ident(&cf.name),
                        rust_type: rust_field_type(cf).to_string(),
                        is_vec: false,
                    });
                }

                // A `type=union` child of this repeated item → an `Option<Enum>` column
                // (prefixed by the Item struct so its enum/variant structs are unique).
                for uf in kids
                    .iter()
                    .filter(|c| c.field_type == ParsedFieldType::Union)
                {
                    if let Some((field, union_enums, union_structs)) =
                        crate::union::collect_union(uf, &struct_name)
                    {
                        struct_fields.push(field);
                        enums.extend(union_enums);
                        child_structs.extend(union_structs);
                    }
                }

                for nf in &nested_children {
                    if repeats(nf) && !children_of(nf).is_empty() {
                        let nested_struct = format!("{prefix}{}Item", pascal_case(tag_or_name(nf)));
                        let mut nested_fields: Vec<RustField> = Vec::new();
                        for ncf in children_of(nf).iter().filter(|c| is_attr_field(c)) {
                            if ncf.method == "hasAttr" {
                                continue;
                            }
                            nested_fields.push(RustField {
                                name: rust_ident(&ncf.name),
                                rust_type: rust_field_type(ncf).to_string(),
                                is_vec: false,
                            });
                        }
                        if !nested_fields.is_empty() {
                            child_structs.push(RustChildStruct {
                                name: nested_struct.clone(),
                                fields: nested_fields,
                            });
                            struct_fields.push(RustField {
                                name: rust_ident(tag_or_name(nf)),
                                rust_type: format!("Vec<{nested_struct}>"),
                                is_vec: true,
                            });
                        }
                    }
                }

                if !struct_fields.is_empty() {
                    child_structs.push(RustChildStruct {
                        name: struct_name.clone(),
                        fields: struct_fields,
                    });
                    add_field(
                        &mut top_fields,
                        RustField {
                            name: rust_ident(tag_or_name(f)),
                            rust_type: format!("Vec<{struct_name}>"),
                            is_vec: true,
                        },
                    );
                }
            } else {
                // Single child → inline its attr fields + recurse.
                for cf in &attr_children {
                    if cf.method == "hasAttr" {
                        continue;
                    }
                    add_field(
                        &mut top_fields,
                        RustField {
                            name: rust_ident(&cf.name),
                            rust_type: rust_field_type(cf).to_string(),
                            is_vec: false,
                        },
                    );
                }
                // Recurse over nested children AND any `type=union` fields the child
                // carries (a union has `method == ""`, so it is neither attr nor child
                // and would otherwise be dropped here — matching what `emit_struct_reads`
                // passes down, which recurses over all kids).
                let nested_owned: Vec<ParsedField> = kids
                    .iter()
                    .filter(|c| is_child_field(c) || c.field_type == ParsedFieldType::Union)
                    .map(|c| (*c).clone())
                    .collect();
                let (nested_top, nested_structs, nested_enums) =
                    collect_response_fields(&nested_owned, prefix);
                for nf in nested_top {
                    add_field(&mut top_fields, nf);
                }
                child_structs.extend(nested_structs);
                enums.extend(nested_enums);
            }
        } else if is_attr_field(f) && f.method != "hasAttr" {
            add_field(
                &mut top_fields,
                RustField {
                    name: rust_ident(&f.name),
                    rust_type: rust_field_type(f).to_string(),
                    is_vec: false,
                },
            );
        }
    }

    (top_fields, child_structs, enums)
}
