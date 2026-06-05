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

/// `f.tag ?? f.name`.
fn tag_or_name(f: &ParsedField) -> &str {
    f.tag.as_deref().unwrap_or(&f.name)
}

/// The Rust type for a response field, derived from the method's canonical
/// [`wap::method_field_type`] + optionality — one mapping, no per-consumer drift.
pub(crate) fn rust_field_type(field: &ParsedField) -> &'static str {
    // Presence flags carry their type on the field, not the accessor method.
    if field.field_type == ParsedFieldType::Bool {
        return "bool";
    }
    let base = match wap::method_field_type(&field.method) {
        ParsedFieldType::Integer => "u64",
        ParsedFieldType::Bytes => "Vec<u8>",
        ParsedFieldType::DeviceJid
        | ParsedFieldType::GroupJid
        | ParsedFieldType::JidTyped
        | ParsedFieldType::Jid => "Jid",
        // String / Enum / (Bool/Union handled elsewhere) materialize as String.
        _ => "String",
    };
    if wap::is_optional_method(&field.method) {
        match base {
            "u64" => "Option<u64>",
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
/// accessor (via [`wap::is_attr_method`]), a `contentBytes` leaf, or a `hasAttr`
/// presence marker (the latter filtered out by callers before emission).
pub(crate) fn is_attr_field(f: &ParsedField) -> bool {
    wap::is_attr_method(&f.method)
        || f.method == wap::CONTENT_BYTES
        || f.method == wap::CONTENT_STRING
        || f.method == wap::CONTENT_INT
        || f.method == wap::HAS_ATTR
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
    Some(if kids.iter().any(|c| c.method == wap::CONTENT_BYTES) {
        ContentType::Bytes
    } else {
        ContentType::String
    })
}

fn is_content_method(f: &ParsedField) -> bool {
    f.method == wap::CONTENT_STRING || f.method == wap::CONTENT_BYTES
}

fn children_of(f: &ParsedField) -> &[ParsedField] {
    f.children.as_deref().unwrap_or(&[])
}

fn repeats(f: &ParsedField) -> bool {
    f.repeats == Some(true)
}

/// Walk the response field tree, collecting top-level struct fields and any
/// `<Tag>Item` child structs for repeating children.
pub(crate) fn collect_response_fields(
    fields: &[ParsedField],
) -> (Vec<RustField>, Vec<RustChildStruct>) {
    let mut top_fields: Vec<RustField> = Vec::new();
    let mut child_structs: Vec<RustChildStruct> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut add_field = |out: &mut Vec<RustField>, f: RustField| {
        if seen.insert(f.name.clone()) {
            out.push(f);
        }
    };

    for f in fields {
        if is_child_field(f) {
            let kids = children_of(f);
            // `child("x").contentString()` → a single `x: String` field (named by
            // the child tag), not a stray `content` attr that collapses siblings.
            if let Some(ct) = f.content_type.or_else(|| child_content_type(f)) {
                let base = if ct == ContentType::Bytes {
                    "Vec<u8>"
                } else {
                    "String"
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
                let struct_name = format!("{}Item", pascal_case(tag_or_name(f)));
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

                for nf in &nested_children {
                    if repeats(nf) && !children_of(nf).is_empty() {
                        let nested_struct = format!("{}Item", pascal_case(tag_or_name(nf)));
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
                let nested_owned: Vec<ParsedField> =
                    nested_children.iter().map(|c| (*c).clone()).collect();
                let (nested_top, nested_structs) = collect_response_fields(&nested_owned);
                for nf in nested_top {
                    add_field(&mut top_fields, nf);
                }
                child_structs.extend(nested_structs);
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

    (top_fields, child_structs)
}
