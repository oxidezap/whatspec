//! Nested response unions (smax `…MixinGroup` disjunctions) → Rust enums.
//!
//! A `type=union` response field carries `union_variants`: the alternatives the smax
//! disjunction parser tries in first-success order. The reference codegen would
//! otherwise drop these fields entirely; here we model the two cleanly-recoverable
//! shapes as Rust enums so a consumer can read the union value. Anything else
//! ([`classify_union`] returns `None`) is skipped — `collect_response_fields` and
//! `emit_response_parser` both gate on the same classification, so an unsupported
//! union simply leaves no struct field (the rest of the response stays typed) rather
//! than producing a parser that won't compile.
//!
//! Recognized shapes (structural, not name-matched, so they survive WA version
//! churn — a renamed variant or a new content literal flows through unchanged):
//!
//! * **Content** — variants are discriminated by the text content of one child
//!   (`<member_add_mode>admin_add</…>`), reached via the field's `source_path` (or a
//!   tag shared by every variant). Content-pinned variants become unit enum arms; an
//!   optional trailing variant with no content pin is the fallback that captures the
//!   raw content (and any leaf fields it reads). The child is read optionally, so an
//!   absent or unrecognized value yields `None`.
//! * **Same-node value** — variants carry attribute leaves read off the SAME node,
//!   told apart by which variant's required attrs are all present (first-success).
//!   The separability check rejects a union whose earlier arm would shadow a later
//!   one.

use std::collections::BTreeSet;

use wa_ir::{AssertionKind, ParsedField, ParsedFieldType, ResponseAssertion, UnionVariant, wap};

use crate::fields::{RustEnum, RustEnumVariant, RustField, is_attr_field, rust_field_type};
use crate::naming::{pascal_case, rust_ident, rust_lit};

/// The codegen-able shape of a `type=union` field.
pub(crate) enum UnionShape {
    /// Enum chosen by the text content of a descended child; `descend` is the
    /// wrapper-tag chain to that child. `fallback` (if any) captures everything that
    /// matches no `arm`.
    Content {
        descend: Vec<String>,
        arms: Vec<ContentArm>,
        fallback: Option<ValueArm>,
    },
    /// Struct-variant enum read off the SAME node, chosen by first-success over the
    /// variants' required attrs.
    SameNode { arms: Vec<ValueArm> },
}

/// A content-pinned arm: `content` selects unit variant `variant`.
pub(crate) struct ContentArm {
    pub variant: String,
    pub content: String,
}

/// A variant carrying leaf fields (a same-node arm, or a content union's fallback).
pub(crate) struct ValueArm {
    pub variant: String,
    pub fields: Vec<ParsedField>,
}

/// The enum type name for a union field — deterministic from the field name and the
/// owning spec/struct `prefix`, so the field type (collect), the enum definition
/// pass, and the parser (emit) all derive the same identifier.
pub(crate) fn enum_name(f: &ParsedField, prefix: &str) -> String {
    format!("{prefix}{}", pascal_case(&f.name))
}

fn tag_assert(a: &[ResponseAssertion]) -> Option<&str> {
    a.iter()
        .find(|x| x.kind == AssertionKind::Tag)
        .and_then(|x| x.name.as_deref())
}

fn content_assert(a: &[ResponseAssertion]) -> Option<&str> {
    a.iter()
        .find(|x| x.kind == AssertionKind::Content)
        .and_then(|x| x.value.as_deref())
}

/// Classify a `type=union` field into a [`UnionShape`], or `None` when the union is
/// not one of the recoverable shapes (so callers skip it consistently).
pub(crate) fn classify_union(f: &ParsedField) -> Option<UnionShape> {
    if f.field_type != ParsedFieldType::Union {
        return None;
    }
    let variants = f.union_variants.as_deref()?;
    if variants.len() < 2 {
        return None;
    }
    classify_content(f, variants).or_else(|| classify_same_node(f, variants))
}

/// Content: variants pinned to a child's text content. The descend chain is the
/// field's `source_path`, or a tag shared by every variant. At most one variant may
/// omit the content pin — the fallback (which may read leaf fields off the child).
fn classify_content(f: &ParsedField, variants: &[UnionVariant]) -> Option<UnionShape> {
    let mut arms = Vec::new();
    let mut fallback: Option<ValueArm> = None;
    let mut contents = BTreeSet::new();
    for v in variants {
        match content_assert(&v.assertions) {
            Some(c) => {
                if !v.fields.is_empty() {
                    return None; // a content-pinned arm is a pure marker
                }
                if !contents.insert(c.to_string()) {
                    return None; // duplicate discriminator
                }
                arms.push(ContentArm {
                    variant: v.name.clone(),
                    content: c.to_string(),
                });
            }
            None => {
                // The lone fallback: anything the content pins didn't match. Its
                // fields are read off the descended child, so they must be leaves.
                if fallback.is_some() || !v.fields.iter().all(is_simple_leaf) {
                    return None;
                }
                fallback = Some(ValueArm {
                    variant: v.name.clone(),
                    fields: v.fields.clone(),
                });
            }
        }
    }
    if arms.is_empty() {
        return None; // no content discriminator → not a content union
    }
    let descend = content_descend(f, variants)?;
    Some(UnionShape::Content {
        descend,
        arms,
        fallback,
    })
}

/// The wrapper-tag chain to the content-bearing child: the field's `source_path`, or
/// (absent that) a tag asserted by EVERY variant.
fn content_descend(f: &ParsedField, variants: &[UnionVariant]) -> Option<Vec<String>> {
    if let Some(sp) = f.source_path.as_ref().filter(|s| !s.is_empty()) {
        return Some(sp.clone());
    }
    let tag = tag_assert(&variants[0].assertions)?;
    if variants
        .iter()
        .all(|v| tag_assert(&v.assertions) == Some(tag))
    {
        Some(vec![tag.to_string()])
    } else {
        None
    }
}

/// Same-node value: every variant reads attr leaves off the same node (no descent,
/// no tag, no content pin), separable by required-attr presence.
fn classify_same_node(f: &ParsedField, variants: &[UnionVariant]) -> Option<UnionShape> {
    if f.source_path.as_ref().is_some_and(|s| !s.is_empty()) {
        return None; // a descent isn't a same-node read
    }
    for v in variants {
        if tag_assert(&v.assertions).is_some() || content_assert(&v.assertions).is_some() {
            return None;
        }
        if v.fields.is_empty() || !v.fields.iter().all(is_simple_leaf) {
            return None;
        }
    }
    // First-success is unambiguous only if no earlier variant's required-attr set is
    // a subset of a later one's: a subset would always match first and shadow the
    // later arm. (An empty required set can therefore appear only on the LAST arm,
    // making it the catch-all fallback.)
    let reqs: Vec<BTreeSet<String>> = variants.iter().map(required_attrs).collect();
    for i in 0..reqs.len() {
        for j in (i + 1)..reqs.len() {
            if reqs[i].is_subset(&reqs[j]) {
                return None;
            }
        }
    }
    let arms = variants
        .iter()
        .map(|v| ValueArm {
            variant: v.name.clone(),
            fields: v.fields.clone(),
        })
        .collect();
    Some(UnionShape::SameNode { arms })
}

/// A leaf an enum struct-variant can carry: an attribute or content accessor (not a
/// presence flag), with no nested children and not itself a union.
fn is_simple_leaf(f: &ParsedField) -> bool {
    f.field_type != ParsedFieldType::Union
        && f.children.as_ref().is_none_or(|c| c.is_empty())
        && is_attr_field(f)
        && f.method != wap::HAS_ATTR
}

/// The variant's fail-on-absent attrs (required, non-`maybe` accessors) — the
/// presence set that discriminates it from its siblings.
fn required_attrs(v: &UnionVariant) -> BTreeSet<String> {
    v.fields
        .iter()
        .filter(|f| f.required && f.method.starts_with("attr"))
        .map(|f| f.wire_name.clone().unwrap_or_else(|| f.name.clone()))
        .collect()
}

/// Build the [`RustEnumVariant`] list for a shape (used by [`collect_union`]).
fn enum_variants(shape: &UnionShape) -> Vec<RustEnumVariant> {
    let value_variant = |variant: &str, fields: &[ParsedField]| RustEnumVariant {
        name: pascal_case(variant),
        fields: fields
            .iter()
            .map(|cf| RustField {
                name: rust_ident(&cf.name),
                rust_type: rust_field_type(cf).to_string(),
                is_vec: false,
            })
            .collect(),
    };
    match shape {
        UnionShape::Content { arms, fallback, .. } => {
            let mut out: Vec<RustEnumVariant> = arms
                .iter()
                .map(|a| RustEnumVariant {
                    name: pascal_case(&a.variant),
                    fields: Vec::new(),
                })
                .collect();
            if let Some(fb) = fallback {
                out.push(value_variant(&fb.variant, &fb.fields));
            }
            out
        }
        UnionShape::SameNode { arms } => arms
            .iter()
            .map(|a| value_variant(&a.variant, &a.fields))
            .collect(),
    }
}

/// The struct field (typed `Option<Enum>`) and the enum definition for a union
/// field, or `None` when the union isn't codegen-able. `Option` (never bare) keeps
/// the parser resilient: an unrecognized variant decodes to `None`, not a hard error.
pub(crate) fn collect_union(f: &ParsedField, prefix: &str) -> Option<(RustField, RustEnum)> {
    let shape = classify_union(f)?;
    let name = enum_name(f, prefix);
    let field = RustField {
        name: rust_ident(&f.name),
        rust_type: format!("Option<{name}>"),
        is_vec: false,
    };
    let enum_def = RustEnum {
        name,
        doc: format!("Discriminated union for response field `{}`.", f.name),
        variants: enum_variants(&shape),
    };
    Some((field, enum_def))
}

/// Emit the `let <field> = …;` reads that decode a union off `node_var`, plus the
/// struct-init line (`<field>,`). `None` when the union isn't codegen-able — the
/// caller skips it (matching [`collect_union`]).
pub(crate) fn emit_union_read(
    f: &ParsedField,
    node_var: &str,
    prefix: &str,
    indent: &str,
) -> Option<(Vec<String>, String)> {
    let shape = classify_union(f)?;
    let name = enum_name(f, prefix);
    let field = rust_ident(&f.name);
    let mut lines = Vec::new();
    match shape {
        UnionShape::Content {
            descend,
            arms,
            fallback,
        } => emit_content(
            &name,
            &field,
            node_var,
            &descend,
            &arms,
            fallback.as_ref(),
            indent,
            &mut lines,
        ),
        UnionShape::SameNode { arms } => {
            emit_same_node(&name, &field, node_var, &arms, indent, &mut lines)
        }
    }
    Some((lines, format!("{indent}    {field},")))
}

/// Emit a content-discriminated union read: descend (optionally) to the content node,
/// match its text against the arms, fall back if present (else unknown → `None`).
#[allow(clippy::too_many_arguments)]
fn emit_content(
    enum_name: &str,
    field: &str,
    node_var: &str,
    descend: &[String],
    arms: &[ContentArm],
    fallback: Option<&ValueArm>,
    indent: &str,
    lines: &mut Vec<String>,
) {
    let node = descend_opt_expr(node_var, descend);
    lines.push(format!("{indent}let {field} = {node}.and_then(|n| {{"));
    lines.push(format!(
        "{indent}    match n.content_str().unwrap_or_default() {{"
    ));
    for a in arms {
        lines.push(format!(
            "{indent}        {} => Some({enum_name}::{}),",
            rust_lit(&a.content),
            pascal_case(&a.variant)
        ));
    }
    match fallback {
        Some(fb) => lines.push(format!(
            "{indent}        _ => Some({}),",
            value_payload(enum_name, &fb.variant, &fb.fields, "n")
        )),
        None => lines.push(format!("{indent}        _ => None,")),
    }
    lines.push(format!("{indent}    }}"));
    lines.push(format!("{indent}}});"));
}

/// Emit a same-node value union read: try each arm in first-success order by its
/// required attrs; an arm with no required attr is the unconditional fallback.
fn emit_same_node(
    enum_name: &str,
    field: &str,
    node_var: &str,
    arms: &[ValueArm],
    indent: &str,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{indent}let {field} = {{"));
    let inner = format!("{indent}    ");
    let mut catch_all = false;
    for (idx, a) in arms.iter().enumerate() {
        let payload = format!(
            "Some({})",
            value_payload(enum_name, &a.variant, &a.fields, node_var)
        );
        match same_node_guard(a, node_var) {
            None => {
                // No required attr → unconditional fallback (separability guarantees
                // this is the last arm).
                if idx == 0 {
                    lines.push(format!("{inner}{payload}"));
                } else {
                    lines.push(format!("{inner}else {{ {payload} }}"));
                }
                catch_all = true;
                break;
            }
            Some(g) => {
                let kw = if idx == 0 { "if" } else { "else if" };
                lines.push(format!("{inner}{kw} {g} {{ {payload} }}"));
            }
        }
    }
    if !catch_all {
        lines.push(format!("{inner}else {{ None }}"));
    }
    lines.push(format!("{indent}}};"));
}

/// `node_var.get_optional_child(s0).and_then(|n| n.get_optional_child(s1))…` — the
/// content node reached by descending `segs`, as an `Option<NodeRef>` expression.
fn descend_opt_expr(node_var: &str, segs: &[String]) -> String {
    let mut expr = format!("{node_var}.get_optional_child({})", rust_lit(&segs[0]));
    for seg in &segs[1..] {
        expr = format!(
            "{expr}.and_then(|n| n.get_optional_child({}))",
            rust_lit(seg)
        );
    }
    expr
}

/// The `if` condition selecting a same-node variant: all its required attrs present.
/// `None` when the variant has no required attr (an unconditional fallback).
fn same_node_guard(arm: &ValueArm, node_var: &str) -> Option<String> {
    let conds: Vec<String> = arm
        .fields
        .iter()
        .filter(|f| f.required && f.method.starts_with("attr"))
        .map(|f| {
            let wire = f.wire_name.as_deref().unwrap_or(&f.name);
            format!("{node_var}.get_attr({}).is_some()", rust_lit(wire))
        })
        .collect();
    if conds.is_empty() {
        None
    } else {
        Some(conds.join(" && "))
    }
}

/// `Enum::Variant` or `Enum::Variant { field: <expr>, … }` reading its leaves off
/// `node_var`. Required leaves are guarded present (by `same_node_guard` or the
/// fallback's position), so they read with `unwrap_or_default`.
fn value_payload(enum_name: &str, variant: &str, fields: &[ParsedField], node_var: &str) -> String {
    let v = pascal_case(variant);
    if fields.is_empty() {
        return format!("{enum_name}::{v}");
    }
    let body: Vec<String> = fields
        .iter()
        .map(|f| format!("{}: {}", rust_ident(&f.name), field_expr(f, node_var)))
        .collect();
    format!("{enum_name}::{v} {{ {} }}", body.join(", "))
}

/// A leaf read as an EXPRESSION (no `?`), for an enum variant struct-init. Mirrors
/// `emit_field_parse`'s type mapping but defaults required leaves instead of failing
/// (the variant guard already proved the required attrs present).
fn field_expr(f: &ParsedField, node_var: &str) -> String {
    let method = f.method.as_str();
    if method == wap::CONTENT_STRING {
        return format!("{node_var}.content_str().unwrap_or_default().to_string()");
    }
    if method == wap::CONTENT_BYTES {
        return format!("{node_var}.content_bytes().map(|b| b.to_vec()).unwrap_or_default()");
    }
    if method == wap::CONTENT_INT {
        return format!(
            "{node_var}.content_str().and_then(|s| s.parse().ok()).unwrap_or_default()"
        );
    }
    let wire = f.wire_name.as_deref().unwrap_or(&f.name);
    let flit = rust_lit(wire);
    let optional = wap::is_optional_method(method);
    match wap::method_field_type(method) {
        ParsedFieldType::Integer if optional => {
            format!("{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse().ok())")
        }
        ParsedFieldType::Integer => format!(
            "{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse().ok()).unwrap_or_default()"
        ),
        ParsedFieldType::DeviceJid
        | ParsedFieldType::GroupJid
        | ParsedFieldType::JidTyped
        | ParsedFieldType::Jid
            if optional =>
        {
            format!("{node_var}.get_attr({flit}).and_then(|v| v.to_jid())")
        }
        ParsedFieldType::DeviceJid
        | ParsedFieldType::GroupJid
        | ParsedFieldType::JidTyped
        | ParsedFieldType::Jid => {
            format!("{node_var}.get_attr({flit}).and_then(|v| v.to_jid()).unwrap_or_default()")
        }
        _ if optional => format!("{node_var}.get_attr({flit}).map(|v| v.as_str().to_string())"),
        _ => format!(
            "{node_var}.get_attr({flit}).map(|v| v.as_str().to_string()).unwrap_or_default()"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a single `type=union` field from JSON (the IR's on-wire shape).
    fn union_field(json: serde_json::Value) -> ParsedField {
        serde_json::from_value(json).expect("valid ParsedField")
    }

    /// A content-discriminated union with a typed fallback (the group member-mode
    /// shape): two content-pinned markers + a fallback capturing the raw content.
    fn member_mode_union() -> ParsedField {
        union_field(serde_json::json!({
            "method": "", "name": "memberAddModeMemberAddModes", "type": "union",
            "required": true, "sourcePath": ["member_add_mode"],
            "unionVariants": [
                {"name": "AdminAddMode", "fields": [],
                 "assertions": [{"kind": "tag", "name": "member_add_mode"},
                                {"kind": "content", "value": "admin_add"}]},
                {"name": "AllMembersAddMode", "fields": [],
                 "assertions": [{"kind": "tag", "name": "member_add_mode"},
                                {"kind": "content", "value": "all_member_add"}]},
                {"name": "UnknownAddMode",
                 "fields": [{"method": "contentString", "name": "elementValue",
                             "type": "string", "required": true}],
                 "assertions": [{"kind": "tag", "name": "member_add_mode"}]}
            ]
        }))
    }

    /// A same-node value union (the group subject shape): NamedSubject requires the
    /// `subject` attr, the fallback makes it optional.
    fn subject_union() -> ParsedField {
        union_field(serde_json::json!({
            "method": "", "name": "namedSubjectOrUnnamedSubjectFallbackMixinGroup",
            "type": "union", "required": true,
            "unionVariants": [
                {"name": "NamedSubject",
                 "fields": [{"method": "attrString", "name": "subject",
                             "wireName": "subject", "type": "string", "required": true}]},
                {"name": "UnnamedSubjectFallback",
                 "fields": [{"method": "maybeAttrString", "name": "subject",
                             "wireName": "subject", "type": "string", "required": false}]}
            ]
        }))
    }

    #[test]
    fn content_union_with_fallback_classifies_and_emits() {
        let f = member_mode_union();
        let (field, enum_def) = collect_union(&f, "Spec").expect("classified");
        assert_eq!(field.rust_type, "Option<SpecMemberAddModeMemberAddModes>");
        // Two unit arms + one struct fallback.
        assert_eq!(enum_def.variants.len(), 3);
        let admin = &enum_def.variants[0];
        assert_eq!(admin.name, "AdminAddMode");
        assert!(admin.fields.is_empty(), "content marker is a unit variant");
        let fb = enum_def
            .variants
            .iter()
            .find(|v| v.name == "UnknownAddMode")
            .unwrap();
        assert_eq!(fb.fields.len(), 1, "fallback carries the raw content field");
        assert_eq!(fb.fields[0].rust_type, "String");

        let (lines, _init) = emit_union_read(&f, "group", "Spec", "").unwrap();
        let code = lines.join("\n");
        // Optional descent + content match + typed fallback that captures the content.
        assert!(
            code.contains("group.get_optional_child(\"member_add_mode\").and_then(|n| {"),
            "{code}"
        );
        assert!(
            code.contains("\"admin_add\" => Some(SpecMemberAddModeMemberAddModes::AdminAddMode)"),
            "{code}"
        );
        assert!(
            code.contains(
                "_ => Some(SpecMemberAddModeMemberAddModes::UnknownAddMode { element_value: n.content_str().unwrap_or_default().to_string() })"
            ),
            "fallback should capture raw content:\n{code}"
        );
    }

    #[test]
    fn pure_content_union_falls_to_none() {
        // Drop the fallback variant → an unknown content must decode to None.
        let f = union_field(serde_json::json!({
            "method": "", "name": "memberAddModeMemberAddModes", "type": "union",
            "required": true, "sourcePath": ["member_add_mode"],
            "unionVariants": [
                {"name": "AdminAddMode", "fields": [],
                 "assertions": [{"kind": "content", "value": "admin_add"}]},
                {"name": "AllMembersAddMode", "fields": [],
                 "assertions": [{"kind": "content", "value": "all_member_add"}]}
            ]
        }));
        let (lines, _) = emit_union_read(&f, "group", "Spec", "").unwrap();
        let code = lines.join("\n");
        assert!(
            code.contains("_ => None,"),
            "no fallback → unknown content is None:\n{code}"
        );
    }

    #[test]
    fn same_node_value_union_cascades_by_required_attr() {
        let f = subject_union();
        let (field, enum_def) = collect_union(&f, "Spec").expect("classified");
        assert!(field.rust_type.starts_with("Option<Spec"));
        assert_eq!(enum_def.variants.len(), 2);
        assert_eq!(enum_def.variants[0].fields[0].rust_type, "String");
        assert_eq!(enum_def.variants[1].fields[0].rust_type, "Option<String>");

        let (lines, _) = emit_union_read(&f, "group", "Spec", "").unwrap();
        let code = lines.join("\n");
        // First-success: NamedSubject when `subject` present, else the fallback.
        assert!(
            code.contains("if group.get_attr(\"subject\").is_some() {"),
            "{code}"
        );
        assert!(code.contains("::NamedSubject {"), "{code}");
        assert!(
            code.contains("else {"),
            "fallback arm for the optional variant:\n{code}"
        );
        assert!(
            !code.contains("else { None }"),
            "the empty-required arm is the catch-all, not None:\n{code}"
        );
    }

    #[test]
    fn non_separable_same_node_union_is_rejected() {
        // First variant has NO required attr → it would always match and shadow the
        // second. Must classify as unsupported (None), not emit a misleading cascade.
        let f = union_field(serde_json::json!({
            "method": "", "name": "ambiguous", "type": "union", "required": true,
            "unionVariants": [
                {"name": "Always", "fields": [{"method": "maybeAttrString", "name": "a",
                                               "type": "string", "required": false}]},
                {"name": "Specific", "fields": [{"method": "attrString", "name": "b",
                                                 "type": "string", "required": true}]}
            ]
        }));
        assert!(
            classify_union(&f).is_none(),
            "subset-shadowed union must be rejected"
        );
        assert!(collect_union(&f, "Spec").is_none());
        assert!(emit_union_read(&f, "n", "Spec", "").is_none());
    }

    #[test]
    fn union_with_nested_union_field_is_rejected() {
        // A variant whose payload contains another union (the participant shape) is
        // not a simple leaf set → unsupported, so the field is dropped (not broken).
        let f = union_field(serde_json::json!({
            "method": "", "name": "groupInfoParticipantMixins", "type": "union",
            "required": true,
            "unionVariants": [
                {"name": "Admin", "fields": [
                    {"method": "attrEnum", "name": "type", "type": "enum", "required": true},
                    {"method": "", "name": "inner", "type": "union", "required": true,
                     "unionVariants": [{"name": "X", "fields": []}]}
                ], "assertions": [{"kind": "tag", "name": "participant"}]},
                {"name": "NonAdmin", "fields": [
                    {"method": "maybeAttrString", "name": "label", "type": "string", "required": false}
                ], "assertions": [{"kind": "tag", "name": "participant"}]}
            ]
        }));
        assert!(
            classify_union(&f).is_none(),
            "nested-union variant must be rejected"
        );
    }
}
