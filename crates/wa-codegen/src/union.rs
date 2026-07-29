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
//! * **Tag-discriminated** — variants share one node's tag but carry richer payloads
//!   (nested children/unions). Each becomes a newtype enum arm over its own generated
//!   struct; the parser tries them first-success, gated by each variant's pinned attr
//!   values and required fields. The same separability check (signature subset + a
//!   pinned-attr conflict) rejects shapes where an earlier arm would shadow a later.

use std::collections::BTreeSet;

use wa_ir::{AssertionKind, ParsedField, ParsedFieldType, ResponseAssertion, UnionVariant, wap};

use crate::emit::emit_struct_parser;
use crate::fields::{
    RustChildStruct, RustEnum, RustEnumVariant, RustField, collect_response_fields, is_attr_field,
    rust_field_type,
};
use crate::naming::{pascal_case, rust_ident, rust_lit, rust_lit_inner};
use crate::spec::parser_is_valid;

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
    /// Struct-variant enum read off the SAME node, chosen by the VALUE of one pinned
    /// attribute rather than by which attributes happen to be present. `<category
    /// name="calladd" value=…>`: the name picks both the enum the value is validated
    /// against and what the variant is called.
    AttrDiscriminated { attr: String, arms: Vec<AttrArm> },
    /// Newtype enum over per-variant structs, read off one node (all variants share the
    /// node's tag). Variants may carry nested children/unions, so each becomes its own
    /// generated struct; the parser tries them in first-success order, gated by each
    /// variant's pinned attrs + its required fields. Separability is checked up front.
    TagDiscriminated {
        descend: Vec<String>,
        arms: Vec<TagArm>,
    },
}

/// A tag-discriminated arm: a variant whose payload is read by [`emit_struct_parser`]
/// off the shared node, gated by `attr_values` (pinned discriminator attrs).
pub(crate) struct TagArm {
    pub variant: String,
    pub attr_values: Vec<(String, String)>,
    pub fields: Vec<ParsedField>,
}

/// An attr-discriminated arm: the discriminator holding `value` selects `variant`,
/// which carries the leaves that arm reads (none, for an accepted-but-empty name).
pub(crate) struct AttrArm {
    pub variant: String,
    pub value: String,
    pub fields: Vec<ParsedField>,
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
    classify_content(f, variants)
        .or_else(|| classify_attr_discriminated(f, variants))
        .or_else(|| classify_same_node(f, variants))
        .or_else(|| classify_tag_discriminated(f, variants))
}

/// Tag-discriminated: every variant shares the same tag (the node the union reads off)
/// and carries fields — possibly nested children/unions. The variants are told apart
/// by a first-success cascade (pinned attr values + required-field presence). Rejected
/// (→ `None`, field dropped) unless EVERY variant's per-arm parser validates AND the
/// variants are separable (no earlier arm's discriminator signature subsets a later
/// one's without a conflicting pinned attr — which would shadow the later arm).
fn classify_tag_discriminated(f: &ParsedField, variants: &[UnionVariant]) -> Option<UnionShape> {
    let tag = tag_assert(&variants[0].assertions)?;
    if !variants
        .iter()
        .all(|v| tag_assert(&v.assertions) == Some(tag))
    {
        return None;
    }
    if variants.iter().any(|v| v.fields.is_empty()) {
        return None;
    }
    // Each variant's payload must be a parser the codegen can actually emit.
    for v in variants {
        if !parser_is_valid(&v.fields, "ProbeStruct", "ProbeStruct") {
            return None;
        }
    }
    // Separability: an earlier variant whose signature subsets a later one's (and isn't
    // told apart by a conflicting pinned attr) would always match first and shadow it.
    let sigs: Vec<BTreeSet<String>> = variants.iter().map(variant_signature).collect();
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            if sigs[i].is_subset(&sigs[j]) && !variants_conflict(&variants[i], &variants[j]) {
                return None;
            }
        }
    }
    let descend = f
        .source_path
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_default();
    let arms = variants
        .iter()
        .map(|v| TagArm {
            variant: v.name.clone(),
            attr_values: v
                .assertions
                .iter()
                .filter(|a| a.kind == AssertionKind::Attr)
                .filter_map(|a| Some((a.name.clone()?, a.value.clone()?)))
                .collect(),
            fields: v.fields.clone(),
        })
        .collect();
    Some(UnionShape::TagDiscriminated { descend, arms })
}

/// The discriminator signature of a variant: pinned attr/content values plus the names
/// of its fail-on-absent fields. A required nested union counts as one atom (its own
/// `union_variants` aren't recursed — they don't tell THIS variant from a sibling).
fn variant_signature(v: &UnionVariant) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    for a in &v.assertions {
        match a.kind {
            AssertionKind::Attr => {
                if let (Some(n), Some(val)) = (&a.name, &a.value) {
                    s.insert(format!("ATTRVAL:{n}={val}"));
                }
            }
            AssertionKind::Content => {
                if let Some(val) = &a.value {
                    s.insert(format!("CONTENT:{val}"));
                }
            }
            _ => {}
        }
    }
    fn walk(fields: &[ParsedField], s: &mut BTreeSet<String>) {
        for f in fields {
            if f.field_type == ParsedFieldType::Union {
                if f.required {
                    s.insert(format!("NESTED:{}", f.name));
                }
                continue;
            }
            // A repeated child reads as a possibly-empty `Vec` (the parser never bails
            // when it's absent), so neither it NOR its contents are fail-on-absent —
            // they can't discriminate a variant. Excluding them keeps the separability
            // gate from accepting a union whose first arm matches unconditionally and
            // shadows a later one (e.g. newsletter views-count: required repeated
            // `views_count` vs the deprecated `count` attr).
            if f.repeats == Some(true) {
                continue;
            }
            if f.required && (f.method == "child" || f.method.starts_with("attr")) {
                s.insert(format!("REQ:{}", f.name));
            }
            if let Some(kids) = &f.children {
                walk(kids, s);
            }
        }
    }
    walk(&v.fields, &mut s);
    s
}

/// Two variants are told apart when both pin the SAME attr to DIFFERENT values
/// (`type:"text"` vs `type:"media"`) — then neither shadows the other.
fn variants_conflict(a: &UnionVariant, b: &UnionVariant) -> bool {
    a.assertions.iter().any(|x| {
        x.kind == AssertionKind::Attr
            && x.value.is_some()
            && b.assertions
                .iter()
                .any(|y| y.kind == AssertionKind::Attr && y.name == x.name && y.value != x.value)
    })
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
/// Attr-discriminated: every variant pins the SAME attribute to a DIFFERENT value, and
/// carries only leaves read off that same node (or nothing at all). Unlike
/// [`classify_same_node`], which tells arms apart by which attributes are present, this
/// reads one attribute and matches its value — so arms that read the very same wire
/// attribute stay distinguishable.
fn classify_attr_discriminated(f: &ParsedField, variants: &[UnionVariant]) -> Option<UnionShape> {
    if f.source_path.as_ref().is_some_and(|s| !s.is_empty()) {
        return None; // a descent isn't a same-node read
    }
    let mut attr: Option<String> = None;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut arms = Vec::new();
    for v in variants {
        if tag_assert(&v.assertions).is_some() || content_assert(&v.assertions).is_some() {
            return None;
        }
        if !v.fields.iter().all(is_simple_leaf) {
            return None;
        }
        // Exactly one pinned attr, and the same one across the union.
        let pins: Vec<(&str, &str)> = v
            .assertions
            .iter()
            .filter(|a| a.kind == AssertionKind::Attr)
            .filter_map(|a| Some((a.name.as_deref()?, a.value.as_deref()?)))
            .collect();
        let [(name, value)] = pins[..] else {
            return None;
        };
        match &attr {
            Some(a) if a != name => return None,
            Some(_) => {}
            None => attr = Some(name.to_string()),
        }
        // Two arms on the same value would shadow each other.
        if !seen.insert(value.to_string()) {
            return None;
        }
        arms.push(AttrArm {
            variant: v.name.clone(),
            value: value.to_string(),
            fields: v.fields.clone(),
        });
    }
    Some(UnionShape::AttrDiscriminated { attr: attr?, arms })
}

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

/// The struct field (typed `Option<Enum>`), the enum definition(s), and any per-variant
/// structs for a union field — or `None` when it isn't codegen-able. `Option` (never
/// bare) keeps the parser resilient: an unrecognized variant decodes to `None`. A
/// tag-discriminated union also returns a generated struct per variant (with the child
/// item structs + nested enums those reach), all emitted at module level.
pub(crate) fn collect_union(
    f: &ParsedField,
    prefix: &str,
) -> Option<(RustField, Vec<RustEnum>, Vec<RustChildStruct>)> {
    let shape = classify_union(f)?;
    let name = enum_name(f, prefix);
    let field = RustField {
        name: rust_ident(&f.name),
        rust_type: format!("Option<{name}>"),
        is_vec: false,
    };
    let doc = format!("Discriminated union for response field `{}`.", f.name);

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
        tuple_type: None,
    };

    match &shape {
        UnionShape::Content { arms, fallback, .. } => {
            let mut variants: Vec<RustEnumVariant> = arms
                .iter()
                .map(|a| RustEnumVariant {
                    name: pascal_case(&a.variant),
                    fields: Vec::new(),
                    tuple_type: None,
                })
                .collect();
            if let Some(fb) = fallback {
                variants.push(value_variant(&fb.variant, &fb.fields));
            }
            let e = RustEnum {
                name,
                doc,
                variants,
            };
            Some((field, vec![e], Vec::new()))
        }
        UnionShape::AttrDiscriminated { arms, .. } => {
            let variants = arms
                .iter()
                .map(|a| value_variant(&a.variant, &a.fields))
                .collect();
            let e = RustEnum {
                name,
                doc,
                variants,
            };
            Some((field, vec![e], Vec::new()))
        }
        UnionShape::SameNode { arms } => {
            let variants = arms
                .iter()
                .map(|a| value_variant(&a.variant, &a.fields))
                .collect();
            let e = RustEnum {
                name,
                doc,
                variants,
            };
            Some((field, vec![e], Vec::new()))
        }
        UnionShape::TagDiscriminated { arms, .. } => {
            // Each arm becomes a newtype variant over its own generated struct, which
            // recursively collects its fields, child item structs, and nested enums.
            let mut variants = Vec::new();
            let mut enums = Vec::new();
            let mut structs = Vec::new();
            for a in arms {
                let vname = pascal_case(&a.variant);
                let struct_name = format!("{name}{vname}");
                let (top, child_structs, nested_enums) =
                    collect_response_fields(&a.fields, &struct_name);
                structs.push(RustChildStruct {
                    name: struct_name.clone(),
                    fields: top,
                });
                structs.extend(child_structs);
                enums.extend(nested_enums);
                variants.push(RustEnumVariant {
                    name: vname,
                    fields: Vec::new(),
                    tuple_type: Some(struct_name),
                });
            }
            enums.insert(
                0,
                RustEnum {
                    name,
                    doc,
                    variants,
                },
            );
            Some((field, enums, structs))
        }
    }
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
        UnionShape::AttrDiscriminated { attr, arms } => {
            emit_attr_discriminated(&name, &field, node_var, &attr, &arms, indent, &mut lines)
        }
        UnionShape::SameNode { arms } => {
            emit_same_node(&name, &field, node_var, &arms, indent, &mut lines)
        }
        UnionShape::TagDiscriminated { descend, arms } => emit_tag_discriminated(
            &name, &field, node_var, &descend, &arms, prefix, indent, &mut lines,
        ),
    }
    Some((lines, format!("{indent}    {field},")))
}

/// Emit a tag-discriminated union read: descend (optionally) to the shared node, then
/// try each variant's per-arm parser in first-success order — the first whose pinned
/// attrs match and whose required fields all read wins. Unmatched → `None`.
#[allow(clippy::too_many_arguments)]
fn emit_tag_discriminated(
    enum_name: &str,
    field: &str,
    node_var: &str,
    descend: &[String],
    arms: &[TagArm],
    prefix: &str,
    indent: &str,
    lines: &mut Vec<String>,
) {
    if descend.is_empty() {
        lines.push(format!(
            "{indent}let {field} = (|| -> Option<{enum_name}> {{"
        ));
        emit_tag_cascade(
            enum_name,
            node_var,
            arms,
            prefix,
            &format!("{indent}    "),
            lines,
        );
        lines.push(format!("{indent}}})();"));
    } else {
        let node = descend_opt_expr(node_var, descend);
        lines.push(format!("{indent}let {field} = {node}.and_then(|n| {{"));
        emit_tag_cascade(
            enum_name,
            "n",
            arms,
            prefix,
            &format!("{indent}    "),
            lines,
        );
        lines.push(format!("{indent}}});"));
    }
}

/// The first-success cascade body (shared by the descend / no-descend wrappers): one
/// per-arm closure that bails on a failed pinned-attr guard or a missing required
/// field, then `return Some(Enum::Variant(struct))` on the first that parses.
fn emit_tag_cascade(
    enum_name: &str,
    read_var: &str,
    arms: &[TagArm],
    _prefix: &str,
    indent: &str,
    lines: &mut Vec<String>,
) {
    let inner = format!("{indent}    ");
    for a in arms {
        let vname = pascal_case(&a.variant);
        let struct_name = format!("{enum_name}{vname}");
        lines.push(format!(
            "{indent}let __r: Result<{struct_name}, anyhow::Error> = (|| -> Result<{struct_name}, anyhow::Error> {{"
        ));
        for (n, val) in &a.attr_values {
            lines.push(format!(
                "{inner}if {read_var}.get_attr({}).map(|x| x.as_str()).as_deref() != Some({}) {{ anyhow::bail!(\"{}: {} != {}\"); }}",
                rust_lit(n),
                rust_lit(val),
                vname,
                rust_lit_inner(n),
                rust_lit_inner(val),
            ));
        }
        // The per-variant struct is its OWN prefix, so child item structs match the
        // names `collect_response_fields(&a.fields, &struct_name)` generated.
        lines.extend(emit_struct_parser(
            &a.fields,
            read_var,
            &struct_name,
            &inner,
            &struct_name,
        ));
        lines.push(format!("{indent}}})();"));
        lines.push(format!(
            "{indent}if let Ok(__v) = __r {{ return Some({enum_name}::{vname}(__v)); }}"
        ));
    }
    lines.push(format!("{indent}None"));
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
/// Emit an attr-discriminated read: take the discriminator once, then match its value.
/// An unrecognized value decodes to `None`, so a name this bundle did not know about
/// leaves the field empty rather than failing the whole response.
#[allow(clippy::too_many_arguments)]
fn emit_attr_discriminated(
    enum_name: &str,
    field: &str,
    node_var: &str,
    attr: &str,
    arms: &[AttrArm],
    indent: &str,
    lines: &mut Vec<String>,
) {
    // `.map(|x| x.as_str()).as_deref()`, the same way the tag cascade reads a pinned attr:
    // the accessor yields a value that only borrows as `str` through `as_str`.
    lines.push(format!(
        "{indent}let {field} = match {node_var}.get_attr({}).map(|x| x.as_str()).as_deref() {{",
        rust_lit(attr)
    ));
    for a in arms {
        // The IR marks a leaf required; without it the arm is not that variant. Reading it
        // anyway would default the field and fabricate a value the element never carried.
        let required: Vec<String> = a
            .fields
            .iter()
            .filter(|f| f.required && f.method.starts_with("attr"))
            .map(|f| {
                let wire = f.wire_name.as_deref().unwrap_or(&f.name);
                format!("{node_var}.get_attr({}).is_some()", rust_lit(wire))
            })
            .collect();
        let guard = if required.is_empty() {
            String::new()
        } else {
            format!(" if {}", required.join(" && "))
        };
        lines.push(format!(
            "{indent}    Some({}){guard} => Some({}),",
            rust_lit(&a.value),
            value_payload(enum_name, &a.variant, &a.fields, node_var)
        ));
    }
    lines.push(format!("{indent}    _ => None,"));
    lines.push(format!("{indent}}};"));
}

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
    // Derived, not enumerated — the same three names were spelled out here as in
    // `is_attr_field` and `child_content_type`, so a `contentUint` inside a union variant
    // fell through to the attribute path and was read as an attribute that does not exist.
    if wap::is_content_method(method) {
        return format!("{node_var}.{}", crate::emit::content_decoder(method));
    }
    let wire = f.wire_name.as_deref().unwrap_or(&f.name);
    let flit = rust_lit(wire);
    let optional = wap::is_optional_method(method) || !f.required;
    match wap::method_field_type(method) {
        ParsedFieldType::Integer if optional => {
            format!("{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse().ok())")
        }
        ParsedFieldType::Integer => format!(
            "{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse().ok()).unwrap_or_default()"
        ),
        t if t.is_jid() && optional => {
            format!("{node_var}.get_attr({flit}).and_then(|v| v.to_jid())")
        }
        t if t.is_jid() => {
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

    /// The privacy-settings shape: one attribute picks both the variant and what the
    /// runtime calls the value read beside it.
    fn category_union() -> ParsedField {
        union_field(serde_json::json!({
            "method": "dispatch", "name": "name_dispatch", "type": "union", "required": true,
            "unionVariants": [
                {"name": "readreceipts",
                 "assertions": [{"kind": "attr", "name": "name", "value": "readreceipts"}],
                 "fields": [{"method": "attrString", "name": "readReceipts",
                             "wireName": "value", "type": "string", "required": true}]},
                {"name": "calladd",
                 "assertions": [{"kind": "attr", "name": "name", "value": "calladd"}],
                 "fields": [{"method": "attrString", "name": "callAdd",
                             "wireName": "value", "type": "string", "required": true}]},
                {"name": "stickers",
                 "assertions": [{"kind": "attr", "name": "name", "value": "stickers"}],
                 "fields": []}
            ]
        }))
    }

    #[test]
    fn attr_discriminated_union_matches_on_the_pinned_value() {
        // Every arm reads the same wire attribute, so a presence test cannot tell them
        // apart — only the discriminator's value can.
        let f = category_union();
        let (field, enums, structs) = collect_union(&f, "Spec").expect("classified");
        assert_eq!(field.rust_type, "Option<SpecNameDispatch>");
        assert!(structs.is_empty(), "leaves need no per-variant struct");
        let variants = &enums[0].variants;
        assert_eq!(
            variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            ["Readreceipts", "Calladd", "Stickers"]
        );
        assert_eq!(variants[0].fields[0].name, "read_receipts");
        assert!(
            variants[2].fields.is_empty(),
            "an accepted name with no value"
        );

        let (lines, _) = emit_union_read(&f, "node", "Spec", "").expect("emitted");
        let src = lines.join("\n");
        assert!(
            src.contains("match node.get_attr(\"name\").map(|x| x.as_str()).as_deref()"),
            "reads the discriminator once: {src}"
        );
        assert!(
            src.contains(
                "Some(\"calladd\") if node.get_attr(\"value\").is_some() => Some(SpecNameDispatch::Calladd {"
            ),
            "a required leaf gates its arm rather than being defaulted: {src}"
        );
        assert!(
            src.contains("Some(\"stickers\") => Some(SpecNameDispatch::Stickers)"),
            "a valueless name is a unit variant: {src}"
        );
        assert!(
            src.contains("_ => None"),
            "an unknown name decodes to None rather than failing: {src}"
        );
    }

    #[test]
    fn attr_discriminated_union_refuses_two_arms_on_one_value() {
        // Two arms pinned to the same value would shadow each other; the field is skipped
        // rather than emitted with an unreachable arm.
        let mut f = category_union();
        let vs = f.union_variants.as_mut().unwrap();
        vs[1].assertions[0].value = Some("readreceipts".to_string());
        assert!(classify_union(&f).is_none());
    }

    #[test]
    fn content_union_with_fallback_classifies_and_emits() {
        let f = member_mode_union();
        let (field, enums, _structs) = collect_union(&f, "Spec").expect("classified");
        let enum_def = &enums[0];
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
        let (field, enums, _structs) = collect_union(&f, "Spec").expect("classified");
        let enum_def = &enums[0];
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
    fn tag_discriminated_participant_union_recovers() {
        // The participant shape: two variants share tag=participant; Admin has a
        // required `type` (and a nested union) that NonAdmin lacks, so they're
        // separable (Admin first, NonAdmin fallback). Recovered as a newtype enum
        // over per-variant structs.
        let f = union_field(serde_json::json!({
            "method": "", "name": "groupInfoParticipantMixins", "type": "union",
            "required": true,
            "unionVariants": [
                {"name": "GroupInfoParticipantAdmin", "fields": [
                    {"method": "attrEnum", "name": "type", "wireName": "type", "type": "enum", "required": true},
                    {"method": "maybeAttrString", "name": "participantLabel", "wireName": "participant_label", "type": "string", "required": false}
                ], "assertions": [{"kind": "tag", "name": "participant"}]},
                {"name": "GroupInfoParticipantNonAdmin", "fields": [
                    {"method": "maybeAttrString", "name": "participantLabel", "wireName": "participant_label", "type": "string", "required": false}
                ], "assertions": [{"kind": "tag", "name": "participant"}]}
            ]
        }));
        let (field, enums, structs) = collect_union(&f, "Spec").expect("classified");
        assert!(field.rust_type.starts_with("Option<Spec"));
        // Newtype variants over two generated structs.
        let e = &enums[0];
        assert_eq!(e.variants.len(), 2);
        assert!(e.variants.iter().all(|v| v.tuple_type.is_some()));
        assert!(
            structs
                .iter()
                .any(|s| s.name.ends_with("GroupInfoParticipantAdmin"))
        );
        // The parser tries each arm; Admin's required `type` makes it fail-fast for a
        // NonAdmin response.
        let (lines, _) = emit_union_read(&f, "participant_item", "Spec", "").unwrap();
        let code = lines.join("\n");
        assert!(code.contains("::GroupInfoParticipantAdmin(__v)"), "{code}");
        assert!(
            code.contains("if let Ok(__v) = __r"),
            "first-success cascade:\n{code}"
        );
    }

    #[test]
    fn tag_discriminated_attr_value_discriminator() {
        // Newsletter text/media: same tag, told apart by a pinned `type` attr value.
        let f = union_field(serde_json::json!({
            "method": "", "name": "newsletterTextOrMediaMixinGroup", "type": "union",
            "required": true,
            "unionVariants": [
                {"name": "NewsletterText", "fields": [
                    {"method": "attrString", "name": "type", "wireName": "type", "type": "string", "required": true}
                ], "assertions": [{"kind": "tag", "name": "message"}, {"kind": "attr", "name": "type", "value": "text"}]},
                {"name": "NewsletterMedia", "fields": [
                    {"method": "attrString", "name": "type", "wireName": "type", "type": "string", "required": true},
                    {"method": "attrEnum", "name": "plaintextMediatype", "wireName": "mediatype", "type": "enum", "required": true}
                ], "assertions": [{"kind": "tag", "name": "message"}, {"kind": "attr", "name": "type", "value": "media"}]}
            ]
        }));
        let (lines, _) = emit_union_read(&f, "message_item", "Spec", "").unwrap();
        let code = lines.join("\n");
        // Each arm guards on its pinned type value (Cow-safe comparison).
        assert!(
            code.contains(
                "message_item.get_attr(\"type\").map(|x| x.as_str()).as_deref() != Some(\"text\")"
            ),
            "{code}"
        );
        assert!(code.contains("Some(\"media\")"), "{code}");
    }

    #[test]
    fn non_separable_tag_union_is_rejected() {
        // userFetch shape: Error and ErrorFallback have IDENTICAL required sets and no
        // pinned-attr conflict → ErrorFallback is unreachable → must drop, not misclassify.
        let f = union_field(serde_json::json!({
            "method": "", "name": "userFetch", "type": "union", "required": true,
            "unionVariants": [
                {"name": "Success", "fields": [
                    {"method": "attrString", "name": "skeyId", "wireName": "skey_id", "type": "string", "required": true}
                ], "assertions": [{"kind": "tag", "name": "user"}]},
                {"name": "Error", "fields": [
                    {"method": "attrString", "name": "errorText", "wireName": "error_text", "type": "string", "required": true},
                    {"method": "attrInt", "name": "errorCode", "wireName": "error_code", "type": "integer", "required": true}
                ], "assertions": [{"kind": "tag", "name": "user"}]},
                {"name": "ErrorFallback", "fields": [
                    {"method": "attrString", "name": "errorText", "wireName": "error_text", "type": "string", "required": true},
                    {"method": "attrInt", "name": "errorCode", "wireName": "error_code", "type": "integer", "required": true}
                ], "assertions": [{"kind": "tag", "name": "user"}]}
            ]
        }));
        assert!(
            classify_union(&f).is_none(),
            "Error == ErrorFallback (no discriminator) must be rejected"
        );
    }

    #[test]
    fn required_repeated_child_is_not_a_discriminator() {
        // views-count shape: the first arm's only required field is a REPEATED child,
        // which the parser reads as a possibly-empty Vec (never bails) — so it matches
        // unconditionally and shadows the later `count`-attr arm. Must be rejected, not
        // emitted (which would drop the deprecated count).
        let f = union_field(serde_json::json!({
            "method": "", "name": "viewsCountViewsOrDeprecated", "type": "union", "required": true,
            "unionVariants": [
                {"name": "Views", "fields": [
                    {"method": "child", "name": "viewsCount", "tag": "views_count", "type": "string",
                     "required": true, "repeats": true,
                     "children": [{"method": "attrInt", "name": "v", "wireName": "v", "type": "integer", "required": true}]}
                ], "assertions": [{"kind": "tag", "name": "message"}]},
                {"name": "Deprecated", "fields": [
                    {"method": "attrInt", "name": "viewsCountCount", "wireName": "count", "type": "integer", "required": true}
                ], "assertions": [{"kind": "tag", "name": "message"}]}
            ]
        }));
        assert!(
            classify_union(&f).is_none(),
            "an arm whose only required field is a repeated child shadows later arms"
        );
    }
}
