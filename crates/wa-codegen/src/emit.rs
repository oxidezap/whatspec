//! Emit Rust source fragments: response parsers and request builders.

use std::collections::HashMap;

use wa_ir::wap;
use wa_ir::{ParsedField, ParsedFieldType, WapAttrKind, WapChildNode, WapContentKind};

use crate::fields::{
    child_content_type, flatten_same_node, is_attr_field, is_child_field, is_jid_kind,
};
use crate::naming::{pascal_case, rust_ident, rust_lit, rust_lit_inner, snake_case};

fn tag_or_name(f: &ParsedField) -> &str {
    f.tag.as_deref().unwrap_or(&f.name)
}

fn children_of(f: &ParsedField) -> &[ParsedField] {
    f.children.as_deref().unwrap_or(&[])
}

fn repeats(f: &ParsedField) -> bool {
    f.repeats == Some(true)
}

/// Emit the `let <name> = ...;` lines that read a single field off `node_var`.
///
/// Content accessors read the node body; attribute accessors derive their shape
/// from the canonical [`wap::method_field_type`] + optionality, so a newly-added
/// accessor in `wap` flows through here instead of being swallowed by a silent
/// `_ => Vec::new()` catch-all. Non-field methods (child accessors, `hasAttr`,
/// `contentInt`) are materialized elsewhere and emit nothing here.
pub(crate) fn emit_field_parse(f: &ParsedField, node_var: &str, indent: &str) -> Vec<String> {
    let name = rust_ident(&f.name);
    // The attribute is read by its WIRE name (snake_case), not the camelCase
    // struct field name; smax responses name the field by the makeResult key.
    let wire = f.wire_name.as_deref().unwrap_or(&f.name);
    let flit = rust_lit(wire);
    let fmsg = rust_lit_inner(wire);
    let method = f.method.as_str();

    // Every remaining content spelling reads the node body and is typed by the canonical
    // classifier, so a newly-recognized one (`contentUint`, `contentEnum`,
    // `contentBytesRange`, `contentLiteralBytes`) is parsed rather than silently skipped.
    if wap::is_content_method(method) {
        let mut out = vec![format!(
            "{indent}let {name} = {node_var}.{};",
            content_decoder(method)
        )];
        // The same band the attribute path enforces. A content leaf declaring `intMin: -10`
        // decoded the number and checked nothing, and the moment its width could be signed a
        // `-20` materialized where the unsigned parse had been refusing every negative value by
        // accident. The union's content guard already tests this band; the ordinary read did
        // not, which is one rule spelled in two places with one copy missing it — again.
        if let Some(test) = super::fields::int_band(f, &name) {
            out.push(format!(
                "{indent}anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
            ));
        }
        // And the length a bytes accessor pins, which this path decoded and ignored entirely:
        // `contentBytes(32)` and `contentBytesRange(1, 128)` both record what they will accept,
        // and the generated parser took a body of any length. The union's leaf guard has
        // checked it all along — the same one-rule-two-places asymmetry as the integer band,
        // on the other kind of constraint, so it reads the same shared predicate.
        //
        // Only where the decoded value IS bytes. `contentUint(N)` records a byte length too and
        // folds those bytes into a `u64`, which has no `len()`; the classifier calls it an
        // integer, so asking it here keeps the two apart.
        if wap::method_field_type(method) == ParsedFieldType::Bytes
            && let Some(test) = super::fields::byte_band(f, &name)
        {
            out.push(format!(
                "{indent}anyhow::ensure!({test}, \"{fmsg} wrong length: {{}}\", {name}.len());"
            ));
        }
        return out;
    }
    if !wap::is_attr_method(method) {
        return Vec::new();
    }

    // See `rust_field_type`: the accessor spelling and the IR's `required` are both
    // sources of optionality, and the two must agree or the initializer will not match the
    // declared field type.
    let optional = wap::is_optional_method(method) || !f.required;
    // A declared band is part of what the accessor accepts, and this path decoded the number and
    // enforced nothing — so `attrIntRange("weight", -10000, 10000)` took a `-20000` the source
    // turns away. Harmless while every integer was `u64`, because the parse itself refused every
    // negative value; the moment the width could be signed it became an over-acceptance, and it
    // is the union guard's own `int_band`, read from one place now.
    let band = super::fields::int_band(f, &name);
    match wap::method_field_type(method) {
        ParsedFieldType::Integer if optional => {
            let read = format!(
                "{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse::<{}>().ok())",
                super::fields::integer_width(f)
            );
            match &band {
                // Out of band is not the same as absent: the source accessor THROWS on a value
                // outside its range, so mapping it to `None` would accept a response the parser
                // rejects — quietly, and with the field simply missing. Whether an unparseable
                // value is absent or an error is a separate question this leaves as it was.
                Some(test) => vec![
                    format!("{indent}let {name} = match {read} {{"),
                    format!("{indent}    Some({name}) => {{"),
                    format!(
                        "{indent}        anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
                    ),
                    format!("{indent}        Some({name})"),
                    format!("{indent}    }}"),
                    format!("{indent}    None => None,"),
                    format!("{indent}}};"),
                ],
                None => vec![format!("{indent}let {name} = {read};")],
            }
        }
        ParsedFieldType::Integer => {
            let mut out = vec![
                format!(
                    "{indent}let {name}: {} = {node_var}.get_attr({flit})",
                    super::fields::integer_width(f)
                ),
                format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
                format!("{indent}    .as_str()"),
                format!("{indent}    .parse()?;"),
            ];
            if let Some(test) = &band {
                out.push(format!(
                    "{indent}anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
                ));
            }
            out
        }
        // An OPTIONAL JID must come first: `rust_field_type` declares `Option<Jid>` for a
        // `maybeAttr…Jid`, and falling into the branch below both mis-typed the
        // initializer and rejected the absence the accessor exists to permit.
        t if t.is_jid() && optional => vec![format!(
            "{indent}let {name} = {node_var}.get_attr({flit}).and_then(|v| v.to_jid());"
        )],
        // Every JID flavor materializes as one `Jid`; switch on `is_jid()` so a newly
        // preserved flavor (UserJid/LidUserJid/…) is parsed as a JID, not a String.
        t if t.is_jid() => vec![format!(
            "{indent}let {name} = {node_var}.get_attr({flit}).and_then(|v| v.to_jid()).ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?;"
        )],
        _ if optional => vec![format!(
            "{indent}let {name} = {node_var}.get_attr({flit}).map(|v| v.as_str().to_string());"
        )],
        _ => vec![
            format!("{indent}let {name} = {node_var}.get_attr({flit})"),
            format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
            format!("{indent}    .as_str()"),
            format!("{indent}    .to_string();"),
        ],
    }
}

/// How to read a content leaf off a node, as a full expression yielding the field's type.
///
/// `contentInt()` and `contentUint(N)` are BOTH integers and are decoded completely
/// differently: `contentInt` is decimal text (a follower count), while `contentUint(N)`
/// is N big-endian bytes (a 3-byte prekey id, a 4-byte registration id). Reading the
/// latter as text makes every one of them silently `0`, which is what grouping them by
/// `method_field_type` alone did.
pub(crate) fn content_decoder(method: &str) -> &'static str {
    if method == "contentUint" {
        return "content_bytes()\n        .map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))\n        .unwrap_or_default()";
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => "content_bytes().map(|b| b.to_vec()).unwrap_or_default()",
        ParsedFieldType::Integer => {
            "content_str().and_then(|s| s.parse().ok()).unwrap_or_default()"
        }
        _ => "content_str().unwrap_or_default().to_string()",
    }
}

/// The same read for a leaf the parser only takes sometimes — yielding `Option<T>` where
/// [`content_decoder`] yields `T`.
///
/// A union variant's member is typed from the IR's `required`, so an arm reading its
/// content behind a guard is declared `Option<String>`; defaulting the read instead
/// produced a `String` for that member and the generated module did not compile.
pub(crate) fn content_decoder_opt(method: &str) -> &'static str {
    if method == "contentUint" {
        return "content_bytes().map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))";
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => "content_bytes().map(|b| b.to_vec())",
        ParsedFieldType::Integer => "content_str().and_then(|s| s.parse().ok())",
        _ => "content_str().map(|s| s.to_string())",
    }
}

/// Emit the body of `parse_response`, ending with `Ok(<ResponseType> {{ ... }})`.
pub(crate) fn emit_response_parser(
    fields: &[ParsedField],
    response_type_name: &str,
    indent: &str,
    prefix: &str,
) -> Vec<String> {
    // lines[0] is reserved for the deferred `use` import, lines[1] is a blank; the
    // body reads off the `response` node and ends in `Ok(<ResponseType> { … })`.
    let mut lines: Vec<String> = vec![String::new(), String::new()];
    lines.extend(emit_struct_parser(
        fields,
        "response",
        response_type_name,
        indent,
        prefix,
    ));
    lines
}

/// Emit the reads for `fields` off `node_var` followed by `Ok(<struct_name> { … })`.
/// Mirrors [`emit_response_parser`] but for an arbitrary node var and struct — reused
/// to build a tag-discriminated union variant's per-arm parser (see [`crate::union`]).
pub(crate) fn emit_struct_parser(
    fields: &[ParsedField],
    node_var: &str,
    struct_name: &str,
    indent: &str,
    prefix: &str,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    // Recursively emit the reads off `node_var`, mirroring `collect_response_fields`:
    // attrs/content leaves become fields, repeated children become `Vec<Item>` loops,
    // and a non-repeated child is descended and its fields flattened into the parent
    // (so the parser inits exactly the struct `collect_response_fields` derived).
    let mut wrapper_vars: HashMap<(String, Vec<String>), String> = HashMap::new();
    let mut init_fields: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    emit_struct_reads(
        fields,
        node_var,
        prefix,
        indent,
        &mut lines,
        &mut wrapper_vars,
        &mut init_fields,
        &mut seen,
    );

    lines.push(format!("{indent}Ok({struct_name} {{"));
    lines.extend(init_fields);
    lines.push(format!("{indent}    ..Default::default()"));
    lines.push(format!("{indent}}})"));
    lines
}

/// Descend `path` (a field's `source_path` wrapper tags) from `base`, returning the
/// node var to read off. `source_path` is relative to the enclosing node, so the
/// descent is keyed by `(base, path)` (memoized per base — the same wrapper under two
/// different parents must descend each). Each segment is read as required (a missing
/// wrapper is a parse error), mirroring a required `child`.
fn descend_from(
    base: &str,
    path: Option<&[String]>,
    vars: &mut HashMap<(String, Vec<String>), String>,
    lines: &mut Vec<String>,
    indent: &str,
) -> String {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return base.to_string();
    };
    let mut parent = base.to_string();
    let mut acc: Vec<String> = Vec::new();
    for seg in path {
        acc.push(seg.clone());
        let key = (base.to_string(), acc.clone());
        if let Some(var) = vars.get(&key) {
            parent = var.clone();
            continue;
        }
        let segs = acc
            .iter()
            .map(|s| snake_case(s))
            .collect::<Vec<_>>()
            .join("_");
        // The common top-level descent stays `<path>_wrap`; nested descents prefix the
        // base node so the same wrapper tag under different parents can't collide.
        let var = if base == "response" {
            format!("{segs}_wrap")
        } else {
            format!("{}__{segs}_wrap", snake_case(base))
        };
        lines.push(format!(
            "{indent}let {var} = {parent}.get_optional_child({})",
            rust_lit(seg)
        ));
        lines.push(format!(
            "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
            rust_lit_inner(seg)
        ));
        vars.insert(key, var.clone());
        parent = var;
    }
    parent
}

/// Recursively emit the reads for `fields` off `node_var`, appending each resulting
/// struct field to `inits` (deduped via `seen`). Mirrors `collect_response_fields`
/// branch-for-branch so the parser inits exactly the fields that function derives:
/// attrs/content-leaves become fields read off the (source-path-descended) node; a
/// repeated child becomes a `Vec<Item>` loop (with one level of repeated grandchild
/// item vecs, as collect models); a non-repeated child is descended and its fields
/// flattened into the SAME struct (collect inlines single children).
#[allow(clippy::too_many_arguments)]
fn emit_struct_reads(
    fields: &[ParsedField],
    node_var: &str,
    prefix: &str,
    indent: &str,
    lines: &mut Vec<String>,
    wrapper_vars: &mut HashMap<(String, Vec<String>), String>,
    inits: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    let fields = flatten_same_node(fields);
    for f in &fields {
        // ── discriminated union (`type=union`) → enum read ──
        // Gated on the same `classify_union` that `collect_response_fields` uses, so a
        // codegen-able union inits the `Option<Enum>` field collect derived, and an
        // unsupported one is skipped by both (the rest of the struct stays typed).
        if f.field_type == ParsedFieldType::Union {
            let id = rust_ident(&f.name);
            if !seen.insert(id.clone()) {
                continue;
            }
            // `emit_union_read` handles its own (optional) `source_path` descent — a
            // union is `Option<Enum>`, so an absent wrapper must yield `None`, not the
            // required `?` descent `descend_from` would emit.
            if let Some((union_lines, init)) =
                crate::union::emit_union_read(f, node_var, prefix, indent)
            {
                lines.extend(union_lines);
                inits.push(init);
            } else {
                seen.remove(&id);
            }
            continue;
        }
        // ── attribute / content-leaf-via-method field ──
        if is_attr_field(f) && f.method != "hasAttr" {
            let id = rust_ident(&f.name);
            if !seen.insert(id.clone()) {
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            lines.extend(emit_field_parse(f, &base, indent));
            inits.push(format!("{indent}    {id},"));
            continue;
        }
        if !is_child_field(f) {
            continue;
        }
        let tag = tag_or_name(f);

        // ── child whose content is the value (`child("x").contentString()`) ──
        if let Some(ct) = f.content_type.or_else(|| child_content_type(f)) {
            let id = rust_ident(tag);
            if !seen.insert(id.clone()) {
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            let lit = rust_lit(tag);
            // Two spellings per kind: one that yields an `Option` for the `maybeChild`
            // chain, one that unwraps for the required branch. Kept as literal text per
            // kind so adding the integer reading leaves the existing bytes/string output
            // byte-for-byte unchanged.
            //
            // The child's OWN accessor decides when it has one, because `ContentType`
            // cannot tell decimal text from big-endian bytes: `contentInt` and
            // `contentUint` are both `Integer` and decode oppositely.
            let leaf = children_of(f)
                .iter()
                .find(|c| wap::is_content_method(&c.method));
            let leaf_method = leaf.map(|c| c.method.as_str());
            let (opt_read, req_read) = match leaf_method {
                Some("contentUint") => (
                    "content_bytes().map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))",
                    "content_bytes()\n        .map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))\n        .unwrap_or_default()",
                ),
                _ => match ct {
                    wa_ir::ContentType::Bytes => (
                        "content_bytes().map(|b| b.to_vec())",
                        "content_bytes().map(|b| b.to_vec()).unwrap_or_default()",
                    ),
                    wa_ir::ContentType::Integer => (
                        "content_str().and_then(|s| s.parse().ok())",
                        "content_str().and_then(|s| s.parse().ok()).unwrap_or_default()",
                    ),
                    _ => (
                        "content_str().map(|s| s.to_string())",
                        "content_str().unwrap_or_default().to_string()",
                    ),
                },
            };
            // The leaf's declared band, which THIS path was not applying. A relaxed
            // `child("weight")` over a `contentInt` leaf bounded to `-10..=10` bypasses
            // `emit_field_parse` entirely and parsed a `-20` straight into the field. That is
            // the third site for one rule — the attribute read, the ordinary content read, and
            // here — so it is `int_band` again rather than a third spelling, and it is asked of
            // the LEAF, which is also where `collect_response_fields` took the width from.
            let fmsg = rust_lit_inner(tag);
            // The leaf's declared band, and its declared LENGTH — this path was given the
            // integer one and the byte one reached the two other content paths without reaching
            // here, so `child("blob")` over a `contentBytes(32)` leaf stored a vector of any
            // length. The length is gated on the decoded value being bytes, so a `contentUint`
            // fold into a `u64` is not asked for its `len()`. Each keeps its own message,
            // because a value out of range and a payload of the wrong length are not the same
            // report and the value they name is not the same expression.
            let band = leaf.and_then(|c| {
                if let Some(test) = super::fields::int_band(c, &id) {
                    return Some(format!(
                        "anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {id});"
                    ));
                }
                if wap::method_field_type(&c.method) != ParsedFieldType::Bytes {
                    return None;
                }
                let test = super::fields::byte_band(c, &id)?;
                Some(format!(
                    "anyhow::ensure!({test}, \"{fmsg} wrong length: {{}}\", {id}.len());"
                ))
            });
            // Same two sources as the declared type, or the initializer will not match it.
            if f.method == "maybeChild" || !f.required {
                match &band {
                    // Out of band is not absent, exactly as on the attribute path: the source
                    // accessor THROWS on a value outside its range, so folding it to `None`
                    // would take a response the parser rejects and leave the field simply
                    // missing.
                    Some(check) => {
                        lines.push(format!(
                            "{indent}let {id} = match {base}.get_optional_child({lit})"
                        ));
                        lines.push(format!("{indent}    .and_then(|n| n.{opt_read}) {{"));
                        lines.push(format!("{indent}    Some({id}) => {{"));
                        lines.push(format!("{indent}        {check}"));
                        lines.push(format!("{indent}        Some({id})"));
                        lines.push(format!("{indent}    }}"));
                        lines.push(format!("{indent}    None => None,"));
                        lines.push(format!("{indent}}};"));
                    }
                    None => {
                        lines.push(format!(
                            "{indent}let {id} = {base}.get_optional_child({lit})"
                        ));
                        lines.push(format!("{indent}    .and_then(|n| n.{opt_read});"));
                    }
                }
            } else {
                lines.push(format!(
                    "{indent}let {id}_node = {base}.get_optional_child({lit})"
                ));
                lines.push(format!(
                    "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
                    rust_lit_inner(tag)
                ));
                lines.push(format!("{indent}let {id} = {id}_node.{req_read};"));
                if let Some(check) = &band {
                    lines.push(format!("{indent}{check}"));
                }
            }
            inits.push(format!("{indent}    {id},"));
            continue;
        }

        let kids = children_of(f);
        if kids.is_empty() {
            continue;
        }

        if repeats(f) {
            // Repeated child → `Vec<Item>`. The Item carries this child's own attrs
            // and one level of repeated grandchild vecs (matching collect).
            let id = rust_ident(tag);
            if !seen.insert(id.clone()) {
                continue;
            }
            // Use `kids` as-is (no same-node flatten) so the Item's read set matches
            // what `collect_response_fields` puts in the `<Tag>Item` struct exactly.
            let item_attrs = dedup_attrs(kids);
            let nested_repeats: Vec<&ParsedField> = kids
                .iter()
                .filter(|n| is_child_field(n) && repeats(n) && !children_of(n).is_empty())
                .filter(|n| !dedup_attrs(children_of(n)).is_empty())
                .collect();
            let union_kids: Vec<&ParsedField> = kids
                .iter()
                .filter(|n| n.field_type == ParsedFieldType::Union)
                .collect();
            if item_attrs.is_empty() && nested_repeats.is_empty() && union_kids.is_empty() {
                seen.remove(&id);
                continue;
            }
            let struct_name = format!("{prefix}{}Item", pascal_case(tag));
            let vec_var = format!("{}_items", snake_case(tag));
            let loop_var = format!("{}_item", snake_case(tag));
            let inner = format!("{indent}    ");
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            lines.push(format!("{indent}let mut {vec_var} = Vec::new();"));
            lines.push(format!(
                "{indent}for {loop_var} in {base}.get_children_by_tag({}) {{",
                rust_lit(tag)
            ));
            for cf in &item_attrs {
                lines.extend(emit_field_parse(cf, &loop_var, &inner));
            }
            // `type=union` columns on the Item: read each off the item node (prefixed by
            // the Item struct so the generated enum/variant structs match collect).
            let mut union_init: Vec<String> = Vec::new();
            for uf in &union_kids {
                if let Some((ulines, uinit)) =
                    crate::union::emit_union_read(uf, &loop_var, &struct_name, &inner)
                {
                    lines.extend(ulines);
                    union_init.push(uinit);
                }
            }
            let mut nested_init: Vec<String> = Vec::new();
            for nf in &nested_repeats {
                let n_tag = tag_or_name(nf);
                // collect names the nested item `<prefix><Tag>Item` (spec-prefixed).
                let n_struct = format!("{prefix}{}Item", pascal_case(n_tag));
                let n_vec = format!("{}_items", snake_case(n_tag));
                let n_loop = format!("{}_item", snake_case(n_tag));
                let n_inner = format!("{inner}    ");
                let n_attrs = dedup_attrs(children_of(nf));
                let n_base = descend_from(
                    &loop_var,
                    nf.source_path.as_deref(),
                    wrapper_vars,
                    lines,
                    &inner,
                );
                lines.push(format!("{inner}let mut {n_vec} = Vec::new();"));
                lines.push(format!(
                    "{inner}for {n_loop} in {n_base}.get_children_by_tag({}) {{",
                    rust_lit(n_tag)
                ));
                for ncf in &n_attrs {
                    lines.extend(emit_field_parse(ncf, &n_loop, &n_inner));
                }
                lines.push(format!("{n_inner}{n_vec}.push({n_struct} {{"));
                for ncf in &n_attrs {
                    lines.push(format!("{n_inner}    {},", rust_ident(&ncf.name)));
                }
                lines.push(format!("{n_inner}    ..Default::default()"));
                lines.push(format!("{n_inner}}});"));
                lines.push(format!("{inner}}}"));
                nested_init.push(format!("{inner}    {}: {n_vec},", rust_ident(n_tag)));
            }
            lines.push(format!("{inner}{vec_var}.push({struct_name} {{"));
            for cf in &item_attrs {
                lines.push(format!("{inner}    {},", rust_ident(&cf.name)));
            }
            lines.extend(union_init);
            lines.extend(nested_init);
            lines.push(format!("{inner}    ..Default::default()"));
            lines.push(format!("{inner}}});"));
            lines.push(format!("{indent}}}"));
            inits.push(format!("{indent}    {id}: {vec_var},"));
        } else {
            // Non-repeated child → descend and flatten its fields into the current
            // struct, mirroring collect's single-child inlining. The descent is
            // emitted as a required (`?`) binding ONLY when the subtree actually reads
            // a field: a childless wrapper (e.g. a bare `<appeal_status/>` marker that
            // contributes nothing to the struct) would otherwise create a dead binding
            // whose required `ok_or_else` makes the whole parse fail whenever that
            // optional marker is simply absent. Decide via a scratch run over clones
            // (so a discarded subtree pollutes neither `seen` nor `wrapper_vars`), then
            // re-run against the real buffers to commit consistently.
            let cvar = rust_ident(tag);
            let mut scratch_lines: Vec<String> = Vec::new();
            let mut scratch_inits: Vec<String> = Vec::new();
            let mut scratch_seen = seen.clone();
            let mut scratch_vars = wrapper_vars.clone();
            emit_struct_reads(
                kids,
                &cvar,
                prefix,
                indent,
                &mut scratch_lines,
                &mut scratch_vars,
                &mut scratch_inits,
                &mut scratch_seen,
            );
            if scratch_inits.is_empty() {
                // Childless wrapper — descending would read nothing, so skip it
                // entirely rather than emit a dead, fragile required binding.
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            if f.required {
                // Required child: a missing `<tag>` is a parse error.
                lines.push(format!(
                    "{indent}let {cvar} = {base}.get_optional_child({})",
                    rust_lit(tag)
                ));
                lines.push(format!(
                    "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
                    rust_lit_inner(tag)
                ));
                emit_struct_reads(
                    kids,
                    &cvar,
                    prefix,
                    indent,
                    lines,
                    wrapper_vars,
                    inits,
                    seen,
                );
            } else {
                // Optional child (`optionalChildWithTag` in smax): when absent, its
                // fields default rather than failing the whole parse. Read the subtree
                // inside `if let Some(<tag>)` and bind every contributed field through a
                // tuple, defaulting each in the `else`. Field TYPES are unchanged (the
                // `else` defaults each element), so `collect_response_fields` needs no
                // weakening — required leaves INSIDE a present child still fail-fast.
                let inner = format!("{indent}    ");
                let mut body_lines: Vec<String> = Vec::new();
                let mut body_inits: Vec<String> = Vec::new();
                emit_struct_reads(
                    kids,
                    &cvar,
                    prefix,
                    &inner,
                    &mut body_lines,
                    wrapper_vars,
                    &mut body_inits,
                    seen,
                );
                // Map each init `name,` / `name: value,` to (outer binding, inner value).
                let pairs: Vec<(String, String)> = body_inits
                    .iter()
                    .map(|l| {
                        let t = l.trim().trim_end_matches(',');
                        match t.split_once(": ") {
                            Some((name, value)) => (name.to_string(), value.to_string()),
                            None => (t.to_string(), t.to_string()),
                        }
                    })
                    .collect();
                let names = pairs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
                let values = pairs.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
                let defaults = vec!["Default::default()".to_string(); pairs.len()];
                // A 1-tuple needs the trailing comma; >1 don't (and reads cleaner).
                let tuple = |items: &[String]| {
                    if items.len() == 1 {
                        format!("({},)", items[0])
                    } else {
                        format!("({})", items.join(", "))
                    }
                };
                lines.push(format!(
                    "{indent}let {} = if let Some({cvar}) = {base}.get_optional_child({}) {{",
                    tuple(&names),
                    rust_lit(tag)
                ));
                lines.extend(body_lines);
                lines.push(format!("{inner}{}", tuple(&values)));
                lines.push(format!("{indent}}} else {{"));
                lines.push(format!("{inner}{}", tuple(&defaults)));
                lines.push(format!("{indent}}};"));
                for n in names {
                    inits.push(format!("{indent}    {n},"));
                }
            }
        }
    }
}

/// Dedup attribute children by name, dropping `hasAttr`.
fn dedup_attrs(kids: &[ParsedField]) -> Vec<&ParsedField> {
    let mut seen = std::collections::HashSet::new();
    kids.iter()
        .filter(|f| is_attr_field(f) && f.method != "hasAttr")
        .filter(|f| seen.insert(f.name.clone()))
        .collect()
}

/// Accumulators threaded through [`emit_child_builder`] for a node's variant groups
/// (smax MixinGroup disjunctions): `enum_defs` collects the top-level `enum` types,
/// `fields` the `(struct_field, type, optional)` triples the spec struct must carry.
/// `spec_base` prefixes generated enum names so two specs don't collide.
pub(crate) struct VariantCtx<'a> {
    pub spec_base: &'a str,
    pub enum_defs: &'a mut Vec<String>,
    pub fields: &'a mut Vec<(String, String, bool)>,
}

/// Emit the `let <tag>_node = NodeBuilder::new("tag")…build();` statements for a
/// request child, recursing into nested children first. `used_names` dedups
/// repeated tags. Returns `(lines, var_name)` — the caller takes the returned
/// var name rather than reconstructing it from the shared counter (which is
/// bumped further by sibling/grandchild recursion).
///
/// The node is built through a rebindable `let mut` so optional attributes can be
/// added conditionally (`if let Some(v) = &self.x`), which a fluent chain can't.
/// A node's variant groups (mutually-exclusive MixinGroup alternatives) generate an
/// `enum` per group and a `match` in the build; see [`emit_variant_groups`].
pub(crate) fn emit_child_builder(
    child: &WapChildNode,
    indent: &str,
    used_names: &mut HashMap<String, usize>,
    ctx: &mut VariantCtx,
) -> (Vec<String>, String) {
    let mut lines: Vec<String> = Vec::new();
    let base_name = format!("{}_node", snake_case(&child.tag));
    let count = *used_names.get(&base_name).unwrap_or(&0);
    used_names.insert(base_name.clone(), count + 1);
    let var_name = if count == 0 {
        base_name.clone()
    } else {
        format!("{base_name}_{}", count + 1)
    };

    let mut nested_var_names: Vec<String> = Vec::new();
    for nested in &child.children {
        let (nested_lines, nested_var) = emit_child_builder(nested, indent, used_names, ctx);
        lines.extend(nested_lines);
        nested_var_names.push(nested_var);
    }

    // Collect the attr/children mutations; the node only needs `mut` if there's
    // at least one (otherwise `unused_mut` would warn in the consumer).
    let mut body: Vec<String> = Vec::new();
    for attr in &child.attrs {
        let alit = rust_lit(&attr.name);
        let ident = rust_ident(&attr.name);
        match &attr.kind {
            WapAttrKind::Const => {
                if let Some(value) = &attr.value {
                    body.push(format!(
                        "{indent}{var_name} = {var_name}.attr({alit}, {});",
                        rust_lit(value)
                    ));
                }
            }
            WapAttrKind::String | WapAttrKind::Dynamic => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, &*self.{ident});"
                ));
            }
            WapAttrKind::Integer => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, self.{ident}.to_string());"
                ));
            }
            k if is_jid_kind(k) => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, self.{ident}.clone());"
                ));
            }
            WapAttrKind::Optional => {
                body.push(format!(
                    "{indent}if let Some(v) = &self.{ident} {{ {var_name} = {var_name}.attr({alit}, v.as_str()); }}"
                ));
            }
            _ => {}
        }
    }
    body.extend(emit_variant_groups(child, &var_name, indent, ctx));
    body.extend(emit_node_content(child, &var_name, indent, ctx));
    if !nested_var_names.is_empty() {
        body.push(format!(
            "{indent}{var_name} = {var_name}.children([{}]);",
            nested_var_names.join(", ")
        ));
    }

    if body.is_empty() {
        lines.push(format!(
            "{indent}let {var_name} = NodeBuilder::new({}).build();",
            rust_lit(&child.tag)
        ));
    } else {
        lines.push(format!(
            "{indent}let mut {var_name} = NodeBuilder::new({});",
            rust_lit(&child.tag)
        ));
        lines.extend(body);
        lines.push(format!("{indent}let {var_name} = {var_name}.build();"));
    }
    (lines, var_name)
}

/// Emit, for each of a node's variant groups, a top-level `enum` (pushed to
/// `ctx.enum_defs`), a spec-struct field (pushed to `ctx.fields`), and the build
/// `match` that applies the chosen variant's attrs to `var_name`. A group is a smax
/// MixinGroup disjunction: exactly one variant applies (or none, when optional).
fn emit_variant_groups(
    node: &WapChildNode,
    var_name: &str,
    indent: &str,
    ctx: &mut VariantCtx,
) -> Vec<String> {
    let mut build = Vec::new();
    let multi = node.variant_groups.len() > 1;
    for (gi, group) in node.variant_groups.iter().enumerate() {
        let base = format!("{}{}", ctx.spec_base, pascal_case(&node.tag));
        let enum_name = if multi {
            format!("{base}Variant{}", gi + 1)
        } else {
            format!("{base}Variant")
        };
        let field = {
            let f = snake_case(&node.tag);
            if multi { format!("{f}_v{}", gi + 1) } else { f }
        };
        let disc = variant_discriminator(group);
        // Deduped variant names: when the discriminator can't tell variants apart
        // (e.g. six `<config>` alternatives that all lead with a dynamic `platform`
        // attr → all named `Platform`), suffix collisions so the enum has distinct
        // variants. Computed once and indexed by both the def and the match below so
        // the arm always names the same variant the def declared.
        let vnames = dedup_variant_names(group, disc.as_deref());

        // enum definition
        let mut def = vec![
            "#[derive(Debug, Clone)]".to_string(),
            format!("pub enum {enum_name} {{"),
        ];
        for (vi, v) in group.variants.iter().enumerate() {
            let vname = &vnames[vi];
            let payload: Vec<String> = v
                .attrs
                .iter()
                .filter(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
                .map(|a| {
                    format!(
                        "{}: {}",
                        rust_ident(&a.name),
                        crate::fields::rust_attr_type(&a.kind)
                    )
                })
                .collect();
            if payload.is_empty() {
                def.push(format!("    {vname},"));
            } else {
                def.push(format!("    {vname} {{ {} }},", payload.join(", ")));
            }
        }
        def.push("}".to_string());
        ctx.enum_defs.extend(def);
        ctx.enum_defs.push(String::new());

        let ty = if group.optional {
            format!("Option<{enum_name}>")
        } else {
            enum_name.clone()
        };
        ctx.fields.push((field.clone(), ty, group.optional));

        // build match
        let (matchee, inner_indent) = if group.optional {
            build.push(format!("{indent}if let Some(__v) = &self.{field} {{"));
            ("__v".to_string(), format!("{indent}    "))
        } else {
            (format!("&self.{field}"), indent.to_string())
        };
        build.push(format!("{inner_indent}match {matchee} {{"));
        for (vi, v) in group.variants.iter().enumerate() {
            let vname = &vnames[vi];
            build.extend(variant_arm(
                &enum_name,
                vname,
                v,
                var_name,
                &format!("{inner_indent}    "),
            ));
        }
        build.push(format!("{inner_indent}}}"));
        if group.optional {
            build.push(format!("{indent}}}"));
        }
    }
    build
}

/// Emit the leaf element content of a request node (`<value>`, `<signature>`, the
/// prekey `<link_code_pairing_nonce>`) — the byte payload the node carries between
/// its tags. Without this a key-material node builds empty and is unusable on the
/// wire. Two shapes, both `bytes`:
/// - a compile-time constant ([`WapContent::const_bytes`], e.g. the one-byte `00`
///   nonce) → a literal `.bytes(vec![0x00])`;
/// - a caller-supplied buffer (a bare `bytes` content, e.g. a prekey `signature`)
///   → a `Vec<u8>` spec field pushed to `ctx.fields` (mirroring
///   [`emit_variant_groups`]) and threaded in as `.bytes(self.<field>.clone())`.
///
/// The field name derives from the caller's collision-free `var_name` (`id_node` →
/// `id_content`, `id_node_2` → `id_content_2`) so repeated leaf tags across a
/// stanza (the three `<value>`/`<id>` nodes in a prekey `<skey>` tree) each get a
/// distinct field.
fn emit_node_content(
    child: &WapChildNode,
    var_name: &str,
    indent: &str,
    ctx: &mut VariantCtx,
) -> Vec<String> {
    let Some(content) = &child.content else {
        return Vec::new();
    };
    // A fixed byte constant: emit the literal buffer, no caller input needed. Handled
    // in isolation — a `const_bytes` that fails to decode degrades to no content, and
    // must never fall through to the caller-supplied-field branch below (that would
    // turn a fixed constant into an unwanted `Vec<u8>` builder argument).
    if let Some(hex) = &content.const_bytes {
        return decode_hex(hex)
            .map(|bytes| {
                let lits = bytes
                    .iter()
                    .map(|b| format!("0x{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![format!(
                    "{indent}{var_name} = {var_name}.bytes(vec![{lits}]);"
                )]
            })
            .unwrap_or_default();
    }
    // A caller-supplied byte buffer: thread a `Vec<u8>` spec field. Rename the
    // *terminal* `_node` segment (the var is `{tag}_node` or `{tag}_node_{n}`) so a
    // tag that itself contains `_node` isn't corrupted (`node_id_node` → `node_id_content`).
    if content.kind == WapContentKind::Bytes {
        let field = match var_name.rfind("_node") {
            Some(pos) => format!(
                "{}_content{}",
                &var_name[..pos],
                &var_name[pos + "_node".len()..]
            ),
            None => format!("{var_name}_content"),
        };
        ctx.fields
            .push((field.clone(), "Vec<u8>".to_string(), false));
        return vec![format!(
            "{indent}{var_name} = {var_name}.bytes(self.{field}.clone());"
        )];
    }
    Vec::new()
}

/// Decode an even-length hex string (`"00"`, `"0a1b"`) to its bytes. Returns `None`
/// for malformed input (odd length, non-ASCII, or a non-hex digit) so a bad
/// `const_bytes` degrades to no content rather than panicking codegen. The
/// `is_ascii` gate also keeps the byte-index slicing below on char boundaries.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// A const attr present in every variant of a group with DISTINCT values is the
/// discriminator (e.g. `type` = `jid`/`invite`); variants are named by its value.
fn variant_discriminator(group: &wa_ir::WapVariantGroup) -> Option<String> {
    let first = group.variants.first()?;
    'attr: for a in &first.attrs {
        if a.kind != WapAttrKind::Const {
            continue;
        }
        let mut values = Vec::new();
        for v in &group.variants {
            match v
                .attrs
                .iter()
                .find(|x| x.name == a.name && x.kind == WapAttrKind::Const)
            {
                Some(found) => values.push(found.value.clone().unwrap_or_default()),
                None => continue 'attr,
            }
        }
        // distinct across variants → a usable discriminator
        let mut sorted = values.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() == group.variants.len() {
            return Some(a.name.clone());
        }
    }
    None
}

/// Variant name: the discriminator value (`Jid`/`Invite`), else the first non-const
/// attr name (`Before`/`After`), else `VariantN`.
fn variant_name(v: &wa_ir::WapVariant, disc: Option<&str>, idx: usize) -> String {
    if let Some(d) = disc
        && let Some(a) = v.attrs.iter().find(|x| x.name == d)
        && let Some(val) = &a.value
    {
        return pascal_case(val);
    }
    if let Some(a) = v
        .attrs
        .iter()
        .find(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
    {
        return pascal_case(&a.name);
    }
    format!("Variant{}", idx + 1)
}

/// Variant names for a whole group, deduped: two alternatives that resolve to the
/// same [`variant_name`] (e.g. several `platform`-led `<config>` variants → all
/// `Platform`) would otherwise collide into one enum variant with mismatched fields.
/// The first keeps the base name; later collisions get a `2`/`3`/… suffix, stable in
/// declaration order so the def and the match agree.
fn dedup_variant_names(group: &wa_ir::WapVariantGroup, disc: Option<&str>) -> Vec<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(group.variants.len());
    for (vi, v) in group.variants.iter().enumerate() {
        let base = variant_name(v, disc, vi);
        let mut name = base.clone();
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}{n}");
            n += 1;
        }
        out.push(name);
    }
    out
}

/// One `match` arm: destructure the variant's non-const attrs and apply each attr
/// (const literal, bound dynamic, or optional) to the node `var_name`.
fn variant_arm(
    enum_name: &str,
    vname: &str,
    v: &wa_ir::WapVariant,
    var_name: &str,
    indent: &str,
) -> Vec<String> {
    let binds: Vec<String> = v
        .attrs
        .iter()
        .filter(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
        .map(|a| rust_ident(&a.name))
        .collect();
    let pat = if binds.is_empty() {
        format!("{enum_name}::{vname}")
    } else {
        format!("{enum_name}::{vname} {{ {} }}", binds.join(", "))
    };
    let mut lines = vec![format!("{indent}{pat} => {{")];
    let body_indent = format!("{indent}    ");
    for a in &v.attrs {
        let alit = rust_lit(&a.name);
        let ident = rust_ident(&a.name);
        match &a.kind {
            WapAttrKind::Const => {
                if let Some(value) = &a.value {
                    lines.push(format!(
                        "{body_indent}{var_name} = {var_name}.attr({alit}, {});",
                        rust_lit(value)
                    ));
                }
            }
            WapAttrKind::Optional => lines.push(format!(
                "{body_indent}if let Some(x) = {ident} {{ {var_name} = {var_name}.attr({alit}, x.as_str()); }}"
            )),
            WapAttrKind::Integer => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.to_string());"
            )),
            k if is_jid_kind(k) => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.clone());"
            )),
            WapAttrKind::String | WapAttrKind::Dynamic => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.as_str());"
            )),
            _ => {}
        }
    }
    lines.push(format!("{indent}}}"));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::collect_response_fields;
    use wa_ir::{WapAttrDef, WapChildNode};

    /// A bounded integer attribute, as `attrIntRange` records one.
    fn ranged(name: &str, lo: Option<i64>, hi: Option<i64>, required: bool) -> ParsedField {
        ParsedField {
            method: "attrIntRange".into(),
            name: name.into(),
            wire_name: Some(name.into()),
            field_type: ParsedFieldType::Integer,
            required,
            int_min: lo,
            int_max: hi,
            ..Default::default()
        }
    }

    #[test]
    fn a_bounded_integer_read_enforces_its_band() {
        // The accessor rejects a value outside its range, and this path decoded the number and
        // checked nothing — so `attrIntRange("weight", -10000, 10000)` took a `-20000` the source
        // turns away. Harmless while every integer was `u64`, because the parse itself refused
        // every negative value; signed, it is an over-acceptance. The union arm's selection guard
        // has applied the same band all along, and both read it from one place now.
        let src = emit_field_parse(&ranged("weight", Some(-10000), Some(10000), true), "n", "")
            .join("\n");
        assert!(
            src.contains("let weight: i64"),
            "signed by its range: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!((-10000i64..=10000i64).contains(&weight)"#),
            "and the band is enforced after decoding: {src}"
        );
    }

    #[test]
    fn a_bounded_content_read_enforces_its_band_as_well() {
        // The same accessor promise on the content path. A `contentInt` leaf declaring a range
        // decoded the number and checked nothing, and the moment its width could be signed a
        // `-20` materialized where the unsigned parse had been refusing every negative value by
        // accident. The union's content guard has tested this band all along — one rule spelled
        // in two places with one copy missing it, which is most of this branch's review.
        let mut f = ranged("weight", Some(-10), Some(10), true);
        f.method = "contentInt".into();
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("content_str()"),
            "still the content decoder: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!((-10i64..=10i64).contains(&weight)"#),
            "and the band is enforced after decoding: {src}"
        );
    }

    #[test]
    fn an_unbounded_content_read_checks_nothing_extra() {
        // The bound: a content leaf with no declared range is read exactly as before. The check
        // follows the band, not the accessor.
        let mut f = ranged("weight", None, None, true);
        f.method = "contentInt".into();
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            !src.contains("ensure!"),
            "nothing declared, nothing enforced: {src}"
        );
    }

    #[test]
    fn an_optional_bounded_integer_read_enforces_it_too() {
        // Out of band is not the same as absent: the source THROWS on a value outside the range,
        // so filtering it to `None` would accept a response the parser rejects, quietly and with
        // the field missing. Absent stays absent.
        let src = emit_field_parse(&ranged("weight", Some(0), Some(10), false), "n", "").join("\n");
        assert!(
            src.contains("None => None,"),
            "absence is still absence: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!(weight <= 10u64"#),
            "and a present value is checked: {src}"
        );
        assert!(
            !src.contains(">= 0u64"),
            "a floor no u64 can fail is not a check: {src}"
        );
    }

    #[test]
    fn an_unbounded_integer_read_checks_nothing_extra() {
        // The bounds. No declared band is nothing to enforce, and a bound no value of the emitted
        // width can fail says nothing either — a floor of zero on a `u64` is not a check, it is
        // noise the consumer's linter would flag. (A NEGATIVE floor is a different matter: it is
        // what makes the field signed, and then it constrains something.)
        for f in [
            ranged("count", None, None, true),
            ranged("count", Some(0), None, true),
        ] {
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(!src.contains("ensure!"), "nothing to enforce: {src}");
        }
    }

    fn attr(name: &str, kind: WapAttrKind, value: Option<&str>) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: value.map(|v| v.into()),
            required: false,
            enum_ref: None,
        }
    }
    fn leaf(tag: &str) -> WapChildNode {
        WapChildNode {
            tag: tag.into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
        }
    }

    /// Build a child node with a throwaway variant context (for the tests that don't
    /// exercise variant groups).
    fn build1(child: &WapChildNode) -> (Vec<String>, String) {
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        emit_child_builder(child, "", &mut HashMap::new(), &mut ctx)
    }

    #[test]
    fn variant_group_emits_enum_field_and_match() {
        use wa_ir::{WapVariant, WapVariantGroup};
        // `messages{count}` with a required query-params disjunction (jid/invite,
        // discriminated by `type`) and an optional directions disjunction.
        let node = WapChildNode {
            tag: "messages".into(),
            attrs: vec![attr("count", WapAttrKind::Integer, None)],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![
                WapVariantGroup {
                    optional: false,
                    variants: vec![
                        WapVariant {
                            attrs: vec![
                                attr("type", WapAttrKind::Const, Some("jid")),
                                attr("jid", WapAttrKind::UserJid, None),
                            ],
                            children: vec![],
                        },
                        WapVariant {
                            attrs: vec![
                                attr("type", WapAttrKind::Const, Some("invite")),
                                attr("key", WapAttrKind::String, None),
                            ],
                            children: vec![],
                        },
                    ],
                },
                WapVariantGroup {
                    optional: true,
                    variants: vec![
                        WapVariant {
                            attrs: vec![attr("before", WapAttrKind::Integer, None)],
                            children: vec![],
                        },
                        WapVariant {
                            attrs: vec![attr("after", WapAttrKind::Integer, None)],
                            children: vec![],
                        },
                    ],
                },
            ],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "Foo",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        let (lines, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx);
        let enum_src = enums.join("\n");
        let code = lines.join("\n");

        // Discriminated enum for the query-params group (named by `type`).
        assert!(
            enum_src.contains("pub enum FooMessagesVariant1 {"),
            "{enum_src}"
        );
        assert!(enum_src.contains("Jid { jid: Jid }"), "{enum_src}");
        assert!(enum_src.contains("Invite { key: String }"), "{enum_src}");
        // Directions group named by its distinguishing attr.
        assert!(
            enum_src.contains("pub enum FooMessagesVariant2 {"),
            "{enum_src}"
        );
        assert!(enum_src.contains("Before { before: u64 }"), "{enum_src}");

        // Spec fields: required enum + optional enum.
        assert!(
            fields
                .iter()
                .any(|(n, t, opt)| n == "messages_v1" && t == "FooMessagesVariant1" && !opt)
        );
        assert!(
            fields.iter().any(|(n, t, opt)| n == "messages_v2"
                && t == "Option<FooMessagesVariant2>"
                && *opt)
        );

        // Build match applies the const discriminator + bound payload.
        assert!(code.contains("match &self.messages_v1 {"), "{code}");
        assert!(
            code.contains("messages_node = messages_node.attr(\"type\", \"jid\");"),
            "{code}"
        );
        assert!(
            code.contains("messages_node = messages_node.attr(\"jid\", jid.clone());"),
            "{code}"
        );
        assert!(
            code.contains("if let Some(__v) = &self.messages_v2 {"),
            "{code}"
        );
    }

    #[test]
    fn same_named_variants_are_deduped() {
        use wa_ir::{WapVariant, WapVariantGroup};
        // Several `<config>` alternatives that all lead with a dynamic `platform` attr
        // resolve to the same `variant_name` (`Platform`); they must become distinct
        // enum variants (Platform / Platform2 / Platform3), and the build match must
        // name the same deduped variants so the generated code compiles.
        let mk = |extra: &str| WapVariant {
            attrs: vec![
                attr("platform", WapAttrKind::String, None),
                attr(extra, WapAttrKind::String, None),
            ],
            children: vec![],
        };
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![mk("appid"), mk("voip"), mk("endpoint")],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "Foo",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        let (lines, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx);
        let enum_src = enums.join("\n");
        // Three distinct variants, no duplicate `Platform`.
        assert_eq!(
            enum_src.matches("Platform").count(),
            3,
            "expected Platform/Platform2/Platform3:\n{enum_src}"
        );
        assert!(
            enum_src.contains("Platform {")
                && enum_src.contains("Platform2 {")
                && enum_src.contains("Platform3 {"),
            "{enum_src}"
        );
        // The match arms reference the same deduped names.
        let code = lines.join("\n");
        assert!(
            code.contains("Platform2 {") && code.contains("Platform3 {"),
            "{code}"
        );
    }

    #[test]
    fn source_path_attr_is_read_off_descended_wrapper() {
        // `protocol` carries sourcePath=["props"]: it lives on <props>, not the
        // <iq> root. The parser must descend the wrapper, and optional siblings
        // sharing the wrapper must read off it too, while a plain root attr stays
        // on `response`.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"attrString","name":"propsProtocol","wireName":"protocol","type":"string","required":true,"sourcePath":["props"]},
            {"method":"maybeAttrString","name":"propsHash","wireName":"hash","type":"string","required":false,"sourcePath":["props"]},
            {"method":"attrString","name":"type","wireName":"type","type":"string","required":true}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let props_wrap = response.get_optional_child(\"props\")"),
            "no <props> wrapper descent:\n{code}"
        );
        assert!(
            code.contains("let props_protocol = props_wrap.get_attr(\"protocol\")"),
            "required attr not read off the wrapper:\n{code}"
        );
        assert!(
            code.contains("let props_hash = props_wrap.get_attr(\"hash\")"),
            "optional sibling not read off the wrapper:\n{code}"
        );
        assert!(
            code.contains("response.get_attr(\"type\")"),
            "root attr should still read off response:\n{code}"
        );
    }

    #[test]
    fn source_path_child_is_read_off_descended_wrapper() {
        // A child with sourcePath=["detail"] (smax flattenedChildWithTag): the
        // <request> child lives under <detail>, not the <iq> root, and its attrs
        // are read off that descended child.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"detailRequest","tag":"request","type":"string","required":false,"sourcePath":["detail"],
             "children":[{"method":"attrString","name":"foo","wireName":"foo","type":"string","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let detail_wrap = response.get_optional_child(\"detail\")"),
            "{code}"
        );
        // The child is optional (`required:false`), so it reads inside `if let Some` —
        // but still off the descended <detail> wrapper, not the response root.
        assert!(
            code.contains("if let Some(request) = detail_wrap.get_optional_child(\"request\")"),
            "child not read off the <detail> wrapper:\n{code}"
        );
        assert!(
            !code.contains("response.get_optional_child(\"request\")"),
            "child STILL read off the response root:\n{code}"
        );
    }

    #[test]
    fn optional_child_defaults_when_absent_instead_of_failing() {
        // A `required:false` child (smax `optionalChildWithTag`) must not bail the whole
        // parse when absent: its fields read inside `if let Some` and default otherwise.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"suspended","tag":"suspended","type":"string","required":false,
             "children":[{"method":"attrInt","name":"value","wireName":"value","type":"integer","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("if let Some(suspended) = response.get_optional_child(\"suspended\")"),
            "optional child should read inside `if let Some`:\n{code}"
        );
        assert!(
            code.contains("} else {") && code.contains("(Default::default(),)"),
            "absent optional child should default its fields:\n{code}"
        );
        assert!(
            !code.contains(".ok_or_else(|| anyhow::anyhow!(\"missing <suspended>\"))"),
            "optional child must NOT bail when absent:\n{code}"
        );
    }

    #[test]
    fn required_child_still_bails_when_absent() {
        // A `required:true` child keeps the fail-fast descent.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"group","tag":"group","type":"string","required":true,
             "children":[{"method":"attrString","name":"id","wireName":"id","type":"string","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let group = response.get_optional_child(\"group\")")
                && code.contains(".ok_or_else(|| anyhow::anyhow!(\"missing <group>\"))?"),
            "required child must fail-fast when absent:\n{code}"
        );
    }

    #[test]
    fn nested_source_path_descends_each_segment() {
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"attrString","name":"nonceValue","wireName":"value","type":"string","required":true,"sourcePath":["detail","nonce"]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let detail_wrap = response.get_optional_child(\"detail\")"),
            "{code}"
        );
        assert!(
            code.contains("let detail_nonce_wrap = detail_wrap.get_optional_child(\"nonce\")"),
            "{code}"
        );
        assert!(
            code.contains("let nonce_value = detail_nonce_wrap.get_attr(\"value\")"),
            "{code}"
        );
    }

    #[test]
    fn optional_only_wrapper_is_still_descended() {
        // Every attr under <props> is optional → the wrapper node is still required
        // (smax `flattenedChildWithTag`), so it must be descended, not read off the
        // <iq> root (else the attrs would always parse as None).
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"maybeAttrString","name":"propsAbKey","wireName":"ab_key","type":"string","required":false,"sourcePath":["props"]},
            {"method":"maybeAttrString","name":"propsHash","wireName":"hash","type":"string","required":false,"sourcePath":["props"]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let props_wrap = response.get_optional_child(\"props\")"),
            "optional-only wrapper not descended:\n{code}"
        );
        assert!(
            code.contains("let props_ab_key = props_wrap.get_attr(\"ab_key\")"),
            "optional attr not read off the wrapper:\n{code}"
        );
        assert!(
            !code.contains("response.get_attr(\"ab_key\")"),
            "optional attr STILL read off the root:\n{code}"
        );
    }

    #[test]
    fn optional_same_node_wrapper_weakens_attr_children() {
        // `{displayNameMixin: m.success ? m.value : null}` → an OPTIONAL same-node
        // wrapper. When flattened the wrapper disappears, so its required attr child
        // must be weakened to an optional read (the wrapper may be absent).
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"","name":"displayNameMixin","type":"string","required":false,"sameNode":true,
             "children":[{"method":"attrString","name":"displayName","wireName":"display_name","type":"string","required":true}]}
        ]))
        .unwrap();
        // Struct field is Option<…>.
        let (struct_fields, _, _) = collect_response_fields(&fields, "Foo");
        let df = struct_fields
            .iter()
            .find(|f| f.name == "display_name")
            .expect("display_name field");
        assert_eq!(
            df.rust_type, "Option<String>",
            "weakened field should be Option"
        );
        // Parser reads it optionally (no `missing` error).
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let display_name = response.get_attr(\"display_name\").map("),
            "optional same_node child not read optionally:\n{code}"
        );
        assert!(
            !code.contains("missing display_name"),
            "optional same_node child still read as required:\n{code}"
        );
    }

    #[test]
    fn optional_request_attr_is_emitted_conditionally() {
        let child = WapChildNode {
            tag: "query".into(),
            attrs: vec![
                attr("opt", WapAttrKind::Optional, None),
                attr("xmlns", WapAttrKind::Const, Some("w:x")),
            ],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, var) = build1(&child);
        let code = lines.join("\n");
        assert_eq!(var, "query_node");
        assert!(code.contains("let mut query_node = NodeBuilder::new(\"query\");"));
        assert!(
            code.contains(
                "if let Some(v) = &self.opt { query_node = query_node.attr(\"opt\", v.as_str()); }"
            ),
            "{code}"
        );
        assert!(code.contains("query_node = query_node.attr(\"xmlns\", \"w:x\");"));
        assert!(code.contains("let query_node = query_node.build();"));
    }

    #[test]
    fn empty_node_avoids_unused_mut() {
        let (lines, _) = build1(&leaf("ping"));
        let code = lines.join("\n");
        assert!(code.contains("let ping_node = NodeBuilder::new(\"ping\").build();"));
        assert!(!code.contains("let mut ping_node"));
    }

    #[test]
    fn same_tag_nested_siblings_get_distinct_var_names() {
        let parent = WapChildNode {
            tag: "list".into(),
            attrs: vec![],
            children: vec![leaf("item"), leaf("item")],
            content: None,
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, _) = build1(&parent);
        let code = lines.join("\n");
        assert!(code.contains("let item_node = NodeBuilder::new(\"item\").build();"));
        assert!(code.contains("let item_node_2 = NodeBuilder::new(\"item\").build();"));
        // Both wired into the parent in order — the bug reconstructed wrong names here.
        assert!(
            code.contains("list_node = list_node.children([item_node, item_node_2]);"),
            "{code}"
        );
    }

    #[test]
    fn const_bytes_content_emits_literal_byte_buffer() {
        use wa_ir::{WapContent, WapContentKind};
        // The one-byte `00` link-code pairing nonce: a compile-time constant, so the
        // builder writes the literal buffer directly (no caller input). Previously the
        // node was built empty, making the request unusable on the wire.
        let node = WapChildNode {
            tag: "link_code_pairing_nonce".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(1),
                const_bytes: Some("00".into()),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, _) = build1(&node);
        let code = lines.join("\n");
        assert!(
            code.contains(
                "link_code_pairing_nonce_node = link_code_pairing_nonce_node.bytes(vec![0x00]);"
            ),
            "{code}"
        );
    }

    #[test]
    fn dynamic_bytes_content_threads_a_vec_u8_spec_field() {
        use wa_ir::{WapContent, WapContentKind};
        // A prekey `<signature>` carries caller-supplied key material, so the builder
        // threads a `Vec<u8>` spec field named after the (collision-free) var and
        // writes it as the node content.
        let node = WapChildNode {
            tag: "signature".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(64),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        let (lines, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx);
        let code = lines.join("\n");
        assert!(
            code.contains("signature_node = signature_node.bytes(self.signature_content.clone());"),
            "{code}"
        );
        assert_eq!(
            fields,
            vec![(
                "signature_content".to_string(),
                "Vec<u8>".to_string(),
                false
            )]
        );
    }

    #[test]
    fn dynamic_content_field_renames_only_the_terminal_node_segment() {
        use wa_ir::{WapContent, WapContentKind};
        // A tag whose own name contains `_node` must not corrupt the field name: the
        // var `node_id_node` yields `node_id_content`, not `node_content_node`.
        let node = WapChildNode {
            tag: "node_id".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(8),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx);
        assert_eq!(fields[0].0, "node_id_content");
    }

    #[test]
    fn malformed_const_bytes_emits_nothing_and_adds_no_field() {
        use wa_ir::{WapContent, WapContentKind};
        // A `const_bytes` that can't be decoded degrades to no content — it must not
        // fall through and be turned into a caller-supplied `Vec<u8>` field.
        let node = WapChildNode {
            tag: "nonce".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                const_bytes: Some("zz".into()), // not hex
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
        };
        let (lines, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx);
        assert!(fields.is_empty(), "no spec field for a malformed constant");
        assert!(
            !lines.join("\n").contains(".bytes("),
            "no content emitted for a malformed constant"
        );
    }

    /// A `child("weight")` whose only body is a bounded `contentInt` leaf.
    fn child_over(leaf: ParsedField, required: bool) -> ParsedField {
        ParsedField {
            method: if required { "child" } else { "maybeChild" }.into(),
            name: "weight".into(),
            wire_name: Some("weight".into()),
            required,
            children: Some(vec![leaf]),
            ..Default::default()
        }
    }

    fn bounded_leaf(lo: Option<i64>, hi: Option<i64>) -> ParsedField {
        let mut leaf = ranged("weight", lo, hi, true);
        leaf.method = "contentInt".into();
        leaf
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_band() {
        // A child collapsed to its content leaf is emitted HERE, not through
        // `emit_field_parse`, so the band the other two paths apply reached neither shape: a
        // `contentInt` leaf bounded to `-10..=10` parsed a `-20` straight into the field. The
        // band is the leaf's, which is also where the declared width comes from.
        for required in [true, false] {
            let src = emit_struct_parser(
                &[child_over(bounded_leaf(Some(-10), Some(10)), required)],
                "n",
                "R",
                "",
                "P",
            )
            .join("\n");
            assert!(
                src.contains(
                    r#"anyhow::ensure!((-10i64..=10i64).contains(&weight), "weight out of range"#
                ),
                "the leaf's band is enforced (required={required}): {src}"
            );
        }
    }

    #[test]
    fn an_out_of_band_flattened_child_content_value_is_an_error_not_an_absence() {
        // The optional shape keeps absence and rejection apart: the source accessor THROWS on a
        // value outside its range, so mapping it to `None` would accept a response the parser
        // turns away and leave the field quietly missing.
        let src = emit_struct_parser(
            &[child_over(bounded_leaf(Some(-10), Some(10)), false)],
            "n",
            "R",
            "",
            "P",
        )
        .join("\n");
        assert!(
            src.contains("Some(weight) => {") && src.contains("None => None,"),
            "absent stays absent, out of band errors: {src}"
        );
    }

    #[test]
    fn an_unbounded_flattened_child_content_read_is_emitted_exactly_as_before() {
        // The paired bound: with nothing declared there is no band, and both shapes read as
        // they always have — no `ensure!`, and the optional one is still the plain `and_then`
        // rather than a `match` with one arm.
        for (required, expected) in [
            (true, "let weight = weight_node.content_str()"),
            (
                false,
                "    .and_then(|n| n.content_str().and_then(|s| s.parse().ok()));",
            ),
        ] {
            let src = emit_struct_parser(
                &[child_over(bounded_leaf(None, None), required)],
                "n",
                "R",
                "",
                "P",
            )
            .join("\n");
            assert!(
                !src.contains("ensure!"),
                "nothing declared, nothing enforced (required={required}): {src}"
            );
            assert!(
                src.contains(expected),
                "and the read is untouched (required={required}): {src}"
            );
        }
    }

    #[test]
    fn a_length_pinned_content_read_enforces_it() {
        // `contentBytes(32)` and `contentBytesRange(1, 128)` both record what the accessor will
        // accept, and this path decoded the payload and checked nothing — so the generated
        // parser took a body of any length. The union's leaf guard has checked it all along;
        // one rule, two places, one copy missing it, on the byte side this time.
        for (method, len, lo, hi, want) in [
            (
                "contentBytes",
                Some(32),
                None,
                None,
                "element_value.len() == 32",
            ),
            (
                "contentBytesRange",
                None,
                Some(1),
                Some(128),
                "(1..=128).contains(&element_value.len())",
            ),
            (
                "contentBytesRange",
                None,
                Some(4),
                None,
                "element_value.len() >= 4",
            ),
        ] {
            let f = ParsedField {
                method: method.into(),
                name: "elementValue".into(),
                wire_name: Some("elementValue".into()),
                field_type: ParsedFieldType::Bytes,
                required: true,
                byte_length: len,
                byte_min: lo,
                byte_max: hi,
                ..Default::default()
            };
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(
                src.contains(&format!(
                    "anyhow::ensure!({want}, \"elementValue wrong length"
                )),
                "the declared length is enforced: {src}"
            );
        }
    }

    #[test]
    fn a_content_read_with_no_pinned_length_checks_nothing_extra() {
        // The paired bound, both ways it matters. Nothing declared means nothing enforced — and
        // `contentUint(N)` declares a byte length but folds those bytes into a `u64`, which has
        // no `len()`, so asking the classifier rather than the metadata is what keeps the two
        // apart instead of emitting code that does not compile.
        for (method, len) in [("contentBytes", None), ("contentUint", Some(8))] {
            let f = ParsedField {
                method: method.into(),
                name: "elementValue".into(),
                wire_name: Some("elementValue".into()),
                required: true,
                byte_length: len,
                ..Default::default()
            };
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(
                !src.contains("wrong length"),
                "no length check here ({method}): {src}"
            );
        }
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_length() {
        // The third site for the byte band, and the last: this path was given the INTEGER band
        // five rounds ago and the byte one reached the attribute read and the ordinary content
        // read without reaching here, so `child("blob")` over a `contentBytes(32)` leaf stored
        // a vector of any length in both shapes.
        for required in [true, false] {
            let mut leaf = ranged("blob", None, None, true);
            leaf.method = "contentBytes".into();
            leaf.byte_length = Some(32);
            let src =
                emit_struct_parser(&[child_over(leaf, required)], "n", "R", "", "P").join("\n");
            assert!(
                src.contains(r#"anyhow::ensure!(weight.len() == 32, "weight wrong length"#),
                "the leaf's length is enforced (required={required}): {src}"
            );
        }
    }

    #[test]
    fn a_flattened_child_content_read_asks_the_classifier_for_its_length() {
        // The bound, and it is the one that stops this emitting code that does not compile:
        // `contentUint(N)` records a byte length too and folds those bytes into a `u64`, which
        // has no `len()`. Nothing declared is nothing enforced, as before.
        for (method, len) in [("contentUint", Some(8)), ("contentBytes", None)] {
            let mut leaf = ranged("blob", None, None, true);
            leaf.method = method.into();
            leaf.byte_length = len;
            let src = emit_struct_parser(&[child_over(leaf, true)], "n", "R", "", "P").join("\n");
            assert!(
                !src.contains("wrong length"),
                "no length check here ({method}): {src}"
            );
        }
    }
}
