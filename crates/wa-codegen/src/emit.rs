//! Emit Rust source fragments: response parsers and request builders.

use std::collections::HashMap;

use wa_ir::wap;
use wa_ir::{ParsedField, ParsedFieldType, WapAttrKind, WapChildNode};

use crate::fields::{
    child_content_type, collect_response_fields, is_attr_field, is_child_field, is_jid_kind,
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
    let flit = rust_lit(&f.name);
    let fmsg = rust_lit_inner(&f.name);
    let method = f.method.as_str();

    if method == wap::CONTENT_BYTES {
        return vec![format!(
            "{indent}let {name} = match &{node_var}.content {{ Some(NodeContent::Bytes(b)) => b.clone(), _ => vec![] }};"
        )];
    }
    if method == wap::CONTENT_STRING {
        return vec![format!(
            "{indent}let {name} = match &{node_var}.content {{ Some(NodeContent::String(s)) => s.clone(), _ => String::new() }};"
        )];
    }
    if !wap::is_attr_method(method) {
        return Vec::new();
    }

    let optional = wap::is_optional_method(method);
    match wap::method_field_type(method) {
        ParsedFieldType::Integer if optional => vec![format!(
            "{indent}let {name} = optional_attr({node_var}, {flit}).and_then(|s| s.parse().ok());"
        )],
        ParsedFieldType::Integer => vec![
            format!("{indent}let {name}: u64 = optional_attr({node_var}, {flit})"),
            format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
            format!("{indent}    .parse()?;"),
        ],
        ParsedFieldType::DeviceJid
        | ParsedFieldType::GroupJid
        | ParsedFieldType::JidTyped
        | ParsedFieldType::Jid => vec![format!(
            "{indent}let {name} = crate::iq::node::required_jid({node_var}, {flit})?;"
        )],
        _ if optional => vec![format!(
            "{indent}let {name} = optional_attr({node_var}, {flit}).map(|s| s.to_string());"
        )],
        _ => vec![
            format!("{indent}let {name} = optional_attr({node_var}, {flit})"),
            format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
            format!("{indent}    .to_string();"),
        ],
    }
}

/// Emit the body of `parse_response`, ending with `Ok(<ResponseType> {{ ... }})`.
pub(crate) fn emit_response_parser(
    fields: &[ParsedField],
    response_type_name: &str,
    indent: &str,
) -> Vec<String> {
    // lines[0] is reserved for the deferred `use` import, lines[1] is a blank.
    let mut lines: Vec<String> = vec![String::new(), String::new()];

    let (struct_fields, _) = collect_response_fields(fields);
    let struct_field_names: std::collections::HashSet<String> =
        struct_fields.iter().map(|f| f.name.clone()).collect();

    let top_attrs: Vec<&ParsedField> = fields
        .iter()
        .filter(|f| is_attr_field(f) && f.method != "hasAttr")
        .collect();
    let child_fields: Vec<&ParsedField> = fields.iter().filter(|f| is_child_field(f)).collect();

    for f in &top_attrs {
        if !struct_field_names.contains(&rust_ident(&f.name)) {
            continue;
        }
        lines.extend(emit_field_parse(f, "response", indent));
    }

    let mut init_fields: Vec<String> = Vec::new();
    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut add_init = |line: String, key: String| {
        if emitted.insert(key) {
            init_fields.push(line);
        }
    };

    for f in &top_attrs {
        add_init(
            format!("{indent}    {},", rust_ident(&f.name)),
            rust_ident(&f.name),
        );
    }

    for child in &child_fields {
        let child_tag = tag_or_name(child);
        let child_var = rust_ident(child_tag);
        let child_lit = rust_lit(child_tag);
        let kids = children_of(child);

        // Leaf child/maybeChild with contentType, OR a `child("x").contentString()`
        // wrapper → a single `x` field read off the child node's content.
        if let Some(ct) = child.content_type.or_else(|| child_content_type(child)) {
            let field_name = rust_ident(child_tag);
            let bytes = ct == wa_ir::ContentType::Bytes;
            if child.method == "maybeChild" {
                lines.push(format!(
                    "{indent}let {field_name} = response.get_optional_child({child_lit})"
                ));
                if bytes {
                    lines.push(format!("{indent}    .and_then(|n| match &n.content {{ Some(NodeContent::Bytes(b)) => Some(b.clone()), _ => None }});"));
                } else {
                    lines.push(format!("{indent}    .and_then(|n| match &n.content {{ Some(NodeContent::String(s)) => Some(s.clone()), _ => None }});"));
                }
            } else {
                lines.push(format!(
                    "{indent}let {field_name}_node = required_child(response, {child_lit})?;"
                ));
                if bytes {
                    lines.push(format!("{indent}let {field_name} = match &{field_name}_node.content {{ Some(NodeContent::Bytes(b)) => b.clone(), _ => vec![] }};"));
                } else {
                    lines.push(format!("{indent}let {field_name} = match &{field_name}_node.content {{ Some(NodeContent::String(s)) => s.clone(), _ => String::new() }};"));
                }
            }
            add_init(format!("{indent}    {field_name},"), field_name);
            continue;
        }
        if kids.is_empty() {
            continue;
        }

        let has_parseable =
            kids.iter().any(is_attr_field) || kids.iter().any(|f| is_child_field(f) && repeats(f));
        if !has_parseable {
            continue;
        }

        if child.method == "child" {
            lines.push(format!(
                "{indent}let {child_var} = required_child(response, {child_lit})?;"
            ));
            let child_attrs: Vec<&ParsedField> = kids
                .iter()
                .filter(|f| is_attr_field(f) && f.method != "hasAttr")
                .collect();
            let child_nested: Vec<&ParsedField> =
                kids.iter().filter(|f| is_child_field(f)).collect();

            for cf in &child_attrs {
                lines.extend(emit_field_parse(cf, &child_var, indent));
                add_init(
                    format!("{indent}    {},", rust_ident(&cf.name)),
                    rust_ident(&cf.name),
                );
            }

            for nf in &child_nested {
                if !repeats(nf) || children_of(nf).is_empty() {
                    continue;
                }
                let n_tag = tag_or_name(nf);
                let n_struct = format!("{}Item", pascal_case(n_tag));
                let n_vec = format!("{}_items", snake_case(n_tag));

                lines.push(format!("{indent}let mut {n_vec} = Vec::new();"));
                lines.push(format!(
                    "{indent}for child in {child_var}.get_children_by_tag({}) {{",
                    rust_lit(n_tag)
                ));

                let n_attrs = dedup_attrs(children_of(nf));
                for ncf in &n_attrs {
                    lines.extend(emit_field_parse(ncf, "child", &format!("{indent}    ")));
                }
                lines.push(format!("{indent}    {n_vec}.push({n_struct} {{"));
                for ncf in &n_attrs {
                    lines.push(format!("{indent}        {},", rust_ident(&ncf.name)));
                }
                lines.push(format!("{indent}        ..Default::default()"));
                lines.push(format!("{indent}    }});"));
                lines.push(format!("{indent}}}"));
                add_init(
                    format!("{indent}    {}: {n_vec},", rust_ident(n_tag)),
                    rust_ident(n_tag),
                );
            }
        } else if repeats(child) {
            let struct_name = format!("{}Item", pascal_case(child_tag));
            let vec_var = format!("{}_items", snake_case(child_tag));

            lines.push(format!("{indent}let mut {vec_var} = Vec::new();"));
            lines.push(format!(
                "{indent}for child in response.get_children_by_tag({child_lit}) {{"
            ));

            let child_attrs = dedup_attrs(kids);
            for cf in &child_attrs {
                lines.extend(emit_field_parse(cf, "child", &format!("{indent}    ")));
            }
            lines.push(format!("{indent}    {vec_var}.push({struct_name} {{"));
            for cf in &child_attrs {
                lines.push(format!("{indent}        {},", rust_ident(&cf.name)));
            }
            lines.push(format!("{indent}        ..Default::default()"));
            lines.push(format!("{indent}    }});"));
            lines.push(format!("{indent}}}"));
            add_init(
                format!("{indent}    {}: {vec_var},", rust_ident(child_tag)),
                rust_ident(child_tag),
            );
        }
    }

    lines.push(format!("{indent}Ok({response_type_name} {{"));
    lines.extend(init_fields);
    lines.push(format!("{indent}    ..Default::default()"));
    lines.push(format!("{indent}}})"));

    // Resolve the deferred import from what was actually emitted.
    let code = lines.join("\n");
    let mut imports: Vec<&str> = Vec::new();
    if code.contains("required_child(") {
        imports.push("required_child");
    }
    if code.contains("optional_attr(") {
        imports.push("optional_attr");
    }
    lines[0] = if imports.is_empty() {
        String::new()
    } else {
        format!("{indent}use crate::iq::node::{{{}}};", imports.join(", "))
    };

    lines
}

/// Dedup attribute children by name, dropping `hasAttr`.
fn dedup_attrs(kids: &[ParsedField]) -> Vec<&ParsedField> {
    let mut seen = std::collections::HashSet::new();
    kids.iter()
        .filter(|f| is_attr_field(f) && f.method != "hasAttr")
        .filter(|f| seen.insert(f.name.clone()))
        .collect()
}

/// Emit the `let <tag>_node = NodeBuilder::new("tag")…build();` statements for a
/// request child, recursing into nested children first. `used_names` dedups
/// repeated tags. Returns `(lines, var_name)` — the caller takes the returned
/// var name rather than reconstructing it from the shared counter (which is
/// bumped further by sibling/grandchild recursion).
///
/// The node is built through a rebindable `let mut` so optional attributes can be
/// added conditionally (`if let Some(v) = &self.x`), which a fluent chain can't.
pub(crate) fn emit_child_builder(
    child: &WapChildNode,
    indent: &str,
    used_names: &mut HashMap<String, usize>,
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
        let (nested_lines, nested_var) = emit_child_builder(nested, indent, used_names);
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

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{WapAttrDef, WapChildNode};

    fn attr(name: &str, kind: WapAttrKind, value: Option<&str>) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: value.map(|v| v.into()),
            required: false,
        }
    }
    fn leaf(tag: &str) -> WapChildNode {
        WapChildNode {
            tag: tag.into(),
            attrs: vec![],
            children: vec![],
            repeats: false,
        }
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
            repeats: false,
        };
        let (lines, var) = emit_child_builder(&child, "", &mut HashMap::new());
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
        let (lines, _) = emit_child_builder(&leaf("ping"), "", &mut HashMap::new());
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
            repeats: false,
        };
        let (lines, _) = emit_child_builder(&parent, "", &mut HashMap::new());
        let code = lines.join("\n");
        assert!(code.contains("let item_node = NodeBuilder::new(\"item\").build();"));
        assert!(code.contains("let item_node_2 = NodeBuilder::new(\"item\").build();"));
        // Both wired into the parent in order — the bug reconstructed wrong names here.
        assert!(
            code.contains("list_node = list_node.children([item_node, item_node_2]);"),
            "{code}"
        );
    }
}
