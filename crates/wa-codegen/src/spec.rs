//! Generate one `IqSpec` impl (struct + constructor + response + build/parse).

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use wa_ir::{IqStanzaDef, IqTarget, IqType, WapAttrKind, WapChildNode};

use crate::emit::{emit_child_builder, emit_response_parser};
use crate::fields::{collect_response_fields, rust_attr_type};
use crate::naming::{pascal_case, rust_ident};

fn iq_type_str(t: IqType) -> &'static str {
    match t {
        IqType::Get => "get",
        IqType::Set => "set",
    }
}

static LET_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet (type|fn|loop|match|mod|pub|use|struct|impl|trait|enum)\b").unwrap()
});
static INIT_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\w+),").unwrap());
static LET_BINDING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\blet\s+(mut\s+)?(\w+)\b").unwrap());

/// Generate the Rust source for a single IQ stanza's spec.
/// The base (pre-dedup) `…Spec` struct name for an op: from its exported
/// function, falling back to the module name. The caller is responsible for
/// disambiguating collisions within a namespace (see [`generate_spec`]).
pub(crate) fn spec_base_name(op: &IqStanzaDef) -> String {
    let base = match &op.exported_function {
        // Skip `default` and the minifier's `$N` locals (e.g. usync's `$3`,
        // upload-prekeys' `$4`) — neither is a usable name; fall back to the
        // module name (`WAWebUsync` → `Usync`).
        Some(e) if e != "default" && !e.starts_with('$') => e.clone(),
        _ => op
            .module_name
            .strip_prefix("WAWeb")
            .unwrap_or(&op.module_name)
            .to_string(),
    };
    format!("{}Spec", pascal_case(&base))
}

/// Generate one `IqSpec` impl. `spec_name` is the (possibly disambiguated) struct
/// name chosen by the caller, so two ops in the same namespace never collide.
pub(crate) fn generate_spec(op: &IqStanzaDef, ns_const: &str, spec_name: &str) -> String {
    let mut lines: Vec<String> = Vec::new();

    let is_confirmation = op.response.fields.is_empty();
    let iq = iq_type_str(op.iq_type);

    // Spec fields from request-children attrs (skip const + generated id).
    let mut spec_fields: Vec<(String, &'static str, WapAttrKind)> = Vec::new();
    let mut seen_spec = HashSet::new();
    collect_attrs(&op.request.children, &mut spec_fields, &mut seen_spec);

    // ── Spec struct ──
    let doc_owner = op.exported_function.as_deref().unwrap_or(&op.namespace);
    lines.push(format!("/// {doc_owner}:{iq} IQ spec."));
    lines.push("///".to_string());
    lines.push(format!("/// Source: `{}`", op.module_name));
    if !spec_fields.is_empty() {
        lines.push("#[derive(Debug, Clone)]".to_string());
        lines.push(format!("pub struct {spec_name} {{"));
        for (name, ty, _) in &spec_fields {
            lines.push(format!("    pub {name}: {ty},"));
        }
        lines.push("}".to_string());
    } else {
        lines.push("#[derive(Debug, Clone, Default)]".to_string());
        lines.push(format!("pub struct {spec_name};"));
    }
    lines.push(String::new());

    // ── Constructor ──
    if !spec_fields.is_empty() {
        lines.push(format!("impl {spec_name} {{"));
        let params = spec_fields
            .iter()
            .map(|(name, ty, _)| match *ty {
                "String" => format!("{name}: impl Into<String>"),
                "Jid" => format!("{name}: &Jid"),
                _ => format!("{name}: {ty}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("    pub fn new({params}) -> Self {{"));
        lines.push("        Self {".to_string());
        for (name, ty, _) in &spec_fields {
            match *ty {
                "String" => lines.push(format!("            {name}: {name}.into(),")),
                "Jid" => lines.push(format!("            {name}: {name}.clone(),")),
                _ => lines.push(format!("            {name},")),
            }
        }
        lines.push("        }".to_string());
        lines.push("    }".to_string());
        lines.push("}".to_string());
        lines.push(String::new());
    }

    // ── Response type ──
    let mut response_type_name: String;
    if is_confirmation {
        response_type_name = "()".to_string();
    } else {
        let (mut top_fields, _) = collect_response_fields(&op.response.fields);
        let mut seen = HashSet::new();
        top_fields.retain(|f| seen.insert(f.name.clone()));
        if top_fields.is_empty() {
            response_type_name = "()".to_string();
        } else {
            response_type_name = format!("{}Response", spec_name.trim_end_matches("Spec"));
            lines.push(format!("/// Response from {doc_owner}:{iq}."));
            lines.push("#[derive(Debug, Clone, Default)]".to_string());
            lines.push(format!("pub struct {response_type_name} {{"));
            for f in &top_fields {
                lines.push(format!("    pub {}: {},", f.name, f.rust_type));
            }
            lines.push("}".to_string());
            lines.push(String::new());
        }
    }
    let effectively_confirmation = response_type_name == "()";

    // ── IqSpec impl ──
    lines.push(format!("impl IqSpec for {spec_name} {{"));
    lines.push(format!("    type Response = {response_type_name};"));
    lines.push(String::new());

    // build_iq
    lines.push("    fn build_iq(&self) -> InfoQuery<'static> {".to_string());
    let target = if matches!(op.target, IqTarget::Group) {
        "Jid::new(\"\", Server::Group)"
    } else {
        "Jid::new(\"\", Server::Pn)"
    };
    if !op.request.children.is_empty() {
        let mut top_var_names: Vec<String> = Vec::new();
        let mut used_names = std::collections::HashMap::new();
        for child in &op.request.children {
            let (child_lines, child_var) = emit_child_builder(child, "        ", &mut used_names);
            lines.extend(child_lines);
            top_var_names.push(child_var);
        }
        lines.push(String::new());
        lines.push(format!("        InfoQuery::{iq}("));
        lines.push(format!("            {ns_const},"));
        lines.push(format!("            {target},"));
        lines.push(format!(
            "            Some(NodeContent::Nodes(vec![{}])),",
            top_var_names.join(", ")
        ));
        lines.push("        )".to_string());
    } else {
        lines.push(format!(
            "        InfoQuery::{iq}({ns_const}, {target}, None)"
        ));
    }
    lines.push("    }".to_string());
    lines.push(String::new());

    // parse_response — validate the parser can produce all struct fields.
    let mut can_generate = !effectively_confirmation;
    if can_generate {
        let (check_fields, check_child_structs) = collect_response_fields(&op.response.fields);
        let names: Vec<&str> = check_fields.iter().map(|f| f.name.as_str()).collect();
        if names.iter().collect::<HashSet<_>>().len() != names.len() {
            can_generate = false;
        }
        if can_generate {
            let parser_code =
                emit_response_parser(&op.response.fields, &response_type_name, "        ")
                    .join("\n");
            for f in &check_fields {
                if !parser_code.contains(&format!("{},", f.name))
                    && !parser_code.contains(&format!("{}:", f.name))
                {
                    can_generate = false;
                    break;
                }
            }
            if can_generate && LET_KEYWORD.is_match(&parser_code) {
                can_generate = false;
            }
            if can_generate {
                'outer: for cs in &check_child_structs {
                    let required: HashSet<&str> =
                        cs.fields.iter().map(|f| f.name.as_str()).collect();
                    for body in struct_init_bodies(&parser_code, &cs.name) {
                        let inited: HashSet<&str> = INIT_FIELD
                            .captures_iter(body)
                            .map(|c| c.get(1).unwrap().as_str())
                            .collect();
                        if !required.iter().all(|r| inited.contains(r)) {
                            can_generate = false;
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // Fall back to () if the parser can't be generated cleanly.
    if !can_generate && !effectively_confirmation {
        let marker = format!("/// Response from {doc_owner}:{iq}.");
        if let Some(start) = lines.iter().rposition(|l| *l == marker) {
            let mut end = start;
            while end < lines.len() && lines[end] != "}" {
                end += 1;
            }
            let remove_to = (end + 2).min(lines.len());
            lines.drain(start..remove_to);
        }
        response_type_name = "()".to_string();
        if let Some(idx) = lines.iter().position(|l| l.contains("type Response =")) {
            lines[idx] = "    type Response = ();".to_string();
        }
    }

    let resp_param = if effectively_confirmation || response_type_name == "()" {
        "_response"
    } else {
        "response"
    };
    if effectively_confirmation || response_type_name == "()" {
        lines.push(format!(
            "    fn parse_response(&self, {resp_param}: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {{"
        ));
        lines.push("        Ok(())".to_string());
    } else {
        lines.push("    #[allow(clippy::needless_update, unused_variables)]".to_string());
        lines.push(format!(
            "    fn parse_response(&self, {resp_param}: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {{"
        ));
        lines.extend(emit_response_parser(
            &op.response.fields,
            &response_type_name,
            "        ",
        ));
    }
    lines.push("    }".to_string());
    lines.push("}".to_string());

    fix_unused_vars(lines.join("\n"))
}

fn collect_attrs(
    children: &[WapChildNode],
    out: &mut Vec<(String, &'static str, WapAttrKind)>,
    seen: &mut HashSet<String>,
) {
    for child in children {
        for attr in &child.attrs {
            if !matches!(attr.kind, WapAttrKind::Const | WapAttrKind::GeneratedId) {
                let ident = rust_ident(&attr.name);
                if seen.insert(ident.clone()) {
                    out.push((ident, rust_attr_type(&attr.kind), attr.kind.clone()));
                }
            }
        }
        collect_attrs(&child.children, out, seen);
    }
}

/// Prefix single-use `let` bindings with `_` to silence unused-variable lints.
fn fix_unused_vars(mut code: String) -> String {
    let vars: Vec<String> = LET_BINDING
        .captures_iter(&code)
        .filter_map(|c| c.get(2).map(|m| m.as_str().to_string()))
        .collect();
    for var in vars {
        if var.starts_with('_') {
            continue;
        }
        // A whole-code occurrence count of 1 means the name appears only in its
        // own `let` binding (and no superstring contains it), so a single literal
        // replacement of that binding is exact — no regex needed.
        if code.matches(&var).count() <= 1 {
            let with_mut = format!("let mut {var}");
            if code.contains(&with_mut) {
                code = code.replacen(&with_mut, &format!("let mut _{var}"), 1);
            } else {
                code = code.replacen(&format!("let {var}"), &format!("let _{var}"), 1);
            }
        }
    }
    code
}

/// Bodies of `name { ... }` struct-init blocks in `code` (everything between each
/// `name`-prefixed `{` and the next `}`). Mirrors the old `(?s)name\s*\{([^}]*)\}`
/// scan without compiling a per-name regex.
fn struct_init_bodies<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find(name) {
        let after = from + rel + name.len();
        let rest = &code[after..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('{') {
            from = after;
            continue;
        }
        let body_start = after + (rest.len() - trimmed.len()) + 1;
        match code[body_start..].find('}') {
            Some(end_rel) => {
                out.push(&code[body_start..body_start + end_rel]);
                from = body_start + end_rel + 1;
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{IqRequestDef, ParsedResponse};

    fn stanza(module: &str, exported: Option<&str>) -> IqStanzaDef {
        IqStanzaDef {
            module_name: module.into(),
            namespace: "w:test".into(),
            iq_type: IqType::Get,
            target: IqTarget::Server,
            parser_name: "p".into(),
            exported_function: exported.map(str::to_string),
            all_exports: vec![],
            request: IqRequestDef {
                namespace: "w:test".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                children: vec![],
            },
            response: ParsedResponse {
                parser_name: "unknown".into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn spec_base_name_falls_back_to_module_for_minified_exports() {
        // A real exported name is used as-is.
        assert_eq!(
            spec_base_name(&stanza("WAWebGetThing", Some("queryThing"))),
            "QueryThingSpec"
        );
        // Minifier `$N` locals (usync `$3`, upload-prekeys `$4`) and `default`
        // fall back to the module name (sans the `WAWeb` prefix).
        assert_eq!(
            spec_base_name(&stanza("WAWebUsync", Some("$3"))),
            "UsyncSpec"
        );
        assert_eq!(
            spec_base_name(&stanza("WAWebUploadPrekeysForRegTask", Some("$4"))),
            "UploadPrekeysForRegTaskSpec"
        );
        assert_eq!(
            spec_base_name(&stanza("WAWebFoo", Some("default"))),
            "FooSpec"
        );
    }

    #[test]
    fn struct_init_bodies_extracts_each_block() {
        let code = "EntryItem {\n    a,\n    b,\n}\nnoise EntryItem { c }";
        let bodies = struct_init_bodies(code, "EntryItem");
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("a,") && bodies[0].contains("b,"));
        assert_eq!(bodies[1].trim(), "c");
    }

    #[test]
    fn struct_init_bodies_ignores_name_not_followed_by_brace() {
        assert!(struct_init_bodies("let EntryItem = 1;", "EntryItem").is_empty());
    }

    #[test]
    fn fix_unused_vars_underscores_single_use_bindings() {
        // `x` is used; `y`/`z` are not.
        let code = "let x = 1;\nlet mut y = Vec::new();\nlet z = foo();\nuse_it(x);".to_string();
        let out = fix_unused_vars(code);
        assert!(out.contains("let x = 1;"), "used binding untouched");
        assert!(
            out.contains("let mut _y = Vec::new();"),
            "unused mut binding"
        );
        assert!(out.contains("let _z = foo();"), "unused binding");
    }
}
