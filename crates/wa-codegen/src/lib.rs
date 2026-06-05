//! IR -> Rust source generation: emits `IqSpec` impls (request builders + response
//! parsers) from the IQ IR, in the shape `wacore` expects (`InfoQuery`,
//! `NodeBuilder`, `wacore_binary::node::Node`). Generated files are committed
//! artifacts, regenerated when the IR changes.

mod abprops_export;
mod appstate_export;
mod emit;
mod enums_export;
mod fields;
mod mex_export;
mod mex_ids;
mod naming;
mod spec;

pub use abprops_export::generate_abprops;
pub use appstate_export::generate_appstate_schemas;
pub use enums_export::generate_enums;
pub use mex_export::generate_mex_operations;
pub use mex_ids::{MexIdRefresh, refresh_mex_ids};

use std::collections::HashSet;

use wa_ir::{IqIr, IqStanzaDef, IqTarget};

use fields::{RustChildStruct, collect_response_fields};
use naming::{rust_lit, snake_case};
use spec::{generate_spec, spec_base_name};

/// A generated Rust source file.
pub struct GeneratedModule {
    pub filename: String,
    pub module_name: String,
    pub code: String,
}

/// Generate one Rust module per IQ namespace from the IQ IR.
pub fn generate_rust_modules(ir: &IqIr) -> Vec<GeneratedModule> {
    // Group stanzas by namespace, preserving first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<&IqStanzaDef>> =
        std::collections::HashMap::new();
    for stanza in &ir.stanzas {
        if !groups.contains_key(&stanza.namespace) {
            order.push(stanza.namespace.clone());
        }
        groups
            .entry(stanza.namespace.clone())
            .or_default()
            .push(stanza);
    }

    let mut modules = Vec::new();
    for namespace in &order {
        let operations = &groups[namespace];
        let module_name = snake_case(namespace);
        let ns_const = format!("{}_NAMESPACE", snake_case(namespace).to_uppercase());

        let mut module_names: Vec<&str> = Vec::new();
        let mut seen_mods = HashSet::new();
        for o in operations {
            if seen_mods.insert(o.module_name.as_str()) {
                module_names.push(&o.module_name);
            }
        }

        let needs_node_builder = operations.iter().any(|o| !o.request.children.is_empty());
        let needs_server_jid = operations
            .iter()
            .any(|o| !matches!(o.target, IqTarget::Group));

        let mut lines: Vec<String> = Vec::new();
        lines.push(format!(
            "//! Auto-generated IQ stanza specs for namespace `{namespace}`."
        ));
        lines.push("//!".to_string());
        lines.push(format!(
            "//! Source WA Web modules: {}",
            module_names.join(", ")
        ));
        lines.push("//! Generated from the IQ IR by wa-codegen.".to_string());
        lines.push("//!".to_string());
        lines.push("//! **DO NOT EDIT MANUALLY** — regenerate with the whatspec CLI.".to_string());
        lines.push(String::new());

        lines.push("use crate::iq::spec::IqSpec;".to_string());
        lines.push("use crate::request::InfoQuery;".to_string());
        if needs_node_builder {
            lines.push("use wacore_binary::builder::NodeBuilder;".to_string());
        }
        let jid_imports = if needs_server_jid {
            "Jid, SERVER_JID"
        } else {
            "Jid"
        };
        lines.push(format!("use wacore_binary::jid::{{{jid_imports}}};"));
        lines.push("use wacore_binary::node::{Node, NodeContent};".to_string());
        lines.push(String::new());

        lines.push("/// IQ namespace.".to_string());
        lines.push(format!(
            "pub const {ns_const}: &str = {};",
            rust_lit(namespace)
        ));
        lines.push(String::new());

        // Shared child item structs (deduped across the namespace's specs).
        let mut all_child_structs: Vec<RustChildStruct> = Vec::new();
        for op in operations {
            if op.response.fields.is_empty() {
                continue;
            }
            let (_, mut child_structs) = collect_response_fields(&op.response.fields);
            for cs in &mut child_structs {
                let mut seen = HashSet::new();
                cs.fields.retain(|f| seen.insert(f.name.clone()));
            }
            for cs in child_structs {
                match all_child_structs.iter_mut().find(|e| e.name == cs.name) {
                    None => all_child_structs.push(cs),
                    // Keep the superset when the same struct shows up with more fields.
                    Some(existing) if cs.fields.len() > existing.fields.len() => *existing = cs,
                    _ => {}
                }
            }
        }

        if !all_child_structs.is_empty() {
            lines.push(
                "// ─── Shared child types ──────────────────────────────────────────────────────"
                    .to_string(),
            );
            lines.push(String::new());
            for cs in &all_child_structs {
                lines.push("/// Child item struct.".to_string());
                lines.push("#[derive(Debug, Clone, Default)]".to_string());
                lines.push(format!("pub struct {} {{", cs.name));
                for f in &cs.fields {
                    lines.push(format!("    pub {}: {},", f.name, f.rust_type));
                }
                lines.push("}".to_string());
                lines.push(String::new());
            }
        }

        lines.push(
            "// ─── IQ Specs ───────────────────────────────────────────────────────────────"
                .to_string(),
        );
        lines.push(String::new());
        // Disambiguate struct names within the namespace deterministically: the
        // same module often emits several `("iq", …)` variants that derive the
        // same base name. Identical specs (same name + same code) are emitted
        // once; genuinely different specs sharing a name get a stable numeric
        // suffix in scan order, so the output stays byte-stable across runs.
        let mut used_names: HashSet<String> = HashSet::new();
        let mut emitted_code: HashSet<String> = HashSet::new();
        for op in operations {
            let base = spec_base_name(op);
            // First, generate with the base name to detect exact duplicates.
            let base_code = generate_spec(op, &ns_const, &base);
            if used_names.contains(&base) {
                if emitted_code.contains(&base_code) {
                    // Identical spec already emitted — skip the duplicate entirely.
                    continue;
                }
                // Same name, different spec → find the next free numeric suffix.
                let mut n = 2;
                let unique = loop {
                    let candidate = format!("{}{n}Spec", base.trim_end_matches("Spec"));
                    if !used_names.contains(&candidate) {
                        break candidate;
                    }
                    n += 1;
                };
                let code = generate_spec(op, &ns_const, &unique);
                used_names.insert(unique);
                emitted_code.insert(code.clone());
                lines.push(code);
            } else {
                used_names.insert(base);
                emitted_code.insert(base_code.clone());
                lines.push(base_code);
            }
            lines.push(String::new());
        }

        modules.push(GeneratedModule {
            filename: format!("{module_name}.rs"),
            module_name,
            code: lines.join("\n"),
        });
    }

    modules
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{
        IqRequestDef, IqType, ParsedField, ParsedFieldType, ParsedResponse, WapAttrDef,
        WapAttrKind, WapChildNode,
    };

    fn attr(name: &str, kind: WapAttrKind) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: None,
            required: true,
        }
    }

    fn parsed(method: &str, name: &str, ty: ParsedFieldType) -> ParsedField {
        ParsedField {
            method: method.into(),
            name: name.into(),
            field_type: ty,
            required: true,
            byte_length: None,
            enum_keys: None,
            tag: None,
            children: None,
            repeats: None,
            content_type: None,
        }
    }

    #[test]
    fn content_wrapper_children_become_tag_named_fields() {
        // `child("headline").contentString()` + `child("body").contentString()`
        // must yield distinct `headline`/`body` String fields, NOT one collapsed
        // `content`.
        let content_child = |tag: &str| {
            let mut c = parsed("child", tag, ParsedFieldType::String);
            c.tag = Some(tag.into());
            c.children = Some(vec![parsed(
                "contentString",
                "content",
                ParsedFieldType::String,
            )]);
            c
        };
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebTitle".into(),
                namespace: "fb:thrift_iq".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                parser_name: "p".into(),
                exported_function: Some("title".into()),
                all_exports: vec!["title".into()],
                request: IqRequestDef {
                    namespace: "fb:thrift_iq".into(),
                    iq_type: IqType::Get,
                    target: IqTarget::Server,
                    children: vec![],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![content_child("headline"), content_child("body")],
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_rust_modules(&ir)[0].code;
        assert!(c.contains("pub headline: String,"), "headline field");
        assert!(c.contains("pub body: String,"), "body field");
        assert!(
            !c.contains("pub content: String,"),
            "must not collapse to `content`"
        );
        assert!(c.contains("let headline_node = required_child(response, \"headline\")?;"));
        assert!(c.contains("let body = match &body_node.content"));
    }

    #[test]
    fn generates_spec_with_request_and_response() {
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebTestJob".into(),
                namespace: "w:test".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                parser_name: "p".into(),
                exported_function: Some("queryTest".into()),
                all_exports: vec!["queryTest".into()],
                request: IqRequestDef {
                    namespace: "w:test".into(),
                    iq_type: IqType::Get,
                    target: IqTarget::Server,
                    children: vec![WapChildNode {
                        tag: "query".into(),
                        attrs: vec![
                            attr("jid", WapAttrKind::UserJid),
                            attr("limit", WapAttrKind::Integer),
                        ],
                        children: vec![],
                        repeats: false,
                    }],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![parsed("attrString", "status", ParsedFieldType::String)],
                },
            }],
            unparseable: vec![],
        };

        let modules = generate_rust_modules(&ir);
        assert_eq!(modules.len(), 1);
        let m = &modules[0];
        assert_eq!(m.filename, "w_test.rs");

        let c = &m.code;
        assert!(c.contains("pub const W_TEST_NAMESPACE: &str = \"w:test\";"));
        assert!(c.contains("pub struct QueryTestSpec {"));
        assert!(c.contains("pub jid: Jid,"));
        assert!(c.contains("pub limit: u64,"));
        assert!(c.contains("pub fn new(jid: &Jid, limit: u64) -> Self {"));
        assert!(c.contains("impl IqSpec for QueryTestSpec {"));
        assert!(c.contains("fn build_iq(&self) -> InfoQuery<'static> {"));
        assert!(c.contains("NodeBuilder::new(\"query\")"));
        assert!(c.contains(".attr(\"jid\", self.jid.clone())"));
        assert!(c.contains(".attr(\"limit\", self.limit.to_string())"));
        assert!(c.contains("InfoQuery::get("));
        assert!(c.contains("pub struct QueryTestResponse {"));
        assert!(c.contains("pub status: String,"));
        assert!(c.contains("let status = optional_attr(response, \"status\")"));
    }

    #[test]
    fn maybe_attr_enum_generates_optional_field() {
        // Regression: `maybeAttrEnum` used to be unhandled, forcing a spurious
        // `Response = ()` fallback. It must behave like `maybeAttrString`.
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebModeJob".into(),
                namespace: "w:mode".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                parser_name: "p".into(),
                exported_function: Some("queryMode".into()),
                all_exports: vec!["queryMode".into()],
                request: IqRequestDef {
                    namespace: "w:mode".into(),
                    iq_type: IqType::Get,
                    target: IqTarget::Server,
                    children: vec![],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![parsed("maybeAttrEnum", "mode", ParsedFieldType::String)],
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_rust_modules(&ir)[0].code;
        assert!(c.contains("pub mode: Option<String>,"), "field type");
        assert!(
            c.contains("let mode = optional_attr(response, \"mode\").map(|s| s.to_string());"),
            "parse line"
        );
        assert!(
            !c.contains("type Response = ();"),
            "must not fall back to unit"
        );
    }

    #[test]
    fn confirmation_spec_has_unit_response() {
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebAck".into(),
                namespace: "w:x".into(),
                iq_type: IqType::Set,
                target: IqTarget::Group,
                parser_name: "p".into(),
                exported_function: None,
                all_exports: vec![],
                request: IqRequestDef {
                    namespace: "w:x".into(),
                    iq_type: IqType::Set,
                    target: IqTarget::Group,
                    children: vec![],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![],
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_rust_modules(&ir)[0].code;
        assert!(c.contains("pub struct AckSpec;")); // no fields → unit struct
        assert!(c.contains("type Response = ();"));
        assert!(c.contains("InfoQuery::set(W_X_NAMESPACE, Jid::new(\"\", \"g.us\"), None)"));
        assert!(c.contains("Ok(())"));
    }
}
