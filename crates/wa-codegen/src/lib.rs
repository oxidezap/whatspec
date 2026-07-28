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
mod notif_export;
mod spec;
mod stanza_export;
mod tokens_export;
mod union;
mod wam;

pub use abprops_export::generate_abprops;
pub use appstate_export::generate_appstate_schemas;
pub use enums_export::generate_enums;
pub use mex_export::generate_mex_operations;
pub use mex_ids::{MexIdRefresh, refresh_mex_ids};
pub use notif_export::generate_notif;
pub use stanza_export::generate_stanza;
pub use tokens_export::generate_tokens_json;
pub use wam::generate_wam;

use std::collections::HashSet;

use wa_ir::{IqIr, IqStanzaDef};

use fields::{RustChildStruct, RustEnum, collect_response_fields, emit_enum_def};
use naming::{rust_lit, snake_case};
use spec::{generate_spec, op_uses_outcome_union, spec_base_name};

/// Generate the single reference Rust file from the IQ IR: one `pub mod` per IQ
/// namespace (the namespace const, shared child types, and one `IqSpec` impl per
/// stanza), in the shape `wacore` expects. Mirrors how every other domain emits a
/// single `.rs`; consumers do one `include!`/`mod` instead of a 30-file tree.
pub fn generate_iq(ir: &IqIr) -> String {
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

    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated IQ stanza specs (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One `pub mod` per IQ namespace; each holds the namespace const, shared child\n\
         //! types, and one `IqSpec` impl per stanza. Regenerated from the IQ IR by wa-codegen.\n\n\
         // A generated catalog: a consumer uses a subset (so unused specs/types are\n\
         // expected), and nested wrapper vars use a `base__path_wrap` convention.\n\
         #![allow(clippy::all, dead_code, non_snake_case)]\n\n",
        ir.wa_version
    ));

    for namespace in &order {
        let operations = &groups[namespace];
        let module_name = snake_case(namespace);

        // Source WA Web modules, for the per-namespace doc comment.
        let mut module_names: Vec<&str> = Vec::new();
        let mut seen_mods = HashSet::new();
        for o in operations {
            if seen_mods.insert(o.module_name.as_str()) {
                module_names.push(&o.module_name);
            }
        }
        out.push_str(&format!(
            "/// IQ namespace `{namespace}`. Source: {}.\n",
            module_names.join(", ")
        ));
        out.push_str(&format!("pub mod {module_name} {{\n"));
        // Indent each body line one level into the module (blank lines stay empty).
        for line in namespace_body(namespace, operations).join("\n").split('\n') {
            if line.is_empty() {
                out.push('\n');
            } else {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str("}\n\n");
    }

    out
}

/// The body of one namespace module: imports, the namespace const, shared child
/// structs, and the `IqSpec` impls. Returned unindented (the caller nests it).
fn namespace_body(namespace: &str, operations: &[&IqStanzaDef]) -> Vec<String> {
    let ns_const = format!("{}_NAMESPACE", snake_case(namespace).to_uppercase());

    let needs_node_builder = operations.iter().any(|o| !o.request.children.is_empty());

    let mut lines: Vec<String> = Vec::new();
    lines.push("use crate::iq::spec::IqSpec;".to_string());
    lines.push("use crate::request::InfoQuery;".to_string());
    if needs_node_builder {
        // `NodeBuilder` + `NodeContent::Nodes` are only used when a request has
        // child nodes. Response parsing goes through `NodeRef`'s own methods.
        lines.push("use wacore_binary::builder::NodeBuilder;".to_string());
        lines.push("use wacore_binary::node::NodeContent;".to_string());
    }
    // Every `build_iq` targets `Jid::new("", Server::{Pn,Group})`.
    lines.push("use wacore_binary::jid::{Jid, Server};".to_string());
    lines.push(String::new());

    lines.push("/// IQ namespace.".to_string());
    lines.push(format!(
        "pub const {ns_const}: &str = {};",
        rust_lit(namespace)
    ));
    lines.push(String::new());

    // Resolve each spec's final (collision-free) name and code first. Disambiguate
    // deterministically: the same module often emits several `("iq", …)` variants
    // that derive the same base name. Identical specs (same name + same code) are
    // emitted once; genuinely different specs sharing a name get a stable numeric
    // suffix in scan order. The final name is also the prefix for that spec's child
    // item structs, so the struct definitions (below) and the parser references
    // (inside `code`) line up.
    let mut used_names: HashSet<String> = HashSet::new();
    let mut emitted_code: HashSet<String> = HashSet::new();
    let mut resolved: Vec<(&IqStanzaDef, String, String)> = Vec::new();
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
            used_names.insert(unique.clone());
            emitted_code.insert(code.clone());
            resolved.push((op, unique, code));
        } else {
            used_names.insert(base.clone());
            emitted_code.insert(base_code.clone());
            resolved.push((op, base, base_code));
        }
    }

    // Shared child item structs, named `<SpecBase><Tag>Item` so two specs in this
    // namespace can carry same-tagged children with incompatible shapes. Names are
    // unique per spec now, so the dedup only collapses byte-identical specs.
    let mut all_child_structs: Vec<RustChildStruct> = Vec::new();
    let mut all_enums: Vec<RustEnum> = Vec::new();
    for (op, spec_name, _) in &resolved {
        let prefix = spec_name.trim_end_matches("Spec");
        // A true outcome-union op emits its per-variant structs/enums inline in
        // `generate_spec`; collecting the primary-mirror types here would be dead. But
        // an op that CARRIES variants yet falls back to the single-shape struct (the
        // outcome wasn't separable) emits from `response.fields` — so it still needs
        // its child structs/enums at module level.
        if op.response.fields.is_empty() || op_uses_outcome_union(op, prefix) {
            continue;
        }
        let (_, mut child_structs, enums) = collect_response_fields(&op.response.fields, prefix);
        for cs in &mut child_structs {
            let mut seen = HashSet::new();
            cs.fields.retain(|f| seen.insert(f.name.clone()));
        }
        for cs in child_structs {
            match all_child_structs.iter_mut().find(|e| e.name == cs.name) {
                None => all_child_structs.push(cs),
                // Names are unique per spec now, so a collision means byte-identical
                // structs. As a defensive tie-break, keep whichever carries more
                // fields (a field-count heuristic, not a true superset check).
                Some(existing) if cs.fields.len() > existing.fields.len() => *existing = cs,
                _ => {}
            }
        }
        for e in enums {
            // Enum names are spec-prefixed; a collision means a byte-identical enum.
            if !all_enums.iter().any(|x| x.name == e.name) {
                all_enums.push(e);
            }
        }
    }

    if !all_child_structs.is_empty() || !all_enums.is_empty() {
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
        for e in &all_enums {
            lines.extend(emit_enum_def(e));
        }
    }

    lines.push(
        "// ─── IQ Specs ───────────────────────────────────────────────────────────────"
            .to_string(),
    );
    lines.push(String::new());
    for (_, _, code) in &resolved {
        lines.push(code.clone());
        lines.push(String::new());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{
        IqRequestDef, IqTarget, IqType, ParsedField, ParsedFieldType, ParsedResponse, WapAttrDef,
        WapAttrKind, WapChildNode,
    };

    fn attr(name: &str, kind: WapAttrKind) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: None,
            required: true,
            enum_ref: None,
        }
    }

    fn parsed(method: &str, name: &str, ty: ParsedFieldType) -> ParsedField {
        ParsedField {
            method: method.into(),
            name: name.into(),
            field_type: ty,
            required: true,
            ..Default::default()
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
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_iq(&ir);
        assert!(c.contains("pub mod fb_thrift_iq {"), "namespace module");
        assert!(c.contains("pub headline: String,"), "headline field");
        assert!(c.contains("pub body: String,"), "body field");
        assert!(
            !c.contains("pub content: String,"),
            "must not collapse to `content`"
        );
        assert!(c.contains("let headline_node = response.get_optional_child(\"headline\")"));
        assert!(c.contains(".ok_or_else(|| anyhow::anyhow!(\"missing <headline>\"))?;"));
        assert!(c.contains("let body = body_node.content_str().unwrap_or_default().to_string();"));
    }

    #[test]
    fn integer_content_children_get_their_own_named_fields() {
        // Two things were wrong at once, and the second hid the first: the codegen's
        // content predicate admitted only three spellings, so live `contentUint` fields
        // were dropped and the generated Rust came out unchanged — which read as "nothing
        // broke". Once they arrived, every one of them was named `content` and collapsed
        // into a single field, so two of three values were still lost.
        let uint_child = |tag: &str| {
            let mut c = parsed("child", tag, ParsedFieldType::String);
            c.tag = Some(tag.into());
            c.children = Some(vec![parsed(
                "contentUint",
                "content",
                ParsedFieldType::Integer,
            )]);
            c
        };
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebDigest".into(),
                namespace: "encrypt".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                parser_name: "p".into(),
                exported_function: Some("digest".into()),
                all_exports: vec!["digest".into()],
                request: IqRequestDef {
                    namespace: "encrypt".into(),
                    iq_type: IqType::Get,
                    target: IqTarget::Server,
                    children: vec![],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![uint_child("registration"), uint_child("id")],
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_iq(&ir);
        assert!(c.contains("pub registration: u64,"), "registration field");
        assert!(c.contains("pub id: u64,"), "id field");
        assert!(
            !c.contains("pub content: u64,"),
            "must not collapse both onto `content`"
        );
        // The accessor reads N big-endian bytes, not decimal text — a 3-byte prekey id,
        // a 4-byte registration id. Parsing that as a string makes every one silently 0.
        assert!(
            c.contains("content_bytes()") && c.contains("(acc << 8) | x as u64"),
            "and the value is decoded big-endian:\n{c}"
        );
    }

    #[test]
    fn a_ranged_byte_content_child_is_still_bytes() {
        // `child("blob").contentBytesRange(1, 128)` decodes to bytes. Asking the
        // classifier for the integer branch while testing the exact name `contentBytes`
        // for the bytes branch — in one expression — typed this as `String` and read it
        // with `content_str()`, so a byte payload came out as lossy text.
        let mut blob = parsed("child", "blob", ParsedFieldType::String);
        blob.tag = Some("blob".into());
        blob.children = Some(vec![parsed(
            "contentBytesRange",
            "content",
            ParsedFieldType::Bytes,
        )]);
        let ir = IqIr {
            wa_version: "0.0.0".into(),
            stanzas: vec![IqStanzaDef {
                module_name: "WAWebBlob".into(),
                namespace: "encrypt".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                parser_name: "p".into(),
                exported_function: Some("blob".into()),
                all_exports: vec!["blob".into()],
                request: IqRequestDef {
                    namespace: "encrypt".into(),
                    iq_type: IqType::Get,
                    target: IqTarget::Server,
                    children: vec![],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![blob],
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_iq(&ir);
        assert!(c.contains("pub blob: Vec<u8>,"), "typed as bytes:\n{c}");
        assert!(
            c.contains("blob_node.content_bytes()"),
            "and read as bytes:\n{c}"
        );
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
                        content: None,
                        repeats: false,
                        variant_groups: vec![],
                    }],
                },
                response: ParsedResponse {
                    parser_name: "p".into(),
                    assertions: vec![],
                    fields: vec![parsed("attrString", "status", ParsedFieldType::String)],
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };

        let c = &generate_iq(&ir);
        // One `pub mod` per namespace, named by the snake_cased namespace.
        assert!(c.contains("pub mod w_test {"));
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
        // Parses against the real wacore API: `&NodeRef` + `get_attr`/`as_str`.
        assert!(c.contains(
            "fn parse_response(&self, response: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {"
        ));
        assert!(c.contains("let status = response.get_attr(\"status\")"));
        assert!(c.contains(".as_str()"));
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
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_iq(&ir);
        assert!(c.contains("pub mode: Option<String>,"), "field type");
        assert!(
            c.contains("let mode = response.get_attr(\"mode\").map(|v| v.as_str().to_string());"),
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
                    ..Default::default()
                },
            }],
            unparseable: vec![],
        };
        let c = &generate_iq(&ir);
        assert!(c.contains("pub struct AckSpec;")); // no fields → unit struct
        assert!(c.contains("type Response = ();"));
        assert!(c.contains("InfoQuery::set(W_X_NAMESPACE, Jid::new(\"\", Server::Group), None)"));
        assert!(c.contains("Ok(())"));
    }

    #[test]
    fn generated_iq_rs_is_valid_rust() {
        // The generated IQ module compiles into no crate in this workspace (it targets
        // wacore downstream), so nothing here would catch a codegen change that emits
        // syntactically-broken Rust. Generate from the committed reference IR and
        // syntax-check the whole file (resolution/types aren't checked — syn only
        // parses — but every brace/expr/enum/match must be well-formed).
        let ir_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/iq/index.json");
        let json =
            std::fs::read_to_string(ir_path).unwrap_or_else(|e| panic!("read {ir_path}: {e}"));
        let ir: wa_ir::IqIr = serde_json::from_str(&json).expect("deserialize committed IqIr");
        let code = generate_iq(&ir);
        syn::parse_file(&code)
            .unwrap_or_else(|e| panic!("generated iq.rs is not valid Rust ({e})"));
    }

    #[test]
    fn generated_notif_rs_is_valid_rust() {
        // Same guard as IQ: the notif catalog compiles into no crate here, so
        // syntax-check the whole generated file against the committed reference IR.
        // Skips when the notif IR isn't committed yet (it lands on the next real
        // `update`); the synthetic-IR check in `notif_export` always runs.
        let ir_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../generated/notif/index.json"
        );
        let Ok(json) = std::fs::read_to_string(ir_path) else {
            eprintln!("skip: {ir_path} not committed yet");
            return;
        };
        let ir: wa_ir::NotifIr =
            serde_json::from_str(&json).expect("deserialize committed NotifIr");
        let code = generate_notif(&ir);
        syn::parse_file(&code)
            .unwrap_or_else(|e| panic!("generated notif.rs is not valid Rust ({e})"));
    }
}
