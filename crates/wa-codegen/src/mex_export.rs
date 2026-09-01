//! Generate self-contained, fully-typed Rust for every mex operation from the
//! mex IR (`variablesShape` / `response` type trees).
//!
//! One `pub mod <op>` per operation, each with a `Variables` + `Response` struct
//! (nested objects become named sub-structs, deduped by signature) and the
//! persisted `DOC_ID` / `OPERATION_KIND` / `NAME` consts. The output depends only
//! on `serde` — no whatsapp-rust internals — so users can call any query/mutation
//! with typed inputs/outputs without the library exposing a per-op API.

use std::collections::{BTreeMap, HashSet};

use wa_ir::{MexIr, MexOperationKind, TypeNode, VariablePresence, VariablePresenceNode};

use crate::naming::{pascal_case, rust_ident, snake_case, unique_ident};

/// Render the full `operations.rs` artifact.
pub fn generate_mex_operations(ir: &MexIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated typed mex operations (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One module per persisted GraphQL operation: typed `Variables` + `Response`\n\
         //! plus `DOC_ID`/`OPERATION_KIND`/`NAME`. Depends only on `serde`.\n\n\
         #![allow(clippy::all)]\n\nuse serde::{{Deserialize, Serialize}};\n",
        ir.wa_version
    ));

    let mut used_mods = HashSet::new();
    for (short, op) in &ir.operations {
        // Keyword-escape / disambiguate the module name (a mex op named e.g.
        // `match` would otherwise emit an invalid `pub mod match`).
        let module = unique_ident(&snake_case(short), &mut used_mods, "op");
        let mut b = Builder::default();
        b.register(
            "Variables",
            &op.variables_shape,
            Some(&op.variables_presence),
        );
        b.register("Response", &op.response, None);

        out.push_str(&format!(
            "\n/// `{}` ({}).\n",
            op.original_name,
            kind_str(op.operation_kind)
        ));
        out.push_str(&format!("pub mod {module} {{\n"));
        out.push_str("    use super::{Deserialize, Serialize};\n\n");
        out.push_str(&format!(
            "    pub const NAME: &str = \"{}\";\n",
            op.original_name
        ));
        out.push_str(&format!(
            "    pub const DOC_ID: &str = \"{}\";\n",
            op.doc_id
        ));
        out.push_str(&format!(
            "    pub const OPERATION_KIND: &str = \"{}\";\n\n",
            kind_str(op.operation_kind)
        ));
        for s in &b.structs {
            out.push_str(&s.render("    "));
            out.push('\n');
        }
        out.push_str("}\n");
    }
    out
}

fn kind_str(k: MexOperationKind) -> &'static str {
    match k {
        MexOperationKind::Query => "query",
        MexOperationKind::Mutation => "mutation",
    }
}

/// A generated struct: name + ordered fields.
struct StructDef {
    name: String,
    fields: Vec<StructField>,
}

/// One generated field. `required` carries the IR's `always` verdict through to
/// the emitted type: a variable WA Web writes on every request is a `T` that is
/// always serialized, not an `Option<T>` the caller can forget. Sending `{}` to a
/// persisted operation whose compiled tree references the variable is what the
/// server answers with a bare `400`, and an `Option` with `skip_serializing_if`
/// makes that the default. Anything the IR does not call `always` - including
/// `undetermined` - keeps the optional form.
struct StructField {
    rust_field: String,
    json_key: String,
    ty: String,
    required: bool,
}

impl StructDef {
    /// `(json_key, field, type)` signature for dedup (ignores the struct name).
    /// The JSON key is part of the shape: two structs with the same Rust field
    /// names/types but different `#[serde(rename)]` keys must NOT be merged.
    fn signature(&self) -> String {
        self.fields
            .iter()
            .map(|f| format!("{}={}:{}", f.json_key, f.rust_field, f.ty))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn render(&self, indent: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "{indent}#[derive(Debug, Clone, Default, Serialize, Deserialize)]\n"
        ));
        s.push_str(&format!("{indent}pub struct {} {{\n", self.name));
        for f in &self.fields {
            let (rust_field, json_key, ty) = (&f.rust_field, &f.json_key, &f.ty);
            if rust_field.trim_start_matches("r#") != json_key {
                s.push_str(&format!("{indent}    #[serde(rename = \"{json_key}\")]\n"));
            }
            if f.required {
                s.push_str(&format!(
                    "{indent}    /// WA Web writes this key on every request.\n"
                ));
                s.push_str(&format!("{indent}    #[serde(default)]\n"));
            } else {
                s.push_str(&format!(
                    "{indent}    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n"
                ));
            }
            s.push_str(&format!("{indent}    pub {rust_field}: {ty},\n"));
        }
        s.push_str(&format!("{indent}}}\n"));
        s
    }
}

#[derive(Default)]
struct Builder {
    structs: Vec<StructDef>,
    /// struct name → its signature, to dedup identical shapes and disambiguate
    /// distinct shapes that want the same name.
    by_name: BTreeMap<String, String>,
}

impl Builder {
    /// Register a top-level struct named `name` from an object tree, with the
    /// presence tree that says which of its keys are never omitted.
    fn register(
        &mut self,
        name: &str,
        fields: &BTreeMap<String, TypeNode>,
        presence: Option<&BTreeMap<String, VariablePresenceNode>>,
    ) -> String {
        let mut def = StructDef {
            name: name.to_string(),
            fields: Vec::new(),
        };
        for (key, node) in fields {
            let verdict = presence.and_then(|p| p.get(key));
            let ty = self.field_type(node, &pascal_case(key), verdict);
            def.fields.push(field(key, ty, verdict));
        }
        self.intern(def)
    }

    /// The Rust type for a tree node used as a field value (registering any
    /// nested struct). Scalars map to `String`/`i64`/`bool`; arrays to `Vec<_>`.
    fn field_type(
        &mut self,
        node: &TypeNode,
        name_hint: &str,
        presence: Option<&VariablePresenceNode>,
    ) -> String {
        match node {
            TypeNode::Leaf(tag) => scalar_rust(tag).to_string(),
            TypeNode::Array(items) => {
                // The IR always carries a single element shape; fall back to a
                // valid serde-only scalar if an empty array ever slips through.
                let element = presence.and_then(|p| p.items.as_deref());
                let inner = items
                    .first()
                    .map(|n| self.field_type(n, name_hint, element))
                    .unwrap_or_else(|| "String".to_string());
                format!("Vec<{inner}>")
            }
            TypeNode::Object(map) => {
                let mut def = StructDef {
                    name: name_hint.to_string(),
                    fields: Vec::new(),
                };
                for (key, child) in map {
                    let verdict = presence.and_then(|p| p.fields.get(key));
                    let ty = self.field_type(child, &pascal_case(key), verdict);
                    def.fields.push(field(key, ty, verdict));
                }
                self.intern(def)
            }
        }
    }

    /// Add `def`, reusing an existing identically-shaped struct of the same name,
    /// or disambiguating with a numeric suffix on a name+shape collision.
    fn intern(&mut self, mut def: StructDef) -> String {
        if def.name.is_empty() {
            def.name = "Item".to_string();
        }
        let sig = def.signature();
        let base = def.name.clone();
        let mut name = base.clone();
        let mut n = 2;
        loop {
            match self.by_name.get(&name) {
                Some(existing) if *existing == sig => return name, // identical → reuse
                Some(_) => {
                    name = format!("{base}{n}");
                    n += 1;
                }
                None => break,
            }
        }
        def.name = name.clone();
        self.by_name.insert(name.clone(), sig);
        self.structs.push(def);
        name
    }
}

/// One field, optional unless the IR says the client always writes the key.
fn field(key: &str, ty: String, presence: Option<&VariablePresenceNode>) -> StructField {
    let required = presence.is_some_and(|p| p.presence == VariablePresence::Always);
    StructField {
        rust_field: rust_ident(key),
        json_key: key.to_string(),
        ty: if required {
            ty
        } else {
            format!("Option<{ty}>")
        },
        required,
    }
}

fn scalar_rust(tag: &str) -> &'static str {
    match tag {
        "number" => "i64",
        "boolean" => "bool",
        _ => "String",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::MexOperation;

    fn leaf(t: &str) -> TypeNode {
        TypeNode::Leaf(t.to_string())
    }

    fn obj(pairs: Vec<(&str, TypeNode)>) -> BTreeMap<String, TypeNode> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    fn ir_with(
        op_short: &str,
        vars: BTreeMap<String, TypeNode>,
        resp: BTreeMap<String, TypeNode>,
    ) -> MexIr {
        ir_with_presence(op_short, vars, BTreeMap::new(), resp)
    }

    fn ir_with_presence(
        op_short: &str,
        vars: BTreeMap<String, TypeNode>,
        presence: BTreeMap<String, VariablePresenceNode>,
        resp: BTreeMap<String, TypeNode>,
    ) -> MexIr {
        let mut operations = BTreeMap::new();
        operations.insert(
            op_short.to_string(),
            MexOperation {
                original_name: format!("WAWeb{op_short}Query"),
                doc_id: "123".into(),
                operation_kind: MexOperationKind::Query,
                variables: vec![],
                variables_shape: vars,
                variables_presence: presence,
                response: resp,
            },
        );
        MexIr {
            wa_version: "2.3000.1".into(),
            operations,
        }
    }

    #[test]
    fn emits_typed_module_with_scalars_and_nesting() {
        let vars = obj(vec![(
            "input",
            TypeNode::Object(obj(vec![
                ("group_jid", leaf("string")),
                ("limit", leaf("number")),
            ])),
        )]);
        let resp = obj(vec![(
            "xwa2_thing",
            TypeNode::Object(obj(vec![
                ("name", leaf("string")),
                ("is_open", leaf("boolean")),
                (
                    "items",
                    TypeNode::Array(vec![TypeNode::Object(obj(vec![("id", leaf("string"))]))]),
                ),
            ])),
        )]);
        let code = generate_mex_operations(&ir_with("FetchThing", vars, resp));

        assert!(code.contains("pub mod fetch_thing {"));
        assert!(code.contains("pub const DOC_ID: &str = \"123\";"));
        assert!(code.contains("pub const OPERATION_KIND: &str = \"query\";"));
        // Variables struct + nested Input struct.
        assert!(code.contains("pub struct Variables {"));
        assert!(code.contains("pub input: Option<Input>,"));
        assert!(code.contains("pub group_jid: Option<String>,"));
        assert!(code.contains("pub limit: Option<i64>,"));
        // Response + nested + array-of-object + bool.
        assert!(code.contains("pub struct Response {"));
        assert!(code.contains("pub is_open: Option<bool>,"));
        assert!(code.contains("pub items: Option<Vec<Items>>,"));
    }

    #[test]
    fn always_sent_variables_are_not_optional() {
        // The consumer defect behind oxidezap/whatsapp-rust#1372: every variable was
        // an `Option` with `skip_serializing_if`, so a caller that filled none of
        // them sent `{}` to an operation whose compiled tree names them.
        let vars = obj(vec![
            ("fetch_wamo_sub", leaf("boolean")),
            ("fetch_viewer_metadata", leaf("boolean")),
            ("fetch_pinned_messages", leaf("boolean")),
        ]);
        let presence: BTreeMap<String, VariablePresenceNode> = [
            ("fetch_wamo_sub", VariablePresence::Always),
            ("fetch_viewer_metadata", VariablePresence::Conditional),
            ("fetch_pinned_messages", VariablePresence::Undetermined),
        ]
        .into_iter()
        .map(|(k, p)| (k.to_string(), VariablePresenceNode::leaf(p)))
        .collect();
        let code =
            generate_mex_operations(&ir_with_presence("Flags", vars, presence, BTreeMap::new()));
        assert!(
            code.contains("pub fetch_wamo_sub: bool,"),
            "an always-sent variable is a value, not an Option: {code}"
        );
        assert!(code.contains("pub fetch_viewer_metadata: Option<bool>,"));
        assert!(
            code.contains("pub fetch_pinned_messages: Option<bool>,"),
            "undetermined keeps the optional form - the IR did not say it is sent"
        );
    }

    #[test]
    fn a_nested_always_key_is_required_too() {
        let vars = obj(vec![(
            "input",
            TypeNode::Object(obj(vec![
                ("r#type", leaf("string")),
                ("key", leaf("string")),
            ])),
        )]);
        let mut input = VariablePresenceNode::leaf(VariablePresence::Always);
        input.fields.insert(
            "r#type".to_string(),
            VariablePresenceNode::leaf(VariablePresence::Always),
        );
        input.fields.insert(
            "key".to_string(),
            VariablePresenceNode::leaf(VariablePresence::Conditional),
        );
        let presence = [("input".to_string(), input)].into_iter().collect();
        let code =
            generate_mex_operations(&ir_with_presence("Nested", vars, presence, BTreeMap::new()));
        assert!(code.contains("pub input: Input,"), "{code}");
        assert!(code.contains("pub key: Option<String>,"));
    }

    #[test]
    fn keyword_field_uses_raw_ident_no_rename() {
        // serde maps `r#type` → `"type"` automatically, so no rename is emitted.
        let resp = obj(vec![(
            "node",
            TypeNode::Object(obj(vec![("type", leaf("string"))])),
        )]);
        let code = generate_mex_operations(&ir_with("Foo", BTreeMap::new(), resp));
        assert!(code.contains("pub r#type: Option<String>,"));
        assert!(
            !code.contains("rename = \"type\""),
            "r# raw ident needs no serde rename"
        );
    }

    #[test]
    fn empty_array_falls_back_to_valid_type() {
        // An empty `Array` (no element shape) must not emit `Vec<serde_json_value>`.
        let resp = obj(vec![("tags", TypeNode::Array(vec![]))]);
        let code = generate_mex_operations(&ir_with("Empty", BTreeMap::new(), resp));
        assert!(
            !code.contains("serde_json_value"),
            "no invalid placeholder type"
        );
        assert!(code.contains("pub tags: Option<Vec<String>>,"));
    }

    #[test]
    fn distinct_shapes_same_name_are_disambiguated() {
        // Two `node` objects with different shapes → `Node` and `Node2`.
        let resp = obj(vec![
            (
                "a",
                TypeNode::Object(obj(vec![(
                    "node",
                    TypeNode::Object(obj(vec![("x", leaf("string"))])),
                )])),
            ),
            (
                "b",
                TypeNode::Object(obj(vec![(
                    "node",
                    TypeNode::Object(obj(vec![("y", leaf("number"))])),
                )])),
            ),
        ]);
        let code = generate_mex_operations(&ir_with("Dup", BTreeMap::new(), resp));
        assert!(code.contains("pub struct Node {"));
        assert!(code.contains("pub struct Node2 {"));
    }
}
