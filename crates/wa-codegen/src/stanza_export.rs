//! Generate a reference Rust catalog of outgoing stanzas from the stanza IR.
//!
//! Two parts:
//!  - a shared `enums` module of wire-enum value tables, one per enum an attribute is
//!    linked to — **including** the object-literal enums (`USYNC_ADDRESSING_MODE`,
//!    `ENC_RETRY_RECEIPT_ATTRS`) that never reach the `$InternalEnum` catalog;
//!  - one `pub mod <stanza_type>` per tag, with one struct per builder module holding
//!    its attributes as fields (enum-linked ones point at their table via a doc link).
//!
//! Const tables (not typed enums) match the enums-catalog codegen: auto-derived variant
//! names can't produce colliding/invalid Rust idents. The cross-language contract is
//! `stanza/index.json`; this is the Rust reference consumer.

use std::collections::{BTreeMap, HashSet};

use wa_ir::{AttrEnumRef, StanzaDef, StanzaIr, WapAttrDef, WapAttrKind, WapChildNode};

use crate::naming::{pascal_case, rust_lit, snake_case, unique_ident};

/// Render the full `stanza.rs` artifact.
pub fn generate_stanza(ir: &StanzaIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated outgoing stanza catalog (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! A generated catalog: a consumer uses a subset, so unused structs/tables are\n\
         //! expected. The contract is `stanza/index.json`; this is the Rust reference.\n\n\
         #![allow(clippy::all)]\n",
        ir.wa_version
    ));

    // ── Shared enum value tables (deduped by module + name) ──
    let mut enums: BTreeMap<(&str, &str), &AttrEnumRef> = BTreeMap::new();
    for s in &ir.stanzas {
        collect_enum_refs(&s.attrs, &mut enums);
        for c in &s.children {
            collect_child_enum_refs(c, &mut enums);
        }
    }
    // Map each enum's (module, name) to the const ident it will be emitted under, so an
    // attribute field's doc can link to it.
    let mut enum_const: BTreeMap<(&str, &str), String> = BTreeMap::new();
    if !enums.is_empty() {
        out.push_str(
            "\n/// Wire-enum value tables an enum-linked attribute draws from.\npub mod enums {\n",
        );
        let mut used = HashSet::new();
        for ((module, name), er) in &enums {
            let cname = unique_ident(&snake_case(name).to_uppercase(), &mut used, "E");
            enum_const.insert((module, name), cname.clone());
            out.push_str(&format!("    /// `{}` (`{}`).\n", er.name, er.module));
            out.push_str(&format!("    pub const {cname}: &[(&str, &str)] = &[\n"));
            for v in &er.variants {
                out.push_str(&format!(
                    "        ({}, {}),\n",
                    rust_lit(&v.name),
                    rust_lit(&v.value)
                ));
            }
            out.push_str("    ];\n");
        }
        out.push_str("}\n");
    }

    // ── One module per stanza tag, a struct per builder ──
    let mut by_tag: BTreeMap<String, Vec<&StanzaDef>> = BTreeMap::new();
    for s in &ir.stanzas {
        by_tag
            .entry(format!("{:?}", s.stanza_type).to_lowercase())
            .or_default()
            .push(s);
    }
    for (tag, stanzas) in &by_tag {
        out.push_str(&format!("\npub mod {tag} {{\n"));
        let mut used_structs = HashSet::new();
        for s in stanzas {
            emit_stanza_struct(&mut out, s, &enum_const, &mut used_structs);
        }
        out.push_str("}\n");
    }
    out
}

/// Emit `pub struct <Module>[<Subtype>] { <attr>: <ty>, … }` for one stanza. Attributes
/// are the wire fields a consumer sets; an enum-linked attr's doc points at its table.
fn emit_stanza_struct(
    out: &mut String,
    s: &StanzaDef,
    enum_const: &BTreeMap<(&str, &str), String>,
    used: &mut HashSet<String>,
) {
    let base = pascal_case(&s.module_name);
    let name = match &s.subtype {
        Some(sub) => format!("{base}{}", pascal_case(sub)),
        None => base,
    };
    let name = unique_ident(&name, used, "Stanza");
    out.push_str(&format!(
        "    /// Outgoing `<{tag}>` built by `{module}`{sub}.\n",
        tag = format!("{:?}", s.stanza_type).to_lowercase(),
        module = s.module_name,
        sub = s
            .subtype
            .as_deref()
            .map(|x| format!(" (type=`{x}`)"))
            .unwrap_or_default(),
    ));
    out.push_str("    #[derive(Debug, Clone, Default)]\n");
    out.push_str(&format!("    pub struct {name} {{\n"));
    let mut used_fields = HashSet::new();
    emit_attr_fields(out, &s.attrs, enum_const, &mut used_fields);
    // Flatten enum-linked attributes from immediate children too (the crypto link lives
    // on `<message><enc type=…>`), so the struct surfaces them for the consumer.
    for c in &s.children {
        emit_child_enum_fields(out, c, enum_const, &mut used_fields);
    }
    out.push_str("    }\n");
}

fn emit_attr_fields(
    out: &mut String,
    attrs: &[WapAttrDef],
    enum_const: &BTreeMap<(&str, &str), String>,
    used: &mut HashSet<String>,
) {
    for a in attrs {
        let field = unique_ident(&snake_case(&a.name), used, "f");
        if let Some(er) = &a.enum_ref
            && let Some(cname) = enum_const.get(&(er.module.as_str(), er.name.as_str()))
        {
            out.push_str(&format!(
                "        /// Wire value from [`super::enums::{cname}`] (`{}`).\n",
                er.name
            ));
            out.push_str(&format!("        pub {field}: String,\n"));
        } else {
            let ty = match a.kind {
                WapAttrKind::Integer => "u64",
                WapAttrKind::Optional => "Option<String>",
                _ => "String",
            };
            out.push_str(&format!("        pub {field}: {ty},\n"));
        }
    }
}

/// Emit only the enum-linked attributes of a child (recursively), prefixed by the child
/// tag, so a struct surfaces e.g. `enc_type` from `<message><enc type=…>`.
fn emit_child_enum_fields(
    out: &mut String,
    node: &WapChildNode,
    enum_const: &BTreeMap<(&str, &str), String>,
    used: &mut HashSet<String>,
) {
    for a in &node.attrs {
        if let Some(er) = &a.enum_ref
            && let Some(cname) = enum_const.get(&(er.module.as_str(), er.name.as_str()))
        {
            let field = unique_ident(&snake_case(&format!("{}_{}", node.tag, a.name)), used, "f");
            out.push_str(&format!(
                "        /// `<{}>` wire value from [`super::enums::{cname}`] (`{}`).\n",
                node.tag, er.name
            ));
            out.push_str(&format!("        pub {field}: String,\n"));
        }
    }
    for c in &node.children {
        emit_child_enum_fields(out, c, enum_const, used);
    }
}

fn collect_enum_refs<'a>(
    attrs: &'a [WapAttrDef],
    out: &mut BTreeMap<(&'a str, &'a str), &'a AttrEnumRef>,
) {
    for a in attrs {
        if let Some(er) = &a.enum_ref {
            out.entry((er.module.as_str(), er.name.as_str()))
                .or_insert(er);
        }
    }
}

fn collect_child_enum_refs<'a>(
    node: &'a WapChildNode,
    out: &mut BTreeMap<(&'a str, &'a str), &'a AttrEnumRef>,
) {
    collect_enum_refs(&node.attrs, out);
    for c in &node.children {
        collect_child_enum_refs(c, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{AttrEnumVariant, Direction, StanzaTag};

    fn variant(name: &str, value: &str) -> AttrEnumVariant {
        AttrEnumVariant {
            name: name.into(),
            value: value.into(),
        }
    }

    fn enum_attr(name: &str, ename: &str, module: &str, vars: Vec<AttrEnumVariant>) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind: WapAttrKind::String,
            value: None,
            required: true,
            enum_ref: Some(AttrEnumRef {
                name: ename.into(),
                module: module.into(),
                variants: vars,
            }),
        }
    }

    fn plain_attr(name: &str, kind: WapAttrKind) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: None,
            required: true,
            enum_ref: None,
        }
    }

    #[test]
    fn generates_valid_rust_with_enum_tables_and_child_link() {
        let enc = WapChildNode {
            tag: "enc".into(),
            attrs: vec![enum_attr(
                "type",
                "CiphertextType",
                "WAWebBackendJobs.flow",
                vec![variant("Skmsg", "skmsg"), variant("Pkmsg", "pkmsg")],
            )],
            ..Default::default()
        };
        let ir = StanzaIr {
            wa_version: "1.0".into(),
            stanzas: vec![
                StanzaDef {
                    stanza_type: StanzaTag::Receipt,
                    direction: Direction::Outgoing,
                    module_name: "WAWebSendRetryReceiptJob".into(),
                    exported_function: None,
                    all_exports: vec![],
                    namespace: None,
                    subtype: Some("retry".into()),
                    target: None,
                    attrs: vec![
                        plain_attr("id", WapAttrKind::String),
                        plain_attr("count", WapAttrKind::Integer),
                        enum_attr(
                            "type",
                            "ENC_RETRY_RECEIPT_ATTRS",
                            "WAWebVoipSignalingEnums",
                            vec![
                                variant("SINGLE_PARTICIPANT", "enc"),
                                variant("GROUP_CALL", "enc_rekey_retry"),
                            ],
                        ),
                    ],
                    children: vec![],
                    response: None,
                },
                StanzaDef {
                    stanza_type: StanzaTag::Message,
                    direction: Direction::Outgoing,
                    module_name: "WAWebSendMsgJob".into(),
                    exported_function: None,
                    all_exports: vec![],
                    namespace: None,
                    subtype: None,
                    target: None,
                    attrs: vec![plain_attr("id", WapAttrKind::String)],
                    children: vec![enc],
                    response: None,
                },
            ],
        };
        let code = generate_stanza(&ir);
        syn::parse_file(&code)
            .unwrap_or_else(|e| panic!("generated stanza.rs invalid: {e}\n{code}"));
        // Enum value tables, including the object-literal enum.
        assert!(code.contains("pub mod enums"));
        assert!(code.contains(r#"("GROUP_CALL", "enc_rekey_retry")"#));
        assert!(code.contains(r#"("Skmsg", "skmsg")"#));
        // A struct per stanza, in a per-tag module; integer attr is u64.
        assert!(code.contains("pub mod receipt"));
        assert!(code.contains("pub mod message"));
        assert!(code.contains("pub count: u64"));
        // The child enc.type link is surfaced on the message struct and doc-links its table.
        assert!(code.contains("pub enc_type: String"));
        assert!(code.contains("super::enums::CIPHERTEXT_TYPE"));
    }

    #[test]
    fn committed_stanza_ir_generates_valid_rust() {
        // Guard the codegen against the real, committed IR — like the other domains.
        let ir_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../generated/stanza/index.json"
        );
        let Ok(json) = std::fs::read_to_string(ir_path) else {
            eprintln!("skip: {ir_path} not committed yet");
            return;
        };
        let ir: StanzaIr = serde_json::from_str(&json).expect("deserialize committed StanzaIr");
        let code = generate_stanza(&ir);
        syn::parse_file(&code)
            .unwrap_or_else(|e| panic!("generated stanza.rs is not valid Rust ({e})"));
    }
}
