//! Generate a reference Rust catalog of `$InternalEnum`s from the enums IR.
//!
//! One `pub mod <module>` per source module; within it, each enum is a
//! `pub const <NAME>: &[(&str, V)]` slice of `(variant, value)` pairs (`V` =
//! `i64` for code enums, `&str` for wire-string enums). A const table — rather
//! than a typed enum — is used because the catalog is large and auto-derived, so
//! arbitrary variant names can't produce invalid/ colliding Rust idents. The
//! cross-language contract is `enums/index.json`; this is the Rust reference.

use std::collections::{BTreeMap, HashSet};

use wa_ir::{EnumValueKind, EnumsIr, InternalEnumDef, Scalar};

use crate::naming::{snake_case, unique_ident};

/// Render the full `enums.rs` artifact.
pub fn generate_enums(ir: &EnumsIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated $InternalEnum catalog (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One module per source module; each enum is a `(variant, value)` table.\n\n\
         #![allow(clippy::all)]\n",
        ir.wa_version
    ));

    // Group by source module (BTreeMap → deterministic module order).
    let mut by_mod: BTreeMap<&str, Vec<&InternalEnumDef>> = BTreeMap::new();
    for e in &ir.enums {
        by_mod.entry(e.module.as_str()).or_default().push(e);
    }

    let mut used_mods: HashSet<String> = HashSet::new();
    for (module, defs) in &by_mod {
        let mod_name = unique_ident(&snake_case(module), &mut used_mods, "m");
        out.push_str(&format!("\npub mod {mod_name} {{\n"));
        let mut used_consts: HashSet<String> = HashSet::new();
        for d in defs {
            let const_name =
                unique_ident(&snake_case(&d.name).to_uppercase(), &mut used_consts, "E");
            emit_enum(&mut out, d, &const_name);
        }
        out.push_str("}\n");
    }
    out
}

fn emit_enum(out: &mut String, d: &InternalEnumDef, const_name: &str) {
    // The value type (`i64` vs `&'static str`) already signals int-code vs
    // wire-string, so the const needs no doc comment beyond its name.
    let ty = match d.value_kind {
        EnumValueKind::Int => "i64",
        EnumValueKind::String => "&'static str",
    };
    out.push_str(&format!(
        "    pub const {const_name}: &[(&str, {ty})] = &[\n"
    ));
    for v in &d.variants {
        let value = match (&d.value_kind, &v.value) {
            (EnumValueKind::Int, Scalar::Int(i)) => i.to_string(),
            (EnumValueKind::String, Scalar::Str(s)) => format!("{s:?}"),
            // Kind/value mismatch shouldn't occur (extractor guarantees it); skip.
            _ => continue,
        };
        out.push_str(&format!("        ({:?}, {value}),\n", v.name));
    }
    out.push_str("    ];\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::EnumVariant;

    fn def(
        module: &str,
        name: &str,
        kind: EnumValueKind,
        vs: &[(&str, Scalar)],
    ) -> InternalEnumDef {
        InternalEnumDef::new(
            name.into(),
            module.into(),
            kind,
            vs.iter()
                .map(|(n, v)| EnumVariant {
                    name: (*n).into(),
                    value: v.clone(),
                })
                .collect(),
        )
    }

    #[test]
    fn emits_module_grouped_const_tables() {
        let ir = EnumsIr {
            wa_version: "1.0".into(),
            enums: vec![
                def(
                    "WAWebChatType",
                    "ChatType",
                    EnumValueKind::String,
                    &[("INDIVIDUAL", Scalar::Str("individual".into()))],
                ),
                def(
                    "WAWebChatType",
                    "Codes",
                    EnumValueKind::Int,
                    &[("STALE", Scalar::Int(421))],
                ),
            ],
        };
        let code = generate_enums(&ir);
        assert!(code.contains("pub mod wa_web_chat_type {"));
        assert!(code.contains("pub const CHAT_TYPE: &[(&str, &'static str)]"));
        assert!(code.contains("(\"INDIVIDUAL\", \"individual\")"));
        assert!(code.contains("pub const CODES: &[(&str, i64)]"));
        assert!(code.contains("(\"STALE\", 421)"));
    }

    #[test]
    fn dedups_colliding_const_names() {
        let ir = EnumsIr {
            wa_version: "1.0".into(),
            enums: vec![
                def("M", "Foo", EnumValueKind::Int, &[("A", Scalar::Int(1))]),
                def("M", "foo", EnumValueKind::Int, &[("B", Scalar::Int(2))]),
            ],
        };
        let code = generate_enums(&ir);
        assert!(code.contains("pub const FOO:"));
        assert!(code.contains("pub const FOO_2:"));
    }
}
