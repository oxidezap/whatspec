//! Generate a reference Rust registry of A/B-props from the abprops IR.
//!
//! Mirrors WA Web's own organization: one `pub mod` per registry module
//! (`web`, `hybrid`, `group`, …), each with one `pub const <NAME>: AbProp` per
//! flag (the screaming-snake of its key) plus a module-local `ALL`. Per-flag
//! consts are **tree-shakeable** — a consumer that names only the flags it uses
//! pays for only those, and a flag the bundle drops becomes a compile error at
//! its use site. A top-level `ALL` lists each module's slice for whole-catalog
//! iteration. The cross-language contract is `abprops/index.json`; this is the
//! Rust reference consumer.

use std::collections::HashSet;

use wa_ir::{AbPropConfig, AbPropType, AbPropsIr, Scalar};

use crate::naming::{snake_case, unique_ident};

/// Render the full `abprops.rs` artifact.
pub fn generate_abprops(ir: &AbPropsIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated A/B-props registry (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One `pub mod` per WA Web registry, one `pub const` per flag (screaming-snake of\n\
         //! its key) with the numeric `code` sent in the `<props>` IQ, value type, and default;\n\
         //! reference only what you use. Each module's `ALL` lists its flags; the top-level\n\
         //! `ALL` lists every module's slice.\n\n\
         #![allow(clippy::all)]\n\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum AbPropType {{\n    Bool,\n    Int,\n    Float,\n    Str,\n}}\n\n\
         #[derive(Debug, Clone, Copy, PartialEq)]\n\
         pub enum AbDefault {{\n    Bool(bool),\n    Int(i64),\n    Float(f64),\n    Str(&'static str),\n}}\n\n\
         #[derive(Debug, Clone, Copy)]\n\
         pub struct AbProp {{\n    pub name: &'static str,\n    pub code: u32,\n    \
         pub value_type: AbPropType,\n    pub default: AbDefault,\n}}\n\n",
        ir.wa_version
    ));

    // `ir.configs` is sorted by (module, name); emit one Rust module per registry.
    let mut module_idents = HashSet::new();
    let mut emitted: Vec<String> = Vec::new();
    let mut i = 0;
    while i < ir.configs.len() {
        let wa_module = ir.configs[i].module.as_str();
        let mut j = i;
        while j < ir.configs.len() && ir.configs[j].module == wa_module {
            j += 1;
        }
        let group = &ir.configs[i..j];
        let ident = unique_ident(&module_ident(wa_module), &mut module_idents, "m");
        out.push_str(&render_module(&ident, wa_module, group));
        emitted.push(ident);
        i = j;
    }

    // Top-level aggregate: iterate every flag with `ALL.iter().flat_map(|r| r.iter())`.
    out.push_str(
        "/// Every registry's `ALL`, for whole-catalog iteration:\n\
         /// `ALL.iter().flat_map(|r| r.iter())`.\npub const ALL: &[&[AbProp]] = &[\n",
    );
    for m in &emitted {
        out.push_str(&format!("    {m}::ALL,\n"));
    }
    out.push_str("];\n");
    out
}

/// Render one `pub mod <ident> { … }` for a single WA Web registry's flags.
fn render_module(ident: &str, wa_module: &str, group: &[AbPropConfig]) -> String {
    let mut out = format!(
        "/// `{wa_module}` — {} flags.\npub mod {ident} {{\n    use super::{{AbDefault, AbProp, AbPropType}};\n\n",
        group.len()
    );
    // Per-module ident scope, so a flag shared across modules keeps its name in each.
    let mut used = HashSet::new();
    let names: Vec<String> = group
        .iter()
        .map(|c| unique_ident(&snake_case(&c.name).to_uppercase(), &mut used, "F"))
        .collect();
    for (c, const_name) in group.iter().zip(&names) {
        out.push_str(&format!(
            "    pub const {const_name}: AbProp = AbProp {{ name: {:?}, code: {}, value_type: AbPropType::{}, default: {} }};\n",
            c.name,
            c.code,
            type_variant(c.value_type),
            default_lit(&c.default),
        ));
    }
    out.push_str(&format!(
        "\n    /// All {} flags in this registry, sorted by name.\n    pub const ALL: &[AbProp] = &[\n",
        group.len()
    ));
    for const_name in &names {
        out.push_str(&format!("        {const_name},\n"));
    }
    out.push_str("    ];\n}\n\n");
    out
}

/// WA registry module name → a short Rust module ident: strip the `WAWeb` prefix
/// and `ABPropsConfigs` suffix (`WAWebHybridABPropsConfigs` → `hybrid`), with the
/// bare web registry (`WAWebABPropsConfigs` → empty) mapped to `web`.
fn module_ident(wa_module: &str) -> String {
    let s = wa_module.strip_prefix("WAWeb").unwrap_or(wa_module);
    let s = s.strip_suffix("ABPropsConfigs").unwrap_or(s);
    if s.is_empty() {
        "web".to_string()
    } else {
        snake_case(s)
    }
}

fn type_variant(t: AbPropType) -> &'static str {
    match t {
        AbPropType::Bool => "Bool",
        AbPropType::Int => "Int",
        AbPropType::String => "Str",
        AbPropType::Float => "Float",
    }
}

fn default_lit(s: &Scalar) -> String {
    match s {
        Scalar::Bool(b) => format!("AbDefault::Bool({b})"),
        Scalar::Int(i) => format!("AbDefault::Int({i})"),
        Scalar::Float(f) => format!("AbDefault::Float({})", float_lit(*f)),
        Scalar::Str(v) => format!("AbDefault::Str({v:?})"),
    }
}

/// A valid Rust `f64` literal. `{:?}` renders finite values correctly (e.g.
/// `0.0`), but yields `NaN`/`inf`/`-inf` for non-finite values, which aren't
/// literals — map those to the `f64::` constants.
fn float_lit(f: f64) -> String {
    if f.is_nan() {
        "f64::NAN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 {
            "f64::INFINITY".to_string()
        } else {
            "f64::NEG_INFINITY".to_string()
        }
    } else {
        format!("{f:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::AbPropConfig;

    fn cfg(module: &str, name: &str, code: u32, ty: AbPropType, default: Scalar) -> AbPropConfig {
        AbPropConfig {
            module: module.into(),
            name: name.into(),
            code,
            value_type: ty,
            default,
            alt_default: None,
        }
    }

    #[test]
    fn renders_table_rows_for_each_type() {
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![
                cfg(
                    "WAWebABPropsConfigs",
                    "flag_b",
                    10,
                    AbPropType::Bool,
                    Scalar::Bool(false),
                ),
                cfg(
                    "WAWebABPropsConfigs",
                    "flag_f",
                    11,
                    AbPropType::Float,
                    Scalar::Float(0.0),
                ),
            ],
        };
        let code = generate_abprops(&ir);
        // Registry module mirrors the WA Web module (web ← WAWebABPropsConfigs).
        assert!(code.contains("pub mod web {"));
        // Per-flag const (tree-shakeable), named by screaming-snake of the key.
        assert!(code.contains(
            "pub const FLAG_B: AbProp = AbProp { name: \"flag_b\", code: 10, value_type: AbPropType::Bool, default: AbDefault::Bool(false) };"
        ));
        // Float default renders as a valid f64 literal.
        assert!(code.contains("default: AbDefault::Float(0.0) }"));
        // Per-module ALL references the consts; top-level ALL lists module slices.
        assert!(code.contains("pub const ALL: &[AbProp] = &["));
        assert!(code.contains("        FLAG_B,\n"));
        assert!(code.contains("pub const ALL: &[&[AbProp]] = &[\n    web::ALL,\n];"));
    }

    #[test]
    fn separates_registries_into_modules() {
        // A flag shared across two registries keeps its name in each module.
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![
                cfg(
                    "WAWebABPropsConfigs",
                    "shared",
                    1,
                    AbPropType::Bool,
                    Scalar::Bool(false),
                ),
                cfg(
                    "WAWebGroupABPropsConfigs",
                    "grp_only",
                    2,
                    AbPropType::Int,
                    Scalar::Int(3),
                ),
                cfg(
                    "WAWebGroupABPropsConfigs",
                    "shared",
                    1,
                    AbPropType::Bool,
                    Scalar::Bool(false),
                ),
            ],
        };
        let code = generate_abprops(&ir);
        assert!(code.contains("pub mod web {"));
        assert!(code.contains("pub mod group {"));
        // `shared` const exists in both modules (no cross-module dedup).
        assert_eq!(code.matches("pub const SHARED: AbProp").count(), 2);
        assert!(code.contains("pub const GRP_ONLY: AbProp"));
        assert!(
            code.contains("pub const ALL: &[&[AbProp]] = &[\n    web::ALL,\n    group::ALL,\n];")
        );
    }

    #[test]
    fn non_finite_float_default_renders_valid_literal() {
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![cfg(
                "WAWebABPropsConfigs",
                "nanflag",
                1,
                AbPropType::Float,
                Scalar::Float(f64::NAN),
            )],
        };
        let code = generate_abprops(&ir);
        // `{:?}` would emit `NaN` (not a literal); must be `f64::NAN`.
        assert!(code.contains("AbDefault::Float(f64::NAN)"), "{code}");
        assert!(!code.contains("Float(NaN)"));
    }

    #[test]
    fn dedups_colliding_const_names() {
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![
                cfg(
                    "WAWebABPropsConfigs",
                    "foo",
                    1,
                    AbPropType::Bool,
                    Scalar::Bool(false),
                ),
                cfg(
                    "WAWebABPropsConfigs",
                    "FOO",
                    2,
                    AbPropType::Bool,
                    Scalar::Bool(true),
                ),
            ],
        };
        let code = generate_abprops(&ir);
        assert!(code.contains("pub const FOO: AbProp"));
        assert!(code.contains("pub const FOO_2: AbProp"));
    }
}
