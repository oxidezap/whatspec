//! Generate a reference Rust registry of A/B-props from the abprops IR.
//!
//! Emits one `pub const <NAME>: AbProp` per flag (the screaming-snake of its key)
//! plus an `ALL` slice that references them. Per-flag consts are **tree-shakeable**
//! — a consumer that names only the flags it uses pays for only those, and a flag
//! the bundle drops becomes a compile error at its use site — while `ALL` stays
//! available for whole-registry iteration. The cross-language contract is
//! `abprops/index.json`; this is the Rust reference consumer.

use std::collections::HashSet;

use wa_ir::{AbPropType, AbPropsIr, Scalar};

use crate::naming::{snake_case, unique_ident};

/// Render the full `abprops.rs` artifact.
pub fn generate_abprops(ir: &AbPropsIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated A/B-props registry (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One `pub const` per flag (screaming-snake of its key) with the numeric `code`\n\
         //! sent in the `<props>` IQ, value type, and default; reference only what you use.\n\
         //! `ALL` lists every flag for iteration.\n\n\
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

    // Assign each flag a unique const ident up front so `ALL` can reference them.
    let mut used = HashSet::new();
    let names: Vec<String> = ir
        .configs
        .iter()
        .map(|c| unique_ident(&snake_case(&c.name).to_uppercase(), &mut used, "F"))
        .collect();

    for (c, const_name) in ir.configs.iter().zip(&names) {
        out.push_str(&format!(
            "pub const {const_name}: AbProp = AbProp {{ name: {:?}, code: {}, value_type: AbPropType::{}, default: {} }};\n",
            c.name,
            c.code,
            type_variant(c.value_type),
            default_lit(&c.default),
        ));
    }

    out.push_str(&format!(
        "\n/// All {} A/B-props, sorted by name.\npub const ALL: &[AbProp] = &[\n",
        ir.configs.len()
    ));
    for const_name in &names {
        out.push_str(&format!("    {const_name},\n"));
    }
    out.push_str("];\n");
    out
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

    #[test]
    fn renders_table_rows_for_each_type() {
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![
                AbPropConfig {
                    name: "flag_b".into(),
                    code: 10,
                    value_type: AbPropType::Bool,
                    default: Scalar::Bool(false),
                    alt_default: None,
                },
                AbPropConfig {
                    name: "flag_f".into(),
                    code: 11,
                    value_type: AbPropType::Float,
                    default: Scalar::Float(0.0),
                    alt_default: None,
                },
            ],
        };
        let code = generate_abprops(&ir);
        // Per-flag const (tree-shakeable), named by screaming-snake of the key.
        assert!(code.contains(
            "pub const FLAG_B: AbProp = AbProp { name: \"flag_b\", code: 10, value_type: AbPropType::Bool, default: AbDefault::Bool(false) };"
        ));
        // Float default renders as a valid f64 literal.
        assert!(code.contains("default: AbDefault::Float(0.0) }"));
        // ALL references the per-flag consts rather than re-inlining literals.
        assert!(code.contains("pub const ALL: &[AbProp] = &["));
        assert!(code.contains("    FLAG_B,\n"));
        assert!(code.contains("    FLAG_F,\n"));
    }

    #[test]
    fn non_finite_float_default_renders_valid_literal() {
        let ir = AbPropsIr {
            wa_version: "1.0".into(),
            configs: vec![AbPropConfig {
                name: "nanflag".into(),
                code: 1,
                value_type: AbPropType::Float,
                default: Scalar::Float(f64::NAN),
                alt_default: None,
            }],
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
                AbPropConfig {
                    name: "foo".into(),
                    code: 1,
                    value_type: AbPropType::Bool,
                    default: Scalar::Bool(false),
                    alt_default: None,
                },
                AbPropConfig {
                    name: "FOO".into(),
                    code: 2,
                    value_type: AbPropType::Bool,
                    default: Scalar::Bool(true),
                    alt_default: None,
                },
            ],
        };
        let code = generate_abprops(&ir);
        assert!(code.contains("pub const FOO: AbProp"));
        assert!(code.contains("pub const FOO_2: AbProp"));
    }
}
