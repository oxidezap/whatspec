//! Native tooling: extract WhatsApp Web's A/B-props (feature-flag) registry from
//! the `WAWebABPropsConfigs` bundle module.
//!
//! The module holds one big object literal `name: [code, "type", default, alt]`
//! (~1.7k entries). We locate that object (the one with by far the most
//! tuple-shaped entries) and read each flag's code/type/default(s).
#![cfg(not(target_arch = "wasm32"))]

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ObjectExpression, UnaryOperator};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{AbPropConfig, AbPropType, AbPropsIr, Scalar};
use wa_oxc::{as_string_lit, parse_cjs};
use wa_transform::ModuleDefinition;

/// The module that defines the registry.
const MODULE: &str = "WAWebABPropsConfigs";
/// A registry object must have at least this many tuple-shaped entries — well
/// below the real ~1.7k, but far above any incidental object literal.
const MIN_ENTRIES: usize = 100;

/// Convenience: split a whole bundle into modules, then extract the registry.
/// Mirrors `extract_mex` / `extract_appstate` for a uniform per-domain surface;
/// the pipeline uses [`extract_abprops_from_modules`] to share one split.
pub fn extract_abprops(source: &str, wa_version: &str) -> AbPropsIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_abprops_from_modules(source, &defs, wa_version)
}

/// Extract the A/B-props registry from an already-split module index.
pub fn extract_abprops_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> AbPropsIr {
    let mut configs = module_defs
        .iter()
        .find(|m| m.name == MODULE)
        .map(|m| extract_from_slice(&source[m.start..m.end]))
        .unwrap_or_default();
    // Deterministic order independent of source layout.
    configs.sort_by(|a, b| a.name.cmp(&b.name));
    configs.dedup_by(|a, b| a.name == b.name);
    AbPropsIr {
        wa_version: wa_version.to_string(),
        configs,
    }
}

fn extract_from_slice(slice: &str) -> Vec<AbPropConfig> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut finder = RegistryFinder { best: Vec::new() };
    finder.visit_program(&ret.program);
    finder.best
}

/// Walks every object literal and keeps the one that parses into the most
/// flag entries — the registry dwarfs any other object in the module.
struct RegistryFinder {
    best: Vec<AbPropConfig>,
}

impl<'a> Visit<'a> for RegistryFinder {
    fn visit_object_expression(&mut self, obj: &ObjectExpression<'a>) {
        if obj.properties.len() > self.best.len() {
            let parsed = parse_registry(obj);
            if parsed.len() > self.best.len() {
                self.best = parsed;
            }
        }
        walk::walk_object_expression(self, obj);
    }
}

/// Parse an object as `{ name: [code, "type", default, alt], … }`; returns the
/// entries it could read (empty for a non-registry object).
fn parse_registry(obj: &ObjectExpression) -> Vec<AbPropConfig> {
    let mut out = Vec::new();
    for (name, value) in wa_oxc::obj_props(obj) {
        let Expression::ArrayExpression(arr) = value else {
            continue;
        };
        if let Some(cfg) = parse_entry(name, arr) {
            out.push(cfg);
        }
    }
    if out.len() >= MIN_ENTRIES {
        out
    } else {
        Vec::new()
    }
}

fn parse_entry(name: &str, arr: &oxc_ast::ast::ArrayExpression) -> Option<AbPropConfig> {
    let el = |i: usize| arr.elements.get(i).and_then(|e| e.as_expression());
    let code = as_u32(el(0)?)?;
    let value_type = match as_string_lit(el(1)?)? {
        "bool" => AbPropType::Bool,
        "int" => AbPropType::Int,
        "string" => AbPropType::String,
        "float" => AbPropType::Float,
        _ => return None,
    };
    let default = scalar_for(el(2)?, value_type)?;
    let alt_default = el(3)
        .and_then(|e| scalar_for(e, value_type))
        .filter(|alt| *alt != default);
    Some(AbPropConfig {
        name: name.to_string(),
        code,
        value_type,
        default,
        alt_default,
    })
}

/// Parse a default literal as the declared type. Handles the minified bool form
/// `!0` / `!1` (unary-not over a number) and negative numbers (`-5`).
fn scalar_for(e: &Expression, ty: AbPropType) -> Option<Scalar> {
    match ty {
        AbPropType::Bool => bool_lit(e).map(Scalar::Bool),
        AbPropType::Int => num_lit(e).map(|n| Scalar::Int(n as i64)),
        AbPropType::Float => num_lit(e).map(Scalar::Float),
        AbPropType::String => as_string_lit(e).map(|s| Scalar::Str(s.to_string())),
    }
}

/// `true`/`false`, or the minified `!0` (true) / `!1` (false).
fn bool_lit(e: &Expression) -> Option<bool> {
    match e {
        Expression::BooleanLiteral(b) => Some(b.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            num_lit(&u.argument).map(|n| n == 0.0)
        }
        _ => None,
    }
}

/// A numeric literal, including a unary-minus negative.
fn num_lit(e: &Expression) -> Option<f64> {
    match e {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            num_lit(&u.argument).map(|n| -n)
        }
        _ => None,
    }
}

fn as_u32(e: &Expression) -> Option<u32> {
    match e {
        Expression::NumericLiteral(n) if n.value >= 0.0 && n.value.fract() == 0.0 => {
            Some(n.value as u32)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_with_types_and_defaults() {
        // A module whose registry object has the four value types + a differing alt.
        let m = r#"__d("WAWebABPropsConfigs",[],function(g,r,d,o,e,i,l){
            l.configs = PADDING_TO_REACH_MIN;
        },1);"#;
        // Build a registry object literal big enough to clear MIN_ENTRIES.
        let mut entries = String::new();
        for k in 0..120 {
            entries.push_str(&format!("flag_{k}:[{k},\"bool\",!1,!1],"));
        }
        entries.push_str("a_int:[5,\"int\",7,7],b_str:[6,\"string\",\"x\",\"x\"],");
        entries.push_str("c_flt:[8,\"float\",0,0],d_alt:[9,\"bool\",!1,!0],");
        let module = m.replace("PADDING_TO_REACH_MIN", &format!("{{{entries}}}"));
        let defs = wa_transform::extract_module_definitions(&module);
        let ir = extract_abprops_from_modules(&module, &defs, "1.0");
        let by = |n: &str| ir.configs.iter().find(|c| c.name == n).unwrap();
        assert!(ir.configs.len() >= 124);
        assert_eq!(by("a_int").code, 5);
        assert_eq!(by("a_int").value_type, AbPropType::Int);
        assert_eq!(by("a_int").default, Scalar::Int(7));
        assert_eq!(by("b_str").default, Scalar::Str("x".into()));
        assert_eq!(by("c_flt").value_type, AbPropType::Float);
        assert_eq!(by("flag_0").default, Scalar::Bool(false));
        // Sorted by name and alt_default only kept when it differs.
        assert!(by("flag_0").alt_default.is_none());
        assert_eq!(by("d_alt").alt_default, Some(Scalar::Bool(true)));
        assert!(ir.configs.windows(2).all(|w| w[0].name <= w[1].name));
    }

    #[test]
    fn missing_module_yields_empty() {
        let ir = extract_abprops_from_modules("var x=1;", &[], "1.0");
        assert!(ir.configs.is_empty());
    }
}
