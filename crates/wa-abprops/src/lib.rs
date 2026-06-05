//! Native tooling: extract WhatsApp Web's A/B-props (feature-flag) registries
//! from every `*ABPropsConfigs` bundle module.
//!
//! WA Web ships several registry modules — `WAWebABPropsConfigs` (the ~1.7k web
//! flags), `WAWebHybridABPropsConfigs` (native/Windows), `WAWebGroupABPropsConfigs`
//! (group-level) — each a big object literal `name: [code, "type", default, alt]`.
//! We read every module whose name ends in `ABPropsConfigs`, locate its registry
//! object (the one with by far the most tuple-shaped entries), and tag each flag
//! with its source module. A flag may appear in more than one module (identical
//! code/default); both are kept so the output mirrors WA Web's own organization.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::HashSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ObjectExpression, UnaryOperator};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{AbPropConfig, AbPropType, AbPropsIr, Scalar};
use wa_oxc::{as_string_lit, parse_cjs};
use wa_transform::ModuleDefinition;

/// Modules whose name ends in this suffix hold an A/B-props registry. Matching by
/// suffix (rather than an exact name) auto-captures new registries WA may add.
const MODULE_SUFFIX: &str = "ABPropsConfigs";
/// A registry object must have at least this many tuple-shaped entries. The
/// module-name filter already restricts us to real registries, so this only needs
/// to clear incidental object literals; the smallest real registry (group-level)
/// still has well over a dozen.
const MIN_ENTRIES: usize = 5;

/// Convenience: split a whole bundle into modules, then extract the registries.
/// Mirrors `extract_mex` / `extract_appstate` for a uniform per-domain surface;
/// the pipeline uses [`extract_abprops_from_modules`] to share one split.
pub fn extract_abprops(source: &str, wa_version: &str) -> AbPropsIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_abprops_from_modules(source, &defs, wa_version)
}

/// Extract every A/B-props registry from an already-split module index.
pub fn extract_abprops_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> AbPropsIr {
    // The same registry module can recur across concatenated bundle shards; take
    // the first occurrence of each module name (first declaration wins).
    let mut seen: HashSet<&str> = HashSet::new();
    let mut configs: Vec<AbPropConfig> = Vec::new();
    for def in module_defs {
        if !def.name.ends_with(MODULE_SUFFIX) || !seen.insert(def.name.as_str()) {
            continue;
        }
        configs.extend(extract_from_slice(&source[def.start..def.end], &def.name));
    }
    // Deterministic order independent of source layout; one entry per
    // (module, name) — a single module never legitimately repeats a key.
    configs.sort_by(|a, b| (&a.module, &a.name).cmp(&(&b.module, &b.name)));
    configs.dedup_by(|a, b| a.module == b.module && a.name == b.name);
    AbPropsIr {
        wa_version: wa_version.to_string(),
        configs,
    }
}

fn extract_from_slice(slice: &str, module: &str) -> Vec<AbPropConfig> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut finder = RegistryFinder {
        module,
        best: Vec::new(),
    };
    finder.visit_program(&ret.program);
    finder.best
}

/// Walks every object literal and keeps the one that parses into the most
/// flag entries — the registry dwarfs any other object in the module.
struct RegistryFinder<'m> {
    module: &'m str,
    best: Vec<AbPropConfig>,
}

impl<'a> Visit<'a> for RegistryFinder<'_> {
    fn visit_object_expression(&mut self, obj: &ObjectExpression<'a>) {
        if obj.properties.len() > self.best.len() {
            let parsed = parse_registry(obj, self.module);
            if parsed.len() > self.best.len() {
                self.best = parsed;
            }
        }
        walk::walk_object_expression(self, obj);
    }
}

/// Parse an object as `{ name: [code, "type", default, alt], … }`; returns the
/// entries it could read (empty for a non-registry object).
fn parse_registry(obj: &ObjectExpression, module: &str) -> Vec<AbPropConfig> {
    let mut out = Vec::new();
    for (name, value) in wa_oxc::obj_props(obj) {
        let Expression::ArrayExpression(arr) = value else {
            continue;
        };
        if let Some(cfg) = parse_entry(module, name, arr) {
            out.push(cfg);
        }
    }
    if out.len() >= MIN_ENTRIES {
        out
    } else {
        Vec::new()
    }
}

fn parse_entry(
    module: &str,
    name: &str,
    arr: &oxc_ast::ast::ArrayExpression,
) -> Option<AbPropConfig> {
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
        module: module.to_string(),
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
        assert_eq!(by("a_int").module, "WAWebABPropsConfigs");
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

    #[test]
    fn extracts_every_registry_module_tagged_by_module() {
        // A web registry (clears MIN_ENTRIES) plus a tiny group registry: both
        // must be captured, each flag tagged with its module, and a name shared
        // across modules kept once per module.
        let mut web = String::new();
        for k in 0..10 {
            web.push_str(&format!("flag_{k}:[{k},\"bool\",!1],"));
        }
        web.push_str("shared:[99,\"bool\",!1],");
        // Both registries must clear MIN_ENTRIES.
        let mut group = String::from("shared:[99,\"bool\",!1],grp_only:[42,\"int\",3],");
        for k in 0..6 {
            group.push_str(&format!("g_{k}:[{},\"bool\",!1],", 200 + k));
        }
        let module = format!(
            "__d(\"WAWebABPropsConfigs\",[],function(g,r,d,o,e,i,l){{l.c={{{web}}}}},1);\
             __d(\"WAWebGroupABPropsConfigs\",[],function(g,r,d,o,e,i,l){{l.c={{{group}}}}},2);"
        );
        let defs = wa_transform::extract_module_definitions(&module);
        let ir = extract_abprops_from_modules(&module, &defs, "1.0");

        let group_flags: Vec<_> = ir
            .configs
            .iter()
            .filter(|c| c.module == "WAWebGroupABPropsConfigs")
            .collect();
        assert!(
            group_flags
                .iter()
                .any(|c| c.name == "grp_only" && c.code == 42),
            "group-level registry captured"
        );
        // `shared` exists under BOTH modules (mirrors WA Web's duplication).
        let shared: Vec<_> = ir.configs.iter().filter(|c| c.name == "shared").collect();
        assert_eq!(shared.len(), 2);
        let mods: Vec<&str> = shared.iter().map(|c| c.module.as_str()).collect();
        assert!(
            mods.contains(&"WAWebABPropsConfigs") && mods.contains(&"WAWebGroupABPropsConfigs")
        );
        // Sorted by (module, name).
        assert!(
            ir.configs
                .windows(2)
                .all(|w| (&w[0].module, &w[0].name) <= (&w[1].module, &w[1].name))
        );
    }
}
