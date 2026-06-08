//! Native tooling: extract WhatsApp Web's WAM (analytics/metrics) catalog.
//!
//! Each metric is declared by `WAWebWamCodegenUtils.defineEvents({Name: [code,
//! props, weights, channel?, privateStatsId?]})` in a `WAWeb…WamEvent` module, where
//! `props` is `{fieldName: [fieldId, type]}` and `type` is `<utils>.TYPES.<BASE>` or
//! `o("WAWebWamEnum…").<EXPORT>`. We parse every event, resolve the enum modules its
//! fields reference, and record which modules emit each event (the dep graph).
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{ArrayExpression, Expression, ObjectExpression, Statement};
use wa_ir::{WamEnum, WamEnumVariant, WamEvent, WamField, WamFieldType, WamIr};
use wa_oxc::{
    arg_expr, as_call, as_int, as_member, as_object, as_string_lit, first_string_arg, parse_cjs,
    property_key_name,
};
use wa_transform::ModuleDefinition;

/// The runtime module every WAM event module depends on.
const CODEGEN_DEP: &str = "WAWebWamCodegenUtils";

/// Convenience: split a bundle and extract the WAM catalog.
pub fn extract_wam(source: &str, wa_version: &str) -> WamIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_wam_from_modules(source, &defs, wa_version)
}

/// Extract the WAM catalog from an already-split module index.
pub fn extract_wam_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> WamIr {
    // event module name → consumer modules (modules that list it as a dependency,
    // i.e. construct + `.commit()` it). Built from the whole dep graph.
    let mut consumers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for m in module_defs {
        for d in &m.deps {
            if d.ends_with("WamEvent") && d.as_str() != m.name {
                consumers.entry(d.as_str()).or_default().insert(&m.name);
            }
        }
    }

    let mut events: Vec<WamEvent> = Vec::new();
    let mut enum_modules: BTreeSet<String> = BTreeSet::new();
    for m in module_defs {
        // A WAM event module is a `…WamEvent` that depends on the codegen runtime.
        if !(m.name.ends_with("WamEvent") && m.deps.iter().any(|d| d == CODEGEN_DEP)) {
            continue;
        }
        for mut ev in parse_events(&source[m.start..m.end], &m.name) {
            for f in &ev.fields {
                if let WamFieldType::Enum { module } = &f.field_type {
                    enum_modules.insert(module.clone());
                }
            }
            ev.consumers = consumers
                .get(m.name.as_str())
                .map(|s| s.iter().map(|x| x.to_string()).collect())
                .unwrap_or_default();
            events.push(ev);
        }
    }

    // Resolve only the enum modules events actually reference (self-contained IR).
    let mut enums: Vec<WamEnum> = Vec::new();
    for m in module_defs {
        if enum_modules.contains(&m.name)
            && let Some(en) = parse_enum(&source[m.start..m.end], &m.name)
        {
            enums.push(en);
        }
    }

    events.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.name.cmp(&b.name)));
    events.dedup_by(|a, b| a.code == b.code && a.name == b.name);
    enums.sort_by(|a, b| a.module.cmp(&b.module));
    enums.dedup_by(|a, b| a.module == b.module);
    WamIr {
        wa_version: wa_version.to_string(),
        events,
        enums,
    }
}

/// An array element's inner expression (skips holes/spreads).
fn arr_elem<'b, 'a>(arr: &'b ArrayExpression<'a>, i: usize) -> Option<&'b Expression<'a>> {
    arr.elements.get(i).and_then(|e| e.as_expression())
}

/// Parse the `defineEvents({...})` call(s) in a module slice into events.
fn parse_events(slice: &str, module: &str) -> Vec<WamEvent> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut out = Vec::new();
    for stmt in &ret.program.body {
        walk_define_events(stmt, module, &mut out);
    }
    out
}

/// Find `<x>.defineEvents(<obj>, …)` calls anywhere in a statement and parse the
/// first-arg object's events.
fn walk_define_events(stmt: &Statement, module: &str, out: &mut Vec<WamEvent>) {
    // The module factory wraps everything; re-parsing the slice gives us a flat
    // program, so a recursive expression walk via the visitor is overkill — instead
    // we scan for the call textually-resilient way: walk the AST with a small visitor.
    use oxc_ast_visit::{Visit, walk};
    struct V<'m> {
        module: &'m str,
        out: &'m mut Vec<WamEvent>,
    }
    impl<'a> Visit<'a> for V<'_> {
        fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
            if wa_oxc::callee_method(call) == Some("defineEvents")
                && let Some(obj) = call
                    .arguments
                    .first()
                    .and_then(arg_expr)
                    .and_then(as_object)
            {
                for (name, value) in wa_oxc::obj_props(obj) {
                    if let Some(ev) = parse_event(name, value, self.module) {
                        self.out.push(ev);
                    }
                }
            }
            walk::walk_call_expression(self, call);
        }
    }
    let mut v = V { module, out };
    v.visit_statement(stmt);
}

/// Parse one `Name: [code, propsObj, weightsArr, channel?, psId?]` entry.
fn parse_event(name: &str, value: &Expression, module: &str) -> Option<WamEvent> {
    let Expression::ArrayExpression(arr) = value else {
        return None;
    };
    let code = as_int(arr_elem(arr, 0)?)? as u32;
    let props = as_object(arr_elem(arr, 1)?)?;
    let fields = parse_fields(props);

    let weights = arr_elem(arr, 2)
        .and_then(|e| match e {
            Expression::ArrayExpression(a) => Some(a),
            _ => None,
        })
        .map(|a| {
            (0..a.elements.len())
                .filter_map(|i| arr_elem(a, i).and_then(as_int).map(|v| v as u32))
                .collect()
        })
        .unwrap_or_default();

    // channel (default "regular") + privateStatsId (the JS `-1` sentinel → None).
    let channel = arr_elem(arr, 3)
        .and_then(as_string_lit)
        .unwrap_or("regular")
        .to_string();
    let private_stats_id = arr_elem(arr, 4).and_then(as_int).filter(|&v| v != -1);

    Some(WamEvent {
        name: name.to_string(),
        code,
        module: module.to_string(),
        channel,
        weights,
        private_stats_id,
        fields,
        consumers: Vec::new(),
    })
}

/// Parse `{fieldName: [fieldId, type], …}` into ordered fields (skips entries whose
/// type isn't a recognized base type or enum ref).
fn parse_fields(obj: &ObjectExpression) -> Vec<WamField> {
    let mut fields = Vec::new();
    for (name, value) in wa_oxc::obj_props(obj) {
        let Expression::ArrayExpression(arr) = value else {
            continue;
        };
        let (Some(id), Some(ty)) = (
            arr_elem(arr, 0).and_then(as_int),
            arr_elem(arr, 1).and_then(parse_field_type),
        ) else {
            continue;
        };
        fields.push(WamField {
            name: name.to_string(),
            id: id as u32,
            field_type: ty,
        });
    }
    fields
}

/// `<utils>.TYPES.<BASE>` → a base type; `o("WAWebWamEnum…").<EXPORT>` → an enum ref.
fn parse_field_type(e: &Expression) -> Option<WamFieldType> {
    let (obj, prop) = as_member(e)?;
    // Base type: the member chain `<x>.TYPES.<NAME>`.
    if let Some((_, mid)) = as_member(obj)
        && mid == "TYPES"
    {
        return base_type(prop);
    }
    // Enum ref: `o("WAWebWamEnum…").<EXPORT>` — the object is the require call.
    if let Some(call) = as_call(obj)
        && let Some(module) = first_string_arg(call)
        && module.starts_with("WAWebWamEnum")
    {
        return Some(WamFieldType::Enum {
            module: module.to_string(),
        });
    }
    None
}

fn base_type(name: &str) -> Option<WamFieldType> {
    Some(match name {
        "BOOLEAN" => WamFieldType::Boolean,
        "INTEGER" => WamFieldType::Integer,
        "NUMBER" => WamFieldType::Number,
        "STRING" => WamFieldType::String,
        "TIMER" => WamFieldType::Timer,
        _ => return None,
    })
}

/// Parse a `WAWebWamEnum…` module: `Object.freeze({KEY: int})` exported under a name.
fn parse_enum(slice: &str, module: &str) -> Option<WamEnum> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V {
        /// local var name → frozen object's variants
        locals: BTreeMap<String, Vec<WamEnumVariant>>,
        /// `export = local` (export name, local ident)
        pending: Vec<(String, String)>,
        /// `export = Object.freeze({...})` (export name, variants)
        named: Vec<(String, Vec<WamEnumVariant>)>,
    }
    impl<'a> Visit<'a> for V {
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if let (Some(name), Some(obj)) = (
                d.id.get_identifier_name(),
                d.init.as_ref().and_then(frozen_object),
            ) && let Some(vars) = parse_enum_variants(obj)
            {
                self.locals.insert(name.to_string(), vars);
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(m) = a.left.as_member_expression()
                && let Some(prop) = m.static_property_name()
            {
                if let Some(obj) = frozen_object(&a.right) {
                    if let Some(vars) = parse_enum_variants(obj) {
                        self.named.push((prop.to_string(), vars));
                    }
                } else if let Some(id) = wa_oxc::as_identifier(&a.right) {
                    self.pending.push((prop.to_string(), id.to_string()));
                }
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut v = V {
        locals: BTreeMap::new(),
        pending: Vec::new(),
        named: Vec::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    // Resolve `export = local`.
    for (name, local) in &v.pending {
        if let Some(vars) = v.locals.get(local) {
            v.named.push((name.clone(), vars.clone()));
        }
    }
    // First named export wins; `exports`/`default` name by module.
    let (name, variants) = v.named.into_iter().next()?;
    let name = if name == "exports" || name == "default" {
        module.to_string()
    } else {
        name
    };
    Some(WamEnum {
        name,
        module: module.to_string(),
        variants,
    })
}

/// `Object.freeze(<obj>)` → the object literal; also accepts a bare object literal.
fn frozen_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    if let Some(call) = as_call(e)
        && let Some((_, prop)) = as_member(&call.callee)
        && prop == "freeze"
    {
        return as_object(arg_expr(call.arguments.first()?)?);
    }
    as_object(e)
}

/// Parse `{KEY: int}` into variants (source order). `None` on a non-int value.
fn parse_enum_variants(obj: &ObjectExpression) -> Option<Vec<WamEnumVariant>> {
    let mut out = Vec::new();
    for prop in &obj.properties {
        let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop else {
            return None;
        };
        let key = property_key_name(&p.key)?;
        let value = as_int(&p.value)?;
        out.push(WamEnumVariant {
            key: key.to_string(),
            value,
        });
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests;
