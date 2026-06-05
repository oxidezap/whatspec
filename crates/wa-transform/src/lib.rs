//! Native tooling: parse a WA Web bundle with oxc and extract the individual
//! Metro `__d("Name", [deps], factory, id)` module definitions.
//!
//! Faithful port of the bundler's `extract-modules.ts`, but native oxc instead of
//! the napi bindings. Returns byte offsets only — no source copying — so callers
//! slice the original bundle themselves.
#![cfg(not(target_arch = "wasm32"))]

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

/// A single `__d()` module definition extracted from a bundle.
///
/// Offsets are byte positions into the source the definition was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDefinition {
    /// Module name (first arg to `__d`).
    pub name: String,
    /// Dependency module names (string entries of the second arg array).
    pub deps: Vec<String>,
    /// Byte span of the whole `__d(...)` call.
    pub start: usize,
    pub end: usize,
    /// Byte span of the factory (third arg).
    pub factory_start: usize,
    pub factory_end: usize,
}

/// Extract every `__d()` module definition from a Metro bundle's source.
pub fn extract_module_definitions(code: &str) -> Vec<ModuleDefinition> {
    if code.is_empty() {
        return Vec::new();
    }
    let allocator = Allocator::default();
    // Metro bundles are scripts, not ES modules.
    let ret = Parser::new(&allocator, code, SourceType::cjs()).parse();

    let mut visitor = ModuleVisitor {
        modules: Vec::new(),
    };
    visitor.visit_program(&ret.program);
    visitor.modules
}

struct ModuleVisitor {
    modules: Vec<ModuleDefinition>,
}

impl<'a> Visit<'a> for ModuleVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        match parse_define(call) {
            // A module: record it and do NOT walk its children — `__d` never nests
            // inside another factory body, so skipping it avoids traversing the
            // (potentially huge) factory.
            Some(def) => self.modules.push(def),
            // Non-`__d` call: keep walking so `__d` inside an IIFE wrapper is found.
            None => walk::walk_call_expression(self, call),
        }
    }
}

/// Match `__d("name", [..deps], factory, id)` and pull out its metadata.
fn parse_define(call: &CallExpression) -> Option<ModuleDefinition> {
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "__d" {
        return None;
    }
    if call.arguments.len() < 3 {
        return None;
    }

    // First arg: module name (string literal).
    let Some(Expression::StringLiteral(name_lit)) = call.arguments[0].as_expression() else {
        return None;
    };
    let name = name_lit.value.to_string();

    // Second arg: dependency array (string elements only; non-strings/holes skipped).
    let mut deps = Vec::new();
    if let Some(Expression::ArrayExpression(arr)) = call.arguments[1].as_expression() {
        for el in &arr.elements {
            if let Some(Expression::StringLiteral(s)) = el.as_expression() {
                deps.push(s.value.to_string());
            }
        }
    }

    // Third arg: factory — keep only its span.
    let factory_span = call.arguments[2].span();

    Some(ModuleDefinition {
        name,
        deps,
        start: call.span.start as usize,
        end: call.span.end as usize,
        factory_start: factory_span.start as usize,
        factory_end: factory_span.end as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(extract_module_definitions("").is_empty());
    }

    #[test]
    fn extracts_name_deps_and_offsets() {
        let code = r#"__d("WAWebFoo",["WAWebBar","WAWebBaz"],function(g,r,d){var x=1;},123);"#;
        let mods = extract_module_definitions(code);
        assert_eq!(mods.len(), 1);
        let m = &mods[0];
        assert_eq!(m.name, "WAWebFoo");
        assert_eq!(m.deps, vec!["WAWebBar", "WAWebBaz"]);
        // The full-call span covers the whole `__d(...)`.
        assert_eq!(
            &code[m.start..m.end],
            r#"__d("WAWebFoo",["WAWebBar","WAWebBaz"],function(g,r,d){var x=1;},123)"#
        );
        // The factory span isolates the function expression.
        assert_eq!(
            &code[m.factory_start..m.factory_end],
            "function(g,r,d){var x=1;}"
        );
    }

    #[test]
    fn multiple_modules_including_iife_wrapped() {
        // First two top-level; third wrapped in an IIFE — must still be found.
        let code = r#"
            __d("A",[],function(){});
            __d("B",["A"],function(){});
            (function(){ __d("C",["B"],function(){}); })();
        "#;
        let mods = extract_module_definitions(code);
        let names: Vec<_> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["A", "B", "C"]);
        assert_eq!(mods[2].deps, vec!["B"]);
    }

    #[test]
    fn deps_arg_not_array_yields_empty_deps() {
        // Metro uses 0/null for "no deps".
        let mods = extract_module_definitions(r#"__d("NoDeps",0,function(){});"#);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "NoDeps");
        assert!(mods[0].deps.is_empty());
    }

    #[test]
    fn non_string_dep_elements_are_skipped() {
        let mods = extract_module_definitions(r#"__d("M",["Real",42,null,"Also"],function(){});"#);
        assert_eq!(mods[0].deps, vec!["Real", "Also"]);
    }

    #[test]
    fn ignores_non_define_and_malformed_calls() {
        let code = r#"
            other("X",[],function(){});      // not __d
            obj.__d("Y",[],function(){});    // member call, not bare __d
            __d("TooFew",[]);                // < 3 args
            __d(123,[],function(){});        // non-string name
            __d("Good",[],function(){});     // valid
        "#;
        let mods = extract_module_definitions(code);
        let names: Vec<_> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["Good"]);
    }

    #[test]
    fn does_not_descend_into_factory_calls() {
        // A bare `__d(...)` call appearing *inside* a factory body should not be
        // mistaken for a module (it isn't how Metro nests, and we skip the body).
        let code = r#"__d("Outer",[],function(){ __d("ShouldNotAppear",[],function(){}); });"#;
        let mods = extract_module_definitions(code);
        let names: Vec<_> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["Outer"]);
    }
}
