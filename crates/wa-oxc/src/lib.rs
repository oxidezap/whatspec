//! Shared accessors over the oxc AST, used by every WA Web bundle scanner.
//!
//! Lifetimes are decoupled: `'b` is the borrow, `'a` the AST arena. This lets the
//! helpers be used from `Visit` methods (which hand out short borrows of `<'a>` nodes).
#![cfg(not(target_arch = "wasm32"))]

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentTarget, CallExpression, Expression, ObjectExpression, ObjectPropertyKind,
    PropertyKey, Statement, UnaryOperator,
};
use oxc_parser::{Parser, ParserReturn};
use oxc_span::SourceType;

/// The Metro module-definition function: `__d("Name", deps, factory, id)`.
pub const DEFINE_FN: &str = "__d";

/// Parse a bundle/source slice as CommonJS (Metro bundles are scripts, not ES
/// modules). Centralizes the `Allocator` + `Parser::new(...).parse()` boilerplate
/// repeated across every extractor; the caller owns the `Allocator` so the
/// returned AST borrows from it.
pub fn parse_cjs<'a>(allocator: &'a Allocator, source: &'a str) -> ParserReturn<'a> {
    Parser::new(allocator, source, SourceType::cjs()).parse()
}

/// The single string-literal argument of a custom-require/define-style call:
/// `o("ModuleName")` / `__d("Name", …)` → `"ModuleName"` / `"Name"`.
pub fn first_string_arg<'b, 'a>(call: &'b CallExpression<'a>) -> Option<&'b str> {
    as_string_lit(arg_expr(call.arguments.first()?)?)
}

/// If `stmt` is a top-level `__d("Name", ...)` definition, return its module name.
pub fn define_module_name<'a>(stmt: &'a Statement<'a>) -> Option<&'a str> {
    let Statement::ExpressionStatement(es) = stmt else {
        return None;
    };
    let call = as_call(&es.expression)?;
    if as_identifier(&call.callee)? != DEFINE_FN {
        return None;
    }
    as_string_lit(arg_expr(call.arguments.first()?)?)
}

/// Identifier name, if `e` is an identifier reference.
pub fn as_identifier<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b str> {
    match e {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

/// Integer value, if `e` is a numeric literal (truncated to i64).
pub fn as_int(e: &Expression) -> Option<i64> {
    match e {
        // Only an exact integer value — `value as i64` would silently truncate a
        // fractional or out-of-range literal (e.g. a mis-read proto field id).
        Expression::NumericLiteral(n)
            if n.value.fract() == 0.0
                && n.value >= i64::MIN as f64
                && n.value < -(i64::MIN as f64) =>
        {
            Some(n.value as i64)
        }
        // Minified negatives are `-N` (unary minus over a literal), e.g. proto
        // enum values like `-1`; fold them so they aren't silently dropped.
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            if let Expression::NumericLiteral(number) = &u.argument
                && number.value == -(i64::MIN as f64)
                && number
                    .raw
                    .as_ref()
                    .is_some_and(|raw| raw.as_str() == "9223372036854775808")
            {
                Some(i64::MIN)
            } else {
                as_int(&u.argument).and_then(i64::checked_neg)
            }
        }
        _ => None,
    }
}

/// Name of a simple assignment target (`x = ...` → `x`).
pub fn assignment_target_name<'b, 'a>(t: &'b AssignmentTarget<'a>) -> Option<&'b str> {
    match t {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

/// String value, if `e` is a string literal.
pub fn as_string_lit<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b str> {
    match e {
        Expression::StringLiteral(s) => Some(s.value.as_str()),
        _ => None,
    }
}

/// The call, if `e` is a call expression.
pub fn as_call<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b CallExpression<'a>> {
    match e {
        Expression::CallExpression(c) => Some(c),
        _ => None,
    }
}

/// `(object, static_property_name)` if `e` is a static member expression
/// (`obj.prop`). Computed/private members return `None`.
pub fn as_member<'b, 'a>(e: &'b Expression<'a>) -> Option<(&'b Expression<'a>, &'b str)> {
    let m = e.as_member_expression()?;
    let prop = m.static_property_name()?;
    Some((m.object(), prop))
}

/// The expression form of a call argument (skips spread elements).
pub fn arg_expr<'b, 'a>(arg: &'b Argument<'a>) -> Option<&'b Expression<'a>> {
    arg.as_expression()
}

/// Property name accessed by a member expression callee, e.g. `x.foo()` → `foo`.
pub fn callee_method<'b, 'a>(call: &'b CallExpression<'a>) -> Option<&'b str> {
    as_member(&call.callee).map(|(_, name)| name)
}

/// The object a method call is invoked on, e.g. `x.foo()` → `x`.
pub fn callee_object<'b, 'a>(call: &'b CallExpression<'a>) -> Option<&'b Expression<'a>> {
    as_member(&call.callee).map(|(obj, _)| obj)
}

/// The object expression, if `e` is one.
pub fn as_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    match e {
        Expression::ObjectExpression(o) => Some(o),
        _ => None,
    }
}

/// Static name of an object property key (`{ foo: 1 }` / `{ "foo": 1 }` → `foo`).
/// Computed keys return `None`.
pub fn property_key_name<'b, 'a>(key: &'b PropertyKey<'a>) -> Option<&'b str> {
    match key {
        PropertyKey::StaticIdentifier(k) => Some(k.name.as_str()),
        PropertyKey::StringLiteral(k) => Some(k.value.as_str()),
        _ => None,
    }
}

/// Value of an object property by key name (first match; identifier/string keys).
pub fn obj_prop<'b, 'a>(obj: &'b ObjectExpression<'a>, key: &str) -> Option<&'b Expression<'a>> {
    obj.properties.iter().find_map(|p| match p {
        ObjectPropertyKind::ObjectProperty(pr) if property_key_name(&pr.key) == Some(key) => {
            Some(&pr.value)
        }
        _ => None,
    })
}

/// Iterate an object literal's `(name, value)` pairs, skipping spreads, methods,
/// and computed/non-identifier keys — the shape extractors want when reading a
/// `{ a: …, b: … }` literal. (Callers that must *reject* an object containing a
/// spread, rather than skip it, should iterate `properties` directly.)
pub fn obj_props<'b, 'a>(
    obj: &'b ObjectExpression<'a>,
) -> impl Iterator<Item = (&'b str, &'b Expression<'a>)> {
    obj.properties.iter().filter_map(|p| match p {
        ObjectPropertyKind::ObjectProperty(pr) => {
            property_key_name(&pr.key).map(|name| (name, &pr.value))
        }
        _ => None,
    })
}

/// A function literal invoked directly or through its `call`/`apply` method.
pub fn directly_invoked_function<'b, 'a>(
    call: &'b CallExpression<'a>,
) -> Option<&'b Expression<'a>> {
    let callee = call.callee.without_parentheses();
    let function = if matches!(
        callee,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    ) {
        callee
    } else {
        let (owner, method) = as_member(callee)?;
        if !matches!(method, "call" | "apply") {
            return None;
        }
        owner.without_parentheses()
    };
    matches!(
        function,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    )
    .then_some(function)
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum StrictMode {
    Strict,
    Sloppy,
    #[default]
    Unknown,
}

impl StrictMode {
    pub fn for_body(self, body: &oxc_ast::ast::FunctionBody<'_>) -> Self {
        if body.has_use_strict_directive() {
            Self::Strict
        } else {
            self
        }
    }
}

pub fn block_bindings(statements: &[Statement<'_>]) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration) if !declaration.kind.is_var() => {
                for binding in &declaration.declarations {
                    names.extend(
                        binding
                            .id
                            .get_binding_identifiers()
                            .iter()
                            .map(|id| id.name.to_string()),
                    );
                }
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    names.insert(id.name.to_string());
                }
            }
            Statement::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    names.insert(id.name.to_string());
                }
            }
            _ => {}
        }
    }
    names
}

pub fn assignment_target_names(target: &AssignmentTarget<'_>) -> std::collections::HashSet<String> {
    use oxc_ast_visit::{Visit, walk};
    #[derive(Default)]
    struct Targets(std::collections::HashSet<String>);
    impl<'a> Visit<'a> for Targets {
        fn visit_simple_assignment_target(
            &mut self,
            target: &oxc_ast::ast::SimpleAssignmentTarget<'a>,
        ) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = target {
                self.0.insert(id.name.to_string());
            }
        }
        fn visit_assignment_target_property_identifier(
            &mut self,
            property: &oxc_ast::ast::AssignmentTargetPropertyIdentifier<'a>,
        ) {
            self.0.insert(property.binding.name.to_string());
            if let Some(init) = &property.init {
                self.visit_expression(init);
            }
        }
        fn visit_expression(&mut self, expression: &Expression<'a>) {
            if matches!(
                expression,
                Expression::FunctionExpression(_)
                    | Expression::ArrowFunctionExpression(_)
                    | Expression::ClassExpression(_)
            ) {
                return;
            }
            walk::walk_expression(self, expression);
        }
    }
    let mut targets = Targets::default();
    targets.visit_assignment_target(target);
    targets.0
}

pub fn assignment_target_has_member(target: &AssignmentTarget<'_>) -> bool {
    use oxc_ast_visit::{Visit, walk};
    #[derive(Default)]
    struct Members(bool);
    impl<'a> Visit<'a> for Members {
        fn visit_simple_assignment_target(
            &mut self,
            target: &oxc_ast::ast::SimpleAssignmentTarget<'a>,
        ) {
            self.0 |= target.as_member_expression().is_some();
        }
        fn visit_expression(&mut self, expression: &Expression<'a>) {
            if matches!(
                expression,
                Expression::FunctionExpression(_)
                    | Expression::ArrowFunctionExpression(_)
                    | Expression::ClassExpression(_)
            ) {
                return;
            }
            walk::walk_expression(self, expression);
        }
    }
    let mut members = Members::default();
    members.visit_assignment_target(target);
    members.0
}

/// Function-scoped variables and body declarations, excluding nested function interiors.
pub fn function_body_bindings(
    body: &oxc_ast::ast::FunctionBody<'_>,
    mode: StrictMode,
) -> std::collections::HashSet<String> {
    use oxc_ast_visit::{Visit, walk};
    #[derive(Default)]
    struct Binder {
        names: std::collections::HashSet<String>,
        depth: usize,
        mode: StrictMode,
    }
    impl<'a> Visit<'a> for Binder {
        fn visit_variable_declaration(
            &mut self,
            declaration: &oxc_ast::ast::VariableDeclaration<'a>,
        ) {
            if declaration.kind.is_var() || self.depth == 0 {
                for binding in &declaration.declarations {
                    self.names.extend(
                        binding
                            .id
                            .get_binding_identifiers()
                            .iter()
                            .map(|id| id.name.to_string()),
                    );
                }
            }
            walk::walk_variable_declaration(self, declaration);
        }
        fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
            self.depth += 1;
            walk::walk_block_statement(self, block);
            self.depth -= 1;
        }
        fn visit_for_statement(&mut self, statement: &oxc_ast::ast::ForStatement<'a>) {
            self.depth += 1;
            walk::walk_for_statement(self, statement);
            self.depth -= 1;
        }
        fn visit_for_in_statement(&mut self, statement: &oxc_ast::ast::ForInStatement<'a>) {
            self.depth += 1;
            walk::walk_for_in_statement(self, statement);
            self.depth -= 1;
        }
        fn visit_for_of_statement(&mut self, statement: &oxc_ast::ast::ForOfStatement<'a>) {
            self.depth += 1;
            walk::walk_for_of_statement(self, statement);
            self.depth -= 1;
        }
        fn visit_switch_statement(&mut self, statement: &oxc_ast::ast::SwitchStatement<'a>) {
            self.depth += 1;
            walk::walk_switch_statement(self, statement);
            self.depth -= 1;
        }
        fn visit_statement(&mut self, statement: &Statement<'a>) {
            match statement {
                Statement::FunctionDeclaration(function) => {
                    if (self.depth == 0 || self.mode == StrictMode::Sloppy)
                        && let Some(id) = &function.id
                    {
                        self.names.insert(id.name.to_string());
                    }
                }
                Statement::ClassDeclaration(class) => {
                    if self.depth == 0
                        && let Some(id) = &class.id
                    {
                        self.names.insert(id.name.to_string());
                    }
                }
                _ => walk::walk_statement(self, statement),
            }
        }
        fn visit_expression(&mut self, expression: &Expression<'a>) {
            if matches!(
                expression,
                Expression::FunctionExpression(_)
                    | Expression::ArrowFunctionExpression(_)
                    | Expression::ClassExpression(_)
            ) {
                return;
            }
            walk::walk_expression(self, expression);
        }
    }
    let mut binder = Binder {
        mode: mode.for_body(body),
        ..Default::default()
    };
    binder.visit_function_body(body);
    binder.names
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    #[test]
    fn function_bindings_exclude_nested_functions_and_block_lexicals() {
        let allocator = Allocator::default();
        let parsed = parse_cjs(
            &allocator,
            "(function(parameter){var direct;{let block;var hoisted;}function nested(inner){var hidden;}const root=0;for(let iteration of values){var loop;}});",
        );
        assert!(parsed.errors.is_empty());
        let Statement::ExpressionStatement(statement) = &parsed.program.body[0] else {
            panic!("function expression")
        };
        let Expression::FunctionExpression(function) = statement.expression.without_parentheses()
        else {
            panic!("function expression")
        };
        let names = function_body_bindings(function.body.as_ref().unwrap(), StrictMode::Sloppy);
        for name in ["direct", "hoisted", "nested", "root", "loop"] {
            assert!(names.contains(name), "{name}");
        }
        for name in ["parameter", "block", "inner", "hidden", "iteration"] {
            assert!(!names.contains(name), "{name}");
        }
    }

    #[test]
    fn matchers_work_on_real_ast() {
        let alloc = Allocator::default();
        let code = r#"e.child("tag").attrInt("code");"#;
        let ret = Parser::new(&alloc, code, SourceType::cjs()).parse();
        let oxc_ast::ast::Statement::ExpressionStatement(es) = &ret.program.body[0] else {
            panic!("expected expr stmt");
        };
        let outer = as_call(&es.expression).expect("outer call");
        assert_eq!(callee_method(outer), Some("attrInt"));
        assert_eq!(
            as_string_lit(arg_expr(&outer.arguments[0]).unwrap()),
            Some("code")
        );

        let inner = as_call(callee_object(outer).unwrap()).expect("inner call");
        assert_eq!(callee_method(inner), Some("child"));
        assert_eq!(as_identifier(callee_object(inner).unwrap()), Some("e"));
        assert_eq!(
            as_string_lit(arg_expr(&inner.arguments[0]).unwrap()),
            Some("tag")
        );
    }

    #[test]
    fn as_int_rejects_fractional_and_out_of_range() {
        let alloc = Allocator::default();
        let ret = Parser::new(
            &alloc,
            "[7, 1.5, 9e30, -3, 9223372036854775808, -9223372036854775808, -9223372036854775809, -9223372036854775808.1, -9.223372036854776e18];",
            SourceType::cjs(),
        )
        .parse();
        let oxc_ast::ast::Statement::ExpressionStatement(es) = &ret.program.body[0] else {
            panic!("expr stmt");
        };
        let oxc_ast::ast::Expression::ArrayExpression(arr) = &es.expression else {
            panic!("array");
        };
        let el = |i: usize| as_int(arr.elements[i].as_expression().unwrap());
        assert_eq!(el(0), Some(7)); // plain integer
        assert_eq!(el(1), None); // fractional → no silent truncation to 1
        assert_eq!(el(2), None); // 9e30 is out of i64 range
        assert_eq!(el(4), None); // the rounded f64 i64::MAX bound is exclusive
        assert_eq!(el(5), Some(i64::MIN));
        assert_eq!(el(6), None);
        assert_eq!(el(7), None);
        assert_eq!(el(8), None);
        assert_eq!(el(3), Some(-3)); // unary minus is folded (proto enum negatives)
    }
}

#[cfg(test)]
#[test]
fn block_declaration_ownership_depends_on_strictness() {
    let allocator = Allocator::default();
    let parsed = parse_cjs(
        &allocator,
        "(function(){{function nested(){}class Local{}}});",
    );
    let Statement::ExpressionStatement(statement) = &parsed.program.body[0] else {
        panic!("function")
    };
    let Expression::FunctionExpression(function) = statement.expression.without_parentheses()
    else {
        panic!("function")
    };
    let body = function.body.as_ref().unwrap();
    assert!(function_body_bindings(body, StrictMode::Sloppy).contains("nested"));
    for mode in [StrictMode::Strict, StrictMode::Unknown] {
        let names = function_body_bindings(body, mode);
        assert!(!names.contains("nested"));
        assert!(!names.contains("Local"));
    }
}
