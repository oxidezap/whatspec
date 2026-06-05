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
                && n.value <= i64::MAX as f64 =>
        {
            Some(n.value as i64)
        }
        // Minified negatives are `-N` (unary minus over a literal), e.g. proto
        // enum values like `-1`; fold them so they aren't silently dropped.
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            as_int(&u.argument).map(|v| -v)
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

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

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
        let ret = Parser::new(&alloc, "[7, 1.5, 9e30, -3];", SourceType::cjs()).parse();
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
        assert_eq!(el(3), Some(-3)); // unary minus is folded (proto enum negatives)
    }
}
