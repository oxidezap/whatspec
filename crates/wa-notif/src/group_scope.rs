//! Conservative import binding qualification for the complete group handler.
//! Lexical bindings are over-approximated per function. A valid future lexical
//! refactor may require review; a shadowed/free loader is never guessed.
use oxc_ast::ast::{BindingIdentifier, CallExpression, Expression, Function, Statement};
use oxc_ast_visit::{Visit, walk};
use std::collections::BTreeSet;
use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit};

pub(crate) fn validate_import_bindings(
    statements: &[Statement<'_>],
    known_modules: impl Iterator<Item = String>,
) -> Result<(), String> {
    let aliases = crate::group_envelope::loader_aliases(statements)?;
    let [Statement::ExpressionStatement(es)] = statements else {
        return Err("module wrapper".into());
    };
    let call = as_call(&es.expression).ok_or("module wrapper call")?;
    let Some(Expression::ArrayExpression(deps)) = call.arguments.get(1).and_then(arg_expr) else {
        return Err("nonliteral dependencies".into());
    };
    let mut modules: BTreeSet<String> = known_modules.collect();
    for element in &deps.elements {
        let expression = element.as_expression().ok_or("spread/hole dependency")?;
        modules.insert(
            as_string_lit(expression)
                .ok_or("dynamic dependency")?
                .to_owned(),
        );
    }
    let Some(Expression::FunctionExpression(factory)) = call
        .arguments
        .get(2)
        .and_then(arg_expr)
        .map(Expression::without_parentheses)
    else {
        return Err("module factory".into());
    };
    #[derive(Default)]
    struct Bindings {
        names: BTreeSet<String>,
        assignments: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Bindings {
        fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
            self.names.insert(id.name.to_string());
        }
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if let Some(id) = &f.id {
                self.names.insert(id.name.to_string());
            }
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(name) = a.left.get_identifier_name() {
                self.assignments.insert(name.to_owned());
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    struct Check<'s> {
        aliases: BTreeSet<String>,
        modules: &'s BTreeSet<String>,
        errors: Vec<String>,
    }
    impl<'a> Visit<'a> for Check<'_> {
        fn visit_function(&mut self, f: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
            let mut bindings = Bindings::default();
            bindings.visit_formal_parameters(&f.params);
            if let Some(id) = &f.id {
                bindings.names.insert(id.name.to_string());
            }
            if let Some(body) = &f.body {
                bindings.visit_function_body(body);
            }
            let mut next = self.aliases.clone();
            for name in &bindings.names {
                next.remove(name);
            }
            if bindings.assignments.iter().any(|name| next.contains(name)) {
                self.errors
                    .push("module loader assigned through enclosing scope".into());
            }
            let previous = std::mem::replace(&mut self.aliases, next);
            walk::walk_function(self, f, flags);
            self.aliases = previous;
        }
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            if call
                .arguments
                .first()
                .and_then(arg_expr)
                .and_then(as_string_lit)
                .is_some_and(|name| self.modules.contains(name))
                && (call.arguments.len() != 1
                    || !as_identifier(&call.callee).is_some_and(|name| self.aliases.contains(name)))
            {
                self.errors
                    .push("module import uses an effectful, free or shadowed loader".into());
            }
            walk::walk_call_expression(self, call);
        }
    }
    let mut check = Check {
        aliases,
        modules: &modules,
        errors: vec![],
    };
    check.visit_function_body(factory.body.as_ref().ok_or("factory body")?);
    if check.errors.is_empty() {
        Ok(())
    } else {
        Err(check.errors.join("; "))
    }
}

/// An external action parser may only update the explicitly modeled marker.
/// Reject other writes into the envelope, including writes in nested closures.
pub(crate) fn validate_captured_writes(
    function: &Function<'_>,
    captured: &BTreeSet<String>,
    marker: Option<(&str, oxc_span::Span)>,
) -> Result<(), String> {
    #[derive(Default)]
    struct Locals(BTreeSet<String>);
    impl<'a> Visit<'a> for Locals {
        fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
            self.0.insert(id.name.to_string());
        }
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if let Some(id) = &f.id {
                self.0.insert(id.name.to_string());
            }
        }
    }
    let mut locals = Locals::default();
    locals.visit_formal_parameters(&function.params);
    if let Some(body) = &function.body {
        locals.visit_function_body(body);
    }
    if marker.is_some_and(|(name, _)| locals.0.contains(name)) {
        return Err("action marker is shadowed by a local".into());
    }
    let captured: BTreeSet<_> = captured.difference(&locals.0).cloned().collect();
    struct Writes<'s> {
        captured: &'s BTreeSet<String>,
        marker: Option<(&'s str, oxc_span::Span)>,
        invalid: bool,
    }
    impl<'a> Visit<'a> for Writes<'_> {
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if validate_captured_writes(f, self.captured, self.marker).is_err() {
                self.invalid = true;
            }
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(name) = a.left.get_identifier_name() {
                if self.captured.contains(name) && self.marker != Some((name, a.span)) {
                    self.invalid = true;
                }
            } else {
                self.invalid = true;
            }
            walk::walk_assignment_expression(self, a);
        }
        fn visit_update_expression(&mut self, _: &oxc_ast::ast::UpdateExpression<'a>) {
            self.invalid = true;
        }
    }
    let mut writes = Writes {
        captured: &captured,
        marker,
        invalid: false,
    };
    if let Some(body) = &function.body {
        writes.visit_function_body(body);
    }
    if writes.invalid {
        Err("external action/helper mutates the envelope".into())
    } else {
        Ok(())
    }
}
