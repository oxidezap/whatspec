//! Conservative import binding qualification for the complete group handler.
//! Lexical bindings are over-approximated per function. A valid future lexical
//! refactor may require review; a shadowed/free loader is never guessed.
use oxc_ast::ast::{BindingIdentifier, CallExpression, Expression, Function, Statement};
use oxc_ast_visit::{Visit, walk};
use std::collections::BTreeSet;
use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit};

pub(crate) fn is_preserved_global(name: &str) -> bool {
    matches!(name, "Boolean" | "babelHelpers")
}

/// A qualified switch must not contain dynamic or duplicate case values that
/// can intercept an independently projected arm.
pub(crate) fn validate_dispatch_cases(
    switch: &oxc_ast::ast::SwitchStatement<'_>,
    resolver: &crate::actions::ConstResolver<'_>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for case in &switch.cases {
        // Case consequents share the switch's lexical environment. A binding
        // in an unrelated case can put a qualified arm's inputs in the TDZ.
        // Explicit nested blocks keep their own scope and are not rejected here.
        if case.consequent.iter().any(|statement| {
            let mut statement = statement;
            while let Statement::LabeledStatement(label) = statement {
                statement = &label.body;
            }
            match statement {
                Statement::VariableDeclaration(v) => !v.kind.is_var(),
                Statement::ClassDeclaration(_) | Statement::FunctionDeclaration(_) => true,
                _ => false,
            }
        }) {
            return Err("unqualified switch-wide lexical declaration".into());
        }
        if let Some(test) = &case.test {
            let value = as_string_lit(test)
                .map(str::to_owned)
                .or_else(|| resolver.resolve(test))
                .ok_or("unqualified dispatch case value")?;
            if !seen.insert(value) {
                return Err("duplicate dispatch case value".into());
            }
        }
    }
    Ok(())
}

/// Collect every identifier written by an assignment pattern, including nested,
/// default and rest targets. Expressions used as keys/defaults are checked by
/// the caller's normal expression traversal, not mistaken for target bindings.
pub(crate) fn assignment_names(target: &oxc_ast::ast::AssignmentTarget<'_>) -> BTreeSet<String> {
    #[derive(Default)]
    struct Targets(BTreeSet<String>);
    impl<'a> Visit<'a> for Targets {
        fn visit_simple_assignment_target(&mut self, t: &oxc_ast::ast::SimpleAssignmentTarget<'a>) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = t {
                self.0.insert(id.name.to_string());
            }
        }
        fn visit_assignment_target_property_identifier(
            &mut self,
            p: &oxc_ast::ast::AssignmentTargetPropertyIdentifier<'a>,
        ) {
            self.0.insert(p.binding.name.to_string());
        }
        fn visit_expression(&mut self, _: &Expression<'a>) {}
    }
    let mut targets = Targets::default();
    targets.visit_assignment_target(target);
    targets.0
}

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
        lexical: BTreeSet<String>,
        assignments: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Bindings {
        fn visit_variable_declaration(
            &mut self,
            declaration: &oxc_ast::ast::VariableDeclaration<'a>,
        ) {
            if declaration.kind.is_var() {
                walk::walk_variable_declaration(self, declaration);
            } else {
                let mut lexical = Bindings::default();
                walk::walk_variable_declaration(&mut lexical, declaration);
                self.lexical.extend(lexical.names);
                self.lexical.extend(lexical.lexical);
                self.assignments.extend(lexical.assignments);
            }
        }
        fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
            if let Some(parameter) = &clause.param {
                let mut names = Bindings::default();
                names.visit_binding_pattern(&parameter.pattern);
                self.lexical.extend(names.names);
                self.lexical.extend(names.lexical);
                self.assignments.extend(names.assignments);
            }
            self.visit_block_statement(&clause.body);
        }
        fn visit_class(&mut self, class: &oxc_ast::ast::Class<'a>) {
            let mut lexical = Bindings::default();
            walk::walk_class(&mut lexical, class);
            self.lexical.extend(lexical.names);
            self.lexical.extend(lexical.lexical);
            self.assignments.extend(lexical.assignments);
        }
        fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
            self.names.insert(id.name.to_string());
        }
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if let Some(id) = &f.id {
                self.lexical.insert(id.name.to_string());
            }
        }
        fn visit_update_expression(&mut self, u: &oxc_ast::ast::UpdateExpression<'a>) {
            if let Some(name) = u.argument.get_identifier_name() {
                self.assignments.insert(name.to_owned());
            }
            walk::walk_update_expression(self, u);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            self.assignments.extend(assignment_names(&a.left));
            walk::walk_assignment_expression(self, a);
        }
    }
    struct Check<'s> {
        aliases: BTreeSet<String>,
        modules: &'s BTreeSet<String>,
        errors: Vec<String>,
    }
    impl<'a> Visit<'a> for Check<'_> {
        fn visit_identifier_reference(&mut self, id: &oxc_ast::ast::IdentifierReference<'a>) {
            if id.name == "arguments" {
                self.errors
                    .push("arguments mappings and escapes require qualification".into());
            }
        }
        fn visit_unary_expression(&mut self, unary: &oxc_ast::ast::UnaryExpression<'a>) {
            if unary.operator == oxc_syntax::operator::UnaryOperator::Delete {
                self.errors
                    .push("property deletion requires effect qualification".into());
            }
            walk::walk_unary_expression(self, unary);
        }
        fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
            if is_preserved_global(id.name.as_str()) {
                self.errors.push(format!("global {} is shadowed", id.name));
            }
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if assignment_names(&a.left)
                .iter()
                .any(|name| is_preserved_global(name))
            {
                self.errors.push("preserved global is assigned".into());
            }
            walk::walk_assignment_expression(self, a);
        }
        fn visit_update_expression(&mut self, u: &oxc_ast::ast::UpdateExpression<'a>) {
            if u.argument
                .get_identifier_name()
                .is_some_and(is_preserved_global)
            {
                self.errors.push("preserved global is updated".into());
            }
            walk::walk_update_expression(self, u);
        }
        fn visit_for_of_statement(&mut self, _: &oxc_ast::ast::ForOfStatement<'a>) {
            self.errors
                .push("iteration assignment scopes require qualification".into());
        }
        fn visit_for_in_statement(&mut self, _: &oxc_ast::ast::ForInStatement<'a>) {
            self.errors
                .push("iteration assignment scopes require qualification".into());
        }
        fn visit_arrow_function_expression(
            &mut self,
            _: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.errors
                .push("arrow-function scope requires explicit qualification".into());
        }
        fn visit_function(&mut self, f: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
            if f.params.rest.is_some()
                || f.params.items.iter().any(|parameter| {
                    parameter.initializer.is_some()
                        || !matches!(
                            parameter.pattern,
                            oxc_ast::ast::BindingPattern::BindingIdentifier(_)
                        )
                })
            {
                self.errors
                    .push("non-simple parameter scopes require qualification".into());
                return;
            }
            let mut bindings = Bindings::default();
            bindings.visit_formal_parameters(&f.params);
            if let Some(id) = &f.id {
                bindings.names.insert(id.name.to_string());
            }
            if let Some(body) = &f.body {
                bindings.visit_function_body(body);
            }
            if !self.aliases.is_disjoint(&bindings.lexical) {
                self.errors
                    .push("lexical binding collides with captured module loader".into());
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
            if as_identifier(call.callee.without_parentheses()) == Some("eval") {
                self.errors
                    .push("direct eval can mutate lexical bindings".into());
            }
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
    struct Locals(BTreeSet<String>, BTreeSet<String>);
    impl<'a> Visit<'a> for Locals {
        fn visit_class(&mut self, class: &oxc_ast::ast::Class<'a>) {
            if let Some(id) = &class.id {
                self.1.insert(id.name.to_string());
            }
        }
        fn visit_arrow_function_expression(
            &mut self,
            _: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
        }
        fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
            self.0.insert(id.name.to_string());
        }
        fn visit_variable_declaration(&mut self, d: &oxc_ast::ast::VariableDeclaration<'a>) {
            if d.kind.is_var() {
                walk::walk_variable_declaration(self, d);
            } else {
                let mut names = Locals::default();
                walk::walk_variable_declaration(&mut names, d);
                self.1.extend(names.0);
                self.1.extend(names.1);
            }
        }
        fn visit_catch_clause(&mut self, c: &oxc_ast::ast::CatchClause<'a>) {
            if let Some(param) = &c.param {
                let mut names = Locals::default();
                names.visit_binding_pattern(&param.pattern);
                self.1.extend(names.0);
            }
            self.visit_block_statement(&c.body);
        }
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if let Some(id) = &f.id {
                self.1.insert(id.name.to_string());
            }
        }
    }
    if function.params.rest.is_some()
        || function.params.items.iter().any(|p| {
            p.initializer.is_some()
                || !matches!(
                    p.pattern,
                    oxc_ast::ast::BindingPattern::BindingIdentifier(_)
                )
        })
    {
        return Err("unsupported action/helper parameter pattern or initializer".into());
    }
    let mut locals = Locals::default();
    locals.visit_formal_parameters(&function.params);
    if let Some(body) = &function.body {
        locals.visit_function_body(body);
    }
    if !captured.is_disjoint(&locals.1) {
        return Err("lexical/catch binding collides with captured envelope state".into());
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
        fn visit_unary_expression(&mut self, unary: &oxc_ast::ast::UnaryExpression<'a>) {
            if unary.operator == oxc_syntax::operator::UnaryOperator::Delete {
                self.invalid = true;
            }
            walk::walk_unary_expression(self, unary);
        }
        fn visit_for_of_statement(&mut self, _: &oxc_ast::ast::ForOfStatement<'a>) {
            self.invalid = true;
        }
        fn visit_for_in_statement(&mut self, _: &oxc_ast::ast::ForInStatement<'a>) {
            self.invalid = true;
        }
        fn visit_arrow_function_expression(
            &mut self,
            _: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.invalid = true;
        }
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
