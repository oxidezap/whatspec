use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, Function, IdentifierReference, Statement};
use oxc_ast_visit::{Visit, walk};
use wa_oxc::{arg_expr, as_call, as_identifier, as_member, as_string_lit, callee_method};
use wa_transform::ModuleDefinition;

const METHODS: &[&str] = &["fetchQuery", "commitMutation", "fetchSubscription"];

pub(crate) fn module_loader_calls(program: &oxc_ast::ast::Program<'_>) -> HashSet<u32> {
    #[derive(Default)]
    struct Writes {
        names: HashSet<String>,
        shadowed: HashSet<String>,
        mode: wa_oxc::StrictMode,
    }
    impl Writes {
        fn mask(
            &mut self,
            params: &oxc_ast::ast::FormalParameters<'_>,
            body: Option<&oxc_ast::ast::FunctionBody<'_>>,
        ) {
            for parameter in &params.items {
                self.shadowed.extend(
                    parameter
                        .pattern
                        .get_binding_identifiers()
                        .iter()
                        .map(|id| id.name.to_string()),
                );
            }
            if let Some(rest) = &params.rest {
                self.shadowed.extend(
                    rest.rest
                        .argument
                        .get_binding_identifiers()
                        .iter()
                        .map(|id| id.name.to_string()),
                );
            }
            if let Some(body) = body {
                self.shadowed
                    .extend(wa_oxc::function_body_bindings(body, self.mode));
            }
        }
    }
    impl<'a> Visit<'a> for Writes {
        fn visit_simple_assignment_target(
            &mut self,
            target: &oxc_ast::ast::SimpleAssignmentTarget<'a>,
        ) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = target
                && !self.shadowed.contains(id.name.as_str())
            {
                self.names.insert(id.name.to_string());
            }
        }
        fn visit_function(
            &mut self,
            function: &Function<'a>,
            flags: oxc_syntax::scope::ScopeFlags,
        ) {
            let outer = self.shadowed.clone();
            let mode = self.mode;
            if let Some(body) = &function.body {
                self.mode = self.mode.for_body(body);
            }
            self.mask(&function.params, function.body.as_deref());
            if let Some(id) = &function.id {
                self.shadowed.insert(id.name.to_string());
            }
            walk::walk_function(self, function, flags);
            self.shadowed = outer;
            self.mode = mode;
        }
        fn visit_arrow_function_expression(
            &mut self,
            function: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            let outer = self.shadowed.clone();
            let mode = self.mode;
            self.mode = self.mode.for_body(&function.body);
            self.mask(&function.params, Some(&function.body));
            walk::walk_arrow_function_expression(self, function);
            self.shadowed = outer;
            self.mode = mode;
        }
        fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
            let outer = self.shadowed.clone();
            self.shadowed.extend(wa_oxc::block_bindings(&block.body));
            walk::walk_block_statement(self, block);
            self.shadowed = outer;
        }
        fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
            let outer = self.shadowed.clone();
            if let Some(parameter) = &clause.param {
                self.shadowed.extend(
                    parameter
                        .pattern
                        .get_binding_identifiers()
                        .iter()
                        .map(|id| id.name.to_string()),
                );
            }
            walk::walk_catch_clause(self, clause);
            self.shadowed = outer;
        }
    }
    #[derive(Default)]
    struct Loaders {
        names: HashSet<String>,
        calls: HashSet<u32>,
        factory: Option<u32>,
        mode: wa_oxc::StrictMode,
    }
    impl Loaders {
        fn mask(
            &mut self,
            params: &oxc_ast::ast::FormalParameters<'_>,
            body: Option<&oxc_ast::ast::FunctionBody<'_>>,
        ) {
            for parameter in &params.items {
                for id in parameter.pattern.get_binding_identifiers() {
                    self.names.remove(id.name.as_str());
                }
            }
            if let Some(rest) = &params.rest {
                for id in rest.rest.argument.get_binding_identifiers() {
                    self.names.remove(id.name.as_str());
                }
            }
            if let Some(body) = body {
                self.mask_body(body);
            }
        }
        fn mask_body(&mut self, body: &oxc_ast::ast::FunctionBody<'_>) {
            let bound = wa_oxc::function_body_bindings(body, self.mode);
            let mut writes = Writes {
                mode: self.mode,
                ..Default::default()
            };
            writes.visit_function_body(body);
            self.names
                .retain(|name| !bound.contains(name) && !writes.names.contains(name));
        }
    }
    impl<'a> Visit<'a> for Loaders {
        fn visit_function(
            &mut self,
            function: &Function<'a>,
            flags: oxc_syntax::scope::ScopeFlags,
        ) {
            let outer = self.names.clone();
            let mode = self.mode;
            if let Some(body) = &function.body {
                self.mode = self.mode.for_body(body);
            }
            if self.factory == Some(function.span.start) {
                self.names = function
                    .params
                    .items
                    .iter()
                    .skip(1)
                    .take(4)
                    .filter(|parameter| parameter.initializer.is_none())
                    .filter_map(|parameter| {
                        parameter
                            .pattern
                            .get_identifier_name()
                            .map(|name| name.to_string())
                    })
                    .collect();
                if let Some(body) = &function.body {
                    self.mask_body(body);
                }
            } else {
                self.mask(&function.params, function.body.as_deref());
                if let Some(id) = &function.id {
                    self.names.remove(id.name.as_str());
                }
            }
            walk::walk_function(self, function, flags);
            self.names = outer;
            self.mode = mode;
        }
        fn visit_arrow_function_expression(
            &mut self,
            function: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            let outer = self.names.clone();
            let mode = self.mode;
            self.mode = self.mode.for_body(&function.body);
            self.mask(&function.params, Some(&function.body));
            walk::walk_arrow_function_expression(self, function);
            self.names = outer;
            self.mode = mode;
        }
        fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
            let outer = self.names.clone();
            let bound = wa_oxc::block_bindings(&block.body);
            self.names.retain(|name| !bound.contains(name));
            walk::walk_block_statement(self, block);
            self.names = outer;
        }
        fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
            let outer = self.names.clone();
            if let Some(parameter) = &clause.param {
                for id in parameter.pattern.get_binding_identifiers() {
                    self.names.remove(id.name.as_str());
                }
            }
            walk::walk_catch_clause(self, clause);
            self.names = outer;
        }
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            let outer_factory = self.factory;
            if as_identifier(&call.callee) == Some(wa_oxc::DEFINE_FN)
                && let Some(Expression::FunctionExpression(function)) = call
                    .arguments
                    .get(2)
                    .and_then(arg_expr)
                    .map(Expression::without_parentheses)
            {
                self.factory = Some(function.span.start);
            }
            if call.arguments.len() == 1
                && as_identifier(&call.callee).is_some_and(|name| self.names.contains(name))
                && call
                    .arguments
                    .first()
                    .and_then(arg_expr)
                    .and_then(as_string_lit)
                    .is_some()
            {
                self.calls.insert(call.span.start);
            }
            walk::walk_call_expression(self, call);
            self.factory = outer_factory;
        }
    }
    let mut loaders = Loaders {
        mode: if program.has_use_strict_directive() {
            wa_oxc::StrictMode::Strict
        } else {
            wa_oxc::StrictMode::Sloppy
        },
        ..Default::default()
    };
    loaders.visit_program(program);
    loaders.calls
}

#[derive(Default)]
pub(crate) struct Transports(HashSet<(String, String)>);

impl Transports {
    pub(crate) fn is_transport(&self, call: &CallExpression, loaders: &HashSet<u32>) -> bool {
        if callee_method(call).is_some_and(|method| METHODS.contains(&method)) {
            return true;
        }
        let Some((owner, method)) = as_member(&call.callee) else {
            return false;
        };
        let Some(module) = as_call(owner)
            .filter(|call| loaders.contains(&call.span.start))
            .and_then(|call| call.arguments.first())
            .and_then(arg_expr)
            .and_then(as_string_lit)
        else {
            return false;
        };
        self.0.contains(&(module.to_string(), method.to_string()))
    }

    pub(crate) fn build(source: &str, definitions: &[ModuleDefinition]) -> Self {
        let mut transports = Self::default();
        loop {
            let before = transports.0.len();
            let mut seen = HashSet::new();
            for definition in definitions {
                if !seen.insert(&definition.name) {
                    continue;
                }
                let slice = &source[definition.start..definition.end];
                if !METHODS.iter().any(|method| slice.contains(method))
                    && !definition.deps.iter().any(|dependency| {
                        transports.0.iter().any(|(module, _)| module == dependency)
                    })
                {
                    continue;
                }
                let allocator = Allocator::default();
                let parsed =
                    wa_oxc::parse_cjs(&allocator, &source[definition.start..definition.end]);
                let loaders = module_loader_calls(&parsed.program);
                let Some(factory) = parsed.program.body.iter().find_map(|statement| {
                    let Statement::ExpressionStatement(statement) = statement else {
                        return None;
                    };
                    let call = as_call(&statement.expression)?;
                    let Expression::FunctionExpression(factory) = call
                        .arguments
                        .get(2)
                        .and_then(arg_expr)?
                        .without_parentheses()
                    else {
                        return None;
                    };
                    Some(factory)
                }) else {
                    continue;
                };
                let Some(body) = &factory.body else { continue };
                let mut functions: HashMap<_, _> = body
                    .statements
                    .iter()
                    .filter_map(|statement| {
                        let Statement::FunctionDeclaration(function) = statement else {
                            return None;
                        };
                        Some((function.id.as_ref()?.name.as_str(), function.as_ref()))
                    })
                    .collect();
                let declared_functions = body
                    .statements
                    .iter()
                    .filter(|statement| matches!(statement, Statement::FunctionDeclaration(_)))
                    .count();
                if declared_functions != functions.len() {
                    continue;
                }
                let receivers: HashSet<_> = factory
                    .params
                    .items
                    .get(6)
                    .into_iter()
                    .filter_map(|p| p.pattern.get_identifier_name().map(|name| name.to_string()))
                    .collect();
                struct Exports {
                    receivers: HashSet<String>,
                    exports: HashMap<String, Option<String>>,
                    rewritten: HashSet<String>,
                    shadowed: HashSet<String>,
                    loaders: HashSet<String>,
                    opaque: bool,
                    mode: wa_oxc::StrictMode,
                }
                impl<'a> Visit<'a> for Exports {
                    fn visit_function(
                        &mut self,
                        _: &Function<'a>,
                        _: oxc_syntax::scope::ScopeFlags,
                    ) {
                    }
                    fn visit_arrow_function_expression(
                        &mut self,
                        _: &oxc_ast::ast::ArrowFunctionExpression<'a>,
                    ) {
                    }
                    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
                        let outer = self.shadowed.clone();
                        self.shadowed.extend(wa_oxc::block_bindings(&block.body));
                        walk::walk_block_statement(self, block);
                        self.shadowed = outer;
                    }
                    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
                        let outer = self.shadowed.clone();
                        if let Some(parameter) = &clause.param {
                            self.shadowed.extend(
                                parameter
                                    .pattern
                                    .get_binding_identifiers()
                                    .iter()
                                    .map(|id| id.name.to_string()),
                            );
                        }
                        self.visit_block_statement(&clause.body);
                        self.shadowed = outer;
                    }
                    fn visit_new_expression(&mut self, _: &oxc_ast::ast::NewExpression<'a>) {
                        self.opaque = true;
                    }
                    fn visit_update_expression(
                        &mut self,
                        update: &oxc_ast::ast::UpdateExpression<'a>,
                    ) {
                        if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(
                            id,
                        ) = &update.argument
                        {
                            if !self.shadowed.contains(id.name.as_str()) {
                                self.rewritten.insert(id.name.to_string());
                            }
                        } else {
                            self.opaque = true;
                        }
                        walk::walk_update_expression(self, update);
                    }
                    fn visit_for_of_statement(
                        &mut self,
                        statement: &oxc_ast::ast::ForOfStatement<'a>,
                    ) {
                        let outer = self.shadowed.clone();
                        if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) =
                            &statement.left
                        {
                            for binding in &declaration.declarations {
                                for id in binding.id.get_binding_identifiers() {
                                    if declaration.kind.is_var() {
                                        if !self.shadowed.contains(id.name.as_str()) {
                                            self.rewritten.insert(id.name.to_string());
                                        }
                                    } else {
                                        self.shadowed.insert(id.name.to_string());
                                    }
                                }
                            }
                        } else if let Some(target) = statement.left.as_assignment_target() {
                            self.opaque |= wa_oxc::assignment_target_has_member(target);
                            for name in wa_oxc::assignment_target_names(target) {
                                if !self.shadowed.contains(&name) {
                                    self.rewritten.insert(name);
                                }
                            }
                        }
                        walk::walk_for_of_statement(self, statement);
                        self.shadowed = outer;
                    }
                    fn visit_for_in_statement(
                        &mut self,
                        statement: &oxc_ast::ast::ForInStatement<'a>,
                    ) {
                        let outer = self.shadowed.clone();
                        if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) =
                            &statement.left
                        {
                            for binding in &declaration.declarations {
                                for id in binding.id.get_binding_identifiers() {
                                    if declaration.kind.is_var() {
                                        if !self.shadowed.contains(id.name.as_str()) {
                                            self.rewritten.insert(id.name.to_string());
                                        }
                                    } else {
                                        self.shadowed.insert(id.name.to_string());
                                    }
                                }
                            }
                        } else if let Some(target) = statement.left.as_assignment_target() {
                            self.opaque |= wa_oxc::assignment_target_has_member(target);
                            for name in wa_oxc::assignment_target_names(target) {
                                if !self.shadowed.contains(&name) {
                                    self.rewritten.insert(name);
                                }
                            }
                        }
                        walk::walk_for_in_statement(self, statement);
                        self.shadowed = outer;
                    }
                    fn visit_class(&mut self, _: &oxc_ast::ast::Class<'a>) {
                        self.opaque = true;
                    }
                    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
                        walk::walk_call_expression(self, call);
                        let Some(function) = wa_oxc::directly_invoked_function(call) else {
                            let loader = as_identifier(&call.callee).is_some_and(|name| {
                                self.loaders.contains(name) && !self.shadowed.contains(name)
                            });
                            self.opaque |= !loader
                                || call.arguments.len() != 1
                                || call
                                    .arguments
                                    .first()
                                    .and_then(arg_expr)
                                    .and_then(as_string_lit)
                                    .is_none();
                            return;
                        };
                        let (parameters, body, name, generator): (
                            &oxc_ast::ast::FormalParameters<'a>,
                            Option<&oxc_ast::ast::FunctionBody<'a>>,
                            Option<&str>,
                            bool,
                        ) = match function {
                            Expression::FunctionExpression(function) => (
                                &function.params,
                                function.body.as_ref().map(|body| body.as_ref()),
                                function.id.as_ref().map(|id| id.name.as_str()),
                                function.generator,
                            ),
                            Expression::ArrowFunctionExpression(function) => {
                                (&function.params, Some(&function.body), None, false)
                            }
                            _ => return,
                        };
                        let outer = self.shadowed.clone();
                        let outer_mode = self.mode;
                        if let Some(body) = body {
                            self.mode = self.mode.for_body(body);
                        }
                        if let Some(name) = name {
                            self.shadowed.insert(name.to_string());
                        }
                        for parameter in &parameters.items {
                            self.shadowed.extend(
                                parameter
                                    .pattern
                                    .get_binding_identifiers()
                                    .iter()
                                    .map(|id| id.name.to_string()),
                            );
                        }
                        if let Some(rest) = &parameters.rest {
                            self.shadowed.extend(
                                rest.rest
                                    .argument
                                    .get_binding_identifiers()
                                    .iter()
                                    .map(|id| id.name.to_string()),
                            );
                        }
                        self.visit_formal_parameters(parameters);
                        if !generator && let Some(body) = body {
                            self.shadowed
                                .extend(wa_oxc::function_body_bindings(body, self.mode));
                            self.visit_function_body(body);
                        }
                        self.shadowed = outer;
                        self.mode = outer_mode;
                    }
                    fn visit_variable_declarator(
                        &mut self,
                        binding: &oxc_ast::ast::VariableDeclarator<'a>,
                    ) {
                        if binding.init.is_some() {
                            for identifier in binding.id.get_binding_identifiers() {
                                if !self.shadowed.contains(identifier.name.as_str()) {
                                    self.rewritten.insert(identifier.name.to_string());
                                }
                            }
                        }
                        walk::walk_variable_declarator(self, binding);
                    }
                    fn visit_assignment_expression(
                        &mut self,
                        assignment: &oxc_ast::ast::AssignmentExpression<'a>,
                    ) {
                        for name in wa_oxc::assignment_target_names(&assignment.left) {
                            if !self.shadowed.contains(&name) {
                                self.rewritten.insert(name);
                            }
                        }
                        self.opaque |= wa_oxc::assignment_target_has_member(&assignment.left)
                            && assignment.left.as_member_expression().is_none();
                        if let Some(member) = assignment.left.as_member_expression()
                            && let Some(receiver) = member.object().get_identifier_reference()
                            && self.receivers.contains(receiver.name.as_str())
                            && !self.shadowed.contains(receiver.name.as_str())
                            && let Some(name) = member.static_property_name()
                        {
                            let local = as_identifier(&assignment.right)
                                .filter(|name| !self.shadowed.contains(*name))
                                .map(str::to_string);
                            self.exports
                                .entry(name.to_string())
                                .and_modify(|previous| {
                                    if *previous != local {
                                        *previous = None;
                                    }
                                })
                                .or_insert(local);
                        }
                        if let Some(member) = assignment.left.as_member_expression() {
                            self.opaque |= member.static_property_name().is_none();
                            self.opaque |=
                                !member
                                    .object()
                                    .get_identifier_reference()
                                    .is_some_and(|id| {
                                        self.receivers.contains(id.name.as_str())
                                            && !self.shadowed.contains(id.name.as_str())
                                    });
                        }
                        walk::walk_assignment_expression(self, assignment);
                    }
                }
                let mut exports = Exports {
                    receivers,
                    exports: HashMap::new(),
                    rewritten: HashSet::new(),
                    shadowed: HashSet::new(),
                    loaders: factory
                        .params
                        .items
                        .iter()
                        .skip(1)
                        .take(3)
                        .filter_map(|parameter| {
                            parameter
                                .pattern
                                .get_identifier_name()
                                .map(|name| name.to_string())
                        })
                        .collect(),
                    opaque: false,
                    mode: if parsed.program.has_use_strict_directive() {
                        wa_oxc::StrictMode::Strict
                    } else {
                        wa_oxc::StrictMode::Sloppy
                    }
                    .for_body(body),
                };
                exports.visit_function_body(body);
                if exports.opaque
                    || exports.receivers.iter().any(|receiver| {
                        exports.rewritten.contains(receiver)
                            || functions.contains_key(receiver.as_str())
                    })
                {
                    continue;
                }
                functions.retain(|name, _| !exports.rewritten.contains(*name));
                for (export, local) in exports.exports {
                    let Some(local) = local else { continue };
                    if functions.get(local.as_str()).is_some_and(|function| {
                        forwards(
                            function,
                            &functions,
                            &transports,
                            &loaders,
                            &mut HashSet::new(),
                        )
                    }) {
                        transports.0.insert((definition.name.clone(), export));
                    }
                }
            }
            if transports.0.len() == before {
                return transports;
            }
        }
    }
}

fn forwards<'a>(
    function: &Function<'a>,
    functions: &HashMap<&str, &Function<'a>>,
    transports: &Transports,
    loaders: &HashSet<u32>,
    visiting: &mut HashSet<String>,
) -> bool {
    if function.generator {
        return false;
    }
    let Some(body) = &function.body else {
        return false;
    };
    let name = function
        .id
        .as_ref()
        .map(|id| id.name.to_string())
        .unwrap_or_default();
    if visiting.len() >= 32 || !visiting.insert(name.clone()) {
        return false;
    }
    let result = direct(function, transports, loaders)
        || (|| {
            let [Statement::ReturnStatement(ret)] = body.statements.as_slice() else {
                return false;
            };
            let Some(expression) = ret.argument.as_ref() else {
                return false;
            };
            if let Some(target) = apply_target(expression) {
                if function.params.rest.is_some()
                    || function.params.items.iter().any(|parameter| {
                        parameter.initializer.is_some()
                            || parameter.pattern.get_binding_identifiers().iter().any(
                                |identifier| {
                                    identifier.name == target || identifier.name == "arguments"
                                },
                            )
                    })
                {
                    return false;
                }
                return functions.get(target).is_some_and(|function| {
                    forwards(function, functions, transports, loaders, visiting)
                });
            }
            if !function.params.items.is_empty() || function.params.rest.is_some() {
                return false;
            }
            let Expression::SequenceExpression(sequence) = expression.without_parentheses() else {
                return false;
            };
            let [Expression::AssignmentExpression(assignment), apply] =
                sequence.expressions.as_slice()
            else {
                return false;
            };
            if wa_oxc::assignment_target_name(&assignment.left) != Some(name.as_str())
                || apply_target(apply) != Some(name.as_str())
            {
                return false;
            }
            let Some(call) = as_call(&assignment.right) else {
                return false;
            };
            let runtime = as_member(&call.callee)
                .and_then(|(owner, _)| as_call(owner))
                .and_then(|owner| owner.arguments.first())
                .and_then(arg_expr)
                .and_then(as_string_lit);
            if runtime != Some("asyncToGeneratorRuntime")
                || callee_method(call) != Some("asyncToGenerator")
                || call.arguments.len() != 1
            {
                return false;
            }
            let Some(Expression::FunctionExpression(generator)) =
                call.arguments.first().and_then(arg_expr)
            else {
                return false;
            };
            !generator.r#async && direct(generator, transports, loaders)
        })();
    visiting.remove(&name);
    result
}

fn apply_target<'b>(expression: &'b Expression<'_>) -> Option<&'b str> {
    let call = as_call(expression)?;
    let (target, method) = as_member(&call.callee)?;
    if method != "apply"
        || call.arguments.len() != 2
        || !matches!(
            call.arguments.first().and_then(arg_expr),
            Some(Expression::ThisExpression(_))
        )
        || call
            .arguments
            .get(1)
            .and_then(arg_expr)
            .and_then(as_identifier)
            != Some("arguments")
    {
        return None;
    }
    as_identifier(target)
}

fn direct(function: &Function, transports: &Transports, loaders: &HashSet<u32>) -> bool {
    if function.params.items.len() != 2 {
        return false;
    }
    let params = function
        .params
        .items
        .iter()
        .map(|parameter| match &parameter.pattern {
            oxc_ast::ast::BindingPattern::BindingIdentifier(identifier)
                if parameter.initializer.is_none() =>
            {
                Some(identifier.name)
            }
            _ => None,
        })
        .collect::<Option<Vec<_>>>();
    let Some(params) = params else { return false };
    if params.len() != 2 || function.params.rest.is_some() {
        return false;
    }
    if let Some(body) = &function.body {
        let bindings = wa_oxc::function_body_bindings(body, wa_oxc::StrictMode::Sloppy);
        if params.iter().any(|name| bindings.contains(name.as_str())) {
            return false;
        }
    }
    struct Probe<'s> {
        params: [&'s str; 2],
        reads: [usize; 2],
        shadowed: [bool; 2],
        sends: usize,
        suspended: bool,
        invalid: bool,
        transports: &'s Transports,
        loaders: &'s HashSet<u32>,
    }
    impl<'a> Visit<'a> for Probe<'_> {
        fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
            let outer = self.shadowed;
            let names = wa_oxc::block_bindings(&block.body);
            for (index, name) in self.params.iter().enumerate() {
                self.shadowed[index] |= names.contains(*name);
            }
            walk::walk_block_statement(self, block);
            self.shadowed = outer;
        }
        fn visit_function(
            &mut self,
            function: &Function<'a>,
            flags: oxc_syntax::scope::ScopeFlags,
        ) {
            let before = (self.reads, self.sends);
            let outer = self.shadowed;
            let suspended = self.suspended;
            for parameter in &function.params.items {
                for identifier in parameter.pattern.get_binding_identifiers() {
                    for (index, name) in self.params.iter().enumerate() {
                        self.shadowed[index] |= identifier.name == *name;
                    }
                }
            }
            walk::walk_function(self, function, flags);
            self.shadowed = outer;
            self.suspended = suspended;
            self.invalid |= before != (self.reads, self.sends);
        }
        fn visit_arrow_function_expression(
            &mut self,
            function: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            let before = (self.reads, self.sends);
            let suspended = self.suspended;
            walk::walk_arrow_function_expression(self, function);
            self.suspended = suspended;
            self.invalid |= before != (self.reads, self.sends);
        }
        fn visit_statement(&mut self, statement: &Statement<'a>) {
            let sends = self.sends;
            walk::walk_statement(self, statement);
            if matches!(
                statement,
                Statement::WhileStatement(_)
                    | Statement::DoWhileStatement(_)
                    | Statement::ForStatement(_)
                    | Statement::ForInStatement(_)
                    | Statement::ForOfStatement(_)
            ) && self.sends != sends
            {
                self.invalid = true;
            }
        }
        fn visit_for_of_statement(&mut self, statement: &oxc_ast::ast::ForOfStatement<'a>) {
            walk::walk_for_of_statement(self, statement);
            self.suspended |= statement.r#await;
        }
        fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
            let outer = self.shadowed;
            if let Some(parameter) = &clause.param {
                for identifier in parameter.pattern.get_binding_identifiers() {
                    for (index, name) in self.params.iter().enumerate() {
                        self.shadowed[index] |= identifier.name == *name;
                    }
                }
            }
            self.visit_block_statement(&clause.body);
            self.shadowed = outer;
        }
        fn visit_await_expression(&mut self, expression: &oxc_ast::ast::AwaitExpression<'a>) {
            walk::walk_await_expression(self, expression);
            self.suspended = true;
        }
        fn visit_yield_expression(&mut self, expression: &oxc_ast::ast::YieldExpression<'a>) {
            walk::walk_yield_expression(self, expression);
            self.suspended = true;
        }
        fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
            for (index, param) in self.params.iter().enumerate() {
                if !self.shadowed[index] && reference.name == *param {
                    self.reads[index] += 1;
                }
            }
            self.invalid |= reference.name == "arguments";
        }
        fn visit_variable_declarator(&mut self, binding: &oxc_ast::ast::VariableDeclarator<'a>) {
            self.invalid |= binding
                .id
                .get_binding_identifiers()
                .iter()
                .any(|id| self.params.contains(&id.name.as_str()));
            walk::walk_variable_declarator(self, binding);
        }
        fn visit_assignment_expression(
            &mut self,
            assignment: &oxc_ast::ast::AssignmentExpression<'a>,
        ) {
            let written = wa_oxc::assignment_target_names(&assignment.left);
            self.invalid |= self
                .params
                .iter()
                .enumerate()
                .any(|(index, name)| !self.shadowed[index] && written.contains(*name));
            walk::walk_assignment_expression(self, assignment);
        }
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            let forward = self.transports.is_transport(call, self.loaders)
                && call
                    .arguments
                    .first()
                    .and_then(arg_expr)
                    .and_then(as_identifier)
                    == Some(self.params[0])
                && call
                    .arguments
                    .get(1)
                    .and_then(arg_expr)
                    .and_then(as_identifier)
                    == Some(self.params[1]);
            walk::walk_call_expression(self, call);
            if forward {
                self.sends += 1;
                self.invalid |= self.suspended || self.shadowed.iter().any(|shadowed| *shadowed);
            }
        }
    }
    let mut probe = Probe {
        params: [params[0].as_str(), params[1].as_str()],
        reads: [0, 0],
        shadowed: [false, false],
        sends: 0,
        suspended: false,
        invalid: false,
        transports,
        loaders,
    };
    if let Some(body) = &function.body {
        probe.visit_function_body(body);
    }
    probe.sends == 1 && probe.reads == [1, 1] && !probe.invalid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_direct_and_lowered_async_transports_by_their_bodies() {
        for functions in [
            r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}"#,
            r#"async function send(op,vars){return await o("Relay").fetchQuery(op,vars)}"#,
            r#"function send(op,vars){return next.apply(this,arguments)}function next(op,vars){return o("Relay").commitMutation(op,vars)}"#,
            r#"function send(op,vars){return next.apply(this,arguments)}function next(){return next=n("asyncToGeneratorRuntime").asyncToGenerator(function*(op,vars){var reader=null,result=yield o("Relay").fetchQuery(op,vars,{reader:function(value){reader=value}});return {reader:reader,result:result}}),next.apply(this,arguments)}"#,
        ] {
            let source = format!(
                r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{{functions}l.arbitraryName=send;}});"#
            );
            let definitions = wa_transform::extract_module_definitions(&source);
            let transports = Transports::build(&source, &definitions);
            assert!(
                transports
                    .0
                    .contains(&("Wrapper".into(), "arbitraryName".into()))
            );
        }
    }

    #[test]
    fn refuses_transformed_rebound_unused_and_cyclic_forwarders() {
        for body in [
            r#"return o("Relay").fetchQuery(op,{input:vars})"#,
            r#"vars={};return o("Relay").fetchQuery(op,vars)"#,
            r#"mutate(vars);return o("Relay").fetchQuery(op,vars)"#,
            r#"return o("Relay").fetchQuery(vars,op)"#,
            r#"function unused(op,vars){return o("Relay").fetchQuery(op,vars)}return null"#,
            r#"return send.apply(this,arguments)"#,
        ] {
            let source = format!(
                r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{{body}}}l.arbitraryName=send;}});"#
            );
            let definitions = wa_transform::extract_module_definitions(&source);
            assert!(
                Transports::build(&source, &definitions).0.is_empty(),
                "{body}"
            );
        }
    }
}

#[cfg(test)]
#[test]
fn qualifies_current_event_client_without_pinning_its_export_names() {
    let source = include_str!(
        "../../../tests/fixtures/bundles-1054751086/WAWebSharableEventServerClient.js"
    );
    let definitions = wa_transform::extract_module_definitions(source);
    let transports = Transports::build(source, &definitions);
    assert!(transports.0.contains(&(
        "WAWebSharableEventServerClient".into(),
        "querySharableEventServer".into()
    )));
    assert!(transports.0.contains(&(
        "WAWebSharableEventServerClient".into(),
        "mutateSharableEventServer".into()
    )));
}

#[cfg(test)]
#[test]
fn rewritten_helpers_and_exports_cannot_qualify_a_transport() {
    for tail in [
        "send=unknown;l.custom=send;",
        "l.custom=send;l.custom=unknown;",
        "l.custom=send;l.custom=function(){};",
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{return o("Relay").fetchQuery(op,vars)}}{tail}}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{tail}"
        );
    }
}

#[cfg(test)]
#[test]
fn destructuring_cannot_shift_transport_parameter_positions() {
    for parameters in [
        "op,{meta},vars",
        "op,vars={input:1}",
        "op,{vars}",
        "op,...vars",
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send({parameters}){{return o("Relay").fetchQuery(op,vars)}}l.custom=send;}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{parameters}"
        );
    }
}

#[cfg(test)]
#[test]
fn suspended_lazy_rebound_and_shadowed_wrappers_are_not_transports() {
    for functions in [
        r#"async function send(op,vars){await ready();return o("Relay").fetchQuery(op,vars)}"#,
        r#"async function send(op,vars){return o("Relay").fetchQuery(op,vars,await ready())}"#,
        r#"function send(op,vars){return next.apply(this,arguments)}function next(){return next=n("asyncToGeneratorRuntime").asyncToGenerator(function*(op,vars){yield ready();return o("Relay").fetchQuery(op,vars)}),next.apply(this,arguments)}"#,
        r#"function* send(op,vars){return o("Relay").fetchQuery(op,vars)}"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}var send=unknown;"#,
        r#"function next(op,vars){return o("Relay").fetchQuery(op,vars)}function send(next,vars){return next.apply(this,arguments)}"#,
        r#"function next(op,vars){return o("Relay").fetchQuery(op,vars)}function send(op,vars,next){return next.apply(this,arguments)}"#,
    ] {
        let source =
            format!(r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{{functions}l.custom=send;}});"#);
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{functions}"
        );
    }
}

#[cfg(test)]
#[test]
fn generator_apply_forwarders_do_not_run_when_called() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){function next(op,vars){return o("Relay").fetchQuery(op,vars)}function* send(op,vars){return next.apply(this,arguments)}l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(Transports::build(source, &definitions).0.is_empty());
}

#[cfg(test)]
#[test]
fn an_explicit_arguments_parameter_cannot_forward_the_implicit_argument_list() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){function next(op,vars){return o("Relay").fetchQuery(op,vars)}function send(op,vars,arguments){return next.apply(this,arguments)}l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(Transports::build(source, &definitions).0.is_empty());
}

#[cfg(test)]
#[test]
fn block_local_helpers_do_not_replace_outer_transports() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){function send(op,vars){return o("Relay").fetchQuery(op,vars)}{let send=unknown;}l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(
        Transports::build(source, &definitions)
            .0
            .contains(&("Wrapper".into(), "custom".into()))
    );
}

#[cfg(test)]
#[test]
fn asynchronous_iteration_and_loop_backedges_cannot_delay_forwarding() {
    for body in [
        r#"for await(const value of stream){}return o("Relay").fetchQuery(op,vars)"#,
        r#"while(again()){o("Relay").fetchQuery(op,vars);await ready()}"#,
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{async function send(op,vars){{{body}}}l.custom=send;}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{body}"
        );
    }
}

#[cfg(test)]
#[test]
fn ordinary_iteration_before_forwarding_remains_synchronous() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){async function send(op,vars){for(const value of values){}return o("Relay").fetchQuery(op,vars)}l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(
        Transports::build(source, &definitions)
            .0
            .contains(&("Wrapper".into(), "custom".into()))
    );
}

#[cfg(test)]
#[test]
fn caught_values_cannot_replace_forwarded_parameters() {
    for parameter in ["op", "vars"] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{try{{throw marker}}catch({parameter}){{return o("Relay").fetchQuery(op,vars)}}}}l.custom=send;}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{parameter}"
        );
    }
}

#[cfg(test)]
#[test]
fn catch_shadowing_in_deferred_code_does_not_replace_outer_arguments() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){function send(op,vars){function logger(){try{}catch(vars){log(vars)}}return o("Relay").fetchQuery(op,vars)}l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(
        Transports::build(source, &definitions)
            .0
            .contains(&("Wrapper".into(), "custom".into()))
    );
}

#[cfg(test)]
#[test]
fn immediately_invoked_functions_cannot_hide_helper_replacements() {
    for replacement in [
        r#"(()=>{send=changed})()"#,
        r#"(function(){send=changed})()"#,
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{return o("Relay").fetchQuery(op,vars)}}{replacement};l.custom=send;}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{replacement}"
        );
    }
}

#[cfg(test)]
#[test]
fn immediate_calls_respect_local_bindings_and_generator_initialization() {
    for (invocation, qualified) in [
        (r#"(function(){var send=changed})()"#, true),
        (r#"((send)=>{send=changed})(value)"#, true),
        (r#"(function*(){send=changed})()"#, true),
        (r#"(function*(x=(send=changed)){})()"#, false),
        (r#"(function(x=(send=changed)){var send})()"#, false),
        (r#"(()=>()=>{send=changed})()()"#, false),
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{return o("Relay").fetchQuery(op,vars)}}{invocation};l.custom=send;}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert_eq!(
            Transports::build(&source, &definitions)
                .0
                .contains(&("Wrapper".into(), "custom".into())),
            qualified,
            "{invocation}"
        );
    }
}

#[cfg(test)]
#[test]
fn declarations_and_factory_effects_cannot_replace_forwarders_silently() {
    for setup in [
        r#"function send(op,vars){function vars(){}return o("Relay").fetchQuery(op,vars)}"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}function mutate(){send=changed}new mutate();"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}for(send of [changed]){}"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}for(send in values){}"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}[send]=[changed];"#,
        r#"function send(op,vars){return o("Relay").fetchQuery(op,vars)}l={};"#,
    ] {
        let source =
            format!(r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{{setup}l.custom=send;}});"#);
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{setup}"
        );
    }
}

#[cfg(test)]
#[test]
fn strict_block_functions_do_not_hide_outer_helper_replacements() {
    let source = r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){function send(op,vars){return o("Relay").fetchQuery(op,vars)}(function(){"use strict";{function send(){}}send=changed})();l.custom=send;});"#;
    let definitions = wa_transform::extract_module_definitions(source);
    assert!(Transports::build(source, &definitions).0.is_empty());
}

#[cfg(test)]
#[test]
fn review_dynamic_exports_and_sloppy_block_functions_cannot_qualify() {
    for body in [
        r#"l.custom=send;l[key]=changed;"#,
        r#"(function(){{function send(){}}l.custom=send})();"#,
    ] {
        let source = format!(
            r#"__d("Wrapper",[],function(t,n,r,o,a,i,l){{function send(op,vars){{return o("Relay").fetchQuery(op,vars)}}{body}}});"#
        );
        let definitions = wa_transform::extract_module_definitions(&source);
        assert!(
            Transports::build(&source, &definitions).0.is_empty(),
            "{body}"
        );
    }
}

#[cfg(test)]
#[test]
fn module_loaders_respect_nested_bindings_and_captured_writes() {
    for (setup, expected) in [
        ("function local(o){o=changed}", true),
        ("function local(){o=changed}", false),
        (
            r#"(function(){"use strict";{function o(){}}o=changed})()"#,
            false,
        ),
        ("", true),
    ] {
        let source = format!(
            r#"__d("Job",[],function(t,n,r,o,a,i,l){{{setup}function run(){{return o("Transport").send(handle,vars)}}}});"#
        );
        let allocator = Allocator::default();
        let parsed = wa_oxc::parse_cjs(&allocator, &source);
        let calls = module_loader_calls(&parsed.program);
        let at = source.find("o(\"Transport\")").unwrap() as u32;
        assert_eq!(calls.contains(&at), expected, "{setup}");
    }
}
