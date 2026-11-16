use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, Function, IdentifierReference, Statement};
use oxc_ast_visit::{Visit, walk};
use wa_oxc::{arg_expr, as_call, as_identifier, as_member, as_string_lit, callee_method};
use wa_transform::ModuleDefinition;

const METHODS: &[&str] = &["fetchQuery", "commitMutation", "fetchSubscription"];

#[derive(Default)]
pub(crate) struct Transports(HashSet<(String, String)>);

impl Transports {
    pub(crate) fn is_transport(&self, call: &CallExpression) -> bool {
        if callee_method(call).is_some_and(|method| METHODS.contains(&method)) {
            return true;
        }
        let Some((owner, method)) = as_member(&call.callee) else {
            return false;
        };
        let Some(module) = as_call(owner)
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
                }
                impl<'a> Visit<'a> for Exports {
                    fn visit_function(
                        &mut self,
                        _: &Function<'a>,
                        _: oxc_syntax::scope::ScopeFlags,
                    ) {
                    }
                    fn visit_variable_declarator(
                        &mut self,
                        binding: &oxc_ast::ast::VariableDeclarator<'a>,
                    ) {
                        if binding.init.is_some() {
                            for identifier in binding.id.get_binding_identifiers() {
                                self.rewritten.insert(identifier.name.to_string());
                            }
                        }
                        walk::walk_variable_declarator(self, binding);
                    }
                    fn visit_assignment_expression(
                        &mut self,
                        assignment: &oxc_ast::ast::AssignmentExpression<'a>,
                    ) {
                        if let Some(name) = wa_oxc::assignment_target_name(&assignment.left) {
                            self.rewritten.insert(name.to_string());
                        }
                        if let Some(member) = assignment.left.as_member_expression()
                            && let Some(receiver) = member.object().get_identifier_reference()
                            && self.receivers.contains(receiver.name.as_str())
                            && let Some(name) = member.static_property_name()
                        {
                            let local = as_identifier(&assignment.right).map(str::to_string);
                            self.exports
                                .entry(name.to_string())
                                .and_modify(|previous| {
                                    if *previous != local {
                                        *previous = None;
                                    }
                                })
                                .or_insert(local);
                        }
                        walk::walk_assignment_expression(self, assignment);
                    }
                }
                let mut exports = Exports {
                    receivers,
                    exports: HashMap::new(),
                    rewritten: HashSet::new(),
                };
                exports.visit_function_body(body);
                functions.retain(|name, _| !exports.rewritten.contains(*name));
                for (export, local) in exports.exports {
                    let Some(local) = local else { continue };
                    if functions.get(local.as_str()).is_some_and(|function| {
                        forwards(function, &functions, &transports, &mut HashSet::new())
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
    visiting: &mut HashSet<String>,
) -> bool {
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
    let result = (!function.generator && direct(function, transports))
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
                            || parameter
                                .pattern
                                .get_binding_identifiers()
                                .iter()
                                .any(|identifier| identifier.name == target)
                    })
                {
                    return false;
                }
                return functions
                    .get(target)
                    .is_some_and(|function| forwards(function, functions, transports, visiting));
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
            !generator.r#async && direct(generator, transports)
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

fn direct(function: &Function, transports: &Transports) -> bool {
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
    struct Probe<'s> {
        params: [&'s str; 2],
        reads: [usize; 2],
        shadowed: [bool; 2],
        sends: usize,
        suspended: bool,
        invalid: bool,
        transports: &'s Transports,
    }
    impl<'a> Visit<'a> for Probe<'_> {
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
            self.invalid |= wa_oxc::assignment_target_name(&assignment.left)
                .is_some_and(|name| self.params.contains(&name));
            walk::walk_assignment_expression(self, assignment);
        }
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            let forward = self.transports.is_transport(call)
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
                self.invalid |= self.suspended;
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
