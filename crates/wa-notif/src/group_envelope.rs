//! Lower the complete ordered group envelope prefix and final projection.
//! Unsupported syntax rejects the whole contract. Child action semantics are a
//! separate parser boundary with its own normalized contracts.
use crate::actions::ConstResolver;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Function, NewExpression, ObjectPropertyKind, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use oxc_syntax::operator::{AssignmentOperator, BinaryOperator, LogicalOperator, UnaryOperator};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use wa_ir::group_envelope::*;
use wa_oxc::{arg_expr, as_call, as_identifier, as_int, as_member, as_string_lit};

fn plain_function(f: &Function<'_>, arity: usize) -> bool {
    !f.r#async
        && !f.generator
        && f.params.rest.is_none()
        && f.params.items.len() == arity
        && f.params.items.iter().all(|p| {
            p.initializer.is_none()
                && matches!(
                    p.pattern,
                    oxc_ast::ast::BindingPattern::BindingIdentifier(_)
                )
        })
        && f.body.as_ref().is_some_and(|b| b.directives.is_empty())
}
pub(crate) fn loader_aliases(statements: &[Statement<'_>]) -> Result<BTreeSet<String>, String> {
    let [Statement::ExpressionStatement(es)] = statements else {
        return Err("expected one complete Metro module".into());
    };
    let call = as_call(&es.expression).ok_or("module wrapper call")?;
    if as_identifier(&call.callee) != Some("__d")
        || call.arguments.len() != 4
        || call
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_string_lit)
            != Some("WAWebHandleGroupNotification")
    {
        return Err("module wrapper identity".into());
    }
    let Some(Expression::FunctionExpression(factory)) = call
        .arguments
        .get(2)
        .and_then(arg_expr)
        .map(Expression::without_parentheses)
    else {
        return Err("module factory".into());
    };
    if factory.r#async
        || factory.generator
        || factory.params.rest.is_some()
        || factory.params.items.len() != 7
        || factory.params.items.iter().any(|p| {
            p.initializer.is_some()
                || !matches!(
                    p.pattern,
                    oxc_ast::ast::BindingPattern::BindingIdentifier(_)
                )
        })
    {
        return Err("module loader bindings".into());
    }
    let loaders = factory.params.items[1..4]
        .iter()
        .map(|p| {
            p.pattern
                .get_identifier_name()
                .map(|n| n.to_string())
                .ok_or("module loader pattern".to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if loaders.len() != 3 {
        return Err("ambiguous module loaders".into());
    }
    struct Writes<'s> {
        loaders: &'s BTreeSet<String>,
        changed: bool,
    }
    impl<'a> Visit<'a> for Writes<'_> {
        fn visit_function(&mut self, _: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {}
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if !crate::group_scope::assignment_names(&a.left).is_disjoint(self.loaders) {
                self.changed = true;
            }
            walk::walk_assignment_expression(self, a);
        }
        fn visit_update_expression(&mut self, u: &oxc_ast::ast::UpdateExpression<'a>) {
            if u.argument
                .get_identifier_name()
                .is_some_and(|name| self.loaders.contains(name))
            {
                self.changed = true;
            }
            walk::walk_update_expression(self, u);
        }
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if d.id
                .get_identifier_name()
                .is_some_and(|n| self.loaders.contains(n.as_str()))
            {
                self.changed = true;
            }
            walk::walk_variable_declarator(self, d);
        }
    }
    let mut writes = Writes {
        loaders: &loaders,
        changed: false,
    };
    writes.visit_function_body(factory.body.as_ref().ok_or("missing module factory body")?);
    if writes.changed {
        return Err("module loader is reassigned".into());
    }
    Ok(loaders)
}

struct Lower {
    node: String,
    loaders: BTreeSet<String>,
    locals: BTreeMap<String, u32>,
}
impl Lower {
    fn local(&self, name: &str) -> Result<u32, String> {
        self.locals
            .get(name)
            .copied()
            .ok_or_else(|| format!("unbound envelope local {name}"))
    }
    fn bind(&mut self, name: &str) -> u32 {
        let next = self.locals.len() as u32;
        *self.locals.entry(name.into()).or_insert(next)
    }
    fn expr(&mut self, e: &Expression<'_>) -> Result<GroupEnvelopeExpr, String> {
        use GroupEnvelopeExpr as E;
        if let Some(s) = as_string_lit(e) {
            return Ok(E::String { value: s.into() });
        }
        if let Some(n) = as_int(e) {
            return Ok(E::Integer { value: n });
        }
        match e {
            Expression::Identifier(id) if id.name.as_str() == self.node => Ok(E::Node),
            Expression::Identifier(id) => Ok(E::Local {
                local: self.local(id.name.as_str())?,
            }),
            Expression::NullLiteral(_) => Ok(E::Null),
            Expression::BooleanLiteral(b) => Ok(E::Bool { value: b.value }),
            Expression::ParenthesizedExpression(p) => self.expr(&p.expression),
            Expression::UnaryExpression(u) => match u.operator {
                UnaryOperator::LogicalNot => Ok(E::Not {
                    value: Box::new(self.expr(&u.argument)?),
                }),
                UnaryOperator::Void if as_int(&u.argument) == Some(0) => Ok(E::Undefined),
                _ => Err("unsupported envelope unary expression".into()),
            },
            Expression::BinaryExpression(b) => {
                let operator = match b.operator {
                    BinaryOperator::StrictEquality => GroupEnvelopeBinary::StrictEqual,
                    BinaryOperator::StrictInequality => GroupEnvelopeBinary::StrictNotEqual,
                    BinaryOperator::Equality
                        if matches!(b.left, Expression::NullLiteral(_))
                            || matches!(b.right, Expression::NullLiteral(_)) =>
                    {
                        GroupEnvelopeBinary::NullishEqual
                    }
                    BinaryOperator::Inequality
                        if matches!(b.left, Expression::NullLiteral(_))
                            || matches!(b.right, Expression::NullLiteral(_)) =>
                    {
                        GroupEnvelopeBinary::NullishNotEqual
                    }
                    BinaryOperator::Addition => GroupEnvelopeBinary::Add,
                    _ => return Err("unsupported envelope binary expression".into()),
                };
                Ok(E::Binary {
                    operator,
                    left: Box::new(self.expr(&b.left)?),
                    right: Box::new(self.expr(&b.right)?),
                })
            }
            Expression::LogicalExpression(l) => Ok(E::Logical {
                operator: match l.operator {
                    LogicalOperator::And => GroupEnvelopeLogical::And,
                    LogicalOperator::Or => GroupEnvelopeLogical::Or,
                    _ => return Err("unsupported logical operator".into()),
                },
                left: Box::new(self.expr(&l.left)?),
                right: Box::new(self.expr(&l.right)?),
            }),
            Expression::ConditionalExpression(c) => Ok(E::Conditional {
                condition: Box::new(self.expr(&c.test)?),
                then_value: Box::new(self.expr(&c.consequent)?),
                else_value: Box::new(self.expr(&c.alternate)?),
            }),
            Expression::AssignmentExpression(a) if a.operator == AssignmentOperator::Assign => {
                Ok(E::Assign {
                    local: self
                        .local(a.left.get_identifier_name().ok_or("nonlocal assignment")?)?,
                    value: Box::new(self.expr(&a.right)?),
                })
            }
            Expression::SequenceExpression(s) => Ok(E::Sequence {
                values: s
                    .expressions
                    .iter()
                    .map(|v| self.expr(v))
                    .collect::<Result<_, _>>()?,
            }),
            Expression::ObjectExpression(o) => {
                let mut keys = BTreeSet::new();
                let mut fields = vec![];
                for p in &o.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = p else {
                        return Err("spread in envelope projection".into());
                    };
                    let name = p
                        .key
                        .static_name()
                        .ok_or("dynamic envelope key")?
                        .into_owned();
                    if !keys.insert(name.clone()) {
                        return Err("duplicate envelope output key".into());
                    }
                    fields.push(GroupEnvelopeField {
                        name,
                        value: self.expr(&p.value)?,
                    });
                }
                Ok(E::Object { fields })
            }
            Expression::CallExpression(c) => {
                if let Some((receiver, method)) = as_member(&c.callee) {
                    if as_identifier(receiver) == Some(self.node.as_str()) {
                        if c.arguments.len() != 1 {
                            return Err("unsupported envelope accessor arity".into());
                        }
                        let a = arg_expr(&c.arguments[0]).ok_or("spread accessor argument")?;
                        if method == "throw" {
                            return Ok(E::Reject {
                                message: Box::new(self.expr(a)?),
                            });
                        }
                        let name = as_string_lit(a)
                            .ok_or("dynamic wire attribute")?
                            .to_string();
                        let method = match method {
                            "assertTag" => GroupEnvelopeRead::AssertTag,
                            "hasAttr" => GroupEnvelopeRead::HasAttr,
                            "attrString" => GroupEnvelopeRead::AttrString,
                            "attrGroupJid" => GroupEnvelopeRead::AttrGroupJid,
                            "attrUserJid" => GroupEnvelopeRead::AttrUserJid,
                            "maybeAttrPhoneUserJid" => GroupEnvelopeRead::MaybeAttrPhoneUserJid,
                            "attrTime" => GroupEnvelopeRead::AttrTime,
                            "maybeAttrString" => GroupEnvelopeRead::MaybeAttrString,
                            _ => return Err("unsupported envelope node operation".into()),
                        };
                        return Ok(E::Read { method, name });
                    }
                    if method == "toJid" && c.arguments.is_empty() {
                        return Ok(E::Convert {
                            conversion: GroupEnvelopeConversion::ToJid,
                            value: Box::new(self.expr(receiver)?),
                        });
                    }
                    if let Some(module) = import_module(receiver, &self.loaders) {
                        let fact = match (module, method) {
                            ("WAWebUserPrefsMeUser", "getMeDeviceLidOrThrow") => {
                                Some(GroupEnvelopeContextFact::MeDeviceLid)
                            }
                            ("WAWebUserPrefsMeUser", "getMaybeMeDevicePn") => {
                                Some(GroupEnvelopeContextFact::MaybeMeDevicePn)
                            }
                            ("WAWebUsernameGatingUtils", "usernameDisplayedEnabled") => {
                                Some(GroupEnvelopeContextFact::UsernameDisplayed)
                            }
                            _ => None,
                        };
                        if let Some(fact) = fact {
                            if !c.arguments.is_empty() {
                                return Err("context accessor arguments".into());
                            }
                            return Ok(E::Context { fact });
                        }
                        let conversion = match (module, method) {
                            ("WAWebJidToWid", "groupJidToWid") => {
                                GroupEnvelopeConversion::GroupJidToWid
                            }
                            ("WAWebJidToWid", "userJidToUserWid") => {
                                GroupEnvelopeConversion::UserJidToWid
                            }
                            ("WAWebAsISOCountryCode", "asISOCountryCode") => {
                                GroupEnvelopeConversion::AsIsoCountryCode
                            }
                            _ => {
                                return Err(format!(
                                    "unsupported envelope dependency {module}.{method}"
                                ));
                            }
                        };
                        if c.arguments.len() != 1 {
                            return Err("conversion arity".into());
                        }
                        return Ok(E::Convert {
                            conversion,
                            value: Box::new(
                                self.expr(arg_expr(&c.arguments[0]).ok_or("spread conversion")?)?,
                            ),
                        });
                    }
                }
                if import_module(&c.callee, &self.loaders) == Some("isStringNullOrEmpty")
                    && c.arguments.len() == 1
                {
                    return Ok(E::IsEmpty {
                        value: Box::new(
                            self.expr(
                                arg_expr(&c.arguments[0]).ok_or("spread emptiness argument")?,
                            )?,
                        ),
                    });
                }
                Err("unrecognized envelope call".into())
            }
            _ => Err(format!("unsupported envelope expression {:?}", e.span())),
        }
    }
    fn statements(&mut self, statements: &[Statement<'_>]) -> Result<Vec<GroupEnvelopeOp>, String> {
        let mut ops = vec![];
        for s in statements {
            match s {
                Statement::VariableDeclaration(v) => {
                    if v.kind != oxc_ast::ast::VariableDeclarationKind::Var {
                        return Err("lexical envelope declaration unsupported".into());
                    }
                    for d in &v.declarations {
                        let local = self.bind(
                            d.id.get_identifier_name()
                                .ok_or("destructuring envelope variable")?
                                .as_ref(),
                        );
                        let value = d.init.as_ref().map(|e| self.expr(e)).transpose()?;
                        ops.push(GroupEnvelopeOp::Bind { local, value });
                    }
                }
                Statement::ExpressionStatement(e) => ops.push(GroupEnvelopeOp::Evaluate {
                    value: self.expr(&e.expression)?,
                }),
                Statement::BlockStatement(b) => ops.extend(self.statements(&b.body)?),
                Statement::IfStatement(i) => {
                    let condition = self.expr(&i.test)?;
                    let then_ops = self.statements(std::slice::from_ref(&i.consequent))?;
                    let else_ops = i
                        .alternate
                        .as_ref()
                        .map(|s| self.statements(std::slice::from_ref(s)))
                        .transpose()?
                        .unwrap_or_default();
                    ops.push(GroupEnvelopeOp::If {
                        condition,
                        then_ops,
                        else_ops,
                    });
                }
                Statement::TryStatement(t) => {
                    if t.finalizer.is_some() {
                        return Err("envelope finally effects unsupported".into());
                    }
                    let body = self.statements(&t.block.body)?;
                    let catch = t.handler.as_ref().ok_or("try without local diagnostic")?;
                    let error = catch
                        .param
                        .as_ref()
                        .and_then(|p| p.pattern.get_identifier_name())
                        .ok_or("missing diagnostic error binding")?;
                    let message_parts = diagnostic(
                        &catch.body.body,
                        error.as_ref(),
                        &self.locals,
                        &self.loaders,
                    )?;
                    ops.push(GroupEnvelopeOp::TryDiagnostic {
                        body,
                        message_parts,
                    });
                }
                _ => return Err("unsupported envelope statement".into()),
            }
        }
        Ok(ops)
    }
}
fn import_module<'b, 'a>(e: &'b Expression<'a>, loaders: &BTreeSet<String>) -> Option<&'b str> {
    let c = as_call(e.without_parentheses())?;
    if !as_identifier(&c.callee).is_some_and(|name| loaders.contains(name))
        || c.arguments.len() != 1
    {
        return None;
    }
    as_string_lit(arg_expr(&c.arguments[0])?)
}
fn diagnostic(
    statements: &[Statement<'_>],
    error: &str,
    locals: &BTreeMap<String, u32>,
    loaders: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let [Statement::ExpressionStatement(es)] = statements else {
        return Err("nonlocal catch effects".into());
    };
    let call = as_call(&es.expression).ok_or("non-call diagnostic")?;
    let (receiver, "ERROR") = as_member(&call.callee).ok_or("diagnostic method")? else {
        return Err("non-error diagnostic".into());
    };
    if import_module(receiver, loaders) != Some("WALogger") || call.arguments.len() != 2 {
        return Err("unrecognized catch diagnostic".into());
    }
    let Expression::LogicalExpression(lazy) =
        arg_expr(&call.arguments[0]).ok_or("spread diagnostic")?
    else {
        return Err("unrecognized diagnostic template cache".into());
    };
    if lazy.operator != LogicalOperator::Or {
        return Err("diagnostic template cache guard".into());
    }
    let cache = as_identifier(&lazy.left).ok_or("diagnostic cache binding")?;
    if locals.contains_key(cache) || cache == error {
        return Err("diagnostic mutates envelope local".into());
    }
    let Expression::AssignmentExpression(assign) = lazy.right.without_parentheses() else {
        return Err("diagnostic cache assignment".into());
    };
    if assign.operator != AssignmentOperator::Assign
        || assign.left.get_identifier_name() != Some(cache)
    {
        return Err("diagnostic cache target".into());
    }
    let template = as_call(&assign.right).ok_or("diagnostic template")?;
    let (owner, method) = as_member(&template.callee).ok_or("diagnostic template method")?;
    if as_identifier(owner) != Some("babelHelpers")
        || method != "taggedTemplateLiteralLoose"
        || template.arguments.len() != 1
    {
        return Err("unrecognized diagnostic helper".into());
    }
    let Expression::ArrayExpression(parts) =
        arg_expr(&template.arguments[0]).ok_or("spread template")?
    else {
        return Err("nonliteral template".into());
    };
    let mut strings = vec![];
    for part in &parts.elements {
        let e = part.as_expression().ok_or("sparse diagnostic template")?;
        strings.push(
            as_string_lit(e)
                .ok_or("dynamic diagnostic template")?
                .to_string(),
        );
    }
    let formatted = as_call(arg_expr(&call.arguments[1]).ok_or("spread diagnostic error")?)
        .ok_or("formatted diagnostic error")?;
    let (safe, "toString") = as_member(&formatted.callee).ok_or("diagnostic error string")? else {
        return Err("diagnostic error method".into());
    };
    let safe = as_call(safe).ok_or("unsafe diagnostic error")?;
    if !formatted.arguments.is_empty()
        || import_module(&safe.callee, loaders) != Some("getErrorSafe")
        || safe.arguments.len() != 1
        || safe
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_identifier)
            != Some(error)
    {
        return Err("unrecognized diagnostic error conversion".into());
    }
    Ok(strings)
}

fn actions(
    expr: &Expression<'_>,
    node: &str,
    marker: &str,
    captured: &BTreeSet<String>,
    resolver: &ConstResolver<'_>,
    loaders: &BTreeSet<String>,
) -> Result<(String, String), String> {
    let filter = as_call(expr).ok_or("action filter call")?;
    let (mapped, "filter") = as_member(&filter.callee).ok_or("action filter")? else {
        return Err("action filter method".into());
    };
    if filter.arguments.len() != 1
        || filter
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_identifier)
            != Some("Boolean")
    {
        return Err("non-Boolean action filtering".into());
    }
    let mapped = as_call(mapped).ok_or("action map call")?;
    let (receiver, "mapChildren") = as_member(&mapped.callee).ok_or("action mapping")? else {
        return Err("action mapping method".into());
    };
    if as_identifier(receiver) != Some(node) || mapped.arguments.len() != 1 {
        return Err("action mapping receiver".into());
    }
    let Expression::FunctionExpression(callback) =
        arg_expr(&mapped.arguments[0]).ok_or("spread action callback")?
    else {
        return Err("non-function action callback".into());
    };
    if !plain_function(callback, 1) {
        return Err("action callback arity or effects".into());
    }
    let body = callback
        .body
        .as_ref()
        .ok_or("missing action callback body")?;
    let [
        Statement::VariableDeclaration(var),
        Statement::SwitchStatement(switch),
    ] = body.statements.as_slice()
    else {
        return Err("unsupported action dispatch setup".into());
    };
    if var.declarations.len() != 2 || var.declarations[0].init.is_some() {
        return Err("action dispatch locals".into());
    }
    let tag_binding = var.declarations[1]
        .id
        .get_identifier_name()
        .ok_or("action tag binding")?;
    let tag_call = var.declarations[1]
        .init
        .as_ref()
        .and_then(as_call)
        .ok_or("action tag read")?;
    let (child, "tag") = as_member(&tag_call.callee).ok_or("action tag method")? else {
        return Err("non-tag action discriminator".into());
    };
    let child_param = callback
        .params
        .items
        .first()
        .and_then(|p| p.pattern.get_identifier_name())
        .ok_or("action child parameter")?;
    if !tag_call.arguments.is_empty()
        || as_identifier(child) != Some(child_param.as_ref())
        || as_identifier(&switch.discriminant) != Some(tag_binding.as_ref())
    {
        return Err("action discriminator mismatch".into());
    }
    let mut missing = None;
    let mut marker_assignment = None;
    let mut unknown = None;
    fn terminates(statements: &[Statement<'_>]) -> bool {
        match statements.last() {
            Some(Statement::ReturnStatement(_) | Statement::ThrowStatement(_)) => true,
            Some(Statement::BlockStatement(block)) => terminates(&block.body),
            _ => false,
        }
    }
    for (index, case) in switch.cases.iter().enumerate() {
        if let Some(test) = &case.test {
            let Some((obj, "MISSING_PARTICIPANT_IDENTIFICATION")) = as_member(test) else {
                continue;
            };
            let Some((owner, "GROUP_NOTIFICATION_TAG")) = as_member(obj) else {
                continue;
            };
            if import_module(owner, loaders) != Some("WAWebHandleGroupNotificationConst") {
                continue;
            }
            let wire = resolver
                .resolve(test)
                .ok_or("missing identification wire constant")?;
            if index > 0 && !terminates(&switch.cases[index - 1].consequent) {
                return Err("fall-through into missing-identification arm".into());
            }
            if missing.is_some() {
                return Err("duplicate missing-identification arm".into());
            }
            let [Statement::BlockStatement(block)] = case.consequent.as_slice() else {
                return Err("marker arm block".into());
            };
            let [
                Statement::ExpressionStatement(set),
                Statement::ReturnStatement(ret),
            ] = block.body.as_slice()
            else {
                return Err("marker arm does not return no action".into());
            };
            let Expression::AssignmentExpression(assign) = &set.expression else {
                return Err("marker does not assign flag".into());
            };
            if assign.operator != AssignmentOperator::Assign
                || assign.left.get_identifier_name() != Some(marker)
                || ret.argument.is_some()
            {
                return Err("marker changes action semantics".into());
            }
            let enabled = matches!(&assign.right,Expression::BooleanLiteral(b) if b.value)
                || matches!(&assign.right,Expression::UnaryExpression(u) if u.operator==UnaryOperator::LogicalNot && as_int(&u.argument)==Some(0));
            if !enabled {
                return Err("marker is not true".into());
            }
            marker_assignment = Some(assign.span);
            missing = Some(wire);
        } else {
            if unknown.is_some() {
                return Err("duplicate default action arm".into());
            }
            let [Statement::ThrowStatement(thrown)] = case.consequent.as_slice() else {
                return Err("unknown action does not throw".into());
            };
            let call = as_call(&thrown.argument).ok_or("unknown action error")?;
            let (receiver, "createParseError") =
                as_member(&call.callee).ok_or("unknown action parse error")?
            else {
                return Err("unknown action error method".into());
            };
            if as_identifier(receiver) != Some(node) || call.arguments.len() != 1 {
                return Err("unknown action error receiver".into());
            }
            let Expression::BinaryExpression(msg) =
                arg_expr(&call.arguments[0]).ok_or("spread action error")?
            else {
                return Err("unknown error message shape".into());
            };
            if msg.operator != BinaryOperator::Addition
                || as_identifier(&msg.right) != Some(tag_binding.as_ref())
            {
                return Err("unknown action error discriminator".into());
            }
            unknown = Some(
                as_string_lit(&msg.left)
                    .ok_or("unknown action error prefix")?
                    .to_string(),
            );
        }
    }
    crate::group_scope::validate_captured_writes(
        callback,
        captured,
        Some((
            marker,
            marker_assignment.ok_or("missing marker assignment")?,
        )),
    )?;
    Ok((
        missing.ok_or("missing marker arm")?,
        unknown.ok_or("missing rejecting default arm")?,
    ))
}

fn lower_callback(
    f: &Function<'_>,
    slices: &HashMap<&str, &str>,
    loaders: &BTreeSet<String>,
) -> Result<GroupEnvelopeContract, String> {
    let body = f.body.as_ref().ok_or("missing group parser body")?;
    let node = f
        .params
        .items
        .first()
        .and_then(|p| p.pattern.get_identifier_name())
        .ok_or("missing group parser parameter")?
        .to_string();
    if !plain_function(f, 1) {
        return Err("group parser arity".into());
    }
    let mut lower = Lower {
        node: node.clone(),
        loaders: loaders.clone(),
        locals: BTreeMap::new(),
    };
    let (last, before) = body.statements.split_last().ok_or("empty parser")?;
    let Statement::ReturnStatement(ret) = last else {
        return Err("group parser has trailing effects".into());
    };
    let (action_stmt, prefix) = before.split_last().ok_or("missing group actions")?;
    let Statement::VariableDeclaration(action_vars) = action_stmt else {
        return Err("non-variable action result".into());
    };
    if action_vars.declarations.len() != 2 || action_vars.declarations[0].init.is_some() {
        return Err("action boundary locals".into());
    }
    fn hoist(lower: &mut Lower, s: &Statement<'_>) -> Result<(), String> {
        match s {
            Statement::VariableDeclaration(v) => {
                for d in &v.declarations {
                    let name =
                        d.id.get_identifier_name()
                            .ok_or("destructured envelope declaration")?;
                    if name.as_str() == lower.node {
                        return Err("envelope parameter redeclaration".into());
                    }
                    lower.bind(name.as_ref());
                }
            }
            Statement::BlockStatement(b) => {
                for s in &b.body {
                    hoist(lower, s)?;
                }
            }
            Statement::IfStatement(i) => {
                hoist(lower, &i.consequent)?;
                if let Some(s) = &i.alternate {
                    hoist(lower, s)?;
                }
            }
            Statement::TryStatement(t) => {
                for s in &t.block.body {
                    hoist(lower, s)?;
                }
                if let Some(c) = &t.handler {
                    for s in &c.body.body {
                        hoist(lower, s)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    for stmt in before {
        hoist(&mut lower, stmt)?;
    }
    lower
        .loaders
        .retain(|name| name != &lower.node && !lower.locals.contains_key(name));
    let mut ops = vec![];
    for stmt in prefix {
        if let Statement::FunctionDeclaration(helper) = stmt {
            let name = helper
                .id
                .as_ref()
                .ok_or("anonymous action helper declaration")?
                .name
                .as_str();
            if name == lower.node || lower.locals.contains_key(name) || lower.loaders.contains(name)
            {
                return Err("action helper shadows envelope binding".into());
            }
            let captured = lower
                .locals
                .keys()
                .cloned()
                .chain(std::iter::once(node.clone()))
                .collect();
            crate::group_scope::validate_captured_writes(helper, &captured, None)?;
            continue;
        }
        ops.extend(lower.statements(std::slice::from_ref(stmt))?);
    }
    let marker_name = action_vars.declarations[0]
        .id
        .get_identifier_name()
        .ok_or("marker local")?;
    let result_name = action_vars.declarations[1]
        .id
        .get_identifier_name()
        .ok_or("actions local")?;
    let marker_local = lower.bind(marker_name.as_ref());
    let result_local = lower.bind(result_name.as_ref());
    let resolver = ConstResolver::new(slices);
    let (missing_identification_tag, unknown_action_error_prefix) = actions(
        action_vars.declarations[1]
            .init
            .as_ref()
            .ok_or("missing action expression")?,
        &node,
        marker_name.as_ref(),
        &lower
            .locals
            .keys()
            .cloned()
            .chain(std::iter::once(node.clone()))
            .collect(),
        &resolver,
        &lower.loaders,
    )?;
    let projection = lower.expr(ret.argument.as_ref().ok_or("empty envelope projection")?)?;
    let GroupEnvelopeExpr::Object { .. } = &projection else {
        return Err("non-object envelope projection".into());
    };
    Ok(GroupEnvelopeContract {
        module_name: "WAWebHandleGroupNotification".into(),
        start_byte: f.span.start as usize,
        end_byte: f.span.end as usize,
        locals: lower.locals.len() as u32,
        prefix: ops,
        actions: GroupEnvelopeActions {
            start_byte: action_stmt.span().start as usize,
            end_byte: action_stmt.span().end as usize,
            result_local,
            missing_identification_local: marker_local,
            missing_identification_tag,
            unknown_action_error_prefix,
        },
        projection,
    })
}

/// Extract the complete envelope program, with a separately identified action
/// parser boundary. All spans are UTF-8 bytes relative to the Metro module.
pub fn extract_group_envelope(
    slices: &HashMap<&str, &str>,
) -> Result<GroupEnvelopeContract, String> {
    let source = slices
        .get("WAWebHandleGroupNotification")
        .ok_or("missing group handler")?;
    let allocator = Allocator::default();
    let parsed = wa_oxc::parse_cjs(&allocator, source);
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err("invalid group module".into());
    }
    crate::group_scope::validate_import_bindings(
        &parsed.program.body,
        slices.keys().map(|name| name.to_string()),
    )?;
    struct Find<'s> {
        slices: &'s HashMap<&'s str, &'s str>,
        results: Vec<Result<GroupEnvelopeContract, String>>,
        loaders: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Find<'_> {
        fn visit_new_expression(&mut self, n: &NewExpression<'a>) {
            if n.arguments
                .first()
                .and_then(arg_expr)
                .and_then(as_string_lit)
                == Some("groupNotificationParser")
            {
                if import_module(&n.callee, &self.loaders) != Some("WADeprecatedWapParser")
                    || n.arguments.len() != 2
                {
                    self.results
                        .push(Err("unrecognized group parser constructor".into()));
                    return;
                }
                let Some(Expression::FunctionExpression(callback)) =
                    n.arguments.get(1).and_then(arg_expr)
                else {
                    self.results
                        .push(Err("unrecognized group parser callback".into()));
                    return;
                };
                self.results
                    .push(lower_callback(callback, self.slices, &self.loaders));
                return;
            }
            walk::walk_new_expression(self, n);
        }
    }
    let loaders = loader_aliases(&parsed.program.body)?;
    let mut finder = Find {
        slices,
        loaders,
        results: vec![],
    };
    finder.visit_program(&parsed.program);
    if finder.results.len() != 1 {
        return Err(format!(
            "expected one group envelope parser, found {}",
            finder.results.len()
        ));
    }
    finder.results.remove(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str =
        include_str!("../../../tests/conformance/groups/sources/WAWebHandleGroupNotification.js");
    const CONSTANTS: &str = include_str!(
        "../../../tests/conformance/groups/sources/WAWebHandleGroupNotificationConst.js"
    );
    fn extract(source: &str) -> Result<GroupEnvelopeContract, String> {
        extract_group_envelope(&HashMap::from([
            ("WAWebHandleGroupNotification", source),
            ("WAWebHandleGroupNotificationConst", CONSTANTS),
        ]))
    }
    #[test]
    fn prefix_marker_initialization_is_preserved_in_the_program() {
        let changed = SOURCE.replace("function v(e){", "var D=!0;function v(e){");
        assert_ne!(changed, SOURCE);
        let contract = extract(&changed).unwrap();
        assert!(contract.prefix.iter().any(|op| matches!(op, GroupEnvelopeOp::Bind { local, value: Some(_) } if *local == contract.actions.missing_identification_local)));
    }
    #[test]
    fn marker_fallthrough_aliases_fail_closed() {
        let marker = "case o(\"WAWebHandleGroupNotificationConst\").GROUP_NOTIFICATION_TAG.MISSING_PARTICIPANT_IDENTIFICATION:";
        for alias in ["case \"second_marker\":", "case \"second_marker\":void 0;"] {
            let changed = SOURCE.replace(marker, &format!("{alias}{marker}"));
            assert_ne!(changed, SOURCE);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn initializer_free_redeclaration_is_retained_as_no_assignment() {
        let changed = SOURCE.replace("function v(e){", "var c;function v(e){");
        assert_ne!(changed, SOURCE);
        let contract = extract(&changed).unwrap();
        assert_eq!(
            contract.prefix.len(),
            extract(SOURCE).unwrap().prefix.len() + 1
        );
        assert!(contract.prefix.iter().any(|op| matches!(
            op,
            GroupEnvelopeOp::Bind {
                local: 7,
                value: None
            }
        )));
    }
    #[test]
    fn hidden_captured_writes_and_loader_patterns_reject() {
        for injected in [
            "{let c;}c=null;",
            "if(false){let c;}c=null;",
            "try{}catch(c){}c=null;",
            "function nested(){if(false){let c;}c=null;}nested();",
            "(c=>{})(null);c=null;",
        ] {
            for anchor in ["function v(e){", "var n,a=t.tag();"] {
                let changed = SOURCE.replacen(anchor, &format!("{anchor}{injected}"), 1);
                assert_ne!(changed, SOURCE);
                assert!(extract(&changed).is_err(), "{anchor}: {injected}");
            }
        }
        for params in ["e,extra=(c=null)", "{e}", "...e"] {
            let changed = SOURCE.replace("function v(e){", &format!("function v({params}){{"));
            assert_ne!(changed, SOURCE);
            assert!(extract(&changed).is_err(), "{params}");
        }
        for target in [
            "({o}={o:function(){}});",
            "[o]=[];",
            "({x:{o=null}}={x:{}});",
            "[...o]=[];",
            "({...o}={});",
            "o++;",
            "--o;",
        ] {
            for anchor in ["function(t,n,r,o,a,i,l){", "function v(e){"] {
                let changed = SOURCE.replacen(anchor, &format!("{anchor}{target}"), 1);
                assert_ne!(changed, SOURCE, "factory anchor");
                assert!(extract(&changed).is_err(), "{anchor}: {target}");
            }
        }
    }
    #[test]
    fn complete_prefix_and_final_projection_are_extracted() {
        let contract = extract(SOURCE).unwrap();
        let committed: GroupEnvelopeContract =
            serde_json::from_str(include_str!("../../../generated/notif/group-envelope.json"))
                .unwrap();
        assert_eq!(contract, committed);
        assert!(contract.locals > 10);
        assert!(
            contract
                .prefix
                .iter()
                .any(|op| matches!(op, GroupEnvelopeOp::TryDiagnostic { .. }))
        );
        assert_eq!(
            contract.actions.missing_identification_tag,
            "missing_participant_identification"
        );
        assert_eq!(
            contract.actions.unknown_action_error_prefix,
            "Unrecognized group action "
        );
        let GroupEnvelopeExpr::Object { fields } = &contract.projection else {
            panic!("object projection")
        };
        assert_eq!(fields.first().unwrap().name, "externalId");
        assert_eq!(
            fields.last().unwrap().name,
            "hasIncompleteParticipantInformation"
        );
        assert!(
            contract.actions.start_byte > contract.start_byte
                && contract.actions.end_byte < contract.end_byte
        );
    }
    #[test]
    fn guard_changes_are_retained_in_program() {
        for changed in [
            SOURCE.replace("n===a", "n!==a"),
            SOURCE.replace(
                "e.hasAttr(\"participant_username\")&&_",
                "e.hasAttr(\"participant_username\")||_",
            ),
        ] {
            assert_ne!(changed, SOURCE);
            assert_ne!(
                extract(&changed).unwrap().prefix,
                extract(SOURCE).unwrap().prefix
            );
        }
    }
    #[test]
    fn unsupported_prefix_effects_reject_everything() {
        let changed = SOURCE.replace(
            "var u=o(\"WAWebJidToWid\")",
            "unknownEffect();var u=o(\"WAWebJidToWid\")",
        );
        assert_ne!(changed, SOURCE);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn catch_may_not_write_envelope_state() {
        let changed = SOURCE.replace(
            "m||(m=babelHelpers.taggedTemplateLiteralLoose",
            "D||(D=babelHelpers.taggedTemplateLiteralLoose",
        );
        assert_ne!(changed, SOURCE);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn external_action_cannot_modify_or_shadow_envelope_state() {
        for changed in [
            SOURCE.replace("var n,a=t.tag();", "c=null;var n,a=t.tag();"),
            SOURCE.replace("var n,a=t.tag();", "var D,n,a=t.tag();"),
            SOURCE.replace("function v(e){", "function v(e){c=null;"),
        ] {
            assert_ne!(changed, SOURCE);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn missing_marker_and_unknown_action_are_fail_closed() {
        for changed in [
            SOURCE.replace("D=!0;return", "D=!1;return"),
            SOURCE.replace(
                "throw e.createParseError(\"Unrecognized group action \"+a)",
                "return null",
            ),
        ] {
            assert_ne!(changed, SOURCE);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn callback_modes_and_loader_effects_are_rejected() {
        for changed in [
            SOURCE.replace(
                "\"groupNotificationParser\",function(e)",
                "\"groupNotificationParser\",async function(e)",
            ),
            SOURCE.replace(
                "\"groupNotificationParser\",function(e)",
                "\"groupNotificationParser\",function*(e)",
            ),
            SOURCE.replace(
                "\"groupNotificationParser\",function(e)",
                "\"groupNotificationParser\",function(e=sideEffect())",
            ),
            SOURCE.replace(
                "\"groupNotificationParser\",function(e)",
                "\"groupNotificationParser\",function(e,...rest)",
            ),
            SOURCE.replace(
                "o(\"WAWebUserPrefsMeUser\").getMaybeMeDevicePn()",
                "evil(\"WAWebUserPrefsMeUser\").getMaybeMeDevicePn()",
            ),
            SOURCE.replace(
                "o(\"WAWebUserPrefsMeUser\").getMaybeMeDevicePn()",
                "o(\"WAWebUserPrefsMeUser\",sideEffect()).getMaybeMeDevicePn()",
            ),
        ] {
            assert_ne!(changed, SOURCE);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn local_renames_do_not_change_the_program() {
        let changed = SOURCE
            .replace("n=e.attrString(\"to\")", "q=e.attrString(\"to\")")
            .replace("l=n===a", "l=q===a")
            .replace("&&n===i", "&&q===i")
            .replace("+n+'\"'", "+q+'\"'");
        assert_ne!(changed, SOURCE);
        assert_eq!(extract(&changed).unwrap(), extract(SOURCE).unwrap());
    }
}
