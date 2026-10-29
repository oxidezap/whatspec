//! Fail-closed AST lowering of the complete six exported protobuf validators.
//! Every executable statement and return projection must lower successfully.
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use wa_ir::{
    AppstateValidationIr, ValidationExpression as E, ValidationFunction, ValidationStatement as S,
    ValidationTransform as T,
};
use wa_oxc::{as_identifier, as_member, as_string_lit, first_string_arg, parse_cjs};

pub const MODULE: &str = "WAWebSyncdValidateServerSyncProtobuf";
const NAMES: [&str; 6] = [
    "validateSnapshotProtobuf",
    "validatePatchProtobuf",
    "validateExternalBlobReference",
    "validateMutationProtobuf",
    "validateRecordProtobuf",
    "validateKeyIdProtobuf",
];

/// Compile all six exported protobuf methods. Decoded mutation-batch validation
/// is a separate boundary.
pub fn extract(source: &str, version: &str) -> Result<AppstateValidationIr, String> {
    let defs =
        wa_transform::extract_module_definitions_checked(source).map_err(|e| e.join("; "))?;
    let modules: Vec<_> = defs.iter().filter(|m| m.name == MODULE).collect();
    let first = modules
        .first()
        .ok_or("missing protobuf validation module")?;
    let original = &source[first.start..first.end];
    if modules.iter().any(|m| &source[m.start..m.end] != original) {
        return Err("conflicting validation module definitions".into());
    }
    let allocator = Allocator::default();
    let parsed = parse_cjs(&allocator, original);
    if !parsed.errors.is_empty() || parsed.panicked {
        return Err("validation module parse error".into());
    }
    let mut finder = Finder {
        functions: BTreeMap::new(),
        error: None,
        offset: 0,
        requires: require_bindings(&parsed.program),
    };
    finder.visit_program(&parsed.program);
    if let Some(error) = finder.error {
        return Err(error);
    }
    let expected: Vec<_> = NAMES[..].to_vec();
    if finder.functions.len() != expected.len()
        || expected.iter().any(|n| !finder.functions.contains_key(*n))
    {
        return Err("incomplete protobuf validator exports".into());
    }
    Ok(AppstateValidationIr {
        format_version: 1,
        wa_version: version.into(),
        module_sha256: format!("{:x}", Sha256::digest(original.as_bytes())),
        functions: finder.functions,
    })
}
struct Finder {
    functions: BTreeMap<String, ValidationFunction>,
    error: Option<String>,
    offset: usize,
    requires: HashSet<String>,
}
impl<'a> Visit<'a> for Finder {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let AssignmentTarget::StaticMemberExpression(member) = &assignment.left
            && let Expression::FunctionExpression(function) = &assignment.right
        {
            let name = member.property.name.as_str();
            if name.starts_with("validate") {
                let result = (|| {
                    if !NAMES[..].contains(&name) {
                        return Err(format!("unknown validator {name}"));
                    }
                    let mut lower = Lower {
                        locals: HashMap::new(),
                        slots: 0,
                        requires: self.requires.clone(),
                        receiver: as_identifier(&member.object)
                            .ok_or("unsupported validator receiver")?
                            .into(),
                    };
                    for (i, param) in function.params.items.iter().enumerate() {
                        let BindingPattern::BindingIdentifier(id) = &param.pattern else {
                            return Err("unsupported parameter".into());
                        };
                        lower
                            .locals
                            .insert(id.name.to_string(), E::Argument { index: i });
                    }
                    let body = function.body.as_ref().ok_or("missing validator body")?;
                    let statements = lower.statements(&body.statements)?;
                    Ok(ValidationFunction {
                        module: MODULE.into(),
                        start_byte: self.offset + function.span.start as usize,
                        end_byte: self.offset + function.span.end as usize,
                        parameters: function.params.items.len(),
                        body: statements,
                    })
                })();
                match result {
                    Ok(f) => {
                        if self.functions.insert(name.into(), f).is_some() {
                            self.error = Some("duplicate validator export".into());
                        }
                    }
                    Err(e) => self.error = Some(format!("{name}: {e}")),
                }
                return;
            }
        }
        walk::walk_assignment_expression(self, assignment);
    }
}
pub(super) struct Lower {
    locals: HashMap<String, E>,
    slots: usize,
    receiver: String,
    requires: HashSet<String>,
}
impl Lower {
    fn module<'b>(&self, expression: &'b Expression<'_>) -> Option<&'b str> {
        let mut inner = expression;
        while let Expression::ParenthesizedExpression(p) = inner {
            inner = &p.expression;
        }
        let Expression::CallExpression(call) = inner else {
            return None;
        };
        let name = as_identifier(&call.callee)?;
        if !self.requires.contains(name) || self.locals.contains_key(name) {
            return None;
        }
        module(expression)
    }

    pub(super) fn function(
        function: &Function<'_>,
        requires: HashSet<String>,
    ) -> Result<Vec<S>, String> {
        let mut lower = Self {
            locals: HashMap::new(),
            slots: 0,
            receiver: String::new(),
            requires,
        };
        for (index, param) in function.params.items.iter().enumerate() {
            let BindingPattern::BindingIdentifier(id) = &param.pattern else {
                return Err("unsupported decoded validator parameter".into());
            };
            lower
                .locals
                .insert(id.name.to_string(), E::Argument { index });
        }
        lower.statements(
            &function
                .body
                .as_ref()
                .ok_or("missing function body")?
                .statements,
        )
    }

    pub(super) fn statements(&mut self, statements: &[Statement<'_>]) -> Result<Vec<S>, String> {
        let mut result = Vec::new();
        for statement in statements {
            result.extend(self.statement(statement)?);
        }
        Ok(result)
    }
    fn statement(&mut self, statement: &Statement<'_>) -> Result<Vec<S>, String> {
        Ok(match statement {
            Statement::VariableDeclaration(v) => {
                let mut out = Vec::new();
                for d in &v.declarations {
                    let BindingPattern::BindingIdentifier(id) = &d.id else {
                        return Err("unsupported binding".into());
                    };
                    let value = self.expr(d.init.as_ref().ok_or("uninitialized binding")?)?;
                    let slot = self.slots;
                    self.slots += 1;
                    self.locals
                        .insert(id.name.to_string(), E::Slot { index: slot });
                    out.push(S::Bind { slot, value });
                }
                out
            }
            Statement::IfStatement(i) => vec![S::If {
                condition: self.expr(&i.test)?,
                yes: self.statement(&i.consequent)?,
                no: match &i.alternate {
                    Some(s) => self.statement(s)?,
                    None => vec![],
                },
            }],
            Statement::BlockStatement(b) => self.statements(&b.body)?,
            Statement::ReturnStatement(r) => vec![S::Return {
                value: self.expr(r.argument.as_ref().ok_or("bare return")?)?,
            }],
            Statement::ExpressionStatement(e) => vec![S::Evaluate {
                value: self.expr(&e.expression)?,
            }],
            Statement::ThrowStatement(t) => {
                let Expression::SequenceExpression(sequence) = &t.argument else {
                    return Err("unqualified throw".into());
                };
                if sequence.expressions.len() != 2 {
                    return Err("unsupported fatal side effects".into());
                }
                let Expression::CallExpression(report) = &sequence.expressions[0] else {
                    return Err("missing fatal metric".into());
                };
                let Some((object, "reportSyncdFatalError")) = as_member(&report.callee) else {
                    return Err("wrong fatal reporter".into());
                };
                if self.module(object) != Some("WAWebSyncdMetricFatalError")
                    || report.arguments.len() != 2
                {
                    return Err("unqualified fatal reporter".into());
                }
                let metric = self.expr(arg(&report.arguments[0])?)?;
                // Require the reporting context too; dropping extra effects is unsafe.
                let context = self.expr(arg(&report.arguments[1])?)?;
                if context
                    != (E::Object {
                        fields: vec![("collection".into(), E::Argument { index: 0 })],
                    })
                {
                    return Err("unsupported reporting context".into());
                }
                let Expression::NewExpression(error) = &sequence.expressions[1] else {
                    return Err("missing fatal constructor".into());
                };
                let Some((object, "SyncdFatalError")) = as_member(&error.callee) else {
                    return Err("wrong fatal class".into());
                };
                if self.module(object) != Some("WAWebSyncdError") || error.arguments.len() != 1 {
                    return Err("unqualified fatal class".into());
                }
                let message = as_string_lit(arg(&error.arguments[0])?)
                    .ok_or("dynamic fatal message")?
                    .to_owned();
                vec![S::Fatal { metric, message }]
            }
            _ => return Err(format!("unsupported statement at {:?}", statement.span())),
        })
    }
    fn expr(&mut self, expression: &Expression<'_>) -> Result<E, String> {
        use oxc_syntax::operator::{BinaryOperator as B, LogicalOperator as L, UnaryOperator as U};
        Ok(match expression {
            Expression::ParenthesizedExpression(p) => return self.expr(&p.expression),
            Expression::Identifier(i) => self
                .locals
                .get(i.name.as_str())
                .cloned()
                .ok_or_else(|| format!("unbound {}", i.name))?,
            Expression::NullLiteral(_) => E::Null,
            Expression::NumericLiteral(n) if n.value.fract() == 0.0 => E::Integer {
                value: n.value as i64,
            },
            Expression::StringLiteral(s) => E::String {
                value: s.value.to_string(),
            },
            Expression::UnaryExpression(u)
                if u.operator == U::Void
                    && matches!(&u.argument,Expression::NumericLiteral(n) if n.value==0.0) =>
            {
                E::Undefined
            }
            Expression::UnaryExpression(u) if u.operator == U::LogicalNot => E::Not {
                value: Box::new(self.expr(&u.argument)?),
            },
            Expression::StaticMemberExpression(m) => {
                if let Some((object, "SyncdFatalErrorType")) = as_member(&m.object)
                    && self.module(object) == Some("WAWebSyncdMetricFatalError")
                {
                    E::Metric {
                        name: m.property.name.to_string(),
                    }
                } else {
                    E::Field {
                        object: Box::new(self.expr(&m.object)?),
                        field: m.property.name.to_string(),
                    }
                }
            }
            Expression::LogicalExpression(l) => {
                let left = Box::new(self.expr(&l.left)?);
                let right = Box::new(self.expr(&l.right)?);
                match l.operator {
                    L::And => E::And { left, right },
                    L::Or => E::Or { left, right },
                    _ => return Err("unsupported logical operator".into()),
                }
            }
            Expression::BinaryExpression(b)
                if (b.operator == B::Equality || b.operator == B::Inequality)
                    && matches!(&b.right, Expression::NullLiteral(_)) =>
            {
                E::Nullish {
                    value: Box::new(self.expr(&b.left)?),
                    negate: b.operator == B::Inequality,
                }
            }
            Expression::BinaryExpression(b) if b.operator == B::GreaterThan => E::Greater {
                left: Box::new(self.expr(&b.left)?),
                right: Box::new(self.expr(&b.right)?),
            },
            Expression::ConditionalExpression(c) => E::Choose {
                condition: Box::new(self.expr(&c.test)?),
                yes: Box::new(self.expr(&c.consequent)?),
                no: Box::new(self.expr(&c.alternate)?),
            },
            Expression::AssignmentExpression(a) => {
                let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left else {
                    return Err("unsupported assignment target".into());
                };
                if a.operator != AssignmentOperator::Assign {
                    return Err("compound assignment".into());
                }
                let Some(E::Slot { index }) = self.locals.get(id.name.as_str()) else {
                    return Err("assignment outside local".into());
                };
                E::Assign {
                    slot: *index,
                    value: Box::new(self.expr(&a.right)?),
                }
            }
            Expression::SequenceExpression(s) => E::Sequence {
                values: s
                    .expressions
                    .iter()
                    .map(|e| self.expr(e))
                    .collect::<Result<_, _>>()?,
            },
            Expression::ObjectExpression(o) => {
                let mut fields = Vec::new();
                for p in &o.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = p else {
                        return Err("object spread".into());
                    };
                    if p.computed || p.method || p.kind != PropertyKind::Init {
                        return Err("unsupported object property".into());
                    }
                    let key = p.key.static_name().ok_or("dynamic object key")?.to_string();
                    fields.push((key, self.expr(&p.value)?));
                }
                E::Object { fields }
            }
            Expression::CallExpression(c) => {
                let (object, method) = as_member(&c.callee).ok_or("unsupported callee")?;
                if method == "map" {
                    if c.arguments.len() != 1 {
                        return Err("map arity".into());
                    }
                    let Expression::FunctionExpression(callback) = arg(&c.arguments[0])? else {
                        return Err("map callback".into());
                    };
                    if callback.params.items.len() != 1 {
                        return Err("map parameters".into());
                    }
                    let BindingPattern::BindingIdentifier(id) = &callback.params.items[0].pattern
                    else {
                        return Err("map binding".into());
                    };
                    let old = self
                        .locals
                        .insert(id.name.to_string(), E::Argument { index: 3 });
                    let body =
                        self.statements(&callback.body.as_ref().ok_or("map body")?.statements)?;
                    match old {
                        Some(v) => {
                            self.locals.insert(id.name.to_string(), v);
                        }
                        None => {
                            self.locals.remove(id.name.as_str());
                        }
                    }
                    E::Map {
                        input: Box::new(self.expr(object)?),
                        body,
                    }
                } else {
                    if self.module(object) == Some("decodeProtobuf") && method == "decodeProtobuf" {
                        if c.arguments.len() != 2 {
                            return Err("unqualified decoder arity".into());
                        }
                        let Expression::StaticMemberExpression(spec) = arg(&c.arguments[0])? else {
                            return Err("unqualified decoder spec".into());
                        };
                        if self.module(&spec.object) != Some("WAWebProtobufSyncAction.pb") {
                            return Err("unqualified decoder module".into());
                        }
                        let transform = match spec.property.name.as_str() {
                            "PatchDebugDataSpec" => T::DecodePatchDebugData,
                            "SyncActionDataSpec" => T::DecodeSyncActionData,
                            _ => return Err("unknown decoded spec".into()),
                        };
                        return Ok(E::Transform {
                            transform,
                            arguments: vec![self.expr(arg(&c.arguments[1])?)?],
                        });
                    }
                    let arguments = c
                        .arguments
                        .iter()
                        .map(|a| self.expr(arg(a)?))
                        .collect::<Result<Vec<_>, _>>()?;
                    if NAMES[..].contains(&method)
                        && as_identifier(object) == Some(self.receiver.as_str())
                        && !self.locals.contains_key(self.receiver.as_str())
                    {
                        E::Validate {
                            validator: method.into(),
                            arguments,
                        }
                    } else {
                        let transform = match (self.module(object), method) {
                            (Some("WALongInt"), "numberOrThrowIfTooLarge") => T::SafeInteger,
                            (Some("WALongInt"), "maybeNumberOrThrowIfTooLarge") => T::MaybeNumber,
                            (Some("WASyncdKeyTypes"), "toSyncKeyId") => T::SyncKeyId,
                            (Some("decodeProtobuf"), "decodeProtobuf") => {
                                if c.arguments.len() != 2
                                    || !matches!(arg(&c.arguments[0])?,Expression::StaticMemberExpression(m) if m.property.name=="PatchDebugDataSpec" && self.module(&m.object)==Some("WAWebProtobufSyncAction.pb"))
                                {
                                    return Err("unqualified debug decoder".into());
                                }
                                return Ok(E::Transform {
                                    transform: T::DecodePatchDebugData,
                                    arguments: vec![self.expr(arg(&c.arguments[1])?)?],
                                });
                            }
                            _ => return Err(format!("unsupported dependency {method}")),
                        };
                        E::Transform {
                            transform,
                            arguments,
                        }
                    }
                }
            }
            _ => return Err(format!("unsupported expression at {:?}", expression.span())),
        })
    }
}
fn arg<'a, 'b>(arg: &'b Argument<'a>) -> Result<&'b Expression<'a>, String> {
    arg.as_expression().ok_or("spread argument".into())
}
fn module<'a>(expression: &'a Expression<'_>) -> Option<&'a str> {
    if let Expression::ParenthesizedExpression(p) = expression {
        return module(&p.expression);
    }
    let Expression::CallExpression(c) = expression else {
        return None;
    };
    if as_identifier(&c.callee).is_none() || c.arguments.len() != 1 {
        return None;
    }
    first_string_arg(c)
}

pub(super) fn require_bindings(program: &Program<'_>) -> HashSet<String> {
    #[derive(Default)]
    struct Imports {
        names: HashSet<String>,
    }
    impl<'a> Visit<'a> for Imports {
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            if as_identifier(&call.callee) == Some("__d")
                && let Some(argument) = call.arguments.get(2)
                && let Some(mut factory) = argument.as_expression()
            {
                while let Expression::ParenthesizedExpression(p) = factory {
                    factory = &p.expression;
                }
                if let Expression::FunctionExpression(f) = factory {
                    for param in f.params.items.iter().skip(1).take(3) {
                        if let BindingPattern::BindingIdentifier(id) = &param.pattern {
                            self.names.insert(id.name.to_string());
                        }
                    }
                }
            }
            walk::walk_call_expression(self, call);
        }
    }
    let mut visitor = Imports::default();
    visitor.visit_program(program);
    visitor.names
}
