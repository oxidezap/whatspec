//! Recover direct local object arguments only when all uses are known reads.
//! No general alias analysis: mutation, rebinding, escape, conditional initialization,
//! duplicate bindings, and references before initialization leave the argument unread.
use crate::RequireAliases;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_syntax::scope::ScopeFlags;
use std::collections::{BTreeMap, BTreeSet};
use wa_ir::{WamCallSiteValue, WamFieldWrite};

#[derive(Clone)]
pub(super) struct Fields {
    pub fields: Vec<(String, WamFieldWrite, Option<WamCallSiteValue>)>,
    pub partial: bool,
}

type Key = (u32, String);
struct Candidate {
    end: u32,
    value: Fields,
    valid: bool,
}
struct Frame {
    start: u32,
    names: BTreeSet<String>,
}

#[derive(Default)]
struct Locals {
    names: BTreeMap<String, usize>,
}
impl<'a> Visit<'a> for Locals {
    fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
        *self.names.entry(id.name.to_string()).or_default() += 1;
    }
    fn visit_function(&mut self, f: &Function<'a>, _: ScopeFlags) {
        // A declaration binds its name here, but its parameters/body belong to itself.
        if f.is_function_declaration()
            && let Some(id) = &f.id
        {
            self.visit_binding_identifier(id);
        }
    }
    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
}

struct Collector<'b> {
    aliases: &'b RequireAliases,
    frames: Vec<Frame>,
    candidates: BTreeMap<Key, Candidate>,
    references: Vec<(u32, u32, Key)>,
    allowed: BTreeSet<u32>,
}

impl Collector<'_> {
    fn enter<'a>(
        &mut self,
        start: u32,
        params: &FormalParameters<'a>,
        body: Option<&FunctionBody<'a>>,
    ) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(params);
        if let Some(body) = body {
            locals.visit_function_body(body);
        }
        if let Some(body) = body {
            for stmt in &body.statements {
                let Statement::VariableDeclaration(decl) = stmt else {
                    continue;
                };
                for binding in &decl.declarations {
                    let Some(name) = binding.id.get_identifier_name() else {
                        continue;
                    };
                    if locals.names.get(name.as_str()) != Some(&1) {
                        continue;
                    }
                    let Some(init) = binding
                        .init
                        .as_ref()
                        .filter(|v| wa_oxc::as_object(v).is_some())
                    else {
                        continue;
                    };
                    let mut fields = Vec::new();
                    let mut partial = false;
                    let mut unread = None;
                    super::read_argument(
                        init,
                        &mut fields,
                        &mut partial,
                        &mut unread,
                        self.aliases,
                        None,
                    );
                    self.candidates.insert(
                        (start, name.to_string()),
                        Candidate {
                            end: binding.span.end,
                            value: Fields { fields, partial },
                            valid: true,
                        },
                    );
                }
            }
        }
        self.frames.push(Frame {
            start,
            names: locals.names.into_keys().collect(),
        });
    }

    fn allow_read(&mut self, arg: &Expression<'_>) {
        if let Expression::Identifier(id) = arg {
            self.allowed.insert(id.span.start);
        } else if let Some(call) = wa_oxc::as_call(arg)
            && super::is_object_merge(call)
            // extends writes its first argument. Only a fresh literal target is safe.
            && call.arguments.first().and_then(wa_oxc::arg_expr).is_some_and(|v| wa_oxc::as_object(v).is_some())
        {
            for arg in call.arguments.iter().skip(1).filter_map(wa_oxc::arg_expr) {
                if let Expression::Identifier(id) = arg {
                    self.allowed.insert(id.span.start);
                }
            }
        }
    }
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
        self.enter(f.span.start, &f.params, f.body.as_deref());
        walk::walk_function(self, f, flags);
        self.frames.pop();
    }
    fn visit_arrow_function_expression(&mut self, f: &ArrowFunctionExpression<'a>) {
        self.enter(f.span.start, &f.params, Some(&f.body));
        walk::walk_arrow_function_expression(self, f);
        self.frames.pop();
    }
    fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
        if let Some(owner) = self
            .frames
            .iter()
            .rev()
            .find(|f| f.names.contains(id.name.as_str()))
        {
            self.references.push((
                id.span.start,
                self.frames.last().map_or(0, |f| f.start),
                (owner.start, id.name.to_string()),
            ));
        }
    }
    fn visit_new_expression(&mut self, n: &NewExpression<'a>) {
        if super::wam_event_callee(&n.callee, self.aliases).is_some()
            && let Some(arg) = n.arguments.first().and_then(wa_oxc::arg_expr)
        {
            self.allow_read(arg);
        }
        walk::walk_new_expression(self, n);
    }
    fn visit_with_statement(&mut self, stmt: &WithStatement<'a>) {
        for candidate in self.candidates.values_mut() {
            candidate.valid = false;
        }
        walk::walk_with_statement(self, stmt);
    }
    fn visit_call_expression(&mut self, c: &CallExpression<'a>) {
        // Direct eval could mutate any visible binding without an AST reference.
        if wa_oxc::as_identifier(super::unparen(&c.callee)) == Some("eval") {
            for candidate in self.candidates.values_mut() {
                candidate.valid = false;
            }
        }
        walk::walk_call_expression(self, c);
    }
}

pub(super) fn collect(program: &Program<'_>, aliases: &RequireAliases) -> BTreeMap<u32, Fields> {
    let mut scan = Collector {
        aliases,
        frames: Vec::new(),
        candidates: BTreeMap::new(),
        references: Vec::new(),
        allowed: BTreeSet::new(),
    };
    scan.visit_program(program);
    for (position, _, key) in &scan.references {
        if let Some(candidate) = scan.candidates.get_mut(key)
            && (!scan.allowed.contains(position) || *position < candidate.end)
        {
            candidate.valid = false;
        }
    }
    scan.references
        .into_iter()
        .filter_map(|(position, scope, key)| {
            let candidate = scan.candidates.get(&key)?;
            // A closure may run before an outer initializer. Keep that case unresolved.
            (candidate.valid && scope == key.0 && scan.allowed.contains(&position))
                .then(|| (position, candidate.value.clone()))
        })
        .collect()
}
