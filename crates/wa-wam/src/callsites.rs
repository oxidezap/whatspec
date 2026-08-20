//! Where WA Web constructs a WAM event, and the fields it writes there.
//!
//! The dep graph says which modules *import* an event module; it cannot say which ones
//! emit it. What can be read instead is the construction itself —
//! `new (o("WAWeb…WamEvent").<Export>)(…)` — plus the writes that follow it on the value
//! it is bound to, since WA fills an event through three spellings of one mechanism: the
//! constructor's object, `event.field = …`, and `event.set({field: …})` (the codegen's
//! `set` is literally `for (k in obj) this[k] = obj[k]`, and the constructor calls it).
//!
//! Deliberately not extracted: the condition a construction sits under. A call site is a
//! place the client can emit the event, never a promise that it does.

use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, CallExpression, Expression, NewExpression,
    ObjectPropertyKind, UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use wa_ir::{WamCallSiteValue, WamFieldWrite};

use crate::RequireAliases;
use wa_oxc::{as_call, as_int, as_member, as_object, as_string_lit, first_string_arg, parse_cjs};

/// A construction found in one module, before it is matched against the catalog.
pub(crate) struct RawSite {
    /// The `WAWeb…WamEvent` module the construction requires.
    pub event_module: String,
    /// The export it constructs (`MessageSendWamEvent`), which names the event when a
    /// module defines more than one.
    pub export: String,
    /// Fields written by the constructor's own argument.
    pub fields: Vec<(String, WamFieldWrite, Option<WamCallSiteValue>)>,
    /// The constructor argument also carries values the scan could not read.
    pub partial: bool,
    /// The expression form of a constructor argument the scan could not read at all,
    /// carried rather than counted here: the same module is defined by several bundle
    /// files, so a residue counted during the scan would count one construction as
    /// many. The caller counts it once, after deduplication.
    pub unread_argument: Option<&'static str>,
    /// Position, so later writes can be attached to the nearest construction before them.
    pub start: u32,
    /// What the value is bound to, when it is bound at all.
    pub binding: Option<Binding>,
}

/// What a construction's value is bound to, and how far a write to it can be trusted
/// to be a write to *this* construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Binding {
    /// A local. WA reuses one-letter names across a module, so a write only counts
    /// where the name cannot mean anything else: inside the function that declared it,
    /// or inside a function nested in that one, which closes over the same binding —
    /// `var e = new …; setTimeout(function () { e.count = 1 })` writes the same event.
    Local { name: String, function: u32 },
    /// An instance property (`this.$2`). Its writes are spread across the methods of
    /// the class that holds it, so the immediate function boundary is exactly what must
    /// not be applied — `owner` is the outermost function inside the module factory,
    /// which is the class the minifier emits as one IIFE. Two classes in one module
    /// reusing the same slot therefore stay apart.
    Instance { name: String, owner: u32 },
}

/// A `<binding>.<field> = …` or `<binding>.set({…})` write. `field` is `None` when the
/// write's key is not readable — a spread, a computed name, an object built elsewhere —
/// which writes fields the published list cannot name and so makes its site partial.
struct RawWrite {
    binding: Binding,
    field: Option<String>,
    value: Option<WamCallSiteValue>,
    start: u32,
    /// The functions enclosing the write, outermost first.
    scope: Vec<u32>,
    /// The scope the write's own name resolves to: the innermost enclosing function that
    /// declares it as a parameter or a local. `None` when nothing visible declares it,
    /// which is where the scope chain above is all there is to go on.
    declared_in: Option<u32>,
}

/// Every construction in one module slice, with the post-construction writes already
/// attached to the site each belongs to.
pub(crate) fn scan_module(slice: &str) -> Vec<RawSite> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let aliases = crate::require_aliases(&ret.program);
    let mut v = SiteVisitor {
        bindings: BTreeMap::new(),
        sites: Vec::new(),
        writes: Vec::new(),
        scopes: vec![Scope {
            span: 0,
            names: std::collections::BTreeSet::new(),
        }],
        aliases: &aliases,
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    let SiteVisitor {
        mut sites, writes, ..
    } = v;
    sites.sort_by_key(|s| s.start);
    for w in writes {
        // The nearest construction before the write that binds the same name — nearest,
        // because a module reuses names, and the closest preceding construction is the
        // one the write was written for. A write that still lands on the wrong event has
        // to name a field that event declares to be published at all, which the caller
        // checks.
        let Some(site) = sites
            .iter_mut()
            .rfind(|s| s.start < w.start && binds(s.binding.as_ref(), &w))
        else {
            continue;
        };
        match w.field {
            Some(field) => site.fields.push((field, WamFieldWrite::Assigned, w.value)),
            // A key the scan could not read still writes a field, so the site's list
            // stops being the whole of what it writes.
            None => site.partial = true,
        }
    }
    sites
}

/// Whether a construction's binding is the one a write names.
///
/// For a local, the name has to resolve to the scope that declared the construction:
/// `var x = new …; f(function (x) { x.count = 1 })` writes the parameter, not the event,
/// and matching on the name plus the scope chain alone would publish it on the event
/// whenever the field name happens to fit. When nothing visible declares the name — WA
/// also writes `x = new …` with no declaration — the chain is all there is, so it stays
/// the fallback rather than dropping the write.
fn binds(binding: Option<&Binding>, w: &RawWrite) -> bool {
    match (binding, &w.binding) {
        (Some(Binding::Local { name, function }), Binding::Local { name: n, .. }) => {
            name == n
                && match w.declared_in {
                    Some(scope) => scope == *function,
                    None => w.scope.contains(function),
                }
        }
        (Some(b), other) => b == other,
        (None, _) => false,
    }
}

struct SiteVisitor<'m> {
    /// Span start of a `new` expression → the binding its result is given.
    bindings: BTreeMap<u32, Binding>,
    sites: Vec<RawSite>,
    writes: Vec<RawWrite>,
    /// The scopes being visited, outermost first, each with the names it declares as a
    /// parameter or a local. The first is the module itself; the next is the module
    /// factory, so the one after that is the class or top-level function that owns an
    /// instance property.
    scopes: Vec<Scope>,
    /// Locals standing for a `o("Module")` require, so an enum member written through
    /// one resolves the same way a field type written through one does.
    aliases: &'m RequireAliases,
}

/// One scope and the names it introduces.
struct Scope {
    span: u32,
    names: std::collections::BTreeSet<String>,
}

impl SiteVisitor<'_> {
    /// The scope a local declared here belongs to. `0` at module top level.
    fn function(&self) -> u32 {
        self.scopes.last().map(|s| s.span).unwrap_or(0)
    }

    /// The function that owns `this` here: the outermost one inside the module factory,
    /// which is the unit the minifier emits a class as.
    fn owner(&self) -> u32 {
        self.scopes
            .get(2)
            .map(|s| s.span)
            .unwrap_or_else(|| self.function())
    }

    /// The enclosing scope spans, outermost first.
    fn scope_chain(&self) -> Vec<u32> {
        self.scopes.iter().map(|s| s.span).collect()
    }

    /// The innermost enclosing scope that declares `name`.
    fn resolve(&self, name: &str) -> Option<u32> {
        self.scopes
            .iter()
            .rfind(|s| s.names.contains(name))
            .map(|s| s.span)
    }

    /// Record a name the current scope declares.
    fn declare(&mut self, name: &str) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.names.insert(name.to_string());
        }
    }

    /// Enter a function scope, with its parameters already declared in it.
    fn enter(&mut self, span: u32, params: &oxc_ast::ast::FormalParameters) {
        let names = params
            .items
            .iter()
            .filter_map(|p| p.pattern.get_identifier_name())
            .map(|n| n.to_string())
            .collect();
        self.scopes.push(Scope { span, names });
    }
}

impl<'a> Visit<'a> for SiteVisitor<'_> {
    fn visit_function(&mut self, f: &oxc_ast::ast::Function<'a>, flags: ScopeFlags) {
        self.enter(f.span.start, &f.params);
        walk::walk_function(self, f, flags);
        self.scopes.pop();
    }

    fn visit_arrow_function_expression(&mut self, f: &oxc_ast::ast::ArrowFunctionExpression<'a>) {
        self.enter(f.span.start, &f.params);
        walk::walk_arrow_function_expression(self, f);
        self.scopes.pop();
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(name) = d.id.get_identifier_name() {
            self.declare(&name);
        }
        if let Some(Expression::NewExpression(n)) = d.init.as_ref()
            && let Some(name) = d.id.get_identifier_name()
        {
            self.bindings.insert(
                n.span.start,
                Binding::Local {
                    name: name.to_string(),
                    function: self.function(),
                },
            );
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        if let Some(target) = binding_key(&a.left, self.function(), self.owner()) {
            if let Expression::NewExpression(n) = &a.right {
                self.bindings.insert(n.span.start, target);
            }
        } else if let Some(m) = a.left.as_member_expression()
            && let Some(field) = m.static_property_name()
            && let Some(base) = binding_key_expr(m.object(), self.function(), self.owner())
        {
            // `count += 1` writes the field, but `1` is not what goes out — the value
            // depends on what was there. The write is recorded; its value is not.
            let value = match a.operator {
                AssignmentOperator::Assign => literal_value(&a.right, self.aliases),
                _ => None,
            };
            let declared_in = binding_name(&base).and_then(|n| self.resolve(n));
            self.writes.push(RawWrite {
                binding: base,
                field: Some(field.to_string()),
                value,
                start: a.span.start,
                scope: self.scope_chain(),
                declared_in,
            });
        }
        walk::walk_assignment_expression(self, a);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // `event.set(…)` — the same write the constructor performs, spelled as a method,
        // so it is read by the same function: an object literal states its keys, a merge
        // states the ones it can and marks the rest unread, and anything else names
        // nothing and is a write this list cannot describe.
        if wa_oxc::callee_method(call) == Some("set")
            && let Some(base) = wa_oxc::callee_object(call)
                .and_then(|e| binding_key_expr(e, self.function(), self.owner()))
            && let Some(arg) = call.arguments.first().and_then(wa_oxc::arg_expr)
        {
            let mut fields = Vec::new();
            let mut partial = false;
            let mut unread = None;
            read_argument(arg, &mut fields, &mut partial, &mut unread, self.aliases);
            let declared_in = binding_name(&base).and_then(|n| self.resolve(n));
            for (field, _, value) in fields {
                self.writes.push(RawWrite {
                    binding: base.clone(),
                    field: Some(field),
                    value,
                    start: call.span.start,
                    scope: self.scope_chain(),
                    declared_in,
                });
            }
            // One unnamed write stands for everything the argument writes and the scan
            // could not name, whether that is a spread, a computed key, or an object
            // assembled somewhere else entirely.
            if partial || unread.is_some() {
                self.writes.push(RawWrite {
                    binding: base.clone(),
                    field: None,
                    value: None,
                    start: call.span.start,
                    scope: self.scope_chain(),
                    declared_in,
                });
            }
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, n: &NewExpression<'a>) {
        if let Some((module, export)) = wam_event_callee(&n.callee, self.aliases) {
            let mut fields = Vec::new();
            let mut partial = false;
            let mut unread_argument = None;
            match n.arguments.first().and_then(wa_oxc::arg_expr) {
                // `new (…)(…)` with no argument: a real, complete field set of zero.
                None => {}
                Some(arg) => read_argument(
                    arg,
                    &mut fields,
                    &mut partial,
                    &mut unread_argument,
                    self.aliases,
                ),
            }
            self.sites.push(RawSite {
                event_module: module.to_string(),
                export: export.to_string(),
                fields,
                partial,
                unread_argument,
                start: n.span.start,
                binding: self.bindings.get(&n.span.start).cloned(),
            });
        }
        walk::walk_new_expression(self, n);
    }
}

/// The fields a constructor argument writes. An object literal states them; a
/// `babelHelpers.extends(…)` merge states the ones its literal operands carry and marks
/// the site partial for the rest; anything else names none and is counted by form.
fn read_argument(
    arg: &Expression,
    fields: &mut Vec<(String, WamFieldWrite, Option<WamCallSiteValue>)>,
    partial: &mut bool,
    unread: &mut Option<&'static str>,
    aliases: &RequireAliases,
) {
    if let Some(obj) = as_object(arg) {
        for prop in &obj.properties {
            match prop {
                ObjectPropertyKind::ObjectProperty(p) => {
                    match wa_oxc::property_key_name(&p.key) {
                        Some(name) => fields.push((
                            name.to_string(),
                            WamFieldWrite::Constructor,
                            literal_value(&p.value, aliases),
                        )),
                        // A computed key writes a field whose name is a runtime value.
                        None => *partial = true,
                    }
                }
                // A spread merges keys from elsewhere.
                ObjectPropertyKind::SpreadProperty(_) => *partial = true,
            }
        }
        return;
    }
    if let Some(call) = as_call(arg)
        && is_object_merge(call)
    {
        for a in &call.arguments {
            match a.as_expression() {
                Some(e) if as_object(e).is_some() => {
                    read_argument(e, fields, partial, unread, aliases)
                }
                _ => *partial = true,
            }
        }
        return;
    }
    *partial = true;
    *unread = Some(expression_form(arg));
}

/// `babelHelpers.extends(a, b, …)` — the transpiler's object spread, and the only
/// merge helper WA's event constructions are handed.
fn is_object_merge(call: &CallExpression) -> bool {
    let Some((obj, prop)) = as_member(&call.callee) else {
        return false;
    };
    prop == "extends" && wa_oxc::as_identifier(obj) == Some("babelHelpers")
}

/// A coarse name for an expression form, for the drop counters.
fn expression_form(e: &Expression) -> &'static str {
    match e {
        Expression::Identifier(_) => "identifier",
        Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => "member",
        Expression::CallExpression(_) => "call",
        Expression::ConditionalExpression(_) => "conditional",
        Expression::LogicalExpression(_) => "logical",
        _ => "other",
    }
}

/// `new (o("WAWeb…WamEvent").<Export>)(…)` → `(module, export)`.
///
/// The module is usually required inline, but a reporter that emits several events
/// caches it first (`var E = o("WAWeb…WamEvent"); new E.FooWamEvent(…)`). Reading only
/// the inline form would lose those sites from the published list *and* from the
/// `constructions` denominator, so the loss would not even show up as a gap.
fn wam_event_callee<'b, 'a>(
    callee: &'b Expression<'a>,
    aliases: &'b RequireAliases,
) -> Option<(&'b str, &'b str)> {
    let (obj, export) = as_member(callee)?;
    let obj = unparen(obj);
    let module = match as_call(obj).and_then(first_string_arg) {
        Some(module) => module,
        None => {
            wa_oxc::as_identifier(obj).and_then(|id| aliases.module_at(id, obj.span().start))?
        }
    };
    module.ends_with("WamEvent").then_some((module, export))
}

/// The name a local binding carries, for resolving it against the enclosing scopes.
fn binding_name(binding: &Binding) -> Option<&str> {
    match binding {
        Binding::Local { name, .. } => Some(name),
        Binding::Instance { .. } => None,
    }
}

/// The expression inside any number of parentheses. The construction is minified as
/// `new(o("…")).Export(…)`, so the require call reaches the AST wrapped in the
/// parentheses `new` needs to bind to the member expression rather than to the call.
fn unparen<'b, 'a>(e: &'b Expression<'a>) -> &'b Expression<'a> {
    let mut cur = e;
    while let Expression::ParenthesizedExpression(p) = cur {
        cur = &p.expression;
    }
    cur
}

/// The binding an assignment target names, for `x = …` and `this.$2 = …`.
fn binding_key(
    target: &oxc_ast::ast::AssignmentTarget,
    function: u32,
    owner: u32,
) -> Option<Binding> {
    if let Some(name) = wa_oxc::assignment_target_name(target) {
        return Some(Binding::Local {
            name: name.to_string(),
            function,
        });
    }
    let m = target.as_member_expression()?;
    this_property(m).map(|p| Binding::Instance {
        name: p.to_string(),
        owner,
    })
}

/// The same binding, read off an expression (the base of a `<base>.<field>` write).
fn binding_key_expr(e: &Expression, function: u32, owner: u32) -> Option<Binding> {
    if let Some(name) = wa_oxc::as_identifier(e) {
        return Some(Binding::Local {
            name: name.to_string(),
            function,
        });
    }
    let m = e.as_member_expression()?;
    this_property(m).map(|p| Binding::Instance {
        name: p.to_string(),
        owner,
    })
}

/// `this.$2` → `$2`; anything whose object is not `this` → `None`.
fn this_property<'b, 'a>(m: &'b oxc_ast::ast::MemberExpression<'a>) -> Option<&'b str> {
    matches!(m.object(), Expression::ThisExpression(_))
        .then(|| m.static_property_name())
        .flatten()
}

/// The value a site writes, when it is fixed at extraction time. A runtime expression
/// yields `None` rather than a slice of source: a consumer must not have to parse
/// JavaScript to read this IR.
fn literal_value(e: &Expression, aliases: &RequireAliases) -> Option<WamCallSiteValue> {
    let e = unparen(e);
    match e {
        Expression::BooleanLiteral(b) => return Some(WamCallSiteValue::Bool { value: b.value }),
        // Minified booleans are `!0` / `!1`.
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            if let Some(n) = as_int(&u.argument) {
                return Some(WamCallSiteValue::Bool { value: n == 0 });
            }
        }
        _ => {}
    }
    if let Some(s) = as_string_lit(e) {
        return Some(WamCallSiteValue::Str {
            value: s.to_string(),
        });
    }
    if let Some(n) = as_int(e) {
        return Some(WamCallSiteValue::Int { value: n });
    }
    // `o("WAWebWamEnum…").ENUM_NAME.MEMBER` — named, not resolved to its integer, so it
    // still reads against the enum catalog after WA renumbers.
    if let Some((enum_obj, key)) = as_member(e)
        && let Some((holder, _)) = as_member(enum_obj)
        // `(e = o("WAWebWamEnum…")).TYPE.MEMBER` is the minifier's first use of a module
        // it reads more than once; every use after it is the bare local.
        && let holder = crate::unwrap_binding(holder)
        && let Some(module) = as_call(holder)
            .and_then(first_string_arg)
            // The minifier reads a repeatedly used enum module off a local, exactly as
            // it does in the event modules; resolve it at the position of this use.
            .or_else(|| {
                wa_oxc::as_identifier(holder)
                    .and_then(|id| aliases.module_at(id, holder.span().start))
            })
        && module.starts_with("WAWebWamEnum")
    {
        return Some(WamCallSiteValue::EnumMember {
            module: module.to_string(),
            key: key.to_string(),
        });
    }
    None
}
