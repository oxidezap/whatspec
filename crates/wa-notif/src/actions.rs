//! The notification **payload action union** (`w:gp2` and friends).
//!
//! [`crate`] catalogues the notification envelope: which `type`s exist, which handler
//! each forwards to, and the envelope fields (`to`, `from`, `participant`, `t`,
//! `addressing_mode`). What that envelope *carries* is a second, larger union: the
//! handler maps over the notification's children and switches on each child's tag,
//! returning a differently-shaped action per tag.
//!
//! ```js
//! stanza.mapChildren(function (child) {
//!   switch (child.tag()) {
//!     case TAG.ADD:           return { actionType: ACTIONS.ADD, participants: …, reason: … };
//!     case TAG.SUBJECT:       return { actionType: ACTIONS.SUBJECT, subject: child.attrString("subject"), … };
//!     case TAG.EPHEMERAL:     return { actionType: ACTIONS.EPHEMERAL, duration: child.attrInt("expiration") };
//!     case TAG.NOT_EPHEMERAL: return { actionType: ACTIONS.EPHEMERAL, duration: 0 };   // ← normalised
//!   }
//! })
//! ```
//!
//! Two things there are unrecoverable from the wire and are what this module exists to
//! pin down. The tag→action mapping is **many-to-one** (`not_ephemeral` normalises into
//! `ephemeral` with `duration: 0`, so a `NOT_EPHEMERAL` branch in a consumer is dead
//! code), and field names are **rebound** (the timer arrives in `expiration` but the
//! action field is `duration`; reading it as `ephemeralDuration` — the *create*
//! payload's spelling — silently yields 0).
//!
//! Both the case labels and the `actionType` values are `Module.CONST.MEMBER`
//! references, so they are resolved against the defining module rather than guessed.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Statement, SwitchStatement};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{
    NotifActionChild, NotifActionConstant, NotifActionDef, NotifActionField, NotifConstValue, wap,
};
use wa_oxc::{arg_expr, as_call, as_identifier, as_int, as_member, as_string_lit, callee_method};

/// One exported constant object, as `MEMBER → "wire value"`.
type ConstMap = HashMap<String, String>;

/// Resolves `o("Module").CONST_OBJECT.MEMBER` references to their wire string, against
/// the bundle's module slices. Memoized per `(module, object)`.
pub(crate) struct ConstResolver<'a> {
    slices: &'a HashMap<&'a str, &'a str>,
    cache: std::cell::RefCell<HashMap<(String, String), Option<ConstMap>>>,
}

impl<'a> ConstResolver<'a> {
    pub(crate) fn new(slices: &'a HashMap<&'a str, &'a str>) -> Self {
        Self {
            slices,
            cache: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// `o("Mod").OBJECT.MEMBER` → the member's string value.
    fn member(&self, module: &str, object: &str, member: &str) -> Option<String> {
        let key = (module.to_string(), object.to_string());
        if !self.cache.borrow().contains_key(&key) {
            let resolved = self
                .slices
                .get(module)
                .and_then(|slice| const_string_map(slice, object));
            self.cache.borrow_mut().insert(key.clone(), resolved);
        }
        self.cache.borrow()[&key]
            .as_ref()
            .and_then(|m| m.get(member).cloned())
    }

    /// Resolve the enum argument of an enum accessor — `o("Mod").ENUM_NAME`, a member
    /// *reference* rather than a `.MEMBER` lookup — to its full variant set, reusing the
    /// same resolver the request and response sides use so all three type an enum
    /// attribute identically.
    fn enum_ref(&self, e: &Expression) -> Option<wa_ir::AttrEnumRef> {
        let (obj, name) = as_member(e)?;
        let module = as_string_lit(arg_expr(as_call(obj)?.arguments.first()?)?)?;
        let def = wa_enums::resolve_named_enum(self.slices.get(module)?, module, name)?;
        let variants: Vec<wa_ir::AttrEnumVariant> = def
            .variants
            .into_iter()
            .map(|v| match v.value {
                wa_ir::Scalar::Str(s) => Some(wa_ir::AttrEnumVariant {
                    name: v.name,
                    value: s,
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        (!variants.is_empty()).then(|| wa_ir::AttrEnumRef {
            name: name.to_string(),
            module: module.to_string(),
            variants,
        })
    }

    /// Resolve a `o("Mod").OBJECT.MEMBER` expression, or `None` for anything else.
    fn resolve(&self, e: &Expression) -> Option<String> {
        let (obj, member) = as_member(e)?;
        let (owner, object) = as_member(obj)?;
        let module = as_string_lit(arg_expr(as_call(owner)?.arguments.first()?)?)?;
        self.member(module, object, member)
    }
}

/// Every `NAME: "value"` of a module's exported constant object, whether written as an
/// `Object.freeze({…})`, a `$InternalEnum({…})` or a bare object literal, and whether
/// exported inline (`l.TAGS = {…}`) or through a local (`var e = {…}; l.TAGS = e`).
///
/// Deliberately its own resolver rather than [`wa_enums::resolve_named_enum`]: that one
/// is intentionally narrow (it gates `Object.freeze` behind an allowlist, because the
/// app has thousands of frozen `CONSTANT_CASE` infra objects that must not leak into the
/// *enum catalog*). Here the object is named by the switch we are already reading, so
/// there is nothing to filter — only one specific export is ever asked for.
fn const_string_map(slice: &str, export: &str) -> Option<ConstMap> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    if ret.panicked {
        return None;
    }
    let mut collector = ConstCollector {
        locals: HashMap::new(),
        exports: HashMap::new(),
    };
    collector.visit_program(&ret.program);
    if let Some(direct) = collector.exports.get(export) {
        return match direct {
            Export::Inline(map) => Some(map.clone()),
            Export::Local(name) => collector.locals.get(name).cloned().flatten(),
        };
    }
    None
}

enum Export {
    Inline(ConstMap),
    Local(String),
}

struct ConstCollector {
    /// Local name → its all-string object, or `None` when the same minified name is
    /// bound to **different** objects in the module. The minifier reuses short
    /// identifiers aggressively across nested scopes, so a module-wide "last one wins"
    /// map could resolve an export to an unrelated nested table and mint wrong wire tags
    /// or `actionType` values. Ambiguity therefore resolves to nothing, which shows up
    /// as a missing action rather than a silently wrong one.
    locals: HashMap<String, Option<ConstMap>>,
    exports: HashMap<String, Export>,
}

impl<'a> Visit<'a> for ConstCollector {
    fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
        if let Some(name) = d.id.get_identifier_name()
            && let Some(map) = d.init.as_ref().and_then(string_const_object)
        {
            match self.locals.entry(name.to_string()) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(Some(map));
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // A second, different binding of the same name makes it ambiguous.
                    if e.get().as_ref() != Some(&map) {
                        e.insert(None);
                    }
                }
            }
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
        if let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            if let Some(map) = string_const_object(&a.right) {
                self.exports
                    .entry(prop.to_string())
                    .or_insert(Export::Inline(map));
            } else if let Some(id) = as_identifier(&a.right) {
                self.exports
                    .entry(prop.to_string())
                    .or_insert(Export::Local(id.to_string()));
            }
        }
        walk::walk_assignment_expression(self, a);
    }
}

/// An all-string-valued object literal, unwrapping the `Object.freeze(…)` /
/// `$InternalEnum(…)` / `ident(…)` single-argument wrappers WA writes them in.
/// `None` if any value isn't a string literal — a mixed object is not a token table.
fn string_const_object(e: &Expression) -> Option<ConstMap> {
    let obj = match wa_oxc::as_object(e) {
        Some(o) => o,
        // A single-argument wrapper call: `Object.freeze({…})`, `n("$InternalEnum")({…})`.
        None => wa_oxc::as_object(arg_expr(as_call(e)?.arguments.first()?)?)?,
    };
    let mut map = ConstMap::new();
    for (key, value) in wa_oxc::obj_props(obj) {
        map.insert(key.to_string(), as_string_lit(value)?.to_string());
    }
    (!map.is_empty()).then_some(map)
}

/// Extract a handler module's payload action union, if it has one.
///
/// Locates the `switch` whose cases are `Module.CONST.MEMBER` references resolving to
/// wire strings — the child-tag dispatch — and reads one [`NotifActionDef`] per arm.
/// `None` when the module has no such switch (most handlers forward straight to a
/// parser and carry no action union).
pub(crate) fn extract_actions(
    handler_slice: &str,
    consts: &ConstResolver,
) -> Option<Vec<NotifActionDef>> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, handler_slice);
    if ret.panicked {
        return None;
    }
    // Arms routinely delegate the bulk of their shape to a module-local helper
    // (`participants: y(chat, child, tag)` is where every participant list lives), so
    // the helpers are indexed up front and inlined on demand.
    let mut locals = LocalFns::default();
    locals.visit_program(&ret.program);
    // A minified helper name reused by a nested function would otherwise resolve to
    // whichever declaration was visited last, letting an arm inline an unrelated
    // function and emit wrong fields. Ambiguity resolves to nothing instead — the same
    // rule the constant tables use — so the failure is a missing action, not a wrong one.
    let mut by_name: HashMap<String, Option<String>> = HashMap::new();
    for (name, (a, b)) in locals.spans {
        let src = handler_slice[a..b].to_string();
        match by_name.entry(name) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(Some(src));
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if e.get().as_deref() != Some(src.as_str()) {
                    e.insert(None);
                }
            }
        }
    }
    let ctx = ArmCtx {
        consts,
        locals: by_name
            .into_iter()
            .filter_map(|(n, src)| src.map(|s| (n, s)))
            .collect(),
    };
    let mut finder = SwitchFinder {
        ctx: &ctx,
        best: None,
    };
    finder.visit_program(&ret.program);
    finder.best.filter(|v| !v.is_empty())
}

/// What an arm reader needs: the constant tables its labels resolve through, and the
/// module's local helper functions, as re-parsable source (keyed by name).
struct ArmCtx<'c, 'a> {
    consts: &'c ConstResolver<'a>,
    locals: HashMap<String, String>,
}

/// Collects `function name(…){…}` / `var name = function(…){…}` spans in a module.
#[derive(Default)]
struct LocalFns {
    spans: Vec<(String, (usize, usize))>,
}

impl<'a> Visit<'a> for LocalFns {
    fn visit_function(
        &mut self,
        f: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        if let Some(id) = f.id.as_ref() {
            let sp = oxc_span::GetSpan::span(f);
            self.spans
                .push((id.name.to_string(), (sp.start as usize, sp.end as usize)));
        }
        walk::walk_function(self, f, flags);
    }

    fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
        if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
            && matches!(
                init,
                Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
            )
        {
            let sp = oxc_span::GetSpan::span(init);
            self.spans
                .push((name.to_string(), (sp.start as usize, sp.end as usize)));
        }
        walk::walk_variable_declarator(self, d);
    }
}

struct SwitchFinder<'c, 'a> {
    ctx: &'c ArmCtx<'c, 'a>,
    /// The richest action union seen so far (a module can hold more than one
    /// const-keyed switch; the payload union is the one with the most arms).
    best: Option<Vec<NotifActionDef>>,
}

impl<'a> Visit<'a> for SwitchFinder<'_, 'a> {
    fn visit_switch_statement(&mut self, switch: &SwitchStatement<'a>) {
        let actions = extract_switch(switch, self.ctx);
        if actions.len() > self.best.as_ref().map_or(0, Vec::len) {
            self.best = Some(actions);
        }
        walk::walk_switch_statement(self, switch);
    }
}

/// Read every arm of a const-keyed child-tag switch into [`NotifActionDef`]s.
fn extract_switch(switch: &SwitchStatement, ctx: &ArmCtx) -> Vec<NotifActionDef> {
    let mut out = Vec::new();
    for (i, case) in switch.cases.iter().enumerate() {
        let Some(wire_tag) = case.test.as_ref().and_then(|t| ctx.consts.resolve(t)) else {
            continue;
        };
        // `case TAG_A: case TAG_B: return {…}` — a fall-through label has an empty body
        // and runs the next non-empty one. Recording it as an empty action would lose the
        // action type and every field of a legally dispatched tag.
        let consequent = switch.cases[i..]
            .iter()
            .map(|c| &c.consequent)
            .find(|c| !c.is_empty())
            .map(|c| &c[..])
            .unwrap_or(&case.consequent);
        let shapes = arm_result_shapes(consequent);
        if shapes.is_empty() {
            // A recognised tag whose arm returns no shape (a bare flag set, an early
            // break). Still catalogued: knowing the tag is dispatched at all beats
            // omitting it.
            out.push(empty_action(wire_tag));
            continue;
        }
        // An arm can branch into more than one shape. Which of the two it is matters:
        // `description` branches into two DIFFERENT actions (`desc_remove` when the
        // child has a `<delete>`, else `desc_add`), while `ephemeral` branches into the
        // SAME action behind a feature flag, differing only in extra optional fields.
        // So branches are grouped by `actionType`: different ones stay separate arms of
        // the union, identical ones merge into one (a field only some branches read is
        // optional in the merge).
        let mut grouped: Vec<NotifActionDef> = Vec::new();
        for (shape, scope) in shapes {
            for action in expand_shape(&wire_tag, shape, &scope, ctx, 0) {
                match grouped
                    .iter_mut()
                    .find(|g| g.action_type == action.action_type)
                {
                    Some(existing) => merge_action(existing, action),
                    None => grouped.push(action),
                }
            }
        }
        out.extend(grouped);
    }
    out
}

fn empty_action(wire_tag: String) -> NotifActionDef {
    NotifActionDef {
        wire_tag,
        action_type: None,
        fields: Vec::new(),
        constant_fields: Vec::new(),
        children: Vec::new(),
    }
}

/// Fold a second branch of the same action into the first: a field either branch reads
/// is present, and required only if BOTH read it unconditionally. A constant only one
/// branch stamps is dropped — it is not a property of the action, only of that branch.
fn merge_action(into: &mut NotifActionDef, from: NotifActionDef) {
    // A field the incoming branch does not read at all is, by definition, absent from
    // one legal shape of this action — so it cannot stay required just because the
    // first branch read it unconditionally. Weaken those before folding the rest in.
    for existing in into.fields.iter_mut() {
        if !from.fields.iter().any(|f| f.name == existing.name) {
            existing.required = false;
        }
    }
    for f in from.fields {
        match into.fields.iter_mut().find(|x| x.name == f.name) {
            Some(existing) => existing.required &= f.required,
            None => into.fields.push(NotifActionField {
                required: false,
                ..f
            }),
        }
    }
    for c in from.children {
        if !into.children.iter().any(|x| x.name == c.name) {
            into.children.push(c);
        }
    }
    into.constant_fields
        .retain(|c| from.constant_fields.contains(c));
}

/// Every distinct result shape an arm can return: one per branch of a `cond ? A : B`
/// (nested ternaries included), each with its `babelHelpers.extends(…)` merged away.
fn arm_result_shapes<'b, 'a>(consequent: &'b [Statement<'a>]) -> Vec<Shape<'b, 'a>> {
    arm_result_shapes_in(consequent, &Scope::new())
}

/// As [`arm_result_shapes`], with an enclosing scope the branches layer over.
fn arm_result_shapes_in<'b, 'a>(
    consequent: &'b [Statement<'a>],
    outer: &Scope<'b, 'a>,
) -> Vec<Shape<'b, 'a>> {
    let stmts = match consequent {
        [Statement::BlockStatement(b)] => &b.body[..],
        other => other,
    };
    let mut out = Vec::new();
    collect_returns(stmts, outer, &mut out);
    out
}

/// Every `return` reachable in `stmts`, descending through control flow (`if`/`else`,
/// blocks, `try`) but never into a nested function or a nested `switch` — an arm or helper that
/// writes `if (cond) return {actionType: A, …}; return {actionType: B, …}` exposes both
/// shapes, where a direct-children-only scan would silently keep just the last.
/// The result shapes of a function expression, handling the implicit return of an
/// expression-bodied arrow (`p => userJidToUserWid(p.attrUserJid("jid"))`), whose body
/// oxc stores as a lone `ExpressionStatement` rather than a `return`.
fn fn_result_shapes<'b, 'a>(e: &'b Expression<'a>, base: &Scope<'b, 'a>) -> Vec<Shape<'b, 'a>> {
    if let Expression::ArrowFunctionExpression(arrow) = e
        && let Some(expr) = arrow.get_expression()
    {
        let mut branches = Vec::new();
        collect_branches(expr, &mut branches);
        return branches.into_iter().map(|x| (x, base.clone())).collect();
    }
    function_body_of(e)
        .map(|stmts| arm_result_shapes_in(stmts, base))
        .unwrap_or_default()
}

fn collect_returns<'b, 'a>(
    stmts: &'b [Statement<'a>],
    outer: &Scope<'b, 'a>,
    out: &mut Vec<Shape<'b, 'a>>,
) {
    // This level's declarations, layered over the enclosing ones. Built per branch on
    // purpose: mutually exclusive branches routinely rebind the same minified name to
    // DIFFERENT accessors, and a single flattened scope would make one branch's return
    // read the other branch's attribute — a wrong `wireName`, not a missing field.
    let mut scope = outer.clone();
    for s in stmts {
        if let Statement::VariableDeclaration(decl) = s {
            for d in &decl.declarations {
                if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref()) {
                    scope.insert(name.as_str(), init);
                }
            }
        }
    }
    for s in stmts {
        match s {
            Statement::ReturnStatement(r) => {
                if let Some(arg) = r.argument.as_ref() {
                    let mut branches = Vec::new();
                    collect_branches(arg, &mut branches);
                    out.extend(branches.into_iter().map(|e| (e, scope.clone())));
                }
            }
            Statement::BlockStatement(b) => collect_returns(&b.body, &scope, out),
            Statement::IfStatement(i) => {
                collect_returns(std::slice::from_ref(&i.consequent), &scope, out);
                if let Some(alt) = &i.alternate {
                    collect_returns(std::slice::from_ref(alt), &scope, out);
                }
            }
            Statement::TryStatement(t) => collect_returns(&t.block.body, &scope, out),
            // Deliberately NOT descending into a nested `switch`: that is a different
            // dispatch level, and its arms are other actions' shapes, not branches of
            // this one.
            _ => {}
        }
    }
}

fn collect_branches<'b, 'a>(e: &'b Expression<'a>, out: &mut Vec<&'b Expression<'a>>) {
    match e {
        Expression::ConditionalExpression(c) => {
            collect_branches(&c.consequent, out);
            collect_branches(&c.alternate, out);
        }
        Expression::ParenthesizedExpression(p) => collect_branches(&p.expression, out),
        other => out.push(other),
    }
}

/// The `var x = <expr>` bindings of one statement list, so a result object that names a
/// local (`{ id: n }` after `var n = jidToWid(child.attrGroupJid("jid"))`) still resolves
/// to the wire read behind it. WA's minifier hoists nearly every accessor into a local,
/// so without this most helper-built shapes would read as fieldless.
type Scope<'b, 'a> = HashMap<&'b str, &'b Expression<'a>>;

/// A result shape together with the bindings in force where it is returned.
type Shape<'b, 'a> = (&'b Expression<'a>, Scope<'b, 'a>);

/// A single flat scope for callers that have no return path to attribute a binding to
/// (the object-property walker visits every property in a callback at once).
///
/// Without a path, a name rebound to a *different* initializer in a sibling branch
/// cannot be resolved correctly — so it is refused rather than guessed, the same
/// "missing, not wrong" rule the constant tables and helper names follow.
fn scope_bindings<'b, 'a>(stmts: &'b [Statement<'a>]) -> Scope<'b, 'a> {
    let mut out = Scope::new();
    let mut ambiguous: Vec<&str> = Vec::new();
    collect_bindings(stmts, &mut out, &mut ambiguous);
    for name in ambiguous {
        out.remove(name);
    }
    out
}

/// Collect `var` bindings through control flow, mirroring [`collect_returns`].
///
/// `var` is function-scoped in JS, so a declaration inside an `if` block is in scope for
/// the whole function — and now that returns are collected from nested branches, their
/// locals have to be too, or `if (c) { var id = child.attrString("id"); return {id} }`
/// yields a return whose `id` resolves to nothing and is silently dropped. First binding
/// wins, so the walk order (source order) decides, not the recursion order.
fn collect_bindings<'b, 'a>(
    stmts: &'b [Statement<'a>],
    out: &mut Scope<'b, 'a>,
    ambiguous: &mut Vec<&'b str>,
) {
    for s in stmts {
        match s {
            Statement::VariableDeclaration(decl) => {
                for d in &decl.declarations {
                    if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                    {
                        match out.entry(name.as_str()) {
                            std::collections::hash_map::Entry::Vacant(e) => {
                                e.insert(init);
                            }
                            std::collections::hash_map::Entry::Occupied(e) => {
                                if !std::ptr::eq(*e.get(), init) {
                                    ambiguous.push(name.as_str());
                                }
                            }
                        }
                    }
                }
            }
            Statement::BlockStatement(b) => collect_bindings(&b.body, out, ambiguous),
            Statement::IfStatement(i) => {
                collect_bindings(std::slice::from_ref(&i.consequent), out, ambiguous);
                if let Some(alt) = &i.alternate {
                    collect_bindings(std::slice::from_ref(alt), out, ambiguous);
                }
            }
            Statement::TryStatement(t) => collect_bindings(&t.block.body, out, ambiguous),
            _ => {}
        }
    }
}

/// Follow a bare identifier through the scope to the expression bound to it. Bounded so
/// a self-referential minified binding can't loop.
fn deref_ident<'b, 'a>(e: &'b Expression<'a>, scope: &Scope<'b, 'a>) -> &'b Expression<'a> {
    let mut cur = e;
    for _ in 0..4 {
        let Some(name) = as_identifier(cur) else {
            return cur;
        };
        match scope.get(name) {
            Some(bound) if !std::ptr::eq(*bound, cur) => cur = bound,
            _ => return cur,
        }
    }
    cur
}

/// Turn one arm result shape into the action(s) it can produce.
///
/// A shape that *delegates wholesale* to a module-local helper (`case UNLINK: return
/// I(child)`) is not one action: the helper branches, and its branches can be different
/// actions — `I` returns `delete_parent_group_unlink`, `integrity_parent_group_unlink`
/// and the sub-group variants depending on `unlink_type` and `unlink_reason`. Folding
/// them into one definition keeps whichever `actionType` resolved first and silently
/// drops the rest, so the helper's branches are expanded into sibling shapes and run
/// through the same merge-by-`actionType` grouping the switch arms use.
///
/// A helper called in *value position* (`participants: y(chat, child, tag)`) is a
/// different thing — it contributes fields to the enclosing action — and keeps being
/// folded in by [`fold_object`].
fn expand_shape(
    wire_tag: &str,
    result: &Expression,
    scope: &Scope,
    ctx: &ArmCtx,
    depth: u8,
) -> Vec<NotifActionDef> {
    if depth <= MAX_INLINE_DEPTH
        && let Some(src) = local_call_source(deref_ident(result, scope), ctx)
    {
        let expanded = expand_helper(wire_tag, &src, ctx, depth + 1);
        if !expanded.is_empty() {
            return expanded;
        }
    }
    vec![read_action(wire_tag.to_string(), result, scope, ctx, depth)]
}

/// Parse a helper and expand each of its result branches, inside this parse's own
/// allocator (only the owned definitions escape).
fn expand_helper(wire_tag: &str, fn_src: &str, ctx: &ArmCtx, depth: u8) -> Vec<NotifActionDef> {
    let alloc = Allocator::default();
    let wrapped = format!("({fn_src})");
    let ret = wa_oxc::parse_cjs(&alloc, &wrapped);
    if ret.panicked {
        return Vec::new();
    }
    let Some(func) = ret.program.body.iter().find_map(|s| match s {
        Statement::ExpressionStatement(es) => Some(&es.expression),
        _ => None,
    }) else {
        return Vec::new();
    };
    let mut out: Vec<NotifActionDef> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &Scope::new()) {
        for action in expand_shape(wire_tag, shape, &scope, ctx, depth) {
            match out.iter_mut().find(|g| g.action_type == action.action_type) {
                Some(existing) => merge_action(existing, action),
                None => out.push(action),
            }
        }
    }
    out
}

/// Read one arm result shape into a [`NotifActionDef`].
///
/// The shape is an object literal, a `babelHelpers.extends(a, b, …)` of several, or a
/// call to a module-local helper that builds one (`return T(chat, child, author)`) —
/// all three are folded into the same definition.
fn read_action<'b, 'a>(
    wire_tag: String,
    result: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    ctx: &ArmCtx,
    depth: u8,
) -> NotifActionDef {
    let mut def = empty_action(wire_tag);
    fold_shape(result, scope, &mut def, ctx, depth);
    def.constant_fields.sort_by(|a, b| a.name.cmp(&b.name));
    def
}

/// Fold one result expression's contribution into `def`.
fn fold_shape<'b, 'a>(
    e: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    def: &mut NotifActionDef,
    ctx: &ArmCtx,
    depth: u8,
) {
    if depth > MAX_INLINE_DEPTH {
        return;
    }
    let e = deref_ident(e, scope);
    match e {
        Expression::ParenthesizedExpression(p) => fold_shape(&p.expression, scope, def, ctx, depth),
        // `babelHelpers.extends(objLiteral, helper(child), …)` — every argument
        // contributes; WA uses it precisely to merge a helper's fields into an arm.
        Expression::CallExpression(c) if callee_method(c) == Some("extends") => {
            for arg in &c.arguments {
                if let Some(inner) = arg_expr(arg) {
                    fold_shape(inner, scope, def, ctx, depth + 1);
                }
            }
        }
        Expression::ObjectExpression(_) => fold_object(e, scope, def, ctx, depth),
        _ => {
            // A helper whose whole result is a repeated element (`return
            // child.mapChildrenWithTag("participant", …)` — where every participant
            // list lives). The caller names it after the key it was bound to.
            if let Some(child) = mapped_child("", e, scope, ctx.consts) {
                def.children.push(child);
            } else if let Some(src) = local_call_source(e, ctx) {
                inline_local(&src, def, ctx, depth);
            }
        }
    }
}

/// How deep a chain of helper inlinings is followed. Three is enough for every observed
/// arm (`arm → participants helper → per-participant object`) and bounds a cycle.
const MAX_INLINE_DEPTH: u8 = 3;

/// The source of the module-local helper `e` calls, if it is one.
fn local_call_source(e: &Expression, ctx: &ArmCtx) -> Option<String> {
    let call = as_call(e)?;
    let name = as_identifier(&call.callee)?;
    ctx.locals.get(name).cloned()
}

/// Re-parse a helper's source and fold each of its result branches into `def`.
///
/// The inlining happens inside this parse's own allocator, so no AST reference escapes
/// it — the helper's contribution is accumulated straight into `def`.
fn inline_local(fn_src: &str, def: &mut NotifActionDef, ctx: &ArmCtx, depth: u8) {
    let alloc = Allocator::default();
    // Wrapped in parens so a `function name(…){…}` declaration parses as an expression.
    let wrapped = format!("({fn_src})");
    let ret = wa_oxc::parse_cjs(&alloc, &wrapped);
    if ret.panicked {
        return;
    }
    let Some(func) = ret.program.body.iter().find_map(|s| match s {
        Statement::ExpressionStatement(es) => Some(&es.expression),
        _ => None,
    }) else {
        return;
    };
    // Each of the helper's result branches is folded on its own and then MERGED, not
    // accumulated: a helper returning `{x: …}` in one branch and `{y: …}` in another
    // describes two legal shapes, and combining them would make the enclosing action
    // require both and reject either. `merge_action` weakens what only some branches
    // carry — the same rule the switch arms use.
    let mut branches: Vec<NotifActionDef> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &Scope::new()) {
        let mut one = empty_action(String::new());
        fold_shape(shape, &scope, &mut one, ctx, depth + 1);
        match branches
            .iter_mut()
            .find(|b| b.action_type == one.action_type)
        {
            Some(existing) => merge_action(existing, one),
            None => branches.push(one),
        }
    }
    // Distinct action types cannot arise here (a value-position helper contributes
    // fields, it does not pick the action), so folding the merged branches in is safe.
    for b in branches {
        merge_into(def, b);
    }
}

/// Fold a helper's contribution into the enclosing action, keeping what the enclosing
/// object already stated and weakening nothing it owns.
fn merge_into(def: &mut NotifActionDef, from: NotifActionDef) {
    if def.action_type.is_none() {
        def.action_type = from.action_type;
    }
    for f in from.fields {
        if !def.fields.iter().any(|x| x.name == f.name) {
            def.fields.push(f);
        }
    }
    for c in from.children {
        if !def.children.iter().any(|x| x.name == c.name) {
            def.children.push(c);
        }
    }
    for c in from.constant_fields {
        if !def.constant_fields.iter().any(|x| x.name == c.name) {
            def.constant_fields.push(c);
        }
    }
}

/// The statement list of a function expression / declaration.
fn function_body_of<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b [Statement<'a>]> {
    match e {
        Expression::ParenthesizedExpression(p) => function_body_of(&p.expression),
        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| b.statements.as_slice()),
        Expression::ArrowFunctionExpression(f) => Some(f.body.statements.as_slice()),
        _ => None,
    }
}

/// Read the `{ key: value, … }` properties of one result shape into `def`.
fn fold_object<'b, 'a>(
    obj: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    def: &mut NotifActionDef,
    ctx: &ArmCtx,
    depth: u8,
) {
    let Some(o) = wa_oxc::as_object(obj) else {
        return;
    };
    for (key, value) in wa_oxc::obj_props(o) {
        // The normalised action identity. Resolved through the const table, so the
        // many-to-one mapping (`not_ephemeral` → `ephemeral`) is recorded as WA means
        // it, not as the case label suggests. `None` when the arm computes it (e.g.
        // `link` selects between three actions by its own `link_type` attribute) —
        // recorded as unknown rather than guessed.
        let value = deref_ident(value, scope);
        if key == "actionType" {
            if def.action_type.is_none() {
                def.action_type = ctx.consts.resolve(value);
            }
            continue;
        }
        if let Some(c) = const_value(value) {
            push_constant(def, key, c);
            continue;
        }
        if let Some(child) = mapped_child(key, value, scope, ctx.consts) {
            if !def.children.iter().any(|x| x.name == child.name) {
                def.children.push(child);
            }
            continue;
        }
        // A helper call in value position (`participants: y(chat, child, tag)`): inline
        // it under this key — that is where every participant list actually lives.
        if let Some(src) = local_call_source(strip_guard(value), ctx)
            && depth < MAX_INLINE_DEPTH
        {
            let mut nested = empty_action(String::new());
            inline_local(&src, &mut nested, ctx, depth);
            // A helper whose result is a repeated element becomes this key's child list;
            // one that returns a flat object contributes its fields under their own names.
            for mut c in nested.children {
                c.name = key.to_string();
                if !def.children.iter().any(|x| x.name == c.name) {
                    def.children.push(c);
                }
            }
            for f in nested.fields {
                if !def.fields.iter().any(|x| x.name == f.name) {
                    def.fields.push(f);
                }
            }
            continue;
        }
        if let Some(field) = read_field(key, value, scope, ctx.consts)
            && !def.fields.iter().any(|x| x.name == field.name)
        {
            def.fields.push(field);
        }
    }
}

fn push_constant(def: &mut NotifActionDef, name: &str, value: NotifConstValue) {
    if !def.constant_fields.iter().any(|c| c.name == name) {
        def.constant_fields.push(NotifActionConstant {
            name: name.to_string(),
            value,
        });
    }
}

/// A literal an arm stamps unconditionally (`value: !0`, `duration: 0`, `type: "x"`).
fn const_value(e: &Expression) -> Option<NotifConstValue> {
    match e {
        Expression::BooleanLiteral(b) => Some(NotifConstValue::Bool(b.value)),
        Expression::StringLiteral(s) => Some(NotifConstValue::Str(s.value.to_string())),
        // The minifier writes booleans as `!0` / `!1`.
        Expression::UnaryExpression(u) if u.operator == oxc_ast::ast::UnaryOperator::LogicalNot => {
            as_int(&u.argument).map(|n| NotifConstValue::Bool(n == 0))
        }
        _ => as_int(e).map(NotifConstValue::Int),
    }
}

/// `child.mapChildrenWithTag("participant", function (p) { … })` → the repeated
/// sub-element and the fields read off each one.
fn mapped_child<'b, 'a>(
    key: &str,
    e: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    consts: &ConstResolver,
) -> Option<NotifActionChild> {
    let call = as_call(strip_guard(e))?;
    if callee_method(call)? != wap::MAP_CHILDREN_WITH_TAG {
        return None;
    }
    let wire_tag = arg_expr(call.arguments.first()?).and_then(as_string_lit)?;
    let mut fields = Vec::new();
    for arg in &call.arguments {
        if let Some(e) = arg_expr(arg) {
            collect_accessor_fields(e, scope, consts, &mut fields);
        }
    }
    Some(NotifActionChild {
        name: key.to_string(),
        wire_tag: wire_tag.to_string(),
        fields,
    })
}

/// Read a single output field from the expression bound to `key`.
///
/// Handles the four shapes an arm uses: a bare accessor (`child.attrString("subject")`),
/// a presence guard (`child.hasAttr("reason") ? f(child.attrString("reason")) : null`),
/// a null-coalesce (`(x = child.maybeAttrString("t")) != null ? x : d`), and a content
/// read (`child.child("body").contentString()`). Anything else — a computed value with
/// no single wire source — yields `None` rather than a guessed name.
fn read_field<'b, 'a>(
    key: &str,
    e: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    consts: &ConstResolver,
) -> Option<NotifActionField> {
    let e = deref_ident(e, scope);
    let optional_by_guard = is_guarded(e);
    let acc = find_accessor(strip_guard(e), scope)?;
    Some(NotifActionField {
        name: key.to_string(),
        wire_name: acc.wire_name,
        field_type: wap::method_field_type(&acc.method),
        required: !optional_by_guard && !wap::is_optional_method(&acc.method),
        content: acc.content,
        enum_ref: acc.enum_arg.and_then(|a| consts.enum_ref(a)),
    })
}

/// Whether the value is read behind a presence guard, so the attribute may be absent.
///
/// A ternary and a `guard && value` both gate the read on something. `a || b` / `a ?? b`
/// do NOT: the accessor on the left runs unconditionally and `attrString` still rejects
/// an absent attribute — the right operand only supplies a default for a value the
/// parser already required. Treating those as guards marked required fields optional.
fn is_guarded(e: &Expression) -> bool {
    match e {
        Expression::ConditionalExpression(_) => true,
        Expression::LogicalExpression(l) => {
            l.operator == oxc_syntax::operator::LogicalOperator::And
        }
        _ => false,
    }
}

/// The value branch of a `cond ? value : fallback` / `a || b` guard, else `e` itself.
///
/// The minifier's null-coalesce idiom hides the accessor in the *test*:
/// `(x = child.maybeAttrString("threshold")) != null ? x : void 0`. The consequent is
/// then a bare `x` that no declaration binds, so following it alone loses the field
/// (`locked`'s `threshold` vanished exactly this way). When the consequent is an
/// identifier assigned inside the test, the assignment's right-hand side is the value.
fn strip_guard<'b, 'a>(e: &'b Expression<'a>) -> &'b Expression<'a> {
    match e {
        Expression::ConditionalExpression(c) => {
            let value = strip_guard(&c.consequent);
            match as_identifier(value).and_then(|name| assigned_in(&c.test, name)) {
                Some(assigned) => strip_guard(assigned),
                None => value,
            }
        }
        Expression::ParenthesizedExpression(p) => strip_guard(&p.expression),
        // `guard && value` puts the value on the RIGHT — taking the left yields the
        // `hasAttr` test, which is deliberately not a wire accessor, so the field would
        // vanish. `a || b` / `a ?? b` are the opposite: the left IS the value and the
        // right only defaults it.
        Expression::LogicalExpression(l) => match l.operator {
            oxc_syntax::operator::LogicalOperator::And => strip_guard(&l.right),
            _ => strip_guard(&l.left),
        },
        Expression::AssignmentExpression(a) => strip_guard(&a.right),
        _ => e,
    }
}

/// The right-hand side of an `name = <expr>` assignment somewhere inside `e`.
fn assigned_in<'b, 'a>(e: &'b Expression<'a>, name: &str) -> Option<&'b Expression<'a>> {
    match e {
        Expression::AssignmentExpression(a) => {
            let target = a.left.get_identifier_name().map(|n| n.to_string());
            if target.as_deref() == Some(name) {
                Some(&a.right)
            } else {
                assigned_in(&a.right, name)
            }
        }
        Expression::ParenthesizedExpression(p) => assigned_in(&p.expression, name),
        Expression::BinaryExpression(b) => {
            assigned_in(&b.left, name).or_else(|| assigned_in(&b.right, name))
        }
        Expression::LogicalExpression(l) => {
            assigned_in(&l.left, name).or_else(|| assigned_in(&l.right, name))
        }
        Expression::UnaryExpression(u) => assigned_in(&u.argument, name),
        _ => None,
    }
}

/// The innermost wap accessor call in `e` → `(method, wireName, isContentRead)`.
///
/// Descends through the wrapper calls an arm applies to a raw wire value
/// (`userJidToUserWid(child.attrUserJid("jid"))`, `S(child.attrString("reason"))`), and
/// through a `child("body").contentString()` chain — where the *tag* is the wire name,
/// since a content read has no attribute of its own.
fn find_accessor<'b, 'a>(e: &'b Expression<'a>, scope: &Scope<'b, 'a>) -> Option<Accessor<'b, 'a>> {
    find_accessor_at(e, scope, 0)
}

/// A resolved wire read: the accessor method, the attribute (or child tag) it reads,
/// whether it is a content read, and the enum argument it validates against, if any.
struct Accessor<'b, 'a> {
    method: String,
    wire_name: String,
    content: bool,
    enum_arg: Option<&'b Expression<'a>>,
}

/// How deep the wrapper-call descent goes. Bounded like every other descent in this
/// module: mutually referential minified bindings (`var a = g(b), b = g(a)` — legal JS,
/// and the minifier reuses short names aggressively) would otherwise cycle through
/// `deref_ident` and blow the stack, turning a bundle shape into a hard crash of the
/// generator instead of a field that simply isn't recovered.
const MAX_ACCESSOR_DEPTH: u8 = 8;

fn find_accessor_at<'b, 'a>(
    e: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    depth: u8,
) -> Option<Accessor<'b, 'a>> {
    if depth > MAX_ACCESSOR_DEPTH {
        return None;
    }
    let call = as_call(deref_ident(e, scope))?;
    if let Some(method) = callee_method(call) {
        let arg0 = call.arguments.first().and_then(arg_expr);
        let name = arg0.and_then(as_string_lit);
        if let Some(name) = name
            && is_wire_accessor(method)
        {
            // An enum accessor takes the enum as a further argument
            // (`maybeAttrEnum("type", o("Mod").GROUP_PARTICIPANT_TYPES)`) — often hoisted
            // into a local first (`attrEnumOrNullIfUnknown("reason", v)`), so the
            // candidate is dereferenced through the scope before being recognised.
            let enum_arg = call
                .arguments
                .iter()
                .skip(1)
                .filter_map(arg_expr)
                .map(|a| deref_ident(a, scope))
                .find(|a| as_member(a).is_some());
            return Some(Accessor {
                method: method.to_string(),
                wire_name: name.to_string(),
                content: false,
                enum_arg,
            });
        }
        // `X.contentString()` / `X.contentInt()` — no argument; the wire name is the tag
        // of whatever `X` descends to, and `""` when it reads the arm's own node.
        if matches!(
            method,
            wap::CONTENT_STRING | wap::CONTENT_INT | wap::CONTENT_BYTES
        ) {
            // The receiver is often hoisted (`var body = child.child("body"); … body
            // .contentString()`), so it must be dereferenced through the scope first —
            // otherwise the wire name comes out empty and a consumer cannot tell content
            // read from a nested child apart from content read on the action node.
            let tag = wa_oxc::callee_object(call)
                .map(|obj| deref_ident(obj, scope))
                .and_then(as_call)
                .and_then(|inner| inner.arguments.first().and_then(arg_expr))
                .and_then(as_string_lit)
                .unwrap_or_default();
            return Some(Accessor {
                method: method.to_string(),
                wire_name: tag.to_string(),
                content: true,
                enum_arg: None,
            });
        }
    }
    // A wrapper call (`userJidToUserWid(…)`, a local normaliser): look inside.
    call.arguments
        .iter()
        .filter_map(arg_expr)
        .find_map(|a| find_accessor_at(a, scope, depth + 1))
}

/// Whether `method` is a wap accessor that reads a named wire attribute. Keyed on the
/// accessor prefix rather than an exhaustive list so a new JID/time flavour is covered
/// automatically; `hasAttr` is excluded because it is the *guard*, not the read.
fn is_wire_accessor(method: &str) -> bool {
    (method.starts_with("attr") || method.starts_with("maybeAttr")) && method != wap::HAS_ATTR
}

/// Collect every wire accessor reachable inside a mapped-child callback, as fields.
/// Order follows source order; duplicates (the same attribute read twice, e.g. once for
/// a derived flag) are folded into the first occurrence.
fn collect_accessor_fields<'b, 'a>(
    e: &'b Expression<'a>,
    outer: &Scope<'b, 'a>,
    consts: &ConstResolver,
    out: &mut Vec<NotifActionField>,
) {
    // The callback's own `var` bindings, layered over the enclosing scope: the minifier
    // hoists most reads into locals inside the callback too.
    let mut scope = outer.clone();
    if let Some(stmts) = function_body_of(e) {
        scope.extend(scope_bindings(stmts));
    }
    struct Walker<'o, 'b, 'a> {
        scope: &'o Scope<'b, 'a>,
        consts: &'o ConstResolver<'o>,
        out: &'o mut Vec<NotifActionField>,
    }
    impl<'b, 'a> Visit<'a> for Walker<'_, 'b, 'a> {
        fn visit_object_property(&mut self, p: &oxc_ast::ast::ObjectProperty<'a>) {
            if let Some(key) = wa_oxc::property_key_name(&p.key)
                && let Some(field) = read_field(key, &p.value, self.scope, self.consts)
                && !self.out.iter().any(|f| f.name == field.name)
            {
                self.out.push(field);
            }
            walk::walk_object_property(self, p);
        }
    }
    // Only function arguments hold the per-element shape; a bare expression contributes
    // nothing (the tag string, the bounds).
    if matches!(
        e,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    ) {
        let mut w = Walker {
            scope: &scope,
            consts,
            out,
        };
        w.visit_expression(e);
    }
    // A callback that returns a bare value rather than an object
    // (`p => userJidToUserWid(p.attrUserJid("jid"))`) has no property key to name the
    // field by, so the wire attribute names it — better than reporting no fields at all.
    if out.is_empty() {
        for (shape, inner) in fn_result_shapes(e, &scope) {
            if let Some(acc) = find_accessor(shape, &inner) {
                out.push(NotifActionField {
                    name: acc.wire_name.clone(),
                    wire_name: acc.wire_name,
                    field_type: wap::method_field_type(&acc.method),
                    required: !wap::is_optional_method(&acc.method),
                    content: acc.content,
                    enum_ref: acc.enum_arg.and_then(|a| consts.enum_ref(a)),
                });
            }
        }
    }
}
