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
    /// `(module, enum)` → its resolved variants. Memoized for the same reason `cache` is:
    /// `resolve_named_enum` re-parses the whole module slice, and the resolver is hit once
    /// per enum-accessor field — including a second time by the bare-value fallback, which
    /// re-walks the same shapes.
    enums: std::cell::RefCell<HashMap<(String, String), Option<wa_ir::AttrEnumRef>>>,
}

impl<'a> ConstResolver<'a> {
    pub(crate) fn new(slices: &'a HashMap<&'a str, &'a str>) -> Self {
        Self {
            slices,
            cache: std::cell::RefCell::new(HashMap::new()),
            enums: std::cell::RefCell::new(HashMap::new()),
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
        let key = (module.to_string(), name.to_string());
        if let Some(hit) = self.enums.borrow().get(&key) {
            return hit.clone();
        }
        let resolved = self.resolve_enum_uncached(module, name);
        self.enums.borrow_mut().insert(key, resolved.clone());
        resolved
    }

    fn resolve_enum_uncached(&self, module: &str, name: &str) -> Option<wa_ir::AttrEnumRef> {
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
        // Only the module factory's own parameters count as export receivers. Without
        // that, `cache.GROUP_ACTIONS = local` written before the real
        // `exports.GROUP_ACTIONS = actual` would be taken as the export and — being
        // first — kept, resolving case labels through an unrelated table and minting
        // wrong wire tags. Empty when the factory shape is not recognised, in which case
        // any identifier receiver is accepted, as before: a narrower rule must not turn
        // an unfamiliar module into a silently empty one.
        receivers: factory_params(&ret.program),
        locals: HashMap::new(),
        exports: HashMap::new(),
    };
    collector.visit_program(&ret.program);
    if let Some(Some(direct)) = collector.exports.get(export) {
        return match direct {
            Export::Inline(map) => Some(map.clone()),
            Export::Local(name) => collector.locals.get(name).cloned().flatten(),
        };
    }
    None
}

#[derive(PartialEq)]
enum Export {
    Inline(ConstMap),
    Local(String),
}

/// The parameter names of the `__d(name, deps, factory)` module factory — the only
/// identifiers a module can legitimately hang an export off.
fn factory_params(program: &oxc_ast::ast::Program) -> Vec<String> {
    fn params_of(e: &Expression) -> Option<Vec<String>> {
        let f = match e {
            Expression::ParenthesizedExpression(p) => return params_of(&p.expression),
            Expression::FunctionExpression(f) => f,
            _ => return None,
        };
        Some(
            f.params
                .items
                .iter()
                .filter_map(|p| p.pattern.get_identifier_name().map(|n| n.to_string()))
                .collect(),
        )
    }
    for stmt in &program.body {
        if let Statement::ExpressionStatement(es) = stmt
            && let Some(call) = as_call(&es.expression)
        {
            for arg in &call.arguments {
                if let Some(params) = arg_expr(arg).and_then(params_of) {
                    return params;
                }
            }
        }
    }
    Vec::new()
}

struct ConstCollector {
    /// See the note at the construction site.
    receivers: Vec<String>,
    /// Local name → its all-string object, or `None` when the same minified name is
    /// bound to **different** objects in the module. The minifier reuses short
    /// identifiers aggressively across nested scopes, so a module-wide "last one wins"
    /// map could resolve an export to an unrelated nested table and mint wrong wire tags
    /// or `actionType` values. Ambiguity therefore resolves to nothing, which shows up
    /// as a missing action rather than a silently wrong one.
    locals: HashMap<String, Option<ConstMap>>,
    /// `None` marks a property assigned differently through two factory parameters —
    /// unresolvable rather than guessed.
    exports: HashMap<String, Option<Export>>,
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
            && m.object().get_identifier_reference().is_some_and(|id| {
                self.receivers.is_empty() || self.receivers.iter().any(|r| r == id.name.as_str())
            })
        {
            // `factory_params` cannot tell the exports binding from the loader or the
            // dependency map — WA spells the factory `(t,n,r,o,a,i,l)` and uses `l` in
            // some modules and `i` in others. So rather than guess which parameter is
            // the real one, a property assigned DIFFERENTLY through two of them is
            // refused: the export resolves to nothing, and the failure is a missing
            // action rather than a wire tag read out of an unrelated table.
            let found = string_const_object(&a.right)
                .map(Export::Inline)
                .or_else(|| as_identifier(&a.right).map(|id| Export::Local(id.to_string())));
            if let Some(export) = found {
                match self.exports.entry(prop.to_string()) {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(Some(export));
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        if e.get().as_ref() != Some(&export) {
                            e.insert(None);
                        }
                    }
                }
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
        // A const-keyed switch whose arms only cause side effects is not a payload action
        // union — it is an ordinary child dispatch, already described by the
        // notification's `content` and sub-discriminants. `account_sync` has one, and
        // cataloguing it minted 11 phantom actions with no action type, field, constant
        // or child, inflating the count with entries a consumer can do nothing with. An
        // individual empty arm is still kept (knowing a tag is dispatched beats omitting
        // it); a switch where EVERY arm is empty is rejected whole.
        if actions.iter().any(is_meaningful)
            && actions.len() > self.best.as_ref().map_or(0, Vec::len)
        {
            self.best = Some(actions);
        }
        walk::walk_switch_statement(self, switch);
    }
}

/// Whether an arm says anything beyond "this tag is dispatched".
fn is_meaningful(a: &NotifActionDef) -> bool {
    a.action_type.is_some()
        || !a.fields.is_empty()
        || !a.constant_fields.is_empty()
        || !a.children.is_empty()
}

/// Read every arm of a const-keyed child-tag switch into [`NotifActionDef`]s.
fn extract_switch(switch: &SwitchStatement, ctx: &ArmCtx) -> Vec<NotifActionDef> {
    let mut out = Vec::new();
    for (i, case) in switch.cases.iter().enumerate() {
        let Some(wire_tag) = case.test.as_ref().and_then(|t| ctx.consts.resolve(t)) else {
            continue;
        };
        // `case TAG_A: case TAG_B: return {…}` — a fall-through label runs the next case
        // that actually produces something. Stopping at the first NON-EMPTY consequent is
        // not enough: a label may do setup or log first (`case TAG_A: log();`) and still
        // fall through, and treating that as its own arm loses the action type and every
        // field of a legally dispatched tag. Search forward for the first case that
        // yields a result shape instead.
        // …but the chain ENDS at a terminating statement. `case A: log(); break; case B:
        // return {…}` does not fall through, and scanning past the `break` would publish
        // B's action type and fields under A's wire tag — a shape that tag never produces.
        let run: Vec<&Statement> =
            fall_through_body(&switch.cases[i..]).unwrap_or_else(|| as_refs(&case.consequent));
        let shapes = arm_result_shapes_of(&run);
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
        let mut grouped: Vec<BranchFold> = Vec::new();
        for (shape, scope) in shapes {
            for action in expand_shape(&wire_tag, shape, &scope, ctx, 0) {
                match grouped
                    .iter_mut()
                    .find(|g| g.def.action_type == action.action_type)
                {
                    Some(fold) => fold.absorb(action),
                    None => grouped.push(BranchFold::new(action)),
                }
            }
        }
        out.extend(grouped.into_iter().map(BranchFold::finish));
    }
    out
}

/// The body a case actually runs, following the fall-through chain.
///
/// Starting at the case itself, walk forward until one yields a result shape — a label
/// may do setup or log before falling through, so "the first non-empty consequent" is not
/// the answer. The chain **ends** at a terminating statement: `case A: log(); break;` does
/// not fall through, and continuing past it would publish the next case's action under
/// A's wire tag, a shape that tag never produces.
fn fall_through_body<'b, 'a>(
    cases: &'b [oxc_ast::ast::SwitchCase<'a>],
) -> Option<Vec<&'b Statement<'a>>> {
    // Everything the chain executes, in order — not just the case that returns. A label
    // may bind before falling through (`case A: var id = child.attrString("id"); case B:
    // return {id}`), and handing back only B's body drops `id` from A's scope.
    let mut run: Vec<&Statement> = Vec::new();
    let mut produced = false;
    for case in cases {
        run.extend(case.consequent.iter());
        produced |= !arm_result_shapes(&case.consequent).is_empty();
        // Only a case that terminates on EVERY path stops the chain. A shape found here
        // is not enough: `case A: if (cond) return X; case B: return Y;` legally produces
        // either, and stopping at A published only X. Keep walking and let the collected
        // shapes accumulate — `collect_returns` reads them all out of `run`.
        if terminates(&case.consequent) {
            return produced.then_some(run);
        }
    }
    produced.then_some(run)
}

/// Whether a case body ends its own control flow on **every** path rather than falling
/// through.
///
/// "Every path" is what makes it safe for [`fall_through_body`] to stop here, and it is
/// load-bearing now that a collected shape no longer stops the walk: `if (cond) return X;`
/// leaves a path open and must fall through, while `switch (t) { case "a": return X;
/// default: return Y }` closes them all and must not.
fn terminates(stmts: &[Statement]) -> bool {
    stmts.iter().any(|s| stmt_exits(s, false))
}

/// Whether `s` exits the enclosing switch case on every path.
///
/// `nested` says whether a bare `break` would leave an inner breakable construct instead
/// of the case — inside a nested `switch`, `break` returns control to the case and is not
/// an exit at all.
fn stmt_exits(s: &Statement, nested: bool) -> bool {
    match s {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BreakStatement(_) | Statement::ContinueStatement(_) => !nested,
        Statement::BlockStatement(b) => b.body.iter().any(|s| stmt_exits(s, nested)),
        // Both arms, or the statement after the `if` still runs.
        Statement::IfStatement(i) => i
            .alternate
            .as_ref()
            .is_some_and(|alt| stmt_exits(&i.consequent, nested) && stmt_exits(alt, nested)),
        // Exhaustive only with a `default`; an empty case body falls into the next one,
        // so it does not have to exit on its own.
        Statement::SwitchStatement(sw) => {
            sw.cases.iter().any(|c| c.test.is_none())
                && sw.cases.iter().all(|c| {
                    c.consequent.is_empty() || c.consequent.iter().any(|s| stmt_exits(s, true))
                })
        }
        _ => false,
    }
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

/// The union of one wire tag's branches, accumulated.
///
/// **One** implementation of the alternative rule, because writing it per level is what
/// kept going wrong: the rule lived in three places (scalars, children, child fields) and
/// each review round fixed the copy that had been pointed at while the others stayed
/// stale. Every tombstone below lives for the whole fold rather than one call of it —
/// that was the other half of the same bug, since a conflict removed by branch B is
/// re-added by branch C if the state resets in between.
///
/// The rule itself: a field either branch reads is present; it is required only when
/// EVERY branch reads it unconditionally; and a key two branches bind to *different* wire
/// reads is refused, because reporting one of them describes the other branch's payload
/// wrongly. Distinct from composition *within* one shape (`babelHelpers.extends`, a
/// duplicate object key), where the last write simply wins — see [`merge_into`].
struct BranchFold {
    def: NotifActionDef,
    /// Scalar keys two branches disagreed on.
    dead: Conflicts,
    /// Child names bound to two different wire tags.
    dead_children: Conflicts,
    /// Per child name, the field keys its branches disagreed on.
    dead_child_fields: HashMap<String, Conflicts>,
}

impl BranchFold {
    fn new(def: NotifActionDef) -> Self {
        Self {
            def,
            dead: Conflicts::new(),
            dead_children: Conflicts::new(),
            dead_child_fields: HashMap::new(),
        }
    }

    /// Fold one more branch of the same action into the union.
    fn absorb(&mut self, from: NotifActionDef) {
        if self.def.action_type.is_none() {
            self.def.action_type = from.action_type;
        }
        merge_fields(&mut self.def.fields, from.fields, false, &mut self.dead);
        for c in from.children {
            match self.def.children.iter_mut().find(|x| x.name == c.name) {
                // Same output name and the same element: their field sets are
                // alternatives and merge under the rule above.
                Some(existing) if existing.wire_tag == c.wire_tag => {
                    let dead = self.dead_child_fields.entry(c.name.clone()).or_default();
                    merge_fields(&mut existing.fields, c.fields, false, dead);
                }
                // Same name, different element. Leaving the first would tell a consumer
                // every legal shape uses it.
                Some(existing) => {
                    self.dead_children.insert(existing.name.clone());
                }
                None => self.def.children.push(c),
            }
        }
        // A constant only some branches stamp is not a property of the action.
        self.def
            .constant_fields
            .retain(|c| from.constant_fields.contains(c));
    }

    /// Apply every tombstone. Run once, after the last branch.
    fn finish(mut self) -> NotifActionDef {
        apply_conflicts(&mut self.def.fields, &self.dead);
        self.def
            .children
            .retain(|c| !self.dead_children.contains(&c.name));
        for c in &mut self.def.children {
            if let Some(dead) = self.dead_child_fields.get(&c.name) {
                apply_conflicts(&mut c.fields, dead);
            }
        }
        self.def
    }
}

/// Every distinct result shape an arm can return: one per branch of a `cond ? A : B`
/// (nested ternaries included), each with its `babelHelpers.extends(…)` merged away.
fn arm_result_shapes<'b, 'a>(consequent: &'b [Statement<'a>]) -> Vec<Shape<'b, 'a>> {
    arm_result_shapes_of(&as_refs(consequent))
}

/// As [`arm_result_shapes`], over a statement list assembled from several sources — the
/// fall-through chain runs the statements of every case it passes through, not only the
/// one that returns.
fn arm_result_shapes_of<'b, 'a>(consequent: &[&'b Statement<'a>]) -> Vec<Shape<'b, 'a>> {
    arm_result_shapes_in(consequent, &Scope::new())
}

fn as_refs<'b, 'a>(stmts: &'b [Statement<'a>]) -> Vec<&'b Statement<'a>> {
    stmts.iter().collect()
}

/// As [`arm_result_shapes`], with an enclosing scope the branches layer over.
fn arm_result_shapes_in<'b, 'a>(
    consequent: &[&'b Statement<'a>],
    outer: &Scope<'b, 'a>,
) -> Vec<Shape<'b, 'a>> {
    let unwrapped;
    let stmts: &[&Statement] = match consequent {
        [Statement::BlockStatement(b)] => {
            unwrapped = as_refs(&b.body);
            &unwrapped
        }
        other => other,
    };
    let mut out = Vec::new();
    collect_returns(stmts, outer, &mut out);
    out
}

/// Every `return` reachable in `stmts`, descending through control flow (`if`/`else`,
/// blocks, `try`, a nested `switch`) but never into a nested function — an arm or helper that
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
        .map(|stmts| arm_result_shapes_in(&as_refs(stmts), base))
        .unwrap_or_default()
}

fn collect_returns<'b, 'a>(
    stmts: &[&'b Statement<'a>],
    outer: &Scope<'b, 'a>,
    out: &mut Vec<Shape<'b, 'a>>,
) {
    // Bindings accumulate in STATEMENT ORDER and each return snapshots what is in scope
    // where it sits. A pre-pass over the whole list would install a later initializer
    // before an earlier return: `var x = attr("a"); if (c) return {a:x}; var x =
    // attr("b")` would report the first branch as reading `b`, an assignment that has
    // not run. Hoisting moves the declaration, not the assignment.
    //
    // Scopes are also per branch, because mutually exclusive branches routinely rebind
    // the same minified name to different accessors, and one flattened scope would make
    // one branch's return read the other branch's attribute — a wrong `wireName` rather
    // than a missing field.
    let mut scope = outer.clone();
    for s in stmts.iter().copied() {
        match s {
            Statement::VariableDeclaration(decl) => {
                for d in &decl.declarations {
                    if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                    {
                        scope.insert(name.as_str(), init);
                    }
                }
            }
            // `x = child.attrString("lid")` — a reassignment, not a declaration. The
            // minifier hoists a `var` to the top and assigns later, so handling only
            // declarations left the *initializer* installed at every return below the
            // assignment: the runtime read `lid` while the IR published `jid`.
            //
            // An assignment whose right-hand side is not a wire read REMOVES the binding
            // rather than leaving the old one: the name no longer holds what it held, and
            // reporting a value that has been overwritten is worse than reporting none.
            Statement::ExpressionStatement(e) => {
                if let Expression::AssignmentExpression(a) = &e.expression
                    && let Some(name) = a.left.get_identifier_name()
                {
                    let reads_wire = find_accessor(strip_guard(&a.right), &scope).is_some();
                    if reads_wire {
                        scope.insert(name, &a.right);
                    } else {
                        scope.remove(name);
                    }
                }
            }
            Statement::ReturnStatement(r) => {
                if let Some(arg) = r.argument.as_ref() {
                    let mut branches = Vec::new();
                    collect_branches(arg, &mut branches);
                    out.extend(branches.into_iter().map(|e| (e, scope.clone())));
                }
            }
            Statement::BlockStatement(b) => collect_returns(&as_refs(&b.body), &scope, out),
            Statement::IfStatement(i) => {
                collect_returns(&[&i.consequent], &scope, out);
                if let Some(alt) = &i.alternate {
                    collect_returns(&[alt], &scope, out);
                }
            }
            Statement::TryStatement(t) => collect_returns(&as_refs(&t.block.body), &scope, out),
            // A nested `switch` inside an arm (or a helper body) is how THAT arm picks
            // its shape — `case LINK: switch (linkType) { case "parent": return {…};
            // default: return {…} }` describes two legal actions for `link`, and skipping
            // it left the arm empty. Nested *functions* are still not descended into,
            // which is what keeps the top-level child-tag dispatch out of a helper's
            // returns.
            Statement::SwitchStatement(sw) => {
                for c in &sw.cases {
                    collect_returns(&as_refs(&c.consequent), &scope, out);
                }
            }
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
        // `return sideEffect(…), value` — a comma expression's value is its LAST element.
        // The minifier uses it constantly to fold a call in before returning the object
        // (`return c || C(chat, u, tag), u`), so taking the whole sequence as the shape
        // finds no object at all.
        Expression::SequenceExpression(seq) => {
            if let Some(last) = seq.expressions.last() {
                collect_branches(last, out);
            }
        }
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
    let mut merged: Vec<BranchFold> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &Scope::new()) {
        for action in expand_shape(wire_tag, shape, &scope, ctx, depth) {
            match merged
                .iter_mut()
                .find(|g| g.def.action_type == action.action_type)
            {
                Some(fold) => fold.absorb(action),
                None => merged.push(BranchFold::new(action)),
            }
        }
    }
    merged.into_iter().map(BranchFold::finish).collect()
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
    let mut branches: Vec<BranchFold> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &Scope::new()) {
        let mut one = empty_action(String::new());
        fold_shape(shape, &scope, &mut one, ctx, depth + 1);
        match branches
            .iter_mut()
            .find(|b| b.def.action_type == one.action_type)
        {
            Some(fold) => fold.absorb(one),
            None => branches.push(BranchFold::new(one)),
        }
    }
    let branches: Vec<NotifActionDef> = branches.into_iter().map(BranchFold::finish).collect();
    // Distinct action types cannot arise here (a value-position helper contributes
    // fields, it does not pick the action), so folding the merged branches in is safe.
    for b in branches {
        merge_into(def, b);
    }
}

/// Fold a helper's contribution into the enclosing action, keeping what the enclosing
/// object already stated and weakening nothing it owns.
/// One key's value in an action shape, in whichever of the three forms it takes.
///
/// The three collections are three *representations* of one namespace — a shape's keys —
/// not three independent namespaces. Modelling them separately is what let a key exist
/// twice in different forms.
enum KeyValue {
    Field(NotifActionField),
    Child(NotifActionChild),
    Const(NotifConstValue),
}

/// Write `key` into `def`, last write wins across **all three** collections.
///
/// The eviction is the point. Each collection used to replace only within itself, so
/// `extends({id: child.attrString("jid")}, {id: 0})` — which yields just `id: 0` at
/// runtime — published a wire-read field *and* a constant both named `id`, and the
/// reverse order left the stale constant behind. A later write does not merely shadow an
/// earlier one; it replaces it, whatever form the earlier one took.
fn write_key(def: &mut NotifActionDef, key: &str, value: KeyValue) {
    def.fields.retain(|x| x.name != key);
    def.children.retain(|x| x.name != key);
    def.constant_fields.retain(|x| x.name != key);
    match value {
        KeyValue::Field(f) => def.fields.push(f),
        KeyValue::Child(c) => def.children.push(c),
        KeyValue::Const(v) => def.constant_fields.push(NotifActionConstant {
            name: key.to_string(),
            value: v,
        }),
    }
}

/// Fold a helper's result into `def` as an `babelHelpers.extends` operand.
///
/// A helper contributes at ITS position in the argument list, so everything it writes —
/// `actionType` included — overrides what an earlier operand wrote, the same last-write
/// rule an object literal follows. Keeping `actionType` on first-write meant
/// `extends({actionType: A}, helper())` where the helper returns `B` dispatched as `A`.
fn merge_into(def: &mut NotifActionDef, from: NotifActionDef) {
    if from.action_type.is_some() {
        def.action_type = from.action_type;
    }
    for f in from.fields {
        let key = f.name.clone();
        write_key(def, &key, KeyValue::Field(f));
    }
    for c in from.children {
        let key = c.name.clone();
        write_key(def, &key, KeyValue::Child(c));
    }
    for c in from.constant_fields {
        write_key(def, &c.name.clone(), KeyValue::Const(c.value));
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
        // Last write wins for EVERY key a shape writes, not just the scalar fields:
        // `extends({actionType: A}, {actionType: B})` and `{duration: 0, duration: 1}`
        // both yield the later value at runtime. Fixing this for one kind of key and
        // leaving `actionType` and the constants on first-write was the same rule
        // written in three places again.
        if key == "actionType" {
            def.action_type = ctx.consts.resolve(value);
            continue;
        }
        if let Some(c) = const_value(value) {
            write_key(def, key, KeyValue::Const(c));
            continue;
        }
        if let Some(child) = mapped_child(key, value, scope, ctx.consts) {
            write_key(def, key, KeyValue::Child(child));
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
                write_key(def, key, KeyValue::Child(c));
            }
            for f in nested.fields {
                let fkey = f.name.clone();
                write_key(def, &fkey, KeyValue::Field(f));
            }
            continue;
        }
        if let Some(field) = read_field(key, value, scope, ctx.consts) {
            // Last write wins WITHIN one shape: a duplicate key in an object literal, and
            // a later `babelHelpers.extends(…)` operand, both override at runtime —
            // `extends({id: attrString("jid")}, {id: attrString("lid")})` yields `lid`.
            // (Between mutually exclusive BRANCHES the rule is the opposite: they merge,
            // and a genuine disagreement is refused. See `merge_fields`.)
            write_key(def, key, KeyValue::Field(field));
        }
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
    // A ternary between two REAL values is not a presence guard, and treating every
    // conditional as one kept the consequent and threw the alternate away:
    // `{id: cond ? child.attrString("jid") : child.attrString("lid")}` published an
    // optional `jid` and lost `lid` entirely — or lost the field altogether when only
    // the alternate read the wire.
    if let Some(v) = value_selection(key, e, scope, consts) {
        return v;
    }
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

/// Resolve a `cond ? a : b` whose branches are two real values rather than a value and
/// an absence.
///
/// Returns `None` when this is not that shape (a plain guard, or not a ternary), so the
/// caller falls through to its normal handling. `Some(None)` means the key is **refused**.
///
/// The three outcomes follow the rule the branch fold already uses elsewhere:
/// * one side nullish → a presence guard, whichever side reads the wire, optional;
/// * both sides the same wire read → that read;
/// * two different wire reads → refused, because one output key cannot name two wire
///   attributes and picking the consequent is a coin flip the IR would state as fact.
fn value_selection<'b, 'a>(
    key: &str,
    e: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    consts: &ConstResolver,
) -> Option<Option<NotifActionField>> {
    let Expression::ConditionalExpression(c) = e else {
        return None;
    };
    // The null-coalesce idiom `(x = maybeAttrString("t")) != null ? x : void 0` hides the
    // read in the TEST; `strip_guard` already resolves it, and it is a guard, not a
    // selection. Leave it alone.
    if as_identifier(strip_guard(&c.consequent))
        .and_then(|n| assigned_in(&c.test, n))
        .is_some()
    {
        return None;
    }
    let (a, b) = (strip_guard(&c.consequent), strip_guard(&c.alternate));
    let (ra, rb) = (find_accessor(a, scope), find_accessor(b, scope));
    match (ra, rb) {
        // Only one side reads the wire: a presence guard in whichever direction it is
        // written. `cond ? null : child.attrString("x")` is as common as the other order
        // and used to lose the field completely.
        (Some(acc), None) if is_nullish(b) => Some(Some(guarded_field(key, acc, consts))),
        (None, Some(acc)) if is_nullish(a) => Some(Some(guarded_field(key, acc, consts))),
        (Some(x), Some(y)) => {
            if x.wire_name == y.wire_name && x.method == y.method && x.content == y.content {
                None // same read on both paths — the plain path handles it
            } else {
                Some(None) // two sources for one key: refuse
            }
        }
        _ => None,
    }
}

/// Whether the expression is a literal absence — the far side of a presence guard.
fn is_nullish(e: &Expression) -> bool {
    match e {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(i) => i.name == "undefined",
        // The minifier writes `undefined` as `void 0`.
        Expression::UnaryExpression(u) => u.operator == oxc_ast::ast::UnaryOperator::Void,
        _ => false,
    }
}

/// The field an accessor yields when it sits behind a presence guard: always optional,
/// because the guard exists precisely so the attribute may be absent.
fn guarded_field(key: &str, acc: Accessor, consts: &ConstResolver) -> NotifActionField {
    NotifActionField {
        name: key.to_string(),
        wire_name: acc.wire_name,
        field_type: wap::method_field_type(&acc.method),
        required: false,
        content: acc.content,
        enum_ref: acc.enum_arg.and_then(|a| consts.enum_ref(a)),
    }
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
            return Some(Accessor {
                method: method.to_string(),
                wire_name: name.to_string(),
                content: false,
                enum_arg: enum_table_arg(method, call, scope),
            });
        }
        // A content read — `X.contentString()`, `X.contentUint()`, … — takes no attribute
        // name, so the wire name is the tag of whatever `X` descends to, and `""` when it
        // reads the arm's own node. Asking `wap` rather than listing spellings here is
        // what keeps a newly classified accessor from being silently dropped.
        if wap::is_content_method(method) {
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
                // `node.contentEnum(TABLE)` validates against a table just as the
                // attribute path does; hardcoding `None` here typed the field as an enum
                // while denying a consumer its legal values.
                enum_arg: enum_table_arg(method, call, scope),
            });
        }
    }
    // A wrapper call (`userJidToUserWid(…)`, a local normaliser): look inside.
    call.arguments
        .iter()
        .filter_map(arg_expr)
        .find_map(|a| find_accessor_at(a, scope, depth + 1))
}

/// The enum table an enum-valued accessor validates against.
///
/// Gated on the shared classifier rather than a list of spellings, and applied to the
/// attribute and content paths alike — `maybeAttrEnum("type", o("Mod").TABLE)`,
/// `attrEnumOrNullIfUnknown("reason", v)` (hoisted into a local, so the candidate is
/// dereferenced first) and `contentEnum(TABLE)` are the same constraint written three
/// ways. `None` for a non-enum accessor.
fn enum_table_arg<'b, 'a>(
    method: &str,
    call: &'b oxc_ast::ast::CallExpression<'a>,
    scope: &Scope<'b, 'a>,
) -> Option<&'b Expression<'a>> {
    if wap::method_field_type(method) != wa_ir::ParsedFieldType::Enum {
        return None;
    }
    call.arguments
        .iter()
        .filter_map(arg_expr)
        .map(|a| deref_ident(a, scope))
        .find(|a| as_member(a).is_some())
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
    // Only function arguments hold the per-element shape; a bare expression contributes
    // nothing (the tag string, the bounds).
    if !matches!(
        e,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    ) {
        return;
    }
    // Per RETURN SHAPE, then merged — the same rule the action arms and the value-position
    // helpers use. A callback that returns different objects from an `if` or a ternary
    // describes alternative element shapes: flattening every property in the body into
    // one list would mark a field read in only one branch as required, and let two
    // branches reusing an output name silently keep whichever came first.
    let mut merged: Vec<NotifActionField> = Vec::new();
    let mut dead = Conflicts::new();
    let mut branches = 0usize;
    for (shape, inner) in fn_result_shapes(e, &scope) {
        branches += 1;
        let mut fields = Vec::new();
        collect_shape_fields(shape, &inner, consts, &mut fields);
        merge_fields(&mut merged, fields, branches == 1, &mut dead);
    }
    apply_conflicts(&mut merged, &dead);
    // A callback that returns a bare value rather than an object
    // (`p => userJidToUserWid(p.attrUserJid("jid"))`) has no property key to name the
    // field by, so the wire attribute names it — better than reporting no fields at all.
    // It goes through `merge_fields` too, one field set per return shape. Appending each
    // read directly bypassed the branch fold, so `p => cond ? p.attrString("jid") :
    // p.attrString("lid")` reported BOTH as required when each execution reads one.
    if merged.is_empty() {
        let mut bare = 0usize;
        for (shape, inner) in fn_result_shapes(e, &scope) {
            bare += 1;
            let fields = find_accessor(shape, &inner)
                .map(|acc| NotifActionField {
                    name: acc.wire_name.clone(),
                    wire_name: acc.wire_name,
                    field_type: wap::method_field_type(&acc.method),
                    required: !wap::is_optional_method(&acc.method),
                    content: acc.content,
                    enum_ref: acc.enum_arg.and_then(|a| consts.enum_ref(a)),
                })
                .into_iter()
                .collect();
            merge_fields(&mut merged, fields, bare == 1, &mut dead);
        }
        apply_conflicts(&mut merged, &dead);
    }
    for f in merged {
        if !out.iter().any(|x| x.name == f.name) {
            out.push(f);
        }
    }
}

/// Every `{ key: <wire read> }` property reachable in one result shape.
fn collect_shape_fields<'b, 'a>(
    shape: &'b Expression<'a>,
    scope: &Scope<'b, 'a>,
    consts: &ConstResolver,
    out: &mut Vec<NotifActionField>,
) {
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
    let mut w = Walker { scope, consts, out };
    // The minifier almost always builds the object into a local and returns the name
    // (`var u = {…}; return sideEffect(), u`), so the returned expression is an
    // identifier — walking it directly would find no properties at all.
    w.visit_expression(deref_ident(shape, scope));
}

/// Names whose wire read two branches disagreed on. A **tombstone**, kept for the whole
/// merge rather than one call of it: with three or more branches, `A(jid)` conflicting
/// with `B(lid)` would remove the key and then `C(jid)` — seeing nothing there — would
/// add it back, so the union would again advertise one source while another legal branch
/// reads a different attribute.
type Conflicts = std::collections::HashSet<String>;

/// Fold one branch's fields into the accumulated set: a field either branch reads is
/// present, and required only when EVERY branch reads it unconditionally.
///
/// When two branches bind the same output key to **different wire reads**, there is no
/// single answer — reporting the first branch's attribute would describe the other
/// branch's payload wrongly — so the key is tombstoned. Missing, not wrong, as everywhere
/// else in this module. Call [`apply_conflicts`] once the last branch is in.
fn merge_fields(
    into: &mut Vec<NotifActionField>,
    from: Vec<NotifActionField>,
    first: bool,
    dead: &mut Conflicts,
) {
    if !first {
        for existing in into.iter_mut() {
            if !from.iter().any(|f| f.name == existing.name) {
                existing.required = false;
            }
        }
    }
    for f in from {
        if dead.contains(&f.name) {
            continue;
        }
        match into.iter_mut().find(|x| x.name == f.name) {
            Some(existing) if same_wire_read(existing, &f) => existing.required &= f.required,
            Some(existing) => {
                dead.insert(existing.name.clone());
            }
            None => into.push(NotifActionField {
                required: f.required && first,
                ..f
            }),
        }
    }
}

/// Drop every tombstoned key. Run after the final branch, never between them.
fn apply_conflicts(fields: &mut Vec<NotifActionField>, dead: &Conflicts) {
    fields.retain(|f| !dead.contains(&f.name));
}

/// Whether two bindings of the same output key describe the same wire read.
fn same_wire_read(a: &NotifActionField, b: &NotifActionField) -> bool {
    a.wire_name == b.wire_name
        && a.field_type == b.field_type
        && a.content == b.content
        && a.enum_ref == b.enum_ref
}
