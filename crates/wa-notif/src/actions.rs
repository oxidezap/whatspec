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
//!
//! # What this models, and what it does not
//!
//! Reading those arms means interpreting minified JavaScript, and this file has grown a
//! small scope-and-control-flow analysis to do it. It is not a general one, and the
//! boundary is worth stating rather than rediscovering: a construct outside it does not
//! produce a *wrong* action so much as a thin one, and knowing which is which is the
//! difference between trusting the output and auditing it.
//!
//! **Modelled.** Bindings in statement order (`var`, plain and comma-sequence
//! assignment, `let`/`const` confined to their block); branch scopes that clone and
//! rejoin, with a name any branch rewrote tombstoned rather than guessed; `if`/`else`,
//! bare blocks, `switch` with fall-through suffixes, `try`/`catch`/`finally` (the
//! finalizer's writes are definite, the body's are not), every loop form (`do…while`
//! runs once, so its writes are definite unless a path breaks out), and reachability —
//! nothing after a statement that exits on every path is collected. Module-local
//! helpers are inlined, bounded, including one applied to a wire read passed by value or
//! through an alias. Ambiguity is refused: two branches binding one output key to
//! different wire reads drop the key, and a table or object that cannot be read whole
//! (a spread, a computed member) is refused entirely rather than half-reported.
//!
//! **Not modelled.** Values that flow through anything other than a local binding or a
//! helper parameter — a property of an object, an array element, a closure over an outer
//! function's variable. Loop iteration: a body is analysed once, so a field whose source
//! depends on which pass wrote it is not resolved. Any arithmetic or string building on
//! a wire value. `label:`/`continue label`. Nested functions other than the helpers
//! reached explicitly, which is deliberate — descending into them is what would drag the
//! top-level child-tag dispatch into an arm's returns.
//!
//! When a construct falls outside, the arm loses the field rather than inventing one,
//! and `dropsByReason` counts what was seen and not recovered. That is the invariant to
//! preserve if this grows: a reader that guesses is worse than one that reports a gap.

use std::collections::{HashMap, HashSet};

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
    /// Enum-valued action fields whose allowed-value table could not be named, keyed
    /// `wireName@table` so two fields losing the same constraint count twice and one
    /// field seen twice counts once.
    ///
    /// The action path has no linker to drain a pending marker, so it reports here. The
    /// `w:gp2` `create.reason` field shipped as `"type": "enum"` with no values and no
    /// signal anywhere — the exact "lost or absent?" ambiguity the rest of the change
    /// exists to remove.
    enum_drops: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl<'a> ConstResolver<'a> {
    pub(crate) fn new(slices: &'a HashMap<&'a str, &'a str>) -> Self {
        Self {
            slices,
            cache: std::cell::RefCell::new(HashMap::new()),
            enums: std::cell::RefCell::new(HashMap::new()),
            enum_drops: Default::default(),
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

    /// The enum an action field validates against, reporting the loss when there is a
    /// table but it is not a nameable `o("Mod").ENUM` reference (a module-local object,
    /// a computed set). `wire_name` identifies the occurrence in the report.
    fn action_enum_ref(
        &self,
        method: &str,
        arg: Option<&Expression>,
        wire_name: &str,
    ) -> Option<wa_ir::AttrEnumRef> {
        if wap::method_field_type(method) != wa_ir::ParsedFieldType::Enum {
            return None;
        }
        let resolved = arg.and_then(|a| self.enum_ref(a));
        if resolved.is_none() {
            // Keyed by the table argument's SOURCE SPAN when there is one. `wireName@method`
            // was resolver-wide, so two actions each losing `reason` counted once. A span is
            // a stronger identity than the action name in both directions: two arms with two
            // `attrEnumOrNullIfUnknown("reason", …)` calls are two losses, and two arms
            // sharing one helper's call are one constraint referenced twice.
            let key = arg.map_or_else(
                || format!("{wire_name}@{method}"),
                |a| {
                    let sp = oxc_span::GetSpan::span(a);
                    format!("{}..{}@{method}", sp.start, sp.end)
                },
            );
            self.enum_drops.borrow_mut().insert(key);
        }
        resolved
    }

    /// The allowed-value tables seen on action fields and not recoverable, for
    /// `diagnostics.notif.dropsByReason`.
    pub(crate) fn take_enum_drops(&self) -> usize {
        self.enum_drops.borrow().len()
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
    // A spread, a method or a computed key is SKIPPED by `obj_props`, so accepting the
    // survivors publishes a partial map: `{ADD: "old", ...base}` resolves `ADD` to `old`
    // when the runtime switch uses the spread's value, and a spread-only member vanishes.
    // Either way the arm gets a `wireTag`/`actionType` the handler never produces —
    // invented, not merely lost. Same rule as the response-side enum tables.
    if obj.properties.len() != wa_oxc::obj_props(obj).count() {
        return None;
    }
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
    let locals: HashMap<String, String> = by_name
        .into_iter()
        .filter_map(|(n, src)| src.map(|s| (n, s)))
        .collect();
    let no_formals = HashSet::new();
    let ctx = ArmCtx {
        consts,
        source: handler_slice,
        locals: &locals,
        formals: &no_formals,
    };
    let mut finder = SwitchFinder {
        ctx: &ctx,
        best: None,
        tag_locals: Default::default(),
    };
    finder.visit_program(&ret.program);
    finder.best.filter(|v| !v.is_empty())
}

/// What an arm reader needs: the constant tables its labels resolve through, and the
/// module's local helper functions, as re-parsable source (keyed by name).
struct ArmCtx<'c, 'a> {
    consts: &'c ConstResolver<'a>,
    locals: &'c HashMap<String, String>,
    /// The source THIS context's spans index into, so an inlined helper can be given the
    /// TEXT of the arguments it was called with. The helper is re-parsed in its own
    /// allocator, so a call-site AST reference cannot cross into it — its source can.
    ///
    /// Borrowed rather than fixed to the module, because nested inlining re-parses a
    /// SYNTHETIC buffer: the spans of nodes in it are offsets into that buffer, and
    /// slicing the module with them lands on unrelated text — in range, so the bounds
    /// check never fires, just wrong. `inline_local` rebinds this to the buffer it parsed.
    source: &'c str,
    /// Formal parameter names of the helper currently being inlined.
    ///
    /// They SHADOW module helpers of the same name for the whole body, but they are not
    /// in `Scope`: `apply_args` deliberately declines to substitute unless an argument
    /// carries a wire read (doing it unconditionally cost 62 shape elements), so the
    /// binding that would have recorded them never happens. Carried separately so the
    /// shadowing survives even when the substitution is skipped.
    formals: &'c HashSet<String>,
}

impl<'c, 'a> ArmCtx<'c, 'a> {
    /// The same context reading a different source buffer, for the helper's formals.
    fn nested(&self, source: &'c str, formals: &'c HashSet<String>) -> ArmCtx<'c, 'a> {
        ArmCtx {
            consts: self.consts,
            locals: self.locals,
            source,
            formals,
        }
    }
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
    /// Locals bound to a child's TAG in the function currently being walked
    /// (`var a = t.tag()`), so a switch can be identified by what it dispatches ON
    /// rather than by how many arms it happens to have.
    tag_locals: std::collections::HashSet<String>,
}

/// Whether `e` reads a node's tag — `t.tag()` or `t.tag`.
fn is_tag_read(e: &Expression) -> bool {
    if let Some(call) = as_call(e) {
        return callee_method(call) == Some("tag") && call.arguments.is_empty();
    }
    as_member(e).is_some_and(|(_, name)| name == "tag")
}

impl<'a> Visit<'a> for SwitchFinder<'_, 'a> {
    /// Record this function's `var x = child.tag()` bindings before walking its body,
    /// so a switch inside it can be checked against them.
    fn visit_function_body(&mut self, body: &oxc_ast::ast::FunctionBody<'a>) {
        let outer = std::mem::take(&mut self.tag_locals);
        for st in &body.statements {
            if let Statement::VariableDeclaration(d) = st {
                for decl in &d.declarations {
                    if let (Some(n), Some(init)) =
                        (decl.id.get_identifier_name(), decl.init.as_ref())
                        && is_tag_read(init)
                    {
                        self.tag_locals.insert(n.as_str().to_string());
                    }
                }
            }
        }
        walk::walk_function_body(self, body);
        self.tag_locals = outer;
    }

    fn visit_switch_statement(&mut self, switch: &SwitchStatement<'a>) {
        // Identified by what it dispatches ON, not by size. The payload union switches on
        // a mapped child's TAG (`var a = t.tag(); switch (a)`); an unrelated const-keyed
        // switch in the same module — with more returning arms — would otherwise win the
        // "most arms" tie-break and publish non-wire constants as `wireTag`s.
        let on_tag = is_tag_read(&switch.discriminant)
            || as_identifier(&switch.discriminant).is_some_and(|n| self.tag_locals.contains(n));
        if !on_tag {
            walk::walk_switch_statement(self, switch);
            return;
        }
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
    list_exits(stmts, false)
}

/// Whether the list leaves the enclosing case on every path.
///
/// Order matters, and `any` got it wrong: in `case X: if (cond) break; return A;` inside a
/// nested switch, the `break` leaves only the INNER switch and control resumes in the
/// outer case, yet the later `return` made the whole list look terminating. A statement
/// that can escape upward poisons the conclusion before any later statement is consulted.
fn list_exits(stmts: &[Statement], nested: bool) -> bool {
    list_exits_refs(&stmts.iter().collect::<Vec<_>>(), nested)
}

/// [`list_exits`] over borrowed statements, so a fall-through suffix can be assembled
/// across cases without cloning the AST.
fn list_exits_refs(stmts: &[&Statement], nested: bool) -> bool {
    for s in stmts.iter().copied() {
        if can_escape(s, nested) {
            return false;
        }
        if stmt_exits(s, nested) {
            return true;
        }
    }
    false
}

/// Whether some path through `s` reaches a `break` that leaves the construct we are
/// analysing rather than ending the case. Only meaningful inside a nested breakable
/// construct — at case level a `break` *is* the exit.
fn can_escape(s: &Statement, nested: bool) -> bool {
    if !nested {
        return false;
    }
    match s {
        Statement::BreakStatement(_) => true,
        Statement::BlockStatement(b) => b.body.iter().any(|s| can_escape(s, nested)),
        Statement::IfStatement(i) => {
            can_escape(&i.consequent, nested)
                || i.alternate.as_ref().is_some_and(|a| can_escape(a, nested))
        }
        // A deeper switch or loop consumes the `break` itself, so it cannot reach us.
        _ => false,
    }
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
        Statement::BlockStatement(b) => list_exits(&b.body, nested),
        // Both arms, or the statement after the `if` still runs.
        Statement::IfStatement(i) => i
            .alternate
            .as_ref()
            .is_some_and(|alt| stmt_exits(&i.consequent, nested) && stmt_exits(alt, nested)),
        // Exhaustive only with a `default`, and only if every case leaves the switch —
        // which each case may do through its own fall-through suffix, not just its own
        // body. `case X: setup(); default: return A` exits on both paths: `X` runs
        // `setup()` and falls into the default's `return`. Requiring the body alone to
        // exit (accepting only an EMPTY fall-through label) called that switch
        // non-terminating, and the enclosing case then borrowed the next outer case's
        // action for a wire tag that never produces it.
        // A `finally` that exits settles it on its own; otherwise the `try` body must
        // exit and, if there is a handler, so must it. `try { return X } finally
        // { return Y }` always returns, and treating it as fall-through let the arm
        // borrow the next case's action.
        Statement::TryStatement(t) => {
            let finalizer_exits = t
                .finalizer
                .as_ref()
                .is_some_and(|f| list_exits(&f.body, nested));
            finalizer_exits
                || (list_exits(&t.block.body, nested)
                    && t.handler
                        .as_ref()
                        .is_none_or(|h| list_exits(&h.body.body, nested)))
        }
        // A `do…while` body runs at least once, so if it exits on every path the loop
        // does. `do { return A } while (c); return B` was collecting A and then walking
        // on to publish the unreachable B.
        // The body's own `break`/`continue` are consumed by THIS loop, so they cannot
        // prove it exits its caller: `do { break; } while (c); return B` reaches B.
        Statement::DoWhileStatement(d) => !can_escape(&d.body, true) && stmt_exits(&d.body, nested),
        Statement::SwitchStatement(sw) => {
            sw.cases.iter().any(|c| c.test.is_none())
                && (0..sw.cases.len()).all(|i| {
                    let suffix: Vec<&Statement> = sw.cases[i..]
                        .iter()
                        .flat_map(|c| c.consequent.iter())
                        .collect();
                    list_exits_refs(&suffix, true)
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
        // A collection this branch does NOT carry cannot be claimed as always present —
        // the same all-branches accounting `merge_fields` does for scalars.
        for existing in self.def.children.iter_mut() {
            if !from.children.iter().any(|c| c.name == existing.name) {
                existing.required = false;
            }
        }
        for c in from.children {
            match self.def.children.iter_mut().find(|x| x.name == c.name) {
                // Same output name and the same element: their field sets are
                // alternatives and merge under the rule above.
                Some(existing) if existing.wire_tag == c.wire_tag => {
                    // `from` may itself be a FOLD of several branches, and already know
                    // the child is absent from one of them. Merging only the fields kept
                    // `existing.required` true and re-asserted a presence the incoming
                    // side had already disproved.
                    existing.required &= c.required;
                    let dead = self.dead_child_fields.entry(c.name.clone()).or_default();
                    merge_fields(&mut existing.fields, c.fields, false, dead);
                }
                // Same name, different element. Leaving the first would tell a consumer
                // every legal shape uses it.
                Some(existing) => {
                    self.dead_children.insert(existing.name.clone());
                }
                // First seen in a LATER branch, so an earlier one lacked it.
                None => self.def.children.push(NotifActionChild {
                    required: false,
                    ..c
                }),
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
    collect_returns_into(stmts, &mut scope, out);
}

/// [`collect_returns`] over a scope the caller owns, so a construct that always runs —
/// a bare block — can hand its writes back instead of having them discarded with a clone.
fn collect_returns_into<'b, 'a>(
    stmts: &[&'b Statement<'a>],
    scope: &mut Scope<'b, 'a>,
    out: &mut Vec<Shape<'b, 'a>>,
) {
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
            // The minifier also writes runs of assignments as one comma sequence
            // (`a = t.attrString("jid"), b = t.attrInt("n")`), which arrives as a
            // `SequenceExpression`; matching only a bare assignment skipped those
            // entirely and left the stale initializer installed.
            Statement::ExpressionStatement(e) => {
                // A write buried in a short-circuit or ternary runs on SOME paths only:
                // `cond && (x = attrString("lid"))` leaves `x` holding either value, so
                // the name no longer has one known source and is tombstoned. Ignoring it
                // left the pre-expression binding installed and published it as fact.
                for name in conditional_writes(&e.expression) {
                    scope.remove(name);
                }
                let mut ops = Vec::new();
                flatten_sequence(&e.expression, &mut ops);
                for a in ops {
                    if let Some(name) = a.left.get_identifier_name() {
                        // The binding now holds the new right-hand side, whatever it is.
                        // Requiring it to resolve to a wire accessor dropped the minifier's
                        // `var x; x = {actionType: A, id: attr("jid")}; return x` — a fully
                        // static shape — and published an empty action. Pointing the name at
                        // what it now holds satisfies the "never report an overwritten
                        // value" rule better than forgetting it: if the new value is not
                        // interpretable, the field simply does not resolve.
                        scope.insert(name, &a.right);
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
            // A bare block ALWAYS runs and `var` is function-scoped, so its writes
            // survive it: `{ x = child.attrString("lid"); } return {id: x}` reads `lid`.
            // Analyzing it against a clone discarded that and published the pre-block
            // source. (A branch's block is different — it reaches here through the `if`
            // arm below, which clones deliberately.)
            Statement::BlockStatement(b) => {
                // `var` writes escape a bare block (function scope); `let`/`const` do not.
                // Propagating everything let an inner `let x` shadow the outer `x` for the
                // rest of the function — the runtime reads the OUTER value after the block.
                let shadowed: Vec<(&str, Option<&'b Expression<'a>>)> = block_scoped_names(&b.body)
                    .into_iter()
                    .map(|n| (n, scope.get(n).copied()))
                    .collect();
                collect_returns_into(&as_refs(&b.body), scope, out);
                for (name, prior) in shadowed {
                    match prior {
                        Some(e) => scope.insert(name, e),
                        None => scope.remove(name),
                    };
                }
            }
            Statement::IfStatement(i) => {
                collect_returns(&[&i.consequent], scope, out);
                if let Some(alt) = &i.alternate {
                    collect_returns(&[alt], scope, out);
                }
                // Where the branches rejoin, a name either branch reassigned no longer has
                // one known value: `var x = attrString("jid"); if (c) x = attrString("lid");
                // return {id: x}` reads `lid` on one legal path, and keeping the pre-branch
                // binding published `jid` as if it were certain. Tombstoned rather than
                // guessed, the same way a key bound to two different reads is refused.
                tombstone_branch_writes(s, scope);
            }
            Statement::TryStatement(t) => {
                // The `try` body and its `catch` are alternative paths — WA wraps a
                // parse in `try { … } catch (e) { … }` and the handler's return is as
                // legal as the body's — and both see the pre-`try` scope, since nothing
                // the body wrote is guaranteed to have run when the handler is entered.
                let mut paths = Vec::new();
                collect_returns(&as_refs(&t.block.body), scope, &mut paths);
                if let Some(h) = &t.handler {
                    // The catch PARAMETER is the caught exception, not whatever the outer
                    // scope bound to that name. `var e = attrString("jid"); try {…}
                    // catch (e) { return {id: e} }` published `id` as a read of `jid`;
                    // masking it makes the handler's `e` resolve to nothing, which is the
                    // truth.
                    let mut catch_scope = scope.clone();
                    if let Some(param) = h.param.as_ref()
                        && let Some(name) = param.pattern.get_identifier_name()
                    {
                        catch_scope.remove(name.as_str());
                    }
                    collect_returns(&as_refs(&h.body.body), &catch_scope, &mut paths);
                }
                // What the finalizer does to the earlier shapes is a control-flow
                // question, not a "did it yield anything" one. Emptiness gets both ends
                // wrong: `finally { if (c) return B }` keeps A legal when `c` is false,
                // and `finally { throw e }` yields nothing at all yet leaves the vector
                // empty. Only a finalizer that leaves on EVERY path replaces them.
                let mut finalizer = Vec::new();
                if let Some(f) = &t.finalizer {
                    // The finalizer runs AFTER the try body, so the entry scope is wrong:
                    // `var x = a("jid"); try { x = a("lid") } finally { return {id: x} }`
                    // returns `lid`. The body may also have thrown part-way, so neither
                    // binding is certain — every name the try or catch writes is
                    // tombstoned for the finalizer, the same conservative merge used
                    // where branches rejoin.
                    let mut fin_scope = scope.clone();
                    tombstone_branch_writes(s, &mut fin_scope);
                    collect_returns(&as_refs(&f.body), &fin_scope, &mut finalizer);
                }
                let finalizer_settles = t
                    .finalizer
                    .as_ref()
                    .is_some_and(|f| list_exits(&f.body, false));
                if !finalizer_settles {
                    out.extend(paths);
                }
                out.extend(finalizer);
                // A `try` body may have run in part; nothing IT wrote is certain after it.
                // The FINALIZER is different: it runs on every path, so its writes are
                // definite and tombstoning them lost fields the return always reads.
                // Uncertain try/catch writes are dropped first, then the finalizer's are
                // replayed over the result.
                tombstone_branch_writes(s, scope);
                if let Some(f) = &t.finalizer {
                    replay_writes(&f.body, scope);
                }
            }
            // A nested `switch` inside an arm (or a helper body) is how THAT arm picks
            // its shape — `case LINK: switch (linkType) { case "parent": return {…};
            // default: return {…} }` describes two legal actions for `link`, and skipping
            // it left the arm empty. Nested *functions* are still not descended into,
            // which is what keeps the top-level child-tag dispatch out of a helper's
            // returns.
            Statement::SwitchStatement(sw) => {
                // Each case is analyzed with its own FALL-THROUGH SUFFIX, the same rule
                // the outer action switch follows: `case "a": x = attrString("jid");
                // case "b": return {id: x}` runs the assignment on the `a` path, and
                // analyzing the consequents independently lost `id` there.
                for i in 0..sw.cases.len() {
                    let mut run: Vec<&Statement> = Vec::new();
                    for c in &sw.cases[i..] {
                        run.extend(c.consequent.iter());
                        if list_exits(&c.consequent, true) {
                            break;
                        }
                    }
                    collect_returns(&run, scope, out);
                }
                tombstone_branch_writes(s, scope);
            }
            // A loop body is a conditional path like any other: `while (c) { return A }
            // return B` legally produces both, and falling into the catch-all collected
            // only B. Its writes are tombstoned on exit for the same reason a branch's
            // are — the body may have run any number of times, including zero.
            // A `do…while` body runs AT LEAST once, so its writes are definite — the
            // ordinary loop merge tombstoned them and lost every field they bound.
            Statement::DoWhileStatement(d) => {
                // The body runs at least once, so its writes are definite — UNLESS a path
                // leaves it early: `do { if (c) break; x = a("lid"); } while (…)` reaches
                // the return without assigning `x`, and propagating unconditionally
                // recorded `lid` as its one certain source.
                if can_escape(&d.body, true) {
                    collect_returns(&[&d.body], scope, out);
                    tombstone_branch_writes(s, scope);
                } else {
                    collect_returns_into(&[&d.body], scope, out);
                }
            }
            Statement::ForStatement(_)
            | Statement::ForInStatement(_)
            | Statement::ForOfStatement(_)
            | Statement::WhileStatement(_) => {
                // A `for` INITIALIZER runs before every path that enters the body, so it
                // is a definite write for the body's scope — `for (x = a("lid"); …;)
                // return {id: x}` always reads `lid`, and analyzing the body against the
                // pre-loop scope published the stale source.
                let mut entry = scope.clone();
                if let Statement::ForStatement(f) = s {
                    match &f.init {
                        Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(d)) => {
                            for decl in &d.declarations {
                                if let (Some(n), Some(init)) =
                                    (decl.id.get_identifier_name(), decl.init.as_ref())
                                {
                                    entry.insert(n.as_str(), init);
                                }
                            }
                        }
                        Some(init) => {
                            if let Some(e) = init.as_expression() {
                                let mut ops = Vec::new();
                                flatten_sequence(e, &mut ops);
                                for a in ops {
                                    if let Some(n) = a.left.get_identifier_name() {
                                        entry.insert(n, &a.right);
                                    }
                                }
                            }
                        }
                        None => {}
                    }
                }
                if let Some(body) = loop_body(s) {
                    collect_returns(&[body], &entry, out);
                }
                tombstone_branch_writes(s, scope);
            }
            _ => {}
        }
        // Nothing after a statement that leaves on every path runs. This covers the bare
        // `return` and, equally, `if (c) return A; else return B;` — whose trailing
        // `return C` is unreachable yet was emitted as a third legal action.
        if stmt_exits(s, false) {
            return;
        }
    }
}

/// The names a statement list declares with `let`/`const` — bindings that die with their
/// block, unlike `var`.
fn block_scoped_names<'b, 'a>(stmts: &'b [Statement<'a>]) -> Vec<&'b str> {
    use oxc_ast::ast::VariableDeclarationKind as K;
    let mut out = Vec::new();
    for s in stmts {
        if let Statement::VariableDeclaration(d) = s
            && matches!(d.kind, K::Let | K::Const)
        {
            out.extend(
                d.declarations
                    .iter()
                    .filter_map(|x| x.id.get_identifier_name())
                    .map(|n| n.as_str()),
            );
        }
    }
    out
}

/// The body statement of any loop form, so one arm can handle them all.
fn loop_body<'b, 'a>(s: &'b Statement<'a>) -> Option<&'b Statement<'a>> {
    match s {
        Statement::ForStatement(f) => Some(&f.body),
        Statement::ForInStatement(f) => Some(&f.body),
        Statement::ForOfStatement(f) => Some(&f.body),
        Statement::WhileStatement(w) => Some(&w.body),
        Statement::DoWhileStatement(d) => Some(&d.body),
        _ => None,
    }
}

/// The assignment operands of an expression, flattening the minifier's comma sequences.
fn flatten_sequence<'b, 'a>(
    e: &'b Expression<'a>,
    out: &mut Vec<&'b oxc_ast::ast::AssignmentExpression<'a>>,
) {
    match e {
        Expression::AssignmentExpression(a) => out.push(a),
        Expression::SequenceExpression(seq) => {
            for sub in &seq.expressions {
                flatten_sequence(sub, out);
            }
        }
        Expression::ParenthesizedExpression(p) => flatten_sequence(&p.expression, out),
        _ => {}
    }
}

/// Names assigned inside a CONDITIONAL part of an expression — an operand of `&&`/`||`
/// or either arm of a ternary. Definite top-level writes are excluded; [`flatten_sequence`]
/// handles those.
fn conditional_writes<'b>(e: &'b Expression) -> Vec<&'b str> {
    fn walk<'b>(e: &'b Expression, guarded: bool, out: &mut Vec<&'b str>) {
        match e {
            Expression::AssignmentExpression(a) => {
                if guarded && let Some(n) = a.left.get_identifier_name() {
                    out.push(n);
                }
                walk(&a.right, guarded, out);
            }
            Expression::LogicalExpression(l) => {
                walk(&l.left, guarded, out);
                walk(&l.right, true, out);
            }
            Expression::ConditionalExpression(c) => {
                walk(&c.test, guarded, out);
                walk(&c.consequent, true, out);
                walk(&c.alternate, true, out);
            }
            Expression::SequenceExpression(seq) => {
                for sub in &seq.expressions {
                    walk(sub, guarded, out);
                }
            }
            Expression::ParenthesizedExpression(p) => walk(&p.expression, guarded, out),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(e, false, &mut out);
    out
}

/// Re-apply the writes a statement list performs, for a construct that runs on EVERY
/// path (a `finally`). Only top-level declarations and assignments; anything conditional
/// inside stays out, which is what keeps this from re-asserting an uncertain value.
fn replay_writes<'b, 'a>(stmts: &'b [Statement<'a>], scope: &mut Scope<'b, 'a>) {
    for st in stmts {
        match st {
            Statement::VariableDeclaration(d) => {
                for decl in &d.declarations {
                    if let (Some(n), Some(init)) =
                        (decl.id.get_identifier_name(), decl.init.as_ref())
                    {
                        scope.insert(n.as_str(), init);
                    }
                }
            }
            Statement::ExpressionStatement(e) => {
                let mut ops = Vec::new();
                flatten_sequence(&e.expression, &mut ops);
                for a in ops {
                    if let Some(n) = a.left.get_identifier_name() {
                        scope.insert(n, &a.right);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Drop every binding a conditional construct may have reassigned, so statements after
/// the rejoin do not read a value that only one path wrote.
fn tombstone_branch_writes(s: &Statement, scope: &mut Scope) {
    let mut names = Vec::new();
    assigned_names(s, &mut names);
    for n in names {
        scope.remove(n);
    }
}

/// Every identifier assigned anywhere inside `s`, not descending into nested functions
/// (whose assignments belong to their own scope, not this one).
fn assigned_names<'a>(s: &'a Statement, out: &mut Vec<&'a str>) {
    fn expr<'a>(e: &'a Expression, out: &mut Vec<&'a str>) {
        match e {
            Expression::AssignmentExpression(a) => {
                if let Some(n) = a.left.get_identifier_name() {
                    out.push(n);
                }
                expr(&a.right, out);
            }
            Expression::SequenceExpression(seq) => {
                seq.expressions.iter().for_each(|e| expr(e, out))
            }
            Expression::ParenthesizedExpression(p) => expr(&p.expression, out),
            Expression::ConditionalExpression(c) => {
                expr(&c.test, out);
                expr(&c.consequent, out);
                expr(&c.alternate, out);
            }
            Expression::LogicalExpression(l) => {
                expr(&l.left, out);
                expr(&l.right, out);
            }
            _ => {}
        }
    }
    match s {
        Statement::ExpressionStatement(e) => expr(&e.expression, out),
        Statement::VariableDeclaration(d) => {
            for decl in &d.declarations {
                if let (Some(n), Some(_)) = (decl.id.get_identifier_name(), decl.init.as_ref()) {
                    out.push(n.as_str());
                }
            }
        }
        Statement::BlockStatement(b) => b.body.iter().for_each(|s| assigned_names(s, out)),
        Statement::IfStatement(i) => {
            expr(&i.test, out);
            assigned_names(&i.consequent, out);
            if let Some(a) = &i.alternate {
                assigned_names(a, out);
            }
        }
        s if loop_body(s).is_some() => {
            if let Some(b) = loop_body(s) {
                assigned_names(b, out);
            }
        }
        Statement::TryStatement(t) => {
            t.block.body.iter().for_each(|s| assigned_names(s, out));
            if let Some(h) = &t.handler {
                h.body.body.iter().for_each(|s| assigned_names(s, out));
            }
            if let Some(f) = &t.finalizer {
                f.body.iter().for_each(|s| assigned_names(s, out));
            }
        }
        Statement::SwitchStatement(sw) => sw
            .cases
            .iter()
            .for_each(|c| c.consequent.iter().for_each(|s| assigned_names(s, out))),
        Statement::ReturnStatement(r) => {
            if let Some(a) = r.argument.as_ref() {
                expr(a, out);
            }
        }
        _ => {}
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
        && let Some(src) = local_call_source(deref_ident(result, scope), ctx, scope)
    {
        let expanded = expand_helper(wire_tag, &src.0, &src.1, ctx, depth + 1);
        if !expanded.is_empty() {
            return expanded;
        }
    }
    vec![read_action(wire_tag.to_string(), result, scope, ctx, depth)]
}

/// The helper source, immediately applied to its call-site arguments when one of them is
/// itself a wire read.
///
/// Applied ONLY in that case. A helper handed the NODE (`y(chat, child, tag)` — the
/// overwhelmingly common form) already works: its body reads off its own parameter and
/// `find_accessor` finds that structurally. Binding those formals to call-site
/// identifiers that do not exist in this parse resolves them to nothing, and doing it
/// unconditionally cost 62 shape elements. The value-passing form is the one that needs
/// the binding.
fn apply_args(fn_src: &str, arg_srcs: &[String]) -> String {
    let passes_a_read = arg_srcs
        .iter()
        .any(|a| a.contains(".attr") || a.contains(".maybeAttr") || a.contains(".content"));
    if passes_a_read {
        format!("(({fn_src})({}))", arg_srcs.join(", "))
    } else {
        format!("({fn_src})")
    }
}

/// The parameter names a helper declares, whether or not the call was substituted.
fn helper_formals(e: &Expression) -> HashSet<String> {
    let params = match e {
        Expression::FunctionExpression(f) => &f.params,
        Expression::ArrowFunctionExpression(f) => &f.params,
        _ => return HashSet::new(),
    };
    let mut out = HashSet::new();
    let mut add = |p: &oxc_ast::ast::BindingPattern| {
        for id in p.get_binding_identifiers() {
            out.insert(id.name.to_string());
        }
    };
    for p in &params.items {
        add(&p.pattern);
    }
    if let Some(rest) = &params.rest {
        add(&rest.rest.argument);
    }
    out
}

/// Split a parsed `((fn)(a, b))` into the function and a scope binding its formals to
/// the call-site argument expressions.
///
/// Both live in the SAME allocator (the arguments were re-parsed from their source text
/// alongside the helper), which is what makes the binding expressible at all — a
/// call-site AST node from the enclosing parse could not cross into here.
fn applied_helper<'b, 'a>(e: &'b Expression<'a>) -> (&'b Expression<'a>, Scope<'b, 'a>) {
    let mut scope = Scope::new();
    // The wrapper is `((fn)(args))`, so the outer parens hide the call.
    let e = match e {
        Expression::ParenthesizedExpression(p) => &p.expression,
        other => other,
    };
    let Some(call) = as_call(e) else {
        return (e, scope);
    };
    let func = &call.callee;
    let params = match func {
        Expression::ParenthesizedExpression(p) => function_params(&p.expression),
        other => function_params(other),
    };
    for (i, name) in params.into_iter().enumerate() {
        if let Some(arg) = call.arguments.get(i).and_then(arg_expr) {
            scope.insert(name, arg);
        }
    }
    match func {
        Expression::ParenthesizedExpression(p) => (&p.expression, scope),
        other => (other, scope),
    }
}

/// The formal parameter names of a function expression / declaration.
fn function_params<'b, 'a>(e: &'b Expression<'a>) -> Vec<&'b str> {
    let items = match e {
        Expression::FunctionExpression(f) => &f.params.items,
        Expression::ArrowFunctionExpression(f) => &f.params.items,
        _ => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|p| p.pattern.get_identifier_name().map(|n| n.as_str()))
        .collect()
}

/// Parse a helper and expand each of its result branches, inside this parse's own
/// allocator (only the owned definitions escape).
fn expand_helper(
    wire_tag: &str,
    fn_src: &str,
    arg_srcs: &[String],
    ctx: &ArmCtx,
    depth: u8,
) -> Vec<NotifActionDef> {
    let alloc = Allocator::default();
    let wrapped = apply_args(fn_src, arg_srcs);
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
    let (func, bound) = applied_helper(func);
    // Same rebinding `inline_local` does, and for the same reason: from here the spans
    // index `wrapped`, so a nested `local_call_source` slicing the module with them lands
    // on unrelated text — in range, so nothing catches it. Only one of the two whole-body
    // expansion paths had it, which is exactly how the first bug survived its own fix.
    let formals = helper_formals(func);
    let ctx = &ctx.nested(&wrapped, &formals);
    let mut merged: Vec<BranchFold> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &bound) {
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
            if let Some(child) = mapped_child("", e, scope, ctx) {
                def.children.push(child);
            } else if let Some(src) = local_call_source(e, ctx, scope) {
                inline_local(&src.0, &src.1, def, ctx, depth);
            }
        }
    }
}

/// How deep a chain of helper inlinings is followed. Three is enough for every observed
/// arm (`arm → participants helper → per-participant object`) and bounds a cycle.
const MAX_INLINE_DEPTH: u8 = 3;

/// The source of the module-local helper `e` calls, if it is one.
fn local_call_source<'b, 'a>(
    e: &'b Expression<'a>,
    ctx: &ArmCtx,
    scope: &Scope<'b, 'a>,
) -> Option<(String, Vec<String>)> {
    let call = as_call(e)?;
    let name = as_identifier(&call.callee)?;
    // The CALLEE is subject to the caller's bindings too, not only the arguments below.
    // `outer(h, node){ return h(node) }` calls the `h` it was handed, so the module-level
    // `h` of the same name would publish an unrelated helper's fields, or a different
    // action entirely.
    //
    // What the caller bound is preferred, not merely refused: its text comes out of the
    // source these spans index, which is why `ArmCtx` carries that buffer. Refusing
    // outright loses a resolvable case — the whole field list of a callback passed as a
    // literal. Only when the binding cannot be read back does it fall through to nothing.
    let src = match scope.get(name) {
        Some(bound) => {
            let sp = oxc_span::GetSpan::span(*bound);
            ctx.source
                .get(sp.start as usize..sp.end as usize)?
                .to_string()
        }
        // A formal whose argument `apply_args` declined to substitute: the name is bound
        // at runtime to something this pass never saw, so the module helper is certainly
        // not it.
        None if ctx.formals.contains(name) => return None,
        None => ctx.locals.get(name).cloned()?,
    };
    // The argument TEXT, so `inline_local` can bind the helper's formals. A span outside
    // the module source (a synthesized node) yields nothing for that position rather than
    // a wrong slice.
    //
    // Resolved through the caller's scope FIRST. The minifier hoists nearly every read
    // into a local, so `var x = child.attrString("jid"); h(x)` passes the text `x` — which
    // carries no wire read, means nothing inside the helper's own parse, and made the
    // binding decline. Splicing what `x` is BOUND to is what makes the alias form work.
    let args = call
        .arguments
        .iter()
        .map(|a| {
            arg_expr(a)
                .map(|e| deref_ident(e, scope))
                .map(oxc_span::GetSpan::span)
                .and_then(|sp| ctx.source.get(sp.start as usize..sp.end as usize))
                .unwrap_or("")
                .to_string()
        })
        .collect();
    Some((src, args))
}

/// Re-parse a helper's source and fold each of its result branches into `def`.
///
/// The inlining happens inside this parse's own allocator, so no AST reference escapes
/// it — the helper's contribution is accumulated straight into `def`.
fn inline_local(
    fn_src: &str,
    arg_srcs: &[String],
    def: &mut NotifActionDef,
    ctx: &ArmCtx,
    depth: u8,
) {
    let alloc = Allocator::default();
    // Wrapped in parens so a `function name(…){…}` declaration parses as an expression,
    // and IMMEDIATELY APPLIED to the call site's argument text. A helper that only reads
    // off a node it is handed works either way, but one that receives an already-read
    // VALUE (`function h(v){ return {id: v} }` called as `h(child.attrString("jid"))`)
    // resolves its parameter to nothing without this, and the field is lost.
    let wrapped = apply_args(fn_src, arg_srcs);
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
    let (func, bound) = applied_helper(func);
    // From here the spans belong to `wrapped`, not to whatever this context was reading.
    // Folding with the outer source would slice the module at this buffer's offsets: in
    // range and therefore unguarded, but unrelated text — which cost the field a second
    // helper level down (`mk2(v){ return mk(v) }`).
    let formals = helper_formals(func);
    let ctx = &ctx.nested(&wrapped, &formals);
    // Each of the helper's result branches is folded on its own and then MERGED, not
    // accumulated: a helper returning `{x: …}` in one branch and `{y: …}` in another
    // describes two legal shapes, and combining them would make the enclosing action
    // require both and reject either. `merge_action` weakens what only some branches
    // carry — the same rule the switch arms use.
    let mut branches: Vec<BranchFold> = Vec::new();
    for (shape, scope) in fn_result_shapes(func, &bound) {
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
    // `obj_props` skips a spread, so folding the survivors publishes a partial shape:
    // `{id: attrString("jid"), ...{id: attrString("lid")}}` yields `lid` at runtime and
    // `jid` here. Same rule the constant tables and the enum tables already follow — a
    // shape that cannot be read whole is refused rather than half-reported.
    if o.properties.len() != wa_oxc::obj_props(o).count() {
        return;
    }
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
            // A shape may write the normalised identity directly (`{actionType: "create"}`)
            // instead of through the constant table. The resolver only accepts
            // `o("Mod").OBJECT.MEMBER`, so a fully static literal came back `None` and the
            // arm published no `actionType` at all — indistinguishable from an identity
            // the arm genuinely computes.
            def.action_type = as_string_lit(value)
                .map(str::to_string)
                .or_else(|| ctx.consts.resolve(value));
            continue;
        }
        if let Some(c) = const_value(value) {
            write_key(def, key, KeyValue::Const(c));
            continue;
        }
        if let Some(child) = mapped_child(key, value, scope, ctx) {
            write_key(def, key, KeyValue::Child(child));
            continue;
        }
        // A helper call in value position (`participants: y(chat, child, tag)`): inline
        // it under this key — that is where every participant list actually lives.
        if let Some(src) = local_call_source(strip_guard(value), ctx, scope)
            && depth < MAX_INLINE_DEPTH
        {
            let mut nested = empty_action(String::new());
            inline_local(&src.0, &src.1, &mut nested, ctx, depth);
            // A helper that yields nothing is a helper the inliner cannot see through —
            // typically because the value arrives through a PARAMETER
            // (`reason: hasAttr("reason") ? S(t.attrString("reason")) : null`, where `S`
            // normalises the string it is handed). Its body reads no wire attribute of its
            // own, so inlining produced an empty shape and the key was dropped, live for
            // `add`, `remove` and `delete`'s `reason`.
            //
            // Falling through to `read_field` recovers it: the wire read is in the CALL's
            // arguments, which `find_accessor` already descends into — and it refuses the
            // key outright if two arguments disagree.
            if nested.children.is_empty() && nested.fields.is_empty() {
                if let Some(field) = read_field(key, value, scope, ctx.consts) {
                    write_key(def, key, KeyValue::Field(field));
                }
                continue;
            }
            // A helper whose result is a repeated element becomes this key's child list;
            // one that returns a flat object contributes its fields under their own names.
            //
            // The OUTER guard has to survive the inlining. `local_call_source` above is
            // handed `strip_guard(value)`, so `participants: enabled && buildIt(node)`
            // reaches the helper with the guard already gone, and the `mapped_child` inside
            // sees an unguarded map — reporting a collection as always present when the
            // falsy path produces none. The guard belongs to the key, not to the helper.
            let outer_absent = guard_admits_absence(value);
            for mut c in nested.children {
                c.name = key.to_string();
                c.required &= !outer_absent;
                write_key(def, key, KeyValue::Child(c));
            }
            // Fields carry the same guard as children above. A helper whose branches
            // yield a mapped collection in one and a flat object in the other contributes
            // both kinds under `cond && helper(node)`, and only the collection was being
            // weakened — leaving a genuinely optional field marked required.
            for mut f in nested.fields {
                f.required &= !outer_absent;
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
    ctx: &ArmCtx,
) -> Option<NotifActionChild> {
    let call = as_call(strip_guard(e))?;
    if callee_method(call)? != wap::MAP_CHILDREN_WITH_TAG {
        return None;
    }
    let wire_tag = arg_expr(call.arguments.first()?).and_then(as_string_lit)?;
    let mut fields = Vec::new();
    for arg in &call.arguments {
        if let Some(e) = arg_expr(arg) {
            collect_accessor_fields(e, scope, ctx, &mut fields);
        }
    }
    Some(NotifActionChild {
        // `strip_guard` above deliberately reaches THROUGH a guard to find the map call,
        // so `participants: enabled && node.mapChildrenWithTag(…)` is recovered — and on
        // that path there is a legal execution with no collection at all. Reporting it
        // required regardless promised a consumer a collection that may never arrive,
        // and `BranchFold` cannot correct it: the guard sits inside one object shape
        // rather than splitting the arm into branches it could merge.
        //
        // What it is NOT is `!is_guarded(e)`. `read_field` runs `value_selection` before
        // consulting the guard precisely because a ternary between two REAL values is a
        // choice of source, not an absence — and the one live case here is exactly that:
        // `requests: t.hasChildren() ? t.mapChildrenWithTag(…) : [{wid: …}]` always
        // yields a collection. Only a literal absence on the far side makes it optional.
        required: !guard_admits_absence(e),
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
    let enum_ref = consts.action_enum_ref(&acc.method, acc.enum_arg, &acc.wire_name);
    Some(NotifActionField {
        name: key.to_string(),
        wire_name: acc.wire_name,
        field_type: wap::method_field_type(&acc.method),
        required: !optional_by_guard && !wap::is_optional_method(&acc.method),
        content: acc.content,
        enum_ref,
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
                // The SAME read on both paths runs on every execution, so it keeps the
                // accessor's own requiredness. Falling through to the plain path made
                // `read_field` see a conditional, call it a presence guard, and publish
                // `required: false` for an accessor that still rejects an absent value.
                Some(Some(NotifActionField {
                    name: key.to_string(),
                    required: !wap::is_optional_method(&x.method),
                    field_type: wap::method_field_type(&x.method),
                    wire_name: x.wire_name,
                    content: x.content,
                    enum_ref: x.enum_arg.and_then(|a| consts.enum_ref(a)),
                }))
            } else {
                Some(None) // two sources for one key: refuse
            }
        }
        _ => None,
    }
}

/// Whether a guard around a value has an execution path that produces NO value.
///
/// Stricter than [`is_guarded`], which asks only whether a guard is present. A ternary
/// selecting between two real values (`cond ? mapChildren(…) : [fallback]`) is guarded
/// yet always yields something, so treating every guard as optionality would publish
/// `required: false` for a collection that is in fact always there. `a && value` is the
/// opposite: the falsy path yields no value at all.
fn guard_admits_absence(e: &Expression) -> bool {
    match e {
        // `(cond ? map(…) : null)` is a paren wrapping the guard, and matching on the
        // wrapper would answer "no guard here" for a guard that is plainly there. The
        // same wrapper has cost this file a field twice before; `strip_guard` unwraps it
        // for exactly this reason, so the two must agree on what they are looking at.
        Expression::ParenthesizedExpression(p) => guard_admits_absence(&p.expression),
        Expression::ConditionalExpression(c) => {
            // Each branch is examined WHOLE, not just its stripped terminal: a guard can
            // sit inside one (`cond ? enabled && map(…) : fallback`), where neither end
            // is nullish yet the `!enabled` path still yields no collection. Terminates —
            // every step descends into a strictly smaller expression.
            is_nullish(strip_guard(&c.consequent))
                || is_nullish(strip_guard(&c.alternate))
                || guard_admits_absence(&c.consequent)
                || guard_admits_absence(&c.alternate)
        }
        Expression::LogicalExpression(l) => {
            l.operator == oxc_syntax::operator::LogicalOperator::And
        }
        _ => false,
    }
}

/// Whether the expression is a literal absence — the far side of a presence guard.
///
/// `false` counts. `enabled ? map(…) : !1` yields a boolean rather than a collection on
/// the disabled path, exactly as `enabled && map(…)` does, and only the `&&` form was
/// recognised. `!1` is how the minifier writes it.
fn is_nullish(e: &Expression) -> bool {
    match e {
        Expression::NullLiteral(_) => true,
        Expression::BooleanLiteral(b) => !b.value,
        Expression::Identifier(i) => i.name == "undefined",
        Expression::UnaryExpression(u) => match u.operator {
            // The minifier writes `undefined` as `void 0`.
            oxc_ast::ast::UnaryOperator::Void => true,
            // ...and  as .
            oxc_ast::ast::UnaryOperator::LogicalNot => as_int(&u.argument) == Some(1),
            // ...and `false` as `!1`.
            _ => false,
        },
        _ => false,
    }
}

/// The field an accessor yields when it sits behind a presence guard: always optional,
/// because the guard exists precisely so the attribute may be absent.
fn guarded_field(key: &str, acc: Accessor, consts: &ConstResolver) -> NotifActionField {
    let enum_ref = consts.action_enum_ref(&acc.method, acc.enum_arg, &acc.wire_name);
    NotifActionField {
        name: key.to_string(),
        wire_name: acc.wire_name,
        field_type: wap::method_field_type(&acc.method),
        required: false,
        content: acc.content,
        enum_ref,
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
    //
    // Exactly one argument may read the wire. `combine(c.attrString("a"),
    // c.attrString("b"))` derives its value from both, and a `NotifActionField` names one
    // `wireName` with one requiredness — so taking whichever came first would state as
    // fact something the IR cannot express. Refused instead, the same rule a key bound to
    // two different reads across branches already follows.
    // EVERY argument is inspected, not just the second: `combine(a("jid"), a("jid"),
    // a("lid"))` matches on the second and conflicts on the third, and stopping early
    // published `jid` again for a value that also depends on `lid`.
    let mut found = call
        .arguments
        .iter()
        .filter_map(arg_expr)
        .filter_map(|a| find_accessor_at(a, scope, depth + 1));
    let first = found.next()?;
    // A repeated read of the SAME attribute is not ambiguous — a normaliser given the
    // same value twice still has one source.
    let conflicts = found.any(|a| a.wire_name != first.wire_name || a.method != first.method);
    (!conflicts).then_some(first)
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
    ctx: &ArmCtx,
    out: &mut Vec<NotifActionField>,
) {
    let consts = ctx.consts;
    // No whole-body pre-pass. `collect_returns` installs the callback's own `var`
    // bindings in STATEMENT ORDER, which is the same rule it already documents for the
    // top level: hoisting moves the declaration, not the assignment, so snapshotting the
    // whole body made a later initializer visible to an earlier return —
    // `if (c) return {id: x}; var x = item.attrString("late")` published a wire
    // dependency on `late` for a branch that runs before it exists.
    let scope = outer.clone();
    // Only function arguments hold the per-element shape; a bare expression contributes
    // nothing (the tag string, the bounds).
    if !matches!(
        e,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    ) {
        // A module-local callback passed BY NAME — `mapChildrenWithTag("participant",
        // parseParticipant)` — is a function too. Rejecting the identifier before looking
        // at its body emitted the child with an empty field list, which tells a consumer
        // the element carries nothing.
        // The caller's own bindings come FIRST. A parameter or local of the same name as
        // a module function shadows it, and the runtime calls what the caller bound — so
        // reaching straight for `ctx.locals` would publish an unrelated function's fields
        // as if they were this element's.
        // Only when NOTHING in scope binds the name is the module-level function the one
        // that runs. A name that is bound but resolves to no expression we can follow is
        // refused rather than guessed at.
        let resolved = deref_ident(e, outer);
        if !std::ptr::eq(resolved, e) {
            // Recurse ONLY into something that is no longer an identifier. `deref_ident`
            // is bounded at four hops, so on an alias cycle whose length does not divide
            // four (`a → b → c → a`) it returns a *different* identifier every time —
            // and recursing on that walks the cycle forever until the stack goes. An
            // unresolved chain is refused, which is what the hop limit was already for.
            // Recurse ONLY into something that is no longer an identifier: on a cycle
            // whose length does not divide the hop limit, `deref_ident` hands back a
            // different identifier every call and recursing walks it forever.
            //
            // But a chain ending on an identifier has a second, benign cause: a TERMINAL
            // alias naming a module callback (`var cb = parseP`). Refusing those cost the
            // child its whole field list. Scope still binding the name is what separates
            // the two — a terminal module name is not bound by the caller, a cycle's is.
            match as_identifier(resolved) {
                None => collect_accessor_fields(resolved, outer, ctx, out),
                Some(inner) if outer.get(inner).is_none() => {
                    if let Some(src) = ctx.locals.get(inner) {
                        collect_named_callback_fields(src, ctx, out);
                    }
                }
                Some(_) => {}
            }
            return;
        }
        if let Some(src) = as_identifier(e)
            .filter(|n| outer.get(n).is_none())
            .and_then(|n| ctx.locals.get(n))
        {
            collect_named_callback_fields(src, ctx, out);
        }
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
                .map(|acc| {
                    let enum_ref =
                        consts.action_enum_ref(&acc.method, acc.enum_arg, &acc.wire_name);
                    NotifActionField {
                        name: acc.wire_name.clone(),
                        wire_name: acc.wire_name,
                        field_type: wap::method_field_type(&acc.method),
                        required: !wap::is_optional_method(&acc.method),
                        content: acc.content,
                        enum_ref,
                    }
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

/// Read a NAMED mapped-child callback's per-element fields, re-parsing it in its own
/// allocator the way the value-position helpers are inlined.
///
/// The returned fields are owned, so nothing from that parse escapes it.
fn collect_named_callback_fields(fn_src: &str, ctx: &ArmCtx, out: &mut Vec<NotifActionField>) {
    let alloc = Allocator::default();
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
    // The `(…)` wrapper that makes a declaration parse as an expression also hides it
    // behind a `ParenthesizedExpression`, which fails the function gate downstream.
    let func = match func {
        Expression::ParenthesizedExpression(p) => &p.expression,
        other => other,
    };
    let mut fields = Vec::new();
    collect_accessor_fields(func, &Scope::new(), ctx, &mut fields);
    for f in fields {
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
            // Do NOT descend into a property whose value is itself an object literal:
            // that is NESTING, not more of this shape. `{meta: {id: p.attrString("id")}}`
            // has no top-level `id`, and walking in claimed each element had one. The walk
            // still descends everything else, which is how it reaches the operands of a
            // `babelHelpers.extends(…)` wrapper.
            if wa_oxc::as_object(deref_ident(&p.value, self.scope)).is_some() {
                return;
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
