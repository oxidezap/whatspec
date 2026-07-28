//! Native tooling: extract WhatsApp Web's `$InternalEnum` wire-enum catalog.
//!
//! WA defines most of its enums as `var X = n("$InternalEnum")({ NAME: value, … })`
//! and exports them under a name. We collect each definition, recover its name
//! from the module's export (`obj.Name = X` / `obj.exports = X` → module name),
//! and keep only enums whose values are all-integer or all-string literals.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, Expression, ObjectExpression, ObjectPropertyKind, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{EnumValueKind, EnumVariant, EnumsIr, InternalEnumDef, Scalar};
use wa_oxc::{
    arg_expr, as_call, as_identifier, as_object, first_string_arg, parse_cjs, property_key_name,
};
use wa_transform::ModuleDefinition;

/// The dependency every `$InternalEnum`-defining module declares.
const DEP: &str = "$InternalEnum";

/// Parsed enum body: its value kind + variants (source order).
type EnumData = (EnumValueKind, Vec<EnumVariant>);

/// Convenience: split a whole bundle into modules, then extract the catalog.
/// Mirrors `extract_mex` / `extract_appstate`; the pipeline uses
/// [`extract_enums_from_modules`] to share one split with the other extractors.
pub fn extract_enums(source: &str, wa_version: &str) -> EnumsIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_enums_from_modules(source, &defs, wa_version)
}

/// Extract the `$InternalEnum` catalog from an already-split module index.
pub fn extract_enums_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> EnumsIr {
    let mut enums = Vec::new();
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if m.deps.iter().any(|d| d == DEP) {
            // The reliable, cheap path: `$InternalEnum({…})` definitions.
            enums.extend(extract_from_module(slice, &m.name));
        } else if is_protocol_enum_module(&m.name) {
            // Some wire enums are plain object literals exported by name
            // (`var e={INACTIVE:-6,…}; i.ACK=e`) with no `$InternalEnum` dep. A plain
            // object is ambiguous (every `{a:1,b:2}` config/UI/i18n map looks like one),
            // so this path is scoped to modules WA names by its *protocol* enum-bag
            // convention — `WASmax<In|Out>…Enums` plus the two ack/receipt level modules —
            // never the app's infra constants (loggers, locales, JPEG markers, …). Within
            // those, [`extract_plain_object_enums`] still keeps only `CONSTANT_CASE`
            // members so a stray helper export can't leak in.
            enums.extend(extract_plain_object_enums(slice, &m.name));
        }
    }
    // Deterministic order independent of bundle layout.
    enums.sort_by(|a, b| a.module.cmp(&b.module).then_with(|| a.name.cmp(&b.name)));
    enums.dedup_by(|a, b| a.module == b.module && a.name == b.name);
    EnumsIr {
        wa_version: wa_version.to_string(),
        enums,
    }
}

fn extract_from_module(slice: &str, module: &str) -> Vec<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut c = Collector {
        module,
        locals: HashMap::new(),
        named: Vec::new(),
        pending: Vec::new(),
    };
    c.visit_program(&ret.program);

    // Resolve `export = local` bindings against the locals captured by var-init.
    for (name, local) in &c.pending {
        if let Some(data) = c.locals.get(local) {
            c.named.push((name.clone(), data.clone()));
        }
    }

    let mut out: Vec<InternalEnumDef> = Vec::new();
    for (name, (value_kind, variants)) in c.named {
        if out.iter().any(|d| d.name == name) {
            continue; // first binding wins (aliases collapse)
        }
        out.push(InternalEnumDef {
            name,
            module: module.to_string(),
            value_kind,
            variants,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Every name a function body hoists: its `var` declarations and its nested function
/// declarations, wherever in the body they are written.
///
/// `var` is FUNCTION-scoped, so one inside an `if` or a loop binds for the whole body too;
/// nested functions are not descended into, because their own `var`s belong to them.
fn collect_hoisted(stmts: &[oxc_ast::ast::Statement], out: &mut HashSet<String>) {
    use oxc_ast::ast::Statement as S;
    for stmt in stmts {
        match stmt {
            S::FunctionDeclaration(d) => {
                if let Some(id) = &d.id {
                    out.insert(id.name.to_string());
                }
            }
            S::VariableDeclaration(d) => collect_declared(d, out),
            S::BlockStatement(b) => collect_hoisted(&b.body, out),
            S::IfStatement(i) => {
                collect_hoisted(std::slice::from_ref(&i.consequent), out);
                if let Some(alt) = &i.alternate {
                    collect_hoisted(std::slice::from_ref(alt), out);
                }
            }
            // The HEADER declares too, and `var` there is hoisted across the function
            // exactly as one in the body is — scanning only the body left
            // `for (var e of xs)` invisible.
            S::ForStatement(f) => {
                if let Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(d)) = &f.init {
                    collect_declared(d, out);
                }
                collect_hoisted(std::slice::from_ref(&f.body), out);
            }
            S::ForInStatement(f) => {
                if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(d) = &f.left {
                    collect_declared(d, out);
                }
                collect_hoisted(std::slice::from_ref(&f.body), out);
            }
            S::ForOfStatement(f) => {
                if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(d) = &f.left {
                    collect_declared(d, out);
                }
                collect_hoisted(std::slice::from_ref(&f.body), out);
            }
            S::WhileStatement(w) => collect_hoisted(std::slice::from_ref(&w.body), out),
            S::DoWhileStatement(w) => collect_hoisted(std::slice::from_ref(&w.body), out),
            S::TryStatement(t) => {
                collect_hoisted(&t.block.body, out);
                if let Some(h) = &t.handler {
                    collect_hoisted(&h.body.body, out);
                }
                if let Some(fin) = &t.finalizer {
                    collect_hoisted(&fin.body, out);
                }
            }
            S::SwitchStatement(sw) => {
                for case in &sw.cases {
                    collect_hoisted(&case.consequent, out);
                }
            }
            S::LabeledStatement(l) => collect_hoisted(std::slice::from_ref(&l.body), out),
            _ => {}
        }
    }
}

/// Every plain identifier an assignment TARGET writes, however the pattern is spelled.
fn assignment_target_names(target: &oxc_ast::ast::AssignmentTarget) -> Vec<String> {
    let mut out = Vec::new();
    // Cheap and textual on the AST: only the simple names matter here, because only a
    // simple name can be an enum local this pass recorded.
    if let Some(pattern) = target.as_assignment_target_pattern() {
        use oxc_ast::ast::AssignmentTargetPattern as P;
        match pattern {
            P::ArrayAssignmentTarget(a) => {
                for el in a.elements.iter().flatten() {
                    if let Some(id) = el.identifier() {
                        out.push(id.name.to_string());
                    }
                }
            }
            P::ObjectAssignmentTarget(o) => {
                for prop in &o.properties {
                    match prop {
                        oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(
                            p,
                        ) => out.push(p.binding.name.to_string()),
                        oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyProperty(
                            p,
                        ) => {
                            if let Some(id) = p.binding.identifier() {
                                out.push(id.name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Every identifier one `var`/`let`/`const` declaration binds.
fn collect_declared(d: &oxc_ast::ast::VariableDeclaration, out: &mut HashSet<String>) {
    for decl in &d.declarations {
        for id in decl.id.get_binding_identifiers() {
            out.insert(id.name.to_string());
        }
    }
}

/// The identifier names a parameter list binds.
fn param_names(params: &oxc_ast::ast::FormalParameters) -> HashSet<String> {
    // EVERY identifier a parameter list binds, not just the plainly-named ones. A
    // destructured parameter (`function f({e})`) binds `e` exactly as much as
    // `function f(e)` does, and the rest element is not in `items` at all — both were
    // invisible, so a composition inside such a function still resolved the module-level
    // operand. `get_binding_identifiers` is the same traversal `wa_scan::shadow_params`
    // uses for its own shadowing, rather than a second hand-rolled walk to drift from.
    let mut out = HashSet::new();
    let mut add = |pattern: &oxc_ast::ast::BindingPattern| {
        for ident in pattern.get_binding_identifiers() {
            out.insert(ident.name.to_string());
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

/// Resolve `X.Name = local` bindings against the locals captured by var-init, filling
/// `exports` (first binding wins). Shared by [`resolve_named_enum`] and the plain-object
/// catalog pass so the two resolution sites can't drift.
fn resolve_pending(r: &mut NamedResolver) {
    for (export, local) in &r.pending {
        // Same refusal as `NamedResolver::local`, spelled out because the method borrows
        // all of `r` while `exports` below needs a disjoint mutable borrow. An export
        // bound to a name the module rebinds is exactly as unsafe to publish here.
        if r.shadowed.contains(local) {
            continue;
        }
        if let Some(data) = r.locals.get(local) {
            r.exports
                .entry(export.clone())
                .or_insert_with(|| data.clone());
        }
    }
}

/// Resolve one named enum export from a single module, for the IQ attribute
/// enum-linking. Unlike the catalog extractor this also accepts a **plain
/// object-literal** export (`X.Name = {KEY:"val"}` or `var l = {…}; X.Name = l`) —
/// how enums like `USYNC_ADDRESSING_MODE` / `ENC_RETRY_RECEIPT_ATTRS` are defined
/// (they never reach the `$InternalEnum` catalog). It is targeted by `name` and
/// validated by [`parse_enum`] (all-literal values, one value kind), so a non-enum
/// object can't resolve. Returns `None` when `name` isn't an enum-shaped export — the
/// caller then drops the link rather than guessing.
pub fn resolve_named_enum(module_slice: &str, module: &str, name: &str) -> Option<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, module_slice);
    if ret.panicked {
        return None;
    }
    let mut r = NamedResolver::new();
    r.visit_program(&ret.program);
    resolve_pending(&mut r);
    let (value_kind, variants) = r.exports.get(name)?.clone();
    Some(InternalEnumDef {
        name: name.to_string(),
        module: module.to_string(),
        value_kind,
        variants,
    })
}

/// An enum-body object: either `$InternalEnum({…})` or a bare object literal.
fn enum_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    internal_enum_object(e).or_else(|| as_object(e))
}

/// Whether `name` is `CONSTANT_CASE` (`[A-Z][A-Z0-9_]*`) — the member-name shape WA
/// uses for its plain-object wire enums (`INACTIVE`, `READ_SELF`, `CONTENT_TOO_BIG`),
/// as opposed to the `camelCase` keys of config/lookup maps.
fn is_constant_case(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `module` is one WA declares its *wire-protocol* enums in as plain object
/// literals (no `$InternalEnum`): the `WASmax<In|Out>…Enums` smax enum bags, plus the
/// two ack/receipt-level modules that predate that convention. Deliberately narrow —
/// the app has thousands of `CONSTANT_CASE` infra objects (loggers, locales, JPEG
/// markers, UI constants) that are not part of the protocol surface.
fn is_protocol_enum_module(module: &str) -> bool {
    ((module.starts_with("WASmaxIn") || module.starts_with("WASmaxOut"))
        && module.ends_with("Enums"))
        || module == "WAWebAck"
        || module == "WAAckLevel"
}

/// Extract plain-object-literal enums exported by name from a non-`$InternalEnum`
/// module (`i.ACK = {INACTIVE:-6,…}` or `var e={…}; i.ACK=e`). Kept deliberately strict
/// — only exports with ≥2 members, all-literal single-kind values ([`parse_enum`]), and
/// all-`CONSTANT_CASE` member names — so config/lookup maps don't leak into the catalog.
fn extract_plain_object_enums(slice: &str, module: &str) -> Vec<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    if ret.panicked {
        return Vec::new();
    }
    let mut r = NamedResolver::new();
    r.visit_program(&ret.program);
    resolve_pending(&mut r);
    let mut out: Vec<InternalEnumDef> = Vec::new();
    for (name, (value_kind, variants)) in r.exports {
        if variants.len() >= 2 && variants.iter().all(|v| is_constant_case(&v.name)) {
            out.push(InternalEnumDef {
                name,
                module: module.to_string(),
                value_kind,
                variants,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

struct NamedResolver {
    locals: HashMap<String, EnumData>,
    /// Names bound to two DIFFERENT enum bodies somewhere in the module.
    ///
    /// `locals` is flat while JavaScript is lexically scoped, so a minified module that
    /// reuses a short name inside a nested function — `var e={A:"a"}` at the top, then
    /// `function f(){var e={X:"x"}}` — overwrites the outer binding that a later
    /// `extends({}, e, …)` still refers to at runtime. Publishing `X` there would be a
    /// closed value set naming members the runtime never accepts, which is the one thing
    /// this crate must not do; both readers of `locals` refuse such a name instead.
    ///
    /// Tracking real scopes would be the complete answer. Refusal is the cheap one that
    /// cannot be wrong, and no bundle in the pinned set has a single collision — so the
    /// choice costs nothing today and stays correct if that changes.
    shadowed: HashSet<String>,
    /// Parameter names bound by the functions currently being visited, innermost last.
    ///
    /// A parameter shadows only INSIDE its own body, so unlike [`Self::shadowed`] this is
    /// a stack rather than a module-wide set. Refusing such a name everywhere was measured
    /// and costs real constraints — `STANZA_MSG_TYPES` resolves at module level in a
    /// module that happens to reuse its local's name as a parameter elsewhere.
    param_scopes: Vec<HashSet<String>>,
    exports: HashMap<String, EnumData>,
    pending: Vec<(String, String)>,
}

impl NamedResolver {
    fn new() -> Self {
        Self {
            locals: HashMap::new(),
            shadowed: HashSet::new(),
            param_scopes: Vec::new(),
            exports: HashMap::new(),
            pending: Vec::new(),
        }
    }

    /// The body bound to `name`, unless the module rebinds it to a different one.
    fn local(&self, name: &str) -> Option<&EnumData> {
        if self.shadowed.contains(name) || self.param_shadows(name) {
            return None;
        }
        self.locals.get(name)
    }

    /// Whether an enclosing function binds `name` as a parameter, so a read of it here
    /// is that parameter and not the module local this pass recorded.
    fn param_shadows(&self, name: &str) -> bool {
        self.param_scopes.iter().any(|s| s.contains(name))
    }

    fn bind_local(&mut self, name: &str, data: EnumData) {
        match self.locals.get(name) {
            Some(prev) if *prev != data => {
                self.shadowed.insert(name.to_string());
            }
            _ => {}
        }
        self.locals.insert(name.to_string(), data);
    }
}

impl NamedResolver {
    /// Evaluate `babelHelpers.extends(a, b, …)` into one enum, left to right.
    ///
    /// Each operand must be something already understood — an object literal, an
    /// `$InternalEnum(…)`, or a local this pass has already bound. Anything else refuses
    /// the whole thing rather than publishing the operands it could read: a partial
    /// merge is a closed value set that omits members the runtime accepts, which is
    /// worse than recording the loss.
    ///
    /// Later operands override earlier keys, as the runtime does. A single value kind is
    /// required, so a string enum merged with an int one resolves to nothing.
    /// The local an `extends(target, …)` MUTATES, when the target is a bare name.
    ///
    /// `extends` writes into its first argument, so after `extends(e, {B:"b"})` the
    /// runtime's `e` has `B` too. Recovering the pre-merge body would publish an enum
    /// that rejects a value it accepts — which the refusal in `merge_extends` prevents
    /// for the RESULT, and which this exists to prevent for the target itself.
    fn mutated_extends_target<'e>(e: &'e Expression) -> Option<&'e str> {
        let call = as_call(e)?;
        let callee = wa_oxc::as_member(&call.callee)?;
        if callee.1 != "extends" || as_identifier(callee.0) != Some("babelHelpers") {
            return None;
        }
        as_identifier(arg_expr(call.arguments.first()?)?)
    }

    fn merge_extends(&self, e: &Expression) -> Option<EnumData> {
        let call = as_call(e)?;
        let callee = wa_oxc::as_member(&call.callee)?;
        if callee.1 != "extends" || as_identifier(callee.0) != Some("babelHelpers") {
            return None;
        }
        // The first operand is the TARGET, and `extends` mutates it. WA's convention is
        // `extends({}, …)`, which mutates a throwaway; `extends(base, {B:"b"})` would also
        // add `B` to `base` itself, so recovering only the result would publish a `BASE`
        // export that is missing a member the runtime has. Recovering the composition is
        // not worth modelling the mutation, so a non-empty target refuses the whole thing.
        match call
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_object)
        {
            Some(o) if o.properties.is_empty() => {}
            _ => return None,
        }
        let mut kind: Option<EnumValueKind> = None;
        let mut merged: Vec<EnumVariant> = Vec::new();
        for arg in &call.arguments {
            let operand = arg_expr(arg)?;
            // An empty `{}` is the conventional first operand and contributes nothing —
            // and `parse_enum` rejects it (no variants), so it has to be recognised
            // before the refusal path or it kills every merge.
            if let Some(o) = as_object(operand)
                && o.properties.is_empty()
            {
                continue;
            }
            let (k, variants) = match enum_object(operand).and_then(parse_enum) {
                Some(data) => data,
                // A bare identifier must already be bound by this pass.
                None => self.local(as_identifier(operand)?)?.clone(),
            };
            if !variants.is_empty() {
                match kind {
                    Some(prev) if prev != k => return None,
                    _ => kind = Some(k),
                }
            }
            for v in variants {
                match merged.iter_mut().find(|x| x.name == v.name) {
                    Some(existing) => *existing = v,
                    None => merged.push(v),
                }
            }
        }
        if merged.is_empty() {
            return None;
        }
        Some((kind?, merged))
    }
}

impl<'a> Visit<'a> for NamedResolver {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        // `var x = extends(e, {B:"b"})` MUTATES `e`. `merge_extends` already refuses to
        // publish `x`, but `e` itself kept its pre-merge body and a later `i.BASE = e`
        // published an enum missing a member the runtime accepts.
        if let Some(init) = &d.init
            && let Some(target) = Self::mutated_extends_target(init)
            && !self.param_shadows(target)
        {
            self.shadowed.insert(target.to_string());
        }
        if d.id.get_identifier_name().is_none() {
            // A DESTRUCTURED declaration (`const {e} = obj`) binds `e` just as much as
            // `var e = …` does, and `get_identifier_name` sees none of it — so the whole
            // branch below was skipped and the outer body stayed usable. Refused on
            // collision only, the same rule an unreadable initializer follows: a
            // destructuring that shadows nothing costs nothing to ignore.
            //
            // The hoisted prescan already marks these LEXICALLY, so writing them into the
            // module-wide set as well outlived the body that binds them and refused a
            // later, unrelated outer composition. Same guard the simple-identifier path
            // takes, for the same reason.
            for ident in d.id.get_binding_identifiers() {
                if !self.param_shadows(&ident.name) && self.locals.contains_key(ident.name.as_str())
                {
                    self.shadowed.insert(ident.name.to_string());
                }
            }
        }
        if let Some(local) = d.id.get_identifier_name() {
            let data = d
                .init
                .as_ref()
                .and_then(enum_object)
                .and_then(parse_enum)
                // WA composes enums as well as declaring them:
                // `VISIBILITY_WITH_ERROR = extends({}, VISIBILITY, {error: "error"})`.
                // Recognising only literals left every composed one unresolvable, and the
                // fields validating against them shipped as `"type": "enum"` with no
                // values — 41 lost constraints, the largest single entry in
                // `dropsByReason`.
                .or_else(|| d.init.as_ref().and_then(|e| self.merge_extends(e)));
            // A name bound by an enclosing parameter (or hoisted binding) is LOCAL to that
            // body, so writing it into the module-wide `locals`/`shadowed` would let a
            // write inside one function invalidate a valid module-level read elsewhere.
            if self.param_shadows(&local) {
                walk::walk_variable_declarator(self, d);
                return;
            }
            match data {
                Some(data) => self.bind_local(local.as_str(), data),
                // A redeclaration this pass cannot READ is as much a shadow as one it
                // can: `var e = getEnum()` in a nested scope leaves the outer body in
                // `locals`, and a later composition would publish values the runtime
                // never has. Only when the name is already bound — an unparseable `var`
                // that shadows nothing costs nothing to ignore.
                None if self.locals.contains_key(local.as_str()) => {
                    self.shadowed.insert(local.to_string());
                }
                None => {}
            }
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_function(
        &mut self,
        f: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        // Everything this body binds is HOISTED over all of it, so a declaration written
        // AFTER a composition still binds the operand that composition reads. Recording
        // them as the walk reached them was source-ordered and reversing the two lines
        // slipped straight past, so the whole body is pre-scanned before descending.
        //
        // Lexical, not module-wide: the enclosing scope is what a nested `function e(){}`
        // shadows, and poisoning `e` for the entire module would refuse a composition
        // written outside this body that never sees the inner binding at all.
        let mut hoisted = param_names(&f.params);
        // A NAMED function expression binds its own name inside its body (`var g =
        // function e(){ … e … }` sees the function, not an outer `e`). That name lives on
        // `f.id`, not among the declarations collected from the enclosing body, so it was
        // the one binding form the prescan could not see.
        if let Some(id) = &f.id
            && self.locals.contains_key(id.name.as_str())
        {
            hoisted.insert(id.name.to_string());
        }
        if let Some(body) = &f.body {
            let mut declared = HashSet::new();
            collect_hoisted(&body.statements, &mut declared);
            // Only the ones that SHADOW something already bound. The module body is itself
            // a function, so an unconditional sweep made its own `var e = {…}` shadow the
            // local it declares — every enum in the catalog refused itself. Parameters
            // stay unconditional: they can never BE the module local.
            hoisted.extend(
                declared
                    .into_iter()
                    .filter(|n| self.locals.contains_key(n.as_str())),
            );
        }
        self.param_scopes.push(hoisted);
        walk::walk_function(self, f, flags);
        self.param_scopes.pop();
    }

    fn visit_catch_clause(&mut self, c: &oxc_ast::ast::CatchClause<'a>) {
        // `catch (e)` binds `e` for the handler body exactly as a parameter binds it for
        // a function body — the third form of the same shadow, after parameters and
        // destructured declarations.
        let names = c
            .param
            .as_ref()
            .map(|p| {
                p.pattern
                    .get_binding_identifiers()
                    .into_iter()
                    .map(|i| i.name.to_string())
                    .collect()
            })
            .unwrap_or_default();
        self.param_scopes.push(names);
        walk::walk_catch_clause(self, c);
        self.param_scopes.pop();
    }

    fn visit_arrow_function_expression(&mut self, f: &oxc_ast::ast::ArrowFunctionExpression<'a>) {
        // A block-bodied arrow hoists exactly as a function does; only its parameters
        // were being recorded.
        let mut hoisted = param_names(&f.params);
        let mut declared = HashSet::new();
        collect_hoisted(&f.body.statements, &mut declared);
        hoisted.extend(
            declared
                .into_iter()
                .filter(|n| self.locals.contains_key(n.as_str())),
        );
        self.param_scopes.push(hoisted);
        walk::walk_arrow_function_expression(self, f);
        self.param_scopes.pop();
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        if let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            if let Some(data) = enum_object(&a.right).and_then(parse_enum) {
                self.exports.entry(prop.to_string()).or_insert(data);
            } else if prop == "exports"
                && let Some(o) = as_object(&a.right)
            {
                // `X.exports = { Name: <enum|local>, … }` — a named export bag; index
                // each member so an enum published this way still resolves.
                for (key, value) in wa_oxc::obj_props(o) {
                    if let Some(data) = enum_object(value).and_then(parse_enum) {
                        self.exports.entry(key.to_string()).or_insert(data);
                    } else if let Some(id) = as_identifier(value)
                        // The same deferred-alias guard as the single-property branch
                        // below: `pending` resolves after the walk, when the parameter
                        // stack is unwound, so a parameter-shadowed name has to be
                        // refused HERE or it silently resolves to the module local.
                        && !self.param_shadows(id)
                    {
                        self.pending.push((key.to_string(), id.to_string()));
                    }
                }
            } else if let Some(id) = as_identifier(&a.right)
                // `pending` is resolved AFTER the walk, when the parameter stack is
                // already unwound, so the scope has to be recorded now: `function f(e){
                // i.OUT = e }` would otherwise export the module-local `e`.
                && !self.param_shadows(id)
            {
                self.pending.push((prop.to_string(), id.to_string()));
            }
        } else if a.left.get_identifier_name().is_none() && a.left.as_member_expression().is_none()
        {
            // A destructuring ASSIGNMENT (`({e} = obj)`) rebinds without declaring, so no
            // declarator ever runs and the cached body survived a write that replaced it.
            for name in assignment_target_names(&a.left) {
                if !self.param_shadows(&name) && self.locals.contains_key(name.as_str()) {
                    self.shadowed.insert(name);
                }
            }
        } else if let Some(name) = a.left.get_identifier_name() {
            // A bare `e = …` rebinding, which `visit_variable_declarator` never sees.
            // Without this, only `var`-form rebindings reached `shadowed`, so a module
            // that reassigns an operand before composing it still published the stale
            // body — the same wrong closed set the shadow guard was added to prevent,
            // reached through the one form it did not watch.
            // Deliberately does NOT fall back to `merge_extends` the way the `var` form
            // does. A self-referential rebind (`e = extends({}, e, {B:"b"})`) is only
            // resolvable if you know whether a given read of `e` happens before or after
            // it, and this pass has no ordering model for reads — so publishing the
            // merged set would over-claim for every read that precedes the composition.
            // Refusing costs nothing here: the merge yields a body different from the one
            // already bound, so `bind_local` would mark the name shadowed anyway.
            if self.param_shadows(name) {
                // Local to the body that binds it — see the declarator path.
                walk::walk_assignment_expression(self, a);
                return;
            }
            match enum_object(&a.right).and_then(parse_enum) {
                Some(data) => self.bind_local(name, data),
                // Rebound to something this pass cannot read: whatever `locals` still
                // holds for the name is no longer what the runtime has, so the name is
                // no more usable than an ambiguous one.
                None => {
                    self.shadowed.insert(name.to_string());
                }
            }
        }
        walk::walk_assignment_expression(self, a);
    }
}

struct Collector<'m> {
    module: &'m str,
    /// `var local = $InternalEnum(...)` → its parsed body.
    locals: HashMap<String, EnumData>,
    /// Inline-named definitions (`obj.Name = $InternalEnum(...)`).
    named: Vec<(String, EnumData)>,
    /// `obj.Name = localIdent` — resolved against `locals` after the walk.
    pending: Vec<(String, String)>,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let (Some(name), Some(obj)) = (
            d.id.get_identifier_name(),
            d.init
                .as_ref()
                .and_then(|e| collector_enum_object(e, self.module)),
        ) && let Some(data) = parse_enum(obj)
        {
            self.locals.insert(name.to_string(), data);
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        if let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            // `obj.exports = …` is the module's default export → name by module.
            let export_name = if prop == "exports" {
                self.module.to_string()
            } else {
                prop.to_string()
            };
            if let Some(obj) = collector_enum_object(&a.right, self.module) {
                if let Some(data) = parse_enum(obj) {
                    self.named.push((export_name, data));
                }
            } else if let Some(id) = as_identifier(&a.right) {
                self.pending.push((export_name, id.to_string()));
            } else if prop == "exports" {
                // `obj.exports = { Name: <enum|local>, … }` — a named bag.
                if let Some(o) = as_object(&a.right) {
                    self.collect_export_bag(o);
                }
            }
        }
        walk::walk_assignment_expression(self, a);
    }
}

impl Collector<'_> {
    fn collect_export_bag(&mut self, o: &ObjectExpression) {
        for (key, value) in wa_oxc::obj_props(o) {
            if let Some(obj) = collector_enum_object(value, self.module) {
                if let Some(data) = parse_enum(obj) {
                    self.named.push((key.to_string(), data));
                }
            } else if let Some(id) = as_identifier(value) {
                self.pending.push((key.to_string(), id.to_string()));
            }
        }
    }
}

/// If `e` is `<require>("$InternalEnum")({ … })`, the argument object literal.
fn internal_enum_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    let outer = as_call(e)?;
    let inner = as_call(&outer.callee)?;
    if first_string_arg(inner) != Some(DEP) {
        return None;
    }
    as_object(arg_expr(outer.arguments.first()?)?)
}

/// If `e` is `Object.freeze({ … })`, the frozen object literal. WA freezes some wire
/// enums (`RECEIPT_TYPE`) this way rather than via `$InternalEnum`.
fn object_freeze_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    let call = as_call(e)?;
    let (obj, prop) = wa_oxc::as_member(&call.callee)?;
    if as_identifier(obj)? != "Object" || prop != "freeze" {
        return None;
    }
    as_object(arg_expr(call.arguments.first()?)?)
}

/// Whether every key of `obj` is `CONSTANT_CASE` (and it has at least one) — the gate for
/// admitting an `Object.freeze` body, which unlike `$InternalEnum` also wraps plenty of
/// non-enum config (camelCase lookup maps, option bags).
fn all_constant_case(obj: &ObjectExpression) -> bool {
    let mut any = false;
    for (key, _) in wa_oxc::obj_props(obj) {
        any = true;
        if !is_constant_case(key) {
            return false;
        }
    }
    any
}

/// Modules that declare a *wire* enum via `Object.freeze({…})` rather than `$InternalEnum`
/// or a bare literal. Deliberately a curated allowlist (like [`is_protocol_enum_module`]):
/// `Object.freeze` wraps countless internal constant maps — storage-key tables, WASI errno
/// codes, IndexedDB schema — that are all-`CONSTANT_CASE` too, so membership alone can't
/// tell them apart from a real enum. Only `WAWebSendReceiptJobCommon`'s `RECEIPT_TYPE` (the
/// canonical receipt-type token set) qualifies today.
fn is_frozen_enum_module(module: &str) -> bool {
    module == "WAWebSendReceiptJobCommon"
}

/// An enum body for the `$InternalEnum`-module [`Collector`]: `$InternalEnum({…})`
/// (trusted), or — only in an [`is_frozen_enum_module`] module — an `Object.freeze({…})`
/// whose members are all `CONSTANT_CASE`. [`parse_enum`] applies the remaining value-shape
/// gates.
fn collector_enum_object<'b, 'a>(
    e: &'b Expression<'a>,
    module: &str,
) -> Option<&'b ObjectExpression<'a>> {
    if let Some(obj) = internal_enum_object(e) {
        return Some(obj);
    }
    if !is_frozen_enum_module(module) {
        return None;
    }
    let obj = object_freeze_object(e)?;
    all_constant_case(obj).then_some(obj)
}

/// Parse the enum body. Returns `None` for spread/computed keys, non-literal
/// values, or mixed int/string value kinds.
fn parse_enum(obj: &ObjectExpression) -> Option<EnumData> {
    let mut kind: Option<EnumValueKind> = None;
    let mut variants = Vec::new();
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            return None;
        };
        let name = property_key_name(&p.key)?;
        let (k, value) = match &p.value {
            Expression::StringLiteral(s) => {
                (EnumValueKind::String, Scalar::Str(s.value.to_string()))
            }
            other => (EnumValueKind::Int, Scalar::Int(wa_oxc::as_int(other)?)),
        };
        match kind {
            None => kind = Some(k),
            Some(prev) if prev != k => return None, // mixed → skip enum
            _ => {}
        }
        variants.push(EnumVariant {
            name: name.to_string(),
            value,
        });
    }
    match kind {
        Some(k) if !variants.is_empty() => Some((k, variants)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_composed_enum_merges_its_operands() {
        // WA composes enums as well as declaring them, and the composed ones are the
        // interesting ones: `VISIBILITY_WITH_ERROR` is `VISIBILITY` plus the `error`
        // sentinel the parser checks for. Recognising only literals left 41 constraints
        // unresolvable — the largest single entry in `dropsByReason`.
        let module = r#"__d("WAWebPrivacySettings",[],(function(t,n,r,o,a,i){
            var e={all:"all",contacts:"contacts",none:"none"},
                l=babelHelpers.extends({},e,{error:"error"});
            i.VISIBILITY=e,i.VISIBILITY_WITH_ERROR=l
        }),66);"#;
        let def = resolve_named_enum(module, "WAWebPrivacySettings", "VISIBILITY_WITH_ERROR")
            .expect("the composed export resolves");
        let values: Vec<&str> = def
            .variants
            .iter()
            .map(|v| match &v.value {
                Scalar::Str(s) => s.as_str(),
                _ => "<non-string>",
            })
            .collect();
        assert_eq!(
            values,
            ["all", "contacts", "none", "error"],
            "in merge order"
        );
        // The base is still resolvable on its own, and does NOT gain the sentinel.
        let base = resolve_named_enum(module, "WAWebPrivacySettings", "VISIBILITY").unwrap();
        assert_eq!(base.variants.len(), 3);
    }

    #[test]
    fn a_composition_that_mutates_its_target_is_refused() {
        // `extends(base, {B:"b"})` adds `B` to `base` ITSELF at runtime. Recovering only
        // the result would publish a `BASE` export missing a member the runtime has —
        // an enum that claims to reject a value it accepts. WA's convention is an empty
        // target, so requiring one costs nothing and rules the mutation out.
        let module = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"},l=babelHelpers.extends(e,{B:"b"});
            i.BASE=e,i.WITH=l
        }),1);"#;
        assert!(resolve_named_enum(module, "M", "WITH").is_none());
        // ...and the TARGET is refused too. This once asserted that `BASE` still resolved
        // with its one written member — which is precisely the enum "claiming to reject a
        // value it accepts" that the paragraph above calls out. The comment described the
        // hazard and the assertion below it enshrined the hazard; refusing is the only
        // answer consistent with both.
        assert!(
            resolve_named_enum(module, "M", "BASE").is_none(),
            "`extends` wrote `B` into `e`, so the pre-merge body is not what the runtime has"
        );
    }

    #[test]
    fn a_name_the_module_rebinds_is_refused_everywhere_it_is_read() {
        // `locals` is flat; JavaScript is not. A minifier that reuses `e` inside a nested
        // function must not leak into the outer binding the composition below reads. This
        // once asserted REFUSAL on both, which was the conservative approximation of a
        // resolver that could not tell an inner `e` from an outer one; now that parameter,
        // hoisted and catch scopes are modelled, the honest answer is the lexical one —
        // and keeping a refusal here would throw away two resolvable enums. What still
        // refuses is ambiguity the pass genuinely cannot order, below.
        let module = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(){var e={X:"x"};return e}
            var l=babelHelpers.extends({},e,{B:"b"});
            i.WITH=l,i.ALIAS=e
        }),1);"#;
        // Now that the pass models scopes, the honest answer here is to RESOLVE: the inner
        // `var e` is local to `f`, and both reads below are outer ones that never see it.
        // The refusal this once asserted was the conservative approximation of a resolver
        // that could not tell the two apart — worth keeping only while that was true.
        assert_eq!(
            resolve_named_enum(module, "M", "WITH")
                .expect("the outer composition is unambiguous")
                .variants
                .len(),
            2,
            "outer `e` plus `B`, not the inner `{{X}}`"
        );
        assert_eq!(
            resolve_named_enum(module, "M", "ALIAS")
                .expect("the outer alias is unambiguous")
                .variants
                .len(),
            1
        );
        // A bare `e = …` rebinding is invisible to `visit_variable_declarator`, so only
        // the `var` form reached `shadowed` at first — the same stale-body bug through
        // the one write form the guard did not watch.
        let assigned = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(){e={X:"x"}}
            var l=babelHelpers.extends({},e,{B:"b"});
            i.WITH=l,i.ALIAS=e
        }),1);"#;
        assert!(resolve_named_enum(assigned, "M", "WITH").is_none());
        assert!(resolve_named_enum(assigned, "M", "ALIAS").is_none());

        // Rebound to something unreadable is no better: whatever `locals` still holds is
        // not what the runtime has.
        let opaque = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(){e=computed()}
            i.ALIAS=e
        }),1);"#;
        assert!(resolve_named_enum(opaque, "M", "ALIAS").is_none());

        // A PARAMETER binds the name for its whole body, which neither the declarator nor
        // the assignment path sees.
        let param = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(e){ var l=babelHelpers.extends({},e,{B:"b"}); i.WITH=l }
            f({X:"x"})
        }),1);"#;
        assert!(resolve_named_enum(param, "M", "WITH").is_none());

        // ...but only INSIDE that body. Refusing the name module-wide was measured against
        // the pinned bundles and lost a real constraint (`STANZA_MSG_TYPES`), so a merge
        // outside the shadowing function must still resolve.
        let outside = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(e){ return e }
            var l=babelHelpers.extends({},e,{B:"b"});
            i.WITH=l
        }),1);"#;
        let def = resolve_named_enum(outside, "M", "WITH").expect("resolves outside the body");
        assert_eq!(def.variants.len(), 2);

        // A redeclaration this pass cannot READ shadows just as much as one it can.
        let unreadable = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(){ var e=getEnum(); var l=babelHelpers.extends({},e,{B:"b"}); i.OUT=l }
        }),1);"#;
        assert!(resolve_named_enum(unreadable, "M", "OUT").is_none());

        // A deferred alias (`i.OUT = e`) is resolved after the walk, when the parameter
        // stack is already unwound — so the shadow has to be recorded at the assignment.
        let deferred = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(e){ i.OUT=e }
            f({X:"x"})
        }),1);"#;
        assert!(resolve_named_enum(deferred, "M", "OUT").is_none());

        // A DESTRUCTURED parameter binds its names too, and a rest element is not even
        // in `items` — both were invisible to the plain-name lookup.
        let destructured = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f({e}){ var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
            f({e:{X:"x"}})
        }),1);"#;
        assert!(resolve_named_enum(destructured, "M", "OUT").is_none());

        let rest = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(q, ...e){ var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(rest, "M", "OUT").is_none());

        // The exports BAG defers aliases the same way the single-property form does, so
        // it needs the same parameter guard.
        let bag = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(e){ i.exports={OUT:e} }
            f({X:"x"})
        }),1);"#;
        assert!(resolve_named_enum(bag, "M", "OUT").is_none());

        // A bare rebind to a composition is REFUSED, not resolved: which body a read of
        // `e` sees depends on whether it precedes the rebind, and nothing here models
        // that order. See the note at the assignment branch.
        let composed = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            e=babelHelpers.extends({},e,{B:"b"});
            i.OUT=e
        }),1);"#;
        assert!(resolve_named_enum(composed, "M", "OUT").is_none());

        // A DESTRUCTURED declaration binds its names too, and `get_identifier_name` sees
        // none of them.
        let destructured_var = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(obj){ var {e}=obj; var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(destructured_var, "M", "OUT").is_none());

        // `catch (e)` binds for the handler body — the third form of the same shadow.
        let caught = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            try { risky() } catch(e) { var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(caught, "M", "OUT").is_none());
        // Sanity: the SAME shape without the catch binding must resolve, or the assertion
        // above proves nothing about catch.
        let no_catch = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            try { risky() } catch(q) { var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
        }),1);"#;
        assert_eq!(
            resolve_named_enum(no_catch, "M", "OUT")
                .expect("resolves when catch binds another name")
                .variants
                .len(),
            2
        );

        // A nested `function e(){}` hoists a binding over the enclosing body.
        let fn_name = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function g(){ function e(){} var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(fn_name, "M", "OUT").is_none());

        // ...and hoisting means the declaration may come AFTER the composition that reads
        // the name. A source-ordered check misses exactly this order.
        let hoisted_after = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function g(){ var x=babelHelpers.extends({},e,{B:"b"}); function e(){} i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(hoisted_after, "M", "OUT").is_none());

        // `var` is hoisted over the whole function too, so one written AFTER the
        // composition still binds the operand it reads.
        let var_after = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function g(){ var x=babelHelpers.extends({},e,{B:"b"}); var e={X:"x"}; i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(var_after, "M", "OUT").is_none());

        // ...and a `var` nested in a block is function-scoped all the same.
        let var_in_block = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function g(){ var x=babelHelpers.extends({},e,{B:"b"}); if (c) { var e={X:"x"} } i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(var_in_block, "M", "OUT").is_none());

        // A named function EXPRESSION binds its own name inside its body.
        let self_named = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            var f=function e(){ var x=babelHelpers.extends({},e,{B:"b"}); i.OUT=x };
        }),1);"#;
        assert!(resolve_named_enum(self_named, "M", "OUT").is_none());

        // A destructured shadow is LEXICAL: after the body that binds it, an unrelated
        // outer composition must still resolve.
        let outer_after_destructure = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(obj){ var {e}=obj; return e }
            var l=babelHelpers.extends({},e,{B:"b"});
            i.OUT=l
        }),1);"#;
        assert_eq!(
            resolve_named_enum(outer_after_destructure, "M", "OUT")
                .expect("the outer composition never sees the inner binding")
                .variants
                .len(),
            2
        );

        // A loop HEADER declares too, and `var` there hoists across the function.
        let loop_header = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(xs){ var x=babelHelpers.extends({},e,{B:"b"}); for (var e of xs) {} i.OUT=x }
        }),1);"#;
        assert!(resolve_named_enum(loop_header, "M", "OUT").is_none());

        // A destructuring ASSIGNMENT rebinds without declaring, so no declarator runs.
        let destructure_assign = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            ({e}=obj);
            var x=babelHelpers.extends({},e,{B:"b"});
            i.OUT=x
        }),1);"#;
        assert!(resolve_named_enum(destructure_assign, "M", "OUT").is_none());

        // A name rebound to the SAME body is not ambiguous — refusing it would throw away
        // a resolvable enum for nothing.
        let same = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={A:"a"};
            function f(){var e={A:"a"};return e}
            i.ALIAS=e
        }),1);"#;
        assert_eq!(
            resolve_named_enum(same, "M", "ALIAS")
                .expect("an identical rebinding is still resolvable")
                .variants
                .len(),
            1
        );
    }

    #[test]
    fn a_composition_over_something_unreadable_is_refused() {
        // A partial merge is a CLOSED value set missing members the runtime accepts —
        // worse than recording the loss, so an unresolvable operand refuses the whole.
        let module = r#"__d("M",[],(function(t,n,r,o,a,i){
            var e={all:"all"},l=babelHelpers.extends({},e,computed());
            i.WITH=l
        }),1);"#;
        assert!(resolve_named_enum(module, "M", "WITH").is_none());
    }

    fn run(src: &str) -> Vec<InternalEnumDef> {
        let defs = wa_transform::extract_module_definitions(src);
        extract_enums_from_modules(src, &defs, "1.0").enums
    }

    #[test]
    fn resolve_named_enum_handles_object_literal_and_internal_and_bag() {
        // Plain object-literal export (`var l = {...}; i.Name = l`).
        let obj = r#"__d("M",[],(function(g,r,d,o,e,i,l){ var s={PN:"pn",LID:"lid"}; i.USYNC_ADDRESSING_MODE=s; }),1);"#;
        let r = resolve_named_enum(obj, "M", "USYNC_ADDRESSING_MODE").expect("object-literal");
        assert_eq!(
            r.variants
                .iter()
                .map(|v| v.value.clone())
                .collect::<Vec<_>>(),
            [Scalar::Str("pn".into()), Scalar::Str("lid".into())]
        );
        // `$InternalEnum` export.
        let ie = r#"__d("M",["$InternalEnum"],(function(g,n,d,o,e,i,l){ i.CiphertextType=n("$InternalEnum")({Skmsg:"skmsg",Pkmsg:"pkmsg"}); }),1);"#;
        assert_eq!(
            resolve_named_enum(ie, "M", "CiphertextType")
                .unwrap()
                .variants
                .len(),
            2
        );
        // Named export bag (`i.exports = { Name: <enum> }`).
        let bag = r#"__d("M",["$InternalEnum"],(function(g,n,d,o,e,i,l){ i.exports={Scope:n("$InternalEnum")({A:"a",B:"b"})}; }),1);"#;
        assert_eq!(
            resolve_named_enum(bag, "M", "Scope")
                .unwrap()
                .variants
                .len(),
            2
        );
        // A name that isn't an enum export resolves to nothing.
        assert!(resolve_named_enum(obj, "M", "Nope").is_none());
    }

    #[test]
    fn string_and_int_enums_named_by_export() {
        let src = r#"__d("WAWebChatType",["$InternalEnum"],function(g,r,d,o,e,i,l){
            var t=r("$InternalEnum")({INDIVIDUAL:"individual",GROUP:"group",NEWSLETTER:"newsletter"});
            l.ChatType=t;
            l.Codes=r("$InternalEnum")({A:1,B:2,C:3});
        },1);"#;
        let enums = run(src);
        let chat = enums
            .iter()
            .find(|e| e.name == "ChatType")
            .expect("ChatType");
        assert_eq!(chat.value_kind, EnumValueKind::String);
        assert_eq!(chat.variants.len(), 3);
        assert_eq!(chat.variants[0].name, "INDIVIDUAL");
        assert_eq!(chat.variants[0].value, Scalar::Str("individual".into()));
        let codes = enums.iter().find(|e| e.name == "Codes").expect("Codes");
        assert_eq!(codes.value_kind, EnumValueKind::Int);
        assert_eq!(codes.variants[1].value, Scalar::Int(2));
    }

    #[test]
    fn object_freeze_wire_enum_captured_only_in_allowlisted_module() {
        // `WAWebSendReceiptJobCommon` declares RECEIPT_TYPE via `Object.freeze({…})` (not
        // `$InternalEnum`) and is on the frozen-enum allowlist → captured, alongside its
        // sibling `$InternalEnum` enum in the same module.
        let receipt = r#"__d("WAWebSendReceiptJobCommon",["$InternalEnum"],(function(g,n,d,o,e,i,l){
            var u=Object.freeze({INACTIVE:"inactive",DELIVERY:"delivery",READ:"read",PEER_MSG:"peer_msg"});
            var c=n("$InternalEnum")({ORPHAN:0,NO_CHECKMARK_UX:1});
            l.RECEIPT_TYPE=u;l.ReceiptModeBitPosition=c;
        }),1);"#;
        let enums = run(receipt);
        let rt = enums
            .iter()
            .find(|e| e.name == "RECEIPT_TYPE")
            .expect("RECEIPT_TYPE captured");
        assert_eq!(rt.value_kind, EnumValueKind::String);
        assert_eq!(rt.variants.len(), 4);
        assert_eq!(rt.variants[0].name, "INACTIVE");
        assert_eq!(rt.variants[0].value, Scalar::Str("inactive".into()));
        assert!(enums.iter().any(|e| e.name == "ReceiptModeBitPosition"));

        // A frozen CONSTANT_CASE object in a NON-allowlisted `$InternalEnum` module (here a
        // WASI errno table) is a config map, not a wire enum — the allowlist keeps it out.
        let other = r#"__d("WASISnapshotPreview1",["$InternalEnum"],(function(g,n,d,o,e,i,l){
            var p=Object.freeze({SUCCESS:0,E2BIG:1,EACCESS:2});l.RESULT=p;
        }),1);"#;
        assert!(
            run(other).iter().all(|e| e.name != "RESULT"),
            "frozen config in a non-allowlisted module must not leak into the enum catalog"
        );
    }

    #[test]
    fn default_export_named_by_module_and_mixed_skipped() {
        let src = r#"__d("WAWebNackCode",["$InternalEnum"],function(g,r,d,o,e,i,l){
            e.exports=r("$InternalEnum")({Stale:421,Capped:475});
        },1);
        __d("WAWebMixed",["$InternalEnum"],function(g,r,d,o,e,i,l){
            l.Bad=r("$InternalEnum")({A:1,B:"two"});
        },2);"#;
        let enums = run(src);
        let nack = enums
            .iter()
            .find(|e| e.module == "WAWebNackCode")
            .expect("nack");
        assert_eq!(nack.name, "WAWebNackCode"); // default export → module name
        assert_eq!(nack.variants[0].value, Scalar::Int(421));
        // Mixed-value enum is skipped entirely.
        assert!(enums.iter().all(|e| e.module != "WAWebMixed"));
    }

    #[test]
    fn module_without_dep_is_ignored() {
        // Contains the call text but doesn't declare the dep → not scanned.
        let src = r#"__d("Nope",[],function(g,r,d,o,e,i,l){ l.X=r("$InternalEnum")({A:1}); },1);"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn plain_object_wire_enums_captured_only_from_protocol_modules() {
        // WA's ack/receipt level enums and smax `*Enums` bags are plain object literals
        // with no `$InternalEnum` dep — captured via the protocol-module convention.
        let src = r#"
            __d("WAWebAck",[],(function(t,n,r,o,a,i){var e={INACTIVE:-6,SENT:1,READ:3};i.ACK=e}),1);
            __d("WASmaxInReceiptEnums",["WAJids"],(function(t,n,r,o,a,i,l){var e={CBP:"cbp",NBP:"nbp"};i.ENUM_CBP_NBP=e}),1);
        "#;
        let enums = run(src);
        let ack = enums
            .iter()
            .find(|e| e.module == "WAWebAck")
            .expect("WAWebAck.ACK");
        assert_eq!(ack.name, "ACK");
        assert_eq!(ack.value_kind, EnumValueKind::Int);
        assert_eq!(ack.variants.len(), 3);
        assert!(
            enums
                .iter()
                .any(|e| e.module == "WASmaxInReceiptEnums" && e.name == "ENUM_CBP_NBP")
        );
    }

    #[test]
    fn plain_object_non_protocol_and_camelcase_are_not_enums() {
        // Same plain-object shape, but a non-protocol infra module → not scanned
        // (would otherwise flood the catalog with loggers/locales/UI constants).
        let infra = r#"__d("WAWebLog",[],(function(t,n,r,o,a,i){var e={DEBUG:0,INFO:1,ERROR:2};i.Level=e}),1);"#;
        assert!(run(infra).iter().all(|e| e.module != "WAWebLog"));
        // A protocol module, but a `camelCase`-keyed (non-enum) map is still rejected by
        // the CONSTANT_CASE guard.
        let cfg = r#"__d("WASmaxInFooEnums",[],(function(t,n,r,o,a,i){var e={maxRetries:3,timeoutMs:5};i.config=e}),1);"#;
        assert!(run(cfg).iter().all(|e| e.module != "WASmaxInFooEnums"));
        // A protocol module whose plain-object export mixes int and string values is
        // rejected (single value-kind), mirroring the `$InternalEnum` mixed-skip path.
        let mixed = r#"__d("WASmaxInBarEnums",[],(function(t,n,r,o,a,i){var e={A:1,B:"two"};i.MIXED=e}),1);"#;
        assert!(run(mixed).iter().all(|e| e.module != "WASmaxInBarEnums"));
    }
}
