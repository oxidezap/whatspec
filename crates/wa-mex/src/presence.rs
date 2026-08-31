//! Whether the official client always puts a variable key on the wire.
//!
//! `variablesShape` says what type each variable has. It said nothing about
//! presence, and a persisted operation's compiled tree references its variables
//! unconditionally: omitting one the client never omits is a validation failure
//! the server answers with a bare `400`. The evidence is in the same expression
//! the shape pass already walks - WA Web's own call site - so this reads it
//! there instead of leaving a consumer to guess from a field name.
//!
//! Structural over the `oxc` AST: presence turns on the *form* of the value
//! expression (`x === !0` cannot evaluate to `undefined`, `t.x` can), and a scan
//! that cannot tell a comparison from a property read cannot answer the question
//! at all.
//!
//! The unit is the key as `JSON.stringify` leaves it. WA serializes the
//! variables object, and serialization drops a key whose value is `undefined`,
//! so "the key is written" and "the key reaches the server" are one question
//! asked of the value.

use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentExpression, CallExpression, Expression,
    LogicalOperator, ObjectExpression, ObjectPropertyKind, PropertyKey, UnaryOperator,
    VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{VariablePresence, VariablePresenceNode};

use crate::PresenceDiagnostics;

/// The Relay runtime entry points a persisted operation is sent through. The
/// same three the shape pass scans for, so both passes read the same call sites.
const FETCH_METHODS: &[&str] = &["fetchQuery", "commitMutation", "fetchSubscription"];

/// How far an expression is converted and how far a binding chain is followed.
/// Deep enough for the chains WA's minifier produces (`d` → the object literal,
/// `c` → `u !== "INVITE"` → the ternary behind `u`) and finite in the presence of
/// a self-referential binding (`var e = e || {}`).
const MAX_DEPTH: usize = 12;

/// A value expression, kept only as far as presence depends on it.
///
/// Owned rather than borrowed because oxc's visitor hands out node references
/// that do not outlive the callback, and the classification has to survive until
/// the binding it names is resolved. Every arm is a fact about evaluation rather
/// than about syntax: whether the expression can be `undefined`, and what keys it
/// carries if it is an object.
#[derive(Debug, Clone)]
enum Value {
    /// No evaluation yields `undefined`: a literal, a comparison, a coercion, a
    /// function, a `new`.
    Defined,
    /// Can yield `undefined`: a property read, an optional chain, `void x`, a
    /// binding this module does not write.
    MaybeUndefined,
    /// A form this pass does not judge - a call's return value, an `await`.
    Unjudged,
    /// An identifier, resolved against the enclosing bindings when read.
    Ref(String),
    Object(Vec<Prop>),
    Array(Vec<Value>),
    /// `a ?? b` / `a || b`: the result is `a` only when `a` is non-nullish /
    /// truthy, so it is defined exactly when `b` is.
    OrElse(Box<Value>),
    /// `a && b`: can yield a falsy `a`, `undefined` included.
    AndThen(Box<Value>, Box<Value>),
    /// `c ? a : b`.
    Either(Box<Value>, Box<Value>),
    /// A call, with the module name when it takes a single string literal -
    /// which is how a Relay operation handle is written, `n("X.graphql")`.
    Call(Option<String>, Vec<Value>),
}

#[derive(Debug, Clone)]
enum Prop {
    Key(String, Value),
    Spread(Value),
    /// A computed key: it names no variable that could be published.
    Unreadable,
}

/// What an expression can evaluate to, as far as the AST establishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Definedness {
    /// No evaluation yields `undefined`.
    Defined,
    /// Can yield `undefined`, so the key can leave the wire.
    MaybeUndefined,
    /// A form this pass does not judge.
    Unjudged,
}

impl Definedness {
    fn presence(self) -> VariablePresence {
        match self {
            Definedness::Defined => VariablePresence::Always,
            Definedness::MaybeUndefined => VariablePresence::Conditional,
            Definedness::Unjudged => VariablePresence::Undetermined,
        }
    }
}

/// Local bindings, innermost frame last.
///
/// The minifier reuses one-letter names across sibling functions, so a flat
/// module-wide table would resolve `t` in one function against another's
/// binding. Frames are pushed and popped with the function nodes themselves,
/// which is the only boundary that makes a name mean one thing.
#[derive(Default)]
struct Scopes {
    frames: Vec<HashMap<String, Value>>,
}

impl Scopes {
    fn push(&mut self) {
        self.frames.push(HashMap::new());
    }
    fn pop(&mut self) {
        self.frames.pop();
    }
    fn bind(&mut self, name: &str, value: Value) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(name.to_string(), value);
        }
    }
    fn lookup(&self, name: &str) -> Option<&Value> {
        self.frames.iter().rev().find_map(|f| f.get(name))
    }
    /// Follow an identifier to what it is bound to.
    fn resolve<'v>(&'v self, value: &'v Value, depth: usize) -> &'v Value {
        match value {
            Value::Ref(name) if depth < MAX_DEPTH => match self.lookup(name) {
                Some(bound) => self.resolve(bound, depth + 1),
                None => value,
            },
            _ => value,
        }
    }
}

// ─── expression → value ──────────────────────────────────────────────────────

fn convert(expr: &Expression, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return Value::Unjudged;
    }
    let next = depth + 1;
    match expr {
        Expression::ObjectExpression(o) => Value::Object(convert_props(o, next)),
        Expression::ArrayExpression(a) => Value::Array(
            a.elements
                .iter()
                .map(|el| match el {
                    ArrayExpressionElement::SpreadElement(_) => Value::Unjudged,
                    ArrayExpressionElement::Elision(_) => Value::MaybeUndefined,
                    other => other
                        .as_expression()
                        .map(|e| convert(e, next))
                        .unwrap_or(Value::Unjudged),
                })
                .collect(),
        ),

        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_)
        // `new X()` evaluates to an object, never to `undefined`.
        | Expression::NewExpression(_)
        // Every binary operator (`===`, `!==`, `<`, `+`, `in`, `instanceof`, …)
        // yields a primitive. This is the arm that classifies WA's `x === !0`
        // coercion, which is the whole finding.
        | Expression::BinaryExpression(_) => Value::Defined,

        // `!x`, `!!x`, `typeof x`, `-x` yield primitives; `void x` IS `undefined`,
        // so it is the one unary that does not.
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::Void => Value::MaybeUndefined,
            _ => Value::Defined,
        },

        Expression::LogicalExpression(l) => match l.operator {
            LogicalOperator::Coalesce | LogicalOperator::Or => {
                Value::OrElse(Box::new(convert(&l.right, next)))
            }
            LogicalOperator::And => Value::AndThen(
                Box::new(convert(&l.left, next)),
                Box::new(convert(&l.right, next)),
            ),
        },

        // `t == null ? void 0 : t.x` is how the minifier writes an optional
        // chain, and its `void 0` arm is what makes that form conditional.
        Expression::ConditionalExpression(c) => Value::Either(
            Box::new(convert(&c.consequent, next)),
            Box::new(convert(&c.alternate, next)),
        ),

        Expression::SequenceExpression(s) => match s.expressions.last() {
            Some(last) => convert(last, next),
            None => Value::Unjudged,
        },
        Expression::ParenthesizedExpression(p) => convert(&p.expression, next),
        Expression::AssignmentExpression(a) => convert(&a.right, next),

        // A property read yields `undefined` for any key the object lacks, and an
        // optional chain yields it for a nullish base. Both are the plain
        // passthrough WA writes when a caller's options object supplies the value.
        Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::PrivateFieldExpression(_)
        | Expression::ChainExpression(_) => Value::MaybeUndefined,

        Expression::Identifier(id) => {
            if id.name.as_str() == "undefined" {
                Value::MaybeUndefined
            } else {
                Value::Ref(id.name.as_str().to_string())
            }
        }

        Expression::CallExpression(c) => Value::Call(
            wa_oxc::first_string_arg(c).map(str::to_string),
            c.arguments
                .iter()
                .filter_map(Argument::as_expression)
                .map(|a| convert(a, next))
                .collect(),
        ),

        _ => Value::Unjudged,
    }
}

fn convert_props(obj: &ObjectExpression, depth: usize) -> Vec<Prop> {
    obj.properties
        .iter()
        .map(|p| match p {
            ObjectPropertyKind::ObjectProperty(p) => match static_key(&p.key) {
                Some(key) => Prop::Key(key, convert(&p.value, depth)),
                None => Prop::Unreadable,
            },
            ObjectPropertyKind::SpreadProperty(s) => Prop::Spread(convert(&s.argument, depth)),
        })
        .collect()
}

fn static_key(key: &PropertyKey) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.as_str().to_string()),
        _ => None,
    }
}

// ─── classification ──────────────────────────────────────────────────────────

/// Whether a value can evaluate to `undefined`.
///
/// The three verdicts are the three presence states, so every judgement about a
/// key is made here once, from JS's own evaluation rules rather than from what
/// the key is called.
fn definedness(value: &Value, scopes: &Scopes, depth: usize) -> Definedness {
    if depth >= MAX_DEPTH {
        return Definedness::Unjudged;
    }
    let next = depth + 1;
    match value {
        Value::Defined | Value::Object(_) | Value::Array(_) => Definedness::Defined,
        Value::MaybeUndefined => Definedness::MaybeUndefined,
        Value::Unjudged | Value::Call(..) => Definedness::Unjudged,
        Value::OrElse(rhs) => definedness(rhs, scopes, next),
        Value::AndThen(lhs, rhs) => {
            definedness(lhs, scopes, next).max(definedness(rhs, scopes, next))
        }
        Value::Either(a, b) => definedness(a, scopes, next).max(definedness(b, scopes, next)),
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => definedness(bound, scopes, next),
            // A binding from outside this module's bodies - a parameter, an
            // import. It is a passthrough, and a passthrough can be `undefined`.
            None => Definedness::MaybeUndefined,
        },
    }
}

/// One call site's answer for the whole variables object.
type SiteTree = BTreeMap<String, VariablePresenceNode>;

/// Classify every key of a variables object.
fn classify_object(
    props: &[Prop],
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
) -> SiteTree {
    let mut out: SiteTree = BTreeMap::new();
    for prop in props {
        match prop {
            Prop::Unreadable => diag.unreadable_keys += 1,
            Prop::Key(key, value) => {
                let node = classify_value(value, scopes, diag, depth, VariablePresence::Always);
                insert_weaker(&mut out, key.clone(), node);
            }
            Prop::Spread(source) => {
                // `...(cond ? {a: 1} : {})` and `...(cond && {a: 1})` are how WA
                // adds a key only under a gate: the keys are real and every one
                // of them is conditional. An ungated spread of a literal passes
                // its keys through unchanged.
                let (source, gated) = spread_source(source, scopes);
                let floor = if gated {
                    VariablePresence::Conditional
                } else {
                    VariablePresence::Always
                };
                match scopes.resolve(source, 0) {
                    Value::Object(inner) => {
                        for (k, mut node) in classify_object(inner, scopes, diag, depth) {
                            node.presence = node.presence.weaker(floor);
                            insert_weaker(&mut out, k, node);
                        }
                    }
                    // A spread whose keys cannot be enumerated: it may carry
                    // variables that would otherwise read as written by nobody,
                    // so it is counted rather than passed over.
                    _ => diag.unreadable_spreads += 1,
                }
            }
        }
    }
    out
}

/// The object a spread copies from, and whether a condition gates it.
fn spread_source<'v>(value: &'v Value, scopes: &'v Scopes) -> (&'v Value, bool) {
    match scopes.resolve(value, 0) {
        Value::AndThen(_, rhs) => (rhs, true),
        Value::Either(a, b) => {
            let carries =
                |v: &Value| matches!(scopes.resolve(v, 0), Value::Object(p) if !p.is_empty());
            match (carries(a), carries(b)) {
                (true, false) => (a, true),
                (false, true) => (b, true),
                // Both arms carry keys, or neither does: nothing to single out,
                // so the caller counts it as unreadable.
                _ => (value, true),
            }
        }
        other => (other, false),
    }
}

/// Classify one property value, descending through object and array literals so
/// a nested key is answered too.
fn classify_value(
    value: &Value,
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
    floor: VariablePresence,
) -> VariablePresenceNode {
    let presence = definedness(value, scopes, 0).presence().weaker(floor);
    let mut node = VariablePresenceNode::leaf(presence);
    if depth >= MAX_DEPTH {
        return node;
    }
    match scopes.resolve(value, 0) {
        Value::Object(props) => {
            node.fields = classify_object(props, scopes, diag, depth + 1);
        }
        Value::Array(items) => {
            // A list's element is not a key, so it gets no verdict of its own; it
            // exists to carry the element's keys, which are.
            if let Some(Value::Object(props)) = items.first().map(|v| scopes.resolve(v, 0)) {
                let mut item = VariablePresenceNode::leaf(VariablePresence::Always);
                item.fields = classify_object(props, scopes, diag, depth + 1);
                node.items = Some(Box::new(item));
            }
        }
        _ => {}
    }
    node
}

fn insert_weaker(out: &mut SiteTree, key: String, node: VariablePresenceNode) {
    match out.remove(&key) {
        Some(existing) => out.insert(key, merge_nodes(existing, node)),
        None => out.insert(key, node),
    };
}

/// Merge two verdicts about one key, keeping the weaker claim and the union of
/// the nested keys.
fn merge_nodes(a: VariablePresenceNode, b: VariablePresenceNode) -> VariablePresenceNode {
    let mut fields = a.fields;
    for (k, v) in b.fields {
        match fields.remove(&k) {
            Some(existing) => fields.insert(k, merge_nodes(existing, v)),
            None => fields.insert(k, v),
        };
    }
    let items = match (a.items, b.items) {
        (Some(x), Some(y)) => Some(Box::new(merge_nodes(*x, *y))),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    };
    VariablePresenceNode {
        presence: a.presence.weaker(b.presence),
        fields,
        items,
    }
}

/// Merge two call sites' answers.
///
/// A key one site writes and the other does not is a key the client can leave
/// off, so the absence is a verdict rather than a gap - which is what lets a
/// second call site weaken the first.
fn merge_sites(mut a: SiteTree, mut b: SiteTree) -> SiteTree {
    let keys: Vec<String> = a.keys().chain(b.keys()).cloned().collect();
    let mut out = SiteTree::new();
    for key in keys {
        let node = match (a.remove(&key), b.remove(&key)) {
            (Some(l), Some(r)) => merge_nodes(l, r),
            (Some(mut n), None) | (None, Some(mut n)) => {
                n.presence = n.presence.weaker(VariablePresence::Conditional);
                n
            }
            (None, None) => continue,
        };
        out.insert(key, node);
    }
    out
}

/// Whether a value is (or reaches) a `require`-style call naming `module`.
///
/// The handle a Relay call is given is `n("X.graphql")`, usually behind the
/// minifier's memoising ternary, so the check looks through the expression
/// rather than at its outermost node.
fn references_module(value: &Value, module: &str, scopes: &Scopes, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let next = depth + 1;
    match value {
        Value::Call(name, args) => {
            name.as_deref() == Some(module)
                || args
                    .iter()
                    .any(|a| references_module(a, module, scopes, next))
        }
        Value::Either(a, b) | Value::AndThen(a, b) => {
            references_module(a, module, scopes, next) || references_module(b, module, scopes, next)
        }
        Value::OrElse(rhs) => references_module(rhs, module, scopes, next),
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => references_module(bound, module, scopes, next),
            None => false,
        },
        _ => false,
    }
}

// ─── the caller-module scan ──────────────────────────────────────────────────

/// Collects the variables object of every Relay call in a caller module that
/// sends this operation.
struct CallSiteCollector<'d> {
    /// The `<name>.graphql` module whose call sites we want.
    module: String,
    /// Whether the caller depends on exactly one `.graphql` module, in which case
    /// a call whose handle argument cannot be tied to a module can only be this
    /// one.
    sole_operation: bool,
    scopes: Scopes,
    sites: Vec<SiteTree>,
    diag: &'d mut PresenceDiagnostics,
}

impl<'a> Visit<'a> for CallSiteCollector<'_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        self.scopes.push();
        walk::walk_program(self, program);
        self.scopes.pop();
    }

    fn visit_function(
        &mut self,
        func: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        self.scopes.push();
        self.bind_params(&func.params);
        walk::walk_function(self, func, flags);
        self.scopes.pop();
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.scopes.push();
        self.bind_params(&func.params);
        walk::walk_arrow_function_expression(self, func);
        self.scopes.pop();
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(name) = d.id.get_identifier_name()
            && let Some(init) = d.init.as_ref()
        {
            let value = convert(init, 0);
            self.scopes.bind(name.as_str(), value);
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        // The memoised require is written `e !== void 0 ? e : e = n("X.graphql")`,
        // so the binding for the operation handle exists only as an assignment.
        if let Some(name) = wa_oxc::assignment_target_name(&n.left) {
            let value = convert(&n.right, 0);
            self.scopes.bind(name, value);
        }
        walk::walk_assignment_expression(self, n);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.is_operation_call(call)
            && let Some(vars) = call.arguments.get(1).and_then(Argument::as_expression)
        {
            let value = convert(vars, 0);
            match self.variables_object(&value) {
                Some(tree) => self.sites.push(tree),
                None => self.diag.unreadable_call_arguments += 1,
            }
        }
        walk::walk_call_expression(self, call);
    }
}

impl CallSiteCollector<'_> {
    /// Bind a function's parameters, so a name the caller passes in resolves to a
    /// passthrough rather than to whatever the enclosing module bound it to.
    ///
    /// The minifier reuses one letter for both - `WAWebMexFetchNewsletterAdminInfoJob`
    /// memoises its operation handle into a module-level `e` and names the job
    /// function's parameter `e` too - so without this the inner `e` resolves to the
    /// outer `require` call and a plain passthrough reads as unjudged.
    fn bind_params(&mut self, params: &oxc_ast::ast::FormalParameters) {
        // Destructured and rest parameters bind no single name and are left
        // alone: an unbound name already resolves to `MaybeUndefined`, so the
        // verdict is the same one binding them would give.
        for item in &params.items {
            if let Some(name) = item.pattern.get_identifier_name() {
                self.scopes.bind(&name, Value::MaybeUndefined);
            }
        }
    }

    /// Whether this call sends *this* operation: its handle argument resolves to
    /// a `require("<module>")`, or the caller has only one operation to send and
    /// so cannot be sending another.
    fn is_operation_call(&self, call: &CallExpression) -> bool {
        let Some(method) = wa_oxc::callee_method(call) else {
            return false;
        };
        if !FETCH_METHODS.contains(&method) {
            return false;
        }
        let Some(first) = call.arguments.first().and_then(Argument::as_expression) else {
            return false;
        };
        references_module(&convert(first, 0), &self.module, &self.scopes, 0) || self.sole_operation
    }

    /// The variables object of a matched call, if the argument is one or resolves
    /// to one.
    fn variables_object(&mut self, value: &Value) -> Option<SiteTree> {
        match self.scopes.resolve(value, 0) {
            Value::Object(props) => Some(classify_object(props, &self.scopes, self.diag, 0)),
            // `cond ? {…} : {…}` picks one object per call, so a key only one arm
            // writes is one the client can omit - which `merge_sites` says.
            Value::Either(a, b) => {
                // Cloned out of the borrow: `branch_object` needs `&mut self` for
                // the diagnostics, and the arms are shallow by construction.
                let (a, b) = (a.as_ref().clone(), b.as_ref().clone());
                let left = self.branch_object(&a);
                let right = self.branch_object(&b);
                match (left, right) {
                    (Some(l), Some(r)) => Some(merge_sites(l, r)),
                    (Some(x), None) | (None, Some(x)) => Some(x),
                    (None, None) => None,
                }
            }
            _ => None,
        }
    }

    fn branch_object(&mut self, value: &Value) -> Option<SiteTree> {
        match self.scopes.resolve(value, 0) {
            Value::Object(props) => Some(classify_object(props, &self.scopes, self.diag, 0)),
            _ => None,
        }
    }
}

/// Presence for every declared variable of one operation.
///
/// `callers` is every module that depends on the operation, each with whether it
/// is that module's only operation. All of them, because `always` means "no
/// recovered call site contradicts this": a second job module sending the same
/// operation is evidence, and reading only the first would let an unconditional
/// claim stand on a partial view.
///
/// `arg_def_names` is authoritative for which keys exist - the same list
/// `variables_shape` is filtered by - so a key a call site writes that the
/// operation does not declare is not published, and a declared key no site
/// writes is answered rather than omitted.
pub(crate) fn variables_presence(
    callers: &[(&str, bool)],
    module: &str,
    arg_def_names: &[String],
    diag: &mut PresenceDiagnostics,
) -> BTreeMap<String, VariablePresenceNode> {
    if arg_def_names.is_empty() {
        return BTreeMap::new();
    }
    let mut merged: Option<SiteTree> = None;
    for (src, sole_operation) in callers {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, src);
        let mut collector = CallSiteCollector {
            module: module.to_string(),
            sole_operation: *sole_operation,
            scopes: Scopes::default(),
            sites: Vec::new(),
            diag,
        };
        collector.visit_program(&ret.program);
        // Every recovered site has to agree for a key to be `always`, so the sites
        // are folded rather than picked from - across callers as well as within one.
        for site in collector.sites {
            merged = Some(match merged {
                Some(acc) => merge_sites(acc, site),
                None => site,
            });
        }
    }

    let Some(mut merged) = merged else {
        diag.operations_without_call_site += 1;
        return arg_def_names
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    VariablePresenceNode::leaf(VariablePresence::Undetermined),
                )
            })
            .collect();
    };

    arg_def_names
        .iter()
        .map(|name| {
            let node = merged.remove(name).unwrap_or_else(|| {
                // Declared by the operation and written by no recovered site: the
                // client does not send it, which is a form of "not always".
                VariablePresenceNode::leaf(VariablePresence::Conditional)
            });
            (name.clone(), node)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "WAWebFooQuery.graphql";

    /// Classify a caller body against one operation module, as the extractor does.
    fn presence_of(
        caller: &str,
        vars: &[&str],
    ) -> (BTreeMap<String, VariablePresenceNode>, PresenceDiagnostics) {
        let names: Vec<String> = vars.iter().map(|s| s.to_string()).collect();
        let mut diag = PresenceDiagnostics::default();
        let out = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        (out, diag)
    }

    fn at(tree: &BTreeMap<String, VariablePresenceNode>, key: &str) -> VariablePresence {
        tree.get(key)
            .unwrap_or_else(|| panic!("{key} missing from {tree:?}"))
            .presence
    }

    #[test]
    fn boolean_coercion_is_always_sent() {
        // The exact form of WAWebMexFetchAllNewslettersMetadataJob: an optional
        // chain coerced with `=== !0`, which cannot evaluate to `undefined`.
        let caller = r#"function f(t){return o("WAWebMexClient").fetchQuery(n("WAWebFooQuery.graphql"),{fetch_wamo_sub:(t==null?void 0:t.fetchWamoSub)===!0,fetch_status_metadata:!!(t==null?void 0:t.fetchStatusMetadata)})}"#;
        let (tree, _) = presence_of(caller, &["fetch_wamo_sub", "fetch_status_metadata"]);
        assert_eq!(at(&tree, "fetch_wamo_sub"), VariablePresence::Always);
        assert_eq!(at(&tree, "fetch_status_metadata"), VariablePresence::Always);
    }

    #[test]
    fn coalescing_takes_the_right_hand_side() {
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:t.x??!1,b:t.y??t.z,c:t.w||"d"})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Always,
            "?? with a literal"
        );
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "?? whose right side can itself be undefined"
        );
        assert_eq!(
            at(&tree, "c"),
            VariablePresence::Always,
            "|| with a literal"
        );
    }

    #[test]
    fn literals_and_locals_resolving_to_literals_are_always_sent() {
        // `type: u` where `u` is a ternary of two string literals, and `full: c`
        // where `c` is a comparison - both from WAWebMexFetchNewsletterJob.
        let caller = r#"function f(t){var u=r("W").isNewsletter(t)?"JID":"INVITE",c=u!=="INVITE",d={type:u,full:c,fixed:"x"};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),d)}"#;
        let (tree, _) = presence_of(caller, &["type", "full", "fixed"]);
        assert_eq!(at(&tree, "type"), VariablePresence::Always);
        assert_eq!(at(&tree, "full"), VariablePresence::Always);
        assert_eq!(at(&tree, "fixed"), VariablePresence::Always);
    }

    #[test]
    fn passthrough_of_a_possibly_undefined_value_is_conditional() {
        let caller = r#"function f(t,i){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:i.fetchViewerMetadata,b:t,c:i==null?void 0:i.k})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Conditional,
            "property read"
        );
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "bare binding"
        );
        assert_eq!(
            at(&tree, "c"),
            VariablePresence::Conditional,
            "lowered optional chain"
        );
    }

    #[test]
    fn conditional_spread_marks_its_keys_conditional() {
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,...(t.gate?{b:!0}:{}),...(t.other&&{c:!1})})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "ternary spread"
        );
        assert_eq!(at(&tree, "c"), VariablePresence::Conditional, "&& spread");
    }

    #[test]
    fn an_ungated_spread_passes_its_keys_through() {
        let caller = r#"function f(t){var e={a:!0,b:t.x};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{...e,c:!1})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(at(&tree, "b"), VariablePresence::Conditional);
        assert_eq!(at(&tree, "c"), VariablePresence::Always);
    }

    #[test]
    fn unclassifiable_expression_is_undetermined_not_optional() {
        // A gate read through a function call: the key is written unconditionally
        // and the value could be anything, so nothing about presence is
        // established - and "undetermined" must not decay into "conditional",
        // which a consumer would read as licence to omit the key.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{fetch_pinned_messages:o("G").isChannelMessagePinReadEnabled(),plain:!0})}"#;
        let (tree, diag) = presence_of(caller, &["fetch_pinned_messages", "plain"]);
        assert_eq!(
            at(&tree, "fetch_pinned_messages"),
            VariablePresence::Undetermined
        );
        assert_ne!(
            at(&tree, "fetch_pinned_messages"),
            VariablePresence::Conditional,
            "an unread expression is not evidence that the client omits the key"
        );
        assert_eq!(at(&tree, "plain"), VariablePresence::Always);
        assert_eq!(diag.operations_without_call_site, 0);
    }

    #[test]
    fn nested_object_keys_get_their_own_verdict() {
        let caller = r#"function f(t,a){var u="JID";return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{key:t,type:u,view_role:a}})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let input = tree.get("input").unwrap();
        assert_eq!(
            input.presence,
            VariablePresence::Always,
            "the literal itself"
        );
        assert_eq!(input.fields["type"].presence, VariablePresence::Always);
        assert_eq!(input.fields["key"].presence, VariablePresence::Conditional);
        assert_eq!(
            input.fields["view_role"].presence,
            VariablePresence::Conditional
        );
    }

    #[test]
    fn list_element_keys_are_classified_under_items() {
        let caller = r#"function f(t){return o("C").commitMutation(n("WAWebFooQuery.graphql"),{input:[{id:t.id,fixed:!0}]})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let item = tree["input"].items.as_ref().expect("list element node");
        assert_eq!(item.fields["fixed"].presence, VariablePresence::Always);
        assert_eq!(item.fields["id"].presence, VariablePresence::Conditional);
    }

    #[test]
    fn a_key_only_one_site_writes_is_conditional() {
        let caller = r#"function f(t){if(t)return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,b:!0});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!1})}"#;
        let (tree, _) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always, "written by both");
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "one site only"
        );
    }

    #[test]
    fn a_call_for_another_operation_is_not_this_operations_site() {
        // Two operations sent from one module: matching on the method name alone
        // would let the other call's object decide this one's presence.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebOtherQuery.graphql"),{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_declared_variable_no_site_writes_is_conditional() {
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let (tree, _) = presence_of(caller, &["a", "unwritten"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(at(&tree, "unwritten"), VariablePresence::Conditional);
    }

    #[test]
    fn a_second_caller_module_can_weaken_the_first() {
        // Two job modules sending one operation. Reading only the first would
        // publish `b` as `always` on a partial view, and `always` is the verdict a
        // consumer turns into a non-optional field.
        let first =
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,b:!0})}"#;
        let second = r#"function g(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!1})}"#;
        let names = vec!["a".to_string(), "b".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(
            &[(first, false), (second, false)],
            MODULE,
            &names,
            &mut diag,
        );
        assert_eq!(at(&tree, "a"), VariablePresence::Always, "written by both");
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "the second caller does not write it"
        );
        assert_eq!(diag.operations_without_call_site, 0);
    }

    #[test]
    fn a_caller_with_no_site_does_not_hide_another_callers_evidence() {
        // A dependent module that sends nothing is not a site, so it must neither
        // weaken the verdict nor count as "no call site".
        let quiet = "function f(){return 1}";
        let live = r#"function g(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(quiet, false), (live, false)], MODULE, &names, &mut diag);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(diag.operations_without_call_site, 0);
    }

    #[test]
    fn no_call_site_is_undetermined_and_counted() {
        let (tree, diag) = presence_of("function f(){return 1}", &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.operations_without_call_site, 1);
    }

    #[test]
    fn an_unreadable_spread_is_counted_rather_than_passed_over() {
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,...t.extra})}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(diag.unreadable_spreads, 1);
    }

    #[test]
    fn a_binding_that_refers_to_itself_terminates() {
        let caller = r#"function f(){var e=e||{};var d={a:e};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),d)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        // The verdict is not the point; terminating is.
        assert!(tree.contains_key("a"));
    }
}
