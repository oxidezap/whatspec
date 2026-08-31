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
    Argument, ArrayExpressionElement, AssignmentExpression, AssignmentOperator, CallExpression,
    Expression, LogicalOperator, ObjectExpression, ObjectPropertyKind, PropertyKey, UnaryOperator,
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
    /// Bindings the module declares at its own top level, collected before the
    /// walk. A closure resolves its free names when it RUNS, not where it sits,
    /// so `function f(){ …{a: x}… } var x = !0;` uses the defined `x`; walking in
    /// source order alone would classify `a` against a name not yet seen.
    ///
    /// Consulted only after the frames, so a real binding still wins and a later
    /// assignment still joins the prior one rather than replacing it - the rule
    /// that keeps a conditional rebinding conservative.
    hoisted: HashMap<String, Value>,
}

impl Scopes {
    fn push(&mut self) {
        self.frames.push(HashMap::new());
    }
    fn pop(&mut self) {
        self.frames.pop();
    }
    /// Bind a name, keeping any binding already in this frame beside the new one.
    ///
    /// The scan walks the AST in source order and has no control flow, so
    /// `var v = {}; if (flag) v = {a: !0}; fetchQuery(op, v)` would otherwise
    /// leave `v` at the conditional assignment and call `a` unconditional. Two
    /// bindings for one name are two values that may reach the call, which is
    /// what `Either` already means everywhere else in this pass.
    fn bind(&mut self, name: &str, value: Value) {
        if let Some(frame) = self.frames.last_mut() {
            match frame.remove(name) {
                Some(prior) => frame.insert(
                    name.to_string(),
                    Value::Either(Box::new(prior), Box::new(value)),
                ),
                None => frame.insert(name.to_string(), value),
            };
        }
    }
    fn lookup(&self, name: &str) -> Option<&Value> {
        self.frames
            .iter()
            .rev()
            .find_map(|f| f.get(name))
            .or_else(|| self.hoisted.get(name))
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
        // `new X()` evaluates to an object, never to `undefined`.
        | Expression::NewExpression(_)
        // Every binary operator (`===`, `!==`, `<`, `+`, `in`, `instanceof`, …)
        // yields a primitive. This is the arm that classifies WA's `x === !0`
        // coercion, which is the whole finding.
        | Expression::BinaryExpression(_) => Value::Defined,

        // A defined value is not the same as a value that survives the wire.
        // `JSON.stringify` drops a property whose value is a function, so
        // `{a: () => !0}` serializes to `{}` and the key is never sent. Being
        // defined is the test for `undefined`, not proof the key arrives.
        Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_) => Value::MaybeUndefined,

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
        // A logical assignment can yield the LEFT side without ever evaluating
        // the right: `x &&= !0` is `undefined` when `x` is. Only a plain `=`
        // (or an arithmetic compound, which yields a primitive) is its right side.
        Expression::AssignmentExpression(a) => match a.operator {
            AssignmentOperator::LogicalAnd => Value::AndThen(
                Box::new(Value::MaybeUndefined),
                Box::new(convert(&a.right, next)),
            ),
            AssignmentOperator::LogicalOr | AssignmentOperator::LogicalNullish => {
                Value::OrElse(Box::new(convert(&a.right, next)))
            }
            // A plain `=` evaluates to its right side. An arithmetic or bitwise
            // compound assignment evaluates to the computed primitive instead,
            // which is defined whatever the operand was - `x += y` is a number
            // or a string even when `y` is `undefined` (`NaN` serializes as
            // `null`, with the key still there).
            AssignmentOperator::Assign => convert(&a.right, next),
            _ => Value::Defined,
        },

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
///
/// In source order, because JS object construction is ordered: a spread
/// overwrites the keys written before it and is overwritten by the keys written
/// after. That is what makes a spread this pass cannot enumerate destructive
/// rather than merely missing.
fn classify_object(
    props: &[Prop],
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
) -> SiteTree {
    classify_object_reporting(props, scopes, diag, depth).0
}

/// [`classify_object`], plus whether a spread this level could not enumerate may
/// still be carrying keys into it.
fn classify_object_reporting(
    props: &[Prop],
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
) -> (SiteTree, bool) {
    let mut opaque = false;
    let mut out: SiteTree = BTreeMap::new();
    // A spread whose source resolves back through itself (`var e = {...e}`)
    // would otherwise descend forever, and an extractor that aborts publishes
    // nothing at all.
    if depth >= MAX_DEPTH {
        diag.unreadable_spreads += 1;
        return (out, true);
    }
    for prop in props {
        match prop {
            Prop::Unreadable => {
                // A computed key names something this pass cannot read, and that
                // something may be a key already written: `{a: !0, [k]: void 0}`
                // drops `a` when `k` is `"a"`. Same rule as an unreadable spread,
                // and a later explicit write still restores the key.
                diag.unreadable_keys += 1;
                opaque = true;
                for node in out.values_mut() {
                    withdraw(node);
                }
            }
            Prop::Key(key, value) => {
                // Replaces rather than merges: within one literal the last write
                // to a key IS the value, so `{...base, a: !0}` is `a: !0` however
                // `base` wrote it. Merging here would publish a key the client
                // always sends as omissible, which is the defect this whole
                // dimension exists to remove, only pointing the other way.
                let node = classify_value(value, scopes, diag, depth, VariablePresence::Always);
                out.insert(key.clone(), node);
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
                        for (k, mut node) in classify_object(inner, scopes, diag, depth + 1) {
                            node.presence = node.presence.weaker(floor);
                            // A later spread overwrites the keys it carries, the
                            // same order rule the explicit keys follow.
                            out.insert(k, node);
                        }
                    }
                    // A spread whose keys cannot be enumerated writes an unknown
                    // set of them, `undefined` included, over everything already
                    // written. So it does not merely fail to add keys: it
                    // withdraws what was established before it, which is the one
                    // way an unread expression could otherwise leave an `always`
                    // standing that the client contradicts.
                    _ => {
                        diag.unreadable_spreads += 1;
                        opaque = true;
                        for node in out.values_mut() {
                            withdraw(node);
                        }
                    }
                }
            }
        }
    }
    (out, opaque)
}

/// Reduce a verdict and everything under it to `undetermined`.
fn withdraw(node: &mut VariablePresenceNode) {
    node.presence = node.presence.weaker(VariablePresence::Undetermined);
    withdraw_children(node);
}

/// Withdraw everything under a node without touching the node's own verdict.
///
/// A list element is not a key, so `VariablePresenceNode::items` fixes its
/// presence at `always` by construction and `scripts/lint-ir.py` rejects any
/// other value. Recursing into it with the full withdrawal would move it to
/// `undetermined` and make the document unpublishable - the keys under it are
/// what the uncertainty applies to.
fn withdraw_children(node: &mut VariablePresenceNode) {
    for child in node.fields.values_mut() {
        withdraw(child);
    }
    if let Some(items) = node.items.as_deref_mut() {
        withdraw_children(items);
    }
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
            // Every element, folded the way two call sites are: the item shape
            // describes all of them, so a key `[{a: !0}, {}]` writes once is a
            // key some element lacks. A list's element is not itself a key, so it
            // gets no verdict of its own - it carries the element's keys.
            let mut fields: Option<SiteTree> = None;
            // An element this pass cannot enumerate may omit any key its readable
            // siblings write, so it withdraws the item verdicts rather than
            // letting them be decided without it. Same rule as an unreadable
            // spread and an unreadable ternary arm.
            let mut unreadable_element = false;
            for element in items {
                let Value::Object(props) = scopes.resolve(element, 0) else {
                    unreadable_element = true;
                    continue;
                };
                let here = classify_object(props, scopes, diag, depth + 1);
                fields = Some(match fields {
                    Some(acc) => merge_sites(acc, here),
                    None => here,
                });
            }
            if let Some(fields) = fields {
                let mut item = VariablePresenceNode::leaf(VariablePresence::Always);
                item.fields = fields;
                if unreadable_element {
                    withdraw_children(&mut item);
                }
                node.items = Some(Box::new(item));
            }
        }
        _ => {}
    }
    node
}

/// Merge two verdicts about one key, keeping the weaker claim and the union of
/// the nested keys.
fn merge_nodes(a: VariablePresenceNode, b: VariablePresenceNode) -> VariablePresenceNode {
    // A key one side carries and the other does not is a key that can be absent,
    // at every level and not only at the top: merging `{input:{a}}` with
    // `{input:{}}` has to leave `input.a` conditional, or the nested field is
    // published as unconditional on the evidence of one writer.
    let mut fields = a.fields;
    let only_in_b: Vec<String> = b
        .fields
        .keys()
        .filter(|k| !fields.contains_key(*k))
        .cloned()
        .collect();
    let only_in_a: Vec<String> = fields
        .keys()
        .filter(|k| !b.fields.contains_key(*k))
        .cloned()
        .collect();
    for (k, v) in b.fields {
        match fields.remove(&k) {
            Some(existing) => fields.insert(k, merge_nodes(existing, v)),
            None => fields.insert(k, v),
        };
    }
    for k in only_in_a.into_iter().chain(only_in_b) {
        if let Some(node) = fields.get_mut(&k) {
            node.presence = node.presence.weaker(VariablePresence::Conditional);
        }
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

/// The module's own top-level `var`/`let`/`const` bindings.
///
/// Only that level: a name declared inside one function says nothing about the
/// same spelling inside another, and the minifier reuses single letters
/// everywhere. Both shapes are read, the bare program body and the body of a
/// `__d("Name", deps, factory)` factory, since a WA module is the latter and the
/// unit tests exercise the former.
fn hoist_module_bindings(program: &oxc_ast::ast::Program) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    collect_declarations(&program.body, &mut out);
    for stmt in &program.body {
        let oxc_ast::ast::Statement::ExpressionStatement(es) = stmt else {
            continue;
        };
        let Some(call) = wa_oxc::as_call(&es.expression) else {
            continue;
        };
        if wa_oxc::as_identifier(&call.callee) != Some(wa_oxc::DEFINE_FN) {
            continue;
        }
        for arg in &call.arguments {
            if let Some(Expression::FunctionExpression(f)) = arg.as_expression()
                && let Some(body) = &f.body
            {
                collect_declarations(&body.statements, &mut out);
            }
        }
    }
    out
}

fn collect_declarations(statements: &[oxc_ast::ast::Statement], out: &mut HashMap<String, Value>) {
    for stmt in statements {
        let oxc_ast::ast::Statement::VariableDeclaration(decl) = stmt else {
            continue;
        };
        for d in &decl.declarations {
            if let Some(name) = d.id.get_identifier_name() {
                let value = match d.init.as_ref() {
                    Some(init) => convert(init, 0),
                    None => Value::MaybeUndefined,
                };
                out.insert(name.as_str().to_string(), value);
            }
        }
    }
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
    /// Calls that send this operation whose variables object could not be read.
    unreadable_sites: usize,
    /// Whether a recovered site carries a spread whose keys could not be listed,
    /// so a declared key nothing wrote may still be reaching the wire.
    opaque_keys: bool,
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
        if let Some(name) = d.id.get_identifier_name() {
            // An uninitialized declaration is still a binding: it shadows an
            // outer name of the same spelling, and until something writes it the
            // value is `undefined`. Skipping it let `var x;` inside a module that
            // also binds `x` resolve to the module's value.
            let value = match d.init.as_ref() {
                Some(init) => convert(init, 0),
                None => Value::MaybeUndefined,
            };
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
        if self.is_operation_call(call) {
            let Some(vars) = call.arguments.get(1).and_then(Argument::as_expression) else {
                // The operation is sent with no variables argument at all. That is
                // a site, and one that writes nothing: skipping it would let a
                // sibling call's object speak for an invocation that sends no key.
                self.sites.push(SiteTree::new());
                walk::walk_call_expression(self, call);
                return;
            };
            let value = convert(vars, 0);
            match self.variables_object(&value) {
                Some(tree) => self.sites.push(tree),
                // This call sends the operation and its variables object could
                // not be read, so nothing is known about which keys it writes.
                // `always` means no recovered site contradicts the key, and an
                // unread site cannot be shown not to.
                None => {
                    self.diag.unreadable_call_arguments += 1;
                    self.unreadable_sites += 1;
                }
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
        // Every name the pattern introduces, destructured and rest included.
        // Leaving those unbound is not the same as binding them: an unbound name
        // falls through to the enclosing frames, so `function f({x})` inside a
        // module that also binds `x` would resolve the parameter to the module's
        // value and call a passthrough unconditional.
        for item in &params.items {
            for ident in item.pattern.get_binding_identifiers() {
                self.scopes.bind(ident.name.as_str(), Value::MaybeUndefined);
            }
        }
        if let Some(rest) = &params.rest {
            for ident in rest.rest.argument.get_binding_identifiers() {
                self.scopes.bind(ident.name.as_str(), Value::MaybeUndefined);
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
            Value::Object(props) => {
                let (tree, opaque) = classify_object_reporting(props, &self.scopes, self.diag, 0);
                // A spread whose keys could not be enumerated may be supplying a
                // declared key this site never writes explicitly. Falling through
                // to the "no site wrote it" default would publish `conditional`,
                // which claims the client omits it; nothing here establishes that.
                self.opaque_keys |= opaque;
                Some(tree)
            }
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
                    // One arm is an object and the other could not be read, so
                    // what the call sends on that path is unknown. Publishing the
                    // readable arm alone would let it decide the operation by
                    // itself, which is the whole failure mode this guards.
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn branch_object(&mut self, value: &Value) -> Option<SiteTree> {
        match self.scopes.resolve(value, 0) {
            Value::Object(props) => {
                let (tree, opaque) = classify_object_reporting(props, &self.scopes, self.diag, 0);
                self.opaque_keys |= opaque;
                Some(tree)
            }
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
    let mut unreadable_sites = 0usize;
    let mut opaque_keys = false;
    for (src, sole_operation) in callers {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, src);
        let scopes = Scopes {
            hoisted: hoist_module_bindings(&ret.program),
            ..Scopes::default()
        };
        let mut collector = CallSiteCollector {
            module: module.to_string(),
            sole_operation: *sole_operation,
            scopes,
            sites: Vec::new(),
            unreadable_sites: 0,
            opaque_keys: false,
            diag,
        };
        collector.visit_program(&ret.program);
        unreadable_sites += collector.unreadable_sites;
        opaque_keys |= collector.opaque_keys;
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
            let mut node = merged.remove(name).unwrap_or_else(|| {
                // Declared by the operation and written by no recovered site. That
                // is "not always" - unless a spread nobody could read might be
                // supplying it, in which case nothing at all is established.
                VariablePresenceNode::leaf(if opaque_keys {
                    VariablePresence::Undetermined
                } else {
                    VariablePresence::Conditional
                })
            });
            if unreadable_sites > 0 {
                withdraw(&mut node);
            }
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
    fn a_nested_key_only_one_site_writes_is_conditional() {
        // Absence is a verdict at every level, not only at the top: one site
        // writes `input.b`, the other writes `input` without it.
        let caller = r#"function f(t){if(t)return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{a:!0,b:!0}});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{a:!1}})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let input = &tree["input"];
        assert_eq!(input.presence, VariablePresence::Always);
        assert_eq!(input.fields["a"].presence, VariablePresence::Always);
        assert_eq!(
            input.fields["b"].presence,
            VariablePresence::Conditional,
            "written by one site's input object and not the other's"
        );
    }

    #[test]
    fn a_conditionally_reassigned_binding_is_not_read_as_the_last_write() {
        // The scan has no control flow, so the assignment inside the branch would
        // otherwise stand as the value reaching the call.
        let caller = r#"function f(t){var v={};if(t){v={a:!0}}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Conditional,
            "one of the two values reaching the call does not write it"
        );
    }

    #[test]
    fn a_destructured_parameter_shadows_an_outer_binding() {
        // `x` is bound at module level AND destructured out of the parameter. The
        // parameter wins, and a parameter is a passthrough.
        let caller = r#"var x=!0;function f({x}){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_ternary_with_one_unreadable_arm_does_not_decide_alone() {
        // `cond ? {a: !0} : somethingUnreadable`: the readable arm cannot speak
        // for the call, because the other path may send something else entirely.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),t.flag?{a:!0}:t.other)}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_call_arguments, 1);
    }

    #[test]
    fn mutually_recursive_spreads_terminate() {
        let caller = r#"function f(){var a={...b},b={...a};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),a)}"#;
        let (tree, _) = presence_of(caller, &["k"]);
        assert!(tree.contains_key("k"), "the operation is still published");
    }

    #[test]
    fn a_later_write_replaces_an_earlier_one() {
        // JS object construction is ordered, so `{...base, a: !0}` is `a: !0`
        // whatever `base` said. Merging the two would publish a key the client
        // always sends as omissible, which is this dimension's own defect
        // pointing the other way.
        let caller = r#"function f(t){var base={a:t.maybe,b:t.maybe};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{...base,a:!0})}"#;
        let (tree, _) = presence_of(caller, &["a", "b"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Always,
            "the explicit write after the spread is the value"
        );
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "nothing overwrote what the spread said"
        );
    }

    #[test]
    fn a_logical_assignment_keeps_its_left_side_in_play() {
        // `x &&= !0` yields `x` when `x` is falsy, `undefined` included, so it is
        // not the same as assigning the literal.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:(t.x&&=!0),b:(t.y||=!0),c:(t.z=!0)})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Conditional,
            "&&= can yield the left side"
        );
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Always,
            "||= yields the right side when the left is falsy"
        );
        assert_eq!(
            at(&tree, "c"),
            VariablePresence::Always,
            "a plain assignment is its right side"
        );
    }

    #[test]
    fn an_uninitialized_declaration_shadows_an_outer_binding() {
        // `var x` inside the function is a binding whose value is `undefined`,
        // not a reason to fall through to the module's `x`.
        let caller = r#"var x=!0;function f(){var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn every_array_element_contributes_to_the_item_shape() {
        // The item node describes all elements, so a key only one of them writes
        // is a key some element lacks.
        let caller = r#"function f(t){return o("C").commitMutation(n("WAWebFooQuery.graphql"),{input:[{a:!0,b:!0},{a:!1}]})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let item = tree["input"].items.as_ref().expect("list element node");
        assert_eq!(item.fields["a"].presence, VariablePresence::Always);
        assert_eq!(
            item.fields["b"].presence,
            VariablePresence::Conditional,
            "the second element omits it"
        );
    }

    #[test]
    fn a_function_valued_property_is_not_on_the_wire() {
        // `JSON.stringify({a: () => !0})` is `{}`. A defined value is not the
        // same as a value that reaches the server.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:function(){return!0},b:()=>!0,c:!0})}"#;
        let (tree, _) = presence_of(caller, &["a", "b", "c"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
        assert_eq!(at(&tree, "b"), VariablePresence::Conditional);
        assert_eq!(at(&tree, "c"), VariablePresence::Always);
    }

    #[test]
    fn a_call_with_no_variables_argument_is_a_site_that_writes_nothing() {
        // Skipping it would let the sibling call's object speak for an
        // invocation that sends no key at all.
        let caller = r#"function f(t){if(t)return o("C").fetchQuery(n("WAWebFooQuery.graphql"));return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_module_binding_declared_after_the_closure_still_resolves() {
        // A closure resolves its free names when it runs, so the declaration
        // order in the source does not decide the verdict.
        let caller =
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}var x=!0;"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn an_unreadable_spread_leaves_unwritten_keys_undetermined() {
        // `fetchQuery(op, {...opts})`: nothing says whether `opts` supplies `a`
        // always, sometimes or never, so `conditional` would be a claim the
        // extractor cannot make. A key written explicitly is still definite.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{...t.opts,b:!0})}"#;
        let (tree, diag) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Always,
            "written after the spread, so the spread cannot reach it"
        );
        assert_eq!(diag.unreadable_spreads, 1);
    }

    #[test]
    fn a_computed_key_withdraws_what_came_before_it() {
        // `{a: !0, [k]: void 0}` drops `a` when `k` is `"a"`, so a key this pass
        // cannot read is not merely a key it fails to add.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,[t.k]:t.v,b:!0})}"#;
        let (tree, diag) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Always,
            "written after it, so out of its reach"
        );
        assert_eq!(diag.unreadable_keys, 1);
    }

    #[test]
    fn an_unreadable_array_element_withdraws_the_item_keys() {
        // A mixed array: the readable element cannot speak for the one this pass
        // has no way to enumerate.
        for caller in [
            r#"function f(t){return o("C").commitMutation(n("WAWebFooQuery.graphql"),{input:[{a:!0},t.other]})}"#,
            r#"function f(t){return o("C").commitMutation(n("WAWebFooQuery.graphql"),{input:[...t.extra,{a:!0}]})}"#,
        ] {
            let (tree, _) = presence_of(caller, &["input"]);
            let item = tree["input"].items.as_ref().expect("list element node");
            assert_eq!(
                item.fields["a"].presence,
                VariablePresence::Undetermined,
                "{caller}"
            );
            assert_eq!(
                item.presence,
                VariablePresence::Always,
                "the element container is not a key and stays `always`"
            );
        }
    }

    #[test]
    fn withdrawing_keeps_a_list_element_container_always() {
        // `VariablePresenceNode::items` is `always` by construction and the linter
        // rejects anything else, so a withdrawal has to reach the element's KEYS
        // without moving the container itself.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),t.opaque);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:[{a:!0}]})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let item = tree["input"].items.as_ref().expect("list element node");
        assert_eq!(
            item.presence,
            VariablePresence::Always,
            "an unreadable sibling site must not make the document unpublishable"
        );
        assert_eq!(item.fields["a"].presence, VariablePresence::Undetermined);
    }

    #[test]
    fn a_compound_assignment_yields_a_primitive() {
        // `x += y` is a number or a string whatever `y` was, so the key is there.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{count:(t.x+=t.step),plain:(t.y=t.z)})}"#;
        let (tree, _) = presence_of(caller, &["count", "plain"]);
        assert_eq!(at(&tree, "count"), VariablePresence::Always);
        assert_eq!(
            at(&tree, "plain"),
            VariablePresence::Conditional,
            "a plain `=` is its right side"
        );
    }

    #[test]
    fn no_call_site_is_undetermined_and_counted() {
        let (tree, diag) = presence_of("function f(){return 1}", &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.operations_without_call_site, 1);
    }

    #[test]
    fn a_self_referential_spread_terminates() {
        // `var e = {...e, a: !0}` resolves the spread back to the object being
        // built. Descending without a depth bound overflowed the stack, and an
        // extractor that aborts publishes nothing at all.
        let caller = r#"function f(){var e={...e,a:!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),e)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert!(tree.contains_key("a"), "the operation is still published");
    }

    #[test]
    fn an_unreadable_spread_withdraws_the_keys_before_it() {
        // `{a: !0, ...t.extra}` is not `a` plus unknown extras: a later spread
        // overwrites `a`, and it can overwrite it with `undefined`, which JSON
        // drops. Publishing `always` there would be the exact overstatement the
        // verdict must not make. A key written AFTER the spread wins, so it keeps
        // its verdict.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,...t.extra,b:!0})}"#;
        let (tree, diag) = presence_of(caller, &["a", "b"]);
        assert_eq!(
            at(&tree, "a"),
            VariablePresence::Undetermined,
            "written before a spread that could overwrite it"
        );
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Always,
            "written after the spread, so the spread cannot reach it"
        );
        assert_eq!(diag.unreadable_spreads, 1);
    }

    #[test]
    fn an_unreadable_call_argument_withdraws_the_operations_verdicts() {
        // Two sites, one of them a variables object that does not resolve. The
        // readable one alone cannot establish `always`: the other sends the same
        // operation and nothing is known about which keys it writes.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),t.opts);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_call_arguments, 1);
    }

    #[test]
    fn a_binding_that_refers_to_itself_terminates() {
        let caller = r#"function f(){var e=e||{};var d={a:e};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),d)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        // The verdict is not the point; terminating is.
        assert!(tree.contains_key("a"));
    }
}
