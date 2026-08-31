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
    OrElse(Box<Value>, Box<Value>),
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

/// Which frame a write lands in.
#[derive(Debug, Clone, Copy)]
enum Scope {
    /// The block or function currently being visited: a `let` or a `const`.
    Current,
    /// The enclosing function: a `var`, which a block does not contain.
    Function,
    /// Wherever the name is already bound: an assignment updates that binding.
    Assignment,
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
    /// Per frame, the names its function declares with `var` anywhere in its
    /// body. JS hoists those to the top of the function as `undefined`, so a
    /// call that precedes the declaration must not resolve the name against an
    /// enclosing binding. Consulted after the frames and before the module's own
    /// hoisted table, which is the shadowing order.
    frame_hoisted: Vec<HashMap<String, Value>>,
    /// Whether each frame is a function's, as opposed to a block's. `let` and
    /// `const` belong to the block that declares them and go out of scope with
    /// it; `var` belongs to the enclosing function and outlives the block.
    frame_is_function: Vec<bool>,
    /// Bindings the module declares at its own top level, collected before the
    /// walk. A closure resolves its free names when it RUNS, not where it sits,
    /// so `function f(){ …{a: x}… } var x = !0;` uses the defined `x`; walking in
    /// source order alone would classify `a` against a name not yet seen.
    ///
    /// Consulted only after the frames, so a real binding still wins and a later
    /// assignment still joins the prior one rather than replacing it - the rule
    /// that keeps a conditional rebinding conservative.
    hoisted: HashMap<String, Value>,
    /// One log per branch being walked, innermost last. Each entry is a name the
    /// branch wrote and what it held when the branch began, which is what the
    /// path around the branch reaches.
    ///
    /// The write itself lands in the frame, so a call INSIDE the branch reads
    /// what the branch wrote - `if (t) { x = !0; fetchQuery(op, {a: x}) }` sends
    /// `a` on the only path that calls at all. The join with the pre-branch value
    /// happens on the way out, for the calls that follow.
    branches: Vec<Vec<BranchWrite>>,
}

/// A name a branch wrote, with the value it had before the branch began.
struct BranchWrite {
    frame: usize,
    name: String,
    before: Option<Value>,
}

impl Scopes {
    fn push(&mut self, hoisted: HashMap<String, Value>) {
        self.push_frame(hoisted, true);
    }
    /// A lexical block: `let`/`const` inside it disappear with it.
    fn push_block(&mut self) {
        self.push_frame(HashMap::new(), false);
    }
    fn push_frame(&mut self, hoisted: HashMap<String, Value>, is_function: bool) {
        self.frames.push(HashMap::new());
        self.frame_hoisted.push(hoisted);
        self.frame_is_function.push(is_function);
    }
    fn pop(&mut self) {
        self.frames.pop();
        self.frame_hoisted.pop();
        self.frame_is_function.pop();
    }
    /// The innermost frame a `var` belongs to, skipping blocks.
    fn function_frame(&self) -> Option<usize> {
        self.frame_is_function
            .iter()
            .rposition(|is_function| *is_function)
    }

    /// The frame an assignment writes: the innermost one already binding the
    /// name, since that is the binding being updated, and the enclosing function
    /// only when nothing binds it yet.
    ///
    /// Writing to the function frame unconditionally left a block's `let` visible
    /// with its old value, because `lookup` reaches the block first.
    fn assignment_frame(&self, name: &str) -> Option<usize> {
        match self.frames.iter().rposition(|f| f.contains_key(name)) {
            Some(idx) => Some(idx),
            None => self.function_frame(),
        }
    }
    /// Bind a name, joining any binding already in this frame when the write is
    /// one a branch can skip.
    ///
    /// The scan has no control flow, so `var v = {}; if (flag) v = {a: !0};`
    /// would otherwise leave `v` at the conditional assignment and call `a`
    /// unconditional: two values may reach the call, which is what `Either`
    /// means everywhere else in this pass. A write at the straight-line level of
    /// its function does reach the call, though, and joining there is the
    /// opposite error - `v = {}; v = {a: !0}; fetchQuery(op, v)` sends `a` every
    /// time, and calling it `conditional` leaves a consumer with the optional
    /// field this whole dimension exists to remove.
    fn bind(&mut self, name: &str, value: Value) {
        self.bind_in(name, value, Scope::Current);
    }
    /// Bind in the enclosing FUNCTION scope rather than the current block, for a
    /// `var`, which a block does not contain.
    fn bind_function_scoped(&mut self, name: &str, value: Value) {
        self.bind_in(name, value, Scope::Function);
    }
    /// Update the binding an assignment targets, wherever it lives.
    fn bind_assignment(&mut self, name: &str, value: Value) {
        self.bind_in(name, value, Scope::Assignment);
    }
    fn bind_in(&mut self, name: &str, value: Value, scope: Scope) {
        let index = match scope {
            Scope::Function => self.function_frame(),
            Scope::Assignment => self.assignment_frame(name),
            Scope::Current => self.frames.len().checked_sub(1),
        };
        let Some(index) = index else {
            return;
        };
        if let Some(log) = self.branches.last()
            && !log.iter().any(|w| w.frame == index && w.name == name)
        {
            // What the name held before this branch. A `var` whose first write is
            // inside the branch has no entry in the frame yet, only the
            // `undefined` the hoist put in this frame's table - and that
            // `undefined` is what the path around the branch reaches.
            let before = self.frames[index]
                .get(name)
                .or_else(|| self.frame_hoisted[index].get(name))
                .cloned();
            let write = BranchWrite {
                frame: index,
                name: name.to_string(),
                before,
            };
            self.branches
                .last_mut()
                .expect("a branch is open")
                .push(write);
        }
        self.frames[index].insert(name.to_string(), value);
    }

    /// Start a branch: writes inside it are what the code inside it reads.
    fn enter_branch(&mut self) {
        self.branches.push(Vec::new());
    }

    /// End a branch, joining each name it wrote with the value the path around
    /// the branch carries. A frame pushed inside the branch is already gone with
    /// its bindings, so a write recorded against it needs no join.
    fn leave_branch(&mut self) {
        let Some(log) = self.branches.pop() else {
            return;
        };
        for write in log {
            if write.frame >= self.frames.len() {
                continue;
            }
            if let Some(before) = write.before {
                if let Some(after) = self.frames[write.frame].remove(&write.name) {
                    self.frames[write.frame].insert(
                        write.name.clone(),
                        Value::Either(Box::new(before.clone()), Box::new(after)),
                    );
                }
                // An enclosing branch joins against the value from before IT
                // began, so it has to learn about this name too.
                if let Some(outer) = self.branches.last_mut()
                    && !outer
                        .iter()
                        .any(|w| w.frame == write.frame && w.name == write.name)
                {
                    outer.push(BranchWrite {
                        frame: write.frame,
                        name: write.name,
                        before: Some(before),
                    });
                }
            }
        }
    }
    /// Innermost scope outward, and within each scope its bindings before its
    /// hoisted names.
    ///
    /// Not all frames and then all hoisted tables: a name hoisted in the inner
    /// function shadows an enclosing binding of the same spelling, and checking
    /// every frame first would resolve `var x` inside `f` against the module's
    /// `x` - the shadowing this table exists to provide.
    fn lookup(&self, name: &str) -> Option<&Value> {
        self.frames
            .iter()
            .zip(&self.frame_hoisted)
            .rev()
            .find_map(|(bound, hoisted)| bound.get(name).or_else(|| hoisted.get(name)))
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

        // `new X()` never evaluates to `undefined`, but the instance decides its
        // own serialization: a `toJSON` returning `undefined` drops the key.
        // Which class it is, and what it does there, is not something this pass
        // establishes.
        Expression::NewExpression(_) => Value::Unjudged,

        // `!x`, `!!x`, `typeof x`, `-x` yield primitives; `void x` IS `undefined`,
        // so it is the one unary that does not.
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::Void => Value::MaybeUndefined,
            _ => Value::Defined,
        },

        Expression::LogicalExpression(l) => match l.operator {
            LogicalOperator::Coalesce | LogicalOperator::Or => {
                Value::OrElse(
                    Box::new(convert(&l.left, next)),
                    Box::new(convert(&l.right, next)),
                )
            }
            LogicalOperator::And => Value::AndThen(
                Box::new(convert(&l.left, next)),
                Box::new(convert(&l.right, next)),
            ),
        },

        // `t == null ? void 0 : t.x` is how the minifier writes an optional
        // chain, and its `void 0` arm is what makes that form conditional.
        Expression::ConditionalExpression(c) => match memoised(c) {
            // `e !== void 0 ? e : e = n("X.graphql")` is the memoising require:
            // one branch reads the binding the other writes, so both arms are
            // the assigned value and the ternary is not a choice between two
            // things. Kept as that value, because the alternative is resolving
            // `e` later, in whatever scope the read happens to sit in - and the
            // job functions around these handles reuse the same letters for
            // their own parameters.
            Some(memo) => convert(memo, next),
            None => Value::Either(
                Box::new(convert(&c.consequent, next)),
                Box::new(convert(&c.alternate, next)),
            ),
        },

        Expression::SequenceExpression(s) => match s.expressions.last() {
            Some(last) => convert(last, next),
            None => Value::Unjudged,
        },
        Expression::ParenthesizedExpression(p) => convert(&p.expression, next),
        // A logical assignment can yield the LEFT side without ever evaluating
        // the right: `x &&= !0` is `undefined` when `x` is. Only a plain `=`
        // (or an arithmetic compound, which yields a primitive) is its right side.
        Expression::AssignmentExpression(a) => assignment_value(a, next),

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

        // `x++` / `++x` evaluate to a number: `NaN` when the operand was not one,
        // which serializes as `null` with the key still there.
        Expression::UpdateExpression(_) => Value::Defined,

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
        Value::OrElse(_, rhs) => definedness(rhs, scopes, next),
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

/// [`classify_object`], plus the paths under it whose keys are not fully known:
/// each names an object a spread or a computed key may still be writing into,
/// the empty path being this object itself. A sibling site must not answer for
/// those keys, so they are withdrawn once every site has been merged.
fn classify_object_reporting(
    props: &[Prop],
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
) -> (SiteTree, Vec<Vec<String>>) {
    let mut opaque: Vec<Vec<String>> = Vec::new();
    let mut out: SiteTree = BTreeMap::new();
    // A spread whose source resolves back through itself (`var e = {...e}`)
    // would otherwise descend forever, and an extractor that aborts publishes
    // nothing at all.
    if depth >= MAX_DEPTH {
        diag.unreadable_spreads += 1;
        return (out, vec![Vec::new()]);
    }
    for prop in props {
        match prop {
            Prop::Unreadable => {
                // A computed key names something this pass cannot read, and that
                // something may be a key already written: `{a: !0, [k]: void 0}`
                // drops `a` when `k` is `"a"`. Same rule as an unreadable spread,
                // and a later explicit write still restores the key.
                diag.unreadable_keys += 1;
                opaque.push(Vec::new());
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
                let (node, nested) =
                    classify_value_reporting(value, scopes, diag, depth, VariablePresence::Always);
                for mut path in nested {
                    path.insert(0, key.clone());
                    opaque.push(path);
                }
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
                        // The nested object's own opacity travels outward: with
                        // `var base = {...opts}; fetchQuery(op, {...base})` the
                        // unreadable `opts` is inside `base`, and dropping the
                        // flag here would let the outer site read as fully known.
                        let (nested, nested_opaque) =
                            classify_object_reporting(inner, scopes, diag, depth + 1);
                        // The spread's keys land in THIS object, so the paths it
                        // could not read do too.
                        opaque.extend(nested_opaque);
                        for (k, mut node) in nested {
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
                        opaque.push(Vec::new());
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
/// a nested key is answered too, and reporting the paths under it whose keys are
/// not fully known - see [`classify_object_reporting`].
fn classify_value_reporting(
    value: &Value,
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
    floor: VariablePresence,
) -> (VariablePresenceNode, Vec<Vec<String>>) {
    let presence = definedness(value, scopes, 0).presence().weaker(floor);
    let mut node = VariablePresenceNode::leaf(presence);
    let mut opaque: Vec<Vec<String>> = Vec::new();
    if depth >= MAX_DEPTH {
        return (node, opaque);
    }
    match scopes.resolve(value, 0) {
        Value::Object(props) => {
            let (fields, nested) = classify_object_reporting(props, scopes, diag, depth + 1);
            node.fields = fields;
            opaque.extend(nested);
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
        // Two objects can reach this key, one per call - a binding written in a
        // branch, or a ternary. Its nested keys are read the way two call sites
        // are: a key only one of them writes is a key the client can omit.
        Value::Either(a, b) => {
            let (left, left_opaque) = classify_value_reporting(a, scopes, diag, depth, floor);
            let (right, right_opaque) = classify_value_reporting(b, scopes, diag, depth, floor);
            let merged = merge_nodes(left, right);
            node.fields = merged.fields;
            node.items = merged.items;
            opaque.extend(left_opaque);
            opaque.extend(right_opaque);
        }
        _ => {}
    }
    (node, opaque)
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
        // One side described the element and the other did not. The keys the
        // described side wrote are not established for the list as a whole - the
        // other site's list may carry an element without them - so they are
        // withdrawn while the container itself stays `always`.
        (Some(mut x), None) | (None, Some(mut x)) => {
            withdraw_children(&mut x);
            Some(x)
        }
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

/// The names a function body declares with `var`, at any depth inside it.
///
/// JS hoists them to the top of the function with the value `undefined`, so a
/// call that runs before the declaration sees `undefined` and not whatever an
/// enclosing scope binds to the same spelling. Nested functions are not
/// descended into: their `var`s belong to them.
fn hoisted_vars(body: &oxc_ast::ast::FunctionBody) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    collect_hoisted(&body.statements, &mut out);
    out
}

fn collect_hoisted(statements: &[oxc_ast::ast::Statement], out: &mut HashMap<String, Value>) {
    use oxc_ast::ast::Statement as S;
    for stmt in statements {
        match stmt {
            S::VariableDeclaration(decl) => collect_hoisted_declaration(decl, out),
            // A function declaration binds its name for the whole function, and
            // `JSON.stringify` drops a key whose value is a function - so a
            // local `function x(){}` is both a shadow of an outer `x` and a key
            // that does not reach the wire.
            S::FunctionDeclaration(f) => {
                if let Some(id) = &f.id {
                    out.insert(id.name.as_str().to_string(), Value::MaybeUndefined);
                }
            }
            S::BlockStatement(b) => collect_hoisted(&b.body, out),
            S::IfStatement(i) => {
                collect_hoisted(std::slice::from_ref(&i.consequent), out);
                if let Some(alt) = &i.alternate {
                    collect_hoisted(std::slice::from_ref(alt), out);
                }
            }
            // A loop header declares in the enclosing function, not in the loop:
            // `for (var i ...)` hoists `i` exactly like a `var` on the line above,
            // and missing it lets an outer binding of the same name answer for it.
            S::ForStatement(f) => {
                if let Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(decl)) = &f.init {
                    collect_hoisted_declaration(decl, out);
                }
                collect_hoisted(std::slice::from_ref(&f.body), out);
            }
            S::ForInStatement(f) => {
                if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(decl) = &f.left {
                    collect_hoisted_declaration(decl, out);
                }
                collect_hoisted(std::slice::from_ref(&f.body), out);
            }
            S::ForOfStatement(f) => {
                if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(decl) = &f.left {
                    collect_hoisted_declaration(decl, out);
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
                if let Some(f) = &t.finalizer {
                    collect_hoisted(&f.body, out);
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

/// The names a single `var` declaration hoists, wherever it is written.
fn collect_hoisted_declaration(
    decl: &oxc_ast::ast::VariableDeclaration,
    out: &mut HashMap<String, Value>,
) {
    if !decl.kind.is_var() {
        return;
    }
    for d in &decl.declarations {
        for ident in d.id.get_binding_identifiers() {
            out.insert(ident.name.as_str().to_string(), Value::MaybeUndefined);
        }
    }
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

/// The name a member assignment writes through: `v.a.b = x` is a write to `v`.
fn member_assignment_base<'b, 'a>(
    target: &'b oxc_ast::ast::AssignmentTarget<'a>,
) -> Option<&'b str> {
    use oxc_ast::ast::{AssignmentTarget as T, Expression as E};
    let mut expr = match target {
        T::StaticMemberExpression(m) => &m.object,
        T::ComputedMemberExpression(m) => &m.object,
        T::PrivateFieldExpression(m) => &m.object,
        _ => return None,
    };
    loop {
        match expr {
            E::Identifier(id) => return Some(id.name.as_str()),
            E::StaticMemberExpression(m) => expr = &m.object,
            E::ComputedMemberExpression(m) => expr = &m.object,
            E::PrivateFieldExpression(m) => expr = &m.object,
            E::ParenthesizedExpression(p) => expr = &p.expression,
            _ => return None,
        }
    }
}

/// Whether an expression IS `null`, `undefined` or `void 0`, spelled out at the
/// call rather than reached through a binding. A property read that happens to
/// be undefined at run time is not this: it is a value this pass cannot read.
fn is_nullish_literal(expr: &Expression) -> bool {
    match expr {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name.as_str() == "undefined",
        Expression::UnaryExpression(u) => u.operator == UnaryOperator::Void,
        Expression::ParenthesizedExpression(p) => is_nullish_literal(&p.expression),
        _ => false,
    }
}

/// The static property path a member assignment writes, from the binding
/// outward: `v.order.jid = x` gives `["order", "jid"]`. `None` for a computed
/// key, which names nothing this pass can publish.
fn static_path(target: &oxc_ast::ast::AssignmentTarget) -> Option<Vec<String>> {
    use oxc_ast::ast::{AssignmentTarget as T, Expression as E};
    let T::StaticMemberExpression(member) = target else {
        return None;
    };
    let mut path = vec![member.property.name.as_str().to_string()];
    let mut expr = &member.object;
    loop {
        match expr {
            E::Identifier(_) => {
                path.reverse();
                return Some(path);
            }
            E::StaticMemberExpression(m) => {
                path.push(m.property.name.as_str().to_string());
                expr = &m.object;
            }
            E::ParenthesizedExpression(p) => expr = &p.expression,
            _ => return None,
        }
    }
}

/// The recovered object with `path` written to `written`, or `None` when the
/// path does not run through objects this pass read - in which case the caller
/// has to stop treating the binding as evidence.
fn write_key(
    value: &Value,
    path: &[String],
    written: Value,
    scopes: &Scopes,
    depth: usize,
) -> Option<Value> {
    if depth >= MAX_DEPTH {
        return None;
    }
    let Value::Object(props) = scopes.resolve(value, 0) else {
        return None;
    };
    let (key, rest) = path.split_first()?;
    let mut out: Vec<Prop> = Vec::with_capacity(props.len() + 1);
    let mut wrote = false;
    for prop in props {
        match prop {
            Prop::Key(k, inner) if k == key => {
                let value = if rest.is_empty() {
                    written.clone()
                } else {
                    write_key(inner, rest, written.clone(), scopes, depth + 1)?
                };
                out.push(Prop::Key(k.clone(), value));
                wrote = true;
            }
            other => out.push(other.clone()),
        }
    }
    if !wrote {
        // A key the literal never wrote, added here. Only the last step of the
        // path can be one: a write through a key the object does not carry is a
        // write to an object this pass never read.
        if !rest.is_empty() {
            return None;
        }
        out.push(Prop::Key(key.clone(), written));
    }
    Some(Value::Object(out))
}

/// What an assignment expression evaluates to, which is also what the name it
/// writes holds afterwards.
fn assignment_value(a: &oxc_ast::ast::AssignmentExpression, depth: usize) -> Value {
    match a.operator {
        // A logical assignment can yield the LEFT side without ever evaluating
        // the right: `x &&= !0` is `undefined` when `x` is. Only a plain `=`
        // (or an arithmetic compound, which yields a primitive) is its right side.
        AssignmentOperator::LogicalAnd => Value::AndThen(
            Box::new(Value::MaybeUndefined),
            Box::new(convert(&a.right, depth)),
        ),
        AssignmentOperator::LogicalOr | AssignmentOperator::LogicalNullish => Value::OrElse(
            Box::new(Value::MaybeUndefined),
            Box::new(convert(&a.right, depth)),
        ),
        // A plain `=` evaluates to its right side. An arithmetic or bitwise
        // compound assignment evaluates to the computed primitive instead,
        // which is defined whatever the operand was - `x += y` is a number
        // or a string even when `y` is `undefined` (`NaN` serializes as
        // `null`, with the key still there).
        AssignmentOperator::Assign => convert(&a.right, depth),
        _ => Value::Defined,
    }
}

/// The assigned side of a memoising ternary: one branch reads a binding, the
/// other assigns it, so the whole expression evaluates to what is assigned.
fn memoised<'a>(cond: &'a oxc_ast::ast::ConditionalExpression<'a>) -> Option<&'a Expression<'a>> {
    let pair = |read: &Expression<'a>, write: &'a Expression<'a>| {
        let Expression::Identifier(id) = read else {
            return None;
        };
        let Expression::AssignmentExpression(a) = write else {
            return None;
        };
        (a.operator == AssignmentOperator::Assign
            && wa_oxc::assignment_target_name(&a.left) == Some(id.name.as_str()))
        .then_some(&a.right)
    };
    pair(&cond.consequent, &cond.alternate).or_else(|| pair(&cond.alternate, &cond.consequent))
}

/// Whether a handle is pinned to a `.graphql` module on EVERY value it can take.
///
/// This is what tells "resolvable and not ours" from "we could not tell". A
/// ternary is one branch per call, so a handle whose other branch is a bare
/// parameter is only half read: the branch that names another operation says
/// nothing about the branch that might name this one, and answering `true` here
/// would drop the site instead of withdrawing what it might contradict.
fn every_branch_names_a_module(value: &Value, scopes: &Scopes, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let next = depth + 1;
    match value {
        Value::Call(name, args) => {
            name.as_deref().is_some_and(|n| n.ends_with(".graphql"))
                || args
                    .iter()
                    .any(|a| every_branch_names_a_module(a, scopes, next))
        }
        // Both branches, because one call takes one of them: a ternary between
        // another operation's module and something this pass cannot read is not
        // a handle it has read.
        Value::Either(a, b) => {
            every_branch_names_a_module(a, scopes, next)
                && every_branch_names_a_module(b, scopes, next)
        }
        // `a && b` hands the call `b`, or a falsy `a` that is no handle at all.
        Value::AndThen(_, rhs) => every_branch_names_a_module(rhs, scopes, next),
        // `a || b` and `a ?? b` DO hand the call `a` when it is there, so the
        // fallback naming a module says nothing about what `a` is.
        Value::OrElse(lhs, rhs) => {
            every_branch_names_a_module(lhs, scopes, next)
                && every_branch_names_a_module(rhs, scopes, next)
        }
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => every_branch_names_a_module(bound, scopes, next),
            None => false,
        },
        _ => false,
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
        Value::OrElse(lhs, rhs) => {
            references_module(lhs, module, scopes, next)
                || references_module(rhs, module, scopes, next)
        }
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
    /// Paths whose keys a spread or a computed key may still be writing, from
    /// any recovered site. The empty path is the variables object itself.
    opaque_paths: Vec<Vec<String>>,
    /// How many branching statements enclose the node being visited. A write
    /// inside one may not run before the call; a write at zero does.
    diag: &'d mut PresenceDiagnostics,
}

impl<'a> Visit<'a> for CallSiteCollector<'_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        self.scopes.push(HashMap::new());
        walk::walk_program(self, program);
        self.scopes.pop();
    }

    fn visit_function(
        &mut self,
        func: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        self.scopes
            .push(func.body.as_deref().map(hoisted_vars).unwrap_or_default());
        self.bind_params(&func.params);
        walk::walk_function(self, func, flags);
        self.scopes.pop();
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.scopes.push(hoisted_vars(&func.body));
        self.bind_params(&func.params);
        walk::walk_arrow_function_expression(self, func);
        self.scopes.pop();
    }

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        // `catch (x)` binds `x` for the handler only, and the thrown value is
        // whatever was thrown - nothing this pass can judge. Without the frame
        // the name falls through to an enclosing binding of the same spelling.
        self.scopes.push_block();
        if let Some(param) = &clause.param {
            for ident in param.pattern.get_binding_identifiers() {
                self.scopes.bind(ident.name.as_str(), Value::MaybeUndefined);
            }
        }
        walk::walk_catch_clause(self, clause);
        self.scopes.pop();
    }

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        self.scopes.push_block();
        walk::walk_block_statement(self, block);
        self.scopes.pop();
    }

    /// Each arm is its own branch: what the `if` writes is not what the `else`
    /// reads, and neither is what follows the statement.
    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_expression(&stmt.test);
        self.in_branch(|v| v.visit_statement(&stmt.consequent));
        if let Some(alternate) = &stmt.alternate {
            self.in_branch(|v| v.visit_statement(alternate));
        }
    }

    fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
        self.in_branch(|v| walk::walk_for_statement(v, stmt));
    }

    fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
        self.in_branch(|v| walk::walk_for_in_statement(v, stmt));
    }

    fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
        self.in_branch(|v| walk::walk_for_of_statement(v, stmt));
    }

    fn visit_while_statement(&mut self, stmt: &oxc_ast::ast::WhileStatement<'a>) {
        self.in_branch(|v| walk::walk_while_statement(v, stmt));
    }

    fn visit_do_while_statement(&mut self, stmt: &oxc_ast::ast::DoWhileStatement<'a>) {
        self.in_branch(|v| walk::walk_do_while_statement(v, stmt));
    }

    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        self.in_branch(|v| walk::walk_switch_statement(v, stmt));
    }

    fn visit_try_statement(&mut self, stmt: &oxc_ast::ast::TryStatement<'a>) {
        self.in_branch(|v| walk::walk_try_statement(v, stmt));
    }

    /// A write inside a short-circuit or a ternary arm runs only when that arm
    /// does, exactly like one inside an `if`.
    fn visit_logical_expression(&mut self, expr: &oxc_ast::ast::LogicalExpression<'a>) {
        self.visit_expression(&expr.left);
        self.in_branch(|v| v.visit_expression(&expr.right));
    }

    fn visit_conditional_expression(&mut self, expr: &oxc_ast::ast::ConditionalExpression<'a>) {
        self.visit_expression(&expr.test);
        self.in_branch(|v| v.visit_expression(&expr.consequent));
        self.in_branch(|v| v.visit_expression(&expr.alternate));
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        // A destructured declaration binds names the same way, and an unbound one
        // falls through to an enclosing scope: `let {x} = opts` beside an outer
        // `x` would otherwise resolve to the outer value. What it extracts is not
        // modelled, so those names are passthroughs.
        if d.id.get_identifier_name().is_none() {
            for ident in d.id.get_binding_identifiers() {
                self.scopes.bind(ident.name.as_str(), Value::MaybeUndefined);
            }
        }
        let function_scoped = d.kind.is_var();
        if let Some(name) = d.id.get_identifier_name() {
            // An uninitialized declaration is still a binding: it shadows an
            // outer name of the same spelling, and until something writes it the
            // value is `undefined`. Skipping it let `var x;` inside a module that
            // also binds `x` resolve to the module's value.
            let value = match d.init.as_ref() {
                Some(init) => convert(init, 0),
                None => Value::MaybeUndefined,
            };
            if function_scoped {
                self.scopes.bind_function_scoped(name.as_str(), value);
            } else {
                self.scopes.bind(name.as_str(), value);
            }
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        // The right side runs first: `x = fetchQuery(op, {a: x})` sends the `x`
        // from before the assignment, so the call inside it has to be read
        // against that binding rather than against the one this write installs.
        walk::walk_assignment_expression(self, n);
        // The memoised require is written `e !== void 0 ? e : e = n("X.graphql")`,
        // so the binding for the operation handle exists only as an assignment.
        if let Some(name) = wa_oxc::assignment_target_name(&n.left) {
            // Not the right side: `x &&= v` leaves `x` alone when it is falsy,
            // so the binding afterwards is what the whole expression yields.
            self.scopes.bind_assignment(name, assignment_value(n, 0));
        } else if let Some(base) = member_assignment_base(&n.left) {
            // `v.a = …` writes a key of an object this pass recovered, which the
            // literal alone does not show: WA builds a variables object and then
            // adds a key to it under a gate. Reading only the literal would
            // publish the keys it wrote and miss this one, so the write lands on
            // the recovered object - and where it cannot (a computed key, a
            // deeper path, a binding that is not an object), the object stops
            // being evidence rather than answering for a shape it no longer has.
            let updated = static_path(&n.left).and_then(|path| {
                let current = self.scopes.lookup(base)?.clone();
                write_key(&current, &path, assignment_value(n, 0), &self.scopes, 0)
            });
            self.scopes
                .bind_assignment(base, updated.unwrap_or(Value::Unjudged));
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !self.is_operation_call(call) && self.is_ambiguous_call(call) {
            // A Relay call in a module that sends several operations, whose
            // handle names no module at all. It may be this operation's, and
            // dropping it silently would let another caller's site decide a key
            // this one might contradict. Counted, and treated as a site nothing
            // is known about.
            self.diag.ambiguous_call_sites += 1;
            self.unreadable_sites += 1;
        }
        if self.is_operation_call(call) {
            let vars = call.arguments.get(1).and_then(Argument::as_expression);
            // No variables argument at all, or one written `null` / `undefined` /
            // `void 0`: either way the call sends an object carrying no key. That
            // is a site, and one that writes nothing - skipping it would let a
            // sibling call's object speak for an invocation that sends no key.
            let Some(vars) = vars.filter(|v| !is_nullish_literal(v)) else {
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

impl<'a> CallSiteCollector<'a> {
    /// Walk something that runs only when its branch is taken, then join what it
    /// wrote with the value the path around it carries.
    fn in_branch(&mut self, walk_arm: impl FnOnce(&mut Self)) {
        self.scopes.enter_branch();
        walk_arm(self);
        self.scopes.leave_branch();
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
            // `function f(...t)` binds `t` to an array on every call, the empty
            // one included, so a key holding it is a key on the wire. What is in
            // it is another matter, and no caller shows that here.
            for ident in rest.rest.argument.get_binding_identifiers() {
                self.scopes.bind(ident.name.as_str(), Value::Defined);
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

    /// A Relay call in a module that sends more than one operation whose handle
    /// this pass could not tie to any module: it may or may not be ours.
    fn is_ambiguous_call(&self, call: &CallExpression) -> bool {
        let Some(method) = wa_oxc::callee_method(call) else {
            return false;
        };
        if !FETCH_METHODS.contains(&method) || self.sole_operation {
            return false;
        }
        match call.arguments.first().and_then(Argument::as_expression) {
            Some(first) => !every_branch_names_a_module(&convert(first, 0), &self.scopes, 0),
            None => false,
        }
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
                self.opaque_paths.extend(opaque);
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
                self.opaque_paths.extend(opaque);
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
    let mut opaque_paths: Vec<Vec<String>> = Vec::new();
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
            opaque_paths: Vec::new(),
            diag,
        };
        collector.visit_program(&ret.program);
        unreadable_sites += collector.unreadable_sites;
        opaque_paths.extend(collector.opaque_paths);
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
        // Only when nothing matched at all. A call whose argument could not be
        // read is a recovered call site, counted under its own reason: reporting
        // both would collapse the split between "the scan found no call" and
        // "the scan found one and could not read it", which is the whole point
        // of naming them separately.
        if unreadable_sites == 0 {
            diag.operations_without_call_site += 1;
        }
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

    // A key under a path nothing could enumerate is a key no sibling site gets to
    // answer for: `{input: {...opts}}` beside `{input: {a: !0}}` says nothing
    // about whether `opts` carries `a`, and merging alone would call it omitted.
    for path in &opaque_paths {
        let mut node = None;
        for key in path {
            node = match node {
                None => merged.get_mut(key),
                Some(parent) => {
                    let parent: &mut VariablePresenceNode = parent;
                    parent.fields.get_mut(key)
                }
            };
            if node.is_none() {
                break;
            }
        }
        // An empty path is the variables object itself, whose unwritten declared
        // keys are handled below rather than here.
        if let Some(node) = node {
            withdraw_children(node);
        }
    }
    let opaque_keys = opaque_paths.iter().any(Vec::is_empty);

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
    fn a_function_local_var_shadows_even_before_its_declaration() {
        // JS hoists `var x` to the top of the function as `undefined`, so a call
        // that runs before the declaration must not reach the module's `x`.
        let caller =
            r#"var x=!0;function f(){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});var x}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_var_declared_in_a_loop_header_shadows_from_the_top_of_the_function() {
        // The header is not the body: `for (var x ...)` hoists `x` into the
        // function exactly like a line above the loop, and a call that runs
        // before the loop must read that `undefined`, not the module's `x`.
        for header in [
            "for(var x=!0;;){}",
            "for(var x in t){}",
            "for(var x of t){}",
        ] {
            let caller = format!(
                r#"var x=!0;function f(t){{o("C").fetchQuery(n("WAWebFooQuery.graphql"),{{a:x}});{header}}}"#
            );
            let (tree, _) = presence_of(&caller, &["a"]);
            assert_eq!(
                at(&tree, "a"),
                VariablePresence::Conditional,
                "{header} declares `x` in the function"
            );
        }
    }

    #[test]
    fn a_straight_line_reassignment_replaces_rather_than_joins() {
        // Every invocation sends `a`; joining the two writes would publish it as
        // omissible and leave a consumer with the optional field this dimension
        // exists to remove.
        let caller = r#"function f(){var v={};v={a:!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_new_expression_is_not_evidence_the_key_survives() {
        // A constructed value is never `undefined`, but its `toJSON` decides
        // whether the key is serialized at all.
        let caller =
            r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:new t.X})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
    }

    #[test]
    fn a_block_scoped_binding_does_not_outlive_its_block() {
        // `let` belongs to the block that declares it, so the call reads the
        // outer `x`, which is `undefined`.
        let caller = r#"function f(){let x;{let x=!0}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_var_and_an_assignment_inside_a_block_outlive_it() {
        // `var` belongs to the function, and an assignment writes the binding
        // wherever it lives - neither disappears with the block.
        let caller =
            r#"function f(){{var v={a:!0}}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_destructured_local_shadows_an_outer_binding() {
        let caller = r#"var x=!0;function f(t){let{x}=t;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_site_with_no_item_shape_withdraws_the_other_sites_item_keys() {
        // One call sends a list literal, the other hands over a value this pass
        // cannot enumerate: the first cannot speak for the second's elements.
        let caller = r#"function f(t){if(t)return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:[{a:!0}]});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:t.other})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let item = tree["input"].items.as_ref().expect("list element node");
        assert_eq!(item.fields["a"].presence, VariablePresence::Undetermined);
        assert_eq!(item.presence, VariablePresence::Always);
    }

    #[test]
    fn an_assignment_updates_the_binding_it_targets() {
        // `x` lives in the block, so the write has to land there: putting it in
        // the function frame left `lookup` reaching the block's older value.
        let caller = r#"function f(t){{let x=!0;x=t.x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_update_expression_is_a_number() {
        // `x++` never yields `undefined`; at worst it is `NaN`, which serializes
        // as `null` with the key still on the wire.
        let caller =
            r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{count:t.n++})}"#;
        let (tree, _) = presence_of(caller, &["count"]);
        assert_eq!(at(&tree, "count"), VariablePresence::Always);
    }

    #[test]
    fn an_unreadable_call_is_not_a_missing_call_site() {
        // The two drop reasons answer different questions, so an operation whose
        // only call could not be read must not be reported as having none.
        let caller =
            r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),t.opts)}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_call_arguments, 1);
        assert_eq!(
            diag.operations_without_call_site, 0,
            "a call was found; it could not be read"
        );
    }

    #[test]
    fn a_catch_parameter_shadows_an_outer_binding() {
        let caller = r#"var x=!0;function f(){try{g()}catch(x){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn opacity_travels_out_of_a_spread_chain() {
        // The unreadable spread is one level in, so the outer site is not fully
        // known either: a declared key nothing wrote may still come from `opts`.
        let caller = r#"function f(t){var base={...t.opts};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{...base})}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_spreads, 1);
    }

    #[test]
    fn an_unresolvable_handle_in_a_multi_operation_module_is_not_ignored() {
        // The module sends more than one operation and this call's handle names
        // none of them, so it may be ours and may contradict the readable site.
        // Silently dropping it would let the readable one decide alone.
        let caller = r#"function f(t,h){o("C").fetchQuery(h,{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.ambiguous_call_sites, 1);
    }

    #[test]
    fn a_handle_naming_another_operation_is_still_skipped() {
        // Resolvable and not ours: that is knowledge, not ambiguity, so it must
        // not withdraw anything.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebOtherQuery.graphql"),{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(diag.ambiguous_call_sites, 0);
    }

    #[test]
    fn a_handle_naming_another_operation_on_only_one_branch_is_ambiguous() {
        // `h ? n("Other.graphql") : h` is one branch per call: the branch that
        // names another operation says nothing about the branch that does not,
        // and that one may be ours. Reading the resolved half as the whole
        // handle would drop this site and let the readable one answer alone.
        let caller = r#"function f(t,h){o("C").fetchQuery(h?n("WAWebOtherQuery.graphql"):h,{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.ambiguous_call_sites, 1);
    }

    #[test]
    fn a_memoised_handle_for_another_operation_is_still_skipped() {
        // WA's own memoising shape, and the letter it memoises into is reused as
        // a parameter of the very function that reads it - the arrangement of
        // `WAWebACSServerProvider`. The ternary reads the binding its own other
        // branch writes, so it is that module however the letter resolves
        // later: known, not ours, and it withdraws nothing.
        let caller = r#"var e,s,u=e!==void 0?e:e=n("WAWebOtherQuery.graphql"),c=s!==void 0?s:s=n("WAWebFooQuery.graphql");function f(e,t){o("C").fetchQuery(u,{a:e.x});return o("C").commitMutation(c,{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(diag.ambiguous_call_sites, 0);
    }

    #[test]
    fn a_var_first_written_inside_a_branch_keeps_its_hoisted_undefined() {
        // `var x` is `undefined` from the top of the function, and the write is
        // in a branch the call can be reached without, so the path around it
        // sends no key.
        let caller = r#"function f(t){if(t)var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_logical_assignment_is_not_a_plain_one() {
        // `x &&= !0` leaves `x` undefined when it is falsy, so the binding it
        // writes is the whole expression, not its right side.
        for caller in [
            r#"function f(){var x;x&&=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#,
            r#"function f(t){var x;x||=t.y;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#,
        ] {
            let (tree, _) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
        }
    }

    #[test]
    fn a_local_function_declaration_shadows_the_module() {
        // The local `x` is a function wherever the call sits, and
        // `JSON.stringify` drops a key whose value is one.
        let caller = r#"var x=!0;function f(){function x(){}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_write_through_a_key_reaches_the_recovered_object() {
        // `WAWebBizCreateOrderJob` builds the variables object and then adds a
        // key to it under a gate, one level down. The literal alone answers for
        // neither the overwritten key nor the added one.
        let overwritten = r#"function f(){var v={a:!0};v.a=void 0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(overwritten, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);

        let added = r#"function f(t){var v={input:{b:!0}};t!=null&&(v.input.a=t);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(added, &["input"]);
        assert_eq!(at(&tree, "input"), VariablePresence::Always);
        let input = &tree["input"];
        assert_eq!(input.fields["b"].presence, VariablePresence::Always);
        assert_eq!(
            input.fields["a"].presence,
            VariablePresence::Conditional,
            "written only on the gated path"
        );
    }

    #[test]
    fn a_write_this_pass_cannot_follow_withdraws_the_object() {
        // A computed key names nothing publishable, so what the binding holds
        // afterwards is no longer the literal that was read.
        let caller = r#"function f(t){var v={a:!0};v[t.k]=1;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
    }

    #[test]
    fn a_call_inside_a_branch_reads_what_that_branch_wrote() {
        // The only invocation runs after the write, so `a` is on every request
        // this module sends - joining with the pre-branch `undefined` would
        // publish an optional field for a key the client never omits.
        let caller = r#"function f(t){var x;if(t){x=!0;o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn the_other_arm_does_not_read_what_this_one_wrote() {
        // Each arm is its own branch: the `else` runs on the path where the `if`
        // did not, so the write above it is not evidence for the call below.
        let caller = r#"function f(t){var x;if(t){x=!0}else{o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn the_right_side_of_an_assignment_runs_before_the_write() {
        // `x = fetchQuery(op, {a: x})` sends the `x` from before the assignment,
        // so binding first would read the call against its own result.
        let caller = r#"function f(){var x=!0;x=o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});return x}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_rest_parameter_is_an_array_on_every_call() {
        // Including the call that passes nothing, where it is the empty array -
        // never `undefined`, so the key is on the wire.
        let caller =
            r#"function f(...t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:t})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn an_explicitly_nullish_variables_argument_is_a_site_that_writes_nothing() {
        // `fetchQuery(op, void 0)` carries no key, which is knowledge - not the
        // same as an argument this pass could not read.
        for caller in [
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),void 0)}"#,
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),null)}"#,
        ] {
            let (tree, diag) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
            assert_eq!(diag.unreadable_call_arguments, 0);
        }
        // And a value that merely might be undefined at run time is still unread.
        let unread =
            r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),t.vars)}"#;
        let (tree, diag) = presence_of(unread, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_call_arguments, 1);
    }

    #[test]
    fn an_unreadable_spread_nested_in_a_key_withdraws_that_key_across_sites() {
        // One site writes `{input: {...opts}}` and another `{input: {a: !0}}`.
        // Nothing says whether `opts` carries `a`, so the readable site does not
        // get to publish it as a key the client omits.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{...t.opts}});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{a:!0}})}"#;
        let names = vec!["input".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(&[(caller, false)], MODULE, &names, &mut diag);
        assert_eq!(
            at(&tree, "input"),
            VariablePresence::Always,
            "the key itself is written by both"
        );
        assert_eq!(
            tree["input"].fields["a"].presence,
            VariablePresence::Undetermined,
            "the spread may be supplying it"
        );
        assert_eq!(diag.unreadable_spreads, 1);
    }

    #[test]
    fn a_fallback_handle_is_read_on_both_sides() {
        // `h || n("Other.graphql")` hands the call `h` whenever it is there, so
        // the branch naming another operation says nothing about the branch that
        // may be naming this one.
        for handle in [
            "h||n(\"WAWebOtherQuery.graphql\")",
            "h??n(\"WAWebOtherQuery.graphql\")",
        ] {
            let caller = format!(
                r#"function f(t,h){{o("C").fetchQuery({handle},{{a:t.x}});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{{a:!0}})}}"#
            );
            let names = vec!["a".to_string()];
            let mut diag = PresenceDiagnostics::default();
            let tree = variables_presence(&[(caller.as_str(), false)], MODULE, &names, &mut diag);
            assert_eq!(at(&tree, "a"), VariablePresence::Undetermined, "{handle}");
            assert_eq!(diag.ambiguous_call_sites, 1, "{handle}");
        }
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
