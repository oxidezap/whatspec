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
    Argument, ArrayExpressionElement, AssignmentExpression, AssignmentOperator, BinaryOperator,
    CallExpression, Expression, LogicalOperator, ObjectExpression, ObjectPropertyKind, PropertyKey,
    UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
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

/// How many times a body that runs more than once is read again before the pass
/// gives up on its bindings settling. Every loop in the pinned bundles settles
/// on the first reading back; the bound is what keeps a body whose values keep
/// moving from being read forever.
const MAX_PASSES: usize = 6;

/// Join two values one call can see, keeping the arms distinct: a loop body
/// read again joins what it wrote with what it wrote last time, and nesting
/// those would grow a value that never settles without saying anything new.
fn either(before: Value, after: Value) -> Value {
    if contains_arm(&before, &after) {
        return before;
    }
    if contains_arm(&after, &before) {
        return after;
    }
    Value::Either(Box::new(before), Box::new(after))
}

/// Whether a value is already one of the values an `Either` tree can take.
fn contains_arm(value: &Value, arm: &Value) -> bool {
    if value == arm {
        return true;
    }
    match value {
        Value::Either(a, b) => contains_arm(a, arm) || contains_arm(b, arm),
        _ => false,
    }
}

/// A value expression, kept only as far as presence depends on it.
///
/// Owned rather than borrowed because oxc's visitor hands out node references
/// that do not outlive the callback, and the classification has to survive until
/// the binding it names is resolved. Every arm is a fact about evaluation rather
/// than about syntax: whether the expression can be `undefined`, and what keys it
/// carries if it is an object.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    /// No evaluation yields `undefined`: a literal, a comparison, a coercion, a
    /// function, a `new`.
    Defined,
    /// Can yield `undefined`: a property read, an optional chain, `void x`, a
    /// binding this module does not write.
    MaybeUndefined,
    /// A form this pass does not judge - a call's return value, an `await`.
    Unjudged,
    /// Defined, truthy, and still not a key on the wire: `JSON.stringify` drops
    /// a property whose value is a function or a class. Kept apart from
    /// `MaybeUndefined` because the difference decides `a || b` - a function on
    /// the left IS the value, where an undefined one hands over to `b`.
    Dropped,
    /// A value that is defined AND truthy: the literals `!0`, `1`, `"x"`. Held
    /// apart from [`Value::Defined`] because `x || y` is `x` only when `x` is
    /// truthy, and `x === !0` is defined while being `false` half the time.
    Truthy,
    /// An identifier, resolved against the enclosing bindings when read.
    Ref(String),
    Object(Vec<Prop>),
    Array(Vec<Value>),
    /// `a || b`: the result is `b` only when `a` is falsy, so a left side this
    /// pass knows to be truthy IS the value.
    OrElse(Box<Value>, Box<Value>),
    /// `a ?? b`: the result is `b` only when `a` is nullish, which is a
    /// different question from truthiness - `0 ?? x` is `0` and `0 || x` is
    /// `x` - and the two operators cannot share a node without answering one
    /// of them wrongly.
    Coalesce(Box<Value>, Box<Value>),
    /// `a && b`: can yield a falsy `a`, `undefined` included.
    AndThen(Box<Value>, Box<Value>),
    /// `c ? a : b`.
    Either(Box<Value>, Box<Value>),
    /// A call, with the module name when it takes a single string literal -
    /// which is how a Relay operation handle is written, `n("X.graphql")`. The
    /// arguments are not kept: what a call was handed says nothing about what it
    /// returns, and a handle is read from the require itself.
    Call(Option<String>),
}

#[derive(Debug, Clone, PartialEq)]
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
    /// Module-level names a module-level statement writes again after they are
    /// declared, with both values joined. A closure reads its free names when it
    /// RUNS, and the module's own initialization has finished by then, so inside
    /// a function these answer instead of the value standing at the point the
    /// function was walked.
    module_rewritten: HashMap<String, Value>,
    /// One log per branch being walked, innermost last. Each entry is a name the
    /// branch wrote and what it held when the branch began, which is what the
    /// path around the branch reaches.
    ///
    /// The write itself lands in the frame, so a call INSIDE the branch reads
    /// what the branch wrote - `if (t) { x = !0; fetchQuery(op, {a: x}) }` sends
    /// `a` on the only path that calls at all. The join with the pre-branch value
    /// happens on the way out, for the calls that follow.
    branches: Vec<Vec<BranchWrite>>,
    /// Every value written while a watch is open, for a block a `catch` can be
    /// entered from part-way through: the handler reads any of them, not only
    /// the one the block ended on.
    watched: Vec<Vec<(usize, String, Value)>>,
}

/// A name a branch wrote, with the value it had before the branch began.
struct BranchWrite {
    frame: usize,
    name: String,
    before: Option<Value>,
}

/// What one arm of an `if` left a name at, beside what it held before the
/// statement.
#[derive(Clone)]
struct ArmExit {
    frame: usize,
    name: String,
    before: Option<Value>,
    after: Option<Value>,
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
        self.write_frame(index, name, value);
    }

    /// Write a name in a frame that is already known, logging what it held when
    /// the branch being walked began.
    fn write_frame(&mut self, index: usize, name: &str, value: Value) {
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
        if let Some(watch) = self.watched.last_mut() {
            watch.push((index, name.to_string(), value.clone()));
        }
        self.frames[index].insert(name.to_string(), value);
    }

    /// Enter an arm that an earlier one can also reach: a `switch` case the
    /// case above it falls into, or a `catch` the block jumps into after some
    /// of its writes. Both the value from before the statement and the one that
    /// earlier arm left reach the code here, which is what `Either` says
    /// everywhere else in this pass.
    fn carry(&mut self, exits: &[ArmExit]) {
        let values: Vec<(usize, String, Value)> = exits
            .iter()
            .filter_map(|exit| Some((exit.frame, exit.name.clone(), exit.after.clone()?)))
            .collect();
        self.carry_values(&values);
    }

    /// The same for values named directly rather than read off an arm's exit: a
    /// `catch` is entered from any point in the block, so every value the block
    /// passed through reaches it and not only the one it ended on.
    fn carry_values(&mut self, values: &[(usize, String, Value)]) {
        for (frame, name, value) in values {
            if *frame >= self.frames.len() {
                continue;
            }
            let here = self.frames[*frame]
                .get(name)
                .or_else(|| self.frame_hoisted[*frame].get(name))
                .cloned();
            let joined = match here {
                Some(before) => either(before, value.clone()),
                None => value.clone(),
            };
            self.write_frame(*frame, name, joined);
        }
    }

    /// Start recording every value written from here on, for a block whose
    /// intermediate states another path can see.
    fn watch(&mut self) {
        self.watched.push(Vec::new());
    }

    /// Stop recording, and hand back what was written while it was open.
    fn watched(&mut self) -> Vec<(usize, String, Value)> {
        self.watched.pop().unwrap_or_default()
    }

    /// `var w = v` makes `w` another way of saying `v`, and it stays one only
    /// while `v` names the same object: `v = {…}` afterwards leaves `w` holding
    /// what it was handed. Following the name instead gave `w` an object it
    /// never saw. A write THROUGH an alias (`w.a = …`) is the opposite case and
    /// keeps the link, which is why this is not part of `bind_assignment`.
    fn detach_aliases(&mut self, name: &str) {
        let current = self.lookup(name).cloned().unwrap_or(Value::MaybeUndefined);
        let aliases: Vec<(usize, String)> = self
            .frames
            .iter()
            .enumerate()
            .flat_map(|(index, frame)| {
                frame.iter().filter_map(move |(alias, value)| match value {
                    Value::Ref(target) if target == name => Some((index, alias.clone())),
                    _ => None,
                })
            })
            .collect();
        for (frame, alias) in aliases {
            self.write_frame(frame, &alias, current.clone());
        }
    }

    /// Whether a frame binds the name itself, rather than inheriting it from an
    /// enclosing one.
    fn binds_here(&self, index: usize, name: &str) -> bool {
        self.frames
            .get(index)
            .is_some_and(|frame| frame.contains_key(name))
    }

    /// Start a branch: writes inside it are what the code inside it reads.
    fn enter_branch(&mut self) {
        self.branches.push(Vec::new());
    }

    /// End a branch WITHOUT joining: hand back what it wrote and put the values
    /// from before it back, so a sibling arm starts where this one did.
    fn take_branch(&mut self) -> Vec<ArmExit> {
        let log = self.branches.pop().unwrap_or_default();
        let mut exits = Vec::new();
        for write in log {
            if write.frame >= self.frames.len() {
                continue;
            }
            let after = self.frames[write.frame].remove(&write.name);
            if let Some(before) = &write.before {
                self.frames[write.frame].insert(write.name.clone(), before.clone());
            }
            exits.push(ArmExit {
                frame: write.frame,
                name: write.name,
                before: write.before,
                after,
            });
        }
        exits
    }

    /// Apply the two arms of an `if`: a name BOTH arms write reaches the code
    /// after them as one of their two values and never as the one from before,
    /// because no path gets past the statement without taking an arm.
    fn join_arms(&mut self, first: Vec<ArmExit>, second: Vec<ArmExit>) {
        self.join_all_arms(vec![first, second], true);
    }

    /// The same over any number of arms. `exhaustive` says whether some arm
    /// always runs: an `if`/`else` pair leaves no way past it, a `switch`
    /// without a `default` does, and a name every arm writes only loses its
    /// earlier value in the first case.
    fn join_all_arms(&mut self, arms: Vec<Vec<ArmExit>>, exhaustive: bool) {
        let count = arms.len();
        let mut merged: Vec<(ArmExit, usize)> = Vec::new();
        for arm in arms {
            for exit in arm {
                match merged
                    .iter_mut()
                    .find(|(m, _)| m.frame == exit.frame && m.name == exit.name)
                {
                    Some((m, written)) => {
                        m.after = match (m.after.take(), exit.after) {
                            (Some(a), Some(b)) => Some(either(a, b)),
                            (a, b) => a.or(b),
                        };
                        *written += 1;
                    }
                    None => merged.push((exit, 1)),
                }
            }
        }
        for (mut exit, written) in merged {
            if exit.frame >= self.frames.len() {
                continue;
            }
            // Written on every path through the statement, so what it held
            // before it is a value nothing below can still see.
            if exhaustive && written == count {
                exit.before = None;
            }
            let Some(after) = exit.after else {
                continue;
            };
            let value = match &exit.before {
                Some(before) => either(before.clone(), after),
                None => after,
            };
            self.frames[exit.frame].insert(exit.name.clone(), value);
            if let Some(outer) = self.branches.last_mut()
                && !outer
                    .iter()
                    .any(|w| w.frame == exit.frame && w.name == exit.name)
            {
                outer.push(BranchWrite {
                    frame: exit.frame,
                    name: exit.name,
                    before: exit.before,
                });
            }
        }
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
                    self.frames[write.frame]
                        .insert(write.name.clone(), either(before.clone(), after));
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
        // Inside a function, a name the module writes again after declaring it
        // is whatever those writes leave: the code here runs after all of them,
        // however early in the file it is written.
        let inside_function = self.frames.len() > 1;
        if inside_function
            && let Some(rewritten) = self.module_rewritten.get(name)
            && !self
                .frames
                .iter()
                .skip(1)
                .zip(self.frame_hoisted.iter().skip(1))
                .any(|(bound, hoisted)| bound.contains_key(name) || hoisted.contains_key(name))
        {
            return Some(rewritten);
        }
        self.frames
            .iter()
            .zip(&self.frame_hoisted)
            .rev()
            .find_map(|(bound, hoisted)| bound.get(name).or_else(|| hoisted.get(name)))
            .or_else(|| self.hoisted.get(name))
    }
    /// The name that owns what `name` refers to: `var w = v` makes `w` another
    /// way of saying `v`, and a write through either reaches one object.
    fn alias_target(&self, name: &str, depth: usize) -> String {
        if depth >= MAX_DEPTH {
            return name.to_string();
        }
        match self.lookup(name) {
            Some(Value::Ref(target)) => {
                let target = target.clone();
                self.alias_target(&target, depth + 1)
            }
            _ => name.to_string(),
        }
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
        | Expression::BinaryExpression(_) => match falsy_literal(expr) {
            Some(false) => Value::Truthy,
            _ => Value::Defined,
        },

        // A defined value is not the same as a value that survives the wire.
        // `JSON.stringify` drops a property whose value is a function, so
        // `{a: () => !0}` serializes to `{}` and the key is never sent. Being
        // defined is the test for `undefined`, not proof the key arrives.
        Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_) => Value::Dropped,

        // `new X()` never evaluates to `undefined`, but the instance decides its
        // own serialization: a `toJSON` returning `undefined` drops the key.
        // Which class it is, and what it does there, is not something this pass
        // establishes.
        Expression::NewExpression(_) => Value::Unjudged,

        // `!x`, `!!x`, `typeof x`, `-x` yield primitives; `void x` IS `undefined`,
        // so it is the one unary that does not.
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::Void => Value::MaybeUndefined,
            // `!0` is how the minifier writes `true`, and its truthiness is as
            // readable as the literal's.
            _ => match falsy_literal(expr) {
                Some(false) => Value::Truthy,
                _ => Value::Defined,
            },
        },

        Expression::LogicalExpression(l) => match l.operator {
            // `!0 || x` never evaluates `x`, and neither does `0 ?? x`: one asks
            // whether the left side is truthy and the other whether it is
            // nullish, and a literal answers without the right side running. The
            // fallback arm below decides on the right operand, which for these
            // two is an operand the expression never reaches.
            LogicalOperator::Or => match falsy_literal(&l.left) {
                Some(false) => convert(&l.left, next),
                Some(true) => convert(&l.right, next),
                None => Value::OrElse(
                    Box::new(convert(&l.left, next)),
                    Box::new(convert(&l.right, next)),
                ),
            },
            LogicalOperator::Coalesce => match nullish_literal(&l.left) {
                Some(false) => convert(&l.left, next),
                Some(true) => convert(&l.right, next),
                None => Value::Coalesce(
                    Box::new(convert(&l.left, next)),
                    Box::new(convert(&l.right, next)),
                ),
            },
            // `false && x` never evaluates `x`: the expression IS the left side,
            // and a literal there settles it either way. Only an operand this
            // pass cannot decide leaves both in play.
            LogicalOperator::And => match falsy_literal(&l.left) {
                Some(true) => convert(&l.left, next),
                Some(false) => convert(&l.right, next),
                None => Value::AndThen(
                    Box::new(convert(&l.left, next)),
                    Box::new(convert(&l.right, next)),
                ),
            },
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

        Expression::CallExpression(c) => {
            Value::Call(wa_oxc::first_string_arg(c).map(str::to_string))
        }

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
            // `{...null}` and `{...void 0}` are no-ops: object spread ignores a
            // nullish source rather than failing, so the keys written beside it
            // stand. Reading the source as unknown withdrew them instead.
            ObjectPropertyKind::SpreadProperty(s) => match is_nullish_literal(&s.argument) {
                true => Prop::Spread(Value::Object(Vec::new())),
                false => Prop::Spread(convert(&s.argument, depth)),
            },
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
        Value::Defined | Value::Truthy | Value::Object(_) | Value::Array(_) => Definedness::Defined,
        Value::MaybeUndefined | Value::Dropped => Definedness::MaybeUndefined,
        Value::Unjudged | Value::Call(_) => Definedness::Unjudged,
        // `a || b` is `b` only when `a` is falsy. A left side this pass knows to
        // be truthy is therefore the value, an object, an array and a function
        // included - and a function is the one whose key `JSON.stringify` drops.
        Value::OrElse(lhs, rhs) => match scopes.resolve(lhs, 0) {
            Value::Truthy | Value::Object(_) | Value::Array(_) => definedness(lhs, scopes, next),
            Value::Dropped => Definedness::MaybeUndefined,
            _ => definedness(rhs, scopes, next),
        },
        // `a ?? b` asks the other question: `0 ?? b` is `0`, which `a || b`
        // would have thrown away. Anything this pass knows to be neither `null`
        // nor `undefined` is the value.
        Value::Coalesce(lhs, rhs) => match scopes.resolve(lhs, 0) {
            Value::Defined | Value::Truthy | Value::Object(_) | Value::Array(_) => {
                definedness(lhs, scopes, next)
            }
            Value::Dropped => Definedness::MaybeUndefined,
            _ => definedness(rhs, scopes, next),
        },
        // `a && b` is `b` whenever `a` is truthy, and a function always is.
        Value::AndThen(lhs, rhs) => match scopes.resolve(lhs, 0) {
            Value::Dropped => definedness(rhs, scopes, next),
            _ => definedness(lhs, scopes, next).max(definedness(rhs, scopes, next)),
        },
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

/// [`classify_object`], plus the paths under it whose keys are not fully known:
/// each names an object a spread or a computed key may still be writing into,
/// the empty path being this object itself. A sibling site must not answer for
/// those keys, so they are withdrawn once every site has been merged.
fn classify_object_reporting(
    props: &[Prop],
    scopes: &Scopes,
    diag: &mut PresenceDiagnostics,
    depth: usize,
) -> (SiteTree, Vec<Opaque>) {
    let mut opaque: Vec<Opaque> = Vec::new();
    let mut out: SiteTree = BTreeMap::new();
    // A spread whose source resolves back through itself (`var e = {...e}`)
    // would otherwise descend forever, and an extractor that aborts publishes
    // nothing at all.
    if depth >= MAX_DEPTH {
        diag.unreadable_spreads += 1;
        return (out, vec![Opaque::here()]);
    }
    for prop in props {
        match prop {
            Prop::Unreadable => {
                // A computed key names something this pass cannot read, and that
                // something may be a key already written: `{a: !0, [k]: void 0}`
                // drops `a` when `k` is `"a"`. Same rule as an unreadable spread,
                // and a later explicit write still restores the key.
                diag.unreadable_keys += 1;
                opaque.push(Opaque::here());
                for node in out.values_mut() {
                    withdraw(node);
                }
            }
            // `JSON.stringify` calls an object's own `toJSON` and serializes what
            // that returns, so the keys written beside it may reach the wire or
            // may not - and what the hook returns is a function body this pass
            // does not read. Only when the value is one it will call: `{toJSON:
            // null}` is serialized as an ordinary key of that name.
            Prop::Key(key, value) if key == "toJSON" && may_be_called(value, scopes, depth) => {
                opaque.push(Opaque::here());
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
                for mut nested in nested {
                    nested.path.insert(0, Step::Field(key.clone()));
                    opaque.push(nested);
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
                        opaque.push(Opaque::here());
                        for node in out.values_mut() {
                            withdraw(node);
                        }
                    }
                }
            }
        }
    }
    // Every key this object ends up carrying is one the site itself wrote, at a
    // value it read: `{...opts, a: !0}` writes `a` after the spread whatever
    // `opts` holds. Only the keys it does NOT carry are the ones an unreadable
    // spread might be supplying, and only those are withdrawn once the sites are
    // merged.
    let serialized_whole = props
        .iter()
        .any(|p| matches!(p, Prop::Key(key, _) if key == "toJSON"));
    for record in &mut opaque {
        if record.path.is_empty() && !serialized_whole {
            record.written = out.keys().cloned().collect();
        }
    }
    (out, opaque)
}

/// An object whose keys are not fully known, by the path that reaches it, with
/// the keys the site did write there.
struct Opaque {
    path: Vec<Step>,
    written: Vec<String>,
}

impl Opaque {
    fn here() -> Self {
        Opaque {
            path: Vec::new(),
            written: Vec::new(),
        }
    }
}

/// One step of a path into a presence tree.
enum Step {
    Field(String),
    Item,
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
) -> (VariablePresenceNode, Vec<Opaque>) {
    let presence = definedness(value, scopes, 0).presence().weaker(floor);
    let mut node = VariablePresenceNode::leaf(presence);
    let mut opaque: Vec<Opaque> = Vec::new();
    if depth >= MAX_DEPTH {
        return (node, opaque);
    }
    match scopes.resolve(value, 0) {
        Value::Object(props) => {
            let (fields, nested) = classify_object_reporting(props, scopes, diag, depth + 1);
            node.fields = fields;
            opaque.extend(nested);
            // The hook decides what this object serializes to, and `undefined`
            // is one of the things it can return - which drops the key holding
            // it, not only the keys inside it.
            if props.iter().any(|prop| match prop {
                Prop::Key(key, value) => key == "toJSON" && may_be_called(value, scopes, depth),
                _ => false,
            }) {
                withdraw(&mut node);
            }
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
                let (here, nested) = classify_object_reporting(props, scopes, diag, depth + 1);
                // An element's own unknowns belong to the element node, which is
                // one step further down the path than this key.
                for mut record in nested {
                    record.path.insert(0, Step::Item);
                    opaque.push(record);
                }
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
            // A class binds its name for the block that declares it, and its
            // value is a function - a key holding one does not reach the wire
            // either. Collected with the `var`s because shadowing is the point:
            // the outer name must not answer for the local one.
            S::ClassDeclaration(c) => {
                if let Some(id) = &c.id {
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

/// The names a block declares with `let`, `const`, `class` or a function
/// declaration, as the `undefined` they hold before the declaration runs.
fn lexical_names(statements: &[oxc_ast::ast::Statement]) -> HashMap<String, Value> {
    use oxc_ast::ast::Statement as S;
    let mut out = HashMap::new();
    for stmt in statements {
        match stmt {
            S::VariableDeclaration(decl) if !decl.kind.is_var() => {
                for d in &decl.declarations {
                    for ident in d.id.get_binding_identifiers() {
                        out.insert(ident.name.as_str().to_string(), Value::MaybeUndefined);
                    }
                }
            }
            S::ClassDeclaration(c) => {
                if let Some(id) = &c.id {
                    out.insert(id.name.as_str().to_string(), Value::MaybeUndefined);
                }
            }
            S::FunctionDeclaration(f) => {
                if let Some(id) = &f.id {
                    out.insert(id.name.as_str().to_string(), Value::MaybeUndefined);
                }
            }
            _ => {}
        }
    }
    out
}

/// The module's own top-level `var`/`let`/`const` bindings./// The module's own top-level `var`/`let`/`const` bindings.
///
/// Only that level: a name declared inside one function says nothing about the
/// same spelling inside another, and the minifier reuses single letters
/// everywhere. Both shapes are read, the bare program body and the body of a
/// `__d("Name", deps, factory)` factory, since a WA module is the latter and the
/// unit tests exercise the former.
fn hoist_module_bindings(
    program: &oxc_ast::ast::Program,
) -> (HashMap<String, Value>, HashMap<String, Value>) {
    let mut out = HashMap::new();
    let mut rewritten = HashMap::new();
    collect_declarations(&program.body, &mut out);
    collect_module_writes(&program.body, &out, &mut rewritten);
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
                collect_module_writes(&body.statements, &out, &mut rewritten);
            }
        }
    }
    (out, rewritten)
}

/// Module-level writes to those bindings, joined with what they were declared
/// with.
///
/// A closure resolves its free names when it RUNS, and a module's own
/// initialization runs first: `var x = !0; function f(){…x…} x = void 0;` calls
/// `f` with `x` at `undefined`. Reading the declaration alone published the
/// value the name never has by the time the call happens. Only statements of the
/// module itself - a function body is a later call, not initialization.
fn collect_module_writes(
    statements: &[oxc_ast::ast::Statement],
    declared: &HashMap<String, Value>,
    out: &mut HashMap<String, Value>,
) {
    for stmt in statements {
        let oxc_ast::ast::Statement::ExpressionStatement(es) = stmt else {
            continue;
        };
        // `x = void 0, e = f;` is one statement and two writes: the minifier
        // writes initialization as a comma expression as readily as as a series
        // of statements.
        let expressions: Vec<&Expression> = match &es.expression {
            Expression::SequenceExpression(seq) => seq.expressions.iter().collect(),
            other => vec![other],
        };
        for expression in expressions {
            let Expression::AssignmentExpression(a) = expression else {
                continue;
            };
            let Some(name) = wa_oxc::assignment_target_name(&a.left) else {
                continue;
            };
            let Some(prior) = out.get(name).or_else(|| declared.get(name)) else {
                continue;
            };
            let joined = Value::Either(Box::new(prior.clone()), Box::new(assignment_value(a, 0)));
            out.insert(name.to_string(), joined);
        }
    }
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

/// Every name an object or array assignment pattern writes: `({x} = opts)`,
/// `[a, b] = pair`. `None` when the target is not a pattern.
fn destructured_assignment_names(target: &oxc_ast::ast::AssignmentTarget) -> Option<Vec<String>> {
    use oxc_ast::ast::AssignmentTarget as T;
    let pattern = match target {
        T::ObjectAssignmentTarget(_) | T::ArrayAssignmentTarget(_) => target,
        _ => return None,
    };
    let mut names = Vec::new();
    collect_assignment_target_names(pattern, &mut names);
    Some(names)
}

fn collect_assignment_target_names(target: &oxc_ast::ast::AssignmentTarget, out: &mut Vec<String>) {
    use oxc_ast::ast::{
        AssignmentTarget as T, AssignmentTargetMaybeDefault as D, AssignmentTargetProperty as P,
    };
    match target {
        T::AssignmentTargetIdentifier(id) => out.push(id.name.as_str().to_string()),
        T::ObjectAssignmentTarget(o) => {
            for property in &o.properties {
                match property {
                    P::AssignmentTargetPropertyIdentifier(id) => {
                        out.push(id.binding.name.as_str().to_string());
                    }
                    P::AssignmentTargetPropertyProperty(p) => match &p.binding {
                        D::AssignmentTargetWithDefault(d) => {
                            collect_assignment_target_names(&d.binding, out);
                        }
                        other => {
                            if let Some(target) = other.as_assignment_target() {
                                collect_assignment_target_names(target, out);
                            }
                        }
                    },
                }
            }
            if let Some(rest) = &o.rest {
                collect_assignment_target_names(&rest.target, out);
            }
        }
        T::ArrayAssignmentTarget(a) => {
            for element in a.elements.iter().flatten() {
                match element {
                    D::AssignmentTargetWithDefault(d) => {
                        collect_assignment_target_names(&d.binding, out);
                    }
                    other => {
                        if let Some(target) = other.as_assignment_target() {
                            collect_assignment_target_names(target, out);
                        }
                    }
                }
            }
            if let Some(rest) = &a.rest {
                collect_assignment_target_names(&rest.target, out);
            }
        }
        _ => {}
    }
}

/// The name a member assignment writes through/// The name a member assignment writes through: `v.a.b = x` is a write to `v`.
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

/// A value with its bindings read now rather than later: the same value, with
/// every `Ref` replaced by what it holds at this point.
fn settle(value: &Value, scopes: &Scopes, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return value.clone();
    }
    let next = depth + 1;
    match value {
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => settle(&bound.clone(), scopes, next),
            None => value.clone(),
        },
        Value::Object(props) => Value::Object(
            props
                .iter()
                .map(|prop| match prop {
                    Prop::Key(key, inner) => Prop::Key(key.clone(), settle(inner, scopes, next)),
                    Prop::Spread(inner) => Prop::Spread(settle(inner, scopes, next)),
                    Prop::Unreadable => Prop::Unreadable,
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| settle(item, scopes, next))
                .collect(),
        ),
        Value::OrElse(a, b) => Value::OrElse(
            Box::new(settle(a, scopes, next)),
            Box::new(settle(b, scopes, next)),
        ),
        Value::Coalesce(a, b) => Value::Coalesce(
            Box::new(settle(a, scopes, next)),
            Box::new(settle(b, scopes, next)),
        ),
        Value::AndThen(a, b) => Value::AndThen(
            Box::new(settle(a, scopes, next)),
            Box::new(settle(b, scopes, next)),
        ),
        Value::Either(a, b) => Value::Either(
            Box::new(settle(a, scopes, next)),
            Box::new(settle(b, scopes, next)),
        ),
        other => other.clone(),
    }
}

/// Whether a literal is falsy/// Whether a literal is falsy, when the expression IS a literal: `Some(true)`
/// for `!1`, `0`, `""`, `null`, `void 0`, `Some(false)` for a literal that is
/// not, and `None` for anything whose truthiness this pass does not decide.
fn falsy_literal(expr: &Expression) -> Option<bool> {
    match expr {
        Expression::BooleanLiteral(b) => Some(!b.value),
        Expression::NullLiteral(_) => Some(true),
        Expression::NumericLiteral(n) => Some(n.value == 0.0),
        Expression::StringLiteral(s) => Some(s.value.is_empty()),
        Expression::ParenthesizedExpression(p) => falsy_literal(&p.expression),
        // `!0` and `!1`, which is how the minifier writes the booleans.
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            falsy_literal(&u.argument).map(|falsy| !falsy)
        }
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void => Some(true),
        _ => None,
    }
}

/// Whether an expression IS `null`, `undefined` or `void 0`, spelled out at the
/// call rather than reached through a binding. A property read that happens to
/// be undefined at run time is not this: it is a value this pass cannot read.
/// Whether a literal is nullish, when the expression IS a literal: `Some(true)`
/// for `null` and `void 0`, `Some(false)` for a literal that is neither, and
/// `None` for anything whose nullishness this pass does not decide. The
/// counterpart of [`falsy_literal`] for `??`, which asks a different question of
/// its left operand than `||` does.
fn nullish_literal(expr: &Expression) -> Option<bool> {
    match expr {
        Expression::NullLiteral(_) => Some(true),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void => Some(true),
        Expression::Identifier(id) if id.name.as_str() == "undefined" => None,
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_) => Some(false),
        Expression::ParenthesizedExpression(p) => nullish_literal(&p.expression),
        _ => None,
    }
}

/// Whether a value could be a function, which is the only thing
/// `JSON.stringify` calls a `toJSON` for. Anything this pass has not resolved
/// could be one.
fn may_be_called(value: &Value, scopes: &Scopes, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return true;
    }
    let next = depth + 1;
    match scopes.resolve(value, 0) {
        Value::Defined | Value::Truthy | Value::Object(_) | Value::Array(_) => false,
        Value::Either(a, b)
        | Value::OrElse(a, b)
        | Value::Coalesce(a, b)
        | Value::AndThen(a, b) => may_be_called(a, scopes, next) || may_be_called(b, scopes, next),
        _ => true,
    }
}

/// Whether a statement always ends the function it sits in, so nothing after it
/// runs with what it wrote. Only `return`: a `throw` is read by an enclosing
/// handler, which is exactly the state those writes leave.
fn always_returns(stmt: &oxc_ast::ast::Statement) -> bool {
    match stmt {
        oxc_ast::ast::Statement::ReturnStatement(_) => true,
        oxc_ast::ast::Statement::BlockStatement(b) => b.body.last().is_some_and(always_returns),
        oxc_ast::ast::Statement::IfStatement(i) => {
            always_returns(&i.consequent)
                && i.alternate.as_ref().is_some_and(|arm| always_returns(arm))
        }
        _ => false,
    }
}

/// Whether a statement always leaves the statement enclosing it: the `break`
/// that ends a `switch` case, and every other abrupt completion. A case ending
/// in one is a case the one above it does not fall into.
fn always_leaves(stmt: &oxc_ast::ast::Statement) -> bool {
    match stmt {
        oxc_ast::ast::Statement::BreakStatement(_)
        | oxc_ast::ast::Statement::ContinueStatement(_)
        | oxc_ast::ast::Statement::ReturnStatement(_)
        | oxc_ast::ast::Statement::ThrowStatement(_) => true,
        oxc_ast::ast::Statement::BlockStatement(b) => b.body.last().is_some_and(always_leaves),
        _ => false,
    }
}

fn is_nullish_literal(expr: &Expression) -> bool {
    match expr {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name.as_str() == "undefined",
        Expression::UnaryExpression(u) => u.operator == UnaryOperator::Void,
        Expression::ParenthesizedExpression(p) => is_nullish_literal(&p.expression),
        _ => false,
    }
}

/// The binding a member expression reads through and the static path from it:
/// `v.order.jid` gives `("v", ["order", "jid"])`. `None` for a computed key or
/// anything but a plain binding at the root.
/// Whether an expression is reached through an optional link, so the call it is
/// the callee of may never happen: `t?.m(…)` runs nothing when `t` is nullish.
fn optional_link(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(m) => m.optional || optional_link(&m.object),
        Expression::ComputedMemberExpression(m) => m.optional || optional_link(&m.object),
        Expression::PrivateFieldExpression(m) => m.optional || optional_link(&m.object),
        Expression::ParenthesizedExpression(p) => optional_link(&p.expression),
        Expression::ChainExpression(_) => true,
        _ => false,
    }
}

/// The name a method is called on, when it is a plain identifier: the receiver
/// of `v.clear()`.
fn callee_receiver<'b, 'a>(callee: &'b Expression<'a>) -> Option<&'b str> {
    let object = match callee {
        Expression::StaticMemberExpression(m) => &m.object,
        Expression::ComputedMemberExpression(m) => &m.object,
        Expression::ParenthesizedExpression(p) => return callee_receiver(&p.expression),
        _ => return None,
    };
    match object {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn member_path<'b, 'a>(expr: &'b Expression<'a>) -> Option<(&'b str, Vec<String>)> {
    let Expression::StaticMemberExpression(member) = expr else {
        return None;
    };
    let mut path = vec![member.property.name.as_str().to_string()];
    let mut current = &member.object;
    loop {
        match current {
            Expression::Identifier(id) => {
                path.reverse();
                return Some((id.name.as_str(), path));
            }
            Expression::StaticMemberExpression(m) => {
                path.push(m.property.name.as_str().to_string());
                current = &m.object;
            }
            Expression::ParenthesizedExpression(p) => current = &p.expression,
            _ => return None,
        }
    }
}

/// The static property path a member assignment writes/// The static property path a member assignment writes, from the binding
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
        AssignmentOperator::LogicalOr => Value::OrElse(
            Box::new(Value::MaybeUndefined),
            Box::new(convert(&a.right, depth)),
        ),
        AssignmentOperator::LogicalNullish => Value::Coalesce(
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
    // Which arm the test sends the already-written binding down. Without this
    // the shape alone is not enough: `flag ? x : x = !0` also reads a binding on
    // one side and writes it on the other, and on the `flag` path it is
    // `undefined` - the opposite of what a memoised require guarantees.
    let (guarded, read_arm_is_consequent) = nullish_guard(&cond.test)?;
    let (read, write) = if read_arm_is_consequent {
        (&cond.consequent, &cond.alternate)
    } else {
        (&cond.alternate, &cond.consequent)
    };
    let Expression::Identifier(id) = read else {
        return None;
    };
    let Expression::AssignmentExpression(a) = write else {
        return None;
    };
    (id.name.as_str() == guarded
        && a.operator == AssignmentOperator::Assign
        && wa_oxc::assignment_target_name(&a.left) == Some(guarded))
    .then_some(&a.right)
}

/// A test that asks whether one binding is already there: the name it asks
/// about, and whether the consequent is the arm on which it IS. `e !== void 0`
/// and `e != null` put it in the consequent; `e === void 0` and `e == null` put
/// it in the alternate.
fn nullish_guard<'b, 'a>(test: &'b Expression<'a>) -> Option<(&'b str, bool)> {
    let Expression::BinaryExpression(b) = test else {
        return None;
    };
    // A strict comparison has to be against `void 0` itself: `undefined !== null`
    // is true, so `x !== null` leaves `x` undefined on the branch the memo
    // pattern promises is written. A loose one covers both nullish values.
    let (defined_in_consequent, strict) = match b.operator {
        BinaryOperator::StrictInequality => (true, true),
        BinaryOperator::Inequality => (true, false),
        BinaryOperator::StrictEquality => (false, true),
        BinaryOperator::Equality => (false, false),
        _ => return None,
    };
    let name = |e: &'b Expression<'a>| match e {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    };
    // `void 0` and `null` only: the name `undefined` can be bound to anything,
    // and a guard that is not a guard would collapse a ternary that is not a
    // memo.
    let intrinsic = |e: &Expression| {
        let void = matches!(e, Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void);
        void || (!strict && matches!(e, Expression::NullLiteral(_)))
    };
    let named = name(&b.left)
        .filter(|_| intrinsic(&b.right))
        .or_else(|| name(&b.right).filter(|_| intrinsic(&b.left)))?;
    Some((named, defined_in_consequent))
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
        // The require itself, not any call that happens to be handed one:
        // `select(h, n("Other.graphql"))` may return `h`, and `h` may be this
        // operation.
        Value::Call(name) => name.as_deref().is_some_and(|n| n.ends_with(".graphql")),
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
        Value::OrElse(lhs, rhs) | Value::Coalesce(lhs, rhs) => {
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
        // The require itself. A call merely HANDED the module may return
        // something else: `select(h, n("X.graphql"))` is not `n("X.graphql")`.
        Value::Call(name) => name.as_deref() == Some(module),
        // Every branch, because one call takes one of them. `h || n("X.graphql")`
        // hands the call `h` whenever `h` is there, so reading it as this
        // operation's would merge whatever `h` sends into this operation's
        // evidence - and with one site, an unsupported `always`.
        Value::Either(a, b) => {
            references_module(a, module, scopes, next) && references_module(b, module, scopes, next)
        }
        Value::OrElse(lhs, rhs) | Value::Coalesce(lhs, rhs) => {
            references_module(lhs, module, scopes, next)
                && references_module(rhs, module, scopes, next)
        }
        // `a && b` hands the call `b`, or a falsy `a` that is no handle at all.
        Value::AndThen(_, rhs) => references_module(rhs, module, scopes, next),
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => references_module(bound, module, scopes, next),
            None => false,
        },
        _ => false,
    }
}

/// Whether ANY value the handle can take names `module`. The mirror of
/// [`references_module`], which asks whether every one of them does: between the
/// two sits a handle that is sometimes this operation and sometimes not, which
/// is a call this pass cannot read as either.
fn may_reference_module(value: &Value, module: &str, scopes: &Scopes, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let next = depth + 1;
    match value {
        Value::Call(name) => name.as_deref() == Some(module),
        Value::Either(a, b) | Value::OrElse(a, b) | Value::Coalesce(a, b) => {
            may_reference_module(a, module, scopes, next)
                || may_reference_module(b, module, scopes, next)
        }
        Value::AndThen(_, rhs) => may_reference_module(rhs, module, scopes, next),
        Value::Ref(name) => match scopes.lookup(name) {
            Some(bound) => may_reference_module(bound, module, scopes, next),
            None => false,
        },
        _ => false,
    }
}

// ─── the caller-module scan ───// ─── the caller-module scan ──────────────────────────────────────────────────

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
    opaque_paths: Vec<Opaque>,
    /// Whether this pass is a second reading of a body already walked - a loop
    /// on its way round again. Its call sites are real and are kept; what it
    /// could not read was already counted the first time.
    replaying: bool,
    /// Where each matched call's variables argument starts in this caller. The
    /// shape pass reads the same text and needs the same calls: one that belongs
    /// to another operation of the same module is not this operation's shape
    /// either.
    variable_arguments: Vec<u32>,
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
        // `var f = function x(){…x…}` sees its own name throughout its body, and
        // that name is the function - a key holding one is dropped by
        // `JSON.stringify`, so an outer `x` must not answer for it.
        if let Some(id) = &func.id {
            self.scopes.bind(id.name.as_str(), Value::MaybeUndefined);
        }
        self.bind_params(&func.params);
        // A function body is a branch of its own: whether it ever runs is not
        // this pass's to say, so what it writes to an enclosing binding reaches
        // the code inside it and joins with the old value for everything else.
        // `function init(){x = !0}` beside `function send(){…x…}` is the case -
        // `send` may be called without `init` ever having been. And it is walked
        // twice for the same reason a loop body is: a function called again
        // reads what its own last call left behind.
        self.read_until_it_settles(|v| walk::walk_function(v, func, flags));
        self.scopes.pop();
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.scopes.push(hoisted_vars(&func.body));
        self.bind_params(&func.params);
        self.read_until_it_settles(|v| walk::walk_arrow_function_expression(v, func));
        self.scopes.pop();
    }

    /// A default runs only when the argument is missing, so what it writes is
    /// not something the body can count on: `function f(t = (z = !0))` leaves
    /// `z` undefined on every call that passes `t`.
    fn visit_formal_parameter(&mut self, param: &oxc_ast::ast::FormalParameter<'a>) {
        self.visit_binding_pattern(&param.pattern);
        if let Some(initializer) = &param.initializer {
            self.in_branch(|v| v.visit_expression(initializer));
        }
    }

    /// `let {x = (z = !0)} = opts` runs the default only when the property is
    /// missing, exactly like a parameter's.
    fn visit_assignment_pattern(&mut self, pattern: &oxc_ast::ast::AssignmentPattern<'a>) {
        self.visit_binding_pattern(&pattern.left);
        self.in_branch(|v| v.visit_expression(&pattern.right));
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
        // `let` and `const` cover the whole block, not the part after the line
        // that declares them: a closure written above one captures THAT binding,
        // so the names go in before the statements are walked.
        self.scopes.push_frame(lexical_names(&block.body), false);
        walk::walk_block_statement(self, block);
        self.scopes.pop();
    }

    /// Each arm is its own branch: what the `if` writes is not what the `else`
    /// reads, and neither is what follows the statement.
    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_expression(&stmt.test);
        // An arm that returns is a path the code after the statement is not on,
        // so what it wrote is not a value that code can read: `if (t) { x = void
        // 0; return } fetchQuery(op, {a: x})` sends `a` on every call that
        // reaches it.
        let returns = always_returns(&stmt.consequent);
        let Some(alternate) = &stmt.alternate else {
            if returns {
                self.scopes.enter_branch();
                self.visit_statement(&stmt.consequent);
                self.scopes.take_branch();
            } else {
                self.in_branch(|v| v.visit_statement(&stmt.consequent));
            }
            return;
        };
        // Both arms start from the state before the statement, and the code
        // after it sees their two exits: `var x; if (t) x = !0; else x = !1;`
        // leaves no path on which `x` is still `undefined`.
        self.scopes.enter_branch();
        self.visit_statement(&stmt.consequent);
        let first = self.scopes.take_branch();
        self.scopes.enter_branch();
        self.visit_statement(alternate);
        let second = self.scopes.take_branch();
        // With one arm returning, the code after the statement is on the other
        // arm and on no other path, so that arm answers for it alone.
        match (returns, always_returns(alternate)) {
            (true, true) => {}
            (true, false) => self.scopes.join_all_arms(vec![second], true),
            (false, true) => self.scopes.join_all_arms(vec![first], true),
            (false, false) => self.scopes.join_arms(first, second),
        }
    }

    fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
        // `for (let x …)` binds `x` for the loop and nothing after it, so the
        // header needs a block of its own around header and body alike. And the
        // update runs AFTER the body, which the generic walker has the other way
        // round: the first pass through the body has not seen it.
        self.scopes.push_block();
        if let Some(init) = &stmt.init {
            match init {
                oxc_ast::ast::ForStatementInit::VariableDeclaration(decl) => {
                    self.visit_variable_declaration(decl);
                }
                other => {
                    if let Some(expr) = other.as_expression() {
                        self.visit_expression(expr);
                    }
                }
            }
        }
        if let Some(test) = &stmt.test {
            self.visit_expression(test);
        }
        // Round again: every iteration after the first reads what the body and
        // the update left behind. `for (; t; x = void 0) { fetchQuery(op, {a:
        // x}) }` sends `a` once and omits it thereafter.
        self.read_until_it_settles(|v| {
            v.visit_statement(&stmt.body);
            if let Some(update) = &stmt.update {
                v.visit_expression(update);
            }
        });
        self.scopes.pop();
    }

    fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
        // Same shape as `for of`, with one difference: what a `for in` writes is
        // a property NAME, which is a string on every iteration - never
        // `undefined`, however little this pass knows about the object.
        self.scopes.push_block();
        self.visit_expression(&stmt.right);
        self.read_until_it_settles(|v| {
            match stmt.left.as_assignment_target() {
                Some(target) => {
                    let mut names = Vec::new();
                    collect_assignment_target_names(target, &mut names);
                    let key = match target {
                        oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(_) => {
                            Value::Defined
                        }
                        _ => Value::MaybeUndefined,
                    };
                    for name in names {
                        v.scopes.bind_assignment(&name, key.clone());
                    }
                }
                None => {
                    if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(decl) = &stmt.left {
                        v.visit_variable_declaration(decl);
                    }
                }
            }
            v.visit_statement(&stmt.body);
        });
        self.scopes.pop();
    }

    fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
        // `for (let x …)` binds `x` for the loop and nothing after it, so the
        // header needs a block of its own around header and body alike. The
        // thing iterated is evaluated ONCE, before any of it - only the binding
        // and the body go round - and a header that writes an EXISTING binding
        // rewrites it per element, with whatever the list holds.
        self.scopes.push_block();
        self.visit_expression(&stmt.right);
        self.read_until_it_settles(|v| {
            match stmt.left.as_assignment_target() {
                Some(target) => {
                    let mut names = Vec::new();
                    collect_assignment_target_names(target, &mut names);
                    for name in names {
                        v.scopes.bind_assignment(&name, Value::MaybeUndefined);
                    }
                }
                None => {
                    if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(decl) = &stmt.left {
                        v.visit_variable_declaration(decl);
                    }
                }
            }
            v.visit_statement(&stmt.body);
        });
        self.scopes.pop();
    }

    fn visit_while_statement(&mut self, stmt: &oxc_ast::ast::WhileStatement<'a>) {
        self.read_until_it_settles(|v| walk::walk_while_statement(v, stmt));
    }

    fn visit_do_while_statement(&mut self, stmt: &oxc_ast::ast::DoWhileStatement<'a>) {
        self.read_until_it_settles(|v| walk::walk_do_while_statement(v, stmt));
    }

    /// Each case from the state before the statement: a `break` makes them
    /// exclusive, so what one writes is not what the next reads. Only a
    /// `default` makes the set exhaustive - without one, no case may run at all.
    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        self.visit_expression(&stmt.discriminant);
        let mut arms = Vec::with_capacity(stmt.cases.len());
        let mut has_default = false;
        // A case the one above it falls into is entered from two places: the
        // discriminant matching it, and the case above running first. Whether a
        // `break` ends that case is not read here, and carrying its exit is the
        // half that cannot claim a key the client may omit.
        let mut falls_through: Vec<ArmExit> = Vec::new();
        // Every test up to the matching case is evaluated before any body runs,
        // and which case matches is not read here: each test's own writes join
        // with the state around them, and the bodies start from that.
        for case in &stmt.cases {
            if let Some(test) = &case.test {
                self.in_branch(|v| v.visit_expression(test));
            }
        }
        for case in &stmt.cases {
            has_default |= case.test.is_none();
            self.scopes.enter_branch();
            self.scopes.carry(&falls_through);
            // The test was walked above, in the order the switch evaluates it.
            for statement in &case.consequent {
                self.visit_statement(statement);
            }
            let exits = self.scopes.take_branch();
            falls_through = match case.consequent.last().is_some_and(always_leaves) {
                true => Vec::new(),
                false => exits.clone(),
            };
            arms.push(exits);
        }
        self.scopes.join_all_arms(arms, has_default);
    }

    /// The handler runs from wherever the block threw, which is any point in
    /// it, so it reads the state the `try` started from or any the block had
    /// reached by then - never only the one the block would have finished with.
    fn visit_try_statement(&mut self, stmt: &oxc_ast::ast::TryStatement<'a>) {
        self.scopes.enter_branch();
        self.scopes.watch();
        self.visit_block_statement(&stmt.block);
        let passed_through = self.scopes.watched();
        let block = self.scopes.take_branch();
        let mut arms = vec![block];
        if let Some(handler) = &stmt.handler {
            self.scopes.enter_branch();
            // The throw comes from a point in the block this pass does not know,
            // so the handler reads the state the block started from or ANY state
            // the block wrote on the way: `x = void 0; mayThrow(); x = !0` can
            // throw between the two writes, and the value in between is one the
            // handler sees.
            self.scopes.carry_values(&passed_through);
            self.visit_catch_clause(handler);
            arms.push(self.scopes.take_branch());
        }
        self.scopes.join_all_arms(arms, false);
        if let Some(finalizer) = &stmt.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    /// A write inside a short-circuit or a ternary arm runs only when that arm
    /// does, exactly like one inside an `if`.
    fn visit_logical_expression(&mut self, expr: &oxc_ast::ast::LogicalExpression<'a>) {
        self.visit_expression(&expr.left);
        self.in_branch(|v| v.visit_expression(&expr.right));
    }

    /// Both arms from the state before the ternary, the same as an `if`: only
    /// one of them runs, so a call in the second must not read what the first
    /// wrote.
    fn visit_conditional_expression(&mut self, expr: &oxc_ast::ast::ConditionalExpression<'a>) {
        self.visit_expression(&expr.test);
        self.scopes.enter_branch();
        self.visit_expression(&expr.consequent);
        let first = self.scopes.take_branch();
        self.scopes.enter_branch();
        self.visit_expression(&expr.alternate);
        let second = self.scopes.take_branch();
        self.scopes.join_arms(first, second);
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
        // The initializer runs before the name holds anything: a call inside it
        // sees the binding as it was, which for a `var` is the hoisted
        // `undefined`. Walking it after the bind let `var x = (fetchQuery(op,
        // {a: x}), !0)` read the value the statement was about to install.
        walk::walk_variable_declarator(self, d);
        if let Some(name) = d.id.get_identifier_name() {
            // An uninitialized declaration is still a binding: it shadows an
            // outer name of the same spelling, and until something writes it the
            // value is `undefined`. Skipping it let `var x;` inside a module that
            // also binds `x` resolve to the module's value.
            //
            // Settled, not left as a reference: `var y = x; x = !0` copies what
            // `x` held, and following the name afterwards would hand `y` a value
            // it never had. An object keeps its reference, because a write
            // through either name reaches the one object.
            // `var x;` after `var x = !0` is not a write: JS redeclares the
            // name and leaves the value alone. Only when the frame this
            // declaration lands in binds the name already - the hoisted
            // `undefined` is not a value anything wrote.
            let frame = if function_scoped {
                self.scopes.function_frame()
            } else {
                self.scopes.frames.len().checked_sub(1)
            };
            if d.init.is_none()
                && frame.is_some_and(|frame| self.scopes.binds_here(frame, name.as_str()))
            {
                return;
            }
            let value = match d.init.as_ref() {
                Some(init) => {
                    let value = convert(init, 0);
                    match self.scopes.resolve(&value, 0) {
                        Value::Object(_) | Value::Array(_) => value,
                        _ => settle(&value, &self.scopes, 0),
                    }
                }
                None => Value::MaybeUndefined,
            };
            if function_scoped {
                self.scopes.bind_function_scoped(name.as_str(), value);
            } else {
                self.scopes.bind(name.as_str(), value);
            }
        }
    }

    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        // The right side runs first: `x = fetchQuery(op, {a: x})` sends the `x`
        // from before the assignment, so the call inside it has to be read
        // against that binding rather than against the one this write installs.
        //
        // `x ||= v` is the exception: the right side runs only when the left is
        // falsy, so a write inside it is one the path around it does not make.
        if n.operator.is_logical() {
            self.visit_assignment_target(&n.left);
            self.in_branch(|v| v.visit_expression(&n.right));
        } else {
            walk::walk_assignment_expression(self, n);
        }
        // The memoised require is written `e !== void 0 ? e : e = n("X.graphql")`,
        // so the binding for the operation handle exists only as an assignment.
        if let Some(name) = wa_oxc::assignment_target_name(&n.left) {
            // The name now says something else, so any alias holding it keeps
            // what it was given rather than following the name here.
            self.scopes.detach_aliases(name);
            // Not the right side: `x &&= v` leaves `x` alone when it is falsy,
            // so the binding afterwards is what the whole expression yields.
            self.scopes.bind_assignment(name, assignment_value(n, 0));
        } else if let Some(idents) = destructured_assignment_names(&n.left) {
            // `({x} = opts)` writes `x` with something this pass does not model,
            // and leaving it bound to what it held before publishes that older
            // value for a name the statement has replaced.
            for name in idents {
                self.scopes.detach_aliases(&name);
                self.scopes.bind_assignment(&name, Value::MaybeUndefined);
            }
        } else if let Some(base) = member_assignment_base(&n.left) {
            // `v.a = …` writes a key of an object this pass recovered, which the
            // literal alone does not show: WA builds a variables object and then
            // adds a key to it under a gate. Reading only the literal would
            // publish the keys it wrote and miss this one, so the write lands on
            // the recovered object - and where it cannot (a computed key, a
            // deeper path, a binding that is not an object), the object stops
            // being evidence rather than answering for a shape it no longer has.
            // `var w = v; w.a = …` mutates the one object both names hold, so
            // the write follows the alias to the binding that owns it.
            let owner = self.scopes.alias_target(base, 0);
            let updated = static_path(&n.left).and_then(|path| {
                let current = self.scopes.lookup(&owner)?.clone();
                write_key(&current, &path, assignment_value(n, 0), &self.scopes, 0)
            });
            self.scopes
                .bind_assignment(&owner, updated.unwrap_or(Value::Unjudged));
        }
    }

    fn visit_update_expression(&mut self, expr: &oxc_ast::ast::UpdateExpression<'a>) {
        // `x++` leaves a number behind - `NaN` when it was not one, which
        // `JSON.stringify` writes as `null` with the key still there. Either way
        // the binding is no longer whatever it was.
        if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = &expr.argument
        {
            self.scopes.detach_aliases(id.name.as_str());
            self.scopes
                .bind_assignment(id.name.as_str(), Value::Defined);
        }
        walk::walk_update_expression(self, expr);
    }

    fn visit_unary_expression(&mut self, expr: &oxc_ast::ast::UnaryExpression<'a>) {
        // `delete v.a` takes the key off the object both this binding and any
        // alias hold, and the expression itself is only the boolean that says it
        // worked. A key that is gone is a key `JSON.stringify` cannot write.
        if expr.operator == UnaryOperator::Delete
            && let Some((base, path)) = member_path(&expr.argument)
        {
            let owner = self.scopes.alias_target(base, 0);
            let updated = self
                .scopes
                .lookup(&owner)
                .cloned()
                .and_then(|current| {
                    write_key(&current, &path, Value::MaybeUndefined, &self.scopes, 0)
                })
                .unwrap_or(Value::Unjudged);
            self.scopes.bind_assignment(&owner, updated);
        }
        walk::walk_unary_expression(self, expr);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // `t?.(x = !0)` and `t?.m(x = !0)` evaluate nothing when `t` is nullish,
        // so everything the call does - its arguments' writes, and the call
        // itself - belongs to a branch.
        if call.optional || optional_link(&call.callee) {
            self.in_branch(|v| v.read_call(call));
        } else {
            self.read_call(call);
        }
    }
}

impl CallSiteCollector<'_> {
    /// The body of [`Visit::visit_call_expression`], split out so an optional
    /// call can run all of it inside a branch.
    fn read_call<'a>(&mut self, call: &CallExpression<'a>)
    where
        Self: Visit<'a>,
    {
        // In evaluation order: the callee, then the handle, then the variables
        // object - which is read where it is built, because an argument after it
        // can write a binding it captured. `fetchQuery(op, {a: x}, x = !0)`
        // builds `{a: undefined}` first.
        self.visit_expression(&call.callee);
        // Read where it is passed: the variables object built after it can
        // rebind the name the handle came from, and the call still sends what
        // that name held here.
        let mut handle = None;
        if let Some(argument) = call.arguments.first() {
            self.visit_argument(argument);
            handle = argument.as_expression().map(|e| self.settled(e));
        }
        let handle = handle.as_ref();
        // The variables object is built property by property, and a later one
        // can write a binding an earlier one read: `{a: x, b: (x = !0, !0)}`
        // stores `undefined` in `a`. So each value is taken where it is written,
        // and the writes it makes land before the next is read.
        let snapshot = call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .and_then(|expression| self.snapshot_object(expression));
        let second = call.arguments.get(1).and_then(Argument::as_expression);
        if snapshot.is_none()
            && let Some(argument) = call.arguments.get(1)
        {
            self.visit_argument(argument);
        }
        // The second argument is evaluated HERE, though the call happens after
        // the arguments that follow it: one of those can point the name at
        // another object, and the call still receives the one this argument
        // named. Held under a name of this pass's own - no JS identifier has a
        // space in it - so a rebinding detaches it exactly as it detaches any
        // other alias, while a write through the name still reaches it.
        let held = second.map(|expression| format!(" variables@{}", expression.span().start));
        if let (Some(name), Some(expression)) = (&held, second)
            && snapshot.is_none()
        {
            let value = convert(expression, 0);
            self.scopes.bind(name, value);
        }
        // The arguments after it run before the call does, and one of them can
        // still reach an object the second argument only NAMES: `fetchQuery(op,
        // v, delete v.a)` hands Relay a `v` without `a`. A literal is not
        // reachable that way and was snapshotted where it was written.
        for argument in call.arguments.iter().skip(2) {
            self.visit_argument(argument);
        }
        if !self.is_operation_call(call, handle) && self.is_ambiguous_call(call, handle) {
            // A Relay call in a module that sends several operations, whose
            // handle names no module at all. It may be this operation's, and
            // dropping it silently would let another caller's site decide a key
            // this one might contradict. Counted, and treated as a site nothing
            // is known about.
            if !self.replaying {
                self.diag.ambiguous_call_sites += 1;
            }
            self.unreadable_sites += 1;
        }
        if self.is_operation_call(call, handle) {
            let vars = call.arguments.get(1).and_then(Argument::as_expression);
            if let Some(expression) = vars {
                self.variable_arguments.push(expression.span().start);
            }
            // `undefined` is a name like any other: a parameter or a local can
            // hold a whole variables object under it, and that is a site this
            // pass cannot read rather than one that writes nothing.
            let nullish = |v: &&Expression<'a>| match v {
                Expression::Identifier(id) if id.name.as_str() == "undefined" => {
                    self.scopes.lookup("undefined").is_none()
                }
                other => is_nullish_literal(other),
            };
            // No variables argument at all, or one written `null` / `undefined` /
            // `void 0`: either way the call sends an object carrying no key. That
            // is a site, and one that writes nothing - skipping it would let a
            // sibling call's object speak for an invocation that sends no key.
            let Some(vars) = vars.filter(|v| !nullish(v)) else {
                self.sites.push(SiteTree::new());
                return;
            };
            let value = snapshot
                .or_else(|| {
                    held.as_ref()
                        .and_then(|name| self.scopes.lookup(name).cloned())
                })
                .unwrap_or_else(|| convert(vars, 0));
            match self.variables_object(&value) {
                Some(tree) => self.sites.push(tree),
                // This call sends the operation and its variables object could
                // not be read, so nothing is known about which keys it writes.
                // `always` means no recovered site contradicts the key, and an
                // unread site cannot be shown not to.
                None => {
                    if !self.replaying {
                        self.diag.unreadable_call_arguments += 1;
                    }
                    self.unreadable_sites += 1;
                }
            }
        }
        // A helper handed a recovered object can do anything to it - delete a
        // key, overwrite one with `undefined` - and this pass reads no function
        // body it did not have to. The object stops being evidence. Relay's own
        // methods are the exception: their argument IS the request, read at the
        // point it is passed.
        if !wa_oxc::callee_method(call).is_some_and(|m| FETCH_METHODS.contains(&m)) {
            for argument in call.arguments.iter().filter_map(Argument::as_expression) {
                match argument {
                    Expression::Identifier(id) => self.stops_being_evidence(id.name.as_str()),
                    // `mutate(v.input)` hands over a part of a recovered object,
                    // and what that body does to it is a change to the one
                    // object. Which subtree came back changed is not something
                    // this pass follows, so the owner stops being evidence.
                    other => {
                        if let Some((base, _)) = member_path(other) {
                            self.stops_being_evidence(base);
                        }
                    }
                }
            }
            // `v.clear()` reaches the same object `clear(v)` does: the receiver
            // is handed to a body this pass does not read, exactly like an
            // argument.
            if let Some(receiver) = callee_receiver(&call.callee) {
                self.stops_being_evidence(receiver);
            }
        }
    }

    /// A recovered object handed somewhere this pass does not read stops
    /// answering for the keys it carries.
    fn stops_being_evidence(&mut self, name: &str) {
        let owner = self.scopes.alias_target(name, 0);
        let carries_keys = matches!(
            self.scopes.resolve(&Value::Ref(owner.clone()), 0),
            Value::Object(_) | Value::Array(_)
        );
        if carries_keys {
            self.scopes.bind_assignment(&owner, Value::Unjudged);
        }
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

    /// Walk a body that runs more than once, then walk it again with what the
    /// last pass left behind, until the bindings stop moving. The second reading
    /// is where a call after a write meets the write: `while (t) { fetchQuery(op,
    /// {a: x}); x = void 0 }` sends `a` on the first iteration and on no other.
    ///
    /// One reading back is not always enough - `while (t) { …{a: x}…; x = y; y =
    /// void 0 }` takes three iterations to reach the call that omits the key -
    /// so the body is read until a pass writes what the pass before it did, and
    /// a body still moving after [`MAX_PASSES`] is one whose calls this pass
    /// cannot claim to have read. Its diagnostics are counted once: a replay
    /// does not start another.
    fn read_until_it_settles(&mut self, walk_body: impl Fn(&mut Self)) {
        self.in_branch(|v| {
            walk_body(v);
            if v.replaying {
                return;
            }
            v.replaying = true;
            let sites_before = v.sites.len();
            let mut settled = false;
            for _ in 0..MAX_PASSES {
                let bindings = v.scopes.frames.clone();
                walk_body(v);
                if v.scopes.frames == bindings {
                    settled = true;
                    break;
                }
            }
            v.replaying = false;
            // Still moving, and a call inside it read values no pass here
            // reached. The sites it did recover are kept - they are real calls -
            // beside one that says the reading is incomplete.
            if !settled && v.sites.len() > sites_before {
                v.unreadable_sites += 1;
            }
        });
    }
}

impl CallSiteCollector<'_> {
    /// Read an object literal in source order, taking each value where it is
    /// written and letting the writes inside it land before the next is read.
    ///
    /// `None` for anything but a literal: a binding is resolved at the call, and
    /// there is nothing to interleave. The walk happens here rather than in the
    /// caller, so a property's own side effects are applied exactly once.
    fn snapshot_object(&mut self, expression: &Expression<'_>) -> Option<Value> {
        let Expression::ObjectExpression(object) = expression else {
            return None;
        };
        let mut props = Vec::with_capacity(object.properties.len());
        for property in &object.properties {
            match property {
                ObjectPropertyKind::ObjectProperty(p) => {
                    let key = match &p.key {
                        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_string()),
                        PropertyKey::StringLiteral(lit) => Some(lit.value.as_str().to_string()),
                        _ => None,
                    };
                    // A computed key is an expression of its own, and it runs
                    // before the value beside it: `{[(x = void 0, "z")]: 1, a:
                    // x}` clears `x` before `a` reads it.
                    if p.computed
                        && let Some(key) = p.key.as_expression()
                    {
                        self.visit_expression(key);
                    }
                    // The property's own expression runs first, writes and all,
                    // and what it leaves is the value stored: `{a: (x = void 0,
                    // x)}` stores the `x` the assignment just cleared.
                    self.visit_expression(&p.value);
                    let value = self.settled(&p.value);
                    props.push(match key {
                        Some(key) => Prop::Key(key, value),
                        None => Prop::Unreadable,
                    });
                }
                ObjectPropertyKind::SpreadProperty(spread) => {
                    self.visit_expression(&spread.argument);
                    // A nullish source spreads nothing, the same as in `convert`.
                    let value = match is_nullish_literal(&spread.argument) {
                        true => Value::Object(Vec::new()),
                        false => self.settled(&spread.argument),
                    };
                    props.push(Prop::Spread(value));
                }
            }
        }
        Some(Value::Object(props))
    }

    /// The value an expression has HERE, with every binding it names resolved,
    /// so a write further along the object cannot reach back into it.
    fn settled(&self, expression: &Expression<'_>) -> Value {
        settle(&convert(expression, 0), &self.scopes, 0)
    }

    /// Bind a function's parameters, so a name the caller passes in resolves to a    /// Bind a function's parameters, so a name the caller passes in resolves to a
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
            // `function f(x = !0)` substitutes the default whenever the argument
            // is missing or `undefined`, so the binding is the default and not a
            // passthrough. Only for a plain `x`: with `function f({x} = {})` the
            // default is the object destructured, and what it yields for `x` is
            // another matter.
            let plain = matches!(
                &item.pattern,
                oxc_ast::ast::BindingPattern::BindingIdentifier(_)
            );
            let default = item
                .initializer
                .as_ref()
                .filter(|_| plain)
                .map(|d| convert(d, 0));
            for ident in item.pattern.get_binding_identifiers() {
                let value = default.clone().unwrap_or(Value::MaybeUndefined);
                self.scopes.bind(ident.name.as_str(), value);
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
    fn is_operation_call(&self, call: &CallExpression, handle: Option<&Value>) -> bool {
        let Some(method) = wa_oxc::callee_method(call) else {
            return false;
        };
        if !FETCH_METHODS.contains(&method) {
            return false;
        }
        let Some(handle) = handle else {
            return false;
        };
        references_module(handle, &self.module, &self.scopes, 0) || self.sole_operation
    }

    /// A Relay call in a module that sends more than one operation whose handle
    /// this pass could not tie to any module: it may or may not be ours.
    fn is_ambiguous_call(&self, call: &CallExpression, handle: Option<&Value>) -> bool {
        let Some(method) = wa_oxc::callee_method(call) else {
            return false;
        };
        if !FETCH_METHODS.contains(&method) || self.sole_operation {
            return false;
        }
        let Some(handle) = handle else {
            return false;
        };
        // Either the handle is not read whole, or one of the branches it CAN
        // take is this operation while another is not: `cond ? n("Ours") :
        // n("Other")` names a module on both sides and is still a call this
        // operation may be making. Neither case is knowledge about which keys
        // this operation sends, and `is_operation_call` has already said the
        // handle is not certainly ours.
        !every_branch_names_a_module(handle, &self.scopes, 0)
            || may_reference_module(handle, &self.module, &self.scopes, 0)
    }

    /// The variables object of a matched call, if the argument is one or resolves
    /// to one.
    fn variables_object(&mut self, value: &Value) -> Option<SiteTree> {
        match self.scopes.resolve(value, 0) {
            Value::Object(props) => {
                // A replay reads the same object a second time, so its
                // diagnostics go to a scratch that is thrown away: the first
                // reading counted them.
                let mut replayed = PresenceDiagnostics::default();
                let (tree, opaque) = if self.replaying {
                    classify_object_reporting(props, &self.scopes, &mut replayed, 0)
                } else {
                    classify_object_reporting(props, &self.scopes, self.diag, 0)
                };
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
                let mut replayed = PresenceDiagnostics::default();
                let (tree, opaque) = if self.replaying {
                    classify_object_reporting(props, &self.scopes, &mut replayed, 0)
                } else {
                    classify_object_reporting(props, &self.scopes, self.diag, 0)
                };
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
    variable_arguments: &mut Vec<(usize, u32)>,
) -> BTreeMap<String, VariablePresenceNode> {
    // Not an early return: an operation whose `argumentDefinitions` this pass
    // could not read still has call sites, and the shape pass reads their
    // variables objects through the offsets collected below. There is simply no
    // name to publish a verdict for.
    let publish = !arg_def_names.is_empty();
    let mut merged: Option<SiteTree> = None;
    let mut unreadable_sites = 0usize;
    let mut opaque_paths: Vec<Opaque> = Vec::new();
    for (caller, (src, sole_operation)) in callers.iter().enumerate() {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, src);
        let (hoisted, module_rewritten) = hoist_module_bindings(&ret.program);
        let scopes = Scopes {
            hoisted,
            module_rewritten,
            ..Scopes::default()
        };
        let mut collector = CallSiteCollector {
            module: module.to_string(),
            sole_operation: *sole_operation,
            scopes,
            sites: Vec::new(),
            unreadable_sites: 0,
            opaque_paths: Vec::new(),
            replaying: false,
            variable_arguments: Vec::new(),
            diag,
        };
        collector.visit_program(&ret.program);
        unreadable_sites += collector.unreadable_sites;
        opaque_paths.extend(collector.opaque_paths);
        variable_arguments.extend(collector.variable_arguments.iter().map(|at| (caller, *at)));
        // Every recovered site has to agree for a key to be `always`, so the sites
        // are folded rather than picked from - across callers as well as within one.
        for site in collector.sites {
            merged = Some(match merged {
                Some(acc) => merge_sites(acc, site),
                None => site,
            });
        }
    }

    if !publish {
        // No declared name to answer for, so the keys the sites wrote are the
        // whole answer - `align_with_shape` publishes exactly the ones the shape
        // recovered from those same calls. The no-call-site diagnostic stays out
        // of it: an operation with no variables has nothing to be silent about.
        let mut written = merged.unwrap_or_default();
        if unreadable_sites > 0 {
            for node in written.values_mut() {
                withdraw(node);
            }
        }
        return written;
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
    for record in &opaque_paths {
        let mut node: Option<&mut VariablePresenceNode> = None;
        for step in &record.path {
            node = match (node, step) {
                (None, Step::Field(key)) => merged.get_mut(key),
                (Some(parent), Step::Field(key)) => parent.fields.get_mut(key),
                (Some(parent), Step::Item) => parent.items.as_deref_mut(),
                (None, Step::Item) => None,
            };
            if node.is_none() {
                break;
            }
        }
        // An empty path is the variables object itself, whose unwritten declared
        // keys are handled below rather than here.
        if let Some(node) = node {
            for (key, child) in node.fields.iter_mut() {
                if !record.written.contains(key) {
                    withdraw(child);
                }
            }
            if let Some(items) = node.items.as_deref_mut() {
                withdraw_children(items);
            }
        }
    }
    // The keys of the variables object itself that no site wrote, same rule one
    // level up: a spread nobody could read may be supplying them.
    let opaque_keys: Vec<&str> = opaque_paths
        .iter()
        .filter(|record| record.path.is_empty())
        .flat_map(|record| record.written.iter().map(String::as_str))
        .collect();
    let opaque_top = opaque_paths.iter().any(|record| record.path.is_empty());

    arg_def_names
        .iter()
        .map(|name| {
            let mut node = merged.remove(name).unwrap_or_else(|| {
                // Declared by the operation and written by no recovered site. That
                // is "not always" - unless a spread nobody could read might be
                // supplying it, in which case nothing at all is established.
                VariablePresenceNode::leaf(if opaque_top && !opaque_keys.contains(&name.as_str()) {
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
        let out = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
            &mut Vec::new(),
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
        let tree = variables_presence(
            &[(quiet, false), (live, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.ambiguous_call_sites, 1);
    }

    #[test]
    fn a_handle_that_is_sometimes_ours_is_ambiguous() {
        // `t ? n("Ours") : n("Other")` names a module on both sides, so it is
        // read whole - and one of the two is this operation, so the call may be
        // ours and may contradict the site that is.
        let caller = r#"function f(t){o("C").fetchQuery(t?n("WAWebFooQuery.graphql"):n("WAWebOtherQuery.graphql"),{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
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
    fn a_fallback_handle_does_not_attribute_the_call_either() {
        // `h || n("WAWebFooQuery.graphql")` hands the call `h` whenever `h` is
        // there, so reading it as this operation's site would merge whatever `h`
        // sends into this operation's evidence - and this is the only site, so
        // its keys would come out `always`.
        for handle in [
            "h||n(\"WAWebFooQuery.graphql\")",
            "h??n(\"WAWebFooQuery.graphql\")",
            "h?n(\"WAWebFooQuery.graphql\"):h",
            "s(h,n(\"WAWebFooQuery.graphql\"))",
        ] {
            let caller = format!(
                r#"function f(t,h){{o("C").fetchQuery({handle},{{a:!0}});o("C").fetchQuery(n("WAWebOtherQuery.graphql"),{{a:t.x}})}}"#
            );
            let names = vec!["a".to_string()];
            let mut diag = PresenceDiagnostics::default();
            let tree = variables_presence(
                &[(caller.as_str(), false)],
                MODULE,
                &names,
                &mut diag,
                &mut Vec::new(),
            );
            assert_eq!(at(&tree, "a"), VariablePresence::Undetermined, "{handle}");
            assert_eq!(diag.ambiguous_call_sites, 1, "{handle}");
        }
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
            let tree = variables_presence(
                &[(caller.as_str(), false)],
                MODULE,
                &names,
                &mut diag,
                &mut Vec::new(),
            );
            assert_eq!(at(&tree, "a"), VariablePresence::Undetermined, "{handle}");
            assert_eq!(diag.ambiguous_call_sites, 1, "{handle}");
        }
    }

    #[test]
    fn both_arms_of_an_if_leave_no_path_around_them() {
        // `var x; if (t) x = !0; else x = !1;` has no path on which `x` is still
        // undefined below, so joining each arm with the pre-branch value in turn
        // publishes an optional field for a key the client always sends.
        let caller = r#"function f(t){var x;if(t){x=!0}else{x=!1}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);

        // And one arm alone still joins: the other path reaches the call.
        let one = r#"function f(t){var x;if(t){x=!0}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(one, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_ternary_is_a_memo_only_when_its_test_asks_about_that_binding() {
        // `flag ? x : x = !0` reads a binding on one side and writes it on the
        // other, exactly like the memoised require - and sends `undefined` on
        // the `flag` path, which the require never does.
        let caller = r#"function f(t){var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:t?x:x=!0})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);

        // The real shape, both spellings of the guard.
        for memo in ["x!==void 0?x:x=!0", "x===void 0?x=!0:x"] {
            let caller = format!(
                r#"function f(){{var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{{a:{memo}}})}}"#
            );
            let (tree, _) = presence_of(&caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Always, "{memo}");
        }
    }

    #[test]
    fn a_local_class_declaration_shadows_the_module() {
        // Same as a local function: the name is a class where the call sits, and
        // `JSON.stringify` drops a key whose value is one.
        let caller = r#"var x=!0;function f(){class x{}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_closure_reads_what_the_module_leaves_behind() {
        // The module finishes initializing before anything calls `f`, so the
        // write below the function is the value the call sees - not the one
        // standing where the function is written.
        let caller = r#"var x=!0;function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}x=void 0;"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_call_that_is_handed_a_module_is_not_a_handle() {
        // `select(h, n("Other.graphql"))` may return `h`, and `h` may be this
        // operation: an unread call is unread whatever it is given.
        let caller = r#"function f(t,h){o("C").fetchQuery(s(h,n("WAWebOtherQuery.graphql")),{a:t.x});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.ambiguous_call_sites, 1);
    }

    #[test]
    fn a_write_through_an_alias_reaches_the_object_itself() {
        // `var w = v` is another name for one object, and the write goes through
        // to it: reading `v` afterwards has to see what `w` did.
        let caller = r#"function f(){var v={a:!0},w=v;w.a=void 0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_key_written_after_an_opaque_spread_is_still_written() {
        // `{...opts, a: !0}` writes `a` whatever `opts` holds. Only the keys the
        // site does NOT write are the ones the spread might be supplying.
        let caller = r#"function f(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{...t.opts,a:!0}});return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{a:!0,b:!0}})}"#;
        let names = vec!["input".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
        let input = &tree["input"];
        assert_eq!(
            input.fields["a"].presence,
            VariablePresence::Always,
            "written explicitly by both sites, after the spread"
        );
        assert_eq!(
            input.fields["b"].presence,
            VariablePresence::Undetermined,
            "the first site may be supplying it through `opts`"
        );
    }

    #[test]
    fn an_unreadable_spread_inside_a_list_element_withdraws_the_element() {
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:[{...t.opts},{a:!0}]})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        let item = tree["input"].items.as_deref().expect("list element");
        assert_eq!(item.fields["a"].presence, VariablePresence::Undetermined);
    }

    #[test]
    fn both_arms_of_a_ternary_start_where_it_did() {
        // Only the alternate reaches the call, and on that path `x` is untouched.
        let caller = r#"function f(t){var x=!0;return t?x=void 0:o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn what_one_function_writes_is_not_what_another_reads() {
        // `send` can be called without `init` ever having run, so walking `init`
        // must not leave its write standing for the call in `send`.
        let caller = r#"var x;function g(){x=!0}function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_destructuring_assignment_writes_the_names_it_names() {
        let caller = r#"function f(t){var x=!0;({x}=t);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_argument_runs_before_the_call_it_belongs_to() {
        // `{a: (x = void 0, !0), b: x}` evaluates `a` first, and `b` is the `x`
        // it left behind.
        let caller = r#"function f(){var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:(x=void 0,!0),b:x})}"#;
        let (tree, _) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(at(&tree, "b"), VariablePresence::Conditional);
    }

    #[test]
    fn a_function_on_the_left_of_a_fallback_is_the_value() {
        // It is neither nullish nor falsy, so the right side never runs - and
        // `JSON.stringify` drops a key holding a function.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:(function(){})||!0})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_lexical_loop_header_does_not_outlive_the_loop() {
        // `for (let x …)` binds `x` for the loop only: the call below reads the
        // outer one.
        let caller = r#"function f(){var x=!0;for(let x;!1;){}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_bound_undefined_is_a_name_like_any_other() {
        // `function f(undefined)` can be handed a whole variables object, so the
        // call is one this pass cannot read - not one that writes nothing.
        let caller = r#"function f(undefined){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),undefined)}"#;
        let (tree, diag) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
        assert_eq!(diag.unreadable_call_arguments, 1);
    }

    #[test]
    fn a_parameter_with_a_default_is_the_default() {
        // JS substitutes it for a missing argument and for an explicit
        // `undefined` alike, so every call that gets here writes the key.
        let caller =
            r#"function f(t=!0){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:t})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_named_function_expression_binds_its_own_name() {
        // Inside the body `x` is the function, not the module's boolean.
        let caller = r#"var x=!0;var f=function x(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_loop_body_runs_before_the_update() {
        // The first pass through the body has not seen `x = !0` yet, and this
        // one breaks out before a second.
        let caller = r#"function f(t){var x;for(;t;x=!0){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});break}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn one_switch_case_does_not_answer_for_another() {
        // `break` makes the cases exclusive: the call in the second runs on a
        // path where the first never wrote.
        let caller = r#"function f(t){var x;switch(t){case 0:x=!0;break;case 1:o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_handler_reads_the_state_the_try_started_from() {
        // The block can throw before its last line, and that is the path the
        // handler runs on.
        let caller = r#"function f(t){var x;try{t();x=!0}catch(e){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_block_binds_its_lexical_names_for_the_whole_block() {
        // The closure is written above the `let`, and captures it all the same.
        let caller = r#"var x=!0;function f(){{var g=()=>o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});let x;g()}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_object_with_its_own_to_json_decides_its_own_serialization() {
        // `JSON.stringify` calls the hook and serializes what it returns, which
        // is a function body this pass does not read.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,toJSON(){return{}}})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
    }

    #[test]
    fn an_argument_after_the_variables_object_is_too_late_to_change_it() {
        // `fetchQuery(op, {a: x}, x = !0)` builds `{a: undefined}` first.
        let caller = r#"function f(){var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x},x=!0)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_deleted_key_is_not_a_key() {
        // `delete v.a` takes it off the object, and the expression itself is
        // only the boolean saying so.
        let caller = r#"function f(){var v={a:!0};delete v.a;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_default_belongs_to_the_pattern_it_is_written_on() {
        // `function f({x} = {})` defaults the object, not `x`: called with no
        // argument, `x` is `undefined`.
        let caller =
            r#"function f({x}={}){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);

        // A plain parameter still takes its own default.
        let plain =
            r#"function f(t=!0){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:t})}"#;
        let (tree, _) = presence_of(plain, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_loop_body_runs_again_with_what_the_update_left() {
        // The first iteration sends `a`; every one after it does not.
        let caller = r#"function f(t){var x=!0;for(;t;x=void 0){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_for_of_header_rewrites_the_binding_it_names() {
        // `for (x of xs)` writes `x` once per element, and what the list holds
        // is not something this pass reads.
        let caller = r#"function f(t){var x=!0;for(x of t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_object_handed_to_a_helper_stops_being_evidence() {
        // `clear(v)` can delete a key or overwrite it with `undefined`, and this
        // pass reads no function body it did not have to.
        let caller = r#"function f(t){var v={a:!0};t.clear(v);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);

        // Relay's own method is not a helper: its argument IS the request.
        let sent = r#"function f(){var v={a:!0};o("C").fetchQuery(n("WAWebFooQuery.graphql"),v);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(sent, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_while_body_runs_again_with_what_it_wrote() {
        // The first iteration sends `a`; the write at the bottom of the body is
        // what every iteration after it reads.
        for caller in [
            r#"function f(t){var x=!0;while(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});x=void 0}}"#,
            r#"function f(t){var x=!0;do{o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});x=void 0}while(t)}"#,
        ] {
            let (tree, _) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
        }
    }

    #[test]
    fn a_function_called_again_reads_what_it_left() {
        // Same shape without the loop: the second invocation of `send` runs with
        // the `x` the first one cleared.
        let caller = r#"var x=!0;function f(){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});x=void 0}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_falsy_left_operand_of_and_is_the_value() {
        // `!1 && x` never evaluates `x`, so the key is `false` on every call.
        let caller = r#"function f(t){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!1&&t.x,b:!0&&t.x})}"#;
        let (tree, _) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(
            at(&tree, "b"),
            VariablePresence::Conditional,
            "a truthy left side hands the expression its right"
        );
    }

    #[test]
    fn a_module_write_inside_a_comma_expression_still_counts() {
        // The minifier writes initialization as one statement of many writes,
        // and a closure reads what all of them left.
        let caller = r#"var x=!0,e;function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}x=void 0,e=f;"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_function_reached_through_a_binding_is_still_the_value() {
        // `g || !0` selects `g`, which is truthy and which `JSON.stringify`
        // drops - the fallback never runs.
        let caller = r#"function f(){var g=function(){return!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:g||!0})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_property_is_read_where_it_is_written() {
        // `{a: x, b: (x = !0, !0)}` stores `undefined` in `a`: the write in `b`
        // comes after it. And the reverse order still lets `b` see the write.
        let caller = r#"function f(){var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x,b:(x=!0,!0)})}"#;
        let (tree, _) = presence_of(caller, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
        assert_eq!(at(&tree, "b"), VariablePresence::Always);

        let reversed = r#"function f(){var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:(x=void 0,!0),b:x})}"#;
        let (tree, _) = presence_of(reversed, &["a", "b"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
        assert_eq!(at(&tree, "b"), VariablePresence::Conditional);
    }

    #[test]
    fn what_a_loop_iterates_is_evaluated_once() {
        // `for (let y of (x = !0, xs))` writes `x` before the first iteration
        // and never again, so the body's own write is what later iterations
        // read - a replay that re-ran the header would undo it.
        let caller = r#"function f(t){var x;for(let y of (x=!0,t)){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});x=void 0}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_strict_null_guard_is_not_a_memo() {
        // `undefined !== null` is true, so `x !== null ? x : x = !0` hands the
        // call an undefined `x` on the branch a memoised require never does.
        let caller = r#"function f(){var x,y=x!==null?x:x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:y})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);

        // The loose form covers both nullish values, and is a memo.
        let loose = r#"function f(){var x,y=x!=null?x:x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:y})}"#;
        let (tree, _) = presence_of(loose, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_for_in_key_is_a_string_on_every_iteration() {
        // It is a property name, whatever this pass knows about the object.
        let caller = r#"function f(t){var k;for(k in t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:k})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn an_update_expression_writes_its_operand() {
        // `x++` leaves a number - `NaN` when it was not one, which serializes as
        // `null` with the key still there.
        let caller =
            r#"function f(){var x;x++;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_copied_binding_keeps_the_value_it_copied() {
        // `var y = x; x = !0` leaves `y` at what `x` held, not at what it holds.
        let caller = r#"function f(){var x,y=x;x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:y})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);

        // An object is not copied, though: both names hold the one object, and a
        // write through either reaches it.
        let shared = r#"function f(){var v={a:!0},w=v;w.a=void 0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(shared, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_property_runs_its_own_writes_before_it_is_read() {
        // `{a: (x = void 0, x)}` stores the `x` the assignment just cleared.
        let caller = r#"function f(){var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:(x=void 0,x)})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_initializer_runs_before_the_name_holds_anything() {
        // The call inside it sees the hoisted `undefined`, not the value the
        // statement is about to install.
        let caller = r#"function f(){var x=(o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x}),!0);return x}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_case_the_one_above_falls_into_reads_what_it_wrote() {
        // No `break`, so `case 1` runs after `case 0` as well as instead of it,
        // and on that path the write above it has happened.
        let caller = r#"function f(t){var x=!0;switch(t){case 0:x=void 0;case 1:o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_handler_also_reads_what_the_block_wrote_before_it_threw() {
        // The throw is after the write here, so the handler sees the cleared
        // value on that path and the original on every earlier one.
        let caller = r#"function f(t){var x=!0;try{x=void 0;t()}catch(e){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_alias_keeps_the_object_it_was_given() {
        // `w` was handed the empty object; `v = {a: !0}` afterwards is a new
        // object `w` never saw, and reading `w` as `v` published a key the call
        // does not send.
        let caller = r#"function f(){var v={},w=v;v={a:!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),w)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_method_called_on_a_recovered_object_stops_it_being_evidence() {
        // `v.clear()` is a body this pass does not read, handed the same object
        // `clear(v)` would be.
        let caller = r#"function f(){var v={a:!0};v.clear();return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
    }

    #[test]
    fn a_redeclaration_without_an_initializer_writes_nothing() {
        // `var x;` after `var x = !0` declares a name that is already there and
        // leaves its value alone - it does not reset it to `undefined`.
        let caller = r#"function f(){var x=!0;var x;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_computed_key_runs_before_the_value_beside_it() {
        // The key expression clears `x`, and the property after it reads what
        // the key left.
        let caller = r#"function f(){var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{[(x=void 0,"z")]:!0,a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn the_right_side_of_a_logical_assignment_runs_only_sometimes() {
        // `x ||= (y = !0)` leaves `y` undefined whenever `x` is truthy.
        let caller = r#"function f(){var x=!0,y;x||=(y=!0);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:y})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_parameter_default_runs_only_when_the_argument_is_missing() {
        // Every call that passes `t` skips the default, and with it the write
        // the default makes.
        let caller = r#"function f(t=(z=!0)){var z;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:z})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn an_optional_call_may_not_run_its_arguments() {
        // `t?.(x = !0)` evaluates nothing at all when `t` is nullish.
        let caller = r#"function f(t){var x;t?.(x=!0);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn the_handle_is_read_where_it_is_passed() {
        // The first call is handed this operation and its variables object
        // rebinds `h` on the way; the call still sent ours, and the key it
        // leaves off the wire is this operation's evidence.
        let caller = r#"function f(t){var h=n("WAWebFooQuery.graphql");o("C").fetchQuery(h,{a:(h=n("WAWebOtherQuery.graphql"),void 0)});h=n("WAWebFooQuery.graphql");return o("C").fetchQuery(h,{a:!0})}"#;
        let names = vec!["a".to_string()];
        let mut diag = PresenceDiagnostics::default();
        let tree = variables_presence(
            &[(caller, false)],
            MODULE,
            &names,
            &mut diag,
            &mut Vec::new(),
        );
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_body_is_read_until_its_bindings_settle() {
        // Three iterations before the call stops sending `a`: the first two send
        // it, and one reading back would have called the key unconditional.
        let caller = r#"function f(t){var x=!0,y=!0;while(t){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x});x=y;y=void 0}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_left_operand_the_expression_keeps_is_the_value() {
        // `!0 || void 0` never evaluates its right side, and neither does
        // `0 ?? void 0`: deciding on the right operand made both omissible.
        for caller in [
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0||void 0})}"#,
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:0??void 0})}"#,
        ] {
            let (tree, _) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Always);
        }
    }

    #[test]
    fn a_part_of_a_recovered_object_handed_over_withdraws_the_whole() {
        // `mutate(v.input)` can clear the key inside it, and which subtree came
        // back changed is not something this pass follows.
        let caller = r#"function f(t){var v={input:{a:!0}};t.mutate(v.input);return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v)}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        assert_eq!(at(&tree, "input"), VariablePresence::Undetermined);
        assert!(
            tree["input"].fields.is_empty(),
            "an object this pass stopped reading answers for none of its keys"
        );
    }

    #[test]
    fn an_arm_that_returns_is_not_a_path_the_call_is_on() {
        // Every call that reaches the request took the other path, on which the
        // write inside the arm never happened.
        let caller = r#"function f(t){var x=!0;if(t){x=void 0;return}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);

        // And the same for the arm that does not return: with the returning one
        // gone, the other answers for the code after the statement alone.
        let both = r#"function f(t){var x;if(t){return}else{x=!0}return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}"#;
        let (tree, _) = presence_of(both, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_to_json_that_cannot_be_called_is_an_ordinary_key() {
        // `JSON.stringify` consults the hook only when it is a function, so
        // `{toJSON: null}` serializes the keys beside it as written.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,toJSON:null})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);

        // A function under that name still decides the object's serialization.
        let hook = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,toJSON:function(){return{}}})}"#;
        let (tree, _) = presence_of(hook, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Undetermined);
    }

    #[test]
    fn a_later_argument_still_reaches_an_object_the_call_only_names() {
        // `v` is a reference, and the third argument runs before Relay is
        // called: the object it receives has no `a` in it.
        let caller = r#"function f(){var v={a:!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v,delete v.a)}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn the_call_receives_the_object_the_argument_named() {
        // A later argument points `v` at another object, and the call still
        // sends the one argument two evaluated to.
        let empty = r#"function f(t){var v={a:!0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v,(v={}))}"#;
        let (tree, _) = presence_of(empty, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);

        // And the other way round: the object the call receives is the empty
        // one, whatever the name holds by the time the call runs.
        let richer = r#"function f(t){var v={};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),v,(v={a:!0}))}"#;
        let (tree, _) = presence_of(richer, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_binding_the_fallback_never_reaches_past_is_the_value() {
        // `x || void 0` with a truthy `x` never evaluates its right side, and
        // `x ?? void 0` with a zero never evaluates its own: the two operators
        // ask different questions of the same binding.
        for caller in [
            r#"function f(){var x=!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x||void 0})}"#,
            r#"function f(){var x=0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x??void 0})}"#,
        ] {
            let (tree, _) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Always);
        }

        // And where the left side gives way, the right side still decides: a
        // zero is falsy, and a comparison is a boolean that is false half the
        // time.
        for caller in [
            r#"function f(){var x=0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x||void 0})}"#,
            r#"function f(t){var x=t===!0;return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x||void 0})}"#,
        ] {
            let (tree, _) = presence_of(caller, &["a"]);
            assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
        }
    }

    #[test]
    fn a_handler_reads_a_state_the_block_only_passed_through() {
        // The block clears `x` and puts it back; a throw between the two is the
        // path the handler runs on, and neither end of the block shows it.
        let caller = r#"function f(t){var x=!0;try{x=void 0;t();x=!0}catch(e){o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_destructuring_default_runs_only_when_the_key_is_missing() {
        // The object supplies `x`, so the default beside it never runs and the
        // write inside it never happens.
        let caller = r#"function f(){var z;var {x=(z=!0)}={x:0};return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:z})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
    }

    #[test]
    fn a_nullish_spread_writes_nothing_and_withdraws_nothing() {
        // `{...null}` is a no-op in JS, not a source of keys this pass cannot
        // read: the key written beside it stands.
        let caller =
            r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:!0,...null})}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Always);
    }

    #[test]
    fn a_nested_hook_decides_the_key_that_holds_it() {
        // `input.toJSON()` can return `undefined`, and then `input` itself is
        // not on the wire - not only the keys under it.
        let caller = r#"function f(){return o("C").fetchQuery(n("WAWebFooQuery.graphql"),{input:{a:!0,toJSON:function(){}}})}"#;
        let (tree, _) = presence_of(caller, &["input"]);
        assert_eq!(at(&tree, "input"), VariablePresence::Undetermined);
    }

    #[test]
    fn a_case_test_runs_before_the_body_that_matches() {
        // The first test is evaluated on the way to the second case, so its
        // write has happened by the time the call in that case runs.
        let caller = r#"function f(t){var x=!0;switch(1){case (x=void 0,0):break;case 1:o("C").fetchQuery(n("WAWebFooQuery.graphql"),{a:x})}}"#;
        let (tree, _) = presence_of(caller, &["a"]);
        assert_eq!(at(&tree, "a"), VariablePresence::Conditional);
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
