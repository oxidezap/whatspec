//! Phase-2 structural extraction: the `response` type tree from a Relay
//! operation's `selections`.
//!
//! Faithful port of the reference's text-based parser (`parser.cjs`) +
//! `findOperationLiteral` / `shapeFromSelections` / `mergeShapeNode`. The Relay
//! compiler hoists shared selection/field objects into local `var`s, so the
//! literal parser resolves bare identifiers against earlier declarations in the
//! same module body. Leaves are emitted as the `unknown` tag here; pragmatic
//! typing fills concrete scalar types in a later pass.

use std::collections::BTreeMap;

use wa_ir::TypeNode;

/// A parsed JS literal value (structure only — enough to walk `selections`).
/// `Ref`/`Num` payloads are retained for the upcoming variablesShape pass.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Val {
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Num,
    Obj(Vec<(String, Val)>),
    Arr(Vec<Val>),
    /// An identifier / complex expression we could not resolve to a literal.
    Ref(String),
}

impl Val {
    fn get(&self, key: &str) -> Option<&Val> {
        match self {
            Val::Obj(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    fn is_truthy_bool(&self) -> bool {
        matches!(self, Val::Bool(true))
    }
}

// Byte scanners shared with wa-appstate live in the `wa-text` crate.
use wa_text::{skip_expr, skip_string, skip_ws};

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

// ─── literal parser with identifier tracing (port of parseValue/Object/Array) ─

/// Resolves bare identifiers to their literal values by scanning earlier
/// `var <id> = <literal>` declarations in the body (last assignment wins).
struct Tracer<'b> {
    body: &'b [u8],
    cache: std::collections::HashMap<String, Option<Val>>,
}

impl<'b> Tracer<'b> {
    fn new(body: &'b [u8]) -> Self {
        Tracer {
            body,
            cache: std::collections::HashMap::new(),
        }
    }

    fn trace(&mut self, ident: &str) -> Option<Val> {
        if let Some(v) = self.cache.get(ident) {
            return v.clone();
        }
        // Guard against self-reference recursion.
        self.cache.insert(ident.to_string(), None);
        let mut last: Option<Val> = None;
        let mut search = 0usize;
        let ident_b = ident.as_bytes();
        while let Some(pos) = find_assignment(self.body, ident_b, search) {
            search = pos + 1;
            let after = skip_ws(self.body, pos);
            if after < self.body.len() && (self.body[after] == b'{' || self.body[after] == b'[') {
                let (v, _) = parse_value(self.body, after, self);
                if !matches!(v, Val::Null | Val::Undefined) {
                    last = Some(v);
                }
            }
        }
        self.cache.insert(ident.to_string(), last.clone());
        last
    }
}

/// A JS regex word char (`\w` = `[A-Za-z0-9_]`). Note `$` is NOT a word char —
/// this matters: the reference tracer uses `\b<ident>` and so cannot resolve
/// `$`-named hoisted vars (`,$={...}`), dropping their fields. We replicate that
/// boundary semantics to stay byte-exact with the reference's structural output.
fn is_word_js(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Find `<ident> = ` after `from`, matching the reference's `\b<ident>\s*=`:
/// a JS word boundary precedes the identifier and `=` (not `==`/`=>`) follows.
fn find_assignment(b: &[u8], ident: &[u8], from: usize) -> Option<usize> {
    if ident.is_empty() {
        return None;
    }
    let mut i = from;
    let first_word = is_word_js(ident[0]);
    while i + ident.len() < b.len() {
        if b[i..].starts_with(ident) {
            // `\b` before the identifier: boundary iff prev/cur word-ness differ.
            let prev_word = i > 0 && is_word_js(b[i - 1]);
            if prev_word != first_word {
                let after = i + ident.len();
                let mut j = skip_ws(b, after);
                if j < b.len() && b[j] == b'=' {
                    let nx = b.get(j + 1).copied();
                    if nx != Some(b'=') && nx != Some(b'>') {
                        j = skip_ws(b, j + 1);
                        return Some(j);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Parse a JS literal at `b[start]`. Returns `(value, end)`.
fn parse_value(b: &[u8], start: usize, tracer: &mut Tracer) -> (Val, usize) {
    let i = skip_ws(b, start);
    if i >= b.len() {
        return (Val::Null, i);
    }
    let c = b[i];
    if c == b'"' || c == b'\'' || c == b'`' {
        let end = skip_string(b, i);
        // `skip_string` clamps `end` to `b.len()` on an unterminated string, so the
        // inner range `i+1..end-1` can invert (start > end) for a lone trailing
        // quote. Guard with a checked slice rather than subtracting blindly.
        let raw = b.get(i + 1..end.saturating_sub(1)).unwrap_or(&[]);
        return (Val::Str(String::from_utf8_lossy(raw).into_owned()), end);
    }
    if c == b'{' {
        return parse_object(b, i, tracer);
    }
    if c == b'[' {
        return parse_array(b, i, tracer);
    }
    // Minifier booleans: `!0` = true, `!1` = false.
    if c == b'!' {
        match b.get(i + 1) {
            Some(b'0') => return (Val::Bool(true), i + 2),
            Some(b'1') => return (Val::Bool(false), i + 2),
            _ => {}
        }
    }
    if c.is_ascii_digit() || c == b'.' || c == b'-' {
        let mut k = i;
        if b[k] == b'-' {
            k += 1;
        }
        while k < b.len()
            && (b[k].is_ascii_digit() || matches!(b[k], b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            k += 1;
        }
        return (Val::Num, k);
    }
    if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
        let mut k = i;
        while k < b.len() && is_ident_byte(b[k]) {
            k += 1;
        }
        let ident = String::from_utf8_lossy(&b[i..k]).into_owned();
        // Walk member/call chains.
        let mut j = k;
        let mut is_complex = false;
        while j < b.len() {
            let ch = b[j];
            if ch == b'.' || ch == b'(' || ch == b'[' {
                is_complex = true;
                j = skip_expr(b, j, b",}]):");
                break;
            }
            if ch.is_ascii_whitespace() {
                j += 1;
                continue;
            }
            break;
        }
        if !is_complex {
            match ident.as_str() {
                "true" => return (Val::Bool(true), k),
                "false" => return (Val::Bool(false), k),
                "null" => return (Val::Null, k),
                "undefined" | "void" => return (Val::Undefined, k),
                _ => {}
            }
            if let Some(v) = tracer.trace(&ident) {
                return (v, k);
            }
            return (Val::Ref(ident), k);
        }
        let raw = String::from_utf8_lossy(&b[i..j]).trim().to_string();
        return (Val::Ref(raw), j);
    }
    let end = skip_expr(b, i, b",}]):");
    (Val::Null, end)
}

fn parse_key(b: &[u8], start: usize) -> (Option<String>, usize) {
    let mut i = skip_ws(b, start);
    if i >= b.len() {
        return (None, i);
    }
    let c = b[i];
    if c == b'"' || c == b'\'' {
        let q = c;
        i += 1;
        let st = i;
        while i < b.len() && b[i] != q {
            if b[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        let key = String::from_utf8_lossy(&b[st..i]).into_owned();
        return (Some(key), i + 1);
    }
    if c == b'[' {
        let end = skip_expr(b, i + 1, b"]");
        return (None, end + 1);
    }
    let st = i;
    while i < b.len() && is_ident_byte(b[i]) {
        i += 1;
    }
    if i > st {
        (Some(String::from_utf8_lossy(&b[st..i]).into_owned()), i)
    } else {
        (None, i)
    }
}

fn parse_object(b: &[u8], start: usize, tracer: &mut Tracer) -> (Val, usize) {
    let mut i = start + 1;
    let mut out: Vec<(String, Val)> = Vec::new();
    i = skip_ws(b, i);
    while i < b.len() && b[i] != b'}' {
        i = skip_ws(b, i);
        if i >= b.len() {
            break;
        }
        if b[i] == b'}' {
            break;
        }
        if b[i..].starts_with(b"...") {
            i += 3;
            let (v, end) = parse_value(b, i, tracer);
            if let Val::Obj(props) = v {
                for (k, vv) in props {
                    if !out.iter().any(|(ek, _)| *ek == k) {
                        out.push((k, vv));
                    }
                }
            }
            i = end;
            i = skip_ws(b, i);
            if i < b.len() && b[i] == b',' {
                i += 1;
            }
            continue;
        }
        let (key, kend) = parse_key(b, i);
        i = skip_ws(b, kend);
        if i < b.len() && b[i] == b'(' {
            i = skip_expr(b, i, b",}");
            if i < b.len() && b[i] == b',' {
                i += 1;
            }
            continue;
        }
        if i >= b.len() || b[i] != b':' {
            if let Some(k) = key {
                out.push((k.clone(), Val::Ref(k)));
            }
            if i < b.len() && b[i] == b',' {
                i += 1;
            }
            continue;
        }
        i += 1; // :
        let (v, end) = parse_value(b, i, tracer);
        if let Some(k) = key {
            // First write wins (mirror of `if (!(k in out))` semantics for spreads
            // is handled above; plain keys overwrite in JS, but Relay literals
            // never duplicate plain keys, so push is fine).
            out.push((k, v));
        }
        i = end;
        i = skip_ws(b, i);
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
    }
    let end = if i < b.len() { i + 1 } else { i };
    (Val::Obj(out), end)
}

fn parse_array(b: &[u8], start: usize, tracer: &mut Tracer) -> (Val, usize) {
    let mut i = start + 1;
    let mut out: Vec<Val> = Vec::new();
    i = skip_ws(b, i);
    while i < b.len() && b[i] != b']' {
        let (v, end) = parse_value(b, i, tracer);
        out.push(v);
        i = skip_ws(b, end);
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
        i = skip_ws(b, i);
    }
    let end = if i < b.len() { i + 1 } else { i };
    (Val::Arr(out), end)
}

// ─── operation literal + response shape ──────────────────────────────────────

/// Find the `{ kind:"Request", ... }` operation literal in a module body.
fn find_operation_literal(b: &[u8]) -> Option<Val> {
    let marker = find_sub(b, b"\"Request\"", 0)?;
    let mut tracer = Tracer::new(b);
    let mut i = marker as isize;
    let mut depth = 0i32;
    while i >= 0 {
        let c = b[i as usize];
        match c {
            b'}' | b')' | b']' => depth += 1,
            b'{' => {
                if depth == 0 {
                    let (v, _) = parse_object(b, i as usize, &mut tracer);
                    if v.get("kind").and_then(Val::as_str) == Some("Request") {
                        return Some(v);
                    }
                    depth = 0;
                } else {
                    depth -= 1;
                }
            }
            b'(' | b'[' if depth > 0 => {
                depth -= 1;
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

fn find_sub(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Walk a Relay `selections` array → response tree (`unknown`-tagged leaves).
fn shape_from_selections(selections: &Val) -> BTreeMap<String, TypeNode> {
    let mut fields: BTreeMap<String, TypeNode> = BTreeMap::new();
    let Val::Arr(items) = selections else {
        return fields;
    };
    for sel in items {
        let Val::Obj(_) = sel else { continue };
        let kind = sel.get("kind").and_then(Val::as_str).unwrap_or("");
        match kind {
            "ScalarField" | "TypeDiscriminator" => {
                let key = sel
                    .get("alias")
                    .and_then(Val::as_str)
                    .or_else(|| sel.get("name").and_then(Val::as_str))
                    .unwrap_or("__typename");
                fields
                    .entry(key.to_string())
                    .or_insert_with(|| TypeNode::Leaf(TypeNode::UNKNOWN.to_string()));
            }
            "LinkedField" => {
                let Some(key) = sel
                    .get("alias")
                    .and_then(Val::as_str)
                    .or_else(|| sel.get("name").and_then(Val::as_str))
                else {
                    continue;
                };
                let inner = match sel.get("selections") {
                    Some(s) => shape_from_selections(s),
                    None => BTreeMap::new(),
                };
                let plural = sel.get("plural").map(Val::is_truthy_bool).unwrap_or(false);
                let value = if plural {
                    TypeNode::Array(vec![TypeNode::Object(inner)])
                } else {
                    TypeNode::Object(inner)
                };
                let key = key.to_string();
                let merged = match fields.remove(&key) {
                    Some(existing) => merge_shape_node(Some(existing), Some(value)),
                    None => value,
                };
                fields.insert(key, merged);
            }
            "InlineFragment" | "Condition" => {
                if let Some(s) = sel.get("selections") {
                    let inner = shape_from_selections(s);
                    for (k, v) in inner {
                        let merged = match fields.remove(&k) {
                            Some(existing) => merge_shape_node(Some(existing), Some(v)),
                            None => v,
                        };
                        fields.insert(k, merged);
                    }
                }
            }
            _ => {}
        }
    }
    fields
}

/// Merge two shape nodes (InlineFragments may reintroduce parent keys). A leaf
/// stays a leaf; objects merge field-by-field; arrays merge their `[0]` element.
fn merge_shape_node(a: Option<TypeNode>, b: Option<TypeNode>) -> TypeNode {
    match (a, b) {
        (None, Some(b)) => b,
        (Some(a), None) => a,
        (None, None) => TypeNode::Leaf(TypeNode::UNKNOWN.to_string()),
        (Some(a), Some(b)) => match (a, b) {
            (TypeNode::Leaf(_), other) | (other, TypeNode::Leaf(_)) => {
                // `null`/leaf merged with a structured node → the structured one.
                // (In the reference, `a===null` → b, `b===null` → a; both leaves → a.)
                match other {
                    TypeNode::Leaf(l) => TypeNode::Leaf(l),
                    o => o,
                }
            }
            (TypeNode::Array(mut a), TypeNode::Array(b)) => {
                let ai = a.pop();
                let bi = b.into_iter().next();
                TypeNode::Array(vec![merge_shape_node(ai, bi)])
            }
            (TypeNode::Array(a), _) => TypeNode::Array(a),
            (_, TypeNode::Array(b)) => TypeNode::Array(b),
            (TypeNode::Object(a), TypeNode::Object(b)) => {
                let mut out = a;
                for (k, v) in b {
                    let merged = match out.remove(&k) {
                        Some(existing) => merge_shape_node(Some(existing), Some(v)),
                        None => v,
                    };
                    out.insert(k, merged);
                }
                TypeNode::Object(out)
            }
        },
    }
}

// ─── variablesShape (caller-module `.fetchQuery(id, <expr>)` scan) ───────────

/// Structure-only value (keys + plurality; leaves are unknown). Distinct from
/// `Val`: it never carries scalar values, only shape, per the reference's
/// `parseValueShape`.
#[derive(Debug, Clone)]
enum Shape {
    Null,
    Obj(Vec<(String, Shape)>),
    Arr(Box<Shape>),
}

impl Shape {
    fn into_type_node(self) -> TypeNode {
        match self {
            Shape::Null => TypeNode::Leaf(TypeNode::UNKNOWN.to_string()),
            Shape::Obj(props) => TypeNode::Object(
                props
                    .into_iter()
                    .map(|(k, v)| (k, v.into_type_node()))
                    .collect(),
            ),
            Shape::Arr(inner) => TypeNode::Array(vec![inner.into_type_node()]),
        }
    }
    fn get<'a>(&'a self, key: &str) -> Option<&'a Shape> {
        match self {
            Shape::Obj(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Resolve idents to their structural shape, scanning `sub` (the body up to the
/// call site) — mirror of the reference's `makeTracer`.
struct ShapeTracer<'b> {
    sub: &'b [u8],
    cache: std::collections::HashMap<String, Option<Shape>>,
}

impl<'b> ShapeTracer<'b> {
    fn new(sub: &'b [u8]) -> Self {
        ShapeTracer {
            sub,
            cache: std::collections::HashMap::new(),
        }
    }
    fn trace(&mut self, ident: &str) -> Option<Shape> {
        if let Some(v) = self.cache.get(ident) {
            return v.clone();
        }
        self.cache.insert(ident.to_string(), None);
        let mut last: Option<Shape> = None;
        let mut search = 0;
        let ident_b = ident.as_bytes();
        while let Some(pos) = find_assignment(self.sub, ident_b, search) {
            search = pos + 1;
            let after = skip_ws(self.sub, pos);
            if after < self.sub.len() && (self.sub[after] == b'{' || self.sub[after] == b'[') {
                let (v, _) = parse_value_shape(self.sub, after, self);
                if !matches!(v, Shape::Null) {
                    last = Some(v);
                }
            }
        }
        self.cache.insert(ident.to_string(), last.clone());
        last
    }
}

const ARRAY_METHODS: &[&str] = &[
    ".map", ".filter", ".slice", ".concat", ".flat", ".flatMap", ".sort", ".reverse", ".splice",
];

fn parse_value_shape(s: &[u8], start: usize, tracer: &mut ShapeTracer) -> (Shape, usize) {
    let i = skip_ws(s, start);
    if i >= s.len() {
        return (Shape::Null, i);
    }
    let c = s[i];
    if c == b'{' {
        return parse_object_shape(s, i, Some(tracer));
    }
    if c == b'[' {
        return parse_array_shape(s, i, tracer);
    }
    if is_ident_byte(c) {
        let mut k = i;
        while k < s.len() && is_ident_byte(s[k]) {
            k += 1;
        }
        let ident = String::from_utf8_lossy(&s[i..k]).into_owned();
        let mut n = k;
        while n < s.len() && s[n].is_ascii_whitespace() {
            n += 1;
        }
        if s.get(n) != Some(&b'(') && s.get(n) != Some(&b'.') {
            let traced = tracer.trace(&ident).unwrap_or(Shape::Null);
            return (traced, skip_expr(s, i, b",}]"));
        }
    }
    let end = skip_expr(s, i, b",}]");
    let expr = &s[i..end];
    if has_array_method(expr) {
        if let Some(inner) = extract_map_callback_return(expr) {
            return (Shape::Arr(Box::new(inner)), end);
        }
        return (Shape::Arr(Box::new(Shape::Null)), end);
    }
    if starts_with_array_producer(expr) {
        return (Shape::Arr(Box::new(Shape::Null)), end);
    }
    (Shape::Null, end)
}

fn has_array_method(expr: &[u8]) -> bool {
    ARRAY_METHODS.iter().any(|m| {
        let mb = m.as_bytes();
        find_sub(expr, mb, 0)
            .map(|p| {
                let after = p + mb.len();
                let j = skip_ascii_ws(expr, after);
                expr.get(j) == Some(&b'(')
            })
            .unwrap_or(false)
    })
}

fn starts_with_array_producer(expr: &[u8]) -> bool {
    for pfx in [
        &b"Array.from"[..],
        b"Array.of",
        b"Object.keys",
        b"Object.values",
        b"Object.entries",
    ] {
        if expr.starts_with(pfx) {
            let j = skip_ascii_ws(expr, pfx.len());
            if expr.get(j) == Some(&b'(') {
                return true;
            }
        }
    }
    false
}

fn skip_ascii_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// `<x>.map(function(p){return <objLit>})` / `.map(p => <objLit>)` → the item
/// object shape, else `None` (caller falls back to `[null]`).
fn extract_map_callback_return(expr: &[u8]) -> Option<Shape> {
    let m = find_sub(expr, b".map", 0)?;
    let i = find_sub(expr, b"(", m)?;
    let mut dp = 1i32;
    let mut j = i + 1;
    while j < expr.len() && dp > 0 {
        let c = expr[j];
        if c == b'"' || c == b'\'' || c == b'`' {
            j = skip_string(expr, j);
            continue;
        }
        if c == b'(' {
            dp += 1;
        } else if c == b')' {
            dp -= 1;
        }
        j += 1;
    }
    let cb = &expr[i + 1..j.saturating_sub(1)];
    if let Some(rpos) = find_return(cb) {
        let k = skip_ascii_ws(cb, rpos);
        if cb.get(k) == Some(&b'{') {
            let (v, _) = parse_object_shape(cb, k, None);
            return Some(v);
        }
        return None;
    }
    // Arrow shorthand `p => (<expr>)` / `p => <expr>`.
    let arrow = find_sub(cb, b"=>", 0)?;
    let mut k = arrow + 2;
    k = skip_ascii_ws(cb, k);
    if cb.get(k) == Some(&b'(') {
        k += 1;
    }
    if cb.get(k) == Some(&b'{') {
        let (v, _) = parse_object_shape(cb, k, None);
        return Some(v);
    }
    None
}

/// Index just after a `return` keyword (word-bounded), or `None`.
fn find_return(b: &[u8]) -> Option<usize> {
    let mut search = 0;
    while let Some(p) = find_sub(b, b"return", search) {
        let before_ok = p == 0 || !is_word_js(b[p - 1]);
        let after = p + 6;
        let after_ok = after >= b.len() || !is_word_js(b[after]);
        if before_ok && after_ok {
            return Some(after);
        }
        search = p + 1;
    }
    None
}

fn parse_object_shape(
    s: &[u8],
    start: usize,
    mut tracer: Option<&mut ShapeTracer>,
) -> (Shape, usize) {
    let mut i = start + 1;
    let mut out: Vec<(String, Shape)> = Vec::new();
    let mut last = usize::MAX;
    i = skip_ws(s, i);
    while i < s.len() && s[i] != b'}' {
        // No-progress guard: any path that fails to advance forces +1 so a stray
        // token can't wedge the loop (the reference degrades rather than hanging).
        if i == last {
            i += 1;
            continue;
        }
        last = i;
        i = skip_ws(s, i);
        if i >= s.len() || s[i] == b'}' {
            break;
        }
        if s[i..].starts_with(b"...") {
            i += 3;
            let mut k = i;
            while k < s.len() && is_ident_byte(s[k]) {
                k += 1;
            }
            let ident = String::from_utf8_lossy(&s[i..k]).into_owned();
            if !ident.is_empty()
                && let Some(t) = tracer.as_deref_mut()
                && let Some(Shape::Obj(props)) = t.trace(&ident)
            {
                for (kk, vv) in props {
                    if !out.iter().any(|(ek, _)| *ek == kk) {
                        out.push((kk, vv));
                    }
                }
            }
            i = skip_expr(s, i, b",}");
            if i < s.len() && s[i] == b',' {
                i += 1;
            }
            i = skip_ws(s, i);
            continue;
        }
        // key
        let key: Option<String>;
        let c = s[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            let st = i;
            while i < s.len() && s[i] != q {
                if s[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            key = Some(String::from_utf8_lossy(&s[st..i]).into_owned());
            i += 1;
        } else if c == b'[' {
            i = skip_expr(s, i + 1, b"]") + 1;
            key = None;
        } else {
            let st = i;
            while i < s.len() && is_ident_byte(s[i]) {
                i += 1;
            }
            key = if i > st {
                Some(String::from_utf8_lossy(&s[st..i]).into_owned())
            } else {
                None
            };
        }
        i = skip_ws(s, i);
        if i < s.len() && s[i] == b'(' {
            i = skip_expr(s, i, b",}");
            if i < s.len() && s[i] == b',' {
                i += 1;
            }
            i = skip_ws(s, i);
            continue;
        }
        if i >= s.len() || s[i] != b':' {
            if let Some(k) = key {
                out.push((k, Shape::Null));
            }
            if i < s.len() && s[i] == b',' {
                i += 1;
            }
            i = skip_ws(s, i);
            continue;
        }
        i += 1;
        let (v, end) = match tracer.as_deref_mut() {
            Some(t) => parse_value_shape(s, i, t),
            None => parse_value_shape_no_trace(s, i),
        };
        if let Some(k) = key {
            out.push((k, v));
        }
        i = end;
        i = skip_ws(s, i);
        if i < s.len() && s[i] == b',' {
            i += 1;
        }
        i = skip_ws(s, i);
    }
    let end = if i < s.len() { i + 1 } else { i };
    (Shape::Obj(out), end)
}

/// `parse_value_shape` without a tracer (used inside `.map` callbacks, where the
/// reference passes `null` for `traceIdent`).
fn parse_value_shape_no_trace(s: &[u8], start: usize) -> (Shape, usize) {
    let i = skip_ws(s, start);
    if i >= s.len() {
        return (Shape::Null, i);
    }
    match s[i] {
        b'{' => parse_object_shape(s, i, None),
        b'[' => {
            // array without tracing: first element shape, then the matching `]`.
            let j = skip_ws(s, i + 1);
            let first = if j < s.len() && s[j] != b']' {
                parse_value_shape_no_trace(s, j).0
            } else {
                Shape::Null
            };
            let close = skip_expr(s, i + 1, b"]");
            let end = if close < s.len() { close + 1 } else { close };
            (Shape::Arr(Box::new(first)), end)
        }
        _ => (Shape::Null, skip_expr(s, i, b",}]")),
    }
}

fn parse_array_shape(s: &[u8], start: usize, tracer: &mut ShapeTracer) -> (Shape, usize) {
    let mut i = start + 1;
    i = skip_ws(s, i);
    let first = if i < s.len() && s[i] != b']' {
        parse_value_shape(s, i, tracer).0
    } else {
        Shape::Null
    };
    // Skip to the matching `]`.
    let mut dbr = 0i32;
    while i < s.len() {
        let c = s[i];
        match c {
            b'[' => dbr += 1,
            b']' => {
                if dbr == 0 {
                    i += 1;
                    break;
                }
                dbr -= 1;
            }
            b'"' | b'\'' | b'`' => {
                i = skip_string(s, i);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    (Shape::Arr(Box::new(first)), i)
}

/// Merge two shapes (multiple `fetchQuery` calls / ternary branches).
fn merge_shapes(a: Option<Shape>, b: Option<Shape>) -> Option<Shape> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(match (a, b) {
            (Shape::Arr(a), _) => Shape::Arr(a),
            (_, Shape::Arr(b)) => Shape::Arr(b),
            (Shape::Obj(a), Shape::Obj(b)) => {
                let mut out = a;
                for (k, v) in b {
                    if let Some(slot) = out.iter_mut().find(|(ek, _)| *ek == k) {
                        let merged = merge_shapes(Some(slot.1.clone()), Some(v)).unwrap();
                        slot.1 = merged;
                    } else {
                        out.push((k, v));
                    }
                }
                Shape::Obj(out)
            }
            (a, _) => a,
        }),
    }
}

/// Parse the 2nd arg of a `fetchQuery(id, <expr>)` call into a shape, handling a
/// direct object/array, a ternary `cond ? {..} : {..}`, or a bare identifier.
fn parse_second_arg(body: &[u8], start: usize) -> Option<Shape> {
    let i = skip_ws(body, start);
    let mut tracer = ShapeTracer::new(&body[..start]);
    if i >= body.len() {
        return None;
    }
    let c = body[i];
    if c == b'{' || c == b'[' {
        return Some(parse_value_shape(body, i, &mut tracer).0);
    }
    // Look for a top-level `?` (ternary) before a `,`/`)`.
    let mut j = i;
    let mut dp = 0i32;
    let mut found: Option<usize> = None;
    while j < body.len() {
        let ch = body[j];
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            j = skip_string(body, j);
            continue;
        }
        match ch {
            b'(' => dp += 1,
            b')' => {
                if dp == 0 {
                    break;
                }
                dp -= 1;
            }
            b'?' if dp == 0 => {
                found = Some(j);
                break;
            }
            b',' if dp == 0 => break,
            _ => {}
        }
        j += 1;
    }
    if let Some(q) = found {
        let mut k = skip_ws(body, q + 1);
        let left = if body.get(k) == Some(&b'{') || body.get(k) == Some(&b'[') {
            let (v, end) = parse_value_shape(body, k, &mut tracer);
            k = end;
            Some(v)
        } else if k < body.len() && is_ident_byte(body[k]) {
            let st = k;
            while k < body.len() && is_ident_byte(body[k]) {
                k += 1;
            }
            tracer.trace(&String::from_utf8_lossy(&body[st..k]))
        } else {
            k = skip_expr(body, k, b":,");
            None
        };
        k = skip_ws(body, k);
        if body.get(k) == Some(&b':') {
            k = skip_ws(body, k + 1);
            let right = if body.get(k) == Some(&b'{') || body.get(k) == Some(&b'[') {
                Some(parse_value_shape(body, k, &mut tracer).0)
            } else if k < body.len() && is_ident_byte(body[k]) {
                let st = k;
                while k < body.len() && is_ident_byte(body[k]) {
                    k += 1;
                }
                tracer.trace(&String::from_utf8_lossy(&body[st..k]))
            } else {
                None
            };
            return merge_shapes(left, right);
        }
        return left;
    }
    if is_ident_byte(c) {
        let mut k = i;
        while k < body.len() && is_ident_byte(body[k]) {
            k += 1;
        }
        return tracer.trace(&String::from_utf8_lossy(&body[i..k]));
    }
    None
}

/// Keep only argDef-named keys (the authoritative variable names), preserving
/// their recovered nested shape and filling missing ones as `null` leaves.
fn augment_with_arg_defs(
    shape: Option<Shape>,
    arg_def_names: &[String],
) -> BTreeMap<String, TypeNode> {
    if arg_def_names.is_empty() {
        return match shape {
            Some(Shape::Obj(props)) => props
                .into_iter()
                .map(|(k, v)| (k, v.into_type_node()))
                .collect(),
            _ => BTreeMap::new(),
        };
    }
    let src = match &shape {
        Some(s @ Shape::Obj(_)) => Some(s),
        _ => None,
    };
    let mut out = BTreeMap::new();
    for name in arg_def_names {
        let node = src
            .and_then(|s| s.get(name))
            .cloned()
            .unwrap_or(Shape::Null)
            .into_type_node();
        out.insert(name.clone(), node);
    }
    out
}

/// Build the `variablesShape` for an operation from its caller module body +
/// the authoritative argDef names.
pub(crate) fn variables_shape(
    caller_srcs: &[&str],
    variable_arguments: &[(usize, u32)],
    arg_def_names: &[String],
) -> BTreeMap<String, TypeNode> {
    // Every caller, folded, for the same reason the presence pass reads them all:
    // two job modules can send the same operation with different nested input
    // fields, and the two maps are published as siblings whose keys must agree.
    // Deriving the shape from one caller while presence saw them all would let
    // presence carry a nested key the shape does not, which `scripts/lint-ir.py`
    // rejects outright - the operation would fail to publish rather than come
    // out imprecise.
    // Only the calls the presence pass tied to THIS operation. A caller that
    // sends two operations writes two variables objects, and reading both into
    // one shape publishes the other operation's keys here - which the presence
    // pass then has to answer for with a verdict about a key this operation does
    // not have.
    let raw = variable_arguments
        .iter()
        .filter_map(|(caller, offset)| {
            let body = caller_srcs.get(*caller)?.as_bytes();
            parse_second_arg(body, *offset as usize)
        })
        .fold(None, |acc, shape| merge_shapes(acc, Some(shape)));
    type_tree(augment_with_arg_defs(raw, arg_def_names), true)
}

// ─── pragmatic leaf typing ───────────────────────────────────────────────────

/// Pragmatic scalar type from a field name (snake_case GraphQL convention).
/// Not the reference's consumer-scanning heuristic — a deterministic, readable
/// approximation: booleans for predicate/flag names, numbers for count/time/size
/// names, string otherwise.
fn infer_scalar(name: &str) -> &'static str {
    const BOOL_PREFIX: &[&str] = &[
        "is_", "has_", "can_", "should_", "allow_", "are_", "was_", "did_", "fetch_", "include_",
        "enable", "disable",
    ];
    const BOOL_SUFFIX: &[&str] = &["_enabled", "_disabled", "_allowed", "_required"];
    const NUM_SUFFIX: &[&str] = &[
        "_count",
        "_time",
        "_timestamp",
        "_ts",
        "_at",
        "_secs",
        "_seconds",
        "_ms",
        "_index",
        "_size",
        "_width",
        "_height",
        "_duration",
        "_revision",
        "_version",
        "_number",
    ];
    if BOOL_PREFIX.iter().any(|p| name.starts_with(p))
        || BOOL_SUFFIX.iter().any(|s| name.ends_with(s))
        || name == "enabled"
    {
        return "boolean";
    }
    if NUM_SUFFIX.iter().any(|s| name.ends_with(s))
        || matches!(
            name,
            "count"
                | "index"
                | "size"
                | "width"
                | "height"
                | "duration"
                | "timestamp"
                | "limit"
                | "offset"
                | "version"
        )
    {
        return "number";
    }
    "string"
}

/// Plural id/jid collection names (`*_ids`, `*_jids`) are GraphQL list variables
/// (e.g. `message_ids: [String!]`), not scalars. Applied only to input variables,
/// where an opaque ref carries no structural array clue; confirmed against WA Web
/// (`pinNewsletterMessages(a, [String(n)])` feeds `input.message_ids`).
fn is_id_list_name(name: &str) -> bool {
    name.ends_with("_ids") || name.ends_with("_jids")
}

/// Type a *named* field. The plural-`_ids`/`_jids` list heuristic fires only
/// here — where `key_hint` genuinely names the field — never on array elements,
/// which merely inherit the parent's plural key and would otherwise double-wrap
/// into `[[string]]`. Gated to input variables (`vars`); responses pass `false`.
fn type_field(node: TypeNode, key_hint: &str, vars: bool) -> TypeNode {
    let opaque_leaf = matches!(&node, TypeNode::Leaf(t) if t.as_str() == TypeNode::UNKNOWN);
    if vars && opaque_leaf && is_id_list_name(key_hint) {
        return TypeNode::Array(vec![TypeNode::Leaf("string".to_string())]);
    }
    type_node(node, key_hint, vars)
}

/// Replace `unknown` scalar leaves with a pragmatic concrete type based on the
/// field name they sit under. Array elements inherit their field's name hint but
/// stay scalar (the list heuristic lives in `type_field`); object fields recurse
/// through `type_field` so nested `_ids` fields are still promoted. `vars` threads
/// the input-variable context (see `type_field`).
fn type_node(node: TypeNode, key_hint: &str, vars: bool) -> TypeNode {
    match node {
        TypeNode::Leaf(tag) if tag == TypeNode::UNKNOWN => {
            TypeNode::Leaf(infer_scalar(key_hint).to_string())
        }
        TypeNode::Leaf(t) => TypeNode::Leaf(t),
        TypeNode::Array(items) => TypeNode::Array(
            items
                .into_iter()
                .map(|n| type_node(n, key_hint, vars))
                .collect(),
        ),
        TypeNode::Object(map) => TypeNode::Object(
            map.into_iter()
                .map(|(k, n)| {
                    let typed = type_field(n, &k, vars);
                    (k, typed)
                })
                .collect(),
        ),
    }
}

fn type_tree(map: BTreeMap<String, TypeNode>, vars: bool) -> BTreeMap<String, TypeNode> {
    map.into_iter()
        .map(|(k, n)| {
            let typed = type_field(n, &k, vars);
            (k, typed)
        })
        .collect()
}

/// Extract the response shape tree from a `.graphql` module body (typed leaves).
pub(crate) fn response_from_module(module_src: &str) -> BTreeMap<String, TypeNode> {
    let b = module_src.as_bytes();
    let Some(op) = find_operation_literal(b) else {
        return BTreeMap::new();
    };
    let structural = op
        .get("operation")
        .and_then(|o| o.get("selections"))
        .map(shape_from_selections)
        .unwrap_or_default();
    type_tree(structural, false)
}

/// Test helper: every Relay call in the sources, as the scanner used to find
/// them, so the shape tests can stay written against a caller body.
#[cfg(test)]
fn all_variable_arguments(caller_srcs: &[&str]) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    for (i, src) in caller_srcs.iter().enumerate() {
        let body = src.as_bytes();
        for method in [
            &b".fetchQuery"[..],
            b".commitMutation",
            b".fetchSubscription",
        ] {
            let mut search = 0;
            while let Some(p) = find_sub(body, method, search) {
                let after = p + method.len();
                let paren = skip_ascii_ws(body, after);
                search = p + 1;
                if body.get(paren) != Some(&b'(') {
                    continue;
                }
                let comma = skip_expr(body, paren + 1, b",");
                if body.get(comma) != Some(&b',') {
                    continue;
                }
                out.push((i, (comma + 1) as u32));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A compact Relay-style operation literal with hoisted selection vars,
    // a scalar, a singular LinkedField, a plural LinkedField, and an alias.
    const MODULE: &str = r#"__d("WAWebFooQuery.graphql",[],(function(g,r,d,o,e,i){
        var s=[{kind:"ScalarField",name:"id"},{kind:"ScalarField",alias:"renamed",name:"raw"}],
            t=[{kind:"ScalarField",name:"x"}],
            u=[{kind:"LinkedField",name:"items",plural:!0,selections:t},{kind:"LinkedField",name:"meta",plural:!1,selections:s}];
        e.exports=(function(){return{kind:"Request",params:{id:"1",name:"WAWebFooQuery",operationKind:"query"},operation:{name:"WAWebFooQuery",selections:u}}})()
    }),1);"#;

    #[test]
    fn unterminated_string_does_not_panic() {
        // A lone trailing quote makes skip_string clamp end to b.len(); the inner
        // slice i+1..end-1 would invert and panic without the guard. Exercise the
        // string, object, and array entry points.
        let mut tracer = Tracer::new(b"");
        assert!(matches!(parse_value(b"\"", 0, &mut tracer).0, Val::Str(_)));
        let _ = parse_object(b"{a:\"", 0, &mut tracer);
        let _ = parse_array(b"[\"", 0, &mut tracer);
    }

    #[test]
    fn builds_response_tree_with_plurality_and_aliases() {
        let resp = response_from_module(MODULE);
        // meta -> object { id, renamed }
        let meta = resp.get("meta").expect("meta field");
        let TypeNode::Object(m) = meta else {
            panic!("meta should be object: {meta:?}")
        };
        assert!(m.contains_key("id") && m.contains_key("renamed"));
        // items -> array of object { x }
        let items = resp.get("items").expect("items field");
        let TypeNode::Array(arr) = items else {
            panic!("items should be array")
        };
        let TypeNode::Object(inner) = &arr[0] else {
            panic!("items[0] object")
        };
        assert!(inner.contains_key("x"));
    }

    #[test]
    fn inline_fragment_merges_into_parent() {
        let m = r#"__d("WAWebBarQuery.graphql",[],(function(g,r,d,o,e,i){
            e.exports={kind:"Request",params:{id:"2",name:"WAWebBarQuery",operationKind:"query"},operation:{name:"WAWebBarQuery",selections:[{kind:"LinkedField",name:"node",plural:!1,selections:[{kind:"ScalarField",name:"a"},{kind:"InlineFragment",selections:[{kind:"ScalarField",name:"b"}]}]}]}}
        }),1);"#;
        let resp = response_from_module(m);
        let TypeNode::Object(node) = resp.get("node").unwrap() else {
            panic!()
        };
        assert!(
            node.contains_key("a") && node.contains_key("b"),
            "inline fragment fields merged"
        );
    }

    #[test]
    fn no_request_yields_empty() {
        assert!(response_from_module("var x=1;").is_empty());
    }

    fn leaf(node: &TypeNode) -> &str {
        match node {
            TypeNode::Leaf(s) => s,
            _ => panic!("expected leaf, got {node:?}"),
        }
    }

    #[test]
    fn pragmatic_scalar_typing() {
        assert_eq!(infer_scalar("is_admin"), "boolean");
        assert_eq!(infer_scalar("fetch_full_image"), "boolean");
        assert_eq!(infer_scalar("auto_add_disabled"), "boolean");
        assert_eq!(infer_scalar("member_count"), "number");
        assert_eq!(infer_scalar("creation_time"), "number");
        assert_eq!(infer_scalar("version"), "number");
        assert_eq!(infer_scalar("name"), "string");
        assert_eq!(infer_scalar("jid"), "string");
    }

    #[test]
    fn response_leaves_are_typed_by_field_name() {
        let m = r#"__d("WAWebTypedQuery.graphql",[],(function(g,r,d,o,e,i){
            e.exports={kind:"Request",params:{id:"1",name:"WAWebTypedQuery",operationKind:"query"},operation:{name:"WAWebTypedQuery",selections:[{kind:"ScalarField",name:"name"},{kind:"ScalarField",name:"member_count"},{kind:"ScalarField",name:"is_open"}]}}
        }),1);"#;
        let r = response_from_module(m);
        assert_eq!(leaf(r.get("name").unwrap()), "string");
        assert_eq!(leaf(r.get("member_count").unwrap()), "number");
        assert_eq!(leaf(r.get("is_open").unwrap()), "boolean");
    }

    #[test]
    fn dollar_named_var_is_not_traced_like_the_reference() {
        // Relay hoists a `$`-named selection var; the reference's `\b$` regex
        // can't resolve it, so the field is dropped. We must match that.
        let m = r#"__d("WAWebDollarQuery.graphql",[],(function(g,r,d,o,e,i){
            var $={kind:"ScalarField",name:"secret"},n=[{kind:"ScalarField",name:"id"},$];
            e.exports={kind:"Request",params:{id:"1",name:"WAWebDollarQuery",operationKind:"query"},operation:{name:"WAWebDollarQuery",selections:n}}
        }),1);"#;
        let r = response_from_module(m);
        assert!(r.contains_key("id"), "normal field present");
        assert!(
            !r.contains_key("secret"),
            "$-traced field dropped (reference parity)"
        );
    }

    #[test]
    fn variables_shape_from_caller_fetch_query() {
        // Caller invokes fetchQuery(id, {input:{group_jid,reason}, fetch_meta}).
        let caller = r#"function send(t){return o("RelayRuntime").fetchQuery(n,{input:{group_jid:t.jid,reason:t.why},fetch_meta:!0})}"#;
        let vs = variables_shape(
            &[caller],
            &all_variable_arguments(&[caller]),
            &["input".to_string(), "fetch_meta".to_string()],
        );
        let TypeNode::Object(input) = vs.get("input").unwrap() else {
            panic!("input object")
        };
        assert_eq!(leaf(input.get("group_jid").unwrap()), "string");
        assert_eq!(leaf(input.get("reason").unwrap()), "string");
        assert_eq!(leaf(vs.get("fetch_meta").unwrap()), "boolean");
    }

    #[test]
    fn variables_shape_plural_ids_ref_becomes_string_list() {
        // Real WA shape: `fetchQuery(id, {newsletter_id:t, input:{message_ids:r}})`,
        // where `r` is an opaque param fed an array at the outer call site
        // (`pinNewsletterMessages(a, [String(n)])`). Plural `_ids` ⇒ list of strings.
        let caller = r#"function s(t,r){return o("WAWebMexClient").fetchQuery(i,{newsletter_id:t,input:{message_ids:r}})}"#;
        let vs = variables_shape(
            &[caller],
            &all_variable_arguments(&[caller]),
            &["newsletter_id".to_string(), "input".to_string()],
        );
        assert_eq!(leaf(vs.get("newsletter_id").unwrap()), "string");
        let TypeNode::Object(input) = vs.get("input").unwrap() else {
            panic!("input object")
        };
        let TypeNode::Array(items) = input.get("message_ids").unwrap() else {
            panic!("message_ids must be a list, not a scalar")
        };
        assert_eq!(leaf(&items[0]), "string");

        // `_jids` suffix takes the same branch.
        let caller_jids = r#"function s(t,r){return o("WAWebMexClient").fetchQuery(i,{input:{participant_jids:r}})}"#;
        let vs_jids = variables_shape(
            &[caller_jids],
            &all_variable_arguments(&[caller_jids]),
            &["input".to_string()],
        );
        let TypeNode::Object(input_jids) = vs_jids.get("input").unwrap() else {
            panic!("input object")
        };
        let TypeNode::Array(jids) = input_jids.get("participant_jids").unwrap() else {
            panic!("participant_jids must be a list, not a scalar")
        };
        assert_eq!(leaf(&jids[0]), "string");
    }

    #[test]
    fn variables_shape_plural_ids_explicit_array_not_double_wrapped() {
        // When the caller already spells the list out (`message_ids:[e]`), the
        // extractor yields `Array([Leaf(unknown)])`. The heuristic must not fire on
        // the array *element* (inherited `_ids` key), else we'd get `[[string]]`.
        let caller = r#"function s(t,e){return o("WAWebMexClient").fetchQuery(i,{input:{message_ids:[e]}})}"#;
        let vs = variables_shape(
            &[caller],
            &all_variable_arguments(&[caller]),
            &["input".to_string()],
        );
        let TypeNode::Object(input) = vs.get("input").unwrap() else {
            panic!("input object")
        };
        let TypeNode::Array(items) = input.get("message_ids").unwrap() else {
            panic!("message_ids array")
        };
        assert_eq!(items.len(), 1, "single list level");
        assert_eq!(
            leaf(&items[0]),
            "string",
            "element is a scalar, not a nested list"
        );
    }

    #[test]
    fn variables_shape_argdefs_are_authoritative() {
        // No caller → every argDef becomes a typed leaf; sibling keys excluded.
        let vs = variables_shape(
            &[],
            &all_variable_arguments(&[]),
            &["newsletter_id".to_string()],
        );
        assert_eq!(vs.len(), 1);
        assert!(vs.contains_key("newsletter_id"));
    }

    #[test]
    fn map_callback_nested_array_keeps_sibling_keys() {
        // Regression: `.map(e => ({ a:[{x}], b:1 }))` — the no-trace array parser
        // must stop at its matching `]`, not run to end and drop `b`.
        let caller = r#"function f(a){return o("R").commitMutation(n,{input:a.map(function(e){return{a:[{x:e.x}],b:e.y}})})}"#;
        let vs = variables_shape(
            &[caller],
            &all_variable_arguments(&[caller]),
            &["input".to_string()],
        );
        let TypeNode::Array(items) = vs.get("input").unwrap() else {
            panic!("input array")
        };
        let TypeNode::Object(item) = &items[0] else {
            panic!("item object")
        };
        assert!(item.contains_key("a"), "nested-array key present");
        assert!(
            item.contains_key("b"),
            "sibling key after array NOT dropped"
        );
        assert!(
            matches!(item.get("a"), Some(TypeNode::Array(_))),
            "a is an array"
        );
    }

    #[test]
    fn variables_shape_map_callback_recovers_array_item() {
        // `.map(function(e){return {newsletter_id:..,capability:..}})` → array item shape.
        let caller = r#"function f(a){return o("R").commitMutation(n,{input:{exposures:a.map(function(e){return{newsletter_id:e.id,capability:e.cap}})}})}"#;
        let vs = variables_shape(
            &[caller],
            &all_variable_arguments(&[caller]),
            &["input".to_string()],
        );
        let TypeNode::Object(input) = vs.get("input").unwrap() else {
            panic!()
        };
        let TypeNode::Array(items) = input.get("exposures").unwrap() else {
            panic!("exposures array")
        };
        let TypeNode::Object(item) = &items[0] else {
            panic!("array item object")
        };
        assert!(item.contains_key("newsletter_id") && item.contains_key("capability"));
    }
}
