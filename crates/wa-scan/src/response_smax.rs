//! Response analysis for the `WASmax` world (Phase 3).
//!
//! Unlike the legacy `WADeprecatedWapParser` (methods called on the node param,
//! e.g. `e.attrString("x")`), smax responses are **free functions** in dedicated
//! `WASmaxIn<X>ResponseSuccess` modules, written as a Result-railway:
//!
//! ```text
//! function group(node) {                       // inner child parser
//!   var t = assertTag(node, "group");          if (!t.success) return t;
//!   var n = optional(attrIntRange, node, "size", 0, 19999);
//!   var r = parseGroupInfoMixin(node);         if (!r.success) return r;
//!   return makeResult(babelHelpers.extends({ size: n.value }, r.value));
//! }
//! function iq(node, ref) {                      // exported ResponseSuccess parser
//!   var a = optionalChildWithTag(node, "group", group);  // recurse into `group`
//!   …
//!   return makeResult({ type: s.value, group: a.value });
//! }
//! ```
//!
//! The **tail** `makeResult({...})` / `babelHelpers.extends({...}, mixin.value)`
//! is the authoritative field list: each `k: V.value` names an output field whose
//! type comes from the helper that bound `V`. Assertions (`assertTag`, `literal…`)
//! bind vars but contribute no field. Child accessors (`optionalChildWithTag`,
//! `mapChildrenWithTag`, …) take a *local* parser function as their last arg; we
//! resolve and analyze it recursively to recover the child's (possibly repeated)
//! field tree. Cross-module payload **mixins** (`parse…Mixin`) are resolved from
//! the response index.
//!
//! We normalize the smax helper vocabulary into the canonical [`wa_ir::wap`]
//! method names the codegen already understands, so the IR and codegen are
//! unchanged. This analyzer is entirely separate from the legacy one (`response.rs`)
//! to avoid any regression to its 33 stanzas / tests.

use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, Function, Statement};
use oxc_span::GetSpan;
use wa_ir::wap;
use wa_ir::{AssertionKind, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, callee_method};

/// A module's local parser functions, keyed by name → re-parsable source. Child
/// accessors reference these by identifier (`optionalChildWithTag(n, "x", parseX)`).
type LocalFns = HashMap<String, String>;

/// One railway binding: `var V = <call>;` → what `V` resolves to.
#[derive(Clone)]
enum Binding {
    /// A value field: the normalized wap method + field type + required flag.
    Field {
        method: String,
        field_type: ParsedFieldType,
        required: bool,
        byte_length: Option<u32>,
        /// The wire attr/content name (the accessor's literal arg), when present.
        wire_name: Option<String>,
    },
    /// A nested payload mixin call (`parse<Name>Mixin(...)`) → its module-less
    /// mixin key, resolved later from the response index.
    Mixin(String),
    /// A child accessor (`optionalChildWithTag`/`mapChildrenWithTag`/…) whose
    /// inner parser was resolved + analyzed: the child's wire tag, its field tree,
    /// and whether it repeats (`mapChildrenWithTag` → a list).
    ChildGroup {
        tag: String,
        fields: Vec<ParsedField>,
        repeats: bool,
        /// The accessor was `optionalChild`/`optionalChildWithTag` (the child may
        /// be absent), so the field is optional regardless of the tail form.
        optional: bool,
    },
    /// An assertion / literal / node-reshape — no field.
    None,
}

/// Analyze every exported `parse…` function in a smax module slice into
/// `(export_name, ParsedResponse)` pairs. Local child parsers are resolved within
/// the module; cross-module payload mixins come from `mixins`.
pub(crate) fn analyze_module_exports(
    module_slice: &str,
    mixins: &HashMap<String, ParsedResponse>,
) -> Vec<(String, ParsedResponse)> {
    let locals = collect_local_fn_sources(module_slice);
    let mut out = Vec::new();
    for (export, local) in collect_exports(module_slice) {
        if !export.starts_with("parse") {
            continue;
        }
        let Some(src) = locals.get(&local) else {
            continue;
        };
        let mut visited = HashSet::new();
        visited.insert(local.clone());
        if let Some((assertions, fields)) = analyze_fn_source(src, &locals, mixins, &mut visited) {
            out.push((
                export.clone(),
                ParsedResponse {
                    parser_name: export,
                    assertions,
                    fields,
                    ..Default::default()
                },
            ));
        }
    }
    out
}

/// Analyze a single parse-function source (`function name(args){…}`).
fn analyze_fn_source(
    fn_source: &str,
    locals: &LocalFns,
    mixins: &HashMap<String, ParsedResponse>,
    visited: &mut HashSet<String>,
) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, fn_source);
    let func = ret.program.body.iter().find_map(|s| match s {
        Statement::FunctionDeclaration(f) => Some(&**f),
        _ => None,
    })?;
    analyze_function(func, locals, mixins, visited)
}

fn analyze_function(
    func: &Function,
    locals: &LocalFns,
    mixins: &HashMap<String, ParsedResponse>,
    visited: &mut HashSet<String>,
) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
    let body = func.body.as_ref()?;
    let mut assertions: Vec<ResponseAssertion> = Vec::new();
    let mut bindings: HashMap<String, Binding> = HashMap::new();

    let mut tail: Option<&Expression> = None;
    for stmt in &body.statements {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                for d in &decl.declarations {
                    let Some(name) = d.id.get_identifier_name() else {
                        continue;
                    };
                    if let Some(init) = d.init.as_ref() {
                        let b = classify_call(init, &mut assertions, locals, mixins, visited);
                        bindings.insert(name.to_string(), b);
                    }
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                tail = ret_stmt.argument.as_ref();
            }
            _ => {}
        }
    }

    // The tail names the output fields. Resolve each against the bindings.
    let tail = tail?;
    let fields = resolve_tail(tail, &bindings, mixins)?;
    Some((assertions, fields))
}

/// Classify the RHS of a railway binding into a [`Binding`], recording any
/// assertion it implies (assertTag/assertAttr/literal…).
fn classify_call(
    init: &Expression,
    assertions: &mut Vec<ResponseAssertion>,
    locals: &LocalFns,
    mixins: &HashMap<String, ParsedResponse>,
    visited: &mut HashSet<String>,
) -> Binding {
    let Some(call) = as_call(init) else {
        return Binding::None;
    };
    let Some(method) = smax_helper_name(call) else {
        // Could be `parse<Name>Mixin(...)` — a payload mixin.
        if let Some(name) = mixin_parse_name(call) {
            return Binding::Mixin(name);
        }
        return Binding::None;
    };
    let args = &call.arguments;
    // The wire attr/content name is the first string-literal arg of the accessor
    // (`attrString(node,"server_id")` → "server_id"; `optional(ACC,node,"size",…)`
    // / `literal(ACC,node,"type",…)` → the attr at the first string). Content
    // accessors take no string → None. This is the field's snake_case wire name,
    // distinct from the camelCase makeResult key the field is named by.
    let wire_name = args
        .iter()
        .find_map(|a| arg_expr(a).and_then(as_string_lit))
        .map(str::to_string);
    match method {
        "assertTag" => {
            if let Some(tag) = args.get(1).and_then(arg_expr).and_then(as_string_lit) {
                assertions.push(ResponseAssertion {
                    kind: AssertionKind::Tag,
                    name: Some(tag.to_string()),
                    value: None,
                });
            }
            Binding::None
        }
        "assertAttr" => {
            let name = args.get(1).and_then(arg_expr).and_then(as_string_lit);
            let value = args.get(2).and_then(arg_expr).and_then(as_string_lit);
            assertions.push(ResponseAssertion {
                kind: AssertionKind::Attr,
                name: name.map(str::to_string),
                value: value.map(str::to_string),
            });
            Binding::None
        }
        // `literal(ACCESSOR, node, attr, fixedValue)` pins an attr/content to a
        // constant. When the bound var is named in `makeResult` (e.g.
        // `{type: s.value}`) it is a real output field whose type comes from the
        // wrapped accessor; when it's only an assertion (unreferenced) it emits
        // nothing. `literalContent`/`contentLiteralBytes` carry no makeResult value.
        "literal" => {
            let inner = args
                .first()
                .and_then(arg_expr)
                .and_then(inner_accessor_name);
            match inner.and_then(normalize_accessor) {
                Some((m, ft, bl)) => Binding::Field {
                    method: m,
                    field_type: ft,
                    required: true,
                    byte_length: bl,
                    wire_name,
                },
                None => Binding::None,
            }
        }
        "literalContent" | "contentLiteralBytes" => Binding::None,
        // Optional literal → a present-or-absent marker; treat as optional string.
        "optionalLiteral" => Binding::Field {
            method: wap::MAYBE_ATTR_STRING.to_string(),
            field_type: ParsedFieldType::String,
            required: false,
            byte_length: None,
            wire_name,
        },
        // `optional(ACCESSOR, node, …)` → the wrapped accessor decides the type;
        // required = false.
        "optional" => {
            let inner = args
                .first()
                .and_then(arg_expr)
                .and_then(inner_accessor_name);
            match inner.and_then(normalize_accessor) {
                Some((m, ft, bl)) => Binding::Field {
                    method: optional_variant(&m),
                    field_type: ft,
                    required: false,
                    byte_length: bl,
                    wire_name,
                },
                None => Binding::None,
            }
        }
        // Child accessors take a local parser fn as their last identifier arg
        // (`optionalChildWithTag(node, "group", parseGroup)`,
        // `mapChildrenWithTag(node, "group", 0, 1e4, parseGroup)`). Resolve and
        // analyze it recursively to recover the child's field tree.
        "child"
        | "childWithTag"
        | "optionalChild"
        | "optionalChildWithTag"
        | "flattenedChildWithTag"
        | "mapChildrenWithTag" => classify_child(method, args, locals, mixins, visited),
        other => match normalize_accessor(other) {
            Some((m, ft, bl)) => Binding::Field {
                method: m,
                field_type: ft,
                required: true,
                byte_length: bl,
                wire_name,
            },
            None => Binding::None,
        },
    }
}

/// Resolve a child accessor's inner parser fn and analyze it into a [`Binding::ChildGroup`].
fn classify_child(
    method: &str,
    args: &oxc_allocator::Vec<oxc_ast::ast::Argument>,
    locals: &LocalFns,
    mixins: &HashMap<String, ParsedResponse>,
    visited: &mut HashSet<String>,
) -> Binding {
    // The wire tag is the first string-literal arg.
    let tag = args
        .iter()
        .find_map(|a| arg_expr(a).and_then(as_string_lit))
        .map(str::to_string);
    // The inner parser is the last identifier arg that names a known local fn.
    let inner_fn = args
        .iter()
        .rev()
        .find_map(|a| arg_expr(a).and_then(as_identifier))
        .filter(|id| locals.contains_key(*id))
        .map(str::to_string);
    let (Some(tag), Some(fn_name)) = (tag, inner_fn) else {
        // 2-arg `flattenedChildWithTag(node, "x")` (a node descend) and any child
        // without a resolvable parser contribute no field on their own.
        return Binding::None;
    };
    if !visited.insert(fn_name.clone()) {
        return Binding::None; // recursion guard
    }
    let result = locals
        .get(&fn_name)
        .and_then(|src| analyze_fn_source(src, locals, mixins, visited));
    visited.remove(&fn_name);
    match result {
        Some((_assertions, fields)) if !fields.is_empty() => Binding::ChildGroup {
            tag,
            fields,
            repeats: method == "mapChildrenWithTag",
            optional: matches!(method, "optionalChild" | "optionalChildWithTag"),
        },
        _ => Binding::None,
    }
}

/// Map a smax accessor name → (canonical wap method, field type, byte_length).
fn normalize_accessor(m: &str) -> Option<(String, ParsedFieldType, Option<u32>)> {
    let s = |c: &str, t: ParsedFieldType| Some((c.to_string(), t, None));
    match m {
        "attrString" | "attrStanzaId" | "attrCallId" | "attrStringFromReference" => {
            s(wap::ATTR_STRING, ParsedFieldType::String)
        }
        "attrInt" | "attrIntRange" => s(wap::ATTR_INT, ParsedFieldType::Integer),
        "attrStringEnum" => s(wap::ATTR_ENUM, ParsedFieldType::Enum),
        "contentString" => s(wap::CONTENT_STRING, ParsedFieldType::String),
        "contentInt" => s(wap::CONTENT_INT, ParsedFieldType::Integer),
        "contentStringEnum" => s(wap::ATTR_ENUM, ParsedFieldType::Enum),
        "contentBytes" => s(wap::CONTENT_BYTES, ParsedFieldType::Bytes),
        "contentBytesRange" => s(wap::CONTENT_BYTES, ParsedFieldType::Bytes),
        // Every smax JID accessor maps to the single typed-JID method the codegen
        // materializes (granularity is a future iteration). `attrJidEnum` pins the
        // JID's server kind via an enum arg but still yields a JID; `attrLidUserJid`
        // is the LID-or-user accessor.
        "attrJid" | "attrDomainJid" | "attrUserJid" | "attrDeviceJid" | "attrGroupJid"
        | "attrNewsletterJid" | "attrLidJid" | "attrLidUserJid" | "attrJidEnum" | "literalJid" => {
            s(wap::ATTR_JID_WITH_TYPE, ParsedFieldType::Jid)
        }
        _ => None,
    }
}

/// The optional (`maybe…`) variant of a canonical method, where one exists.
fn optional_variant(m: &str) -> String {
    match m {
        x if x == wap::ATTR_STRING => wap::MAYBE_ATTR_STRING.to_string(),
        x if x == wap::ATTR_INT => wap::MAYBE_ATTR_INT.to_string(),
        x if x == wap::ATTR_ENUM => wap::MAYBE_ATTR_ENUM.to_string(),
        other => other.to_string(),
    }
}

/// `o("WASmaxParseUtils"|"WASmaxParseJid"|"WASmaxParseReference").method(...)`
/// → the bare `method`, for the parse-helper namespaces only.
fn smax_helper_name<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    let owner = require_owner_of_call(call)?;
    matches!(
        owner,
        "WASmaxParseUtils" | "WASmaxParseJid" | "WASmaxParseReference"
    )
    .then(|| callee_method(call))
    .flatten()
}

/// For `o("Mod").method(...)`, return `"Mod"`.
fn require_owner_of_call<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    let obj = wa_oxc::callee_object(call)?;
    let inner = as_call(obj)?;
    as_string_lit(arg_expr(inner.arguments.first()?)?)
}

/// `o("WASmaxIn…Mixin").parse<Name>Mixin(...)` → the `parse<Name>Mixin` fn name.
fn mixin_parse_name<'a>(call: &'a CallExpression<'a>) -> Option<String> {
    let owner = require_owner_of_call(call)?;
    if !(owner.starts_with("WASmaxIn") && owner.ends_with("Mixin")) {
        return None;
    }
    let method = callee_method(call)?;
    (method.starts_with("parse") && method.ends_with("Mixin")).then(|| method.to_string())
}

/// An accessor passed by reference as the first arg of `optional`/`literal`:
/// `optional(o("WASmaxParseUtils").attrIntRange, …)` → `"attrIntRange"`.
fn inner_accessor_name<'a>(e: &'a Expression<'a>) -> Option<&'a str> {
    // Member expression `o("Mod").method` (not a call — a function reference).
    let (_, prop) = wa_oxc::as_member(e)?;
    Some(prop)
}

/// Resolve the tail `makeResult({...})` / `makeResult(babelHelpers.extends(...))`
/// into the final field list, using the railway bindings + payload mixins.
fn resolve_tail(
    tail: &Expression,
    bindings: &HashMap<String, Binding>,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<Vec<ParsedField>> {
    // Unwrap `X.success ? makeResult(...) : X` → the consequent.
    let expr = match tail {
        Expression::ConditionalExpression(c) => &c.consequent,
        other => other,
    };
    // `return X.success, X` (comma) → SequenceExpression delegating to a mixin/child var.
    if let Expression::SequenceExpression(seq) = expr {
        if let Some(last) = seq.expressions.last()
            && let Some(name) = as_identifier(last)
        {
            return match bindings.get(name) {
                Some(Binding::Mixin(m)) => mixins.get(m).map(|p| p.fields.clone()),
                Some(Binding::ChildGroup { fields, .. }) => Some(fields.clone()),
                _ => None,
            };
        }
        return None;
    }
    let call = as_call(expr)?;
    // Expect `…makeResult(ARG)`.
    if callee_method(call)? != "makeResult" {
        return None;
    }
    let arg = arg_expr(call.arguments.first()?)?;
    resolve_result_arg(arg, bindings, mixins)
}

/// Resolve the argument of `makeResult(...)` — an object literal or
/// `babelHelpers.extends(obj, mixin.value, …)`.
fn resolve_result_arg(
    arg: &Expression,
    bindings: &HashMap<String, Binding>,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<Vec<ParsedField>> {
    let mut fields = Vec::new();
    match arg {
        Expression::ObjectExpression(_) => {
            collect_object_fields(arg, bindings, mixins, &mut fields);
        }
        Expression::CallExpression(c) if callee_method(c) == Some("extends") => {
            // babelHelpers.extends(objLiteral, M1.value, M2.value, …)
            for a in &c.arguments {
                let Some(e) = arg_expr(a) else { continue };
                if matches!(e, Expression::ObjectExpression(_)) {
                    collect_object_fields(e, bindings, mixins, &mut fields);
                } else if let Some((var, _)) = value_member(e) {
                    // `Mi.value`/`Ci.value` spread → inline the mixin's or child's
                    // fields at this level (flattened).
                    let spread = match bindings.get(var) {
                        Some(Binding::Mixin(m)) => mixins.get(m).map(|p| p.fields.as_slice()),
                        Some(Binding::ChildGroup { fields, .. }) => Some(fields.as_slice()),
                        _ => None,
                    };
                    if let Some(src) = spread {
                        for f in src {
                            if !fields.iter().any(|x: &ParsedField| x.name == f.name) {
                                fields.push(f.clone());
                            }
                        }
                    }
                }
            }
        }
        _ => return None,
    }
    Some(fields)
}

/// Collect `{ name: V.value, … }` into fields, resolving `V` via bindings.
fn collect_object_fields(
    obj: &Expression,
    bindings: &HashMap<String, Binding>,
    mixins: &HashMap<String, ParsedResponse>,
    out: &mut Vec<ParsedField>,
) {
    let Some(o) = wa_oxc::as_object(obj) else {
        return;
    };
    for prop in &o.properties {
        let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let Some(key) = wa_oxc::property_key_name(&p.key) else {
            continue;
        };
        // value is `V.value` or `V.success ? V.value : null`.
        let (var, optional) = match &p.value {
            Expression::ConditionalExpression(c) => match value_member(&c.consequent) {
                Some((v, _)) => (v, true),
                None => continue,
            },
            other => match value_member(other) {
                Some((v, _)) => (v, false),
                None => continue,
            },
        };
        match bindings.get(var) {
            Some(Binding::Field {
                method,
                field_type,
                required,
                byte_length,
                wire_name,
            }) => {
                out.push(ParsedField {
                    method: method.clone(),
                    name: key.to_string(),
                    wire_name: wire_name.clone(),
                    field_type: *field_type,
                    required: *required && !optional,
                    byte_length: *byte_length,
                    ..Default::default()
                });
            }
            Some(Binding::ChildGroup {
                tag,
                fields,
                repeats,
                optional: child_optional,
            }) => {
                // A nested child node (`{ key: childResult.value }`): the field name
                // is the result key, the wire tag is the child's tag, and the
                // child's parsed fields become its `children`. An `optionalChild*`
                // accessor makes the field optional even with a plain `.value` tail.
                out.push(ParsedField {
                    method: wap::CHILD.to_string(),
                    name: key.to_string(),
                    required: !optional && !child_optional,
                    tag: Some(tag.clone()),
                    children: Some(fields.clone()),
                    repeats: Some(*repeats),
                    ..Default::default()
                });
            }
            Some(Binding::Mixin(m)) => {
                // A same-node payload mixin referenced as `{ key: M.value }`: its
                // fields parse the PARENT node's attrs, so flatten them in (an
                // `M.success ? M.value : null` ref makes them all optional).
                if let Some(p) = mixins.get(m) {
                    for f in &p.fields {
                        if out.iter().any(|x: &ParsedField| x.name == f.name) {
                            continue;
                        }
                        let mut f = f.clone();
                        if optional {
                            f.required = false;
                        }
                        out.push(f);
                    }
                }
            }
            _ => {}
        }
    }
}

/// `V.value` / `V.success` → `("V", "value"|"success")`.
fn value_member<'a>(e: &'a Expression<'a>) -> Option<(&'a str, &'a str)> {
    let (obj, prop) = wa_oxc::as_member(e)?;
    let var = as_identifier(obj)?;
    Some((var, prop))
}

// ─── module-level helpers (local fns + exports) ───────────────────────────────

/// Every `function <name>(…){…}` declared directly in the module factory body,
/// as `name → source` (re-parsable). Child accessors reference these by name.
fn collect_local_fn_sources(slice: &str) -> LocalFns {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let mut spans: Vec<(String, (usize, usize))> = Vec::new();
    walk_factory_stmts::<(), _>(&ret.program.body, &mut |s| {
        if let Statement::FunctionDeclaration(f) = s
            && let Some(id) = f.id.as_ref()
        {
            let sp = f.span();
            spans.push((id.name.to_string(), (sp.start as usize, sp.end as usize)));
        }
        None
    });
    spans
        .into_iter()
        .map(|(n, (a, b))| (n, slice[a..b].to_string()))
        .collect()
}

/// Module exports `l.<export> = <localIdent>` (handling the `l.a=e,l.b=s` comma
/// sequence the minifier emits), as `(export, local)` pairs.
fn collect_exports(slice: &str) -> Vec<(String, String)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let mut out = Vec::new();
    walk_factory_stmts::<(), _>(&ret.program.body, &mut |s| {
        if let Statement::ExpressionStatement(es) = s {
            match &es.expression {
                Expression::AssignmentExpression(a) => push_export(a, &mut out),
                Expression::SequenceExpression(seq) => {
                    for e in &seq.expressions {
                        if let Expression::AssignmentExpression(a) = e {
                            push_export(a, &mut out);
                        }
                    }
                }
                _ => {}
            }
        }
        None
    });
    out
}

/// `l.<export> = <localIdent>` → push `(export, local)`.
fn push_export(a: &oxc_ast::ast::AssignmentExpression, out: &mut Vec<(String, String)>) {
    if let Some(m) = a.left.as_member_expression()
        && let Some(export) = m.static_property_name()
        && let Some(local) = as_identifier(&a.right)
    {
        out.push((export.to_string(), local.to_string()));
    }
}

/// The statement list of a module factory function, unwrapping a parenthesized
/// wrapper: `__d(name, deps, (function(){ … }))` — oxc wraps the parenthesized
/// form in a `ParenthesizedExpression`, which a bare `FunctionExpression` match
/// would miss.
pub(crate) fn factory_body<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b [Statement<'a>]> {
    let inner = match e {
        Expression::ParenthesizedExpression(p) => &p.expression,
        other => other,
    };
    match inner {
        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| b.statements.as_slice()),
        _ => None,
    }
}

/// Walk every statement in a module, descending into `__d(name, deps, factory)`
/// factory bodies (via [`factory_body`]). `visit` is called on each statement; the
/// first `Some` it returns short-circuits the walk and becomes the result. For an
/// exhaustive visit (e.g. accumulating into a `Vec`), use a visitor that mutates by
/// side effect and always returns `None`.
pub(crate) fn walk_factory_stmts<'a, T, F>(stmts: &[Statement<'a>], visit: &mut F) -> Option<T>
where
    F: FnMut(&Statement<'a>) -> Option<T>,
{
    for s in stmts {
        if let Some(r) = visit(s) {
            return Some(r);
        }
        if let Statement::ExpressionStatement(es) = s
            && let Expression::CallExpression(call) = &es.expression
        {
            for arg in &call.arguments {
                if let Some(inner) = arg.as_expression().and_then(factory_body)
                    && let Some(r) = walk_factory_stmts(inner, visit)
                {
                    return Some(r);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_mixins() -> HashMap<String, ParsedResponse> {
        HashMap::new()
    }

    /// Analyze a single self-contained parse fn (no local child parsers).
    fn analyze_one(
        body: &str,
        mixins: &HashMap<String, ParsedResponse>,
    ) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
        analyze_fn_source(body, &LocalFns::new(), mixins, &mut HashSet::new())
    }

    #[test]
    fn attrs_and_literal_assertion() {
        // attrString → field; literal(...) → assertion, no field; type from binding.
        let body = r#"function e(node, ref){
            var n = o("WASmaxParseUtils").assertTag(node, "iq"); if(!n.success) return n;
            var r = o("WASmaxParseUtils").attrString(node, "id"); if(!r.success) return r;
            var c = o("WASmaxParseUtils").attrInt(node, "count"); if(!c.success) return c;
            var s = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, node, "type", "result"); if(!s.success) return s;
            return r.success ? o("WAResultOrError").makeResult({ id: r.value, count: c.value }) : r;
        }"#;
        let (asserts, fields) = analyze_one(body, &no_mixins()).expect("analyzed");
        assert!(asserts.iter().any(|a| a.kind == AssertionKind::Tag));
        assert_eq!(fields.len(), 2);
        let id = fields.iter().find(|f| f.name == "id").unwrap();
        assert_eq!(id.method, wap::ATTR_STRING);
        assert!(id.required);
        let count = fields.iter().find(|f| f.name == "count").unwrap();
        assert_eq!(count.method, wap::ATTR_INT);
        assert_eq!(count.field_type, ParsedFieldType::Integer);
    }

    #[test]
    fn optional_accessor_is_not_required() {
        let body = r#"function e(node){
            var s = o("WASmaxParseUtils").optional(o("WASmaxParseUtils").attrIntRange, node, "size", 0, 19999);
            return o("WAResultOrError").makeResult({ size: s.value });
        }"#;
        let (_a, fields) = analyze_one(body, &no_mixins()).expect("analyzed");
        let size = fields.iter().find(|f| f.name == "size").unwrap();
        assert!(!size.required, "optional → not required");
        assert_eq!(size.field_type, ParsedFieldType::Integer);
        assert_eq!(size.method, wap::MAYBE_ATTR_INT);
    }

    #[test]
    fn ternary_field_in_make_result_is_optional() {
        // `name: V.success ? V.value : null` in the makeResult object marks the
        // field optional, distinct from a plain `V.value` (required).
        let body = r#"function e(node){
            var r = o("WASmaxParseUtils").attrString(node, "id"); if(!r.success) return r;
            var s = o("WASmaxParseUtils").attrString(node, "name");
            return r.success ? o("WAResultOrError").makeResult({ id: r.value, name: s.success ? s.value : null }) : r;
        }"#;
        let (_a, fields) = analyze_one(body, &no_mixins()).expect("analyzed");
        let id = fields.iter().find(|f| f.name == "id").unwrap();
        let name = fields.iter().find(|f| f.name == "name").unwrap();
        assert!(id.required, "plain V.value → required");
        assert!(!name.required, "V.success ? V.value : null → optional");
    }

    #[test]
    fn delegates_to_single_mixin_via_comma() {
        // `return X.success, X` where X is a payload mixin → use the mixin's fields.
        let mut mixins = no_mixins();
        mixins.insert(
            "parseIQResultResponseMixin".to_string(),
            ParsedResponse {
                parser_name: "m".into(),
                assertions: vec![],
                fields: vec![ParsedField {
                    method: wap::ATTR_STRING.into(),
                    name: "from".into(),
                    field_type: ParsedFieldType::String,
                    required: true,
                    byte_length: None,
                    enum_keys: None,
                    tag: None,
                    children: None,
                    repeats: None,
                    content_type: None,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let body = r#"function e(node, ref){
            var n = o("WASmaxParseUtils").assertTag(node, "iq"); if(!n.success) return n;
            var r = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return r.success, r;
        }"#;
        let (_a, fields) = analyze_one(body, &mixins).expect("analyzed");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "from");
    }

    #[test]
    fn extends_spread_inlines_mixin_fields() {
        let mut mixins = no_mixins();
        mixins.insert(
            "parseIQResultResponseMixin".to_string(),
            ParsedResponse {
                parser_name: "m".into(),
                assertions: vec![],
                fields: vec![ParsedField {
                    method: wap::ATTR_STRING.into(),
                    name: "type".into(),
                    field_type: ParsedFieldType::String,
                    required: true,
                    byte_length: None,
                    enum_keys: None,
                    tag: None,
                    children: None,
                    repeats: None,
                    content_type: None,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let body = r#"function e(node, ref){
            var r = o("WASmaxParseUtils").attrString(node, "iso"); if(!r.success) return r;
            var i = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return i.success ? o("WAResultOrError").makeResult(babelHelpers.extends({ countryCodeIso: r.value }, i.value)) : i;
        }"#;
        let (_a, fields) = analyze_one(body, &mixins).expect("analyzed");
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"countryCodeIso"));
        assert!(names.contains(&"type"), "mixin fields spread in");
    }

    #[test]
    fn unrecognized_tail_yields_none() {
        let body = r#"function e(node){ return somethingElse(node); }"#;
        assert!(analyze_one(body, &no_mixins()).is_none());
    }

    #[test]
    fn optional_child_with_tag_nests_inner_parser_fields() {
        // `optionalChildWithTag(iq, "group", e)` → a nested `group` child whose
        // fields come from the local `e` parser; `{group: a.value}` in the tail.
        let module = r#"__d("WASmaxInGroupsGetGroupInfoResponseSuccess",["WASmaxParseUtils","WASmaxParseReference","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(g){
                var t = o("WASmaxParseUtils").assertTag(g, "group"); if(!t.success) return t;
                var n = o("WASmaxParseUtils").optional(o("WASmaxParseUtils").attrIntRange, g, "size", 0, 19999);
                var s = o("WASmaxParseUtils").attrString(g, "subject"); if(!s.success) return s;
                return o("WAResultOrError").makeResult({ size: n.value, subject: s.value });
            }
            function s(t, n){
                var r = o("WASmaxParseUtils").assertTag(t, "iq"); if(!r.success) return r;
                var a = o("WASmaxParseUtils").optionalChildWithTag(t, "group", e); if(!a.success) return a;
                return o("WAResultOrError").makeResult({ group: a.value });
            }
            l.parseGetGroupInfoResponseSuccessGroup = e, l.parseGetGroupInfoResponseSuccess = s;
        }), 1);"#;
        let exports = analyze_module_exports(module, &no_mixins());
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseGetGroupInfoResponseSuccess")
            .expect("exported parser");
        assert_eq!(pr.fields.len(), 1);
        let group = &pr.fields[0];
        assert_eq!(group.name, "group");
        assert_eq!(group.method, wap::CHILD);
        assert_eq!(group.tag.as_deref(), Some("group"));
        assert_eq!(group.repeats, Some(false));
        assert!(
            !group.required,
            "optionalChildWithTag → field is optional even with a plain `.value` tail"
        );
        let kids = group.children.as_ref().expect("nested fields");
        assert!(kids.iter().any(|f| f.name == "subject"));
        assert!(kids.iter().any(|f| f.name == "size" && !f.required));
    }

    #[test]
    fn literal_attr_referenced_in_make_result_becomes_a_field() {
        // `literal(attrString, node, "type", "result")` is a constant assertion,
        // but when its var is named in makeResult (`{type: s.value}`) it is a real
        // (string) output field — recovering the `type` field the response carries.
        let body = r#"function e(node, ref){
            var s = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, node, "type", "result"); if(!s.success) return s;
            var u = o("WASmaxParseUtils").attrString(node, "id"); if(!u.success) return u;
            return o("WAResultOrError").makeResult({ type: s.value, id: u.value });
        }"#;
        let (_a, fields) = analyze_one(body, &no_mixins()).expect("analyzed");
        let ty = fields
            .iter()
            .find(|f| f.name == "type")
            .expect("type field");
        assert_eq!(ty.method, wap::ATTR_STRING);
        assert!(ty.required);
        assert!(fields.iter().any(|f| f.name == "id"));
    }

    #[test]
    fn map_children_with_tag_marks_repeated_child() {
        // `mapChildrenWithTag(groups, "group", 0, 1e4, e)` → a repeated `group`
        // child list; `{groupsGroup: d.value}` in the tail.
        let module = r#"__d("WASmaxInGroupsGetParticipatingGroupsResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(g){
                var t = o("WASmaxParseUtils").assertTag(g, "group"); if(!t.success) return t;
                var s = o("WASmaxParseUtils").attrString(g, "id"); if(!s.success) return s;
                return o("WAResultOrError").makeResult({ id: s.value });
            }
            function s(t, n){
                var r = o("WASmaxParseUtils").assertTag(t, "iq"); if(!r.success) return r;
                var a = o("WASmaxParseUtils").flattenedChildWithTag(t, "groups"); if(!a.success) return a;
                var d = o("WASmaxParseUtils").mapChildrenWithTag(a.value, "group", 0, 1e4, e); if(!d.success) return d;
                return o("WAResultOrError").makeResult({ groupsGroup: d.value });
            }
            l.parseGetParticipatingGroupsResponseSuccessGroupsGroup = e, l.parseGetParticipatingGroupsResponseSuccess = s;
        }), 1);"#;
        let exports = analyze_module_exports(module, &no_mixins());
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseGetParticipatingGroupsResponseSuccess")
            .expect("exported parser");
        assert_eq!(pr.fields.len(), 1);
        let groups = &pr.fields[0];
        assert_eq!(groups.name, "groupsGroup");
        assert_eq!(groups.tag.as_deref(), Some("group"));
        assert_eq!(groups.repeats, Some(true), "mapChildrenWithTag → repeated");
        assert!(
            groups
                .children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "id"))
        );
    }

    #[test]
    fn collects_comma_sequence_exports() {
        let module = r#"__d("WASmaxInFooBarResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(node){
                var s = o("WASmaxParseUtils").attrString(node, "id"); if(!s.success) return s;
                return o("WAResultOrError").makeResult({ id: s.value });
            }
            l.helper = e, l.parseFooBarResponseSuccess = e;
        }), 1);"#;
        let exports = analyze_module_exports(module, &no_mixins());
        assert!(
            exports
                .iter()
                .any(|(n, _)| n == "parseFooBarResponseSuccess"),
            "comma-sequence export resolved"
        );
    }
}
