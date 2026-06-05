//! Response analysis for the `WASmax` world (Phase 3).
//!
//! Unlike the legacy `WADeprecatedWapParser` (methods called on the node param,
//! e.g. `e.attrString("x")`), smax responses are **free functions** in dedicated
//! `WASmaxIn<X>ResponseSuccess` modules, written as a Result-railway:
//!
//! ```text
//! function e(node, ref) {
//!   var n = o("WASmaxParseUtils").assertTag(node, "iq"); if (!n.success) return n;
//!   var r = o("WASmaxParseUtils").attrString(node, "id");  if (!r.success) return r;
//!   var s = o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString, node, "type", "result");
//!   if (!s.success) return s;
//!   return r.success ? o("WAResultOrError").makeResult({ id: r.value, type: s.value }) : r;
//! }
//! ```
//!
//! The **tail** `makeResult({...})` / `babelHelpers.extends({...}, mixin.value)`
//! is the authoritative field list: each `k: V.value` names an output field whose
//! type comes from the helper that bound `V`. Assertions (`assertTag`, `literal…`)
//! bind vars but contribute no field.
//!
//! We normalize the smax helper vocabulary into the canonical [`wa_ir::wap`]
//! method names the codegen already understands, so the IR and codegen are
//! unchanged. This analyzer is entirely separate from the legacy one (`response.rs`)
//! to avoid any regression to its 33 stanzas / tests.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, Function, Program, Statement};
use wa_ir::wap;
use wa_ir::{AssertionKind, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, callee_method};

/// One railway binding: `var V = <call>;` → what `V` resolves to.
#[derive(Clone)]
enum Binding {
    /// A value field: the normalized wap method + field type + required flag.
    Field {
        method: String,
        field_type: ParsedFieldType,
        required: bool,
        byte_length: Option<u32>,
    },
    /// A nested payload mixin call (`parse<Name>Mixin(...)`) → its module-less
    /// mixin key, resolved later from the response index.
    Mixin(String),
    /// An assertion / literal / node-reshape — no field.
    None,
}

/// Analyze a smax parse-function body into a [`ParsedResponse`]-style result.
/// `mixins` looks up `parse<Name>Mixin` payloads by their function name.
pub(crate) fn analyze_smax_parse_fn(
    body_code: &str,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_code);
    // The body is wrapped so it parses as a program; find the first function.
    let func = ret.program.body.iter().find_map(|s| match s {
        Statement::FunctionDeclaration(f) => Some(&**f),
        _ => None,
    })?;
    analyze_function(func, body_code, mixins)
}

fn analyze_function(
    func: &Function,
    source: &str,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
    let body = func.body.as_ref()?;
    let mut assertions: Vec<ResponseAssertion> = Vec::new();
    let mut bindings: HashMap<String, Binding> = HashMap::new();
    let mut field_names: HashMap<String, (String, String)> = HashMap::new(); // var → (field_name)

    let mut tail: Option<&Expression> = None;
    for stmt in &body.statements {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                for d in &decl.declarations {
                    let Some(name) = d.id.get_identifier_name() else {
                        continue;
                    };
                    if let Some(init) = d.init.as_ref() {
                        let b = classify_call(init, &mut assertions);
                        bindings.insert(name.to_string(), b);
                    }
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                tail = ret_stmt.argument.as_ref();
            }
            Statement::ExpressionStatement(_) => {}
            _ => {}
        }
    }
    let _ = &mut field_names;

    // The tail names the output fields. Resolve each against the bindings.
    let tail = tail?;
    let fields = resolve_tail(tail, &bindings, mixins, source)?;
    Some((assertions, fields))
}

/// Classify the RHS of a railway binding into a [`Binding`], recording any
/// assertion it implies (assertTag/assertAttr/literal…).
fn classify_call(init: &Expression, assertions: &mut Vec<ResponseAssertion>) -> Binding {
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
        // Literal assertions on an attr/content — no field.
        "literal" | "literalContent" | "contentLiteralBytes" => Binding::None,
        // Optional literal → a present-or-absent marker; treat as optional string.
        "optionalLiteral" => Binding::Field {
            method: wap::MAYBE_ATTR_STRING.to_string(),
            field_type: ParsedFieldType::String,
            required: false,
            byte_length: None,
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
                },
                None => Binding::None,
            }
        }
        // A `flattenedChildWithTag` reshapes the node (returns the child); for
        // field purposes it's not a leaf — skip (children handled via mixins).
        "flattenedChildWithTag" => Binding::None,
        other => match normalize_accessor(other) {
            Some((m, ft, bl)) => Binding::Field {
                method: m,
                field_type: ft,
                required: true,
                byte_length: bl,
            },
            None => Binding::None,
        },
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
        // materializes (granularity is a future iteration).
        "attrJid" | "attrDomainJid" | "attrUserJid" | "attrDeviceJid" | "attrGroupJid"
        | "attrNewsletterJid" | "attrLidJid" | "literalJid" => {
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
    source: &str,
) -> Option<Vec<ParsedField>> {
    // Unwrap `X.success ? makeResult(...) : X` → the consequent.
    let expr = match tail {
        Expression::ConditionalExpression(c) => &c.consequent,
        other => other,
    };
    // `return X.success, X` (comma) → SequenceExpression delegating to a mixin var.
    if let Expression::SequenceExpression(seq) = expr {
        if let Some(last) = seq.expressions.last()
            && let Some(name) = as_identifier(last)
            && let Some(Binding::Mixin(m)) = bindings.get(name)
        {
            return mixins.get(m).map(|p| p.fields.clone());
        }
        return None;
    }
    let call = as_call(expr)?;
    // Expect `…makeResult(ARG)`.
    if callee_method(call)? != "makeResult" {
        return None;
    }
    let arg = arg_expr(call.arguments.first()?)?;
    resolve_result_arg(arg, bindings, mixins, source)
}

/// Resolve the argument of `makeResult(...)` — an object literal or
/// `babelHelpers.extends(obj, mixin.value, …)`.
fn resolve_result_arg(
    arg: &Expression,
    bindings: &HashMap<String, Binding>,
    mixins: &HashMap<String, ParsedResponse>,
    source: &str,
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
                    // `Mi.value` spread → inline the mixin's fields.
                    if let Some(Binding::Mixin(m)) = bindings.get(var)
                        && let Some(p) = mixins.get(m)
                    {
                        for f in &p.fields {
                            if !fields.iter().any(|x: &ParsedField| x.name == f.name) {
                                fields.push(f.clone());
                            }
                        }
                    }
                }
            }
        }
        _ => {
            let _ = source;
            return None;
        }
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
            }) => {
                out.push(ParsedField {
                    method: method.clone(),
                    name: key.to_string(),
                    field_type: *field_type,
                    required: *required && !optional,
                    byte_length: *byte_length,
                    enum_keys: None,
                    tag: None,
                    children: None,
                    repeats: None,
                    content_type: None,
                });
            }
            Some(Binding::Mixin(m)) => {
                // A named nested mixin field: inline as a child group.
                if let Some(p) = mixins.get(m) {
                    let mut f = ParsedField {
                        method: wap::CHILD.to_string(),
                        name: key.to_string(),
                        field_type: ParsedFieldType::String,
                        required: !optional,
                        byte_length: None,
                        enum_keys: None,
                        tag: Some(key.to_string()),
                        children: Some(p.fields.clone()),
                        repeats: None,
                        content_type: None,
                    };
                    if f.children.as_ref().is_some_and(|c| c.is_empty()) {
                        f.children = None;
                    }
                    out.push(f);
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

/// Analyze a parse-function body source (`function name(){…}`) into a
/// [`ParsedResponse`].
pub(crate) fn analyze_module(
    body_source: &str,
    parser_name: &str,
    mixins: &HashMap<String, ParsedResponse>,
) -> Option<ParsedResponse> {
    let (assertions, fields) = analyze_smax_parse_fn(body_source, mixins)?;
    Some(ParsedResponse {
        parser_name: parser_name.to_string(),
        assertions,
        fields,
    })
}

/// Extract the source of the function bound to export `fn_name` in a module slice
/// (`function fn_name(args){ … }` or `function localName(args){…}; l.fn_name=localName`),
/// returned as a standalone `function …` string the analyzer can re-parse.
///
/// Handles the minified `l.export = localFn` indirection by resolving the export
/// to the local function name, then locating that function's declaration.
pub(crate) fn parse_fn_body_by_name(slice: &str, fn_name: &str) -> Option<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    // Resolve `l.<fn_name> = <localIdent>` → the local function's name.
    let local = resolve_export_local(&ret.program, fn_name).unwrap_or_else(|| fn_name.to_string());
    // Find a `function <local>(…){…}` declaration anywhere in the factory body.
    let span = find_function_span(&ret.program, &local)?;
    Some(slice[span.0..span.1].to_string())
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

/// `l.export = localIdent` → `localIdent`.
fn resolve_export_local(program: &Program, export: &str) -> Option<String> {
    walk_factory_stmts(&program.body, &mut |s| {
        let Statement::ExpressionStatement(es) = s else {
            return None;
        };
        let Expression::AssignmentExpression(a) = &es.expression else {
            return None;
        };
        let m = a.left.as_member_expression()?;
        if m.static_property_name() != Some(export) {
            return None;
        }
        as_identifier(&a.right).map(|id| id.to_string())
    })
}

/// Byte span of `function <name>(…){…}` anywhere in the program (recursing into
/// the module factory function body).
fn find_function_span(program: &Program, name: &str) -> Option<(usize, usize)> {
    use oxc_span::GetSpan;
    walk_factory_stmts(&program.body, &mut |s| {
        let Statement::FunctionDeclaration(f) = s else {
            return None;
        };
        if f.id.as_ref().map(|i| i.name.as_str()) != Some(name) {
            return None;
        }
        let sp = f.span();
        Some((sp.start as usize, sp.end as usize))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_mixins() -> HashMap<String, ParsedResponse> {
        HashMap::new()
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
        let (asserts, fields) = analyze_smax_parse_fn(body, &no_mixins()).expect("analyzed");
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
        let (_a, fields) = analyze_smax_parse_fn(body, &no_mixins()).expect("analyzed");
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
        let (_a, fields) = analyze_smax_parse_fn(body, &no_mixins()).expect("analyzed");
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
                }],
            },
        );
        let body = r#"function e(node, ref){
            var n = o("WASmaxParseUtils").assertTag(node, "iq"); if(!n.success) return n;
            var r = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return r.success, r;
        }"#;
        let (_a, fields) = analyze_smax_parse_fn(body, &mixins).expect("analyzed");
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
                }],
            },
        );
        let body = r#"function e(node, ref){
            var r = o("WASmaxParseUtils").attrString(node, "iso"); if(!r.success) return r;
            var i = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return i.success ? o("WAResultOrError").makeResult(babelHelpers.extends({ countryCodeIso: r.value }, i.value)) : i;
        }"#;
        let (_a, fields) = analyze_smax_parse_fn(body, &mixins).expect("analyzed");
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"countryCodeIso"));
        assert!(names.contains(&"type"), "mixin fields spread in");
    }

    #[test]
    fn unrecognized_tail_yields_none() {
        let body = r#"function e(node){ return somethingElse(node); }"#;
        assert!(analyze_smax_parse_fn(body, &no_mixins()).is_none());
    }
}
