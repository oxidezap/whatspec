//! Response parser analysis: walk a `WADeprecatedWapParser` callback body and
//! reconstruct the response field tree (assertions, attrs, nested children).
//!
//! Mirrors `analyzeParserAST` + `processChildMethod` from the TS scanner. Handles
//! accessors on the param directly, chained `param.child("x").attr...`, and
//! `child()` results captured in local variables.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, Expression, Function, NewExpression, VariableDeclaration,
    VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use wa_ir::wap;
use wa_ir::{
    AssertionKind, ContentType, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion,
};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, callee_method, callee_object};

/// The class name a legacy response parser is constructed from.
const PARSER_CLASS: &str = "WADeprecatedWapParser";

/// If `new_expr` is `new WADeprecatedWapParser("name", function(p){ … })`, analyze
/// its callback body into a [`ParsedResponse`] (name + assertions + field tree).
///
/// `source` is the module slice the new-expression's spans index into. Shared by
/// the IQ module scanner (which keeps the module's single parser) and
/// [`parse_module_wap_parsers`] (which collects every parser in a module), so the
/// two can't drift on how a parser is recognized.
pub(crate) fn parsed_response_from_new_expr(
    new_expr: &NewExpression,
    source: &str,
) -> Option<ParsedResponse> {
    if new_expr.arguments.len() < 2 {
        return None;
    }
    let name = resolve_parser_name(&new_expr.arguments[0], source)?;
    let Some(Expression::FunctionExpression(cb)) = arg_expr(&new_expr.arguments[1]) else {
        return None;
    };
    // The callee must reference WADeprecatedWapParser.
    let callee_span = new_expr.callee.span();
    let callee_src = &source[callee_span.start as usize..callee_span.end as usize];
    if !callee_src.contains(PARSER_CLASS) {
        return None;
    }
    let param = cb
        .params
        .items
        .first()
        .and_then(|p| p.pattern.get_identifier_name())?;
    let body = cb.body.as_ref()?;
    let cb_body = &source[body.span.start as usize..body.span.end as usize];
    let result = analyze_parser_ast_in_module(cb_body, param.as_str(), source);
    Some(ParsedResponse {
        parser_name: name,
        assertions: result.assertions,
        fields: result.fields,
        ..Default::default()
    })
}

/// The parser's name: the inline string literal (the common case), or — when the
/// constructor is `new WADeprecatedWapParser(d, fn)` with the name hoisted into a
/// variable (`d = "mexNotificationParser"`, as `WAWebHandleMexNotification` does) —
/// the string that variable is bound to in the module. Recovering the variable form
/// keeps the mex-notification envelope from being dropped for lack of an inline name.
fn resolve_parser_name(arg: &Argument, source: &str) -> Option<String> {
    let expr = arg_expr(arg)?;
    if let Some(lit) = as_string_lit(expr) {
        return Some(lit.to_string());
    }
    resolve_string_binding(source, as_identifier(expr)?)
}

/// The unique string literal bound to `name` via a `var name = "literal"`
/// declaration in `source`. Returns `None` when the name is unbound or bound to more
/// than one distinct string — an ambiguous name is not worth risking a wrong label.
fn resolve_string_binding(source: &str, name: &str) -> Option<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, source);
    if ret.panicked {
        return None;
    }
    let mut finder = StringBindingFinder {
        name,
        values: Vec::new(),
    };
    finder.visit_program(&ret.program);
    finder.values.sort();
    finder.values.dedup();
    match finder.values.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// Collects the string literals bound to `name` by `var name = "literal"` anywhere in
/// a module, so [`resolve_string_binding`] can require a unique value.
struct StringBindingFinder<'a> {
    name: &'a str,
    values: Vec<String>,
}

impl<'a> Visit<'a> for StringBindingFinder<'_> {
    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let (Some(id), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                && id.as_str() == self.name
                && let Some(lit) = as_string_lit(init)
            {
                self.values.push(lit.to_string());
            }
        }
        walk::walk_variable_declaration(self, decl);
    }
}

/// Collect every `new WADeprecatedWapParser("name", fn)` in a module slice as a
/// [`ParsedResponse`]. Used by non-IQ domains (e.g. notification handlers) to
/// recover a stanza's typed content shape with the same parser-body analysis the
/// IQ response scanner uses. Returns empty for an unparseable slice or a module
/// with no legacy parser (a handler that delegates to a job/sub-module).
pub fn parse_module_wap_parsers(source: &str) -> Vec<ParsedResponse> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, source);
    if ret.panicked {
        return Vec::new();
    }
    let mut collector = ParserCollector {
        source,
        out: Vec::new(),
    };
    collector.visit_program(&ret.program);
    collector.out
}

struct ParserCollector<'s> {
    source: &'s str,
    out: Vec<ParsedResponse>,
}

impl<'a> Visit<'a> for ParserCollector<'_> {
    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        if let Some(pr) = parsed_response_from_new_expr(new_expr, self.source) {
            self.out.push(pr);
        }
        walk::walk_new_expression(self, new_expr);
    }
}

/// Result of analyzing a parser callback body.
pub(crate) struct ParserResult {
    pub assertions: Vec<ResponseAssertion>,
    pub fields: Vec<ParsedField>,
}

/// Accessors that read a value off a node, as the parser treats them: the shared
/// attribute accessors ([`wap::is_attr_method`]) plus the `contentBytes` /
/// `contentString` leaves. Broader than codegen's notion of an attr field — both
/// draw method names from the shared [`wap`] vocabulary so they can't drift.
fn is_attr_method(m: &str) -> bool {
    wap::is_attr_method(m) || m == wap::CONTENT_BYTES || m == wap::CONTENT_STRING
}

fn is_assert_method(m: &str) -> bool {
    matches!(m, "assertTag" | "assertAttr" | "assertFromServer")
}

fn is_child_method(m: &str) -> bool {
    wap::is_child_method(m)
}

fn is_content_method(m: &str) -> bool {
    wap::is_content_method(m)
}

fn method_to_field_type(m: &str) -> ParsedFieldType {
    wap::method_field_type(m)
}

fn is_method_required(m: &str) -> bool {
    !wap::is_optional_method(m)
}

fn mk_field(method: &str, name: &str, ftype: ParsedFieldType, required: bool) -> ParsedField {
    ParsedField {
        method: method.to_string(),
        name: name.to_string(),
        field_type: ftype,
        required,
        ..Default::default()
    }
}

/// Build a field for a `method(arg0)` accessor, using the string-literal argument as
/// the field name (else `"content"`), and capturing the `contentBytes(N)` byte length
/// when the first argument is a numeric literal — the length WA Web's parser pins the
/// wire field to (`child("signature").contentBytes(64)` → 64).
/// The `o("Mod").ENUM_NAME` table an enum-valued accessor validates against, as a
/// **pending** [`wa_ir::AttrEnumRef`] — name and module filled, variants empty.
///
/// The legacy scanner sees one module at a time and cannot read another's exports, so it
/// records the reference and [`crate::enum_link`] fills it in a post-pass, the same
/// convention the request-attribute enums already use. Without this the field shipped as
/// `"type": "enum"` with nothing saying which values are legal — 98 of them.
fn pending_enum_ref(method: &str, call: &CallExpression) -> Option<wa_ir::AttrEnumRef> {
    if wap::method_field_type(method) != ParsedFieldType::Enum {
        return None;
    }
    let (obj, name) = call
        .arguments
        .iter()
        .skip(1)
        .filter_map(arg_expr)
        .find_map(wa_oxc::as_member)?;
    let module = wa_oxc::as_call(obj)
        .and_then(|c| c.arguments.first())
        .and_then(arg_expr)
        .and_then(as_string_lit)?;
    Some(wa_ir::AttrEnumRef {
        name: name.to_string(),
        module: module.to_string(),
        variants: Vec::new(),
    })
}

fn field_from_call(method: &str, call: &CallExpression) -> ParsedField {
    let arg0 = call.arguments.first().and_then(arg_expr);
    let field_name = arg0.and_then(as_string_lit).unwrap_or("content");
    let mut f = mk_field(
        method,
        field_name,
        method_to_field_type(method),
        is_method_required(method),
    );
    if method == wap::CONTENT_BYTES
        && let Some(Expression::NumericLiteral(n)) = arg0
    {
        f.byte_length = Some(n.value as u32);
    }
    f.enum_ref = pending_enum_ref(method, call);
    f
}

/// Find an existing top-level field by `tag`, or create one (a `child`-style
/// parent with an empty `children` list). Returns its index in `fields`.
fn find_or_create_field(
    fields: &mut Vec<ParsedField>,
    tag: &str,
    method: &str,
    required: bool,
) -> usize {
    if let Some(i) = fields.iter().position(|f| f.tag.as_deref() == Some(tag)) {
        return i;
    }
    let mut f = mk_field(method, tag, ParsedFieldType::String, required);
    f.tag = Some(tag.to_string());
    f.children = Some(Vec::new());
    fields.push(f);
    fields.len() - 1
}

/// Append a child field under `fields[idx]` if an equivalent one isn't present.
fn push_child_field(fields: &mut [ParsedField], idx: usize, child: ParsedField) {
    let children = fields[idx].children.get_or_insert_with(Vec::new);
    if !children
        .iter()
        .any(|c| c.name == child.name && c.method == child.method)
    {
        children.push(child);
    }
}

/// Analyze a parser callback body string against its parameter name.
/// Test-only convenience wrapper: analyze a callback body with no enclosing module (the
/// direct-callback unit tests). Production callers use [`analyze_parser_ast_in_module`].
#[cfg(test)]
pub(crate) fn analyze_parser_ast(code: &str, param: &str) -> ParserResult {
    analyze_parser_ast_in_module(code, param, "")
}

/// Like [`analyze_parser_ast`], but with the enclosing module source available so the
/// (otherwise strictly intra-procedural) analyzer can reach module-scope sibling helpers a
/// parser hands a child node to (`return l ? m(n,i) : d(r,i)`) and module-scope maps an
/// enum accessor references (`attrEnumOrNullIfUnknown("type", u)`). Pass `""` when there is
/// no enclosing module (the direct-callback tests).
pub(crate) fn analyze_parser_ast_in_module(
    code: &str,
    param: &str,
    module_source: &str,
) -> ParserResult {
    analyze_with_scope(code, param, &ModuleScope::from_source(module_source))
}

/// Analyze a parser callback body against a *pre-extracted* [`ModuleScope`]. Every
/// module-scope lookup (a sibling helper's params/body, an enum value map's keys) reads
/// the scope built once by [`ModuleScope::from_source`] instead of re-parsing the whole
/// module per lookup — and the recursive callback analysis (`process_child_method`) reuses
/// the same scope, so a module is parsed exactly once per top-level parser.
fn analyze_with_scope(code: &str, param: &str, module: &ModuleScope) -> ParserResult {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, code);
    let mut a = ParserAnalyzer {
        code,
        param,
        module,
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::new(),
        pending_enum_keys: HashMap::new(),
        helper_depth: 0,
    };
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    ParserResult {
        assertions: a.assertions,
        fields: a.fields,
    }
}

struct ParserAnalyzer<'src, 'ms> {
    code: &'src str,
    param: &'src str,
    /// The enclosing module's pre-extracted helpers/maps (empty when there is no module),
    /// for resolving module-scope sibling helpers and enum value maps.
    module: &'ms ModuleScope,
    assertions: Vec<ResponseAssertion>,
    fields: Vec<ParsedField>,
    /// local var name → tag, for `var t = param.child("tag")`. Also pre-seeded when a
    /// helper is re-analyzed with a parameter bound to a caller's child node (see
    /// [`ParserAnalyzer::try_helper_descent`]).
    child_vars: HashMap<String, String>,
    /// wire attr name → its enum's allowed keys, from `attrEnumOrNullIfUnknown("attr", map)`
    /// (the map is module-scope, so it's resolved and stashed here, then attached to the
    /// matching field in a post-pass — order-independent of the plain read of the attr).
    pending_enum_keys: HashMap<String, Vec<String>>,
    /// Recursion guard for module-scope helper descent (`m(n,i)` → analyze `m`'s body).
    helper_depth: u32,
}

impl<'a> Visit<'a> for ParserAnalyzer<'_, '_> {
    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            // Track `var t = param.child("tag")` (or chained off another child var).
            if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                && let Some(call) = as_call(init)
            {
                let method = callee_method(call);
                let is_child = matches!(method, Some("child") | Some("maybeChild"));
                if let (true, Some(obj)) = (is_child, callee_object(call)) {
                    let on_param = as_identifier(obj) == Some(self.param);
                    let on_child_var =
                        as_identifier(obj).is_some_and(|n| self.child_vars.contains_key(n));
                    if (on_param || on_child_var)
                        && let Some(tag) = call
                            .arguments
                            .first()
                            .and_then(arg_expr)
                            .and_then(as_string_lit)
                    {
                        self.child_vars
                            .insert(name.as_str().to_string(), tag.to_string());
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.handle_call(call);
        self.try_helper_descent(call);
        // Always descend: chained calls expose both inner and outer nodes.
        walk::walk_call_expression(self, call);
    }
}

impl ParserAnalyzer<'_, '_> {
    fn handle_call(&mut self, call: &CallExpression) {
        let Some(method) = callee_method(call) else {
            return;
        };
        let Some(obj) = callee_object(call) else {
            return;
        };
        let param = self.param;
        let obj_is_param = as_identifier(obj) == Some(param);

        // ── Assertions on the param ──
        if is_assert_method(method) && obj_is_param {
            match method {
                "assertTag" => {
                    if let Some(v) = arg_str(call, 0) {
                        self.assertions.push(ResponseAssertion {
                            kind: AssertionKind::Tag,
                            name: Some(v.to_string()),
                            value: None,
                            reference_path: None,
                        });
                    }
                }
                "assertAttr" => {
                    if let Some(name) = arg_str(call, 0) {
                        self.assertions.push(ResponseAssertion {
                            kind: AssertionKind::Attr,
                            name: Some(name.to_string()),
                            value: arg_str(call, 1).map(str::to_string),
                            reference_path: None,
                        });
                    }
                }
                "assertFromServer" => self.assertions.push(ResponseAssertion {
                    kind: AssertionKind::FromServer,
                    name: None,
                    value: None,
                    reference_path: None,
                }),
                _ => {}
            }
            return;
        }

        // ── Enum accessor with a module-scope value map, on the param ──
        // `attrEnumOrNullIfUnknown("type", u)` reads `type` and validates it against the
        // module-scope map `u`; stash `u`'s keys (the allowed value set) for the `type`
        // field — the plain read of the same attr creates it, so don't emit a duplicate.
        if method == "attrEnumOrNullIfUnknown"
            && obj_is_param
            && let Some(wire) = arg_str(call, 0)
        {
            if let Some(keys) = call
                .arguments
                .get(1)
                .and_then(arg_expr)
                .and_then(as_identifier)
                .and_then(|m| self.module.maps.get(m).cloned())
            {
                self.pending_enum_keys
                    .entry(wire.to_string())
                    .or_insert(keys);
            }
            return;
        }

        // ── Attr/content accessor on the param directly ──
        if is_attr_method(method) && obj_is_param {
            self.fields.push(field_from_call(method, call));
            return;
        }

        // ── Attr method chained on a child() result: e.child("error").attrInt("code") ──
        if is_attr_method(method)
            && let Some((parent_tag, inner_method)) = self.child_call_parent(obj)
        {
            let idx = find_or_create_field(
                &mut self.fields,
                &parent_tag,
                inner_method,
                inner_method == "child",
            );
            push_child_field(&mut self.fields, idx, field_from_call(method, call));
            return;
        }

        // ── child() / maybeChild() directly on the param ──
        if (method == "child" || method == "maybeChild") && obj_is_param {
            let Some(tag) = arg_str(call, 0) else { return };
            if !self
                .fields
                .iter()
                .any(|f| f.method == method && f.tag.as_deref() == Some(tag))
            {
                let mut f = mk_field(method, tag, ParsedFieldType::String, method == "child");
                f.tag = Some(tag.to_string());
                f.children = Some(Vec::new());
                self.fields.push(f);
            }
            return;
        }

        // ── Chained: param.child("tag").<childMethod>(...) ──
        if is_child_method(method)
            && let Some(inner) = as_call(obj)
            && let Some(inner_method) = callee_method(inner)
            && (inner_method == "child" || inner_method == "maybeChild")
            && callee_object(inner).and_then(as_identifier) == Some(param)
            && let Some(parent_tag) = arg_str(inner, 0)
        {
            let pt = parent_tag.to_string();
            process_child_method(method, call, &pt, &mut self.fields, self.code, self.module);
            return;
        }

        // ── child methods on a tracked child var: t.forEachChildWithTag(...) ──
        if is_child_method(method)
            && let Some(parent_tag) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            process_child_method(
                method,
                call,
                &parent_tag,
                &mut self.fields,
                self.code,
                self.module,
            );
            return;
        }

        // ── Attr methods on a tracked child var: t.attrString("name") ──
        if is_attr_method(method)
            && let Some(parent_tag) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            let idx = find_or_create_field(&mut self.fields, &parent_tag, "child", true);
            push_child_field(&mut self.fields, idx, field_from_call(method, call));
        }

        // ── content methods on a tracked child var ──
        // (Note: the "chained `param.child("tag").content...()`" case the TS scanner
        // also tried is a no-op under pre-order visitation — the outer call is
        // visited before the inner `child()` creates the parent field, so there is
        // nothing to annotate. `contentBytes`/`contentString` chained on a child are
        // instead captured as a child field by the attr-chained branch above; only
        // the child-var form below can set `contentType`.)
        if is_content_method(method)
            && let Some(parent_tag) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
            && let Some(f) = self
                .fields
                .iter_mut()
                .find(|f| f.tag.as_deref() == Some(parent_tag.as_str()))
        {
            f.content_type = Some(content_kind(method));
        }
    }

    /// If `obj` is `param.child("tag")` or `childVar.child("tag")`, return
    /// `(parent_tag, inner_method)`.
    fn child_call_parent(&self, obj: &Expression) -> Option<(String, &'static str)> {
        let inner = as_call(obj)?;
        let inner_method = callee_method(inner)?;
        let inner_method = match inner_method {
            "child" => "child",
            "maybeChild" => "maybeChild",
            _ => return None,
        };
        let inner_obj = callee_object(inner)?;
        let on_param = as_identifier(inner_obj) == Some(self.param);
        let on_child_var =
            as_identifier(inner_obj).is_some_and(|n| self.child_vars.contains_key(n));
        if !on_param && !on_child_var {
            return None;
        }
        let parent_tag = inner
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_string_lit)?;
        Some((parent_tag.to_string(), inner_method))
    }

    /// A bare-identifier call `helper(a, …, childVar, …)` that hands a tracked child node
    /// to a module-scope sibling helper (`var i = param.maybeChild("participants"); …
    /// return l ? m(n, i) : d(r, i)`). WA parses some children in such a helper rather than
    /// inline; descend into it — binding the helper parameter at the child's argument
    /// position to that child — and merge the recovered `<tag>` shape into the local field.
    fn try_helper_descent(&mut self, call: &CallExpression) {
        if self.helper_depth >= 2 || self.module.functions.is_empty() {
            return;
        }
        // Callee must be a bare identifier (`m(…)`), not `obj.method(…)`.
        let Some(name) = as_identifier(&call.callee) else {
            return;
        };
        // An argument that is a tracked child var — cheap to check before any re-parse.
        let Some((arg_idx, tag)) = call.arguments.iter().enumerate().find_map(|(i, a)| {
            let id = arg_expr(a).and_then(as_identifier)?;
            self.child_vars.get(id).map(|t| (i, t.clone()))
        }) else {
            return;
        };
        let Some((params, body_src)) = self.module.functions.get(name) else {
            return;
        };
        let Some(bound_param) = params.get(arg_idx) else {
            return;
        };
        let recovered = analyze_child_node(
            body_src,
            bound_param,
            &tag,
            self.module,
            self.helper_depth + 1,
        );
        merge_child_shape(&mut self.fields, &tag, recovered);
    }

    /// Attach each stashed `attrEnumOrNullIfUnknown` key set to the top-level attr field
    /// for that wire name (created by the plain read of the same attr), or synthesize an
    /// optional-string field carrying the keys when the attr is read only via the enum
    /// accessor. Sorted for a deterministic synthesized-field order.
    fn attach_pending_enum_keys(&mut self) {
        let mut pending: Vec<(String, Vec<String>)> = std::mem::take(&mut self.pending_enum_keys)
            .into_iter()
            .collect();
        pending.sort_by(|a, b| a.0.cmp(&b.0));
        for (wire, keys) in pending {
            if let Some(f) = self
                .fields
                .iter_mut()
                .find(|f| f.name == wire && f.tag.is_none())
            {
                if f.enum_keys.is_none() {
                    f.enum_keys = Some(keys);
                }
            } else {
                // No companion plain read created a field for this attr (doesn't occur in
                // the current corpus, but keep it well-formed): synthesize one under a
                // *recognized* optional-enum accessor — `attrEnumOrNullIfUnknown` reads an
                // optional attr validated against an enum key set, which is exactly
                // `maybeAttrEnum`. A raw "attrEnumOrNullIfUnknown" method would not be in
                // `wap::is_attr_method`, leaving the field unclassified downstream.
                let mut f = mk_field(wap::MAYBE_ATTR_ENUM, &wire, ParsedFieldType::String, false);
                f.enum_keys = Some(keys);
                self.fields.push(f);
            }
        }
    }
}

/// The module-scope symbols the (otherwise intra-procedural) parser analyzer reaches into,
/// extracted **once** from the enclosing module source rather than re-parsed per lookup.
/// Empty when there is no enclosing module (the direct-callback tests) or the module fails
/// to parse.
#[derive(Default)]
struct ModuleScope {
    /// helper name → (parameter names, body source). Covers both `function name(p){body}`
    /// declarations and `var name = function(p){body}` expressions, so a sibling helper the
    /// parser hands a child node to is reachable in either the un-minified or minified form.
    functions: HashMap<String, (Vec<String>, String)>,
    /// object-map name → its keys in source order — the allowed value set an enum accessor
    /// (`attrEnumOrNullIfUnknown("attr", map)`) validates a wire attr against.
    maps: HashMap<String, Vec<String>>,
}

impl ModuleScope {
    fn from_source(module_source: &str) -> Self {
        if module_source.is_empty() {
            return Self::default();
        }
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, module_source);
        if ret.panicked {
            return Self::default();
        }
        let mut b = ModuleScopeBuilder {
            module_source,
            functions: HashMap::new(),
            maps: HashMap::new(),
            fn_depth: 0,
        };
        b.visit_program(&ret.program);
        Self {
            functions: b.functions,
            maps: b.maps,
        }
    }
}

struct ModuleScopeBuilder<'a> {
    module_source: &'a str,
    functions: HashMap<String, (Vec<String>, String)>,
    maps: HashMap<String, Vec<String>>,
    /// Number of function bodies we are currently inside. The bundle wraps every module
    /// in one factory (`__d("M",…,function(…){ <module body> })`), so a module-scope
    /// sibling helper — the only kind `try_helper_descent` may resolve a bare-identifier
    /// call to — sits at depth 1. Recording only depth-1 functions keeps a same-named
    /// helper defined *inside another function* from being treated as module-scope.
    fn_depth: u32,
}

impl ModuleScopeBuilder<'_> {
    /// Record `name`'s params + body source, first declaration wins (matching the prior
    /// first-match-in-visit-order `FnFinder` behavior for a shadowed name).
    fn record_fn(
        &mut self,
        name: &str,
        params: &oxc_ast::ast::FormalParameters,
        body: oxc_span::Span,
    ) {
        if self.functions.contains_key(name) {
            return;
        }
        let param_names = params
            .items
            .iter()
            .filter_map(|p| p.pattern.get_identifier_name().map(|n| n.to_string()))
            .collect();
        let body_src = self.module_source[body.start as usize..body.end as usize].to_string();
        self.functions
            .insert(name.to_string(), (param_names, body_src));
    }
}

impl<'a> Visit<'a> for ModuleScopeBuilder<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        // A `function name(){…}` directly in the factory body (depth 1) is a module-scope
        // sibling helper; deeper ones are function-local and must not be resolvable as
        // module-scope. `record_fn` still first-wins, matching the old finder's order.
        if self.fn_depth == 1
            && let Some(id) = func.id.as_ref()
            && let Some(body) = func.body.as_ref()
        {
            self.record_fn(id.name.as_str(), &func.params, body.span);
        }
        self.fn_depth += 1;
        walk::walk_function(self, func, flags);
        self.fn_depth -= 1;
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(name) = d.id.get_identifier_name()
            && let Some(init) = d.init.as_ref()
        {
            match init {
                // `var name = function(p){ body }` — the common minified helper form the
                // old declaration-only finder missed. Only a factory-body-level (depth 1)
                // binding is a module-scope helper.
                Expression::FunctionExpression(f) if self.fn_depth == 1 => {
                    if let Some(body) = f.body.as_ref() {
                        self.record_fn(name.as_str(), &f.params, body.span);
                    }
                }
                // `var name = { key: val, … }` — an enum value map.
                _ => {
                    if let Some(obj) = wa_oxc::as_object(init) {
                        self.maps
                            .entry(name.as_str().to_string())
                            .or_insert_with(|| {
                                wa_oxc::obj_props(obj).map(|(k, _)| k.to_string()).collect()
                            });
                    }
                }
            }
        }
        walk::walk_variable_declarator(self, d);
    }
}

/// Analyze a helper `body_src`, treating `node_param` as a child node tagged `tag` (its
/// `mapChildrenWithTag`/`forEachChildWithTag`/attr accessors become fields under `tag`).
/// Returns the recovered children of that `<tag>` node.
fn analyze_child_node(
    body_src: &str,
    node_param: &str,
    tag: &str,
    module: &ModuleScope,
    depth: u32,
) -> Vec<ParsedField> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_src);
    if ret.panicked {
        return Vec::new();
    }
    let mut a = ParserAnalyzer {
        code: body_src,
        // No stanza param — only the seeded child var is tracked, so the helper's other
        // parameters (the base result it also carries) contribute nothing.
        param: "",
        module,
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::from([(node_param.to_string(), tag.to_string())]),
        pending_enum_keys: HashMap::new(),
        helper_depth: depth,
    };
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    a.fields
        .into_iter()
        .find(|f| f.tag.as_deref() == Some(tag))
        .and_then(|f| f.children)
        .unwrap_or_default()
}

/// Union `new_children` into the existing `<tag>` field's children (the local
/// `var i = param.maybeChild("tag")` field), de-duplicating by `(tag, name)`.
fn merge_child_shape(fields: &mut [ParsedField], tag: &str, new_children: Vec<ParsedField>) {
    let Some(field) = fields.iter_mut().find(|f| f.tag.as_deref() == Some(tag)) else {
        return;
    };
    let existing = field.children.get_or_insert_with(Vec::new);
    for nc in new_children {
        if !existing
            .iter()
            .any(|c| c.tag == nc.tag && c.name == nc.name)
        {
            existing.push(nc);
        }
    }
}

fn content_kind(method: &str) -> ContentType {
    if method == "contentBytes" {
        ContentType::Bytes
    } else {
        ContentType::String
    }
}

/// String value of the nth call argument, if it's a string literal.
fn arg_str<'b>(call: &'b CallExpression, n: usize) -> Option<&'b str> {
    call.arguments
        .get(n)
        .and_then(arg_expr)
        .and_then(as_string_lit)
}

/// Handle `forEachChildWithTag` / `mapChildrenWithTag` / `mapChildren` by
/// recursively analyzing the callback and attaching results under `parent_tag`.
fn process_child_method(
    method: &str,
    call: &CallExpression,
    parent_tag: &str,
    fields: &mut Vec<ParsedField>,
    code: &str,
    module: &ModuleScope,
) {
    match method {
        "forEachChildWithTag" | "mapChildrenWithTag" => {
            let Some(child_tag) = arg_str(call, 0) else {
                return;
            };
            let Some(Expression::FunctionExpression(cb)) = call.arguments.get(1).and_then(arg_expr)
            else {
                return;
            };
            let Some(cb_param) = cb
                .params
                .items
                .first()
                .and_then(|p| p.pattern.get_identifier_name())
            else {
                return;
            };
            let Some(body) = cb.body.as_ref() else { return };
            let cb_body = &code[body.span.start as usize..body.span.end as usize];
            let child_result = analyze_with_scope(cb_body, cb_param.as_str(), module);

            let idx = find_or_create_field(fields, parent_tag, "child", true);
            let mut f = mk_field(method, child_tag, ParsedFieldType::String, true);
            f.tag = Some(child_tag.to_string());
            f.children = Some(child_result.fields);
            f.repeats = Some(true);
            fields[idx].children.get_or_insert_with(Vec::new).push(f);
        }
        "mapChildren" => {
            let Some(Expression::FunctionExpression(cb)) =
                call.arguments.first().and_then(arg_expr)
            else {
                return;
            };
            let Some(cb_param) = cb
                .params
                .items
                .first()
                .and_then(|p| p.pattern.get_identifier_name())
            else {
                return;
            };
            let Some(body) = cb.body.as_ref() else { return };
            let cb_body = &code[body.span.start as usize..body.span.end as usize];
            let child_result = analyze_with_scope(cb_body, cb_param.as_str(), module);

            let idx = find_or_create_field(fields, parent_tag, "child", true);
            let mut f = mk_field("mapChildren", "children", ParsedFieldType::String, true);
            f.children = Some(child_result.fields);
            f.repeats = Some(true);
            fields[idx].children.get_or_insert_with(Vec::new).push(f);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertions() {
        let r = analyze_parser_ast(
            r#"{ e.assertTag("iq"); e.assertAttr("type","result"); e.assertFromServer(); }"#,
            "e",
        );
        assert_eq!(r.assertions.len(), 3);
        assert_eq!(r.assertions[0].kind, AssertionKind::Tag);
        assert_eq!(r.assertions[0].name.as_deref(), Some("iq"));
        assert_eq!(r.assertions[1].kind, AssertionKind::Attr);
        assert_eq!(r.assertions[1].value.as_deref(), Some("result"));
        assert_eq!(r.assertions[2].kind, AssertionKind::FromServer);
    }

    #[test]
    fn attrs_on_param() {
        let r = analyze_parser_ast(
            r#"{ e.attrString("name"); e.attrInt("count"); e.maybeAttrString("opt"); e.attrDeviceJid("from"); }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n).unwrap();
        assert_eq!(by("name").field_type, ParsedFieldType::String);
        assert_eq!(by("count").field_type, ParsedFieldType::Integer);
        assert!(!by("opt").required);
        assert_eq!(by("from").field_type, ParsedFieldType::DeviceJid);
    }

    #[test]
    fn content_bytes_with_length() {
        let r = analyze_parser_ast(r#"{ e.contentBytes(32); }"#, "e");
        let f = &r.fields[0];
        assert_eq!(f.field_type, ParsedFieldType::Bytes);
        assert_eq!(f.byte_length, Some(32));
        assert_eq!(f.name, "content");
    }

    #[test]
    fn child_chained_attr() {
        let r = analyze_parser_ast(r#"{ e.child("error").attrInt("code"); }"#, "e");
        let err = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("error"))
            .unwrap();
        let kids = err.children.as_ref().unwrap();
        assert_eq!(kids[0].name, "code");
        assert_eq!(kids[0].field_type, ParsedFieldType::Integer);
    }

    #[test]
    fn chained_content_bytes_captures_byte_length() {
        // `e.child("value").contentBytes(32)` — the length must be captured on the
        // content field, not dropped (the digest/prekey-bundle response shape).
        let r = analyze_parser_ast(r#"{ e.child("value").contentBytes(32); }"#, "e");
        let value = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("value"))
            .unwrap();
        let content = value
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.method == "contentBytes")
            .unwrap();
        assert_eq!(content.byte_length, Some(32));
    }

    #[test]
    fn child_var_content_bytes_captures_byte_length() {
        // The tracked-child-var form `var m = e.child("skey"); m.contentBytes(64)`.
        let r = analyze_parser_ast(r#"{ var m = e.child("skey"); m.contentBytes(64); }"#, "e");
        let skey = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("skey"))
            .unwrap();
        let content = skey
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.method == "contentBytes")
            .unwrap();
        assert_eq!(content.byte_length, Some(64));
    }

    #[test]
    fn child_via_local_var_with_content() {
        let r = analyze_parser_ast(
            r#"{ var t = e.child("data"); t.attrString("v"); t.contentString(); }"#,
            "e",
        );
        let data = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("data"))
            .unwrap();
        assert_eq!(data.content_type, Some(ContentType::String));
        assert!(
            data.children
                .as_ref()
                .unwrap()
                .iter()
                .any(|c| c.name == "v")
        );
    }

    #[test]
    fn for_each_child_with_tag_recurses() {
        let r = analyze_parser_ast(
            r#"{ e.child("list").forEachChildWithTag("item", function(c){ c.attrString("id"); c.attrInt("n"); }); }"#,
            "e",
        );
        let list = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("list"))
            .unwrap();
        let item = list
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.tag.as_deref() == Some("item"))
            .unwrap();
        assert_eq!(item.repeats, Some(true));
        let names: Vec<_> = item
            .children
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["id", "n"]);
    }

    #[test]
    fn map_children_collects_under_children() {
        let r = analyze_parser_ast(
            r#"{ e.child("items").mapChildren(function(c){ c.attrString("k"); }); }"#,
            "e",
        );
        let items = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("items"))
            .unwrap();
        let mapped = &items.children.as_ref().unwrap()[0];
        assert_eq!(mapped.method, "mapChildren");
        assert_eq!(mapped.name, "children");
        assert_eq!(mapped.repeats, Some(true));
    }

    #[test]
    fn chained_content_bytes_on_child_becomes_child_field() {
        // `param.child("blob").contentBytes()` → attr-chained branch: a "content"
        // child of type Bytes under "blob" (contentType is only set via child vars).
        let r = analyze_parser_ast(r#"{ e.child("blob").contentBytes(); }"#, "e");
        let blob = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("blob"))
            .unwrap();
        let kids = blob.children.as_ref().unwrap();
        assert!(
            kids.iter()
                .any(|c| c.name == "content" && c.field_type == ParsedFieldType::Bytes)
        );
    }

    #[test]
    fn content_on_child_var_sets_content_type() {
        let r = analyze_parser_ast(r#"{ var t = e.child("raw"); t.contentBytes(); }"#, "e");
        let raw = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("raw"))
            .unwrap();
        assert_eq!(raw.content_type, Some(ContentType::Bytes));
    }

    #[test]
    fn maybe_child_variants() {
        // Chained attr on a maybeChild() result.
        let r = analyze_parser_ast(r#"{ e.maybeChild("opt").attrString("v"); }"#, "e");
        let opt = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("opt"))
            .unwrap();
        assert_eq!(opt.method, "maybeChild");
        assert!(opt.children.as_ref().unwrap().iter().any(|c| c.name == "v"));

        // maybeChild() directly on the param.
        let r2 = analyze_parser_ast(r#"{ e.maybeChild("solo"); }"#, "e");
        assert!(
            r2.fields
                .iter()
                .any(|f| f.method == "maybeChild" && f.tag.as_deref() == Some("solo"))
        );
    }

    #[test]
    fn nested_child_var_chain() {
        // `u` is tracked as a child var derived from another child var `t`.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("a"); var u = t.child("b"); u.attrString("x"); }"#,
            "e",
        );
        let b = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("b"))
            .unwrap();
        assert!(b.children.as_ref().unwrap().iter().any(|c| c.name == "x"));
    }

    #[test]
    fn attr_chained_on_non_child_is_ignored() {
        // `.attrString` chained on a call that isn't `child()/maybeChild()`, and on
        // a `child()` of an unrelated object — neither produces a field.
        let r = analyze_parser_ast(r#"{ e.foo("a").attrString("x"); }"#, "e");
        assert!(r.fields.is_empty());
        let r2 = analyze_parser_ast(r#"{ unrelated.child("a").attrString("x"); }"#, "e");
        assert!(r2.fields.is_empty());
    }

    #[test]
    fn invalid_body_is_empty() {
        let r = analyze_parser_ast("{ this is not js ", "e");
        assert!(r.fields.is_empty() && r.assertions.is_empty());
    }

    #[test]
    fn recovers_variable_named_parser() {
        // `WAWebHandleMexNotification` hoists the parser name into a variable
        // (`d = "mexNotificationParser", m = new WADeprecatedWapParser(d, fn)`); the
        // name must be resolved from the binding or the parser is silently dropped.
        let module = r#"__d("WAWebHandleMexNotification",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var d="mexNotificationParser",m=new(r("WADeprecatedWapParser"))(d,function(e){
                e.assertTag("notification"), e.assertAttr("type","mex");
                return { id: e.attrString("id") };
            });
        }), 1);"#;
        let parsers = parse_module_wap_parsers(module);
        assert_eq!(
            parsers.len(),
            1,
            "variable-named parser should be recovered"
        );
        assert_eq!(parsers[0].parser_name, "mexNotificationParser");
        assert!(parsers[0].fields.iter().any(|f| f.name == "id"));
    }

    #[test]
    fn ambiguous_variable_name_is_not_guessed() {
        // The same short name bound to two different strings → don't risk a wrong
        // label; the parser is left unnamed (dropped) rather than mislabeled.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var d="one";
            var d="two";
            var m=new(r("WADeprecatedWapParser"))(d,function(e){ return { id: e.attrString("id") }; });
        }), 1);"#;
        assert!(parse_module_wap_parsers(module).is_empty());
    }

    #[test]
    fn variable_name_reused_in_another_function_is_not_mislabeled() {
        // The binding lookup is module-wide, so a short name reused in an unrelated
        // function with a DIFFERENT value makes it ambiguous. The uniqueness guard
        // then refuses to guess (the parser is dropped) — the point being that a
        // reused name can never attach the WRONG label, only degrade to none.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function build(){ var d="mexNotificationParser"; return new(r("WADeprecatedWapParser"))(d,function(e){ return { id: e.attrString("id") }; }); }
            function other(){ var d="unrelatedLabel"; return d; }
            l.p=build(), l.o=other;
        }), 1);"#;
        // Two distinct bindings for `d` → ambiguous → the parser is dropped entirely
        // (not attached with either label). Asserting emptiness — rather than just the
        // absence of the wrong name — keeps this from passing vacuously.
        let parsers = parse_module_wap_parsers(module);
        assert!(parsers.is_empty());
        assert!(parsers.iter().all(|p| p.parser_name != "unrelatedLabel"));
    }

    #[test]
    fn descends_into_module_helper_for_child_grandchildren() {
        // A parser whose `<participants>` child is parsed in a module-scope sibling helper
        // (`return d(e, i)` with the child `i` at arg 1) — the helper's `<user>`
        // grandchildren must be recovered via arg→param binding + descent.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function d(e,t){ t.mapChildrenWithTag("user", function(u){ u.attrDeviceJid("jid"); u.attrTime("t"); }); return {}; }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i=e.maybeChild("participants");
                return d(e, i);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let participants = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("participants"))
            .expect("participants field");
        let user = participants
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.tag.as_deref() == Some("user"))
            .expect("user grandchild recovered via helper descent");
        let attrs: Vec<&str> = user
            .children
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            attrs.contains(&"jid") && attrs.contains(&"t"),
            "user attrs: {attrs:?}"
        );
    }

    #[test]
    fn descends_into_function_expression_helper() {
        // Same as above, but the sibling helper is bound as a *function expression*
        // (`var d = function(e,t){…}`) — the minified form WA ships. The pre-extracted
        // module scope must find it just like a `function d(){…}` declaration.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var d=function(e,t){ t.mapChildrenWithTag("user", function(u){ u.attrDeviceJid("jid"); u.attrTime("t"); }); return {}; };
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i=e.maybeChild("participants");
                return d(e, i);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let participants = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("participants"))
            .expect("participants field");
        let user = participants
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.tag.as_deref() == Some("user"))
            .expect("user grandchild recovered via fn-expression helper descent");
        let attrs: Vec<&str> = user
            .children
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            attrs.contains(&"jid") && attrs.contains(&"t"),
            "user attrs: {attrs:?}"
        );
    }

    #[test]
    fn helper_descent_ignores_nested_same_name_function() {
        // A module-scope helper `d` parses `<user jid>`; an unrelated function also has a
        // *local* `var d = function(){…}` (parsing a different shape) that appears earlier
        // in source. Helper descent must bind to the module-scope `d`, not the nested one
        // — recording every-nesting `d` (first-wins) would cross-wire the two.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function wrapper(){ var d=function(e,t){ t.mapChildrenWithTag("user", function(u){ u.attrString("wrong"); }); return {}; }; return d; }
            function d(e,t){ t.mapChildrenWithTag("user", function(u){ u.attrDeviceJid("jid"); }); return {}; }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i=e.maybeChild("participants");
                return d(e, i);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let user = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("participants"))
            .and_then(|f| f.children.as_ref())
            .and_then(|kids| kids.iter().find(|c| c.tag.as_deref() == Some("user")))
            .expect("user grandchild via module-scope helper");
        let attrs: Vec<&str> = user
            .children
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            attrs.contains(&"jid"),
            "module-scope helper's shape: {attrs:?}"
        );
        assert!(
            !attrs.contains(&"wrong"),
            "nested same-name helper must not be resolved as module-scope: {attrs:?}"
        );
    }

    #[test]
    fn attr_enum_or_null_attaches_module_map_keys() {
        // `attrEnumOrNullIfUnknown("type", u)` validates `type` against a module-scope map
        // `u`; its keys must attach to the `type` field (created by the plain read) as the
        // allowed value set — without emitting a duplicate field.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var u={delivery:1,read:2,played:3};
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var t=e.hasAttr("type")?e.attrEnumOrNullIfUnknown("type",u):0;
                e.maybeAttrString("type");
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let type_fields: Vec<_> = p
            .fields
            .iter()
            .filter(|f| f.name == "type" && f.tag.is_none())
            .collect();
        assert_eq!(type_fields.len(), 1, "no duplicate type field");
        assert_eq!(
            type_fields[0].enum_keys.as_deref(),
            Some(["delivery", "read", "played"].map(String::from).as_slice())
        );
    }
}
