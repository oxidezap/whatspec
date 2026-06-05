//! Response parser analysis: walk a `WADeprecatedWapParser` callback body and
//! reconstruct the response field tree (assertions, attrs, nested children).
//!
//! Mirrors `analyzeParserAST` + `processChildMethod` from the TS scanner. Handles
//! accessors on the param directly, chained `param.child("x").attr...`, and
//! `child()` results captured in local variables.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, VariableDeclaration};
use oxc_ast_visit::{Visit, walk};
use wa_ir::wap;
use wa_ir::{AssertionKind, ContentType, ParsedField, ParsedFieldType, ResponseAssertion};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, callee_method, callee_object};

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
pub(crate) fn analyze_parser_ast(code: &str, param: &str) -> ParserResult {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, code);
    let mut a = ParserAnalyzer {
        code,
        param,
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::new(),
    };
    a.visit_program(&ret.program);
    ParserResult {
        assertions: a.assertions,
        fields: a.fields,
    }
}

struct ParserAnalyzer<'src> {
    code: &'src str,
    param: &'src str,
    assertions: Vec<ResponseAssertion>,
    fields: Vec<ParsedField>,
    /// local var name → tag, for `var t = param.child("tag")`.
    child_vars: HashMap<String, String>,
}

impl<'a> Visit<'a> for ParserAnalyzer<'_> {
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
        // Always descend: chained calls expose both inner and outer nodes.
        walk::walk_call_expression(self, call);
    }
}

impl ParserAnalyzer<'_> {
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
                        });
                    }
                }
                "assertAttr" => {
                    if let Some(name) = arg_str(call, 0) {
                        self.assertions.push(ResponseAssertion {
                            kind: AssertionKind::Attr,
                            name: Some(name.to_string()),
                            value: arg_str(call, 1).map(str::to_string),
                        });
                    }
                }
                "assertFromServer" => self.assertions.push(ResponseAssertion {
                    kind: AssertionKind::FromServer,
                    name: None,
                    value: None,
                }),
                _ => {}
            }
            return;
        }

        // ── Attr/content accessor on the param directly ──
        if is_attr_method(method) && obj_is_param {
            let arg0 = call.arguments.first().and_then(arg_expr);
            let field_name = arg0.and_then(as_string_lit).unwrap_or("content");
            let mut f = mk_field(
                method,
                field_name,
                method_to_field_type(method),
                is_method_required(method),
            );
            if method == "contentBytes"
                && let Some(Expression::NumericLiteral(n)) = arg0
            {
                f.byte_length = Some(n.value as u32);
            }
            self.fields.push(f);
            return;
        }

        // ── Attr method chained on a child() result: e.child("error").attrInt("code") ──
        if is_attr_method(method)
            && let Some((parent_tag, inner_method)) = self.child_call_parent(obj)
        {
            let field_name = arg_str(call, 0).unwrap_or("content");
            let idx = find_or_create_field(
                &mut self.fields,
                &parent_tag,
                inner_method,
                inner_method == "child",
            );
            push_child_field(
                &mut self.fields,
                idx,
                mk_field(
                    method,
                    field_name,
                    method_to_field_type(method),
                    is_method_required(method),
                ),
            );
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
            process_child_method(method, call, &pt, &mut self.fields, self.code);
            return;
        }

        // ── child methods on a tracked child var: t.forEachChildWithTag(...) ──
        if is_child_method(method)
            && let Some(parent_tag) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            process_child_method(method, call, &parent_tag, &mut self.fields, self.code);
            return;
        }

        // ── Attr methods on a tracked child var: t.attrString("name") ──
        if is_attr_method(method)
            && let Some(parent_tag) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            let field_name = arg_str(call, 0).unwrap_or("content");
            let idx = find_or_create_field(&mut self.fields, &parent_tag, "child", true);
            push_child_field(
                &mut self.fields,
                idx,
                mk_field(
                    method,
                    field_name,
                    method_to_field_type(method),
                    is_method_required(method),
                ),
            );
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
            let child_result = analyze_parser_ast(cb_body, cb_param.as_str());

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
            let child_result = analyze_parser_ast(cb_body, cb_param.as_str());

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
}
