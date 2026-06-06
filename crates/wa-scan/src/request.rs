//! Request-side child resolution: turn `wap()` child arguments into
//! [`WapChildNode`] trees, tracing variable references, `.map()` calls, and
//! helper-function returns.
//!
//! The variable scope is **offset-based** (name → source spans), not AST-node
//! references: oxc's `Visit` hands out short-lived borrows, so instead of storing
//! nodes we store byte spans into the module source and re-parse slices on demand.
//! All span-relative work uses the source a node came from (`node_source`); all
//! scope lookups slice the module source. This mirrors the TS scanner's re-parse
//! approach while staying lifetime-clean.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Function, Program, Statement, VariableDeclaration};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use wa_ir::WapChildNode;

use crate::alias::{AliasMap, build_alias_map, resolve_owner};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use wa_oxc::{arg_expr, as_call, as_identifier, callee_method, callee_object};

/// Max function-boundary crossings while tracing returns/templates. Bounds the
/// `resolve_child_node` ↔ `resolve_function_return` recursion so a (pathological)
/// mutually-recursive helper pair can't loop forever; real builders nest only a
/// few templates deep.
const MAX_FN_DEPTH: u32 = 8;

/// One initializer of a tracked variable, as byte spans into the module source.
#[derive(Clone)]
struct VarInit {
    init_start: usize,
    init_end: usize,
    /// `{...}` body span if the initializer (or declaration) is a function.
    fn_body: Option<(usize, usize)>,
}

/// Variable/function name → all initializers seen (offset-based, lifetime-free).
#[derive(Default)]
pub(crate) struct VarScope {
    vars: HashMap<String, Vec<VarInit>>,
}

impl VarScope {
    fn push(&mut self, name: &str, init: VarInit) {
        self.vars.entry(name.to_string()).or_default().push(init);
    }
}

/// Build a [`VarScope`] from a parsed program: every `var/let/const x = init` and
/// every `function name() {...}` declaration, at any nesting.
pub(crate) fn build_var_scope(program: &Program) -> VarScope {
    let mut b = ScopeBuilder {
        scope: VarScope::default(),
    };
    b.visit_program(program);
    b.scope
}

struct ScopeBuilder {
    scope: VarScope,
}

impl<'a> Visit<'a> for ScopeBuilder {
    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref()) {
                let fn_body = match init {
                    Expression::FunctionExpression(f) => fn_body_span(f),
                    _ => None,
                };
                let span = init.span();
                self.scope.push(
                    name.as_str(),
                    VarInit {
                        init_start: span.start as usize,
                        init_end: span.end as usize,
                        fn_body,
                    },
                );
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_statement(&mut self, stmt: &Statement<'a>) {
        if let Statement::FunctionDeclaration(func) = stmt
            && let Some(id) = &func.id
        {
            self.scope.push(
                id.name.as_str(),
                VarInit {
                    init_start: func.span.start as usize,
                    init_end: func.span.end as usize,
                    fn_body: fn_body_span(func),
                },
            );
        }
        walk::walk_statement(self, stmt);
    }
}

fn fn_body_span(f: &Function) -> Option<(usize, usize)> {
    f.body
        .as_ref()
        .map(|b| (b.span.start as usize, b.span.end as usize))
}

/// Resolve a `wap()` child-argument expression into zero or more child nodes.
///
/// - `node_source`: the source `node` was parsed from (for span-relative ops).
/// - `module_source`: the module source the scope offsets index into.
pub(crate) fn resolve_child_node(
    node: &Expression,
    node_source: &str,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    depth: u32,
) -> Vec<WapChildNode> {
    // Unwrap `(…)` — a transparent wrapper (e.g. a re-parsed `return (expr)`).
    if let Expression::ParenthesizedExpression(p) = node {
        return resolve_child_node(
            &p.expression,
            node_source,
            scope,
            module_source,
            aliases,
            depth,
        );
    }

    // Case 1: direct wap()/smax() call.
    if let Some(call) = as_call(node)
        && let Some(wap) = parse_wap_call(call, aliases)
    {
        let attrs = wap
            .attrs_node
            .map(|n| extract_attrs_from_obj(n, node_source, aliases))
            .unwrap_or_default();
        let mut children = Vec::new();
        for child_arg in wap.child_args {
            if let Some(ce) = arg_expr(child_arg) {
                children.extend(resolve_child_node(
                    ce,
                    node_source,
                    scope,
                    module_source,
                    aliases,
                    depth,
                ));
            }
        }
        return vec![WapChildNode {
            tag: wap.tag.to_string(),
            attrs,
            children,
            repeats: false,
        }];
    }

    // Case 1b: an array of children — `[a, b]` or `[].concat(a, b)` produce a
    // children list; resolve and flatten each element.
    if let Expression::ArrayExpression(arr) = node {
        let mut out = Vec::new();
        for el in &arr.elements {
            if let Some(e) = el.as_expression() {
                out.extend(resolve_child_node(
                    e,
                    node_source,
                    scope,
                    module_source,
                    aliases,
                    depth,
                ));
            }
        }
        return out;
    }

    // Case 2: variable reference — try every initializer (re-parsing its slice).
    if let Some(name) = as_identifier(node) {
        if let Some(inits) = scope.vars.get(name) {
            for init in inits {
                let slice = &module_source[init.init_start..init.init_end];
                let alloc = Allocator::default();
                let ret = wa_oxc::parse_cjs(&alloc, slice);
                if let Some(expr) = first_expression(&ret.program) {
                    if let Some(m) = resolve_map_call(expr, slice, aliases) {
                        return m;
                    }
                    let r = resolve_child_node(expr, slice, scope, module_source, aliases, depth);
                    if !r.is_empty() {
                        return r;
                    }
                }
            }
        }
        return Vec::new();
    }

    // Case 3: a `.map(fn)` producing an array of children.
    if let Some(m) = resolve_map_call(node, node_source, aliases) {
        return m;
    }

    // Case 4: smax composition/optional/repeated child helpers.
    //   WASmaxChildren.REPEATED_CHILD(tmpl, list, …)        → repeating child template
    //   WASmaxChildren.OPTIONAL_CHILD/HAS_OPTIONAL_CHILD(tmpl, val) → optional child
    //   WASmax…Mixin.merge…Mixin(stanza, …)                 → the passed-in stanza
    //   WASmaxMixins.optionalMerge(mergeFn, stanza, …)      → the stanza (2nd arg)
    //   [].concat(a, b, …)                                  → flatten the lists
    // The `tmpl` of REPEATED/OPTIONAL_CHILD is a stanza or a template *function*
    // (resolved via its return); merge/optionalMerge/concat may carry the stanza in
    // any argument, so we resolve them all. (Cross-module mixin *fragments* — the
    // attrs/children a `merge…Mixin` adds via `mergeStanzas` — are Phase 2.)
    if let Some(call) = as_call(node)
        && let Some(method) = callee_method(call)
    {
        let owner = callee_object(call).and_then(|o| resolve_owner(o, aliases));
        let repeated = owner == Some("WASmaxChildren") && method == "REPEATED_CHILD";
        let optional = owner == Some("WASmaxChildren")
            && matches!(method, "OPTIONAL_CHILD" | "HAS_OPTIONAL_CHILD");
        if repeated || optional {
            if let Some(first) = call.arguments.first().and_then(arg_expr) {
                let mut r =
                    resolve_template_arg(first, node_source, scope, module_source, aliases, depth);
                if repeated {
                    for c in &mut r {
                        c.repeats = true;
                    }
                }
                if !r.is_empty() {
                    return r;
                }
            }
        }
        // `merge…Mixin` and the disjunction `merge…MixinGroup` both wrap a stanza.
        let is_merge = method.starts_with("merge") && method.contains("Mixin");
        let is_optional_merge = owner == Some("WASmaxMixins") && method == "optionalMerge";
        let is_concat = method == "concat";
        if is_merge || is_optional_merge || is_concat {
            // The stanza/children can be in any argument (concat lists, the 2nd-arg
            // stanza of optionalMerge, the 1st-arg stanza of a merge); resolve all.
            let mut out = Vec::new();
            // `recv.concat(extra)` returns the receiver's elements too, so resolve
            // the receiver (e.g. `[a].concat(b)` must keep `a`).
            if is_concat && let Some(obj) = callee_object(call) {
                out.extend(resolve_child_node(
                    obj,
                    node_source,
                    scope,
                    module_source,
                    aliases,
                    depth,
                ));
            }
            for a in &call.arguments {
                if let Some(e) = arg_expr(a) {
                    out.extend(resolve_child_node(
                        e,
                        node_source,
                        scope,
                        module_source,
                        aliases,
                        depth,
                    ));
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }

    // Case 5: `helper(args)` — trace the helper's return value.
    if let Some(call) = as_call(node)
        && let Some(callee_name) = as_identifier(&call.callee)
        && let Some(inits) = scope.vars.get(callee_name)
    {
        for vi in inits {
            if let Some((bs, be)) = vi.fn_body {
                let r = resolve_function_return(bs, be, scope, module_source, aliases, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
    }

    Vec::new()
}

/// Resolve a `REPEATED_CHILD`/`OPTIONAL_CHILD` template argument: an inline stanza,
/// or a template *function* reference whose return builds the child (`REPEATED_CHILD(e, …)`
/// where `function e(o){ return …smax("item", …) }`).
fn resolve_template_arg(
    arg: &Expression,
    node_source: &str,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    depth: u32,
) -> Vec<WapChildNode> {
    // A template is usually a *function* reference: trace its return. Prefer the
    // function initializer over any same-named non-function var — the flat scope
    // conflates a template fn `e` with an unrelated `var e = smax(…)` in a sibling
    // helper, and the function is the one passed as the template.
    if let Some(name) = as_identifier(arg)
        && let Some(inits) = scope.vars.get(name)
    {
        for vi in inits {
            if let Some((bs, be)) = vi.fn_body {
                let r = resolve_function_return(bs, be, scope, module_source, aliases, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
    }
    // Otherwise an inline stanza or other directly-resolvable expression.
    resolve_child_node(arg, node_source, scope, module_source, aliases, depth)
}

/// `x.map(function(o){ return e.wap(...) })` → repeating child template(s).
fn resolve_map_call(
    node: &Expression,
    node_source: &str,
    aliases: &AliasMap,
) -> Option<Vec<WapChildNode>> {
    let call = as_call(node)?;
    if callee_method(call)? != "map" {
        return None;
    }
    let Expression::FunctionExpression(func) = arg_expr(call.arguments.first()?)? else {
        // `.map(ref)` with a non-inline callback — can't inspect it statically.
        return None;
    };
    let body = func.body.as_ref()?;
    let body_code = &node_source[body.span.start as usize..body.span.end as usize];
    let mut children = find_wap_calls_in_body(body_code, aliases);
    if children.is_empty() {
        return None;
    }
    for c in &mut children {
        c.repeats = true;
    }
    Some(children)
}

/// Trace a function body for `wap()` calls, following `return helper(...)` chains.
fn resolve_function_return(
    body_start: usize,
    body_end: usize,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    depth: u32,
) -> Vec<WapChildNode> {
    if depth > MAX_FN_DEPTH {
        return Vec::new();
    }
    let body = &module_source[body_start..body_end];
    // Resolve each `return <expr>` through the normal child resolver so nested
    // children stay nested (a template returning `smax("description", …,
    // smax("body", …))` keeps `body` under `description`).
    //
    // Lexical scope: this body's own vars (shifted to module-absolute offsets)
    // SHADOW the module scope, but the module scope still backs cross-function refs
    // (a sibling template fn like `e` in `REPEATED_CHILD(e, …)`). This fixes the
    // flat-scope collision (`return e` → this body's `var e`, not a sibling's) while
    // keeping sibling-fn templates resolvable. Builder helper graphs are acyclic
    // (they terminate at runtime), so the `resolve_child_node` recursion terminates.
    let alloc = Allocator::default();
    let parsed = wa_oxc::parse_cjs(&alloc, body);
    let mut merged = build_var_scope(&parsed.program);
    for inits in merged.vars.values_mut() {
        for vi in inits {
            vi.init_start += body_start;
            vi.init_end += body_start;
            if let Some((s, e)) = vi.fn_body.as_mut() {
                *s += body_start;
                *e += body_start;
            }
        }
    }
    for (name, ginits) in &scope.vars {
        merged
            .vars
            .entry(name.clone())
            .or_default()
            .extend(ginits.iter().cloned());
    }
    let mut out = Vec::new();
    for arg_src in collect_return_arg_sources(body) {
        let alloc2 = Allocator::default();
        let owned = format!("({arg_src});");
        let r2 = wa_oxc::parse_cjs(&alloc2, &owned);
        if let Some(expr) = first_expression(&r2.program) {
            out.extend(resolve_child_node(
                expr,
                &owned,
                &merged,
                module_source,
                aliases,
                depth,
            ));
        }
    }
    if !out.is_empty() {
        return out;
    }
    let direct = find_wap_calls_in_body(body, aliases);
    if !direct.is_empty() {
        return direct;
    }
    for name in collect_returned_call_names(body) {
        if let Some(inits) = scope.vars.get(&name) {
            for vi in inits {
                if let Some((nbs, nbe)) = vi.fn_body {
                    let r =
                        resolve_function_return(nbs, nbe, scope, module_source, aliases, depth + 1);
                    if !r.is_empty() {
                        return r;
                    }
                }
            }
        }
    }
    Vec::new()
}

/// All `wap()`/`smax()` calls anywhere in a body string, as flat children.
///
/// The body is re-parsed in isolation, so smax aliases local to the enclosing
/// module aren't visible; we rebuild a local alias map from this body so any
/// `(X = o("WASmaxJsx"))` inside it is still resolved.
fn find_wap_calls_in_body(body_code: &str, outer: &AliasMap) -> Vec<WapChildNode> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_code);
    let local = build_alias_map(&ret.program);
    let mut c = WapCollector {
        out: Vec::new(),
        source: body_code,
        // Prefer the body-local aliases; fall back to the outer ones.
        local: &local,
        outer,
    };
    c.visit_program(&ret.program);
    c.out
}

struct WapCollector<'s> {
    out: Vec<WapChildNode>,
    source: &'s str,
    local: &'s AliasMap,
    outer: &'s AliasMap,
}

impl<'a> Visit<'a> for WapCollector<'_> {
    fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
        let parsed = parse_wap_call(call, self.local).or_else(|| parse_wap_call(call, self.outer));
        if let Some(wap) = parsed {
            let attrs = wap
                .attrs_node
                .map(|n| extract_attrs_from_obj(n, self.source, self.local))
                .unwrap_or_default();
            self.out.push(WapChildNode {
                tag: wap.tag.to_string(),
                attrs,
                children: Vec::new(),
                repeats: false,
            });
        }
        walk::walk_call_expression(self, call);
    }
}

/// Source text of each top-level `return <expr>` argument in a function body
/// (descending into nested blocks, but NOT into nested functions — a `.map`/template
/// callback's own return is resolved separately and must not be hoisted here).
fn collect_return_arg_sources(body_code: &str) -> Vec<String> {
    // `return` is only valid inside a function, so wrap the body before parsing;
    // spans then index into `wrapped`.
    let wrapped = format!("(function(){body_code});");
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, &wrapped);
    let func = ret.program.body.iter().find_map(|s| match s {
        Statement::ExpressionStatement(es) => {
            let e = match &es.expression {
                Expression::ParenthesizedExpression(p) => &p.expression,
                other => other,
            };
            match e {
                Expression::FunctionExpression(f) => f.body.as_ref(),
                _ => None,
            }
        }
        _ => None,
    });
    let mut out = Vec::new();
    if let Some(body) = func {
        for stmt in &body.statements {
            collect_returns_in_stmt(stmt, &wrapped, &mut out);
        }
    }
    out
}

fn collect_returns_in_stmt(stmt: &Statement, src: &str, out: &mut Vec<String>) {
    match stmt {
        Statement::BlockStatement(b) => {
            for s in &b.body {
                collect_returns_in_stmt(s, src, out);
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(arg) = &r.argument {
                let sp = arg.span();
                out.push(src[sp.start as usize..sp.end as usize].to_string());
            }
        }
        // Don't descend into functions / control-flow: builder returns are top-level.
        _ => {}
    }
}

/// Names of functions returned directly: `return helper(args)` → `helper`.
fn collect_returned_call_names(body_code: &str) -> Vec<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_code);
    let mut c = ReturnCallCollector { names: Vec::new() };
    c.visit_program(&ret.program);
    c.names
}

struct ReturnCallCollector {
    names: Vec<String>,
}

impl<'a> Visit<'a> for ReturnCallCollector {
    fn visit_return_statement(&mut self, stmt: &oxc_ast::ast::ReturnStatement<'a>) {
        if let Some(arg) = &stmt.argument
            && let Some(call) = as_call(arg)
            && let Some(name) = as_identifier(&call.callee)
        {
            let name = name.to_string();
            if !self.names.contains(&name) {
                self.names.push(name);
            }
        }
        walk::walk_return_statement(self, stmt);
    }
}

fn first_expression<'a>(program: &'a Program<'a>) -> Option<&'a Expression<'a>> {
    program.body.iter().find_map(|stmt| match stmt {
        Statement::ExpressionStatement(es) => Some(&es.expression),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build scope from `code`, then resolve the expression `expr_src` against it.
    fn resolve(code: &str, expr_src: &str) -> Vec<WapChildNode> {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let scope = build_var_scope(&ret.program);
        let aliases = build_alias_map(&ret.program);

        let alloc2 = Allocator::default();
        let owned = format!("{expr_src};");
        let ret2 = wa_oxc::parse_cjs(&alloc2, &owned);
        let expr = first_expression(&ret2.program).unwrap();
        resolve_child_node(expr, &owned, &scope, code, &aliases, 0)
    }

    #[test]
    fn inline_alias_merge_optionalmerge_chain() {
        // Minified Groups-style builder: a `merge…MixinGroup` wrapping an inline-alias
        // `(n = o("WASmaxMixins")).optionalMerge(…)` chain over a `<create>` whose
        // children come from `[].concat(REPEATED_CHILD(fn,…), [HAS_OPTIONAL_CHILD(fn,…)])`.
        // Exercises paren-unwrapped owner resolution + concat + template fn-refs.
        let code = r#"
            function e(o){ return o("WASmaxMixins").optionalMerge(o("P").mergePermMixin, o("WASmaxJsx").smax("participant", {jid:"x"}), a); }
            function u(){ return o("WASmaxJsx").smax("locked", null); }
            var X = o("WASmaxJsx").smax("iq", null,
              o("Mod").mergeNamedSubjectFallbackMixinGroup(
                (n=o("WASmaxMixins")).optionalMerge(o("A").mergeShareMixin,
                  n.optionalMerge(o("B").mergeDedupMixin,
                    o("WASmaxJsx").smax("create", null,
                      [].concat((r=o("WASmaxChildren")).REPEATED_CHILD(e, a, 0, 19999), [r.HAS_OPTIONAL_CHILD(u, l)])
                    ), A),
                  F),
              W));
        "#;
        let out = resolve(code, "X");
        assert_eq!(out.len(), 1);
        let create = out[0]
            .children
            .iter()
            .find(|c| c.tag == "create")
            .expect("create recovered through the merge/optionalMerge chain");
        let tags: Vec<_> = create.children.iter().map(|c| c.tag.as_str()).collect();
        assert!(
            tags.contains(&"participant"),
            "participant template: {tags:?}"
        );
        assert!(tags.contains(&"locked"), "locked template: {tags:?}");
        assert!(
            create
                .children
                .iter()
                .find(|c| c.tag == "participant")
                .unwrap()
                .repeats,
            "REPEATED_CHILD marks participant repeats"
        );
    }

    #[test]
    fn template_fn_preserves_nested_children() {
        // A template function whose returned stanza has its own child must keep the
        // nesting (`description > body`), not sibling-ize them.
        let code = r#"function tmpl(o){ return o("WASmaxJsx").smax("description", {id:"7"}, o("WASmaxJsx").smax("body", {})); }"#;
        let out = resolve(
            code,
            r#"o("WASmaxChildren").REPEATED_CHILD(tmpl, list, 0, 9)"#,
        );
        assert_eq!(out.len(), 1, "one top-level child, not flattened siblings");
        assert_eq!(out[0].tag, "description");
        assert!(out[0].repeats);
        assert_eq!(out[0].children.len(), 1, "body nested under description");
        assert_eq!(out[0].children[0].tag, "body");
    }

    #[test]
    fn repeated_child_fn_ref_template_resolves() {
        // `REPEATED_CHILD(fn, list, …)` where `fn` is a function reference whose
        // return builds the child template (traced via resolve_function_return).
        let code = r#"function tmpl(o){ return o("WASmaxJsx").smax("item", {id:"1"}); }"#;
        let out = resolve(
            code,
            r#"o("WASmaxChildren").REPEATED_CHILD(tmpl, list, 0, 20)"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "item");
        assert!(out[0].repeats, "REPEATED_CHILD marks repeats");
    }

    #[test]
    fn optional_merge_resolves_stanza_arg() {
        // `WASmaxMixins.optionalMerge(mergeFn, stanza, …)` → the 2nd-arg stanza.
        let out = resolve(
            "",
            r#"o("WASmaxMixins").optionalMerge(o("M").mergeFooMixin, o("WASmaxJsx").smax("query", {phash:"p"}), args)"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "query");
    }

    #[test]
    fn concat_includes_non_empty_receiver() {
        // `[recv].concat(extra)` keeps both the receiver's and the arguments'
        // children (the receiver is not dropped).
        let out = resolve(
            "",
            r#"[o("WASmaxJsx").smax("a", {})].concat(o("WASmaxJsx").smax("b", {}))"#,
        );
        let tags: Vec<_> = out.iter().map(|c| c.tag.as_str()).collect();
        assert_eq!(tags, ["a", "b"], "receiver `a` and argument `b` both kept");
    }

    #[test]
    fn direct_wap_with_nested_children() {
        let out = resolve("", r#"e.wap("a", {x:"1"}, e.wap("b", {y:"2"}))"#);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "a");
        assert_eq!(out[0].children.len(), 1);
        assert_eq!(out[0].children[0].tag, "b");
        assert_eq!(out[0].attrs[0].name, "x");
    }

    #[test]
    fn variable_reference_resolves_to_wap() {
        let code = r#"var c = e.wap("child", {id:"7"});"#;
        let out = resolve(code, "c");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "child");
    }

    #[test]
    fn map_call_marks_repeats() {
        let out = resolve(
            "",
            r#"list.map(function(o){ return e.wap("item", {v:"1"}); })"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "item");
        assert!(out[0].repeats);
    }

    #[test]
    fn variable_holding_map_call_repeats() {
        let code = r#"var items = list.map(function(o){ return e.wap("row", {}); });"#;
        let out = resolve(code, "items");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "row");
        assert!(out[0].repeats);
    }

    #[test]
    fn function_return_tracing_direct_and_chained() {
        // Direct: helper returns a wap.
        let code = r#"function build(t){ return e.wap("direct", {}); }"#;
        let out = resolve(code, "build(t)");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "direct");

        // Chained: outer returns inner(), inner returns a wap.
        let code2 = r#"
            function inner(t){ return e.wap("deep", {}); }
            function outer(t){ return inner(t); }
        "#;
        let out2 = resolve(code2, "outer(t)");
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].tag, "deep");
    }

    #[test]
    fn unknown_identifier_and_dead_ends() {
        assert!(resolve("", "unknownVar").is_empty());
        // A call to a non-function var resolves to nothing.
        assert!(resolve(r#"var x = 5;"#, "x(1)").is_empty());
        // A bare non-wap, non-call expression.
        assert!(resolve("", "1 + 2").is_empty());
        // In scope, but the initializer doesn't resolve to any children.
        assert!(resolve(r#"var x = 5;"#, "x").is_empty());
        // `.map` with a non-inline callback reference can't be inspected.
        assert!(resolve("", "list.map(someRef)").is_empty());
    }

    #[test]
    fn recursion_depth_is_bounded() {
        // Mutually recursive helpers with no wap: must terminate, return empty.
        let code = r#"
            function a(t){ return b(t); }
            function b(t){ return a(t); }
        "#;
        assert!(resolve(code, "a(t)").is_empty());
    }

    #[test]
    fn map_without_wap_resolves_empty() {
        // `.map` callback returns a non-wap value → no children.
        assert!(resolve("", r#"list.map(function(o){ return o.value; })"#).is_empty());
    }

    #[test]
    fn find_wap_calls_collects_flat() {
        let body = r#"{ var a = e.wap("one", {}); foo(); return e.wap("two", {z:"9"}); }"#;
        let out = find_wap_calls_in_body(body, &AliasMap::default());
        let tags: Vec<_> = out.iter().map(|c| c.tag.as_str()).collect();
        assert_eq!(tags, ["one", "two"]);
        assert!(out.iter().all(|c| !c.repeats && c.children.is_empty()));
    }

    #[test]
    fn smax_nested_child_resolves() {
        // A smax stanza with a nested smax child, via the WASmaxJsx alias.
        let code = "";
        let out = resolve(
            code,
            r#"o("WASmaxJsx").smax("query", {}, o("WASmaxJsx").smax("item", {id:"1"}))"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "query");
        assert_eq!(out[0].children.len(), 1);
        assert_eq!(out[0].children[0].tag, "item");
    }

    #[test]
    fn smax_repeated_child_marks_repeats() {
        let out = resolve("", r#"o("WASmaxChildren").REPEATED_CHILD(fn, list, 0, 20)"#);
        // fn isn't inspectable here (bare ident), so no template — but must not panic.
        assert!(out.is_empty());
        // With an inline smax in arg0 it resolves and marks repeats.
        let out2 = resolve(
            "",
            r#"o("WASmaxChildren").REPEATED_CHILD(o("WASmaxJsx").smax("row", {}), list, 0, 20)"#,
        );
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].tag, "row");
        assert!(out2[0].repeats);
    }
}
