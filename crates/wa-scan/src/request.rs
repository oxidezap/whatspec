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
//!
//! The resolution functions thread a wide, shared context (scope, both sources,
//! aliases, the mixin contributions, and the helper index) through a mutual
//! recursion, so the many-argument signatures are intrinsic rather than a smell.
#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrowFunctionExpression, AssignmentExpression, Expression, Function,
    ObjectPropertyKind, Program, PropertyKey, Statement, VariableDeclaration,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use wa_ir::{
    WapArgPath, WapArgSegment, WapAttrDef, WapAttrKind, WapChildNode, WapChildPresence, WapContent,
    WapContentKind,
};

use crate::alias::{AliasMap, build_alias_map, resolve_owner};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::helper_index::HelperIndex;
use crate::module::require_module_name;
use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_member, as_string_lit, callee_method,
    callee_object,
};

/// The WAWap primitive that emits an `n`-byte big-endian integer as element
/// content (`BIG_ENDIAN_CONTENT(keyId, 3)`); the 2nd argument is the byte length.
const BIG_ENDIAN_CONTENT: &str = "BIG_ENDIAN_CONTENT";

/// The leaf element content of a `wap("tag", attrs, <content>)` node — recovered
/// only when the node has no child nodes and a single, value-like argument.
///
/// Distinguishes a value payload from a child node structurally: a string literal
/// is a fixed `Const`; `BIG_ENDIAN_CONTENT(x, n)` is `n` bytes; a member value
/// reference (`e.keyPair.pubKey`, `e.signature`) is opaque `Dynamic` bytes/text.
///
/// A bare identifier is content only when it resolves to an argument path. That
/// discriminates the two things a minified identifier can be in this position: WA's
/// builders bind the payload to a local first (`var t = e.subjectElementValue;
/// smax("subject", null, t)` — `<subject>`'s whole payload), while a node variable
/// (`var n = smax("body", …); smax("description", null, n)`) is a child and roots at no
/// parameter. Ignoring identifiers outright was the safe half of that distinction and
/// dropped the payload of every request whose builder destructures first — which is
/// every builder that lives behind a mixin.
fn leaf_content(
    child_args: &[Argument],
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
) -> Option<WapContent> {
    if child_args.len() != 1 {
        return None;
    }
    let e = arg_expr(child_args.first()?)?;
    let path = relative_arg_path(e, scope, module_source, ref_off, 0).filter(|p| !p.is_empty());
    let mut content = content_of_expr(e).or_else(|| {
        path.is_some().then_some(WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        })
    })?;
    if content.arg_path.is_none() {
        content.arg_path = path;
    }
    Some(content)
}

fn content_of_expr(e: &Expression) -> Option<WapContent> {
    // Fixed string literal → const content.
    if let Some(v) = as_string_lit(e) {
        return Some(WapContent {
            kind: WapContentKind::Const,
            value: Some(v.to_string()),
            ..Default::default()
        });
    }
    // `X.BIG_ENDIAN_CONTENT(value, n)` → n bytes, written directly in the builder
    // (no `byte_length_source`).
    if let Some(call) = as_call(e)
        && callee_method(call) == Some(BIG_ENDIAN_CONTENT)
    {
        let byte_length = call
            .arguments
            .get(1)
            .and_then(arg_expr)
            .and_then(as_int)
            .and_then(|n| u32::try_from(n).ok());
        return Some(WapContent {
            kind: WapContentKind::Bytes,
            byte_length,
            ..Default::default()
        });
    }
    // A value reference (`e.signature`, `e.keyPair.pubKey`) → opaque content. Its
    // byte length, if any, is filled later by the content-length cross-reference.
    if e.as_member_expression().is_some() {
        return Some(WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        });
    }
    None
}

/// Max function-boundary crossings while tracing returns/templates. Bounds the
/// `resolve_child_node` ↔ `resolve_function_return` recursion so a (pathological)
/// mutually-recursive helper pair can't loop forever; real builders nest only a
/// few templates deep.
const MAX_FN_DEPTH: u32 = 8;

/// Wildcard tag a mixin uses when it contributes attrs/children to *whatever*
/// stanza it's merged into (`smax("smax$any", {…})`): on merge the attrs/children
/// are applied to the destination node regardless of its tag.
const WILDCARD_TAG: &str = "smax$any";

/// Cross-module mixin contributions: mixin module name → the stanza tree it folds
/// into a destination via `mergeStanzas`/`merge…Mixin`/`optionalMerge`. Built once
/// (topologically) by [`crate::mixin_index`]; passed to [`resolve_child_node`] so a
/// `merge…Mixin(dst, …)` recovers not just `dst` but the attrs/children the mixin
/// adds to it (e.g. newsletter `messages{after, before, count}`). `None` makes
/// resolution purely structural — identical to the pre-Phase-3 behavior.
pub(crate) type MixinContributions = BTreeMap<String, Vec<WapChildNode>>;

/// One initializer of a tracked variable, as byte spans into the module source.
#[derive(Clone)]
struct VarInit {
    init_start: usize,
    init_end: usize,
    /// `{...}` body span if the initializer (or declaration) is a function.
    fn_body: Option<(usize, usize)>,
    /// The enclosing function's body span for an initializer that lives *inside* a
    /// function — a `var x = init` or a reassignment `x = init`. `None` for a
    /// module-scope declaration (hoisted, cross-function-visible) and for
    /// `function`-declaration helpers (resolved via [`Self::fn_body`], not this filter).
    /// A function-local initializer applies only to references inside its owning
    /// function, so [`resolve_child_node`] won't let a `<foo>` built for `x` in one
    /// function leak into an unrelated function's same-named `x`.
    owner_fn: Option<(usize, usize)>,
}

/// Variable/function name → all initializers seen (offset-based, lifetime-free).
#[derive(Default)]
pub(crate) struct VarScope {
    vars: HashMap<String, Vec<VarInit>>,
    /// Every function as `(body_start, body_end, parameter_names)` — all of them, not
    /// only the ones shaped like a builder.
    ///
    /// A smax builder/template takes exactly one argument object, so a lone parameter
    /// *is* the argument root: every `var x = <param>.<key>` inside the body names a
    /// path into it. Recorded here rather than derived from the body, because the
    /// parameter list lives in the function header — outside the body span the resolver
    /// re-parses.
    ///
    /// The zero- and many-parameter functions are recorded too, even though they have no
    /// argument root, because their spans decide which declarations are lexically in
    /// scope: a nested helper's locals sit inside its parent's byte range without being
    /// in its scope, and a span list that skipped those functions could not tell the two
    /// apart.
    fn_params: Vec<(usize, usize, Vec<String>)>,
}

impl VarScope {
    fn push(&mut self, name: &str, init: VarInit) {
        self.vars.entry(name.to_string()).or_default().push(init);
    }

    /// The innermost function whose body contains `off`, with its parameter names.
    ///
    /// The innermost wins: a template nested inside a builder shadows the builder's own
    /// parameter, exactly as JS scoping does with the minifier's reused single letters.
    fn innermost_fn(&self, off: usize) -> Option<(usize, usize, &Vec<String>)> {
        self.fn_params
            .iter()
            .filter(|(s, e, _)| *s <= off && off <= *e)
            .min_by_key(|(s, e, _)| e.saturating_sub(*s))
            .map(|(s, e, params)| (*s, *e, params))
    }

    /// The argument-object parameter of the innermost function containing `off` — the
    /// root identifier a member chain must start at for it to be an argument path.
    /// `None` outside every tracked function, when the context is unknown, or when the
    /// enclosing function does not take exactly one parameter: a marker template
    /// (`function u(){ return smax("locked", null) }`) reads no arguments at all, and a
    /// multi-parameter function has no single argument object to address.
    fn arg_root_at(&self, off: usize) -> Option<(usize, usize, &str)> {
        let (s, e, params) = self.innermost_fn(off)?;
        match params.as_slice() {
            [only] => Some((s, e, only.as_str())),
            _ => None,
        }
    }

    /// Whether an initializer at `init_off` is written in the SAME function as `off`,
    /// rather than merely inside its byte range. A nested helper's body lies within its
    /// parent's span, so a range test alone lets `function h(e){ var x = e.inner }` count
    /// as an initializer of the parent's own `x` — which, under the ambiguity rule,
    /// silently drops the parent's valid path instead of merely picking the wrong one.
    fn same_fn(&self, off: usize, init_off: usize) -> bool {
        let span = |o| self.innermost_fn(o).map(|(s, e, _)| (s, e));
        span(off) == span(init_off)
    }
}

/// Build a [`VarScope`] from a parsed program: every `var/let/const x = init` and
/// every `function name() {...}` declaration, at any nesting.
pub(crate) fn build_var_scope(program: &Program) -> VarScope {
    let mut b = ScopeBuilder {
        scope: VarScope::default(),
        fn_stack: Vec::new(),
    };
    b.visit_program(program);
    b.scope
}

struct ScopeBuilder {
    scope: VarScope,
    /// Spans of the function bodies currently being walked (outermost → innermost).
    /// The innermost is the lexical owner of any reassignment recorded here, so a
    /// `x = init` is tagged with the function it lives in and can't leak to a
    /// same-named `x` in an unrelated function.
    fn_stack: Vec<(usize, usize)>,
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
                        owner_fn: None,
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
                    owner_fn: None,
                },
            );
        }
        walk::walk_statement(self, stmt);
    }

    /// Track the function whose body we are inside so [`Self::visit_assignment_expression`]
    /// can tag each reassignment with its lexical owner. Covers function declarations
    /// and function expressions; arrows are handled by the sibling override below.
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let pushed = fn_body_span(func);
        if let Some(span) = pushed {
            self.fn_stack.push(span);
            // The parameter list lives in the header, outside the body span the
            // resolver later re-parses in isolation, so it must be captured here.
            self.scope
                .fn_params
                .push((span.0, span.1, param_names(&func.params)));
        }
        walk::walk_function(self, func, flags);
        if pushed.is_some() {
            self.fn_stack.pop();
        }
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let span = (arrow.body.span.start as usize, arrow.body.span.end as usize);
        self.fn_stack.push(span);
        // An arrow is the same argument-object shape as the `function` form above and
        // gets the same treatment, so the two spellings cannot diverge. Today's bundle is
        // down-levelled to ES5 and contains no arrow inside any `WASmax*` module, so this
        // recovers nothing yet; recording it is what stops a build that stops
        // down-levelling from dropping paths silently, with the loss visible only as a
        // fall in the floor-guarded counts after the fact.
        self.scope
            .fn_params
            .push((span.0, span.1, param_names(&arrow.params)));
        walk::walk_arrow_function_expression(self, arrow);
        self.fn_stack.pop();
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        // A later reassignment `x = init` is also an initializer of `x` — WA builds some
        // children this way (`var r=null; cond&&(r=wap("list",…))`), and a declaration-only
        // scope would resolve `x` to just its `null` seed and drop the real child. Record
        // plain-identifier assignments too; child resolution already unions every recorded
        // init and keeps the first non-empty (member-expression targets stay excluded).
        if let Some(name) = wa_oxc::assignment_target_name(&a.left) {
            let fn_body = match &a.right {
                Expression::FunctionExpression(f) => fn_body_span(f),
                _ => None,
            };
            let span = a.right.span();
            self.scope.push(
                name,
                VarInit {
                    init_start: span.start as usize,
                    init_end: span.end as usize,
                    fn_body,
                    owner_fn: self.fn_stack.last().copied(),
                },
            );
        }
        walk::walk_assignment_expression(self, a);
    }
}

/// A function's parameter names, in order — the frame's received values.
///
/// Exactly one of them is the structural definition of "has an argument object"
/// ([`VarScope::arg_root_at`]), and it is what keeps this honest across the two builder
/// families in the IQ domain. Every `WASmaxOut*Request` builder takes one options
/// object, so a path into it is a complete address. The legacy `WAWeb*Job` builders take
/// positional parameters (`function(e, t)`); a path there would name a key without
/// naming which parameter it hangs off, which reads like an address and is not one.
/// Those requests get no path and are counted instead.
///
/// A rest parameter yields nothing at all: the arity is open, so no position is a fixed
/// argument object. A destructuring pattern is skipped for the same reason — it names no
/// single binding the resolver can root a chain at.
fn param_names(params: &oxc_ast::ast::FormalParameters) -> Vec<String> {
    if params.rest.is_some() {
        return Vec::new();
    }
    // Every formal must be a plain binding, or the list is abandoned entirely. Silently
    // skipping a destructured one changes the apparent ARITY — `function f(e, {x})`
    // would read as a single-argument builder and publish `e`'s keys as though they
    // addressed the only options object.
    let mut names = Vec::with_capacity(params.items.len());
    for p in &params.items {
        match p.pattern.get_identifier_name() {
            Some(n) => names.push(n.to_string()),
            None => return Vec::new(),
        }
    }
    names
}

fn fn_body_span(f: &Function) -> Option<(usize, usize)> {
    f.body
        .as_ref()
        .map(|b| (b.span.start as usize, b.span.end as usize))
}

// ─── Argument paths (the builder side of the contract) ───────────────────────────
//
// Every value a request carries is read off the single argument object WA's builder
// takes. The path is recovered from two structural facts and nothing else: a builder
// or template function's FIRST parameter is that argument object, and a `var x =
// <param>.<key>` inside its body binds `x` to `<key>`. Names are never pattern-matched
// — `…Args`, `has…` and `any…` are WA conventions that make the IR readable, not
// evidence about where a value goes.
//
// Composition is by prefixing rather than by threading a context down the recursion:
// each function body resolves its paths relative to its OWN argument root, and the
// call site that supplies that root (a `REPEATED_CHILD` list, an `OPTIONAL_CHILD`
// argument object, a `merge…Mixin` argument) prefixes the subtree it just resolved.
// A nested combinator therefore composes automatically, and no resolution function
// needs to know how deep it sits.

/// Max identifier hops while chasing `var a = b, b = e.key` aliases. Bounds the
/// self-recursion in [`relative_arg_path`] so a cyclic reassignment can't loop.
const MAX_ALIAS_DEPTH: u32 = 8;

/// Prepend `prefix` to every argument path in `nodes` (and their attrs/content),
/// in place. This is how a template's self-relative paths become absolute: the
/// caller knows which argument object it handed the template, the template does not.
fn prefix_arg_paths(nodes: &mut [WapChildNode], prefix: &[WapArgSegment]) {
    if prefix.is_empty() {
        return;
    }
    for n in nodes {
        prefix_one(&mut n.arg_path, prefix);
        for a in &mut n.attrs {
            prefix_one(&mut a.arg_path, prefix);
        }
        if let Some(c) = n.content.as_mut() {
            prefix_one(&mut c.arg_path, prefix);
        }
        for g in &mut n.variant_groups {
            for v in &mut g.variants {
                for a in &mut v.attrs {
                    prefix_one(&mut a.arg_path, prefix);
                }
                prefix_arg_paths(&mut v.children, prefix);
            }
        }
        prefix_arg_paths(&mut n.children, prefix);
    }
}

/// The prefix a helper call supplies for the subtree it returns: the argument path of
/// its first argument.
///
/// The empty path is a RESULT, not a failure. `helper(e)` hands over the caller's whole
/// argument object, so the callee's frame IS the caller's and the right prefix is
/// nothing — prefixing with it is a no-op and the paths are already absolute. `None` is
/// the different answer: the argument is absent or cannot be addressed at all
/// (`helper({jid: e.userJid})`), so the subtree's paths cannot be made absolute. What a
/// caller does with `None` differs by kind; see the two call sites.
fn helper_prefix(
    call: &oxc_ast::ast::CallExpression,
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
) -> Option<WapArgPath> {
    let e = call.arguments.first().and_then(arg_expr)?;
    relative_arg_path(e, scope, module_source, ref_off, 0)
}

/// Enforce the argument-object boundary at a request root: a builder that does not take
/// exactly one options object publishes NO argument paths.
///
/// Paths resolved directly in such a frame are already absent — there is no root to
/// resolve against. What this catches is the ones that arrive from elsewhere: a subtree
/// inlined from a cross-module helper or a `.map()` mapper carries paths relative to
/// ITS OWN parameter, and a two-parameter builder like
/// `function f(e, t){ … wap("sync", null, e.map(g)) }` cannot name what it passed, so
/// those paths would surface as though they addressed the request's arguments. The
/// legacy `WAWeb*Job` family is exactly this shape.
///
/// Applied at the root rather than inside the resolver because only the root knows it is
/// a request: the same "cannot name it" state inside a mixin's `merge(dst, args)` is not
/// a failure at all — [`apply_contribution`] prefixes that contribution at the merge site.
pub(crate) fn enforce_argument_boundary(
    children: &mut [WapChildNode],
    scope: &VarScope,
    builder_off: usize,
) {
    if scope.arg_root_at(builder_off).is_none() {
        clear_arg_paths(children);
    }
}

/// Drop every argument path in a subtree. Used where a subtree's paths are relative to a
/// frame this call site cannot name: a relative path published as an absolute one is a
/// wrong address, which is worse than none — an absent path is counted.
pub(crate) fn clear_arg_paths(nodes: &mut [WapChildNode]) {
    for n in nodes {
        n.arg_path = None;
        for a in &mut n.attrs {
            a.arg_path = None;
        }
        if let Some(c) = n.content.as_mut() {
            c.arg_path = None;
        }
        for g in &mut n.variant_groups {
            for v in &mut g.variants {
                for a in &mut v.attrs {
                    a.arg_path = None;
                }
                clear_arg_paths(&mut v.children);
            }
        }
        clear_arg_paths(&mut n.children);
    }
}

fn prefix_one(path: &mut Option<WapArgPath>, prefix: &[WapArgSegment]) {
    if let Some(p) = path.as_mut() {
        let mut full = prefix.to_vec();
        full.append(p);
        *p = full;
    }
}

/// The argument path an expression reads, relative to the argument root of the
/// function `ref_off` sits in. `Some(vec![])` means "the argument object itself"
/// (a bare reference to the parameter). `None` means not structurally recoverable —
/// the caller counts it rather than inventing one.
fn relative_arg_path(
    e: &Expression,
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
    depth: u32,
) -> Option<WapArgPath> {
    if depth > MAX_ALIAS_DEPTH {
        return None;
    }
    let (fn_start, _, root) = scope.arg_root_at(ref_off?)?;

    if let Expression::ParenthesizedExpression(p) = e {
        return relative_arg_path(&p.expression, scope, module_source, ref_off, depth);
    }

    // `<param>` itself → the whole argument object.
    if let Some(name) = as_identifier(e) {
        if name == root {
            return Some(Vec::new());
        }
        // A local alias: `var a = t.participantArgs`. Only initializers written INSIDE
        // the enclosing function count. The module scope is flat and name-keyed, and the
        // minifier reuses `a`/`i`/`t` in every sibling builder of the same module, so
        // without the lexical bound one function's `i = t.descriptionArgs` and another's
        // `i = optionalMerge(…)` are the same entry — and the first one that happens to
        // resolve wins, pointing a child at a stranger's argument.
        let inits = scope.vars.get(name)?;
        let mut found: Option<WapArgPath> = None;
        for init in inits {
            if !scope.same_fn(fn_start, init.init_start) {
                continue;
            }
            if let Some((s, en)) = init.owner_fn
                && !matches!(ref_off, Some(o) if s <= o && o < en)
            {
                continue;
            }
            let slice = &module_source[init.init_start..init.init_end];
            let alloc = Allocator::default();
            let parsed = wa_oxc::parse_cjs(&alloc, slice);
            let Some(expr) = first_expression(&parsed.program) else {
                continue;
            };
            let Some(p) = relative_arg_path(expr, scope, module_source, ref_off, depth + 1) else {
                continue;
            };
            // A name assigned twice from DIFFERENT arguments (`var a = e.old; a =
            // e.current;`) has no single answer here: `ref_off` is the enclosing
            // function, not the use site, so which assignment reaches the read is not
            // computable from what this holds. Taking the first would publish an address
            // that is right about half the time, and a consumer following it writes into
            // the wrong argument with nothing to warn it. Agreeing initializers (the same
            // path recorded twice, which the flat scope produces routinely) are not
            // ambiguous.
            match &found {
                Some(prev) if *prev != p => return None,
                Some(_) => {}
                None => found = Some(p),
            }
        }
        return found;
    }

    // `<param>.a.b` → ["a", "b"]. Computed members (`x[i]`) are not a static key and
    // stop the walk.
    if e.as_member_expression().is_some() {
        let mut keys = Vec::new();
        let mut cur = e;
        while let Some(m) = cur.as_member_expression() {
            let prop = m.static_property_name()?;
            keys.push(prop.to_string());
            cur = m.object();
        }
        keys.reverse();
        // The BASE is resolved by a restricted walk that refuses calls, and that
        // restriction is the whole point. `var t = attrFromReference(attrStanzaId, e,
        // ["id"]); … STANZA_ID(t.value)` reads a value out of the stanza being ACKED, not
        // out of the builder's options object — but the general walk descends into a
        // call's arguments, finds the bare parameter there and reports the empty path,
        // which then absorbs `.value` and publishes `value` as an address. A call's
        // result is a computed value; only the parameter itself, or a chain rooted at it,
        // can be the object a key is read off.
        let base = base_arg_path(cur, scope, module_source, ref_off, depth + 1)?;
        let mut out = base;
        out.extend(
            keys.into_iter()
                .map(|key| WapArgSegment { key, list: false }),
        );
        return Some(out);
    }

    // A value coercion — `WAWap.JID(t)`, `OPTIONAL(WAWap.JID, n)`, `CUSTOM_STRING(t)`.
    // A coercion-function reference (`o("WAWap").JID`) is rooted at a `require` call, not
    // at the parameter, so it never resolves and cannot be mistaken for the value.
    //
    // Exactly one argument may resolve. A call that reads two — `combine(e.left,
    // e.right)` — has no single source, and naming the first would describe a value the
    // builder does not produce from it alone: a consumer supplying only that path gets a
    // different stanza. Same rule as the conditional below, for the same reason.
    if let Some(call) = as_call(e) {
        let mut found: Option<WapArgPath> = None;
        for a in &call.arguments {
            let Some(ae) = arg_expr(a) else { continue };
            let Some(p) = relative_arg_path(ae, scope, module_source, ref_off, depth + 1) else {
                continue;
            };
            match &found {
                Some(prev) if *prev != p => return None,
                Some(_) => {}
                None => found = Some(p),
            }
        }
        return found;
    }

    // `cond ? a : b`. Both arms reading the SAME argument is one address. Divergent arms
    // are two, and one path cannot describe two sources.
    //
    // A one-sided result is only safe when the other arm is not a source at all — the
    // `cond ? CUSTOM_STRING(e.value) : DROP_ATTR` shape, where the alternate is a module
    // constant. An arm that MENTIONS the argument root but failed to resolve
    // (`flag ? e.primary : e.values[i]`, where computed access has no static key) is a
    // real alternative the resolver merely could not read, and publishing the arm that
    // did read points a consumer at a source the builder may not use.
    if let Expression::ConditionalExpression(c) = e {
        let arm = |x| relative_arg_path(x, scope, module_source, ref_off, depth + 1);
        let (a, b) = (arm(&c.consequent), arm(&c.alternate));
        return match (a, b) {
            (Some(x), Some(y)) if x == y => Some(x),
            (Some(x), None) if !mentions(&c.alternate, root) => Some(x),
            (None, Some(y)) if !mentions(&c.consequent, root) => Some(y),
            _ => None,
        };
    }

    None
}

/// The argument path of the OBJECT a member chain is read off: the enclosing frame's
/// parameter, or an alias that itself resolves to one.
///
/// Deliberately narrower than [`relative_arg_path`] — no calls, no conditionals. Those
/// produce a computed value, and a key read off a computed value is not an address into
/// the argument object however the value was derived. See the call site for the shape
/// that made this necessary.
fn base_arg_path(
    e: &Expression,
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
    depth: u32,
) -> Option<WapArgPath> {
    if depth > MAX_ALIAS_DEPTH {
        return None;
    }
    if let Expression::ParenthesizedExpression(p) = e {
        return base_arg_path(&p.expression, scope, module_source, ref_off, depth);
    }
    let (fn_start, _, root) = scope.arg_root_at(ref_off?)?;
    if let Some(name) = as_identifier(e) {
        if name == root {
            return Some(Vec::new());
        }
        let mut found: Option<WapArgPath> = None;
        for init in scope.vars.get(name)? {
            if !scope.same_fn(fn_start, init.init_start) {
                continue;
            }
            if let Some((s, en)) = init.owner_fn
                && !matches!(ref_off, Some(o) if s <= o && o < en)
            {
                continue;
            }
            let slice = &module_source[init.init_start..init.init_end];
            let alloc = Allocator::default();
            let parsed = wa_oxc::parse_cjs(&alloc, slice);
            let Some(expr) = first_expression(&parsed.program) else {
                continue;
            };
            let Some(p) = base_arg_path(expr, scope, module_source, ref_off, depth + 1) else {
                continue;
            };
            // Same disagreement rule as the general walk: two different sources for one
            // name is no address at all.
            match &found {
                Some(prev) if *prev != p => return None,
                Some(_) => {}
                None => found = Some(p),
            }
        }
        return found;
    }
    if e.as_member_expression().is_some() {
        return relative_arg_path(e, scope, module_source, ref_off, depth);
    }
    None
}

/// Rebase a template's or mapper's subtree onto the caller's frame, and return the path
/// the caller handed it.
///
/// `arg` is the expression the combinator passed (a `REPEATED_CHILD` list, an
/// `OPTIONAL_CHILD` argument object, a `.map()` receiver); `list` marks that path's last
/// segment as the one a consumer indexes.
///
/// The three outcomes match the cross-module helper's, for the same reason — the callee
/// resolved its paths against its own parameter and only the call site knows what that
/// was:
///
/// - the argument names a path → prefix, and that path is the node's own;
/// - it does not, and the caller HAS an argument object → the subtree's paths are
///   relative to something this frame cannot name, so they are cleared. Left alone they
///   read as top-level addresses into the request's arguments, which is what published
///   `collection`/`version` on a mapped `<collection>` as though a consumer should write
///   them at the root;
/// - it does not, and the caller has no argument object → a mixin's `merge(dst, args)`
///   frame, where nothing can be said. [`apply_contribution`] prefixes the whole
///   contribution at the merge site that knows.
fn rebase_template(
    nodes: &mut [WapChildNode],
    arg: Option<&Expression>,
    list: bool,
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
) -> Option<WapArgPath> {
    let path = arg
        .and_then(|e| relative_arg_path(e, scope, module_source, ref_off, 0))
        .filter(|p| !p.is_empty())
        .map(|mut p| {
            if list && let Some(last) = p.last_mut() {
                last.list = true;
            }
            p
        });
    match path.as_deref() {
        Some(prefix) => prefix_arg_paths(nodes, prefix),
        None if ref_off.and_then(|o| scope.arg_root_at(o)).is_some() => clear_arg_paths(nodes),
        None => {}
    }
    path
}

/// Whether an expression references `root` anywhere — the identifier that names the
/// enclosing frame's argument object.
///
/// Used to tell "this arm reads no argument" from "this arm reads one the resolver could
/// not spell out". Textual over the expression's own source rather than an AST walk,
/// because the callers hold a re-parsed slice whose spans do not index the module.
fn mentions(e: &Expression, root: &str) -> bool {
    struct Finder<'a> {
        root: &'a str,
        found: bool,
    }
    impl<'a> Visit<'a> for Finder<'_> {
        fn visit_identifier_reference(&mut self, id: &oxc_ast::ast::IdentifierReference<'a>) {
            self.found = self.found || id.name == self.root;
        }
    }
    let mut f = Finder { root, found: false };
    f.visit_expression(e);
    f.found
}

/// Fill in `arg_path` on each attribute of a node whose attrs came from `attrs_node`.
///
/// A `Const` attribute is skipped: the builder writes the literal itself, so there is
/// no argument to point at, and an absent path there means "nothing to supply" rather
/// than "we failed".
pub(crate) fn is_optional_literal(value: &Expression, aliases: &AliasMap) -> bool {
    as_call(value).is_some_and(|call| {
        callee_method(call) == Some("OPTIONAL_LITERAL")
            && callee_object(call).and_then(|o| resolve_owner(o, aliases)) == Some("WASmaxAttrs")
    })
}

pub(crate) fn annotate_attr_arg_paths(
    attrs: &mut [WapAttrDef],
    attrs_node: &Expression,
    aliases: &AliasMap,
    scope: &VarScope,
    module_source: &str,
    ref_off: Option<usize>,
) {
    let Expression::ObjectExpression(obj) = attrs_node else {
        return;
    };
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let PropertyKey::StaticIdentifier(key) = &p.key else {
            continue;
        };
        let Some(attr) = attrs.iter_mut().find(|a| a.name == key.name.as_str()) else {
            continue;
        };
        if attr.kind == WapAttrKind::Const {
            continue;
        }
        // `WASmaxAttrs.OPTIONAL_LITERAL("true", e.hasDelete)` writes a FIXED wire value
        // and takes a boolean deciding whether to write it at all. The generic call walk
        // finds the boolean and would report it as the attribute's value address — so a
        // consumer reads "put this attribute's value at `hasDescriptionDeleteTrue`" and
        // supplies the wire string, when what the builder wants there is a flag. That is
        // the attribute analogue of a presence marker, and `arg_path` has no way to say
        // so; naming nothing is the honest answer until it does.
        if is_optional_literal(&p.value, aliases) {
            continue;
        }
        // An empty path (a bare reference to the argument object) is not an
        // attribute source; only a keyed read is.
        if let Some(path) = relative_arg_path(&p.value, scope, module_source, ref_off, 0)
            && !path.is_empty()
        {
            attr.arg_path = Some(path);
        }
    }
}

/// Resolve a `wap()` child-argument expression into zero or more child nodes.
///
/// - `node_source`: the source `node` was parsed from (for span-relative ops).
/// - `module_source`: the module source the scope offsets index into.
/// - `ref_off`: the module offset of the *original* reference this resolution serves —
///   i.e. the function context it belongs to. Threaded unchanged through recursion
///   (including re-parsed slices, where the node's own offset is unknowable) so a
///   function-scoped initializer (`owner_fn`) is only applied to references that
///   actually live inside its owning function. `None` when the context is unknown
///   (unit-test callers that resolve a standalone expression string); function-scoped
///   initializers are then conservatively skipped. Descending into a *different*
///   function's body (a helper/template return) resets it to that body's start.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_child_node(
    node: &Expression,
    node_source: &str,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
    ref_off: Option<usize>,
) -> Vec<WapChildNode> {
    // Unwrap `(…)` — a transparent wrapper (e.g. a re-parsed `return (expr)`).
    if let Expression::ParenthesizedExpression(p) = node {
        return resolve_child_node(
            &p.expression,
            node_source,
            scope,
            module_source,
            aliases,
            contributions,
            helpers,
            depth,
            ref_off,
        );
    }

    // Case 0: a conditional child `cond ? A : B` (e.g. an optional child built as
    // `a.length > 0 ? wap("list", …) : null`, as the aggregate receipt/ack builder does).
    // Resolve BOTH branches and union their children: the common `cond ? node : null`
    // yields just `node` (the `null` side resolves to nothing), while a genuinely
    // divergent `cond ? wap("a", …) : wap("b", …)` catalogs both possible children
    // rather than silently dropping one — the schema should reflect every shape a child
    // can take. Identical children (e.g. `cond ? x : x`) are collapsed so the union
    // doesn't duplicate.
    if let Expression::ConditionalExpression(cond) = node {
        let resolve = |branch| {
            resolve_child_node(
                branch,
                node_source,
                scope,
                module_source,
                aliases,
                contributions,
                helpers,
                depth,
                ref_off,
            )
        };
        // Presence is deliberately NOT weakened here. A `cond ? wap("x", …) : null` child
        // can indeed be omitted, but by a control-flow guard rather than by one of the
        // `WASmaxChildren` combinators `presence` is defined over — there is no argument
        // object behind it, so calling it `Optional` would answer "which combinator built
        // this" with something that is not one. The seam shows in the counters: 17 such
        // children would be reported as combinator children missing an argument address
        // they can never have. Extracting the guard is a different question from shape.
        let mut out = resolve(&cond.consequent);
        for child in resolve(&cond.alternate) {
            if !out.contains(&child) {
                out.push(child);
            }
        }
        return out;
    }

    // Case 1: direct wap()/smax() call.
    if let Some(call) = as_call(node)
        && let Some(wap) = parse_wap_call(call, aliases)
    {
        let mut attrs = wap
            .attrs_node
            .map(|n| extract_attrs_from_obj(n, node_source, aliases))
            .unwrap_or_default();
        if let Some(n) = wap.attrs_node {
            annotate_attr_arg_paths(&mut attrs, n, aliases, scope, module_source, ref_off);
        }
        let mut children = Vec::new();
        for child_arg in wap.child_args {
            if let Some(ce) = arg_expr(child_arg) {
                children.extend(resolve_child_node(
                    ce,
                    node_source,
                    scope,
                    module_source,
                    aliases,
                    contributions,
                    helpers,
                    depth,
                    ref_off,
                ));
            }
        }
        let content = if children.is_empty() {
            leaf_content(wap.child_args, scope, module_source, ref_off)
        } else {
            None
        };
        return vec![WapChildNode {
            tag: wap.tag.to_string(),
            attrs,
            children,
            content,
            repeats: false,
            variant_groups: Vec::new(),
            ..Default::default()
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
                    contributions,
                    helpers,
                    depth,
                    ref_off,
                ));
            }
        }
        return out;
    }

    // Case 2: variable reference — try every initializer (re-parsing its slice).
    if let Some(name) = as_identifier(node) {
        if let Some(inits) = scope.vars.get(name) {
            for init in inits {
                // A function-scoped initializer (`owner_fn`, i.e. a declaration or
                // reassignment inside a function) only initializes the `name` referenced
                // from within its owning function — skip it for a reference that lives
                // elsewhere (or whose context is unknown), so a `<foo>` built in one
                // function can't leak into an unrelated function's same-named variable.
                if let Some((s, e)) = init.owner_fn
                    && !matches!(ref_off, Some(o) if s <= o && o < e)
                {
                    continue;
                }
                let slice = &module_source[init.init_start..init.init_end];
                let alloc = Allocator::default();
                let ret = wa_oxc::parse_cjs(&alloc, slice);
                if let Some(expr) = first_expression(&ret.program) {
                    if let Some(m) = resolve_map_call(
                        expr,
                        slice,
                        scope,
                        module_source,
                        aliases,
                        contributions,
                        helpers,
                        depth,
                        ref_off,
                    ) {
                        return m;
                    }
                    let r = resolve_child_node(
                        expr,
                        slice,
                        scope,
                        module_source,
                        aliases,
                        contributions,
                        helpers,
                        depth,
                        ref_off,
                    );
                    if !r.is_empty() {
                        return r;
                    }
                }
            }
        }
        return Vec::new();
    }

    // Case 3: a `.map(fn)` producing an array of children.
    if let Some(m) = resolve_map_call(
        node,
        node_source,
        scope,
        module_source,
        aliases,
        contributions,
        helpers,
        depth,
        ref_off,
    ) {
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
    // any argument, so we resolve them all. When `contributions` is provided, a
    // `merge…Mixin(dst, …)` / `optionalMerge(mergeFn, dst, …)` also folds the mixin's
    // own attrs/children into the resolved `dst` (Phase 3 — nested sub-stanza attrs).
    if let Some(call) = as_call(node)
        && let Some(method) = callee_method(call)
    {
        let owner = callee_object(call).and_then(|o| resolve_owner(o, aliases));
        let repeated = owner == Some("WASmaxChildren") && method == "REPEATED_CHILD";
        let optional = owner == Some("WASmaxChildren") && method == "OPTIONAL_CHILD";
        let presence_flag = owner == Some("WASmaxChildren") && method == "HAS_OPTIONAL_CHILD";
        if (repeated || optional || presence_flag)
            && let Some(first) = call.arguments.first().and_then(arg_expr)
        {
            let mut r = resolve_template_arg(
                first,
                node_source,
                scope,
                module_source,
                aliases,
                contributions,
                helpers,
                depth,
                ref_off,
            );
            // The 2nd argument is what the combinator feeds the template: the list for
            // REPEATED_CHILD, the argument object for OPTIONAL_CHILD, the boolean for
            // HAS_OPTIONAL_CHILD. It is therefore both this node's own argument path
            // and the prefix that turns the template's self-relative paths absolute —
            // the template resolved above knows nothing about where it was called from.
            //
            // `[]` marks the ONE segment a consumer must index: REPEATED_CHILD calls the
            // template once per element, so everything the template reads lives on an
            // element. OPTIONAL_CHILD hands the object over whole and gets no marker —
            // the same suffix in the wrong place writes the value where the vendor
            // builder never reads it.
            let node_path = rebase_template(
                &mut r,
                call.arguments.get(1).and_then(arg_expr),
                repeated,
                scope,
                module_source,
                ref_off,
            );
            if repeated {
                let (min, max) = repeat_bounds(call);
                for c in &mut r {
                    c.repeats = true;
                    c.repeat_min = min;
                    c.repeat_max = max;
                    c.arg_path = node_path.clone();
                }
            } else {
                for c in &mut r {
                    c.presence = if optional {
                        WapChildPresence::Optional
                    } else {
                        WapChildPresence::PresenceFlag
                    };
                    c.arg_path = node_path.clone();
                }
            }
            if !r.is_empty() {
                return r;
            }
        }
        // `merge…Mixin` and the disjunction `merge…MixinGroup` both wrap a stanza.
        let is_merge = method.starts_with("merge") && method.contains("Mixin");
        // A MixinGroup's selector method drops the `Mixin` suffix
        // (`mergeQueryNewsletterParams`); recognize it by a `WASmaxOut*` owner so its
        // contribution is still folded in.
        let merge_owner = callee_object(call).and_then(require_module_name);
        let is_cross_merge = method.starts_with("merge")
            && merge_owner
                .as_deref()
                .is_some_and(|m| m.starts_with("WASmaxOut"));
        let is_optional_merge = owner == Some("WASmaxMixins") && method == "optionalMerge";
        // `WASmaxMixins.mergeStanzas(dst, frag)` fuses two stanzas — resolve both.
        let is_merge_stanzas = owner == Some("WASmaxMixins") && method == "mergeStanzas";
        let is_concat = method == "concat";
        if is_merge || is_cross_merge || is_optional_merge || is_merge_stanzas || is_concat {
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
                    contributions,
                    helpers,
                    depth,
                    ref_off,
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
                        contributions,
                        helpers,
                        depth,
                        ref_off,
                    ));
                }
            }
            // Phase 3: fold the called mixin's own contribution into the resolved
            // destination(s). For a `merge…(dst,…)` the mixin is the callee's owner
            // module; for `optionalMerge(o("X").merge…, dst,…)` it's the owner of the
            // 1st argument (the merge-fn reference).
            if let Some(contribs) = contributions
                && (is_merge || is_cross_merge || is_optional_merge)
            {
                let mixin = if is_optional_merge {
                    call.arguments
                        .first()
                        .and_then(arg_expr)
                        .and_then(merge_ref_owner)
                } else {
                    merge_owner
                };
                if let Some(name) = mixin
                    && let Some(contrib) = contribs.get(&name)
                {
                    // A mixin resolves its own paths against the argument object the
                    // caller hands it — the 2nd argument of `merge…(dst, args)`, the
                    // 3rd of `optionalMerge(mergeFn, dst, args)`. Prefixing here is what
                    // makes `namedSubjectOrUnnamedSubjectFallbackMixinGroupArgs`
                    // reachable from the request root; without it the mixin's paths
                    // would silently claim to start at the request's own arguments.
                    // Same three outcomes as every other frame-handing call site, via the
                    // same helper: prefix when the argument names a path, clear when this
                    // frame has an argument object but cannot name what it passed, and
                    // leave alone when it has none — the two-parameter merge frame, which
                    // a caller further out rebases.
                    let args_idx = if is_optional_merge { 2 } else { 1 };
                    let mut contrib = contrib.clone();
                    rebase_template(
                        &mut contrib,
                        call.arguments.get(args_idx).and_then(arg_expr),
                        false,
                        scope,
                        module_source,
                        ref_off,
                    );
                    apply_contribution(&mut out, &contrib, is_optional_merge);
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }

    // Case 5: `helper(args)` — trace the helper's return value.
    //
    // The helper resolves its paths against ITS OWN parameter, so they arrive relative
    // to whatever this call passed. That argument is the prefix, exactly as it is for a
    // `REPEATED_CHILD` list or a mixin's argument object: without it `helper(e.userArgs)`
    // over a helper reading `arg.jid` publishes a bare `jid`, which reads as an absolute
    // address into the request's own arguments and is not one.
    //
    // Unaddressable argument: leave the paths, do NOT clear. A local helper is resolved
    // in the same scope as its caller, and the case that matters is a mixin's
    // `merge(dst, args)` calling `build(args)` — a two-parameter frame has no argument
    // root, so nothing can be named here, and `apply_contribution` prefixes the whole
    // contribution at the merge site that does know. Clearing instead destroys 63 correct
    // paths. The cross-module branch below is the opposite case and does clear.
    if let Some(call) = as_call(node)
        && let Some(callee_name) = as_identifier(&call.callee)
        && let Some(inits) = scope.vars.get(callee_name)
    {
        for vi in inits {
            if let Some((bs, be)) = vi.fn_body {
                let mut r = resolve_function_return(
                    bs,
                    be,
                    scope,
                    module_source,
                    aliases,
                    contributions,
                    helpers,
                    depth + 1,
                );
                if !r.is_empty() {
                    if let Some(prefix) = helper_prefix(call, scope, module_source, ref_off) {
                        prefix_arg_paths(&mut r, &prefix);
                    }
                    return r;
                }
            }
        }
    }

    // Case 5b: cross-module helper `o("Module").fn(args)` — inline the wap subtree
    // the helper returns (e.g. `o("WAWebSignalUtilsApi").xmppSignedPreKey(t)` → the
    // `<skey><id/><value/><signature/></skey>` tree), read from the pre-built index.
    //
    // The index is built once per (module, fn) with no call site in view, so any path in
    // it is relative to that helper's own parameter and needs the same prefixing. When
    // this call site's argument is not itself addressable, the paths are dropped rather
    // than published as though they were absolute — and here that is right where it is
    // wrong above, because nothing downstream will ever rebase a subtree that came from
    // the index: `xmppSignedPreKey(t)` in a job generator reads a key pair the job
    // fetched, not an argument anybody passes.
    if let Some(call) = as_call(node)
        && let Some((module, func)) = require_member_call(&call.callee)
        && let Some(tree) = helpers.get(&module, &func)
    {
        let mut tree = tree.clone();
        match helper_prefix(call, scope, module_source, ref_off) {
            Some(prefix) => prefix_arg_paths(&mut tree, &prefix),
            None => clear_arg_paths(&mut tree),
        }
        return tree;
    }

    Vec::new()
}

/// The `min`/`max` of `REPEATED_CHILD(template, list, min, max)`.
///
/// Three outcomes, because two of them must not look alike:
///
/// - both literals → a closed range;
/// - a literal `min` with `1/0` as the `max` → "at least min, no ceiling". WA writes an
///   unbounded maximum as the division, so this is a bound the builder STATES;
/// - anything else → neither bound is emitted, and the site is counted.
///
/// The third case is why the maximum is not simply "literal or nothing". A computed but
/// finite maximum would otherwise serialize exactly like the stated infinity above, and
/// a consumer would read a real ceiling as its absence — the precise conflation between
/// "no constraint" and "a constraint we could not extract" this IR exists to avoid. No
/// call site in the current bundle takes that form (all 65 are literals or `1/0`), so
/// suppressing it costs nothing today and keeps the claim true if one appears.
fn repeat_bounds(call: &oxc_ast::ast::CallExpression) -> (Option<u32>, Option<u32>) {
    let lit = |i: usize| {
        call.arguments
            .get(i)
            .and_then(arg_expr)
            .and_then(as_int)
            .and_then(|n| u32::try_from(n).ok())
    };
    let max_arg = call.arguments.get(3).and_then(arg_expr);
    match (lit(2), lit(3)) {
        (Some(min), Some(max)) => (Some(min), Some(max)),
        // `1/0` (or a bare `Infinity`) is a stated bound, not a failure to read one — but
        // the minimum still has to be readable, or there is no range to state.
        (Some(min), None) if max_arg.is_some_and(is_infinity) => (Some(min), None),
        // Bounds move together. A ceiling with no floor is half a range, and it would be
        // counted as a recovered bound while the floor the builder also enforces is
        // silently absent.
        _ => (None, None),
    }
}

/// Whether an expression is JavaScript's positive infinity as a minifier writes it:
/// `1/0`, or the global `Infinity`. Structural — a variable that merely holds infinity
/// at runtime is not recognized, and is treated as an unresolved bound.
///
/// The numerator has to be *positive*: `-1/0` is negative infinity, an upper bound no
/// list length can satisfy, and reading it as "unbounded" would state the opposite of
/// what the builder enforces.
fn is_infinity(e: &Expression) -> bool {
    if let Expression::Identifier(id) = e {
        return id.name == "Infinity";
    }
    let Expression::BinaryExpression(b) = e else {
        return false;
    };
    b.operator == oxc_syntax::operator::BinaryOperator::Division
        && as_int(&b.left).is_some_and(|n| n > 0)
        && as_int(&b.right) == Some(0)
}

/// `o("Module").fn` (a member whose object is a `require` call) → `(Module, fn)`.
/// The child-position form of a cross-module helper reference.
fn require_member_call(callee: &Expression) -> Option<(String, String)> {
    let (obj, method) = as_member(callee)?;
    let module = require_module_name(obj)?;
    Some((module, method.to_string()))
}

/// The mixin module a merge-fn reference belongs to: `o("X").merge…Mixin` (a member
/// expression) or `o("X").merge…Mixin(…)` (a call) → `"X"`. Used to resolve the
/// `optionalMerge` first argument to the contributing mixin.
fn merge_ref_owner(expr: &Expression) -> Option<String> {
    if let Some(call) = as_call(expr) {
        return callee_object(call).and_then(require_module_name);
    }
    if let Some(m) = expr.as_member_expression() {
        return require_module_name(m.object());
    }
    None
}

/// Fold a mixin's contribution into the destination node(s) it's merged onto,
/// mirroring `mergeStanzas`. A contribution root tagged [`WILDCARD_TAG`] (`smax$any`)
/// applies its attrs/children/variant-groups to every destination node regardless of
/// tag; any other root merges by tag and is APPENDED when no destination matches (the
/// dst may be an external placeholder that resolves empty — e.g. a MixinGroup union's
/// `e_dst` — so the contribution must still produce the node). `optional` (set for
/// `optionalMerge`) marks the folded variant groups optional. Only ever ADDS.
fn apply_contribution(dst: &mut Vec<WapChildNode>, contrib: &[WapChildNode], optional: bool) {
    for root in contrib {
        if root.tag == WILDCARD_TAG {
            if dst.is_empty() {
                // No destination yet: keep the wildcard so a later merge can apply
                // it. It never reaches the IR — the base sub-stanza is always present
                // by the time a request resolves.
                let mut r = root.clone();
                mark_groups_optional(&mut r.variant_groups, optional);
                mark_optional(&mut r, optional);
                dst.push(r);
            } else {
                for d in dst.iter_mut() {
                    merge_node_into(d, root, optional);
                }
            }
        } else if let Some(d) = dst.iter_mut().find(|d| d.tag == root.tag) {
            merge_node_into(d, root, optional);
        } else {
            // No matching destination tag: append the node (mergeStanzas semantics).
            // `optionalMerge` can skip the whole contribution, so a tag it INTRODUCES is
            // one the request may not carry — unlike one that merges onto a destination
            // built at its own call site, which keeps that site's cardinality.
            let mut r = root.clone();
            mark_groups_optional(&mut r.variant_groups, optional);
            mark_optional(&mut r, optional);
            dst.push(r);
        }
    }
}

/// Fold `src`'s attrs (existing win), children (by tag), and variant groups into the
/// in-place destination node `d`. `optional` weakens the folded variant groups.
fn merge_node_into(d: &mut WapChildNode, src: &WapChildNode, optional: bool) {
    for a in &src.attrs {
        if !d.attrs.iter().any(|x| x.name == a.name) {
            d.attrs.push(a.clone());
        }
    }
    // A repeatable contribution (its root came from `REPEATED_CHILD`/`.map(…)`)
    // promotes a locally-singular child, mirroring `mixin_index::merge_children` so a
    // repeated child folded onto an existing tag isn't silently treated as singular.
    d.repeats = d.repeats || src.repeats;
    adopt_builder_facts(d, src);
    crate::mixin_index::merge_children(&mut d.children, &src.children);
    for g in &src.variant_groups {
        let mut g2 = g.clone();
        g2.optional = g2.optional || optional;
        d.variant_groups.push(g2);
    }
}

/// Take from a merged-in fragment the builder facts the destination doesn't have:
/// element content and repeat bounds.
///
/// Fill-if-empty rather than overwrite — the destination is the node built at the call
/// site and is the more specific description; a fragment only ever ADDS, mirroring
/// `mergeStanzas`. This is where a mixin's element value stops disappearing: the merge
/// used to union attrs and children and drop everything else, so a `<subject>` built in
/// a mixin arrived at the request as a bare tag.
///
/// **`presence` is deliberately not among them.** It has no "unset" — `Required` is
/// both a real state and the serde default — so a fill-if-empty test cannot tell a
/// destination that is genuinely unconditional from one that was never classified, and
/// would happily weaken the first. It does not need to: this runs only when a
/// destination node with that tag already exists, which means it was built at its own
/// call site, and a child some call site emits unconditionally is unconditional
/// regardless of what another site does with it. A fragment whose tag has no destination
/// is appended whole by [`apply_contribution`], keeping its own presence intact.
pub(crate) fn adopt_builder_facts(d: &mut WapChildNode, src: &WapChildNode) {
    if d.content.is_none() {
        d.content = src.content.clone();
    }
    // Bounds move together or not at all. A destination with a minimum and no maximum is
    // the contract's *explicit* unbounded range (WA's `1/0`), not a half-filled one, so
    // taking a fragment's finite ceiling would quietly cap a list its own call site left
    // open. Only a destination that states no bound at all can adopt one.
    if d.repeat_min.is_none() && d.repeat_max.is_none() {
        d.repeat_min = src.repeat_min;
        d.repeat_max = src.repeat_max;
    }
    // `arg_path` is deliberately NOT adopted. Content and bounds are wire facts about the
    // element — the merged stanza really does carry that value, really is bounded that
    // way — but a path is an address for the node's own argument object, and a node two
    // sites build together has no single one. The destination was built at its own call
    // site; taking the fragment's address would tell a consumer to hand that object over
    // whole and get the destination's locally-built half for free, which it would not.
}

/// Weaken a node the caller knows may be skipped. Only ever `Required` → `Optional`: a
/// presence marker or an already-optional child was classified at its own call site and
/// says something this does not.
fn mark_optional(node: &mut WapChildNode, optional: bool) {
    if optional && node.presence.is_required() {
        node.presence = WapChildPresence::Optional;
    }
}

fn mark_groups_optional(groups: &mut [wa_ir::WapVariantGroup], optional: bool) {
    if optional {
        for g in groups {
            g.optional = true;
        }
    }
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
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
    ref_off: Option<usize>,
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
                let r = resolve_function_return(
                    bs,
                    be,
                    scope,
                    module_source,
                    aliases,
                    contributions,
                    helpers,
                    depth + 1,
                );
                if !r.is_empty() {
                    return r;
                }
            }
        }
    }
    // Otherwise an inline stanza or other directly-resolvable expression — still in the
    // caller's function context, so pass `ref_off` through.
    resolve_child_node(
        arg,
        node_source,
        scope,
        module_source,
        aliases,
        contributions,
        helpers,
        depth,
        ref_off,
    )
}

/// `list.map(<mapper>)` → repeating child template(s). The mapper is either an
/// inline `function(o){ return e.wap(...) }` or a *reference* — a cross-module
/// `o("Module").fn` helper or a local function name — resolved via the helper index
/// / module scope (e.g. `e.map(o("WAWebSignalUtilsApi").xmppPreKey)` → repeating
/// `<key>`).
#[allow(clippy::too_many_arguments)]
fn resolve_map_call(
    node: &Expression,
    node_source: &str,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
    ref_off: Option<usize>,
) -> Option<Vec<WapChildNode>> {
    let call = as_call(node)?;
    if callee_method(call)? != "map" {
        return None;
    }
    let mapper = arg_expr(call.arguments.first()?)?;
    let mut children = match mapper {
        // Inline callback: collect the `wap()` calls in its body.
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            let body_code = &node_source[body.span.start as usize..body.span.end as usize];
            // The callback's own parameter is the element it maps, and every key it reads
            // hangs off that; `rebase_template` then prefixes the receiver.
            let element = param_names(&func.params);
            find_wap_calls_in_body(
                body_code,
                aliases,
                match element.as_slice() {
                    [only] => Some(only.as_str()),
                    _ => None,
                },
            )
        }
        // Reference mapper — a cross-module helper or a local function.
        _ => resolve_mapper_ref(
            mapper,
            scope,
            module_source,
            aliases,
            contributions,
            helpers,
            depth,
        ),
    };
    if children.is_empty() {
        return None;
    }
    // The mapper reads one ELEMENT of the receiver, so its paths are relative to that
    // element and the receiver is their prefix — the same rebasing a `REPEATED_CHILD`
    // template needs, and for the same reason. Without it a mapped `<collection>`
    // published `collection`/`version` as though a consumer wrote them at the root of the
    // request's arguments.
    let list_path = rebase_template(
        &mut children,
        callee_object(call),
        true,
        scope,
        module_source,
        ref_off,
    );
    for c in &mut children {
        c.repeats = true;
        c.arg_path = list_path.clone();
    }
    Some(children)
}

/// Resolve a `.map(<ref>)` mapper reference to the child subtree it produces per
/// element: `o("Module").fn` via the helper index, or a local function name via the
/// module scope's function body.
fn resolve_mapper_ref(
    mapper: &Expression,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
) -> Vec<WapChildNode> {
    // Cross-module `o("Module").fn`.
    if let Some((module, func)) = require_member_call(mapper)
        && let Some(tree) = helpers.get(&module, &func)
    {
        return tree.clone();
    }
    // Local function name.
    if let Some(name) = as_identifier(mapper)
        && let Some(inits) = scope.vars.get(name)
    {
        for vi in inits {
            if let Some((bs, be)) = vi.fn_body {
                let r = resolve_function_return(
                    bs,
                    be,
                    scope,
                    module_source,
                    aliases,
                    contributions,
                    helpers,
                    depth + 1,
                );
                if !r.is_empty() {
                    return r;
                }
            }
        }
    }
    Vec::new()
}

/// Resolve each top-level `return <expr>` of a function body SEPARATELY (one entry
/// per return), so a MixinGroup union's branch variants stay distinct. Applies the
/// same lexical-scope merge as [`resolve_function_return`]. Does not run the
/// no-returns fallbacks (those only matter when there are no resolvable returns).
fn resolve_function_returns_each(
    body_start: usize,
    body_end: usize,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
) -> Vec<Vec<WapChildNode>> {
    if depth > MAX_FN_DEPTH {
        return Vec::new();
    }
    let body = &module_source[body_start..body_end];
    // Lexical scope: this body's own vars (shifted to module-absolute offsets) SHADOW
    // the module scope, but the module scope still backs cross-function refs. Mirrors
    // the merge in `resolve_function_return`.
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
            // `owner_fn` was recorded relative to this sub-parse; shift it to the same
            // module-absolute frame as `ref_off` (= `body_start`) so a body-local
            // initializer's ownership check still lines up.
            if let Some((s, e)) = vi.owner_fn.as_mut() {
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
    // Argument roots follow the same shift-then-inherit rule as the vars. The body slice
    // re-parse cannot see this function's OWN parameter (it lives in the header, outside
    // the span), so the module scope's entry is the one that answers `arg_root_at` here —
    // dropping it made every path resolved through a template return come out empty.
    for (s, e, name) in &mut merged.fn_params {
        *s += body_start;
        *e += body_start;
        let _ = name;
    }
    merged.fn_params.extend(scope.fn_params.iter().cloned());
    let mut per_return = Vec::new();
    for arg_src in collect_return_arg_sources(body) {
        let alloc2 = Allocator::default();
        let owned = format!("({arg_src});");
        let r2 = wa_oxc::parse_cjs(&alloc2, &owned);
        if let Some(expr) = first_expression(&r2.program) {
            // We are now resolving references that live inside THIS function body, so the
            // reference context is the body itself — a `body`-local initializer must apply
            // (its `owner_fn` was shifted to module-absolute above), while a foreign
            // function's initializer still won't.
            let r = resolve_child_node(
                expr,
                &owned,
                &merged,
                module_source,
                aliases,
                contributions,
                helpers,
                depth,
                Some(body_start),
            );
            if !r.is_empty() {
                per_return.push(r);
            }
        }
    }
    per_return
}

/// Trace a function body for `wap()` calls, following `return helper(...)` chains.
/// Flattens every `return` into one child list (nesting preserved); for the
/// per-return form used by union detection see [`resolve_function_returns_each`].
fn resolve_function_return(
    body_start: usize,
    body_end: usize,
    scope: &VarScope,
    module_source: &str,
    aliases: &AliasMap,
    contributions: Option<&MixinContributions>,
    helpers: &HelperIndex,
    depth: u32,
) -> Vec<WapChildNode> {
    let flat: Vec<WapChildNode> = resolve_function_returns_each(
        body_start,
        body_end,
        scope,
        module_source,
        aliases,
        contributions,
        helpers,
        depth,
    )
    .into_iter()
    .flatten()
    .collect();
    if !flat.is_empty() {
        return flat;
    }
    if depth > MAX_FN_DEPTH {
        return Vec::new();
    }
    // No resolvable returns: fall back to a flat scan, then `return helper(...)` chains.
    let body = &module_source[body_start..body_end];
    let direct = find_wap_calls_in_body(body, aliases, None);
    if !direct.is_empty() {
        return direct;
    }
    for name in collect_returned_call_names(body) {
        if let Some(inits) = scope.vars.get(&name) {
            for vi in inits {
                if let Some((nbs, nbe)) = vi.fn_body {
                    let r = resolve_function_return(
                        nbs,
                        nbe,
                        scope,
                        module_source,
                        aliases,
                        contributions,
                        helpers,
                        depth + 1,
                    );
                    if !r.is_empty() {
                        return r;
                    }
                }
            }
        }
    }
    Vec::new()
}

/// Every exported function in a module that returns a non-`<iq>` `wap()` subtree,
/// as `(name, resolved subtree)` — the cross-module child helpers a request may
/// reference (`o("Module").fn(...)` / `.map(o("Module").fn)`). Built once per
/// module by [`crate::helper_index`]; `helpers` carries the index built so far so a
/// helper that calls another helper still resolves.
pub(crate) fn exported_wap_helpers(
    slice: &str,
    helpers: &HelperIndex,
) -> Vec<(String, Vec<WapChildNode>)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let scope = build_var_scope(&ret.program);
    let aliases = build_alias_map(&ret.program);
    let mut finder = ExportFnFinder {
        scope: &scope,
        out: Vec::new(),
    };
    finder.visit_program(&ret.program);

    let mut result = Vec::new();
    for (name, (bs, be)) in finder.out {
        let tree = resolve_function_return(bs, be, &scope, slice, &aliases, None, helpers, 0);
        // Keep only child helpers: non-empty and not an `<iq>` builder (those are
        // whole requests, never referenced as a child).
        if !tree.is_empty() && tree.iter().all(|n| n.tag != "iq") {
            result.push((name, tree));
        }
    }
    result
}

/// Collects `<exports>.name = fn` / `= localFnName` assignments (the exported
/// functions), resolving a name reference to its function body via `scope`.
struct ExportFnFinder<'s> {
    scope: &'s VarScope,
    out: Vec<(String, (usize, usize))>,
}

impl<'a> Visit<'a> for ExportFnFinder<'_> {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if let Some(m) = assign.left.as_member_expression()
            && matches!(m.object(), Expression::Identifier(_))
            && let Some(prop) = m.static_property_name()
        {
            let body = match &assign.right {
                Expression::FunctionExpression(func) => fn_body_span(func),
                Expression::Identifier(id) => self
                    .scope
                    .vars
                    .get(id.name.as_str())
                    .and_then(|inits| inits.iter().find_map(|vi| vi.fn_body)),
                _ => None,
            };
            if let Some(b) = body {
                self.out.push((prop.to_string(), b));
            }
        }
        walk::walk_assignment_expression(self, assign);
    }
}

/// Resolve the stanza tree a mixin module contributes when merged into a
/// destination — its exported `merge…` function's return, with cross-module
/// `merge…Mixin`/`optionalMerge` calls expanded via `contributions` (the already-
/// resolved fragments of the mixins it depends on; the caller resolves in
/// dependency order). Same-tag roots are collapsed so a MixinGroup union's variants
/// (`before`/`after`) fold into one node. Returns empty for a module with no
/// `merge…` export (e.g. a Request module). See [`crate::mixin_index`].
pub(crate) fn resolve_contribution(
    slice: &str,
    contributions: &MixinContributions,
    helpers: &HelperIndex,
) -> Vec<WapChildNode> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    let scope = build_var_scope(&ret.program);
    let aliases = build_alias_map(&ret.program);
    let Some((bs, be)) = find_merge_fn_body(&ret.program, &scope) else {
        return Vec::new();
    };

    // A MixinGroup disjunction (`if(flagA) merge…A; if(flagB) merge…B; else throw`)
    // contributes a single node carrying its branches as mutually-exclusive variants
    // — preserving the discriminator (e.g. `type:"jid"` vs `type:"invite"`) instead of
    // collapsing the branches into one over-merged node.
    if slice.contains("MixinGroupExhaustiveError") {
        let branches = resolve_function_returns_each(
            bs,
            be,
            &scope,
            slice,
            &aliases,
            Some(contributions),
            helpers,
            0,
        );
        // Each branch resolves to one node (the dst with that variant's attrs folded
        // in); the shared tag (e.g. `messages` or `smax$any`) anchors the group.
        let variants: Vec<wa_ir::WapVariant> = branches
            .iter()
            .filter_map(|b| b.first())
            .map(|n| wa_ir::WapVariant {
                attrs: n.attrs.clone(),
                children: n.children.clone(),
            })
            .filter(|v| !v.attrs.is_empty() || !v.children.is_empty())
            .collect();
        if variants.len() >= 2 {
            let tag = branches
                .iter()
                .find_map(|b| b.first())
                .map(|n| n.tag.clone())
                .unwrap_or_default();
            return vec![WapChildNode {
                tag,
                variant_groups: vec![wa_ir::WapVariantGroup {
                    optional: false,
                    variants,
                }],
                ..Default::default()
            }];
        }
        // < 2 distinct variants: fall through to the normal (collapsed) resolution.
    }

    let raw = resolve_function_return(
        bs,
        be,
        &scope,
        slice,
        &aliases,
        Some(contributions),
        helpers,
        0,
    );
    // Collapse same-tag roots so a non-union mixin's repeated returns fold into one.
    let mut merged = Vec::new();
    crate::mixin_index::merge_children(&mut merged, &raw);
    merged
}

/// Body span of a mixin module's exported `merge…` function: the `RHS` of the
/// `<exports>.merge… = fn` assignment, either an inline function or a reference to
/// a named one resolved through `scope`. First match wins.
fn find_merge_fn_body(program: &Program, scope: &VarScope) -> Option<(usize, usize)> {
    let mut f = MergeFnFinder { scope, body: None };
    f.visit_program(program);
    f.body
}

struct MergeFnFinder<'s> {
    scope: &'s VarScope,
    body: Option<(usize, usize)>,
}

impl<'a> Visit<'a> for MergeFnFinder<'_> {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if self.body.is_none()
            && let Some(m) = assign.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
            && prop.starts_with("merge")
        {
            match &assign.right {
                Expression::FunctionExpression(func) => self.body = fn_body_span(func),
                Expression::Identifier(id) => {
                    if let Some(inits) = self.scope.vars.get(id.name.as_str()) {
                        self.body = inits.iter().find_map(|vi| vi.fn_body);
                    }
                }
                _ => {}
            }
        }
        walk::walk_assignment_expression(self, assign);
    }
}

/// All `wap()`/`smax()` calls anywhere in a body string, as flat children.
///
/// The body is re-parsed in isolation, so smax aliases local to the enclosing
/// module aren't visible; we rebuild a local alias map from this body so any
/// `(X = o("WASmaxJsx"))` inside it is still resolved.
fn find_wap_calls_in_body(
    body_code: &str,
    outer: &AliasMap,
    arg_root: Option<&str>,
) -> Vec<WapChildNode> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_code);
    // Layered over the enclosing module's aliases: the callback calls `WASmaxAttrs`
    // through a name declared outside the body it is re-parsed from, so a body-only map
    // reads `A.OPTIONAL_LITERAL(…)` as an ordinary dynamic value and publishes its
    // presence flag as the attribute's address.
    let local = build_alias_map(&ret.program).over(outer);
    // A scope over this body ALONE, with the callback's parameter as its argument root.
    // That is all a mapper needs: it reads one element and nothing else, so every path it
    // states is relative to that parameter — and the caller rebases the lot onto the
    // receiver afterwards. Without the root the collector produced nodes whose keys were
    // simply absent, so a consumer could find the list and not what to put in it.
    let mut scope = build_var_scope(&ret.program);
    if let Some(root) = arg_root {
        scope
            .fn_params
            .push((0, body_code.len(), vec![root.to_string()]));
    }
    let mut c = WapCollector {
        out: Vec::new(),
        source: body_code,
        aliases: &local,
        scope: &scope,
        rooted: arg_root.is_some(),
    };
    c.visit_program(&ret.program);
    c.out
}

struct WapCollector<'s> {
    out: Vec<WapChildNode>,
    source: &'s str,
    /// The body's own aliases layered over the enclosing module's, so every pass below
    /// reads the same names — the tag, the attribute kinds and the paths.
    aliases: &'s AliasMap,
    /// The body's own scope, carrying the callback parameter as an argument root when
    /// there is one.
    scope: &'s VarScope,
    /// Whether that root exists. Without it the sweep has no reference context and every
    /// path is unrecoverable by construction, which is a different thing from failing to
    /// resolve one.
    rooted: bool,
}

impl<'a> Visit<'a> for WapCollector<'_> {
    fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
        let parsed = parse_wap_call(call, self.aliases);
        if let Some(wap) = parsed {
            let mut attrs = wap
                .attrs_node
                .map(|n| extract_attrs_from_obj(n, self.source, self.aliases))
                .unwrap_or_default();
            // Offset 0 is inside the synthetic body span, so it names the callback frame.
            let ref_off = self.rooted.then_some(0);
            if let Some(n) = wap.attrs_node {
                annotate_attr_arg_paths(
                    &mut attrs,
                    n,
                    self.aliases,
                    self.scope,
                    self.source,
                    ref_off,
                );
            }
            self.out.push(WapChildNode {
                tag: wap.tag.to_string(),
                attrs,
                children: Vec::new(),
                content: leaf_content(wap.child_args, self.scope, self.source, ref_off),
                repeats: false,
                variant_groups: Vec::new(),
                ..Default::default()
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
        // MixinGroup unions select a variant by flag: `if(t.before) return mergeA(…);
        // if(t.after) return mergeB(…); throw …`. Collect each branch's return so the
        // contribution is the UNION of the variants (merged by tag downstream); a
        // guard returning a non-stanza simply resolves to nothing.
        Statement::IfStatement(i) => {
            collect_returns_in_stmt(&i.consequent, src, out);
            if let Some(alt) = &i.alternate {
                collect_returns_in_stmt(alt, src, out);
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(arg) = &r.argument {
                let sp = arg.span();
                out.push(src[sp.start as usize..sp.end as usize].to_string());
            }
        }
        // Don't descend into functions: a `.map`/template callback's own return is
        // resolved separately and must not be hoisted here.
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
        // `expr` is re-parsed from a standalone string, so its offset can't be mapped to
        // `code`'s function scopes — pass `None` (these tests use module-scope vars).
        resolve_child_node(
            expr,
            &owned,
            &scope,
            code,
            &aliases,
            None,
            &HelperIndex::default(),
            0,
            None,
        )
    }

    /// Resolve the return value of a named builder function in `code`, the way the IQ
    /// scanner reaches a request's children — inside a function, so the argument-path
    /// machinery has a reference context and an argument root to work from. [`resolve`]
    /// deliberately has neither.
    fn resolve_builder(code: &str, fn_name: &str) -> Vec<WapChildNode> {
        resolve_builder_with(code, fn_name, &HelperIndex::default())
    }

    /// [`resolve_builder`] with a seeded cross-module helper index, so the branch that
    /// inlines an indexed subtree can be exercised.
    fn resolve_builder_with(code: &str, fn_name: &str, helpers: &HelperIndex) -> Vec<WapChildNode> {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let scope = build_var_scope(&ret.program);
        let aliases = build_alias_map(&ret.program);
        let (bs, be) = scope
            .vars
            .get(fn_name)
            .and_then(|inits| inits.iter().find_map(|vi| vi.fn_body))
            .unwrap_or_else(|| panic!("no function body for `{fn_name}`"));
        let out = resolve_function_return(bs, be, &scope, code, &aliases, None, helpers, 0);
        // A builder returns the `<iq>`; the tests are about its children, which is also
        // what the IQ scanner keeps.
        match out.as_slice() {
            [root] if root.tag == "iq" => root.children.clone(),
            _ => out,
        }
    }

    fn path_of(p: &Option<WapArgPath>) -> Vec<(String, bool)> {
        p.iter()
            .flatten()
            .map(|s| (s.key.clone(), s.list))
            .collect()
    }

    #[test]
    fn element_value_survives_a_destructured_local() {
        // `smax("subject", null, t)` where `t` was destructured off the builder's
        // argument object. The payload of a group rename is the element's content and
        // nothing else, so a builder that binds it to a local first must still yield it.
        let code = r#"
            function b(e){ var t = e.subjectElementValue;
              return o("WASmaxJsx").smax("iq", null, o("WASmaxJsx").smax("subject", null, t)); }
        "#;
        let out = resolve_builder(code, "b");
        let subject = out
            .iter()
            .find(|c| c.tag == "subject")
            .expect("subject child");
        let content = subject
            .content
            .as_ref()
            .expect("`<subject>` carries its element value");
        assert_eq!(
            path_of(&content.arg_path),
            vec![("subjectElementValue".to_string(), false)]
        );
    }

    #[test]
    fn a_node_variable_is_still_a_child_not_content() {
        // The other half of the identifier rule: a local bound to a `smax(…)` call is a
        // CHILD. It roots at no parameter, so it yields no path and no content — the
        // discrimination that lets the test above be safe.
        let code = r#"
            function b(e){ var n = o("WASmaxJsx").smax("body", null);
              return o("WASmaxJsx").smax("description", null, n); }
        "#;
        let out = resolve_builder(code, "b");
        let desc = out.iter().find(|c| c.tag == "description").expect("desc");
        assert!(desc.content.is_none(), "content: {:?}", desc.content);
        assert_eq!(
            desc.children
                .iter()
                .map(|c| c.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["body"]
        );
    }

    #[test]
    fn repeated_child_arg_path_marks_the_list_segment() {
        // `REPEATED_CHILD(tmpl, list, min, max)` calls the template once per element, so
        // the LIST segment is indexed and the template's own keys are not.
        let code = r#"
            function t(e){ var j = e.participantJid;
              return o("WASmaxJsx").smax("participant", {jid: o("WAWap").JID(j)}); }
            function b(e){ var a = e.participantArgs;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").REPEATED_CHILD(t, a, 1, 1024)); }
        "#;
        let out = resolve_builder(code, "b");
        let p = out.iter().find(|c| c.tag == "participant").expect("child");
        assert!(p.repeats);
        assert_eq!(p.presence, WapChildPresence::Required);
        assert_eq!((p.repeat_min, p.repeat_max), (Some(1), Some(1024)));
        assert_eq!(
            path_of(&p.arg_path),
            vec![("participantArgs".to_string(), true)],
            "the node addresses the list itself"
        );
        assert_eq!(
            path_of(&p.attrs[0].arg_path),
            vec![
                ("participantArgs".to_string(), true),
                ("participantJid".to_string(), false)
            ],
            "`[]` on the list segment, never on the key read off an element"
        );
    }

    #[test]
    fn optional_child_arg_path_carries_no_list_marker() {
        // The mirror of the test above, and the reason both exist: `OPTIONAL_CHILD`
        // hands the argument object to the template WHOLE. Indexing it would write the
        // value where the vendor builder never reads, so no segment may be marked.
        let code = r#"
            function t(e){ var i = e.descriptionId;
              return o("WASmaxJsx").smax("description", {id: o("WAWap").CUSTOM_STRING(i)}); }
            function b(e){ var d = e.descriptionArgs;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").OPTIONAL_CHILD(t, d)); }
        "#;
        let out = resolve_builder(code, "b");
        let d = out.iter().find(|c| c.tag == "description").expect("child");
        assert_eq!(d.presence, WapChildPresence::Optional);
        assert!(!d.repeats);
        assert_eq!((d.repeat_min, d.repeat_max), (None, None));
        assert_eq!(
            path_of(&d.arg_path),
            vec![("descriptionArgs".to_string(), false)]
        );
        assert_eq!(
            path_of(&d.attrs[0].arg_path),
            vec![
                ("descriptionArgs".to_string(), false),
                ("descriptionId".to_string(), false)
            ]
        );
        assert!(
            d.arg_path
                .iter()
                .flatten()
                .chain(d.attrs.iter().flat_map(|a| a.arg_path.iter().flatten()))
                .all(|s| !s.list),
            "no segment of an OPTIONAL_CHILD path may be marked as a list"
        );
    }

    #[test]
    fn the_three_cardinalities_are_distinguishable() {
        // Required, optional and presence-marker children that are all empty on the
        // wire. Without `presence` the three are the same `{tag, [], []}` node, and a
        // consumer cannot tell which one it may model as a `bool`.
        let code = r#"
            function req(){ return o("WASmaxJsx").smax("always", null); }
            function opt(e){ var x = e.optArgs; return o("WASmaxJsx").smax("maybe", null); }
            function flag(){ return o("WASmaxJsx").smax("locked", null); }
            function b(e){ var a = e.optArgs, l = e.hasLocked;
              return o("WASmaxJsx").smax("iq", null, [req(),
                o("WASmaxChildren").OPTIONAL_CHILD(opt, a),
                o("WASmaxChildren").HAS_OPTIONAL_CHILD(flag, l)]); }
        "#;
        let out = resolve_builder(code, "b");
        let by = |tag: &str| {
            out.iter()
                .find(|c| c.tag == tag)
                .unwrap_or_else(|| panic!("{tag}: {out:?}"))
                .presence
        };
        assert_eq!(by("always"), WapChildPresence::Required);
        assert_eq!(by("maybe"), WapChildPresence::Optional);
        assert_eq!(by("locked"), WapChildPresence::PresenceFlag);
        assert_eq!(
            path_of(&out.iter().find(|c| c.tag == "locked").unwrap().arg_path),
            vec![("hasLocked".to_string(), false)],
            "a presence marker addresses its boolean, not an argument object"
        );
    }

    #[test]
    fn an_unbounded_max_leaves_only_the_minimum() {
        // WA writes an open upper bound as `1/0`. Recovering `min` anyway is what keeps
        // "at least n, no ceiling" distinguishable from a `.map()` child that states
        // no bound at all — the latter has neither.
        let code = r#"
            function t(e){ return o("WASmaxJsx").smax("item", null); }
            function b(e){ var a = e.itemArgs;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").REPEATED_CHILD(t, a, 0, 1/0)); }
        "#;
        let out = resolve_builder(code, "b");
        let item = out.iter().find(|c| c.tag == "item").expect("item");
        assert_eq!((item.repeat_min, item.repeat_max), (Some(0), None));
    }

    #[test]
    fn a_computed_max_suppresses_both_bounds() {
        // The counterpart of the test above, and the reason it can mean what it says: a
        // maximum WA computes rather than writes is NOT infinity, and must not serialize
        // like it. Dropping the minimum too is what stops a real ceiling from reading as
        // its absence.
        let code = r#"
            function t(e){ return o("WASmaxJsx").smax("item", null); }
            function b(e){ var a = e.itemArgs, n = e.cap;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").REPEATED_CHILD(t, a, 0, n)); }
        "#;
        let out = resolve_builder(code, "b");
        let item = out.iter().find(|c| c.tag == "item").expect("item");
        assert_eq!((item.repeat_min, item.repeat_max), (None, None));
    }

    #[test]
    fn a_negative_infinity_max_is_not_unbounded() {
        // `-1/0` is negative infinity: an upper bound no list length can satisfy. It is
        // written the same way as the open bound above and differs only in sign, so a
        // check for "numerator over zero" reads it as the opposite of what it says.
        let code = r#"
            function t(e){ return o("WASmaxJsx").smax("item", null); }
            function b(e){ var a = e.itemArgs;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").REPEATED_CHILD(t, a, 0, -1/0)); }
        "#;
        let out = resolve_builder(code, "b");
        let item = out.iter().find(|c| c.tag == "item").expect("item");
        assert_eq!(
            (item.repeat_min, item.repeat_max),
            (None, None),
            "an unreadable bound, not an open one"
        );
    }

    /// Resolve a builder's return the way `module.rs` does when it walks an `<iq>` call:
    /// against the MODULE scope, at the reference's real module offset. Distinct from
    /// [`resolve_builder`], which re-parses the body first and so puts the body's own
    /// declarations ahead of the module's — masking exactly the name collisions the flat
    /// scope creates.
    fn resolve_in_module(code: &str, fn_name: &str) -> Vec<WapChildNode> {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let scope = build_var_scope(&ret.program);
        let aliases = build_alias_map(&ret.program);
        let fn_at = code
            .find(&format!("function {fn_name}("))
            .unwrap_or_else(|| panic!("no `{fn_name}` in the source"));
        let ret_at = code[fn_at..].find("return ").expect("a return") + fn_at + "return ".len();
        let end = code[ret_at..].find(";").expect("a terminator") + ret_at;
        let owned = format!("({});", &code[ret_at..end]);
        let alloc2 = Allocator::default();
        let ret2 = wa_oxc::parse_cjs(&alloc2, &owned);
        let expr = first_expression(&ret2.program).unwrap();
        let out = resolve_child_node(
            expr,
            &owned,
            &scope,
            code,
            &aliases,
            None,
            &HelperIndex::default(),
            0,
            Some(ret_at),
        );
        match out.as_slice() {
            [root] if root.tag == "iq" => root.children.clone(),
            _ => out,
        }
    }

    #[test]
    fn a_siblings_local_cannot_donate_an_argument_path() {
        // The minifier reuses `a` in every builder of a module and the variable scope is
        // flat and name-keyed, so the sibling declared FIRST is the first candidate for
        // the name. Only an initializer written inside the enclosing function may name a
        // path, or `<other>` here is addressed as `wrongArgs` — the shape that had
        // `GroupsCreate`'s `<description>` reading out of `participantArgs`.
        let code = r#"
            function sibling(e){ var a = e.wrongArgs; return o("WASmaxJsx").smax("x", null); }
            function t(e){ return o("WASmaxJsx").smax("other", null); }
            function b(e){ var a = e.rightArgs;
              return o("WASmaxJsx").smax("iq", null, o("WASmaxChildren").OPTIONAL_CHILD(t, a)); }
        "#;
        let out = resolve_in_module(code, "b");
        let n = out.iter().find(|c| c.tag == "other").expect("child");
        assert_eq!(path_of(&n.arg_path), vec![("rightArgs".to_string(), false)]);
    }

    #[test]
    fn an_arrow_records_its_argument_root_like_a_function() {
        // The two spellings of "takes one argument object" must agree, or a path that is
        // recoverable in one is silently absent in the other. Nothing in today's bundle
        // takes the arrow form (it is down-levelled to ES5), so this pins the symmetry
        // rather than covering live output.
        //
        // Scope-level rather than end-to-end on purpose: an arrow passed as a child
        // TEMPLATE is still not traced, because `resolve_template_arg` reaches a template
        // through `VarInit::fn_body`, which only a `function` expression sets. That is a
        // separate, pre-existing limit of template resolution — asserting it here would
        // claim a coverage this change does not deliver.
        let code = r#"var t = (e) => o("WASmaxJsx").smax("x", {jid: e.participantJid});"#;
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let scope = build_var_scope(&ret.program);
        let inside = code.find("e.participantJid").expect("marker");
        assert_eq!(
            scope.arg_root_at(inside).map(|(_, _, name)| name),
            Some("e"),
            "an arrow's single parameter is an argument root"
        );
    }

    #[test]
    fn an_ambiguous_source_yields_no_argument_path() {
        // Two rules, one reason, so they are asserted together: a call reading two
        // arguments (`<a>`) and a local assigned from two different ones (`<b>`) each
        // have no single address. Publishing the first would be right about half the
        // time, and a consumer following it writes into the wrong argument with nothing
        // to warn it — worse than publishing nothing, which is counted.
        let code = r#"
            function b(e){ var x = e.old; x = e.current;
              return o("WASmaxJsx").smax("iq", null, [
                o("WASmaxJsx").smax("a", {v: combine(e.left, e.right)}),
                o("WASmaxJsx").smax("b", {v: o("WAWap").CUSTOM_STRING(x)})]); }
        "#;
        let out = resolve_builder(code, "b");
        for tag in ["a", "b"] {
            let n = out.iter().find(|c| c.tag == tag).expect(tag);
            assert!(n.attrs[0].arg_path.is_none(), "<{tag}>: {:?}", n.attrs[0]);
        }
    }

    #[test]
    fn a_repeated_assignment_of_the_same_argument_is_not_ambiguous() {
        // The bound is on DISAGREEMENT, not on multiplicity: two initializers naming the
        // same argument still name one address, and dropping those would lose paths the
        // builder states plainly.
        let code = r#"
            function b(e){ var x = e.jid; x = e.jid;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxJsx").smax("u", {v: o("WAWap").JID(x)})); }
        "#;
        let out = resolve_builder(code, "b");
        let u = out.iter().find(|c| c.tag == "u").expect("u");
        assert_eq!(
            path_of(&u.attrs[0].arg_path),
            vec![("jid".to_string(), false)]
        );
    }

    #[test]
    fn a_nested_helpers_local_does_not_shadow_its_parents() {
        // A nested function's body lies inside its parent's byte range, so a range test
        // alone counts `h`'s `var x` as an initializer of the parent's `x`. Under the
        // ambiguity rule that does not merely pick wrong — it sees two disagreeing
        // sources and drops the parent's perfectly good path.
        let code = r#"
            function b(e){ var x = e.outer;
              function h(e){ var x = e.inner; return o("WASmaxJsx").smax("inner", {v: x}); }
              return o("WASmaxJsx").smax("iq", null, o("WASmaxJsx").smax("outer", {v: x})); }
        "#;
        let out = resolve_builder(code, "b");
        let n = out.iter().find(|c| c.tag == "outer").expect("outer");
        assert_eq!(
            path_of(&n.attrs[0].arg_path),
            vec![("outer".to_string(), false)]
        );
    }

    /// A one-attribute `<user>` whose `jid` sits at `userJid` relative to the helper that
    /// built it — the shape the cross-module index stores.
    fn indexed_user_helper() -> HelperIndex {
        let user = WapChildNode {
            tag: "user".to_string(),
            attrs: vec![WapAttrDef {
                name: "jid".to_string(),
                kind: WapAttrKind::UserJid,
                value: None,
                required: true,
                enum_ref: None,
                arg_path: Some(vec![WapArgSegment {
                    key: "userJid".to_string(),
                    list: false,
                }]),
            }],
            ..Default::default()
        };
        HelperIndex::with("WAWebUserApi", "userNode", vec![user])
    }

    #[test]
    fn a_cross_module_helper_handed_the_whole_argument_object_keeps_its_paths() {
        // `helper(e)` passes the caller's own argument object, so the helper's frame IS
        // the caller's and the right prefix is nothing. An empty prefix is a RESULT, and
        // reading it as a failure cleared paths that were already absolute and correct.
        let code = r#"
            function b(e){ return o("WASmaxJsx").smax("iq", null, o("WAWebUserApi").userNode(e)); }
        "#;
        let out = resolve_builder_with(code, "b", &indexed_user_helper());
        let u = out.iter().find(|c| c.tag == "user").expect("user");
        assert_eq!(
            path_of(&u.attrs[0].arg_path),
            vec![("userJid".to_string(), false)],
            "no prefix needed, and none applied"
        );
    }

    #[test]
    fn a_cross_module_helper_handed_a_keyed_argument_is_prefixed() {
        let code = r#"
            function b(e){ var a = e.userArgs;
              return o("WASmaxJsx").smax("iq", null, o("WAWebUserApi").userNode(a)); }
        "#;
        let out = resolve_builder_with(code, "b", &indexed_user_helper());
        let u = out.iter().find(|c| c.tag == "user").expect("user");
        assert_eq!(
            path_of(&u.attrs[0].arg_path),
            vec![
                ("userArgs".to_string(), false),
                ("userJid".to_string(), false)
            ]
        );
    }

    #[test]
    fn a_cross_module_helper_handed_something_unnameable_keeps_nothing() {
        // The index is built with no call site in view, so nothing downstream will ever
        // rebase this subtree. A path relative to a frame nobody can name is a wrong
        // address, and a wrong address is worse than an absent one.
        let code = r#"
            function b(e){ return o("WASmaxJsx").smax("iq", null,
              o("WAWebUserApi").userNode({jid: e.userJid})); }
        "#;
        let out = resolve_builder_with(code, "b", &indexed_user_helper());
        let u = out.iter().find(|c| c.tag == "user").expect("user");
        assert!(u.attrs[0].arg_path.is_none(), "{:?}", u.attrs[0]);
    }

    #[test]
    fn a_conditional_arm_that_reads_an_argument_makes_it_ambiguous() {
        // `cond ? e.primary : e.values[i]` — the second arm has no static key, so the
        // resolver cannot spell it out, but it plainly READS an argument and may be the
        // one the builder uses. Publishing the arm that resolved points a consumer at a
        // source that is only sometimes right.
        let code = r#"
            function b(e){ return o("WASmaxJsx").smax("iq", null,
              o("WASmaxJsx").smax("x", {v: e.flag ? e.primary : e.values[i]})); }
        "#;
        let out = resolve_builder(code, "b");
        let n = out.iter().find(|c| c.tag == "x").expect("x");
        assert!(n.attrs[0].arg_path.is_none(), "{:?}", n.attrs[0]);
    }

    #[test]
    fn a_conditional_against_a_constant_keeps_the_resolved_arm() {
        // The shape WA actually writes: a value or `DROP_ATTR`. The alternate names no
        // argument at all, so it is not a second source and the one path stands.
        let code = r#"
            function b(e){ return o("WASmaxJsx").smax("iq", null,
              o("WASmaxJsx").smax("x", {v: e.kind === "s" ? o("WAWap").CUSTOM_STRING(e.stamp) : o("WAWap").DROP_ATTR})); }
        "#;
        let out = resolve_builder(code, "b");
        let n = out.iter().find(|c| c.tag == "x").expect("x");
        assert_eq!(
            path_of(&n.attrs[0].arg_path),
            vec![("stamp".to_string(), false)]
        );
    }

    #[test]
    fn a_destructured_parameter_does_not_shrink_the_arity() {
        // `function f(e, {x})` has two formals. Skipping the pattern would leave one name
        // behind and make `e` look like the sole options object, publishing its keys as
        // addresses into an argument list that has two positions.
        let code = r#"
            function b(e, {x}){ return o("WAWap").wap("iq", null,
              o("WAWap").wap("u", {jid: e.jid})); }
        "#;
        let out = resolve_builder(code, "b");
        let u = out.iter().find(|c| c.tag == "u").expect("u");
        assert!(u.attrs[0].arg_path.is_none(), "{:?}", u.attrs[0]);
    }

    #[test]
    fn an_optional_child_handed_something_unnameable_keeps_nothing() {
        // The template's paths are relative to the object literal, which this frame
        // cannot name. Left alone they read as addresses into the request's own
        // arguments — `jid` rather than `userArgs → jid`.
        let code = r#"
            function t(e){ return o("WASmaxJsx").smax("u", {jid: o("WAWap").JID(e.jid)}); }
            function b(e){ return o("WASmaxJsx").smax("iq", null,
              o("WASmaxChildren").OPTIONAL_CHILD(t, {jid: e.userJid})); }
        "#;
        let out = resolve_builder(code, "b");
        let u = out.iter().find(|c| c.tag == "u").expect("u");
        assert!(
            u.arg_path.is_none() && u.attrs[0].arg_path.is_none(),
            "{u:?}"
        );
    }

    #[test]
    fn a_map_mapper_is_rebased_onto_its_receiver() {
        // `.map()` reads one element of the receiver, so the receiver is the list and the
        // mapper's keys hang off an element — the same shape as `REPEATED_CHILD`.
        let code = r#"
            function b(e){ var l = e.productIds;
              return o("WAWap").wap("iq", null, o("WAWap").wap("list", null,
                l.map(function(e){ return o("WAWap").wap("product", {id: e.productId}); }))); }
        "#;
        let out = resolve_builder(code, "b");
        let p = out
            .iter()
            .flat_map(|c| std::iter::once(c).chain(c.children.iter()))
            .find(|c| c.tag == "product")
            .expect("product");
        assert!(p.repeats);
        assert_eq!(
            path_of(&p.arg_path),
            vec![("productIds".to_string(), true)],
            "the node addresses the list it is mapped over"
        );
        assert_eq!(
            path_of(&p.attrs[0].arg_path),
            vec![
                ("productIds".to_string(), true),
                ("productId".to_string(), false)
            ],
            "and its keys are read off an element, not off the request's arguments"
        );
    }

    #[test]
    fn a_map_callback_reads_the_enclosing_module_aliases() {
        // The callback body is re-parsed on its own, so the module-level
        // `A = o("WASmaxAttrs")` it calls through is not declared in what the sweep sees.
        // With only the body's own aliases, `A.OPTIONAL_LITERAL("true", e.hasDelete)` is
        // an ordinary dynamic value: the fixed wire string is lost and the boolean that
        // merely gates the attribute is published as the address to put a value at.
        let code = r#"
            var A; A = o("WASmaxAttrs");
            function b(e){ var l = e.itemArgs;
              return o("WAWap").wap("iq", null, l.map(function(e){
                return o("WAWap").wap("item", {del: A.OPTIONAL_LITERAL("true", e.hasDelete)}); })); }
        "#;
        let out = resolve_builder(code, "b");
        let item = out
            .iter()
            .flat_map(|c| std::iter::once(c).chain(c.children.iter()))
            .find(|c| c.tag == "item")
            .expect("item");
        let del = item.attrs.iter().find(|a| a.name == "del").expect("del");
        assert_eq!(del.kind, WapAttrKind::Optional);
        assert_eq!(del.value.as_deref(), Some("true"));
        assert!(
            del.arg_path.is_none(),
            "a fixed literal's gate is not its value address: {:?}",
            del.arg_path
        );
    }

    #[test]
    fn a_key_read_off_a_call_result_is_not_an_argument_path() {
        // `attrFromReference(accessor, e, ["id"])` reads out of the stanza being ACKED.
        // The general walk descends into a call's arguments, finds the bare parameter and
        // reports the empty path, which then absorbs `.value` — publishing `value` as an
        // address into the builder's options object, which it is not. A key read off a
        // computed value is not an address however the value was derived.
        let code = r#"
            function b(e){ var t = o("M").attrFromReference(o("P").attrStanzaId, e, ["id"]);
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxJsx").smax("ack", {id: o("WAWap").STANZA_ID(t.value)})); }
        "#;
        let out = resolve_builder(code, "b");
        let ack = out.iter().find(|c| c.tag == "ack").expect("ack");
        assert!(ack.attrs[0].arg_path.is_none(), "{:?}", ack.attrs[0]);
    }

    #[test]
    fn a_key_read_off_the_parameter_is_still_an_argument_path() {
        // The counterpart, so the restriction above stays a restriction on CALLS rather
        // than on member chains: a nested read off the parameter is a plain address.
        let code = r#"
            function b(e){ var t = e.outer;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxJsx").smax("x", {v: o("WAWap").CUSTOM_STRING(t.inner)})); }
        "#;
        let out = resolve_builder(code, "b");
        let x = out.iter().find(|c| c.tag == "x").expect("x");
        assert_eq!(
            path_of(&x.attrs[0].arg_path),
            vec![("outer".to_string(), false), ("inner".to_string(), false)]
        );
    }

    #[test]
    fn a_computed_minimum_suppresses_both_bounds() {
        // Bounds move together. A ceiling with no floor is half a range, and it would be
        // counted as a recovered bound while the floor the builder also enforces is
        // silently absent — the same conflation the computed-maximum rule avoids.
        let code = r#"
            function t(e){ return o("WASmaxJsx").smax("item", null); }
            function b(e){ var a = e.itemArgs, n = e.floor;
              return o("WASmaxJsx").smax("iq", null,
                o("WASmaxChildren").REPEATED_CHILD(t, a, n, 10)); }
        "#;
        let out = resolve_builder(code, "b");
        let item = out.iter().find(|c| c.tag == "item").expect("item");
        assert_eq!((item.repeat_min, item.repeat_max), (None, None));
    }

    #[test]
    fn an_optional_literal_attribute_names_no_value_path() {
        // `OPTIONAL_LITERAL("true", flag)` writes a FIXED wire value and takes a boolean
        // deciding whether to write it. Reporting the boolean as the value's address
        // tells a consumer to put the wire string there.
        let code = r#"
            function b(e){ return o("WASmaxJsx").smax("iq", null,
              o("WASmaxJsx").smax("description", {
                id: o("WAWap").CUSTOM_STRING(e.descriptionId),
                delete: o("WASmaxAttrs").OPTIONAL_LITERAL("true", e.hasDelete)})); }
        "#;
        let out = resolve_builder(code, "b");
        let d = out
            .iter()
            .find(|c| c.tag == "description")
            .expect("description");
        let by = |n: &str| d.attrs.iter().find(|a| a.name == n).expect(n);
        assert_eq!(
            path_of(&by("id").arg_path),
            vec![("descriptionId".to_string(), false)],
            "an ordinary optional attribute still names its value"
        );
        assert!(by("delete").arg_path.is_none(), "{:?}", by("delete"));
    }

    #[test]
    fn an_optional_merge_introducing_a_tag_marks_it_optional() {
        // `optionalMerge` can skip the whole contribution, so a tag it INTRODUCES may be
        // absent from the request. A tag that merges onto a destination built at its own
        // call site keeps that site's cardinality instead.
        let mut dst = vec![cnode("create", &[])];
        apply_contribution(&mut dst, &[cnode("create", &[]), cnode("extra", &[])], true);
        let by = |t: &str| {
            dst.iter()
                .find(|c| c.tag == t)
                .unwrap_or_else(|| panic!("{t}: {dst:?}"))
                .presence
        };
        assert_eq!(
            by("extra"),
            WapChildPresence::Optional,
            "a tag the optional mixin introduces"
        );
        assert_eq!(
            by("create"),
            WapChildPresence::Required,
            "a tag that already existed keeps its own call site's cardinality"
        );
    }

    #[test]
    fn a_multi_parameter_builder_yields_no_argument_path() {
        // A legacy `WAWeb*Job` builder takes positional parameters, so a bare key would
        // name a property without naming which parameter it hangs off. That reads like
        // an address and is not one, so nothing is emitted.
        let code = r#"
            function b(e, t){ var j = e.jid;
              return o("WAWap").wap("iq", null, o("WAWap").wap("user", {jid: j})); }
        "#;
        let out = resolve_builder(code, "b");
        let u = out.iter().find(|c| c.tag == "user").expect("user");
        assert!(u.attrs[0].arg_path.is_none(), "{:?}", u.attrs[0]);
    }

    /// Like [`resolve`], but with cross-module mixin contributions available (Phase
    /// 3): a `merge…Mixin(dst,…)` folds the mixin's attrs/children into `dst`.
    fn resolve_with(
        code: &str,
        expr_src: &str,
        contributions: &MixinContributions,
        helpers: &HelperIndex,
    ) -> Vec<WapChildNode> {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let scope = build_var_scope(&ret.program);
        let aliases = build_alias_map(&ret.program);

        let alloc2 = Allocator::default();
        let owned = format!("{expr_src};");
        let ret2 = wa_oxc::parse_cjs(&alloc2, &owned);
        let expr = first_expression(&ret2.program).unwrap();
        resolve_child_node(
            expr,
            &owned,
            &scope,
            code,
            &aliases,
            Some(contributions),
            helpers,
            0,
            None,
        )
    }

    #[test]
    fn short_circuit_reassigned_child_is_recovered() {
        // `var r=null; cond && (r=wap("list",…))` — a child built by conditional
        // reassignment (the aggregate receipt builder's shape), not a declaration
        // initializer. Its `<list>` must still be recovered; a declaration-only scope
        // resolves `r` to its `null` seed and drops the real child.
        let code = r#"
            var r = null;
            cond && (r = o("WAWap").wap("list", null, o("WAWap").wap("item", {id: x})));
            var S = o("WAWap").wap("receipt", {to: y}, r);
        "#;
        let out = resolve(code, "S");
        assert_eq!(out.len(), 1, "{out:?}");
        let list = out[0]
            .children
            .iter()
            .find(|c| c.tag == "list")
            .expect("list child recovered from the &&-reassignment");
        assert!(
            list.children.iter().any(|c| c.tag == "item"),
            "item under list: {:?}",
            list.children
        );
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

    /// A contribution node `tag{attrs}` for the Phase-3 tests.
    fn cnode(tag: &str, attrs: &[&str]) -> WapChildNode {
        WapChildNode {
            content: None,
            tag: tag.to_string(),
            attrs: attrs
                .iter()
                .map(|a| wa_ir::WapAttrDef {
                    name: a.to_string(),
                    kind: wa_ir::WapAttrKind::Const,
                    value: None,
                    required: false,
                    enum_ref: None,
                    arg_path: None,
                })
                .collect(),
            children: Vec::new(),
            repeats: false,
            variant_groups: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn merge_mixin_folds_contribution_into_dst() {
        // `mergeFooMixin(smax("messages",null), …)` with a known contribution folds
        // the mixin's attrs into the resolved destination by tag.
        let mut contribs = MixinContributions::new();
        contribs.insert(
            "WASmaxOutFooPayloadMixin".into(),
            vec![cnode("messages", &["count"])],
        );
        let out = resolve_with(
            "",
            r#"o("WASmaxOutFooPayloadMixin").mergeFooPayloadMixin(o("WASmaxJsx").smax("messages", null), a)"#,
            &contribs,
            &HelperIndex::default(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "messages");
        assert!(out[0].attrs.iter().any(|a| a.name == "count"));
    }

    #[test]
    fn wildcard_contribution_applies_regardless_of_dst_tag() {
        // A `smax$any` contribution root applies its attrs to the dst whatever its tag.
        let mut contribs = MixinContributions::new();
        contribs.insert(
            "WASmaxOutFooParamsMixin".into(),
            vec![cnode("smax$any", &["jid", "type"])],
        );
        let out = resolve_with(
            "",
            r#"o("WASmaxOutFooParamsMixin").mergeFooParamsMixin(o("WASmaxJsx").smax("messages", null), a)"#,
            &contribs,
            &HelperIndex::default(),
        );
        assert_eq!(
            out[0].tag, "messages",
            "dst keeps its tag, not the wildcard"
        );
        let names: Vec<_> = out[0].attrs.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"jid") && names.contains(&"type"));
    }

    #[test]
    fn cross_merge_without_mixin_suffix_is_recognized() {
        // A MixinGroup selector method (`mergeFooParams`, no `Mixin` suffix) is folded
        // when its owner is a `WASmaxOut*` module.
        let mut contribs = MixinContributions::new();
        contribs.insert(
            "WASmaxOutFooParams".into(),
            vec![cnode("smax$any", &["jid"])],
        );
        let out = resolve_with(
            "",
            r#"o("WASmaxOutFooParams").mergeFooParams(o("WASmaxJsx").smax("messages", null), a)"#,
            &contribs,
            &HelperIndex::default(),
        );
        assert!(out[0].attrs.iter().any(|a| a.name == "jid"));
    }

    #[test]
    fn optional_merge_folds_referenced_mixin_contribution() {
        // `optionalMerge(o("X").mergeY, dst, …)` folds X's contribution onto `dst`,
        // keeping `dst`'s own local attrs.
        let mut contribs = MixinContributions::new();
        contribs.insert(
            "WASmaxOutDirections".into(),
            vec![cnode("messages", &["before", "after"])],
        );
        let out = resolve_with(
            "",
            r#"o("WASmaxMixins").optionalMerge(o("WASmaxOutDirections").mergeDirections, o("WASmaxJsx").smax("messages", {count:o("WAWap").INT(t)}), n)"#,
            &contribs,
            &HelperIndex::default(),
        );
        assert_eq!(out[0].tag, "messages");
        let names: Vec<_> = out[0].attrs.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"count"), "local attr kept");
        assert!(
            names.contains(&"before") && names.contains(&"after"),
            "ref contribution folded"
        );
    }

    #[test]
    fn no_contributions_is_structural_only() {
        // Backward-compat: with no contributions a merge recovers only the dst stanza,
        // never invents attrs (identical to pre-Phase-3 behavior).
        let out = resolve(
            "",
            r#"o("WASmaxOutFooMixin").mergeFooMixin(o("WASmaxJsx").smax("messages", null), a)"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag, "messages");
        assert!(out[0].attrs.is_empty());
    }

    #[test]
    fn function_return_collects_both_if_branch_returns() {
        // A MixinGroup selector returns a different stanza per branch; both variants
        // are collected (so a union's attrs all surface), not just the first.
        let code = r#"
            function sel(dst, t){
                if (t.a) return o("WASmaxJsx").smax("x", {p:"1"});
                if (t.b) return o("WASmaxJsx").smax("x", {q:"2"});
                throw err;
            }
        "#;
        let out = resolve(code, "sel(dst, t)");
        let xs: Vec<_> = out.iter().filter(|c| c.tag == "x").collect();
        assert_eq!(xs.len(), 2, "both if-branch variants collected");
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
        let out = find_wap_calls_in_body(body, &AliasMap::default(), None);
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

    #[test]
    fn merge_node_into_promotes_repeats() {
        // A repeatable contribution folded onto a locally-singular child of the same
        // tag must promote `repeats` (mirrors mixin_index::merge_children).
        let mut dst = WapChildNode {
            tag: "item".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
            ..Default::default()
        };
        let src = WapChildNode {
            tag: "item".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: true,
            variant_groups: vec![],
            ..Default::default()
        };
        merge_node_into(&mut dst, &src, false);
        assert!(
            dst.repeats,
            "repeatable contribution must promote the child"
        );
    }
}
