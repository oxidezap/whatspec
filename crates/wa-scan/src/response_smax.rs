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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression, Function, Statement};
use oxc_span::GetSpan;
use wa_ir::wap;
use wa_ir::{
    AssertionKind, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion, UnionVariant,
};

use wa_oxc::{arg_expr, as_call, as_identifier, as_int, as_string_lit, callee_method};

/// A module's local parser functions, keyed by name → re-parsable source. Child
/// accessors reference these by identifier (`optionalChildWithTag(n, "x", parseX)`).
type LocalFns = HashMap<String, String>;

/// What a cross-module `o("WASmaxIn<M>").parse<Fn>(…)` call resolves to.
#[derive(Clone)]
pub(crate) enum Resolved {
    /// A flat field list — a payload mixin or a plain parser on the same node.
    Fields(Vec<ParsedField>),
    /// A discriminated union — a `…MixinGroup`/`…Errors` disjunction (a cascade of
    /// `o(mod).parseV(…) → {name:"V", value}` ending in `errorMixinDisjunction`).
    Union(Vec<UnionVariant>),
}

/// Lazily resolves cross-module smax parsers (`o("WASmaxIn<M>").parse<Fn>`) against
/// every `WASmaxIn*` module slice, memoizing by `module::fn` and breaking import
/// cycles. Subsumes the old eager mixin index: a payload mixin is just a parser
/// that resolves to [`Resolved::Fields`]; a `…MixinGroup` resolves to
/// [`Resolved::Union`].
pub(crate) struct Resolver<'a> {
    /// All `WASmaxIn*` module name → slice (first occurrence wins; shard dedup).
    slices: &'a HashMap<&'a str, &'a str>,
    cache: RefCell<HashMap<String, Option<Resolved>>>,
    in_progress: RefCell<HashSet<String>>,
    /// Memoized same-node assertions per parser (a separate axis from `cache`, which
    /// holds fields/unions); see [`Resolver::assertions`].
    assert_cache: RefCell<HashMap<String, Vec<ResponseAssertion>>>,
    assert_in_progress: RefCell<HashSet<String>>,
}

impl<'a> Resolver<'a> {
    pub(crate) fn new(slices: &'a HashMap<&'a str, &'a str>) -> Self {
        Resolver {
            slices,
            cache: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(HashSet::new()),
            assert_cache: RefCell::new(HashMap::new()),
            assert_in_progress: RefCell::new(HashSet::new()),
        }
    }

    /// Resolve `o(module).func(…)` to its fields or union, or `None` if the module
    /// is absent, the fn isn't found, or a cycle is hit.
    pub(crate) fn resolve(&self, module: &str, func: &str) -> Option<Resolved> {
        let key = format!("{module}::{func}");
        if let Some(hit) = self.cache.borrow().get(&key) {
            return hit.clone();
        }
        if !self.in_progress.borrow_mut().insert(key.clone()) {
            return None; // import cycle — bail, the outer frame will fill it in
        }
        let result = self.resolve_uncached(module, func);
        self.in_progress.borrow_mut().remove(&key);
        self.cache.borrow_mut().insert(key, result.clone());
        result
    }

    fn resolve_uncached(&self, module: &str, func: &str) -> Option<Resolved> {
        let slice = *self.slices.get(module)?;
        // Map the export name to its local fn (or use it directly if it names one).
        let locals = collect_local_fn_sources(slice);
        let local = collect_exports(slice)
            .into_iter()
            .find(|(e, _)| e == func)
            .map(|(_, l)| l)
            .filter(|l| locals.contains_key(l))
            .or_else(|| locals.contains_key(func).then(|| func.to_string()))?;
        let src = locals.get(&local)?;
        if src.contains("errorMixinDisjunction") {
            Some(Resolved::Union(analyze_disjunction(src, self)))
        } else {
            let mut visited = HashSet::new();
            visited.insert(local.clone());
            let (_assertions, fields) = analyze_fn_source(src, &locals, self, &mut visited)?;
            Some(Resolved::Fields(fields))
        }
    }

    /// The same-node assertions a parser enforces on its node argument: literal-value
    /// attr checks (`literal(attrString, e, "type", "result")`) and tag checks,
    /// including those bubbled up from same-node mixins it calls (e.g. an error
    /// parser's `type:"error"` comes from `parseIQErrorResponseMixin(e, …)`). These
    /// are the discriminators that tell RPC outcome variants apart; the JS keeps them
    /// as parser asserts (not output fields), so they're recovered separately from
    /// [`Resolver::resolve`]. Memoized; cycle-safe.
    pub(crate) fn assertions(&self, module: &str, func: &str) -> Vec<ResponseAssertion> {
        let key = format!("{module}::{func}");
        if let Some(hit) = self.assert_cache.borrow().get(&key) {
            return hit.clone();
        }
        if !self.assert_in_progress.borrow_mut().insert(key.clone()) {
            return Vec::new(); // cycle — bail
        }
        let result = self.assertions_uncached(module, func);
        self.assert_in_progress.borrow_mut().remove(&key);
        self.assert_cache.borrow_mut().insert(key, result.clone());
        result
    }

    fn assertions_uncached(&self, module: &str, func: &str) -> Vec<ResponseAssertion> {
        let Some(slice) = self.slices.get(module) else {
            return Vec::new();
        };
        let locals = collect_local_fn_sources(slice);
        let Some(local) = collect_exports(slice)
            .into_iter()
            .find(|(e, _)| e == func)
            .map(|(_, l)| l)
            .filter(|l| locals.contains_key(l))
            .or_else(|| locals.contains_key(func).then(|| func.to_string()))
        else {
            return Vec::new();
        };
        let Some(src) = locals.get(&local) else {
            return Vec::new();
        };
        // A disjunction (`…MixinGroup`/`…Errors`) has no single same-node assertion.
        if src.contains("errorMixinDisjunction") {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        visited.insert(local.clone());
        let raw = analyze_fn_source(src, &locals, self, &mut visited)
            .map(|(assertions, _)| assertions)
            .unwrap_or_default();
        // Bubbling can re-add an identical assert (a direct `assertTag(e,"iq")` plus the
        // same one from a same-node mixin); keep the first occurrence of each (n tiny).
        let mut out: Vec<ResponseAssertion> = Vec::new();
        for a in raw {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }
}

/// One railway binding: `var V = <call>;` → what `V` resolves to.
#[derive(Clone)]
enum Binding {
    /// A value field: the normalized wap method + field type + required flag.
    Field {
        method: String,
        field_type: ParsedFieldType,
        required: bool,
        byte_length: Option<u32>,
        /// Inclusive integer bounds from an `attrIntRange(node, name, min, max)`, when
        /// the accessor was a range check (and not the timestamp-marker range, which is
        /// surfaced as `field_type: Timestamp` instead).
        int_range: Option<(i64, i64)>,
        /// The wire attr/content name (the accessor's literal arg), when present.
        wire_name: Option<String>,
        /// Wrapper tags to descend before reading, when the accessor's node arg is a
        /// `flattenedChildWithTag` descent (`attrString(n.value, "id")` reads off the
        /// `<report>` child `n`, not the parent node).
        source_path: Option<Vec<String>>,
    },
    /// A cross-module parser call (`o(mod).parse<Fn>(node)`) that resolved to a
    /// flat field list: a same-node payload mixin or a plain sub-parser.
    Fields(Vec<ParsedField>),
    /// A cross-module disjunction call (`o(mod).parse<Fn>MixinGroup(node)`) that
    /// resolved to a discriminated union of variants. `source_path` records any
    /// `flattenedChildWithTag` wrappers descended to reach the parsed node.
    Union {
        variants: Vec<UnionVariant>,
        source_path: Vec<String>,
    },
    /// A bare child-node descend (`flattenedChildWithTag(node, "tag")` with no
    /// parser): not a field itself, but names the child node a later parser reads
    /// off (`o(mod).parseMixin(r.value)` → a `<tag>` child, not a same-node mixin).
    /// `path` is the full wrapper chain from the function's node param (nested
    /// descends accumulate: `…(t.value,"id")` after `…(e,"key")` → `["key","id"]`).
    ChildNode { path: Vec<String> },
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
        /// Wrapper tags descended (via `flattenedChildWithTag`) before `<tag>`.
        source_path: Vec<String>,
    },
    /// An assertion / literal / node-reshape — no field.
    None,
}

/// Analyze every exported `parse…` function in a smax module slice into
/// `(export_name, ParsedResponse)` pairs. Local child parsers are resolved within
/// the module; cross-module parsers/mixins/unions come from `resolver`.
pub(crate) fn analyze_module_exports(
    module_slice: &str,
    resolver: &Resolver,
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
        if let Some((assertions, fields)) = analyze_fn_source(src, &locals, resolver, &mut visited)
        {
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
    resolver: &Resolver,
    visited: &mut HashSet<String>,
) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, fn_source);
    let func = ret.program.body.iter().find_map(|s| match s {
        Statement::FunctionDeclaration(f) => Some(&**f),
        _ => None,
    })?;
    analyze_function(func, locals, resolver, visited)
}

fn analyze_function(
    func: &Function,
    locals: &LocalFns,
    resolver: &Resolver,
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
                        let b = classify_call(
                            init,
                            &mut assertions,
                            locals,
                            resolver,
                            visited,
                            &bindings,
                        );
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
    let fields = resolve_tail(tail, &bindings)?;
    Some((assertions, fields))
}

/// Classify the RHS of a railway binding into a [`Binding`], recording any
/// assertion it implies (assertTag/assertAttr/literal…).
fn classify_call(
    init: &Expression,
    assertions: &mut Vec<ResponseAssertion>,
    locals: &LocalFns,
    resolver: &Resolver,
    visited: &mut HashSet<String>,
    bindings: &HashMap<String, Binding>,
) -> Binding {
    let Some(call) = as_call(init) else {
        return Binding::None;
    };
    let Some(method) = smax_helper_name(call) else {
        // Not a parse-helper: could be a cross-module parser `o(mod).parse<Fn>(…)`
        // — a payload mixin, a same-node sub-parser, or a `…MixinGroup` disjunction.
        if let Some((module, func)) = cross_module_parse_call(call) {
            // Does it parse a child node? `parseMixin(r.value)` where r descended via
            // `flattenedChildWithTag(e, "tag")` → the mixin reads off `<tag>` (and any
            // wrappers above it), so model it as a tagged child, not a same-node mixin.
            let node_path = node_descend_path(&call.arguments, bindings);
            // A mixin parsed on the SAME node (no descend) enforces its own asserts on
            // that node — bubble them up so an error variant inherits the `type:"error"`
            // its `parseIQErrorResponseMixin(e, …)` asserts. Child-descend mixins assert
            // on the child, not the variant's node, so don't bubble those.
            if node_path.is_empty() {
                let bubbled = resolver.assertions(&module, &func);
                assertions.extend(bubbled);
            }
            return match resolver.resolve(&module, &func) {
                Some(Resolved::Fields(fields)) => match split_path(&node_path) {
                    Some((tag, source_path)) => Binding::ChildGroup {
                        tag,
                        fields,
                        repeats: false,
                        optional: false,
                        source_path,
                    },
                    None => Binding::Fields(fields),
                },
                Some(Resolved::Union(variants)) => Binding::Union {
                    variants,
                    source_path: node_path,
                },
                None => Binding::None,
            };
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
    // If the accessor reads off a `flattenedChildWithTag` descent (its node arg is
    // `n.value` where `n` is a ChildNode), record the wrapper tag(s) to descend.
    let source_path = opt_vec(node_descend_path(args, bindings));
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
        // nothing. `literalContent` pins a constant string (no makeResult value).
        "literal" => {
            // `literal(ACC, node, "attr", "fixedValue")` pins the attr to a constant —
            // a hard discriminator when the value is a string literal on the SAME node
            // (`type:"result"`). A reference value (`literal(…, "id", r.value)`) is
            // request-relative, not a fixed discriminator, so skip it.
            if source_path.is_none()
                && let Some(attr) = args.get(2).and_then(arg_expr).and_then(as_string_lit)
                && let Some(value) = args.get(3).and_then(arg_expr).and_then(as_string_lit)
            {
                assertions.push(ResponseAssertion {
                    kind: AssertionKind::Attr,
                    name: Some(attr.to_string()),
                    value: Some(value.to_string()),
                });
            }
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
                    int_range: None,
                    wire_name,
                    source_path,
                },
                None => Binding::None,
            }
        }
        // `literalContent(ACC, node, "value")` pins the node's text content to a
        // constant — the discriminator for marker union variants (`admin_add` vs
        // `all_member_add`). Not an output field (the value is fixed); record it as a
        // Content assertion when on the same node.
        "literalContent" => {
            if source_path.is_none()
                && let Some(value) = args.get(2).and_then(arg_expr).and_then(as_string_lit)
            {
                assertions.push(ResponseAssertion {
                    kind: AssertionKind::Content,
                    name: None,
                    value: Some(value.to_string()),
                });
            }
            Binding::None
        }
        // `contentLiteralBytes(node, [..])` pins the node's content to a fixed byte
        // sequence and returns it — a real bytes field when named in `makeResult`.
        "contentLiteralBytes" => Binding::Field {
            method: wap::CONTENT_BYTES.to_string(),
            field_type: ParsedFieldType::Bytes,
            required: true,
            byte_length: None,
            int_range: None,
            wire_name: None,
            source_path,
        },
        // Optional literal → a present-or-absent marker; treat as optional string.
        "optionalLiteral" => Binding::Field {
            method: wap::MAYBE_ATTR_STRING.to_string(),
            field_type: ParsedFieldType::String,
            required: false,
            byte_length: None,
            int_range: None,
            wire_name,
            source_path,
        },
        // `optional(ACCESSOR, node, …)` → the wrapped accessor decides the type;
        // required = false.
        "optional" => {
            let inner = args
                .first()
                .and_then(arg_expr)
                .and_then(inner_accessor_name);
            match inner.and_then(normalize_accessor) {
                Some((m, ft, bl)) => {
                    let (field_type, int_range) = int_range_and_type(inner, args, ft);
                    Binding::Field {
                        method: optional_variant(&m),
                        field_type,
                        required: false,
                        byte_length: bl,
                        int_range,
                        wire_name,
                        source_path,
                    }
                }
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
        | "mapChildrenWithTag" => classify_child(method, args, locals, resolver, visited, bindings),
        other => match normalize_accessor(other) {
            Some((m, ft, bl)) => {
                let (field_type, int_range) = int_range_and_type(Some(other), args, ft);
                Binding::Field {
                    method: m,
                    field_type,
                    required: true,
                    byte_length: bl,
                    int_range,
                    wire_name,
                    source_path,
                }
            }
            None => Binding::None,
        },
    }
}

/// The wrapper tags descended to reach an accessor's node argument: the full
/// [`Binding::ChildNode`] path when the node is `n.value` (a `flattenedChildWithTag`
/// descent), or empty when the node is the parent param (no descent). The node is
/// the first argument that is an identifier or an `X.value` member (accessor refs
/// like `o("..").attrInt` are neither, so they are skipped).
fn node_descend_path(
    args: &oxc_allocator::Vec<oxc_ast::ast::Argument>,
    bindings: &HashMap<String, Binding>,
) -> Vec<String> {
    for a in args {
        let Some(e) = arg_expr(a) else { continue };
        if let Some((var, prop)) = value_member(e) {
            if prop != "value" {
                continue;
            }
            return match bindings.get(var) {
                Some(Binding::ChildNode { path }) => path.clone(),
                _ => Vec::new(),
            };
        }
        if as_identifier(e).is_some() {
            return Vec::new(); // node is a plain parent param — no descent
        }
    }
    Vec::new()
}

/// Resolve a child accessor's inner parser fn and analyze it into a [`Binding::ChildGroup`].
/// The inner parser is either a local fn (`optionalChildWithTag(n, "x", parseX)`) or
/// a cross-module reference (`mapChildrenWithTag(n, "x", 0, N, o("Mod").parseX)`).
fn classify_child(
    method: &str,
    args: &oxc_allocator::Vec<oxc_ast::ast::Argument>,
    locals: &LocalFns,
    resolver: &Resolver,
    visited: &mut HashSet<String>,
    bindings: &HashMap<String, Binding>,
) -> Binding {
    // The wire tag is the first string-literal arg.
    let Some(tag_idx) = args
        .iter()
        .position(|a| arg_expr(a).and_then(as_string_lit).is_some())
    else {
        // No tag string → not a tagged child accessor.
        return Binding::None;
    };
    let tag = arg_expr(&args[tag_idx])
        .and_then(as_string_lit)
        .unwrap()
        .to_string();
    // Wrapper tags descended to reach this accessor's node arg (e.g. the child is
    // mapped off a `flattenedChildWithTag` wrapper: `iq -> list -> user`).
    let source_path = node_descend_path(args, bindings);
    // Inner parser: a local identifier (preferred), else a cross-module ref. It is
    // an arg AFTER the tag — the node arg comes BEFORE it and can be an identifier
    // that collides with a local fn name (minified `function e(e,t)` shadows fn `e`
    // with its node param `e`); restricting to post-tag args avoids that mis-pick.
    let inner_local = args
        .iter()
        .skip(tag_idx + 1)
        .rev()
        .find_map(|a| arg_expr(a).and_then(as_identifier))
        .filter(|id| locals.contains_key(*id))
        .map(str::to_string);
    let fields = if let Some(fn_name) = inner_local {
        if !visited.insert(fn_name.clone()) {
            return Binding::None; // recursion guard
        }
        let result = locals
            .get(&fn_name)
            .and_then(|src| analyze_fn_source(src, locals, resolver, visited));
        visited.remove(&fn_name);
        match result {
            Some((_assertions, fields)) if !fields.is_empty() => fields,
            _ => return Binding::None,
        }
    } else if let Some((module, func)) = args
        .iter()
        .skip(tag_idx + 1)
        .rev()
        .find_map(|a| arg_expr(a).and_then(cross_module_parse_ref))
    {
        match resolver.resolve(&module, &func) {
            Some(Resolved::Fields(fields)) if !fields.is_empty() => fields,
            // A child whose content is itself a disjunction: carry the union as a
            // single nested field named for the child tag.
            Some(Resolved::Union(variants)) if !variants.is_empty() => vec![ParsedField {
                name: tag.clone(),
                field_type: ParsedFieldType::Union,
                union_variants: Some(variants),
                required: true,
                ..Default::default()
            }],
            _ => return Binding::None,
        }
    } else if method == "flattenedChildWithTag" {
        // A bare `flattenedChildWithTag(node, "tag")` descend (no parser): record the
        // accumulated child path so a later `parseMixin(r.value)` / accessor reading
        // `r.value` can attribute its fields to `<…wrappers…>/<tag>`.
        let mut path = source_path;
        path.push(tag);
        return Binding::ChildNode { path };
    } else {
        return Binding::None;
    };
    Binding::ChildGroup {
        tag,
        fields,
        repeats: method == "mapChildrenWithTag",
        optional: matches!(method, "optionalChild" | "optionalChildWithTag"),
        source_path,
    }
}

/// The `attrIntRange` bounds WA uses to range-check a Unix timestamp (2020-01-01 …
/// 2100-01-01), in seconds and in milliseconds (`15778656e5`/`41024736e5`). A field
/// checked against exactly one of these windows is a wall-clock time, not a counter.
const TIMESTAMP_RANGE_SECONDS: (i64, i64) = (1577865600, 4102473600);
const TIMESTAMP_RANGE_MILLIS: (i64, i64) = (1577865600000, 4102473600000);

/// Refine an integer accessor's type/bounds from an `attrIntRange(node, name, min,
/// max)` call. Returns the (possibly refined) field type and any integer bounds:
///  - the timestamp-marker range → [`ParsedFieldType::Timestamp`], no bounds carried;
///  - any other range → the base type with its `(min, max)` bounds;
///  - a non-range accessor → the base type, no bounds.
///
/// `min`/`max` are the two numeric literals in the call — the only ones present, in
/// both the direct `attrIntRange(node, name, min, max)` and the wrapped
/// `optional(attrIntRange, node, name, min, max)` forms.
fn int_range_and_type(
    accessor: Option<&str>,
    args: &[Argument],
    base: ParsedFieldType,
) -> (ParsedFieldType, Option<(i64, i64)>) {
    if accessor != Some("attrIntRange") {
        return (base, None);
    }
    let mut nums = args.iter().filter_map(|a| arg_expr(a).and_then(as_int));
    match (nums.next(), nums.next()) {
        (Some(min), Some(max)) if (min, max) == TIMESTAMP_RANGE_SECONDS => {
            (ParsedFieldType::Timestamp, None)
        }
        (Some(min), Some(max)) if (min, max) == TIMESTAMP_RANGE_MILLIS => {
            (ParsedFieldType::TimestampMillis, None)
        }
        (Some(min), Some(max)) => (base, Some((min, max))),
        _ => (base, None),
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
        // Keep the JID flavor each accessor validates rather than collapsing every JID
        // to one type. The flavor is protocol-safety-critical: a LID user JID and a PN
        // user JID are different identities for the same person. The `phone*` variants
        // are the explicit-PN spelling of the plain user/device accessors.
        "attrUserJid" | "attrPhoneUserJid" => s(wap::ATTR_USER_JID, ParsedFieldType::UserJid),
        "attrLidUserJid" => s(wap::ATTR_LID_USER_JID, ParsedFieldType::LidUserJid),
        "attrDeviceJid" | "attrPhoneDeviceJid" => {
            s(wap::ATTR_DEVICE_JID, ParsedFieldType::DeviceJid)
        }
        "attrLidDeviceJid" => s(wap::ATTR_LID_DEVICE_JID, ParsedFieldType::LidDeviceJid),
        "attrGroupJid" => s(wap::ATTR_GROUP_JID, ParsedFieldType::GroupJid),
        "attrNewsletterJid" => s(wap::ATTR_NEWSLETTER_JID, ParsedFieldType::NewsletterJid),
        "attrCallJid" => s(wap::ATTR_CALL_JID, ParsedFieldType::CallJid),
        "attrBroadcastJid" => s(wap::ATTR_BROADCAST_JID, ParsedFieldType::BroadcastJid),
        "attrStatusJid" => s(wap::ATTR_STATUS_JID, ParsedFieldType::StatusJid),
        // Generic / multi-flavor accessors stay a bare Jid: `attrChatJid` is a user OR
        // a group, `attrJid`/`attrDomainJid` accept any, `attrJidEnum` pins the server
        // kind via a runtime enum arg (no single static flavor).
        "attrJid" | "attrDomainJid" | "attrChatJid" | "attrPhoneChatJid" | "attrWapJid"
        | "attrFromJid" | "attrFromPhoneJid" | "attrLidJid" | "attrJidEnum" | "literalJid" => {
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

/// `o("WASmaxIn<M>").parse<Fn>(...)` (a call) → `(module, func)` for any
/// `WASmaxIn*` module — a cross-module payload mixin, sub-parser, or `…MixinGroup`.
fn cross_module_parse_call(call: &CallExpression) -> Option<(String, String)> {
    let owner = require_owner_of_call(call)?;
    if !owner.starts_with("WASmaxIn") {
        return None;
    }
    let method = callee_method(call)?;
    method
        .starts_with("parse")
        .then(|| (owner.to_string(), method.to_string()))
}

/// `o("WASmaxIn<M>").parse<Fn>` (a member *reference*, not a call) →
/// `(module, func)` — an inner parser passed by reference to a child accessor.
fn cross_module_parse_ref(e: &Expression) -> Option<(String, String)> {
    let (obj, prop) = wa_oxc::as_member(e)?;
    let inner = as_call(obj)?;
    let owner = as_string_lit(arg_expr(inner.arguments.first()?)?)?;
    if !owner.starts_with("WASmaxIn") || !prop.starts_with("parse") {
        return None;
    }
    Some((owner.to_string(), prop.to_string()))
}

/// Analyze a disjunction fn (a `…MixinGroup`/`…Errors`/`parseConfigs` cascade ending
/// in `errorMixinDisjunction`) into ordered union variants. Each cascade arm
/// `var V=o(mod).parseW(node); if(V.success) return {name:"W", value:V.value}` becomes
/// a [`UnionVariant`] whose fields are `parseW`'s resolved fields.
fn analyze_disjunction(fn_src: &str, resolver: &Resolver) -> Vec<UnionVariant> {
    scan_cascade_variants(fn_src)
        .into_iter()
        .map(|(name, module, func)| {
            let fields = match resolver.resolve(&module, &func) {
                Some(Resolved::Fields(f)) => f,
                // A variant that is itself a disjunction (union-of-unions): keep it
                // as a single nested union field rather than flattening.
                Some(Resolved::Union(v)) if !v.is_empty() => vec![ParsedField {
                    name: "value".to_string(),
                    field_type: ParsedFieldType::Union,
                    union_variants: Some(v),
                    required: true,
                    ..Default::default()
                }],
                _ => Vec::new(),
            };
            // The variant parser's same-node guards (`assertTag`, `literal(attr,val)`,
            // `literalContent(val)`) are how a consumer discriminates this variant from
            // its siblings — e.g. a marker like `AdminAddMode` carries only
            // `content == "admin_add"`.
            let assertions = resolver.assertions(&module, &func);
            UnionVariant {
                name,
                fields,
                assertions,
            }
        })
        .collect()
}

/// Scan a first-success cascade — an RPC generator or a disjunction fn — for its
/// ordered `(name, module, func)` arms. Each arm is a `{name:"<NAME>"…}` return
/// preceded by its `o("WASmaxIn<M>").<func>(` parser call. The minified cascade is
/// regular enough to scan textually (shared by the RPC pass and union analysis).
pub(crate) fn scan_cascade_variants(slice: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = slice[from..].find("{name:\"") {
        let name_start = from + rel + "{name:\"".len();
        let Some(q) = slice[name_start..].find('"') else {
            break;
        };
        let name = slice[name_start..name_start + q].to_string();
        if let Some((module, func)) = nearest_parse_call_before(slice, from + rel) {
            out.push((name, module, func));
        }
        from = name_start + q;
    }
    out
}

/// The `(module, func)` of the nearest `o("WASmaxIn<M>").<func>(` call ending before
/// `pos` (the parser whose result the following `{name:…}` arm wraps).
fn nearest_parse_call_before(slice: &str, pos: usize) -> Option<(String, String)> {
    let at = slice[..pos].rfind("o(\"WASmaxIn")?;
    let name_start = at + "o(\"".len();
    let end = slice[name_start..].find('"')?;
    let module = slice[name_start..name_start + end].to_string();
    let after = name_start + end + "\")".len();
    let rest = slice.get(after..)?;
    let dot = rest.strip_prefix('.')?;
    let paren = dot.find('(')?;
    Some((module, dot[..paren].to_string()))
}

/// An accessor passed by reference as the first arg of `optional`/`literal`:
/// `optional(o("WASmaxParseUtils").attrIntRange, …)` → `"attrIntRange"`.
fn inner_accessor_name<'a>(e: &'a Expression<'a>) -> Option<&'a str> {
    // Member expression `o("Mod").method` (not a call — a function reference).
    let (_, prop) = wa_oxc::as_member(e)?;
    Some(prop)
}

/// Resolve the tail `makeResult({...})` / `makeResult(babelHelpers.extends(...))`
/// into the final field list, using the railway bindings (which already carry any
/// cross-module fields/unions resolved at classification time).
fn resolve_tail(
    tail: &Expression,
    bindings: &HashMap<String, Binding>,
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
                Some(Binding::Fields(fields)) => Some(fields.clone()),
                // Delegated child group (`return n.success, n`): lift its fields with
                // the wrapper path so a passthrough mixin's descent isn't lost.
                Some(Binding::ChildGroup {
                    tag,
                    fields,
                    repeats: false,
                    source_path,
                    ..
                }) => Some(lift_child_fields(tag, source_path, fields)),
                Some(Binding::ChildGroup { fields, .. }) => Some(fields.clone()),
                // The whole response delegates to a disjunction: carry it as a
                // single unnamed union field (`value` is the conventional payload key).
                Some(Binding::Union {
                    variants,
                    source_path,
                }) => Some(vec![ParsedField {
                    name: "value".to_string(),
                    field_type: ParsedFieldType::Union,
                    union_variants: Some(variants.clone()),
                    required: true,
                    source_path: opt_vec(source_path.clone()),
                    ..Default::default()
                }]),
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
    resolve_result_arg(arg, bindings)
}

/// Resolve the argument of `makeResult(...)` — an object literal or
/// `babelHelpers.extends(obj, mixin.value, …)`.
fn resolve_result_arg(
    arg: &Expression,
    bindings: &HashMap<String, Binding>,
) -> Option<Vec<ParsedField>> {
    let mut fields = Vec::new();
    match arg {
        Expression::ObjectExpression(_) => {
            collect_object_fields(arg, bindings, &mut fields);
        }
        Expression::CallExpression(c) if callee_method(c) == Some("extends") => {
            // babelHelpers.extends(objLiteral, M1.value, M2.value, …)
            for a in &c.arguments {
                let Some(e) = arg_expr(a) else { continue };
                if matches!(e, Expression::ObjectExpression(_)) {
                    collect_object_fields(e, bindings, &mut fields);
                } else if let Some((var, _)) = value_member(e) {
                    // `Mi.value`/`Ci.value` spread → inline the mixin's or child's
                    // fields at this level (flattened). A delegated child group lifts
                    // its fields with the wrapper path (passthrough descent preserved).
                    let spread: Option<Vec<ParsedField>> = match bindings.get(var) {
                        Some(Binding::Fields(f)) => Some(f.clone()),
                        Some(Binding::ChildGroup {
                            tag,
                            fields,
                            repeats: false,
                            source_path,
                            ..
                        }) => Some(lift_child_fields(tag, source_path, fields)),
                        Some(Binding::ChildGroup { fields, .. }) => Some(fields.clone()),
                        _ => None,
                    };
                    if let Some(src) = spread {
                        for f in src {
                            if !fields.iter().any(|x: &ParsedField| x.name == f.name) {
                                fields.push(f);
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
        // A boolean presence flag: `{hasX: V.success}` or `{hasX: V.value != null}`
        // — the key records whether a sub-node/attr was present, not its value. The
        // wire name (when known) is the underlying accessor's attr.
        if let Some(flag_var) = bool_flag_var(&p.value) {
            out.push(ParsedField {
                name: key.to_string(),
                field_type: ParsedFieldType::Bool,
                wire_name: bindings.get(flag_var).and_then(binding_wire_name),
                required: true,
                ..Default::default()
            });
            continue;
        }
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
                int_range,
                wire_name,
                source_path,
            }) => {
                let (int_min, int_max) = match int_range {
                    Some((min, max)) => (Some(*min), Some(*max)),
                    None => (None, None),
                };
                out.push(ParsedField {
                    method: method.clone(),
                    name: key.to_string(),
                    wire_name: wire_name.clone(),
                    field_type: *field_type,
                    required: *required && !optional,
                    byte_length: *byte_length,
                    int_min,
                    int_max,
                    source_path: source_path.clone(),
                    ..Default::default()
                });
            }
            Some(Binding::ChildGroup {
                tag,
                fields,
                repeats,
                optional: child_optional,
                source_path,
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
                    source_path: opt_vec(source_path.clone()),
                    ..Default::default()
                });
            }
            Some(Binding::Fields(fields)) => {
                // A payload mixin / sub-parser referenced as `{ key: M.value }`: the
                // JS object shape nests M's fields under `key`, so model it as a
                // nested field. `same_node` marks that the children read off the
                // PARENT node (no `<key>` wire element) — the mixin parsed the same
                // node. Nesting (vs flattening) preserves the runtime shape and keeps
                // same-named leaves under distinct keys from colliding (e.g. PreKeys
                // `keyId`/`keyValue` both expose `elementValue`).
                out.push(ParsedField {
                    name: key.to_string(),
                    children: Some(fields.clone()),
                    same_node: true,
                    required: !optional,
                    ..Default::default()
                });
            }
            Some(Binding::Union {
                variants,
                source_path,
            }) => {
                // A disjunction (`…MixinGroup`) referenced as `{ key: G.value }`: a
                // discriminated-union field whose alternatives are the variants.
                out.push(ParsedField {
                    name: key.to_string(),
                    field_type: ParsedFieldType::Union,
                    union_variants: Some(variants.clone()),
                    required: !optional,
                    source_path: opt_vec(source_path.clone()),
                    ..Default::default()
                });
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

/// A makeResult value that is a boolean *presence* flag → the underlying var:
/// `V.success` (a railway success bit) or `V.value != null` / `V.value !== null`
/// (the `optionalLiteral`/`optional` "was it present" idiom). Distinct from a
/// plain `V.value` (the value itself) and from the `V.success ? V.value : null`
/// optional-value ternary.
fn bool_flag_var<'a>(e: &'a Expression<'a>) -> Option<&'a str> {
    // `V.success`
    if let Some((var, prop)) = value_member(e) {
        return (prop == "success").then_some(var);
    }
    // `V.value != null` (null on either side).
    if let Expression::BinaryExpression(b) = e {
        use oxc_ast::ast::BinaryOperator::{Inequality, StrictInequality};
        if !matches!(b.operator, Inequality | StrictInequality) {
            return None;
        }
        let member = if is_nullish(&b.right) {
            &b.left
        } else if is_nullish(&b.left) {
            &b.right
        } else {
            return None;
        };
        if let Some((var, prop)) = value_member(member) {
            return (prop == "value").then_some(var);
        }
    }
    None
}

/// `null` / `undefined` / `void 0`.
fn is_nullish(e: &Expression) -> bool {
    match e {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => {
            matches!(u.operator, oxc_ast::ast::UnaryOperator::Void)
        }
        _ => false,
    }
}

/// The wire attr/content name a binding reads, when it is a single accessor field.
fn binding_wire_name(b: &Binding) -> Option<String> {
    match b {
        Binding::Field { wire_name, .. } => wire_name.clone(),
        _ => None,
    }
}

/// `Vec` → `Option<Vec>` (empty ⇒ `None`), for `source_path` fields.
fn opt_vec(v: Vec<String>) -> Option<Vec<String>> {
    (!v.is_empty()).then_some(v)
}

/// Lift a child group's fields up one level (it is delegated/spread, not nested):
/// each field gains the group's wrapper path (`source_path + [tag]`) as a prefix to
/// its own `source_path`, so a `flattenedChildWithTag` descent inside a passthrough
/// mixin (`…(e,"identity"); return parseKeyDataMixin(t.value)`) is preserved.
fn lift_child_fields(
    tag: &str,
    source_path: &[String],
    fields: &[ParsedField],
) -> Vec<ParsedField> {
    let mut prefix = source_path.to_vec();
    prefix.push(tag.to_string());
    fields
        .iter()
        .map(|f| {
            let mut f = f.clone();
            let mut sp = prefix.clone();
            if let Some(existing) = &f.source_path {
                sp.extend(existing.iter().cloned());
            }
            f.source_path = Some(sp);
            f
        })
        .collect()
}

/// Split a child wire path into `(innermost tag, wrappers above it)`, or `None`
/// when the path is empty (the node is the parent itself — a same-node mixin).
fn split_path(path: &[String]) -> Option<(String, Vec<String>)> {
    path.split_last()
        .map(|(tag, rest)| (tag.clone(), rest.to_vec()))
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
impl Resolver<'_> {
    /// Seed the resolver cache with a pre-resolved cross-module parser (tests only).
    fn seed(&self, module: &str, func: &str, resolved: Resolved) {
        self.cache
            .borrow_mut()
            .insert(format!("{module}::{func}"), Some(resolved));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Analyze a single self-contained parse fn (no cross-module references).
    fn analyze_one(body: &str) -> Option<(Vec<ResponseAssertion>, Vec<ParsedField>)> {
        let slices = HashMap::new();
        let resolver = Resolver::new(&slices);
        analyze_fn_source(body, &LocalFns::new(), &resolver, &mut HashSet::new())
    }

    /// Analyze a module slice with no cross-module references (local parsers only).
    fn analyze_mod_local(module: &str) -> Vec<(String, ParsedResponse)> {
        let slices = HashMap::new();
        let resolver = Resolver::new(&slices);
        analyze_module_exports(module, &resolver)
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
        let (asserts, fields) = analyze_one(body).expect("analyzed");
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
        let (_a, fields) = analyze_one(body).expect("analyzed");
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
        let (_a, fields) = analyze_one(body).expect("analyzed");
        let id = fields.iter().find(|f| f.name == "id").unwrap();
        let name = fields.iter().find(|f| f.name == "name").unwrap();
        assert!(id.required, "plain V.value → required");
        assert!(!name.required, "V.success ? V.value : null → optional");
    }

    /// A one-field same-node mixin, pre-resolved for the seeded-resolver tests.
    fn one_field_mixin(name: &str) -> Resolved {
        Resolved::Fields(vec![ParsedField {
            method: wap::ATTR_STRING.into(),
            name: name.into(),
            field_type: ParsedFieldType::String,
            required: true,
            ..Default::default()
        }])
    }

    #[test]
    fn delegates_to_single_mixin_via_comma() {
        // `return X.success, X` where X is a payload mixin → use the mixin's fields.
        let slices = HashMap::new();
        let resolver = Resolver::new(&slices);
        resolver.seed(
            "WASmaxInMdIQResultResponseMixin",
            "parseIQResultResponseMixin",
            one_field_mixin("from"),
        );
        let body = r#"function e(node, ref){
            var n = o("WASmaxParseUtils").assertTag(node, "iq"); if(!n.success) return n;
            var r = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return r.success, r;
        }"#;
        let (_a, fields) =
            analyze_fn_source(body, &LocalFns::new(), &resolver, &mut HashSet::new())
                .expect("analyzed");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "from");
    }

    #[test]
    fn extends_spread_inlines_mixin_fields() {
        let slices = HashMap::new();
        let resolver = Resolver::new(&slices);
        resolver.seed(
            "WASmaxInMdIQResultResponseMixin",
            "parseIQResultResponseMixin",
            one_field_mixin("type"),
        );
        let body = r#"function e(node, ref){
            var r = o("WASmaxParseUtils").attrString(node, "iso"); if(!r.success) return r;
            var i = o("WASmaxInMdIQResultResponseMixin").parseIQResultResponseMixin(node, ref);
            return i.success ? o("WAResultOrError").makeResult(babelHelpers.extends({ countryCodeIso: r.value }, i.value)) : i;
        }"#;
        let (_a, fields) =
            analyze_fn_source(body, &LocalFns::new(), &resolver, &mut HashSet::new())
                .expect("analyzed");
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"countryCodeIso"));
        assert!(names.contains(&"type"), "mixin fields spread in");
    }

    #[test]
    fn unrecognized_tail_yields_none() {
        let body = r#"function e(node){ return somethingElse(node); }"#;
        assert!(analyze_one(body).is_none());
    }

    #[test]
    fn jid_accessors_keep_their_flavor() {
        // Each JID accessor must yield its specific flavor, not a collapsed `Jid`. The
        // PN-user vs LID-user split is the protocol-safety-critical case.
        let module = r#"__d("WASmaxInFooResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function s(t){
                var r = o("WASmaxParseUtils").assertTag(t, "iq"); if(!r.success) return r;
                var a = o("WASmaxParseUtils").attrUserJid(t, "from"); if(!a.success) return a;
                var b = o("WASmaxParseUtils").attrLidUserJid(t, "lid"); if(!b.success) return b;
                var c = o("WASmaxParseUtils").attrGroupJid(t, "group"); if(!c.success) return c;
                var d = o("WASmaxParseUtils").attrNewsletterJid(t, "nl"); if(!d.success) return d;
                var e = o("WASmaxParseUtils").attrJid(t, "any"); if(!e.success) return e;
                var f = o("WASmaxParseUtils").attrPhoneUserJid(t, "pn"); if(!f.success) return f;
                var g = o("WASmaxParseUtils").attrPhoneDeviceJid(t, "pndev"); if(!g.success) return g;
                var h = o("WASmaxParseUtils").attrPhoneChatJid(t, "pnchat"); if(!h.success) return h;
                return o("WAResultOrError").makeResult({ from: a.value, lid: b.value, group: c.value, nl: d.value, any: e.value, pn: f.value, pndev: g.value, pnchat: h.value });
            }
            l.parseFooResponseSuccess = s;
        }), 1);"#;
        let exports = analyze_mod_local(module);
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseFooResponseSuccess")
            .expect("parser");
        let ft = |name: &str| {
            pr.fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.field_type)
        };
        assert_eq!(ft("from"), Some(ParsedFieldType::UserJid));
        assert_eq!(ft("lid"), Some(ParsedFieldType::LidUserJid));
        assert_eq!(ft("group"), Some(ParsedFieldType::GroupJid));
        assert_eq!(ft("nl"), Some(ParsedFieldType::NewsletterJid));
        // A bare `attrJid` (no single flavor) stays a generic Jid.
        assert_eq!(ft("any"), Some(ParsedFieldType::Jid));
        // The `phone*` aliases are the explicit-PN spelling of the plain accessors.
        assert_eq!(ft("pn"), Some(ParsedFieldType::UserJid));
        assert_eq!(ft("pndev"), Some(ParsedFieldType::DeviceJid));
        assert_eq!(ft("pnchat"), Some(ParsedFieldType::Jid));
    }

    #[test]
    fn int_range_captures_bounds_and_timestamps() {
        let module = r#"__d("WASmaxInBarResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function s(t){
                var r = o("WASmaxParseUtils").assertTag(t, "iq"); if(!r.success) return r;
                var a = o("WASmaxParseUtils").attrIntRange(t, "backoff", 0, 86400); if(!a.success) return a;
                var b = o("WASmaxParseUtils").attrIntRange(t, "ts", 1577865600, 4102473600); if(!b.success) return b;
                var c = o("WASmaxParseUtils").attrIntRange(t, "tsms", 15778656e5, 41024736e5); if(!c.success) return c;
                var d = o("WASmaxParseUtils").optional(o("WASmaxParseUtils").attrIntRange, t, "size", 0, 19999);
                var e = o("WASmaxParseUtils").attrInt(t, "plain"); if(!e.success) return e;
                return o("WAResultOrError").makeResult({ backoff: a.value, ts: b.value, tsms: c.value, size: d.value, plain: e.value });
            }
            l.parseBarResponseSuccess = s;
        }), 1);"#;
        let exports = analyze_mod_local(module);
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseBarResponseSuccess")
            .expect("parser");
        let field = |name: &str| pr.fields.iter().find(|f| f.name == name).expect(name);
        // A bounded integer keeps type Integer and carries its (min, max).
        let bk = field("backoff");
        assert_eq!(bk.field_type, ParsedFieldType::Integer);
        assert_eq!((bk.int_min, bk.int_max), (Some(0), Some(86400)));
        // The timestamp-marker range (seconds) → Timestamp, no bounds carried.
        let ts = field("ts");
        assert_eq!(ts.field_type, ParsedFieldType::Timestamp);
        assert_eq!((ts.int_min, ts.int_max), (None, None));
        // The ×1000 window (written in scientific notation) → TimestampMillis.
        assert_eq!(field("tsms").field_type, ParsedFieldType::TimestampMillis);
        // `optional(attrIntRange, …)` still captures the bounds and stays optional.
        let sz = field("size");
        assert_eq!((sz.int_min, sz.int_max), (Some(0), Some(19999)));
        assert!(!sz.required);
        // A plain attrInt has no bounds.
        let pl = field("plain");
        assert_eq!(pl.field_type, ParsedFieldType::Integer);
        assert_eq!((pl.int_min, pl.int_max), (None, None));
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
        let exports = analyze_mod_local(module);
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
        let (_a, fields) = analyze_one(body).expect("analyzed");
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
        let exports = analyze_mod_local(module);
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
        let exports = analyze_mod_local(module);
        assert!(
            exports
                .iter()
                .any(|(n, _)| n == "parseFooBarResponseSuccess"),
            "comma-sequence export resolved"
        );
    }

    #[test]
    fn scan_cascade_extracts_name_module_func() {
        // A first-success cascade → ordered (name, module, func) triples.
        let s = r#"var t=o("WASmaxInFooAMixin").parseAMixin(e);if(t.success)return o("X").makeResult({name:"A",value:t.value});var n=o("WASmaxInFooBMixin").parseBMixin(e);return n.success?o("X").makeResult({name:"B",value:n.value}):o("U").errorMixinDisjunction(e,["A","B"],[t,n]);"#;
        assert_eq!(
            scan_cascade_variants(s),
            vec![
                ("A".into(), "WASmaxInFooAMixin".into(), "parseAMixin".into()),
                ("B".into(), "WASmaxInFooBMixin".into(), "parseBMixin".into()),
            ]
        );
    }

    #[test]
    fn mixin_group_resolves_to_nested_union_field() {
        // A `…MixinGroup` disjunction over two mixins, consumed as `{bar: G.value}`,
        // becomes a `Union` field whose variants carry each mixin's fields.
        let group = r#"__d("WASmaxInFooBarMixinGroup",["WASmaxParseUtils","WAResultOrError","WASmaxInFooAMixin","WASmaxInFooBMixin"],(function(t,n,r,o,a,i,l){
            function e(e){
                var t=o("WASmaxInFooAMixin").parseAMixin(e);if(t.success)return o("WAResultOrError").makeResult({name:"A",value:t.value});
                var n=o("WASmaxInFooBMixin").parseBMixin(e);return n.success?o("WAResultOrError").makeResult({name:"B",value:n.value}):o("WASmaxParseUtils").errorMixinDisjunction(e,["A","B"],[t,n]);
            }
            l.parseBarMixinGroup=e;
        }),1);"#;
        let amod = r#"__d("WASmaxInFooAMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").attrString(e,"a");if(!s.success)return s;return o("WAResultOrError").makeResult({a:s.value});}
            l.parseAMixin=e;
        }),1);"#;
        let bmod = r#"__d("WASmaxInFooBMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").attrInt(e,"b");if(!s.success)return s;return o("WAResultOrError").makeResult({b:s.value});}
            l.parseBMixin=e;
        }),1);"#;
        let resp = r#"function e(node){
            var g=o("WASmaxInFooBarMixinGroup").parseBarMixinGroup(node);
            return g.success?o("WAResultOrError").makeResult({bar:g.value}):g;
        }"#;
        let slices = HashMap::from([
            ("WASmaxInFooBarMixinGroup", group),
            ("WASmaxInFooAMixin", amod),
            ("WASmaxInFooBMixin", bmod),
        ]);
        let resolver = Resolver::new(&slices);
        let (_a, fields) =
            analyze_fn_source(resp, &LocalFns::new(), &resolver, &mut HashSet::new())
                .expect("analyzed");
        assert_eq!(fields.len(), 1);
        let bar = &fields[0];
        assert_eq!(bar.name, "bar");
        assert_eq!(bar.field_type, ParsedFieldType::Union);
        let vars = bar.union_variants.as_ref().expect("union variants");
        assert_eq!(
            vars.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["A", "B"]
        );
        assert!(vars[0].fields.iter().any(|f| f.name == "a"));
        assert!(vars[1].fields.iter().any(|f| f.name == "b"));
    }

    #[test]
    fn cross_module_same_node_parser_nests_under_key() {
        // A cross-module sub-parser on the same node (`{configs: o(mod).parseConfigs(e)}`)
        // that resolves to a flat field list nests under the key with `same_node`
        // (matches the JS object shape; the children read off the parent node).
        let cfg = r#"__d("WASmaxInFooConfigs",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").attrString(e,"k");if(!s.success)return s;return o("WAResultOrError").makeResult({k:s.value});}
            l.parseConfigs=e;
        }),1);"#;
        let resp = r#"function e(node){var n=o("WASmaxInFooConfigs").parseConfigs(node);return n.success?o("WAResultOrError").makeResult({configs:n.value}):n;}"#;
        let slices = HashMap::from([("WASmaxInFooConfigs", cfg)]);
        let resolver = Resolver::new(&slices);
        let (_a, fields) =
            analyze_fn_source(resp, &LocalFns::new(), &resolver, &mut HashSet::new())
                .expect("analyzed");
        assert_eq!(fields.len(), 1);
        let configs = &fields[0];
        assert_eq!(configs.name, "configs");
        assert!(
            configs.same_node,
            "same-node mixin nests with same_node=true"
        );
        assert!(
            configs
                .children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "k")),
            "mixin fields nested under the key"
        );
    }

    #[test]
    fn nested_keyed_mixins_keep_same_named_leaves_distinct() {
        // Two sub-mixins both expose a field named `elementValue`; nesting under
        // distinct keys must keep both (the flatten-dedup bug dropped one).
        let idm = r#"__d("WASmaxInFooIdMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").contentBytesRange(e,3,3);return s.success?o("WAResultOrError").makeResult({elementValue:s.value}):s;}
            l.parseIdMixin=e;
        }),1);"#;
        let datam = r#"__d("WASmaxInFooDataMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").contentBytesRange(e,32,32);return s.success?o("WAResultOrError").makeResult({elementValue:s.value}):s;}
            l.parseDataMixin=e;
        }),1);"#;
        let resp = r#"function e(node){
            var a=o("WASmaxInFooIdMixin").parseIdMixin(node);
            var b=o("WASmaxInFooDataMixin").parseDataMixin(node);
            return b.success?o("WAResultOrError").makeResult({keyId:a.value,keyValue:b.value}):b;
        }"#;
        let slices = HashMap::from([("WASmaxInFooIdMixin", idm), ("WASmaxInFooDataMixin", datam)]);
        let resolver = Resolver::new(&slices);
        let (_a, fields) =
            analyze_fn_source(resp, &LocalFns::new(), &resolver, &mut HashSet::new())
                .expect("analyzed");
        let key_id = fields.iter().find(|f| f.name == "keyId").expect("keyId");
        let key_value = fields
            .iter()
            .find(|f| f.name == "keyValue")
            .expect("keyValue");
        assert!(
            key_id
                .children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "elementValue"))
        );
        assert!(
            key_value
                .children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "elementValue")),
            "second same-named leaf survives under its own key"
        );
    }

    #[test]
    fn mixin_on_flattened_child_becomes_tagged_child() {
        // `r=flattenedChildWithTag(e,"opts"); a=o(mod).parseMixin(r.value); {key:a.value}`
        // → a `<opts>`-tagged child field, NOT a same-node mixin. The exported fn is
        // minified `function e(e,t)` so its node param `e` shadows the local fn `e`
        // — the bare-descend node arg must not be mistaken for the inner parser.
        let mixin = r#"__d("WASmaxInFooOptsMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").contentBytesRange(e,1,4096);return s.success?o("WAResultOrError").makeResult({elementValue:s.value}):s;}
            l.parseOptsMixin=e;
        }),1);"#;
        let resp_mod = r#"__d("WASmaxInFooGetOptsResponseSuccess",["WASmaxParseUtils","WASmaxInFooOptsMixin","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e,t){
                var n=o("WASmaxParseUtils").assertTag(e,"iq");if(!n.success)return n;
                var r=o("WASmaxParseUtils").flattenedChildWithTag(e,"opts");if(!r.success)return r;
                var a=o("WASmaxInFooOptsMixin").parseOptsMixin(r.value);if(!a.success)return a;
                return o("WAResultOrError").makeResult(babelHelpers.extends({optsMixin:a.value},{}));
            }
            l.parseGetOptsResponseSuccess=e;
        }),1);"#;
        let slices = HashMap::from([
            ("WASmaxInFooOptsMixin", mixin),
            ("WASmaxInFooGetOptsResponseSuccess", resp_mod),
        ]);
        let resolver = Resolver::new(&slices);
        let exports = analyze_module_exports(resp_mod, &resolver);
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseGetOptsResponseSuccess")
            .expect("exported parser");
        assert_eq!(pr.fields.len(), 1);
        let opts = &pr.fields[0];
        assert_eq!(opts.name, "optsMixin");
        assert_eq!(
            opts.tag.as_deref(),
            Some("opts"),
            "mixin on flattenedChildWithTag node is a tagged child, not same_node"
        );
        assert!(!opts.same_node);
        assert!(
            opts.children
                .as_ref()
                .is_some_and(|k| k.iter().any(|f| f.name == "elementValue"))
        );
    }

    #[test]
    fn passthrough_mixin_lifts_wrapper_onto_delegated_fields() {
        // A mixin that descends `flattenedChildWithTag(e,"identity")` then RETURNS a
        // sub-mixin's result directly (`return n.success, n`, no own makeResult key)
        // must still attribute the sub-mixin's fields to `<identity>`.
        let data = r#"__d("WASmaxInFooKeyDataMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").contentBytesRange(e,32,32);return s.success?o("WAResultOrError").makeResult({elementValue:s.value}):s;}
            l.parseKeyDataMixin=e;
        }),1);"#;
        let identity = r#"__d("WASmaxInFooIdentityKeyMixin",["WASmaxParseUtils","WASmaxInFooKeyDataMixin","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var t=o("WASmaxParseUtils").flattenedChildWithTag(e,"identity");if(!t.success)return t;var n=o("WASmaxInFooKeyDataMixin").parseKeyDataMixin(t.value);return n.success,n;}
            l.parseIdentityKeyMixin=e;
        }),1);"#;
        let slices = HashMap::from([
            ("WASmaxInFooKeyDataMixin", data),
            ("WASmaxInFooIdentityKeyMixin", identity),
        ]);
        let resolver = Resolver::new(&slices);
        let Resolved::Fields(fields) = resolver
            .resolve("WASmaxInFooIdentityKeyMixin", "parseIdentityKeyMixin")
            .expect("resolved")
        else {
            panic!("expected Fields");
        };
        let ev = fields
            .iter()
            .find(|f| f.name == "elementValue")
            .expect("elementValue");
        assert_eq!(
            ev.source_path.as_deref(),
            Some(["identity".to_string()].as_slice()),
            "passthrough mixin lifts the <identity> wrapper onto the delegated field"
        );
    }

    #[test]
    fn repeated_child_under_wrapper_records_source_path() {
        // `a=flattenedChildWithTag(t,"list"); mapChildrenWithTag(a.value,"user",0,N,e)`
        // → a repeated `<user>` child with source_path ["list"] (the wrapper above it).
        let module = r#"__d("WASmaxInFooGetUsersResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxParseUtils").attrString(e,"jid");if(!s.success)return s;return o("WAResultOrError").makeResult({jid:s.value});}
            function s(t,n){
                var r=o("WASmaxParseUtils").assertTag(t,"iq");if(!r.success)return r;
                var a=o("WASmaxParseUtils").flattenedChildWithTag(t,"list");if(!a.success)return a;
                var d=o("WASmaxParseUtils").mapChildrenWithTag(a.value,"user",0,1e5,e);
                return d.success?o("WAResultOrError").makeResult({listUser:d.value}):d;
            }
            l.parseGetUsersResponseSuccessUser=e, l.parseGetUsersResponseSuccess=s;
        }),1);"#;
        let slices = HashMap::new();
        let resolver = Resolver::new(&slices);
        let exports = analyze_module_exports(module, &resolver);
        let (_n, pr) = exports
            .iter()
            .find(|(n, _)| n == "parseGetUsersResponseSuccess")
            .expect("exported parser");
        let lu = pr
            .fields
            .iter()
            .find(|f| f.name == "listUser")
            .expect("listUser");
        assert_eq!(lu.tag.as_deref(), Some("user"));
        assert_eq!(lu.repeats, Some(true));
        assert_eq!(
            lu.source_path.as_deref(),
            Some(["list".to_string()].as_slice()),
            "the <list> wrapper above the repeated <user> child is captured"
        );
    }

    #[test]
    fn nested_flattened_child_chain_accumulates_path() {
        // `t=flattenedChildWithTag(e,"key"); n=flattenedChildWithTag(t.value,"id");
        //  a=attrString(n.value,"x")` → x has source_path ["key","id"].
        let body = r#"function e(e){
            var t=o("WASmaxParseUtils").flattenedChildWithTag(e,"key");if(!t.success)return t;
            var n=o("WASmaxParseUtils").flattenedChildWithTag(t.value,"id");if(!n.success)return n;
            var a=o("WASmaxParseUtils").attrString(n.value,"x");
            return a.success?o("WAResultOrError").makeResult({x:a.value}):a;
        }"#;
        let (_a, fields) = analyze_one(body).expect("analyzed");
        let x = fields.iter().find(|f| f.name == "x").expect("x");
        assert_eq!(
            x.source_path.as_deref(),
            Some(["key".to_string(), "id".to_string()].as_slice())
        );
    }

    #[test]
    fn attr_off_flattened_child_records_source_path() {
        // A mixin that descends `flattenedChildWithTag(e,"report")` then reads
        // `attrString(n.value,"id")` → the field records source_path=["report"] so
        // it is read off `<report>`, not the parent node.
        let mixin = r#"__d("WASmaxInFooReportIdMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){
                var t=o("WASmaxParseUtils").assertTag(e,"iq");if(!t.success)return t;
                var n=o("WASmaxParseUtils").flattenedChildWithTag(e,"report");if(!n.success)return n;
                var r=o("WASmaxParseUtils").attrString(n.value,"id");
                return r.success?o("WAResultOrError").makeResult({reportId:r.value}):r;
            }
            l.parseReportIdMixin=e;
        }),1);"#;
        let slices = HashMap::from([("WASmaxInFooReportIdMixin", mixin)]);
        let resolver = Resolver::new(&slices);
        let Resolved::Fields(fields) = resolver
            .resolve("WASmaxInFooReportIdMixin", "parseReportIdMixin")
            .expect("resolved")
        else {
            panic!("expected Fields");
        };
        let report_id = fields
            .iter()
            .find(|f| f.name == "reportId")
            .expect("reportId");
        assert_eq!(report_id.wire_name.as_deref(), Some("id"));
        assert_eq!(
            report_id.source_path.as_deref(),
            Some(["report".to_string()].as_slice())
        );
    }

    #[test]
    fn boolean_presence_flags_become_bool_fields() {
        // `{hasA: c.success}` and `{hasB: p.value != null}` → Bool fields, the latter
        // carrying the underlying optional accessor's wire name.
        let body = r#"function e(node){
            var c = o("WASmaxParseUtils").attrString(node, "id"); if(!c.success) return c;
            var p = o("WASmaxParseUtils").optionalLiteral(o("WASmaxParseUtils").attrString, node, "c_dhash", "x");
            return o("WAResultOrError").makeResult({ id: c.value, hasA: c.success, hasB: p.value != null });
        }"#;
        let (_a, fields) = analyze_one(body).expect("analyzed");
        let has_a = fields.iter().find(|f| f.name == "hasA").expect("hasA");
        assert_eq!(has_a.field_type, ParsedFieldType::Bool);
        let has_b = fields.iter().find(|f| f.name == "hasB").expect("hasB");
        assert_eq!(has_b.field_type, ParsedFieldType::Bool);
        assert_eq!(has_b.wire_name.as_deref(), Some("c_dhash"));
    }

    #[test]
    fn import_cycle_does_not_loop() {
        // Two modules whose parsers reference each other cross-module: the resolver
        // must terminate (cycle guard) rather than recurse forever.
        let a = r#"__d("WASmaxInCycA",["WASmaxParseUtils","WAResultOrError","WASmaxInCycB"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxInCycB").parseB(e);return s.success?o("WAResultOrError").makeResult({b:s.value}):s;}
            l.parseA=e;
        }),1);"#;
        let b = r#"__d("WASmaxInCycB",["WASmaxParseUtils","WAResultOrError","WASmaxInCycA"],(function(t,n,r,o,a,i,l){
            function e(e){var s=o("WASmaxInCycA").parseA(e);return s.success?o("WAResultOrError").makeResult({a:s.value}):s;}
            l.parseB=e;
        }),1);"#;
        let slices = HashMap::from([("WASmaxInCycA", a), ("WASmaxInCycB", b)]);
        let resolver = Resolver::new(&slices);
        // Just needs to terminate; the cycle collapses to no resolvable fields.
        let _ = resolver.resolve("WASmaxInCycA", "parseA");
    }

    #[test]
    fn captures_literal_value_assertion_and_bubbles_same_node_mixin() {
        // A success parser pins `type:"result"` directly; an error parser inherits
        // `type:"error"` from a same-node mixin it calls — both must surface as the
        // variant's discriminating assertion.
        let success = r#"__d("WASmaxInFooGetResponseSuccess",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(t,n){
                var r=o("WASmaxParseUtils").assertTag(t,"iq");if(!r.success)return r;
                var s=o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString,t,"type","result");
                return s.success?o("WAResultOrError").makeResult({type:s.value}):s;
            }
            l.parseGetResponseSuccess=e;
        }),1);"#;
        let errmixin = r#"__d("WASmaxInFooIQErrorResponseMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e,t){
                var r=o("WASmaxParseUtils").assertTag(e,"iq");if(!r.success)return r;
                var s=o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString,e,"type","error");
                return s.success?o("WAResultOrError").makeResult({type:s.value}):s;
            }
            l.parseIQErrorResponseMixin=e;
        }),1);"#;
        let error = r#"__d("WASmaxInFooGetResponseError",["WASmaxParseUtils","WASmaxInFooIQErrorResponseMixin","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e,t){
                var r=o("WASmaxParseUtils").assertTag(e,"iq");if(!r.success)return r;
                var m=o("WASmaxInFooIQErrorResponseMixin").parseIQErrorResponseMixin(e,t);if(!m.success)return m;
                var c=o("WASmaxParseUtils").attrString(e,"code");
                return c.success?o("WAResultOrError").makeResult({code:c.value}):c;
            }
            l.parseGetResponseError=e;
        }),1);"#;
        let slices = HashMap::from([
            ("WASmaxInFooGetResponseSuccess", success),
            ("WASmaxInFooIQErrorResponseMixin", errmixin),
            ("WASmaxInFooGetResponseError", error),
        ]);
        let resolver = Resolver::new(&slices);
        let has_type = |asserts: &[ResponseAssertion], val: &str| {
            asserts.iter().any(|a| {
                a.kind == AssertionKind::Attr
                    && a.name.as_deref() == Some("type")
                    && a.value.as_deref() == Some(val)
            })
        };
        let sa = resolver.assertions("WASmaxInFooGetResponseSuccess", "parseGetResponseSuccess");
        assert!(
            has_type(&sa, "result"),
            "success asserts type=result: {sa:?}"
        );
        let ea = resolver.assertions("WASmaxInFooGetResponseError", "parseGetResponseError");
        assert!(
            has_type(&ea, "error"),
            "error bubbles type=error from same-node mixin: {ea:?}"
        );
        // The duplicate `assertTag(e,"iq")` (direct + bubbled) is collapsed.
        assert_eq!(
            ea.iter()
                .filter(|a| a.kind == AssertionKind::Tag && a.name.as_deref() == Some("iq"))
                .count(),
            1,
            "duplicate tag assertion deduped: {ea:?}"
        );
    }

    #[test]
    fn marker_union_variants_capture_content_discriminator() {
        // A MixinGroup of marker variants discriminated by node content
        // (`literalContent(content, e, "admin_add")`) — the content value must be
        // captured as the variant's discriminator, and the fallback (plain
        // `contentString`) carries none.
        let admin = r#"__d("WASmaxInGAdminAddModeMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var t=o("WASmaxParseUtils").assertTag(e,"member_add_mode");if(!t.success)return t;var n=o("WASmaxParseUtils").literalContent(o("WASmaxParseUtils").contentString,e,"admin_add");return n.success?o("WAResultOrError").makeResult({}):n;}
            l.parseAdminAddModeMixin=e;
        }),1);"#;
        let unknown = r#"__d("WASmaxInGUnknownAddModeMixin",["WASmaxParseUtils","WAResultOrError"],(function(t,n,r,o,a,i,l){
            function e(e){var t=o("WASmaxParseUtils").assertTag(e,"member_add_mode");if(!t.success)return t;var n=o("WASmaxParseUtils").contentString(e);return n.success?o("WAResultOrError").makeResult({elementValue:n.value}):n;}
            l.parseUnknownAddModeMixin=e;
        }),1);"#;
        let group = r#"__d("WASmaxInGMemberAddModes",["WAResultOrError","WASmaxInGAdminAddModeMixin","WASmaxInGUnknownAddModeMixin","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){
            function e(e){var t=o("WASmaxInGAdminAddModeMixin").parseAdminAddModeMixin(e);if(t.success)return o("WAResultOrError").makeResult({name:"AdminAddMode",value:t.value});var n=o("WASmaxInGUnknownAddModeMixin").parseUnknownAddModeMixin(e);return n.success?o("WAResultOrError").makeResult({name:"UnknownAddMode",value:n.value}):o("WASmaxParseUtils").errorMixinDisjunction(e,["AdminAddMode","UnknownAddMode"]);}
            l.parseMemberAddModes=e;
        }),1);"#;
        let slices = HashMap::from([
            ("WASmaxInGAdminAddModeMixin", admin),
            ("WASmaxInGUnknownAddModeMixin", unknown),
            ("WASmaxInGMemberAddModes", group),
        ]);
        let resolver = Resolver::new(&slices);
        let Some(Resolved::Union(variants)) =
            resolver.resolve("WASmaxInGMemberAddModes", "parseMemberAddModes")
        else {
            panic!("expected a union");
        };
        let admin_v = variants
            .iter()
            .find(|v| v.name == "AdminAddMode")
            .expect("admin");
        assert!(
            admin_v.assertions.iter().any(
                |a| a.kind == AssertionKind::Content && a.value.as_deref() == Some("admin_add")
            ),
            "marker variant captures its content discriminator: {:?}",
            admin_v.assertions
        );
        let unknown_v = variants
            .iter()
            .find(|v| v.name == "UnknownAddMode")
            .expect("unknown");
        assert!(
            !unknown_v
                .assertions
                .iter()
                .any(|a| a.kind == AssertionKind::Content),
            "the plain-content fallback carries no content discriminator: {:?}",
            unknown_v.assertions
        );
    }
}
