//! Constant content-value cross-reference.
//!
//! A request builder writes a leaf value opaquely — `smax("link_code_pairing_nonce",
//! null, t)` where `t = e.linkCodePairingNonceElementValue` — so the *value* isn't in
//! the builder; it lives at the distant call site
//! (`sendCompanionHelloRPC({ …: { linkCodePairingNonceElementValue: new Uint8Array(1) }})`).
//! That `new Uint8Array(1)` is a compile-time constant: one `0x00` byte. A consumer
//! hand-writing this field can't tell it from any other 1-byte value (WhatsApp's own
//! Go client shipped `[]byte("0")` = `0x30` here), and byte length alone can't catch
//! it — both are one byte. Pinning the *value* does.
//!
//! Precision rests on double unanimity, so a guessed value is never emitted:
//!  1. **Per argument** (`collect_arg_consts`): a smax content-arg name
//!     (`…ElementValue`) resolves to a constant only if *every* object-literal that
//!     assigns it across the bundle is the same `new Uint8Array(N)`. One dissenting
//!     assignment (a variable, a string, a different N) drops it — `titleElementValue`
//!     (7 different values) and `actionElementValue` (`"waffle_1"` vs `"waffle_100"`)
//!     are excluded automatically.
//!  2. **Per tag** (`collect_tag_consts`): a tag maps to a constant only if every
//!     builder emitting that tag feeds it the same constant arg and none feeds it
//!     dynamic content.
//!
//! Scope is deliberately narrow: only `new Uint8Array(N)` (a zero-filled buffer) fed
//! through a `…ElementValue` smax argument. Inline string literals are already
//! captured directly by the builder resolver; the crypto idiom `var t =
//! new Uint8Array(1); crypto.getRandomValues(t)` uses a *variable* (not an inline
//! object-property value) and so never matches — its bytes are random, not constant.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, CallExpression, Expression, FormalParameters, Function,
    ObjectExpression, VariableDeclaration,
};
use oxc_ast_visit::{Visit, walk};
use oxc_syntax::scope::ScopeFlags;
use wa_ir::{WapChildNode, WapContentKind};
use wa_transform::ModuleDefinition;

use wa_oxc::{arg_expr, as_int, as_member, as_string_lit, callee_method, obj_props};

/// Suffix every smax content-argument name carries (`linkCodePairingNonceElementValue`,
/// `titleElementValue`, …). Identifies a candidate builder argument (an object-literal
/// property or a `e.<arg>` content reference). In Pass 1 it also gates which modules
/// are re-parsed — a module mentioning any `*ElementValue` name necessarily contains
/// the substring, so no assignment of a candidate argument is filtered away (which
/// would break the global unanimity guard). Pass 2, by contrast, filters by the
/// *builders* (`.smax(`/`.wap(`), since per-tag unanimity must see every builder of a
/// tag, not only the ones that happen to use an `…ElementValue` argument.
const ARG_SUFFIX: &str = "ElementValue";

/// The smax/wap element-content builders whose 3rd argument is the leaf value.
const CONTENT_BUILDERS: [&str; 2] = ["smax", "wap"];

/// A statically-resolved constant content value. Only zero-filled byte buffers today
/// (the real gap); string constants are already captured inline by the builder
/// resolver.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum ConstValue {
    /// `new Uint8Array(N)` → `N` bytes, all `0x00`.
    ZeroBytes(u32),
}

/// `tag` → the constant value every builder writes as its content, plus the smax
/// content-argument name it was resolved from (its provenance).
#[derive(Default)]
pub struct ConstValueIndex {
    by_tag: BTreeMap<String, (ConstValue, String)>,
}

impl ConstValueIndex {
    fn get(&self, tag: &str) -> Option<(&ConstValue, &str)> {
        self.by_tag.get(tag).map(|(cv, src)| (cv, src.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// Build the index over every module whose slice mentions a `…ElementValue` argument.
pub(crate) fn build_pass(defs: &[ModuleDefinition], source: &str) -> ConstValueIndex {
    let arg_consts = collect_arg_consts(defs, source);
    collect_tag_consts(defs, source, &arg_consts)
}

/// Upper bound on a recognized constant byte buffer. Real stanza leaves are tiny (a
/// nonce is one byte; the largest sized wire field is a few hundred bytes), so a
/// `new Uint8Array(N)` beyond this is a minifier artifact or an intentionally huge
/// allocation, not a wire constant — treated as unrecognized (never materialized, so
/// the hex expansion can't allocate an unbounded string).
const MAX_CONST_BYTES: i64 = 4096;

/// The `new Uint8Array(N)` length of an expression, if it is exactly that (a single
/// numeric argument within [`MAX_CONST_BYTES`]). `new Uint8Array(someVar)` /
/// `new Uint8Array([1,2])` / an out-of-range `N` / any other callee return `None`.
fn zero_bytes_of(e: &Expression) -> Option<u32> {
    let Expression::NewExpression(n) = e else {
        return None;
    };
    let Expression::Identifier(id) = &n.callee else {
        return None;
    };
    if id.name.as_str() != "Uint8Array" || n.arguments.len() != 1 {
        return None;
    }
    let len = n.arguments.first().and_then(arg_expr).and_then(as_int)?;
    if !(0..=MAX_CONST_BYTES).contains(&len) {
        return None;
    }
    u32::try_from(len).ok()
}

// ---- Pass 1: argument name → constant value (global unanimity) ------------------

/// Accumulated evidence for one `…ElementValue` argument name across the bundle.
#[derive(Default)]
struct ArgAgg {
    /// Distinct `new Uint8Array(N)` lengths assigned to this name.
    zero_byte_lengths: BTreeSet<u32>,
    /// Whether the name was ever assigned something that is *not* a `new Uint8Array(N)`
    /// (a variable, a string, a call, …) — which disqualifies it from being constant.
    saw_non_const: bool,
}

/// Scan every object literal for `…ElementValue: <value>` and keep a name only if every
/// assignment agrees on the same `new Uint8Array(N)` and nothing else.
fn collect_arg_consts(defs: &[ModuleDefinition], source: &str) -> HashMap<String, ConstValue> {
    let mut agg: HashMap<String, ArgAgg> = HashMap::new();
    let mut scanned = HashSet::new();
    for m in defs {
        if !scanned.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        if !slice.contains(ARG_SUFFIX) {
            continue;
        }
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, slice);
        if ret.panicked {
            continue;
        }
        let mut c = ArgCollector { agg: &mut agg };
        c.visit_program(&ret.program);
    }

    agg.into_iter()
        .filter_map(|(name, a)| {
            // Exactly one byte length, seen only as a byte constant, everywhere.
            if a.saw_non_const {
                return None;
            }
            match (a.zero_byte_lengths.len(), a.zero_byte_lengths.iter().next()) {
                (1, Some(&n)) => Some((name, ConstValue::ZeroBytes(n))),
                _ => None,
            }
        })
        .collect()
}

struct ArgCollector<'m> {
    agg: &'m mut HashMap<String, ArgAgg>,
}

impl<'a> Visit<'a> for ArgCollector<'_> {
    fn visit_object_expression(&mut self, obj: &ObjectExpression<'a>) {
        for (name, value) in obj_props(obj) {
            if !name.ends_with(ARG_SUFFIX) {
                continue;
            }
            let entry = self.agg.entry(name.to_string()).or_default();
            match zero_bytes_of(value) {
                Some(n) => {
                    entry.zero_byte_lengths.insert(n);
                }
                None => entry.saw_non_const = true,
            }
        }
        walk::walk_object_expression(self, obj);
    }
}

// ---- Pass 2: tag → constant value (per-tag unanimity over builders) -------------

/// The content a builder feeds a tag, as observed at one `smax`/`wap` call site.
enum Content {
    /// The content is `e.<argName>` (directly or via a `var t = e.<argName>` local).
    Arg(String),
    /// The content is anything else (a variable, a call, a nested node, …).
    Dynamic,
}

/// Scan every builder-bearing module (`.smax(`/`.wap(`) for `smax("tag", attrs,
/// <content>)` and keep a tag only if every builder feeds it the same constant
/// argument and none feeds it dynamic content.
fn collect_tag_consts(
    defs: &[ModuleDefinition],
    source: &str,
    arg_consts: &HashMap<String, ConstValue>,
) -> ConstValueIndex {
    // tag → distinct constant values seen, whether any builder fed it dynamic content,
    // and the first argument name that pinned it (for provenance).
    let mut consts: BTreeMap<String, BTreeSet<ConstValue>> = BTreeMap::new();
    let mut dynamic: BTreeSet<String> = BTreeSet::new();
    let mut arg_source: BTreeMap<String, String> = BTreeMap::new();
    let mut scanned = HashSet::new();

    for m in defs {
        if !scanned.insert(m.name.as_str()) {
            continue;
        }
        // Filter by the *builders* (`.smax(`/`.wap(`), NOT by `ElementValue`. Per-tag
        // unanimity must see EVERY builder of a candidate tag — including one in a
        // module with no `…ElementValue` argument that feeds the same tag dynamic
        // content. Filtering by the argument suffix here would hide that dissenting
        // builder and could wrongly promote the tag to a constant.
        let slice = &source[m.start..m.end];
        if !slice.contains(".smax(") && !slice.contains(".wap(") {
            continue;
        }
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, slice);
        if ret.panicked {
            continue;
        }
        let mut c = TagCollector {
            local_args: HashMap::new(),
            out: Vec::new(),
        };
        c.visit_program(&ret.program);
        for (tag, content) in c.out {
            match content {
                Content::Arg(arg) => match arg_consts.get(&arg) {
                    Some(cv) => {
                        consts.entry(tag.clone()).or_default().insert(cv.clone());
                        arg_source.entry(tag).or_insert(arg);
                    }
                    // A builder argument that isn't a proven constant makes the tag
                    // non-uniform → dynamic.
                    None => {
                        dynamic.insert(tag);
                    }
                },
                Content::Dynamic => {
                    dynamic.insert(tag);
                }
            }
        }
    }

    let mut index = ConstValueIndex::default();
    for (tag, values) in consts {
        if dynamic.contains(&tag) {
            continue;
        }
        if let (1, Some(cv)) = (values.len(), values.iter().next())
            && let Some(src) = arg_source.remove(&tag)
        {
            index.by_tag.insert(tag, (cv.clone(), src));
        }
    }
    index
}

struct TagCollector {
    /// Per-function local: `t` bound by `var t = <obj>.<argName>` → `argName`.
    local_args: HashMap<String, String>,
    out: Vec<(String, Content)>,
}

impl<'a> Visit<'a> for TagCollector {
    // Scope the `var t = e.arg` bindings to their function, so a local named `t` in one
    // builder is never read as another builder's binding (mirrors the length index).
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let outer = self.local_args.clone();
        shadow_params(&mut self.local_args, &func.params);
        walk::walk_function(self, func, flags);
        self.local_args = outer;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let outer = self.local_args.clone();
        shadow_params(&mut self.local_args, &arrow.params);
        walk::walk_arrow_function_expression(self, arrow);
        self.local_args = outer;
    }

    // Restore the binding map on leaving a nested block so a block-scoped `let`/`const`
    // alias (`if (x) { let t = e.fooElementValue; }`) can't leak past its block and be
    // read by a later `smax(…, t)`. A function-scoped `var` at the function's top level
    // lives in the `FunctionBody` (not a `BlockStatement`), so it is unaffected; a `var`
    // inside a nested block is conservatively confined too (a false negative — never a
    // wrong value). Matches the fail-safe stance: ambiguity drops, it never guesses.
    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        let outer = self.local_args.clone();
        walk::walk_block_statement(self, block);
        self.local_args = outer;
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let Some(name) = d.id.get_identifier_name() {
                match d.init.as_ref().and_then(arg_name_of) {
                    // `var t = e.linkCodePairingNonceElementValue` → track `t`.
                    Some(arg) => {
                        self.local_args.insert(name.as_str().to_string(), arg);
                    }
                    // Reused for something else → drop any stale binding.
                    None => {
                        self.local_args.remove(name.as_str());
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(method) = callee_method(call)
            && CONTENT_BUILDERS.contains(&method)
            // Exactly (tag, attrs, content): a leaf value, not a container with children.
            && call.arguments.len() == 3
            && let Some(tag) = call.arguments.first().and_then(arg_expr).and_then(as_string_lit)
            && let Some(content_expr) = call.arguments.get(2).and_then(arg_expr)
        {
            let content = self.classify_content(content_expr);
            self.out.push((tag.to_string(), content));
        }
        walk::walk_call_expression(self, call);
    }
}

impl TagCollector {
    /// The content a builder's 3rd argument represents: a resolvable `…ElementValue`
    /// argument (directly `e.arg` or via a tracked `var t = e.arg`), else dynamic.
    fn classify_content(&self, e: &Expression) -> Content {
        if let Expression::Identifier(id) = e {
            return match self.local_args.get(id.name.as_str()) {
                Some(arg) => Content::Arg(arg.clone()),
                None => Content::Dynamic,
            };
        }
        match arg_name_of(e) {
            Some(arg) => Content::Arg(arg),
            None => Content::Dynamic,
        }
    }
}

/// The `…ElementValue` property name of a member expression (`e.linkCodePairing…`), if
/// it is one whose property carries the smax content-argument suffix.
fn arg_name_of(e: &Expression) -> Option<String> {
    let (_, prop) = as_member(e)?;
    prop.ends_with(ARG_SUFFIX).then(|| prop.to_string())
}

/// Remove a nested function's parameter names from the (copied) binding map so a
/// parameter shadows — never inherits — an outer binding of the same name. Covers
/// destructured params via `get_binding_identifiers`.
fn shadow_params(local_args: &mut HashMap<String, String>, params: &FormalParameters) {
    let mut remove_bound = |pattern: &oxc_ast::ast::BindingPattern| {
        for ident in pattern.get_binding_identifiers() {
            local_args.remove(ident.name.as_str());
        }
    };
    for p in &params.items {
        remove_bound(&p.pattern);
    }
    if let Some(rest) = &params.rest {
        remove_bound(&rest.rest.argument);
    }
}

// ---- Enrichment -----------------------------------------------------------------

/// Cross-reference each constant leaf value onto the request tree: for a leaf whose
/// tag has a proven constant, pin the bytes + provenance. Two cases:
///  - the leaf has opaque (`Dynamic`) content → fill it in place;
///  - the leaf has *no* content because the builder passed a bare local
///    (`smax("…", null, t)`, which the resolver leaves contentless) → create it, but
///    only when the node is a genuine leaf (no children, no variant groups), never on
///    a container.
///
/// A value the builder already resolved (`Const`/`Bytes`) is always left untouched.
/// Recurses into children and mutually-exclusive variant groups.
pub(crate) fn enrich(children: &mut [WapChildNode], index: &ConstValueIndex) {
    if index.is_empty() {
        return;
    }
    for node in children {
        if let Some((cv, src)) = index.get(&node.tag) {
            let is_leaf = node.children.is_empty() && node.variant_groups.is_empty();
            let should_fill = match &node.content {
                // Fill only opaque content; a builder-pinned value wins.
                Some(c) => {
                    c.kind == WapContentKind::Dynamic
                        && c.value.is_none()
                        && c.const_bytes.is_none()
                }
                // Create content only on a true leaf (a bare-local `smax` value).
                None => is_leaf,
            };
            if should_fill {
                let content = node.content.get_or_insert_with(Default::default);
                match cv {
                    ConstValue::ZeroBytes(n) => {
                        content.kind = WapContentKind::Bytes;
                        content.const_bytes = Some("00".repeat(*n as usize));
                        if content.byte_length.is_none() {
                            content.byte_length = Some(*n);
                        }
                        content.value_source = Some(format!("const:{src}"));
                    }
                }
            }
        }
        enrich(&mut node.children, index);
        for group in &mut node.variant_groups {
            for variant in &mut group.variants {
                enrich(&mut variant.children, index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(bundle: &str) -> ConstValueIndex {
        let defs = wa_transform::extract_module_definitions(bundle);
        build_pass(&defs, bundle)
    }

    /// The real shape: a builder reads `e.<arg>` into a local and feeds it to `smax`,
    /// and a distant call site assigns that arg `new Uint8Array(1)`.
    #[test]
    fn resolves_nonce_zero_byte_across_call_site() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.linkCodePairingNonceElementValue,n=o("X").smax("link_code_pairing_nonce",null,t); return n; };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return o("R").sendCompanionHelloRPC({linkCodePairingNonceArgs:{linkCodePairingNonceElementValue:new Uint8Array(1)}}); };
            },2);
        "#;
        let idx = index(bundle);
        assert_eq!(
            idx.get("link_code_pairing_nonce"),
            Some((
                &ConstValue::ZeroBytes(1),
                "linkCodePairingNonceElementValue"
            ))
        );
    }

    /// Direct `smax("tag", null, e.arg)` (no intermediate local) also resolves.
    #[test]
    fn resolves_direct_member_content() {
        let bundle = r#"
            __d("B",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ return o("X").smax("nonce",null,e.fooElementValue); };
            },1);
            __d("C",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {fooElementValue:new Uint8Array(4)}; };
            },2);
        "#;
        assert_eq!(
            index(bundle).get("nonce"),
            Some((&ConstValue::ZeroBytes(4), "fooElementValue"))
        );
    }

    /// An argument assigned two different constants anywhere is dropped (unanimity).
    #[test]
    fn disagreeing_arg_values_are_dropped() {
        let bundle = r#"
            __d("B",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("C",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },2);
            __d("D",[],function(g,r,d,o,e,i,l){ l.c=function(){ return {fooElementValue:new Uint8Array(2)}; }; },3);
        "#;
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// An argument assigned a non-constant (a variable) anywhere is dropped, even if it
    /// is also assigned a `new Uint8Array(N)` elsewhere.
    #[test]
    fn arg_with_any_dynamic_assignment_is_dropped() {
        let bundle = r#"
            __d("B",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("C",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },2);
            __d("E",[],function(g,r,d,o,e,i,l){ l.d=function(z){ return {fooElementValue:z}; }; },3);
        "#;
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// A dissenting builder that emits the tag with dynamic content lives in a module
    /// with NO `…ElementValue` argument. Pass 2 must still see it (it filters by the
    /// builder `.smax(`/`.wap(`, not by the argument suffix), so the tag is dropped —
    /// not wrongly promoted to a constant.
    #[test]
    fn dynamic_builder_without_element_value_arg_drops_tag() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },2);
            __d("OtherBuilder",[],function(g,r,d,o,e,i,l){ l.c=function(x){ return o("X").smax("nonce",null,x.runtimeBuf); }; },3);
        "#;
        // `OtherBuilder` mentions no `ElementValue`, but feeds `nonce` dynamic content.
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// A `let` alias declared inside a nested block must not leak out of the block and
    /// be read by a later `smax(…, t)` in the enclosing scope.
    #[test]
    fn block_scoped_let_alias_does_not_leak() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ if (e.flag) { let t = e.fooElementValue; use(t); } return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },2);
        "#;
        // The `smax` reads a `t` outside the block that bound it → dynamic → no const.
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// A `var t = e.arg` at the function's top level (the common builder shape) still
    /// resolves — block-scoping restores only on leaving *nested* blocks, and a function
    /// body is not one.
    #[test]
    fn function_top_level_var_alias_still_resolves() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t = e.fooElementValue; return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },2);
        "#;
        assert_eq!(
            index(bundle).get("nonce"),
            Some((&ConstValue::ZeroBytes(1), "fooElementValue"))
        );
    }

    /// An absurdly large `new Uint8Array(N)` is not treated as a wire constant (guards
    /// the hex expansion against an unbounded allocation).
    #[test]
    fn oversized_byte_buffer_is_not_constant() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1000000)}; }; },2);
        "#;
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// The crypto idiom — `new Uint8Array(1)` bound to a *variable* then filled — is a
    /// statement, not an object-property value, so it never registers as a constant.
    #[test]
    fn crypto_random_variable_is_not_a_constant() {
        let bundle = r#"
            __d("B",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("F",[],function(g,r,d,o,e,i,l){ l.d=function(){ var t=new Uint8Array(1); crypto.getRandomValues(t); return t; }; },2);
        "#;
        // `fooElementValue` is never assigned a constant → no entry.
        assert_eq!(index(bundle).get("nonce"), None);
    }

    /// A tag fed a constant by one builder and dynamic content by another is dropped.
    #[test]
    fn tag_with_mixed_const_and_dynamic_builders_is_dropped() {
        let bundle = r#"
            __d("B",[],function(g,r,d,o,e,i,l){ l.a=function(e){ return o("X").smax("nonce",null,e.fooElementValue); }; },1);
            __d("G",[],function(g,r,d,o,e,i,l){ l.z=function(e){ return o("X").smax("nonce",null,e.someRuntimeBufElementValue); }; },2);
            __d("C",[],function(g,r,d,o,e,i,l){ l.b=function(){ return {fooElementValue:new Uint8Array(1)}; }; },3);
            __d("H",[],function(g,r,d,o,e,i,l){ l.q=function(x){ return {someRuntimeBufElementValue:x.buf}; }; },4);
        "#;
        // `someRuntimeBufElementValue` isn't a constant → the `nonce` tag is dynamic.
        assert_eq!(index(bundle).get("nonce"), None);
    }

    #[test]
    fn enrich_fills_dynamic_leaf_with_zero_bytes() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.linkCodePairingNonceElementValue; return o("X").smax("link_code_pairing_nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {linkCodePairingNonceElementValue:new Uint8Array(1)}; };
            },2);
        "#;
        let idx = index(bundle);
        let mut node = WapChildNode {
            tag: "link_code_pairing_nonce".into(),
            content: Some(wa_ir::WapContent {
                kind: WapContentKind::Dynamic,
                ..Default::default()
            }),
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut node), &idx);
        let c = node.content.as_ref().unwrap();
        assert_eq!(c.kind, WapContentKind::Bytes);
        assert_eq!(c.const_bytes.as_deref(), Some("00"));
        assert_eq!(c.byte_length, Some(1));
        assert_eq!(
            c.value_source.as_deref(),
            Some("const:linkCodePairingNonceElementValue")
        );
    }

    #[test]
    fn enrich_creates_content_on_contentless_leaf() {
        // The real shape: the builder passes a bare local (`smax("…", null, t)`), which
        // the request resolver leaves as a leaf with no content. Enrich must create it.
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.fooElementValue; return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {fooElementValue:new Uint8Array(1)}; };
            },2);
        "#;
        let idx = index(bundle);
        let mut node = WapChildNode {
            tag: "nonce".into(),
            content: None,
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut node), &idx);
        let c = node.content.as_ref().expect("content created");
        assert_eq!(c.kind, WapContentKind::Bytes);
        assert_eq!(c.const_bytes.as_deref(), Some("00"));
        assert_eq!(c.byte_length, Some(1));
        assert_eq!(c.value_source.as_deref(), Some("const:fooElementValue"));
    }

    #[test]
    fn enrich_leaves_contentless_container_alone() {
        // A node with the same tag but *children* is a container, not a value leaf —
        // enrich must not fabricate content on it.
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.fooElementValue; return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {fooElementValue:new Uint8Array(1)}; };
            },2);
        "#;
        let idx = index(bundle);
        let mut node = WapChildNode {
            tag: "nonce".into(),
            content: None,
            children: vec![WapChildNode {
                tag: "inner".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut node), &idx);
        assert!(node.content.is_none());
    }

    #[test]
    fn enrich_descends_into_variant_groups() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.fooElementValue; return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {fooElementValue:new Uint8Array(2)}; };
            },2);
        "#;
        let idx = index(bundle);
        let mut parent = WapChildNode {
            tag: "wrap".into(),
            variant_groups: vec![wa_ir::WapVariantGroup {
                optional: false,
                variants: vec![wa_ir::WapVariant {
                    attrs: vec![],
                    children: vec![WapChildNode {
                        tag: "nonce".into(),
                        content: Some(wa_ir::WapContent {
                            kind: WapContentKind::Dynamic,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                }],
            }],
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut parent), &idx);
        let c = parent.variant_groups[0].variants[0].children[0]
            .content
            .as_ref()
            .unwrap();
        assert_eq!(c.const_bytes.as_deref(), Some("0000"));
        assert_eq!(c.byte_length, Some(2));
    }

    #[test]
    fn enrich_never_overrides_builder_resolved_value() {
        let bundle = r#"
            __d("Builder",[],function(g,r,d,o,e,i,l){
                l.a = function(e){ var t=e.fooElementValue; return o("X").smax("nonce",null,t); };
            },1);
            __d("CallSite",[],function(g,r,d,o,e,i,l){
                l.b = function(){ return {fooElementValue:new Uint8Array(1)}; };
            },2);
        "#;
        let idx = index(bundle);
        // A leaf the builder already resolved to a fixed string must be untouched.
        let mut node = WapChildNode {
            tag: "nonce".into(),
            content: Some(wa_ir::WapContent {
                kind: WapContentKind::Const,
                value: Some("literal".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        enrich(std::slice::from_mut(&mut node), &idx);
        let c = node.content.as_ref().unwrap();
        assert_eq!(c.kind, WapContentKind::Const);
        assert_eq!(c.value.as_deref(), Some("literal"));
        assert_eq!(c.const_bytes, None);
    }
}
