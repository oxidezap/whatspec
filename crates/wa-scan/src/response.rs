//! Response parser analysis: walk a `WADeprecatedWapParser` callback body and
//! reconstruct the response field tree (assertions, attrs, nested children).
//!
//! Mirrors `analyzeParserAST` + `processChildMethod` from the TS scanner. Handles
//! accessors on the param directly, chained `param.child("x").attr...`, and
//! `child()` results captured in local variables.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, Expression, Function, NewExpression, Statement, VariableDeclaration,
    VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use wa_ir::wap;
use wa_ir::{
    AssertionKind, ContentType, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion,
    UnionVariant,
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
        pending_drops: result.unresolved,
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
    /// See [`ParsedResponse::pending_drops`].
    pub unresolved: Vec<String>,
    /// The nodes local names were bound to. A dispatch arm is re-analysed on its own and
    /// starts with none, so a `<detail>` bound before the chain and read inside an arm
    /// resolved to nothing, and its reads left both the variant and the element.
    pub child_vars: HashMap<String, Vec<PathSeg>>,
}

/// Accessors that read a value off a node, as the parser treats them: every shared
/// attribute accessor ([`wap::is_attr_method`]) plus every content leaf
/// ([`wap::is_content_method`]). Broader than codegen's notion of an attr field — both
/// draw method names from the shared [`wap`] vocabulary so they can't drift.
///
/// Both halves are *derived*. Naming `contentBytes`/`contentString` here and nothing
/// else was the enumerate-vs-derive bug a third time: `method_field_type` learned to
/// decode `contentUint`, `contentEnum`, `contentBytesRange` and `contentLiteralBytes`,
/// but this list did not, so on the legacy path those reads produced no typed field at
/// all — only a coarse `contentType` on the parent, losing the integer, enum, range and
/// literal constraints.
fn is_value_method(m: &str) -> bool {
    wap::is_attr_method(m) || wap::is_content_method(m)
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
fn pending_enum_ref(method: &str, call: &CallExpression, module_scope: &ModuleScope) -> EnumSource {
    if wap::method_field_type(method) != ParsedFieldType::Enum {
        return EnumSource::NotAnEnum;
    }
    // A content accessor takes its table as the FIRST argument (`contentEnum(TABLE)`);
    // an attribute one names the attribute first (`attrStringEnum("state", TABLE)`).
    // Reading past the name unconditionally found nothing on the content spellings.
    let skip = usize::from(!wap::is_content_method(method));
    let Some(arg) = call.arguments.iter().skip(skip).filter_map(arg_expr).next() else {
        return EnumSource::Unresolved;
    };
    // `attrEnumValues("type", o("Mod").CiphertextType.members())` — the allowed set is
    // the enum's `.members()`, so the table is the *callee's object*, not the call.
    let stripped = strip_members_call(arg);
    let via_members = !std::ptr::eq(stripped, arg);
    let arg = stripped;
    // FORM A: a cross-module export. Recorded as pending; `enum_link` finishes it.
    if let Some((obj, name)) = wa_oxc::as_member(arg)
        && let Some(module) = wa_oxc::as_call(obj)
            .and_then(|c| c.arguments.first())
            .and_then(arg_expr)
            .and_then(as_string_lit)
    {
        return EnumSource::Pending(wa_ir::AttrEnumRef {
            name: name.to_string(),
            module: module.to_string(),
            variants: Vec::new(),
        });
    }
    // FORM B: a module-local table (`attrEnumValues("mediatype", u.members())`, where
    // `u = n("$InternalEnum")({Image: "image", …})`). The allowed set is already in this
    // module, so it becomes `enumKeys` directly — no cross-module post-pass, and no
    // `enumRef` named after a minified local.
    if let Some(name) = as_identifier(arg) {
        let table = if via_members {
            module_scope.members.get(name)
        } else {
            module_scope.maps.get(name)
        };
        if let Some(values) = table.filter(|v| !v.is_empty()) {
            return EnumSource::Keys(values.clone());
        }
    }
    EnumSource::Unresolved
}

/// Where an enum accessor's allowed-value set came from.
///
/// `Unresolved` exists so an enum whose table is not structurally recoverable is
/// *counted* rather than published as an unconstrained `"type": "enum"` — the same
/// "missing beats wrong, but never silent" rule the rest of the scan follows.
enum EnumSource {
    NotAnEnum,
    Pending(wa_ir::AttrEnumRef),
    Keys(Vec<String>),
    Unresolved,
}

/// Unwrap a trailing `.members()` / `.getMembers()` accessor, which WA uses to spell
/// "the allowed values of this enum"; anything else is returned unchanged.
fn strip_members_call<'b, 'a>(e: &'b Expression<'a>) -> &'b Expression<'a> {
    wa_oxc::as_call(e)
        .filter(|c| c.arguments.is_empty())
        .and_then(|c| match callee_method(c) {
            Some("members" | "getMembers") => callee_object(c),
            _ => None,
        })
        .unwrap_or(e)
}

fn field_from_call(
    method: &str,
    call: &CallExpression,
    module_scope: &ModuleScope,
    unresolved: &mut Vec<String>,
) -> ParsedField {
    let arg0 = call.arguments.first().and_then(arg_expr);
    // A content accessor reads the element's content and names no attribute, so its
    // first argument is never the field name — `contentEnum(TABLE)` would otherwise be
    // named after nothing at all.
    let field_name = if wap::is_content_method(method) {
        "content"
    } else {
        arg0.and_then(as_string_lit).unwrap_or("content")
    };
    let mut f = mk_field(
        method,
        field_name,
        method_to_field_type(method),
        is_method_required(method),
    );
    // Each byte accessor pins something different, and routing them all here without
    // reading their arguments published unconstrained `bytes` — an emitter would think
    // any payload passes where the parser accepts one sequence or one length band.
    match method {
        // `contentBytes(64)` and `contentUint(3)` both take a BYTE COUNT. `contentUint`
        // is not a decimal string: WA packs a prekey id into 3 bytes and a registration
        // id into 4, big-endian, so the length is part of the wire contract and dropping
        // it left the field looking like unbounded text.
        wap::CONTENT_BYTES | "contentUint" => {
            if let Some(Expression::NumericLiteral(n)) = arg0 {
                f.byte_length = Some(n.value as u32);
            }
        }
        // `contentLiteralBytes(new Uint8Array([5]))` — the node is the receiver on this
        // path, so the sequence is argument 0 (smax passes the node first).
        "contentLiteralBytes" => match arg0.and_then(crate::response_smax::static_byte_literal) {
            Some(bytes) => {
                f.byte_length = Some(bytes.len() as u32);
                f.literal_value = Some(bytes.iter().map(|b| format!("{b:02x}")).collect());
            }
            None => unresolved.push(format!("contentLiteralBytes@{field_name}")),
        },
        // `contentBytesRange(min, max)` — a payload-size band. `min == max` is a fixed
        // length, which `byte_length` already expresses.
        "contentBytesRange" => {
            let bound = |i: usize| match call.arguments.get(i).and_then(arg_expr) {
                Some(Expression::NumericLiteral(n)) => Some(n.value as u32),
                _ => None,
            };
            match (bound(0), bound(1)) {
                (Some(min), Some(max)) if min == max => f.byte_length = Some(min),
                (Some(min), Some(max)) => {
                    f.byte_min = Some(min);
                    f.byte_max = Some(max);
                }
                _ => unresolved.push(format!("contentBytesRange@{field_name}")),
            }
        }
        // `attrIntRange("count", 1, 10)` — the band the accessor enforces. The smax path
        // records these (it spells the call with the node first); the WAP path did not, so
        // a union arm reading one could only guard on whether the value parses and took a
        // `count="99"` the source turns away. An open bound stays open: WA writes
        // `attrIntRange(e, "t", 0, void 0)` for "no upper limit".
        "attrIntRange" => {
            let bound = |i: usize| match call.arguments.get(i).and_then(arg_expr) {
                Some(Expression::NumericLiteral(n)) => Some(n.value as i64),
                _ => None,
            };
            f.int_min = bound(1);
            f.int_max = bound(2);
        }
        _ => {}
    }
    match pending_enum_ref(method, call, module_scope) {
        EnumSource::Pending(er) => f.pending_enum_ref = Some(wa_ir::PendingEnum::Link(er)),
        EnumSource::Keys(keys) => f.enum_keys = Some(keys),
        EnumSource::Unresolved => f.pending_enum_ref = Some(wa_ir::PendingEnum::Unresolvable),
        EnumSource::NotAnEnum => {}
    }
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
    analyze_with_scope(
        code,
        param,
        &ModuleScope::from_source(module_source),
        &Default::default(),
    )
}

/// Analyze a parser callback body against a *pre-extracted* [`ModuleScope`]. Every
/// module-scope lookup (a sibling helper's params/body, an enum value map's keys) reads
/// the scope built once by [`ModuleScope::from_source`] instead of re-parsing the whole
/// module per lookup — and the recursive callback analysis (`process_child_method`) reuses
/// the same scope, so a module is parsed exactly once per top-level parser.
fn analyze_with_scope(
    code: &str,
    param: &str,
    module: &ModuleScope,
    outer_bindings: &std::collections::HashSet<String>,
) -> ParserResult {
    analyze_seeded(code, param, module, outer_bindings, HashMap::new())
}

/// As [`analyze_with_scope`], but starting from nodes the enclosing scope already bound.
fn analyze_seeded(
    code: &str,
    param: &str,
    module: &ModuleScope,
    outer_bindings: &std::collections::HashSet<String>,
    seed: HashMap<String, Vec<PathSeg>>,
) -> ParserResult {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, code);
    let mut a = ParserAnalyzer {
        code,
        param,
        module,
        recursed: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: seed,
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: 0,
    };
    // A helper the ENCLOSING parser bound shadows the module's here too, and this
    // scope cannot see that binding on its own.
    a.local_bindings = all_bindings(&ret.program);
    a.local_bindings
        .names
        .extend(outer_bindings.iter().cloned());
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    ParserResult {
        assertions: a.assertions,
        fields: a.fields,
        unresolved: a.unresolved,
        child_vars: a.child_vars,
    }
}

/// The identifier a receiver chain bottoms out at: `x` for `x`, for `x.child("a")` and
/// for `x.child("a").child("b")`.
fn base_identifier<'b>(expr: &'b Expression<'_>) -> Option<&'b str> {
    if let Some(n) = as_identifier(expr) {
        return Some(n);
    }
    base_identifier(callee_object(as_call(expr)?)?)
}

/// The `dropsByReason` key for a read inside a callback that re-binds the parser's
/// parameter and that no recursion covered.
const SHADOWED_READ: &str = "shadowedCallbackRead";

/// The `dropsByReason` key for a wire read whose receiver this scope cannot resolve to a
/// node — a name bound here from something outside the scope, most often a callback that
/// aliased one of the parser's own nodes.
const UNKNOWN_RECEIVER: &str = "readThroughUnknownNode";

/// The `dropsByReason` key for a helper chain the descent stopped following.
const HELPER_DEPTH: &str = "helperChainTooDeep";

struct ParserAnalyzer<'src, 'ms> {
    code: &'src str,
    param: &'src str,
    /// Source ranges of callback bodies [`process_child_method`] already analysed in their
    /// own scope.
    ///
    /// Extraction is name-based: `obj_is_param` compares identifiers, and `child_vars` maps
    /// them to tags. Minified callbacks reuse both — `mapChildrenWithTag("enc", function(e){…})`
    /// inside a parser whose own parameter is `e`, or an inner `var t = e.maybeChild("id")`
    /// over an outer `var t = e.child("product_list")`. Reading such a body twice emitted its
    /// fields at the root as well, flat and one level too high, resolved against whichever
    /// binding the outer analyser happened to hold.
    ///
    /// Suppressing by span rather than by name only skips what the recursion demonstrably
    /// covered: a callback `process_child_method` declined to descend into is still read
    /// here, as before, instead of vanishing.
    recursed: Vec<Span>,
    /// The names each enclosing inner function binds, innermost last.
    ///
    /// Suppression is about ownership, not position: a callback's own bindings are not the
    /// parser's nodes, but a captured outer one still is. `var x = e.child("meta")` read
    /// inside `mapChildrenWithTag("row", …)` is a read of `meta`, and the recursion cannot
    /// see it — its analyser starts with no bindings at all — so this walk has to.
    ///
    /// A callback the recursion did not descend into is walked here too, and its own
    /// bindings resolve against the outer ones — landing at the root, flat and one level
    /// too high. Those are neither kept nor dropped in silence: see [`SHADOWED_READ`].

    /// The enclosing module's pre-extracted helpers/maps (empty when there is no module),
    /// for resolving module-scope sibling helpers and enum value maps.
    module: &'ms ModuleScope,
    assertions: Vec<ResponseAssertion>,
    fields: Vec<ParsedField>,
    /// local var name → tag, for `var t = param.child("tag")`. Also pre-seeded when a
    /// helper is re-analyzed with a parameter bound to a caller's child node (see
    /// [`ParserAnalyzer::try_helper_descent`]).
    child_vars: HashMap<String, Vec<PathSeg>>,
    /// wire attr name → its enum's allowed keys, from `attrEnumOrNullIfUnknown("attr", map)`
    /// (the map is module-scope, so it's resolved and stashed here, then attached to the
    /// matching field in a post-pass — order-independent of the plain read of the attr).
    pending_enum_keys: HashMap<String, Vec<String>>,
    /// Wire attributes read by `attrEnumOrNullIfUnknown` whose allowed-value table could
    /// not be named. Resolved in [`ParserAnalyzer::attach_pending_enum_keys`] alongside
    /// the ones that did resolve.
    unresolved_enum_attrs: std::collections::BTreeSet<String>,
    /// Constraints seen on this parser but not statically resolvable, as
    /// `dropsByReason` keys. Parked on the produced [`ParsedResponse`] for whoever
    /// finishes it, since the legacy scanner has no diagnostics channel of its own.
    unresolved: Vec<String>,
    /// Names a callback bound to a node it reached from outside itself, with the extent
    /// they cover. Recorded for the diagnostic only — never resolved, because following
    /// them means keeping `child_vars` lexically correct, and every attempt at that
    /// attached fields to whichever node the name meant somewhere else. Knowing the read
    /// is lost is worth more than guessing where it belongs.
    unfollowable: Vec<(Span, String)>,
    /// Every name the analysed source binds, collected before the walk. A parser that
    /// defines its own `parse` shadows the module-scope helper of that name, and resolving
    /// the callee by identifier text alone attached a stranger's fields to the result.
    local_bindings: Bindings,
    /// Identities a conditional helper descent weakened, in visit order. A helper called on
    /// both sides of a branch runs on every path, so what it reads is required after all —
    /// the same intersection the assertions get, which the fields were never given.
    relaxed_by_branch: Vec<RelaxedId>,
    /// How many occurrences of each assertion this scope only reaches down a branch. By
    /// count, not by value: the same guard made once inside an `if` and once outside is
    /// enforced on every path, and filtering by equality dropped both.
    conditional_assertions: Vec<ResponseAssertion>,
    /// Whether the call being visited sits under a branch. A helper reached only when
    /// `kind === "a"` does not make its payload required of every element.
    conditional_depth: u32,
    /// What an enclosing guard has tested the presence of, as (node, wire). `hasChild(t) ?
    /// e.child(t) … : null` says the element may not carry `t`; a plain `if (flag)` says
    /// nothing about any field, and weakening on branch depth alone let an `id` read on
    /// every path through the parser look optional. The node matters too: a test on some
    /// other object says nothing about this one, however alike the names read.
    guarded_names: Vec<(String, String)>,
    /// Recursion guard for module-scope helper descent (`m(n,i)` → analyze `m`'s body).
    helper_depth: u32,
}

impl<'a> Visit<'a> for ParserAnalyzer<'_, '_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        // What a callback binds dies with it. An alias may overwrite an outer entry of the
        // same name, and the alias' own extent expiring would not put the outer one back.
        let outer_vars = self.child_vars.clone();
        walk::walk_function(self, func, flags);
        self.child_vars = outer_vars;
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        let outer_vars = self.child_vars.clone();
        walk::walk_arrow_function_expression(self, func);
        self.child_vars = outer_vars;
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        // A descendant bound inside a callback that has its own scope — whether the
        // recursion read it or the shadow check will discount it — must not rebind the
        // outer name, or later reads land against the wrong node.
        if self.inside_recursed(decl.span) || self.param_shadowed(decl.span) {
            self.note_unfollowable_bindings(decl);
            walk::walk_variable_declaration(self, decl);
            return;
        }
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
                        // The whole way down, not just the last step: a var bound off
                        // another var names a grandchild, and keeping only its own tag put
                        // the node beside its parent instead of inside it.
                        let mut path = as_identifier(obj)
                            .and_then(|n| self.child_vars.get(n))
                            .cloned()
                            .unwrap_or_default();
                        path.push(PathSeg {
                            tag: tag.to_string(),
                            method: method.unwrap_or("child").to_string(),
                        });
                        self.child_vars.insert(name.as_str().to_string(), path);
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_statement(&mut self, stmt: &Statement<'a>) {
        // One place asks the question, so a construct that introduces a non-taken path
        // cannot be forgotten the way `switch`, the loops and `try` each were in turn.
        if skips_on_some_path(stmt) {
            self.conditional_depth += 1;
            walk::walk_statement(self, stmt);
            self.conditional_depth -= 1;
        } else {
            walk::walk_statement(self, stmt);
        }
    }

    /// `try`/`catch`/`finally` cannot be answered by [`skips_on_some_path`] alone: the
    /// three parts differ from each other, and the walk reaches them through one node.
    fn visit_try_statement(&mut self, stmt: &oxc_ast::ast::TryStatement<'a>) {
        // The block may abort partway — that is what having a handler means — so what it
        // reads past the throwing call is not read on every path.
        self.conditional_depth += 1;
        self.visit_block_statement(&stmt.block);
        // The handler runs only when the block failed.
        if let Some(h) = &stmt.handler {
            self.visit_catch_clause(h);
        }
        self.conditional_depth -= 1;
        // The finalizer runs whichever way the block went, so it is not conditional on
        // anything. Weakening it would call a read the parser always performs optional.
        if let Some(f) = &stmt.finalizer {
            self.visit_block_statement(f);
        }
    }

    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_expression(&stmt.test);
        // `if (e.hasAttr("x")) …` says the element may lack `x` only on the path where it
        // was found; the `else` is where it is known ABSENT, and a read there is required
        // by whatever the parser does next. A negated test flips the two.
        let tested = self.canonical_guards(&stmt.test);
        let n = tested.len();
        self.conditional_depth += 1;

        let before_then = (self.assertions.len(), self.relaxed_by_branch.len());
        self.guarded_names.extend(tested);
        self.visit_statement(&stmt.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        let then_side: Vec<ResponseAssertion> = self.assertions[before_then.0..].to_vec();
        let then_weak = self.relaxed_by_branch[before_then.1..].to_vec();

        let mut established = Vec::new();
        if let Some(alt) = &stmt.alternate {
            let before_else = (self.assertions.len(), self.relaxed_by_branch.len());
            self.visit_statement(alt);
            let else_side: Vec<ResponseAssertion> = self.assertions[before_else.0..].to_vec();
            let else_weak = self.relaxed_by_branch[before_else.1..].to_vec();
            self.unmark_branch_intersection(&then_side, &else_side);
            established = branch_intersection(&then_weak, &else_weak);
        }
        // Settled after the truncate, so a claim handed up outlives the branch that
        // established it and the enclosing conditional can see it.
        self.relaxed_by_branch.truncate(before_then.1);
        self.settle_branch_intersection(established);
        self.conditional_depth -= 1;
    }

    fn visit_logical_expression(&mut self, expr: &oxc_ast::ast::LogicalExpression<'a>) {
        // `enabled && parse(e)` runs the right side only sometimes — the same as an `if`,
        // spelled shorter.
        self.visit_expression(&expr.left);
        // `a && b` runs `b` when `a` held, so what `a` found is established there. `a || b`
        // runs `b` when `a` did NOT hold — `hasAttr("id") || e.attrString("id")` reads the
        // attribute precisely when it is missing, and calling that optional inverts what
        // the parser says.
        let tested = match expr.operator {
            oxc_syntax::operator::LogicalOperator::And => self.canonical_guards(&expr.left),
            _ => Vec::new(),
        };
        let n = tested.len();
        self.guarded_names.extend(tested);
        self.conditional_depth += 1;
        self.visit_expression(&expr.right);
        self.conditional_depth -= 1;
        self.guarded_names.truncate(self.guarded_names.len() - n);
    }

    fn visit_conditional_expression(&mut self, expr: &oxc_ast::ast::ConditionalExpression<'a>) {
        self.visit_expression(&expr.test);
        let tested = self.canonical_guards(&expr.test);
        let n = tested.len();
        self.conditional_depth += 1;

        let before_then = (self.assertions.len(), self.relaxed_by_branch.len());
        self.guarded_names.extend(tested);
        self.visit_expression(&expr.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        let then_side: Vec<ResponseAssertion> = self.assertions[before_then.0..].to_vec();
        let then_weak = self.relaxed_by_branch[before_then.1..].to_vec();

        let before_else = (self.assertions.len(), self.relaxed_by_branch.len());
        self.visit_expression(&expr.alternate);
        let else_side: Vec<ResponseAssertion> = self.assertions[before_else.0..].to_vec();
        let else_weak = self.relaxed_by_branch[before_else.1..].to_vec();
        self.unmark_branch_intersection(&then_side, &else_side);
        let established = branch_intersection(&then_weak, &else_weak);

        self.relaxed_by_branch.truncate(before_then.1);
        self.settle_branch_intersection(established);
        self.conditional_depth -= 1;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.inside_recursed(call.span) {
            // Read in its own scope by `process_child_method` — unless it reaches back
            // through a node that scope never bound, which only this walk can resolve.
            if self.reads_an_outer_node(call) {
                self.handle_call(call);
            } else if self.passes_an_outer_node(call) {
                self.try_helper_descent(call);
            } else {
                self.note_unknown_receiver(call);
            }
        } else if self.param_shadowed(call.span) {
            if self.reads_an_outer_node(call) {
                self.handle_call(call);
            } else if self.passes_an_outer_node(call) {
                self.try_helper_descent(call);
            } else {
                self.note_shadowed_read(call);
            }
        } else {
            self.handle_call(call);
            self.try_helper_descent(call);
            self.try_own_node_helper_descent(call);
        }
        // Always descend: chained calls expose both inner and outer nodes.
        walk::walk_call_expression(self, call);
    }
}

impl ParserAnalyzer<'_, '_> {
    /// Whether `span` falls inside a callback body already analysed in its own scope.
    fn inside_recursed(&self, span: Span) -> bool {
        self.recursed
            .iter()
            .any(|r| span.start >= r.start && span.end <= r.end)
    }

    /// An assertion made whichever way a branch goes is made always. Both occurrences were
    /// marked conditional on the way in; their intersection is not. `if`/`else` and the
    /// ternary are the same shape here, and teaching only one left the other filtering
    /// both occurrences away.
    /// A helper called on both sides of a branch runs on every path, so what it reads is
    /// required after all — two weakened copies OR to weak, and the field ended up optional
    /// where the parser always demands it.
    fn settle_branch_intersection(&mut self, established: Vec<RelaxedId>) {
        // Established relative to THIS conditional only. Nested inside a one-sided outer
        // `if`, the outer can still skip both branches, so the claim is handed up as the
        // outer branch's own weak entry rather than promoted outright.
        if self.conditional_depth > 1 {
            self.relaxed_by_branch.extend(established);
            return;
        }
        for id in &established {
            promote_required(&mut self.fields, id, "");
        }
    }

    fn unmark_branch_intersection(
        &mut self,
        then_side: &[ResponseAssertion],
        else_side: &[ResponseAssertion],
    ) {
        for a in then_side.iter().filter(|a| else_side.contains(a)) {
            for _ in 0..2 {
                if let Some(i) = self.conditional_assertions.iter().position(|x| x == a) {
                    self.conditional_assertions.swap_remove(i);
                }
            }
        }
    }

    /// Whether an enclosing inner function re-binds the parser's own parameter, as seen
    /// from `span`.
    fn param_shadowed(&self, span: Span) -> bool {
        self.bound_by_inner_scope(self.param, span)
    }

    /// Whether `name`, read at `span`, belongs to an enclosing callback rather than to the
    /// parser's own body.
    fn bound_by_inner_scope(&self, name: &str, span: Span) -> bool {
        self.local_bindings.bound_inside(name, span)
    }

    /// Whether `call` reads through a node bound outside every enclosing callback — the
    /// parser's own parameter, or a child var it captured. Those are the reads no inner
    /// scope accounts for, so only this walk can place them.
    /// Whether the call hands a captured child node to a module-scope helper. The helper's
    /// fields belong to that node, and the recursion has no binding to reach it by.
    fn passes_an_outer_node(&self, call: &CallExpression) -> bool {
        call.arguments.iter().any(|a| {
            arg_expr(a).and_then(as_identifier).is_some_and(|n| {
                self.child_vars.contains_key(n) && self.names_an_outer_node(n, call.span)
            })
        })
    }

    fn reads_an_outer_node(&self, call: &CallExpression) -> bool {
        callee_object(call)
            .and_then(base_identifier)
            .is_some_and(|n| {
                (n == self.param || self.child_vars.contains_key(n))
                    && self.names_an_outer_node(n, call.span)
            })
    }

    /// Whether `name`, at `span`, still means the node it was bound to outside every
    /// enclosing callback.
    fn names_an_outer_node(&self, name: &str, span: Span) -> bool {
        !self.bound_by_inner_scope(name, span)
    }

    /// Count a wire read the outer walk cannot place: it sits in a callback that re-binds
    /// the parser's parameter, so the name it reads through is not the node it names here.
    /// Keeping it would publish a field at the wrong level; dropping it quietly would let
    /// coverage shrink unnoticed.
    /// Count a wire read this scope has no node for. A callback analysed on its own starts
    /// with no bindings, so `var x = e.child("meta"); x.attrString("id")` reads through a
    /// name it cannot follow — and resolving it against the enclosing walk's map is what
    /// kept attaching fields to whichever node that name meant elsewhere.
    /// Note a name a callback binds to a node it reached from outside itself. The binding
    /// stays the callback's — this only remembers that reads through it have nowhere to go,
    /// so they can be counted instead of vanishing.
    /// The tags naming the node `base.child(chained)` denotes, outermost first — `["digest",
    /// "list"]` for `t.child("list")` where `t` tracks `<digest>`. `None` when `base` is not
    /// a node this scope can name.
    fn node_path(&self, base: &str, chained: &str, method: &str, at: Span) -> Option<Vec<PathSeg>> {
        let seg = PathSeg {
            tag: chained.to_string(),
            method: method.to_string(),
        };
        if base == self.param {
            return Some(vec![seg]);
        }
        if !self.names_an_outer_node(base, at) {
            return None;
        }
        let mut path = self.child_vars.get(base)?.clone();
        path.push(seg);
        Some(path)
    }

    /// A read, with the accessor's requiredness tempered by where it sits: guarded by
    /// `hasChild(…) ? … : null` it is not required of every element, however unconditional
    /// the accessor itself looks.
    fn read_field(&mut self, method: &str, call: &CallExpression) -> ParsedField {
        let mut f = field_from_call(method, call, self.module, &mut self.unresolved);
        let wire = f.wire_name.clone().unwrap_or_else(|| f.name.clone());
        let node = callee_object(call)
            .and_then(receiver_path)
            .unwrap_or_else(|| self.param.to_string());
        if self.presence_guarded(&node, &wire) {
            f.required = false;
        }
        f
    }

    /// Whether an enclosing guard asked whether this very field, on this very node, is
    /// there. Both sides are canonical paths, so the two spellings of one node — the var
    /// tracking it and the chain reaching it — are the same key.
    fn presence_guarded(&self, node: &str, wire: &str) -> bool {
        let node = self.canonical_node(node);
        self.guarded_names
            .iter()
            .any(|(n, w)| *n == node && w == wire)
    }

    /// The presence facts a test establishes, keyed by the node they are about.
    fn canonical_guards(&self, test: &Expression) -> Vec<(String, String)> {
        presence_tested(test)
            .into_iter()
            .map(|(node, wire)| (self.canonical_node(&node), wire))
            .collect()
    }

    /// A receiver spelling reduced to the path it names, relative to the parser's node.
    /// `e` and a var tracking `<a>` both resolve, so `a.hasChild("b")` and
    /// `e.child("a").hasChild("b")` are recognized as the same question.
    fn canonical_node(&self, receiver: &str) -> String {
        let mut parts = receiver.split('/');
        let Some(head) = parts.next() else {
            return String::new();
        };
        let mut path: Vec<String> = if head == self.param {
            Vec::new()
        } else if let Some(tracked) = self.child_vars.get(head) {
            tracked.iter().map(|s| s.tag.clone()).collect()
        } else {
            vec![head.to_string()]
        };
        path.extend(parts.map(str::to_string));
        path.join("/")
    }

    fn note_unfollowable_bindings(&mut self, decl: &VariableDeclaration) {
        let Some(extent) = self.local_bindings.innermost_extent(decl.span) else {
            return;
        };
        for d in &decl.declarations {
            if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                && let Some(call) = as_call(init)
                && matches!(callee_method(call), Some("child") | Some("maybeChild"))
                && callee_object(call)
                    .and_then(base_identifier)
                    .is_some_and(|n| {
                        (n == self.param || self.child_vars.contains_key(n))
                            && !self.bound_by_inner_scope(n, decl.span)
                    })
            {
                self.unfollowable.push((extent, name.as_str().to_string()));
            }
        }
    }

    fn note_unknown_receiver(&mut self, call: &CallExpression) {
        let Some(method) = callee_method(call) else {
            return;
        };
        if !(is_value_method(method) || is_child_method(method)) {
            return;
        }
        let Some(node) = callee_object(call).and_then(base_identifier) else {
            return;
        };
        if !self
            .unfollowable
            .iter()
            .any(|(e, n)| n == node && call.span.start >= e.start && call.span.end <= e.end)
        {
            return;
        }
        let what = arg_str(call, 0).unwrap_or("?");
        self.unresolved
            .push(format!("{UNKNOWN_RECEIVER}@{method}:{node}.{what}"));
    }

    fn note_shadowed_read(&mut self, call: &CallExpression) {
        let Some(method) = callee_method(call) else {
            return;
        };
        if !(is_value_method(method) || is_child_method(method)) {
            return;
        }
        let Some(obj) = callee_object(call) else {
            return;
        };
        // A node of the callback's own counts too: `var o = r.maybeChild("error")` reads a
        // real element, and it is no more placeable here than a read through the stale
        // outer binding it shadows.
        // Through the chain's base, not only a bare identifier: `e.child("x").attrString(…)`
        // loses the outer accessor too, and counting only the inner `child` left the ratchet
        // blind to it.
        let base = base_identifier(obj);
        let reads_a_node = base.is_some_and(|n| {
            n == self.param
                || self.child_vars.contains_key(n)
                || self.bound_by_inner_scope(n, call.span)
        });
        if reads_a_node {
            // Name the read, not just the accessor: `dropsByReason` counts these per site
            // through a set, so two `attrString`s would collapse into one and the ratchet
            // would not move when a third field started going missing.
            let node = base.unwrap_or("?");
            let what = arg_str(call, 0).unwrap_or("?");
            self.unresolved
                .push(format!("{SHADOWED_READ}@{method}:{node}.{what}"));
        }
    }

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
            let before = self.assertions.len();
            let guarded = self.conditional_depth > 0;
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
            // An assertion behind a branch holds when that branch runs, not always. A
            // caller following this scope cannot see that from the call site, so the fact
            // travels with the assertion.
            if guarded {
                for a in &self.assertions[before..] {
                    self.conditional_assertions.push(a.clone());
                }
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
            match call
                .arguments
                .get(1)
                .and_then(arg_expr)
                .and_then(as_identifier)
                .and_then(|m| self.module.maps.get(m).cloned())
            {
                Some(keys) => {
                    self.pending_enum_keys
                        .entry(wire.to_string())
                        .or_insert(keys);
                }
                // The table is not a module-scope identifier — `o("Mod").TABLE`, or a
                // computed set. The parser still enforces an enum here, so returning
                // silently produced neither a link nor a drop and the new diagnostics
                // reported nothing lost. Recorded so it is counted, and so a field gets
                // synthesized when no companion read created one.
                None => {
                    self.unresolved_enum_attrs.insert(wire.to_string());
                }
            }
            return;
        }

        // ── Attr/content accessor on the param directly ──
        if is_value_method(method) && obj_is_param {
            let read = self.read_field(method, call);
            // Merged, not appended: the same attribute read twice is one field, and two
            // entries let a guarded copy sit in front of the read that always happens.
            merge_or_push(&mut self.fields, read, &mut self.unresolved);
            return;
        }

        // ── Attr method chained on a child() result: e.child("error").attrInt("code") ──
        if is_value_method(method)
            && let Some(mut path) = self.child_call_parent(obj, call.span)
        {
            // The guard is about the node this step hangs off, which is everything before
            // it — not about the parser's own node, however deep the chain runs.
            let owner: String = path[..path.len().saturating_sub(1)]
                .iter()
                .map(|p| p.tag.as_str())
                .collect::<Vec<_>>()
                .join("/");
            if let Some(last) = path.last_mut()
                && last.method == "child"
                && self.presence_guarded(&owner, &last.tag)
            {
                last.method = "maybeChild".to_string();
            }
            // Reached without a guard, the node IS required however an earlier guarded read
            // left it — the lookup reuses what is there and would keep the weaker claim.
            let unguarded = path.last().is_some_and(|l| l.method == "child");
            let read = self.read_field(method, call);
            if let Some(node) = node_at_mut(&mut self.fields, &path) {
                node.required |= unguarded;
                let kids = node.children.get_or_insert_with(Vec::new);
                merge_or_push(kids, read, &mut self.unresolved);
            }
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
                // `hasChild(t) ? e.child(t)… : null` reads a `child`, but only when the
                // element carries one.
                let required = method == "child" && !self.presence_guarded("", tag);
                let mut f = mk_field(method, tag, ParsedFieldType::String, required);
                f.tag = Some(tag.to_string());
                f.children = Some(Vec::new());
                merge_or_push(&mut self.fields, f, &mut self.unresolved);
            }
            return;
        }

        // ── child methods directly on the param: param.mapChildrenWithTag("enc", …) ──
        //
        // The repeated element sits at the response root. Without this the child was never
        // built, and the callback's reads reached the IR only because the callback names
        // its parameter after the parser's — landing at the root, flat and unrepeated.

        if is_child_method(method) && obj_is_param {
            process_child_method(
                method,
                call,
                "",
                &mut ChildSink {
                    fields: &mut self.fields,
                    unresolved: &mut self.unresolved,
                    recursed: &mut self.recursed,
                    bindings: &self.local_bindings.outer_at(call.span),
                },
                self.code,
                self.module,
            );
            return;
        }

        // ── Chained: <node>.child("tag").<childMethod>(...) ──
        //
        // The node is the parser's own or one a var already tracks: `digestResponseParser`
        // writes `t.child("list").mapChildren(…)` off `var t = e.child("digest")`, and only
        // the first spelling was recognized — the mapped element went unbuilt and its reads
        // were counted as unplaceable rather than extracted.
        if is_child_method(method)
            && let Some(inner) = as_call(obj)
            && let Some(inner_method) = callee_method(inner)
            && (inner_method == "child" || inner_method == "maybeChild")
            && let Some(base) = callee_object(inner).and_then(as_identifier)
            && let Some(chained) = arg_str(inner, 0)
            && let Some(path) = self.node_path(base, chained, inner_method, call.span)
        {
            process_child_method_at(
                method,
                call,
                &path,
                &mut ChildSink {
                    fields: &mut self.fields,
                    unresolved: &mut self.unresolved,
                    recursed: &mut self.recursed,
                    bindings: &self.local_bindings.outer_at(call.span),
                },
                self.code,
                self.module,
            );
            return;
        }

        // ── child methods on a tracked child var: t.forEachChildWithTag(...) ──
        if is_child_method(method)
            && let Some(path) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            process_child_method_at(
                method,
                call,
                &path,
                &mut ChildSink {
                    fields: &mut self.fields,
                    unresolved: &mut self.unresolved,
                    recursed: &mut self.recursed,
                    bindings: &self.local_bindings.outer_at(call.span),
                },
                self.code,
                self.module,
            );
            return;
        }

        // ── Attr methods on a tracked child var: t.attrString("name") ──
        if is_value_method(method)
            && let Some(path) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
        {
            let read = self.read_field(method, call);
            if let Some(node) = node_at_mut(&mut self.fields, &path) {
                let kids = node.children.get_or_insert_with(Vec::new);
                // The same reconciliation the direct and chained reads get: a guarded copy
                // must not mask the plain read that follows it.
                merge_or_push(kids, read, &mut self.unresolved);
            }
        }

        // ── content methods on a tracked child var ──
        // (Note: the "chained `param.child("tag").content...()`" case the TS scanner
        // also tried is a no-op under pre-order visitation — the outer call is
        // visited before the inner `child()` creates the parent field, so there is
        // nothing to annotate. `contentBytes`/`contentString` chained on a child are
        // instead captured as a child field by the attr-chained branch above; only
        // the child-var form below can set `contentType`.)
        if is_content_method(method)
            && let Some(path) = as_identifier(obj)
                .and_then(|n| self.child_vars.get(n))
                .cloned()
            && let Some(f) = node_at(&mut self.fields, &path)
        {
            f.content_type = Some(content_kind(method));
        }
    }

    /// If `obj` is `param.child("tag")` or `childVar.child("tag")`, return
    /// `(parent_tag, inner_method)`.
    /// The path of the node an attribute is chained off — every level of it. Naming only
    /// the last step put `a.child("b").attrString("id")` beside `<a>` instead of inside it,
    /// so a consumer read the attribute from the wrong place on the wire.
    fn child_call_parent(&self, obj: &Expression, at: Span) -> Option<Vec<PathSeg>> {
        let inner = as_call(obj)?;
        let inner_method = match callee_method(inner)? {
            m @ ("child" | "maybeChild") => m,
            _ => return None,
        };
        let base = callee_object(inner).and_then(as_identifier)?;
        let tag = inner
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_string_lit)?;
        self.node_path(base, tag, inner_method, at)
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
        // A helper the parser binds itself is not the module's.
        if self.local_bindings.shadows(name, call.span) {
            return;
        }
        // An argument that is a tracked child var — cheap to check before any re-parse.
        // Only an argument still naming the node it was bound to: an enclosing callback may
        // have re-bound the name, and descending on the stale entry would hang the helper's
        // fields off whatever node that name used to mean.
        let Some((arg_idx, tag)) = call.arguments.iter().enumerate().find_map(|(i, a)| {
            let id = arg_expr(a).and_then(as_identifier)?;
            if !self.names_an_outer_node(id, call.span) {
                return None;
            }
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
        // The helper's parameter names the node at the end of the path; the caller's tree
        // is where the whole path lives.
        let Some(leaf) = tag.last() else { return };
        let mut recovered = analyze_child_node(
            body_src,
            bound_param,
            &leaf.tag,
            self.module,
            self.helper_depth + 1,
        );
        if self.conditional_depth > 0 {
            // In the parser's coordinates, not the helper's: these land UNDER `tag`, while
            // the promotion walks from the root. Recording them as if they sat at the top
            // meant a claim both branches establish never found its field again.
            let at = tag
                .iter()
                .map(|s| s.tag.as_str())
                .collect::<Vec<_>>()
                .join("/");
            for f in &mut recovered {
                note_relaxed(f, &at, &mut self.relaxed_by_branch);
                relax_deeply(f);
            }
        }
        merge_child_shape_at(&mut self.fields, &tag, recovered, &mut self.unresolved);
    }

    /// Descend into a helper handed *this* node — `mapChildrenWithTag("row", function (row)
    /// { parse(row) })`, where `row` is the scope's own parameter rather than a tracked
    /// child. `try_helper_descent` recognizes arguments only through `child_vars`, so the
    /// helper's reads were never entered and the element came out empty and undiagnosed.
    fn try_own_node_helper_descent(&mut self, call: &CallExpression) {
        if self.module.functions.is_empty() || self.param.is_empty() {
            return;
        }
        let Some(name) = as_identifier(&call.callee) else {
            return;
        };
        // A helper the parser binds itself is not the module's.
        if self.local_bindings.shadows(name, call.span) {
            return;
        }
        // Every position it is handed to, not just the first: `parse(e, e)` binds the
        // node to both parameters, and reading only one dropped what the other saw.
        let positions: Vec<usize> = call
            .arguments
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                arg_expr(a)
                    .and_then(as_identifier)
                    .is_some_and(|id| id == self.param && !self.bound_by_inner_scope(id, call.span))
            })
            .map(|(i, _)| i)
            .collect();
        if positions.is_empty() {
            return;
        }
        let Some((params, body_src)) = self.module.functions.get(name) else {
            return;
        };
        // Past the point where this is known to be a helper handed the node: stopping here
        // leaves the shape incomplete, and saying so is the difference between a bounded
        // descent and a silent one.
        if self.helper_depth >= 2 {
            self.unresolved.push(format!("{HELPER_DEPTH}@{name}"));
            return;
        }
        let mut recovered = Vec::new();
        let mut lost = Vec::new();
        let mut guards = Vec::new();
        for idx in positions {
            let Some(bound_param) = params.get(idx) else {
                continue;
            };
            let (f, l, g) = analyze_node_helper(
                body_src,
                bound_param,
                params,
                self.module,
                self.helper_depth + 1,
            );
            for one in f {
                merge_or_push(&mut recovered, one, &mut self.unresolved);
            }
            lost.extend(l);
            guards.extend(g);
        }
        self.unresolved.extend(lost);
        // What the helper enforces on the node it was handed is a constraint on that node,
        // and dropping it published a shape that accepts what the parser rejects — but only
        // when the parser always runs it. Reached down one branch, its guards are that
        // branch's, and hoisting them would reject everything the other branches accept.
        if self.conditional_depth == 0 {
            for g in guards {
                if !self.assertions.contains(&g) {
                    self.assertions.push(g);
                }
            }
        }
        // Reached only down one branch, its payload is not required of every element —
        // requiring it would have consumers reject the elements the other branch accepts.
        if self.conditional_depth > 0 {
            for f in &mut recovered {
                note_relaxed(f, "", &mut self.relaxed_by_branch);
                relax_deeply(f);
            }
        }
        // Merged, not skipped: the caller and the helper can both reach the same child,
        // and keeping whichever landed first dropped everything the other one saw.
        for f in recovered {
            merge_or_push(&mut self.fields, f, &mut self.unresolved);
        }
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
                    // Retype the companion read. The plain `maybeAttrString("type")` beside
                    // `attrEnumOrNullIfUnknown("type", map)` is the SAME wire attribute
                    // validated against that key set, so leaving it `type: "string"` while
                    // hanging nine `enumKeys` off it hid the constraint from every consumer
                    // that selects enum fields by `type == "enum"` — the incoming receipt's
                    // `type` shipped exactly that way.
                    let optional = wap::is_optional_method(&f.method);
                    f.method = if optional {
                        wap::MAYBE_ATTR_ENUM.to_string()
                    } else {
                        wap::ATTR_ENUM.to_string()
                    };
                    f.field_type = ParsedFieldType::Enum;
                    f.required = !optional;
                }
            } else {
                // No companion plain read created a field for this attr (doesn't occur in
                // the current corpus, but keep it well-formed): synthesize one under a
                // *recognized* optional-enum accessor — `attrEnumOrNullIfUnknown` reads an
                // optional attr validated against an enum key set, which is exactly
                // `maybeAttrEnum`. A raw "attrEnumOrNullIfUnknown" method would not be in
                // `wap::is_attr_method`, leaving the field unclassified downstream.
                let mut f = mk_field(wap::MAYBE_ATTR_ENUM, &wire, ParsedFieldType::Enum, false);
                f.enum_keys = Some(keys);
                self.fields.push(f);
            }
        }
        // The same two halves for a table that could NOT be named: mark the companion read
        // as an enum with an unrecoverable value set, or synthesize the field, so the
        // constraint is counted either way instead of vanishing.
        for wire in std::mem::take(&mut self.unresolved_enum_attrs) {
            match self
                .fields
                .iter_mut()
                .find(|f| f.name == wire && f.tag.is_none())
            {
                Some(f) if f.enum_keys.is_none() && f.pending_enum_ref.is_none() => {
                    let optional = wap::is_optional_method(&f.method);
                    f.method = if optional {
                        wap::MAYBE_ATTR_ENUM.to_string()
                    } else {
                        wap::ATTR_ENUM.to_string()
                    };
                    f.field_type = ParsedFieldType::Enum;
                    f.required = !optional;
                    f.pending_enum_ref = Some(wa_ir::PendingEnum::Unresolvable);
                }
                Some(_) => {}
                None => {
                    let mut f = mk_field(wap::MAYBE_ATTR_ENUM, &wire, ParsedFieldType::Enum, false);
                    f.pending_enum_ref = Some(wa_ir::PendingEnum::Unresolvable);
                    self.fields.push(f);
                }
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
    /// The same maps by their string *values* — what `.members()` yields for a
    /// module-local enum (`attrEnumValues("mediatype", u.members())`).
    members: HashMap<String, Vec<String>>,
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
            members: HashMap::new(),
            fn_depth: 0,
        };
        b.visit_program(&ret.program);
        Self {
            functions: b.functions,
            maps: b.maps,
            members: b.members,
        }
    }
}

struct ModuleScopeBuilder<'a> {
    module_source: &'a str,
    functions: HashMap<String, (Vec<String>, String)>,
    maps: HashMap<String, Vec<String>>,
    members: HashMap<String, Vec<String>>,
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
                // `var name = { key: val, … }` — an enum value map — or the same object
                // wrapped in a one-argument factory, which is how WA declares a
                // module-local enum: `var u = n("$InternalEnum")({Image: "image", …})`.
                // Only a factory-body-level (depth 1) binding is module-scope, the same
                // gate the helper branch above uses. Recording at ANY depth let two
                // parsers reusing one minified name share a table: the second `u.members()`
                // resolved to the first parser's values and published a closed `enumKeys`
                // set that is simply wrong — an invented constraint, worse than a lost one.
                _ => {
                    if self.fn_depth != 1 {
                        walk::walk_variable_declarator(self, d);
                        return;
                    }
                    let obj = wa_oxc::as_object(init).or_else(|| {
                        wa_oxc::as_call(init)
                            .filter(|c| c.arguments.len() == 1)
                            .and_then(|c| arg_expr(&c.arguments[0]))
                            .and_then(wa_oxc::as_object)
                    });
                    // `obj_props` silently skips a spread, a method and a computed key,
                    // so an object containing one yields a SHORTER list that still
                    // collects successfully — publishing a closed set that claims the
                    // parser rejects whatever the skipped property contributed. A table
                    // we cannot read whole is not a table.
                    let obj = obj.filter(|o| o.properties.len() == wa_oxc::obj_props(o).count());
                    if let Some(obj) = obj {
                        let n = name.as_str().to_string();
                        // Keys and values are both allowed-value sets, for *different*
                        // accessors: `attrEnumOrNullIfUnknown("t", map)` validates against
                        // the keys, while `attrEnumValues("t", enum.members())` validates
                        // against the members — the wire values. Recording only the keys
                        // left every `.members()` table unresolvable.
                        self.maps.entry(n.clone()).or_insert_with(|| {
                            wa_oxc::obj_props(obj).map(|(k, _)| k.to_string()).collect()
                        });
                        // All-or-nothing, like the cross-module resolver's `variants_of`:
                        // `{A: "a", B: computed}` must not publish `["a"]` as the complete
                        // set — that is an enum the IR says rejects `B` when the runtime
                        // accepts it. An incomplete table is left absent and the accessor
                        // is counted as unresolved instead.
                        let members: Option<Vec<String>> = wa_oxc::obj_props(obj)
                            .map(|(_, v)| as_string_lit(v).map(str::to_string))
                            .collect();
                        if let Some(members) = members.filter(|m| !m.is_empty()) {
                            self.members.entry(n).or_insert(members);
                        }
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
/// Re-analyse a module-scope helper that was handed the node being read *itself*, with its
/// parameter standing for that node. The fields come back belonging to the caller's node —
/// there is no tag to nest them under, because the helper was given no child.
fn analyze_node_helper(
    body_src: &str,
    bound_param: &str,
    formals: &[String],
    module: &ModuleScope,
    depth: u32,
) -> (Vec<ParsedField>, Vec<String>, Vec<ResponseAssertion>) {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_src);
    if ret.panicked {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let mut a = ParserAnalyzer {
        code: body_src,
        param: bound_param,
        module,
        recursed: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::new(),
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: depth,
    };
    a.local_bindings = all_bindings(&ret.program);
    // Its own parameters are names it binds: `delegate(node, parse)` calls the `parse` it
    // was handed, not the module's, and the body alone does not say so.
    a.local_bindings.names.extend(formals.iter().cloned());
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    // What the helper could not resolve is the caller's loss too: reporting the field
    // without it lets the constraint ratchet read as clean while a byte range vanished.
    // Only what the helper enforces on every path: an `assertAttr` behind its own `if`
    // holds when that branch runs, and hoisting it would have the parser demand it always.
    let mut guarded = a.conditional_assertions.clone();
    let unconditional = a
        .assertions
        .into_iter()
        .filter(|x| match guarded.iter().position(|g| g == x) {
            Some(i) => {
                guarded.swap_remove(i);
                false
            }
            None => true,
        })
        .collect();
    (a.fields, a.unresolved, unconditional)
}

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
        recursed: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::from([(node_param.to_string(), vec![PathSeg::required(tag)])]),
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: depth,
    };
    a.local_bindings = all_bindings(&ret.program);
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    a.fields
        .into_iter()
        .find(|f| f.tag.as_deref() == Some(tag))
        .and_then(|f| f.children)
        .unwrap_or_default()
}

/// Union `new_children` into the children of the node `path` names — the one a local
/// `var i = param.maybeChild("tag")` built.
fn merge_child_shape_at(
    fields: &mut Vec<ParsedField>,
    path: &[PathSeg],
    new_children: Vec<ParsedField>,
    lost: &mut Vec<String>,
) {
    // Creating, not looking up: a step of the path is only built when a read lands on it,
    // so for `var u = t.child("b"); helper(u)` the `<b>` node does not exist yet and
    // everything the helper recovered would be dropped without a word.
    let Some(field) = node_at_mut(fields, path) else {
        return;
    };
    let existing = field.children.get_or_insert_with(Vec::new);
    // Merged, not first-wins: an inline read and a helper can both reach the same node,
    // and keeping whichever landed first dropped everything the other one saw.
    for nc in new_children {
        merge_or_push(existing, nc, lost);
    }
}

/// The content kind an accessor decodes to, derived from the canonical classifier so a
/// newly-recognized spelling is typed rather than defaulted to text.
fn content_kind(method: &str) -> ContentType {
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => ContentType::Bytes,
        ParsedFieldType::Integer => ContentType::Integer,
        _ => ContentType::String,
    }
}

/// String value of the nth call argument, if it's a string literal.
fn arg_str<'b>(call: &'b CallExpression, n: usize) -> Option<&'b str> {
    call.arguments
        .get(n)
        .and_then(arg_expr)
        .and_then(as_string_lit)
}

/// One step of a tracked path: the tag, and the accessor that reached it. Materialising a
/// `maybeChild` step as a required `child` would have the IR demand an element the source
/// parser explicitly allows to be absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathSeg {
    tag: String,
    method: String,
}

impl PathSeg {
    fn required(tag: &str) -> Self {
        Self {
            tag: tag.to_string(),
            method: "child".to_string(),
        }
    }
}

/// The node `path` names, creating the chain if it is not there yet.
fn node_at_mut<'f>(
    fields: &'f mut Vec<ParsedField>,
    path: &[PathSeg],
) -> Option<&'f mut ParsedField> {
    let (seg, rest) = path.split_first()?;
    let idx = find_or_create_field(
        fields,
        &seg.tag,
        &seg.method,
        is_method_required(&seg.method),
    );
    if rest.is_empty() {
        return fields.get_mut(idx);
    }
    node_at_mut(fields[idx].children.get_or_insert_with(Vec::new), rest)
}

/// The node `path` names, without creating anything — for annotating what a read already
/// built rather than conjuring a node a later read would have to reconcile with.
fn node_at<'f>(fields: &'f mut [ParsedField], path: &[PathSeg]) -> Option<&'f mut ParsedField> {
    let (seg, rest) = path.split_first()?;
    let node = fields
        .iter_mut()
        .find(|f| f.tag.as_deref() == Some(seg.tag.as_str()))?;
    if rest.is_empty() {
        return Some(node);
    }
    node_at(node.children.as_mut()?, rest)
}

/// Put `f` under the chain of tags `path`, creating the nodes on the way.
///
/// `t.child("list").mapChildren(…)` names two levels — the tag `t` was bound to and the one
/// chained off it — and hanging the result off only the last would put a `<list>` beside
/// `<digest>` instead of inside it.
fn place_at(
    fields: &mut Vec<ParsedField>,
    path: &[PathSeg],
    f: ParsedField,
    lost: &mut Vec<String>,
) {
    let Some((seg, rest)) = path.split_first() else {
        merge_or_push(fields, f, lost);
        return;
    };
    let idx = find_or_create_field(
        fields,
        &seg.tag,
        &seg.method,
        is_method_required(&seg.method),
    );
    place_at(
        fields[idx].children.get_or_insert_with(Vec::new),
        rest,
        f,
        lost,
    );
}

/// Add `f`, folding it into a field that already maps the same tag the same way.
///
/// Two branches mapping `<row>` with different callbacks are one repeated element that
/// carries both shapes. Appending them as siblings left a later de-dup by name to keep the
/// first and drop the other branch's fields without a word.
/// Record how many arms read each node of a structural field, by its path within it.
fn count_paths(f: &ParsedField, path: &str, out: &mut std::collections::HashSet<String>) {
    out.insert(path.to_string());
    for k in f.children.iter().flatten() {
        count_paths(k, &format!("{path}/{}", k.name), out);
    }
}

/// What a shape claims, by identity, so an intersection of branches can put it back.
/// What both branches of one conditional establish.
fn branch_intersection(then_weak: &[RelaxedId], else_weak: &[RelaxedId]) -> Vec<RelaxedId> {
    then_weak
        .iter()
        .filter(|i| else_weak.contains(i))
        .cloned()
        .collect()
}

fn note_relaxed(f: &ParsedField, at: &str, out: &mut Vec<RelaxedId>) {
    if f.required {
        out.push((
            at.to_string(),
            f.method.clone(),
            f.wire_name.clone().unwrap_or_else(|| f.name.clone()),
            f.tag.clone(),
        ));
    }
    let below = below(at, f);
    for k in f.children.iter().flatten() {
        note_relaxed(k, &below, out);
    }
}

/// Where a field sits, not merely what it is called. Two branches whose helpers read an
/// `id` under different children produced the same identity, and intersecting them
/// promoted both — requiring an attribute neither branch enforces on every path.
type RelaxedId = (String, String, String, Option<String>);

fn below(at: &str, f: &ParsedField) -> String {
    if at.is_empty() {
        f.name.clone()
    } else {
        format!("{at}/{}", f.name)
    }
}

/// Put a claim back on the field it belongs to, wherever it sits.
fn promote_required(fields: &mut [ParsedField], id: &RelaxedId, at: &str) {
    for f in fields.iter_mut() {
        let here = (
            at.to_string(),
            f.method.clone(),
            f.wire_name.clone().unwrap_or_else(|| f.name.clone()),
            f.tag.clone(),
        );
        if here == *id {
            f.required = true;
        }
        let below = below(at, f);
        if let Some(kids) = f.children.as_mut() {
            promote_required(kids, id, &below);
        }
    }
}

/// Loosen a whole shape. A helper reached only down a branch says nothing about any part
/// of what it reads — weakening its top level and leaving the descendants required made a
/// present child missing its attributes a rejection the source parser never makes.
fn relax_deeply(f: &mut ParsedField) {
    f.required = false;
    for k in f.children.iter_mut().flatten() {
        relax_deeply(k);
    }
}

/// Loosen only what some arm does not read. A child hoisted out of the arms is merged from
/// all of them, and one that only the `a` arm reaches cannot be required of a `b` element —
/// but one every arm reads is required all the same, and weakening it would accept nodes
/// the parser rejects.
fn relax_absent_from_some_arm(
    f: &mut ParsedField,
    path: &str,
    seen: &HashMap<String, usize>,
    arms: usize,
) {
    if seen.get(path).copied().unwrap_or(0) < arms {
        f.required = false;
    }
    for k in f.children.iter_mut().flatten() {
        let child_path = format!("{path}/{}", k.name);
        relax_absent_from_some_arm(k, &child_path, seen, arms);
    }
}

/// The `dropsByReason` key for two reads of one field whose constraints disagree.
const MERGE_CONFLICT: &str = "incompatibleRepeatedRead";

/// Every caller passes a sink: a merge that cannot represent both reads is a loss like any
/// other, and the convenience wrapper that dropped `lost` on the floor meant seven of the
/// nine merge sites reported nothing at all.
fn merge_or_push(into: &mut Vec<ParsedField>, f: ParsedField, lost: &mut Vec<String>) {
    // Identity includes what the field reads, not only what it is called: a dispatch can
    // give two arms' reads the same runtime name while they take different attributes.
    let Some(i) = into.iter().position(|g| {
        g.method == f.method && g.tag == f.tag && g.name == f.name && g.wire_name == f.wire_name
    }) else {
        into.push(f);
        return;
    };
    // Two reads of one field: if either happens unconditionally the field IS required,
    // and keeping whichever landed first let a helper's guarded copy mask a later plain
    // read of the same attribute.
    into[i].required |= f.required;
    take_constraints(&mut into[i], &f, lost);
    let Some(incoming) = f.children else { return };
    let existing = into[i].children.get_or_insert_with(Vec::new);
    // Recursively: two branches that both map `<row>` may differ only in what their nested
    // `<sub>` reads, and taking the first `<sub>` whole would drop what the other accepts.
    for c in incoming {
        merge_or_push(existing, c, lost);
    }
}

/// Carry what the incoming read pins onto the one already recorded.
///
/// Coalescing repeated reads kept only the first field's metadata, so a second
/// `contentBytesRange` — which the parser enforces just as much — simply vanished. Where
/// only one side pins something the pin is taken; where both pin something different the
/// merge cannot represent both, and says so rather than publishing whichever came first.
fn take_constraints(into: &mut ParsedField, from: &ParsedField, lost: &mut Vec<String>) {
    macro_rules! carry {
        ($($field:ident),+ $(,)?) => {$(
            match (&into.$field, &from.$field) {
                (None, Some(v)) => into.$field = Some(v.clone()),
                (Some(a), Some(b)) if a != b => {
                    lost.push(format!("{MERGE_CONFLICT}@{}:{}", stringify!($field), into.name));
                }
                _ => {}
            }
        )+};
    }
    carry!(
        byte_length,
        byte_min,
        byte_max,
        int_min,
        int_max,
        enum_keys,
        enum_ref,
        pending_enum_ref,
        literal_value,
        content_type,
        reference_path,
        source_path,
        repeats,
    );
}

/// Reads a dispatch chain where it actually sits, rather than looking for comparisons
/// anywhere in the body.
///
/// Scanning for every `if` against the discriminator kept mistaking things for arms: one
/// nested inside another arm, one under an unrelated guard, one in a block that shadowed
/// the binding. Each was a separate patch. Reading the chain structurally settles all of
/// them at once — a statement is an arm only if it IS one of the chain's own statements,
/// and anything the chain does not account for declines the transformation.
struct DispatchChain {
    arms: Vec<(Vec<String>, Span)>,
}

/// The statements a dispatch chain lives among: the callback body, unwrapped through the
/// braces the slice carries and into the label the minifier wraps the chain in — which the
/// discriminator's own declaration sits outside of.
fn chain_statements<'b, 'a>(body: &'b [Statement<'a>]) -> &'b [Statement<'a>] {
    let mut stmts = body;
    while let [Statement::BlockStatement(b)] = stmts {
        stmts = &b.body;
    }
    let mut labelled = stmts.iter().filter_map(|stmt| match stmt {
        Statement::LabeledStatement(l) => match &l.body {
            Statement::BlockStatement(b) => Some(&b.body[..]),
            _ => None,
        },
        _ => None,
    });
    match (labelled.next(), labelled.next()) {
        // Exactly one labelled region holds the chain. With two, arms live in both and
        // reading one would leave the other's payload to be hoisted as unconditional —
        // requiring each variant to carry the other's fields.
        (Some(only), None) => only,
        (Some(_), Some(_)) => &[],
        _ => stmts,
    }
}

/// Whether any statement outside `chain` compares `subject` — an arm the chain does not
/// hold. Reading the label alone left such an arm to be hoisted as an unconditional field,
/// so the recognized variants required a payload only the outsider carries.
fn arms_outside(body: &[Statement<'_>], chain: &[Statement<'_>], subject: &str) -> bool {
    let (lo, hi) = match (chain.first(), chain.last()) {
        (Some(f), Some(l)) => (f.span().start, l.span().end),
        _ => return false,
    };
    fn scan(stmts: &[Statement<'_>], lo: u32, hi: u32, subject: &str) -> bool {
        stmts.iter().any(|s| {
            let sp = s.span();
            if sp.start >= lo && sp.end <= hi {
                return false;
            }
            match s {
                Statement::BlockStatement(b) => scan(&b.body, lo, hi, subject),
                Statement::LabeledStatement(l) => {
                    scan(std::slice::from_ref(&l.body), lo, hi, subject)
                }
                _ => compares_subject(s, subject),
            }
        })
    }
    scan(body, lo, hi, subject)
}

/// A name as the Rust codegen will spell it as a struct member.
///
/// The scanner cannot call `wa-codegen`'s `snake_case` — the dependency runs the other way
/// — so the rule is mirrored here: break at a lower/digit→upper boundary and before the
/// last capital of an acronym, then fold everything that is not alphanumeric. Only ever
/// used to ask whether two IR names would land on ONE member, never to rename a field.
fn rust_member_form(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 {
            let prev = chars[i - 1];
            let camel =
                (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && c.is_ascii_uppercase();
            let acronym = prev.is_ascii_uppercase()
                && c.is_ascii_uppercase()
                && chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            if (camel || acronym) && !out.ends_with('_') {
                out.push('_');
            }
        }
        out.push(if c.is_ascii_alphanumeric() { c } else { '_' });
    }
    let mut folded = String::with_capacity(out.len());
    for c in out.chars() {
        if c == '_' && folded.ends_with('_') {
            continue;
        }
        folded.push(c);
    }
    folded.trim_matches('_').to_lowercase()
}

/// One property holds one read, across every arm merged into a variant.
///
/// Two independent arms testing the SAME literal both run, so a property both assign holds
/// only the last value. Merged into one variant they sat side by side — two members of one
/// name, which the codegen emits as a struct that does not compile. The earlier read still
/// happened, so it keeps its wire name rather than disappearing.
///
/// False when the variant still cannot be spelled: the wire name a displaced read falls
/// back to can be one another property already took — `t.value = first; t.value = second;
/// t.first = third` leaves two members called `first` — and there is no name left that is
/// both free and true. The caller declines rather than emitting a struct that will not
/// compile.
fn one_read_per_property(fields: &mut [ParsedField]) -> bool {
    let mut last: HashMap<String, usize> = HashMap::new();
    for (i, f) in fields.iter().enumerate() {
        last.insert(f.name.clone(), i);
    }
    for (i, f) in fields.iter_mut().enumerate() {
        if last.get(&f.name) != Some(&i)
            && let Some(wire) = f.wire_name.clone()
        {
            f.name = wire;
        }
    }
    // As the codegen will spell them: `fooBar` and `foo_bar` are two properties in
    // JavaScript and one member in Rust, so comparing the names verbatim let the pair
    // through into a struct that does not compile.
    let mut seen: std::collections::HashSet<String> = Default::default();
    fields
        .iter()
        .all(|f| seen.insert(rust_member_form(&f.name)))
}

/// Whether `stmt` ends the body on every path it can take. A bare `return`/`throw`, or a
/// block that reaches one — `{ return result; }` runs exactly as the bare statement does,
/// and the arms after either of them are unreachable.
/// Whether control can reach past `stmt` without having run what is inside it — the
/// question `conditional_depth` exists to answer, asked once instead of at each visitor.
///
/// A helper called only down such a path does not make its payload required of every
/// element, and its guards are that path's rather than the caller's. Enumerating the
/// forms at the point of use is how `switch`, then the loops, then a caught `try` each
/// arrived separately as the same bug: the guards of a helper reached one way only were
/// hoisted onto every element, and generated decoding then rejected the paths the parser
/// accepts.
///
/// `if`, `?:` and `&&` are absent on purpose — they raise the counter in their own
/// visitors, which also track *what* the test proved. `try` is absent because its three
/// parts disagree and the walk reaches them through one node; see `visit_try_statement`.
fn skips_on_some_path(stmt: &Statement<'_>) -> bool {
    match stmt {
        // A case runs for its own value; the others reach past it. True even with a
        // `default`: an exhaustive switch whose every case reads the same field would be
        // required after all, but under-requiring only accepts more than the parser does,
        // where over-requiring rejects what it accepts.
        Statement::SwitchStatement(_) => true,
        // Zero iterations is a path through the loop that runs none of the body.
        Statement::WhileStatement(_)
        | Statement::ForStatement(_)
        | Statement::ForInStatement(_)
        | Statement::ForOfStatement(_) => true,
        // `do` runs its body before the test, so one pass is guaranteed — unless a `break`
        // or `continue` can cut that pass short, which leaves the rest of the body no more
        // certain than a branch.
        Statement::DoWhileStatement(d) => contains_exit(&d.body),
        _ => false,
    }
}

fn exits_unconditionally(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        // `break x` jumps past the labelled block the chain lives in, so the value that
        // reached it takes no later arm. An UNLABELLED break leaves only the nearest loop
        // or switch, and is read where those are.
        Statement::BreakStatement(b) => b.label.is_some(),
        // Only an unconditional one: a `return` under an `if` inside the block is a path,
        // not the block's outcome, so the statements after it still run.
        Statement::BlockStatement(b) => b.body.iter().any(exits_unconditionally),
        Statement::LabeledStatement(l) => exits_unconditionally(&l.body),
        // Both ways out are still out: `if (flag) return a; else return b;` ends the body
        // on every path it can take, and matching only the bare forms let the arms after
        // it be synthesized as reachable. A one-sided `if` is not this — the missing
        // branch falls through and the statements after it run.
        Statement::IfStatement(i) => {
            exits_unconditionally(&i.consequent)
                && i.alternate.as_ref().is_some_and(exits_unconditionally)
        }
        // Every path out of the switch leaves the callback: a `default`, so no value falls
        // past the end, and every case exiting.
        //
        // A case exits by its own body OR by falling through to one that does —
        // `case "x": read(); default: return r;` runs the default's `return` for `"x"`
        // too. Demanding an exit in each case's own consequent called that switch
        // non-exiting, which is the harmful direction: the arms after it were then merged
        // and their payload required of a value the parser never reaches them for.
        // `break` is the one thing that neither exits nor falls through.
        // `try { return r; } finally { … }` returns; the finalizer runs on the way out
        // without stopping it, and a finalizer that returns of its own leaves on every
        // path. With a `catch`, the try block's exit is not the only outcome, so the
        // handler has to reach one too.
        // `do { return r; } while (c)` runs its body before the test, so an exit in the
        // first iteration is an exit full stop — unlike `while`/`for`, whose body may
        // never run. That asymmetry is why the naming pass treats `do`/`while` as
        // unconditional too.
        Statement::DoWhileStatement(d) => exits_unconditionally(&d.body),
        Statement::TryStatement(t) => {
            let finalizer = t
                .finalizer
                .as_ref()
                .is_some_and(|f| f.body.iter().any(exits_unconditionally));
            if finalizer {
                return true;
            }
            let block = t.block.body.iter().any(exits_unconditionally);
            match t.handler.as_ref() {
                Some(h) => block && h.body.body.iter().any(exits_unconditionally),
                None => block,
            }
        }
        Statement::SwitchStatement(s) => {
            let mut exits_from = vec![false; s.cases.len()];
            for i in (0..s.cases.len()).rev() {
                let body = &s.cases[i].consequent;
                exits_from[i] = if body.iter().any(exits_unconditionally) {
                    true
                } else if body
                    .iter()
                    .any(|st| matches!(st, Statement::BreakStatement(_)))
                {
                    false
                } else {
                    exits_from.get(i + 1).copied().unwrap_or(false)
                };
            }
            s.cases.iter().any(|c| c.test.is_none()) && exits_from.iter().all(|e| *e)
        }
        _ => false,
    }
}

/// Whether any statement under `stmt` compares `subject` — an arm nested inside another
/// arm is not a sibling alternative, and the shape cannot say so.
fn compares_subject(stmt: &Statement<'_>, subject: &str) -> bool {
    struct Probe<'s> {
        subject: &'s str,
        found: bool,
    }
    impl<'a> Visit<'a> for Probe<'_> {
        fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
        fn visit_arrow_function_expression(
            &mut self,
            _f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
        }
        // Any expression, not only an `if` test: `kind === "b" && …` inside the `a` arm is
        // just as unreachable, and placing its read in `a` made consumers reject elements
        // the parser accepts.
        fn visit_expression(&mut self, e: &Expression<'a>) {
            if equality_literals(e, self.subject).is_some_and(|l| !l.is_empty()) {
                self.found = true;
            }
            walk::walk_expression(self, e);
        }
    }
    let mut p = Probe {
        subject,
        found: false,
    };
    p.visit_statement(stmt);
    p.found
}

/// How many times `subject` is bound under `stmt`, and whether it is ever written to.
/// The discriminator is bound once, up front; a second binding or any assignment means a
/// later comparison tests something other than the wire attribute keyed on here.
fn rebinds_subject(stmt: &Statement<'_>, subject: &str) -> (usize, bool) {
    struct Counter<'s> {
        subject: &'s str,
        bindings: usize,
        written: bool,
    }
    impl<'a> Visit<'a> for Counter<'_> {
        fn visit_variable_declaration(&mut self, d: &VariableDeclaration<'a>) {
            for decl in &d.declarations {
                self.bindings += decl
                    .id
                    .get_binding_identifiers()
                    .iter()
                    .filter(|i| i.name == self.subject)
                    .count();
            }
            walk::walk_variable_declaration(self, d);
        }
        fn visit_assignment_expression(&mut self, e: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left
                && id.name == self.subject
            {
                self.written = true;
            }
            walk::walk_assignment_expression(self, e);
        }

        // `[kind] = values` overwrites it as surely as `kind = …`; matching only a bare
        // identifier on the left let the comparisons after it be read as alternatives
        // keyed on a wire attribute the subject no longer holds.
        fn visit_assignment_target(&mut self, t: &oxc_ast::ast::AssignmentTarget<'a>) {
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = t
                && id.name == self.subject
            {
                self.written = true;
            }
            walk::walk_assignment_target(self, t);
        }

        // `kind++` writes it as surely as `kind = …`, and the comparisons after it test
        // something the wire never said.
        fn visit_update_expression(&mut self, e: &oxc_ast::ast::UpdateExpression<'a>) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) =
                &e.argument
                && id.name == self.subject
            {
                self.written = true;
            }
            walk::walk_update_expression(self, e);
        }
    }
    let mut c = Counter {
        subject,
        bindings: 0,
        written: false,
    };
    c.visit_statement(stmt);
    (c.bindings, c.written)
}

impl DispatchChain {
    /// Read the chain, or decline. Declining leaves the body extracted flat, which is what
    /// it was before this shape was recognized at all — never a loss.
    fn read(body: &[Statement<'_>], subject: &str, bound_at: u32) -> Option<Self> {
        let stmts = chain_statements(body);
        if arms_outside(body, stmts, subject) {
            return None;
        }
        // Counted over the whole body, not just the chain: the declaration usually sits
        // outside the label, and an assignment between the two would be missed there.
        let mut bindings = 0usize;
        for stmt in body {
            let (n, written) = rebinds_subject(stmt, subject);
            bindings += n;
            if written {
                return None;
            }
        }
        if bindings > 1 {
            return None;
        }
        let mut arms: Vec<(Vec<String>, Span)> = Vec::new();
        // Values whose arm ended the callback, so a later arm naming one cannot run.
        let mut exited: std::collections::HashSet<String> = Default::default();
        for stmt in stmts.iter() {
            // Nothing after an unconditional exit runs, so a comparison there is not an
            // alternative the element can take. A block is as final as a bare statement —
            // `{ return result; }` ends the body just the same, and matching only the
            // spelling let the arms after it be synthesized as reachable.
            if exits_unconditionally(stmt) {
                break;
            }
            let Statement::IfStatement(first) = stmt else {
                // A comparison the chain does not hold as an arm of its own — one nested in
                // a block between two siblings — would be left to `body_without_arms` and
                // hoisted as a field of every variant, requiring each of them to carry a
                // payload only that branch reads. `arms_outside` cannot see it: the block
                // sits INSIDE the chain's own span.
                if compares_subject(stmt, subject) {
                    return None;
                }
                continue;
            };
            // Before the accessor runs the name holds `undefined`, so the comparison is
            // not against the wire attribute this dispatch is keyed on.
            if first.span.start < bound_at {
                return None;
            }
            let mut current = &**first;
            // Within one chain the arms are mutually exclusive, so a literal repeated in it
            // is unreachable — unlike two independent `if`s on the same value, which both
            // run and are merged. Merging this one would require the second arm's reads of
            // elements the parser never gives them to.
            let mut in_this_chain: std::collections::HashSet<String> = Default::default();
            loop {
                let lits = equality_literals(&current.test, subject)?;
                if lits.is_empty() {
                    return None;
                }
                // The arm's own body must not compare the discriminator again: that
                // comparison is reachable only inside this arm, never as a sibling.
                if compares_subject(&current.consequent, subject) {
                    return None;
                }
                let owned: Vec<String> = lits.into_iter().map(str::to_string).collect();
                if owned.iter().any(|l| !in_this_chain.insert(l.clone())) {
                    return None;
                }
                // An arm that ends the callback makes a LATER arm for the same value
                // unreachable — the merge of two arms sharing a literal is sound only
                // because both run. Merging past an exit required of that value a payload
                // the parser never reads for it. Arms for other values are untouched:
                // the exit only rules out the value that reached it.
                if owned.iter().any(|l| exited.contains(l)) {
                    return None;
                }
                if exits_unconditionally(&current.consequent) {
                    exited.extend(owned.iter().cloned());
                }
                arms.push((owned, current.consequent.span()));
                match &current.alternate {
                    // `else if` continues the chain — and must also be the discriminator.
                    Some(Statement::IfStatement(next)) => current = next,
                    // A plain `else` payload belongs to no value.
                    Some(_) => return None,
                    None => break,
                }
            }
        }
        (arms.len() >= 2).then_some(Self { arms })
    }
}

/// The wire names a guard asks about — `hasAttr("x")`, `hasChild("x")` — through `&&`,
/// `||` and parentheses. Only these say a field may be absent; any other condition is
/// about something else entirely.
/// How a receiver names its node: the identifier it bottoms out at, plus the tags of any
/// `child`/`maybeChild` steps. `e.child("detail")` is `e/detail`, so a guard on it is not
/// mistaken for a guard on `e` — nor discarded for not being a bare name.
fn receiver_path(expr: &Expression<'_>) -> Option<String> {
    if let Some(n) = as_identifier(expr) {
        return Some(n.to_string());
    }
    let call = as_call(expr)?;
    let step = match callee_method(call)? {
        m @ ("child" | "maybeChild") => {
            let _ = m;
            arg_str(call, 0)?
        }
        _ => return None,
    };
    Some(format!("{}/{step}", receiver_path(callee_object(call)?)?))
}

fn presence_tested(test: &Expression<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    fn walk(e: &Expression<'_>, out: &mut Vec<(String, String)>) {
        match e {
            Expression::ParenthesizedExpression(p) => walk(&p.expression, out),
            // Only through `&&`: a test that holds when EITHER side does establishes
            // nothing, since the other side may be what satisfied it.
            Expression::LogicalExpression(l)
                if l.operator == oxc_syntax::operator::LogicalOperator::And =>
            {
                walk(&l.left, out);
                walk(&l.right, out);
            }
            // Anything else — a negation, a comparison, a call whose result is tested
            // against something — is not the plain truth test this rule is about. Naming
            // the forms that INVERT kept missing one (`!x`, then `x || y`, then the `else`
            // branch, then `x === false`); requiring the form that ESTABLISHES cannot.
            _ => {
                if let Some(call) = as_call(e)
                    && matches!(callee_method(call), Some(wap::HAS_ATTR) | Some("hasChild"))
                    && let Some(node) = callee_object(call).and_then(receiver_path)
                    && let Some(name) = arg_str(call, 0)
                {
                    out.push((node, name.to_string()));
                }
            }
        }
    }
    walk(test, &mut out);
    out
}

/// Every name a source binds, at any depth — `var` hoists and functions are declared
/// wherever, so this is a pre-pass rather than something the walk can accumulate.
#[derive(Default)]
struct AllBindings {
    /// Bound at the top of the analysed source, so in scope throughout it.
    names: std::collections::HashSet<String>,
    /// Bound inside a nested function or a block, with the extent it covers. A sibling
    /// callback — or a block — that happens to bind the same short name does not shadow a
    /// helper called outside it.
    scoped: Vec<(Span, String)>,
    fns: Vec<Span>,
    blocks: Vec<Span>,
    /// Whether the binding being collected reaches past its block: a parameter, a `var`,
    /// or a function declaration. `let`, `const`, a class and a `catch` parameter stop at
    /// the block — the same split `BoundNames` keeps, which this collector was missing.
    hoists: bool,
}

impl AllBindings {
    fn bind(&mut self, name: &str, hoists: bool) {
        let extent = if hoists {
            self.fns.last().copied()
        } else {
            self.blocks
                .last()
                .copied()
                .or_else(|| self.fns.last().copied())
        };
        match extent {
            Some(e) => self.scoped.push((e, name.to_string())),
            None => {
                self.names.insert(name.to_string());
            }
        }
    }
}

impl<'a> Visit<'a> for AllBindings {
    fn visit_binding_identifier(&mut self, id: &oxc_ast::ast::BindingIdentifier<'a>) {
        self.bind(id.name.as_str(), self.hoists);
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        let outer = self.hoists;
        self.hoists = !decl.kind.is_lexical();
        walk::walk_variable_declaration(self, decl);
        self.hoists = outer;
    }

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        self.blocks.push(block.span);
        walk::walk_block_statement(self, block);
        self.blocks.pop();
    }

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        // A declaration binds its name in the scope it sits in — recorded against its own
        // body, a call beside it would not see the local and would resolve the module's. A
        // named function EXPRESSION is the other way round: its name exists only inside it.
        if let Some(id) = func.id.as_ref() {
            if func.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration {
                // In a strict bundle a declaration in a nested block binds only there; at
                // the top of a body the current extent is the function anyway.
                self.bind(id.name.as_str(), false);
            } else {
                self.scoped.push((func.span, id.name.as_str().to_string()));
            }
        }
        self.fns.push(func.span);
        let outer = self.hoists;
        self.hoists = true;
        walk::walk_function(self, func, flags);
        self.hoists = outer;
        self.fns.pop();
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.fns.push(func.span);
        let outer = self.hoists;
        // An arrow's parameters are its own, the same as any function's. Walking them
        // without saying so recorded them against the block enclosing the arrow, so an
        // unrelated `parse => 0` shadowed the module helper for everything around it.
        self.hoists = true;
        self.visit_formal_parameters(&func.params);
        self.hoists = false;
        self.visit_function_body(&func.body);
        self.hoists = outer;
        self.fns.pop();
    }

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        self.blocks.push(clause.span);
        let outer = self.hoists;
        self.hoists = false;
        walk::walk_catch_clause(self, clause);
        self.hoists = outer;
        self.blocks.pop();
    }

    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        // The cases share one block, and the discriminant is evaluated outside it.
        let body = stmt.cases.first().map_or(stmt.span, |first| {
            Span::new(first.span.start, stmt.span.end)
        });
        self.blocks.push(body);
        walk::walk_switch_statement(self, stmt);
        self.blocks.pop();
    }

    fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
        self.blocks.push(stmt.span);
        walk::walk_for_statement(self, stmt);
        self.blocks.pop();
    }

    fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
        self.blocks.push(stmt.span);
        walk::walk_for_in_statement(self, stmt);
        self.blocks.pop();
    }

    fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
        self.blocks.push(stmt.span);
        walk::walk_for_of_statement(self, stmt);
        self.blocks.pop();
    }

    fn visit_class(&mut self, class: &oxc_ast::ast::Class<'a>) {
        // A declaration introduces its name where it sits; a named class expression binds
        // it only inside itself.
        if let Some(id) = class.id.as_ref() {
            if class.r#type == oxc_ast::ast::ClassType::ClassDeclaration {
                self.bind(id.name.as_str(), false);
            } else {
                self.scoped.push((class.span, id.name.as_str().to_string()));
            }
        }
        self.visit_class_body(&class.body);
    }
}

/// Where each name the source binds is in scope.
#[derive(Default, Clone)]
struct Bindings {
    names: std::collections::HashSet<String>,
    scoped: Vec<(Span, String)>,
}

impl Bindings {
    /// Whether `name` is bound by this source at `at` — and so is not the module's helper
    /// of that name. Scoped by extent: suppressing every call because some unrelated
    /// nested function reused the name is a silent loss of its fields.
    fn shadows(&self, name: &str, at: Span) -> bool {
        self.names.contains(name) || self.bound_inside(name, at)
    }

    /// Whether `name` is bound by a scope strictly inside this source that contains `at` —
    /// a callback's own binding rather than the analysed body's. One collector answers
    /// this and [`Self::shadows`]: keeping a second one for it meant every extent had to
    /// be taught twice, and five of them only ever reached one side.
    fn bound_inside(&self, name: &str, at: Span) -> bool {
        self.scoped
            .iter()
            .any(|(e, n)| n == name && at.start >= e.start && at.end <= e.end)
    }

    /// The tightest scope containing `at`, which is how far a name bound there reaches.
    fn innermost_extent(&self, at: Span) -> Option<Span> {
        self.scoped
            .iter()
            .map(|(e, _)| *e)
            .filter(|e| at.start >= e.start && at.end <= e.end)
            .min_by_key(|e| e.end - e.start)
    }

    /// The names in scope at `at` — what a callback sited there inherits. Not only the
    /// function-wide ones: a `let` enclosing the callback is in scope for it, and passing
    /// just `names` let the callback resolve a module helper the parser had shadowed.
    fn outer_at(&self, at: Span) -> std::collections::HashSet<String> {
        let mut out = self.names.clone();
        out.extend(
            self.scoped
                .iter()
                .filter(|(e, _)| at.start >= e.start && at.end <= e.end)
                .map(|(_, n)| n.clone()),
        );
        out
    }
}

fn all_bindings(program: &oxc_ast::ast::Program<'_>) -> Bindings {
    let mut c = AllBindings::default();
    c.visit_program(program);
    Bindings {
        names: c.names,
        scoped: c.scoped,
    }
}

/// Finds the attribute a dispatch reads once and then branches on.
struct DiscriminatorFinder<'s> {
    param: &'s str,
    /// The scope the reads are resolved against, for the constraint tables an accessor
    /// may name.
    module: &'s ModuleScope,
    /// Every attribute a local is bound to, in source order: the name, the field the read
    /// produces, and where the accessor ends. The field, not just its accessor — a
    /// dispatch on `attrEnum` pins a value table, and rebuilding the discriminator from
    /// the method alone dropped it while `fold_unaccounted` removed the populated copy.
    /// Which of these drives the dispatch is not knowable here; taking the first meant an
    /// unrelated `var id = e.attrString("id")` read before it sank the whole thing.
    found: Vec<(String, ParsedField, u32, Option<Span>)>,
    /// Enclosing blocks, so a binding's own extent is known: a block-local `kind` is not
    /// the outer name the comparisons after the block actually test.
    blocks: Vec<Span>,
}

impl<'a> Visit<'a> for DiscriminatorFinder<'_> {
    // Same reason as `ArmCollector`: a reused parameter name inside a nested callback is a
    // different node, and reading its attribute is not this element's discriminator.
    fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _f: &oxc_ast::ast::ArrowFunctionExpression<'a>) {}

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        self.blocks.push(block.span);
        walk::walk_block_statement(self, block);
        self.blocks.pop();
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for d in &decl.declarations {
            if let (Some(bound), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                && let Some(call) = as_call(init)
                && let Some(method) = callee_method(call)
                && wap::is_attr_method(method)
                && callee_object(call).and_then(as_identifier) == Some(self.param)
                && let Some(wire) = arg_str(call, 0)
            {
                let mut discard = Vec::new();
                let mut f = field_from_call(method, call, self.module, &mut discard);
                f.name = wire.to_string();
                f.wire_name = None;
                let extent = self.blocks.last().copied();
                self.found
                    .push((bound.as_str().to_string(), f, call.span.end, extent));
            }
        }
        walk::walk_variable_declaration(self, decl);
    }
}

/// Every string literal `name` is compared against with `===` in `test`, through `||`.
fn equality_literals<'b>(test: &'b Expression<'_>, name: &str) -> Option<Vec<&'b str>> {
    match test {
        Expression::ParenthesizedExpression(p) => equality_literals(&p.expression, name),
        Expression::LogicalExpression(l)
            if l.operator == oxc_syntax::operator::LogicalOperator::Or =>
        {
            // Every operand, or none of it: `kind === "a" || isLegacy` also runs for values
            // this shape cannot name, and a union keyed on `kind` alone would claim it does.
            let mut left = equality_literals(&l.left, name)?;
            left.extend(equality_literals(&l.right, name)?);
            Some(left)
        }
        Expression::BinaryExpression(b)
            if b.operator == oxc_ast::ast::BinaryOperator::StrictEquality =>
        {
            for (a, other) in [(&b.left, &b.right), (&b.right, &b.left)] {
                if as_identifier(a) == Some(name)
                    && let Some(lit) = as_string_lit(other)
                {
                    return Some(vec![lit]);
                }
            }
            None
        }
        _ => None,
    }
}

/// The property a variant's value is assigned to — `readReceipts` in
/// `var r = e.attrEnum("value", …); t.readReceipts = r`. That is the name the runtime
/// gives the field, and it is not recoverable from the wire, where every arm reads the
/// same `value`.
///
/// Only an assignment whose right-hand side is the value the arm just read counts: an arm
/// that sets a flag first would otherwise stamp that flag's name onto the field, and a
/// wrong output name is harder to notice than a missing one.
/// The leaf a read lands on. A content accessor takes no wire name — the scanner files it
/// under `content` — so demanding an argument dropped `result.body = e.contentString()` and
/// the variant exposed `content` instead of the property the parser returns.
fn read_key(call: &CallExpression<'_>) -> Option<String> {
    match callee_method(call) {
        Some(m) if is_content_method(m) => Some("content".to_string()),
        _ => arg_str(call, 0).map(str::to_string),
    }
}

fn assigned_names(src: &str, param: &str) -> (HashMap<String, Vec<(String, String)>>, bool) {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, src);
    if ret.panicked {
        return (HashMap::new(), false);
    }
    struct Finder<'s> {
        param: &'s str,
        /// Local name → the wire attribute it was read from, in this arm.
        from_wire: HashMap<String, String>,
        /// What each open block displaced, to put back when it closes.
        blocks: Vec<Vec<(String, Option<String>)>>,
        /// Wire attribute → the (object, property) pairs its value is assigned to.
        named: HashMap<String, Vec<(String, String)>>,
        /// Conditionals open around the assignment being visited.
        depth: u32,
        /// The depth each property was last claimed at, to tell a straight-line
        /// overwrite from one that only happens down a branch.
        claimed_at: HashMap<(String, String), u32>,
        /// Set when a property is claimed by two reads that do not overwrite each other:
        /// `if (flag) t.value = a; else t.value = b` returns one or the other, and
        /// naming the later one alone published a field the parser often does not return.
        branch_dependent: bool,
    }
    impl<'a> Visit<'a> for Finder<'_> {
        // A nested callback reusing the parameter's name reads a different node; its
        // assignment would claim the wire name first and rename the field after it.
        fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
        fn visit_arrow_function_expression(
            &mut self,
            _f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
        }

        fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
            for d in &decl.declarations {
                let Some(bound) = d.id.get_identifier_name() else {
                    continue;
                };
                let name = bound.as_str().to_string();
                // A lexical alias ends with its block; what it displaced comes back, or the
                // outer name would go on pointing at the inner read.
                if decl.kind.is_lexical()
                    && let Some(frame) = self.blocks.last_mut()
                {
                    frame.push((name.clone(), self.from_wire.get(&name).cloned()));
                }
                // Whatever it is now, it is no longer the outer read: `{ let v = 0; }` over
                // a tracked `v` used to leave the wire mapping live, and the constant the
                // block actually returns was published under the outer attribute's name.
                let read = d
                    .init
                    .as_ref()
                    .and_then(as_call)
                    .filter(|call| {
                        callee_method(call).is_some_and(is_value_method)
                            && callee_object(call).and_then(as_identifier) == Some(self.param)
                    })
                    .and_then(read_key);
                match read {
                    Some(wire) => {
                        self.from_wire.insert(name, wire);
                    }
                    None => {
                        self.from_wire.remove(&name);
                    }
                }
            }
            walk::walk_variable_declaration(self, decl);
        }

        // Only the branches: the test itself runs on every path through the statement.
        fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
            self.visit_expression(&stmt.test);
            self.depth += 1;
            self.visit_statement(&stmt.consequent);
            if let Some(alt) = &stmt.alternate {
                self.visit_statement(alt);
            }
            self.depth -= 1;
        }

        fn visit_conditional_expression(&mut self, e: &oxc_ast::ast::ConditionalExpression<'a>) {
            self.visit_expression(&e.test);
            self.depth += 1;
            self.visit_expression(&e.consequent);
            self.visit_expression(&e.alternate);
            self.depth -= 1;
        }

        // `flag && (t.value = x)` performs the assignment only when the left side allows
        // it, exactly like a branch. Left unraised, the write looked unconditional and
        // took the property from an earlier read that may well be the one returned.
        fn visit_logical_expression(&mut self, e: &oxc_ast::ast::LogicalExpression<'a>) {
            self.visit_expression(&e.left);
            self.depth += 1;
            self.visit_expression(&e.right);
            self.depth -= 1;
        }

        fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
            self.visit_expression(&stmt.discriminant);
            self.depth += 1;
            for case in &stmt.cases {
                self.visit_switch_case(case);
            }
            self.depth -= 1;
        }

        // Everything after a statement that CAN leave the callback runs only on the paths
        // that did not. `t.value = first; if (flag) return t; t.value = second` overwrote
        // the property outright, though the early return hands back the first read.
        fn visit_statements(&mut self, stmts: &oxc_allocator::Vec<'a, Statement<'a>>) {
            let mut past_exit = false;
            for stmt in stmts {
                if past_exit {
                    self.depth += 1;
                }
                self.visit_statement(stmt);
                if past_exit {
                    self.depth -= 1;
                } else if contains_exit(stmt) {
                    past_exit = true;
                }
            }
        }

        // The `try` body may stop partway and the `catch` runs only when it does, so a
        // write in either is one the other path does not make. Visiting both at depth zero
        // let the catch's assignment look like an unconditional overwrite of the try's.
        fn visit_try_statement(&mut self, t: &oxc_ast::ast::TryStatement<'a>) {
            self.depth += 1;
            self.visit_block_statement(&t.block);
            if let Some(h) = &t.handler {
                self.visit_catch_clause(h);
            }
            self.depth -= 1;
            // The finalizer runs on every path out, so a write there is not conditional.
            if let Some(f) = &t.finalizer {
                self.visit_block_statement(f);
            }
        }

        // A loop that runs zero times performs no write, so a property set in its body may
        // still hold whatever an earlier read put there. The init runs regardless; the
        // test, the update and the body do not. `do`/`while` is deliberately absent — its
        // body always runs once, so a write there really is unconditional.
        fn visit_for_statement(&mut self, s: &oxc_ast::ast::ForStatement<'a>) {
            if let Some(init) = &s.init {
                walk::walk_for_statement_init(self, init);
            }
            self.depth += 1;
            if let Some(test) = &s.test {
                self.visit_expression(test);
            }
            if let Some(update) = &s.update {
                self.visit_expression(update);
            }
            self.visit_statement(&s.body);
            self.depth -= 1;
        }

        fn visit_for_of_statement(&mut self, s: &oxc_ast::ast::ForOfStatement<'a>) {
            self.visit_expression(&s.right);
            self.depth += 1;
            walk::walk_for_statement_left(self, &s.left);
            self.visit_statement(&s.body);
            self.depth -= 1;
        }

        fn visit_for_in_statement(&mut self, s: &oxc_ast::ast::ForInStatement<'a>) {
            self.visit_expression(&s.right);
            self.depth += 1;
            walk::walk_for_statement_left(self, &s.left);
            self.visit_statement(&s.body);
            self.depth -= 1;
        }

        fn visit_while_statement(&mut self, s: &oxc_ast::ast::WhileStatement<'a>) {
            self.visit_expression(&s.test);
            self.depth += 1;
            self.visit_statement(&s.body);
            self.depth -= 1;
        }

        fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
            self.blocks.push(Vec::new());
            walk::walk_block_statement(self, block);
            for (name, prev) in self.blocks.pop().unwrap_or_default() {
                match prev {
                    Some(w) => self.from_wire.insert(name, w),
                    None => self.from_wire.remove(&name),
                };
            }
        }

        // `x++` leaves a number where the read was, so the alias no longer names it. Found
        // by sweeping for the sibling of the assignment case rather than by another round.
        fn visit_update_expression(&mut self, e: &oxc_ast::ast::UpdateExpression<'a>) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) =
                &e.argument
            {
                self.from_wire.remove(id.name.as_str());
            }
            walk::walk_update_expression(self, e);
        }

        fn visit_assignment_expression(&mut self, e: &oxc_ast::ast::AssignmentExpression<'a>) {
            // `t.total += e.attrInt("delta")` returns the SUM, not the read, and `||=` may
            // not even perform it. Taken as a plain assignment, the variant published the
            // raw delta under `total` — a value the parser never returns. The read still
            // happened, so it keeps its own wire name; only the property naming is refused.
            if e.operator != oxc_syntax::operator::AssignmentOperator::Assign {
                if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left {
                    self.from_wire.remove(id.name.as_str());
                }
                walk::walk_assignment_expression(self, e);
                return;
            }
            // `x = e.attrString("other")` makes `x` name the other attribute — or, if the
            // new value is not a wire read at all, nothing this can follow. Left alone,
            // the property was being attached to whatever `x` used to hold.
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left {
                let name = id.name.as_str().to_string();
                let rebound = as_call(&e.right).filter(|c| {
                    callee_method(c).is_some_and(is_value_method)
                        && callee_object(c).and_then(as_identifier) == Some(self.param)
                });
                match rebound.and_then(read_key) {
                    Some(wire) => {
                        // Rebound only down a branch, the alias names the earlier read or
                        // the later one depending on which path ran. Overwriting the map
                        // published the later one unconditionally, so a `t.value = x`
                        // after it claimed a read the callback often does not return.
                        if self.depth > 0 && self.from_wire.get(&name).is_some_and(|w| *w != wire) {
                            self.branch_dependent = true;
                        }
                        self.from_wire.insert(name, wire);
                    }
                    None => {
                        // Down a branch, `x = "fixed"` leaves `x` holding the read on the
                        // other path, so a later `t.value = x` names it there and not
                        // here. Dropping the mapping silently published the read under its
                        // wire name as though the property never claimed it.
                        if self.depth > 0 && self.from_wire.contains_key(&name) {
                            self.branch_dependent = true;
                        }
                        self.from_wire.remove(&name);
                    }
                }
            }
            let assigned_to = match &e.left {
                oxc_ast::ast::AssignmentTarget::StaticMemberExpression(m) => {
                    as_identifier(&m.object)
                        .map(|r| (r.to_string(), m.property.name.as_str().to_string()))
                }
                // `result["callAdd"] = …` names the field as plainly as the dotted form.
                oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(m) => {
                    as_identifier(&m.object)
                        .zip(as_string_lit(&m.expression))
                        .map(|(r, p)| (r.to_string(), p.to_string()))
                }
                _ => None,
            };
            if let Some((receiver, property)) = assigned_to {
                // Either spelling: through a temporary, or the accessor written straight
                // into the result — `t.callAdd = e.attrEnum("value", …)`.
                let wire = as_identifier(&e.right)
                    .and_then(|r| self.from_wire.get(r))
                    .cloned()
                    .or_else(|| {
                        let call = as_call(&e.right)?;
                        (callee_method(call).is_some_and(is_value_method)
                            && callee_object(call).and_then(as_identifier) == Some(self.param))
                        .then(|| read_key(call))?
                    });
                if let Some(wire) = wire {
                    // One property, one value: `t.value = x; t.value = y` returns `y`, and
                    // naming both reads after it gave a variant two fields called `value`
                    // — a struct the codegen cannot emit. The earlier read still happened,
                    // so it keeps its wire name rather than disappearing.
                    let key = (receiver.clone(), property.clone());
                    let taken = self
                        .named
                        .iter()
                        .find(|(w, names)| {
                            **w != wire
                                && names.iter().any(|(r, p)| *r == receiver && *p == property)
                        })
                        .is_some();
                    // A later assignment overwrites an earlier one only when both are on
                    // the same path. Under a conditional it may not run at all, and the
                    // property then holds whichever read the taken branch performed —
                    // something one field cannot say, so the shape is refused instead.
                    if taken
                        && (self.depth > 0 || self.claimed_at.get(&key).is_some_and(|d| *d > 0))
                    {
                        self.branch_dependent = true;
                    }
                    for (w, names) in self.named.iter_mut() {
                        if *w != wire {
                            names.retain(|(r, p)| !(*r == receiver && *p == property));
                        }
                    }
                    self.named.retain(|_, names| !names.is_empty());
                    self.claimed_at.insert(key, self.depth);
                    // Keyed by the object written to as well: an assignment to something
                    // else — a cache, a log — is not a field of the result, and taking its
                    // property name exposed an API field the parser never returns.
                    let names = self.named.entry(wire).or_default();
                    if !names.iter().any(|(r, p)| *r == receiver && *p == property) {
                        names.push((receiver.clone(), property));
                    }
                }
            }
            walk::walk_assignment_expression(self, e);
        }
    }
    let mut f = Finder {
        param,
        from_wire: HashMap::new(),
        blocks: Vec::new(),
        named: HashMap::new(),
        depth: 0,
        claimed_at: HashMap::new(),
        branch_dependent: false,
    };
    f.visit_program(&ret.program);
    (f.named, f.branch_dependent)
}

/// Add back every flat read the dispatch does not already account for.
///
/// The reconstruction covers the discriminator, what the arms read, and what they lift out
/// of themselves. A leaf read outside the branches — an id taken before the chain, or in a
/// branch that tests something else — belongs to the element just as much, and is in
/// neither the union nor `unresolved`.
fn fold_unaccounted(
    mut dispatched: Vec<ParsedField>,
    outside: Vec<ParsedField>,
    lost: &mut Vec<String>,
) -> Vec<ParsedField> {
    /// What a read IS, not only what it is called: a `<id>` child and an `id` attribute
    /// share a name and nothing else, and matching on the name alone dropped one of them.
    fn identity(f: &ParsedField) -> (String, String, Option<String>) {
        (
            f.method.clone(),
            f.wire_name.clone().unwrap_or_else(|| f.name.clone()),
            f.tag.clone(),
        )
    }
    let accounted: std::collections::HashSet<(String, String, Option<String>)> =
        dispatched.iter().map(identity).collect();
    for f in outside {
        // A leaf whose identity is already there was renamed by its arm, and merging would
        // push a second copy under the wire name. A structural field is different: the
        // dispatch holds the same child, and skipping it whole dropped everything the
        // callback reads on that child outside the arms.
        let mergeable = dispatched.iter().any(|g| {
            g.method == f.method && g.tag == f.tag && g.name == f.name && g.wire_name == f.wire_name
        });
        if !accounted.contains(&identity(&f)) || (f.children.is_some() && mergeable) {
            merge_or_push(&mut dispatched, f, lost);
        }
    }
    dispatched
}

/// The callback's source with each arm blanked out, so re-analysing it shows exactly what
/// the element reads OUTSIDE the dispatch.
///
/// Which reads the arms explain cannot be told from the merged flat result: `value` read
/// in two of four arms, and `id` read in one arm plus once outside, look identical there.
/// This asks the question instead of inferring it from how many variants carry a field.
fn body_without_arms(body_src: &str, arms: &[(Vec<String>, Span)], base: u32) -> String {
    let mut out = body_src.as_bytes().to_vec();
    for (_, span) in arms {
        let (s, e) = (
            span.start.saturating_sub(base) as usize,
            span.end.saturating_sub(base) as usize,
        );
        if e > out.len() || e.saturating_sub(s) < 2 {
            continue;
        }
        // Keep it parseable: an `if` still needs a body, so leave empty braces behind.
        for b in &mut out[s..e] {
            *b = b' ';
        }
        out[s] = b'{';
        out[e - 1] = b'}';
    }
    String::from_utf8(out).unwrap_or_else(|_| body_src.to_string())
}

/// Read a `<category name="…" value="…">` dispatch: one attribute picks both the enum the
/// value is validated against and the name the runtime gives it.
///
/// Extracted flat, the ten arms became ten sibling `value` fields, each with a different
/// enum and none saying which `name` selects it — the linkage and the output names were
/// both gone. As a union the arms stay apart, each pinned by the attribute that chooses it.
fn discriminated_children(
    body_src: &str,
    param: &str,
    module: &ModuleScope,
    outer_bindings: &std::collections::HashSet<String>,
    lost: &mut Vec<String>,
) -> Option<Vec<ParsedField>> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, body_src);
    if ret.panicked {
        return None;
    }

    // `var n = param.attrString("name")` — the discriminator, read once, up front. The
    // callback's body arrives wrapped in its own braces, so this is not a top-level
    // statement of the slice.
    let mut finder = DiscriminatorFinder {
        param,
        module,
        found: Vec::new(),
        blocks: Vec::new(),
    };
    finder.visit_program(&ret.program);
    // The one a chain is actually built on.
    let (_bound, disc_field, collector) =
        finder.found.into_iter().find_map(|(b, f, at, extent)| {
            // The arms compare against string literals, so an accessor whose value is a number
            // or a JID never takes any of them — a union keyed on those strings would describe
            // branches the parser cannot reach.
            if !matches!(
                f.field_type,
                ParsedFieldType::String | ParsedFieldType::Enum
            ) {
                return None;
            }
            let chain = DispatchChain::read(&ret.program.body, &b, at)?;
            // Every arm has to sit where this binding is the one being compared; a block-local
            // one says nothing about the comparisons after its block.
            if let Some(e) = extent
                && !chain
                    .arms
                    .iter()
                    .all(|(_, s)| s.start >= e.start && s.end <= e.end)
            {
                return None;
            }
            Some((b, f, chain))
        })?;
    let wire = disc_field.name.clone();

    // What the element does outside the chain, computed first: its bindings are in scope
    // for every arm, and an arm re-analysed without them cannot resolve a node the body
    // bound before the dispatch.
    let base = ret.program.span.start;
    let outside = analyze_with_scope(
        &body_without_arms(body_src, &collector.arms, base),
        param,
        module,
        outer_bindings,
    );

    // Which object the arms are building. An assignment to anything else — a cache, a log
    // — is not a field of the result, and its property name would surface as an API field
    // the parser never returns. The one the most arms write to is the accumulator.
    let accumulator = {
        // Frequency alone let a cache written by more arms than the result win, and its
        // property names became the generated API. The name the body hands back settles it.
        // A returned name that stands for one object or another depending on which path
        // ran cannot settle the accumulator, and guessing hands the API to whichever
        // object a branch happens to name.
        let (returned, ambiguous) = returned_names(body_src);
        if ambiguous {
            return None;
        }
        let mut per_arm: HashMap<String, usize> = HashMap::new();
        for (_, span) in &collector.arms {
            let src = &body_src[span.start as usize..span.end as usize];
            let mut here: std::collections::HashSet<String> = Default::default();
            for pairs in assigned_names(src, param).0.values() {
                here.extend(pairs.iter().map(|(r, _)| r.clone()));
            }
            for r in here {
                *per_arm.entry(r).or_default() += 1;
            }
        }
        let pick = |m: &HashMap<String, usize>| {
            m.iter()
                .max_by_key(|(name, n)| (**n, std::cmp::Reverse((*name).clone())))
                .map(|(name, _)| name.clone())
        };
        let handed_back: HashMap<String, usize> = per_arm
            .iter()
            .filter(|(name, _)| returned.contains(*name))
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        pick(&handed_back).or_else(|| pick(&per_arm))
    };

    let mut variants: Vec<UnionVariant> = Vec::new();
    let mut common: Vec<ParsedField> = Vec::new();
    // Counted over the values, not the branches: two arms handling one value merge into one
    // variant, and a denominator of two made a child both of them require look optional.
    let mut distinct_values: std::collections::HashSet<String> = Default::default();
    // The VALUES a child is read under, not the branches that read it: two arms testing the
    // same literal merge into one variant, and counting each of them made a child only that
    // variant carries look required of every variant.
    let mut structural_cover: std::collections::HashSet<(String, String)> = Default::default();
    for (lits, span) in &collector.arms {
        let arm_src = &body_src[span.start as usize..span.end as usize];
        let arm = analyze_seeded(
            arm_src,
            param,
            module,
            outer_bindings,
            outside.child_vars.clone(),
        );
        // An arm whose property mapping depends on which branch ran cannot be spelled as
        // one variant; declining leaves the body extracted flat.
        let (runtime_names, branch_dependent) = assigned_names(arm_src, param);
        if branch_dependent {
            return None;
        }
        // Only the leaf the arm selects belongs to the variant. Anything structural it
        // also reads — the `<error>` its reporting helper picks up — is the element's.
        let (leaves, structural): (Vec<_>, Vec<_>) = arm
            .fields
            .iter()
            .cloned()
            .partition(|f| f.children.is_none());
        for lit in lits {
            distinct_values.insert(lit.clone());
        }
        // Once per arm: an arm reading `<detail>` both as a child and as a mapped element
        // still only proves that ONE arm reaches it.
        let mut in_this_arm: std::collections::HashSet<String> = Default::default();
        for f in structural {
            count_paths(&f, &f.name, &mut in_this_arm);
            // A child lifted out of the arms carries ONE set of constraints, so two arms
            // pinning the same leaf differently — `count` in `1..=10` for `a` and
            // `20..=30` for `b` — cannot both be honoured there. The merge reports the
            // clash; keeping the first arm's band silently rejected values the source
            // accepts for the other, so the dispatch is refused instead.
            let mut clash = Vec::new();
            merge_or_push(&mut common, f, &mut clash);
            if clash.iter().any(|m| m.starts_with(MERGE_CONFLICT)) {
                return None;
            }
            lost.extend(clash);
        }
        for path in in_this_arm {
            for lit in lits {
                structural_cover.insert((lit.clone(), path.clone()));
            }
        }
        for lit in lits {
            // Each leaf takes the name of the property ITS value is assigned to, and one
            // read feeding two properties yields both — the parser returns both.
            let fields: Vec<ParsedField> = leaves
                .iter()
                .cloned()
                .flat_map(|f| {
                    let mine: Vec<&String> = runtime_names
                        .get(&f.name)
                        .into_iter()
                        .flatten()
                        .filter(|(r, _)| Some(r) == accumulator.as_ref())
                        .map(|(_, p)| p)
                        .collect();
                    if mine.is_empty() {
                        return vec![f];
                    }
                    mine.into_iter()
                        .map(|n| {
                            let mut one = f.clone();
                            one.wire_name = Some(f.name.clone());
                            one.name = n.clone();
                            one
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            // The same literal tested twice is one alternative, not two: emitted twice it
            // would be an unreachable arm, and the codegen refuses the whole union for it.
            if let Some(existing) = variants.iter_mut().find(|v| v.name == *lit) {
                for f in fields {
                    merge_or_push(&mut existing.fields, f, lost);
                }
                // Both branches run for this value, so both branches' guards hold.
                for a in &arm.assertions {
                    if !existing.assertions.contains(a) {
                        existing.assertions.push(a.clone());
                    }
                }
                continue;
            }
            // Whatever else the arm enforces goes with it. Replacing its assertions with
            // the synthesized discriminator alone published a variant that accepts what
            // the parser turns away — and stripped the very thing the codegen's exact
            // check would have refused the shape for.
            let mut assertions = vec![ResponseAssertion {
                kind: AssertionKind::Attr,
                name: Some(wire.clone()),
                value: Some(lit.to_string()),
                reference_path: None,
            }];
            // An arm that spells out the value its comparison already established adds
            // nothing. Kept as a second assertion it made the codegen — which allows
            // exactly one — refuse an otherwise representable union, dropping the field
            // and every arm's payload with it.
            let synthesized = assertions[0].clone();
            assertions.extend(
                arm.assertions
                    .iter()
                    .filter(|a| **a != synthesized)
                    .cloned(),
            );
            variants.push(UnionVariant {
                name: lit.to_string(),
                fields,
                assertions,
            });
        }
    }
    if variants.len() < 2 {
        return None;
    }
    // A child only some arms read is not the element's to require: lifted beside the union
    // it would apply to every variant, and a consumer would reject the ones that never
    // carry it. The same goes for what is INSIDE it — arms reading `detail.a` and
    // `detail.b` share the `<detail>` but not its contents, and requiring both would
    // reject the elements either arm accepts.
    let mut structural_seen: HashMap<String, usize> = HashMap::new();
    for (_, path) in structural_cover {
        *structural_seen.entry(path).or_default() += 1;
    }
    for f in &mut common {
        let path = f.name.clone();
        relax_absent_from_some_arm(f, &path, &structural_seen, distinct_values.len());
    }

    // Applied after every arm has been merged in: within one arm the last assignment
    // already wins, but two arms testing one literal are merged here and both survived.
    for v in &mut variants {
        if !one_read_per_property(&mut v.fields) {
            return None;
        }
    }

    let mut union = mk_field("dispatch", &wire, ParsedFieldType::Union, true);
    union.wire_name = None;
    // The name is synthesized, so it can land on one the element already reads —
    // discriminator `kind` beside an `e.attrString("kind_dispatch")` gave two fields that
    // name, and the codegen emits them as one struct with a duplicate member. Nothing
    // depends on the exact spelling, so the collision is stepped over rather than
    // declining the whole reconstruction. Everything the field could sit beside is
    // counted: what the arms lift out, and what the body reads outside them.
    union.name = {
        // Compared as the codegen will spell them: `kindDispatch` and `kind_dispatch` are
        // one Rust member, so matching the IR names verbatim let the pair through.
        let taken: std::collections::HashSet<String> = std::iter::once(&disc_field.name)
            .chain(common.iter().map(|f| &f.name))
            .chain(outside.fields.iter().map(|f| &f.name))
            .map(|n| rust_member_form(n))
            .collect();
        let mut name = format!("{wire}_dispatch");
        let mut n = 2;
        while taken.contains(&rust_member_form(&name)) {
            name = format!("{wire}_dispatch_{n}");
            n += 1;
        }
        name
    };
    union.union_variants = Some(variants);
    let mut out = vec![disc_field];
    out.extend(common);
    out.push(union);
    // Whatever the element reads outside the chain is still its own — asked directly of
    // the body with the arms blanked.
    Some(fold_unaccounted(out, outside.fields, lost))
}

/// The names a body hands back — `return result` — ignoring what nested callbacks return,
/// which belong to their own scope.
fn returned_names(src: &str) -> (std::collections::HashSet<String>, bool) {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, src);
    if ret.panicked {
        return (Default::default(), false);
    }
    struct Returns {
        depth: usize,
        out: std::collections::HashSet<String>,
        /// `var alias = result` — the name on the left stands for the one on the right.
        aliases: HashMap<String, String>,
        /// Conditionals open around the alias being recorded.
        cond: usize,
        /// Set when the returned name stands for one object or another depending on which
        /// path ran — `alias = result; if (flag) alias = cache; return alias`.
        ambiguous: bool,
    }
    impl<'a> Visit<'a> for Returns {
        fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
            self.depth += 1;
            walk::walk_function(self, f, flags);
            self.depth -= 1;
        }
        fn visit_arrow_function_expression(
            &mut self,
            f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.depth += 1;
            walk::walk_arrow_function_expression(self, f);
            self.depth -= 1;
        }
        fn visit_variable_declaration(&mut self, d: &VariableDeclaration<'a>) {
            if self.depth == 0 {
                for decl in &d.declarations {
                    if let Some(name) = decl.id.get_identifier_name()
                        && let Some(init) = decl.init.as_ref().and_then(as_identifier)
                    {
                        if self.cond > 0
                            && self
                                .aliases
                                .get(name.as_str())
                                .is_some_and(|prev| prev != init)
                        {
                            self.ambiguous = true;
                        }
                        self.aliases
                            .insert(name.as_str().to_string(), init.to_string());
                    }
                }
            }
            walk::walk_variable_declaration(self, d);
        }

        // `var alias; alias = result;` stands for the accumulator exactly as the
        // declarator form does — reading only initializers left the returned name
        // unresolved and the choice fell back to frequency.
        fn visit_assignment_expression(&mut self, e: &oxc_ast::ast::AssignmentExpression<'a>) {
            if self.depth == 0
                && e.operator == oxc_syntax::operator::AssignmentOperator::Assign
                && let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left
                && let Some(from) = as_identifier(&e.right)
            {
                let name = id.name.as_str().to_string();
                // Down a branch it may not run, so the name stands for the earlier target
                // on the other path. Overwriting the map handed the accumulator choice to
                // whichever object the branch happens to name.
                if self.cond > 0 && self.aliases.get(&name).is_some_and(|prev| prev != from) {
                    self.ambiguous = true;
                }
                self.aliases.insert(name, from.to_string());
            }
            walk::walk_assignment_expression(self, e);
        }

        fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
            self.visit_expression(&stmt.test);
            self.cond += 1;
            self.visit_statement(&stmt.consequent);
            if let Some(alt) = &stmt.alternate {
                self.visit_statement(alt);
            }
            self.cond -= 1;
        }

        fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
            self.visit_expression(&stmt.discriminant);
            self.cond += 1;
            for case in &stmt.cases {
                self.visit_switch_case(case);
            }
            self.cond -= 1;
        }

        // A body that may run zero times repoints the alias only on some paths, exactly
        // like a branch. `do`/`while` is absent on purpose: its body always runs, so the
        // rebinding there really is unconditional.
        fn visit_for_statement(&mut self, s: &oxc_ast::ast::ForStatement<'a>) {
            if let Some(init) = &s.init {
                walk::walk_for_statement_init(self, init);
            }
            self.cond += 1;
            walk::walk_for_statement(self, s);
            self.cond -= 1;
        }

        fn visit_for_of_statement(&mut self, s: &oxc_ast::ast::ForOfStatement<'a>) {
            self.visit_expression(&s.right);
            self.cond += 1;
            self.visit_statement(&s.body);
            self.cond -= 1;
        }

        fn visit_for_in_statement(&mut self, s: &oxc_ast::ast::ForInStatement<'a>) {
            self.visit_expression(&s.right);
            self.cond += 1;
            self.visit_statement(&s.body);
            self.cond -= 1;
        }

        fn visit_while_statement(&mut self, s: &oxc_ast::ast::WhileStatement<'a>) {
            self.visit_expression(&s.test);
            self.cond += 1;
            self.visit_statement(&s.body);
            self.cond -= 1;
        }

        fn visit_conditional_expression(&mut self, e: &oxc_ast::ast::ConditionalExpression<'a>) {
            self.visit_expression(&e.test);
            self.cond += 1;
            self.visit_expression(&e.consequent);
            self.visit_expression(&e.alternate);
            self.cond -= 1;
        }

        fn visit_logical_expression(&mut self, e: &oxc_ast::ast::LogicalExpression<'a>) {
            self.visit_expression(&e.left);
            self.cond += 1;
            self.visit_expression(&e.right);
            self.cond -= 1;
        }

        fn visit_return_statement(&mut self, r: &oxc_ast::ast::ReturnStatement<'a>) {
            if self.depth == 0
                && let Some(a) = &r.argument
            {
                // `return flag ? result : cache` hands back one object or the other, and
                // reading only a bare identifier saw neither — so the accumulator fell to
                // the frequency tie-break and a cache took the API.
                let mut named = Vec::new();
                returned_candidates(a, &mut named);
                self.out.extend(named);
            }
            walk::walk_return_statement(self, r);
        }
    }
    let mut f = Returns {
        depth: 0,
        out: Default::default(),
        aliases: HashMap::new(),
        cond: 0,
        ambiguous: false,
    };
    f.visit_program(&ret.program);
    // `var result = {}, alias = result; … return alias` hands back the accumulator under
    // another name. Comparing the returned identifier directly found nothing that matched,
    // so the choice fell to the frequency tie-break and a cache written by more arms than
    // the result took the API. Following the alias chain settles it; the bound stops a
    // `a = b; b = a` cycle from spinning.
    // Every returned name, followed to the object it ultimately stands for. Two returns
    // naming aliases of ONE object are no ambiguity at all; two naming different objects
    // cannot both be the accumulator, and picking either publishes the other's fields.
    let mut roots: std::collections::HashSet<String> = Default::default();
    let mut out = f.out.clone();
    for name in f.out {
        let mut at = name;
        for _ in 0..8 {
            let Some(next) = f.aliases.get(&at) else {
                break;
            };
            out.insert(next.clone());
            if *next == at {
                break;
            }
            at = next.clone();
        }
        roots.insert(at);
    }
    // And the other direction: `var out = result; out.foo = …; return result` writes the
    // accumulator through a name the return never mentions. Matching receivers against the
    // returned set alone found none of them, so the choice fell to the frequency tie-break
    // and a cache took the API.
    for _ in 0..8 {
        let more: Vec<String> = f
            .aliases
            .iter()
            .filter(|(alias, target)| out.contains(*target) && !out.contains(*alias))
            .map(|(alias, _)| alias.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    (out, f.ambiguous || roots.len() > 1)
}

/// The objects a `return` can hand back: a bare name, or either side of a ternary or
/// short-circuit that chooses between them.
fn returned_candidates(e: &Expression<'_>, out: &mut Vec<String>) {
    match e {
        Expression::ParenthesizedExpression(p) => returned_candidates(&p.expression, out),
        Expression::ConditionalExpression(c) => {
            returned_candidates(&c.consequent, out);
            returned_candidates(&c.alternate, out);
        }
        Expression::LogicalExpression(l) => {
            returned_candidates(&l.left, out);
            returned_candidates(&l.right, out);
        }
        _ => {
            if let Some(n) = as_identifier(e) {
                out.push(n.to_string());
            }
        }
    }
}

/// Whether `stmt` can stop the statements after it from running — a `return`/`throw` that
/// leaves the callback, or a `break`/`continue` that skips the rest of the enclosing body.
///
/// `break` matters for the one loop whose body is otherwise guaranteed: `do { if (flag)
/// break; t.value = second; } while (…)` runs its body once, but not all of it, so the
/// write is no more certain than one behind an `if`.
fn contains_exit(stmt: &Statement<'_>) -> bool {
    struct Probe {
        found: bool,
    }
    impl<'a> Visit<'a> for Probe {
        fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
        fn visit_arrow_function_expression(
            &mut self,
            _f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
        }
        fn visit_return_statement(&mut self, _r: &oxc_ast::ast::ReturnStatement<'a>) {
            self.found = true;
        }
        fn visit_throw_statement(&mut self, _t: &oxc_ast::ast::ThrowStatement<'a>) {
            self.found = true;
        }
        fn visit_break_statement(&mut self, _b: &oxc_ast::ast::BreakStatement<'a>) {
            self.found = true;
        }
        fn visit_continue_statement(&mut self, _c: &oxc_ast::ast::ContinueStatement<'a>) {
            self.found = true;
        }
    }
    let mut p = Probe { found: false };
    p.visit_statement(stmt);
    p.found
}

/// The bound name and body source of a child callback, written either as
/// `function (n) {…}` or as an arrow — including the expression-bodied `n => n.attrString(…)`.
fn callback_scope<'c>(expr: &Expression<'_>, code: &'c str) -> Option<(String, &'c str, Span)> {
    let (params, body) = match expr {
        Expression::FunctionExpression(f) => {
            (&f.params, f.body.as_ref()? as &oxc_ast::ast::FunctionBody)
        }
        Expression::ArrowFunctionExpression(f) => {
            (&f.params, &f.body as &oxc_ast::ast::FunctionBody)
        }
        _ => return None,
    };
    let param = params.items.first()?.pattern.get_identifier_name()?;
    Some((
        param.as_str().to_string(),
        &code[body.span.start as usize..body.span.end as usize],
        body.span,
    ))
}

/// Where [`process_child_method`] writes what re-analysing a callback produced.
struct ChildSink<'a> {
    fields: &'a mut Vec<ParsedField>,
    unresolved: &'a mut Vec<String>,
    /// See [`ParserAnalyzer::recursed`].
    recursed: &'a mut Vec<Span>,
    /// See [`ParserAnalyzer::local_bindings`] — the callback inherits what encloses it.
    bindings: &'a std::collections::HashSet<String>,
}

fn process_child_method(
    method: &str,
    call: &CallExpression,
    parent_tag: &str,
    sink: &mut ChildSink,
    code: &str,
    module: &ModuleScope,
) {
    let path: Vec<PathSeg> = if parent_tag.is_empty() {
        Vec::new()
    } else {
        vec![PathSeg::required(parent_tag)]
    };
    process_child_method_at(method, call, &path, sink, code, module);
}

fn process_child_method_at(
    method: &str,
    call: &CallExpression,
    path: &[PathSeg],
    sink: &mut ChildSink,
    code: &str,
    module: &ModuleScope,
) {
    match method {
        "forEachChildWithTag" | "mapChildrenWithTag" => {
            let Some(child_tag) = arg_str(call, 0) else {
                return;
            };
            let Some(cb) = call.arguments.get(1).and_then(arg_expr) else {
                return;
            };
            let Some((cb_param, cb_body, cb_span)) = callback_scope(cb, code) else {
                return;
            };
            sink.recursed.push(cb_span);
            let child_result = analyze_with_scope(cb_body, &cb_param, module, sink.bindings);

            let mut f = mk_field(method, child_tag, ParsedFieldType::String, true);
            f.tag = Some(child_tag.to_string());
            // A body that dispatches on one of its own attributes describes alternatives,
            // not a flat record: keep them apart rather than as same-named siblings. What
            // it reads outside the dispatch is still the element's own, and replacing the
            // flat result wholesale dropped it — silently, which is the one outcome this
            // module is built to avoid.
            f.children = Some(
                match discriminated_children(
                    cb_body,
                    &cb_param,
                    module,
                    sink.bindings,
                    sink.unresolved,
                ) {
                    Some(dispatched) => dispatched,
                    None => child_result.fields,
                },
            );
            f.repeats = Some(true);
            // What the child's own scope could not resolve is still a loss for the parser.
            sink.unresolved.extend(child_result.unresolved);
            place_at(sink.fields, path, f, sink.unresolved);
        }
        "mapChildren" => {
            let Some(cb) = call.arguments.first().and_then(arg_expr) else {
                return;
            };
            let Some((cb_param, cb_body, cb_span)) = callback_scope(cb, code) else {
                return;
            };
            sink.recursed.push(cb_span);
            let child_result = analyze_with_scope(cb_body, &cb_param, module, sink.bindings);

            let mut f = mk_field("mapChildren", "children", ParsedFieldType::String, true);
            f.children = Some(child_result.fields);
            f.repeats = Some(true);
            sink.unresolved.extend(child_result.unresolved);
            place_at(sink.fields, path, f, sink.unresolved);
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
    fn a_child_method_on_the_param_nests_at_the_root() {
        // `incomingMsgParser` writes `e.mapChildrenWithTag("enc", …)` straight on its own
        // node. Only the chained and child-var forms were handled, so the repeated element
        // was never built — and the callback's reads reached the IR only because the
        // callback names its parameter after the parser's, landing flat at the root.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("enc", function(e){ e.attrString("type"); e.maybeAttrInt("count"); }); }"#,
            "e",
        );
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["enc"], "one repeated child, nothing flat beside it");
        let enc = &r.fields[0];
        assert_eq!(enc.repeats, Some(true));
        assert_eq!(
            enc.children
                .as_ref()
                .unwrap()
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["type", "count"],
            "the callback's reads belong to the child, once"
        );
    }

    #[test]
    fn an_arrow_callback_builds_the_child_too() {
        // Suppressing the shadowed parameter without teaching the recursion about arrows
        // would drop the callback's reads entirely instead of nesting them.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("enc", (e) => { e.attrString("type"); }); }"#,
            "e",
        );
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["enc"], "the arrow callback still builds its child");
        assert_eq!(
            r.fields[0]
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["type"]),
            "and its reads land inside, not nowhere"
        );
    }

    #[test]
    fn an_expression_bodied_arrow_callback_builds_the_child_too() {
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("enc", (e) => e.attrString("type")); }"#,
            "e",
        );
        assert_eq!(
            r.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["enc"]
        );
        assert_eq!(
            r.fields[0]
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["type"]),
        );
    }

    #[test]
    fn a_child_var_inside_a_shadowed_callback_stays_inside() {
        // The shadow counter suppresses direct calls on the reused name, but a descendant
        // bound inside the callback must not register in the outer analyzer's child map —
        // its reads would surface a second time at the response root.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("row", function(e){ var x = e.child("inner"); x.attrString("id"); }); }"#,
            "e",
        );
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["row"],
            "no `inner` leaking to the root beside `row`"
        );
    }

    #[test]
    fn a_callback_rebinding_an_outer_child_var_does_not_misplace_its_reads() {
        // `productListResponse` binds `var t = e.child("product_list")`, then inside the
        // mapped callback binds `var t = e.maybeChild("id")` over it. Reading the callback
        // twice resolved `t.contentString()` against whichever binding the outer analyser
        // held — landing under `id` at the root, or under `product_list`. Both are wrong:
        // it belongs to the `id` of each `product`.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("product_list");
                 t.forEachChildWithTag("product", function(e){
                   var t = e.maybeChild("id");
                   t.contentString();
                 }); }"#,
            "e",
        );
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["product_list"], "nothing beside the one child");
        let product_list = &r.fields[0];
        let kids = product_list.children.as_ref().unwrap();
        assert_eq!(
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["product"],
            "`product_list` holds only the mapped child — no stray `content`"
        );
        assert_eq!(
            kids[0]
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id"]),
            "the rebound read belongs to the product's `id`"
        );
    }

    #[test]
    fn a_callback_reading_a_captured_child_keeps_that_read() {
        // The callback's own bindings are not the parser's nodes, but `x` is: it was bound
        // outside and only captured here. The recursion analyses the body with no bindings
        // at all, so it cannot place this read — suppressing it by span alone lost `meta`'s
        // `id` outright.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){ x.attrString("id"); row.attrString("v"); }); }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n);
        assert_eq!(
            by("meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id"]),
            "the captured node keeps the read made through it"
        );
        assert_eq!(
            by("row")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["v"]),
            "and the callback's own read stays where the recursion put it"
        );
        assert!(
            r.unresolved.is_empty(),
            "nothing counted lost: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_captured_child_read_survives_a_callback_that_shadows_the_param() {
        // Same capture, but the callback re-binds `e` as the minifier usually writes it:
        // the shadow arm has to make the same exception the span arm does.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.forEachChildWithTag("row", function(e){ x.attrString("id"); }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id"]),
        );
    }

    #[test]
    fn a_callback_rebinding_an_outer_child_var_does_not_read_through_the_stale_one() {
        // `usyncParser` binds `r` to `<usync>`, then re-binds `r` inside a `forEach` to a
        // child of `<result>`. Resolving the inner `r` against the outer binding published
        // `usync/refresh` and an `<error>` at the response root — neither is where the wire
        // puts them. `a` is only captured, never re-bound, so reads through it still count.
        let r = analyze_parser_ast(
            r#"{ t.assertAttr("type","result"); var n={}, r=t.child("usync"), a=r.child("result");
                 Object.keys(c).forEach(function(e){
                   var t=c[e]; var r=a.maybeChild(t);
                   if(r){ var o=r.maybeChild("error");
                     o ? n.error[t]={errorCode:o.attrInt("code")}
                       : (n.refresh[t]=r.attrInt("refresh",0)) } }); }"#,
            "t",
        );
        assert_eq!(
            r.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["usync"],
            "no `error` at the root, and no `refresh` under the wrong node"
        );
        assert!(
            r.fields[0]
                .children
                .as_ref()
                .is_none_or(|c| c.iter().all(|f| f.name != "refresh")),
            "`refresh` is not a child of `usync`"
        );
        let shadowed = r
            .unresolved
            .iter()
            .filter(|u| u.starts_with(SHADOWED_READ))
            .count();
        assert_eq!(
            shadowed, 3,
            "every displaced read is counted: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_callback_reading_the_parser_node_itself_keeps_that_read() {
        // The callback takes its own parameter, so nothing is shadowed and `e` inside it is
        // still the parser's node. The recursion knows only `row`, so a read through `e`
        // reaches the IR only if this walk keeps it.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("row", function(row){ e.attrString("status"); row.attrString("v"); }); }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n);
        assert!(by("status").is_some(), "the parser's own attr survives");
        assert_eq!(
            by("row")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["v"]),
        );
        assert!(
            r.unresolved.is_empty(),
            "nothing counted lost: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_lexical_binding_shadows_only_inside_its_block() {
        // `let` reaches to the end of its block, not of the function. Treating the whole
        // body as owned made the earlier read of the captured `x` look callback-owned, and
        // `meta`'s `id` was dropped without a diagnostic.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   x.attrString("id");
                   if (row) { let x = row.child("inner"); x.attrString("deep"); }
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id"]),
            "the read before the block still targets the captured node"
        );
    }

    #[test]
    fn a_loop_header_binding_shadows_only_the_loop() {
        // `for (let x = 0; …)` binds to the loop, not to the callback. Recording it against
        // the enclosing body made both reads around the loop look callback-owned.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   x.attrString("before");
                   for (let x = 0; x < 3; x++) { row.attrString("v"); }
                   x.attrString("after");
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["before", "after"]),
            "reads on either side of the loop still target the captured node"
        );
    }

    #[test]
    fn a_catch_binding_shadows_only_its_clause() {
        // Minified handlers write `catch (e)` inside parsers whose parameter is also `e`.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   try { row.attrString("v"); } catch (x) { }
                   x.attrString("after");
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["after"]),
            "the catch parameter does not reach past its clause"
        );
    }

    #[test]
    fn a_named_callback_binds_its_own_name_inside_itself() {
        // `function x(row){…}` binds `x` throughout its body, so the read is of the
        // function, not of the captured `<meta>` node it happens to be named after.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function x(row){ x.attrString("bad"); }); }"#,
            "e",
        );
        assert!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .is_none_or(|c| c.iter().all(|f| f.name != "bad")),
            "the callback's own name is not the captured node: {:?}",
            r.fields
        );
    }

    #[test]
    fn a_class_binding_shadows_only_its_block() {
        // Block-scoped forms are not a list to keep up with: anything that is not a
        // parameter or a `var` is recorded against the extent it sits in. A `class` in a
        // nested block must not reach the reads around it.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   x.attrString("before");
                   { class x {} }
                   x.attrString("after");
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["before", "after"]),
        );
    }

    #[test]
    fn each_displaced_read_is_counted_on_its_own() {
        // `dropsByReason` folds these through a set keyed by site plus detail, so a bare
        // accessor name made two lost fields indistinguishable — and the ratchet could not
        // move when a third went missing.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("d"); rows.forEach(function(e){ e.attrString("a"); e.attrString("b"); }); }"#,
            "e",
        );
        let mut shadowed: Vec<&str> = r
            .unresolved
            .iter()
            .filter(|u| u.starts_with(SHADOWED_READ))
            .map(|u| u.as_str())
            .collect();
        shadowed.sort_unstable();
        shadowed.dedup();
        assert_eq!(
            shadowed,
            [
                "shadowedCallbackRead@attrString:e.a",
                "shadowedCallbackRead@attrString:e.b"
            ],
            "two lost reads stay two: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn two_branches_mapping_the_same_tag_become_one_element() {
        // The walk is structural, so both arms of a conditional are visited. Appending them
        // as sibling `row` fields left a later de-dup by name to keep the first and drop the
        // other branch's reads without a word.
        let r = analyze_parser_ast(
            r#"{ c ? e.mapChildrenWithTag("row", function(x){ x.attrString("jid"); })
                   : e.mapChildrenWithTag("row", function(x){ x.attrString("lid"); }); }"#,
            "e",
        );
        assert_eq!(
            r.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["row"],
            "one element, not two"
        );
        assert_eq!(
            r.fields[0]
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["jid", "lid"]),
            "carrying what either branch accepts"
        );
    }

    #[test]
    fn a_block_function_declaration_shadows_only_its_block() {
        // In a strict bundle a `function` declared in a nested block binds only there.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   x.attrString("before");
                   { function x(){} }
                   x.attrString("after");
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["before", "after"]),
        );
    }

    #[test]
    fn merging_two_branches_reaches_the_nested_shapes_too() {
        // Both arms map `<row>` and both map a nested `<sub>`; keeping the first `<sub>`
        // whole would publish only what one arm reads.
        let r = analyze_parser_ast(
            r#"{ c ? e.mapChildrenWithTag("row", function(x){ x.mapChildrenWithTag("sub", function(y){ y.attrString("a"); }); })
                   : e.mapChildrenWithTag("row", function(x){ x.mapChildrenWithTag("sub", function(y){ y.attrString("b"); }); }); }"#,
            "e",
        );
        let sub = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "sub"))
            .expect("one nested sub");
        assert_eq!(
            sub.children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["a", "b"]),
            "both arms' nested reads survive"
        );
    }

    #[test]
    fn a_chained_shadowed_read_is_counted_apart_from_its_receiver() {
        // Counting only the inner `child` left the outer accessor invisible, so adding or
        // removing the lost `id` moved no number.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("d"); rows.forEach(function(e){ e.child("x").attrString("id"); }); }"#,
            "e",
        );
        let mut got: Vec<&str> = r
            .unresolved
            .iter()
            .filter(|u| u.starts_with(SHADOWED_READ))
            .map(|u| u.as_str())
            .collect();
        got.sort_unstable();
        got.dedup();
        assert_eq!(
            got,
            [
                "shadowedCallbackRead@attrString:e.id",
                "shadowedCallbackRead@child:e.x"
            ],
            "both the child and the accessor on it are counted: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_named_class_expression_binds_only_inside_itself() {
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   const C = class x {};
                   x.attrString("id");
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id"]),
        );
    }

    #[test]
    fn a_switch_discriminant_is_read_outside_the_case_scope() {
        // JS evaluates the discriminant before the cases' block exists, so a `let` in a
        // case does not shadow the name the discriminant reads through.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("meta");
                 e.mapChildrenWithTag("row", function(row){
                   switch (x.attrString("kind")) { case "a": let x = row.child("inner"); }
                 }); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["kind"]),
        );
    }

    #[test]
    fn a_name_a_callback_binds_is_the_callbacks_own() {
        // A callback-local binding is not resolved against the outer map, even when its
        // initializer reads the parser's node — `x` is the callback's, and following it
        // here needs a lexical model of `child_vars` this walk deliberately does without.
        // The read is not invented under the wrong node, and it is not lost either.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("row", function(row){
                   var x = e.child("meta");
                   x.attrString("id");
                 }); }"#,
            "e",
        );
        // `<meta>` is read off the parser's node, so it is there — but empty, because the
        // accessor went through a name only the callback knows.
        assert_eq!(
            r.fields
                .iter()
                .find(|f| f.name == "meta")
                .and_then(|f| f.children.as_ref())
                .map(Vec::len),
            Some(0),
        );
        assert!(
            r.unresolved
                .iter()
                .any(|u| u == "readThroughUnknownNode@attrString:x.id"),
            "and the read it could not place is counted: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_child_method_chained_off_a_tracked_var_nests_under_both_tags() {
        // `digestResponseParser` writes `t.child("list").mapChildren(…)` off
        // `var t = e.child("digest")`. Only the `param.child("x").<childMethod>()` spelling
        // was recognized, so this one built nothing and its reads were counted as
        // unplaceable. The chain names two levels, and the result belongs under both.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("digest"); t.child("list").mapChildren(function(n){ n.contentUint(3); }); }"#,
            "e",
        );
        assert_eq!(
            r.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["digest"],
            "nothing beside the node the var tracks"
        );
        let list = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "list"))
            .expect("`list` sits inside `digest`");
        let mapped = list
            .children
            .as_ref()
            .and_then(|c| c.first())
            .expect("the mapped element");
        assert_eq!(mapped.repeats, Some(true));
        assert_eq!(
            mapped
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["content"]),
        );
        assert!(r.unresolved.is_empty(), "nothing lost: {:?}", r.unresolved);
    }

    #[test]
    fn an_attribute_dispatch_becomes_a_union_not_same_named_siblings() {
        // `privacyParser` reads `<category name value>`, where `name` picks both the enum
        // `value` is validated against and what the runtime calls the field. Flat, that was
        // ten sibling `value` fields with ten different enums and nothing saying which
        // `name` chose which — the linkage and the output names both gone.
        let r = analyze_parser_ast(
            r#"{ e.child("privacy").forEachChildWithTag("category", function(e){
                   var n = e.attrString("name");
                   x: {
                     if (n === "readreceipts") { var a = e.attrString("value"); t.readReceipts = a; break x }
                     if (n === "calladd") { var b = e.attrString("value"); t.callAdd = b; break x }
                     if (n === "stickers" || n === "cover_photo") break x;
                   }
                 }); }"#,
            "e",
        );
        let cat = r.fields[0].children.as_ref().unwrap()[0].clone();
        let kids = cat.children.as_ref().unwrap();
        assert_eq!(
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["name", "name_dispatch"],
            "the discriminator stays a field; the arms become one union"
        );
        let variants = kids[1].union_variants.as_ref().expect("union variants");
        assert_eq!(
            variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            ["readreceipts", "calladd", "stickers", "cover_photo"],
        );
        // Each arm says which `name` selects it …
        assert_eq!(variants[1].assertions[0].name.as_deref(), Some("name"));
        assert_eq!(variants[1].assertions[0].value.as_deref(), Some("calladd"));
        // … and carries the runtime's name for the wire's `value`.
        assert_eq!(variants[1].fields[0].name, "callAdd");
        assert_eq!(variants[1].fields[0].wire_name.as_deref(), Some("value"));
        // A name accepted without a value is a variant that carries nothing.
        assert!(variants[2].fields.is_empty());
    }

    #[test]
    fn a_dispatch_keeps_what_the_element_reads_outside_it() {
        // The reconstruction covers the discriminator and the arms. A read before the
        // chain belongs to the element too, and replacing the flat result lost it.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var id = e.attrString("id");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let names: Vec<&str> = kids.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"id"),
            "the unconditional read survives: {names:?}"
        );
        assert!(names.contains(&"kind_dispatch"), "{names:?}");
    }

    #[test]
    fn a_dispatch_merges_two_tests_of_the_same_value() {
        // A literal tested twice is one alternative. Emitted twice it is an unreachable
        // arm, and the codegen refuses the whole union rather than degrading to one.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("other"); t.beta = y; }
                   if (n === "a") { var z = e.attrString("extra"); t.alpha = z; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .unwrap();
        let vs = union.union_variants.as_ref().unwrap();
        assert_eq!(
            vs.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"],
            "one variant per value"
        );
        assert_eq!(
            vs[0].fields.len(),
            2,
            "both tests' reads: {:?}",
            vs[0].fields
        );
    }

    #[test]
    fn a_dispatch_takes_the_name_the_parsed_value_is_assigned_to() {
        // An arm that sets a flag first would otherwise stamp that flag's name onto the
        // field — a wrong output name is harder to notice than a missing one.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { seen.touched = 1; var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .unwrap();
        let vs = union.union_variants.as_ref().unwrap();
        assert_eq!(
            vs[0].fields[0].name, "alpha",
            "not the bookkeeping property"
        );
        assert_eq!(vs[0].fields[0].wire_name.as_deref(), Some("value"));
    }

    #[test]
    fn a_dispatch_on_an_optional_attribute_stays_optional() {
        // `maybeAttrString` admits an element with no discriminator at all; rewriting it
        // as required would have consumers reject those.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.maybeAttrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let disc = &r.fields[0].children.as_ref().unwrap()[0];
        assert_eq!(disc.name, "kind");
        assert!(!disc.required, "the accessor's optionality is kept");
    }

    #[test]
    fn a_child_only_some_arms_read_is_not_required_of_all_of_them() {
        // Lifted beside the union it applies to every variant; required, a consumer would
        // reject the arms that never carry it.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("d"); }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("lifted beside the union");
        assert!(!detail.required, "only one arm reads it");
    }

    #[test]
    fn a_maybe_child_step_of_a_path_stays_optional() {
        // The path carried only tags, so a step first materialised here became a required
        // `child` — the IR then demanded an element the parser explicitly allows to be
        // absent.
        let r = analyze_parser_ast(
            r#"{ var outer = e.child("outer"); var inner = outer.maybeChild("inner"); inner.attrString("id"); }"#,
            "e",
        );
        let inner = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "inner"))
            .expect("`inner` under `outer`");
        assert_eq!(inner.method, "maybeChild");
        assert!(!inner.required, "the accessor said it may be absent");
    }

    #[test]
    fn a_dispatch_with_a_plain_else_is_declined() {
        // The `else` payload belongs to no value. Folded beside the union it would be
        // required of the arms that never carry it, so the shape is left flat instead.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   else if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                   else { var z = e.attrString("other"); t.rest = z; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "no union claimed: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_dispatch_renames_only_the_leaf_that_was_assigned() {
        // One name for the whole arm renamed every leaf the same, which the codegen emits
        // as two identically-named fields of one variant.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.attrString("id"); var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .unwrap();
        let names: Vec<&str> = union.union_variants.as_ref().unwrap()[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, ["id", "alpha"], "only the assigned leaf is renamed");
    }

    #[test]
    fn a_helper_the_parser_binds_itself_is_not_the_modules() {
        // Resolving the callee by identifier text alone attached a stranger's fields.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var parse = function(q){ q.attrString("from_local"); };
                e.mapChildrenWithTag("row", function(row){ parse(row); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("row"))
            .expect("row");
        assert!(
            row.children
                .as_ref()
                .is_none_or(|c| c.iter().all(|f| f.name != "from_module")),
            "the module helper is shadowed: {:?}",
            row.children
        );
    }

    #[test]
    fn a_helper_reached_down_one_branch_is_not_required_of_all() {
        // Two branches each hand the node to a different helper; requiring both payloads
        // would have consumers reject the elements either branch accepts.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parseA(p){ p.attrString("a_only"); }
            function parseB(p){ p.attrString("b_only"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    if (row.attrString("kind") === "a") { parseA(row); } else { parseB(row); }
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let kids = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("row"))
            .and_then(|f| f.children.as_ref())
            .expect("row children");
        for name in ["a_only", "b_only"] {
            let f = kids.iter().find(|f| f.name == name).expect(name);
            assert!(!f.required, "{name} is only read down one branch");
        }
    }

    #[test]
    fn a_name_bound_in_a_sibling_scope_does_not_shadow_a_helper() {
        // Suppressing every call because some unrelated nested function reused the name is
        // a silent loss of the helper's fields — the direction this module never takes.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("other", function(z){ var parse = 1; z.attrString("k"); });
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let meta = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("meta"))
            .expect("meta");
        assert!(
            meta.children
                .as_ref()
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the sibling callback's binding does not reach this call: {:?}",
            meta.children
        );
    }

    #[test]
    fn a_mixed_or_condition_is_not_a_dispatch_arm() {
        // `kind === "a" || legacy` also runs for values the union cannot name, so keying
        // on `kind` alone would claim a `b` element takes the `b` arm when it does not.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a" || legacy) { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_nested_callback_does_not_lend_its_branches_to_the_element() {
        // The inner callback reuses `e`, but its node is `rows`', not the mapped element's.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   e.attrString("id");
                   rows.forEach(function(e){
                     var kind = e.attrString("kind");
                     if (kind === "a") { e.attrString("va"); }
                     if (kind === "b") { e.attrString("vb"); }
                   });
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "no union synthesised from the inner callback: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_own_node_helper_reports_what_it_could_not_resolve() {
        // Publishing the field without the loss lets the constraint ratchet read as clean
        // while a byte range disappeared.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.contentBytesRange(lo, hi); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){ parse(row); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|d| d.starts_with("contentBytesRange")),
            "the helper's loss reaches the caller: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_helper_reaches_a_node_no_read_has_built_yet() {
        // Only `<a>` exists when the helper is called: `<b>` is built by the read that
        // lands on it, and there is none here. Looking the path up instead of creating it
        // dropped everything the helper recovered, without a word.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("deep"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var t = e.child("a");
                var u = t.child("b");
                parse(u);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let deep = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("a"))
            .and_then(|f| f.children.as_ref())
            .and_then(|c| c.iter().find(|f| f.tag.as_deref() == Some("b")))
            .and_then(|f| f.children.as_ref())
            .map(|c| c.iter().map(|g| g.name.as_str()).collect::<Vec<_>>());
        assert_eq!(deep, Some(vec!["deep"]), "in `a`'s `b`: {:?}", p.fields);
    }

    #[test]
    fn a_local_function_declaration_shadows_the_module_helper() {
        // The `var parse = function(){…}` form lands in the top-level set; a `function
        // parse(){…}` declaration was being recorded against its own body, so a call
        // beside it did not see the local and resolved the module's.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                function parse(q){ q.attrString("from_local"); }
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let meta = p.fields.iter().find(|f| f.tag.as_deref() == Some("meta"));
        assert!(
            meta.and_then(|f| f.children.as_ref())
                .is_none_or(|c| c.iter().all(|f| f.name != "from_module")),
            "the local declaration wins: {:?}",
            meta.and_then(|f| f.children.as_ref())
        );
    }

    #[test]
    fn a_guarded_read_is_not_required_of_every_element() {
        // `hasChild(t) ? … : null` reads a `child`, but only when the element carries one.
        // Taking the accessor at face value had the IR demand both of these of every
        // message, when the source asks for neither.
        let r = analyze_parser_ast(
            r#"{ var c = e.hasChild("verified_name") ? e.child("verified_name").contentBytes() : null;
                 var m = e.hasAttr("verified_name") ? e.attrInt("verified_name") : -1;
                 e.attrString("id"); }"#,
            "e",
        );
        let by = |n: &str, meth: &str| {
            r.fields
                .iter()
                .find(|f| f.name == n && f.method == meth)
                .unwrap_or_else(|| panic!("{n}/{meth} in {:?}", r.fields))
        };
        assert!(
            !by("verified_name", "child").required,
            "guarded by hasChild"
        );
        assert!(
            !by("verified_name", "attrInt").required,
            "guarded by hasAttr"
        );
        assert!(by("id", "attrString").required, "this one is not guarded");
    }

    #[test]
    fn an_arm_under_an_unrelated_guard_is_not_a_dispatch() {
        // `if (enabled) { if (kind === "a") … }` runs only when `enabled`; keyed on `kind`
        // alone the union would decode an `a` element that the parser never handles.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (enabled) { if (n === "a") { var x = e.attrString("value"); t.alpha = x; } }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_reassigned_discriminator_is_not_a_dispatch() {
        // The later branch compares a different attribute; pinning it to the first would
        // name the wrong variant for both kinds of element.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var k = e.attrString("kind");
                   if (k === "a") { var x = e.attrString("value"); t.alpha = x; }
                   k = e.attrString("status");
                   if (k === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_read_on_every_branch_stays_required() {
        // Weakening on branch depth alone made an `id` the parser reads down every path
        // look optional. Only a guard that asks whether THIS field is there says that.
        let r = analyze_parser_ast(
            r#"{ if (flag) { e.attrString("id"); } else { e.attrString("id"); }
                 var c = e.hasChild("meta") ? e.child("meta").contentBytes() : null; }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n).unwrap();
        assert!(
            by("id").required,
            "read on both branches, never asked about"
        );
        assert!(!by("meta").required, "guarded by hasChild");
    }

    #[test]
    fn an_accessor_assigned_straight_to_a_property_is_still_named() {
        // The other spelling: no temporary between the read and the result property.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("value"); }
                   if (n === "b") { t.beta = e.attrString("value"); }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let v = &union.union_variants.as_ref().unwrap()[0];
        assert_eq!(v.fields[0].name, "alpha");
        assert_eq!(v.fields[0].wire_name.as_deref(), Some("value"));
    }

    #[test]
    fn an_own_node_helper_carries_its_guards_back() {
        // The helper enforces `type == "a"` on the node it was handed; publishing its
        // fields without that accepts exactly what the parser rejects.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.assertAttr("type", "a"); p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.assertions.iter().any(|a| a.kind == AssertionKind::Attr
                && a.name.as_deref() == Some("type")
                && a.value.as_deref() == Some("a")),
            "the helper's guard reaches the shape: {:?}",
            p.assertions
        );
    }

    /// The dispatch shapes the chain reader declines. Each was its own patch once; reading
    /// the chain structurally settles them together, and declining only means the body is
    /// extracted flat — what it was before this shape was recognized at all.
    #[test]
    fn a_dispatch_is_declined_when_the_chain_does_not_account_for_it() {
        let cases: [(&str, &str); 4] = [
            (
                "a comparison nested inside another arm is not a sibling",
                r#"if (n === "a") { if (n === "b") { e.attrString("vb"); } }
                   if (n === "c") { var y = e.attrString("value"); t.g = y; }"#,
            ),
            (
                "an `else if` on something else leaves a tail the union cannot name",
                r#"if (n === "a") { var x = e.attrString("value"); t.a = x; }
                   else if (legacy) { var y = e.attrString("other"); t.b = y; }
                   if (n === "c") { var z = e.attrString("value"); t.c = z; }"#,
            ),
            (
                "a block that rebinds the discriminator tests a different value",
                r#"if (n === "a") { var q = e.attrString("value"); t.a = q; }
                   { let n = "b"; }
                   if (n === "c") { var z = e.attrString("value"); t.c = z; }"#,
            ),
            (
                "an arm reached only under an unrelated guard is not an alternative",
                r#"if (enabled) { if (n === "a") { var x = e.attrString("value"); t.a = x; } }
                   if (n === "b") { var y = e.attrString("value"); t.b = y; }"#,
            ),
        ];
        for (why, chain) in cases {
            let src = format!(
                r#"{{ e.forEachChildWithTag("row", function(e){{
                       var n = e.attrString("kind");
                       {chain}
                     }}); }}"#
            );
            let r = analyze_parser_ast(&src, "e");
            let kids = r.fields[0].children.as_ref().unwrap();
            assert!(
                kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
                "{why}: {:?}",
                kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_helper_reached_down_one_branch_does_not_lend_its_guards_to_the_parser() {
        // Its fields are already weakened for a conditional call; its assertions were being
        // hoisted anyway, which rejects everything the other branches accept.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parseA(p){ p.assertAttr("type", "a"); p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (e.attrString("kind") === "a") { parseA(e); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("type")),
            "the branch's guard is not the parser's: {:?}",
            p.assertions
        );
    }

    #[test]
    fn a_short_circuited_helper_call_is_conditional() {
        // `enabled && parse(e)` runs the helper only sometimes, the same as an `if`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("maybe_here"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                enabled && parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let f = p
            .fields
            .iter()
            .find(|f| f.name == "maybe_here")
            .expect("recovered");
        assert!(!f.required, "reached only when the left side holds");
    }

    #[test]
    fn a_short_circuit_guard_makes_its_field_optional_too() {
        // The same guard the ternary case already handled, in the spelling minifiers also
        // emit — the branch was counted but the name it asked about was not.
        let r = analyze_parser_ast(
            r#"{ e.hasChild("meta") && e.child("meta").attrString("v");
                 e.attrString("id"); }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n).unwrap();
        assert!(!by("meta").required, "guarded by hasChild");
        assert!(by("id").required, "not guarded");
    }

    #[test]
    fn a_guard_on_another_node_does_not_weaken_this_one() {
        // Matching the accessor name alone let an unrelated object's presence test drop
        // `required` from a field this parser always reads.
        let r = analyze_parser_ast(
            r#"{ var x = req.hasAttr("id") ? e.attrString("id") : null; }"#,
            "e",
        );
        assert!(
            r.fields.iter().find(|f| f.name == "id").unwrap().required,
            "the test was about `req`, not about this element"
        );
    }

    #[test]
    fn an_own_node_helper_merges_with_what_the_caller_already_read() {
        // Both reach `<meta>`; skipping the helper's copy because the tag was there kept
        // only whichever landed first.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.child("meta").attrString("b"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.child("meta").attrString("a");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let kids = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("meta"))
            .and_then(|f| f.children.as_ref())
            .map(|c| c.iter().map(|g| g.name.as_str()).collect::<Vec<_>>());
        assert_eq!(kids, Some(vec!["a", "b"]), "both reads: {:?}", p.fields);
    }

    #[test]
    fn a_helper_chain_the_descent_stops_following_is_reported() {
        // Three hops deep the accessors are never reached. Publishing the shape anyway and
        // calling the extraction complete is the silent kind of incompleteness.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse3(p){ p.attrString("deep"); }
            function parse2(p){ parse3(p); }
            function parse(p){ parse2(p); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().all(|f| f.name != "deep"),
            "not reached, as the bound says"
        );
        assert!(
            p.pending_drops
                .iter()
                .any(|d| d.starts_with("helperChainTooDeep")),
            "and the stop is on the record: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_dispatch_is_found_past_an_unrelated_attribute_binding() {
        // Taking the first attribute read as the discriminator sank the whole shape when
        // anything was read before it.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var id = e.attrString("id");
                   var kind = e.attrString("kind");
                   if (kind === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (kind === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().any(|f| f.name == "kind_dispatch"),
            "keyed on `kind`, not on the first thing read: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn arms_reading_different_parts_of_one_child_do_not_require_each_others() {
        // The arms share `<detail>` but not its contents; requiring both would reject every
        // element that takes just one arm.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("a"); }
                   if (n === "b") { e.child("detail").attrString("b"); }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("lifted beside the union");
        let kids = detail.children.as_ref().unwrap();
        assert_eq!(kids.len(), 2, "both arms' reads are kept");
        assert!(
            kids.iter().all(|k| !k.required),
            "neither is required of the other's arm: {:?}",
            kids.iter()
                .map(|k| (k.name.as_str(), k.required))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_unconditional_read_outranks_a_guarded_copy_of_itself() {
        // The helper contributes an optional `id`; the parser then reads it outright. Kept
        // first-seen, the optional one would let a consumer accept an element without it.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (flag) { parse(e); }
                e.attrString("id");
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let ids: Vec<bool> = p
            .fields
            .iter()
            .filter(|f| f.name == "id")
            .map(|f| f.required)
            .collect();
        assert_eq!(ids, [true], "one `id`, and the parser always reads it");
    }

    #[test]
    fn a_negated_presence_test_does_not_excuse_the_read_it_guards() {
        // `if (!e.hasAttr("id")) e.attrString("id")` establishes ABSENCE on the branch
        // taken; the read there is not made optional by the test.
        let r = analyze_parser_ast(r#"{ if (!e.hasAttr("id")) { e.attrString("id"); } }"#, "e");
        assert!(r.fields.iter().find(|f| f.name == "id").unwrap().required);
    }

    #[test]
    fn a_presence_test_excuses_only_the_branch_that_found_it() {
        // The `else` is where the attribute is known missing; a read there is the parser's
        // own business, not something the test permits to be absent.
        let r = analyze_parser_ast(
            r#"{ if (e.hasAttr("id")) { e.attrString("other"); } else { e.attrString("id"); } }"#,
            "e",
        );
        let by = |n: &str| r.fields.iter().find(|f| f.name == n).unwrap();
        assert!(
            by("id").required,
            "read where the attribute is known missing — the test does not excuse it"
        );
        assert!(by("other").required, "the test said nothing about this one");
    }

    #[test]
    fn an_or_does_not_establish_what_its_left_side_found() {
        // `a || b` runs `b` when `a` did NOT hold: the attribute is read precisely when it
        // is missing, which is the opposite of optional. And a test satisfied by something
        // else entirely establishes nothing about the field at all.
        let short_circuit =
            analyze_parser_ast(r#"{ e.hasAttr("id") || e.attrString("id"); }"#, "e");
        assert!(
            short_circuit
                .fields
                .iter()
                .find(|f| f.name == "id")
                .unwrap()
                .required,
            "read exactly when absent"
        );

        let either = analyze_parser_ast(
            r#"{ if (flag || e.hasAttr("id")) { e.attrString("id"); } }"#,
            "e",
        );
        assert!(
            either
                .fields
                .iter()
                .find(|f| f.name == "id")
                .unwrap()
                .required,
            "`flag` may be what satisfied the test"
        );
    }

    #[test]
    fn a_descendant_every_arm_reads_stays_required() {
        // Loosening whatever a hoisted child carries was too blunt: `id` is read by both
        // arms, and accepting an element without it is accepting what the parser rejects.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var d = e.child("detail"); d.attrString("id"); d.attrString("only_a"); }
                   if (n === "b") { var d = e.child("detail"); d.attrString("id"); }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("hoisted");
        let by = |n: &str| {
            detail
                .children
                .as_ref()
                .unwrap()
                .iter()
                .find(|f| f.name == n)
                .unwrap_or_else(|| panic!("{n} in {:?}", detail.children))
        };
        assert!(by("id").required, "both arms read it");
        assert!(!by("only_a").required, "only one arm does");
    }

    #[test]
    fn a_merge_conflict_below_the_top_level_is_reported_too() {
        // Seven of the nine merge sites passed a throwaway sink, so a conflict anywhere but
        // the parser's own top level was dropped without a word — the one outcome this
        // module exists to prevent.
        let via_var = analyze_parser_ast(
            r#"{ var d = e.child("d"); d.contentBytes(32); d.contentBytes(64); }"#,
            "e",
        );
        assert!(
            via_var
                .unresolved
                .iter()
                .any(|u| u.starts_with(MERGE_CONFLICT)),
            "a child's clashing pins are a loss too: {:?}",
            via_var.unresolved
        );

        let agreeing = analyze_parser_ast(
            r#"{ var d = e.child("d"); d.contentBytes(32); d.contentBytes(32); }"#,
            "e",
        );
        assert!(
            agreeing.unresolved.is_empty(),
            "identical pins are not a conflict: {:?}",
            agreeing.unresolved
        );
    }

    #[test]
    fn a_repeated_read_keeps_both_pins_or_says_it_cannot() {
        // Coalescing repeated reads kept only the first field's metadata, so a second
        // range the parser enforces just as much simply vanished.
        let carried = analyze_parser_ast(r#"{ e.contentBytes(32); e.contentBytes(32); }"#, "e");
        assert!(
            carried.unresolved.is_empty(),
            "identical pins agree: {:?}",
            carried.unresolved
        );

        let clashing = analyze_parser_ast(r#"{ e.contentBytes(32); e.contentBytes(64); }"#, "e");
        assert!(
            clashing
                .unresolved
                .iter()
                .any(|u| u.starts_with("incompatibleRepeatedRead")),
            "one field cannot hold both, and the merge says so: {:?}",
            clashing.unresolved
        );
    }

    #[test]
    fn a_dispatch_keeps_a_read_that_only_shares_a_name() {
        // A `<id>` child and an `id` attribute share a name and nothing else; matching on
        // the name alone let the union's attribute swallow the child.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   e.child("id").attrString("v");
                   if (n === "a") { var x = e.attrString("id"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("id"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().any(|f| f.name == "id" && f.method == "child"),
            "the child survives beside the union: {:?}",
            kids.iter()
                .map(|f| (f.name.as_str(), f.method.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_comparison_before_the_discriminator_exists_is_not_an_arm() {
        // Hoisted, the name holds `undefined` until the accessor runs, so the first test
        // never selects anything the wire says.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   if (kind === "a") { e.attrString("va"); }
                   var kind = e.attrString("kind");
                   if (kind === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn arms_split_across_two_regions_decline_rather_than_lose_one() {
        // Reading one region would leave the other's payload hoisted as unconditional,
        // making each variant carry the other's fields.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   x: { if (n === "a") { e.attrString("va"); } if (n === "b") { e.attrString("vb"); } }
                   y: { if (n === "c") { e.attrString("vc"); } }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_arm_keeps_what_it_enforces_beside_the_discriminator() {
        // Replacing the arm's assertions with the synthesized one published a variant that
        // accepts what the parser turns away — and stripped the very thing the codegen's
        // exact-assertion check would have refused the shape for.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.assertAttr("mode", "on"); var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        assert!(
            a.assertions
                .iter()
                .any(|x| x.name.as_deref() == Some("mode") && x.value.as_deref() == Some("on")),
            "the arm's own guard travels with it: {:?}",
            a.assertions
        );
    }

    #[test]
    fn one_arm_reaching_a_child_twice_still_counts_once() {
        // Two spellings of the same child in one arm say nothing about the other arm, and
        // counting each made the child look common to both.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("x"); e.mapChildrenWithTag("detail", function(d){ d.attrString("y"); }); }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("hoisted");
        assert!(!detail.required, "only the `a` arm reads it");
    }

    #[test]
    fn only_a_plain_presence_test_excuses_a_read() {
        // Listing the forms that invert kept missing one. These all reach the accessor
        // somewhere in the condition; none of them is the plain `hasAttr(x)` that says the
        // element may lack `x` on the branch taken.
        for guard in [
            r#"!e.hasAttr("id")"#,
            r#"e.hasAttr("id") === false"#,
            r#"e.hasAttr("id") != true"#,
            r#"flag || e.hasAttr("id")"#,
        ] {
            let src = format!(r#"{{ if ({guard}) {{ e.attrString("id"); }} }}"#);
            let r = analyze_parser_ast(&src, "e");
            assert!(
                r.fields.iter().find(|f| f.name == "id").unwrap().required,
                "`{guard}` does not establish that `id` may be absent here"
            );
        }
        // The form that does.
        let r = analyze_parser_ast(r#"{ if (e.hasAttr("id")) { e.attrString("id"); } }"#, "e");
        assert!(!r.fields.iter().find(|f| f.name == "id").unwrap().required);
    }

    #[test]
    fn the_discriminator_keeps_what_its_accessor_pins() {
        // Rebuilt from the method alone it lost the value table, and `fold_unaccounted`
        // then removed the populated copy — so an unknown `kind` decoded to nothing where
        // the source accessor rejects it.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var KINDS = { A: "a", B: "b" };
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.forEachChildWithTag("row", function(e){
                    var n = e.attrEnumValues("kind", KINDS);
                    if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                    if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let kind = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("row"))
            .and_then(|f| f.children.as_ref())
            .and_then(|c| c.iter().find(|f| f.name == "kind"))
            .expect("the discriminator");
        assert!(
            kind.enum_keys.is_some() || kind.enum_ref.is_some() || kind.pending_enum_ref.is_some(),
            "the table it was read against survives: {kind:?}"
        );
    }

    #[test]
    fn two_branches_on_one_value_contribute_both_their_guards() {
        // Both run for that value, so both hold; merging only the fields let an element
        // through that the second branch asserts against.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                   if (n === "a") { e.assertAttr("status", "ok"); }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = union
            .union_variants
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "a")
            .unwrap();
        assert!(
            a.assertions
                .iter()
                .any(|x| x.name.as_deref() == Some("status")),
            "the later branch's guard is on the variant too: {:?}",
            a.assertions
        );
    }

    #[test]
    fn a_reassigned_alias_no_longer_names_what_it_was_declared_with() {
        // `x` holds the other attribute by the time it is assigned, so naming the `value`
        // field after that property attaches it to the wrong read.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); x = e.attrString("other"); t.foo = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let value = a
            .fields
            .iter()
            .find(|f| f.wire_name.as_deref() == Some("value") || f.name == "value");
        assert!(
            value.is_some_and(|f| f.name == "value"),
            "`value` is not renamed after a property fed by something else: {:?}",
            a.fields
                .iter()
                .map(|f| (f.name.as_str(), f.wire_name.as_deref()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_guard_on_a_chained_node_is_still_a_guard() {
        // Requiring the receiver to be a bare name discarded the test, leaving `id`
        // required of every `<detail>` the parser is happy to find without one.
        let r = analyze_parser_ast(
            r#"{ if (e.child("detail").hasAttr("id")) { e.child("detail").attrString("id"); } }"#,
            "e",
        );
        let id = r
            .fields
            .iter()
            .find(|f| f.name == "detail")
            .and_then(|f| f.children.as_ref())
            .and_then(|c| c.iter().find(|f| f.name == "id"))
            .expect("under detail");
        assert!(!id.required, "the guard was about this node");
    }

    #[test]
    fn a_block_local_name_does_not_shadow_a_helper_called_after_it() {
        // Treating every binding outside a nested function as function-wide made a
        // block-scoped `let` swallow the module helper for the rest of the parser.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                { let parse = 1; }
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some("meta"))
                .and_then(|f| f.children.as_ref())
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the block's binding ended with the block: {:?}",
            p.fields
        );
    }

    #[test]
    fn a_chained_attribute_read_lands_at_the_full_path() {
        // Naming only the last step put `<b>` beside `<a>`, so a consumer read the
        // attribute from the wrong place on the wire. `digestResponseParser` does exactly
        // this with `t.child("registration")` off `var t = e.child("digest")`.
        let r = analyze_parser_ast(
            r#"{ var a = e.child("a"); a.child("b").attrString("id"); }"#,
            "e",
        );
        assert_eq!(
            r.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["a"],
            "nothing beside the outer node"
        );
        let id = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "b"))
            .and_then(|f| f.children.as_ref())
            .and_then(|c| c.iter().find(|f| f.name == "id"));
        assert!(id.is_some(), "`id` under `a`'s `b`: {:?}", r.fields);
    }

    #[test]
    fn an_assertion_a_helper_only_reaches_down_a_branch_is_not_the_parsers() {
        // The call is unconditional, so the caller's own depth says nothing; the guard is
        // inside the helper, and demanding it always would reject what the parser accepts.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ if (enabled) { p.assertAttr("status", "ok"); } p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("status")),
            "only what it enforces on every path: {:?}",
            p.assertions
        );
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the unconditional read still arrives"
        );
    }

    #[test]
    fn a_loop_local_name_does_not_shadow_a_helper_called_after_it() {
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                for (let parse of items) { }
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some("meta"))
                .and_then(|f| f.children.as_ref())
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the loop's binding ended with the loop: {:?}",
            p.fields
        );
    }

    #[test]
    fn an_alias_shadowed_in_a_block_is_restored_after_it() {
        // The inner `let` named the other attribute; left in place, the read after the
        // block was named after a property fed by something else.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") {
                     var x = e.attrString("value");
                     { let x = e.attrString("other"); }
                     t.alpha = x;
                   }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        assert!(
            a.fields
                .iter()
                .any(|f| f.name == "alpha" && f.wire_name.as_deref() == Some("value")),
            "`alpha` names the outer read: {:?}",
            a.fields
                .iter()
                .map(|f| (f.name.as_str(), f.wire_name.as_deref()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_read_an_arm_shares_with_the_element_stays_beside_the_union() {
        // `id` is read in the `a` arm AND outside the chain, so every element carries it.
        // Letting the arm account for it left the `b` variant accepting one without.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.attrString("id"); }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                   e.attrString("id");
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let id = kids.iter().find(|f| f.name == "id");
        assert!(
            id.is_some_and(|f| f.required),
            "read on every path, so beside the union: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_read_only_the_arms_make_stays_inside_them() {
        // The mirror of the above: `value` is read in some arms and nowhere else, so it
        // belongs to those variants and must not be lifted out.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                   if (n === "c" || n === "d") break;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert_eq!(
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["kind", "kind_dispatch"],
            "no `value` beside the union"
        );
    }

    #[test]
    fn a_helper_guard_made_both_ways_is_still_the_parsers() {
        // Filtering the conditional ones by value dropped the unconditional occurrence
        // too, losing a constraint the helper always enforces.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ if (flag) { p.assertAttr("status", "ok"); } p.assertAttr("status", "ok"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("status")),
            "the unconditional occurrence survives: {:?}",
            p.assertions
        );
    }

    #[test]
    fn a_lexical_shadow_reaches_the_callback_it_encloses() {
        // The `let` is in scope for the callback and captured by it; passing only the
        // function-wide names let the callback resolve the module helper instead.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                let parse = function(q){ q.attrString("from_local"); };
                e.mapChildrenWithTag("row", function(row){ parse(row); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("row"))
            .expect("row");
        assert!(
            row.children
                .as_ref()
                .is_none_or(|c| c.iter().all(|f| f.name != "from_module")),
            "the enclosing binding shadows it here too: {:?}",
            row.children
        );
    }

    #[test]
    fn a_guard_deep_in_a_chain_is_matched_to_the_step_it_is_about() {
        // The guard is about `<a>`'s `<b>`. Looked up against the parser's own node it
        // never matched, while an unrelated `e.hasChild("b")` would have.
        let guarded = analyze_parser_ast(
            r#"{ var a = e.child("a");
                 if (a.hasChild("b")) { a.child("b").attrString("id"); } }"#,
            "e",
        );
        let b = guarded.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "b"))
            .expect("`b` under `a`");
        assert!(!b.required, "the guard was about this very step");

        // And a test on a different node does not stand in for it.
        let elsewhere = analyze_parser_ast(
            r#"{ var a = e.child("a");
                 if (e.hasChild("b")) { a.child("b").attrString("id"); } }"#,
            "e",
        );
        let b = elsewhere.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "b"))
            .expect("`b` under `a`");
        assert!(
            b.required,
            "that test was about the root's `<b>`, not this one"
        );
    }

    #[test]
    fn an_unguarded_read_promotes_a_child_a_guarded_one_created() {
        // The guarded read makes `<detail>` optional; the plain one after it says the
        // parser demands it. Reusing the node without promoting kept the weaker claim.
        let r = analyze_parser_ast(
            r#"{ if (e.hasChild("detail")) { e.child("detail").attrString("a"); }
                 e.child("detail").attrString("id"); }"#,
            "e",
        );
        let detail = r.fields.iter().find(|f| f.name == "detail").unwrap();
        assert!(detail.required, "the unguarded read settles it");
    }

    #[test]
    fn coverage_counts_values_not_branches() {
        // Two branches handling `a` merge into one variant; counting them separately made
        // a child both values require look optional.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("x"); }
                   if (n === "a") { var q = e.attrString("value"); t.alpha = q; }
                   if (n === "b") { e.child("detail").attrString("y"); }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("hoisted");
        assert!(detail.required, "both values require it");
    }

    #[test]
    fn a_dispatch_needs_an_accessor_that_can_hold_the_literals() {
        // `attrInt` never equals `"1"`, so those branches are unreachable in the source and
        // a union keyed on them would describe what the parser cannot do.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrInt("kind");
                   if (n === "1") { e.attrString("va"); }
                   if (n === "2") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_named_function_expression_does_not_shadow_the_module_helper() {
        // Its name exists only inside it, so a call beside it is the module's.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var unused = function parse(q){ q.attrString("inner"); };
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some("meta"))
                .and_then(|f| f.children.as_ref())
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the expression's name never reached out here: {:?}",
            p.fields
        );
    }

    #[test]
    fn an_assertion_made_on_both_branches_is_made_always() {
        // Every path enforces it, so the parser does. Both occurrences were marked
        // conditional on the way in, and discarding them lost a real constraint.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ if (flag) { p.assertAttr("status", "ok"); } else { p.assertAttr("status", "ok"); } }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("status")),
            "the intersection of the branches: {:?}",
            p.assertions
        );
    }

    #[test]
    fn an_or_arm_covers_every_value_it_accepts() {
        // One arm handling two values creates two variants; counting it once made a child
        // every variant requires look optional.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a" || n === "b") { e.child("detail").attrString("x"); }
                   if (n === "c") { e.child("detail").attrString("y"); }
                 }); }"#,
            "e",
        );
        let detail = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.name == "detail")
            .expect("hoisted");
        assert!(detail.required, "all three values require it");
    }

    #[test]
    fn a_conditional_helper_loosens_its_whole_shape() {
        // Weakening its top level and leaving the descendants required made a present
        // `<detail>` without `id` a rejection the source parser never makes.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.child("detail").attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (enabled) { parse(e); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let id = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("detail"))
            .and_then(|f| f.children.as_ref())
            .and_then(|c| c.iter().find(|f| f.name == "id"))
            .expect("under detail");
        assert!(!id.required, "reached only when the branch runs");
    }

    #[test]
    fn a_helper_handed_the_node_twice_is_read_through_both() {
        // `parse(e, e)` binds it to both parameters; reading only the first dropped what
        // the second saw.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(a,b){ a.attrString("id"); b.attrString("status"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e, e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let names: Vec<&str> = p.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"id") && names.contains(&"status"),
            "both parameters read the node: {names:?}"
        );
    }

    #[test]
    fn a_computed_property_names_the_field_too() {
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t["callAdd"] = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        assert_eq!(a.fields[0].name, "callAdd");
        assert_eq!(a.fields[0].wire_name.as_deref(), Some("value"));
    }

    #[test]
    fn an_arrow_parameter_belongs_to_its_arrow() {
        // Recorded against the enclosing block, an unrelated `parse => 0` shadowed the
        // module helper for everything around it.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var unused = parse => 0;
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some("meta"))
                .and_then(|f| f.children.as_ref())
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the arrow's parameter stayed in the arrow: {:?}",
            p.fields
        );
    }

    #[test]
    fn a_switch_case_binding_stays_in_the_switch() {
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                switch (flag) { case 1: let parse = 1; }
                var t = e.child("meta");
                parse(t);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some("meta"))
                .and_then(|f| f.children.as_ref())
                .is_some_and(|c| c.iter().any(|f| f.name == "from_module")),
            "the case's binding ended with the switch: {:?}",
            p.fields
        );
    }

    #[test]
    fn a_ternary_intersection_is_unconditional_too() {
        // The `if`/`else` form was taught this; the ternary is the same shape and was not.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ flag ? p.assertAttr("status","ok") : p.assertAttr("status","ok"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("status")),
            "made whichever way it goes: {:?}",
            p.assertions
        );
    }

    #[test]
    fn a_dispatch_declines_when_an_arm_compares_again_in_an_expression() {
        // `kind === "b" && …` inside the `a` arm is unreachable; placing its read in `a`
        // made consumers reject elements the parser accepts.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { n === "b" && e.attrString("x"); }
                   if (n === "c") { e.attrString("y"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_block_local_discriminator_does_not_drive_the_arms_after_it() {
        // The comparisons test the outer name; keying a union on the block-local read
        // described a selection the parser never made.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   { let kind = e.attrString("kind"); }
                   if (kind === "a") { e.attrString("va"); }
                   if (kind === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn arms_after_an_unconditional_exit_are_not_alternatives() {
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.attrString("va"); }
                   return 1;
                   if (n === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "one reachable arm is not a dispatch: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn one_read_feeding_two_properties_yields_both() {
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); t.foo = x; t.bar = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["foo", "bar"], "the parser returns both");
    }

    #[test]
    fn an_arm_resolves_a_node_the_body_bound_before_the_chain() {
        // Re-analysed alone the arm starts with no bindings, so `detail` resolved to
        // nothing and its read left the variant and the element alike.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var detail = e.child("detail");
                   var n = e.attrString("kind");
                   if (n === "a") { detail.attrString("id"); }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let has_id = kids
            .iter()
            .find(|f| f.name == "detail")
            .and_then(|f| f.children.as_ref())
            .is_some_and(|c| c.iter().any(|g| g.name == "id"))
            || kids
                .iter()
                .filter_map(|f| f.union_variants.as_ref())
                .flatten()
                .any(|v| {
                    v.fields.iter().any(|f| {
                        f.name == "detail"
                            && f.children
                                .as_ref()
                                .is_some_and(|c| c.iter().any(|g| g.name == "id"))
                    })
                });
        assert!(has_id, "`detail`'s `id` survives somewhere: {kids:?}");
    }

    #[test]
    fn a_helper_formal_shadows_the_module_helper_of_that_name() {
        // `delegate(node, parse)` calls the `parse` it was handed, not the module's.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("from_module"); }
            function delegate(node, parse){ parse(node); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                delegate(e, other);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().all(|f| f.name != "from_module"),
            "the formal shadows it: {:?}",
            p.fields
        );
    }

    #[test]
    fn a_helper_called_on_both_branches_still_requires_what_it_reads() {
        // Each call is weakened for sitting in a branch, and two weak claims OR to weak —
        // but the helper runs whichever way the branch goes.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (flag) { parse(e); } else { parse(e); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let id = p.fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "every path reads it");
    }

    /// A module whose parser reaches `parse` only through `body`.
    fn helper_reached_via(body: &str) -> Vec<ParsedField> {
        let module = format!(
            r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){{
            function parse(p){{ p.attrString("id"); }}
            var c=new(r("WADeprecatedWapParser"))("p", function(e){{
                e.assertTag("receipt");
                {body}
            }});
        }}),1);"#
        );
        parse_module_wap_parsers(&module)
            .into_iter()
            .find(|r| r.parser_name == "p")
            .expect("parser")
            .fields
    }

    #[test]
    fn a_helper_reached_only_down_one_switch_case_is_not_required() {
        // `case "a"` runs for its own value and every other value reaches past it, so what
        // the helper reads is not read of every element. Counting only `if`/`?:`/`&&` as
        // branches had the 44-case `w:gp2` subtype dispatch demand a `<description>` of
        // participant-add notifications, which never carry one.
        let fields =
            helper_reached_via(r#"switch (mode) { case "a": parse(e); break; default: break; }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "one case is not every path: {id:?}");
    }

    #[test]
    fn a_helper_reached_only_inside_a_loop_is_not_required() {
        // A loop that runs zero times calls nothing.
        let fields = helper_reached_via("while (more) { parse(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "zero iterations read nothing: {id:?}");
    }

    #[test]
    fn a_helper_reached_only_inside_a_caught_try_is_not_required() {
        // The source catches the failure and carries on; hoisting the helper's assertions
        // would have generated decoding reject the node the parser accepted.
        let fields = helper_reached_via("try { parse(e); } catch (x) {}");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the handler swallows the failure: {id:?}");
    }

    #[test]
    fn a_helper_called_in_a_finally_is_still_required() {
        // The finalizer runs whichever way the block went. Weakening every part of a `try`
        // alike would call a read the parser always performs optional.
        let fields = helper_reached_via("try { g(); } finally { parse(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the finalizer always runs: {id:?}");
    }

    #[test]
    fn a_helper_called_in_a_do_while_is_still_required() {
        // `do` runs its body before the test, so one pass is guaranteed — the asymmetry
        // with `while`/`for` that makes this a separate answer rather than "a loop".
        let fields = helper_reached_via("do { parse(e); } while (more);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the first pass always runs: {id:?}");
    }

    #[test]
    fn a_literal_repeated_inside_one_chain_declines() {
        // The arms of a chain are mutually exclusive, so the second is unreachable —
        // unlike two independent `if`s on one value, which both run and are merged.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.attrString("x"); }
                   else if (n === "a") { e.attrString("y"); }
                   else if (n === "b") { e.attrString("z"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_intersection_inside_a_one_sided_guard_stays_guarded() {
        // Both inner branches run the helper, but the outer `if` can skip both. Promoting
        // the claim outright made every field the helper reads required of every element.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (enabled) { if (flag) { parse(e); } else { parse(e); } }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let id = p.fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(
            !id.required,
            "`enabled` can be false, so nothing here is read on every path"
        );
    }

    #[test]
    fn a_block_local_name_stops_meaning_the_outer_read() {
        // Only accessor-initialized declarations displaced the mapping, so a block that
        // rebinds the name to a constant published that constant under the wire attribute.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { let v = e.attrString("value"); { let v = 0; t.synthetic = v; } t.alpha = v; }
                   if (n === "b") { let w = e.attrString("value"); t.beta = w; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(
            !names.contains(&"synthetic"),
            "the inner `v` is a constant, not the wire read: {names:?}"
        );
        assert!(
            names.contains(&"alpha"),
            "the outer `v` still names it: {names:?}"
        );
    }

    #[test]
    fn the_accumulator_is_the_object_the_body_hands_back() {
        // Chosen by write frequency, a cache written by more arms than the result won and
        // its property names became the generated API.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var out = {};
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); cache.ca = x; cache.cb = x; out.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); cache.cc = y; out.beta = y; }
                   return out;
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["alpha"], "`out` is returned; `cache` is not");
    }

    #[test]
    fn a_content_read_assigned_to_a_property_takes_that_name() {
        // Content accessors carry no wire argument, so the correlation was dropped and the
        // variant exposed `content` instead of the property the parser returns.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.body = e.contentString(); }
                   if (n === "b") { t.beta = e.attrString("value"); }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let body = a
            .fields
            .iter()
            .find(|f| f.name == "body")
            .expect("named after the property");
        assert_eq!(body.wire_name.as_deref(), Some("content"));
    }

    #[test]
    fn an_arm_restating_its_own_discriminator_adds_no_second_assertion() {
        // Two assertions made the codegen — which allows exactly one — refuse the union,
        // dropping the field and every arm's payload with it.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.assertAttr("kind", "a"); e.attrString("va"); }
                   if (n === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        assert_eq!(
            a.assertions.len(),
            1,
            "the arm restated what its comparison already said: {:?}",
            a.assertions
        );
    }

    #[test]
    fn a_claim_both_branches_establish_below_a_child_survives() {
        // The paths are recorded in the parser's coordinates. Written in the helper's, a
        // claim both branches establish never found its field again, and reads no guard
        // protects came out optional — the shape of the real receipt parser.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function d(e,t){ return t.mapChildrenWithTag("user", function(e){ return e.attrTime("t"); }); }
            function m(t,n){ n.forEachChildWithTag("user", function(t){ t.attrTime("t"); }); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i = e.maybeChild("participants");
                var l = i.hasAttr("message_id");
                return l ? m(n,i) : d(r,i);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let participants = p
            .fields
            .iter()
            .find(|f| f.name == "participants")
            .expect("participants");
        let users: Vec<&ParsedField> = participants
            .children
            .iter()
            .flatten()
            .filter(|f| f.name == "user")
            .collect();
        assert_eq!(users.len(), 2, "one <user> read per branch");
        for u in users {
            let t = u
                .children
                .iter()
                .flatten()
                .find(|f| f.name == "t")
                .expect("t under user");
            assert!(
                t.required,
                "both branches read it with no guard, so every path enforces it"
            );
        }
    }

    #[test]
    fn two_arms_on_one_literal_cover_one_variant_not_two() {
        // Two branches testing the same value merge into one variant. Counting each of them
        // made `<detail>` look required of every variant, and `b` elements were rejected.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("x"); }
                   if (n === "a") { e.child("detail").attrString("y"); }
                   if (n === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let detail = kids
            .iter()
            .find(|f| f.name == "detail")
            .expect("hoisted beside the union");
        assert!(
            !detail.required,
            "only the `a` variant carries it, so `b` must still decode"
        );
    }

    #[test]
    fn same_named_leaves_under_different_children_do_not_share_a_claim() {
        // The branch intersection identified fields by (method, wire, tag) alone, so an
        // `id` under `<a>` and an `id` under `<b>` looked like one field and each branch
        // appeared to establish the other's.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function pa(p){ p.child("a").attrString("id"); }
            function pb(p){ p.child("b").attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (flag) { pa(e); } else { pb(e); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        for tag in ["a", "b"] {
            let node = p.fields.iter().find(|f| f.name == tag).expect(tag);
            let id = node
                .children
                .as_ref()
                .and_then(|c| c.iter().find(|f| f.name == "id"))
                .expect("id under it");
            assert!(
                !id.required,
                "<{tag}> is read only down one branch, so its id is not enforced everywhere"
            );
        }
    }

    #[test]
    fn a_child_the_dispatch_and_the_callback_both_read_keeps_both_reads() {
        // The outside pass matched the arm's `<detail>` by identity and dropped its whole
        // subtree, so the read the element always does disappeared.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrString("arm"); }
                   if (n === "b") { e.attrString("vb"); }
                   e.child("detail").attrString("common");
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let detail = kids.iter().find(|f| f.name == "detail").expect("detail");
        let names: Vec<&str> = detail
            .children
            .iter()
            .flatten()
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            names.contains(&"common"),
            "the unconditional read survives the merge: {names:?}"
        );
    }

    #[test]
    fn a_read_through_a_tracked_var_reconciles_like_any_other() {
        let r = analyze_parser_ast(
            r#"{ var d = e.child("d");
                 if (d.hasAttr("x")) { d.attrString("x"); }
                 d.attrString("x"); }"#,
            "e",
        );
        let x = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "x"))
            .expect("under d");
        assert!(
            x.required,
            "the plain read after the guarded one settles it"
        );
    }

    #[test]
    fn a_ternary_calling_one_helper_both_ways_keeps_its_fields() {
        // The `if`/`else` visitor restores this; the ternary was left intersecting only
        // assertions, so the helper's fields stayed weak.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                flag ? parse(e) : parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let id = p.fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "it runs whichever way the ternary goes");
    }

    #[test]
    fn a_dispatch_split_between_a_label_and_its_siblings_declines() {
        // Reading the label alone left the outside arm to be hoisted as an unconditional
        // field, so `a` and `b` would carry `c`'s payload.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   x: { if (n === "a") { e.attrString("va"); } if (n === "b") { e.attrString("vb"); } }
                   if (n === "c") { e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_updated_discriminator_declines_like_an_assigned_one() {
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.attrString("va"); }
                   n++;
                   if (n === "b") { e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            kids.iter().all(|f| f.field_type != ParsedFieldType::Union),
            "left flat: {:?}",
            kids.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn only_the_accumulator_the_arms_build_names_the_fields() {
        // An assignment to something else is not a field of the result; taking its property
        // exposed an API field the parser never returns.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); cache.nope = x; t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["alpha"], "`cache` is not the result");
    }

    #[test]
    fn an_updated_alias_no_longer_names_its_read() {
        // The sibling of the assignment case, found by sweeping rather than by review.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("value"); x++; t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = &union.union_variants.as_ref().unwrap()[0];
        assert!(
            a.fields.iter().all(|f| f.name != "alpha"),
            "`x` held a number by then: {:?}",
            a.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_recursed_callback_is_not_also_reported_as_a_loss() {
        // The callback re-binds `e`, so the shadow check would discount its reads — but
        // `process_child_method` already read them in their own scope. Only what no
        // recursion covered is a drop; counting these too would report losses that are
        // sitting right there in the tree.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("enc", function(e){ e.attrString("type"); }); }"#,
            "e",
        );
        assert_eq!(
            r.fields[0]
                .children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["type"]),
            "the read is in the tree"
        );
        assert!(
            r.unresolved.is_empty(),
            "so it is not also counted as lost: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_shadowed_read_no_recursion_covered_is_counted_not_kept() {
        // A callback the recursion has no reason to enter — this one is not a child method's
        // at all. It re-binds `e`, so its read is not a read of the parser's own node;
        // publishing it at the root would put `content` beside `digest`.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("digest"); rows.forEach(function(e){ return e.contentUint(3); }); }"#,
            "e",
        );
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["digest"],
            "no `content` leaking beside the real child"
        );
        assert!(
            r.unresolved
                .iter()
                .any(|u| u == "shadowedCallbackRead@contentUint:e.?"),
            "and the read the walk could not place is still counted: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_direct_child_callback_reports_what_it_could_not_resolve() {
        // The reads of a directly mapped child are re-analysed in their own scope; a
        // constraint that scope could not resolve has to reach the outer diagnostics,
        // or coverage can shrink silently.
        let r = analyze_parser_ast(
            r#"{ e.mapChildrenWithTag("enc", function(e){ e.contentBytesRange(a, b); }); }"#,
            "e",
        );
        assert!(
            r.unresolved
                .iter()
                .any(|u| u.starts_with("contentBytesRange")),
            "the loss inside the callback is still counted: {:?}",
            r.unresolved
        );
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
        // `u` is tracked as a child var derived from another child var `t` — so it names
        // `<a>`'s `<b>`, not a second root-level `<b>`. Tracking only the last tag put the
        // node beside its parent.
        let r = analyze_parser_ast(
            r#"{ var t = e.child("a"); var u = t.child("b"); u.attrString("x"); }"#,
            "e",
        );
        assert_eq!(
            r.fields
                .iter()
                .map(|f| f.tag.as_deref().unwrap_or(&f.name))
                .collect::<Vec<_>>(),
            ["a"],
            "nothing at the root but the outer node"
        );
        let b = r.fields[0]
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.tag.as_deref() == Some("b")))
            .expect("`b` sits inside `a`");
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
    fn descends_into_a_helper_handed_a_node_captured_by_a_callback() {
        // The helper call sits inside a mapped child, so the recursion owns that body — but
        // `i` was bound outside it and the nested analyser has no binding for it. Only this
        // walk can descend, and the `<user>` grandchildren hang off `participants`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function d(e,t){ t.mapChildrenWithTag("user", function(u){ u.attrDeviceJid("jid"); }); return {}; }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i=e.maybeChild("participants");
                e.mapChildrenWithTag("row", function(row){ row.attrString("v"); d(e, i); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let participants = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("participants"))
            .expect("participants field");
        assert!(
            participants
                .children
                .as_ref()
                .is_some_and(|c| c.iter().any(|g| g.tag.as_deref() == Some("user"))),
            "helper descent still reaches the captured node: {:?}",
            participants.children
        );
    }

    #[test]
    fn helper_descent_skips_an_argument_a_callback_re_bound() {
        // Both `x` and `y` are tracked, but the callback re-binds `x`. Picking the first
        // name found in the map descended on the stale entry and hung the helper's fields
        // off `<xx>`, a node this call never mentions.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function d(a,b){
                a.mapChildrenWithTag("ua", function(u){ u.attrString("p"); });
                b.mapChildrenWithTag("ub", function(u){ u.attrString("q"); });
            }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var x=e.child("xx");
                var y=e.maybeChild("participants");
                e.mapChildrenWithTag("row", function(row){ var x=row.child("inner"); d(x, y); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let kids = |tag: &str| {
            p.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some(tag))
                .and_then(|f| f.children.as_ref())
                .map(|c| {
                    c.iter()
                        .filter_map(|g| g.tag.as_deref())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        assert!(
            !kids("xx").contains(&"ua"),
            "nothing is invented under the re-bound name: {:?}",
            kids("xx")
        );
        assert!(
            kids("participants").contains(&"ub"),
            "and the argument that still names its node is the one descended on: {:?}",
            kids("participants")
        );
    }

    #[test]
    fn descends_into_a_helper_handed_the_mapped_node_itself() {
        // The callback delegates its own element to a module-scope helper. Helper descent
        // recognized arguments only through `child_vars`, and a mapped child's parameter is
        // not one — so `<row>` came out empty with nothing reported lost.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); p.attrTime("t"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){ parse(row); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("row"))
            .expect("row field");
        assert_eq!(
            row.children
                .as_ref()
                .map(|c| c.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()),
            Some(vec!["id", "t"]),
            "the helper's reads belong to the element it was handed"
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

    #[test]
    fn an_unnameable_enum_table_is_still_counted() {
        // `attrEnumOrNullIfUnknown("type", o("Mod").TABLE)` — the table is not a
        // module-scope identifier, so the fast path missed and returned, producing no
        // link, no drop and (with no companion read) no field. The parser enforces an
        // enum there; a silent loss is the one outcome this change exists to prevent.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var t=e.attrEnumOrNullIfUnknown("type", o("Other").TABLE);
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let f = p
            .fields
            .iter()
            .find(|f| f.name == "type")
            .expect("the field is synthesized rather than vanishing");
        assert_eq!(f.field_type, ParsedFieldType::Enum);
        assert_eq!(f.pending_enum_ref, Some(wa_ir::PendingEnum::Unresolvable));
        assert!(f.enum_keys.is_none(), "and no invented value set");
    }

    #[test]
    fn a_companion_read_is_retyped_when_it_gains_enum_keys() {
        // `attrEnumOrNullIfUnknown("type", map)` beside a plain `maybeAttrString("type")`
        // is the SAME attribute validated against that key set. Hanging `enumKeys` off the
        // companion while leaving it `type: "string"` hid the constraint from every
        // consumer that selects enum fields by `type == "enum"`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var u={delivery:1,read:2};
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var t=e.hasAttr("type")?e.attrEnumOrNullIfUnknown("type",u):0;
                e.maybeAttrString("type");
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let f = p
            .fields
            .iter()
            .find(|f| f.name == "type" && f.tag.is_none())
            .expect("the type field");
        assert_eq!(
            f.field_type,
            ParsedFieldType::Enum,
            "retyped, not just annotated"
        );
        assert_eq!(
            f.method,
            wap::MAYBE_ATTR_ENUM,
            "and under the enum accessor"
        );
        assert!(!f.required, "the companion read was optional and stays so");
        assert_eq!(
            f.enum_keys.as_deref(),
            Some(["delivery", "read"].map(String::from).as_slice())
        );
    }

    #[test]
    fn a_typed_content_accessor_becomes_a_typed_field() {
        // `contentUint` was outside the local attr/content list, so a read of it produced
        // no field at all — only a coarse `contentType` on the parent. Both halves of the
        // predicate are derived from `wap` now, so every spelling `method_field_type`
        // decodes reaches field extraction.
        let r = analyze_parser_ast(r#"{ e.child("registration").contentUint(); }"#, "e");
        let parent = r
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("registration"))
            .expect("the <registration> child is recovered");
        let leaf = parent
            .children
            .as_ref()
            .and_then(|c| c.first())
            .expect("its content read is a field");
        assert_eq!(leaf.method, "contentUint");
        assert_eq!(leaf.field_type, ParsedFieldType::Integer);
        assert_eq!(leaf.name, "content", "a content read names no attribute");
    }

    #[test]
    fn attr_enum_values_recovers_a_module_local_enums_members() {
        // `attrEnumValues("mediatype", u.members())` where `u` is a module-local
        // `$InternalEnum`. The table is neither an `o("Mod").ENUM` member (so the
        // cross-module post-pass cannot see it) nor a bare map identifier — it is the
        // enum's VALUES. Reading past the `.members()` call and taking the values is what
        // turns an apparently unconstrained `"type": "enum"` into the legal set.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var u=n("$InternalEnum")({Image:"image",Video:"video"});
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("message");
                e.child("media").attrEnumValues("mediatype", u.members());
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let media = p
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("media"))
            .expect("the <media> child");
        let field = media
            .children
            .as_ref()
            .and_then(|c| c.iter().find(|f| f.name == "mediatype"))
            .expect("the mediatype attr");
        assert_eq!(
            field.enum_keys.as_deref(),
            Some(["image", "video"].map(String::from).as_slice()),
            "`.members()` yields the enum's VALUES, not its keys"
        );
    }

    #[test]
    fn an_unresolvable_enum_table_is_marked_pending_not_silently_dropped() {
        // An enum accessor whose table is a computed expression must be distinguishable
        // from a field that is not an enum at all — the first is a constraint we failed
        // to extract and belongs in `dropsByReason`.
        let r = analyze_parser_ast(r#"{ e.attrStringEnum("state", pick()); }"#, "e");
        let f = r.fields.iter().find(|f| f.name == "state").expect("field");
        assert_eq!(f.pending_enum_ref, Some(wa_ir::PendingEnum::Unresolvable));
        assert!(f.enum_keys.is_none() && f.enum_ref.is_none());
    }

    #[test]
    fn legacy_byte_accessors_keep_the_constraint_they_pin() {
        // Routing the typed content accessors into field extraction is only half the job:
        // `field_from_call` read the argument of plain `contentBytes` and nothing else, so
        // these two published unconstrained bytes — an emitter would think any payload
        // passes where the parser accepts one sequence, or one length band.
        let r = analyze_parser_ast(
            r#"{ e.child("t").contentLiteralBytes(Uint8Array.of(5, 255));
                 e.child("blob").contentBytesRange(1, 128); }"#,
            "e",
        );
        let leaf = |tag: &str| {
            r.fields
                .iter()
                .find(|f| f.tag.as_deref() == Some(tag))
                .and_then(|f| f.children.as_ref())
                .and_then(|c| c.first())
                .unwrap_or_else(|| panic!("no leaf under <{tag}>"))
                .clone()
        };
        let pinned = leaf("t");
        assert_eq!(pinned.literal_value.as_deref(), Some("05ff"));
        assert_eq!(pinned.byte_length, Some(2));
        let ranged = leaf("blob");
        assert_eq!((ranged.byte_min, ranged.byte_max), (Some(1), Some(128)));
        assert_eq!(
            ranged.byte_length, None,
            "a true range is not a fixed length"
        );
    }

    #[test]
    fn a_zero_filled_uint8array_is_a_recoverable_pin() {
        // `new Uint8Array(4)` is a LENGTH — and therefore exactly four zero bytes, as much
        // a compile-time constant as a literal array. Refusing it lost a recoverable pin;
        // reading the `4` as the byte 0x04 would have invented a different one.
        let r = analyze_parser_ast(
            r#"{ e.child("nonce").contentLiteralBytes(new Uint8Array(4)); }"#,
            "e",
        );
        let leaf = r.fields[0].children.as_ref().unwrap()[0].clone();
        assert_eq!(leaf.literal_value.as_deref(), Some("00000000"));
        assert_eq!(leaf.byte_length, Some(4));
        assert!(r.unresolved.is_empty(), "and nothing is reported lost");
    }

    #[test]
    fn an_unresolvable_byte_pin_is_reported_not_published_as_free_bytes() {
        let r = analyze_parser_ast(r#"{ e.child("t").contentLiteralBytes(computed()); }"#, "e");
        assert!(
            r.unresolved
                .iter()
                .any(|d| d.starts_with("contentLiteralBytes@")),
            "the loss is counted: {:?}",
            r.unresolved
        );
    }

    #[test]
    fn a_byte_pin_from_a_foreign_factory_is_not_trusted() {
        // `factory.of(1, 2)` is an ordinary call that may return anything; reading its
        // arguments as the pinned bytes would invent a `literalValue` rather than record
        // an unresolved one. Same for `new Whatever([1, 2])`.
        for src in [
            r#"{ e.child("t").contentLiteralBytes(factory.of(1, 2)); }"#,
            r#"{ e.child("t").contentLiteralBytes(new Whatever([1, 2])); }"#,
        ] {
            let r = analyze_parser_ast(src, "e");
            let leaf = r.fields[0].children.as_ref().unwrap()[0].clone();
            assert_eq!(leaf.literal_value, None, "no invented pin for {src}");
            assert!(
                r.unresolved
                    .iter()
                    .any(|d| d.starts_with("contentLiteralBytes@")),
                "and the loss is counted for {src}"
            );
        }
    }

    #[test]
    fn a_table_with_a_spread_is_not_a_complete_table() {
        // `obj_props` silently skips a spread, so the surviving literals collected
        // successfully and were published as a CLOSED set — claiming the parser rejects
        // whatever the spread contributed. An invented constraint, not a lost one.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var u=n("$InternalEnum")({A:"a", ...base});
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("message");
                e.attrEnumValues("k", u.members());
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let f = p.fields.iter().find(|f| f.name == "k").expect("field");
        assert!(
            f.enum_keys.is_none(),
            "an unreadable table is not a value set"
        );
        assert_eq!(f.pending_enum_ref, Some(wa_ir::PendingEnum::Unresolvable));
    }

    #[test]
    fn a_partially_literal_enum_table_is_refused_whole() {
        // `{A: "a", B: computed}` must not publish `["a"]` as the complete legal set —
        // that is an enum the IR says rejects `B` while the runtime accepts it.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var u=n("$InternalEnum")({A:"a",B:pick()});
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("message");
                e.attrEnumValues("k", u.members());
                return {};
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let f = p.fields.iter().find(|f| f.name == "k").expect("field");
        assert!(f.enum_keys.is_none(), "an incomplete table is not the set");
        assert_eq!(f.pending_enum_ref, Some(wa_ir::PendingEnum::Unresolvable));
    }
    #[test]
    fn two_reads_into_one_property_name_only_the_one_it_keeps() {
        // `t.value = x; t.value = y` returns ONE `value` — the second read. Naming both
        // after it gave the variant two fields of that name, which the codegen emits as a
        // struct that does not compile.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("first"); t.value = x;
                                    var y = e.attrString("second"); t.value = y; }
                   if (n === "b") { var z = e.attrString("third"); t.other = z; }
                 }); }"#,
            "e",
        );
        let union = r.fields[0]
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a dispatch");
        let a = union
            .union_variants
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "a")
            .expect("the first arm");
        let named: Vec<(&str, Option<&str>)> = a
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.wire_name.as_deref()))
            .collect();
        assert_eq!(
            named,
            [("first", None), ("value", Some("second"))],
            "the property takes the read it ends up holding; the other keeps its wire name"
        );
    }
    #[test]
    fn a_synthesized_dispatch_name_steps_over_one_the_element_reads() {
        // The union's name is made up, so it can land on a field the element already has.
        // Two fields of one name are a struct the codegen cannot emit.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   e.attrString("kind_dispatch");
                   if (n === "a") { var x = e.attrString("value"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("value"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let names: Vec<&str> = kids.iter().map(|f| f.name.as_str()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "a name is used twice: {names:?}");
        assert!(
            kids.iter()
                .any(|f| f.field_type == ParsedFieldType::Union && f.name == "kind_dispatch_2"),
            "the union takes the next free name: {names:?}"
        );
    }

    #[test]
    fn an_exit_inside_a_block_ends_the_chain_too() {
        // `{ return t; }` runs exactly as a bare `return` does; the arm after it cannot.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("va"); t.alpha = x; }
                   { return t; }
                   if (n === "b") { var y = e.attrString("vb"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let union = kids.iter().find(|f| f.field_type == ParsedFieldType::Union);
        let names: Vec<String> = union
            .and_then(|f| f.union_variants.as_ref())
            .map(|vs| vs.iter().map(|v| v.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !names.iter().any(|n| n == "b"),
            "the unreachable arm is not an alternative: {names:?}"
        );
    }

    #[test]
    fn an_arm_the_chain_cannot_hold_declines_rather_than_hoisting_it() {
        // A comparison in a block between two siblings is inside the chain's own span, so
        // `arms_outside` cannot see it. Left alone it was reanalyzed as an unconditional
        // field, making every variant require a payload only that branch reads.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("va"); t.alpha = x; }
                   { if (n === "c") { var z = e.attrString("vc"); t.gamma = z; } }
                   if (n === "b") { var y = e.attrString("vb"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            kids.iter().any(|f| f.name == "vc"),
            "and the read it could not place is still extracted"
        );
    }
    #[test]
    fn a_synthesized_name_avoids_one_the_codegen_would_spell_alike() {
        // `kindDispatch` and `kind_dispatch` are one Rust member, so comparing the IR
        // names verbatim let the pair through into a struct that does not compile.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   e.attrString("kindDispatch");
                   if (n === "a") { var x = e.attrString("va"); t.alpha = x; }
                   if (n === "b") { var y = e.attrString("vb"); t.beta = y; }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let mut spelled: Vec<String> = kids.iter().map(|f| rust_member_form(&f.name)).collect();
        let total = spelled.len();
        spelled.sort();
        spelled.dedup();
        assert_eq!(
            spelled.len(),
            total,
            "two fields land on one member: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn two_arms_of_one_literal_still_leave_one_read_per_property() {
        // Both arms run, so `t.value` holds the second read; merged into one variant the
        // pair survived because their wire names differ.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first"); }
                   if (n === "a") { t.value = e.attrString("second"); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let union = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .expect("a union");
        let a = union
            .union_variants
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "a")
            .expect("the a arm");
        let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "a name is used twice: {names:?}");
        // The property holds the last read; the first keeps its own wire name.
        assert!(
            a.fields
                .iter()
                .any(|f| f.name == "value" && f.wire_name.as_deref() == Some("second")),
            "the property holds the read it keeps: {names:?}"
        );
        assert!(
            a.fields.iter().any(|f| f.name == "first"),
            "and the earlier read is still recorded: {names:?}"
        );
    }
    #[test]
    fn a_wap_bounded_integer_keeps_the_band_it_enforces() {
        // The smax path records these; the WAP path did not, so a union arm reading one
        // could only guard on whether the value parses.
        let r = analyze_parser_ast(r#"{ e.attrIntRange("count", 1, 10); }"#, "e");
        let f = r
            .fields
            .iter()
            .find(|f| f.name == "count")
            .expect("the field");
        assert_eq!(
            (f.int_min, f.int_max),
            (Some(1), Some(10)),
            "the accessor's band is carried"
        );
    }

    #[test]
    fn an_open_upper_bound_stays_open() {
        // `attrIntRange(e, "t", 0, void 0)` is WA's spelling for "no upper limit"; a
        // fabricated max would reject timestamps the parser accepts.
        let r = analyze_parser_ast(r#"{ e.attrIntRange("t", 0, void 0); }"#, "e");
        let f = r.fields.iter().find(|f| f.name == "t").expect("the field");
        assert_eq!(
            (f.int_min, f.int_max),
            (Some(0), None),
            "only the bound it spells"
        );
    }
    #[test]
    fn a_property_two_branches_disagree_on_declines() {
        // `if (flag) t.value = first; else t.value = second` returns one or the other;
        // naming the later read alone published a field the parser often does not return.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") {
                     if (flag) { t.value = e.attrString("first"); }
                     else { t.value = e.attrString("second"); }
                   }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_displaced_read_with_nowhere_to_fall_back_declines() {
        // The wire name a displaced read falls back to can be one another property already
        // took, leaving two members called `first` — a struct the codegen cannot emit.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") {
                     t.value = e.attrString("first");
                     t.value = e.attrString("second");
                     t.first = e.attrString("third");
                   }
                   if (n === "b") { t.other = e.attrString("fourth"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined rather than emitting one name twice: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_arm_after_that_value_already_returned_is_not_merged_into_it() {
        // `if (kind === "a") { …; return t; }` ends the callback for `a`, so a later `a`
        // arm cannot run — merging it required of `a` a payload the parser never reads.
        // The `b` arm between them is untouched by that exit.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va"); return t; }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let union = kids.iter().find(|f| f.field_type == ParsedFieldType::Union);
        let a_fields: Vec<String> = union
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }
    #[test]
    fn an_arm_whose_branches_both_return_ends_that_value_too() {
        // `if (flag) return t; else return t;` leaves the callback on every path, so a
        // later arm for the same value cannot run.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") {
                     t.alpha = e.attrString("va");
                     if (flag) { return t; } else { return t; }
                   }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }

    #[test]
    fn a_variant_whose_properties_share_one_member_declines() {
        // `fooBar` and `foo_bar` are two properties in JavaScript and one member in Rust.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.fooBar = e.attrString("a1"); t.foo_bar = e.attrString("b1"); }
                   if (n === "b") { t.other = e.attrString("c1"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined rather than emitting one member twice: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn a_switch_that_returns_on_every_path_ends_that_value() {
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     switch (m) { case 1: return t; default: return t; } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }

    #[test]
    fn a_case_that_falls_through_is_not_an_exit() {
        // An empty case runs the next one's body; treating the switch as exhaustive would
        // drop an arm the parser really can reach.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     switch (m) { case 1: default: break; } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "gamma"),
            "the later arm still runs and is merged: {a_fields:?}"
        );
    }

    #[test]
    fn a_compound_assignment_does_not_name_the_read_it_folds_in() {
        // `t.total += e.attrInt("delta")` returns the sum; naming the read `total`
        // published a value the parser never returns under that property.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.total += e.attrInt("delta"); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<(String, Option<String>)> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| {
                v.fields
                    .iter()
                    .map(|f| (f.name.clone(), f.wire_name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            a_fields.iter().all(|(n, _)| n != "total"),
            "the property does not claim the read: {a_fields:?}"
        );
        assert!(
            a_fields.iter().any(|(n, _)| n == "delta"),
            "and the read is still recorded under its wire name: {a_fields:?}"
        );
    }
    #[test]
    fn a_case_that_falls_through_to_a_return_exits_too() {
        // `case "x": read(); default: return t;` runs the default's return for "x" as
        // well, so every path out of the switch leaves the callback.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     switch (mode) { case "x": e.attrString("sx"); default: return t; } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }

    #[test]
    fn a_case_that_breaks_does_not_carry_the_next_ones_exit() {
        // `break` leaves the switch, not the callback, so the statements after it run and
        // the later arm really is reachable.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     switch (mode) { case "x": break; default: return t; } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "gamma"),
            "the later arm still runs and is merged: {a_fields:?}"
        );
    }

    #[test]
    fn an_assignment_behind_a_short_circuit_does_not_overwrite() {
        // `flag && (t.value = second)` may not run, so `value` can still be the first
        // read — one field cannot say both, and the dispatch is refused.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first");
                                    flag && (t.value = e.attrString("second")); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn a_return_through_a_finally_ends_that_value_too() {
        // The finalizer runs on the way out without stopping the return.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     try { return t; } finally { cleanup(); } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }

    #[test]
    fn a_caught_try_only_exits_when_the_handler_does_too() {
        // With a `catch` that falls through, the statements after the try still run.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     try { return t; } catch (err) { logged(); } }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "gamma"),
            "the later arm still runs and is merged: {a_fields:?}"
        );
    }

    #[test]
    fn an_alias_rebound_down_a_branch_does_not_name_the_later_read() {
        // `var x = first; if (flag) x = second; t.value = x` returns one or the other.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("first");
                                    if (flag) { x = e.attrString("second"); }
                                    t.value = x; }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_accumulator_is_found_through_the_alias_it_is_returned_as() {
        // `var result = {}, alias = result; … return alias` hands the accumulator back
        // under another name; the direct comparison found nothing and a cache written by
        // more arms took the API.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias = result;
                   if (n === "a") { result.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1");
                                    cache.wrongB = e.attrString("w2"); }
                   if (n === "b") { result.bar = e.attrString("b1");
                                    cache.wrongC = e.attrString("w3");
                                    cache.wrongD = e.attrString("w4"); }
                   return alias;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "foo"),
            "the returned object names the field: {a_fields:?}"
        );
        assert!(
            !a_fields.iter().any(|n| n.starts_with("wrong")),
            "and the cache does not: {a_fields:?}"
        );
    }
    #[test]
    fn an_accumulator_aliased_by_assignment_is_found_too() {
        // `var alias; alias = result;` stands for the accumulator as much as the
        // declarator form; reading only initializers left the cache winning on frequency.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias;
                   alias = result;
                   if (n === "a") { result.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1");
                                    cache.wrongB = e.attrString("w2"); }
                   if (n === "b") { result.bar = e.attrString("b1");
                                    cache.wrongC = e.attrString("w3");
                                    cache.wrongD = e.attrString("w4"); }
                   return alias;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "foo") && !a_fields.iter().any(|n| n.starts_with("wrong")),
            "the returned object names the fields, not the cache: {a_fields:?}"
        );
    }

    #[test]
    fn an_accumulator_written_through_an_alias_is_found_too() {
        // The other direction: the return names `result`, but the writes go through
        // `alias`. Matching receivers against the returned set alone found none of them,
        // so the choice fell to frequency and the cache — written by one arm more than
        // the accumulator — took the API.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias = result;
                   if (n === "a") { alias.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1"); }
                   if (n === "b") { alias.bar = e.attrString("b1");
                                    cache.wrongB = e.attrString("w2"); }
                   if (n === "c") { cache.wrongC = e.attrString("w3"); }
                   return result;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "foo") && !a_fields.iter().any(|n| n == "wrongA"),
            "the accumulator names the fields, not the cache: {a_fields:?}"
        );
    }

    #[test]
    fn a_property_written_in_a_loop_does_not_overwrite() {
        // A loop that runs zero times performs no write, so `value` may still hold the
        // earlier read — one field cannot say both.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first");
                                    for (var i = 0; i < m; i++) { t.value = e.attrString("second"); } }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_do_while_body_always_runs_so_its_write_stands() {
        // `do { … } while (…)` performs the write at least once, so the later read really
        // is what the property holds — declining here would lose a union needlessly.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first");
                                    do { t.value = e.attrString("second"); } while (m); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<(String, Option<String>)> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| {
                v.fields
                    .iter()
                    .map(|f| (f.name.clone(), f.wire_name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            a_fields
                .iter()
                .any(|(n, w)| n == "value" && w.as_deref() == Some("second")),
            "the property holds the read it keeps: {a_fields:?}"
        );
    }
    #[test]
    fn a_write_past_a_break_in_a_do_while_does_not_overwrite() {
        // The body of `do { … } while (…)` runs, but not necessarily all of it: a `break`
        // ahead of the write skips it, so `value` may still hold the earlier read.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first");
                                    do { if (flag) break;
                                         t.value = e.attrString("second"); } while (m); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_labeled_break_ends_that_value_too() {
        // `break x` jumps past the labelled block the chain lives in.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   x: { if (n === "a") { t.alpha = e.attrString("va"); break x; }
                        if (n === "b") { t.beta = e.attrString("vb"); }
                        if (n === "a") { t.gamma = e.attrString("vc"); } }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }

    #[test]
    fn a_discriminator_destructured_into_declines_the_chain() {
        // `[n] = values` replaces what the comparisons test, so they are not alternatives
        // keyed on the wire attribute any more.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   [n] = values;
                   if (n === "a") { t.alpha = e.attrString("va"); }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_alias_overwritten_by_a_constant_down_a_branch_declines() {
        // `if (flag) x = "fixed"` leaves `x` holding the read on the other path, so
        // `t.value = x` names it there and not here.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { var x = e.attrString("first");
                                    if (flag) { x = "fixed"; }
                                    t.value = x; }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn an_accumulator_a_branch_may_repoint_declines() {
        // `alias = result; { if (flag) alias = cache; } return alias` hands back one object
        // or the other; guessing gives the API to whichever a branch names.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias;
                   alias = result;
                   { if (flag) { alias = cache; } }
                   if (n === "a") { result.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1"); }
                   if (n === "b") { result.bar = e.attrString("b1");
                                    cache.wrongB = e.attrString("w2"); }
                   return alias;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn arms_that_pin_one_lifted_leaf_differently_decline() {
        // A child lifted out of the arms carries one band; `1..=10` for `a` and `20..=30`
        // for `b` cannot both be honoured there.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { e.child("detail").attrIntRange("count", 1, 10);
                                    t.alpha = e.attrString("va"); }
                   if (n === "b") { e.child("detail").attrIntRange("count", 20, 30);
                                    t.beta = e.attrString("vb"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined rather than publishing one arm's band for both: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn a_do_while_that_returns_ends_that_value() {
        // The body runs before the test, so an exit in the first iteration is an exit —
        // unlike `while`/`for`, whose body may never run at all.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.alpha = e.attrString("va");
                     do { return t; } while (c); }
                   if (n === "b") { t.beta = e.attrString("vb"); }
                   if (n === "a") { t.gamma = e.attrString("vc"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            !a_fields.iter().any(|n| n == "gamma"),
            "the unreachable arm is not part of the variant: {a_fields:?}"
        );
    }
    #[test]
    fn an_accumulator_a_loop_may_repoint_declines() {
        // A body that may run zero times repoints the alias only on some paths.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias;
                   alias = result;
                   while (flag) { alias = cache; break; }
                   if (n === "a") { result.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1"); }
                   if (n === "b") { result.bar = e.attrString("b1");
                                    cache.wrongB = e.attrString("w2"); }
                   return alias;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_write_in_a_catch_does_not_overwrite_the_try() {
        // The catch runs only when the try stopped partway, so `value` holds the first
        // read on the successful path — one field cannot say both.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { try { t.value = e.attrString("first"); }
                                    catch (err) { t.value = e.attrString("second"); } }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn a_write_after_a_conditional_exit_does_not_overwrite() {
        // The early return hands back the first read, so `value` is not always the second.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   if (n === "a") { t.value = e.attrString("first");
                                    if (flag) { return t; }
                                    t.value = e.attrString("second"); }
                   if (n === "b") { t.other = e.attrString("third"); }
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined, so the reads stay flat: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_return_choosing_between_two_objects_declines() {
        // `return flag ? result : cache` hands back one or the other; reading only a bare
        // identifier saw neither, and the cache won the frequency tie-break.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, cache = {};
                   if (n === "a") { result.foo = e.attrString("f1");
                                    cache.wrongA = e.attrString("w1");
                                    cache.wrongB = e.attrString("w2"); }
                   if (n === "b") { result.bar = e.attrString("b1");
                                    cache.wrongC = e.attrString("w3");
                                    cache.wrongD = e.attrString("w4"); }
                   return flag ? result : cache;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        assert!(
            !kids.iter().any(|f| f.field_type == ParsedFieldType::Union),
            "declined rather than publishing one object's names: {:?}",
            kids.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn two_returns_naming_aliases_of_one_object_are_not_ambiguous() {
        // Both returns hand back the same accumulator under different names, so the
        // choice is settled and the dispatch stands.
        let r = analyze_parser_ast(
            r#"{ e.forEachChildWithTag("row", function(e){
                   var n = e.attrString("kind");
                   var result = {}, alias = result;
                   if (n === "a") { result.foo = e.attrString("f1"); }
                   if (n === "b") { result.bar = e.attrString("b1"); }
                   return alias;
                 }); }"#,
            "e",
        );
        let kids = r.fields[0].children.as_ref().unwrap();
        let a_fields: Vec<String> = kids
            .iter()
            .find(|f| f.field_type == ParsedFieldType::Union)
            .and_then(|f| f.union_variants.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "a"))
            .map(|v| v.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default();
        assert!(
            a_fields.iter().any(|n| n == "foo"),
            "one object, so the accumulator is settled: {a_fields:?}"
        );
    }
}
