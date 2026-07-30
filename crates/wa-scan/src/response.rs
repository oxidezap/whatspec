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

use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_string_lit, callee_method, callee_object,
};

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
            // Three answers, not two. `void 0` — which is how WA writes "no upper limit" — is an
            // OPEN bound and the band stays half-open. An expression this scan cannot fold is an
            // UNKNOWN one, and reading it as open was the same mistake as reading a negative
            // literal as absent, from the other side: `attrIntRange("score", minimum, 10)`
            // became "signed, at most 10", so the decoder took a `-1` that a `minimum` of 5
            // turns away. Neither bound is recorded when either is unreadable, and the drop
            // says so rather than a band nobody can check.
            // Through `as_int`, because JavaScript has no negative literal: `-10` is a unary
            // minus over `10`, and matching `NumericLiteral` alone recorded no floor at all.
            // An absent floor is not neutral — it is the open-bottom band, which the width rule
            // reads as "this field is signed with no lower limit", so the emitted decoder took
            // a `-20` the accessor turns away. The exact opposite of what the bound is for, and
            // reachable only for a negative one. `as_int` also turns away a fractional or
            // out-of-range literal, which the cast quietly truncated.
            let bound = |i: usize| match call.arguments.get(i).and_then(arg_expr) {
                // A missing argument, `void 0`, `undefined` or `null`: the accessor is told
                // there is no bound on that side.
                None => IntBound::Open,
                Some(e) if is_no_bound(e) => IntBound::Open,
                // Through `as_int`, because JavaScript has no negative literal: `-10` is a
                // unary minus over `10`. It also turns away a fractional or out-of-range
                // literal, which the old cast quietly truncated.
                Some(e) => as_int(e).map_or(IntBound::Unreadable, IntBound::At),
            };
            match (bound(1), bound(2)) {
                (IntBound::Unreadable, _) | (_, IntBound::Unreadable) => {
                    unresolved.push(format!("{RANGE_BOUND}@{field_name}"));
                }
                (lo, hi) => {
                    f.int_min = lo.value();
                    f.int_max = hi.value();
                }
            }
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
        guard_claims: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: 0,
        block_depth: 0,
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
        assertions: unconditional_assertions(&mut a),
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
/// A helper was handed a node whose name has since been assigned to, so where its reads
/// belong is no longer known.
const NODE_REASSIGNED: &str = "reassignedNodeHandedOn";
/// The formal the node was handed to binds by pattern rather than by name, so the helper
/// body cannot be analysed against it.
const UNNAMED_FORMAL: &str = "nodeBoundByPattern";

/// The `dropsByReason` key for a `switch` arm that redeclares a tracked child node and then
/// falls through, so the arms after it are reached with two different bindings of that name
/// depending on where the value entered.
///
/// `switch (mode) { case "a": var x = e.child("inner"); case "b": parse(x); break; }` reads
/// `x` as `<inner>` when entered at `"a"` and as the outer `x` when entered at `"b"`. Both
/// placements are correct for their own path, and the tree needs both — which means walking
/// the reading arm once per entry path. That is O(cases²) re-walks, each able to trigger
/// helper descent and re-parse a module function, against a corpus whose largest dispatch has
/// 44 arms. Declined on that cost, and counted here so the omission is visible in the drop
/// accounting instead of being a shape that quietly claims one placement is the only one.
const SWITCH_ARM_SHADOW: &str = "arm-shadowed node";

/// The `dropsByReason` key for a case test that reads the wire on a path no entry accounts for.
///
/// A test that is not reached by every value-producing execution is evaluated by exactly the
/// entries that did not match an earlier one — `switch (mode) { case "a": parse(e); break; case
/// parse(e): break; default: parse(e); }` calls `parse` on every path, but through the test on
/// some of them. Attributing that would mean a per-test relaxation slice plus a model of which
/// entries evaluate which test, in the visitor this branch has already revised six times.
///
/// Declined on that, and detected rather than guessed at: the marker fires exactly when such a
/// test contributed a read, which in the locked corpus is never. Of 4836 non-literal case tests
/// there, 4831 are `o("SomeModule").MEMBER` enum lookups and not one contains a wire accessor —
/// the shape is ubiquitous in form and absent in substance.
const SWITCH_TEST_READ: &str = "case-test read";

/// A bound on `attrIntRange` that is neither a literal nor the "no bound" spelling — a
/// `minimum` whose value only the running module knows. Recorded rather than guessed, because
/// both guesses are wrong in a direction: calling it open makes the field signed and unbounded
/// below, and calling it zero invents a floor the source may not enforce.
const RANGE_BOUND: &str = "unreadableRangeBound";

/// One side of a declared integer range, which is three answers and not two.
enum IntBound {
    /// Explicitly no bound on this side — a missing argument, `void 0`, `undefined`, `null`.
    Open,
    At(i64),
    /// An expression this scan cannot fold.
    Unreadable,
}

impl IntBound {
    fn value(self) -> Option<i64> {
        match self {
            IntBound::At(n) => Some(n),
            _ => None,
        }
    }
}

/// Whether `e` is how a source says "no bound on this side".
fn is_no_bound(e: &Expression<'_>) -> bool {
    match e {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(i) => i.name == "undefined",
        Expression::UnaryExpression(u) => u.operator == oxc_syntax::operator::UnaryOperator::Void,
        Expression::ParenthesizedExpression(p) => is_no_bound(&p.expression),
        _ => false,
    }
}

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
    /// The same guards again, as CLAIMS a branch hands up — the assertion half of
    /// [`ParserAnalyzer::relaxed_by_branch`], and separate storage for the same reason.
    ///
    /// `conditional_assertions` is a multiset subtracted from the output, so an entry must
    /// stay in it for exactly as long as its guard is unpublished. The per-branch slices an
    /// intersection reads want the opposite: rewriting, so a nested conditional hands its
    /// enclosing one only what it established. Serving both from one list, the nested settle
    /// could only leave the region alone — and every branch-local guard travelled up with it,
    /// so `if (outer) { if (inner) assertAttr("kind","a"); else assertAttr("kind","b"); }`
    /// published `kind="a"` against a parser that asserts `"b"` down one path and nothing at
    /// all down another. Rejecting what the source accepts, from the one place the two roles
    /// could not both be honoured.
    guard_claims: Vec<ResponseAssertion>,
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
    /// How many `{ … }` blocks deep the walk is. The analysed source is itself a block — a
    /// callback body — and names declared at the top of it live for the whole of it,
    /// including a dispatch reconstructed after the walk from the final `child_vars`.
    block_depth: u32,
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

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        // A `let`/`const` naming a child dies with the block, so the outer entry of that
        // name has to come back — `{ let x = e.child("inner"); } x.attrString("outside")`
        // read the outside attribute off `<inner>`, which puts a field under a node the
        // parser never reads it from. Restoring per FUNCTION was not enough, and
        // restoring the whole map per block would be wrong the other way: `var` is
        // function-scoped and a child it binds is meant to outlive the block.
        // Only for a block NESTED inside the body. The outermost one IS the analysed source,
        // and restoring at the end of it deleted a `let`-bound child before
        // `discriminated_children` read the map to seed the dispatch arms — so
        // `let detail = e.child("detail")` followed by arms reading `detail` produced an empty
        // `<detail>` and lost both reads with nothing recorded.
        let nested = self.block_depth > 0;
        let shadowed: Vec<(String, Option<Vec<PathSeg>>)> = if nested {
            block
                .body
                .iter()
                .filter_map(|s| match s {
                    Statement::VariableDeclaration(d) => Some(&**d),
                    _ => None,
                })
                .flat_map(|d| self.lexical_children_of(Some(d)))
                .collect()
        } else {
            Vec::new()
        };
        self.block_depth += 1;
        walk::walk_block_statement(self, block);
        self.block_depth -= 1;
        self.restore_children(shadowed);
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

    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        // The discriminant is evaluated to choose a case, so it runs whichever case wins.
        self.visit_expression(&stmt.discriminant);
        // Tests are evaluated in order until one matches, so a test is skipped only when an
        // earlier one matched. A test is therefore reached on every execution that can produce
        // a value when every earlier tested case, once entered, THROWS — the paths that skip it
        // are exactly the paths that hand nothing back.
        //
        // The first tested case is the vacuous instance of that, and a `default` written first
        // is not a test and does not shield the one after it: `switch (mode) { default: break;
        // case parse(e): break; }` still evaluates `parse`. So is `switch (mode) { case "a":
        // throw Error(); case parse(e): break; default: break; }`, where the only value-
        // producing executions are the ones that fell through the `"a"` test — reading that
        // second test as conditional relaxed a read every successful parse performs.
        // An arm that redeclares a tracked child and then falls through leaves the arms after
        // it reachable with two different bindings of that name. Only the falling-through case
        // is ambiguous: `case "x": var t = e.child("t"); break;` rebinds nothing anyone else
        // sees. Counted rather than resolved — see `SWITCH_ARM_SHADOW`.
        let tracked_before: Vec<String> = self.child_vars.keys().cloned().collect();
        for (i, case) in stmt.cases.iter().enumerate() {
            if leaves_switch(&case.consequent, true) || i + 1 >= stmt.cases.len() {
                continue;
            }
            for name in hoisted_names(&case.consequent) {
                if tracked_before.iter().any(|t| t == &name) {
                    self.unresolved.push(format!("{SWITCH_ARM_SHADOW}@{name}"));
                }
            }
        }
        let entry_throws = entry_paths_throw(&stmt.cases);
        let always_evaluated: Vec<bool> = (0..stmt.cases.len())
            .map(|i| {
                stmt.cases[i].test.is_some()
                    && (0..i).all(|j| stmt.cases[j].test.is_none() || entry_throws[j])
            })
            .collect();
        for (i, case) in stmt.cases.iter().enumerate() {
            if always_evaluated[i]
                && let Some(test) = case.test.as_ref()
            {
                self.visit_expression(test);
            }
        }
        let before = (self.assertions.len(), self.relaxed_by_branch.len());
        self.conditional_depth += 1;
        // What each case establishes ON ITS OWN. A helper every case calls runs on every
        // path, the same way one called from both sides of an `if` does — and `if` gets that
        // back through an intersection this had no equivalent of, so N weakened copies just
        // stayed weak and a field the parser always reads came out optional.
        let mut per_case: Vec<Vec<RelaxedId>> = Vec::new();
        // The guards each case establishes, collected the same way and settled through the
        // same intersection — a helper every arm calls enforces its `assertAttr` on every
        // path, and discarding those while promoting the arm's FIELDS to required published a
        // shape that accepts values every source path rejects.
        let guard_mark = (self.guard_claims.len(), self.conditional_assertions.len());
        let mut per_case_guards: Vec<Vec<ResponseAssertion>> = Vec::new();
        // Every case shares ONE lexical scope, and it ends with the switch — so a `let`/`const`
        // naming a child must not outlive it. `switch (m) { case 1: let d = e.child("inner");
        // break; } d.attrString("outside")` filed the trailing read under `<inner>`, which is
        // the wrong-node direction the block and loop-header restores were added for. This
        // visitor mutated `child_vars` and put nothing back; `SWITCH_ARM_SHADOW` does not cover
        // it, since that fires only for a falling-through arm and only records a drop.
        let shadowed: Vec<(String, Option<Vec<PathSeg>>)> = stmt
            .cases
            .iter()
            .flat_map(|c| c.consequent.iter())
            .filter_map(|st| match st {
                Statement::VariableDeclaration(d) => Some(&**d),
                _ => None,
            })
            .flat_map(|d| self.lexical_children_of(Some(d)))
            .collect();
        // What the switch was entered WITH, to put back at an arm boundary no fallthrough
        // crosses.
        let entered_with = self.child_vars.clone();
        for (i, case) in stmt.cases.iter().enumerate() {
            // Entering at this case runs it and the ones after it; the ones before it run only
            // if control fell through, and an arm that ends on every path lets nothing through.
            // `case "a": var t = e.child("inner"); break; case "b": t.attrString("id");` filed
            // the second arm's read under `<inner>` — a node that entry never reached. The
            // wrong node, and silently: `SWITCH_ARM_SHADOW` fires only for an arm that falls
            // through AND redeclares a name tracked before the switch, which a `break` here
            // rules out. This is the half of the fallthrough model that costs nothing to be
            // exact about; which bindings a falling-through entry carries stays counted.
            if i > 0
                && stmt.cases[i - 1]
                    .consequent
                    .iter()
                    .any(ends_the_statement_list)
            {
                self.child_vars.clone_from(&entered_with);
            }
            // Falling through into a case runs its CONSEQUENT, never its test, so the two are
            // collected apart — folding a later case's test into the entry path had
            // `case "a": case parse(e): break;` promote reads the `"a"` path never performs.
            if !always_evaluated[i]
                && let Some(test) = case.test.as_ref()
            {
                // A test reached only by the entries that did not match earlier: its reads
                // belong to those paths, and nothing here can say which. Counted — see
                // `SWITCH_TEST_READ`.
                let before_test = self.relaxed_by_branch.len();
                self.visit_expression(test);
                if self.relaxed_by_branch.len() > before_test {
                    self.unresolved.push(SWITCH_TEST_READ.to_string());
                }
            }
            let at = self.relaxed_by_branch.len();
            let at_guards = self.guard_claims.len();
            for st in &case.consequent {
                self.visit_statement(st);
            }
            per_case.push(self.relaxed_by_branch[at..].to_vec());
            per_case_guards.push(self.guard_claims[at_guards..].to_vec());
        }
        // Entering at case `i` runs case `i` and then falls through to `i+1`, `i+2`… until one
        // of them leaves. `switch (mode) { case "a": default: parse(e); }` runs `parse` for
        // every value, and intersecting each case's OWN reads called the empty first case
        // decisive and left the payload optional.
        let mut entry: Vec<Vec<RelaxedId>> = vec![Vec::new(); stmt.cases.len()];
        let mut entry_guards: Vec<Vec<ResponseAssertion>> = vec![Vec::new(); stmt.cases.len()];
        for i in (0..stmt.cases.len()).rev() {
            let body = &stmt.cases[i].consequent;
            let leaves = leaves_switch(body, false);
            let mut weak = per_case[i].clone();
            let mut guards = per_case_guards[i].clone();
            if !leaves && i + 1 < stmt.cases.len() {
                weak.extend(entry[i + 1].iter().cloned());
                guards.extend(entry_guards[i + 1].iter().cloned());
            }
            entry[i] = weak;
            entry_guards[i] = guards;
        }
        let per_case = entry;
        let per_case_guards = entry_guards;
        // Only when a `default` makes the cases cover every value — otherwise an unlisted
        // value runs none of them, and promoting would require of every element something
        // the parser reads on no path at all. A case that merely falls through establishes
        // nothing of its own, so the intersection stays empty and nothing is promoted.
        // Over the paths that can PRODUCE a result. An arm ending in `throw` returns nothing,
        // so every successful execution took one of the others — including it as an empty path
        // left a field optional that every path yielding a value reads.
        let exhaustive = stmt.cases.iter().any(|c| c.test.is_none());
        // Entering at case `i` runs its consequent and then falls through, so whether that
        // ENTRY can produce a value is what decides whether it belongs in the intersection.
        // `entry_paths_throw` already modelled the fallthrough for the test ordering and this
        // asked `throws_out` of the local consequent alone, so `case "a": default: throw` left
        // the empty `"a"` entry in the fold and the helper's fields optional.
        // And over the entries an execution can actually START at. A case repeating an earlier
        // case's literal is never matched — the first one wins — so its reads say nothing about
        // any entry path, and including the empty duplicate emptied the intersection.
        let entry_shadowed = shadowed_case_tests(&stmt.cases);
        let yields_a_value = |i: &usize| -> bool { !entry_throws[*i] && !entry_shadowed[*i] };
        let established = if exhaustive {
            per_case
                .into_iter()
                .enumerate()
                .filter(|(i, _)| yields_a_value(i))
                .map(|(_, weak)| weak)
                .reduce(|a, b| branch_intersection(&a, &b))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let guard_sides: Vec<Vec<ResponseAssertion>> = if exhaustive {
            per_case_guards
                .into_iter()
                .enumerate()
                .filter(|(i, _)| yields_a_value(i))
                .map(|(_, g)| g)
                .collect()
        } else {
            Vec::new()
        };
        self.relaxed_by_branch.truncate(before.1);
        self.settle_guard_intersection(guard_mark.0, guard_mark.1, &guard_sides);
        // Still inside this switch's own increment, so `settle` can tell whether an
        // enclosing conditional can skip the whole thing — the same order `if` uses.
        self.settle_branch_intersection(established);
        self.conditional_depth -= 1;
        self.restore_children(shadowed);
    }

    fn visit_while_statement(&mut self, stmt: &oxc_ast::ast::WhileStatement<'a>) {
        // The test is evaluated before the first pass, so it runs even when the body does not.
        self.visit_expression(&stmt.test);
        // But a test that cannot be false has no zero-iteration path: `while (!0) { parse(e);
        // break; }` is `for (;;)` spelled differently, and the corpus writes it that way 74
        // times. Wrapping the body in a skipped path regardless relaxed reads every successful
        // execution performs.
        if always_true(&stmt.test) {
            self.walk_guaranteed_pass(&stmt.body);
        } else {
            self.in_skipped_path(|s| s.visit_statement(&stmt.body));
        }
    }

    fn visit_do_while_statement(&mut self, stmt: &oxc_ast::ast::DoWhileStatement<'a>) {
        // `do` runs its body before the test, so the first pass is guaranteed. A `break` can
        // cut that pass short, but only for what comes AFTER it — `do { parse(e); break; }`
        // still runs `parse` every time, and weakening the whole body called its reads
        // optional. So the body is walked in order and the counter goes up at the first
        // statement that something before it could have jumped past.
        self.walk_guaranteed_pass(&stmt.body);
        // And the test is only reached if the pass did not leave the loop first:
        // `do { break; } while (parse(e))` never evaluates `parse` at all, so recovering its
        // reads as required rejects nodes the parser never looks at. A body that can only
        // THROW past the test is different — `do { if (bad) throw Error(); } while (parse(e))`
        // evaluates `parse` on every execution that yields anything.
        // `continue` is not one of those ways out: in a `do`/`while` it transfers control TO
        // the test, so `do { continue; } while (parse(e))` evaluates `parse` on every execution
        // that can leave the loop at all. Counting it with `break` relaxed a read every
        // successful parse performs.
        if leaves_the_loop_with_a_value(&stmt.body) {
            self.in_skipped_path(|s| s.visit_expression(&stmt.test));
        } else {
            self.visit_expression(&stmt.test);
        }
    }

    fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
        // A `let`/`const` in the header is scoped to the loop, so a child it names has to be
        // put back afterwards — `for (let x = e.child("inner"); …) {} x.attrString("id")` reads
        // the trailing attribute off the OUTER `x`. Only block statements were being restored,
        // and a loop header is not one.
        let shadowed = self.lexical_children_of(stmt.init.as_ref().and_then(|i| match i {
            oxc_ast::ast::ForStatementInit::VariableDeclaration(d) => Some(&**d),
            _ => None,
        }));
        // Initializer and test are evaluated before the first pass; the update only after
        // a pass that happened.
        if let Some(init) = &stmt.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &stmt.test {
            self.visit_expression(test);
        }
        // With no test there is no zero-iteration path: `for (;;) { … }` necessarily starts
        // its body, so what the body reads before it can leave is read every time — the same
        // asymmetry `do`/`while` has, which is why the body is walked in order here too.
        // No test, or one that cannot be false: either way the body necessarily starts. The
        // braced and unbraced arms said the same thing twice and only one of them had the
        // in-order walk, which is why they are one arm now.
        let guaranteed = stmt.test.as_ref().is_none_or(always_true);
        match (&stmt.body, guaranteed) {
            (body, true) => {
                self.walk_guaranteed_pass(body);
                if let Some(update) = &stmt.update {
                    self.in_skipped_path(|s| s.visit_expression(update));
                }
            }
            // Body first, then the update: that is the order JavaScript runs them, and a
            // binding the body makes is one the update can read. Reversed, `for (; more;
            // parse(detail)) { var detail = e.child("detail"); }` reached `parse` before
            // `child_vars` held `detail` and lost the helper's fields with nothing recorded.
            // Both stay inside the skipped path — a tested loop may run zero times.
            _ => self.in_skipped_path(|s| {
                s.visit_statement(&stmt.body);
                if let Some(update) = &stmt.update {
                    s.visit_expression(update);
                }
            }),
        }
        self.restore_children(shadowed);
    }

    fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
        // The object is evaluated to be enumerated, however few keys it turns out to have.
        self.visit_expression(&stmt.right);
        // The binding is bound once per key, so a default in it — `for (const [v = read(e)]
        // …)` — runs only when there is a key. Writing these visitors by hand and walking
        // only the iterable and the body dropped such a read with nothing recorded.
        self.in_skipped_path(|s| {
            s.visit_for_statement_left(&stmt.left);
            s.visit_statement(&stmt.body);
        });
    }

    fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
        self.visit_expression(&stmt.right);
        // A list that syntactically cannot be empty runs the body at least once, so what the pass
        // reads before it can leave is read every time — the same guaranteed-pass asymmetry
        // `for (;;)` and `while (!0)` have, over the one iterable whose length is decidable here.
        // An arbitrary expression keeps its zero-iteration path.
        if iterates_at_least_once(&stmt.right) {
            self.visit_for_statement_left(&stmt.left);
            self.walk_guaranteed_pass(&stmt.body);
            return;
        }
        self.in_skipped_path(|s| {
            s.visit_for_statement_left(&stmt.left);
            s.visit_statement(&stmt.body);
        });
    }

    fn visit_try_statement(&mut self, stmt: &oxc_ast::ast::TryStatement<'a>) {
        // Nothing here runs at all: a block that hangs reaches neither the handler nor the
        // finalizer, so their reads belong to no path. The whole-try classification learned
        // this in `throws_out`; treating the handler as the block's successor here made a
        // `catch` that parses required, which is the same mistake pointing the other way.
        if hangs_forever(&stmt.block.body) {
            self.in_skipped_path(|s| {
                s.visit_block_statement(&stmt.block);
                if let Some(h) = &stmt.handler {
                    s.visit_catch_clause(h);
                }
                if let Some(f) = &stmt.finalizer {
                    s.visit_block_statement(f);
                }
            });
            return;
        }
        // A `finally` that can leave with a result hands one back whatever the block was doing,
        // so `try { parse(e); } finally { return fallback; }` returns `fallback` without ever
        // finishing `parse` — nothing the block or the handler reads is read on every path that
        // yields something. `throws_out` learned this fact last round for the try as a WHOLE;
        // the visitor deciding requiredness for the try's own reads never asked, so it kept
        // them required and the shape rejected responses the parser accepts. The same rule in
        // two places with one copy missing it, for the fourth time on this branch.
        if fin_leaves_with_a_value(stmt) {
            self.in_skipped_path(|s| {
                s.visit_block_statement(&stmt.block);
                if let Some(h) = &stmt.handler {
                    s.visit_catch_clause(h);
                }
            });
            // Still unconditional: it runs whichever way the block went.
            if let Some(f) = &stmt.finalizer {
                self.visit_block_statement(f);
            }
            return;
        }
        match &stmt.handler {
            // With a handler the block may abort partway and the parser carries on, so what
            // it reads past a throwing call is not read on every path — and the handler
            // itself runs only when the block failed. But a helper BOTH call, so every
            // successful execution passed through it, which is the two-sided intersection
            // `if` already does and this had no equivalent of.
            Some(h) => {
                let parked = self.conditional_assertions.len();
                let before = (self.guard_claims.len(), self.relaxed_by_branch.len());
                self.conditional_depth += 1;
                self.visit_block_statement(&stmt.block);
                let tried = (
                    self.guard_claims[before.0..].to_vec(),
                    self.relaxed_by_branch[before.1..].to_vec(),
                );
                let after_try = (self.guard_claims.len(), self.relaxed_by_branch.len());
                self.visit_catch_clause(h);
                let caught = (
                    self.guard_claims[after_try.0..].to_vec(),
                    self.relaxed_by_branch[after_try.1..].to_vec(),
                );
                // Over the paths that can PRODUCE a result, the same filter the switch arms
                // get. `catch (_) { throw Error(); }` hands nothing back, so every execution
                // that yielded a result completed the block — intersecting against the empty
                // handler left the block's reads optional where every successful parse
                // performs them. Both throwing means no path yields anything and nothing is
                // established, which `unwrap_or_default` already says.
                let mut weak_sides = Vec::new();
                let mut guard_sides = Vec::new();
                if !throws_out(&stmt.block.body) {
                    weak_sides.push(tried.1);
                    guard_sides.push(tried.0);
                }
                if !throws_out(&h.body.body) {
                    weak_sides.push(caught.1);
                    guard_sides.push(caught.0);
                }
                let established = weak_sides
                    .into_iter()
                    .reduce(|a, b| branch_intersection(&a, &b))
                    .unwrap_or_default();
                self.relaxed_by_branch.truncate(before.1);
                self.settle_guard_intersection(before.0, parked, &guard_sides);
                self.settle_branch_intersection(established);
                self.conditional_depth -= 1;
            }
            // Without one, an error propagates out of the parser: there is no path where
            // the block failed and a result was still produced, so its reads stay required.
            None => self.visit_block_statement(&stmt.block),
        }
        // The finalizer runs whichever way the block went, so it is conditional on nothing.
        if let Some(f) = &stmt.finalizer {
            self.visit_block_statement(f);
        }
    }

    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_expression(&stmt.test);
        // A test no value of it can change is not a branch at all: `if (!0) { parse(e); }` runs
        // `parse` on every execution, and raising the counter regardless intersected its reads
        // with an `else` that does not exist — leaving optional what the parser always performs.
        // The same `always_true`/`always_false` the loops read, on the construct they came from.
        // The side NOT taken is still walked, in a skipped path: its reads are unreachable, and
        // recording them as optional says less than dropping them silently would.
        if let Some(taken) =
            statically_selected(&stmt.test, &stmt.consequent, stmt.alternate.as_ref())
        {
            if let Some(t) = taken.0 {
                self.visit_statement(t);
            }
            if let Some(dead) = taken.1 {
                self.in_skipped_path(|s| s.visit_statement(dead));
            }
            return;
        }
        // `if (e.hasAttr("x")) …` says the element may lack `x` only on the path where it
        // was found; the `else` is where it is known ABSENT, and a read there is required
        // by whatever the parser does next. A negated test flips the two.
        let tested = self.canonical_guards(&stmt.test);
        let n = tested.len();
        let parked = self.conditional_assertions.len();
        self.conditional_depth += 1;

        let before_then = (self.guard_claims.len(), self.relaxed_by_branch.len());
        self.guarded_names.extend(tested);
        self.visit_statement(&stmt.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        let then_side = self.guard_claims[before_then.0..].to_vec();
        let then_weak = self.relaxed_by_branch[before_then.1..].to_vec();

        let mut established = Vec::new();
        if let Some(alt) = &stmt.alternate {
            let before_else = (self.guard_claims.len(), self.relaxed_by_branch.len());
            self.visit_statement(alt);
            let else_side = self.guard_claims[before_else.0..].to_vec();
            let else_weak = self.relaxed_by_branch[before_else.1..].to_vec();
            // Over the sides that can PRODUCE a value. `if (flag) { parse(e); } else { throw
            // Error(); }` calls `parse` on every execution that yields anything, and
            // intersecting against the empty throwing side left the payload optional and its
            // guard unpublished. The switch and the try have filtered this for two rounds; the
            // construct that taught them the intersection had not.
            let sides: Vec<(Vec<RelaxedId>, Vec<ResponseAssertion>)> = [
                (&stmt.consequent, then_weak, then_side),
                (alt, else_weak, else_side),
            ]
            .into_iter()
            .filter(|(body, _, _)| !throws_out(std::slice::from_ref(*body)))
            .map(|(_, w, g)| (w, g))
            .collect();
            let guard_sides: Vec<Vec<ResponseAssertion>> =
                sides.iter().map(|(_, g)| g.clone()).collect();
            self.settle_guard_intersection(before_then.0, parked, &guard_sides);
            established = sides
                .into_iter()
                .map(|(w, _)| w)
                .reduce(|a, b| branch_intersection(&a, &b))
                .unwrap_or_default();
        } else {
            // With no `else` the implicit other side establishes nothing, so the intersection
            // is empty — but the claims were still sitting in the region, and an enclosing
            // conditional read them as this branch's own. `if (outer) { if (inner)
            // assertAttr("kind", "a"); } else { assertAttr("kind", "a"); }` published a guard
            // the parser makes only when `inner` holds. Settling with no sides at all says it:
            // nothing established, claims dropped, everything stays parked.
            self.settle_guard_intersection(before_then.0, parked, &[]);
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
        // `!0 && parse(e)` and `0 || parse(e)` both run the right side always — the third
        // spelling of the same rule, and the counter went up for it too.
        if logical_right_is_certain(expr) {
            self.visit_expression(&expr.right);
            self.guarded_names.truncate(self.guarded_names.len() - n);
            return;
        }
        let claims = (self.guard_claims.len(), self.relaxed_by_branch.len());
        self.conditional_depth += 1;
        self.visit_expression(&expr.right);
        self.conditional_depth -= 1;
        self.discard_claims(claims);
        self.guarded_names.truncate(self.guarded_names.len() - n);
    }

    fn visit_conditional_expression(&mut self, expr: &oxc_ast::ast::ConditionalExpression<'a>) {
        self.visit_expression(&expr.test);
        // `!0 ? a : b` selects its side as surely as `if (!0)` does. Spelling the rule for the
        // statement and not for the expression is how half the findings on this branch happened,
        // so both read the one selector.
        if let Some((taken, dead)) =
            statically_selected(&expr.test, &expr.consequent, Some(&expr.alternate))
        {
            if let Some(taken) = taken {
                self.visit_expression(taken);
            }
            if let Some(dead) = dead {
                self.in_skipped_path(|s| s.visit_expression(dead));
            }
            return;
        }
        let tested = self.canonical_guards(&expr.test);
        let n = tested.len();
        let parked = self.conditional_assertions.len();
        self.conditional_depth += 1;

        let before_then = (self.guard_claims.len(), self.relaxed_by_branch.len());
        self.guarded_names.extend(tested);
        self.visit_expression(&expr.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        let then_side = self.guard_claims[before_then.0..].to_vec();
        let then_weak = self.relaxed_by_branch[before_then.1..].to_vec();

        let before_else = (self.guard_claims.len(), self.relaxed_by_branch.len());
        self.visit_expression(&expr.alternate);
        let else_side = self.guard_claims[before_else.0..].to_vec();
        let else_weak = self.relaxed_by_branch[before_else.1..].to_vec();
        self.settle_guard_intersection(before_then.0, parked, &[then_side, else_side]);
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

    /// An assertion made whichever way a branch goes is made always: the assertion half of
    /// [`ParserAnalyzer::settle_branch_intersection`], and deliberately the same shape.
    ///
    /// `sides` are the claim slices, one per path that can produce a result. `claims` is where
    /// this conditional's claim region begins and `parked` where its parked region does — the
    /// two are rewritten differently, which is the whole reason they are two lists.
    ///
    /// A value every side establishes holds on every path, so EVERY occurrence parked inside
    /// the region is released — how many times one branch redundantly re-asserts it says
    /// nothing about whether it holds, and removing a fixed two left `if (c) { parse(e);
    /// parse(e); } else { parse(e); }` with a stray mark that filtered the guard back out.
    fn settle_guard_intersection(
        &mut self,
        claims: usize,
        parked: usize,
        sides: &[Vec<ResponseAssertion>],
    ) {
        let Some((first, rest)) = sides.split_first() else {
            // No path yields a value, so nothing is established — and the claims this
            // conditional collected are nobody's, since no enclosing branch runs it for a
            // result either.
            self.guard_claims.truncate(claims);
            return;
        };
        let established: Vec<ResponseAssertion> = first
            .iter()
            .filter(|a| rest.iter().all(|s| s.contains(a)))
            .cloned()
            .collect();
        // The claims this conditional hands up are exactly what it established, whatever it
        // took to establish them. Everything else was one inner path's alone.
        self.guard_claims.truncate(claims);
        // Established relative to THIS conditional only. Nested inside a one-sided outer `if`,
        // the outer can still skip every branch, so the guard stays parked — unpublished — and
        // travels on as the outer branch's own claim for the enclosing intersection to weigh.
        // Releasing it regardless of nesting published a guard the parser enforces on no path
        // at all.
        if self.conditional_depth > 1 {
            self.guard_claims.extend(established);
            return;
        }
        // At the outermost conditional there is nothing left to skip the branch, so what every
        // side established is unconditional: unpark every occurrence of it and it publishes.
        let mut region = self.conditional_assertions.split_off(parked);
        region.retain(|a| !established.contains(a));
        self.conditional_assertions.append(&mut region);
    }

    /// Whether an enclosing inner function re-binds the parser's own parameter, as seen
    /// from `span`.
    fn param_shadowed(&self, span: Span) -> bool {
        self.bound_by_inner_scope(self.param, span)
    }

    /// The name the formal at `idx` binds, or `None` with the stop recorded — there is no
    /// formal at that position, or it binds by pattern and so has no name to analyse the
    /// helper body against. One lookup for both descent paths: the two spellings of it were
    /// identical, and identical is how they drift.
    fn bound_formal<'p>(
        &mut self,
        params: &'p [Option<String>],
        idx: usize,
        helper: &str,
    ) -> Option<&'p str> {
        match params.get(idx) {
            Some(Some(p)) => Some(p.as_str()),
            // A formal that binds by pattern: the node arrives, and there is no name to
            // analyse the body against. That is a read the shape is missing.
            Some(None) => {
                self.unresolved.push(format!("{UNNAMED_FORMAL}@{helper}"));
                None
            }
            // No formal at all at that position. `helper(row)` where `helper()` declares
            // none simply ignores the argument, so there is nothing to recover and nothing
            // to report — counting it marked complete shapes as having lost something.
            None => None,
        }
    }

    /// The child entries a lexical declaration is about to shadow, with what they were —
    /// one snapshot for every scope that can host one, so a block and a loop header cannot
    /// disagree about which names die with them.
    fn lexical_children_of(
        &self,
        decl: Option<&VariableDeclaration<'_>>,
    ) -> Vec<(String, Option<Vec<PathSeg>>)> {
        decl.filter(|d| d.kind.is_lexical())
            .into_iter()
            .flat_map(|d| d.declarations.iter())
            .flat_map(|d| d.id.get_binding_identifiers())
            .map(|i| {
                let name = i.name.to_string();
                let before = self.child_vars.get(&name).cloned();
                (name, before)
            })
            .collect()
    }

    fn restore_children(&mut self, shadowed: Vec<(String, Option<Vec<PathSeg>>)>) {
        for (name, before) in shadowed {
            match before {
                Some(path) => self.child_vars.insert(name, path),
                None => self.child_vars.remove(&name),
            };
        }
    }

    /// Walk a loop body whose first pass is guaranteed, in source order: everything up to the
    /// first statement that something before it could have jumped past runs whatever happens,
    /// and only what follows that is a skipped path.
    ///
    /// `do`/`while`, a testless `for` and a `while` whose test cannot be false all have this
    /// same asymmetry. It was written out three times, once without the unbraced case and once
    /// not at all, which is how `while (!0)` kept relaxing a read the parser always performs.
    fn walk_guaranteed_pass<'a>(&mut self, body: &Statement<'a>) {
        let Statement::BlockStatement(b) = body else {
            // Nothing precedes a single statement, so the guaranteed pass reaches it.
            self.visit_statement(body);
            return;
        };
        let mut skipped = false;
        for st in &b.body {
            if skipped {
                self.in_skipped_path(|s| s.visit_statement(st));
            } else {
                self.visit_statement(st);
                // Only an exit that hands back a result: a statement that can merely THROW
                // past what follows it does not put a later read on a path some successful
                // parse skipped.
                skipped = exits_with_a_value(st);
            }
        }
    }

    /// Walk something control can reach past without having run it, with the branch counter
    /// raised for the duration.
    ///
    /// A helper called only down such a path does not make its payload required of every
    /// element, and its guards are that path's rather than the caller's. `switch`, the loops
    /// and a caught `try` each arrived separately as the same bug, so the first fix asked one
    /// whole-statement question — which was wrong in the other direction: a `switch`
    /// discriminant, a loop test and a `try` without a handler all run whatever happens, and
    /// weakening them called reads optional that the parser always performs. WHICH PART of a
    /// statement is skippable differs per construct, so each says so itself and this only
    /// carries the counter.
    fn in_skipped_path(&mut self, f: impl FnOnce(&mut Self)) {
        let claims = (self.guard_claims.len(), self.relaxed_by_branch.len());
        self.conditional_depth += 1;
        f(self);
        self.conditional_depth -= 1;
        // And it claims nothing for the branch it sits in. There is no intersection here to
        // settle — the path is simply skippable — so anything parked inside it must not travel
        // on as the enclosing branch's contribution: `if (a) { for (x of y) helper(e); } else {
        // helper(e); }` had both sides claim what `helper` reads, and the enclosing `if`
        // intersected them into a promotion, requiring of every element a read an empty list
        // performs on no path. The guards went the same way, publishing an `assertAttr` the
        // parser may never make. Both directions reject what the source accepts.
        self.discard_claims(claims);
    }

    /// Forget the claims made since `(guards, weak)` — for a construct that establishes
    /// nothing, whatever ran inside it.
    ///
    /// The parked entries stay: a guard keeps its unpublished mark and a relaxed field keeps
    /// being optional, which is what "this may not have run" means for the output. Only the
    /// claim an enclosing intersection would read is dropped.
    fn discard_claims(&mut self, (guards, weak): (usize, usize)) {
        self.guard_claims.truncate(guards);
        self.relaxed_by_branch.truncate(weak);
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
                let parked: Vec<ResponseAssertion> = self.assertions[before..].to_vec();
                self.conditional_assertions.extend(parked.iter().cloned());
                self.guard_claims.extend(parked);
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
        let mut moved = false;
        let picked = call.arguments.iter().enumerate().find_map(|(i, a)| {
            let id = arg_expr(a).and_then(as_identifier)?;
            if !self.names_an_outer_node(id, call.span) {
                return None;
            }
            // A node this scope tracks is the only thing that can be HANDED ON, so it is the
            // only thing whose loss there is to report. Asking about the write first meant any
            // ordinary local that happens to be assigned — `for (i = 0; i < n; i++) helper(i)`
            // — recorded `reassignedNodeHandedOn` for a child node that was never involved.
            // That is the same false-positive accounting the `picked`-is-none check below was
            // added to remove, one condition earlier, and it is the harmful kind: it makes
            // `dropsByReason` claim losses that did not happen.
            let tracked = self.child_vars.get(id)?;
            // `child_vars` is only updated by a declarator, so `i = i.child("other")` leaves
            // the recorded path pointing at the node `i` USED to name and the helper's fields
            // land under it. The sibling path was hardened against exactly this and this one
            // was not — the same instance-not-class split that put `leaf_guard` inline in one
            // union shape and left the other with a presence test.
            if self.local_bindings.written_in_scope(id, call.span) {
                moved = true;
                return None;
            }
            Some((i, tracked.clone()))
        });
        // Only once nothing survived. Pushing from inside the search recorded a loss for
        // `helper(reassigned, stillGood)` and then descended through the second argument
        // anyway — a drop entry for a read that was recovered. The own-node path already
        // waits for the whole search to fail; this one did not.
        let Some((arg_idx, tag)) = picked else {
            if moved {
                self.unresolved.push(format!("{NODE_REASSIGNED}@{name}"));
            }
            return;
        };
        let Some((params, body_src)) = self.module.functions.get(name) else {
            return;
        };
        let Some(bound_param) = self.bound_formal(params, arg_idx, name) else {
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
        // node to both parameters, and reading only one dropped what the other saw. An
        // alias of the node is the node — comparing against the parameter's own identifier
        // alone lost the helper entirely when the callback copied it first.
        //
        // A name that has been assigned to no longer stands for the node it was bound to, and
        // `names_for` already declines to follow one. The parameter itself is the case it
        // cannot see, so it is checked here — per ARGUMENT, not per call: rejecting the whole
        // call because the parameter was written somewhere threw away
        // `var original = row; row = row.child("detail"); parse(original)`, where `original`
        // still names the row and the helper's fields are recoverable there.
        let (stands_for, uncertain) = self.local_bindings.names_for(self.param, call.span);
        // The parameter is bound before the body runs, so anything that gives it a value —
        // an assignment or a redeclaration with an initializer — moves it off the node.
        let param_moved = self.local_bindings.written_in_scope(self.param, call.span)
            || self.local_bindings.given_before(self.param, call.span);
        let positions: Vec<usize> = call
            .arguments
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                arg_expr(a).and_then(as_identifier).is_some_and(|id| {
                    stands_for.contains(id)
                        && !(id == self.param && param_moved)
                        && !self.bound_by_inner_scope(id, call.span)
                })
            })
            .map(|(i, _)| i)
            .collect();
        // Handed on under a name that names the node only down some path: the call is
        // unconditional, so `conditional_depth` says nothing about it, and what the helper reads
        // is still read only when that path ran. Per ARGUMENT, so `parse(e)` beside an unrelated
        // conditional alias keeps its requiredness.
        let via_a_conditional_alias = positions.iter().any(|i| {
            call.arguments
                .get(*i)
                .and_then(arg_expr)
                .and_then(as_identifier)
                .is_some_and(|id| uncertain.contains(id))
        });
        if positions.is_empty() {
            // The node was handed on under a name that no longer stands for it — the
            // parameter itself after a write, or a copy given a second value. The shape is
            // incomplete either way, and saying so is what separates a bounded descent from
            // a silent one.
            if param_moved
                && call.arguments.iter().any(|a| {
                    arg_expr(a)
                        .and_then(as_identifier)
                        .is_some_and(|id| id == self.param)
                })
            {
                self.unresolved.push(format!("{NODE_REASSIGNED}@{name}"));
            }
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
            let Some(bound_param) = self.bound_formal(params, idx, name) else {
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
        //
        // So the conditional case is RECORDED rather than discarded, with the fact that it
        // was conditional travelling alongside in `conditional_assertions` — exactly how a
        // direct `e.assertAttr` behind an `if` is handled. Discarding it outright left
        // nothing for an intersection to hand back, so a helper called on both sides of a
        // branch had its fields promoted to required (the fields ARE parked, in
        // `relaxed_by_branch`) while its guard vanished: decoding accepted values every
        // source path rejects. No dedup on this side — two occurrences are what a two-sided
        // intersection needs to see, and one is unmarked per occurrence.
        for g in guards {
            if self.conditional_depth > 0 {
                self.assertions.push(g.clone());
                self.conditional_assertions.push(g.clone());
                self.guard_claims.push(g);
                continue;
            }
            // At depth zero the guard holds always, so it is recorded with nothing parked
            // beside it — and recorded unconditionally, because a presence test here dropped
            // it outright. `if (flag) { parse(e); } parse(e);` recorded one occurrence and
            // PARKED it; the presence test then skipped the unconditional call, the
            // subtraction removed the parked copy, and the guard vanished even though the
            // second call enforces it on every path. Order-dependent too: unconditional-first
            // published it fine. The multiset is the whole mechanism, and
            // `unconditional_assertions` collapses whatever survives it, so a repeated call
            // costs an occurrence here and never a duplicate in the output.
            self.assertions.push(g);
        }
        // Reached only down one branch, its payload is not required of every element —
        // requiring it would have consumers reject the elements the other branch accepts.
        if self.conditional_depth > 0 {
            for f in &mut recovered {
                note_relaxed(f, "", &mut self.relaxed_by_branch);
                relax_deeply(f);
            }
        } else if via_a_conditional_alias {
            // Same conclusion, different reason — and NO claim parked: nothing an enclosing
            // branch does makes the alias certain, so there is no intersection that should ever
            // hand this back as established.
            for f in &mut recovered {
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
    functions: HashMap<String, (Vec<Option<String>>, String)>,
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
    functions: HashMap<String, (Vec<Option<String>>, String)>,
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
    /// Record `name`'s params + body source. First one wins, except for a hoisted
    /// declaration, where the LAST is the binding that survives.
    ///
    /// `function parse(p){A} function parse(p){B} parse(e)` calls B: both declarations are
    /// hoisted and the later assignment is the one left standing. Keeping the first published
    /// the fields of a body that never runs and omitted the ones that do — a shape disagreeing
    /// with the helper the parser actually calls. An assignment form is not hoisted this way,
    /// so which of two is live depends on where the call sits, and first-wins stays the
    /// conservative reading there.
    fn record_fn(
        &mut self,
        name: &str,
        params: &oxc_ast::ast::FormalParameters,
        body: oxc_span::Span,
        hoisted: bool,
    ) {
        if self.functions.contains_key(name) && !hoisted {
            return;
        }
        // By POSITION, not just the ones that have a name: a destructured formal
        // (`function parse({opts}, node)`) contributes no identifier, and dropping it slid
        // every later parameter one place left. The node then bound to the wrong formal, or
        // to none at all, and the helper's reads left the shape with nothing recorded.
        let param_names: Vec<Option<String>> = params
            .items
            .iter()
            .map(|p| p.pattern.get_identifier_name().map(|n| n.to_string()))
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
        // A generator is not one of these: `function* parse(p){…}` called as `parse(e)` builds
        // an iterator and runs none of the body, so descending into it required of every
        // response what no execution of that call reads. The same fact the IIFE rule learned
        // one round earlier, at the other site that decides whether a body runs.
        if self.fn_depth == 1
            && !func.generator
            && let Some(id) = func.id.as_ref()
            && let Some(body) = func.body.as_ref()
        {
            let hoisted = func.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration;
            self.record_fn(id.name.as_str(), &func.params, body.span, hoisted);
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
                Expression::FunctionExpression(f) if self.fn_depth == 1 && !f.generator => {
                    if let Some(body) = f.body.as_ref() {
                        self.record_fn(name.as_str(), &f.params, body.span, false);
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
    formals: &[Option<String>],
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
        guard_claims: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: depth,
        block_depth: 0,
    };
    a.local_bindings = all_bindings(&ret.program);
    // Its own parameters are names it binds: `delegate(node, parse)` calls the `parse` it
    // was handed, not the module's, and the body alone does not say so.
    // The named ones. A formal that binds by pattern shadows whatever its properties are
    // called, which this list cannot say — the positions are what it is kept for.
    a.local_bindings
        .names
        .extend(formals.iter().flatten().cloned());
    a.visit_program(&ret.program);
    a.attach_pending_enum_keys();
    // What the helper could not resolve is the caller's loss too: reporting the field
    // without it lets the constraint ratchet read as clean while a byte range vanished.
    // Only what the helper enforces on every path: an `assertAttr` behind its own `if`
    // holds when that branch runs, and hoisting it would have the parser demand it always.
    let unconditional = unconditional_assertions(&mut a);
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
        guard_claims: Vec::new(),
        relaxed_by_branch: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: depth,
        block_depth: 0,
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
/// The assertions that hold on EVERY path: everything recorded, minus the occurrences
/// marked as made behind a branch.
///
/// A multiset subtraction rather than a filter — `if (c) assertAttr(k); else assertAttr(k);`
/// records the assertion twice and `unmark_branch_intersection` unmarks both, so removing
/// every occurrence of a marked value would delete the pair the two-sided intersection just
/// established. The helper path did this inline and the top-level parser did not do it at
/// all, so an `assertTag` made down one branch was published as one every response
/// satisfies — the harmful direction, since decoding then rejects what the parser accepts.
fn unconditional_assertions(a: &mut ParserAnalyzer) -> Vec<ResponseAssertion> {
    let mut guarded = std::mem::take(&mut a.conditional_assertions);
    let mut out: Vec<ResponseAssertion> = Vec::new();
    for x in std::mem::take(&mut a.assertions) {
        // Multiset subtraction first, THEN dedup. Collapsing duplicates before the
        // subtraction would leave one occurrence matching a mark that belongs to another and
        // filter out a guard that holds — the order is what makes both halves work.
        if let Some(i) = guarded.iter().position(|g| *g == x) {
            guarded.swap_remove(i);
            continue;
        }
        // Two identical assertions constrain nothing a single one does not: a helper called
        // on both sides of a branch establishes its guard once, and both occurrences reaching
        // the output published `assertAttr("kind", "x")` twice on the same shape.
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

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

/// A member access by a name this can read, computed or not: `f.call` and `f["call"]` reach the
/// same function, and matching only the dotted spelling left the bracket one walking an inline
/// body as one nobody calls. `static_name` answers `None` for a key nothing here resolves, which
/// is what keeps `f[k]` out.
fn named_member<'b, 'a>(
    e: &'b Expression<'a>,
) -> Option<(std::borrow::Cow<'b, str>, &'b Expression<'a>)> {
    match e {
        Expression::StaticMemberExpression(m) => Some((
            std::borrow::Cow::Borrowed(m.property.name.as_str()),
            &m.object,
        )),
        // Peeled: `f[("call")]` names the same property as `f["call"]`, and parentheses around
        // a key change nothing about which one it is.
        Expression::ComputedMemberExpression(m) => match peel(&m.expression) {
            Expression::StringLiteral(s) => {
                Some((std::borrow::Cow::Borrowed(s.value.as_str()), &m.object))
            }
            // A template with nothing substituted into it is a string spelled another way, and
            // ``f[`call`]`` reaches the same function as `f.call`. One with a substitution names
            // whatever that evaluates to, which is not a question for a syntactic pass.
            Expression::TemplateLiteral(t) if t.expressions.is_empty() && t.quasis.len() == 1 => t
                .quasis
                .first()
                .and_then(|q| q.value.cooked.as_ref())
                .map(|c| (std::borrow::Cow::Borrowed(c.as_str()), &m.object)),
            _ => None,
        },
        _ => None,
    }
}

/// The `.bind` member a call's callee resolves to, if that is what it is — so `f.bind(…)` is
/// told from `f.map(…)`, whose result is not `f`.
fn bind_member<'b, 'a>(callee: &'b Expression<'a>) -> Option<&'b Expression<'a>> {
    match named_member(invoked_callee(callee)) {
        Some((name, object)) if name == "bind" => Some(object),
        _ => None,
    }
}

/// The expression a call actually invokes, through the wrappers that do not change it:
/// parentheses, and a comma expression, whose value is its last element.
///
/// `(0, function(){ … })()` is how a minifier calls a function with `this` unbound, and reading
/// only the parenthesised form classified that body as one nobody calls — so a write inside it
/// stayed confined and the helper's fields were published on the node it had moved away from.
fn invoked_callee<'b, 'a>(mut e: &'b Expression<'a>) -> &'b Expression<'a> {
    // A member taken through the comma operator is a bare function VALUE: the reference is
    // discarded, so `(0, f.call)(null)` hands `Function.prototype.call` an `undefined` receiver
    // and throws before `f` is entered. Parentheses keep the reference and are not this.
    let mut through_comma = false;
    loop {
        e = match e {
            Expression::ParenthesizedExpression(p) => &p.expression,
            Expression::SequenceExpression(s) if !s.expressions.is_empty() => {
                through_comma = true;
                s.expressions.last().expect("checked non-empty")
            }
            // `(function(){ … }).call(null)` runs that body as immediately as `()` does; the
            // callee is a member expression, so the matcher fell through to the deferred walk
            // and the write stayed confined.
            //
            // Unwrapped unconditionally, not only for an inline receiver: `thing.call(…)`
            // unwraps to `thing`, which the caller's own test then rejects as something it has
            // never seen the body of. Guarding it here as well was an inert second copy of that
            // test, and no mutation could tell the two versions apart.
            // `(function(){ … }).bind(null)()` runs that body now too. The callee of the outer
            // call is itself a CALL, so nothing above matched it and the body was walked as one
            // nobody reaches. Only `.bind`, whose result IS the receiver's body; what
            // `(function(){ … }).map(g)` hands back is something else.
            Expression::CallExpression(c) => match bind_member(&c.callee) {
                Some(object) => object,
                None => return e,
            },
            other => match named_member(other) {
                Some((name, object))
                    if matches!(name.as_ref(), "call" | "apply") && !through_comma =>
                {
                    object
                }
                _ => return other,
            },
        };
    }
}

/// What actually reaches the invoked function's parameters, one slot per position.
///
/// `f(a, b)` hands them straight through. `f.call(thisArg, a, b)` hands `a, b`, the first
/// argument being the receiver. `f.apply(thisArg, [1])` hands the elements of that array — a
/// literal one is as readable as an argument list, and answering "unknowable" for every `.apply`
/// walked a default the call really does prevent.
///
/// `None` in a slot is an array ELISION — a position that certainly holds `undefined`, so it
/// supplies nothing while the positions after it stay where they are. A spread is the other
/// answer and ends the mapping outright, because it moves every position after it by an amount
/// nothing here knows.
fn effective_arguments<'b, 'a>(
    callee_expr: &'b Expression<'a>,
    arguments: &'b [Argument<'a>],
) -> Vec<Option<&'b Expression<'a>>> {
    arguments_then(callee_expr, arguments, Vec::new())
}

/// Through the wrappers that do not change which value an expression is — and no further.
/// `invoked_callee` looks through `bind` as well, which is the wrong depth for anything asking
/// what the receiver of a `bind` actually is.
fn peel<'b, 'a>(mut e: &'b Expression<'a>) -> &'b Expression<'a> {
    loop {
        e = match e {
            Expression::ParenthesizedExpression(p) => &p.expression,
            Expression::SequenceExpression(s) if !s.expressions.is_empty() => {
                s.expressions.last().expect("checked non-empty")
            }
            other => return other,
        };
    }
}

/// The mapping so far, and whether it reached the end of the list rather than stopping at a
/// spread. Nothing may be appended after a stop: where the next value lands is then unknown.
fn mapped<'b, 'a>(args: &'b [Argument<'a>]) -> (Vec<Option<&'b Expression<'a>>>, bool) {
    let mut out = Vec::new();
    for a in args {
        match a {
            Argument::SpreadElement(_) => return (out, false),
            other => out.push(other.as_expression()),
        }
    }
    (out, true)
}

fn append<'b, 'a>(
    (mut out, complete): (Vec<Option<&'b Expression<'a>>>, bool),
    trailing: Vec<Option<&'b Expression<'a>>>,
) -> Vec<Option<&'b Expression<'a>>> {
    if complete {
        out.extend(trailing);
    }
    out
}

/// [`effective_arguments`], with a suffix that lands after whatever this callee contributes.
///
/// The suffix is what makes nesting come out in the right order. `f.bind(a).bind(b)()` binds
/// `b` AFTER `a`, because the second `bind` extends the list the first one built — so the
/// outer group is a suffix of the inner one, not a prefix. Building it the other way round
/// produced `[b, a]`, which supplies the wrong parameter and, when the first bound value is
/// `undefined`, suppresses a default that really runs.
fn arguments_then<'b, 'a>(
    callee_expr: &'b Expression<'a>,
    arguments: &'b [Argument<'a>],
    trailing: Vec<Option<&'b Expression<'a>>>,
) -> Vec<Option<&'b Expression<'a>>> {
    let mut e = callee_expr;
    loop {
        e = match e {
            Expression::ParenthesizedExpression(p) => &p.expression,
            Expression::SequenceExpression(s) if !s.expressions.is_empty() => {
                s.expressions.last().expect("checked non-empty")
            }
            // `f.bind(thisArg, ...bound)(...outer)` hands `f` the BOUND arguments first and the
            // outer call's after them, which is as countable as an argument list. I answered
            // "nothing readable" for the whole shape when the invocation was first recognized,
            // and asserted so in a test; review was right that `.bind(null)(1)` supplies the
            // first parameter as plainly as `(1)` does.
            Expression::CallExpression(c) => {
                let Some(receiver) = bind_member(&c.callee) else {
                    return Vec::new();
                };
                // A spread in the RECEIVER slot moves every position after it, so which
                // argument is the `thisArg` is not decidable — same reading `.call` takes.
                if matches!(c.arguments.first(), Some(Argument::SpreadElement(_))) {
                    return Vec::new();
                }
                // This bind's own group, then the outer call's, then whatever already followed:
                // all of it lands after any group an INNER bind contributed, which is what the
                // recursion below recovers.
                let tail = append(
                    mapped(c.arguments.get(1..).unwrap_or_default()),
                    append(mapped(arguments), trailing),
                );
                // `(f.call).bind(…)` would need the receiver slot dropped from a list this has
                // already flattened, so it is left unread rather than mapped wrongly. Anything
                // else recurses: a receiver that is itself a bound function contributes its own
                // group in front, and one that is not contributes nothing and hands `tail` back.
                //
                // Peeled rather than run through `invoked_callee`, which looks through `bind`
                // itself — asking it here reported a nested bind as the function underneath and
                // the inner group was dropped, which is the bug this recursion exists to fix.
                return match named_member(peel(receiver)) {
                    Some((name, _)) if matches!(name.as_ref(), "call" | "apply") => Vec::new(),
                    _ => arguments_then(receiver, &[], tail),
                };
            }
            _ if named_member(e).is_some() => {
                let (name, _) = named_member(e).expect("checked");
                // A spread in the receiver slot contributes an unknown number of values, so
                // neither slicing it off nor indexing past it identifies anything: `f.call(
                // ...args, 1)` passes `1` as the receiver when `args` is empty and as the
                // first argument when it holds one.
                if matches!(name.as_ref(), "call" | "apply")
                    && matches!(arguments.first(), Some(Argument::SpreadElement(_)))
                {
                    return Vec::new();
                }
                return match name.as_ref() {
                    "call" => append(mapped(arguments.get(1..).unwrap_or_default()), trailing),
                    "apply" => {
                        let Some(Expression::ArrayExpression(arr)) =
                            arguments.get(1).and_then(Argument::as_expression)
                        else {
                            return Vec::new();
                        };
                        let mut out = Vec::new();
                        let mut complete = true;
                        for el in &arr.elements {
                            match el {
                                oxc_ast::ast::ArrayExpressionElement::SpreadElement(_) => {
                                    complete = false;
                                    break;
                                }
                                other => out.push(other.as_expression()),
                            }
                        }
                        append((out, complete), trailing)
                    }
                    _ => append(mapped(arguments), trailing),
                };
            }
            _ => return append(mapped(arguments), trailing),
        };
    }
}

/// Everything such a callee evaluates on the way to the function it invokes.
fn leading_parts<'b, 'a>(e: &'b Expression<'a>, out: &mut Vec<&'b Expression<'a>>) {
    match e {
        Expression::ParenthesizedExpression(p) => leading_parts(&p.expression, out),
        Expression::SequenceExpression(s) => {
            if let Some((last, rest)) = s.expressions.split_last() {
                out.extend(rest);
                leading_parts(last, out);
            }
        }
        // Through the `.call`/`.apply` wrapper the callee unwrapper now looks through, or
        // `(current = other, function(){}).call(null)` loses that assignment entirely — the
        // function is found and the comma's leading element is not. Two readers of one shape,
        // and only one of them was taught it.
        _ if named_member(e).is_some_and(|(name, _)| matches!(name.as_ref(), "call" | "apply")) => {
            let (_, object) = named_member(e).expect("checked");
            leading_parts(object, out);
        }
        // `(function(){ … }).bind(null, current = other)()` evaluates the bind call — receiver
        // and arguments both — before the body it returns is ever entered. The callee unwrapper
        // looks through this shape, and this reader did not, so the assignment beside the bound
        // receiver was recorded nowhere and the helper's fields were published on a node the
        // call had replaced. Same two-readers-of-one-shape split as the `.call` arm above.
        Expression::CallExpression(c) => {
            let Some(receiver) = bind_member(&c.callee) else {
                return;
            };
            leading_parts(receiver, out);
            out.extend(c.arguments.iter().map(|a| match a {
                // A spread still evaluates what it spreads.
                Argument::SpreadElement(s) => &s.argument,
                other => other.to_expression(),
            }));
        }
        _ => {}
    }
}

/// Whether `t`'s finalizer can complete abruptly with something other than an error, in which
/// case it hands that back whatever the block and handler did.
///
/// Anywhere inside it, not only at its top: `finally { if (retry) return fallback; }` discards
/// the pending error on the path that returns. `break` and `continue` out of the finalizer
/// discard it the same way, an unlabelled one belonging to a loop the finalizer opens itself
/// does not, and a `return` inside a function the finalizer merely constructs is that
/// function's — all three of which `exits_with_a_value` already decides.
///
/// Asked by `throws_out` about the try as a whole and by the visitor about the try's own reads.
/// It was spelled inline for the first and not asked at all by the second.
fn fin_leaves_with_a_value(t: &oxc_ast::ast::TryStatement<'_>) -> bool {
    let Some(fin) = t.finalizer.as_ref() else {
        return false;
    };
    // In order, stopping where control does: `finally { throw Error(); return fallback; }`
    // never reaches that `return`, and asking `any` of the whole list called the finalizer one
    // that hands a result back — so a `try` that really does throw counted as a value path and
    // diluted the intersection around it. The same in-order reading the statement walks use.
    for st in &fin.body {
        if exits_with_a_value(st) {
            return true;
        }
        if ends_the_statement_list(st) {
            return false;
        }
    }
    false
}

/// Whether `body` can neither complete nor raise — it hangs, so nothing after it runs and no
/// handler around it is ever reached.
///
/// [`throws_out`] answers the question every caller but one asks: can this path hand a result
/// back. A loop nothing leaves and a `throw` are the same answer there. They are not the same
/// to a `try` — an error reaches the handler and a hang does not — so `try { for (;;); } catch
/// (_) {}` was read as falling into a handler that completes, and therefore as a path that
/// yields something.
///
/// Deliberately narrow. Any statement whose evaluation could raise ends the walk, because
/// claiming a hang where a throw is possible hides a handler that does run — the direction that
/// makes required what the parser leaves optional. It recognises the minifier's `for (;;);` and
/// `while (!0) {}` and nothing that does work.
fn hangs_forever(body: &[Statement<'_>]) -> bool {
    for st in body {
        if is_a_hang(st) {
            return true;
        }
        if !is_quiet(st) {
            return false;
        }
    }
    false
}

/// A loop that is entered, cannot be left, and evaluates nothing that could raise.
fn is_a_hang(st: &Statement<'_>) -> bool {
    hangs_under(st, None)
}

/// The same, carrying the label the loop was written with — a `continue` naming it is one of
/// this loop's own, so it spins rather than leaves.
fn hangs_under(st: &Statement<'_>, label: Option<&str>) -> bool {
    match st {
        Statement::WhileStatement(w) => always_true(&w.test) && spins(&w.body, label),
        Statement::DoWhileStatement(d) => always_true(&d.test) && spins(&d.body, label),
        // A header that holds anything is a header that runs it: an init or an update can
        // raise, and a test that is not a literal is not decidable here anyway.
        Statement::ForStatement(f) => {
            f.init.is_none()
                && f.update.is_none()
                && f.test.as_ref().is_none_or(always_true)
                && spins(&f.body, label)
        }
        Statement::LabeledStatement(l) => hangs_under(&l.body, Some(l.label.name.as_str())),
        Statement::BlockStatement(b) => hangs_forever(&b.body),
        _ => false,
    }
}

/// A loop body that goes round again and does nothing else: it evaluates nothing, so it cannot
/// raise, and the only transfer it makes is back to the top of this same loop.
///
/// `while (!0) { continue; }` is as much a hang as `while (!0) {}`, and reading only the empty
/// spelling left the `catch` around it counting as a path that yields something. A `break` is
/// the opposite answer — it leaves — and anything evaluated at all could raise instead.
fn spins(st: &Statement<'_>, label: Option<&str>) -> bool {
    match st {
        // `continue` starts the next pass; unlabelled it belongs to the nearest loop, which is
        // this one, and labelled it has to name this one.
        Statement::ContinueStatement(c) => match &c.label {
            None => true,
            Some(l) => label == Some(l.name.as_str()),
        },
        Statement::BlockStatement(b) => b.body.iter().all(|st| spins(st, label)),
        other => is_quiet(other),
    }
}

/// A statement that evaluates nothing and ends nothing: it can neither raise nor leave the
/// construct around it. Everything else is assumed to be able to do both.
///
/// A `continue` is NOT one of these at the statement-list level, where it leaves the list —
/// only inside the body of the loop it belongs to, which is what [`spins`] asks.
fn is_quiet(st: &Statement<'_>) -> bool {
    match st {
        Statement::EmptyStatement(_) | Statement::DebuggerStatement(_) => true,
        Statement::BlockStatement(b) => b.body.iter().all(is_quiet),
        _ => false,
    }
}

/// Where the part of an immediately invoked function that runs synchronously with the call
/// ends: the first `await` it can reach, or all of it when there is none.
///
/// The first one in source order, not the first one every path reaches — a write past an
/// `await` some execution performs is one the caller does not wait for, and the caller's own
/// statements are all that this scanner reads.
fn synchronous_until(
    is_async: bool,
    span: Span,
    body: Option<&oxc_ast::ast::FunctionBody<'_>>,
) -> Vec<Span> {
    if !is_async {
        return vec![span];
    }
    struct FirstAwait {
        at: Option<u32>,
        nested: u32,
        /// Branches of an undecided `if` that contain no await of their own, and the
        /// CONTINUATION after a branch some path bypasses. Whichever side suspends, the other
        /// one still runs to its end without waiting for anything — and so does everything
        /// after the branch, on that same path.
        unsuspended: Vec<Span>,
        /// Where the walked body ends, for naming that continuation.
        body_end: u32,
        /// Continuations still to be closed: a position past a branch some path bypasses. Each
        /// runs synchronously until the next suspension EVERY surviving path reaches, which is
        /// not known until the walk has gone past it.
        pending: Vec<u32>,
        /// Every await, in source order, for closing those continuations.
        ///
        /// Every one of them, rather than only the ones no branch can bypass. I wrote the
        /// narrower rule first and no input separates the two: a construct that makes an await
        /// skippable records its own continuation after itself, so closing an earlier
        /// continuation at that await and closing it where the later continuation begins cover
        /// the same ground. A gate no test can hold is one to remove.
        unavoidable: Vec<u32>,
    }
    impl FirstAwait {
        fn note(&mut self, at: u32) {
            if self.nested == 0 {
                self.at = Some(self.at.map_or(at, |a| a.min(at)));
                self.unavoidable.push(at);
            }
        }
        /// A branch some execution skips: what follows it is synchronous on that path, until
        /// the next suspension every surviving path reaches.
        fn bypassed_after(&mut self, at: u32) {
            if self.nested == 0 {
                self.pending.push(at);
            }
        }

        /// The first await inside one statement, ignoring nested functions — asked of each side
        /// of a branch separately, which is the whole point.
        fn within(st: &Statement<'_>) -> Option<u32> {
            let mut probe = FirstAwait {
                at: None,
                nested: 0,
                unsuspended: Vec::new(),
                body_end: 0,
                pending: Vec::new(),
                unavoidable: Vec::new(),
            };
            probe.visit_statement(st);
            probe.at
        }
        /// The same, of one EXPRESSION — which a ternary's arms are.
        fn within_expr(e: &Expression<'_>) -> Option<u32> {
            let mut probe = FirstAwait {
                at: None,
                nested: 0,
                unsuspended: Vec::new(),
                body_end: 0,
                pending: Vec::new(),
                unavoidable: Vec::new(),
            };
            probe.visit_expression(e);
            probe.at
        }
    }
    impl<'a> Visit<'a> for FirstAwait {
        fn visit_await_expression(&mut self, e: &oxc_ast::ast::AwaitExpression<'a>) {
            self.note(e.span.start);
            walk::walk_await_expression(self, e);
        }
        // `for await (const x of xs)` suspends on every pass, and it is not an await EXPRESSION.
        //
        // The ITERABLE is not part of that: it is evaluated synchronously, and only drawing the
        // first result from it suspends. Noting the suspension at the head of the whole
        // statement put the iterable's own writes past the cutoff, so a write the caller does
        // see was confined to the function and the helper's fields were published on a node it
        // had replaced.
        fn visit_for_of_statement(&mut self, st: &oxc_ast::ast::ForOfStatement<'a>) {
            if !st.r#await {
                walk::walk_for_of_statement(self, st);
                return;
            }
            // …and the prefix this builds is SPAN-based, so noting the cutoff at the iterable's
            // end swept the loop TARGET in with it — the target is written above the iterable and
            // assigned only once the first result has been awaited. The suspension is noted at
            // the head of the statement, which excludes the target and the body, and the
            // iterable's own span is added back as a region that suspends nothing.
            //
            // Added back only when the iterable holds no await of its own: past one, the rest of
            // the iterable is the continuation's like anything else.
            let inner = FirstAwait::within_expr(&st.right);
            self.visit_expression(&st.right);
            if inner.is_none() && self.nested == 0 {
                self.unsuspended.push(st.right.span());
            }
            self.note(st.span.start);
            self.visit_for_statement_left(&st.left);
            self.visit_statement(&st.body);
        }
        // An `await` under a test no value can change is one control never reaches, so it
        // suspends nothing: `if (0) await x;` leaves the statements after it as synchronous as
        // they look. Taking the first TEXTUAL await confined a write the caller does see, and
        // the helper's fields were published on the node it had moved away from.
        //
        // And the two sides of an UNDECIDED `if` are alternatives, not a sequence. One side's
        // await says nothing about the other, which runs to its end without waiting — taking
        // the minimum across both confined a write that really is synchronous whenever its own
        // side is selected, and the field came out required on a node half the executions had
        // replaced. Each side is asked separately and the one that does not suspend is kept.
        fn visit_if_statement(&mut self, st: &oxc_ast::ast::IfStatement<'a>) {
            self.visit_expression(&st.test);
            if let Some((taken, _dead)) =
                statically_selected(&st.test, &st.consequent, st.alternate.as_ref())
            {
                if let Some(taken) = taken {
                    self.visit_statement(taken);
                }
                return;
            }
            let sides: Vec<(&Statement<'a>, Option<u32>)> = std::iter::once(&st.consequent)
                .chain(st.alternate.as_ref())
                .map(|s| (s, FirstAwait::within(s)))
                .collect();
            // A one-sided `if` has an implicit empty alternate, which suspends nothing — so a
            // path bypasses the await whenever the alternate is missing OR some side holds no
            // await of its own.
            let suspends = sides.iter().any(|(_, o)| o.is_some());
            let bypassed =
                suspends && (st.alternate.is_none() || sides.iter().any(|(_, o)| o.is_none()));
            for (side, first) in &sides {
                match first {
                    Some(at) => self.note(*at),
                    // Only when a SIBLING suspends is this worth recording: with no await
                    // anywhere in the `if`, the statements after it are synchronous too and the
                    // ordinary cutoff already covers this side.
                    None if suspends && self.nested == 0 => {
                        self.unsuspended.push(side.span());
                    }
                    None => {}
                }
                self.visit_statement(side);
            }
            // And the CONTINUATION. The sides were recorded from round nineteen and what comes
            // after them was not, so `if (flag) await 0; current = other;` — where a one-sided
            // `if` supplies no non-suspending sibling span at all — made the await a global
            // cutoff and confined a write that runs synchronously whenever `flag` is false. Two
            // executions disagree about whether the caller sees it, and the model owes the
            // answer that declines rather than the one that publishes under a node half of them
            // replaced.
            //
            // To the end of the body, which over-reaches past a LATER unconditional await. That
            // direction only marks more writes as seen, which loses fields rather than filing
            // them under the wrong node — the same asymmetry every other choice in this probe is
            // made on.
            if bypassed {
                self.bypassed_after(st.span.end);
            }
        }
        // A ternary is the decided branch the `if` arm already prunes, one syntactic level over.
        // `1 ? 0 : await 0` never evaluates that await, so the statements after it are as
        // synchronous as they look — and the generic walk took it as the cutoff.
        fn visit_conditional_expression(&mut self, e: &oxc_ast::ast::ConditionalExpression<'a>) {
            self.visit_expression(&e.test);
            if let Some((taken, _dead)) =
                statically_selected(&e.test, &e.consequent, Some(&e.alternate))
            {
                if let Some(taken) = taken {
                    self.visit_expression(taken);
                }
                return;
            }
            // The two arms are ALTERNATIVES, not a sequence: one's await says nothing about the
            // other, which runs to its end without waiting. Visiting them in order let the
            // consequent's `await` become the cutoff for the alternate as well, and a write that
            // really is synchronous whenever its own arm is selected was confined to the
            // function. The `if` arm has recorded that since round nineteen; this one merged
            // them, which is the same half-a-rule the ternary keeps being reported for.
            let sides = [&e.consequent, &e.alternate].map(|s| (s, FirstAwait::within_expr(s)));
            let suspends = sides.iter().any(|(_, o)| o.is_some());
            for (side, first) in &sides {
                match first {
                    Some(at) => self.note(*at),
                    None if suspends && self.nested == 0 => {
                        self.unsuspended.push(side.span());
                    }
                    None => {}
                }
                self.visit_expression(side);
            }
            // And the continuation, exactly as the `if` records it: when one arm suspends and
            // the other does not, everything after the ternary is synchronous on the arm that
            // did not. The `if` was given this a round ago and its expression form was not,
            // which is the half-a-rule these two keep trading.
            if suspends && sides.iter().any(|(_, o)| o.is_none()) {
                self.bypassed_after(e.span.end);
            }
        }
        // A short-circuit operator is the same decided branch in expression form. `0 && await 0`
        // never evaluates its right side, so the await in it suspends nothing and the statements
        // after it are as synchronous as they look — the pruning was written for `if` and left
        // out here, so the probe took an unreachable await as the cutoff and confined a write
        // the caller does see. `??` prunes on the same answer: a value this calls certainly
        // truthy is certainly not nullish.
        fn visit_logical_expression(&mut self, e: &oxc_ast::ast::LogicalExpression<'a>) {
            self.visit_expression(&e.left);
            let dead = match e.operator {
                oxc_syntax::operator::LogicalOperator::And => always_false(&e.left),
                oxc_syntax::operator::LogicalOperator::Or => always_true(&e.left),
                // `??` asks whether the left side is nullish, not whether it is falsy, and the
                // two part company at `0` — which is non-nullish, so `0 ?? await 0` never
                // reaches that await. Grouping it with `||` answered the narrower question.
                oxc_syntax::operator::LogicalOperator::Coalesce => never_nullish(&e.left),
            };
            if dead {
                return;
            }
            // The right side runs only when the left side allowed it, so an await inside it is
            // one some execution skips — and everything AFTER the operator is synchronous on
            // that path. Same rule as the `if` and the ternary, and the third place it had to
            // be written because each was reported after the previous one was closed.
            let bypassable = !logical_right_is_certain(e);
            if bypassable {
                let before = self.at;
                self.visit_expression(&e.right);
                if self.at != before {
                    self.bypassed_after(e.span.end);
                }
            } else {
                self.visit_expression(&e.right);
            }
        }
        // An `await` inside a nested function is that function's suspension, not this one's.
        fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
            self.nested += 1;
            walk::walk_function(self, f, flags);
            self.nested -= 1;
        }
        fn visit_arrow_function_expression(
            &mut self,
            f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.nested += 1;
            walk::walk_arrow_function_expression(self, f);
            self.nested -= 1;
        }
    }
    let mut probe = FirstAwait {
        at: None,
        nested: 0,
        unsuspended: Vec::new(),
        body_end: span.end,
        pending: Vec::new(),
        unavoidable: Vec::new(),
    };
    if let Some(body) = body {
        probe.visit_function_body(body);
    }
    // Each continuation runs until the next suspension EVERY surviving path reaches. Recording
    // it to the end of the body — which is how it was first written — treated a write past a
    // LATER unconditional await as synchronous, and that direction loses fields rather than
    // filing them under the wrong node, but it loses them all the same.
    let body_end = probe.body_end;
    let unavoidable = probe.unavoidable;
    let mut unsuspended = probe.unsuspended;
    unsuspended.extend(probe.pending.into_iter().filter_map(|start| {
        let end = unavoidable
            .iter()
            .copied()
            .filter(|h| *h > start)
            .min()
            .unwrap_or(body_end);
        (end > start).then(|| Span::new(start, end))
    }));
    let Some(cutoff) = probe.at else {
        return vec![span];
    };
    let mut regions = vec![Span::new(span.start, cutoff)];
    // A side that suspends nothing, but only past the cutoff — before it the first region
    // already covers the same ground.
    regions.extend(unsuspended.into_iter().filter(|r| r.end > cutoff));
    regions
}

/// Whether every path through `body` leaves by throwing, so it can produce no result at all.
///
/// A `switch` arm like `default: throw Error()` is not a path a successful parse can have
/// taken, so it has nothing to say about which fields such a parse read.
///
/// EVERY path, which is why this walks in order and stops rather than asking `any`. In
/// `{ if (flag) break; throw Error(); }` the throw is reachable but so is the break, and
/// calling that arm non-completing let `entry_paths_throw` promote a later case test the
/// breaking path never evaluates. Anything that can leave without throwing ends the question
/// where it stands.
fn throws_out(body: &[Statement<'_>]) -> bool {
    for st in body {
        let throws = match st {
            Statement::ThrowStatement(_) => true,
            Statement::BlockStatement(b) => throws_out(&b.body),
            // Both ways out are still out: `if (flag) throw A(); else throw B();` produces no
            // result on any path it can take. Matching only the bare and braced forms let a
            // handler spelled this way count as a path that yields something, so it diluted the
            // intersection with an empty side — `exits_unconditionally` already reads a
            // two-sided `if` this way and this did not.
            Statement::IfStatement(i) => i.alternate.as_ref().is_some_and(|alt| {
                throws_out(std::slice::from_ref(&i.consequent))
                    && throws_out(std::slice::from_ref(alt))
            }),
            Statement::LabeledStatement(l) => throws_out(std::slice::from_ref(&l.body)),
            // A `try` can be non-completing too, and asking only about bare throws called this
            // handler a path that yields something. `try { throw } finally { … }` throws: the
            // finalizer runs and the error carries on. With a handler it throws only if BOTH
            // sides do — a `catch` that returns swallows it — unless the finalizer itself
            // throws, which overrides whatever the block and handler did.
            Statement::TryStatement(t) => {
                // A block that neither completes nor raises reaches neither the handler nor
                // the finalizer. Reading the hang as a throw handed the question to a handler
                // that completes, and `try { for (;;); } catch (_) {}` became a path that
                // yields something.
                if hangs_forever(&t.block.body) {
                    return true;
                }
                let block = throws_out(&t.block.body);
                let body = match &t.handler {
                    Some(h) => block && throws_out(&h.body.body),
                    None => block,
                };
                // A `finally` that completes abruptly wins over however the block and handler
                // left: `finally { return fallback; }` hands back a result whatever was thrown,
                // so the whole `try` is a value path. Only its throwing case was considered.
                //
                !fin_leaves_with_a_value(t)
                    && (body || t.finalizer.as_ref().is_some_and(|f| throws_out(&f.body)))
            }
            // A loop whose first pass is guaranteed and whose body throws never comes round
            // again: `while (!0) { throw Error(); }` is the minifier's spelling of an
            // unconditional raise, and reading it as a path that yields something left a write
            // before it live and both branches of an enclosing `if` in the intersection. The
            // body's own answer decides, so a `break` anywhere in it still makes the loop
            // completable — `throws_out` stops at the first statement control can leave by.
            Statement::WhileStatement(w) if always_true(&w.test) => {
                !leaves_the_loop_with_a_value(&w.body)
            }
            Statement::ForStatement(f) if f.test.as_ref().is_none_or(always_true) => {
                !leaves_the_loop_with_a_value(&f.body)
            }
            // A `do` runs its body before any test, so a throwing body throws whatever the test
            // says — but a body nothing can leave diverges only when the test cannot end the
            // loop either. `do { continue; } while (c)` comes round again and then stops.
            Statement::DoWhileStatement(d) => {
                throws_out(std::slice::from_ref(&d.body))
                    || (always_true(&d.test) && !leaves_the_loop_with_a_value(&d.body))
            }
            // And a `switch` every arm of which throws, with a `default` so no value escapes
            // by matching nothing. The same `entry_paths_throw` the visitor uses.
            Statement::SwitchStatement(sw) => {
                sw.cases.iter().any(|c| c.test.is_none())
                    && entry_paths_throw(&sw.cases).iter().all(|t| *t)
            }
            _ => false,
        };
        if throws {
            return true;
        }
        if contains_exit(st) {
            return false;
        }
    }
    false
}

/// For each case, whether an EARLIER case tests the same literal, so nothing can enter here
/// directly: a switch matches with strict equality and takes the first case that matches.
///
/// `case "a": parse(e); break; case "a": break;` can only ever run the first, so the empty
/// second one is not an entry path — folding it into the intersection left the payload optional
/// against a switch every reachable entry of which reads it. Reached by FALLTHROUGH it still
/// runs, and that is already carried by the entry before it.
fn shadowed_case_tests(cases: &oxc_allocator::Vec<'_, oxc_ast::ast::SwitchCase<'_>>) -> Vec<bool> {
    let mut seen: Vec<String> = Vec::new();
    cases
        .iter()
        .map(|c| {
            let Some(key) = c.test.as_ref().and_then(literal_case_key) else {
                return false;
            };
            let seen_before = seen.contains(&key);
            seen.push(key);
            seen_before
        })
        .collect()
}

/// The value a case test names, when reading it settles the question. Only the literal forms:
/// anything computed — including a negated literal or a member lookup, which is what 4831 of
/// this corpus's case tests are — is left unkeyed rather than guessed at, and an unkeyed test
/// shadows nothing.
fn literal_case_key(e: &Expression<'_>) -> Option<String> {
    match e {
        Expression::StringLiteral(l) => Some(format!("s{}", l.value)),
        Expression::NumericLiteral(l) => Some(format!("n{}", l.value)),
        Expression::BooleanLiteral(l) => Some(format!("b{}", l.value)),
        Expression::NullLiteral(_) => Some("null".to_string()),
        _ => None,
    }
}

/// For each case, whether ENTERING there leaves the switch by throwing on every path — its
/// own consequent throws, or it falls through into a chain that does.
///
/// Which is what says whether a later case's test can be skipped by anything that still
/// produces a value: a case that throws is not one of those paths.
fn entry_paths_throw(cases: &oxc_allocator::Vec<'_, oxc_ast::ast::SwitchCase<'_>>) -> Vec<bool> {
    let mut out = vec![false; cases.len()];
    for i in (0..cases.len()).rev() {
        let body = &cases[i].consequent;
        out[i] =
            throws_out(body) || (!leaves_switch(body, false) && i + 1 < cases.len() && out[i + 1]);
    }
    out
}

/// Whether an arm can end the switch rather than falling into the next one. Both passes over
/// the cases ask this, and asking it twice in two spellings is how the fallthrough model
/// drifts.
///
/// CAN, not must: what the next arm establishes is only guaranteed for an entry path that
/// certainly reaches it, so `case "a": if (flag) break;` must not borrow the default's reads
/// either. And matching only a top-level `BreakStatement` missed `case "a": { break; }`,
/// which leaves exactly as the bare form does — `contains_exit_where` already answers both,
/// including attributing an unlabelled `break` to a nested loop or switch rather than to
/// this one.
///
/// `throwing_counts` picks WHICH ending is being asked about, because the two callers want
/// different ones and giving them one answer was wrong for one of them:
///
/// - Folding what an entry path READS asks about endings that hand something back. `case "a": if
///   (bad) throw Error(); default: parse(e);` reaches `parse` on every execution that returns
///   anything, because the only path skipping the fallthrough throws — counting that throw as an
///   ending left the payload optional and its guards unpublished.
/// - Deciding whether an arm's declaration can shadow a LATER arm's asks about endings of any
///   kind: a throw never reaches the next arm either.
fn leaves_switch(body: &[Statement<'_>], throwing_counts: bool) -> bool {
    body.iter()
        .any(|st| contains_exit_where(st, throwing_counts, true))
}

/// Whether `stmt` transfers control out of the statement list it sits in, so nothing after it in
/// that list runs.
///
/// Deliberately NOT [`exits_unconditionally`], which answers a different question for the dispatch
/// chain: there an unlabelled `break` leaves only the nearest loop or switch and says nothing about
/// the arms after it, so it does not count. Here the list IS that loop's or switch's body, and an
/// unlabelled `break` or `continue` ends it — `do { break; current = other; } while (0)` can never
/// run that assignment, and recording it as effective refused a descent for a node nothing had
/// moved. Reusing the dispatch predicate covered `return` and `throw` and left both transfers out.
fn ends_the_statement_list(stmt: &Statement<'_>) -> bool {
    ends_the_list_but_for(stmt, &mut Vec::new(), true)
}

/// Whether a loop with this body can start another pass at all.
///
/// `do { parse(current); current = other; break; } while (flag)` cannot: the `break` is reached
/// on every path, so no next iteration sees that write and `parse` is handed the original node
/// every time. Treating the write as loop-carried anyway refused a valid alias and dropped the
/// helper's fields. A `continue` is the one transfer that does start another pass, which is why
/// it does not count as leaving here.
fn can_come_round_again(body: &Statement<'_>) -> bool {
    !ends_the_list_but_for(body, &mut Vec::new(), false)
}

/// The same question, carrying the labels declared INSIDE the statement being asked about.
///
/// `local: { break local; }` lands at the end of its own labelled block and the list carries on:
/// counting it as an exit marked the next statement unreachable, gave the write in it no effective
/// position at all, and the descent was refused for a node that really had been moved. A `break`
/// naming a label from OUTSIDE does leave, which is the whole reason the two cannot be told apart
/// without carrying the set. [`contains_exit_where`] has scoped its labels this way since the
/// round that fixed the dispatch chain; this predicate was written after it and did not.
fn ends_the_list_but_for(
    stmt: &Statement<'_>,
    inside: &mut Vec<String>,
    continue_counts: bool,
) -> bool {
    match stmt {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        // A labelled transfer to a label opened within this statement is consumed by it.
        Statement::BreakStatement(b) => b
            .label
            .as_ref()
            .is_none_or(|l| !inside.iter().any(|k| k == l.name.as_str())),
        // `continue` ends the list it sits in, but it does not leave the LOOP — it starts the
        // next pass. Which of those two questions is being asked is the flag.
        Statement::ContinueStatement(c) => {
            continue_counts
                && c.label
                    .as_ref()
                    .is_none_or(|l| !inside.iter().any(|k| k == l.name.as_str()))
        }
        Statement::BlockStatement(b) => b
            .body
            .iter()
            .any(|st| ends_the_list_but_for(st, inside, continue_counts)),
        Statement::LabeledStatement(l) => {
            inside.push(l.label.name.as_str().to_string());
            let ends = ends_the_list_but_for(&l.body, inside, continue_counts);
            inside.pop();
            ends
        }
        // Both sides, or neither: a one-sided `if` falls through and the rest of the list runs.
        Statement::IfStatement(i) => i.alternate.as_ref().is_some_and(|alt| {
            ends_the_list_but_for(&i.consequent, inside, continue_counts)
                && ends_the_list_but_for(alt, inside, continue_counts)
        }),
        // A `try` hands on however its parts left: `try { break; } finally {}` breaks, and the
        // statement after it never runs. Falling into the catch-all recorded a write there as
        // effective and refused a descent for a node the parser had not reached — the same
        // propagation `throws_out` does for the value question, on the reachability one.
        Statement::TryStatement(t) => {
            let ends = |body: &oxc_allocator::Vec<'_, Statement<'_>>, inside: &mut Vec<String>| {
                body.iter()
                    .any(|st| ends_the_list_but_for(st, inside, continue_counts))
            };
            // A finalizer that leaves of its own overrides whatever the block and handler did,
            // the way its `return` overrides a pending throw.
            if t.finalizer.as_ref().is_some_and(|f| ends(&f.body, inside)) {
                return true;
            }
            let block = ends(&t.block.body, inside);
            match &t.handler {
                // With a handler, the block's exit is not the only outcome — a `catch` that
                // completes normally carries on into the statements after the `try`.
                //
                // Unless the block leaves by something a handler cannot intercept. A `catch`
                // takes exceptions and nothing else, so `try { break; } catch (_) {}` breaks
                // and the handler is never entered — demanding that the handler leave too
                // called that reachable and refused the descent. I had asserted the opposite
                // in this file one round ago; the test that said so is corrected below.
                Some(h) => {
                    leaves_without_raising(&t.block.body, inside, continue_counts)
                        || (block && ends(&h.body.body, inside))
                }
                None => block,
            }
        }
        // A loop or a switch CONSUMES an unlabelled transfer, so one inside it says nothing about
        // the list this statement sits in.
        _ => false,
    }
}

/// The two phases a class definition runs in, as the spans that make each of them up: every
/// computed key is evaluated before any static initializer or static block, whatever their
/// source order. Carried together because each half is only correct beside the other — saying
/// that an initializer follows the keys, and not that a key precedes the initializers, is a
/// rule shipped one direction at a time.
#[derive(Clone, Copy)]
struct ClassPhases<'s> {
    keys: &'s [Span],
    statics: &'s [Span],
    /// Where the static phase stops, when a static block before this element throws: nothing
    /// static written past that point is evaluated at all.
    static_phase_ends: Option<u32>,
    /// A derived constructor's prefix up to and including its `super()` call. Its INSTANCE
    /// fields initialize only once that call returns, so a read anywhere in here precedes
    /// every one of them.
    pre_super: Option<Span>,
}

/// Whether this call is a `.apply` whose argument list cannot be one: `Function.prototype.apply`
/// takes `null`, `undefined` or an object, and throws a `TypeError` on anything else before the
/// receiver's body is entered.
///
/// Only a spelling that settles it. An identifier, a call, anything this cannot read is left
/// alone — claiming a throw where none happens would confine a write the caller does see.
fn apply_list_throws(callee_expr: &Expression<'_>, arguments: &[Argument<'_>]) -> bool {
    let Some((name, _)) = named_member(peel(callee_expr)) else {
        return false;
    };
    if name != "apply" {
        return false;
    }
    let Some(list) = arguments.get(1).and_then(Argument::as_expression) else {
        return false;
    };
    match peel(list) {
        // `null` and `void 0` are the two spellings that mean "no arguments".
        Expression::NullLiteral(_) => false,
        Expression::UnaryExpression(u) => u.operator != oxc_syntax::operator::UnaryOperator::Void,
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_) => true,
        _ => false,
    }
}

/// Whether `new` can call this callee at all. A class and a plain function can be constructed;
/// an arrow, an async function and a generator cannot, and `new` on one throws before its
/// parameters or body are evaluated.
fn is_constructible(callee: &Expression<'_>) -> bool {
    match callee {
        Expression::ClassExpression(_) => true,
        Expression::FunctionExpression(f) => !f.generator && !f.r#async,
        _ => false,
    }
}

/// Whether a class with this heritage throws the moment it is DEFINED.
///
/// `class C extends (() => {})` evaluates the arrow and then rejects it: a heritage has to be
/// `null` or a constructor, and an arrow, an async function and a generator are none of them —
/// nor is any primitive or a plain object. The class body never runs, so a static initializer
/// in it writes nothing.
///
/// Only a spelling that settles it. An identifier is left alone, because claiming a throw where
/// none happens confines a write the caller does see.
fn heritage_throws(super_class: &Expression<'_>) -> bool {
    match peel(super_class) {
        // `extends null` is legal and makes a base-like class with no prototype parent.
        Expression::NullLiteral(_) => false,
        Expression::ClassExpression(_) => false,
        Expression::FunctionExpression(f) => f.generator || f.r#async,
        Expression::ArrowFunctionExpression(_)
        | Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_) => true,
        _ => false,
    }
}

/// Whether constructing this class runs its instance field initializers at all.
///
/// A DERIVED class installs them the moment `super()` returns, so a constructor that leaves
/// before calling it never runs a single one — `constructor(){ return {}; }` is legal in a
/// derived class and completes construction with the returned object. A base class installs
/// them before its constructor body, so leaving early there changes nothing, and an implicit
/// constructor is `constructor(...a){ super(...a) }`, which always calls it.
///
/// Only a `super()` this can find declines nothing: seeing one anywhere on the way keeps
/// today's answer, and the fields are treated as skipped only when an unconditional exit is
/// reached with none seen. Guessing the other way suppresses a write that really happens.
fn instance_fields_initialize(class: &oxc_ast::ast::Class<'_>) -> bool {
    let Some(heritage) = class.super_class.as_ref() else {
        return true;
    };
    // `extends null` is a legal class and an impossible construction: the derived constructor's
    // `super()` — implicit or written — calls `null`, which throws a `TypeError` before a single
    // field initializes. The one derived shape that survives it is a constructor returning an
    // object without calling `super()`, and that already answers `false` below. So a statically
    // null heritage settles the whole question here, and the implicit-constructor shortcut
    // underneath it — which reads a missing constructor as `super(...a)` and therefore as
    // successful — no longer runs for the one heritage where that call cannot return.
    if matches!(peel(heritage), Expression::NullLiteral(_)) {
        return false;
    }
    let ctor = class.body.body.iter().find_map(|el| match el {
        oxc_ast::ast::ClassElement::MethodDefinition(m)
            if m.kind == oxc_ast::ast::MethodDefinitionKind::Constructor =>
        {
            Some(m)
        }
        _ => None,
    });
    let Some(body) = ctor.and_then(|m| m.value.body.as_ref()) else {
        return true;
    };
    for st in &body.statements {
        if calls_super(st) {
            return true;
        }
        if ends_the_statement_list(st) {
            return false;
        }
    }
    // Reaching the end without one is the same answer as leaving before one: a derived
    // constructor that never calls `super()` throws a `ReferenceError` on return, so not a field
    // initializes. Answering `true` here read `constructor(){}` as ordinary construction and
    // recorded a write that happens on no path.
    false
}

/// Whether a statement can evaluate `super(...)` anywhere inside it — including in an arrow,
/// which inherits the constructor's own `super`.
fn calls_super(st: &Statement<'_>) -> bool {
    struct Seen(bool);
    impl<'a> Visit<'a> for Seen {
        fn visit_call_expression(&mut self, c: &CallExpression<'a>) {
            if matches!(c.callee, Expression::Super(_)) {
                self.0 = true;
            }
            walk::walk_call_expression(self, c);
        }
    }
    let mut seen = Seen(false);
    seen.visit_statement(st);
    seen.0
}

/// The spans of `callee` whose evaluation happens at CONSTRUCTION, so the arguments precede them.
///
/// For a function it is the whole callee: everything in the body runs after the arguments. For
/// `new (class { … })()` it is not — the class is DEFINED first, so its heritage, computed keys,
/// static initializers and static blocks all run before the arguments are evaluated, and only the
/// constructor body and the instance field initializers come after. Naming the whole class span
/// had `new (class { static x = parse(current); })(current = other)` read the static initializer
/// as seeing a write it precedes, and the helper's fields were lost from a shape that has them.
fn construction_regions(callee: &Expression<'_>, constructs: bool) -> Vec<Span> {
    let Expression::ClassExpression(c) = callee else {
        return vec![callee.span()];
    };
    if !constructs {
        return vec![callee.span()];
    }
    let mut out = Vec::new();
    for el in &c.body.body {
        match el {
            oxc_ast::ast::ClassElement::MethodDefinition(m)
                if m.kind == oxc_ast::ast::MethodDefinitionKind::Constructor =>
            {
                out.push(m.value.span);
            }
            oxc_ast::ast::ClassElement::PropertyDefinition(p) if !p.r#static => {
                out.extend(p.value.as_ref().map(GetSpan::span));
            }
            oxc_ast::ast::ClassElement::AccessorProperty(p) if !p.r#static => {
                out.extend(p.value.as_ref().map(GetSpan::span));
            }
            _ => {}
        }
    }
    out
}

/// The parameter defaults this invocation's own arguments prevent from running.
///
/// A default is evaluated only when its argument is missing or `undefined`, so a call that
/// supplies a value at that position never runs it. Reading a literal `1` as "definitely not
/// undefined" is the whole judgement: anything whose value has to be computed could be
/// `undefined`, and claiming otherwise would drop a write that really happens — which is the
/// direction that files a helper's fields under a node the parser has already replaced.
///
/// A spread argument makes every position after it unknowable, so it ends the mapping.
///
/// `implicit_leading` counts positions the call supplies with a value that has no expression to
/// read and cannot be `undefined` — a tagged template's strings object. Their parameters' own
/// defaults are prevented exactly as a written argument prevents one, and the pattern they bind
/// is taken apart from a value this cannot read, so nothing nested is claimed.
fn suppressed_defaults(
    callee: &Expression<'_>,
    arguments: &[Option<&Expression<'_>>],
    implicit_leading: usize,
    constructs: bool,
) -> Vec<Span> {
    // `new (class { constructor(x = (current = other)) {} })(1)` passes its arguments to that
    // constructor exactly as a call passes them to a function, so the same defaults are
    // prevented — which is why `callee_params` answers for the class shape too, and why the
    // getter walk beside it reads the very same list rather than a second copy of this match.
    let Some(params) = callee_params(callee, constructs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, param) in params.items.iter().enumerate() {
        // A position supplied without an expression: the default is prevented and the pattern
        // takes apart a value this cannot read, so the walk below has nothing to add.
        if i < implicit_leading {
            if let Some(init) = param.initializer.as_ref() {
                out.push(init.span());
            }
            continue;
        }
        // Past the end of what the call supplies: every remaining default runs.
        let Some(slot) = arguments.get(i - implicit_leading).copied() else {
            break;
        };
        // An array ELISION in an `.apply` list — `f.apply(null, [, 1])` — is a position that
        // certainly holds `undefined`. It supplies nothing, so this parameter's default runs;
        // but the positions after it have NOT moved, so the mapping goes on. Ending it here
        // dropped the `1` that really does reach the next parameter, and its default was
        // recorded as a write the call prevents. A spread is the other answer and never
        // reaches this loop: `mapped` stops the list at one.
        let Some(supplied) = slot else {
            continue;
        };
        // The parameter's OWN default, then whatever the pattern it binds destructures. When
        // the default runs, the pattern takes the default's value apart, not the argument's —
        // so the recursion carries `None` on that side rather than the argument.
        let reached = match param.initializer.as_ref() {
            Some(init) if definitely_defined(supplied) => {
                out.push(init.span());
                Some(supplied)
            }
            // Indistinguishable from carrying `supplied` through, as it happens: any value the
            // pattern walk can read off the source is one `definitely_defined` accepts, so this
            // arm is only reached with an argument that suppresses nothing anyway. Kept as
            // `None` because it states the rule — when the default runs, the pattern takes THAT
            // apart — rather than relying on the coincidence. No test separates the two, and
            // saying so is better than implying one does.
            Some(_) => None,
            None => Some(supplied),
        };
        suppress_in_pattern(&param.pattern, reached, &mut out);
    }
    out
}

/// The getter bodies that BINDING these parameters will invoke.
///
/// `(function ({x}) {})({ get x() { current = other; return 1; } })` runs that getter while the
/// parameters are bound — before the body is entered and before anything after the call reads
/// what it wrote. `suppress_in_pattern` already knows the getter's RESULT is unreadable and
/// leaves the default running, which is right; nothing knew its BODY runs at all, so a write
/// inside it stayed confined to a function nobody was known to call.
///
/// Deliberately shallow: a property named at the top level of a parameter's own object pattern,
/// over a literal object argument, taking the LAST property of that name — the same reading the
/// suppression lookup takes, for the same reason. A nested pattern, a computed key or a spread
/// leaves the getter unclaimed, which loses a write rather than inventing one.
///
/// `implicit_leading` is as in [`suppressed_defaults`]: a position supplied by a value with no
/// expression to read holds no getter this can name, and it is not the parameter's default that
/// the binding takes apart either.
fn bound_getters<'b, 'a>(
    callee: &'b Expression<'a>,
    arguments: &[Option<&'b Expression<'a>>],
    implicit_leading: usize,
    constructs: bool,
) -> Vec<Span> {
    let Some(params) = callee_params(callee, constructs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, param) in params.items.iter().enumerate() {
        let oxc_ast::ast::BindingPattern::ObjectPattern(pat) = &param.pattern else {
            continue;
        };
        if i < implicit_leading {
            continue;
        }
        let supplied_arg = arguments.get(i - implicit_leading).copied().flatten();
        // What the pattern actually takes apart. The argument when the call supplies one — and
        // the parameter's OWN default object when it does not, which is the object
        // `(function ({x} = { get x() { … } }) {})()` destructures and whose getter the binding
        // therefore invokes. Reading only the argument skipped that shape entirely.
        //
        // ONE of them: whichever object the binding actually takes apart. The default is taken
        // apart only when the argument does not supply the parameter, which is the very question
        // `suppressed_defaults` answers, with the same predicate.
        //
        // I removed that guard two rounds ago as inert, on the reasoning that a suppressed
        // initializer is never walked so the getter inside it is unreachable whatever this list
        // says. Unreachable, and not harmless: with BOTH objects listed, the lookup below found
        // the DEFAULT's getter first and stopped, so the supplied getter — the one that really
        // runs — was never claimed. The claim was wrong and no mutation of mine could show it,
        // because no test named the same property in both objects. It is the sixth claim of mine
        // review has had to reverse.
        let objects: Vec<&oxc_ast::ast::ObjectExpression<'a>> = match supplied_arg {
            Some(supplied) if definitely_defined(supplied) => match supplied {
                Expression::ObjectExpression(o) => vec![o],
                _ => Vec::new(),
            },
            _ => match param.initializer.as_deref() {
                Some(Expression::ObjectExpression(o)) => vec![o],
                _ => Vec::new(),
            },
        };
        for prop in &pat.properties {
            let Some(name) = prop.key.static_name() else {
                continue;
            };
            let getter = objects.iter().rev().find_map(|supplied| {
                supplied.properties.iter().rev().find_map(|p| match p {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(op)
                        if op.key.static_name().as_deref() == Some(name.as_ref()) =>
                    {
                        Some(op)
                    }
                    _ => None,
                })
            });
            if let Some(op) = getter
                && op.kind == oxc_ast::ast::PropertyKind::Get
                && let Expression::FunctionExpression(f) = &op.value
            {
                out.push(f.span);
            }
        }
    }
    out
}

/// The formals a call binds, for the callee shapes that have any.
fn callee_params<'b, 'a>(
    callee: &'b Expression<'a>,
    constructs: bool,
) -> Option<&'b oxc_ast::ast::FormalParameters<'a>> {
    match callee {
        Expression::FunctionExpression(f) => Some(&f.params),
        Expression::ArrowFunctionExpression(f) => Some(&f.params),
        Expression::ClassExpression(c) if constructs => {
            c.body.body.iter().find_map(|el| match el {
                oxc_ast::ast::ClassElement::MethodDefinition(m)
                    if m.kind == oxc_ast::ast::MethodDefinitionKind::Constructor =>
                {
                    Some(&*m.value.params)
                }
                _ => None,
            })
        }
        _ => None,
    }
}

/// The defaults inside `pat` that the value it destructures already supplies.
///
/// A default nested in a pattern is the same rule one level in: `function ({x = (current =
/// other)}) {}` called with `{x: 1}` never evaluates that initializer. Checking only
/// `FormalParameter::initializer` left every destructured spelling of it recording a write the
/// call prevents — the direction that files a helper's fields under a node still standing.
///
/// `value` is what this pattern takes apart, when reading the source settles what that is. It
/// is `None` wherever it does not — an argument that is not a literal object or array, a
/// property this call does not name, a spread, a computed key. Every one of those leaves the
/// default running, which is the conservative side.
fn suppress_in_pattern(
    pat: &oxc_ast::ast::BindingPattern<'_>,
    value: Option<&Expression<'_>>,
    out: &mut Vec<Span>,
) {
    use oxc_ast::ast::BindingPattern as BP;
    match pat {
        BP::BindingIdentifier(_) => {}
        BP::AssignmentPattern(p) => {
            let supplied = value.is_some_and(definitely_defined);
            if supplied {
                out.push(p.right.span());
            }
            // Bound to the argument when the default did not run, and to the default's own
            // value when it did — which this does not read, so the inner side gets nothing.
            suppress_in_pattern(&p.left, if supplied { value } else { None }, out);
        }
        BP::ObjectPattern(o) => {
            // Only a literal object — and only the properties written after every spread in
            // it. A spread can supply a name or shadow one, so nothing before or between them
            // settles anything; a property written after the LAST of them is the value the
            // object ends up with whatever the spreads held, so it settles the question exactly
            // as it would in an object with no spread at all. Discarding the whole literal the
            // moment one appeared threw those away too.
            let props: Option<&[oxc_ast::ast::ObjectPropertyKind<'_>]> = match value {
                Some(Expression::ObjectExpression(obj)) => {
                    let after_spreads = obj
                        .properties
                        .iter()
                        .rposition(|p| {
                            matches!(p, oxc_ast::ast::ObjectPropertyKind::SpreadProperty(_))
                        })
                        .map_or(0, |i| i + 1);
                    Some(&obj.properties[after_spreads..])
                }
                _ => None,
            };
            for prop in &o.properties {
                // `static_name` is the predicate, on both sides. Testing `!computed` as well
                // excluded `{["x"]: v}` — a computed key whose name IS readable — while adding
                // nothing, because `static_name` already answers `None` for a key that is not:
                // an inert gate that only cost precision. Removed rather than documented.
                let named = prop.key.static_name().and_then(|name| {
                    // The LAST property of that name, which is the one the object ends up with.
                    // Taking the first had `{x: 1, ["x"]: undefined}` read as supplying `x`,
                    // suppressing a default the effective `undefined` really does run.
                    // The last property of that name FIRST, then whether its text is the
                    // value. Deciding both in one `find_map` let a trailing getter fall
                    // through to an earlier plain property of the same name, which is the
                    // one the object does not end up with.
                    props?
                        .iter()
                        .rev()
                        .find_map(|p| match p {
                            oxc_ast::ast::ObjectPropertyKind::ObjectProperty(op)
                                if op.key.static_name().as_deref() == Some(name.as_ref()) =>
                            {
                                Some(op)
                            }
                            _ => None,
                        })
                        // `{get x(){ … }}` supplies `x` by INVOKING that function, whose result
                        // this cannot read — and `{set x(v){}}` supplies no getter at all, so
                        // reading `x` yields `undefined` and the default runs. The property's own
                        // text is the value only for a plain one; a shorthand METHOD is plain in
                        // that sense, its value being the function itself.
                        .and_then(|op| {
                            (op.kind == oxc_ast::ast::PropertyKind::Init).then_some(&op.value)
                        })
                });
                suppress_in_pattern(&prop.value, named, out);
            }
        }
        BP::ArrayPattern(a) => {
            // By position, and only for a literal array — up to its FIRST spread. A spread
            // contributes an unknown number of elements, so every position from there on
            // shifts by an amount nothing here can read; the positions BEFORE it are exactly
            // where they are written. Discarding the whole literal the moment one appeared
            // threw those away too. The mirror of the object rule, which keeps what comes
            // after the last spread because there names shift and positions do not.
            let items: Option<&[oxc_ast::ast::ArrayExpressionElement<'_>]> = match value {
                Some(Expression::ArrayExpression(arr)) => {
                    let until = arr
                        .elements
                        .iter()
                        .position(|el| {
                            matches!(el, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_))
                        })
                        .unwrap_or(arr.elements.len());
                    Some(&arr.elements[..until])
                }
                _ => None,
            };
            for (i, el) in a.elements.iter().enumerate() {
                let Some(el) = el.as_ref() else { continue };
                let at = items
                    .and_then(|arr| arr.get(i))
                    .and_then(|e| e.as_expression());
                suppress_in_pattern(el, at, out);
            }
        }
    }
}

/// Whether reading `e` settles that it is not `undefined`. Deliberately only the forms that
/// carry their value in the source — a call, a member lookup or a bare identifier can all be
/// `undefined` at run time, and this answers `false` for every one of them.
fn definitely_defined(e: &Expression<'_>) -> bool {
    // Parentheses change nothing about the value, and reading only the bare spelling called
    // `(-1)` unreadable.
    if let Expression::ParenthesizedExpression(p) = e {
        return definitely_defined(&p.expression);
    }
    // Every unary operator but one produces a value: `-1` and `+x` a number, `!0` a boolean,
    // `~x` a number, `typeof x` a string, `delete x` a boolean. `void` is the exception, and
    // it is the spelling minifiers use FOR `undefined` — so excluding the whole node kind
    // turned the minifier's own `-1` into a value this could not read.
    if let Expression::UnaryExpression(u) = e {
        return u.operator != oxc_syntax::operator::UnaryOperator::Void;
    }
    matches!(
        e,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::TemplateLiteral(_)
            | Expression::ObjectExpression(_)
            | Expression::ArrayExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::ClassExpression(_)
            | Expression::NewExpression(_)
    )
}

/// Whether `body` leaves its statement list by a transfer NO exception can be raised before,
/// so a `catch` wrapped around it is bypassed rather than entered.
///
/// `try { break; } catch (_) {}` breaks. `try { f(); break; } catch (_) {}` does not answer
/// yes, because `f()` can throw and the handler then completes normally — and this walk stops
/// at the first statement that could raise rather than looking past it. Everything is assumed
/// able to raise except the few forms that evaluate nothing, which is the same conservative
/// reading `is_quiet` makes for the hang question.
fn leaves_without_raising(
    body: &[Statement<'_>],
    inside: &mut Vec<String>,
    continue_counts: bool,
) -> bool {
    for st in body {
        match st {
            // The transfers themselves evaluate nothing. A bare `return` is one too; `return
            // expr` runs `expr`, which can raise, and falls to the catch-all below.
            Statement::BreakStatement(_) | Statement::ContinueStatement(_) => {
                return ends_the_list_but_for(st, inside, continue_counts);
            }
            Statement::ReturnStatement(r) if r.argument.is_none() => return true,
            Statement::BlockStatement(b) => {
                if leaves_without_raising(&b.body, inside, continue_counts) {
                    return true;
                }
                // A block that neither left nor is quiet could have raised inside it.
                if !is_quiet(st) {
                    return false;
                }
            }
            _ if is_quiet(st) => {}
            _ => return false,
        }
    }
    false
}

/// Whether `stmt` ends the body on every path it can take. A bare `return`/`throw`, or a
/// block that reaches one — `{ return result; }` runs exactly as the bare statement does,
/// and the arms after either of them are unreachable.
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
/// One assignment to a bare name: which function it sits in (`None` = the top of the
/// analysed source, so it covers all of it), what it writes, where, and the innermost loop
/// that repeats it.
#[derive(Debug, Clone)]
struct Write {
    scope: Option<Span>,
    name: String,
    at: Span,
    /// Where the write has taken effect by, which is not where the TARGET is written. `e =
    /// parse(e)` calls `parse` with the original node and only then rebinds `e`, so ordering
    /// the write from the target identifier reported it as already effective and the descent
    /// was refused — losing every field the helper reads and recording a drop that did not
    /// happen. `at` still identifies the write, so a `Given` recorded at the same target keeps
    /// pairing with it.
    effective: u32,
    repeats_in: Option<Span>,
    runs_before: Vec<Span>,
    runs_after: Vec<Span>,
    lands_at: Option<(Span, u32)>,
}

impl Write {
    /// Whether this write is in a scope reaching `at`.
    fn covers(&self, at: Span) -> bool {
        self.scope.is_none_or(|e| covers(e, at))
    }
}

/// Whether a record made at `effective` has already taken effect at `at`.
///
/// Three ways it can have: textual position, repetition — a write below the call runs before it
/// on the next pass — and a region the record precedes whatever its position, which is how a
/// call's arguments relate to its callee's body. The rule was spelled out at each of its five
/// askers, which is how the first two came to be asked in four places and the third in none.
fn in_effect_at(
    effective: u32,
    repeats_in: Option<Span>,
    runs_before: &[Span],
    runs_after: &[Span],
    lands_at: Option<(Span, u32)>,
    at: Span,
) -> bool {
    // A path that cannot produce a result never made this record effective for anything.
    if effective == u32::MAX {
        return false;
    }
    // A region this record FOLLOWS however early it is written — the mirror of `runs_before`,
    // and the thing the class two-phase note on the PR said this model had no place for. Every
    // computed key of a class is evaluated before any static initializer, so a read in a key
    // does not see a write in an initializer written above it. Position alone answered that
    // with the source order.
    if runs_after.iter().any(|r| covers(*r, at)) {
        return false;
    }
    // Written inside an invoked body: it happened where it is written for anything in that
    // same body, and at the call for everything else — which is what puts it after the
    // arguments, that being the whole reason the invocation is recorded at all.
    if let Some((body, call_end)) = lands_at {
        return if covers(body, at) {
            // Position, or a region this record declares it precedes — a class's instance field
            // initializers all run before its constructor body however they are written, and
            // both sit inside the one invoked body, so short-circuiting on position alone
            // answered that ordering with source order.
            effective <= at.start || runs_before.iter().any(|r| covers(*r, at))
        } else {
            call_end <= at.start
        };
    }
    effective <= at.start
        || repeats_in.is_some_and(|l| covers(l, at))
        || runs_before.iter().any(|r| covers(*r, at))
}

/// The names a statement list declares with `var`, at any depth inside it.
///
/// Function-scoped, so `case "a": { var t = e.child("inner"); }` rebinds `t` for everything
/// after it exactly as the unbraced form does — and reading only the top level of each
/// consequent missed it, so the arm-shadow diagnostic stayed silent about an ambiguity it
/// exists to report. Not into a nested function, whose own `var`s are its business.
fn hoisted_names<'a>(body: &[Statement<'a>]) -> Vec<String> {
    struct Hoisted {
        names: Vec<String>,
        nested: u32,
    }
    impl<'a> Visit<'a> for Hoisted {
        fn visit_variable_declaration(&mut self, d: &VariableDeclaration<'a>) {
            if self.nested == 0 && !d.kind.is_lexical() {
                for decl in &d.declarations {
                    for id in decl.id.get_binding_identifiers() {
                        self.names.push(id.name.as_str().to_string());
                    }
                }
            }
            walk::walk_variable_declaration(self, d);
        }
        fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
            self.nested += 1;
            walk::walk_function(self, f, flags);
            self.nested -= 1;
        }
        fn visit_arrow_function_expression(
            &mut self,
            f: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.nested += 1;
            walk::walk_arrow_function_expression(self, f);
            self.nested -= 1;
        }
    }
    let mut probe = Hoisted {
        names: Vec::new(),
        nested: 0,
    };
    for st in body {
        probe.visit_statement(st);
    }
    probe.names
}

/// Whether `outer` contains `inner`.
fn covers(outer: Span, inner: Span) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}

/// One value a name is GIVEN — a declarator initializer or an assignment.
#[derive(Debug, Clone)]
struct Given {
    scope: Span,
    /// Whether something could have skipped this assignment — see [`AllBindings::skippable`].
    conditional: bool,
    name: String,
    /// The name it was copied from, when the right-hand side was a bare identifier.
    from: Option<String>,
    at: Span,
    /// Where this value has taken effect by — see [`Write::effective`]. The same position for
    /// the same reason: an assignment's right-hand side runs before the name is rebound, and
    /// the two records of one assignment must not disagree about when it happened.
    effective: u32,
    repeats_in: Option<Span>,
    /// The invoked body this record sits in, with the end of its call — it happened where it
    /// is written for anything in that body, and at the call for everything outside it.
    lands_at: Option<(Span, u32)>,
    /// A region this record precedes however late it is written. Every argument of a call runs
    /// before the callee's body is entered, so `(function(){ parse(current); })(current = e)`
    /// hands `parse` what the ARGUMENT assigned — and the argument is textually after the body
    /// that reads it. Position alone had that read seeing the older value, and it filed the
    /// helper's fields under a node the parser had already replaced.
    ///
    /// A LIST, because the parts a record precedes are not always one span: the arguments of
    /// `new (class { … })()` run after the class is defined and before it is constructed, so
    /// they precede the constructor body and every instance field initializer while preceding
    /// no static one — three regions inside one class, of which a single span can name at most
    /// the wrong union.
    runs_before: Vec<Span>,
    runs_after: Vec<Span>,
}

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
    /// Loop bodies currently open, each with whether that loop can start another pass. A write
    /// inside one that cannot is not loop-carried, however far below the call it sits.
    loops: Vec<(Span, bool)>,
    /// How many blocks deep the walk is, so the outermost one can be told apart from a
    /// genuinely nested scope.
    block_depth: u32,
    /// Where the assignment currently being walked ends, so a write inside it can say it takes
    /// effect after the right-hand side rather than at the target.
    assign_end: Option<u32>,
    /// How many enclosing statements cannot be left with a result. A write in one of those
    /// never takes effect for anything a later call can observe.
    dead: u32,
    /// How many enclosing statements control cannot reach at all — everything after an
    /// unconditional `return`, `throw` or labelled `break` in the same list.
    ///
    /// Distinct from [`Self::dead`], and it outranks `caught`: a handler makes a THROWING path
    /// resume, so a write before the throw really did happen, but nothing makes a statement after
    /// the transfer run. `try { throw Error(); current = other; } catch (_) {}` recorded that
    /// assignment as effective and refused the descent for a node nothing had moved.
    unreachable: u32,
    /// The regions whose evaluation a record made here precedes, innermost last. A write in a
    /// call's arguments precedes everything in the callee's body, however far after it the
    /// argument is written — and for a constructed class the region is several spans, because
    /// the arguments precede the construction without preceding the definition.
    runs_before: Vec<Vec<Span>>,
    /// Regions a record made here FOLLOWS, whatever its position — see [`in_effect_at`].
    runs_after: Vec<Vec<Span>>,
    /// Invocations being walked, as `(the callee's span, the end of the call)`, outermost
    /// first. What the body writes lands at the call for anything OUTSIDE it — the arguments
    /// ran first and the statements after it run later — while inside that same body the write
    /// happened where it is written. Pinning it for every observer alike was the mistake:
    /// `(function(){ current = other; parse(current); })()` hands `parse` the new node, and
    /// reading the write as not-yet-effective there published the helper's fields on the old
    /// one.
    ///
    /// One of them so far: every argument of a call is evaluated before the callee's body is
    /// entered, so `(function(){ current = other; })(parse(current))` hands `parse` the original
    /// node. Ordering that write by its own span had it look already effective, and the descent
    /// was refused for a node still standing.
    effects_land_at: Vec<(Span, u32)>,
    /// Function bodies that are immediately invoked, each with the REGIONS of it that run
    /// synchronously with the call: a write inside one of those has certainly run by the time
    /// anything after the call reads it.
    ///
    /// Regions rather than one cutoff, because the two sides of an undecided `if` are
    /// alternatives: `if (flag) { await x; } else { current = other; }` suspends on one side and
    /// not on the other, and a single position across both confined a write that really is
    /// synchronous whenever its own side is selected.
    ///
    /// Not the whole body, because calling a function is not always running it. A generator
    /// call builds an iterator and runs nothing, and an `async` body runs only as far as its
    /// first `await` before handing control back — so `(async function(){ await x; current =
    /// other; })()` had a write the callback returns before recorded as one that already
    /// happened.
    iife: Vec<(Span, Vec<Span>)>,

    /// Getter bodies that the parameter binding of a call in progress will invoke, with the end
    /// of that call. Registered while the arguments are walked and applied only around the
    /// getter's OWN body, because binding happens after every argument has been evaluated: a
    /// blanket push would have deferred the arguments' own writes past the call too.
    binding_getters: Vec<(Span, u32)>,

    /// How many enclosing constructs could have skipped the part being walked. A value assigned
    /// down such a path is not certainly the one a later read sees, however textually early it
    /// is: `var current; if (flag) current = e; parse(current)` hands `parse` the element only
    /// when `flag` held.
    ///
    /// Per PART of a construct, not per construct: an `if` test, a loop header and a `switch`
    /// discriminant all run whatever happens, and calling those skippable would relax reads the
    /// parser always performs. A test no value can change is not a branch at all, and the side it
    /// selects runs always — the same `statically_selected` the requiredness walk reads, so the
    /// two cannot disagree about one `if`.
    ///
    /// What remains deliberately conservative is a loop body whose first pass is guaranteed: a
    /// `do`/`while`, a `for (;;)` or a `while (!0)` really does run the top of its body, but WHICH
    /// part of the body that covers is the whole `walk_guaranteed_pass` question, and answering it
    /// wrong here would call an uncertain value certain. Being wrong the other way only leaves a
    /// field optional.
    skippable: u32,
    /// How many enclosing `try` BLOCKS have a handler. A throw inside one of those does not end
    /// anything, so nothing under it is a dead path however it leaves.
    caught: u32,
    /// Whether the binding being collected reaches past its block: a parameter, a `var`,
    /// or a function declaration. `let`, `const`, a class and a `catch` parameter stop at
    /// the block — the same split `BoundNames` keeps, which this collector was missing.
    hoists: bool,
    /// Names ASSIGNED somewhere in the source: the function extent the write sits in, the
    /// name, the write's OWN span, and the innermost loop enclosing it if any. Being bound
    /// and still meaning what you were bound to are different questions, and only the first
    /// one was collected.
    writes: Vec<Write>,
    /// Every value a name is GIVEN — a declarator's initializer or an assignment — with the
    /// function extent it happens in, and the name it was copied from when the value was a
    /// bare identifier. `None` is any other right-hand side.
    ///
    /// Copies and overwrites have to be counted together, because `current = row` is both:
    /// it makes `current` an alias, and it is a write to `current`. Tracking the two
    /// separately had the aliasing assignment invalidate the alias it had just created.
    ///
    /// The extent matters and I claimed otherwise. A nested `function f() { var current =
    /// row; }` records into the same collection as the enclosing body, so an outer
    /// `parse(current)` followed it as though it had been handed `row` and filed the helper's
    /// fields under the wrong node. My attempt to disprove that used two sibling MAPPED
    /// callbacks, which are analysed over their own sources and never share a collection — a
    /// nested plain function does.
    given: Vec<Given>,
    /// Class expressions being constructed in place, by span. `new (class { constructor(){ … }
    /// })()` runs that constructor and every instance field initializer synchronously, which is
    /// the same decidable-from-syntax case an IIFE is — and the fallback treated both as a
    /// method body nobody calls, so a write there stayed confined and the helper's fields were
    /// published on the node the constructor had moved away from.
    constructing: Vec<Span>,
    /// Parameter defaults an immediate invocation's own arguments prevent from running.
    ///
    /// `(function(x = (current = other)){})(1)` never evaluates that initializer, because a
    /// default runs only for a missing or `undefined` argument. Walking the callee wholesale
    /// recorded the write anyway, so the node looked moved and the helper's fields were
    /// dropped from a shape the parser does read them in.
    suppressed_defaults: Vec<Span>,
}

impl AllBindings {
    /// Record that `name` was given a value, scoped to the extent the value can be read
    /// through. A top-level one covers the whole analysed source, the same split
    /// `names`/`scoped` keeps.
    ///
    /// `lexical` is for a `let`/`const` DECLARATOR, whose value dies with its block: after
    /// `{ let current = row; }` the name `current` at the call site is a different binding
    /// entirely, and giving the copy the whole function extent had `names_for` follow the
    /// expired one and file the helper's reads under `<row>`. `bind` already kept this split
    /// and this collector did not. An ASSIGNMENT is not this — `current = row` inside a block
    /// writes through whatever binding is in scope, which reaches as far as that binding
    /// does, so the function extent stays the conservative answer for it.
    fn given_value(&mut self, name: &str, from: Option<&str>, at: Span, lexical: bool) {
        let extent = if lexical {
            self.blocks
                .last()
                .copied()
                .or_else(|| self.fns.last().copied())
                .unwrap_or_else(|| Span::new(0, u32::MAX))
        } else {
            // An assignment reaches as far as the binding it targets, which is not the whole
            // function when something nearer shadows the name — `{ let current; current = row; }
            // parse(current)` copies into the block-local one, and treating it as function-wide
            // made `current` an alias of `row` at a call the block does not reach.
            self.binding_extent(name, at)
                .unwrap_or_else(|| Span::new(0, u32::MAX))
        };
        self.given.push(Given {
            scope: extent,
            conditional: self.skippable > 0,
            name: name.to_string(),
            from: from.map(|s| s.to_string()),
            at,
            effective: self.effect_position(at.end),
            runs_before: self.runs_before.last().cloned().unwrap_or_default(),
            runs_after: self.runs_after.last().cloned().unwrap_or_default(),
            lands_at: self.effects_land_at.first().copied(),
            repeats_in: self.innermost_repeating(),
        });
    }

    /// The extent of the binding `name` refers to at `at`: the tightest recorded scope for
    /// that name containing it, falling back to the enclosing function.
    ///
    /// A write and an assigned value both reach exactly as far as the binding they target, and
    /// recording them against the whole function ignored shadowing — in `{ let row; row = other;
    /// } parse(row)` the assignment touches only the block-local `row`, while the argument is
    /// the untouched callback parameter. Blamed on the parameter, the descent was discarded and
    /// a `reassignedNodeHandedOn` recorded for a node nothing had moved.
    ///
    /// A declaration's own `bind` runs before the walk reaches its initializer or any later
    /// assignment, so the entry is there to be found.
    fn binding_extent(&self, name: &str, at: Span) -> Option<Span> {
        if let Some(e) = self
            .scoped
            .iter()
            .filter(|(e, n)| n == name && covers(*e, at))
            .map(|(e, _)| *e)
            .min_by_key(|e| e.end - e.start)
        {
            return Some(e);
        }
        // A name bound at the TOP of the analysed source lives in `names`, not `scoped`, and it
        // reaches all of it — including out of a nested function that assigns to it. Falling
        // back to the innermost function gave `var current = e; (function(){ current =
        // e.child("detail"); })(); parse(current)` the IIFE's extent, so the write and the value
        // looked expired at the call and `names_for` followed the stale `current = e` alias to
        // the response root.
        if self.names.contains(name) {
            // It reaches all of the source — but only if it RUNS before the read. Inside an
            // immediately invoked function it does. Inside a function that may never be called
            // it may not, and `var current = e; function mutate(){ current = other; }
            // parse(current)` then refused a still-valid alias and lost the helper's fields
            // silently. Deciding that in general is call-graph work this scanner does not do; an
            // IIFE is the case syntax decides, so it is the only one that escapes. Narrowed from
            // "always escapes", which is what I shipped one commit earlier.
            // EVERY function on the chain, not just the innermost: an IIFE inside a function
            // nobody calls has not run either. `function unused(){ (function(){ current = other;
            // })(); } parse(current)` had the inner write escape to all of the source, so the
            // still-valid alias was refused and the helper's fields were lost silently — the same
            // rule the narrowing was written for, applied to one level of nesting instead of all
            // of them.
            let certainly_runs = self.fns.iter().all(|g| self.runs_before(*g, at));
            return match self.fns.last() {
                Some(f) if !certainly_runs => Some(*f),
                _ => None,
            };
        }
        self.fns.last().copied()
    }

    /// Whether `f` is immediately invoked AND the part of it that runs synchronously with the
    /// call reaches `at`. Everything after an `await` is the continuation's, which no later
    /// statement of the caller waits for.
    fn runs_before(&self, f: Span, at: Span) -> bool {
        self.iife
            .iter()
            .any(|(g, regions)| *g == f && regions.iter().any(|r| covers(*r, at)))
    }

    /// Where a record made here has taken effect by. An assignment's own end, so its
    /// right-hand side is ordered before it — and `u32::MAX` on a path that cannot produce a
    /// result, which no call site can be after.
    fn effect_position(&self, default_end: u32) -> u32 {
        // Unreachable first, because a handler cannot rescue it.
        if self.unreachable > 0 {
            return u32::MAX;
        }
        if self.dead > 0 && self.caught == 0 {
            return u32::MAX;
        }
        self.assign_end.unwrap_or(default_end)
    }

    /// The target and body of a `for-of`/`for-in`, walked as what they are: everything that
    /// FOLLOWS the one evaluation of the iterable.
    ///
    /// `for (current of (parse(current), []))` hands `parse` the node, because JavaScript
    /// evaluates the iterable before it ever assigns the target. Two things had said
    /// otherwise. The target's write is written above the iterable, so position alone called
    /// it effective there; and the write repeats with the loop, whose span covers the
    /// iterable textually, so even ordering it after would have been overruled by the
    /// next-pass rule. The iterable is evaluated ONCE and no pass returns to it, which is a
    /// region every write in here follows — the same mirror the class keys use, and the only
    /// spelling that answers both halves at once.
    fn after_the_iterable(&mut self, iterable: Span, f: impl FnOnce(&mut Self)) {
        let mut after = self.runs_after.last().cloned().unwrap_or_default();
        after.push(iterable);
        self.runs_after.push(after);
        f(self);
        self.runs_after.pop();
    }

    /// The innermost enclosing loop that can actually come round again — a write inside one
    /// that cannot is carried by whichever loop outside it can.
    fn innermost_repeating(&self) -> Option<Span> {
        self.loops
            .iter()
            .rev()
            .find(|(_, repeats)| *repeats)
            .map(|(span, _)| *span)
    }

    /// Walk an invocation whose callee is a function written in place, returning whether it
    /// did. Everything that body writes lands at the invocation, everything an argument writes
    /// precedes the body, and what a comma callee evaluates on the way precedes both.
    fn walk_invocation<'a>(
        &mut self,
        callee_expr: &Expression<'a>,
        arguments: &[oxc_ast::ast::Argument<'a>],
        template: Option<&oxc_ast::ast::TemplateLiteral<'a>>,
        span: Span,
        constructs: bool,
    ) -> bool {
        // An immediately invoked function has certainly run by the time anything after it reads
        // what it wrote — the one case where "does this nested function execute" is decidable
        // from the syntax alone.
        let callee = invoked_callee(callee_expr);
        // `f.apply(thisArg, 1)` throws a `TypeError` before `f` is entered: the argument list
        // has to be `null`, `undefined` or an object, and a non-null primitive is none of them.
        // Unwrapping `.apply` unconditionally marked the body immediate for a call that runs it
        // on no path at all.
        if apply_list_throws(callee_expr, arguments) {
            return false;
        }
        // `new (f).call(null)` constructs `Function.prototype.call`, which has no [[Construct]]
        // — a `TypeError` before `f` is ever reached. The callee unwrapper looks through
        // `.call`/`.apply` because an ordinary call there really does run the receiver's body;
        // under `new` the member itself is the target, so unwrapping it approved a body that
        // runs on no path. `.bind` is the other answer and keeps its unwrap: `new (f.bind(x))()`
        // constructs the bound function, which is constructible exactly when `f` is.
        if constructs
            && named_member(peel(callee_expr))
                .is_some_and(|(name, _)| matches!(name.as_ref(), "call" | "apply"))
        {
            return false;
        }
        // `new` needs a CONSTRUCTOR. An arrow, an async function and a generator are none of
        // them, so `new (() => { … })()` throws a TypeError with the body never entered — and
        // recording its writes published a helper's reads under a node nothing had moved. The
        // arguments are evaluated before the throw and still run, which declining here leaves
        // to the ordinary walk.
        if constructs && !is_constructible(callee) {
            return false;
        }
        let runs_now = match callee {
            // A generator call runs none of the BODY — it builds an iterator, and whether
            // anything ever draws from it is the call-graph question this scanner does not
            // answer. Its PARAMETERS are another matter: binding them is part of the call, so a
            // default runs before the iterator is handed back and the caller does see it.
            // Declining the whole callee confined that write with the body's.
            //
            // Exactly the same shape as `async`, which runs synchronously as far as its first
            // `await` — a synchronous region that is a prefix of the callee rather than all of
            // it, which is what this list is for.
            Expression::FunctionExpression(f) if f.generator => {
                self.iife.push((f.span, vec![f.params.span]));
                true
            }
            Expression::FunctionExpression(f) => {
                self.iife.push((
                    f.span,
                    synchronous_until(f.r#async, f.span, f.body.as_deref()),
                ));
                true
            }
            Expression::ArrowFunctionExpression(f) => {
                self.iife
                    .push((f.span, synchronous_until(f.r#async, f.span, Some(&f.body))));
                true
            }
            // `new (class { constructor(){ … } })()` runs user code now, exactly as an IIFE
            // does. Only under `new`: calling a class throws, so the body runs on no path.
            Expression::ClassExpression(c) if constructs => {
                self.constructing.push(c.span);
                true
            }
            _ => false,
        };
        if !runs_now {
            return false;
        }
        // Every argument is evaluated before the body is entered, so what the body writes takes
        // effect at the CALL. Ordering it by its position inside the callee had
        // `(function(){ current = other; })(parse(current))` record the write before the
        // argument that reads the node, and the descent was refused for a node still standing.
        //
        // Around the callee only: an argument that writes runs where it is written, and pinning
        // that to the call would order it after a body it precedes.
        self.effects_land_at.push((callee.span(), span.end));
        // A tagged template hands its tag the strings object and then the substitutions, so the
        // mapping is the substitutions shifted one place — and position 0 is supplied by a value
        // that is certainly not `undefined`, whatever the template says. Handing this an empty
        // list, which is what the round that taught it tagged templates did, read parameter 0 as
        // unsupplied and recorded a default the call always prevents.
        let (effective, implicit_leading) = match template {
            Some(q) => (
                q.expressions.iter().map(Some).collect::<Vec<_>>(),
                // The strings object, and only it: the substitutions follow it one for one.
                1,
            ),
            None => (effective_arguments(callee_expr, arguments), 0),
        };
        // Registered before the callee is walked, not only around the arguments: a getter the
        // binding invokes may live in the PARAMETER's own default object, which is inside the
        // callee. It is matched by span in `visit_function`, so widening the window reaches
        // nothing else.
        let restore_getters = self.binding_getters.len();
        self.binding_getters.extend(
            bound_getters(callee, &effective, implicit_leading, constructs)
                .into_iter()
                .map(|g| (g, span.end)),
        );
        let suppressed = suppressed_defaults(callee, &effective, implicit_leading, constructs);
        let restore = self.suppressed_defaults.len();
        self.suppressed_defaults.extend(suppressed);
        self.visit_expression(callee);
        self.suppressed_defaults.truncate(restore);
        self.effects_land_at.pop();
        // Whatever a callee evaluates on the way to that function runs before the arguments and
        // before the body — so it declares that it PRECEDES the body, exactly as the arguments
        // below do. Position alone answered this only while the shape was a comma expression,
        // whose leading elements are written above the function; a `bind` call's arguments are
        // written BELOW it, so `(function(){ parse(current); }).bind(null, current = other)()`
        // read the body against a write that had already run. Half a swap again: the round that
        // taught this reader the shape did not give it the ordering the shape needs.
        let mut leading = Vec::new();
        leading_parts(callee_expr, &mut leading);
        if !leading.is_empty() {
            self.runs_before
                .push(construction_regions(callee, constructs));
            for part in leading {
                self.visit_expression(part);
            }
            self.runs_before.pop();
        }
        // And the arguments run before that body, whatever their position relative to it:
        // `(function(){ parse(current); })(current = e)` reads what the argument assigned.
        // Only the callee's own span, so a read in another argument still orders normally
        // against this write — the arguments run in their own order.
        // A getter the parameter binding invokes runs as certainly as the body does — but AFTER
        // every argument has been evaluated, not where it is written. `(function ({x}, y) {})({
        // get x() { current = other; } }, parse(current))` hands `parse` the original node and
        // calls the getter afterwards; marking it immediate for the whole argument walk recorded
        // its write at the getter's own offset, above a later argument that precedes it. So the
        // registration is carried and applied around the getter's own body alone, where it also
        // declares that its effects land at the CALL.
        self.runs_before
            .push(construction_regions(callee, constructs));
        for arg in arguments {
            self.visit_argument(arg);
        }
        // A template's substitutions are arguments like any other: every one is evaluated before
        // the tag is called. Visiting the quasi AFTER this region closed ordered them by their
        // own position, which is below the tag — so `(function(){ parse(current); })`t${current =
        // other}`` read the body against a write that had in fact already run.
        if let Some(q) = template {
            self.visit_template_literal(q);
        }
        self.runs_before.pop();
        self.binding_getters.truncate(restore_getters);
        true
    }

    /// Walk the statements of one list, marking everything after an unconditional exit as
    /// unreachable. Nothing else models "the rest of this block does not run".
    ///
    /// `first_pass` adds the guaranteed-entry loop body's asymmetry: everything up to the first
    /// statement that could jump past what follows runs whatever happens, and only what comes
    /// after that could have been skipped. [`ParserAnalyzer::walk_guaranteed_pass`] is the
    /// requiredness side of the same rule; this collector called the whole body skippable, so
    /// `do { current = e; break; } while (0)` — the minifier's one-shot block — left `current`
    /// uncertain and the helper it was handed came out optional.
    fn walk_in_order<'a>(&mut self, body: &[Statement<'a>], first_pass: bool) {
        let mut past_the_exit = false;
        let mut past_a_jump = false;
        for st in body {
            if past_the_exit {
                self.unreachable += 1;
                self.visit_statement(st);
                self.unreachable -= 1;
            } else if past_a_jump {
                self.maybe_skipped(|s| s.visit_statement(st));
            } else {
                self.visit_statement(st);
            }
            past_the_exit = past_the_exit || ends_the_statement_list(st);
            // Only an exit that hands back a RESULT, the same cut the requiredness side makes:
            // no execution that produced one continued past a `throw`, so what follows one is
            // not a write some successful path skipped.
            past_a_jump = past_a_jump || (first_pass && exits_with_a_value(st));
        }
    }

    /// The parts of a class field the class evaluates when it is DEFINED: a computed key
    /// always, an initializer only when it is `static`. An instance initializer runs per `new`,
    /// of which there may be none.
    fn visit_field_at_definition<'a>(
        &mut self,
        computed: bool,
        is_static: bool,
        key: &oxc_ast::ast::PropertyKey<'a>,
        value: Option<&Expression<'a>>,
        constructed: bool,
        phases: ClassPhases<'_>,
    ) {
        let (keys, statics) = (phases.keys, phases.statics);
        // The key first, and OUTSIDE the declaration below: keys run in their own source order
        // among themselves, and only the initializers follow all of them. What a key writes
        // does precede every one of those initializers, whichever way round they are written.
        if computed {
            let declared = !statics.is_empty();
            if declared {
                self.runs_before.push(statics.to_vec());
            }
            self.visit_property_key(key);
            if declared {
                self.runs_before.pop();
            }
        }
        // A static initializer runs when the class is defined. An INSTANCE one runs per `new`,
        // of which there may be none — unless this very class is being constructed in place,
        // where there is exactly one and it happens now.
        // A static element written past a static block that throws is never evaluated: class
        // definition stops at the abrupt completion, so the class binding is never created and
        // nothing below it in the second phase runs. Walking them all recorded a write that
        // happens on no path, which publishes a helper's reads under a node nothing had moved.
        // Its computed KEY still runs — every key is evaluated in the first phase, before any
        // initializer or block — which is why this gates the value alone.
        let skipped = is_static
            && phases
                .static_phase_ends
                .is_some_and(|end| key.span().start >= end);
        if skipped {
            self.unreachable += 1;
        }
        if (is_static || constructed)
            && let Some(v) = value
        {
            let mut after = keys.to_vec();
            // A STATIC initializer runs when the class is defined, long before any constructor;
            // only an instance one waits for `super()`.
            if !is_static && let Some(pre) = phases.pre_super {
                after.push(pre);
            }
            let declared = !after.is_empty();
            if declared {
                self.runs_after.push(after);
            }
            self.visit_expression(v);
            if declared {
                self.runs_after.pop();
            }
        }
        if skipped {
            self.unreachable -= 1;
        }
    }

    /// A loop body whose first pass is guaranteed, walked with that asymmetry — and with the
    /// scope its braces open, which is why it cannot simply hand the list to `walk_in_order`.
    fn walk_first_pass<'a>(&mut self, body: &Statement<'a>) {
        let Statement::BlockStatement(b) = body else {
            // Nothing precedes a single statement, so the guaranteed pass reaches it.
            self.visit_statement(body);
            return;
        };
        self.block_depth += 1;
        self.blocks.push(b.span);
        self.walk_in_order(&b.body, true);
        self.blocks.pop();
        self.block_depth -= 1;
    }

    /// Walk a part of a statement that control can reach past — the requiredness side's
    /// `in_skipped_path`, on the binding side and for the same reason.
    fn maybe_skipped(&mut self, f: impl FnOnce(&mut Self)) {
        self.skippable += 1;
        f(self);
        self.skippable -= 1;
    }

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

    /// The same for a default nested inside a destructuring pattern, which is a real
    /// `AssignmentPattern` node — a formal parameter's own default is not, and reaching only
    /// that one left `function ({x = …})` recording a write its call prevents.
    fn visit_assignment_pattern(&mut self, pat: &oxc_ast::ast::AssignmentPattern<'a>) {
        if !self.suppressed_defaults.contains(&pat.right.span()) {
            walk::walk_assignment_pattern(self, pat);
            return;
        }
        self.visit_binding_pattern(&pat.left);
        self.unreachable += 1;
        self.visit_expression(&pat.right);
        self.unreachable -= 1;
    }

    /// A parameter default whose argument was supplied never runs, so the name it binds is
    /// still bound and whatever the initializer would have written is not.
    fn visit_formal_parameter(&mut self, param: &oxc_ast::ast::FormalParameter<'a>) {
        let Some(init) = param.initializer.as_ref() else {
            walk::walk_formal_parameter(self, param);
            return;
        };
        if !self.suppressed_defaults.contains(&init.span()) {
            walk::walk_formal_parameter(self, param);
            return;
        }
        self.visit_binding_pattern(&param.pattern);
        self.unreachable += 1;
        self.visit_expression(init);
        self.unreachable -= 1;
    }

    fn visit_simple_assignment_target(
        &mut self,
        target: &oxc_ast::ast::SimpleAssignmentTarget<'a>,
    ) {
        // `row = row.child("detail")` and `row++` alike: after either, the name no longer
        // stands for what it was bound to.
        if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = target {
            let w = Write {
                scope: self.binding_extent(id.name.as_str(), id.span),
                name: id.name.as_str().to_string(),
                at: id.span,
                effective: self.effect_position(id.span.end),
                runs_before: self.runs_before.last().cloned().unwrap_or_default(),
                runs_after: self.runs_after.last().cloned().unwrap_or_default(),
                lands_at: self.effects_land_at.first().copied(),
                // A loop whose body throws does not come round again, so a dead write must not
                // claim repetition either — that is the other half of `effective`.
                repeats_in: (self.dead == 0 || self.caught > 0)
                    .then(|| self.innermost_repeating())
                    .flatten(),
            };
            self.writes.push(w);
        }
        walk::walk_simple_assignment_target(self, target);
    }

    fn visit_assignment_expression(&mut self, e: &oxc_ast::ast::AssignmentExpression<'a>) {
        // The target is written only once the right-hand side has been evaluated, so BOTH
        // records of this assignment — the value and the write — take effect at its end.
        // `e = parse(e)` hands `parse` the original node; ordering either record from the
        // target had it look already effective, and the descent was refused with a drop
        // recorded for a node nothing had moved yet. Set before the value is recorded, not
        // just around the walk that records the write: having it cover one and not the other
        // is how the two halves of one assignment came to disagree.
        let outer = self.assign_end.replace(e.span.end);
        // `current = row` makes an alias as much as `var current = row` does; recording only
        // the declarator form left the plain one matching no argument position and losing the
        // helper with nothing said. The accumulator search in this file already reads both,
        // so taking only one here was a narrowing rather than a decision.
        if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(t) = &e.left {
            let from = match (&e.right, e.operator) {
                (Expression::Identifier(src), oxc_syntax::operator::AssignmentOperator::Assign) => {
                    Some(src.name.as_str())
                }
                // `+=` and friends compute from the old value, so the name is not a copy.
                _ => None,
            };
            self.given_value(t.name.as_str(), from, t.span, false);
        }
        walk::walk_assignment_expression(self, e);
        self.assign_end = outer;
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        let outer_hoists = self.hoists;
        self.hoists = !decl.kind.is_lexical();
        for d in &decl.declarations {
            // The binding first, THEN its value. `binding_extent` reads the recorded scopes to
            // decide how far a value reaches, and a declaration's own scope is the one it must
            // find — recording first left the lookup to whatever else answered to that name,
            // so `var current = e; var current = current.child("detail")` scoped the second
            // value by the first and the child it names was never filed. The doc comment on
            // `binding_extent` claimed this order already held; it held for a later assignment
            // and never for the declarator itself.
            self.visit_variable_declarator(d);
            // A destructuring declarator ASSIGNS what it takes apart: `var [e] = [other]`
            // rebinds the parser's own parameter, and `for (var [e] of xs)` does it per pass.
            // Only the single-identifier form recorded anything, so the name still looked like
            // the response node and the helper's reads were filed at the root while the parser
            // reads something else — the wrong node, silently. The ASSIGNMENT spelling of this
            // was fixed six rounds ago; the declaration spelling records the same write now.
            //
            // Both kinds, because the extent does the scoping: a `let` pattern binds its own
            // names, and a write recorded against one of those reaches exactly as far as that
            // binding does — which is what `binding_extent` answers for every other write. I
            // first gated this on `var` and could not construct a case where the gate changed
            // an answer, so it is one rule rather than one rule and a condition.
            if d.id.get_binding_identifier().is_none() {
                for id in d.id.get_binding_identifiers() {
                    let w = Write {
                        scope: self.binding_extent(id.name.as_str(), id.span),
                        name: id.name.as_str().to_string(),
                        at: id.span,
                        effective: self.effect_position(d.span.end),
                        runs_before: self.runs_before.last().cloned().unwrap_or_default(),
                        runs_after: self.runs_after.last().cloned().unwrap_or_default(),
                        lands_at: self.effects_land_at.first().copied(),
                        repeats_in: (self.dead == 0 || self.caught > 0)
                            .then(|| self.innermost_repeating())
                            .flatten(),
                    };
                    self.writes.push(w);
                }
            }
            if let (Some(id), Some(init)) = (d.id.get_binding_identifier(), d.init.as_ref()) {
                let from = match init {
                    Expression::Identifier(src) => Some(src.name.as_str()),
                    _ => None,
                };
                // After the initializer, not at the binding identifier: `var e = parse(e)`
                // evaluates `parse` against the original parameter and only then rebinds. I gave
                // the ASSIGNMENT form this last round and left the declarator on the
                // identifier's span — the same rule in two places with one copy missing it,
                // which is the shape of half the findings on this branch.
                let outer = self.assign_end.replace(d.span.end);
                self.given_value(id.name.as_str(), from, id.span, decl.kind.is_lexical());
                self.assign_end = outer;
            }
        }
        self.hoists = outer_hoists;
    }

    fn visit_statement(&mut self, st: &Statement<'a>) {
        // A write on a path that cannot hand back a result is invisible to every execution that
        // does: `if (bad) { e = other; throw Error(); } parse(e)` reaches `parse` with the
        // untouched node on every path producing one, and blaming that write refused the
        // descent and reported a node nothing had moved. The same "which paths can produce a
        // value" rule the requiredness side asks, on the binding side.
        let dead = throws_out(std::slice::from_ref(st));
        self.dead += u32::from(dead);
        walk::walk_statement(self, st);
        self.dead -= u32::from(dead);
    }

    fn visit_try_statement(&mut self, t: &oxc_ast::ast::TryStatement<'a>) {
        // A throw inside a block a handler CATCHES does not end anything: the handler runs and
        // execution carries on, so a write before that throw is as effective as any other.
        // Asking `throws_out` without the enclosing catch marked those writes dead, and the
        // descent then went ahead against a node the parser had already moved — the wrong-node
        // direction, introduced by the dead-path rule one commit earlier.
        // A SUPPRESSION, not a reset: zeroing `dead` here achieved nothing, because
        // `visit_statement` recomputes it from the very statement that throws. The flag has to
        // outrank the computation.
        //
        // Raised around the block only. A throw in the handler is not caught by its own `try`,
        // and one in the finalizer is not either.
        self.caught += u32::from(t.handler.is_some());
        self.visit_block_statement(&t.block);
        self.caught -= u32::from(t.handler.is_some());
        if let Some(h) = &t.handler {
            self.visit_catch_clause(h);
        }
        if let Some(f) = &t.finalizer {
            self.visit_block_statement(f);
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !self.walk_invocation(&call.callee, &call.arguments, None, call.span, false) {
            walk::walk_call_expression(self, call);
        }
    }

    /// A tagged template calls its tag as immediately as `()` does — ``(function(){ … })`x` ``
    /// runs that body before the next statement. Only calls and `new` were read as invocations,
    /// so the write inside it stayed confined and the helper's fields were published on the node
    /// it had moved away from.
    ///
    /// The tag is handed the strings object and then the substitutions, which is the argument
    /// list `walk_invocation` maps onto its parameters — with the strings object standing in
    /// position 0 as a value nothing can make `undefined`.
    ///
    /// Only when the tag IS the function. A tag reached through `.call`/`.apply`/`.bind` is
    /// handed the strings object in a position those reshape, and not the way an argument list
    /// is reshaped: ``f.call`x` `` invokes `Function.prototype.call`, which reaches `f` only by
    /// forwarding and with the strings object as its receiver, while ``f.bind(null, 1)`x` ``
    /// puts the strings object AFTER bind's own arguments. Mapping either as if the substitutions
    /// began at parameter 0 would suppress a default that really runs, so the invocation is
    /// declined there and the body's write is lost rather than invented.
    fn visit_tagged_template_expression(&mut self, t: &oxc_ast::ast::TaggedTemplateExpression<'a>) {
        let direct = invoked_callee(&t.tag).span() == peel(&t.tag).span();
        if direct && self.walk_invocation(&t.tag, &[], Some(&t.quasi), t.span, false) {
            return;
        }
        walk::walk_tagged_template_expression(self, t);
    }

    /// `new (function(){ … })()` runs that body before the next statement exactly as a call
    /// does, and only calls were read that way — so the write inside it stayed confined and the
    /// helper's fields were published on the node it had moved away from. One method answers
    /// for both spellings rather than the second learning it a round later.
    fn visit_new_expression(&mut self, new: &oxc_ast::ast::NewExpression<'a>) {
        if !self.walk_invocation(&new.callee, &new.arguments, None, new.span, true) {
            walk::walk_new_expression(self, new);
        }
    }

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        // The outermost braces ARE the analysed callback body, not a scope inside it, so a
        // `let` at the top of them lives for all of it. Recording that span as a scope made
        // `bound_inside` answer true for every read in the body, so `let detail =
        // e.child("detail")` followed by a mapped callback reading `detail` had the read
        // refused as one an inner scope accounts for — and both dispatch-arm reads vanished
        // with nothing recorded at all. `var` binds through `names` and worked, which is the
        // asymmetry that located it. `ParserAnalyzer::visit_block_statement` already draws
        // this same line for its own restore; this collector did not.
        let body_itself = self.block_depth == 0 && self.fns.is_empty();
        self.block_depth += 1;
        if !body_itself {
            self.blocks.push(block.span);
        }
        self.walk_in_order(&block.body, false);
        if !body_itself {
            self.blocks.pop();
        }
        self.block_depth -= 1;
    }

    fn visit_while_statement(&mut self, stmt: &oxc_ast::ast::WhileStatement<'a>) {
        self.loops
            .push((stmt.span, can_come_round_again(&stmt.body)));
        // The test runs before the first pass, so it runs even when the body does not.
        self.visit_expression(&stmt.test);
        // Unless it cannot be false, in which case the pass happens: `while (!0)` is how this
        // corpus spells `for (;;)`, and both start their body whatever else they do.
        if always_true(&stmt.test) {
            self.walk_first_pass(&stmt.body);
        } else {
            self.maybe_skipped(|s| s.visit_statement(&stmt.body));
        }
        self.loops.pop();
    }

    fn visit_do_while_statement(&mut self, stmt: &oxc_ast::ast::DoWhileStatement<'a>) {
        self.loops
            .push((stmt.span, can_come_round_again(&stmt.body)));
        // The first pass is guaranteed, so a write at the top of the body really does run. That
        // was declined here as "which part of the body" being the whole `walk_guaranteed_pass`
        // question — but it is the same question with the same answer, and leaving it unasked
        // is not neutral: the requiredness walk read `do { current = e; break; } while (0)` as
        // one statement that always runs and this collector called the value it assigns
        // uncertain, so the helper came out optional either way.
        self.walk_first_pass(&stmt.body);
        // And the test is reached only by a pass that did not leave first: `do { break; } while
        // (current = f())` assigns nothing on the path it takes.
        if leaves_the_loop_with_a_value(&stmt.body) {
            self.maybe_skipped(|s| s.visit_expression(&stmt.test));
        } else {
            self.visit_expression(&stmt.test);
        }
        self.loops.pop();
    }

    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        // The test runs whichever way the branch goes; the sides are what control skips.
        self.visit_expression(&stmt.test);
        // Unless the test decides which side runs, in which case that side runs always and what
        // it assigns is assigned always. The requiredness walk learned this one round ago and
        // this collector — added the round after — did not, so the two disagreed about the same
        // `if`: `var current; if (!0) current = e; parse(current)` had the call read as
        // unconditional and the VALUE read as conditional, and the helper's fields came out
        // optional anyway. One rule, two places, one copy missing it, for the fifth time on this
        // branch; both read the one selector now.
        if let Some((taken, dead)) =
            statically_selected(&stmt.test, &stmt.consequent, stmt.alternate.as_ref())
        {
            if let Some(taken) = taken {
                self.visit_statement(taken);
            }
            // Unreachable, not skippable: a write on the side a decided test never selects
            // cannot happen at all, and calling it merely conditional made it a second live
            // value for the name — so the alias was refused and the helper's fields left the
            // shape with nothing said. `if (0) { … }` with no `else` is the same answer, which
            // is why the selector now reports that nothing is taken rather than declining.
            if let Some(dead) = dead {
                self.unreachable += 1;
                self.visit_statement(dead);
                self.unreachable -= 1;
            }
            return;
        }
        self.maybe_skipped(|s| {
            s.visit_statement(&stmt.consequent);
            if let Some(alt) = &stmt.alternate {
                s.visit_statement(alt);
            }
        });
    }

    fn visit_logical_expression(&mut self, expr: &oxc_ast::ast::LogicalExpression<'a>) {
        // `flag && (current = e)` assigns only when the left side allowed it — and `!0 && …`
        // always allows it.
        self.visit_expression(&expr.left);
        if logical_right_is_certain(expr) {
            self.visit_expression(&expr.right);
            return;
        }
        self.maybe_skipped(|s| s.visit_expression(&expr.right));
    }

    fn visit_conditional_expression(&mut self, expr: &oxc_ast::ast::ConditionalExpression<'a>) {
        self.visit_expression(&expr.test);
        if let Some((taken, dead)) =
            statically_selected(&expr.test, &expr.consequent, Some(&expr.alternate))
        {
            if let Some(taken) = taken {
                self.visit_expression(taken);
            }
            if let Some(dead) = dead {
                self.unreachable += 1;
                self.visit_expression(dead);
                self.unreachable -= 1;
            }
            return;
        }
        self.maybe_skipped(|s| {
            s.visit_expression(&expr.consequent);
            s.visit_expression(&expr.alternate);
        });
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
        // A getter this call's parameter binding invokes: its body runs, and it runs at the
        // call rather than where it is written.
        let bound = self
            .binding_getters
            .iter()
            .find(|(g, _)| *g == func.span)
            .copied();
        if let Some((g, call_end)) = bound {
            self.iife.push((g, vec![g]));
            self.effects_land_at.push((g, call_end));
        }
        self.fns.push(func.span);
        let outer = self.hoists;
        self.hoists = true;
        walk::walk_function(self, func, flags);
        self.hoists = outer;
        self.fns.pop();
        if bound.is_some() {
            self.effects_land_at.pop();
            self.iife.pop();
        }
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
        // A handler runs only when the block failed, so what it assigns is assigned on that
        // path alone.
        self.maybe_skipped(|s| walk::walk_catch_clause(s, clause));
        self.hoists = outer;
        self.blocks.pop();
    }

    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        // The cases share one block, and the discriminant is evaluated outside it.
        let body = stmt.cases.first().map_or(stmt.span, |first| {
            Span::new(first.span.start, stmt.span.end)
        });
        self.blocks.push(body);
        // The discriminant is evaluated to choose a case, so it runs whichever case wins; a
        // case's own test and consequent run only for the values that reach them.
        self.visit_expression(&stmt.discriminant);
        self.maybe_skipped(|s| {
            for case in &stmt.cases {
                s.visit_switch_case(case);
            }
        });
        self.blocks.pop();
    }

    fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
        self.loops
            .push((stmt.span, can_come_round_again(&stmt.body)));
        self.blocks.push(stmt.span);
        // Initializer and test run before the first pass; body and update only after one that
        // happened.
        if let Some(init) = &stmt.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &stmt.test {
            self.visit_expression(test);
        }
        // No test, or one that cannot be false: either way the body necessarily starts, so it
        // gets the guaranteed pass the requiredness side gives it. The update runs only after
        // a pass that completed, so it stays skippable whichever way the test went.
        if stmt.test.as_ref().is_none_or(always_true) {
            self.walk_first_pass(&stmt.body);
            // …and only if a pass can reach it. `for (;; current = other) { parse(current);
            // break; }` runs its body once and leaves, so that update never evaluates — but it
            // is written in the HEADER, before the body, so recording it at all had it look
            // effective at a call below it and the descent was refused for a node nothing had
            // moved. The same `can_come_round_again` the loop-carried rule reads.
            if let Some(update) = &stmt.update
                && can_come_round_again(&stmt.body)
            {
                self.maybe_skipped(|s| s.visit_expression(update));
            }
        } else {
            self.maybe_skipped(|s| {
                s.visit_statement(&stmt.body);
                if let Some(update) = &stmt.update {
                    s.visit_expression(update);
                }
            });
        }
        self.blocks.pop();
        self.loops.pop();
    }

    fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
        self.loops
            .push((stmt.span, can_come_round_again(&stmt.body)));
        self.blocks.push(stmt.span);
        // The object is evaluated to be enumerated, however few keys it turns out to have; the
        // binding and body run once per key, of which there may be none.
        self.visit_expression(&stmt.right);
        self.after_the_iterable(stmt.right.span(), |s| {
            s.maybe_skipped(|s| {
                s.visit_for_statement_left(&stmt.left);
                s.visit_statement(&stmt.body);
            });
        });
        self.blocks.pop();
        self.loops.pop();
    }

    fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
        self.loops
            .push((stmt.span, can_come_round_again(&stmt.body)));
        self.blocks.push(stmt.span);
        self.visit_expression(&stmt.right);
        // One iterable whose length is decidable here: `for (const x of [a, b])` runs its body,
        // the same guaranteed pass the requiredness side gives it. An arbitrary expression
        // keeps its zero-iteration path.
        if iterates_at_least_once(&stmt.right) {
            self.after_the_iterable(stmt.right.span(), |s| {
                s.visit_for_statement_left(&stmt.left);
                s.walk_first_pass(&stmt.body);
            });
            self.blocks.pop();
            self.loops.pop();
            return;
        }
        self.after_the_iterable(stmt.right.span(), |s| {
            s.maybe_skipped(|s| {
                s.visit_for_statement_left(&stmt.left);
                s.visit_statement(&stmt.body);
            });
        });
        self.blocks.pop();
        self.loops.pop();
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
        // `class C extends (current = other, Base) {}` runs that assignment before anything
        // after the class does, so a write there is as effective as any other — and this walked
        // only the body, so `parse(current)` afterwards followed the stale alias and filed the
        // helper's fields under the response root. The wrong-node direction, from a hand-written
        // visitor that enumerated the parts of a class it happened to think of.
        if let Some(heritage) = class.super_class.as_ref() {
            self.visit_expression(heritage);
            // …and a heritage that is not a constructor rejects the class the moment it is
            // DEFINED, so nothing in the body runs — not a computed key, not a static
            // initializer, not a static block. The heritage itself is evaluated first and keeps
            // whatever it wrote; the same constructibility rule `new` reads, at the other place
            // that needs it.
            if heritage_throws(heritage) {
                self.unreachable += 1;
                walk::walk_class_body(self, &class.body);
                self.unreachable -= 1;
                return;
            }
        }
        // And only what the class evaluates when it is DEFINED. An instance field initializer
        // runs per `new`, of which there may be none: `class C { value = (current = other) }`
        // writes nothing by existing, and recording it refused a descent for a node nothing had
        // moved. A computed key and a static initializer do run here, and a method body is a
        // function like any other — deferred, and confined by the extent rule above.
        //
        // In source order, which is not the order the two phases run in: every computed key is
        // evaluated before any static initializer, so a key written after one reads what the
        // initializer has not yet written. Saying that needs a clock this model does not have —
        // see the note on the PR.
        // Whether THIS class is the one being constructed in place. Taken out of the list, so
        // the walk of its own body cannot see it again and a class nested inside it is judged
        // on its own span.
        let constructed = if let Some(i) = self.constructing.iter().position(|s| *s == class.span) {
            self.constructing.remove(i);
            true
        } else {
            false
        };
        // Every instance field initializes BEFORE the constructor body runs, wherever the field
        // is written. Walking the elements in source order got `class { constructor(){ … } x =
        // (current = other); }` backwards — the constructor read the node the field had already
        // replaced. Held back and visited last, so source order decides among the fields and the
        // constructor still comes after all of them.
        //
        // A DERIVED class is not this: its instance fields initialize when `super()` returns,
        // which is somewhere inside the constructor body, and nothing here can say where. Source
        // order stays the answer there, as it was.
        // Every computed key of a class is evaluated when the class is DEFINED, before any
        // static initializer runs — whatever their source order. A key written below an
        // initializer therefore reads what that initializer has not yet written, and walking
        // the elements in order answered it with the initializer.
        //
        // Declared rather than reordered. Repositioning the writes was what I tried when this
        // was first reported, and it broke two neighbours: pushing them past the keys pushes
        // them past each other. Saying "this write follows the keys" leaves every other
        // ordering, including between two initializers, exactly where it was.
        let key_spans: Vec<Span> = class
            .body
            .body
            .iter()
            .filter_map(|el| match el {
                oxc_ast::ast::ClassElement::MethodDefinition(m) if m.computed => Some(m.key.span()),
                oxc_ast::ast::ClassElement::PropertyDefinition(p) if p.computed => {
                    Some(p.key.span())
                }
                oxc_ast::ast::ClassElement::AccessorProperty(p) if p.computed => Some(p.key.span()),
                _ => None,
            })
            .collect();
        // The same ordering read the other way. Saying only that an initializer FOLLOWS the
        // keys left a key written below one still at its own offset, so `class C { static x =
        // parse(current); [(current = other)]() {} }` had the initializer read a node the key
        // had in fact already replaced. Both halves of one rule, and shipping the first alone
        // is the shape this branch keeps finding — so the key's own writes declare that they
        // PRECEDE every static initializer and block.
        let static_spans: Vec<Span> = class
            .body
            .body
            .iter()
            .filter_map(|el| match el {
                oxc_ast::ast::ClassElement::PropertyDefinition(p) if p.r#static => {
                    p.value.as_ref().map(GetSpan::span)
                }
                oxc_ast::ast::ClassElement::AccessorProperty(p) if p.r#static => {
                    p.value.as_ref().map(GetSpan::span)
                }
                oxc_ast::ast::ClassElement::StaticBlock(b) => Some(b.span),
                _ => None,
            })
            .collect();
        // The second phase runs static blocks and static initializers in source order, and stops
        // at the first one that completes abruptly. Only a block that certainly throws is
        // decidable here: a static block ending its own statement list. An INITIALIZER that
        // throws ends the phase exactly as much, and asking whether an arbitrary expression can
        // throw is a question this pass does not answer, so that half is left — it loses the
        // stop rather than inventing one.
        let static_phase_ends: Option<u32> = class.body.body.iter().find_map(|el| match el {
            oxc_ast::ast::ClassElement::StaticBlock(b)
                if b.body.iter().any(ends_the_statement_list) =>
            {
                Some(b.span.end)
            }
            _ => None,
        });
        // Constructing it does not, on its own, run its instance field initializers. A DERIVED
        // constructor installs them when `super()` returns, and one that leaves before calling
        // it — `constructor(){ return {}; }`, which is legal and completes construction — runs
        // none of them. Treating construction alone as enough recorded a write that never
        // happens, and the descent was refused for a node still standing. The constructor body
        // itself does run either way, so only the field gate moves.
        let instance_fields = constructed && instance_fields_initialize(class);
        let ctor_last = constructed && class.super_class.is_none();
        // Reordering the WALK is not enough on its own: effectiveness is decided by position,
        // and a field written after the constructor is textually after the read inside it. So
        // everything else in the class also declares that it precedes the part of the
        // constructor the fields really do precede.
        // The other half of that ordering, and the half only a DERIVED class has. Its fields
        // initialize when `super()` RETURNS, so a read in the constructor BEFORE that call sees
        // none of them — and the fields are written above the constructor, so position alone
        // called them already effective there. The post-`super` region below says what the
        // fields precede; this says what they follow, and neither is right without the other.
        let mut pre_super: Option<Span> = None;
        let ctor_body = constructed
            .then(|| {
                let ctor = class.body.body.iter().find_map(|el| match el {
                    oxc_ast::ast::ClassElement::MethodDefinition(m)
                        if m.kind == oxc_ast::ast::MethodDefinitionKind::Constructor =>
                    {
                        Some(m)
                    }
                    _ => None,
                })?;
                if class.super_class.is_none() {
                    return Some(ctor.value.span);
                }
                // A DERIVED class initializes its fields the moment `super()` returns, so they
                // precede everything after that call and nothing before it. Keeping source
                // order for the whole constructor — which is what excluding derived classes
                // outright did — read a `parse` after the `super()` against a field written
                // below it. Only an unconditional call at the top of the body is decidable;
                // one under an `if` runs somewhere this cannot name, so that declines.
                let body = ctor.value.body.as_ref()?;
                // Through the parentheses that change nothing: `(super());` calls it exactly
                // as `super();` does, and matching the bare spelling alone left the fields
                // ordered by source position against a read that follows them.
                let super_call = body.statements.iter().find_map(|st| match st {
                    Statement::ExpressionStatement(e) => match peel(&e.expression) {
                        Expression::CallExpression(c)
                            if matches!(peel(&c.callee), Expression::Super(_)) =>
                        {
                            Some(c.span)
                        }
                        _ => None,
                    },
                    _ => None,
                })?;
                pre_super = Some(Span::new(ctor.value.span.start, super_call.end));
                Some(Span::new(super_call.end, ctor.value.span.end))
            })
            .flatten();
        if let Some(body) = ctor_body {
            self.runs_before.push(vec![body]);
        }
        let mut held_ctor = None;
        for el in &class.body.body {
            match el {
                // A constructor invoked by `new` right here runs as certainly as an IIFE body,
                // so a write in it escapes to everything after the construction rather than
                // staying confined to a method nobody was known to call.
                oxc_ast::ast::ClassElement::MethodDefinition(m)
                    if constructed && m.kind == oxc_ast::ast::MethodDefinitionKind::Constructor =>
                {
                    self.iife.push((m.value.span, vec![m.value.span]));
                    if ctor_last {
                        held_ctor = Some(el);
                    } else {
                        self.visit_class_element(el);
                    }
                }
                // A computed METHOD key is evaluated in the same phase as any other, and it is
                // the spelling the reported case used — the field walk below never sees one.
                oxc_ast::ast::ClassElement::MethodDefinition(m)
                    if m.computed && !static_spans.is_empty() =>
                {
                    self.runs_before.push(static_spans.clone());
                    self.visit_property_key(&m.key);
                    self.runs_before.pop();
                    self.visit_function(&m.value, ScopeFlags::Function);
                }
                oxc_ast::ast::ClassElement::PropertyDefinition(p) => {
                    self.visit_field_at_definition(
                        p.computed,
                        p.r#static,
                        &p.key,
                        p.value.as_ref(),
                        instance_fields,
                        ClassPhases {
                            keys: &key_spans,
                            statics: &static_spans,
                            pre_super,
                            static_phase_ends,
                        },
                    );
                }
                // `accessor value = …` is a field with a getter and a setter generated for it,
                // and its initializer runs per `new` exactly as a plain one does. Only the two
                // spellings this visitor happened to think of were listed, so the third fell
                // through to the generic walk and a write in an instance initializer was
                // recorded as effective at class definition — a descent refused for a node
                // nothing had moved, which is what enumerating the parts of a class by hand
                // costs each time one is missed.
                oxc_ast::ast::ClassElement::AccessorProperty(p) => {
                    self.visit_field_at_definition(
                        p.computed,
                        p.r#static,
                        &p.key,
                        p.value.as_ref(),
                        instance_fields,
                        ClassPhases {
                            keys: &key_spans,
                            statics: &static_spans,
                            pre_super,
                            static_phase_ends,
                        },
                    );
                }
                // Its braces are a scope: `static { let current = other; }` binds a NEW
                // `current` that dies with the block, and walking it generically recorded that
                // value against the OUTER binding — a second live value for the name, so the
                // alias was refused and the helper's fields left the shape with nothing said.
                oxc_ast::ast::ClassElement::StaticBlock(b) => {
                    self.blocks.push(b.span);
                    self.block_depth += 1;
                    let declared = !key_spans.is_empty();
                    if declared {
                        self.runs_after.push(key_spans.clone());
                    }
                    // …and a block written past an earlier one that throws is not evaluated,
                    // the same rule the initializers above are given.
                    let skipped = static_phase_ends.is_some_and(|end| b.span.start >= end);
                    if skipped {
                        self.unreachable += 1;
                    }
                    self.walk_in_order(&b.body, false);
                    if skipped {
                        self.unreachable -= 1;
                    }
                    if declared {
                        self.runs_after.pop();
                    }
                    self.block_depth -= 1;
                    self.blocks.pop();
                }
                other => self.visit_class_element(other),
            }
        }
        if ctor_body.is_some() {
            self.runs_before.pop();
        }
        if let Some(el) = held_ctor {
            self.visit_class_element(el);
        }
    }
}

/// Where each name the source binds is in scope.
#[derive(Default, Clone)]
struct Bindings {
    names: std::collections::HashSet<String>,
    scoped: Vec<(Span, String)>,
    /// Names the source assigns to, with where the write is and whether it repeats.
    writes: Vec<Write>,
    given: Vec<Given>,
}

impl Bindings {
    /// Whether `name` is bound by this source at `at` — and so is not the module's helper
    /// of that name. Scoped by extent: suppressing every call because some unrelated
    /// nested function reused the name is a silent loss of its fields.
    fn shadows(&self, name: &str, at: Span) -> bool {
        self.names.contains(name) || self.bound_inside(name, at)
    }

    /// Whether `name` is written anywhere in the function containing `at`.
    ///
    /// Being in scope is not the same as still naming what you were bound to. The
    /// helper-descent filter asked only about lexical shadowing, so `row =
    /// row.child("detail"); parse(row)` still counted `row` as the callback's own node and
    /// merged the helper's reads at the element root instead of under `<detail>`. Any write
    /// in the extent disqualifies the name: which side of the call it lands on is a
    /// question this pre-scan cannot order, and guessing puts fields under the wrong node.
    fn written_in_scope(&self, name: &str, at: Span) -> bool {
        self.writes.iter().any(|w| {
            w.name == name
                && w.covers(at)
                // Order matters and I said a pre-scan could not judge it. It can, for the
                // part that is textual: a write AFTER the call did not affect what the call
                // was handed, so `parse(row); row = row.child("detail")` is a valid descent
                // and rejecting it lost recoverable fields.
                //
                // The part that is not textual is repetition — a write below the call runs
                // before it on the next pass — so a write inside a loop that also contains
                // the call still counts.
                && in_effect_at(w.effective, w.repeats_in, &w.runs_before, &w.runs_after, w.lands_at, at)
        })
    }

    /// Every name that still stands for `node` at `at`: `node` itself plus anything
    /// declared as a bare copy of it, transitively, with nothing on the chain written since.
    ///
    /// A mapped callback that aliases its node before delegating — `var current = row;
    /// parse(current)` — matched no argument position, so the helper was never entered and
    /// its fields left the shape with no drop recorded. Recognizing the alias is the same
    /// work as resolving it, so it is resolved rather than merely counted.
    /// Paired with the subset of them that stand for `node` only on SOME path: a value assigned
    /// inside a branch, and anything copied from one. `var current; if (flag) current = e;
    /// parse(current)` hands `parse` the element only when `flag` held, so what it reads there is
    /// not read on every execution — and one in-scope value ordered before the call looked as
    /// definite as any other. Carried alongside rather than filtered out, because the fields ARE
    /// recoverable; they are just not required.
    fn names_for(
        &self,
        node: &str,
        at: Span,
    ) -> (
        std::collections::HashSet<String>,
        std::collections::HashSet<String>,
    ) {
        let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut uncertain: std::collections::HashSet<String> = std::collections::HashSet::new();
        out.insert(node.to_string());
        // To a fixed point, not a fixed count. Each pass adds at least one name or stops, and
        // a name is never added twice, so `a = b; b = a` terminates on the set alone — the
        // cap it was paired with only made a chain of nine copies lose the helper silently.
        loop {
            let more: Vec<(String, bool)> = self
                .given
                .iter()
                .filter(|g| {
                    // Copied from a name that already stands for the node, and given a value
                    // exactly once in the scopes covering the call. Given twice it is not a
                    // copy of anything in particular — `current = row; current =
                    // row.child("detail")` names the detail node by the time the helper is
                    // called, and following it to `row` would file the reads under the wrong
                    // node. `given_once_in` counts only what is in scope, which is also what
                    // keeps a nested function's copy from answering out here; checking the
                    // extent again alongside it said the same thing twice.
                    g.from.as_deref().is_some_and(|f| out.contains(f))
                        && !out.contains(g.name.as_str())
                        // And THIS record is one that can already have taken effect. The count
                        // below is about the name; it says nothing about which value was
                        // selected, so `var current = other; parse(current); current = row`
                        // counted the one value in scope, then picked the LATER record because
                        // its source was already in the set — filing the helper's fields under
                        // `row` at a call where `current` still holds `other`. Same rule the
                        // count uses: textual position, unless a loop repeats it.
                        && in_effect_at(g.effective, g.repeats_in, &g.runs_before, &g.runs_after, g.lands_at, at)
                        && self.given_once_in(&g.name, at)
                        && !self.written_without_a_value(&g.name, at)
                })
                .map(|g| {
                    // Uncertain if this assignment itself could have been skipped, or if what it
                    // copied from was already only conditionally the node — `if (flag) a = e; b =
                    // a; parse(b)` passes `b`, whose own assignment is unconditional, and asking
                    // only about the last link would have called it certain.
                    let via = g.from.as_deref().unwrap_or_default();
                    (g.name.clone(), g.conditional || uncertain.contains(via))
                })
                .collect();
            if more.is_empty() {
                return (out, uncertain);
            }
            for (name, cond) in more {
                if cond {
                    uncertain.insert(name.clone());
                }
                out.insert(name);
            }
        }
    }

    /// Whether `name` is written at `at` by something that recorded no value for it.
    ///
    /// `current = row` is BOTH an alias and a write to `current`, which is why copies are
    /// tracked as `Given` rather than as writes — asking `written_in_scope` here rejected the
    /// very form it was meant to follow. But a destructuring write,
    /// `[current] = [row.child("detail")]`, reaches the write collector and records no value,
    /// so counting values alone still called `current` a copy of `row` and filed the helper's
    /// reads at the row root. A write whose span matches no recorded value is one whose effect
    /// the value list cannot see, and that is what invalidates the alias.
    fn written_without_a_value(&self, name: &str, at: Span) -> bool {
        self.writes.iter().any(|w| {
            w.name == name
                && w.covers(at)
                && in_effect_at(
                    w.effective,
                    w.repeats_in,
                    &w.runs_before,
                    &w.runs_after,
                    w.lands_at,
                    at,
                )
                && !self.given.iter().any(|g| g.name == name && g.at == w.at)
        })
    }

    /// Whether `name` is given a value that can already have taken effect at `at`.
    ///
    /// `var row = row.child("detail")` REDECLARES the callback's parameter and assigns
    /// through it, so afterwards `row` names the detail node. A declaration is not a write to
    /// an existing binding in general — treating every initialized `var` as one disqualified
    /// every tracked child in the file — but for a name that was ALREADY bound, which is what
    /// the parameter is, the initializer moves it. Ordering is the same question as for a
    /// write: textual position, unless a loop repeats it.
    fn given_before(&self, name: &str, at: Span) -> bool {
        self.given.iter().any(|g| {
            g.name == name
                && covers(g.scope, at)
                && in_effect_at(
                    g.effective,
                    g.repeats_in,
                    &g.runs_before,
                    &g.runs_after,
                    g.lands_at,
                    at,
                )
        })
    }

    /// Whether `name` holds one value in the scopes covering `at` — given once, or given the
    /// SAME thing by every record that could have taken effect.
    fn given_once_in(&self, name: &str, at: Span) -> bool {
        // Only values that can already have taken effect at `at`. I made the parameter check
        // order-aware and left this one counting every assignment in the scope, so
        // `var current = row; parse(current); current = row.child("detail")` saw two values and
        // refused to follow `current` — dropping the helper's fields for a write that cannot
        // reach the call. Same rule as `written_in_scope`: textual position, unless a loop
        // repeats it.
        let live: Vec<&Given> = self
            .given
            .iter()
            .filter(|g| {
                g.name == name
                    && covers(g.scope, at)
                    && in_effect_at(
                        g.effective,
                        g.repeats_in,
                        &g.runs_before,
                        &g.runs_after,
                        g.lands_at,
                        at,
                    )
            })
            .collect();
        match live.split_first() {
            None => false,
            Some((_, [])) => true,
            // `if (flag) current = e; else current = e;` writes twice and means one thing, and
            // counting records refused the alias and dropped the helper's fields with nothing
            // recorded. Records that COPY A NAME are comparable that way; two that computed
            // their values are two values however alike they look, which is the case this
            // count exists for — `current = row; current = row.child("detail")`. Whether the
            // paths are exhaustive is a separate question, and the answer is already carried:
            // each record's own `conditional` travels to `names_for`, so a value only some
            // path assigns still reaches the shape as an optional one.
            Some((first, rest)) => {
                first.from.is_some() && rest.iter().all(|g| g.from == first.from)
            }
        }
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
        writes: c.writes,
        given: c.given,
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
    contains_exit_where(stmt, true, true)
}

/// Whether `stmt` can end the construct being asked about *and hand back a result* — so a
/// `throw` does not count.
///
/// This is the question a guaranteed pass wants. `do { if (bad) throw Error(); } while
/// (parse(e))` reaches the test on every execution that produces a value, because the only
/// path skipping it produces none; treating every exit alike weakened the test and called
/// `parse`'s reads optional where every successful parse performs them. Same for what follows
/// a possible throw inside a `do` body or a testless `for`.
fn exits_with_a_value(stmt: &Statement<'_>) -> bool {
    contains_exit_where(stmt, false, true)
}

/// Whether `stmt` can leave the loop it is the body of *carrying a result* — a `return`, a
/// `break`, or a labelled jump out of it.
///
/// Not a `throw`, which leaves handing nothing back, and not a `continue`, which starts the next
/// pass rather than leaving at all. Contrast [`exits_with_a_value`], where a `continue` counts
/// because the question there is what the rest of a guaranteed pass can be skipped by.
///
/// Two callers, and they turn out to be one question. A `do`/`while` reaches its test only if
/// the body did not leave first — `do { continue; } while (parse(e))` evaluates `parse` on every
/// execution that leaves the loop at all. And a loop whose test cannot end it produces a value
/// only by being left this way: `while (!0) { if (bad) throw Error(); }` either throws or runs
/// forever, so it hands nothing back on any path. That case was missed by asking two questions
/// instead — "does every path throw" was false, and "is there no way out" counted the throw as
/// one — and their disjunction covered each pure case while missing the mixture. Asking once
/// covers all three, and one fewer predicate is the point rather than a side effect.
///
/// A LABELLED continue is counted as leaving even when it names this loop — recovering that
/// would need the loop's own label threaded in from the `LabeledStatement` above it, and
/// over-weakening is the safe direction.
fn leaves_the_loop_with_a_value(stmt: &Statement<'_>) -> bool {
    contains_exit_where(stmt, false, false)
}

/// Whether a logical operator's right side runs whatever its left side evaluated to: `!0 && x`
/// and `0 || x` both reach `x` always.
///
/// `??` reaches its right side when the left one IS nullish, which `null` and `void …` both
/// are. Read by the requiredness walk and by the binding collector, which have to agree about
/// the same expression — so a read there came out optional against a parser that always
/// performs it, and the shape accepted responses the source rejects.
fn logical_right_is_certain(expr: &oxc_ast::ast::LogicalExpression<'_>) -> bool {
    match expr.operator {
        oxc_syntax::operator::LogicalOperator::And => always_true(&expr.left),
        oxc_syntax::operator::LogicalOperator::Or => always_false(&expr.left),
        oxc_syntax::operator::LogicalOperator::Coalesce => certainly_nullish(&expr.left),
    }
}

/// Whether `t` is certainly `null` or `undefined` — the complement [`never_nullish`] declines
/// to answer, and no more available for an arbitrary expression than its opposite is.
///
/// `void <anything>` is `undefined` whatever it evaluates, side effects included. A bare
/// `undefined` is an identifier nothing here resolves, so it declines with everything else.
fn certainly_nullish(t: &Expression<'_>) -> bool {
    match t {
        Expression::NullLiteral(_) => true,
        Expression::ParenthesizedExpression(p) => certainly_nullish(&p.expression),
        Expression::UnaryExpression(u) => u.operator == oxc_syntax::operator::UnaryOperator::Void,
        _ => false,
    }
}

/// Which side of a branch a statically decidable test selects, as `(taken, unreachable)`.
///
/// `None` when the test is anything a value could change, which is every test in this corpus —
/// the point is that a minifier's `!0`/`0` spelling is not a branch and must not be read as one.
fn statically_selected<'s, T>(
    test: &Expression<'_>,
    consequent: &'s T,
    alternate: Option<&'s T>,
) -> Option<(Option<&'s T>, Option<&'s T>)> {
    if always_true(test) {
        return Some((Some(consequent), alternate));
    }
    // The taken side is optional because `if (0) { … }` with no `else` takes NOTHING — and
    // answering `None` for it, as though the test were undecided, left the dead consequent
    // walked as merely skippable. A write there is not skippable; it cannot happen.
    if always_false(test) {
        return Some((alternate, Some(consequent)));
    }
    None
}

/// Whether iterating `e` necessarily produces at least one element.
///
/// Only an array literal holding something other than a spread: `[0]` and `[a, b]` iterate, `[]`
/// does not, and `[...xs]` may or may not — deliberately narrow, because reading an iterable as
/// nonempty when it can be empty would require reads the parser can skip. A hole counts: `[,]`
/// yields one `undefined`.
fn iterates_at_least_once(e: &Expression<'_>) -> bool {
    match e {
        Expression::ParenthesizedExpression(p) => iterates_at_least_once(&p.expression),
        Expression::ArrayExpression(a) => a
            .elements
            .iter()
            .any(|el| !matches!(el, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_))),
        _ => false,
    }
}

/// Whether `t` is a test no value of it can make false, so the loop it controls necessarily
/// runs its body. Deliberately narrow: only the spellings a minifier emits, because reading a
/// test as always-true when it is not would require reads the parser can skip.
fn always_true(t: &Expression<'_>) -> bool {
    match t {
        Expression::BooleanLiteral(b) => b.value,
        Expression::NumericLiteral(n) => n.value != 0.0,
        Expression::ParenthesizedExpression(p) => always_true(&p.expression),
        // `while (!0)`, which is how this corpus spells it 74 times over.
        Expression::UnaryExpression(u)
            if u.operator == oxc_syntax::operator::UnaryOperator::LogicalNot =>
        {
            always_false(&u.argument)
        }
        _ => false,
    }
}

/// Whether `t` is a value that is certainly neither `null` nor `undefined`.
///
/// Not the same question as [`always_true`], and `??` asks this one: `0` is falsy and perfectly
/// non-nullish, so `0 ?? x` never evaluates `x`. Reading truthiness there answered a narrower
/// question and left the right side of a coalesce walked when nothing reaches it.
///
/// Literals and the expressions whose result type is fixed by their spelling. `void 0` IS
/// undefined, and a bare `undefined` is an identifier this cannot resolve, so both decline.
fn never_nullish(t: &Expression<'_>) -> bool {
    match t {
        Expression::NullLiteral(_) => false,
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_) => true,
        Expression::ParenthesizedExpression(p) => never_nullish(&p.expression),
        // Every unary operator but `void` yields a primitive that is not nullish — `typeof`
        // a string, `delete` a boolean, `!`/`-`/`+`/`~` a boolean or a number.
        Expression::UnaryExpression(u) => u.operator != oxc_syntax::operator::UnaryOperator::Void,
        _ => false,
    }
}

/// The negation of [`always_true`] for the literals `!` is applied to — not its complement,
/// since neither answer is available for an arbitrary expression.
fn always_false(t: &Expression<'_>) -> bool {
    match t {
        Expression::BooleanLiteral(b) => !b.value,
        Expression::NumericLiteral(n) => n.value == 0.0,
        Expression::NullLiteral(_) => true,
        Expression::ParenthesizedExpression(p) => always_false(&p.expression),
        // `while (!1)` and `if (!1)` are as decided as `!0` is, and this pair was written with
        // the negation on one side only — so `if (!1) { … } else { parse(e); }` intersected the
        // reads of a side nothing reaches, and left what the parser always performs optional.
        // The two are each other's mirror and now say so.
        Expression::UnaryExpression(u)
            if u.operator == oxc_syntax::operator::UnaryOperator::LogicalNot =>
        {
            always_true(&u.argument)
        }
        _ => false,
    }
}

fn contains_exit_where(stmt: &Statement<'_>, throw_counts: bool, continue_counts: bool) -> bool {
    struct Probe {
        found: bool,
        /// Whether a `throw` is one of the ways out being counted. It leaves the construct
        /// either way; whether that matters depends on whether the caller is asking about
        /// control flow or about paths that can yield a result.
        throw_counts: bool,
        /// Whether an unlabelled `continue` counts. It skips the rest of the body but arrives
        /// at a `do`/`while`'s test, so the two questions want different answers.
        continue_counts: bool,
        /// Nested loops open around the statement being looked at. A `break` inside one of
        /// them leaves THAT loop, not the one being asked about — `do { while (f) { break; } }
        /// while (…)` completes its guaranteed pass, and counting the inner break weakened a
        /// test the parser always evaluates. `return`/`throw` leave regardless.
        loops: u32,
        /// Same for `switch`, which consumes an unlabelled `break` but not a `continue`.
        switches: u32,
        /// Labels declared INSIDE the statement being probed. A labelled jump naming one of
        /// these lands back inside the probe, so it is no more a way out than an unlabelled
        /// `break` inside a nested loop is: `do { local: { break local; } parse(e); … }` reaches
        /// `parse` on every pass, and counting the jump called that read optional. Only a label
        /// declared outside — the enclosing loop's own, say — genuinely leaves.
        labels: Vec<String>,
    }
    impl Probe {
        /// Whether the probed statement declares `label` itself.
        fn names(&self, label: &str) -> bool {
            self.labels.iter().any(|n| n == label)
        }
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
            self.found |= self.throw_counts;
        }
        fn visit_break_statement(&mut self, b: &oxc_ast::ast::BreakStatement<'a>) {
            // A LABELLED break jumps out of whatever it names, which no nested construct
            // swallows — unless what it names is itself inside the probe.
            match &b.label {
                Some(l) => self.found |= !self.names(l.name.as_str()),
                None => self.found |= self.loops == 0 && self.switches == 0,
            }
        }
        fn visit_continue_statement(&mut self, c: &oxc_ast::ast::ContinueStatement<'a>) {
            match &c.label {
                Some(l) => self.found |= !self.names(l.name.as_str()),
                None => self.found |= self.loops == 0 && self.continue_counts,
            }
        }
        fn visit_labeled_statement(&mut self, l: &oxc_ast::ast::LabeledStatement<'a>) {
            self.labels.push(l.label.name.as_str().to_string());
            walk::walk_labeled_statement(self, l);
            self.labels.pop();
        }
        fn visit_while_statement(&mut self, st: &oxc_ast::ast::WhileStatement<'a>) {
            self.loops += 1;
            walk::walk_while_statement(self, st);
            self.loops -= 1;
        }
        fn visit_do_while_statement(&mut self, st: &oxc_ast::ast::DoWhileStatement<'a>) {
            self.loops += 1;
            walk::walk_do_while_statement(self, st);
            self.loops -= 1;
        }
        fn visit_for_statement(&mut self, st: &oxc_ast::ast::ForStatement<'a>) {
            self.loops += 1;
            walk::walk_for_statement(self, st);
            self.loops -= 1;
        }
        fn visit_for_in_statement(&mut self, st: &oxc_ast::ast::ForInStatement<'a>) {
            self.loops += 1;
            walk::walk_for_in_statement(self, st);
            self.loops -= 1;
        }
        fn visit_for_of_statement(&mut self, st: &oxc_ast::ast::ForOfStatement<'a>) {
            self.loops += 1;
            walk::walk_for_of_statement(self, st);
            self.loops -= 1;
        }
        fn visit_switch_statement(&mut self, st: &oxc_ast::ast::SwitchStatement<'a>) {
            self.switches += 1;
            walk::walk_switch_statement(self, st);
            self.switches -= 1;
        }
    }
    let mut p = Probe {
        found: false,
        throw_counts,
        continue_counts,
        loops: 0,
        switches: 0,
        labels: Vec::new(),
    };
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
    fn a_let_bound_child_in_a_switch_case_does_not_outlive_the_switch() {
        // The cases share ONE lexical scope and it ends with the switch, so `switch (m) { case
        // 1: let d = e.child("inner"); break; } d.attrString("outside")` reads the trailing
        // attribute off whatever `d` is outside — not off `<inner>`. This visitor mutated
        // `child_vars` and put nothing back, which is the wrong-node direction the block and
        // loop-header restores already existed for.
        let r = analyze_parser_ast(
            r#"{ switch (m) { case 1: let d = e.child("inner"); d.attrString("in"); break; }
                 d.attrString("outside"); }"#,
            "e",
        );
        let inner = r.fields.iter().find(|f| f.name == "inner").expect("inner");
        let kids: Vec<String> = inner
            .children
            .iter()
            .flatten()
            .map(|c| c.name.clone())
            .collect();
        assert!(
            kids.iter().any(|n| n == "in") && !kids.iter().any(|n| n == "outside"),
            "the case-local binding dies with the switch: {kids:?}"
        );
    }

    #[test]
    fn a_var_bound_child_in_a_switch_case_does_outlive_it() {
        // The bound: `var` is function-scoped, so it hoists clear of the switch block and the
        // trailing read really is off `<inner>`. Restoring every declaration would lose it.
        let r = analyze_parser_ast(
            r#"{ switch (m) { case 1: var d = e.child("inner"); d.attrString("in"); break; }
                 d.attrString("outside"); }"#,
            "e",
        );
        let inner = r.fields.iter().find(|f| f.name == "inner").expect("inner");
        let kids: Vec<String> = inner
            .children
            .iter()
            .flatten()
            .map(|c| c.name.clone())
            .collect();
        assert!(
            kids.iter().any(|n| n == "outside"),
            "a hoisting binding survives the switch: {kids:?}"
        );
    }

    #[test]
    fn an_arm_no_fallthrough_reaches_starts_from_the_outer_bindings() {
        // Entering at `case 2` runs `case 2` — `case 1` broke, so nothing it bound is in scope
        // on that path, whatever `var` says about the rest of the function. The arms shared one
        // `child_vars` regardless, so the second arm's read was filed under `<inner>`, a node
        // that entry never reached: the wrong node, and with nothing recorded, since
        // `SWITCH_ARM_SHADOW` fires only for an arm that FALLS THROUGH and redeclares a name
        // the switch was entered with. Every way an arm can end on all its paths.
        for tail in [
            "break;",
            "throw Error();",
            "return t;",
            "if (f) break; else break;",
        ] {
            let r = analyze_parser_ast(
                &format!(
                    r#"{{ switch (m) {{ case 1: var d = e.child("inner"); {tail}
                         case 2: d.attrString("late"); break; }} }}"#
                ),
                "e",
            );
            let inner = r.fields.iter().find(|f| f.name == "inner").expect("inner");
            let kids: Vec<String> = inner
                .children
                .iter()
                .flatten()
                .map(|c| c.name.clone())
                .collect();
            assert!(
                !kids.iter().any(|n| n == "late"),
                "`{tail}` seals the arm, so the next one never sees `d`: {kids:?}"
            );
        }
    }

    #[test]
    fn a_var_nested_inside_a_falling_through_arm_is_still_a_shadow() {
        // `var` is function-scoped, so `case "a": { var t = e.child("inner"); }` rebinds `t` for
        // every arm after it exactly as the unbraced form does. The shadow scan read only the
        // top level of each consequent, so the ambiguity it exists to report went unrecorded —
        // the tree still filed the next arm's read under `<inner>`, now silently, which is the
        // one thing the counted half of this decline is supposed to prevent.
        for arm in [
            r#"{ var t = e.child("inner"); }"#,
            r#"if (f) { var t = e.child("inner"); }"#,
            r#"for (;;) { var t = e.child("inner"); break; }"#,
        ] {
            let r = analyze_parser_ast(
                &format!(
                    r#"{{ var t = e.child("outer");
                         switch (mode) {{ case "a": {arm} case "b": t.attrString("id"); }} }}"#
                ),
                "e",
            );
            assert!(
                r.unresolved.iter().any(|u| u == "arm-shadowed node@t"),
                "`{arm}` rebinds `t` for the arms after it: {:?}",
                r.unresolved
            );
        }
    }

    #[test]
    fn a_binding_that_dies_with_its_block_is_not_a_shadow() {
        // The bounds, and both are why this asks for `var` specifically rather than for every
        // declaration it can find: a `let` inside a nested block ends with that block, and a
        // `var` inside a nested FUNCTION belongs to that function. Neither reaches the arms
        // after it, and reporting them would make the counter fire where nothing is ambiguous.
        for arm in [
            "{ let t = 1; }",
            "(function(){ var t = 1; });",
            "(() => { var t = 1; });",
        ] {
            let r = analyze_parser_ast(
                &format!(
                    r#"{{ var t = e.child("outer");
                         switch (mode) {{ case "a": {arm} case "b": t.attrString("id"); }} }}"#
                ),
                "e",
            );
            assert!(
                r.unresolved.is_empty(),
                "`{arm}` rebinds nothing the next arm sees: {:?}",
                r.unresolved
            );
        }
    }

    #[test]
    fn an_arm_that_falls_through_does_hand_its_bindings_on() {
        // The bound. Fallthrough is the one way the next arm runs with what this one bound, so
        // the read really is off `<inner>` — restoring at every arm boundary would lose it and
        // file the read against the outer node instead, which is the same wrong-node mistake
        // pointing the other way. A `break` only SOME path takes leaves the fallthrough open.
        for tail in ["", "if (f) break;", "if (f) { g(); } else { break; }"] {
            let r = analyze_parser_ast(
                &format!(
                    r#"{{ switch (m) {{ case 1: var d = e.child("inner"); {tail}
                         case 2: d.attrString("late"); break; }} }}"#
                ),
                "e",
            );
            let inner = r.fields.iter().find(|f| f.name == "inner").expect("inner");
            let kids: Vec<String> = inner
                .children
                .iter()
                .flatten()
                .map(|c| c.name.clone())
                .collect();
            assert!(
                kids.iter().any(|n| n == "late"),
                "`{tail}` falls through carrying `d`: {kids:?}"
            );
        }
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

    /// The tags a read landed under, as `parent/child` paths, for placement assertions.
    fn placed_paths(r: &ParserResult) -> Vec<String> {
        let mut out = Vec::new();
        for f in &r.fields {
            if let Some(kids) = &f.children {
                for k in kids {
                    out.push(format!("{}/{}", f.name, k.name));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_let_bound_child_at_the_top_of_the_body_reaches_the_dispatch_arms() {
        // `let detail = e.child("detail")` followed by arms reading `detail` lost BOTH reads
        // and recorded nothing — the outermost braces were registered as a scope, so
        // `bound_inside` called every read in the body one an inner scope accounts for and the
        // walk refused to place them. The same source with `var` recovered both, which is what
        // showed the cause was the scope registration rather than the missing lexical model I
        // had blamed on the review thread.
        let arms = |decl: &str| {
            let src = format!(
                r#"{{ {decl} detail = e.child("detail");
                     e.forEachChildWithTag("row", function(row){{
                         var k = row.attrString("kind");
                         if (k === "a") {{ t.one = detail.attrString("first"); }}
                         if (k === "b") {{ t.two = detail.attrString("second"); }}
                     }});
                   }}"#
            );
            let r = analyze_parser_ast(&src, "e");
            r.fields
                .iter()
                .find(|f| f.name == "detail")
                .and_then(|f| f.children.as_ref())
                .map(|k| k.iter().map(|c| c.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        for decl in ["let", "const", "var"] {
            let kids = arms(decl);
            assert!(
                kids.iter().any(|n| n == "first") && kids.iter().any(|n| n == "second"),
                "`{decl}` at the top of the body reaches the arms: {kids:?}"
            );
        }
    }

    #[test]
    fn a_child_shadowed_by_a_let_in_a_block_is_restored_after_it() {
        // `let` dies with the block, so the read after it is off `<outer>`. Restoring
        // `child_vars` per function only left the inner binding in place, and the trailing
        // attribute was filed under a node the parser never reads it from — a tree that
        // disagrees with the source about structure, not just about strictness.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("outer");
                 { let x = e.child("inner"); x.attrString("inside"); }
                 x.attrString("outside"); }"#,
            "e",
        );
        let paths = placed_paths(&r);
        assert!(
            paths.contains(&"outer/outside".to_string()),
            "the trailing read is the outer child's: {paths:?}"
        );
        assert!(
            !paths.contains(&"inner/outside".to_string()),
            "and not the shadow's: {paths:?}"
        );
    }

    #[test]
    fn a_child_bound_by_var_in_a_block_outlives_it() {
        // The other direction: `var` is function-scoped, so a child it binds inside a block
        // is still that name afterwards. Snapshotting the whole map per block would restore
        // this one too and lose the read.
        let r = analyze_parser_ast(
            r#"{ { var y = e.child("late"); }
                 y.attrString("after"); }"#,
            "e",
        );
        let paths = placed_paths(&r);
        assert!(
            paths.contains(&"late/after".to_string()),
            "`var` outlives the block: {paths:?}"
        );
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
    #[test]
    fn a_tagged_template_supplies_its_strings_object() {
        // A tag is called with the strings object and then the substitutions, so parameter 0 is
        // ALWAYS supplied and its default runs for nobody. The round that taught this reader
        // tagged templates handed the mapping an empty argument list and said in a comment that
        // "a default this cannot rule out simply runs" — which recorded a write no execution
        // performs, so `parse` was read against a node the model had moved on paper only.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {})`t`; parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the strings object supplies that parameter: {fields:?}"
        );
        // The bounds: only the positions the template really fills. A second parameter with no
        // substitution behind it still runs its default, a substitution supplies the position
        // after the strings object, and a substitution spelling `undefined` supplies nothing.
        for body in [
            "var current = e; (function (a, x = (current = other)) {})`t`; parse(current);",
            "var current = e; (function (a, x = (current = other)) {})`t${void 0}`; parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that default still runs: {body}"
            );
        }
        let fields = helper_reached_via(
            "var current = e; (function (a, x = (current = other)) {})`t${1}`; parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the substitution fills that position: {fields:?}"
        );
    }

    #[test]
    fn a_templates_substitutions_run_before_its_tag() {
        // Every substitution is evaluated before the tag is called, so the body reads what they
        // wrote. Visiting the quasi after the invocation ordered them by their own position,
        // which is below the tag — the body was read against a write that had already run.
        let fields = helper_reached_via(
            "var current = e; (function () { parse(current); })`t${current = other}`;",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the substitution already replaced it: {fields:?}"
        );
        // The bound: the body's own write still lands at the call, as it does for a `()` call.
        let fields = helper_reached_via(
            "var current = e; (function () { current = other; })`t`; parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the tag body ran before `parse`: {fields:?}"
        );
        // And the second bound, which is a decline rather than an answer: a tag reached through
        // `.call` invokes `Function.prototype.call`, whose reshaping of the strings object is
        // not the reshaping an argument list gets. That is not modelled, so the invocation is
        // declined and the write is lost — never inverted.
        let fields = helper_reached_via(
            "var current = e; (function () { current = other; }).call`t`; parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "declined rather than mapped wrongly: {fields:?}"
        );
    }

    #[test]
    fn a_class_extending_null_initializes_no_fields() {
        // `extends null` defines a legal class and constructs none: the derived constructor's
        // `super()` — here the implicit one — calls `null` and throws before a field
        // initializes. The implicit-constructor shortcut read a missing constructor as
        // `super(...a)` and therefore as successful, recording a write that happens on no path.
        let fields = helper_reached_via(
            "var current = e; try { new (class extends null { x = (current = other) })() } catch (_) {} parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that construction throws: {fields:?}"
        );
        // The bound: a heritage that really is a constructor still installs its fields.
        let fields = helper_reached_via(
            "var current = e; new (class extends (function(){}) { x = (current = other) })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "an ordinary derived class still runs them: {fields:?}"
        );
    }

    #[test]
    fn a_static_block_that_throws_ends_the_static_phase() {
        // Class definition evaluates static blocks and static initializers in source order and
        // stops at the first abrupt completion, so nothing static below a block that throws is
        // evaluated at all. The element loop walked every one of them.
        let fields = helper_reached_via(
            "var current = e; try { class C { static { throw 0 }; static x = (current = other) } } catch (_) {} parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the phase stopped above that initializer: {fields:?}"
        );
        // The bounds: a block that completes normally stops nothing, and an element written
        // ABOVE the throwing block has already run.
        for body in [
            "var current = e; try { class C { static { 0 }; static x = (current = other) } } catch (_) {} parse(current);",
            "var current = e; try { class C { static x = (current = other); static { throw 0 } } } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that initializer does run: {body}"
            );
        }
    }

    #[test]
    fn the_binding_destructures_the_argument_when_one_is_supplied() {
        // Parameter binding takes apart ONE object: the argument when the call supplies it, the
        // parameter's own default only when it does not. Listing both and searching the default
        // first selected a getter that never runs and left the supplied one — the one that does
        // — deferred.
        //
        // I removed the guard that decided this two rounds ago, calling it inert on the
        // reasoning that a suppressed initializer is never walked. Unreachable is not harmless:
        // it still won the lookup. No mutation of mine could show it, because no test until this
        // one named the same property in both objects.
        let fields = helper_reached_via(
            "var current = e; (function ({x} = {get x(){ current = third }}) {})({get x(){ current = other }}); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the supplied getter is the one that runs: {fields:?}"
        );
        // The bound, which is round forty-two's answer and still holds: with no argument at all
        // the default object is the one taken apart, so ITS getter is the one that runs.
        let fields = helper_reached_via(
            "var current = e; (function ({x} = {get x(){ current = other }}) {})(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the default's getter runs when nothing is supplied: {fields:?}"
        );
    }

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

    /// `(field is required, its helper's guard is published)` for a callback body that
    /// reaches `parse` — which both reads `id` and asserts `kind`. The two travel together or
    /// the shape contradicts itself, so both are read from one run.
    pub(super) fn guards_and_field(body: &str) -> (bool, bool) {
        let module = format!(
            r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){{
            function parse(p){{ p.assertAttr("kind", "x"); p.attrString("id"); }}
            var c=new(r("WADeprecatedWapParser"))("p", function(e){{
                e.assertTag("receipt");
                {body}
            }});
        }}),1);"#
        );
        let out = parse_module_wap_parsers(&module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let required = p
            .fields
            .iter()
            .find(|f| f.name == "id")
            .expect("recovered")
            .required;
        let guarded = p
            .assertions
            .iter()
            .any(|a| a.name.as_deref() == Some("kind"));
        (required, guarded)
    }

    #[test]
    fn a_destructured_formal_does_not_shift_the_node_position() {
        // `function parse({opts}, node)` has the node SECOND. Collecting only the formals
        // that have a name slid it to index 0, so the call's second argument found no
        // formal and the helper's reads left the shape — silently, which is the half that
        // makes the drop accounting a lie.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse({opts}, node){ node.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    parse(cfg, row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the node is the second formal: {:?}",
            row.children
        );
    }

    #[test]
    fn a_node_handed_to_a_destructured_formal_is_counted_not_dropped() {
        // The other side: when the node lands ON the pattern there is no name to analyse
        // the body against, and stopping there has to be recorded like every other bounded
        // exit on this path.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse({node}){ node.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    parse(row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "nodeBoundByPattern@parse"),
            "the stop is counted: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_helper_handed_an_alias_of_the_node_is_still_followed() {
        // `var current = row; parse(current)` matched no argument position, so the helper
        // was never entered — its fields simply were not in the shape, and no drop was
        // recorded either, which is the worse half: the extraction looked complete.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current = row;
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the alias is the node: {:?}",
            row.children
        );
    }

    #[test]
    fn a_nested_functions_alias_does_not_answer_for_this_node() {
        // `current` is bound only inside `f`, so the outer `parse(current)` was never handed
        // the row. A flat alias list made the pair visible anyway and filed `leaked` under
        // `<row>`. I wrote the extent filter for this, could not reproduce it with two
        // sibling MAPPED callbacks — which are analysed over their own sources — and removed
        // it as untestable. A nested plain function shares the collection; it reproduces.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("leaked"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    function f(){ var current = row; current.attrString("inner"); }
                    f();
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let leaked = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "leaked"));
        assert!(
            !leaked,
            "the nested function's alias is not this scope's: {:?}",
            row.children
        );
    }

    #[test]
    fn an_alias_made_by_plain_assignment_is_followed_too() {
        // `var current; current = row` aliases as much as the declarator form does. Reading
        // only initializers left this matching no argument position, losing the helper with
        // nothing recorded — and the aliasing assignment must not count as the write that
        // invalidates the alias it just made.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current;
                    current = row;
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the assigned alias is the node: {:?}",
            row.children
        );
    }

    #[test]
    fn an_assignment_in_a_function_that_may_never_run_does_not_move_the_node() {
        // `var current = e; function mutate(){ current = other; } parse(current)` — nothing calls
        // `mutate`, so `current` still stands for the element and the helper's fields are
        // recoverable. Letting every write to a top-level binding escape its function extent —
        // which is what I shipped one commit earlier to fix the IIFE case — counted this one as
        // an effective second value and lost the fields silently.
        //
        // An IIFE is the case syntax decides; anything else is call-graph work this scanner does
        // not do, so only an IIFE escapes.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var current = e;
                function mutate(){ current = other; }
                parse(current);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the alias still stands: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_write_in_a_class_heritage_expression_moves_the_node() {
        // `class C extends (current = other, Base) {}` performs that assignment before anything
        // after the class runs, so `current` no longer names the element. The binding collector
        // walked only the class BODY, so the write was invisible and `names_for` followed the
        // stale `current = e` — filing the helper's `id` at the response root, which is the
        // wrong-node direction. A hand-written visitor that enumerated the parts of a class it
        // happened to think of; the heritage is the one carrying a runtime expression outside
        // the body.
        let fields = helper_reached_via(
            r#"var current = e; class C extends (current = other, Base) {} parse(current);"#,
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "not at the root, which the parser never reads it from: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_class_with_no_heritage_still_leaves_its_alias_alone() {
        // The bound: a class that assigns nothing moves nothing, so the alias still stands and
        // the helper's fields are recovered. Walking a class as though it always wrote to
        // everything would lose them.
        let fields = helper_reached_via(r#"var current = e; class C {} parse(current);"#);
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the alias is untouched: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_alias_assigned_down_one_path_does_not_require_what_it_reads() {
        // `var current; if (flag) current = e; parse(current)` reaches `parse` with the element
        // only when `flag` held, so what the helper reads there is not read on every execution.
        // The CALL is unconditional, so `conditional_depth` says nothing about it, and one
        // in-scope value ordered before the call looked as definite as any other — requiring
        // `id` of every response, which rejects the ones the other path returns.
        //
        // Recovered and relaxed, not dropped: the field is real, it is just optional.
        for body in [
            "var current; if (flag) current = e; parse(current);",
            "var current; for (var k of ks) { current = e; } parse(current);",
            "var current; flag && (current = e); parse(current);",
            "var current; switch (m) { case 1: current = e; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            let id = fields
                .iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` still recovers the field"));
            assert!(!id.required, "`{body}` assigns it only on one path");
        }
    }

    #[test]
    fn an_alias_assigned_on_every_path_still_requires_it() {
        // The bound, and the reason this asks per PART of a construct: an assignment in a loop
        // header or an `if` TEST runs whatever happens, and a plain one obviously does. Calling
        // every assignment uncertain would relax reads the parser always performs.
        for body in [
            "var current; current = e; parse(current);",
            "var current; if (current = e) { other(); } parse(current);",
            "var current; while ((current = e) && 0) { } parse(current);",
            "var current; for (current = e; 0; ) { } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            let id = fields
                .iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` recovers the field"));
            assert!(id.required, "`{body}` assigns it on every path");
        }
    }

    #[test]
    fn a_conditional_alias_elsewhere_does_not_relax_the_node_itself() {
        // Per argument, not per call: `parse(e)` is handed the parameter, which is bound before
        // the body runs. An unrelated conditional alias in the same function says nothing about
        // it, and asking the question of the whole alias set would have relaxed this.
        let fields = helper_reached_via("var current; if (flag) current = e; parse(e);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the parameter is not conditional");
    }

    #[test]
    fn a_write_inside_a_function_nobody_calls_stays_there() {
        // An IIFE inside a function nothing invokes has not run either, so the write is confined
        // and the alias still stands. The narrowing that let only an IIFE escape asked about the
        // INNERMOST function alone, so one level of nesting was enough to make the write look
        // top-level — and the descent was refused for a node nothing had moved, silently.
        let fields = helper_reached_via(
            "var current = e; function unused(){ (function(){ current = other; })(); } parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the alias is untouched: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_write_in_an_iife_nothing_encloses_still_moves_the_node() {
        // The bound: with every function on the chain immediately invoked, the write certainly
        // ran. Confining every captured write would put the helper's fields back at the wrong
        // node, which is the direction the escape rule exists to stop.
        let fields = helper_reached_via(
            "var current = e; (function(){ current = other; })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the IIFE moved it: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_iife_body_runs_after_the_arguments_it_is_passed() {
        // JavaScript evaluates every argument before entering the callee, so
        // `(function(){ current = other; })(parse(current))` hands `parse` the ORIGINAL node.
        // The write was ordered by its position inside the callee — textually before the
        // argument — so it looked already effective and the descent was refused for a node
        // still standing, silently. The one place where source order and run order disagree
        // within a single expression.
        for body in [
            "var current = e; (function(){ current = other; })(parse(current));",
            "var current = e; (() => { current = other; })(parse(current));",
            "var current = e; (function(){ (function(){ current = other; })(); })(parse(current));",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` passes the untouched node"));
            assert!(id.required, "`{body}` reads it on every execution");
        }
    }

    #[test]
    fn an_argument_runs_before_the_body_it_is_passed_to() {
        // The other half of the same ordering, and the one that was wrong in the harmful
        // direction: `(function(){ parse(current); })(current = other)` evaluates the argument
        // FIRST, so the body reads what it assigned. The write is textually after the read, so
        // position alone called it not-yet-effective and the helper's fields were filed under
        // the node the parser had already replaced — and marked required, at that.
        //
        // A record now carries the region it precedes whatever its position, the same escape
        // hatch a write inside a loop has always had. The node the argument assigns is not one
        // this scan tracks, so the honest outcome is that the fields go nowhere rather than
        // somewhere wrong.
        for body in [
            "var current = e; (function(){ parse(current); })(current = other);",
            "var current = e; ((current) => { parse(current); })(other);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` reads a node this scan cannot place: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_write_inside_an_invoked_body_is_effective_inside_it() {
        // The other side of moving an invoked body's effects to the call, and a regression I
        // introduced doing it: `(function(){ current = other; parse(current); })()` hands
        // `parse` the NEW node, and pinning the write to the call end made it look not-yet-
        // effective at a read in that same body — so the helper's fields were published on the
        // node the write had moved away from.
        //
        // Where an effect lands depends on who is observing. Inside the body it happened where
        // it is written; outside — an argument, or anything after the call — it happened at the
        // invocation. One position could not say both, which is the same shape as the class
        // two-phase clock declined earlier in this PR, and the reason that one is declined is
        // that its observers cannot be told apart this cleanly.
        let fields = helper_reached_via(
            "var current = e; (function(){ current = other; parse(current); })();",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the write precedes the read in its own body: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_invoked_body_still_lands_at_the_call_for_everyone_else() {
        // The bounds, and all three are cases earlier rounds established. A read EARLIER in the
        // same body still precedes the write; an argument still runs before the whole body; and
        // a read after the call still sees what the body did.
        let id = helper_reached_via(
            "var current = e; (function(){ parse(current); current = other; })();",
        )
        .into_iter()
        .find(|f| f.name == "id")
        .expect("the read precedes the write");
        assert!(id.required, "and it reads the original node");
        for body in [
            "var current = e; (function(){ current = other; })(); parse(current);",
            "var current = e; (function(){ parse(current); })(current = other);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` reads the node the write moved to: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_loop_that_cannot_come_round_again_carries_no_write() {
        // `do { parse(current); current = other; break; } while (flag)` hands `parse` the
        // original node every time, because the `break` is reached on every path and no next
        // iteration exists to see that write. The repetition shortcut — a write below the call
        // runs before it on the next pass — applied to every write inside a loop span, so this
        // alias was refused and the helper's fields dropped.
        for body in [
            "var current = e; do { parse(current); current = other; break; } while (flag);",
            "var current = e; while (!0) { parse(current); current = other; break; }",
            "var current = e; do { parse(current); current = other; return t; } while (flag);",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` never repeats"));
            assert!(id.required, "`{body}` reads the original node");
        }
    }

    #[test]
    fn a_loop_that_does_repeat_still_carries_it() {
        // The bounds. A body that can come round again really does run the write before the
        // call on the next pass, so the alias stays refused — that is what the shortcut exists
        // for. A `continue` is not a way out: it starts the next pass, which is precisely when
        // the write is seen. And a non-repeating loop inside one that repeats is carried by the
        // outer one.
        for body in [
            "var current = e; do { parse(current); current = other; } while (flag);",
            "var current = e; do { parse(current); current = other; continue; } while (flag);",
            "var current = e; while (flag) { do { parse(current); current = other; break; } while (0); }",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` sees the write on a later pass: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn an_argument_that_writes_still_runs_where_it_is_written() {
        // The bound: only the CALLEE's effects move to the call. An argument runs in its own
        // place, before the ones after it and before the body — pinning every write inside the
        // call expression to the call would order this one after a read it precedes, which is
        // the same wrong-node mistake pointing the other way.
        let fields = helper_reached_via(
            "var current = e; (function(){})((current = other), parse(current));",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the earlier argument moved it: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        // And the other way round: a read in an EARLIER argument runs before a later argument's
        // write, so the node it is handed is the untouched one. The region a write precedes is
        // the callee's body alone — widening it to the whole call would swallow this.
        let fields =
            helper_reached_via("var current = e; (function(){})(parse(current), current = other);");
        assert!(
            fields.iter().any(|f| f.name == "id" && f.required),
            "the write is in a later argument: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn calling_a_function_is_not_always_running_its_body() {
        // Two spellings where the call returns before the body does the writing. A generator
        // call builds an iterator and runs nothing at all; an `async` body stops at its first
        // `await` and hands control back, so the caller's next statement runs before the rest
        // of it. Both were read as "certainly ran by the time anything after the call reads
        // it", so a still-valid alias was refused and the helper's fields were lost — the same
        // mistake the `unused` narrowing was written for, on the two forms of a call that does
        // not run to the end.
        for body in [
            "var current = e; (function*(){ current = other; })(); parse(current);",
            "var current = e; (async function(){ await x; current = other; })(); parse(current);",
            "var current = e; (async () => { await x; current = other; })(); parse(current);",
            "var current = e; (async function(){ for await (var q of xs) {} current = other; })(); parse(current);",
            // The FIRST suspension ends the synchronous part, whatever comes after it.
            "var current = e; (async function(){ await x; current = other; await y; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` leaves the alias standing: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn what_an_async_body_does_before_its_first_await_has_run() {
        // The bound, and why the region is positional rather than the whole function: an
        // `async` body runs synchronously up to its first suspension, so a write BEFORE the
        // `await` has happened by the time the call returns and confining it would put the
        // helper's fields at the node the write moved away from. An `await` inside a nested
        // function is that function's suspension and does not shorten this one.
        for body in [
            "var current = e; (async function(){ current = other; await x; })(); parse(current);",
            "var current = e; (async () => { current = other; await x; })(); parse(current);",
            "var current = e; (async function(){ (async function(){ await x; })(); current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` moved the node before returning: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_loop_that_must_start_assigns_before_anything_can_jump_past_it() {
        // `do { current = e; break; } while (0)` is the minifier's one-shot block, and the write
        // at the top of it runs on every execution — the guaranteed first pass the requiredness
        // walk has read in order since `walk_guaranteed_pass` was written. This collector called
        // the whole body skippable and declined the question as too hard to answer, so the two
        // halves disagreed about the same statement and the field came out optional anyway. Every
        // loop whose entry is decidable, since one predicate now answers for all of them.
        for body in [
            "var current; do { current = e; break; } while (0); parse(current);",
            "var current; do current = e; while (0); parse(current);",
            "var current; while (!0) { current = e; break; } parse(current);",
            "var current; for (;;) { current = e; break; } parse(current);",
            "var current; for (; !0; ) { current = e; break; } parse(current);",
            "var current; for (var q of [1, 2]) { current = e; break; } parse(current);",
            "var current; do { if (bad) throw Error(); current = e; } while (0); parse(current);",
            "var current; do { g(); } while (current = e); parse(current);",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` moved the node instead"));
            assert!(id.required, "`{body}` assigns on every execution");
        }
    }

    #[test]
    fn a_loop_that_may_not_start_assigns_nothing_for_certain() {
        // The bounds, and why the guarantee is read off the same `always_true` the requiredness
        // side uses rather than assumed for every loop: a tested loop has a zero-iteration path,
        // an iterable of unknown length may be empty, and a write past something that can leave
        // the body is a write some pass skipped. The `do` test is reached only by a pass that
        // did not leave first, so a write THERE is uncertain too.
        for body in [
            "var current; while (f) { current = e; break; } parse(current);",
            "var current; for (; f; ) { current = e; break; } parse(current);",
            "var current; for (var q of xs) { current = e; break; } parse(current);",
            "var current; do { if (f) break; current = e; } while (0); parse(current);",
            "var current; do { break; } while (current = e); parse(current);",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` moved the node instead"));
            assert!(!id.required, "`{body}` has a path that assigns nothing");
        }
    }

    #[test]
    fn a_negative_range_bound_is_a_bound_and_not_an_absent_one() {
        // JavaScript has no negative literal: `-10` is a unary minus over `10`, so matching
        // `NumericLiteral` recorded NO floor. That is not neutral — an absent floor beside a
        // present ceiling is the open-bottom band, which the width rule reads as "signed, no
        // lower limit", so the emitted decoder took a `-20` the accessor turns away. The
        // opposite of what the bound is for, and reachable only for a negative one.
        let r = analyze_parser_ast(
            r#"{ e.attrIntRange("weight", -10, 10); e.attrIntRange("count", 1, 10);
                 e.attrIntRange("ratio", 1.5, 10); }"#,
            "e",
        );
        let band = |n: &str| {
            r.fields
                .iter()
                .find(|f| f.name == n)
                .map(|f| (f.int_min, f.int_max))
                .expect("field")
        };
        assert_eq!(
            band("weight"),
            (Some(-10), Some(10)),
            "the floor is negative"
        );
        assert_eq!(
            band("count"),
            (Some(1), Some(10)),
            "an ordinary pair is unchanged"
        );
        // A fractional floor is one this scan cannot represent, and the round after this one
        // established what that has to mean: not "no floor" — which is the open-bottom band and
        // would be the very over-acceptance being fixed here — but no range at all, with a drop
        // saying so. The cast this replaced truncated it to `1` and published a band the source
        // never enforces.
        assert_eq!(band("ratio"), (None, None), "1.5 is not an integer bound");
    }

    #[test]
    fn a_bound_this_scan_cannot_read_is_not_an_absent_one() {
        // `attrIntRange("score", minimum, 10)` declares a floor whose value only the running
        // module knows. Recording it as `None` made it indistinguishable from the open-bottom
        // band — so the field came out signed and guarded by its maximum alone, and the decoder
        // took a `-1` that a `minimum` of 5 turns away. The same collision as a negative
        // literal read as absent, from the other side.
        //
        // Neither bound is kept when either is unreadable: half of a range the source enforces
        // is a claim this scan cannot stand behind.
        let r = analyze_parser_ast(
            r#"{ e.attrIntRange("score", minimum, 10); e.attrIntRange("span", 1, hi); }"#,
            "e",
        );
        for name in ["score", "span"] {
            let f = r.fields.iter().find(|f| f.name == name).expect("field");
            assert_eq!(
                (f.int_min, f.int_max),
                (None, None),
                "`{name}` has a bound this scan cannot read"
            );
            assert!(
                r.unresolved
                    .iter()
                    .any(|u| u == &format!("unreadableRangeBound@{name}")),
                "and the drop says so: {:?}",
                r.unresolved
            );
        }
    }

    #[test]
    fn a_bound_the_source_declares_open_stays_open() {
        // The bound, and the reason unreadable and open cannot simply be merged: WA writes
        // `attrIntRange(e, "t", 0, void 0)` for "no upper limit", and declining that range
        // would throw away a floor the accessor really does enforce. `undefined` and `null`
        // spell the same thing.
        for spelling in ["void 0", "undefined", "null"] {
            let r = analyze_parser_ast(
                &format!(r#"{{ e.attrIntRange("t", 0, {spelling}); }}"#),
                "e",
            );
            let f = r.fields.iter().find(|f| f.name == "t").expect("field");
            assert_eq!(
                (f.int_min, f.int_max),
                (Some(0), None),
                "`{spelling}` is an open bound, not an unreadable one"
            );
            assert!(
                r.unresolved.is_empty(),
                "nothing dropped: {:?}",
                r.unresolved
            );
        }
    }

    #[test]
    fn a_function_invoked_with_new_has_run_too() {
        // `new (function(){ current = other; })()` runs that body before the next statement
        // exactly as a call does. Only calls were read that way, so the write stayed confined
        // to the function extent and the helper's fields were published on the node the parser
        // had moved away from — the wrong node, and the second spelling of an invocation this
        // collector had to learn separately.
        for body in [
            "var current = e; new (function(){ current = other; })(); parse(current);",
            "var current = e; new (0, function(){ current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` moved the node: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
        // The bound: `new Thing()` names a constructor this scan knows nothing about, and
        // guessing that it writes would refuse every descent past one.
        let fields = helper_reached_via("var current = e; new Thing(); parse(current);");
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "an unknown constructor moves nothing: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_destructuring_declaration_writes_what_it_takes_apart() {
        // `var [e] = [other]` rebinds the parser's own parameter, and `for (var [e] of xs)`
        // does it once per pass. Only the single-identifier declarator recorded anything, so
        // the name still looked like the response node and the helper's reads were filed at the
        // root while the parser reads something else. The ASSIGNMENT spelling of this was fixed
        // six rounds ago; this is the declaration spelling of the same write.
        for body in [
            "var [e] = [other]; parse(e);",
            "var {e} = o; parse(e);",
            "for (var [e] of xs) {} parse(e);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` reads a node this scan cannot place: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
        // The bounds: an undisturbed parameter still is the node, and a `let` pattern binds its
        // own names rather than writing to anything outside itself.
        for body in ["parse(e);", "{ let [e] = [other]; } parse(e);"] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` leaves the parameter standing: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_negated_truthy_literal_selects_its_side_too() {
        // `if (!1) { … } else { parse(e); }` runs the else on every execution. The pair of
        // literal evaluators had the negation on ONE side, so this intersected the reads with a
        // side nothing reaches and left what the parser always performs optional. They are each
        // other's mirror and now say so.
        for body in [
            "if (!1) { other(); } else { parse(e); }",
            "if (!0) { parse(e); } else { other(); }",
            "if (0) { other(); } else { parse(e); }",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` reaches parse"));
            assert!(id.required, "`{body}` selects the reachable side");
        }
        // The bound: an ordinary test is still a branch, and both sides stay conditional.
        let id = helper_reached_via("if (flag) { other(); } else { parse(e); }")
            .into_iter()
            .find(|f| f.name == "id")
            .expect("recovered");
        assert!(!id.required, "an undecided test is still a branch");
    }

    #[test]
    fn a_comma_wrapped_callee_is_still_immediately_invoked() {
        // `(0, function(){ current = other; })()` is how a minifier calls a function with
        // `this` unbound. The matcher unwrapped parentheses only, so that body was classified
        // as one nobody calls: the write stayed confined and the helper's fields were published
        // on the node the parser had already moved away from — the wrong node, confidently.
        for body in [
            "var current = e; (0, function(){ current = other; })(); parse(current);",
            "var current = e; (0, 1, () => { current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` moved the node: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
        // And what the comma evaluates on the way to the function keeps its own position: it
        // runs before the call, and before the arguments. Pinning it to the call the way the
        // BODY's writes are pinned reads it as later than an argument it precedes, which is the
        // wrong node again — so the read has to sit in an argument to tell the two apart.
        for body in [
            "var current = e; ((current = other), function(){})(parse(current));",
            "var current = e; ((current = other), function(){})(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` moved the node before the read: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_static_block_binds_its_own_lexical_names() {
        // `class C { static { let current = other; } }` binds a NEW `current` that dies with
        // the block. Walking it generically recorded that value against the OUTER binding, so
        // the name had two live values, the alias was refused, and every field the helper reads
        // left the shape with nothing recorded.
        let fields = helper_reached_via(
            "var current = e; class C { static { let current = other; } } parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the inner binding is its own: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        // The bound: a static block runs when the class is DEFINED, so an assignment to the
        // captured outer name really does move the node.
        let fields = helper_reached_via(
            "var current = e; class C { static { current = other; } } parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the outer name was assigned: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_finalizer_exit_nothing_reaches_does_not_override() {
        // `finally { throw Error(); return fallback; }` never reaches that `return`, and asking
        // `any` of the whole list called the finalizer one that hands a result back — so a
        // `try` that really does throw counted as a value path and diluted the intersection
        // around it. Walked in order now, stopping where control does.
        assert_eq!(
            guards_and_field(
                "if (flag) { try { other(); } finally { throw Error(); return fallback; } }
                 else { parse(e); }"
            ),
            (true, true),
            "the return is unreachable"
        );
        // The bound: a return the finalizer does reach still overrides whatever was thrown.
        assert_eq!(
            guards_and_field(
                "if (flag) { try { other(); } finally { return fallback; } } else { parse(e); }"
            ),
            (false, false),
            "the finalizer hands back a result"
        );
    }

    #[test]
    fn a_write_control_cannot_reach_moves_nothing() {
        // Everything after an unconditional `return` or `throw` in the same list is unreachable,
        // and nothing modelled that: `dead` is computed per statement and asks only whether THAT
        // statement throws. A handler makes a throwing path resume, so a write before the throw
        // really did happen — but nothing makes a statement after the transfer run, which is why
        // unreachability outranks the catch suppression rather than sharing it.
        for body in [
            "var current = e; try { throw Error(); current = other; } catch (_) {} parse(current);",
            "var current = e; if (flag) { return t; current = other; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` never runs the write: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_write_past_a_break_or_continue_moves_nothing() {
        // `do { break; current = other; } while (0)` can never run that assignment. The in-order
        // walk was asking `exits_unconditionally`, which answers a DIFFERENT question for the
        // dispatch chain — there an unlabelled `break` leaves only the nearest loop or switch and
        // says nothing about the arms after it, so it does not count. Here the list IS that loop's
        // body. Reusing the predicate covered `return` and `throw` and left both transfers out.
        for body in [
            "var current = e; do { break; current = other; } while (0); parse(current);",
            "var current = e; for (var i = 0; i < 2; i++) { continue; current = other; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` never runs the write: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_break_a_label_opens_inside_the_statement_does_not_end_the_list() {
        // `local: { break local; }` lands at the end of its own labelled block, and the list
        // carries on. Counting it as an exit marked the assignment after it unreachable, so the
        // alias it makes was never recorded and the helper's fields were dropped silently. The
        // dispatch predicate has scoped its labels since the round that fixed it; this one was
        // written after that and asked without the set.
        for body in [
            "var current; local: { break local; } current = e; parse(current);",
            "var current; local: { if (f) break local; } current = e; parse(current);",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` runs the assignment after the label"));
            assert!(id.required, "`{body}` assigns on every execution");
        }
    }

    #[test]
    fn a_break_naming_a_label_from_outside_still_ends_it() {
        // The bounds, and why the labels have to be carried rather than labelled breaks simply
        // excused: `break outer` from inside `local:` leaves both, so the assignment after
        // `local:` really is unreachable. An unlabelled `break` belongs to the nearest loop or
        // switch and ends the list it sits in, which is the case this predicate was added for.
        for body in [
            "var current = e; outer: { local: { break outer; } current = other; } parse(current);",
            "var current = e; do { break; current = other; } while (0); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` never runs the write: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_break_a_nested_loop_consumes_does_not_end_the_outer_list() {
        // The other bound on the same rule, and the one the dispatch predicate gets right for its
        // own reasons: an unlabelled transfer is consumed by the nearest loop or switch, so a
        // `break` inside one says nothing about the list the loop itself sits in. `do { while (c)
        // { break; } current = other; } while (0)` really does run that assignment.
        // A `return` inside that loop is the case that actually distinguishes the two answers: the
        // loop may run zero times, so the statement after it still runs, and reading "this
        // statement can be left" as "this list ends here" would call the write unreachable.
        for body in [
            "var current = e; do { while (c) { break; } current = other; } while (0); parse(current);",
            "var current = e; do { while (c) { return t; } current = other; } while (0); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` still runs the write: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_write_before_a_break_still_moves_the_node() {
        // The bound: the transfer ends what FOLLOWS it, not what precedes it.
        let fields = helper_reached_via(
            "var current = e; do { current = other; break; } while (0); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the write ran before the break: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_write_before_a_caught_throw_still_moves_the_node() {
        // The bound, and the reason the two counters are separate: this write DOES run, the
        // handler resumes after it, and the node is moved by the time the helper is called.
        let fields = helper_reached_via(
            "var current = e; try { current = other; throw Error(); } catch (_) {} parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the write ran before the throw: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_instance_field_initializer_writes_nothing_by_existing() {
        // `class C { value = (current = other) }` evaluates that initializer per `new`, of which
        // there may be none — so defining the class moves nothing. Walking every property value
        // recorded the write as effective and refused a valid descent.
        // `accessor value = …` is the same field with a getter and a setter generated for it,
        // and it was not one of the two spellings this visitor listed — so it fell through to
        // the generic walk and its initializer WAS recorded as effective at definition. Which
        // is what enumerating the parts of a class by hand costs every time one is missed.
        for body in [
            "var current = e; class C { value = (current = other) } parse(current);",
            "var current = e; class C { accessor value = (current = other); } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "`{body}` assigns nothing by existing: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn what_a_class_evaluates_when_defined_still_moves_the_node() {
        // The bounds, and they are the whole reason this is per element rather than per class: a
        // STATIC initializer and a COMPUTED KEY are evaluated once, when the class is defined, so
        // both really do move the node. Skipping the body wholesale would lose them.
        for body in [
            "var current = e; class C { static value = (current = other) } parse(current);",
            "var current = e; class C { [(current = other)]() {} } parse(current);",
            "var current = e; class C { static accessor value = (current = other); } parse(current);",
            "var current = e; class C { accessor [(current = other)] = 1; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` runs at definition: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_declaration_inside_a_nested_function_binds_its_own_name() {
        // The complement of the case below, one keyword apart: `(function(){ var current = … })()`
        // binds a NEW `current` for that function, so the outer one still stands for the element
        // and `parse(current)` hands over the response root.
        //
        // Its value was recorded before the walk registered the binding, so the lookup that
        // decides how far a value reaches found no `current` in scope yet, fell back to the
        // top-level binding — which reaches all of the source — and counted two values live at
        // the call. `names_for` follows a copy only when exactly one is, so the alias was refused
        // and the helper's fields left the shape with nothing recorded. `let` was unaffected: it
        // takes its extent from the enclosing block directly and never consults the lookup,
        // which is the asymmetry that located this. `binding_extent`'s own doc claimed the order
        // already held, and it held for every assignment and not for the declarator itself.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var current = e;
                (function(){ var current = e.child("detail"); })();
                parse(current);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the outer alias is untouched: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_assignment_inside_a_nested_function_reaches_the_outer_binding() {
        // `var current = e; (function(){ current = e.child("detail"); })(); parse(current)` —
        // the IIFE definitely updates the OUTER `current`, so it no longer stands for the
        // element. That binding lives in `names` rather than `scoped`, and the extent fell back
        // to the innermost function: the write looked confined to the IIFE and expired at the
        // call, so `names_for` followed the stale `current = e` alias and filed `id` at the
        // response root. Wrong-node, which is the direction that matters.
        //
        // Recovering it UNDER `<detail>` is a separate thing: `child_vars` is updated by a
        // declarator only, deliberately, so an assigned child is not tracked. This asserts the
        // misplacement is gone, not that the field is back.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var current = e;
                (function(){ current = e.child("detail"); })();
                parse(current);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.fields.iter().any(|f| f.name == "id"),
            "not at the root, where the parser never reads it: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_block_local_copy_does_not_name_the_node_outside_its_block() {
        // `{ let current = row; } parse(current)` calls the helper with the OUTER `current`,
        // whatever that is — the block-local copy died with its block. Recording every copy
        // with the enclosing function extent had `names_for` follow the expired one and file
        // `id` under `<row>`, which is the harmful direction: consumers reject `<row>`
        // elements the parser accepts. `bind` already kept the lexical/hoisting split; the
        // value collector did not.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var current = t.somethingElse;
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    { let current = row; }
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(
            !at_root,
            "the block-local copy is out of scope: {:?}",
            row.children
        );
    }

    #[test]
    fn a_var_copy_in_a_block_still_names_the_node_after_it() {
        // The bound on that: `var` hoists out of the block, so `{ var current = row; }
        // parse(current)` really does hand the helper the row — treating every copy as
        // block-scoped would lose it, and silently.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    { var current = row; }
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "a hoisting copy outlives its block: {:?}",
            row.children
        );
    }

    #[test]
    fn an_alias_captured_before_the_node_moves_is_still_followed() {
        // `var original = row; row = row.child("detail"); parse(original)` — `original` still
        // names the row. Rejecting the whole call because the PARAMETER was written somewhere
        // in the function threw away fields that were recoverable, leaving only a drop marker.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var original = row;
                    row = row.child("detail");
                    parse(original);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the captured alias survives the parameter moving: {:?}",
            row.children
        );
    }

    #[test]
    fn a_long_alias_chain_is_followed_to_its_end() {
        // Nine copies. A fixed iteration count stopped short of the last one and lost the
        // helper silently; the set only ever grows, so it terminates on its own.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var a1 = row, a2 = a1, a3 = a2, a4 = a3, a5 = a4,
                        a6 = a5, a7 = a6, a8 = a7, a9 = a8;
                    parse(a9);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the ninth copy still names the node: {:?}",
            row.children
        );
    }

    #[test]
    fn a_tracked_child_that_is_reassigned_is_not_handed_on() {
        // `i = i.child("other")` leaves `child_vars["i"]` naming `<participants>`, so the
        // helper's fields landed under it. The own-node path was hardened against exactly
        // this and this one was not.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var i = e.child("participants");
                i = i.child("other");
                parse(i);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let participants = p.fields.iter().find(|f| f.name == "participants");
        let misplaced = participants
            .and_then(|f| f.children.as_ref())
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(
            !misplaced,
            "not the participants' attribute: {:?}",
            participants.and_then(|f| f.children.as_ref())
        );
    }

    #[test]
    fn an_alias_of_the_node_that_is_reassigned_is_not_followed() {
        // An alias only stands for the node while nothing has written to it. Following
        // `current` after `current = row.child("detail")` would file the helper's reads
        // under `<row>` when the parser reads them off `<detail>`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current = row;
                    current = row.child("detail");
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(!at_root, "the write breaks the alias: {:?}", row.children);
    }

    #[test]
    fn an_alias_destructured_into_is_not_followed_either() {
        // `[current] = [row.child("detail")]` moves `current` as surely as a plain
        // assignment does, but records no VALUE for it — so counting values alone still
        // called `current` a copy of `row` and filed `id` at the row root, where the parser
        // never reads it. That is the harmful direction: consumers reject `<row>` elements
        // the parser accepts.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current = row;
                    [current] = [row.child("detail")];
                    parse(current);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(
            !at_root,
            "the destructuring write breaks the alias: {:?}",
            row.children
        );
    }

    #[test]
    fn a_helper_handed_a_reassigned_node_declines_and_says_so() {
        // `row = row.child("detail"); parse(row)` hands the helper the DETAIL node, so its
        // reads belong under `<detail>`. The filter asked only whether an inner scope
        // rebound the name — an assignment binds nothing — so the reads were merged at the
        // element root and the response tree claimed the parser reads them off `<row>`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    row = row.child("detail");
                    parse(row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(!at_root, "not the row's own attribute: {:?}", row.children);
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "and the drop is counted rather than silent: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_helper_handed_the_untouched_node_still_descends() {
        // The other direction: without a write the descent is exactly as before, so the
        // reassignment check cannot cost the helper reads it used to recover.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    parse(row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the helper's read is the row's: {:?}",
            row.children
        );
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
    fn a_helper_in_a_controlling_expression_is_still_required() {
        // `switch (parse(e))` evaluates the discriminant to choose a case, and a loop test
        // runs before the first pass. Raising the counter around the WHOLE statement — the
        // first shape of this fix — relaxed those too, which is the harmful direction:
        // generated decoding then accepts nodes the parser turns away.
        for body in [
            "switch (parse(e)) { case 1: break; }",
            "while (parse(e)) { break; }",
            "for (var i = parse(e); i < 2; i++) { }",
            "for (var k in parse(e)) { }",
        ] {
            let fields = helper_reached_via(body);
            let id = fields.iter().find(|f| f.name == "id").expect("recovered");
            assert!(id.required, "always evaluated in `{body}`: {id:?}");
        }
    }

    #[test]
    fn a_try_without_a_catch_keeps_its_reads_required() {
        // `try { parse(e); } finally { … }` has no handler, so an error propagates out of
        // the parser: there is no path where the block failed and a result was still
        // produced. Weakening every `try` alike accepted what the source rejects.
        let fields = helper_reached_via("try { parse(e); } finally { cleanup(); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "nothing swallows the failure: {id:?}");
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
    fn a_helper_every_switch_case_calls_is_required_again() {
        // Exhaustive, and each arm calls it, so it runs on every successful path — the same
        // situation as a helper on both sides of an `if`, which is promoted back through an
        // intersection. The switch had no equivalent, so both weakened copies stayed weak.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": parse(e); break; default: parse(e); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "every path calls it: {id:?}");
    }

    #[test]
    fn a_switch_with_no_default_promotes_nothing() {
        // Without a `default` an unlisted value runs no case at all, so a helper in every
        // listed one still runs on no path for that value. Promoting would require of every
        // element a field the parser sometimes never reads.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": parse(e); break; case "b": parse(e); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the cases are not exhaustive: {id:?}");
    }

    #[test]
    fn a_helper_in_only_one_case_of_an_exhaustive_switch_stays_optional() {
        // The intersection is what makes this safe: `default` covering the rest does not make
        // one case's helper universal.
        let fields =
            helper_reached_via(r#"switch (mode) { case "a": parse(e); break; default: other(); }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "only one arm calls it: {id:?}");
    }

    #[test]
    fn a_do_while_test_after_a_continue_is_still_required() {
        // `continue` in a `do`/`while` transfers control TO the test, not past it, so
        // `do { continue; } while (parse(e))` evaluates `parse` on every execution that can
        // leave the loop at all. Counting it alongside `break` relaxed a read every successful
        // parse performs.
        for body in [
            "do { continue; } while (parse(e));",
            "do { if (f) continue; } while (parse(e));",
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (true, true), "`{body}` reaches the test");
        }
    }

    #[test]
    fn a_read_after_a_continue_in_a_do_while_is_not_required() {
        // And the other question, which wants the opposite answer about the same statement: a
        // `continue` DOES skip the rest of the body, so what follows it is on a path some
        // successful pass took without it. Two questions, two answers, one keyword.
        let fields = helper_reached_via("do { if (f) continue; parse(e); } while (m);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the continue skips it: {id:?}");
    }

    #[test]
    fn a_do_while_test_behind_only_a_throw_is_still_required() {
        // `do { if (bad) throw Error(); } while (parse(e))` — the only path that skips the test
        // throws, so every execution producing a value evaluated `parse`. Treating every exit
        // alike weakened the test and called reads optional that every successful parse
        // performs.
        let guards = guards_and_field(r#"do { if (bad) throw Error("x"); } while (parse(e));"#);
        assert_eq!(guards, (true, true), "the skipping path yields nothing");
    }

    #[test]
    fn a_read_after_a_throw_in_a_do_while_is_still_required() {
        // The same distinction one statement over: what follows a possible throw is reached on
        // every path that hands anything back.
        let fields =
            helper_reached_via(r#"do { if (bad) throw Error("x"); parse(e); } while (m);"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "only a throw precedes it: {id:?}");
    }

    #[test]
    fn a_read_after_a_return_in_a_do_while_is_not_required() {
        // And the bound on that pair: a `return` hands back a result without reaching the read,
        // so it really is optional.
        let fields = helper_reached_via("do { if (done) return t; parse(e); } while (m);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the return skips it with a value: {id:?}");
    }

    #[test]
    fn a_do_while_test_behind_an_exit_is_not_required() {
        // `do { break; } while (parse(e))` never evaluates the test at all. Visiting it
        // unconditionally after the body — which the ordering fix introduced — recovered its
        // reads as required, so decoding rejected nodes on a constraint the parser never
        // checks. That is the harmful direction, unlike the body case it was fixing.
        let fields = helper_reached_via("do { break; } while (parse(e));");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break leaves before the test: {id:?}");
    }

    #[test]
    fn a_tested_for_loop_runs_its_body_before_its_update() {
        // `for (; more; parse(detail)) { var detail = e.child("detail"); }` binds `<detail>` in
        // the body and hands it to the helper in the update. Visiting the update first reached
        // `parse` before `child_vars` held the binding and lost the helper's fields entirely,
        // with nothing recorded.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                for (; more; parse(detail)) { var detail = e.child("detail"); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let detail = p
            .fields
            .iter()
            .find(|f| f.name == "detail")
            .expect("detail");
        assert!(
            detail
                .children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the body bound it before the update read it: {:?}",
            detail.children
        );
    }

    #[test]
    fn a_while_whose_test_cannot_be_false_still_runs_its_body_once() {
        // `while (!0)` is `for (;;)` spelled differently — and it is how this corpus spells it,
        // 74 times. Wrapping the body in a skipped path regardless of the test relaxed reads
        // every successful execution performs. All three spellings, braced and bare, plus the
        // same test in a `for` header, since one predicate now answers for both loops.
        for body in [
            "while (true) { parse(e); break; }",
            "while (!0) { parse(e); break; }",
            "while (1) { parse(e); break; }",
            "while (!0) parse(e);",
            "for (; !0 ;) { parse(e); break; }",
        ] {
            let fields = helper_reached_via(body);
            let id = fields.iter().find(|f| f.name == "id").expect("recovered");
            assert!(id.required, "`{body}` necessarily starts its body: {id:?}");
        }
    }

    #[test]
    fn a_while_with_a_real_test_keeps_its_zero_iteration_path() {
        // The bound, and the reason `always_true` is deliberately narrow: a test that can be
        // false means the body may never run, so requiring its reads would reject nodes the
        // parser accepts.
        let fields = helper_reached_via("while (more) { parse(e); break; }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the loop may run zero times: {id:?}");
    }

    #[test]
    fn a_for_loop_with_no_test_still_runs_its_body_once() {
        // `for (;;)` has no zero-iteration path: the body necessarily starts. Wrapping every
        // `for` body in a skipped path relaxed a read the parser always performs.
        let fields = helper_reached_via("for (;;) { parse(e); break; }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "no test means the body starts: {id:?}");
    }

    #[test]
    fn a_for_loop_with_a_test_still_weakens_its_body() {
        // And the ordinary form keeps its zero-iteration path.
        let fields = helper_reached_via("for (var i = 0; i < n; i++) { parse(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the test can fail first: {id:?}");
    }

    #[test]
    fn a_parameter_redeclared_with_an_initializer_has_moved() {
        // `var row = row.child("detail")` redeclares the callback's parameter and assigns
        // through it, so `row` names the detail node afterwards. Recording initializers only
        // as bindings left the own-node descent placing the helper's reads at the element root
        // while the tracked-child path placed them under `<detail>` — one read, two nodes.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(q){ q.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var row = row.child("detail");
                    parse(row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(!at_root, "the redeclaration moved it: {:?}", row.children);
    }

    #[test]
    fn a_helper_both_try_and_catch_call_is_required_again() {
        // Every successful execution passed through one of them, so what it reads is read on
        // every path — the two-sided intersection `if` does and this had no equivalent of.
        let fields = helper_reached_via("try { parse(e); } catch (x) { parse(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "both paths call it: {id:?}");
    }

    #[test]
    fn a_helper_in_only_the_catch_stays_optional() {
        // The block succeeding is a path that never reaches the handler.
        let fields = helper_reached_via("try { other(); } catch (x) { parse(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "only the failure path calls it: {id:?}");
    }

    #[test]
    fn a_case_test_that_reads_the_wire_is_counted() {
        // A test not reached by every value-producing execution is evaluated by exactly the
        // entries that did not match earlier, and its reads belong to those paths. Attributing
        // them needs a per-test relaxation slice plus a model of which entries evaluate which
        // test, in the visitor this branch has revised six times — declined, and detected rather
        // than guessed at. Of 4836 non-literal case tests in the locked corpus, 4831 are
        // `o("SomeModule").MEMBER` enum lookups and not one contains a wire accessor, so this
        // fires nowhere there.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                switch (mode) {
                    case "a": parse(e); break;
                    case parse(e): break;
                    default: parse(e);
                }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops.iter().any(|u| u == "case-test read"),
            "the unattributable read is accounted for: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_case_test_that_reads_nothing_is_not_counted() {
        // The bound: the corpus shape — a literal, or a module lookup — contributes no read, so
        // counting it would put thousands of false losses in `dropsByReason`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                switch (mode) {
                    case "a": parse(e); break;
                    case o("WAWebMsgType").TEXT: break;
                    default: parse(e);
                }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops.iter().any(|u| u == "case-test read"),
            "nothing was read in the test: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn an_arm_that_shadows_a_tracked_node_and_falls_through_is_counted() {
        // `case "a": var x = e.child("inner"); case "b": parse(x);` reads `x` as `<inner>` when
        // entered at `"a"` and as the outer `x` when entered at `"b"`. Both placements are right
        // for their own path and the tree needs both, which means walking the reading arm once
        // per entry path — O(cases²) re-walks, each able to re-parse a module function, against
        // a dispatch with 44 arms here. Declined on that cost and COUNTED instead, so the
        // omission shows up in the drop accounting rather than the shape claiming one placement
        // is the only one.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var x = e.child("outer");
                switch (mode) {
                    case "a": var x = e.child("inner");
                    case "b": parse(x); break;
                    default: break;
                }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops.iter().any(|u| u == "arm-shadowed node@x"),
            "the ambiguous placement is accounted for: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn an_arm_that_shadows_a_tracked_node_and_throws_is_not_counted_either() {
        // A throw never reaches the next arm, so a declaration behind one shadows nothing anybody
        // can see — the shadow question is about endings of ANY kind, unlike the fallthrough fold
        // beside it, which is about endings that hand something back. One predicate answers both
        // and takes which one as an argument; giving it the value-producing answer here would put
        // a false loss in `dropsByReason`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var x = e.child("outer");
                switch (mode) {
                    case "a": var x = e.child("inner"); throw Error("z");
                    case "b": parse(x); break;
                    default: break;
                }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("arm-shadowed")),
            "the throw reaches no later arm: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn an_arm_that_shadows_a_tracked_node_and_breaks_is_not_counted() {
        // The bound: `case "a": var x = …; break;` rebinds nothing any other arm can see, so
        // there is no ambiguity and nothing to report. Counting it would put false losses in
        // `dropsByReason`, which is the failure mode this accounting exists to avoid.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var x = e.child("outer");
                switch (mode) {
                    case "a": var x = e.child("inner"); break;
                    case "b": parse(x); break;
                    default: break;
                }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("arm-shadowed")),
            "the break makes it unambiguous: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_switch_case_falling_through_carries_the_next_ones_reads() {
        // `case "a": default: parse(e);` runs `parse` for every value — entering at `"a"`
        // falls into the default. Intersecting each case's OWN reads called the empty first
        // case decisive and left the payload optional.
        let fields = helper_reached_via(r#"switch (mode) { case "a": default: parse(e); }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the fallthrough reaches it: {id:?}");
    }

    #[test]
    fn a_case_whose_only_skip_throws_borrows_the_next_ones_reads() {
        // `case "a": if (bad) throw Error(); default: parse(e);` reaches `parse` on every execution
        // that returns anything, because the only path skipping the fallthrough throws. Asking
        // whether the arm can end AT ALL counted that throw, so the entry did not inherit the
        // default's reads and the payload stayed optional with its guards unpublished — the same
        // "which paths hand something back" rule the rest of the switch already applies, missing
        // from the one predicate both fallthrough passes share.
        let guards = guards_and_field(
            r#"switch (mode) { case "a": if (bad) throw Error(); default: parse(e); break; }"#,
        );
        assert_eq!(guards, (true, true), "the skipping path yields nothing");
    }

    #[test]
    fn a_case_that_can_break_past_the_next_one_still_does_not_borrow_it() {
        // The bound, and the reason the predicate takes the question as an argument: a `break` ends
        // the arm WITH a result, so that entry really can return without the default's reads.
        let guards = guards_and_field(
            r#"switch (mode) { case "a": if (bad) break; default: parse(e); break; }"#,
        );
        assert_eq!(guards, (false, false), "the breaking path returns");
    }

    #[test]
    fn a_switch_case_that_breaks_does_not_borrow_the_next_ones_reads() {
        // A `break` is what stops an entry path from continuing, so `"a"` reaches nothing.
        let fields = helper_reached_via(r#"switch (mode) { case "a": break; default: parse(e); }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break ends that path: {id:?}");
    }

    #[test]
    fn a_first_switch_case_test_is_always_evaluated() {
        // The first test runs before any case can be selected.
        let fields =
            helper_reached_via(r#"switch (mode) { case parse(e): break; default: break; }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the first test always runs: {id:?}");
    }

    #[test]
    fn a_default_written_first_does_not_shield_the_next_cases_test() {
        // `default` is not a test, so it does not stand between the discriminant and the
        // first comparison: `switch (mode) { default: break; case parse(e): break; }` still
        // evaluates `parse` whatever `mode` is. Reading the test of case ZERO instead of the
        // first case that HAS one relaxed a read the parser always performs.
        let fields =
            helper_reached_via(r#"switch (mode) { default: break; case parse(e): break; }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the first test still runs: {id:?}");
    }

    #[test]
    fn an_arm_that_falls_through_into_a_throw_is_not_a_value_path() {
        // `case "a": default: throw Error();` — entering at `"a"` runs the `default` below it
        // and throws, so no successful execution took that entry. The intersection filter asked
        // `throws_out` of the arm's OWN consequent, which is empty here, so the `"a"` entry
        // stayed in the fold and left the helper's fields optional. `entry_paths_throw` already
        // modelled the fallthrough for the test ordering; this asked the narrower question.
        let guards = guards_and_field(
            r#"switch (kind) { case "a": default: throw Error("x"); case "b": parse(e); break; }"#,
        );
        assert_eq!(guards, (true, true), "only the parse arm yields a value");
    }

    #[test]
    fn an_arm_that_falls_through_into_a_return_is_a_value_path() {
        // The bound: falling through into something that RETURNS hands back a result without
        // the read, so the payload stays optional.
        let guards = guards_and_field(
            r#"switch (kind) { case "a": default: return t; case "b": parse(e); break; }"#,
        );
        assert_eq!(guards, (false, false), "the default returns a value");
    }

    #[test]
    fn a_case_test_past_a_throwing_arm_is_always_reached() {
        // `switch (mode) { case "a": throw Error(); case parse(e): break; default: break; }` —
        // the only way to skip the second test is for `"a"` to match, and that path hands back
        // nothing. So every execution that produces a value evaluated `parse`. This is the
        // general form of the first-tested-case rule: a test is reached on every value path
        // when every earlier tested arm, once entered, throws.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": throw Error("bad"); case parse(e): break; default: break; }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the skipping path throws: {id:?}");
    }

    #[test]
    fn a_case_test_past_a_throwing_arm_that_falls_through_is_reached_too() {
        // `case "a":` with an empty consequent falls into the next arm, so entering at `"a"`
        // runs the `throw` below it — the chain is what throws, not the arm alone.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": case "b": throw Error("bad");
                              case parse(e): break; default: break; }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the fallthrough chain throws: {id:?}");
    }

    #[test]
    fn a_case_test_past_a_throwing_arm_that_breaks_first_is_not_reached() {
        // The bound: `case "a": break;` ahead of the throw leaves the switch WITHOUT throwing,
        // so a value-producing path skipped the later test after all.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": break; case parse(e): break; default: break; }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break returns a value: {id:?}");
    }

    #[test]
    fn a_case_that_can_break_before_throwing_does_not_certainly_throw() {
        // `case "a": if (flag) break; throw Error();` reaches the throw on one path and leaves
        // normally on the other, so it IS one of the value-producing paths — and one that never
        // evaluated the later test. Asking whether a throw appears anywhere in the arm, rather
        // than whether every path reaches one, promoted a read the breaking path skips.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": if (flag) break; throw Error("bad");
                              case parse(e): break; default: break; }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break is a path out with a value: {id:?}");
    }

    #[test]
    fn a_case_whose_break_is_wrapped_in_a_block_does_not_borrow_the_next_ones_reads() {
        // `case "a": { break; }` leaves the switch exactly as a bare `break` does. Matching
        // only a top-level `BreakStatement` read it as falling through, so entering at `"a"`
        // inherited the default's reads and promoted what that path never performs.
        let fields =
            helper_reached_via(r#"switch (mode) { case "a": { break; } default: parse(e); }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the wrapped break still leaves: {id:?}");
    }

    #[test]
    fn a_case_that_may_break_does_not_borrow_the_next_ones_reads_either() {
        // What the next arm establishes is guaranteed only for an entry path that certainly
        // reaches it, so a conditional `break` is enough to stop the borrowing.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": if (flag) break; default: parse(e); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break may skip the default: {id:?}");
    }

    #[test]
    fn a_case_test_after_a_matching_one_is_not_always_reached() {
        // The other side of the same rule: once a test can match, the ones after it are only
        // reached when it did not, so `switch (mode) { case "a": break; case parse(e): break; }`
        // may never evaluate `parse`.
        let fields =
            helper_reached_via(r#"switch (mode) { case "a": break; case parse(e): break; }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "an earlier test can match first: {id:?}");
    }

    #[test]
    fn a_throwing_switch_arm_does_not_dilute_the_exhaustive_intersection() {
        // `default: throw` produces no value at all, so every execution that yielded one took
        // another arm. Intersecting over the throwing arm too — which reads nothing — left a
        // field optional that every path capable of returning a result reads.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": parse(e); break; default: throw Error("bad"); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the throwing arm yields nothing: {id:?}");
    }

    #[test]
    fn an_arm_that_yields_a_value_without_the_read_keeps_it_optional() {
        // And the bound on that: dropping the throwing arm must not drop the arms that DO
        // return, so a value-producing case with no call still leaves the payload optional.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": parse(e); break; case "b": break;
                              default: throw Error("bad"); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the \"b\" arm returns without it: {id:?}");
    }

    #[test]
    fn a_break_inside_a_nested_loop_does_not_end_the_outer_pass() {
        // `break` leaves the NEAREST loop or switch. `do { while (f) { break; } parse(e); }
        // while (m)` still completes its guaranteed pass through `parse`, and counting the
        // inner break as an exit relaxed a read that always happens.
        let fields = helper_reached_via("do { while (f) { break; } parse(e); } while (m);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the inner break leaves the inner loop: {id:?}");
    }

    #[test]
    fn a_break_a_nested_switch_consumes_does_not_end_the_outer_pass() {
        // A `switch` swallows an unlabelled `break` the same way a loop does.
        let fields =
            helper_reached_via(r#"do { switch (k) { case "a": break; } parse(e); } while (m);"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the switch consumes the break: {id:?}");
    }

    #[test]
    fn a_labelled_break_out_of_a_nested_loop_does_end_the_outer_pass() {
        // The bound on that: `break outer` names the construct it leaves, so no nested loop
        // swallows it and what follows really is conditional.
        let fields =
            helper_reached_via("outer: do { while (f) { break outer; } parse(e); } while (m);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the label jumps clear of both: {id:?}");
    }

    #[test]
    fn a_continue_a_nested_loop_consumes_does_not_end_the_outer_pass() {
        // `continue` is taken by the nearest LOOP only — a `switch` does not consume it —
        // so the counters have to be kept apart.
        let fields = helper_reached_via("do { while (f) { continue; } parse(e); } while (m);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the inner continue stays inside: {id:?}");
    }

    #[test]
    fn a_testless_for_with_a_bare_body_still_runs_it() {
        // `for (;;) parse(e);` has no zero-iteration path either. The braced form was handled
        // and the unbraced one fell through to the skipped path — the same over-relaxation,
        // one syntactic form over.
        let fields = helper_reached_via("for (;;) parse(e);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the body is reached: {id:?}");
    }

    #[test]
    fn a_helper_guard_every_switch_arm_makes_is_published() {
        // The gap this test used to record. A helper reached at nonzero depth had its guards
        // discarded outright while its FIELDS were parked in `relaxed_by_branch`, so an
        // exhaustive switch promoted the fields to required and dropped the `assertAttr` —
        // decoding then accepted values every source path rejects, and the shape said both
        // "always present" and "unconstrained" about one read.
        let guards =
            guards_and_field(r#"switch (mode) { case "a": parse(e); break; default: parse(e); }"#);
        assert_eq!(
            guards,
            (true, true),
            "promoted field and its guard travel together"
        );
    }

    #[test]
    fn a_helper_guard_only_one_switch_arm_makes_is_not_published() {
        // The bound on that: an arm the parser may not take enforces nothing, and hoisting its
        // guard would reject everything the other arms accept.
        let guards =
            guards_and_field(r#"switch (mode) { case "a": parse(e); break; default: other(e); }"#);
        assert_eq!(guards, (false, false), "one arm establishes neither");
    }

    #[test]
    fn a_helper_guard_survives_a_call_on_both_sides_of_a_branch() {
        // Not only the switch — the same channel, reached through `if`/`else`, whose field
        // intersection has been there all along.
        let guards = guards_and_field("if (c) { parse(e); } else { parse(e); }");
        assert_eq!(guards, (true, true), "both sides call it");
    }

    #[test]
    fn an_unconditional_helper_call_publishes_its_guard_after_a_conditional_one() {
        // `if (flag) { parse(e); } parse(e);` — the second call enforces the guard on every
        // path. But the first recorded one occurrence and PARKED it, a presence test then
        // skipped the second, and the subtraction removed the parked copy: the guard vanished
        // entirely. Order-dependent, too — unconditional-first published it fine. Counting
        // occurrences against the parked ones is what makes the two orders agree, and it keeps
        // the ordinary duplicate suppressed since `parse(e); parse(e);` parks nothing.
        let guards = guards_and_field("if (flag) { parse(e); } parse(e);");
        assert_eq!(guards, (true, true), "the second call is unconditional");
    }

    #[test]
    fn a_guard_from_two_unconditional_calls_is_published_once() {
        // The bound on that count: nothing is parked here, so the second call adds no
        // occurrence and the guard is stated once rather than twice.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.assertAttr("kind", "x"); p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e); parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let n = p
            .assertions
            .iter()
            .filter(|a| a.name.as_deref() == Some("kind"))
            .count();
        assert_eq!(n, 1, "stated once: {:?}", p.assertions);
    }

    #[test]
    fn a_helper_guard_from_one_side_of_a_branch_is_not_published() {
        let guards = guards_and_field("if (c) { parse(e); }");
        assert_eq!(guards, (false, false), "one side establishes neither");
    }

    #[test]
    fn a_catch_whose_throw_is_wrapped_in_a_try_still_yields_nothing() {
        // `catch (_) { try { throw Error(); } finally { cleanup(); } }` produces no result: the
        // finalizer runs and the error carries on. Asking only about bare throws, blocks,
        // two-sided ifs and labels called this handler a value-producing side and diluted the
        // intersection with it. Same for a `switch` whose every arm throws, given a `default`
        // so no value escapes by matching nothing.
        for body in [
            r#"try { parse(e); } catch (x) { try { throw Error("z"); } finally { cleanup(); } }"#,
            r#"try { parse(e); } catch (x) { switch (k) { case "a": throw A(); default: throw B(); } }"#,
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (true, true), "`{body}` hands nothing back");
        }
    }

    #[test]
    fn a_catch_whose_throw_is_caught_again_is_a_value_path() {
        // The bounds: an inner `catch` swallows the error, and a `switch` with no `default` lets
        // an unmatched value fall straight out — both leave the handler able to return.
        for body in [
            r#"try { parse(e); } catch (x) { try { throw Error("z"); } catch (y) { other(); } }"#,
            r#"try { parse(e); } catch (x) { switch (k) { case "a": throw A(); } }"#,
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (false, false), "`{body}` can still return");
        }
    }

    #[test]
    fn a_throwing_if_branch_does_not_dilute_the_intersection() {
        // `if (flag) { parse(e); } else { throw Error(); }` calls `parse` on every execution
        // that yields anything, so intersecting against the empty throwing side left the payload
        // optional and its guard unpublished. The switch and the try have filtered non-completing
        // sides for two rounds; `if` — the construct that taught them the intersection — had not.
        let guards = guards_and_field(r#"if (flag) { parse(e); } else { throw Error("z"); }"#);
        assert_eq!(guards, (true, true), "the throwing side yields nothing");
    }

    #[test]
    fn a_returning_if_branch_still_dilutes_the_intersection() {
        // The bound: a side that RETURNS hands back a result without the read, so the payload
        // really is optional. Only throwing sides drop out.
        let guards = guards_and_field("if (flag) { parse(e); } else { return t; }");
        assert_eq!(guards, (false, false), "the else returns a value");
    }

    #[test]
    fn a_finalizer_that_returns_overrides_the_throw_it_covers() {
        // `finally { return fallback; }` completes abruptly and hands back a result whatever the
        // block and handler threw, so the whole `try` is a value path. Only the finalizer's
        // THROWING case was considered, so a handler shaped this way was excluded from the
        // successful-path intersection and the outer try's reads were promoted to required.
        let guards = guards_and_field(
            r#"try { parse(e); } catch (x) { try { throw A(); } catch (y) { throw B(); }
               finally { return fallback; } }"#,
        );
        assert_eq!(
            guards,
            (false, false),
            "the fallback returns without the read"
        );
    }

    #[test]
    fn a_finalizer_that_only_cleans_up_does_not_override() {
        // The bound: a finalizer that completes normally leaves the throw in place, so the
        // handler still yields nothing and the outer reads stay required.
        let guards = guards_and_field(
            r#"try { parse(e); } catch (x) { try { throw A(); } catch (y) { throw B(); }
               finally { cleanup(); } }"#,
        );
        assert_eq!(guards, (true, true), "the throw carries on");
    }

    #[test]
    fn a_finalizer_that_returns_from_inside_a_branch_overrides_too() {
        // `finally { if (retry) return fallback; }` hands back a result on the path that
        // returns, so the `try` is not a throwing one. Matching a bare `return` STATEMENT saw
        // only the unconditional spelling — the same rule stopping at the top level of a block,
        // which is how it read `finally { return … }` and missed every branch inside one. A
        // `break` or `continue` out of the finalizer discards the pending error the same way.
        for fin in [
            "if (retry) return fallback;",
            "for (;;) { if (retry) return fallback; }",
        ] {
            let guards = guards_and_field(&format!(
                r#"try {{ parse(e); }} catch (x) {{ try {{ throw A(); }} catch (y) {{ throw B(); }}
                   finally {{ {fin} }} }}"#
            ));
            assert_eq!(guards, (false, false), "`{fin}` leaves with a result");
        }
    }

    #[test]
    fn a_finalizer_that_cannot_leave_by_itself_does_not_override() {
        // The bounds. A `return` inside a function the finalizer merely CONSTRUCTS leaves that
        // function, not the finalizer, and a `break` belonging to a loop the finalizer opens
        // itself lands back in the finalizer — neither discards the error, and counting either
        // would call a cleanup path a value path and dilute the intersection with it. Nor does a
        // finalizer that THROWS: it leaves abruptly, but with an error rather than a result, so
        // the question is which exits hand something back and not which exits exist.
        for fin in [
            "done(function(){ return 1; });",
            "for (;;) { break; }",
            "throw C();",
        ] {
            let guards = guards_and_field(&format!(
                r#"try {{ parse(e); }} catch (x) {{ try {{ throw A(); }} catch (y) {{ throw B(); }}
                   finally {{ {fin} }} }}"#
            ));
            assert_eq!(guards, (true, true), "`{fin}` hands nothing back");
        }
    }

    #[test]
    fn a_loop_that_can_only_be_left_by_throwing_yields_nothing() {
        // `while (!0) { throw A(); }` is the minifier's spelling of an unconditional raise: the
        // first pass is guaranteed and the body never completes, so there is no second pass and
        // no way out but the error. `throws_out` read the bare, braced, two-sided-`if`, labelled,
        // `try` and exhaustive-`switch` forms and no loop at all, so a handler shaped this way
        // counted as a path that hands something back and diluted the intersection.
        for handler in [
            "while (!0) { throw A(); }",
            "for (;;) { throw A(); }",
            "do { throw A(); } while (c);",
        ] {
            let guards =
                guards_and_field(&format!("try {{ parse(e); }} catch (x) {{ {handler} }}"));
            assert_eq!(guards, (true, true), "`{handler}` hands nothing back");
        }
    }

    #[test]
    fn a_loop_something_can_leave_still_yields_a_value() {
        // The bounds, and both of them matter: a test that can be false has a zero-iteration
        // path straight past the body, and a `break` reachable before the throw leaves the loop
        // with the handler still able to return. `throws_out` stops at the first statement
        // control can leave by, which is what keeps the second case out.
        for handler in [
            "while (c) { throw A(); }",
            "while (!0) { if (c) break; throw A(); }",
        ] {
            let guards =
                guards_and_field(&format!("try {{ parse(e); }} catch (x) {{ {handler} }}"));
            assert_eq!(guards, (false, false), "`{handler}` can complete");
        }
    }

    #[test]
    fn a_returning_finalizer_bypasses_the_try_it_covers() {
        // `try { parse(e); } finally { return fallback; }` hands `fallback` back even when
        // `parse` threw on a missing field, so nothing `parse` reads is read on every path that
        // yields something. `throws_out` was taught this about the try as a WHOLE last round and
        // the visitor deciding the try's own requiredness was not, so it kept those reads
        // required and the shape rejected responses the parser accepts — the harmful direction.
        for body in [
            r#"try { parse(e); } finally { return fallback; }"#,
            r#"try { parse(e); } catch (x) { parse(e); } finally { return fallback; }"#,
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (false, false), "`{body}` can return without it");
        }
    }

    #[test]
    fn a_finalizer_that_cannot_leave_keeps_the_try_required() {
        // The bound: a finalizer that completes normally does not bypass anything, so an
        // unhandled block's reads stay required — weakening every `try` with a `finally` would
        // relax reads every successful parse performs.
        let guards = guards_and_field("try { parse(e); } finally { cleanup(); }");
        assert_eq!(guards, (true, true), "the error still propagates");
    }

    #[test]
    fn a_statically_selected_side_is_not_a_branch() {
        // `if (!0)` is not a choice: the consequent runs on every execution. Raising the branch
        // counter regardless intersected its reads against an `else` that does not exist, so a
        // read the parser always performs came out optional and its guard unpublished. All three
        // spellings, because writing the rule for one of them is how this branch keeps failing.
        for body in [
            "if (!0) { parse(e); }",
            "if (0) { other(); } else { parse(e); }",
            "!0 ? parse(e) : other();",
            "0 ? other() : parse(e);",
            "!0 && parse(e);",
            "0 || parse(e);",
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (true, true), "`{body}` always runs it");
        }
    }

    #[test]
    fn a_test_a_value_can_change_still_makes_its_side_conditional() {
        // The bound, in the same three spellings: an ordinary test really is a branch, and
        // reading every test as decided would require of every element what only one path reads.
        for body in [
            "if (flag) { parse(e); }",
            "flag ? parse(e) : other();",
            "flag && parse(e);",
            "flag || parse(e);",
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (false, false), "`{body}` may skip it");
        }
    }

    #[test]
    fn a_loop_nothing_can_leave_yields_nothing_either() {
        // Two ways to hand nothing back and only the throwing one was recognised: `while (!0) {
        // continue; }` and `for (;;) {}` never leave at all, so every execution that returned
        // anything took the other side of the branch they sit in.
        for handler in ["while (!0) { continue; }", "for (;;) { }"] {
            let guards =
                guards_and_field(&format!("try {{ parse(e); }} catch (x) {{ {handler} }}"));
            assert_eq!(guards, (true, true), "`{handler}` diverges");
        }
    }

    #[test]
    fn a_loop_that_throws_or_diverges_yields_nothing_either() {
        // `while (!0) { if (bad) throw Error(); }` either throws or runs forever, so it hands
        // nothing back on any path — and it was read as a value path because the question was
        // asked twice instead of once: "does every path throw" is false here, and "is there no way
        // out" counted the throw as one. Each answer covered a pure case and their disjunction
        // missed the mixture. One predicate — can the body leave carrying a RESULT — covers all
        // three, and it is the predicate the `do`/`while` test question was already using.
        for handler in [
            "while (!0) { if (bad) throw Error(); }",
            "for (;;) { if (bad) throw Error(); else other(); }",
        ] {
            let guards =
                guards_and_field(&format!("try {{ parse(e); }} catch (x) {{ {handler} }}"));
            assert_eq!(guards, (true, true), "`{handler}` hands nothing back");
        }
    }

    #[test]
    fn a_hanging_block_never_reaches_its_handler() {
        // `try { for (;;); } catch (_) {}` hangs. Reading the loop as a throwing path — which
        // is the right answer to the only question the other callers ask, can this hand a
        // result back — handed the try to a handler that completes, so the whole `try` counted
        // as a value path and diluted the intersection with a side nothing reaches. A throw
        // reaches the handler and a hang does not, and one predicate was answering for both.
        for block in [
            "for (;;);",
            "while (!0) {}",
            "do {} while (!0)",
            "outer: for (;;) {}",
        ] {
            let guards = guards_and_field(&format!(
                "if (flag) {{ try {{ {block} }} catch (_) {{}} }} else {{ parse(e); }}"
            ));
            assert_eq!(guards, (true, true), "`{block}` reaches nothing after it");
        }
    }

    #[test]
    fn a_loop_that_only_goes_round_again_is_a_hang_too() {
        // `while (!0) { continue; }` evaluates nothing and leaves nothing — it is `while (!0) {}`
        // with a step in it, and the hang check recognised only the empty spelling. So the
        // `catch` around it counted as a path that yields something and weakened the reads on
        // the other side of the `if`. A `continue` is the one transfer that does not leave the
        // loop it belongs to, unlabelled or naming that loop itself.
        for block in [
            "while (!0) { continue; }",
            "for (;;) { continue; }",
            "do { continue; } while (!0)",
            "spin: while (!0) { continue spin; }",
            "while (!0) { { continue; } }",
        ] {
            let guards = guards_and_field(&format!(
                "if (flag) {{ try {{ {block} }} catch (_) {{}} }} else {{ parse(e); }}"
            ));
            assert_eq!(
                guards,
                (true, true),
                "`{block}` never leaves and never raises"
            );
        }
    }

    #[test]
    fn a_transfer_that_leaves_the_loop_is_not_it_spinning() {
        // The bounds. A `break` leaves, so the loop completes and the `try` is a value path; a
        // `continue` naming an OUTER loop leaves this one the same way; and a `return` leaves
        // the callback entirely. Only the transfer that goes back to the top of this loop makes
        // it a hang — reading them all alike would call a loop that ends an infinite one.
        for block in [
            "while (!0) { break; }",
            "outer: while (!0) { while (!0) { continue outer; } }",
            "while (!0) { return t; }",
        ] {
            let guards = guards_and_field(&format!(
                "if (flag) {{ try {{ {block} }} catch (_) {{}} }} else {{ parse(e); }}"
            ));
            assert_eq!(guards, (false, false), "`{block}` can leave the loop");
        }
        // Which label it names is what decides, and only a loop OUTSIDE the `try` can make that
        // visible — the inner loop is the one being asked about, so the outer one has to be
        // somewhere its own iteration does not change the answer. A `do`/`while (0)` runs once.
        assert_eq!(
            guards_and_field(
                "outer: do { if (flag) { try { while (!0) { continue outer; } } catch (_) {} }
                 else { parse(e); } } while (0)"
            ),
            (false, false),
            "`continue outer` leaves the loop it is written in"
        );
    }

    #[test]
    fn a_loop_that_can_raise_still_reaches_the_handler() {
        // The bound, and the reason the hang is recognised this narrowly: anything the body
        // evaluates can throw, and a throw is exactly what the handler is there for. Only a
        // loop that does no work at all is a hang; `while (!0) { g(); }` may end up in a
        // `catch` that completes, so the `try` is still a path that yields something and the
        // `else` read stays optional. A header counts as work too — it runs on every pass.
        for block in [
            "while (!0) { g(); }",
            "for (;;) { g(); }",
            "for (i = risky(); ; ) {}",
            "for (;; risky()) {}",
            "while (flag) {}",
        ] {
            let guards = guards_and_field(&format!(
                "if (flag) {{ try {{ {block} }} catch (_) {{}} }} else {{ parse(e); }}"
            ));
            assert_eq!(
                guards,
                (false, false),
                "`{block}` can leave through the catch"
            );
        }
    }

    #[test]
    fn nothing_a_hanging_try_is_wrapped_in_runs_either() {
        // The same fact where the requiredness walk asks it: a handler or a finalizer after a
        // block that hangs is not the block's successor, it is unreachable. Treating the
        // handler as the one side that yields a value made everything it reads required —
        // the same mistake as above pointing the other way, and the fourth time on this branch
        // that a rule landed in the classifier and not in the visitor.
        for tail in ["catch (_) { parse(e); }", "finally { parse(e); }"] {
            let guards = guards_and_field(&format!("try {{ for (;;); }} {tail}"));
            assert_eq!(guards, (false, false), "nothing runs `{tail}`");
        }
    }

    #[test]
    fn a_handler_after_a_block_that_can_fail_still_reads() {
        // The bound for that one: a block that does work can throw, so the handler is a path
        // the parser takes, and its reads are recorded as the conditional ones they are rather
        // than dropped. A finalizer after such a block runs on every path, so what it reads is
        // required — which is the behaviour the hang check must not disturb.
        assert_eq!(
            guards_and_field("try { g(); } catch (_) { parse(e); }"),
            (false, false),
            "the handler runs only on failure"
        );
        assert_eq!(
            guards_and_field("try { g(); } finally { parse(e); }"),
            (true, true),
            "the finalizer runs either way"
        );
    }

    #[test]
    fn an_alias_a_decided_branch_assigns_is_not_conditional() {
        // `if (!0) current = e;` assigns on every execution, so the helper it is handed to reads
        // what every response carries. The requiredness walk was taught to select a statically
        // decided side one round before the binding collector existed, and the collector then
        // asked its own version of the question without it — so the CALL was read as
        // unconditional and the VALUE as conditional, and the fields came out optional anyway.
        // All three spellings, from the one selector both now read.
        for body in [
            "var current; if (!0) current = e; parse(current);",
            "var current; if (0) other(); else current = e; parse(current);",
            "var current; !0 && (current = e); parse(current);",
            "var current; 0 || (current = e); parse(current);",
            "var current; !0 ? (current = e) : other(); parse(current);",
            "var current; 0 ? other() : (current = e); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            let id = fields
                .iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` recovers the field"));
            assert!(id.required, "`{body}` assigns on every execution");
        }
    }

    #[test]
    fn a_for_of_over_a_nonempty_literal_runs_its_body_once() {
        // `for (const _ of [0]) { parse(e); break; }` iterates at least once, so what the pass
        // reads before it can leave is read every time — the same guaranteed-pass asymmetry
        // `for (;;)` and `while (!0)` have. Every `for`/`of` went through the skipped path, so a
        // read the parser always performs came out optional and its guard unpublished.
        let guards = guards_and_field("for (const _ of [0]) { parse(e); break; }");
        assert_eq!(guards, (true, true), "a nonempty list iterates");
    }

    #[test]
    fn a_for_of_that_may_be_empty_keeps_its_zero_iteration_path() {
        // The bounds. An arbitrary expression may yield nothing, `[]` yields nothing, and `[...xs]`
        // may — reading any of those as nonempty would require reads the parser can skip.
        for body in [
            "for (const _ of ks) { parse(e); break; }",
            "for (const _ of []) { parse(e); break; }",
            "for (const _ of [...ks]) { parse(e); break; }",
        ] {
            let guards = guards_and_field(body);
            assert_eq!(guards, (false, false), "`{body}` may run no passes");
        }
    }

    #[test]
    fn a_loop_with_a_way_out_still_yields_a_value() {
        // The bounds. A `break` or a `return` leaves; and a `do`/`while` whose body only
        // `continue`s is ended by its own test, which is why the divergence rule asks about the
        // test there and the throwing rule does not.
        for handler in [
            "while (!0) { break; }",
            "while (!0) { return t; }",
            "do { continue; } while (c);",
        ] {
            let guards =
                guards_and_field(&format!("try {{ parse(e); }} catch (x) {{ {handler} }}"));
            assert_eq!(guards, (false, false), "`{handler}` can be left");
        }
    }

    #[test]
    fn a_break_to_a_label_inside_the_body_is_not_a_way_out() {
        // `local: { break local; }` jumps to the end of that block and carries on, so the
        // guaranteed pass reaches `parse` whatever happens. Counting every LABELLED break as an
        // exit — which is right for a label declared outside — put the read on a path some
        // successful parse skipped and called it optional.
        let guards = guards_and_field("do { local: { break local; } parse(e); break; } while (0);");
        assert_eq!(guards, (true, true), "the jump lands back inside");
    }

    #[test]
    fn a_break_to_a_label_outside_the_body_still_leaves() {
        // The bound, and the reason the question is about WHERE the label is: `break outer`
        // leaves the loop, so the read after it really is on a path a successful parse skipped.
        let guards =
            guards_and_field("outer: do { if (c) break outer; parse(e); break; } while (0);");
        assert_eq!(guards, (false, false), "the jump leaves the loop");
    }

    #[test]
    fn a_catch_that_throws_whichever_way_it_branches_yields_nothing() {
        // `catch (_) { if (flag) throw A(); else throw B(); }` produces no result on any path,
        // so every execution that returned one completed the block. `throws_out` matched only
        // the bare and braced forms, so a handler spelled this way counted as a value path and
        // diluted the intersection with an empty side — `exits_unconditionally` has always read
        // a two-sided `if` this way and this did not.
        let guards = guards_and_field(
            r#"try { parse(e); } catch (x) { if (flag) throw A(); else throw B(); }"#,
        );
        assert_eq!(guards, (true, true), "no handler path yields a value");
    }

    #[test]
    fn a_catch_that_throws_down_only_one_branch_is_still_a_value_path() {
        // The bound: a one-sided `if (flag) throw A();` falls through and returns, so the
        // handler IS a path on which the block stopped partway.
        let guards = guards_and_field(r#"try { parse(e); } catch (x) { if (flag) throw A(); }"#);
        assert_eq!(guards, (false, false), "the fallthrough returns");
    }

    #[test]
    fn a_throwing_catch_does_not_relax_the_block_it_guards() {
        // `catch (_) { throw Error(); }` hands nothing back, so every execution that produced
        // a result completed the block. Intersecting the block's reads against the empty
        // throwing handler left them optional where every successful parse performs them —
        // the same rule the switch arms get, one construct over.
        let fields = helper_reached_via(r#"try { parse(e); } catch (x) { throw Error("bad"); }"#);
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the handler yields nothing: {id:?}");
    }

    #[test]
    fn a_catch_that_swallows_the_error_still_relaxes_the_block() {
        // The bound: a handler that RETURNS a result is a path on which the block stopped
        // partway, so what the block read past a throwing call is not read every time.
        let fields = helper_reached_via("try { parse(e); } catch (x) { other(e); }");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the handler is a path too: {id:?}");
    }

    #[test]
    fn a_guard_from_a_block_whose_catch_throws_is_published() {
        // And the guard travels with the field, as everywhere else.
        let guards = guards_and_field(r#"try { parse(e); } catch (x) { throw Error("bad"); }"#);
        assert_eq!(guards, (true, true), "the only surviving path calls it");
    }

    #[test]
    fn a_helper_guard_from_both_try_and_catch_is_published() {
        // Every successful execution passed through one of the two, and an `assertAttr` that
        // throws in the block throws again in the handler, so the constraint holds either way.
        let guards = guards_and_field("try { parse(e); } catch (x) { parse(e); }");
        assert_eq!(guards, (true, true), "both paths call it");
    }

    #[test]
    fn a_guard_established_inside_a_one_sided_outer_branch_is_not_published() {
        // `if (o) { if (c) parse(e); else parse(e); }` — the INNER conditional establishes the
        // guard on both of its paths, but the outer one can skip the whole thing. Releasing on
        // the inner intersection regardless of nesting published a guard the parser enforces
        // on no path at all; the fields have always been handed up as the outer branch's own
        // parked entry, and the guards now are too.
        let guards = guards_and_field("if (o) { if (c) { parse(e); } else { parse(e); } }");
        assert_eq!(guards, (false, false), "the outer branch can skip both");
    }

    /// Every `kind` value the shape publishes for a callback body, so a guard established on
    /// SOME path can be told from one established on every path — two assertions on one
    /// attribute with different values is the case a single "is `kind` published" answer
    /// cannot see, and it is the case the nested intersection got wrong.
    fn published_kind_values(body: &str) -> Vec<Option<String>> {
        let module = format!(
            r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){{
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
            .assertions
            .into_iter()
            .filter(|a| a.name.as_deref() == Some("kind"))
            .map(|a| a.value)
            .collect()
    }

    #[test]
    fn a_guard_only_one_nested_path_makes_is_not_the_branchs_claim() {
        // The inner conditional establishes NOTHING — its two sides assert different values —
        // so the outer branch it sits in claims nothing either. Parking and claiming shared one
        // list, and a nested settle could only leave its region alone: both inner values
        // travelled up as the outer branch's own contribution, the outer intersection found
        // `"a"` on both sides, and the shape demanded `kind="a"` of responses the parser
        // accepts with `kind="b"`.
        let values = published_kind_values(
            r#"if (o) { if (i) { e.assertAttr("kind", "a"); }
                       else { e.assertAttr("kind", "b"); } }
               else { e.assertAttr("kind", "a"); }"#,
        );
        assert!(
            values.is_empty(),
            "one inner path asserts b, so nothing holds always: {values:?}"
        );
    }

    #[test]
    fn a_guard_every_nested_path_makes_is_still_the_branchs_claim() {
        // The complement, and the reason the claim is re-parked rather than dropped: the inner
        // conditional establishes the guard on both of its paths, so the branch it sits in does
        // establish it, and the outer intersection has something to agree with. Dropping every
        // nested claim would fix the case above by publishing nothing at all, ever.
        let values = published_kind_values(
            r#"if (o) { if (i) { e.assertAttr("kind", "a"); }
                       else { e.assertAttr("kind", "a"); } }
               else { e.assertAttr("kind", "a"); }"#,
        );
        assert_eq!(
            values,
            vec![Some("a".to_string())],
            "every path through the parser asserts it"
        );
    }

    #[test]
    fn a_guard_behind_a_one_sided_inner_if_is_not_the_branchs_claim() {
        // The same hole through the construct that settles nothing at all: with no `else` there
        // was no intersection to reach the region, so the claim sat there and the enclosing
        // conditional read it as the whole branch's.
        let values = published_kind_values(
            r#"if (o) { if (i) { e.assertAttr("kind", "a"); } }
               else { e.assertAttr("kind", "a"); }"#,
        );
        assert!(
            values.is_empty(),
            "the branch asserts it only when `i` holds: {values:?}"
        );
    }

    #[test]
    fn a_guard_inside_a_loop_body_is_not_the_branchs_claim() {
        // And through a skipped path: an empty list runs the body no times, so the branch
        // containing the loop establishes nothing.
        let values = published_kind_values(
            r#"if (o) { for (var k of ks) { e.assertAttr("kind", "a"); } }
               else { e.assertAttr("kind", "a"); }"#,
        );
        assert!(
            values.is_empty(),
            "an empty list asserts nothing: {values:?}"
        );
    }

    #[test]
    fn a_guard_in_a_logical_right_side_is_not_the_branchs_claim() {
        // `i && …` is the one-sided `if` spelled shorter, and it parks claims the same way.
        let values = published_kind_values(
            r#"if (o) { i && e.assertAttr("kind", "a"); }
               else { e.assertAttr("kind", "a"); }"#,
        );
        assert!(values.is_empty(), "only when `i` holds: {values:?}");
    }

    #[test]
    fn a_field_read_only_inside_a_loop_body_is_not_promoted() {
        // The field half of the same claim, and the same harm: requiring `id` of every element
        // rejects the ones the other branch's parser accepts. `relaxed_by_branch` and the guard
        // claims are handed up by the same rule, so they are dropped by the same rule.
        let both =
            guards_and_field("if (o) { for (var k of ks) { parse(e); } } else { parse(e); }");
        assert_eq!(both, (false, false), "an empty list reads nothing");
    }

    #[test]
    fn a_field_read_only_in_a_logical_right_side_is_not_promoted() {
        let both = guards_and_field("if (o) { i && parse(e); } else { parse(e); }");
        assert_eq!(both, (false, false), "only when `i` holds");
    }

    #[test]
    fn a_guard_asserted_down_one_branch_of_the_callback_is_not_published() {
        // The parked-assertion list was consumed for helpers and never for the top-level
        // parser, so `if (c) e.assertAttr("kind", "x")` published as a constraint every
        // response satisfies — the harmful direction, and it predates the helper channel.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (c) { e.assertAttr("kind", "x"); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("kind")),
            "one branch enforces nothing: {:?}",
            p.assertions
        );
    }

    #[test]
    fn a_guard_both_branches_make_is_published_once() {
        // Two identical assertions constrain nothing a single one does not, and both branches
        // recording their own occurrence is exactly what the intersection needs to see — so
        // the collapse happens on the way out, after the subtraction rather than before it.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (c) { e.assertAttr("kind", "x"); } else { e.assertAttr("kind", "x"); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let n = p
            .assertions
            .iter()
            .filter(|a| a.name.as_deref() == Some("kind"))
            .count();
        assert_eq!(n, 1, "published once: {:?}", p.assertions);
    }

    #[test]
    fn an_ordinary_local_handed_to_a_helper_is_not_a_lost_node() {
        // Only a node this scope TRACKS can be handed on, so only one can be reported lost.
        // Asking about the write before checking that had `for (i = 0; …) parse(i)` record
        // `reassignedNodeHandedOn` for a child node never involved — which is worse than a
        // missing field, because it makes `dropsByReason` claim losses that did not happen.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(x){ x.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                for (idx = 0; idx < n; idx++) { parse(idx); }
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("reassignedNodeHandedOn")),
            "no node was handed on at all: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_tracked_node_reassigned_before_the_call_is_still_reported() {
        // The bound: when the argument IS a tracked child and a write moved it, the descent
        // really did lose the helper's reads and the accounting has to say so.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(x){ x.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var moved = e.child("moved");
                moved = moved.child("deeper");
                parse(moved);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "a tracked node really was handed on: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_recovered_argument_is_not_reported_as_a_drop() {
        // `helper(reassigned, stillGood)` descends through the second argument, so nothing was
        // lost. Recording the marker from inside the search claimed a loss anyway, and a drop
        // entry for a read that WAS recovered is exactly the noise that makes the accounting
        // useless.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(x, y){ y.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var moved = e.child("moved");
                var kept = e.child("kept");
                moved = moved.child("deeper");
                parse(moved, kept);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("reassignedNodeHandedOn")),
            "the second argument descended: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn an_alias_pointed_at_the_node_only_after_the_call_is_not_followed() {
        // `var current = other; parse(current); current = row;` hands the helper `other`, not
        // the row. The order-aware COUNT is about the name and says nothing about which value
        // was picked, so it saw the one in-scope value and the search then selected the later
        // `current = row` record purely because its source was already in the set — filing `id`
        // under `<row>`, which is the harmful direction. The candidate itself now has to have
        // taken effect, by the same rule the count uses.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current = other;
                    parse(current);
                    current = row;
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            !row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the alias points elsewhere at the call: {:?}",
            row.children
        );
    }

    #[test]
    fn an_assignment_takes_effect_after_its_right_hand_side() {
        // `e = parse(e)` calls `parse` with the ORIGINAL node and only then rebinds `e`. Both
        // records of the assignment were ordered from the target identifier, which is textually
        // before the call, so the node looked already moved: the descent was refused, every
        // field the helper reads was lost, and a `reassignedNodeHandedOn` was recorded for a
        // move that had not happened yet.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e = parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the call sees the original node: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("reassignedNodeHandedOn")),
            "and nothing had moved yet: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_before_the_call_still_moves_the_node() {
        // The bound: `e = e.child("detail"); parse(e)` really does hand the helper the detail
        // node, so the descent is still refused and the loss still recorded.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e = e.child("detail");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "the write precedes the call: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_declarator_takes_effect_after_its_initializer() {
        // `var e = parse(e)` evaluates `parse` against the original parameter and only then
        // rebinds. I gave the ASSIGNMENT form its effect position one commit earlier and left the
        // declarator ordered from the binding identifier — the same rule in two places with one
        // copy missing it, which is the shape of half the findings on this branch.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var e = parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the initializer sees the original node: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            p.pending_drops.is_empty(),
            "nothing moved yet: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_declarator_that_moves_the_node_before_the_call_still_counts() {
        // The bound: `var e = e.child("a"); parse(e)` really does hand over the child, so the
        // reads belong under `<a>` and the root descent is still refused and still reported.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                var e = e.child("a");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "the declarator moved it: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_whose_throw_nothing_catches_is_still_dead() {
        // The bound on the suppression: with no handler anywhere, the throw really does end
        // everything, so the write never reaches a value-producing path and must stay dead.
        // Wrapped in a one-sided `if` so the try block itself can complete and `parse(e)` is
        // actually reachable — otherwise the distinction is unobservable downstream.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                try {
                    if (g) {
                        if (f) { e = e.child("a"); throw A(); }
                        else { e = e.child("a"); throw B(); }
                    }
                } finally {}
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the surviving path never wrote: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            p.pending_drops.is_empty(),
            "nothing lost: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_whose_throw_a_handler_catches_still_moves_the_node() {
        // A throw inside a block a handler CATCHES ends nothing — the handler runs and execution
        // carries on — so a write before it is as effective as any other. The dead-path rule
        // added one commit earlier asked `throws_out` without the enclosing catch, marked these
        // writes dead, and let the descent proceed against a node the parser had already moved.
        // Wrong-node, and a regression of my own.
        //
        // The suppression has to outrank the computation rather than reset it: zeroing the
        // counter at the `try` boundary achieved nothing, because `visit_statement` recomputes it
        // from the very statement that throws.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                try {
                    if (f) { e = e.child("a"); throw A(); }
                    else { e = e.child("a"); throw B(); }
                } catch (x) {}
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.fields.iter().any(|f| f.name == "id"),
            "not at the root, where the parser no longer reads it: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "and the loss is reported: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_on_a_throwing_path_does_not_move_the_node() {
        // `if (bad) { e = other; throw Error(); } parse(e)` reaches `parse` with the untouched
        // node on every execution that produces a result — the writing path produces none.
        // Ordering the write by position alone refused the descent and reported a move.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (bad) { e = other; throw Error("z"); }
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.fields.iter().any(|f| f.name == "id"),
            "the surviving path never wrote: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        assert!(
            p.pending_drops.is_empty(),
            "nothing lost: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_on_a_returning_path_does_move_the_node() {
        // The bound: a `return` hands back a result, so that path DID reach a caller with the
        // node moved and the descent has to decline — and say so.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                if (bad) { e = other; return t; }
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            p.pending_drops
                .iter()
                .any(|u| u == "reassignedNodeHandedOn@parse"),
            "the returning path moved it: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_write_to_a_shadowing_block_binding_does_not_move_the_parameter() {
        // `{ let row; row = other; } parse(row)` assigns to the BLOCK-LOCAL `row`; the argument
        // is the untouched callback parameter. Recording the write against the whole enclosing
        // function blamed the parameter, so a valid descent was discarded and a
        // `reassignedNodeHandedOn` recorded for a node nothing had moved — a drop entry for a
        // loss that did not happen.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    { let row; row = other; }
                    parse(row);
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the parameter was never written: {:?}",
            row.children
        );
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("reassignedNodeHandedOn")),
            "and nothing was lost to report: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn one_value_spelled_on_two_paths_is_still_one_value() {
        // `if (flag) current = e; else current = e;` assigns twice and means one thing, and the
        // count refused the alias for it — the helper's fields left the shape with nothing
        // recorded, for a name that holds the same node however the branch went. Records that
        // COPY A NAME are comparable that way, which is what makes this cheap: no path analysis,
        // just the observation that two copies of `e` are one value.
        //
        // They come back OPTIONAL, not required. Every path here assigns, but saying so needs
        // the branch intersection the requiredness side has and this collector does not — each
        // record carries its own `conditional` and the weaker of the two answers wins, which is
        // the direction that lets a shape accept what the parser demands.
        for body in [
            "var current; if (flag) current = e; else current = e; parse(current);",
            "var current; switch (m) { case 1: current = e; break; default: current = e; } parse(current);",
        ] {
            let id = helper_reached_via(body)
                .into_iter()
                .find(|f| f.name == "id")
                .unwrap_or_else(|| panic!("`{body}` names one node"));
            assert!(!id.required, "`{body}` assigns down a branch: {id:?}");
        }
    }

    #[test]
    fn two_values_are_still_two_however_alike_they_look() {
        // The bounds. Two records that name DIFFERENT sources are two values, and a copy set
        // against a computed value is two as well — `if (flag) current = e; else current =
        // e.child("detail")` names one node down one path and another down the other. Nor does
        // this touch the case the count exists for: a later rebind is a second value, not a
        // second spelling of the first.
        //
        // The all-computed case below is refused twice over, and only one of those is this
        // predicate: `names_for` follows a record only when it copies a NAME, so a pair of
        // computed values never reaches the count at all. Dropping the `from.is_some()` clause
        // breaks no test for exactly that reason — it is there so the predicate answers its own
        // question correctly, not because anything today would notice.
        for body in [
            "var current; if (flag) current = e; else current = other; parse(current);",
            r#"var current; if (flag) current = e; else current = e.child("detail"); parse(current);"#,
            r#"var current; if (flag) current = e.child("a"); else current = e.child("b"); parse(current);"#,
            r#"var current = e; current = e.child("detail"); parse(current);"#,
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "`{body}` names no one node: {:?}",
                fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_generator_helper_is_not_one_the_call_runs() {
        // `function* parse(p){…}` called as `parse(e)` builds an iterator and runs none of the
        // body, so descending into it required of every response what no execution of that call
        // reads — the generated decoder then turns away input the source callback accepts
        // without looking at. The IIFE rule learned this one round earlier; the site that
        // decides whether a module HELPER runs had not.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function* parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.fields.iter().any(|f| f.name == "id"),
            "the body never runs: {:?}",
            p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_helper_the_call_does_run_is_still_descended_into() {
        // The bounds. A plain declaration runs, and so does an `async` one — its body executes
        // synchronously as far as its first `await`, and there is none here. Declining every
        // function whose form is unusual would lose what the parser really reads.
        for helper in [
            r#"function parse(p){ p.attrString("id"); }"#,
            r#"async function parse(p){ p.attrString("id"); }"#,
        ] {
            let module = format!(
                r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){{
                {helper}
                var c=new(r("WADeprecatedWapParser"))("p", function(e){{
                    e.assertTag("receipt");
                    parse(e);
                }});
            }}),1);"#
            );
            let out = parse_module_wap_parsers(&module);
            let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
            assert!(
                p.fields.iter().any(|f| f.name == "id"),
                "`{helper}` runs: {:?}",
                p.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn the_later_of_two_hoisted_declarations_is_the_one_that_runs() {
        // Both are hoisted and the later assignment is the binding left standing, so `parse(e)`
        // calls the second body. Keeping the first published the fields of a body that never
        // runs and omitted the ones that do — a shape disagreeing with the helper the parser
        // actually calls.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(p){ p.attrString("wrong"); }
            function parse(p){ p.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let names: Vec<String> = p.fields.iter().map(|f| f.name.clone()).collect();
        assert!(
            names.iter().any(|n| n == "id") && !names.iter().any(|n| n == "wrong"),
            "the second declaration is the live one: {names:?}"
        );
    }

    #[test]
    fn two_assigned_function_expressions_keep_the_first() {
        // The bound, and why the rule is about HOISTING rather than about being last: `var
        // parse = function(){…}` is not hoisted, so which of two is live depends on where the
        // call sits — `var parse = A; parse(e); var parse = B;` calls A. First-wins is the
        // conservative reading there and is unchanged.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            var parse = function(p){ p.attrString("id"); };
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                parse(e);
            });
            var parse = function(p){ p.attrString("later"); };
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let names: Vec<String> = p.fields.iter().map(|f| f.name.clone()).collect();
        assert!(
            names.iter().any(|n| n == "id") && !names.iter().any(|n| n == "later"),
            "the one live at the call: {names:?}"
        );
    }

    #[test]
    fn an_alias_written_only_after_the_call_is_still_followed() {
        // `var current = row; parse(current); current = row.child("detail")` — the later write
        // cannot reach the call. I made the PARAMETER check order-aware and left the alias
        // count blind to order, so this saw two values and refused to follow `current`.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(q){ q.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    var current = row;
                    parse(current);
                    current = row.child("detail");
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the write is after the call: {:?}",
            row.children
        );
    }

    #[test]
    fn a_fallthrough_does_not_borrow_the_next_cases_test() {
        // Falling through into a case runs its consequent, never its test. Folding the test
        // into the entry path had `case "a": case parse(e): break;` promote a read the `"a"`
        // path never performs.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": case parse(e): break; default: parse(e); }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the \"a\" path never calls it: {id:?}");
    }

    #[test]
    fn a_child_bound_in_a_loop_header_is_restored_after_it() {
        // A `let` in a `for` header is scoped to the loop. Only block statements were being
        // restored, and a loop header is not one, so the trailing read landed under `<inner>`.
        let r = analyze_parser_ast(
            r#"{ var x = e.child("outer");
                 for (let x = e.child("inner"); cond; ) { }
                 x.attrString("id"); }"#,
            "e",
        );
        let paths = placed_paths(&r);
        assert!(
            paths.contains(&"outer/id".to_string()) && !paths.contains(&"inner/id".to_string()),
            "the trailing read is the outer child's: {paths:?}"
        );
    }

    #[test]
    fn a_read_before_a_do_while_break_is_still_required() {
        // The guaranteed first pass reaches everything up to the `break`. Treating the whole
        // body as conditional because it contains one relaxed a call that always runs.
        let fields = helper_reached_via("do { parse(e); break; } while (more);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "the read precedes the break: {id:?}");
    }

    #[test]
    fn a_read_after_a_do_while_break_is_not_required() {
        // And the other side of the same statement: what follows the `break` is exactly as
        // certain as a branch, which is what the original carve-out was for.
        let fields = helper_reached_via("do { if (flag) break; parse(e); } while (more);");
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(!id.required, "the break can skip it: {id:?}");
    }

    #[test]
    fn a_helper_in_a_for_of_binding_default_is_recovered() {
        // `for (const [v = parse(e)] of values)` calls the helper when there is an element.
        // Hand-written visitors that walk only the iterable and the body dropped it, and
        // nothing said so.
        let fields = helper_reached_via("for (const [v = parse(e)] of values) {}");
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the binding is walked: {:?}",
            fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_argument_past_the_helpers_formals_is_not_a_lost_read() {
        // `helper(row)` where `helper()` declares no formals ignores the argument, so there
        // is nothing to recover and nothing to report. Counting the missing position as a
        // pattern binding marked complete shapes as having dropped something.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function helper(){ return 0; }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){ row.attrString("own"); helper(row); });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        assert!(
            !p.pending_drops
                .iter()
                .any(|u| u.starts_with("nodeBoundByPattern")),
            "no formal is not a pattern formal: {:?}",
            p.pending_drops
        );
    }

    #[test]
    fn a_node_written_only_after_the_call_is_still_followed() {
        // `parse(row); row = row.child("detail")` handed the helper the row. I rejected this
        // saying a pre-scan cannot order a write against a call; it can, for the textual
        // part, and rejecting it lost fields that were recoverable.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(q){ q.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    parse(row);
                    row = row.child("detail");
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        assert!(
            row.children
                .as_ref()
                .is_some_and(|kids| kids.iter().any(|f| f.name == "id")),
            "the write is after the call: {:?}",
            row.children
        );
    }

    #[test]
    fn a_node_rewritten_each_pass_of_a_loop_is_not_followed() {
        // The part order cannot settle: a write below the call runs before it on the next
        // pass, so a write inside a loop containing the call still disqualifies the name.
        let module = r#"__d("M",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
            function parse(q){ q.attrString("id"); }
            var c=new(r("WADeprecatedWapParser"))("p", function(e){
                e.assertTag("receipt");
                e.mapChildrenWithTag("row", function(row){
                    while (more) {
                        parse(row);
                        row = row.child("detail");
                    }
                });
            });
        }),1);"#;
        let out = parse_module_wap_parsers(module);
        let p = out.iter().find(|r| r.parser_name == "p").expect("parser");
        let row = p.fields.iter().find(|f| f.name == "row").expect("row");
        let at_root = row
            .children
            .as_ref()
            .is_some_and(|kids| kids.iter().any(|f| f.name == "id"));
        assert!(!at_root, "the loop repeats the write: {:?}", row.children);
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

    #[test]
    fn a_transfer_inside_a_try_ends_the_statement_list() {
        // `try { break; } finally {}` breaks, so `current = other` after it never runs and the
        // read still sees `e`. The catch-all said a `try` never ends the list, which recorded
        // that write as effective and refused the descent.
        for body in [
            "var current = e; do { try { break; } finally {} current = other; } while (0); parse(current);",
            // A finalizer that leaves of its own overrides whatever the block did.
            "var current = e; do { try { g(); } finally { break; } current = other; } while (0); parse(current);",
            // Block and handler both leave, so no path reaches the statement after the `try`.
            "var current = e; do { try { break; } catch (x) { break; } current = other; } while (0); parse(current);",
            // A `catch` intercepts exceptions and nothing else, so a `break` bypasses it. I
            // asserted the opposite one round ago, in the negative below; review was right.
            "var current = e; do { try { break; } catch (x) {} current = other; } while (0); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the write after the transfer is unreachable, so the descent stands: {body}"
            );
        }
    }

    #[test]
    fn a_try_that_can_complete_does_not_end_the_statement_list() {
        // The paired bound: answering `true` for every `TryStatement`, or reading the block
        // without its handler, would call these unreachable too and publish a field the parser
        // never reaches through this alias.
        for body in [
            // Nothing leaves, so the following write is plainly effective.
            "var current = e; do { try { g(); } finally {} current = other; } while (0); parse(current);",
            // A `catch` that completes normally carries on past the `try` — when it can be
            // entered at all. `f()` can raise before the `break` is reached, and the handler
            // then finishes and falls into the statements after the `try`.
            "var current = e; do { try { f(); break; } catch (x) {} current = other; } while (0); parse(current);",
            // `return expr` is not a transfer that evaluates nothing — `f()` runs first and can
            // raise, so the handler is reachable and completes. Only a BARE `return` bypasses.
            "var current = e; do { try { return f(); } catch (x) {} current = other; } while (0); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "a path reaches the reassignment, so the descent is refused: {body}"
            );
        }
    }

    #[test]
    fn a_case_repeating_an_earlier_literal_is_not_an_entry_path() {
        // A switch matches with strict equality and takes the first case that matches, so the
        // second `case "a"` can never be entered directly. Folding its empty reads into the
        // intersection left the payload optional against a switch every reachable entry of
        // which calls `parse`.
        let fields = helper_reached_via(
            r#"switch (mode) { case "a": parse(e); break; case "a": break;
                              default: parse(e); break; }"#,
        );
        let id = fields.iter().find(|f| f.name == "id").expect("recovered");
        assert!(id.required, "nothing can enter the duplicate: {id:?}");
    }

    #[test]
    fn a_distinct_case_still_dilutes_the_intersection() {
        // The paired bound, three ways: a different literal is a real entry path; the FIRST of
        // two duplicates is the one that matches, so an empty one there still dilutes; and a
        // computed test is not decidable by reading it, so it shadows nothing.
        for body in [
            r#"switch (mode) { case "a": parse(e); break; case "b": break;
                               default: parse(e); break; }"#,
            r#"switch (mode) { case "a": break; case "a": parse(e); break;
                               default: parse(e); break; }"#,
            r#"switch (mode) { case k.A: parse(e); break; case k.A: break;
                               default: parse(e); break; }"#,
        ] {
            let fields = helper_reached_via(body);
            let id = fields.iter().find(|f| f.name == "id").expect("recovered");
            assert!(!id.required, "an entry path returns without it: {body}");
        }
    }

    #[test]
    fn a_default_its_argument_supplies_does_not_run() {
        // A parameter default is evaluated only for a missing or `undefined` argument, so
        // `(function (x = (current = other)) {})(1)` never performs that write and `parse` is
        // handed the original node. Walking the callee wholesale recorded it and the helper's
        // fields were dropped from a shape that really does read them.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {})(1); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the supplied argument prevents the default: {fields:?}"
        );
    }

    #[test]
    fn a_default_the_call_does_not_supply_still_runs() {
        // The paired bound. Only a value that can be read off the source settles the question:
        // no argument at all runs the default, and an argument whose value has to be computed
        // could be `undefined`, so it settles nothing and the write stands.
        for body in [
            "var current = e; (function (x = (current = other)) {})(); parse(current);",
            "var current = e; (function (x = (current = other)) {})(maybe); parse(current);",
            "var current = e; (function (x = (current = other)) {})(void 0); parse(current);",
            "var current = e; (function (x = (current = other)) {})(...args); parse(current);",
            // The mapping is positional: an argument for the FIRST parameter says nothing
            // about the second's default.
            "var current = e; (function (a, x = (current = other)) {})(1); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the default can still run, so the node moved: {body}"
            );
        }
    }

    #[test]
    fn a_nested_default_the_argument_supplies_does_not_run() {
        // The same rule one level in. `function ({x = (current = other)})` called with `{x: 1}`
        // never evaluates that initializer, and checking only `FormalParameter::initializer`
        // left every destructured spelling of it recording a write the call prevents.
        for body in [
            "var current = e; (function ({x = (current = other)}) {})({x: 1}); parse(current);",
            "var current = e; (function ([x = (current = other)]) {})([1]); parse(current);",
            // Through a level of nesting, and past a sibling the argument does not name.
            "var current = e; (function ({a: {x = (current = other)}}) {})({a: {x: 1}}); parse(current);",
            // A computed key whose name is readable is readable, and the LAST property of a
            // name is the one the object carries.
            r#"var current = e; (function ({x = (current = other)}) {})({["x"]: 1}); parse(current);"#,
            r#"var current = e; (function ({x = (current = other)}) {})({["x"]: undefined, x: 1}); parse(current);"#,
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the supplied value prevents the nested default: {body}"
            );
        }
    }

    #[test]
    fn a_nested_default_the_argument_leaves_open_still_runs() {
        // The paired bound. Only what reading the source settles counts as supplied: a property
        // the literal does not name, a missing element, an argument that is not a literal at
        // all, a spread that could supply or shadow anything, and a computed key.
        for body in [
            "var current = e; (function ({x = (current = other)}) {})({}); parse(current);",
            "var current = e; (function ([x = (current = other)]) {})([]); parse(current);",
            "var current = e; (function ({x = (current = other)}) {})(obj); parse(current);",
            "var current = e; (function ({x = (current = other)}) {})({...rest}); parse(current);",
            // A spread can SHADOW a property the literal names, with `undefined` among other
            // things, so naming `x` alongside one settles nothing either.
            "var current = e; (function ({x = (current = other)}) {})({x: 1, ...rest}); parse(current);",
            // And a later property of the same name wins, so the effective `x` is `undefined`
            // and the default runs after all.
            r#"var current = e; (function ({x = (current = other)}) {})({x: 1, ["x"]: undefined}); parse(current);"#,
            "var current = e; (function ({x = (current = other)}) {})({x: undefined}); parse(current);",
            // The parameter's own default runs, so the pattern takes THAT apart and the
            // argument says nothing about what is inside it.
            "var current = e; (function ({x = (current = other)} = {}) {})(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the default can still run, so the node moved: {body}"
            );
        }
    }

    #[test]
    fn a_class_constructed_in_place_runs_its_body_now() {
        // `new (class { constructor(){ current = other; } })()` runs that constructor as
        // certainly as an IIFE body runs. Treating it as a method nobody calls confined the
        // write, so the alias `current = e` still looked live and the helper's fields were
        // published on a node the constructor had replaced — the wrong-node direction, which
        // is why this stopped being a decline. An instance field initializer runs on the same
        // construction and is the same answer.
        for body in [
            "var current = e; new (class { constructor() { current = other; } })(); parse(current);",
            "var current = e; new (class { value = (current = other); })(); parse(current);",
            "var current = e; new (class { accessor value = (current = other); })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the construction moved the node: {body}"
            );
        }
    }

    #[test]
    fn a_class_nobody_constructs_still_defers_its_bodies() {
        // The paired bound, and it is the whole reason this is not simply "a class runs its
        // methods". Defining one runs neither its constructor nor its instance initializers;
        // CALLING a class throws, so its body runs on no path; a method that is not the
        // constructor is not invoked by `new`; and `new Thing()` reaches no body this scanner
        // can see at all.
        for body in [
            "var current = e; var C = class { constructor() { current = other; } }; parse(current);",
            "var current = e; var C = class { value = (current = other); }; parse(current);",
            "var current = e; new (class { run() { current = other; } })(); parse(current);",
            "var current = e; new Thing(); parse(current);",
            // CALLING a class throws before any body runs, so the write happens on no path —
            // which is why the arm is guarded on `new` rather than on the callee being a class.
            "var current = e; (class { constructor() { current = other; } })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing ran that body, so the node still stands: {body}"
            );
        }
    }

    #[test]
    fn a_getter_does_not_supply_the_property_it_names() {
        // Reading `x` off `{get x(){ … }}` INVOKES that function, and its result is not
        // something this can read; `{set x(v){}}` supplies no getter at all, so reading `x`
        // yields `undefined`. Either way the default runs. Taking the property's own text as
        // the value saw a `FunctionExpression` and called it definitely defined.
        for body in [
            "var current = e; (function ({x = (current = other)}) {})({get x() { return undefined; }}); parse(current);",
            "var current = e; (function ({x = (current = other)}) {})({set x(v) {}}); parse(current);",
            // The LAST property of the name decides, and it is an accessor — deciding the name
            // and the kind in one pass let this fall through to the plain `x` before it.
            "var current = e; (function ({x = (current = other)}) {})({x: 1, get x() { return undefined; }}); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "an accessor settles nothing, so the default runs: {body}"
            );
        }
    }

    #[test]
    fn a_shorthand_method_is_still_the_property_value() {
        // The bound: a method's value IS that function, so `x` is defined and the default does
        // not run. Declining for every function-valued property would have lost this.
        let fields = helper_reached_via(
            "var current = e; (function ({x = (current = other)}) {})({x() {}}); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "a method supplies the property: {fields:?}"
        );
    }

    #[test]
    fn instance_fields_run_before_the_constructor_body() {
        // Every instance field initializes before the constructor runs, wherever it is written.
        // Source order had `class { constructor(){ parse(current); } x = (current = other); }`
        // read the node the field had already replaced.
        for body in [
            "var current = e; new (class { constructor() { parse(current); } x = (current = other); })();",
            "var current = e; new (class { x = (current = other); constructor() { parse(current); } })();",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the field moved the node before the constructor read it: {body}"
            );
        }
    }

    #[test]
    fn a_derived_class_keeps_its_fields_in_source_order() {
        // A DERIVED class initializes its instance fields when `super()` returns, which is
        // somewhere inside the constructor body and not before it. So a read placed before the
        // `super()` call still sees the node the field has not replaced yet, and declaring the
        // field to precede the whole body — the base-class rule applied one class too far —
        // would answer that with the field.
        let fields = helper_reached_via(
            "var current = e; new (class extends Base { constructor() { parse(current); super(); } x = (current = other); })();",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the field has not run at that point: {fields:?}"
        );
    }

    #[test]
    fn a_class_definition_runs_before_the_constructor_arguments() {
        // `new C(args)` evaluates the class expression first, then the arguments, then
        // constructs. So a STATIC initializer runs before an argument's write and a constructor
        // body runs after it. Naming the whole class span as the region the arguments precede
        // answered both with the second.
        let fields = helper_reached_via(
            "var current = e; new (class { static x = parse(current); })(current = other);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the static initializer ran before the argument: {fields:?}"
        );
    }

    #[test]
    fn a_constructor_argument_still_precedes_the_constructor_body() {
        // The paired bound, and the reason the region is the construction rather than nothing:
        // an argument really does run before the constructor body, however far after it the
        // argument is written.
        let fields = helper_reached_via(
            "var current = e; new (class { constructor() { parse(current); } })(current = other);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the argument moved the node before the constructor read it: {fields:?}"
        );
    }

    #[test]
    fn a_constructor_default_its_argument_supplies_does_not_run() {
        // `new` hands its arguments to the constructor exactly as a call hands them to a
        // function, so the same defaults are prevented — a rule that reached the two function
        // callee shapes and not the one made an invocation the round before.
        let fields = helper_reached_via(
            "var current = e; new (class { constructor(x = (current = other)) {} })(1); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the supplied argument prevents the constructor's default: {fields:?}"
        );
    }

    #[test]
    fn a_constructor_default_the_construction_omits_still_runs() {
        // The bound, as for a plain call.
        let fields = helper_reached_via(
            "var current = e; new (class { constructor(x = (current = other)) {} })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "no argument, so the default runs: {fields:?}"
        );
    }

    #[test]
    fn a_derived_class_orders_its_fields_at_the_super_call() {
        // A derived class initializes its instance fields the moment `super()` returns, so a
        // read after that call sees them however far below it the field is written. Keeping
        // source order for the whole constructor — which is what excluding derived classes
        // outright did — answered that with the field's position.
        let fields = helper_reached_via(
            "var current = e; new (class extends Base { constructor() { super(); parse(current); } x = (current = other); })();",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the field ran when super() returned: {fields:?}"
        );
    }

    #[test]
    fn a_read_before_super_still_precedes_the_fields() {
        // The paired bound, both ways it matters: nothing before the `super()` call has seen a
        // field yet, and a call this cannot place — under an `if`, or absent — leaves source
        // order as the answer rather than guessing at one.
        for body in [
            "var current = e; new (class extends Base { constructor() { parse(current); super(); } x = (current = other); })();",
            "var current = e; new (class extends Base { constructor() { if (f) super(); parse(current); } x = (current = other); })();",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the field has not run at that point: {body}"
            );
        }
    }

    #[test]
    fn a_property_after_every_spread_still_supplies_its_name() {
        // A spread can supply a name or shadow one, so nothing before or between them settles
        // anything — but a property written after the LAST of them is what the object ends up
        // with whatever the spreads held. Discarding the whole literal the moment a spread
        // appeared threw those away with the rest.
        let fields = helper_reached_via(
            "var current = e; (function ({x = (current = other)}) {})({...{}, x: 1}); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the trailing property supplies it: {fields:?}"
        );
    }

    #[test]
    fn a_property_a_later_spread_can_shadow_settles_nothing() {
        // The paired bound: only properties after EVERY spread count, because any spread after
        // one can overwrite it — with `undefined` among other things, which runs the default.
        for body in [
            "var current = e; (function ({x = (current = other)}) {})({x: 1, ...rest}); parse(current);",
            "var current = e; (function ({x = (current = other)}) {})({...a, x: 1, ...b}); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "a later spread can shadow it, so the default may run: {body}"
            );
        }
    }

    #[test]
    fn an_array_position_before_a_spread_is_still_fixed() {
        // A spread contributes an unknown number of elements, so positions from there on shift
        // by an amount nothing here can read — but the ones BEFORE it are exactly where they
        // are written. Discarding the whole literal on sight of a spread threw those away too.
        // The mirror of the object rule, which keeps what comes AFTER the last spread: there
        // names shift and positions do not.
        let fields = helper_reached_via(
            "var current = e; (function ([x = (current = other)]) {})([1, ...rest]); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "element zero is always 1: {fields:?}"
        );
    }

    #[test]
    fn an_array_position_a_spread_can_shift_settles_nothing() {
        // The paired bound: a position at or after the first spread is not the one it looks.
        for body in [
            "var current = e; (function ([a, x = (current = other)]) {})([...rest, 1]); parse(current);",
            "var current = e; (function ([a, x = (current = other)]) {})([1, ...rest]); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the spread shifts that position: {body}"
            );
        }
    }

    #[test]
    fn a_unary_argument_other_than_void_is_supplied() {
        // Every unary operator but one produces a value: `-1` and `+x` a number, `!0` a
        // boolean, `~x` a number, `typeof x` a string. Excluding the whole node kind turned
        // the minifier's own `-1` and `!0` into values this could not read, so a default their
        // call prevents was recorded as a write.
        for body in [
            "var current = e; (function (x = (current = other)) {})(-1); parse(current);",
            "var current = e; (function (x = (current = other)) {})(!0); parse(current);",
            // Parentheses change nothing about the value.
            "var current = e; (function (x = (current = other)) {})((-1)); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the argument is not undefined: {body}"
            );
        }
    }

    #[test]
    fn void_is_still_undefined() {
        // The one exception, and it is the spelling minifiers use FOR `undefined` — so this is
        // the bound that stops the widening from swallowing the case it was written around.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {})(void 0); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "`void 0` supplies undefined, so the default runs: {fields:?}"
        );
    }

    #[test]
    fn an_await_nothing_reaches_suspends_nothing() {
        // The synchronous prefix ends at the first await CONTROL CAN REACH. `if (0) await x;`
        // is not one, so the statements after it run before the call returns — taking the first
        // textual await confined a write the caller does see, and the helper's fields were
        // published on the node it had moved away from.
        let fields = helper_reached_via(
            "var current = e; (async function () { if (0) await 0; current = other; })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the write ran synchronously: {fields:?}"
        );
    }

    #[test]
    fn an_await_that_can_run_still_ends_the_synchronous_part() {
        // The paired bound: an `await` EVERY path reaches cuts the prefix, and what follows it
        // is the continuation's whatever else the body does.
        for body in [
            "var current = e; (async function () { await 0; current = other; })(); parse(current);",
            // Including a write inside the suspending branch itself, past its own await.
            "var current = e; (async function () { if (flag) { await 0; current = other; } })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the caller does not wait for that write: {body}"
            );
        }
        // `if (flag) await 0; current = other;` is NOT one of them, and I had it here asserting
        // that it was. When `flag` is false nothing suspends and the write is as synchronous as
        // it looks, so the two executions disagree about what `parse` receives — and a model
        // that answers "the caller did not see it" publishes the helper's reads under a node
        // half of them replaced. Declining is the answer that loses fields instead. The claim
        // was mine and review corrected it; the case sits in
        // `a_bypassed_await_leaves_its_continuation_synchronous`.
    }

    #[test]
    fn a_statically_dead_branch_writes_nothing() {
        // A write on the side a decided test never selects cannot happen at all. Walking it as
        // merely skippable made it a second live value for the name, so the alias was refused
        // and the helper's fields left the shape with nothing said. `if (0) { … }` with no
        // `else` is the same answer, and the selector had been declining it outright because
        // nothing is taken.
        for body in [
            "var current = e; if (0) { current = other; } else {} parse(current);",
            "var current = e; if (0) { current = other; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that write cannot happen: {body}"
            );
        }
    }

    #[test]
    fn a_branch_that_can_run_still_moves_the_node() {
        // The paired bound: an undecided test leaves two live values, and a decided test that
        // selects the write makes it certain. Neither is silenced by the dead-side rule.
        for body in [
            "var current = e; if (flag) { current = other; } parse(current);",
            "var current = e; if (1) { current = other; } parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the write can happen: {body}"
            );
        }
    }

    #[test]
    fn one_branch_of_an_if_suspending_does_not_confine_the_other() {
        // The two sides of an undecided `if` are alternatives, not a sequence. `if (flag) {
        // await x; } else { current = other; }` suspends on one side and runs to its end on the
        // other, and taking the minimum await position across both confined a write that really
        // is synchronous whenever its own side is selected — so the node looked unmoved and the
        // field came out REQUIRED on a node half the executions had replaced. Two live values
        // now, which is a decline.
        let fields = helper_reached_via(
            "var current = e; (async function () { if (flag) { await 0; } else { current = other; } })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the write may have happened, so the alias is refused: {fields:?}"
        );
    }

    #[test]
    fn a_suspension_the_write_really_is_past_still_confines_it() {
        // The bound, and it is what stops the branch rule swallowing a real suspension: an
        // await BEFORE the `if` is one every side is past, and an `if` both of whose sides
        // suspend leaves everything after it past one too. In both the caller returns before
        // that write and still sees the original node.
        for body in [
            "var current = e; (async function () { await 0; if (flag) {} else { current = other; } })(); parse(current);",
            "var current = e; (async function () { if (flag) { await 0; } else { await 1; } current = other; })(); parse(current);",
            // And a write past the await on its OWN side is past one: keeping the whole branch
            // as synchronous because a sibling suspends would answer that with the sibling.
            "var current = e; (async function () { if (flag) { await 0; current = other; } else {} })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the caller does not wait for that write: {body}"
            );
        }
    }

    #[test]
    fn a_function_invoked_through_call_runs_now() {
        // `(function(){ … }).call(null)` runs that body as immediately as `()` does. The callee
        // is a member expression, so the matcher fell through to the deferred walk, the write
        // stayed confined, and the helper's fields were published on a node it had replaced.
        for body in [
            "var current = e; (function () { current = other; }).call(null); parse(current);",
            "var current = e; (function () { current = other; }).apply(null); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the body ran, so the node moved: {body}"
            );
        }
    }

    #[test]
    fn call_on_anything_but_an_inline_function_is_not_an_invocation() {
        // The bound: `thing.call(null)` is a call this scanner cannot follow, and reading every
        // `.call` as immediate would claim a body it has never seen.
        let fields = helper_reached_via("var current = e; thing.call(null); parse(current);");
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "nothing inline was invoked: {fields:?}"
        );
    }

    #[test]
    fn call_shifts_the_parameters_past_the_receiver() {
        // `.call(thisArg, a)` hands `a` to the first parameter, so a default it supplies does
        // not run — and a LITERAL `.apply(thisArg, [a])` list is as readable as an argument
        // list, which I asserted the opposite of one round ago. Review was right: answering
        // "unknowable" for every `.apply` walked a default the call really does prevent.
        for body in [
            "var current = e; (function (x = (current = other)) {}).call(null, 1); parse(current);",
            "var current = e; (function (x = (current = other)) {}).apply(null, [1]); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the argument past the receiver supplies it: {body}"
            );
        }
        for body in [
            "var current = e; (function (x = (current = other)) {}).call(null); parse(current);",
            // A list this cannot read, and one whose positions a spread has moved.
            "var current = e; (function (x = (current = other)) {}).apply(null, list); parse(current);",
            "var current = e; (function (x = (current = other)) {}).apply(null, [...r]); parse(current);",
            // A spread ENDS the mapping rather than being skipped over: the `1` after it is not
            // at position zero, whatever it looks like.
            "var current = e; (function (x = (current = other)) {}).apply(null, [...r, 1]); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "nothing readable reaches that parameter: {body}"
            );
        }
    }

    #[test]
    fn a_computed_key_runs_before_every_static_initializer() {
        // Every computed key is evaluated when the class is DEFINED, before any static
        // initializer runs, whatever their source order — so a key written BELOW an initializer
        // still reads what that initializer has not yet written. This is the two-phase clock
        // the PR declined for several rounds: repositioning the writes broke two neighbours,
        // because pushing them past the keys pushes them past each other. Declaring that they
        // FOLLOW the keys leaves every other ordering where it was.
        for body in [
            "var current = e; class C { static x = (current = other); [parse(current)]() {} }",
            "var current = e; class C { [parse(current)]() {} static x = (current = other); }",
            // A static block is the same phase as an initializer.
            "var current = e; class C { static { current = other; } [parse(current)]() {} }",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the key ran before the initializer: {body}"
            );
        }
    }

    #[test]
    fn a_read_after_the_class_still_sees_its_static_initializer() {
        // The bound, and the reason this is a declaration and not a reordering: the write is
        // still effective everywhere outside the keys, so a read after the class sees it, and
        // one key does not stop seeing what an EARLIER key wrote.
        for body in [
            "var current = e; class C { static x = (current = other); } parse(current);",
            "var current = e; class C { static [(current = other, 0)] = 1; static [parse(current)] = 2; }",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that write is effective here: {body}"
            );
        }
    }

    #[test]
    fn a_computed_key_write_precedes_every_static_initializer() {
        // The same ordering read the other way. Saying only that an initializer FOLLOWS the
        // keys left a key written below one still at its own offset, so the initializer read a
        // node the key had in fact already replaced. Both halves of one rule; shipping the
        // first alone is the shape this branch keeps finding in its own work.
        for body in [
            "var current = e; class C { static x = parse(current); [(current = other)]() {} }",
            "var current = e; class C { static x = parse(current); static [(current = other)] = 1; }",
            "var current = e; class C { static { parse(current); } [(current = other)]() {} }",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the key ran before the initializer read it: {body}"
            );
        }
    }

    #[test]
    fn an_apply_list_this_can_read_supplies_the_parameters() {
        // A literal `.apply(thisArg, [1])` list is as readable as an argument list. Answering
        // "unknowable" for every `.apply` walked a default the call really does prevent — which
        // I asserted was correct one round ago, and it was not.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {}).apply(null, [1]); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the list supplies that parameter: {fields:?}"
        );
    }

    #[test]
    fn a_call_receiver_keeps_its_leading_effects() {
        // The callee unwrapper looks through `.call`, and `leading_parts` was still handed the
        // member expression — so `(current = other, function(){}).call(null)` found the function
        // and lost the assignment beside it. Two readers of one shape, one of them taught.
        let fields = helper_reached_via(
            "var current = e; (current = other, function () {}).call(null); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the comma's leading element still runs: {fields:?}"
        );
    }

    #[test]
    fn a_bound_function_called_at_once_runs_now() {
        // `(function(){ … }).bind(null)()` runs that body as immediately as `()` does. The
        // callee of the outer call is itself a CALL, so nothing matched it and the body was
        // walked as one nobody reaches.
        let fields = helper_reached_via(
            "var current = e; (function () { current = other; }).bind(null)(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the bound body ran: {fields:?}"
        );
    }

    #[test]
    fn binding_anything_else_is_not_an_invocation() {
        // The bound: `thing.bind(null)()` calls a body this scanner has never seen.
        for body in [
            "var current = e; thing.bind(null)(); parse(current);",
            // And only `.bind`: what `(function(){ … }).map(g)` hands back is not that function,
            // so calling it runs a body this scanner has not seen.
            "var current = e; (function () { current = other; }).map(null)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing inline was invoked: {body}"
            );
        }
    }

    #[test]
    fn bound_arguments_land_on_the_parameters_they_reach() {
        // `f.bind(thisArg, ...bound)(...outer)` hands `f` the bound arguments and then the outer
        // call's, which is as countable as an argument list — so each of these supplies `x` and
        // the default beside it never runs. I claimed the opposite when the invocation was first
        // recognized, and put it in the negative of the test above; review corrected it, and the
        // case sits on this side now.
        for body in [
            "var current = e; (function (x = (current = other)) {}).bind(null)(1); parse(current);",
            "var current = e; (function (x = (current = other)) {}).bind(null, 1)(); parse(current);",
            // Nesting resolves one `bind` at a time: `null` and `1` are the two receivers, and
            // the outer `2` is what reaches `x`.
            "var current = e; (function (x = (current = other)) {}).bind(null).bind(1)(2); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the argument supplied it: {body}"
            );
        }
    }

    #[test]
    fn a_position_no_one_can_count_to_supplies_nothing() {
        // The bound, and the reason the mapping is not simply "skip the receiver". A spread
        // contributes an unknown number of values, so nothing after it is at a knowable
        // position — `f.call(...args, 1)` passes `1` as the receiver when `args` is empty and as
        // the first argument when it holds one. Claiming a position there is the harmful
        // direction: it suppresses a default that really runs, and publishes a helper's reads
        // under a node the call had replaced.
        for body in [
            // Nothing bound and nothing passed: the default is all there is.
            "var current = e; (function (x = (current = other)) {}).bind(null)(); parse(current);",
            "var current = e; (function (x = (current = other)) {}).bind(...args, 1)(); parse(current);",
            "var current = e; (function (x = (current = other)) {}).bind(null, ...args)(1); parse(current);",
            "var current = e; (function (x = (current = other)) {}).call(...args, 1); parse(current);",
            "var current = e; (function (x = (current = other)) {}).apply(...args, [1]); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the default still ran: {body}"
            );
        }
    }

    #[test]
    fn a_bind_call_evaluates_its_own_arguments() {
        // `(function(){ … }).bind(null, current = other)()` evaluates the bind call — receiver
        // and arguments both — before the body it returns is ever entered. The callee unwrapper
        // looks through this shape and this reader did not, so the assignment was recorded
        // nowhere at all.
        for body in [
            "var current = e; (function () {}).bind(null, current = other)(); parse(current);",
            "var current = e; (function () {}).bind(current = other)(); parse(current);",
            "var current = e; (function () {}).bind(null, ...(current = other))(); parse(current);",
            // And the RECEIVER of the bind, which is the half that is easy to leave out:
            // `(current = other, function(){}).bind(null)()` finds the function through the
            // comma and would lose the assignment sitting beside it.
            "var current = e; (current = other, function () {}).bind(null)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the bind call moved it: {body}"
            );
        }
        // The bound: a bind call that writes nothing leaves the node standing.
        let fields = helper_reached_via(
            "var current = e; (function () {}).bind(null, o)(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "nothing moved: {fields:?}"
        );
    }

    #[test]
    fn an_update_the_body_never_reaches_is_not_recorded() {
        // `for (;; current = other) { parse(current); break; }` runs its body once and leaves,
        // so the update never evaluates — but it is written in the HEADER, above the body, so
        // recording it had it look effective at a call below and the descent was refused for a
        // node nothing had moved. The same `can_come_round_again` the loop-carried rule reads.
        let fields = helper_reached_via(
            "var current = e; for (;; current = other) { parse(current); break; }",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that update never runs: {fields:?}"
        );
    }

    #[test]
    fn an_update_a_next_pass_can_reach_is_still_recorded() {
        // The bound: a body that can come round again reaches its update, and the write is then
        // carried into the next pass exactly as before.
        let fields =
            helper_reached_via("var current = e; for (;; current = other) { parse(current); }");
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "a next pass sees it: {fields:?}"
        );
    }

    #[test]
    fn an_iterable_is_evaluated_before_the_loop_target() {
        // JavaScript evaluates the iterable, then assigns the target once per element — so
        // `parse` here is handed the node itself and the empty list never assigns anything.
        // Two rules had said otherwise at once: the target's write is WRITTEN above the
        // iterable, and it repeats with a loop whose span covers the iterable textually, so
        // ordering it alone would still have been overruled by the next-pass rule.
        for body in [
            "var current = e; for (current of (parse(current), [])) {}",
            "var current = e; for (current in (parse(current), {})) {}",
            // And the guaranteed-pass branch is the same statement with a decidable length.
            "var current = e; for (current of (parse(current), [1])) {}",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the iterable ran first: {body}"
            );
        }
    }

    #[test]
    fn the_body_and_what_follows_still_see_the_loop_target() {
        // The bound, both ways. Only the ITERABLE precedes the write; the body runs after the
        // target is assigned, and so does everything past the loop.
        for body in [
            "var current = e; for (current of xs) { parse(current); }",
            "var current = e; for (current of xs) {} parse(current);",
            "var current = e; for (current in xs) { parse(current); }",
            "var current = e; for (current of [1]) { parse(current); }",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the target was assigned by then: {body}"
            );
        }
    }
    #[test]
    fn a_derived_constructor_that_leaves_first_runs_no_field() {
        // A derived class installs its instance fields the moment `super()` RETURNS. A
        // constructor that leaves before calling it — legal, and it completes construction with
        // the object it returns — runs none of them, so `parse` is handed the node itself.
        // Construction alone was taken as enough, and the write was recorded for a field that
        // never initializes.
        let fields = helper_reached_via(
            "var current = e; new (class extends Base { constructor(){ return {}; } x = (current = other) })(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the field never ran: {fields:?}"
        );
    }

    #[test]
    fn every_other_construction_still_runs_its_fields() {
        // The bound, four ways. A `super()` on the way still installs them; an implicit
        // constructor is `constructor(...a){ super(...a) }` and always calls it; a BASE class
        // installs its fields before the constructor body, so leaving early there changes
        // nothing; and a `super()` under a condition is one this cannot rule out, which is the
        // direction that keeps a write rather than guessing it away.
        for body in [
            "var current = e; new (class extends Base { constructor(){ super(); } x = (current = other) })(); parse(current);",
            "var current = e; new (class extends Base { x = (current = other) })(); parse(current);",
            "var current = e; new (class { constructor(){ return {}; } x = (current = other) })(); parse(current);",
            "var current = e; new (class extends Base { constructor(){ if (c) super(); return {}; } x = (current = other) })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the field still initializes: {body}"
            );
        }
    }
    #[test]
    fn an_unreachable_short_circuit_await_suspends_nothing() {
        // A short-circuit operator is a decided branch in expression form. `0 && await 0` never
        // evaluates its right side, so the write after it is as synchronous as it looks and
        // lands at the call — the pruning was written for `if` and left out here, so the probe
        // took an unreachable await as the cutoff and confined a write the caller does see.
        for body in [
            "var current = e; (async function () { 0 && await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { 1 || await 0; current = other; })(); parse(current);",
            // `??` prunes on the same answer: a value this calls certainly truthy is certainly
            // not nullish.
            "var current = e; (async function () { 1 ?? await 0; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the await is unreachable: {body}"
            );
        }
    }

    #[test]
    fn a_reachable_short_circuit_await_still_suspends() {
        // The bound, one per operator, and it is the complement rather than a variation: an
        // undecided left side still reaches the await, and so does a decided one whose value
        // selects the OTHER way. `null ?? x` is the case that separates "certainly falsy" from
        // "certainly non-nullish" — the two are not the same question.
        for body in [
            "var current = e; (async function () { c && (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { 1 && (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { 0 || (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { null ?? (await 0, current = other); })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that await still runs: {body}"
            );
        }
    }

    #[test]
    fn nested_binds_keep_their_inner_to_outer_order() {
        // The second `bind` EXTENDS the list the first one built, so the outer group is a suffix
        // of the inner one. Built the other way round, `.bind(null, undefined).bind(null, 1)`
        // gave the first parameter the `1` and suppressed a default that really runs — and an
        // `undefined` in the first bound slot is exactly the value that makes the difference
        // visible, because it supplies nothing.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {}).bind(null, undefined).bind(null, 1)(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the first bound value is undefined, so the default ran: {fields:?}"
        );
        // And the receiver slot of a `.call` reached THROUGH a bind is not a position this can
        // count either: `f.call.bind(null, 1)()` calls `f.call(1)`, so the `1` is the receiver
        // and `f` gets nothing. Recovering the bind chain with the unwrapper that looks through
        // `bind` reported `f` as the function underneath and mapped the `1` onto its first
        // parameter; peeling only the wrappers that do not change which value an expression is
        // finds the `.call` and declines.
        let fields = helper_reached_via(
            "var current = e; (function (x = (current = other)) {}).call.bind(null, 1)(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the 1 is the receiver, so the default ran: {fields:?}"
        );
        // The bound, the same two values the other way about: now `x` is the `1` and the
        // default is prevented, with `undefined` landing on a parameter that has none.
        for body in [
            "var current = e; (function (x = (current = other)) {}).bind(null, 1).bind(null, undefined)(); parse(current);",
            "var current = e; (function (y, x = (current = other)) {}).bind(null, 1).bind(null, 2)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "the argument supplied it: {body}"
            );
        }
    }

    #[test]
    fn a_bind_argument_runs_before_the_body_it_binds() {
        // The bind call is evaluated to produce the function, so its arguments run before that
        // function's body — `parse` here is handed `other`. Recording those effects at their own
        // offsets answered this with source order, and a `bind` call's arguments are written
        // BELOW the function, so the body read against a write that had already run.
        let fields = helper_reached_via(
            "var current = e; (function () { parse(current); }).bind(null, current = other)();",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the bind argument had already run: {fields:?}"
        );
        // The bound: a bind call that writes nothing leaves the body reading the node, and the
        // neighbour this now matches — an ordinary argument, which has precededed the body since
        // the round that separated the two.
        let fields = helper_reached_via(
            "var current = e; (function () { parse(current); }).bind(null, o)();",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "nothing moved: {fields:?}"
        );
        let fields = helper_reached_via(
            "var current = e; (function () { parse(current); })(current = other);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "an argument precedes the body too: {fields:?}"
        );
        // And it precedes only what construction actually runs last. A class is evaluated in
        // full — computed keys and static initializers included — before `.bind` is even
        // reached, so a static initializer does not see the bind argument, while the
        // constructor body does. Naming the whole callee span here instead of the construction
        // regions is what that first case rules out.
        let fields = helper_reached_via(
            "var current = e; new ((class { static x = parse(current); }).bind(null, current = other))();",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the static initializer ran before the bind: {fields:?}"
        );
        let fields = helper_reached_via(
            "var current = e; new ((class { constructor(){ parse(current); } }).bind(null, current = other))();",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the constructor body runs after it: {fields:?}"
        );
    }
    #[test]
    fn a_coalesce_asks_about_null_not_about_truth() {
        // `??` skips its right side when the left is non-nullish, which is not the same set as
        // truthy: `0` and `""` are falsy and perfectly non-nullish, so the await after them is
        // unreachable and the write is synchronous. Grouping the operator with `||` answered
        // the narrower question and confined a write the caller does see.
        for body in [
            "var current = e; (async function () { 0 ?? await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { \"\" ?? await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { !1 ?? await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { ({}) ?? await 0; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that left side is not nullish: {body}"
            );
        }
    }

    #[test]
    fn a_nullish_left_side_still_reaches_the_coalesce() {
        // The bound, and the three spellings of the value this has to decline: `null`, the
        // `void 0` a minifier writes for `undefined`, and a bare `undefined`, which is an
        // identifier this cannot resolve. An arbitrary expression declines with them.
        for body in [
            "var current = e; (async function () { null ?? (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { void 0 ?? (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { undefined ?? (await 0, current = other); })(); parse(current);",
            "var current = e; (async function () { c ?? (await 0, current = other); })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that await still runs: {body}"
            );
        }
    }

    #[test]
    fn a_for_await_evaluates_its_iterable_first() {
        // `for await` suspends on drawing each result, not on producing the iterable — that is
        // evaluated synchronously, before anything is awaited. Noting the suspension at the
        // head of the whole statement put the iterable's own writes past the cutoff and
        // confined a write the caller does see.
        let fields = helper_reached_via(
            "var current = e; (async function () { for await (const x of (current = other, [])) {} })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the iterable ran synchronously: {fields:?}"
        );
        // The bound: everything the loop itself does is past the suspension, and so is anything
        // in the iterable that follows an await of its own — which is why the right side is
        // walked rather than skipped over.
        for body in [
            "var current = e; (async function () { for await (const x of []) { current = other; } })(); parse(current);",
            "var current = e; (async function () { for await (const x of (await g(), (current = other, []))) {} })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that write is the continuation's: {body}"
            );
        }
    }

    #[test]
    fn a_derived_field_follows_the_code_before_super() {
        // A derived class installs its instance fields the moment `super()` RETURNS, so a read
        // in the constructor before that call sees none of them. The fields are written above
        // the constructor, so position alone called them already effective — the round that
        // said what they PRECEDE left out what they follow, and neither half is right without
        // the other.
        let fields = helper_reached_via(
            "var current = e; new (class extends Base { x = (current = other); constructor(){ parse(current); super(); } })();",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the field had not initialized yet: {fields:?}"
        );
        // The bound, three ways. Past the `super()` the field is installed; a STATIC
        // initializer runs when the class is defined and waits for no constructor at all; and a
        // BASE class installs its fields before its constructor body, so nothing there follows
        // anything.
        for body in [
            "var current = e; new (class extends Base { x = (current = other); constructor(){ super(); parse(current); } })();",
            "var current = e; new (class extends Base { static x = (current = other); constructor(){ parse(current); super(); } })();",
            "var current = e; new (class { x = (current = other); constructor(){ parse(current); } })();",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the field had run by then: {body}"
            );
        }
    }

    #[test]
    fn a_generator_call_runs_its_parameter_defaults() {
        // Calling a generator binds its parameters and hands back an iterator: the default runs
        // now, even though the body runs only when something draws from it. Declining the whole
        // callee confined that write with the body's.
        let fields = helper_reached_via(
            "var current = e; (function* (x = (current = other)) {})(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the default ran at the call: {fields:?}"
        );
        // The bound: the BODY is still nobody's until something iterates, and a supplied
        // argument still prevents the default exactly as it does for a plain function.
        for body in [
            "var current = e; (function* () { current = other; })(); parse(current);",
            "var current = e; (function* (x = (current = other)) {})(1); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing the call ran moved it: {body}"
            );
        }
    }
    #[test]
    fn a_dead_ternary_branch_holds_no_await() {
        // The decided branch the `if` arm already prunes, one syntactic level over: `1 ? 0 :
        // await 0` never evaluates that await, so the write after it is synchronous and the
        // generic walk took it as the cutoff.
        for body in [
            "var current = e; (async function () { 1 ? 0 : await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { 0 ? await 0 : 0; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that await is unreachable: {body}"
            );
        }
        // The bound: an undecided test reaches both sides, and the await in either of them is
        // a real cutoff.
        let fields = helper_reached_via(
            "var current = e; (async function () { c ? 0 : (await 0, current = other); })(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that await still runs: {fields:?}"
        );
    }

    #[test]
    fn an_apply_elision_supplies_undefined_and_moves_nothing() {
        // `f.apply(null, [, 1])` gives the first parameter `undefined` and the second the `1`,
        // so the second default never runs. The elision was read as an unreadable position and
        // ended the mapping, which dropped the `1` that really does reach the parameter after
        // it — and its default was recorded as a write the call prevents.
        let fields = helper_reached_via(
            "var current = e; (function (x, y = (current = other)) {}).apply(null, [, 1]); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the second position was still supplied: {fields:?}"
        );
        // The bound, on both sides of it. The elision supplies NOTHING to the parameter it
        // lands on, so that one's default still runs; and a SPREAD really does end the mapping,
        // because it moves the positions after it by an amount nothing here counts.
        for body in [
            "var current = e; (function (x = (current = other)) {}).apply(null, [, 1]); parse(current);",
            "var current = e; (function (x, y = (current = other)) {}).apply(null, [...a, 1]); parse(current);",
            "var current = e; (function (x, y = (current = other)) {}).apply(null, [1]); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that default still runs: {body}"
            );
        }
    }

    #[test]
    fn a_parenthesized_super_is_still_the_super_call() {
        // `(super());` calls it exactly as `super();` does, and matching the bare spelling alone
        // left a derived class's fields ordered by source position against a read that follows
        // them.
        let fields = helper_reached_via(
            "var current = e; new (class extends Base { constructor(){ (super()); parse(current); } x = (current = other) })();",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the field had initialized by then: {fields:?}"
        );
    }

    #[test]
    fn new_on_something_that_is_not_a_constructor_runs_nothing() {
        // `new` needs a CONSTRUCTOR. An arrow, an async function and a generator are none of
        // them, so this throws a `TypeError` with the body never entered — and recording its
        // writes published a helper's reads under a node nothing had moved.
        for body in [
            "var current = e; try { new (() => { current = other; })(); } catch (_) {} parse(current);",
            "var current = e; try { new (async function () { current = other; })(); } catch (_) {} parse(current);",
            "var current = e; try { new (function* () { current = other; })(); } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing in there ran: {body}"
            );
        }
        // The bound: a plain function and a class are both constructible, and calling either
        // without `new` is unaffected by any of this.
        for body in [
            "var current = e; new (function () { current = other; })(); parse(current);",
            "var current = e; new (class { constructor(){ current = other; } })(); parse(current);",
            "var current = e; (() => { current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that body did run: {body}"
            );
        }
    }

    #[test]
    fn a_nullish_left_side_makes_the_coalesce_certain() {
        // `null ?? parse(e)` performs that call on every path, so what it reads is required.
        // The fallback made every `??` right side conditional, and a read the parser always
        // performs came out optional — a shape that accepts responses the source rejects.
        for body in ["null ?? parse(e);", "void 0 ?? parse(e);"] {
            assert!(
                helper_field_required(body),
                "the right side always runs: {body}"
            );
        }
        // The bound: an arbitrary left side is a real branch, and so is a bare `undefined`,
        // which is an identifier nothing here resolves.
        for body in ["c ?? parse(e);", "undefined ?? parse(e);"] {
            assert!(
                !helper_field_required(body),
                "that call is conditional: {body}"
            );
        }
    }

    /// Whether the field a module helper reads comes out required, for a callback body that
    /// reaches `parse`.
    fn helper_field_required(body: &str) -> bool {
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
            .iter()
            .find(|f| f.name == "id")
            .expect("recovered")
            .required
    }
    #[test]
    fn a_ternary_arm_that_does_not_suspend_keeps_its_own_region() {
        // The two arms are ALTERNATIVES, not a sequence. `flag ? await 0 : current = other`
        // assigns synchronously whenever the alternate is selected, and visiting the arms in
        // order let the consequent's await become the cutoff for both — so a write the caller
        // does see was confined to the function. The `if` arm has recorded this since round
        // nineteen; the ternary merged them.
        for body in [
            "var current = e; (async function () { flag ? await 0 : current = other; })(); parse(current);",
            "var current = e; (async function () { flag ? current = other : await 0; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that arm runs synchronously: {body}"
            );
        }
        // The bound: an arm that awaits BEFORE its write suspends on its own account, and the
        // write after it is the continuation's.
        let fields = helper_reached_via(
            "var current = e; (async function () { flag ? await 0 : (await 1, current = other); })(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that arm awaits first: {fields:?}"
        );
    }

    #[test]
    fn a_member_named_by_a_string_is_the_same_member() {
        // `f["call"]` reaches the same function as `f.call`; oxc spells it as a COMPUTED member,
        // so every matcher written against the dotted form missed it and the inline body was
        // walked as one nobody calls.
        for body in [
            "var current = e; (function () { current = other; })[\"call\"](null); parse(current);",
            "var current = e; (function () { current = other; })[\"apply\"](null); parse(current);",
            "var current = e; (function () { current = other; })[\"bind\"](null)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the body ran now: {body}"
            );
        }
        // The bound: still only these three names, and still only a key this can read — `f[k]`
        // names whatever `k` holds, which is not a question for a syntactic pass.
        for body in [
            "var current = e; (function () { current = other; })[\"map\"](null); parse(current);",
            "var current = e; (function () { current = other; })[k](null); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing inline was invoked: {body}"
            );
        }
    }

    #[test]
    fn a_getter_the_parameters_read_runs_at_the_call() {
        // Binding `{x}` against `{ get x() { … } }` INVOKES that getter, before the body is
        // entered and before anything after the call reads what it wrote. The suppression rule
        // already knew the getter's result is unreadable — which is why the default still runs —
        // and nothing knew its body runs at all, so the write stayed confined.
        let fields = helper_reached_via(
            "var current = e; (function ({x}) {})({ get x() { current = other; return 1; } }); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the getter ran: {fields:?}"
        );
        // The bound: nothing reads the property unless a pattern names it, and a plain property
        // holding a function is a value rather than a call.
        for body in [
            "var current = e; (function (o) {})({ get x() { current = other; return 1; } }); parse(current);",
            "var current = e; (function ({y}) {})({ get x() { current = other; return 1; } }); parse(current);",
            "var current = e; (function ({x}) {})({ x: function () { current = other; } }); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing invoked that body: {body}"
            );
        }
    }
    #[test]
    fn a_for_await_target_is_assigned_after_the_first_result() {
        // The synchronous prefix is SPAN-based, and the loop target is written above the
        // iterable — so noting the cutoff at the iterable's end swept the target in with it,
        // although the target is assigned only once the first result has been awaited.
        let fields = helper_reached_via(
            "var current = e; (async function () { for await (current of [other]) {} })(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the target waits for the first result: {fields:?}"
        );
        // The bound, all three ways round thirty-eight left it: the ITERABLE's own writes are
        // still synchronous, an await inside the iterable still cuts where it sits, and the body
        // is still the continuation's.
        let fields = helper_reached_via(
            "var current = e; (async function () { for await (const x of (current = other, [])) {} })(); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the iterable ran synchronously: {fields:?}"
        );
        for body in [
            "var current = e; (async function () { for await (const x of (await g(), (current = other, []))) {} })(); parse(current);",
            "var current = e; (async function () { for await (const x of []) { current = other; } })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that write is the continuation's: {body}"
            );
        }
    }

    #[test]
    fn a_bound_getter_runs_after_every_argument() {
        // Parameter binding begins only once every argument has been evaluated, so
        // `(function ({x}, y) {})({ get x() { … } }, parse(current))` hands `parse` the original
        // node and calls the getter afterwards. Marking the getter immediate for the whole
        // argument walk recorded its write at the getter's own offset — above a later argument
        // that in fact precedes it.
        let fields = helper_reached_via(
            "var current = e; (function ({x}, y) {})({ get x() { current = other; return 1; } }, parse(current));",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "the getter had not run yet: {fields:?}"
        );
        // The bound, both halves. The getter still runs — a read AFTER the call sees what it
        // wrote — and an ordinary argument's write still reaches the body it precedes, which is
        // what a blanket deferral would have taken away.
        let fields = helper_reached_via(
            "var current = e; (function ({x}) {})({ get x() { current = other; return 1; } }); parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the getter ran by then: {fields:?}"
        );
        let fields = helper_reached_via(
            "var current = e; (function ({x}, y) { parse(current); })({ get x() { return 1; } }, current = other);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "an argument still precedes the body: {fields:?}"
        );
    }
    #[test]
    fn a_getter_in_a_parameter_default_runs_too() {
        // When the call supplies nothing, the pattern takes apart the parameter's OWN default
        // object — so a getter in THAT object is the one binding invokes. Reading only the
        // argument skipped the shape entirely, and the getter was left confined to a function
        // nobody was known to call.
        for body in [
            "var current = e; (function ({x} = { get x() { current = other; return 1; } }) {})(); parse(current);",
            "var current = e; (function ({x} = { get x() { current = other; return 1; } }) {})(void 0); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the default's getter ran: {body}"
            );
        }
        // The bound: a supplied argument means the default never runs, so its object is never
        // built and its getter never called — held by the suppression one level up rather than
        // by anything in the getter walk, which is why that walk carries no guard of its own.
        // And a pattern naming something else reads nothing from the object either.
        for body in [
            "var current = e; (function ({x} = { get x() { current = other; return 1; } }) {})({x: 1}); parse(current);",
            "var current = e; (function ({y} = { get x() { current = other; return 1; } }) {})(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing invoked that getter: {body}"
            );
        }
    }
    #[test]
    fn a_bypassed_await_leaves_its_continuation_synchronous() {
        // `if (flag) await 0; current = other;` assigns synchronously whenever `flag` is false,
        // so the caller may well see it. The sides of an undecided `if` were recorded from round
        // nineteen and the CONTINUATION after them was not — and a one-sided `if` supplies no
        // non-suspending sibling span at all, so the await became a global cutoff. Two
        // executions disagree, and the model owes the answer that declines rather than the one
        // that publishes under a node half of them replaced.
        for body in [
            "var current = e; (async function () { if (flag) await 0; current = other; })(); parse(current);",
            // The explicit empty alternate is the same statement written out.
            "var current = e; (async function () { if (flag) { await 0; } else { } current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "a path bypasses that await: {body}"
            );
        }
        // The bound: when EVERY path suspends there is no continuation to keep, whether the
        // await is unconditional or written into both sides.
        for body in [
            "var current = e; (async function () { await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { if (flag) { await 0; } else { await 1; } current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "every path waits: {body}"
            );
        }
    }

    #[test]
    fn a_parenthesized_computed_key_names_the_same_member() {
        // `f[("call")]` names the same property as `f["call"]`; parentheses around a key change
        // nothing about which one it is.
        for body in [
            "var current = e; (function () { current = other; })[(\"call\")](null); parse(current);",
            "var current = e; (function () { current = other; })[(\"bind\")](null)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the body ran now: {body}"
            );
        }
        // The bound: still only a key this can READ — a parenthesized identifier names whatever
        // it holds.
        let fields = helper_reached_via(
            "var current = e; (function () { current = other; })[(k)](null); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "nothing inline was invoked: {fields:?}"
        );
    }

    #[test]
    fn an_apply_that_throws_runs_no_body() {
        // `f.apply(thisArg, 1)` throws a `TypeError` before `f` is entered: the argument list
        // has to be `null`, `undefined` or an object. Unwrapping `.apply` unconditionally marked
        // the body immediate for a call that runs it on no path at all.
        for body in [
            "var current = e; try { (function () { current = other; }).apply(null, 1); } catch (_) {} parse(current);",
            "var current = e; try { (function () { current = other; }).apply(null, \"x\"); } catch (_) {} parse(current);",
            "var current = e; try { (function () { current = other; }).apply(null, !0); } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that call throws first: {body}"
            );
        }
        // The bound: `null`, `void 0` and a missing second argument all mean "no arguments" and
        // run the body, an array runs it, and anything this cannot read is left alone — claiming
        // a throw where none happens confines a write the caller does see.
        for body in [
            "var current = e; (function () { current = other; }).apply(null, [1]); parse(current);",
            "var current = e; (function () { current = other; }).apply(null); parse(current);",
            "var current = e; (function () { current = other; }).apply(null, null); parse(current);",
            "var current = e; (function () { current = other; }).apply(null, void 0); parse(current);",
            "var current = e; (function () { current = other; }).apply(null, args); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that body does run: {body}"
            );
        }
    }
    #[test]
    fn a_template_key_with_nothing_in_it_is_a_string() {
        // A template with no substitution is a string spelled another way, so ``f[`call`]``
        // reaches the same function as `f.call` and the body runs now.
        for body in [
            "var current = e; (function () { current = other; })[`call`](null); parse(current);",
            "var current = e; (function () { current = other; })[`bind`](null)(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the body ran now: {body}"
            );
        }
        // The bound: a substitution names whatever it evaluates to, which is not a question for
        // a syntactic pass — and the name still has to be one of the three.
        for body in [
            "var current = e; (function () { current = other; })[`ca${x}ll`](null); parse(current);",
            // And one whose FIRST quasi spells the name exactly, which is what separates
            // reading the template from reading its first piece.
            "var current = e; (function () { current = other; })[`call${x}`](null); parse(current);",
            "var current = e; (function () { current = other; })[`map`](null); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "nothing inline was invoked: {body}"
            );
        }
    }

    #[test]
    fn new_on_a_call_member_constructs_the_member() {
        // `new (f).call(null)` constructs `Function.prototype.call`, which has no [[Construct]]
        // — a `TypeError` before `f` is ever reached. The callee unwrapper looks through
        // `.call`/`.apply` because an ordinary call there really does run the receiver's body,
        // and under `new` the member itself is the target.
        for body in [
            "var current = e; try { new (function () { current = other; }).call(null); } catch (_) {} parse(current);",
            "var current = e; try { new (function () { current = other; }).apply(null); } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that construction throws: {body}"
            );
        }
        // The bound, three ways. An ordinary `.call` still runs the receiver's body; `new` on
        // the function itself still constructs it; and `.bind` keeps its unwrap under `new`,
        // because `new (f.bind(x))()` constructs the bound function, which is constructible
        // exactly when `f` is.
        for body in [
            "var current = e; (function () { current = other; }).call(null); parse(current);",
            "var current = e; new (function () { current = other; })(); parse(current);",
            "var current = e; new ((function () { current = other; }).bind(null))(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that body does run: {body}"
            );
        }
        // `bind` is not in that list, and adding it would be an inert third name: a bare
        // `f.bind` member is not a shape the callee unwrapper looks through at all — only a CALL
        // whose callee is one — so `new (f.bind)(x)` never reaches a function body to approve
        // and is declined without this check. Asserted rather than argued, because a condition
        // whose narrowness no test can hold is one this branch has twice had to remove.
        let fields = helper_reached_via(
            "var current = e; try { new (function () { current = other; }).bind(null); } catch (_) {} parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "constructing `bind` itself reaches no body either: {fields:?}"
        );
    }
    #[test]
    fn a_bypassed_continuation_ends_at_the_next_unavoidable_await() {
        // `if (flag) await 0; await 0; current = other;` suspends on EVERY path before the
        // write, so the caller always passes the original node. The continuation after a
        // bypassed branch was recorded to the end of the body — which I flagged a round ago as
        // over-reaching and safe, and it is safe in direction and still a loss. It ends at the
        // next suspension every surviving path reaches now.
        let fields = helper_reached_via(
            "var current = e; (async function () { if (flag) await 0; await 0; current = other; })(); parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "every path waits by then: {fields:?}"
        );
        // The bound: with nothing unavoidable after it the continuation still runs to the end,
        // and an await inside ANOTHER bypassable branch does not close it either.
        for body in [
            "var current = e; (async function () { if (flag) await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { if (flag) await 0; if (other) await 1; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "a path reaches that write without waiting: {body}"
            );
        }
    }

    #[test]
    fn a_bypassed_short_circuit_leaves_its_continuation_synchronous() {
        // The rule the `if` was given a round ago, in the two expression forms that were left
        // without it. `flag && await 0; current = other;` assigns synchronously whenever `flag`
        // is falsy, and `flag ? await 0 : 0` whenever the other arm is taken — so two executions
        // disagree about what `parse` receives and the model owes the answer that declines.
        for body in [
            "var current = e; (async function () { flag && await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { flag || await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { flag ?? await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { flag ? await 0 : 0; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "a path bypasses that await: {body}"
            );
        }
        // The bound: a right side that ALWAYS runs suspends every path, and so does a ternary
        // whose arms both await.
        for body in [
            "var current = e; (async function () { !0 && await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { 0 || await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { null ?? await 0; current = other; })(); parse(current);",
            "var current = e; (async function () { flag ? await 0 : await 1; current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "every path waits: {body}"
            );
        }
    }

    #[test]
    fn a_derived_constructor_without_super_initializes_nothing() {
        // Reaching the end of a derived constructor without calling `super()` throws a
        // `ReferenceError` on return, so not a field initializes. The walk answered `true` on
        // that fallthrough and read `constructor(){}` as ordinary construction.
        let fields = helper_reached_via(
            "var current = e; try { new (class extends Base { constructor(){} x = (current = other) })(); } catch (_) {} parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that construction throws: {fields:?}"
        );
        // The bound: a `super()` anywhere on the way still installs them, and a class with no
        // heritage needs none.
        for body in [
            "var current = e; new (class extends Base { constructor(){ super(); } x = (current = other) })(); parse(current);",
            "var current = e; new (class extends Base { constructor(){ if (c) super(); } x = (current = other) })(); parse(current);",
            "var current = e; new (class { constructor(){} x = (current = other) })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "the field initializes: {body}"
            );
        }
    }

    #[test]
    fn a_member_taken_through_a_comma_has_lost_its_receiver() {
        // `(0, f.call)(null)` discards the reference and hands `Function.prototype.call` an
        // `undefined` receiver, which throws before `f` is entered. Parentheses keep the
        // reference and are not this, which is the bound.
        let fields = helper_reached_via(
            "var current = e; try { (0, (function () { current = other; }).call)(null); } catch (_) {} parse(current);",
        );
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "that call throws first: {fields:?}"
        );
        for body in [
            "var current = e; ((function () { current = other; }).call)(null); parse(current);",
            // And a comma around the FUNCTION rather than the member is unaffected: the value
            // is the function itself, which needs no receiver.
            "var current = e; (0, function () { current = other; })(); parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that body does run: {body}"
            );
        }
    }

    #[test]
    fn a_tagged_template_calls_its_tag() {
        // ``(function(){ … })`x` `` runs that body before the next statement, as immediately as
        // `()` does. Only calls and `new` were read as invocations.
        let fields = helper_reached_via(
            "var current = e; (function () { current = other; })`x`; parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the tag ran: {fields:?}"
        );
        // The bound: a tag this has never seen the body of invokes nothing it can follow, and
        // the substitutions are still walked where they are written.
        let fields = helper_reached_via("var current = e; thing`x`; parse(current);");
        assert!(
            fields.iter().any(|f| f.name == "id"),
            "nothing inline was invoked: {fields:?}"
        );
        let fields = helper_reached_via(
            "var current = e; (function () {})`x${(current = other)}`; parse(current);",
        );
        assert!(
            !fields.iter().any(|f| f.name == "id"),
            "the substitution ran: {fields:?}"
        );
    }

    #[test]
    fn a_heritage_that_is_not_a_constructor_runs_no_class_body() {
        // `class C extends (() => {})` evaluates the arrow and then rejects it, so nothing in
        // the body runs — not a static initializer, not a computed key. The same
        // constructibility rule `new` reads, at the other place that needs it.
        for body in [
            "var current = e; try { class C extends (() => {}) { static x = (current = other); } } catch (_) {} parse(current);",
            "var current = e; try { class C extends (async function () {}) { static x = (current = other); } } catch (_) {} parse(current);",
            "var current = e; try { class C extends 1 { static x = (current = other); } } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                fields.iter().any(|f| f.name == "id"),
                "that class definition throws: {body}"
            );
        }
        // The bound: `extends null` is legal, a plain function and a class are constructors, an
        // identifier is left alone — and the heritage EXPRESSION is evaluated either way.
        for body in [
            "var current = e; class C extends null { static x = (current = other); } parse(current);",
            "var current = e; class C extends Base { static x = (current = other); } parse(current);",
            "var current = e; class C extends (function () {}) { static x = (current = other); } parse(current);",
            "var current = e; try { class C extends (current = other, () => {}) {} } catch (_) {} parse(current);",
        ] {
            let fields = helper_reached_via(body);
            assert!(
                !fields.iter().any(|f| f.name == "id"),
                "that write does happen: {body}"
            );
        }
    }
}
