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
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, code);
    let mut a = ParserAnalyzer {
        code,
        param,
        module,
        recursed: Vec::new(),
        scopes: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::new(),
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
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

/// What a function introduces, split by how far each binding reaches.
#[derive(Default)]
struct BoundNames {
    /// Parameters, the `var`s hoisted to the function, and the functions declared in it —
    /// visible throughout the body.
    names: std::collections::HashSet<String>,
    /// `let`/`const`, each with the block it is confined to. A declaration in a nested
    /// block does not shadow a capture read elsewhere in the same function.
    lexical: Vec<(Span, String)>,
    /// The function body this frame covers — the extent an alias bound in it is good for.
    extent: Span,
    /// Enclosing blocks during collection, innermost last.
    blocks: Vec<Span>,
    /// Whether the binding being collected reaches the whole function: a parameter, or a
    /// `var`. Everything else — `let`, `const`, `class`, a `catch` parameter — is confined
    /// to the extent it sits in, so that is the default and only the hoisted forms are
    /// named. Enumerating the block-scoped forms instead kept missing one.
    hoist: bool,
}

impl BoundNames {
    /// Collect over a function body, whose own span bounds any top-level `let`/`const`.
    fn of(
        own_name: Option<&str>,
        params: &oxc_ast::ast::FormalParameters,
        body: &oxc_ast::ast::FunctionBody,
    ) -> Self {
        let mut c = Self::default();
        // A named function expression binds its own name inside itself, and nowhere else.
        if let Some(n) = own_name {
            c.names.insert(n.to_string());
        }
        c.extent = body.span;
        c.hoist = true;
        c.visit_formal_parameters(params);
        c.hoist = false;
        c.blocks.push(body.span);
        c.visit_function_body(body);
        c.blocks.pop();
        c
    }
}

impl<'a> Visit<'a> for BoundNames {
    fn visit_binding_identifier(&mut self, id: &oxc_ast::ast::BindingIdentifier<'a>) {
        if self.hoist {
            self.names.insert(id.name.as_str().to_string());
        } else if let Some(&extent) = self.blocks.last() {
            self.lexical.push((extent, id.name.as_str().to_string()));
        }
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        let outer = self.hoist;
        // `var` reaches the whole function; `let`/`const` stop at their extent.
        self.hoist = !decl.kind.is_lexical();
        walk::walk_variable_declaration(self, decl);
        self.hoist = outer;
    }

    fn visit_block_statement(&mut self, block: &oxc_ast::ast::BlockStatement<'a>) {
        self.blocks.push(block.span);
        walk::walk_block_statement(self, block);
        self.blocks.pop();
    }

    // A loop header, a `switch` and a `catch` each bound their own lexical declarations
    // just as a block does. Without an extent of their own, `for (let x = 0; …)` would
    // shadow a captured `x` for everything around the loop.
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

    fn visit_switch_statement(&mut self, stmt: &oxc_ast::ast::SwitchStatement<'a>) {
        // The cases share one block, and the discriminant is evaluated outside it: a `let`
        // in a case must not shadow a name the discriminant itself reads.
        let body = stmt.cases.first().map_or(stmt.span, |first| {
            Span::new(first.span.start, stmt.span.end)
        });
        self.blocks.push(body);
        walk::walk_switch_statement(self, stmt);
        self.blocks.pop();
    }

    fn visit_class(&mut self, class: &oxc_ast::ast::Class<'a>) {
        // Like a function: a declaration introduces its name in the enclosing extent, a
        // named class *expression* binds it only inside itself.
        if class.r#type == oxc_ast::ast::ClassType::ClassDeclaration
            && let Some(id) = class.id.as_ref()
            && let Some(&extent) = self.blocks.last()
        {
            self.lexical.push((extent, id.name.as_str().to_string()));
        }
        self.visit_class_body(&class.body);
    }

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        // `catch (e)` binds to the clause — and minified handlers reuse `e` freely.
        self.blocks.push(clause.span);
        walk::walk_catch_clause(self, clause);
        self.blocks.pop();
    }

    // A nested function's parameters and locals belong to *its* scope, not this one; only
    // the name it introduces here does. Descending would let an inner binding pass for an
    // outer one and discount reads that are genuinely the enclosing node's.
    fn visit_function(&mut self, func: &Function<'a>, _flags: ScopeFlags) {
        // Only a *declaration* introduces its name here — a named function expression binds
        // it inside itself, and claiming it out here would discount reads through a capture
        // of the same name. Against the current extent, not the function: at the top of a
        // body that extent *is* the function, and in a nested block it binds only there.
        if func.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration
            && let Some(id) = func.id.as_ref()
            && let Some(&extent) = self.blocks.last()
        {
            self.lexical.push((extent, id.name.as_str().to_string()));
        }
    }

    fn visit_arrow_function_expression(
        &mut self,
        _func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
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
    scopes: Vec<BoundNames>,
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
        let Some(body) = func.body.as_ref() else {
            walk::walk_function(self, func, flags);
            return;
        };
        let own = func.id.as_ref().map(|i| i.name.as_str());
        self.scopes.push(BoundNames::of(own, &func.params, body));
        // What a callback binds dies with it. An alias may overwrite an outer entry of the
        // same name, and the alias' own extent expiring would not put the outer one back.
        let outer_vars = self.child_vars.clone();
        walk::walk_function(self, func, flags);
        self.child_vars = outer_vars;
        self.scopes.pop();
    }

    fn visit_arrow_function_expression(
        &mut self,
        func: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.scopes
            .push(BoundNames::of(None, &func.params, &func.body));
        let outer_vars = self.child_vars.clone();
        walk::walk_arrow_function_expression(self, func);
        self.child_vars = outer_vars;
        self.scopes.pop();
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

    fn visit_if_statement(&mut self, stmt: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_expression(&stmt.test);
        // `if (e.hasAttr("x")) …` says the element may lack `x` only on the path where it
        // was found; the `else` is where it is known ABSENT, and a read there is required
        // by whatever the parser does next. A negated test flips the two.
        let tested = self.canonical_guards(&stmt.test);
        let n = tested.len();
        self.conditional_depth += 1;

        let before_then = self.assertions.len();
        self.guarded_names.extend(tested);
        self.visit_statement(&stmt.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        let then_side: Vec<ResponseAssertion> = self.assertions[before_then..].to_vec();

        if let Some(alt) = &stmt.alternate {
            let before_else = self.assertions.len();
            self.visit_statement(alt);
            let else_side: Vec<ResponseAssertion> = self.assertions[before_else..].to_vec();
            // Enforced whichever way the branch goes, so enforced always. Both occurrences
            // were marked conditional on the way in; their intersection is not.
            for a in then_side.iter().filter(|a| else_side.contains(a)) {
                for _ in 0..2 {
                    if let Some(i) = self.conditional_assertions.iter().position(|x| x == a) {
                        self.conditional_assertions.swap_remove(i);
                    }
                }
            }
        }
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
        self.guarded_names.extend(tested);
        self.visit_expression(&expr.consequent);
        self.guarded_names.truncate(self.guarded_names.len() - n);
        self.visit_expression(&expr.alternate);
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

    /// Whether an enclosing inner function re-binds the parser's own parameter, as seen
    /// from `span`.
    fn param_shadowed(&self, span: Span) -> bool {
        self.bound_by_inner_scope(self.param, span)
    }

    /// Whether `name`, read at `span`, belongs to an enclosing callback rather than to the
    /// parser's own body.
    fn bound_by_inner_scope(&self, name: &str, span: Span) -> bool {
        self.scopes.iter().any(|s| {
            s.names.contains(name)
                || s.lexical
                    .iter()
                    .any(|(b, n)| n == name && span.start >= b.start && span.end <= b.end)
        })
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
        let Some(extent) = self.scopes.last().map(|s| s.extent) else {
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
            merge_or_push_reporting(&mut self.fields, read, &mut self.unresolved);
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
                merge_or_push(kids, read);
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
                merge_or_push(&mut self.fields, f);
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
                if !kids
                    .iter()
                    .any(|c| c.name == read.name && c.method == read.method)
                {
                    kids.push(read);
                }
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
            for f in &mut recovered {
                f.required = false;
            }
        }
        merge_child_shape_at(&mut self.fields, &tag, recovered);
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
        let Some(arg_idx) = call.arguments.iter().position(|a| {
            arg_expr(a)
                .and_then(as_identifier)
                .is_some_and(|id| id == self.param && !self.bound_by_inner_scope(id, call.span))
        }) else {
            return;
        };
        let Some((params, body_src)) = self.module.functions.get(name) else {
            return;
        };
        let Some(bound_param) = params.get(arg_idx) else {
            return;
        };
        // Past the point where this is known to be a helper handed the node: stopping here
        // leaves the shape incomplete, and saying so is the difference between a bounded
        // descent and a silent one.
        if self.helper_depth >= 2 {
            self.unresolved.push(format!("{HELPER_DEPTH}@{name}"));
            return;
        }
        let (mut recovered, lost, guards) =
            analyze_node_helper(body_src, bound_param, self.module, self.helper_depth + 1);
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
                f.required = false;
            }
        }
        // Merged, not skipped: the caller and the helper can both reach the same child,
        // and keeping whichever landed first dropped everything the other one saw.
        for f in recovered {
            merge_or_push_reporting(&mut self.fields, f, &mut self.unresolved);
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
        scopes: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::new(),
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
        conditional_depth: 0,
        guarded_names: Vec::new(),
        helper_depth: depth,
    };
    a.local_bindings = all_bindings(&ret.program);
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
        scopes: Vec::new(),
        assertions: Vec::new(),
        fields: Vec::new(),
        child_vars: HashMap::from([(node_param.to_string(), vec![PathSeg::required(tag)])]),
        pending_enum_keys: HashMap::new(),
        unresolved_enum_attrs: Default::default(),
        unresolved: Vec::new(),
        unfollowable: Vec::new(),
        local_bindings: Default::default(),
        conditional_assertions: Vec::new(),
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
        merge_or_push(existing, nc);
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
struct PathSeg {
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
fn place_at(fields: &mut Vec<ParsedField>, path: &[PathSeg], f: ParsedField) {
    let Some((seg, rest)) = path.split_first() else {
        merge_or_push(fields, f);
        return;
    };
    let idx = find_or_create_field(
        fields,
        &seg.tag,
        &seg.method,
        is_method_required(&seg.method),
    );
    place_at(fields[idx].children.get_or_insert_with(Vec::new), rest, f);
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

fn merge_or_push(into: &mut Vec<ParsedField>, f: ParsedField) {
    let mut discard = Vec::new();
    merge_or_push_reporting(into, f, &mut discard);
}

fn merge_or_push_reporting(into: &mut Vec<ParsedField>, f: ParsedField, lost: &mut Vec<String>) {
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
        merge_or_push_reporting(existing, c, lost);
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
        fn visit_if_statement(&mut self, s: &oxc_ast::ast::IfStatement<'a>) {
            if equality_literals(&s.test, self.subject).is_some_and(|l| !l.is_empty()) {
                self.found = true;
            }
            walk::walk_if_statement(self, s);
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
        for stmt in stmts.iter() {
            let Statement::IfStatement(first) = stmt else {
                continue;
            };
            // Before the accessor runs the name holds `undefined`, so the comparison is
            // not against the wire attribute this dispatch is keyed on.
            if first.span.start < bound_at {
                return None;
            }
            let mut current = &**first;
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
                arms.push((
                    lits.into_iter().map(str::to_string).collect(),
                    current.consequent.span(),
                ));
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

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        self.blocks.push(clause.span);
        walk::walk_catch_clause(self, clause);
        self.blocks.pop();
    }

    // A loop header binds its own declarations, the same as a block — `for (let parse of
    // …)` does not shadow a helper called after the loop.
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

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        // A declaration binds its name in the scope it sits in — recorded against its own
        // body, a call beside it would not see the local and would resolve the module's. A
        // named function EXPRESSION is the other way round: its name exists only inside it.
        if let Some(id) = func.id.as_ref() {
            if func.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration {
                self.bind(id.name.as_str(), true);
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
        walk::walk_arrow_function_expression(self, func);
        self.fns.pop();
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
        self.names.contains(name)
            || self
                .scoped
                .iter()
                .any(|(e, n)| n == name && at.start >= e.start && at.end <= e.end)
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
    found: Vec<(String, ParsedField, u32)>,
}

impl<'a> Visit<'a> for DiscriminatorFinder<'_> {
    // Same reason as `ArmCollector`: a reused parameter name inside a nested callback is a
    // different node, and reading its attribute is not this element's discriminator.
    fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _f: &oxc_ast::ast::ArrowFunctionExpression<'a>) {}

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
                self.found
                    .push((bound.as_str().to_string(), f, call.span.end));
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
fn assigned_names(src: &str, param: &str) -> HashMap<String, String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, src);
    if ret.panicked {
        return HashMap::new();
    }
    struct Finder<'s> {
        param: &'s str,
        /// Local name → the wire attribute it was read from, in this arm.
        from_wire: HashMap<String, String>,
        /// What each open block displaced, to put back when it closes.
        blocks: Vec<Vec<(String, Option<String>)>>,
        /// Wire attribute → the property its value is assigned to.
        named: HashMap<String, String>,
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
                if let (Some(bound), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
                    && let Some(call) = as_call(init)
                    && callee_method(call).is_some_and(is_value_method)
                    && callee_object(call).and_then(as_identifier) == Some(self.param)
                    && let Some(wire) = arg_str(call, 0)
                {
                    let name = bound.as_str().to_string();
                    // A lexical alias ends with its block; what it displaced comes back,
                    // or the outer name would go on pointing at the inner read.
                    if decl.kind.is_lexical()
                        && let Some(frame) = self.blocks.last_mut()
                    {
                        frame.push((name.clone(), self.from_wire.get(&name).cloned()));
                    }
                    self.from_wire.insert(name, wire.to_string());
                }
            }
            walk::walk_variable_declaration(self, decl);
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

        fn visit_assignment_expression(&mut self, e: &oxc_ast::ast::AssignmentExpression<'a>) {
            // `x = e.attrString("other")` makes `x` name the other attribute — or, if the
            // new value is not a wire read at all, nothing this can follow. Left alone,
            // the property was being attached to whatever `x` used to hold.
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left {
                let name = id.name.as_str().to_string();
                let rebound = as_call(&e.right).filter(|c| {
                    callee_method(c).is_some_and(is_value_method)
                        && callee_object(c).and_then(as_identifier) == Some(self.param)
                });
                match rebound.and_then(|c| arg_str(c, 0)) {
                    Some(wire) => {
                        self.from_wire.insert(name, wire.to_string());
                    }
                    None => {
                        self.from_wire.remove(&name);
                    }
                }
            }
            if let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(m) = &e.left {
                // Either spelling: through a temporary, or the accessor written straight
                // into the result — `t.callAdd = e.attrEnum("value", …)`.
                let wire = as_identifier(&e.right)
                    .and_then(|r| self.from_wire.get(r))
                    .cloned()
                    .or_else(|| {
                        let call = as_call(&e.right)?;
                        (callee_method(call).is_some_and(is_value_method)
                            && callee_object(call).and_then(as_identifier) == Some(self.param))
                        .then(|| arg_str(call, 0).map(str::to_string))?
                    });
                if let Some(wire) = wire {
                    self.named
                        .entry(wire)
                        .or_insert_with(|| m.property.name.as_str().to_string());
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
    };
    f.visit_program(&ret.program);
    f.named
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
        if !accounted.contains(&identity(&f)) {
            merge_or_push(&mut dispatched, f);
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
    };
    finder.visit_program(&ret.program);
    // The one a chain is actually built on.
    let (_bound, disc_field, collector) = finder.found.into_iter().find_map(|(b, f, at)| {
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
        Some((b, f, chain))
    })?;
    let wire = disc_field.name.clone();

    let mut variants: Vec<UnionVariant> = Vec::new();
    let mut common: Vec<ParsedField> = Vec::new();
    // Counted over the values, not the branches: two arms handling one value merge into one
    // variant, and a denominator of two made a child both of them require look optional.
    let mut distinct_values: std::collections::HashSet<String> = Default::default();
    let mut structural_seen: HashMap<String, usize> = HashMap::new();
    for (lits, span) in &collector.arms {
        let arm_src = &body_src[span.start as usize..span.end as usize];
        let arm = analyze_with_scope(arm_src, param, module, outer_bindings);
        let runtime_names = assigned_names(arm_src, param);
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
            merge_or_push(&mut common, f);
        }
        for path in in_this_arm {
            *structural_seen.entry(path).or_default() += 1;
        }
        for lit in lits {
            let fields: Vec<ParsedField> = leaves
                .iter()
                .cloned()
                .map(|mut f| {
                    // Each leaf takes the name of the property ITS value is assigned to.
                    // One name for the whole arm renamed every leaf the same, which the
                    // codegen then emits as duplicate fields of one variant.
                    if let Some(n) = runtime_names.get(&f.name) {
                        f.wire_name = Some(f.name.clone());
                        f.name = n.clone();
                    }
                    f
                })
                .collect();
            // The same literal tested twice is one alternative, not two: emitted twice it
            // would be an unreachable arm, and the codegen refuses the whole union for it.
            if let Some(existing) = variants.iter_mut().find(|v| v.name == *lit) {
                for f in fields {
                    merge_or_push(&mut existing.fields, f);
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
            assertions.extend(arm.assertions.iter().cloned());
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
    for f in &mut common {
        let path = f.name.clone();
        relax_absent_from_some_arm(f, &path, &structural_seen, distinct_values.len());
    }

    let mut union = mk_field("dispatch", &wire, ParsedFieldType::Union, true);
    union.wire_name = None;
    union.name = format!("{wire}_dispatch");
    union.union_variants = Some(variants);
    let mut out = vec![disc_field];
    out.extend(common);
    out.push(union);
    // Whatever the element reads outside the chain is still its own. Asking the body with
    // the arms blanked answers that exactly; inferring it from the merged flat result
    // could not tell an arm's read from one the parser makes on every path.
    let base = ret.program.span.start;
    let outside = analyze_with_scope(
        &body_without_arms(body_src, &collector.arms, base),
        param,
        module,
        outer_bindings,
    );
    Some(fold_unaccounted(out, outside.fields))
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
                match discriminated_children(cb_body, &cb_param, module, sink.bindings) {
                    Some(dispatched) => dispatched,
                    None => child_result.fields,
                },
            );
            f.repeats = Some(true);
            // What the child's own scope could not resolve is still a loss for the parser.
            sink.unresolved.extend(child_result.unresolved);
            place_at(sink.fields, path, f);
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
            place_at(sink.fields, path, f);
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
}
