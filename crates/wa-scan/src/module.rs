//! Full per-module scan: find `wap("iq", {...}, ...children)` request builders
//! and the `new WADeprecatedWapParser("name", fn)` response parser, then assemble
//! [`IqStanzaDef`]s. Port of `scanModuleSourceAST`.

use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentExpression, CallExpression, Expression, NewExpression};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use wa_ir::{
    IqRequestDef, IqStanzaDef, IqTarget, IqType, ParsedResponse, WapAttrDef, WapAttrKind,
    WapChildNode,
};

use crate::alias::{AliasMap, build_alias_map};
use crate::attrs::{extract_attrs_from_obj, parse_wap_call};
use crate::helper_index::HelperIndex;
use crate::mixin_index::MixinIndex;
use crate::request::{VarScope, build_var_scope, resolve_child_node};
use crate::response_index::ResponseIndex;
use wa_oxc::{arg_expr, as_call, callee_method, callee_object};

/// Scan a single module's `__d(...)` source for IQ stanza definitions.
///
/// `mixins`/`responses` are the cross-module indexes; pass their `default()`
/// (empty) for a purely local scan — with empty indexes this behaves exactly as
/// before (the smax xmlns/type and response branches resolve nothing).
pub fn scan_module_source(
    source: &str,
    mixins: &MixinIndex,
    responses: &ResponseIndex,
    helpers: &HelperIndex,
) -> Vec<IqStanzaDef> {
    scan_module_outcome(source, mixins, responses, helpers)
        .map(|(stanzas, _)| stanzas)
        .unwrap_or_default()
}

/// How much one IQ-request module gained from the cross-module `mergeStanzas`
/// fragments — the input to the `diagnostics.iq.crossModule` manifest counters.
/// A module that builds its whole `<iq>` inline has `referenced_mixins == false`
/// and `fields_recovered == 0`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrossModuleStat {
    /// The module folds in ≥1 `o("WASmaxOut…").merge…Mixin(…)` fragment.
    pub referenced_mixins: bool,
    /// Tag/attr entries the fragment merge ADDED to this module's richest emitted
    /// `<iq>` (i.e. fields that would be dropped without Phase 2). 0 when the
    /// referenced mixins only contributed `xmlns`/`type`, not children.
    pub fields_recovered: usize,
}

/// Why an IQ-candidate module (matched by [`crate::is_iq_module`]) yielded no
/// stanza. Drives the `unparseable` diagnostics so a silently-dropped module is
/// recorded with a reason instead of vanishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// oxc could not parse the module slice (`ParserReturn::panicked`).
    ParseError,
    /// The slice is not a `__d("Name", …)` module (no module name in the AST).
    NotAModule,
    /// The `("iq", …)` builder substring was present but the AST walk found no
    /// actual `wap`/`smax` iq builder call (e.g. it was inside a string literal).
    NoIqCall,
    /// IQ builder call(s) found, but every one was dropped by the namespace/type
    /// guard — xmlns or get/set type stayed unresolved even after mixin merge.
    Unresolved,
    /// A cross-module mixin fragment: the module ONLY exports `merge…Mixin`
    /// combinators, so its partial `<iq>` (missing xmlns and/or type by design) is
    /// meant to be folded into real requests via `mergeStanzas` — not a standalone
    /// stanza. Its data already lives in the concrete request consumers; recording
    /// it separately keeps these benign fragments out of the genuine-failure count.
    MixinFragment,
}

impl DropReason {
    /// Stable, human-readable reason recorded in [`wa_ir::Unparseable::reason`].
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::ParseError => "parse error (oxc panicked)",
            DropReason::NotAModule => "not a __d() module",
            DropReason::NoIqCall => "iq builder substring present but no AST iq call",
            DropReason::Unresolved => "namespace/type unresolved (dropped by guard)",
            DropReason::MixinFragment => {
                "mixin fragment (folded into requests, not a standalone stanza)"
            }
        }
    }
}

/// Scan a single module's `__d(...)` source for IQ stanza definitions, returning
/// either the stanzas it produced or the [`DropReason`] explaining why an
/// IQ-candidate module produced none. See [`scan_module_source`] for the
/// reason-discarding variant.
pub fn scan_module_outcome(
    source: &str,
    mixins: &MixinIndex,
    responses: &ResponseIndex,
    helpers: &HelperIndex,
) -> Result<(Vec<IqStanzaDef>, CrossModuleStat), DropReason> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, source);
    // A catastrophic parse failure leaves an empty program; surface it instead of
    // silently treating the module as "no iq found".
    if ret.panicked {
        return Err(DropReason::ParseError);
    }

    // Module name from the AST (`__d("Name", ...)`), not a brittle `__d("` substring.
    let Some(module_name) = ret.program.body.iter().find_map(wa_oxc::define_module_name) else {
        return Err(DropReason::NotAModule);
    };

    // Pass 1: variable/function scope (offset-based, lifetime-free) + smax aliases.
    let scope = build_var_scope(&ret.program);
    let aliases = build_alias_map(&ret.program);

    // Pass 2: collect exports, iq requests, the response parser, and the mixin
    // modules this module folds in (for cross-module xmlns/type resolution).
    let mut scanner = ModuleScanner {
        source,
        scope: &scope,
        aliases: &aliases,
        helpers,
        iq_calls: Vec::new(),
        parser: None,
        exports: Vec::new(),
        type_hints: std::collections::HashMap::new(),
        mixin_callees: Vec::new(),
        current_export: None,
    };
    scanner.visit_program(&ret.program);

    if scanner.iq_calls.is_empty() {
        return Err(DropReason::NoIqCall);
    }

    // Phase 2: resolve namespace/type for iq calls that lacked them locally, by
    // unioning the iq fragments of the mixins this module references. The guard
    // (drop when namespace or type stays unresolved) is preserved — only
    // previously-discarded calls can be recovered, never relaxed.
    //
    // The mixin union is module-level (one set of referenced mixins per module),
    // so compute it once and only when some iq call actually needs it.
    // A call also needs the union when it has no addressee of its own: a `to` the local
    // builder never writes is exactly the one a folded-in fragment supplies, and leaving
    // the union uncomputed would report `unset` for a request that has a target.
    let needs_resolution = scanner.iq_calls.iter().any(|iq| {
        iq.namespace.is_none()
            || iq.iq_type.is_none()
            || !iq.target.is_some_and(|t| t.is_resolved())
    });
    let mixin_resolved = if needs_resolution {
        crate::mixin_index::resolve(mixins, &scanner.mixin_callees)
    } else {
        (None, None, None)
    };
    // Cross-module `mergeStanzas` fragments: the children/attrs the referenced
    // mixins add to the `<iq>` (e.g. `spam_list{spam_flow}`). Merged by tag into the
    // locally-built children so those cross-module fields aren't lost.
    let referenced_mixins = !scanner.mixin_callees.is_empty();
    let frag_children = if scanner.mixin_callees.is_empty() {
        Vec::new()
    } else {
        crate::mixin_index::resolve_fragment_children(mixins, &scanner.mixin_callees)
    };
    // Diagnostic: the most fields any single emitted stanza recovers from the
    // cross-module fragments (counted on the guard-surviving stanzas only, since a
    // dropped one contributes nothing to the IR). Reported as `crossModule` so the
    // Phase-2 recovery is visible/regressable in the manifest.
    let mut fields_recovered = 0usize;
    let resolved: Vec<ResolvedIqCall> = scanner
        .iq_calls
        .into_iter()
        .filter_map(|mut iq| {
            if iq.namespace.is_none() {
                iq.namespace = mixin_resolved.0.clone();
            }
            if iq.iq_type.is_none() {
                iq.iq_type = mixin_resolved.1;
            }
            // The local builder's own `to` is the request's; a fragment only answers for
            // one the request did not write. That ordering is what keeps
            // `IqTarget::Unknown` meaning what its doc says — the addressee is a parameter
            // of the call — instead of being quietly upgraded to whatever server some
            // mixin happened to name.
            //
            // The `Unknown` arm is the other half: an addressee NEITHER side wrote is
            // `Unset`, but one that either side wrote and neither could resolve is
            // `Unknown`. Collapsing them would tell an emitter to send no `to` for a
            // request that has one — which is the shape of all four newsletter requests,
            // `smax("iq", null, …)` locally with `mergeNewsletterIQGetRequestMixin`
            // supplying `to: WAWap.JID(x)`.
            iq.target = Some(match (iq.target, mixin_resolved.2) {
                (Some(local), _) if local.is_resolved() => local,
                (None, Some(from_mixin)) if from_mixin.is_resolved() => from_mixin,
                (Some(IqTarget::Unknown), _) | (_, Some(IqTarget::Unknown)) => IqTarget::Unknown,
                // Nothing wrote a `to` on either side. `iq_target_from_to` yields `None`
                // for that, never `Unset`, so this is the only arm that can produce it.
                _ => IqTarget::Unset,
            });
            // Guard: a stanza needs both a namespace and a type, or it's dropped.
            match (iq.namespace.clone(), iq.iq_type) {
                (Some(namespace), Some(iq_type)) => {
                    let recovered =
                        crate::mixin_index::count_recovered_fields(&iq.children, &frag_children);
                    fields_recovered = fields_recovered.max(recovered);
                    crate::mixin_index::merge_children(&mut iq.children, &frag_children);
                    Some(ResolvedIqCall {
                        namespace,
                        iq_type,
                        target: iq.target.unwrap_or(IqTarget::Unset),
                        children: iq.children,
                        export: iq.export,
                    })
                }
                _ => None,
            }
        })
        .collect();

    // Modules often build the same `<iq>` in several code paths; emit each distinct
    // stanza once (identity = namespace/type/target/children, ignoring which export
    // built it). Order-preserving so the first occurrence's export wins. n is tiny.
    let mut deduped: Vec<ResolvedIqCall> = Vec::new();
    for r in resolved {
        if !deduped.iter().any(|d| {
            d.namespace == r.namespace
                && d.iq_type == r.iq_type
                && d.target == r.target
                && d.children == r.children
        }) {
            deduped.push(r);
        }
    }
    let resolved = deduped;

    // Exports drive the primary-name pick (below) and the fragment classification at
    // the unresolved bail (hoisted here so both see them).
    let exports = scanner.exports;
    let function_exports: Vec<&str> = exports
        .iter()
        .map(String::as_str)
        .filter(|e| {
            *e != "default" && !is_all_caps(e) && !ends_ci(e, "parser") && !ends_ci(e, "response")
        })
        .collect();

    // A module that exports a `merge…Mixin` combinator is a fragment: its `<iq>` is a
    // partial skeleton folded into the concrete request consumers via the mixin index,
    // never a standalone stanza. Otherwise the skeleton leaks into the stanza set as a
    // bogus "degraded" duplicate of data that already lives in the real requests, and a
    // fragment that resolved empty is mislabeled a genuine namespace/type failure.
    //
    // `any` (not `all`), and checked before the resolution guard, on purpose: a genuine
    // mixin often exports a `merge…Mixin` combinator *alongside* `make…` payload helpers
    // (`WASmaxOutSpamFRXMixin`) and often resolves its own `<iq>` to a skeleton rather
    // than to nothing — an `all`/`resolved.is_empty()` gate misses exactly those.
    //
    // Soundness of keying on the export name: `merge…Mixin` is WA's *exclusive*
    // cross-module mixin-export convention — sibling modules fold a mixin in by name via
    // `o("WASmaxOut…Mixin").merge<Name>Mixin(dst, …)`, so a real request builder never
    // defines a member with that name (internally or as an export). So although
    // `function_exports` is derived from every member assignment (not only verified
    // factory exports), the convention makes a false positive impossible here — borne
    // out by a full regen showing zero typed stanzas lost.
    let is_fragment = function_exports
        .iter()
        .any(|e| e.starts_with("merge") && e.contains("Mixin"));
    if is_fragment {
        return Err(DropReason::MixinFragment);
    }
    if resolved.is_empty() {
        // A non-fragment module that built an iq-shaped call but couldn't pin a
        // namespace/type (even after the mixin union) is a genuine guard drop.
        return Err(DropReason::Unresolved);
    }

    let primary: Option<&str> = function_exports
        .first()
        .copied()
        .or_else(|| exports.iter().any(|e| e == "default").then_some("default"))
        .or_else(|| exports.first().map(String::as_str));

    // Response: the legacy `WADeprecatedWapParser` if this module has one;
    // otherwise, for a smax `WASmaxOut<X>Request`, the typed response parsed from
    // the separate `WASmaxIn<X>ResponseSuccess` module (Phase 3). Legacy modules
    // (`WAWeb*`) never enter the smax branch, so the 33 legacy responses are
    // preserved byte-exact.
    let smax_response: Option<ParsedResponse> = if scanner.parser.is_none() {
        smax_request_op_name(module_name).and_then(|x| {
            // Prefer the RPC/ResponseSuccess index; fall back to a request-anchored
            // lookup for ops whose response module ends differently (e.g. ping's
            // `…ResponseServerResponse`).
            responses
                .get_by_x(x)
                .cloned()
                .or_else(|| responses.resolve_for_request_op(x))
        })
    } else {
        None
    };
    let response = scanner
        .parser
        .clone()
        .or(smax_response)
        .unwrap_or_else(unknown_parser);
    let parser_name = response.parser_name.clone();

    let stanzas = resolved
        .into_iter()
        .map(|iq| IqStanzaDef {
            module_name: module_name.to_string(),
            namespace: iq.namespace.clone(),
            iq_type: iq.iq_type,
            target: iq.target,
            parser_name: parser_name.clone(),
            // The export that lexically built this iq; fall back to the module's
            // primary function export when it wasn't captured (e.g. built at top level).
            exported_function: iq.export.clone().or_else(|| primary.map(str::to_string)),
            all_exports: exports.clone(),
            request: IqRequestDef {
                namespace: iq.namespace,
                iq_type: iq.iq_type,
                target: iq.target,
                children: iq.children,
            },
            response: response.clone(),
        })
        .collect();

    Ok((
        stanzas,
        CrossModuleStat {
            referenced_mixins,
            fields_recovered,
        },
    ))
}

fn unknown_parser() -> ParsedResponse {
    ParsedResponse {
        parser_name: "unknown".to_string(),
        ..Default::default()
    }
}

/// `^[A-Z_]+$` — an all-uppercase/underscore constant name.
fn is_all_caps(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
}

/// Case-insensitive suffix check (`/[Ss]uffix$/`). Byte-compared so a non-ASCII
/// export name can't trigger a UTF-8 boundary panic.
fn ends_ci(s: &str, suffix: &str) -> bool {
    let (sb, fb) = (s.as_bytes(), suffix.as_bytes());
    sb.len() >= fb.len() && sb[sb.len() - fb.len()..].eq_ignore_ascii_case(fb)
}

/// An iq builder call as collected during the walk. `namespace`/`iq_type` may be
/// unresolved locally (e.g. a `smax("iq", null, …)` whose xmlns/type come from
/// mixins) and get filled in afterwards from the [`MixinIndex`].
struct IqCall {
    namespace: Option<String>,
    iq_type: Option<IqType>,
    /// `None` when the builder writes no `to` — distinct from a `to` that resolved to
    /// nothing, which is [`IqTarget::Unknown`] and must not be overwritten by a mixin.
    target: Option<IqTarget>,
    children: Vec<WapChildNode>,
    /// The module export whose function lexically encloses this call (e.g.
    /// `e.sendFooBar = function(){ … wap("iq") … }` → `sendFooBar`), captured
    /// during the walk so the stanza's `exportedFunction` isn't guessed by index.
    export: Option<String>,
}

/// An iq call after namespace/type resolution + guard — ready to emit.
struct ResolvedIqCall {
    namespace: String,
    iq_type: IqType,
    target: IqTarget,
    children: Vec<WapChildNode>,
    export: Option<String>,
}

struct ModuleScanner<'src> {
    source: &'src str,
    scope: &'src VarScope,
    helpers: &'src HelperIndex,
    aliases: &'src AliasMap,
    iq_calls: Vec<IqCall>,
    parser: Option<ParsedResponse>,
    exports: Vec<String>,
    /// iq-call span start → `type` implied by an enclosing `merge…(Get|Set)…Mixin`.
    /// Populated when the wrapper is visited (parent-before-child), read when the
    /// inner iq call is visited.
    type_hints: std::collections::HashMap<u32, IqType>,
    /// `WASmaxOut…` mixin modules this module folds in (by name, source order,
    /// deduped) — the candidates for cross-module xmlns/type resolution.
    mixin_callees: Vec<String>,
    /// The export name currently being walked (`e.<name> = …`), so an iq call is
    /// tagged with the function that lexically encloses it. Saved/restored around
    /// each member-assignment to handle nesting.
    current_export: Option<String>,
}

impl<'a> Visit<'a> for ModuleScanner<'_> {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let mut export: Option<String> = None;
        if let Some(m) = assign.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
            && prop != "__esModule"
            && prop != "prototype"
        {
            self.exports.push(prop.to_string());
            export = Some(prop.to_string());
        }
        // Tag iq calls inside `e.<name> = …` with `<name>`; restore on exit so
        // nested assignments don't leak their name to siblings.
        let prev = self.current_export.clone();
        if export.is_some() {
            self.current_export = export;
        }
        walk::walk_assignment_expression(self, assign);
        self.current_export = prev;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // A `merge…(Get|Set)…Mixin(stanza, …)` wrapper carries the iq `type` for
        // its inner stanza-builder argument (the type lives in a base mixin in
        // another module). Record the hint for that inner call's span; since the
        // walk visits this wrapper before its arguments, the hint is in place by
        // the time the inner iq call is visited.
        if let (Some(ty), Some(inner)) = (mixin_type_hint(call), call.arguments.first())
            && let Some(inner_call) = arg_expr(inner).and_then(as_call)
        {
            self.type_hints.insert(inner_call.span().start, ty);
        }

        // Collect `o("WASmaxOut…").merge…Mixin(…)` references so the post-walk
        // pass can resolve xmlns/type from those mixins' fragments.
        if let Some(method) = callee_method(call)
            && method.starts_with("merge")
            && method.contains("Mixin")
            && let Some(name) = callee_object(call).and_then(require_module_name)
            && name.starts_with("WASmaxOut")
            && !self.mixin_callees.contains(&name)
        {
            self.mixin_callees.push(name);
        }

        let hint = self.type_hints.get(&call.span().start).copied();
        if let Some(iq) = self.try_iq_call(call, hint) {
            self.iq_calls.push(iq);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        if self.parser.is_none() {
            self.try_parser(new_expr);
        }
        walk::walk_new_expression(self, new_expr);
    }
}

/// If `call` is a `merge…Get…Mixin` / `merge…Set…Mixin` invocation, the iq type
/// its inner stanza argument should take. `None` for any other call.
fn mixin_type_hint(call: &CallExpression) -> Option<IqType> {
    iq_type_from_merge_name(callee_method(call)?)
}

/// Who an `<iq>` built with these root attributes is addressed to, or `None` when the
/// builder writes no `to` at all — a state the caller resolves against the mixins it
/// folds in before settling on [`IqTarget::Unset`].
///
/// Shared with [`crate::mixin_index`] so a fragment's `to` is read by the same rule as a
/// request's. The rule it replaced had one arm — the literal `"g.us"` — and an `_ =>
/// Server` default, so a `to` the scan could not read was reported as the server: every
/// one of the 143 stanzas said `s.whatsapp.net`, including the `w:g2` requests the
/// client addresses to the group's own JID.
pub(crate) fn iq_target_from_to(attrs: &[WapAttrDef]) -> Option<IqTarget> {
    let to = attrs.iter().find(|a| a.name == "to")?;
    Some(match (&to.kind, to.value.as_deref()) {
        (WapAttrKind::Const, Some("g.us")) => IqTarget::GroupServer,
        (WapAttrKind::Const, Some("s.whatsapp.net")) => IqTarget::Server,
        // `GROUP_JID(x)` — a `<group>@g.us` JID computed from a call argument. The server
        // is fixed even though the JID is not, and it is NOT the same addressee as the
        // bare `g.us` above: WA writes the two from separate mixins
        // (`…BaseGetGroupMixin` vs `…BaseGetServerMixin`), and 26 of the 33 `w:g2`
        // requests take this one.
        (WapAttrKind::GroupJid, _) => IqTarget::GroupJid,
        // A runtime JID of some other flavour, or an expression the scan did not follow.
        _ => IqTarget::Unknown,
    })
}

/// `o("ModuleName")` → `"ModuleName"` (custom-require call, one string-literal
/// arg). Shared with [`crate::mixin_index`].
pub(crate) fn require_module_name(e: &Expression) -> Option<String> {
    wa_oxc::first_string_arg(as_call(e)?).map(str::to_string)
}

/// `WASmaxOut<X>Request` → `X` (operation name shared with the response module
/// `WASmaxIn<X>ResponseSuccess`). `None` for any other module name.
fn smax_request_op_name(module: &str) -> Option<&str> {
    module
        .strip_prefix("WASmaxOut")
        .and_then(|s| s.strip_suffix("Request"))
}

/// The iq type implied by a `merge…(Get|Set)…Mixin` function name, or `None` if
/// the name isn't a merge-mixin or is ambiguous. Shared by the per-module type
/// hint (above) and the cross-module mixin index ([`crate::mixin_index`]).
pub(crate) fn iq_type_from_merge_name(method: &str) -> Option<IqType> {
    // Accept both `…Mixin` and `…MixinGroup` (the OR-combinator variant).
    if !(method.starts_with("merge") && method.contains("Mixin")) {
        return None;
    }
    // Require an unambiguous Get/Set token between "merge" and "Mixin".
    match (method.contains("Get"), method.contains("Set")) {
        (true, false) => Some(IqType::Get),
        (false, true) => Some(IqType::Set),
        _ => None,
    }
}

impl ModuleScanner<'_> {
    fn try_iq_call(&self, call: &CallExpression, mixin_type: Option<IqType>) -> Option<IqCall> {
        let wap = parse_wap_call(call, self.aliases)?;
        if wap.tag != "iq" {
            return None;
        }
        // Attrs may be `null`/absent (e.g. `smax("iq", null, …children)`), in which
        // case namespace/type are resolved later from the referenced mixins.
        let attrs = wap
            .attrs_node
            .map(|n| extract_attrs_from_obj(n, self.source, self.aliases))
            .unwrap_or_default();
        // namespace: literal xmlns if present locally; else left None for the
        // post-walk mixin resolution (which re-applies the drop-if-unresolved guard).
        let namespace = const_value(&attrs, "xmlns").map(str::to_string);
        // type: inline `type:"get"/"set"`, else the enclosing merge…(Get|Set)…Mixin
        // hint; an unknown inline value (not get/set) drops the call outright.
        let iq_type = match const_value(&attrs, "type") {
            Some("get") => Some(IqType::Get),
            Some("set") => Some(IqType::Set),
            Some(_) => return None,
            None => mixin_type,
        };
        let target = iq_target_from_to(&attrs);

        let mut children = Vec::new();
        for child_arg in wap.child_args {
            if let Some(ce) = arg_expr(child_arg) {
                children.extend(resolve_child_node(
                    ce,
                    self.source,
                    self.scope,
                    self.source,
                    self.aliases,
                    // The request's locally-built children resolve structurally; the
                    // cross-module attrs a referenced mixin contributes arrive via
                    // `resolve_fragment_children` (Phase 2/3), merged in afterward.
                    None,
                    self.helpers,
                    0,
                    // `ce` is at a real module offset (source == module_source), so its
                    // position anchors the function context for scoped-initializer checks.
                    Some(ce.span().start as usize),
                ));
            }
        }

        Some(IqCall {
            namespace,
            iq_type,
            target,
            children,
            export: self.current_export.clone(),
        })
    }

    fn try_parser(&mut self, new_expr: &NewExpression) {
        // A module has at most one legacy response parser; the shared recognizer
        // (also used by `parse_module_wap_parsers`) keeps the two paths in lockstep.
        if let Some(parser) = crate::response::parsed_response_from_new_expr(new_expr, self.source)
        {
            self.parser = Some(parser);
        }
    }
}

/// Value of a `const`-kind attribute by name.
fn const_value<'a>(attrs: &'a [WapAttrDef], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name == name)
        .and_then(|a| a.value.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty mixin index: with it, `scan_module_source` is purely local (the
    /// Phase-2 path resolves nothing), matching pre-Phase-2 behavior.
    fn mi() -> MixinIndex {
        MixinIndex::default()
    }

    /// Empty response index: the smax response branch resolves nothing.
    fn ri() -> ResponseIndex {
        ResponseIndex::default()
    }

    fn hi() -> crate::helper_index::HelperIndex {
        crate::helper_index::HelperIndex::default()
    }

    const MODULE: &str = r#"
        __d("WAWebFooBarRPC", ["WADeprecatedSendIq","WAWap"], function(g,r,d,o,e,i,n){
            "use strict";
            e.sendFooBar = function(t){
                var q = i.wap("iq", { to: r("WAWap").S_WHATSAPP_NET, xmlns: "w:foo", type: "get", id: i.generateId() },
                    i.wap("query", { jid: i.USER_JID() }));
                return r("WADeprecatedSendIq").sendIq(q, new (r("WADeprecatedWapParser"))("FooBarResult", function(s){
                    s.assertTag("iq");
                    var c = s.child("result");
                    c.attrString("status");
                    c.forEachChildWithTag("entry", function(x){ x.attrInt("code"); });
                }));
            };
        }, 123);
    "#;

    #[test]
    fn scans_full_module() {
        let stanzas = scan_module_source(MODULE, &mi(), &ri(), &hi());
        assert_eq!(stanzas.len(), 1);
        let s = &stanzas[0];
        assert_eq!(s.module_name, "WAWebFooBarRPC");
        assert_eq!(s.namespace, "w:foo");
        assert_eq!(s.iq_type, IqType::Get);
        assert_eq!(s.target, IqTarget::Server);
        assert_eq!(s.parser_name, "FooBarResult");
        assert_eq!(s.exported_function.as_deref(), Some("sendFooBar"));

        // Request children: <query jid=.../>.
        assert_eq!(s.request.children.len(), 1);
        assert_eq!(s.request.children[0].tag, "query");
        assert!(s.request.children[0].attrs.iter().any(|a| a.name == "jid"));

        // Response: result child with status attr + repeating entry children.
        let result = s
            .response
            .fields
            .iter()
            .find(|f| f.tag.as_deref() == Some("result"))
            .unwrap();
        let kids = result.children.as_ref().unwrap();
        assert!(kids.iter().any(|c| c.name == "status"));
        assert!(
            kids.iter()
                .any(|c| c.tag.as_deref() == Some("entry") && c.repeats == Some(true))
        );
        assert!(
            s.response
                .assertions
                .iter()
                .any(|a| a.name.as_deref() == Some("iq"))
        );
    }

    #[test]
    fn identical_iq_built_twice_emits_one_stanza() {
        // Same <iq> built in two code paths → one stanza (dedup), and the export
        // is the function that lexically built it (not guessed by index).
        let m = r#"__d("WAWebDup",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.viaA = function(){ return i.wap("iq", { xmlns: "w:dup", type: "get" }); };
            e.viaB = function(){ return i.wap("iq", { xmlns: "w:dup", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s.len(), 1, "identical iq calls must dedup to one stanza");
        assert_eq!(s[0].namespace, "w:dup");
        assert_eq!(s[0].exported_function.as_deref(), Some("viaA"));
    }

    #[test]
    fn distinct_iqs_keep_their_enclosing_export() {
        // Two different stanzas, each named by its own enclosing export (the old
        // index-based mapping could cross-wire these).
        let m = r#"__d("WAWebTwo",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.getThing = function(){ return i.wap("iq", { xmlns: "w:a", type: "get" }); };
            e.setThing = function(){ return i.wap("iq", { xmlns: "w:b", type: "set" }); };
        });"#;
        let mut s = scan_module_source(m, &mi(), &ri(), &hi());
        s.sort_by(|a, b| a.namespace.cmp(&b.namespace));
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].namespace, "w:a");
        assert_eq!(s[0].exported_function.as_deref(), Some("getThing"));
        assert_eq!(s[1].namespace, "w:b");
        assert_eq!(s[1].exported_function.as_deref(), Some("setThing"));
    }

    #[test]
    fn group_target_detected() {
        let m = r#"__d("WAWebGrp",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.go = function(){ return i.wap("iq", { to: "g.us", xmlns: "w:g2", type: "set" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].target, IqTarget::GroupServer);
        assert_eq!(s[0].iq_type, IqType::Set);
    }

    #[test]
    fn a_to_that_does_not_resolve_to_a_server_is_unknown_not_the_server() {
        // The case that made every stanza claim `s.whatsapp.net`: the builder DOES write
        // a `to`, and it is a JID computed from the call's argument. The old rule had one
        // arm for the literal `"g.us"` and sent everything else to Server, so a request
        // addressed to a runtime JID reported the server it was never sent to.
        let m = r#"__d("WAWebDyn",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.go = function(t){ return i.wap("iq", { to: r("WAWap").JID(t), xmlns: "w:dyn", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].target, IqTarget::Unknown);
        assert!(!s[0].target.is_resolved());
    }

    #[test]
    fn an_unresolvable_to_from_a_folded_in_mixin_is_unknown_not_unset() {
        // `smax("iq", null, …)` writes no `to` of its own, so the addressee is whatever
        // the mixins it folds in supply — and `mergeNewsletterIQGetRequestMixin` supplies
        // `to: WAWap.JID(x)`, a runtime JID. The request HAS an addressee; the scan
        // cannot name it. Reporting `unset` would tell an emitter to send no `to` at all,
        // which is a different stanza — the same rounding-off this whole change removes,
        // one level further in.
        let mixin = r#"__d("WASmaxOutFooIQGetRequestMixin",["WAWap","WASmaxJsx"],function(g,r,d,o,e,i){
            e.mergeFooIQGetRequestMixin = function(s,t){ return o("WASmaxJsx").smax("iq", { to: o("WAWap").JID(t), xmlns: "newsletter", type: "get" }); };
        });"#;
        let m = r#"__d("WASmaxOutFooRequest",["WASmaxJsx","WASmaxOutFooIQGetRequestMixin"],function(g,r,d,o,e,i){
            e.makeFooRequest = function(t){ var q = o("WASmaxJsx").smax("iq", null); o("WASmaxOutFooIQGetRequestMixin").mergeFooIQGetRequestMixin(q, t); return q; };
        });"#;
        let bundle = format!("{mixin}\n{m}");
        let defs = wa_transform::extract_module_definitions(&bundle);
        let mixins = crate::mixin_index::build_pass(&defs, &bundle, &hi());
        let s = scan_module_source(m, &mixins, &ri(), &hi());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].target, IqTarget::Unknown);
    }

    #[test]
    fn a_builder_that_writes_no_to_reports_unset() {
        // Distinct from `Unknown`: nothing addresses this stanza, so an emitter should
        // send no `to` rather than substitute a server. `deprecatedSendIq` adds none.
        let m = r#"__d("WAWebNoTo",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.go = function(){ return i.wap("iq", { xmlns: "w:noto", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s[0].target, IqTarget::Unset);
    }

    #[test]
    fn the_wap_server_constants_resolve_to_their_servers() {
        // `WAWap.S_WHATSAPP_NET` / `G_US` are `WapJid.create(null, "s.whatsapp.net")` and
        // `(null, "g.us")` — compile-time constants, and the spelling the builders
        // actually use. The literal `"g.us"` the old rule keyed on appears nowhere in the
        // bundle any more, which is why the group requests went missing.
        let m = r#"__d("WAWebConst",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.a = function(){ return i.wap("iq", { to: r("WAWap").S_WHATSAPP_NET, xmlns: "w:a", type: "get" }); };
            e.b = function(){ return i.wap("iq", { to: r("WAWap").G_US, xmlns: "w:b", type: "set" }); };
            e.c = function(t){ return i.wap("iq", { to: r("WAWap").GROUP_JID(t), xmlns: "w:c", type: "set" }); };
        });"#;
        let mut s = scan_module_source(m, &mi(), &ri(), &hi());
        s.sort_by(|a, b| a.namespace.cmp(&b.namespace));
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].target, IqTarget::Server);
        // The bare group server and one group's own JID are different addressees: the
        // first is a literal to send, the second needs the group supplied.
        assert_eq!(s[1].target, IqTarget::GroupServer);
        assert_eq!(s[2].target, IqTarget::GroupJid);
        assert!(s[1].target.is_group() && s[2].target.is_group());
        assert!(
            s[2].target.is_resolved(),
            "the server is known, the JID is not"
        );
    }

    #[test]
    fn the_alias_spelling_does_not_decide_whether_the_server_is_recognised() {
        // The same constant reached three ways: through the require call, through an
        // inline `(n = o("WAWap"))`, and through a `var` bound earlier. All three are one
        // address in the source, so all three must be `Server` here — otherwise the IR's
        // answer depends on how the minifier happened to spell the binding, and the
        // `to`-is-honest rule turns into a coin flip.
        let m = r#"__d("WAWebAliased",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            var w = o("WAWap"), n;
            e.a = function(){ return i.wap("iq", { to: r("WAWap").S_WHATSAPP_NET, xmlns: "w:a", type: "get" }); };
            e.b = function(){ return (n = o("WAWap")).wap("iq", { to: n.S_WHATSAPP_NET, xmlns: "w:b", type: "get" }); };
            e.c = function(){ return i.wap("iq", { to: w.S_WHATSAPP_NET, xmlns: "w:c", type: "get" }); };
        });"#;
        let mut s = scan_module_source(m, &mi(), &ri(), &hi());
        s.sort_by(|a, b| a.namespace.cmp(&b.namespace));
        assert_eq!(s.len(), 3);
        for st in &s {
            assert_eq!(
                st.target,
                IqTarget::Server,
                "{} reads the same constant as the others",
                st.namespace
            );
        }
    }

    #[test]
    fn a_server_constant_from_an_unrelated_module_is_not_an_address() {
        // The gate on the owner: `X.S_WHATSAPP_NET` only names the server when `X` is
        // `WAWap`. A same-named property of anything else stays unresolved rather than
        // being read as an address.
        let m = r#"__d("WAWebOther",["WADeprecatedSendIq","WAWap"],function(g,r,d,o,e,i){
            e.go = function(){ return i.wap("iq", { to: r("WAWebSomethingElse").S_WHATSAPP_NET, xmlns: "w:o", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s[0].target, IqTarget::Unknown);
    }

    #[test]
    fn no_iq_yields_nothing() {
        assert!(
            scan_module_source(
                r#"__d("WAWebNope",[],function(){ var x = 1; });"#,
                &mi(),
                &ri(),
                &hi()
            )
            .is_empty()
        );
        // Not a module at all.
        assert!(scan_module_source("var z = 1;", &mi(), &ri(), &hi()).is_empty());
    }

    #[test]
    fn iq_without_parser_uses_unknown() {
        let m = r#"__d("WAWebNP",["WAWap"],function(g,r,d,o,e,i){
            e.f = function(){ return i.wap("iq", { xmlns: "w:x", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].parser_name, "unknown");
        assert!(s[0].response.fields.is_empty());
    }

    #[test]
    fn mixin_skeleton_is_dropped_as_fragment_not_a_degraded_stanza() {
        // A `merge*Mixin` module that builds a namespace/type skeleton `<iq>` is a
        // fragment folded into the concrete request consumers — not a standalone,
        // degraded stanza. It must be classified as MixinFragment, not emitted.
        let m = r#"__d("WASmaxOutFooIQMixin",["WAWap"],function(g,r,d,o,e,i){
            e.mergeFooIQMixin = function(){ return i.wap("iq", { xmlns: "foo", type: "get" }); };
        });"#;
        assert_eq!(
            scan_module_outcome(m, &mi(), &ri(), &hi()).unwrap_err(),
            DropReason::MixinFragment
        );
    }

    #[test]
    fn mixin_with_make_helper_export_is_still_a_fragment() {
        // A mixin module that also exports a `make*` payload helper (as the real
        // `WASmaxOutSpamFRXMixin` does) must still classify as a fragment — the presence
        // of the `merge*Mixin` combinator is the signal, not a pure-mixin export set.
        let m = r#"__d("WASmaxOutFooIQMixin",["WAWap"],function(g,r,d,o,e,i){
            e.makeFooToken = function(){ return 1; };
            e.mergeFooIQMixin = function(){ return i.wap("iq", { xmlns: "foo", type: "get" }); };
        });"#;
        assert_eq!(
            scan_module_outcome(m, &mi(), &ri(), &hi()).unwrap_err(),
            DropReason::MixinFragment
        );
    }

    #[test]
    fn iq_type_other_than_get_set_is_skipped() {
        let m = r#"__d("WAWebOdd",["WAWap"],function(g,r,d,o,e,i){
            e.f = function(){ return i.wap("iq", { xmlns: "w:x", type: "result" }); };
        });"#;
        assert!(scan_module_source(m, &mi(), &ri(), &hi()).is_empty());
    }

    #[test]
    fn ends_ci_is_utf8_safe() {
        assert!(ends_ci("fooParser", "parser"));
        assert!(ends_ci("Response", "response"));
        assert!(!ends_ci("xy", "parser"));
        // A multibyte char near the suffix boundary must not panic.
        assert!(!ends_ci("café", "parser"));
        assert!(!ends_ci("naïve", "ive"));
    }

    #[test]
    fn export_filtering_prefers_function_export() {
        // Exports include a CONST, a Parser-suffixed name, and a real fn export.
        let m = r#"__d("WAWebE",["WAWap"],function(g,r,d,o,e,i){
            e.SOME_CONST = 1;
            e.fooParser = 2;
            e.doThing = function(){ return i.wap("iq", { xmlns: "w:e", type: "get" }); };
        });"#;
        let s = scan_module_source(m, &mi(), &ri(), &hi());
        assert_eq!(s[0].exported_function.as_deref(), Some("doThing"));
        assert!(s[0].all_exports.contains(&"SOME_CONST".to_string()));
    }
}
