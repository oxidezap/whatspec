//! Native tooling: extract WhatsApp Web's incoming stanza-dispatch catalog.
//!
//! WA Web routes inbound stanzas through dispatcher modules shaped as a two-level
//! `switch` — `switch(stanza.tag)` at the top, and inside the `notification` arm a
//! `switch(notification.type)`:
//!
//! ```js
//! switch (stanza.tag) {
//!   case "receipt": …
//!   case "notification":
//!     switch (notification.type) {
//!       case "devices":  return … o("WAWebHandleDeviceNotification").handleDevicesNotification(e);
//!       case "encrypt":  { var f = e.content[0].tag; switch (f) { case "count": …; case "digest": … } }
//!       …
//!     }
//!   case "presence": return r("WAWebHandlePresence")(e);
//!   …
//! }
//! ```
//!
//! There is **more than one** such dispatcher (the main
//! `WAWebCommsHandleLoggedInStanza` plus a `WAWebCommsHandleWorkerCompatibleStanza`);
//! we locate each structurally — a `switch(.tag)` whose `notification` arm holds a
//! `switch(.type)`, a signature that excludes tag-classifiers like
//! `WAWebCreateNackFromStanza` — and **merge** their arms. The result is [`NotifIr`],
//! the union catalog, drift-pinned to the bundle.
//!
//! Handler resolution is structural, never by hardcoded name: an arm forwards via
//! `require("Module").method(stanza)` or `require("Module")(stanza)` (optionally
//! wrapped in promise plumbing like `e(handler(t)).catch(fn)`), all recovered from
//! the AST.
#![cfg(not(target_arch = "wasm32"))]

mod actions;

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Statement, SwitchCase, SwitchStatement, VariableDeclaration};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{
    AssertionKind, NotifIr, NotificationDef, ParsedResponse, ServerRequestTag, StanzaTagDef,
    SubCase, SubDiscriminant, SubDiscriminantOn,
};
use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_member, as_string_lit, callee_method,
    callee_object, first_string_arg, parse_cjs,
};
use wa_transform::ModuleDefinition;

/// A resolved handler forward: `(module, Some(method))` for
/// `require("Module").method(...)`, `(module, None)` for `require("Module")(...)`.
type Handler = (String, Option<String>);

/// Convenience: split a whole bundle into modules, then extract the catalog.
/// Mirrors the other extractors; the pipeline uses
/// [`extract_notif_from_modules`] to share one split.
pub fn extract_notif(source: &str, wa_version: &str) -> NotifIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_notif_from_modules(source, &defs, wa_version)
}

/// Extract the incoming stanza-dispatch catalog from an already-split module index.
///
/// Scans every module whose slice contains a `"notification"` case (a cheap, stable
/// pre-filter) and **merges** all qualifying dispatchers into one catalog. WA Web
/// splits notification handling across modules — the main
/// `WAWebCommsHandleLoggedInStanza` plus a `WAWebCommsHandleWorkerCompatibleStanza`
/// that adds the group/identity arms (`w:gp2`, `encrypt`→`identity`) — so reading
/// only the richest single dispatcher would silently drop those types.
pub fn extract_notif_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> NotifIr {
    extract_notif_with_diagnostics(source, module_defs, wa_version).0
}

/// Like [`extract_notif_from_modules`], but also returns the constraints the handlers'
/// legacy parsers carried and this domain could not resolve, by `dropsByReason` key.
/// See [`wa_scan::scan_incoming_with_diagnostics`] for why they are counted.
pub fn extract_notif_with_diagnostics(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> (NotifIr, std::collections::BTreeMap<String, usize>) {
    // Collect each dispatcher once (a module is often defined in several shards).
    let mut dispatchers: Vec<(String, Dispatch)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if !is_dispatcher_candidate(slice) || !seen.insert(m.name.as_str()) {
            continue;
        }
        if let Some(dispatch) = analyze_module(slice) {
            dispatchers.push((m.name.clone(), dispatch));
        }
    }
    // Merge in a stable order (by module name) so the union is deterministic and
    // "first non-empty handler wins" is reproducible regardless of bundle layout.
    dispatchers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut dispatcher_modules = Vec::new();
    let mut dispatch = Dispatch::default();
    for (name, d) in dispatchers {
        dispatcher_modules.push(name);
        merge_dispatch(&mut dispatch, d);
    }
    dispatcher_modules.sort();
    dispatcher_modules.dedup();

    // Deterministic order, independent of source layout.
    dispatch.stanza_tags.sort_by(|a, b| a.tag.cmp(&b.tag));
    dispatch
        .notifications
        .sort_by(|a, b| a.notif_type.cmp(&b.notif_type));
    for n in &mut dispatch.notifications {
        for sd in &mut n.sub_discriminants {
            sd.cases.sort_by(|a, b| a.value.cmp(&b.value));
        }
    }

    // Phase 2: attach each notification's typed content shape, read from its
    // handler module's `WADeprecatedWapParser`. Built after the catalog so a
    // handler that yields no parser leaves `content` absent (degraded), never
    // dropping the catalog entry.
    let slice_by_name = module_slice_index(source, module_defs);
    // The legacy parser leaves `o("Mod").ENUM` links pending — it reads one module at a
    // time — so this domain runs the same cross-module post-pass the IQ scan does.
    // Skipping it did not merely lose the link: the pending marker used to be an
    // `enumRef` with no variants, published as "this field admits no value".
    let mut enums = wa_scan::ResponseEnumLinker::new(module_defs, source);
    for n in &mut dispatch.notifications {
        let Some(module) = n.handler_module.clone() else {
            continue;
        };
        let Some(slice) = slice_by_name.get(module.as_str()) else {
            continue;
        };
        let notif_type = n.notif_type.clone();
        n.content = notification_content(slice, &notif_type);
        if let Some(content) = &mut n.content {
            enums.resolve(&format!("{module}::{notif_type}"), content);
        }
    }

    // Phase 3: the payload action union. `content` describes the envelope; a handler
    // that maps over the notification's children and switches on each child's tag
    // carries a whole second union inside it (`w:gp2`'s 40+ group actions). Resolved
    // against the full module index, since both the case labels and the `actionType`
    // values are `Module.CONST.MEMBER` references defined elsewhere.
    // The union is located per MODULE, not per handler function: the switch does not
    // live in the exported handler at all — `handleGroupNotification` builds a
    // `WADeprecatedWapParser` around a sibling local, and the child-tag switch is inside
    // that local. Scoping discovery to the handler's own body would therefore find
    // nothing and lose the whole `w:gp2` union.
    //
    // The cost of module scope is that a module hosting two handlers with two different
    // child-tag switches would hand the larger union to both of its notification types.
    // No module serves more than one type today, so rather than guess at which switch
    // belongs to which handler, a shared module is left without actions — an omission a
    // consumer can see, instead of an action union silently attributed to the wrong type.
    let mut types_per_module: HashMap<String, usize> = HashMap::new();
    for n in &dispatch.notifications {
        if let Some(m) = n.handler_module.clone() {
            *types_per_module.entry(m).or_default() += 1;
        }
    }
    let consts = actions::ConstResolver::new(&slice_by_name);
    for n in &mut dispatch.notifications {
        let Some(module) = n.handler_module.as_deref() else {
            continue;
        };
        if types_per_module.get(module).copied().unwrap_or(0) > 1 {
            continue;
        }
        let Some(slice) = slice_by_name.get(module) else {
            continue;
        };
        if let Some(found) = actions::extract_actions(slice, &consts) {
            n.actions = found;
        }
    }

    // Phase 2b: a type still degraded here has a handler that delegates parsing to
    // the smax receive-RPC path rather than an inline `WADeprecatedWapParser`, so its
    // field tree lives in a `WASmaxIn<X>...Request` module (the srvreq domain).
    // Recover it by matching the server-request read-shape whose asserted `type`
    // equals the notification's, keeping only unambiguous single-shape types.
    if dispatch.notifications.iter().any(|n| n.content.is_none()) {
        let srvreq_shapes = srvreq_notification_shapes(source, module_defs);
        for n in &mut dispatch.notifications {
            if n.content.is_none()
                && let Some(shape) = srvreq_shapes.get(&n.notif_type)
            {
                let mut shape = shape.clone();
                // This fallback runs after the pass above, so its shapes get resolved
                // here — otherwise a link recovered from a server-request read-shape
                // would be the one kind that still shipped unfinished.
                enums.resolve(&format!("srvreq::{}", n.notif_type), &mut shape);
                n.content = Some(shape);
            }
        }
    }

    let drops = enums.into_drop_counts();
    (
        NotifIr {
            wa_version: wa_version.to_string(),
            dispatcher_modules,
            stanza_tags: dispatch.stanza_tags,
            notifications: dispatch.notifications,
        },
        drops,
    )
}

/// Fold one dispatcher's arms into the accumulated catalog. New tags/types are
/// added; a type seen in multiple dispatchers keeps the first non-empty handler
/// and takes the **union** of sub-discriminant cases (e.g. `encrypt` gains
/// `identity` from the worker dispatcher on top of `count`/`digest`).
fn merge_dispatch(into: &mut Dispatch, from: Dispatch) {
    for tag in from.stanza_tags {
        match into.stanza_tags.iter_mut().find(|t| t.tag == tag.tag) {
            None => into.stanza_tags.push(tag),
            Some(existing) => {
                if existing.handler_module.is_none() {
                    existing.handler_module = tag.handler_module;
                    existing.handler_function = tag.handler_function;
                }
            }
        }
    }
    for notif in from.notifications {
        match into
            .notifications
            .iter_mut()
            .find(|n| n.notif_type == notif.notif_type)
        {
            None => into.notifications.push(notif),
            Some(existing) => {
                if existing.handler_module.is_none() {
                    existing.handler_module = notif.handler_module;
                    existing.handler_function = notif.handler_function;
                }
                merge_sub_discriminants(&mut existing.sub_discriminants, notif.sub_discriminants);
            }
        }
    }
}

/// Union sub-discriminant cases by (discriminant source, case value).
fn merge_sub_discriminants(into: &mut Vec<SubDiscriminant>, from: Vec<SubDiscriminant>) {
    for sd in from {
        match into.iter_mut().find(|x| x.on == sd.on) {
            None => into.push(sd),
            Some(existing) => {
                for case in sd.cases {
                    if let Some(cur) = existing.cases.iter_mut().find(|c| c.value == case.value) {
                        if cur.handler_module.is_none() {
                            cur.handler_module = case.handler_module;
                            cur.handler_function = case.handler_function;
                        }
                    } else {
                        existing.cases.push(case);
                    }
                }
            }
        }
    }
}

/// The catalog a single dispatcher module yields.
#[derive(Default)]
struct Dispatch {
    stanza_tags: Vec<StanzaTagDef>,
    notifications: Vec<NotificationDef>,
}

/// Module name → its source slice (first definition wins; a module is often
/// defined in several bundle shards). Lets a handler module be located by name
/// without re-splitting the bundle.
fn module_slice_index<'s>(
    source: &'s str,
    module_defs: &'s [ModuleDefinition],
) -> HashMap<&'s str, &'s str> {
    let mut idx = HashMap::new();
    for m in module_defs {
        idx.entry(m.name.as_str())
            .or_insert_with(|| &source[m.start..m.end]);
    }
    idx
}

/// The typed content shape of a notification `type`, read from its handler
/// module's legacy response parser (`new WADeprecatedWapParser("incoming…", fn)`).
/// `None` when the handler carries no such parser (it delegates parsing to a
/// job/sub-module) — a degraded, but still catalogued, entry.
fn notification_content(handler_slice: &str, notif_type: &str) -> Option<ParsedResponse> {
    let parsers = wa_scan::parse_module_wap_parsers(handler_slice);
    pick_notification_parser(parsers, notif_type)
}

/// Typed notification content recovered from the server-request read-shapes (the
/// srvreq domain): notification `type` → the `WASmaxIn<X>...Request` shape whose
/// parser asserts that `type`. Only types with a single matching shape are kept, so
/// a type parsed by several distinct request modules stays degraded rather than being
/// bound to one arbitrary shape (mirroring [`pick_notification_parser`]'s caution).
fn srvreq_notification_shapes(
    source: &str,
    module_defs: &[ModuleDefinition],
) -> std::collections::HashMap<String, ParsedResponse> {
    let asserted_type = |p: &ParsedResponse| -> Option<String> {
        p.assertions.iter().find_map(|a| {
            (a.kind == AssertionKind::Attr && a.name.as_deref() == Some("type"))
                .then(|| a.value.clone())
                .flatten()
        })
    };
    let mut by_type: std::collections::HashMap<String, Vec<ParsedResponse>> =
        std::collections::HashMap::new();
    for def in wa_scan::scan_server_requests_from_modules(source, module_defs) {
        if def.tag != ServerRequestTag::Notification {
            continue;
        }
        if let Some(t) = asserted_type(&def.shape) {
            by_type.entry(t).or_default().push(def.shape);
        }
    }
    by_type
        .into_iter()
        .filter_map(|(t, mut shapes)| match shapes.len() {
            1 => Some((t, shapes.pop().expect("len checked"))),
            _ => None,
        })
        .collect()
}

/// Choose the parser for `notif_type` from a handler module's parsers.
///
/// A module can hold parsers for several notification types (each asserting its
/// own `type`). Selection is deliberately conservative so one type's content shape
/// is never attached to another:
/// 1. the parser whose `assertAttr("type", notif_type)` matches (unambiguous even
///    among many parsers);
/// 2. else, only when there is **exactly one** notification-asserting parser (a
///    lone parser can't be confused with a sibling), use it;
/// 3. else, only when the module has **exactly one** parser at all, use it.
///
/// Anything else — several notification-asserting parsers, none pinned to
/// `notif_type` — is ambiguous and yields `None` (a degraded, still-catalogued
/// entry), rather than guessing.
fn pick_notification_parser(
    parsers: Vec<ParsedResponse>,
    notif_type: &str,
) -> Option<ParsedResponse> {
    let matches_type = |p: &ParsedResponse| {
        p.assertions.iter().any(|a| {
            a.kind == AssertionKind::Attr
                && a.name.as_deref() == Some("type")
                && a.value.as_deref() == Some(notif_type)
        })
    };
    let asserts_notification = |p: &ParsedResponse| {
        p.assertions
            .iter()
            .any(|a| a.kind == AssertionKind::Tag && a.name.as_deref() == Some("notification"))
    };
    // 1. Exact type match.
    if let Some(i) = parsers.iter().position(matches_type) {
        return parsers.into_iter().nth(i);
    }
    // 2. A single notification-asserting parser is unambiguous; multiple are not.
    let notif_positions: Vec<usize> = parsers
        .iter()
        .enumerate()
        .filter(|(_, p)| asserts_notification(p))
        .map(|(i, _)| i)
        .collect();
    if let [i] = notif_positions[..] {
        return parsers.into_iter().nth(i);
    }
    // 3. A single parser of any kind is unambiguous.
    if parsers.len() == 1 {
        return parsers.into_iter().next();
    }
    None
}

/// Cheap pre-filter: the dispatcher switches on a `"notification"` stanza tag, so
/// its slice contains that string literal. Matching the quoted literal (either
/// quote style) is whitespace-independent — robust to minifier spacing changes —
/// while still skipping the vast majority of modules. Non-dispatcher modules that
/// slip through are cheaply rejected by [`analyze_module`] (no qualifying switch).
fn is_dispatcher_candidate(slice: &str) -> bool {
    slice.contains("\"notification\"") || slice.contains("'notification'")
}

/// Parse a module slice and, if it contains the dispatch switch, extract its
/// catalog. `None` when the module has no qualifying `switch(x.tag)`.
fn analyze_module(slice: &str) -> Option<Dispatch> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    if ret.panicked {
        return None;
    }
    let mut finder = Finder { dispatch: None };
    finder.visit_program(&ret.program);
    finder.dispatch
}

/// Walks a parsed module to locate the first `switch(x.tag)` that has a
/// `"notification"` case, then extracts its catalog in place (no AST refs escape
/// the visit).
struct Finder {
    dispatch: Option<Dispatch>,
}

impl<'a> Visit<'a> for Finder {
    fn visit_switch_statement(&mut self, switch: &SwitchStatement<'a>) {
        if self.dispatch.is_none() && is_tag_switch(switch) {
            self.dispatch = Some(extract_dispatch(switch));
        }
        walk::walk_switch_statement(self, switch);
    }
}

/// A `switch(x.tag)` that dispatches notifications: its `"notification"` arm holds
/// a nested `switch(x.type)`. Requiring the inner type-switch (not just a
/// `notification` case) is what separates a real handler dispatcher from a
/// tag-classifier that merely mentions `notification` — e.g. `WAWebCreateNackFromStanza`,
/// which switches on tag to build a nack but never dispatches by notification type.
fn is_tag_switch(switch: &SwitchStatement) -> bool {
    member_prop(&switch.discriminant) == Some("tag")
        && switch.cases.iter().any(|c| {
            case_test_str(c) == Some("notification") && notif_arm_dispatches_by_type(&c.consequent)
        })
}

/// Whether a `notification` tag arm contains a `switch(x.type)` — the mark of a
/// real notification dispatcher.
fn notif_arm_dispatches_by_type(consequent: &[Statement]) -> bool {
    let body = first_try_block(consequent).unwrap_or_else(|| flatten_leading_block(consequent));
    body.iter().any(|s| {
        matches!(s, Statement::SwitchStatement(sw) if member_prop(&sw.discriminant) == Some("type"))
    })
}

/// Extract the stanza-tag arms and, from the `notification` arm, the notification
/// catalog.
fn extract_dispatch(switch: &SwitchStatement) -> Dispatch {
    let mut d = Dispatch::default();
    for case in &switch.cases {
        let Some(tag) = case_test_str(case) else {
            continue;
        };
        let handler = primary_handler(&case.consequent);
        d.stanza_tags.push(StanzaTagDef {
            tag: tag.to_string(),
            handler_module: handler.as_ref().map(|(m, _)| m.clone()),
            handler_function: handler.and_then(|(_, f)| f),
        });
        if tag == "notification" {
            d.notifications = extract_notifications(&case.consequent);
        }
    }
    d
}

/// Extract the `switch(notification.type)` arms (plus the trailing
/// `String(type) === "…"` if-guards) from the `notification` tag arm's body.
fn extract_notifications(consequent: &[Statement]) -> Vec<NotificationDef> {
    // The arm body is `try { switch(type){…} … } catch {}` in the main dispatcher
    // and `{ switch(type){…} break }` in the worker one; unwrap either wrapper so the
    // `switch` and the trailing if-guards are direct children.
    let body = first_try_block(consequent).unwrap_or_else(|| flatten_leading_block(consequent));

    let mut out = Vec::new();
    // The `switch(n.type)` arms.
    if let Some(switch) = body.iter().find_map(|s| match s {
        Statement::SwitchStatement(sw) if member_prop(&sw.discriminant) == Some("type") => {
            Some(sw.as_ref())
        }
        _ => None,
    }) {
        for case in &switch.cases {
            if let Some(ty) = case_test_str(case) {
                out.push(extract_notification_case(ty, &case.consequent));
            }
        }
    }
    // Trailing `if (… String(n.type) === "X" …) return handler(e)` arms — a couple
    // of types (passkey_prologue_request, crsc_continuation) dispatch this way.
    for stmt in body {
        if let Statement::IfStatement(if_stmt) = stmt
            && let Some(ty) = type_eq_string_literal(&if_stmt.test)
            && !out.iter().any(|n| n.notif_type == ty)
        {
            let handler = primary_handler(std::slice::from_ref(&if_stmt.consequent));
            out.push(NotificationDef {
                notif_type: ty.to_string(),
                handler_module: handler.as_ref().map(|(m, _)| m.clone()),
                handler_function: handler.and_then(|(_, f)| f),
                sub_discriminants: Vec::new(),
                content: None,
                actions: Vec::new(),
            });
        }
    }
    out
}

/// Build one [`NotificationDef`] from a `case "type": …` arm.
fn extract_notification_case(notif_type: &str, consequent: &[Statement]) -> NotificationDef {
    let handler = primary_handler(consequent);
    NotificationDef {
        notif_type: notif_type.to_string(),
        handler_module: handler.as_ref().map(|(m, _)| m.clone()),
        handler_function: handler.and_then(|(_, f)| f),
        sub_discriminants: extract_sub_discriminants(consequent),
        content: None,
        actions: Vec::new(),
    }
}

/// Second-level dispatch: a `switch(f)` where `f = something[0].tag` (the first
/// child node's tag), e.g. `encrypt` → `count` / `digest`.
fn extract_sub_discriminants(consequent: &[Statement]) -> Vec<SubDiscriminant> {
    let stmts = flatten_leading_block(consequent);
    // Locals bound to a `X[0].tag` expression (the sub-discriminant source).
    let first_child_tag_vars = first_child_tag_locals(stmts);

    let mut out = Vec::new();
    for stmt in stmts {
        let Statement::SwitchStatement(sw) = stmt else {
            continue;
        };
        let is_first_child_tag = match &sw.discriminant {
            Expression::Identifier(id) => first_child_tag_vars
                .iter()
                .any(|v| v.as_str() == id.name.as_str()),
            other => is_first_child_tag_expr(other),
        };
        if !is_first_child_tag {
            continue;
        }
        let cases: Vec<SubCase> = sw
            .cases
            .iter()
            .filter_map(|c| {
                let value = case_test_str(c)?;
                let handler = primary_handler(&c.consequent);
                Some(SubCase {
                    value: value.to_string(),
                    handler_module: handler.as_ref().map(|(m, _)| m.clone()),
                    handler_function: handler.and_then(|(_, f)| f),
                })
            })
            .collect();
        if !cases.is_empty() {
            out.push(SubDiscriminant {
                on: SubDiscriminantOn::FirstChildTag,
                cases,
            });
        }
    }
    out
}

/// Names of locals initialized as `X[0].tag` within `stmts` (the first-child-tag
/// sub-discriminant sources).
fn first_child_tag_locals(stmts: &[Statement]) -> Vec<String> {
    let mut names = Vec::new();
    for stmt in stmts {
        let Statement::VariableDeclaration(decl) = stmt else {
            continue;
        };
        collect_first_child_tag_decls(decl, &mut names);
    }
    names
}

fn collect_first_child_tag_decls(decl: &VariableDeclaration, out: &mut Vec<String>) {
    for d in &decl.declarations {
        if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref())
            && is_first_child_tag_expr(init)
        {
            out.push(name.to_string());
        }
    }
}

/// `X[0].tag` — a static `.tag` member over a `[0]`-indexed element.
fn is_first_child_tag_expr(e: &Expression) -> bool {
    let Some((obj, "tag")) = as_member(e) else {
        return false;
    };
    match obj {
        Expression::ComputedMemberExpression(cm) => as_int(&cm.expression) == Some(0),
        _ => false,
    }
}

/// The single handler an arm forwards to: the first *top-level* `return` whose
/// value resolves to a `require("Module")[.method](…)` call. Returns nested inside
/// `if`/`switch` are deliberately ignored — they are conditional sub-dispatches,
/// not the arm's primary handler.
///
/// A few arms bind the handler first and return the local (`var l = yield h(e);
/// return l`), so a fallback second pass reads top-level `var x = yield handler(…)`
/// inits — but only when `x` is actually returned at top level. Without that
/// check, a helper call stashed in a temp that is then dropped (`var t = job(e);
/// break`) would be mistaken for the primary handler.
fn primary_handler(consequent: &[Statement]) -> Option<Handler> {
    let stmts = flatten_leading_block(consequent);
    // Pass 1: `return [yield] handler(…)`.
    for stmt in stmts {
        if let Statement::ReturnStatement(ret) = stmt
            && let Some(arg) = &ret.argument
            && let Some(handler) = resolve_handler_call(unwrap_yield(arg))
        {
            return Some(handler);
        }
    }
    // The locals returned bare at top level (`return x`) — the only vars whose
    // initializer is the arm's actual result.
    let returned: std::collections::HashSet<&str> = stmts
        .iter()
        .filter_map(|s| match s {
            Statement::ReturnStatement(ret) => ret
                .argument
                .as_ref()
                .and_then(|a| as_identifier(unwrap_yield(a))),
            _ => None,
        })
        .collect();
    // Pass 2: `var x = [yield] handler(…); … return x` (x must be returned).
    for stmt in stmts {
        if let Statement::VariableDeclaration(decl) = stmt {
            for d in &decl.declarations {
                if let Some(name) = d.id.get_identifier_name()
                    && returned.contains(name.as_str())
                    && let Some(init) = &d.init
                    && let Some(handler) = resolve_handler_call(unwrap_yield(init))
                {
                    return Some(handler);
                }
            }
        }
    }
    None
}

/// Resolve a handler-forward call to `(module, method?)`:
/// - `require("Module").method(args)` → `(Module, Some(method))`
/// - `require("Module")(args)`        → `(Module, None)`
///
/// Also unwraps the promise plumbing WA wraps handlers in: `<inner>.catch(fn)` /
/// `.then(fn)` and `promiseWrapper(<inner>)` — e.g. the worker dispatcher's
/// `e(o("WAWebHandleGroupNotification").handleGroupNotification(t)).catch(…)`.
fn resolve_handler_call(e: &Expression) -> Option<Handler> {
    resolve_handler_rec(e, 0)
}

fn resolve_handler_rec(e: &Expression, depth: u8) -> Option<Handler> {
    if depth > 4 {
        return None;
    }
    let call = as_call(e)?;
    if let (Some(obj), Some(method)) = (callee_object(call), callee_method(call)) {
        // `require("Module").method(args)`
        if let Some(module) = require_name(obj) {
            return Some((module.to_string(), Some(method.to_string())));
        }
        // `<inner>.catch(fn)` / `.then(fn)` / `.finally(fn)` → the handler is `<inner>`.
        if matches!(method, "catch" | "then" | "finally")
            && let Some(h) = resolve_handler_rec(obj, depth + 1)
        {
            return Some(h);
        }
    }
    // `require("Module")(args)` — the callee is itself the require call.
    if let Some(module) = require_name(&call.callee) {
        return Some((module.to_string(), None));
    }
    // `wrapper(<inner>)` — a promise wrapper `e(handler(t))`; look inside its args
    // for the real handler call. Guarded to a bare-identifier callee so this only
    // peels plumbing wrappers, not arbitrary member calls.
    if as_identifier(&call.callee).is_some() {
        for arg in &call.arguments {
            if let Some(inner) = arg_expr(arg)
                && let Some(h) = resolve_handler_rec(inner, depth + 1)
            {
                return Some(h);
            }
        }
    }
    None
}

/// `ident("ModuleName")` (a factory require param called with one string literal)
/// → `"ModuleName"`. Rejects `String(x)`, `Array.isArray(x)`, `g(e)`, etc.
fn require_name<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b str> {
    let call = as_call(e)?;
    as_identifier(&call.callee)?;
    first_string_arg(call)
}

/// The notification-type literal from an `if` guard that compares the stanza's
/// `type` against a string, e.g. `n.type != null && String(n.type) === "crsc_continuation"`
/// → `"crsc_continuation"`.
///
/// Narrow on purpose: the equality is accepted only when its non-literal side
/// **references `.type`** (directly, or through a `String(x.type)` / `x.type.toString()`
/// wrapper). Without that guard, an unrelated `if (mode === "sentinel")` in the arm
/// would mint a phantom notification type with a bogus handler.
fn type_eq_string_literal<'b, 'a>(expr: &'b Expression<'a>) -> Option<&'b str> {
    match expr {
        Expression::BinaryExpression(bin)
            if matches!(
                bin.operator,
                oxc_ast::ast::BinaryOperator::StrictEquality
                    | oxc_ast::ast::BinaryOperator::Equality
            ) =>
        {
            // One side a string literal, the other a `.type` reference.
            let (lit, other) = match (as_string_lit(&bin.left), as_string_lit(&bin.right)) {
                (Some(s), _) => (s, &bin.right),
                (_, Some(s)) => (s, &bin.left),
                _ => return None,
            };
            references_type(other).then_some(lit)
        }
        // Descend `&&` / `||` chains to reach the `=== "…"` comparison.
        Expression::LogicalExpression(log) => {
            type_eq_string_literal(&log.left).or_else(|| type_eq_string_literal(&log.right))
        }
        Expression::ParenthesizedExpression(p) => type_eq_string_literal(&p.expression),
        _ => None,
    }
}

/// Whether `e` reads the stanza's `type`: a `.type` member, or one wrapped in
/// `String(x.type)` / `x.type.toString()`.
fn references_type(e: &Expression) -> bool {
    if member_prop(e) == Some("type") {
        return true;
    }
    let Some(call) = as_call(e) else {
        return false;
    };
    // `String(x.type)` — a bare-identifier callee over the type expression.
    if as_identifier(&call.callee).is_some() {
        return call
            .arguments
            .iter()
            .filter_map(arg_expr)
            .any(references_type);
    }
    // `x.type.toString()` — recurse into the method's receiver.
    callee_object(call).is_some_and(references_type)
}

// ── small AST helpers ────────────────────────────────────────────────────────────

/// The static member property name of `e` (`x.tag` → `"tag"`), if any.
fn member_prop<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b str> {
    as_member(e).map(|(_, prop)| prop)
}

/// The string-literal `test` of a switch case (`case "devices":` → `"devices"`).
fn case_test_str<'b, 'a>(case: &'b SwitchCase<'a>) -> Option<&'b str> {
    case.test.as_ref().and_then(as_string_lit)
}

/// Unwrap a `yield <expr>` to `<expr>` (WA's async handlers `return yield …`).
fn unwrap_yield<'b, 'a>(e: &'b Expression<'a>) -> &'b Expression<'a> {
    match e {
        Expression::YieldExpression(y) => y.argument.as_ref().map_or(e, |a| unwrap_yield(a)),
        Expression::ParenthesizedExpression(p) => unwrap_yield(&p.expression),
        _ => e,
    }
}

/// If `stmts` is a single `{ … }` block, its inner statements; else `stmts`.
/// A minified `case "x": { … }` arm nests its body in one block statement.
fn flatten_leading_block<'b, 'a>(stmts: &'b [Statement<'a>]) -> &'b [Statement<'a>] {
    match stmts {
        [Statement::BlockStatement(block)] => &block.body[..],
        _ => stmts,
    }
}

/// The body of the first `try { … }` in `stmts`, if any.
fn first_try_block<'b, 'a>(stmts: &'b [Statement<'a>]) -> Option<&'b [Statement<'a>]> {
    stmts.iter().find_map(|s| match s {
        Statement::TryStatement(t) => Some(&t.block.body[..]),
        _ => None,
    })
}

#[cfg(test)]
mod tests;
