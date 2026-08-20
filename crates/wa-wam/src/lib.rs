//! Native tooling: extract WhatsApp Web's WAM (analytics/metrics) surface.
//!
//! Each metric is declared by `WAWebWamCodegenUtils.defineEvents({Name: [code,
//! props, weights, channel?, privateStatsId?]})` in a `WAWeb…WamEvent` module, where
//! `props` is `{fieldName: [fieldId, type]}` and `type` is `<utils>.TYPES.<BASE>` or
//! `o("WAWebWamEnum…").<EXPORT>`. We parse every event and resolve the enum modules its
//! fields reference.
//!
//! An event catalog alone is the contents of a buffer nobody can assemble, so the same
//! scan reads the three neighbouring modules that describe the buffer itself —
//! `defineGlobal` and the private-stats table in `WAWebWamGlobals`, and the literals of
//! `WAWebWamConstants` — and, for each event, the places WA Web constructs it (see
//! [`callsites`]).
#![cfg(not(target_arch = "wasm32"))]

mod callsites;

use std::collections::{BTreeMap, BTreeSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{ArrayExpression, Expression, ObjectExpression, Statement};
use wa_ir::{
    WamCallSite, WamCallSiteField, WamConstant, WamEnum, WamEnumVariant, WamEvent, WamField,
    WamFieldType, WamFieldWrite, WamGlobal, WamIr, WamPrivateStatsId,
};
use wa_oxc::{
    arg_expr, as_call, as_int, as_member, as_object, as_string_lit, first_string_arg, parse_cjs,
    property_key_name,
};
use wa_transform::ModuleDefinition;

/// The runtime module every WAM event module depends on.
const CODEGEN_DEP: &str = "WAWebWamCodegenUtils";

/// The module whose whole body is the buffer's literal policy. Matched by name because
/// it has nothing else to match on: no call, no marker, just six exported numbers.
const CONSTANTS_MODULE: &str = "WAWebWamConstants";

/// The export that carries the private-stats rotation table.
const PRIVATE_STATS_TABLE: &str = "PrivateStatsAllIds";

/// The property that overrides an event's sampling weight at emission time.
const SAMPLING_WEIGHT_PROPERTY: &str = "weight";

/// What the scan recovered and, more importantly, what it did not.
#[derive(Debug, Default, Clone)]
pub struct WamDiagnostics {
    /// Buffer globals read from `defineGlobal`.
    pub globals: usize,
    /// Private-stats rotation groups read.
    pub private_stats_ids: usize,
    /// Buffer constants read.
    pub constants: usize,
    /// Constructions of a `…WamEvent` export seen anywhere in the bundle — the
    /// denominator the call-site numbers are a share of.
    pub constructions: usize,
    /// Call sites published on an event, after identical ones are deduplicated.
    pub call_sites: usize,
    /// Of those, the ones whose field set is a lower bound rather than the whole of it.
    pub partial_call_sites: usize,
    /// `(call site, field)` pairs published.
    pub call_site_fields: usize,
    /// Of those, the ones carrying a value fixed at extraction time.
    pub call_site_field_values: usize,
    /// What the scan could not turn into a field set, by reason — counted rather than
    /// omitted, so a construction that resisted reading and one that writes nothing
    /// never look alike.
    pub drops_by_reason: BTreeMap<String, usize>,
}

/// Convenience: split a bundle and extract the WAM surface (diagnostics dropped).
pub fn extract_wam(source: &str, wa_version: &str) -> WamIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_wam_from_modules(source, &defs, wa_version).0
}

/// Extract the WAM surface from an already-split module index.
pub fn extract_wam_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> (WamIr, WamDiagnostics) {
    let mut diag = WamDiagnostics::default();

    // event module name → modules that declare a dependency on it. The dep graph, and
    // no more than that: what a dependent does with the module is not visible here,
    // which is why `call_sites` exists beside it.
    let mut consumers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for m in module_defs {
        for d in &m.deps {
            if d.ends_with("WamEvent") && d.as_str() != m.name {
                consumers.entry(d.as_str()).or_default().insert(&m.name);
            }
        }
    }

    // Events carry the export name they are published under alongside them, and are
    // deduplicated BEFORE anything is attached: a module defined by two bundle files
    // yields the event twice, and attaching call sites first would hang them on the copy
    // the dedup then drops.
    let mut parsed: Vec<(Option<String>, WamEvent)> = Vec::new();
    let mut enum_modules: BTreeSet<String> = BTreeSet::new();
    for m in module_defs {
        // A WAM event module is a `…WamEvent` that depends on the codegen runtime.
        if !(m.name.ends_with("WamEvent") && m.deps.iter().any(|d| d == CODEGEN_DEP)) {
            continue;
        }
        for (export, mut ev) in parse_events(&source[m.start..m.end], &m.name) {
            for f in &ev.fields {
                if let WamFieldType::Enum { module } = &f.field_type {
                    enum_modules.insert(module.clone());
                }
            }
            ev.consumers = consumers
                .get(m.name.as_str())
                .map(|s| s.iter().map(|x| x.to_string()).collect())
                .unwrap_or_default();
            parsed.push((export, ev));
        }
    }
    parsed.sort_by(|a, b| a.1.code.cmp(&b.1.code).then_with(|| a.1.name.cmp(&b.1.name)));
    parsed.dedup_by(|a, b| a.1.code == b.1.code && a.1.name == b.1.name);

    // (event module, export) → index, for attributing constructions.
    let mut exports: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (i, (export, ev)) in parsed.iter().enumerate() {
        if let Some(export) = export {
            exports.insert((ev.module.clone(), export.clone()), i);
        }
    }
    let mut events: Vec<WamEvent> = parsed.into_iter().map(|(_, ev)| ev).collect();

    let (globals, private_stats_ids, constants) =
        parse_buffer_modules(source, module_defs, &mut enum_modules);
    diag.globals = globals.len();
    diag.private_stats_ids = private_stats_ids.len();
    diag.constants = constants.len();

    collect_call_sites(source, module_defs, &mut events, &exports, &mut diag);

    // Resolve the enum modules events and globals reference (self-contained IR).
    let mut enums: Vec<WamEnum> = Vec::new();
    for m in module_defs {
        if enum_modules.contains(&m.name)
            && let Some(en) = parse_enum(&source[m.start..m.end], &m.name)
        {
            enums.push(en);
        }
    }

    enums.sort_by(|a, b| a.module.cmp(&b.module));
    enums.dedup_by(|a, b| a.module == b.module);
    (
        WamIr {
            wa_version: wa_version.to_string(),
            events,
            enums,
            globals,
            private_stats_ids,
            constants,
        },
        diag,
    )
}

/// The buffer's own three descriptions: the globals that fill its header, the
/// private-stats groups a `private` buffer's id rotates on, and the literal policy.
fn parse_buffer_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    enum_modules: &mut BTreeSet<String>,
) -> (Vec<WamGlobal>, Vec<WamPrivateStatsId>, Vec<WamConstant>) {
    let mut globals: Vec<WamGlobal> = Vec::new();
    let mut ps_ids: Vec<WamPrivateStatsId> = Vec::new();
    let mut constants: Vec<WamConstant> = Vec::new();
    let mut table_module: Option<String> = None;
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if m.deps.iter().any(|d| d == CODEGEN_DEP) && slice.contains("defineGlobal") {
            globals.extend(parse_globals(slice));
            let table = parse_private_stats_table(slice, &m.name);
            if !table.is_empty() {
                table_module = Some(m.name.clone());
                ps_ids.extend(table);
            }
        }
        if m.name == CONSTANTS_MODULE {
            constants.extend(parse_constants(slice, &m.name));
        }
    }
    // The runtime adds one group the published table does not carry — the `none` key
    // that 21 events name — so a `privateStatsId` of 0 would otherwise resolve against
    // nothing. Read from the module that adds it, and attributed to it.
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if Some(&m.name) != table_module.as_ref()
            && slice.contains(PRIVATE_STATS_TABLE)
            && let Some(extra) = parse_extra_private_stats(slice, &m.name)
        {
            for e in extra {
                if !ps_ids.iter().any(|p| p.id == e.id) {
                    ps_ids.push(e);
                }
            }
        }
    }
    for g in &globals {
        if let WamFieldType::Enum { module } = &g.field_type {
            enum_modules.insert(module.clone());
        }
    }
    globals.sort_by(|a, b| a.name.cmp(&b.name));
    globals.dedup_by(|a, b| a.name == b.name);
    ps_ids.sort_by_key(|p| p.id);
    ps_ids.dedup_by_key(|p| p.id);
    constants.sort_by(|a, b| a.name.cmp(&b.name));
    constants.dedup_by(|a, b| a.name == b.name);
    (globals, ps_ids, constants)
}

/// Attach every construction the bundle contains to the event it constructs.
///
/// Only modules that declare a dependency on some `…WamEvent` are parsed: a Metro
/// module can only reach one through its own dependency list, so the rest cannot
/// contain a construction to miss.
fn collect_call_sites(
    source: &str,
    module_defs: &[ModuleDefinition],
    events: &mut [WamEvent],
    exports: &BTreeMap<(String, String), usize>,
    diag: &mut WamDiagnostics,
) {
    // event module → the single event it defines, for the modules that define one.
    let mut sole: BTreeMap<&str, usize> = BTreeMap::new();
    let mut defined: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, ev) in events.iter().enumerate() {
        *defined.entry(ev.module.as_str()).or_default() += 1;
        sole.insert(ev.module.as_str(), i);
    }
    let mut sites: BTreeMap<usize, Vec<WamCallSite>> = BTreeMap::new();
    let mut seen: BTreeSet<(String, String, u32)> = BTreeSet::new();
    for m in module_defs {
        if !m.deps.iter().any(|d| d.ends_with("WamEvent")) {
            continue;
        }
        for raw in callsites::scan_module(&source[m.start..m.end], &mut diag.drops_by_reason) {
            // The same module can be defined by more than one bundle file; a second copy
            // is the same source, not a second site.
            if !seen.insert((m.name.clone(), raw.event_module.clone(), raw.start)) {
                continue;
            }
            diag.constructions += 1;
            let index = exports
                .get(&(raw.event_module.clone(), raw.export.clone()))
                .copied()
                .or_else(|| match defined.get(raw.event_module.as_str()) {
                    Some(1) => sole.get(raw.event_module.as_str()).copied(),
                    _ => None,
                });
            let Some(index) = index else {
                // `WAWebWamCodegenWamEvent`'s `RawWamEvent` is the generic envelope: a
                // construction of a schema the catalog does not define, by design.
                *diag
                    .drops_by_reason
                    .entry("construction of an event with no catalog entry".to_string())
                    .or_default() += 1;
                continue;
            };
            let ev = &events[index];
            let mut fields: Vec<WamCallSiteField> = Vec::new();
            let mut partial = raw.partial;
            for (name, write, value) in raw.fields {
                if !ev.fields.iter().any(|f| f.name == name) {
                    // `weight` is not a field: it is the sampling weight on the event
                    // object, and writing it is the site overriding what the catalog
                    // declares. Worth counting under its own name — it is the only
                    // evidence in the IR that `weights` is a default.
                    let reason = if name == SAMPLING_WEIGHT_PROPERTY {
                        "call site overriding the catalog sampling weight"
                    } else {
                        // Anything else is a write we attributed wrongly, or a field the
                        // catalog does not know. Either way it is not schema to publish.
                        "written key naming no field of the event"
                    };
                    *diag.drops_by_reason.entry(reason.to_string()).or_default() += 1;
                    partial = true;
                    continue;
                }
                fields.push(WamCallSiteField { name, write, value });
            }
            fields.sort_by(|a, b| a.name.cmp(&b.name));
            merge_writes(&mut fields);
            sites.entry(index).or_default().push(WamCallSite {
                module: m.name.clone(),
                fields,
                partial,
            });
        }
    }
    for (index, mut list) in sites {
        list.sort_by(|a, b| {
            a.module.cmp(&b.module).then_with(|| {
                field_names(a)
                    .cmp(&field_names(b))
                    .then_with(|| a.partial.cmp(&b.partial))
            })
        });
        list.dedup_by(|a, b| a == b);
        for s in &list {
            diag.call_sites += 1;
            diag.partial_call_sites += usize::from(s.partial);
            diag.call_site_fields += s.fields.len();
            diag.call_site_field_values += s.fields.iter().filter(|f| f.value.is_some()).count();
        }
        events[index].call_sites = list;
    }
}

/// One entry per field, from the (already name-sorted) writes a site performs.
///
/// A site that constructs a field and reassigns it later — `e2eSuccessful: true` at the
/// top and `false` on the error path — writes it once unconditionally, so the entry is
/// the constructor write; but the value it ends up sending is whichever branch ran, so
/// the value is dropped rather than published as the site's answer. Two writes of the
/// same field with the same value keep it.
fn merge_writes(fields: &mut Vec<WamCallSiteField>) {
    let mut out: Vec<WamCallSiteField> = Vec::with_capacity(fields.len());
    for f in fields.drain(..) {
        match out.last_mut() {
            Some(prev) if prev.name == f.name => {
                if prev.value != f.value {
                    prev.value = None;
                }
                if f.write == WamFieldWrite::Constructor {
                    prev.write = WamFieldWrite::Constructor;
                }
            }
            _ => out.push(f),
        }
    }
    *fields = out;
}

fn field_names(s: &WamCallSite) -> Vec<&str> {
    s.fields.iter().map(|f| f.name.as_str()).collect()
}

/// Parse `defineGlobal({name: [id, type, channels?]})`. An omitted channel list means
/// `["regular"]`, exactly as the runtime defaults it.
fn parse_globals(slice: &str) -> Vec<WamGlobal> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let aliases = require_aliases(&ret.program);
    let mut out = Vec::new();
    for stmt in &ret.program.body {
        walk_call(stmt, "defineGlobal", &mut |call| {
            let Some(obj) = call
                .arguments
                .first()
                .and_then(arg_expr)
                .and_then(as_object)
            else {
                return;
            };
            for (name, value) in wa_oxc::obj_props(obj) {
                let Expression::ArrayExpression(arr) = value else {
                    continue;
                };
                let (Some(id), Some(field_type)) = (
                    arr_elem(arr, 0).and_then(as_int),
                    arr_elem(arr, 1).and_then(|e| parse_field_type(e, &aliases)),
                ) else {
                    continue;
                };
                let channels = match arr_elem(arr, 2) {
                    Some(Expression::ArrayExpression(ch)) => (0..ch.elements.len())
                        .filter_map(|i| arr_elem(ch, i).and_then(as_string_lit))
                        .map(str::to_string)
                        .collect(),
                    _ => vec!["regular".to_string()],
                };
                out.push(WamGlobal {
                    name: name.to_string(),
                    id: id as u32,
                    field_type,
                    channels,
                });
            }
        });
    }
    out
}

/// Parse the `[{key, keyHashInt, rotationPeriodDays}]` rotation table.
fn parse_private_stats_table(slice: &str, module: &str) -> Vec<WamPrivateStatsId> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V<'m> {
        module: &'m str,
        out: Vec<WamPrivateStatsId>,
    }
    impl<'a> Visit<'a> for V<'_> {
        fn visit_array_expression(&mut self, arr: &ArrayExpression<'a>) {
            let mut entries = Vec::new();
            for i in 0..arr.elements.len() {
                let Some(entry) = arr_elem(arr, i)
                    .and_then(as_object)
                    .and_then(|o| private_stats_entry(o, self.module))
                else {
                    entries.clear();
                    break;
                };
                entries.push(entry);
            }
            self.out.append(&mut entries);
            walk::walk_array_expression(self, arr);
        }
    }
    let mut v = V {
        module,
        out: Vec::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    v.out
}

fn private_stats_entry(obj: &ObjectExpression, module: &str) -> Option<WamPrivateStatsId> {
    Some(WamPrivateStatsId {
        key: as_string_lit(wa_oxc::obj_prop(obj, "key")?)?.to_string(),
        id: as_int(wa_oxc::obj_prop(obj, "keyHashInt")?)?,
        rotation_period_days: as_int(wa_oxc::obj_prop(obj, "rotationPeriodDays")?)?,
        module: module.to_string(),
    })
}

/// The groups a module adds on top of the published table: `<x>.<key> = <int>` for the
/// id, `<y>.<key> = {rotationPeriodDays: <int>}` for the period, joined on the key.
fn parse_extra_private_stats(slice: &str, module: &str) -> Option<Vec<WamPrivateStatsId>> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V {
        ids: BTreeMap<String, i64>,
        periods: BTreeMap<String, i64>,
    }
    impl<'a> Visit<'a> for V {
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(m) = a.left.as_member_expression()
                && let Some(key) = m.static_property_name()
            {
                if let Some(v) = as_int(&a.right) {
                    self.ids.insert(key.to_string(), v);
                } else if let Some(days) = as_object(&a.right)
                    .and_then(|o| wa_oxc::obj_prop(o, "rotationPeriodDays"))
                    .and_then(as_int)
                {
                    self.periods.insert(key.to_string(), days);
                }
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut v = V {
        ids: BTreeMap::new(),
        periods: BTreeMap::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    let out: Vec<WamPrivateStatsId> = v
        .periods
        .iter()
        .filter_map(|(key, days)| {
            Some(WamPrivateStatsId {
                key: key.clone(),
                id: *v.ids.get(key)?,
                rotation_period_days: *days,
                module: module.to_string(),
            })
        })
        .collect();
    (!out.is_empty()).then_some(out)
}

/// Parse `WAWebWamConstants`: locals bound to a number, exported under their name.
fn parse_constants(slice: &str, module: &str) -> Vec<WamConstant> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V {
        locals: BTreeMap<String, i64>,
        exports: Vec<(String, String)>,
        direct: Vec<(String, i64)>,
    }
    impl<'a> Visit<'a> for V {
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if let (Some(name), Some(v)) = (
                d.id.get_identifier_name(),
                d.init.as_ref().and_then(|e| as_int(e)),
            ) {
                self.locals.insert(name.to_string(), v);
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(m) = a.left.as_member_expression()
                && let Some(name) = m.static_property_name()
            {
                if let Some(v) = as_int(&a.right) {
                    self.direct.push((name.to_string(), v));
                } else if let Some(id) = wa_oxc::as_identifier(&a.right) {
                    self.exports.push((name.to_string(), id.to_string()));
                }
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut v = V {
        locals: BTreeMap::new(),
        exports: Vec::new(),
        direct: Vec::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    let mut out: Vec<WamConstant> = v
        .direct
        .into_iter()
        .chain(
            v.exports
                .iter()
                .filter_map(|(name, local)| Some((name.clone(), *v.locals.get(local)?))),
        )
        .map(|(name, value)| WamConstant {
            name,
            value,
            module: module.to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    out
}

/// Run `f` on every `<x>.<method>(…)` call in a statement.
fn walk_call(stmt: &Statement, method: &str, f: &mut dyn FnMut(&oxc_ast::ast::CallExpression)) {
    use oxc_ast_visit::{Visit, walk};
    struct V<'m> {
        method: &'m str,
        f: &'m mut dyn FnMut(&oxc_ast::ast::CallExpression),
    }
    impl<'a> Visit<'a> for V<'_> {
        fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
            if wa_oxc::callee_method(call) == Some(self.method) {
                (self.f)(call);
            }
            walk::walk_call_expression(self, call);
        }
    }
    let mut v = V { method, f };
    v.visit_statement(stmt);
}

/// An array element's inner expression (skips holes/spreads).
fn arr_elem<'b, 'a>(arr: &'b ArrayExpression<'a>, i: usize) -> Option<&'b Expression<'a>> {
    arr.elements.get(i).and_then(|e| e.as_expression())
}

/// Parse the `defineEvents({...})` call(s) in a module slice into events, each with the
/// name it is exported under when that is recoverable.
///
/// The export name is what a construction elsewhere in the bundle spells
/// (`new (o("<module>").<Export>)(…)`), so it is what attributes a call site to the
/// right event in a module that defines more than one.
fn parse_events(slice: &str, module: &str) -> Vec<(Option<String>, WamEvent)> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V<'m> {
        module: &'m str,
        /// Locals standing for a `o("Module")` require.
        aliases: &'m BTreeMap<String, String>,
        /// Events, tagged with the span of the `defineEvents` call that made them.
        out: Vec<(u32, WamEvent)>,
        /// Local name → span of the `defineEvents` call it holds.
        locals: BTreeMap<String, u32>,
        /// Export name → span, either assigned directly or through a local.
        by_span: BTreeMap<u32, String>,
        pending: Vec<(String, String)>,
    }
    impl<'a> Visit<'a> for V<'_> {
        fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
            if wa_oxc::callee_method(call) == Some("defineEvents")
                && let Some(obj) = call
                    .arguments
                    .first()
                    .and_then(arg_expr)
                    .and_then(as_object)
            {
                for (name, value) in wa_oxc::obj_props(obj) {
                    if let Some(ev) = parse_event(name, value, self.module, self.aliases) {
                        self.out.push((call.span.start, ev));
                    }
                }
            }
            walk::walk_call_expression(self, call);
        }
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if let Some(name) = d.id.get_identifier_name()
                && let Some(span) = d.init.as_ref().and_then(define_events_span)
            {
                self.locals.insert(name.to_string(), span);
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(m) = a.left.as_member_expression()
                && let Some(export) = m.static_property_name()
            {
                if let Some(span) = define_events_span(&a.right) {
                    self.by_span.insert(span, export.to_string());
                } else if let Some(id) = wa_oxc::as_identifier(&a.right) {
                    self.pending.push((export.to_string(), id.to_string()));
                }
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let aliases = require_aliases(&ret.program);
    let mut v = V {
        module,
        aliases: &aliases,
        out: Vec::new(),
        locals: BTreeMap::new(),
        by_span: BTreeMap::new(),
        pending: Vec::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    for (export, local) in &v.pending {
        if let Some(span) = v.locals.get(local) {
            v.by_span.insert(*span, export.clone());
        }
    }
    v.out
        .into_iter()
        .map(|(span, ev)| (v.by_span.get(&span).cloned(), ev))
        .collect()
}

/// The span of a `<x>.defineEvents(…)` call, if that is what the expression is.
fn define_events_span(e: &Expression) -> Option<u32> {
    let call = as_call(e)?;
    (wa_oxc::callee_method(call) == Some("defineEvents")).then_some(call.span.start)
}

/// Parse one `Name: [code, propsObj, weightsArr, channel?, psId?]` entry.
fn parse_event(
    name: &str,
    value: &Expression,
    module: &str,
    aliases: &BTreeMap<String, String>,
) -> Option<WamEvent> {
    let Expression::ArrayExpression(arr) = value else {
        return None;
    };
    let code = as_int(arr_elem(arr, 0)?)? as u32;
    let props = as_object(arr_elem(arr, 1)?)?;
    let fields = parse_fields(props, aliases);

    let weights = arr_elem(arr, 2)
        .and_then(|e| match e {
            Expression::ArrayExpression(a) => Some(a),
            _ => None,
        })
        .map(|a| {
            (0..a.elements.len())
                .filter_map(|i| arr_elem(a, i).and_then(as_int).map(|v| v as u32))
                .collect()
        })
        .unwrap_or_default();

    // channel (default "regular") + privateStatsId (the JS `-1` sentinel → None).
    let channel = arr_elem(arr, 3)
        .and_then(as_string_lit)
        .unwrap_or("regular")
        .to_string();
    let private_stats_id = arr_elem(arr, 4).and_then(as_int).filter(|&v| v != -1);

    Some(WamEvent {
        name: name.to_string(),
        code,
        module: module.to_string(),
        channel,
        weights,
        private_stats_id,
        fields,
        consumers: Vec::new(),
        call_sites: Vec::new(),
    })
}

/// Parse `{fieldName: [fieldId, type], …}` into ordered fields (skips entries whose
/// type isn't a recognized base type or enum ref).
fn parse_fields(obj: &ObjectExpression, aliases: &BTreeMap<String, String>) -> Vec<WamField> {
    let mut fields = Vec::new();
    for (name, value) in wa_oxc::obj_props(obj) {
        let Expression::ArrayExpression(arr) = value else {
            continue;
        };
        let (Some(id), Some(ty)) = (
            arr_elem(arr, 0).and_then(as_int),
            arr_elem(arr, 1).and_then(|e| parse_field_type(e, aliases)),
        ) else {
            continue;
        };
        fields.push(WamField {
            name: name.to_string(),
            id: id as u32,
            field_type: ty,
        });
    }
    fields
}

/// `<utils>.TYPES.<BASE>` → a base type; `o("WAWebWamEnum…").<EXPORT>` → an enum ref.
///
/// The minifier writes the require of a repeatedly used enum module once and reads a
/// local afterwards — `(e = o("WAWebWamEnum…")).X` at the first field, `e.X` at the
/// next — so `aliases` carries what each local was bound to. Without it those fields
/// resolve to no type and drop out of the event, which is how an event with five enum
/// fields came to publish one.
fn parse_field_type(e: &Expression, aliases: &BTreeMap<String, String>) -> Option<WamFieldType> {
    let (obj, prop) = as_member(e)?;
    let obj = unwrap_binding(obj);
    // Base type: the member chain `<x>.TYPES.<NAME>`.
    if let Some((_, mid)) = as_member(obj)
        && mid == "TYPES"
    {
        return base_type(prop);
    }
    // Enum ref: the require call itself, or a local standing for it.
    let module = as_call(obj)
        .and_then(first_string_arg)
        .map(str::to_string)
        .or_else(|| wa_oxc::as_identifier(obj).and_then(|id| aliases.get(id).cloned()))?;
    module
        .starts_with("WAWebWamEnum")
        .then_some(WamFieldType::Enum { module })
}

/// Strip the parentheses and the inline assignment the minifier wraps a first use in:
/// `(e = o("M"))` → `o("M")`.
fn unwrap_binding<'b, 'a>(e: &'b Expression<'a>) -> &'b Expression<'a> {
    let mut cur = e;
    loop {
        cur = match cur {
            Expression::ParenthesizedExpression(p) => &p.expression,
            Expression::AssignmentExpression(a) => &a.right,
            _ => return cur,
        };
    }
}

/// Locals bound to a `o("Module")` require, so a field type written through one still
/// names its module.
fn require_aliases(program: &oxc_ast::ast::Program) -> BTreeMap<String, String> {
    use oxc_ast_visit::{Visit, walk};
    struct V {
        out: BTreeMap<String, String>,
    }
    impl<'a> Visit<'a> for V {
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if let Some(name) = d.id.get_identifier_name()
                && let Some(module) = d.init.as_ref().and_then(required_module)
            {
                self.out.insert(name.to_string(), module.to_string());
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(name) = wa_oxc::assignment_target_name(&a.left)
                && let Some(module) = required_module(&a.right)
            {
                self.out.insert(name.to_string(), module.to_string());
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut v = V {
        out: BTreeMap::new(),
    };
    for stmt in &program.body {
        v.visit_statement(stmt);
    }
    v.out
}

/// The module name of a `<require>("Module")` call.
fn required_module<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b str> {
    first_string_arg(as_call(e)?)
}

fn base_type(name: &str) -> Option<WamFieldType> {
    Some(match name {
        "BOOLEAN" => WamFieldType::Boolean,
        "INTEGER" => WamFieldType::Integer,
        "NUMBER" => WamFieldType::Number,
        "STRING" => WamFieldType::String,
        "TIMER" => WamFieldType::Timer,
        _ => return None,
    })
}

/// Parse a `WAWebWamEnum…` module: `Object.freeze({KEY: int})` exported under a name.
fn parse_enum(slice: &str, module: &str) -> Option<WamEnum> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);

    use oxc_ast_visit::{Visit, walk};
    struct V {
        /// local var name → frozen object's variants
        locals: BTreeMap<String, Vec<WamEnumVariant>>,
        /// `export = local` (export name, local ident)
        pending: Vec<(String, String)>,
        /// `export = Object.freeze({...})` (export name, variants)
        named: Vec<(String, Vec<WamEnumVariant>)>,
    }
    impl<'a> Visit<'a> for V {
        fn visit_variable_declarator(&mut self, d: &oxc_ast::ast::VariableDeclarator<'a>) {
            if let (Some(name), Some(obj)) = (
                d.id.get_identifier_name(),
                d.init.as_ref().and_then(frozen_object),
            ) && let Some(vars) = parse_enum_variants(obj)
            {
                self.locals.insert(name.to_string(), vars);
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &oxc_ast::ast::AssignmentExpression<'a>) {
            if let Some(m) = a.left.as_member_expression()
                && let Some(prop) = m.static_property_name()
            {
                if let Some(obj) = frozen_object(&a.right) {
                    if let Some(vars) = parse_enum_variants(obj) {
                        self.named.push((prop.to_string(), vars));
                    }
                } else if let Some(id) = wa_oxc::as_identifier(&a.right) {
                    self.pending.push((prop.to_string(), id.to_string()));
                }
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut v = V {
        locals: BTreeMap::new(),
        pending: Vec::new(),
        named: Vec::new(),
    };
    for stmt in &ret.program.body {
        v.visit_statement(stmt);
    }
    // Resolve `export = local`.
    for (name, local) in &v.pending {
        if let Some(vars) = v.locals.get(local) {
            v.named.push((name.clone(), vars.clone()));
        }
    }
    // First named export wins; `exports`/`default` name by module.
    let (name, variants) = v.named.into_iter().next()?;
    let name = if name == "exports" || name == "default" {
        module.to_string()
    } else {
        name
    };
    Some(WamEnum {
        name,
        module: module.to_string(),
        variants,
    })
}

/// `Object.freeze(<obj>)` → the object literal; also accepts a bare object literal.
fn frozen_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    if let Some(call) = as_call(e)
        && let Some((_, prop)) = as_member(&call.callee)
        && prop == "freeze"
    {
        return as_object(arg_expr(call.arguments.first()?)?);
    }
    as_object(e)
}

/// Parse `{KEY: int}` into variants (source order). `None` on a non-int value.
fn parse_enum_variants(obj: &ObjectExpression) -> Option<Vec<WamEnumVariant>> {
    let mut out = Vec::new();
    for prop in &obj.properties {
        let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop else {
            return None;
        };
        let key = property_key_name(&p.key)?;
        let value = as_int(&p.value)?;
        out.push(WamEnumVariant {
            key: key.to_string(),
            value,
        });
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests;
