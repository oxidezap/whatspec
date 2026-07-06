//! Native tooling: extract WhatsApp Web's `$InternalEnum` wire-enum catalog.
//!
//! WA defines most of its enums as `var X = n("$InternalEnum")({ NAME: value, … })`
//! and exports them under a name. We collect each definition, recover its name
//! from the module's export (`obj.Name = X` / `obj.exports = X` → module name),
//! and keep only enums whose values are all-integer or all-string literals.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, Expression, ObjectExpression, ObjectPropertyKind, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{EnumValueKind, EnumVariant, EnumsIr, InternalEnumDef, Scalar};
use wa_oxc::{
    arg_expr, as_call, as_identifier, as_object, first_string_arg, parse_cjs, property_key_name,
};
use wa_transform::ModuleDefinition;

/// The dependency every `$InternalEnum`-defining module declares.
const DEP: &str = "$InternalEnum";

/// Parsed enum body: its value kind + variants (source order).
type EnumData = (EnumValueKind, Vec<EnumVariant>);

/// Convenience: split a whole bundle into modules, then extract the catalog.
/// Mirrors `extract_mex` / `extract_appstate`; the pipeline uses
/// [`extract_enums_from_modules`] to share one split with the other extractors.
pub fn extract_enums(source: &str, wa_version: &str) -> EnumsIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_enums_from_modules(source, &defs, wa_version)
}

/// Extract the `$InternalEnum` catalog from an already-split module index.
pub fn extract_enums_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> EnumsIr {
    let mut enums = Vec::new();
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if m.deps.iter().any(|d| d == DEP) {
            // The reliable, cheap path: `$InternalEnum({…})` definitions.
            enums.extend(extract_from_module(slice, &m.name));
        } else if is_protocol_enum_module(&m.name) {
            // Some wire enums are plain object literals exported by name
            // (`var e={INACTIVE:-6,…}; i.ACK=e`) with no `$InternalEnum` dep. A plain
            // object is ambiguous (every `{a:1,b:2}` config/UI/i18n map looks like one),
            // so this path is scoped to modules WA names by its *protocol* enum-bag
            // convention — `WASmax<In|Out>…Enums` plus the two ack/receipt level modules —
            // never the app's infra constants (loggers, locales, JPEG markers, …). Within
            // those, [`extract_plain_object_enums`] still keeps only `CONSTANT_CASE`
            // members so a stray helper export can't leak in.
            enums.extend(extract_plain_object_enums(slice, &m.name));
        }
    }
    // Deterministic order independent of bundle layout.
    enums.sort_by(|a, b| a.module.cmp(&b.module).then_with(|| a.name.cmp(&b.name)));
    enums.dedup_by(|a, b| a.module == b.module && a.name == b.name);
    EnumsIr {
        wa_version: wa_version.to_string(),
        enums,
    }
}

fn extract_from_module(slice: &str, module: &str) -> Vec<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut c = Collector {
        module,
        locals: HashMap::new(),
        named: Vec::new(),
        pending: Vec::new(),
    };
    c.visit_program(&ret.program);

    // Resolve `export = local` bindings against the locals captured by var-init.
    for (name, local) in &c.pending {
        if let Some(data) = c.locals.get(local) {
            c.named.push((name.clone(), data.clone()));
        }
    }

    let mut out: Vec<InternalEnumDef> = Vec::new();
    for (name, (value_kind, variants)) in c.named {
        if out.iter().any(|d| d.name == name) {
            continue; // first binding wins (aliases collapse)
        }
        out.push(InternalEnumDef {
            name,
            module: module.to_string(),
            value_kind,
            variants,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Resolve one named enum export from a single module, for the IQ attribute
/// enum-linking. Unlike the catalog extractor this also accepts a **plain
/// object-literal** export (`X.Name = {KEY:"val"}` or `var l = {…}; X.Name = l`) —
/// how enums like `USYNC_ADDRESSING_MODE` / `ENC_RETRY_RECEIPT_ATTRS` are defined
/// (they never reach the `$InternalEnum` catalog). It is targeted by `name` and
/// validated by [`parse_enum`] (all-literal values, one value kind), so a non-enum
/// object can't resolve. Returns `None` when `name` isn't an enum-shaped export — the
/// caller then drops the link rather than guessing.
pub fn resolve_named_enum(module_slice: &str, module: &str, name: &str) -> Option<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, module_slice);
    if ret.panicked {
        return None;
    }
    let mut r = NamedResolver {
        locals: HashMap::new(),
        exports: HashMap::new(),
        pending: Vec::new(),
    };
    r.visit_program(&ret.program);
    // `X.Name = local` bindings resolve against the locals captured by var-init.
    for (export, local) in &r.pending {
        if let Some(data) = r.locals.get(local) {
            r.exports
                .entry(export.clone())
                .or_insert_with(|| data.clone());
        }
    }
    let (value_kind, variants) = r.exports.get(name)?.clone();
    Some(InternalEnumDef {
        name: name.to_string(),
        module: module.to_string(),
        value_kind,
        variants,
    })
}

/// An enum-body object: either `$InternalEnum({…})` or a bare object literal.
fn enum_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    internal_enum_object(e).or_else(|| as_object(e))
}

/// Whether `name` is `CONSTANT_CASE` (`[A-Z][A-Z0-9_]*`) — the member-name shape WA
/// uses for its plain-object wire enums (`INACTIVE`, `READ_SELF`, `CONTENT_TOO_BIG`),
/// as opposed to the `camelCase` keys of config/lookup maps.
fn is_constant_case(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `module` is one WA declares its *wire-protocol* enums in as plain object
/// literals (no `$InternalEnum`): the `WASmax<In|Out>…Enums` smax enum bags, plus the
/// two ack/receipt-level modules that predate that convention. Deliberately narrow —
/// the app has thousands of `CONSTANT_CASE` infra objects (loggers, locales, JPEG
/// markers, UI constants) that are not part of the protocol surface.
fn is_protocol_enum_module(module: &str) -> bool {
    (module.starts_with("WASmax") && module.ends_with("Enums"))
        || module == "WAWebAck"
        || module == "WAAckLevel"
}

/// Extract plain-object-literal enums exported by name from a non-`$InternalEnum`
/// module (`i.ACK = {INACTIVE:-6,…}` or `var e={…}; i.ACK=e`). Kept deliberately strict
/// — only exports with ≥2 members, all-literal single-kind values ([`parse_enum`]), and
/// all-`CONSTANT_CASE` member names — so config/lookup maps don't leak into the catalog.
fn extract_plain_object_enums(slice: &str, module: &str) -> Vec<InternalEnumDef> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    if ret.panicked {
        return Vec::new();
    }
    let mut r = NamedResolver {
        locals: HashMap::new(),
        exports: HashMap::new(),
        pending: Vec::new(),
    };
    r.visit_program(&ret.program);
    for (export, local) in &r.pending {
        if let Some(data) = r.locals.get(local) {
            r.exports
                .entry(export.clone())
                .or_insert_with(|| data.clone());
        }
    }
    let mut out: Vec<InternalEnumDef> = Vec::new();
    for (name, (value_kind, variants)) in r.exports {
        if variants.len() >= 2 && variants.iter().all(|v| is_constant_case(&v.name)) {
            out.push(InternalEnumDef {
                name,
                module: module.to_string(),
                value_kind,
                variants,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

struct NamedResolver {
    locals: HashMap<String, EnumData>,
    exports: HashMap<String, EnumData>,
    pending: Vec<(String, String)>,
}

impl<'a> Visit<'a> for NamedResolver {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(local) = d.id.get_identifier_name()
            && let Some(obj) = d.init.as_ref().and_then(enum_object)
            && let Some(data) = parse_enum(obj)
        {
            self.locals.insert(local.to_string(), data);
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        if let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            if let Some(data) = enum_object(&a.right).and_then(parse_enum) {
                self.exports.entry(prop.to_string()).or_insert(data);
            } else if prop == "exports"
                && let Some(o) = as_object(&a.right)
            {
                // `X.exports = { Name: <enum|local>, … }` — a named export bag; index
                // each member so an enum published this way still resolves.
                for (key, value) in wa_oxc::obj_props(o) {
                    if let Some(data) = enum_object(value).and_then(parse_enum) {
                        self.exports.entry(key.to_string()).or_insert(data);
                    } else if let Some(id) = as_identifier(value) {
                        self.pending.push((key.to_string(), id.to_string()));
                    }
                }
            } else if let Some(id) = as_identifier(&a.right) {
                self.pending.push((prop.to_string(), id.to_string()));
            }
        }
        walk::walk_assignment_expression(self, a);
    }
}

struct Collector<'m> {
    module: &'m str,
    /// `var local = $InternalEnum(...)` → its parsed body.
    locals: HashMap<String, EnumData>,
    /// Inline-named definitions (`obj.Name = $InternalEnum(...)`).
    named: Vec<(String, EnumData)>,
    /// `obj.Name = localIdent` — resolved against `locals` after the walk.
    pending: Vec<(String, String)>,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let (Some(name), Some(obj)) = (
            d.id.get_identifier_name(),
            d.init.as_ref().and_then(internal_enum_object),
        ) && let Some(data) = parse_enum(obj)
        {
            self.locals.insert(name.to_string(), data);
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        if let Some(m) = a.left.as_member_expression()
            && let Some(prop) = m.static_property_name()
        {
            // `obj.exports = …` is the module's default export → name by module.
            let export_name = if prop == "exports" {
                self.module.to_string()
            } else {
                prop.to_string()
            };
            if let Some(obj) = internal_enum_object(&a.right) {
                if let Some(data) = parse_enum(obj) {
                    self.named.push((export_name, data));
                }
            } else if let Some(id) = as_identifier(&a.right) {
                self.pending.push((export_name, id.to_string()));
            } else if prop == "exports" {
                // `obj.exports = { Name: <enum|local>, … }` — a named bag.
                if let Some(o) = as_object(&a.right) {
                    self.collect_export_bag(o);
                }
            }
        }
        walk::walk_assignment_expression(self, a);
    }
}

impl Collector<'_> {
    fn collect_export_bag(&mut self, o: &ObjectExpression) {
        for (key, value) in wa_oxc::obj_props(o) {
            if let Some(obj) = internal_enum_object(value) {
                if let Some(data) = parse_enum(obj) {
                    self.named.push((key.to_string(), data));
                }
            } else if let Some(id) = as_identifier(value) {
                self.pending.push((key.to_string(), id.to_string()));
            }
        }
    }
}

/// If `e` is `<require>("$InternalEnum")({ … })`, the argument object literal.
fn internal_enum_object<'b, 'a>(e: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    let outer = as_call(e)?;
    let inner = as_call(&outer.callee)?;
    if first_string_arg(inner) != Some(DEP) {
        return None;
    }
    as_object(arg_expr(outer.arguments.first()?)?)
}

/// Parse the enum body. Returns `None` for spread/computed keys, non-literal
/// values, or mixed int/string value kinds.
fn parse_enum(obj: &ObjectExpression) -> Option<EnumData> {
    let mut kind: Option<EnumValueKind> = None;
    let mut variants = Vec::new();
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            return None;
        };
        let name = property_key_name(&p.key)?;
        let (k, value) = match &p.value {
            Expression::StringLiteral(s) => {
                (EnumValueKind::String, Scalar::Str(s.value.to_string()))
            }
            other => (EnumValueKind::Int, Scalar::Int(wa_oxc::as_int(other)?)),
        };
        match kind {
            None => kind = Some(k),
            Some(prev) if prev != k => return None, // mixed → skip enum
            _ => {}
        }
        variants.push(EnumVariant {
            name: name.to_string(),
            value,
        });
    }
    match kind {
        Some(k) if !variants.is_empty() => Some((k, variants)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<InternalEnumDef> {
        let defs = wa_transform::extract_module_definitions(src);
        extract_enums_from_modules(src, &defs, "1.0").enums
    }

    #[test]
    fn resolve_named_enum_handles_object_literal_and_internal_and_bag() {
        // Plain object-literal export (`var l = {...}; i.Name = l`).
        let obj = r#"__d("M",[],(function(g,r,d,o,e,i,l){ var s={PN:"pn",LID:"lid"}; i.USYNC_ADDRESSING_MODE=s; }),1);"#;
        let r = resolve_named_enum(obj, "M", "USYNC_ADDRESSING_MODE").expect("object-literal");
        assert_eq!(
            r.variants
                .iter()
                .map(|v| v.value.clone())
                .collect::<Vec<_>>(),
            [Scalar::Str("pn".into()), Scalar::Str("lid".into())]
        );
        // `$InternalEnum` export.
        let ie = r#"__d("M",["$InternalEnum"],(function(g,n,d,o,e,i,l){ i.CiphertextType=n("$InternalEnum")({Skmsg:"skmsg",Pkmsg:"pkmsg"}); }),1);"#;
        assert_eq!(
            resolve_named_enum(ie, "M", "CiphertextType")
                .unwrap()
                .variants
                .len(),
            2
        );
        // Named export bag (`i.exports = { Name: <enum> }`).
        let bag = r#"__d("M",["$InternalEnum"],(function(g,n,d,o,e,i,l){ i.exports={Scope:n("$InternalEnum")({A:"a",B:"b"})}; }),1);"#;
        assert_eq!(
            resolve_named_enum(bag, "M", "Scope")
                .unwrap()
                .variants
                .len(),
            2
        );
        // A name that isn't an enum export resolves to nothing.
        assert!(resolve_named_enum(obj, "M", "Nope").is_none());
    }

    #[test]
    fn string_and_int_enums_named_by_export() {
        let src = r#"__d("WAWebChatType",["$InternalEnum"],function(g,r,d,o,e,i,l){
            var t=r("$InternalEnum")({INDIVIDUAL:"individual",GROUP:"group",NEWSLETTER:"newsletter"});
            l.ChatType=t;
            l.Codes=r("$InternalEnum")({A:1,B:2,C:3});
        },1);"#;
        let enums = run(src);
        let chat = enums
            .iter()
            .find(|e| e.name == "ChatType")
            .expect("ChatType");
        assert_eq!(chat.value_kind, EnumValueKind::String);
        assert_eq!(chat.variants.len(), 3);
        assert_eq!(chat.variants[0].name, "INDIVIDUAL");
        assert_eq!(chat.variants[0].value, Scalar::Str("individual".into()));
        let codes = enums.iter().find(|e| e.name == "Codes").expect("Codes");
        assert_eq!(codes.value_kind, EnumValueKind::Int);
        assert_eq!(codes.variants[1].value, Scalar::Int(2));
    }

    #[test]
    fn default_export_named_by_module_and_mixed_skipped() {
        let src = r#"__d("WAWebNackCode",["$InternalEnum"],function(g,r,d,o,e,i,l){
            e.exports=r("$InternalEnum")({Stale:421,Capped:475});
        },1);
        __d("WAWebMixed",["$InternalEnum"],function(g,r,d,o,e,i,l){
            l.Bad=r("$InternalEnum")({A:1,B:"two"});
        },2);"#;
        let enums = run(src);
        let nack = enums
            .iter()
            .find(|e| e.module == "WAWebNackCode")
            .expect("nack");
        assert_eq!(nack.name, "WAWebNackCode"); // default export → module name
        assert_eq!(nack.variants[0].value, Scalar::Int(421));
        // Mixed-value enum is skipped entirely.
        assert!(enums.iter().all(|e| e.module != "WAWebMixed"));
    }

    #[test]
    fn module_without_dep_is_ignored() {
        // Contains the call text but doesn't declare the dep → not scanned.
        let src = r#"__d("Nope",[],function(g,r,d,o,e,i,l){ l.X=r("$InternalEnum")({A:1}); },1);"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn plain_object_wire_enums_captured_only_from_protocol_modules() {
        // WA's ack/receipt level enums and smax `*Enums` bags are plain object literals
        // with no `$InternalEnum` dep — captured via the protocol-module convention.
        let src = r#"
            __d("WAWebAck",[],(function(t,n,r,o,a,i){var e={INACTIVE:-6,SENT:1,READ:3};i.ACK=e}),1);
            __d("WASmaxInReceiptEnums",["WAJids"],(function(t,n,r,o,a,i,l){var e={CBP:"cbp",NBP:"nbp"};i.ENUM_CBP_NBP=e}),1);
        "#;
        let enums = run(src);
        let ack = enums
            .iter()
            .find(|e| e.module == "WAWebAck")
            .expect("WAWebAck.ACK");
        assert_eq!(ack.name, "ACK");
        assert_eq!(ack.value_kind, EnumValueKind::Int);
        assert_eq!(ack.variants.len(), 3);
        assert!(
            enums
                .iter()
                .any(|e| e.module == "WASmaxInReceiptEnums" && e.name == "ENUM_CBP_NBP")
        );
    }

    #[test]
    fn plain_object_non_protocol_and_camelcase_are_not_enums() {
        // Same plain-object shape, but a non-protocol infra module → not scanned
        // (would otherwise flood the catalog with loggers/locales/UI constants).
        let infra = r#"__d("WAWebLog",[],(function(t,n,r,o,a,i){var e={DEBUG:0,INFO:1,ERROR:2};i.Level=e}),1);"#;
        assert!(run(infra).iter().all(|e| e.module != "WAWebLog"));
        // A protocol module, but a `camelCase`-keyed (non-enum) map is still rejected by
        // the CONSTANT_CASE guard.
        let cfg = r#"__d("WASmaxInFooEnums",[],(function(t,n,r,o,a,i){var e={maxRetries:3,timeoutMs:5};i.config=e}),1);"#;
        assert!(run(cfg).iter().all(|e| e.module != "WASmaxInFooEnums"));
    }
}
