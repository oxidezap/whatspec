//! Extract WhatsApp protobuf specs from a bundle. Per-module `Visit` passes
//! capture owned descriptors; a final resolution pass wires cross-module type
//! references and `$`-nesting into a [`ProtoFile`].

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpression, AssignmentExpression, BinaryExpression, BinaryOperator, Expression,
    ObjectExpression, ObjectPropertyKind, UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{
    ProtoEntity, ProtoEnum, ProtoEnumValue, ProtoField, ProtoFile, ProtoMember, ProtoMessage,
    ProtoOneOf,
};
use wa_oxc::{
    arg_expr, as_call, as_identifier, as_int, as_string_lit, assignment_target_name,
    property_key_name,
};
use wa_transform::ModuleDefinition;

// ─── Wire vocabulary ──────────────────────────────────────────────────────────

/// One spec type is split across two declarations; this rejoins it pre-parse.
const SPLIT_DECL_FROM: &str = "LimitSharing$Trigger";
const SPLIT_DECL_TO: &str = "LimitSharing$TriggerType";

/// Identifier suffix that marks a message/enum spec export (`FooSpec`).
const SPEC_SUFFIX: &str = "Spec";
/// Nested-name separator inside spec identifiers (`Message$ContextInfo`).
const NESTING_SEP: char = '$';

/// Exported member props that are NOT message/enum identifiers.
const PROP_INTERNAL_SPEC: &str = "internalSpec";
const PROP_INTERNAL_DEFAULTS: &str = "internalDefaults";
const PROP_NAME: &str = "name";

/// Constraint keys inside an `internalSpec` object are `__`-prefixed.
const CONSTRAINT_PREFIX: &str = "__";
const KEY_ONEOFS: &str = "__oneofs__";

/// Special module providing enum construction; never a real cross-reference type.
const INTERNAL_ENUM_MODULE: &str = "$InternalEnum";

/// Member-array type/flag namespaces: `X.TYPES.UINT32`, `X.FLAGS.REPEATED`.
const NS_TYPES: &str = "TYPES";
const NS_FLAGS: &str = "FLAGS";

/// Field type keywords (lowercased `TYPES.*`).
const TYPE_MESSAGE: &str = "message";
const TYPE_ENUM: &str = "enum";
const TYPE_MAP: &str = "map";
/// `elements[1]` property name signalling an enum field.
const ENUM_TYPE_PROP: &str = "ENUM";
/// Suffix on enum spec names used to disambiguate enum cross-refs.
const TYPE_SUFFIX: &str = "Type";

const FLAG_PACKED: &str = "packed";
const FLAG_OPTIONAL: &str = "optional";
const FLAG_REPEATED: &str = "repeated";

// ─── Name helpers ─────────────────────────────────────────────────────────────

/// `FooSpec` → `Foo` (borrowing when there is no suffix to strip).
fn rename(name: &str) -> &str {
    name.strip_suffix(SPEC_SUFFIX).unwrap_or(name)
}

/// `A$B$C` → `C`.
fn unnest(name: &str) -> &str {
    name.rsplit(NESTING_SEP).next().unwrap_or(name)
}

/// `A$B$C` → `A$B` (the parent path).
fn get_nesting(name: &str) -> &str {
    match name.rfind(NESTING_SEP) {
        Some(i) => &name[..i],
        None => "",
    }
}

// ─── Intermediate model ───────────────────────────────────────────────────────

/// Deferred type reference, resolved after all modules are scanned.
enum TypeDesc {
    Scalar(String),
    Map(Box<TypeDesc>, Box<TypeDesc>),
    /// `elements[2]` was an identifier → look up this module's idents by alias.
    IdentAlias(String),
    /// `elements[2]` was a member expression → cross-module / nested reference.
    MemberRef {
        elem1_is_enum: bool,
        obj: Option<String>,
        prop: String,
    },
    Unresolved,
}

struct FieldDesc {
    name: String,
    id: i64,
    ty: TypeDesc,
    flags: Vec<String>,
}

enum MemberDesc {
    Field(FieldDesc),
    OneOf {
        name: String,
        fields: Vec<FieldDesc>,
    },
}

#[derive(Default)]
struct Ident {
    name: String,
    alias: Option<String>,
    enum_values: Option<Vec<ProtoEnumValue>>,
    members: Option<Vec<MemberDesc>>,
    /// field name → proto2 default token, from `X.internalDefaults = {...}`.
    defaults: HashMap<String, String>,
}

#[derive(Default)]
struct ModuleInfo {
    cross_refs: Vec<(String, String)>, // (alias, module)
    identifiers: HashMap<String, Ident>,
    /// `(target_alias, members)` captured from `X.internalSpec = {...}`.
    specs: Vec<(String, Vec<MemberDesc>)>,
    /// `(target_alias, field→default)` captured from `X.internalDefaults = {...}`.
    defaults: Vec<(String, HashMap<String, String>)>,
    enum_aliases: HashMap<String, Vec<ProtoEnumValue>>,
    alias_matches: Vec<(String, String)>, // (renamed key, alias)
    ident_order: Vec<String>,
}

#[derive(Default)]
struct Indent {
    indentation: String,
    members: BTreeSet<String>,
}

// ─── Public entry ─────────────────────────────────────────────────────────────

/// Extract a [`ProtoFile`] from a bundle's source.
pub fn extract_proto(bundle_source: &str, wa_version: &str) -> ProtoFile {
    let module_defs = wa_transform::extract_module_definitions(bundle_source);
    extract_proto_from_modules(bundle_source, &module_defs, wa_version)
}

/// Extract a [`ProtoFile`] from an already-split module index (shares one
/// whole-bundle parse with the other extractors; only proto module slices are
/// re-parsed here).
pub fn extract_proto_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> ProtoFile {
    let mut modules: HashMap<String, ModuleInfo> = HashMap::new();
    let mut indent_map: HashMap<String, Indent> = HashMap::new();

    for def in module_defs {
        let slice = &source[def.start..def.end];
        if !slice.contains(PROP_INTERNAL_SPEC) {
            continue;
        }
        // One spec type is split across two declarations; rejoin it before
        // parsing. The split only ever occurs inside a proto module, so patching
        // the slice is equivalent to the old whole-bundle replace, without the
        // ~71MB clone.
        let patched: Cow<str> = if slice.contains(SPLIT_DECL_FROM) {
            Cow::Owned(slice.replace(SPLIT_DECL_FROM, SPLIT_DECL_TO))
        } else {
            Cow::Borrowed(slice)
        };

        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, &patched);

        let mut info = ModuleInfo::default();

        let mut cross = CrossRefCollector { refs: Vec::new() };
        cross.visit_program(&ret.program);
        info.cross_refs = cross.refs;

        let mut idents = IdentCollector { names: Vec::new() };
        idents.visit_program(&ret.program);
        info.ident_order = idents.names;

        let mut enums = EnumAliasCollector {
            aliases: HashMap::new(),
        };
        enums.visit_program(&ret.program);
        info.enum_aliases = enums.aliases;

        let mut am = AliasMatchCollector {
            matches: Vec::new(),
        };
        am.visit_program(&ret.program);
        info.alias_matches = am.matches;

        let mut contents = ContentsCollector { specs: Vec::new() };
        contents.visit_program(&ret.program);
        info.specs = contents.specs;

        let mut defaults = DefaultsCollector {
            defaults: Vec::new(),
        };
        defaults.visit_program(&ret.program);
        info.defaults = defaults.defaults;

        modules.insert(def.name.clone(), info);
    }

    // Build blank identifiers (reversed: first declaration wins) + nesting map.
    for info in modules.values_mut() {
        for key in info.ident_order.iter().rev() {
            let indentation = get_nesting(key).to_string();
            indent_map.entry(key.clone()).or_default().indentation = indentation.clone();
            if !indentation.is_empty() {
                indent_map
                    .entry(indentation.clone())
                    .or_default()
                    .members
                    .insert(key.clone());
            }
            info.identifiers
                .entry(key.clone())
                .or_insert_with(|| Ident {
                    name: key.clone(),
                    ..Default::default()
                });
        }
    }

    // Match aliases → identifiers, attach enum values.
    for info in modules.values_mut() {
        let aliases = std::mem::take(&mut info.alias_matches);
        let enum_aliases = std::mem::take(&mut info.enum_aliases);
        for (key, alias) in aliases {
            if let Some(ident) = info.identifiers.get_mut(&key) {
                ident.alias = Some(alias.clone());
                ident.enum_values = enum_aliases.get(&alias).cloned();
            }
        }
    }

    // Attach message members to their target identifier (by alias).
    for info in modules.values_mut() {
        let specs = std::mem::take(&mut info.specs);
        for (target_alias, members) in specs {
            if let Some(key) = info
                .identifiers
                .iter()
                .find(|(_, v)| v.alias.as_deref() == Some(target_alias.as_str()))
                .map(|(k, _)| k.clone())
            {
                info.identifiers.get_mut(&key).unwrap().members = Some(members);
            }
        }
    }

    // Attach proto2 field defaults to their target identifier (same alias match).
    for info in modules.values_mut() {
        let defaults = std::mem::take(&mut info.defaults);
        for (target_alias, map) in defaults {
            if let Some(key) = info
                .identifiers
                .iter()
                .find(|(_, v)| v.alias.as_deref() == Some(target_alias.as_str()))
                .map(|(k, _)| k.clone())
            {
                info.identifiers.get_mut(&key).unwrap().defaults = map;
            }
        }
    }

    // Resolve into the proto entity tree.
    let mut entities: Vec<ProtoEntity> = Vec::new();
    for info in modules.values() {
        for ident in info.identifiers.values() {
            let is_top_level = indent_map
                .get(&ident.name)
                .map(|i| i.indentation.is_empty())
                .unwrap_or(true);
            if is_top_level
                && let Some(entity) = build_entity(ident, &ident.name, info, &modules, &indent_map)
            {
                entities.push(entity);
            }
        }
    }

    ProtoFile {
        wa_version: wa_version.to_string(),
        entities: make_protoc_valid(entities),
    }
}

// ─── protoc-validity post-processing ──────────────────────────────────────────

/// Reconcile the resolved tree with `protoc`'s C++ enum scoping.
///
/// WhatsApp's runtime is protobuf.js, which scopes enum values *per enum*, so the
/// bundle happily declares two top-level enums sharing a value name (e.g.
/// `ADVEncryptionType` and `HostedState` both with `E2EE`/`HOSTED`). `protoc`
/// instead treats enum values as siblings of the enum's *container*, so two such
/// top-level enums collide at package scope. The bundle also re-exports common
/// types from several modules (a legacy `WAFingerprint.pb` + a
/// `WAWebProtobufsFingerprintV3.pb` variant, …), surfacing the same type twice.
/// Neither survives `protoc`. This pass:
///   1. drops duplicate top-level entities (keeps one), and
///   2. relocates a colliding top-level enum *into* the message that references
///      it, scoping its values out of the package namespace.
fn make_protoc_valid(entities: Vec<ProtoEntity>) -> Vec<ProtoEntity> {
    relocate_colliding_enums(dedup_top_level(entities))
}

/// Keep one entity per top-level name. Duplicates are byte-identical in practice
/// (the same spec exported by two modules); sorting by `(name, debug)` makes the
/// survivor deterministic even if two same-named entities ever diverged, since the
/// source `modules` map iterates in a nondeterministic order.
fn dedup_top_level(mut entities: Vec<ProtoEntity>) -> Vec<ProtoEntity> {
    entities.sort_by(|a, b| {
        a.name()
            .cmp(b.name())
            .then_with(|| format!("{a:?}").cmp(&format!("{b:?}")))
    });
    let mut out: Vec<ProtoEntity> = Vec::with_capacity(entities.len());
    for e in entities {
        if out.last().map(ProtoEntity::name) != Some(e.name()) {
            out.push(e);
        }
    }
    out
}

/// Move any top-level enum whose value names clash with another top-level enum's
/// under the message that references it. In each clash component the most-
/// referenced enum stays at package scope (it is the hardest to re-home cleanly);
/// the rest are nested into a referencing message, which scopes their values away.
fn relocate_colliding_enums(mut entities: Vec<ProtoEntity>) -> Vec<ProtoEntity> {
    // value name -> top-level enums declaring it.
    let mut owners: HashMap<String, BTreeSet<String>> = HashMap::new();
    for e in &entities {
        if let ProtoEntity::Enum(en) = e {
            for v in &en.values {
                owners
                    .entry(v.name.clone())
                    .or_default()
                    .insert(en.name.clone());
            }
        }
    }
    // Adjacency among enums that share at least one value name.
    let mut adj: HashMap<String, BTreeSet<String>> = HashMap::new();
    for set in owners.values().filter(|s| s.len() > 1) {
        for a in set {
            for b in set.iter().filter(|b| *b != a) {
                adj.entry(a.clone()).or_default().insert(b.clone());
            }
        }
    }
    if adj.is_empty() {
        return entities;
    }

    let refs = referencers(&entities);
    let ref_count = |name: &str| refs.get(name).map(BTreeSet::len).unwrap_or(0);

    // Walk clash components; pick a keeper, schedule the rest for relocation.
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut decisions: Vec<(String, String)> = Vec::new(); // (enum, host message)
    let mut prefix_only: Vec<String> = Vec::new(); // colliding but no referencer
    for start in adj.keys().cloned().collect::<BTreeSet<String>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut comp: BTreeSet<String> = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(n) = stack.pop() {
            if !visited.insert(n.clone()) {
                continue;
            }
            comp.insert(n.clone());
            for m in adj.get(&n).into_iter().flatten() {
                if !visited.contains(m) {
                    stack.push(m.clone());
                }
            }
        }
        // Keeper: most referencers; tie broken by smallest name (deterministic).
        let keeper = comp
            .iter()
            .max_by(|a, b| ref_count(a).cmp(&ref_count(b)).then_with(|| b.cmp(a)))
            .cloned()
            .expect("component is non-empty");
        for en in comp.iter().filter(|e| **e != keeper) {
            match refs.get(en).and_then(|hosts| hosts.iter().next()) {
                Some(host) => decisions.push((en.clone(), host.clone())),
                None => prefix_only.push(en.clone()),
            }
        }
    }

    let relocated: BTreeSet<String> = decisions.iter().map(|(e, _)| e.clone()).collect();

    // Pull the relocated enums out of the top level.
    let mut taken: HashMap<String, ProtoEntity> = HashMap::new();
    entities.retain(|e| {
        if matches!(e, ProtoEntity::Enum(_)) && relocated.contains(e.name()) {
            taken.insert(e.name().to_string(), e.clone());
            false
        } else {
            true
        }
    });

    // Defensive fallback for an unreferenced colliding enum (cannot be nested):
    // prefix its values so they no longer clash at package scope. Does not occur
    // in current bundles, but keeps the output protoc-valid unconditionally.
    for e in &mut entities {
        if let ProtoEntity::Enum(en) = e
            && prefix_only.contains(&en.name)
        {
            let prefix = en.name.clone();
            for v in &mut en.values {
                v.name = format!("{prefix}_{}", v.name);
            }
        }
    }

    // An enum referenced by *several* top-level messages can still be relocated,
    // but references from outside its new home must then be fully qualified.
    let qualified: HashMap<String, String> = decisions
        .iter()
        .filter(|(en, _)| ref_count(en) > 1)
        .map(|(en, host)| (en.clone(), format!("{host}.{en}")))
        .collect();
    if !qualified.is_empty() {
        for e in &mut entities {
            if let ProtoEntity::Message(m) = e {
                rewrite_refs(m, &qualified);
            }
        }
    }

    // Nest each relocated enum under its host (host-grouped, sorted by name).
    let mut by_host: BTreeMap<String, Vec<ProtoEntity>> = BTreeMap::new();
    for (en, host) in &decisions {
        if let Some(ent) = taken.remove(en) {
            by_host.entry(host.clone()).or_default().push(ent);
        }
    }
    for e in &mut entities {
        if let ProtoEntity::Message(m) = e
            && let Some(mut adds) = by_host.remove(&m.name)
        {
            adds.sort_by(|a, b| a.name().cmp(b.name()));
            m.nested.extend(adds);
        }
    }
    // A host should always be found above; re-home any leftover at top level
    // rather than silently dropping it.
    for adds in by_host.into_values() {
        entities.extend(adds);
    }

    entities
}

/// Map each top-level message to the type names referenced anywhere in its
/// subtree (fields, `oneof` fields, and nested messages).
fn referencers(entities: &[ProtoEntity]) -> HashMap<String, BTreeSet<String>> {
    let mut map: HashMap<String, BTreeSet<String>> = HashMap::new();
    for e in entities {
        if let ProtoEntity::Message(m) = e {
            let mut refs = BTreeSet::new();
            collect_refs(m, &mut refs);
            for r in refs {
                map.entry(r).or_default().insert(m.name.clone());
            }
        }
    }
    map
}

fn collect_refs(m: &ProtoMessage, out: &mut BTreeSet<String>) {
    for mem in &m.members {
        match mem {
            ProtoMember::Field(f) => {
                for b in type_ref_bases(&f.type_name) {
                    out.insert(b.to_string());
                }
            }
            ProtoMember::OneOf(o) => {
                for f in &o.fields {
                    for b in type_ref_bases(&f.type_name) {
                        out.insert(b.to_string());
                    }
                }
            }
        }
    }
    for n in &m.nested {
        if let ProtoEntity::Message(nm) = n {
            collect_refs(nm, out);
        }
    }
}

/// Base (unqualified) type name(s) of a printed field type: the trailing segment
/// of a dotted path, or both sides of a `map<K, V>`.
fn type_ref_bases(type_name: &str) -> Vec<&str> {
    /// Trailing segment of a dotted path (`A.B.C` → `C`), trimmed.
    fn base(t: &str) -> &str {
        let t = t.trim();
        t.rsplit('.').next().unwrap_or(t)
    }
    match type_name
        .strip_prefix("map<")
        .and_then(|s| s.strip_suffix('>'))
    {
        Some(inner) => inner.split(',').map(base).collect(),
        None => vec![base(type_name)],
    }
}

/// Rewrite field types referencing a relocated enum to their qualified form.
fn rewrite_refs(m: &mut ProtoMessage, map: &HashMap<String, String>) {
    for mem in &mut m.members {
        match mem {
            ProtoMember::Field(f) => rewrite_type(&mut f.type_name, map),
            ProtoMember::OneOf(o) => {
                for f in &mut o.fields {
                    rewrite_type(&mut f.type_name, map);
                }
            }
        }
    }
    for n in &mut m.nested {
        if let ProtoEntity::Message(nm) = n {
            rewrite_refs(nm, map);
        }
    }
}

fn rewrite_type(type_name: &mut String, map: &HashMap<String, String>) {
    if let Some(repl) = map.get(type_name.as_str()) {
        *type_name = repl.clone();
        return;
    }
    if let Some(inner) = type_name
        .strip_prefix("map<")
        .and_then(|s| s.strip_suffix('>'))
    {
        let parts: Vec<String> = inner
            .split(',')
            .map(|p| {
                let t = p.trim();
                map.get(t).cloned().unwrap_or_else(|| t.to_string())
            })
            .collect();
        *type_name = format!("map<{}>", parts.join(", "));
    }
}

// ─── Resolution ───────────────────────────────────────────────────────────────

fn build_entity(
    ident: &Ident,
    display_name: &str,
    info: &ModuleInfo,
    modules: &HashMap<String, ModuleInfo>,
    indent_map: &HashMap<String, Indent>,
) -> Option<ProtoEntity> {
    if let Some(members) = &ident.members {
        // A message. Resolve members, then attach nested children (sorted).
        let proto_members = members
            .iter()
            .map(|m| resolve_member(m, &ident.name, &ident.defaults, info, modules, indent_map))
            .collect();

        let mut nested = Vec::new();
        if let Some(indent) = indent_map.get(&ident.name) {
            for child_key in &indent.members {
                if let Some(child) = info.identifiers.get(child_key) {
                    let child_display = child_key
                        .strip_prefix(&format!("{}$", ident.name))
                        .unwrap_or(unnest(child_key));
                    if let Some(e) = build_entity(child, child_display, info, modules, indent_map) {
                        nested.push(e);
                    }
                }
            }
        }

        Some(ProtoEntity::Message(ProtoMessage {
            name: display_name.to_string(),
            members: proto_members,
            nested,
        }))
    } else {
        ident.enum_values.as_ref().map(|values| {
            ProtoEntity::Enum(ProtoEnum {
                name: display_name.to_string(),
                values: values.clone(),
            })
        })
    }
}

fn resolve_member(
    m: &MemberDesc,
    parent_name: &str,
    defaults: &HashMap<String, String>,
    info: &ModuleInfo,
    modules: &HashMap<String, ModuleInfo>,
    indent_map: &HashMap<String, Indent>,
) -> ProtoMember {
    match m {
        MemberDesc::OneOf { name, fields } => {
            // oneof fields carry no auto-`optional` and no parent context, so
            // nested types are always fully qualified. proto2 forbids defaults on
            // oneof fields, so pass an empty map (also enforced by `message_member`).
            let fields = fields
                .iter()
                .map(|f| build_field(f, None, false, &HashMap::new(), info, modules, indent_map))
                .collect();
            ProtoMember::OneOf(ProtoOneOf {
                name: name.clone(),
                fields,
            })
        }
        MemberDesc::Field(f) => ProtoMember::Field(build_field(
            f,
            Some(parent_name),
            true,
            defaults,
            info,
            modules,
            indent_map,
        )),
    }
}

fn build_field(
    f: &FieldDesc,
    parent_name: Option<&str>,
    message_member: bool,
    defaults: &HashMap<String, String>,
    info: &ModuleInfo,
    modules: &HashMap<String, ModuleInfo>,
    indent_map: &HashMap<String, Indent>,
) -> ProtoField {
    let resolved_type = resolve_type(&f.ty, info, modules);
    let type_name = qualify_type(&resolved_type, parent_name, indent_map);

    let mut flags = f.flags.clone();
    // `packed` is a wire encoding hint, not a label: lift it out wherever it sits
    // and keep the remaining flags (e.g. `repeated`) in order — truncating from
    // `packed` would drop `repeated` if it ever appeared after it.
    let packed = flags.iter().any(|fl| fl == FLAG_PACKED);
    flags.retain(|fl| fl != FLAG_PACKED);
    if message_member && flags.is_empty() && !type_name.contains(TYPE_MAP) {
        flags.push(FLAG_OPTIONAL.to_string());
    }

    // A proto2 default applies only to a singular scalar/enum/message field — never a
    // oneof member (`message_member` is false there), a `repeated` field, or a `map`
    // (protoc rejects a default on the latter two). All of WA's `internalDefaults`
    // target singular optional fields; the guards keep a future stray one valid.
    let default = (message_member
        && !flags.iter().any(|fl| fl == FLAG_REPEATED)
        && !type_name.contains(TYPE_MAP))
    .then(|| defaults.get(&f.name).cloned())
    .flatten();

    ProtoField {
        name: f.name.clone(),
        id: f.id,
        type_name,
        flags,
        packed,
        default,
    }
}

fn resolve_type(ty: &TypeDesc, info: &ModuleInfo, modules: &HashMap<String, ModuleInfo>) -> String {
    match ty {
        TypeDesc::Scalar(s) => s.clone(),
        TypeDesc::Map(k, v) => format!(
            "map<{}, {}>",
            resolve_type(k, info, modules),
            resolve_type(v, info, modules)
        ),
        TypeDesc::IdentAlias(alias) => info
            .identifiers
            .values()
            .find(|v| v.alias.as_deref() == Some(alias.as_str()))
            .map(|v| v.name.clone())
            .unwrap_or_else(|| alias.clone()),
        TypeDesc::MemberRef {
            elem1_is_enum,
            obj,
            prop,
        } => {
            if (*elem1_is_enum && prop.contains(TYPE_SUFFIX)) || prop.contains(SPEC_SUFFIX) {
                rename(prop).to_string()
            } else {
                // Cross-module reference: match the cross-ref by exact alias.
                let key = rename(prop);
                let cross = info
                    .cross_refs
                    .iter()
                    .find(|(alias, _)| Some(alias.as_str()) == obj.as_deref());
                if let Some((_, module)) = cross
                    && module != INTERNAL_ENUM_MODULE
                    && modules
                        .get(module)
                        .is_some_and(|m| m.identifiers.contains_key(key))
                {
                    return key.to_string();
                }
                key.to_string()
            }
        }
        TypeDesc::Unresolved => "/*unresolved*/".to_string(),
    }
}

/// Apply `$`-nesting: unnest the type name and, if it lives under a different
/// parent than the current message, qualify it with a dotted path.
fn qualify_type(
    type_name: &str,
    parent_name: Option<&str>,
    indent_map: &HashMap<String, Indent>,
) -> String {
    let base = unnest(type_name).to_string();
    if let Some(indent) = indent_map.get(type_name)
        && !indent.indentation.is_empty()
        && Some(indent.indentation.as_str()) != parent_name
    {
        return format!("{}.{}", indent.indentation.replace(NESTING_SEP, "."), base);
    }
    base
}

// ─── Collectors ───────────────────────────────────────────────────────────────

struct CrossRefCollector {
    refs: Vec<(String, String)>,
}
impl<'a> Visit<'a> for CrossRefCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(call) = as_call(&n.right)
            && call.arguments.len() == 1
            && let Some(arg0) = arg_expr(&call.arguments[0])
            && !matches!(arg0, Expression::ObjectExpression(_))
            && let (Some(alias), Some(module)) =
                (assignment_target_name(&n.left), as_string_lit(arg0))
        {
            self.refs.push((alias.to_string(), module.to_string()));
        }
        walk::walk_assignment_expression(self, n);
    }
}

struct IdentCollector {
    names: Vec<String>,
}
impl<'a> Visit<'a> for IdentCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(prop) = n
            .left
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            && prop != PROP_INTERNAL_SPEC
            && prop != PROP_INTERNAL_DEFAULTS
            && prop != PROP_NAME
        {
            self.names.push(rename(prop).to_string());
        }
        walk::walk_assignment_expression(self, n);
    }
}

struct EnumAliasCollector {
    aliases: HashMap<String, Vec<ProtoEnumValue>>,
}
impl EnumAliasCollector {
    /// Enum defined as `X = someCall({A:0, B:1})` (e.g. `$InternalEnum(...)`).
    fn record_call(&mut self, name_alias: &str, init: &Expression) {
        if let Some(call) = as_call(init)
            && let Some(Expression::ObjectExpression(obj)) =
                call.arguments.first().and_then(arg_expr)
        {
            let values = enum_values_from_obj(obj);
            if !values.is_empty() {
                self.aliases.insert(name_alias.to_string(), values);
            }
        }
    }

    /// Enum defined as a direct literal `var X = {A:0, B:1}`.
    fn record_object_literal(&mut self, name_alias: &str, init: &Expression) {
        if let Expression::ObjectExpression(obj) = init {
            let values = enum_values_from_obj(obj);
            if !values.is_empty() {
                self.aliases.insert(name_alias.to_string(), values);
            }
        }
    }
}
impl<'a> Visit<'a> for EnumAliasCollector {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let (Some(name), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref()) {
            self.record_call(name.as_str(), init);
            self.record_object_literal(name.as_str(), init);
        }
        walk::walk_variable_declarator(self, d);
    }
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(name) = assignment_target_name(&n.left) {
            self.record_call(name, &n.right);
        }
        walk::walk_assignment_expression(self, n);
    }
}

fn enum_values_from_obj(obj: &ObjectExpression) -> Vec<ProtoEnumValue> {
    let mut out = Vec::new();
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        // Keep forward `IDENT: int` members; skip non-forward entries (e.g.
        // protobuf.js's bidirectional reverse map `0: "NAME"`) rather than
        // discarding the whole enum. Aliases only become enums when matched to an
        // enum declaration later, so a stray non-enum object stays harmless.
        if let (Some(name), Some(id)) = (property_key_name(&p.key), as_int(&p.value)) {
            out.push(ProtoEnumValue {
                name: name.to_string(),
                id,
            });
        }
    }
    out
}

struct AliasMatchCollector {
    matches: Vec<(String, String)>,
}
impl<'a> Visit<'a> for AliasMatchCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(prop) = n
            .left
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            && let Some(right) = as_identifier(&n.right)
        {
            self.matches
                .push((rename(prop).to_string(), right.to_string()));
        }
        walk::walk_assignment_expression(self, n);
    }
}

struct ContentsCollector {
    specs: Vec<(String, Vec<MemberDesc>)>,
}
impl<'a> Visit<'a> for ContentsCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(member) = n.left.as_member_expression()
            && member.static_property_name() == Some(PROP_INTERNAL_SPEC)
            && let (Some(obj_name), Expression::ObjectExpression(obj)) =
                (as_identifier(member.object()), &n.right)
        {
            self.specs
                .push((obj_name.to_string(), parse_internal_spec(obj)));
        }
        walk::walk_assignment_expression(self, n);
    }
}

/// Captures `X.internalDefaults = { field: <defaultExpr>, … }` — the proto2
/// per-field defaults, keyed (like `internalSpec`) by the message's alias `X`.
struct DefaultsCollector {
    defaults: Vec<(String, HashMap<String, String>)>,
}
impl<'a> Visit<'a> for DefaultsCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if let Some(member) = n.left.as_member_expression()
            && member.static_property_name() == Some(PROP_INTERNAL_DEFAULTS)
            && let (Some(obj_name), Expression::ObjectExpression(obj)) =
                (as_identifier(member.object()), &n.right)
        {
            self.defaults
                .push((obj_name.to_string(), parse_defaults(obj)));
        }
        walk::walk_assignment_expression(self, n);
    }
}

/// Parse an `internalDefaults` object into `field → proto2 default token`, dropping
/// any value whose expression shape isn't a recognized default (see [`resolve_default`]).
fn parse_defaults(obj: &ObjectExpression) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for prop in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(p) = prop
            && let Some(key) = property_key_name(&p.key)
            && let Some(value) = resolve_default(&p.value)
        {
            out.insert(key.to_string(), value);
        }
    }
    out
}

/// Resolve a single `internalDefaults` value to its proto2 default token. WA declares
/// these as an enum-variant member (`s.E2EE` / `c.Foo.E2EE` → the variant name), a
/// numeric literal (`1`), a negated number (`-1`), or a boolean written `!1`/`!0`.
/// Returns `None` for anything else (which then emits no default, never a wrong one).
fn resolve_default(expr: &Expression) -> Option<String> {
    // An enum default references a variant: the bare last property name is the token.
    if let Some(member) = expr.as_member_expression() {
        return member.static_property_name().map(str::to_string);
    }
    match expr {
        Expression::NumericLiteral(n) => Some(format_number(n.value)),
        Expression::BooleanLiteral(b) => Some(b.value.to_string()),
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::UnaryExpression(u) => {
            let Expression::NumericLiteral(n) = &u.argument else {
                return None;
            };
            match u.operator {
                // `!1` → false, `!0` → true (JS truthiness of the numeric operand).
                UnaryOperator::LogicalNot => Some((n.value == 0.0).to_string()),
                UnaryOperator::UnaryNegation => Some(format!("-{}", format_number(n.value))),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Render a numeric default without a spurious `.0` (WA's numeric defaults are integers).
fn format_number(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 {
        (v as i64).to_string()
    } else {
        v.to_string()
    }
}

// ─── internalSpec parsing ─────────────────────────────────────────────────────

fn parse_internal_spec(obj: &ObjectExpression) -> Vec<MemberDesc> {
    let mut fields: Vec<FieldDesc> = Vec::new();
    let mut oneofs: Vec<(String, Vec<String>)> = Vec::new();

    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let Some(key) = property_key_name(&p.key) else {
            continue;
        };

        if key.starts_with(CONSTRAINT_PREFIX) {
            if key == KEY_ONEOFS
                && let Expression::ObjectExpression(o) = &p.value
            {
                for op in &o.properties {
                    if let ObjectPropertyKind::ObjectProperty(oneof) = op
                        && let (Some(oname), Expression::ArrayExpression(arr)) =
                            (property_key_name(&oneof.key), &oneof.value)
                    {
                        let names = arr
                            .elements
                            .iter()
                            .filter_map(|e| e.as_expression().and_then(as_string_lit))
                            .map(str::to_string)
                            .collect();
                        oneofs.push((oname.to_string(), names));
                    }
                }
            }
            continue;
        }

        if let Expression::ArrayExpression(arr) = &p.value
            && let Some(field) = parse_field(key, arr)
        {
            fields.push(field);
        }
    }

    // Splice oneof members out of the flat field list into their groups, then emit
    // the remaining fields (original order) followed by the oneof groups. A
    // name→index map keeps this O(fields + oneof_names) instead of O(n²) scans.
    let mut by_name: HashMap<String, usize> = HashMap::with_capacity(fields.len());
    for (i, f) in fields.iter().enumerate() {
        by_name.entry(f.name.clone()).or_insert(i);
    }
    let mut slots: Vec<Option<FieldDesc>> = fields.into_iter().map(Some).collect();

    let mut oneof_members: Vec<MemberDesc> = Vec::new();
    for (name, names) in oneofs {
        let mut group = Vec::new();
        for n in &names {
            if let Some(&idx) = by_name.get(n)
                && let Some(f) = slots[idx].take()
            {
                group.push(f);
            }
        }
        oneof_members.push(MemberDesc::OneOf {
            name,
            fields: group,
        });
    }

    let mut members: Vec<MemberDesc> = slots.into_iter().flatten().map(MemberDesc::Field).collect();
    members.extend(oneof_members);
    members
}

fn parse_field(name: &str, arr: &ArrayExpression) -> Option<FieldDesc> {
    let id = as_int(arr.elements.first()?.as_expression()?)?;
    let elem1 = arr.elements.get(1).and_then(|e| e.as_expression());
    let elem2 = arr.elements.get(2).and_then(|e| e.as_expression());

    let mut scalar_type: Option<String> = None;
    let mut map_type: Option<TypeDesc> = None;
    let mut is_message_or_enum = false;
    let mut flags: Vec<String> = Vec::new();

    if let Some(e1) = elem1 {
        let mut parts = Vec::new();
        flatten_or(e1, &mut parts);
        for m in parts {
            if let Some((obj, prop)) = wa_oxc::as_member(m)
                && let Some((_, container)) = wa_oxc::as_member(obj)
            {
                match container {
                    NS_TYPES => {
                        let t = prop.to_ascii_lowercase();
                        if t == TYPE_MESSAGE || t == TYPE_ENUM {
                            is_message_or_enum = true;
                        } else if t == TYPE_MAP {
                            map_type = Some(parse_map_type(elem2));
                        } else {
                            scalar_type = Some(t);
                        }
                    }
                    NS_FLAGS => flags.push(prop.to_ascii_lowercase()),
                    _ => {}
                }
            }
        }
    }

    let ty = if is_message_or_enum {
        type_ref_from_elem2(elem1, elem2)
    } else if let Some(map) = map_type {
        map
    } else {
        TypeDesc::Scalar(scalar_type.unwrap_or_else(|| "/*?*/".to_string()))
    };

    Some(FieldDesc {
        name: name.to_string(),
        id,
        ty,
        flags,
    })
}

/// Deferred `map<K, V>` from `elements[2]` (a `[K, V]` array). Each side is a
/// scalar member ref (`X.TYPES.STRING`) or an identifier alias (resolved later).
fn parse_map_type(elem2: Option<&Expression>) -> TypeDesc {
    let part = |e: Option<&Expression>| -> TypeDesc {
        match e {
            Some(ex) if wa_oxc::as_member(ex).is_some() => {
                TypeDesc::Scalar(wa_oxc::as_member(ex).unwrap().1.to_ascii_lowercase())
            }
            Some(ex) => match as_identifier(ex) {
                Some(name) => TypeDesc::IdentAlias(name.to_string()),
                None => TypeDesc::Scalar("?".to_string()),
            },
            None => TypeDesc::Scalar("?".to_string()),
        }
    };
    let Some(Expression::ArrayExpression(arr)) = elem2 else {
        return TypeDesc::Map(
            Box::new(TypeDesc::Scalar("?".into())),
            Box::new(TypeDesc::Scalar("?".into())),
        );
    };
    TypeDesc::Map(
        Box::new(part(arr.elements.first().and_then(|e| e.as_expression()))),
        Box::new(part(arr.elements.get(1).and_then(|e| e.as_expression()))),
    )
}

fn type_ref_from_elem2(elem1: Option<&Expression>, elem2: Option<&Expression>) -> TypeDesc {
    let Some(e2) = elem2 else {
        return TypeDesc::Unresolved;
    };
    if let Some(name) = as_identifier(e2) {
        return TypeDesc::IdentAlias(name.to_string());
    }
    if let Some((obj, prop)) = wa_oxc::as_member(e2) {
        let elem1_is_enum = elem1
            .and_then(wa_oxc::as_member)
            .map(|(_, p)| p == ENUM_TYPE_PROP)
            .unwrap_or(false);
        // The cross-ref object name can come from `obj`, `obj.left`, or `obj.callee`.
        let obj_name = as_identifier(obj)
            .map(str::to_string)
            .or_else(|| match obj {
                Expression::AssignmentExpression(a) => {
                    assignment_target_name(&a.left).map(str::to_string)
                }
                Expression::CallExpression(c) => as_identifier(&c.callee).map(str::to_string),
                _ => None,
            });
        return TypeDesc::MemberRef {
            elem1_is_enum,
            obj: obj_name,
            prop: prop.to_string(),
        };
    }
    TypeDesc::Unresolved
}

/// Flatten a chain of `a | b | c` bitwise-or expressions.
fn flatten_or<'b, 'a>(e: &'b Expression<'a>, out: &mut Vec<&'b Expression<'a>>) {
    if let Expression::BinaryExpression(b) = e {
        let bin: &BinaryExpression = b;
        if matches!(bin.operator, BinaryOperator::BitwiseOR) {
            flatten_or(&bin.left, out);
            flatten_or(&bin.right, out);
            return;
        }
    }
    out.push(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stringify::stringify;

    // Mirrors a real proto module: call-form + literal-form enums, scalar/enum/
    // message/map fields, packed-repeated, a oneof, and a nested message.
    const MODULE: &str = r#"__d("WAWebProtobufsTest.pb",["$InternalEnum","WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e, ev={X:0,Y:1}, s=n("$InternalEnum")({A:0,B:1}), u={}, c={};
        u.name="Outer";
        u.internalSpec={kind:[2,(e=r("WAProtoConst")).TYPES.ENUM,s],inner:[3,e.TYPES.MESSAGE,c],lit:[4,e.TYPES.ENUM,ev],mp:[5,e.TYPES.MAP,[e.TYPES.STRING,e.TYPES.UINT32]],lbl:[6,e.TYPES.STRING],ids:[7,e.FLAGS.REPEATED|e.FLAGS.PACKED|e.TYPES.UINT32],ids2:[8,e.FLAGS.PACKED|e.FLAGS.REPEATED|e.TYPES.UINT32],__oneofs__:{body:["lbl"]}};
        c.name="Outer$Inner";
        c.internalSpec={x:[1,e.TYPES.STRING]};
        l.TestEnum=s,l.LitEnum=ev,l.OuterSpec=u,l.Outer$InnerSpec=c;
    }),1);"#;

    #[test]
    fn extracts_full_feature_set() {
        let out = stringify(&extract_proto(MODULE, "2.3000.1"));

        assert!(out.contains("enum TestEnum {\n  A = 0;\n  B = 1;\n}"));
        assert!(out.contains("enum LitEnum {\n  X = 0;\n  Y = 1;\n}")); // var-literal enum
        assert!(out.contains("message Outer {"));
        assert!(out.contains("optional TestEnum kind = 2;"));
        assert!(out.contains("optional Inner inner = 3;")); // nested ref, qualified to Inner
        assert!(out.contains("optional LitEnum lit = 4;"));
        assert!(out.contains("map<string, uint32> mp = 5;")); // maps get no `optional`
        assert!(out.contains("repeated uint32 ids = 7 [packed = true];"));
        // `packed` listed BEFORE `repeated` must still keep `repeated`.
        assert!(out.contains("repeated uint32 ids2 = 8 [packed = true];"));
        assert!(out.contains("oneof body {\n    string lbl = 6;\n  }")); // no `optional` in oneof
        // Inner is emitted nested, not at top level.
        assert!(out.contains("  message Inner {\n    optional string x = 1;\n  }"));
        assert!(!out.contains("\nmessage Inner {"));
    }

    // Two modules where one references the other's message type via a cross-ref.
    const CROSS: &str = r#"__d("ModA.pb",["WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e,b=r("ModB.pb"),u={};
        u.name="Holder";
        u.internalSpec={ref:[1,(e=r("WAProtoConst")).TYPES.MESSAGE,b.PayloadSpec]};
        l.HolderSpec=u;
    }),1);
    __d("ModB.pb",["WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e,c={};
        c.name="Payload";
        c.internalSpec={data:[1,(e=r("WAProtoConst")).TYPES.BYTES]};
        l.PayloadSpec=c;
    }),2);"#;

    #[test]
    fn resolves_cross_module_message_ref() {
        let out = stringify(&extract_proto(CROSS, "2.3000.1"));
        assert!(out.contains("message Holder {\n  optional Payload ref = 1;\n}"));
        assert!(out.contains("message Payload {\n  optional bytes data = 1;\n}"));
    }

    #[test]
    fn empty_or_non_proto_source() {
        let out = stringify(&extract_proto("var x = 1;", "2.3000.1"));
        assert!(!out.contains("message "));
    }

    // `internalDefaults` across every value shape WA uses: enum variant (`s.ON`), a
    // `!1` boolean, an int, and a negative int. A oneof member's default is dropped
    // (proto2 forbids oneof defaults).
    const DEFAULTS: &str = r#"__d("ModD.pb",["$InternalEnum","WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e, s=n("$InternalEnum")({UNKNOWN:0,ON:1}), u={};
        u.internalDefaults={mode:s.ON,flag:!1,on:!0,count:5,delta:-1,pick:s.ON,tags:5};
        u.name="Thing";
        u.internalSpec={mode:[1,(e=r("WAProtoConst")).TYPES.ENUM,s],flag:[2,e.TYPES.BOOL],on:[6,e.TYPES.BOOL],count:[3,e.TYPES.INT32],delta:[4,e.TYPES.INT32],pick:[5,e.TYPES.ENUM,s],tags:[7,e.TYPES.MAP,[e.TYPES.STRING,e.TYPES.STRING]],__oneofs__:{choice:["pick"]}};
        l.Mode=s,l.ThingSpec=u;
    }),1);"#;

    #[test]
    fn recovers_internal_defaults() {
        let out = stringify(&extract_proto(DEFAULTS, "2.3000.1"));
        assert!(
            out.contains("optional Mode mode = 1 [default = ON];"),
            "{out}"
        );
        assert!(
            out.contains("optional bool flag = 2 [default = false];"),
            "{out}"
        );
        // `!0` is JS-truthy → `true` (the complement of the `!1` case above).
        assert!(
            out.contains("optional bool on = 6 [default = true];"),
            "{out}"
        );
        assert!(
            out.contains("optional int32 count = 3 [default = 5];"),
            "{out}"
        );
        assert!(
            out.contains("optional int32 delta = 4 [default = -1];"),
            "{out}"
        );
        // A `map` field never carries a default (protoc rejects it), even with an
        // `internalDefaults` entry.
        assert!(
            out.contains("map<string, string> tags = 7;") && !out.contains("tags = 7 [default"),
            "{out}"
        );
        // `pick` is a oneof member → no default (proto2 forbids it).
        assert!(out.contains("Mode pick = 5;"), "{out}");
        assert!(
            !out.contains("pick = 5 [default"),
            "oneof field must not carry a default: {out}"
        );
    }

    // Same type exported by two differently-named modules (a legacy + a `…V3`
    // variant in real bundles). protoc rejects the redefinition; we keep one.
    const DUP: &str = r#"__d("ModA.pb",["WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e,u={}; u.name="Thing"; u.internalSpec={x:[1,(e=r("WAProtoConst")).TYPES.STRING]}; l.ThingSpec=u;
    }),1);
    __d("ModB.pb",["WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e,u={}; u.name="Thing"; u.internalSpec={x:[1,(e=r("WAProtoConst")).TYPES.STRING]}; l.ThingSpec=u;
    }),2);"#;

    #[test]
    fn dedups_duplicate_top_level_type() {
        let out = stringify(&extract_proto(DUP, "2.3000.1"));
        assert_eq!(out.matches("message Thing {").count(), 1);
    }

    // Two top-level enums share a value name (`SHARED`). protobuf.js allows it;
    // protoc does not (C++ enum scoping). EnumA has two referencers and stays at
    // package scope; EnumB has one and is nested into it, scoping `SHARED` away.
    const COLLIDE: &str = r#"__d("ModC.pb",["$InternalEnum","WAProtoConst"],(function(t,n,r,o,a,i,l){
        var e, ea=n("$InternalEnum")({SHARED:0,X:1}), eb=n("$InternalEnum")({SHARED:0,Y:1}), m1={}, m2={}, m3={};
        m1.name="One";   m1.internalSpec={a:[1,(e=r("WAProtoConst")).TYPES.ENUM,ea]};
        m2.name="Two";   m2.internalSpec={a:[1,e.TYPES.ENUM,ea]};
        m3.name="Three"; m3.internalSpec={b:[1,e.TYPES.ENUM,eb]};
        l.EnumA=ea,l.EnumB=eb,l.OneSpec=m1,l.TwoSpec=m2,l.ThreeSpec=m3;
    }),1);"#;

    #[test]
    fn relocates_colliding_enum_into_referencer() {
        let out = stringify(&extract_proto(COLLIDE, "2.3000.1"));
        // EnumA (2 referencers) stays at the top level.
        assert!(out.contains("\nenum EnumA {"));
        // EnumB is nested into its sole referencer Three, not left at top level.
        assert!(!out.contains("\nenum EnumB {"));
        assert!(out.contains("  enum EnumB {"));
        assert!(out.contains("    SHARED = 0;")); // value scoped inside Three
        // The field reference stays bare and resolves to the nested enum.
        assert!(out.contains("  optional EnumB b = 1;"));
    }

    #[test]
    fn name_helpers() {
        assert_eq!(rename("FooSpec"), "Foo");
        assert_eq!(rename("Foo"), "Foo");
        assert_eq!(unnest("A$B$C"), "C");
        assert_eq!(get_nesting("A$B$C"), "A$B");
        assert_eq!(get_nesting("Top"), "");
    }
}
