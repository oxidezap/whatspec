//! Extract WhatsApp protobuf specs from a bundle. Per-module `Visit` passes
//! capture owned descriptors; a final resolution pass wires cross-module type
//! references and `$`-nesting into a [`ProtoFile`].

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpression, AssignmentExpression, BinaryExpression, BinaryOperator, Expression,
    ObjectExpression, ObjectPropertyKind, VariableDeclarator,
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
}

#[derive(Default)]
struct ModuleInfo {
    cross_refs: Vec<(String, String)>, // (alias, module)
    identifiers: HashMap<String, Ident>,
    /// `(target_alias, members)` captured from `X.internalSpec = {...}`.
    specs: Vec<(String, Vec<MemberDesc>)>,
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
        entities,
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
            .map(|m| resolve_member(m, &ident.name, info, modules, indent_map))
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
    info: &ModuleInfo,
    modules: &HashMap<String, ModuleInfo>,
    indent_map: &HashMap<String, Indent>,
) -> ProtoMember {
    match m {
        MemberDesc::OneOf { name, fields } => {
            // oneof fields carry no auto-`optional` and no parent context, so
            // nested types are always fully qualified.
            let fields = fields
                .iter()
                .map(|f| build_field(f, None, false, info, modules, indent_map))
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

    ProtoField {
        name: f.name.clone(),
        id: f.id,
        type_name,
        flags,
        packed,
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

        assert!(out.contains("enum TestEnum {\n    A = 0;\n    B = 1;\n}"));
        assert!(out.contains("enum LitEnum {\n    X = 0;\n    Y = 1;\n}")); // var-literal enum
        assert!(out.contains("message Outer {"));
        assert!(out.contains("optional TestEnum kind = 2;"));
        assert!(out.contains("optional Inner inner = 3;")); // nested ref, qualified to Inner
        assert!(out.contains("optional LitEnum lit = 4;"));
        assert!(out.contains("map<string, uint32> mp = 5;")); // maps get no `optional`
        assert!(out.contains("repeated uint32 ids = 7 [packed=true];"));
        // `packed` listed BEFORE `repeated` must still keep `repeated`.
        assert!(out.contains("repeated uint32 ids2 = 8 [packed=true];"));
        assert!(out.contains("oneof body {\n        string lbl = 6;\n    }")); // no `optional` in oneof
        // Inner is emitted nested, not at top level.
        assert!(out.contains("    message Inner {\n        optional string x = 1;\n    }"));
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
        assert!(out.contains("message Holder {\n    optional Payload ref = 1;\n}"));
        assert!(out.contains("message Payload {\n    optional bytes data = 1;\n}"));
    }

    #[test]
    fn empty_or_non_proto_source() {
        let out = stringify(&extract_proto("var x = 1;", "2.3000.1"));
        assert!(!out.contains("message "));
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
