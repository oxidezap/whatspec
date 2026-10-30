//! Bounded AST evaluation of the official unlink decision helper. Unsupported
//! statements, effects or values reject the projection instead of losing guards.
use crate::actions::ConstResolver;
const OBJECT_PROTOTYPE_KEYS: &[&str] = &[
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "__proto__",
    "toLocaleString",
];

use oxc_allocator::Allocator;
use oxc_ast::ast::{BindingPattern, Expression, Function, ObjectPropertyKind, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use std::collections::{BTreeSet, HashMap};
use wa_ir::group_normalization::{GroupUnlinkContract, GroupUnlinkRow};
use wa_oxc::{arg_expr, as_call, as_identifier, as_member, as_string_lit};

const UNKNOWN_INPUT: &str = "__whatspec_unknown_value__";

#[derive(Clone, PartialEq)]
enum Value {
    Text(String),
    Node,
    UnknownKind,
    UnknownReason,
    Null,
    Undefined,
    Bool(bool),
    Object(HashMap<String, Value>),
    Groups,
    Unsupported,
}

struct Eval<'a> {
    resolver: &'a ConstResolver<'a>,
    vars: HashMap<String, Value>,
    kind: String,
    reason: Option<String>,
}
impl Eval<'_> {
    fn expr(&self, expr: &Expression<'_>) -> Result<Value, String> {
        if let Some(text) = as_string_lit(expr) {
            return Ok(Value::Text(text.into()));
        }
        if let Some(text) = self.resolver.resolve(expr) {
            let import = as_member(expr)
                .and_then(|(obj, _)| as_member(obj))
                .and_then(|(owner, _)| as_call(owner))
                .ok_or("invalid constant reference")?;
            if import.arguments.len() != 1 || as_identifier(&import.callee).is_none() {
                return Err("effectful constant reference".into());
            }
            return Ok(Value::Text(text));
        }
        match expr {
            Expression::NullLiteral(_) => Ok(Value::Null),
            Expression::Identifier(id) => self
                .vars
                .get(id.name.as_str())
                .cloned()
                .ok_or_else(|| format!("unbound {}", id.name)),
            Expression::ConditionalExpression(c) => match self.expr(&c.test)? {
                Value::Bool(true) => self.expr(&c.consequent),
                Value::Bool(false) => self.expr(&c.alternate),
                _ => Err("non-boolean guard".into()),
            },
            Expression::BinaryExpression(b)
                if b.operator == oxc_syntax::operator::BinaryOperator::StrictEquality =>
            {
                let left = self.expr(&b.left)?;
                let right = self.expr(&b.right)?;
                if matches!(
                    (&left, &right),
                    (Value::UnknownKind, Value::UnknownReason)
                        | (Value::UnknownReason, Value::UnknownKind)
                ) {
                    return Err("independent unknown strings may be equal or unequal".into());
                }
                if matches!(
                    left,
                    Value::Object(_) | Value::Groups | Value::Unsupported | Value::Node
                ) || matches!(
                    right,
                    Value::Object(_) | Value::Groups | Value::Unsupported | Value::Node
                ) {
                    return Err("reference equality requires identity modeling".into());
                }
                Ok(Value::Bool(left == right))
            }
            Expression::ObjectExpression(obj) => {
                let mut values = HashMap::new();
                for property in &obj.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = property else {
                        return Err("spread in normalization".into());
                    };
                    if p.computed {
                        return Err("computed normalization key".into());
                    }
                    let key = p
                        .key
                        .static_name()
                        .ok_or("computed normalization key")?
                        .into_owned();
                    if key == "__proto__" {
                        return Err("custom object prototype".into());
                    }
                    if values.insert(key, self.expr(&p.value)?).is_some() {
                        return Err("duplicate key".into());
                    }
                }
                Ok(Value::Object(values))
            }
            Expression::ComputedMemberExpression(m) => {
                let Value::Object(obj) = self.expr(&m.object)? else {
                    return Err("lookup on non-object".into());
                };
                let key = match self.expr(&m.expression)? {
                    Value::Text(key) => key,
                    Value::UnknownKind | Value::UnknownReason => return Ok(Value::Undefined),
                    _ => return Err("non-string lookup".into()),
                };
                Ok(obj.get(&key).cloned().unwrap_or_else(|| {
                    if OBJECT_PROTOTYPE_KEYS.contains(&key.as_str()) {
                        Value::Unsupported
                    } else {
                        Value::Undefined
                    }
                }))
            }
            Expression::CallExpression(c) => {
                let (object, method) = as_member(&c.callee).ok_or("unsupported call")?;
                if as_identifier(object).and_then(|id| self.vars.get(id)) != Some(&Value::Node) {
                    return Err("unrecognized call receiver".into());
                }
                let attr = c
                    .arguments
                    .first()
                    .and_then(arg_expr)
                    .and_then(as_string_lit)
                    .ok_or("nonliteral attribute")?;
                if c.arguments.len() != if method == "mapChildrenWithTag" { 2 } else { 1 } {
                    return Err("unsupported accessor arity".into());
                }
                match (method, attr) {
                    ("attrString", "unlink_type") => Ok(if self.kind == UNKNOWN_INPUT {
                        Value::UnknownKind
                    } else {
                        Value::Text(self.kind.clone())
                    }),
                    ("hasAttr", "unlink_reason") => Ok(Value::Bool(self.reason.is_some())),
                    ("attrString", "unlink_reason") => self
                        .reason
                        .clone()
                        .map(|reason| {
                            if reason == UNKNOWN_INPUT {
                                Value::UnknownReason
                            } else {
                                Value::Text(reason)
                            }
                        })
                        .ok_or_else(|| "required reason absent".into()),
                    // Group payload is projected separately; verify the callback's
                    // exact accessor sequence before discarding its data here.
                    ("mapChildrenWithTag", "group") if valid_groups(c) => Ok(Value::Groups),
                    _ => Err(format!("unsupported accessor {method}({attr})")),
                }
            }
            _ => Err(format!("unsupported expression at {:?}", expr.span())),
        }
    }
    fn statements(&mut self, stmts: &[Statement<'_>]) -> Result<Option<Value>, String> {
        for stmt in stmts {
            if let Some(value) = self.statement(stmt)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    fn statement(&mut self, stmt: &Statement<'_>) -> Result<Option<Value>, String> {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                if !decl.kind.is_var() {
                    return Err("lexical declaration requires scope lowering".into());
                }
                for binding in &decl.declarations {
                    let name = binding.id.get_identifier_name().ok_or("destructuring")?;
                    let value = self.expr(binding.init.as_ref().ok_or("uninitialized binding")?)?;
                    self.vars.insert(name.to_string(), value);
                }
                Ok(None)
            }
            Statement::ReturnStatement(ret) => Ok(Some(
                self.expr(ret.argument.as_ref().ok_or("empty return")?)?,
            )),
            Statement::BlockStatement(block) => self.statements(&block.body),
            Statement::IfStatement(branch) => match self.expr(&branch.test)? {
                Value::Bool(true) => self.statement(&branch.consequent),
                Value::Bool(false) => branch
                    .alternate
                    .as_ref()
                    .map_or(Ok(None), |s| self.statement(s)),
                _ => Err("non-boolean if".into()),
            },
            _ => Err("unsupported statement in unlink helper".into()),
        }
    }
}

fn valid_groups(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
    let Some(Expression::FunctionExpression(callback)) = call.arguments.get(1).and_then(arg_expr)
    else {
        return false;
    };
    if callback.r#async
        || callback.generator
        || callback.params.items.len() != 1
        || callback.params.rest.is_some()
        || callback.params.items[0].initializer.is_some()
        || !matches!(
            callback.params.items[0].pattern,
            BindingPattern::BindingIdentifier(_)
        )
    {
        return false;
    }
    let Some(parameter) = callback
        .params
        .items
        .first()
        .and_then(|p| p.pattern.get_identifier_name())
    else {
        return false;
    };
    let Some(body) = &callback.body else {
        return false;
    };
    let [Statement::ReturnStatement(ret)] = body.statements.as_slice() else {
        return false;
    };
    let Some(Expression::ObjectExpression(obj)) = &ret.argument else {
        return false;
    };
    if obj.properties.len() != 3 {
        return false;
    }
    let mut keys = BTreeSet::new();
    for (index, property) in obj.properties.iter().enumerate() {
        let ObjectPropertyKind::ObjectProperty(p) = property else {
            return false;
        };
        if p.computed {
            return false;
        }
        let Some(key) = p.key.static_name() else {
            return false;
        };
        if key.as_ref() != ["id", "subject", "subjectTime"][index] {
            return false;
        }
        if !keys.insert(key.to_string()) {
            return false;
        }
        let mut value = &p.value;
        let (method, attribute) = match key.as_ref() {
            "id" => {
                let Some(convert) = as_call(value) else {
                    return false;
                };
                let Some((owner, "groupJidToWid")) = as_member(&convert.callee) else {
                    return false;
                };
                if as_call(owner)
                    .is_none_or(|c| c.arguments.len() != 1 || as_identifier(&c.callee).is_none())
                {
                    return false;
                }
                if as_call(owner)
                    .and_then(|c| c.arguments.first())
                    .and_then(arg_expr)
                    .and_then(as_string_lit)
                    != Some("WAWebJidToWid")
                    || convert.arguments.len() != 1
                {
                    return false;
                }
                let Some(arg) = convert.arguments.first().and_then(arg_expr) else {
                    return false;
                };
                value = arg;
                ("attrGroupJid", "jid")
            }
            "subject" => ("attrString", "subject"),
            "subjectTime" => ("attrInt", "s_t"),
            _ => return false,
        };
        let Some(read) = as_call(value) else {
            return false;
        };
        let Some((receiver, actual_method)) = as_member(&read.callee) else {
            return false;
        };
        if as_identifier(receiver) != Some(parameter.as_str())
            || actual_method != method
            || read.arguments.len() != 1
            || read
                .arguments
                .first()
                .and_then(arg_expr)
                .and_then(as_string_lit)
                != Some(attribute)
        {
            return false;
        }
    }
    true
}

/// Extract a qualified finite decision table from complete Metro module slices.
/// All helper paths are evaluated for every literal and an unknown sentinel.
/// The caller must bind the resulting spans to the original bundle hash.
pub fn extract_unlink(slices: &HashMap<&str, &str>) -> Result<GroupUnlinkContract, String> {
    let source = slices
        .get("WAWebHandleGroupNotification")
        .ok_or("missing group handler")?;
    let alloc = Allocator::default();
    let parsed = wa_oxc::parse_cjs(&alloc, source);
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err("invalid group module".into());
    }
    crate::group_qualification::validate_providers(slices)?;
    crate::group_scope::validate_import_bindings(
        &parsed.program.body,
        slices.keys().map(|name| name.to_string()),
    )?;
    struct Extract<'s> {
        source: &'s str,
        slices: &'s HashMap<&'s str, &'s str>,
        results: Vec<Result<GroupUnlinkContract, String>>,
    }
    impl<'a> Visit<'a> for Extract<'_> {
        fn visit_function(&mut self, f: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
            struct Reads(usize);
            impl<'a> Visit<'a> for Reads {
                fn visit_function(&mut self, _: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {}
                fn visit_call_expression(&mut self, c: &oxc_ast::ast::CallExpression<'a>) {
                    if wa_oxc::callee_method(c) == Some("attrString")
                        && c.arguments
                            .first()
                            .and_then(arg_expr)
                            .and_then(as_string_lit)
                            == Some("unlink_type")
                    {
                        self.0 += 1;
                    }
                    walk::walk_call_expression(self, c);
                }
            }
            if let Some(body) = &f.body {
                let mut reads = Reads(0);
                reads.visit_function_body(body);
                if reads.0 > 0 {
                    self.results.push(
                        crate::group_qualification::action_context(
                            self.source,
                            body.span(),
                            "UNLINK",
                        )
                        .and_then(|()| evaluate(f, self.slices)),
                    );
                    return;
                }
            }
            walk::walk_function(self, f, flags);
        }
    }
    let mut visitor = Extract {
        source,
        slices,
        results: vec![],
    };
    visitor.visit_program(&parsed.program);
    if visitor.results.len() != 1 {
        return Err(format!(
            "expected one unlink helper, found {}",
            visitor.results.len()
        ));
    }
    visitor.results.remove(0)
}

fn evaluate(f: &Function<'_>, slices: &HashMap<&str, &str>) -> Result<GroupUnlinkContract, String> {
    if f.r#async
        || f.generator
        || f.params.items.len() != 1
        || f.params.rest.is_some()
        || f.params.items[0].initializer.is_some()
        || !matches!(
            f.params.items[0].pattern,
            BindingPattern::BindingIdentifier(_)
        )
    {
        return Err("changed helper kind/parameters".into());
    }
    let resolver = ConstResolver::for_groups(slices);
    let body = f.body.as_ref().ok_or("missing helper body")?;
    let param = f
        .params
        .items
        .first()
        .and_then(|p| p.pattern.get_identifier_name())
        .ok_or("missing node parameter")?;
    // Reject calls on any receiver except the actual helper parameter. Alias it
    // through an AST-independent binding in the expression evaluator.
    struct Literals<'r, 's> {
        resolver: &'r ConstResolver<'s>,
        values: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Literals<'_, '_> {
        fn visit_object_expression(&mut self, obj: &oxc_ast::ast::ObjectExpression<'a>) {
            for p in &obj.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = p
                    && let Some(key) = p.key.static_name()
                {
                    self.values.insert(key.into_owned());
                }
            }
            walk::walk_object_expression(self, obj);
        }
        fn visit_expression(&mut self, e: &Expression<'a>) {
            if let Some(s) = as_string_lit(e) {
                self.values.insert(s.into());
            }
            if let Some(s) = self.resolver.resolve(e) {
                self.values.insert(s);
            }
            walk::walk_expression(self, e);
        }
    }
    let mut literals = Literals {
        resolver: &resolver,
        values: BTreeSet::new(),
    };
    literals.visit_function_body(body);
    let sentinel = UNKNOWN_INPUT;
    if literals.values.contains(sentinel) {
        return Err("sentinel collision".into());
    }
    let mut values: Vec<_> = literals.values.into_iter().collect();
    values.extend(OBJECT_PROTOTYPE_KEYS.iter().map(|s| s.to_string()));
    values.sort();
    values.dedup();
    values.push(sentinel.into());
    let mut rows = vec![];
    for kind in &values {
        for reason in std::iter::once(None).chain(values.iter().map(|v| Some(v.clone()))) {
            let mut vars = HashMap::new();
            vars.insert(param.to_string(), Value::Node);
            let mut eval = Eval {
                resolver: &resolver,
                vars,
                kind: kind.clone(),
                reason: reason.clone(),
            };
            let value = eval
                .statements(&body.statements)?
                .ok_or("helper has no return")?;
            let Value::Object(mut obj) = value else {
                return Err("non-object helper result".into());
            };
            if obj.remove("groupDatas") != Some(Value::Groups) || obj.len() != 1 {
                return Err("changed normalized payload".into());
            }
            let (action_type, unsupported_action) = match obj.remove("actionType") {
                Some(Value::Text(v)) if v == sentinel => {
                    return Err("unknown input escapes finite action table".into());
                }
                Some(Value::Text(v)) => (Some(v), false),
                Some(Value::Null | Value::Undefined) => (None, false),
                Some(Value::Unsupported) => (None, true),
                _ => return Err("non-string action".into()),
            };
            rows.push(GroupUnlinkRow {
                unlink_type: (kind != sentinel).then(|| kind.clone()),
                reason: reason.filter(|v| v != sentinel),
                action_type,
                unsupported_action,
            });
        }
    }
    // Publish only distinctions which affect the decision. Duplicates include
    // unrelated literal strings and unknown/absent reasons with equal behavior.
    rows.sort_by(|a, b| {
        (
            &a.unlink_type,
            &a.reason,
            &a.action_type,
            a.unsupported_action,
        )
            .cmp(&(
                &b.unlink_type,
                &b.reason,
                &b.action_type,
                b.unsupported_action,
            ))
    });
    rows.dedup();
    for pair in rows.windows(2) {
        if pair[0].unlink_type == pair[1].unlink_type && pair[0].reason == pair[1].reason {
            return Err("absent and unknown reasons have different semantics".into());
        }
    }
    let kinds: BTreeSet<_> = rows
        .iter()
        .filter(|r| {
            rows.iter()
                .find(|fallback| fallback.unlink_type.is_none() && fallback.reason == r.reason)
                .is_some_and(|fallback| {
                    fallback.action_type != r.action_type
                        || fallback.unsupported_action != r.unsupported_action
                })
        })
        .map(|r| r.unlink_type.clone())
        .collect();
    let reasons: BTreeSet<_> = rows
        .iter()
        .filter(|r| r.reason.is_some())
        .filter(|r| {
            rows.iter()
                .find(|d| d.unlink_type == r.unlink_type && d.reason.is_none())
                .is_some_and(|d| {
                    d.action_type != r.action_type || d.unsupported_action != r.unsupported_action
                })
        })
        .map(|r| r.reason.clone())
        .collect();
    rows.retain(|r| {
        (r.unlink_type.is_none() || kinds.contains(&r.unlink_type))
            && (r.reason.is_none() || reasons.contains(&r.reason))
    });
    Ok(GroupUnlinkContract {
        module_name: "WAWebHandleGroupNotification".into(),
        start_byte: f.span.start as usize,
        end_byte: f.span.end as usize,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const GROUP: &str =
        include_str!("../../../tests/conformance/groups/sources/WAWebHandleGroupNotification.js");
    const TYPES: &str = include_str!("../../../tests/conformance/groups/sources/WAWebGroupType.js");
    fn extract(source: &str) -> Result<GroupUnlinkContract, String> {
        extract_unlink(&HashMap::from([
            ("WAWebHandleGroupNotification", source),
            ("WAWebGroupType", TYPES),
        ]))
    }
    #[test]
    fn equal_and_unequal_unknown_inputs_must_not_share_an_assumed_value() {
        let mut keys: BTreeSet<&str> = OBJECT_PROTOTYPE_KEYS.iter().copied().collect();
        keys.extend([
            "unlink_type",
            "unlink_reason",
            "same",
            "group",
            "WAWebJidToWid",
            "jid",
            "subject",
            "s_t",
            "id",
            "subjectTime",
            "actionType",
            "groupDatas",
        ]);
        keys.remove("__proto__");
        let table = keys
            .into_iter()
            .map(|key| format!("\"{key}\":\"same\""))
            .collect::<Vec<_>>()
            .join(",");
        let helper = format!(
            r#"function I(e){{var t=e.attrString("unlink_type"),n=e.hasAttr("unlink_reason")?e.attrString("unlink_reason"):null,a={{{table}}};return{{actionType:t==="__proto__"?"same":n===null?"same":t===n?"same":a[t],groupDatas:e.mapChildrenWithTag("group",function(e){{return{{id:o("WAWebJidToWid").groupJidToWid(e.attrGroupJid("jid")),subject:e.attrString("subject"),subjectTime:e.attrInt("s_t")}}}})}}}}"#
        );
        let original = extract(GROUP).unwrap();
        let mut changed = GROUP.to_string();
        changed.replace_range(original.start_byte..original.end_byte, &helper);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn unknown_input_strings_cannot_escape_as_constant_fallbacks() {
        for value in ["t", "n"] {
            let changed = GROUP.replace("actionType:a[t]", &format!("actionType:{value}"));
            assert_ne!(changed, GROUP);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn node_identity_cannot_be_forged_with_a_string() {
        let changed = GROUP.replace("function I(e){", "function I(e){var e=\"$node\";");
        assert_ne!(changed, GROUP);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn null_action_exceptions_are_retained_against_non_null_fallbacks() {
        let changed = GROUP.replace(
            "actionType:a[t]",
            "actionType:t===\"future_kind\"?null:\"fallback\"",
        );
        assert_ne!(changed, GROUP);
        let contract = extract(&changed).unwrap();
        assert!(contract.rows.iter().any(|r| r.unlink_type.as_deref() == Some("future_kind") && r.action_type.is_none()));
        assert!(
            contract
                .rows
                .iter()
                .any(|r| r.unlink_type.is_none() && r.action_type.as_deref() == Some("fallback"))
        );
    }
    #[test]
    fn missing_lookup_is_undefined_during_strict_comparisons() {
        let changed = GROUP.replace(
            "actionType:a[t]",
            "actionType:t===\"future_kind\"?a[t]===null?\"wrong_null_branch\":a[t]:a[t]",
        );
        assert_ne!(changed, GROUP);
        let rows = extract(&changed).unwrap().rows;
        assert!(
            !rows
                .iter()
                .any(|r| r.action_type.as_deref() == Some("wrong_null_branch"))
        );
        assert_eq!(rows, extract(GROUP).unwrap().rows);
    }
    #[test]
    fn official_projection_is_reproducible() {
        let expected: GroupUnlinkContract =
            serde_json::from_str(include_str!("../../../generated/notif/group-unlink.json"))
                .unwrap();
        assert_eq!(extract(GROUP).unwrap(), expected);
        assert_eq!(expected.rows.len(), 48);
        assert!(
            expected
                .rows
                .iter()
                .any(|r| r.unlink_type.as_deref() == Some("sibling_group")
                    && r.action_type.as_deref() == Some("sibling_group_unlink"))
        );
    }
    #[test]
    fn changing_integrity_guard_changes_the_projection() {
        let changed = GROUP.replace(
            "n===o(\"WAWebGroupType\").DELETE_REASON.INTEGRITY_DELETE_PARENT",
            "n===\"new_integrity_reason\"",
        );
        assert_ne!(changed, GROUP);
        assert_ne!(
            extract(&changed).unwrap().rows,
            extract(GROUP).unwrap().rows
        );
    }
    #[test]
    fn unsupported_effect_rejects_the_whole_projection() {
        let changed = GROUP.replace("function I(e){", "function I(e){unknownEffect();");
        assert_ne!(changed, GROUP);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn unsupported_comparison_rejects_instead_of_dropping_a_guard() {
        let changed = GROUP.replace("t===\"parent_group\"", "t!==\"parent_group\"");
        assert_ne!(changed, GROUP);
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn extra_accessor_arguments_and_changed_group_projection_reject() {
        for changed in [
            GROUP.replace(
                "attrString(\"unlink_type\")",
                "attrString(\"unlink_type\",unknownEffect())",
            ),
            GROUP.replace(
                "subjectTime:e.attrInt(\"s_t\")",
                "subject:e.attrInt(\"s_t\")",
            ),
        ] {
            assert_ne!(changed, GROUP);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn prototype_values_and_effectful_callbacks_are_not_silently_undefined() {
        let contract = extract(GROUP).unwrap();
        assert!(
            contract
                .rows
                .iter()
                .any(|r| r.unlink_type.as_deref() == Some("toString") && r.unsupported_action)
        );
        for changed in [
            GROUP.replace("function I(e){", "async function I(e){"),
            GROUP.replace("function I(e){", "function* I(e){"),
            GROUP.replace("function I(e){", "function I(e,extra=unknownEffect()){ "),
            GROUP.replace(
                "mapChildrenWithTag(\"group\",function(e){return{id:",
                "mapChildrenWithTag(\"group\",async function(e){return{id:",
            ),
            GROUP.replace(
                "mapChildrenWithTag(\"group\",function(e){return{id:",
                "mapChildrenWithTag(\"group\",function(e,...extra){return{id:",
            ),
            GROUP.replace(
                "o(\"WAWebJidToWid\").groupJidToWid(e.attrGroupJid(\"jid\"))",
                "o(\"WAWebJidToWid\",unknownEffect()).groupJidToWid(e.attrGroupJid(\"jid\"))",
            ),
        ] {
            assert_ne!(changed, GROUP);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn import_bindings_cannot_be_guessed_through_free_or_shadowed_loaders() {
        for changed in [
            GROUP.replace(
                "o(\"WAWebGroupType\").DELETE_REASON",
                "evil(\"WAWebGroupType\").DELETE_REASON",
            ),
            GROUP.replace("var n,a=t.tag();", "var o,n,a=t.tag();"),
        ] {
            assert_ne!(changed, GROUP);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn field_order_computed_keys_and_reference_equality_are_not_guessed() {
        for changed in [
            GROUP.replace(
                "subject:e.attrString(\"subject\"),subjectTime:e.attrInt(\"s_t\")",
                "subjectTime:e.attrInt(\"s_t\"),subject:e.attrString(\"subject\")",
            ),
            GROUP.replace(
                "sub_group:o(\"WAWebGroupType\").GROUP_ACTIONS.SUB_GROUP_UNLINK",
                "[t]:o(\"WAWebGroupType\").GROUP_ACTIONS.SUB_GROUP_UNLINK",
            ),
            GROUP.replace("t===\"parent_group\"", "({x:1})===({x:1})"),
        ] {
            assert_ne!(changed, GROUP);
            assert!(extract(&changed).is_err());
        }
    }
}
