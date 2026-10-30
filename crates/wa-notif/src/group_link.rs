//! Source-backed qualification of the LINK branch. This intentionally accepts
//! only the complete observed control/data-flow shape. Unsupported constructs
//! reject the contract rather than publishing a partial normalized action.
use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPattern, Expression, ObjectPropertyKind, Statement, SwitchCase, VariableDeclarationKind,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use wa_ir::group_link::{GroupLinkContract, GroupLinkField, GroupLinkRow};
use wa_oxc::{arg_expr, as_call, as_identifier, as_member, as_string_lit};

use crate::actions::ConstResolver;

/// Standard Object.prototype string properties. A plain `table[kind]` lookup
/// exposes these inherited non-string values; they are unsupported normalized
/// action identities, not members of the ordinary undefined fallback class.
pub const OBJECT_PROTOTYPE_STRING_KEYS: &[&str] = &[
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

/// Slices must contain complete Metro definitions from one verified bundle set.
/// Resolve the case's tag and all action values against their actual modules.
pub fn extract_link(slices: &HashMap<&str, &str>) -> Result<GroupLinkContract, String> {
    let source = slices
        .get("WAWebHandleGroupNotification")
        .ok_or("missing group handler")?;
    let allocator = Allocator::default();
    let parsed = wa_oxc::parse_cjs(&allocator, source);
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err("invalid complete group module".into());
    }
    crate::group_qualification::validate_providers(slices)?;
    crate::group_scope::validate_import_bindings(
        &parsed.program.body,
        slices.keys().map(|name| name.to_string()),
    )?;
    struct Extract<'s> {
        source: &'s str,
        resolver: ConstResolver<'s>,
        results: Vec<Result<GroupLinkContract, String>>,
    }
    impl<'a> Visit<'a> for Extract<'_> {
        fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
            if let Some((_, "mapChildren")) = as_member(&call.callee)
                && call.arguments.len() == 1
                && let Some(Expression::FunctionExpression(callback)) =
                    call.arguments.first().and_then(arg_expr)
                && !callback.r#async
                && !callback.generator
                && callback.params.rest.is_none()
                && callback.params.items.len() == 1
                && callback.params.items[0].initializer.is_none()
                && let BindingPattern::BindingIdentifier(child) = &callback.params.items[0].pattern
                && let Some(body) = &callback.body
                && let [
                    Statement::VariableDeclaration(vars),
                    Statement::SwitchStatement(switch),
                ] = body.statements.as_slice()
                && vars.kind.is_var()
                && vars.declarations.len() == 2
                && vars.declarations[0].init.is_none()
                && let Some(tag_name) = vars.declarations[1].id.get_identifier_name()
                && let Some(tag_read) = vars.declarations[1].init.as_ref().and_then(as_call)
                && let Some((receiver, "tag")) = as_member(&tag_read.callee)
                && as_identifier(receiver) == Some(child.name.as_str())
                && tag_name.as_str() != child.name.as_str()
                && vars.declarations[0]
                    .id
                    .get_identifier_name()
                    .is_some_and(|temporary| {
                        temporary != tag_name && temporary.as_str() != child.name.as_str()
                    })
                && tag_read.arguments.is_empty()
                && as_identifier(&switch.discriminant) == Some(tag_name.as_str())
            {
                for (index, case) in switch.cases.iter().enumerate() {
                    if case.test.as_ref().is_some_and(is_link_case) {
                        self.results.push(
                            crate::group_scope::validate_dispatch_cases(switch, &self.resolver)
                                .and_then(|()| {
                                    if index > 0
                                        && !terminates_case(&switch.cases[index - 1].consequent)
                                    {
                                        return Err(
                                            "other dispatch cases can fall through into LINK"
                                                .into(),
                                        );
                                    }
                                    crate::group_qualification::action_context(
                                        self.source,
                                        case.span(),
                                        "LINK",
                                    )?;
                                    project_case(case, &self.resolver, child.name.as_str())
                                }),
                        );
                    }
                }
                // Other nested syntax is still inspected for unqualified LINK cases.
                for case in &switch.cases {
                    for stmt in &case.consequent {
                        self.visit_statement(stmt);
                    }
                }
                return;
            }
            walk::walk_call_expression(self, call);
        }
        fn visit_switch_case(&mut self, case: &SwitchCase<'a>) {
            if case.test.as_ref().is_some_and(is_link_case) {
                self.results
                    .push(Err("LINK case outside qualified child dispatch".into()));
            }
            walk::walk_switch_case(self, case);
        }
    }
    let mut visitor = Extract {
        source,
        resolver: ConstResolver::for_groups(slices),
        results: vec![],
    };
    visitor.visit_program(&parsed.program);
    if visitor.results.len() != 1 {
        return Err(format!(
            "expected one LINK case, found {}",
            visitor.results.len()
        ));
    }
    visitor.results.remove(0)
}

// Only unconditional exits prove that an earlier tag cannot enter LINK.
fn terminates_case(statements: &[Statement<'_>]) -> bool {
    match statements.last() {
        Some(Statement::ReturnStatement(_) | Statement::ThrowStatement(_)) => true,
        Some(Statement::BreakStatement(b)) => b.label.is_none(),
        Some(Statement::BlockStatement(b)) => terminates_case(&b.body),
        _ => false,
    }
}

fn is_link_case(e: &Expression<'_>) -> bool {
    let Some((object, "LINK")) = as_member(e) else {
        return false;
    };
    let Some((owner, "GROUP_NOTIFICATION_TAG")) = as_member(object) else {
        return false;
    };
    let Some(require) = as_call(owner) else {
        return false;
    };
    require.arguments.len() == 1
        && as_identifier(&require.callee).is_some()
        && require
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_string_lit)
            == Some("WAWebHandleGroupNotificationConst")
}

fn project_case(
    case: &SwitchCase<'_>,
    resolver: &ConstResolver<'_>,
    dispatched_child: &str,
) -> Result<GroupLinkContract, String> {
    let wire_tag = resolver
        .resolve(case.test.as_ref().ok_or("missing LINK test")?)
        .ok_or("unresolved LINK wire tag")?;
    let [Statement::BlockStatement(block)] = case.consequent.as_slice() else {
        return Err("unsupported LINK case statement sequence".into());
    };
    let [
        Statement::VariableDeclaration(vars),
        Statement::ReturnStatement(ret),
    ] = block.body.as_slice()
    else {
        return Err("unsupported LINK block statement sequence".into());
    };
    if vars.kind != VariableDeclarationKind::Var {
        return Err("lexical LINK declarations need scope qualification".into());
    }
    let [kind, table] = vars.declarations.as_slice() else {
        return Err("changed LINK binding sequence".into());
    };
    let kind_name = kind
        .id
        .get_identifier_name()
        .ok_or("destructured link type")?;
    let table_name = table
        .id
        .get_identifier_name()
        .ok_or("destructured action table")?;
    if kind_name == table_name
        || kind_name.as_str() == dispatched_child
        || table_name.as_str() == dispatched_child
    {
        return Err("LINK type/table/child bindings collide".into());
    }
    let kind_read =
        as_call(kind.init.as_ref().ok_or("missing link type read")?).ok_or("non-call link type")?;
    let (node, method) = as_member(&kind_read.callee).ok_or("unsupported link type receiver")?;
    let node_name = as_identifier(node).ok_or("non-local link node")?;
    if node_name != dispatched_child || method != "attrString" || kind_read.arguments.len() != 1 {
        return Err("unsupported link type accessor".into());
    }
    let link_type_attribute = kind_read
        .arguments
        .first()
        .and_then(arg_expr)
        .and_then(as_string_lit)
        .ok_or("dynamic link type attribute")?
        .to_string();
    let Expression::ObjectExpression(table_object) =
        table.init.as_ref().ok_or("missing link table")?
    else {
        return Err("non-object link table".into());
    };
    let mut actions = BTreeMap::new();
    for property in &table_object.properties {
        let ObjectPropertyKind::ObjectProperty(p) = property else {
            return Err("spread in link action table".into());
        };
        if p.computed {
            return Err("computed action key".into());
        }
        let key = p
            .key
            .static_name()
            .ok_or("dynamic action key")?
            .into_owned();
        let action = resolve_pure_constant(&p.value, resolver)?;
        if actions.insert(key, action).is_some() {
            return Err("duplicate action key".into());
        }
    }
    // The projection is qualified for this complete three-way source branch.
    // A changed family needs explicit qualification, never a thinner output.
    if actions.keys().map(String::as_str).collect::<Vec<_>>()
        != ["parent_group", "sibling_group", "sub_group"]
    {
        return Err("changed or incomplete LINK type family".into());
    }
    let Expression::ObjectExpression(output) = ret.argument.as_ref().ok_or("empty LINK return")?
    else {
        return Err("non-object LINK return".into());
    };
    let fields = object_fields(output)?;
    if fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        != ["actionType", "groupDatas"]
    {
        return Err("changed LINK output sequence".into());
    }
    let Expression::ComputedMemberExpression(lookup) = fields[0].1 else {
        return Err("non-table action lookup".into());
    };
    if as_identifier(&lookup.object) != Some(table_name.as_str())
        || as_identifier(&lookup.expression) != Some(kind_name.as_str())
    {
        return Err("changed action lookup binding".into());
    }
    let groups = as_call(fields[1].1).ok_or("non-call group projection")?;
    let Some((receiver, "mapChildrenWithTag")) = as_member(&groups.callee) else {
        return Err("unsupported group projection".into());
    };
    if as_identifier(receiver) != Some(node_name) || groups.arguments.len() != 2 {
        return Err("changed group projection receiver/arity".into());
    }
    let group_child_tag = groups
        .arguments
        .first()
        .and_then(arg_expr)
        .and_then(as_string_lit)
        .ok_or("dynamic group tag")?
        .to_string();
    let Some(Expression::FunctionExpression(callback)) = groups.arguments.get(1).and_then(arg_expr)
    else {
        return Err("unsupported group callback".into());
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
        return Err("changed callback kind/parameters".into());
    }
    let parameter = callback.params.items[0]
        .pattern
        .get_identifier_name()
        .ok_or("destructured group parameter")?;
    if parameter == kind_name || callback.id.as_ref().is_some_and(|id| id.name == kind_name) {
        return Err("group callback shadows captured link type".into());
    }
    let body = callback.body.as_ref().ok_or("empty group callback")?;
    let [Statement::ReturnStatement(group_return)] = body.statements.as_slice() else {
        return Err("effects or statements in group projection".into());
    };
    let Some(Expression::ObjectExpression(group_output)) = &group_return.argument else {
        return Err("non-object group projection".into());
    };
    let group_fields = object_fields(group_output)?;
    if group_fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        != ["id", "subject", "subjectTime", "hiddenSubgroup"]
    {
        return Err("changed group output sequence".into());
    }
    let id = as_call(group_fields[0].1).ok_or("missing group ID conversion")?;
    let Some((owner, "groupJidToWid")) = as_member(&id.callee) else {
        return Err("changed group ID conversion".into());
    };
    let require = as_call(owner).ok_or("non-import group ID conversion")?;
    if require.arguments.len() != 1
        || as_identifier(&require.callee).is_none()
        || require
            .arguments
            .first()
            .and_then(arg_expr)
            .and_then(as_string_lit)
            != Some("WAWebJidToWid")
        || id.arguments.len() != 1
    {
        return Err("effectful or changed group ID conversion".into());
    }
    let mut reads = vec![read_field(
        "id",
        id.arguments
            .first()
            .and_then(arg_expr)
            .ok_or("missing jid argument")?,
        parameter.as_str(),
        "attrGroupJid",
    )?];
    reads.push(read_field(
        "subject",
        group_fields[1].1,
        parameter.as_str(),
        "attrString",
    )?);
    reads.push(read_field(
        "subjectTime",
        group_fields[2].1,
        parameter.as_str(),
        "attrInt",
    )?);
    let Expression::ConditionalExpression(hidden) = group_fields[3].1 else {
        return Err("missing hidden-subgroup gate".into());
    };
    let Expression::BinaryExpression(guard) = &hidden.test else {
        return Err("unsupported hidden-subgroup guard".into());
    };
    if guard.operator != oxc_syntax::operator::BinaryOperator::StrictInequality
        || as_identifier(&guard.left) != Some(kind_name.as_str())
    {
        return Err("unsupported hidden-subgroup condition".into());
    }
    let excluded = as_string_lit(&guard.right).ok_or("dynamic hidden-subgroup exclusion")?;
    if !actions.contains_key(excluded) {
        return Err("hidden-subgroup exclusion outside qualified type family".into());
    }
    let hidden_read = read_field(
        "hiddenSubgroup",
        &hidden.consequent,
        parameter.as_str(),
        "hasChild",
    )?;
    let Expression::UnaryExpression(absent) = &hidden.alternate else {
        return Err("non-absent hidden-subgroup alternate".into());
    };
    if absent.operator != oxc_syntax::operator::UnaryOperator::Void
        || wa_oxc::as_int(&absent.argument) != Some(0)
    {
        return Err("effectful/non-void hidden-subgroup alternate".into());
    }
    let mut rows = vec![GroupLinkRow {
        link_type: None,
        action_type: None,
        unsupported_action: false,
        hidden_subgroup_child: Some(hidden_read.wire_name.clone()),
    }];
    for (kind, action) in actions {
        let child = (kind != excluded).then(|| hidden_read.wire_name.clone());
        rows.push(GroupLinkRow {
            link_type: Some(kind),
            action_type: Some(action),
            unsupported_action: false,
            hidden_subgroup_child: child,
        });
    }
    for key in OBJECT_PROTOTYPE_STRING_KEYS {
        rows.push(GroupLinkRow {
            link_type: Some((*key).to_string()),
            action_type: None,
            unsupported_action: true,
            hidden_subgroup_child: Some(hidden_read.wire_name.clone()),
        });
    }
    rows.sort_by(|a, b| a.link_type.cmp(&b.link_type));
    Ok(GroupLinkContract {
        module_name: "WAWebHandleGroupNotification".into(),
        start_byte: block.span.start as usize,
        end_byte: block.span.end as usize,
        wire_tag,
        link_type_attribute,
        group_child_tag,
        group_fields: reads,
        rows,
    })
}

fn resolve_pure_constant(
    expr: &Expression<'_>,
    resolver: &ConstResolver<'_>,
) -> Result<String, String> {
    let (object, _) = as_member(expr).ok_or("non-member action constant")?;
    let (owner, _) = as_member(object).ok_or("non-export action constant")?;
    let require = as_call(owner).ok_or("non-import action constant")?;
    if require.arguments.len() != 1 || as_identifier(&require.callee).is_none() {
        return Err("effectful constant import".into());
    }
    resolver
        .resolve(expr)
        .ok_or_else(|| "unresolved action constant".into())
}
fn read_field(
    name: &str,
    expr: &Expression<'_>,
    parameter: &str,
    method: &str,
) -> Result<GroupLinkField, String> {
    let call = as_call(expr).ok_or("non-call group field")?;
    let (receiver, actual) = as_member(&call.callee).ok_or("dynamic group accessor")?;
    if as_identifier(receiver) != Some(parameter) || actual != method || call.arguments.len() != 1 {
        return Err("changed group field receiver/method/arity".into());
    }
    let wire = call
        .arguments
        .first()
        .and_then(arg_expr)
        .and_then(as_string_lit)
        .ok_or("nonliteral group field")?;
    Ok(GroupLinkField {
        name: name.into(),
        wire_name: wire.into(),
        method: method.into(),
    })
}
fn object_fields<'b, 'a>(
    object: &'b oxc_ast::ast::ObjectExpression<'a>,
) -> Result<Vec<(String, &'b Expression<'a>)>, String> {
    let mut fields = vec![];
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(p) = property else {
            return Err("spread in output object".into());
        };
        if p.computed {
            return Err("computed output key".into());
        }
        let key = p
            .key
            .static_name()
            .ok_or("nonliteral output key")?
            .into_owned();
        if fields.iter().any(|(name, _)| name == &key) {
            return Err("duplicate output key".into());
        }
        fields.push((key, &p.value));
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HANDLER: &str =
        include_str!("../../../tests/conformance/groups/sources/WAWebHandleGroupNotification.js");
    const TYPES: &str = include_str!("../../../tests/conformance/groups/sources/WAWebGroupType.js");
    const TAGS: &str = include_str!(
        "../../../tests/conformance/groups/sources/WAWebHandleGroupNotificationConst.js"
    );
    fn extract(handler: &str) -> Result<GroupLinkContract, String> {
        extract_link(&HashMap::from([
            ("WAWebHandleGroupNotification", handler),
            ("WAWebGroupType", TYPES),
            ("WAWebHandleGroupNotificationConst", TAGS),
        ]))
    }
    #[test]
    fn module_initialization_cannot_replace_imported_link_constants() {
        for mutation in [
            "o(\"WAWebGroupType\").GROUP_ACTIONS={PARENT_GROUP_LINK:\"changed\",SUB_GROUP_LINK:\"changed\",SIBLING_GROUP_LINK:\"changed\"};",
            "o(\"WAWebGroupType\").GROUP_ACTIONS.PARENT_GROUP_LINK=\"changed\";",
        ] {
            let changed = HANDLER.replacen(
                "var e,s,u,c,d,m,p,_,f;",
                &format!("{mutation}var e,s,u,c,d,m,p,_,f;"),
                1,
            );
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err(), "{mutation}");
        }
    }
    #[test]
    fn switch_wide_lexical_bindings_cannot_shadow_dispatch_inputs() {
        for declaration in [
            "let t;",
            "const t=null;",
            "let {t}={};",
            "class t{}",
            "function t(){}",
            "label: function t(){}",
            "outer: inner: function t(){}",
        ] {
            let changed = HANDLER.replacen(
                "switch(a){",
                &format!("switch(a){{case \"extra\":{declaration}return null;"),
                1,
            );
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err(), "{declaration}");
        }
    }
    #[test]
    fn switch_fallthrough_into_link_requires_termination() {
        let anchor = "case o(\"WAWebHandleGroupNotificationConst\").GROUP_NOTIFICATION_TAG.LINK:";
        for body in ["", "void 0;", "if(false)return null;"] {
            let changed = HANDLER.replace(anchor, &format!("case \"extra\":{body}{anchor}"));
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err(), "{body}");
        }
        // A terminating block owns its lexical child binding; it neither
        // shadows the switch nor falls into LINK.
        let changed = HANDLER.replace(
            anchor,
            &format!("case \"extra\":{{let t;return null;}}{anchor}"),
        );
        // Structurally safe scope changes still alter the opaque execution
        // context and require snapshot requalification.
        assert!(extract(&changed).is_err());
    }
    #[test]
    fn dispatch_tag_collisions_and_intercepting_cases_reject() {
        for changed in [
            HANDLER
                .replace("var n,a=t.tag();switch(a)", "var n,t=t.tag();switch(t)")
                .replace(
                    "Unrecognized group action \"+a",
                    "Unrecognized group action \"+t",
                ),
            HANDLER.replace("switch(a){", "switch(a){case \"link\":return null;"),
        ] {
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn link_type_table_and_child_bindings_must_be_distinct() {
        for changed in [
            HANDLER
                .replace(
                    "i=t.attrString(\"link_type\"),l={",
                    "i=t.attrString(\"link_type\"),i={",
                )
                .replace("actionType:l[i]", "actionType:i[i]"),
            HANDLER
                .replace(
                    "i=t.attrString(\"link_type\"),l={",
                    "t=t.attrString(\"link_type\"),l={",
                )
                .replace("actionType:l[i]", "actionType:l[t]"),
        ] {
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn link_receivers_and_callback_binding_collisions_reject() {
        let source = HANDLER;
        for changed in [
            source
                .replace(
                    "i=t.attrString(\"link_type\")",
                    "i=e.attrString(\"link_type\")",
                )
                .replace(
                    "groupDatas:t.mapChildrenWithTag",
                    "groupDatas:e.mapChildrenWithTag",
                ),
            source
                .replace(
                    "mapChildrenWithTag(\"group\",function(e){return{id:",
                    "mapChildrenWithTag(\"group\",function(i){return{id:",
                )
                .replace("e.attrGroupJid(\"jid\")", "i.attrGroupJid(\"jid\")")
                .replace("e.attrString(\"subject\")", "i.attrString(\"subject\")")
                .replace("e.attrInt(\"s_t\")", "i.attrInt(\"s_t\")")
                .replace("e.hasChild(\"hidden\")", "i.hasChild(\"hidden\")"),
            source.replace(
                "mapChildrenWithTag(\"group\",function(e){return{id:",
                "mapChildrenWithTag(\"group\",function i(e){return{id:",
            ),
        ] {
            assert_ne!(changed, source);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn official_link_projection_preserves_absent_versus_false() {
        let contract = extract(HANDLER).unwrap();
        assert_eq!(contract.wire_tag, "link");
        assert_eq!(contract.rows.len(), 16);
        assert_eq!(
            contract
                .rows
                .iter()
                .filter(|r| r.unsupported_action)
                .count(),
            12
        );
        for key in ["toString", "__proto__"] {
            let row = contract
                .rows
                .iter()
                .find(|r| r.link_type.as_deref() == Some(key))
                .unwrap();
            assert!(row.unsupported_action);
            assert!(row.action_type.is_none());
        }
        let parent = contract
            .rows
            .iter()
            .find(|r| r.link_type.as_deref() == Some("parent_group"))
            .unwrap();
        assert_eq!(parent.action_type.as_deref(), Some("parent_group_link"));
        assert!(parent.hidden_subgroup_child.is_none());
        for row in contract
            .rows
            .iter()
            .filter(|r| r.link_type.as_deref() != Some("parent_group"))
        {
            assert_eq!(row.hidden_subgroup_child.as_deref(), Some("hidden_group"));
        }
        assert_eq!(
            contract
                .group_fields
                .iter()
                .map(|f| (f.name.as_str(), f.method.as_str(), f.wire_name.as_str()))
                .collect::<Vec<_>>(),
            [
                ("id", "attrGroupJid", "jid"),
                ("subject", "attrString", "subject"),
                ("subjectTime", "attrInt", "s_t")
            ]
        );
    }
    #[test]
    fn changing_the_guard_changes_the_projection() {
        let changed = HANDLER.replace("i!==\"parent_group\"", "i!==\"sub_group\"");
        assert_ne!(changed, HANDLER);
        let actual = extract(&changed).unwrap();
        assert!(
            actual
                .rows
                .iter()
                .find(|r| r.link_type.as_deref() == Some("sub_group"))
                .unwrap()
                .hidden_subgroup_child
                .is_none()
        );
        assert_ne!(actual.rows, extract(HANDLER).unwrap().rows);
    }
    #[test]
    fn unsupported_payload_effects_fields_and_guards_reject() {
        for changed in [
            HANDLER.replace(
                "subjectTime:e.attrInt(\"s_t\"),hiddenSubgroup",
                "subjectTime:e.maybeAttrInt(\"s_t\"),hiddenSubgroup",
            ),
            HANDLER.replace("i!==\"parent_group\"", "i===\"parent_group\""),
            HANDLER.replace(
                "subjectTime:e.attrInt(\"s_t\"),hiddenSubgroup",
                "subject:e.attrInt(\"s_t\"),hiddenSubgroup",
            ),
            HANDLER.replace(
                "i=t.attrString(\"link_type\")",
                "i=t.attrString(\"link_type\",unknownEffect())",
            ),
            HANDLER.replace("groupDatas:t.mapChildrenWithTag(\"group\",function(e){return{id:","groupDatas:t.mapChildrenWithTag(\"group\",async function(e){return{id:"),
            HANDLER.replace("groupDatas:t.mapChildrenWithTag(\"group\",function(e){return{id:","groupDatas:t.mapChildrenWithTag(\"group\",function*(e){return{id:"),
            HANDLER.replace("groupDatas:t.mapChildrenWithTag(\"group\",function(e){return{id:","groupDatas:t.mapChildrenWithTag(\"group\",function(e,extra=unknownEffect()){return{id:"),
            HANDLER.replace("groupDatas:t.mapChildrenWithTag(\"group\",function(e){return{id:","groupDatas:t.mapChildrenWithTag(\"group\",function(e,...extra){return{id:"),
            HANDLER.replace("o(\"WAWebJidToWid\").groupJidToWid(e.attrGroupJid(\"jid\"))","o(\"WAWebJidToWid\",unknownEffect()).groupJidToWid(e.attrGroupJid(\"jid\"))"),
        ] {
            assert_ne!(changed, HANDLER);
            assert!(extract(&changed).is_err());
        }
    }
    #[test]
    fn missing_case_and_unresolved_tag_reject() {
        let changed = HANDLER.replace(
            ".GROUP_NOTIFICATION_TAG.LINK:",
            ".GROUP_NOTIFICATION_TAG.UNKNOWN:",
        );
        assert_ne!(changed, HANDLER);
        assert!(extract(&changed).is_err());
        assert!(
            extract_link(&HashMap::from([
                ("WAWebHandleGroupNotification", HANDLER),
                ("WAWebGroupType", TYPES)
            ]))
            .is_err()
        );
    }
    #[test]
    fn enclosing_hoisted_loader_shadowing_rejects_the_projection() {
        let changed = HANDLER.replace("var n,a=t.tag();", "var o,n,a=t.tag();");
        assert_ne!(changed, HANDLER);
        assert!(extract(&changed).is_err());
    }
}
