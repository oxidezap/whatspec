//! Stanza-builder call parsing + request attribute classification.
//!
//! Two builders produce stanzas in the bundle: the legacy `X.wap("tag", …)` and
//! the newer `WASmaxJsx.smax("tag", …)`. The module that defines `smax` does
//! `l.smax = WAWap.wap`, so the two are the *same* runtime function with the same
//! `(tag, attrs?, ...children)` shape — we accept both method names here.

use oxc_ast::ast::{Argument, CallExpression, Expression, ObjectPropertyKind, PropertyKey};
use wa_ir::{WapAttrDef, WapAttrKind};

use crate::alias::{AliasMap, resolve_owner};
use wa_oxc::{arg_expr, as_call, as_member, as_string_lit, callee_method, callee_object};

/// A parsed `.wap("tag", attrs?, ...children)` / `.smax(...)` call.
pub(crate) struct WapCall<'a> {
    pub tag: &'a str,
    pub attrs_node: Option<&'a Expression<'a>>,
    pub child_args: &'a [Argument<'a>],
}

/// Recognize a stanza-builder call: `X.wap("tag", ...)` (any object), or
/// `WASmaxJsx.smax("tag", ...)` where the object resolves to `WASmaxJsx` (direct
/// `o("WASmaxJsx")`, an alias from `aliases`, or `(X = o("WASmaxJsx"))`).
///
/// The `wap` path is unchanged (object not inspected), preserving byte-exact
/// behavior for the legacy builder.
pub(crate) fn parse_wap_call<'a>(
    call: &'a CallExpression<'a>,
    aliases: &AliasMap,
) -> Option<WapCall<'a>> {
    match callee_method(call)? {
        "wap" => {}
        "smax" => {
            // Only treat `.smax` as a builder when its object is WASmaxJsx.
            let obj = callee_object(call)?;
            if resolve_owner(obj, aliases) != Some("WASmaxJsx") {
                return None;
            }
        }
        _ => return None,
    }
    let args = &call.arguments;
    let tag = as_string_lit(arg_expr(args.first()?)?)?;
    let attrs_node = args.get(1).and_then(arg_expr);
    let child_args = args.get(2..).unwrap_or(&[]);
    Some(WapCall {
        tag,
        attrs_node,
        child_args,
    })
}

/// Extract attribute definitions from a stanza attrs object expression.
/// Non-identifier keys (string/computed) are skipped, matching the TS scanner.
pub(crate) fn extract_attrs_from_obj<'a>(
    node: &'a Expression<'a>,
    source: &str,
    aliases: &AliasMap,
) -> Vec<WapAttrDef> {
    let Expression::ObjectExpression(obj) = node else {
        return Vec::new();
    };
    let mut attrs = Vec::new();
    for prop in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(p) = prop
            && let PropertyKey::StaticIdentifier(key) = &p.key
        {
            attrs.push(classify_attr_node(
                key.name.as_str(),
                &p.value,
                source,
                aliases,
            ));
        }
    }
    attrs
}

/// Classify a single attribute value into a [`WapAttrDef`].
fn classify_attr_node<'a>(
    name: &str,
    value: &'a Expression<'a>,
    source: &str,
    aliases: &AliasMap,
) -> WapAttrDef {
    let owned = |kind: WapAttrKind, val: Option<String>, required: bool| WapAttrDef {
        name: name.to_string(),
        kind,
        value: val,
        required,
    };

    // String literal → fixed const.
    if let Some(v) = as_string_lit(value) {
        return owned(WapAttrKind::Const, Some(v.to_string()), true);
    }

    // Builder method call: X.CUSTOM_STRING(), X.INT(), X.USER_JID(), ...
    // The switch keys off the method name only, so smax/wap share it; the
    // `WASmaxAttrs.OPTIONAL(...)` wrapper is handled just below.
    if let Some(call) = as_call(value)
        && let Some(method) = callee_method(call)
    {
        // `WASmaxAttrs.OPTIONAL(kind, val)` / `OPTIONAL_LITERAL(lit, cond)` →
        // optional (same meaning as the legacy `DROP_ATTR`). Only when the
        // object actually resolves to WASmaxAttrs, so we don't grab an
        // unrelated `.OPTIONAL` from other code.
        if matches!(method, "OPTIONAL" | "OPTIONAL_LITERAL")
            && callee_object(call).and_then(|o| resolve_owner(o, aliases)) == Some("WASmaxAttrs")
        {
            return owned(WapAttrKind::Optional, None, false);
        }
        let kind = match method {
            "CUSTOM_STRING" | "STANZA_ID" => Some(WapAttrKind::String),
            "INT" => Some(WapAttrKind::Integer),
            "USER_JID" | "JID" | "DOMAIN_JID" => Some(WapAttrKind::UserJid),
            "DEVICE_JID" => Some(WapAttrKind::DeviceJid),
            "GROUP_JID" => Some(WapAttrKind::GroupJid),
            "generateId" => Some(WapAttrKind::GeneratedId),
            _ => None,
        };
        if let Some(kind) = kind {
            return owned(kind, None, true);
        }
    }

    // Property access X.DROP_ATTR → optional. (No need to special-case
    // `X.S_WHATSAPP_NET`: target detection already defaults `to:` to Server when
    // it isn't the literal "g.us", and leaving it Dynamic keeps the legacy wap
    // path byte-exact.)
    if let Some((_, prop)) = as_member(value)
        && prop == "DROP_ATTR"
    {
        return owned(WapAttrKind::Optional, None, false);
    }

    // Ternary mentioning DROP_ATTR → optional (matches JSON.stringify().includes()).
    if let Expression::ConditionalExpression(cond) = value {
        let s = &source[cond.span.start as usize..cond.span.end as usize];
        if s.contains("DROP_ATTR") {
            return owned(WapAttrKind::Optional, None, false);
        }
    }

    owned(WapAttrKind::Dynamic, None, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::build_alias_map;
    use oxc_allocator::Allocator;
    use oxc_ast::ast::Statement;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    fn first_call<'a>(program: &'a oxc_ast::ast::Program<'a>) -> &'a CallExpression<'a> {
        let Statement::ExpressionStatement(es) = &program.body[0] else {
            panic!("expected expr stmt");
        };
        as_call(&es.expression).expect("call")
    }

    fn no_aliases() -> AliasMap {
        AliasMap::default()
    }

    #[test]
    fn parse_wap_basic_and_negatives() {
        let alloc = Allocator::default();
        let code = r#"e.wap("iq", {xmlns:"w:g2"}, child1, child2);"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let call = first_call(&ret.program);
        let wap = parse_wap_call(call, &no_aliases()).expect("wap");
        assert_eq!(wap.tag, "iq");
        assert!(wap.attrs_node.is_some());
        assert_eq!(wap.child_args.len(), 2);

        // Non-wap method.
        let alloc2 = Allocator::default();
        let ret2 = wa_oxc::parse_cjs(&alloc2, r#"e.notwap("x");"#);
        assert!(parse_wap_call(first_call(&ret2.program), &no_aliases()).is_none());
    }

    #[test]
    fn parse_smax_requires_wasmaxjsx_object() {
        let alloc = Allocator::default();
        // Direct o("WASmaxJsx").smax(...)
        let code = r#"o("WASmaxJsx").smax("iq", {xmlns:"blocklist"}, c);"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let s = parse_wap_call(first_call(&ret.program), &no_aliases()).expect("smax");
        assert_eq!(s.tag, "iq");
        assert_eq!(s.child_args.len(), 1);

        // `.smax` on an unrelated object is NOT a builder.
        let a2 = Allocator::default();
        let r2 = Parser::new(&a2, r#"o("Other").smax("iq", {});"#, SourceType::cjs()).parse();
        assert!(parse_wap_call(first_call(&r2.program), &no_aliases()).is_none());
    }

    #[test]
    fn parse_smax_via_alias() {
        let alloc = Allocator::default();
        // Module-style: alias n -> WASmaxJsx, then bare n.smax(...).
        let code =
            r#"var u = (n = o("WASmaxJsx")).smax("iq", {xmlns:"spam"}, n.smax("item", {}));"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let aliases = build_alias_map(&ret.program);
        // The inner `n.smax("item", ...)` must be recognized via the alias.
        // Walk to find a bare `n.smax(...)` call.
        let mut found = false;
        for stmt in &ret.program.body {
            if let Statement::VariableDeclaration(d) = stmt
                && let Some(init) = d.declarations[0].init.as_ref()
                && let Some(outer) = as_call(init)
            {
                // outer is (n=...).smax(...,inner); inner is arg 2.
                if let Some(inner) = outer.arguments.get(2).and_then(arg_expr)
                    && let Some(c) = as_call(inner)
                {
                    let parsed = parse_wap_call(c, &aliases).expect("aliased smax");
                    assert_eq!(parsed.tag, "item");
                    found = true;
                }
            }
        }
        assert!(found, "did not locate the aliased inner smax call");
    }

    #[test]
    fn classifies_smax_optional_attrs() {
        let alloc = Allocator::default();
        let code = r#"o("WASmaxJsx").smax("iq", {
            opt: o("WASmaxAttrs").OPTIONAL(o("WAWap").CUSTOM_STRING, a),
            optlit: o("WASmaxAttrs").OPTIONAL_LITERAL("1", flag),
            sid: o("WAWap").STANZA_ID(t),
            dom: o("WAWap").DOMAIN_JID(t)
        });"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let aliases = build_alias_map(&ret.program);
        let s = parse_wap_call(first_call(&ret.program), &aliases).unwrap();
        let attrs = extract_attrs_from_obj(s.attrs_node.unwrap(), code, &aliases);
        let by = |n: &str| attrs.iter().find(|a| a.name == n).unwrap();
        assert_eq!(by("opt").kind, WapAttrKind::Optional);
        assert!(!by("opt").required);
        assert_eq!(by("optlit").kind, WapAttrKind::Optional);
        assert_eq!(by("sid").kind, WapAttrKind::String);
        assert_eq!(by("dom").kind, WapAttrKind::UserJid);
    }

    #[test]
    fn classifies_every_attr_kind() {
        let alloc = Allocator::default();
        let code = r#"e.wap("iq", {
            xmlns: "w:g2",
            count: e.INT(),
            name: e.CUSTOM_STRING(),
            usr: e.USER_JID(),
            usr2: e.JID(),
            dev: e.DEVICE_JID(),
            grp: e.GROUP_JID(),
            sid: e.generateId(),
            opt: e.DROP_ATTR,
            cond: flag ? "v" : e.DROP_ATTR,
            to: e.S_WHATSAPP_NET,
            dyn: someVar,
            "quoted": "skipme"
        });"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let wap = parse_wap_call(first_call(&ret.program), &no_aliases()).unwrap();
        let attrs = extract_attrs_from_obj(wap.attrs_node.unwrap(), code, &no_aliases());

        let by = |n: &str| attrs.iter().find(|a| a.name == n).unwrap();
        assert_eq!(by("xmlns").kind, WapAttrKind::Const);
        assert_eq!(by("xmlns").value.as_deref(), Some("w:g2"));
        assert_eq!(by("count").kind, WapAttrKind::Integer);
        assert_eq!(by("name").kind, WapAttrKind::String);
        assert_eq!(by("usr").kind, WapAttrKind::UserJid);
        assert_eq!(by("usr2").kind, WapAttrKind::UserJid);
        assert_eq!(by("dev").kind, WapAttrKind::DeviceJid);
        assert_eq!(by("grp").kind, WapAttrKind::GroupJid);
        assert_eq!(by("sid").kind, WapAttrKind::GeneratedId);
        assert_eq!(by("opt").kind, WapAttrKind::Optional);
        assert!(!by("opt").required);
        assert_eq!(by("cond").kind, WapAttrKind::Optional);
        assert_eq!(by("to").kind, WapAttrKind::Dynamic); // member, not DROP_ATTR
        assert_eq!(by("dyn").kind, WapAttrKind::Dynamic);
        // Quoted (string-literal) key is skipped.
        assert!(!attrs.iter().any(|a| a.name == "quoted"));
    }

    #[test]
    fn extract_skips_spread_property() {
        let alloc = Allocator::default();
        let code = r#"e.wap("iq", {...rest, real:"v"});"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let wap = parse_wap_call(first_call(&ret.program), &no_aliases()).unwrap();
        let attrs = extract_attrs_from_obj(wap.attrs_node.unwrap(), code, &no_aliases());
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "real");
    }

    #[test]
    fn extract_on_non_object_is_empty() {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, r#"x("notobj");"#);
        let call = first_call(&ret.program);
        let arg = arg_expr(&call.arguments[0]).unwrap();
        assert!(extract_attrs_from_obj(arg, r#"x("notobj");"#, &no_aliases()).is_empty());
    }
}
