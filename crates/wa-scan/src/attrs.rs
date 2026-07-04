//! Stanza-builder call parsing + request attribute classification.
//!
//! Two builders produce stanzas in the bundle: the legacy `X.wap("tag", …)` and
//! the newer `WASmaxJsx.smax("tag", …)`. The module that defines `smax` does
//! `l.smax = WAWap.wap`, so the two are the *same* runtime function with the same
//! `(tag, attrs?, ...children)` shape — we accept both method names here.

use oxc_ast::ast::{Argument, CallExpression, Expression, ObjectPropertyKind, PropertyKey};
use wa_ir::{AttrEnumRef, WapAttrDef, WapAttrKind};

use crate::alias::{AliasMap, resolve_owner};
use crate::module::require_module_name;
use wa_oxc::{arg_expr, as_call, as_member, as_string_lit, callee_method, callee_object};

/// `o("Mod").EnumName.VARIANT` → `(module, enumName)`, when the base is a `require`
/// call (`o("Mod")`) and `EnumName` is enum-shaped. The specific variant is dropped —
/// the attribute links to the whole enum.
///
/// `require_module_name` only checks for a string-arg call, so a stray `foo("x").Y.Z`
/// could slip past; two things keep that from becoming a bogus link: `EnumName` must
/// start uppercase (enum exports are `CiphertextType` / `USYNC_ADDRESSING_MODE`, never
/// a lowercase field), and — the real backstop — the cross-module resolver drops any
/// link whose module/enum doesn't actually resolve to a wire enum. So this is a
/// permissive first filter, not the final guard.
fn enum_ref_of(e: &Expression) -> Option<(String, String)> {
    let (obj, _variant) = as_member(e)?;
    let (base, enum_name) = as_member(obj)?;
    if !enum_name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
    {
        return None;
    }
    let module = require_module_name(base)?;
    Some((module, enum_name.to_string()))
}

/// Find an `o("Mod").EnumName.VARIANT` reference anywhere in a guard expression — the
/// RHS of the `===` in `cond === o("Mod").Enum.VARIANT`, through `&&`/`||`/parens.
fn find_enum_ref_in(e: &Expression) -> Option<(String, String)> {
    if let Some(r) = enum_ref_of(e) {
        return Some(r);
    }
    match e {
        Expression::BinaryExpression(b) => {
            find_enum_ref_in(&b.left).or_else(|| find_enum_ref_in(&b.right))
        }
        Expression::LogicalExpression(b) => {
            find_enum_ref_in(&b.left).or_else(|| find_enum_ref_in(&b.right))
        }
        Expression::ParenthesizedExpression(p) => find_enum_ref_in(&p.expression),
        _ => None,
    }
}

/// FORM B: `cond === o("Mod").Enum.VARIANT ? CUSTOM_STRING(<value>) : DROP_ATTR`. The
/// enum only gates presence; the attribute is drawn from it *only if* the emitted value
/// belongs to it. Returns `(module, enum, guard_value)`:
///  - the consequent structurally references the SAME enum (`CUSTOM_STRING(Enum.X)`,
///    like `addressing_mode`) → the value is inarguably an enum variant → `guard_value`
///    is `None` (link unconditionally);
///  - the consequent is a string literal (`CUSTOM_STRING("status")`) → `guard_value` is
///    `Some(literal)`, and the link is kept only if the resolver finds it *is* a variant
///    of the enum (so `enc.state`'s `"false"`, not a `CiphertextType`, is dropped);
///  - anything else → `None` (no link).
fn form_b_link(
    test: &Expression,
    consequent: &Expression,
) -> Option<(String, String, Option<String>)> {
    let (module, ename) = find_enum_ref_in(test)?;
    // The emitted value: the sole arg of the consequent's `CUSTOM_STRING(...)`.
    let arg = as_call(consequent)
        .filter(|c| callee_method(c) == Some("CUSTOM_STRING"))
        .and_then(|c| c.arguments.first())
        .and_then(arg_expr)?;
    if let Some((cm, ce)) = enum_ref_of(arg) {
        // Structural: link only when it's the same enum as the guard.
        return ((cm, ce) == (module.clone(), ename.clone())).then_some((module, ename, None));
    }
    // Literal: validate membership against the resolved enum later.
    as_string_lit(arg).map(|lit| (module, ename, Some(lit.to_string())))
}

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
        enum_ref: None,
    };
    // A pending enum link — only its (name, module) are known here; the variants are
    // resolved cross-module after the scan (see `crate::enum_link`), which then clears
    // `value`. `variants` empty marks it unresolved; `value` carries the FORM B guard
    // value the resolver must confirm is a member of the enum (`None` for FORM A).
    let with_enum = |kind: WapAttrKind,
                     required: bool,
                     module: String,
                     ename: String,
                     guard: Option<String>| {
        WapAttrDef {
            name: name.to_string(),
            kind,
            value: guard,
            required,
            enum_ref: Some(AttrEnumRef {
                name: ename,
                module,
                variants: Vec::new(),
            }),
        }
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
        // FORM A: `CUSTOM_STRING(o("Mod").EnumName.VARIANT)` — the wire value is drawn
        // from that enum. Gated on `CUSTOM_STRING` (a wire builder) so an unrelated
        // `o(Mod).X.Y` member chain is never mistaken for an enum reference.
        if method == "CUSTOM_STRING"
            && let Some(arg) = call.arguments.first().and_then(arg_expr)
            && let Some((module, ename)) = enum_ref_of(arg)
        {
            return with_enum(WapAttrKind::String, true, module, ename, None);
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
    // FORM B: when the guard tests an enum (`cond === o("Mod").Enum.VARIANT ? … :
    // DROP_ATTR`), link the attr to that enum — but only via `form_b_link`, which keeps
    // the link solely when the emitted value belongs to the enum (a literal must be one
    // of its variants; `enc.state`'s `"false"` is not a `CiphertextType`, so it's
    // dropped). The guard value rides in `value` until the resolver validates it.
    if let Expression::ConditionalExpression(cond) = value {
        let s = &source[cond.span.start as usize..cond.span.end as usize];
        if s.contains("DROP_ATTR") {
            if let Some((module, ename, guard)) = form_b_link(&cond.test, &cond.consequent) {
                return with_enum(WapAttrKind::Optional, false, module, ename, guard);
            }
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
    fn detects_form_a_and_form_b_enum_links() {
        let alloc = Allocator::default();
        let code = r#"e.wap("enc", {
            type: o("WAWap").CUSTOM_STRING(o("Mod").CiphertextType.Skmsg),
            state: cond === o("Mod").CiphertextType.Pkmsg ? o("WAWap").CUSTOM_STRING("false") : o("WAWap").DROP_ATTR,
            addr: x === o("U").USYNC_ADDRESSING_MODE.LID ? o("WAWap").CUSTOM_STRING(o("U").USYNC_ADDRESSING_MODE.LID) : o("WAWap").DROP_ATTR,
            scope: k === o("S").SessionScope.STATUS ? o("WAWap").CUSTOM_STRING("status") : o("WAWap").DROP_ATTR,
            diff: a === o("A").EnumA.X ? o("WAWap").CUSTOM_STRING(o("B").EnumB.Y) : o("WAWap").DROP_ATTR
        });"#;
        let ret = wa_oxc::parse_cjs(&alloc, code);
        let wap = parse_wap_call(first_call(&ret.program), &no_aliases()).unwrap();
        let attrs = extract_attrs_from_obj(wap.attrs_node.unwrap(), code, &no_aliases());
        let by = |n: &str| attrs.iter().find(|a| a.name == n).unwrap();
        let er = |a: &WapAttrDef| a.enum_ref.as_ref().map(|e| e.name.clone());

        // FORM A: the value IS the enum → pending link, no guard value.
        assert_eq!(er(by("type")).as_deref(), Some("CiphertextType"));
        assert_eq!(by("type").value, None);
        // FORM B literal: the guard value rides in `value` for later membership check;
        // "false" is NOT a CiphertextType, so the resolver will drop it.
        assert_eq!(er(by("state")).as_deref(), Some("CiphertextType"));
        assert_eq!(by("state").value.as_deref(), Some("false"));
        assert_eq!(by("state").kind, WapAttrKind::Optional);
        // FORM B structural: consequent references the SAME enum → no guard value.
        assert_eq!(er(by("addr")).as_deref(), Some("USYNC_ADDRESSING_MODE"));
        assert_eq!(by("addr").value, None);
        // FORM B literal with a member-looking value.
        assert_eq!(er(by("scope")).as_deref(), Some("SessionScope"));
        assert_eq!(by("scope").value.as_deref(), Some("status"));
        // Consequent references a DIFFERENT enum than the guard → not linked.
        assert_eq!(er(by("diff")), None);
        assert_eq!(by("diff").kind, WapAttrKind::Optional);
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
