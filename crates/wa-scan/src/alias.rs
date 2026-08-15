//! Per-module alias resolution for the `WASmax` builders.
//!
//! Minified modules bind the require result into a local and reuse it bare:
//!
//! ```text
//! var u = (n = o("WASmaxJsx")).smax("iq", null, n.smax("spam_list", {...}));
//! //          ^^^^^^^^^^^^^^^^ alias: n -> "WASmaxJsx"
//! //                                  then `n.smax(...)` is the same builder
//! ```
//!
//! We can't recognize `n.smax(...)` as a stanza builder without knowing `n`
//! resolves to `WASmaxJsx`. This pass walks a module once and records every
//! `X = o("Owner")` assignment (including the `(X = o("Owner"))` form embedded in
//! a larger expression), mapping the local name to the owner module string.
//!
//! Only the handful of owners the scanner cares about are tracked, so the map
//! stays tiny and a pure-`.wap` module yields an empty map (no behavior change).

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{AssignmentExpression, Expression, VariableDeclarator};
use oxc_ast_visit::{Visit, walk};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, assignment_target_name};

/// Owner module strings whose aliases we resolve. Anything else is ignored so
/// the map stays small and `.wap`-only modules produce nothing.
const TRACKED_OWNERS: &[&str] = &[
    "WASmaxJsx",
    "WAWap",
    "WASmaxAttrs",
    "WASmaxChildren",
    "WASmaxMixins",
];

/// Local variable name → owner module string (e.g. `n` → `"WASmaxJsx"`).
#[derive(Default)]
pub(crate) struct AliasMap {
    map: HashMap<String, &'static str>,
}

impl AliasMap {
    /// The owner a local name resolves to, if tracked.
    fn owner_of(&self, name: &str) -> Option<&'static str> {
        self.map.get(name).copied()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// `o("Owner")` → the canonicalized owner string (interned to `'static`), if it's
/// a tracked owner. The require ident varies (`o`/`n`/`r` per factory), so we key
/// off the string-literal argument, not the callee name.
fn require_owner(e: &Expression) -> Option<&'static str> {
    let call = as_call(e)?;
    // Single string-literal argument naming the module.
    let name = as_string_lit(arg_expr(call.arguments.first()?)?)?;
    TRACKED_OWNERS.iter().copied().find(|&o| o == name)
}

/// Resolve the object an expression denotes to a tracked owner:
/// - `o("Owner")` → `Owner`
/// - `X` (identifier) → owner `X` was aliased to
/// - `(X = o("Owner"))` → `Owner`
pub(crate) fn resolve_owner(e: &Expression, aliases: &AliasMap) -> Option<&'static str> {
    // Unwrap `(…)` — minified code writes inline aliases as `(n = o("X")).method()`,
    // and the parenthesized assignment must be seen through.
    if let Expression::ParenthesizedExpression(p) = e {
        return resolve_owner(&p.expression, aliases);
    }
    if let Some(owner) = require_owner(e) {
        return Some(owner);
    }
    if let Some(name) = as_identifier(e) {
        return aliases.owner_of(name);
    }
    if let Expression::AssignmentExpression(assign) = e {
        return resolve_owner(&assign.right, aliases);
    }
    None
}

/// Build the [`AliasMap`] for a parsed module program.
pub(crate) fn build_alias_map(program: &oxc_ast::ast::Program) -> AliasMap {
    let mut b = AliasBuilder {
        map: AliasMap::default(),
        ambiguous: HashSet::new(),
    };
    b.visit_program(program);
    // A name that also holds something else somewhere in the module is not an alias. The
    // map is keyed by name with no scope attached, so a nested `var w = o("WAWap")` would
    // otherwise speak for every `w` in the module — including an unrelated builder's, whose
    // `w.S_WHATSAPP_NET` would then be published as a fixed address. Dropping the name
    // costs a resolution the scanner would have to earn back; keeping it risks a wrong
    // address, and this IR's whole point is that those are not the same mistake.
    for name in &b.ambiguous {
        b.map.map.remove(name);
    }
    b.map
}

struct AliasBuilder {
    map: AliasMap,
    /// Names bound to more than one thing in the module — a different tracked owner, or
    /// any non-require value. Only names *given a value* count: `var n;` followed by
    /// `(n = o("WAWap"))` is one binding, which is how minified modules spell it.
    ambiguous: HashSet<String>,
}

impl AliasBuilder {
    /// Record what `name` was bound to, or mark it ambiguous if that disagrees with a
    /// binding already seen.
    fn bind(&mut self, name: &str, value: Option<&'static str>) {
        // A `None` value is a binding to something that is not a tracked module object.
        // Not a conflict: minified modules reuse every short name, so treating it as one
        // costs 20 requests their addressee (measured) to remove a hazard that needs the
        // other object to carry a `WAWap`-only constant.
        let Some(owner) = value else { return };
        if self.map.map.get(name).is_some_and(|prev| *prev != owner) {
            self.ambiguous.insert(name.to_string());
        } else {
            self.map.map.insert(name.to_string(), owner);
        }
    }
}

impl<'a> Visit<'a> for AliasBuilder {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        // `X = o("Owner")` — both standalone and embedded in a larger expression
        // (the visitor reaches the inner assignment of `(X = o(...)).method()`).
        if let Some(name) = assignment_target_name(&assign.left) {
            let owner = require_owner(&assign.right);
            self.bind(name, owner);
        }
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        // `var w = o("Owner")` — the same binding written as a declarator instead of an
        // assignment. Minified modules use both spellings for the same thing, and the
        // bundle really does contain the declarator form, so recognizing only
        // `X = o(...)` leaves the identical code unresolved depending on how it was
        // written.
        if let Some(id) = decl.id.get_binding_identifier()
            && let Some(init) = &decl.init
        {
            let owner = require_owner(init);
            self.bind(&id.name, owner);
        }
        walk::walk_variable_declarator(self, decl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;

    fn aliases(code: &str) -> AliasMap {
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, code);
        build_alias_map(&ret.program)
    }

    #[test]
    fn captures_embedded_and_standalone_assignments() {
        let m = aliases(
            r#"var u = (n = o("WASmaxJsx")).smax("iq", null);
               var t; t = o("WASmaxAttrs");
               var w = o("WAWap");"#,
        );
        assert_eq!(m.owner_of("n"), Some("WASmaxJsx"));
        assert_eq!(m.owner_of("t"), Some("WASmaxAttrs"));
        assert_eq!(m.owner_of("w"), Some("WAWap"));
    }

    #[test]
    fn a_declarator_binding_is_the_same_alias_as_an_assignment() {
        // The two spellings are the same code to a reader, so they must be the same
        // code to the scanner: whether the server constant is reached through
        // `(n = o("WAWap")).S_WHATSAPP_NET` or through a `var` bound earlier decides
        // nothing about what the attribute means.
        let m = aliases(r#"var w = o("WAWap"), q = o("WASmaxJsx");"#);
        assert_eq!(m.owner_of("w"), Some("WAWap"));
        assert_eq!(m.owner_of("q"), Some("WASmaxJsx"));

        // Still only the tracked owners, and still nothing for a non-require init.
        let m = aliases(r#"var w = o("WAWebSomethingElse"), v = someObject;"#);
        assert!(m.is_empty());
    }

    #[test]
    fn one_name_naming_two_owners_names_neither() {
        // The map is keyed by name with no scope attached, so a name bound to two
        // different tracked owners in one module cannot speak for either — whichever
        // walk order wins, half its uses get the wrong module. Unresolved is the only
        // answer that is true at both sites.
        let m = aliases(r#"var n = o("WAWap"); function f(){ var n = o("WASmaxJsx"); }"#);
        assert_eq!(m.owner_of("n"), None);

        // Binding the same owner twice is not a conflict, and neither is the
        // `var n;` … `(n = o("WAWap"))` spelling the bundle actually uses — the bare
        // declaration gives the name no value.
        let m = aliases(
            r#"var n; var u = (n = o("WAWap")).wap("iq", {to: n.S_WHATSAPP_NET});
               function f(){ var t = (n = o("WAWap")).generateId(); }"#,
        );
        assert_eq!(m.owner_of("n"), Some("WAWap"));

        // A name that also holds an untracked value keeps its alias. Minified modules
        // reuse every short identifier, so treating that as a conflict costs 20 requests
        // their addressee (measured on this bundle) — and reading a `WAWap`-only constant
        // off the other object would be `undefined`, which is not code WA ships.
        let m = aliases(
            r#"function a(){ var w = o("WAWap"); return w.S_WHATSAPP_NET; }
               function b(){ var w = somethingElse(); return w.other; }"#,
        );
        assert_eq!(m.owner_of("w"), Some("WAWap"));
    }

    #[test]
    fn ignores_untracked_owners() {
        let m = aliases(r#"x = o("WAWebSomethingElse");"#);
        assert!(m.is_empty());
    }

    #[test]
    fn resolve_owner_forms() {
        let alloc = Allocator::default();
        // o("WASmaxJsx") direct
        let r1 = wa_oxc::parse_cjs(&alloc, r#"o("WASmaxJsx");"#);
        let oxc_ast::ast::Statement::ExpressionStatement(es) = &r1.program.body[0] else {
            panic!()
        };
        let empty = AliasMap::default();
        assert_eq!(resolve_owner(&es.expression, &empty), Some("WASmaxJsx"));

        // require with a different ident name still resolves by string arg.
        let r2 = wa_oxc::parse_cjs(&alloc, r#"n("WAWap");"#);
        let oxc_ast::ast::Statement::ExpressionStatement(es2) = &r2.program.body[0] else {
            panic!()
        };
        assert_eq!(resolve_owner(&es2.expression, &empty), Some("WAWap"));
    }
}
