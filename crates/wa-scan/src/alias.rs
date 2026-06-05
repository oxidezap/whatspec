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

use std::collections::HashMap;

use oxc_ast::ast::{AssignmentExpression, Expression};
use oxc_ast_visit::{Visit, walk};

use wa_oxc::{arg_expr, as_call, as_identifier, as_string_lit, assignment_target_name};

/// Owner module strings whose aliases we resolve. Anything else is ignored so
/// the map stays small and `.wap`-only modules produce nothing.
const TRACKED_OWNERS: &[&str] = &["WASmaxJsx", "WAWap", "WASmaxAttrs", "WASmaxChildren"];

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
    if let Some(owner) = require_owner(e) {
        return Some(owner);
    }
    if let Some(name) = as_identifier(e) {
        return aliases.owner_of(name);
    }
    if let Expression::AssignmentExpression(assign) = e {
        return require_owner(&assign.right);
    }
    None
}

/// Build the [`AliasMap`] for a parsed module program.
pub(crate) fn build_alias_map(program: &oxc_ast::ast::Program) -> AliasMap {
    let mut b = AliasBuilder {
        map: AliasMap::default(),
    };
    b.visit_program(program);
    b.map
}

struct AliasBuilder {
    map: AliasMap,
}

impl<'a> Visit<'a> for AliasBuilder {
    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        // `X = o("Owner")` — both standalone and embedded in a larger expression
        // (the visitor reaches the inner assignment of `(X = o(...)).method()`).
        if let (Some(name), Some(owner)) = (
            assignment_target_name(&assign.left),
            require_owner(&assign.right),
        ) {
            self.map.map.insert(name.to_string(), owner);
        }
        walk::walk_assignment_expression(self, assign);
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
        // `var w = o("WAWap")` is a declarator init, not an AssignmentExpression,
        // so it is NOT captured here — resolve_owner handles `o("WAWap")` directly.
        assert_eq!(m.owner_of("w"), None);
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
