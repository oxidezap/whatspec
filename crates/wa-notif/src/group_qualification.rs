//! Fail-closed qualification of source omitted by the envelope IR.
//!
//! These SHA-256 fingerprints refer to WA Web 2.3000.1047483476, qualified by
//! tests/conformance/groups. They are not a general effect/purity analysis.
//! AST spans select the regions; no source is evaluated here. A source update
//! to an opaque region requires renewed independent source/adapter qualification.
use oxc_ast::ast::{Function, IdentifierReference, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use std::collections::BTreeSet;

// The module-frame fingerprint fixes this factory-scoped lazy template cache.
// Diagnostic lowering may omit its initialization only for this exact binding.
pub(crate) const DIAGNOSTIC_CACHE: &str = "m";

fn fingerprint(chunks: &[&str]) -> String {
    let mut bytes = Vec::new();
    for chunk in chunks {
        bytes.extend_from_slice(&(chunk.len() as u64).to_be_bytes());
        bytes.extend_from_slice(chunk.as_bytes());
    }
    wa_text::sha256_hex(&bytes)
}

/// Independent action extractors must qualify initialization before reading
/// imported constants, just as envelope lowering does. The parser body remains
/// available for each extractor's own AST qualification.
pub(crate) fn complete_module_frame(
    source: &str,
    program: &oxc_ast::ast::Program<'_>,
) -> Result<(), String> {
    struct Find<'s> {
        source: &'s str,
        results: Vec<Result<(), String>>,
    }
    impl<'a> Visit<'a> for Find<'_> {
        fn visit_new_expression(&mut self, expression: &oxc_ast::ast::NewExpression<'a>) {
            if expression
                .arguments
                .first()
                .and_then(wa_oxc::arg_expr)
                .and_then(wa_oxc::as_string_lit)
                == Some("groupNotificationParser")
            {
                self.results.push(
                    match expression.arguments.get(1).and_then(wa_oxc::arg_expr) {
                        Some(oxc_ast::ast::Expression::FunctionExpression(parser)) => {
                            module_frame(self.source, parser)
                        }
                        _ => Err("unqualified group parser callback".into()),
                    },
                );
                return;
            }
            walk::walk_new_expression(self, expression);
        }
    }
    let mut finder = Find {
        source,
        results: vec![],
    };
    finder.visit_program(program);
    if finder.results.len() != 1 {
        return Err("expected one complete group parser module frame".into());
    }
    finder.results.remove(0)
}

pub(crate) fn module_frame(source: &str, parser: &Function<'_>) -> Result<(), String> {
    let body = parser.body.as_ref().ok_or("missing parser body")?;
    // Preserve the parser header and its entire enclosing module, including
    // loader initialization, helper definitions, globals and export wiring.
    let before = source
        .get(..body.span.start as usize)
        .ok_or("parser span")?;
    let after = source.get(body.span.end as usize..).ok_or("parser span")?;
    if fingerprint(&[before, after])
        != "dcec3eb8a54f58e659c37f922dac88bd35db7f9a75630eba74c91269deed9593"
    {
        return Err("unqualified opaque group module frame".into());
    }
    Ok(())
}

pub(crate) fn actions(source: &str, callback: &Function<'_>) -> Result<BTreeSet<String>, String> {
    let text = source
        .get(callback.span.start as usize..callback.span.end as usize)
        .ok_or("action callback span")?;
    if fingerprint(&[text]) != "55083eab54fbaa69a6706a0c5c0fbcd17d7f9cd9239ace333197a46402ce6692" {
        return Err("unqualified opaque group action callback".into());
    }
    Ok(references(callback))
}

pub(crate) fn helpers(source: &str, prefix: &[Statement<'_>]) -> Result<BTreeSet<String>, String> {
    let mut chunks = Vec::new();
    let mut refs = BTreeSet::new();
    for stmt in prefix {
        if let Statement::FunctionDeclaration(function) = stmt {
            let span = function.span();
            chunks.push(
                source
                    .get(span.start as usize..span.end as usize)
                    .ok_or("helper span")?,
            );
            refs.extend(references(function));
        }
    }
    if fingerprint(&chunks) != "59819f4ce7d98e07ee02c2f7bd69ed1108a666dcb2eadd26ed504c4eab040683" {
        return Err("unqualified opaque group envelope helpers".into());
    }
    Ok(refs)
}

fn references(function: &Function<'_>) -> BTreeSet<String> {
    // The fingerprint has already required the exact qualified functions. This
    // scope walk records their free bindings so prefix changes cannot redirect
    // an omitted call or remove a root capture while retaining identical text.
    #[derive(Default)]
    struct Bindings(BTreeSet<String>);
    impl<'a> Visit<'a> for Bindings {
        fn visit_binding_identifier(&mut self, id: &oxc_ast::ast::BindingIdentifier<'a>) {
            self.0.insert(id.name.to_string());
        }
        fn visit_function(&mut self, f: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
            if let Some(id) = &f.id {
                self.0.insert(id.name.to_string());
            }
        }
    }
    #[derive(Default)]
    struct References {
        scopes: Vec<BTreeSet<String>>,
        free: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for References {
        fn visit_function(&mut self, f: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
            let mut bindings = Bindings::default();
            bindings.visit_formal_parameters(&f.params);
            if let Some(id) = &f.id {
                bindings.0.insert(id.name.to_string());
            }
            if let Some(body) = &f.body {
                bindings.visit_function_body(body);
            }
            self.scopes.push(bindings.0);
            walk::walk_function(self, f, flags);
            self.scopes.pop();
        }
        fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
            if !self
                .scopes
                .iter()
                .rev()
                .any(|scope| scope.contains(id.name.as_str()))
            {
                self.free.insert(id.name.to_string());
            }
        }
    }
    let mut refs = References::default();
    refs.visit_function(function, oxc_syntax::scope::ScopeFlags::empty());
    refs.free
}

/// All opaque references are pinned above. New bindings in the modeled prefix
/// must not redirect any of them. These are the original root function's locals
/// (including its parameter), not an allowlist of callable effects.
pub(crate) fn validate_prefix_bindings<'a>(
    locals: impl Iterator<Item = &'a str>,
    opaque_references: &BTreeSet<String>,
) -> Result<(), String> {
    const ORIGINAL_ROOT_LOCALS: &[&str] = &[
        "e", "t", "n", "a", "i", "l", "s", "u", "c", "d", "p", "_", "f", "g", "h", "C", "D", "x",
    ];
    let locals: BTreeSet<_> = locals.collect();
    for name in opaque_references {
        if name != "e"
            && ORIGINAL_ROOT_LOCALS.contains(&name.as_str())
            && !locals.contains(name.as_str())
        {
            return Err(format!("opaque root capture is no longer bound: {name}"));
        }
    }
    for name in locals {
        if opaque_references.contains(name) && !ORIGINAL_ROOT_LOCALS.contains(&name) {
            return Err(format!("prefix binding shadows opaque dependency {name}"));
        }
    }
    Ok(())
}
