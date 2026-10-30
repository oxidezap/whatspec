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

/// Qualify every byte outside the region independently interpreted by an action
/// extractor. This includes factory setup, transitive helpers, the envelope
/// prefix, dispatch siblings and projection. Unknown effects anywhere in that
/// execution context require requalification, even without identifier writes.
pub(crate) fn action_context(
    source: &str,
    region: oxc_span::Span,
    kind: &str,
) -> Result<(), String> {
    let before = source.get(..region.start as usize).ok_or("action span")?;
    let after = source.get(region.end as usize..).ok_or("action span")?;
    let expected = match kind {
        "LINK" => "84d5edb013196745b038c30fd8efa2fec2ce4b6faac0feaf6a97390e7e656c08",
        "UNLINK" => "f3c64ae496e0e8da4d0ffc79486a11cc3c18eac5533a0a2576c29e938aa92fe8",
        _ => return Err("unknown group action context".into()),
    };
    let actual = fingerprint(&[before, after]);
    if actual != expected {
        return Err(format!("unqualified {kind} execution context: {actual}"));
    }
    Ok(())
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

#[cfg(test)]
mod context_tests {
    use std::collections::HashMap;
    const SOURCE: &str =
        include_str!("../../../tests/conformance/groups/sources/WAWebHandleGroupNotification.js");
    const TYPES: &str = include_str!("../../../tests/conformance/groups/sources/WAWebGroupType.js");
    const TAGS: &str = include_str!(
        "../../../tests/conformance/groups/sources/WAWebHandleGroupNotificationConst.js"
    );

    #[test]
    fn all_group_entry_points_reject_unmodeled_constant_effects() {
        let mut accepted = vec![];
        for anchor in [
            "var e,s,u,c,d,m,p,_,f;",
            "function g(e){",
            "\"groupNotificationParser\",function(e){",
            "var n,a=t.tag();switch(a){",
        ] {
            for effect in [
                "o(\"WAWebGroupType\").GROUP_ACTIONS={PARENT_GROUP_LINK:\"changed\",PARENT_GROUP_UNLINK:\"changed\"};",
                "o(\"WAWebGroupType\").GROUP_ACTIONS.PARENT_GROUP_LINK=\"changed\";",
                "var alias=o(\"WAWebGroupType\").GROUP_ACTIONS;alias.PARENT_GROUP_UNLINK=\"changed\";",
                "Object.assign(o(\"WAWebGroupType\").GROUP_ACTIONS,{PARENT_GROUP_LINK:\"changed\"});",
                "(function(){o(\"WAWebGroupType\").GROUP_ACTIONS.PARENT_GROUP_UNLINK=\"changed\";})();",
            ] {
                let replacement = if anchor.ends_with('{') && !anchor.starts_with("var n,") {
                    format!("{anchor}{effect}")
                } else {
                    format!("{effect}{anchor}")
                };
                let changed = SOURCE.replacen(anchor, &replacement, 1);
                assert_ne!(changed, SOURCE);
                let slices = HashMap::from([
                    ("WAWebHandleGroupNotification", changed.as_str()),
                    ("WAWebGroupType", TYPES),
                    ("WAWebHandleGroupNotificationConst", TAGS),
                ]);
                for (name, rejected) in [
                    ("LINK", crate::group_link::extract_link(&slices).is_err()),
                    (
                        "UNLINK",
                        crate::group_normalization::extract_unlink(&slices).is_err(),
                    ),
                    (
                        "envelope",
                        crate::group_envelope::extract_group_envelope(&slices).is_err(),
                    ),
                ] {
                    if !rejected {
                        accepted.push(format!("{name}: {anchor}: {effect}"));
                    }
                }
            }
        }
        assert!(accepted.is_empty(), "accepted effects: {accepted:#?}");
    }
}
