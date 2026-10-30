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

// Complete supplier modules from the same qualified bundle set as the handler.
// Pin initialization and helper dependencies as well as literal export tables.
const PROVIDER_HASHES: &[(&str, &str)] = &[
    (
        "$InternalEnum",
        "82b7b18d50af52e7f59e70338c869994bbfe707f85df522835b9c4d4b95cddb0",
    ),
    (
        "WAJids",
        "8b8655512bfc775d31954e5101970d1774e2c0800e4608698be13105cc23fb0c",
    ),
    (
        "WAParsableWapNode",
        "1c2e9ba9fabf92a027b2e8ced39a2cc7cc89cc107e6add73d90834a0bef868f3",
    ),
    (
        "WAParsableXmlNode",
        "5d238b9f2e2ecde2141c039a19811f665104b3ab03a149578004a402f492681a",
    ),
    (
        "WATimeUtils",
        "e7db2185c131de2170fbc36e206306066db2406fe1b60537ecd6ccc1c41bbacc",
    ),
    (
        "WAWebEphemeralityTypes",
        "b3df456a1c650a866935c3caea9561edb55bb3baa8383a0bf8b38002729bbf29",
    ),
    (
        "WAWebEphemeralityUtils",
        "3f6f783ec1f2044d44cb52693893c84bbc14b5708ea63eb64458aeec3f025986",
    ),
    (
        "WAWebGroupApiConst",
        "2150ec07a7cf11888d83fedd1eeeb8e0a6418e357f4e90ebca909bee654a524e",
    ),
    (
        "WAWebGroupHistoryPostJoinTypes",
        "793a8a262c5a6fc2b85d0dca45b5357b9bf16255224bd74512faf919b11a5f00",
    ),
    (
        "WAWebGroupMemberLinkMode",
        "002a12217ac7efb7863198fd7f3682c96dc148669b228a94db06710ac3a5821d",
    ),
    (
        "WAWebGroupType",
        "d63035154901e9677bc08acd8ab3994845087875ca5ce84636ec765b72553519",
    ),
    (
        "WAWebGroupsQueryApi",
        "0db1b65d79a6a1ad9648528c31359696af86feb8ea070edf476f1a9c4a02cf39",
    ),
    (
        "WAWebHandleGroupNotificationConst",
        "176daa1a4d66aee3b907bc26ba2e40da1fde706e142f44bf1bdb8cfb9fd3581e",
    ),
    (
        "WAWebRequestMethodType",
        "8a192131c0e7fb54652fd29cdfee7934fff4a4118f1d7b2a1ed3b7f9cf2302c1",
    ),
    (
        "WAWebSchemaGroupMetadata",
        "7fa15b1681882906c7cdef2fea492ba9c3cb82c0799414b64add593f92c3cb66",
    ),
    (
        "nullthrows",
        "dc6eb8c1da357368b7ab18fbb02faf3a0d1c098671c2f6df9f0c438d84a65569",
    ),
];

pub(crate) fn provider_is_qualified(module: &str, source: &str) -> bool {
    PROVIDER_HASHES
        .iter()
        .any(|(name, hash)| *name == module && wa_text::sha256_hex(source.as_bytes()) == *hash)
}

/// Check supplied dependencies even when their initialization only affects a
/// different module. Unknown slices may coexist in a complete bundle, but the
/// group-specific resolver must never consume an unqualified provider.
pub(crate) fn validate_providers(
    slices: &std::collections::HashMap<&str, &str>,
) -> Result<(), String> {
    for &(module, _) in PROVIDER_HASHES {
        if let Some(source) = slices.get(module)
            && !provider_is_qualified(module, source)
        {
            return Err(format!(
                "unqualified group provider initialization: {module}"
            ));
        }
    }
    Ok(())
}

/// Optional access is a separate control-flow operation, not an ordinary read.
/// Check it before any matcher/resolver can discard that distinction.
pub(crate) fn reject_optional_access(body: &oxc_ast::ast::FunctionBody<'_>) -> Result<(), String> {
    struct Check(bool);
    impl<'a> Visit<'a> for Check {
        fn visit_expression(&mut self, expression: &oxc_ast::ast::Expression<'a>) {
            use oxc_ast::ast::Expression;
            if matches!(expression, Expression::ChainExpression(_))
                || matches!(expression, Expression::CallExpression(call) if call.optional)
                || matches!(expression, Expression::ComputedMemberExpression(member) if member.optional)
                || matches!(expression, Expression::StaticMemberExpression(member) if member.optional)
            {
                self.0 = true;
            }
            walk::walk_expression(self, expression);
        }
    }
    let mut check = Check(false);
    check.visit_function_body(body);
    if check.0 {
        return Err("unqualified optional access".into());
    }
    Ok(())
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

    const PROVIDERS: &[(&str, &str)] = &[
        (
            "$InternalEnum",
            include_str!("../../../tests/conformance/groups/sources/$InternalEnum.js"),
        ),
        (
            "WAJids",
            include_str!("../../../tests/conformance/groups/sources/WAJids.js"),
        ),
        (
            "WAParsableWapNode",
            include_str!("../../../tests/conformance/groups/sources/WAParsableWapNode.js"),
        ),
        (
            "WAParsableXmlNode",
            include_str!("../../../tests/conformance/groups/sources/WAParsableXmlNode.js"),
        ),
        (
            "WATimeUtils",
            include_str!("../../../tests/conformance/groups/sources/WATimeUtils.js"),
        ),
        (
            "WAWebEphemeralityTypes",
            include_str!("../../../tests/conformance/groups/sources/WAWebEphemeralityTypes.js"),
        ),
        (
            "WAWebEphemeralityUtils",
            include_str!("../../../tests/conformance/groups/sources/WAWebEphemeralityUtils.js"),
        ),
        (
            "WAWebGroupApiConst",
            include_str!("../../../tests/conformance/groups/sources/WAWebGroupApiConst.js"),
        ),
        (
            "WAWebGroupHistoryPostJoinTypes",
            include_str!(
                "../../../tests/conformance/groups/sources/WAWebGroupHistoryPostJoinTypes.js"
            ),
        ),
        (
            "WAWebGroupMemberLinkMode",
            include_str!("../../../tests/conformance/groups/sources/WAWebGroupMemberLinkMode.js"),
        ),
        (
            "WAWebGroupType",
            include_str!("../../../tests/conformance/groups/sources/WAWebGroupType.js"),
        ),
        (
            "WAWebGroupsQueryApi",
            include_str!("../../../tests/conformance/groups/sources/WAWebGroupsQueryApi.js"),
        ),
        (
            "WAWebHandleGroupNotificationConst",
            include_str!(
                "../../../tests/conformance/groups/sources/WAWebHandleGroupNotificationConst.js"
            ),
        ),
        (
            "WAWebRequestMethodType",
            include_str!("../../../tests/conformance/groups/sources/WAWebRequestMethodType.js"),
        ),
        (
            "WAWebSchemaGroupMetadata",
            include_str!("../../../tests/conformance/groups/sources/WAWebSchemaGroupMetadata.js"),
        ),
        (
            "nullthrows",
            include_str!("../../../tests/conformance/groups/sources/nullthrows.js"),
        ),
    ];

    #[test]
    fn all_interpreted_regions_reject_unmodeled_tails() {
        let slices: HashMap<_, _> = PROVIDERS
            .iter()
            .copied()
            .chain([("WAWebHandleGroupNotification", SOURCE)])
            .collect();
        let link = crate::group_link::extract_link(&slices).unwrap();
        let unlink = crate::group_normalization::extract_unlink(&slices).unwrap();
        let envelope_end = SOURCE.find("});function x(e)").unwrap();
        for tail in [
            ";function e(){}",
            ";label: function e(){}",
            ";{function e(){}}",
            ";let shadow;",
            ";var {x}={};",
            ";try{}finally{}",
            ";while(false){}",
            ";Object.assign(o(\"WAWebGroupType\"),{});",
        ] {
            for (entry, at) in [
                ("LINK", link.end_byte - 1),
                ("UNLINK", unlink.end_byte - 1),
                ("envelope", envelope_end),
            ] {
                let changed = format!("{}{tail}{}", &SOURCE[..at], &SOURCE[at..]);
                let mut mutated = slices.clone();
                mutated.insert("WAWebHandleGroupNotification", &changed);
                let rejected = match entry {
                    "LINK" => crate::group_link::extract_link(&mutated).is_err(),
                    "UNLINK" => crate::group_normalization::extract_unlink(&mutated).is_err(),
                    _ => crate::group_envelope::extract_group_envelope(&mutated).is_err(),
                };
                assert!(rejected, "{entry}: {tail}");
            }
        }
    }

    #[test]
    fn unknown_constant_providers_cannot_enter_through_a_modeled_region() {
        let original = HashMap::from([
            ("WAWebHandleGroupNotification", SOURCE),
            ("WAWebGroupType", TYPES),
        ]);
        let contract = crate::group_normalization::extract_unlink(&original).unwrap();
        let helper = &SOURCE[contract.start_byte..contract.end_byte];
        let changed_helper = helper.replace("WAWebGroupType", "UnqualifiedProvider");
        assert_ne!(changed_helper, helper);
        let mut changed = SOURCE.to_string();
        changed.replace_range(contract.start_byte..contract.end_byte, &changed_helper);
        let provider = TYPES.replace("WAWebGroupType", "UnqualifiedProvider");
        let slices = HashMap::from([
            ("WAWebHandleGroupNotification", changed.as_str()),
            ("WAWebGroupType", TYPES),
            ("UnqualifiedProvider", provider.as_str()),
        ]);
        assert!(crate::group_normalization::extract_unlink(&slices).is_err());
    }

    #[test]
    fn defining_module_effects_cannot_publish_stale_actions() {
        let changed = TYPES.replace("l.GROUP_ACTIONS=d", "l.GROUP_ACTIONS=d,Object.assign(l,{GROUP_ACTIONS:{...d,PARENT_GROUP_UNLINK:\"changed\"}})");
        assert_ne!(changed, TYPES);
        let slices = HashMap::from([
            ("WAWebHandleGroupNotification", SOURCE),
            ("WAWebGroupType", changed.as_str()),
            ("WAWebHandleGroupNotificationConst", TAGS),
        ]);
        assert!(crate::group_normalization::extract_unlink(&slices).is_err());
        assert!(crate::group_link::extract_link(&slices).is_err());
    }

    #[test]
    fn supplied_provider_initialization_is_qualified_for_every_entry_point() {
        let mut slices: HashMap<_, _> = PROVIDERS.iter().copied().collect();
        slices.insert("WAWebHandleGroupNotification", SOURCE);
        assert!(crate::group_link::extract_link(&slices).is_ok());
        assert!(crate::group_normalization::extract_unlink(&slices).is_ok());
        assert!(crate::group_envelope::extract_group_envelope(&slices).is_ok());
        let mut accepted = vec![];
        for &(module, source) in PROVIDERS {
            // Alter the complete initialization, including definitions that the
            // static resolver does not visit (aliases, getters and closures).
            let at = source.find("){").unwrap() + 2;
            for effect in [
                "Object.assign(l,{GROUP_ACTIONS:{PARENT_GROUP_UNLINK:\"changed\"}});",
                "var alias=l;alias.GROUP_ACTIONS={};",
                "Object.defineProperty(l,\"GROUP_ACTIONS\",{get(){return {}}});",
                "(function(){l.GROUP_ACTIONS={}})();",
                "Object.freeze=function(x){return {}};",
            ] {
                let changed = format!("{}{effect}{}", &source[..at], &source[at..]);
                let mut mutated = slices.clone();
                mutated.insert(module, &changed);
                for (entry, rejected) in [
                    ("LINK", crate::group_link::extract_link(&mutated).is_err()),
                    (
                        "UNLINK",
                        crate::group_normalization::extract_unlink(&mutated).is_err(),
                    ),
                    (
                        "envelope",
                        crate::group_envelope::extract_group_envelope(&mutated).is_err(),
                    ),
                ] {
                    if !rejected {
                        accepted.push(format!("{entry}: {module}: {effect}"));
                    }
                }
            }
        }
        assert!(
            accepted.is_empty(),
            "accepted provider effects: {accepted:#?}"
        );
    }

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
