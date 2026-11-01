//! Fail-closed qualification of source omitted by the envelope IR.
//!
//! Fingerprints qualify the historical 2.3000.1047483476 and current
//! 2.3000.1052559453 sources in tests/conformance/groups. They are not a general effect/purity analysis.
//! AST spans select the regions; no source is evaluated here. A source update
//! to an opaque region requires renewed independent source/adapter qualification.
use oxc_ast::ast::{Function, IdentifierReference, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentProfile {
    module_frame: String,
    actions: String,
    helpers: String,
    link_context: String,
    unlink_context: String,
    diagnostic_cache: String,
    providers: BTreeMap<String, String>,
    root_locals: Vec<String>,
    link_warning_null: WarningNull,
    unlink_warning_null: WarningNull,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WarningNull {
    sha256: String,
    source: String,
    argument: String,
    template: Vec<String>,
    event: String,
}
/// These effectful expressions are qualified byte-for-byte, including the lazy
/// cache and WARN/sendLogs call order. They are never treated as pure calls.
pub(crate) fn unknown_type_warning(
    source: &str,
    expression: &oxc_ast::ast::Expression<'_>,
    family: &str,
) -> Option<(String, wa_ir::group_normalization::GroupUnknownTypeWarning)> {
    let expression = expression.without_parentheses();
    if !matches!(expression, oxc_ast::ast::Expression::SequenceExpression(_)) {
        return None;
    }
    let qualified = match family {
        "LINK" => &CURRENT.link_warning_null,
        "UNLINK" => &CURRENT.unlink_warning_null,
        _ => return None,
    };
    let span = expression.span();
    let bytes = source.get(span.start as usize..span.end as usize)?;
    if bytes != qualified.source || wa_text::sha256_hex(bytes.as_bytes()) != qualified.sha256 {
        return None;
    }
    if current_handler(source).ok() != Some(true) {
        return None;
    }
    Some((
        qualified.argument.clone(),
        wa_ir::group_normalization::GroupUnknownTypeWarning {
            template: qualified.template.clone(),
            event: qualified.event.clone(),
        },
    ))
}
static CURRENT: LazyLock<CurrentProfile> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "qualified-group-1052559453.json"
    ))
    .expect("qualified group profile")
});
const LEGACY_FRAME: &str = "dcec3eb8a54f58e659c37f922dac88bd35db7f9a75630eba74c91269deed9593";

fn current_handler(source: &str) -> Result<bool, String> {
    struct Probe<'s> {
        source: &'s str,
        hashes: Vec<String>,
    }
    impl<'a> Visit<'a> for Probe<'_> {
        fn visit_new_expression(&mut self, node: &oxc_ast::ast::NewExpression<'a>) {
            if node
                .arguments
                .first()
                .and_then(wa_oxc::arg_expr)
                .and_then(wa_oxc::as_string_lit)
                == Some("groupNotificationParser")
                && let Some(oxc_ast::ast::Expression::FunctionExpression(callback)) = node
                    .arguments
                    .get(1)
                    .and_then(wa_oxc::arg_expr)
                    .map(oxc_ast::ast::Expression::without_parentheses)
                && let Some(body) = &callback.body
            {
                self.hashes.push(fingerprint(&[
                    &self.source[..body.span.start as usize],
                    &self.source[body.span.end as usize..],
                ]));
            }
            walk::walk_new_expression(self, node);
        }
        fn visit_function(
            &mut self,
            function: &Function<'a>,
            flags: oxc_syntax::scope::ScopeFlags,
        ) {
            if let Some(body) = &function.body {
                struct Reads(bool);
                impl<'a> Visit<'a> for Reads {
                    fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
                        if wa_oxc::callee_method(call) == Some("attrString")
                            && call
                                .arguments
                                .first()
                                .and_then(wa_oxc::arg_expr)
                                .and_then(wa_oxc::as_string_lit)
                                == Some("unlink_type")
                        {
                            self.0 = true
                        }
                        walk::walk_call_expression(self, call)
                    }
                }
                let mut reads = Reads(false);
                reads.visit_function_body(body);
                if reads.0 {
                    self.hashes.push(fingerprint(&[
                        &self.source[..body.span.start as usize],
                        &self.source[body.span.end as usize..],
                    ]));
                }
            }
            walk::walk_function(self, function, flags);
        }
    }
    let alloc = oxc_allocator::Allocator::default();
    let parsed = wa_oxc::parse_cjs(&alloc, source);
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err("invalid group qualification source".into());
    }
    let mut probe = Probe {
        source,
        hashes: vec![],
    };
    probe.visit_program(&parsed.program);
    let legacy = probe.hashes.iter().any(|hash| {
        hash == LEGACY_FRAME
            || hash == "f3c64ae496e0e8da4d0ffc79486a11cc3c18eac5533a0a2576c29e938aa92fe8"
    });
    let current = probe
        .hashes
        .iter()
        .any(|hash| hash == &CURRENT.module_frame || hash == &CURRENT.unlink_context);
    match (legacy, current) {
        (true, false) => Ok(false),
        (false, true) => Ok(true),
        _ => Err("unqualified opaque group module frame".into()),
    }
}

pub(crate) fn diagnostic_cache(source: &str) -> Result<&'static str, String> {
    Ok(if current_handler(source)? {
        CURRENT.diagnostic_cache.as_str()
    } else {
        DIAGNOSTIC_CACHE
    })
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
        || CURRENT
            .providers
            .get(module)
            .is_some_and(|hash| wa_text::sha256_hex(source.as_bytes()) == *hash)
}

/// Check supplied dependencies even when their initialization only affects a
/// different module. Unknown slices may coexist in a complete bundle, but the
/// group-specific resolver must never consume an unqualified provider.
pub(crate) fn validate_providers(
    slices: &std::collections::HashMap<&str, &str>,
) -> Result<(), String> {
    let current = slices
        .get("WAWebHandleGroupNotification")
        .map(|source| current_handler(source))
        .transpose()?
        .unwrap_or(false);
    if current {
        for (module, hash) in &CURRENT.providers {
            if let Some(source) = slices.get(module.as_str())
                && wa_text::sha256_hex(source.as_bytes()) != *hash
            {
                return Err(format!(
                    "unqualified group provider initialization: {module}"
                ));
            }
        }
        return Ok(());
    }
    for &(module, _) in PROVIDER_HASHES {
        if let Some(source) = slices.get(module)
            && !PROVIDER_HASHES.iter().any(|(name, hash)| {
                name == &module && wa_text::sha256_hex(source.as_bytes()) == *hash
            })
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
    let current = current_handler(source)?;
    let expected = match kind {
        "LINK" if current => CURRENT.link_context.as_str(),
        "UNLINK" if current => CURRENT.unlink_context.as_str(),
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
        != if current_handler(source)? {
            CURRENT.module_frame.as_str()
        } else {
            LEGACY_FRAME
        }
    {
        return Err("unqualified opaque group module frame".into());
    }
    Ok(())
}

pub(crate) fn actions(source: &str, callback: &Function<'_>) -> Result<BTreeSet<String>, String> {
    let text = source
        .get(callback.span.start as usize..callback.span.end as usize)
        .ok_or("action callback span")?;
    if fingerprint(&[text])
        != if current_handler(source)? {
            CURRENT.actions.as_str()
        } else {
            "55083eab54fbaa69a6706a0c5c0fbcd17d7f9cd9239ace333197a46402ce6692"
        }
    {
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
    if fingerprint(&chunks)
        != if current_handler(source)? {
            CURRENT.helpers.as_str()
        } else {
            "59819f4ce7d98e07ee02c2f7bd69ed1108a666dcb2eadd26ed504c4eab040683"
        }
    {
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
    source: &str,
    locals: impl Iterator<Item = &'a str>,
    opaque_references: &BTreeSet<String>,
) -> Result<(), String> {
    const ORIGINAL_ROOT_LOCALS: &[&str] = &[
        "e", "t", "n", "a", "i", "l", "s", "u", "c", "d", "p", "_", "f", "g", "h", "C", "D", "x",
    ];
    let original: BTreeSet<&str> = if current_handler(source)? {
        CURRENT.root_locals.iter().map(String::as_str).collect()
    } else {
        ORIGINAL_ROOT_LOCALS.iter().copied().collect()
    };
    let locals: BTreeSet<_> = locals.collect();
    for name in opaque_references {
        if name != "e" && original.contains(name.as_str()) && !locals.contains(name.as_str()) {
            return Err(format!("opaque root capture is no longer bound: {name}"));
        }
    }
    for name in locals {
        if opaque_references.contains(name) && !original.contains(name) {
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

#[cfg(test)]
mod current_tests {
    use std::collections::HashMap;
    use wa_ir::{
        group_envelope::GroupEnvelopeContract, group_link::GroupLinkContract,
        group_normalization::GroupUnlinkContract,
    };

    fn sources() -> HashMap<String, String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/groups/versions/2.3000.1052559453/sources");
        std::fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_stem().unwrap().to_str().unwrap().to_string(),
                    std::fs::read_to_string(path).unwrap(),
                )
            })
            .collect()
    }
    fn borrowed(sources: &HashMap<String, String>) -> HashMap<&str, &str> {
        sources
            .iter()
            .map(|(name, source)| (name.as_str(), source.as_str()))
            .collect()
    }
    fn rejected(sources: &HashMap<String, String>) {
        let slices = borrowed(sources);
        assert!(crate::group_envelope::extract_group_envelope(&slices).is_err());
        assert!(crate::group_link::extract_link(&slices).is_err());
        assert!(crate::group_normalization::extract_unlink(&slices).is_err());
    }
    #[test]
    fn exact_current_snapshot_reproduces_all_three_contracts() {
        let sources = sources();
        let slices = borrowed(&sources);
        let expected: GroupEnvelopeContract =
            serde_json::from_str(include_str!("../../../generated/notif/group-envelope.json"))
                .unwrap();
        assert_eq!(
            crate::group_envelope::extract_group_envelope(&slices).unwrap(),
            expected
        );
        let expected: GroupLinkContract =
            serde_json::from_str(include_str!("../../../generated/notif/group-link.json")).unwrap();
        assert_eq!(crate::group_link::extract_link(&slices).unwrap(), expected);
        let expected: GroupUnlinkContract =
            serde_json::from_str(include_str!("../../../generated/notif/group-unlink.json"))
                .unwrap();
        assert_eq!(
            crate::group_normalization::extract_unlink(&slices).unwrap(),
            expected
        );
    }
    #[test]
    fn current_providers_cannot_be_mutated_or_mixed_with_historical_sources() {
        let sources = sources();
        for name in sources
            .keys()
            .filter(|name| name.as_str() != "WAWebHandleGroupNotification")
        {
            let mut changed = sources.clone();
            changed
                .get_mut(name)
                .unwrap()
                .push_str(";throw Error('effect')");
            rejected(&changed);
            let old = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/conformance/groups/sources")
                .join(format!("{name}.js"));
            if let Ok(old) = std::fs::read_to_string(old)
                && old != sources[name]
            {
                let mut changed = sources.clone();
                changed.insert(name.clone(), old);
                rejected(&changed);
            }
        }
    }
    #[test]
    fn warning_null_effects_and_module_caches_fail_closed_on_drift() {
        for (old, new) in [
            ("group-unrecognized-link-type", "changed-link-event"),
            ("group-unrecognized-unlink-type", "changed-unlink-event"),
            ("Unrecognized link_type: ", "changed link message "),
            ("Unrecognized unlink_type: ", "changed unlink message "),
            ("s==null?", "s===null?"),
            ("i==null?", "i===null?"),
            ("WARN(m||(m=", "WARN(p||(p="),
        ] {
            let mut sources = sources();
            let source = sources.get_mut("WAWebHandleGroupNotification").unwrap();
            let changed = source.replacen(old, new, 1);
            assert_ne!(*source, changed, "{old}");
            *source = changed;
            rejected(&sources);
        }
    }
    #[test]
    fn warning_effect_cannot_hide_in_a_discarded_initializer() {
        let mut sources = sources();
        let source = sources.get_mut("WAWebHandleGroupNotification").unwrap();
        let expression = &super::CURRENT.unlink_warning_null.source;
        let anchor = "function D(e){";
        *source = source.replacen(anchor, &format!("{anchor}var discarded=({expression});"), 1);
        assert!(crate::group_normalization::extract_unlink(&borrowed(&sources)).is_err());
    }
}
