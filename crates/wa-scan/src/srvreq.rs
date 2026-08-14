//! Server-initiated request read-shape scanning: the field trees WA Web parses out
//! of stanzas the *server pushes* to the client (`WASmaxIn<X>Request` modules).
//!
//! Each such module is a smax parser written as the same Result-railway a
//! `WASmaxIn<X>ResponseSuccess` uses, so we recover it with the shared
//! [`analyze_module_exports`] machinery (assertions + a [`ParsedResponse`] field
//! tree, with cross-module payload mixins resolved by the [`Resolver`]).
//!
//! A module may export several parsers: the top-level one plus inner child parsers
//! it recurses into (`WASmaxIn<X>Request` → `parse<X>Request` and, e.g.,
//! `parse<X>RequestPairDeviceRef`). We catalog only the **root**: the export not
//! named as an extension of another export (child names are `<root><Suffix>`) that
//! also asserts a recognized top-level stanza tag. Ambiguity → drop (an inner
//! parser asserting a child-element tag never survives the tag gate).

use std::collections::{HashMap, HashSet};

use wa_ir::{AssertionKind, ServerRequestDef, ServerRequestTag};
use wa_transform::ModuleDefinition;

use crate::response_smax::{Resolver, analyze_module_exports};

/// The top-level stanza tags a server-initiated request dispatches on. `None` for a
/// child-element tag (`action`/`ref`/`group`/…) or any tag outside this domain,
/// which drops the parser (fail-safe: never catalog a non-top-level shape).
fn server_request_tag(tag: &str) -> Option<ServerRequestTag> {
    Some(match tag {
        "notification" => ServerRequestTag::Notification,
        "iq" => ServerRequestTag::Iq,
        "ib" => ServerRequestTag::Ib,
        "presence" => ServerRequestTag::Presence,
        "chatstate" => ServerRequestTag::Chatstate,
        "message" => ServerRequestTag::Message,
        "status" => ServerRequestTag::Status,
        _ => return None,
    })
}

/// A `WASmaxIn<X>Request` module that defines a server-initiated request read-shape.
/// Excludes error-response variants (`WASmaxIn<X>Response<V>InvalidRequest`, already
/// covered as iq response variants) and mixin fragments (`…Mixin`, folded into a
/// parent, not standalone).
fn is_server_request_module(name: &str) -> bool {
    name.starts_with("WASmaxIn")
        && name.ends_with("Request")
        && !name.contains("Response")
        && !name.contains("Mixin")
}

/// Scan every server-initiated request read-shape a bundle defines: each
/// `WASmaxIn<X>Request` module's root parser, with its field tree recovered.
pub fn scan_server_requests_from_modules(
    source: &str,
    defs: &[ModuleDefinition],
) -> Vec<ServerRequestDef> {
    // Every module name → slice (first occurrence wins; shard dedup) so the resolver
    // can chase the cross-module payload mixins these parsers call.
    let mut slices: HashMap<&str, &str> = HashMap::new();
    for m in defs {
        slices
            .entry(m.name.as_str())
            .or_insert(&source[m.start..m.end]);
    }
    let resolver = Resolver::new(&slices);

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in defs {
        if !is_server_request_module(&m.name) || !seen.insert(m.name.as_str()) {
            continue;
        }
        let exports = analyze_module_exports(&source[m.start..m.end], &resolver);
        for (name, shape) in &exports {
            // Skip inner child parsers: their export name extends another export's
            // at a word boundary (`<root><ChildSuffix>`, PascalCase), and their fields
            // are already nested in the root's tree. Requiring the suffix to start on a
            // word boundary (an uppercase char) keeps a bare-substring sibling — e.g.
            // `parseFoobar` vs `parseFoo` — from being misread as a child; only a root
            // (extended by no sibling) is a candidate.
            let is_child = exports.iter().any(|(other, _)| {
                if other == name {
                    return false;
                }
                name.strip_prefix(other.as_str())
                    .is_some_and(|suffix| suffix.starts_with(char::is_uppercase))
            });
            if is_child {
                continue;
            }
            // The root's `assertTag("…")` is the dispatched stanza tag. A parser that
            // asserts a non-top-level tag (or none) is dropped by the tag gate.
            let tag = shape
                .assertions
                .iter()
                .find(|a| a.kind == AssertionKind::Tag)
                .and_then(|a| a.name.as_deref())
                .and_then(server_request_tag);
            if let Some(tag) = tag {
                let mut shape = shape.clone();
                // A same-node payload mixin re-asserts the stanza tag its caller
                // already checked, so the recovered assertion list can carry an
                // identical (tag / literal-pin) entry more than once. Collapse exact
                // duplicates, keeping first occurrence — the distinct discriminators
                // (tag + any pinned `type`/`xmlns`) are the routing key a consumer
                // needs; the repeat carries no extra information.
                let mut deduped = Vec::with_capacity(shape.assertions.len());
                for a in std::mem::take(&mut shape.assertions) {
                    if !deduped.contains(&a) {
                        deduped.push(a);
                    }
                }
                shape.assertions = deduped;
                out.push(ServerRequestDef {
                    tag,
                    module: m.name.clone(),
                    shape,
                });
            }
        }
    }
    // Deterministic order, independent of bundle layout; then drop exact
    // (tag, module, parser) duplicates.
    out.sort_by(|a, b| {
        (a.tag as u8)
            .cmp(&(b.tag as u8))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.shape.parser_name.cmp(&b.shape.parser_name))
    });
    out.dedup_by(|a, b| {
        a.tag == b.tag && a.module == b.module && a.shape.parser_name == b.shape.parser_name
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bundle: &str) -> Vec<ServerRequestDef> {
        let defs = wa_transform::extract_module_definitions(bundle);
        scan_server_requests_from_modules(bundle, &defs)
    }

    #[test]
    fn captures_self_contained_ib_request() {
        // The real `WASmaxInClientExpirationClientExpirationRequest`: no cross-module
        // mixin, `ib` tag, a `flattenedChildWithTag` descent, and an optional int.
        let bundle = r#"__d("WASmaxInClientExpirationClientExpirationRequest",["WAResultOrError","WASmaxParseJid","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"ib");if(!t.success)return t;var n=o("WASmaxParseUtils").flattenedChildWithTag(e,"client_expiration");if(!n.success)return n;var r=o("WASmaxParseJid").literalJid(o("WASmaxParseJid").attrDomainJid,e,"from","s.whatsapp.net");if(!r.success)return r;var a=o("WASmaxParseUtils").optional(o("WASmaxParseUtils").attrIntRange,n.value,"t",0,void 0);return a.success?o("WAResultOrError").makeResult({from:r.value,clientExpirationT:a.value}):a}l.parseClientExpirationRequest=e}),98);"#;
        let got = scan(bundle);
        assert_eq!(got.len(), 1);
        let d = &got[0];
        assert_eq!(d.tag, ServerRequestTag::Ib);
        assert_eq!(d.module, "WASmaxInClientExpirationClientExpirationRequest");
        assert_eq!(d.shape.parser_name, "parseClientExpirationRequest");
        assert!(d.shape.fields.iter().any(|f| f.name == "from"));
        let t = d
            .shape
            .fields
            .iter()
            .find(|f| f.name == "clientExpirationT")
            .expect("optional int field");
        assert!(!t.parser_required);
    }

    #[test]
    fn selects_root_and_drops_inner_child_parsers() {
        // A multi-export module: the root asserts the top-level `iq`, an inner parser
        // asserts the child `ref`. Only the root is catalogued; the inner (child) tag
        // is not a server-request tag and is prefixed by the root's name anyway.
        let bundle = r#"__d("WASmaxInMdSetToCompanionRequest",["WAResultOrError","WASmaxParseJid","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"ref");if(!t.success)return t;var n=o("WASmaxParseUtils").contentBytes(e);return n.success?o("WAResultOrError").makeResult({elementValue:n.value}):n}function s(t){var n=o("WASmaxParseUtils").assertTag(t,"iq");if(!n.success)return n;var r=o("WASmaxParseUtils").flattenedChildWithTag(t,"pair-device");if(!r.success)return r;var a=o("WASmaxParseJid").literalJid(o("WASmaxParseJid").attrDomainJid,t,"from","s.whatsapp.net");if(!a.success)return a;var s=o("WASmaxParseUtils").mapChildrenWithTag(r.value,"ref",6,6,e);return s.success?o("WAResultOrError").makeResult(babelHelpers.extends({from:a.value},{pairDeviceRef:s.value})):s}l.parseSetToCompanionRequestPairDeviceRef=e,l.parseSetToCompanionRequest=s}),98);"#;
        let got = scan(bundle);
        assert_eq!(got.len(), 1, "only the root parser is catalogued");
        assert_eq!(got[0].tag, ServerRequestTag::Iq);
        assert_eq!(got[0].shape.parser_name, "parseSetToCompanionRequest");
    }

    #[test]
    fn root_selection_survives_many_child_parsers() {
        // The real 6-export CTWA banner module shape: five inner child parsers named
        // `parseBannerSuggestionRequest<Suffix>` plus the root `parseBannerSuggestionRequest`
        // asserting the top-level `notification` (type "business"). Only the root survives.
        let bundle = r#"__d("WASmaxInBizCtwaActionBannerSuggestionRequest",["WAResultOrError","WASmaxParseJid","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"action");if(!t.success)return t;var n=o("WASmaxParseUtils").optional(o("WASmaxParseUtils").attrString,e,"deep_link");return n.success?o("WAResultOrError").makeResult({deepLink:n.value}):n}function s(e){var t=o("WASmaxParseUtils").assertTag(e,"localised_heading");if(!t.success)return t;var r=o("WASmaxParseUtils").attrString(e,"value");return r.success?o("WAResultOrError").makeResult({value:r.value}):r}function u(e){var t=o("WASmaxParseUtils").assertTag(e,"localised_body");if(!t.success)return t;var r=o("WASmaxParseUtils").attrString(e,"value");return r.success?o("WAResultOrError").makeResult({value:r.value}):r}function c(e){var t=o("WASmaxParseUtils").assertTag(e,"localised_highlight");if(!t.success)return t;var r=o("WASmaxParseUtils").attrString(e,"value");return r.success?o("WAResultOrError").makeResult({value:r.value}):r}function d(e){var t=o("WASmaxParseUtils").assertTag(e,"banner");if(!t.success)return t;var r=o("WASmaxParseUtils").attrString(e,"headline");return r.success?o("WAResultOrError").makeResult({headline:r.value}):r}function m(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString,e,"type","business");if(!n.success)return n;var r=o("WASmaxParseUtils").optionalChildWithTag(e,"banner",d);return r.success?o("WAResultOrError").makeResult({type:n.value,banner:r.value}):r}l.parseBannerSuggestionRequestCtwaSuggestionBannerAction=e,l.parseBannerSuggestionRequestCtwaSuggestionBannerContentLocalisedHeading=s,l.parseBannerSuggestionRequestCtwaSuggestionBannerContentLocalisedBody=u,l.parseBannerSuggestionRequestCtwaSuggestionBannerContentLocalisedHighlight=c,l.parseBannerSuggestionRequestCtwaSuggestionBanner=d,l.parseBannerSuggestionRequest=m}),98);"#;
        let got = scan(bundle);
        assert_eq!(got.len(), 1, "only the root, not the 5 child parsers");
        assert_eq!(got[0].tag, ServerRequestTag::Notification);
        assert_eq!(got[0].shape.parser_name, "parseBannerSuggestionRequest");
        // The pinned `type="business"` discriminator is preserved as an assertion.
        assert!(
            got[0]
                .shape
                .assertions
                .iter()
                .any(|a| a.kind == AssertionKind::Attr
                    && a.name.as_deref() == Some("type")
                    && a.value.as_deref() == Some("business")),
            "notification type discriminator preserved"
        );
    }

    #[test]
    fn dedupes_bubbled_tag_assertion() {
        // The root asserts `notification` and calls a same-node mixin that *also*
        // asserts `notification`; the recovered list must keep one tag assertion (the
        // distinct `type` pin stays), not the raw duplicate the bubbling produces.
        let bundle = r#"
            __d("WASmaxInAcmeServerNotificationMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"id");return n.success?o("WAResultOrError").makeResult({id:n.value}):n}l.parseServerNotificationMixin=e}),1);
            __d("WASmaxInAcmeThingNotificationRequest",["WASmaxInAcmeServerNotificationMixin","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").literal(o("WASmaxParseUtils").attrString,e,"type","acme");if(!n.success)return n;var r=o("WASmaxInAcmeServerNotificationMixin").parseServerNotificationMixin(e);return r.success?o("WAResultOrError").makeResult(babelHelpers.extends({type:n.value},r.value)):r}l.parseThingNotificationRequest=e}),1);
        "#;
        let got = scan(bundle);
        assert_eq!(got.len(), 1);
        let a = &got[0].shape.assertions;
        assert_eq!(
            a.iter().filter(|x| x.kind == AssertionKind::Tag).count(),
            1,
            "the bubbled duplicate tag assertion is collapsed"
        );
        assert!(
            a.iter().any(|x| x.kind == AssertionKind::Attr
                && x.name.as_deref() == Some("type")
                && x.value.as_deref() == Some("acme")),
            "the distinct type discriminator is preserved"
        );
    }

    #[test]
    fn word_boundary_keeps_bare_prefix_sibling() {
        // Two independent roots in one module whose names share a leading substring
        // that is *not* a word boundary (`parseThing` vs `parseThingy`): the child
        // check must not treat `parseThingy` as an extension of `parseThing` (the
        // suffix `y` is lowercase, not a `<root><ChildSuffix>` boundary), so both
        // survive. A raw `starts_with` would have silently dropped one.
        let bundle = r#"__d("WASmaxInAcmeThingNotificationRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"a");return n.success?o("WAResultOrError").makeResult({a:n.value}):n}function s(e){var t=o("WASmaxParseUtils").assertTag(e,"ib");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"b");return n.success?o("WAResultOrError").makeResult({b:n.value}):n}l.parseThing=e,l.parseThingy=s}),1);"#;
        let got = scan(bundle);
        assert_eq!(
            got.len(),
            2,
            "a bare-substring sibling is not dropped as a child"
        );
        let names: Vec<&str> = got.iter().map(|d| d.shape.parser_name.as_str()).collect();
        assert!(names.contains(&"parseThing") && names.contains(&"parseThingy"));
    }

    #[test]
    fn excludes_error_variants_and_mixins() {
        // A `*ResponseInvalidRequest` (iq error variant) and a `*Mixin` fragment are
        // both out of scope; a plain `*Request` is in.
        let bundle = r#"
            __d("WASmaxInBlocklistsGetBlockListResponseInvalidRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"iq");if(!t.success)return t;return o("WAResultOrError").makeResult({})}l.parseGetBlockListResponseInvalidRequest=e}),1);
            __d("WASmaxInMdServerNotificationMixin",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").attrString(e,"id");return t.success?o("WAResultOrError").makeResult({id:t.value}):t}l.parseServerNotificationMixin=e}),1);
            __d("WASmaxInPresenceServerUpdateRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"presence");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"from");return n.success?o("WAResultOrError").makeResult({from:n.value}):n}l.parseServerUpdateRequest=e}),1);
        "#;
        let got = scan(bundle);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].tag, ServerRequestTag::Presence);
        assert_eq!(got[0].module, "WASmaxInPresenceServerUpdateRequest");
    }

    #[test]
    fn is_ordered_and_deduped() {
        // Two distinct modules; output is sorted by (tag, module) and shard-duplicate
        // module declarations collapse.
        let bundle = r#"
            __d("WASmaxInStatusDeliverIncomingNewsletterStatusRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"status");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"id");return n.success?o("WAResultOrError").makeResult({id:n.value}):n}l.parseIncomingNewsletterStatusRequest=e}),1);
            __d("WASmaxInChatstateServerNotificationRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"chatstate");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"from");return n.success?o("WAResultOrError").makeResult({from:n.value}):n}l.parseServerNotificationRequest=e}),1);
            __d("WASmaxInChatstateServerNotificationRequest",["WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"chatstate");if(!t.success)return t;var n=o("WASmaxParseUtils").attrString(e,"from");return n.success?o("WAResultOrError").makeResult({from:n.value}):n}l.parseServerNotificationRequest=e}),1);
        "#;
        let got = scan(bundle);
        assert_eq!(got.len(), 2, "shard-duplicate module collapses");
        // `iq`(1) < `chatstate`(4) < `status`(6) by enum order → chatstate before status.
        assert_eq!(got[0].tag, ServerRequestTag::Chatstate);
        assert_eq!(got[1].tag, ServerRequestTag::Status);
    }
}
