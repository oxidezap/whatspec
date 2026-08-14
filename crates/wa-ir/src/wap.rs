//! Canonical WAP response-parser accessor method names and their classification,
//! shared by the scanner (`wa-scan`) and the codegen (`wa-codegen`) so the two
//! can't drift — a past drift silently dropped `maybeAttrEnum`. Pure and
//! dependency-free, so it stays WASM-safe like the rest of the IR contract.

use crate::{ParsedField, ParsedFieldType, UnknownValuePolicy};

// Attribute accessors.
pub const ATTR_STRING: &str = "attrString";
pub const ATTR_INT: &str = "attrInt";
pub const ATTR_ENUM: &str = "attrEnum";
pub const MAYBE_ATTR_STRING: &str = "maybeAttrString";
pub const MAYBE_ATTR_INT: &str = "maybeAttrInt";
pub const MAYBE_ATTR_ENUM: &str = "maybeAttrEnum";
pub const ATTR_ENUM_VALUES: &str = "attrEnumValues";
pub const ATTR_DEVICE_JID: &str = "attrDeviceJid";
pub const ATTR_GROUP_JID: &str = "attrGroupJid";
pub const ATTR_JID_WITH_TYPE: &str = "attrJidWithType";
pub const HAS_ATTR: &str = "hasAttr";

// Timestamp accessors (unix seconds) — pervasive in incoming notifications.
pub const ATTR_TIME: &str = "attrTime";
pub const MAYBE_ATTR_TIME: &str = "maybeAttrTime";

// JID-typed accessors beyond the IQ set. WA has one accessor per JID flavor; each
// decodes to a `Jid` but validates a distinct server/format. The flavor is kept (see
// `method_field_type`) — not collapsed — because it is protocol-safety-critical: a LID
// user JID and a PN user JID are different identities for the same person.
pub const ATTR_USER_JID: &str = "attrUserJid";
pub const MAYBE_ATTR_USER_JID: &str = "maybeAttrUserJid";
pub const ATTR_WAP_JID: &str = "attrWapJid";
pub const ATTR_CHAT_JID: &str = "attrChatJid";
pub const ATTR_FROM_JID: &str = "attrFromJid";
pub const ATTR_LID_USER_JID: &str = "attrLidUserJid";
pub const MAYBE_ATTR_LID_USER_JID: &str = "maybeAttrLidUserJid";
pub const ATTR_LID_DEVICE_JID: &str = "attrLidDeviceJid";
pub const ATTR_NEWSLETTER_JID: &str = "attrNewsletterJid";
pub const ATTR_CALL_JID: &str = "attrCallJid";
pub const ATTR_BROADCAST_JID: &str = "attrBroadcastJid";
pub const ATTR_STATUS_JID: &str = "attrStatusJid";

// Content accessors.
pub const CONTENT_BYTES: &str = "contentBytes";
pub const CONTENT_STRING: &str = "contentString";
pub const CONTENT_INT: &str = "contentInt";

// Child accessors.
pub const CHILD: &str = "child";
pub const MAYBE_CHILD: &str = "maybeChild";
pub const FOR_EACH_CHILD_WITH_TAG: &str = "forEachChildWithTag";
pub const MAP_CHILDREN: &str = "mapChildren";
pub const MAP_CHILDREN_WITH_TAG: &str = "mapChildrenWithTag";

/// The child-producing accessors (a `child`/`maybeChild` or a `map*`/`forEach*`).
pub fn is_child_method(m: &str) -> bool {
    matches!(
        m,
        CHILD | MAYBE_CHILD | FOR_EACH_CHILD_WITH_TAG | MAP_CHILDREN | MAP_CHILDREN_WITH_TAG
    )
}

/// Content accessors — every spelling that reads the element's content rather than an
/// attribute, whatever it decodes to. The single source of truth for the question, so a
/// caller cannot recognise a subset: teaching [`method_field_type`] about `contentUint`
/// while a reader still whitelisted three spellings made those fields drop out entirely
/// instead of being typed.
pub fn is_content_method(m: &str) -> bool {
    matches!(
        m,
        CONTENT_STRING
            | CONTENT_BYTES
            | CONTENT_INT
            | "contentUint"
            | "contentEnum"
            | "contentStringEnum"
            | "contentBytesRange"
            | "contentLiteralBytes"
    )
}

/// The attribute value accessors (`attr*` / `maybeAttr*`, including the typed-JID
/// ones). Excludes content accessors and `hasAttr` — callers that also treat
/// those as fields combine this with the relevant content/`hasAttr` checks. This
/// is the single source of truth for "is this method an attribute accessor",
/// shared by the scanner and the codegen so the two can't drift.
pub fn is_attr_method(m: &str) -> bool {
    // Derived from the spelling, not enumerated. Every accessor WA names `attr…` /
    // `maybeAttr…` reads an attribute; `hasAttr` is the presence test, not a read, and
    // the `…FromReference` helpers read off the REQUEST rather than the node.
    //
    // Enumerating was the bug: the list drifted from `method_field_type`, so giving a JID
    // accessor its own name instead of collapsing it onto `attrJidWithType` silently
    // dropped 85 lines of generated code — the fields fell outside the list and stopped
    // being treated as attribute reads at all.
    // `literalJid` is an attribute read too — it reads a JID attribute and pins it to a
    // value — while `literalContent` pins the element's content and names no attribute.
    let literal_attr = m.starts_with("literal") && !m.contains("Content");
    let attr = (m.starts_with("attr") || m.starts_with("maybeAttr")) && m != HAS_ATTR;
    (attr || literal_attr) && !m.ends_with("FromReference")
}

/// `maybe*` accessors decode to optional / non-required fields.
pub fn is_optional_method(m: &str) -> bool {
    m.starts_with("maybe")
}

/// The scalar [`ParsedFieldType`] a response accessor decodes to.
///
/// `maybeAttrX` is derived from `attrX` rather than enumerated beside it. The two decode
/// identically — the `maybe` spelling only tolerates absence — so listing both invites
/// exactly the bug that motivated this: `maybeAttrPhoneUserJid` was missing from the
/// table and reported a PN user JID as a bare `string`, the conflation this module's own
/// note calls protocol-safety-critical. Deriving means a flavour added to the table
/// covers both spellings, and one that is never added defaults visibly for both.
pub fn method_field_type(m: &str) -> ParsedFieldType {
    if let Some(rest) = m.strip_prefix("maybe")
        && let Some(first) = rest.chars().next()
    {
        let attr: String = first.to_lowercase().chain(rest.chars().skip(1)).collect();
        return method_field_type(&attr);
    }
    match m {
        ATTR_STRING => ParsedFieldType::String,
        // An enum accessor decodes to an enum, not a bare string. The smax side already
        // types these `Enum` through its own normalizer, so mapping them to `String` here
        // made one concept two types across domains — 486 fields said `enum` and 28 said
        // `string` for the same accessors — and left an `enumRef` hanging off a field a
        // consumer filtering on `type == "enum"` would never look at.
        ATTR_ENUM | ATTR_ENUM_VALUES => ParsedFieldType::Enum,
        // `attrFutureTime` range-checks a unix time it read with `attrInt`; `contentUint`
        // decodes an unsigned integer out of the content bytes.
        ATTR_INT | ATTR_TIME | "attrIntRange" | "attrFutureTime" | CONTENT_INT | "contentUint" => {
            ParsedFieldType::Integer
        }
        // Each JID accessor pins the flavor (server/format) it validates. Keeping the
        // flavor — rather than collapsing to a bare `Jid` — is protocol-safety-critical:
        // a LID user JID and a PN user JID are different identities for the same person.
        ATTR_USER_JID => ParsedFieldType::UserJid,
        // The `phone*` spellings are the explicit-PN aliases of the plain user/device
        // accessors.
        "attrPhoneUserJid" => ParsedFieldType::UserJid,
        "attrPhoneDeviceJid" => ParsedFieldType::DeviceJid,
        ATTR_LID_USER_JID => ParsedFieldType::LidUserJid,
        ATTR_DEVICE_JID => ParsedFieldType::DeviceJid,
        ATTR_LID_DEVICE_JID => ParsedFieldType::LidDeviceJid,
        ATTR_GROUP_JID => ParsedFieldType::GroupJid,
        ATTR_NEWSLETTER_JID => ParsedFieldType::NewsletterJid,
        ATTR_CALL_JID => ParsedFieldType::CallJid,
        ATTR_BROADCAST_JID => ParsedFieldType::BroadcastJid,
        ATTR_STATUS_JID => ParsedFieldType::StatusJid,
        // `attrFromJidChat` / `attrFromJidPhoneChat` both delegate to `attrJidWithType`.
        ATTR_JID_WITH_TYPE | "attrJidEnum" | "attrFromJidChat" | "attrFromJidPhoneChat" => {
            ParsedFieldType::JidTyped
        }
        // `attrWapJid`/`attrChatJid`/`attrFromJid` accept more than one flavor
        // (a chat is a user or a group), so they stay a generic `Jid`.
        ATTR_WAP_JID | ATTR_CHAT_JID | ATTR_FROM_JID => ParsedFieldType::Jid,
        // Multi-flavor accessors: a chat is a user OR a group, `attrDomainJid`/`attrLidJid`
        // accept more than one server, so they stay a generic JID rather than a string.
        "attrJid" | "literalJid" | "attrPhoneChatJid" | "attrDomainJid" | "attrLidJid"
        | "attrFromPhoneJid" => ParsedFieldType::Jid,
        // The enum accessors, whose raw spellings the legacy parsers use directly.
        // `contentEnum` reads the content as a string and looks it up.
        "attrStringEnum" | "contentStringEnum" | "contentEnum" | "attrEnumOrNullIfUnknown" => {
            ParsedFieldType::Enum
        }
        // Every content accessor that yields raw bytes, whatever length rule it applies.
        CONTENT_BYTES | "contentBytesRange" | "contentLiteralBytes" => ParsedFieldType::Bytes,
        _ => ParsedFieldType::String,
    }
}

/// Whether an accessor validates what it reads against an enum table **the IR carries**,
/// and so has an out-of-set behaviour a consumer can act on. `attrString` accepts
/// whatever is there and has none.
///
/// Derived from [`method_field_type`] rather than from a second list of spellings — a
/// table kept twice drifts, and the half that drifts is the one nobody is looking at.
/// Reading it off the decoded type is also what makes the condition the right one: the
/// enum-linking pass only resolves a field's `enumRef` when the field decodes to
/// [`ParsedFieldType::Enum`], so "the accessor checks a table" and "the IR publishes that
/// table" are the same question.
///
/// The JID accessors are deliberately outside it, `attrJidEnum` included. They do reject
/// an unrecognised server — but they decode to [`ParsedFieldType::JidTyped`], the linker
/// never resolves their argument, and all 34 `attrJidEnum` fields carry neither `enumRef`
/// nor `enumKeys`. A policy on them would tell a consumer that values outside a set are
/// rejected while naming no set, which is the unusable state this dimension exists to
/// remove, not to relocate.
pub fn has_closed_value_set(m: &str) -> bool {
    method_field_type(m) == ParsedFieldType::Enum
}

/// What a parser does with a value outside the set the accessor `m` checks against, or
/// `None` when `m` checks against no set at all (see [`has_closed_value_set`]).
///
/// `maybeAttrX` derives from `attrX` here for the same reason it does in
/// [`method_field_type`], and it is worth stating why the derivation is *sound* and not
/// merely convenient: `maybe` governs a value that is **absent**, this governs one that
/// is **present and unrecognised**, and the two are independent. `maybeAttrEnum` yields
/// null for a missing attribute and still rejects `type="wat"` — which is why the
/// optionality already published as `parserRequired` never answered this question.
pub fn method_unknown_value_policy(m: &str) -> Option<UnknownValuePolicy> {
    if !has_closed_value_set(m) {
        return None;
    }
    if let Some(rest) = m.strip_prefix("maybe")
        && let Some(first) = rest.chars().next()
    {
        let attr: String = first.to_lowercase().chain(rest.chars().skip(1)).collect();
        return method_unknown_value_policy(&attr);
    }
    Some(match m {
        // `WAHasProperty(set, v) ? set[v] : null` — the value is dropped, the parse
        // survives, and the field is null on a value this bundle's enum does not list.
        "attrEnumOrNullIfUnknown" => UnknownValuePolicy::Null,
        // The legacy accessors `throw` on a miss (`to have "type"={a|b} but has value
        // "c"`), and their smax counterparts return a failed `ResultOrError` the caller
        // propagates — the node does not parse either way.
        //
        // `attrEnumValues` takes an OPTIONAL third argument it would return instead of
        // throwing; no call site in the bundle passes one, and the argument is not in
        // the IR, so a build where one appears must not keep reading `reject` here.
        ATTR_ENUM | ATTR_ENUM_VALUES | "attrStringEnum" | "contentEnum" | "contentStringEnum" => {
            UnknownValuePolicy::Reject
        }
        // A new enum accessor: visible as unjudged rather than assumed to reject.
        _ => UnknownValuePolicy::Unclassified,
    })
}

/// Stamp [`ParsedField::unknown_value`] from each field's accessor, throughout the
/// subtree (children and union variants alike).
///
/// The policy is a property of the accessor, so it is filled in once here rather than at
/// every site that builds a [`ParsedField`] — five domains build them and the sixth one
/// added would forget. `scripts/lint-ir.py` re-checks the invariant against the emitted
/// documents so a domain that skips this pass fails the build rather than shipping enum
/// fields with no policy.
///
/// A policy already on the field wins. `method` is not always the accessor the client
/// called: where an extractor merges two reads of one attribute it records the merged
/// shape, and re-deriving from that name would answer for an accessor that never ran.
/// Whoever performed the merge knows which accessor decides the out-of-set case and says
/// so; this pass only fills the silence.
pub fn classify_unknown_values(fields: &mut [ParsedField]) {
    for f in fields {
        if f.unknown_value.is_none() {
            f.unknown_value = method_unknown_value_policy(&f.method);
        }
        if let Some(children) = f.children.as_mut() {
            classify_unknown_values(children);
        }
        if let Some(variants) = f.union_variants.as_mut() {
            for v in variants {
                classify_unknown_values(&mut v.fields);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_classification() {
        for m in [
            CHILD,
            MAYBE_CHILD,
            FOR_EACH_CHILD_WITH_TAG,
            MAP_CHILDREN,
            MAP_CHILDREN_WITH_TAG,
        ] {
            assert!(is_child_method(m), "{m}");
        }
        assert!(!is_child_method(ATTR_STRING));
    }

    #[test]
    fn attr_classification() {
        for m in [
            ATTR_STRING,
            ATTR_INT,
            ATTR_ENUM,
            ATTR_ENUM_VALUES,
            MAYBE_ATTR_STRING,
            MAYBE_ATTR_INT,
            MAYBE_ATTR_ENUM,
            ATTR_DEVICE_JID,
            ATTR_GROUP_JID,
            ATTR_JID_WITH_TYPE,
            // Timestamp and extended-JID accessors (notification parsers). Kept here
            // too so dropping one from the `matches!` block trips this test, not just
            // the dedicated `notification_accessors_classified`.
            ATTR_TIME,
            MAYBE_ATTR_TIME,
            ATTR_USER_JID,
            MAYBE_ATTR_USER_JID,
            ATTR_WAP_JID,
            ATTR_CHAT_JID,
            ATTR_FROM_JID,
            ATTR_LID_USER_JID,
            MAYBE_ATTR_LID_USER_JID,
            ATTR_LID_DEVICE_JID,
            ATTR_NEWSLETTER_JID,
            ATTR_CALL_JID,
            ATTR_BROADCAST_JID,
            ATTR_STATUS_JID,
        ] {
            assert!(is_attr_method(m), "{m}");
        }
        // Content accessors, hasAttr, and child accessors are not attr methods.
        for m in [
            CONTENT_BYTES,
            CONTENT_STRING,
            CONTENT_INT,
            HAS_ATTR,
            CHILD,
            MAYBE_CHILD,
        ] {
            assert!(!is_attr_method(m), "{m}");
        }
    }

    #[test]
    fn maybe_spellings_inherit_their_base_accessor() {
        // The rule that replaced enumerating both spellings: a `maybe` variant decodes
        // exactly like its base, so a flavour listed once covers both — and a flavour
        // never listed defaults visibly for both instead of only for the `maybe` half,
        // which is how `maybeAttrPhoneUserJid` came to report a PN user JID as a string.
        for base in [
            ATTR_STRING,
            ATTR_INT,
            ATTR_ENUM,
            ATTR_TIME,
            ATTR_USER_JID,
            ATTR_LID_USER_JID,
            ATTR_GROUP_JID,
            ATTR_DEVICE_JID,
            ATTR_NEWSLETTER_JID,
            "attrPhoneUserJid",
        ] {
            let maybe = format!("maybe{}{}", base[..1].to_uppercase(), &base[1..]);
            assert_eq!(
                method_field_type(&maybe),
                method_field_type(base),
                "{maybe} must decode like {base}"
            );
        }
        // The PN/LID split survives the derivation — the distinction this module calls
        // protocol-safety-critical.
        assert_eq!(
            method_field_type("maybeAttrPhoneUserJid"),
            ParsedFieldType::UserJid
        );
        assert_eq!(
            method_field_type(MAYBE_ATTR_LID_USER_JID),
            ParsedFieldType::LidUserJid
        );
        assert_ne!(
            method_field_type("maybeAttrPhoneUserJid"),
            method_field_type(MAYBE_ATTR_LID_USER_JID)
        );
    }

    #[test]
    fn every_bundle_accessor_is_classified() {
        // The accessors WA's parsers actually use, swept from the bundle. Anything here
        // that falls through to `String` is either genuinely a string or a flavour we are
        // silently dropping — so the list is pinned, and a new one must be judged rather
        // than defaulting quietly.
        for (m, want) in [
            ("attrFutureTime", ParsedFieldType::Integer),
            ("attrIntRange", ParsedFieldType::Integer),
            ("contentUint", ParsedFieldType::Integer),
            ("contentEnum", ParsedFieldType::Enum),
            ("attrStringEnum", ParsedFieldType::Enum),
            ("contentStringEnum", ParsedFieldType::Enum),
            ("attrEnumOrNullIfUnknown", ParsedFieldType::Enum),
            ("contentBytesRange", ParsedFieldType::Bytes),
            ("contentLiteralBytes", ParsedFieldType::Bytes),
            ("maybeAttrGroupJid", ParsedFieldType::GroupJid),
            ("attrPhoneDeviceJid", ParsedFieldType::DeviceJid),
            ("attrFromJidChat", ParsedFieldType::JidTyped),
            ("attrFromJidPhoneChat", ParsedFieldType::JidTyped),
            ("attrJidEnum", ParsedFieldType::JidTyped),
            ("attrDomainJid", ParsedFieldType::Jid),
            ("attrLidJid", ParsedFieldType::Jid),
            ("attrPhoneChatJid", ParsedFieldType::Jid),
            ("attrFromPhoneJid", ParsedFieldType::Jid),
        ] {
            assert_eq!(method_field_type(m), want, "{m}");
        }
        // Genuinely strings: a stanza id, and the reference helpers whose type comes from
        // the accessor they wrap.
        for m in [
            ATTR_STRING,
            CONTENT_STRING,
            "attrStanzaId",
            "attrStringFromReference",
        ] {
            assert_eq!(method_field_type(m), ParsedFieldType::String, "{m}");
        }
    }

    #[test]
    fn every_closed_set_accessor_has_a_policy() {
        // The accessors WA checks a value set with, swept from the bundle, with what its
        // implementation actually does on a miss. `attrEnum` throws
        // (`to have "type"={a|b} but has value "c"`); the smax spellings return a failed
        // `ResultOrError` the caller propagates; `attrEnumOrNullIfUnknown` returns null.
        //
        // Pinned so a spelling that appears in a later bundle has to be judged: an
        // accessor that falls through classifies `Unclassified`, which this asserts none
        // of these does, and which `scripts/lint-ir.py` holds at zero in the emitted
        // documents.
        for (m, want) in [
            (ATTR_ENUM, UnknownValuePolicy::Reject),
            (MAYBE_ATTR_ENUM, UnknownValuePolicy::Reject),
            (ATTR_ENUM_VALUES, UnknownValuePolicy::Reject),
            ("attrStringEnum", UnknownValuePolicy::Reject),
            ("contentEnum", UnknownValuePolicy::Reject),
            ("contentStringEnum", UnknownValuePolicy::Reject),
            ("attrEnumOrNullIfUnknown", UnknownValuePolicy::Null),
        ] {
            assert_eq!(method_unknown_value_policy(m), Some(want), "{m}");
        }
        // An accessor whose table the IR does not carry has no policy — absent is "there
        // is no set here", not "anything goes past a set we forgot". Both JID accessors
        // are deliberately in this half: they do reject an unrecognised server, but the
        // linker never resolves their argument, so a policy would name a set the document
        // does not contain.
        for m in [
            ATTR_STRING,
            ATTR_INT,
            CONTENT_BYTES,
            ATTR_USER_JID,
            HAS_ATTR,
            ATTR_JID_WITH_TYPE,
            "attrJidEnum",
            "attrStringFromReference",
        ] {
            assert_eq!(method_unknown_value_policy(m), None, "{m}");
        }
        // Every accessor the type table calls an enum is judged. `Unclassified` is not
        // reachable by any spelling today, by construction — this is the assertion that
        // keeps it that way, since the state only appears when someone teaches
        // `method_field_type` a new enum accessor and not the table below it.
        // `scripts/lint-ir.py` holds the emitted count of it at zero for the same reason.
        for m in [
            ATTR_ENUM,
            MAYBE_ATTR_ENUM,
            ATTR_ENUM_VALUES,
            "attrStringEnum",
            "contentEnum",
            "contentStringEnum",
            "attrEnumOrNullIfUnknown",
        ] {
            assert!(has_closed_value_set(m), "{m}");
            assert_ne!(
                method_unknown_value_policy(m),
                Some(UnknownValuePolicy::Unclassified),
                "{m} must be judged, not defaulted",
            );
        }
    }

    #[test]
    fn maybe_spellings_inherit_their_unknown_value_policy() {
        // Same derivation rule as `method_field_type`, and it has to be: the two
        // questions are independent. `maybe` says the ATTRIBUTE may be absent; the policy
        // says what happens when it is present with a value the enum does not list.
        // `maybeAttrEnum` is `hasAttr(x) ? attrEnum(x) : null`, so it still rejects
        // `type="wat"` — enumerating the `maybe` spellings separately is how one of them
        // would eventually get the other answer.
        for base in [ATTR_ENUM, ATTR_ENUM_VALUES, "attrStringEnum", "contentEnum"] {
            let maybe = format!("maybe{}{}", base[..1].to_uppercase(), &base[1..]);
            assert_eq!(
                method_unknown_value_policy(&maybe),
                method_unknown_value_policy(base),
                "{maybe} must judge unknown values like {base}",
            );
        }
        assert!(is_optional_method(MAYBE_ATTR_ENUM));
        assert_eq!(
            method_unknown_value_policy(MAYBE_ATTR_ENUM),
            Some(UnknownValuePolicy::Reject),
        );
    }

    #[test]
    fn classification_reaches_children_and_union_variants() {
        // The pass must not stop at the root: an enum field nested under a mixin
        // container or inside a union arm is where the policy matters most, since that is
        // where a generator decides whether to close the enum.
        let leaf = |m: &str| ParsedField {
            method: m.to_string(),
            field_type: method_field_type(m),
            ..Default::default()
        };
        let mut fields = vec![
            ParsedField {
                method: String::new(),
                field_type: ParsedFieldType::Node,
                children: Some(vec![leaf(ATTR_ENUM)]),
                ..Default::default()
            },
            ParsedField {
                method: String::new(),
                field_type: ParsedFieldType::Union,
                union_variants: Some(vec![crate::UnionVariant {
                    name: "A".into(),
                    fields: vec![leaf("attrEnumOrNullIfUnknown")],
                    assertions: vec![],
                }]),
                ..Default::default()
            },
        ];
        classify_unknown_values(&mut fields);
        assert_eq!(fields[0].unknown_value, None, "the container has no set");
        assert_eq!(
            fields[0].children.as_ref().unwrap()[0].unknown_value,
            Some(UnknownValuePolicy::Reject),
        );
        assert_eq!(
            fields[1].union_variants.as_ref().unwrap()[0].fields[0].unknown_value,
            Some(UnknownValuePolicy::Null),
        );
    }

    #[test]
    fn a_policy_the_extractor_already_judged_survives_the_pass() {
        // Where two reads of one attribute are merged into one field, `method` names the
        // merged shape and not the accessor that decides an out-of-set value. Re-deriving
        // from `attrEnum` there would publish a rejection the client does not perform, so
        // a policy already on the field is left alone — including a deliberate
        // `Unclassified`, which must stay visible rather than be overwritten with a guess.
        let mut fields = vec![
            ParsedField {
                method: ATTR_ENUM.into(),
                field_type: ParsedFieldType::Enum,
                unknown_value: Some(UnknownValuePolicy::Null),
                ..Default::default()
            },
            ParsedField {
                method: MAYBE_ATTR_ENUM.into(),
                field_type: ParsedFieldType::Enum,
                unknown_value: Some(UnknownValuePolicy::Unclassified),
                ..Default::default()
            },
            ParsedField {
                method: ATTR_ENUM.into(),
                field_type: ParsedFieldType::Enum,
                ..Default::default()
            },
        ];
        classify_unknown_values(&mut fields);
        assert_eq!(fields[0].unknown_value, Some(UnknownValuePolicy::Null));
        assert_eq!(
            fields[1].unknown_value,
            Some(UnknownValuePolicy::Unclassified)
        );
        assert_eq!(
            fields[2].unknown_value,
            Some(UnknownValuePolicy::Reject),
            "silence is still filled in"
        );
    }

    #[test]
    fn optional_and_field_types() {
        assert!(is_optional_method(MAYBE_ATTR_ENUM));
        assert!(!is_optional_method(ATTR_ENUM));
        // An enum accessor decodes to an enum, matching how the smax normalizer already
        // types the same concept — the two used to disagree across domains.
        assert_eq!(method_field_type(MAYBE_ATTR_ENUM), ParsedFieldType::Enum);
        assert_eq!(method_field_type(ATTR_ENUM), ParsedFieldType::Enum);
        assert_eq!(method_field_type(ATTR_INT), ParsedFieldType::Integer);
        assert_eq!(method_field_type(CONTENT_BYTES), ParsedFieldType::Bytes);
        assert_eq!(
            method_field_type(ATTR_JID_WITH_TYPE),
            ParsedFieldType::JidTyped
        );
    }

    #[test]
    fn notification_accessors_classified() {
        // The accessors incoming-notification parsers add beyond the IQ set.
        for m in [
            ATTR_TIME,
            MAYBE_ATTR_TIME,
            ATTR_USER_JID,
            MAYBE_ATTR_USER_JID,
            ATTR_WAP_JID,
            ATTR_CHAT_JID,
            ATTR_FROM_JID,
            ATTR_LID_USER_JID,
            MAYBE_ATTR_LID_USER_JID,
            ATTR_LID_DEVICE_JID,
            ATTR_NEWSLETTER_JID,
            ATTR_CALL_JID,
            ATTR_BROADCAST_JID,
            ATTR_STATUS_JID,
            ATTR_ENUM_VALUES,
        ] {
            assert!(is_attr_method(m), "{m} should be an attr method");
        }
        // Timestamps decode to integers.
        assert_eq!(method_field_type(ATTR_TIME), ParsedFieldType::Integer);
        assert_eq!(method_field_type(MAYBE_ATTR_TIME), ParsedFieldType::Integer);
        // Each JID accessor keeps its flavor; the LID-vs-PN split is preserved.
        assert_eq!(method_field_type(ATTR_USER_JID), ParsedFieldType::UserJid);
        assert_eq!(
            method_field_type(MAYBE_ATTR_USER_JID),
            ParsedFieldType::UserJid
        );
        assert_eq!(
            method_field_type(ATTR_LID_USER_JID),
            ParsedFieldType::LidUserJid
        );
        assert_eq!(
            method_field_type(MAYBE_ATTR_LID_USER_JID),
            ParsedFieldType::LidUserJid
        );
        assert_eq!(
            method_field_type(ATTR_LID_DEVICE_JID),
            ParsedFieldType::LidDeviceJid
        );
        assert_eq!(
            method_field_type(ATTR_NEWSLETTER_JID),
            ParsedFieldType::NewsletterJid
        );
        assert_eq!(method_field_type(ATTR_CALL_JID), ParsedFieldType::CallJid);
        assert_eq!(
            method_field_type(ATTR_BROADCAST_JID),
            ParsedFieldType::BroadcastJid
        );
        assert_eq!(
            method_field_type(ATTR_STATUS_JID),
            ParsedFieldType::StatusJid
        );
        // The multi-flavor accessors stay a bare Jid (a chat is a user or a group).
        for m in [ATTR_WAP_JID, ATTR_CHAT_JID, ATTR_FROM_JID] {
            assert_eq!(method_field_type(m), ParsedFieldType::Jid, "{m}");
        }
        // Every JID accessor — specific, `maybe*`, and multi-flavor — reports as JID
        // for codegen purposes, so a dropped/miswired arm trips this.
        for m in [
            ATTR_USER_JID,
            MAYBE_ATTR_USER_JID,
            ATTR_LID_USER_JID,
            MAYBE_ATTR_LID_USER_JID,
            ATTR_DEVICE_JID,
            ATTR_LID_DEVICE_JID,
            ATTR_GROUP_JID,
            ATTR_NEWSLETTER_JID,
            ATTR_CALL_JID,
            ATTR_BROADCAST_JID,
            ATTR_STATUS_JID,
            ATTR_JID_WITH_TYPE,
            ATTR_WAP_JID,
            ATTR_CHAT_JID,
            ATTR_FROM_JID,
        ] {
            assert!(method_field_type(m).is_jid(), "{m}");
        }
        assert_eq!(method_field_type(ATTR_ENUM_VALUES), ParsedFieldType::Enum);
        // `maybe*` variants stay optional.
        assert!(is_optional_method(MAYBE_ATTR_TIME));
        assert!(is_optional_method(MAYBE_ATTR_USER_JID));
        assert!(!is_optional_method(ATTR_USER_JID));
    }
}
