//! Canonical WAP response-parser accessor method names and their classification,
//! shared by the scanner (`wa-scan`) and the codegen (`wa-codegen`) so the two
//! can't drift — a past drift silently dropped `maybeAttrEnum`. Pure and
//! dependency-free, so it stays WASM-safe like the rest of the IR contract.

use crate::ParsedFieldType;

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

/// Content accessors (`contentString` / `contentBytes` / `contentInt`).
pub fn is_content_method(m: &str) -> bool {
    matches!(m, CONTENT_STRING | CONTENT_BYTES | CONTENT_INT)
}

/// The attribute value accessors (`attr*` / `maybeAttr*`, including the typed-JID
/// ones). Excludes content accessors and `hasAttr` — callers that also treat
/// those as fields combine this with the relevant content/`hasAttr` checks. This
/// is the single source of truth for "is this method an attribute accessor",
/// shared by the scanner and the codegen so the two can't drift.
pub fn is_attr_method(m: &str) -> bool {
    matches!(
        m,
        ATTR_STRING
            | ATTR_INT
            | ATTR_ENUM
            | ATTR_ENUM_VALUES
            | MAYBE_ATTR_STRING
            | MAYBE_ATTR_INT
            | MAYBE_ATTR_ENUM
            | ATTR_DEVICE_JID
            | ATTR_GROUP_JID
            | ATTR_JID_WITH_TYPE
            | ATTR_TIME
            | MAYBE_ATTR_TIME
            | ATTR_USER_JID
            | MAYBE_ATTR_USER_JID
            | ATTR_WAP_JID
            | ATTR_CHAT_JID
            | ATTR_FROM_JID
            | ATTR_LID_USER_JID
            | MAYBE_ATTR_LID_USER_JID
            | ATTR_LID_DEVICE_JID
            | ATTR_NEWSLETTER_JID
            | ATTR_CALL_JID
            | ATTR_BROADCAST_JID
            | ATTR_STATUS_JID
    )
}

/// `maybe*` accessors decode to optional / non-required fields.
pub fn is_optional_method(m: &str) -> bool {
    m.starts_with("maybe")
}

/// The scalar [`ParsedFieldType`] a response accessor decodes to.
pub fn method_field_type(m: &str) -> ParsedFieldType {
    match m {
        ATTR_STRING | MAYBE_ATTR_STRING => ParsedFieldType::String,
        // An enum accessor decodes to an enum, not a bare string. The smax side already
        // types these `Enum` through its own normalizer, so mapping them to `String` here
        // made one concept two types across domains — 486 fields said `enum` and 28 said
        // `string` for the same accessors — and left an `enumRef` hanging off a field a
        // consumer filtering on `type == "enum"` would never look at.
        ATTR_ENUM | MAYBE_ATTR_ENUM | ATTR_ENUM_VALUES => ParsedFieldType::Enum,
        ATTR_INT | MAYBE_ATTR_INT | ATTR_TIME | MAYBE_ATTR_TIME => ParsedFieldType::Integer,
        // Each JID accessor pins the flavor (server/format) it validates. Keeping the
        // flavor — rather than collapsing to a bare `Jid` — is protocol-safety-critical:
        // a LID user JID and a PN user JID are different identities for the same person.
        ATTR_USER_JID | MAYBE_ATTR_USER_JID => ParsedFieldType::UserJid,
        // The `phone*` spellings are the explicit-PN aliases of the plain user/device
        // accessors. Missing them typed a PN user JID as a bare `string`, which is
        // exactly the conflation the note above calls protocol-safety-critical.
        "attrPhoneUserJid" | "maybeAttrPhoneUserJid" => ParsedFieldType::UserJid,
        "attrPhoneDeviceJid" => ParsedFieldType::DeviceJid,
        ATTR_LID_USER_JID | MAYBE_ATTR_LID_USER_JID => ParsedFieldType::LidUserJid,
        ATTR_DEVICE_JID => ParsedFieldType::DeviceJid,
        ATTR_LID_DEVICE_JID => ParsedFieldType::LidDeviceJid,
        ATTR_GROUP_JID => ParsedFieldType::GroupJid,
        ATTR_NEWSLETTER_JID => ParsedFieldType::NewsletterJid,
        ATTR_CALL_JID => ParsedFieldType::CallJid,
        ATTR_BROADCAST_JID => ParsedFieldType::BroadcastJid,
        ATTR_STATUS_JID => ParsedFieldType::StatusJid,
        ATTR_JID_WITH_TYPE | "attrJidEnum" => ParsedFieldType::JidTyped,
        // `attrWapJid`/`attrChatJid`/`attrFromJid` accept more than one flavor
        // (a chat is a user or a group), so they stay a generic `Jid`.
        ATTR_WAP_JID | ATTR_CHAT_JID | ATTR_FROM_JID => ParsedFieldType::Jid,
        // Multi-flavor accessors: a chat is a user OR a group, `attrDomainJid`/`attrLidJid`
        // accept more than one server, so they stay a generic JID rather than a string.
        "attrPhoneChatJid" | "attrDomainJid" | "attrLidJid" | "attrFromPhoneJid" => {
            ParsedFieldType::Jid
        }
        // Range-checked integers and the enum accessors, whose raw spellings the legacy
        // parsers use directly.
        "attrIntRange" | "contentInt" => ParsedFieldType::Integer,
        "attrStringEnum" | "contentStringEnum" | "attrEnumOrNullIfUnknown" => ParsedFieldType::Enum,
        CONTENT_BYTES => ParsedFieldType::Bytes,
        _ => ParsedFieldType::String,
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
