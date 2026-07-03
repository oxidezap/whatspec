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

// JID-typed accessors beyond the IQ set. WA has one accessor per JID flavor
// (user / chat / generic-wap / LID user / LID device / "from"); they all decode
// to a `Jid`, differing only in which server/format they accept. Kept as distinct
// method names (not collapsed) so the accessor surface stays a faithful mirror.
pub const ATTR_USER_JID: &str = "attrUserJid";
pub const MAYBE_ATTR_USER_JID: &str = "maybeAttrUserJid";
pub const ATTR_WAP_JID: &str = "attrWapJid";
pub const ATTR_CHAT_JID: &str = "attrChatJid";
pub const ATTR_FROM_JID: &str = "attrFromJid";
pub const ATTR_LID_USER_JID: &str = "attrLidUserJid";
pub const MAYBE_ATTR_LID_USER_JID: &str = "maybeAttrLidUserJid";
pub const ATTR_LID_DEVICE_JID: &str = "attrLidDeviceJid";

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
    )
}

/// `maybe*` accessors decode to optional / non-required fields.
pub fn is_optional_method(m: &str) -> bool {
    m.starts_with("maybe")
}

/// The scalar [`ParsedFieldType`] a response accessor decodes to.
pub fn method_field_type(m: &str) -> ParsedFieldType {
    match m {
        ATTR_STRING | MAYBE_ATTR_STRING | ATTR_ENUM | MAYBE_ATTR_ENUM | ATTR_ENUM_VALUES => {
            ParsedFieldType::String
        }
        ATTR_INT | MAYBE_ATTR_INT | ATTR_TIME | MAYBE_ATTR_TIME => ParsedFieldType::Integer,
        ATTR_DEVICE_JID | ATTR_LID_DEVICE_JID => ParsedFieldType::DeviceJid,
        ATTR_GROUP_JID => ParsedFieldType::GroupJid,
        ATTR_JID_WITH_TYPE => ParsedFieldType::JidTyped,
        ATTR_USER_JID
        | MAYBE_ATTR_USER_JID
        | ATTR_WAP_JID
        | ATTR_CHAT_JID
        | ATTR_FROM_JID
        | ATTR_LID_USER_JID
        | MAYBE_ATTR_LID_USER_JID => ParsedFieldType::Jid,
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
        assert_eq!(method_field_type(MAYBE_ATTR_ENUM), ParsedFieldType::String);
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
            ATTR_ENUM_VALUES,
        ] {
            assert!(is_attr_method(m), "{m} should be an attr method");
        }
        // Timestamps decode to integers.
        assert_eq!(method_field_type(ATTR_TIME), ParsedFieldType::Integer);
        assert_eq!(method_field_type(MAYBE_ATTR_TIME), ParsedFieldType::Integer);
        // The JID flavors all decode to a Jid (device-LID is a device JID).
        for m in [
            ATTR_USER_JID,
            MAYBE_ATTR_USER_JID,
            ATTR_WAP_JID,
            ATTR_CHAT_JID,
            ATTR_FROM_JID,
            ATTR_LID_USER_JID,
            MAYBE_ATTR_LID_USER_JID,
        ] {
            assert_eq!(method_field_type(m), ParsedFieldType::Jid, "{m}");
        }
        assert_eq!(
            method_field_type(ATTR_LID_DEVICE_JID),
            ParsedFieldType::DeviceJid
        );
        assert_eq!(method_field_type(ATTR_ENUM_VALUES), ParsedFieldType::String);
        // `maybe*` variants stay optional.
        assert!(is_optional_method(MAYBE_ATTR_TIME));
        assert!(is_optional_method(MAYBE_ATTR_USER_JID));
        assert!(!is_optional_method(ATTR_USER_JID));
    }
}
