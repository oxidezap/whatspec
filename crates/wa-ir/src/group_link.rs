//! Qualified LINK normalization. Shape catalogs alone cannot distinguish an
//! omitted hidden-subgroup field from a false child-presence result.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLinkContract {
    pub module_name: String,
    /// Module-relative byte span of the complete LINK case block.
    pub start_byte: usize,
    pub end_byte: usize,
    pub wire_tag: String,
    pub link_type_attribute: String,
    pub group_child_tag: String,
    /// Required group payload reads, in JavaScript evaluation order.
    pub group_fields: Vec<GroupLinkField>,
    /// `linkType: null` is the ordinary unknown-string fallback, excluding
    /// rows marked `unsupportedAction`. The wire attribute itself
    /// is still required. An unknown type produces an undefined action upstream.
    pub rows: Vec<GroupLinkRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLinkField {
    pub name: String,
    pub wire_name: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLinkRow {
    pub link_type: Option<String>,
    pub action_type: Option<String>,
    /// A plain table lookup reached a standard Object.prototype property and
    /// returned a non-string value. Reject this unqualified action identity;
    /// it must never be collapsed into the ordinary undefined fallback.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsupported_action: bool,
    /// When present, warn and return null before reading group children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub null_result: Option<crate::group_normalization::GroupUnknownTypeWarning>,
    /// When present, read this child's presence for `hiddenSubgroup: bool`.
    /// When absent, omit `hiddenSubgroup`, rather than emitting false.
    pub hidden_subgroup_child: Option<String>,
}
