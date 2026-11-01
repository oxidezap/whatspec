//! Qualified group action normalization, separate from raw payload shapes.
use serde::{Deserialize, Serialize};

/// A finite projection of the unlink helper. `None` is the unknown-value fallback,
/// not an absent wire attribute: `unlink_type` is required by the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupUnlinkContract {
    pub module_name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub rows: Vec<GroupUnlinkRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupUnlinkRow {
    pub unlink_type: Option<String>,
    pub reason: Option<String>,
    pub action_type: Option<String>,
    /// The official plain-object lookup returned an inherited non-string value.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsupported_action: bool,
    /// Read every `group` child first with `attrGroupJid("jid")`,
    /// `attrString("subject")`, and `attrInt("s_t")`, in that order.
    /// Then look up the action; on this branch, warn and return null.
    /// LINK instead warns and returns before reading group children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub null_result: Option<GroupUnknownTypeWarning>,
}

/// A qualified unknown-type branch invokes WARN(template, wire type), then
/// sendLogs(event), then returns null. Calls are observable and may throw;
/// consumers must preserve their order and must not emit a partial action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupUnknownTypeWarning {
    pub template: Vec<String>,
    pub event: String,
}
