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
}
