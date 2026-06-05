//! AppState (syncd) action-schema IR — extracted from `WAWeb*Sync` modules.
//!
//! Each action has a wire `name`, a `collection` + schema `version`, a `scope`
//! that determines its mutation-index shape (`indexParts`), and a value carried
//! in one `SyncActionValue` oneof field.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One element of an action's mutation index. `type` discriminates the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type")]
pub enum IndexPart {
    /// Fixed literal at a position (the action wire name lives at position 0).
    #[serde(rename = "literal")]
    Literal { value: String },
    /// WhatsApp JID string.
    #[serde(rename = "jid")]
    Jid { name: String },
    /// `'0'`/`'1'` boolean encoding.
    #[serde(rename = "boolString")]
    BoolString { name: String },
    /// Participant slot — a JID, or literal `'0'`.
    #[serde(rename = "jidOrZero")]
    JidOrZero { name: String },
    /// Stringified protobuf enum int; `protoEnum` is the enum path under SyncActionValue.
    #[serde(rename = "enum", rename_all = "camelCase")]
    Enum { name: String, proto_enum: String },
    /// Opaque identifier (msg id, label id, …).
    #[serde(rename = "string")]
    StringPart { name: String },
    /// Unrecognised slot.
    #[serde(rename = "unknown")]
    Unknown { name: String },
}

/// A single AppState action schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AppstateAction {
    pub module: String,
    /// Wire action name (e.g. `deviceAgent`).
    pub name: String,
    pub collection: Option<String>,
    pub version: Option<u32>,
    pub scope: String,
    pub base_class: String,
    pub value_field: Option<String>,
    pub value_proto_type: Option<String>,
    /// Map of value-field name → protobuf enum path, when the value has enums.
    pub value_enum_fields: Option<BTreeMap<String, String>>,
    pub chat_jid_index: Option<i64>,
    pub index_parts: Vec<IndexPart>,
}

/// The AppState IR document: version stamp, collections, and actions by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AppstateIr {
    pub wa_version: String,
    pub collections: Vec<String>,
    pub actions: BTreeMap<String, AppstateAction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_part_wire_shapes() {
        let parts = vec![
            IndexPart::Literal {
                value: "deviceAgent".into(),
            },
            IndexPart::StringPart {
                name: "agentId".into(),
            },
            IndexPart::Enum {
                name: "k".into(),
                proto_enum: "SettingsSyncAction.SettingKey".into(),
            },
            IndexPart::JidOrZero { name: "p".into() },
        ];
        let json = serde_json::to_value(&parts).unwrap();
        assert_eq!(json[0]["type"], "literal");
        assert_eq!(json[0]["value"], "deviceAgent");
        assert_eq!(json[1]["type"], "string");
        assert_eq!(json[2]["type"], "enum");
        assert_eq!(json[2]["protoEnum"], "SettingsSyncAction.SettingKey");
        assert_eq!(json[3]["type"], "jidOrZero");
        assert_eq!(
            serde_json::from_value::<Vec<IndexPart>>(json).unwrap(),
            parts
        );
    }
}
