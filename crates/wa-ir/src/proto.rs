//! Protobuf IR — the resolved message/enum tree extracted from WA Web.
//!
//! This is the *resolved* form: field `type_name`s are already the final printable
//! strings (scalar, cross-ref name, qualified nested name, or `map<K, V>`), flags
//! are final (including the auto-`optional`), and nested entities are attached to
//! their parent in emission order. The stringifier is therefore a dumb walk.

use serde::{Deserialize, Serialize};

/// A whole `.proto` file: a version stamp plus sorted top-level entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoFile {
    pub wa_version: String,
    pub entities: Vec<ProtoEntity>,
}

/// A top-level or nested protobuf entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProtoEntity {
    Message(ProtoMessage),
    Enum(ProtoEnum),
}

impl ProtoEntity {
    /// Display name used for sorting + the `message`/`enum` header.
    pub fn name(&self) -> &str {
        match self {
            ProtoEntity::Message(m) => &m.name,
            ProtoEntity::Enum(e) => &e.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoMessage {
    pub name: String,
    pub members: Vec<ProtoMember>,
    /// Nested messages/enums, emitted (indented) after the members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested: Vec<ProtoEntity>,
}

/// A message member: a plain field or a `oneof` group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProtoMember {
    Field(ProtoField),
    OneOf(ProtoOneOf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoField {
    pub name: String,
    pub id: i64,
    /// Final printable type: scalar (`uint32`), message/enum name (possibly
    /// `Parent.Nested`-qualified), or `map<K, V>`.
    pub type_name: String,
    /// Final flag words in print order (e.g. `["optional"]`, `["repeated"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub packed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoOneOf {
    pub name: String,
    pub fields: Vec<ProtoField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoEnum {
    pub name: String,
    pub values: Vec<ProtoEnumValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProtoEnumValue {
    pub name: String,
    pub id: i64,
}
