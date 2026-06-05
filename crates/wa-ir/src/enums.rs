//! Wire-enum catalog IR — extracted from WA Web's pervasive `$InternalEnum`
//! pattern (`n("$InternalEnum")({ NAME: value, … })`).
//!
//! These back the string/numeric wire enums clients otherwise hand-maintain
//! (nack/error codes, receipt/chat/notification types, …). Each captured enum is
//! a named set of `(variant → value)` pairs; values are either all integers
//! (codes) or all strings (wire tokens) — mixed/computed-value enums are skipped.

use serde::{Deserialize, Serialize};

use crate::Scalar;

/// Whether an enum's values are integer codes or wire strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum EnumValueKind {
    Int,
    String,
}

/// One `NAME: value` member of an enum (value is an [`Scalar::Int`] or
/// [`Scalar::Str`], matching the enclosing [`InternalEnumDef::value_kind`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct EnumVariant {
    pub name: String,
    pub value: Scalar,
}

/// A single `$InternalEnum` definition with its resolved name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct InternalEnumDef {
    /// Resolved enum name (its export, or the module name for a default export).
    pub name: String,
    /// The module that defines it.
    pub module: String,
    pub value_kind: EnumValueKind,
    /// Variants in source order (often ordinal-significant for int enums).
    pub variants: Vec<EnumVariant>,
}

/// The enum-catalog IR document: version stamp + every captured enum, sorted by
/// `(module, name)` for determinism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct EnumsIr {
    pub wa_version: String,
    pub enums: Vec<InternalEnumDef>,
}
