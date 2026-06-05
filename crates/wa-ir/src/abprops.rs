//! A/B-props (feature-flag) registry IR — extracted from WA Web's
//! `WAWebABPropsConfigs`.
//!
//! Each flag carries the numeric `code` the client puts in the `<props>` IQ to
//! request it, its value type, and its default(s). WA ships ~1.7k of these and
//! they churn every release, so hand-maintaining a subset (as downstream clients
//! do) drifts quickly — this captures the whole registry.

use serde::{Deserialize, Serialize};

use crate::Scalar;

/// The declared value type of an A/B prop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum AbPropType {
    Bool,
    Int,
    String,
    Float,
}

/// One feature-flag entry: `name → [code, type, default, alt_default]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AbPropConfig {
    /// The WA Web registry module this flag is declared in (e.g.
    /// `WAWebABPropsConfigs`, `WAWebHybridABPropsConfigs`,
    /// `WAWebGroupABPropsConfigs`). WhatsApp ships several registries and a flag
    /// may appear in more than one (identical code/default), so the module is part
    /// of a flag's identity — consumers key by `(module, name)`.
    pub module: String,
    /// Flag key, e.g. `privacy_token_sending_on_all_1_on_1_messages`.
    pub name: String,
    /// Numeric config id sent in the `<props>` IQ.
    pub code: u32,
    pub value_type: AbPropType,
    /// The flag's default value (typed per `value_type`).
    pub default: Scalar,
    /// A second default the bundle stores per flag (differs for ~25% of flags —
    /// often the server/"enabled" default); present only when it differs from
    /// `default`. Exact semantics are WA-internal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_default: Option<Scalar>,
}

/// The A/B-props IR document: version stamp + every flag from every registry
/// module, sorted by `(module, name)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AbPropsIr {
    pub wa_version: String,
    pub configs: Vec<AbPropConfig>,
}
