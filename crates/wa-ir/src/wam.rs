//! WAM (WhatsApp Analytics/Metrics) catalog IR — the cross-language contract for
//! the client-side telemetry event surface.
//!
//! WA Web defines each metric as `WAWebWamCodegenUtils.defineEvents({Name: [code,
//! props, weights, channel?, privateStatsId?]})` in a `WAWeb…WamEvent` module, where
//! `props` is `{fieldName: [fieldId, type]}` and `type` is one of the five base
//! [`WamFieldType`]s or a reference to a `WAWebWamEnum…` enum. This IR captures the
//! full schema so any language can generate typed, correctly-serialized emitters.
//!
//! The IR is pure schema (no wire-codec details): the byte format is stable across
//! WA versions and lives in each target's reference codec, not here. The only
//! emission-relevant data the IR carries is each field's wire `id` + its
//! [`WamFieldType`] (which fixes the schema→wire value mapping a codec applies).

use serde::{Deserialize, Serialize};

/// The type of a WAM event field. The five base types come from
/// `WAWebWamCodegenUtils.TYPES`; `Enum` references a [`WamEnum`] by its defining
/// module. A codec maps each to a wire value (boolean→0/1 int, integer/timer→int,
/// number→int-or-float64, string→string, enum→its numeric value as int).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WamFieldType {
    Boolean,
    Integer,
    Number,
    String,
    Timer,
    /// A field typed by a WAM enum; `module` is the defining `WAWebWamEnum…` module
    /// (the unambiguous key into [`WamIr::enums`]).
    #[serde(rename_all = "camelCase")]
    Enum {
        module: String,
    },
}

/// One field of a WAM event: its `makeResult`-style camelCase name, its numeric wire
/// `id`, and its [`WamFieldType`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamField {
    pub name: String,
    pub id: u32,
    #[serde(flatten)]
    pub field_type: WamFieldType,
}

/// One WAM event definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamEvent {
    /// Event name (the `defineEvents` key, e.g. `AppLaunch`).
    pub name: String,
    /// Numeric event code (the wire id, e.g. `1094`).
    pub code: u32,
    /// The defining `WAWeb…WamEvent` module.
    pub module: String,
    /// Sampling channel / `wamChannel` (e.g. `regular`, `realtime`, `private`).
    pub channel: String,
    /// Sampling weights `[default, ring1, ring2]` (a ring is chosen by gating).
    pub weights: Vec<u32>,
    /// `privateStatsIdInt` when set (the JS sentinel `-1` is normalized to `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_stats_id: Option<i64>,
    /// Fields in source order.
    pub fields: Vec<WamField>,
    /// WA Web modules that construct + `.commit()` this event — a hint for consumers
    /// about where/when each metric is emitted. Sorted, deduped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<String>,
}

/// One member of a WAM enum (`KEY: value`); WAM enum values are always integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamEnumVariant {
    pub key: String,
    pub value: i64,
}

/// A WAM enum (`WAWebWamEnum…` module, `Object.freeze({KEY: int})`) referenced as a
/// field type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamEnum {
    /// Exported name (e.g. `APP_LAUNCH_TYPE`).
    pub name: String,
    /// Defining module (the key referenced by [`WamFieldType::Enum`]).
    pub module: String,
    /// Members in source order.
    pub variants: Vec<WamEnumVariant>,
}

/// The WAM catalog IR document: version stamp, every event, and the enums their
/// fields reference (both sorted for determinism).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamIr {
    pub wa_version: String,
    pub events: Vec<WamEvent>,
    pub enums: Vec<WamEnum>,
}
