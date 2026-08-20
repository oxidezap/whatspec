//! WAM (WhatsApp Analytics/Metrics) catalog IR — the cross-language contract for
//! the client-side telemetry event surface.
//!
//! WA Web defines each metric as `WAWebWamCodegenUtils.defineEvents({Name: [code,
//! props, weights, channel?, privateStatsId?]})` in a `WAWeb…WamEvent` module, where
//! `props` is `{fieldName: [fieldId, type]}` and `type` is one of the five base
//! [`WamFieldType`]s or a reference to a `WAWebWamEnum…` enum. This IR captures the
//! full schema so any language can generate typed, correctly-serialized emitters.
//!
//! The event catalog alone describes the *contents* of a message no consumer can yet
//! assemble or schedule, so the IR also carries the rest of what the bundle states
//! declaratively about the buffer those events go into: the [`WamGlobal`]s that fill its
//! header (with the channels each may legally be written on), the
//! [`WamPrivateStatsId`] table an event's `privateStatsId` resolves against, the
//! [`WamConstant`]s that fix its protocol version and flush policy, and — per event —
//! the [`WamCallSite`]s where WA Web actually constructs it and the fields it writes
//! there.
//!
//! What stays out: the byte format, which is stable across WA versions and lives in each
//! target's codec; and control flow, so a call site says where and with which fields, and
//! never under which condition.

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
    /// Sampling weights as `defineEvents` lists them, in source order. WA picks one by
    /// gating — a gate selects entry 1 or 2, and with neither gate on the client uses a
    /// literal `1` rather than entry 0 — and the buffer writer then lets a runtime
    /// sampling lookup override whatever was picked. So these are the catalog's
    /// declared weights, not the weight a given buffer carries.
    pub weights: Vec<u32>,
    /// `privateStatsIdInt` when set (the JS sentinel `-1` is normalized to `None`).
    /// A foreign key into [`WamIr::private_stats_ids`]: it names the rotation group
    /// whose anonymous id a `private` buffer carrying this event writes. Every
    /// `private`-channel event has one and every non-`private` event has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_stats_id: Option<i64>,
    /// Fields in source order.
    pub fields: Vec<WamField>,
    /// Modules that declare a dependency on this event's module — the bundle's dep
    /// graph, nothing more. Sorted, deduped.
    ///
    /// A module lands here for importing the event's module, whatever it does with it:
    /// `WAWebWamProcessWorkerData` is on nearly every event because it routes the
    /// worker's data, and a module that only reads the type is indistinguishable from
    /// one that emits. It is a starting point for reading the bundle, not evidence of
    /// emission — [`call_sites`](Self::call_sites) is where a construction was actually
    /// seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<String>,
    /// Places a construction of this event was seen, sorted by module. A module may
    /// appear more than once when it constructs the event at several sites.
    ///
    /// Absent means no construction was recovered — which is not the same as "never
    /// emitted": the count of constructions the scan could not attribute is published
    /// in `manifest.diagnostics.wam`, so the two never look alike.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_sites: Vec<WamCallSite>,
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

/// One buffer-level global: a value the client writes once per buffer (or per event)
/// under its own wire `id`, ahead of the events it applies to.
///
/// Declared by `WAWebWamGlobals` as `defineGlobal({name: [id, type, channels]})` — the
/// same `id`/type vocabulary an event field uses, plus the one axis an event field does
/// not have: the channels the global may legally be written on.
///
/// A separate record from [`WamField`] rather than a `WamField` with a channel list,
/// because the list is not a property an event field has at all: giving every field an
/// empty `channels` would invite reading an event field as channel-scoped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamGlobal {
    /// The `defineGlobal` key (e.g. `psId`).
    pub name: String,
    /// Wire id, in the same id space the buffer writes event fields in.
    pub id: u32,
    #[serde(flatten)]
    pub field_type: WamFieldType,
    /// Channels this global may be written on, in source order (`regular`, `realtime`,
    /// `private`). WA's own writer skips a global whose list does not contain the
    /// buffer's channel, mapping `realtime` onto `regular` first, so a buffer that
    /// carries one anyway is one no client sends. `defineGlobal` defaults an omitted
    /// list to `["regular"]`; that default is resolved here, so the list is never empty.
    ///
    /// It does not say the client *will* write the global on those channels — only that
    /// writing it elsewhere is illegal. What supplies each value is runtime state this
    /// IR does not model.
    pub channels: Vec<String>,
}

/// One entry of the private-stats id table: the rotation group a `private`-channel
/// event's [`WamEvent::private_stats_id`] names.
///
/// A `private` buffer carries one anonymous id (the `psId` global) shared by every event
/// in it; which id depends on the event's group, and each group rotates on its own
/// period. Without the table an event's `privateStatsId` is an integer that resolves
/// against nothing.
///
/// It does not carry the id *value*: that is a random per-install secret the client
/// generates, persists and rotates — never a constant, and not something to extract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamPrivateStatsId {
    /// The group's key (e.g. `IdTtlDaily`).
    pub key: String,
    /// `keyHashInt` — the integer an event's `privateStatsId` names.
    pub id: i64,
    /// Days between rotations of this group's id. `-1` is WA's sentinel for "never
    /// rotates" and is kept as written rather than normalized away, because `0` would
    /// be a different statement and `null` would lose that the client asked for it.
    pub rotation_period_days: i64,
    /// The module the entry was read from. `WAWebWamGlobals` for the published table;
    /// the `none` group (id `0`, the one 21 events name) is contributed by
    /// `WAWebWamPrivateStats` on top of it, so its provenance is a different module and
    /// says so here.
    pub module: String,
}

/// One WAM buffer constant: a literal the client reads from `WAWebWamConstants`.
///
/// These govern the buffer's protocol version and its size/flush policy — not the
/// schema of any event. They are here because the alternative is every consumer
/// hardcoding them (this repository's own reference codec did, with `5` and no
/// provenance) and no consumer noticing when WA changes one.
///
/// The line drawn: only the literals `WAWebWamConstants` exports, a module whose whole
/// body is that export list. A number that lives inside a function — the 1 % beaconing
/// roll in `WAWebWamBeaconing`, say — is a step of an algorithm, and extracting it
/// without the algorithm would publish a number no consumer can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamConstant {
    /// The exported name, as WA spells it (e.g. `WAM_PROTOCOL_VERSION`).
    pub name: String,
    /// The literal value.
    pub value: i64,
    /// The defining module.
    pub module: String,
}

/// A value a call site writes into an event field, when the scan can read it.
///
/// Only the forms whose meaning is fixed at extraction time. Anything computed at
/// runtime — a function call, a variable, a conditional — has no value here at all,
/// which is why [`WamCallSiteField::value`] is optional rather than a "?" placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WamCallSiteValue {
    /// A boolean literal (minified as `!0`/`!1`).
    #[serde(rename_all = "camelCase")]
    Bool { value: bool },
    /// An integer literal. A non-integral number is left unresolved rather than
    /// rounded.
    #[serde(rename_all = "camelCase")]
    Int { value: i64 },
    /// A string literal.
    #[serde(rename_all = "camelCase")]
    Str { value: String },
    /// A member of a WAM enum, named rather than resolved to its integer, so it stays
    /// readable against [`WamIr::enums`] when WA renumbers.
    #[serde(rename_all = "camelCase")]
    EnumMember {
        /// The defining `WAWebWamEnum…` module — the key into [`WamIr::enums`].
        module: String,
        /// The variant's key (e.g. `REGULAR_MESSAGE`).
        key: String,
    },
}

/// How a call site writes one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum WamFieldWrite {
    /// A key of the object handed to the event's constructor. Written whenever the
    /// site runs.
    Constructor,
    /// A later `event.field = …` or `event.set({field: …})` on the constructed value.
    /// WA writes many of these under a condition, and this IR does not model
    /// conditions, so it means "the site may write this field", not "does".
    Assigned,
}

/// One field a call site writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamCallSiteField {
    /// The field's name in the event — guaranteed to be one of [`WamEvent::fields`],
    /// since a written key that names no field of the event is counted as unresolved
    /// instead of published. Unique within a call site: a site that writes one field
    /// twice yields one entry, the constructor write if there is one.
    pub name: String,
    /// How the site writes it.
    pub write: WamFieldWrite,
    /// The value, when it is a literal or a named enum member and the site writes only
    /// that one. A field written twice at the same site — constructed `true`, reassigned
    /// `false` on an error path — carries no value here, because which one goes out is
    /// the branch's answer, not the site's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<WamCallSiteValue>,
}

/// One place in WA Web that constructs this event — `new (o("<module>").<Export>)(…)` —
/// and the fields it is seen writing there.
///
/// This is *where* and *with which fields*, recovered from the construction and from
/// later writes to the value it is bound to. It is deliberately not *when*: the guard
/// the site sits under is control flow, which this repository does not extract, so a
/// call site is a place the client can emit the event, never a promise that it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamCallSite {
    /// The module the construction is written in.
    pub module: String,
    /// Fields the site writes, sorted by name. Empty with `partial: false` means the
    /// site constructs the event with no fields at all, which is a fact about it; empty
    /// with `partial: true` means the scan could read none of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<WamCallSiteField>,
    /// `true` when the site also writes fields the scan could not read — the argument
    /// was a variable, or an object merged from one. `fields` is then a lower bound on
    /// what the site writes, never the full set, and a consumer checking its own emitter
    /// for parity must not treat this site as an exhaustive list.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

/// The WAM IR document: version stamp, every event, the enums their fields reference,
/// and the buffer those events are written into — globals, private-stats groups and
/// constants. Every list is sorted for determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WamIr {
    pub wa_version: String,
    pub events: Vec<WamEvent>,
    pub enums: Vec<WamEnum>,
    /// Buffer globals, sorted by name. Their enum types resolve against
    /// [`enums`](Self::enums) exactly as an event field's does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<WamGlobal>,
    /// The private-stats rotation groups, sorted by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_stats_ids: Vec<WamPrivateStatsId>,
    /// The buffer constants, sorted by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constants: Vec<WamConstant>,
}
