//! Incoming stanza-dispatch IR — the catalog of `<notification>` types (and the
//! top-level stanza tags) WA Web dispatches inbound stanzas on.
//!
//! Extracted from WA Web's stanza dispatcher modules, each a two-level `switch`:
//! `switch(stanza.tag)` at the top (`receipt`, `notification`, `presence`, …) and,
//! inside the `notification` arm, a `switch(notification.type)` over the
//! notification kinds (`devices`, `encrypt`, `account_sync`, …). Each arm forwards
//! to a handler module.
//!
//! WA Web splits this across **more than one** dispatcher: the main
//! `WAWebCommsHandleLoggedInStanza` plus a `WAWebCommsHandleWorkerCompatibleStanza`
//! that adds group/identity arms (`w:gp2`, `encrypt`→`identity`). The catalog is the
//! **union** of every dispatcher's arms, so no type is missed by only reading one.
//!
//! This is the discriminant catalog clients otherwise hand-maintain (e.g. a
//! `match notification_type` with string literals). Pinning it to the bundle keeps
//! those dispatch tables from drifting when WA adds or renames a notification type.
//!
//! The typed *content shape* of each notification (the fields inside `<devices>`,
//! `<encrypt>`, …) is carried in [`NotificationDef::content`], recovered from the
//! handler's `WADeprecatedWapParser` with the same machinery the IQ domain uses —
//! reusing [`ParsedResponse`] so the two domains share one field-tree model.

use serde::{Deserialize, Serialize};

use crate::ParsedResponse;

/// One arm of the top-level `switch(stanza.tag)` — a stanza tag WA Web handles on
/// an authenticated connection (`receipt`, `notification`, `presence`, `call`, …).
///
/// The `notification` tag is special: it fans out further into
/// [`NotifIr::notifications`]. Every other tag forwards straight to a handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct StanzaTagDef {
    /// The stanza tag matched (`stanza.tag`), e.g. `"receipt"`.
    pub tag: String,
    /// The module the arm forwards to (`o("WAWebHandleX").handleX(stanza)` /
    /// `r("WAWebHandleX")(stanza)`), when the arm resolves to a single handler
    /// call. `None` for arms that only branch further, log, or return inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_module: Option<String>,
    /// The method invoked on [`handler_module`], when the arm calls
    /// `module.method(...)` rather than the module value directly.
    ///
    /// [`handler_module`]: StanzaTagDef::handler_module
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_function: Option<String>,
}

/// A second-level discriminant a notification arm branches on *after* `type` —
/// e.g. `encrypt` switches on its first child tag (`count` vs `digest`), `psa` on
/// `surfaces` vs `reset_smb_last_qp_prefetch_timestamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SubDiscriminant {
    /// What the arm inspects to pick a case. Currently always
    /// [`SubDiscriminantOn::FirstChildTag`] (`content[0].tag`); kept as an enum so a
    /// future attr-based sub-switch is representable without a schema break.
    pub on: SubDiscriminantOn,
    /// The recognized cases, in source order.
    pub cases: Vec<SubCase>,
}

/// The value a [`SubDiscriminant`] inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum SubDiscriminantOn {
    /// The tag of the notification's first child node (`content[0].tag`).
    FirstChildTag,
}

/// One case of a [`SubDiscriminant`] (`encrypt`'s `count`, `psa`'s `surfaces`, …).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SubCase {
    /// The discriminant value matched (the child tag), e.g. `"count"`.
    pub value: String,
    /// The handler module the case forwards to, when it resolves to a single
    /// handler call. `None` for a bare guard (`if(tag==="invite") break`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_module: Option<String>,
    /// The method invoked on [`handler_module`], when applicable.
    ///
    /// [`handler_module`]: SubCase::handler_module
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_function: Option<String>,
}

/// One arm of the inner `switch(notification.type)` — a `<notification type="…">`
/// kind and the handler that parses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotificationDef {
    /// The `type` attribute value the arm matches (`"devices"`, `"encrypt"`, …).
    /// The discriminant a client dispatches on.
    #[serde(rename = "type")]
    pub notif_type: String,
    /// The handler module the arm forwards to (`WAWebHandleDeviceNotification`),
    /// when the arm resolves to a single handler call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_module: Option<String>,
    /// The method invoked on [`handler_module`], e.g. `handleDevicesNotification`.
    /// `None` when the arm calls the module value directly (`r("Mod")(stanza)`).
    ///
    /// [`handler_module`]: NotificationDef::handler_module
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_function: Option<String>,
    /// Second-level discriminants the arm branches on after `type` (empty for the
    /// common case of a flat forward to one handler).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_discriminants: Vec<SubDiscriminant>,
    /// The typed content shape parsed from the handler's `WADeprecatedWapParser`
    /// (Phase 2). `None` when the handler carries no statically-recoverable parser
    /// (it delegates to a job/sub-module) — the catalog entry still stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ParsedResponse>,
    /// The payload **action union** carried inside the notification, when its handler
    /// dispatches on the child tag (`w:gp2` and friends — see [`NotifActionDef`]).
    /// [`content`] describes the envelope; this describes what is inside it. Empty for
    /// a notification whose handler carries no such per-child-tag switch.
    ///
    /// [`content`]: NotificationDef::content
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<NotifActionDef>,
}

/// One arm of a notification's payload action union: a child tag of the
/// `<notification>` and the fields the handler reads off it.
///
/// WA Web parses these in a `switch (child.tag())` inside the handler (e.g.
/// `WAWebHandleGroupNotification`), where each arm returns an object stamped with an
/// `actionType`. Two facts there are invisible from the wire alone and cannot be
/// derived by a consumer:
///
/// 1. **The mapping is many-to-one.** Several wire tags normalize onto one
///    `actionType` — `ephemeral` and `not_ephemeral` both become `ephemeral`, so a
///    consumer that branches on `not_ephemeral` is writing dead code.
/// 2. **Field names are rebound.** The disappearing-message timer arrives in the
///    `expiration` attribute but the action field is called `duration` (the *create*
///    payload's spelling, `ephemeralDuration`, belongs to a different shape) — reading
///    it under the wrong name silently yields 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotifActionDef {
    /// The child element's tag on the wire (`"ephemeral"`, `"not_ephemeral"`,
    /// `"subject"`, …) — the value the handler switches on.
    pub wire_tag: String,
    /// The normalized action identity the handler stamps as `actionType`. **Not** always
    /// equal to [`wire_tag`]: `not_ephemeral` maps to `ephemeral`, `locked`/`unlocked`
    /// both map to `restrict`, and so on. `None` when the arm computes it dynamically
    /// (e.g. `link` picks between three actions by its `link_type` attribute), which is
    /// recorded rather than guessed.
    ///
    /// [`wire_tag`]: NotifActionDef::wire_tag
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    /// The fields the arm reads off the child node, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<NotifActionField>,
    /// Output fields the arm sets to a **constant** rather than reading from the wire —
    /// `not_ephemeral` sets `duration: 0`, `locked` sets `value: true`, `unlocked`
    /// `value: false`. This is exactly the normalization that is invisible from the
    /// stanza, and it is what makes the many-to-one tag mapping lossless: `ephemeral`
    /// vs `not_ephemeral` differ only by this. Sorted by key for determinism.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constant_fields: Vec<NotifActionConstant>,
    /// Repeated sub-elements the arm maps over (`revoke` → one entry per
    /// `<participant>`), each with its own field list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<NotifActionChild>,
}

/// One field an action arm reads off the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotifActionField {
    /// The output field name in the parsed action (`"duration"`).
    pub name: String,
    /// The wire attribute it is read from (`"expiration"`), or the child tag for a
    /// content read. Differs from [`name`] often enough that assuming they match is the
    /// bug this field exists to prevent.
    ///
    /// [`name`]: NotifActionField::name
    pub wire_name: String,
    /// How the value decodes, reusing the response-field type vocabulary.
    #[serde(rename = "type")]
    pub field_type: crate::ParsedFieldType,
    /// Whether the arm reads the attribute unconditionally (`attrInt("expiration")`) or
    /// guards on its presence (`hasAttr("reason") ? … : null`, `maybeAttrString`).
    pub required: bool,
    /// The element's text content is read instead of an attribute
    /// (`child("body").contentString()`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content: bool,
    /// The wire enum the value is validated against, when the arm reads it with an enum
    /// accessor (`child.maybeAttrEnum("type", o("WAWebGroupApiConst").GROUP_PARTICIPANT_TYPES)`).
    /// Without it a `"type": "enum"` field says the value is constrained but not to what,
    /// which leaves a parser and an emitter guessing — the same gap `enumRef` closes on
    /// the response side.
    ///
    /// Absent when the accessor validates against an **anonymous** lookup table declared
    /// inline in the handler (`attrEnumOrNullIfUnknown("reason", v)` where `v` is a local
    /// object literal). Such a table has no stable name — the identifier is whatever the
    /// minifier picked this build — so naming it would churn the IR on every WhatsApp
    /// rollout and invent an identity the bundle does not have. Reported as unresolved
    /// rather than faked; recovering those value sets is a separate modelling question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_ref: Option<crate::AttrEnumRef>,
}

/// A `key → constant` pair an action arm stamps onto its result unconditionally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotifActionConstant {
    pub name: String,
    pub value: NotifConstValue,
}

/// The value of a [`NotifActionConstant`] — the literal kinds a handler arm actually
/// stamps (`!0`/`!1`, `0`, a wire string). Deliberately narrower than [`crate::Scalar`]
/// (no float) so the notif IR stays `Eq`-comparable for the determinism checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum NotifConstValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

/// A repeated sub-element an action arm maps over
/// (`mapChildrenWithTag("participant", …)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotifActionChild {
    /// The output field the mapped list lands in (`"participants"`).
    pub name: String,
    /// The repeated element's wire tag (`"participant"`).
    pub wire_tag: String,
    /// The fields read off each element.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<NotifActionField>,
    /// Whether EVERY branch producing this action carries the collection.
    ///
    /// `if (c) return {actionType: A, participants: …}; return {actionType: A}` yields two
    /// legal shapes for one action, and only one of them has `participants`. Without this
    /// the metadata claimed the list is always present — the same over-assertion that
    /// `required` on a scalar field exists to prevent, one level up.
    ///
    /// Always serialized. Skipping the `true` case would leave a non-Rust consumer —
    /// which is who the IR is for — unable to tell "required by default" from
    /// "unspecified", and the JSON Schema cannot carry the default either.
    #[serde(default = "crate::default_true")]
    pub required: bool,
}

/// The incoming-dispatch IR document: version stamp + the dispatcher module name +
/// the two-level dispatch catalog, sorted for determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct NotifIr {
    pub wa_version: String,
    /// The dispatcher modules the catalog is the union of, sorted (e.g.
    /// `WAWebCommsHandleLoggedInStanza`, `WAWebCommsHandleWorkerCompatibleStanza`).
    pub dispatcher_modules: Vec<String>,
    /// Top-level stanza tags, sorted by `tag`.
    pub stanza_tags: Vec<StanzaTagDef>,
    /// `<notification>` types, sorted by `type`.
    pub notifications: Vec<NotificationDef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_type_field_renamed_and_optionals_skipped() {
        let def = NotificationDef {
            notif_type: "devices".into(),
            handler_module: Some("WAWebHandleDeviceNotification".into()),
            handler_function: Some("handleDevicesNotification".into()),
            sub_discriminants: vec![],
            content: None,
            actions: vec![],
        };
        let json = serde_json::to_value(&def).unwrap();
        // `notif_type` serializes under the wire name `type`.
        assert_eq!(json["type"], "devices");
        assert_eq!(json["handlerModule"], "WAWebHandleDeviceNotification");
        // Empty/None fields are omitted, not emitted as [] / null.
        assert!(json.get("subDiscriminants").is_none());
        assert!(json.get("content").is_none());
        // Round-trips.
        assert_eq!(
            serde_json::from_value::<NotificationDef>(json).unwrap(),
            def
        );
    }

    #[test]
    fn sub_discriminant_on_serializes_camel_case() {
        let sd = SubDiscriminant {
            on: SubDiscriminantOn::FirstChildTag,
            cases: vec![SubCase {
                value: "count".into(),
                handler_module: Some("WAWebHandlePreKeyLow".into()),
                handler_function: None,
            }],
        };
        let json = serde_json::to_value(&sd).unwrap();
        assert_eq!(json["on"], "firstChildTag");
        assert_eq!(json["cases"][0]["value"], "count");
        // Direct module call → no handlerFunction key.
        assert!(json["cases"][0].get("handlerFunction").is_none());
    }
}
