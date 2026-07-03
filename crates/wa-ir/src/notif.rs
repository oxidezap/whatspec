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
