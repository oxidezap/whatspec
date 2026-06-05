//! IQ / XML stanza IR.
//!
//! Faithful Rust port of the `IqStanzaDef` model from the `sigilo` bundler's
//! `scan-iq-stanzas.ts`. Two layers live here:
//!
//! - The **IQ-specific** model (`IqStanzaDef` and friends) — request/response of a
//!   single `<iq>` operation, the MVP codegen target.
//! - The **generalized stanza** model (`StanzaDef`, `IncomingHandlerDef`) — covers
//!   non-IQ stanzas (`message`, `receipt`, `notification`, …) and the incoming
//!   dispatch table, for later expansion. It is **reserved/experimental**: no
//!   extractor produces it and it appears in no emitted artifact, so it is gated
//!   behind the off-by-default `generalized-stanza` feature to keep the shipped
//!   contract minimal.
//!
//! Field naming matches the upstream `index.json` via `rename_all = "camelCase"`.
//! `T | null` fields (always present, possibly null) serialize as `null`;
//! `T?` optional fields are skipped when absent — matching the TS emitter.

use serde::{Deserialize, Serialize};

// ─── Request stanza model ────────────────────────────────────────────────────────

/// Classification of a single WAP attribute on a request stanza node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WapAttrKind {
    /// Fixed literal value (carried in [`WapAttrDef::value`]).
    Const,
    /// Dynamic string argument.
    String,
    /// Integer argument (stringified on the wire).
    Integer,
    /// `<user>@s.whatsapp.net`.
    UserJid,
    /// `<user>:<device>@s.whatsapp.net`.
    DeviceJid,
    /// `<group>@g.us`.
    GroupJid,
    /// Auto-generated stanza id (`wap.generateId()`).
    GeneratedId,
    /// Optional string argument.
    Optional,
    /// Computed/dynamic value not statically resolvable.
    Dynamic,
}

/// A single attribute on a request stanza node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapAttrDef {
    pub name: String,
    pub kind: WapAttrKind,
    /// Present only for [`WapAttrKind::Const`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub required: bool,
}

/// A node in a request stanza tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapChildNode {
    pub tag: String,
    pub attrs: Vec<WapAttrDef>,
    pub children: Vec<WapChildNode>,
    /// Whether this child can appear multiple times (maps to `Vec<_>` in codegen).
    pub repeats: bool,
}

/// IQ operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum IqType {
    Get,
    Set,
}

/// IQ target server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum IqTarget {
    #[serde(rename = "s.whatsapp.net")]
    Server,
    #[serde(rename = "g.us")]
    Group,
}

/// The outgoing request half of an IQ operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IqRequestDef {
    pub namespace: String,
    pub iq_type: IqType,
    pub target: IqTarget,
    pub children: Vec<WapChildNode>,
}

// ─── Response stanza model ───────────────────────────────────────────────────────

/// What a response parser asserts before accepting a node as its variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AssertionKind {
    Tag,
    Attr,
    FromServer,
}

/// A single guard a response parser applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ResponseAssertion {
    pub kind: AssertionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Scalar type a parsed response field decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ParsedFieldType {
    String,
    Integer,
    Enum,
    Bytes,
    Jid,
    DeviceJid,
    GroupJid,
    JidTyped,
}

/// How a child/leaf node's content is accessed in the response parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    String,
    Bytes,
    Nodes,
}

/// One field extracted from a response stanza by a parser.
///
/// `method` is the parser accessor used (e.g. `attrString`, `maybeChild`,
/// `forEachChildWithTag`) and is left open-ended (free-form string) to track the
/// real WA accessor surface; the codegen switches on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ParsedField {
    pub method: String,
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: ParsedFieldType,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ParsedField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeats: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<ContentType>,
}

/// The parsed response half of an IQ operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ParsedResponse {
    pub parser_name: String,
    pub assertions: Vec<ResponseAssertion>,
    pub fields: Vec<ParsedField>,
}

// ─── IQ operation ────────────────────────────────────────────────────────────────

/// A complete IQ operation: its request shape and response parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IqStanzaDef {
    pub module_name: String,
    pub namespace: String,
    pub iq_type: IqType,
    pub target: IqTarget,
    pub parser_name: String,
    /// Primary exported function name, or `null` when the module default-exports.
    pub exported_function: Option<String>,
    pub all_exports: Vec<String>,
    pub request: IqRequestDef,
    pub response: ParsedResponse,
}

/// A module the scanner recognized as an IQ module but could not fully parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct Unparseable {
    pub module_name: String,
    pub reason: String,
}

/// Raw output of an IQ scan over a set of bundles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IqScanResult {
    pub stanzas: Vec<IqStanzaDef>,
    pub unparseable: Vec<Unparseable>,
}

// ─── Generalized stanza model (non-IQ + incoming dispatch) ───────────────────────
//
// Reserved/experimental — gated behind the off-by-default `generalized-stanza`
// feature (see the module doc). No extractor produces these and they appear in no
// emitted artifact yet.

/// Top-level WA protocol stanza tag.
#[cfg(feature = "generalized-stanza")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum StanzaTag {
    Iq,
    Message,
    Receipt,
    Ack,
    Notification,
    Call,
    Chatstate,
    Presence,
}

/// Whether a stanza is constructed (outgoing) or handled (incoming).
#[cfg(feature = "generalized-stanza")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// A generic stanza definition covering IQ and all other stanza types.
#[cfg(feature = "generalized-stanza")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct StanzaDef {
    pub stanza_type: StanzaTag,
    pub direction: Direction,
    pub module_name: String,
    pub exported_function: Option<String>,
    pub all_exports: Vec<String>,
    /// IQ `xmlns`, or the type attr / tag classification for other stanzas.
    pub namespace: Option<String>,
    /// IQ `get`/`set`, or the `type` attr value for other stanzas.
    pub subtype: Option<String>,
    pub target: Option<String>,
    pub attrs: Vec<WapAttrDef>,
    pub children: Vec<WapChildNode>,
    /// Present for IQ stanzas; `null` for fire-and-forget stanzas.
    pub response: Option<ParsedResponse>,
}

/// An entry in the incoming stanza dispatch table.
#[cfg(feature = "generalized-stanza")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IncomingHandlerDef {
    pub stanza_type: String,
    pub subtype: Option<String>,
    pub handler_module: String,
    pub handler_function: String,
}

/// Full output of a generalized stanza scan.
#[cfg(feature = "generalized-stanza")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct StanzaScanResult {
    pub iq_stanzas: Vec<IqStanzaDef>,
    pub all_stanzas: Vec<StanzaDef>,
    pub incoming_handlers: Vec<IncomingHandlerDef>,
    pub unparseable: Vec<Unparseable>,
}

// ─── Emitted artifact ────────────────────────────────────────────────────────────

/// The versioned IQ IR document that gets committed and fed to codegen.
///
/// Mirrors the `{ waVersion, ... }` envelope of upstream `index.json` files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IqIr {
    pub wa_version: String,
    pub stanzas: Vec<IqStanzaDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unparseable: Vec<Unparseable>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_kind_wire_names_match_upstream() {
        // Sanity-check the snake_case mapping against the TS string union.
        let cases = [
            (WapAttrKind::Const, "\"const\""),
            (WapAttrKind::UserJid, "\"user_jid\""),
            (WapAttrKind::DeviceJid, "\"device_jid\""),
            (WapAttrKind::GroupJid, "\"group_jid\""),
            (WapAttrKind::GeneratedId, "\"generated_id\""),
            (WapAttrKind::Dynamic, "\"dynamic\""),
        ];
        for (kind, wire) in cases {
            assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
        }
    }

    #[test]
    fn parsed_field_renames_type_and_camelcases() {
        let f = ParsedField {
            method: "maybeChild".into(),
            name: "media".into(),
            field_type: ParsedFieldType::JidTyped,
            required: false,
            byte_length: None,
            enum_keys: None,
            tag: Some("media".into()),
            children: None,
            repeats: Some(true),
            content_type: Some(ContentType::Bytes),
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["type"], "jid_typed");
        assert_eq!(json["contentType"], "bytes");
        assert_eq!(json["repeats"], true);
        // Optional absent fields are omitted.
        assert!(json.get("byteLength").is_none());
        assert!(json.get("enumKeys").is_none());
        // Round-trips.
        assert_eq!(serde_json::from_value::<ParsedField>(json).unwrap(), f);
    }

    #[test]
    fn iq_stanza_emits_null_for_absent_export() {
        let def = IqStanzaDef {
            module_name: "WAWebFoo".into(),
            namespace: "w:foo".into(),
            iq_type: IqType::Get,
            target: IqTarget::Server,
            parser_name: "WADeprecatedWapParser".into(),
            exported_function: None,
            all_exports: vec![],
            request: IqRequestDef {
                namespace: "w:foo".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                children: vec![],
            },
            response: ParsedResponse {
                parser_name: "p".into(),
                assertions: vec![],
                fields: vec![],
            },
        };
        let json = serde_json::to_value(&def).unwrap();
        // `T | null` field is present as null, not skipped.
        assert!(json.as_object().unwrap().contains_key("exportedFunction"));
        assert!(json["exportedFunction"].is_null());
        assert_eq!(json["iqType"], "get");
        assert_eq!(json["target"], "s.whatsapp.net");
    }
}
