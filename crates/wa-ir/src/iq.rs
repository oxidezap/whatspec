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

/// The kind of leaf payload a request node carries in its element content
/// (`wap("id", null, BIG_ENDIAN_CONTENT(x, 3))` → the `<id>` node's content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WapContentKind {
    /// Raw bytes (`BIG_ENDIAN_CONTENT(x, n)`, a key/signature buffer, …).
    Bytes,
    /// A fixed string literal (carried in [`WapContent::value`]).
    Const,
    /// A computed value not statically resolvable to bytes/const (a variable ref,
    /// a helper result, …). Present but opaque.
    #[default]
    Dynamic,
}

/// The element content of a leaf request node — what sits between `<tag>` and
/// `</tag>` when the node carries a value rather than child nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapContent {
    pub kind: WapContentKind,
    /// Fixed byte length. Either written directly in the request builder
    /// (`BIG_ENDIAN_CONTENT(x, 3)` → 3, [`byte_length_source`] absent) or
    /// cross-referenced from the symmetric parser that reads the same wire field
    /// (`child("signature").contentBytes(64)` → 64, [`byte_length_source`] set).
    ///
    /// [`byte_length_source`]: WapContent::byte_length_source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u32>,
    /// Provenance of an *inferred* [`byte_length`] — the parser module the length was
    /// cross-referenced from (e.g. `"parse:WAWebRetryRequestParser"`). Absent when the
    /// length is written directly in the request builder, so a consumer can tell a
    /// wire-contract fact from a builder-literal one.
    ///
    /// [`byte_length`]: WapContent::byte_length
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_length_source: Option<String>,
    /// The literal value for [`WapContentKind::Const`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A node in a request stanza tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapChildNode {
    pub tag: String,
    /// Attributes always present on this node (independent of any variant group).
    pub attrs: Vec<WapAttrDef>,
    pub children: Vec<WapChildNode>,
    /// The leaf element content, when this node carries a value instead of child
    /// nodes (`<id>`, `<value>`, `<signature>` in a prekey `<skey>`). `None` for
    /// container nodes and attr-only nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<WapContent>,
    /// Whether this child can appear multiple times (maps to `Vec<_>` in codegen).
    pub repeats: bool,
    /// Mutually-exclusive variant groups this node can take, each from a smax
    /// MixinGroup disjunction (e.g. newsletter params: a `jid` variant XOR an
    /// `invite` variant, discriminated by `type`). Exactly one variant of each
    /// required group applies; at most one of each optional group. Empty for the
    /// common case of a node with no disjunction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variant_groups: Vec<WapVariantGroup>,
}

/// A set of mutually-exclusive alternatives a [`WapChildNode`] can take, recovered
/// from one smax MixinGroup disjunction (`if(flagA) merge…A; if(flagB) merge…B;
/// else throw`). Consumers pick exactly one variant (or none when [`optional`]).
///
/// [`optional`]: WapVariantGroup::optional
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapVariantGroup {
    /// The group is folded via `optionalMerge`: zero variants may apply.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
    pub variants: Vec<WapVariant>,
}

/// One alternative within a [`WapVariantGroup`]: the attrs/children it contributes
/// to the node. Variants of a group sharing a const attr (e.g. `type`) are
/// discriminated by it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapVariant {
    pub attrs: Vec<WapAttrDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<WapChildNode>,
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
    /// The node's text content is pinned to a fixed value (`literalContent(content,
    /// node, "admin_add")`) — a discriminator for marker union variants. The value is
    /// in [`ResponseAssertion::value`]; `name` is unused.
    Content,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ParsedFieldType {
    #[default]
    String,
    Integer,
    Enum,
    Bytes,
    Jid,
    DeviceJid,
    GroupJid,
    JidTyped,
    /// A presence boolean (`{hasX: child.success}` in smax) — true iff a sub-node
    /// or attr is present. The presence target is carried in `tag`.
    Bool,
    /// A discriminated union (`{name, value}` smax disjunction) — the alternatives
    /// are carried in [`ParsedField::union_variants`].
    Union,
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

/// One alternative of a discriminated union (`{name, value}` smax disjunction).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct UnionVariant {
    /// The discriminator tag (the disjunction `name`, e.g. `GroupInfo`).
    pub name: String,
    /// The variant's payload fields (empty for a marker/unit variant).
    pub fields: Vec<ParsedField>,
    /// The same-node guards the variant's parser enforces (`assertTag`,
    /// `literal(attr,value)`, `literalContent(value)`) — how a consumer tells this
    /// variant apart from its siblings. Empty when the parser carries no fixed guard.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<ResponseAssertion>,
}

/// One field extracted from a response stanza by a parser.
///
/// `method` is the parser accessor used (e.g. `attrString`, `maybeChild`,
/// `forEachChildWithTag`) and is left open-ended (free-form string) to track the
/// real WA accessor surface; the codegen switches on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ParsedField {
    pub method: String,
    /// The output (struct field) name — the camelCase `makeResult` key in smax.
    pub name: String,
    /// The wire attribute/content name (snake_case), when it differs from `name`.
    /// Codegen reads the attribute by this name; falls back to `name` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_name: Option<String>,
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
    /// Alternatives for a [`ParsedFieldType::Union`] field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub union_variants: Option<Vec<UnionVariant>>,
    /// The field's attrs/content are read off the PARENT node, not a child named
    /// `tag` (a smax payload mixin spread inline) — codegen must not descend.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub same_node: bool,
    /// Wrapper tags to descend (in order) before reading this field — e.g. a
    /// `flattenedChildWithTag("groups")` ancestor for a repeated `<group>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<Vec<String>>,
}

/// How a response-root union variant classifies (drives codegen `Ok`/`Err` arms).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ResponseVariantKind {
    #[default]
    Success,
    Error,
    /// A structured non-happy outcome that still parses (Nack, Conflict, …).
    Alternative,
}

/// One alternative of a response-root discriminated union (an `WASmaxIn<X>Response<V>`
/// variant aggregated by the `WASmax<X>RPC` orchestrator).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ResponseVariant {
    /// The RPC discriminator tag (parser export minus `parse`, e.g.
    /// `GetResponseSuccessPictureURL`).
    pub tag: String,
    pub module_name: String,
    pub kind: ResponseVariantKind,
    pub assertions: Vec<ResponseAssertion>,
    pub fields: Vec<ParsedField>,
}

/// The parsed response half of an IQ operation.
///
/// When `variants` is non-empty the response is a discriminated union (the RPC
/// tries each in order, first success wins); `fields` then mirrors the primary
/// success variant for back-compatible single-shape consumers. When `variants` is
/// empty, `fields` is the single response shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ParsedResponse {
    pub parser_name: String,
    pub assertions: Vec<ResponseAssertion>,
    pub fields: Vec<ParsedField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<ResponseVariant>,
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
            ..Default::default()
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
                ..Default::default()
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
