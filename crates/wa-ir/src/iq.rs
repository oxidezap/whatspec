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

/// One step of a [`WapArgPath`] — a key in the builder's argument object, plus
/// whether that key holds the **list** a repeated child iterates.
///
/// `list` is set on exactly one kind of segment: the array argument of a
/// `WASmaxChildren.REPEATED_CHILD(template, list, min, max)` call, which invokes the
/// template once per element. It is *not* set for `OPTIONAL_CHILD`/`HAS_OPTIONAL_CHILD`,
/// where the argument object is handed to the template as-is. The distinction is
/// load-bearing rather than cosmetic: writing `participantArgs.participantJid` where the
/// builder reads `participantArgs[0].participantJid` puts the value somewhere the vendor
/// builder never looks, and the stanza goes out without it.
///
/// It does not say how long the list may be — that is [`WapChildNode::repeat_min`] /
/// [`repeat_max`] on the node the path addresses — and it does not say the key is
/// present at runtime.
///
/// [`repeat_max`]: WapChildNode::repeat_max
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapArgSegment {
    /// The property name read off the argument object (`participantArgs`, `iqTo`, …).
    pub key: String,
    /// This key holds the array a `REPEATED_CHILD` iterates; the next segment (and
    /// everything below it) is read off an *element*, not off the array.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub list: bool,
}

/// Where a value lives in the **argument object of WhatsApp's own request builder** —
/// an absolute path from the builder's single parameter, e.g.
/// `participantArgs[] → participantJid` for `makeCreateRequest({participantArgs: [{
/// participantJid: … }]})`.
///
/// This describes the *builder*, not the wire. A consumer that encodes the stanza itself
/// has no use for it and should read `tag`/`attrs`/`content`; a consumer that calls the
/// vendor builder needs it, because the argument key is frequently not derivable from
/// the wire name it ends up in (`subjectElementValue` → the content of `<subject>`).
///
/// What it does **not** guarantee: that the key is required (see
/// [`WapChildNode::presence`]), that a value written there is valid, or that a path
/// exists at all — an unrecoverable path is absent from the IR and counted under
/// `manifest.diagnostics.iq.argPaths`, never guessed.
pub type WapArgPath = Vec<WapArgSegment>;

/// Whether a request child node must be built, may be omitted, or exists only to
/// signal a flag — the three states `WASmaxChildren` distinguishes and the wire does
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WapChildPresence {
    /// Built unconditionally — the builder calls the child template directly, or
    /// `REPEATED_CHILD` iterates a list that is itself a required argument. For a
    /// repeated child, "required" is about the *list argument*: a `repeat_min` of 0
    /// still allows the list to be empty.
    #[default]
    Required,
    /// `WASmaxChildren.OPTIONAL_CHILD(template, args)` — emitted only when the
    /// argument object is supplied. The child carries real attrs/content when present.
    Optional,
    /// `WASmaxChildren.HAS_OPTIONAL_CHILD(template, flag)` — a **presence marker**:
    /// the template takes no arguments, so the element is empty and its entire meaning
    /// is being there (`<locked/>` on a group create). A consumer can model it as a
    /// `bool` argument, which it cannot do for [`Optional`] and must not do for an
    /// empty [`Required`] child.
    ///
    /// It does not guarantee the element has no attributes on the wire — only that
    /// this builder writes none.
    ///
    /// [`Optional`]: WapChildPresence::Optional
    PresenceFlag,
}

/// A single attribute on a request stanza node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct WapAttrDef {
    pub name: String,
    pub kind: WapAttrKind,
    /// The fixed wire value the builder writes itself.
    ///
    /// Present for a [`WapAttrKind::Const`] attribute, and for an
    /// [`Optional`](WapAttrKind::Optional) one built by
    /// `WASmaxAttrs.OPTIONAL_LITERAL(lit, flag)` — there the value is this literal and
    /// the argument is a boolean deciding whether the attribute is written at all, the
    /// attribute analogue of [`WapChildPresence::PresenceFlag`]. Such an attribute
    /// carries no [`arg_path`]: there is no address for a value the builder supplies, and
    /// pointing at the boolean would tell a consumer to put the wire string there.
    ///
    /// It does not say the attribute is always sent — only what it says when it is.
    ///
    /// [`arg_path`]: WapAttrDef::arg_path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub required: bool,
    /// The wire enum this attribute's value comes from, when the builder writes it via
    /// a structural enum reference — `CUSTOM_STRING(o("Mod").EnumName.VARIANT)` or a
    /// `cond === o("Mod").EnumName.VARIANT ? … : DROP_ATTR` guard. Carries the enum's
    /// full `(name, module, variants)` so a consumer can type the attribute as that
    /// enum instead of a bare string. Resolved from the enum's definition (whether a
    /// `$InternalEnum` or a plain object literal); absent when the value is a literal,
    /// a variable, or any non-enum expression (never guessed from value coincidence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_ref: Option<AttrEnumRef>,
    /// Where this attribute's value comes from in the builder's argument object — an
    /// absolute [`WapArgPath`]. Absent for a [`WapAttrKind::Const`] (the builder writes
    /// the literal itself, there is no argument) and whenever the path is not
    /// structurally recoverable; those are counted, not guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_path: Option<WapArgPath>,
}

/// A wire enum a request attribute's value is drawn from, recovered by resolving a
/// structural `o("Mod").EnumName.VARIANT` reference in the builder. String-valued (all
/// stanza-attr enums are wire tokens), so a consumer can generate a real enum type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AttrEnumRef {
    /// The enum's name (`CiphertextType`, `USYNC_ADDRESSING_MODE`, …).
    pub name: String,
    /// The module that defines it (`WAWebBackendJobs.flow`, `WAWebUsync`, …).
    pub module: String,
    /// The enum's variants in source order.
    pub variants: Vec<AttrEnumVariant>,
}

/// One `NAME: "wire_value"` member of an [`AttrEnumRef`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AttrEnumVariant {
    pub name: String,
    pub value: String,
}

impl WapChildPresence {
    /// Whether this is the default (unconditional) presence — the serde skip predicate,
    /// so the common case costs no bytes in the emitted document.
    pub fn is_required(&self) -> bool {
        matches!(self, WapChildPresence::Required)
    }
}

impl WapAttrDef {
    /// Whether this attribute's wire value comes from a caller argument rather than from
    /// the builder itself — so an absent [`arg_path`] is an extraction gap rather than
    /// nothing to address. A constant, a generated id, and an attribute with a recorded
    /// fixed [`value`] (WA's `OPTIONAL_LITERAL`, whose argument is a presence flag) all
    /// read none.
    ///
    /// Says nothing about whether the value is required, only about where it comes from.
    ///
    /// [`arg_path`]: WapAttrDef::arg_path
    /// [`value`]: WapAttrDef::value
    pub fn reads_argument(&self) -> bool {
        !matches!(self.kind, WapAttrKind::Const | WapAttrKind::GeneratedId) && self.value.is_none()
    }
}

impl WapContent {
    /// Whether this payload comes from a caller argument rather than from the builder —
    /// the same question [`WapAttrDef::reads_argument`] asks, for element content. Only a
    /// [`WapContentKind::Const`] reads none: the builder writes that literal itself.
    ///
    /// A [`const_bytes`] payload still does. It is *pinned* rather than written — every
    /// call site in the bundle passes the same compile-time constant — so the argument
    /// exists and a consumer calling the builder must supply it. The two facts answer
    /// different questions: [`arg_path`] says where the value goes, `const_bytes` says
    /// what to put there.
    ///
    /// [`const_bytes`]: WapContent::const_bytes
    /// [`arg_path`]: WapContent::arg_path
    pub fn reads_argument(&self) -> bool {
        self.kind != WapContentKind::Const
    }
}

impl WapChildNode {
    /// Whether a `WASmaxChildren` combinator fed this child — `REPEATED_CHILD`,
    /// `OPTIONAL_CHILD` or `HAS_OPTIONAL_CHILD` — so it has an argument of its own for
    /// [`arg_path`] to address. A child built unconditionally in the builder body has no
    /// argument object behind it and is not missing an address by lacking one.
    ///
    /// [`arg_path`]: WapChildNode::arg_path
    pub fn is_combinator_fed(&self) -> bool {
        self.repeats || !self.presence.is_required()
    }
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
    /// A fixed byte value (hex-encoded, e.g. `"00"` for a one-byte zero buffer) the
    /// builder writes as content. Recovered by cross-referencing the smax content
    /// argument to its unanimous compile-time constant at every call site
    /// (`{ linkCodePairingNonceElementValue: new Uint8Array(1) }` → one `0x00`
    /// byte). Kept separate from [`value`] (a `Const` *string*) so a byte constant
    /// and a text constant can never be confused (`"00"` the string vs `00` the
    /// byte). When set, [`byte_length`] is its length and [`value_source`] its
    /// provenance.
    ///
    /// [`value`]: WapContent::value
    /// [`byte_length`]: WapContent::byte_length
    /// [`value_source`]: WapContent::value_source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub const_bytes: Option<String>,
    /// Provenance of a cross-referenced constant [`const_bytes`] (or [`value`]) — the
    /// smax content-argument name the constant was resolved from, prefixed `const:`
    /// (e.g. `"const:linkCodePairingNonceElementValue"`). Absent when the value is a
    /// builder-inline literal, so a consumer can tell a call-site-inferred constant
    /// from a directly-written one.
    ///
    /// [`const_bytes`]: WapContent::const_bytes
    /// [`value`]: WapContent::value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_source: Option<String>,
    /// Where the content value comes from in the builder's argument object — an
    /// absolute [`WapArgPath`] (`<subject>`'s text is `subjectElementValue`). Absent for
    /// a [`WapContentKind::Const`]/`const_bytes` payload the builder writes itself, and
    /// whenever the path is not structurally recoverable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_path: Option<WapArgPath>,
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
    ///
    /// Says what the element carries when the builder writes it, not that it is always
    /// written: a payload contributed by an `optionalMerge` onto a node built elsewhere
    /// is stated here even though that merge can be skipped. There is no per-content
    /// optionality in this contract — [`presence`] is a property of the node.
    ///
    /// [`presence`]: WapChildNode::presence
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<WapContent>,
    /// Whether this child can appear multiple times (maps to `Vec<_>` in codegen).
    pub repeats: bool,
    /// Whether the builder emits this child unconditionally, only when its arguments
    /// are supplied, or only as a presence marker. See [`WapChildPresence`]; defaults
    /// to [`WapChildPresence::Required`], which is also what a node whose call site was
    /// not one of the `WASmaxChildren` combinators gets.
    #[serde(default, skip_serializing_if = "WapChildPresence::is_required")]
    pub presence: WapChildPresence,
    /// Lower bound on the number of repetitions, from the 3rd argument of
    /// `REPEATED_CHILD(template, list, min, max)`. Present only when [`repeats`] is set
    /// and the bound is a literal; a computed or non-finite bound is omitted and
    /// counted, never defaulted to 0.
    ///
    /// It is the bound *this builder* enforces before sending. The server enforces its
    /// own, which may be stricter.
    ///
    /// [`repeats`]: WapChildNode::repeats
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat_min: Option<u32>,
    /// Upper bound on the number of repetitions — the 4th argument of `REPEATED_CHILD`
    /// (`add/participant` caps at 1024, `query/group` at 10000). Same presence rules as
    /// [`repeat_min`].
    ///
    /// [`repeat_min`]: WapChildNode::repeat_min
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat_max: Option<u32>,
    /// Where this node's own argument object lives in the builder's arguments — the
    /// list for a [`repeats`] child (its last segment carries [`WapArgSegment::list`]),
    /// the argument object for an [`WapChildPresence::Optional`] one, the boolean for a
    /// [`WapChildPresence::PresenceFlag`] one.
    ///
    /// Absent for a node the builder constructs inline: such a node has no argument
    /// object of its own, and its attrs/content carry absolute paths regardless, so a
    /// consumer never has to concatenate.
    ///
    /// [`repeats`]: WapChildNode::repeats
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_path: Option<WapArgPath>,
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
    /// The attribute named by [`ResponseAssertion::name`] must **echo a value taken
    /// from the request** — `literal(attrString, node, "from",
    /// attrStringFromReference(request, ["to"]))`. The expected value is not a
    /// constant, so [`ResponseAssertion::value`] is absent; where it comes from is in
    /// [`ResponseAssertion::reference_path`].
    ///
    /// This is the rule 17 of the 26 namespace `IQError…Mixin`s (and every success
    /// parser) enforce: an answer's `id` must equal the request's `id` and its `from`
    /// the request's `to`. An emitter that hardcodes `from="s.whatsapp.net"` produces
    /// stanzas a real client cannot parse whenever the request went to `g.us`.
    Reference,
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
    /// Where the expected value is read from **in the request**, for
    /// [`AssertionKind::Reference`]. It is the argument list of WA's
    /// `attrStringFromReference(request, path)` helper: every element but the last is a
    /// child tag to descend into, and the last is the attribute name. So `["to"]` means
    /// "the request's `to` attribute" and `["account", "action"]` means "the `action`
    /// attribute of the request's `<account>` child".
    ///
    /// Carried structurally (rather than left to be inferred from `name`) so a consumer
    /// never has to pattern-match attribute names to know an echo rule applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_path: Option<Vec<String>>,
}

/// Scalar type a parsed response field decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ParsedFieldType {
    #[default]
    String,
    Integer,
    /// An integer the parser range-checks as a Unix timestamp in **seconds** —
    /// recognized by the `attrIntRange(t, 1577865600, 4102473600)` bound, i.e.
    /// `2020-01-01T08:00:00Z`…`2100-01-01T08:00:00Z` (the exact constants; both are
    /// 08:00 UTC, not midnight). WA uses this to tell a wall-clock time apart from a
    /// plain counter. A consumer can decode it as a date/time rather than a bare integer.
    Timestamp,
    /// A Unix timestamp in **milliseconds** — the same window range-checked ×1000
    /// (`attrIntRange(t, 15778656e5, 41024736e5)`). Distinct from [`Timestamp`] so a
    /// consumer applies the right scale.
    ///
    /// [`Timestamp`]: ParsedFieldType::Timestamp
    TimestampMillis,
    Enum,
    Bytes,
    /// A JID with no flavor-specific validation (`attrJid`/`attrWapJid`/`attrFromJid`).
    Jid,
    /// `<user>@s.whatsapp.net` — a phone-number (PN) user JID (`attrUserJid`).
    /// Distinct from [`LidUserJid`]: the two are different identities for the same
    /// person and must never be conflated — a protocol-safety-critical distinction.
    ///
    /// [`LidUserJid`]: ParsedFieldType::LidUserJid
    UserJid,
    /// `<user>@lid` — a LID (privacy) user JID (`attrLidUserJid`). See [`UserJid`].
    ///
    /// [`UserJid`]: ParsedFieldType::UserJid
    LidUserJid,
    /// `<user>:<device>@s.whatsapp.net` (`attrDeviceJid`).
    DeviceJid,
    /// `<user>:<device>@lid` — a LID device JID (`attrLidDeviceJid`).
    LidDeviceJid,
    /// `<group>@g.us` (`attrGroupJid`).
    GroupJid,
    /// `<id>@newsletter` (`attrNewsletterJid`).
    NewsletterJid,
    /// `<id>@call` (`attrCallJid`).
    CallJid,
    /// `<target>@broadcast` (`attrBroadcastJid`).
    BroadcastJid,
    /// `status@broadcast` (`attrStatusJid`).
    StatusJid,
    /// A JID validated against a server-kind enum arg but with no single flavor
    /// (`attrJidWithType`/`attrJidEnum`).
    JidTyped,
    /// A presence boolean (`{hasX: child.success}` in smax) — true iff a sub-node
    /// or attr is present. The presence target is carried in `tag`.
    Bool,
    /// A discriminated union (`{name, value}` smax disjunction) — the alternatives
    /// are carried in [`ParsedField::union_variants`].
    Union,
}

impl ParsedFieldType {
    /// Whether this type is any JID flavor (generic or a specific server/format).
    /// The codegen materializes every flavor as one `Jid` today, so it switches on
    /// this rather than listing each variant — a new flavor is covered automatically.
    pub fn is_jid(&self) -> bool {
        matches!(
            self,
            ParsedFieldType::Jid
                | ParsedFieldType::UserJid
                | ParsedFieldType::LidUserJid
                | ParsedFieldType::DeviceJid
                | ParsedFieldType::LidDeviceJid
                | ParsedFieldType::GroupJid
                | ParsedFieldType::NewsletterJid
                | ParsedFieldType::CallJid
                | ParsedFieldType::BroadcastJid
                | ParsedFieldType::StatusJid
                | ParsedFieldType::JidTyped
        )
    }
}

/// How a child/leaf node's content is accessed in the response parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    String,
    Bytes,
    /// A decimal integer in the element body (`contentUint`, `contentInt`). Distinct
    /// from [`String`] because a consumer that reads it as text has to re-parse, and
    /// because collapsing it onto `String` is how three sibling integer contents ended
    /// up sharing one generated field.
    ///
    /// [`String`]: ContentType::String
    Integer,
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

/// Scanner-internal state for an enum accessor's allowed-value table, before the
/// cross-module post-pass runs. Never serialized — see [`ParsedField::pending_enum_ref`].
///
/// The unresolvable case is a *variant*, not an absence, so it can be counted. An enum
/// whose table the scan could not follow and a field that is simply not an enum must not
/// look alike: the first is a constraint we failed to extract and belongs in
/// `dropsByReason`, the second is nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingEnum {
    /// `o("Mod").ENUM` — a module export the bundle-wide index can finish resolving.
    Link(AttrEnumRef),
    /// A table that is not a structurally recoverable reference (a computed expression,
    /// a runtime-composed set, an object literal with a non-literal member). A unit
    /// variant: the reporting pass names the loss from the field's own `wireName`/`name`,
    /// so there is nothing to carry here.
    Unresolvable,
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
    /// Inclusive lower bound on the byte-content length, enforced via
    /// `contentBytesRange(node, min, max)` when `min != max` — a payload-size *limit*
    /// (a media buffer capped at 1 MiB, a token capped at 128 bytes), as opposed to a
    /// fixed [`byte_length`] (the `min == max` case). Present only for a
    /// [`ParsedFieldType::Bytes`] field with a true range; a consumer can enforce the
    /// bound rather than guessing an unbounded buffer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_min: Option<u32>,
    /// Inclusive upper bound from the same `contentBytesRange` check (see [`byte_min`]).
    ///
    /// [`byte_min`]: ParsedField::byte_min
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_max: Option<u32>,
    /// Inclusive lower bound the parser enforces via `attrIntRange(node, name, min,
    /// max)`. Present only for a bounded [`ParsedFieldType::Integer`]; a consumer can
    /// validate or pick a narrower Rust width from these. The timestamp-marker range is
    /// not carried here — it is surfaced as [`ParsedFieldType::Timestamp`] instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub int_min: Option<i64>,
    /// Inclusive upper bound from the same `attrIntRange` check (see [`int_min`]).
    ///
    /// [`int_min`]: ParsedField::int_min
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub int_max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_keys: Option<Vec<String>>,
    /// The wire enum this field's value is drawn from, when the parser reads it with an
    /// enum accessor (`attrStringEnum(node, "state", o("Mod").ENUM_OFF_ON)`). Resolved
    /// the same way the request side resolves [`WapAttrDef::enum_ref`], so a consumer
    /// can type the field as that enum instead of a bare string — and an emitter knows
    /// which values are legal instead of guessing from the generated `ENUM_OFF_ON` name.
    /// Absent when the enum argument is not a structurally resolvable module export, or
    /// resolves to a non-string enum (never guessed).
    ///
    /// [`WapAttrDef::enum_ref`]: WapAttrDef::enum_ref
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_ref: Option<AttrEnumRef>,
    /// Scanner-internal: an enum reference seen but not yet resolved.
    ///
    /// The legacy scanner reads one module at a time and cannot follow `o("Mod").ENUM`
    /// to its definition, so it records the *reference* here and a cross-module post-pass
    /// promotes it into [`enum_ref`] once the whole bundle index exists.
    ///
    /// It is a separate field, and never serialized, because the pending state must not
    /// be expressible in the published IR. It previously lived in [`enum_ref`] with an
    /// empty `variants`, and the two callers that skipped the post-pass shipped exactly
    /// that: `incoming/index.json` told consumers `ALL_NONE` and `STANZA_MSG_TYPES` admit
    /// **no** legal value. Now a caller that forgets can only lose the link, never
    /// publish a false one.
    ///
    /// [`enum_ref`]: ParsedField::enum_ref
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub pending_enum_ref: Option<PendingEnum>,
    /// The fixed value the parser pins this field to — `literal(attrString, participant,
    /// "type", "admin")` → `"admin"`, `literal(attrInt, error, "code", 429)` → `"429"`.
    /// Always the string form of the literal; [`field_type`] says how to read it (a
    /// `code` field with `literalValue: "429"` is the integer 429 on the wire). On a
    /// [`ParsedFieldType::Bytes`] field it is **lowercase hex** — the encoding
    /// [`WapContent::const_bytes`] already uses on the request side —
    /// and [`byte_length`] is its length: `contentLiteralBytes(node, new Uint8Array([5]))`
    /// → `literalValue: "05"`, `byteLength: 1`.
    ///
    /// [`byte_length`]: ParsedField::byte_length
    ///
    /// [`required`] tells the two pinning forms apart, and the difference matters to an
    /// emitter: a **required** literal (`literal`) is a hard discriminator — the
    /// attribute MUST be present and equal to this value or the variant does not match;
    /// an **optional** one (`optionalLiteral`) is pinned only when present — the emitter
    /// may omit the attribute, but must never send a contradicting value.
    ///
    /// **On a [`ParsedFieldType::Bool`] field the pin is always conditional.** Such a
    /// field is a *presence flag* — `{hasListCDhash: m.value != null}` — so its
    /// `required: true` describes the flag (the parser always produces it), never the
    /// wire attribute named by [`wire_name`], which by construction may be absent. The
    /// pin constrains that attribute when present, and never the boolean itself.
    ///
    /// [`field_type`]: ParsedField::field_type
    /// [`required`]: ParsedField::required
    /// [`wire_name`]: ParsedField::wire_name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literal_value: Option<String>,
    /// The field is pinned not to a constant but to **a value taken from the request** —
    /// the same echo rule [`AssertionKind::Reference`] carries, in the same
    /// `attrStringFromReference` path form, but for a pin that is *not* a variant guard.
    ///
    /// A required echo (`literal(…, "from", ref.to)`) is recorded as an assertion, since
    /// it must hold for the variant to match at all. An **optional** one
    /// (`optionalLiteral(…, "c_dhash", ref.item.dhash)`) is not a guard — the attribute
    /// may be absent — so it lives here instead: an emitter may omit it, but if it sends
    /// it, the value must be the request's. Mutually exclusive with [`literal_value`],
    /// and — like it — always conditional when carried on a [`ParsedFieldType::Bool`]
    /// presence flag.
    ///
    /// [`literal_value`]: ParsedField::literal_value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_path: Option<Vec<String>>,
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
///
/// The error side is split by **who is at fault**, because that decides what a caller
/// should do: a 4xx will fail again if retried unchanged, a 5xx may not. WA models the
/// two as separate parsers with disjoint code ranges (`bad-request` 400,
/// `rate-overlimit` 429, fallback 400–499 / `internal-server-error` 500, fallback
/// 500–599), so the split is the protocol's, not an interpretation.
///
/// The side is derived from the **codes** the variant accepts, never from its name: WA
/// spells the arms inconsistently (`…ResponseServerError`, but also
/// `…ResponseInternalServerError`, and `SetResponsePreKeySuccessVnameFailure` reads as a
/// success while asserting `type="error"`). A variant whose codes are mixed or outside
/// both families stays [`Error`] — an error whose side could not be determined, which is
/// a fact worth stating rather than a coin flip.
///
/// [`Error`]: ResponseVariantKind::Error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ResponseVariantKind {
    #[default]
    Success,
    /// The request was wrong (4xx) — retrying it unchanged will fail again.
    ClientError,
    /// The server failed (5xx) — the same request may succeed later.
    ServerError,
    /// An error whose side the accepted codes do not determine.
    Error,
    /// A structured non-happy outcome that still parses (Nack, Conflict, …).
    Alternative,
}

impl ResponseVariantKind {
    /// Whether this is any error outcome, whichever side is at fault.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            ResponseVariantKind::Error
                | ResponseVariantKind::ClientError
                | ResponseVariantKind::ServerError
        )
    }
}

/// One accepted `<error>` shape of a response variant: the `code` and `text` that must
/// occur **together**.
///
/// A variant accepting `400 bad-request` and `501 feature-not-implemented` cannot be
/// described by two independent lists — nothing would then rule out `400
/// feature-not-implemented`, a combination the parser rejects, so an emitter picking one
/// value from each list produces an unparseable stanza. The pairing is the point.
///
/// Every field is optional because each is a genuine shape: an arm may pin an exact
/// `(code, text)`, pin only the code and read the text freely
/// (`IQErrorReportTokenValidationFail` accepts any text with 548), or pin neither and
/// range-check the code (the `IQErrorFallback*` arms).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ErrorArm {
    /// The disjunction alternative this arm comes from (`IQErrorBadRequest`), when the
    /// error is parsed as a `…Errors` union. `None` for an RPC that parses a single
    /// `<error>` child directly, which has exactly one arm and no name for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The exact `code` this arm pins, when it pins one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,
    /// The exact `text` this arm pins. Absent is a fact, not a gap — see the note above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Inclusive lower bound of the codes this arm accepts, when it range-checks instead
    /// of pinning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_min: Option<i64>,
    /// Inclusive upper bound of the same range (see [`code_min`]).
    ///
    /// [`code_min`]: ErrorArm::code_min
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_max: Option<i64>,
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
    /// The accepted `<error>` shapes, in parser order — **which code goes with which
    /// text**. See [`ErrorArm`]; this is the only representation of the vocabulary,
    /// deliberately, because the flattened `errorCodes` / `errorTexts` lists it replaced
    /// let an emitter combine one arm's code with another's text and produce a stanza no
    /// branch accepts.
    ///
    /// An arm describes the *discriminating* `<error>` node. When the variant also pins
    /// the node above it, those pins are in [`error_envelope`], and the full shape is
    /// **arm + envelope**.
    ///
    /// To answer "does this RPC accept code N / text T?", scan the arms — the question
    /// the flat lists used to answer is one `.iter().any(…)` away, and asking it that way
    /// cannot produce an invalid pair.
    ///
    /// [`error_envelope`]: ResponseVariant::error_envelope
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_arms: Vec<ErrorArm>,
    /// Pins on the `<error>` node **enclosing** the one the arms discriminate, for a
    /// two-level error.
    ///
    /// `SetResponsePreKeySuccessVnameFailure` is the shape: `<error code="207">` — the
    /// partial-failure envelope, shared by every arm — wrapping an inner `<error>` whose
    /// text the disjunction pins and whose code is range-checked. Pins are partitioned by
    /// the node they are read from, so the envelope holds only the enclosing node's and
    /// the inner node's shared constraints stay on the arms; mixing them would tell a
    /// consumer that code 207 must also fall in 400–599.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_envelope: Option<ErrorArm>,
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
    /// Scanner-internal: constraints this parser carried that could not be resolved
    /// structurally, as `dropsByReason` keys. Never serialized.
    ///
    /// The legacy scanner reads one module at a time and has no diagnostics channel of
    /// its own, so it parks the losses on the shape it produces and whoever finishes the
    /// shape drains them ([`crate::wap`]'s consumers do this via the response enum
    /// linker). It exists for the same reason [`ParsedField::pending_enum_ref`] does: a
    /// constraint seen and not recovered must never be indistinguishable from no
    /// constraint at all.
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub pending_drops: Vec<String>,
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

/// A module the scanner recognized as an IQ module but that yielded no standalone
/// stanza. NOT necessarily a failure: `reason` distinguishes a genuine parse/resolution
/// failure (the minority) from a benign mixin fragment folded into real requests (the
/// majority). Recorded either way to honor the no-silent-vanish invariant. The
/// manifest's `diagnostics.iq` splits these into `unparseable` (genuine) and
/// `excludedFragments` (benign) so neither count is inflated by the other.
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
    /// Modules that produced no stanza, each with a `reason` — a mix of genuine failures
    /// and benign folded-in fragments (see [`Unparseable`]); not all are true failures.
    pub unparseable: Vec<Unparseable>,
}

// ─── Generalized stanza model (non-IQ + incoming dispatch) ───────────────────────
//
// The outgoing model (`StanzaTag`, `Direction`, `StanzaDef`) is produced by the
// non-IQ stanza scanner and emitted under `stanza/`. The incoming dispatch model
// (`IncomingHandlerDef`, `StanzaScanResult`) is still reserved behind the off-by-
// default `generalized-stanza` feature.

/// Top-level WA protocol stanza tag.
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
    Status,
    Privacy,
}

/// Whether a stanza is constructed (outgoing) or handled (incoming).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// A generic stanza definition covering IQ and all other stanza types.
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
    /// True for a `merge…Mixin` fragment: a partial stanza (e.g. a message
    /// content-type mixin `smax("message",{type:"reaction"})`) that WA folds into a
    /// concrete stanza via `mergeStanzas`, not a standalone sendable stanza. Catalogued
    /// so the full set of message/receipt content types is visible; consumers building a
    /// stanza to send should filter these out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fragment: bool,
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

/// The versioned generalized-stanza IR document: every outgoing non-IQ stanza the
/// bundle builds (`receipt`, `presence`, `chatstate`, `ack`, …), in the same
/// `{ waVersion, … }` envelope as the other domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct StanzaIr {
    pub wa_version: String,
    pub stanzas: Vec<StanzaDef>,
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
