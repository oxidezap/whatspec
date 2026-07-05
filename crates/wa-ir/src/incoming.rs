//! Incoming stanza read-shapes: the field trees WA Web parses out of *received*
//! `message`/`receipt`/`call`/`ack` stanzas, recovered from their
//! `WADeprecatedWapParser` bodies.
//!
//! This is the receiving counterpart to the outgoing [`StanzaDef`] catalog. It reuses
//! the same [`ParsedResponse`] shape the iq/notif domains recover from parsers. The
//! `<notification>` read-shapes live in the notif domain and `iq` responses in the iq
//! domain; this catalogs the remaining content tags a client must decode.
//!
//! [`StanzaDef`]: crate::iq::StanzaDef

use serde::{Deserialize, Serialize};

use crate::iq::ParsedResponse;

/// The content-stanza tags that carry a recoverable *incoming* read-shape. A narrow
/// enum (not the broad [`StanzaTag`]) so the catalog can only hold tags the domain
/// actually recovers — `iq`/`notification` (other domains) and stream-control tags are
/// unrepresentable here. New variants are added only when a parser for them appears.
///
/// [`StanzaTag`]: crate::iq::StanzaTag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum IncomingTag {
    Message,
    Receipt,
    Call,
    Ack,
}

/// One received stanza's read-shape: which tag it parses, the module that defines the
/// parser, and the recovered field tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IncomingDef {
    /// The content tag the parser asserts (`message` / `receipt` / `call` / `ack`).
    pub tag: IncomingTag,
    /// The WA Web module that defines the parser.
    pub module: String,
    /// The recovered read-shape: parser name, assertions, and field tree (the same
    /// [`ParsedResponse`] the iq/notif domains use).
    pub shape: ParsedResponse,
}

/// The incoming read-shape IR document: version stamp + the catalog, sorted for
/// determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IncomingIr {
    pub wa_version: String,
    /// Received stanza read-shapes, sorted by `(tag, parser name)`.
    pub incoming: Vec<IncomingDef>,
}
