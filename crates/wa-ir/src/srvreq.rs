//! Server-initiated request read-shapes: the field trees WA Web parses out of
//! stanzas the **server pushes** to the client unprompted — companion-pairing
//! steps, presence server-updates, client-expiration notices, chatstate, newsletter
//! delivery, and other `notification`/`iq`/`ib` control stanzas — recovered from
//! their `WASmaxIn<X>Request` parser modules.
//!
//! These are the receive-side counterpart to the client-initiated smax requests
//! whose *responses* the [`iq`] domain catalogs. A `WASmax<X>RPC` orchestrator
//! dispatches each one via `receive<X>RPC(node) { parse<X>Request(node); … }`, so
//! the parser body is a Result-railway identical to a smax `ResponseSuccess` — and
//! is recovered with the same machinery into a [`ParsedResponse`].
//!
//! Distinct from the [`incoming`] domain (legacy `WADeprecatedWapParser` *content*
//! stanzas: message/receipt/call/ack) both in mechanism (smax free-functions) and
//! in surface (control/push stanzas the `incoming` domain deliberately excludes).
//! Where a server request carries `tag = notification`, its `type` discriminator is
//! preserved as an `attr` assertion on the shape — the read-shape a consumer needs
//! for exactly the notification kinds the [`notif`] domain records without content.
//!
//! [`iq`]: crate::iq
//! [`incoming`]: crate::incoming
//! [`notif`]: crate::notif
//! [`ParsedResponse`]: crate::iq::ParsedResponse

use serde::{Deserialize, Serialize};

use crate::iq::ParsedResponse;

/// The top-level stanza tag a server-initiated request asserts. A narrow enum (not
/// the broad [`StanzaTag`]) so the catalog can only hold the tags these RPCs
/// actually dispatch on; child-element tags (`action`, `ref`, `group`, …) asserted
/// by inner parsers are unrepresentable here. New variants are added only when a
/// server-request parser for them appears.
///
/// [`StanzaTag`]: crate::iq::StanzaTag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ServerRequestTag {
    Notification,
    Iq,
    Ib,
    Presence,
    Chatstate,
    Message,
    Status,
}

/// One server-initiated request's read-shape: the tag it dispatches on, the module
/// that defines the parser, and the recovered field tree. Mirrors [`IncomingDef`],
/// differing only in the (broader) tag universe of server-pushed control stanzas.
///
/// [`IncomingDef`]: crate::incoming::IncomingDef
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServerRequestDef {
    /// The top-level stanza tag the parser asserts.
    pub tag: ServerRequestTag,
    /// The WA Web `WASmaxIn<X>Request` module that defines the parser.
    pub module: String,
    /// The recovered read-shape: root parser name, assertions (the tag plus any
    /// pinned `type` discriminator), and field tree — the same [`ParsedResponse`]
    /// the iq/incoming domains use.
    pub shape: ParsedResponse,
}

/// The server-initiated request read-shape IR document: version stamp + the
/// catalog, sorted for determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServerRequestIr {
    pub wa_version: String,
    /// Server-initiated request read-shapes, sorted by `(tag, module, parser name)`.
    pub requests: Vec<ServerRequestDef>,
}

impl ServerRequestIr {
    /// Run [`ParsedResponse::classify_accessors`] over every read-shape.
    pub fn classify_accessors(&mut self) {
        for r in &mut self.requests {
            r.shape.classify_accessors();
        }
    }
}
