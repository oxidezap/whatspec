//! Binary-protocol token dictionary IR — WA Web's `WAWapDict` tables.
//!
//! WhatsApp's binary XMPP encoding replaces frequently-sent strings with compact
//! token tags. WA Web ships a flat single-byte table plus four double-byte
//! dictionaries, stamped with a `DICT_VERSION`.
//!
//! The tables are **canonicalized to the wire-indexable form** every known
//! consumer uses — whatsmeow (`SingleByteTokens`), Baileys (`SINGLE_BYTE_TOKENS`),
//! and whatsapp-rust (`tokens.json`): [`TokensIr::single_byte`]`[0]` is the reserved
//! empty token (WA's raw list starts at tag 1), so `single_byte[tag]` and
//! `double_byte[dict][index]` are direct lookups with no offset. Keeping this shape
//! here (rather than the raw bundle order) means a consumer can't reintroduce an
//! off-by-one.

use serde::{Deserialize, Serialize};

/// The binary-token dictionary IR document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct TokensIr {
    pub wa_version: String,
    /// WA's `DICT_VERSION` stamp (whatsmeow's `DictVersion`; currently 3).
    pub dict_version: u32,
    /// Single-byte token table. Index 0 is the reserved empty token, so
    /// `single_byte[tag]` is a direct lookup; length is WA's raw list + 1.
    pub single_byte: Vec<String>,
    /// The double-byte dictionaries (`DICTIONARY_0..N_TOKEN`) in order;
    /// `double_byte[dict][index]` is a direct lookup with no offset.
    pub double_byte: Vec<Vec<String>>,
}
