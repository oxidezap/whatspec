//! Native tooling: extract WhatsApp AppState (syncd) action schemas from WA Web
//! bundles.
//!
//! The reference extractor is text/regex-based (not AST), with heuristics tuned to
//! the minified output, so this is a faithful text/regex port (using `regex`)
//! rather than an AST re-derivation — that's what byte-matches.
//!
//! Phase 1 (here): the deterministic fields — collections + per-action `module`,
//! `name`, `collection`, `version`, `scope`, `baseClass`, `chatJidIndex`.
//! Phase 2 (TODO): `valueField`/`valueProtoType`/`valueEnumFields` (buildPendingMutation
//! + SyncAction.pb cross-ref) and `indexParts` (the slot-name inference heuristics).
#![cfg(not(target_arch = "wasm32"))]

mod extract;
mod text;

pub use extract::{extract_appstate, extract_appstate_from_modules};
