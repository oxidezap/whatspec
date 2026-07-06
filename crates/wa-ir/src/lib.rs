//! WASM-safe IR (intermediate representation) for the extracted WhatsApp Web
//! protocol surface.
//!
//! This crate is **the contract**: the native tooling (`wa-scan`) produces these
//! types from WA Web bundles, and the codegen (`wa-codegen`) consumes them to emit
//! Rust. It has no native-only dependencies (only `serde`) so it compiles to
//! `wasm32-unknown-unknown` and can be shared with the runtime/`tsify` layer later.
//!
//! JSON field naming mirrors the upstream `@vinikjkkj/wa-spec` `index.json`
//! (`camelCase`) on purpose: the Rust scanner output stays diff-comparable against
//! the existing TS extractor during migration.
//!
//! The model ported here covers the IQ/XML stanza domain (the MVP). Other domains
//! (mex, appstate, wam, proto) get their own modules as they are added.

pub mod abprops;
pub mod appstate;
pub mod enums;
pub mod incoming;
pub mod iq;
pub mod mex;
pub mod notif;
pub mod proto;
pub mod srvreq;
pub mod tokens;
pub mod wam;
pub mod wap;

pub use abprops::*;
pub use appstate::*;
pub use enums::*;
pub use incoming::*;
pub use iq::*;
pub use mex::*;
pub use notif::*;
pub use proto::*;
pub use srvreq::*;
pub use tokens::*;
pub use wam::*;

use serde::{Deserialize, Serialize};

/// A JSON scalar literal (bool / integer / float / string), used for A/B-prop
/// defaults and enum values. `untagged` so it serializes as the bare JSON value;
/// the surrounding `valueType` / `valueKind` field tells consumers which arm to
/// expect. Not `Eq` because of the `f64` arm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

/// Version of the IR **contract** (the shape of the emitted `index.json` files
/// and the JSON Schema), independent of the WhatsApp build version.
///
/// `waVersion` changes on every WhatsApp rollout; `schemaVersion` changes only
/// when the *structure* of the IR changes. Consumers pin this to stay stable
/// across WhatsApp updates. Bump on any breaking change to the IR shape.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Envelope that stamps a domain IR document with [`SCHEMA_VERSION`] at emit
/// time, without altering the inner document's shape.
///
/// `#[serde(flatten)]` keeps the document's own fields (`waVersion`, `stanzas`,
/// …) at the top level and merely adds `schemaVersion` alongside them — additive,
/// so existing consumers that ignore unknown fields are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IrEnvelope<T> {
    /// The IR contract version — see [`SCHEMA_VERSION`].
    pub schema_version: String,
    #[serde(flatten)]
    pub document: T,
}

impl<T> IrEnvelope<T> {
    /// Wrap `document` with the current [`SCHEMA_VERSION`].
    pub fn new(document: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            document,
        }
    }
}

/// JSON Schema documents for the IR contract, one per domain, as pretty JSON.
///
/// Returned as `(relative_path, json)` pairs so the CLI can write them under
/// `schema/`. Consumers use these to validate the emitted `index.json` files and
/// to auto-generate their own IR types (quicktype, json-schema-codegen, …).
///
/// Each schema is the envelope (`schemaVersion` + the domain document), so it
/// matches exactly what the corresponding `index.json` contains.
#[cfg(feature = "schema")]
pub fn schemas() -> Vec<(&'static str, String)> {
    fn dump<T: schemars::JsonSchema>() -> String {
        let schema = schemars::schema_for!(IrEnvelope<T>);
        serde_json::to_string_pretty(&schema).expect("schema serializes") + "\n"
    }
    vec![
        ("schema/iq.schema.json", dump::<iq::IqIr>()),
        ("schema/stanza.schema.json", dump::<iq::StanzaIr>()),
        ("schema/mex.schema.json", dump::<mex::MexIr>()),
        (
            "schema/appstate.schema.json",
            dump::<appstate::AppstateIr>(),
        ),
        ("schema/abprops.schema.json", dump::<abprops::AbPropsIr>()),
        ("schema/enums.schema.json", dump::<enums::EnumsIr>()),
        ("schema/wam.schema.json", dump::<wam::WamIr>()),
        ("schema/notif.schema.json", dump::<notif::NotifIr>()),
        ("schema/tokens.schema.json", dump::<tokens::TokensIr>()),
        (
            "schema/incoming.schema.json",
            dump::<incoming::IncomingIr>(),
        ),
        (
            "schema/srvreq.schema.json",
            dump::<srvreq::ServerRequestIr>(),
        ),
    ]
}

#[cfg(all(test, feature = "schema"))]
mod schema_tests {
    use super::*;

    #[test]
    fn schemas_are_well_formed_and_versioned() {
        let out = schemas();
        assert_eq!(out.len(), 11, "one schema per neutral domain");
        for (path, json) in &out {
            // Each schema parses as JSON and is a JSON Schema object with a
            // `properties` map. (`$defs` only appears for domains with nested named
            // types; a flat domain like `tokens` legitimately has none.)
            let v: serde_json::Value =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                v.get("properties").is_some(),
                "{path}: expected a JSON Schema object with properties"
            );
            // The envelope's schemaVersion field is part of the contract.
            let props = &v["properties"];
            assert!(
                props.get("schemaVersion").is_some(),
                "{path}: schema must require schemaVersion"
            );
        }
    }

    #[test]
    fn envelope_stamps_current_version() {
        let env = IrEnvelope::new(iq::IqIr {
            wa_version: "2.3000.1".into(),
            stanzas: vec![],
            unparseable: vec![],
        });
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["schemaVersion"], SCHEMA_VERSION);
        // flatten keeps the document fields at top level.
        assert_eq!(json["waVersion"], "2.3000.1");
    }
}

/// The committed `generated/*/index.json` documents must round-trip losslessly
/// through the IR types — the Rust-side counterpart to the Python schema check, so a
/// drift between the committed output and the contract is caught in `cargo test`
/// rather than only by the separate CI validator.
#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use std::path::Path;

    /// Deserialize a committed `generated/<rel>` document into its IR envelope and
    /// re-serialize it, returning an error message on any mismatch instead of
    /// panicking. A field the IR can't model is dropped on the round-trip, so the
    /// comparison fails — catching a hand-edit or an IR change that wasn't regenerated.
    /// Returning `Result` (rather than asserting) lets the caller exercise every domain
    /// in one run, so a single failing test names all drifting domains at once.
    fn round_trips<T: DeserializeOwned + Serialize>(rel: &str) -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../generated")
            .join(rel);
        let raw =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let committed: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("{rel}: not valid JSON: {e}"))?;
        let typed: IrEnvelope<T> = serde_json::from_value(committed.clone())
            .map_err(|e| format!("{rel}: does not deserialize into its IR type: {e}"))?;
        let reserialized =
            serde_json::to_value(&typed).map_err(|e| format!("{rel}: serialize IR: {e}"))?;
        if committed != reserialized {
            return Err(format!(
                "{rel}: committed output does not round-trip through its IR type (schema/IR drift)"
            ));
        }
        Ok(())
    }

    #[test]
    fn committed_output_round_trips_through_the_ir() {
        // Evaluate every domain (no `?`/short-circuit) so one run reports every drifting
        // domain, not just the first — a failure in `iq` must not hide drift in `tokens`.
        let results = [
            round_trips::<iq::IqIr>("iq/index.json"),
            round_trips::<iq::StanzaIr>("stanza/index.json"),
            round_trips::<mex::MexIr>("mex/index.json"),
            round_trips::<appstate::AppstateIr>("appstate/index.json"),
            round_trips::<abprops::AbPropsIr>("abprops/index.json"),
            round_trips::<enums::EnumsIr>("enums/index.json"),
            round_trips::<wam::WamIr>("wam/index.json"),
            round_trips::<notif::NotifIr>("notif/index.json"),
            round_trips::<tokens::TokensIr>("tokens/index.json"),
            round_trips::<incoming::IncomingIr>("incoming/index.json"),
            round_trips::<srvreq::ServerRequestIr>("srvreq/index.json"),
        ];
        let failures: Vec<&str> = results
            .iter()
            .filter_map(|r| r.as_ref().err().map(String::as_str))
            .collect();
        assert!(
            failures.is_empty(),
            "IR round-trip drift in {} domain(s):\n  - {}",
            failures.len(),
            failures.join("\n  - ")
        );
    }
}
