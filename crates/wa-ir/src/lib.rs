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
pub mod wasm;

pub use abprops::*;
pub use appstate::*;
pub use enums::*;
pub use incoming::*;
/// `true` — the serde default for a flag whose absence means "yes".
///
/// Paired with [`is_true`] so the common case stays out of the document: a child that
/// every branch carries serializes no `required` key at all, and only the exception is
/// written down.
pub fn default_true() -> bool {
    true
}

/// Whether a flag is at its default, for `skip_serializing_if`.
pub fn is_true(b: &bool) -> bool {
    *b
}

pub use iq::*;
pub use mex::*;
pub use notif::*;
pub use proto::*;
pub use srvreq::*;
pub use tokens::*;
pub use wam::*;
pub use wasm::*;

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
///
/// # 2.0.0 — why the major bump
///
/// Almost everything the validation-constraint work added is additive and optional
/// (`literalValue`, `referencePath`, `enumRef`, `errorArms`, `actions`, …), which a 1.x
/// consumer ignores. **One** change is not: [`AssertionKind`] gained a `reference`
/// variant, and that widens the value space of an *existing* field.
///
/// A consumer with a closed enum — one generated from the 1.0 JSON Schema, or the Rust
/// enum itself — rejects the document rather than ignoring an unknown key. This is not
/// hypothetical: validating the current `iq/index.json` against the committed 1.0 schema
/// fails with 579 errors, all `'reference' is not valid under any of the given schemas`.
/// Publishing that as a minor bump would tell consumers the opposite of the truth.
///
/// The migration is one variant wide: handle (or ignore) `kind: "reference"` on response
/// assertions. Everything else in 2.0.0 is opt-in.
///
/// # 3.0.0 — why the major bump
///
/// The same rule applied to ourselves. This release stops three fields from asserting
/// something the extractor did not establish, and each of the three does it by widening
/// or renaming an existing field rather than by adding an optional one:
///
/// - [`IqTarget`] gained `unset` and `unknown`. All 143 stanzas used to say
///   `s.whatsapp.net` because the enum had nowhere else to put "not resolved" — the 33
///   `w:g2` requests included, which the client addresses to the group. A closed-enum
///   2.x consumer now rejects the document instead of silently reading the two new
///   states as absent.
/// - [`ParsedFieldType`] gained `node`, and 617 fields that declared `string` while
///   carrying children now declare it. A consumer switching on `type` sees a value it
///   has no arm for — which is the point, since the arm it *had* was wrong.
/// - `ParsedField`'s `required` is now [`parserRequired`]. A rename rather than a doc
///   fix because the old name stated a wire fact the field never carried; a consumer
///   reading the old key gets `undefined`, which fails loudly instead of defaulting to
///   "optional".
///
/// The rest is additive: [`ParsedField::unknown_value`], the two enum-catalog flags, and
/// the enums catalog growing to cover every `enumRef` in the IR.
///
/// [`AssertionKind`]: crate::AssertionKind
/// [`IqTarget`]: crate::IqTarget
/// [`ParsedFieldType`]: crate::ParsedFieldType
/// [`parserRequired`]: crate::ParsedField::parser_required
/// [`ParsedField::unknown_value`]: crate::ParsedField::unknown_value
///
/// # 4.0.0 — the builder side of a request
///
/// The IR gained a dimension it did not have: where a value goes in the argument object
/// of WA's own request builder ([`WapArgSegment`], on nodes, attributes, element contents
/// and the request's addressee), the cardinality of a request child
/// ([`WapChildPresence`], plus [`WapChildNode::repeat_min`]/[`repeat_max`]), and element
/// contents that used to stop at the mixin boundary.
///
/// Nearly all of it is additive — every new property is optional and skipped at its
/// default, and each committed `*/index.json` validates clean against its own 3.0.0
/// schema, 0 errors across all 12 domains. **One change is not**, and it is why this is a
/// major rather than a minor:
///
/// - [`WapAttrDef::value`] was documented as present only for [`WapAttrKind::Const`], and
///   now also carries the fixed literal of an `OPTIONAL_LITERAL` attribute, whose `kind`
///   is [`Optional`](WapAttrKind::Optional). A 3.0 consumer reading a present `value` as
///   an unconditional constant would send that attribute always; it is written only when
///   the builder's boolean gate says so. Migration: treat `value` on a non-`Const`
///   attribute as "this is what it says WHEN it is written", and read
///   [`WapChildPresence`]'s attribute analogue from the `kind`. Eight committed IQ
///   attributes are in this state. The old JSON Schema accepts them, which is exactly why
///   the version has to say what the schema cannot.
///
/// What else changed *value* rather than shape: `content` is now populated on 45 request
/// nodes that previously had none — an optional field filled in where the builder does
/// supply a payload.
///
/// [`WapArgSegment`]: crate::WapArgSegment
/// [`WapChildPresence`]: crate::WapChildPresence
/// [`WapChildNode::repeat_min`]: crate::WapChildNode::repeat_min
/// [`repeat_max`]: crate::WapChildNode::repeat_max
/// [`WapAttrDef::value`]: crate::WapAttrDef::value
/// [`WapAttrKind::Const`]: crate::WapAttrKind::Const
/// # 4.1.0 — the WAM buffer, and where an event is emitted
///
/// A minor, and deliberately so: every addition is a new optional property or a new
/// top-level list that a 4.0 consumer skips, and the committed `wam/index.json`
/// validates clean against the 4.0 schema. The IR gained the three modules beside the
/// event catalog — [`WamGlobal`]s with the channels each is legal on,
/// [`WamPrivateStatsId`]s (the table an event's `privateStatsId` resolves against) and
/// [`WamConstant`]s — plus [`WamEvent::call_sites`], the places a construction of an
/// event was actually found.
///
/// One existing field changed meaning without changing shape, and it is worth reading
/// before trusting it: [`WamEvent::consumers`] was documented as the modules that
/// construct and commit the event, while carrying the dependency graph, which states no
/// such thing — a module that only imports the type is in it, and the worker's router is in
/// nearly all of them. The doc now says what the field is. Migration is not mechanical
/// but it is small: a consumer using `consumers` as an emission list should read
/// `call_sites` instead, and one using it to find modules to read can keep it. The name
/// stayed because it is accurate for what the field holds; renaming it would have cost
/// every domain a major for a field whose data never changed.
///
/// [`WamGlobal`]: crate::WamGlobal
/// [`WamPrivateStatsId`]: crate::WamPrivateStatsId
/// [`WamConstant`]: crate::WamConstant
/// [`WamEvent::call_sites`]: crate::WamEvent::call_sites
/// [`WamEvent::consumers`]: crate::WamEvent::consumers
pub const SCHEMA_VERSION: &str = "4.1.0";

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
        ("schema/wasm.schema.json", dump::<wasm::WasmIr>()),
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
        assert_eq!(out.len(), 12, "one schema per neutral domain");
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

    /// The JSON Pointer (e.g. `/stanzas/3/response/parserName`) to the first place
    /// `a` and `b` diverge, or `None` if they are equal. Best-effort locator so a
    /// round-trip mismatch on a document-sized blob names *what* drifted instead of
    /// forcing a hand-diff of two JSON dumps. IR keys are plain camelCase identifiers,
    /// so no JSON-Pointer escaping is needed.
    fn first_diff_path(a: &serde_json::Value, b: &serde_json::Value) -> Option<String> {
        use serde_json::Value;
        match (a, b) {
            (Value::Object(ma), Value::Object(mb)) => {
                for (k, va) in ma {
                    match mb.get(k) {
                        Some(vb) => {
                            if let Some(sub) = first_diff_path(va, vb) {
                                return Some(format!("/{k}{sub}"));
                            }
                        }
                        None => return Some(format!("/{k} (dropped on round-trip)")),
                    }
                }
                mb.keys()
                    .find(|k| !ma.contains_key(*k))
                    .map(|k| format!("/{k} (added on round-trip)"))
            }
            (Value::Array(xa), Value::Array(xb)) => xa
                .iter()
                .zip(xb)
                .enumerate()
                .find_map(|(i, (va, vb))| first_diff_path(va, vb).map(|sub| format!("/{i}{sub}")))
                .or_else(|| {
                    (xa.len() != xb.len())
                        .then(|| format!(" (array length {} vs {})", xa.len(), xb.len()))
                }),
            _ => (a != b).then(String::new),
        }
    }

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
            // Point at the first divergence so the failure is actionable without a
            // manual diff of two document-sized blobs.
            let at = first_diff_path(&committed, &reserialized)
                .map(|p| format!(" — first divergence at `{p}`"))
                .unwrap_or_default();
            return Err(format!(
                "{rel}: committed output does not round-trip through its IR type (schema/IR drift){at}"
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
            round_trips::<wasm::WasmIr>("wasm/index.json"),
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

    #[test]
    fn first_diff_path_locates_the_divergence() {
        use serde_json::json;
        // Equal documents → no divergence.
        assert_eq!(
            first_diff_path(&json!({"a": [1, 2]}), &json!({"a": [1, 2]})),
            None
        );
        // A changed leaf is reported by its nested pointer path.
        assert_eq!(
            first_diff_path(&json!({"a": {"b": 1}}), &json!({"a": {"b": 2}})),
            Some("/a/b".to_string())
        );
        // An array element diff carries its index.
        assert_eq!(
            first_diff_path(&json!({"xs": [1, 2, 3]}), &json!({"xs": [1, 9, 3]})),
            Some("/xs/1".to_string())
        );
        // A key present only on the committed side (dropped by the round-trip) is named.
        assert_eq!(
            first_diff_path(&json!({"keep": 1, "gone": 2}), &json!({"keep": 1})),
            Some("/gone (dropped on round-trip)".to_string())
        );
        // A length mismatch with an equal prefix is flagged on the array.
        assert_eq!(
            first_diff_path(&json!({"xs": [1, 2]}), &json!({"xs": [1, 2, 3]})),
            Some("/xs (array length 2 vs 3)".to_string())
        );
    }
}
