//! Wire-enum catalog IR — extracted from WA Web's pervasive `$InternalEnum`
//! pattern (`n("$InternalEnum")({ NAME: value, … })`).
//!
//! These back the string/numeric wire enums clients otherwise hand-maintain
//! (nack/error codes, receipt/chat/notification types, …). Each captured enum is
//! a named set of `(variant → value)` pairs; values are either all integers
//! (codes) or all strings (wire tokens) — mixed/computed-value enums are skipped.

use serde::{Deserialize, Serialize};

use crate::Scalar;

/// Whether an enum's values are integer codes or wire strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum EnumValueKind {
    Int,
    String,
}

/// One `NAME: value` member of an enum (value is an [`Scalar::Int`] or
/// [`Scalar::Str`], matching the enclosing [`InternalEnumDef::value_kind`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct EnumVariant {
    pub name: String,
    pub value: Scalar,
}

/// A single enum definition with its resolved name.
///
/// **The key is `(module, name)`, never `name`.** Four names in the catalog are defined
/// twice (`ACK`, `HostedState`, `ENUM_CBP_NBP_PMP`, `EventType`) and `EventType`'s two
/// definitions do not even agree on [`value_kind`] — an `int` one in
/// `WASmaxMockRunnerUtils` and a `string` one in `WAWebCommonMsgUtils`. A consumer
/// indexing by name picks one and generates a type whose values come from the other.
///
/// [`value_kind`]: InternalEnumDef::value_kind
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct InternalEnumDef {
    /// Resolved enum name (its export, or the module name for a default export).
    /// Unique only together with [`module`] — see the type's note.
    ///
    /// [`module`]: InternalEnumDef::module
    pub name: String,
    /// The module that defines it.
    pub module: String,
    pub value_kind: EnumValueKind,
    /// Variants in source order (often ordinal-significant for int enums).
    pub variants: Vec<EnumVariant>,
    /// The name is **WA's build-generated one, spelled out of the variants themselves**
    /// (`ENUM_FALSE_TRUE`, `ENUM_0_1_7`, `ENUM_HIDDEN_HSCROLL_…`) rather than chosen to
    /// mean anything. Set when the name is exactly `ENUM_` followed by the variants'
    /// (or values') alphanumerics, uppercased, de-duplicated and sorted — the rule WA's
    /// own emitter uses, applied in reverse, not a guess from the prefix.
    ///
    /// It is a warning to a code generator, not a defect: eleven different modules each
    /// define a *different* two-value enum called `ENUM_FALSE_TRUE`, so the name is
    /// neither unique nor descriptive and must not become a type name. What the enum
    /// means lives at the reference site, in the field that reads it.
    ///
    /// It does not say the enum is uninteresting, and its absence does not promise the
    /// name is unique — [`name`] is not a key either way.
    ///
    /// [`name`]: InternalEnumDef::name
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub synthetic_name: bool,
    /// The integer values are **bit positions**, so the value that reaches the wire for
    /// a variant is `1 << value`, not `value`. Recovered from the bundle shifting by a
    /// member of this enum (`t |= 1 << Mod.ReceiptModeBitPosition.ORPHAN`), never from
    /// the name: it is evidence, and `ReceiptModeBitPosition` is the only enum in the
    /// catalog that carries any.
    ///
    /// `false` means no shift use was found, which is not proof the enum is a plain code
    /// table — an enum whose only consumer computes the shift somewhere the scan cannot
    /// follow looks the same. It is never set on a string enum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bit_position: bool,
}

impl InternalEnumDef {
    /// Build a definition, deciding [`synthetic_name`] from the variants.
    ///
    /// The only constructor, so an extraction path added later cannot forget the flag
    /// and publish a generated name as if it were a chosen one. [`bit_position`] is not
    /// decided here: it comes from how the bundle *uses* the enum, which no single
    /// definition site can see.
    ///
    /// [`synthetic_name`]: InternalEnumDef::synthetic_name
    /// [`bit_position`]: InternalEnumDef::bit_position
    pub fn new(
        name: String,
        module: String,
        value_kind: EnumValueKind,
        variants: Vec<EnumVariant>,
    ) -> Self {
        let mut def = Self {
            name,
            module,
            value_kind,
            variants,
            synthetic_name: false,
            bit_position: false,
        };
        def.synthetic_name = def.has_generated_name();
        def
    }

    /// The name WA's emitter would generate for this enum from `pick` of each variant —
    /// alphanumerics only, uppercased, de-duplicated, sorted, joined, `ENUM_`-prefixed.
    fn generated_name(&self, pick: fn(&EnumVariant) -> String) -> String {
        let mut parts: Vec<String> = self
            .variants
            .iter()
            .map(|v| {
                pick(v)
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_uppercase)
                    .collect()
            })
            .collect();
        parts.sort();
        parts.dedup();
        format!("ENUM_{}", parts.join("_"))
    }

    /// Whether [`name`] is reconstructible from the variants — see [`synthetic_name`],
    /// which this sets. Checked against both the variant names and the wire values
    /// because WA spells the generated name from whichever it has.
    ///
    /// [`name`]: InternalEnumDef::name
    /// [`synthetic_name`]: InternalEnumDef::synthetic_name
    pub fn has_generated_name(&self) -> bool {
        self.name == self.generated_name(|v| v.name.clone())
            || self.name == self.generated_name(|v| scalar_text(&v.value))
    }
}

/// The source text of a scalar enum value, as WA's name generator would spell it.
fn scalar_text(v: &Scalar) -> String {
    match v {
        Scalar::Bool(b) => b.to_string(),
        Scalar::Int(i) => i.to_string(),
        Scalar::Float(f) => f.to_string(),
        Scalar::Str(s) => s.clone(),
    }
}

/// The enum-catalog IR document: version stamp + every captured enum, sorted by
/// `(module, name)` for determinism.
///
/// It is the **complete** index every `enumRef` in every other domain resolves against:
/// an enum a response or request field references is in here whether or not it is an
/// `$InternalEnum`, so a consumer never has to know in advance whether a reference will
/// be found. Before that was true, 75 of the 87 enums referenced inline existed nowhere
/// in the catalog, and a generator reading the catalog alone emitted a fraction of the
/// types it needed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct EnumsIr {
    pub wa_version: String,
    pub enums: Vec<InternalEnumDef>,
}
