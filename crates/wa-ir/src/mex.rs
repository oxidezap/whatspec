//! Mex (Relay GraphQL) IR — persisted query/mutation operations extracted from
//! WA Web: their persisted `docId`, kind, variable names, the
//! `variablesShape` / `response` type trees, and - per variable key - whether
//! the official client always puts that key on the wire.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum MexOperationKind {
    Query,
    Mutation,
}

/// A node in a `variablesShape` / `response` type tree.
///
/// Mirrors the reference's JSON shape via `untagged`: an object renders as
/// `{field: ..}`, a plural field as a single-element `[inner]` array, and a
/// scalar leaf as a type-tag string (`"string"`/`"number"`/`"boolean"`/
/// `"enum:A|B"`/`"unknown"`). Object key ordering is normalized (sorted) — the
/// tree is compared semantically, not by source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum TypeNode {
    Object(BTreeMap<String, TypeNode>),
    Array(Vec<TypeNode>),
    Leaf(String),
}

impl TypeNode {
    /// The scalar leaf tag used before pragmatic typing resolves a concrete type.
    pub const UNKNOWN: &'static str = "unknown";
}

/// Whether the official client's own call sites put a variable key on the wire.
///
/// A persisted operation's compiled tree references its variables
/// unconditionally, so a server validates the *presence* of a key, not only its
/// type. `variablesShape` answers "what type", and answered nothing about "is it
/// there" - which made "the client may omit this" and "we could not tell"
/// the same silence, read by every emitter as the first.
///
/// The unit is the key as it survives serialization: WA hands the variables
/// object to `JSON.stringify`, which drops a key whose value is `undefined`, so
/// a key written with a possibly-`undefined` value is not a key on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum VariablePresence {
    /// Every recovered call site writes the key, with a value no JS evaluation
    /// can make `undefined` (a literal, a comparison, a coercion like `x === !0`
    /// or `!!x`, a `??`/`||` whose right side is itself defined, a ternary whose
    /// both arms are).
    Always,
    /// At least one recovered call site can leave the key off the wire: it sits
    /// behind a conditional spread, its value passes an expression through that
    /// may be `undefined` (a bare binding, a property read, an optional chain),
    /// or that site's variables object does not write the key at all.
    Conditional,
    /// Not established. No call site was recovered for the operation, or the
    /// value is an expression form this extractor does not judge (a call, an
    /// `await`, anything whose result it cannot reason about). Deliberately not
    /// folded into `Conditional`: "the official client sometimes omits this" is
    /// a claim, and one this variant has not earned.
    Undetermined,
}

impl VariablePresence {
    /// The weaker of two claims about the same key, for merging call sites.
    ///
    /// Ordered `Always < Conditional < Undetermined`, so one site that may omit
    /// the key outweighs another that always writes it, and one unjudged
    /// expression outweighs both - a key is only `Always` when nothing seen
    /// contradicts it.
    pub fn weaker(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Presence of one variable key, plus the same answer for the keys nested under
/// it.
///
/// A sibling of `variablesShape` rather than a richer leaf inside it: enriching
/// the shape's type tags would break every consumer that reads them as strings,
/// and presence is a property of the *key*, not of the type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct VariablePresenceNode {
    pub presence: VariablePresence,
    /// Keys of the object this variable carries, when the call site writes an
    /// object literal. Empty for a scalar.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, VariablePresenceNode>,
    /// The element of a list variable. An element is not a key, so its own
    /// `presence` is `Always` by construction; it exists to carry the element's
    /// `fields`, which are keys and are subject to the same question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<VariablePresenceNode>>,
}

impl VariablePresenceNode {
    /// A leaf carrying just a verdict.
    pub fn leaf(presence: VariablePresence) -> Self {
        VariablePresenceNode {
            presence,
            fields: BTreeMap::new(),
            items: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct MexOperation {
    /// The full Relay operation name, e.g. `WAWebFetchGroupInfoQuery`.
    pub original_name: String,
    /// Persisted query id (numeric string), or the operation name when the
    /// query is sent as text rather than persisted.
    pub doc_id: String,
    pub operation_kind: MexOperationKind,
    /// Top-level variable (argument) names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<String>,
    /// Typed shape of the input variables (argument name → type tree).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables_shape: BTreeMap<String, TypeNode>,
    /// Whether the official client always sends each input variable, keyed the
    /// same way as `variables_shape` and nested the same way - see
    /// [`VariablePresence`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables_presence: BTreeMap<String, VariablePresenceNode>,
    /// Typed shape of the response (top-level field → type tree).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response: BTreeMap<String, TypeNode>,
}

/// The mex IR document: version stamp + operations keyed by short name (the
/// `WAWeb`/`Query`/`Mutation`-stripped name), sorted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct MexIr {
    pub wa_version: String,
    pub operations: BTreeMap<String, MexOperation>,
}
