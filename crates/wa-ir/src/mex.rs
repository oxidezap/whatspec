//! Mex (Relay GraphQL) IR — persisted query/mutation operations extracted from
//! WA Web: their persisted `docId`, kind, variable names, and (phase 2) the
//! `variablesShape` / `response` type trees.

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
