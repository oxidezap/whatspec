//! Native tooling: extract WhatsApp Mex (Relay GraphQL) persisted operations from
//! WA Web bundles — each `*.graphql` module's persisted `docId`, kind, and
//! variable names.
#![cfg(not(target_arch = "wasm32"))]

mod extract;
mod shape;

pub use extract::{extract_mex, extract_mex_from_modules};
