//! Native tooling: extract WhatsApp Mex (Relay GraphQL) persisted operations from
//! WA Web bundles - each `*.graphql` module's persisted `docId`, kind, variable
//! names and typed shapes, plus whether the official client always sends each
//! variable.
#![cfg(not(target_arch = "wasm32"))]

mod extract;
mod presence;
mod shape;

pub use extract::{
    MexDiagnostics, PresenceDiagnostics, extract_mex, extract_mex_from_modules,
    extract_mex_from_modules_with_diagnostics, extract_mex_with_diagnostics,
};
