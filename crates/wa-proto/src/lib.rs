//! Native tooling: extract WhatsApp protobuf message/enum specs from WA Web
//! bundles (the `internalSpec` modules) and emit a `WAProto.proto`.
#![cfg(not(target_arch = "wasm32"))]

mod extract;
mod stringify;

pub use extract::{extract_proto, extract_proto_from_modules};
pub use stringify::stringify;
