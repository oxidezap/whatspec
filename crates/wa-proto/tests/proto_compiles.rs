//! Guard: the committed `generated/proto/WAProto.proto` must be a syntactically valid,
//! fully self-consistent protobuf schema.
//!
//! `WAProto.proto` is the only generated artifact with no validation in CI — the JSON
//! domains are schema-checked by `scripts/validate-schemas.py`, but the `.proto` was
//! never even parsed. Since `update.yml` auto-regenerates and auto-commits on new
//! WhatsApp versions with no human review, a future bundle change that breaks extraction
//! (a dangling type reference, a duplicate message name, mis-scoped enum values — exactly
//! the failure class the enum-relocation pass in `extract.rs` risks producing) would be
//! committed silently. `protox` is a pure-Rust protoc that parses *and* resolves every
//! type, so such a break fails `cargo test` here instead.

use std::path::Path;

#[test]
fn committed_waproto_compiles_and_resolves() {
    let proto_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../generated/proto");
    let proto_file = proto_dir.join("WAProto.proto");

    // The artifact is committed and produced by the generator, but tolerate its absence
    // (e.g. a partial checkout) rather than fail spuriously.
    if !proto_file.exists() {
        eprintln!("skipping: {} not present", proto_file.display());
        return;
    }

    // `compile` parses the file and resolves every cross-reference against the include
    // root; an unresolved type name, duplicate definition, or mis-scoped enum value is a
    // hard error — precisely what we want to catch.
    let descriptors = protox::compile(["WAProto.proto"], [&proto_dir]).unwrap_or_else(|e| {
        panic!(
            "committed generated/proto/WAProto.proto is not a valid, self-consistent \
             protobuf schema: {e}"
        )
    });

    // Sanity floor: the real schema compiles to a non-empty descriptor set. An empty one
    // would mean the include root resolved to nothing meaningful.
    assert!(
        !descriptors.file.is_empty(),
        "expected the committed WAProto.proto to compile to at least one file descriptor"
    );
}
