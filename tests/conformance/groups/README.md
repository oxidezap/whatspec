# Group normalization qualification

`group-unlink.json` is an isolated experimental projection, not the complete
normalized `w:gp2` parser. It does not replace the existing shape catalog and is
not registered as a complete domain in the manifest. Its spans are relative to
the complete `WAWebHandleGroupNotification` module recorded in `evidence.json`.

Regenerate with `cargo run -p wa-notif --example unlink_contract -- <handler-bundle>
<group-type-bundle>`. Inputs must be the exact restored bundle set. The extractor
rejects conflicting module definitions, parse errors, unsupported helper
statements and changed group-data projections. It evaluates every literal,
object key and an unknown sentinel, then retains the input distinctions which
change the normalized action. Null input keys represent unknown-value fallback;
an absent and an unknown reason must have the same behavior or extraction fails.
`unlink_type` itself remains required by the wire parser.

`node tests/conformance/groups/unlink.cjs` simulates the isolated official helper
with synthetic attributes and compares it with the IR. It checks the preserved
module hashes first. The constant module is official too; unrelated services,
transport, storage and the authenticated client are not run. Rust tests compare
the committed projection with AST extraction and mutate guards/effects.

The envelope, participant/history gates, create/link normalization and the
runtime adapter still require separate qualification. Raw create/link/unlink
nodes in consumers are not proof of a complete normalized parser.
