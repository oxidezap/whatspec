# App-state validation boundary

`manifest.domains.appstate.validation` and `batchValidation` point to independently
versioned format-1 programs. The action-schema IR and its global version stay
unchanged. Both documents have JSON Schemas and reject unknown operations.

The protobuf compiler lowers all six exported methods, every executable statement,
subvalidator call, condition, dependency call and return projection. Nullish checks
and JS truthiness are distinct instructions. Empty byte buffers and arrays are
truthy; absent and null values are not. Mapping executes before later guards,
including snapshot records before MAC/key validation. Both patch return arms are
represented, including the omission of exitCode in the external arm.

The batch recognizer qualifies the *whole* `WAWebSyncdValidateMutations` module
against the reviewed AST-parsed reference. It tolerates whitespace and consistent
minifier renaming, but rejects algorithm changes. `SeparateSetRemoveV1` emits two
sets, fatal Patch errors, nonfatal Snapshot diagnostics and Local warnings. A
Snapshot diagnostic can itself fail while decoding duplicate actions; that error
propagates. The decoded SET method is lowered through the same expression compiler.
Diagnostic dependencies are explicit `BatchEffects` hooks; crypto, persistence,
downloads, logging policy and recovery remain host responsibilities.

The Rust emitter produces ordinary functions and control flow over a borrowed byte
view. Objects and arrays share immutable storage across slots; native text views
borrow their input. String length counts UTF-16 units. Named function expressions,
default parameters and other unqualified lexical forms fail extraction.
There is no JavaScript runtime or IR interpreter. `Transforms` supplies the
protobuf decoder and representation conversions. `WASyncdKeyTypes.toSyncKeyId` is
an identity operation in this snapshot. `WALongInt.numberOrThrowIfTooLarge` checks
that the decoder returned a JS number, not `Number.isSafeInteger`; native adapters
must retain the distinction between decoded safe numbers and HexLong values.

`crates/wa-codegen/tests/fixtures/appstate_evidence.json` identifies the locked
archive, bundle hashes and AST byte spans. The isolated official-method fixtures
cover 4,671 protobuf and 258 batch cases. The protobuf decoder is stubbed there to
exercise call/error order, so those cases do not prove the decoder implementation.
They compare fatal class/message/metric, dependency error class and full successful
projections. Batch diagnostic traces are compared; log wording is not a contract.
No authenticated WhatsApp client or server was exercised. The batch recognizer is
qualified for this one distinct source shape; byte-identical older snapshots do
not establish robustness to a future refactor.

Regenerate the oracle fixtures with `oracle.cjs` and `batch_oracle.cjs` in
`crates/wa-appstate/tests/fixtures/`, using the hash-pinned AST-extracted modules.
Regenerate the Rust fixtures with the `wa-codegen` `gen_validation` example.
