# Compiled qualification of #51 and #53

Status: **blocked by a reproduced source/output divergence**. This test is meant
for an explicitly stacked qualification change after the IQ workstream addresses
the finding. Do not silently add it to #51 alone: it requires #53's generated
context-taking API and small runtime adapter.

The local `test/composed-iq-qualification` branch composes these immutable heads:

- #51: `ebbfaedfdfab5543a796feadadae7ca397c45ff9`.
- #53: `a79c93f3fef9f15778cda88d889113011ea7d5a1`.
- Local composition commit: `1f847fe591057670986ea6cac82352f0c9144c27`.

No published head was changed. No emitter or other IQ-workstream file was edited.
The local merge preserved `wa-codegen` 0.2.0 and the exact audit dependency
versions from #54.

## Method and inputs

`crates/wa-codegen/tests/independent_iq.rs` runs `generate_iq` twice for each
snapshot and checks byte identity. It compiles each resulting Rust source with
`rustc --test`, then executes seven independently authored test groups in
`fixtures/independent_iq_cases.rs`. The expected outcomes are not generated from
IR or codegen. Only the in-memory node adapter, imports and constructors are
reused from #53; none of its expected-case assertions or main are run.

The selected input JSON files contain the two actual stanza records from the
committed IQ IR at `1a441f0` and `1f5167c`. Their full-source and selected-file
hashes are in `inputs/provenance.json`. Both inputs validate against the real IQ
schema. Metadata version is retained and unrelated unparseable entries removed.
These files are generator inputs, never sources of expected outcomes.

The pre-existing #51 captures establish requests and successful responses.
`sources/<waVersion>` adds 19 exact modules covering error envelopes, selected
code/text parsers, error disjunctions, reference access and parsing helpers.
Both complete bundle sets were verified again before AST capture. Each added
module has a hash and byte span in `provenance.json`. All 19 module bodies are
identical across the two snapshots. No JavaScript was executed.

To recapture with the same verified flow, build the `module_spans` example in
the default target directory, then run:

```sh
python3 tests/conformance/compiled/capture_errors.py LOCK BUNDLES NEW_OUTPUT
```

## Executed results

For **each** WA snapshot, 2.3000.1045368834 and 2.3000.1047483476:

| Compiled test group | Result |
| --- | --- |
| Request destination, namespace, type, subject bytes and accept attributes | Pass |
| Empty success, approval success, duplicate-child fallback, unknown extension | Pass |
| Ordered client/server outcomes, 304 exception, 400–499 and 500–599 bounds | Pass |
| Decimal coercion and malformed/absent/duplicate error inputs | Pass |
| Correlation for every response kind, absent/mismatched attrs, actual request context | Pass |
| Optional field payload and fallback after malformed/duplicate field | Pass |
| Binary error content before optional-child parsing | **Fail** |

The two pilot outputs are each 63,757 bytes. Their SHA-256 values are:

- Old: `2250a8ec0ea5ddf7a06250cc9be5ca74056012ae25a24aeb4872c5e0088d5763`.
- Current: `bbfcb27f75341e5d6bda2d98fcb1aaa1357864159167cb2e3fbf33377097ff84`.

The difference is the snapshot version in the generated header. The two-snapshot
compile-and-run test phase completed in about 0.82 seconds after building its
Rust test driver. This is a single shared-executor observation, not a benchmark.

## Minimal finding for the IQ workstream

Use a correlated SetSubject response with this tree:

```text
iq {type: "error", id: "req-1", from: "123@g.us"}
  error {code: "406", text: "not-acceptable"}
    content: binary bytes "opaque"
```

The source result is client error **IQErrorFallbackClient**. The compiled output
returns **IQErrorNotAcceptable**, with default empty `name` and `reason` strings.

Source trace:

1. `WASmaxInGroupsIQErrorNotAcceptableMixin` calls
   `optionalChildWithTag(error, "field", parser)` before checking code/text.
2. `WASmaxParseUtils.optionalChildWithTag` calls `optionalChild`, which calls
   `maybeChildren`. `maybeChildren` rejects `content instanceof Uint8Array`.
3. `WASmaxInGroupsSetSubjectClientErrors` continues after any specific failure.
4. `WASmaxInGroupsIQErrorFallbackClientMixin` reads only text and code in
   400..499, so this input reaches that fallback successfully.

The generated selector checks `get_children_by_tag("field").count() <= 1`,
then treats a missing optional child as default empty fields. It does not
establish that the error content is a child list or absent. Both snapshots
reproduce the same mismatch. The test sets only `bytes`, with an empty children
vector, so it does not create an impossible mixed binary/children input.

For current snapshot bundle
`09d91fdc4089c50ab1d35dd6c796ee82ef4c3296710316d20383c85738b871b8`:

- `WASmaxParseUtils`: bytes 2256336..2263058.
- `WASmaxInGroupsIQErrorNotAcceptableMixin`: bytes 88701..89641.
- `WASmaxInGroupsIQErrorFallbackClientMixin`: bytes 85725..86174.

The source disjunction is in bundle
`65b89bd62b933ca76911900c83c40c2fad84263a99d2b99eced9578c1e4bdf55`,
`WASmaxInGroupsSetSubjectClientErrors`, bytes 24289..26417.
All ends are exclusive. Hashes/spans for the old snapshot are retained alongside
its captured sources.

Reproduce the full matrix:

```sh
cargo test --locked -p wa-codegen --test independent_iq
```

On failure the generated source and compiled executable are retained in the
reported temporary directory. Run that executable with
`--exact binary_error_content_reaches_fallback` for the minimal failing case.

## Limits and next step

This executes generated Rust, not the Web client or server. The adapter is a
small tree implementation satisfying the reference emitter's existing paths;
it is not an external client's implementation and adds no client dependency.
It does not qualify binary encoding, arbitrary JS attribute types, JID helpers,
all builder-input rejection, transport, or the other IQ operations. The success
and error expectations are static source observations of preserved builds.

The IQ owner should choose a faithful content-kind guard or an explicit
unsupported-contract diagnosis when that semantic check cannot be expressed.
No change to their emitter is made here. After their fix, rerun this same failing
case and the complete matrix before proposing a stacked qualification PR with
explicit dependencies on both #51 and #53. Do not weaken the expected fallback
or turn the failure into an ignored test.

## IQ fix qualification

Composition updated with IQ-owned fix
`9e609d4dee4c80ec50bc42a75110e69db13400d8` from #53.
The original seven case groups were rerun without changing their expectations:
both snapshots changed from six passing / one failing to seven passing / zero
failing. The binary 406 error now selects `IQErrorFallbackClient`.

An additional independent group checks absent content versus empty binary
content and confirms attribute-only fallback accepts empty and nonempty bytes
for both pilots. The existing valid `field` child case still selects the specific
406 payload with its original name/reason. Both snapshots now pass all eight
groups, including deterministic regeneration and compiled execution. The combined
independent test phase took 0.79 s after build; #53's compiled runtime test also
passed. No original expected outcome was changed, no emitter was edited here,
and no test was disabled. Earlier failure evidence above refers to a863bfb.

## Integrated quality and fixture review

The composition includes quality #52 at
`1d5d7f3323a6b71493a1bd68b3a326dfb468b361`, preserving its commits,
and audit #54 via the existing dependency commits. A follow-up quality fix for
external schema references is pending; this is not final qualification.

Review identified two missing evidence checks. The offline CI fixture command now
checks both compiled source sets against their recorded AST lengths/hashes and
both selected inputs against provenance hashes and versions. Same-length source
and input mutations passed the former check and fail the extended check. This
verifies recorded identity, not authenticity of jointly edited provenance; full
recapture remains necessary. The selected records and complete historical IQ
hashes were also compared to their recorded git commits locally.

Both verified bundle sets were recaptured with `WASmaxInGroupsBaseServerErrorMixin`
added, giving 20 modules per snapshot. Its body shows the unique error child,
IQ error response correlation and ordered ServerErrors parser delegation. All
20 module bodies are identical between snapshots. No JavaScript was executed.
