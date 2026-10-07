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

## Joint qualification through schema closure fix

Quality #52 at `eaea5f9e5d864ee9d5ef4074709eddb9aba51735` is now
integrated with original ancestry. The follow-up changes Python validation and
its tests/docs, not Rust extraction or code generation. Its 15 Python tests pass,
including references in unvisited branches. The composition workflow now runs
`python3 -m unittest discover -s scripts/tests -v` after installing jsonschema;
the separate conformance-fixtures job remains unchanged.

Local workspace tests with all features passed: 1,657 tests, none failed or
ignored. This includes the two compiled independent snapshot suites and the IQ
owner's runtime suite. All-feature/all-target Clippy and formatting passed.
The committed 12 schema/document pairs, all exact lint baselines and five fixture
tests pass. The current snapshot regenerated twice with all 35 files identical:
15,384,513 bytes, 45.132 s and 51.543 s. The committed 27-artifact `--check` passed
in 53.467 s. These are development-build observations, not comparable performance
benchmarks against the earlier release-build baseline.

CI run 37698190460 on 7ea45e4 passed determinism and fixture checks, but failed
before running Rust tests: Cargo could not remove `target/debug/examples/gen`
with ENOENT. Its log also identifies output-name collisions among the existing
`gen` examples in wa-appstate, wa-codegen, wa-mex and wa-proto. This is not a
conformance assertion failure; it remains an infrastructure issue to coordinate.
A local default-feature build separately exhausted disk space; only this
composition's build cache was removed, and the retry disables debug symbols.

The three fixture-review threads have evidence replies and are resolved.
Further quality findings about local objects in merges and overlapping module
definitions remain under investigation by their owner. Do not declare complete
stability from this qualification. No other PR branch has been modified.

The default-feature retry completed with 1,657 passing tests, zero failures and
zero ignored tests. Both snapshots still pass all eight independent compiled
case groups. The old snapshot also regenerated twice identically: 35 files,
15,307,071 bytes. Runs took 43.237 s and 83.053 s; the latter overlapped the clean
Rust build after disk recovery. Its 12 schema/document pairs pass the updated
validator. The interrupted generation was not counted as a successful repeat.

Recommended integration order is #54, #52, #51 and #53, followed by #55's remaining
qualification changes after retargeting/reviewing its diff. Preserve ancestry and
avoid redistributing the composition commits into the individual workstreams.

## Cargo example output collision repair

The CI failure is supported by Cargo's own collision diagnostics, not classified
as an unexplained flaky test. `cargo metadata --no-deps --format-version 1` on
cd0f9da reports four auto-discovered example targets named `gen`, owned by
wa-appstate, wa-codegen, wa-mex and wa-proto. All use the same output path
`target/debug/examples/gen`; run 37698190460 then fails removing that path with
ENOENT during the parallel workspace build.

Each example now has a unique filename/target. No manifest or concurrency setting
changes are needed. Invocation migration, with all remaining arguments unchanged:

| Package | Previous example | New example |
| --- | --- | --- |
| wa-appstate | `--example gen` | `--example gen_appstate` |
| wa-codegen | `--example gen` | `--example gen_iq` |
| wa-mex | `--example gen` | `--example gen_mex` |
| wa-proto | `--example gen` | `--example gen_proto` |

The source command documentation and usage messages follow the new names.
Extraction/generation logic is unchanged. Old target-name aliases are not retained
because they would recreate the shared output path. These are developer examples;
no library API or generated contract changes.

Validation: a uniqueness check over Cargo metadata fails on cd0f9da with exactly
those four targets and passes after the rename. `cargo build --workspace --examples
--message-format=json` reports four distinct executable paths. Parallel
`cargo test --workspace` passes 1,657 tests with zero failures/ignored tests and no
output-collision warning. Parallelism was not reduced.

## Quality follow-up 106c762

Integrated #52 at `106c7621348935daa343edf73ebc6ad50ad798a8` with
ancestry intact and no conflicts. Its nested-module, local-merge, unknown-field
site and schema-diff regressions pass. The workspace now passes 1,663 tests,
including the compiled pilot suites, with zero failures or ignored tests.
All-feature/all-target Clippy, formatting, 12/12 committed schemas, exact lint,
15 quality Python tests and five capture tests pass.

Review dispositions remain separate:

- PRRT_kwDOSxmno86qIUij: the nested-definition regression establishes the same
  counted definitions and diagnostic totals as production extraction. The full
  nested source index is retained for provenance lookup.
- PRRT_kwDOSxmno86qIUin: unknown-field sites are fixed, but global-channel gaps
  remain unlocated. The independently built CLI reproduces a counter of two with
  an empty site list and no explicit unlocated-counter field. Keep this open.
- PRRT_kwDOSxmno86qIUie: manifest-to-lock identity is still owned by quality and
  remains open; a matching version alone does not bind the input bundle set.

The remaining global-channel reproduction uses a synthetic single-bundle lock,
verified by the normal CLI path, without executing JavaScript:

```javascript
__d("WAWebWamGlobals",["WAWebWamCodegenUtils"],function(t,n,r,o,a,i,l){var e=o("WAWebWamCodegenUtils");l.Global=e.defineGlobal({computed:[3,e.TYPES.STRING,[CHANNEL]],empty:[4,e.TYPES.STRING,[]]})});
```

Using exactly those bytes without a trailing newline yields setHash
`840dfc3f996afcfac451f80043580175b4443db0487ec4c056ffb02bc9fd57be`.
`whatspec quality-gaps LOCK BUNDLE_DIR` returns
`dropsByReason: {"global with an unreadable channel list": 2}` and
`wamGapSites: []`. The review thread records this evidence for the quality owner;
no implementation was duplicated in this workstream.

The integrated CLI also passes the locked current-snapshot `--check`, reproducing all 27 committed artifacts after the WAM changes.

## Final quality integration d067d60

Integrated #52 `d067d60b4042455aa9fb1c0fa4850b7e93fff214` without
conflicts. The delta retains conservative WAM values after opaque setters,
property overwrites and merge operands, and explicitly represents incomplete
provenance instead of implying verification.

Independent CLI reproductions close the remaining review findings:

- With identical artifact/manifest bytes and two different self-consistent locks
  sharing one WA version, report v2 returns `sameInputs: null`,
  `sameDeclaredInputs: false` and `inputBinding.status: unverified` on both sides.
  Comparing the same snapshot also leaves actual input identity unknown.
- A changed artifact and a matching v2 review retain `inputBinding: unverified`
  on the delta. Applying an assessment does not promote declared inputs into
  verified inputs. Version-1 review evidence is rejected explicitly.
- The exact global-channel fixture recorded above now returns two total gaps and
  two `unlocatedDropsByReason` gaps, with an empty site list. No location is
  fabricated and no counted gap disappears.

The final composition passes 1,671 workspace tests, zero failures/ignored tests,
including eight compiled independent groups per snapshot and the IQ runtime
suite. All-feature/all-target Clippy, formatting, 12/12 committed schemas, lint,
15 quality Python tests and five fixture tests pass. These checks use the final
quality head; older generation size/timing observations above remain historical.

Residual limits do not block the two bounded IQ pilots: historical manifests
cannot prove which declared bundle set generated their artifacts; unreadable
WAM global channel lists have counted but unlocated gaps; incomplete dynamic
JavaScript semantics remain explicit diagnostics. This conformance harness uses
an in-memory adapter and static source evidence, so it does not certify an
external binary codec, server behavior, all IQ operations or complete MEX/WAM
coverage. Report v2 requires consumers of the optional diff/review format to
migrate; no schema version or downstream-client contract was silently changed.

The final locked `--check` passes for all 27 committed artifacts. The additional
Greptile merge-order finding is covered by the integrated seven-case
`constructor_merges_follow_operand_order_without_overstating_unknown_overrides`
regression: later unknown operands clear earlier constants while later explicit
writes can restore a known value. Its object-property and opaque-setter neighbor
regressions also pass. No further implementation was added in this workstream.
