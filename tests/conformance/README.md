# Independent conformance baseline

This baseline checks extraction against reviewed Web source for SetSubject,
AcceptGroupAdd and FetchNewsletter. It adds no consumer dependency or runtime
API. It does not qualify the reference Rust emitter or the server protocol.

The IQ test extracts the captured modules afresh and compares the resulting
contract with hand-reviewed expectations. It also checks the committed IQ IR.
Its response model supports only the selected success assertions. An additional
success field or unknown assertion needs an explicit test extension. This is
static verification, not execution of the JavaScript builders or parsers.

## Evidence

Captured from the exact `bundle-store` assets for these commits. Both manifests
use schema version 4.3.0. No account, credentials or session data were used.

| Snapshot | Repository commit | Bundles | Uncompressed JS bytes |
| --- | --- | ---: | ---: |
| 2.3000.1045368834 | `1a441f0329c941fcdb238490a6c604550d8a9939` | 516 | 77,347,149 |
| 2.3000.1047483476 | `1f5167c4cebf263edaf001e06a2497f213c55793` | 579 | 75,824,128 |

The old setHash is
`99a75bd7a4961e15051172c8b99fc460d57e58f7eb47ea9c46824657dd083e00`.
The current setHash is
`05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b`.

The asset name is `bundles-<waVersion>-<setHash>.tar.xz` under
[the bundle-store release](https://github.com/oxidezap/whatspec/releases/tag/bundle-store).
The measured archive SHA-256 digests are, respectively:

- `2edd4b3f8dae50b503e0b15920adc774e2680cdb542396d57608bb0374196ee1`
- `22243b9c2ff18a66cea8fd66551821fe0f9f09786d107e2be8284637db86c349`

Each snapshot's `provenance.json` records all selected definitions, bundle SHA-256,
byte start/end with exclusive end, and source hash. The fixture bytes are the
exact AST span plus `;\n`. The capture verifies the complete JS multiset against
the lock, including multiplicity, size, bundle count and recomputed setHash.
It rejects missing modules and divergent duplicate definitions before writing.
It uses `wa_transform::extract_module_definitions`, never eval or vm.

Only module boundaries share infrastructure with extraction. Expected protocol
facts below come from reviewing the captured source, not the extracted IR or
emitter. This does not independently verify the AST parser itself.

## Reviewed expectations

| Source path | Observation | Checks |
| --- | --- | --- |
| BaseSetGroupMixin -> BaseIQSetRequestMixin | `GROUP_JID(iqTo)`, namespace `w:g2`, type `set` | Both request contracts retain target, argument path, namespace and type |
| SetSubjectRequest -> ChangeSubjectMixin | `subjectElementValue` is `<subject>` content | Dynamic content argument survives extraction |
| AcceptGroupAddRequest | `acceptCode`, `acceptExpiration`, `acceptAdmin` become code, expiration, admin through CUSTOM_STRING, INT, USER_JID | Required attributes, types and argument paths |
| IQResultResponseMixin | Tag iq, type result, id equals request.id, from equals request.to | Missing, null and mismatched attributes, wrong tag, missing correlation context |
| AcceptGroupAddRPC | Approval success, bare success, client error, server error, in that order | Outcome order, child-present and childless successes, mutations removing gate or reversing successes |
| AcceptGroupAddResponseGroupJoinRequestSuccess | `flattenedChildWithTag(..., "membership_approval_request")` must succeed | Child-presence gate retained |
| SetSubjectResponseSuccess / AcceptGroupAddResponseSuccess | No payload child required and no extra-child rejection in these wrappers | Legitimate empty result, unrelated extension child |

The success values still contain the pinned `type` field. “Empty success” means
no payload child, not permission to drop envelope validation or correlation.

The small response model does not implement nested child flattening, helper
coercions, request builder execution, binary encoding, error payload parsing,
transport, timing or server behavior. It does not establish rejection rules for
invalid JavaScript builder arguments. Error outcome *order* is covered; the
error parser dependency closure is deliberately outside this capture. It does
not prove that a generated Rust parser enforces these constraints. Full
qualification remains pending integration with the other workstreams.

## MEX triage

The complete captured FetchNewsletter job and GraphQL module are identical in
both snapshots. `fetch_full_image` and coerced flags are always present;
`fetch_viewer_metadata` is conditional because a bare property read can be
undefined; `fetch_pinned_messages` remains undetermined because its external
call is not analyzed. Nested input.type is always present while input.key and
input.view_role can be omitted.

All these flag variables have inferred boolean type from their `fetch_` names.
The extractor's scalar-name heuristic supplies that type; these tests do not
establish inference from Relay conditions.
That type does not prove nullability or presence. Synthetic callers of the real
GraphQL operation separately test null, false, undefined, a property read, a
comparison and an unresolved call. Null survives JSON object-key serialization;
undefined does not. These fixtures do not claim the server accepts null for a
boolean variable. No concrete whatspec MEX defect was found in these cases,
and no MEX production implementation was changed.

## Run and recapture

Run from the repository root:

```sh
cargo test -p wa-scan -p wa-mex --test independent_conformance
python3 -m unittest discover -s tests/conformance -p 'test_*.py'
cargo fmt --all -- --check
```

The Python tests check fixture span/hash identity and rejection of changed,
missing, extra bundles, wrong setHash and wrong bundle count. They need no
network or compiled extractor. Instrumented subprocess tests also cover input
mutation and single-quoted or escaped module names reaching the AST. Those tests
check the subprocess boundary, not AST correctness. The Rust tests use only
committed fixtures.
The independent CI job `conformance-fixtures` runs
`python3 tests/conformance/test_capture.py -v` on every workflow run, including
when dependency checks fail in the separate `check` job.

To review a new snapshot, first restore its exact lock from bundle-store, then:

```sh
cargo build -p wa-transform --example module_spans
python3 tests/conformance/capture.py LOCK_JSON VERIFIED_BUNDLE_DIRECTORY NEW_CAPTURE_DIRECTORY
```

`NEW_CAPTURE_DIRECTORY` must not exist. `capture.py` expects the example at
`target/debug/examples/module_spans`. If using a custom Cargo target directory,
copy that executable there or build the example with the default target first.
Review all changed definitions and dependency paths before changing expected
outcomes. Every bundle is parsed without a substring prefilter, so valid string
spellings are not silently excluded. The helper receives the already verified
bytes on stdin; it does not reread the input file. AST module definitions supply
the actual byte spans.

The 2026-10-07 cloud executor's `whatspec restore` failed with
`invalid peer certificate: UnknownIssuer`. Downloading the *same* release asset
with curl's active TLS validation succeeded. Every extracted JS hash and size
was then checked against the committed lock. TLS verification was not disabled.

## Before/after evidence

The test `source_derived_contracts_hold_across_two_verified_snapshots` was copied,
with these fixtures, into an isolated worktree at
`4e4c50a39b0b7d4e94a79697ee2d334d7e391c90`, before the child-gate fix.
It fails on the bare AcceptGroupAdd result:

```text
left:  Some("AcceptGroupAddResponseGroupJoinRequestSuccess")
right: Some("AcceptGroupAddResponseSuccess")
```

The same test passes at baseline HEAD `1f5167c4cebf263edaf001e06a2497f213c55793`.
Use a distinct `CARGO_TARGET_DIR` for each worktree when reproducing this check;
sharing one target across these same-version worktrees caused stale build
artifacts during the initial experiment. The final checks use separate targets.
The permanent mutation test also catches lost child gates and reordered outcomes.

## Update effort and generation cost

All 13 captured module definitions are byte-identical between the two snapshots.
All 13 provenance locations changed. Updating this selected baseline required
zero semantic expectation changes and zero source overrides. The two fixture
sets, including provenance, occupy 16,901 and 16,905 bytes. This observation does
not establish stability of the rest of either bundle or eliminate future review.
Recapture with verified bytes on stdin and no lexical prefilter reproduced both
sets byte-for-byte. It took 23.265 s for the old snapshot and 18.812 s for the
current snapshot on this executor, excluding download and compilation.

Generation used baseline HEAD, the release-profile CLI, rustc 1.99.0, x86_64
Linux, offline restored bundles, and separate initially empty output directories.
Times are individual wall-clock observations on a shared cloud executor; the
first run overlapped a test build. They are not performance claims. Build time,
download time and archive decompression are excluded.

| Snapshot | First generation | Repeat generation | `--check` | Output files | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2.3000.1045368834 | 14.060 s | 11.853 s | 11.999 s | 35 | 14,750,300 |
| 2.3000.1047483476 | 12.616 s | 12.872 s | 11.801 s | 35 | 14,828,437 |

All 35 files matched byte-for-byte between independent generations for each
snapshot. The output size increased by 78,137 bytes. The CLI's `--check` covers
27 committed artifacts; it also passed against the current committed tree.
All 12 schema/document pairs passed validation for the committed snapshot and
both regenerated outputs. Reference Rust output is included in the 35-file
comparison but was not compiled against a runtime consumer.

Reproduce with the release CLI, explicit version and empty output paths:

```sh
cargo build --release -p whatspec
time target/release/whatspec update --bundles BUNDLES --wa-version VERSION --out OUTPUT_1
time target/release/whatspec update --bundles BUNDLES --wa-version VERSION --out OUTPUT_2
diff -qr OUTPUT_1 OUTPUT_2
time target/release/whatspec update --bundles BUNDLES --wa-version VERSION --out OUTPUT_1 --check
python3 scripts/validate-schemas.py OUTPUT_1
```

Current lint remains red on six *improved* exact baselines: unresolved IQ
attribute paths 49 vs 55, child paths 10 vs 12, MEX operations without established
presence 10 vs 13, undetermined MEX variables 106 vs 108, WAM constructions with
no catalog entry 29 vs 41, and unread WAM arguments 93 vs 104. Baselines and CI
were not changed here, apart from adding the independent fixture-test job.
Published-SHA CI and combined emitter qualification are
still required before declaring the repository qualified.
