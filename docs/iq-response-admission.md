# IQ response generation admission

This is the first response-emitter change, not a claim of complete IQ generation.
`wa-codegen` 0.2.0 stops reporting success when response generation loses a
contract, payload, or outcome. It does not change the language-neutral IQ schema
or add a runtime dependency. The schema remains 4.3.0.

## Behavior and migration

An operation whose response cannot be represented retains its previous fallback
associated response type, including `()` where that was the old type. Its parser
now always returns an error naming the operation and the generation limitation.
The generated spec also exposes `RESPONSE_GENERATION_ERROR: &'static str` when
its response generation is rejected. This constant is an emitter diagnostic,
not a wire protocol field. An operation without this constant is **not** thereby
certified complete.

| Diagnostic | Meaning |
| --- | --- |
| `response.contract_missing` | No recovered response fields or explicit outcomes. Empty metadata does not prove an empty successful response. |
| `response.payload_unemittable` | Recovered fields produced no response payload. |
| `response.parser_unemittable` | The generated initializer cannot represent the recovered payload. |
| `outcomes.unemittable` | A variant parser cannot be emitted, or an earlier variant can shadow a later one under the emitter's known predicates. The message names variant indexes and tags. |

An explicit, admitted empty outcome still produces a successful empty outcome
value after its selector matches. Rejected outcome unions no longer silently
use only their primary success mirror. Child-presence assertions participate in
both the admission signature and emitted selector. A gated success followed by
a bare success retains both branches; reversing them still fails admission.

Consumers upgrading from 0.1.0 must review the diagnostics for their selected
operations. Use a reviewed implementation for a rejected operation until its
missing semantics are supported. Do not convert the new errors back into unit
success. Request constructors and existing fallback response types remain;
newly admitted unions can change an associated response from a struct to an enum.
This behavior change is why the emitter version changes to 0.2.0. No release is
published by this change.

This is generation-time rigor, not a policy requiring runtime rejection of every
unknown extension in an otherwise supported stanza.

## Admission design for coordination

A future strict entry point needs a report keyed by `moduleName` and wire path,
with independent status and diagnostics for each dimension below. Status must
separate supported, unsupported, and not established; an absent diagnostic cannot
mean that unknown semantics were proved absent. Generation is admitted only when
all dimensions required by the selected operation are supported. This report is
a proposed interface, **not implemented by the response-only constant above**.

| Dimension | Required evidence / rule | Status in this patch |
| --- | --- | --- |
| Request | Known target, argument mapping, content, child cardinality and variants; no invented inputs. | Existing request emitter preserved; pilot mappings tested. No general strict request admission. |
| Response | All recovered payload fields emitted; explicit empty outcome distinguished from missing extraction. | Missing/fully discarded payload and invalid initializer fail explicitly. This is not a recursive completeness proof. |
| Outcomes | Source order retained and every supported outcome reachable. No primary-success fallback. | Rejected unions fail explicitly. Child presence is handled. Error-arm discrimination remains a pilot blocker. |
| Constraints | Literal values, ranges, enum policy, error code/text pairings and reference constraints retained. | No new global constraint-admission claim. Existing `pending_drops` is not serialized, so it cannot prove per-operation recovery from saved IR. |
| Guards | Only demonstrated guards necessary for the selected operation. Request correlation must receive the actual request context. | Child-presence guard added. Correlation is not implemented in this patch; no universal expression AST is introduced. |

Proposed correlation input is the actual request's `id` and `to`, independent of
any caller's transport, event model or application API. The legacy response
method has no generated request ID. A follow-up must define a context-taking
entry point before claiming checks of `response.id == request.id` and
`response.from == request.to`. Do not infer these from an unrelated request or
hardcode the server address. Any IR/schema additions for recovery status need
coordination with the snapshot and conformance fronts; none are made here.

## Pilot findings

Both pilots remain rejected by full outcome admission in this patch. The gate
cannot distinguish their client-error and server-error arms using its current
signature, although the IR carries their error vocabularies. Admitting only the
success variants would conceal that limitation.

| Operation | Request evidence | Ordered outcomes | Current emitter diagnostic |
| --- | --- | --- | --- |
| SetSubject | `GROUP_JID(iqTo)`; `<subject>` content is `subjectElementValue`. | Success, client error, server error. | `response.variants[1] SetSubjectResponseClientError can shadow response.variants[2] SetSubjectResponseServerError`. |
| AcceptGroupAdd | `GROUP_JID(iqTo)`; `<accept code=… expiration=… admin=…>` reads `acceptCode`, `acceptExpiration`, `acceptAdmin`. | Success with `membership_approval_request`, bare success, client error, server error. | `response.variants[2] AcceptGroupAddResponseClientError can shadow response.variants[3] AcceptGroupAddResponseServerError`. |

Both result and error mixins compare the response's `id` and `from` with the
request's `id` and `to`. SetSubject's success has no operation payload beyond the
result envelope; it still requires those checks. The generated ID comes from the
base request mixin. Assertions are verified in the committed IR tests, but those
tests do not claim the generated parser enforces correlation.

### Source provenance

Revalidated against repository `1f5167c4cebf263edaf001e06a2497f213c55793` and
WhatsApp Web snapshot `2.3000.1047483476`, on 2026-10-07. Remote HEAD matched.
The reference report was checked against the bundle and current checkout.

The exact [bundle-store asset](https://github.com/oxidezap/whatspec/releases/download/bundle-store/bundles-2.3000.1047483476-05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b.tar.xz)
was already present in the selected environment. `whatspec restore --from-lock
… --archive …` verified all 579 bundles against the committed lock.

- Archive SHA-256: `22243b9c2ff18a66cea8fd66551821fe0f9f09786d107e2be8284637db86c349`.
- Bundle set hash: `05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b`.
- A: `65b89bd62b933ca76911900c83c40c2fad84263a99d2b99eced9578c1e4bdf55`.
- B: `09d91fdc4089c50ab1d35dd6c796ee82ef4c3296710316d20383c85738b871b8`.
- C: `34859849724a114869fd78e4479a6c412b4ab3ec36c3da2985d8ec4ecb75d5d2`.

Modules were extracted statically with `wa_transform::extract_module_definitions`.
Offsets are byte intervals with exclusive ends. No `eval`, `vm`, sessions or
credentials were used to extract or test protocol behavior.

| Module | Bundle | Span |
| --- | --- | --- |
| `WASmaxOutGroupsSetSubjectChangeSubjectMixin` | A | 27847..28186 |
| `WASmaxOutGroupsSetSubjectRequest` | A | 28188..28588 |
| `WASmaxGroupsSetSubjectRPC` | A | 28590..29826 |
| `WASmaxOutGroupsBaseIQSetRequestMixin` | B | 1138342..1138644 |
| `WASmaxOutGroupsBaseSetGroupMixin` | B | 1138646..1139064 |
| `WASmaxInGroupsIQResultResponseMixin` | B | 107120..107921 |
| `WASmaxInGroupsIQErrorResponseMixin` | B | 31289..32087 |
| `WASmaxInGroupsAcceptGroupAddResponseGroupJoinRequestSuccess` | C | 4229..4728 |
| `WASmaxInGroupsAcceptGroupAddResponseSuccess` | C | 5098..5459 |
| `WASmaxOutGroupsAcceptGroupAddRequest` | C | 5461..5920 |
| `WASmaxGroupsAcceptGroupAddRPC` | C | 5922..7533 |

These are static observations of this preserved Web build, not proof of the
server's complete contract or current account behavior.

## Validation and cost

Four regression tests fail on the base commit and pass after the change: missing
contract, wholly discarded payload, an actual unrepresentable nested response
from `WAWebQueryBusinessCategoriesJob`, and ordered child-gated success. The
empty-outcome control remains successful. The pilot test reads the real IQ IR.
The whole generated file is syntax-checked, not type-checked against an external
consumer. The conformance front owns independent execution validation.

Two in-process debug generations of all 142 IQ operations produced identical
1,204,604-byte outputs, SHA-256
`4a4473e33d9e8fbcdf87d47783b0ea6c654fdd13243695918910e72c380fb50f`,
in 2.43 and 2.40 seconds. 69 parsers have an explicit rejection diagnostic.
The base emitter produced 1,523,859 bytes in 2.84 and 2.98 seconds in the same
debug setup. The smaller output mostly removes parsers that could not preserve
all outcomes; it is not an optimization claim. These are local generation
measurements, not runtime or release-build benchmarks.
The reference Rust file is ignored by git; no new checked-in generated catalog or
runtime dependency is required. Future updates must review the rejected operation
set as well as source changes, without relaxing admission to preserve a count.

Local validation passed `cargo test --locked --workspace`, including 176
`wa-codegen` tests,
`cargo clippy --locked -p wa-codegen --all-targets -- -D warnings`, formatting,
and all 12 real JSON Schemas. Full bundle regeneration with `--check` reported
27 committed artifacts up to date. `scripts/lint-ir.py` still fails on the
pre-existing exact-count baselines; its output is byte-identical on the base
commit and this branch. This patch changes neither IR nor baselines.
