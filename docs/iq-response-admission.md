# IQ response generation admission

This change admits the two verified pilots, not every possible IQ contract.
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
| `guards.reference_unsupported` / `guards.reference_nonuniform` | A recovered request reference cannot use the supported uniform wire context. |
| `guards.request_context_required` | Call `parse_response_with_request` with the actual request ID and target. |
| `outcomes.error_contract_unsupported` | A direct error payload has an assertion outside the bounded tag/code/text decoder; no generic fallback may erase that guard. |
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
| Outcomes | Source order retained and every supported outcome reachable. No primary-success fallback. | Rejected unions fail explicitly. Child presence is handled. Bounded direct code/text error unions preserve source order and distinguish partially overlapping outcomes; fully covered later outcomes are rejected. |
| Constraints | Literal values, ranges, enum policy, error code/text pairings and reference constraints retained. | Pilot code/text pairs, decimal-prefix integer coercion, inclusive ranges and unique selected children are enforced. No global constraint-admission claim. Existing `pending_drops` is not serialized, so it cannot prove per-operation recovery from saved IR. |
| Guards | Only demonstrated guards necessary for the selected operation. Request correlation must receive the actual request context. | Root tag, unique selected child and actual request ID/target checks are implemented. No universal expression AST is introduced. |

The generated inherent method accepts only wire strings:

```rust
spec.parse_response_with_request(&response, actual_request_id, actual_request_to)?
```

Use the ID and target of the stanza actually sent. The existing trait method
cannot supply that context and now returns `guards.request_context_required`
for correlated operations. It must not fabricate context from the response.
Unsupported reference paths fail admission explicitly. No transport, event or
consumer API is added, and no IR/schema changes are needed.

Integration review added three generator regressions, all failing at
`09adb8b7809b85dba8fdde4d3ebd7a3a4d0aed1b` and passing after correction:
collective error-range coverage uses guard implication rather than assertion
vector order; extra unmodeled direct-error assertions reject specialization
with a diagnostic; and disjoint root tags participate in both admission and
runtime selection. A stricter earlier child guard is a negative control for
coverage. These constructed IR cases check generator invariants; they do not
claim new server behavior. The real pilot execution tests remain unchanged.

## Verified pilots

| Operation | Request evidence | Ordered outcomes |
| --- | --- | --- |
| SetSubject | `GROUP_JID(iqTo)`; `<subject>` content is `subjectElementValue`. | Success, client error, server error. |
| AcceptGroupAdd | `GROUP_JID(iqTo)`; `<accept code=… expiration=… admin=…>` reads `acceptCode`, `acceptExpiration`, `acceptAdmin`. | Success with `membership_approval_request`, bare success, client error, server error. |

Both result and error mixins compare response `id`/`from` with request `id`/`to`.
SetSubject's empty success remains valid after envelope and context checks.
AcceptGroupAdd's client arm includes code 500 with text `resource-constraint`;
other code-500 errors can reach the later server arm. Classification therefore
uses ordered code/text pairs, not a guessed split between 4xx and 5xx.
The direct payload specialization requires matching IR field and error-arm
metadata, small bounded integer codes, and the demonstrated optional child shape.
Unsupported shapes retain explicit admission diagnostics.

`WASmaxParseUtils.attrInt` uses decimal `parseInt`: `0304`, `+304`, `304tail`
and `304.9` decode to 304 before literal/range checks. The generated bounded
error decoder retains that behavior and ECMAScript leading whitespace. Required
`<error>` is unique; duplicate approval children fail the gated success and
continue to bare success in source order. For SetSubject 406/`not-acceptable`, a malformed or duplicated optional
`<field>` makes the specific parser fail; the source disjunction then tries the
400–499 fallback, which succeeds. Code/text selection is not a commit point.
The compiled regression checks absent, valid, malformed and duplicated children.
`optionalChildWithTag` calls `maybeChildren` first, which rejects binary content
(including an empty byte array). A binary body on the 406/`not-acceptable` error
therefore reaches fallback too. The guard applies only to arms inspecting
children: attribute-only 400/`bad-request` and 500/`resource-constraint` retain
their specific outcomes with binary bodies. Empty, UTF-8 and non-UTF-8 byte
bodies are covered by the compiled regression.
Unknown unrelated children remain accepted. This is not general JavaScript evaluation or a universal guard AST.

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
- D: `7783a694b3a8bc3a379585817de0e477c75729c73b21adbffbf060f5f0ac2860`.

Modules were extracted statically with `wa_transform::extract_module_definitions`.
Offsets are byte intervals with exclusive ends. No `eval`, `vm`, sessions or
credentials were used to extract or test protocol behavior.

| Module | Bundle | Span |
| --- | --- | --- |
| `WASmaxOutGroupsSetSubjectChangeSubjectMixin` | A | 27847..28186 |
| `WASmaxOutGroupsSetSubjectRequest` | A | 28188..28588 |
| `WASmaxGroupsSetSubjectRPC` | A | 28590..29826 |
| `WASmaxInGroupsSetSubjectClientErrors` | A | 24289..26417 |
| `WASmaxOutGroupsBaseIQSetRequestMixin` | B | 1138342..1138644 |
| `WASmaxOutGroupsBaseSetGroupMixin` | B | 1138646..1139064 |
| `WASmaxInGroupsIQResultResponseMixin` | B | 107120..107921 |
| `WASmaxInGroupsIQErrorResponseMixin` | B | 31289..32087 |
| `WASmaxInGroupsAcceptGroupAddResponseGroupJoinRequestSuccess` | C | 4229..4728 |
| `WASmaxInGroupsAcceptGroupAddResponseSuccess` | C | 5098..5459 |
| `WASmaxOutGroupsAcceptGroupAddRequest` | C | 5461..5920 |
| `WASmaxGroupsAcceptGroupAddRPC` | C | 5922..7533 |
| `WASmaxParseUtils` | B | 2256336..2263058 |
| `WASmaxInGroupsIQErrorResourceConstraintMixin` | D | 623..1153 |

These are static observations of this preserved Web build, not proof of the
server's complete contract or current account behavior.

## Validation and cost

Four regression tests fail on the base commit and pass after the change: missing
contract, wholly discarded payload, an actual unrepresentable nested response
from `WAWebQueryBusinessCategoriesJob`, and ordered child-gated success. The
empty-outcome control remains successful. The pilot test reads the real IQ IR.
The whole generated file is syntax-checked. A separate integration test compiles
and executes the two real generated pilots with a small in-memory node adapter:
requests, empty/gated successes, ordered nested error payloads, code/text ranges,
coercion, duplicate children, unknown children, and missing/mismatched request
context. Copying this test to the first fail-closed commit reproduces the missing
context API failure. The adapter does not qualify a binary codec or a downstream
client; independent conformance remains separately owned.

Two debug generations of all 142 IQ operations produced identical 2,061,750-byte
outputs, SHA-256 `214c9d9fede66c9ff6cf4194e75a506b8fd780b9c56675f0232f864626d6ecbd`,
in 4.43 and 3.92 seconds, with 39 explicitly rejected parsers. The original base
produced 1,523,859 bytes in 2.84 and 2.98 seconds. The increase includes recovered
outcome types and context-taking parsers; it is not an optimization claim.
The Rust reference catalog remains ignored by git. Maintenance requires review
of the admitted/rejected operation set and the bounded helper against source
changes; neither a rejection count nor reduced output size is a quality target.

Reproduce with `cargo test --locked -p wa-codegen`, including 181 unit tests and
the compiled runtime integration test; `cargo clippy --locked -p wa-codegen
--all-targets -- -D warnings`; schema validation; and full bundle regeneration
with `whatspec update --check`. No generated IR or baseline changes are included.
The separately owned dependency audit fix from PR #54 is carried as its own
commit. Main commit `9b8bc4e05eec14fa49b488c8eb8e56ce8ac5bfdb` incorporates
the separately reviewed quality work from PR #52, including the source-backed
baseline reconciliation. This branch integrates that main revision without
additional baseline changes. Independent two-snapshot pilot qualification is
maintained in PR #55, outside this emitter patch.
