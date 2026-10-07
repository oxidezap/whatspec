# Snapshot quality investigation — 2026-10-07

Remote HEAD at the initial check was `1f5167c4cebf263edaf001e06a2497f213c55793`;
the prior snapshot was `1a441f0329c941fcdb238490a6c604550d8a9939`. Their difference
contains only 16 generated files, with the same extractor and IR schema 4.3.0.
The Library research report supplied for this investigation was treated as claims
to verify. No other repository or real session was used.

| Evidence | Old | New |
|---|---|---|
| WA version | 2.3000.1045368834 | 2.3000.1047483476 |
| Bundles | 516 | 579 |
| Set hash | `99a75bd7a4961e15051172c8b99fc460d57e58f7eb47ea9c46824657dd083e00` | `05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b` |
| Archive SHA-256 | `2edd4b3f8dae50b503e0b15920adc774e2680cdb542396d57608bb0374196ee1` | `22243b9c2ff18a66cea8fd66551821fe0f9f09786d107e2be8284637db86c349` |

Both archives came from this repository's `bundle-store` release. Restore checked
the exact bundle multiset, sizes, hashes and set hash. Rust TLS reported
`UnknownIssuer`; `curl` downloaded the same assets using the environment trust
store without disabling TLS checks, then restore consumed the local archives.
The `gh` API returned `Forbidden`; connected GitHub tools handled PR operations.

## Checks and baseline dispositions

Both historical snapshots pass all 12 emitted JSON schemas. The old validator
incorrectly passed an empty directory; it now fails missing documents/schemas,
invalid JSON/schema, and external references. It reports the number actually
validated. Eleven validator regression tests cover those cases.

A follow-up review reproduced another false success: an external `$ref` inside
an absent optional property or unused `$defs` passed with `{}`. Both new cases
fail on the previous validator. Validation now checks the complete structural
reference closure before checking the instance, using only embedded resources.
Draft-aware positive cases cover local pointers, anchors, nested IDs and recursive
references; annotation data remains opaque unless a reference targets it.

Before the WAM extraction fix, the same release binary reproduced all 27 checked
artifacts of both historical commits. Warm runs took 13.970 s / 13.114 s, with
peak RSS 2,387,992 / 2,386,528 KiB. These are single observations, not benchmarks.

All six failing count baselines have source-level dispositions below. They remain
exact pins in both directions, not upper bounds. Four additional Python tests
run lint on the real snapshot and mutate every repinned state upward/downward
(12 mutations), proving that neither an increase nor an unexplained decrease is
silently accepted. Schema conformance and lint are separate checks.

| Counted gap | Historical old | Historical new | After fix / new pin | Disposition |
|---|---:|---:|---:|---|
| IQ attributes without argument paths | 55 | 49 | 49 | Privacy recovers 3; absent KMP definition removes 3 |
| IQ children without argument paths | 12 | 10 | 10 | Privacy recovers 1; absent KMP definition removes 1 |
| MEX undetermined presence nodes | 108 | 106 | 106 | Departing operations subtract 6; ContactManager adds 3; SmartComposer adds 1 |
| MEX operations with no established presence | 13 | 10 | 10 | Four departed operations; one new, unresolved SmartComposer operation |
| WAM uncataloged constructions | 41 | 29 | 29 | 15 old Windows bridge definitions depart; 3 arrive |
| WAM unread arguments | 104 | 93 | 79 | Bridge change −12; StatusSubtitle regression +1; local-object fix −14 |

The [gap ledger](snapshot-quality-2026-10-07.gaps.json) records exact module names,
constructor spans/hashes, counter arithmetic, and remaining limitations. The
[source sidecar](snapshot-quality-2026-10-07.sources.json) locates the selected
modules in both locked sets. Every bundle parses without recovery: 20,209 old and
19,713 new exact static module names. This establishes coverage of static module
definitions, not completeness of the server protocol or dynamic JavaScript.
A follow-up test exposed the extraction fast path skipping nested definitions.
The checked index now traverses them; both complete pinned indexes remain
byte-for-byte identical, so none of the absence findings depended on that shortcut.

## IQ evidence

`WAWebSetPrivacyJob` changes its helper from four positional parameters to an
object containing `dhash`, `name`, `users`, and `value`. Both sources construct
`privacy/category` and repeated `user` nodes. The new IR recovers three category
argument paths and the child's `users[]` path. It also corrects old `name/action`
and `name/wid` paths to `users[]/action` and `users[]/wid`. This is improved
extraction enabled by an upstream refactor, not a wire feature removal.

`WAWebKmpSyncdRequestBuilder` contributes three missing attribute paths, one child
path, and one content path in the old snapshot. Its exact static definition is
absent from the fully parsed new set. That catalog departure explains the
counter decrease. It does not establish that app-state support vanished, or that
another module is a rename. The disposition is upstream static-definition
change; the fate of the wire operation remains indeterminate.

The unchanged missing-content total of 23 hides cancellation: KMP contributes
−1 and SetAbout contributes +1. `WAWebSetAboutJob` now exports both `setAbout` and
`sendSetAbout`, with the construction in a positional `sendSetAbout` function.
The selected IR entry loses its argument-object content path. The source no
longer supplies such an object at that entry. Treat the add/remove pair separately,
without a guaranteed rename or a promise of source API compatibility.

## MEX evidence and retained gaps

Nine operation names depart and three arrive; their exact names are in the gap
ledger. The corresponding departed `.graphql` definitions are absent from the
fully parsed new set. Four removed operations account for six undetermined keys
and four wholly undetermined operations. These are catalog departures, not proof
of server-side operation retirement.

`WAWebContactManagerCustomerProfilesQuery` adds `filters`, built through `.map`,
and two nested field names. Their presence stays undetermined because the current
classifier does not establish the call's return semantics. The source adds these
fields; this is a new unresolved surface, not silently discarded extraction.
Its `candidate_lids` now uses a nullish fallback to `[]`; the IR's string/conditional
inference is **not** a proved upstream type change and remains indeterminate.
A method named `map` alone does not guarantee Array semantics. These limitations
are preserved explicitly rather than claiming a complete variable contract.

The new SmartComposer operation takes a mutation function from
`CometRelay.useMutation(...)[0]` and later calls it with a nested `variables.input`
object. The extractor does not resolve that alias; it falls back to the compiled
GraphQL `input` argument with undetermined presence. The visible nested fields
remain unrecovered. This is a new unsupported call shape, recorded as a gap; it
adds one node and one wholly undetermined operation. The baseline review does
not certify that fallback as complete or infer those missing fields.

The ContactManager persisted-ID change is independently proven by literal
facebookRelayOperation exports: `27747880408206174` → `27796221486653417`.

## WAM evidence and extraction repair

Each departed/added `WAWebWindowsHybridBridgeWam.v*` definition constructs one
`RawWamEvent` from a runtime object originating in native JSON. That schema cannot
be recovered as a fixed catalog event. The 15 departures and 3 arrivals explain
both the uncataloged count change (41→29) and −12 unread identifiers. Call (1)
and member (3) unread forms remain unchanged.

There is also a genuine loss: `WAWebStatusSubtitle.react` moves the inline
attribution object into a local variable, preserving `attributionType`,
`statusCategory`, and `viewerActionType`. The old extractor turns the direct
construction into an empty partial site. Exact pinned module fixtures reproduce
that failure on provenance-only commit `4d1bed4`; the same test passes with the
local-object fix. A smaller synthetic refactor also fails before and passes after.

Recovery accepts only a uniquely bound, directly initialized function-local
object, with all uses accounted for as recognized constructor reads or sources
of a fresh-target `babelHelpers.extends`. Mutation, escape, rebinding, conditional
initialization, pre-initialization reads, direct eval (including parenthesized
callees), shadowing and outer closure
reads remain unresolved. The pinned `WAWebWamTypeHash` constructor copies input
fields through `set`; it does not mutate the source object. The async closure's
inherited fields remain partial because invocation timing is not established.

The initial local-object fix (`58afb2e`) recovers 14 unread arguments on the current set and 14 on the old set
(the memberships differ; the ledger lists both). On the current snapshot it adds
157 field occurrences, six field values, and two distinct call sites; partial
sites fall from 126 to 114. Remaining unread arguments are 75 identifiers, one
call and three members. Only `generated/wam/index.json` and
`generated/manifest.json` change. No IQ, `spec.rs`, or IR schema redesign occurs.
A review follow-up also recovers approved locals used inside fresh-target merges.
`WAWebKeepInChatMsgAction` supplies nine fields through its local object in each
of two constructors. `WAWebSmbMarkAsXOrderAction` supplies seven in each of two
constructors; their additional call operands remain unread, so those sites stay
partial. The follow-up adds 32 field occurrences and eight values, and separates
two previously identical partial sites. Totals become 813 sites, 3,478 field
occurrences, 804 values and 113 partial sites. All six baseline pins remain
unchanged. Both source modules are in the focused sidecar. Regression tests
reproduce the omitted merge fields and preserve partial status for unknown
operands, escaped locals, mutated targets and outer closure reads.


A second merge regression reproduces a lost final value: merging the approved
local `{retryCount:3}` before `{retryCount:4}` must retain `4`. Constructor
operands now follow overwrite order; later event writes retain their existing
conservative treatment. An unread later operand may overwrite earlier values,
so those values are withdrawn until its keys can be established. Seven fixture
cases cover both operand orders, unknown calls, computed keys and spreads.

On the exact current bundle set, this correction changes ten module/event
pairs. Ignoring values, their field/write shapes are identical before and after;
all 874 constructions remain counted. Six sites become duplicates after value
withdrawal: WebcMemoryStat loses one duplicate, EditBusinessProfile two,
CtwaOrderSignal one and PaidMessagingUserInteractionsLogger two. The other six
changed groups are StatusReply, ChatMute, AttachmentTrayActions,
PsGroupExitExperienceExitDialogInteraction, SmbQpCallHealth and
CompanionInviteContact. All ten modules have exact source locators in the
focused sidecar. Their unsupported later operands include calls, identifiers,
conditional objects and logical expressions. This is a conservative correction
to extraction certainty, not an upstream removal. Resolving those operand key
sets could recover values later; the current extractor does not prove them.

The final totals are 807 sites, 3,453 field occurrences, 769 values and 107
partial sites. The write guard caught 813 → 807; an isolated generation and the
field/write-shape comparison established the six deduplications before replacing
the generated WAM/manifest. No guard, floor or diagnostic baseline was lowered.

The nested-definition provenance review separately exposed overlapping WAM
scans. Its regression counted each gap twice before the fix. `quality-gaps` now
uses the normal extractor's outer module selection, while the source index
continues to include nested definitions. Neither locked snapshot contains such
nested definitions, so their reviewed gap ledgers are unchanged.

Existing extraction entry points and `WamDiagnostics` retain their API; the gap
sidecar uses a new optional function. IR schema stays 4.3.0 because this fills
existing field semantics and makes no consumer contract change.

## Reproduction and maintenance

At `4d1bed4`, `quality-gaps` emits the historical gap counts without the local
argument recovery. On the final revision it emits the repaired counts:

```sh
whatspec source-index OLD_LOCK OLD_BUNDLES > old-sources.json
whatspec source-index NEW_LOCK NEW_BUNDLES > new-sources.json
whatspec quality-gaps OLD_LOCK OLD_BUNDLES > old-gaps.json
whatspec quality-gaps NEW_LOCK NEW_BUNDLES > new-gaps.json
whatspec update --bundles NEW_BUNDLES --wa-version 2.3000.1047483476 --check
python3 scripts/validate-schemas.py generated
python3 scripts/lint-ir.py generated
python3 -m unittest discover -s scripts/tests -v
cargo test -p wa-transform -p wa-wam -p whatspec --all-features
```

Source indexes are generated on demand (~14.2 MB each), not committed wholesale.
The focused source and gap ledgers are ~104.6 KB and ~21.4 KB. Two real WAM fixtures
retain exact source slices, with bundle hashes and offsets in their headers.
The WAM document grows from 2,794,121 to 2,807,208 bytes by recovering existing
field semantics; optional provenance adds no per-field IR metadata. WAM gap evidence incurs extra parsing only
when requested. At the initial local-object revision, regeneration checks reproduce all 27 artifacts for the repaired current
snapshot and a separately regenerated old snapshot. Observed check times were
26.063 s (new) and 18.561 s (old); peak child RSS across the sequence was
2,390,792 KiB. Compilation overlapped these runs, so they are cost observations,
not an isolated performance comparison.

Changes to snapshot membership require reviewing these ledgers;
count arithmetic alone is insufficient.

Unknown catalog-field writes also receive one gap location per counted
occurrence, with the field name, rather than a counter without source evidence.
Filtered source sidecars now explicitly record their requested module names;
absence findings are limited to that selection.

The generic contract report contains 495 deltas (2,725,481 bytes), keeps ordered
arrays and does not infer renames.
The [review ledger](snapshot-quality-2026-10-07.reviews.json) classifies the privacy
improvement and persisted-ID change; the remaining 493 deltas stay indeterminate until
reviewed. `--evidence` binds each review to both artifact hashes. The baseline
dispositions above concern those six counters, not all contract differences.


## Manifest/lock binding limitation

A same-version lock-swap regression confirms that the historical manifest does
not bind its document hashes to the lock's bundle set. A valid replacement lock
was accepted and previously gave an authoritative-looking `sameInputs` verdict.
Report version 2 retains historical comparison but marks the input binding
unverified, reports declared lock identities separately, and returns unknown
(`null`) for `sameInputs`. No hashes are fabricated or backfilled into manifests;
the existing manual restore/regeneration evidence remains distinct from what the
comparison command can verify on its own. Version-1 review ledgers must migrate.

The exact global-channel fixture recorded in #55 (set hash
`840dfc3f996afcfac451f80043580175b4443db0487ec4c056ffb02bc9fd57be`)
reproduces two drops with zero construction sites. These remain unlocated and
are now explicitly reported as one `unlocatedDropsByReason` counter of two;
no complete source-attribution claim is made for them.
