# Snapshot quality review

The existing text `whatspec diff OLD NEW` is a count and name summary. Use
`whatspec diff OLD NEW --json` for contract deltas across every manifest domain.
The report checks domain hashes, document versions, and lock self-consistency.
It fails on missing declared artifacts. Run schema validation separately, because
matching a manifest hash does not establish schema conformance.

```sh
python3 scripts/validate-schemas.py generated
python3 scripts/lint-ir.py generated
python3 -m unittest discover -s scripts/tests -v
cargo run --release -p whatspec -- diff old-generated generated --json > contracts.json
```

The JSON report has its own `reportVersion: 1`. It is an additive CLI output,
not a change to IR `schemaVersion`. No runtime consumer policy changes. In
particular, strict maintenance checks do not require clients to reject unknown
extensions in received traffic.

Each delta includes before/after values, document SHA-256, JSON Pointers, bundle
set hashes, and a stable ID bound to those values. Enums use `(module, name)`.
MEX and app-state use the document's map keys. Other recognized top-level
collections use explicit keys listed in `contract_diff.rs`. Duplicate keys stay
in an ordered group with original indices; they are never silently deduplicated.
Nested arrays retain order and multiplicity, including response alternatives.
Their full before/after arrays are emitted rather than inventing field identities.
An unkeyed collection can therefore produce a larger delta on reordering.
Protobuf changes are opaque artifact hash deltas, not parsed field diffs.

No shape-based rename detection occurs. An export or module name change remains
an addition and removal unless a reviewer establishes the relationship. The tool
does not turn a renamed export into a guaranteed operation identity or promise
API compatibility. Schema version differences are explicit report metadata.

## Recovering source evidence

Restore each snapshot from its own `bundles.lock.json`, using the corresponding
`bundle-store` asset. The restore command checks bundle hashes, sizes, set hash,
and multiplicity. Archive digests and bundle set hashes are different values.

```sh
whatspec restore --from-lock generated/bundles.lock.json --out bundles
whatspec source-index generated/bundles.lock.json bundles WAWebSetPrivacyJob > sources.json
```

`source-index` independently checks the exact bundle multiset. It parses modules
with the existing AST extractor and emits a separate optional sidecar containing
bundle SHA-256, module and factory hashes, dependency names, and byte offsets.
It never evaluates JavaScript. Source names may be selected after the two paths;
omit them to index all recovered modules. Offsets are UTF-8 bytes with an
exclusive end, so invalid UTF-8 is rejected rather than decoded lossily.
Every recovered occurrence remains visible, including conflicting definitions.
The index is deterministic and contains no workspace-specific file paths.

The existing AST API does not expose parse diagnostics. Consequently the sidecar
states `coverage: recovered-definitions-only`: a missing name is not proof of
upstream removal. A module hint in a contract report is also only a starting
point. Follow dependencies and mixins before attributing a field's semantics.
For a field-level review, cite both its IR pointer and the relevant module span.
This keeps recoverable provenance outside every repeated field of the IR.

## Classifying a change

Every delta starts as `indeterminate`. A smaller count, a different source hash,
or an unchanged generator version string is insufficient to classify it.

- `upstream-change` needs a source change that explains the contract delta, such
  as the old and new persisted operation ID literals.
- `extraction-improvement` needs evidence that the source supports the newly
  recovered constraint. A source refactor can make the same extractor recover
  more information. This is different from proving an extractor code fix.
- `extraction-loss` needs a source constraint that survives but is missing or
  distorted in the new IR. Reproduce it with the pinned inputs before fixing it.
- `indeterminate` records unresolved causes, absent modules without complete
  coverage, and aggregate diagnostic changes without per-site attribution.

Store reviewed assessments in a small JSON file:

```json
{
  "reportVersion": 1,
  "reviews": [{
    "id": "exact ID from contracts.json",
    "classification": "upstream-change",
    "basis": "Describe the source observation and its limits.",
    "references": ["sources.json#/modules/ExactModule/0"]
  }]
}
```

Apply it with `whatspec diff OLD NEW --json --evidence reviews.json`. Stale IDs,
duplicate IDs, unknown classes, and empty evidence fail. Any edit to a referenced
artifact invalidates its reviews, even if that edit is in another operation. This
conservative rule costs a review refresh after regeneration. These are explicitly
reviewed assessments, not machine-verified proofs: the CLI does not fetch or
interpret reference strings. Code review must validate their contents. Classify
mixed changes as indeterminate or explain each component in the basis.

For extraction fixes, regenerate before and after with the same verified bundle
set. For upstream updates, keep generator code fixed across both input sets, then
inspect changed source paths. Preserve unresolved gaps and exact lint baselines
until the review explains them. Do not normalize a loss into a lower limit.

The tools add no dependencies, committed full source index, or per-field IR
metadata. Reports are generated on demand. Full ordered arrays can be sizeable;
keep only focused evidence and assessments in version control. See the dated
investigation for measured cost and remaining baseline blockers.
