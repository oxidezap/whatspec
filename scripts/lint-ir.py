#!/usr/bin/env python3
"""Check invariants of the generated IR that the JSON Schemas cannot express.

The schemas validate SHAPE: that a field has the keys it should, of the right
types. They cannot say whether the document is *usable* — whether a field the IR
calls an enum actually names its legal values, whether a byte pin is the length
it claims, whether a union carries the variants that make it a union. Those are
the questions a consumer writing a generator in any language has to answer, and
they are what this checks.

Two kinds of finding:

* **errors** — an internal contradiction. A `literalValue` on an integer field
  that is not an integer is not a gap in extraction; it is a document that says
  two things at once. These always fail.
* **counted** — a known, legitimately non-empty state, held to a BASELINE. An
  enum WA composes at runtime cannot be resolved, and the IR records that under
  `dropsByReason` rather than pretending; the count may shrink (extraction
  improved) but a rise means a new construct started slipping through unnoticed.

Network-free and deterministic, so it runs in CI beside the schema validation.

Usage: scripts/lint-ir.py [generated-dir]   (default: ./generated)
"""
import json
import sys
from pathlib import Path

# Counted states, with the value observed when this guard was introduced. Raising
# one of these is a deliberate act: it means a constraint the extractor used to
# recover is now being lost, and the number has to be updated with a reason.
BASELINE = {
    "enum field with no values": 173,
    "content integer with no byte width": 0,
}

# `contentInt` reads DECIMAL TEXT, so it has no byte width and must not be asked
# for one; `contentUint(N)` reads N big-endian bytes and must always carry it.
WIDTH_BEARING = {"contentUint"}

# The `ParsedFieldType` vocabulary, mirroring `wa_ir::ParsedFieldType`. A value
# outside it in a `type` position is itself worth reporting.
FIELD_TYPES = {
    "string", "integer", "timestamp", "timestamp_millis", "enum", "bytes",
    "jid", "user_jid", "lid_user_jid", "device_jid", "lid_device_jid",
    "group_jid", "newsletter_jid", "call_jid", "broadcast_jid", "status_jid",
    "jid_typed", "bool", "union",
}


def walk(node, visit, path=""):
    """Depth-first over every dict in the document, with a readable path."""
    if isinstance(node, dict):
        visit(node, path)
        for k, v in node.items():
            walk(v, visit, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, visit, f"{path}/{i}")


def check_field(f, path, errors, counts):
    """Invariants of one `ParsedField`-shaped object."""
    t = f.get("type")
    method = f.get("method", "")

    # An enum that names no legal values is the "is this unconstrained, or did we
    # lose the constraint?" ambiguity the IR exists to remove.
    if t == "enum" and not f.get("enumRef") and not f.get("enumKeys"):
        counts["enum field with no values"] += 1

    # The pending marker must never reach the artifact: an empty variant list
    # tells a consumer the field admits NO value.
    ref = f.get("enumRef")
    if isinstance(ref, dict) and not ref.get("variants"):
        errors.append(f"{path}: enumRef {ref.get('name')!r} has no variants")

    if method in WIDTH_BEARING and "byteLength" not in f:
        counts["content integer with no byte width"] += 1

    lv = f.get("literalValue")
    if lv is not None:
        if t == "integer":
            try:
                int(lv)
            except (TypeError, ValueError):
                errors.append(f"{path}: literalValue {lv!r} is not an integer")
        if t == "bytes":
            if any(c not in "0123456789abcdef" for c in lv) or len(lv) % 2:
                errors.append(f"{path}: literalValue {lv!r} is not lowercase hex")
            elif "byteLength" in f and len(lv) != f["byteLength"] * 2:
                errors.append(
                    f"{path}: literalValue is {len(lv) // 2} bytes, "
                    f"byteLength says {f['byteLength']}"
                )

    # A union whose alternatives are absent is not a union — a consumer has
    # nothing to switch on.
    if t == "union" and len(f.get("unionVariants") or []) < 2:
        errors.append(f"{path}: union carries fewer than two variants")

    for lo, hi in (("byteMin", "byteMax"), ("intMin", "intMax")):
        if lo in f and hi in f and f[lo] > f[hi]:
            errors.append(f"{path}: {lo} {f[lo]} exceeds {hi} {f[hi]}")

    # An echo rule with no path says "this equals something in the request" and
    # then does not say what.
    if "referencePath" in f and not f["referencePath"]:
        errors.append(f"{path}: referencePath is empty")


def check_assertion(a, path, errors):
    if a.get("kind") == "reference" and not a.get("referencePath"):
        errors.append(f"{path}: reference assertion with no referencePath")
    if a.get("kind") == "attr" and not a.get("name"):
        errors.append(f"{path}: attr assertion with no attribute name")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "generated")
    errors: list[str] = []
    counts = dict.fromkeys(BASELINE, 0)

    docs = sorted(root.glob("*/index.json"))
    if not docs:
        sys.exit(f"no domain documents under {root}")

    for doc in docs:
        data = json.loads(doc.read_text())
        domain = doc.parent.name

        def visit(node, path, domain=domain):
            # Recognised by the TYPE VOCABULARY, not by auxiliary keys. Keying on
            # `method`/`wireName` looked right and silently skipped the appstate
            # fields, which carry neither — the linter would have reported a clean
            # count while missing a whole domain.
            if node.get("type") in FIELD_TYPES:
                check_field(node, f"{domain}{path}", errors, counts)
            if "kind" in node and "reference_path" not in node:
                check_assertion(node, f"{domain}{path}", errors)

        walk(data, visit)

    ok = True
    for name, observed in sorted(counts.items()):
        allowed = BASELINE[name]
        if observed > allowed:
            print(f"REGRESSION  {name}: {observed} (baseline {allowed})")
            ok = False
        else:
            mark = "ok  " if observed == allowed else "ok ↓"
            print(f"{mark}        {name}: {observed} (baseline {allowed})")

    for e in errors:
        print(f"ERROR       {e}")

    if errors:
        print(f"\n{len(errors)} internal contradiction(s) in the IR")
        return 1
    if not ok:
        print("\na counted state rose above its baseline — a constraint is being lost")
        return 1
    print(f"\n{len(docs)} document(s) internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
