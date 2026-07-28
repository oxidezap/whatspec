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
from collections import defaultdict
from pathlib import Path

# Counted states, with the value observed when this guard was introduced. Raising
# one of these is a deliberate act: it means a constraint the extractor used to
# recover is now being lost, and the number has to be updated with a reason.
BASELINE = {
    "content integer with no byte width": 0,
}

# The enums no extraction path could resolve, by IDENTITY rather than by total.
#
# A single number cannot see a SUBSTITUTION: one field gaining values while another loses
# them holds the sum at 155 and reports `ok`, which is precisely the silent constraint loss
# this file exists to catch. Identity is domain + field name + wire name + accessor, so it
# survives reordering — a positional path would churn on every unrelated insertion. The
# counts are multiplicities: the same wire enum is read at several places.
#
# 155 fields collapse to 30 identities. Adding one, dropping one, or changing a count all
# fail; each is a deliberate act that costs one line here.
UNRESOLVED_ENUMS = {
    "incoming|edit|edit|attrEnum": 1,
    "iq|automaticBinding|automatic-binding|maybeAttrEnum": 2,
    "iq|canAddPayout|can-add-payout|attrEnum": 2,
    "iq|canPayout|can-payout|attrEnum": 2,
    "iq|canSell|can-sell|attrEnum": 2,
    "iq|capabilitiesDefaultEligibleP2m|default-eligible-p2m|maybeAttrEnum": 6,
    "iq|capabilitiesDefaultEligibleP2p|default-eligible-p2p|maybeAttrEnum": 6,
    "iq|capabilitiesDefaultEligible|default-eligible|attrEnum": 6,
    "iq|capabilitiesEditable|editable|attrEnum": 6,
    "iq|capabilitiesP2mCreditEligible|p2m-credit-eligible|attrEnum": 2,
    "iq|capabilitiesP2mDebitEligible|p2m-debit-eligible|attrEnum": 2,
    "iq|capabilitiesVerifiable|verifiable|attrEnum": 6,
    "iq|defaultCreditP2m|default-credit-p2m|maybeAttrEnum": 8,
    "iq|defaultCreditP2p|default-credit-p2p|maybeAttrEnum": 8,
    "iq|defaultCredit|default-credit|attrEnum": 8,
    "iq|defaultDebitP2m|default-debit-p2m|maybeAttrEnum": 8,
    "iq|defaultDebitP2p|default-debit-p2p|maybeAttrEnum": 8,
    "iq|defaultDebit|default-debit|attrEnum": 8,
    "iq|error|error|maybeAttrEnum": 7,
    "iq|isAadhaarEnabled|is-aadhaar-enabled|maybeAttrEnum": 2,
    "iq|isInternationalPayEnabled|is_international_pay_enabled|maybeAttrEnum": 2,
    "iq|isMpinSet|is-mpin-set|attrEnum": 2,
    "iq|membershipApprovalRequestError|error|maybeAttrEnum": 2,
    "iq|needsDeviceBinding|needs-device-binding|attrEnum": 2,
    "iq|p2mEligible|p2m-eligible|maybeAttrEnum": 18,
    "iq|p2pEligible|p2p-eligible|maybeAttrEnum": 18,
    "iq|pinFormatVersion|pin-format-version|attrEnum": 2,
    "iq|pixOnboardingState|pix-onboarding-state|maybeAttrEnum": 2,
    "iq|verified|verified|attrEnum": 6,
    "notif|reason|reason|": 1,
}

# `contentInt` reads DECIMAL TEXT, so it has no byte width and must not be asked
# for one; `contentUint(N)` reads N big-endian bytes and must always carry it.
WIDTH_BEARING = {"contentUint"}

# `WamChannel`. Anything else is mapped to `Regular` by the reference generator rather
# than preserved, so an unknown value loses the channel silently instead of failing.
WAM_CHANNELS = {"regular", "realtime", "private"}

# Keys only a response field carries. They identify a `ParsedField` independently of
# whether its `type` is one we know — which is what lets an unrecognized type be
# REPORTED instead of skipped. Deliberately excludes `name`/`type` alone: appstate has
# its own vocabulary (`literal`, `boolString`, `jidOrZero`, proto type names) and the
# notification envelope carries `type` as the notification kind, so keying on those
# would flag correct documents.
FIELD_MARKERS = {
    "method", "wireName", "enumRef", "enumKeys", "literalValue", "byteLength",
    "byteMin", "byteMax", "intMin", "intMax", "unionVariants", "referencePath",
}

# The `ParsedFieldType` vocabulary, mirroring `wa_ir::ParsedFieldType`.
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


def check_field(f, path, domain, errors, counts, unresolved):
    """Invariants of one `ParsedField`-shaped object."""
    t = f.get("type")
    method = f.get("method", "")

    # An enum that names no legal values is the "is this unconstrained, or did we
    # lose the constraint?" ambiguity the IR exists to remove.
    #
    # `protoEnum` names the values too, just by pointing at a protobuf enum instead of
    # inlining them (appstate's `SettingsSync.settingPlatform`). Omitting it counted two
    # fully-resolved constraints as lost — and since the baseline is a ratchet, a new
    # proto-backed enum could then silently cancel out a genuine unresolved-enum fix
    # while the total held still.
    if (
        t == "enum"
        and not f.get("enumRef")
        and not f.get("enumKeys")
        and not f.get("protoEnum")
    ):
        unresolved[f"{domain}|{f.get('name')}|{f.get('wireName')}|{method}"] += 1

    if method in WIDTH_BEARING and "byteLength" not in f:
        counts["content integer with no byte width"] += 1

    lv = f.get("literalValue")
    # The schema types it as a string; anything else would make the hex scan below iterate
    # a non-iterable and abort the whole run — the same "error path assumes a shape it did
    # not verify" that already crashed this file once.
    if lv is not None and not isinstance(lv, str):
        errors.append(f"{path}: literalValue is {type(lv).__name__}, not a string")
        lv = None
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
    if t == "union":
        variants = f.get("unionVariants") or []
        if len(variants) < 2:
            errors.append(f"{path}: union carries fewer than two variants")
        else:
            # Two entries are not two ALTERNATIVES if they answer to the same name. The
            # name is the documented discriminator and the Rust codegen emits it as the
            # variant identifier, so a repeat is either ambiguous or uncompilable.
            # Only real names: a missing one is `None`, and two of those would both
            # count as a duplicate AND make the report `sorted()` a `None` against a
            # `str`. Absence is not a repeat.
            names = [
                v.get("name")
                for v in variants
                if isinstance(v, dict) and isinstance(v.get("name"), str)
            ]
            repeated = sorted({n for n in names if names.count(n) > 1})
            if repeated:
                errors.append(f"{path}: union alternatives repeat a name ({repeated})")

    # Each pair is the two bounds of ONE range accessor. Inverted is a contradiction;
    # so is half of one — the schema permits either key alone, but a consumer handed
    # `intMin` with no `intMax` has a weaker constraint than the wire actually enforces
    # and no way to know it lost the other end.
    for (lo, hi), owner in ((("byteMin", "byteMax"), "bytes"), (("intMin", "intMax"), "integer")):
        if (lo in f) != (hi in f):
            present, missing = (lo, hi) if lo in f else (hi, lo)
            errors.append(f"{path}: {present} without {missing} is half a range")
        elif lo in f and f[lo] > f[hi]:
            errors.append(f"{path}: {lo} {f[lo]} exceeds {hi} {f[hi]}")
        # A byte range belongs to a bytes field and an integer range to an integer one.
        # On any other type the two halves instruct a consumer to do incompatible things
        # — a string with a numeric range — and it either builds a nonsense validator or
        # drops the constraint. Today every one of them sits on its own type.
        if lo in f and t != owner:
            errors.append(f"{path}: {lo}/{hi} on a {t!r} field, not {owner!r}")

    # An echo rule with no path says "this equals something in the request" and
    # then does not say what.
    if "referencePath" in f and not f["referencePath"]:
        errors.append(f"{path}: referencePath is empty")

    # `ParsedField::reference_path` is documented as mutually exclusive with
    # `literal_value`: one pins a constant, the other pins a value copied from the
    # request. Carried together they are two different answers to "what is this
    # field's value", and a consumer cannot honour both. Checking each key on its own
    # let the pair through — no live case today, which is the point of adding it now.
    if lv is not None and f.get("referencePath"):
        errors.append(
            f"{path}: carries both literalValue and referencePath, "
            f"which pin the value to different things"
        )


def check_enum_ref(node, path, errors):
    """An `enumRef` anywhere, not only on a `ParsedField`.

    Request-side and stanza attributes carry one too, keyed by `kind` rather than `type`,
    so gating this on the field-type vocabulary let the pending marker — an empty
    `variants`, which tells a consumer the attribute admits NO value — ship on those
    surfaces unchecked.
    """
    ref = node.get("enumRef")
    if isinstance(ref, dict) and not ref.get("variants"):
        errors.append(f"{path}: enumRef {ref.get('name')!r} has no variants")


def check_const_bytes(node, path, errors):
    """A request-side `constBytes` pin: the same invariant as a response `literalValue`
    on a bytes field, written differently. Both say "these exact bytes"; only one was
    checked."""
    cb = node.get("constBytes")
    if not isinstance(cb, str):
        return
    if any(c not in "0123456789abcdef" for c in cb) or len(cb) % 2:
        errors.append(f"{path}: constBytes {cb!r} is not lowercase hex")
    elif "byteLength" in node and len(cb) != node["byteLength"] * 2:
        errors.append(
            f"{path}: constBytes is {len(cb) // 2} bytes, "
            f"byteLength says {node['byteLength']}"
        )


def check_enum_catalog_refs(data, domain, errors):
    """Enum references that point INTO the document's own top-level `enums` catalog.

    Every other enum in the IR inlines its values, so `check_enum_ref` — which looks at
    an `enumRef` object in place — is enough. WAM instead names a module and expects the
    consumer to find it in `enums`, and nothing verified the link resolved: a dangling
    name, or a definition left with no variants (which the schema permits), still read as
    "internally consistent" while a consumer could not encode the field at all.

    Keyed on the document HAVING a catalog rather than on the domain name, so a second
    domain adopting the same shape is covered without anyone remembering to add it here.
    """
    catalog = data.get("enums")
    if not isinstance(catalog, list):
        return
    # An EMPTY catalog is not "nothing to check" — it is the worst case. If extraction
    # collapsed the list while the enum-typed fields remained, every reference in the
    # document is dangling, and returning early here reported exactly that document as
    # internally consistent. An empty list is an empty lookup; the walk still runs.
    by_module = {}
    for i, e in enumerate(catalog):
        if not isinstance(e, dict):
            continue
        # Checked directly, not only through a reference: `generated/enums/` is a catalog
        # nothing in the document points at, so validating references alone left every one
        # of its 326 definitions unexamined. A named enum with no values is the same
        # broken promise whether or not this document happens to cite it.
        if not e.get("variants"):
            errors.append(
                f"{domain}/enums/{i}: enum {e.get('name')!r} is defined with no values"
            )
        # `valueKind` is what tells a consumer how to represent these values; the schema
        # permits any `Scalar` per variant, so it cannot check the two agree. A variant
        # that disagrees would have the consumer pick an incompatible representation.
        # `bool` is excluded explicitly — in Python it IS an int.
        # One member name, one value. JS keeps only the last duplicate property, so a
        # definition carrying both gives a consumer two contradictory answers for the same
        # member — and `uniqueItems` cannot see it, because the objects differ in `value`.
        members = [
            v.get("name") or v.get("key")
            for v in e.get("variants") or []
            if isinstance(v, dict) and isinstance(v.get("name") or v.get("key"), str)
        ]
        repeated = sorted({m for m in members if members.count(m) > 1})
        if repeated:
            errors.append(
                f"{domain}/enums/{i}: enum {e.get('name')!r} defines "
                f"{repeated} more than once"
            )

        expected = {"int": int, "string": str}.get(e.get("valueKind"))
        if expected is not None:
            for j, v in enumerate(e.get("variants") or []):
                # A non-dict entry is malformed IR — exactly what this exists to catch —
                # so it must be REPORTED, not crash the run on `.get`. The value guard
                # below was written defensively; the message beside it was not.
                if not isinstance(v, dict):
                    errors.append(
                        f"{domain}/enums/{i}: enum {e.get('name')!r} variant {j} "
                        f"is {type(v).__name__}, not an object"
                    )
                    continue
                val = v.get("value")
                if not isinstance(val, expected) or isinstance(val, bool):
                    errors.append(
                        f"{domain}/enums/{i}: enum {e.get('name')!r} is valueKind "
                        f"{e.get('valueKind')!r} but variant "
                        f"{(v.get('name') or v.get('key'))!r} carries {val!r}"
                    )
        if "module" in e:
            by_module.setdefault(e["module"], []).append(e)

    def visit(node, path):
        if node.get("kind") != "enum" or "module" not in node:
            return
        module = node["module"]
        found = by_module.get(module, [])
        if not found:
            errors.append(f"{domain}{path}: enum reference {module!r} is in no definition")
        elif len(found) > 1:
            errors.append(
                f"{domain}{path}: enum reference {module!r} matches "
                f"{len(found)} definitions, so it does not identify one"
            )
        elif not found[0].get("variants"):
            errors.append(f"{domain}{path}: enum reference {module!r} resolves to no values")

    walk(data, visit)


def check_event_codes(data, domain, errors):
    """A WAM event's `code` is its wire identifier, so two events cannot share one.

    The schema has no way to say "unique across the array". A consumer generating a
    dispatch table by code would silently overwrite one of the pair, and one of the two
    event shapes would then be unreachable — with nothing in the document indicating it.
    """
    events = data.get("events")
    if not isinstance(events, list):
        return
    seen = {}
    for e in events:
        if not isinstance(e, dict) or "code" not in e:
            continue
        code = e["code"]
        if code in seen:
            errors.append(
                f"{domain}: events {seen[code]!r} and {e.get('name')!r} "
                f"share code {code}, which is the wire identifier"
            )
        else:
            seen[code] = e.get("name")
        # `[default, ring1, ring2]` — the positions ARE the meaning, so a short array does
        # not lose the last ring, it shifts every ring that remains. The schema permits any
        # length.
        # The wire format carries the code in 16 bits, and the reference consumer emits it
        # as `u16`. The schema permits the whole `u32` range, and the extractor turns a
        # negative source literal into a large one — either way the IR would be declared
        # usable and then generate metadata that cannot encode.
        if isinstance(code, int) and not 0 <= code <= 0xFFFF:
            errors.append(
                f"{domain}: event {e.get('name')!r} has code {code}, "
                f"which does not fit the 16-bit wire field"
            )
        # An unrecognised channel is not preserved by the reference generator — it maps
        # to `Regular`, so a typo silently uploads on channel 0 instead of failing.
        channel = e.get("channel")
        if channel is not None and channel not in WAM_CHANNELS:
            errors.append(
                f"{domain}: event {e.get('name')!r} has channel {channel!r}, "
                f"not one of {sorted(WAM_CHANNELS)}"
            )
        weights = e.get("weights")
        if not isinstance(weights, list) or len(weights) != 3:
            errors.append(
                f"{domain}: event {e.get('name')!r} carries "
                f"{len(weights) if isinstance(weights, list) else 'no'} sampling "
                f"weight(s), not the three positions [default, ring1, ring2]"
            )
        # A field's `id` is its wire identifier WITHIN the event, so the same rule applies
        # one level down: an encoder handed two fields sharing an id cannot tell them
        # apart. Scoped per event — ids repeat across events by design.
        by_id = {}
        for f in e.get("fields") or []:
            if not isinstance(f, dict) or "id" not in f:
                continue
            fid = f["id"]
            if fid in by_id:
                errors.append(
                    f"{domain}: in event {e.get('name')!r}, fields {by_id[fid]!r} and "
                    f"{f.get('name')!r} share id {fid}"
                )
            else:
                by_id[fid] = f.get("name")


def check_action_keys(node, path, errors):
    """`fields`, `constantFields` and `children` are three representations of ONE object
    key namespace, so a name may appear in only one of them.

    Runtime cannot produce two values for one key, and a consumer handed both a wire-read
    `reason` and a constant `reason` has a shape that contradicts itself. Each array is
    internally consistent by construction; nothing compared them to each other.
    """
    arrays = [k for k in ("fields", "constantFields", "children") if isinstance(node.get(k), list)]
    if len(arrays) < 2:
        return
    names = [
        it["name"]
        for k in arrays
        for it in node[k]
        if isinstance(it, dict) and "name" in it
    ]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        errors.append(f"{path}: one key filled twice across fields/constantFields/children: {repeated}")


def check_variant_group(node, path, errors):
    """A `WapVariantGroup` says exactly one of its alternatives applies.

    With none listed, a REQUIRED group promises a choice and supplies nothing to choose:
    an emitter cannot construct the request, and the Rust generator emits a required field
    whose enum has no variants. An optional group with no alternatives is merely empty.
    """
    if "variants" not in node or "optional" not in node:
        return
    if not node.get("optional") and not node.get("variants"):
        errors.append(f"{path}: required variant group offers no alternative")


def check_assertion(a, path, errors):
    if a.get("kind") == "reference":
        if not a.get("referencePath"):
            errors.append(f"{path}: reference assertion with no referencePath")
        # The path says WHERE in the request the value comes from; `name` says which
        # response attribute has to echo it. With only the path a consumer knows the
        # source of a rule it cannot apply to anything.
        if not a.get("name"):
            errors.append(f"{path}: reference assertion with no target attribute name")
    if a.get("kind") == "attr" and not a.get("name"):
        errors.append(f"{path}: attr assertion with no attribute name")
    # `WapAttrKind::Const` is documented as "fixed literal value (carried in
    # `WapAttrDef::value`)", but `value` is optional in the schema. Without it the IR
    # tells an emitter the value is fixed and then declines to say to what.
    #
    # Only this direction. `value` is NOT exclusive to const: `kind` is shared with the
    # assertion vocabulary, where `attr` and `content` carry one legitimately (1781 nodes
    # today), so rejecting `value` on non-const kinds would flag correct documents.
    if a.get("kind") == "const" and a.get("value") is None:
        errors.append(f"{path}: const attribute with no value")
    # A `content` assertion IS the fixed text a marker union variant matches on. Without
    # the value a consumer cannot tell when the variant applies. Narrow on purpose: an
    # `attr` assertion may legitimately assert only presence.
    if a.get("kind") == "content" and a.get("value") is None:
        errors.append(f"{path}: content assertion with no value to match")
    # A `tag` assertion IS the expected tag; the incoming and server-request scanners read
    # it from `name`. Without it the assertion can neither enforce nor dispatch a shape.
    if a.get("kind") == "tag" and not a.get("name"):
        errors.append(f"{path}: tag assertion with no tag name")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "generated")
    errors: list[str] = []
    counts = dict.fromkeys(BASELINE, 0)
    unresolved: dict[str, int] = defaultdict(int)

    docs = sorted(root.glob("*/index.json"))
    if not docs:
        sys.exit(f"no domain documents under {root}")

    for doc in docs:
        data = json.loads(doc.read_text())
        domain = doc.parent.name

        def visit(node, path, domain=domain):
            # A field is anything with a KNOWN type, or anything carrying a key only a
            # response field has. The first clause reaches the appstate fields, which
            # carry no `method`/`wireName`; the second is what makes an unrecognized type
            # reportable rather than invisible — keying on the vocabulary alone meant a
            # typo in `type` silently excused the field from every other check.
            # A marker only counts when the object HAS a type: an assertion carries
            # `referencePath` too, and flagging those as untyped fields was the first
            # version of this check reporting four contradictions that were not.
            known = node.get("type") in FIELD_TYPES
            marked = "type" in node and any(k in node for k in FIELD_MARKERS)
            if known or marked:
                if not known:
                    errors.append(
                        f"{domain}{path}: field type {node.get('type')!r} is not in the "
                        f"ParsedFieldType vocabulary"
                    )
                check_field(node, f"{domain}{path}", domain, errors, counts, unresolved)
            if "kind" in node and "reference_path" not in node:
                check_assertion(node, f"{domain}{path}", errors)
            # Independent of the field gate — see each function's note.
            check_enum_ref(node, f"{domain}{path}", errors)
            check_const_bytes(node, f"{domain}{path}", errors)
            check_action_keys(node, f"{domain}{path}", errors)
            check_variant_group(node, f"{domain}{path}", errors)

        walk(data, visit)
        # Needs the whole document, not one node: the reference and its definition sit in
        # different subtrees.
        check_enum_catalog_refs(data, domain, errors)
        check_event_codes(data, domain, errors)

    ok = True
    # Set difference in BOTH directions, plus the multiplicities. A gain that offsets a
    # loss keeps the total at 155 and is exactly what a scalar cannot see.
    for ident in sorted(set(unresolved) | set(UNRESOLVED_ENUMS)):
        now, was = unresolved.get(ident, 0), UNRESOLVED_ENUMS.get(ident, 0)
        if now == was:
            continue
        ok = False
        if was == 0:
            print(f"REGRESSION  newly unresolved enum: {ident} (x{now})")
        elif now == 0:
            print(f"IMPROVED    enum now resolved: {ident} — drop it from the baseline")
        else:
            print(f"CHANGED     {ident}: {was} -> {now} — update the baseline")
    if ok:
        print(
            f"ok          unresolved enums: {sum(unresolved.values())} across "
            f"{len(unresolved)} identities, as pinned"
        )

    for name, observed in sorted(counts.items()):
        allowed = BASELINE[name]
        if observed > allowed:
            print(f"REGRESSION  {name}: {observed} (baseline {allowed})")
            ok = False
        elif observed < allowed:
            # A RATCHET, not an upper bound. Accepting a decrease silently banks the
            # difference as slack: 157 -> 150 followed by seven newly unresolved enums is
            # back at 157 and passes, which is exactly the drift this is supposed to catch.
            # An improvement is real work and updating the number with it costs one line.
            print(f"IMPROVED    {name}: {observed} (baseline {allowed}) — lower the baseline")
            ok = False
        else:
            print(f"ok          {name}: {observed} (baseline {allowed})")

    for e in errors:
        print(f"ERROR       {e}")

    if errors:
        print(f"\n{len(errors)} internal contradiction(s) in the IR")
        return 1
    if not ok:
        print(
            "\na counted state left its baseline — raise means a constraint is being lost, "
            "fall means the baseline owes an update"
        )
        return 1
    print(f"\n{len(docs)} document(s) internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
