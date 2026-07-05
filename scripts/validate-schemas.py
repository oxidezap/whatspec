#!/usr/bin/env python3
"""Validate the generated domain `index.json` files against the emitted JSON
Schemas (both live under the generated output dir). Network-free and
deterministic, so it runs in CI as a drift guard: if a committed `index.json`
stops conforming to its committed `schema/*.json`, this fails.

Usage: scripts/validate-schemas.py [generated-dir]   (default: ./generated)
"""
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema not installed — `pip install jsonschema`")

# (domain document, its schema) — mirrors wa_ir::schemas() / the CLI manifest.
DOMAINS = [
    ("iq/index.json", "schema/iq.schema.json"),
    ("mex/index.json", "schema/mex.schema.json"),
    ("appstate/index.json", "schema/appstate.schema.json"),
    ("abprops/index.json", "schema/abprops.schema.json"),
    ("enums/index.json", "schema/enums.schema.json"),
    ("wam/index.json", "schema/wam.schema.json"),
    ("notif/index.json", "schema/notif.schema.json"),
    ("tokens/index.json", "schema/tokens.schema.json"),
    ("stanza/index.json", "schema/stanza.schema.json"),
    ("incoming/index.json", "schema/incoming.schema.json"),
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "generated")
    failures = 0
    for doc_rel, schema_rel in DOMAINS:
        doc_path, schema_path = root / doc_rel, root / schema_rel
        if not doc_path.exists() or not schema_path.exists():
            print(f"skip {doc_rel}: missing document or schema")
            continue
        schema = json.loads(schema_path.read_text())
        document = json.loads(doc_path.read_text())
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(document), key=lambda e: e.path)
        if errors:
            failures += 1
            print(f"FAIL {doc_rel} (against {schema_rel}):")
            for err in errors[:20]:
                loc = "/".join(str(p) for p in err.path) or "<root>"
                print(f"  - {loc}: {err.message}")
            if len(errors) > 20:
                print(f"  …and {len(errors) - 20} more")
        else:
            print(f"ok   {doc_rel} conforms to {schema_rel}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
