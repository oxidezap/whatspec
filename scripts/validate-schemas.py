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
    from jsonschema.exceptions import SchemaError
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012, specification_with
    from referencing.exceptions import Unresolvable
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
    ("srvreq/index.json", "schema/srvreq.schema.json"),
    ("wasm/index.json", "schema/wasm.schema.json"),
]


def schema_validator(schema, default=Draft202012Validator):
    if not isinstance(schema, dict) or "$schema" not in schema:
        return default
    if not isinstance(schema["$schema"], str):
        raise ValueError("$schema must be a dialect URI string")
    selected = validator_for(schema, default=None)
    if selected is None:
        raise ValueError(f"unsupported schema dialect: {schema['$schema']}")
    return selected


def checked_registry(schema):
    """Check every schema-valued location, including branches no instance visits.

    Resource.subresources follows the declared draft's schema keywords, so objects
    in const/default/examples are data, not schemas. Registry has no retriever:
    URI-shaped IDs may name embedded resources, but nothing is fetched.
    """
    selected = schema_validator(schema)
    selected.check_schema(schema)
    root = Resource.from_contents(schema, default_specification=DRAFT202012)
    registry = Registry().with_resource("", root).crawl()
    pending = [(root, registry.resolver().in_subresource(root), selected)]
    seen = set()
    while pending:
        resource, resolver, inherited = pending.pop()
        contents = resource.contents
        dialect = schema_validator(contents, inherited)
        identity = (id(contents), dialect)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(contents, dict):
            for keyword in ("$ref", "$dynamicRef", "$recursiveRef"):
                if keyword in dialect.VALIDATORS and keyword in contents:
                    resolved = resolver.lookup(contents[keyword])
                    # A pointer must lead to a schema, not an arbitrary JSON value.
                    target_dialect = schema_validator(resolved.contents, dialect)
                    target_dialect.check_schema(resolved.contents)
                    target = Resource.from_contents(
                        resolved.contents,
                        default_specification=specification_with(
                            target_dialect.ID_OF(target_dialect.META_SCHEMA)),
                    )
                    # A ref can turn an otherwise opaque annotation into a schema.
                    pending.append((target, resolved.resolver, target_dialect))
        pending.extend(
            (child, resolver.in_subresource(child), dialect)
            for child in resource.subresources()
        )
    return selected, registry


def validate(root: Path) -> int:
    failures = 0
    for doc_rel, schema_rel in DOMAINS:
        doc_path, schema_path = root / doc_rel, root / schema_rel
        if not doc_path.exists() or not schema_path.exists():
            failures += 1
            print(f"FAIL {doc_rel}: missing document or schema")
            continue
        try:
            schema = json.loads(schema_path.read_text())
            document = json.loads(doc_path.read_text())
            selected, registry = checked_registry(schema)
            validator = selected(schema, registry=registry)
            errors = sorted(validator.iter_errors(document),
                            key=lambda e: tuple(str(p) for p in e.path))
        except (OSError, ValueError, SchemaError, Unresolvable) as err:
            failures += 1
            print(f"FAIL {doc_rel} (against {schema_rel}): {err}")
            continue
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
    print(f"{len(DOMAINS) - failures}/{len(DOMAINS)} schema/document pairs validated; "
          f"{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(validate(Path(sys.argv[1] if len(sys.argv) > 1 else "generated")))
