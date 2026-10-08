"""Offline regressions for incomplete and malformed generated snapshots."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'validate-schemas.py'
spec = importlib.util.spec_from_file_location('validate_schemas', SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class SnapshotValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for document, schema in validator.DOMAINS:
            for rel, value in [(document, {}), (schema, {'type': 'object'})]:
                path = self.root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))

    def validate(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return validator.validate(self.root)

    def test_complete_snapshot(self):
        self.assertEqual(self.validate(), 0)

    def test_summary_counts_only_successful_pairs(self):
        (self.root / validator.DOMAINS[0][0]).unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = validator.validate(self.root)
        self.assertEqual(result, 1)
        self.assertIn("11/12 schema/document pairs validated; 1 failed", output.getvalue())

    def test_missing_document_is_failure(self):
        (self.root / validator.DOMAINS[0][0]).unlink()
        self.assertEqual(self.validate(), 1)

    def test_missing_schema_is_failure(self):
        (self.root / validator.DOMAINS[0][1]).unlink()
        self.assertEqual(self.validate(), 1)

    def test_empty_snapshot_is_failure(self):
        with tempfile.TemporaryDirectory() as empty:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(validator.validate(Path(empty)), 1)

    def test_invalid_schema_is_failure(self):
        (self.root / validator.DOMAINS[0][1]).write_text('{"type":"not-a-type"}')
        self.assertEqual(self.validate(), 1)

    def test_malformed_document_is_failure(self):
        (self.root / validator.DOMAINS[0][0]).write_text('{')
        self.assertEqual(self.validate(), 1)

    def test_wrong_shape_is_failure(self):
        (self.root / validator.DOMAINS[0][0]).write_text('[]')
        self.assertEqual(self.validate(), 1)

    def test_unused_external_references_are_failure(self):
        for schema in [
            {"type": "object", "properties": {"optional": {"$ref": "https://invalid.example/schema.json"}}},
            {"$defs": {"unused": {"$ref": "https://invalid.example/schema.json"}}},
        ]:
            with self.subTest(schema=schema):
                (self.root / validator.DOMAINS[0][1]).write_text(json.dumps(schema))
                self.assertEqual(self.validate(), 1)

    def test_reference_structure_respects_drafts_and_local_scopes(self):
        cases = [
            # Forward local pointers/anchors, nested resource IDs, and recursion.
            ({"$defs": {"node": {"$anchor": "node", "properties": {"next": {"$ref": "#node"}}}},
              "properties": {"optional": {"$ref": "#/$defs/node"}}}, 0),
            ({"$id": "https://example.test/root", "$defs": {
                "child": {"$id": "child", "$defs": {"leaf": {"$anchor": "leaf", "type": "string"}},
                          "properties": {"x": {"$ref": "#leaf"}}}},
              "properties": {"optional": {"$ref": "child#leaf"}}}, 0),
            ({"$defs": {"bad": {"$ref": "#/$defs/missing"}}}, 1),
            ({"$defs": {"bad": {"$ref": "#missing"}}}, 1),
            ({"$defs": {"bad": {"$dynamicRef": "https://invalid.example/schema.json"}}}, 1),
            ({"$dynamicAnchor": "node", "$defs": {"node": {"$dynamicRef": "#node"}}}, 0),
            ({"$schema": "http://json-schema.org/draft-07/schema#",
              "definitions": {"unused": {"$ref": "https://invalid.example/schema.json"}}}, 1),
            ({"$schema": "http://json-schema.org/draft-07/schema#",
              "definitions": {"node": {"$id": "#node", "type": "object"}},
              "properties": {"optional": {"$ref": "#node"}}}, 0),
            ({"$schema": "http://json-schema.org/draft-04/schema#",
              "definitions": {"node": {"id": "#node", "type": "object"}},
              "properties": {"optional": {"$ref": "#node"}}}, 0),
            ({"$schema": "https://json-schema.org/draft/2019-09/schema",
              "$recursiveAnchor": True, "$defs": {"node": {"$recursiveRef": "#"}}}, 0),
            ({"$schema": "http://json-schema.org/draft-07/schema#",
              "$dynamicRef": "https://invalid.example/schema.json"}, 0),
            ({"type": "object", "default": {"$ref": "https://invalid.example/schema.json"},
              "examples": [{"$ref": "https://invalid.example/schema.json"}],
              "properties": {"optional": {"const": {"$ref": "https://invalid.example/schema.json"}}}}, 0),
            ({"properties": {"optional": {"$ref": "#/default"}},
              "default": {"$ref": "https://invalid.example/schema.json"}}, 1),
            ({"$schema": "https://invalid.example/unknown-draft"}, 1),
            ({"$schema": []}, 1),
        ]
        for schema, expected in cases:
            with self.subTest(schema=schema):
                (self.root / validator.DOMAINS[0][1]).write_text(json.dumps(schema))
                self.assertEqual(self.validate(), expected)

    def test_external_reference_is_failure_without_network(self):
        (self.root / validator.DOMAINS[0][1]).write_text('{"$ref":"https://invalid.example/schema.json"}')
        self.assertEqual(self.validate(), 1)


if __name__ == '__main__':
    unittest.main()
