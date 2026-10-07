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

    def test_external_reference_is_failure_without_network(self):
        (self.root / validator.DOMAINS[0][1]).write_text('{"$ref":"https://invalid.example/schema.json"}')
        self.assertEqual(self.validate(), 1)


if __name__ == '__main__':
    unittest.main()
