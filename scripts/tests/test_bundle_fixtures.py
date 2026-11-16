import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/bundles-1054751086"


class BundleFixtures(unittest.TestCase):
    def test_sources_match_pinned_bundle_hashes_and_spans(self):
        metadata = json.loads((FIXTURES / "sources.json").read_text())
        lock = json.loads((ROOT / "generated/bundles.lock.json").read_text())
        self.assertEqual(metadata["waVersion"], lock["waVersion"])
        self.assertEqual(metadata["setHash"], lock["setHash"])
        bundles = {bundle["sha256"]: bundle for bundle in lock["bundles"]}
        names = set()
        for module in metadata["modules"]:
            with self.subTest(module=module["name"]):
                self.assertNotIn(module["name"], names)
                names.add(module["name"])
                source = (FIXTURES / (module["name"] + ".js")).read_bytes()
                self.assertEqual(hashlib.sha256(source).hexdigest(), module["sha256"])
                bundle = bundles[module["bundleSha256"]]
                self.assertGreaterEqual(module["start"], 0)
                self.assertLessEqual(module["end"], bundle["size"])
                self.assertEqual(module["end"] - module["start"], len(source))
                self.assertTrue(source.startswith(('__d("' + module["name"] + '"').encode()))
        self.assertEqual(names, {path.stem for path in FIXTURES.glob("*.js")})
