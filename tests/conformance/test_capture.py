"""Offline checks for capture identity and corrupted input rejection."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from capture import MODULES, capture


class CaptureTests(unittest.TestCase):
    def test_committed_sources_match_every_recorded_span_hash(self):
        for version in ['2.3000.1045368834', '2.3000.1047483476']:
            root = Path(__file__).parent / version
            evidence = json.loads((root / 'provenance.json').read_text())
            self.assertEqual({e['module'] for e in evidence['modules']}, set(MODULES))
            for entry in evidence['modules']:
                source = (root / (entry['module'] + '.js')).read_bytes()
                self.assertTrue(source.endswith(b';\n'))
                source = source[:-2]  # Capture's terminator, not part of the AST span.
                self.assertEqual(len(source), entry['end'] - entry['start'])
                self.assertEqual(hashlib.sha256(source).hexdigest(), entry['sourceSha256'])

    def test_changed_missing_extra_and_wrong_set_hash_are_rejected_before_ast(self):
        for failure in ['changed', 'missing', 'extra', 'setHash', 'count']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundles = root / 'bundles'
                bundles.mkdir()
                source = b'fixture'
                digest = hashlib.sha256(source).hexdigest()
                lock = dict(waVersion='fixture', bundleCount=1,
                            setHash=hashlib.sha256(f'{digest}:7'.encode()).hexdigest(),
                            bundles=[dict(sha256=digest, size=7)])
                (bundles / 'input.js').write_bytes(source)
                if failure == 'changed':
                    (bundles / 'input.js').write_bytes(b'changed')
                elif failure == 'missing':
                    (bundles / 'input.js').unlink()
                elif failure == 'extra':
                    (bundles / 'extra.js').write_bytes(source)
                elif failure == 'setHash':
                    lock['setHash'] = '0' * 64
                else:
                    lock['bundleCount'] = 2
                lock_path = root / 'lock.json'
                lock_path.write_text(json.dumps(lock))
                with self.assertRaises(ValueError):
                    capture(lock_path, bundles, root / 'output')
                self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
