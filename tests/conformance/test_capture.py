"""Offline checks for capture identity and corrupted input rejection."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from capture import MODULES, capture
from compiled.capture_errors import MODULES as COMPILED_MODULES


class CaptureTests(unittest.TestCase):
    def capture_synthetic(self, spelling, mutate_file=False):
        name = 'ConformanceModule'
        source = f'__d({spelling},[],function(){{}});'.encode()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundles = root / 'bundles'
            bundles.mkdir()
            bundle = bundles / 'input.js'
            bundle.write_bytes(source)
            digest = hashlib.sha256(source).hexdigest()
            lock = dict(waVersion='fixture', bundleCount=1,
                        setHash=hashlib.sha256(f'{digest}:{len(source)}'.encode()).hexdigest(),
                        bundles=[dict(sha256=digest, size=len(source))])
            lock_path = root / 'lock.json'
            lock_path.write_text(json.dumps(lock))

            def ast(args, **kwargs):
                # An instrumented subprocess boundary, not a replacement AST
                # oracle: prove the verified bytes are sent without rereading.
                if mutate_file:
                    bundle.write_bytes(b'/* moved offsets */' + source)
                self.assertEqual(args[1], '-')
                self.assertEqual(kwargs.get('input'), source)
                return f'{name}\t0\t{len(source) - 1}\n'.encode()

            with patch('capture.MODULES', [name]), patch(
                'capture.subprocess.check_output', side_effect=ast
            ) as parser:
                capture(lock_path, bundles, root / 'output')
                parser.assert_called_once()
            self.assertEqual((root / 'output' / f'{name}.js').read_bytes(), source + b'\n')

    def test_ast_receives_the_verified_bytes_even_if_original_file_changes(self):
        self.capture_synthetic('"ConformanceModule"', mutate_file=True)

    def test_single_quoted_and_escaped_names_reach_the_ast(self):
        for spelling in ["'ConformanceModule'", r"'\u0043onformanceModule'"]:
            with self.subTest(spelling=spelling):
                self.capture_synthetic(spelling)

    def test_committed_sources_match_every_recorded_span_hash(self):
        for base, modules in [(Path(__file__).parent, MODULES),
                              (Path(__file__).parent / 'compiled/sources', COMPILED_MODULES)]:
            for version in ['2.3000.1045368834', '2.3000.1047483476']:
                root = base / version
                evidence = json.loads((root / 'provenance.json').read_text())
                self.assertEqual(evidence['waVersion'], version)
                self.assertEqual({e['module'] for e in evidence['modules']}, set(modules))
                self.assertEqual({p.stem for p in root.glob('*.js')}, set(modules))
                for entry in evidence['modules']:
                    source = (root / (entry['module'] + '.js')).read_bytes()
                    self.assertTrue(source.endswith(b';\n'))
                    source = source[:-2]
                    self.assertEqual(len(source), entry['end'] - entry['start'])
                    self.assertEqual(hashlib.sha256(source).hexdigest(), entry['sourceSha256'])

    def test_compiled_inputs_match_recorded_hashes(self):
        root = Path(__file__).parent / 'compiled/inputs'
        evidence = json.loads((root / 'provenance.json').read_text())
        self.assertEqual({e['waVersion'] for e in evidence},
                         {'2.3000.1045368834', '2.3000.1047483476'})
        self.assertEqual(len(evidence), 2)
        for entry in evidence:
            source = (root / (entry['waVersion'] + '.json')).read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(), entry['selectedInputSha256'])
            self.assertEqual(json.loads(source)['waVersion'], entry['waVersion'])

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
