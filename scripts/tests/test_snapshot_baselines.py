"""Mutate the real snapshot: each reviewed baseline must still reject drift both ways."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lint_ir', ROOT / 'scripts/lint-ir.py')
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)


def nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from nodes(child)


class ReviewedBaselines(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'generated'
        shutil.copytree(ROOT / 'generated', self.root)

    def run_lint(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['lint-ir.py', str(self.root)]), contextlib.redirect_stdout(output):
            status = lint.main()
        return status, output.getvalue()

    def changed(self, path, original, mutate, name):
        value = copy.deepcopy(original)
        mutate(value)
        (self.root / path).write_text(json.dumps(value))
        status, output = self.run_lint()
        self.assertEqual(status, 1)
        self.assertIn('CHANGED     ' + name + ':', output)
        (self.root / path).write_text(json.dumps(original))

    def test_reviewed_snapshot_passes(self):
        status, output = self.run_lint()
        self.assertEqual(status, 0, output)

    def test_wam_gaps_still_fail_in_both_directions(self):
        path = 'manifest.json'
        original = json.loads((self.root / path).read_text())
        for key, name in [
            ('unreadConstructionArgument.identifier', 'wam construction with an unread argument'),
            ('construction of an event with no catalog entry', 'wam construction of an event with no catalog entry'),
        ]:
            for delta in [-1, 1]:
                with self.subTest(key=key, delta=delta):
                    def mutate(value):
                        drops = value['diagnostics']['wam']['dropsByReason']
                        drops[key] += delta
                    self.changed(path, original, mutate, name)

    def test_iq_argument_gaps_still_fail_in_both_directions(self):
        path = 'iq/index.json'
        original = json.loads((self.root / path).read_text())
        for kind in ['attribute', 'child']:
            for add_gap in [False, True]:
                with self.subTest(kind=kind, add_gap=add_gap):
                    def mutate(value):
                        candidates = []
                        for stanza in value['stanzas']:
                            for node in nodes(stanza.get('request', {}).get('children', [])):
                                if kind == 'attribute':
                                    candidates += [a for a in node.get('attrs', []) if a.get('kind') not in ('const', 'generated_id') and 'value' not in a]
                                elif node.get('repeats') or node.get('presence', 'required') != 'required':
                                    candidates.append(node)
                        node = next(n for n in candidates if ('argPath' in n) == add_gap)
                        if add_gap:
                            del node['argPath']
                        else:
                            node['argPath'] = ['baseline_probe']
                    self.changed(path, original, mutate, f'iq builder {kind} with no argument path')

    def test_mex_presence_gaps_still_fail_in_both_directions(self):
        path = 'mex/index.json'
        original = json.loads((self.root / path).read_text())
        for operation in [False, True]:
            name = 'mex operation with no established variable presence' if operation else 'mex variable with an undetermined presence'
            for add_gap in [False, True]:
                with self.subTest(operation=operation, add_gap=add_gap):
                    def mutate(value):
                        for op in value['operations'].values():
                            presence = op.get('variablesPresence', {})
                            if operation:
                                if presence and all(n['presence'] == 'undetermined' for n in presence.values()) != add_gap:
                                    for node in presence.values():
                                        node['presence'] = 'undetermined' if add_gap else 'always'
                                    return
                            else:
                                for node in nodes(presence):
                                    if 'presence' in node and (node['presence'] == 'undetermined') != add_gap:
                                        node['presence'] = 'undetermined' if add_gap else 'always'
                                        return
                        self.fail('no suitable presence node')
                    self.changed(path, original, mutate, name)
