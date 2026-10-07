#!/usr/bin/env python3
"""Verify a complete locked bundle set, then capture named modules by AST spans.

Usage: python3 tests/conformance/capture.py LOCK BUNDLES OUTPUT
Build first: cargo build -p wa-transform --example module_spans
No bundle code is executed. OUTPUT must not already exist.
"""
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import sys

MODULES = [
    'WASmaxOutGroupsSetSubjectRequest',
    'WASmaxOutGroupsSetSubjectChangeSubjectMixin',
    'WASmaxOutGroupsBaseSetGroupMixin',
    'WASmaxOutGroupsBaseIQSetRequestMixin',
    'WASmaxOutGroupsAcceptGroupAddRequest',
    'WASmaxGroupsSetSubjectRPC',
    'WASmaxGroupsAcceptGroupAddRPC',
    'WASmaxInGroupsSetSubjectResponseSuccess',
    'WASmaxInGroupsAcceptGroupAddResponseSuccess',
    'WASmaxInGroupsAcceptGroupAddResponseGroupJoinRequestSuccess',
    'WASmaxInGroupsIQResultResponseMixin',
    'WAWebMexFetchNewsletterJob',
    'WAWebMexFetchNewsletterJobQuery.graphql',
]


def capture(lock_path, bundles, output):
    lock = json.loads(lock_path.read_text())
    files = sorted(bundles.rglob('*.js'))
    raw = [(p, p.read_bytes()) for p in files]
    actual = collections.Counter((hashlib.sha256(b).hexdigest(), len(b)) for _, b in raw)
    expected = collections.Counter((b['sha256'], b['size']) for b in lock['bundles'])
    if actual != expected or len(files) != lock['bundleCount']:
        raise ValueError('bundle multiset differs from lock')
    fingerprint = hashlib.sha256('\n'.join(sorted(
        f'{h}:{s}' for (h, s), n in actual.items() for _ in range(n)
    )).encode()).hexdigest()
    if fingerprint != lock['setHash']:
        raise ValueError('setHash differs from lock')
    executable = Path(__file__).resolve().parents[2] / 'target/debug/examples/module_spans'
    captured = {}
    evidence = []
    for path, data in raw:
        if not any(('"' + name + '"').encode() in data for name in MODULES):
            continue
        spans = subprocess.check_output([str(executable), str(path), *MODULES], text=True)
        for row in spans.splitlines():
            name, start, end = row.split('\t')
            start, end = int(start), int(end)
            source = data[start:end]
            if name in captured and captured[name] != source:
                raise ValueError(f'divergent duplicate module: {name}')
            captured[name] = source
            evidence.append(dict(module=name, bundleSha256=hashlib.sha256(data).hexdigest(),
                                 start=start, end=end, sourceSha256=hashlib.sha256(source).hexdigest()))
    if set(captured) != set(MODULES):
        raise ValueError(f'missing modules: {set(MODULES) - set(captured)}')
    output.mkdir(parents=True, exist_ok=False)
    for name, source in sorted(captured.items()):
        (output / (name + '.js')).write_bytes(source + b';\n')
    (output / 'provenance.json').write_text(json.dumps(dict(
        waVersion=lock['waVersion'], setHash=fingerprint,
        bundleCount=len(files), bundleBytes=sum(len(b) for _, b in raw),
        modules=sorted(evidence, key=lambda e: (e['module'], e['bundleSha256'], e['start']))
    ), indent=2) + '\n')
    print(f"verified {len(files)} bundles; captured {len(captured)} modules, {len(evidence)} definitions")


if __name__ == '__main__':
    capture(*(Path(arg) for arg in sys.argv[1:]))
