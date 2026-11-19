"""Retain the still-blocked forced-export race using authored temporary bytes only.

Run from the repository root with PYTHONPATH=src. This is evidence of a known
remaining defect, not a passing acceptance test; it does not alter repository files.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
REFS = ('9c411ca3d7b47f950be5f0c6f01b3c54184554c6',
        '88b0b52281dd314aa72f93819145a73135618bc4',
        'd436a7ec571efa75dcd627ca9835c65f60e09c74')
SOURCE = 'src/patchtrace/strings/export.py'


def probe(ref, source, failure):
    name = 'patchtrace.strings._force_source_probe'
    module = types.ModuleType(name)
    module.__package__ = 'patchtrace.strings'
    sys.modules[name] = module
    exec(compile(source, f'{ref}:{SOURCE}', 'exec'), module.__dict__)
    with tempfile.TemporaryDirectory(prefix='patchtrace-force-proof-') as temporary:
        root = Path(temporary)
        target = root / 'report.json'
        target.write_bytes(b'prior complete export')
        replaced = []
        sync = os.fsync

        def substitute(descriptor):
            sync(descriptor)
            stages = list(root.glob('.*.tmp'))
            assert len(stages) == 1
            stage = stages[0]
            stage.rename(root / 'owned-source')
            stage.write_bytes(b'foreign replacement bytes')
            replaced.append(stage)
            if failure == 'io':
                raise OSError(5, 'controlled source interruption')
            if failure == 'cancel':
                raise KeyboardInterrupt('controlled export cancellation')

        error = None
        with patch.object(os, 'fsync', substitute):
            try:
                module.write_atomic(target, b'expected export bytes', force=True)
            except BaseException as exc:
                error = type(exc).__name__
        return {'ref': ref, 'source_sha256': hashlib.sha256(source).hexdigest(),
                'failure': failure, 'error': error, 'target': target.read_text(),
                'owned_source': (root / 'owned-source').read_text(),
                'foreign_replacement_preserved': replaced[0].exists()}


def main():
    if not sys.platform.startswith('linux'):
        raise SystemExit('This retained source-substitution proof requires Linux rename semantics.')
    rows = []
    for ref in REFS:
        source = subprocess.check_output(['git', 'show', f'{ref}:{SOURCE}'], cwd=ROOT)
        rows.extend(probe(ref, source, failure) for failure in ('none', 'io', 'cancel'))
    rows.extend(probe('current-worktree', (ROOT / SOURCE).read_bytes(), failure)
                for failure in ('none', 'io', 'cancel'))
    print(json.dumps({'status': 'BLOCKED', 'scope': 'forced export source ownership', 'observations': rows},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
