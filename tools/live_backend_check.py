"""Run real static PE fixture acceptance; never execute either target DLL."""
import os
import sys
import threading
from pathlib import Path

from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.service import ProjectService

root = Path('live-project').resolve()
service = ProjectService.create(Path('tests/fixtures/old.dll'), Path('tests/fixtures/new.dll'),
                                'Known bounds-check patch', root)
try:
    path, run = run_comparison(BackendConfig(sys.executable, os.environ['GHIDRA_INSTALL_DIR'], 900),
                               service.project, root, threading.Event(), lambda e: print(e.message, flush=True))
    if run.status != 'completed':
        raise RuntimeError(run.error or 'Expected completed backend run')
    service.apply_analysis(path, run)
    candidates = [m for m in service.project.matches
                  if any('read_item' in f.name for f in m.older + m.newer)]
    if not candidates or not any(m.category == 'modified' and m.older and m.newer for m in candidates):
        raise AssertionError('Known exported bounds-check function missing from modified matches')
    text = '\n'.join(f.code or '' for m in candidates for f in m.newer)
    if 'if' not in text:
        raise AssertionError('Expected bounds check not present in new decompilation')
    print(f'Known patch accepted: {len(service.project.matches)} change records')
finally:
    service.close()
