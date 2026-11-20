"""Native raw-output cache acceptance (SPEC-07 §13): real Ghidriff twice, second run must be a cache hit
with byte-identical raw JSON and identical normalized matches. Never executes either target DLL."""
import hashlib
import os
import sys
import tempfile
import threading
from pathlib import Path

from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.service import ProjectService


def analyse(root: Path, cache: Path):
    service = ProjectService.create(Path('tests/fixtures/old.dll'), Path('tests/fixtures/new.dll'), 'cache check', root)
    try:
        events = []
        config = BackendConfig(sys.executable, os.environ['GHIDRA_INSTALL_DIR'], 900, cache_dir=str(cache))
        path, run = run_comparison(config, service.project, root, threading.Event(), lambda e: events.append(e))
        if run.status != 'completed':
            raise RuntimeError(run.error or 'run did not complete')
        service.apply_analysis(path, run)
        raw = (root / run.raw_path).read_bytes()
        matches = sorted((m.category, tuple(sorted(f.name for f in m.older + m.newer))) for m in service.project.matches)
        return run, hashlib.sha256(raw).hexdigest(), matches, events
    finally:
        service.close()


with tempfile.TemporaryDirectory(prefix='pt-cache-') as directory:
    base = Path(directory)
    first, raw1, matches1, _ = analyse(base / 'one', base / 'cache')
    if 'cache_origin' in first.settings:
        raise AssertionError('first run unexpectedly came from cache')
    second, raw2, matches2, events = analyse(base / 'two', base / 'cache')
    if 'cache_origin' not in second.settings:
        raise AssertionError(f'second run was not a cache hit; java={first.settings.get("java_runtime_version")}')
    if raw1 != raw2 or matches1 != matches2:
        raise AssertionError('cache hit differs from the fresh run')
    print(f'Raw cache hit verified: sha256 {raw1[:16]}..., {len(matches1)} matches identical')
