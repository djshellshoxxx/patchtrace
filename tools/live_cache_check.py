"""Native raw-output cache acceptance (SPEC-07 §13): real Ghidriff twice, second run must be a cache hit
with byte-identical raw JSON and identical normalized matches. Never executes either target DLL."""
import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
import threading
from collections import deque
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import patch

from patchtrace import backend
from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.diagnostics import redact_log
from patchtrace.service import ProjectService

CONTRACT = 'native-cache-diagnostics/1'
MAX_DOCUMENT_BYTES = 512 * 1024
MAX_EVENTS = 64
MAX_JAVA_PROBES = 4
SETTINGS = ('older_sha256', 'newer_sha256', 'python_version', 'pyghidra_version', 'ghidra_version',
            'java_runtime_version', 'symbol_policy')


def _text(value, limit=512):
    try:
        return redact_log(str(value), limit) if value is not None else None
    except Exception:
        return '<diagnostic text unavailable>'


def _number(value):
    try:
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None
    except (OverflowError, ValueError):
        return None


def _write_diagnostics(directory, name, document):
    if directory is None:
        return
    try:
        payload = (json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8')
        if len(payload) > MAX_DOCUMENT_BYTES:
            raise ValueError('diagnostic document exceeds its byte limit')
        with (directory / name).open('xb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception as exc:
        # A diagnostic failure must never replace the original acceptance exception.
        print(f'Cache diagnostics could not be written ({name}; {type(exc).__name__}).', file=sys.stderr)


@contextmanager
def _observe_java(document):
    """Observe existing probes only; preserve arguments, results, exceptions and the original callable."""
    original = backend.run_process

    def observed(argv, *args, **kwargs):
        if len(argv) != 2 or argv[1] != '-version':
            return original(argv, *args, **kwargs)
        if len(document['java_probes']) >= MAX_JAVA_PROBES:
            document['java_probes_omitted'] = document.get('java_probes_omitted', 0) + 1
            return original(argv, *args, **kwargs)
        probe = {'executable': _text(argv[0], 2048), 'argument': '-version',
                 'timeout_seconds': _number(kwargs.get('timeout_seconds'))}
        document['java_probes'].append(probe)
        try:
            result = original(argv, *args, **kwargs)
        except BaseException as exc:
            probe.update(exception_class=type(exc).__name__, message=_text(exc, 4096))
            raise
        try:
            probe.update(returncode=_number(result.returncode), reason=_text(result.reason),
                         log_tail=_text(result.log_tail, 4096),
                         elapsed_seconds=_number(getattr(result, 'elapsed_seconds', None)))
        except Exception as exc:
            probe['observation_error_class'] = type(exc).__name__
        return result

    with patch.object(backend, 'run_process', observed):
        yield


def _run_summary(run):
    settings = {key: _text(run.settings[key]) for key in SETTINGS if key in run.settings}
    origin = run.settings.get('cache_origin')
    if isinstance(origin, dict):
        settings['cache_origin'] = {key: _text(origin[key]) for key in ('key', 'created') if key in origin}
    return {'id': _text(run.id), 'status': _text(run.status), 'backend_version': _text(run.backend_version),
            'settings': settings, 'raw_path': _text(run.raw_path), 'error': _text(run.error, 4096)}


def analyse(root: Path, cache: Path, *, diagnostics: Path | None = None, label='first'):
    service = None
    events = [] if diagnostics is None else deque(maxlen=MAX_EVENTS)
    event_count = 0
    document = {'contract': CONTRACT, 'phase': label, 'java_probes': []}

    def on_event(event):
        nonlocal event_count
        event_count += 1
        events.append(event)

    try:
        service = ProjectService.create(Path('tests/fixtures/old.dll'), Path('tests/fixtures/new.dll'),
                                        'cache check', root)
        config = BackendConfig(sys.executable, os.environ['GHIDRA_INSTALL_DIR'], 900, cache_dir=str(cache))
        with _observe_java(document) if diagnostics is not None else nullcontext():
            path, run = run_comparison(config, service.project, root, threading.Event(), on_event)
        if diagnostics is not None:
            document['run'] = _run_summary(run)
        if run.status != 'completed':
            raise RuntimeError(run.error or 'run did not complete')
        service.apply_analysis(path, run)
        raw = (root / run.raw_path).read_bytes()
        matches = sorted((m.category, tuple(sorted(f.name for f in m.older + m.newer))) for m in service.project.matches)
        digest = hashlib.sha256(raw).hexdigest()
        document.update(raw_sha256=digest, match_count=len(matches))
        return run, digest, matches, list(events)
    except BaseException as exc:
        document.update(exception_class=type(exc).__name__, message=_text(exc, 4096))
        raise
    finally:
        try:
            if service is not None:
                service.close()
        finally:
            if diagnostics is not None:
                document['events'] = [{'stage': _text(event.stage), 'message': _text(event.message)}
                                      for event in events]
                document['events_omitted'] = max(0, event_count - MAX_EVENTS)
                _write_diagnostics(diagnostics, f'{label}.json', document)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics-dir', type=Path, help='create a new directory for bounded run/probe receipts')
    args = parser.parse_args(argv)
    diagnostics = args.diagnostics_dir
    if diagnostics is not None:
        diagnostics.mkdir(parents=True, exist_ok=False)
    document = {'contract': CONTRACT, 'phase': 'acceptance'}
    try:
        with tempfile.TemporaryDirectory(prefix='pt-cache-') as directory:
            base = Path(directory)
            first, raw1, matches1, _ = analyse(base / 'one', base / 'cache', diagnostics=diagnostics, label='first')
            if 'cache_origin' in first.settings:
                raise AssertionError('first run unexpectedly came from cache')
            second, raw2, matches2, _ = analyse(base / 'two', base / 'cache', diagnostics=diagnostics, label='second')
            if 'cache_origin' not in second.settings:
                raise AssertionError(f'second run was not a cache hit; java={first.settings.get("java_runtime_version")}')
            if raw1 != raw2 or matches1 != matches2:
                raise AssertionError('cache hit differs from the fresh run')
            print(f'Raw cache hit verified: sha256 {raw1[:16]}..., {len(matches1)} matches identical')
        document['status'] = 'passed'
    except BaseException as exc:
        document.update(status='failed', exception_class=type(exc).__name__, message=_text(exc, 4096))
        raise
    finally:
        _write_diagnostics(diagnostics, 'result.json', document)


if __name__ == '__main__':
    main()
