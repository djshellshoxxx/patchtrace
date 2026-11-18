"""Current-source desktop entry controls; children cannot use the shared venv's older editable tree."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'offline-investigation: synthetic F8 journey passed'


def child(tmp_path, setup='', *, headless=False):
    temporary = tmp_path / 'tmp'
    temporary.mkdir()
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), QT_QPA_PLATFORM='offscreen',
               TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
    code = """
import os, pathlib, socket, subprocess, sys
def refuse(*args, **kwargs):
    raise AssertionError('self-test tried network or target execution')
socket.socket.connect = socket.socket.connect_ex = refuse
socket.create_connection = socket.getaddrinfo = refuse
subprocess.Popen = os.system = refuse
import patchtrace.__main__ as entry
assert pathlib.Path(entry.__file__).resolve() == pathlib.Path(sys.argv[1]).resolve()
""" + setup + "\nsys.argv = ['patchtrace', " + ("'rank', '--help'" if headless else "'--self-test'") + "]\n"
    code += "try:\n    rc = entry.main()\nexcept SystemExit as error:\n    rc = error.code\n"
    if headless:
        code += "assert not any(n.startswith(('PySide6', 'patchtrace.ui', 'patchtrace.gui.qt')) for n in sys.modules)\n"
    code += "raise SystemExit(rc)\n"
    result = subprocess.run([sys.executable, '-c', code, str(ROOT / 'src/patchtrace/__main__.py')],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    return result, temporary


def test_source_pinned_entry_completes_synthetic_journey_and_cleans_temp(tmp_path):
    result, temporary = child(tmp_path)
    assert result.returncode == 0, result.stderr
    assert 'optional-deps:' in result.stdout
    assert MARKER in result.stdout, result.stdout
    line = next(line for line in result.stdout.splitlines() if line.startswith('offline-investigation-receipt: '))
    receipt = json.loads(line.split(': ', 1)[1])
    assert receipt['contract'] == 'patchtrace-kb-selftest/1' and receipt['synthetic'] is True
    assert receipt['stale_after_reopen'] is True and receipt['matches'] == 4
    assert not list(temporary.glob('patchtrace-self-test-*'))


@pytest.mark.parametrize('failure', ['sample', 'journey', 'cleanup'])
def test_entry_failure_keeps_nonzero_status_and_never_prints_success(tmp_path, failure):
    setup = {
        'sample': """
from patchtrace.service import ProjectService
real_sample = ProjectService.sample
def broken_sample(root):
    service = real_sample(root)
    service.project.sample = False
    return service
ProjectService.sample = staticmethod(broken_sample)
""",
        'journey': """
from patchtrace.gui.qt import kb_selftest
def broken_candidate(window):
    raise RuntimeError('controlled journey failure')
    yield
kb_selftest._candidate = broken_candidate
""",
        'cleanup': """
from patchtrace.gui.qt import selftest_loop
def refuse_cleanup(path):
    raise PermissionError('controlled cleanup failure')
selftest_loop.shutil.rmtree = refuse_cleanup
""",
    }[failure]
    result, temporary = child(tmp_path, setup)
    assert result.returncode != 0
    assert MARKER not in result.stdout and 'offline-investigation-receipt:' not in result.stdout
    assert {'sample': 'Desktop self-test', 'journey': 'controlled journey failure',
            'cleanup': 'controlled cleanup failure'}[failure] in result.stderr
    if failure != 'cleanup':
        assert not list(temporary.glob('patchtrace-self-test-*'))
    else:
        assert list(temporary.glob('patchtrace-self-test-*'))


def test_headless_dispatch_stays_qt_free_with_exact_source_pin(tmp_path):
    result, temporary = child(tmp_path, headless=True)
    assert result.returncode == 0, result.stderr
    assert 'usage:' in result.stdout and MARKER not in result.stdout
    assert not list(temporary.iterdir())
