"""Current registry execution and version envelope; no native package claims."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from argparse import Namespace
from pathlib import Path

from patchtrace import cli, version_cli


def test_real_version_command_is_headless_and_uses_current_envelope():
    root = Path(__file__).resolve().parents[1]
    program = ('import sys; from patchtrace.cli import main; code=main(["version", "--json"]); '
               'assert not any(x.startswith("PySide6") for x in sys.modules); raise SystemExit(code)')
    child = subprocess.run([sys.executable, '-c', program], cwd=root,
                           env={**os.environ, 'PYTHONPATH': str(root / 'src'), 'PYTHONDONTWRITEBYTECODE': '1'},
                           capture_output=True, text=True, timeout=35)
    assert child.returncode == 0, child.stderr
    data = json.loads(child.stdout)
    assert data['contract'] == 'enrichment-cli/1' and data['command'] == 'version'
    assert data['status'] == 'complete' and data['result']['contract'] == 'build-info/1'
    assert data['result']['version'] and data['result']['source_sha256'] != 'unknown'


def test_version_cancellation_keeps_standard_exit_code(capsys):
    cancel = threading.Event()
    cancel.set()
    try:
        version_cli.run(Namespace(json=True), cancel)
    except cli.CliError as exc:
        assert exc.code == 5
    else:
        raise AssertionError('cancellation did not propagate')
    assert not capsys.readouterr().out
