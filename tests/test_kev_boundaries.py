"""kev/1 import boundaries: pure modules pull in no Qt, network or sqlite, and KEV never reaches ranking."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / 'src'
KEV = SRC / 'patchtrace' / 'kev'
PURE = ('contracts', 'limits', 'parse', 'join', 'view_model', 'ports', 'teach', 'tooltip_entries', 'kb_adapter')
FORBIDDEN = ('PySide6', 'urllib', 'urllib.request', 'http.client', 'socket', 'sqlite3', 'ssl')


@pytest.mark.parametrize('module', PURE)
def test_kev_modules_import_without_qt_network_or_sqlite(module):
    code = (f'import sys, patchtrace.kev.{module}; '
            f'bad = [m for m in {FORBIDDEN!r} if m in sys.modules]; print(",".join(bad)); sys.exit(1 if bad else 0)')
    env = {**os.environ, 'PYTHONPATH': str(SRC)}
    run = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60, env=env)
    assert run.returncode == 0, f'{module} imported {run.stdout.strip()} {run.stderr[-300:]}'


def test_kev_never_imports_ranking_or_hypothesis_code():
    banned = ('enrichment.ranking', 'contextual_rank', 'enrichment.cve', 'hypotheses', 'lexicon', 'attention')
    for path in KEV.glob('*.py'):
        imports = [line for line in path.read_text(encoding='utf-8').splitlines()
                   if line.startswith(('import ', 'from '))]
        for line in imports:
            assert not any(name in line for name in banned), f'{path.name}: {line}'


def test_kev_package_has_no_qt_import_anywhere():
    for path in KEV.glob('*.py'):
        assert 'PySide6' not in path.read_text(encoding='utf-8'), path.name
