"""Secondary command facade has no import-time dependency cycle or Qt dependency."""
from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize('first', ['patchtrace.secondary.cli_import', 'patchtrace.cli'])
def test_secondary_dispatch_import_orders_are_headless(first):
    code = f'''
import importlib, sys
importlib.import_module({first!r})
from patchtrace.secondary.cli_import import dispatch
from patchtrace import cli
args = cli._parser(['secondary', 'reconcile']).parse_args(['secondary', 'reconcile', '/missing'])
assert args.action == 'reconcile'
assert callable(dispatch)
assert not any(name.startswith(('PySide6', 'patchtrace.ui')) for name in sys.modules)
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
