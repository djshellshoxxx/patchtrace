"""Windows-acceptance spec A1-A3, A5, A6 (imported variant) and A10 through the real CLI entry point.

Runs on every OS, including windows-latest (nothing here is skipped by platform). It launches
`python -m patchtrace` as a subprocess; the frozen PatchTrace.exe is exercised only by tools/frozen_smoke.py
in the Windows CI step, so a pass here is not evidence about the frozen package.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.cli_commands import names

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'frozen_smoke.py'


def _load():
    spec = importlib.util.spec_from_file_location('frozen_smoke', TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules['frozen_smoke'] = module
    spec.loader.exec_module(module)
    return module


def test_smoke_checks_pass_against_source_cli():
    smoke = _load()
    lines: list[str] = []
    failures = smoke.run_checks([sys.executable, '-m', 'patchtrace'], frozen=False, emit=lines.append)
    assert failures == [], failures
    labels = '\n'.join(lines)
    for expected in ('A1 series --help', 'A2 unknown', 'A3 missing', 'A5 rank --json', 'A10 unicode-cjk',
                     'A10 onedrive-style', 'A10 long-200', 'A6s series chains'):
        assert f'PASS {expected}' in labels, labels
    assert not any(line.startswith('FAIL') for line in lines)


@pytest.mark.parametrize('command', names())
def test_cli_help_paths_never_import_qt(command):
    code = ('import sys\nfrom patchtrace import cli\n'
            'rc = cli.main([sys.argv[1], "--help"])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else (rc or 0))\n')
    result = subprocess.run([sys.executable, '-c', code, command], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'usage:' in result.stdout


def test_every_cli_command_is_covered_by_the_smoke_list():
    smoke = _load()
    parser = cli._parser()
    sub = next(a for a in parser._actions if getattr(a, 'choices', None))
    assert set(sub.choices) == set(smoke.COMMANDS)


def test_live_rzdiff_check_parses_real_coloured_help_text():
    """Real `rz-diff -h` (rizin 0.9.1) output contains ANSI colour codes; the flag-drift check must see through them."""
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('live_rzdiff_check', root / 'tools' / 'live_rzdiff_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = (root / 'tests' / 'fixtures' / 'secondary' / 'rz-diff-0.9.1-help.txt').read_text(encoding='utf-8')
    assert '\x1b[' in text  # the fixture is the raw coloured output, not a cleaned copy
    assert set(module.FROZEN_FLAGS) <= module.help_options(text)
    # A help text that lacks a frozen flag must be detected (the check is not a substring match).
    assert '-t' not in module.help_options('  -j   JSON output\n  --type  not an option line\n')
