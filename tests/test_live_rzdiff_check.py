"""tools/live_rzdiff_check.py drives the production path (engine_env + adapter + run_engines).

Exercised here with a fake rz-diff (mocked evidence, not live acceptance): the fake records the environment
it received, so the test proves the shared allow-list reached the child and secrets did not.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from fake_exe import make_fake_exe

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'live_rzdiff_check.py'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'secondary' / 'rzdiff-functions.json'
sys.path.insert(0, str(ROOT / 'tools'))

import live_rzdiff_check  # noqa: E402


def fake_rz(tmp_path: Path, help_text: str) -> Path:
    spy = tmp_path / 'spy.json'
    body = f'''import json, os, sys
args = sys.argv[1:]
if args == ['-v']:
    print('rz-diff 0.9.1 @ linux-x86-64'); sys.exit(0)
if args == ['-h']:
    print({help_text!r}); sys.exit(0)
open({str(spy)!r}, 'w').write(json.dumps(dict(os.environ)))
sys.stdout.write(open({str(FIXTURE)!r}).read())
'''
    return make_fake_exe(tmp_path / 'bin', 'rz-diff', body)


HELP = 'Usage: rz-diff [options] <file0> <file1>\n  -C           show calls\n  -j           json\n  -t [type]    type\n'


def run_tool(tmp_path: Path, exe: Path) -> tuple[int, dict]:
    older, newer = tmp_path / 'old.dll', tmp_path / 'new.dll'
    older.write_bytes(b'MZold')
    newer.write_bytes(b'MZnew')
    out = tmp_path / 'live.json'
    env = {**os.environ, 'AWS_SECRET_ACCESS_KEY': 'sentinel', 'PYTHONPATH': str(ROOT / 'src')}
    proc = subprocess.run([sys.executable, str(TOOL), str(exe), str(older), str(newer), str(out), '--pin', '0.9.1',
                           '--archive-sha256', '0' * 64, '--os', 'test'], env=env, capture_output=True, text=True,
                          timeout=120)
    return proc.returncode, json.loads(out.read_text())


def test_help_options_parse_declared_flags_only():
    assert live_rzdiff_check.help_options(HELP + '  --long  x\n  -Cx\nmentions -j inline\n') == {'-C', '-j', '-t'}
    assert live_rzdiff_check.help_options('Use -C -j -t here') == set()


def test_tool_runs_through_scheduler_with_shared_env(tmp_path):
    code, result = run_tool(tmp_path, fake_rz(tmp_path, HELP))
    assert code == 0, result
    assert result['status'] == 'passed' and result['engine_run']['status'] == 'ok' and result['match_count'] == 4
    child_env = json.loads((tmp_path / 'spy.json').read_text())
    assert 'AWS_SECRET_ACCESS_KEY' not in child_env and 'PYTHONPATH' not in child_env


def test_tool_fails_on_flag_drift(tmp_path):
    code, result = run_tool(tmp_path, fake_rz(tmp_path, 'Usage: rz-diff -C -j -t (all inline)\n  -a  arch\n'))
    assert code == 1 and result['status'] == 'failed'
    assert result['help_flags'] == {'-C': False, '-j': False, '-t': False}
