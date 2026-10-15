"""Tier W one-command local runner (decision O1): refusals, consent gating, aggregate-only output. Hermetic: a fake
runner replaces `python -m tools.calibration.tier_w`; no Microsoft data, network or Ghidra."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_w import run_local as R  # noqa: E402

HOSTS = 'winbindex.m417z.com,msdl.microsoft.com'
EVAL = {'contract': 'tier-w-evaluation/1', 'tier': 'W', 'precision': 0.9, 'recall': 0.8, 'identity_tp': 9,
        'pairs': 3, 'status': 'ok', 'by_lineage': {'tw.ntdll.dll': {'precision': 1.0}},
        'file_name': 'ntdll.dll', 'pair_id': 'tw.abc', 'sha256': 'ab' * 32, 'path': '/secret/ntdll.dll',
        'by_condition': {'symbols-hidden': {'precision': 0.7, 'recall': 0.6}}}


def parse(argv):
    return R.build_parser().parse_args(argv)


def fake(calls, *, codes=None):
    def run(argv, env, timeout):
        stage = argv[3] if argv[2] == 'tools.calibration.tier_w' else 'guard'
        calls.append((stage, argv, env))
        body = json.dumps(EVAL if stage == 'evaluate' else {'stage': stage, 'count': 2})
        return (codes or {}).get(stage, 0), 'noise\n' + body
    return run


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    monkeypatch.setattr(R, 'cli_available', lambda: True)
    return {corpus.ROOT_ENV: str(root), 'PATH': '/usr/bin'}, root


def run(argv, environ, calls, runner=None):
    lines = []
    code = R.run_pipeline(parse(argv), environ, runner or fake(calls), out=lines.append)
    return code, '\n'.join(lines)


def test_full_run_is_aggregate_only(env):
    environ, root = env
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t', '--consent-hosts', HOSTS], environ, calls)
    assert code == 0
    for secret in ('ntdll', 'tw.abc', '/secret', 'ab' * 32, 'by_lineage', 'file_name'):
        assert secret not in out
    assert '"precision": 0.9' in out and '"identity_tp": 9' in out and 'symbols-hidden' in out
    assert [c[0] for c in calls] == [*R.STAGE_ORDER, 'guard']
    assert (root / 'tier-w/run-local/tier-w-t/evaluate.log').is_file()
    assert json.loads((root / 'tier-w/reports/tier-w-t.run-local.json').read_text())['tier'] == 'W'


def test_network_stages_skipped_without_consent(env):
    environ, _ = env
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t'], environ, calls)
    ran = [c[0] for c in calls]
    assert code == 0 and not {'catalogue', 'resolve', 'fetch'} & set(ran)
    assert 'no --consent-hosts' in out


def test_child_env_has_no_credentials_and_gets_root(env, monkeypatch):
    environ, root = env
    monkeypatch.setenv('GITHUB_TOKEN', 'x')
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'y')
    calls = []
    run(['--corpus-id', 'tier-w-t'], environ, calls)
    child = calls[0][2]
    assert Path(child[corpus.ROOT_ENV]).resolve() == root.resolve()
    assert 'GITHUB_TOKEN' not in child and 'ANTHROPIC_API_KEY' not in child


@pytest.mark.parametrize('var', ['CI', 'GITHUB_ACTIONS'], ids=['ci', 'actions'])
def test_refuses_on_ci(env, var):
    environ, _ = env
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t'], {**environ, var: 'true'}, calls)
    assert code == 2 and not calls and 'refusing to run in CI' in out


def test_refuses_unset_root():
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t'], {}, calls)
    assert code == 2 and not calls and corpus.ROOT_ENV in out


def test_refuses_root_inside_worktree(monkeypatch):
    calls = []
    monkeypatch.setattr(R, 'cli_available', lambda: True)
    code, out = run(['--corpus-id', 'tier-w-t'], {corpus.ROOT_ENV: str(ROOT / 'tmp-corpus')}, calls)
    assert code == 2 and not calls and 'inside the work tree' in out


def test_refuses_dotted_root(tmp_path, monkeypatch):
    monkeypatch.setattr(R, 'cli_available', lambda: True)
    code, out = run(['--corpus-id', 'tier-w-t'], {corpus.ROOT_ENV: str(tmp_path / '.hidden' / 'c')}, [])
    assert code == 2 and 'dot' in out


@pytest.mark.parametrize('argv', [['--corpus-id', 'tier-w-t', '--consent-hosts', 'example.com'],
                                  ['--corpus-id', 'bad id'], ['--corpus-id', 'tier-w-t', '--only', 'nope']],
                         ids=['host', 'corpus-id', 'stage'])
def test_bad_arguments_refused(env, argv):
    environ, _ = env
    code, out = run(argv, environ, [])
    assert code == 2 and 'refused' in out


def test_blocked_without_cli(env, monkeypatch):
    environ, _ = env
    monkeypatch.setattr(R, 'cli_available', lambda: False)
    code, out = run(['--corpus-id', 'tier-w-t'], environ, [])
    assert code == 3 and 'blocked' in out


def test_stops_at_first_hard_failure(env):
    environ, _ = env
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t'], environ, calls, fake(calls, codes={'symbols': 3}))
    assert code == 3 and calls[-1][0] == 'symbols' and '"stopped"' in out


def test_partial_continues_and_reports_one(env):
    environ, _ = env
    calls = []
    code, _ = run(['--corpus-id', 'tier-w-t'], environ, calls, fake(calls, codes={'run': 1}))
    assert code == 1 and calls[-1][0] == 'guard'


def test_guard_failure_is_partial(env):
    environ, _ = env
    calls = []
    code, _ = run(['--corpus-id', 'tier-w-t'], environ, calls, fake(calls, codes={'guard': 1}))
    assert code == 1


def test_run_stage_gets_backend_options(env):
    environ, _ = env
    calls = []
    run(['--corpus-id', 'tier-w-t', '--python', 'py', '--ghidra-dir', 'gd', '--timeout', '99', '--only', 'run'],
        environ, calls)
    assert calls[0][1][-6:] == ['--python', 'py', '--ghidra-dir', 'gd', '--timeout', '99']


def test_dry_run_executes_nothing(env):
    environ, root = env
    calls = []
    code, out = run(['--corpus-id', 'tier-w-t', '--dry-run'], environ, calls)
    assert code == 0 and not calls and 'dry-run' in out and not root.exists()


@pytest.mark.parametrize('key', ['pair_id', 'file_name', 'by_lineage', 'sha256', 'tags', 'reason'])
def test_unsafe_keys_dropped(key):
    assert R.aggregate_only({key: 1, 'identity_tp': 2}) == {'identity_tp': 2}


def test_strings_and_lists_filtered():
    view = R.aggregate_only({'a': 'ntdll.dll', 'b': 'ok', 'c': [1, 2], 'd': ['x'], 'e': list(range(40))})
    assert view == {'b': 'ok', 'c': [1, 2]}


def test_run_local_has_no_network_or_upload_code():
    text = (ROOT / 'tools/calibration/tier_w/run_local.py').read_text()
    for banned in ('urllib', 'requests', 'socket', 'http.client', 'upload_artifact'):
        assert banned not in text
