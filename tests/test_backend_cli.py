"""BUNDLE B7: `patchtrace backend status|verify|selftest|diagnose` (enrichment-cli/1 envelope, exit 0/2/3/4/5).

Hermetic: a tiny synthetic bundle; `selftest` replaces ONLY `backend.run_comparison` with a fake that writes a
Ghidriff-shaped JSON. That is a mocked-backend test, not live evidence that the real bundle runs Ghidriff.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess

import pytest
from test_backend_bundle import make_bundle

from patchtrace import backend, cli
from patchtrace.backend_bundle import find_bundled_runtime
from patchtrace.models import AnalysisRun, JobEvent, uid
from patchtrace.sample import synthetic_pe

HOST = 'windows' if os.name == 'nt' else 'linux'
PROBE = {'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': '3.0.2', 'available': True}


@pytest.fixture
def app(tmp_path, monkeypatch):
    exe = tmp_path / 'App Dir é'
    exe.mkdir()
    make_bundle(exe, HOST)
    work = tmp_path / 'user work'
    monkeypatch.delenv('PATCHTRACE_BUNDLE_DIR', raising=False)
    # `status` and `verify` must never start a process
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('a process was started'))
    return exe, work


def run(capsys, *argv):
    code = cli.main(['backend', *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_json(capsys, app, action, *extra):
    exe, work = app
    code, out, _err = run(capsys, action, '--json', '--bundle-dir', str(exe), '--work-dir', str(work), *extra)
    return code, json.loads(out)


# ---- status ---------------------------------------------------------------------------------

def test_status_ok_envelope(app, capsys):
    exe, _ = app
    code, doc = run_json(capsys, app, 'status')
    ref = find_bundled_runtime(exe, host=HOST)
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'backend status'
    assert doc['status'] == 'complete' and doc['warnings'] == []
    bundle = doc['result']['bundle']
    assert bundle['found'] and bundle['runtime_id'] == ref.runtime_id and bundle['fast_check'] == 'ok'
    assert bundle['manifest_sha256'] == ref.manifest_sha256 and bundle['platform'] == HOST
    assert bundle['versions']['ghidra'] == '12.0.4' and bundle['files'] == 5 and bundle['full_verified'] is False
    assert bundle['problems'] == [] and 'not who published' in bundle['authenticity']


def test_status_text_output(app, capsys):
    exe, work = app
    code, out, _ = run(capsys, 'status', '--bundle-dir', str(exe), '--work-dir', str(work))
    assert code == 0 and out.startswith('Bundled runtime ghidra-12.0.4')
    assert out.splitlines()[0].endswith(': fast check ok') and 'full hash verification: not yet run' in out


def test_status_without_bundle_is_no_result(app, capsys, tmp_path):
    empty = tmp_path / 'empty'
    empty.mkdir()
    code, out, _ = run(capsys, 'status', '--json', '--bundle-dir', str(empty))
    doc = json.loads(out)
    assert code == 4 and doc['status'] == 'no-results' and doc['result'] == {'bundle': {'found': False}}


@pytest.mark.parametrize('damage, expected', [('extra', 'PT-BUNDLE-EXTRA'), ('size', 'PT-BUNDLE-SIZE'),
                                              ('manifest', 'PT-BUNDLE-MANIFEST')])
def test_status_bundle_problem_exits_5(app, capsys, damage, expected):
    exe, _ = app
    if damage == 'extra':
        (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    elif damage == 'size':
        (exe / 'backend' / 'payload' / 'ghidra/docs/a.txt').write_bytes(b'tiny')
    else:
        (exe / 'backend' / 'manifest.json').write_text('{oops', encoding='utf-8')
    code, doc = run_json(capsys, app, 'status')
    assert code == 5 and doc['status'] == 'failed'
    assert doc['result']['bundle']['problems'][0]['code'] == expected
    assert doc['result']['bundle']['fast_check'] == 'failed'


# ---- verify ---------------------------------------------------------------------------------

def test_verify_fast_ok(app, capsys):
    code, doc = run_json(capsys, app, 'verify')
    assert code == 0 and doc['result']['verify'] == {
        'mode': 'fast', 'ok': True, 'runtime_id': doc['result']['verify']['runtime_id'], 'files': 5,
        'bytes': doc['result']['verify']['bytes'], 'problems': [], 'truncated': False}


def test_verify_full_ok_records_marker_that_status_reports(app, capsys):
    exe, work = app
    code, doc = run_json(capsys, app, 'verify', '--full')
    assert code == 0 and doc['result']['verify']['mode'] == 'full'
    ref = find_bundled_runtime(exe, host=HOST)
    assert (work / f'bundle-verified-{ref.manifest_sha256}.json').is_file()
    code, doc = run_json(capsys, app, 'status')
    assert doc['result']['bundle']['full_verified'] is True


def test_verify_full_detects_same_size_corruption(app, capsys):
    exe, work = app
    target = exe / 'backend' / 'payload' / 'ghidra/docs/a.txt'
    target.write_bytes(b'9876543210')  # same size as the original, different bytes
    code, doc = run_json(capsys, app, 'verify', '--full')
    assert code == 5 and doc['result']['verify']['problems'] == [
        {'code': 'PT-BUNDLE-HASH', 'path': 'ghidra/docs/a.txt'}]
    assert not list(work.glob('bundle-verified-*'))  # a failed full check records no marker
    code, _doc = run_json(capsys, app, 'verify')  # the fast check cannot see it, by design
    assert code == 0


def test_verify_full_progress_goes_to_stderr_only(app, capsys):
    exe, work = app
    code, out, err = run(capsys, 'verify', '--full', '--json', '--bundle-dir', str(exe), '--work-dir', str(work))
    json.loads(out)  # stdout is exactly one JSON document
    assert code == 0 and 'Verifying 5 files... 100%' in err


def test_verify_without_bundle_is_no_result(capsys, tmp_path):
    code, out, _ = run(capsys, 'verify', '--json', '--bundle-dir', str(tmp_path))
    assert code == 4 and json.loads(out)['status'] == 'no-results'


# ---- usage errors (exit 2, envelope on failure) ---------------------------------------------

@pytest.mark.parametrize('argv', [['selftest'], ['selftest', '--older', 'a', '--newer', 'b'], ['nonsense'], []],
                         ids=['no-options', 'no-expectation', 'unknown-action', 'no-action'])
def test_usage_errors_exit_2(capsys, argv):
    code, _out, err = run(capsys, *argv)
    assert code == 2 and err.startswith('error:')


# ---- selftest (mocked run_comparison) -------------------------------------------------------

@pytest.fixture
def pair(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return older, newer


@pytest.fixture
def fake_engine(monkeypatch):
    seen = {}

    def install(status='completed', functions=('patched_fn',), error=None):
        def fake(config, project, root, cancel, on_event):
            seen['config'], seen['root'] = config, root
            if status != 'completed':
                return root / 'runs' / 'quarantine-x', AnalysisRun(status=status, error=error)
            run_id = uid()
            raw = root / 'runs' / run_id / 'raw' / 'result.ghidriff.json'
            raw.parent.mkdir(parents=True)
            sha = {a.side: a.sha256 for a in project.artifacts}
            raw.write_text(json.dumps({
                'old_meta': {'SHA256': sha['older']}, 'new_meta': {'SHA256': sha['newer']},
                'functions': {'added': [{'name': n, 'address': '1000'} for n in functions],
                              'deleted': [], 'modified': []}}), encoding='utf-8')
            on_event(JobEvent(run_id=run_id, stage='analysis', message='fake engine', progress=0.5))
            return raw, AnalysisRun(id=run_id, status='completed', raw_path=raw.relative_to(root).as_posix(),
                                    raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
        monkeypatch.setattr(backend, 'run_comparison', fake)
        return seen
    return install


def selftest(capsys, app, pair, *extra, functions=('patched_fn',)):
    exe, work = app
    older, newer = pair
    args = ['selftest', '--json', '--bundle-dir', str(exe), '--work-dir', str(work),
            '--older', str(older), '--newer', str(newer)]
    for name in functions:
        args += ['--expect-function', name]
    code, out, err = run(capsys, *args, *extra)
    return code, json.loads(out), err


def test_selftest_passes_with_bundle_config_and_no_cache(app, pair, capsys, fake_engine):
    seen = fake_engine()
    code, doc, err = selftest(capsys, app, pair)
    exe, work = app
    ref = find_bundled_runtime(exe, host=HOST)
    assert code == 0 and doc['status'] == 'complete', (doc, err)
    assert doc['result']['expected_functions'] == {'patched_fn': True} and doc['result']['matches'] == 1
    config = seen['config']
    assert config.bundle and config.restrict_env and config.allow_symbol_downloads is False
    assert config.python_executable == str(ref.python) and config.java_home == str(ref.java_home)
    assert config.cache_dir == ''  # a cached result must never stand in for a real run
    assert str(seen['root']).startswith(str(work.resolve()))  # per-user work dir, never the install dir
    assert 'selftest: analysis: fake engine' in err


def test_selftest_expectation_not_met_exits_4(app, pair, capsys, fake_engine):
    fake_engine(functions=('other_fn',))
    code, doc, _ = selftest(capsys, app, pair, functions=('patched_fn', 'other_fn'))
    assert code == 4 and doc['status'] == 'no-results'
    assert doc['result']['expected_functions'] == {'patched_fn': False, 'other_fn': True}


def test_selftest_backend_failure_exits_3(app, pair, capsys, fake_engine):
    fake_engine(status='failed', error='PT-BACKEND: boom')
    code, doc, _ = selftest(capsys, app, pair)
    assert code == 3 and doc['status'] == 'failed' and 'PT-BACKEND: boom' in doc['result']['error']


def test_selftest_bad_raw_output_is_quarantined_exit_3(app, pair, capsys, monkeypatch):
    def fake(config, project, root, cancel, on_event):
        run_id = uid()
        raw = root / 'runs' / run_id / 'raw' / 'bad.json'
        raw.parent.mkdir(parents=True)
        raw.write_bytes(b'{"unexpected":"fixture"}')
        return raw, AnalysisRun(id=run_id, status='completed', raw_path=raw.relative_to(root).as_posix(),
                                raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
    monkeypatch.setattr(backend, 'run_comparison', fake)
    code, doc, _ = selftest(capsys, app, pair)
    assert code == 3 and 'PT-SCHEMA' in doc['result']['error']


def test_selftest_bundle_problem_exits_5_without_running(app, pair, capsys, monkeypatch):
    monkeypatch.setattr(backend, 'run_comparison', lambda *a: pytest.fail('must not run on a broken bundle'))
    (app[0] / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    code, doc, _ = selftest(capsys, app, pair)
    assert code == 5 and doc['result']['bundle']['problems'][0]['code'] == 'PT-BUNDLE-EXTRA'


def test_selftest_identical_artifacts_exit_2(app, pair, capsys, fake_engine):
    fake_engine()
    older, _ = pair
    code, doc, err = selftest(capsys, app, (older, older))
    assert code == 2 and 'identical' in doc['error']


def test_selftest_work_dir_inside_install_is_refused(app, pair, capsys, fake_engine):
    fake_engine()
    exe, _ = app
    older, newer = pair
    code, out, _ = run(capsys, 'selftest', '--json', '--bundle-dir', str(exe),
                       '--work-dir', str(exe / 'backend' / 'work'), '--older', str(older),
                       '--newer', str(newer), '--expect-function', 'x')
    assert code == 2 and 'PT-BUNDLE-WORKDIR' in json.loads(out)['error']


def test_selftest_project_dir_must_be_new(app, pair, capsys, fake_engine, tmp_path):
    fake_engine()
    occupied = tmp_path / 'occupied'
    occupied.mkdir()
    (occupied / 'file').write_text('x')
    code, doc, _ = selftest(capsys, app, pair, '--project-dir', str(occupied))
    assert code == 2 and 'new or empty' in doc['error']


@pytest.mark.parametrize('timeout', ['9', '86401'])
def test_selftest_timeout_range(app, pair, capsys, timeout):
    code, doc, _ = selftest(capsys, app, pair, '--timeout', timeout)
    assert code == 2 and '--timeout' in doc['error']


def test_selftest_without_bundle_exits_2(pair, capsys, tmp_path):
    older, newer = pair
    code, _out, err = run(capsys, 'selftest', '--bundle-dir', str(tmp_path), '--older', str(older),
                          '--newer', str(newer), '--expect-function', 'x')
    assert code == 2 and 'no bundled runtime' in err


def test_selftest_missing_input_exits_2(app, capsys, tmp_path):
    exe, work = app
    code, _out, err = run(capsys, 'selftest', '--bundle-dir', str(exe), '--work-dir', str(work),
                          '--older', str(tmp_path / 'nope'), '--newer', str(tmp_path / 'nope2'),
                          '--expect-function', 'x')
    assert code == 2 and '--older must be an existing file' in err


# ---- diagnose -------------------------------------------------------------------------------

@pytest.fixture
def probed(monkeypatch):
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: PROBE)
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')


def test_diagnose_ok_has_real_bundle_line(app, capsys, probed):
    exe, _ = app
    find_bundled_runtime(exe, host=HOST).python.chmod(0o755)
    code, doc = run_json(capsys, app, 'diagnose')
    assert code == 0 and doc['result']['problems'] == []
    assert any(line.endswith(': fast check ok') and line.startswith('Bundled runtime ') for line in doc['result']['lines'])


def test_diagnose_backend_problem_exits_3(app, capsys, monkeypatch):
    exe, _ = app
    find_bundled_runtime(exe, host=HOST).python.chmod(0o755)

    def broken(_config):
        raise RuntimeError('PT-BACKEND: install ghidriff in the selected Python 3.10+ environment')
    monkeypatch.setattr(backend, '_probe_backend', broken)
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')
    code, doc = run_json(capsys, app, 'diagnose')
    assert code == 3 and doc['status'] == 'failed' and doc['result']['problems']


def test_diagnose_bundle_problem_exits_5(app, capsys, probed):
    exe, _ = app
    (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    code, doc = run_json(capsys, app, 'diagnose')
    assert code == 5 and doc['result']['bundle']['problems'][0]['code'] == 'PT-BUNDLE-EXTRA'


def test_diagnose_without_bundle_exits_2(capsys, tmp_path):
    code, out, _ = run(capsys, 'diagnose', '--json', '--bundle-dir', str(tmp_path))
    assert code == 2 and json.loads(out)['status'] == 'failed'


def test_cli_help_lists_backend(capsys):
    with pytest.raises(SystemExit) as stop:
        cli._parser().parse_args(['backend', '--help'])
    assert stop.value.code == 0
    out = capsys.readouterr().out
    for action in ('status', 'verify', 'selftest', 'diagnose'):
        assert action in out
