"""SPEC-53 GHR-2: the Ghidriff launcher and its handshake validator, against a FAKE `ghidriff` package.

Hermetic: proves the hook wrapping, report and refusal behaviour only. It is not evidence that the pinned real
Ghidriff or Ghidra honours an empty server list (that is the GHR-5 native matrix).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace.ghidriff_launch import validate
from patchtrace.symbols.modes import SymbolError

FAKE_ENGINE = '''
class GhidraDiffEngine:
    def setup_symbol_server(self, symbols_path, level=0, server_urls=None):
        import json, os
        with open(os.environ["FAKE_TRACE"], "a") as f:
            f.write(json.dumps({"urls": server_urls}) + "\\n")
'''
FAKE_MAIN = '''
import sys
def main():
    from ghidriff.ghidra_diff_engine import GhidraDiffEngine
    GhidraDiffEngine().setup_symbol_server("syms")
    print("fake ghidriff args", sys.argv[1:])
    return 3 if "--fail" in sys.argv else 0
'''


def fake_ghidriff(root: Path, *, engine: str = FAKE_ENGINE, main: str = FAKE_MAIN) -> Path:
    pkg = root / 'fake' / 'ghidriff'
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / '__init__.py').write_text('')
    (pkg / 'ghidra_diff_engine.py').write_text(engine)
    (pkg / '__main__.py').write_text(main)
    return root / 'fake'


@pytest.fixture
def launch(tmp_path):
    script = validate.write_private_copy(tmp_path)
    trace = tmp_path / 'trace.jsonl'

    def run(mode, *, fake=None, staged=(), extra=(), xdg=True, tail=('a.bin', 'b.bin')):
        fake = fake or fake_ghidriff(tmp_path)
        report = tmp_path / f'report-{mode}.json'
        env = {k: v for k, v in os.environ.items() if k != 'XDG_CONFIG_HOME'}
        env.update(PYTHONPATH=str(fake), FAKE_TRACE=str(trace))
        if xdg:
            env['XDG_CONFIG_HOME'] = str(tmp_path / 'xdg')
        argv = [sys.executable, str(script), '--pt-mode', mode, '--pt-report', str(report)]
        for name in staged:
            argv += ['--pt-staged', name]
        proc = subprocess.run([*argv, *extra, '--', *tail], env=env, capture_output=True, text=True, timeout=60)
        return proc, report, trace
    return run


def urls(trace: Path):
    return [json.loads(line)['urls'] for line in trace.read_text().splitlines()]


def test_local_forces_empty_server_list_and_reports(launch):
    proc, report, trace = launch('local', staged=('foo.pdb',))
    assert proc.returncode == 0, proc.stderr
    assert urls(trace) == [[]]
    assert proc.stdout.splitlines()[0] == 'PT-LAUNCHER/1 mode=local servers=0'
    doc = validate.validate_run('local', report, proc.stdout, ('foo.pdb',))
    assert doc['setup_calls'] == 1 and doc['server_urls_forced_empty'] is True and doc['pdbs_staged'] == ['foo.pdb']


def test_local_without_hook_exits_78_and_never_runs_upstream(launch, tmp_path):
    fake = fake_ghidriff(tmp_path, engine='class GhidraDiffEngine:\n    pass\n')
    proc, report, trace = launch('local', fake=fake)
    assert proc.returncode == 78 and 'PT-SYMBOL-LAUNCHER-INCOMPATIBLE' in proc.stderr
    assert not trace.exists() and not report.exists()
    with pytest.raises(SymbolError) as exc:
        validate.check_exit(proc.returncode, proc.stderr)
    assert exc.value.code == 'PT-SYMBOL-LAUNCHER-INCOMPATIBLE'


def test_local_with_changed_hook_signature_is_refused(launch, tmp_path):
    fake = fake_ghidriff(tmp_path, engine='class GhidraDiffEngine:\n    def setup_symbol_server(self, path): pass\n')
    assert launch('local', fake=fake)[0].returncode == 78


def test_requires_per_run_settings_directory(launch):
    proc, _, trace = launch('local', xdg=False)
    assert proc.returncode == 78 and not trace.exists()


def test_online_needs_explicit_flag_and_does_not_patch(launch):
    proc, _, trace = launch('online')
    assert proc.returncode == 64 and 'PT-SYMBOL-NETWORK-REFUSED' in proc.stderr and not trace.exists()
    proc, report, trace = launch('online', extra=('--pt-allow-servers',))
    assert proc.returncode == 0 and urls(trace) == [None]
    assert json.loads(report.read_text())['server_urls_forced_empty'] is False


def test_upstream_exit_status_passes_through_and_report_still_written(launch):
    proc, report, _ = launch('local', tail=('--fail',))
    assert proc.returncode == 3 and report.is_file()


@pytest.mark.parametrize('argv', [[], ['--pt-mode', 'bogus', '--pt-report', 'x', '--', 'a'], ['--pt-mode', 'off'],
                                  ['--pt-mode', 'off', '--pt-report', 'x']])
def test_usage_errors(tmp_path, argv):
    script = validate.write_private_copy(tmp_path)
    proc = subprocess.run([sys.executable, str(script), *argv], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 64


def test_validator_rejects_every_mismatch(tmp_path):
    good = {'contract': 'ptlaunch/1', 'mode': 'local', 'server_urls_forced_empty': True, 'setup_calls': 1,
            'pdbs_staged': ['a.pdb']}
    path = tmp_path / 'r.json'

    def check(doc, mode='local', staged=('a.pdb',), log=''):
        path.write_text(json.dumps(doc))
        return validate.validate_run(mode, path, log, staged)

    assert check(good)['setup_calls'] == 1
    for bad in (dict(good, contract='ptlaunch/2'), dict(good, mode='off'), dict(good, setup_calls=0),
                dict(good, server_urls_forced_empty=False), dict(good, pdbs_staged=[])):
        with pytest.raises(SymbolError) as exc:
            check(bad)
        assert exc.value.code == 'PT-SYMBOL-LAUNCHER-MISMATCH'
    with pytest.raises(SymbolError):
        check(good, log='PT-LAUNCHER/1 mode=off servers=0\n')
    with pytest.raises(SymbolError):
        check(dict(good, mode='off'), mode='off')            # off must not patch the hook
    with pytest.raises(SymbolError):
        validate.validate_run('local', tmp_path / 'missing.json', '', ())
    path.write_text('{' * 10)
    with pytest.raises(SymbolError):
        validate.validate_run('local', path, '', ())


def test_packaged_script_digest_is_stable_text():
    assert validate.script_sha256() == validate.script_sha256() and b'\r\n' not in validate.script_bytes()
