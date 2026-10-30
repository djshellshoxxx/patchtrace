"""SPEC-53 GHR-3: `local` symbol mode through backend.run_comparison, against a FAKE ghidriff package.

Mocked-backend evidence only: it shows argv, staging, cache keying, settings and refusal paths. It does not show
that real Ghidriff/Ghidra honours an empty server list (the GHR-5 native matrix does).
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import uuid
from pathlib import Path

import pytest
from pe_builder import PeSpec, build_pe
from test_symbols_staging import G1, G2, make_pdb

from patchtrace import backend, reports
from patchtrace.backend import BackendConfig, _ghidriff_argv, _LocalSymbols, run_comparison
from patchtrace.enrichment.cache import RuntimeFingerprint
from patchtrace.models import Artifact, ComparisonProject

ENGINE = '''
class GhidraDiffEngine:
    def setup_symbol_server(self, symbols_path, level=0, server_urls=None):
        import json, os
        with open(os.environ["FAKE_TRACE"], "a") as f:
            f.write(json.dumps({"urls": server_urls, "symbols": str(symbols_path)}) + "\\n")
'''
MAIN = '''
import json, pathlib, sys
def main():
    from ghidriff.ghidra_diff_engine import GhidraDiffEngine
    GhidraDiffEngine().setup_symbol_server(sys.argv[sys.argv.index("--symbols-path") + 1])
    out = pathlib.Path(sys.argv[sys.argv.index("--output-path") + 1])
    (out / "json").mkdir(parents=True)
    (out / "json" / "old-new.ghidriff.json").write_text(
        json.dumps({"functions": {"added": [], "deleted": [], "modified": []}}))
'''


def pe_with_pdb(guid: str, age: int, name: str) -> bytes:
    return build_pe(PeSpec(rsds=(uuid.UUID(guid).bytes_le, age, f'C:\\build\\{name}')))


@pytest.fixture
def env(tmp_path, monkeypatch):
    ghidra = tmp_path / 'ghidra'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    fake = tmp_path / 'fake' / 'ghidriff'
    fake.mkdir(parents=True)
    (fake / '__init__.py').write_text('')
    (fake / 'ghidra_diff_engine.py').write_text(ENGINE)
    (fake / '__main__.py').write_text(MAIN)
    trace = tmp_path / 'trace.jsonl'
    real_env = backend._environment

    def environment(config, settings_dir=None):
        e = real_env(config, settings_dir)
        e.update(PYTHONPATH=str(tmp_path / 'fake'), FAKE_TRACE=str(trace))
        return e

    real_run = backend.run_process

    def run_fake(argv, **kwargs):
        # Explicit test injection keeps production -I, private cwd and launcher routing intact.
        assert argv[1:4] == ['-I', '-X', 'utf8']
        scratch = Path(kwargs['cwd'])
        assert scratch != ghidra and (scratch / 'ghidra-settings').is_dir()
        if '--pt-mode' in argv:
            start = argv.index('--') + 1
            for side, value in zip(('older', 'newer'), argv[start:start + 2], strict=True):
                snapshot = Path(value)
                assert snapshot == scratch / 'inputs' / side / f'{side}.exe'
                assert snapshot.read_bytes() == (tmp_path / f'{side}.exe').read_bytes()
            bootstrap = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
                         'script=sys.argv.pop(1);sys.argv[0]=script;runpy.run_path(script,run_name="__main__")')
            argv = [*argv[:4], '-c', bootstrap, str(tmp_path / 'fake'), *argv[4:]]
        else:
            index = argv.index('-m')
            argv = [*argv[:index], str(fake / '__main__.py'), *argv[index + 2:]]
        return real_run(argv, **kwargs)

    monkeypatch.setattr(backend, 'run_process', run_fake)
    monkeypatch.setattr(backend, '_environment', environment)
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: {
        'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': 'fake-test-only', 'available': True})
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.3')
    pdbs = tmp_path / 'pdbs'
    pdbs.mkdir()
    arts = []
    for side, age in (('older', 1), ('newer', 2)):
        data = pe_with_pdb(G1, age, 'mod.pdb')
        (tmp_path / f'{side}.exe').write_bytes(data)
        arts.append(Artifact(side=side, name=f'{side}.exe', size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                             relative_path=f'{side}.exe'))
    project = ComparisonProject(name='local-symbols', artifacts=arts)

    def config(**kw):
        return BackendConfig(PYTHON, str(ghidra), symbol_mode='local', symbol_pdb_dirs=(str(pdbs),), **kw)
    return tmp_path, project, pdbs, trace, config


PYTHON = str(Path(sys.executable).resolve())


def run(config, project, root):
    return run_comparison(config, project, root, threading.Event(), lambda _e: None)


def urls(trace):
    return [json.loads(line)['urls'] for line in trace.read_text().splitlines()]


def test_local_run_forces_empty_servers_and_records_provenance(env):
    root, project, pdbs, trace, config = env
    (pdbs / 'mod.pdb').write_bytes(make_pdb(G1, 1))     # matches the older side only (age 1)
    path, run_ = run(config(), project, root)
    assert run_.status == 'completed', run_.error
    assert urls(trace) == [[]]
    s = run_.settings
    assert s['symbol_mode'] == 'local' and s['symbol_policy'] == 'local' and s['symbol_servers'] == []
    assert [x['name'] for x in s['staged_symbols']] == ['mod.pdb'] and len(s['symbol_input_digest']) == 64
    assert any(x['side'] == 'newer' and x['reason'] == 'age_mismatch' for x in s['skipped_symbols'])
    assert (path.parents[2] / 'ptlaunch-report.json').is_file()
    assert not list(Path(backend.tempfile.gettempdir()).glob('patchtrace-ghidra-*/launcher'))  # scratch removed


def test_decoy_pdb_is_not_staged_and_changes_nothing_else(env):
    root, project, pdbs, trace, config = env
    (pdbs / 'mod.pdb').write_bytes(make_pdb(G2, 1))
    _, run_ = run(config(), project, root)
    assert run_.status == 'completed' and run_.settings['staged_symbols'] == []
    assert {x['reason'] for x in run_.settings['skipped_symbols']} == {'guid_mismatch'}
    assert urls(trace) == [[]]


def test_cache_key_follows_staged_pdbs(env, tmp_path):
    root, project, pdbs, trace, config = env
    cache = str(tmp_path / 'cache')
    (pdbs / 'mod.pdb').write_bytes(make_pdb(G1, 1))
    _, first = run(config(cache_dir=cache), project, root)
    _, again = run(config(cache_dir=cache), project, root)
    assert first.status == again.status == 'completed' and 'cache_origin' not in first.settings
    assert 'cache_origin' in again.settings and len(urls(trace)) == 1           # repeat local run is a hit
    (pdbs / 'mod.pdb').write_bytes(make_pdb(G1, 1, pad=1))                      # same identity, other bytes
    _, other = run(config(cache_dir=cache), project, root)
    assert 'cache_origin' not in other.settings and len(urls(trace)) == 2       # different PDB hash: new key
    off = BackendConfig(PYTHON, config().ghidra_dir, cache_dir=cache)
    _, off_run = run(off, project, root)
    assert 'cache_origin' not in off_run.settings and off_run.settings['symbol_policy'] == 'disabled'


def test_incompatible_ghidriff_fails_closed_and_quarantines(env, tmp_path):
    root, project, pdbs, trace, config = env
    (tmp_path / 'fake' / 'ghidriff' / 'ghidra_diff_engine.py').write_text('class GhidraDiffEngine:\n    pass\n')
    path, run_ = run(config(), project, root)
    assert run_.status == 'failed' and run_.error.startswith('PT-SYMBOL-LAUNCHER-INCOMPATIBLE')
    assert path.name.startswith('quarantine-') and not trace.exists()


def test_launcher_that_never_hooks_is_a_mismatch(env, tmp_path):
    root, project, pdbs, trace, config = env
    (tmp_path / 'fake' / 'ghidriff' / '__main__.py').write_text(
        MAIN.replace('GhidraDiffEngine().setup_symbol_server(sys.argv[sys.argv.index("--symbols-path") + 1])', 'pass'))
    path, run_ = run(config(), project, root)
    assert run_.status == 'failed' and run_.error.startswith('PT-SYMBOL-LAUNCHER-MISMATCH')
    assert path.name.startswith('quarantine-')


def test_config_validation_and_argv(env, tmp_path):
    root, project, pdbs, trace, config = env
    base = config()
    assert backend._config_errors(base) == []
    for bad in (dict(symbol_mode='bogus', symbol_pdb_dirs=()), dict(symbol_pdb_dirs=('relative',)),
                dict(symbol_pdb_dirs=(str(tmp_path / 'missing'),)), dict(allow_symbol_downloads=True),
                dict(symbol_mode='off', symbol_pdb_dirs=(str(pdbs),))):
        cfg = BackendConfig(base.python_executable, base.ghidra_dir, **{
            'symbol_mode': 'local', 'symbol_pdb_dirs': (str(pdbs),), **bad})
        assert any('PT-SYMBOL-MODE' in e for e in backend._config_errors(cfg)), bad
    local = _LocalSymbols(Path('/s/ptlaunch.py'), Path('/s/r.json'), Path('/s/symbols'), ('a.pdb',))
    argv = _ghidriff_argv(base, Path('/o'), Path('/n'), tmp_path / 'raw', tmp_path / 'p', tmp_path / 'g', local)
    assert '--no-symbols' not in argv and argv[argv.index('--') + 1:][:2] == [str(Path('/o')), str(Path('/n'))]
    assert argv[argv.index('--pt-mode') + 1] == 'local' and argv[-2:] == ['--symbols-path', str(Path('/s/symbols'))]
    off = _ghidriff_argv(BackendConfig(base.python_executable, base.ghidra_dir), Path('/o'), Path('/n'),
                         tmp_path / 'raw', tmp_path / 'p', tmp_path / 'g')
    assert '--no-symbols' in off and '-m' in off and '--pt-mode' not in off


def test_child_env_for_local_is_not_online(env):
    root, project, pdbs, trace, config = env
    assert backend._is_online(config()) is False
    assert backend._is_online(BackendConfig('x', 'y', allow_symbol_downloads=True)) is True


def test_fingerprint_local_needs_digest():
    fields = dict(engine='ghidriff', ghidriff_revision='r', ghidra_version='12', pyghidra_version='3', python_version='3.12',
                  java_version='21', platform_arch='x', loader_options='default', analysis_options='symbols',
                  adapter_version='a', symbol_policy='local')
    assert not RuntimeFingerprint(**fields, symbol_input_digest='none').eligible()[0]
    assert RuntimeFingerprint(**fields, symbol_input_digest='a' * 64).eligible()[0]
    assert not RuntimeFingerprint(**dict(fields, symbol_policy='online'), symbol_input_digest='a' * 64).eligible()[0]


def test_report_exports_only_safe_symbol_fields():
    good = {'symbol_mode': 'local', 'symbol_input_digest': 'a' * 64, 'launcher_version': '0.1.0',
            'staged_symbols': [{'name': 'mod.pdb', 'guid_age': '1' * 33, 'sha256': 'b' * 64}],
            'skipped_symbols': [{'name': 'x', 'side': 'older', 'reason': 'guid_mismatch'}]}
    out = reports._safe_settings(good)
    assert out['symbol_mode'] == 'local' and out['staged_symbols'][0]['name'] == 'mod.pdb'
    assert 'skipped_symbols' not in out
    bad = reports._safe_settings(dict(good, symbol_mode='C:\\x', symbol_input_digest='zz',
                                      staged_symbols=[{'name': '../x', 'guid_age': '1' * 33, 'sha256': 'b' * 64}]))
    assert 'symbol_mode' not in bad and 'symbol_input_digest' not in bad and 'staged_symbols' not in bad
