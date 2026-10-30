"""Unit-only orchestration evidence using substitute builds, never native acceptance or target execution."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r import research_build as R
from tools.calibration.tier_r.build import BuildError


@pytest.fixture
def substituted_factory(monkeypatch, tmp_path):
    """Keep real BaseSource specs and label persistence; substitute every native/tool/label operation."""
    specs = []
    finalized = []
    suite = SimpleNamespace(suite='unit-pilot', project='defined', pairs=[
        SimpleNamespace(old='v1', new='v2', intent='Unit fixture only', truth=())])
    bases = {v: F.BaseSource(project='defined', lineage='L-unit', family='synthetic',
                            source={'suite': 'unit/defined', 'version': v, 'license_spdx': 'MIT'},
                            root=tmp_path / v, files=('r1.c',), output='defined.dll',
                            cflags=('-fno-builtin',), std='c11', tag=v) for v in ('v1', 'v2')}
    chain = SimpleNamespace(profile_status=lambda profile: None, describe=lambda: {'unit_only': True})
    monkeypatch.setattr(R, 'probe', lambda: chain)
    monkeypatch.setattr(F, 'suite_bases', lambda path: (suite, bases))

    class Session:
        def __init__(self, tools, store):
            self.store = store

        def build(self, spec):
            specs.append(spec)
            if spec.profile == 'mingw-gcc':
                raise BuildError('unit substitute: compiler failed')
            return SimpleNamespace(spec=spec)

        def side(self, result, root):
            return SimpleNamespace(build=result)

    monkeypatch.setattr(F, 'Session', Session)
    monkeypatch.setattr(R, 'label_authored', lambda *args: ([], []))

    def finalize(**kwargs):
        finalized.append(kwargs)
        return {'pair_id': kwargs['pid'], 'digest_sha256': 'd' * 64,
                'older': {'sha256': 'a' * 64}, 'newer': {'sha256': 'b' * 64},
                'summary': {'disagreements': len(kwargs['case']['problems'])}}

    monkeypatch.setattr(F, 'finalize', finalize)
    return SimpleNamespace(specs=specs, finalized=finalized, chain=chain)


def test_profile_opt_ids_preserve_all_cells_without_overwrite(substituted_factory, tmp_path):
    receipt = R.build_pilot(tmp_path / 'store', profiles=('msvc-free', 'mingw-clang'), opts=('O0', 'O2'))
    entries = receipt['entries']
    assert len(entries) == 4 and len({e['pair_id'] for e in entries}) == 4
    assert receipt['status'] == 'built'
    for entry in entries:
        assert entry['profile'] in entry['pair_id'] and entry['opt'] in entry['pair_id']
        saved = json.loads(Path(entry['labels_path']).read_text())
        assert saved['pair_id'] == entry['pair_id']
    assert len(list((tmp_path / 'store' / 'labels').glob('*.json'))) == 4
    assert {spec.opt for spec in substituted_factory.specs} == {'O0', 'O2'}
    assert {spec.profile for spec in substituted_factory.specs} == {'msvc-free', 'mingw-clang'}
    assert all(spec.cflags == ('-fno-builtin',) for spec in substituted_factory.specs), 'no new flags'
    assert any('export' in note.lower() for e in entries for note in e['notes'])
    assert all(call['stratum'] == 'authored' and call['label_source'] == 'authored-truth'
               for call in substituted_factory.finalized)
    json.dumps(receipt)


def test_compile_failure_is_blocked_and_later_configurations_continue(substituted_factory, tmp_path):
    receipt = R.build_pilot(tmp_path / 'store', profiles=('mingw-gcc', 'msvc-free'), opts=('O2',))
    assert receipt['status'] == 'partial'
    first, second = receipt['entries']
    assert first['status'] == 'blocked' and first['stage'] == 'build'
    assert first['error_type'] == 'BuildError' and 'compiler failed' in first['reason']
    assert 'labels_path' not in first
    assert second['status'] == 'built' and Path(second['labels_path']).is_file()


def test_unavailable_toolchain_does_not_attempt_build(substituted_factory, tmp_path):
    substituted_factory.chain.profile_status = lambda profile: 'unit substitute: compiler unavailable'
    receipt = R.build_pilot(tmp_path / 'store', profiles=('msvc-free',), opts=('O2',))
    assert receipt['status'] == 'blocked'
    assert receipt['entries'][0]['stage'] == 'toolchain'
    assert substituted_factory.specs == []


@pytest.mark.parametrize(('profiles', 'opts'), [
    (('unknown',), ('O2',)), (('msvc-free',), ('Ofast',)), ((), ('O2',)),
    (('msvc-free',), ()), (('msvc-free', 'msvc-free'), ('O2',))])
def test_invalid_configuration_fails_before_probing(monkeypatch, tmp_path, profiles, opts):
    monkeypatch.setattr(R, 'probe', lambda: pytest.fail('invalid input reached tool probing'))
    with pytest.raises(ValueError):
        R.build_pilot(tmp_path / 'store', profiles=profiles, opts=opts)


def test_relative_and_repository_stores_rejected_before_probing(monkeypatch):
    monkeypatch.setattr(R, 'probe', lambda: pytest.fail('unsafe store reached tool probing'))
    for store in (Path('relative-store'), R.REPO / 'generated-test-store'):
        with pytest.raises(ValueError):
            R.build_pilot(store, profiles=('msvc-free',), opts=('O2',))


def test_authored_disagreements_remain_findings_not_passes(substituted_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(R, 'label_authored', lambda *args: ([], ['unit-only body disagreement']))
    receipt = R.build_pilot(tmp_path / 'store', profiles=('msvc-free',), opts=('O2',))
    assert receipt['status'] == 'findings'
    assert receipt['entries'][0]['status'] == 'findings'
    assert receipt['entries'][0]['disagreements'] == 1
    assert substituted_factory.finalized[0]['case']['problems'] == ['unit-only body disagreement']


def test_cli_writes_json_receipt_and_reports_blocked(substituted_factory, tmp_path, capsys):
    output = tmp_path / 'receipt.json'
    code = R.main(['--store', str(tmp_path / 'store'), '--output', str(output),
                   '--profiles', 'mingw-gcc', '--opts', 'O2'])
    assert code == 3
    saved = json.loads(output.read_text())
    assert saved['status'] == 'blocked'
    assert json.loads(capsys.readouterr().out) == saved
