"""SPEC-10b §10.1: committed BinExport goldens carry complete provenance and pass the full pipeline.

Synthetic goldens only (no plugin output yet, C3-7 open): these prove format/pair/basis handling, not live
compatibility with Ghidra/IDA exports.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from patchtrace.persistence import strict_json
from patchtrace.sample import synthetic_pe
from patchtrace.secondary.binexport_identity import PeLayout, accept_pair
from patchtrace.secondary.binexport_limits import BinExportLimits, Budget
from patchtrace.secondary.binexport_pipeline import inspect_binexport
from patchtrace.secondary.contracts import SecondaryError

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / 'tests' / 'fixtures' / 'binexport'
REQUIRED = {'file', 'file_sha256', 'source_sha256', 'source_origin', 'tool', 'options', 'produced_on',
            'produced_by', 'license', 'architecture_name', 'observed_executable_id', 'live_compatibility_evidence'}


def records() -> dict[str, dict]:
    doc = strict_json((DIR / 'PROVENANCE.json').read_text(encoding='utf-8'))
    assert doc['contract'] == 'binexport-fixture-provenance/1'
    return {r['file']: r for r in doc['fixtures']}


def test_every_golden_has_complete_matching_provenance():
    recs = records()
    files = sorted(p.name for p in DIR.glob('*.BinExport'))
    assert files and files == sorted(recs)
    total = 0
    for name, rec in recs.items():
        assert REQUIRED <= set(rec), name
        data = (DIR / name).read_bytes()
        total += len(data)
        assert len(data) <= 256 * 1024 and hashlib.sha256(data).hexdigest() == rec['file_sha256']
        if rec['id_binding'] == 'sha256':
            assert rec['observed_executable_id'] == rec['source_sha256']
        else:
            assert len(rec['observed_executable_id']) == 32
        assert rec['live_compatibility_evidence'] is False and 'NOT a BinExport plugin' in rec['tool']
    assert total <= 2 * 1024 * 1024


def test_goldens_are_reproducible():
    spec = importlib.util.spec_from_file_location('gen_fixtures', ROOT / 'tools' / 'gen_binexport_fixtures.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.main(['--check']) == 0
    for rec in gen.build()[1]:
        variant = int(rec['source_origin'].split('(')[1].split(')')[0])
        assert hashlib.sha256(synthetic_pe(variant)).hexdigest() == rec['source_sha256']


@pytest.mark.parametrize('name', sorted(records()))
def test_goldens_through_pipeline(tmp_path, name):
    rec = records()[name]
    layout = PeLayout(rec['image_base'], rec['size_of_image'], 'IMAGE_FILE_MACHINE_AMD64')
    kw = dict(artifact_sha256=rec['source_sha256'], role='older', limits=BinExportLimits(), budget=Budget(),
              pe_layout=layout)
    if rec['id_binding'] != 'sha256':
        with pytest.raises(SecondaryError) as info:
            inspect_binexport(DIR / name, tmp_path / 'a', **kw)
        assert info.value.reason == f'executable_id_{rec["id_binding"]}'
        kw['accept_unbound'] = True
    s = inspect_binexport(DIR / name, tmp_path / 'b', **kw)
    assert (s.id_binding, s.address_basis, len(s.function_addresses)) == \
        (rec['id_binding'], rec['address_basis'], rec['functions'])
    assert s.file_sha256 == rec['file_sha256'] and s.warnings == ()


def test_golden_pair_and_mixed_basis(tmp_path):
    recs = records()

    def accepted(name, role):
        rec = recs[name]
        s = inspect_binexport(DIR / name, tmp_path / f'{name}-{role}', artifact_sha256=rec['source_sha256'],
                              role=role, limits=BinExportLimits(), budget=Budget(),
                              pe_layout=PeLayout(rec['image_base'], rec['size_of_image']))
        return type('Accepted', (), {'summary': s})()
    older = accepted('synthetic-older.BinExport', 'older')
    newer = accepted('synthetic-newer.BinExport', 'newer')
    older_sha, newer_sha = recs['synthetic-older.BinExport']['source_sha256'], \
        recs['synthetic-newer.BinExport']['source_sha256']
    accept_pair(older, newer, older_sha, newer_sha)
    with pytest.raises(SecondaryError) as info:
        accept_pair(older, accepted('synthetic-newer-rva.BinExport', 'newer'), older_sha, newer_sha)
    assert info.value.reason == 'address_basis_mixed'

