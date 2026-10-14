"""SPEC-33 s12 / decision O1: the repository guard fails on Microsoft images, PDBs (except allow-listed self-made
fixtures), Tier-W manifests, Tier-W derived documents and Tier-W labels. Synthetic files only."""
from __future__ import annotations

import json
import shutil
import struct
import sys

from pe_builder import PeSpec, build_pe
from tier_w_builders import ROOT, TIER_W_FIXTURES, build_msf

sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_w.guard import SELF_MADE, allowed_pdbs, tier_w_problems  # noqa: E402


def write(tree, rel, data):
    path = tree / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    return rel


def test_guard_rules(tmp_path, monkeypatch):
    monkeypatch.setenv(corpus.ROOT_ENV, str(tmp_path / 'outside'))
    tree = tmp_path / 'tree'
    ms_pe = build_pe(PeSpec(overlay='Microsoft Corporation'.encode('utf-16-le')))
    win_pdb_pe = build_pe(PeSpec(rsds=(b'\x11' * 16, 1, 'D:\\os\\obj\\ntkrnlmp.pdb')))
    clean_pe = build_pe(PeSpec(rsds=(b'\x22' * 16, 1, 'tiny.pdb')))
    files = {
        'docs/a.pdb': build_msf([b'', b'']),
        'tests/fixtures/tier_w/other.pdb': build_msf([b'']),
        'notes/b.pdb': b'not really a pdb',
        'tests/fixtures/ms.exe': ms_pe,
        'tests/fixtures/k.exe': win_pdb_pe,
        'tests/fixtures/clean.exe': clean_pe,
        'misc/ntdll.dll': b'anything',
        'm.json': {'contract': 'calibration-corpus/1', 'binaries': [{'tier': 'W'}]},
        'r.json': {'contract': 'calibration-corpus/1', 'binaries': [{'tier': 'R'}]},
        's.json': {'contract': 'symbol-map/1', 'tier': 'W', 'symbols': []},
        't.json': {'contract': 'symbol-map/1', 'tier': 'test', 'symbols': []},
        'l.jsonl': b'{"pair": "tw.afd.sys.0123456789", "match_id": "m", "A": "same", "source": "symbol-derived"}\n',
        'ok.jsonl': b'{"pair": "p001", "match_id": "m", "A": "same", "source": "synthetic-exact"}\n',
        'bad.json': b'{not json',
    }
    rels = [write(tree, rel, data) for rel, data in files.items()]
    problems = tier_w_problems(tree, rels)
    flagged = {p.split(':', 1)[0] for p in problems}
    assert flagged == {'docs/a.pdb', 'tests/fixtures/tier_w/other.pdb', 'notes/b.pdb', 'tests/fixtures/ms.exe',
                       'tests/fixtures/k.exe', 'misc/ntdll.dll', 'm.json', 's.json', 'l.jsonl'}
    assert flagged <= {p.split(':', 1)[0] for p in corpus.guard(tree, None, files=rels)}  # hooked into corpus


def test_self_made_pdb_allow_list(tmp_path, monkeypatch):
    monkeypatch.setenv(corpus.ROOT_ENV, str(tmp_path / 'outside'))
    tree = tmp_path / 'tree'
    target = tree / 'tests' / 'fixtures' / 'tier_w'
    target.mkdir(parents=True)
    for name in ('SELF_MADE.json', 'tiny_v1.pdb', 'tiny_v1.pe'):
        shutil.copyfile(TIER_W_FIXTURES / name, target / name)
    rels = ['tests/fixtures/tier_w/tiny_v1.pdb', 'tests/fixtures/tier_w/tiny_v1.pe', SELF_MADE]
    assert tier_w_problems(tree, rels) == []
    data = bytearray((target / 'tiny_v1.pdb').read_bytes())
    struct.pack_into('<I', data, len(data) - 4, 0xDEADBEEF)   # any change breaks the SHA-256 allow-list entry
    (target / 'tiny_v1.pdb').write_bytes(bytes(data))
    assert [p.split(':', 1)[0] for p in tier_w_problems(tree, rels)] == ['tests/fixtures/tier_w/tiny_v1.pdb']


def test_repository_has_no_tier_w_or_microsoft_data():
    """Decision O1 enforced on every test run: tracked files only (the local corpus root is never in git)."""
    tracked = corpus.candidate_files(ROOT, include_untracked=False)
    assert tier_w_problems(ROOT, tracked) == []
    assert sorted(allowed_pdbs(ROOT)) == ['tests/fixtures/tier_w/tiny_v1.pdb', 'tests/fixtures/tier_w/tiny_v2.pdb']
