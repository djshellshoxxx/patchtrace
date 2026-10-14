"""The SYNTHETIC BinExport2 pair used by the live BinDiff test (tests/bindiff_live_pair.py) is well formed.

Structural checks with a stdlib wire decoder; whether BinDiff accepts it is only shown by the live test.
"""
from __future__ import annotations

import hashlib

import pytest
from bindiff_live_pair import MNEMONICS, decode, write_pair

from patchtrace.sample import synthetic_pe
from patchtrace.secondary.bindiff_inputs import AcceptedBinExportLike, bind_pair
from patchtrace.secondary.contracts import SecondaryError


def _structure(data: bytes) -> dict:
    top = decode(data)
    meta = decode(top[1][0])
    call_graph = decode(top[8][0])
    vertices = [decode(v) for v in call_graph.get(1, [])]
    edges = [decode(e) for e in call_graph.get(2, [])]
    instructions = [decode(i) for i in top[5]]
    blocks = [decode(decode(b)[1][0]) for b in top[6]]
    graphs = [decode(g) for g in top[7]]
    return {'meta': {k: v[0] for k, v in meta.items()}, 'mnemonics': [decode(m)[1][0].decode() for m in top[4]],
            'vertices': vertices, 'edges': edges, 'instructions': instructions, 'blocks': blocks, 'graphs': graphs}


def test_pair_is_deterministic_and_bound_to_project_owned_synthetic_pes(tmp_path):
    first, second = write_pair(tmp_path / 'a'), write_pair(tmp_path / 'b')
    for role in ('older', 'newer'):
        assert (tmp_path / 'a' / f'{role}.BinExport').read_bytes() == (tmp_path / 'b' / f'{role}.BinExport').read_bytes()
    assert first.older_sha256 == hashlib.sha256(synthetic_pe(0)).hexdigest() == second.older_sha256
    assert first.newer_sha256 == hashlib.sha256(synthetic_pe(1)).hexdigest()
    assert first.older_artifact.read_bytes() == synthetic_pe(0)
    for item, sha in ((first.older, first.older_sha256), (first.newer, first.newer_sha256)):
        assert isinstance(item, AcceptedBinExportLike)
        data = item.snapshot_path.read_bytes()
        assert item.summary.file_sha256 == hashlib.sha256(data).hexdigest() and item.summary.executable_id == sha
        meta = _structure(data)['meta']
        assert meta[2].decode() == sha and meta[3] == b'x86-64' and meta[1].decode().startswith('synthetic-')


@pytest.mark.parametrize('role, functions', [('older', 20), ('newer', 21)])
def test_graphs_are_consistent(tmp_path, role, functions):
    pair = write_pair(tmp_path)
    s = _structure(getattr(pair, role).snapshot_path.read_bytes())
    assert s['mnemonics'] == list(MNEMONICS)
    addresses = [v[1][0] for v in s['vertices']]
    assert len(addresses) == functions == len(s['graphs']) and addresses == sorted(set(addresses))
    assert all(0 <= e[1][0] < functions and 0 <= e[2][0] < functions for e in s['edges'])
    instruction_addresses = [i[1][0] for i in s['instructions']]
    assert instruction_addresses == sorted(set(instruction_addresses))
    assert all(0 <= i[3][0] < len(MNEMONICS) and len(i[5][0]) == 2 for i in s['instructions'])
    for block in s['blocks']:
        assert 0 <= block[1][0] < block[2][0] <= len(s['instructions'])
    for graph, address in zip(s['graphs'], addresses, strict=True):
        members, entry = graph[1], graph[3][0]
        assert entry in members and s['instructions'][s['blocks'][entry][1][0]][1][0] == address
        for edge in (decode(e) for e in graph.get(2, [])):
            assert edge[1][0] in members and edge[2][0] in members


def test_pair_differs_only_where_patched(tmp_path):
    pair = write_pair(tmp_path)
    older = _structure(pair.older.snapshot_path.read_bytes())
    newer = _structure(pair.newer.snapshot_path.read_bytes())
    assert len(newer['instructions']) == len(older['instructions']) + 2 + 2 + 4
    assert len(newer['edges']) == len(older['edges']) + 1


def test_pair_binds_in_order_and_reversed_is_orientation(tmp_path):
    pair = write_pair(tmp_path)
    bound = bind_pair(pair.older, pair.newer, pair.older_sha256, pair.newer_sha256)
    assert bound.provenance()['binexport_binding'] == 'sha256'
    with pytest.raises(SecondaryError) as info:
        bind_pair(pair.newer, pair.older, pair.older_sha256, pair.newer_sha256)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'
