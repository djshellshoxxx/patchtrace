"""SPEC-28 §6: supersede semantics, v1 compatibility and alternatives (pure + store level)."""
from __future__ import annotations

import dataclasses
import itertools
import json

import pytest
from test_secondary_store import _publish, _set, case  # noqa: F401  (case is a fixture)

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary import load_secondary
from patchtrace.secondary.contracts import AlternativeMatch, SecondaryMatchSet
from patchtrace.secondary.store import as_v2, current_sets, publish_engine_set, select_current
from patchtrace.service import ProjectService


def _with_store(root, fn):
    service = ProjectService.open(root)
    try:
        return fn(EnrichmentStore(service.store))
    finally:
        service.close()


def test_rerun_same_engine_upserts_single_row(case):  # noqa: F811
    root, sides, run, revision, pid = case
    for sha in ('1' * 64, '2' * 64, '3' * 64):
        guard = Guard(pid, run.id, run.raw_sha256, sha)
        _with_store(root, lambda s, sha=sha, guard=guard: publish_engine_set(
            s, guard, guard, revision, as_v2(_set(sides['older'], sides['newer'], sha))))
    rows = _with_store(root, lambda s: s.entries('secondary-matches'))
    assert len(rows) == 1
    [(_, newest)] = _with_store(root, current_sets)
    assert newest.contract == 'secondary/2' and newest.file_sha256 == '3' * 64


def test_legacy_v1_duplicates_collapse_to_newest_non_stale(case):  # noqa: F811
    root, sides, run, revision, pid = case
    _publish(root, run, pid, revision, _set(sides['older'], sides['newer'], '1' * 64, address=1))
    _publish(root, run, pid, revision, _set(sides['older'], sides['newer'], '2' * 64, address=2))
    assert len(_with_store(root, lambda s: s.entries('secondary-matches'))) == 2
    [(_, chosen)] = _with_store(root, current_sets)
    assert chosen.matches[0].older_address == 2


def test_stale_newest_does_not_hide_valid_older(case):  # noqa: F811
    root, sides, run, revision, pid = case
    first = _set(sides['older'], sides['newer'], '1' * 64, address=1)
    second = _set(sides['older'], sides['newer'], '2' * 64, address=2)
    _publish(root, run, pid, revision, first)
    _publish(root, run, pid, revision, second)
    rows = _with_store(root, load_secondary)
    marked = [(dataclasses.replace(e, stale=e.id == second.entry_id), m) for e, m in rows]
    chosen, notes = select_current(marked)
    assert [m.file_sha256 for _, m in chosen] == ['1' * 64] and notes == []


def test_superseded_rows_are_reported(case):  # noqa: F811
    root, sides, run, revision, pid = case
    _publish(root, run, pid, revision, _set(sides['older'], sides['newer'], '1' * 64))
    _publish(root, run, pid, revision, _set(sides['older'], sides['newer'], '2' * 64))
    _, notes = select_current(_with_store(root, load_secondary))
    assert len(notes) == 1 and 'supersedes' in notes[0]


def test_reconcile_never_raises_for_any_publish_order(case, capsys):  # noqa: F811
    root, sides, run, revision, pid = case
    sets = [_set(sides['older'], sides['newer'], str(i) * 64, address=i) for i in (1, 2, 3)]
    for ordering in itertools.permutations(sets):
        for item in ordering:
            _publish(root, run, pid, revision, item)
        assert cli.main(['secondary', 'reconcile', str(root), '--json']) in (0, 4)
        capsys.readouterr()


def test_v1_json_roundtrips_unchanged():
    base = _set('a' * 64, 'b' * 64, 'c' * 64)
    dumped = base.model_dump(mode='json')
    assert 'alternatives' not in dumped and 'run_id' not in dumped and dumped['contract'] == 'secondary/1'
    assert SecondaryMatchSet.model_validate_json(base.model_dump_json()) == base


def _alt(base, rank):
    return AlternativeMatch(anchor_side='older', anchor_address=0x10, candidate=base.matches[0],
                            source='rz-diff', rank=rank)


def test_alternatives_persist_with_source_labels():
    base = _set('a' * 64, 'b' * 64, 'c' * 64)
    v2 = base.model_copy(update={'contract': 'secondary/2', 'alternatives': (_alt(base, 2),), 'run_id': 'r'})
    back = SecondaryMatchSet.model_validate_json(v2.model_dump_json())
    assert back.alternatives[0].source == 'rz-diff' and back.run_id == 'r'


def test_alternatives_require_v2_and_are_bounded():
    base = _set('a' * 64, 'b' * 64, 'c' * 64)
    payload = base.model_dump(mode='json')
    alt = _alt(base, 2).model_dump(mode='json')
    with pytest.raises(ValueError):
        SecondaryMatchSet.model_validate_json(json.dumps({**payload, 'alternatives': [alt]}))
    many = [{**alt, 'rank': i + 2} for i in range(9)]
    with pytest.raises(ValueError, match='LIMIT'):
        SecondaryMatchSet.model_validate_json(
            json.dumps({**payload, 'contract': 'secondary/2', 'alternatives': many}))
