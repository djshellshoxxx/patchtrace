"""SPEC-10 §5 / SPEC-11: reconciliation by address and enrichment storage of secondary sets."""
from __future__ import annotations

import pytest

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.secondary import load_secondary, publish_secondary
from patchtrace.secondary.contracts import KIND, SecondaryMatch, SecondaryMatchSet
from patchtrace.secondary.reconcile import reconcile
from patchtrace.service import ProjectService

OLD, NEW = 'a' * 64, 'b' * 64


def fn(side, address):
    return FunctionRecord(artifact_id=side, run_id='r', name=f'f{address}', address=address)


def gmatch(ident, older=None, newer=None, category='modified'):
    olders = older if isinstance(older, list) else [older] if older else []
    return FunctionMatch(id=ident, run_id='r', category=category, older=[fn('o', a) for a in olders],
                         newer=[fn('n', newer)] if newer else [])


def sm(older, newer):
    return SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=older, newer_address=newer,
                          older_name=None, newer_name=None, similarity_milli=500, similarity_text='0.5',
                          confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')


def mset(*matches):
    return SecondaryMatchSet(engine='rz-diff', engine_version='0.9.1', older_sha256=OLD, newer_sha256=NEW,
                             file_sha256='c' * 64, matches=matches, limitations=('raw bytes',))


def test_reconcile_classifies_by_address_without_mutation():
    matches = [
        gmatch('agree', '140001000', '140001000'),
        gmatch('differ', '0x140002000', '140002000'),
        gmatch('none', '140005000', '140005000'),
        gmatch('removed', '140006000', None, 'removed'),
        gmatch('added', None, '140007000', 'added'),
        gmatch('many', ['140008000', '140008100'], '140008000', 'merged'),
        gmatch('bad', 'zzz', '140009000'),
    ]
    snapshot = [m.model_dump() for m in matches]
    secondary = mset(sm(0x140001000, 0x140001000), sm(0x140002000, 0x140002400), sm(0x140006000, None),
                     sm(0x140003000, 0x140007000), sm(0x1400A0000, None))
    report = reconcile(matches, secondary)
    status = {row.match_id: row.status for row in report.rows}
    assert status == {'agree': 'agreement', 'differ': 'disagreement', 'none': 'absent', 'removed': 'agreement',
                      'added': 'disagreement', 'many': 'not-comparable', 'bad': 'not-comparable'}
    assert 'not proof' in next(r.note for r in report.rows if r.status == 'agreement')
    assert [m.older_address for m in report.secondary_only] == [0x1400A0000]
    assert report.counts() == {'agreement': 2, 'disagreement': 2, 'absent': 1, 'not-comparable': 2}
    assert any('Image-base' in text for text in report.limitations)
    assert [m.model_dump() for m in matches] == snapshot


def test_conflicting_secondary_partners_are_disagreement():
    report = reconcile([gmatch('m', '10', '20')], mset(sm(0x10, 0x20), sm(0x30, 0x20)))
    assert report.rows[0].status == 'disagreement' and len(report.rows[0].secondary) == 2


def test_match_contract_rejects_inconsistent_records():
    with pytest.raises(ValueError):
        sm(None, None)
    with pytest.raises(ValueError):
        SecondaryMatch(engine='bindiff', engine_version='8', older_address=1, newer_address=None,
                       older_name=None, newer_name=None, similarity_milli=1, similarity_text='0.001',
                       confidence_milli=1, confidence_text='0.001', flags=(), algorithm='x')
    with pytest.raises(ValueError):
        SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=1, newer_address=1,
                       older_name=None, newer_name=None, similarity_milli=1001, similarity_text='1.001',
                       confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')


def test_store_round_trip_keeps_ghidriff_untouched(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    try:
        before = svc.project.model_dump_json()
        run = next(r for r in svc.project.runs if r.raw_sha256)
        guard = Guard(svc.project.id, run.id, run.raw_sha256, 'c' * 64)
        store = EnrichmentStore(svc.store)
        secondary = mset(sm(1, 2), sm(3, None))
        entry = publish_secondary(store, guard, guard, svc.project.revision, secondary)
        assert entry.kind == KIND and entry.id == secondary.entry_id and not entry.stale
        [(loaded_entry, loaded)] = load_secondary(store, guard)
        assert loaded == secondary
        assert svc.project.model_dump_json() == before
        assert mset(sm(1, 2)).entry_id == secondary.entry_id  # keyed by file/pair, not content
    finally:
        svc.close()
