"""SPEC-28 §6 (C5): one current secondary set per engine; reconcile never raises on duplicates."""
from __future__ import annotations

import pytest

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary import publish_secondary
from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet
from patchtrace.service import ProjectService


def _set(older, newer, file_sha, address=0x10, engine='rz-diff'):
    match = SecondaryMatch(engine=engine, engine_version='0.9.1', older_address=address, newer_address=address,
                           older_name=None, newer_name=None, similarity_milli=500, similarity_text='0.5',
                           confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')
    return SecondaryMatchSet(engine=engine, engine_version='0.9.1', older_sha256=older, newer_sha256=newer,
                             file_sha256=file_sha, matches=(match,), limitations=('raw bytes',))


@pytest.fixture
def case(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    run = next(r for r in service.project.runs if r.status == 'completed' and r.raw_sha256)
    root, revision, pid = service.root, service.project.revision, service.project.id
    service.close()
    return root, sides, run, revision, pid


def _publish(root, run, pid, revision, match_set):
    service = ProjectService.open(root)
    store = EnrichmentStore(service.store)
    guard = Guard(pid, run.id, run.raw_sha256, match_set.file_sha256)
    try:
        return publish_secondary(store, guard, guard, revision, match_set)
    finally:
        service.close()


def test_reconcile_never_raises_with_duplicate_engines(case, capsys):
    """Regression: two rz-diff sets (different stdout hash) used to make reconcile raise ValueError."""
    root, sides, run, revision, pid = case
    for sha in ('1' * 64, '2' * 64):
        _publish(root, run, pid, revision, _set(sides['older'], sides['newer'], sha))
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    assert capsys.readouterr().out.count('"engine": "rz-diff"') == 1
