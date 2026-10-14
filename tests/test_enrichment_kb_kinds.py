"""KB integration plan A-5 (+ KEV plan A4, + integration owner AM1): the KB, KEV, saved-search and rule kinds
are known enrichment kinds that are never derived, so retention, run pruning and the cap fallback never
delete them. Pattern: `test_unified_rows_survive_enrichment_retention`. Synthetic sample project only."""
from __future__ import annotations

import pytest

from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import create_sample

FUTURE = '9999-01-01T00:00:00+00:00'
APPEND_ONLY = 'kb-investigation'  # one row per revision
NEW_KINDS = (APPEND_ONLY, 'kb-context', 'kev-context', 'search-saved', 'rule-candidate', 'rule-decision',
             'rule-version', 'rule-test', 'rule-export')


@pytest.fixture
def case(tmp_path):
    svc = create_sample(tmp_path / 'p')
    yield svc
    if not svc.store.closed:
        svc.close()


def _ids(svc, kinds):
    rows = svc.store.connection.execute('SELECT id, kind FROM enrichment_entries').fetchall()
    return {i for i, k in rows if k in kinds}


def _put(enrichment, kind, key, guard, current):
    row_id = f'{kind}:{key}'
    enrichment.publish(kind, guard, current, 0, 'complete', {'kind': kind, 'key': key}, row_id)
    return row_id


def test_new_kinds_are_known_but_never_derived():
    assert set(NEW_KINDS) <= storage.KINDS
    assert not set(NEW_KINDS) & set(storage.DERIVED_KINDS)


def test_new_kinds_rows_survive_enrichment_retention(case):
    enrichment = EnrichmentStore(case.store)
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)  # the pipeline guard that retention evaluates against
    kb = Guard(case.project.id, 'kb', 'c' * 64, 'd' * 64)
    outdated = Guard(case.project.id, 'kb', 'c' * 64, 'e' * 64)
    keep = {_put(enrichment, APPEND_ONLY, f'inv:{rev}', kb, kb) for rev in range(1, 13)}
    others = [kind for kind in NEW_KINDS if kind != APPEND_ONLY]
    for kind in others:  # every other kind keeps a current row and a stale one
        keep |= {_put(enrichment, kind, 'fresh', kb, kb), _put(enrichment, kind, 'old', outdated, kb)}
    for n in range(12):  # enough derived generations that retention has real work to do
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:{rid}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': rid, 'wil': rid},
                                                             'config_digest': 'c'}, f'pipeline:{rid}')
    assert _ids(case, set(NEW_KINDS)) == keep
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert _ids(case, set(NEW_KINDS)) == keep
    for kind in others:  # stale rows stay stale and are still kept
        flags = {e.id: e.stale for e in enrichment.entries(kind, kb)}
        assert flags == {f'{kind}:fresh': False, f'{kind}:old': True}
