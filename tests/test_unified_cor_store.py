"""SPEC-31 store audit `cor` (02 s4): retention keeps the project's current result. Synthetic sample project."""
from __future__ import annotations

from test_unified_store import _ids, _stage, case  # noqa: F401 - `case` is a fixture

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.unified import store


def test_retention_never_evicts_the_result_the_project_is_current_on(case):  # noqa: F811
    """Results published while the project moved on (stale rows) must not push the still-current one out (02 s4:
    'keep the newest L-32 ... plus the current one')."""
    enrichment = EnrichmentStore(case.store)
    staged, first, current = _stage(case, version='v0', config='same')
    store.publish_result(enrichment, staged, guard=current, current=current, revision=1)
    for i in range(1, 5):
        staged, _manifest, guard = _stage(case, version=f'v{i}', config='same')
        store.publish_result(enrichment, staged, guard=guard, current=current, revision=1)
    kept = _ids(case, {'unified-result'})
    assert first.result_id in kept and len(kept) == 4      # the current one plus the newest L-32 = 3
    assert store.load_result(enrichment, current).state == 'current'
