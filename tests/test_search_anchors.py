"""WB1 S10: PIL anchors become typed search plans; coverage is per anchor, changed code first, unknown is not none."""
from __future__ import annotations

import pytest

from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.search.anchors import (
    UNKNOWN_ABSENCE,
    coverage_for,
    plan_for,
    plans_for,
    query_text,
)
from patchtrace.search.contracts import CoverageEntry, SearchResult


def anchor(kind: str, value: str, n: int = 1) -> Anchor:
    return Anchor(anchor_id=f'{n:064x}', kind=kind, value=value, source='csaf-title', quality='explicit',
                  label=f'{kind} {value}'[:300])


def entry(group: str, status: str = 'indexed') -> CoverageEntry:
    return CoverageEntry(group=group, kinds=('function',), status=status)


def fake_search(changed=0, indexed=0, missing=()):
    """A search double: hit counts by scope, plus the groups reported as not indexed."""
    seen = []

    def search(request):
        seen.append(request.plan)
        count = changed if request.plan.scope == 'changed' else indexed
        coverage = (entry('fn'), *(entry(g, 'missing') for g in missing))
        status = 'partial' if missing and not count else 'ok' if count else 'no-results'
        return SearchResult(status=status, coverage=coverage, total=count)

    search.seen = seen
    return search


@pytest.mark.parametrize(('kind', 'value', 'expected'), [
    ('module', 'clfs.sys', 'scope:changed "clfs.sys"'),
    ('feature', 'IPv6', 'scope:changed "IPv6"'),
    ('component', 'Common Log File System', 'scope:changed "Common Log File System"'),
    ('api', 'ExAllocatePool', 'scope:changed "ExAllocatePool"'),
    ('string', 'Invalid  length "x"', 'kind:string scope:changed "Invalid length x"'),
    ('pdb', 'clfs.pdb', 'kind:build scope:changed "clfs.pdb"'),
], ids=['module', 'feature', 'component', 'api', 'string', 'pdb'])
def test_each_kind_maps_to_a_plan(kind, value, expected):
    assert query_text(anchor(kind, value), changed=True) == expected
    item = plan_for(anchor(kind, value))
    assert item.plan is not None and item.plan.scope == 'changed' and item.plan.mode == 'exact'
    assert item.plan.phrases


def test_anchor_text_never_acts_as_query_syntax():
    item = plan_for(anchor('string', '-bad* OR (x) kind:code'))
    assert item.plan is not None and item.plan.kinds == ('string',)
    assert item.plan.excludes == () and item.plan.terms == ()


def test_unsearchable_anchor_is_kept_with_a_reason():
    item = plan_for(anchor('string', 'x' * 400))
    assert item.plan is None and item.reason
    cov = coverage_for([item], fake_search())[0]
    assert cov.status == 'not-searchable' and cov.reason == item.reason


def test_plans_follow_anchor_set_order():
    anchors = AnchorSet(cve='CVE-2024-1234', anchors=(anchor('module', 'a.sys', 1), anchor('api', 'Foo', 2)))
    assert [p.anchor_id for p in plans_for(anchors)] == [f'{1:064x}', f'{2:064x}']


@pytest.mark.parametrize(('search', 'status', 'hits', 'unindexed'), [
    (fake_search(changed=3, indexed=9), 'changed', 3, ()),
    (fake_search(changed=0, indexed=2), 'indexed-only', 2, ()),
    (fake_search(), 'none', 0, ()),
    (fake_search(missing=('ir:newer',)), 'unknown', 0, ('ir:newer',)),
], ids=['changed', 'indexed-only', 'none', 'unknown'])
def test_coverage_status(search, status, hits, unindexed):
    cov = coverage_for(plans_for([anchor('module', 'clfs.sys')]), search)[0]
    assert (cov.status, cov.hits, cov.unindexed) == (status, hits, unindexed)
    if status == 'unknown':
        assert cov.reason == UNKNOWN_ABSENCE


def test_changed_scope_runs_first_and_stops_on_a_hit():
    search = fake_search(changed=1)
    coverage_for(plans_for([anchor('api', 'Foo')]), search)
    assert [p.scope for p in search.seen] == ['changed']
    search = fake_search()
    coverage_for(plans_for([anchor('api', 'Foo')]), search)
    assert [p.scope for p in search.seen] == ['changed', 'indexed']


def test_coverage_is_one_entry_per_anchor_with_no_combined_score():
    anchors = [anchor('module', 'a.sys', 1), anchor('api', 'Foo', 2), anchor('string', 'x' * 400, 3)]
    result = coverage_for(plans_for(anchors), fake_search(changed=1))
    assert [c.anchor_id for c in result] == [a.anchor_id for a in anchors]
    assert [c.status for c in result] == ['changed', 'changed', 'not-searchable']
