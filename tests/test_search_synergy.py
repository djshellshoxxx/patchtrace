"""WB1 S4: the known-answer synergy test and the `SearchService` behaviour behind it."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest
from search_builders import make_service
from search_synergy_builders import attention, extra_specs, make_project

from patchtrace import optional_deps
from patchtrace.search import fuzzy
from patchtrace.search.contracts import SearchRequest, SearchResult
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.query import parse_query
from patchtrace.search.segment import open_segment
from patchtrace.search.service import SearchService, name_spans, parse_snippet


def ask(text: str, **options) -> SearchRequest:
    mode = options.pop('mode', 'auto')
    return SearchRequest(plan=parse_query(text, mode=mode), **options)


def synergy(tmp_path, seed=None, **options) -> SearchService:
    return SearchService(make_project(tmp_path / 'project', seed=seed), tmp_path / 'cache', attention=attention,
                         comparable=lambda engine: True, extra_specs=extra_specs, **options)


def lead_shape(result: SearchResult) -> list[tuple]:
    return [(h.evidence[0].kind, h.evidence[0].title, h.tier, h.change_class, h.components) for h in result.hits]


def test_container_size_beats_each_channel(tmp_path):
    result = synergy(tmp_path).search(ask('container size'))
    assert result.status == 'ok' and result.total == 3
    assert lead_shape(result) == [('function', 'ClfsValidateContainerSize', 1, 0, 2),
                                  ('advisory', 'CVE-2099-10001', 3, 3, 1),
                                  ('code', 'ClfsDumpState', 4, 2, 1)]
    f1, advisory, dump = result.hits
    assert sorted({e.origin for e in f1.evidence}) == ['floss', 'ghidra']
    assert [e.kind for e in f1.evidence if e.origin == 'floss'] == ['string']
    assert (f1.presence.older, f1.presence.newer) == ('absent', 'present')
    assert f1.expansion.category == 'modified'
    assert {(r.side, r.name) for r in f1.expansion.counterparts} == {('older', 'ClfsValidateContainerSize'),
                                                                     ('newer', 'ClfsValidateContainerSize')}
    assert f1.expansion.attention.rank == 1 and f1.expansion.attention.of == 3
    assert f1.rank_reasons == (
        'tier 1: every query word is a whole word of the name',
        'change class 0: changed pairing or added/removed string', 'pairing is modified',
        '2 independent sources: floss, ghidra', 'attention/1 rank 1 of 3 (uncalibrated ordering)')
    assert advisory.expansion is None and advisory.evidence[0].locator.scheme == 'advisory'
    assert advisory.evidence[0].locator.function_id is None
    assert 'ClfsDumpState' not in {e.title for e in f1.evidence} and dump.expansion.category == 'unchanged'


def test_no_numeric_score_anywhere(tmp_path):
    payload = synergy(tmp_path).search(ask('container size')).model_dump(mode='json')

    def floats(node):
        if isinstance(node, dict):
            return [x for v in node.values() for x in floats(v)]
        if isinstance(node, list):
            return [x for v in node for x in floats(v)]
        return [node] if isinstance(node, float) else []
    assert floats(payload) == []
    assert not any('score' in key or 'bm25' in key for key in json.dumps(payload).split('"') if key.isidentifier())


@pytest.mark.parametrize('seed', [1, 2, 3], ids=['s1', 's2', 's3'])
def test_order_is_independent_of_document_order(tmp_path, seed):
    base = lead_shape(synergy(tmp_path / 'a').search(ask('container size')))
    assert lead_shape(synergy(tmp_path / 'b', seed=seed).search(ask('container size'))) == base


def test_each_channel_alone_fails(tmp_path):
    service = synergy(tmp_path)
    service.search(ask('container size'))
    names = ['ClfsValidateContainerSize', 'ClfsCopyRecordHeader', 'ClfsReadBlock', 'ClfsDumpState']
    assert [n for n in names if 'container size' in n.lower()] == []  # a substring filter with a space finds nothing
    request = service.build_request()
    spec = next(s for s in request.specs if s.group == 'fn')
    from patchtrace.search import paths
    directory = paths.project_dir(paths.validate_cache_root(tmp_path / 'cache', request.root), request.project_id)
    with open_segment(paths.segment_path(directory, 'fn', spec.digest16)) as segment:
        rows = segment.conn.execute("SELECT d.display FROM fts_code JOIN doc d ON d.id = fts_code.rowid "
                                    "WHERE fts_code MATCH '\"container\" AND \"size\"' ORDER BY bm25(fts_code)").fetchall()
    assert rows[0][0] == 'ClfsDumpState'  # plain bm25 over code text puts the decoy first
    ranking = attention(None)[0]
    second = next(e for e in ranking.entries if e.rank == 2).match_id
    assert second == 'm-f2' and 'ClfsCopyRecordHeader' not in {h.evidence[0].title for h in service.search(
        ask('container size')).hits}


def test_advisory_is_not_fused_to_the_function(tmp_path):
    result = synergy(tmp_path).search(ask('oversized'))
    assert [(h.evidence[0].kind, h.components, h.expansion) for h in result.hits] == [('advisory', 1, None)]


# ------------------------------------------------------------------------------------ service behaviour

@pytest.fixture
def service(tmp_path):
    return SearchService(make_service(tmp_path / 'project'), tmp_path / 'cache')


def titles(result):
    return [(h.evidence[0].title, h.tier) for h in result.hits]


@pytest.mark.parametrize('query, expected', [
    ('format line', [('FormatLine', 1)]),
    ('RtlCopyMemoryHelper', [('RtlCopyMemoryHelper', 0)]),
    ('copy memory', [('RtlCopyMemoryHelper', 1)]),
    ('copymem', [('RtlCopyMemoryHelper', 2)]),
    ('FormatLi', [('FormatLine', 2)]),
], ids=['words', 'exact', 'camel', 'substring', 'prefix'])
def test_name_tiers(service, query, expected):
    hits = [(t, tier) for t, tier in titles(service.search(ask(f'kind:function {query}'))) if t in {e[0] for e in expected}]
    assert hits == expected


def test_exact_hash_and_secret_redaction(service):
    assert service.search(ask('hunter2hunter2')).status == 'no-results'
    secret = service.search(ask('kind:string redacted'))
    assert any('redacted' in h.evidence[0].title for h in secret.hits)


def test_filters_modes_and_scope(service):
    removed = service.search(ask('is:removed kind:function'))
    assert {h.expansion.category for h in removed.hits} == {'removed'}
    changed = service.search(ask('main loop scope:changed'))
    assert changed.status == 'no-results'
    assert [h.evidence[0].title for h in service.search(ask('main loop')).hits][:1] == ['MainLoop']
    assert service.search(ask('copymem', mode='words')).status == 'no-results'
    assert titles(service.search(ask('RtlCopyMemoryHelper', mode='exact')))[0] == ('RtlCopyMemoryHelper', 0)
    older_only = service.search(ask('kind:function side:older format'))
    assert {e.side for h in older_only.hits for e in h.evidence} == {'older'}


def test_in_signature_scans_signatures(service):
    scoped = service.search(ask('in:signature format'))
    assert scoped.hits and scoped.hits[0].evidence[0].reasons[0].field == 'signature'


def test_pages_use_a_bound_cursor(service):
    request = ask('kind:function', limit=1)
    page1 = service.search(request)
    assert page1.cursor and page1.total > 1
    page2 = service.search(request.model_copy(update={'cursor': page1.cursor}))
    assert page1.hits[0].hit_id != page2.hits[0].hit_id
    with pytest.raises(SearchError) as stale:
        service.search(ask('kind:string', limit=1).model_copy(update={'cursor': page1.cursor}))
    assert stale.value.code == 'PT-SEARCH-STALE'
    with pytest.raises(SearchError) as bad:
        service.search(request.model_copy(update={'cursor': '!!'}))
    assert bad.value.code == 'PT-SEARCH-INPUT'


def test_too_broad_is_capped_and_unranked(tmp_path):
    limits = replace(DEFAULT_LIMITS, candidate_cap=1)
    service = SearchService(make_service(tmp_path / 'project'), tmp_path / 'cache', limits=limits)
    result = service.search(ask('kind:function'))
    assert result.status == 'too-broad' and result.total_capped and result.total is None
    assert 0 < len(result.hits) <= 200
    assert result.hits[0].rank_reasons == ('unranked: too many documents match',)


def test_unbuilt_index_reports_indexing_and_cancel(service):
    assert service.search(ask('format'), build=False).status == 'indexing'
    with pytest.raises(SearchError) as cancelled:
        service.search(ask('format'), cancel=lambda: True)
    assert cancelled.value.code == 'PT-SEARCH-CANCEL'


def test_result_round_trips_and_locators_validate(service):
    result = service.search(ask('format line'))
    assert SearchResult.model_validate_json(result.model_dump_json()) == result
    locator = result.hits[0].evidence[0].locator
    service.check_locator(locator)
    older = next(e.locator for h in result.hits for e in h.evidence if e.side == 'older')
    service.check_locator(older)
    for match in service.service.project.matches:
        for record in match.older:
            record.code = 'changed'
    with pytest.raises(SearchError) as gone:
        service.check_locator(older)
    assert gone.value.code == 'PT-SEARCH-LOCATOR'


def test_typo_suggestions_and_rapidfuzz_absence(service, monkeypatch):
    result = service.search(ask('FromatLine'))
    assert [(s.name, s.edits) for s in result.suggestions][:1] == [('FormatLine', 1)]
    assert result.suggestions[0].locator.scheme == 'function' and not result.hits
    monkeypatch.setattr(optional_deps, 'available', lambda name: False)
    absent = service.search(ask('FromatLine'))
    assert absent.suggestions == () and fuzzy.UNAVAILABLE in absent.warnings
    unavailable = service.search(ask('FromatLine', mode='similar'))
    assert unavailable.status == 'unsupported' and fuzzy.UNAVAILABLE in unavailable.warnings


def test_similar_mode_lists_suggestions_not_hits(service):
    result = service.search(ask('FormatLin', mode='similar'))
    assert result.hits == () and [s.name for s in result.suggestions] == ['FormatLine']
    assert result.status == 'ok'


def test_auto_names_are_never_suggested(service):
    assert [s.name for s in service.search(ask('FUN_140002001')).suggestions] == []


def test_snippet_and_span_helpers():
    text, spans = parse_snippet('a \x02probe\x03 b\nc')
    assert (text, spans) == ('a probe b\\nc', ((2, 7),))
    long_text, long_spans = parse_snippet('x' * 400 + '\x02y\x03')
    assert len(long_text) == 300 and long_spans == ()
    assert name_spans('RtlCopyMemory', parse_query('copy memory')) == ((3, 13),)
    assert name_spans('İstanbul', parse_query('stan')) == ()


def test_hundred_thousand_documents_answer_inside_the_timeout(tmp_path):
    import time

    from patchtrace.search.expand import PairIndex
    from patchtrace.search.segment import SegmentDoc, build_segment
    from patchtrace.search.service import _Reader
    from patchtrace.search.sources.base import name_fields

    def docs():
        for i in range(100_000):
            name = f'Module{i % 997}Handler{i}'
            yield SegmentDoc('function', 'newer', f'f{i}', name, i, **name_fields(name))
    info = build_segment(tmp_path, 'fn', '0123456789abcdef', docs(), ('name',))
    with open_segment(info.path) as segment:
        for query in ('handler7 module5', 'dler99'):
            started = time.perf_counter()
            found = _Reader(segment, parse_query(query), PairIndex(None, {}, {}, {}), DEFAULT_LIMITS).candidates()
            assert found and time.perf_counter() - started < DEFAULT_LIMITS.query_timeout_s
