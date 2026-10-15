from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from patchtrace.search import contracts
from patchtrace.search.contracts import (
    Attention,
    CounterpartHint,
    CoverageEntry,
    Evidence,
    FunctionRef,
    Locator,
    NameSuggestion,
    PairExpansion,
    Presence,
    QueryPlan,
    Reason,
    SavedSearch,
    SearchHit,
    SearchRequest,
    SearchResult,
)
from patchtrace.search.query import parse_query

UTC = '2026-10-14T08:00:00Z'


def locator(**kw) -> Locator:
    return Locator(scheme='function', run_id='run-1', side='newer', function_id='f:1', rva=0x1a40, **kw)


def evidence(**kw) -> Evidence:
    base = dict(kind='function', side='newer', origin='ghidra', title='RtlCopyMemory', snippet='RtlCopyMemory',
                spans=((3, 7),), reasons=(Reason(code='name-words', field='words'),), locator=locator(),
                seen_by=('ghidra',), group='fn', digest16='0123456789abcdef')
    return Evidence(**{**base, **kw})


def hit(**kw) -> SearchHit:
    base = dict(hit_id='h:1', tier=1, change_class=0, components=1, evidence=(evidence(),), evidence_total=1,
                presence=Presence(older='unknown', newer='present', basis='added in raw strings'),
                expansion=PairExpansion(category='modified', counterparts=(FunctionRef(function_id='f:0', name='x', side='older'),),
                                        attention=Attention(rank=3, of=41)),
                rank_reasons=('name words',))
    return SearchHit(**{**base, **kw})


def full_result() -> SearchResult:
    ref = FunctionRef(function_id='f:1', name='RtlCopyMemory', side='newer', rva=0x1a40)
    return SearchResult(
        status='partial', hits=(hit(),), total=1, total_capped=False, cursor='abc', interpreted_as="'copy' as a word prefix",
        coverage=(CoverageEntry(group='fn', kinds=('function', 'code'), side=None, status='indexed', docs=10,
                                digest16='0123456789abcdef', built_utc=UTC),
                  CoverageEntry(group='ir:newer', kinds=('asm',), side='newer', status='unavailable',
                                reason='Ghidriff keeps only a hash of instructions')),
        suggestions=(NameSuggestion(name='RtlCopyMemory', edits=1, locator=locator()),),
        counterpart_hints=(CounterpartHint(older=ref, newer=ref, edits=1, shared_words=('copy',)),),
        warnings=('index is partial',), index_key='fedcba9876543210', timings_ms={'query': 3})


def test_result_round_trips_through_json():
    result = full_result()
    assert SearchResult.model_validate_json(result.model_dump_json()) == result
    assert result.contract == 'search/1'


def test_request_and_plan_round_trip():
    request = SearchRequest(plan=parse_query('kind:string payload'), sort='change', limit=200, generation=3)
    assert SearchRequest.model_validate_json(request.model_dump_json()) == request
    assert request.plan.contract == 'search-query/1'
    with pytest.raises(ValidationError):
        SearchRequest(plan=request.plan, limit=201)
    with pytest.raises(ValidationError):
        SearchRequest(plan=request.plan, limit=0)


def test_saved_search_rows_are_append_only_shapes():
    plan = parse_query('payload')
    created = SavedSearch(saved_id='s1', op='create', name='payload', plan=plan, created=UTC)
    deleted = SavedSearch(saved_id='s2', op='delete', of='s1', created=UTC)
    assert SavedSearch.model_validate_json(created.model_dump_json()) == created
    assert deleted.contract == 'search-saved/1'
    for bad in (dict(op='create', name='', plan=plan), dict(op='create', name='n'), dict(op='create', name='n', plan=plan, of='s1'),
                dict(op='delete'), dict(op='delete', of='s1', plan=plan), dict(op='delete', of='s1', name='n')):
        with pytest.raises(ValidationError):
            SavedSearch(saved_id='s3', created=UTC, **bad)


@pytest.mark.parametrize('kw', [dict(line_start=3), dict(line_end=3), dict(line_start=5, line_end=4)],
                         ids=['start-only', 'end-only', 'reversed'])
def test_locator_lines_go_together(kw):
    with pytest.raises(ValidationError):
        locator(**kw)
    assert locator(line_start=4, line_end=4).line_end == 4


@pytest.mark.parametrize('kw', [dict(run_id='../x'), dict(function_id=''), dict(excerpt_sha256='ABC'), dict(rva=-1)],
                         ids=['traversal', 'empty-id', 'sha', 'negative'])
def test_locator_rejects_malformed_values(kw):
    with pytest.raises(ValidationError):
        Locator(scheme='function', **kw)


@pytest.mark.parametrize('kw', [dict(spans=((0, 14),)), dict(spans=((5, 5),)), dict(spans=((7, 3),)), dict(seen_by=('floss',)),
                                dict(seen_by=()), dict(origin='registry')], ids=['past-end', 'empty', 'reversed', 'origin-missing',
                                                                                'no-origin', 'bad-origin'])
def test_evidence_validates_spans_and_provenance(kw):
    with pytest.raises(ValidationError):
        evidence(**kw)


def test_display_text_is_sanitised_on_construction():
    item = evidence(title='‮evil\x00', snippet='\x02hit\x03', spans=())
    assert item.title == '\\u202eevil\\x00' and item.snippet == '\\x02hit\\x03'
    assert evidence(title='x' * 500).title.endswith('...') and len(evidence(title='x' * 500).title) <= 200


def test_hit_bounds():
    with pytest.raises(ValidationError):
        hit(evidence_total=0)
    with pytest.raises(ValidationError):
        hit(evidence=(evidence(),) * 7, evidence_total=7)
    with pytest.raises(ValidationError):
        hit(tier=5)
    with pytest.raises(ValidationError):
        hit(components=0)


def test_attention_is_ordinal_only():
    assert Attention(rank=1, of=1).formula == 'attention/1'
    with pytest.raises(ValidationError):
        Attention(rank=42, of=41)
    with pytest.raises(ValidationError):
        Attention(rank=1, of=2, formula='attention/2')


def test_models_are_strict_frozen_and_closed():
    with pytest.raises(ValidationError):
        Presence(older='maybe')
    with pytest.raises(ValidationError):
        Presence(unexpected=1)
    with pytest.raises(ValidationError):
        Presence(older=True)
    with pytest.raises(ValidationError):
        Presence().older = 'present'
    with pytest.raises(ValidationError):
        SearchResult(status='ok', timings_ms={'Bad Key': 1})


def test_no_contract_carries_a_score():
    banned = ('score', 'confidence', 'percent', 'probability', 'bm25', 'weight')
    models = [obj for obj in vars(contracts).values() if isinstance(obj, type) and issubclass(obj, BaseModel) and obj is not BaseModel]
    assert len(models) >= 18
    for model in models:
        for name in model.model_fields:
            assert not any(word in name for word in banned), (model.__name__, name)


def test_query_plan_limits():
    with pytest.raises(ValidationError):
        QueryPlan(text='x' * 257)
    with pytest.raises(ValidationError):
        QueryPlan(text='x', excludes=('a',) * 5)
