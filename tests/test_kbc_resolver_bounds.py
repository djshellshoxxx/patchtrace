"""Hostile variant counts must bound evaluation work, not merely the displayed pair list."""
from __future__ import annotations

import pytest
from kbc_k5_support import scope

from patchtrace.kbcorrelation import lineage, resolver

NAME, KB = 'example.sys', 'KB5000003'


def rows(count=100):
    common = {'version_key': '11-24H2', 'size': 8192, 'machine_type': 0x8664, 'variant': 'full',
              'heading_class': 'standard', 'download': 'direct', 'record_sha256': 'd' * 64}
    items = [common | {'sha256': 'f' * 64, 'kb': 'KB5000001', 'release_date': '2099-01-01',
                       'release_version': '26100.100'}]
    items += [common | {'sha256': f'{i + 1:064x}', 'kb': KB, 'release_date': '2099-02-01',
                        'release_version': '26100.200'} for i in range(count)]
    result, rejected = lineage.index_rows(items, file_name=NAME)
    assert rejected == 0
    return result


@pytest.mark.parametrize('budget', ['result-count', 'row-work'])
def test_enumeration_stops_at_budget_before_grading_unreturned_variants(monkeypatch, budget):
    source = rows()
    limit, evaluated_cap = (7, 7) if budget == 'result-count' else (20, 7)
    if budget == 'row-work':
        monkeypatch.setattr(resolver, 'MAX_PAIR_ROW_WORK', len(source) * evaluated_cap)
    original, evaluated = resolver.propose_index_pair, []

    def counted(*args, **kwargs):
        evaluated.append(args)
        assert len(evaluated) <= evaluated_cap, 'the limit must stop evaluation, not only slice its output'
        return original(*args, **kwargs)

    monkeypatch.setattr(resolver, 'propose_index_pair', counted)
    result = resolver.resolve(source, kb=KB, scope=scope(), file_name=NAME, limit=limit)
    assert len(result.pairs) == len(evaluated) == evaluated_cap
    assert result.truncated and result.ambiguous and result.changed_in_kb == 'unknown'


def test_work_budget_with_no_enumerated_pair_is_a_gap_not_a_missing_predecessor(monkeypatch):
    source = rows()
    monkeypatch.setattr(resolver, 'MAX_PAIR_ROW_WORK', len(source) - 1)
    result = resolver.resolve(source, kb=KB, scope=scope(), file_name=NAME)
    assert result.pairs == () and result.truncated and result.ambiguous
    assert result.blockers == ('INDEX_GAP',) and 'no predecessor conclusion' in result.note


def test_repeated_variant_chronology_is_parsed_in_linear_work(monkeypatch):
    source = rows()
    original, calls = lineage._release_instant, []

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(lineage, '_release_instant', counted)
    result = resolver.resolve(source, kb=KB, scope=scope(), file_name=NAME, limit=10)
    assert result.truncated and len(result.pairs) == 10
    assert len(calls) <= 10 * len(source), 'reparsing every peer for every target is quadratic work'


@pytest.mark.parametrize('limit', [0, -1, 1001, True, 1.5, None])
def test_pair_enumeration_limit_cannot_bypass_the_hard_cap(limit):
    with pytest.raises(ValueError, match='limit'):
        resolver.resolve(rows(1), kb=KB, scope=scope(), file_name=NAME, limit=limit)
