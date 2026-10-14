"""KB / CVE identifier rules (kb-syntax/1): canonical `KB` + 4-10 ASCII digits, leading zeros kept, no numeric cast."""
from __future__ import annotations

import pytest

from patchtrace.kbcorrelation import ids


@pytest.mark.parametrize('value', ['KB1234', 'KB0001234', 'KB5099001', 'KB1234567890'], ids=['4d', 'zeros', '7d', '10d'])
def test_canonical_kb_accepted(value):
    assert ids.is_canonical_kb(value)
    assert ids.canonical_kb(value) == value


@pytest.mark.parametrize('value', ['kb1234', 'Kb1234', '1234', 'KB123', 'KB12345678901', 'KB', 'KB12a4', ' KB1234',
                                   'KB1234 ', 'KB1234\n', 'KB١٢٣٤', 'KB１２３４', 'KB-1234', 'KB+123', 'KB1_234', '',
                                   'KB1234;'],
                         ids=['lower', 'mixed', 'bare', 'short', 'long', 'empty-digits', 'alpha', 'lead-ws',
                              'trail-ws', 'newline', 'arabic', 'fullwidth', 'dash', 'plus', 'underscore', 'blank',
                              'punct'])
def test_canonical_kb_rejected(value):
    assert not ids.is_canonical_kb(value)
    with pytest.raises(ids.KbSyntaxError):
        ids.canonical_kb(value)


@pytest.mark.parametrize('raw,expected', [('KB5099001', 'KB5099001'), ('kb5099001', 'KB5099001'),
                                          ('5099001', 'KB5099001'), ('  KB5099001\t', 'KB5099001'),
                                          ('0001234', 'KB0001234'), ('kb 5099001', 'KB5099001'),
                                          ('KB-5099001', 'KB5099001')],
                         ids=['canon', 'lower', 'bare', 'ws', 'zeros', 'space', 'dash'])
def test_edge_normaliser_accepts(raw, expected):
    assert ids.normalise_kb_edge(raw) == expected


@pytest.mark.parametrize('raw', ['', 'KB', '123', '12345678901', 'KB12x', '٥٠٩٩٠٠١', '1234\n5678', 'KB KB1234',
                                 '5099001.0', '-5099001', 1234, None, b'1234'],
                         ids=['empty', 'prefix-only', 'short', 'long', 'alpha', 'arabic', 'inner-nl', 'double',
                              'float', 'neg', 'int', 'none', 'bytes'])
def test_edge_normaliser_rejects(raw):
    with pytest.raises(ids.KbSyntaxError):
        ids.normalise_kb_edge(raw)


def test_leading_zeros_survive_and_never_cast():
    assert ids.normalise_kb_edge('0000123') == 'KB0000123'
    assert ids.canonical_kb('KB0001234') != ids.canonical_kb('KB1234')
    assert ids.kb_sort_key('KB0001234') != ids.kb_sort_key('KB1234')


def test_sort_key_is_total_and_not_numeric():
    values = ['KB10000', 'KB2000', 'KB0900', 'KB1234567890']
    ordered = sorted(values, key=ids.kb_sort_key)
    assert ordered == sorted(values, key=lambda v: (len(v), v))


def test_syntax_version_constant():
    assert ids.KB_SYNTAX == 'kb-syntax/1'


@pytest.mark.parametrize('value', ['CVE-2099-10001', 'CVE-2024-0001', 'CVE-2099-1234567'],
                         ids=['5d', '4d', '7d'])
def test_cve_ok(value):
    assert ids.is_cve(value)
    assert ids.normalise_cve(value) == value


@pytest.mark.parametrize('value,expected', [('cve-2099-10001', 'CVE-2099-10001'), (' CVE-2099-10001 ', 'CVE-2099-10001')],
                         ids=['lower', 'ws'])
def test_cve_edge_normalise(value, expected):
    assert ids.normalise_cve(value) == expected


@pytest.mark.parametrize('value', ['CVE-99-1', 'CVE-2099-123', 'CVE2099-10001', 'CVE-2099-١٢٣٤', 'CVE-2099-10001x', 5, None],
                         ids=['year', 'short', 'dash', 'arabic', 'tail', 'int', 'none'])
def test_cve_rejected(value):
    assert not ids.is_cve(value)
    with pytest.raises(ids.KbSyntaxError):
        ids.normalise_cve(value)


def test_cve_sort_key_orders_by_year_then_sequence():
    values = ['CVE-2099-10001', 'CVE-2024-9999', 'CVE-2099-9999', 'CVE-2024-10000']
    assert sorted(values, key=ids.cve_sort_key) == ['CVE-2024-9999', 'CVE-2024-10000', 'CVE-2099-9999',
                                                    'CVE-2099-10001']


def test_extract_kb_tokens_only_exact_tokens():
    text = 'See KB5099001, kb5099002 and XKB5099003 plus KB123 and KB5099004x; also KB5099001.'
    assert ids.find_kb_tokens(text) == ('KB5099001',)
    assert ids.find_kb_tokens('Install KB5099004.') == ('KB5099004',)
