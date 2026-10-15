from __future__ import annotations

import json
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.intelligence.tools.common import display_text
from patchtrace.search.errors import SearchError
from patchtrace.search.normalize import clean_query_text, fold, is_auto_name, nfc, sanitize_text
from patchtrace.search.tokenize import code_idents, msvc_light, name_words, split_identifier

FIXTURES = Path(__file__).parent / 'fixtures' / 'search'
NAMES = json.loads((FIXTURES / 'names.json').read_text(encoding='utf-8'))
HOSTILE = json.loads((FIXTURES / 'hostile.json').read_text(encoding='utf-8'))
ANY_TEXT = st.text(alphabet=st.characters(exclude_categories=()), max_size=80)


@pytest.mark.parametrize('name,expected', [('Straße', 'strasse'), ('ＦＵＮ', 'fun'), ('ﬁle', 'file'), ('ÄB', 'äb'),
                                           ('é', 'é')], ids=['sharp-s', 'fullwidth', 'ligature', 'umlaut', 'combining'])
def test_fold_is_nfkc_casefold(name, expected):
    assert fold(name) == expected


def test_nfc_composes():
    assert nfc('é') == 'é'


@pytest.mark.parametrize('name,auto', [
    ('FUN_140001a40', True), ('sub_401000', True), ('LAB_1400a2b3c', True), ('DAT_14000', True),
    ('thunk_FUN_140001a40', True), ('FUN_12', False), ('FUN_', False), ('RtlCopyMemory', False),
    ('sub_name', False), ('MyFUN_140001a40', False)],
    ids=['fun', 'sub', 'lab', 'dat', 'thunk', 'short', 'bare', 'real', 'subname', 'prefixed'])
def test_auto_name_detector(name, auto):
    assert is_auto_name(name) is auto


@pytest.mark.parametrize('index', range(len(HOSTILE)), ids=lambda i: f'h{i}')
def test_sanitize_equals_display_text_on_hostile_strings(index):
    value = HOSTILE[index]
    assert sanitize_text(value, 500) == display_text(value, 500)


@given(ANY_TEXT, st.integers(min_value=4, max_value=120))
@settings(max_examples=300, deadline=None)
def test_sanitize_equals_display_text_property(value, limit):
    assert sanitize_text(value, limit) == display_text(value, limit)


@given(ANY_TEXT)
@settings(max_examples=200, deadline=None)
def test_sanitized_text_has_no_invisible_characters(value):
    out = sanitize_text(value, 200, multiline=True)
    assert all(c == '\n' or unicodedata.category(c) not in {'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'} for c in out)
    assert len(out) <= 200


def test_multiline_keeps_newlines_only_when_asked():
    assert sanitize_text('a\nb\tc', 50) == 'a\\nb\\tc'
    assert sanitize_text('a\nb\tc', 50, multiline=True) == 'a\nb\\tc'


def test_snippet_markers_cannot_survive_sanitising():
    assert sanitize_text('\x02hit\x03', 50, multiline=True) == '\\x02hit\\x03'


@pytest.mark.parametrize('text,expected', [('  a \t b\n', 'a b'), ('é', 'é'), ('a b', 'a b')],
                         ids=['space', 'nfc', 'nbsp'])
def test_clean_query_text(text, expected):
    assert clean_query_text(text) == expected


@pytest.mark.parametrize('text', ['\ud800', 'a\x00', '‮', '​', '\x02', '\x1f', ' ', ''],
                         ids=['surrogate', 'nul', 'bidi', 'zwsp', 'stx', 'us', 'lsep', 'private'])
def test_clean_query_text_rejects_unsafe(text):
    with pytest.raises(SearchError) as err:
        clean_query_text(text)
    assert err.value.code == 'PT-SEARCH-QUERY'


@pytest.mark.parametrize('index', range(len(NAMES)), ids=lambda i: f'n{i}')
def test_name_words_golden(index):
    entry = NAMES[index]
    assert name_words(*entry['names']) == entry['words']


def test_golden_table_has_forty_names_or_more():
    assert len(NAMES) >= 40


@pytest.mark.parametrize('name,light', [
    ('?Validate@CFoo@@QEAAHXZ', 'CFoo::Validate'), ('?Dispatch@Inner@Outer@@AEAAXXZ', 'Outer::Inner::Dispatch'),
    ('??0CFoo@@QEAA@XZ', None), ('?$Tmpl@H@@', None), ('RtlCopyMemory', None), ('?x', None)],
    ids=['method', 'nested', 'ctor', 'template', 'plain', 'truncated'])
def test_msvc_light(name, light):
    assert msvc_light(name) == light


def test_name_words_dedupes_across_forms():
    assert name_words('RtlCopyMemory', 'RtlCopyMemory') == 'rtl copy memory'


def test_name_words_is_capped():
    assert len(name_words('_'.join(f'w{i}x' for i in range(500))).split()) <= 128


def test_code_idents_dedupes_and_splits():
    text = 'if (ProbeForRead(ptr, len)) { RtlCopyMemory(dst, ptr, len); } // 0x7fff'
    assert code_idents(text) == 'if probe for read ptr len rtl copy memory dst'


def test_code_idents_respects_the_word_cap():
    assert len(code_idents(' '.join(f'identifier{i}' for i in range(100)), max_words=10).split()) == 10


@given(ANY_TEXT)
@settings(max_examples=300, deadline=None)
def test_split_identifier_never_raises_and_words_are_folded(name):
    words = split_identifier(name)
    assert all(word and word == fold(word) for word in words)
