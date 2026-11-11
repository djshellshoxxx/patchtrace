"""Call-graph kernel: label parsing and untrusted-text sanitizer (WB2 G1)."""
from __future__ import annotations

import pytest

from patchtrace.callgraph import labels, text
from patchtrace.secondary.evidence_view import _UNSAFE


@pytest.mark.parametrize(
    ('label', 'expected'),
    [('FUN_00401000', 0x401000), ('FUN_1a', 0x1A), ('FUN_', None), ('FUN_zz', None), ('xFUN_10', None), ('Parse', None)],
    ids=['hex8', 'short', 'empty', 'nonhex', 'prefixed', 'named'],
)
def test_default_address(label, expected):
    assert labels.default_address(label) == expected
    assert labels.is_default_name(label) is (expected is not None)


@pytest.mark.parametrize(
    ('label', 'expected'),
    [('thunk_Foo', 'Foo'), ('thunk_', None), ('Foo', None), ('xthunk_Foo', None)],
    ids=['thunk', 'bare', 'plain', 'infix'],
)
def test_thunk_target(label, expected):
    assert labels.thunk_target(label) == expected


@pytest.mark.parametrize(
    ('label', 'expected'),
    [('Foo-3', ('Foo', 3)), ('a-b-12', ('a-b', 12)), ('Foo', None), ('Foo-x', None), ('-3', None),
     ('x-' + '9' * 5000, None), ('Foo-\u0663', None)],
    ids=['simple', 'dashed-stem', 'none', 'nonnumeric', 'no-stem', 'huge-suffix-105-cg2', 'non-ascii-digit'],
)
def test_split_count_suffix(label, expected):
    assert labels.split_count_suffix(label) == expected


@pytest.mark.parametrize(
    ('label', 'expected'),
    [
        ('KERNEL32.DLL::CreateFileW', ('kernel32', 'CreateFileW')),
        ('ntdll::NtClose', ('ntdll', 'NtClose')),
        ('libc.so::memcpy', ('libc', 'memcpy')),
        ('::x', None),
        ('lib::', None),
        ('plain', None),
    ],
    ids=['dll', 'bare-lib', 'so', 'no-lib', 'no-name', 'no-sep'],
)
def test_parse_external(label, expected):
    parsed = labels.parse_external(label)
    assert (tuple(parsed) if parsed else None) == expected
    if parsed:
        assert parsed.key == f'{expected[0]}::{expected[1]}'


def test_external_address_detection():
    assert labels.is_external_address('EXTERNAL:0000000c')
    assert not labels.is_external_address('00401000')
    assert not labels.is_external_address(None)


@pytest.mark.parametrize(
    ('name', 'library', 'expected'),
    [
        ('CreateFileW', None, ('CreateFileW', 'CreateFile')),
        ('CreateFileA', 'kernel32.dll', ('CreateFileA', 'CreateFile')),
        ('NtClose', None, ('NtClose',)),
        ('AW', None, ('AW',)),
        ('#12', 'WS2_32.DLL', ('ws2_32.#12',)),
        ('#12', None, ()),
    ],
    ids=['wide', 'ansi', 'plain', 'too-short', 'ordinal', 'ordinal-no-lib'],
)
def test_api_variants(name, library, expected):
    assert labels.api_variants(name, library) == expected


def test_sanitizer_matches_evidence_view_pattern():
    assert text.UNSAFE.pattern == _UNSAFE.pattern


def test_sanitize_removes_unsafe_and_caps():
    hostile = 'a\x00b‮c d\x1fe<b>{0}%s'
    assert text.sanitize(hostile) == 'abcde<b>{0}%s'
    long = 'x' * 10_000
    out = text.sanitize(long)
    assert len(out) == 512 and out.endswith('...')
    assert text.sanitize(None) == ''


def test_one_line_collapses_whitespace_and_caps_at_120():
    assert text.one_line('a\nb\tc\r\nd') == 'a b c  d'
    assert len(text.one_line('y' * 500)) == 120
