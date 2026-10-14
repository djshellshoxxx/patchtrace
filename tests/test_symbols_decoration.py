"""WBQ S10: symbol decoration facts (`patchtrace.symbols`). Pure, hermetic, no decoder or target needed.

The known answers are tests/fixtures/wbq/ms_kat.tsv: 59 name pairs from the LLVM Demangle tests (ms_kat.NOTICE).
Its `demangled` cells are the output of LLVM's own Microsoft demangler and its `qualified_name` cells are that
decoder's rendering of each name part. Cases marked "decoder-verified" below were run through the same decoder.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import re
import time
from pathlib import Path
from typing import NamedTuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.symbols import (
    KINDS,
    MAX_NAME_BYTES,
    MAX_QUALIFIED_NAME_CHARS,
    Decoration,
    core_name,
    parse_decoration,
)
from patchtrace.symbols.kinds import kind_of

KAT_PATH = Path(__file__).parent / 'fixtures' / 'wbq' / 'ms_kat.tsv'
SYMBOLS_DIR = Path(__file__).parents[1] / 'src' / 'patchtrace' / 'symbols'


class Kat(NamedTuple):
    mangled: str
    demangled: str
    kind: str
    qualified_name: str
    tail: str
    complex: str
    source: str


def load_kat() -> list[Kat]:
    raw = KAT_PATH.read_bytes()
    assert b'\r' not in raw, 'ms_kat.tsv must stay LF (.gitattributes: tests/fixtures/wbq/** text eol=lf)'
    lines = [line for line in raw.decode('utf-8').split('\n') if line and not line.startswith('#')]
    assert lines[0].split('\t') == list(Kat._fields)
    return [Kat(*line.split('\t')) for line in lines[1:]]


KAT = load_kat()
SIMPLE_KAT = [row for row in KAT if row.qualified_name]
KAT_IDS = [row.source for row in KAT]
SIMPLE_IDS = [row.source for row in SIMPLE_KAT]


def expected(row: Kat) -> Decoration:
    return Decoration(row.kind, row.mangled, row.qualified_name or None, row.tail or None, row.complex == '1')


def assert_invariants(name: str, got: Decoration) -> None:
    assert got.original == name and got.kind in KINDS
    assert (got.qualified_name is None) == (got.tail is None)
    if got.qualified_name is not None:
        assert got.kind == 'msvc' and not got.complex and got.tail
        assert got.qualified_name.isascii() and got.qualified_name.isprintable()
        assert len(got.qualified_name) <= MAX_QUALIFIED_NAME_CHARS
    if got.complex:
        assert got.kind == 'msvc' and got.qualified_name is None
    if got.kind != 'msvc':
        assert got.qualified_name is None and not got.complex
    if len(name) > MAX_NAME_BYTES:
        assert got == Decoration('plain', name)


# --- the known answers ------------------------------------------------------------------------------------

def test_kat_ships_its_notice_and_the_verbatim_licence():
    notice = (KAT_PATH.parent / 'ms_kat.NOTICE').read_text(encoding='utf-8')
    licence = (KAT_PATH.parent / 'ms_kat.LICENSE.TXT').read_bytes()
    assert 'Apache-2.0 WITH LLVM-exception' in notice and 'llvmorg-23.1.0' in notice
    assert b'Apache License' in licence and b'LLVM Exceptions' in licence
    assert hashlib.sha256(licence).hexdigest() in notice  # LF bytes, as fetched (.gitattributes eol=lf)


def test_kat_has_the_promised_shape():
    assert 50 <= len(KAT) <= 70
    assert len({row.source for row in KAT}) == len(KAT) == len({row.mangled for row in KAT})
    assert {row.kind for row in KAT} == {'msvc', 'string-literal', 'rtti'}
    assert len(SIMPLE_KAT) >= 25 and sum(row.complex == '1' for row in KAT) >= 20
    assert all(row.complex in ('0', '1') and bool(row.qualified_name) == bool(row.tail) for row in KAT)
    assert not any(row.qualified_name and row.complex == '1' for row in KAT)


@pytest.mark.parametrize('row', KAT, ids=KAT_IDS)
def test_kat_known_answers(row):
    assert parse_decoration(row.mangled) == expected(row)


@pytest.mark.parametrize('row', SIMPLE_KAT, ids=SIMPLE_IDS)
def test_kat_name_and_tail_agree_with_the_decoder_output(row):
    assert re.search(r'(?<![\w:~])' + re.escape(row.qualified_name) + r'(?![\w:])', row.demangled)
    assert row.mangled.endswith(row.tail)
    # the name part with a trivial tail is a complete variable name that keeps the same qualified name
    probe = row.mangled[: len(row.mangled) - len(row.tail)] + '3HA'
    assert parse_decoration(probe) == Decoration('msvc', probe, row.qualified_name, '3HA')


def test_kat_matches_the_llvm_decoder_when_it_is_installed():
    decoder = pytest.importorskip('pydemumble')
    if importlib.metadata.version('pydemumble') != '0.1.3':
        pytest.skip('ms_kat.tsv was produced with pydemumble 0.1.3')
    for row in KAT:
        assert decoder.demangle(row.mangled) == row.demangled, row.source
        if row.qualified_name:
            name_part = row.mangled[: len(row.mangled) - len(row.tail)]
            assert decoder.demangle(name_part + '3HA') == 'int ' + row.qualified_name, row.source


# --- PatchTrace's own cases (decoder-verified) ------------------------------------------------------------

NAMED = [
    ('parse-packet', '?ParsePacket@CParser@@QEAAJPEBEK@Z', 'CParser::ParsePacket', 'QEAAJPEBEK@Z'),
    ('parse-packet-widened', '?ParsePacket@CParser@@QEAAJPEBE_K@Z', 'CParser::ParsePacket', 'QEAAJPEBE_K@Z'),
    ('function-pointer-argument', '?f@@YAXP6AXH@Z@Z', 'f', 'YAXP6AXH@Z@Z'),
    ('constructor', '??0CFoo@@QEAA@XZ', 'CFoo::CFoo', 'QEAA@XZ'),
    ('import-pointer-prefix', '__imp_?Foo@@YAXXZ', 'Foo', 'YAXXZ'),
    ('incremental-link-thunk', '@ILT+1005(?f@@YAXXZ)', 'f', 'YAXXZ'),
    ('prefix-inside-thunk', '@ILT+7(__imp_?f@@YAXXZ)', 'f', 'YAXXZ'),
    ('byte-count-suffix-after-function', '?f@@YAXXZ@4', 'f', 'YAXXZ'),
    ('byte-count-suffix-after-variable', '?x@@3HA@12', 'x', '3HA'),
    ('no-type-information-digit-is-kept', '?foo@@9', 'foo', '9'),
    ('suffix-after-a-double-at-is-kept', '?f@@YAXXZ@@4', 'f', 'YAXXZ@@4'),
    ('class-repeated-as-a-scope', '?f@A@1@3HA', 'A::A::f', '3HA'),
    ('scope-names-the-function', '?f@A@0@3HA', 'f::A::f', '3HA'),
    ('duplicate-names-share-one-index', '?a@b@a@c@2@3HA', 'c::c::a::b::a', '3HA'),
    ('tenth-name-is-addressable', '?n0@n1@n2@n3@n4@n5@n6@n7@n8@n9@n10@90@3HA',
     'n0::n9::n10::n9::n8::n7::n6::n5::n4::n3::n2::n1::n0', '3HA'),
    ('names-past-the-tenth-are-not-indexed', '?n0@n1@n2@n3@n4@n5@n6@n7@n8@n9@n10@n11@9@3HA',
     'n9::n11::n10::n9::n8::n7::n6::n5::n4::n3::n2::n1::n0', '3HA'),
]


@pytest.mark.parametrize('name, qualified, tail', [case[1:] for case in NAMED], ids=[case[0] for case in NAMED])
def test_derived_names(name, qualified, tail):
    assert parse_decoration(name) == Decoration('msvc', name, qualified, tail)


SPECIAL = [  # complex (a construct that is deliberately not resolved) or not readable at all
    ('operator-assign', '??4A@@QEAAXXZ', True),
    ('vftable', '??_7Foo@@6B@', True),
    ('template-function', '??$f@H@@YAXH@Z', True),
    ('template-scope', '?f@?$A@H@@QEAAXXZ', True),
    ('template-constructor', '??0?$A@H@@QEAA@XZ', True),
    ('anonymous-namespace', '?x@?A@@3HA', True),
    ('function-local-static', '?x@?1??f@@YAXXZ@4HA', True),
    ('scope-name-with-a-colon', '?x@a:b@@3HA', True),
    ('scope-name-with-angle-brackets', '?x@a<b>@@3HA', True),
    ('question-mark-inside-a-name', '?x@a?b@@3HA', True),
    ('truncated-operator', '??4', True),
    ('truncated-template-scope', '?x@?$A', True),
    ('truncated-local-scope', '?x@?1', True),
    ('chain-never-ends', '?x@y', False),
    ('no-at-at-all', '?x', False),
    ('only-a-question-mark', '?', False),
    ('empty-first-name', '?@@3HA', False),
    ('no-type-encoding', '?x@@', False),
    ('back-reference-out-of-range', '?x@5@@3HA', False),
    ('back-reference-past-deduplicated-table', '?a@b@a@c@3@3HA', False),
    ('back-reference-with-empty-table', '?0@@3HA', False),
    ('constructor-without-a-class', '??0@@QEAA@XZ', False),
]


@pytest.mark.parametrize('name, is_complex', [case[1:] for case in SPECIAL], ids=[case[0] for case in SPECIAL])
def test_no_name_is_derived_and_unknown_stays_unknown(name, is_complex):
    assert parse_decoration(name) == Decoration('msvc', name, None, None, is_complex)


KINDS_BY_NAME = [
    ('msvc-data', '?x@@3HA', 'msvc'),
    ('string-literal', '??_C@_02PCEFGMJL@hi?$AA@', 'string-literal'),
    ('rtti-class', '.?AVFoo@@', 'rtti'),
    ('rtti-struct', '.?AUBar@Foo@@', 'rtti'),
    ('itanium-nested', '_ZN3Foo3BarEi', 'itanium'),
    ('itanium-free', '_Z3foov', 'itanium'),
    ('rust-legacy', '_ZN4core3fmt5write17h0123456789abcdefE', 'rust'),
    ('rust-legacy-needs-lowercase-hex', '_ZN4core3fmt5write17h0123456789ABCDEFE', 'itanium'),
    ('rust-v0', '_RNvCs1234_7mycrate3foo', 'rust'),
    ('rust-v0-with-version', '_R0NvCs1234_7mycrate3foo', 'rust'),
    ('msvc-runtime-check-is-not-rust', '_RTC_CheckEsp', 'plain'),
    ('c-name', 'memcpy', 'plain'),
    ('stdcall-name', '_MessageBoxA@16', 'plain'),
    ('import-of-a-stdcall-name', '__imp__MessageBoxA@16', 'plain'),
    ('import-prefix-alone', '__imp_', 'plain'),
    ('empty', '', 'plain'),
]


@pytest.mark.parametrize('name, kind', [case[1:] for case in KINDS_BY_NAME], ids=[case[0] for case in KINDS_BY_NAME])
def test_kind_by_prefix_and_other_kinds_derive_no_name(name, kind):
    got = parse_decoration(name)
    assert got.kind == kind
    if kind != 'msvc':
        assert got == Decoration(kind, name)


CORES = [
    ('plain', '?x@@3HA', '?x@@3HA'),
    ('import-prefix', '__imp_?x@@3HA', '?x@@3HA'),
    ('thunk', '@ILT+1(?x@@3HA)', '?x@@3HA'),
    ('suffix-after-z', '?x@@YAXXZ@4', '?x@@YAXXZ'),
    ('stdcall-c-name', '_f@8', '_f'),
    ('fastcall-c-name', '@f@8', '@f'),
    ('suffix-needs-one-to-four-digits', '_f@12345', '_f@12345'),
    ('rtti-descriptor-keeps-its-digit', '??_R3Base@@8', '??_R3Base@@8'),
    ('lone-suffix-is-kept', '@8', '@8'),
    ('empty-thunk-is-kept', '@ILT+1()', '@ILT+1()'),
    ('too-long', '?' + 'a' * MAX_NAME_BYTES, None),
    ('empty', '', None),
    ('space', '?x@@3HA ', None),
    ('control', '?x@@3HA\x00', None),
    ('not-ascii', '?x@\u00e9@@3HA', None),
]


@pytest.mark.parametrize('name, core', [case[1:] for case in CORES], ids=[case[0] for case in CORES])
def test_core_name_strips_only_wrappers(name, core):
    assert core_name(name) == core


def test_kind_of_reads_only_the_prefix():
    assert kind_of('??_C@_') == 'string-literal' and kind_of('?') == 'msvc' and kind_of('_Z') == 'itanium'


# --- hostile and bounded input ----------------------------------------------------------------------------

HOSTILE = [
    ('nul', '?x@@3HA\x00'),
    ('newline', '?x@@3HA\n'),
    ('space', '?x@@3HA '),
    ('del', '?x@@3HA\x7f'),
    ('latin1', '?x@@3H\u00e9'),
    ('bidi-override', '?x@\u202e@@3HA'),
    ('line-separator', '?x@\u2028@@3HA'),
    ('lone-surrogate', '?x@\ud800@@3HA'),
    ('surrogate-escape', b'?x@\xff@@3HA'.decode('utf-8', 'surrogateescape')),
]


@pytest.mark.parametrize('name', [case[1] for case in HOSTILE], ids=[case[0] for case in HOSTILE])
def test_names_outside_printable_ascii_are_plain(name):
    assert parse_decoration(name) == Decoration('plain', name)


def chain_of_length(size: int) -> str:
    """'?x@' + 'a@' * k + '@' + a tail of letters, exactly `size` characters (size >= 10)."""
    pieces = (size - 3 - 1 - 3) // 2
    name = '?x@' + 'a@' * pieces + '@' + '3HA'
    return name + 'A' * (size - len(name))


def test_the_512_character_cap_is_inclusive():
    at_cap, over_cap = chain_of_length(MAX_NAME_BYTES), chain_of_length(MAX_NAME_BYTES + 1)
    assert len(at_cap) == MAX_NAME_BYTES and len(over_cap) == MAX_NAME_BYTES + 1
    got = parse_decoration(at_cap)
    assert got.kind == 'msvc' and got.qualified_name == '::'.join(['a'] * 252 + ['x']) and got.tail.startswith('3HA')
    assert parse_decoration(over_cap) == Decoration('plain', over_cap)


def test_back_references_cannot_expand_a_name_past_the_cap():
    at_cap = '?' + 'a' * 340 + '@00@3HA'  # three pieces of 340 characters: 3 * 340 + 2 * 2 = 1,024 exactly
    over_cap = '?' + 'a' * 341 + '@00@3HA'
    bomb = '?' + 'a' * 252 + '@' + '0' * 252 + '@3HA'  # 510 characters that would expand to about 65,000
    assert MAX_QUALIFIED_NAME_CHARS == 1024
    assert parse_decoration(at_cap) == Decoration('msvc', at_cap, '::'.join(['a' * 340] * 3), '3HA')
    for name in (over_cap, bomb):
        assert len(name) <= MAX_NAME_BYTES
        assert parse_decoration(name) == Decoration('msvc', name, None, None, True)


def test_a_huge_name_is_refused_without_being_scanned():
    huge = '?' + 'a@' * 600_000
    start = time.perf_counter()
    assert parse_decoration(huge) == Decoration('plain', huge)
    assert time.perf_counter() - start < 1.0


def test_pathological_shapes_stay_cheap_and_total():
    shapes = ['?' * 512, '??' * 256, '?@' * 256, '@' * 512, '?x' + '@' * 510, '?' + 'a@' * 255, '?' + '0' * 511,
              '?x@' + '0' * 400 + '@3HA', '??0' + 'a@' * 250 + '@XZ', '_ZN' + '1a' * 250,
              '@ILT+1(' + '?x@@3HA' * 60 + ')', '??1' + 'a' * 505 + '@@XZ', '?' + 'a' * 252 + '@' + '0' * 252 + '@3HA']
    start = time.perf_counter()
    for _ in range(200):
        for shape in shapes:
            assert_invariants(shape, parse_decoration(shape))
    assert time.perf_counter() - start < 5.0  # about 0.1 s here; the bound only catches a runaway loop


# --- properties -------------------------------------------------------------------------------------------

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=300, derandomize=True,
                database=None)
MANGLING_CHARS = '?@$_.:<>()+- \t0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
mangling_text = st.text(alphabet=MANGLING_CHARS, max_size=600)
any_name = st.one_of(
    mangling_text,
    mangling_text.map(lambda text: '?' + text),
    mangling_text.map(lambda text: '??' + text),
    mangling_text.map(lambda text: '__imp_?' + text),
    mangling_text.map(lambda text: f'@ILT+7(?{text})'),
    st.text(max_size=600),
    st.binary(max_size=600).map(lambda raw: raw.decode('utf-8', 'surrogateescape')),
)


@FAST
@given(any_name)
def test_any_text_is_total_and_keeps_the_invariants(name):
    assert_invariants(name, parse_decoration(name))


@FAST
@given(st.sampled_from(KAT), st.lists(st.tuples(st.integers(0, 80), st.sampled_from(('del', 'ins', 'sub')),
                                                st.sampled_from(MANGLING_CHARS)), max_size=6))
def test_mutated_known_answers_are_total(row, edits):
    name = row.mangled
    for position, operation, char in edits:
        position %= len(name) + 1
        name = {'del': name[:position] + name[position + 1:], 'ins': name[:position] + char + name[position:],
                'sub': name[:position] + char + name[position + 1:]}[operation]
    assert_invariants(name, parse_decoration(name))


identifier = st.from_regex(r'[A-Za-z_$][A-Za-z0-9_$]{0,12}', fullmatch=True)
# the last character is a letter so that the generated tail can never look like a trailing byte count
type_encoding = st.builds(lambda body, last: body + last, st.from_regex(r'[3-9A-Z][A-Za-z0-9@_$?]{0,20}', fullmatch=True),
                          st.sampled_from('AZ'))


@FAST
@given(st.lists(identifier, min_size=1, max_size=20), type_encoding, st.sampled_from(('', '0', '1')))
def test_generated_scope_chains_round_trip_through_every_wrapper(chain, tail, structor):
    name = '?' + ('?' + structor if structor else '') + '@'.join(chain) + '@@' + tail
    pieces = [chain[0], *chain] if structor else chain
    if structor == '1':
        pieces[0] = '~' + chain[0]
    expected_name = '::'.join(reversed(pieces))
    got = parse_decoration(name)
    assert got == Decoration('msvc', name, expected_name, tail)
    for wrapped in (f'__imp_{name}', f'@ILT+99({name})', f'{name}@8'):
        facts = parse_decoration(wrapped)
        assert (facts.kind, facts.qualified_name, facts.tail, facts.complex) == (
            got.kind, got.qualified_name, got.tail, got.complex)


# --- purity -----------------------------------------------------------------------------------------------

def test_decoration_modules_use_only_the_standard_library_and_execute_nothing():
    allowed = {'__future__', 'dataclasses', 're', 'typing'}
    banned_calls = {'eval', 'exec', 'compile', '__import__', 'open', 'input'}
    for stem in ('__init__', 'kinds', 'decoration'):
        tree = ast.parse((SYMBOLS_DIR / f'{stem}.py').read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert {alias.name.split('.')[0] for alias in node.names} <= allowed, stem
            elif isinstance(node, ast.ImportFrom) and not node.level:
                assert node.module.split('.')[0] in allowed, stem
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, (stem, node.func.id)
