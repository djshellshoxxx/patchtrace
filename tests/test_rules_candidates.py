"""R3: rule candidates without bytes - features, gates, the SPEC-29 and pe_overview adapters and `propose`, on the REAL
recorded capa 9.4.0 and FLOSS 3.1.1 goldens of the synthetic `capa-api` and `floss-static` pairs
(docs/specs/program-e/YRX-integration-plan.md s7 and s9; fixtures in `tests/rules_fixtures.py`).

Pure parts (features, gates, adapters) need nothing but the repository. The tests that compile and scan a rule use the
real YARA-X in this process (the R2 tests do the same) and skip with a reason where the `rules` extra is missing; in CI
`test_rules_worker.py::test_engine_extra_is_installed_in_the_qa_matrix` fails instead, so a matrix cannot pass hollow.
Nothing here executes a target or touches the network.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import random
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import rules_fixtures as rf
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.pe_overview.models import ImportDll, ImportsInfo
from patchtrace.rules import candidates as cd
from patchtrace.rules import features as ft
from patchtrace.rules import gates as g
from patchtrace.rules.adapters import tools_delta as td
from patchtrace.rules.adapters.pe_imports import PeImports, table_of
from patchtrace.rules.contracts import (
    ApiRef,
    CapabilityFeature,
    CellResult,
    Diagnostic,
    ImportFeature,
    LintResult,
    StringFeature,
)
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import DEFAULT_LIMITS
from patchtrace.rules.ports import (
    CapabilityObservation,
    Coverage,
    ImportEntry,
    ImportTable,
    StringObservation,
)

ROOT = Path(__file__).resolve().parents[1]
KERNEL32 = 'KERNEL32.dll'
ADDED = 'PatchTrace synthetic: index %u exceeds length %u'   # the only string the newer floss-static image adds
PIECES = [ADDED[i:i + 20] for i in range(0, 28, 4)]          # seven overlapping parts of it, each 20 characters


@pytest.fixture
def bench(tmp_path):
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def engine():
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    return pytest.importorskip('patchtrace.rules.engine')


def check_for(bench, pair_name: str):
    return rf.engine_checker({side: bench.build(pair_name, side).data for side in rf.SIDES})


def sha(text: str | bytes) -> str:
    return hashlib.sha256(text if isinstance(text, bytes) else text.encode('utf-8')).hexdigest()


def observation(text: str, side: str = 'newer', *, encoding: str = 'ascii', offset: int = 0x720,
                separation: str | None = None, secret: str | None = None, linked: str = 'file-level',
                data: bytes | None = None) -> StringObservation:
    raw = data if data is not None else text.encode('utf-16-le' if encoding == 'wide' else 'latin-1')
    return StringObservation(side=side, value_sha256=sha(text), data=raw, encoding=encoding, offset=offset,
                             evidence_run_id=f'r-{side}', linked_by=linked,
                             separation=separation or f'{side}-only', secret_kind=secret)


def entry(dll: str, name: str | None, ordinal: int | None = None, slot: int | None = None) -> ImportEntry:
    return ImportEntry(dll=dll, name=name, ordinal=ordinal, delay=False, slot_rva=slot)


# --- features: escaping ----------------------------------------------------------------------------------------------

@given(st.binary(min_size=1, max_size=256))
def test_escape_is_injective_and_satisfies_the_contract(data):
    text = ft.escape_text(data)
    assert ft.unescape_text(text) == data
    feature = StringFeature(included=False, side='newer', value_sha256='a' * 64, length=len(data), text=text,
                            encoding='ascii', offset=0, evidence_run_id='r', linked_by='file-level',
                            separation='newer-only')
    assert feature.text.isascii() and feature.text.isprintable()


@pytest.mark.parametrize('data', [b'"', b'\\', b'\n\r\t', b'\x00', b'*/ }', b'\xe2\x80\xae', b'"; condition: true //',
                                  b'\\x41', b'say "hi"\\'],
                         ids=['quote', 'backslash', 'whitespace', 'nul', 'comment-end', 'bidi', 'break-out',
                              'looks-escaped', 'quote-backslash'])
def test_escaped_text_cannot_close_the_string_or_add_a_line(data):
    text = ft.escape_text(data)
    unit = r'(?:[ !#-\[\]-~]|\\(?:["\\nrt]|x[0-9a-f]{2}))'
    assert re.fullmatch(unit + '+', text), text
    assert '\n' not in text and ft.unescape_text(text) == data


HOSTILE = [b'"', b'\\', b'\n\r\t', b'\x00\x01\xfe\xff', b'*/ }', b'"; condition: true //', b'\\x41', b'say "hi"\\',
           b'ASCII and \xe2\x80\xae bidi']


@pytest.mark.parametrize('data', HOSTILE, ids=[f'h{i}' for i in range(len(HOSTILE))])
def test_the_engine_reads_escaped_text_as_exactly_the_bytes_it_came_from(engine, data):
    import yara_x
    rules = yara_x.compile(f'rule t {{ strings: $a = "{ft.escape_text(data)}" ascii condition: $a }}')
    scanner = yara_x.Scanner(rules)
    padded = b'..' + data + b'..'
    assert [m.offset for p in scanner.scan(padded).matching_rules[0].patterns for m in p.matches] == [2]
    assert not scanner.scan(b'..' + data[:-1] + b'..').matching_rules   # one byte short is not a match


def test_escaped_latin1_text_with_the_wide_modifier_matches_utf16le(engine):
    import yara_x
    text = 'A\xe9\xff'
    rules = yara_x.compile(f'rule t {{ strings: $a = "{ft.escape_text(text.encode("latin-1"))}" wide condition: $a }}')
    assert yara_x.Scanner(rules).scan(b'..' + text.encode('utf-16-le')).matching_rules


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=1, max_size=64))
def test_the_engine_agrees_with_the_escape_for_any_bytes(data):
    yara_x = pytest.importorskip('yara_x', reason='YARA-X is not installed')
    rules = yara_x.compile(f'rule t {{ strings: $a = "{ft.escape_text(data)}" condition: $a }}')
    assert yara_x.Scanner(rules).scan(b'<' + data + b'>').matching_rules


# --- features: strings -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize('item,expected', [
    (observation('PatchTrace marker'), ('PatchTrace marker', 'ascii', 17)),
    (observation('A\xe9', encoding='wide'), (r'A\xe9', 'wide', 2)),
    (observation('say "hi"'), (r'say \"hi\"', 'ascii', 8)),
], ids=['ascii', 'wide-latin1', 'quote'])
def test_string_conversion(item, expected):
    built = ft.string_features([item])
    (feature,) = built.features
    assert (feature.text, feature.encoding, feature.length) == expected and built.notes == ()
    assert feature.included is False and feature.linked_by == 'file-level'


@pytest.mark.parametrize('item,note', [
    (observation('x', encoding='wide', data='\u20ac'.encode('utf-16-le')), 'string-not-expressible:1'),
    (observation('x', encoding='wide', data=b'a\x00b'), 'string-not-expressible:1'),
    (observation('x', data=b''), 'string-unverified:1'),
    (observation('x' * 257), 'string-size:1'),
    (observation('AKIAIOSFODNN7EXAMPLE', secret='aws-access-key'), 'string-secret:1'),
    (observation('contradiction', separation='older-only'), 'string-contradiction:1'),
    (StringObservation(side='newer', value_sha256='a' * 64, data=b'text', encoding='ascii', offset=1,
                       evidence_run_id='r\x07', linked_by='file-level', separation='newer-only'), 'string-invalid:1'),
], ids=['wide-nonlatin', 'wide-odd', 'unverified', 'too-long', 'secret', 'contradiction', 'invalid-run-id'])
def test_strings_that_cannot_seed_a_rule_are_counted_not_lost(item, note):
    built = ft.string_features([item])
    assert built.features == () and built.notes == (note,)


def test_the_text_pattern_size_limit_is_inclusive():
    assert [f.length for f in ft.string_features([observation('x' * 256)]).features] == [256]
    assert ft.string_features([observation('x' * 257)]).notes == ('string-size:1',)


def test_a_secret_the_adapter_missed_is_caught_by_the_second_line():
    from patchtrace.intelligence.tools.common import secret_kind
    leaked = observation('aws_access_key_id=AKIAIOSFODNN7EXAMPLE')   # the adapter did not flag it
    built = ft.string_features([leaked, observation('harmless text here')], detect_secret=secret_kind)
    assert [f.text for f in built.features] == ['harmless text here'] and built.notes == ('string-secret:1',)


def test_duplicate_strings_collapse_to_the_lowest_offset_and_order_is_canonical():
    items = [observation('beta string', offset=0x900), observation('alpha string', offset=0x800),
             observation('beta string', offset=0x700), observation('alpha string', side='older', offset=0x100,
                                                                   separation='older-only')]
    built = ft.string_features(items)
    assert [(f.side, f.text, f.offset) for f in built.features] == [
        ('newer', 'beta string', 0x700), ('newer', 'alpha string', 0x800), ('older', 'alpha string', 0x100)]


# --- features: imports -----------------------------------------------------------------------------------------------

def table(*entries: ImportEntry) -> ImportTable:
    return ImportTable(tuple(entries))


def test_import_delta_both_directions_and_both_sides_hidden():
    older = table(entry(KERNEL32, 'A'), entry(KERNEL32, 'Shared'), entry('USER32.dll', 'Old'))
    newer = table(entry('kernel32.DLL', 'shared'.title()), entry(KERNEL32, 'B'), entry(KERNEL32, 'Shared'))
    built = ft.import_features(older, newer)
    assert [(f.dll, f.name, f.separation) for f in built.features] == [
        (KERNEL32, 'A', 'older-only'), (KERNEL32, 'B', 'newer-only'), ('USER32.dll', 'Old', 'older-only')]
    assert built.notes == () and not any(f.included for f in built.features)


def test_the_loader_compares_dll_names_case_insensitively():
    built = ft.import_features(table(entry('KERNEL32.dll', 'F')), table(entry('kernel32.DLL', 'F')))
    assert built.features == ()


def test_referenced_imports_present_in_both_builds_are_shown_but_never_separating():
    both = table(entry(KERNEL32, 'GetProcAddress'))
    built = ft.import_features(both, both, {(KERNEL32.lower(), 'GetProcAddress')})
    (feature,) = built.features
    assert feature.separation == 'both-sides' and feature.name == 'GetProcAddress'


def test_an_unavailable_table_makes_the_other_side_unknown_not_only_it():
    for older, newer in ((None, table(entry(KERNEL32, 'F'))), (table(entry(KERNEL32, 'F')), None)):
        assert [f.separation for f in ft.import_features(older, newer).features] == ['unknown']
    assert ft.import_features(None, None).features == ()


def test_unreferenced_delta_imports_are_capped_but_referenced_ones_survive():
    names = [f'Fn{i:03d}' for i in range(ft.OFFERED_IMPORTS + 5)]
    newer = table(*(entry(KERNEL32, n) for n in names))
    keep = {(KERNEL32.lower(), 'Fn020')}
    built = ft.import_features(table(), newer, keep)
    assert len(built.features) == ft.OFFERED_IMPORTS + 1 and built.notes == ('imports-not-offered:4',)
    assert 'Fn020' in {f.name for f in built.features}


def test_ordinal_and_invalid_imports():
    built = ft.import_features(table(), table(entry('MYLIB.dll', None, 12), entry('MYLIB.dll', None, 0)))
    assert [(f.ordinal, f.name) for f in built.features] == [(12, None)] and built.notes == ('import-invalid:1',)


# --- features: capabilities ------------------------------------------------------------------------------------------

def capability(rule: str = 'terminate process', classification: str = 'removed-with-code', **kw):
    return CapabilityObservation(rule_id=rule, namespace=kw.get('namespace', 'host-interaction/process'),
                                 attack=kw.get('attack', ()), classification=classification,
                                 api_gates=kw.get('api_gates', ()))


def test_capability_features_are_sorted_deduplicated_and_bounded():
    gates = tuple(ApiRef(dll=KERNEL32, name=f'Api{i:02d}') for i in range(12))
    built = ft.capability_features([
        capability('b rule', 'newly-introduced', attack=tuple(f'T{1000 + i}' for i in range(20)), api_gates=gates),
        capability('a rule'), capability('a rule'), capability('bad\nrule')])
    assert [(f.rule_id, f.separation) for f in built.features] == [('a rule', 'older-only'),
                                                                   ('b rule', 'newer-only')]
    assert len(built.features[1].attack) == ft.ATTACK_IDS and len(built.features[1].api_gates) == ft.API_GATES
    assert built.notes == ('capability-invalid:1',)


def test_a_rule_that_is_removed_and_introduced_stays_two_features():
    built = ft.capability_features([capability('moved', 'newly-introduced'), capability('moved')])
    assert [f.classification for f in built.features] == ['newly-introduced', 'removed-with-code']


@settings(max_examples=40, deadline=None)
@given(st.permutations(range(6)))
def test_canonical_order_ignores_the_order_the_ports_used(order):
    items = [observation(f'string number {i}', offset=0x700 + 16 * i) for i in range(6)]
    shuffled = [items[i] for i in order]
    assert ft.string_features(shuffled).features == ft.string_features(items).features


# --- gates -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('literal,run,state', [(16, 6, 'pass'), (15, 6, 'fail'), (16, 5, 'fail'), (200, 5, 'fail'),
                                               (20, 15, 'pass')],
                         ids=['edge', 'one-short', 'run-short', 'long-but-choppy', 'term'])
def test_gate_len(literal, run, state):
    gate = g.long_enough(literal, run)
    assert (gate.gate_id, gate.state, gate.measured) == ('len', state, literal)
    assert g.sentence(gate) == f'Long enough: {literal} literal bytes, longest run {run}'


@pytest.mark.parametrize('length,literal,state,percent', [(24, 20, 'pass', 16), (10, 6, 'pass', 40),
                                                          (10, 5, 'fail', 50), (100, 59, 'fail', 41),
                                                          (100, 60, 'pass', 40)],
                         ids=['term', 'edge-small', 'half', 'just-over', 'edge-large'])
def test_gate_wild(length, literal, state, percent):
    gate = g.not_mostly_wildcards(length, literal)
    assert (gate.state, gate.measured) == (state, percent)


@pytest.mark.parametrize('hits,state', [(None, 'unknown'), (0, 'fail'), (1, 'pass'), (2, 'fail')],
                         ids=['not-counted', 'absent', 'one', 'many'])
def test_gate_uniq(hits, state):
    assert g.one_place(hits).state == state


HIT = CellResult(state='hit', hits=1, offsets=(589,), rvas=(0x104d,))
MISS = CellResult(state='no-hit', hits=0)
SKIPPED = CellResult(state='not-scanned', reason='not-pe')
TIMED = CellResult(state='timeout')


@pytest.mark.parametrize('own,other,expected,state', [
    (HIT, MISS, None, 'pass'), (HIT, MISS, 0x104d, 'pass'), (HIT, MISS, 0x2000, 'fail'),
    (HIT, HIT, None, 'fail'), (MISS, MISS, None, 'fail'), (MISS, HIT, None, 'fail'),
    (SKIPPED, MISS, None, 'unknown'), (HIT, SKIPPED, None, 'unknown'), (TIMED, MISS, None, 'unknown'),
    (None, MISS, None, 'unknown')],
    ids=['pass', 'pass-at-rva', 'wrong-rva', 'both-hit', 'neither', 'reversed', 'own-skipped', 'other-skipped',
         'own-timeout', 'no-scan'])
def test_gate_sep(own, other, expected, state):
    assert g.separates(own, other, expected).state == state


def test_an_unscanned_build_is_never_a_clean_build():
    gate = g.separates(HIT, SKIPPED)
    assert gate.state == 'unknown' and gate.measured is None and 'not-pe' in gate.detail


def diagnostic(code: str, title: str = 't') -> Diagnostic:
    return Diagnostic(code=code, title=title, line=1, column=1)


@pytest.mark.parametrize('lint,state,detail', [
    (None, 'unknown', 'the rule was not compiled'),
    (LintResult(name='r', ok=True), 'pass', 'no warnings'),
    (LintResult(name='r', ok=True, warnings=(diagnostic('text_as_hex'),)), 'pass', 'only the style note text_as_hex'),
    (LintResult(name='r', ok=True, warnings=(diagnostic('slow_pattern', 'slow'),)), 'fail', 'slow_pattern: slow'),
    (LintResult(name='r', ok=False, errors=(diagnostic('E040', 'bad tag'),)), 'fail', 'E040: bad tag')],
    ids=['not-compiled', 'clean', 'style-note', 'warning', 'error'])
def test_gate_compile(lint, state, detail):
    gate = g.compiles(lint)
    assert (gate.state, gate.detail) == (state, detail)


def test_gate_secret_uses_the_detector_on_the_real_bytes():
    from patchtrace.intelligence.tools.common import secret_kind
    assert g.no_secret([b'harmless'], secret_kind).state == 'pass'
    gate = g.no_secret([b'harmless', b'key AKIAIOSFODNN7EXAMPLE end'], secret_kind)
    assert (gate.state, gate.measured) == ('fail', 1)


@pytest.mark.parametrize('flags,state', [(None, 'unknown'), ((), 'pass'), (('heuristic-only',), 'pass'),
                                         (('toolchain-changed',), 'fail'), (('packed', 'protected'), 'fail'),
                                         (('environment-unknown',), 'unknown')],
                         ids=['not-run', 'clean', 'weak', 'changed', 'packed', 'unknown'])
def test_gate_dist(flags, state):
    assert g.one_toolchain(flags).state == state


def test_gate_elig():
    assert g.eligibility('material', False).state == 'pass'
    waived = g.eligibility('review', True)
    assert (waived.state, waived.measured) == ('waived', 'confirmed')
    assert g.eligibility('review', False).state == 'fail' and g.eligibility('unknown', False).measured == 'unknown'


def gate(gate_id: str, state: str) -> g.Gate:
    return g.Gate(gate_id=gate_id, state=state)


def test_first_blocking_prefers_a_failure_to_an_unknown_and_unknown_blocks_too():
    gates = [gate('elig', 'waived'), gate('len', 'pass'), gate('sep', 'unknown'), gate('compile', 'fail'),
             gate('dist', 'fail')]
    assert g.first_blocking(gates).gate_id == 'compile'          # the failure explains the unknown before it
    assert g.first_blocking([*gates[:3], gate('compile', 'pass')]).gate_id == 'sep'
    assert g.first_blocking([gate('len', 'fail'), gate('sep', 'fail')]).gate_id == 'len'
    assert g.first_blocking([gate('elig', 'fail'), gate('dist', 'fail'), gate('compile', 'waived')]) is None


# --- adapter: pe_imports ---------------------------------------------------------------------------------------------

def test_pe_imports_reads_both_real_tables(bench):
    pair = rf.capa_pair(bench, 'term')
    source = PeImports({side: bench.build('capa-api', side).overview for side in rf.SIDES})
    older, newer = source.imports(pair, 'older'), source.imports(pair, 'newer')
    assert sorted(e.name for e in older.entries) == ['GetComputerNameA', 'GetModuleHandleA', 'GetProcAddress',
                                                    'TerminateProcess']
    assert sorted(e.name for e in newer.entries) == ['GetComputerNameA', 'GetEnvironmentVariableA',
                                                    'GetModuleHandleA', 'GetProcAddress', 'WriteFile']
    assert {e.dll for e in older.entries} == {KERNEL32} and all(e.slot_rva is None and not e.delay
                                                                for e in older.entries)


def test_pe_imports_refuses_a_table_of_another_file(bench):
    pair = rf.capa_pair(bench, 'term')
    wrong = PeImports({'older': bench.build('capa-api', 'newer').overview})
    with pytest.raises(RuleError) as caught:
        wrong.imports(pair, 'older')
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-STALE', 'artifact-moved')
    assert PeImports({}).imports(pair, 'older') is None


def test_pe_imports_unreadable_tables_are_unavailable_not_empty(bench):
    overview = bench.build('capa-api', 'older').overview
    base = overview.imports
    dll = base.dlls[0]
    for bad in (dataclasses.replace(base, truncated=True),
                dataclasses.replace(base, dlls=(dataclasses.replace(dll, truncated=True),)),
                dataclasses.replace(base, dlls=(dataclasses.replace(dll, functions=('<unreadable @ 0x5000>',)),)),
                dataclasses.replace(base, dlls=(dataclasses.replace(dll, name='<unreadable name @ 0x40>'),))):
        assert table_of(dataclasses.replace(overview, imports=bad)) is None
    assert table_of(dataclasses.replace(overview, imports=None)) is None   # a directory the headers declare


def test_pe_imports_a_declared_empty_directory_is_a_known_empty_table(bench):
    overview = bench.build('capa-api', 'older').overview
    directories = tuple(dataclasses.replace(d, present=False, rva=0, size=0) if d.name == 'Import' else d
                        for d in overview.data_directories)
    assert table_of(dataclasses.replace(overview, imports=None, data_directories=directories)) == ImportTable(())


def test_pe_imports_ordinals():
    info = ImportsInfo((ImportDll('MYLIB.dll', ('#12', 'Name', '#0'), 3, False),), 1, 3, False)
    entries = table_of(SimpleNamespace(imports=info)).entries
    assert [(e.name, e.ordinal) for e in entries] == [(None, 12), ('Name', None), (None, 0)]


# --- adapter: FLOSS strings ------------------------------------------------------------------------------------------

def floss_source(bench, delta=None):
    delta = delta or rf.floss_delta(bench)
    return td.FlossStrings(delta, {side: bench.build('floss-static', side).reader for side in rf.SIDES}), delta


def test_floss_delta_gives_the_exact_bytes_of_the_added_and_removed_strings(bench):
    source, _ = floss_source(bench)
    channel = source.strings(rf.strings_pair(bench))
    assert channel.coverage == rf.COMPLETE
    got = {(o.side, o.separation): o for o in channel.items}
    assert set(got) == {('newer', 'newer-only'), ('older', 'older-only')}
    added, removed = got[('newer', 'newer-only')], got[('older', 'older-only')]
    assert added.data == b'PatchTrace synthetic: index %u exceeds length %u'
    assert removed.data == b'PatchTrace synthetic: debug dump of internal state'
    assert (added.encoding, added.linked_by, added.secret_kind) == ('ascii', 'file-level', None)
    assert added.evidence_run_id == 'r-newer' and removed.evidence_run_id == 'r-older'
    for item in (added, removed):   # the offset really holds the bytes
        assert bench.build('floss-static', item.side).data[item.offset:item.offset + len(item.data)] == item.data
        assert item.value_sha256 == sha(item.data.decode())


def test_floss_unchanged_secret_and_wide_strings_are_not_offered(bench):
    source, delta = floss_source(bench)
    texts = {o.data for o in source.strings(rf.strings_pair(bench)).items}
    assert not any(b'AKIA' in t or b'wide' in t for t in texts)
    assert delta.counts['strings_unchanged'] >= 3


def test_floss_secret_strings_are_flagged_and_their_bytes_never_read(bench):
    delta = rf.floss_delta(bench)
    marked = tuple(c.model_copy(update={'secret_kind': 'aws-access-key'}) if c.change == 'added' else c
                   for c in delta.strings)
    reads = []

    class Spy:
        def __init__(self, reader):
            self.sha256 = reader.sha256
            self._reader = reader

        def read(self, offset, length, *, clip=True):
            reads.append((self.sha256, offset))
            return self._reader.read(offset, length, clip=clip)

    source = td.FlossStrings(delta.model_copy(update={'strings': marked}),
                             {side: Spy(bench.build('floss-static', side).reader) for side in rf.SIDES})
    items = {o.separation: o for o in source.strings(rf.strings_pair(bench)).items}
    assert items['newer-only'].secret_kind == 'aws-access-key' and items['newer-only'].data == b''
    newer = bench.build('floss-static', 'newer').sha256
    assert not any(sha_ == newer for sha_, _ in reads)   # the secret's artifact was not even read
    assert items['older-only'].data.startswith(b'PatchTrace')


def test_floss_bytes_that_do_not_match_the_tools_claim_stay_unverified(bench):
    delta = rf.floss_delta(bench)

    class Liar:
        sha256 = bench.build('floss-static', 'newer').sha256

        def read(self, offset, length, *, clip=True):
            return b'x' * length

    source = td.FlossStrings(delta, {'newer': Liar()})
    items = {o.side: o for o in source.strings(rf.strings_pair(bench)).items}
    assert items['newer'].data == b'' and items['older'].data == b''   # no reader for older: nothing re-read


def test_floss_unreadable_range_is_unverified_not_an_error(bench):
    delta = rf.floss_delta(bench)
    moved = tuple(c.model_copy(update={'newer': tuple(
        link.model_copy(update={'file_offset': 10**9}) for link in c.newer)}) if c.change == 'added' else c
                  for c in delta.strings)
    source = td.FlossStrings(delta.model_copy(update={'strings': moved}),
                             {side: bench.build('floss-static', side).reader for side in rf.SIDES})
    item = next(o for o in source.strings(rf.strings_pair(bench)).items if o.side == 'newer')
    assert item.data == b'' and item.offset == 10**9


def test_floss_oversize_strings_are_read_only_far_enough_to_be_refused(bench):
    delta = rf.floss_delta(bench)
    long = tuple(c.model_copy(update={'length': 5000}) if c.change == 'added' else c for c in delta.strings)
    asked = []

    class Wide:
        sha256 = bench.build('floss-static', 'newer').sha256

        def read(self, offset, length, *, clip=True):
            asked.append(length)
            return b'x' * length

    source = td.FlossStrings(delta.model_copy(update={'strings': long}), {'newer': Wide()})
    item = next(o for o in source.strings(rf.strings_pair(bench)).items if o.side == 'newer')
    assert asked == [td.READ_CAP] and len(item.data) == td.READ_CAP
    assert ft.string_features([item]).notes == ('string-size:1',)


def test_floss_only_static_ascii_and_wide_strings_are_offered(bench):
    delta = rf.floss_delta(bench)
    change = next(c for c in delta.strings if c.change == 'added')
    variants = {'decoded': change.model_copy(update={'newer_types': ('decoded',)}),
                'utf8': change.model_copy(update={'newer_encodings': ('UTF-8',)}),
                'mixed': change.model_copy(update={'newer_encodings': ('ASCII', 'UTF-16LE')}),
                'static-and-language': change.model_copy(update={'newer_types': ('language', 'static')})}
    readers = {side: bench.build('floss-static', side).reader for side in rf.SIDES}
    for name, variant in variants.items():
        found = td.FlossStrings(delta.model_copy(update={'strings': (variant,)}), readers).strings(
            rf.strings_pair(bench)).items
        assert bool(found) == (name == 'static-and-language'), name


def test_floss_indeterminate_strings_are_unknown_not_added(bench):
    delta = rf.floss_delta(bench)
    change = next(c for c in delta.strings if c.change == 'added').model_copy(update={'change': 'indeterminate'})
    source = td.FlossStrings(delta.model_copy(update={'strings': (change,)}),
                             {side: bench.build('floss-static', side).reader for side in rf.SIDES})
    (item,) = source.strings(rf.strings_pair(bench)).items
    assert (item.side, item.separation) == ('newer', 'unknown')


def test_floss_channel_states_and_refusals(bench):
    pair = rf.strings_pair(bench)
    readers = {side: bench.build('floss-static', side).reader for side in rf.SIDES}
    delta = rf.floss_delta(bench)
    assert td.FlossStrings(None, readers).strings(pair).coverage == rf.UNAVAILABLE
    broken = delta.model_copy(update={'comparable': False, 'reasons': ('x',), 'strings': ()})
    assert td.FlossStrings(broken, readers).strings(pair).coverage == rf.UNAVAILABLE
    with pytest.raises(RuleError) as caught:
        td.FlossStrings(delta.model_copy(update={'engine': 'capa'}), readers).strings(pair)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INPUT', 'wrong-engine')
    swapped = {'older': readers['newer'], 'newer': readers['older']}   # links fit the pair, the artifacts do not
    with pytest.raises(RuleError) as artifact:
        td.FlossStrings(delta, swapped).strings(pair)
    assert (artifact.value.code, artifact.value.reason) == ('PT-RULE-STALE', 'artifact-moved')
    other = rf.capa_pair(bench, 'term')   # another pair of builds: the readers and the links no longer fit
    with pytest.raises(RuleError) as stale:
        td.FlossStrings(delta, readers).strings(other)
    assert stale.value.code == 'PT-RULE-STALE'


# --- adapter: capa capabilities --------------------------------------------------------------------------------------

def capa_source(bench, world=None, *, apis=True, imports=True, evidence=True):
    world = world or rf.capa_world(bench)
    tables = PeImports({side: bench.build('capa-api', side).overview for side in rf.SIDES})
    return td.CapaCapabilities(
        world.delta, evidence=world.evidence if evidence else None,
        apis={side: td.capa_api_names(world.raw[side]) for side in rf.SIDES} if apis else None,
        imports=tables if imports else None), world


@pytest.mark.parametrize('which,expected', [
    ('term', [('terminate process', 'host-interaction/process/terminate', 'removed-with-code', (),
               [(KERNEL32, 'TerminateProcess')])]),
    ('log', [('write file on Windows', 'host-interaction/file-system/write', 'newly-introduced', (),
              [(KERNEL32, 'WriteFile')])]),
    ('env', [('query environment variable', 'host-interaction/environment-variable', 'newly-introduced', ('T1082',),
              [(KERNEL32, 'GetEnvironmentVariableA')])]),
], ids=['term', 'log', 'env'])
def test_capa_capabilities_follow_the_pairs_own_function(bench, which, expected):
    source, _ = capa_source(bench)
    channel = source.capabilities(rf.capa_pair(bench, which))
    assert channel.coverage == rf.COMPLETE
    assert [(c.rule_id, c.namespace, c.classification, c.attack, [(a.dll, a.name) for a in c.api_gates])
            for c in channel.items] == expected


def test_capa_unchanged_unlocalized_and_foreign_capabilities_are_never_offered(bench):
    source, world = capa_source(bench)
    offered = {c.rule_id for which in ('term', 'log', 'env') for c in source.capabilities(
        rf.capa_pair(bench, which)).items}
    assert offered == {'terminate process', 'write file on Windows', 'query environment variable'}
    assert {c.rule_id for c in world.delta.capabilities} - offered >= {
        'get hostname', 'contain a thread local storage (.tls) section', 'encode data using XOR'}


def test_capa_capabilities_lose_attributes_not_the_capability_when_a_helper_is_missing(bench):
    pair = rf.capa_pair(bench, 'env')

    def offered(**kw):
        (item,) = capa_source(bench, **kw)[0].capabilities(pair).items
        return bool(item.api_gates), item.attack
    assert offered() == (True, ('T1082',))
    assert offered(apis=False) == (False, ('T1082',))      # no raw capa document: no API names
    assert offered(imports=False) == (False, ('T1082',))   # no import table: no name may be turned into a gate
    assert offered(evidence=False) == (True, ())           # no normalised set: no ATT&CK ids


def test_capa_channel_states_and_refusals(bench):
    source, world = capa_source(bench)
    pair = rf.capa_pair(bench, 'term')
    assert td.CapaCapabilities(None).capabilities(pair).coverage == rf.UNAVAILABLE
    no_pairing = world.delta.model_copy(update={'pairing': 'unavailable'})
    assert td.CapaCapabilities(no_pairing).capabilities(pair).coverage == rf.UNAVAILABLE   # classes are 'unknown'
    with pytest.raises(RuleError) as caught:
        td.CapaCapabilities(world.delta.model_copy(update={'engine': 'floss'})).capabilities(pair)
    assert caught.value.reason == 'wrong-engine'
    with pytest.raises(RuleError) as stale:
        source.capabilities(rf.strings_pair(bench))
    assert stale.value.code == 'PT-RULE-STALE'


@pytest.mark.parametrize('spelling,expected', [
    ('TerminateProcess', ('KERNEL32.dll', 'TerminateProcess')), ('GetEnvironmentVariable', (KERNEL32, 'GetEnvironmentVariableA')),
    ('MessageBox', ('USER32.dll', 'MessageBoxW')), ('kernel32.WriteFile', (KERNEL32, 'WriteFile')),
    ('user32.WriteFile', None), ('CreateFile', None), ('Missing', None), ('Shared', None),
    ('Dual', (KERNEL32, 'Dual'))],
    ids=['exact', 'a-suffix', 'w-suffix', 'qualified', 'wrong-dll', 'a-and-w', 'absent', 'two-dlls', 'exact-wins'])
def test_resolve_api_only_returns_imports_the_build_really_has(spelling, expected):
    imports = table(entry(KERNEL32, 'TerminateProcess'), entry(KERNEL32, 'GetEnvironmentVariableA'),
                    entry('USER32.dll', 'MessageBoxW'), entry(KERNEL32, 'WriteFile'),
                    entry(KERNEL32, 'CreateFileA'), entry(KERNEL32, 'CreateFileW'),
                    entry(KERNEL32, 'Shared'), entry('OTHER.dll', 'Shared'), entry('X.dll', None, 7),
                    entry(KERNEL32, 'Dual'), entry(KERNEL32, 'DualA'))
    got = td.resolve_api(spelling, imports)
    assert (None if got is None else (got.dll, got.name)) == expected


def test_capa_api_names_from_the_recorded_document(bench):
    world = rf.capa_world(bench)
    assert td.capa_api_names(world.raw['older']) == {('get hostname', 0x1030): ('GetComputerName',),
                                                    ('terminate process', 0x104d): ('TerminateProcess',)}
    newer = td.capa_api_names(world.raw['newer'])
    assert newer[('write file on Windows', 0x1096)] == ('WriteFile',)
    assert not any(rule == 'link function at runtime on Windows' for rule, _ in newer)   # instruction scope
    document = json.loads(world.raw['older'])
    document['rules']['terminate process']['meta']['is_subscope_rule'] = True   # capa lists these only as parts
    subscope = td.capa_api_names(json.dumps(document).encode())
    assert ('terminate process', 0x104d) not in subscope and ('get hostname', 0x1030) in subscope
    for broken in (b'', b'{"meta": 1, "rules": {}}', world.raw['older'][:-40]):
        with pytest.raises(RuleError) as caught:
            td.capa_api_names(broken)
        assert (caught.value.code, caught.value.reason) == ('PT-RULE-INTEGRITY', 'capa-document')


# --- propose ---------------------------------------------------------------------------------------------------------

def propose_capa(bench, which: str, **kw):
    source, _ = capa_source(bench)
    sources = cd.Sources(capabilities=source, imports=PeImports(
        {side: bench.build('capa-api', side).overview for side in rf.SIDES}))
    return cd.propose(rf.capa_pair(bench, which), sources,
                      check=check_for(bench, 'capa-api'), **kw)


def summary(candidate):
    label = {StringFeature: lambda f: f.text, ImportFeature: lambda f: f.name, CapabilityFeature: lambda f: f.rule_id}
    return [(type(f).__name__, label[type(f)](f), f.included) for f in candidate.features]


def test_removed_function_proposes_one_older_rule_from_its_import_and_capability(bench, engine):
    proposal = propose_capa(bench, 'term')
    (candidate,) = proposal.candidates
    assert candidate.direction == 'older' and candidate.rule_name.endswith('_older') and not candidate.unvetted
    assert summary(candidate) == [('ImportFeature', 'TerminateProcess', True),
                                  ('CapabilityFeature', 'terminate process', True)]
    assert [(x.gate_id, x.state) for x in candidate.gates] == [('elig', 'pass'), ('sep', 'pass'), ('compile', 'pass'),
                                                               ('secret', 'pass'), ('dist', 'unknown')]
    assert 'pe.imports("KERNEL32.dll", "TerminateProcess")' in candidate.rule_text
    assert candidate.engine.decoder == 'none' and candidate.compile_warnings == ()
    assert proposal.rejected == () and proposal.notes == () and proposal.first_failure() is None
    assert {c.channel: c.coverage for c in proposal.coverage} == {
        'strings': rf.UNAVAILABLE, 'capabilities': rf.COMPLETE, 'imports': rf.COMPLETE, 'bytes': rf.UNAVAILABLE}


def test_the_rule_describes_its_own_build_only(bench, engine):
    (candidate,) = propose_capa(bench, 'term').candidates
    older, newer = (bench.build('capa-api', s).data for s in rf.SIDES)
    check = rf.engine_checker({'older': older, 'newer': newer})
    verdict = check(candidate.rule_name, candidate.rule_text, candidate.source, 'older')
    assert (verdict.own.state, verdict.other.state) == ('hit', 'no-hit')


def test_modified_function_older_side_has_nothing_to_say_newer_side_gates_on_its_api(bench, engine):
    proposal = propose_capa(bench, 'log')
    assert [(r.direction, r.reason) for r in proposal.rejected] == [('older', 'no-feature')]
    (candidate,) = proposal.candidates
    assert candidate.direction == 'newer'
    # GetEnvironmentVariableA is newer-only too, but it belongs to another function: offered, never ticked
    assert summary(candidate) == [('ImportFeature', 'GetEnvironmentVariableA', False),
                                  ('ImportFeature', 'WriteFile', True),
                                  ('CapabilityFeature', 'write file on Windows', True)]
    assert 'GetEnvironmentVariableA' not in candidate.rule_text and '"WriteFile"' in candidate.rule_text


def test_added_function_proposes_one_newer_rule(bench, engine):
    proposal = propose_capa(bench, 'env')
    (candidate,) = proposal.candidates
    assert candidate.direction == 'newer' and proposal.rejected == ()
    assert [f for f in candidate.features if f.included and isinstance(f, ImportFeature)][0].name == \
        'GetEnvironmentVariableA'
    assert candidate.source.category == 'added' and candidate.source.older is None


def test_directions_are_filtered_and_validated(bench, engine):
    modified = propose_capa(bench, 'log', directions=('newer',))
    assert [c.direction for c in modified.candidates] == ['newer'] and modified.rejected == ()
    with pytest.raises(RuleError) as caught:
        propose_capa(bench, 'term', directions=('newer',))   # a removed function has no newer build to describe
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INPUT', 'direction')


def test_strings_of_the_floss_pair_anchor_one_rule_per_build(bench, engine):
    source, _ = floss_source(bench)
    result = cd.propose(rf.strings_pair(bench), cd.Sources(strings=source),
                        check=check_for(bench, 'floss-static'))
    by_direction = {c.direction: c for c in result.candidates}
    assert set(by_direction) == {'older', 'newer'} and result.rejected == ()
    assert summary(by_direction['older']) == [('StringFeature', 'PatchTrace synthetic: debug dump of internal state',
                                               True)]
    assert summary(by_direction['newer']) == [('StringFeature', 'PatchTrace synthetic: index %u exceeds length %u',
                                               True)]
    older = by_direction['older']
    assert older.lineage_id != by_direction['newer'].lineage_id and older.candidate_id != by_direction['newer'].candidate_id
    assert [(x.gate_id, x.state, x.measured) for x in older.gates][:2] == [('elig', 'pass', 'material'),
                                                                           ('len', 'pass', 50)]
    assert '$s1 = "PatchTrace synthetic: debug dump of internal state" ascii' in older.rule_text
    assert older.features[0].linked_by == 'file-level'


def test_a_change_that_is_not_material_proposes_nothing_unless_the_analyst_confirms(bench, engine):
    source, _ = floss_source(bench)
    for materiality in ('review', 'unknown', 'cosmetic'):
        with pytest.raises(RuleError) as caught:
            cd.propose(rf.strings_pair(bench, materiality=materiality), cd.Sources(strings=source),
                       check=check_for(bench, 'floss-static'))
        assert (caught.value.code, caught.value.reason) == ('PT-RULE-INPUT', 'not-material')
    confirmed = cd.propose(rf.strings_pair(bench, materiality='review', confirmed=True), cd.Sources(strings=source),
                           check=check_for(bench, 'floss-static'))
    assert confirmed.candidates and all(c.unvetted for c in confirmed.candidates)
    assert all(c.gates[0].state == 'waived' for c in confirmed.candidates)


def test_missing_channels_are_reported_as_unavailable_never_as_empty(bench, engine):
    result = cd.propose(rf.capa_pair(bench, 'term'), cd.Sources(),
                        check=check_for(bench, 'capa-api'))
    assert result.candidates == () and [r.reason for r in result.rejected] == ['no-feature']
    assert all(c.coverage == rf.UNAVAILABLE for c in result.coverage)
    assert result.first_failure() == 'No feature separates the older build'


def candidate_for(bench, observations, **kw):
    return cd.propose(rf.strings_pair(bench), cd.Sources(strings=rf.FakeStrings(observations)),
                      check=check_for(bench, 'floss-static'), **kw)


def test_imports_of_a_build_with_an_unavailable_counterpart_are_counted_not_offered(bench, engine):
    only_older = rf.FakeImports(table(entry(KERNEL32, 'OnlyHere')), None)
    result = cd.propose(rf.strings_pair(bench), cd.Sources(imports=only_older),
                        check=check_for(bench, 'floss-static'))
    assert result.candidates == () and result.notes == ('imports-unknown:1',)
    assert {c.channel: c.coverage for c in result.coverage}['imports'] == Coverage('complete', 'unavailable')


def test_secret_strings_never_reach_rule_text(bench, engine):
    secret = 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE'
    result = candidate_for(bench, [observation('PatchTrace synthetic: index %u exceeds length %u'),
                                   observation(secret, offset=0x740), observation('flagged', secret='jwt')],
                           directions=('newer',))
    (candidate,) = result.candidates
    assert 'AKIA' not in candidate.rule_text and 'flagged' not in candidate.rule_text
    assert result.notes == ('string-secret:2',)
    assert {x.gate_id: x.state for x in candidate.gates}['secret'] == 'pass'


def test_file_level_strings_anchor_at_most_four_longest_first_and_short_ones_are_only_offered(bench, engine):
    texts = ['PatchTrace synthetic: index %u exceeds length %u', 'PatchTrace synthetic: ', 'PatchTrace s',
             'PatchTrace', 'Patch', 'PatchTrace synthetic', 'PatchTrace synt']
    items = [observation(t, offset=0x700 + 0x40 * i) for i, t in enumerate(texts)]
    (candidate,) = candidate_for(bench, items, directions=('newer',)).candidates
    # the four longest, listed by offset; the three others are offered, 'Patch' being shorter than a literal run
    assert [f.text for f in candidate.features if f.included] == [
        'PatchTrace synthetic: index %u exceeds length %u', 'PatchTrace synthetic: ', 'PatchTrace synthetic',
        'PatchTrace synt']
    assert [f.text for f in candidate.features if not f.included] == ['PatchTrace s', 'PatchTrace', 'Patch']


def test_a_string_exactly_as_long_as_a_literal_run_can_anchor(bench, engine):
    items = [observation('index ', offset=0x700), observation('exceeds length %u', offset=0x740),
             observation('Patch', offset=0x780)]
    (candidate,) = candidate_for(bench, items, directions=('newer',)).candidates
    assert [(f.text, f.included) for f in candidate.features] == [
        ('index ', True), ('exceeds length %u', True), ('Patch', False)]


def test_when_every_string_is_too_short_to_anchor_nothing_is_proposed(bench, engine):
    result = candidate_for(bench, [observation('OK'), observation('Patch')], directions=('newer',))
    assert result.candidates == () and result.rejected[0].reason == 'no-feature'


def test_unknown_separation_strings_are_offered_but_never_ticked(bench, engine):
    items = [observation('PatchTrace synthetic: index %u exceeds length %u'),
             observation('indeterminate string value', separation='unknown', offset=0x760)]
    (candidate,) = candidate_for(bench, items, directions=('newer',)).candidates
    assert [(f.text, f.included, f.separation) for f in candidate.features] == [
        ('PatchTrace synthetic: index %u exceeds length %u', True, 'newer-only'),
        ('indeterminate string value', False, 'unknown')]


def test_the_feature_cap_cuts_offers_before_ticked_features(bench, engine):
    items = [observation('PatchTrace synthetic: index %u exceeds length %u')] + [
        observation(f'unknown separation string {i:03d}', separation='unknown', offset=0x800 + 64 * i)
        for i in range(DEFAULT_LIMITS.features_per_candidate + 6)]
    result = candidate_for(bench, items, directions=('newer',))
    (candidate,) = result.candidates
    assert len(candidate.features) == DEFAULT_LIMITS.features_per_candidate
    assert candidate.features[0].included and result.notes == ('features-cut:7',)


def test_ids_are_content_addressed_and_independent_of_port_order(bench, engine):
    items = [observation(ADDED), observation('exceeds length %u', offset=0x780)]
    first = candidate_for(bench, items, directions=('newer',)).candidates[0]
    again = candidate_for(bench, list(reversed(items)), directions=('newer',)).candidates[0]
    assert (first.candidate_id, first.lineage_id, first.rule_sha256) == (again.candidate_id, again.lineage_id,
                                                                         again.rule_sha256)
    fewer = candidate_for(bench, items[:1], directions=('newer',)).candidates[0]
    assert fewer.lineage_id == first.lineage_id and fewer.candidate_id != first.candidate_id   # a revision
    assert fewer.rule_name == first.rule_name and fewer.rule_text != first.rule_text
    other = cd.propose(rf.strings_pair(bench, match_id='match-other'), cd.Sources(strings=rf.FakeStrings(items)),
                       check=check_for(bench, 'floss-static'), directions=('newer',))
    assert other.candidates[0].lineage_id != first.lineage_id


def test_the_same_rule_from_another_analysis_run_is_another_candidate_of_the_same_lineage(bench, engine):
    sources = cd.Sources(strings=rf.FakeStrings([observation(ADDED)]))
    pair = rf.strings_pair(bench)
    first = cd.propose(pair, sources, check=check_for(bench, 'floss-static'),
                       directions=('newer',)).candidates[0]
    rerun = cd.propose(pair.model_copy(update={'run_id': 'run-2'}), sources,
                       check=check_for(bench, 'floss-static'), directions=('newer',)).candidates[0]
    assert (rerun.lineage_id, rerun.rule_sha256) == (first.lineage_id, first.rule_sha256)
    assert rerun.candidate_id != first.candidate_id


def test_a_failed_blocking_gate_keeps_the_rule_out_and_says_which(bench, engine):
    def never_in_its_own_build(name, text, pair, direction):
        real = check_for(bench, 'floss-static')(name, text, pair, direction)
        return dataclasses.replace(real, own=CellResult(state='no-hit', hits=0))

    items = [observation('PatchTrace synthetic: index %u exceeds length %u')]
    sources = cd.Sources(strings=rf.FakeStrings(items))
    result = cd.propose(rf.strings_pair(bench), sources, check=never_in_its_own_build,
                        directions=('newer',))
    assert result.candidates == ()
    (rejection,) = result.rejected
    assert (rejection.reason, rejection.gate.gate_id, rejection.gate.state) == ('gate', 'sep', 'fail')
    assert result.first_failure() == 'Does not appear in the other build: does not match its own build'


def test_a_build_that_could_not_be_scanned_is_not_offered_as_separated(bench, engine):
    def unreadable_other(name, text, pair, direction):
        real = check_for(bench, 'floss-static')(name, text, pair, direction)
        return dataclasses.replace(real, other=CellResult(state='not-scanned', reason='unreadable'))

    sources = cd.Sources(strings=rf.FakeStrings([observation('PatchTrace synthetic: index %u exceeds length %u')]))
    result = cd.propose(rf.strings_pair(bench), sources, check=unreadable_other,
                        directions=('newer',))
    assert result.candidates == () and result.rejected[0].gate.state == 'unknown'


def test_a_rule_that_does_not_compile_is_rejected_by_the_compile_gate(bench, engine):
    def rogue(spec):
        return rf.render_rule(spec).replace('newer_side', 'rogue_tag')   # E040: a tag outside the whitelist

    sources = cd.Sources(strings=rf.FakeStrings([observation('PatchTrace synthetic: index %u exceeds length %u')]))
    result = cd.propose(rf.strings_pair(bench), sources, render=rogue, check=check_for(bench, 'floss-static'),
                        directions=('newer',))
    (rejection,) = result.rejected
    assert (rejection.gate.gate_id, rejection.gate.state) == ('compile', 'fail') and 'E040' in rejection.gate.detail


def test_a_renderer_that_breaks_the_contract_is_a_compile_error_not_a_candidate(bench, engine):
    sources = cd.Sources(strings=rf.FakeStrings([observation('PatchTrace synthetic: index %u exceeds length %u')]))

    def renamed(spec):   # the engine accepts any PT_<12 hex>_newer rule; the candidate must define ITS rule
        return rf.render_rule(dataclasses.replace(spec, lineage_id='f' * 64))
    with pytest.raises(RuleError) as caught:
        cd.propose(rf.strings_pair(bench), sources, render=renamed, check=check_for(bench, 'floss-static'),
                   directions=('newer',))
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-COMPILE', 'candidate-invalid')


def test_the_toolchain_gate_is_informational_and_follows_the_flags(bench, engine):
    items = [observation('PatchTrace synthetic: index %u exceeds length %u')]
    for flags, state in ((None, 'unknown'), ((), 'pass'), (('toolchain-changed',), 'fail')):
        (candidate,) = candidate_for(bench, items, directions=('newer',), flags=flags).candidates
        assert candidate.gates[-1].gate_id == 'dist' and candidate.gates[-1].state == state


def test_the_runner_checker_gives_the_same_verdict_through_the_hidden_worker(bench, engine, tmp_path):
    paths = {}
    for side in rf.SIDES:
        paths[side] = tmp_path / f'floss-{side}.bin'
        paths[side].write_bytes(bench.build('floss-static', side).data)
    sources = cd.Sources(strings=rf.FakeStrings([observation('PatchTrace synthetic: index %u exceeds length %u')]))
    pair = rf.strings_pair(bench)
    in_process = cd.propose(pair, sources, check=check_for(bench, 'floss-static'),
                            directions=('newer',))
    through_worker = cd.propose(pair, sources, check=cd.RunnerChecker(paths),
                                directions=('newer',))
    assert through_worker.candidates == in_process.candidates
    paths['older'].unlink()
    with pytest.raises(RuleError) as caught:
        cd.propose(pair, sources, check=cd.RunnerChecker(paths), directions=('newer',))
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-STALE', 'build-missing')


def test_a_build_swapped_after_the_pair_was_accepted_is_never_scanned_as_the_recorded_build(bench, engine, tmp_path):
    paths = {side: tmp_path / f'swap-{side}.bin' for side in rf.SIDES}
    for side in rf.SIDES:   # both slots hold the NEWER build: the older hash no longer matches its file
        paths[side].write_bytes(bench.build('floss-static', 'newer').data)
    sources = cd.Sources(strings=rf.FakeStrings([observation('PatchTrace synthetic: index %u exceeds length %u')]))
    result = cd.propose(rf.strings_pair(bench), sources, check=cd.RunnerChecker(paths),
                        directions=('newer',))
    assert result.candidates == () and result.rejected[0].gate.state == 'unknown'   # the older file is "changed"


def test_shuffled_observations_give_the_same_proposal(bench, engine):
    items = [observation(piece, offset=0x700 + 32 * i) for i, piece in enumerate(PIECES)]
    rng = random.Random(7)
    base = candidate_for(bench, items, directions=('newer',)).candidates[0]
    for _ in range(3):
        rng.shuffle(items)
        assert candidate_for(bench, items, directions=('newer',)).candidates[0] == base


# --- purity ----------------------------------------------------------------------------------------------------------

NETWORK = {'socket', 'ssl', 'http', 'urllib', 'urllib3', 'requests', 'httpx', 'ftplib', 'smtplib', 'telnetlib', 'aiohttp',
           'xmlrpc', 'asyncio', 'websocket', 'websockets'}
ENGINE_ONLY = {'yara_x', 'iced_x86'}


def imported_modules(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            found.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split('.')[0])
    return found


def test_rules_have_no_network_imports():
    files = sorted((ROOT / 'src' / 'patchtrace' / 'rules').rglob('*.py'))
    assert any(f.name == 'tools_delta.py' for f in files)
    for path in files:
        assert not imported_modules(path) & NETWORK, path.name


def test_only_the_engine_modules_import_the_extensions():
    allowed = {'engine.py', 'worker.py', 'mask_iced.py'}
    for path in sorted((ROOT / 'src' / 'patchtrace' / 'rules').rglob('*.py')):
        if path.name not in allowed:
            assert not imported_modules(path) & ENGINE_ONLY, path.name


def test_no_qt_in_the_rules_package():
    for path in sorted((ROOT / 'src' / 'patchtrace' / 'rules').rglob('*.py')):
        if path.name == 'qt_panel.py':  # the one Qt module of the package: the Rules dock's widgets
            continue
        assert not {m for m in imported_modules(path) if m.startswith(('PySide', 'shiboken'))}, path.name
