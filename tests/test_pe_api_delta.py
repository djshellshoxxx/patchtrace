"""WBQ S4: static import API delta between an older and a newer PE (added/removed, never guessed).

Unknown is not a negative: an import table that could not be read must give `unavailable`, never "all removed".
"""
from __future__ import annotations

import json
import struct
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from pe_builder import PeSpec, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview.api_delta import PROVENANCE, ApiChange, ApiDelta, compute_api_delta
from patchtrace.pe_overview.models import DataDirectory, ImportDll, ImportsInfo, PeOverview

OLD_SHA, NEW_SHA = 'a' * 64, 'b' * 64


def table(*dlls: tuple[str, list[str]], truncated: bool = False, dll_truncated: bool = False) -> ImportsInfo:
    items = tuple(ImportDll(name, tuple(fns), len(fns), dll_truncated) for name, fns in dlls)
    return ImportsInfo(items, len(items), sum(len(d.functions) for d in items), truncated)


def overview(imports: ImportsInfo | None, *, import_dir: bool | None = True, status: str = 'ok',
             sha: str = OLD_SHA) -> PeOverview:
    """`import_dir`: True = directory present, False = verified absent, None = headers were never parsed."""
    dirs = None if import_dir is None else (
        DataDirectory(0, 'Export', 0, 0, False),
        DataDirectory(1, 'Import', 0x2000 if import_dir else 0, 40 if import_dir else 0, import_dir))
    return PeOverview(size=1, sha256=sha, status=status, imports=imports, data_directories=dirs)


def delta(older: PeOverview, newer: PeOverview) -> ApiDelta:
    return compute_api_delta(older=older, newer=newer)


def triples(d: ApiDelta) -> list[tuple[str, str, str, str]]:
    return [(c.change, c.dll, c.name, c.kind) for c in d.changes]


# -- orientation ---------------------------------------------------------------------------------------

def test_changes_are_oriented_older_to_newer_and_ordered():
    older = overview(table(('KERNEL32.dll', ['CreateFileW', 'CloseHandle']), ('USER32.dll', ['MessageBoxA'])))
    newer = overview(table(('kernel32.dll', ['CreateFileW', 'ReadFile', 'WriteFile']),
                           ('ntdll.dll', ['RtlULongAdd'])), sha=NEW_SHA)
    d = delta(older, newer)
    assert d.status == 'changed'
    assert triples(d) == [
        ('removed', 'kernel32.dll', 'CloseHandle', 'name'),
        ('added', 'kernel32.dll', 'ReadFile', 'name'),
        ('added', 'kernel32.dll', 'WriteFile', 'name'),
        ('added', 'ntdll.dll', 'RtlULongAdd', 'name'),
        ('removed', 'user32.dll', 'MessageBoxA', 'name'),
    ]
    assert (d.older_count, d.newer_count) == (3, 4)
    assert d.reason == '3 added, 2 removed (older to newer)'


def test_swapping_the_sides_swaps_added_and_removed_and_the_provenance():
    older = overview(table(('k.dll', ['A', 'B'])))
    newer = overview(table(('k.dll', ['B', 'C']), ('n.dll', ['D'])), sha=NEW_SHA)
    forward, backward = delta(older, newer), delta(newer, older)
    flipped = {'added': 'removed', 'removed': 'added'}
    assert sorted((c.dll, c.name, flipped[c.change]) for c in forward.changes) == \
        sorted((c.dll, c.name, c.change) for c in backward.changes)
    assert (forward.older_count, forward.newer_count) == (backward.newer_count, backward.older_count) == (2, 3)
    assert (forward.older_sha256, forward.newer_sha256) == (OLD_SHA, NEW_SHA)
    assert (backward.older_sha256, backward.newer_sha256) == (NEW_SHA, OLD_SHA)


def test_sides_are_keyword_only():
    one = overview(table(('k.dll', ['A'])))
    with pytest.raises(TypeError):
        compute_api_delta(one, one)  # a positional call could silently swap older and newer


# -- matching rules ------------------------------------------------------------------------------------

def test_dll_case_function_order_and_split_descriptors_do_not_make_changes():
    older = overview(table(('KERNEL32.dll', ['A', 'B']), ('USER32.dll', ['C'])))
    newer = overview(table(('user32.DLL', ['C']), ('kernel32.dll', ['B']), ('Kernel32.dll', ['A'])), sha=NEW_SHA)
    d = delta(older, newer)
    assert d.status == 'unchanged' and d.changes == () and (d.older_count, d.newer_count) == (3, 3)
    assert d.reason == 'same static import table'


def test_function_names_are_case_sensitive_like_the_loader():
    d = delta(overview(table(('k.dll', ['CreateFileW']))), overview(table(('k.dll', ['createfilew']))))
    assert triples(d) == [('removed', 'k.dll', 'CreateFileW', 'name'), ('added', 'k.dll', 'createfilew', 'name')]


def test_ordinals_are_kept_apart_from_names_and_sorted_numerically():
    older = overview(table(('ws2_32.dll', ['#10', '#9', 'send'])))
    newer = overview(table(('ws2_32.dll', ['recv'])), sha=NEW_SHA)
    assert triples(delta(older, newer)) == [
        ('added', 'ws2_32.dll', 'recv', 'name'), ('removed', 'ws2_32.dll', 'send', 'name'),
        ('removed', 'ws2_32.dll', '#9', 'ordinal'), ('removed', 'ws2_32.dll', '#10', 'ordinal')]


@pytest.mark.parametrize(('text', 'kind'), [
    ('#0', 'ordinal'), ('#65535', 'ordinal'), ('#7', 'ordinal'),
    ('#65536', 'name'), ('#07', 'name'), ('#', 'name'), ('#-1', 'name'), ('#1a', 'name'), ('7', 'name'),
], ids=['zero', 'max', 'plain', 'over-word', 'leading-zero', 'bare-hash', 'negative', 'suffix', 'no-hash'])
def test_only_the_form_the_parser_emits_for_an_ordinal_is_an_ordinal(text, kind):
    (change,) = delta(overview(table(('k.dll', []))), overview(table(('k.dll', [text])))).changes
    assert change.kind == kind and change.name == text


def test_a_name_moving_between_ordinal_and_name_is_reported_as_it_is_listed():
    d = delta(overview(table(('k.dll', ['#7']))), overview(table(('k.dll', ['Seven']))))
    assert triples(d) == [('added', 'k.dll', 'Seven', 'name'), ('removed', 'k.dll', '#7', 'ordinal')]


# -- unknown is not a negative -------------------------------------------------------------------------

def test_an_unreadable_side_is_unavailable_never_all_removed_or_added():
    known = overview(table(('k.dll', ['A', 'B'])))
    unread = overview(None, status='partial', sha=NEW_SHA)  # Import directory declared, nothing parsed
    d = delta(known, unread)
    assert d.status == 'unavailable' and d.changes == () and (d.older_count, d.newer_count) == (2, None)
    assert 'newer' in d.reason and 'older' not in d.reason
    r = delta(unread, known)
    assert r.status == 'unavailable' and r.changes == () and (r.older_count, r.newer_count) == (None, 2)
    assert 'older' in r.reason and 'newer' not in r.reason


def test_both_sides_unreadable_names_both():
    d = delta(overview(None), overview(None, sha=NEW_SHA))
    assert d.status == 'unavailable' and 'older' in d.reason and 'newer' in d.reason
    assert (d.older_count, d.newer_count) == (None, None)


@pytest.mark.parametrize('status', ['not_pe', 'cancelled'])
def test_files_whose_headers_were_never_parsed_are_unavailable(status):
    d = delta(overview(table(('k.dll', ['A']))), overview(None, import_dir=None, status=status))
    assert d.status == 'unavailable' and d.changes == ()


def test_a_verified_absent_import_directory_is_an_empty_table():
    none = overview(None, import_dir=False)
    some = overview(table(('k.dll', ['A'])), sha=NEW_SHA)
    d = delta(none, some)
    assert d.status == 'changed' and triples(d) == [('added', 'k.dll', 'A', 'name')] and d.older_count == 0
    assert triples(delta(some, none)) == [('removed', 'k.dll', 'A', 'name')]
    both = delta(none, overview(None, import_dir=False, sha=NEW_SHA))
    assert both.status == 'unchanged' and (both.older_count, both.newer_count) == (0, 0)


@pytest.mark.parametrize('side', ['older', 'newer'])
@pytest.mark.parametrize('how', ['table', 'one-dll'], ids=['table-flag', 'dll-flag'])
def test_a_truncated_import_table_makes_the_delta_unavailable(side, how):
    cut = table(('k.dll', ['A']), ('m.dll', ['B']), truncated=how == 'table', dll_truncated=how == 'one-dll')
    full = table(('k.dll', ['A', 'C']))
    older, newer = (cut, full) if side == 'older' else (full, cut)
    d = delta(overview(older), overview(newer, sha=NEW_SHA))
    assert d.status == 'unavailable' and d.changes == ()
    assert side in d.reason and 'limit' in d.reason


@pytest.mark.parametrize('dll, fn', [
    ('k.dll', '<unreadable @ 0x1f40>'), ('k.dll', '<invalid thunk 0x80001000>'),
    ('<unreadable name @ 0x2000>', 'A'), ('<unreadable name @ 0x2000>', None),
], ids=['name-pointer', 'thunk', 'dll-name', 'dll-name-no-functions'])
def test_placeholders_for_unreadable_entries_are_never_compared_as_names(dll, fn):
    # their text carries an RVA that differs between builds, so equal-looking text would be coincidence
    bad = overview(table((dll, [] if fn is None else [fn, 'B'])))
    d = delta(bad, overview(table(('k.dll', ['A', 'B'])), sha=NEW_SHA))
    assert d.status == 'unavailable' and d.changes == () and 'older' in d.reason and 'unreadable' in d.reason
    assert delta(overview(table(('k.dll', ['A']))), bad).status == 'unavailable'


# -- real parses ---------------------------------------------------------------------------------------

def inspect(tmp_path: Path, data: bytes, name: str, **kw) -> PeOverview:
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader, **kw)


def built(tmp_path: Path, name: str, imports: dict, **kw) -> PeOverview:
    return inspect(tmp_path, build_pe_ex(PeSpec(imports=imports))[0], name, **kw)


def test_builder_pair_end_to_end(tmp_path):
    older = built(tmp_path, 'old.dll', {'KERNEL32.dll': ['CreateFileW', 7], 'USER32.dll': ['MessageBoxA']})
    newer = built(tmp_path, 'new.dll', {'KERNEL32.dll': ['CreateFileW', 7], 'ntdll.dll': ['RtlULongAdd']})
    d = delta(older, newer)
    assert d.status == 'changed' and (d.older_sha256, d.newer_sha256) == (older.sha256, newer.sha256)
    assert triples(d) == [('added', 'ntdll.dll', 'RtlULongAdd', 'name'),
                          ('removed', 'user32.dll', 'MessageBoxA', 'name')]
    assert delta(older, older).status == 'unchanged'


def test_builder_pe_without_imports_is_a_verified_empty_table(tmp_path):
    bare = built(tmp_path, 'bare.exe', {})
    imp = built(tmp_path, 'imp.exe', {'k.dll': ['A']})
    assert bare.imports is None and bare.directory('Import').present is False
    assert triples(delta(bare, imp)) == [('added', 'k.dll', 'A', 'name')]


@pytest.mark.parametrize('limits', [Limits(max_import_dlls=1), Limits(max_functions_per_dll=1),
                                    Limits(max_total_names=1)],
                         ids=['dll-cap', 'per-dll-cap', 'total-cap'])
def test_a_real_parse_cut_by_a_cap_gives_no_delta(tmp_path, limits):
    cut = built(tmp_path, 'cut.dll', {'a.dll': ['F1', 'F2'], 'b.dll': ['G1', 'G2']}, limits=limits)
    full = built(tmp_path, 'full.dll', {'a.dll': ['F1']})
    assert cut.imports.truncated
    assert delta(cut, full).status == 'unavailable' and delta(full, cut).status == 'unavailable'


def test_a_real_parse_with_an_unreadable_name_gives_no_delta(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'a.dll': ['F1', 'F2']}))
    bad = bytearray(data)
    struct.pack_into('<Q', bad, info['first_thunk_off'], 0x7FFFF000)  # name RVA outside the file
    cut = inspect(tmp_path, bytes(bad), 'cut.dll')
    assert cut.imports.dlls[0].functions[0].startswith('<unreadable') and not cut.imports.truncated
    other = built(tmp_path, 'ok.dll', {'a.dll': ['F1', 'F2']})
    assert delta(other, cut).status == 'unavailable'


# -- records, cost -------------------------------------------------------------------------------------

def test_delta_is_plain_data_with_provenance():
    older, newer = overview(table(('k.dll', ['A']))), overview(table(('k.dll', ['B'])), sha=NEW_SHA)
    d = delta(older, newer)
    assert d.provenance == PROVENANCE and 'static import table only' in PROVENANCE
    assert json.loads(json.dumps(asdict(d)))['changes'] == [
        asdict(ApiChange('k.dll', 'A', 'name', 'removed')), asdict(ApiChange('k.dll', 'B', 'name', 'added'))]
    assert d == delta(older, newer) and hash(d) == hash(delta(older, newer))


def test_large_tables_stay_fast_and_exact():
    n = Limits().max_total_names
    older = overview(table(('big.dll', [f'Api{i:05d}' for i in range(n)])))
    newer = overview(table(('big.dll', [f'Api{i:05d}' for i in range(n // 2, n + n // 2)])), sha=NEW_SHA)
    started = time.monotonic()
    d = delta(older, newer)
    assert time.monotonic() - started < 2
    assert d.status == 'changed' and len(d.changes) == n
    assert [c.change for c in d.changes[:3]] == ['removed'] * 3 and d.changes[0].name == 'Api00000'
    assert d.changes[-1] == ApiChange('big.dll', f'Api{n + n // 2 - 1:05d}', 'name', 'added')
