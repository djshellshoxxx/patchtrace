"""SPEC-31 06 s10 item 3 + A-28: the Ghidriff adapter over the normalizer's one-to-many abstention. Synthetic snapshot
rows only (unified_s0_fixtures); nothing here ran an engine."""
from __future__ import annotations

import pytest
from unified_s0_fixtures import RAW_SHA, addr_map, func, inputs, match, raw_ok, va

from patchtrace.unified.limits import Budget
from patchtrace.unified.sources import RawGhidriff
from patchtrace.unified.sources.ghidriff import GhidriffAdapter


def run(data):
    return GhidriffAdapter().atoms(data, addr_map(), Budget())


def d1_rows():
    """The rows `normalize_ghidriff` writes for D1: get_version stays 1:1, read_item@0x1000 abstains with its two
    counterparts read_item@0x1080 and read_item_fast@0x1900, plus the ordinary added/removed rows."""
    return [match('m-gv', 'modified', [func('get_version', 0x1600, ratio='0.94')], [func('get_version', 0x1700)],
                  types=['Symbols']),
            match('m-a', 'ambiguous', older=[func('read_item', 0x1000)]),
            match('m-b1', 'ambiguous', newer=[func('read_item', 0x1080)]),
            match('m-b2', 'ambiguous', newer=[func('read_item_fast', 0x1900)]),
            match('m-add', 'added', newer=[func('report_invalid_index', 0x1200)]),
            match('m-del', 'removed', older=[func('debug_dump', 0x1400)])]


TABLE = {va(0x1000): [[va(0x1080), ['SymbolsHash']], [va(0x1900), ['StructuralGraphHash']]],
         va(0x1600): [[va(0x1700), ['SymbolsHash']]]}


def one_sided(out):
    return {(a.step, a.older_rva, a.newer_rva) for a in out.atoms if None in (a.older_rva, a.newer_rva)}


def test_ghidriff_abstained_rows_are_not_one_sided_votes():
    out = run(inputs(d1_rows(), raw_ok(TABLE)))
    [group] = out.groups
    assert (group.kind, group.decision, group.reason) == ('ghidriff-1n', 'ambiguous', 'one-to-many')
    assert group.older == (0x1000,) and group.newer == (0x1080, 0x1900)
    assert one_sided(out) == {('added', None, 0x1200), ('deleted', 0x1400, None)}  # nothing at A, B1 or B2
    pairs = {(a.older_rva, a.newer_rva): a for a in out.atoms if None not in (a.older_rva, a.newer_rva)}
    assert set(pairs) == {(0x1600, 0x1700)} and pairs[(0x1600, 0x1700)].ref == 'm-gv'
    assert out.limitations == ('ghidriff-one-to-many-abstained:3',)
    names = {(n.side, n.rva): n.name for n in out.nodes}
    assert names[('older', 0x1000)] == 'read_item' and names[('newer', 0x1900)] == 'read_item_fast'


@pytest.mark.parametrize('status', ['missing', 'hash-mismatch'], ids=['missing', 'mismatch'])
def test_ghidriff_abstention_without_a_usable_raw_table_is_unknown_not_negative(status):
    out = run(inputs(d1_rows(), RawGhidriff(status=status, address_matches=TABLE, sha256=RAW_SHA)))
    assert out.groups == ()
    assert one_sided(out) == {('added', None, 0x1200), ('deleted', 0x1400, None)}
    assert {(a.older_rva, a.newer_rva) for a in out.atoms if None not in (a.older_rva, a.newer_rva)} == {
        (0x1600, 0x1700)}
    assert set(out.limitations) == {f'raw-{status}', 'ghidriff-one-to-many-abstained:3'}


def test_two_one_to_one_rows_sharing_an_rva_become_one_group():
    """Characterization (judge 3): a partial 1:N that reached the normalizer as two clean rows is still one group."""
    rows = [match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['SymbolsHash']),
            match('m2', 'modified', [func('f', 0x1000)], [func('g', 0x1100)], types=['BSIM'])]
    out = run(inputs(rows, raw_ok({})))
    [group] = out.groups
    assert group.older == (0x1000,) and group.newer == (0x1080, 0x1100)
    assert {a.cardinality for a in group.atoms} == {'1:N'} and out.atoms == ()


def test_manual_one_sided_ambiguous_stays_with_the_manual_adapter():
    manual = match('m1', 'ambiguous', older=[func('f', 0x1000)], types=['manual'], manual=True)
    out = run(inputs([manual], raw_ok({})))
    assert out.atoms == () and out.limitations == ()
