"""Mixed-machine Winbindex regressions from the L1 cleanmgr.exe failure shape.

These compact synthetic records retain the native/WoW64 layout of the captured
metadata. They prove resolver behavior, not live file attribution or accuracy.
"""
from __future__ import annotations

import copy
import json

import pytest

from patchtrace.acquisition.winbindex import parse_rows
from patchtrace.kbcorrelation import lineage as ln
from patchtrace.kbcorrelation import resolver as rs
from patchtrace.kbcorrelation.products import scope_for

NAME = 'cleanmgr.exe'
OLD_KB, NEW_KB = 'KB5050009', 'KB5051987'
AMD64, X86, ARM64 = 0x8664, 0x14C, 0xAA64
SCOPE = scope_for('a' * 64, 'client', 'Windows 11 Version 24H2 for x64-based Systems')


def update(date, build, *, preview=False):
    return {'updateInfo': {'releaseDate': date, 'releaseVersion': build,
                           'heading': f'OS Build {build}' + (' Preview' if preview else '')}}


def entry(sha, machine, updates):
    return {'fileInfo': {'sha256': sha, 'machineType': machine, 'size': 4096,
                         'timestamp': 123, 'virtualSize': 8192},
            'windowsVersions': {'11-24H2': updates}}


def record(*, amd64_first=False):
    # Both machines ship in both updates; hash sorting is not an architecture selector.
    old = {OLD_KB: update('2025-01-14', '26100.2894')}
    new = {NEW_KB: update('2025-02-11', '26100.3194')}
    native_new, wow_new = ('c', 'd') if amd64_first else ('e', 'd')
    return {'a' * 64: entry('a' * 64, AMD64, copy.deepcopy(old)),
            'b' * 64: entry('b' * 64, X86, copy.deepcopy(old)),
            native_new * 64: entry(native_new * 64, AMD64, copy.deepcopy(new)),
            wow_new * 64: entry(wow_new * 64, X86, copy.deepcopy(new))}


def rows_of(document):
    parsed = parse_rows(json.dumps(document).encode(), NAME, '2026-11-18', compressed=False)
    rows, rejected = ln.index_rows([row.as_mapping() for row in parsed.rows], file_name=NAME)
    assert parsed.skipped == rejected == 0
    return rows


def resolve(rows, kb=NEW_KB):
    return rs.resolve(rows, kb=kb, scope=SCOPE, file_name=NAME)


@pytest.mark.parametrize('amd64_first', [False, True])
def test_native_predecessor_is_independent_of_wow64_hash_order(amd64_first):
    document = record(amd64_first=amd64_first)
    untouched = copy.deepcopy(document)
    rows = rows_of(document)
    before = tuple(rows)
    result = resolve(rows)
    assert result.changed_in_kb == 'yes'
    (pair,) = result.pairs
    assert pair.grade == 'A' and pair.reason_codes == ()
    assert pair.older.machine == pair.newer.machine == 'amd64'
    assert pair.older.sha256 == 'a' * 64
    assert pair.newer.sha256 == ('c' if amd64_first else 'e') * 64
    assert resolve(tuple(reversed(rows))) == result
    assert document == untouched and rows == before
    assert len(rows) == 4 and {row.machine for row in rows} == {'amd64', 'x86'}


@pytest.mark.parametrize('machine, label', [(X86, 'x86'), (ARM64, 'arm64'), (None, 'unknown')])
def test_target_only_under_other_machine_is_explicitly_blocked(machine, label):
    document = record()
    del document['d' * 64]
    document['e' * 64]['fileInfo']['machineType'] = machine
    rows = rows_of(document)
    result = resolve(rows)
    assert result.pairs == () and result.blockers == ('ARCH',)
    assert result.changed_in_kb == 'unknown' and label in result.note
    assert any(row.kb == NEW_KB and row.machine == label for row in rows)


def test_other_machine_cannot_supply_a_missing_native_predecessor():
    document = record()
    del document['a' * 64]
    result = resolve(rows_of(document))
    assert result.pairs == () and result.blockers == ('NO_OLDER',)
    assert result.changed_in_kb == 'unknown'


def test_other_machine_does_not_break_an_unchanged_native_sha_run():
    document = record()
    preview, later = 'KB5052093', 'KB5053598'
    document['a' * 64]['windowsVersions']['11-24H2']['KB5050094'] = update(
        '2025-01-28', '26100.3037', preview=True)
    document['e' * 64]['windowsVersions']['11-24H2'] = {
        preview: update('2025-02-25', '26100.3323', preview=True),
        later: update('2025-03-11', '26100.3476')}
    document['f' * 64] = entry('f' * 64, X86, {later: update('2025-03-11', '26100.3476')})
    result = resolve(rows_of(document), later)
    assert result.changed_in_kb == 'no' and result.last_changed_in == preview
    (pair,) = result.pairs
    assert pair.grade == 'A' and pair.older.sha256 == 'a' * 64 and pair.newer.sha256 == 'e' * 64
    assert pair.window == (preview,) and 'WINDOW_CONFOUNDED' in pair.reason_codes


def test_same_machine_variants_remain_unknown_and_tied_order_stays_blocked():
    document = record()
    document['f' * 64] = entry('f' * 64, AMD64, {NEW_KB: update('2025-02-11', '26100.3194')})
    rows = rows_of(document)
    result = resolve(rows)
    assert result.changed_in_kb == 'unknown' and result.ambiguous and len(result.pairs) == 2
    assert all(pair.older.machine == pair.newer.machine == 'amd64' for pair in result.pairs)
    assert {pair.newer.sha256 for pair in result.pairs} == {'e' * 64, 'f' * 64}
    assert all(pair.older.sha256 == 'a' * 64 and pair.grade == 'A'
               and pair.fix_boundary == 'unverified' and 'WINDOW_CONFOUNDED' in pair.reason_codes
               for pair in result.pairs)
    # An explicit comparison between same-time variants still cannot establish chronological order.
    peers = [next(row for row in rows if row.sha256 == sha * 64) for sha in ('e', 'f')]
    tied = rs.propose_index_pair(*peers, scope_id=SCOPE.scope_id)
    assert tied.grade == 'X' and 'ORDER_UNVERIFIED' in tied.reason_codes


def test_direct_mismatched_proposal_keeps_the_architecture_hard_block():
    rows = rows_of(record())
    older = next(row for row in rows if row.sha256 == 'a' * 64)
    newer = next(row for row in rows if row.sha256 == 'd' * 64)
    pair = rs.propose_index_pair(older, newer, scope_id=SCOPE.scope_id)
    assert pair.grade == 'X' and pair.bytes_state == 'incompatible'
    assert 'ARCH' in pair.reason_codes
