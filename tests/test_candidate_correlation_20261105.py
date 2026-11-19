"""Candidate identity and chronology controls over authored Winbindex facts."""
from __future__ import annotations

from dataclasses import replace

import pytest
from kbc_k5_support import SHA, record, rows_of, scope

from patchtrace.kbcorrelation.resolver import propose_index_pair, resolve
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError


def candidates():
    rows, _ = rows_of(record())
    by_kb = {r.kb: r for r in rows if r.build.version_key == '11-24H2'}
    return by_kb['KB5096000'], by_kb['KB5097000']


def test_different_component_basename_is_a_hard_block_even_with_ordered_builds():
    older, newer = candidates()
    newer = replace(newer, build=newer.build.model_copy(update={'file_name': 'otherdrv.sys'}))
    pair = propose_index_pair(older, newer, scope_id='1' * 64)
    assert pair.grade == 'X' and 'NAME_MISMATCH' in pair.reason_codes
    assert pair.fix_boundary == 'unverified'


@pytest.mark.parametrize('tie_breaker', ['sha256', 'kb', 'base-image'])
def test_display_tie_breaker_is_not_proof_of_temporal_order(tie_breaker):
    older, newer = candidates()
    fields = {'release_date': older.build.release_date, 'release_version': older.build.release_version}
    if tie_breaker == 'sha256':
        fields['kb'] = older.kb
    elif tie_breaker == 'base-image':
        older = replace(older, build=older.build.model_copy(update={'kb': None}))
    newer = replace(newer, build=newer.build.model_copy(update=fields))
    pair = propose_index_pair(older, newer, scope_id='1' * 64)
    assert pair.grade == 'X' and pair.lineage_state == 'incompatible'
    assert 'ORDER_UNVERIFIED' in pair.reason_codes


def test_same_build_observations_do_not_gain_orientation_when_hashes_are_swapped():
    older, newer = candidates()
    newer = replace(newer, build=newer.build.model_copy(update={
        'release_date': older.build.release_date, 'release_version': older.build.release_version,
        'kb': older.kb}))
    for left, right in [(older, newer), (newer, older)]:
        pair = propose_index_pair(left, right, scope_id='1' * 64)
        assert pair.grade == 'X' and 'ORDER_UNVERIFIED' in pair.reason_codes


def test_numeric_build_order_remains_available_within_the_same_release_date():
    older, newer = candidates()
    older = replace(older, build=older.build.model_copy(update={'release_version': '26100.9'}))
    newer = replace(newer, build=newer.build.model_copy(update={
        'release_date': older.build.release_date, 'release_version': '26100.10'}))
    pair = propose_index_pair(older, newer, scope_id='1' * 64)
    assert pair.grade == 'A' and 'ORDER_UNVERIFIED' not in pair.reason_codes


def test_same_update_variants_are_retained_without_invented_chronology_and_order_is_stable():
    document = record()
    document[SHA['V']]['windowsVersions'] = {'11-24H2': document[SHA['Z']]['windowsVersions']['11-24H2']}
    rows, skipped = rows_of(document)
    result = resolve(rows, kb='KB5099001', scope=scope(), file_name='exampledrv.sys', skipped_rows=skipped)
    reversed_result = resolve(tuple(reversed(rows)), kb='KB5099001', scope=scope(), file_name='exampledrv.sys',
                              skipped_rows=skipped)
    assert result == reversed_result
    assert result.changed_in_kb == 'unknown' and len(result.pairs) == 2
    assert result.ambiguous and not result.truncated
    assert {pair.newer.sha256 for pair in result.pairs} == {SHA['Z'], SHA['V']}
    # Preserve both target variants against the established earlier observation;
    # a display tie-breaker must not substitute a peer for that predecessor.
    assert all(pair.older.sha256 == SHA['Y'] and pair.older.build_ubr == '26100.110'
               and pair.newer.build_ubr == '26200.120' and pair.grade == 'A'
               and pair.fix_boundary == 'unverified' and 'WINDOW_CONFOUNDED' in pair.reason_codes
               for pair in result.pairs)
    with pytest.raises(KbcStoreError, match='--pair') as caught:
        KbService._pick_pair([result], None)
    assert caught.value.code == 'PT-KBC-INPUT'
    # The original unordered-comparison safety assertion still applies to any
    # direct proposal between the peers, in both orientations.
    peers = [row for row in rows if row.build.version_key == '11-24H2' and row.kb == 'KB5099001']
    assert len(peers) == 2
    for older, newer in (peers, tuple(reversed(peers))):
        tied = propose_index_pair(older, newer, scope_id=scope().scope_id)
        assert tied.grade == 'X' and 'ORDER_UNVERIFIED' in tied.reason_codes
        assert tied.fix_boundary == 'unverified'
