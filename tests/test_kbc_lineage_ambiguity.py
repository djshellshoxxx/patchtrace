"""Independent chronology and explicit variant-choice counterexamples; offline synthetic metadata."""
from dataclasses import replace

import pytest

from patchtrace.kbcorrelation import lineage, resolver
from patchtrace.kbcorrelation.products import scope_for
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError

FILE_NAME = 'example.sys'
SCOPE = scope_for('1' * 64, 'client', 'Windows 11 Version 24H2 for x64-based Systems')


def mapping(sha, kb, build, *, day='2099-02-01'):
    return {
        'sha256': sha * 64, 'kb': kb, 'version_key': '11-24H2', 'release_date': day,
        'release_version': build, 'size': 8192, 'machine_type': 0x8664, 'variant': 'full',
        'heading_class': 'standard', 'download': 'direct', 'record_sha256': 'd' * 64,
    }


def resolve(mappings, target='KB5000003'):
    rows, rejected = lineage.index_rows(mappings, file_name=FILE_NAME)
    assert rejected == 0
    return resolver.resolve(rows, kb=target, scope=SCOPE, file_name=FILE_NAME, fixed_build='26100.200')


@pytest.mark.parametrize('unknown_build', [None, 'malformed'])
def test_incomparable_same_instant_bytes_are_not_sorted_away(unknown_build):
    result = resolve([
        mapping('a', 'KB5000001', unknown_build),
        mapping('b', 'KB5000002', '26100.100'),
        mapping('c', 'KB5000003', '26100.200'),
    ])
    assert result.changed_in_kb == 'unknown'
    assert all(pair.fix_boundary != 'source-supported' for pair in result.pairs)


def test_same_instant_different_build_families_do_not_establish_order():
    result = resolve([
        mapping('a', 'KB5000001', '26000.100'),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert result.changed_in_kb == 'unknown'
    assert all(pair.grade == 'X' for pair in result.pairs)


def test_same_machine_same_build_variants_never_pick_one_by_sha():
    result = resolve([
        mapping('a', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
        mapping('c', 'KB5000003', '26100.200'),
    ])
    assert result.changed_in_kb == 'unknown'
    viable = [pair for pair in result.pairs if pair.grade != 'X']
    assert len(viable) != 1, [(pair.older.sha256[0], pair.newer.sha256[0], pair.grade) for pair in result.pairs]
    try:
        default = KbService._pick_pair([result], None)
    except KbcStoreError as exc:
        assert exc.code == 'PT-KBC-INPUT'
    else:
        assert default is None


def test_different_kb_tie_does_not_change_claim_based_on_kb_number():
    old = mapping('a', 'KB5000001', '26100.100', day='2099-01-01')
    target = mapping('b', 'KB5000003', '26100.200')
    before = resolve([old, target, mapping('c', 'KB5000002', '26100.200')])
    after = resolve([old, target, mapping('c', 'KB5000004', '26100.200')])
    assert before.changed_in_kb == after.changed_in_kb == 'unknown'
    assert [(p.grade, p.fix_boundary, p.reason_codes) for p in before.pairs] == [
        (p.grade, p.fix_boundary, p.reason_codes) for p in after.pairs
    ]


def test_unordered_older_variants_withhold_fix_boundary_and_automatic_choice():
    result = resolve([
        mapping('a', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('c', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert result.changed_in_kb == 'yes'  # the target differs from either earlier variant
    assert result.ambiguous
    assert all(pair.fix_boundary == 'unverified' and 'WINDOW_CONFOUNDED' in pair.reason_codes
               for pair in result.pairs)
    with pytest.raises(KbcStoreError, match='--pair') as caught:
        KbService._pick_pair([result], None)
    assert caught.value.code == 'PT-KBC-INPUT'
    (pair,) = result.pairs
    assert KbService._pick_pair([result], pair.pair_id[:12]) == pair


@pytest.mark.parametrize('sole_viable_cause', ['unavailable-variant', 'truncated-list'])
def test_variant_ambiguity_refuses_default_and_keeps_explicit_choice(sole_viable_cause):
    old = mapping('a', 'KB5000001', '26100.100', day='2099-01-01')
    variant = mapping('c', 'KB5000003', '26100.200')
    if sole_viable_cause == 'unavailable-variant':
        variant.update(download=None, variant='delta')
    rows, rejected = lineage.index_rows(
        [old, mapping('b', 'KB5000003', '26100.200'), variant], file_name=FILE_NAME
    )
    assert rejected == 0
    limit = 1 if sole_viable_cause == 'truncated-list' else 1000
    result = resolver.resolve(rows, kb='KB5000003', scope=SCOPE, file_name=FILE_NAME, limit=limit)
    assert result.changed_in_kb == 'unknown'
    (only_viable,) = [pair for pair in result.pairs if pair.grade != 'X']
    assert KbService._pick_pair([result], only_viable.pair_id[:12]) == only_viable
    try:
        default = KbService._pick_pair([result], None)
    except KbcStoreError as exc:
        assert exc.code == 'PT-KBC-INPUT'
    else:
        assert default is None


@pytest.mark.parametrize(('old_date', 'old_build'), [('2099-01-01', None), ('2099-02-01', '26100.100')])
def test_unambiguous_pair_uses_explicit_within_family_chronology(old_date, old_build):
    result = resolve([
        mapping('a', 'KB5000001', old_build, day=old_date),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert result.changed_in_kb == 'yes'
    (pair,) = result.pairs
    assert (pair.grade, pair.fix_boundary) == ('A', 'source-supported')
    assert KbService._pick_pair([result], None) == pair


@pytest.mark.parametrize('peer_sha', ['a', 'c'], ids=['peer-sorts-before', 'peer-sorts-after'])
def test_change_stays_unknown_when_prior_variants_disagree_on_target_content(peer_sha):
    result = resolve([
        mapping('b', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping(peer_sha, 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert result.ambiguous
    assert all(pair.fix_boundary == 'unverified' for pair in result.pairs)
    assert (result.changed_in_kb, result.last_changed_in) == ('unknown', None)


@pytest.mark.parametrize('peer_sha', ['a', 'c'], ids=['peer-sorts-before', 'peer-sorts-after'])
def test_unchanged_run_cannot_attribute_its_origin_to_a_hash_sorted_kb(peer_sha):
    result = resolve([
        mapping('b', 'KB5000000', '26100.50', day='2098-12-15'),
        mapping(peer_sha, 'KB5000000', '26100.50', day='2098-12-15'),
        mapping('b', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert result.ambiguous
    assert result.changed_in_kb in ('unknown', 'no')
    assert result.last_changed_in is None


def test_strictly_ordered_different_bytes_between_observations_keep_reversion():
    result = resolve([
        mapping('b', 'KB5000000', '26100.50', day='2098-12-15'),
        mapping('c', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ])
    assert (result.changed_in_kb, result.last_changed_in, result.ambiguous) == ('yes', None, False)


@pytest.mark.parametrize('cached', [False, True])
def test_predecessor_accepts_equal_copied_target_with_local_chronology_cache(cached):
    rows, rejected = lineage.index_rows([
        mapping('a', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ], file_name=FILE_NAME)
    assert rejected == 0
    line = lineage.timeline(rows, '11-24H2')
    target = replace(line[-1])
    assert target == line[-1] and target is not line[-1]
    order = lineage.LineageOrder(line) if cached else None
    older, between = lineage.predecessor(line, target, order=order)
    assert older is line[0] and between == ()


@pytest.mark.parametrize('cached', [False, True])
def test_predecessor_absent_target_preserves_value_error(cached):
    rows, rejected = lineage.index_rows([
        mapping('a', 'KB5000001', '26100.100', day='2099-01-01'),
        mapping('b', 'KB5000003', '26100.200'),
    ], file_name=FILE_NAME)
    assert rejected == 0
    line = lineage.timeline(rows, '11-24H2')
    absent = replace(line[-1], availability='local')
    assert absent not in line
    order = lineage.LineageOrder(line) if cached else None
    with pytest.raises(ValueError):
        lineage.predecessor(line, absent, order=order)
