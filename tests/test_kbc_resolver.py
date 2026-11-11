"""K5: pair candidates from index rows (plan 3.1 table, 7.2 pair rules, plan 6 traps). Pure; synthetic records."""
from __future__ import annotations

import itertools
import json

import pytest
from kbc_k5_support import SHA, record, rows_of, scope

from patchtrace.kbcorrelation import lineage as ln
from patchtrace.kbcorrelation import resolver as rs

NAME = 'exampledrv.sys'


def resolve(kb, doc=None, *, name=NAME, sc=None, **kw):
    rows, skipped = rows_of(record(name) if doc is None else doc, name)
    return rs.resolve(rows, kb=kb, scope=sc or scope(), file_name=name, skipped_rows=kw.pop('skipped_rows', skipped),
                      **kw)


def test_new_build_is_a_grade_a_index_adjacent_pair_with_bytes_pending():
    res = resolve('KB5097000')
    (pair,) = res.pairs
    assert res.changed_in_kb == 'yes' and res.version_key == '11-24H2'
    assert (pair.grade, pair.tier, pair.bytes_state, pair.lineage_state) == ('A', 'C', 'pending', 'index-adjacent')
    assert (pair.older.sha256, pair.newer.sha256) == (SHA['X'], SHA['Y']) and pair.window == ()
    assert pair.older.origin == 'index-row' and pair.older.authenticity == 'signature-unknown'
    assert pair.window_complete is None


def test_md5_only_newest_build_is_a_pair_with_candidate_availability():
    res = resolve('KB5099001')
    (pair,) = res.pairs
    assert pair.newer.sha256 == SHA['Z'] and pair.newer.availability == 'candidates'
    assert pair.older.sha256 == SHA['Y'] and pair.grade == 'A'
    assert 'INDEX_GAP' in pair.reason_codes  # two index entries were skipped: the newest builds may be missing


def test_unchanged_in_kb_is_not_a_pair_for_that_kb():
    res = resolve('KB5099001', name='examplenet.sys')
    (pair,) = res.pairs
    assert res.changed_in_kb == 'no' and res.last_changed_in == 'KB5097000'
    assert pair.window == ('KB5097000', 'KB5098000') and 'WINDOW_CONFOUNDED' in pair.reason_codes
    assert pair.grade == 'A' and pair.older.sha256 == '1' * 64


def test_kb_absent_from_the_index_says_so():
    res = resolve('KB5000000')
    assert res.pairs == () and res.blockers == ('NO_NEWER',)
    assert res.note == 'Not in the file index (Windows 10/11 client x64 only).' and res.changed_in_kb == 'unknown'


def test_first_indexed_build_has_no_older():
    res = resolve('KB5096000', name='examplenet.sys')
    assert res.pairs == () and res.blockers == ('NO_OLDER',) and res.changed_in_kb == 'unknown'
    assert res.note == 'No earlier build of this file is listed for this product.'


def test_base_image_is_a_valid_older_side():
    (pair,) = resolve('KB5096000').pairs
    assert pair.older.sha256 == SHA['A'] and pair.older.build_ubr is None and pair.grade == 'A'


def test_pair_never_auto_across_scope():
    res = resolve('KB5099002', sc=scope('10-22H2'))
    assert res.version_key == '10-22H2' and res.blockers == ('NO_OLDER',) and res.pairs == ()
    rows, _ = rows_of(record())
    by_key = {(r.build.version_key, r.kb): r for r in rows}
    cross = rs.propose_index_pair(by_key[('11-24H2', 'KB5097000')], by_key[('10-22H2', 'KB5099002')],
                                  scope_id='1' * 64)
    assert cross.grade == 'X' and 'CROSS_PRODUCT' in cross.reason_codes and cross.lineage_state == 'incompatible'


def test_server_scope_is_a_hard_block_not_an_empty_answer():
    res = resolve('KB5097000', sc=scope(family='windows-server'))
    assert res.blockers == ('SERVER_NOT_COVERED',) and res.pairs == ()
    assert res.note.startswith('The file index covers Windows 10/11 client updates only')


def test_scope_without_index_key_is_not_guessed():
    res = resolve('KB5097000', sc=scope(None))
    assert res.pairs == () and res.note == 'No file-index key is known for this product.'


def test_same_class_only_keeps_a_preview_build_out_of_the_older_side():
    doc = record()
    preview = doc[SHA['Y']]['windowsVersions']['11-24H2'].pop('KB5098000')
    doc['7' * 64] = {'fileInfo': dict(doc[SHA['Y']]['fileInfo'], sha256='7' * 64),
                     'windowsVersions': {'11-24H2': {'KB5098000': preview}}}
    default = resolve('KB5099001', doc)
    assert default.pairs[0].older.sha256 == SHA['Y'] and default.pairs[0].window == ('KB5098000',)
    assert 'WINDOW_CONFOUNDED' in default.pairs[0].reason_codes
    wider = resolve('KB5099001', doc, same_class_only=False)
    assert wider.pairs[0].older.sha256 == '7' * 64 and wider.pairs[0].window == ()


def test_all_pairs_obey_the_grade_rules():
    # property over every ordered pair of rows from both records, with and without an ARM64 stand-in
    rows, _ = rows_of(record())
    net, _ = rows_of(record('examplenet.sys'), 'examplenet.sys')
    for older, newer in itertools.permutations([*rows, *net], 2):
        pair = rs.propose_index_pair(older, newer, scope_id='1' * 64)
        same_scope = older.build.version_key == newer.build.version_key
        ordered = rs.order_key(older) < rs.order_key(newer)
        if pair.grade == 'A':
            assert same_scope and ordered and older.sha256 != newer.sha256
            assert older.machine == newer.machine == 'amd64'
        if not same_scope:
            assert pair.grade == 'X'
        if not ordered:
            assert pair.grade == 'X' and pair.lineage_state == 'incompatible'


@pytest.mark.parametrize('architecture', ['arm64', 'x86', 'unknown'])
def test_unsupported_product_scope_architecture_blocks_amd64_index_pairs(architecture):
    # Even two internally compatible x64 rows do not belong to a non-x64 selected product.
    result = resolve('KB5097000', sc=scope(arch=architecture))
    assert result.pairs == () and result.blockers == ('ARCH',)
    assert 'AMD64' in result.note


def test_arm64_product_name_does_not_resolve_to_amd64_index_pair():
    from patchtrace.kbcorrelation.products import scope_for

    product = scope_for('a' * 64, 'arm-product', 'Windows 11 Version 24H2 for ARM64-based Systems')
    assert product.winbindex_key == '11-24H2' and product.architecture == 'arm64'
    result = resolve('KB5097000', sc=product)
    assert result.pairs == () and result.blockers == ('ARCH',)


def test_arm64_side_is_a_hard_block():
    doc = record()
    doc[SHA['Y']]['fileInfo']['machineType'] = 43620
    (pair,) = resolve('KB5097000', doc).pairs
    assert pair.grade == 'X' and pair.bytes_state == 'incompatible' and 'ARCH' in pair.reason_codes


def test_reverse_order_is_never_grade_a():
    rows, _ = rows_of(record())
    by_kb = {r.kb: r for r in rows if r.build.version_key == '11-24H2'}
    pair = rs.propose_index_pair(by_kb['KB5097000'], by_kb['KB5096000'], scope_id='1' * 64)
    assert pair.grade == 'X' and 'ORDER_UNVERIFIED' in pair.reason_codes


def test_identical_content_is_grade_x():
    rows, _ = rows_of(record('examplenet.sys'), 'examplenet.sys')
    same = [r for r in rows if r.sha256 == '2' * 64]
    pair = rs.propose_index_pair(same[0], same[1], scope_id='1' * 64)
    assert pair.grade == 'X' and 'IDENTICAL_CONTENT' in pair.reason_codes


def test_delta_only_side_is_a_hard_block():
    doc = record()
    del doc[SHA['Z']]['fileInfo']['lastSectionVirtualAddress']
    (pair,) = resolve('KB5099001', doc).pairs
    assert pair.newer.availability == 'delta-only' and pair.grade == 'X' and 'DELTA_ONLY' in pair.reason_codes


@pytest.mark.parametrize('fixed, expected', [
    ('26100.120', 'source-supported'), ('26200.120', 'source-supported'), ('26100.200', 'unverified'),
    ('26100.100', 'contradicted'), ('bad', 'unverified'), (None, 'unverified')],
    ids=['heading-build', 'release-version', 'later-fix', 'older-at-fix', 'malformed', 'none'])
def test_fix_boundary_uses_only_stated_builds(fixed, expected):
    (pair,) = resolve('KB5099001', fixed_build=fixed).pairs
    assert pair.fix_boundary == expected


def test_shared_kb_build_prefix_is_not_taken_from_the_sibling():
    # KB5077181 pattern: the row under 11-24H2 carries the 25H2 build in releaseVersion; the heading lists both
    doc = record()
    heading = doc[SHA['Z']]['windowsVersions']['11-24H2']['KB5099001']['updateInfo']
    heading['heading'] = 'February 11, 2099-KB5099001 (OS Build 26200.120)'
    (pair,) = resolve('KB5099001', doc, fixed_build='26100.120').pairs
    assert pair.fix_boundary == 'unverified'
    sibling = resolve('KB5099001', doc, sc=scope('11-25H2'), fixed_build='26200.120')
    assert sibling.version_key == '11-25H2' and sibling.pairs == () and sibling.blockers == ('NO_OLDER',)


def test_fix_boundary_needs_the_immediate_predecessor():
    (pair,) = resolve('KB5099001', name='examplenet.sys', fixed_build='26100.120').pairs
    assert pair.fix_boundary == 'unverified'  # the window is not empty: the change may belong to an earlier update


def test_ranking_is_lexicographic_and_stable():
    rows, _ = rows_of(record())
    by_kb = {r.kb: r for r in rows if r.build.version_key == '11-24H2'}
    good = rs.propose_index_pair(by_kb['KB5096000'], by_kb['KB5097000'], scope_id='1' * 64)
    blocked = rs.propose_index_pair(by_kb['KB5097000'], by_kb['KB5096000'], scope_id='1' * 64)
    wide = rs.propose_index_pair(by_kb['KB5096000'], by_kb['KB5099001'], scope_id='1' * 64,
                                 intervening=(by_kb['KB5097000'],))
    ordered = sorted([blocked, wide, good], key=rs.rank_key)
    assert ordered == [good, wide, blocked]
    assert rs.rank_key(good, 'yes') < rs.rank_key(good, 'unknown') < rs.rank_key(good, 'no')


def test_pair_list_is_truncated_and_flagged():
    doc = record()
    doc[SHA['V']]['windowsVersions'] = {'11-24H2': doc[SHA['Z']]['windowsVersions']['11-24H2']}
    res = resolve('KB5099001', doc, limit=1)
    assert len(res.pairs) == 1 and res.truncated and res.changed_in_kb == 'unknown'


def test_resolution_is_deterministic():
    assert resolve('KB5099001') == resolve('KB5099001')


def test_malformed_kb_is_rejected():
    with pytest.raises(ValueError):
        resolve('5099001')


# --- audit KBA-06: reverted bytes (spec 31-C C4) ---------------------------------------------------------------

# Pair ids of the committed fixtures as origin/main 882d1ca0 produced them (key 11-24H2, both class modes). The
# KBA-06 rule changes reverted timelines only, so every one of these is pinned.
MAIN_PAIR_IDS = {
    ('exampledrv.sys', 'KB5096000'): '3ce8d74792c32f7f6f4bf44b19a7f024caa91de47bb6673793305d98021f01a4',
    ('exampledrv.sys', 'KB5097000'): 'c7bc8acfec1f63a62fe40672e571b059e5d64d88709c49b782675e76d0a2d8d4',
    ('exampledrv.sys', 'KB5098000'): '927bfdff8b3b515e0951acd892d6e0d3202d4a1b55bbe46c4b7f1383ec5d8260',
    ('exampledrv.sys', 'KB5099001'): '3748ac4f43f306ff757eaf17fb756582c716c009a09a0463115743d2a021729b',
    ('examplenet.sys', 'KB5097000'): 'df5293e0ef559649fb98fe1d4774dcb0d2e0182b4a2fd6d0e7676961f5752bb0',
    ('examplenet.sys', 'KB5098000'): '5c3d52670d35f6737975752e0ee333e0699d84e63050861f6b0c208dddae8b85',
    ('examplenet.sys', 'KB5099001'): '179c8d861150e55ab3820ab8872557a268666c10ae081a60398fe5bc61102879',
}
STD, PRE = 'standard', 'preview'


def synthetic_rows(*spec):
    """Index rows of one 11-24H2 timeline from ``(sha letter, heading class)`` in release order, from KB5000000."""
    maps = [{'sha256': sha * 64, 'kb': f'KB500000{i}', 'version_key': '11-24H2', 'release_date': f'2099-01-{i + 1:02d}',
             'release_version': f'26100.{100 * (i + 1)}', 'machine_type': 0x8664, 'size': 100, 'heading_class': cls,
             'variant': 'full', 'download': 'direct', 'record_sha256': 'e' * 64} for i, (sha, cls) in enumerate(spec)]
    rows, rejected = ln.index_rows(maps, file_name='x.sys')
    assert rejected == 0
    return rows


def test_kba06_pair_ids_of_the_committed_fixtures_are_unchanged():
    seen = {}
    for name in ('exampledrv.sys', 'examplenet.sys'):
        rows, skipped = rows_of(record(name), name)
        for key, kb in itertools.product(ln.version_keys(rows), sorted({r.kb for r in rows if r.kb})):
            for same_class_only in (True, False):
                res = rs.resolve(rows, kb=kb, scope=scope(key), file_name=name, skipped_rows=skipped,
                                 same_class_only=same_class_only)
                assert key == '11-24H2' or res.pairs == ()
                for pair in res.pairs:
                    assert seen.setdefault((name, kb), pair.pair_id) == pair.pair_id
    assert seen == MAIN_PAIR_IDS


def test_kba06_reverted_build_pairs_with_the_earlier_distinct_build_not_its_own_bytes():
    rows = synthetic_rows(('f', STD), ('a', STD), ('b', PRE), ('a', STD))
    res = rs.resolve(rows, kb='KB5000003', scope=scope(), file_name='x.sys')
    (pair,) = res.pairs
    assert (pair.older.sha256, pair.newer.sha256, pair.grade) == ('f' * 64, 'a' * 64, 'A')
    assert pair.window == ('KB5000001', 'KB5000002') and pair.reason_codes == ('WINDOW_CONFOUNDED',)
    assert res.changed_in_kb == 'yes' and res.blockers == ()


def test_kba06_reverted_build_without_a_distinct_earlier_build_has_no_older():
    res = rs.resolve(synthetic_rows(('a', STD), ('b', PRE), ('a', STD)), kb='KB5000002', scope=scope(),
                     file_name='x.sys')
    assert res.pairs == () and res.blockers == ('NO_OLDER',)


def test_kba06_no_resolver_pair_carries_identical_content():
    """Every 4-row timeline over three contents and two update classes, every target, both class modes: the older
    side is the nearest earlier row with other bytes that the class rule admits, never the target's own bytes."""
    kinds = list(itertools.product('abc', (STD, PRE)))
    for spec in itertools.product(kinds, repeat=4):
        rows = ln.timeline(synthetic_rows(*spec), '11-24H2')
        for (position, target), same_class_only in itertools.product(enumerate(rows), (True, False)):
            res = rs.resolve(rows, kb=target.kb, scope=scope(), file_name='x.sys', same_class_only=same_class_only)
            start = position
            while start and rows[start - 1].sha256 == target.sha256:
                start -= 1
            anchor = rows[start].build.heading_class
            admitted = [r.sha256 for r in rows[:start] if r.sha256 != target.sha256
                        and (not same_class_only or r.build.heading_class == anchor)]
            assert [p.older.sha256 for p in res.pairs] == admitted[-1:], (spec, target.kb, same_class_only)
            assert all('IDENTICAL_CONTENT' not in p.reason_codes for p in res.pairs)
            assert (res.blockers == ('NO_OLDER',)) == (not admitted)


# --- audit KBA-08: a release-less Windows 10 name against the real Winbindex spelling ---------------------------

def test_kba08_release_less_windows_10_scope_resolves_rows_under_the_bare_1507_key():
    """Scope identity writes ``10-1507``; Winbindex itself keys Windows 10 bare (``1507``, audit KBA-01)."""
    from patchtrace.kbcorrelation.products import scope_for

    rtm = scope_for('d' * 64, 'P1', 'Windows 10 for x64-based Systems')
    res = resolve('KB5097000', json.loads(json.dumps(record()).replace('"11-24H2"', '"1507"')), sc=rtm)
    assert (res.version_key, res.blockers, res.changed_in_kb) == ('10-1507', (), 'yes')
    (pair,), (base,) = res.pairs, resolve('KB5097000').pairs
    assert (pair.older.sha256, pair.newer.sha256, pair.grade, pair.window) == (
        base.older.sha256, base.newer.sha256, base.grade, base.window)
