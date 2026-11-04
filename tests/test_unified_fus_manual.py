"""Manual adapter: an analyst pairing whose side cannot be resolved to an RVA is never turned into a one-sided claim."""
from __future__ import annotations

import pytest
from unified_s0_fixtures import addr_map, func, inputs, match

from patchtrace.unified import store
from patchtrace.unified.compute import compute_result
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources import DEGRADING
from patchtrace.unified.sources.manual import ManualAdapter


def test_unresolvable_side_does_not_become_a_one_sided_claim():
    manual = match('mm1', 'modified', [func('f', 0x1000)], [func('g', None)], types=['manual'], manual=True)
    out = ManualAdapter().atoms(inputs([manual]), addr_map(), Budget())
    assert out.atoms == () and out.groups == ()
    assert 'manual-unresolved:1' in out.limitations
    assert 'manual-unresolved' in DEGRADING


def test_resolvable_one_sided_declaration_is_kept():
    manual = match('mm2', 'removed', older=[func('f', 0x1000)], manual=True)
    out = ManualAdapter().atoms(inputs([manual]), addr_map(), Budget())
    assert [(a.older_rva, a.newer_rva) for a in out.atoms] == [(0x1000, None)]
    assert out.limitations == ()


def test_manual_unmatched_with_both_sides_is_never_an_affirmative_pairing():
    """The analyst's category says the functions have no counterpart: two one-sided claims, never a tier-M pair."""
    manual = match('mm3', 'unmatched', older=[func('f', 0x1000)], newer=[func('g', 0x1100)], manual=True)
    out = ManualAdapter().atoms(inputs([manual]), addr_map(), Budget())
    assert out.groups == ()
    assert {(a.older_rva, a.newer_rva) for a in out.atoms} == {(None, 0x1100), (0x1000, None)}


ONE_SIDED = ('removed', 'added', 'unmatched')   # 06 s6: the only categories that declare a missing counterpart



@pytest.mark.parametrize('category', ['modified', 'unchanged', 'split', 'merged', 'ambiguous'])
@pytest.mark.parametrize('side', ['older', 'newer'])
def test_a_pairing_category_with_one_empty_side_is_never_a_one_sided_claim(category, side):
    """`correct_match` does not tie the category to the sides, so an analyst can save `modified` with one function.
    Turning that into a tier-M older-only/newer-only claim would state the opposite of the analyst's category; the
    correction is skipped and counted like any other unresolvable one (degrading, the run is partial)."""
    picked = {side: [func('f', 0x1000 if side == 'older' else 0x1100)]}
    manual = match('mm4', category, manual=True, **picked)
    out = ManualAdapter().atoms(inputs([manual]), addr_map(), Budget())
    assert out.atoms == () and out.groups == ()
    assert 'manual-unresolved:1' in out.limitations


@pytest.mark.parametrize('category', ONE_SIDED[2:])
def test_unmatched_with_one_side_stays_a_one_sided_claim(category):
    manual = match('mm5', category, older=[func('f', 0x1000)], manual=True)
    out = ManualAdapter().atoms(inputs([manual]), addr_map(), Budget())
    assert [(a.older_rva, a.newer_rva) for a in out.atoms] == [(0x1000, None)]
    assert out.limitations == ()


def test_the_adapter_version_keys_the_changed_semantics():
    """Results stored before the fixes above must not be served as current: the version is part of the result key."""
    from patchtrace.unified.sources.manual import VERSION
    manual = match('mm6', 'modified', older=[func('f', 0x1000)], newer=[func('g', 0x1100)], manual=True)
    refs = ManualAdapter().source_refs(inputs([manual]), addr_map())
    assert VERSION == 'manual/5' and [r.version for r in refs] == ['manual/5']


@pytest.mark.parametrize('category,side', [
    (category, side) for category in ('modified', 'unchanged', 'split', 'merged', 'ambiguous',
                                       'removed', 'added', 'unmatched')
    for side in ('older', 'newer')
    if (category, side) not in (('removed', 'newer'), ('added', 'older'))
])
def test_partly_resolved_correction_is_rejected_as_a_whole(category, side):
    older = [func('old', 0x1000)] if category != 'added' else []
    newer = [func('new', 0x1100)] if category != 'removed' else []
    (older if side == 'older' else newer).append(func('unresolved', None))
    correction = match('incomplete', category, older=older, newer=newer, manual=True)
    valid = match('valid', 'modified', older=[func('old_valid', 0x1200)],
                  newer=[func('new_valid', 0x1300)], manual=True)
    out = ManualAdapter().atoms(inputs([correction, valid]), addr_map(), Budget())
    assert [(atom.older_rva, atom.newer_rva) for atom in out.atoms] == [(0x1200, 0x1300)]
    assert out.groups == ()
    assert {(node.side, node.rva) for node in out.nodes} == {('older', 0x1200), ('newer', 0x1300)}
    assert 'manual-unresolved:1' in out.limitations


def test_partly_resolved_manual_merge_publishes_partial_without_pair_or_facts(tmp_path):
    correction = match('merge', 'merged', older=[func('old', 0x1000), func('missing', None)],
                       newer=[func('new', 0x1100)], manual=True)
    destination = tmp_path / 'result'
    destination.mkdir()
    manifest = compute_result(inputs([correction]), addr_map(), result_dir=destination, sources=['manual'])
    assert manifest.status == 'partial'
    assert 'manual-unresolved:1' in manifest.limitations
    assert list(store.read_rows(destination, manifest)) == []
    assert list(store.read_facts(destination, manifest)) == []


@pytest.mark.parametrize('category', ['added', 'removed'])
@pytest.mark.parametrize('shape', ['both', 'opposite', 'empty'])
def test_added_and_removed_declarations_require_the_named_side_only(tmp_path, category, shape):
    older = [func('old', 0x1000)] if shape == 'both' or (shape == 'opposite' and category == 'added') else []
    newer = [func('new', 0x1100)] if shape == 'both' or (shape == 'opposite' and category == 'removed') else []
    correction = match('contradictory', category, older=older, newer=newer, manual=True)
    data = inputs([correction])
    out = ManualAdapter().atoms(data, addr_map(), Budget())
    assert out.atoms == () and out.groups == () and out.nodes == ()
    assert 'manual-unresolved:1' in out.limitations
    destination = tmp_path / 'result'
    destination.mkdir()
    manifest = compute_result(data, addr_map(), result_dir=destination, sources=['manual'])
    assert manifest.status == 'partial' and 'manual-unresolved:1' in manifest.limitations
    assert list(store.read_rows(destination, manifest)) == []
    assert list(store.read_facts(destination, manifest)) == []
