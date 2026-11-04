"""Manual adapter: an analyst pairing whose side cannot be resolved to an RVA is never turned into a one-sided claim."""
from __future__ import annotations

import pytest
from unified_s0_fixtures import addr_map, func, inputs, match

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
    assert VERSION == 'manual/3' and [r.version for r in refs] == ['manual/3']
