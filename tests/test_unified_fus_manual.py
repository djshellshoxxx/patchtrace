"""Manual adapter: an analyst pairing whose side cannot be resolved to an RVA is never turned into a one-sided claim."""
from __future__ import annotations

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
