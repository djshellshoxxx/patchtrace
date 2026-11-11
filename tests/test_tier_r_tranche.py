"""LBL-02/03/04 recipe tranche (libdeflate, stb, c-ares): offline shape checks on the committed catalogue.

The build is the real check and runs on a CI runner (run R1); these tests pin what can be known without a compiler:
the recipe and its cards exist in both layouts, every card is a pair of declared pins, licences are permissive with
recorded hashes, and a card whose build has not been run says so instead of claiming verification.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402

CATALOGUE = ROOT / 'tools' / 'calibration' / 'tier_r' / 'catalogue'
BOOK = C.load_recipes((CATALOGUE / 'recipes.json').read_bytes())
CARDS = C.load_cards((CATALOGUE / 'releases.json').read_bytes()) + C.load_cards((CATALOGUE / 'cves.json').read_bytes())
HEX40, HEX64 = re.compile(r'^[0-9a-f]{40}$'), re.compile(r'^[0-9a-f]{64}$')
# project -> (SPDX licence, minimum cards, pins must be adjacent releases)
TRANCHE = {'libdeflate': ('MIT', 3, True), 'stb': ('MIT', 3, True), 'c-ares': ('MIT', 3, True)}


def _raw_cards(project):
    return json.loads((CATALOGUE / 'releases.d' / f'{project}.json').read_text(encoding='utf-8'))


@pytest.mark.parametrize('project', sorted(TRANCHE))
def test_tranche_recipe_is_in_both_layouts(project):
    spdx = TRANCHE[project][0]
    recipe = BOOK.get(project)
    assert recipe is not None and recipe.license_spdx == spdx
    assert C.load_recipes((CATALOGUE / 'recipes.d' / f'{project}.json').read_bytes()).get(project) == recipe
    assert tuple(c for c in CARDS if c.project == project) == C.load_cards(json.dumps(_raw_cards(project)).encode())


@pytest.mark.parametrize('project', sorted(TRANCHE))
def test_tranche_pairs_are_declared_pins(project):
    _, minimum, adjacent = TRANCHE[project]
    recipe = BOOK.get(project)
    cards = [c for c in CARDS if c.project == project]
    assert len(cards) >= minimum
    for pin in recipe.pins:
        assert HEX40.match(pin.commit) and HEX64.match(pin.license_sha256) and pin.ref != pin.commit
    order = [p.commit for p in recipe.pins]
    for card in cards:
        old, new = recipe.pin_for(card.old.commit), recipe.pin_for(card.new.commit)
        assert old and new and old.ref == card.old.ref and new.ref == card.new.ref, card.id
        if adjacent:
            assert order.index(old.commit) + 1 == order.index(new.commit), f'{card.id}: not adjacent pins'
        assert card.license_spdx == recipe.license_spdx
        assert card.changed_functions or card.kind in {'refactor-control', 'no-op', 'build-system-only'}, card.id
        assert len(card.unchanged_controls) >= 2, card.id
        assert not set(card.unchanged_controls) & {f.name for f in card.changed_functions}, card.id


@pytest.mark.parametrize('project', sorted(TRANCHE))
def test_unbuilt_cards_never_claim_an_agent_verification(project):
    """verified_by_agent_run covers the source diff only; a card whose factory build has not run says so."""
    for raw in _raw_cards(project):
        verification = raw['verification']
        if verification.get('build_verified') is not True:
            assert verification.get('status') == 'unverified-build', raw['id']
            assert raw['build']['mingw_ok'] == 'unverified', raw['id']



def test_stb_translation_unit_wrappers_define_their_implementation_macro():
    """stb is header-only and has no tags: each authored wrapper is exactly `#define X_IMPLEMENTATION` + `#include`."""
    recipe = BOOK.get('stb')
    assert recipe.sources == ('stb_vorbis.c',) and recipe.write
    for rule in recipe.write:
        header = rule.path.replace('_impl.c', '.h')
        macro = header[:-2].upper() + '_IMPLEMENTATION'
        assert rule.text == f'#define {macro}\n#include "{header}"\n', rule.path
