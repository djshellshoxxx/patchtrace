"""LBL-05 card audit regressions (offline). Findings and evidence: docs/audits/20261015-lbl05-card-audit.md.

Passing tests pin what the audit verified. Strict xfails pin open items that need an owner or integrator decision
outside this slice's exclusive files; they turn into failures (XPASS) as soon as the data is fixed, so the marker is
then removed.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402

FOUND = ROOT / 'corpus' / 'catalog'
RELEASES = ROOT / 'tools' / 'calibration' / 'tier_r' / 'catalogue' / 'releases.d'
RECIPES = ROOT / 'tools' / 'calibration' / 'tier_r' / 'catalogue' / 'recipes.d'
REGISTER = ROOT / 'docs' / 'plans' / 'calibration-licences.md'
CVE_ID = re.compile(r'CVE-\d{4}-\d{4,7}')
DISAGREE = re.compile(r'\b([1-9]\d*) disagree')
AUDITED_CVE_IDS = 32  # docs/audits/20261015-lbl05-card-audit.md, corpus/catalog/*.json
_spec = importlib.util.spec_from_file_location('corpus_check', ROOT / 'tools' / 'corpus_check.py')
corpus_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus_check)


def _found_cards() -> list[dict]:
    return [card for path in sorted(FOUND.glob('*.json')) for card in json.loads(path.read_text(encoding='utf-8'))]


def _recipe(project: str) -> dict:
    for path in sorted(RECIPES.glob('*.json')):
        for recipe in json.loads(path.read_text(encoding='utf-8'))['recipes']:
            if recipe['project'] == project:
                return recipe
    raise KeyError(project)


@pytest.mark.parametrize('path', [pytest.param(p, id=p.stem) for p in sorted(FOUND.glob('*.json'))])
def test_found_card_file_passes_structural_checker(path: Path) -> None:
    assert corpus_check.check_catalog(path) == []


def test_cve_ids_are_well_formed_unique_and_match_the_audited_count() -> None:
    ids = [cve for card in _found_cards() for cve in card.get('cve', [])]
    assert all(re.fullmatch(CVE_ID, cve) for cve in ids)
    assert len(ids) == len(set(ids)) == AUDITED_CVE_IDS


def test_cve_ids_appear_only_on_cve_fix_cards() -> None:
    assert all(card['kind'] == 'cve-fix' for card in _found_cards() if card.get('cve'))


@pytest.mark.parametrize('card', [pytest.param(c, id=c['id']) for c in _found_cards()])
def test_fix_pair_commits_differ(card: dict) -> None:
    assert card['old']['commit'] != card['new']['commit']


@pytest.mark.parametrize('path', [pytest.param(p, id=p.stem) for p in sorted(RELEASES.glob('*.json'))])
def test_release_cards_declare_no_unexplained_disagree(path: Path) -> None:
    for card in json.loads(path.read_text(encoding='utf-8')):
        assert not DISAGREE.search(json.dumps(card)), card['id']


@pytest.mark.parametrize('path', [pytest.param(p, id=p.stem) for p in sorted(RELEASES.glob('*.json'))])
def test_release_pins_resolve_to_recipe_pins_and_licence(path: Path) -> None:
    cards = json.loads(path.read_text(encoding='utf-8'))
    recipe = _recipe(path.stem)
    pins = {pin['ref']: pin for pin in recipe['pins']}
    for card in cards:
        assert card['license_spdx'] == recipe['license_spdx'], card['id']
        assert card['upstream_git'] == recipe['upstream_git'], card['id']
        for side in ('old', 'new'):
            ref = card[side]['ref']
            assert ref in pins, (card['id'], ref)
            assert pins[ref]['commit'] == card[side]['commit'], (card['id'], side)


@pytest.mark.parametrize('path', [pytest.param(p, id=p.stem) for p in sorted(RECIPES.glob('*.json'))])
def test_recipe_licences_are_on_the_allow_list(path: Path) -> None:
    for recipe in json.loads(path.read_text(encoding='utf-8'))['recipes']:
        assert recipe['license_spdx'] in C.PERMISSIVE_SPDX, recipe['project']


def test_pcre2_recipe_licence_matches_the_register() -> None:
    assert _recipe('pcre2')['license_spdx'] == 'BSD-3-Clause WITH PCRE2-exception'


def test_no_found_card_uses_a_blocked_licence() -> None:
    blocked = [card['id'] for card in _found_cards() if card['license_spdx'] == 'PostgreSQL']
    assert blocked == []


def test_brotli_and_zstd_are_in_the_licence_register() -> None:
    text = REGISTER.read_text(encoding='utf-8')
    assert 'brotli' in text and 'zstd' in text
