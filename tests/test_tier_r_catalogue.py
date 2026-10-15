"""SPEC-32 committed catalogue (offline): recipes load strictly, every card validates with tools/corpus_check.py, every
card's project has a recipe whose pins carry both commits, CVE ids are well formed and only on cve-fix cards, licences are
on the allow-list with a recorded SHA-256, and nothing in the catalogue is an executable image."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402

CATALOGUE = ROOT / 'tools' / 'calibration' / 'tier_r' / 'catalogue'
FOUND = ROOT / 'corpus' / 'catalog'
_spec = importlib.util.spec_from_file_location('corpus_check', ROOT / 'tools' / 'corpus_check.py')
corpus_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus_check)

BOOK = C.load_recipes((CATALOGUE / 'recipes.json').read_bytes())
CARD_FILES = ('releases.json', 'cves.json')
CARDS = [card for name in CARD_FILES for card in C.load_cards((CATALOGUE / name).read_bytes())]
HEX40, HEX64 = re.compile(r'^[0-9a-f]{40}$'), re.compile(r'^[0-9a-f]{64}$')
CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,7}$')
MAX_PROJECTS = 15  # 13 + LBL-02..04 (libdeflate, stb, c-ares); LBL plan s9 allows 14 + reserve
RECIPES = [pytest.param(r, id=r.project) for r in BOOK.recipes]
CARD_PARAMS = [pytest.param(c, id=c.id) for c in CARDS]


def test_recipes_and_cards_are_consistent():
    assert BOOK.recipes and CARDS
    for card in CARDS:
        recipe = BOOK.get(card.project)
        assert recipe is not None, card.id
        assert card.license_spdx == recipe.license_spdx
        for side in (card.old, card.new):
            pin = recipe.pin_for(side.commit)
            assert pin is not None and pin.ref == side.ref, (card.id, side)
    for name in CARD_FILES:
        assert corpus_check.check_catalog(CATALOGUE / name) == [], name


def test_project_count_is_bounded_and_every_exclusion_has_a_reason():
    assert 2 <= len(BOOK.recipes) <= MAX_PROJECTS
    for entry in BOOK.excluded:
        assert entry.get('project') and len(entry.get('reason', '')) > 20, entry
    assert not {e['project'] for e in BOOK.excluded} & {r.project for r in BOOK.recipes}


@pytest.mark.parametrize('recipe', RECIPES)
def test_recipe_pins_are_verified_shapes(recipe):
    assert recipe.license_spdx in C.PERMISSIVE_SPDX
    assert recipe.license_spdx in corpus_check.SPDX, 'cards must be able to use the recipe licence id'
    assert recipe.pins, 'a recipe without pins cannot be fetched'
    for pin in recipe.pins:
        assert HEX40.match(pin.commit) and HEX64.match(pin.license_sha256), pin
        assert pin.ref and pin.ref != pin.commit
    assert len({p.commit for p in recipe.pins}) == len(recipe.pins)
    assert recipe.upstream_git.startswith('https://github.com/')


@pytest.mark.parametrize('recipe', RECIPES)
def test_recipes_are_explicit_argv_inputs_not_build_scripts(recipe):
    """No configure/cmake/make/python/tcl is ever run: sources are C files, config comes from copy/write only."""
    for pattern in (*recipe.sources, *recipe.exclude):
        assert not pattern.endswith(('.sh', '.py', '.cmake', '.in', '.tcl', '.mk')), pattern
        assert '..' not in pattern.split('/'), pattern
    for rule in recipe.copy_files:
        assert rule.src != rule.dst
    for rule in recipe.write:
        assert rule.path.endswith(('.h', '.c')), rule.path
    for variant in recipe.variants:
        for rule in variant.write or ():
            assert rule.path.endswith(('.h', '.c')), rule.path
    for dep in recipe.depends:
        assert BOOK.get(dep.project) is not None, dep
        assert BOOK.get(dep.project).pin_for(dep.commit) is not None, 'dependency must be a pinned commit of its recipe'


@pytest.mark.parametrize('card', CARD_PARAMS)
def test_card_kind_matches_cve_ids(card):
    assert all(CVE_ID.match(c) for c in card.cve), card.cve
    if card.kind == 'cve-fix':
        assert card.cve, 'a cve-fix card must name its CVE ids (from the project own changelog or commit message)'
        assert card.changed_functions, 'a fix card must name its changed functions'
        assert card.semantic_change is True
    else:
        assert not card.cve, 'only cve-fix cards carry CVE ids'
    assert card.old.commit != card.new.commit and HEX40.match(card.old.commit) and HEX40.match(card.new.commit)
    assert card.sources and all(s.startswith('https://') for s in card.sources)


def test_catalogue_files_hold_the_right_strata():
    releases = C.load_cards((CATALOGUE / 'releases.json').read_bytes())
    cves = C.load_cards((CATALOGUE / 'cves.json').read_bytes())
    assert releases and cves
    assert all(c.kind in {'release', 'large-rewrite'} for c in releases)
    assert all(c.kind == 'cve-fix' for c in cves)


def test_card_ids_are_unique_across_catalogue_and_found_cases():
    ids = [c.id for c in CARDS]
    for path in sorted(FOUND.glob('*.json')):
        ids += [c['id'] for c in json.loads(path.read_text(encoding='utf-8'))]
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_tag_pinned_found_cases_with_a_recipe_resolve_to_pins():
    """A found case whose refs are plain tags and whose project has a recipe must be buildable from its pins."""
    plain = re.compile(r'^[A-Za-z0-9._-]+$')
    for path in sorted(FOUND.glob('*.json')):
        for card in json.loads(path.read_text(encoding='utf-8')):
            recipe = BOOK.get(card['project'])
            if recipe is None or not all(plain.match(card[s]['ref']) for s in ('old', 'new')):
                continue
            for side in ('old', 'new'):
                pin = recipe.pin_for(card[side]['commit'])
                assert pin is not None and pin.ref == card[side]['ref'], (card['id'], side)


def test_catalogue_holds_no_executable_images():
    files = [p.relative_to(ROOT).as_posix() for p in CATALOGUE.rglob('*') if p.is_file()]
    assert all(Path(f).suffix == '.json' for f in files)
    assert [p for p in corpus.guard(ROOT, None, files=files) if 'inside the work tree' not in p] == []


def test_per_project_split_mirrors_the_monolithic_files():
    """recipes.d/<project>.json and releases.d/<project>.json (LBL-01 loader layout) carry exactly the same data."""
    merged = [r for path in sorted((CATALOGUE / 'recipes.d').glob('*.json'))
              for r in C.load_recipes(path.read_bytes()).recipes]
    assert {r.project: r for r in merged} == {r.project: r for r in BOOK.recipes}
    split = [c for path in sorted((CATALOGUE / 'releases.d').glob('*.json')) for c in C.load_cards(path.read_bytes())]
    assert sorted(split, key=lambda c: c.id) == sorted(CARDS, key=lambda c: c.id)
    for path in sorted((CATALOGUE / 'releases.d').glob('*.json')):
        assert corpus_check.check_catalog(path) == [], path.name
