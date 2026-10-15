"""SPEC-31 S6a Tier R catalogue (tools/unified/corpus): offline consistency of recipes, cards and pins.

Nothing here builds or fetches: the live evidence (fetch, build, label) is recorded in docs/qa.md by the corpus runs.
The catalogue only adds the SPEC-31 view on top of SPEC-32 (`tools/calibration/tier_r`), which owns the contracts."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.unified.corpus import catalogue  # noqa: E402

PERMISSIVE_ONLY = {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'Zlib', 'ISC', 'Libpng-2.0', 'blessing'}


def test_the_committed_catalogue_has_no_problems():
    assert catalogue.problems() == []


def test_every_tier_r_project_of_the_spec_is_a_recipe_or_a_documented_exclusion():
    book = catalogue.recipe_book()
    built = {r.project for r in book.recipes}
    excluded = {e['project']: e['reason'] for e in catalogue.excluded()}
    assert set(catalogue.TIER_R_PROJECTS) <= built | set(excluded)
    assert all(len(excluded[p]) > 20 for p in set(catalogue.TIER_R_PROJECTS) - built)


def test_the_unified_catalogue_defines_no_recipe_of_its_own_and_holds_no_microsoft_data():
    assert not (catalogue.HERE / 'recipes.json').exists(), 'recipes live only in the Tier R book'
    assert {r.license_spdx for r in catalogue.recipe_book().recipes} <= PERMISSIVE_ONLY
    text = (catalogue.HERE / 'cards.json').read_text(encoding='utf-8').lower()
    assert not [w for w in ('microsoft', 'winbindex', 'ntoskrnl', 'tier w') if w in text]


def test_every_card_of_a_shared_project_uses_the_tier_r_recipe():
    book = catalogue.recipe_book()
    own = {c.id: c for c in C.load_cards((catalogue.HERE / 'cards.json').read_bytes())}
    assert {c.project for c in own.values()} <= {r.project for r in book.recipes}
    assert set(catalogue.SHARED_CARDS).isdisjoint(own)


def test_every_release_pair_names_two_pinned_commits_of_a_known_recipe():
    book = catalogue.recipe_book()
    cards = catalogue.load_cards()
    assert {c.project for c in cards} >= {'zlib', 'libpng', 'lua'}
    for card in cards:
        recipe = book.get(card.project)
        assert recipe is not None, card.id
        for side in (card.old, card.new):
            pin = recipe.pin_for(side.commit)
            assert pin is not None and pin.ref == side.ref, (card.id, side.ref)


def test_every_card_has_toolchain_independent_source_digests_and_nothing_else_has():
    pins = catalogue.load_pins()
    ids = {c.id for c in catalogue.load_cards()}
    assert set(pins.pairs) == ids
    for digests in pins.pairs.values():
        assert digests.old != digests.new


def test_the_new_catalogue_files_hold_no_executable_images():
    files = [p.relative_to(ROOT).as_posix() for p in catalogue.HERE.rglob('*') if p.is_file()]
    assert files and [p for p in corpus.guard(ROOT, None, files=files) if 'inside the work tree' not in p] == []


def test_the_new_cards_pass_the_corpus_input_checker():
    from tools import corpus_check
    assert corpus_check.check_catalog(catalogue.HERE / 'cards.json') == []


def _book_with(recipe: dict) -> C.RecipeBook:
    base = catalogue.recipe_book().model_dump(mode='json')
    base['recipes'] = [*base['recipes'], recipe]
    return C.RecipeBook.model_validate_json(json.dumps(base))


def test_a_copyleft_recipe_is_refused_by_the_contract():
    recipe = copy.deepcopy(catalogue.recipe_book().recipes[0].model_dump(mode='json'))
    recipe.update(project='gpl-lib', license_spdx='GPL-3.0-only')
    with pytest.raises(ValueError, match='permissive'):
        _book_with(recipe)


def test_a_card_with_an_unpinned_commit_is_a_problem(monkeypatch):
    cards = list(catalogue.load_cards())
    bad = cards[0].model_copy(update={'new': C.CardRef(ref='v9.9.9', commit='f' * 40)})
    monkeypatch.setattr(catalogue, 'load_cards', lambda: (bad, *cards[1:]))
    assert any(bad.id in p and 'not a pin' in p for p in catalogue.problems())


def test_a_dependency_that_is_not_a_pinned_recipe_is_a_problem(monkeypatch):
    mine = catalogue.recipe_book()
    libpng = mine.get('libpng')
    assert libpng.depends, 'the libpng recipe compiles zlib in'
    unpinned = libpng.depends[0].model_copy(update={'commit': 'e' * 40})
    broken = C.RecipeBook(contract='tier-r-recipes/1', recipes=tuple(
        r.model_copy(update={'depends': (unpinned,)}) if r.project == 'libpng' else r for r in mine.recipes))
    monkeypatch.setattr(catalogue, 'recipe_book', lambda: broken)
    assert any('libpng' in p and 'dependency zlib' in p for p in catalogue.problems())
    ghost = libpng.depends[0].model_copy(update={'project': 'nonesuch'})
    ghosted = C.RecipeBook(contract='tier-r-recipes/1', recipes=tuple(
        r.model_copy(update={'depends': (ghost,)}) if r.project == 'libpng' else r for r in mine.recipes))
    monkeypatch.setattr(catalogue, 'recipe_book', lambda: ghosted)
    assert any('dependency nonesuch' in p for p in catalogue.problems())


def test_a_missing_digest_entry_is_a_problem(monkeypatch):
    pins = catalogue.load_pins()
    thinner = pins.model_copy(update={'pairs': dict(list(pins.pairs.items())[1:])})
    monkeypatch.setattr(catalogue, 'load_pins', lambda: thinner)
    assert any('no source digests' in p for p in catalogue.problems())


def test_tree_digest_is_stable_order_free_and_ignores_the_fetch_receipt(tmp_path):
    a, b = tmp_path / 'a', tmp_path / 'b'
    for root, order in ((a, ('x.c', 'sub/y.h')), (b, ('sub/y.h', 'x.c'))):
        for rel in order:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(rel.encode())
    (b / '.ka-fetched.json').write_text('{"time": 1}', encoding='utf-8')
    (b / '.git').mkdir()
    (b / '.git' / 'HEAD').write_text('ref', encoding='utf-8')
    assert catalogue.tree_sha256(a) == catalogue.tree_sha256(b)
    (a / 'x.c').write_bytes(b'changed')
    assert catalogue.tree_sha256(a) != catalogue.tree_sha256(b)


def test_tree_digest_does_not_follow_symlinks(tmp_path):
    linked, plain = tmp_path / 'linked', tmp_path / 'plain'
    for root in (linked, plain):
        root.mkdir()
        (root / 'real.c').write_bytes(b'int x;')
    try:
        (linked / 'link.c').symlink_to(linked / 'real.c')
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not available on this platform')
    assert catalogue.tree_sha256(linked) == catalogue.tree_sha256(plain)
