"""SPEC-32 committed catalogue (offline): recipes load strictly, every card validates with tools/corpus_check.py, every
card's project has a recipe whose pins carry both commits, and nothing in the catalogue is an executable image."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402

CATALOGUE = ROOT / 'tools' / 'calibration' / 'tier_r' / 'catalogue'
_spec = importlib.util.spec_from_file_location('corpus_check', ROOT / 'tools' / 'corpus_check.py')
corpus_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus_check)


def test_recipes_and_cards_are_consistent():
    book = C.load_recipes((CATALOGUE / 'recipes.json').read_bytes())
    cards = C.load_cards((CATALOGUE / 'releases.json').read_bytes())
    assert book.recipes and cards
    for card in cards:
        recipe = book.get(card.project)
        assert recipe is not None, card.id
        assert card.license_spdx == recipe.license_spdx
        for side in (card.old, card.new):
            pin = recipe.pin_for(side.commit)
            assert pin is not None and pin.ref == side.ref, (card.id, side)
    assert corpus_check.check_catalog(CATALOGUE / 'releases.json') == []


def test_catalogue_holds_no_executable_images():
    files = [p.relative_to(ROOT).as_posix() for p in CATALOGUE.rglob('*') if p.is_file()]
    assert [p for p in corpus.guard(ROOT, None, files=files) if 'inside the work tree' not in p] == []
