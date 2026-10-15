"""Tier R catalogue of the SPEC-31 gates (08-evaluation s2, 09-licensing s4): which open-source release pairs feed them.

SPEC-32 (`tools/calibration/tier_r`) owns the contracts and the build/label factory and keeps its own catalogue
(zlib). This module adds only the SPEC-31 view on top of it: recipes for the libraries the gates name, case cards of
their adjacent release tags and `pins.json`, the SHA-256 of every pinned source tree. Images differ per compiler
version, so no image hash is pinned here; image hashes live in the run reports. Nothing in this module touches the
network; fetching and building are in `cli.py`.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from tools import corpus_check
from tools.calibration.common import strict_json
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r.fetch import RECEIPT

HERE = Path(__file__).resolve().parent
SPEC32 = HERE.parents[1] / 'calibration' / 'tier_r' / 'catalogue'
# 08 s2 (Tier R row) and 09 s4: every one is a recipe or a documented exclusion.
TIER_R_PROJECTS = ('zlib', 'libpng', 'sqlite3', 'lua', 'mbedtls')


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Digests(_Strict):
    old: C.Sha256
    new: C.Sha256


class UnifiedPins(_Strict):
    contract: Literal['unified-corpus-pins/1']
    pairs: dict[str, Digests]


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    strict_json(data)
    return data


def spec32_book() -> C.RecipeBook:
    return C.load_recipes(_read(SPEC32 / 'recipes.json'))


def load_recipes() -> C.RecipeBook:
    return C.load_recipes(_read(HERE / 'recipes.json'))


def merged_book() -> C.RecipeBook:
    """SPEC-32's recipes plus this catalogue's (a project defined twice is an error, never silently overridden)."""
    return C.RecipeBook(contract='tier-r-recipes/1', recipes=(*spec32_book().recipes, *load_recipes().recipes))


def excluded() -> list[dict[str, str]]:
    return [*spec32_book().excluded, *load_recipes().excluded]


def load_cards() -> tuple[C.CaseCard, ...]:
    return (*C.load_cards(_read(SPEC32 / 'releases.json')), *C.load_cards(_read(HERE / 'cards.json')))


def load_pins() -> UnifiedPins:
    return UnifiedPins.model_validate_json(_read(HERE / 'pins.json'))


def tree_sha256(root: Path) -> str:
    """SHA-256 over `<file sha256>  <relative path>` lines of every regular file (sorted, symlinks never followed, `.git`
    and the fetch receipt left out): the toolchain-independent fingerprint of a fetched source tree."""
    lines = []
    for path in sorted(Path(root).rglob('*')):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file() or rel.startswith('.git/') or rel == RECEIPT:
            continue
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}\n')
    return hashlib.sha256(''.join(lines).encode('utf-8')).hexdigest()


def _card_problems(card: C.CaseCard, book: C.RecipeBook) -> list[str]:
    recipe = book.get(card.project)
    if recipe is None:
        return [f'{card.id}: no recipe for project {card.project}']
    out = []
    if card.license_spdx != recipe.license_spdx:
        out.append(f'{card.id}: card licence {card.license_spdx} differs from recipe {recipe.license_spdx}')
    for name, side in (('old', card.old), ('new', card.new)):
        pin = recipe.pin_for(side.commit)
        if pin is None or pin.ref != side.ref:
            out.append(f'{card.id}: {name} {side.ref} ({side.commit[:12]}) is not a pin of recipe {card.project}')
    return out


def problems() -> list[str]:
    """Offline consistency findings of the committed catalogue (empty = consistent)."""
    mine, base = load_recipes(), spec32_book()
    clash = sorted({r.project for r in mine.recipes} & {r.project for r in base.recipes})
    if clash:
        return [f'recipe {p} is defined by both catalogues' for p in clash]
    out: list[str] = []
    book = merged_book()
    known = {r.project for r in book.recipes} | {e['project'] for e in excluded()}
    out += [f'Tier R project {p} is neither a recipe nor a documented exclusion'
            for p in TIER_R_PROJECTS if p not in known]
    for recipe in book.recipes:
        for dep in recipe.depends:
            target = book.get(dep.project)
            if target is None or target.pin_for(dep.commit) is None:
                out.append(f'recipe {recipe.project}: dependency {dep.project}@{dep.commit[:12]} is not a pinned recipe')
    cards = load_cards()
    for card in cards:
        out += _card_problems(card, book)
    pins = load_pins()
    ids = [c.id for c in cards]
    out += [f'{i}: no source digests in pins.json' for i in ids if i not in pins.pairs]
    out += [f'pins.json: digests for unknown card {i}' for i in pins.pairs if i not in ids]
    out += [f'{i}: old and new source digests are equal' for i, d in pins.pairs.items() if d.old == d.new]
    out += [f'cards.json: {finding}' for finding in corpus_check.check_catalog(HERE / 'cards.json')]
    return out
