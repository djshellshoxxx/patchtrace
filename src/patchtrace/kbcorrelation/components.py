"""Component hints (KB-integration-plan section 3, tiers A-E; slice K3). Pure.

A KB number never yields files, so a hint is only ever one of:

* tier E, a file name the analyst typed (a user assertion, no evidential upgrade);
* tier D, a module-looking name found in an advisory title (a search suggestion that never selects a file).

Tier A needs a structured official field (absent from the data we hold), B needs package inventory and C an index row
for a name already given (later slices). ``changed_in_kb`` stays ``unknown`` until the file index can say. A name in
both lists is one hint at the lower (more documented) tier with both reasons.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from .contracts import ComponentHint, CveCard, SourceRef, domain_id, validate_file_name
from .limits import DEFAULT_LIMITS

# Names the title literally contains; the suffix list is the one acquisition accepts for PE files.
_MODULE = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9_][A-Za-z0-9_.-]{0,59}\.(?:sys|dll|exe|ocx|cpl|drv))(?![A-Za-z0-9_-])',
                     re.IGNORECASE)
SELECTING_TIERS = ('A', 'B', 'C', 'E')  # tier D never selects a file


def normalise_name(raw: str) -> str:
    """Analyst input to a lowercase PE basename; raises ``ValueError`` (the caller maps it to ``PT-KBC-INPUT``)."""
    if type(raw) is not str or '/' in raw or '\\' in raw:
        raise ValueError('a file name has no directory part')
    try:
        return validate_file_name(raw.strip().lower())
    except Exception:
        raise ValueError('a file name is a lowercase basename of [a-z0-9._-] ending in .sys, .dll or .exe') from None


def _hint(basename: str, scope_id: str, tier: str, reasons: Sequence[str],
          refs: Sequence[SourceRef]) -> ComponentHint:
    return ComponentHint(hint_id=domain_id('kbc.hint', 1, {'basename': basename, 'scope_id': scope_id}),
                         basename=basename, scope_id=scope_id, tier=tier, reasons=tuple(sorted(set(reasons))),
                         claim_refs=tuple(sorted(refs, key=lambda r: (r.doc_id, r.pointer))))


def _title_names(card: CveCard) -> list[str]:
    names = []
    for found in _MODULE.findall(card.title or ''):
        try:
            names.append(normalise_name(found))
        except ValueError:
            continue
    return names


def hints_for(cards: Iterable[CveCard], refs_by_cve: dict[str, SourceRef], names: Iterable[str], scope_id: str,
              *, limit: int = DEFAULT_LIMITS.hints) -> tuple[tuple[ComponentHint, ...], bool]:
    """Hints for one product scope, best tier first, and whether the list was cut at ``limit``."""
    found: dict[str, tuple[str, list[str], list[SourceRef]]] = {}

    def add(name: str, tier: str, reason: str, ref: SourceRef | None) -> None:
        have = found.setdefault(name, (tier, [], []))
        have[1].append(reason)
        if ref is not None:
            have[2].append(ref)
        if tier < have[0]:
            found[name] = (tier, have[1], have[2])

    for card in cards:
        for name in _title_names(card):
            add(name, 'D', f'module name in the advisory title of {card.cve}', refs_by_cve.get(card.cve))
    for raw in names:
        add(normalise_name(raw), 'E', 'entered by the analyst', None)
    ordered = sorted(found.items(), key=lambda item: (item[1][0], item[0]))
    hints = tuple(_hint(name, scope_id, tier, reasons, refs) for name, (tier, reasons, refs) in ordered[:limit])
    return hints, len(ordered) > limit


def selectable(hints: Iterable[ComponentHint]) -> bool:
    """True when at least one hint may select a file (tier D alone never does)."""
    return any(h.tier in SELECTING_TIERS for h in hints)
