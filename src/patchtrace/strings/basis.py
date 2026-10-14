"""Basis rules (spec WB3 s7.1): may two string tables be compared, and on which types? Pure.

Every difference between the sides is either harmonized (minimum length), narrowed (a type that only one side ran
or whose emulation settings differ is `not compared`, never "removed"), made indeterminate (a truncated or failed
stage), or blocks the comparison (a different extraction semantics). Each decision leaves a plain note.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import get_args

from .contracts import Harmonized, StageState, StringBasis, StringsError, StringType

TYPE_ORDER: tuple[str, ...] = get_args(StringType)
EMULATION_TYPES = frozenset({'stack', 'tight', 'decoded'})
_NEEDS_SAME_EXECUTABLE = EMULATION_TYPES | {'language'}


@dataclass(frozen=True)
class BasisVerdict:
    comparable: bool
    harmonized: Harmonized | None
    notes: tuple[str, ...]
    block_reasons: tuple[str, ...]
    compared: frozenset[str]
    indeterminate: frozenset[str]
    not_compared: frozenset[str]

    @property
    def readable_types(self) -> frozenset[str]:
        """Types whose rows take part in the delta (indeterminate ones yield `?`, never added or removed)."""
        return self.compared | self.indeterminate


def _types(basis: StringBasis) -> frozenset[str]:
    return frozenset(t for part in basis.parts for t in part.types)


def _semantics(basis: StringBasis) -> frozenset[str]:
    return frozenset(part.semantics_id for part in basis.parts)


def _floss(basis: StringBasis):
    return next((part for part in basis.parts if part.source == 'floss'), None)


def _blocked(reasons: list[str]) -> BasisVerdict:
    empty: frozenset[str] = frozenset()
    return BasisVerdict(False, None, (), tuple(reasons), empty, empty, empty)


def _stage(basis: StringBasis, kind: str) -> StageState:
    return basis.stages.get(kind) or StageState(state='not-run')


def compare_bases(older: StringBasis, newer: StringBasis) -> BasisVerdict:
    if older.side != 'older' or newer.side != 'newer':
        raise StringsError('PT-STR-STALE', 'the tables are not an older build followed by a newer build')
    if _semantics(older) != _semantics(newer):
        return _blocked(['the two scans extract strings by different rules'])
    notes: list[str] = []
    min_length = max(older.min_length, newer.min_length)
    if older.min_length != newer.min_length:
        notes.append(f'Minimum length differs ({older.min_length} and {newer.min_length}): both sides are compared '
                     f'at {min_length}.')
    if {p.source for p in older.parts} != {p.source for p in newer.parts}:
        notes.append('The sides were read by different sources; static strings are compared and both sources '
                     'are shown.')
    shared = set(_types(older) & _types(newer))
    not_compared = set(_types(older) ^ _types(newer))
    for kind in sorted(not_compared, key=TYPE_ORDER.index):
        notes.append(f'{kind} strings were extracted on one side only and are not compared.')
    for kind in sorted(shared & _NEEDS_SAME_EXECUTABLE, key=TYPE_ORDER.index):
        reason = _unmatched_setup(kind, older, newer)
        if reason:
            shared.discard(kind)
            not_compared.add(kind)
            notes.append(f'{kind} strings are not compared: {reason}.')
    compared: set[str] = set()
    indeterminate: set[str] = set()
    for kind in sorted(shared, key=TYPE_ORDER.index):
        states = {_stage(older, kind).state, _stage(newer, kind).state}
        if 'not-run' in states:
            not_compared.add(kind)
            notes.append(f'{kind} strings did not run on one side and are not compared.')
        elif states & {'truncated', 'failed'}:
            indeterminate.add(kind)
            notes.append(f'{kind} extraction was incomplete on one side, so differences in {kind} strings are '
                         f'shown as "?".')
        else:
            compared.add(kind)
    if not compared and not indeterminate:
        return _blocked(['no string type was extracted on both sides'])
    types = tuple(t for t in TYPE_ORDER if t in compared | indeterminate)
    return BasisVerdict(True, Harmonized(min_length=min_length, types=types), tuple(notes), (),
                        frozenset(compared), frozenset(indeterminate), frozenset(not_compared))


def _unmatched_setup(kind: str, older: StringBasis, newer: StringBasis) -> str:
    a, b = _floss(older), _floss(newer)
    if a is None or b is None:
        return 'it needs a FLOSS run on both sides'
    if a.executable_sha256 is None or a.executable_sha256 != b.executable_sha256:
        return 'the FLOSS executable differs or is unknown'
    if kind in EMULATION_TYPES and (a.consent_sha256 is None or a.consent_sha256 != b.consent_sha256):
        return 'the emulation consent differs'
    if kind == 'language' and older.language.detected != newer.language.detected:
        return 'the detected language differs'
    return ''
