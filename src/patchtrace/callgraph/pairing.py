"""A2 pair map: which function on one side corresponds to which on the other, with the deciding source."""
from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from .contracts import Opinion, Pairing, Side
from .labels import is_default_name
from .project_input import EmittedPair, ProjectInput

UNKNOWN = Pairing(kind='unknown')


class ExtraOpinion(NamedTuple):
    """A secondary engine's opinion (from a port); kept next to Ghidriff's, never merged into it."""
    side: Side
    label: str
    via: str
    partners: tuple[str, ...]


def _other(side: Side) -> Side:
    return 'newer' if side == 'older' else 'older'


def _kind(partners: tuple[str, ...]) -> str:
    return 'one' if len(partners) == 1 else 'many'


class PairMap:
    """Precedence: manual correction > emitted pair > raw name_matches > equality of non-default labels
    (inferred; only when raw matches are not available). Engine disagreement outside manual = contested."""

    def __init__(self, data: ProjectInput, labels: dict[Side, set[str]] | None = None,
                 extra: Iterable[ExtraOpinion] = ()) -> None:
        self._raw = data.raw.matches
        self._labels = labels or {'older': set(), 'newer': set()}
        self._by_label: dict[tuple[Side, str], list[EmittedPair]] = {}
        for pair in data.pairs:
            for side, names in (('older', pair.older), ('newer', pair.newer)):
                for name in set(names):
                    self._by_label.setdefault((side, name), []).append(pair)
        self._extra: dict[tuple[Side, str], list[Opinion]] = {}
        for item in extra:
            self._extra.setdefault((item.side, item.label), []).append(Opinion(via=item.via, partners=item.partners))
        self._cache: dict[tuple[Side, str], Pairing] = {}

    def partner(self, side: Side, label: str) -> Pairing:
        key = (side, label)
        if key not in self._cache:
            self._cache[key] = self._decide(side, label)
        return self._cache[key]

    def _decide(self, side: Side, label: str) -> Pairing:
        primary = self._ghidriff(side, label)
        opinions = self._extra.get((side, label), [])
        if primary.via == 'manual' or not opinions:
            return primary
        own = [Opinion(via=primary.via, partners=primary.partners)] if primary.kind != 'unknown' else []
        engines = (*own, *opinions)
        partner_sets = {frozenset(o.partners) for o in engines}
        if len(partner_sets) > 1:
            return Pairing(kind='contested', engines=engines)
        winner = engines[0]
        return Pairing(kind=_kind(winner.partners), partners=winner.partners, via=winner.via, engines=engines)

    def _ghidriff(self, side: Side, label: str) -> Pairing:
        emitted = self._by_label.get((side, label), [])
        emitted = [p for p in emitted if p.manual] or emitted
        if len(emitted) > 1:  # one name, several emitted records: the label cannot say which function
            return UNKNOWN
        if emitted:
            return self._from_pair(emitted[0], side)
        raw = self._raw_partners(side, label)
        if raw:
            partners = tuple(name for name, _ in raw)
            via = f'ghidriff:{raw[0][1]}' if raw[0][1] else 'ghidriff'
            return Pairing(kind=_kind(partners), partners=partners, via=via,
                           engines=(Opinion(via=via, partners=partners),))
        return self._inferred(side, label)

    @staticmethod
    def _from_pair(pair: EmittedPair, side: Side) -> Pairing:
        partners = pair.newer if side == 'older' else pair.older
        if not partners:
            kind = 'removed' if side == 'older' else 'added'
            return Pairing(kind=kind, via=pair.via, engines=(Opinion(via=pair.via, partners=()),))
        return Pairing(kind=_kind(partners), partners=partners, via=pair.via,
                       engines=(Opinion(via=pair.via, partners=partners),))

    def _raw_partners(self, side: Side, label: str) -> tuple[tuple[str, str], ...]:
        if self._raw is None:
            return ()
        table = self._raw.names if side == 'older' else self._raw.reverse_names
        return table.get(label, ())

    def _inferred(self, side: Side, label: str) -> Pairing:
        if self._raw is not None or is_default_name(label) or label not in self._labels[_other(side)]:
            return UNKNOWN
        return Pairing(kind='one', partners=(label,), via='inferred', inferred=True,
                       engines=(Opinion(via='inferred', partners=(label,)),))
