"""`series` from an `nway/1` series (SPEC-09). Orientation by ordinal; a chain gap is unknown, not a removal."""
from __future__ import annotations

from typing import Protocol

from pydantic import ValidationError

from ...nway.contracts import Series as NwaySeries
from .. import text
from ..contracts import Series, SeriesBuild, SeriesChain, SeriesGap, SeriesPair
from . import Built, bounded, refuse

GAP_REASON = 'no function was found at this build; unknown, not a removal'


class SeriesPort(Protocol):
    def series(self) -> NwaySeries | None: ...
    def is_stale(self) -> bool: ...


def build_series(port: SeriesPort | None) -> Built | None:
    series = None if port is None else port.series()
    if series is None:
        return None
    gaps = sorted({g for chain in series.chains for g in chain.gaps})
    try:
        section = Series(
            builds=[SeriesBuild(ordinal=b.ordinal, label=bounded(b.label, text.CAP_NAME)[0], sha256=b.artifact_sha256)
                    for b in series.builds],
            pairs=[SeriesPair(older_ordinal=p.from_ordinal, newer_ordinal=p.to_ordinal, state='analyzed')
                   for p in series.pair_projects],
            chains=[SeriesChain(label=f'chain {c.chain_id[:12]} ({c.status})',
                                ordinals=sorted({n.ordinal for n in c.nodes})) for c in series.chains],
            gaps=[SeriesGap(after_ordinal=g, reason=GAP_REASON) for g in gaps], stale=port.is_stale())
    except ValidationError as exc:
        raise refuse('series', exc) from None
    return Built(section)
