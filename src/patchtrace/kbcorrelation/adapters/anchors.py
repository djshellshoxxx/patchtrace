"""FAB anchors about a CVE as correlator facts (FAB-integration-plan 4; K8).

Independence comes from ``fabric.origins``: witnesses that share an origin tag are one component, so NVD, MSRC and KEV
repeating one CWE count once. Counts are reported as counts of components, never summed into a score.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ...fabric.contracts import Anchor
from ...fabric.origins import components
from ..leads import plain_text


@dataclass(frozen=True)
class CveAnchorFacts:
    cve: str
    cwes: tuple[str, ...]            # CWE anchors whose witnesses name this CVE in facet ``cve``
    witnesses: int
    independent: int                 # origin components over all witnesses, shared origins merged
    producers: tuple[str, ...]
    sources: tuple[str, ...]         # witness source slugs, the provenance
    labels: tuple[str, ...]          # cleaned display labels, bounded


def cve_facts(anchors: Iterable[Anchor], *, label_limit: int = 200) -> dict[str, CveAnchorFacts]:
    """One record per CVE named by a ``cve`` anchor or by facet ``cve`` of a ``cwe`` anchor's witnesses."""
    sets: dict[str, list[tuple[str, ...]]] = {}
    info: dict[str, dict[str, set[str]]] = {}
    for anchor in anchors:
        for cve in _subjects(anchor):
            bucket = info.setdefault(cve, {'cwe': set(), 'producer': set(), 'source': set(), 'label': set()})
            for witness in anchor.witnesses:
                if anchor.kind == 'cwe' and ('cve', cve) not in witness.facets:
                    continue
                sets.setdefault(cve, []).append(witness.origins)
                bucket['producer'].add(witness.producer)
                bucket['source'].add(witness.source)
                bucket['label'].add(plain_text(witness.label, label_limit))
            if anchor.kind == 'cwe':
                bucket['cwe'].add(anchor.key)
    out: dict[str, CveAnchorFacts] = {}
    for cve, bucket in info.items():
        origin_sets = sets[cve]
        out[cve] = CveAnchorFacts(
            cve=cve, cwes=tuple(sorted(bucket['cwe'])), witnesses=len(origin_sets),
            independent=len(components(origin_sets)), producers=tuple(sorted(bucket['producer'])),
            sources=tuple(sorted(bucket['source'])), labels=tuple(sorted(x for x in bucket['label'] if x)))
    return dict(sorted(out.items()))


def _subjects(anchor: Anchor) -> tuple[str, ...]:
    if anchor.kind == 'cve':
        return (anchor.key,)
    if anchor.kind == 'cwe':
        return tuple(sorted({v for w in anchor.witnesses for k, v in w.facets if k == 'cve'}))
    return ()
