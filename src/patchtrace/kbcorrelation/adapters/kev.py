"""KEV and FAB-anchor adapters for ``leads.ExploitationLookup`` (KEV-integration-plan 4; K8).

A listing is a CVE-level fact. Everything that is not an answer from a loaded catalog (no port, unavailable, invalid
ID, no anchor) is ``no-snapshot``: unknown is never "not listed".
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from ...fabric.contracts import Anchor
from ...kev.ports import KevLookupPort
from ..leads import ExploitationLookup, KevFact

_DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
_SHA = re.compile(r'[0-9a-f]{64}')
UNKNOWN = KevFact('no-snapshot')


class KevExploitation:
    """Wraps the KEV door; ``None`` is the optional-capability case (KEV not installed or not loaded)."""

    def __init__(self, port: KevLookupPort | None) -> None:
        self._port = port

    def status(self, cve: str) -> KevFact:
        if self._port is None:
            return UNKNOWN
        found = self._port.lookup(cve)
        if found.status == 'listed' and found.entry is not None:
            return KevFact('listed', found.entry.date_added, found.snapshot_id)
        if found.status == 'not-listed':
            return KevFact('not-listed', None, found.snapshot_id)
        return UNKNOWN


class AnchorExploitation:
    """KEV listings carried as FAB witness facets ``kev=listed``, ``date_added``, ``snapshot`` on a ``cve`` anchor.

    Only a positive witness answers. The absence of an anchor says nothing, so it is never ``not-listed``."""

    def __init__(self, anchors: Iterable[Anchor]) -> None:
        self._listed: dict[str, KevFact] = {}
        for anchor in anchors:
            if anchor.kind != 'cve':
                continue
            for witness in anchor.witnesses:
                facets = dict(witness.facets)
                if facets.get('kev') != 'listed':
                    continue
                day, snap = facets.get('date_added', ''), facets.get('snapshot', '')
                fact = KevFact('listed', day if _DAY.fullmatch(day) else None, snap if _SHA.fullmatch(snap) else None)
                old = self._listed.get(anchor.key)
                if old is None or (fact.date_added or '') < (old.date_added or ''):
                    self._listed[anchor.key] = fact

    def status(self, cve: str) -> KevFact:
        return self._listed.get(cve, UNKNOWN)


class FirstAnswer:
    """The first lookup that answers; a catalog's ``not-listed`` outranks silence from a later one."""

    def __init__(self, lookups: Sequence[ExploitationLookup]) -> None:
        self._lookups = tuple(lookups)

    def status(self, cve: str) -> KevFact:
        for lookup in self._lookups:
            fact = lookup.status(cve)
            if fact.state != 'no-snapshot':
                return fact
        return UNKNOWN
