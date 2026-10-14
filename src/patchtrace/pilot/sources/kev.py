"""CISA KEV as context for ordering CVEs (PIL-integration-plan.md s4, s7; the KEV track: KEV-integration-plan.md).

KEV says a CVE was added to a catalog; it never says where in the code a fix is. Nothing here produces an observation,
and KEV changes only the order of CVEs in the picker, never the order of functions.

ABSENCE IS CONTEXT, NOT A VOTE. A CVE that is not in the loaded snapshot is `not-in-snapshot`: a statement about that one
snapshot, with its id, that ranks exactly like having no catalog at all (`unknown`). Neither says anything about
exploitation, and a malformed CVE id is `unknown`, never "not in the snapshot".

The KEV track (not built yet) either implements `ports.KevSource` itself or fills `CatalogKev` from its parsed catalog:
PIL needs only the snapshot id and the date each listed CVE was added.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from ..contracts import Kev
from ..limits import PilotError

if TYPE_CHECKING:
    from ..ports import KevSource

_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')  # the shape of contracts.CveId (ASCII digits only)
_MAX_CVE = 24
_SHA256 = re.compile(r'[0-9a-f]{64}')
NO_CATALOG = Kev(state='unknown')


def _is_cve(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_CVE and _CVE.fullmatch(value) is not None


def _refused(message: str, reason: str) -> PilotError:
    return PilotError('PT-PILOT-INPUT', message, reason=reason)


class CatalogKev:
    """`ports.KevSource` over an in-memory catalog extract: the snapshot id and the date each listed CVE was added."""

    def __init__(self, snapshot_id: str, listed: Mapping[str, str]):
        if not isinstance(snapshot_id, str) or not _SHA256.fullmatch(snapshot_id):
            raise _refused('A KEV snapshot id is a lower-case SHA-256 digest', 'kev-snapshot-id')
        if not isinstance(listed, Mapping):
            raise _refused('A KEV catalog maps CVE ids to the date they were added', 'kev-catalog')
        entries = {}
        for cve, added in listed.items():
            if not _is_cve(cve):
                raise _refused('A KEV catalog is keyed by CVE ids', 'kev-cve')
            try:
                entries[cve] = Kev(state='listed', date_added=added, snapshot_id=snapshot_id)
            except ValueError:  # pydantic's ValidationError: not a real calendar date
                raise _refused('A KEV entry needs a real date YYYY-MM-DD', 'kev-date') from None
        self._snapshot = snapshot_id
        self._listed = MappingProxyType(entries)
        self._absent = Kev(state='not-in-snapshot', snapshot_id=snapshot_id)

    def lookup(self, cve: str) -> Kev:
        if not _is_cve(cve):
            return NO_CATALOG
        return self._listed.get(cve, self._absent)

    def snapshot_id(self) -> str:
        return self._snapshot


def kev_context(source: KevSource | None, cve: str) -> Kev:
    """What the loaded catalog says about `cve`: `unknown` without a catalog, else the source's own answer.

    An answer that names another snapshot than the one the source holds would make the recorded
    `PilotInputs.kev_snapshot_id` wrong, so it is refused."""
    if source is None:
        return NO_CATALOG
    answer = source.lookup(cve)
    if not isinstance(answer, Kev):
        raise _refused('A KEV source answers with a Kev record', 'kev-answer')
    if answer.state != 'unknown' and answer.snapshot_id != source.snapshot_id():
        raise PilotError('PT-PILOT-MISMATCH', 'A KEV answer names a snapshot other than its source holds',
                         reason='kev-snapshot')
    return answer


def kev_rank(kev: Kev) -> int:
    """0 for a listed CVE, 1 for everything else: absence and unknown rank alike."""
    return 0 if kev.state == 'listed' else 1


def order_cves(kev_by_cve: Mapping[str, Kev]) -> tuple[str, ...]:
    """The picker order: listed CVEs first, then by CVE id. Nothing else (no date, no score) takes part."""
    return tuple(sorted(kev_by_cve, key=lambda cve: (kev_rank(kev_by_cve[cve]), cve)))
