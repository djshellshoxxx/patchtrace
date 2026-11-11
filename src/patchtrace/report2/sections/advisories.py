"""`advisories` (CVE, KB, CWE, vendor phrase): vendor claims as inert text; ids pass a strict regex or the export stops."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from .. import text
from ..contracts import Advisory
from . import Built, bounded, cap_rows, refuse


@dataclass(frozen=True)
class AdvisoryRecord:
    kind: str
    id: str
    text: str
    vendor: str = ''
    url: str = ''
    fetched_at: str = ''
    snapshot_digest: str | None = None
    kev_listed: bool | None = None


class AdvisoryPort(Protocol):
    def advisories(self) -> Sequence[AdvisoryRecord]: ...


def _advisory(record: AdvisoryRecord) -> Advisory:
    body, cut = bounded(record.text, text.CAP_ADVISORY, verbatim=True)
    return Advisory(
        kind=record.kind, id=bounded(record.id, text.CAP_NAME)[0], vendor=bounded(record.vendor, text.CAP_NAME)[0],
        url_text=bounded(record.url, text.CAP_NAME)[0], fetched_at=bounded(record.fetched_at, text.CAP_NAME)[0],
        snapshot_digest=record.snapshot_digest, kev_listed=record.kev_listed, text=body, truncated=cut)


def build_advisories(port: AdvisoryPort | None) -> Built | None:
    records = [] if port is None else list(port.advisories())
    if not records:
        return None
    records, truncated = cap_rows(records, text.MAX_ADVISORIES, 'advisories')
    try:
        return Built(tuple(_advisory(r) for r in records), truncated)
    except ValidationError as exc:
        raise refuse('advisories', exc) from None
