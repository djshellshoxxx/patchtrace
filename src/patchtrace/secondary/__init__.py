"""Optional secondary match engines (SPEC-10 BinDiff, SPEC-11 rz-diff); Ghidriff stays primary."""
from __future__ import annotations

import json
import logging

from ..enrichment.storage import EnrichmentStore, Entry, Guard
from .contracts import KIND, SecondaryMatchSet

_log = logging.getLogger(__name__)


def publish_secondary(store: EnrichmentStore, guard: Guard, current: Guard, revision: int,
                      match_set: SecondaryMatchSet) -> Entry:
    """Store a validated set as its own enrichment entry; Ghidriff records are untouched."""
    return store.publish(KIND, guard, current, revision, 'complete', match_set.model_dump(mode='json'),
                         match_set.entry_id)


def load_secondary(store: EnrichmentStore, current: Guard | None = None) -> list[tuple[Entry, SecondaryMatchSet]]:
    """Every readable stored set. A corrupt or invalid row is skipped with a warning (per-row
    isolation): one bad row must never crash `secondary reconcile` or hide the good ones."""
    def corrupt(row_id: str) -> None:
        _log.warning('Skipping secondary row %s: failed its integrity hash', row_id)

    out = []
    for entry in store.entries(KIND, current, on_corrupt=corrupt):
        try:
            # Strict models reject JSON lists as tuples in Python mode; JSON mode revalidates stored rows exactly.
            out.append((entry, SecondaryMatchSet.model_validate_json(json.dumps(entry.body))))
        except ValueError as exc:
            _log.warning('Skipping secondary row %s: %s', entry.id, str(exc).splitlines()[0][:120])
    return out
