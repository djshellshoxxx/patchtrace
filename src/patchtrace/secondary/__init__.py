"""Optional secondary match engines (SPEC-10 BinDiff, SPEC-11 rz-diff); Ghidriff stays primary."""
from __future__ import annotations

import json

from ..enrichment.storage import EnrichmentStore, Entry, Guard
from .contracts import KIND, SecondaryMatchSet


def publish_secondary(store: EnrichmentStore, guard: Guard, current: Guard, revision: int,
                      match_set: SecondaryMatchSet) -> Entry:
    """Store a validated set as its own enrichment entry; Ghidriff records are untouched."""
    return store.publish(KIND, guard, current, revision, 'complete', match_set.model_dump(mode='json'),
                         match_set.entry_id)


def load_secondary(store: EnrichmentStore, current: Guard | None = None) -> list[tuple[Entry, SecondaryMatchSet]]:
    # Strict models reject JSON lists as tuples in Python mode; JSON mode revalidates stored rows exactly.
    return [(entry, SecondaryMatchSet.model_validate_json(json.dumps(entry.body)))
            for entry in store.entries(KIND, current)]
