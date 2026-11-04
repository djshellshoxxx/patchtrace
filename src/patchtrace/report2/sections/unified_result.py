"""`unified_result` reference from the unified store (SPEC-31): identity and status only, bulk rows stay on disk.

This module reads the pointer and manifest of an already-verified `LoadedResult`; it never opens `rows.jsonl.gz`,
`facts.jsonl.gz` or any other part.
"""
from __future__ import annotations

from typing import Protocol

from pydantic import ValidationError

from ...unified.store import LoadedResult
from .. import text
from ..contracts import UnifiedResult
from . import Built, bounded, refuse


class UnifiedPort(Protocol):
    def load(self) -> LoadedResult: ...


def build_unified_result(port: UnifiedPort | None) -> Built | None:
    loaded = None if port is None else port.load()
    if loaded is None or loaded.state not in ('current', 'stale') or loaded.manifest is None or loaded.pointer is None:
        return None
    manifest = loaded.manifest
    engines = sorted({'ghidriff', *(s.source for s in manifest.sources)})
    try:
        section = UnifiedResult(
            result_id=manifest.result_id, manifest_sha256=loaded.pointer.manifest_sha256,
            engines=[bounded(e, text.CAP_NAME)[0] for e in engines], status=manifest.status,
            stale=loaded.state != 'current')
    except ValidationError as exc:
        raise refuse('unified_result', exc) from None
    return Built(section)
