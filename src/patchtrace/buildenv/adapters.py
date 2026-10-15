"""Adapters from the stdlib PE build facts and the stored `diec` run to the strict build-environment records."""
from __future__ import annotations

import dataclasses

from ..intelligence.tools.common import ToolRun
from ..intelligence.tools.diec import KNOWN_DATABASES
from ..pe_overview.build_facts import PeBuildFacts as RawPeBuildFacts
from .contracts import DieSummary, PeBuildFacts


def pe_facts_from(raw: RawPeBuildFacts) -> PeBuildFacts:
    """Strict copy of the dataclass; a value outside the contract raises a pydantic error (a programming error)."""
    return PeBuildFacts.model_validate(dataclasses.asdict(raw))


def die_summary_from(run: ToolRun | None) -> DieSummary | None:
    """None when no run was stored for the side; the caller treats that as `not-run`."""
    if run is None:
        return None
    manifest, options = run.manifest, run.options
    produced = run.status in ('ok', 'none-found')
    return DieSummary(
        status=run.status, run_id=run.run_id, tool_version=manifest.version,
        db_label=KNOWN_DATABASES.get(manifest.rules_sha256 or ''), db_sha256=manifest.rules_sha256,
        argv_version=options.get('argv'), heuristics=options.get('mode') == 'deep+heuristic',
        cache_key=run.cache_key if produced else None)

