"""Section builders (SPEC-50 RPT2-4): each reads one Protocol port and returns `None` when its producer is absent.

A builder normalizes every untrusted string once (7.3), caps its rows (7.3 item 6) and raises
`ExportError('PT-EXPORT-SECTION')` for input that fails the contract: the export is refused, never silently thinned.
`collect` wires the ports of one export into `SectionInputs`.
"""
from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from ...reports import ExportError
from .. import text
from ..contracts import Truncated
from ..inputs import SectionInputs


@dataclass(frozen=True)
class Built:
    value: object
    truncated: Truncated | None = None


def bounded(value: str, cap: int, *, verbatim: bool = False) -> tuple[str, bool]:
    """(normalized text, whether the cap cut it)."""
    return (text.normalize_text(value, verbatim=verbatim, max_chars=cap),
            len(text.neutralize(value, verbatim=verbatim)) > cap)


def cap_rows(rows: list, cap: int, section: str) -> tuple[list, Truncated | None]:
    if len(rows) <= cap:
        return rows, None
    return rows[:cap], Truncated(section=section, omitted_count=len(rows) - cap)


def refuse(section: str, exc: Exception) -> ExportError:
    detail = exc.errors()[0]['msg'] if isinstance(exc, ValidationError) and exc.errors() else str(exc)
    return ExportError(f'PT-EXPORT-SECTION: {section} failed validation ({text.neutralize(detail)[:200]})')


def collect(*, evidence=None, series=None, unified=None, run_settings=None, build_facts=None, advisories=None,
            leads=None) -> SectionInputs:
    """Build every section from its optional port; the first refusal propagates."""
    from .advisories import build_advisories
    from .build_facts import build_build_facts
    from .engine_evidence import build_engine_evidence
    from .leads import build_leads
    from .series import build_series
    from .symbols import build_symbols
    from .unified_result import build_unified_result
    built: dict[str, Built | None] = {
        'engine_evidence': build_engine_evidence(evidence), 'series': build_series(series),
        'unified_result': build_unified_result(unified), 'symbols': build_symbols(run_settings),
        'build_facts': build_build_facts(build_facts), 'advisories': build_advisories(advisories),
        'leads': build_leads(leads)}
    return SectionInputs(
        **{key: None if b is None else b.value for key, b in built.items()},
        truncated=tuple(b.truncated for b in built.values() if b is not None and b.truncated is not None))
