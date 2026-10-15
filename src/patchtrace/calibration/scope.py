"""Honest-scope vocabulary and the pure status notice (LBL integration plan 7.5, 7.8). No Qt, network or free text.

Artifacts and ledgers carry only closed scope ids; every sentence shown to an analyst lives here. Wording rules:
no percent sign and none of the banned stems in `BANNED_STEMS` (enforced by `test_scope_copy_sweep`).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, get_args

ScopeId = Literal['no-windows-system-binaries', 'open-source-c-only', 'test-compilers-only', 'no-lto-pgo',
                  'no-cpp-heavy', 'x64-only', 'stripped-images-only', 'few-lineages', 'single-annotator',
                  'planted-changes-synthetic', 'symbols-hidden-only', 'engine-versions-pinned']
SCOPE_IDS: tuple[str, ...] = get_args(ScopeId)
NoticeState = Literal['untested', 'tested-synthetic', 'tested-windows', 'degraded', 'expired']

TIER_R_CLAIM = 'Measured on test builds of open-source code; says nothing about Windows system files.'
BANNED_STEMS = ('probab', 'vulnerab', 'verified', 'proven', 'certain', 'safe', 'secure', 'fixed', 'exploit', '%')

SCOPE_TEXT: dict[str, str] = {
    'no-windows-system-binaries': 'Not tested on Windows system files (kernel, drivers, system libraries).',
    'open-source-c-only': 'Tested on open-source C libraries only.',
    'test-compilers-only': 'Built with test compilers (clang, mingw), not the Microsoft build chain.',
    'no-lto-pgo': 'Not tested on whole-program or profile-guided builds.',
    'no-cpp-heavy': 'Not tested on C++-heavy code.',
    'x64-only': 'Tested on 64-bit x86 images only.',
    'stripped-images-only': 'Tested on stripped images only.',
    'few-lineages': 'Few independent code sets, so results are coarse.',
    'single-annotator': 'Labels come from a single annotator.',
    'planted-changes-synthetic': 'Changes were planted by a tool, not taken from real updates.',
    'symbols-hidden-only': 'Tested with symbols hidden from the engines.',
    'engine-versions-pinned': 'Valid only for the pinned engine versions.',
}
# Text ids for the E-5 guide (meaning / next step); the guide owns the copy, this module owns the ids.
MEANING_ID = {k: f'scope.{k}.meaning' for k in SCOPE_TEXT}
NEXT_ID = {k: f'scope.{k}.next' for k in SCOPE_TEXT}

_LINE = {
    'untested': 'Not tested: lead order is a ranking only and carries no accuracy claim.',
    'tested-synthetic': 'Tested on test builds only: ranking checked on open-source code, not on Windows files.',
    'tested-windows': 'Tested on Windows files: see the evidence limits for what was covered.',
    'degraded': 'Validation data could not be read: treated as not tested.',
    'expired': 'Validation data is out of date: treated as not tested.',
}
MAX_LINE, MAX_LIMITS, MAX_LIMIT_LINE, MAX_PROVENANCE = 300, 60, 200, 6


class ScopeError(ValueError):
    """PT-CALIB-SCOPE: unknown scope id."""

    code = 'PT-CALIB-SCOPE'


def scope_text(scope_id: str) -> str:
    try:
        return SCOPE_TEXT[scope_id]
    except KeyError:
        raise ScopeError(f'PT-CALIB-SCOPE: unknown scope id {scope_id!r}') from None


@dataclass(frozen=True)
class ScopeNotice:
    state: NoticeState
    line: str
    limits_lines: tuple[str, ...]
    provenance_lines: tuple[str, ...]
    code: str


def notice(level: str, ledger, artifacts: Mapping | None = None) -> ScopeNotice:
    """Pure status for the Evidence dock and reports. `ledger` is a `ledger.LedgerResult` (or None);
    `artifacts` maps profile to `artifact.LoadResult`. Windows-tested needs a non-ordinal display level."""
    entries = ledger.live_entries() if ledger is not None else ()
    reason = getattr(ledger, 'reason', 'missing')
    broken = any(getattr(r, 'artifact', None) is None for r in (artifacts or {}).values())
    if reason == 'expired':
        state: NoticeState = 'expired'
    elif reason not in ('ok', 'missing') or broken:
        state = 'degraded'
    elif any(e.state == 'windows-validated' for e in entries) and level != 'ordinal':
        state = 'tested-windows'
    elif any(e.state in ('synthetic-validated', 'windows-validated') for e in entries):
        state = 'tested-synthetic'
    else:
        state = 'untested'
    ids: list[str] = []
    if state != 'tested-windows':
        ids.append('no-windows-system-binaries')
    for entry in entries:
        if entry.state != 'unvalidated':
            ids.extend(entry.scope_ids)
    seen = tuple(dict.fromkeys(ids))[:MAX_LIMITS]
    limits = tuple(scope_text(i)[:MAX_LIMIT_LINE] for i in seen)
    prov = tuple(f'{e.channel}/{e.facet}: {e.state}, report {e.report_sha256[:12]}, {e.n_lineages} code sets'
                 for e in entries if e.state != 'unvalidated' and e.report_sha256)[:MAX_PROVENANCE]
    return ScopeNotice(state, _LINE[state][:MAX_LINE], limits, prov, f'scope.{state}')
