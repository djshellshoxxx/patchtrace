"""Qt-free view model of the build-environment card and notice bar (DIE plan s8).

Everything untrusted goes through `display_text`; severity is a glyph plus a word, never colour only. A dismissal is
scoped to one delta id, so a different pair or a changed tool setup shows its banners again.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..intelligence.tools.common import display_text
from .contracts import BuildChange, BuildEnvDelta, BuildFingerprint
from .copy import BASIS_TEXT, DISCLAIMER, FACT_LABELS, REASONS, STATES, STATUS_TEXT
from .delta import toolchain_text

MAX_ROWS = 128
PROVENANCE_LIMIT = 8 * 1024
TECHNICAL_ENTRIES = 64


@dataclass(frozen=True, slots=True)
class FactRow:
    key: str
    label: str
    older: str
    newer: str
    status: str
    basis: str


@dataclass(frozen=True, slots=True)
class BannerView:
    code: str
    side: str
    severity: str
    glyph: str
    text: str
    teach_id: str | None


@dataclass(frozen=True, slots=True)
class BuildEnvViewModel:
    state: str
    state_text: str
    banners: tuple[BannerView, ...] = ()
    rows: tuple[FactRow, ...] = ()
    summary: str = ''
    provenance: str = ''
    technical: tuple[str, ...] = ()
    delta_id: str | None = None


def _state(state: str, **values: object) -> BuildEnvViewModel:
    return BuildEnvViewModel(state, STATES[state].format(**{k: display_text(str(v), 200) for k, v in values.items()}))


def reading_view(side: str, done: int, total: int) -> BuildEnvViewModel:
    return _state('B1', side=side.upper(), done=done, total=total)


def banner_views(delta: BuildEnvDelta, dismissed_delta_id: str | None = None) -> tuple[BannerView, ...]:
    if dismissed_delta_id == delta.delta_id:
        return ()
    return tuple(BannerView(w.code, w.side, w.severity, '[!]' if w.severity == 'caution' else '[i]',
                            f'{w.summary} {w.detail}'.strip(), w.teach_id) for w in delta.preflight)


def _basis(change: BuildChange, tool_version: str) -> str:
    return ', '.join(BASIS_TEXT[s].format(version=tool_version).replace('  ', ' ') for s in change.basis)


def fact_rows(delta: BuildEnvDelta, tool_version: str = '') -> tuple[FactRow, ...]:
    return tuple(FactRow(c.key, FACT_LABELS[c.key], display_text(c.older or '-', 200), display_text(c.newer or '-', 200),
                         STATUS_TEXT[c.change], _basis(c, tool_version)) for c in delta.changes[:MAX_ROWS])


def _die_lines(fp: BuildFingerprint) -> list[str]:
    die = fp.die
    if die is None or not die.produced():
        return [f'{fp.side.upper()} Detect It Easy: {die.status if die else "not-run"}']
    return [f'{fp.side.upper()} Detect It Easy {die.tool_version or "?"}, database {die.db_label or "unlabelled"}'
            f' ({(die.db_sha256 or "")[:16]}), argv {die.argv_version or "?"}, run {die.run_id}']


def provenance_block(older: BuildFingerprint, newer: BuildFingerprint) -> str:
    lines = []
    for fp in (older, newer):
        lines += [f'{fp.side.upper()} artifact sha256 {fp.artifact_sha256}',
                  f'{fp.side.upper()} PE facts {fp.built_from.pe_facts_version}', *_die_lines(fp)]
    lines.append(DISCLAIMER)
    return display_text('\n'.join(lines), PROVENANCE_LIMIT)


def technical_lines(older: BuildFingerprint, newer: BuildFingerprint) -> tuple[str, ...]:
    """Raw Rich entries and anomalies per side, bounded; shown only on request."""
    lines: list[str] = []
    for fp in (older, newer):
        rich = fp.pe.rich if fp.pe else None
        for entry in (rich.entries[:TECHNICAL_ENTRIES] if rich else ()):
            lines.append(f'{fp.side.upper()} Rich product {entry.product_id} build {entry.build} count {entry.count}')
        lines += [f'{fp.side.upper()} anomaly {name}' for name in fp.anomalies]
    return tuple(lines)


def _reason_text(delta: BuildEnvDelta) -> str:
    return '; '.join(REASONS.get(r, r) for r in delta.reasons) or REASONS['no-comparable-facts']


def _unreadable_sides(older: BuildFingerprint | None, newer: BuildFingerprint | None) -> list[str]:
    def readable(fp: BuildFingerprint | None) -> bool:
        return fp is not None and (fp.pe is not None or (fp.die is not None and fp.die.produced()))
    return [name for name, fp in (('OLDER', older), ('NEWER', newer)) if not readable(fp)]


def build_view(older: BuildFingerprint | None, newer: BuildFingerprint | None, delta: BuildEnvDelta | None, *,
               project_open: bool = True, error_code: str | None = None, unsupported_version: str | None = None,
               stale: bool = False, dismissed_delta_id: str | None = None,
               technical: bool = False) -> BuildEnvViewModel:
    """State precedence: no project, error, unsupported tool, stale, unreadable side, then the toolchain verdict."""
    if not project_open:
        return _state('B0')
    if error_code:
        return _state('B8', code=error_code)
    if unsupported_version:
        return _state('B9', version=unsupported_version)
    if older is None or newer is None or delta is None:
        if stale:
            return _state('B7')
        side = ' and '.join(_unreadable_sides(older, newer)) or 'both files'
        return _state('B6', side=side, reason=REASONS['headers-unreadable'])
    if stale:
        return _full(_state('B7'), older, newer, delta, dismissed_delta_id, technical)
    failed = _unreadable_sides(older, newer)
    if failed:
        return _full(_state('B6', side=' and '.join(failed), reason=REASONS['headers-unreadable']), older, newer,
                     delta, dismissed_delta_id, technical)
    if delta.toolchain == 'differs':
        state = _state('B4', summary=toolchain_text(list(delta.changes)))
    elif delta.toolchain == 'same':
        state = _state('B3')
    elif 'die-not-run' in delta.reasons:
        state = _state('B2')
    else:
        state = _state('B5', reason=_reason_text(delta))
    return _full(state, older, newer, delta, dismissed_delta_id, technical)


def _full(state: BuildEnvViewModel, older: BuildFingerprint, newer: BuildFingerprint, delta: BuildEnvDelta,
          dismissed: str | None, technical: bool) -> BuildEnvViewModel:
    version = (older.die.tool_version if older.die and older.die.tool_version else '') or ''
    return BuildEnvViewModel(
        state=state.state, state_text=state.state_text, banners=banner_views(delta, dismissed),
        rows=fact_rows(delta, version), summary=toolchain_text(list(delta.changes)) if delta.toolchain == 'differs' else '',
        provenance=provenance_block(older, newer), technical=technical_lines(older, newer) if technical else (),
        delta_id=delta.delta_id)
