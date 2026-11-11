"""What the Detection rules panel says about the stored rule rows (YRX-integration-plan s8; panel spec section 4). Pure: no Qt.

The panel reads stored candidates, decisions, versions and test grids; it proposes, decides, tests and exports nothing
(those need the R6a service, which is not built). Everything shown is a count taken from a stored record: a rule is a
pattern that separates two builds, never a statement about whether a file is affected, and a cell that was not scanned,
timed out or failed is unknown, never "no match". Rule, label and file text is untrusted: every cell passes
`sanitize_text` in the table layer and every detail string is bounded here.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore
from ..gui.text import CLAIMS_NEUTRAL, VIEW_LIMIT, sanitize_text
from . import gates
from .contracts import (
    BytesFeature,
    CellResult,
    ImportFeature,
    MatrixRun,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
    StringFeature,
    TargetRef,
)
from .errors import RuleError
from .store import RuleStore

CLAIMS = CLAIMS_NEUTRAL
TITLE = 'Detection rules'
TEXT_LIMIT = 64 * 1024            # a stored rule is at most this long (spec section 3)
CLIPBOARD_LIMIT = 16 * 1024       # exact rule text is copied only if it fits; it is never cut
OVERSIZE = 'Rule text exceeds the clipboard limit. Use Export.'
FOOTER = ('A match means the file contains this pattern. It does not show whether the file is affected by a flaw. '
          'No match does not show that it is unaffected. Counts are raw numbers, not scores.')
IDLE_HINT = 'Rules are proposed with the patchtrace rules command for a pair you have accepted.'
READ_ERRORS = (RuleError, EnrichmentError, sqlite3.Error, OSError)

ACTION_WORDS = {'accept': 'Accepted', 'reject': 'Rejected', 'defer': 'Deferred', 'archive': 'Archived'}
DIRECTION_WORDS = {'older': 'Older build', 'newer': 'Newer build'}
CELL_WORDS = {'hit': 'Match', 'no-hit': 'No match', 'timeout': 'Timed out', 'error': 'Error',
              'not-scanned': 'Not scanned'}
REASON_WORDS = {'too-large': 'file is larger than the limit', 'unreadable': 'file could not be read',
                'not-pe': 'not a PE image', 'file-changed': 'file changed while reading',
                'cancelled': 'run was cancelled'}
VERDICT_WORDS = {'as-expected': 'as expected', 'unexpected-hit': 'unexpected match',
                 'unexpected-miss': 'unexpected no match'}
ROLE_WORDS = {'older-anchor': 'Older anchor', 'newer-anchor': 'Newer anchor', 'series': 'Series', 'extra': 'Extra',
              'clean': 'Clean', 'control': 'Control'}
EXPECT_WORDS = {'hit': 'Expect match', 'no-hit': 'Expect no match', 'unknown': 'No expectation'}
ROLE_FILTER = (('all', 'All roles'), *((key, text) for key, text in ROLE_WORDS.items()))
STATE_FILTER = (('all', 'All results'), *((key, text) for key, text in CELL_WORDS.items()))


@dataclass(frozen=True, slots=True)
class Stored:
    """What the GUI thread read: every stored rule row of the project (the project database is thread-bound)."""
    candidates: tuple[RuleCandidate, ...] = ()
    decisions: tuple[RuleDecision, ...] = ()
    versions: tuple[RuleVersion, ...] = ()
    tests: tuple[MatrixRun, ...] = ()
    skipped: int = 0

    @property
    def empty(self) -> bool:
        return not (self.candidates or self.versions or self.tests)


def load_stored(service, project) -> Stored:
    """GUI thread: read the five rule kinds. A row that does not validate is counted in `skipped`, never shown."""
    rules = RuleStore(EnrichmentStore(service.store), Path(service.root), project.id, project.revision)
    return Stored(tuple(rules.candidates()), tuple(rules.decisions()), tuple(rules.versions()), tuple(rules.tests()),
                  len(rules.skipped))


# ---- small text helpers ------------------------------------------------------------------------------------------

def line(value: object, limit: int = 120) -> str:
    return sanitize_text(value, limit)


def function_label(candidate: RuleCandidate) -> str:
    ref = candidate.source.older if candidate.direction == 'older' else candidate.source.newer
    name = f'{ref.name} ' if ref and ref.name else ''
    return f'{name}at 0x{ref.rva:X}' if ref else 'unknown function'


def latest_decision(stored: Stored, candidate_id: str) -> RuleDecision | None:
    chosen = [d for d in stored.decisions if d.candidate_id == candidate_id]
    return max(enumerate(chosen), key=lambda item: (item[1].decided_at, item[0]))[1] if chosen else None


def latest_version(stored: Stored, candidate_id: str) -> RuleVersion | None:
    found = [v for v in stored.versions if v.candidate_id == candidate_id]
    return max(found, key=lambda v: v.version) if found else None


def latest_test(stored: Stored, version_id: str) -> MatrixRun | None:
    """The newest stored grid that scanned this version (a failed run keeps no cells and is passed over)."""
    runs = [(run.finished_at, index, run) for index, run in enumerate(stored.tests)
            if run.status != 'failed' and any(rule.version_id == version_id for rule in run.rules)]
    return max(runs, key=lambda item: item[:2])[2] if runs else None


def cell_text(cell: CellResult) -> str:
    word = CELL_WORDS[cell.state]
    if cell.state == 'hit':
        word = f'{word} ({cell.hits})'
    elif cell.state == 'not-scanned':
        word = f'{word}: {REASON_WORDS.get(cell.reason or "", "reason unknown")}'
    elif cell.state == 'error':
        word = f'{word}: {line(cell.reason, 48)}'
    verdict = VERDICT_WORDS.get(cell.verdict)
    return f'{word}; {verdict}' if verdict else word


def test_summary(run: MatrixRun | None, version_id: str) -> str:
    """Raw counts of the version's column: matches, no matches and the files nobody could judge (unknown)."""
    if run is None:
        return 'Not tested'
    column = next(i for i, rule in enumerate(run.rules) if rule.version_id == version_id)
    cells = [run.cells[row * len(run.rules) + column] for row in range(len(run.targets))]
    hits = sum(c.state == 'hit' for c in cells)
    misses = sum(c.state == 'no-hit' for c in cells)
    unknown = len(cells) - hits - misses
    tail = '' if run.status == 'complete' else f' ({run.status} run)'
    return f'{hits} match, {misses} no match, {unknown} unknown of {len(cells)} files{tail}'


# ---- candidates ----------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CandidateRow:
    key: str
    name: str
    direction: str
    function: str
    status: str
    checks: str
    features: str
    tested: str
    unvetted: bool
    search: str
    accessible: str


def checks_summary(candidate: RuleCandidate) -> str:
    done = sum(gates.passed(g) for g in candidate.gates)
    text = f'{done} of {len(candidate.gates)} pass'
    open_gate = gates.first_blocking(candidate.gates)
    if open_gate is None:
        return text
    state = 'failed' if open_gate.state == 'fail' else 'unknown'
    return f'{text}; {gates.LABELS[open_gate.gate_id]} {state}'


def candidate_rows(stored: Stored) -> tuple[CandidateRow, ...]:
    rows = []
    for candidate in sorted(stored.candidates, key=lambda c: (c.direction, c.candidate_id)):
        decision = latest_decision(stored, candidate.candidate_id)
        version = latest_version(stored, candidate.candidate_id)
        tested = test_summary(latest_test(stored, version.version_id), version.version_id) if version else 'No saved version'
        included = sum(f.included for f in candidate.features)
        status = ACTION_WORDS[decision.action] if decision else 'Proposed'
        if candidate.unvetted:
            status += ', unvetted'
        function = function_label(candidate)
        direction = DIRECTION_WORDS[candidate.direction]
        label = decision.analyst_label if decision and decision.analyst_label else ''
        rows.append(CandidateRow(
            candidate.candidate_id, candidate.rule_name, direction, function, status, checks_summary(candidate),
            f'{included} of {len(candidate.features)} included', tested, candidate.unvetted,
            f'{candidate.rule_name} {function} {label} {status}',
            f'{direction} rule {function}: {status}. {checks_summary(candidate)}.'))
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class FeatureRow:
    key: str
    include: str
    kind: str
    feature: str
    older: str
    newer: str
    source: str
    where: str


def _feature_parts(feature) -> tuple[str, str, str, str]:
    """Kind, text, source and place of one feature. Text is a pattern or an escaped literal, never raw bytes."""
    if isinstance(feature, BytesFeature):
        return ('Bytes', feature.pattern, f'{feature.mask_source}, {feature.literal} literal bytes',
                f'RVA 0x{feature.window_rva:X}')
    if isinstance(feature, StringFeature):
        return 'String', feature.text, f'string evidence, {feature.linked_by}', f'{feature.encoding}, offset {feature.offset}'
    if isinstance(feature, ImportFeature):
        name = feature.name if feature.name is not None else f'ordinal {feature.ordinal}'
        return 'Import', f'{feature.dll}!{name}', feature.origin, 'delay import' if feature.delay else 'import table'
    return ('Capability', feature.rule_id, 'capa', ', '.join(f'{g.dll}!{g.name}' for g in feature.api_gates[:3]))


def _presence(separation: str) -> tuple[str, str]:
    """Older and newer cells from a stored separation. Present on one side only is a stored fact; unknown stays unknown."""
    return {'older-only': ('Present', 'Absent'), 'newer-only': ('Absent', 'Present'),
            'both-sides': ('Present', 'Present')}.get(separation, ('Unknown: not compared',) * 2)


def _hit_cells(feature) -> tuple[str, str]:
    own, other = feature.source_hits, feature.other_hits
    if own is None or other is None:
        return _presence(feature.separation)
    return (str(own), str(other)) if feature.side == 'older' else (str(other), str(own))


def feature_rows(candidate: RuleCandidate) -> tuple[FeatureRow, ...]:
    rows = []
    for position, feature in enumerate(candidate.features):
        kind, text, source, where = _feature_parts(feature)
        older, newer = _hit_cells(feature) if isinstance(feature, BytesFeature) else _presence(feature.separation)
        rows.append(FeatureRow(str(position), 'Included' if feature.included else 'Shown only', kind, text, older, newer,
                               source, where))
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class CheckRow:
    key: str
    check: str
    state: str
    measured: str
    basis: str


def check_rows(candidate: RuleCandidate) -> tuple[CheckRow, ...]:
    return tuple(CheckRow(g.gate_id, gates.LABELS[g.gate_id], g.state.capitalize(),
                          'Unknown' if g.measured is None else str(g.measured), g.detail or '-')
                 for g in candidate.gates)


def rule_text(candidate: RuleCandidate) -> str:
    """The stored text, exactly as generated and bounded; it is shown, copied and never executed."""
    return candidate.rule_text[:TEXT_LIMIT]


def clipboard_text(text: str) -> str | None:
    """The exact text, or None when it does not fit: a copy that says "exact" is never truncated."""
    return text if len(text.encode('utf-8')) <= CLIPBOARD_LIMIT else None


def candidate_detail(stored: Stored, candidate: RuleCandidate) -> str:
    decision = latest_decision(stored, candidate.candidate_id)
    lines = [f'{DIRECTION_WORDS[candidate.direction]} rule {candidate.rule_name}',
             f'Function: {function_label(candidate)}',
             f'Status: {ACTION_WORDS[decision.action] if decision else "Proposed"}']
    if candidate.unvetted:
        lines.append('Unvetted: you confirmed the change as material; the engine did not.')
    if decision and decision.analyst_label:
        lines.append(f'Your label: {decision.analyst_label}')
    if decision and decision.note:
        lines.append(f'Your note: {decision.note}')
    lines.append(f'Engine: {candidate.engine.engine} {candidate.engine.version} ({candidate.engine.version_source})')
    return sanitize_text('\n'.join(lines), VIEW_LIMIT, multiline=True)


# ---- saved versions ------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SavedRow:
    key: str
    label: str
    version: str
    tested: str
    created: str
    candidate_id: str
    search: str


def version_label(stored: Stored, version: RuleVersion) -> str:
    decision = next((d for d in stored.decisions if d.decision_id == version.decision_id), None)
    return decision.analyst_label if decision and decision.analyst_label else version.version_id[:12]


def saved_rows(stored: Stored) -> tuple[SavedRow, ...]:
    rows = []
    for version in sorted(stored.versions, key=lambda v: (v.lineage_id, v.version)):
        label = version_label(stored, version)
        tested = test_summary(latest_test(stored, version.version_id), version.version_id)
        rows.append(SavedRow(version.version_id, label, f'v{version.version}', tested, version.created_at,
                             version.candidate_id, f'{label} v{version.version}'))
    return tuple(rows)


# ---- the test grid -------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class GridRow:
    key: str
    build: str
    label: str
    role: str
    role_key: str
    expectation: str
    advisory: str
    cells: tuple[str, ...]
    states: tuple[str, ...]
    unexpected: bool


@dataclass(frozen=True, slots=True)
class Grid:
    run_id: str
    status: str
    versions: tuple[str, ...]
    rows: tuple[GridRow, ...]


def _target_row(run: MatrixRun, index: int, target: TargetRef) -> GridRow:
    width = len(run.rules)
    cells = run.cells[index * width:(index + 1) * width]
    build = str(target.ordinal) if target.ordinal else '-'
    advisory = 'Not stated' if target.advisory_says == 'unknown' else target.advisory_says.replace('_', ' ').capitalize()
    return GridRow(target.target_id, build, target.label, ROLE_WORDS[target.role], target.role,
                   EXPECT_WORDS[target.expect], advisory, tuple(cell_text(c) for c in cells),
                   tuple(c.state for c in cells), any(c.verdict.startswith('unexpected') for c in cells))


def build_grid(stored: Stored) -> Grid | None:
    """The newest stored run with cells, one column per rule version in the run's own order."""
    runs = [(run.finished_at, index, run) for index, run in enumerate(stored.tests) if run.status != 'failed']
    if not runs:
        return None
    run = max(runs, key=lambda item: item[:2])[2]
    by_id = {v.version_id: v for v in stored.versions}
    names = tuple(f'v{by_id[r.version_id].version} {version_label(stored, by_id[r.version_id])}'
                  if r.version_id in by_id else f'Unknown rule {r.version_id[:8]}' for r in run.rules)
    ordered = sorted(enumerate(run.targets), key=lambda item: (item[1].ordinal is None, item[1].ordinal or 0,
                                                              item[1].target_id))
    return Grid(run.run_id, run.status, names, tuple(_target_row(run, i, t) for i, t in ordered))


# ---- freshness and state -------------------------------------------------------------------------------------------

def stale_reasons(stored: Stored, key) -> tuple[str, ...]:
    """Why stored rows no longer describe the open project (framework rule: another run, revision or pair)."""
    sources = [c.source for c in stored.candidates] + [v.source for v in stored.versions]
    reasons = []
    if any((s.older_sha256, s.newer_sha256) != (key.older_sha256, key.newer_sha256) for s in sources):
        reasons.append('the builds differ from the ones the rules came from')
    if any(s.run_id != key.run_id for s in sources):
        reasons.append('the comparison was run again')
    if any(s.revision != key.revision for s in sources):
        reasons.append('the project changed after the rules were proposed')
    return tuple(reasons)


def conditions(stored: Stored | None, key, *, error: tuple[str, str] | None = None, loading: bool = False
               ) -> Mapping[str, Mapping[str, object]]:
    """The states that apply now, for `StateView.show_conditions` to rank (error > stale > partial > ready)."""
    if key is None:
        return {'no-project': {}}
    if error is not None:
        return {'error': {'code': error[0], 'message': error[1]}}
    if stored is None:
        return {'loading': {'noun': 'stored rules'}} if loading else {'idle': {'hint': IDLE_HINT}}
    found: dict[str, Mapping[str, object]] = {}
    if stored.empty and not stored.skipped:
        return {'idle': {'hint': IDLE_HINT}}
    if stored.skipped:
        found['partial'] = {'reasons': f'{stored.skipped} stored rule rows could not be read and are not shown'}
    stale = stale_reasons(stored, key)
    if stale:
        found['stale'] = {'reason': '; '.join(stale)}
    return found or {'ready': {}}
