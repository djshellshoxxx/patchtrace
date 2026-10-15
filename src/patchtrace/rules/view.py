"""Pure view model of the detection-rules panel (plan s8, slice R6a): exact state and cell copy, candidate chips, feature
rows, check rows, the test grid and the saved-rule list. No Qt, no I/O, no engine. Every string that reaches a view comes
from untrusted rule data, so it is stripped of control and bidi characters and bounded; nothing here decides "affected" or
"fixed": a cell is Match, No match, Not scanned, Timed out or Error, and an unscanned file is never counted as clean."""
from __future__ import annotations

import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from . import gates as g
from .contracts import (
    BytesFeature,
    CapabilityFeature,
    CellResult,
    Gate,
    ImportFeature,
    MatrixRun,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
    StringFeature,
    TargetRef,
)

TEXT_LIMIT = 200
FOOTER = ('A match means the file contains this pattern. It does not show whether the file is affected by a flaw. '
          'No match does not show that it is unaffected. Counts are raw numbers, not scores.')

STATES: dict[str, str] = {
    'R0': 'Open a project to work with detection rules.',
    'R1': 'The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or tested. '
          'Saved rules stay readable.',
    'R2': 'Select a function pair you have accepted. Rules are only proposed for pairs you have reviewed.',
    'R3': 'No rules proposed for this pair yet. Choose Propose rules. Nothing is generated or saved until you ask.',
    'R4p': 'Proposing rules from the selected pair...',
    'R4t': 'Testing {rules} rules against {files} files. Files that cannot be read are reported as Not scanned, '
           'never as No match.',
    'R5': 'No rule passed the checks for this pair: {reason}. Bytes are unavailable when the function size is not '
          'known (leaf functions without exception data).',
    'R6': 'These rules describe an earlier analysis or engine version ({reason}). Test again before relying on them.',
    'R7': 'Rule work could not finish: {code}: {message}. Saved rules are unchanged.',
    'R8': 'Too many files or cells ({count}). Narrow the folder or the build list.',
}
REASONS = {'too-large': 'file is larger than the limit', 'unreadable': 'file could not be read',
           'not-pe': 'not a PE image', 'file-changed': 'file changed while reading', 'cancelled': 'run was cancelled'}
VERDICTS = {'as-expected': 'as expected', 'unexpected-hit': 'unexpected match', 'unexpected-miss': 'unexpected no match',
            'unscored': 'no expectation'}
EXPECTED = {'hit': 'expected a match', 'no-hit': 'expected no match', 'unknown': 'no expectation'}
SIDE_WORDS = {True: 'present', False: 'absent', None: 'unknown'}
_DROPPED = ('Cc', 'Cf', 'Cn', 'Co', 'Cs', 'Zl', 'Zp')


def clean(value: object, limit: int = TEXT_LIMIT) -> str:
    """Text safe to show: control, format (bidi) and unassigned characters are dropped, the length is bounded."""
    text = ''.join(c for c in str(value) if unicodedata.category(c) not in _DROPPED)
    return text[:limit] + ('...' if len(text) > limit else '')


@dataclass(frozen=True)
class Status:
    state_id: str
    text: str


def status(state_id: str, **values: object) -> Status:
    """The exact text of a state; placeholders are filled with cleaned values."""
    return Status(state_id[:2], STATES[state_id].format(**{k: clean(v) for k, v in values.items()}))


# --- candidates ------------------------------------------------------------------------------------------------------

def chip(candidate: RuleCandidate, decisions: Sequence[RuleDecision], versions: Sequence[RuleVersion] = ()) -> str:
    """Proposed / Accepted vN / Rejected / Deferred / Archived / Needs review; the last decision in force wins."""
    last = decisions[-1].action if decisions else None
    if last == 'accept':
        mine = [v.version for v in versions if v.lineage_id == candidate.lineage_id]
        return f'Accepted v{max(mine)}' if mine else 'Accepted'
    if last:
        return {'reject': 'Rejected', 'defer': 'Deferred', 'archive': 'Archived'}[last]
    return 'Needs review' if candidate.unvetted else 'Proposed'


@dataclass(frozen=True)
class CandidateRow:
    candidate_id: str
    name: str
    chip: str
    rule_name: str


def candidate_row(candidate: RuleCandidate, decisions: Sequence[RuleDecision],
                  versions: Sequence[RuleVersion] = ()) -> CandidateRow:
    word = 'Older' if candidate.direction == 'older' else 'Newer'
    return CandidateRow(candidate.candidate_id, f'{word}-build rule', chip(candidate, decisions, versions),
                        clean(candidate.rule_name))


@dataclass(frozen=True)
class FeatureRow:
    included: bool
    kind: str
    text: str
    older: str
    newer: str
    where: str


def _presence(separation: str) -> tuple[str, str]:
    """`present`, `absent` (the producing tool completed) or `unknown` (it did not); never a bare dash."""
    older, newer = {'older-only': (True, False), 'newer-only': (False, True), 'both-sides': (True, True)
                    }.get(separation, (None, None))
    return SIDE_WORDS[older], SIDE_WORDS[newer]


def feature_row(feature) -> FeatureRow:
    if isinstance(feature, BytesFeature):
        kind, text, where = 'bytes', feature.pattern, f'0x{feature.window_rva:x}'
    elif isinstance(feature, StringFeature):
        kind, text, where = 'string', f'"{feature.text}"', f'0x{feature.offset:x}'
    elif isinstance(feature, ImportFeature):
        name = feature.name if feature.name is not None else f'#{feature.ordinal}'
        kind, text, where = 'import', f'{feature.dll}!{name}', ''
    elif isinstance(feature, CapabilityFeature):
        kind, text, where = 'capability', feature.rule_id, ''
    else:
        kind, text, where = clean(feature.kind, 32), '', ''
    older, newer = _presence(feature.separation)
    return FeatureRow(feature.included, kind, clean(text), older, newer, where)


def feature_rows(candidate: RuleCandidate) -> tuple[FeatureRow, ...]:
    return tuple(feature_row(f) for f in candidate.features)


@dataclass(frozen=True)
class CheckRow:
    gate_id: str
    state: str
    text: str


def check_rows(gates: Iterable[Gate]) -> tuple[CheckRow, ...]:
    return tuple(CheckRow(gate.gate_id, gate.state, clean(g.sentence(gate))) for gate in gates)


# --- test grid -------------------------------------------------------------------------------------------------------

def cell_text(cell: CellResult) -> str:
    if cell.state == 'hit':
        return 'Match'
    if cell.state == 'no-hit':
        return 'No match'
    if cell.state == 'timeout':
        return 'Timed out'
    if cell.state == 'error':
        return 'Error'
    return f'Not scanned: {REASONS.get(cell.reason or "", "reason not recorded")}'


def accessible_cell(index: int, count: int, target: TargetRef, rule_name: str, cell: CellResult) -> str:
    """"Build 3 of 8, KB5034123, rule PT_...: No match, expected a match"."""
    kb = f', {target.kb}' if target.kb else ''
    return clean(f'Build {index} of {count}{kb}, rule {rule_name}: {cell_text(cell)}, {EXPECTED[target.expect]}')


@dataclass(frozen=True)
class GridRow:
    ordinal: int | None
    label: str
    kb: str
    file_version: str
    role: str
    expectation: str
    advisory: str
    cells: tuple[str, ...]
    verdicts: tuple[str, ...]
    states: tuple[str, ...]
    unexpected: bool


@dataclass(frozen=True)
class SummaryRow:
    rule: str
    match: int
    no_match: int
    not_scanned: int
    unexpected: int

    @property
    def text(self) -> str:
        return (f'{self.match} Match, {self.no_match} No match, {self.not_scanned} Not scanned, '
                f'{self.unexpected} unexpected')


_BLANK = CellResult(state='error', reason='no-result')   # a failed run holds no cells: Error, never No match


class GridView:
    """Rows = builds, columns = rule versions. Precomputed strings only; the row order and the filter are the model's own
    (no proxy model), and a filter returns row indexes, so first paint costs the same for any number of rows. A cell the
    run does not hold reads Error, never No match."""

    def __init__(self, run: MatrixRun, rule_names: Sequence[str]):
        self.run = run
        self.columns = len(run.rules)
        self.rule_names = tuple(clean(n, 64) for n in rule_names)
        self.footer = FOOTER
        self.rows = tuple(self._row(r, target) for r, target in enumerate(run.targets))

    def cell(self, row: int, column: int) -> CellResult:
        index = row * self.columns + column
        return self.run.cells[index] if index < len(self.run.cells) else _BLANK

    def _row(self, r: int, target: TargetRef) -> GridRow:
        cells = [self.cell(r, c) for c in range(self.columns)]
        advisory = clean(target.advisory_says.replace('_', ' '), 32)
        return GridRow(target.ordinal, clean(target.label), clean(target.kb or '', 32), clean(target.file_version or '', 64),
                       target.role, EXPECTED[target.expect], f'Advisory says: {advisory}',
                       tuple(cell_text(c) for c in cells), tuple(VERDICTS[c.verdict] for c in cells),
                       tuple(c.state for c in cells), any(c.verdict.startswith('unexpected') for c in cells))

    def row_indexes(self, *, role: str | None = None, state: str | None = None, unexpected_only: bool = False
                    ) -> tuple[int, ...]:
        return tuple(i for i, row in enumerate(self.rows)
                     if (role is None or row.role == role) and (state is None or state in row.states)
                     and (not unexpected_only or row.unexpected))

    def summary(self) -> tuple[SummaryRow, ...]:
        out = []
        for column, name in enumerate(self.rule_names):
            cells = [self.cell(r, column) for r in range(len(self.rows))]
            count = Counter(c.state for c in cells)
            verdicts = sum(c.verdict.startswith('unexpected') for c in cells)
            out.append(SummaryRow(name, count['hit'], count['no-hit'], len(cells) - count['hit'] - count['no-hit'], verdicts))
        return tuple(out)

    def accessible(self, row: int, column: int) -> str:
        return accessible_cell(row + 1, len(self.rows), self.run.targets[row], self.rule_names[column],
                               self.cell(row, column))


# --- saved rules -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SavedRow:
    lineage_id: str
    version_id: str
    version: int
    label: str
    tested: str


def tested_text(version: RuleVersion, runs: Sequence[MatrixRun], engine_version: str) -> str:
    """"Tested on {date}: 4 builds, 12 clean files" / "Not tested" / "Grid stale: YARA-X version changed". A grid of another
    engine version is stale, never silently current."""
    mine = [r for r in runs if r.status == 'complete' and any(x.version_id == version.version_id for x in r.rules)]
    if not mine:
        return 'Not tested'
    last = max(mine, key=lambda r: (r.finished_at, r.run_id))
    if last.engine.version != engine_version:
        return 'Grid stale: YARA-X version changed'
    clean_files = sum(t.role == 'clean' for t in last.targets)
    return f'Tested on {last.finished_at[:10]}: {len(last.targets) - clean_files} builds, {clean_files} clean files'


def saved_rows(versions: Sequence[RuleVersion], decisions: Sequence[RuleDecision], runs: Sequence[MatrixRun],
               engine_version: str) -> tuple[SavedRow, ...]:
    """The newest version of each lineage; archived lineages leave the list but stay in history (no delete)."""
    by_id = {d.decision_id: d for d in decisions}
    archived = {d.candidate_id for d in decisions if d.action == 'archive'}
    newest: dict[str, RuleVersion] = {}
    for v in sorted(versions, key=lambda v: v.version):
        newest[v.lineage_id] = v
    out = []
    for v in newest.values():
        if v.candidate_id in archived:
            continue
        d = by_id.get(v.decision_id)
        out.append(SavedRow(v.lineage_id, v.version_id, v.version, clean(d.analyst_label or '', 120) if d else '',
                            tested_text(v, runs, engine_version)))
    return tuple(out)
