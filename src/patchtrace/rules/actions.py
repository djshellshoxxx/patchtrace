"""What the Detection rules panel can DO (panel spec R6b): accept, test and export, as Qt-free steps.

Each action is split along the project's thread rule: the project database belongs to the GUI thread and the engine runs
only in the hidden worker child. So an action is a pure `plan_*` (no I/O), a step that needs the engine or the disk and
holds no connection (`check_compiles`, `run_test`, `write_export`: safe on a worker thread), and a `commit_*` that appends
rows on the GUI thread. Nothing here proposes (that is `live`), executes a target, opens the network or replaces a file.

Honesty rules: accepting is an explicit analyst act, never implied by a proposal or a passing test; a persisted row is only
ever appended (a changed mind is a new decision, a revision a new version); a build that could not be read, timed out or
was too large is "Not scanned", "Timed out" or "Error", never "No match"; the exported file is exactly the previewed text.
"""
from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import export as exporting
from . import gates as g
from . import matrix, runner, store
from .contracts import (
    ENGINE_PIN,
    CellResult,
    ExportRecord,
    MatrixRun,
    PairSource,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
    WorkerRule,
    WorkerTarget,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS, RuleLimits
from .store import RuleStore
from .view_model import cell_text

SIDES = ('older', 'newer')
SIDE_WORDS = {'older': 'Older build', 'newer': 'Newer build'}
WARNING_WORDS = {
    'not-tested': 'This rule version has not been tested on any build.',
    'not-scanned': 'Some files of the last test were not scanned, so nothing is known about them.',
    'unexpected-results': 'The last test had results that differ from what was expected.',
    'grid-stale': 'The last test used another engine version than the one in this installation.'}
EXPORT_LICENCE = ('The rule contains byte patterns copied from the analysed files. If those files are third-party software, '
                  'check its licence before sharing the rule or committing it to a repository.')
ILLEGAL_NAME = re.compile(r'[\x00-\x1f\x7f<>:"|?*\\/]')
MAX_NAME = 120
Lint = Callable[..., tuple]
Scan = Callable[..., runner.ScanOutcome]


# ---- accept --------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class AcceptPlan:
    """The decision and the version an accept makes. `fresh` is False when that very accept is already stored."""
    decision: RuleDecision
    version: RuleVersion
    fresh: bool


def plan_accept(candidate: RuleCandidate, decisions: Sequence[RuleDecision], versions: Sequence[RuleVersion], *,
                label: str, note: str = '', cve: Sequence[str] = (), kb: Sequence[str] = (), cwe: Sequence[str] = (),
                now: str) -> AcceptPlan:
    """Pure. `decisions` are those of this candidate (oldest first) and `versions` the stored chain of its lineage. The same
    accept again after a crash between the two rows finishes the second row; an accept equal to the one in force changes
    nothing; a changed label or advisory list is a new version. A hard-gate failure refuses (`PT-RULE-GATE`)."""
    label = label.strip()
    if not label:
        raise RuleError('PT-RULE-INPUT', 'Accepting a rule needs a label', reason='label-required')
    blocked = g.first_blocking(candidate.gates)
    if blocked is not None:
        raise RuleError('PT-RULE-GATE', f'The rule cannot be accepted: {g.sentence(blocked)}', reason='hard-gate')
    advisories = {'cve': sorted(set(cve)), 'kb': sorted(set(kb)), 'cwe': sorted(set(cwe))}
    last = decisions[-1] if decisions else None
    same = last is not None and last.action == 'accept' and (last.analyst_label, last.note) == (label, note) \
        and all(list(getattr(last, name)) == values for name, values in advisories.items())
    decision = last if same else store.decision_for(candidate, 'accept', now, label=label, note=note, **advisories)
    chain = sorted(versions, key=lambda v: v.version)
    existing = next((v for v in chain if v.decision_id == decision.decision_id), None)
    if existing is not None:
        return AcceptPlan(decision, existing, False)
    version = store.version_for(candidate, decision, chain[-1] if chain else None,
                                store.accepted_text(candidate, decision, len(chain) + 1))
    return AcceptPlan(decision, version, True)


def check_compiles(version: RuleVersion, *, lint: Lint = runner.lint, cancel: threading.Event | None = None) -> None:
    """Worker side: the accepted text (with the analyst's label) compiles with this engine, or `PT-RULE-COMPILE`."""
    (found,) = lint((WorkerRule(name='accept', text=version.rule_text),), cancel=cancel)
    gate = g.compiles(found)
    if not g.passed(gate):
        raise RuleError('PT-RULE-COMPILE', f'The accepted rule does not compile: {g.sentence(gate)}',
                        reason='accept-compile')


def commit_accept(rules: RuleStore, candidate: RuleCandidate, plan: AcceptPlan) -> bool:
    """GUI thread: append the decision, then the version it makes. False when nothing new was needed."""
    if not plan.fresh:
        return False
    rules.add_decision(plan.decision, candidate.source)
    rules.add_version(plan.version)
    return True


# ---- test ----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SideResult:
    """One build against the rule: the raw engine state and its words. `cell` is None only for a build that was not sent."""
    side: str
    cell: CellResult
    text: str

    @property
    def label(self) -> str:
        return SIDE_WORDS[self.side]


@dataclass(frozen=True)
class RuleTestOutcome:
    sides: tuple[SideResult, ...]
    engine_version: str
    run: MatrixRun | None = None     # set when the rule is a saved version: the grid to append to the project

    def sentence(self) -> str:
        return '; '.join(f'{item.label}: {item.text}' for item in self.sides)


def _check_timeout(timeout_s: int | None, limits: RuleLimits) -> None:
    if timeout_s is not None and not limits.target_timeout_min_s <= timeout_s <= limits.target_timeout_max_s:
        raise RuleError('PT-RULE-INPUT', f'The per-file timeout must be {limits.target_timeout_min_s} to '
                        f'{limits.target_timeout_max_s} seconds', reason='timeout-range')


def _not_scanned(reason: str) -> CellResult:
    return CellResult(state='not-scanned', reason=reason)


def _side_results(cells: Mapping[str, CellResult]) -> tuple[SideResult, ...]:
    return tuple(SideResult(side, cells[side], cell_text(cells[side])) for side in SIDES)


def scan_sides(rule_name: str, rule_text: str, pair: PairSource, builds: Mapping[str, Path], *,
               timeout_s: int | None = None, cancel: threading.Event | None = None,
               limits: RuleLimits = DEFAULT_LIMITS, scan: Scan = runner.scan) -> RuleTestOutcome:
    """Worker side. Scan the two builds of the pair with ONE rule text in the hidden worker: the files are read as data and
    never run. A build that is missing, not the recorded file, larger than `limits.file_bytes` or not readable is
    "Not scanned" with its reason; a build that exceeds the per-file `timeout_s` is "Timed out". Nothing is stored."""
    _check_timeout(timeout_s, limits)
    hashes = {'older': pair.older_sha256, 'newer': pair.newer_sha256}
    cells: dict[str, CellResult] = {}
    targets: list[WorkerTarget] = []
    for side in SIDES:
        path = builds.get(side)
        try:
            info = Path(path).stat() if path is not None else None
        except OSError:
            info = None
        if info is None or not Path(path).is_file():
            cells[side] = _not_scanned('unreadable')
        elif info.st_size > limits.file_bytes:
            cells[side] = _not_scanned('too-large')
        else:
            targets.append(WorkerTarget(target_id=side, path=str(Path(path).resolve()), sha256=hashes[side],
                                        size=info.st_size))
    engine_version = ''
    if targets:
        outcome = scan((WorkerRule(name=rule_name, text=rule_text),), tuple(targets), timeout_s=timeout_s, cancel=cancel,
                       limits=limits)
        bad = [item for item in outcome.lint if not item.ok]
        if bad:
            raise RuleError('PT-RULE-COMPILE', 'The rule does not compile with this engine', reason='lint')
        engine_version = outcome.engine.version
        cells.update({target.target_id: cell for target, cell in zip(targets, outcome.cells, strict=True)})
    return RuleTestOutcome(_side_results(cells), engine_version)


def run_version_grid(version: RuleVersion, builds: Mapping[str, Path], *, timeout_s: int | None = None,
                     cancel: threading.Event | None = None, limits: RuleLimits = DEFAULT_LIMITS,
                     scan: Scan = runner.scan) -> RuleTestOutcome:
    """Worker side. The same test for a SAVED version, as the project's own grid (`matrix`): the result carries the run to
    append (`commit_test`), so a later export can say the version was tested. Expectations follow the rule: the older
    anchor should match an older-build rule and the newer one should not (and the reverse)."""
    _check_timeout(timeout_s, limits)
    anchors = {side: matrix.Anchor(Path(path), SIDE_WORDS[side]) for side, path in builds.items() if side in SIDES}
    entries, _notes = matrix.gather(version.source, anchors, limits=limits)
    recorded = {'older-anchor': version.source.older_sha256, 'newer-anchor': version.source.newer_sha256}
    if any(entry.target.sha256 != recorded.get(entry.target.role, entry.target.sha256) for entry in entries):
        raise RuleError('PT-RULE-STALE', 'A build is not the file the rule was made for', reason='build-moved')
    if len({entry.target.role for entry in entries} & set(recorded)) < len(recorded):
        raise RuleError('PT-RULE-STALE', 'A build is not the file the rule was made for', reason='build-moved')
    grid = matrix.run_matrix(entries, [version], scan=scan, timeout_s=timeout_s, cancel=cancel, limits=limits)
    cells = {}
    for target, cell in zip(grid.targets, grid.cells, strict=True):
        side = {'older-anchor': 'older', 'newer-anchor': 'newer'}.get(target.role)
        if side is not None:
            cells[side] = cell
    for side in SIDES:
        cells.setdefault(side, _not_scanned('unreadable'))   # the anchor was not among the files: unknown, not a miss
    return RuleTestOutcome(_side_results(cells), grid.engine.version, grid)


def commit_test(rules: RuleStore, version: RuleVersion, run: MatrixRun) -> bool:
    """GUI thread: append the grid of a saved version. A cancelled run is not stored; its cells are unknown."""
    if run.status == 'cancelled':
        return False
    return rules.add_test(run, version.source)


# ---- export --------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ExportPreview:
    """What would be written, exactly: `text` is the file. `warnings` need an explicit acknowledgement."""
    version_id: str
    rule_name: str
    suggested_name: str
    text: str
    warnings: tuple[str, ...]

    @property
    def warning_sentences(self) -> tuple[str, ...]:
        return tuple(WARNING_WORDS.get(code, code) for code in self.warnings)


def plan_export(version: RuleVersion, decisions: Sequence[RuleDecision], candidate: RuleCandidate | None,
                runs: Sequence[MatrixRun], *, basenames: Mapping[str, str] | None = None, include_names: bool = False
                ) -> tuple[ExportPreview, exporting.ExportPlan]:
    """Pure. The text of the file and its informational warnings; a failed hard check (separation, compile, secret,
    integrity) raises `PT-RULE-GATE` or `PT-RULE-INTEGRITY` and nothing can be exported."""
    decision = next((d for d in decisions if d.decision_id == version.decision_id), None)
    if decision is None:
        raise RuleError('PT-RULE-INTEGRITY', 'The decision of this rule version is not stored', reason='decision-missing')
    plan = exporting.build(version, decision, candidate, list(runs), include_names=include_names,
                           basenames=basenames or {}, engine_version=ENGINE_PIN)
    return ExportPreview(version.version_id, plan.rule_name, f'{plan.rule_name}.yar', plan.text, plan.warnings), plan


def sanitise_export_path(text: str) -> Path:
    """The path the analyst chose, made safe to write: no control or reserved characters in the name, `.yar` appended when
    the name has no suffix, any other suffix refused, an existing directory refused. The folder is not created and the
    file is not followed through a link by `export.write` (it creates a new file only)."""
    raw = str(text).strip()
    if not raw or '\x00' in raw:
        raise RuleError('PT-RULE-EXPORT', 'Choose a file name', reason='no-name')
    path = Path(raw).expanduser()
    name = path.name
    if not name or name in ('.', '..') or path.is_dir():
        raise RuleError('PT-RULE-EXPORT', 'Choose a file name, not a folder', reason='no-name')
    if ILLEGAL_NAME.search(name) or name != name.rstrip('. ') or len(name) > MAX_NAME:
        raise RuleError('PT-RULE-EXPORT', 'The file name has characters that are not allowed', reason='bad-name')
    if not path.suffix:
        path = path.with_name(name + '.yar')
    elif path.suffix.lower() != '.yar':
        raise RuleError('PT-RULE-EXPORT', 'The file name must end in .yar', reason='suffix')
    elif path.suffix != '.yar':
        path = path.with_suffix('.yar')
    return path


def write_export(plan: exporting.ExportPlan, version: RuleVersion, destination: Path, *, allow_git_tree: bool = False
                 ) -> ExportRecord:
    """Worker side: create the file (never replaces one) and return the record to append. The bytes are the preview's."""
    return exporting.write(plan, version, destination, allow_git_tree=allow_git_tree)


def commit_export(rules: RuleStore, version: RuleVersion, record: ExportRecord) -> bool:
    """GUI thread: append the export record. The file already exists; a failure here never means "no file was written"."""
    return rules.add_export(record, version.source)


def default_folder() -> Path:
    """Where a chooser starts: the user's home, never the project folder (an export is meant to leave the project)."""
    return Path(os.path.expanduser('~'))
