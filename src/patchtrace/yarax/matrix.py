"""Rule matrix: the synthesizer binding, real gates from scan output, target collection and the test grid (plan s7).

Pure orchestration: every engine call goes through an injected `Engine` (the capped worker in production, a fake in
tests), so nothing here imports `yara_x`. A cell the engine did not read stays unknown (`not-scanned`, `timeout`,
`error`) and never becomes a negative; counts stay raw numbers, never a score. Verdicts are assigned here: the engine
leaves every cell `unscored`.
"""
from __future__ import annotations

import dataclasses
import hashlib
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from ..enrichment.identity import domain_id
from . import gates as gate_checks
from . import runner
from .candidates import RuleWriter, lineage_id, recompose
from .contracts import (
    WORKER_CONTRACT,
    CellResult,
    EngineStamp,
    Expect,
    Feature,
    LintFinding,
    MatrixRun,
    PairSource,
    RuleCandidate,
    RuleText,
    Side,
    TargetRef,
    Verdict,
    WorkerTarget,
)
from .errors import RulesError
from .limits import LIMITS, RuleLimits
from .synth import RuleSpec, parse_rule, synthesize

CHUNK_TARGETS = 16
SCANNED = ('hit', 'no-hit')
ANCHOR_ROLES: dict[str, Side] = {'older-anchor': 'older', 'newer-anchor': 'newer'}
_READ_BLOCK = 1024 * 1024
_REASON_BIG = 'file is larger than the limit'
_REASON_UNREADABLE = 'file could not be read'
_REASON_CANCELLED = 'run was cancelled'

LintFn = Callable[[Sequence[RuleText]], tuple[EngineStamp, tuple[LintFinding, ...]]]
ScanFn = Callable[[Sequence[RuleText], Sequence[WorkerTarget]], tuple[EngineStamp, tuple[CellResult, ...]]]


@dataclass(frozen=True)
class Engine:
    """The three engine operations a run needs; production binds them to the capped worker."""
    probe: Callable[[], EngineStamp]
    lint: LintFn
    scan: ScanFn


def worker_engine(*, cancel: threading.Event, private_dir: Path, limits: RuleLimits = LIMITS,
                  argv_for: runner.ArgvFactory = runner.worker_argv) -> Engine:
    common = {'cancel': cancel, 'private_dir': private_dir, 'limits': limits, 'argv_for': argv_for}
    return Engine(probe=partial(runner.probe, **common), lint=partial(runner.lint, **common),
                  scan=partial(runner.scan, **common))


# ---- the synthesizer behind the candidate engine's RuleWriter ---------------------------------------------------------

def synth_writer(*, version: int = 1, include_names: bool = False, analyst_label: str = '', cve: Sequence[str] = (),
                 kb: Sequence[str] = (), cwe: Sequence[str] = ()) -> RuleWriter:
    """A `RuleWriter` over the closed-grammar synthesizer; the text is checked to carry the candidate's rule name."""
    def write(pair: PairSource, *, direction: Side, rule_name: str, features: Sequence[Feature]) -> str:
        spec = RuleSpec(source=pair, direction=direction, lineage_id=lineage_id(pair, direction), version=version,
                        features=tuple(features), analyst_label=analyst_label, include_names=include_names,
                        unvetted=pair.materiality != 'material', cve=tuple(cve), kb=tuple(kb), cwe=tuple(cwe))
        text = synthesize(spec)
        if parse_rule(text).name != rule_name:
            raise RulesError('PT-RULE-INTEGRITY', 'generated rule does not carry the candidate name')
        return text
    return write


# ---- gates from real scan output --------------------------------------------------------------------------------------

def evaluate(candidate: RuleCandidate, anchors: Mapping[Side, WorkerTarget], engine: Engine) -> RuleCandidate:
    """Fill `compile`, `uniq` and `sep` from the engine: lint the text, then scan the rule's own and the other build.

    A rule that does not compile is not scanned (`sep` stays unknown). A cell the engine could not read leaves its
    gates `unknown`, never `fail`.
    """
    rule = RuleText(name=candidate.rule_name, text=candidate.rule_text)
    stamp, findings = engine.lint((rule,))
    updated = gate_checks.with_compile(candidate.gates, findings)
    if any(g.gate_id == 'compile' and g.state == 'fail' for g in updated):
        return candidate.model_copy(update={'gates': updated, 'compile_warnings': findings[:64], 'engine': stamp})
    other: Side = 'newer' if candidate.direction == 'older' else 'older'
    _stamp, cells = engine.scan((rule,), (anchors[candidate.direction], anchors[other]))
    by_target = {c.target_id: c for c in cells}
    updated = gate_checks.with_scan(updated, candidate.features, by_target.get(anchors[candidate.direction].target_id),
                                    by_target.get(anchors[other].target_id))
    return candidate.model_copy(update={'gates': updated, 'compile_warnings': findings[:64], 'engine': stamp})


def revise(candidate: RuleCandidate, included: Iterable[str], anchors: Mapping[Side, WorkerTarget], engine: Engine,
           *, writer: RuleWriter | None = None) -> RuleCandidate:
    """A toggled revision (same lineage, new feature selection) re-checked against the real engine."""
    return evaluate(recompose(candidate, included, writer=writer or synth_writer()), anchors, engine)


# ---- targets ----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    ref: TargetRef
    path: Path

    def worker(self) -> WorkerTarget:
        return WorkerTarget(target_id=self.ref.target_id, path=str(self.path), sha256=self.ref.sha256,
                            size=self.ref.size)


@dataclass(frozen=True)
class Collected:
    targets: tuple[Target, ...]
    skipped: tuple[str, ...] = ()   # "<basename>: reason", reported as anomalies, never as no-hit


def _hash_file(path: Path, cap: int) -> tuple[str, int] | str:
    """(sha256, size), or the not-scanned reason."""
    digest, size = hashlib.sha256(), 0
    try:
        with open(path, 'rb') as handle:
            while block := handle.read(_READ_BLOCK):
                size += len(block)
                if size > cap:
                    return _REASON_BIG
                digest.update(block)
    except OSError:
        return _REASON_UNREADABLE
    return digest.hexdigest(), size


def file_target(path: Path, role: str, ordinal: int | None, *, expect: Expect = 'unknown', label: str = '',
                sha256: str | None = None, size: int | None = None, limits: RuleLimits = LIMITS) -> Target | str:
    """A `Target` for a file, or the not-scanned reason. Ids carry the role, ordinal and hash prefix, never a path."""
    name = Path(path).name
    if sha256 is None or size is None:
        hashed = _hash_file(Path(path), limits.target_file_bytes)
        if isinstance(hashed, str):
            return f'{name[:120]}: {hashed}'
        sha256, size = hashed
    ref = TargetRef(target_id=f'{role}-{ordinal if ordinal is not None else 0}-{sha256[:12]}',
                    label=(label or name)[:limits.label_chars], role=role, sha256=sha256, size=size, ordinal=ordinal,
                    expect=expect)
    return Target(ref, Path(path))


def _files(directory: Path, recursive: bool) -> list[Path]:
    found = directory.rglob('*') if recursive else directory.iterdir()
    return sorted((p for p in found if p.is_file() and not p.is_symlink()),
                  key=lambda p: p.relative_to(directory).as_posix())


def _role_targets(paths: Sequence[Path], role: str, cap: int, expect: Expect, expected: Mapping[str, Expect],
                  limits: RuleLimits) -> Collected:
    if len(paths) > cap:
        raise RulesError('PT-RULE-LIMIT', f'Too many {role} files ({len(paths)}); the limit is {cap}.')
    targets, skipped = [], []
    for ordinal, path in enumerate(paths, 1):
        made = file_target(path, role, ordinal, limits=limits)
        if isinstance(made, str):
            skipped.append(made)
        else:
            known = expected.get(made.ref.sha256, expect)
            targets.append(dataclasses.replace(made, ref=made.ref.model_copy(update={'expect': known})))
    return Collected(tuple(targets), tuple(skipped))


def collect_targets(anchors: Sequence[Target], *, series_dir: Path | None = None, extra: Sequence[Path] = (),
                    clean_dir: Path | None = None, expected: Mapping[str, Expect] | None = None,
                    limits: RuleLimits = LIMITS) -> Collected:
    """Anchors first, then series, extra and clean files in stable order; caps are enforced before any hashing."""
    expected = expected or {}
    groups = [
        ('series', _files(series_dir, False) if series_dir else [], limits.series_targets, 'unknown'),
        ('extra', list(dict.fromkeys(extra)), limits.extra_targets, 'unknown'),
        ('clean', _files(clean_dir, True) if clean_dir else [], limits.clean_targets, 'no-hit')]
    targets, skipped = list(anchors), []
    for role, paths, cap, expect in groups:
        got = _role_targets(paths, role, cap, expect, expected, limits)
        targets += got.targets
        skipped += got.skipped
    return Collected(tuple(targets), tuple(skipped))


# ---- verdicts and summaries -------------------------------------------------------------------------------------------

def expectation(direction: Side, ref: TargetRef) -> Expect:
    """The anchors follow the rule's direction; every other build says what the analyst set (unknown by default)."""
    anchor = ANCHOR_ROLES.get(ref.role)
    if anchor is None:
        return ref.expect
    return 'hit' if anchor == direction else 'no-hit'


def verdict_of(expect: Expect, state: str) -> Verdict:
    if state not in SCANNED or expect == 'unknown':
        return 'unscored'
    if state == 'hit':
        return 'as-expected' if expect == 'hit' else 'unexpected-hit'
    return 'as-expected' if expect == 'no-hit' else 'unexpected-miss'


def _with_verdicts(cells: Iterable[CellResult], directions: Mapping[str, Side],
                   refs: Mapping[str, TargetRef]) -> tuple[CellResult, ...]:
    return tuple(c.model_copy(update={'verdict': verdict_of(expectation(directions[c.rule_name], refs[c.target_id]),
                                                            c.state)}) for c in cells)


@dataclass(frozen=True)
class GridSummary:
    builds: int
    clean: int
    unexpected_hits: int
    unexpected_misses: int
    not_scanned: int
    engine_version: str


def summarize(run: MatrixRun, rule_name: str) -> GridSummary:
    roles = {t.target_id: t.role for t in run.targets}
    mine = [c for c in run.cells if c.rule_name == rule_name]
    scanned = [c for c in mine if c.state in SCANNED]
    return GridSummary(
        builds=sum(roles[c.target_id] != 'clean' for c in scanned), clean=sum(roles[c.target_id] == 'clean' for c in scanned),
        unexpected_hits=sum(c.verdict == 'unexpected-hit' for c in mine),
        unexpected_misses=sum(c.verdict == 'unexpected-miss' for c in mine),
        not_scanned=len(mine) - len(scanned), engine_version=run.engine.version)


# ---- the grid ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MatrixRule:
    name: str
    text: str
    direction: Side
    version_id: str
    rule_sha256: str


def cache_key(rules: Sequence[MatrixRule], targets: Sequence[Target], engine: EngineStamp,
              limits: RuleLimits = LIMITS) -> str:
    """Hashes only, never paths: the same rules on the same bytes with the same engine give the same key."""
    return domain_id('rule-test', 1, {
        'rules': sorted(r.rule_sha256 for r in rules), 'targets': sorted(t.ref.sha256 for t in targets),
        'engine': engine.version, 'worker': WORKER_CONTRACT, 'limits': limits.digest()})


def _check_run(rules: Sequence[MatrixRule], targets: Sequence[Target], limits: RuleLimits) -> None:
    if not rules or len({r.name for r in rules}) != len(rules):
        raise RulesError('PT-RULE-INPUT', 'A test run needs distinct rules (one version per lineage).')
    if len(rules) > limits.rules_per_run:
        raise RulesError('PT-RULE-LIMIT', f'At most {limits.rules_per_run} rules per run.')
    if len(rules) * len(targets) > limits.cells or sum(t.ref.size for t in targets) > limits.run_bytes:
        raise RulesError('PT-RULE-LIMIT', f'Too many files or cells ({len(rules) * len(targets)}).')


def _unscanned(rules: Sequence[MatrixRule], target: Target, state: str, reason: str) -> list[CellResult]:
    return [CellResult(rule_name=r.name, target_id=target.ref.target_id, state=state, reason=reason) for r in rules]


def _scan_chunk(rules: Sequence[MatrixRule], chunk: Sequence[Target], texts: Sequence[RuleText],
                engine: Engine) -> tuple[CellResult, ...] | None:
    """Cells of one chunk; None when the run was cancelled. An engine failure is `error`/`timeout` cells."""
    try:
        return engine.scan(texts, [t.worker() for t in chunk])[1]
    except RulesError as exc:
        if exc.code == 'PT-RULE-CANCEL':
            return None
        if exc.code not in ('PT-RULE-ENGINE', 'PT-RULE-TIMEOUT'):
            raise
        state = 'timeout' if exc.code == 'PT-RULE-TIMEOUT' else 'error'
        return tuple(c for t in chunk for c in _unscanned(rules, t, state, exc.message[:200]))


def run_matrix(rules: Sequence[MatrixRule], targets: Sequence[Target], *, engine: Engine, stamp: EngineStamp,
               cancel: threading.Event, run_id: str, skipped: Sequence[str] = (),
               known: Iterable[CellResult] = (), on_chunk: Callable[[tuple[CellResult, ...]], None] | None = None,
               limits: RuleLimits = LIMITS) -> MatrixRun:
    """Scan every rule against every target in chunks; `known` cells (earlier chunks of the same key) are reused.

    A chunk the engine fails on becomes `error` cells and the run goes on; a cancel leaves the rest `not-scanned`.
    Compile and availability failures abort the run (the exception propagates, nothing is half-reported).
    """
    _check_run(rules, targets, limits)
    got = {(c.rule_name, c.target_id): c for c in known if c.state in SCANNED}
    texts = tuple(RuleText(name=r.name, text=r.text) for r in rules)
    pending = [t for t in targets if any((r.name, t.ref.target_id) not in got for r in rules)]
    cancelled = False
    for start in range(0, len(pending), CHUNK_TARGETS):
        chunk = pending[start:start + CHUNK_TARGETS]
        cells = None if cancelled or cancel.is_set() else _scan_chunk(rules, chunk, texts, engine)
        if cells is None:
            cancelled = True
            cells = tuple(c for t in chunk for c in _unscanned(rules, t, 'not-scanned', _REASON_CANCELLED))
        elif on_chunk is not None:
            on_chunk(cells)
        got.update({(c.rule_name, c.target_id): c for c in cells})
    refs = {t.ref.target_id: t.ref for t in targets}
    ordered = [got[(r.name, t.ref.target_id)] for t in targets for r in rules]
    cells = _with_verdicts(ordered, {r.name: r.direction for r in rules}, refs)
    complete = all(c.state in SCANNED for c in cells) and not skipped
    status = 'cancelled' if cancelled else 'complete' if complete else 'partial'
    return MatrixRun(run_id=run_id, cache_key=cache_key(rules, targets, stamp, limits), engine=stamp, status=status,
                     targets=tuple(t.ref for t in targets), cells=tuple(cells), limits=runner.worker_limits(limits),
                     anomalies=tuple(f'Not scanned: {s}' for s in skipped))
