"""The test grid of saved rules against builds (YRX-integration-plan sections 7 and 8): rule versions are the columns, builds
the rows, and every cell is what the engine said about one file, scored against what the analyst expected.

Pure orchestration. The engine runs in the hidden worker (`runner.scan`, injectable for tests), a few files per child so a
cancel or a failure keeps what was scanned. Honesty rules: a file that was not read is `not-scanned` with a reason, never
`no-hit`; a verdict exists only for a scanned cell; counts are raw numbers and are never combined into a score; records
keep hashes and display labels, never paths.

Expectations. A target's own `expect` (set by the analyst) wins. Otherwise the anchors follow the rule: an older-build rule
should match the older anchor and not the newer one, a newer-build rule the reverse. Clean files expect no match. Every
other build is unscored until the analyst says what to expect.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

from pydantic import ValidationError

from ..enrichment.identity import domain_id
from .contracts import (
    WORKER_CONTRACT,
    CellResult,
    EngineStamp,
    MatrixRun,
    PairSource,
    RuleVersion,
    RunRule,
    TargetRef,
    WorkerRule,
    WorkerTarget,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS, RuleLimits, limits_digest
from .ports import BuildEntry
from .runner import ScanOutcome
from .runner import scan as scan_worker

BATCH_FILES = 32           # files per child: about 0.5 s of start-up each from source, and a cancel keeps earlier batches
READ_CHUNK = 1024 * 1024
DIRECTION = re.compile(r'(?m)^rule PT_[0-9a-f]{12}_(older|newer)\b')
Scan = Callable[..., ScanOutcome]


def direction_of(version: RuleVersion) -> str:
    found = DIRECTION.search(version.rule_text)
    if found is None:   # RuleVersion validated the rule name; this cannot be reached with a valid record
        raise RuleError('PT-RULE-INTEGRITY', 'A rule version does not define its rule', reason='no-rule')
    return found.group(1)


# --- the builds ------------------------------------------------------------------------------------------------------

def _digest(path: Path) -> tuple[str, int]:
    sha, size = hashlib.sha256(), 0
    try:
        with open(path, 'rb') as handle:
            while chunk := handle.read(READ_CHUNK):
                sha.update(chunk)
                size += len(chunk)
    except OSError:
        raise RuleError('PT-RULE-INPUT', 'A file of the test could not be read', reason='unreadable-input') from None
    return sha.hexdigest(), size


def _files(folder: Path, cap: int, what: str) -> list[Path]:
    """The regular files directly in `folder` by name; links are skipped, not followed."""
    try:
        found = sorted(p for p in folder.iterdir() if p.is_file() and not p.is_symlink())
    except OSError:
        raise RuleError('PT-RULE-INPUT', f'The {what} folder could not be read', reason='folder-unreadable') from None
    if len(found) > cap:
        raise RuleError('PT-RULE-LIMIT', f'The {what} folder holds more than {cap} files', reason=what)
    return found


def _label(path: Path) -> str:
    return path.name[:256] or 'file'


class Anchor(NamedTuple):
    """The local file of one build of the pair and the name to show for it (the project's name for the artifact)."""
    path: Path
    label: str


def gather(pair: PairSource, anchors: Mapping[str, Anchor], *, series: Path | None = None, extra: Iterable[Path] = (),
           clean_dir: Path | None = None, expect: Mapping[str, str] | None = None,
           limits: RuleLimits = DEFAULT_LIMITS) -> tuple[tuple[BuildEntry, ...], tuple[str, ...]]:
    """The rows of a grid: the two anchors of the pair, the series (anchors found among its files keep their role),
    extra builds and the clean files. A file whose content is already a row is not added twice (shared content counts once);
    the second spelling is reported in the notes. `expect` maps a SHA-256 or a display label to `hit`/`no-hit`/`unknown`."""
    extras = list(extra)
    if len(extras) > limits.extra_targets:
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.extra_targets} extra builds', reason='extra')
    planned = [('older-anchor' if side == 'older' else 'newer-anchor', anchors[side].path, anchors[side].label)
               for side in ('older', 'newer') if side in anchors]
    planned += [('series', p, _label(p)) for p in (_files(series, limits.series_targets, 'series') if series else ())]
    planned += [('extra', p, _label(p)) for p in extras]
    planned += [('clean', p, _label(p)) for p in (_files(clean_dir, limits.clean_targets, 'clean') if clean_dir else ())]
    entries, notes, seen, ordinal = [], [], {}, 0
    for role, path, label in planned:
        sha, size = _digest(path)
        if sha in seen:   # the series folder usually holds the anchors again; any other repeat is worth a note
            if not (role == 'series' and seen[sha].endswith('-anchor')):
                notes.append(f'same-content:{label}')
            continue
        role = {pair.older_sha256: 'older-anchor', pair.newer_sha256: 'newer-anchor'}.get(sha, role)
        if role in ('series', 'older-anchor', 'newer-anchor'):
            ordinal += 1
            if ordinal > limits.series_targets:
                raise RuleError('PT-RULE-LIMIT', f'More than {limits.series_targets} series builds', reason='series')
        seen[sha] = role
        entries.append(BuildEntry(_target(f'b{len(entries) + 1:04d}', role, label, sha, size, ordinal, expect or {}),
                                  str(path.resolve())))
    if len(entries) > limits.targets_per_run:
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.targets_per_run} files in one run', reason='targets')
    return tuple(entries), tuple(notes)


def _target(target_id: str, role: str, label: str, sha: str, size: int, ordinal: int, expect: Mapping[str, str]
            ) -> TargetRef:
    given = expect.get(sha, expect.get(label, 'no-hit' if role == 'clean' else 'unknown'))
    try:
        return TargetRef(target_id=target_id, label=label, role=role, sha256=sha, size=size,
                         ordinal=ordinal if role in ('series', 'older-anchor', 'newer-anchor') else None, expect=given)
    except ValidationError:
        raise RuleError('PT-RULE-INPUT', 'A file or an expectation of the test is not valid', reason='bad-target') from None


def read_expectations(path: Path) -> dict[str, str]:
    """`{"<sha256 or file name>": "hit" | "no-hit" | "unknown"}` from a small JSON file."""
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise RuleError('PT-RULE-INPUT', 'The expectations file could not be read as JSON', reason='expect-file') from None
    if not isinstance(data, dict) or not all(isinstance(k, str) and v in ('hit', 'no-hit', 'unknown')
                                             for k, v in data.items()):
        raise RuleError('PT-RULE-INPUT', 'The expectations file maps a file name or SHA-256 to hit, no-hit or unknown',
                        reason='expect-shape')
    return data


# --- scoring ---------------------------------------------------------------------------------------------------------

def expected(direction: str, target: TargetRef) -> str:
    if target.expect != 'unknown':
        return target.expect
    if target.role in ('older-anchor', 'newer-anchor'):
        return 'hit' if target.role.startswith(direction) else 'no-hit'
    return 'unknown'


def verdict(cell: CellResult, wanted: str) -> str:
    """Only a scanned cell is scored; a file that was not scanned is never a miss."""
    if cell.state not in ('hit', 'no-hit') or wanted == 'unknown':
        return 'unscored'
    if (cell.state == 'hit') == (wanted == 'hit'):
        return 'as-expected'
    return 'unexpected-hit' if cell.state == 'hit' else 'unexpected-miss'


def score(cells: Sequence[CellResult], targets: Sequence[TargetRef], directions: Sequence[str]) -> tuple[CellResult, ...]:
    """Row-major `cells` with the verdicts of the targets' expectations."""
    width = len(directions)
    return tuple(cell.model_copy(update={'verdict': verdict(cell, expected(directions[i % width], targets[i // width]))})
                 for i, cell in enumerate(cells))


def rescored(run: MatrixRun, targets: Sequence[TargetRef], versions: Sequence[RuleVersion]) -> MatrixRun:
    """A stored run with the current expectations (the cache key does not cover them)."""
    cells = score(run.cells, targets, [direction_of(v) for v in versions])
    return run.model_copy(update={'targets': tuple(targets), 'cells': cells})


def cache_key(versions: Sequence[RuleVersion], targets: Sequence[TargetRef], engine_version: str, timeout_s: int,
              limits: RuleLimits = DEFAULT_LIMITS) -> str:
    """Hashes only, never paths. Expectations are not part of it: they change the verdict, not what the engine said."""
    return domain_id('rule-test', 1, {'rules': sorted(v.rule_sha256 for v in versions),
                                      'targets': sorted(t.sha256 for t in targets), 'engine': engine_version,
                                      'worker': WORKER_CONTRACT, 'limits': limits_digest(limits), 'timeout': timeout_s})


# --- running ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Totals:
    """Raw counts of one rule's column. `not_scanned` includes timeouts and errors: nothing was learned from those files."""
    match: int
    no_match: int
    not_scanned: int
    unexpected_hit: int
    unexpected_miss: int
    builds: int
    clean: int


def totals(run: MatrixRun, column: int) -> Totals:
    width = len(run.rules)
    cells = run.cells[column::width]
    states = Counter(c.state for c in cells)
    verdicts = Counter(c.verdict for c in cells)
    clean = sum(t.role == 'clean' for t in run.targets)
    return Totals(states['hit'], states['no-hit'], len(cells) - states['hit'] - states['no-hit'],
                  verdicts['unexpected-hit'], verdicts['unexpected-miss'], len(run.targets) - clean, clean)


def _not_scanned(count: int, reason: str) -> list[CellResult]:
    return [CellResult(state='not-scanned', reason=reason) for _ in range(count)]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec='seconds')


def run_matrix(entries: Sequence[BuildEntry], versions: Sequence[RuleVersion], *, scan: Scan = scan_worker,
               timeout_s: int | None = None, cancel: threading.Event | None = None,
               limits: RuleLimits = DEFAULT_LIMITS, now: Callable[[], str] = _now, batch: int = BATCH_FILES
               ) -> MatrixRun:
    """Scan every build against every rule, `batch` files per worker. A cancel between batches keeps the finished cells and
    marks the rest `not-scanned` (`cancelled`); any other worker failure raises, because a partial grid with a hole in it
    would read as a result."""
    if not entries or not versions:
        raise RuleError('PT-RULE-INPUT', 'A test needs at least one rule and one file', reason='empty-request')
    rules = tuple(WorkerRule(name=v.version_id, text=v.rule_text) for v in versions)
    targets = [entry.target for entry in entries]
    timeout = limits.target_timeout_s if timeout_s is None else timeout_s
    cells: list[CellResult] = []
    engine: EngineStamp | None = None
    cancelled = False
    for start in range(0, len(entries), batch):
        chunk = entries[start:start + batch]
        if cancel is not None and cancel.is_set():
            cancelled = True
            break
        sent = [WorkerTarget(target_id=e.target.target_id, path=e.path, sha256=e.target.sha256, size=e.target.size)
                for e in chunk]
        try:
            outcome = scan(rules, sent, timeout_s=timeout_s, cancel=cancel, limits=limits)
        except RuleError as error:
            if error.code != 'PT-RULE-CANCEL':
                raise
            cancelled = True
            break
        bad = [lint for lint in outcome.lint if not lint.ok]
        if bad:
            raise RuleError('PT-RULE-COMPILE', 'A saved rule no longer compiles with this engine', reason='lint')
        engine = engine or outcome.engine
        cells.extend(outcome.cells)
    if engine is None:
        raise RuleError('PT-RULE-CANCEL', 'Rule work was cancelled', reason='cancelled')
    cells.extend(_not_scanned(len(entries) * len(versions) - len(cells), 'cancelled'))
    cells = list(score(cells, targets, [direction_of(v) for v in versions]))
    unread = Counter(c.reason or c.state for c in cells if c.state not in ('hit', 'no-hit'))
    anomalies = tuple(f'{count} cells not scanned: {reason}' for reason, count in sorted(unread.items())
                      if reason != 'cancelled')[:64]
    status = 'cancelled' if cancelled else 'partial' if any(c.state not in ('hit', 'no-hit') for c in cells) else 'complete'
    finished = now()
    key = cache_key(versions, targets, engine.version, timeout, limits)
    return MatrixRun(
        run_id='test-' + domain_id('rule-test-run', 1, {'cache_key': key, 'finished_at': finished})[:24],
        cache_key=key, engine=engine, status=status,
        rules=tuple(RunRule(version_id=v.version_id, rule_sha256=v.rule_sha256) for v in versions),
        targets=tuple(targets), cells=tuple(cells),
        limits={**limits.as_dict(), 'target_timeout_s': timeout}, anomalies=anomalies, finished_at=finished)
