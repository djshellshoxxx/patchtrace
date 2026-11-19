"""Tier-W runner (SPEC-33 s9): every pair through PatchTrace's own Ghidriff path, 1:1 matches as `tier-w-matches/1`.

Per pair and condition (`symbols-hidden` -> `h`, `symbols-visible` -> `v`) a PatchTrace project is made from the local
binaries at `Layout.run_dir(...)/project` and run through `patchtrace.cli._run_pair`, the backend/apply path the desktop
and `series` use. A project that already holds a completed or identical run is reused, not re-run. Only `v` allows
symbol downloads. Secondary engines run once per pair in the `h` project (condition `n/a`). Extraction keeps one-to-one
rows whose RVAs lie in [0, SizeOfImage) of the local PE and counts every other row by reason. One failing pair never
stops the run; the CANCEL file or the cancel event stops it before the next step (and inside a running engine, which
polls it). Engines sit behind Protocols, so tests need no Ghidra; nothing here opens a socket or executes a target.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, get_args

from pydantic import ValidationError

from patchtrace import owned_publication as owned
from patchtrace.enrichment.identity import parse_address
from patchtrace.hostile_text import escape_text
from patchtrace.secondary.contracts import Engine, SecondaryMatchSet

from .contracts import (
    DOC_LIMIT,
    MatchLine,
    PairBinary,
    PairEntry,
    PairsDoc,
    RunCell,
    RunProblem,
    RunRecord,
    load_run_record,
)
from .fetch import cancelled
from .labels import match_id
from .paths import TIER, Layout, TierWError, check_corpus_id, dumps, inside, tool_safe_path
from .pe_tables import PeTableError, PeView

GHIDRIFF = 'ghidriff'
HIDDEN, VISIBLE, NA = 'symbols-hidden', 'symbols-visible', 'n/a'
CONDITIONS = (HIDDEN, VISIBLE)
SECONDARY_ENGINES = frozenset(get_args(Engine))
SKIP_CATEGORIES = frozenset({'split', 'merged', 'ambiguous', 'added', 'removed'})
DONE = frozenset({'completed', 'identical'})
RUN_RECORD = 'run.json'
MESSAGE_LIMIT = 300
VERSION_LIMIT = 200
ADDRESS_TEXT_LIMIT = 40
MATCHES_LIMIT = 1024 * 1024 * 1024
HISTORY = '.tier-w-run-history'


class Cancel(Protocol):
    def is_set(self) -> bool: ...


class ProjectFactory(Protocol):
    def __call__(self, older: Path, newer: Path, name: str, root: Path) -> object: ...


class PairInvoker(Protocol):
    def __call__(self, config: object, project_dir: Path, cancel: Cancel) -> str | None: ...


class SecondaryInvoker(Protocol):
    def __call__(self, project_dir: Path) -> SecondaryMatchSet: ...


ConfigFactory = Callable[[str], object]


def backend_configs(python: str, ghidra_dir: str, timeout: int = 3600) -> ConfigFactory:
    """One `BackendConfig` per condition; only symbols-visible may download symbols (spec s9)."""
    from patchtrace.backend import BackendConfig

    def build(condition: str) -> BackendConfig:
        return BackendConfig(python_executable=python, ghidra_dir=ghidra_dir, timeout_seconds=timeout,
                             allow_symbol_downloads=condition == VISIBLE)
    return build


def create_project(older: Path, newer: Path, name: str, root: Path) -> None:
    from patchtrace.service import ProjectService
    ProjectService.create(older, newer, name, root).close()


def run_pair(config, project_dir: Path, cancel: Cancel) -> str | None:
    from patchtrace.cli import _run_pair
    return _run_pair(config, project_dir, cancel)


class _Skip(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class _Outcome(Exception):
    def __init__(self, outcome: str, message: str):
        super().__init__(message)
        self.outcome = outcome


@dataclass(frozen=True)
class _Image:
    sha256: str
    base: int
    size: int


def _image(path: Path, sha256: str) -> _Image:
    with PeView(path, sha256) as view:
        if not view.size_of_image:
            raise PeTableError(f'{path.name} has no SizeOfImage')
        return _Image(sha256, view.image_base, view.size_of_image)


def _text(value: object, limit: int = MESSAGE_LIMIT) -> str:
    return escape_text(str(value)[:limit])[:limit] or '?'


def _rva(address: int, image: _Image, subtract: bool) -> int:
    rva = address - image.base if subtract else address
    if not 0 <= rva < image.size:
        raise _Skip('out-of-image')
    return rva


def _virtual(function) -> int:
    text = function.address
    value = parse_address(text) if text is not None and len(text) <= ADDRESS_TEXT_LIMIT else None
    if value is None:
        raise _Skip('no-address')
    if function.address_space != 'virtual':
        raise _Skip('address-space')
    return value


def _ghidriff_rvas(match, older: _Image, newer: _Image) -> tuple[int, int]:
    if match.category in SKIP_CATEGORIES:
        raise _Skip(match.category)
    if len(match.older) != 1 or len(match.newer) != 1:
        raise _Skip('not-one-to-one')
    va_older, va_newer = _virtual(match.older[0]), _virtual(match.newer[0])
    return _rva(va_older, older, True), _rva(va_newer, newer, True)


def _secondary_rvas(row, older: _Image, newer: _Image, subtract: bool) -> tuple[int, int]:
    if row.older_address is None or row.newer_address is None:
        raise _Skip('one-sided')
    return _rva(row.older_address, older, subtract), _rva(row.newer_address, newer, subtract)


def _rows(items: Iterable, convert: Callable[..., tuple[int, int]], *args) -> list[tuple[int, int] | str]:
    out: list[tuple[int, int] | str] = []
    for item in items:
        try:
            out.append(convert(item, *args))
        except _Skip as skip:
            out.append(skip.reason)
    return out


def _snapshot(project_dir: Path, images: tuple[_Image, _Image]):
    from patchtrace.service import ProjectService
    service = ProjectService.open(project_dir, maintenance=False)
    try:
        project = service.project
    finally:
        service.close()
    sides = {a.side: a.sha256 for a in project.artifacts}
    if (sides['older'], sides['newer']) != (images[0].sha256, images[1].sha256):
        raise _Outcome('failed', 'project inputs differ from the pair (older/newer hash or orientation)')
    if project.sample:
        raise _Outcome('blocked', 'a demonstration project cannot supply Tier-W engine evidence')
    return project


def _eligible_runs(snapshot, images: tuple[_Image, _Image], condition: str) -> list:
    policy, downloads = ('online', True) if condition == VISIBLE else ('disabled', False)
    return [run for run in snapshot.runs if run.status == 'completed' and run.backend == GHIDRIFF
            and run.settings.get('older_sha256') == images[0].sha256
            and run.settings.get('newer_sha256') == images[1].sha256
            and run.settings.get('symbol_policy') == policy
            and run.settings.get('allow_symbol_downloads') is downloads
            and run.settings.get('symbol_mode', 'online' if downloads else 'off') ==
            ('online' if downloads else 'off')]


class _Stop:
    """The cancel view engines poll: the caller's event or the CANCEL file. Once seen it stays set."""

    def __init__(self, event: threading.Event, layout: Layout):
        self.event, self.layout, self.hit = event, layout, False

    def is_set(self) -> bool:
        self.hit = self.hit or self.event.is_set() or cancelled(self.layout)
        return self.hit

    def set(self) -> None:
        self.event.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self.event.wait(timeout) or self.is_set()


class _Run:
    def __init__(self, layout: Layout, corpus_id: str, keys: Sequence[tuple[str, str]], stop: _Stop,
                 config_factory: ConfigFactory, factory: ProjectFactory, invoker: PairInvoker,
                 secondary: Mapping[str, SecondaryInvoker]):
        self.layout, self.corpus_id, self.keys, self.stop = layout, corpus_id, keys, stop
        self.config_factory, self.factory, self.invoker, self.secondary = config_factory, factory, invoker, secondary
        self.counts = {key: Counter() for key in keys}
        self.skipped = {key: Counter() for key in keys}
        self.lines: dict[tuple, MatchLine] = {}
        self.problems: list[RunProblem] = []

    def project(self, pair: PairEntry, condition: str, files: tuple[Path, Path]) -> Path:
        project = self.layout.run_dir(self.corpus_id, pair.id, condition) / 'project'
        if not (project / 'project.sqlite3').is_file():
            self.factory(files[0], files[1], f'{pair.id} {condition}', project)
        return project

    def ghidriff(self, pair, condition, files, images) -> tuple[str, list]:
        project = self.project(pair, condition, files)
        snapshot = _snapshot(project, images)
        if images[0].sha256 == images[1].sha256 and any(run.status == 'identical' for run in snapshot.runs):
            return 'not-run-identical', []
        done = _eligible_runs(snapshot, images, condition)
        if not done:
            if any(run.status in DONE for run in snapshot.runs):
                raise _Outcome('blocked', 'stored completed runs lack matching backend, input or symbol-policy evidence')
            error = self.invoker(self.config_factory(condition), project, self.stop)
            if error:
                raise _Outcome('failed', error)
            snapshot = _snapshot(project, images)
            done = _eligible_runs(snapshot, images, condition)
        if not done:
            raise _Outcome('failed', 'the engine returned without a completed run with matching provenance')
        selected = done[-1]  # preserve stored run order; never pool historical engine generations
        matches = [m for m in snapshot.matches if m.run_id == selected.id]
        return selected.backend_version, _rows(matches, _ghidriff_rvas, *images)

    def secondary_set(self, engine, pair, files, images) -> tuple[str, list]:
        invoker = self.secondary.get(engine)
        if invoker is None:
            raise _Outcome('blocked', f'no {engine} invoker is configured')
        result = invoker(self.project(pair, HIDDEN, files))
        if not isinstance(result, SecondaryMatchSet) or result.engine != engine:
            raise _Outcome('failed', f'{engine} returned no {engine} match set')
        if (result.older_sha256, result.newer_sha256) != (images[0].sha256, images[1].sha256):
            raise _Outcome('failed', f'{engine} match set differs from the pair (older/newer hash or orientation)')
        if result.image_base_subtracted == 'unknown':
            return result.engine_version, ['image-base-unknown'] * len(result.matches)
        subtract = result.image_base_subtracted == 'no'
        return result.engine_version, _rows(result.matches, _secondary_rvas, *images, subtract)

    def pair(self, pair: PairEntry, older: PairBinary, newer: PairBinary) -> None:
        files = tuple(self.layout.root / 'binaries' / b.sha256 / b.file_name for b in (older, newer))
        absent = [side for side, path in zip(('older', 'newer'), files, strict=True) if not path.is_file()]
        images: tuple[_Image, _Image] | Exception | None = None
        for key in self.keys:
            if self.stop.is_set():
                self.counts[key]['cancelled'] += 1
                continue
            try:
                if absent:
                    raise _Outcome('blocked', f'{" and ".join(absent)} binary missing under binaries/<sha256>/')
                if images is None:
                    try:
                        images = (_image(files[0], older.sha256), _image(files[1], newer.sha256))
                    except PeTableError as exc:
                        images = exc
                if isinstance(images, Exception):
                    raise _Outcome('failed', str(images))
                engine, condition = key
                version, rows = (self.ghidriff(pair, condition, files, images) if engine == GHIDRIFF
                                 else self.secondary_set(engine, pair, files, images))
            except Exception as exc:  # noqa: BLE001 - one failing pair never stops the run
                outcome = exc.outcome if isinstance(exc, _Outcome) else 'failed'
                if outcome == 'failed' and self.stop.is_set():
                    self.counts[key]['cancelled'] += 1
                    continue
                message = str(exc) if isinstance(exc, _Outcome) else f'{type(exc).__name__}: {exc}'
                self.counts[key][outcome] += 1
                self.problems.append(RunProblem(pair=pair.id, engine=key[0], condition=key[1], outcome=outcome,
                                                message=_text(message)))
                continue
            self.record(key, pair, _text(version, VERSION_LIMIT), rows)

    def record(self, key: tuple[str, str], pair: PairEntry, version: str, rows: list) -> None:
        engine, condition = key
        for row in rows:
            if isinstance(row, str):
                self.skipped[key][row] += 1
                continue
            identity = (pair.id, engine, condition, *row)
            if identity in self.lines:
                self.skipped[key]['duplicate'] += 1
                continue
            self.lines[identity] = MatchLine(contract='tier-w-matches/1', tier=TIER, pair=pair.id, engine=engine,
                                             engine_version=version, condition=condition, match_id=match_id(*row),
                                             older_rva=row[0], newer_rva=row[1])
            self.counts[key]['matches'] += 1
        self.counts[key]['ok'] += 1

    def cells(self) -> tuple[RunCell, ...]:
        return tuple(RunCell(engine=engine, condition=condition, attempted=c['ok'] + c['failed'], ok=c['ok'],
                             failed=c['failed'], blocked=c['blocked'], cancelled=c['cancelled'], matches=c['matches'],
                             skipped=dict(sorted(self.skipped[(engine, condition)].items())))
                     for (engine, condition), c in sorted(self.counts.items()))


def _status(cells: Sequence[RunCell]) -> str:
    if any(c.cancelled for c in cells):
        return 'cancelled'
    if not any(c.failed or c.blocked for c in cells):
        return 'ok'
    return 'blocked' if not any(c.ok or c.failed for c in cells) else 'partial'


def _validated(doc: PairsDoc, corpus_id: str, conditions: Sequence[str],
               engines: Sequence[str]) -> list[tuple[PairEntry, PairBinary, PairBinary]]:
    check_corpus_id(corpus_id)
    try:
        if not isinstance(doc, PairsDoc):
            raise ValueError('not a pairs document')
        doc = PairsDoc.model_validate(doc.model_dump(mode='python'))
    except (ValidationError, ValueError):
        raise TierWError('PT-TIERW-INPUT', 'the pairs sidecar is not valid') from None
    if doc.corpus_id != corpus_id:
        raise TierWError('PT-TIERW-INPUT', 'the pairs sidecar belongs to another corpus id')
    if bad := sorted(set(conditions) - set(CONDITIONS)):
        raise TierWError('PT-TIERW-INPUT', f'unknown condition {_text(bad[0], 64)}; use {" or ".join(CONDITIONS)}')
    if bad := sorted(set(engines) - SECONDARY_ENGINES):
        raise TierWError('PT-TIERW-INPUT', f'unknown secondary engine {_text(bad[0], 64)}')
    if not conditions and not engines:
        raise TierWError('PT-TIERW-INPUT', 'select at least one engine and condition')
    by_id = {b.id: b for b in doc.binaries}
    if len(by_id) != len(doc.binaries):
        raise TierWError('PT-TIERW-INPUT', 'binary ids in the pairs sidecar must be unique')
    out, seen = [], set()
    for pair in sorted(doc.pairs, key=lambda p: p.id):
        if not pair.id.startswith('tw.') or pair.id in seen:
            raise TierWError('PT-TIERW-INPUT', f'pair id {_text(pair.id, 64)} is duplicated or lacks the tw. prefix')
        sides = [by_id.get(pair.older), by_id.get(pair.newer)]
        if None in sides or any(not b.file_name.strip('.') for b in sides):
            raise TierWError('PT-TIERW-INPUT', f'pair {pair.id} names a missing or unsafe binary entry')
        seen.add(pair.id)
        out.append((pair, *sides))
    return out


def _ordinary_output_parent(path: Path) -> None:
    # Preserve lexical components: collapsing link/../leaf before checking a link can select another directory.
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:-1]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise TierWError('PT-TIERW-CONFIG', 'runner output parent is unreadable') from None
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                getattr(info, 'st_file_attributes', 0) & 0x400):
            raise TierWError('PT-TIERW-CONFIG', 'runner output parent is linked, reparse or not a directory')


def _output_admission(layout: Layout, corpus_id: str, pairs: Sequence, conditions: set[str],
                      matches_path: Path) -> None:
    _ordinary_output_parent(matches_path)
    outputs = (matches_path, matches_path.with_name(RUN_RECORD))
    if (not inside(matches_path.parent, layout.root) or matches_path.name.casefold() == RUN_RECORD or
            HISTORY in (part.casefold() for part in matches_path.parts)):
        raise TierWError('PT-TIERW-CONFIG', 'matches and run.json must be distinct files under the corpus root')
    inputs = [layout.root / 'binaries' / binary.sha256 / binary.file_name
              for _pair, older, newer in pairs for binary in (older, newer)]
    projects = [layout.run_dir(corpus_id, pair.id, condition) / 'project'
                for pair, _older, _newer in pairs for condition in conditions]
    for output in outputs:
        if (output.is_symlink() or output.is_dir() or inside(output, layout.root / 'binaries') or
                output.resolve() == layout.cancel_file.resolve() or any(inside(output, project) for project in projects)):
            raise TierWError('PT-TIERW-CONFIG', 'runner output aliases a protected input, project or linked path')
        if output.exists() and any(source.exists() and output.samefile(source) for source in inputs):
            raise TierWError('PT-TIERW-CONFIG', 'runner output aliases an input binary')
    if all(output.exists() for output in outputs) and outputs[0].samefile(outputs[1]):
        raise TierWError('PT-TIERW-CONFIG', 'matches and run.json alias the same file')


@dataclass(frozen=True)
class _OutputFile:
    path: Path
    raw: bytes
    identity: tuple[int, int]


class _PublicationCancelled(Exception):
    pass


def _capture_output(path: Path, maximum: int) -> _OutputFile | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    raw = owned.read_bytes(path, maximum=maximum)
    after = path.lstat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise TierWError('PT-TIERW-VERIFY', 'runner output changed while reading')
    return _OutputFile(path, raw, owned.file_identity(after))


def _prior_outputs(matches: Path, corpus_id: str) -> dict[Path, _OutputFile | None]:
    paths = (matches, matches.with_name(RUN_RECORD))
    try:
        previous = {path: _capture_output(path, maximum) for path, maximum in
                    zip(paths, (MATCHES_LIMIT, DOC_LIMIT), strict=True)}
        rows, summary = previous.values()
        if rows is None and summary is None:
            return previous
        if rows is None or summary is None:
            raise TierWError('PT-TIERW-VERIFY', 'runner outputs are incomplete; preserve and recover the prior pair')
        record = load_run_record(summary.raw)
        if record.corpus_id != corpus_id or record.matches_sha256 != hashlib.sha256(rows.raw).hexdigest():
            raise TierWError('PT-TIERW-VERIFY', 'runner outputs have foreign corpus ownership or a mismatched digest')
        for path, expected in previous.items():
            _assert_output(path, expected)
        return previous
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-VERIFY', 'prior runner outputs are unreadable or changed') from None


def _assert_output(path: Path, expected: _OutputFile | None) -> None:
    observed = _capture_output(path, len(expected.raw) if expected is not None else 0)
    if observed != expected:
        raise TierWError('PT-TIERW-VERIFY', 'runner output identity or bytes changed before publication')


def _exact_bytes(expected: bytes):
    def validate(raw: bytes) -> None:
        if raw != expected:
            raise TierWError('PT-TIERW-VERIFY', 'retained runner output has conflicting bytes')
    return validate


def _retain_outputs(anchor: owned.DirectoryAnchor, rows: bytes, summary: bytes) -> None:
    folder = anchor.path / HISTORY / hashlib.sha256(summary).hexdigest()
    for name, raw in (('matches.jsonl', rows), (RUN_RECORD, summary)):
        owned.publish_bytes(folder / name, raw, maximum=len(raw), validate_existing=_exact_bytes(raw), anchor=anchor)
    # A receipt is usable only while both retained names still carry the intended bytes.
    for name, raw in (('matches.jsonl', rows), (RUN_RECORD, summary)):
        owned.read_bytes(folder / name, maximum=len(raw), validate=_exact_bytes(raw), anchor=anchor)


def _stage_output(path: Path, raw: bytes, anchor: owned.DirectoryAnchor) -> _OutputFile:
    owned.publish_bytes(path, raw, anchor=anchor)
    result = _capture_output(path, len(raw))
    if result is None or result.raw != raw:
        raise TierWError('PT-TIERW-VERIFY', 'runner output staging bytes changed')
    return result


def _replace_output(stage: _OutputFile, target: Path, previous: _OutputFile | None) -> None:
    _assert_output(target, previous)
    _assert_output(stage.path, stage)
    os.replace(stage.path, target)
    _assert_output(target, _OutputFile(target, stage.raw, stage.identity))


def _restore_outputs(previous: dict[Path, _OutputFile | None], planned: dict[Path, _OutputFile],
                     pending: owned.DirectoryAnchor, anchor: owned.DirectoryAnchor, primary: BaseException) -> bool:
    restored = True
    for index, (target, old) in enumerate(previous.items()):
        if old is None:
            continue  # No prior artifact to restore; never unlink an ambiguous failed publication.
        try:
            owned.verify_anchor(anchor)
            current = _capture_output(target, max(len(old.raw), len(planned[target].raw)))
            if current == old:
                continue
            if current is None:
                owned.publish_bytes(target, old.raw, anchor=anchor)
            elif current == planned[target]:
                owned.verify_anchor(pending)
                restore = _stage_output(pending.path / f'restore-{index}', old.raw, pending)
                _replace_output(restore, target, current)
            else:
                raise TierWError('PT-TIERW-VERIFY', 'runner output changed outside this publication attempt')
        except BaseException:
            restored = False
    if restored:
        try:
            for target, old in previous.items():
                if old is not None:
                    owned.read_bytes(target, maximum=len(old.raw), validate=_exact_bytes(old.raw), anchor=anchor)
        except BaseException:
            restored = False
    if not restored:
        primary.add_note('Tier-W output restoration failed; the previous pair is retained in .tier-w-run-history.')
    return restored


def _select_outputs(previous: dict[Path, _OutputFile | None], rows: bytes, summary: bytes,
                    anchor: owned.DirectoryAnchor, stop: _Stop) -> None:
    for path, expected in previous.items():
        _assert_output(path, expected)
    if not any(previous.values()):
        published = [_stage_output(path, raw, anchor)
                     for path, raw in zip(previous, (rows, summary), strict=True)]
        for output in published:
            _assert_output(output.path, output)
        owned.verify_anchor(anchor)
        return
    pending = Path(tempfile.mkdtemp(prefix='.tier-w-pending-', dir=anchor.path))
    pending_anchor = owned.directory_anchor(pending)
    stages = {path: _stage_output(pending / str(index), raw, pending_anchor)
              for index, (path, raw) in enumerate(zip(previous, (rows, summary), strict=True))}
    planned = {path: _OutputFile(path, stage.raw, stage.identity) for path, stage in stages.items()}
    try:
        for path, stage in stages.items():
            if stop.is_set():
                raise _PublicationCancelled
            owned.verify_anchor(anchor)
            owned.verify_anchor(pending_anchor)
            _replace_output(stage, path, previous[path])
        if stop.is_set():
            raise _PublicationCancelled
        for path, expected in planned.items():
            _assert_output(path, expected)
        owned.verify_anchor(anchor)
    except BaseException as exc:
        restored = _restore_outputs(previous, planned, pending_anchor, anchor, exc)
        if not restored and isinstance(exc, _PublicationCancelled):
            raise TierWError('PT-TIERW-VERIFY', 'cancelled output publication needs recovery from retained history') from exc
        raise


def _matches_bytes(state: _Run) -> bytes:
    result = bytearray()
    for key in sorted(state.lines):
        line = (json.dumps(state.lines[key].model_dump(mode='json'), sort_keys=True, ensure_ascii=False,
                           allow_nan=False) + '\n').encode()
        if len(result) + len(line) > MATCHES_LIMIT:
            raise TierWError('PT-TIERW-LIMIT', 'runner matches exceed the 1 GiB output budget')
        result.extend(line)
    return bytes(result)


def run_corpus(layout: Layout, pairs_doc: PairsDoc, *, corpus_id: str, conditions: Sequence[str] = (HIDDEN,),
               secondary_engines: Sequence[str] = (), config_factory: ConfigFactory,
               factory: ProjectFactory = create_project, invoker: PairInvoker = run_pair,
               secondary: Mapping[str, SecondaryInvoker] | None = None, matches_path: Path,
               cancel: threading.Event | None = None) -> RunRecord:
    """Run pairs and retain a complete generation before selecting matches and run.json.

    The returned record describes this attempt; a cancelled rerun leaves the previous selected pair intact.
    Selected filenames are individually replaced, with bounded ownership checks and recoverable prior evidence.
    """
    pairs = _validated(pairs_doc, corpus_id, conditions, secondary_engines)
    matches_path = Path(matches_path)
    keys = [(GHIDRIFF, c) for c in CONDITIONS if c in conditions] + [(e, NA) for e in sorted(set(secondary_engines))]
    used = set(conditions) | ({HIDDEN} if secondary_engines else set())
    _output_admission(layout, corpus_id, pairs, used, matches_path)
    previous = _prior_outputs(matches_path, corpus_id)
    for pair, _older, _newer in pairs:
        for condition in sorted(used):
            if problems := tool_safe_path(layout.run_dir(corpus_id, pair.id, condition) / 'project'):
                raise TierWError('PT-TIERW-CONFIG', problems[0])
    state = _Run(layout, corpus_id, keys, _Stop(cancel or threading.Event(), layout), config_factory, factory,
                 invoker, secondary or {})
    for pair, older, newer in pairs:
        state.pair(pair, older, newer)
    rows = _matches_bytes(state)
    cells = state.cells()
    record = RunRecord(contract='tier-w-run/1', tier=TIER, corpus_id=corpus_id,
                       status='cancelled' if state.stop.is_set() else _status(cells),
                       pairs=len(pairs), matches_sha256=hashlib.sha256(rows).hexdigest(),
                       cells=cells, problems=tuple(state.problems))
    summary = dumps(record.model_dump(mode='json'))
    if len(summary) > DOC_LIMIT:
        raise TierWError('PT-TIERW-LIMIT', 'runner summary exceeds the 64 MiB output budget')
    matches_path.parent.mkdir(parents=True, exist_ok=True)
    anchor = owned.directory_anchor(matches_path.parent)
    for path, expected in previous.items():
        _assert_output(path, expected)
    prior_rows, prior_summary = previous.values()
    if prior_rows is not None and prior_summary is not None:
        _retain_outputs(anchor, prior_rows.raw, prior_summary.raw)
    _retain_outputs(anchor, rows, summary)
    for path, expected in previous.items():
        _assert_output(path, expected)
    if state.stop.is_set() and record.status != 'cancelled':
        record = record.model_copy(update={'status': 'cancelled'})
        summary = dumps(record.model_dump(mode='json'))
        _retain_outputs(anchor, rows, summary)
    if record.status == 'cancelled' and prior_rows is not None:
        return record
    if prior_rows is not None and prior_summary is not None and (rows, summary) == (prior_rows.raw, prior_summary.raw):
        return record
    try:
        _select_outputs(previous, rows, summary, anchor, state.stop)
    except _PublicationCancelled:
        record = record.model_copy(update={'status': 'cancelled'})
        _retain_outputs(anchor, rows, dumps(record.model_dump(mode='json')))
    return record
