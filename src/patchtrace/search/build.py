"""Build orchestration (WB1 section 7 'Lifecycle'): which segments a project needs, which exist, and building the rest.

`build_request` runs on the GUI thread and snapshots the store rows into immutable `SourceSpec`s; `build_index` runs
anywhere. Every group has its own digest, so an unchanged group is reused and a changed one is rebuilt alone
(incremental == from-scratch by construction). Groups build cheap-first, one group's failure never stops the
others, and cancellation stops between and inside groups.
"""
from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Container
from dataclasses import dataclass
from pathlib import Path

from patchtrace.enrichment.identity import domain_id
from patchtrace.search import paths
from patchtrace.search.contracts import CoverageEntry
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS, SearchLimits
from patchtrace.search.segment import SegmentInfo, build_segment, open_segment
from patchtrace.search.sources.base import SourceSpec, skipped
from patchtrace.search.sources.functions import function_spec
from patchtrace.search.sources.notes import annotation_spec, finding_spec
from patchtrace.search.sources.pe import PeLoader, pe_spec
from patchtrace.search.sources.raw import raw_spec

ASM_UNAVAILABLE = ("Instruction text is not searchable: Ghidriff keeps only a hash of each function's "
                   'instructions. Run unified extraction to add it.')
TOO_LONG = 'The total index build time limit was reached; build again to continue.'
Progress = Callable[[str, int, int], None]


@dataclass(frozen=True, slots=True)
class BuildRequest:
    project_id: str
    revision: int
    root: Path
    run_id: str | None
    specs: tuple[SourceSpec, ...]

    @property
    def index_key(self) -> str:
        """Names the exact set of expected segments; changes when any group's digest changes."""
        return domain_id('search-index', 1, [(s.group, s.digest16) for s in self.specs])[:16]

    def expected(self) -> tuple[tuple[str, str], ...]:
        """(group, digest16) of every segment this request needs: the argument of `segment.collect_garbage`."""
        return tuple((s.group, s.digest16) for s in self.specs if s.digest16 is not None)


@dataclass(frozen=True, slots=True)
class BuildReport:
    coverage: tuple[CoverageEntry, ...]
    built: tuple[str, ...]
    reused: tuple[str, ...]


def build_request(service, *, run_id: str | None = None) -> BuildRequest:
    """Snapshot `service.project` (a `ProjectService`) into source specs, cheapest first."""
    project, root = service.project, Path(service.root)
    loader = PeLoader(root, {a.side: a.model_copy() for a in project.artifacts})
    artifacts = {a.side: a for a in project.artifacts}
    specs = (annotation_spec(project), finding_spec(project),
             pe_spec('older', artifacts['older'], loader), pe_spec('newer', artifacts['newer'], loader),
             function_spec(project, run_id, loader), raw_spec(project, root, run_id),
             skipped('ir', ('asm',), None, 'unavailable', ASM_UNAVAILABLE))
    return BuildRequest(project.id, project.revision, root, run_id, specs)


def segment_directory(request: BuildRequest, cache_root: Path) -> Path:
    return paths.project_dir(paths.validate_cache_root(cache_root, request.root), request.project_id)


def _entry(spec: SourceSpec, status: str, reason: str = '', info: SegmentInfo | None = None) -> CoverageEntry:
    return CoverageEntry(group=spec.group, kinds=spec.kinds, side=spec.side, status=status,
                         docs=info.docs if info else 0, reason=reason or spec.reason, digest16=spec.digest16,
                         built_utc=info.built_utc if info else None)


def _existing(directory: Path, spec: SourceSpec) -> SegmentInfo | None:
    try:
        with open_segment(paths.segment_path(directory, spec.group, spec.digest16)) as segment:
            return segment.info
    except SearchError:
        return None


def _indexed(spec: SourceSpec, info: SegmentInfo) -> CoverageEntry:
    return _entry(spec, 'truncated' if info.truncated else 'indexed', info=info)


def _on_disk(directory: Path, spec: SourceSpec) -> CoverageEntry:
    if not spec.buildable:
        return _entry(spec, spec.status)
    info = _existing(directory, spec)
    return _entry(spec, 'missing') if info is None else _indexed(spec, info)


def coverage(request: BuildRequest, cache_root: Path) -> tuple[CoverageEntry, ...]:
    """What is indexed right now, without building anything (`search --status`)."""
    directory = segment_directory(request, cache_root)
    return tuple(_on_disk(directory, spec) for spec in request.specs)


def build_index(request: BuildRequest, cache_root: Path, *, groups: Container[str] | None = None,
                rebuild: bool = False, cancel: Callable[[], bool] = lambda: False, progress: Progress | None = None,
                limits: SearchLimits = DEFAULT_LIMITS, clock: Callable[[], float] = time.monotonic) -> BuildReport:
    """Build the missing (or, with `rebuild`, all) segments of `groups` (default: all). Raises only
    `PT-SEARCH-CANCEL` and cache-root errors; a failing group is reported as `failed` and the rest continue."""
    directory = segment_directory(request, cache_root)
    started = clock()
    todo = [s for s in request.specs if s.buildable and (groups is None or s.group in groups)]
    entries: dict[str, CoverageEntry] = {}
    built, reused = [], []
    for done, spec in enumerate(todo):
        if progress:
            progress(spec.group, done, len(todo))
        if cancel():
            raise SearchError('PT-SEARCH-CANCEL', 'the index build was cancelled')
        if clock() - started >= limits.total_build_s:
            entries[spec.group] = _entry(spec, 'failed', TOO_LONG)
            continue
        info = None if rebuild else _existing(directory, spec)
        if info is not None:
            reused.append(spec.group)
        else:
            info = _build_one(spec, directory, rebuild, cancel, limits, clock)
            if isinstance(info, CoverageEntry):
                entries[spec.group] = info
                continue
            built.append(spec.group)
        entries[spec.group] = _indexed(spec, info)
    for spec in request.specs:
        entries.setdefault(spec.group, _on_disk(directory, spec))
    return BuildReport(tuple(entries[s.group] for s in request.specs), tuple(built), tuple(reused))


def _build_one(spec: SourceSpec, directory: Path, rebuild: bool, cancel, limits, clock) -> SegmentInfo | CoverageEntry:
    if rebuild:
        with contextlib.suppress(OSError):  # an open file on Windows stays; the equal digest then wins
            paths.segment_path(directory, spec.group, spec.digest16).unlink(missing_ok=True)
    try:
        return build_segment(directory, spec.group, spec.digest16, spec.documents(), spec.table_sets,
                             cancel=cancel, limits=limits, clock=clock)
    except SearchError as exc:
        if exc.code == 'PT-SEARCH-CANCEL':
            raise
        return _entry(spec, 'failed', exc.message)
    except Exception as exc:  # fault boundary: hostile source data must not stop the other groups
        return _entry(spec, 'failed', f'building this group failed ({type(exc).__name__})')
