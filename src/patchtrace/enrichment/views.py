"""Immutable, ownership-checked views of one completed run (SPEC-07 §4-5).

Detectors never see the mutable project aggregate. `build_views` validates that
each function belongs to the run and to the artifact of its side, derives the
deterministic diff/occurrence/pairing identities, and freezes code into tuples.
Missing decompiled code stays None so detectors can report `unavailable`.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from ..alignment import diff_hunks
from ..models import ComparisonProject, FunctionMatch, FunctionRecord
from . import identity
from .contracts import EnrichmentError, SourceLocation

MAX_LINES = 20_000
MAX_CHARS = 2_000_000


@dataclass(frozen=True)
class FunctionView:
    id: str
    artifact_id: str
    run_id: str
    side: str
    name: str
    address: int | None
    code: tuple[str, ...] | None
    assembly: tuple[str, ...] | None
    truncated: bool

    def location(self, start: int, end: int, representation: str = 'decompiled') -> SourceLocation:
        """1-based inclusive location with the exact excerpt hash."""
        lines = self.code if representation == 'decompiled' else self.assembly
        if lines is None or not 1 <= start <= end <= len(lines):
            raise EnrichmentError('PT-ENRICH-INPUT', 'location outside available source lines')
        return SourceLocation(side=self.side, artifact_id=self.artifact_id, run_id=self.run_id,
                              function_id=self.id, representation=representation, start_line=start,
                              end_line=end, excerpt_sha256=identity.excerpt_sha256(lines[start - 1:end]),
                              address=self.address)


@dataclass(frozen=True)
class Hunk:
    """Half-open zero-based ranges as produced by alignment.diff_hunks."""
    operation: str
    old_start: int
    old_end: int
    new_start: int
    new_end: int


@dataclass(frozen=True)
class MatchView:
    pairing_id: str
    match_id: str
    run_id: str
    category: str
    manual: bool
    quality: str
    older: tuple[FunctionView, ...]
    newer: tuple[FunctionView, ...]
    given_hunks: tuple[Hunk, ...] | None = None  # None: derived from the 1:1 code on first use

    @property
    def two_sided(self) -> bool:
        return bool(self.older) and bool(self.newer)

    @cached_property
    def hunks(self) -> tuple[Hunk, ...]:
        """Line hunks of a 1:1 pairing with code on both sides, else (). Computed once, on demand: a
        derived-cache hit only re-validates locations and never needs the alignment."""
        if self.given_hunks is not None:
            return self.given_hunks
        older, newer = self.older, self.newer
        if len(older) != 1 or len(newer) != 1 or older[0].code is None or newer[0].code is None:
            return ()
        return tuple(Hunk(h.operation, h.old_start, h.old_end, h.new_start, h.new_end)
                     for h in diff_hunks('\n'.join(older[0].code), '\n'.join(newer[0].code), self.match_id))

    @cached_property
    def semantic_ordinals(self) -> frozenset[int]:
        """Ordinals of the non-noise changed hunks (B1 rule, `signals.semantic_hunk_ordinals`), computed once
        per view and shared with B2; `signals.detect` primes it from the context it already built."""
        from .signals import semantic_hunk_ordinals  # lazy: signals imports this module
        return semantic_hunk_ordinals(self)


@dataclass(frozen=True)
class RunView:
    project_id: str
    revision: int
    run_id: str
    raw_sha256: str
    diff_id: str
    older_sha256: str
    newer_sha256: str
    older_name: str
    newer_name: str
    matches: tuple[MatchView, ...]


def _lines(text: str | None) -> tuple[tuple[str, ...] | None, bool]:
    if text is None:
        return None, False
    truncated = len(text) > MAX_CHARS
    lines = text[:MAX_CHARS].splitlines()
    if len(lines) > MAX_LINES:
        lines, truncated = lines[:MAX_LINES], True
    return tuple(lines), truncated


def _function(record: FunctionRecord, side: str, artifact_id: str, run_id: str) -> FunctionView:
    if record.run_id != run_id or record.artifact_id != artifact_id:
        raise EnrichmentError('PT-ENRICH-OWNERSHIP', 'function does not belong to this run and side')
    code, cut_code = _lines(record.code)
    assembly, cut_asm = _lines(record.assembly)
    return FunctionView(record.id, artifact_id, run_id, side, record.name,
                        identity.parse_address(record.address), code, assembly, cut_code or cut_asm)


def _occurrences(diff: str, side: str, functions: tuple[FunctionView, ...]) -> list[dict]:
    return [identity.occurrence(diff, side, f.address, f.name, index) for index, f in
            enumerate(sorted(functions, key=lambda f: (f.address is None, f.address or 0, f.name)))]


def match_view(match: FunctionMatch, diff: str, artifacts: dict[str, str]) -> MatchView:
    older = tuple(_function(f, 'older', artifacts['older'], match.run_id) for f in match.older)
    newer = tuple(_function(f, 'newer', artifacts['newer'], match.run_id) for f in match.newer)
    pairing = identity.pairing_id(diff, match.category, match.manual,
                                  _occurrences(diff, 'older', older), _occurrences(diff, 'newer', newer))
    return MatchView(pairing, match.id, match.run_id, match.category, match.manual, match.quality, older, newer)


def location_problem(function: FunctionView, loc: SourceLocation) -> str | None:
    """Why `loc` does not describe `function`'s live code (None when it does). Pure; no model construction."""
    if (function.id != loc.function_id or function.side != loc.side or function.artifact_id != loc.artifact_id
            or function.run_id != loc.run_id or function.address != loc.address):
        return 'PT-ENRICH-OWNERSHIP'
    lines = function.code if loc.representation == 'decompiled' else function.assembly
    if (lines is None or not 1 <= loc.start_line <= loc.end_line <= len(lines)
            or identity.excerpt_sha256(lines[loc.start_line - 1:loc.end_line]) != loc.excerpt_sha256):
        return 'PT-ENRICH-STALE'
    return None


def validate_location(subject: ComparisonProject | RunView, loc: SourceLocation) -> FunctionView:
    """SPEC-07 §4: before navigation or save, check that `loc` names a function of the run's pairings that
    belongs to its run, artifact and side (`PT-ENRICH-OWNERSHIP`) and that the lines still exist and hash to
    the recorded excerpt (`PT-ENRICH-STALE`). Returns the live function view."""
    if isinstance(subject, RunView):
        run_view = subject
    else:
        try:
            run_view = build_views(subject, loc.run_id)
        except EnrichmentError:
            raise EnrichmentError('PT-ENRICH-OWNERSHIP', 'location names a run that is not a completed run '
                                  'of this project') from None
    if loc.run_id != run_view.run_id:
        raise EnrichmentError('PT-ENRICH-OWNERSHIP', 'location belongs to another analysis run')
    function = next((f for m in run_view.matches for f in (*m.older, *m.newer) if f.id == loc.function_id), None)
    if function is None:
        raise EnrichmentError('PT-ENRICH-OWNERSHIP', 'location names a function outside this run')
    problem = location_problem(function, loc)
    if problem == 'PT-ENRICH-OWNERSHIP':
        raise EnrichmentError(problem, 'location side, artifact, run or address does not match its function')
    if problem is not None:
        raise EnrichmentError(problem, 'location lines no longer match the decompiled code')
    return function


def build_views(project: ComparisonProject, run_id: str | None = None) -> RunView:
    """Views for the given (default: latest completed) run. Raises PT-ENRICH-INPUT if none."""
    completed = [r for r in project.runs if r.status == 'completed' and r.raw_sha256]
    run = next((r for r in completed if r.id == run_id), None) if run_id else (completed[-1] if completed else None)
    if run is None:
        raise EnrichmentError('PT-ENRICH-INPUT', 'no completed analysis run with raw output is available')
    sides = {a.side: a for a in project.artifacts}
    diff = identity.diff_id(sides['older'].sha256, sides['newer'].sha256, run.raw_sha256, run.backend)
    artifacts = {side: artifact.id for side, artifact in sides.items()}
    matches = tuple(match_view(m, diff, artifacts) for m in project.matches if m.run_id == run.id)
    return RunView(project.id, project.revision, run.id, run.raw_sha256, diff, sides['older'].sha256,
                   sides['newer'].sha256, sides['older'].name, sides['newer'].name, matches)
