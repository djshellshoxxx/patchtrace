"""What a source group is: an immutable description plus a lazy document stream.

A `SourceSpec` is built on the GUI thread from store rows (`search.build.build_request`) and holds only immutable
snapshots, so `documents()` may run on a build thread. Documents come out in a total order that does not depend
on the order of the source data, and `ref` is the ordinal in that order (section 7 'Segment file').
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from patchtrace.models import AnalysisRun, ComparisonProject
from patchtrace.search.normalize import fold, is_auto_name
from patchtrace.search.segment import Flag, SegmentDoc, segment_digest
from patchtrace.search.tokenize import name_words


def no_docs() -> Iterable[SegmentDoc]:
    return ()


@dataclass(frozen=True, slots=True)
class SourceSpec:
    group: str
    kinds: tuple[str, ...]
    table_sets: tuple[str, ...]
    side: str | None
    inputs: object  # the digest-pinned input description of section 7 'Digest'
    documents: Callable[[], Iterable[SegmentDoc]] = no_docs
    status: str = 'indexed'  # a coverage status; anything but 'indexed' is never built
    reason: str = ''  # fixed text shown in the coverage entry

    @property
    def buildable(self) -> bool:
        return self.status == 'indexed'

    @property
    def digest16(self) -> str | None:
        return segment_digest(self.group, self.table_sets, self.inputs) if self.buildable else None


def skipped(group: str, kinds: tuple[str, ...], side: str | None, status: str, reason: str) -> SourceSpec:
    """A group that cannot be indexed now (`not-applicable`, `unavailable`): reported, never built."""
    return SourceSpec(group, kinds, ('text',), side, None, status=status, reason=reason)


def name_fields(name: str, *others: str) -> dict:
    """The name-table fields of a `SegmentDoc`: folded raw name, split words of every form, the AUTO flag."""
    return {'name_raw': fold(name), 'name_words': name_words(name, *others),
            'flags': int(Flag.AUTO) if is_auto_name(name) else 0}


def selected_run(project: ComparisonProject, run_id: str | None) -> AnalysisRun | None:
    """The run `build_views` would pick: the given completed run with raw output, else the latest one."""
    completed = [r for r in project.runs if r.status == 'completed' and r.raw_sha256]
    if run_id:
        return next((r for r in completed if r.id == run_id), None)
    return completed[-1] if completed else None
