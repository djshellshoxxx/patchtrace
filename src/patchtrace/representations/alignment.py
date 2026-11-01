"""RD-F03 bounded raw-byte alignment; no function/semantic correspondence or minimum-edit claim.

Exact anchors are unique only inside the explicit input windows. Ambiguity and interrupted searches never
publish a guessed match. Every result still partitions both original byte sequences at their physical offsets.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .paging import MAX_PAGE_SIZE, PageBytes, check_page_size
from .scope import MAX_INT, ByteScope, Segment, _check_int

POLICY = 'raw-offset-align/1'
MAX_SCOPE_SEGMENTS = 4096
SpanKind = Literal['equal', 'replace', 'insert', 'delete', 'unresolved']
Status = Literal['complete', 'ambiguous', 'unaligned', 'limited', 'cancelled']


def _bounded(name: str, value: int, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'{name} must be an integer in {low}..{high}')


@dataclass(frozen=True)
class AlignmentLimits:
    anchor_size: int = 16
    max_shift: int = 4096
    max_work: int = 2_000_000
    max_spans: int = 4096

    def __post_init__(self) -> None:
        _bounded('anchor_size', self.anchor_size, 8, 64)
        _bounded('max_shift', self.max_shift, 0, 4096)
        _bounded('max_work', self.max_work, 1, 2_000_000)
        _bounded('max_spans', self.max_spans, 1, 4096)


DEFAULT_ALIGNMENT_LIMITS = AlignmentLimits()


@dataclass(frozen=True)
class AlignmentSpan:
    kind: SpanKind
    older_offset: int
    older: bytes
    newer_offset: int
    newer: bytes


@dataclass(frozen=True)
class ByteAlignment:
    policy: str
    status: Status
    reason: str | None
    spans: tuple[AlignmentSpan, ...]
    work_used: int


class _Stop(Exception):
    def __init__(self, status: Status, reason: str):
        self.status, self.reason = status, reason


class _Budget:
    def __init__(self, maximum: int, cancel: Callable[[], bool] | None):
        self.maximum, self.cancel, self.used = maximum, cancel, 0

    def tick(self, amount: int = 1) -> None:
        if self.cancel is not None and self.cancel():
            raise _Stop('cancelled', 'cancelled')
        if amount > self.maximum - self.used:
            raise _Stop('limited', 'work-limit')
        self.used += amount


def _validate(data: bytes, offset: int, name: str) -> None:
    if type(data) is not bytes:
        raise TypeError(f'{name} must be immutable bytes')
    if len(data) > MAX_PAGE_SIZE:
        raise ValueError(f'{name} is capped at {MAX_PAGE_SIZE} bytes (one page)')
    _check_int(f'{name}_offset', offset)
    if len(data) > MAX_INT - offset:
        raise ValueError(f'{name} exclusive end is too large')


def _index(data: bytes, cursor: int, limits: AlignmentLimits, budget: _Budget) -> dict[bytes, int | None]:
    found: dict[bytes, int | None] = {}
    last = min(limits.max_shift, len(data) - cursor - limits.anchor_size)
    for relative in range(last + 1):
        budget.tick(limits.anchor_size)
        key = data[cursor + relative:cursor + relative + limits.anchor_size]
        found[key] = None if key in found else relative  # None marks every repeated occurrence, never a winner.
    return found


def _anchor(older: bytes, newer: bytes, o: int, n: int, limits: AlignmentLimits,
            budget: _Budget) -> tuple[int, int] | None:
    left, right = _index(older, o, limits, budget), _index(newer, n, limits, budget)
    chosen = None
    displacement = None
    for key, old in left.items():
        budget.tick()
        if key not in right:
            continue
        new = right[key]
        if old is None or new is None:
            raise _Stop('ambiguous', 'repeated-anchor')
        shift = new - old
        if displacement is not None and shift != displacement:
            raise _Stop('ambiguous', 'conflicting-shifts')
        displacement = shift
        if chosen is None or old + new < chosen[0] + chosen[1]:
            chosen = old, new
    return chosen


def _repeat_boundary(older: bytes, newer: bytes, o: int, n: int, old_count: int, new_count: int) -> bool:
    # A pure gap can slide left if its final byte equals the preceding equal-side byte. Do not silently
    # choose where an A in AAAA was inserted, even when a later unique suffix anchors the resynchronization.
    return (old_count == 0 and new_count > 0 and o > 0 and newer[n + new_count - 1] == older[o - 1]) or (
        new_count == 0 and old_count > 0 and n > 0 and older[o + old_count - 1] == newer[n - 1])


def align_bytes(older: bytes, newer: bytes, *, older_offset: int = 0, newer_offset: int = 0,
                limits: AlignmentLimits = DEFAULT_ALIGNMENT_LIMITS,
                cancel: Callable[[], bool] | None = None) -> ByteAlignment:
    """Describe the supplied contiguous file ranges. Unresolved tails retain every byte on both sides."""
    _validate(older, older_offset, 'older')
    _validate(newer, newer_offset, 'newer')
    if not isinstance(limits, AlignmentLimits):
        raise TypeError('limits must be AlignmentLimits')
    budget = _Budget(limits.max_work, cancel)
    spans: list[AlignmentSpan] = []
    o = n = 0

    def emit(kind: SpanKind, old_count: int, new_count: int) -> None:
        nonlocal o, n
        terminal = o + old_count == len(older) and n + new_count == len(newer)
        if len(spans) >= limits.max_spans - 1 and not terminal:
            raise _Stop('limited', 'span-limit')
        spans.append(AlignmentSpan(kind, older_offset + o, older[o:o + old_count],
                                   newer_offset + n, newer[n:n + new_count]))
        o, n = o + old_count, n + new_count

    try:
        budget.tick(0)
        while o < len(older) or n < len(newer):
            old_left, new_left = len(older) - o, len(newer) - n
            if not old_left or not new_left:
                budget.tick(0)
                if _repeat_boundary(older, newer, o, n, old_left, new_left):
                    raise _Stop('ambiguous', 'repeat-boundary')
                emit('insert' if not old_left else 'delete', old_left, new_left)
                break
            same = 0
            while same < min(old_left, new_left):
                budget.tick()
                if older[o + same] != newer[n + same]:
                    break
                same += 1
            if same:
                emit('equal', same, same)
                continue
            if old_left == new_left and old_left < limits.anchor_size:
                emit('replace', old_left, new_left)  # A positional terminal comparison, never a shifted anchor.
                continue
            anchor = _anchor(older, newer, o, n, limits, budget)
            if anchor is None:
                raise _Stop('unaligned', 'no-anchor-in-window')
            old_count, new_count = anchor
            if _repeat_boundary(older, newer, o, n, old_count, new_count):
                raise _Stop('ambiguous', 'repeat-boundary')
            emit('insert' if old_count == 0 else 'delete' if new_count == 0 else 'replace', old_count, new_count)
    except _Stop as stop:
        if o < len(older) or n < len(newer):
            spans.append(AlignmentSpan('unresolved', older_offset + o, older[o:], newer_offset + n, newer[n:]))
        return ByteAlignment(POLICY, stop.status, stop.reason, tuple(spans), budget.used)
    return ByteAlignment(POLICY, 'complete', None, tuple(spans), budget.used)


def _scope_segments(scope: ByteScope) -> tuple[Segment, ...]:
    if not isinstance(scope, ByteScope) or scope.available is not True:
        raise ValueError('page scope is malformed or unavailable')
    if scope.kind not in ('whole_file', 'file_range', 'function_rva'):
        raise ValueError('page scope kind is unknown')
    _check_int('scope total_length', scope.total_length)
    if scope.rva is not None:
        _check_int('scope rva', scope.rva)
    if (scope.kind == 'function_rva') != (scope.rva is not None):
        raise ValueError('scope coordinate kind does not match its RVA')
    if scope.file_size is not None:
        _check_int('scope file_size', scope.file_size)
    if type(scope.segments) is not tuple or not 1 <= len(scope.segments) <= MAX_SCOPE_SEGMENTS:
        raise ValueError(f'alignment scope needs 1..{MAX_SCOPE_SEGMENTS} segments')
    total = 0
    physical = []
    for segment in scope.segments:
        if not isinstance(segment, Segment):
            raise ValueError('scope segment is malformed')
        _check_int('segment file_offset', segment.file_offset)
        _check_int('segment length', segment.length)
        end = segment.file_offset + segment.length
        if segment.length == 0 or end > MAX_INT or (scope.file_size is not None and end > scope.file_size):
            raise ValueError('scope segment is empty or outside file bounds')
        total += segment.length
        physical.append((segment.file_offset, end))
    if total != scope.total_length:
        raise ValueError('scope segments do not cover its logical length')
    physical.sort()
    if any(a[1] > b[0] for a, b in zip(physical, physical[1:], strict=False)):
        raise ValueError('scope physical segments overlap')
    return scope.segments


def _page_interval(page: PageBytes, length: int) -> tuple[int, int]:
    start = _check_int('logical_start', page.logical_start)
    index = _check_int('page_index', page.page_index)
    count = _check_int('page_count', page.page_count)
    total = page.scope.total_length
    if count == 0 or index >= count or length == 0 or start + length > total:
        raise ValueError('page is outside its scope')
    if index == 0:
        if start != 0:
            raise ValueError('first page must begin at logical offset zero')
        if count == 1:
            if length != total:
                raise ValueError('single page must cover its whole scope')
            return start, start + length
        size = length
    else:
        if start % index:
            raise ValueError('page start is not a page-size multiple')
        size = start // index
    check_page_size(size)
    if count != -(-total // size) or length != min(size, total - start):
        raise ValueError('page metadata disagrees with its paging size')
    return start, start + length


def _page_chunk(page: PageBytes) -> tuple[int, bytes]:
    if not isinstance(page, PageBytes):
        raise TypeError('alignment requires PageBytes')
    if type(page.chunks) is not tuple or len(page.chunks) != 1:
        raise ValueError('alignment requires one contiguous chunk per page')
    chunk = page.chunks[0]
    if type(chunk) is not tuple or len(chunk) != 2:
        raise ValueError('page chunk is malformed')
    offset, data = chunk
    _validate(data, offset, 'page')
    if type(page.byte_count) is not int or page.byte_count != len(data):
        raise ValueError('page byte count does not match its chunk')
    segments = _scope_segments(page.scope)
    start, end = _page_interval(page, len(data))
    logical = 0
    expected = []
    for segment in segments:
        lo, hi = max(start, logical), min(end, logical + segment.length)
        if lo < hi:
            expected.append((segment.file_offset + lo - logical, hi - lo))
        logical += segment.length
    if expected != [(offset, len(data))]:
        raise ValueError('page chunk does not match the physical range of its scope')
    if page.sha256 != hashlib.sha256(data).hexdigest():
        raise ValueError('page digest does not match its chunk')
    return offset, data


def align_pages(older: PageBytes, newer: PageBytes, *, limits: AlignmentLimits = DEFAULT_ALIGNMENT_LIMITS,
                cancel: Callable[[], bool] | None = None) -> ByteAlignment:
    """Use verified page chunks' physical offsets; never flatten a discontinuous function-RVA mapping."""
    old_offset, old_data = _page_chunk(older)
    new_offset, new_data = _page_chunk(newer)
    return align_bytes(old_data, new_data, older_offset=old_offset, newer_offset=new_offset,
                       limits=limits, cancel=cancel)
