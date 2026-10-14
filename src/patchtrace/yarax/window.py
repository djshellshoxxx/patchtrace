"""Byte-window selection from masked function bodies (plan s7, candidate step 2). Pure: no decoder, no I/O.

The window is anchored on the instructions that changed on the rule's side (the whole body for added or removed
functions) and grown by context instructions inside the function until the gates pass (cap 128 B):
`len` (>= 16 literal bytes and a literal run >= 6), `wild` (<= 40 % wildcards), `uniq` (one hit in the source build)
and `sep` (no hit in the other build). Thresholds other than the hex minimum are provisional until calibrated on
Tier R. Hit counting is injected, so the caller decides which bytes count as "the build".
"""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from dataclasses import dataclass
from difflib import SequenceMatcher

from .contracts import BytesFeature, CallPin, GateId, MaskKind, Side
from .limits import LIMITS, RuleLimits
from .masks import KIND_ORDER, WILDCARD
from .ports import MaskedFunction, MaskedInstruction

MIN_LITERAL_RUN = 6
MAX_WILDCARD_RATIO = 0.4

HitCounter = Callable[[str], int]


@dataclass(frozen=True)
class Window:
    start: int  # instruction index range [start, end) in the source function
    end: int
    rva: int
    pattern: str
    length: int
    literal: int
    longest_run: int
    masks: tuple[MaskKind, ...]
    pins: tuple[CallPin, ...]
    source_hits: int = 0
    other_hits: int = 0

    @property
    def wildcard_ratio(self) -> float:
        return 1 - self.literal / self.length if self.length else 1.0


@dataclass(frozen=True)
class Rejection:
    rva: int
    gate: GateId
    detail: str  # the measured number, e.g. "20 literal bytes, longest run 15"


@dataclass(frozen=True)
class WindowSearch:
    windows: tuple[Window, ...]
    rejected: tuple[Rejection, ...]


def count_hits(pattern: str, image: bytes) -> int:
    """Overlapping matches of a hex pattern with `??` wildcards in `image`."""
    body = b''.join(b'.' if token == WILDCARD else re.escape(bytes.fromhex(token)) for token in pattern.split(' '))
    return sum(1 for _ in re.compile(b'(?=' + body + b')', re.DOTALL).finditer(image))


def _longest_run(tokens: list[str]) -> int:
    best = run = 0
    for token in tokens:
        run = 0 if token == WILDCARD else run + 1
        best = max(best, run)
    return best


def build_window(function: MaskedFunction, start: int, end: int) -> Window:
    items = function.instructions[start:end]
    tokens = [token for item in items for token in item.token.split(' ')] if items else []
    pins: list[CallPin] = []
    offset = 0
    for item in items:
        if item.pin is not None:
            pins.append(item.pin.model_copy(update={'disp_offset': item.pin.disp_offset + offset,
                                                    'end_offset': item.pin.end_offset + offset}))
        offset += item.length
    kinds = {kind for item in items for kind in item.masks}
    return Window(start=start, end=end, rva=items[0].rva if items else 0, pattern=' '.join(tokens),
                  length=len(tokens), literal=sum(t != WILDCARD for t in tokens), longest_run=_longest_run(tokens),
                  masks=tuple(k for k in KIND_ORDER if k in kinds), pins=tuple(pins[:LIMITS.call_pins]))


def _measured(window: Window) -> str:
    return f'{window.literal} literal bytes, longest run {window.longest_run}, {window.length - window.literal} wildcards'


def _static_gate(window: Window, limits: RuleLimits) -> GateId | None:
    if window.literal < limits.hex_pattern_min_bytes or window.longest_run < MIN_LITERAL_RUN:
        return 'len'
    if window.wildcard_ratio > MAX_WILDCARD_RATIO:
        return 'wild'
    return None


def changed_spans(source: MaskedFunction, other: MaskedFunction | None) -> list[tuple[int, int]]:
    """Instruction ranges of `source` that differ from `other` after masking; an insertion on the other side is an
    empty range at its position. Without `other` (added or removed function) the whole body is one span."""
    if other is None:
        return [(0, len(source.instructions))]
    matcher = SequenceMatcher(a=[i.token for i in source.instructions], b=[i.token for i in other.instructions],
                              autojunk=False)
    return [(a1, a2) for tag, a1, a2, _b1, _b2 in matcher.get_opcodes() if tag != 'equal']


def _trim(items: tuple[MaskedInstruction, ...], lo: int, hi: int, cap: int) -> int:
    """Largest hi' <= hi such that the instructions in [lo, hi') fit in `cap` bytes (at least one if any)."""
    size = 0
    for index in range(lo, hi):
        size += items[index].length
        if size > cap and index > lo:
            return index
    return hi


def _grow(items: tuple[MaskedInstruction, ...], lo: int, hi: int, cap: int, prefer_before: bool) -> tuple[int, int] | None:
    size = sum(i.length for i in items[lo:hi])
    options = ([(lo - 1, hi)] if lo > 0 else []) + ([(lo, hi + 1)] if hi < len(items) else [])
    if not prefer_before:
        options.reverse()
    for new_lo, new_hi in options:
        if size + items[new_lo if new_lo < lo else new_hi - 1].length <= cap:
            return new_lo, new_hi
    return None


def _grow_span(function: MaskedFunction, span: tuple[int, int], count_source: HitCounter, count_other: HitCounter,
               limits: RuleLimits) -> Window | Rejection:
    items, cap = function.instructions, limits.context_growth_bytes
    lo, hi = span[0], _trim(items, span[0], span[1], cap)
    step = 0
    while True:
        window = build_window(function, lo, hi)
        gate = _static_gate(window, limits)
        source_hits = other_hits = 0
        if gate is None:
            source_hits = count_source(window.pattern)
            other_hits = count_other(window.pattern)
            gate = 'uniq' if source_hits != 1 else 'sep' if other_hits != 0 else None
        if gate is None:
            return dataclasses.replace(window, source_hits=source_hits, other_hits=other_hits)
        detail = {'uniq': f'{source_hits} hits in its own build', 'sep': f'{other_hits} hits in the other build'
                  }.get(gate, _measured(window))
        grown = _grow(items, lo, hi, cap, prefer_before=step % 2 == 0)
        if grown is None:
            return Rejection(window.rva or function.function.rva, gate, detail)
        (lo, hi), step = grown, step + 1


def propose_windows(source: MaskedFunction, other: MaskedFunction | None, count_source: HitCounter,
                    count_other: HitCounter, limits: RuleLimits = LIMITS) -> WindowSearch:
    """Up to `windows_per_direction` windows ranked by literal bytes, each unique in its own build and absent from
    the other; every span that could not be grown into one is reported with the first gate that kept failing."""
    found: dict[tuple[int, int], Window] = {}
    rejected: list[Rejection] = []
    for span in changed_spans(source, other):
        outcome = _grow_span(source, span, count_source, count_other, limits)
        if isinstance(outcome, Rejection):
            rejected.append(outcome)
        else:
            found.setdefault((outcome.start, outcome.end), outcome)
    ranked = sorted(found.values(), key=lambda w: (-w.literal, w.rva))
    return WindowSearch(tuple(ranked[:limits.windows_per_direction]), tuple(rejected))


def to_bytes_feature(window: Window, side: Side, mask_source: str) -> BytesFeature:
    """Persisted form of an accepted window; separation follows from its two hit counts."""
    return BytesFeature(side=side, window_rva=window.rva, length=window.length, pattern=window.pattern,
                        literal=window.literal, longest_run=window.longest_run, mask=window.masks,
                        mask_source=mask_source, pins=window.pins, source_hits=window.source_hits,
                        other_hits=window.other_hits, separation=f'{side}-only')
