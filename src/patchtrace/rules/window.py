"""Byte windows of a changed function (YRX-integration-plan s6 "Generic windows", s7 candidate generation step 2).

A window is a run of whole instructions of the rule's own build, written as a hex pattern whose layout-dependent bytes
are wildcards (`masks`). It is proposed only when it passes four checks on its own numbers: enough literal bytes (`len`),
not mostly wildcards (`wild`), found exactly once in the executable sections of the build it came from (`uniq`) and not
found in the other build (`sep`). Thresholds are `gates`' and provisional until Tier R calibrates them.

Where windows come from. Both bodies are decoded and masked, and `difflib.SequenceMatcher` (autojunk off) compares them
instruction by instruction; the instructions of the rule's side that were deleted or replaced are the changed range (for
a removed or an added function: the whole body; nothing changed after masking means no window, which is how a pure
rebuild or a cosmetic change yields nothing). A changed range is kept with one instruction of context on each side where
the body has them, so a window never starts or ends inside the change, and is grown by one instruction at a time (after,
then before, alternately) until the checks pass or it reaches 128 bytes. A range longer than that is searched with
sliding windows of the largest size, best literal count first. At most three windows survive, best literal count first,
none overlapping another. A body with no window reports the checks that the best attempt failed, never nothing.

The comparison is bounded. What both bodies share at their start and at their end is not compared, and `difflib`'s cost is
proportional to the pairs of equal instructions in what is left (measured: about 0.2 to 0.6 microseconds a pair; 12,000
identical instructions take 30 s), so a middle with more than `MAX_DIFF_PAIRS` of them is not compared at all: it is one
changed range, and `uniq` and `sep` still keep every byte the other build has out of the rule.

The hit counts are the plain byte semantics of the pattern (a wildcard matches any byte) over the executable sections, which
is what the rule's `in (raw_data_offset..)` condition scopes to; the finished rule is still scanned by the engine
(`candidates`' `sep` gate), so a disagreement shows up there instead of being trusted here.
"""
from __future__ import annotations

import difflib
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from . import gates as g
from .contracts import (
    BytesFeature,
    Direction,
    FunctionRef,
    Gate,
    MaskSourceName,
    PairSource,
    Side,
    pattern_metrics,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS, RuleLimits
from .masks import WILDCARD, MaskedFunction, call_pins, mask_function
from .ports import MaskSource

CONTEXT = 1                    # instructions of context kept on each side of a changed range
MAX_DIFF_PAIRS = 1_000_000     # pairs of equal instructions `difflib` may weigh (about 0.5 s at most; provisional)
MAX_EVALUATIONS = 32           # windows whose hits are counted in one call
CACHE_BYTES = 64 * 1024 ** 2   # executable bytes kept in memory per build for repeated counting
_OPPOSITE: dict[str, Side] = {'older': 'newer', 'newer': 'older'}
Opcode = tuple[str, int, int, int, int]   # difflib's: tag, older start and stop, newer start and stop (instruction indexes)


class BuildImage(Protocol):
    """What the byte channel needs from one verified build (`pe_overview.tables.PeTables` provides it). A method that
    cannot read a malformed table raises `ValueError`."""

    @property
    def sha256(self) -> str: ...

    def read_backed(self, rva: int, length: int) -> bytes | None: ...

    def function_extent(self, rva: int) -> int | None: ...

    def relocations(self) -> tuple[list[int], list[int]]: ...

    def import_slots(self) -> Mapping[int, tuple[str, str]]: ...

    def rva_to_offset(self, rva: int) -> int | None: ...

    def executable_sections(self) -> Iterator[tuple[int, bytes]]: ...


@dataclass(frozen=True)
class WindowSet:
    """The result for one direction: the windows that passed (best first, at most `candidates_per_direction`); when none
    passed, the failing checks of the best attempt; the file offsets the function reads through RIP-relative operands (a
    string at one of them is `xref`-linked to the changed code); and the decoder that produced the masks."""
    windows: tuple[BytesFeature, ...]
    failures: tuple[Gate, ...]
    referenced_offsets: frozenset[int]
    decoder: tuple[MaskSourceName, str]


@dataclass(frozen=True)
class _Eval:
    first: int
    last: int
    tokens: tuple[str, ...]
    length: int
    literal: int
    run: int
    gates: tuple[Gate, ...]
    source_hits: int | None = None
    other_hits: int | None = None

    @property
    def passed(self) -> bool:
        return len(self.gates) == 4 and all(g.passed(gate) for gate in self.gates)

    def failure(self) -> Gate:
        return next(gate for gate in self.gates if not g.passed(gate))


def _regex(tokens: tuple[str, ...]) -> re.Pattern[bytes]:
    return re.compile(b''.join(b'.' if t == WILDCARD else re.escape(bytes([int(t, 16)])) for t in tokens), re.DOTALL)


def _shared_ends(older: list[str], newer: list[str]) -> tuple[int, int]:
    """How many instructions two bodies share at their start and, in what is left of them, at their end."""
    limit = min(len(older), len(newer))
    head = 0
    while head < limit and older[head] == newer[head]:
        head += 1
    tail = 0
    while tail < limit - head and older[-1 - tail] == newer[-1 - tail]:
        tail += 1
    return head, tail


def diff_opcodes(older: MaskedFunction, newer: MaskedFunction) -> list[Opcode]:
    """What differs between two bodies after masking, instruction by instruction: `difflib`'s opcodes without the equal
    ones, as indexes of the bodies. The start and the end the bodies share are not compared, and a middle with more than
    `MAX_DIFF_PAIRS` pairs of equal instructions (the measure of `difflib`'s cost) is not compared either: it is one
    `replace`, so the checks on the windows (`uniq`, `sep`) decide instead."""
    a, b = [i.key for i in older.instructions], [i.key for i in newer.instructions]
    head, tail = _shared_ends(a, b)
    a, b = a[head:len(a) - tail], b[head:len(b) - tail]
    in_b = Counter(b)
    if sum(count * in_b[key] for key, count in Counter(a).items()) > MAX_DIFF_PAIRS:
        return [('replace', head, head + len(a), head, head + len(b))]
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [(tag, head + i1, head + i2, head + j1, head + j2)
            for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != 'equal']


def changed_ranges(own: MaskedFunction, other: MaskedFunction | None, direction: Direction,
                   opcodes: Sequence[Opcode] | None = None) -> list[tuple[int, int]]:
    """Instruction ranges of `own` that `other` does not have, after masking. A removed or added function (`other` is
    `None`) is changed throughout. `opcodes` are the pair's `diff_opcodes` when the caller already holds them."""
    if other is None:
        return [(0, len(own.instructions))] if own.instructions else []
    if opcodes is None:
        opcodes = diff_opcodes(*((own, other) if direction == 'older' else (other, own)))
    wanted = ('replace', 'delete') if direction == 'older' else ('replace', 'insert')
    return [(i1, i2) if direction == 'older' else (j1, j2) for tag, i1, i2, j1, j2 in opcodes if tag in wanted]


class _Search:
    """One direction of one pair: the masked function, hit counts with a budget, and the growth and sliding searches."""

    def __init__(self, owner: BytesWindows, direction: Direction, own: MaskedFunction):
        self.owner, self.direction, self.own = owner, direction, own
        self.evaluations = 0
        self.seen: dict[tuple[int, int], _Eval] = {}

    def evaluate(self, first: int, last: int) -> _Eval:
        if (first, last) in self.seen:
            return self.seen[first, last]
        tokens = self.own.tokens(first, last)
        length, literal, run = pattern_metrics(' '.join(tokens))
        gates = [g.long_enough(literal, run), g.not_mostly_wildcards(length, literal)]
        source = other = None
        if all(g.passed(gate) for gate in gates):
            if self.evaluations < MAX_EVALUATIONS:
                self.evaluations += 1
                source, other = self.owner.count(self.direction, tokens), self.owner.count(
                    _OPPOSITE[self.direction], tokens)
            gates += [g.one_place(source), g.absent_elsewhere(other)]
        found = self.seen[first, last] = _Eval(first, last, tokens, length, literal, run, tuple(gates), source, other)
        return found

    def grow(self, start: int, stop: int) -> _Eval:
        """The range with its context, grown until it passes or reaches the cap (the last attempt is returned)."""
        cap, size_of, count = g.WINDOW_GROWTH_CAP, self.own.size_of, len(self.own.instructions)
        first, last = max(0, start - CONTEXT), min(count, stop + CONTEXT)
        while size_of(first, last) > cap:   # the change fits, its context does not: give the context up
            if last > stop:
                last -= 1
            else:
                first += 1
        found, after = self.evaluate(first, last), True
        while not found.passed:
            grown = self._extend(first, last, after)
            if grown is None:
                break
            (first, last), after = grown, not after
            found = self.evaluate(first, last)
        return found

    def _extend(self, first: int, last: int, after: bool) -> tuple[int, int] | None:
        """One more instruction, from the preferred side if the cap allows it, else from the other; `None` at the cap."""
        instructions = self.own.instructions
        room = g.WINDOW_GROWTH_CAP - self.own.size_of(first, last)
        moves = {'after': (first, last + 1) if last < len(instructions) and instructions[last].size <= room else None,
                 'before': (first - 1, last) if first > 0 and instructions[first - 1].size <= room else None}
        return moves['after'] or moves['before'] if after else moves['before'] or moves['after']

    def slide(self, start: int, stop: int, wanted: int) -> list[_Eval]:
        """Non-overlapping passing windows of the largest size inside a range longer than the cap, best literal first."""
        sizes = [i.size for i in self.own.instructions]
        literals = [sum(1 for t in i.tokens if t != WILDCARD) for i in self.own.instructions]
        size_sum, literal_sum = [0], [0]
        for size, literal in zip(sizes, literals, strict=True):
            size_sum.append(size_sum[-1] + size)
            literal_sum.append(literal_sum[-1] + literal)
        ranked, last = [], start
        for first in range(start, stop):
            last = max(last, first + 1)
            while last < stop and size_sum[last + 1] - size_sum[first] <= g.WINDOW_GROWTH_CAP:
                last += 1
            literal = literal_sum[last] - literal_sum[first]
            if literal >= g.MIN_LITERAL_BYTES:
                ranked.append((-literal, first, last))
        chosen: list[_Eval] = []
        for _negative, first, last in sorted(ranked):
            if len(chosen) == wanted or self.evaluations >= MAX_EVALUATIONS:
                break
            if all(last <= c.first or first >= c.last for c in chosen):
                found = self.evaluate(first, last)
                if found.passed:
                    chosen.append(found)
        return chosen


class BytesWindows:
    """The byte channel: `windows(pair, direction)`. `images` maps a side to its verified build."""

    def __init__(self, mask_source: MaskSource, images: Mapping[Side, BuildImage], *,
                 limits: RuleLimits = DEFAULT_LIMITS):
        self._mask, self._images, self._limits = mask_source, images, limits
        self._code: dict[Side, list[tuple[int, bytes]] | None] = {}
        self._counts: dict[tuple[Side, tuple[str, ...]], int] = {}
        self._bodies: dict[tuple[Side, int, int | None], MaskedFunction] = {}
        self._diffs: dict[tuple[int, int, int, int], list[Opcode]] = {}

    # -- the build ---------------------------------------------------------------------------------------------------
    def _sections(self, side: Side) -> Iterable[tuple[int, bytes]]:
        """The executable bytes of a build: kept in memory when small, otherwise read again for every count."""
        if side not in self._code:
            kept, total = [], 0
            for offset, data in self._images[side].executable_sections():
                total += len(data)
                if total > CACHE_BYTES:
                    self._code[side] = None
                    break
                kept.append((offset, data))
            else:
                self._code[side] = kept
        cached = self._code[side]
        return self._images[side].executable_sections() if cached is None else cached

    def count(self, side: Side, tokens: tuple[str, ...]) -> int:
        """Matches of the pattern (overlapping ones included) in the executable sections of `side`, up to the engine's own
        per-pattern cap."""
        key = (side, tokens)
        if key not in self._counts:
            pattern, cap, total = _regex(tokens), self._limits.max_matches_per_pattern, 0
            for _offset, data in self._sections(side):
                position = 0
                while total < cap and (match := pattern.search(data, position)) is not None:
                    total, position = total + 1, match.start() + 1
            self._counts[key] = total
        return self._counts[key]

    def _check_images(self, pair: PairSource) -> None:
        for side in ('older', 'newer'):
            image = self._images.get(side)
            if image is None:
                raise RuleError('PT-RULE-MASK', f'The {side} build is not available for byte patterns',
                                reason='no-image')
            if image.sha256 != (pair.older_sha256 if side == 'older' else pair.newer_sha256):
                raise RuleError('PT-RULE-STALE', f'The {side} build is not the file the pair was accepted for',
                                reason='artifact-moved')

    def _masked(self, side: Side, ref: FunctionRef) -> MaskedFunction:
        key = (side, ref.rva, ref.size)
        if key not in self._bodies:   # both directions of a pair need both bodies: decode each once
            self._bodies[key] = self._decoded(side, ref)
        return self._bodies[key]

    def _opcodes(self, direction: Direction, own: MaskedFunction, other: MaskedFunction | None) -> list[Opcode] | None:
        """Both directions of a pair weigh the same two bodies: compare them once."""
        if other is None:
            return None
        older, newer = (own, other) if direction == 'older' else (other, own)
        key = (older.rva, older.size, newer.rva, newer.size)
        if key not in self._diffs:
            self._diffs[key] = diff_opcodes(older, newer)
        return self._diffs[key]

    def _decoded(self, side: Side, ref: FunctionRef) -> MaskedFunction:
        image = self._images[side]
        if ref.extent == 'unknown' or ref.size is None:
            raise RuleError('PT-RULE-MASK', 'The function size is not known (a leaf function has no exception data)',
                            reason='no-extent')
        if ref.size > self._limits.function_bytes:
            raise RuleError('PT-RULE-LIMIT', f'The function is larger than {self._limits.function_bytes} bytes',
                            reason='function-size')
        try:
            known = image.function_extent(ref.rva) if ref.extent == 'pdata' else None
            relocations = image.relocations()
        except ValueError:
            raise RuleError('PT-RULE-MASK', 'The exception or relocation data of the build cannot be read',
                            reason='table-unreadable') from None
        if known is not None and known != ref.size:
            raise RuleError('PT-RULE-STALE', 'The recorded function size differs from the exception data of the build',
                            reason='extent-differs')
        code = image.read_backed(ref.rva, ref.size)
        if code is None:
            raise RuleError('PT-RULE-MASK', 'The function is not backed by bytes of the file', reason='not-backed')
        return mask_function(code, ref.rva, self._mask.decode(code, ref.rva), relocations)

    # -- the windows -------------------------------------------------------------------------------------------------
    def windows(self, pair: PairSource, direction: Direction) -> WindowSet:
        """Windows of the function the pair has on `direction`'s side. Raises `PT-RULE-MASK` (no verified extent, bytes not
        in the file, unreadable tables), `PT-RULE-LIMIT` (function over the size cap), `PT-RULE-DECODE` (bytes the decoder
        cannot read) or `PT-RULE-STALE` (a build or a recorded size that no longer fits the pair)."""
        own_ref = pair.older if direction == 'older' else pair.newer
        other_ref = pair.newer if direction == 'older' else pair.older
        if own_ref is None:
            raise RuleError('PT-RULE-INPUT', 'The pair has no function in this build', reason='direction')
        self._check_images(pair)
        own = self._masked(direction, own_ref)
        other = None if other_ref is None else self._masked(_OPPOSITE[direction], other_ref)
        search = _Search(self, direction, own)
        passing: list[_Eval] = []
        for start, stop in changed_ranges(own, other, direction, self._opcodes(direction, own, other)):
            if own.size_of(start, stop) > g.WINDOW_GROWTH_CAP:
                passing += search.slide(start, stop, self._limits.candidates_per_direction)
            elif (found := search.grow(start, stop)).passed:
                passing.append(found)
        chosen = self._choose(passing)
        slots = self._slots(direction) if chosen else {}
        features = tuple(self._feature(own, found, direction, slots) for found in chosen)
        failures: tuple[Gate, ...] = ()
        if not features:
            best = max(search.seen.values(), default=None, key=lambda e: (e.literal, -e.first))
            failures = () if best is None else (best.failure(),)
        return WindowSet(features, failures, self._referenced(own, direction), (self._mask.name, self._mask.version))

    def _choose(self, passing: list[_Eval]) -> list[_Eval]:
        chosen: list[_Eval] = []
        for found in sorted({(e.first, e.last): e for e in passing}.values(), key=lambda e: (-e.literal, e.first)):
            if all(found.last <= c.first or found.first >= c.last for c in chosen):
                chosen.append(found)
            if len(chosen) == self._limits.candidates_per_direction:
                break
        return chosen

    def _slots(self, direction: Direction) -> Mapping[int, tuple[str, str]]:
        try:
            return self._images[direction].import_slots()
        except ValueError:
            return {}   # no import table: the window simply has no pin

    def _referenced(self, own: MaskedFunction, direction: Direction) -> frozenset[int]:
        image = self._images[direction]
        targets = {item.target_rva for item in own.instructions
                   if item.target_rva is not None and any(span.kind == 'rip-disp' for span in item.spans)}
        return frozenset(offset for rva in targets if (offset := image.rva_to_offset(rva)) is not None)

    def _feature(self, own: MaskedFunction, found: _Eval, direction: Direction,
                 slots: Mapping[int, tuple[str, str]]) -> BytesFeature:
        return BytesFeature(
            included=True, side=direction, window_rva=own.rva_of(found.first), length=found.length,
            pattern=' '.join(found.tokens), literal=found.literal, longest_run=found.run,
            mask=own.kinds(found.first, found.last), mask_source=self._mask.name,
            pins=call_pins(own, found.first, found.last, slots, limit=self._limits.pins_per_feature),
            source_hits=found.source_hits, other_hits=found.other_hits, separation=f'{direction}-only')
