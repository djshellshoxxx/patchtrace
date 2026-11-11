"""PatchTrace basic string scan (WB3-S3): in-process extraction of ASCII and UTF-16LE (ASCII-range) strings.

It reproduces the documented static-string behaviour of FLOSS 3.1.1 (bytes 0x20-0x7E plus TAB, minimum length 4,
UTF-16LE of those characters only, CR/LF/NUL and every other byte end a string, file offsets, duplicates kept,
ASCII strings first, then wide ones) and nothing else: no stack, tight, decoded or language strings, no
function attribution. It is a different implementation, written from that description and checked against
recorded FLOSS 3.1.1 output, and it is always labelled `SOURCE_LABEL`, never "FLOSS". It reads bytes only; the
target is never loaded or executed.

Chunked reading is exactly equivalent to one regex pass over the whole buffer (property-tested), except that a
single unbroken run longer than `max_run` bytes is cut into `max_run`-byte pieces and counted in
`ScanResult.split_runs`, so one hostile file cannot make a single value arbitrarily large.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from ..intelligence.tools.common import display_text, secret_kind
from .sources import STATIC_SEMANTICS_ID, SourceResult, SourceRow, StringPart, row_order, stage_states

SOURCE_LABEL = 'PatchTrace basic string scan'
SEMANTICS_ID = STATIC_SEMANTICS_ID
SCAN_VERSION = 'builtin-scan/1'
DEFAULT_MIN_LENGTH = 4
MIN_LENGTH_RANGE = (1, 4096)
CHUNK_BYTES = 4 * 1024 * 1024       # cancellation is checked once per chunk
DEFAULT_MAX_RUN = 1024 * 1024
DEFAULT_MAX_ROWS = 200_000          # per side, until the S0 gate raises it (WB3 section 7)
# Bytes are first mapped to 1 (string character), 2 (NUL, the high byte of a wide character) or 0 (anything else).
# A regex over those marks starts with a literal prefix, which CPython searches several times faster than a
# character-class repeat (measured 3-6x); the string text is then cut from the original bytes.
_MARKS = bytes(1 if 0x20 <= b <= 0x7E or b == 9 else 2 if b == 0 else 0 for b in range(256))
_PREFIX = 8
_LOOKBEHIND_FROM = 32           # min_length above this uses the run-start lookbehind (#105 BUG-STR-4)

Cancel = Callable[[], bool]


class ScanError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f'{code}: {message}')
        self.code = code


class ScanRow(NamedTuple):
    value: str
    encoding: str   # 'ASCII' | 'UTF-16LE'
    offset: int


@dataclass
class _Counters:
    split_runs: int = 0
    bytes_read: int = 0


@dataclass(frozen=True)
class ScanResult:
    rows: tuple[ScanRow, ...]
    totals: dict[str, int]           # strings found per encoding, whether kept or not
    min_length: int
    bytes_scanned: int
    split_runs: int = 0
    truncated_encodings: tuple[str, ...] = field(default=())

    @property
    def truncated(self) -> bool:
        return bool(self.truncated_encodings)


@lru_cache(maxsize=8)
def _pattern(unit: int, min_length: int) -> re.Pattern[bytes]:
    # The lookbehind refuses to start inside a run: a run shorter than `min_length` is then tried once, not once
    # per position, which was quadratic in `min_length` (issue #105 BUG-STR-4). A match can only ever start where
    # the previous unit is not a string unit, so the matches are the same.
    # Short minimums keep the plain pattern: the retry cost is bounded by min_length squared and the lookbehind
    # would slow the common scan about fivefold.
    if min_length <= _LOOKBEHIND_FROM:
        return re.compile(_body(unit, min_length))
    one = b'\x01' if unit == 1 else b'\x01\x02'
    return re.compile(b'(?<!' + one + b')' + _body(unit, min_length))


@lru_cache(maxsize=8)
def _follow(unit: int, min_length: int) -> re.Pattern[bytes]:
    """The rest of a run that was split at `max_run`: it starts inside the run on purpose (anchored, no lookbehind)."""
    return re.compile(_body(unit, min_length))


def _body(unit: int, min_length: int) -> bytes:
    one = b'\x01' if unit == 1 else b'\x01\x02'
    head = min(min_length, _PREFIX)
    return one * head + b'(?:' + one + b'){%d,}' % (min_length - head)


def read_chunks(path: Path, chunk_bytes: int = CHUNK_BYTES) -> Iterator[bytes]:
    with open(path, 'rb') as handle:
        while chunk := handle.read(chunk_bytes):
            yield chunk


def _runs(chunks: Iterable[bytes], *, unit: int, min_length: int, max_run: int, stats: _Counters,
          cancel: Cancel | None) -> Iterator[tuple[int, bytes]]:
    """Yield (offset, raw run) exactly as `re.finditer` over the whole buffer would.

    A match is final once at least one more unit follows it. The carried tail starts at an undecided match or at
    the first position that could still begin one, so no match is lost or split at a chunk boundary."""
    pattern, follow = _pattern(unit, min_length), _follow(unit, min_length)
    cut = max_run - max_run % unit
    buf, base = b'', 0
    pending = iter(chunks)
    last = False
    while not last:
        chunk = next(pending, None)
        last = chunk is None
        if cancel is not None and cancel():
            raise ScanError('PT-STR-CANCEL', 'the scan was cancelled')
        if chunk:
            buf += chunk
        marks = buf.translate(_MARKS)
        pos = 0
        held: int | None = None
        anchored = False
        while True:
            match = follow.match(marks, pos) if anchored else pattern.search(marks, pos)
            if match is None:
                if anchored:                            # the rest of a split run is too short: search on
                    anchored = False
                    continue
                break
            anchored = False
            start, end = match.span()
            if end - start > cut:
                stats.split_runs += 1
                yield base + start, buf[start:start + cut]
                pos = start + cut
                anchored = True
            elif not last and end + unit > len(buf):
                held = start
                break
            else:
                yield base + start, buf[start:end]
                pos = end
        keep = held if held is not None else max(pos, len(buf) - unit * min_length + 1)
        buf, base = buf[keep:], base + keep


def _decode(raw: bytes, unit: int) -> str:
    return raw.decode('ascii') if unit == 1 else raw.decode('utf-16-le')


def _counted(chunks: Iterable[bytes], counters: _Counters) -> Iterator[bytes]:
    for chunk in chunks:
        counters.bytes_read += len(chunk)
        yield chunk


def scan_chunks(open_chunks: Callable[[], Iterable[bytes]], *, min_length: int = DEFAULT_MIN_LENGTH,
                max_rows: int = DEFAULT_MAX_ROWS, max_run: int = DEFAULT_MAX_RUN,
                cancel: Cancel | None = None) -> ScanResult:
    """Scan a byte stream that `open_chunks` can open twice (one pass per width keeps the carried state tiny, and
    FLOSS also lists every ASCII string before the wide ones). Rows keep the first `max_rows` per encoding by
    offset while the totals stay exact, so a cut is recorded, never silent (WB3 F21)."""
    if not MIN_LENGTH_RANGE[0] <= min_length <= MIN_LENGTH_RANGE[1]:
        raise ScanError('PT-STR-INPUT', f'the minimum string length must be {MIN_LENGTH_RANGE[0]}..'
                        f'{MIN_LENGTH_RANGE[1]}')
    if max_run < 2 * min_length or max_rows < 0:
        raise ScanError('PT-STR-INPUT', 'invalid scan limits')
    counters = _Counters()
    kept: dict[str, list[ScanRow]] = {'ASCII': [], 'UTF-16LE': []}
    totals = {'ASCII': 0, 'UTF-16LE': 0}
    split_runs = 0
    for unit, name in ((1, 'ASCII'), (2, 'UTF-16LE')):
        counters.split_runs = 0
        source = _counted(open_chunks(), counters) if unit == 1 else open_chunks()
        for offset, raw in _runs(source, unit=unit, min_length=min_length, max_run=max_run, stats=counters,
                                 cancel=cancel):
            totals[name] += 1
            if len(kept[name]) < max_rows:
                kept[name].append(ScanRow(_decode(raw, unit), name, offset))
        split_runs += counters.split_runs
    return ScanResult(tuple(kept['ASCII'] + kept['UTF-16LE']), totals, min_length, counters.bytes_read, split_runs,
                      tuple(name for name in kept if totals[name] > len(kept[name])))


def scan_bytes(data: bytes, *, chunk_bytes: int = CHUNK_BYTES, **kwargs) -> ScanResult:
    return scan_chunks(lambda: (data[i:i + chunk_bytes] for i in range(0, len(data), chunk_bytes)), **kwargs)


def scan_path(path: Path, *, chunk_bytes: int = CHUNK_BYTES, **kwargs) -> ScanResult:
    return scan_chunks(lambda: read_chunks(path, chunk_bytes), **kwargs)


class BuiltinScanSource:
    """`StringSource` over the built-in scan. `offset_to_rva` comes from the verified image (None: no RVA)."""

    def __init__(self, path: Path, *, artifact_sha256: str, side: str, min_length: int = DEFAULT_MIN_LENGTH,
                 max_rows: int = DEFAULT_MAX_ROWS, offset_to_rva: Callable[[int], int | None] | None = None,
                 cancel: Cancel | None = None) -> None:
        self._path, self._ids = path, (artifact_sha256, side)
        self._min_length, self._max_rows = min_length, max_rows
        self._offset_to_rva, self._cancel = offset_to_rva, cancel

    def load(self) -> SourceResult:
        result = scan_path(self._path, min_length=self._min_length, max_rows=self._max_rows, cancel=self._cancel)
        rows = tuple(sorted((self._row(item) for item in result.rows), key=row_order))
        truncated = {'static'} if result.truncated else set()
        seen = sum(result.totals.values())
        digest = hashlib.sha256(f'{SCAN_VERSION}|{SEMANTICS_ID}|{result.min_length}'.encode()).hexdigest()
        part = StringPart(source='builtin-scan', semantics_id=SEMANTICS_ID, source_version=SCAN_VERSION,
                          types=('static',), config_digest=digest)
        anomalies = (f'split-runs:{result.split_runs}',) if result.split_runs else ()
        return SourceResult(
            side=self._ids[1], artifact_sha256=self._ids[0], min_length=result.min_length, language=None,
            rows=rows, rows_seen=seen, stages=stage_states({'static'}, {'static': seen}, truncated), part=part,
            anomalies=anomalies)

    def _row(self, item: ScanRow) -> SourceRow:
        rva = self._offset_to_rva(item.offset) if self._offset_to_rva else None
        return SourceRow(hashlib.sha256(item.value.encode('utf-8', 'surrogatepass')).digest(),
                         display_text(item.value), len(item.value), 'static', item.encoding, item.offset, rva,
                         None, None, None, secret_kind(item.value), 'verified-bytes')
