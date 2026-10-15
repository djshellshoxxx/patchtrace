"""Code text for one unified row, read from what the result stores (SPEC-31 07 s3 "code panes"). Qt-free.

Two channels per row, each an aligned `PairText` with one provenance line per side, or the reason it is unavailable:

- `decompiled`: the C text of the on-demand decompile (S3b), when the result carries the part `decomp.jsonl.gz`;
  lines are `{side, rva, status, code}`, the part is checked against its manifest digest before any line is used.
- `disassembly`: the Ghidra-produced instruction text (`ins.txt`) of the stored ProgramIR, one line per instruction with
  its RVA; the gaps come from the stored-IR alignment of `facts/align.py`, not from a text diff.

Nothing is fabricated: a side without a function, a function the IR does not hold, a sidecar without text, a failed
decompile and a result without decompiled text each say so. The readers are opened lazily, kept per IR key until
`close()`, and guarded by a lock because the panel loads on a worker thread.
"""
from __future__ import annotations

import hashlib
import json
import threading
from bisect import bisect_left
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..alignment import diff_hunks
from ..gui.pair_text import PairHunk, PairText, align_pair
from . import store
from .contracts import IrRef, SideRef, strip_unsafe
from .facts.align import align
from .facts.fnview import FnView, load_view
from .ir.place import ir_dir
from .ir.reader import IrReader
from .limits import UnifiedError
from .read_model import UnifiedRowView, UnifiedViewModel, records_for
from .read_text import clean

DECOMPILED, DISASSEMBLY = 'decompiled', 'disassembly'
CHANNELS = (DECOMPILED, DISASSEMBLY)
MAX_LINES = 4000
DECOMP_PART = 'decomp.jsonl.gz'
NO_FUNCTION = 'No function on this side.'
NOT_STORED = 'Disassembly text is not stored for this function in the ProgramIR.'
NOT_IN_IR = 'This function is not in the stored ProgramIR.'
NO_IR = 'No ProgramIR is stored for this result.'
NO_RESULT = 'The result directory is not available.'
NO_DECOMP = ('Decompiled code is not stored in this result. Review pairs are decompiled on demand by Ghidra when '
             'extraction is configured.')
DECOMP_UNREADABLE = 'The stored decompiled text failed verification and is not shown.'
DECOMP_MISSING = 'The decompiler produced no text for this function.'
DECOMP_STATUS = {'timeout': 'The decompiler timed out on this function.',
                 'failed': 'The decompiler failed on this function.'}
NOT_ALIGNED = 'not aligned: a function is over 4,000 instructions or the IR has no instruction data for it'
_DECOMP_KEYS = frozenset({'side', 'rva', 'status', 'code'})


@dataclass(frozen=True, slots=True)
class CodeChannel:
    """One kind of code text: `pair` and its per-side provenance lines, or None and the `reason` it is unavailable.
    `label` says what the text is; `notes` are honest limits (alignment skipped or capped, an empty side)."""
    channel: str
    label: str
    pair: PairText | None = None
    provenance: tuple[str, str] = ('', '')
    reason: str = ''
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RowCode:
    decompiled: CodeChannel
    disassembly: CodeChannel

    def channel(self, name: str) -> CodeChannel:
        return self.decompiled if name == DECOMPILED else self.disassembly


@dataclass(frozen=True, slots=True)
class _Side:
    """One side of a pair: code lines, or a message in their place (`lines` empty). `keys` are what two lines are
    compared by when they differ from the shown text (the instruction without its address)."""
    lines: tuple[str, ...] = ()
    message: str = ''
    keys: tuple[str, ...] = ()


def _unavailable(channel: str, label: str, reason: str) -> CodeChannel:
    return CodeChannel(channel, label, reason=reason)


def _root(result_dir: Path) -> Path | None:
    """The project root of `runs/<run>/unified/results/<id16>`, or None for any other layout."""
    parents = result_dir.parents
    return parents[4] if len(parents) > 4 and parents[3].name == 'runs' and parents[1].name == 'unified' else None


def increasing_chain(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The longest subsequence of `pairs` (sorted by the first index) whose second index also increases: blocks the
    alignment paired out of address order stay unmatched here, so a pane never has to cross its rows."""
    tails: list[int] = []
    links: list[int | None] = []
    ends: list[int] = []
    for position, (_, new) in enumerate(pairs):
        at = bisect_left(tails, new)
        links.append(ends[at - 1] if at else None)
        if at == len(tails):
            tails.append(new)
            ends.append(position)
        else:
            tails[at], ends[at] = new, position
    chain: list[tuple[int, int]] = []
    cursor = ends[-1] if ends else None
    while cursor is not None:
        chain.append(pairs[cursor])
        cursor = links[cursor]
    return chain[::-1]


def _merged(opcodes: list[tuple[str, int, int, int, int]]) -> list[tuple[str, int, int, int, int]]:
    """Neighbouring changed regions become one hunk (an `equal` region ends it)."""
    out: list[tuple[str, int, int, int, int]] = []
    for operation, a, b, c, d in opcodes:
        if out and operation != 'equal' and out[-1][0] != 'equal':
            _, a0, _, c0, _ = out.pop()
            a, c = a0, c0
            operation = 'replace' if b > a and d > c else 'delete' if b > a else 'insert'
        out.append((operation, a, b, c, d))
    return out


def _region(i: int, j: int, i_end: int, j_end: int) -> tuple[str, int, int, int, int] | None:
    if i_end <= i and j_end <= j:
        return None
    return ('replace' if i_end > i and j_end > j else 'delete' if i_end > i else 'insert', i, i_end, j, j_end)


def ir_opcodes(old: list[str], new: list[str], anchors: list[tuple[int, int]]) -> list[tuple[str, int, int, int, int]]:
    """Half-open opcodes over the full instruction lines (NOPs included) from the instruction pairs of the alignment:
    a paired instruction is `equal` when its text is the same, `replace` otherwise; whatever lies between two pairs is
    a gap on the side that has instructions there."""
    ops: list[tuple[str, int, int, int, int]] = []
    i = j = 0
    for ai, aj in [*anchors, (len(old), len(new))]:
        if (gap := _region(i, j, ai, aj)) is not None:
            ops.append(gap)
        if ai < len(old) and aj < len(new):
            ops.append(('equal' if old[ai] == new[aj] else 'replace', ai, ai + 1, aj, aj + 1))
        i, j = ai + 1, aj + 1
    return _merged(ops)


def _one_sided(real: _Side, other: _Side, older_is_real: bool) -> PairText:
    """The code of one side next to the message of the other: the whole code is a gap against the message."""
    count = max(len(real.lines), 1)
    code = '\n'.join(real.lines)
    note = '\n'.join([other.message] + [''] * (count - 1))
    older, newer = (code, note) if older_is_real else (note, code)
    mapping = tuple(range(len(real.lines)))
    hunk = PairHunk(0, count, 'delete' if older_is_real else 'insert')
    return PairText(older, newer, (hunk,), mapping if older_is_real else (), () if older_is_real else mapping)


def _pair(older: _Side, newer: _Side, opcodes: Callable[[_Side, _Side], list]) -> PairText | None:
    """The aligned pair, or None when neither side has code (the reasons then speak for themselves)."""
    if older.lines and newer.lines:
        return align_pair(older.lines, newer.lines, opcodes(older, newer))
    if older.lines or newer.lines:
        return _one_sided(older if older.lines else newer, newer if older.lines else older, bool(older.lines))
    return None


def _text_opcodes(older: _Side, newer: _Side) -> list[tuple[str, int, int, int, int]]:
    # every line ends with a newline, so empty lines survive `splitlines` and the opcodes index these lists
    hunks = diff_hunks(''.join(f'{line}\n' for line in older.lines), ''.join(f'{line}\n' for line in newer.lines),
                       'code')
    return [(h.operation, h.old_start, h.old_end, h.new_start, h.new_end) for h in hunks]


def _reasons(older: _Side, newer: _Side) -> str:
    messages = [m for m in dict.fromkeys((older.message, newer.message)) if m]
    return ' '.join(messages)


class RowCodeSource:
    """`(view model, row) -> RowCode`. Any thread, one call at a time; `close()` releases the readers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._readers: dict[Path, IrReader] = {}
        self._decomp: dict[Path, dict[tuple[str, int], tuple[str, str | None]] | None] = {}

    def close(self) -> None:
        with self._lock:
            for reader in self._readers.values():
                reader.close()
            self._readers.clear()
            self._decomp.clear()

    def __call__(self, vm: UnifiedViewModel, row: UnifiedRowView) -> RowCode:
        with self._lock:
            try:
                record = records_for(vm, [row]).get(row.row_id)
            except UnifiedError:
                record = None
            if vm.manifest is None or vm.result_dir is None or record is None:
                return RowCode(_unavailable(DECOMPILED, 'Decompiled code', NO_RESULT),
                               _unavailable(DISASSEMBLY, 'Disassembly', NO_RESULT))
            producer = self._producer(vm)
            return RowCode(self._decompiled(vm, record.match.older, record.match.newer, producer),
                           self._disassembly(vm, record.match.older, record.match.newer, producer))

    # -- shared --
    def _reader(self, root: Path, run_id: str, ref: IrRef) -> IrReader:
        directory = ir_dir(root, run_id, ref.ir_key)
        if directory not in self._readers:
            self._readers[directory] = IrReader.open(directory)
        return self._readers[directory]

    def _producer(self, vm: UnifiedViewModel) -> str:
        """`Ghidra <version>` of the stored ProgramIR, or the producer kind, or an empty string."""
        manifest, root = vm.manifest, _root(vm.result_dir)
        if manifest is None or root is None or manifest.ir_older is None:
            return ''
        try:
            producer = self._reader(root, manifest.ghidriff_run_id, manifest.ir_older).manifest.producer
        except (UnifiedError, OSError, ValueError):
            return ''
        return f'Ghidra {clean(producer.ghidra, 32)}' if producer.kind == 'ghidra' else producer.kind

    @staticmethod
    def _provenance(vm: UnifiedViewModel, side: str, ref: SideRef | None, source: str, ir_key: str = '') -> str:
        manifest = vm.manifest
        digest = manifest.older_sha256 if side == 'older' else manifest.newer_sha256
        name = clean(ref.name, 80) if ref is not None and ref.name else 'unnamed function'
        where = f'{name} at 0x{ref.rva:X}' if ref is not None else 'no function'
        parts = [f'{side.capitalize()}: {where}', source, f'artifact {digest[:12]}', f'result {(vm.result_id or "")[:12]}']
        if ir_key:
            parts.insert(2, f'ir {ir_key[:12]}')
        return clean(' | '.join(parts), 400)

    # -- decompiled C --
    def _decomp_records(self, vm: UnifiedViewModel) -> dict[tuple[str, int], tuple[str, str | None]] | None:
        """The verified records of the stored decompile part by (side, rva), None when the part is not there or does
        not verify (a result is never read from a part that disagrees with its manifest)."""
        directory = vm.result_dir
        if directory in self._decomp:
            return self._decomp[directory]
        part = next((p for p in vm.manifest.parts if p.name == DECOMP_PART), None)
        found = None if part is None else self._read_decomp(directory / DECOMP_PART, part)
        self._decomp[directory] = found
        return found

    @staticmethod
    def _read_decomp(path: Path, part) -> dict[tuple[str, int], tuple[str, str | None]] | None:
        digest, size, records = hashlib.sha256(), 0, {}
        try:
            for line in store.part_lines(path):
                digest.update(line)
                size += len(line)
                document = json.loads(line.decode('utf-8'))
                side, rva, status, code = (document.get(k) for k in ('side', 'rva', 'status', 'code'))
                if (set(document) != _DECOMP_KEYS or side not in ('older', 'newer') or type(rva) is not int
                        or status not in ('ok', 'timeout', 'failed') or (status == 'ok') != (type(code) is str)
                        or (side, rva) in records):
                    return None
                records[side, rva] = (status, code)
        except (UnifiedError, ValueError, UnicodeDecodeError, AttributeError):
            return None
        if digest.hexdigest() != part.sha256 or size != part.bytes or len(records) != part.records:
            return None
        return records

    def _c_side(self, records, side: str, refs: tuple[SideRef, ...]) -> _Side:
        if not refs:
            return _Side(message=NO_FUNCTION)
        found = records.get((side, refs[0].rva))
        if found is None:
            return _Side(message=DECOMP_MISSING)
        status, code = found
        if status == 'ok' and code:
            return _Side(tuple(strip_unsafe(line, keep_layout=True) for line in code.splitlines()))
        return _Side(message=DECOMP_STATUS.get(status, DECOMP_MISSING))

    def _decompiled(self, vm, older_refs, newer_refs, producer: str) -> CodeChannel:
        label = f'Decompiled on demand by {producer}' if producer else 'Decompiled on demand'
        records = self._decomp_records(vm)
        if records is None:
            part = any(p.name == DECOMP_PART for p in vm.manifest.parts)
            return _unavailable(DECOMPILED, label, DECOMP_UNREADABLE if part else NO_DECOMP)
        older, newer = self._c_side(records, 'older', older_refs), self._c_side(records, 'newer', newer_refs)
        pair = _pair(older, newer, _text_opcodes)
        if pair is None:
            return _unavailable(DECOMPILED, label, _reasons(older, newer))
        source = label
        return CodeChannel(DECOMPILED, label, pair, (
            self._provenance(vm, 'older', older_refs[0] if older_refs else None, source),
            self._provenance(vm, 'newer', newer_refs[0] if newer_refs else None, source)),
            notes=tuple(m for m in (older.message, newer.message) if m))

    # -- disassembly --
    def _ir_side(self, root: Path, run_id: str, ref: IrRef, side: str, refs: tuple[SideRef, ...]):
        """(side, FnView or None, truncated)."""
        if not refs:
            return _Side(message=NO_FUNCTION), None
        reader = self._reader(root, run_id, ref)
        fid = reader.functions.rva_to_fid.get(refs[0].rva)
        if fid is None:
            return _Side(message=NOT_IN_IR), None
        instructions, texts = reader.instructions(fid), reader.texts(fid)
        if not texts or len(texts) != len(instructions):
            return _Side(message=NOT_STORED), None
        keys = [clean(text, 240) for text in texts[:MAX_LINES]]
        lines = [f'{ins.rva:08x}  {key}' for ins, key in zip(instructions, keys, strict=False)]
        if len(instructions) > MAX_LINES:
            lines.append(f'... {len(instructions) - MAX_LINES} more instructions not shown')
        return _Side(tuple(lines), keys=tuple(keys)), (load_view(reader, side, fid) if len(instructions) <= MAX_LINES else None)

    def _disassembly(self, vm, older_refs, newer_refs, producer: str) -> CodeChannel:
        label = f'Disassembly from ProgramIR ({producer})' if producer else 'Disassembly from ProgramIR'
        manifest, root = vm.manifest, _root(vm.result_dir)
        if root is None or manifest.ir_older is None or manifest.ir_newer is None:
            return _unavailable(DISASSEMBLY, label, NO_IR)
        try:
            older, old_view = self._ir_side(root, manifest.ghidriff_run_id, manifest.ir_older, 'older', older_refs)
            newer, new_view = self._ir_side(root, manifest.ghidriff_run_id, manifest.ir_newer, 'newer', newer_refs)
        except (UnifiedError, OSError, ValueError):
            return _unavailable(DISASSEMBLY, label, NO_IR)
        notes = [m for m in (older.message, newer.message) if m]
        anchors = self._anchors(old_view, new_view, notes) if older.lines and newer.lines else None
        pair = _pair(older, newer, lambda a, b: _whole(a, b) if anchors is None else ir_opcodes(a.keys, b.keys, anchors))
        if pair is None:
            return _unavailable(DISASSEMBLY, label, _reasons(older, newer))
        keys = (manifest.ir_older.ir_key, manifest.ir_newer.ir_key)
        return CodeChannel(DISASSEMBLY, label, pair, (
            self._provenance(vm, 'older', older_refs[0] if older_refs else None, label, keys[0]),
            self._provenance(vm, 'newer', newer_refs[0] if newer_refs else None, label, keys[1])), notes=tuple(notes))

    @staticmethod
    def _anchors(old: FnView | None, new: FnView | None, notes: list[str]) -> list[tuple[int, int]] | None:
        """Instruction pairs of the stored-IR alignment as increasing (older index, newer index), None when it cannot
        be had: the pair then shows its whole text as one changed region and says so."""
        if old is None or new is None:
            notes.append(NOT_ALIGNED)
            return None
        alignment = align(old, new)
        if alignment.capped:
            notes.append('alignment capped (L-27): instructions beyond the cap are shown unmatched')
        return increasing_chain(sorted(alignment.instruction_map.items()))


def _whole(older: _Side, newer: _Side) -> list[tuple[str, int, int, int, int]]:
    return [('replace', 0, len(older.lines), 0, len(newer.lines))]
