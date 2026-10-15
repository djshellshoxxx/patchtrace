"""Code text for unified rows without a Ghidriff match, read from the stored ProgramIR (SPEC-31 07 s3 "code panes").

Only what the sidecar stores is shown: the Ghidra-produced instruction text (`ins.txt`) of the function on each side,
one line per instruction with its RVA. A side without a function, a function the IR does not hold and a sidecar without
text each say so; nothing is fabricated. Qt-free; the readers are opened lazily and kept per IR key until `close()`.
"""
from __future__ import annotations

from pathlib import Path

from .contracts import IrRef
from .ir.place import ir_dir
from .ir.reader import IrReader
from .limits import UnifiedError
from .read_model import UnifiedRowView, UnifiedViewModel, records_for
from .read_text import clean

MAX_LINES = 4000
NO_FUNCTION = 'No function on this side.'
NOT_STORED = 'Disassembly text is not stored for this function in the ProgramIR.'
NOT_IN_IR = 'This function is not in the stored ProgramIR.'


def _root(result_dir: Path) -> Path | None:
    """The project root of `runs/<run>/unified/results/<id16>`, or None for any other layout."""
    parents = result_dir.parents
    return parents[4] if len(parents) > 4 and parents[3].name == 'runs' and parents[1].name == 'unified' else None


class IrPairTexts:
    """`PairTexts` for the Unified panel: `(older text, newer text, label)` or None when no IR is stored for the pair."""

    def __init__(self) -> None:
        self._readers: dict[Path, IrReader] = {}

    def close(self) -> None:
        for reader in self._readers.values():
            reader.close()
        self._readers.clear()

    def __call__(self, vm: UnifiedViewModel, row: UnifiedRowView) -> tuple[str, str, str] | None:
        manifest = vm.manifest
        root = _root(vm.result_dir) if vm.result_dir is not None else None
        if manifest is None or root is None or manifest.ir_older is None or manifest.ir_newer is None:
            return None
        try:
            record = records_for(vm, [row]).get(row.row_id)
            if record is None:
                return None
            texts = [self._side(root, manifest.ghidriff_run_id, ref, side)
                     for ref, side in ((manifest.ir_older, record.match.older), (manifest.ir_newer, record.match.newer))]
        except UnifiedError:
            return None
        producer = self._reader(root, manifest.ghidriff_run_id, manifest.ir_older).manifest.producer
        source = f'Ghidra {clean(producer.ghidra, 32)}' if producer.kind == 'ghidra' else producer.kind
        label = f'Disassembly from ProgramIR ({source}); decompiled code unavailable for this pair'
        return texts[0], texts[1], label

    def _reader(self, root: Path, run_id: str, ref: IrRef) -> IrReader:
        directory = ir_dir(root, run_id, ref.ir_key)
        if directory not in self._readers:
            self._readers[directory] = IrReader.open(directory)
        return self._readers[directory]

    def _side(self, root: Path, run_id: str, ref: IrRef, side) -> str:
        if not side:
            return NO_FUNCTION
        reader = self._reader(root, run_id, ref)
        fid = reader.functions.rva_to_fid.get(side[0].rva)
        if fid is None:
            return NOT_IN_IR
        instructions, texts = reader.instructions(fid), reader.texts(fid)
        if not texts or len(texts) != len(instructions):
            return NOT_STORED
        lines = [f'{ins.rva:08x}  {clean(text, 240)}' for ins, text in zip(instructions[:MAX_LINES], texts, strict=False)]
        if len(instructions) > MAX_LINES:
            lines.append(f'... {len(instructions) - MAX_LINES} more instructions not shown')
        return '\n'.join(lines)
