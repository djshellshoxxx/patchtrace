"""The adapters between a real `IrReader` (slice S1) and the ladder's ports: the `IrSide` the S2 ladder reads and the
`MnemonicSource` the S5 residual stage reads (04 s6.1; `ladder/ports.py` has the column mapping). They live beside the
reader, not in the ladder package, which stays pure (it imports no IR code: tests/test_unified_ladder_props.py).

`ReaderSide` decodes the frozen `program-ir/1` columns into the port's plain rows. Three decisions are explicit here
because the port and the contract describe the same thing in different words:

* an IMPORT STUB (a Ghidra thunk that carries an import key, 03 s12.2 item 3) is an `external` function of the port.
  P01 matches imports by key, and the content passes of the ladder never see an `external` function (I6);
* the `AI` name source of Ghidra 12 is no name anchor, like `ANALYSIS`, so the port (four sources) gets `ANALYSIS`;
* `tiny` counts the instructions that are not alignment padding while the ladder counts `n_insn` (padding included),
  so a function the IR flags tiny is capped at the L-10 limit and stays out of every content pass.

Calls, strings, constants and blocks stream: the ladder reads each table once, so nothing is kept per instruction.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..ladder.ports import KIND_EXTERNAL, KIND_NORMAL, KIND_THUNK, BlockRow, CallRow, CstRow, FnRow, StrRow
from ..limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits
from . import schema
from .features import NULL_KEY
from .reader import IrReader

_KIND = {schema.KIND_CODES['normal']: KIND_NORMAL, schema.KIND_CODES['thunk']: KIND_THUNK,
         schema.KIND_CODES['external']: KIND_EXTERNAL}
_NAME_SOURCE = {code: ('ANALYSIS' if name == 'AI' else name) for name, code in schema.NAME_SRC_CODES.items()}
_TINY = schema.FN_FLAGS['tiny']
_OVERSIZE = schema.FN_FLAGS['oversize'] | schema.FN_FLAGS['truncated']
_PDATA_CONFIRMED = 1                  # `fn.extent_src`: the extent equals the .pdata components (03 s12.6)


def _ir_error(reason: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-IR', 'ladder input rejected: IR rows are inconsistent', reason=reason)


def _key(value: int) -> int | None:
    return None if value == NULL_KEY else value


class ReaderSide:
    """One side of a ProgramIR as the ladder's `IrSide` port."""

    def __init__(self, reader: IrReader, limits: UnifiedLimits = DEFAULT_LIMITS) -> None:
        self._reader = reader
        self._tiny_cap = limits.l10_tiny_instructions

    def function_rows(self) -> Iterator[FnRow]:
        table = self._reader.functions
        col = table.columns
        for fid in range(table.n):
            kind = _KIND.get(col['kind'][fid])
            source = _NAME_SOURCE.get(col['name_src'][fid])
            if kind is None:
                raise _ir_error('kind')
            if source is None:
                raise _ir_error('name-src')
            flags = col['flags'][fid]
            import_key = table.import_key[fid]
            if import_key is not None:
                kind = KIND_EXTERNAL
            target = col['thunk_target'][fid]
            thunk_target = table.rva_to_fid.get(target) if kind == KIND_THUNK and target != NULL_KEY else None
            n_insn = min(col['n_insn'][fid], self._tiny_cap) if flags & _TINY else col['n_insn'][fid]
            yield FnRow(
                fid, col['rva'][fid], col['size'][fid], kind, table.name[fid], source, table.aliases[fid], import_key,
                thunk_target, col['n_bb'][fid], col['n_edge'][fid], n_insn, _key(col['h0'][fid]), _key(col['h1'][fid]),
                _key(col['h2'][fid]), _key(col['h3'][fid]), _key(col['hm'][fid]), _key(col['hms'][fid]),
                _key(col['md_td'][fid]), _key(col['md_bu'][fid]), col['extent_src'][fid] == _PDATA_CONFIRMED,
                bool(flags & _OVERSIZE))

    def call_rows(self) -> Iterator[CallRow]:
        reader = self._reader
        n_call = reader.functions.columns['n_call']
        for fid in range(reader.functions.n):
            if n_call[fid]:
                for row in reader.calls(fid):
                    yield CallRow(fid, row.site, row.callee, row.import_key, row.kind == 'jump')

    def string_rows(self) -> Iterator[StrRow]:
        for fid in range(self._reader.functions.n):
            for row in self._reader.strings(fid):
                yield StrRow(fid, row.sha, row.length)

    def constant_rows(self) -> Iterator[CstRow]:
        for fid in range(self._reader.functions.n):
            for row in self._reader.constants(fid):
                yield CstRow(fid, row.value)

    def block_rows(self) -> Iterator[BlockRow]:
        for fid in range(self._reader.functions.n):
            for row in self._reader.blocks(fid):
                yield BlockRow(fid, row.ord, row.h1, row.n_insn)


class ReaderMnemonics:
    """The residual stage's `MnemonicSource`: the mnemonics of one function, decoded from its `ins` blob only when
    blocking asks for an unmatched, content-eligible function (04 s6.1). Padding is skipped by the consumer."""

    def __init__(self, reader: IrReader) -> None:
        self._reader = reader

    def mnemonics(self, fid: int) -> Iterable[str]:
        return (insn.mnem for insn in self._reader.instructions(fid))
