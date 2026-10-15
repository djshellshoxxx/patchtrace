"""One decoded function of a `program-ir/1` side, as the L2 IR channels read it (SPEC-31 05 s2, S3). Pure.

`FnView` is a snapshot of the on-demand rows of ONE function: the instructions (NOP family included, `kept` lists the
others in address order, which is the stream every key and every alignment uses), the basic blocks, the operand
references, calls, string references and constants. Loading touches only the public `IrReader` accessors; a function
without instruction data (oversize or truncated by the extractor, no `ins` row) has no view and every channel of its
pair is `unavailable` (never `cosmetic` by absence, 05 s5).
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from typing import Literal, NamedTuple

from ..ir import schema
from ..ir.features import F_NOP, is_direct_branch
from ..ir.ins import Insn
from ..ir.reader import BlockRow, ConstRow, IrReader, RefRow, StringRow

Side = Literal['older', 'newer']
FLAG_TINY, FLAG_THUNK, FLAG_IMPORT = (schema.FN_FLAGS[n] for n in ('tiny', 'thunk', 'import'))
FLAG_OVERSIZE, FLAG_TRUNCATED = schema.FN_FLAGS['oversize'], schema.FN_FLAGS['truncated']
FLAG_UNLOCATED, FLAG_MASK_MISSING = schema.FN_FLAGS['mask-unlocated'], schema.FN_FLAGS['mask-missing']


class Call(NamedTuple):
    """A call or tail jump with its target resolved to an RVA (None for an import or an unresolved indirect call)."""
    site: int
    rva: int | None
    key: str | None
    kind: str


@dataclass(frozen=True)
class FnView:
    side: str
    fid: int
    rva: int
    size: int
    flags: int
    insns: tuple[Insn, ...]
    texts: tuple[str, ...]
    kept: tuple[int, ...]                       # indexes into `insns` of the non-NOP instructions
    blocks: tuple[BlockRow, ...]                # a function without a block list is ONE block (ordinal 0)
    block_of: tuple[int, ...]                   # block ordinal of every instruction index
    block_kept: tuple[tuple[int, ...], ...]     # per block: indexes of its non-NOP instructions
    index_of: dict[int, int]                    # instruction rva -> index into `insns`
    refs: dict[tuple[int, int], tuple[RefRow, ...]]     # (instruction ordinal, operand index) -> rows
    calls: tuple[Call, ...]
    strings: dict[int, tuple[StringRow, ...]]   # instruction rva -> string references
    consts: tuple[ConstRow, ...]
    eh: str | None
    h1: bytes | None = None                     # address-masked body key of the whole function (C1)

    def text(self, index: int) -> str:
        if 0 <= index < len(self.texts):
            return self.texts[index]
        insn = self.insns[index]
        return insn.mnem

    def block_start_ord(self, rva: int) -> int | None:
        """Ordinal of the block that STARTS at `rva` (a direct branch target), else None."""
        index = self.index_of.get(rva)
        if index is None:
            return None
        block = self.block_of[index]
        return block if self.blocks[block].rva == rva else None

    def terminator(self, block: int) -> int | None:
        """Index of the direct JMP/Jcc that ends `block` (the instruction `bb.h1` leaves out), else None."""
        members = self.block_kept[block]
        if members and is_direct_branch(self.insns[members[-1]].flow):
            return members[-1]
        return None

    def body(self, block: int) -> tuple[int, ...]:
        """The non-NOP instructions of `block` without its terminating direct branch (the `bb.h1` body)."""
        members = self.block_kept[block]
        return members[:-1] if self.terminator(block) is not None else members


def load_view(reader: IrReader, side: Side, fid: int) -> FnView | None:
    """The view of one function, or None when the IR has no instruction data for it."""
    functions = reader.functions
    flags = functions.get('flags', fid) or 0
    if flags & (FLAG_OVERSIZE | FLAG_TRUNCATED):
        return None
    insns = reader.instructions(fid)
    if not insns:
        return None
    rva = functions.get('rva', fid)
    blocks = tuple(reader.blocks(fid)) or (BlockRow(0, insns[0].rva, 1, len(insns), None, None, ()),)
    starts = [block.rva for block in blocks]
    block_of = tuple(max(0, bisect_right(starts, insn.rva) - 1) for insn in insns)
    kept = tuple(i for i, insn in enumerate(insns) if not insn.flags & F_NOP)
    per_block: list[list[int]] = [[] for _ in blocks]
    for i in kept:
        per_block[block_of[i]].append(i)
    refs: dict[tuple[int, int], list[RefRow]] = {}
    for row in reader.refs(fid):
        refs.setdefault((row.ord, row.opi), []).append(row)
    strings: dict[int, list[StringRow]] = {}
    for row in reader.strings(fid):
        strings.setdefault(row.site, []).append(row)
    return FnView(
        side=side, fid=fid, rva=rva, size=functions.get('size', fid) or 0, flags=flags, insns=tuple(insns),
        texts=tuple(reader.texts(fid)), kept=kept, blocks=blocks, block_of=block_of,
        block_kept=tuple(tuple(b) for b in per_block), index_of={insn.rva: i for i, insn in enumerate(insns)},
        refs={key: tuple(value) for key, value in refs.items()},
        calls=tuple(Call(row.site, None if row.callee is None else functions.get('rva', row.callee), row.import_key,
                         row.kind) for row in reader.calls(fid)),
        strings={key: tuple(value) for key, value in strings.items()}, consts=tuple(reader.constants(fid)),
        eh=functions.eh[fid], h1=functions.get('h1', fid))


def positional_cfg_equal(old: FnView, new: FnView) -> bool:
    """The blocks correspond by ordinal: same block count, and per block the same kept length, the same terminator
    mnemonic and the same successor list (switch tables included). COS-ADDR/1 and the positional alignment need it."""
    if len(old.blocks) != len(new.blocks):
        return False
    for number, (block_old, block_new) in enumerate(zip(old.blocks, new.blocks, strict=True)):
        if block_old.succ != block_new.succ or len(old.block_kept[number]) != len(new.block_kept[number]):
            return False
        term_old, term_new = old.terminator(number), new.terminator(number)
        if (term_old is None) != (term_new is None):
            return False
        if term_old is not None and old.insns[term_old].mnem != new.insns[term_new].mnem:
            return False
    return True
