"""Input port of the L1 ladder: what it reads from ONE side of a ProgramIR (`program-ir/1`, 02-data-model s3).

The ladder never opens SQLite and never sees encoded integers (`kind`, `name_src`, `flags`): an adapter over the
real `IrReader` (slice S1) or over the synthetic builder (`tests/unified_ir_builder.py`) turns the five
tables of the frozen contract into the plain rows below. Every `fid` is the rank of the function by `rva`
(0..n-1), exactly like `fn.fid`. NULL columns are `None`.

| row type    | frozen table / column mapping                                                                         |
|-------------|--------------------------------------------------------------------------------------------------------|
| `FnRow`     | `fn` (all columns the ladder reads); `kind`/`name_src` decoded to the words below, `aliases` split,    |
|             | `thunk_target` resolved to a FID, `pdata_confirmed` = `extent_src == 1`, `oversize` = flags oversize   |
|             | or truncated (the keys are NULL then)                                                                  |
| `CallRow`   | `call`: `callee` is a FID or None, `import_key` is the canonical import identity or None, `jump` is   |
|             | true for a tail jump (`call.kind`)                                                                     |
| `StrRow`    | `str`: `sha` is the 64-hex SHA-256 of the string value, `length` its length                            |
| `CstRow`    | `cst`: ALL non-address immediates (rarity filters are applied by the ladder, 02 s6 L-15)               |
| `BlockRow`  | `bb`: `h1` is the block's masked-bytes hash, `n_insn` its instruction count                            |

Row order is irrelevant: the ladder indexes by `fid` and sorts call sites by `site`.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple, Protocol, runtime_checkable

KIND_NORMAL = 'normal'
KIND_THUNK = 'thunk'
KIND_EXTERNAL = 'external'
KINDS = (KIND_NORMAL, KIND_THUNK, KIND_EXTERNAL)
NAME_SOURCES = ('DEFAULT', 'ANALYSIS', 'IMPORTED', 'USER_DEFINED')


class FnRow(NamedTuple):
    fid: int
    rva: int
    size: int
    kind: str                       # KINDS
    name: str | None
    name_src: str                   # NAME_SOURCES
    aliases: tuple[str, ...]        # other symbols at the entry (ICF), <= 16
    import_key: str | None          # canonical import identity (equal text == same import), kind external only
    thunk_target: int | None        # FID of the thunk's target, kind thunk only
    n_bb: int
    n_edge: int
    n_insn: int
    h0: int | None
    h1: int | None
    h2: int | None
    h3: int | None
    hm: int | None
    hms: int | None
    md_td: int | None
    md_bu: int | None
    pdata_confirmed: bool
    oversize: bool


class CallRow(NamedTuple):
    fid: int
    site: int
    callee: int | None
    import_key: str | None
    jump: bool


class StrRow(NamedTuple):
    fid: int
    sha: str
    length: int


class CstRow(NamedTuple):
    fid: int
    value: int


class BlockRow(NamedTuple):
    fid: int
    ord: int
    h1: int | None
    n_insn: int


@runtime_checkable
class IrSide(Protocol):
    """One validated side of a ProgramIR. Implementations may stream or return lists; each method is called once."""

    def function_rows(self) -> Iterable[FnRow]: ...

    def call_rows(self) -> Iterable[CallRow]: ...

    def string_rows(self) -> Iterable[StrRow]: ...

    def constant_rows(self) -> Iterable[CstRow]: ...

    def block_rows(self) -> Iterable[BlockRow]: ...


@dataclass
class RowsIrSide:
    """An `IrSide` over already materialised rows: the shape an adapter of the real `IrReader` (slice S1) fills from
    the five SQLite tables of `program-ir/1`, and what the synthetic builder produces."""
    functions: Sequence[FnRow] = field(default_factory=list)
    calls: Sequence[CallRow] = field(default_factory=list)
    strings: Sequence[StrRow] = field(default_factory=list)
    constants: Sequence[CstRow] = field(default_factory=list)
    blocks: Sequence[BlockRow] = field(default_factory=list)

    def function_rows(self) -> Iterable[FnRow]:
        return iter(self.functions)

    def call_rows(self) -> Iterable[CallRow]:
        return iter(self.calls)

    def string_rows(self) -> Iterable[StrRow]:
        return iter(self.strings)

    def constant_rows(self) -> Iterable[CstRow]:
        return iter(self.constants)

    def block_rows(self) -> Iterable[BlockRow]:
        return iter(self.blocks)
