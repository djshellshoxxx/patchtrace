"""Group `ir:<side>`: every function of one side's unified IR, with instruction text (WB1 section 7, slice S9).

Read only through the public `IrReader` read API (`unified.ir.reader`), never the sidecar database. Unlike group `fn`
this covers ALL functions including unchanged ones, so `kind:asm` becomes searchable: the `asm` document body is the
reader's masked instruction text (addresses already masked), its identifier words are the distinct mnemonics and the
constants in hex and decimal. A function without stored instruction text gets no `asm` document (nothing is invented),
and a function without a name gets a `sub_<rva>` placeholder flagged AUTO.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from patchtrace.search.segment import SegmentDoc
from patchtrace.search.sources.base import SourceSpec, name_fields, skipped

KINDS = ('function', 'asm')
TABLE_SETS = ('code', 'name')
NO_IR = 'Unified extraction has not produced an instruction database for this side.'
IR_INPUTS_VERSION = 1
_MASK64 = (1 << 64) - 1


class IrPort(Protocol):
    """The slice of `IrReader` this source reads. `functions` is the columnar table (`n`, `name`, `aliases`,
    `get(column, fid)`); the row methods are the reader's own."""
    manifest: Any
    functions: Any

    def texts(self, fid: int) -> list[str]: ...
    def instructions(self, fid: int) -> list[Any]: ...
    def constants(self, fid: int) -> list[Any]: ...


def constant_words(value: int) -> tuple[str, ...]:
    """Hex (from 16 up, the same spelling the query side generates) and signed decimal of one constant."""
    decimal = str(value)
    return (f'0x{value & _MASK64:x}', decimal) if abs(value) >= 16 else (decimal,)


def _idents(reader: IrPort, fid: int) -> str:
    words = dict.fromkeys(i.mnem.lower() for i in reader.instructions(fid))
    for row in reader.constants(fid):
        words.update(dict.fromkeys(constant_words(row.value)))
    return ' '.join(words)


def _name(reader: IrPort, fid: int, rva: int | None) -> str:
    name = reader.functions.name[fid]
    return name or (f'sub_{rva:x}' if rva is not None else f'sub_fid{fid:x}')


def _documents(reader: IrPort, side: str, subjects: Mapping[int, str]) -> Iterable[SegmentDoc]:
    table = reader.functions
    for fid in range(table.n):
        rva = table.get('rva', fid)
        name = _name(reader, fid, rva)
        subject = (subjects.get(rva) if rva is not None else None) or f'ir{fid}'
        aliases = tuple(a for a in table.aliases[fid] if a != name)
        yield SegmentDoc('function', side, subject[:64], name, fid, rva=rva, **name_fields(name, *aliases))
        text = reader.texts(fid)
        if text:
            yield SegmentDoc('asm', side, subject[:64], name, fid, rva=rva, code_body='\n'.join(text),
                             code_idents=_idents(reader, fid))


def _subjects_digest(subjects: Mapping[int, str]) -> str:
    return hashlib.sha256(repr(sorted(subjects.items())).encode()).hexdigest()


def unified_spec(side: str, reader: IrPort | None, subjects: Mapping[int, str] | None = None) -> SourceSpec:
    """`subjects` maps an RVA to the live project function id (so pair expansion works); unmapped functions get an
    opaque `ir<fid>` subject and stay searchable but unpaired."""
    group = f'ir:{side}'
    if reader is None or reader.manifest is None:
        return skipped(group, KINDS, side, 'unavailable', NO_IR)
    subjects = dict(subjects or {})
    inputs = {'ir_key': reader.manifest.ir_key, 'subjects': _subjects_digest(subjects), 'inputs': IR_INPUTS_VERSION}
    return SourceSpec(group, KINDS, TABLE_SETS, side, inputs, lambda: _documents(reader, side, subjects))
