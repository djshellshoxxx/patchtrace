"""`ins/1`: the per-function instruction payload stored zlib-compressed in `ins.blob` (03 s12.5). Pure.

One record per instruction, NOP family included, in address order:
    [rva, raw_hex, mnemonic, flags, flow, [op, ...]]      flags: see features.F_*
    op = [vkind_code, optype, value, field_offset|null, field_length|null, [register, ...]]
vkind codes: register 0, scalar 1, memory 2, stack 3, address 4. `value` is the register name, the immediate, the
memory/stack displacement or frame offset, the target RVA or the import key (operands.OperandFacts.value).
The payload is a compact JSON array whose first element is the version string; texts live in `ins.txt` as the
instruction texts joined by newlines. Consumers decode on demand through `ir.reader` (bounded decompression).
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from .schema import INS_VERSION, MAX_BLOB, compress, decompress, error


class Op(NamedTuple):
    vkind: int
    optype: int
    value: object
    offset: int | None
    length: int | None
    regs: tuple[str, ...]


class Insn(NamedTuple):
    rva: int
    raw: bytes
    mnem: str
    flags: int
    flow: str
    ops: tuple[Op, ...]


def encode_instructions(records: Iterable[Sequence]) -> bytes:
    payload = json.dumps([INS_VERSION, *records], separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return compress(payload.encode('ascii'))


def decode_instructions(blob: bytes, limit: int = MAX_BLOB) -> list[Insn]:
    try:
        document = json.loads(decompress(blob, limit))
        if not isinstance(document, list) or not document or document[0] != INS_VERSION:
            raise ValueError('version')
        out = []
        for rva, raw_hex, mnem, flags, flow, ops in document[1:]:
            out.append(Insn(rva, bytes.fromhex(raw_hex), mnem, flags, flow,
                            tuple(Op(vk, optype, value, offset, length, tuple(regs))
                                  for vk, optype, value, offset, length, regs in ops)))
        return out
    except (ValueError, TypeError):
        raise error('An instruction blob is malformed', 'ins-invalid', 'PT-UNIFIED-STORE') from None


def encode_text(texts: Sequence[str]) -> bytes:
    return compress('\n'.join(texts).encode('utf-8'))


def decode_text(blob: bytes, limit: int = MAX_BLOB) -> list[str]:
    try:
        data = decompress(blob, limit).decode('utf-8')
    except UnicodeDecodeError:
        raise error('An instruction text blob is malformed', 'txt-invalid', 'PT-UNIFIED-STORE') from None
    return data.split('\n') if data else []
