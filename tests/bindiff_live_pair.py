"""SYNTHETIC BinExport2 pair for the live BinDiff acceptance test (SPEC-29 §9.4, §10). Stdlib only.

A tiny protobuf wire encoder for the subset of `binexport2.proto` (google/binexport, Apache-2.0) that BinDiff
reads: meta information, mnemonics, instructions, basic blocks, flow graphs and the call graph. The pair is
bound to project-owned synthetic PEs: each `executable_id` is the SHA-256 of `patchtrace.sample.synthetic_pe(0)`
(older) or `synthetic_pe(1)` (newer), so the ids are known by construction (`Accepted`); the live test still
routes the files through C3's `accept_binexport` when C3 is present, which accepts them (measured). The newer
side patches two functions and adds one, so BinDiff reports similarity below 100 %.

The real BinDiff 8 CLI accepts this shape and matched 20 of 20/21 functions (measured 2026-10-14). It is not
real-driver evidence: never describe results on it as compatibility with Ghidra/IDA exports.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from patchtrace.sample import synthetic_pe

MNEMONICS = ('push', 'mov', 'add', 'sub', 'xor', 'cmp', 'jz', 'call', 'ret', 'lea', 'test', 'pop', 'and', 'or',
             'shl', 'shr', 'inc', 'dec', 'jmp', 'nop')
BASE = 0x180001000
TIMESTAMP = 1_760_400_000


def _varint(value: int) -> bytes:
    if value < 0:
        raise ValueError('negative varints are not used by this encoder')
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def _num(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _raw(field: int, payload: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def _text(field: int, value: str) -> bytes:
    return _raw(field, value.encode('utf-8'))


def encode(executable_id: str, executable_name: str, functions: list[list[list[int]]],
           calls: list[tuple[int, int]]) -> bytes:
    """`functions[i]` = basic blocks of function i, each a list of mnemonic indexes (2-byte instructions)."""
    meta = _text(1, executable_name) + _text(2, executable_id) + _text(3, 'x86-64') + _num(4, TIMESTAMP)
    parts = [_raw(1, meta)] + [_raw(4, _text(1, name)) for name in MNEMONICS]
    instructions, blocks, graphs, vertices = [], [], [], []
    for index, function in enumerate(functions):
        entry = address = BASE + 0x100 * index
        first = len(blocks)
        for mnemonics in function:
            begin = len(instructions)
            for mnemonic in mnemonics:
                instructions.append(_num(1, address) + _num(3, mnemonic) + _raw(5, bytes((0x90, mnemonic))))
                address += 2
            blocks.append(_raw(1, _num(1, begin) + _num(2, len(instructions))))
        graph = b''.join(_num(1, block) for block in range(first, len(blocks)))
        graph += b''.join(_raw(2, _num(1, block) + _num(2, block + 1) + _num(3, 3))
                          for block in range(first, len(blocks) - 1))
        graphs.append(graph + _num(3, first))
        vertices.append(_raw(1, _num(1, entry) + _num(2, 0) + _text(3, f'sub_{entry:x}')))
    parts += [_raw(5, item) for item in instructions] + [_raw(6, item) for item in blocks]
    parts += [_raw(7, item) for item in graphs]
    edges = [_raw(2, _num(1, source) + _num(2, target)) for source, target in calls]
    parts.append(_raw(8, b''.join(vertices + edges)))
    return b''.join(parts)


def pair_shapes(functions: int = 20) -> tuple[list, list, list, list]:
    """(older functions, newer functions, older calls, newer calls); deterministic."""
    count = len(MNEMONICS)
    older = [[[(i + k) % count for k in range(3 + i % 4)], [(i * 7 + 3) % count, 8]] for i in range(functions)]
    newer = [[list(block) for block in function] for function in older]
    if functions > 7:
        newer[3] = [newer[3][0] + [2, 2], newer[3][1]]       # patched: two extra instructions
        newer[7] = [[5, 6], newer[7][0], newer[7][1]]         # patched: an extra check block in front
    newer.append([[1, 4, 4, 8]])                              # added function
    calls = [(i, i + 1) for i in range(functions - 1)]
    return older, newer, calls, calls + [(functions - 1, functions)]


@dataclass(frozen=True)
class Summary:
    file_sha256: str
    executable_id: str
    id_binding: str = 'sha256'
    architecture_name: str = 'x86-64'


@dataclass(frozen=True)
class Accepted:
    """Satisfies `bindiff_inputs.AcceptedBinExportLike` (ids known by construction, not validated by C3)."""
    snapshot_path: Path
    summary: Summary


@dataclass(frozen=True)
class LivePair:
    older: Accepted
    newer: Accepted
    older_sha256: str
    newer_sha256: str
    older_artifact: Path
    newer_artifact: Path
    functions: int


def write_pair(directory: Path, functions: int = 20) -> LivePair:
    directory.mkdir(parents=True, exist_ok=True)
    older_pe, newer_pe = synthetic_pe(0), synthetic_pe(1)
    older_sha, newer_sha = hashlib.sha256(older_pe).hexdigest(), hashlib.sha256(newer_pe).hexdigest()
    old_fns, new_fns, old_calls, new_calls = pair_shapes(functions)
    items = []
    for role, pe, sha, fns, calls in (('older', older_pe, older_sha, old_fns, old_calls),
                                      ('newer', newer_pe, newer_sha, new_fns, new_calls)):
        artifact = directory / f'{role}.dll'
        artifact.write_bytes(pe)  # project-owned synthetic PE; never executed
        data = encode(sha, f'synthetic-{role}.dll', fns, calls)
        export = directory / f'{role}.BinExport'
        export.write_bytes(data)
        items.append((Accepted(export, Summary(hashlib.sha256(data).hexdigest(), sha)), artifact))
    (older, older_artifact), (newer, newer_artifact) = items
    return LivePair(older, newer, older_sha, newer_sha, older_artifact, newer_artifact, functions)


def decode(data: bytes) -> dict[int, list]:
    """Minimal wire decoder for tests: field -> values (int for varints, bytes for length-delimited)."""
    fields: dict[int, list] = {}
    pos = 0

    def varint() -> int:
        nonlocal pos
        shift = value = 0
        while True:
            byte = data[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    while pos < len(data):
        key = varint()
        field, wire = key >> 3, key & 7
        if wire == 0:
            fields.setdefault(field, []).append(varint())
        elif wire == 2:
            length = varint()
            fields.setdefault(field, []).append(data[pos:pos + length])
            pos += length
        else:
            raise ValueError(f'unexpected wire type {wire}')
    return fields
