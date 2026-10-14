"""Top-level wire pre-scan of a BinExport2 buffer, without protobuf (SPEC-10b §6.4).

Bounds record counts, record sizes, wire types and unknown bytes BEFORE any protobuf object is allocated, so
`ParseFromString` only ever sees a message whose top-level shape is already within the caps.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .binexport_limits import BinExportLimits, Budget, err

KNOWN: Mapping[int, str] = MappingProxyType({
    1: 'meta_information', 2: 'expression', 3: 'operand', 4: 'mnemonic', 5: 'instruction', 6: 'basic_block',
    7: 'flow_graph', 8: 'call_graph', 9: 'string_table', 10: 'address_comment', 11: 'string_reference',
    12: 'expression_substitution', 13: 'section', 14: 'library', 15: 'data_reference', 16: 'module',
    17: 'comment', 93992622: 'md_index'})
SINGLETON = frozenset({1, 8})
_UNCAPPED = frozenset({'meta_information', 'call_graph'})  # singletons; nested counts are checked post-parse


@dataclass(frozen=True, slots=True)
class WireStats:
    counts: Mapping[int, int]
    bytes_by_field: Mapping[int, int]
    unknown_bytes: int
    total_bytes: int

    def count(self, name: str) -> int:
        for number, label in KNOWN.items():
            if label == name:
                return self.counts.get(number, 0)
        raise KeyError(name)


def _varint(buf, pos: int, n: int) -> tuple[int, int]:
    result = shift = 0
    for i in range(10):
        if pos >= n:
            raise err('PT-SECONDARY-INPUT', 'wire_truncated', 'BinExport wire data ends inside a varint')
        b = buf[pos]
        pos += 1
        if i == 9 and b > 1:  # 10th byte may only carry bit 63
            raise err('PT-SECONDARY-INPUT', 'wire_malformed', 'BinExport varint exceeds 64 bits')
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, pos
        shift += 7
    raise err('PT-SECONDARY-INPUT', 'wire_malformed', 'BinExport varint exceeds 10 bytes')


def prescan(buf, limits: BinExportLimits, budget: Budget) -> WireStats:
    n = len(buf)
    pos = 0
    counts: dict[int, int] = {}
    size: dict[int, int] = {}
    unknown = 0
    caps = {number: (None if name in _UNCAPPED else limits.cap(name)) for number, name in KNOWN.items()}
    max_record = limits.max_record_bytes
    while pos < n:
        start = pos
        b = buf[pos]
        if b < 0x80:  # fast path: one-byte tag (fields 1..15)
            tag, pos = b, pos + 1
        else:
            tag, pos = _varint(buf, pos, n)
        field, wt = tag >> 3, tag & 7
        if field == 0:
            raise err('PT-SECONDARY-INPUT', 'wire_malformed', 'BinExport field number 0')
        if wt == 2:
            b = buf[pos] if pos < n else 0x80
            if b < 0x80 and pos < n:
                length, pos = b, pos + 1
            else:
                length, pos = _varint(buf, pos, n)
            if length > max_record:
                raise err('PT-SECONDARY-LIMIT', 'record_too_large',
                          f'BinExport record of field {field} exceeds {max_record} bytes')
            if pos + length > n:
                raise err('PT-SECONDARY-INPUT', 'wire_truncated', 'BinExport record extends past end of file')
            pos += length
        elif wt == 0:
            _, pos = _varint(buf, pos, n)
        elif wt in (1, 5):
            pos += 8 if wt == 1 else 4
            if pos > n:
                raise err('PT-SECONDARY-INPUT', 'wire_truncated', 'BinExport fixed-width field past end of file')
        else:
            raise err('PT-SECONDARY-INPUT', 'group_wire_type', f'BinExport wire type {wt} at top level')
        if field in caps:
            if wt != 2:
                raise err('PT-SECONDARY-INPUT', 'wire_type_mismatch',
                          f'BinExport field {field} has wire type {wt}, expected 2')
            c = counts.get(field, 0) + 1
            counts[field] = c
            size[field] = size.get(field, 0) + pos - start
            cap = caps[field]
            if field in SINGLETON:
                if c > 1:
                    raise err('PT-SECONDARY-INPUT', 'duplicate_singleton',
                              f'BinExport field {field} appears more than once')
            elif c > cap:
                name = KNOWN[field]
                raise err('PT-SECONDARY-LIMIT', f'count_cap:{name}', f'BinExport {name} count exceeds {cap}')
        else:
            unknown += pos - start
            if unknown > limits.max_unknown_bytes:
                raise err('PT-SECONDARY-INPUT', 'unknown_fields_excess',
                          f'BinExport unknown fields exceed {limits.max_unknown_bytes} bytes')
        budget.tick()
    if not counts.get(1):
        raise err('PT-SECONDARY-INPUT', 'meta_missing', 'BinExport meta_information missing')
    if not counts.get(8):
        raise err('PT-SECONDARY-INPUT', 'callgraph_missing', 'BinExport call_graph missing')
    return WireStats(MappingProxyType(counts), MappingProxyType(size), unknown, n)
