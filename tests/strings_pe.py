"""SYNTHETIC PE pair and table helpers for the WB3 strings tests. Bytes only, NEVER executed.

`synergy_pair()` follows the SYN-WB3-1 table of the WB3 plan: a message added in the newer build, a format string
edited, a message removed, a string that moves because another one was inserted before it, and a registry path.
The images are built with the T-track builder; they are test inputs, not software.
"""
from __future__ import annotations

from dataclasses import dataclass

from test_intel_tools_pe import KERNEL32, MSVC_RICH, Asm, Rdata, _image

from patchtrace.strings import contracts as c
from patchtrace.strings.limits import NONE_U32
from patchtrace.strings.sources import SourceRow
from patchtrace.strings.table import CONFIDENCE, ENCODINGS, TYPES, StringRow, StringTable

IMAGE_BASE = 0x140000000
RAW_SHA = 'e' * 64


@dataclass(frozen=True)
class SynergyPair:
    older: bytes
    newer: bytes
    rva: dict[str, dict[str, int]]  # side -> string key -> RVA of its first byte


def _strings(newer: bool) -> dict[str, bytes]:
    strings: dict[str, bytes] = {}
    if newer:
        strings['s_exceeds'] = b'index %u exceeds length %u\0'
        strings['s_registry'] = b'Software\\Vendor\\Product\\Mode\0'
    strings['s_loaded'] = b'configuration loaded\0'
    strings['s_header'] = b'bad header (%.64s)\n\0' if newer else b'bad header (%s)\n\0'
    if not newer:
        strings['s_debug'] = b'debug dump of internal state\0'
    return strings


def _build(newer: bool, record: dict[str, int]) -> bytes:
    def code(asm: Asm, rd: Rdata) -> None:
        record.update(rd.string_rva)
        asm.label('main')
        asm.prologue()
        for key in sorted(rd.string_rva):
            asm.lea('rcx', rd.string_rva[key])
            asm.call_iat(rd.iat['OutputDebugStringA'])
        asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')
    return _image(code, {KERNEL32: ['OutputDebugStringA']}, _strings(newer), rich=MSVC_RICH)


def synergy_pair() -> SynergyPair:
    rva: dict[str, dict[str, int]] = {'older': {}, 'newer': {}}
    older = _build(False, rva['older'])
    newer = _build(True, rva['newer'])
    return SynergyPair(older, newer, rva)


def _row(r: SourceRow) -> StringRow:
    return StringRow(
        value_sha256=r.value_sha256, type=TYPES.index(r.type), encoding=ENCODINGS.index(r.encoding),
        length=r.length, offset=_u32(r.offset), rva=_u32(r.rva), fn_rva=_u32(r.fn_rva), site=_u32(r.site_rva),
        confidence=CONFIDENCE.index(r.confidence), display=r.display)


def builtin_table(side: str, artifact_sha256: str, rows: list[SourceRow]) -> StringTable:
    """Columnar table of built-in scan rows (the test stand-in for the later table builder)."""
    part = c.BasisPart(source='builtin-scan', semantics_id=c.STATIC_SEMANTICS_ID, types=('static',),
                       config_digest='c' * 64)
    return _table(side, artifact_sha256, rows, part, {'static': c.StageState(state='complete')})


def floss_table(side: str, rows: list[SourceRow], *, run_id: str = 'run-1') -> StringTable:
    """A FLOSS-shaped table (so emulation rows have a run to cite) from hand-made `SourceRow`s."""
    part = c.BasisPart(source='floss', semantics_id=c.STATIC_SEMANTICS_ID, run_id=run_id, raw_sha256=RAW_SHA,
                       types=('static', 'stack'), config_digest='c' * 64)
    return _table(side, 'a' * 64, rows, part, {'static': c.StageState(state='complete'),
                                              'stack': c.StageState(state='heuristic')})


def _table(side, artifact_sha256, rows, part, stages) -> StringTable:
    basis = c.StringBasis(artifact_sha256=artifact_sha256, side=side, min_length=4, rows_seen=len(rows),
                          rows_kept=len(rows), stages=stages, parts=(part,))
    return StringTable.from_rows(basis, [_row(r) for r in rows])


def _u32(value: int | None) -> int:
    return NONE_U32 if value is None else value
