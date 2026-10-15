"""Extent attribution of capa instruction-scope matches through the unified IR (CAP-9). Pure: no Qt, no I/O.

capa reports an instruction-scope match by address only. A match is attributed to a function when exactly one
function whose extent the PE `.pdata` table confirmed contains the address; it then gets `contained-in-function`.
Leaf functions (no `.pdata`), conflicting or overlapping extents and addresses outside every extent stay
unattributed: no function is guessed. Only the public read API of `unified.ir.reader` is used.
"""
from __future__ import annotations

from bisect import bisect_right

from ...unified.ir.reader import IrReader
from .common import CapabilityEvidence, ToolEvidenceSet

_PDATA_CONFIRMED = 1   # `fn.extent_src`


def _extents(reader: IrReader) -> tuple[list[int], list[int]]:
    """Starts and ends of the pdata-confirmed functions, sorted by start."""
    table = reader.functions
    spans = []
    for fid in range(table.n):
        rva, size = table.get('rva', fid), table.get('size', fid)
        if rva is not None and size and table.get('extent_src', fid) == _PDATA_CONFIRMED:
            spans.append((rva, rva + size))
    spans.sort()
    return [s for s, _ in spans], [e for _, e in spans]


def _owner(starts: list[int], ends: list[int], rva: int) -> int | None:
    index = bisect_right(starts, rva) - 1
    if index < 0 or rva >= ends[index]:
        return None
    # An earlier extent that also reaches `rva` makes the owner ambiguous.
    if index > 0 and max(ends[:index]) > rva:
        return None
    return starts[index]


def attribute(evidence: ToolEvidenceSet, reader: IrReader) -> ToolEvidenceSet:
    """A copy with instruction-scope matches attributed where the extent is verified; the input is unchanged."""
    manifest = reader.manifest
    if manifest is not None and manifest.artifact_sha256 != evidence.artifact_sha256:
        return evidence
    starts, ends = _extents(reader)
    changed = False
    out: list[CapabilityEvidence] = []
    for item in evidence.capabilities:
        link = item.location
        owner = _owner(starts, ends, link.rva) if item.scope == 'instruction' and link.attribution == 'none' \
            and link.rva is not None else None
        if owner is None:
            out.append(item)
            continue
        changed = True
        out.append(item.model_copy(update={'location': link.model_copy(
            update={'function_id': f'rva:0x{owner:x}', 'attribution': 'contained-in-function'})}))
    return evidence.model_copy(update={'capabilities': tuple(out)}) if changed else evidence
