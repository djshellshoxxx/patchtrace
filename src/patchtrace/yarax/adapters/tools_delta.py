"""Tool-evidence adapters: FLOSS string changes and capa pair changes become rule features (plan s7).

Read-only over `ToolDelta` and `PairCapabilityDelta`. A value is offered as a pattern only when its exact bytes can
be re-read from the verified artifact at the recorded offset and hash to the tool's value hash (the display form is
escaped and never seeds a pattern). Whatever cannot be verified is left out: fewer features, never a guess.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Protocol

from ...intelligence.tools.capa_pairs import PairCapabilityDelta, PairChange
from ...intelligence.tools.common import EvidenceLink
from ...intelligence.tools.delta import StringChange, ToolDelta
from ..contracts import CapabilityFeature, PairSource, Side, StringFeature
from ..features import SIDE_ONLY, escape_text
from ..limits import LIMITS

_SINGLE = {'ASCII': 'ascii', 'UTF-8': 'ascii', 'UTF-16LE': 'wide'}
_CHANGE_SIDE: dict[str, Side] = {'added': 'newer', 'removed': 'older'}
_CAPABILITY_SIDE: dict[str, Side] = {'gained': 'newer', 'lost': 'older'}
_MAX_API_GATES = 8


class ByteReader(Protocol):
    """A verified artifact reader (`VerifiedArtifactReader` fits)."""
    sha256: str

    def read(self, offset: int, length: int, *, clip: bool = True) -> bytes: ...


def secrets_excluded(delta: ToolDelta | None) -> int:
    return 0 if delta is None else sum(s.secret_kind is not None and s.change in _CHANGE_SIDE for s in delta.strings)


def quality_flag_codes(*deltas: ToolDelta | PairCapabilityDelta | None) -> tuple[str, ...]:
    return tuple(sorted({flag.code for d in deltas if d is not None for flag in d.flags}))


class FlossStringSource:
    """`StringSource` over a FLOSS `ToolDelta` of the two builds; static, non-secret, ASCII-only values."""

    def __init__(self, delta: ToolDelta | None, readers: Mapping[Side, ByteReader]):
        self._delta = delta
        self._readers = readers

    def string_features(self, pair: PairSource) -> tuple[StringFeature, ...]:
        if self._delta is None or not self._delta.comparable:
            return ()
        shas = {'older': pair.older_sha256, 'newer': pair.newer_sha256}
        found = [self._feature(change, _CHANGE_SIDE[change.change], shas) for change in self._delta.strings
                 if change.change in _CHANGE_SIDE and change.secret_kind is None]
        return tuple(f for f in found if f is not None)

    def _feature(self, change: StringChange, side: Side, shas: Mapping[Side, str]) -> StringFeature | None:
        sha256 = shas[side]
        types = change.older_types if side == 'older' else change.newer_types
        encodings = {_SINGLE.get(e) for e in (change.older_encodings if side == 'older' else change.newer_encodings)}
        reader = self._readers.get(side)
        if types != ('static',) or len(encodings) != 1 or None in encodings or reader is None:
            return None
        if reader.sha256 != sha256 or not 1 <= change.length <= LIMITS.text_pattern_bytes:
            return None
        encoding = next(iter(encodings))
        link = _first_located(change.older if side == 'older' else change.newer, sha256)
        raw = _verified_text(reader, link, encoding, change) if link else None
        text = escape_text(raw) if raw is not None else None
        if link is None or text is None:
            return None
        return StringFeature(side=side, value_sha256=change.value_hash, length=change.length, text=text,
                             encoding=encoding, offset=link.file_offset, evidence_run_id=link.tool_run_id,
                             linked_by='file-level', separation=SIDE_ONLY[side])


def _first_located(links: tuple[EvidenceLink, ...], sha256: str) -> EvidenceLink | None:
    usable = [link for link in links if link.file_offset is not None and link.artifact_sha256 == sha256]
    return min(usable, key=lambda link: link.file_offset) if usable else None


def _verified_text(reader: ByteReader, link: EvidenceLink, encoding: str, change: StringChange) -> bytes | None:
    """The value's ASCII bytes, re-read from the artifact; None when the bytes do not hash to the tool's value."""
    width = 2 if encoding == 'wide' else 1
    raw = reader.read(link.file_offset, change.length * width, clip=False)
    try:
        value = raw.decode('utf-16-le' if encoding == 'wide' else 'utf-8')
    except UnicodeDecodeError:
        return None
    if hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest() != change.value_hash:
        return None
    return value.encode('ascii') if value.isascii() else None


class CapaCapabilitySource:
    """`CapabilitySource` over capa pair changes: gained (newer-only) and lost (older-only) behaviour of this pair.

    Moved behaviour, detection-only differences and pairs capa did not evaluate are not offered.
    """

    def __init__(self, delta: PairCapabilityDelta | None):
        self._delta = delta

    def capability_features(self, pair: PairSource) -> tuple[CapabilityFeature, ...]:
        if self._delta is None or not self._delta.comparable or self._delta.pairing != 'available':
            return ()
        rows = [r for r in self._delta.changes if r.match_id == pair.match_id and r.kind == 'capability'
                and r.change in _CAPABILITY_SIDE and r.noise == 'none' and r.relocation == 'none']
        return tuple(_capability(row) for row in rows)


def _capability(row: PairChange) -> CapabilityFeature:
    side = _CAPABILITY_SIDE[row.change]
    cell = row.older if side == 'older' else row.newer
    gates = sorted({f.value for f in cell.features if f.kind == 'api'})[:_MAX_API_GATES]
    return CapabilityFeature(
        rule_id=row.rule_id, namespace=row.namespace or '', attack=tuple(sorted(
            {label.ident for label in row.labels if label.scheme == 'attack'})),
        classification=f'{row.change} in this function pair', api_gates=tuple(gates), separation=SIDE_ONLY[side])
