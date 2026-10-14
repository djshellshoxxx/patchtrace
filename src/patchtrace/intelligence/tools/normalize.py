"""Canonical module-relative addressing, verified offsets, function attribution and result validation
(SPEC-29 tools T5, T6.1). Pure apart from bounded reads through a `VerifiedArtifactReader`; no Qt, no process.

Rules: an RVA is only produced from a tool address when the conversion is unambiguous and lands inside the image
PatchTrace parsed itself from the same verified bytes; a file offset maps to an RVA only inside the headers or
inside exactly one section's raw data; a function is attributed only from what the tool itself reported (never by
nearest-preceding start); a project function id is linked only when exactly one project record starts at that RVA.
Everything rejected is recorded as an anomaly, never guessed.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from ...enrichment.identity import parse_address
from .common import CONTRACT, ToolError, ToolEvidenceSet, ToolRun, produced

Anomaly = str


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class PeMap:
    """Layout facts of one verified PE image, from PatchTrace's own bounded parser (`pe_overview`)."""
    sha256: str
    size: int
    image_base: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[Section, ...]

    @classmethod
    def from_reader(cls, reader) -> PeMap:
        from ...pe_overview import inspect_pe
        overview = inspect_pe(reader)
        if (overview.image_base is None or overview.size_of_image is None or overview.sections is None
                or overview.size_of_headers is None):
            raise ToolError('PT-TOOL-INPUT', f'the artifact is not a parsable PE image ({overview.status})')
        sections = tuple(Section(s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size)
                         for s in overview.sections)
        return cls(reader.sha256, reader.size, overview.image_base, overview.size_of_image,
                   overview.size_of_headers, sections)

    def in_image(self, rva: int) -> bool:
        return 0 <= rva < self.size_of_image

    def va_to_rva(self, va: int, base: int) -> tuple[int | None, Anomaly | None]:
        rva = va - base
        if not self.in_image(rva):
            return None, f'address-out-of-image:0x{va:x}'
        return rva, None

    def offset_to_rva(self, offset: int) -> tuple[int | None, Anomaly | None]:
        """(rva, None) for a verified mapping; (None, None) for overlay/slack; (None, anomaly) when ambiguous."""
        if not 0 <= offset < self.size:
            return None, f'offset-outside-file:0x{offset:x}'
        hits = [s for s in self.sections
                if s.raw_size and s.raw_offset <= offset < s.raw_offset + min(s.raw_size, s.virtual_size or s.raw_size)]
        if len(hits) > 1:
            return None, f'offset-ambiguous:0x{offset:x}'
        if hits:
            return hits[0].rva + (offset - hits[0].raw_offset), None
        first_raw = min((s.raw_offset for s in self.sections if s.raw_size), default=self.size)
        if offset < min(self.size_of_headers, first_raw):
            return offset, None  # headers are mapped 1:1 at RVA 0
        return None, None  # overlay or section slack: the offset stays, no RVA

    def section_name(self, rva: int) -> str | None:
        if rva < self.size_of_headers:
            return '(headers)'
        for section in self.sections:
            if section.rva <= rva < section.rva + max(section.virtual_size, section.raw_size):
                return section.name
        return None


def encoded(value: str, encoding: str) -> bytes | None:
    try:
        if encoding == 'UTF-16LE':
            return value.encode('utf-16-le')
        if encoding == 'ASCII':
            return value.encode('ascii')
        return value.encode('utf-8')
    except UnicodeEncodeError:
        return None


def bytes_match(reader, offset: int, value: str, encoding: str) -> bool:
    """True when the verified artifact holds exactly the encoded string at `offset` (T5.3 'verified-bytes')."""
    data = encoded(value, encoding)
    if not data or offset < 0 or offset + len(data) > reader.size or len(data) > 1024 * 1024:
        return False
    try:
        return reader.read(offset, len(data), clip=False) == data
    except Exception:  # noqa: BLE001 - any read failure means 'not verified', never a guess
        return False


def check_binding(reported: Mapping[str, str], actual: Mapping[str, str]) -> None:
    """T5.2: every hash the tool reports must equal PatchTrace's hash of the verified copy."""
    for algorithm, value in reported.items():
        expected = actual.get(algorithm)
        if expected is None or not isinstance(value, str) or value.lower() != expected:
            raise ToolError('PT-TOOL-ARTIFACT', f'tool output describes another file ({algorithm} mismatch)')


def validate_set(evidence: ToolEvidenceSet, *, artifact_sha256: str, cache_key: str | None = None,
                 engine: str | None = None) -> ToolEvidenceSet:
    """T5.4: reject a stored set that belongs to another artifact, configuration or parser contract."""
    if evidence.contract != CONTRACT:
        raise ToolError('PT-TOOL-OUTPUT', 'stored evidence uses another parser contract')
    if evidence.artifact_sha256 != artifact_sha256:
        raise ToolError('PT-TOOL-ARTIFACT', 'stored evidence describes another artifact')
    if engine is not None and evidence.engine != engine:
        raise ToolError('PT-TOOL-STALE', 'stored evidence belongs to another engine')
    if cache_key is not None and evidence.cache_key != cache_key:
        raise ToolError('PT-TOOL-STALE', 'stored evidence was produced with another tool configuration')
    return evidence


def comparability(older: ToolRun, newer: ToolRun) -> list[str]:
    """T6.1 reasons why two runs cannot be compared (empty list: comparable)."""
    reasons = []
    if (older.side, newer.side) != ('older', 'newer'):
        reasons.append('runs are not an older/newer pair')
    if older.engine != newer.engine:
        reasons.append('different engines')
    for name, run in (('older', older), ('newer', newer)):
        if not produced(run):
            reasons.append(f'{name} run status is {run.status}')
    if older.config_digest != newer.config_digest:
        a, b = older.manifest.identity(), newer.manifest.identity()
        differing = sorted(k for k in a if a[k] != b[k]) or ['options']
        if older.options != newer.options and 'options' not in differing:
            differing.append('options')
        reasons.append('tool configuration differs: ' + ', '.join(differing))
    if older.input_artifact_hash == newer.input_artifact_hash:
        reasons.append('both runs analysed the same artifact')
    return reasons


# ---- function attribution and pairing -------------------------------------------------------------------------

def _record_rva(record, image_base: int, size_of_image: int | None) -> int | None:
    value = parse_address(getattr(record, 'address', None))
    if value is None:
        return None
    space = getattr(record, 'address_space', 'unknown')
    if space == 'relative':
        rva = value
    elif space == 'file-offset':
        return None
    elif value >= image_base:
        rva = value - image_base
    else:
        return None  # a virtual address below the image base cannot belong to this image
    if size_of_image is not None and rva >= size_of_image:
        return None
    return rva


@dataclass
class _SideIndex:
    records: dict[int, set[str]] = field(default_factory=dict)       # rva -> project FunctionRecord ids
    status: dict[int, set[str]] = field(default_factory=dict)        # rva -> pairing categories
    partners: dict[int, set[int]] = field(default_factory=dict)      # rva -> partner rvas on the other side


class FunctionPairing:
    """Function identity and pairing per side, from the project's normalized matches plus (optionally) the
    hash-verified raw Ghidriff `matches.address_matches` for unchanged pairs (T6.2). Pure."""

    def __init__(self, older: _SideIndex, newer: _SideIndex, available: bool, notes: tuple[str, ...] = ()):
        self._sides = {'older': older, 'newer': newer}
        self.available = available
        self.notes = notes

    @classmethod
    def empty(cls, note: str = 'no completed analysis run: function pairing unavailable') -> FunctionPairing:
        return cls(_SideIndex(), _SideIndex(), False, (note,))

    @classmethod
    def from_project(cls, matches: Sequence, raw_matches: Mapping | None, *, older_base: int, newer_base: int,
                     older_size: int | None = None, newer_size: int | None = None,
                     notes: Iterable[str] = ()) -> FunctionPairing:
        older, newer = _SideIndex(), _SideIndex()
        bases = {'older': (older_base, older_size), 'newer': (newer_base, newer_size)}
        index = {'older': older, 'newer': newer}
        for match in matches:
            rvas: dict[str, list[int]] = {'older': [], 'newer': []}
            for side in ('older', 'newer'):
                for record in getattr(match, side):
                    rva = _record_rva(record, *bases[side])
                    if rva is None:
                        continue
                    rvas[side].append(rva)
                    index[side].records.setdefault(rva, set()).add(record.id)
            category = match.category
            for side, other in (('older', 'newer'), ('newer', 'older')):
                for rva in rvas[side]:
                    index[side].status.setdefault(rva, set()).add(category)
                    index[side].partners.setdefault(rva, set()).update(rvas[other])
        notes = list(notes)
        table = raw_matches.get('address_matches') if isinstance(raw_matches, Mapping) else None
        if isinstance(table, Mapping):
            for old_text, targets in table.items():
                old = parse_address(old_text) if isinstance(old_text, str) else None
                if old is None or old < older_base or not isinstance(targets, list):
                    continue  # EXTERNAL:<hex> import locations and unparsable keys are not image functions
                news = []
                for target in targets:
                    if isinstance(target, list) and target and isinstance(target[0], str):
                        new = parse_address(target[0])
                        if new is not None and new >= newer_base:
                            news.append(new - newer_base)
                old_rva = old - older_base
                if old_rva in older.status or any(n in newer.status for n in news):
                    continue  # normalized and manual matches win over raw engine relations
                category = 'unchanged' if len(set(news)) == 1 and len(targets) == 1 else 'ambiguous'
                older.status.setdefault(old_rva, set()).add(category)
                older.partners.setdefault(old_rva, set()).update(news)
                for new in news:
                    newer.status.setdefault(new, set()).add(category)
                    newer.partners.setdefault(new, set()).add(old_rva)
        elif raw_matches is None:
            notes.append('raw Ghidriff address_matches unavailable: unchanged functions are unknown')
        return cls(older, newer, True, tuple(notes))

    def project_function(self, side: str, rva: int) -> tuple[str | None, bool]:
        """(project FunctionRecord id, ambiguous): an id only when exactly one record starts at `rva`."""
        ids = self._sides[side].records.get(rva, set())
        if len(ids) == 1:
            return next(iter(ids)), False
        return None, len(ids) > 1

    def status(self, side: str, rva: int) -> str:
        """'added'|'removed'|'modified'|'unchanged' when unambiguous; 'ambiguous'; 'unknown' when not paired."""
        if not self.available:
            return 'unknown'
        categories = self._sides[side].status.get(rva)
        if not categories:
            return 'unknown'
        if len(categories) > 1:
            return 'ambiguous'
        category = next(iter(categories))
        return category if category in ('added', 'removed', 'modified', 'unchanged') else 'ambiguous'

    def partners(self, side: str, rva: int) -> tuple[int, ...]:
        return tuple(sorted(self._sides[side].partners.get(rva, set())))
