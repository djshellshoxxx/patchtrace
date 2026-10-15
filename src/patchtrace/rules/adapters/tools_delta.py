"""`StringSource` and `CapabilitySource` over the SPEC-29 older/newer tool deltas (YRX-integration-plan sections 4 and 7).

Strings (FLOSS delta). Only *static* strings that one build has and the other lacks (`added`, `removed`, or `indeterminate`
when a truncated list cannot tell) are offered. The delta carries an escaped, bounded display form that must never seed a
pattern, so the exact bytes are re-read from the verified artifact at the recorded file offset and checked against the
tool's own string hash; bytes that cannot be re-read or do not match are left empty ("unverified"), and a string that looks
like a secret never has its bytes read at all. Decoded, stack and language strings are not file bytes and are not offered.
Every link is file-level: a decoded RIP-relative target equal to the string's RVA (`xref`) needs the decoder (R4).

Capabilities (capa delta). Only `newly-introduced` and `removed-with-code` capabilities with a match in the *pair's own
function* are offered; `newly-detectable`, unlocalized and unchanged ones are ignored. The normalised evidence keeps call
site addresses but not the API names capa matched, so the names are read from the stored raw capa document (`capa_api_names`)
and resolved against the build's own import table: a name capa spells without the A/W suffix (`GetEnvironmentVariable`)
resolves only when exactly one of the exact name, `A` or `W` is imported, and only to an import the build really has.
These gates are therefore capa's spelling checked against the table, not a decoded call; call pins (R4) are exact.

Unknown is not a negative vote: a delta that cannot be compared, or has no function pairing, makes the channel
`unavailable`, which is different from a complete channel that found nothing.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping
from typing import Protocol

from pydantic import ValidationError

from ...artifact_bytes import ArtifactBytesError
from ...intelligence.tools import capa
from ...intelligence.tools.common import DEFAULT_LIMITS as TOOL_LIMITS
from ...intelligence.tools.common import EvidenceLink, ToolError, ToolEvidenceSet, load_json_strict
from ...intelligence.tools.delta import CapabilityChange, StringChange, ToolDelta
from ..contracts import ApiRef, PairSource, Side
from ..errors import RuleError
from ..limits import DEFAULT_LIMITS
from ..ports import (
    CapabilityChannel,
    CapabilityObservation,
    Coverage,
    ImportSource,
    ImportTable,
    StringChannel,
    StringObservation,
)

SIDES: tuple[Side, ...] = ('older', 'newer')
# FLOSS encoding -> (encoding in a rule, bytes per character). UTF-8 strings are language strings: not offered.
_ENCODINGS = {'ASCII': ('ascii', 1), 'UTF-16LE': ('wide', 2)}
# A string longer than a text pattern may be is read only this far: enough for the feature builder to see it is too long.
READ_CAP = 2 * (DEFAULT_LIMITS.text_pattern_bytes + 1)
_UNAVAILABLE = Coverage('unavailable', 'unavailable')
_COMPLETE = Coverage('complete', 'complete')


class ByteReader(Protocol):
    """The part of `VerifiedArtifactReader` the adapter needs."""

    @property
    def sha256(self) -> str: ...

    def read(self, offset: int, length: int, *, clip: bool = True) -> bytes: ...


def _hash(pair: PairSource, side: Side) -> str:
    return pair.older_sha256 if side == 'older' else pair.newer_sha256


def _stale(what: str) -> RuleError:
    return RuleError('PT-RULE-STALE', f'The {what} belongs to another file than the pair', reason='artifact-moved')


def _check_links(pair: PairSource, side: Side, links: tuple[EvidenceLink, ...]) -> None:
    if any(link.artifact_sha256 != _hash(pair, side) for link in links):
        raise _stale(f'{side} tool evidence')


# --- strings ---------------------------------------------------------------------------------------------------------

def _text_hash(data: bytes, encoding: str) -> str | None:
    try:
        text = data.decode('ascii' if encoding == 'ascii' else 'utf-16-le')
    except UnicodeDecodeError:
        return None
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()


class FlossStrings:
    """`StringSource` over a FLOSS `ToolDelta`; `readers` maps a side to the verified artifact of that build."""

    def __init__(self, delta: ToolDelta | None, readers: Mapping[Side, ByteReader]):
        self._delta = delta
        self._readers = readers

    def strings(self, pair: PairSource) -> StringChannel:
        delta = self._delta
        if delta is None:
            return StringChannel(_UNAVAILABLE)
        if delta.engine != 'floss':
            raise RuleError('PT-RULE-INPUT', 'The string delta is not a FLOSS delta', reason='wrong-engine')
        for side, reader in self._readers.items():
            if reader.sha256 != _hash(pair, side):
                raise _stale(f'{side} artifact')
        if not delta.comparable:
            return StringChannel(_UNAVAILABLE)
        found = (self._observe(pair, change) for change in delta.strings)
        return StringChannel(_COMPLETE, tuple(item for items in found for item in items))

    def _observe(self, pair: PairSource, change: StringChange) -> tuple[StringObservation, ...]:
        if change.change == 'added':
            sides = (('newer', 'newer-only'),)
        elif change.change == 'removed':
            sides = (('older', 'older-only'),)
        elif change.change == 'indeterminate':
            sides = tuple((side, 'unknown') for side in SIDES if (change.older if side == 'older' else change.newer))
        else:
            return ()
        return tuple(item for side, separation in sides
                     if (item := self._one(pair, change, side, separation)) is not None)

    def _one(self, pair: PairSource, change: StringChange, side: Side, separation: str) -> StringObservation | None:
        types, encodings, links = ((change.older_types, change.older_encodings, change.older) if side == 'older'
                                   else (change.newer_types, change.newer_encodings, change.newer))
        if not links or 'static' not in types or len(encodings) != 1 or encodings[0] not in _ENCODINGS:
            return None
        _check_links(pair, side, links)
        encoding, width = _ENCODINGS[encodings[0]]
        located = sorted((link for link in links if link.file_offset is not None), key=lambda link: link.file_offset)
        offset = located[0].file_offset if located else 0
        data = b'' if change.secret_kind or not located else self._reread(side, offset, change.length * width,
                                                                           encoding, change.value_hash)
        return StringObservation(side=side, value_sha256=change.value_hash, data=data, encoding=encoding,
                                 offset=offset, evidence_run_id=(located or links)[0].tool_run_id,
                                 linked_by='file-level', separation=separation, secret_kind=change.secret_kind)

    def _reread(self, side: Side, offset: int, wanted: int, encoding: str, value_hash: str) -> bytes:
        reader = self._readers.get(side)
        if reader is None:
            return b''
        try:
            data = reader.read(offset, min(wanted, READ_CAP), clip=False)
        except ArtifactBytesError:
            return b''
        if wanted <= READ_CAP and _text_hash(data, encoding) != value_hash:
            return b''   # the artifact does not hold what the tool said it holds
        return data


# --- capabilities ----------------------------------------------------------------------------------------------------

def capa_api_names(raw: bytes) -> dict[tuple[str, int], tuple[str, ...]]:
    """(rule id, function RVA) -> the API names capa matched there, from a stored raw capa document. Only matches whose
    function capa itself names (function scope, or a basic block of a function in its layout) are listed."""
    try:
        document = capa.ResultDocument.model_validate(load_json_strict(
            raw, max_bytes=TOOL_LIMITS['capa'].stdout_bytes, max_depth=TOOL_LIMITS['capa'].json_depth))
    except (ToolError, ValidationError):
        raise RuleError('PT-RULE-INTEGRITY', 'The stored capa output cannot be read', reason='capa-document') from None
    analysis = document.meta.analysis
    base = analysis.base_address.value
    if analysis.base_address.type != 'absolute' or not isinstance(base, int):
        return {}
    owner = {block.address.value: function.address.value for function in analysis.layout.functions
             for block in function.matched_basic_blocks}
    found: dict[tuple[str, int], set[str]] = defaultdict(set)
    for name, rule in document.rules.items():
        if rule.meta.is_subscope_rule:
            continue
        scope = rule.meta.scopes.static
        for address, match in rule.matches:
            if address.type != 'absolute' or not isinstance(address.value, int):
                continue
            function = address.value if scope == 'function' else owner.get(address.value) if scope == 'basic block' \
                else None
            if function is not None and 0 <= function - base < 2**32:
                found[(name, function - base)].update(_api_features(match))
    return {key: tuple(sorted(names)) for key, names in found.items() if names}


def _api_features(match: capa.Match) -> set[str]:
    names: set[str] = set()
    stack = [match]
    while stack:
        node = stack.pop()
        if node.success:
            feature = node.node.feature if node.node.type == 'feature' else None
            if feature and feature.get('type') == 'api' and isinstance(feature.get('api'), str):
                names.add(feature['api'][:256])
            stack.extend(node.children)
    return names


def _dll_stem(dll: str) -> str:
    return dll.lower().rpartition('.')[0] or dll.lower()


def resolve_api(spelling: str, table: ImportTable) -> ApiRef | None:
    """capa's spelling of an API (`CreateFile`, `kernel32.CreateFile`) -> the import the build really has, or `None`.
    The exact name wins; otherwise exactly one of the `A` and `W` variants must be imported. Anything ambiguous is no
    gate: a wrong gate is worse than a missing one."""
    stem, _, name = spelling.rpartition('.')
    wanted = {name, name + 'A', name + 'W'}
    matches = [entry for entry in table.entries
               if entry.name in wanted and (not stem or _dll_stem(entry.dll) == stem.lower())]
    exact = [entry for entry in matches if entry.name == name]
    pool = {(entry.dll.lower(), entry.name): entry for entry in exact or matches}
    if len(pool) != 1:
        return None
    entry = next(iter(pool.values()))
    return ApiRef(dll=entry.dll, name=entry.name)


class CapaCapabilities:
    """`CapabilitySource` over a capa `ToolDelta`.

    `evidence` (the normalised sets per side) supplies the ATT&CK ids, which the delta does not keep; `apis` maps a side to
    `capa_api_names` of that side's raw capa document; `imports` resolves those names against the real import tables. Each
    is optional: without it the capability is still offered, with fewer attributes."""

    def __init__(self, delta: ToolDelta | None, *, evidence: Mapping[Side, ToolEvidenceSet] | None = None,
                 apis: Mapping[Side, Mapping[tuple[str, int], tuple[str, ...]]] | None = None,
                 imports: ImportSource | None = None):
        self._delta = delta
        self._evidence = evidence or {}
        self._apis = apis or {}
        self._imports = imports

    def capabilities(self, pair: PairSource) -> CapabilityChannel:
        delta = self._delta
        if delta is None:
            return CapabilityChannel(_UNAVAILABLE)
        if delta.engine != 'capa':
            raise RuleError('PT-RULE-INPUT', 'The capability delta is not a capa delta', reason='wrong-engine')
        if not delta.comparable or delta.pairing != 'available':
            return CapabilityChannel(_UNAVAILABLE)
        found = (self._observe(pair, change) for change in delta.capabilities)
        return CapabilityChannel(_COMPLETE, tuple(item for item in found if item is not None))

    def _observe(self, pair: PairSource, change: CapabilityChange) -> CapabilityObservation | None:
        wanted = {'added': ('newer', 'newly-introduced'), 'removed': ('older', 'removed-with-code')}
        side, classification = wanted.get(change.change, (None, None))
        function = pair.newer if side == 'newer' else pair.older
        if change.kind != 'capability' or change.classification != classification or function is None:
            return None
        links = change.newer if side == 'newer' else change.older
        _check_links(pair, side, links)
        function_id = f'rva:0x{function.rva:x}'
        if not any(link.function_id == function_id for link in links):
            return None
        return CapabilityObservation(
            rule_id=change.rule_id, namespace=change.namespace, attack=self._attack(side, change.rule_id, function_id),
            classification=classification, api_gates=self._gates(pair, side, change.rule_id, function.rva))

    def _attack(self, side: Side, rule_id: str, function_id: str) -> tuple[str, ...]:
        evidence = self._evidence.get(side)
        ids = {tag for item in (evidence.capabilities if evidence else ()) for tag in item.attack
               if item.rule_id == rule_id and item.location.function_id == function_id}
        return tuple(sorted(ids))

    def _gates(self, pair: PairSource, side: Side, rule_id: str, function_rva: int) -> tuple[ApiRef, ...]:
        names = self._apis.get(side, {}).get((rule_id, function_rva), ())
        table = self._imports.imports(pair, side) if self._imports is not None and names else None
        if table is None:
            return ()
        gates = {(gate.dll, gate.name): gate for name in names if (gate := resolve_api(name, table)) is not None}
        return tuple(gates[key] for key in sorted(gates))
